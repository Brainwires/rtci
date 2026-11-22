//! Emits RFC 8888 congestion control feedback for the streams being received.

use super::recorder::CcFeedbackRecorder;
use crate::Interceptor;
use crate::cc::feedback_cadence::FeedbackCadence;
use crate::stream_info::StreamInfo;
use crate::twcc::flow_ssrcs;
use crate::{Attribute, AttributedPacket, Packet, TaggedPacket};
use rtcp::transport_feedbacks::cc_feedback_report::Ecn;
use sansio::Protocol;
use shared::error::Error;
use shared::marshal::MarshalSize;
use shared::time::SystemInstant;
use shared::{EcnCodepoint, TransportContext};
use std::collections::HashSet;
use std::collections::VecDeque;
use std::time::{Duration, Instant};

/// How often feedback is sent when no interval is configured.
pub const DEFAULT_INTERVAL: Duration = Duration::from_millis(100);

/// Byte budget for one report, chosen to sit inside a conservative path MTU.
pub const DEFAULT_MAX_REPORT_SIZE: usize = 1200;

/// The RFC 8888 marking for the codepoint a datagram arrived with (`None` is Not-ECT).
fn ecn_of(codepoint: Option<EcnCodepoint>) -> Ecn {
    match codepoint {
        None => Ecn::NotEct,
        Some(EcnCodepoint::Ect0) => Ecn::Ect0,
        Some(EcnCodepoint::Ect1) => Ecn::Ect1,
        Some(EcnCodepoint::Ce) => Ecn::Ce,
    }
}

/// Builder for [`Rfc8888Interceptor`].
///
/// # Example
///
/// ```
/// use rtc_interceptor::{Slot, Registry, Rfc8888Builder};
/// use std::time::Duration;
///
/// let chain = Registry::new()
///     .with(Slot::Rfc8888, Rfc8888Builder::new().with_interval(Duration::from_millis(50)).build())
///     .build();
/// ```
pub struct Rfc8888Builder {
    interval: Duration,
    adaptive_interval: bool,
    max_report_size: usize,
    sender_ssrc: Option<u32>,
}

impl Default for Rfc8888Builder {
    fn default() -> Self {
        Self {
            interval: DEFAULT_INTERVAL,
            adaptive_interval: true,
            max_report_size: DEFAULT_MAX_REPORT_SIZE,
            sender_ssrc: None,
        }
    }
}

/// Whether a stream negotiated RFC 8888 feedback: `a=rtcp-fb:<pt> ack ccfb` (RFC 8888
/// section 6).
pub(crate) fn stream_supports_ccfb(info: &StreamInfo) -> bool {
    info.rtcp_feedback
        .iter()
        .any(|feedback| feedback.typ == "ack" && feedback.parameter == "ccfb")
}

/// An SSRC for a participant that sends no media: random, and never 0 (RFC 3550 section 8).
pub(crate) fn random_ssrc() -> u32 {
    loop {
        let ssrc: u32 = rand::random();
        if ssrc != 0 {
            return ssrc;
        }
    }
}

impl Rfc8888Builder {
    /// Create a builder with the default interval and report size.
    pub fn new() -> Self {
        Self::default()
    }

    /// How often feedback is sent.
    ///
    /// Congestion control wants this often — the estimate is only as fresh as the feedback
    /// driving it — traded against the RTCP bandwidth it costs.
    pub fn with_interval(mut self, interval: Duration) -> Self {
        self.interval = interval;
        self
    }

    /// Whether the interval stretches to what the RTCP bandwidth holds one report in. On by
    /// default.
    ///
    /// "RTCP bandwidth and transmission rules put some upper limits on how frequently the
    /// RTCP feedback messages can be sent" (RFC 8888 section 4), and the RTCP session applies
    /// them: 5% of the session bandwidth unless `b=RS` / `b=RR` say otherwise (RFC 3550
    /// section 6.2). Reports built more often than that queue in the session and reach the
    /// sender late or not at all. With this on, the interval is the configured one where the
    /// bandwidth allows it and longer where it does not, up to half a second: one report for
    /// every RTCP packet the session may send, each covering everything since the last.
    /// `false` keeps the interval fixed.
    pub fn with_adaptive_interval(mut self, adaptive_interval: bool) -> Self {
        self.adaptive_interval = adaptive_interval;
        self
    }

    /// Byte budget for one report.
    ///
    /// A report larger than the path MTU is fragmented or dropped, and feedback that does not
    /// arrive is worth nothing, so feedback that exceeds the budget is split into several
    /// reports (RFC 8888 section 3.1).
    pub fn with_max_report_size(mut self, max_report_size: usize) -> Self {
        self.max_report_size = max_report_size;
        self
    }

    /// The SSRC these reports are sent from.
    ///
    /// Left unset, the interceptor uses the SSRC of the first local stream bound to it (the
    /// RTCP packet sender is then the endpoint's own media source), and while there is none, a
    /// random non-zero SSRC chosen when it is built, as a receive-only RTP participant has
    /// (RFC 3550 section 8). It is never 0.
    pub fn with_sender_ssrc(mut self, sender_ssrc: u32) -> Self {
        self.sender_ssrc = Some(sender_ssrc);
        self
    }

    /// Build the interceptor.
    pub fn build(self) -> Rfc8888Interceptor {
        Rfc8888Interceptor::new(
            self.interval,
            self.adaptive_interval,
            self.max_report_size,
            self.sender_ssrc,
        )
    }
}

/// Reports when each packet of each bound remote stream arrived ([RFC 8888]).
///
/// # Differences from upstream
///
/// `pion/interceptor` injects a `SenderTicker` and a `SenderNow` so its tests can control time.
/// Sans-I/O needs neither: every instant arrives as a parameter, so the tests drive the clock by
/// passing one. Both are dropped.
///
/// Upstream's `Recorder` also never sets its sender SSRC, so every report it builds claims to come
/// from SSRC 0. Here it is configured.
///
/// [RFC 8888]: https://www.rfc-editor.org/rfc/rfc8888
pub struct Rfc8888Interceptor {
    /// When a report is built: the configured interval, stretched to the RTCP bandwidth.
    cadence: FeedbackCadence,
    max_report_size: usize,
    /// The SSRC set on the builder, if one was.
    configured_ssrc: Option<u32>,
    /// The SSRC reports are sent from when none was configured and no local stream is bound.
    receiver_ssrc: u32,
    /// Local streams in the order they were bound: the first is the RTCP packet sender.
    local_ssrcs: Vec<u32>,
    recorder: CcFeedbackRecorder,
    /// Remote streams being reported on.
    streams: HashSet<u32>,
    next_timeout: Option<Instant>,
    /// Wall-clock reference, captured from the first instant handed over, so a monotonic `Instant`
    /// can be turned into the NTP timestamp a report carries.
    epoch: Option<SystemInstant>,
    write_queue: VecDeque<TaggedPacket>,
    /// Inbound packets ready for the next interceptor.
    read_queue: VecDeque<TaggedPacket>,
}

impl Rfc8888Interceptor {
    fn new(
        interval: Duration,
        adaptive_interval: bool,
        max_report_size: usize,
        sender_ssrc: Option<u32>,
    ) -> Self {
        Self {
            read_queue: VecDeque::new(),
            cadence: FeedbackCadence::new(interval, adaptive_interval),
            max_report_size,
            configured_ssrc: sender_ssrc,
            receiver_ssrc: random_ssrc(),
            local_ssrcs: Vec::new(),
            recorder: CcFeedbackRecorder::new(),
            streams: HashSet::new(),
            next_timeout: None,
            epoch: None,
            write_queue: VecDeque::new(),
        }
    }

    /// The SSRC the next report is sent from (RFC 8888 section 3.1: the SSRC of the RTCP packet
    /// sender).
    pub fn sender_ssrc(&self) -> u32 {
        self.configured_ssrc
            .or_else(|| self.local_ssrcs.first().copied())
            .unwrap_or(self.receiver_ssrc)
    }

    /// The middle 32 bits of the NTP timestamp for `now`, which is what a report carries.
    fn report_timestamp(&mut self, now: Instant) -> u32 {
        let epoch = self.epoch.get_or_insert_with(|| SystemInstant::now(now));
        (epoch.ntp(now) >> 16) as u32
    }

    /// Arm the interval from the first instant this interceptor is given.
    fn arm(&mut self, now: Instant) {
        if self.next_timeout.is_none() && !self.streams.is_empty() && !self.cadence.is_off() {
            self.next_timeout = Some(now + self.cadence.interval(now));
        }
    }
}

impl Protocol<TaggedPacket, TaggedPacket, ()> for Rfc8888Interceptor {
    type Rout = TaggedPacket;
    type Wout = TaggedPacket;
    type Eout = ();
    type Error = Error;
    type Time = Instant;

    fn handle_read(&mut self, msg: TaggedPacket) -> Result<(), Self::Error> {
        self.cadence.on_packet(&msg);
        if let Packet::Rtp(rtp_packet) = &msg.message.packet {
            // An RTX packet reaches the chain rewritten into the original it carries; what
            // arrived on the wire was a packet of the retransmission stream, and that is what
            // the report describes (RFC 8888 section 3.1: a block "for each RTP stream", and
            // section 6: feedback for every payload type in use, retransmission included). Its
            // SSRC and sequence number are the ones the sender's history knows the RTX packet
            // by; reporting it as the original would tell the sender a lost packet arrived.
            let (ssrc, sequence_number) = msg
                .message
                .attributes
                .iter()
                .find_map(|attribute| match attribute {
                    Attribute::Retransmitted {
                        ssrc,
                        sequence_number,
                    } => Some((*ssrc, *sequence_number)),
                    _ => None,
                })
                .unwrap_or((rtp_packet.header.ssrc, rtp_packet.header.sequence_number));
            if self.streams.contains(&ssrc) {
                // ECN lives in the IP header, which a sans-I/O interceptor never sees: the
                // application's socket layer reads it and hands it over in the transport
                // context. A datagram without one is reported Not-ECT, which is what an
                // endpoint without ECN support reports anyway.
                self.recorder
                    .add_packet(msg.now, ssrc, sequence_number, ecn_of(msg.transport.ecn));
                self.arm(msg.now);
            }
        }
        self.read_queue.push_back(msg);
        Ok(())
    }

    fn poll_read(&mut self) -> Option<Self::Rout> {
        self.read_queue.pop_front()
    }

    fn handle_write(&mut self, msg: TaggedPacket) -> Result<(), Self::Error> {
        // The media this endpoint sends is part of the session bandwidth, and what the RTCP
        // session is told about its bandwidth passes here on its way to it.
        self.cadence.on_write(&msg);
        self.write_queue.push_back(msg);
        Ok(())
    }

    fn poll_write(&mut self) -> Option<TaggedPacket> {
        // Rejoins the belt and passes every interceptor between here and the wire, so a pacer
        // meters it and a send history counts its bytes like any other outgoing packet.
        self.write_queue.pop_front()
    }

    fn handle_timeout(&mut self, now: Instant) -> Result<(), Error> {
        self.arm(now);

        if let Some(next_timeout) = self.next_timeout
            && now >= next_timeout
        {
            self.next_timeout = Some(now + self.cadence.interval(now));

            if !self.recorder.is_empty() {
                let report_timestamp = self.report_timestamp(now);
                let sender_ssrc = self.sender_ssrc();
                for report in self.recorder.build_reports(
                    now,
                    sender_ssrc,
                    report_timestamp,
                    self.max_report_size,
                ) {
                    if report.report_blocks.is_empty() {
                        continue;
                    }
                    self.cadence.on_feedback(report.marshal_size());
                    self.write_queue.push_back(TaggedPacket {
                        now,
                        transport: TransportContext::default(),
                        message: AttributedPacket::new(Packet::Rtcp(vec![Box::new(report)])),
                    });
                }
            }
        }
        Ok(())
    }

    fn poll_timeout(&mut self) -> Option<Instant> {
        self.next_timeout
    }
}

impl Interceptor for Rfc8888Interceptor {
    /// Only a stream that negotiated `ack ccfb` is reported on: RTCP feedback is sent for the
    /// payload types whose `a=rtcp-fb` line names it and for no other (RFC 4585 section 4.2,
    /// RFC 8888 section 6). A peer that declined `ack ccfb` gets no report.
    ///
    /// The stream's retransmission and FEC SSRCs are reported with it: the feedback covers
    /// every packet of the session's negotiated payload types, repair included (section 6).
    fn bind_remote_stream(&mut self, info: &StreamInfo) {
        if stream_supports_ccfb(info) {
            self.streams.extend(flow_ssrcs(info));
        }
    }

    fn unbind_remote_stream(&mut self, info: &StreamInfo) {
        for ssrc in flow_ssrcs(info) {
            self.streams.remove(&ssrc);
            self.recorder.remove_stream(ssrc);
        }
        if self.streams.is_empty() {
            self.next_timeout = None;
        }
    }

    fn bind_local_stream(&mut self, info: &StreamInfo) {
        if !self.local_ssrcs.contains(&info.ssrc) {
            self.local_ssrcs.push(info.ssrc);
        }
    }

    fn unbind_local_stream(&mut self, info: &StreamInfo) {
        self.local_ssrcs.retain(|ssrc| *ssrc != info.ssrc);
    }
}
