//! TWCC Receiver Interceptor - tracks incoming packets and generates feedback.

use super::recorder::Recorder;
use super::{flow_ssrcs, stream_supports_twcc};
use crate::Interceptor;
use crate::cc::feedback::{CongestionFeedbackFormat, negotiated_congestion_feedback};
use crate::cc::feedback_cadence::FeedbackCadence;
use crate::stream_info::StreamInfo;
use crate::{AttributedPacket, Packet, TaggedPacket};
use sansio::Protocol;
use shared::TransportContext;
use shared::error::Error;
use shared::marshal::Unmarshal;
use std::collections::{HashMap, HashSet, VecDeque};
use std::time::{Duration, Instant};

/// Default interval for sending TWCC feedback.
const DEFAULT_INTERVAL: Duration = Duration::from_millis(100);

/// Builder for the TwccReceiverInterceptor.
///
/// # Example
///
/// ```
/// use rtci_interceptor::{Slot, Registry, TwccReceiverBuilder};
/// use std::time::Duration;
///
/// let chain = Registry::new()
///     .with(Slot::TwccReceiver, TwccReceiverBuilder::new()
///         .with_interval(Duration::from_millis(100))
///         .build())
///     .build();
/// ```
pub struct TwccReceiverBuilder {
    /// Interval between feedback reports.
    interval: Duration,
    /// Whether the interval stretches to what the RTCP bandwidth allows.
    adaptive_interval: bool,
    /// Whether packets already reported received are reported again (libwebrtc).
    rereport_received: bool,
    /// See [`Self::with_feedback_share`]; `None`: the form's default.
    feedback_share: Option<f64>,
    /// See [`Self::with_rtcp_budget`].
    rtcp_budget: Option<u64>,
    /// See [`Self::with_max_adaptive_interval`].
    max_adaptive_interval: Duration,
    /// Whether the header extension alone, without `transport-cc` feedback, makes a stream
    /// reported.
    extension_alone: bool,
}

impl Default for TwccReceiverBuilder {
    fn default() -> Self {
        Self {
            interval: DEFAULT_INTERVAL,
            adaptive_interval: true,
            feedback_share: None,
            rtcp_budget: None,
            max_adaptive_interval: crate::cc::feedback_cadence::MAX_ADAPTIVE_INTERVAL,
            rereport_received: false,
            extension_alone: false,
        }
    }
}

impl TwccReceiverBuilder {
    /// Create a new builder with default settings.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the interval between feedback reports.
    pub fn with_interval(mut self, interval: Duration) -> Self {
        self.interval = interval;
        self
    }

    /// Whether the interval stretches to what the RTCP bandwidth holds one feedback packet
    /// in. On by default.
    ///
    /// All RTCP of an endpoint shares 5% of the session bandwidth (RFC 3550 section 6.2,
    /// unless `b=RS` / `b=RR` say otherwise), and the RTCP session sends no more than that.
    /// At low media rates a tenth of a second of it does not hold a feedback packet, so
    /// feedback built every 100 ms queues in the session and reaches the sender late or not
    /// at all. With this on, the interval is the configured one where the bandwidth allows
    /// it and longer where it does not, up to half a second ("with low uplink bandwidth
    /// feedback may be sent less often", section 3 of the draft): one feedback packet for
    /// every RTCP packet the session may send, each covering everything since the last.
    /// `false` keeps the interval fixed.
    pub fn with_adaptive_interval(mut self, adaptive_interval: bool) -> Self {
        self.adaptive_interval = adaptive_interval;
        self
    }

    /// The share of the media received that the feedback may take while the interval is
    /// adaptive: the interval is the time in which this share holds one feedback packet (with
    /// its lower layers, and the minimal compound packet around it without reduced-size
    /// RTCP). Default 0.05, RFC 3550 section 6.2's 5% for all of RTCP. A smaller share leaves
    /// room in the 5% for the regular reports (the `Performance` behaviour profile: 0.025).
    ///
    /// With [`Self::with_rtcp_budget`] it is the share of the session bandwidth instead
    /// (default [`RTCP_BUDGET_FEEDBACK_SHARE`](crate::RTCP_BUDGET_FEEDBACK_SHARE), 3.75%).
    pub fn with_feedback_share(mut self, share: f64) -> Self {
        self.feedback_share = Some(share);
        self
    }

    /// The RTCP budget form of the adaptive interval, with the session's least bandwidth in
    /// bits per second (the RTCP session's
    /// [`with_minimum_session_bandwidth`](crate::RtcpSessionBuilder::with_minimum_session_bandwidth)):
    /// the feedback takes its share of the session bandwidth, the media measured both ways
    /// (RFC 3550 section 6.2 sizes all of RTCP to it, and RFC 4585 section 3.2 makes feedback
    /// "subject to the RTCP bandwidth constraints"), divided with the peer while this endpoint
    /// sends media too; the interval is the time in which that holds one feedback packet, at
    /// least 50 ms, and [`Self::with_max_adaptive_interval`] does not apply. A peer connection
    /// uses it with `DefaultInterceptorOptions::rtcp_congestion_feedback_in_budget`. Off by
    /// default (the share of the media received, libwebrtc's form).
    pub fn with_rtcp_budget(mut self, minimum_session_bandwidth: u64) -> Self {
        self.rtcp_budget = Some(minimum_session_bandwidth);
        self
    }

    /// The longest the adaptive interval stretches to while media flows. Default 250 ms.
    /// draft-holmer-rmcat-transport-wide-cc-extensions-01 section 3: "in cases of low uplink
    /// bandwidth it is acceptable to send them less frequently, e.g., for instance once per
    /// RTT"; RFC 8888 section 4 leaves the interval to the application ("Applications need to
    /// negotiate an appropriate congestion control feedback interval ... based on ... the
    /// acceptable feedback overhead"). The `Performance` behaviour profile takes 500 ms.
    pub fn with_max_adaptive_interval(mut self, max_interval: Duration) -> Self {
        self.max_adaptive_interval = max_interval;
        self
    }

    /// Whether a packet an earlier feedback message reported as received is reported as
    /// received again when a late packet moves the base sequence number back over it, as
    /// libwebrtc does. Off by default: draft-holmer-rmcat-transport-wide-cc-extensions-01
    /// section 3.1.1 has such packets marked "Packet not received", with no delta. A
    /// libwebrtc sender drops a packet from its history once it is reported received, so it
    /// ignores the later "not received" either way.
    pub fn with_rereport_received(mut self, rereport_received: bool) -> Self {
        self.rereport_received = rereport_received;
        self
    }

    /// Whether a remote stream whose packets carry the transport-wide sequence number header
    /// extension is reported on although `a=rtcp-fb:<pt> transport-cc` was not negotiated for
    /// it. Off by default: the feedback is an RTCP feedback message, sent only where the
    /// session negotiated it (RFC 4585 section 4.2: "MUST NOT" use feedback other than the
    /// listed types), and libwebrtc too reports only when the feedback is negotiated beside
    /// the extension. On is the fork's earlier behaviour, for a peer that signals the
    /// extension alone.
    pub fn with_feedback_on_extension_alone(mut self, extension_alone: bool) -> Self {
        self.extension_alone = extension_alone;
        self
    }

    /// Build the interceptor.
    pub fn build(self) -> TwccReceiverInterceptor {
        let mut interceptor = TwccReceiverInterceptor::new(self.interval, self.adaptive_interval);
        let cadence = FeedbackCadence::new(self.interval, self.adaptive_interval);
        interceptor.cadence = match self.rtcp_budget {
            Some(floor) => cadence
                .with_limits(
                    self.feedback_share
                        .unwrap_or(crate::cc::feedback_cadence::RTCP_BUDGET_FEEDBACK_SHARE),
                    self.max_adaptive_interval,
                )
                .with_rtcp_budget(floor),
            None => cadence.with_limits(
                self.feedback_share
                    .unwrap_or(crate::cc::feedback_cadence::FEEDBACK_SHARE),
                self.max_adaptive_interval,
            ),
        };
        interceptor.rereport_received = self.rereport_received;
        interceptor.extension_alone = self.extension_alone;
        interceptor
    }
}

/// Per-stream state for the receiver.
struct RemoteStream {
    /// Header extension ID for transport-wide CC.
    hdr_ext_id: u8,
}

/// Interceptor that tracks incoming RTP packets and generates TWCC feedback.
///
/// This interceptor examines incoming RTP packets for transport-wide CC sequence
/// numbers and periodically generates TransportLayerCC feedback packets.
pub struct TwccReceiverInterceptor {
    /// When feedback is built: the configured interval, stretched to the RTCP bandwidth.
    cadence: FeedbackCadence,

    /// Start time for calculating arrival times.
    start_time: Option<Instant>,

    /// TWCC recorder for building feedback.
    recorder: Option<Recorder>,

    /// Remote stream state per SSRC.
    streams: HashMap<u32, RemoteStream>,

    /// SSRCs of streams whose feedback is RFC 8888: never reported here, even when their
    /// packets carry a transport-wide sequence number (RFC 8888 section 6).
    rfc8888_ssrcs: HashSet<u32>,

    /// Transport-wide CC header extension ID negotiated on this transport.
    ///
    /// Transport-wide congestion control is per *transport*, not per SSRC: the feedback
    /// must account for every packet that carried the transport-cc sequence extension,
    /// whatever SSRC it rode on. Packets can legitimately arrive on SSRCs that have no
    /// stream binding - RTX/probe padding and RID simulcast layers before they are bound -
    /// and omitting them makes the remote congestion controller read them as lost. This ID
    /// is used as the fallback for those unbound SSRCs.
    transport_hdr_ext_id: Option<u8>,

    /// Queue for feedback packets.
    write_queue: VecDeque<TaggedPacket>,

    /// Next timeout for sending feedback.
    next_timeout: Option<Instant>,
    /// Inbound packets ready for the next interceptor.
    read_queue: VecDeque<TaggedPacket>,
    /// See [`TwccReceiverBuilder::with_rereport_received`].
    rereport_received: bool,
    /// See [`TwccReceiverBuilder::with_feedback_on_extension_alone`].
    extension_alone: bool,
}

impl TwccReceiverInterceptor {
    fn new(interval: Duration, adaptive_interval: bool) -> Self {
        Self {
            read_queue: VecDeque::new(),
            cadence: FeedbackCadence::new(interval, adaptive_interval),
            start_time: None,
            recorder: None,
            streams: HashMap::new(),
            rfc8888_ssrcs: HashSet::new(),
            transport_hdr_ext_id: None,
            write_queue: VecDeque::new(),
            rereport_received: false,
            extension_alone: false,
            next_timeout: None,
        }
    }

    fn generate_feedback(&mut self, now: Instant) {
        let Some(recorder) = self.recorder.as_mut() else {
            return;
        };

        let packets = recorder.build_feedback_packet();
        for pkt in packets {
            self.cadence.on_feedback(pkt.marshal_size());
            self.write_queue.push_back(TaggedPacket {
                now,
                transport: TransportContext::default(),
                message: AttributedPacket::new(Packet::Rtcp(vec![pkt])),
            });
        }
    }
}

impl Protocol<TaggedPacket, TaggedPacket, ()> for TwccReceiverInterceptor {
    type Rout = TaggedPacket;
    type Wout = TaggedPacket;
    type Eout = ();
    type Error = Error;
    type Time = Instant;

    fn handle_read(&mut self, msg: TaggedPacket) -> Result<(), Self::Error> {
        self.cadence.on_packet(&msg);
        // Process incoming RTP packets with TWCC extension
        if let Packet::Rtp(ref rtp_packet) = msg.message.packet
            && !self.rfc8888_ssrcs.contains(&rtp_packet.header.ssrc)
        {
            // Prefer the ID bound for this SSRC, and fall back to the transport-wide one so
            // that padding and not-yet-bound streams still make it into the feedback.
            let hdr_ext_id = self
                .streams
                .get(&rtp_packet.header.ssrc)
                .map(|stream| stream.hdr_ext_id)
                .or(self.transport_hdr_ext_id);

            // Extract transport CC sequence number
            if let Some(hdr_ext_id) = hdr_ext_id
                && let Some(ext_data) = rtp_packet.header.get_extension(hdr_ext_id)
                && let Ok(tcc) =
                    rtp::extension::transport_cc_extension::TransportCcExtension::unmarshal(
                        &mut ext_data.as_ref(),
                    )
            {
                // Initialize recorder on the first packet carrying transport-wide CC
                if self.recorder.is_none() {
                    // Use a random sender SSRC for feedback
                    self.recorder = Some(
                        Recorder::new(rand::random())
                            .with_rereport_received(self.rereport_received),
                    );
                    self.start_time = Some(msg.now);
                    self.next_timeout = Some(msg.now + self.cadence.interval(msg.now));
                }

                // Calculate arrival time in microseconds since start
                let arrival_time = self
                    .start_time
                    .map(|start| msg.now.duration_since(start).as_micros() as i64)
                    .unwrap_or(0);

                if let Some(recorder) = self.recorder.as_mut() {
                    recorder.record(rtp_packet.header.ssrc, tcc.transport_sequence, arrival_time);
                }
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
        // First drain feedback packets
        if let Some(pkt) = self.write_queue.pop_front() {
            return Some(pkt);
        }
        None
    }

    fn handle_timeout(&mut self, now: Instant) -> Result<(), Error> {
        // Check if we need to send feedback
        if let Some(timeout) = self.next_timeout
            && now >= timeout
        {
            self.generate_feedback(now);
            self.next_timeout = Some(now + self.cadence.interval(now));
        }
        Ok(())
    }

    fn poll_timeout(&mut self) -> Option<Instant> {
        self.next_timeout
    }
}

impl Interceptor for TwccReceiverInterceptor {
    fn bind_remote_stream(&mut self, info: &StreamInfo) {
        // One feedback mechanism per stream: a stream that negotiated RFC 8888 is reported by
        // the RFC 8888 recorder and not here as well.
        if negotiated_congestion_feedback(info) == Some(CongestionFeedbackFormat::Rfc8888) {
            self.rfc8888_ssrcs.extend(flow_ssrcs(info));
            self.streams.remove(&info.ssrc);
            return;
        }
        for ssrc in flow_ssrcs(info) {
            self.rfc8888_ssrcs.remove(&ssrc);
        }
        // draft-holmer-rmcat-transport-wide-cc-extensions-01 section 2.3 / RFC 4585 section
        // 4.2: the feedback is sent where `transport-cc` was negotiated, not on the header
        // extension alone.
        let feedback_negotiated = self.extension_alone
            || info
                .rtcp_feedback
                .iter()
                .any(|fb| fb.typ == "transport-cc" && fb.parameter.is_empty());
        if feedback_negotiated && let Some(hdr_ext_id) = stream_supports_twcc(info) {
            // Don't track if ID is 0 (invalid)
            if hdr_ext_id != 0 {
                self.streams.insert(info.ssrc, RemoteStream { hdr_ext_id });
                // An extension ID maps to exactly one URI within an RTP session, and BUNDLE
                // makes the bundled m-lines one session, so every binding here carries the
                // same transport-cc ID: taking the newest is taking the only one. A genuinely
                // different ID means renegotiation, where the newest is also what we want.
                self.transport_hdr_ext_id = Some(hdr_ext_id);
            }
        }
    }

    fn unbind_remote_stream(&mut self, info: &StreamInfo) {
        for ssrc in flow_ssrcs(info) {
            self.rfc8888_ssrcs.remove(&ssrc);
        }
        self.streams.remove(&info.ssrc);
        // Any binding that remains carries the same ID (see `bind_remote_stream`), so only the
        // loss of the last one leaves no negotiated ID to fall back on. Dropping it then keeps
        // a stale ID from outliving the negotiation and being misread as transport-cc.
        if self.streams.is_empty() {
            self.transport_hdr_ext_id = None;
        }
    }

    fn bind_local_stream(&mut self, _info: &StreamInfo) {}

    fn unbind_local_stream(&mut self, _info: &StreamInfo) {}
}
