//! Sender Report Interceptor - Filters hop-by-hop RTCP feedback.

use super::sender_stream::SenderStream;
use crate::Interceptor;
use crate::stream_info::StreamInfo;
use crate::{AttributedPacket, Packet, TaggedPacket};
use rtcp::header::PacketType;
use sansio::Protocol;
use shared::TransportContext;
use shared::error::Error;
use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

/// Builder for the SenderReportInterceptor.
///
/// # Example
///
/// ```
/// use rtc_interceptor::{Slot, Registry, SenderReportBuilder};
/// use std::time::Duration;
///
/// // With default interval (1 second)
/// let chain = Registry::new()
///     .with(Slot::SenderReport, SenderReportBuilder::new().build())
///     .build();
///
/// // With custom interval
/// let chain = Registry::new()
///     .with(Slot::SenderReport, SenderReportBuilder::new().with_interval(Duration::from_millis(500)).build())
///     .build();
///
/// // With use_latest_packet enabled
/// let chain = Registry::new()
///     .with(Slot::SenderReport, SenderReportBuilder::new().with_use_latest_packet().build())
///     .build();
/// ```
pub struct SenderReportBuilder {
    /// Interval between sender reports.
    interval: Duration,
    /// Whether to always use the latest packet, even if out-of-order.
    use_latest_packet: bool,
}

impl Default for SenderReportBuilder {
    fn default() -> Self {
        Self {
            interval: Duration::from_secs(1),
            use_latest_packet: false,
        }
    }
}

impl SenderReportBuilder {
    /// Create a new builder with default settings.
    ///
    /// Default interval is 1 second.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set a custom interval between sender reports.
    ///
    /// # Example
    ///
    /// ```
    /// use rtc_interceptor::{Registry, SenderReportBuilder, Slot};
    /// use std::time::Duration;
    ///
    /// let registry = Registry::new().with(
    ///     Slot::SenderReport,
    ///     SenderReportBuilder::new()
    ///         .with_interval(Duration::from_millis(500))
    ///         .build(),
    /// );
    /// ```
    pub fn with_interval(mut self, interval: Duration) -> Self {
        self.interval = interval;
        self
    }

    /// Enable always using the latest packet for timestamp tracking,
    /// even if it appears to be out-of-order based on sequence numbers.
    ///
    /// By default (disabled), only in-order packets update the RTP↔NTP
    /// timestamp correlation. This prevents out-of-order packets from
    /// corrupting the timestamp mapping.
    ///
    /// Enable this option when:
    /// - Packets are guaranteed to arrive in order
    /// - The application reorders packets before the interceptor
    /// - You want the sender report to always reflect the most recent packet
    ///
    /// # Example
    ///
    /// ```
    /// use rtc_interceptor::{Slot, Registry, SenderReportBuilder};
    ///
    /// let registry =
    ///     Registry::new().with(Slot::SenderReport, SenderReportBuilder::new().with_use_latest_packet().build());
    /// ```
    pub fn with_use_latest_packet(mut self) -> Self {
        self.use_latest_packet = true;
        self
    }

    /// Create a builder function for use with Registry.
    ///
    /// This returns a closure that can be passed to `Registry::with()`.
    ///
    /// # Example
    ///
    /// ```
    /// use rtc_interceptor::{Slot, Registry, SenderReportBuilder};
    ///
    /// let registry = Registry::new()
    ///     .with(Slot::SenderReport, SenderReportBuilder::new().build());
    /// ```
    pub fn build(self) -> SenderReportInterceptor {
        SenderReportInterceptor::new(self.interval, self.use_latest_packet)
    }
}

/// The most receiver reference times held for answering at once.
const MAX_REFERENCE_TIMES: usize = 64;

/// A stream unbound since the chain was last polled.
struct Departing {
    ssrc: u32,
    stream: SenderStream,
    /// Its final sender report and BYE, if it ever sent.
    goodbye: Option<TaggedPacket>,
}

/// Interceptor that filters hop-by-hop RTCP reports.
///
/// This interceptor filters out RTCP Receiver Reports and Transport-Specific
/// Feedback, which are hop-by-hop reports that should not be forwarded
/// end-to-end.
///
/// # Type Parameters
///
/// - `P`: The inner protocol being wrapped
///
/// # Example
///
/// ```
/// use rtc_interceptor::{Slot, Registry, SenderReportBuilder};
///
/// let chain = Registry::new()
///     .with(Slot::SenderReport, SenderReportBuilder::new().build())
///     .build();
/// ```
pub struct SenderReportInterceptor {
    interval: Duration,
    next_timeout: Option<Instant>,

    /// Whether to always use the latest packet, even if out-of-order.
    use_latest_packet: bool,

    streams: HashMap<u32, SenderStream>,

    /// The latest instant handed in, for stamping the goodbye of a stream unbound without one.
    last_now: Option<Instant>,

    /// The receiver reference times (RFC 3611 section 4.4) received since the last sender
    /// reports went out, by the SSRC they came from: the compact NTP timestamp and when it
    /// arrived. Answered with a DLRR block (section 4.5) in the next sender report's compound
    /// packet, as libwebrtc does whether or not anything was negotiated.
    reference_times: HashMap<u32, (u32, Instant)>,

    /// Streams unbound since the chain was last polled, with the goodbye each says. A stream
    /// bound again with the same SSRC before then (a renegotiation re-binding it with a new
    /// codec) takes its state back and says no goodbye: it goes on.
    departing: Vec<Departing>,

    read_queue: VecDeque<TaggedPacket>,
    write_queue: VecDeque<TaggedPacket>,
}

impl SenderReportInterceptor {
    /// Create a new SenderReportInterceptor.
    fn new(interval: Duration, use_latest_packet: bool) -> Self {
        Self {
            interval,
            next_timeout: None,

            use_latest_packet,

            streams: HashMap::new(),

            last_now: None,

            departing: Vec::new(),

            reference_times: HashMap::new(),

            read_queue: VecDeque::new(),
            write_queue: VecDeque::new(),
        }
    }

    /// Queues the goodbye of every stream that was unbound and not bound again.
    fn flush_departing(&mut self) {
        for departing in self.departing.drain(..) {
            if let Some(goodbye) = departing.goodbye {
                self.write_queue.push_back(goodbye);
            }
        }
    }

    /// Check if an RTCP packet type should be filtered.
    ///
    /// Returns `true` for hop-by-hop report types that should not be forwarded:
    /// - Receiver Report (201)
    /// - Transport-Specific Feedback (205)
    fn should_filter(packet_type: PacketType) -> bool {
        packet_type == PacketType::ReceiverReport
            || (packet_type == PacketType::TransportSpecificFeedback)
    }
}

impl Protocol<TaggedPacket, TaggedPacket, ()> for SenderReportInterceptor {
    type Rout = TaggedPacket;
    type Wout = TaggedPacket;
    type Eout = ();
    type Error = Error;
    type Time = Instant;

    fn handle_read(&mut self, msg: TaggedPacket) -> Result<(), Self::Error> {
        if let Packet::Rtcp(rtcp_packets) = &msg.message.packet {
            for packet in rtcp_packets {
                let Some(xr) = packet
                    .as_any()
                    .downcast_ref::<rtcp::extended_report::ExtendedReport>()
                else {
                    continue;
                };
                for block in &xr.reports {
                    if let Some(rrtr) = block
                        .as_any()
                        .downcast_ref::<rtcp::extended_report::ReceiverReferenceTimeReportBlock>()
                    {
                        // A remote that sends from many SSRCs is held to a bounded table.
                        if self.reference_times.len() < MAX_REFERENCE_TIMES
                            || self.reference_times.contains_key(&xr.sender_ssrc)
                        {
                            self.reference_times.insert(
                                xr.sender_ssrc,
                                ((rrtr.ntp_timestamp >> 16) as u32, msg.now),
                            );
                        }
                    }
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
        self.flush_departing();
        self.last_now = Some(self.last_now.map_or(msg.now, |last| last.max(msg.now)));
        if let Packet::Rtp(rtp_packet) = &msg.message.packet
            && let Some(stream) = self.streams.get_mut(&rtp_packet.header.ssrc)
        {
            stream.process_rtp(msg.now, rtp_packet);

            // Arm the report timer from the first packet's instant (see nack::generator).
            if self.next_timeout.is_none() {
                self.next_timeout = Some(msg.now + self.interval);
            }
        }

        self.write_queue.push_back(msg);

        Ok(())
    }

    fn poll_write(&mut self) -> Option<TaggedPacket> {
        self.flush_departing();
        // First drain generated RTCP reports
        if let Some(pkt) = self.write_queue.pop_front() {
            return Some(pkt);
        }
        None
    }

    fn handle_timeout(&mut self, now: Instant) -> Result<(), Error> {
        self.flush_departing();
        self.last_now = Some(self.last_now.map_or(now, |last| last.max(now)));
        if let Some(next_timeout) = self.next_timeout
            && now >= next_timeout
        {
            self.next_timeout = Some(now + self.interval);

            for stream in self.streams.values_mut() {
                if let Some(sr) = stream.generate_report(now) {
                    let mut compound: Vec<Box<dyn rtcp::Packet>> = vec![Box::new(sr)];
                    // The DLRR block answers every reference time received since the last
                    // reports, once, from the first stream that reports (RFC 3611 section 4.5).
                    if !self.reference_times.is_empty() {
                        let reports = self
                            .reference_times
                            .drain()
                            .map(|(ssrc, (last_rr, arrived))| {
                                rtcp::extended_report::DLRRReport {
                                    ssrc,
                                    last_rr,
                                    dlrr: (now.saturating_duration_since(arrived).as_secs_f64()
                                        * 65536.0) as u32,
                                }
                            })
                            .collect();
                        compound.push(Box::new(rtcp::extended_report::ExtendedReport {
                            sender_ssrc: stream.ssrc(),
                            reports: vec![Box::new(rtcp::extended_report::DLRRReportBlock {
                                reports,
                            })],
                        }));
                    }
                    self.write_queue.push_back(TaggedPacket {
                        now,
                        transport: TransportContext::default(),
                        message: AttributedPacket::new(Packet::Rtcp(compound)),
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

impl Interceptor for SenderReportInterceptor {
    /// A stream unbound a moment ago (since the chain was last polled) and bound again with the
    /// same SSRC is the same stream re-bound by a renegotiation: it keeps its packet and octet
    /// counts and RTP / NTP timing, takes the new clock rate, and its goodbye is withdrawn.
    fn bind_local_stream(&mut self, info: &StreamInfo) {
        let stream = match self.departing.iter().position(|d| d.ssrc == info.ssrc) {
            Some(i) => {
                let mut stream = self.departing.remove(i).stream;
                stream.set_clock_rate(info.clock_rate);
                stream
            }
            None => SenderStream::new(info.ssrc, info.clock_rate, self.use_latest_packet),
        };
        self.streams.insert(info.ssrc, stream);
    }

    /// A stream that sent and is now unbound (its sender stopped) says goodbye: a final sender
    /// report and an RTCP BYE for its SSRC and its repair flows, in one compound packet
    /// (RFC 3550 6.6: a BYE follows a report in a compound packet). The goodbye goes out when
    /// the chain is next polled, unless the stream is bound again first.
    fn unbind_local_stream(&mut self, info: &StreamInfo) {
        let Some(mut stream) = self.streams.remove(&info.ssrc) else {
            return;
        };
        let goodbye = match self.last_now {
            Some(now) if stream.has_sent() => stream.generate_report(now).map(|report| {
                let sources = std::iter::once(info.ssrc)
                    .chain(info.ssrc_rtx)
                    .chain(info.ssrc_fec)
                    .collect();
                TaggedPacket {
                    now,
                    transport: TransportContext::default(),
                    message: AttributedPacket::new(Packet::Rtcp(vec![
                        Box::new(report),
                        Box::new(rtcp::goodbye::Goodbye {
                            sources,
                            reason: Default::default(),
                        }),
                    ])),
                }
            }),
            _ => None,
        };
        self.departing.retain(|d| d.ssrc != info.ssrc);
        self.departing.push(Departing {
            ssrc: info.ssrc,
            stream,
            goodbye,
        });
    }

    fn bind_remote_stream(&mut self, _info: &StreamInfo) {}

    fn unbind_remote_stream(&mut self, _info: &StreamInfo) {}
}
