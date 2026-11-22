//! NACK Generator Interceptor - Generates NACK requests for missing packets.

use super::receive_log::ReceiveLog;
use super::stream_supports_nack;
use crate::Interceptor;
use crate::stream_info::StreamInfo;
use crate::{AttributedPacket, Packet, TaggedPacket};
use sansio::Protocol;
use shared::TransportContext;
use shared::error::Error;
use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

/// Builder for the NackGeneratorInterceptor.
///
/// # Example
///
/// ```
/// use rtc_interceptor::{Slot, Registry, NackGeneratorBuilder};
/// use std::time::Duration;
///
/// let chain = Registry::new()
///     .with(Slot::NackGenerator, NackGeneratorBuilder::new()
///         .with_size(512)
///         .with_interval(Duration::from_millis(100))
///         .with_skip_last_n(2)
///         .build())
///     .build();
/// ```
pub struct NackGeneratorBuilder {
    /// Size of the receive log (must be power of 2: 64, 128, ..., 32768).
    size: u16,
    /// Interval between NACK generation cycles.
    interval: Duration,
    /// Number of most recent packets to skip when generating NACKs.
    skip_last_n: u16,
    /// Maximum number of NACKs to send per missing packet (0 = unlimited).
    max_nacks_per_packet: u16,
    /// How long a packet is asked for, counted from when it was found missing.
    max_packet_age: Option<Duration>,
    /// How long a packet has to be missing before it is first asked for.
    reorder_delay: Duration,
    /// The round-trip time assumed until one is measured.
    round_trip_time: Option<Duration>,
}

/// The default of [`NackGeneratorBuilder::with_max_nacks_per_packet`]: a packet that ten
/// requests did not bring is not coming.
pub const DEFAULT_MAX_NACKS_PER_PACKET: u16 = 10;
/// The default of [`NackGeneratorBuilder::with_max_packet_age`]: past two seconds a
/// retransmission is of no use to an interactive stream.
pub const DEFAULT_MAX_PACKET_AGE: Duration = Duration::from_secs(2);

impl Default for NackGeneratorBuilder {
    fn default() -> Self {
        Self {
            size: 512,
            interval: Duration::from_millis(100),
            skip_last_n: 0,
            max_nacks_per_packet: DEFAULT_MAX_NACKS_PER_PACKET,
            max_packet_age: Some(DEFAULT_MAX_PACKET_AGE),
            reorder_delay: Duration::ZERO,
            round_trip_time: None,
        }
    }
}

impl NackGeneratorBuilder {
    /// Create a new builder with default settings.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the size of the receive log.
    ///
    /// Size must be a power of 2 between 64 and 32768 (inclusive).
    pub fn with_size(mut self, size: u16) -> Self {
        self.size = size;
        self
    }

    /// Set the interval between NACK generation cycles.
    pub fn with_interval(mut self, interval: Duration) -> Self {
        self.interval = interval;
        self
    }

    /// Set the number of most recent packets to skip when generating NACKs.
    ///
    /// This helps avoid generating NACKs for packets that are simply delayed
    /// and haven't arrived yet.
    pub fn with_skip_last_n(mut self, skip_last_n: u16) -> Self {
        self.skip_last_n = skip_last_n;
        self
    }

    /// Set the maximum number of NACKs to send per missing packet (RFC 4588 Appendix A: a
    /// receiver limits how often it asks again).
    ///
    /// Default: [`DEFAULT_MAX_NACKS_PER_PACKET`]. 0 is unlimited.
    pub fn with_max_nacks_per_packet(mut self, max: u16) -> Self {
        self.max_nacks_per_packet = max;
        self
    }

    /// Set how long a missing packet is asked for (RFC 4588 6.3: a retransmission is only
    /// requested while it can still be of use). Give the sender's `rtx-time` (RFC 4588 8.1)
    /// when it signals one: past it the sender no longer has the packet.
    ///
    /// Default: [`DEFAULT_MAX_PACKET_AGE`]. `None` is unlimited.
    pub fn with_max_packet_age(mut self, max_packet_age: Option<Duration>) -> Self {
        self.max_packet_age = max_packet_age;
        self
    }

    /// Set how long a packet has to be missing before the first NACK for it (RFC 4588 6.3:
    /// the request is delayed to allow for reordering). Default: zero, the gap is asked for
    /// at the next cycle.
    pub fn with_reorder_delay(mut self, reorder_delay: Duration) -> Self {
        self.reorder_delay = reorder_delay;
        self
    }

    /// Set the round-trip time assumed until the RTCP session measures one
    /// ([`RtcpSessionEvent::RoundTripTime`](crate::RtcpSessionEvent::RoundTripTime)). A
    /// packet is not asked for again before a round trip has passed since the last request
    /// (RFC 4588 6.3: "the timer value shall be based on the observed round-trip time"): the
    /// retransmission could not have arrived sooner.
    pub fn with_round_trip_time(mut self, round_trip_time: Duration) -> Self {
        self.round_trip_time = Some(round_trip_time);
        self
    }

    /// Build the interceptor.
    pub fn build(self) -> NackGeneratorInterceptor {
        let mut interceptor = NackGeneratorInterceptor::new(
            self.size,
            self.interval,
            self.skip_last_n,
            self.max_nacks_per_packet,
        );
        interceptor.max_packet_age = self.max_packet_age;
        interceptor.reorder_delay = self.reorder_delay;
        interceptor.round_trip_time = self.round_trip_time;
        interceptor
    }
}

/// Interceptor that generates NACK requests for missing RTP packets.
///
/// This interceptor monitors incoming RTP packets on remote streams,
/// tracks which sequence numbers have been received, and periodically
/// generates RTCP TransportLayerNack packets for missing sequences.
pub struct NackGeneratorInterceptor {
    /// Configuration
    size: u16,
    interval: Duration,
    skip_last_n: u16,
    max_nacks_per_packet: u16,

    /// Next timeout for NACK generation
    next_timeout: Option<Instant>,

    /// Sender SSRC for NACK packets
    sender_ssrc: u32,

    /// Receive logs per remote stream SSRC
    receive_logs: HashMap<u32, ReceiveLog>,

    max_packet_age: Option<Duration>,
    reorder_delay: Duration,
    /// The round-trip time to the senders, measured by the RTCP session when there is one.
    round_trip_time: Option<Duration>,

    /// What has been asked for, per SSRC and missing sequence number.
    requests: HashMap<u32, HashMap<u16, Request>>,

    /// Queue for outgoing NACK packets
    write_queue: VecDeque<TaggedPacket>,
    /// Inbound packets ready for the next interceptor.
    read_queue: VecDeque<TaggedPacket>,
}

impl NackGeneratorInterceptor {
    fn new(size: u16, interval: Duration, skip_last_n: u16, max_nacks_per_packet: u16) -> Self {
        Self {
            read_queue: VecDeque::new(),
            size,
            interval,
            skip_last_n,
            max_nacks_per_packet,
            next_timeout: None,
            sender_ssrc: rand::random(),
            receive_logs: HashMap::new(),
            max_packet_age: Some(DEFAULT_MAX_PACKET_AGE),
            reorder_delay: Duration::ZERO,
            round_trip_time: None,
            requests: HashMap::new(),
            write_queue: VecDeque::new(),
        }
    }

    /// Generate NACKs for all streams with missing packets.
    fn generate_nacks(&mut self, now: Instant) {
        for (&ssrc, receive_log) in &self.receive_logs {
            let missing = receive_log.missing_seq_numbers(self.skip_last_n);
            if missing.is_empty() {
                self.requests.remove(&ssrc);
                continue;
            }

            let requests = self.requests.entry(ssrc).or_default();
            // A packet that arrived, or that the log no longer covers, is forgotten.
            requests.retain(|sequence_number, _| missing.contains(sequence_number));

            let due: Vec<u16> = missing
                .iter()
                .copied()
                .filter(|sequence_number| {
                    let request = requests.entry(*sequence_number).or_insert(Request {
                        missing_since: now,
                        last_asked: None,
                        asked: 0,
                    });
                    // Give up: asked often enough, or too old to be of use.
                    if self.max_nacks_per_packet > 0 && request.asked >= self.max_nacks_per_packet {
                        return false;
                    }
                    let missing_for = now.saturating_duration_since(request.missing_since);
                    if self.max_packet_age.is_some_and(|max| missing_for > max) {
                        return false;
                    }
                    let due = match request.last_asked {
                        // The first request waits out the reordering allowance.
                        None => missing_for >= self.reorder_delay,
                        // The next waits for the retransmission to have had a round trip.
                        Some(last_asked) => self
                            .round_trip_time
                            .is_none_or(|rtt| now.saturating_duration_since(last_asked) >= rtt),
                    };
                    if due {
                        request.last_asked = Some(now);
                        request.asked = request.asked.saturating_add(1);
                    }
                    due
                })
                .collect();

            if due.is_empty() {
                continue;
            }

            // Create NACK packet
            let nack = rtcp::transport_feedbacks::transport_layer_nack::TransportLayerNack {
                sender_ssrc: self.sender_ssrc,
                media_ssrc: ssrc,
                nacks: rtcp::transport_feedbacks::transport_layer_nack::nack_pairs_from_sequence_numbers(
                    &due,
                ),
            };

            self.write_queue.push_back(TaggedPacket {
                now,
                transport: TransportContext::default(),
                message: AttributedPacket::new(Packet::Rtcp(vec![Box::new(nack)])),
            });
        }
    }
}

/// A missing packet and what has been done about it.
struct Request {
    /// When the generator first found it missing.
    missing_since: Instant,
    /// When it was last asked for.
    last_asked: Option<Instant>,
    /// How often it has been asked for.
    asked: u16,
}

impl Protocol<TaggedPacket, TaggedPacket, ()> for NackGeneratorInterceptor {
    type Rout = TaggedPacket;
    type Wout = TaggedPacket;
    type Eout = ();
    type Error = Error;
    type Time = Instant;

    fn handle_read(&mut self, msg: TaggedPacket) -> Result<(), Self::Error> {
        // RFC 4588 5.3: "a receiver MUST stop requesting retransmissions for an SSRC on
        // receiving its BYE" (RFC 3550 6.6: the source has left). Its receive log goes, and
        // with it every gap still open; packets arriving later under that SSRC are not tracked.
        if let Packet::Rtcp(ref rtcp_packets) = msg.message.packet {
            for rtcp_packet in rtcp_packets {
                if let Some(goodbye) = rtcp_packet
                    .as_any()
                    .downcast_ref::<rtcp::goodbye::Goodbye>()
                {
                    for source in &goodbye.sources {
                        self.receive_logs.remove(source);
                        self.requests.remove(source);
                    }
                }
            }
        }

        // The round-trip time the RTCP session measured, for the pace of repeated requests.
        if let Some(crate::RtcpSessionEvent::RoundTripTime { rtt, .. }) =
            msg.message.custom::<crate::RtcpSessionEvent>()
        {
            self.round_trip_time = Some(*rtt);
        }

        // Track incoming RTP packets
        if let Packet::Rtp(ref rtp_packet) = msg.message.packet
            && let Some(receive_log) = self.receive_logs.get_mut(&rtp_packet.header.ssrc)
        {
            receive_log.add(rtp_packet.header.sequence_number);

            // Arm the NACK timer from the first tracked packet's instant. `None` means nothing is
            // scheduled, so the interceptor asks for no wake-up until a stream is actually flowing.
            if self.next_timeout.is_none() {
                self.next_timeout = Some(msg.now + self.interval);
            }
        }

        self.read_queue.push_back(msg);

        Ok(())
    }

    fn poll_read(&mut self) -> Option<Self::Rout> {
        self.read_queue.pop_front()
    }

    fn handle_write(&mut self, msg: TaggedPacket) -> Result<(), Self::Error> {
        self.write_queue.push_back(msg);
        Ok(())
    }

    fn poll_write(&mut self) -> Option<TaggedPacket> {
        // First drain generated NACK packets
        if let Some(pkt) = self.write_queue.pop_front() {
            return Some(pkt);
        }
        None
    }

    fn handle_timeout(&mut self, now: Instant) -> Result<(), Error> {
        if let Some(next_timeout) = self.next_timeout
            && now >= next_timeout
        {
            self.next_timeout = Some(now + self.interval);
            self.generate_nacks(now);
        }
        Ok(())
    }

    fn poll_timeout(&mut self) -> Option<Instant> {
        self.next_timeout
    }
}

impl Interceptor for NackGeneratorInterceptor {
    fn bind_remote_stream(&mut self, info: &StreamInfo) {
        if stream_supports_nack(info)
            && let Some(receive_log) = ReceiveLog::new(self.size)
        {
            self.receive_logs.insert(info.ssrc, receive_log);
        }
    }

    fn unbind_remote_stream(&mut self, info: &StreamInfo) {
        self.receive_logs.remove(&info.ssrc);
        self.requests.remove(&info.ssrc);
    }

    fn bind_local_stream(&mut self, _info: &StreamInfo) {}

    fn unbind_local_stream(&mut self, _info: &StreamInfo) {}
}
