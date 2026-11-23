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

/// How far back the reordering a stream showed is remembered for its allowance.
const REORDERING_WINDOW: Duration = Duration::from_secs(10);
/// The most the learned reordering allowance holds a first request back.
const MAX_REORDERING_ALLOWANCE: Duration = Duration::from_millis(500);
/// How many of a stream's newest advances of the highest sequence number are kept, to tell
/// when the gap a late packet fills was opened.
const ADVANCES_KEPT: usize = 512;

/// The reordering a stream has shown: how late its out-of-order packets came, against when
/// the first packet that overtook each arrived (RFC 4588 6.3: the first request waits for
/// reordering to be ruled out).
#[derive(Default)]
struct Reordering {
    /// The highest sequence number received, and when each newer one first arrived.
    highest: Option<u16>,
    advances: VecDeque<(u16, Instant)>,
    /// When each late packet arrived and how long after its gap opened.
    late: VecDeque<(Instant, Duration)>,
}

impl Reordering {
    fn on_packet(&mut self, now: Instant, seq: u16, asked_for: bool) {
        let newer = |a: u16, b: u16| (1..0x8000).contains(&a.wrapping_sub(b));
        match self.highest {
            Some(highest) if !newer(seq, highest) => {
                // Out of order. A packet that was asked for may be its retransmission: that
                // says nothing about the path's reordering.
                if seq != highest
                    && !asked_for
                    && let Some((_, opened)) = self
                        .advances
                        .iter()
                        .find(|(advanced, _)| newer(*advanced, seq))
                {
                    self.late
                        .push_back((now, now.saturating_duration_since(*opened)));
                }
            }
            _ => {
                self.highest = Some(seq);
                self.advances.push_back((seq, now));
                while self.advances.len() > ADVANCES_KEPT {
                    self.advances.pop_front();
                }
            }
        }
        while let Some((at, _)) = self.late.front() {
            if now.saturating_duration_since(*at) <= REORDERING_WINDOW {
                break;
            }
            self.late.pop_front();
        }
    }

    /// How long a missing packet of this stream may still be on its way: the latest a
    /// reordered packet came in the last ten seconds, with a quarter on top, at most
    /// [`MAX_REORDERING_ALLOWANCE`].
    fn allowance(&self, now: Instant) -> Duration {
        self.late
            .iter()
            .filter(|(at, _)| now.saturating_duration_since(*at) <= REORDERING_WINDOW)
            .map(|(_, late)| *late)
            .max()
            .map_or(Duration::ZERO, |late| {
                late.mul_f64(1.25).min(MAX_REORDERING_ALLOWANCE)
            })
    }
}

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
    /// the request is delayed to allow for reordering). Default: zero.
    ///
    /// On top of it the generator learns each stream's reordering: a first request also
    /// waits for as long as the stream's out-of-order packets arrived late in the last ten
    /// seconds (a quarter more, at most 500 ms), so a path that reorders does not have every
    /// overtaken packet asked for and retransmitted.
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
    /// The retransmission payload type of each bound stream that has one, by SSRC.
    rtx_payload_types: HashMap<u32, u8>,
    /// The `rtx-time` the remote endpoint announced, by retransmission payload type
    /// ([`NackControl::RemoteRtxTime`](super::NackControl::RemoteRtxTime)).
    remote_rtx_times: HashMap<u8, Duration>,
    reorder_delay: Duration,
    /// The round-trip time to the senders, measured by the RTCP session when there is one.
    round_trip_time: Option<Duration>,

    /// What has been asked for, per SSRC and missing sequence number.
    requests: HashMap<u32, HashMap<u16, Request>>,
    /// The reordering each stream showed.
    reordering: HashMap<u32, Reordering>,

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
            rtx_payload_types: HashMap::new(),
            remote_rtx_times: HashMap::new(),
            reorder_delay: Duration::ZERO,
            round_trip_time: None,
            requests: HashMap::new(),
            reordering: HashMap::new(),
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

            // RFC 4588 8.1: past the sender's `rtx-time` it no longer has the packet. The
            // shorter of that and the configured age is how long a packet is asked for.
            let rtx_time = self
                .rtx_payload_types
                .get(&ssrc)
                .and_then(|payload_type_rtx| self.remote_rtx_times.get(payload_type_rtx))
                .copied();
            let max_packet_age = match (self.max_packet_age, rtx_time) {
                (Some(age), Some(rtx_time)) => Some(age.min(rtx_time)),
                (age, rtx_time) => age.or(rtx_time),
            };

            let reorder_delay = self.reorder_delay.max(
                self.reordering
                    .get(&ssrc)
                    .map_or(Duration::ZERO, |reordering| reordering.allowance(now)),
            );
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
                    if max_packet_age.is_some_and(|max| missing_for > max) {
                        return false;
                    }
                    let due = match request.last_asked {
                        // The first request waits out the reordering allowance.
                        None => missing_for >= reorder_delay,
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
                        self.reordering.remove(source);
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
            let ssrc = rtp_packet.header.ssrc;
            let seq = rtp_packet.header.sequence_number;
            let asked_for = self
                .requests
                .get(&ssrc)
                .and_then(|requests| requests.get(&seq))
                .is_some_and(|request| request.last_asked.is_some());
            self.reordering
                .entry(ssrc)
                .or_default()
                .on_packet(msg.now, seq, asked_for);

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
        if let Some(super::NackControl::RemoteRtxTime {
            payload_type_rtx,
            rtx_time,
        }) = msg.message.custom::<super::NackControl>()
        {
            match rtx_time {
                Some(rtx_time) => self.remote_rtx_times.insert(*payload_type_rtx, *rtx_time),
                None => self.remote_rtx_times.remove(payload_type_rtx),
            };
        }
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
            match info.payload_type_rtx {
                Some(payload_type_rtx) => {
                    self.rtx_payload_types.insert(info.ssrc, payload_type_rtx)
                }
                None => self.rtx_payload_types.remove(&info.ssrc),
            };
        }
    }

    fn unbind_remote_stream(&mut self, info: &StreamInfo) {
        self.receive_logs.remove(&info.ssrc);
        self.requests.remove(&info.ssrc);
        self.reordering.remove(&info.ssrc);
        self.rtx_payload_types.remove(&info.ssrc);
    }

    fn bind_local_stream(&mut self, _info: &StreamInfo) {}

    fn unbind_local_stream(&mut self, _info: &StreamInfo) {}
}
