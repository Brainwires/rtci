//! NACK Responder Interceptor - Responds to NACK requests by retransmitting packets.

use super::send_buffer::SendBuffer;
use super::stream_supports_nack;
use crate::Interceptor;
use crate::cc::probe::ProbeRequest;
use crate::stream_info::StreamInfo;
use crate::{Attribute, AttributedPacket, Packet, TaggedPacket};
use sansio::Protocol;
use shared::TransportContext;
use shared::error::Error;
use shared::marshal::MarshalSize;
use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

/// Builder for the NackResponderInterceptor.
///
/// # Example
///
/// ```
/// use rtci_interceptor::{Slot, Registry, NackResponderBuilder};
///
/// let chain = Registry::new()
///     .with(Slot::NackResponder, NackResponderBuilder::new()
///         .with_size(1024)
///         .build())
///     .build();
/// ```
pub struct NackResponderBuilder {
    /// Size of the send buffer (must be power of 2: 1, 2, 4, ..., 32768).
    size: u16,
    /// How long a sent packet stays available for retransmission.
    max_packet_age: Option<Duration>,
    /// How retransmissions are held to the congestion controller's target.
    rate_limit: RetransmissionRateLimit,
    /// The most of the target the retransmission reserve takes.
    max_reserve_fraction: f64,
}

impl Default for NackResponderBuilder {
    fn default() -> Self {
        Self {
            size: 1024,
            max_packet_age: None,
            rate_limit: RetransmissionRateLimit::default(),
            max_reserve_fraction: MAX_RETRANSMISSION_RESERVE,
        }
    }
}

/// How the NACK responder holds its retransmissions to the congestion controller's target
/// (RFC 4588 section 7), read from [`Attribute::TargetBitrateChanged`] as it passes on the read
/// leg. Until a target has passed, and in a chain without a congestion controller, nothing is
/// held back.
///
/// The rate is counted over the last [`RETRANSMISSION_RATE_WINDOW`]. A NACKed packet that
/// does not fit now waits, oldest request first, and leaves when the window has room for it
/// ([`poll_timeout`](sansio::Protocol::poll_timeout) is that instant), for as long as the
/// receiver keeps asking for it ([`PENDING_REQUEST_LIFETIME`]). Section 7 lets the sender
/// "selectively retransmit only the packets that it deems important and ignore NACK messages
/// for other packets in order to limit the bitrate": a packet still asked for is the one
/// deemed important, one the receiver stopped asking for is dropped.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum RetransmissionRateLimit {
    /// RFC 4588 section 7, both halves: "the acceptable packet rate and bitrate include both
    /// the original and retransmitted data", and "the sender SHOULD NOT send retransmission
    /// packets without reducing the packet rate and bitrate of the original stream (for
    /// example, by encoding the data at a lower rate)".
    ///
    /// Retransmissions take what the original packets of every local stream leave of the
    /// target. While retransmissions wait or were sent within the window, the target reported
    /// for the original media is the congestion controller's less a **retransmission
    /// reserve**: on the read leg [`Attribute::TargetBitrateChanged`] is lowered by it on its
    /// way to the application, and [`RetransmissionReserve`] rides down the write leg to the
    /// congestion controller, whose handle (`GccHandle::target_bitrate_bps`,
    /// `CongestionControlHandle::target_bitrate`) reports the lowered target and keeps the
    /// estimate itself readable (`estimate_bps`, `estimate_bitrate`). An encoder that follows
    /// the target leaves the reserve free, so the repairs have room.
    ///
    /// The reserve is what the waiting requests need to leave within about one round trip
    /// (their octets over the round-trip time the RTCP session measured, at most
    /// [`RETRANSMISSION_RATE_WINDOW`]), or the retransmission rate of the window when that is
    /// more, and never more than [`MAX_RETRANSMISSION_RESERVE`] of the target
    /// ([`NackResponderBuilder::with_max_reserve_fraction`]). It is released as the requests
    /// are served and the retransmissions leave the window: with nothing waiting and nothing
    /// retransmitted within the last window it is zero.
    ///
    /// **At the congestion controller's floor.** The controller's minimum bit rate is this
    /// engine's setting, not the RFC's, and the controller announces it with its target
    /// ([`MinimumTarget`]). The original media is never told less than that minimum (the least
    /// the application set its media to need). When lowering the original media by the reserve
    /// would take it under that floor (target − reserve < minimum), it cannot make the room:
    /// an encoder at its own minimum already fills the floor (in the capacity-cap test, 30
    /// kbit/s of video and 80 kbit/s of audio against a 100 kbit/s target), and the rule above
    /// would leave the repairs nothing for as long as the estimate stays near the floor. There
    /// the retransmissions of packets still asked for take the window's room first: they may
    /// send up to the target within the window, whatever the original packets took, and the
    /// original media is told the target less the reserve. Section 7 lets the sender
    /// "selectively retransmit only the packets that it deems important"; a packet still asked
    /// for is the one deemed important. An application at its minimum adds its own excess
    /// over the floor; the retransmissions never go over the target.
    ///
    /// What holds the sum on the wire when the application ignores the lowered target: with
    /// a pacer in the chain (the default interceptor set) the pacer sends at the controller's
    /// target, retransmissions and media alike; without one (a chain of NACK, TWCC and GCC
    /// alone) it is this rule: above the floor the retransmissions take only what the
    /// original packets leave, so the engine never adds to an application's excess; near the
    /// floor (target under the minimum plus the reserve, at most twice the minimum with the
    /// default reserve) they take at most the target.
    #[default]
    WithinTarget,
    /// A rate limiter on the retransmissions alone, its maximum the target (the form of
    /// libwebrtc's `RtpSender` when it is given a `retransmission_rate_limiter`,
    /// `modules/rtp_rtcp/source/rtp_sender.cc`): the retransmissions stay under the target
    /// whatever the original packets take, and the target reported for the original media is
    /// not lowered, so the sum may reach twice the target. A setting in no behaviour profile:
    /// libwebrtc gives its video senders no such limiter (`call/rtp_video_sender.cc:292-354`
    /// at a222406d; `rtp_rtcp_interface.h:92` defaults it to null) and lowers the encoder
    /// target by the protection share instead. Measured in
    /// `tests/capacity_cap_video_rtc2rtc.rs` against the default: longest freeze 0.84 to
    /// 1.29 s against 0.83 to 1.24 s, 17 to 27 retransmissions dropped at the capped link
    /// against 14 to 17.
    UpToTarget,
    /// No limit beyond the per-stream budget (one retransmission per original packet sent): the
    /// fork's behaviour before. Retransmissions are then not congestion controlled.
    Unlimited,
}

/// The window [`RetransmissionRateLimit`] measures the rates over (libwebrtc's
/// `kRetransmitWindowSizeMs`).
pub const RETRANSMISSION_RATE_WINDOW: Duration = Duration::from_secs(1);

/// The most of the congestion controller's target the retransmission reserve of
/// [`RetransmissionRateLimit::WithinTarget`] takes, by default: half.
pub const MAX_RETRANSMISSION_RESERVE: f64 = 0.5;

/// A request that waits for room is dropped when the receiver has not asked for the packet
/// again within this long, or within two round trips when that is longer: a receiver asks
/// again every round trip while the packet is missing, so one that stopped asking has the
/// packet or no longer wants it.
pub const PENDING_REQUEST_LIFETIME: Duration = Duration::from_secs(1);

/// The shortest round trip the reserve spreads the waiting requests over.
const MIN_RESERVE_HORIZON: Duration = Duration::from_millis(10);

/// The retransmission reserve of [`RetransmissionRateLimit::WithinTarget`], in bits per
/// second: the part of the congestion controller's target kept for retransmissions, which the
/// target reported for the original media leaves out.
///
/// The NACK responder sends it down the write leg (on a packet of its own, an empty RTCP
/// carrier, when it changes), so a congestion controller wire-ward of it reports the lowered
/// target through its handle. Read with [`AttributedPacket::custom`](crate::AttributedPacket::custom).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct RetransmissionReserve {
    /// The reserve, bits per second.
    pub bits_per_second: f64,
}

/// Rides with [`Attribute::TargetBitrateChanged`]: the congestion controller's minimum bit
/// rate, the floor its target never goes under. Where lowering the original media by the
/// retransmission reserve would take it under this floor the NACK responder lets the
/// retransmissions take the window's room first ([`RetransmissionRateLimit::WithinTarget`]).
/// Read with [`AttributedPacket::custom`](crate::AttributedPacket::custom).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct MinimumTarget {
    /// The minimum, bits per second.
    pub bits_per_second: f64,
}

/// The target for the original media: the controller's `target` less the `reserve`, never
/// under the controller's `minimum` (the least the application set its media to need; near it
/// the retransmissions take the room first instead, see [`RetransmissionRateLimit::WithinTarget`]).
fn media_target(target: f64, reserve: f64, minimum: f64) -> f64 {
    (target - reserve).max(minimum.min(target)).max(0.0)
}

/// How much the reported reserve may move before a new one is announced: 5 % of the target,
/// at least 5 kbit/s, and any change to or from zero.
fn reserve_moved(announced: f64, reserve: f64, target_bps: f64) -> bool {
    (announced == 0.0) != (reserve == 0.0)
        || (reserve - announced).abs() >= (0.05 * target_bps).max(5_000.0)
}

/// Octets sent within the last [`RETRANSMISSION_RATE_WINDOW`].
#[derive(Default)]
struct RateWindow {
    sent: VecDeque<(Instant, usize)>,
    octets: usize,
}

/// The instant at which the entries of `windows` leaving [`RETRANSMISSION_RATE_WINDOW`] have
/// freed `deficit` octets, oldest first; `None` if all of them together free less.
fn freed_at(windows: &[&RateWindow], deficit: usize) -> Option<Instant> {
    let mut cursors = vec![0usize; windows.len()];
    let mut freed = 0usize;
    loop {
        let (index, &(at, octets)) = windows
            .iter()
            .zip(&cursors)
            .enumerate()
            .filter_map(|(index, (window, &cursor))| window.sent.get(cursor).map(|e| (index, e)))
            .min_by_key(|(_, (at, _))| *at)?;
        cursors[index] += 1;
        freed += octets;
        if freed >= deficit {
            return Some(at + RETRANSMISSION_RATE_WINDOW);
        }
    }
}

/// A NACKed packet waiting for room in the rate limit.
struct PendingRetransmission {
    ssrc: u32,
    sequence_number: u16,
    /// The packet asked for: its serial in the stream. The request is for that packet, not
    /// for whichever has the sequence number when there is room.
    packet: u64,
    /// The size its retransmission has on the wire.
    octets: usize,
}

impl RateWindow {
    fn expire(&mut self, now: Instant) {
        while let Some(&(at, octets)) = self.sent.front() {
            if now.saturating_duration_since(at) < RETRANSMISSION_RATE_WINDOW {
                break;
            }
            self.sent.pop_front();
            self.octets -= octets;
        }
    }

    fn add(&mut self, now: Instant, octets: usize) {
        self.sent.push_back((now, octets));
        self.octets += octets;
    }

    /// Takes back `octets` added at `at`, if the entry is still in the window.
    fn forget(&mut self, at: Instant, octets: usize) {
        if let Some(entry) = self
            .sent
            .iter_mut()
            .rev()
            .find(|(sent, size)| *sent == at && *size == octets)
        {
            entry.1 = 0;
            self.octets -= octets;
        }
    }
}

impl NackResponderBuilder {
    /// Create a new builder with default settings.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the size of the send buffer.
    ///
    /// Size must be a power of 2 between 1 and 32768 (inclusive).
    /// Larger buffers can retransmit older packets but use more memory.
    pub fn with_size(mut self, size: u16) -> Self {
        self.size = size;
        self
    }

    /// Set how long a sent packet is kept for retransmission: the `rtx-time` of RFC 4588
    /// 8.1, when one is signalled. A NACK for a packet sent longer ago is not answered.
    ///
    /// Default: `None`, a packet is available for as long as the buffer holds it.
    pub fn with_max_packet_age(mut self, max_packet_age: Option<Duration>) -> Self {
        self.max_packet_age = max_packet_age;
        self
    }

    /// Set how retransmissions are held to the congestion controller's target (RFC 4588
    /// section 7). Default: [`RetransmissionRateLimit::WithinTarget`], the RFC's form;
    /// [`RetransmissionRateLimit::UpToTarget`] is the limiter libwebrtc's `RtpSender` has
    /// when it is given one.
    pub fn with_rate_limit(mut self, rate_limit: RetransmissionRateLimit) -> Self {
        self.rate_limit = rate_limit;
        self
    }

    /// Set the most of the congestion controller's target the retransmission reserve of
    /// [`RetransmissionRateLimit::WithinTarget`] takes, from 0 (no reserve: the target is
    /// never lowered) to 1. Default: [`MAX_RETRANSMISSION_RESERVE`].
    pub fn with_max_reserve_fraction(mut self, fraction: f64) -> Self {
        self.max_reserve_fraction = if fraction.is_finite() {
            fraction.clamp(0.0, 1.0)
        } else {
            MAX_RETRANSMISSION_RESERVE
        };
        self
    }

    /// Build the interceptor.
    pub fn build(self) -> NackResponderInterceptor {
        let mut interceptor = NackResponderInterceptor::new(self.size);
        interceptor.max_packet_age = self.max_packet_age;
        interceptor.rate_limit = self.rate_limit;
        interceptor.max_reserve_fraction = self.max_reserve_fraction;
        interceptor
    }
}

/// The RID header extension (RFC 8852 3.1).
const RTP_STREAM_ID_URI: &str = "urn:ietf:params:rtp-hdrext:sdes:rtp-stream-id";
/// The repaired-RID header extension (RFC 8852 3.2), which an RTX packet carries instead.
const REPAIRED_RTP_STREAM_ID_URI: &str = "urn:ietf:params:rtp-hdrext:sdes:repaired-rtp-stream-id";

/// The one-byte or two-byte id `info` negotiated for `uri`.
fn extension_id(info: &StreamInfo, uri: &str) -> Option<u8> {
    info.rtp_header_extensions
        .iter()
        .find(|extension| extension.uri == uri)
        .and_then(|extension| u8::try_from(extension.id).ok())
}

/// Per-stream state for the responder.
struct LocalStream {
    /// Buffer of sent packets for retransmission.
    send_buffer: SendBuffer,
    /// RTX SSRC for RFC4588 retransmission (if configured).
    ssrc_rtx: Option<u32>,
    /// RTX payload type for RFC4588 retransmission (if configured).
    payload_type_rtx: Option<u8>,
    /// Sequence number counter for RTX packets.
    rtx_sequence_number: u16,
    /// The sequence number of the packet sent last, and when.
    last_sent: Option<(u16, Instant)>,
    /// When each sequence number was last retransmitted, so a repeated NACK within
    /// [`MIN_RETRANSMIT_INTERVAL`] does not resend it again.
    last_retransmit: HashMap<u16, Instant>,
    /// The RID extension id, if negotiated.
    rid_extension_id: Option<u8>,
    /// The repaired-RID extension id, if negotiated.
    repaired_rid_extension_id: Option<u8>,
    /// Retransmissions this stream may still send: one more for each original packet sent, up
    /// to the send buffer's size, and one less per retransmission. A NACK naming the whole buffer
    /// may be answered once in full, but repeated NACKs cannot make the stream retransmit faster
    /// than it sends, so the peer cannot turn its NACKs into a multiple of our send rate.
    retransmit_budget: usize,
    /// The budget's ceiling: the send buffer's size.
    retransmit_budget_max: usize,
    /// When each buffered packet was sent, by its place in the send buffer (the sequence
    /// number modulo the buffer size), with the sequence number the entry is for and the
    /// packet's serial (see `written`).
    sent_at: Vec<Option<(u16, Instant, u64)>>,
    /// How many packets of the stream were written: each packet's serial, its place in the
    /// order written, which no later packet of the stream has again whatever its 16-bit
    /// sequence number (the extended sequence number, without trusting the application's
    /// numbering to be continuous).
    written: u64,
    /// What is remembered of the latest retransmission of a packet, by its sequence number.
    /// Each entry names its packet by the serial, so the packet that has the 16-bit number a
    /// cycle later does not inherit it, and each ends by the clock (see [`RepairState`]).
    /// Never more entries than the send buffer has places.
    repairs: HashMap<u16, Repair>,
    /// The sequence number each recent RTX packet of this stream was given → the packet it
    /// repairs and when the retransmission was made, oldest first in `repairs_order`: how
    /// RFC 8888 feedback, which reports the RTX stream under its own sequence numbers, names
    /// a retransmission.
    repairs_by_rtx: HashMap<u16, (u16, Instant)>,
    repairs_order: VecDeque<(u16, Instant)>,
}

/// What is remembered of the retransmissions of one packet.
#[derive(Debug, Clone, Copy)]
struct Repair {
    /// The packet: its serial in the stream.
    packet: u64,
    /// When the first retransmission of the packet that is still remembered was made: a
    /// report on a retransmission made before it is about an earlier packet of the same
    /// 16-bit number.
    first_made: Instant,
    /// When the latest retransmission was made.
    made: Instant,
    state: RepairState,
}

/// Where the latest retransmission of a packet is, as far as the sender knows. Every state
/// ends by the engine's clock (the instant of the request, write, notice or timeout at hand),
/// whether or not another report ever comes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RepairState {
    /// Waiting in the pacer since it was made, for [`IN_PACER_LIFETIME`] at most. The pacer
    /// holds one retransmission per (SSRC, 16-bit sequence number), so this one state holds
    /// for whatever packet has the number: nothing is made for it meanwhile.
    InPacer,
    /// Left toward the wire at `left`, no report yet: a request is held until two round trips
    /// and [`REPAIR_REPORT_MARGIN`] after.
    Unreported { left: Instant },
    /// Left at `left`, and the wait for its report ran out: requests are answered. A report
    /// still counts until [`RETRANSMISSION_REPORT_HORIZON`](crate::RETRANSMISSION_REPORT_HORIZON)
    /// after it left.
    Overdue { left: Instant },
    /// Reported received at `reported`: requests are declined for [`DELIVERED_MEMORY`].
    Delivered { reported: Instant },
}

impl LocalStream {
    /// The serial of the packet now held under `sequence_number`.
    fn packet(&self, sequence_number: u16) -> Option<u64> {
        self.sent_at[usize::from(sequence_number) % self.sent_at.len()]
            .filter(|(held, _, _)| *held == sequence_number)
            .map(|(_, _, serial)| serial)
    }

    /// Remembers `repair` of the packet under `sequence_number`. The entries stay within the
    /// send buffer's places: when they are all taken, those whose packet the buffer no longer
    /// holds go (there is one, since a packet the buffer holds is being added).
    fn remember_repair(&mut self, sequence_number: u16, repair: Repair) {
        if self.repairs.len() >= self.sent_at.len() && !self.repairs.contains_key(&sequence_number)
        {
            let sent_at = &self.sent_at;
            self.repairs.retain(|sequence_number, repair| {
                sent_at[usize::from(*sequence_number) % sent_at.len()].is_some_and(
                    |(held, _, serial)| held == *sequence_number && serial == repair.packet,
                )
            });
        }
        if self.repairs.len() < self.sent_at.len() || self.repairs.contains_key(&sequence_number) {
            self.repairs.insert(sequence_number, repair);
        }
    }
}

/// The most octets one probe cluster is filled with.
const MAX_PROBE_FILL_OCTETS: usize = crate::cc::probe::PROBE_MAX_OCTETS;

/// The most packets one probe cluster is filled with.
const MAX_PROBE_FILL_PACKETS: usize = 128;

/// The padding octets of one probe packet: the most RFC 3550 section 5.1 padding holds (its
/// count is one octet).
pub const PROBE_PADDING_OCTETS: u8 = 255;

/// A sequence number is retransmitted at most once per this interval, however often it is
/// NACKed. Receivers repeat NACKs while the repair is in flight; without this a peer can make
/// us resend the same packets as fast as it can send RTCP (an amplifier).
pub const MIN_RETRANSMIT_INTERVAL: std::time::Duration = std::time::Duration::from_millis(20);

/// How long after its retransmission a packet is not retransmitted again however often it is
/// asked for: [`MIN_RETRANSMIT_INTERVAL`]. libwebrtc waits a round trip
/// (`modules/rtp_rtcp/source/rtp_packet_history.cc`, `VerifyRtt`); measured here that loses
/// repairs: when a retransmission is itself lost, the receiver's next request can fall inside
/// that round trip and be ignored, and the one after waits for RFC 4585's early-feedback hold
/// (`tests/vp8_nack_jitter_buffer_rtc2rtc.rs`, seed 4: packet 1272 retransmitted again 1.42 s
/// after the lost copy, after the 2 s jitter buffer had played past it). A request that
/// crossed a repair in flight costs one duplicate instead.
fn resend_interval(round_trip_time: Option<Duration>) -> Duration {
    let _ = round_trip_time;
    MIN_RETRANSMIT_INTERVAL
}

/// How long after a retransmission left the transport-wide feedback on it is waited for, beyond
/// two round trips, before a request for the same packet is answered without it: the receiver's
/// feedback interval (100 ms by default, `TwccReceiverBuilder`).
pub const REPAIR_REPORT_MARGIN: Duration = Duration::from_millis(100);

/// How long a retransmission the feedback reported received is remembered: a request for its
/// packet within this long of the report crossed it and is not answered. The time is the
/// request's own (the engine's clock), so the memory ends whether or not another report
/// comes: a request after it is answered, which is also what bounds a receiver whose feedback
/// reports retransmissions it did not get. It is the memory of one packet (SSRC and extended
/// sequence number): it ends with the packet's place in the send buffer or its `rtx-time`,
/// past which no request for it is answered anyway, and the packet that has the same 16-bit
/// number a cycle later starts without it.
pub const DELIVERED_MEMORY: Duration = Duration::from_secs(4);

/// What a request for a packet that was retransmitted before gets
/// ([`RetransmissionsReported`](crate::RetransmissionsReported)).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Repeat {
    /// Answered as any request.
    Answer,
    /// Kept waiting until the feedback on the earlier retransmission comes, at most until then.
    Hold(Instant),
    /// Not answered: the earlier retransmission arrived.
    Decline,
}

/// How long a retransmission is taken to wait in the pacer at most: longer than the pacer's
/// queue time bound (2 s by default), past which the pacer drops it and says so.
const IN_PACER_LIFETIME: Duration = Duration::from_secs(4);

/// Most retransmissions queued and not yet taken by `poll_write`. Past it further NACKed
/// packets are not queued until the queue drains.
pub const MAX_QUEUED_RETRANSMISSIONS: usize = 1024;

/// The most retransmission SSRCs whose next sequence number is remembered after their stream
/// was unbound.
const MAX_REMEMBERED_RTX_SSRCS: usize = 1024;

/// Interceptor that responds to NACK requests by retransmitting packets.
///
/// This interceptor buffers outgoing RTP packets on local streams and
/// retransmits them when RTCP TransportLayerNack packets are received.
pub struct NackResponderInterceptor {
    /// Configuration
    size: u16,

    /// How long a sent packet stays available for retransmission (`rtx-time`).
    max_packet_age: Option<Duration>,
    /// The `rtx-time` this endpoint announced, by retransmission payload type
    /// ([`NackControl::LocalRtxTime`](super::NackControl::LocalRtxTime)): it replaces
    /// `max_packet_age` for the streams repaired under that payload type.
    local_rtx_times: HashMap<u8, Duration>,

    /// Send buffers per local stream SSRC
    streams: HashMap<u32, LocalStream>,

    /// The next sequence number of each retransmission SSRC this interceptor has sent on,
    /// kept when its stream is unbound: a stream bound again with the same RTX SSRC (a
    /// renegotiation re-binding it) carries on from here. Starting over would repeat sequence
    /// numbers on a live SSRC, which SRTP refuses to protect twice (the packet index is the
    /// SSRC's rollover counter and sequence number).
    rtx_sequence_numbers: HashMap<u32, u16>,

    /// Queue for retransmitted packets
    write_queue: VecDeque<TaggedPacket>,
    /// Retransmissions in `write_queue` not yet taken by `poll_write`.
    retransmissions_queued: usize,
    /// Inbound packets ready for the next interceptor.
    read_queue: VecDeque<TaggedPacket>,
    /// The RTP session (transport) of each SSRC, from the peer connection's
    /// [`RtpSessionAssignment`](crate::RtpSessionAssignment)s; empty while there is one.
    sessions: HashMap<u32, usize>,

    /// See [`NackResponderBuilder::with_rate_limit`].
    rate_limit: RetransmissionRateLimit,
    /// The congestion controller's latest target, bits per second.
    target_bps: Option<f64>,
    /// The controller's minimum ([`MinimumTarget`]), bits per second.
    minimum_bps: Option<f64>,
    /// The original packets of the local streams, and the retransmissions, sent lately.
    originals: RateWindow,
    retransmitted: RateWindow,
    /// See [`NackResponderBuilder::with_max_reserve_fraction`].
    max_reserve_fraction: f64,
    /// The round trip the RTCP session measured last.
    round_trip_time: Option<Duration>,
    /// NACKed packets waiting for room, oldest request first.
    pending: VecDeque<PendingRetransmission>,
    /// When each waiting packet was last asked for, and which packet it is (its serial).
    pending_asked: HashMap<(u32, u16), (Instant, u64)>,
    /// The octets of `pending`.
    pending_octets: usize,
    /// The reserve last announced, bits per second.
    announced_reserve: f64,
    /// When the next waiting retransmission can leave, worked out since the last change:
    /// `None` when it has to be worked out again.
    release_at: Option<Option<Instant>>,
    /// Whether a pacer wire-ward reports its retransmissions' departures (it has once).
    pacer_reports: bool,
    /// Whether the pacer tells the source to pause ([`PacerPause`](crate::PacerPause)): the
    /// target the application reads is zero.
    paused: bool,
    /// Whether transport-wide feedback reports on the retransmissions
    /// ([`RetransmissionsReported`](crate::RetransmissionsReported)): it has once.
    repairs_reported: bool,
}

impl NackResponderInterceptor {
    fn new(size: u16) -> Self {
        Self {
            read_queue: VecDeque::new(),
            size,
            max_packet_age: None,
            local_rtx_times: HashMap::new(),
            streams: HashMap::new(),
            rtx_sequence_numbers: HashMap::new(),
            write_queue: VecDeque::new(),
            retransmissions_queued: 0,
            sessions: HashMap::new(),
            rate_limit: RetransmissionRateLimit::default(),
            target_bps: None,
            minimum_bps: None,
            originals: RateWindow::default(),
            retransmitted: RateWindow::default(),
            max_reserve_fraction: MAX_RETRANSMISSION_RESERVE,
            round_trip_time: None,
            pending: VecDeque::new(),
            pending_asked: HashMap::new(),
            pending_octets: 0,
            announced_reserve: 0.0,
            release_at: None,
            pacer_reports: false,
            paused: false,
            repairs_reported: false,
        }
    }

    /// Octets at `bits_per_second` over the window.
    fn window_octets(bits_per_second: f64) -> usize {
        (bits_per_second / 8.0 * RETRANSMISSION_RATE_WINDOW.as_secs_f64()) as usize
    }

    /// The octets retransmissions may still take within the window, `None` for no limit.
    fn retransmission_allowance(&mut self, now: Instant) -> Option<usize> {
        let target_bps = self.target_bps?;
        self.originals.expire(now);
        self.retransmitted.expire(now);
        let target = Self::window_octets(target_bps);
        let limit = match self.rate_limit {
            RetransmissionRateLimit::WithinTarget => {
                if self.at_floor() {
                    // Near the floor the retransmissions take the window's room first.
                    target
                } else {
                    // What the originals leave, or the reserve the original media has already
                    // been lowered by, whichever is more.
                    target
                        .saturating_sub(self.originals.octets)
                        .max(Self::window_octets(self.announced_reserve))
                }
            }
            RetransmissionRateLimit::UpToTarget => target,
            RetransmissionRateLimit::Unlimited => return None,
        };
        Some(limit.saturating_sub(self.retransmitted.octets))
    }

    /// Whether lowering the original media by the reserve would take it under the
    /// controller's minimum (see [`RetransmissionRateLimit::WithinTarget`]).
    fn at_floor(&self) -> bool {
        self.rate_limit == RetransmissionRateLimit::WithinTarget
            && self.announced_reserve > 0.0
            && match (self.target_bps, self.minimum_bps) {
                (Some(target), Some(minimum)) => target - self.announced_reserve < minimum,
                _ => false,
            }
    }

    /// The retransmission reserve at `now`, bits per second (see
    /// [`RetransmissionRateLimit::WithinTarget`]); zero under the other rules.
    fn reserve(&mut self, now: Instant) -> f64 {
        let Some(target_bps) = self.target_bps else {
            return 0.0;
        };
        if self.rate_limit != RetransmissionRateLimit::WithinTarget {
            return 0.0;
        }
        self.retransmitted.expire(now);
        if self.pending.is_empty() && self.retransmitted.octets == 0 {
            return 0.0;
        }
        let horizon = self
            .round_trip_time
            .unwrap_or(RETRANSMISSION_RATE_WINDOW)
            .clamp(MIN_RESERVE_HORIZON, RETRANSMISSION_RATE_WINDOW);
        let needed = self.pending_octets as f64 * 8.0 / horizon.as_secs_f64();
        let in_use =
            self.retransmitted.octets as f64 * 8.0 / RETRANSMISSION_RATE_WINDOW.as_secs_f64();
        needed
            .max(in_use)
            .min(self.max_reserve_fraction * target_bps)
    }

    /// How long a waiting request stays without being asked for again.
    fn pending_lifetime(&self) -> Duration {
        self.round_trip_time
            .map_or(PENDING_REQUEST_LIFETIME, |rtt| {
                (rtt * 2).max(PENDING_REQUEST_LIFETIME)
            })
    }

    /// Drops the waiting requests nobody asked for again within their lifetime.
    fn expire_pending(&mut self, now: Instant) {
        let lifetime = self.pending_lifetime();
        let before = self.pending.len();
        let asked = &mut self.pending_asked;
        let octets = &mut self.pending_octets;
        self.pending.retain(|entry| {
            let key = (entry.ssrc, entry.sequence_number);
            let fresh = asked
                .get(&key)
                .is_some_and(|(at, _)| now.saturating_duration_since(*at) <= lifetime);
            if !fresh {
                asked.remove(&key);
                *octets -= entry.octets;
            }
            fresh
        });
        if self.pending.len() != before {
            self.release_at = None;
        }
    }

    /// The wire size of the retransmission of `packet` on `stream`.
    fn retransmission_size(stream: &LocalStream, packet: &rtp::Packet) -> usize {
        packet.marshal_size()
            + if stream.ssrc_rtx.is_some() && stream.payload_type_rtx.is_some() {
                2
            } else {
                0
            }
    }

    /// Whether `seq` of `stream` may be retransmitted at `now` (it is still held, not older
    /// than the `rtx-time`), and its retransmission's size.
    fn retransmittable(&self, stream: &LocalStream, seq: u16, now: Instant) -> Option<usize> {
        let original_packet = stream.send_buffer.get(seq)?;
        // RFC 4588 8.1 (`rtx-time`): a packet is kept for retransmission that long. What
        // the session description announced for the stream's retransmission format is
        // the value; without one, the configured age.
        if let Some(max_packet_age) = stream
            .payload_type_rtx
            .and_then(|payload_type_rtx| self.local_rtx_times.get(&payload_type_rtx))
            .copied()
            .or(self.max_packet_age)
            && let Some((_, sent, _)) = stream.sent_at[usize::from(seq) % stream.sent_at.len()]
                .filter(|(sequence_number, _, _)| *sequence_number == seq)
            && now.saturating_duration_since(sent) > max_packet_age
        {
            return None;
        }
        Some(Self::retransmission_size(stream, original_packet))
    }

    /// Sends the waiting retransmissions the rate limit has room for, oldest request first.
    fn release(&mut self, now: Instant) {
        let mut allowance = self.retransmission_allowance(now);
        let resend_interval = resend_interval(self.round_trip_time);
        // Waits for the feedback that ended are over, reached below or not.
        self.expire_repairs(now);
        // A request held for the feedback on an earlier retransmission keeps its place; the
        // ones behind it are served meanwhile.
        let mut index = 0;
        while let Some(entry) = self.pending.get(index) {
            if self.retransmissions_queued >= MAX_QUEUED_RETRANSMISSIONS {
                break;
            }
            let (ssrc, seq) = (entry.ssrc, entry.sequence_number);
            if !self.holds(ssrc, seq, entry.packet) {
                // The packet asked for is gone; the one that has its number was not asked for.
                self.remove_pending(index);
                continue;
            }
            match self.repeat_state((ssrc, seq), now) {
                Repeat::Hold(_) => {
                    index += 1;
                    continue;
                }
                Repeat::Decline => {
                    self.remove_pending(index);
                    continue;
                }
                Repeat::Answer => {}
            }
            let in_pacer = self.in_pacer(ssrc, seq, now);
            let current = self.streams.get(&ssrc).and_then(|stream| {
                let recently = stream
                    .last_retransmit
                    .get(&seq)
                    .is_some_and(|at| now.saturating_duration_since(*at) < resend_interval)
                    || in_pacer;
                if recently {
                    None
                } else {
                    self.retransmittable(stream, seq, now)
                        .map(|size| (size, stream.retransmit_budget))
                }
            });
            let Some((size, budget)) = current else {
                // Gone from the buffer, too old, its stream unbound, or just sent.
                self.remove_pending(index);
                continue;
            };
            if budget == 0 {
                // Waits for the next original packet, which adds to the budget.
                break;
            }
            if let Some(left) = allowance.as_mut() {
                if size > *left {
                    break;
                }
                *left -= size;
            }
            self.remove_pending(index);
            self.retransmit(now, ssrc, seq, size);
        }
    }

    fn remove_pending(&mut self, index: usize) {
        if let Some(entry) = self.pending.remove(index) {
            self.pending_asked
                .remove(&(entry.ssrc, entry.sequence_number));
            self.pending_octets -= entry.octets;
            self.release_at = None;
        }
    }

    /// Queues the retransmission of `seq` of the stream `ssrc`.
    fn retransmit(&mut self, now: Instant, ssrc: u32, seq: u16, size: usize) {
        let earlier = self.repair(ssrc, seq, now);
        let Some(stream) = self.streams.get_mut(&ssrc) else {
            return;
        };
        if stream.send_buffer.get(seq).is_none() {
            return;
        }
        stream.last_retransmit.insert(seq, now);
        if let Some(packet) = stream.packet(seq) {
            // An earlier retransmission of this same packet still remembered: reports on it
            // go on counting.
            let first_made = earlier
                .filter(|earlier| earlier.packet == packet)
                .map_or(now, |earlier| earlier.first_made);
            let state = if self.pacer_reports {
                RepairState::InPacer
            } else {
                // Without a pacer it leaves now.
                RepairState::Unreported { left: now }
            };
            stream.remember_repair(
                seq,
                Repair {
                    packet,
                    first_made,
                    made: now,
                    state,
                },
            );
        }
        stream.retransmit_budget -= 1;
        self.retransmissions_queued += 1;
        let Some(original_packet) = stream.send_buffer.get(seq) else {
            return;
        };

        let packet =
            if let (Some(ssrc_rtx), Some(pt_rtx)) = (stream.ssrc_rtx, stream.payload_type_rtx) {
                if stream.repairs_order.len() >= usize::from(self.size).max(1)
                    && let Some((oldest, made)) = stream.repairs_order.pop_front()
                    && stream
                        .repairs_by_rtx
                        .get(&oldest)
                        .is_some_and(|(_, at)| *at == made)
                {
                    stream.repairs_by_rtx.remove(&oldest);
                }
                stream
                    .repairs_by_rtx
                    .insert(stream.rtx_sequence_number, (seq, now));
                stream
                    .repairs_order
                    .push_back((stream.rtx_sequence_number, now));
                rtx_packet(
                    &mut stream.rtx_sequence_number,
                    (stream.rid_extension_id, stream.repaired_rid_extension_id),
                    original_packet,
                    ssrc_rtx,
                    pt_rtx,
                )
            } else {
                // No RTX: retransmit original packet as-is
                original_packet.clone()
            };
        self.retransmitted.add(now, size);
        self.release_at = None;

        // Tagged so a send history downstream counts it as new bytes on the wire rather
        // than as the original transmission. A bandwidth estimator that cannot tell the two
        // apart under-counts exactly when the path is lossy — it sees fewer bytes than are
        // really being sent, infers headroom, and raises the target during loss.
        self.write_queue.push_back(TaggedPacket {
            now,
            transport: TransportContext::default(),
            message: AttributedPacket::new(Packet::Rtp(packet)).with(Attribute::Retransmission),
        });
    }

    /// When the oldest waiting retransmission fits the rate limit: the instant enough of the
    /// window's packets have left it. `None` with nothing waiting, without a target to wait
    /// for, or while the stream's budget waits for an original packet (the write of that
    /// packet tries again).
    pub fn next_release(&mut self) -> Option<Instant> {
        if let Some(at) = self.release_at {
            return at;
        }
        let at = self.work_out_release();
        self.release_at = Some(at);
        at
    }

    fn work_out_release(&self) -> Option<Instant> {
        // A request held for the feedback on an earlier retransmission is due when its wait
        // ends (the feedback itself comes on the read leg); the first one not held is the
        // head. `release` forgets the waits that ended, so these are all ahead.
        let wait = self.report_wait();
        let held = |entry: &PendingRetransmission| {
            if !self.repairs_reported {
                return None;
            }
            let stream = self.streams.get(&entry.ssrc)?;
            let repair = stream.repairs.get(&entry.sequence_number)?;
            match repair.state {
                RepairState::Unreported { left }
                    if stream.packet(entry.sequence_number) == Some(repair.packet) =>
                {
                    Some(left + wait)
                }
                _ => None,
            }
        };
        let hold_ends = self.pending.iter().filter_map(held).min();
        let Some(target_bps) = self.target_bps else {
            return hold_ends;
        };
        // With nothing waiting, the reserve falls to zero when the last retransmission leaves
        // the window.
        if self.pending.is_empty() {
            return (self.announced_reserve > 0.0)
                .then(|| self.retransmitted.sent.back())
                .flatten()
                .map(|(at, _)| *at + RETRANSMISSION_RATE_WINDOW);
        }
        // The lifetime of the oldest request ends: due then, to drop it.
        let lifetime = self.pending_lifetime();
        let stale = self
            .pending
            .iter()
            .filter_map(|entry| self.pending_asked.get(&(entry.ssrc, entry.sequence_number)))
            .map(|(asked, _)| *asked)
            .min()
            .map(|asked| asked + lifetime + Duration::from_micros(1));
        let stale = stale.into_iter().chain(hold_ends).min();
        let Some(entry) = self.pending.iter().find(|entry| held(entry).is_none()) else {
            return stale;
        };
        if self
            .streams
            .get(&entry.ssrc)
            .is_none_or(|stream| stream.retransmit_budget == 0)
        {
            return stale;
        }
        let size = entry.octets;
        let target = Self::window_octets(target_bps);
        let (originals, retransmitted) = (self.originals.octets, self.retransmitted.octets);
        let fits = match self.rate_limit {
            RetransmissionRateLimit::WithinTarget if !self.at_floor() => {
                let by_share = freed_at(
                    &[&self.originals, &self.retransmitted],
                    (originals + retransmitted + size)
                        .saturating_sub(target)
                        .max(1),
                )
                .filter(|_| size <= target);
                // The reserve frees as the retransmissions leave the window.
                let reserve = Self::window_octets(self.announced_reserve);
                let by_reserve = freed_at(
                    &[&self.retransmitted],
                    (retransmitted + size).saturating_sub(reserve).max(1),
                )
                .filter(|_| size <= reserve);
                by_share.into_iter().chain(by_reserve).min()
            }
            // Near the floor the room is the retransmissions' first: only they leaving the
            // window frees it.
            RetransmissionRateLimit::WithinTarget | RetransmissionRateLimit::UpToTarget => {
                freed_at(
                    &[&self.retransmitted],
                    (retransmitted + size).saturating_sub(target).max(1),
                )
                .filter(|_| size <= target)
            }
            RetransmissionRateLimit::Unlimited => None,
        };
        fits.into_iter().chain(stale).min()
    }

    /// Announces a reserve that moved: down the write leg for the congestion controller, and
    /// up the read leg as the lowered target for the application.
    /// The carrier that tells the application its target when only the reserve moved: the
    /// controller's target less the reserve, or, while the pacer has the source paused, zero
    /// with the controller's target riding along as the pacer's own announcement of a pause
    /// has it ([`PacerPause`](crate::PacerPause)). Without it a reader of the carrier takes
    /// the zero for the congestion controller's estimate (`availableOutgoingBitrate` read
    /// nothing until the next target from the pacer).
    fn target_carrier(&self, now: Instant, target_bps: f64, reserve: f64) -> TaggedPacket {
        let mut message = AttributedPacket::new(Packet::Rtcp(vec![]));
        if self.paused {
            message.add(Attribute::TargetBitrateChanged {
                bits_per_second: 0.0,
            });
            message.add(Attribute::Custom(std::sync::Arc::new(crate::PacerPause {
                target_bits_per_second: target_bps,
            })));
        } else {
            message.add(Attribute::TargetBitrateChanged {
                bits_per_second: media_target(target_bps, reserve, self.minimum_bps.unwrap_or(0.0)),
            });
        }
        TaggedPacket {
            now,
            transport: TransportContext::default(),
            message,
        }
    }

    fn announce_reserve(&mut self, now: Instant, carrier: bool) {
        let Some(target_bps) = self.target_bps else {
            return;
        };
        let reserve = self.reserve(now);
        if !reserve_moved(self.announced_reserve, reserve, target_bps) {
            return;
        }
        self.announced_reserve = reserve;
        self.release_at = None;
        self.write_queue.push_back(TaggedPacket {
            now,
            transport: TransportContext::default(),
            message: AttributedPacket::new(Packet::Rtcp(vec![])).with(Attribute::Custom(
                std::sync::Arc::new(RetransmissionReserve {
                    bits_per_second: reserve,
                }),
            )),
        });
        if carrier {
            let carrier = self.target_carrier(now, target_bps, reserve);
            self.read_queue.push_back(carrier);
        }
        if self.at_floor() {
            // Near the floor the window's room is the retransmissions': use it now.
            self.release(now);
        }
    }

    /// Fills a probe cluster ([`ProbeRequest`]) with padding-only packets on the RTX stream of
    /// the media stream that sent most recently.
    ///
    /// A probe needs a burst of packets at a multiple of the target rate, and an application
    /// that follows the target does not have one waiting. Each packet is an RTP packet of the
    /// RTX stream with no payload and [`PROBE_PADDING_OCTETS`] of padding (RFC 3550 section
    /// 5.1): an RTX packet too short to hold the original sequence number of RFC 4588 section
    /// 4 carries no media, and every receiver drops it after its transport-wide sequence
    /// number has been recorded (this crate's endpoint, libwebrtc's `RtxReceiveStream`). A
    /// retransmission of a packet already delivered would be a duplicate the receiving
    /// application may play twice. The header is the newest packet's, with its extensions
    /// (MID, the repaired RID in place of the RID), so the packet is demultiplexed as that
    /// stream's repair flow. Without RTX negotiated nothing is added: padding under the media
    /// SSRC would take sequence numbers the application owns. Not charged to the NACK budget:
    /// it answers no NACK.
    ///
    /// With several RTP sessions (transports) a cluster is the session's that asked for it
    /// (the request carries its [`RtpSession`](crate::RtpSession)): it is filled on a stream of
    /// that session only, so the probe travels the path whose capacity it measures (RFC 8836
    /// section 2: each path its own capacity).
    fn fill_probe(&mut self, now: Instant, request: &ProbeRequest, session: Option<usize>) {
        let sessions = &self.sessions;
        let Some(stream) = self
            .streams
            .iter_mut()
            .filter(|(ssrc, _)| match session {
                Some(session) if !sessions.is_empty() => sessions.get(ssrc) == Some(&session),
                _ => true,
            })
            .map(|(_, stream)| stream)
            .filter(|stream| stream.ssrc_rtx.is_some() && stream.payload_type_rtx.is_some())
            .filter(|stream| stream.last_sent.is_some())
            .max_by_key(|stream| stream.last_sent.map(|(_, at)| at))
        else {
            return;
        };
        let (Some(ssrc_rtx), Some(pt_rtx), Some((newest, _))) =
            (stream.ssrc_rtx, stream.payload_type_rtx, stream.last_sent)
        else {
            return;
        };

        // The newest packet still held gives the header.
        let Some(template) = stream.send_buffer.get(newest).cloned() else {
            return;
        };

        let wanted = request.octets.min(MAX_PROBE_FILL_OCTETS);
        let mut filled = 0usize;
        for _ in 0..MAX_PROBE_FILL_PACKETS {
            if filled >= wanted || self.retransmissions_queued >= MAX_QUEUED_RETRANSMISSIONS {
                break;
            }
            let packet = padding_packet(
                &mut stream.rtx_sequence_number,
                (stream.rid_extension_id, stream.repaired_rid_extension_id),
                &template,
                ssrc_rtx,
                pt_rtx,
            );
            filled += packet.marshal_size();
            self.retransmissions_queued += 1;
            self.write_queue.push_back(TaggedPacket {
                now,
                transport: TransportContext::default(),
                message: AttributedPacket::new(Packet::Rtp(packet)).with(Attribute::Retransmission),
            });
        }
    }

    /// Forgets the packets the pacer discarded ([`PacerDiscard`](crate::PacerDiscard)): out of
    /// the retransmission buffer, so a NACK for one is answered by nothing (RFC 4588 section 7:
    /// the sender "MAY selectively retransmit only the packets that it deems important"; a frame
    /// the pacer gave up is not), out of the requests waiting, and out of the original packets
    /// counted against the target, since they never used the link.
    fn forget_discarded(&mut self, discard: &crate::PacerDiscard) {
        if let Some(stream) = self.streams.get_mut(&discard.ssrc) {
            for &seq in &discard.sequence_numbers {
                let Some(packet) = stream.send_buffer.remove(seq) else {
                    continue;
                };
                let slot = usize::from(seq) % stream.sent_at.len();
                if let Some((sequence_number, at, _)) = stream.sent_at[slot]
                    && sequence_number == seq
                {
                    self.originals.forget(at, packet.marshal_size());
                    stream.sent_at[slot] = None;
                }
                stream.repairs.remove(&seq);
            }
        }
        let before = self.pending.len();
        let asked = &mut self.pending_asked;
        let octets = &mut self.pending_octets;
        self.pending.retain(|entry| {
            let discarded = entry.ssrc == discard.ssrc
                && discard.sequence_numbers.contains(&entry.sequence_number);
            if discarded {
                asked.remove(&(entry.ssrc, entry.sequence_number));
                *octets -= entry.octets;
            }
            !discarded
        });
        if self.pending.len() != before {
            self.release_at = None;
        }
    }

    /// The pacer's report of retransmissions that left it or were dropped
    /// ([`RetransmissionsLeft`](crate::RetransmissionsLeft)): no longer on their way. One that
    /// left counts its resend interval from now, the instant it went toward the wire, not from
    /// when it was made (libwebrtc's `RtpPacketHistory` sets the send time when the pacer sends
    /// it); one that was dropped may be asked for again.
    fn retransmissions_left(&mut self, now: Instant, notice: &crate::RetransmissionsLeft) {
        self.pacer_reports = true;
        for &(ssrc, seq) in &notice.departed {
            let Some(stream) = self
                .media_ssrc(ssrc)
                .and_then(|media| self.streams.get_mut(&media))
            else {
                continue;
            };
            let packet = stream.packet(seq);
            if let Some(repair) = stream.repairs.get_mut(&seq)
                && repair.state == RepairState::InPacer
            {
                if packet == Some(repair.packet) {
                    repair.state = RepairState::Unreported { left: now };
                    stream.last_retransmit.insert(seq, now);
                } else {
                    // The packet it repaired is no longer held: nothing of it is asked for
                    // again, and the packet that has the number now starts afresh.
                    stream.repairs.remove(&seq);
                }
            }
        }
        for &(ssrc, seq) in &notice.dropped {
            if let Some(stream) = self
                .media_ssrc(ssrc)
                .and_then(|media| self.streams.get_mut(&media))
                && stream
                    .repairs
                    .get(&seq)
                    .is_some_and(|repair| repair.state == RepairState::InPacer)
            {
                stream.repairs.remove(&seq);
            }
        }
        // A pacer drops what waited its queue time bound and says so; anything older than
        // that is no longer there.
        self.expire_repairs(now);
        self.release_at = None;
    }

    /// What is remembered at `now` of the latest retransmission under `seq` of the stream
    /// `ssrc`. A state that ran out by the clock is ended here (a wait for the report becomes
    /// [`RepairState::Overdue`], anything else is forgotten), and so is what is remembered of
    /// a packet the stream no longer holds under that number, except a retransmission still
    /// in the pacer (see [`RepairState::InPacer`]).
    fn repair(&mut self, ssrc: u32, seq: u16, now: Instant) -> Option<Repair> {
        let wait = self.report_wait();
        let stream = self.streams.get_mut(&ssrc)?;
        let packet = stream.packet(seq);
        let repair = stream.repairs.get_mut(&seq)?;
        if Self::repair_ended(repair, packet, now, wait) {
            stream.repairs.remove(&seq);
            return None;
        }
        Some(*repair)
    }

    /// Brings `repair`, of the packet `packet` holds now, up to `now`; whether it is over.
    fn repair_ended(
        repair: &mut Repair,
        packet: Option<u64>,
        now: Instant,
        wait: Duration,
    ) -> bool {
        let same = packet == Some(repair.packet);
        let horizon = crate::RETRANSMISSION_REPORT_HORIZON.max(wait);
        match repair.state {
            RepairState::InPacer => now.saturating_duration_since(repair.made) >= IN_PACER_LIFETIME,
            RepairState::Unreported { left } => {
                if same && now >= left + wait {
                    repair.state = RepairState::Overdue { left };
                }
                !same || now.saturating_duration_since(left) >= horizon
            }
            RepairState::Overdue { left } => {
                !same || now.saturating_duration_since(left) >= horizon
            }
            RepairState::Delivered { reported } => {
                !same || now.saturating_duration_since(reported) >= DELIVERED_MEMORY
            }
        }
    }

    /// Ends everything remembered of retransmissions that ran out by `now` (see
    /// [`Self::repair`]), and the RTX sequence numbers too old for a report to count.
    fn expire_repairs(&mut self, now: Instant) {
        let wait = self.report_wait();
        let horizon = IN_PACER_LIFETIME + crate::RETRANSMISSION_REPORT_HORIZON.max(wait);
        for stream in self.streams.values_mut() {
            let sent_at = &stream.sent_at;
            stream.repairs.retain(|seq, repair| {
                let packet = sent_at[usize::from(*seq) % sent_at.len()]
                    .filter(|(held, _, _)| held == seq)
                    .map(|(_, _, serial)| serial);
                !Self::repair_ended(repair, packet, now, wait)
            });
            while let Some(&(rtx_sequence, made)) = stream.repairs_order.front() {
                if now.saturating_duration_since(made) < horizon {
                    break;
                }
                stream.repairs_order.pop_front();
                if stream
                    .repairs_by_rtx
                    .get(&rtx_sequence)
                    .is_some_and(|(_, at)| *at == made)
                {
                    stream.repairs_by_rtx.remove(&rtx_sequence);
                }
            }
        }
    }

    /// Whether the stream `ssrc` holds the packet `packet` under `seq`.
    fn holds(&self, ssrc: u32, seq: u16, packet: u64) -> bool {
        self.streams
            .get(&ssrc)
            .is_some_and(|stream| stream.packet(seq) == Some(packet))
    }

    /// Whether a retransmission under `seq` of the stream `ssrc` waits in the pacer at `now`.
    fn in_pacer(&mut self, ssrc: u32, seq: u16, now: Instant) -> bool {
        self.repair(ssrc, seq, now)
            .is_some_and(|repair| repair.state == RepairState::InPacer)
    }

    /// How long a request waits for the feedback on an earlier retransmission of its packet:
    /// two round trips and [`REPAIR_REPORT_MARGIN`], or [`PENDING_REQUEST_LIFETIME`] before a
    /// round trip is known.
    fn report_wait(&self) -> Duration {
        self.round_trip_time
            .map_or(PENDING_REQUEST_LIFETIME, |rtt| {
                rtt * 2 + REPAIR_REPORT_MARGIN
            })
    }

    /// What a request for `key` gets at `now`, given what the feedback reported on its earlier
    /// retransmission (see [`RetransmissionsReported`](crate::RetransmissionsReported)). Without
    /// such reports every request is answered as before. A wait that ran out is forgotten.
    fn repeat_state(&mut self, key: (u32, u16), now: Instant) -> Repeat {
        if !self.repairs_reported {
            return Repeat::Answer;
        }
        let (ssrc, seq) = key;
        match self.repair(ssrc, seq, now).map(|repair| repair.state) {
            Some(RepairState::Delivered { .. }) => Repeat::Decline,
            Some(RepairState::Unreported { left }) => Repeat::Hold(left + self.report_wait()),
            // In the pacer: not asked here (nothing is made while it waits there).
            Some(RepairState::InPacer | RepairState::Overdue { .. }) | None => Repeat::Answer,
        }
    }

    /// The media SSRC of `ssrc`: itself, or the stream whose retransmission SSRC it is.
    fn media_ssrc(&self, ssrc: u32) -> Option<u32> {
        if self.streams.contains_key(&ssrc) {
            Some(ssrc)
        } else {
            self.streams
                .iter()
                .find(|(_, stream)| stream.ssrc_rtx == Some(ssrc))
                .map(|(media, _)| *media)
        }
    }

    /// The transport-wide feedback on retransmissions
    /// ([`RetransmissionsReported`](crate::RetransmissionsReported)). RFC 4588 section 7: the
    /// sender "MAY selectively retransmit only the packets that it deems important and ignore
    /// NACK messages for other packets"; RFC 8834 section 6.1: "It is not appropriate to blindly
    /// retransmit RTP packets in response to a NACK." A request for a packet whose
    /// retransmission the receiver got crossed that retransmission on the way (the receiver
    /// asks again while the packet is missing, and it waited in the path's queue): it is not
    /// answered. One whose retransmission was lost is answered at once.
    fn repairs_reported(&mut self, now: Instant, report: &crate::RetransmissionsReported) {
        self.repairs_reported = true;
        // The clock first: a report counts only for what is still remembered at `now`.
        self.expire_repairs(now);
        let mut delivered = Vec::new();
        for reported in &report.received {
            let Some(media) = self.media_ssrc(reported.ssrc) else {
                continue;
            };
            let seq = reported.sequence_number;
            // Of this packet (not an earlier one of the same number), and not known already:
            // a report that comes again does not begin the memory again.
            if let Some(repair) = self.repair(media, seq, now)
                && self.holds(media, seq, repair.packet)
                && reported.sent >= repair.first_made
                && !matches!(repair.state, RepairState::Delivered { .. })
                && let Some(repair) = self
                    .streams
                    .get_mut(&media)
                    .and_then(|stream| stream.repairs.get_mut(&seq))
            {
                repair.state = RepairState::Delivered { reported: now };
                delivered.push((media, seq));
            }
        }
        for reported in &report.lost {
            let Some(media) = self.media_ssrc(reported.ssrc) else {
                continue;
            };
            let seq = reported.sequence_number;
            // The latest retransmission of this packet was lost: asked for again, it is
            // answered. The loss of an earlier one says nothing of the one on its way.
            if let Some(repair) = self.repair(media, seq, now)
                && reported.sent >= repair.made
                && matches!(
                    repair.state,
                    RepairState::Unreported { .. } | RepairState::Overdue { .. }
                )
                && let Some(stream) = self.streams.get_mut(&media)
            {
                stream.repairs.remove(&seq);
            }
        }
        if !delivered.is_empty() {
            let asked = &mut self.pending_asked;
            let octets = &mut self.pending_octets;
            self.pending.retain(|entry| {
                let key = (entry.ssrc, entry.sequence_number);
                let keep = !delivered.contains(&key);
                if !keep {
                    asked.remove(&key);
                    *octets -= entry.octets;
                }
                keep
            });
        }
        self.release_at = None;
    }

    /// What RFC 8888 congestion control feedback (`CcFeedbackReport`) in `rtcp_packets` says
    /// of the retransmissions: it reports the packets of the RTX stream under their own
    /// sequence numbers, each mapped back to the packet it repaired. The counterpart of the
    /// TWCC sender's [`RetransmissionsReported`](crate::RetransmissionsReported) for streams
    /// whose feedback is RFC 8888.
    fn ccfb_report(
        &self,
        rtcp_packets: &[Box<dyn rtcp::Packet>],
    ) -> crate::RetransmissionsReported {
        let mut report = crate::RetransmissionsReported::default();
        for feedback in rtcp_packets.iter().filter_map(|packet| {
            packet
                .as_any()
                .downcast_ref::<rtcp::transport_feedbacks::cc_feedback_report::CcFeedbackReport>()
        }) {
            let (_, per_stream) = crate::rtpfb::convert::convert_ccfb(feedback);
            for (ssrc, acknowledgements) in per_stream {
                let Some(stream) = self
                    .streams
                    .values()
                    .find(|stream| stream.ssrc_rtx == Some(ssrc))
                else {
                    continue;
                };
                for acknowledgement in acknowledgements {
                    if let Some(&(sequence_number, sent)) =
                        stream.repairs_by_rtx.get(&acknowledgement.sequence_number)
                    {
                        let reported = crate::ReportedRetransmission {
                            ssrc,
                            sequence_number,
                            sent,
                        };
                        if acknowledgement.arrived {
                            report.received.push(reported);
                        } else {
                            report.lost.push(reported);
                        }
                    }
                }
            }
        }
        report
    }

    /// Handle a NACK request by queuing retransmissions.
    fn handle_nack(
        &mut self,
        now: Instant,
        nack: &rtcp::transport_feedbacks::transport_layer_nack::TransportLayerNack,
    ) {
        // Collect sequence numbers to retransmit
        let mut seqs_to_retransmit = Vec::new();

        for nack_pair in &nack.nacks {
            // Check the base packet ID
            seqs_to_retransmit.push(nack_pair.packet_id);

            // Check each bit in lost_packets bitmap
            for i in 0..16 {
                if nack_pair.lost_packets & (1 << i) != 0 {
                    let seq = nack_pair.packet_id.wrapping_add(i + 1);
                    seqs_to_retransmit.push(seq);
                }
            }
        }

        let ssrc = nack.media_ssrc;
        let resend_interval = resend_interval(self.round_trip_time);
        let Some(stream) = self.streams.get_mut(&ssrc) else {
            return;
        };

        // A NACK may name the same packet in several pairs; resend each once.
        seqs_to_retransmit.sort_unstable();
        seqs_to_retransmit.dedup();
        // Forget suppression entries old enough not to matter.
        stream
            .last_retransmit
            .retain(|_, at| now.saturating_duration_since(*at) < resend_interval);

        // Every packet asked for joins the requests waiting, oldest request first (one asked
        // for again keeps its place and is asked for afresh), and leaves as the rate limit has
        // room (RFC 4588 section 7): what does not fit now leaves when the window has room.
        for seq in seqs_to_retransmit {
            let Some(stream) = self.streams.get(&ssrc) else {
                return;
            };
            if stream.last_retransmit.contains_key(&seq) {
                continue;
            }
            let Some(octets) = self.retransmittable(stream, seq, now) else {
                continue;
            };
            if self.in_pacer(ssrc, seq, now)
                || self.repeat_state((ssrc, seq), now) == Repeat::Decline
            {
                continue;
            }
            let Some(stream) = self.streams.get(&ssrc) else {
                return;
            };
            let budget = stream.retransmit_budget;
            let Some(packet) = stream.packet(seq) else {
                continue;
            };
            // A request still waiting under this number for a packet since replaced ends here.
            if self
                .pending_asked
                .get(&(ssrc, seq))
                .is_some_and(|(_, waiting)| *waiting != packet)
                && let Some(waiting) = self
                    .pending
                    .iter()
                    .position(|waiting| waiting.ssrc == ssrc && waiting.sequence_number == seq)
            {
                self.remove_pending(waiting);
            }
            match self.pending_asked.get_mut(&(ssrc, seq)) {
                Some((asked, _)) => *asked = now,
                None => {
                    // The budget (one retransmission per original sent) refuses it: not
                    // kept, the receiver asks again. Only the rate limit makes a request wait.
                    if budget == 0 || self.pending.len() >= MAX_QUEUED_RETRANSMISSIONS {
                        break;
                    }
                    self.pending_asked.insert((ssrc, seq), (now, packet));
                    // A stream's oldest packet first, whenever it was asked for: a receiver
                    // that plays in order waits for its oldest gap, and a packet asked for
                    // again (its repair was lost) would otherwise wait behind every newer one.
                    let at = self
                        .pending
                        .iter()
                        .position(|waiting| {
                            waiting.ssrc == ssrc
                                && waiting.sequence_number.wrapping_sub(seq) < 0x8000
                        })
                        .unwrap_or(self.pending.len());
                    self.pending.insert(
                        at,
                        PendingRetransmission {
                            ssrc,
                            sequence_number: seq,
                            packet,
                            octets,
                        },
                    );
                    self.pending_octets += octets;
                }
            }
        }
        self.release_at = None;
        self.expire_pending(now);
        // The original media is lowered by the reserve before any of these is sent (RFC 4588
        // section 7: "the sender SHOULD NOT send retransmission packets without reducing the
        // packet rate and bitrate of the original stream"); the retransmissions may then use it.
        self.announce_reserve(now, false);
        self.release(now);
    }
}

/// The RTX packet (RFC 4588 section 4) that carries `original` again: the RTX SSRC and
/// payload type, the next sequence number of the RTX stream, and the original sequence number
/// ahead of the payload.
fn rtx_packet(
    rtx_sequence_number: &mut u16,
    rid_extension_ids: (Option<u8>, Option<u8>),
    original_packet: &rtp::Packet,
    ssrc_rtx: u32,
    pt_rtx: u8,
) -> rtp::Packet {
    let (rid_extension_id, repaired_rid_extension_id) = rid_extension_ids;
    let original_seq = original_packet.header.sequence_number;
    let mut rtx_payload = Vec::with_capacity(2 + original_packet.payload.len());
    rtx_payload.extend_from_slice(&original_seq.to_be_bytes());
    rtx_payload.extend_from_slice(&original_packet.payload);

    let rtx_seq = *rtx_sequence_number;
    *rtx_sequence_number = rtx_sequence_number.wrapping_add(1);

    // RFC 4588 4: the RTX packet carries the original's header "as is" apart from the SSRC,
    // payload type and sequence number, so its CSRCs and header extensions (audio level,
    // abs-send-time, mid, ...) go with it. Building a fresh header used to drop them. Version
    // is set explicitly: a buffered packet built with a defaulted header is version 0, which
    // receivers discard on arrival. Padding is not carried: the RTX payload is the original
    // payload alone.
    let mut header = original_packet.header.clone();
    header.version = 2;
    header.ssrc = ssrc_rtx;
    header.payload_type = pt_rtx;
    header.sequence_number = rtx_seq;
    header.padding = false;
    header.padding_size = 0;
    // RFC 8852 3.2: a repair packet names the stream it repairs with the repaired-RID, not
    // the RID, so a receiver never takes the RTX SSRC for a simulcast layer of its own.
    if let Some(rid_id) = rid_extension_id
        && let Some(rid) = header.get_extension(rid_id)
    {
        let _ = header.del_extension(rid_id);
        if let Some(repaired_id) = repaired_rid_extension_id {
            let _ = header.set_extension(repaired_id, rid);
        }
    }

    rtp::Packet {
        header,
        payload: rtx_payload.into(),
    }
}

/// A padding-only packet of the RTX stream (a bandwidth probe): `template`'s header on the RTX
/// SSRC and payload type with the next RTX sequence number, no payload, and
/// [`PROBE_PADDING_OCTETS`] of padding.
fn padding_packet(
    rtx_sequence_number: &mut u16,
    rid_extension_ids: (Option<u8>, Option<u8>),
    template: &rtp::Packet,
    ssrc_rtx: u32,
    pt_rtx: u8,
) -> rtp::Packet {
    let mut packet = rtx_packet(
        rtx_sequence_number,
        rid_extension_ids,
        template,
        ssrc_rtx,
        pt_rtx,
    );
    packet.payload = bytes::Bytes::new();
    packet.header.marker = false;
    packet.header.padding = true;
    packet.header.padding_size = PROBE_PADDING_OCTETS;
    packet
}

impl Protocol<TaggedPacket, TaggedPacket, ()> for NackResponderInterceptor {
    type Rout = TaggedPacket;
    type Wout = TaggedPacket;
    type Eout = ();
    type Error = Error;
    type Time = Instant;

    fn handle_read(&mut self, mut msg: TaggedPacket) -> Result<(), Self::Error> {
        let now = msg.now;
        let announced_before = self.announced_reserve;
        // The congestion controller's target, which the retransmissions are held to.
        let carries_target = if let Some(Attribute::TargetBitrateChanged { bits_per_second }) =
            msg.message.get(&Attribute::TargetBitrateChanged {
                bits_per_second: 0.0,
            }) {
            if bits_per_second.is_finite() && *bits_per_second >= 0.0 {
                self.target_bps = Some(*bits_per_second);
                self.minimum_bps = msg
                    .message
                    .custom::<MinimumTarget>()
                    .map(|minimum| minimum.bits_per_second)
                    .filter(|minimum| minimum.is_finite());
                self.release_at = None;
            }
            true
        } else {
            false
        };

        // The round trip the RTCP session measured: the reserve's horizon.
        if let Some(crate::RtcpSessionEvent::RoundTripTime { rtt, .. }) =
            msg.message.custom::<crate::RtcpSessionEvent>()
        {
            self.round_trip_time = Some(*rtt);
            self.release_at = None;
        }

        // While the pacer tells the source to pause, the target on the packet is zero and the
        // congestion controller's rides with it: the rate the retransmissions are held to.
        if carries_target {
            let pause = msg.message.custom::<crate::PacerPause>().copied();
            self.paused = pause.is_some();
            if let Some(pause) = pause
                && pause.target_bits_per_second.is_finite()
                && pause.target_bits_per_second >= 0.0
            {
                self.target_bps = Some(pause.target_bits_per_second);
            }
        }

        // Retransmissions that left the pacer (or were dropped there).
        if let Some(notice) = msg.message.custom::<crate::RetransmissionsLeft>() {
            let notice = notice.clone();
            self.retransmissions_left(now, &notice);
        }

        // What RFC 8888 feedback reports on the RTX streams: read here, where the sequence
        // number each RTX packet was given is known.
        if let Packet::Rtcp(ref rtcp_packets) = msg.message.packet {
            let report = self.ccfb_report(rtcp_packets);
            if !report.received.is_empty() || !report.lost.is_empty() {
                self.repairs_reported(now, &report);
                self.release(now);
            }
        }

        // What transport-wide feedback reported on the retransmissions.
        if let Some(report) = msg.message.custom::<crate::RetransmissionsReported>() {
            let report = report.clone();
            self.repairs_reported(now, &report);
            // A request held for a retransmission now reported lost leaves at once.
            self.release(now);
        }

        // Packets the pacer (wire-ward of here) discarded: never resent.
        if let Some(discard) = msg.message.custom::<crate::PacerDiscard>() {
            let discard = discard.clone();
            self.forget_discarded(&discard);
        }

        // A probe cluster the congestion controller asks for: fill it.
        if let Some(request) = msg.message.custom::<ProbeRequest>().copied() {
            let session = crate::RtpSession::of(&msg.message);
            self.fill_probe(now, &request, session);
        }

        // Process NACK packets
        if let Packet::Rtcp(ref rtcp_packets) = msg.message.packet {
            for rtcp_packet in rtcp_packets {
                if let Some(nack) = rtcp_packet
                    .as_any()
                    .downcast_ref::<rtcp::transport_feedbacks::transport_layer_nack::TransportLayerNack>()
                {
                    self.handle_nack(now, nack);
                }
            }
        }
        if carries_target {
            // A new target may leave room for what waits.
            self.release(now);
        }

        // The application's target is the controller's less the reserve (RFC 4588 section
        // 7): lowered on the packet that carries it, or announced on a carrier of its own when
        // only the reserve moved.
        if !carries_target
            && self.announced_reserve != announced_before
            && let Some(target_bps) = self.target_bps
        {
            // Moved while the NACK was read: the application hears of it here.
            let carrier = self.target_carrier(now, target_bps, self.announced_reserve);
            self.read_queue.push_back(carrier);
        }
        self.announce_reserve(now, !carries_target);
        if carries_target && self.announced_reserve > 0.0 {
            let (reserve, minimum) = (self.announced_reserve, self.minimum_bps.unwrap_or(0.0));
            for attribute in &mut msg.message.attributes {
                if let Attribute::TargetBitrateChanged { bits_per_second } = attribute {
                    *bits_per_second = media_target(*bits_per_second, reserve, minimum);
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
        if let Some(assignment) = msg.message.custom::<crate::RtpSessionAssignment>() {
            for ssrc in &assignment.ssrcs {
                self.sessions.insert(*ssrc, assignment.session);
            }
        }
        if let Some(super::NackControl::LocalRtxTime {
            payload_type_rtx,
            rtx_time,
        }) = msg.message.custom::<super::NackControl>()
        {
            match rtx_time {
                Some(rtx_time) => self.local_rtx_times.insert(*payload_type_rtx, *rtx_time),
                None => self.local_rtx_times.remove(payload_type_rtx),
            };
        }
        // Every original packet counts against the target (RFC 4588 section 7), whether or
        // not its stream is repaired.
        if let Packet::Rtp(ref rtp_packet) = msg.message.packet
            && !msg.message.has(&Attribute::Retransmission)
        {
            self.originals.expire(msg.now);
            self.originals.add(msg.now, rtp_packet.marshal_size());
        }
        // Buffer outgoing RTP packets
        if let Packet::Rtp(ref rtp_packet) = msg.message.packet
            && let Some(stream) = self.streams.get_mut(&rtp_packet.header.ssrc)
        {
            stream.send_buffer.add(rtp_packet.clone());
            stream.last_sent = Some((rtp_packet.header.sequence_number, msg.now));
            stream.written += 1;
            let slot = usize::from(rtp_packet.header.sequence_number) % stream.sent_at.len();
            stream.sent_at[slot] =
                Some((rtp_packet.header.sequence_number, msg.now, stream.written));
            stream.retransmit_budget =
                (stream.retransmit_budget + 1).min(stream.retransmit_budget_max);
        }
        if matches!(msg.message.packet, Packet::Rtp(_)) {
            self.release_at = None;
            if !self.pending.is_empty() {
                // The budget may have room again.
                self.release(msg.now);
            }
            if !self.pending.is_empty() || self.announced_reserve > 0.0 {
                self.announce_reserve(msg.now, true);
            }
        }

        self.write_queue.push_back(msg);

        Ok(())
    }

    fn poll_write(&mut self) -> Option<TaggedPacket> {
        // First drain retransmitted packets
        let packet = self.write_queue.pop_front()?;
        if packet.message.has(&Attribute::Retransmission) {
            self.retransmissions_queued = self.retransmissions_queued.saturating_sub(1);
        }
        Some(packet)
    }

    fn handle_timeout(&mut self, now: Instant) -> Result<(), Self::Error> {
        // What is remembered of retransmissions ends by this clock, with or without a
        // request or a report to end it.
        self.expire_repairs(now);
        if !self.pending.is_empty() || self.announced_reserve > 0.0 {
            // Worked out afresh: a deadline that passed without a change must not be handed
            // back again (a driver would spin on it).
            self.release_at = None;
            self.expire_pending(now);
            self.release(now);
            self.announce_reserve(now, true);
        }
        Ok(())
    }

    /// Due at once while packets wait in the write queue. A retransmission or a probe cluster's
    /// padding is made on the read leg (a NACK, a [`ProbeRequest`]), which a driver reaches
    /// after its `poll_write` (`poll_write`, `poll_event`, `poll_read`, then `poll_timeout`
    /// and sleep, as the crate's event loop has it): without a deadline the packets would wait
    /// for whatever wakes the driver next, a timer or an incoming datagram, which can be a
    /// long time on a connection with little traffic. The deadline is the instant they were
    /// made, so the driver's `handle_timeout` and the `poll_write` after it take them out at
    /// once; it is gone when the queue is drained.
    ///
    /// A retransmission the rate limit holds back is not in the write queue: its deadline is
    /// the instant the limit next has room for it ([`Self::next_release`]), never earlier (a
    /// driver woken at once would spin), and the same for a waiting request running out and
    /// the reserve falling back to zero.
    fn poll_timeout(&mut self) -> Option<Self::Time> {
        let queued = self.write_queue.front().map(|packet| packet.now);
        queued.into_iter().chain(self.next_release()).min()
    }
}

impl Interceptor for NackResponderInterceptor {
    fn bind_local_stream(&mut self, info: &StreamInfo) {
        if stream_supports_nack(info)
            && let Some(send_buffer) = SendBuffer::new(self.size)
        {
            // RFC 4588 4: the initial sequence number of the retransmission stream is random
            // (RFC 3550 5.1), and the stream is the RTX SSRC's, not the binding's: a stream
            // bound again continues where the SSRC left off.
            let rtx_sequence_number = info
                .ssrc_rtx
                .and_then(|ssrc_rtx| self.rtx_sequence_numbers.get(&ssrc_rtx).copied())
                .unwrap_or_else(rand::random::<u16>);
            self.streams.insert(
                info.ssrc,
                LocalStream {
                    send_buffer,
                    ssrc_rtx: info.ssrc_rtx,
                    payload_type_rtx: info.payload_type_rtx,
                    rtx_sequence_number,
                    last_sent: None,
                    last_retransmit: HashMap::new(),
                    rid_extension_id: extension_id(info, RTP_STREAM_ID_URI),
                    repaired_rid_extension_id: extension_id(info, REPAIRED_RTP_STREAM_ID_URI),
                    retransmit_budget: usize::from(self.size),
                    retransmit_budget_max: usize::from(self.size),
                    sent_at: vec![None; usize::from(self.size).max(1)],
                    written: 0,
                    repairs: HashMap::new(),
                    repairs_by_rtx: HashMap::new(),
                    repairs_order: VecDeque::new(),
                },
            );
        }
    }

    fn unbind_local_stream(&mut self, info: &StreamInfo) {
        if let Some(stream) = self.streams.remove(&info.ssrc)
            && let Some(ssrc_rtx) = stream.ssrc_rtx
        {
            if self.rtx_sequence_numbers.len() >= MAX_REMEMBERED_RTX_SSRCS
                && !self.rtx_sequence_numbers.contains_key(&ssrc_rtx)
            {
                self.rtx_sequence_numbers.clear();
            }
            self.rtx_sequence_numbers
                .insert(ssrc_rtx, stream.rtx_sequence_number);
        }
    }

    fn bind_remote_stream(&mut self, _info: &StreamInfo) {}

    fn unbind_remote_stream(&mut self, _info: &StreamInfo) {}
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stream_info::RTCPFeedback;
    use rtcp::transport_feedbacks::transport_layer_nack::{
        TransportLayerNack, nack_pairs_from_sequence_numbers,
    };
    use std::sync::Arc;

    const SSRC: u32 = 0x1234;
    const RTX_SSRC: u32 = 0x5678;
    const SIZE: u16 = 64;

    fn responder() -> NackResponderInterceptor {
        let mut responder = NackResponderBuilder::new()
            .with_size(SIZE)
            .with_rate_limit(RetransmissionRateLimit::Unlimited)
            .build();
        responder.bind_local_stream(&StreamInfo {
            ssrc: SSRC,
            ssrc_rtx: Some(RTX_SSRC),
            payload_type_rtx: Some(97),
            payload_type: 96,
            rtcp_feedback: vec![RTCPFeedback {
                typ: "nack".to_string(),
                parameter: String::new(),
            }],
            ..Default::default()
        });
        responder
    }

    fn tagged(now: Instant, message: AttributedPacket) -> TaggedPacket {
        TaggedPacket {
            now,
            transport: TransportContext::default(),
            message,
        }
    }

    fn original(responder: &mut NackResponderInterceptor, now: Instant, sequence_number: u16) {
        let packet = rtp::Packet {
            header: rtp::header::Header {
                version: 2,
                payload_type: 96,
                sequence_number,
                ssrc: SSRC,
                ..Default::default()
            },
            payload: vec![0u8; 100].into(),
        };
        responder
            .handle_write(tagged(now, AttributedPacket::new(Packet::Rtp(packet))))
            .unwrap();
    }

    /// The sizes of everything the responder remembers of repairs and requests.
    fn remembered(responder: &NackResponderInterceptor) -> [usize; 5] {
        let stream = &responder.streams[&SSRC];
        [
            stream.repairs.len(),
            stream.repairs_by_rtx.len(),
            stream.repairs_order.len(),
            responder.pending.len(),
            responder.pending_asked.len(),
        ]
    }

    /// A receiver that asks for everything, over and over, and reports whatever it likes of
    /// the retransmissions (received, lost, both, for packets retransmitted or not, with any
    /// instant) cannot make the responder remember more than its send buffer has places:
    /// what is kept of repairs is at most one entry per packet held. And the engine's clock
    /// alone empties it: with no further request or report, a timeout past the longest
    /// memory leaves nothing.
    #[test]
    fn requests_and_reports_without_end_do_not_grow_what_is_remembered() {
        let mut responder = responder();
        let base = Instant::now();
        let size = usize::from(SIZE);
        let mut now = base;
        let mut most = 0;
        // Reports come and a pacer is there, so every state is in use. For the second half
        // the pacer says nothing more: its retransmissions stay "in the pacer", the one
        // state kept for whatever packet has the number.
        for step in 0..20_000u32 {
            now = base + Duration::from_micros(500) * step;
            let sequence_number = step as u16;
            original(&mut responder, now, sequence_number);
            // Ask for the whole buffer, and for numbers far outside it.
            let mut asked: Vec<u16> = (0..SIZE)
                .map(|back| sequence_number.wrapping_sub(back))
                .collect();
            asked.extend((0..SIZE).map(|far| sequence_number.wrapping_add(0x4000 + far * 97)));
            asked.sort_unstable();
            responder
                .handle_read(tagged(
                    now,
                    AttributedPacket::new(Packet::Rtcp(vec![Box::new(TransportLayerNack {
                        sender_ssrc: 1,
                        media_ssrc: SSRC,
                        nacks: nack_pairs_from_sequence_numbers(&asked),
                    })])),
                ))
                .unwrap();
            // Reports on every sequence number there is, a different mix each time.
            let reported = |sequence_number: u16| crate::ReportedRetransmission {
                ssrc: RTX_SSRC,
                sequence_number,
                sent: now,
            };
            let numbers =
                (0..512u16).map(|index| index.wrapping_mul(128).wrapping_add(step as u16));
            let report = match step % 3 {
                0 => crate::RetransmissionsReported {
                    received: numbers.map(reported).collect(),
                    lost: vec![],
                },
                1 => crate::RetransmissionsReported {
                    received: vec![],
                    lost: numbers.map(reported).collect(),
                },
                _ => crate::RetransmissionsReported {
                    received: asked.iter().copied().map(reported).collect(),
                    lost: asked.iter().copied().map(reported).collect(),
                },
            };
            let mut message = AttributedPacket::new(Packet::Rtcp(vec![]))
                .with(Attribute::Custom(Arc::new(report)));
            if step < 10_000 && step % 7 == 0 {
                // The pacer's notices, as arbitrary.
                message.add(Attribute::Custom(Arc::new(crate::RetransmissionsLeft {
                    departed: asked.iter().map(|seq| (RTX_SSRC, *seq)).collect(),
                    dropped: vec![(RTX_SSRC, sequence_number)],
                })));
            }
            responder.handle_read(tagged(now, message)).unwrap();
            while responder.poll_write().is_some() {}
            while responder.poll_read().is_some() {}
            let [repairs, by_rtx, order, pending, asked] = remembered(&responder);
            assert!(
                repairs <= size && by_rtx <= size && order <= size,
                "step {step}: {repairs} repairs, {by_rtx} RTX numbers ({order}) remembered, \
                 the buffer holds {size}"
            );
            assert!(pending <= MAX_QUEUED_RETRANSMISSIONS && asked == pending);
            most = most.max(repairs);
        }
        assert!(
            most > size / 2,
            "most of the buffer's places were remembered at some point: {most} of {size}"
        );
        // Nothing more arrives. The clock alone:
        responder
            .handle_timeout(now + Duration::from_secs(30))
            .unwrap();
        assert_eq!([0; 5], remembered(&responder));
    }

    /// What is remembered of a repair ends with the engine's clock at a timeout, with no
    /// request and no report to end it: a retransmission reported received is forgotten four
    /// seconds after the report.
    #[test]
    fn a_timeout_alone_ends_the_memory_of_a_delivered_retransmission() {
        let mut responder = responder();
        let base = Instant::now();
        for sequence_number in 0..10 {
            original(&mut responder, base, sequence_number);
        }
        let at = |milliseconds: u64| base + Duration::from_millis(milliseconds);
        responder
            .handle_read(tagged(
                at(100),
                AttributedPacket::new(Packet::Rtcp(vec![Box::new(TransportLayerNack {
                    sender_ssrc: 1,
                    media_ssrc: SSRC,
                    nacks: nack_pairs_from_sequence_numbers(&[3]),
                })])),
            ))
            .unwrap();
        responder
            .handle_read(tagged(
                at(200),
                AttributedPacket::new(Packet::Rtcp(vec![])).with(Attribute::Custom(Arc::new(
                    crate::RetransmissionsReported {
                        received: vec![crate::ReportedRetransmission {
                            ssrc: RTX_SSRC,
                            sequence_number: 3,
                            sent: at(100),
                        }],
                        lost: vec![],
                    },
                ))),
            ))
            .unwrap();
        let state = |responder: &NackResponderInterceptor| {
            responder.streams[&SSRC]
                .repairs
                .get(&3)
                .map(|repair| repair.state)
        };
        assert_eq!(
            Some(RepairState::Delivered { reported: at(200) }),
            state(&responder)
        );
        responder.handle_timeout(at(4_199)).unwrap();
        assert!(state(&responder).is_some(), "1 ms before the memory ends");
        responder.handle_timeout(at(4_200)).unwrap();
        assert_eq!(None, state(&responder));
    }
}
