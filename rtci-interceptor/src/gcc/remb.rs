//! The receive-side variant of draft-ietf-rmcat-gcc-02 (section 3): the delay-based controller
//! runs where the media arrives, and its estimate goes back to the sender in a REMB
//! (draft-alvestrand-rmcat-remb).
//!
//! Two interceptors:
//!
//! - [`RembGeneratorInterceptor`] (receiver): for every remote stream that negotiated
//!   `goog-remb` and neither transport-wide congestion control nor RFC 8888 (with either of
//!   those the sender runs the controller itself), it times the arrivals against the send
//!   times, runs the delay-based controller of [`Gcc`] on them, and sends a REMB "as soon as
//!   congestion is detected, otherwise at least once per second" (section 3).
//! - [`AbsSendTimeInterceptor`] (sender): stamps the abs-send-time header extension on every
//!   packet of a local stream that negotiated it, as the packet leaves the pacer (section 3:
//!   "the sender SHOULD use the abs-send-time RTP header extension" with this variant).
//!
//! The send time of a packet is its abs-send-time when the stream carries one (one clock for
//! every stream of the sender, so one estimator for all of them), else its RTP timestamp over
//! the clock rate (one estimator per stream, as libwebrtc's single-stream estimator: RTP
//! timestamps of different streams do not share an origin). The REMB carries the sum of the
//! estimates and names every stream it covers. Retransmissions are left out: a repair leaves
//! long after its timestamp says, and would read as a queue.

use super::estimator::Gcc;
use super::rate_calc::RateCalculator;
use crate::cc::estimator::BandwidthEstimator;
use crate::cc::feedback::negotiated_congestion_feedback;
use crate::rtpfb::acknowledgement::PacketReport;
use crate::stream_info::StreamInfo;
use crate::twcc::flow_ssrcs;
use crate::{Attribute, AttributedPacket, Interceptor, Packet, TaggedPacket};
use rtcp::payload_feedbacks::receiver_estimated_maximum_bitrate::ReceiverEstimatedMaximumBitrate;
use rtcp::transport_feedbacks::cc_feedback_report::Ecn;
use sansio::Protocol;
use shared::TransportContext;
use shared::error::Error;
use shared::marshal::{MarshalSize, Unmarshal};
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::time::{Duration, Instant};

/// The abs-send-time header extension's URI.
pub const ABS_SEND_TIME_URI: &str = "http://www.webrtc.org/experiments/rtp-hdrext/abs-send-time";

/// Where the default interceptor set puts the [`RembGeneratorInterceptor`]
/// (`Slot::Custom(REMB_GENERATOR_SLOT)`): with the other arrival recorders, after the RFC 8888
/// one (9_000) and before the receiver report (10_000).
pub const REMB_GENERATOR_SLOT: usize = 9_500;

/// Where the default interceptor set puts the [`AbsSendTimeInterceptor`]
/// (`Slot::Custom(ABS_SEND_TIME_SLOT)`): wire-ward of the pacer (3_000), so the stamp is the
/// instant a packet leaves it, and of the TWCC sender (2_000); application-ward of the FEC
/// wire-image tap (1_500), so FEC protects the stamped packet.
pub const ABS_SEND_TIME_SLOT: usize = 1_900;

/// The RTCP feedback type that negotiates REMB (`a=rtcp-fb:<pt> goog-remb`).
pub const GOOG_REMB: &str = "goog-remb";

/// How often the arrivals are given to the estimator.
pub const REMB_UPDATE_INTERVAL: Duration = Duration::from_millis(100);

/// The longest a REMB waits when nothing has changed (section 3: "at least once per second").
pub const REMB_MAX_INTERVAL: Duration = Duration::from_secs(1);

/// An estimate below this share of the last one sent is news (congestion) and goes out at
/// once, as libwebrtc's `kSendThresholdPercent` has it.
pub const REMB_DECREASE_TRIGGER: f64 = 0.97;

/// How long arrivals are watched before the first estimate is made from what they carry.
///
/// A sender is still finding its rate in its first seconds; an estimate started from the
/// controller's default and sent at once would cap it there. As libwebrtc's
/// `AimdRateControl` does, the first estimate is the incoming rate after this long.
pub const REMB_INITIALIZATION_TIME: Duration = Duration::from_secs(5);

/// The lowest estimate a REMB carries.
const REMB_MIN_BITRATE: f64 = 10_000.0;
/// The highest.
const REMB_MAX_BITRATE: f64 = 1_000_000_000.0;

/// Abs-send-time: 6.18 fixed-point seconds in 24 bits.
const ABS_SEND_TIME_HZ: f64 = (1u64 << 18) as f64;
const ABS_SEND_TIME_MODULUS: u64 = 1 << 24;
const RTP_TIMESTAMP_MODULUS: u64 = 1 << 32;

/// A wrapping send clock, unwrapped: ticks since its first reading.
#[derive(Debug, Clone, Copy)]
struct SendClock {
    hz: f64,
    modulus: u64,
    last: Option<u64>,
    /// Ticks since the first reading (negative for a packet sent before it, reordered).
    unwrapped: i64,
}

impl SendClock {
    fn new(hz: f64, modulus: u64) -> Self {
        Self {
            hz,
            modulus,
            last: None,
            unwrapped: 0,
        }
    }

    /// Seconds since the first reading, for a raw reading.
    fn seconds(&mut self, raw: u64) -> f64 {
        let raw = raw % self.modulus;
        if let Some(last) = self.last {
            // The shorter way round the circle: forward up to half of it, back otherwise.
            let forward = (raw + self.modulus - last) % self.modulus;
            let delta = if forward <= self.modulus / 2 {
                forward as i64
            } else {
                forward as i64 - self.modulus as i64
            };
            self.unwrapped += delta;
        }
        self.last = Some(raw);
        self.unwrapped as f64 / self.hz
    }
}

/// One delay-based estimate and what feeds it.
struct Estimate {
    clock: SendClock,
    /// The arrival instant the first packet's send time is placed at.
    anchor: Instant,
    /// The send time of the packet placed at `anchor`, in seconds of `clock`.
    anchor_seconds: f64,
    /// Arrivals not yet given to the estimator.
    reports: Vec<PacketReport>,
    /// What arrived, for the first estimate.
    incoming: RateCalculator,
    first_arrival: Instant,
    gcc: Option<Gcc>,
    next_id: u64,
}

impl Estimate {
    fn new(clock: SendClock, now: Instant) -> Self {
        Self {
            clock,
            anchor: now,
            anchor_seconds: f64::NAN,
            reports: Vec::new(),
            incoming: RateCalculator::new(Duration::from_secs(1)),
            first_arrival: now,
            gcc: None,
            next_id: 0,
        }
    }

    fn record(&mut self, now: Instant, epoch: Instant, ssrc: u32, raw_send_time: u64, size: usize) {
        let seconds = self.clock.seconds(raw_send_time);
        if self.anchor_seconds.is_nan() {
            self.anchor_seconds = seconds;
        }
        let offset = seconds - self.anchor_seconds;
        let departure = if offset >= 0.0 {
            self.anchor + Duration::from_secs_f64(offset)
        } else {
            self.anchor
                .checked_sub(Duration::from_secs_f64(-offset))
                .unwrap_or(self.anchor)
        };
        self.incoming.add(now, size);
        let id = self.next_id;
        self.next_id += 1;
        self.reports.push(PacketReport {
            ssrc,
            id,
            rtp_sequence_number: 0,
            is_twcc: false,
            twcc_sequence_number: 0,
            size,
            arrived: true,
            departure,
            arrival: Some(now.saturating_duration_since(epoch)),
            ecn: Ecn::default(),
        });
    }

    /// Gives the estimator what arrived; the estimate, once there is one.
    fn update(&mut self, now: Instant) -> Option<f64> {
        if self.gcc.is_none() {
            if now.saturating_duration_since(self.first_arrival) < REMB_INITIALIZATION_TIME {
                self.reports.clear();
                return None;
            }
            let incoming = self.incoming.rate_bits_per_second(now)?;
            self.gcc = Some(Gcc::new(incoming, REMB_MIN_BITRATE, REMB_MAX_BITRATE));
        }
        let gcc = self.gcc.as_mut()?;
        let reports = std::mem::take(&mut self.reports);
        gcc.on_reports(now, &reports);
        Some(gcc.target_bitrate())
    }
}

/// A remote stream REMB is generated for.
#[derive(Debug, Clone, Copy)]
struct RembStream {
    clock_rate: u32,
    abs_send_time_id: Option<u8>,
}

/// Which estimate a stream's packets feed: the shared one of the abs-send-time clock, or the
/// stream's own.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
enum EstimateKey {
    AbsSendTime,
    Stream(u32),
}

/// Builds a [`RembGeneratorInterceptor`].
#[derive(Debug, Clone)]
pub struct RembGeneratorBuilder {
    interval: Duration,
    sender_ssrc: Option<u32>,
}

impl Default for RembGeneratorBuilder {
    fn default() -> Self {
        Self {
            interval: REMB_UPDATE_INTERVAL,
            sender_ssrc: None,
        }
    }
}

impl RembGeneratorBuilder {
    /// A builder with the defaults: arrivals read every 100 ms.
    pub fn new() -> Self {
        Self::default()
    }

    /// How often the arrivals are given to the estimator.
    pub fn with_interval(mut self, interval: Duration) -> Self {
        self.interval = interval;
        self
    }

    /// The SSRC the REMB is sent from (random by default, as the other feedback
    /// generators' are).
    pub fn with_sender_ssrc(mut self, sender_ssrc: u32) -> Self {
        self.sender_ssrc = Some(sender_ssrc);
        self
    }

    /// Build the interceptor.
    pub fn build(self) -> RembGeneratorInterceptor {
        RembGeneratorInterceptor {
            interval: self.interval,
            sender_ssrc: self
                .sender_ssrc
                .unwrap_or_else(|| rand::random::<u32>().max(1)),
            streams: HashMap::new(),
            estimates: BTreeMap::new(),
            epoch: None,
            next_update: None,
            last_sent: None,
            read_queue: VecDeque::new(),
            write_queue: VecDeque::new(),
        }
    }
}

/// Generates REMB for the remote streams that negotiated `goog-remb` and no per-packet
/// congestion feedback (see the `gcc::remb` module's source documentation).
pub struct RembGeneratorInterceptor {
    interval: Duration,
    sender_ssrc: u32,
    streams: HashMap<u32, RembStream>,
    estimates: BTreeMap<EstimateKey, Estimate>,
    /// The first arrival: what arrival times are measured from.
    epoch: Option<Instant>,
    next_update: Option<Instant>,
    /// The last REMB: its bit rate and when it was sent.
    last_sent: Option<(f64, Instant)>,
    read_queue: VecDeque<TaggedPacket>,
    write_queue: VecDeque<TaggedPacket>,
}

impl RembGeneratorInterceptor {
    fn record(&mut self, msg: &TaggedPacket) {
        let Packet::Rtp(packet) = &msg.message.packet else {
            return;
        };
        let Some(stream) = self.streams.get(&packet.header.ssrc).copied() else {
            return;
        };
        if msg
            .message
            .attributes
            .iter()
            .any(|attribute| matches!(attribute, Attribute::Retransmitted { .. }))
        {
            return;
        }
        let abs_send_time = stream.abs_send_time_id.and_then(|id| {
            let mut data = packet.header.get_extension(id)?;
            rtp::extension::abs_send_time_extension::AbsSendTimeExtension::unmarshal(&mut data).ok()
        });
        let (key, raw, clock) = match abs_send_time {
            Some(extension) => (
                EstimateKey::AbsSendTime,
                extension.timestamp,
                SendClock::new(ABS_SEND_TIME_HZ, ABS_SEND_TIME_MODULUS),
            ),
            None if stream.clock_rate > 0 => (
                EstimateKey::Stream(packet.header.ssrc),
                u64::from(packet.header.timestamp),
                SendClock::new(f64::from(stream.clock_rate), RTP_TIMESTAMP_MODULUS),
            ),
            None => return,
        };
        let now = msg.now;
        let epoch = *self.epoch.get_or_insert(now);
        self.next_update.get_or_insert(now + self.interval);
        self.estimates
            .entry(key)
            .or_insert_with(|| Estimate::new(clock, now))
            .record(now, epoch, packet.header.ssrc, raw, packet.marshal_size());
    }

    fn update(&mut self, now: Instant) {
        let mut total = 0.0;
        let mut any = false;
        for estimate in self.estimates.values_mut() {
            if let Some(bitrate) = estimate.update(now) {
                total += bitrate;
                any = true;
            }
        }
        if !any {
            return;
        }
        let due = match self.last_sent {
            None => true,
            Some((last, at)) => {
                total < REMB_DECREASE_TRIGGER * last
                    || now.saturating_duration_since(at) >= REMB_MAX_INTERVAL
            }
        };
        if !due {
            return;
        }
        let mut ssrcs: Vec<u32> = self.streams.keys().copied().collect();
        ssrcs.sort_unstable();
        self.last_sent = Some((total, now));
        self.write_queue.push_back(TaggedPacket {
            now,
            transport: TransportContext::default(),
            message: AttributedPacket::new(Packet::Rtcp(vec![Box::new(
                ReceiverEstimatedMaximumBitrate {
                    sender_ssrc: self.sender_ssrc,
                    bitrate: total as f32,
                    ssrcs,
                },
            )])),
        });
    }
}

impl Protocol<TaggedPacket, TaggedPacket, ()> for RembGeneratorInterceptor {
    type Rout = TaggedPacket;
    type Wout = TaggedPacket;
    type Eout = ();
    type Error = Error;
    type Time = Instant;

    fn handle_read(&mut self, msg: TaggedPacket) -> Result<(), Self::Error> {
        self.record(&msg);
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

    fn poll_write(&mut self) -> Option<Self::Wout> {
        self.write_queue.pop_front()
    }

    fn handle_timeout(&mut self, now: Instant) -> Result<(), Self::Error> {
        if let Some(at) = self.next_update
            && now >= at
        {
            self.update(now);
            self.next_update = (!self.streams.is_empty()).then(|| now + self.interval);
        }
        Ok(())
    }

    fn poll_timeout(&mut self) -> Option<Self::Time> {
        self.next_update
    }
}

/// Whether REMB is generated for a remote stream: it negotiated `goog-remb`, and no
/// per-packet feedback that would let the sender estimate for itself.
fn wants_remb(info: &StreamInfo) -> bool {
    info.rtcp_feedback.iter().any(|fb| fb.typ == GOOG_REMB)
        && negotiated_congestion_feedback(info).is_none()
}

fn abs_send_time_id(info: &StreamInfo) -> Option<u8> {
    info.rtp_header_extensions
        .iter()
        .find(|ext| ext.uri == ABS_SEND_TIME_URI)
        .and_then(|ext| u8::try_from(ext.id).ok())
        .filter(|id| *id != 0)
}

impl Interceptor for RembGeneratorInterceptor {
    fn bind_remote_stream(&mut self, info: &StreamInfo) {
        if !wants_remb(info) {
            self.streams.remove(&info.ssrc);
            return;
        }
        self.streams.insert(
            info.ssrc,
            RembStream {
                clock_rate: info.clock_rate,
                abs_send_time_id: abs_send_time_id(info),
            },
        );
    }

    fn unbind_remote_stream(&mut self, info: &StreamInfo) {
        self.streams.remove(&info.ssrc);
        self.estimates.remove(&EstimateKey::Stream(info.ssrc));
        if !self
            .streams
            .values()
            .any(|stream| stream.abs_send_time_id.is_some())
        {
            self.estimates.remove(&EstimateKey::AbsSendTime);
        }
        if self.streams.is_empty() {
            self.next_update = None;
        }
    }

    fn bind_local_stream(&mut self, _info: &StreamInfo) {}

    fn unbind_local_stream(&mut self, _info: &StreamInfo) {}
}

/// Stamps the abs-send-time header extension on every packet of a local stream that
/// negotiated it (see the `gcc::remb` module's source documentation): 6.18 fixed-point seconds of the
/// instant the packet passes, which is as it leaves the pacer when the interceptor sits below
/// it (the default set puts it at `Slot::Custom(1_900)`).
#[derive(Default)]
pub struct AbsSendTimeInterceptor {
    /// The extension id, by SSRC (media, RTX and FEC of each stream).
    ids: HashMap<u32, u8>,
    epoch: Option<Instant>,
    read_queue: VecDeque<TaggedPacket>,
    write_queue: VecDeque<TaggedPacket>,
}

impl AbsSendTimeInterceptor {
    /// An interceptor with no stream bound yet.
    pub fn new() -> Self {
        Self::default()
    }

    /// The extension's value at `now`: seconds since the first packet stamped, 6.18
    /// fixed-point, modulo 64 s.
    fn stamp(&mut self, now: Instant) -> [u8; 3] {
        let epoch = *self.epoch.get_or_insert(now);
        let seconds = now.saturating_duration_since(epoch).as_secs_f64();
        let ticks = ((seconds * ABS_SEND_TIME_HZ) as u64) % ABS_SEND_TIME_MODULUS;
        [(ticks >> 16) as u8, (ticks >> 8) as u8, ticks as u8]
    }
}

impl Protocol<TaggedPacket, TaggedPacket, ()> for AbsSendTimeInterceptor {
    type Rout = TaggedPacket;
    type Wout = TaggedPacket;
    type Eout = ();
    type Error = Error;
    type Time = Instant;

    fn handle_read(&mut self, msg: TaggedPacket) -> Result<(), Self::Error> {
        self.read_queue.push_back(msg);
        Ok(())
    }

    fn poll_read(&mut self) -> Option<Self::Rout> {
        self.read_queue.pop_front()
    }

    fn handle_write(&mut self, mut msg: TaggedPacket) -> Result<(), Self::Error> {
        if let Packet::Rtp(packet) = &mut msg.message.packet
            && let Some(id) = self.ids.get(&packet.header.ssrc).copied()
        {
            let stamp = self.stamp(msg.now);
            let _ = packet
                .header
                .set_extension_upgrading(id, bytes::Bytes::copy_from_slice(&stamp));
        }
        self.write_queue.push_back(msg);
        Ok(())
    }

    fn poll_write(&mut self) -> Option<Self::Wout> {
        self.write_queue.pop_front()
    }

    fn handle_timeout(&mut self, _now: Instant) -> Result<(), Self::Error> {
        Ok(())
    }

    fn poll_timeout(&mut self) -> Option<Self::Time> {
        None
    }
}

impl Interceptor for AbsSendTimeInterceptor {
    fn bind_remote_stream(&mut self, _info: &StreamInfo) {}

    fn unbind_remote_stream(&mut self, _info: &StreamInfo) {}

    fn bind_local_stream(&mut self, info: &StreamInfo) {
        if let Some(id) = abs_send_time_id(info) {
            for ssrc in flow_ssrcs(info) {
                self.ids.insert(ssrc, id);
            }
        }
    }

    fn unbind_local_stream(&mut self, info: &StreamInfo) {
        for ssrc in flow_ssrcs(info) {
            self.ids.remove(&ssrc);
        }
    }
}

#[cfg(test)]
#[path = "remb_test.rs"]
mod remb_test;
