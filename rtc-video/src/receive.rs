//! The receive pipeline of one video stream: packets in, pictures to decode out at their time,
//! key-frame requests and statistics on the way.
//!
//! The release rule is libwebrtc's `video/frame_decode_timing.cc` (a222406d): the next
//! decodable picture is released when `render_time - decode_time - render_delay` has come; a
//! picture already more than 5 ms past that (`kMaxAllowedFrameDelay`,
//! `frame_decode_timing.h:34`) is dropped when a later one is decodable; while a key frame is
//! needed the first decodable key frame goes at once (`ForceKeyFrameReleaseImmediately`); on
//! the low-latency path pictures go as soon as they are decodable. At most
//! `max_pending_decodes` pictures are out with the decoder (libwebrtc
//! `kMaxPendingPostDecodeFrames`, `video_receive_stream2.cc:780`).

use std::collections::{BTreeMap, VecDeque};
use std::time::{Duration, Instant};

use bytes::BytesMut;

use crate::assembly::{DEFAULT_MAX_PACKETS, PacketBuffer};
use crate::buffer::{DEFAULT_MAX_FRAMES, DecodableUnit, FrameBuffer};
use crate::frame::{Codec, EncodedFrame, VideoPacket};
use crate::keyframe::{KeyFramePolicy, KeyFrameReason, waits_for};
use crate::payload::read_position;
use crate::reference::ReferenceFinder;
use crate::render::{CHROME_MIN_FREEZE_SAMPLES, RenderStats};
use crate::stats::ReceiveStats;
use crate::timing::{MAX_VIDEO_DELAY, Timing};

/// libwebrtc `kMaxAllowedFrameDelay`.
pub const MAX_ALLOWED_FRAME_DELAY: Duration = Duration::from_millis(5);

/// Settings of a receive pipeline.
#[derive(Debug, Clone)]
pub struct ReceiveConfig {
    /// Packets the packet buffer holds.
    pub max_packets: usize,
    /// Frames the frame buffer holds.
    pub max_frames: usize,
    /// The sender's `rtx-time` (RFC 4588 8.1), which shortens the key-frame waits.
    pub rtx_time: Option<Duration>,
    /// Pictures out with the decoder at once.
    pub max_pending_decodes: usize,
    /// Intervals before freezes are judged (1: W3C; 5: libwebrtc).
    pub min_freeze_samples: usize,
    /// A packet that arrives this long after a packet with a higher sequence number is taken
    /// as a retransmission (the engine folds RTX back before the application sees it, so the
    /// arrival pattern is all there is). `None`: never.
    pub retransmission_lateness: Option<Duration>,
}

impl Default for ReceiveConfig {
    fn default() -> Self {
        Self {
            max_packets: DEFAULT_MAX_PACKETS,
            max_frames: DEFAULT_MAX_FRAMES,
            rtx_time: None,
            max_pending_decodes: 2,
            min_freeze_samples: 1,
            retransmission_lateness: Some(Duration::from_millis(50)),
        }
    }
}

impl ReceiveConfig {
    /// libwebrtc's choices where they differ from the W3C definitions (the `Chrome`
    /// behaviour profile): freezes judged from the fifth interval.
    pub fn chrome() -> Self {
        Self {
            min_freeze_samples: CHROME_MIN_FREEZE_SAMPLES,
            ..Self::default()
        }
    }
}

/// A picture to decode.
#[derive(Debug, Clone)]
pub struct DecodeRequest {
    /// Hand back with the outcome.
    pub token: u64,
    /// The picture: one frame, or every spatial layer of a picture joined (the last frame's
    /// id and references, the first frame's other metadata).
    pub frame: EncodedFrame,
    /// When it should be rendered; `None` for at once (low-latency path).
    pub render_time: Option<Instant>,
}

/// What the decoder made of a picture.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecodeOutcome {
    /// Decoded.
    Decoded {
        /// Width.
        width: u32,
        /// Height.
        height: u32,
        /// QP, when known.
        qp: Option<u32>,
        /// How long decoding took.
        decode_time: Duration,
        /// The decoder decoded it and still asks for a key frame.
        request_key_frame: bool,
    },
    /// Not decoded.
    Failed,
}

#[derive(Debug, Clone)]
struct Pending {
    first_arrival: Instant,
    last_arrival: Instant,
    multi_packet: bool,
    keyframe: bool,
}

/// The receive pipeline of one stream.
#[derive(Debug)]
pub struct ReceivePipeline {
    config: ReceiveConfig,
    codec: Codec,
    packets: PacketBuffer,
    finder: ReferenceFinder,
    frames: FrameBuffer,
    timing: Timing,
    keyframes: KeyFramePolicy,
    render: RenderStats,
    stats: ReceiveStats,
    /// Arrival times of the recent packets, by extended sequence number.
    arrivals: BTreeMap<i64, Instant>,
    pending: BTreeMap<u64, Pending>,
    next_token: u64,
    decoded_at: VecDeque<Instant>,
    playout_delay_ext: Option<(Duration, Duration)>,
    jitter_buffer_target: Option<Duration>,
    sync_delay: Option<Duration>,
    /// Packets at or before this are no longer useful (their frames were released or
    /// dropped): the NACK horizon.
    released_to: Option<i64>,
    frames_dropped_by_finder: u64,
}

impl ReceivePipeline {
    /// A pipeline for a stream of `codec`, starting at `now`.
    pub fn new(codec: Codec, now: Instant, config: ReceiveConfig) -> Self {
        Self {
            packets: PacketBuffer::new(codec, config.max_packets),
            finder: ReferenceFinder::new(),
            frames: FrameBuffer::new(config.max_frames),
            timing: Timing::new(now),
            keyframes: KeyFramePolicy::new(now, waits_for(config.rtx_time)),
            render: RenderStats::new(config.min_freeze_samples),
            stats: ReceiveStats::default(),
            arrivals: BTreeMap::new(),
            pending: BTreeMap::new(),
            next_token: 0,
            decoded_at: VecDeque::new(),
            playout_delay_ext: None,
            jitter_buffer_target: None,
            sync_delay: None,
            released_to: None,
            frames_dropped_by_finder: 0,
            codec,
            config,
        }
    }

    /// The codec.
    pub fn codec(&self) -> Codec {
        self.codec
    }

    /// The timing state.
    pub fn timing(&self) -> &Timing {
        &self.timing
    }

    /// Whether only a key frame can be decoded next.
    pub fn keyframe_required(&self) -> bool {
        self.keyframes.keyframe_required()
    }

    /// The oldest sequence number still useful: packets before it belong to frames released
    /// or given up, and need not be asked for again (RFC 4588 6.3).
    pub fn nack_horizon(&self) -> Option<i64> {
        self.released_to.map(|s| s + 1)
    }

    /// The round-trip time, for the jitter estimate's retransmission term.
    pub fn set_rtt(&mut self, rtt: Duration) {
        self.timing.update_rtt(rtt);
    }

    /// The application's `jitterBufferTarget` (W3C webrtc-extensions), raising the minimum
    /// playout delay.
    pub fn set_jitter_buffer_target(&mut self, target: Option<Duration>) {
        self.jitter_buffer_target = target;
        self.update_playout_delay();
    }

    /// Extra delay from A/V synchronisation.
    pub fn set_sync_delay(&mut self, delay: Option<Duration>) {
        self.sync_delay = delay;
        self.update_playout_delay();
    }

    fn update_playout_delay(&mut self) {
        let (ext_min, ext_max) = self
            .playout_delay_ext
            .unwrap_or((Duration::ZERO, MAX_VIDEO_DELAY));
        let min = ext_min
            .max(self.jitter_buffer_target.unwrap_or_default())
            .max(self.sync_delay.unwrap_or_default());
        self.timing.min_playout_delay = min;
        self.timing.max_playout_delay = ext_max.max(min);
    }

    /// A Dependency Descriptor could not be read: its structure was never received.
    pub fn on_missing_structure(&mut self, now: Instant) {
        self.keyframes.on_missing_structure(now);
    }

    /// Takes a packet.
    pub fn insert_packet(&mut self, mut packet: VideoPacket) {
        let now = packet.arrival;
        let seq = self.packets.peek_sequence(packet.sequence_number);
        // The gap this packet fills became visible when the first packet after it arrived: a
        // packet that comes `retransmission_lateness` after that was asked for again.
        if let Some(lateness) = self.config.retransmission_lateness
            && let Some((_, seen)) = self.arrivals.range(seq + 1..).next()
            && now.saturating_duration_since(*seen) >= lateness
        {
            packet.retransmitted = true;
        }
        self.arrivals.insert(seq, now);
        while self.arrivals.len() > 2048 {
            self.arrivals.pop_first();
        }
        if packet.retransmitted {
            self.stats.packets_retransmitted += 1;
        }
        if !packet.payload.is_empty() {
            let key = read_position(self.codec, packet.marker, &packet.payload)
                .is_some_and(|p| p.keyframe);
            self.keyframes.on_packet(now, key);
        }
        if let Some((min, max)) = packet.playout_delay_ms {
            let ext = (
                Duration::from_millis(u64::from(min) * 10),
                Duration::from_millis(u64::from(max) * 10),
            );
            if self.playout_delay_ext != Some(ext) {
                self.playout_delay_ext = Some(ext);
                self.update_playout_delay();
            }
        }
        let outcome = self.packets.insert(packet);
        if outcome.duplicate {
            self.stats.packets_duplicated += 1;
        }
        if outcome.late {
            self.stats.packets_discarded += 1;
        }
        if outcome.buffer_cleared {
            self.keyframes.on_buffer_cleared(now);
        }
        for _ in 0..outcome.unparsable_frames {
            self.keyframes.on_unparsable(now);
        }
        let mut encoded = Vec::new();
        if let Some(seq) = outcome.padding {
            encoded.extend(self.finder.padding(seq));
        }
        for frame in outcome.frames {
            self.stats.frames_received += 1;
            self.keyframes.on_frame_assembled(now, frame.keyframe);
            self.timing.on_complete_frame(
                frame.rtp_timestamp,
                frame.last_arrival,
                frame.retransmitted,
                frame.end_of_picture,
            );
            encoded.extend(self.finder.manage(frame));
        }
        self.frames_dropped_by_finder = self.finder.dropped();
        for f in encoded {
            let _ = self.frames.insert(f);
        }
    }

    fn release_time(
        &self,
        unit: &DecodableUnit,
        now: Instant,
    ) -> (Option<Instant>, Option<Instant>) {
        let render = self.timing.render_time(unit.rtp_timestamp, now);
        let release = render.map(|r| {
            r.checked_sub(self.timing.decode_time + self.timing.render_delay)
                .unwrap_or(r)
        });
        (render, release)
    }

    /// The next picture to decode, if one is due at `now`.
    pub fn poll_frame(&mut self, now: Instant) -> Option<DecodeRequest> {
        if self.pending.len() >= self.config.max_pending_decodes {
            return None;
        }
        let keyframe_only = self.keyframes.keyframe_required();
        loop {
            let unit = self.frames.next_decodable(keyframe_only)?;
            let (mut render, release) = self.release_time(&unit, now);
            if !keyframe_only && let Some(release) = release {
                if let Some(r) = render
                    && (r > now + MAX_VIDEO_DELAY
                        || r + MAX_VIDEO_DELAY < now
                        || self.timing.target_delay() > MAX_VIDEO_DELAY)
                {
                    log::warn!("bad render timing: timing reset");
                    self.timing.reset(now);
                    render = self.timing.render_time(unit.rtp_timestamp, now);
                } else if release > now {
                    return None;
                } else if now - release > MAX_ALLOWED_FRAME_DELAY && unit.more_decodable {
                    self.frames.drop_unit(&unit);
                    continue;
                }
            }
            return Some(self.release(now, unit, render));
        }
    }

    fn release(
        &mut self,
        now: Instant,
        unit: DecodableUnit,
        render: Option<Instant>,
    ) -> DecodeRequest {
        let frames = self.frames.extract(&unit);
        let first_arrival = frames
            .iter()
            .map(|f| f.frame.first_arrival)
            .min()
            .unwrap_or(now);
        let last_arrival = frames
            .iter()
            .map(|f| f.frame.last_arrival)
            .max()
            .unwrap_or(now);
        let retransmitted = frames.iter().any(|f| f.frame.retransmitted);
        let size: usize = frames.iter().map(|f| f.frame.data.len()).sum();
        let packets: usize = frames.iter().map(|f| f.frame.packet_count).sum();
        let last_seq = frames
            .iter()
            .map(|f| f.frame.last_sequence)
            .max()
            .unwrap_or(0);
        self.timing
            .on_decodable(now, unit.rtp_timestamp, size, last_arrival, retransmitted);
        if !retransmitted && let Some(r) = render {
            self.timing.update_current_delay(r, now);
        }
        let s = &mut self.stats;
        s.jitter_buffer_delay += now.saturating_duration_since(first_arrival).as_secs_f64();
        s.jitter_buffer_target_delay += self.timing.stats_target_delay().as_secs_f64();
        s.jitter_buffer_minimum_delay += self.timing.minimum_delay.as_secs_f64();
        s.jitter_buffer_emitted_count += 1;
        self.keyframes.on_released(now);
        self.released_to = Some(self.released_to.map_or(last_seq, |r| r.max(last_seq)));
        self.packets.clear_to(last_seq);
        self.finder.clear_to(last_seq);
        let keyframe = frames.first().is_some_and(|f| f.is_keyframe());
        let frame = combine(frames);
        let token = self.next_token;
        self.next_token += 1;
        self.pending.insert(
            token,
            Pending {
                first_arrival,
                last_arrival,
                multi_packet: packets > 1,
                keyframe,
            },
        );
        DecodeRequest {
            token,
            frame,
            render_time: render,
        }
    }

    /// The decoder's outcome for the picture of `token`, at `now`.
    pub fn on_decoded(&mut self, now: Instant, token: u64, outcome: DecodeOutcome) {
        let Some(p) = self.pending.remove(&token) else {
            return;
        };
        match outcome {
            DecodeOutcome::Decoded {
                width,
                height,
                qp,
                decode_time,
                request_key_frame,
            } => {
                let s = &mut self.stats;
                s.frames_decoded += 1;
                if p.keyframe {
                    s.key_frames_decoded += 1;
                }
                s.total_decode_time += decode_time.as_secs_f64();
                s.total_processing_delay +=
                    now.saturating_duration_since(p.first_arrival).as_secs_f64();
                if p.multi_packet {
                    s.frames_assembled_from_multiple_packets += 1;
                    s.total_assembly_time += p
                        .last_arrival
                        .saturating_duration_since(p.first_arrival)
                        .as_secs_f64();
                }
                if let Some(qp) = qp {
                    *s.qp_sum.get_or_insert(0) += u64::from(qp);
                }
                s.frame_size = Some((width, height));
                self.decoded_at.push_back(now);
                self.timing.on_decode_time(now, decode_time);
                self.keyframes
                    .on_decoded(now, true, p.keyframe, request_key_frame);
            }
            DecodeOutcome::Failed => {
                self.stats.decode_errors += 1;
                self.keyframes.on_decoded(now, false, p.keyframe, false);
            }
        }
    }

    /// A picture was rendered at `now`.
    pub fn on_rendered(&mut self, now: Instant) {
        self.render.on_rendered(now);
    }

    /// Runs the timers due at `now`.
    pub fn handle_timeout(&mut self, now: Instant) {
        self.keyframes.on_timeout(now);
    }

    /// When the pipeline next needs [`handle_timeout`](Self::handle_timeout) or
    /// [`poll_frame`](Self::poll_frame).
    pub fn poll_timeout(&self, now: Instant) -> Instant {
        let mut t = self.keyframes.deadline();
        if self.pending.len() < self.config.max_pending_decodes
            && let Some(unit) = self
                .frames
                .next_decodable(self.keyframes.keyframe_required())
        {
            match self.release_time(&unit, now).1 {
                Some(r) if !self.keyframes.keyframe_required() => t = t.min(r),
                _ => t = t.min(now),
            }
        }
        t
    }

    /// A key-frame request due now, with its reason: send a PLI.
    pub fn poll_key_frame_request(&mut self) -> Option<KeyFrameReason> {
        let reason = self.keyframes.poll_request()?;
        *self.stats.key_frame_requests.entry(reason).or_default() += 1;
        Some(reason)
    }

    /// The statistics at `now`.
    pub fn stats(&mut self, now: Instant) -> ReceiveStats {
        while let Some(t) = self.decoded_at.front() {
            if now.saturating_duration_since(*t) > Duration::from_secs(1) {
                self.decoded_at.pop_front();
            } else {
                break;
            }
        }
        let mut s = self.stats.clone();
        s.frames_per_second = self.decoded_at.len() as f64;
        s.frames_dropped = (self.frames.dropped_frames() + self.frames_dropped_by_finder) as u32;
        s.packets_discarded += self.frames.dropped_packets();
        let r = &self.render;
        s.frames_rendered = r.frames_rendered;
        s.total_inter_frame_delay = r.total_inter_frame_delay;
        s.total_squared_inter_frame_delay = r.total_squared_inter_frame_delay;
        s.freeze_count = r.freeze_count;
        s.total_freezes_duration = r.total_freezes_duration;
        s.pause_count = r.pause_count;
        s.total_pauses_duration = r.total_pauses_duration;
        s.longest_render_interval = r.longest_interval.as_secs_f64();
        s
    }
}

/// Joins the frames of one picture: the bitstreams in order, the last frame's id, the
/// references from outside the picture, every frame's id in `layer_ids`, the first frame's
/// other metadata.
fn combine(mut frames: Vec<EncodedFrame>) -> EncodedFrame {
    if frames.len() == 1 {
        return frames.pop().expect("one frame");
    }
    let ids: Vec<i64> = frames.iter().map(|f| f.id).collect();
    let id = *ids.last().expect("a picture has a frame");
    let mut references: Vec<i64> = frames
        .iter()
        .flat_map(|f| f.references.iter().copied())
        .filter(|r| !ids.contains(r))
        .collect();
    references.sort_unstable();
    references.dedup();
    let last = frames.last().expect("a picture has a frame");
    let mut data = BytesMut::new();
    let mut packets = 0;
    let mut last_arrival = last.frame.last_arrival;
    for f in &frames {
        data.extend_from_slice(&f.frame.data);
        packets += f.frame.packet_count;
        last_arrival = last_arrival.max(f.frame.last_arrival);
    }
    let mut first = frames.swap_remove(0);
    first.id = id;
    first.references = references;
    first.layer_ids = ids;
    first.frame.data = data.freeze();
    first.frame.packet_count = packets;
    first.frame.last_arrival = last_arrival;
    first.frame.end_of_picture = true;
    first
}
