//! The send pipeline: pictures in, RTP packets out, following the congestion controller.
//!
//! ```text
//!  picture ─▶ pause? ─▶ frame-rate step ─▶ scale to the resolution step ─▶ VideoEncoder ─▶ payloader ─▶ RTP packets
//!   (capture time)  target 0   (degradation)         (degradation)           (key frame?)   (the codec's)
//!                     ▲             ▲                       ▲                     ▲
//!                 set_target_bitrate (the estimate less the retransmission reserve)│
//!                                                                 request_key_frame (PLI, FIR, pacer discard)
//! ```
//!
//! Like the rest of the crate it is sans-I/O: no clock, no thread. Every call takes the time
//! (`now`; a picture also its capture time). The encoder runs inside
//! [`SendPipeline::send_frame`], synchronously; an application that wants encoding off its
//! network thread runs the whole pipeline (it is `Send`) on a worker and hands the packets
//! back. [`crate::engine::VideoSender`] connects it to an `RTCRtpSender`.
//!
//! What it does with the engine's signals, and where each rule comes from:
//!
//! - **Target bitrate** ([`set_target_bitrate`](SendPipeline::set_target_bitrate)): the
//!   encoder's rate, never below the encoder's own minimum
//!   ([`VideoEncoder::min_bitrate_bps`]); under that minimum the encoder stays at it and the
//!   pipeline drops pictures in the ratio target / minimum, so that what is sent stays under
//!   the target (RFC 8834 section 7: "Endpoints have to be designed so they do not transmit
//!   significantly more data than the network path can support").
//! - **Pause** (a target of 0, the engine's pacer holding a second of media): no picture is
//!   encoded until the next nonzero target. On resuming the next picture is a key frame when
//!   [`SendConfig::key_frame_on_resume`] (the default); libwebrtc encodes the next picture as a
//!   delta (`video/video_stream_encoder.cc` `OnBitrateUpdated`, lines 2544-2558 @ a222406d:
//!   the frame held during the pause is encoded as it comes), which is
//!   [`SendConfig::chrome`].
//! - **Key-frame requests** ([`request_key_frame`](SendPipeline::request_key_frame)) from a
//!   PLI (RFC 4585 6.3.1), a FIR (RFC 5104 4.3.1) or the pacer's discard: the next picture is a
//!   key frame, rate-limited by [`KeyFrameRateLimit`]. The default is RFC 5104 section 3.5.1:
//!   "A receiver that receives a request closely after sending a decoder refresh point --
//!   within 2 times the longest round trip time (RTT) known, plus any AVPF-induced RTCP packet
//!   sending delays -- should await a second request message"; and for FIR "If it receives
//!   repetitions of the FIR more than 2*RTT after it has sent a decoder refresh point, it shall
//!   send a new decoder refresh point". Requests while a key frame is already due coalesce
//!   into it. libwebrtc's form (at most one request served per 300 ms, whenever the last key
//!   frame was sent; `video/encoder_rtcp_feedback.cc` lines 32, 66-70 @ a222406d) is
//!   [`KeyFrameRateLimit::MinInterval`] in [`SendConfig::chrome`].
//! - **Degradation** when the target falls under what the current resolution and frame rate
//!   need ([`DegradationPreference`], the W3C `RTCDegradationPreference`): resolution steps of
//!   3/5 of the pixels down to 320x180, frame-rate steps of 2/3 down to 2 fps (libwebrtc's
//!   steps and floors, `call/adaptation/video_stream_adapter.cc` lines 40, 45-47, 150-158,
//!   `api/video_codecs/video_encoder.h` line 39 @ a222406d; no specification gives numbers).
//!   What a resolution needs is libwebrtc's VP8 minimum per resolution
//!   ([`min_bitrate_for`]). The default preference is `balanced`, the W3C default
//!   (webrtc-pc CR 2018-09-27 section 5.2.2: "degradationPreference of type
//!   RTCDegradationPreference, defaulting to "balanced""; mst-content-hint maps a "motion"
//!   hint to "maintain-framerate" and "detail" / "text" to "maintain-resolution"); libwebrtc
//!   keeps `maintain-framerate` for a camera without a hint until balanced "has been tuned"
//!   (`media/engine/webrtc_video_engine.cc` lines 2041-2062 @ a222406d), which is
//!   [`SendConfig::chrome`].

use std::collections::VecDeque;
use std::time::{Duration, Instant};

use bytes::Bytes;
use rtp::packetizer::Payloader;

use crate::VIDEO_CLOCK_RATE;
use crate::encoder::{EncodeError, EncoderFactory, VideoEncoder};
use crate::picture::{I420, I420Buffer, scale_into};

/// The round trip assumed while none is known (RFC 7728 section 8.1, the same AVPF family's
/// rule for pause and resume: "RTP stream receivers that lack an RTT estimate to the sender
/// SHOULD use 500 ms as the default value").
pub const DEFAULT_ROUND_TRIP_TIME: Duration = Duration::from_millis(500);

/// libwebrtc's interval between key-frame requests served (`kMinKeyframeSendIntervalMs`,
/// `video/encoder_rtcp_feedback.cc` line 32 @ a222406d).
pub const CHROME_KEY_FRAME_INTERVAL: Duration = Duration::from_millis(300);

/// The smallest resolution the pipeline degrades to, in pixels (libwebrtc's
/// `kDefaultMinPixelsPerFrame`, 320x180). A smaller source is sent at its own size.
pub const MIN_PIXELS: u64 = 320 * 180;

/// The lowest frame rate the pipeline degrades to (libwebrtc's `kMinFrameRateFps`).
pub const MIN_FRAMERATE: f64 = 2.0;

/// The minimum bitrate each resolution needs at 30 frames a second: libwebrtc's VP8 table
/// (`video/config/simulcast.cc` `kSimulcastFormatsVP8`, `min_bitrate`, "The minimum bitrate
/// needed for encoding stream at widthxheight", @ a222406d), as (pixels, bits per second).
const MIN_BITRATE_TABLE: [(u64, u32); 7] = [
    (0, 30_000),
    (320 * 180, 30_000),
    (480 * 270, 150_000),
    (640 * 360, 150_000),
    (960 * 540, 350_000),
    (1280 * 720, 600_000),
    (1920 * 1080, 800_000),
];

/// What a picture of `pixels` needs at `framerate`, in bits per second: the table above,
/// interpolated linearly in pixels between its rows (proportional above 1080p), scaled by
/// `framerate / 30`.
pub fn min_bitrate_for(pixels: u64, framerate: f64) -> u32 {
    let at30 = match MIN_BITRATE_TABLE.windows(2).find(|w| pixels <= w[1].0) {
        Some(w) => {
            let ((p0, b0), (p1, b1)) = (w[0], w[1]);
            let f = (pixels - p0) as f64 / (p1 - p0) as f64;
            f64::from(b0) + f * (f64::from(b1) - f64::from(b0))
        }
        None => {
            let (p, b) = MIN_BITRATE_TABLE[MIN_BITRATE_TABLE.len() - 1];
            f64::from(b) * pixels as f64 / p as f64
        }
    };
    (at30 * framerate / 30.0).round() as u32
}

/// Which of resolution and frame rate gives way when the target is short (W3C
/// `RTCDegradationPreference`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DegradationPreference {
    /// "Degrade a balance of framerate and resolution": the steps alternate, resolution first.
    /// The W3C default.
    Balanced,
    /// "Degrade resolution in order to maintain framerate".
    MaintainFramerate,
    /// "Degrade framerate in order to maintain resolution".
    MaintainResolution,
    /// "Maintain framerate and resolution regardless of video quality": the encoder's rate
    /// control alone meets the target.
    MaintainFramerateAndResolution,
}

/// How often a key-frame request is served.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyFrameRateLimit {
    /// RFC 5104 section 3.5.1: a request that arrives within two round trips of the last key
    /// frame sent is not served (the requester had not seen it yet). The round trip is the one
    /// given to [`SendPipeline::set_rtt`], [`DEFAULT_ROUND_TRIP_TIME`] until then.
    RoundTrips,
    /// At most one request served per interval, whenever the last key frame was sent
    /// (libwebrtc: [`CHROME_KEY_FRAME_INTERVAL`]).
    MinInterval(Duration),
}

/// What asked for a key frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KeyFrameTrigger {
    /// A Picture Loss Indication from the peer (RFC 4585 6.3.1).
    Pli,
    /// A Full Intra Request from the peer (RFC 5104 4.3.1).
    Fir,
    /// The engine's pacer discarded frames of this stream (`OnPacerDiscard`).
    PacerDiscard,
}

/// What became of a key-frame request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyFrameDecision {
    /// The next picture encoded is a key frame.
    Served,
    /// A key frame was already due: this request is answered by it.
    Coalesced,
    /// Not served: too soon after the last key frame (or the last request served), see
    /// [`KeyFrameRateLimit`].
    Suppressed,
}

/// The send pipeline's settings. `Default` is the specifications' behaviour,
/// [`chrome`](Self::chrome) libwebrtc's where it differs.
#[derive(Debug, Clone, PartialEq)]
pub struct SendConfig {
    /// Which of resolution and frame rate gives way. Default `Balanced` (W3C).
    pub degradation_preference: DegradationPreference,
    /// How often key-frame requests are served. Default `RoundTrips` (RFC 5104 3.5.1).
    pub key_frame_rate_limit: KeyFrameRateLimit,
    /// Whether the first picture after a pause (target 0) is a key frame. Default `true`.
    pub key_frame_on_resume: bool,
    /// The highest frame rate encoded (the source's rate, or the encoding's `maxFramerate`).
    pub max_framerate: f64,
    /// The bitrate before the first target arrives.
    pub initial_bitrate_bps: u32,
    /// A step back up to a higher resolution or frame rate needs this much more than that
    /// level needs (1.25: a quarter more), so that an estimate that moves a little does not
    /// switch the resolution back and forth.
    pub upgrade_margin: f64,
}

impl Default for SendConfig {
    fn default() -> Self {
        Self {
            degradation_preference: DegradationPreference::Balanced,
            key_frame_rate_limit: KeyFrameRateLimit::RoundTrips,
            key_frame_on_resume: true,
            max_framerate: 30.0,
            initial_bitrate_bps: 300_000,
            upgrade_margin: 1.25,
        }
    }
}

impl SendConfig {
    /// libwebrtc's choices (the `Chrome` behaviour profile): `maintain-framerate` for a camera,
    /// one key-frame request served per 300 ms, no key frame on resuming from a pause.
    pub fn chrome() -> Self {
        Self {
            degradation_preference: DegradationPreference::MaintainFramerate,
            key_frame_rate_limit: KeyFrameRateLimit::MinInterval(CHROME_KEY_FRAME_INTERVAL),
            key_frame_on_resume: false,
            ..Self::default()
        }
    }
}

/// The RTP stream the pipeline writes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RtpStreamConfig {
    /// The SSRC.
    pub ssrc: u32,
    /// The negotiated payload type of the codec.
    pub payload_type: u8,
    /// The first sequence number (RFC 3550 5.1: random).
    pub first_sequence_number: u16,
    /// The RTP timestamp of the first picture (RFC 3550 5.1: random).
    pub first_timestamp: u32,
    /// The largest RTP packet, header included, in octets.
    pub mtu: usize,
}

/// Why a picture was not sent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DropReason {
    /// The target is 0: the pacer's pause.
    Paused,
    /// The frame-rate step of the degradation, or the target under the encoder's minimum.
    Framerate,
    /// The encoder's rate control skipped it.
    Encoder,
}

/// One picture encoded and packetized.
#[derive(Debug, Clone)]
pub struct SentFrame {
    /// Its RTP packets, in order, the marker bit on the last.
    pub packets: Vec<rtp::Packet>,
    /// Whether it is a key frame.
    pub keyframe: bool,
    /// The encoded size, before packetization.
    pub octets: usize,
    /// The resolution it was encoded at.
    pub width: u32,
    /// See `width`.
    pub height: u32,
    /// Its RTP timestamp.
    pub timestamp: u32,
    /// The capture time of the picture.
    pub capture: Instant,
}

/// What [`SendPipeline::send_frame`] did with a picture.
#[derive(Debug, Clone)]
pub enum FrameOutcome {
    /// Encoded and packetized.
    Sent(SentFrame),
    /// Not sent.
    Dropped(DropReason),
}

/// The send pipeline's statistics; members named after W3C `RTCOutboundRtpStreamStats` where
/// one exists. Times in seconds.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct SendStats {
    /// Pictures given to `send_frame`.
    pub frames_captured: u32,
    /// `framesEncoded`.
    pub frames_encoded: u32,
    /// `keyFramesEncoded`.
    pub key_frames_encoded: u32,
    /// Pictures not encoded because of a pause.
    pub frames_dropped_paused: u32,
    /// Pictures dropped by the frame-rate step or for a target under the encoder's minimum.
    pub frames_dropped_framerate: u32,
    /// Pictures the encoder's rate control skipped.
    pub frames_dropped_encoder: u32,
    /// RTP packets made.
    pub packets_sent: u64,
    /// Encoded octets (payload before packetization).
    pub bytes_encoded: u64,
    /// `qpSum`, when the encoder reports quantizers.
    pub qp_sum: Option<u64>,
    /// `frameWidth`, `frameHeight` of the last picture encoded.
    pub frame_size: Option<(u32, u32)>,
    /// The frame rate of the current degradation step.
    pub framerate: f64,
    /// `targetBitrate`: the last nonzero target.
    pub target_bitrate: Option<f64>,
    /// Pauses begun (targets of 0 after a nonzero one or at the start).
    pub pauses: u32,
    /// Key frames made because a pause ended.
    pub resume_key_frames: u32,
    /// Key-frame requests by what became of them: served, coalesced, suppressed.
    pub key_frame_requests_served: u32,
    /// See `key_frame_requests_served`.
    pub key_frame_requests_coalesced: u32,
    /// See `key_frame_requests_served`.
    pub key_frame_requests_suppressed: u32,
    /// Of all the requests, those from the pacer's discards.
    pub pacer_discards: u32,
    /// `qualityLimitationReason`: bandwidth while degraded, none otherwise.
    pub quality_limited: bool,
    /// `qualityLimitationDurations`: seconds not limited, and limited by bandwidth.
    pub quality_limitation_none: f64,
    /// See `quality_limitation_none`.
    pub quality_limitation_bandwidth: f64,
    /// `qualityLimitationResolutionChanges`.
    pub quality_limitation_resolution_changes: u32,
    /// `encoderImplementation`.
    pub encoder_implementation: Option<String>,
}

/// One step of the degradation: an index into the resolution steps and the frame-rate steps.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Step {
    resolution: usize,
    framerate: usize,
}

struct Encoder {
    inner: Box<dyn VideoEncoder>,
    width: u32,
    height: u32,
    /// Capture times of the pictures given and not yet returned (look-ahead), by input index.
    pending: VecDeque<(u64, Instant)>,
    next_index: u64,
}

/// The send pipeline of one RTP stream (one encoding).
pub struct SendPipeline {
    config: SendConfig,
    factory: Box<dyn EncoderFactory>,
    payloader: Box<dyn Payloader>,
    rtp: RtpStreamConfig,
    encoder: Option<Encoder>,
    sequence_number: u16,
    first_capture: Option<Instant>,
    target: Option<f64>,
    paused: bool,
    rtt: Option<Duration>,
    key_pending: bool,
    last_key_frame: Option<Instant>,
    last_request_served: Option<Instant>,
    source: Option<(u32, u32)>,
    resolutions: Vec<(u32, u32)>,
    framerates: Vec<f64>,
    path: Vec<Step>,
    level: usize,
    budget: f64,
    last_capture: Option<Instant>,
    scaled: I420Buffer,
    accounted_until: Option<Instant>,
    stats: SendStats,
}

impl SendPipeline {
    /// A pipeline that makes its encoders with `factory` and packetizes with `payloader` (the
    /// negotiated codec's: `RTCRtpCodec::payloader()` of the engine, or one of `rtp::codec`).
    pub fn new(
        factory: Box<dyn EncoderFactory>,
        payloader: Box<dyn Payloader>,
        rtp: RtpStreamConfig,
        config: SendConfig,
    ) -> Self {
        let framerate = config.max_framerate;
        Self {
            config,
            factory,
            payloader,
            sequence_number: rtp.first_sequence_number,
            rtp,
            encoder: None,
            first_capture: None,
            target: None,
            paused: false,
            rtt: None,
            key_pending: false,
            last_key_frame: None,
            last_request_served: None,
            source: None,
            resolutions: Vec::new(),
            framerates: Vec::new(),
            path: Vec::new(),
            level: 0,
            budget: 1.0,
            last_capture: None,
            scaled: I420Buffer::default(),
            accounted_until: None,
            stats: SendStats {
                framerate,
                ..SendStats::default()
            },
        }
    }

    /// The settings.
    pub fn config(&self) -> &SendConfig {
        &self.config
    }

    /// The round-trip time to the peer (for [`KeyFrameRateLimit::RoundTrips`]).
    pub fn set_rtt(&mut self, rtt: Duration) {
        self.rtt = Some(rtt);
    }

    /// Whether the pipeline is paused (the last target was 0).
    pub fn is_paused(&self) -> bool {
        self.paused
    }

    /// Whether the next picture encoded will be a key frame.
    pub fn key_frame_pending(&self) -> bool {
        self.key_pending
    }

    /// The resolution and frame rate of the current degradation step, once a picture has
    /// given the source's size.
    pub fn current_format(&self) -> Option<(u32, u32, f64)> {
        let step = self.path.get(self.level)?;
        let (w, h) = self.resolutions[step.resolution];
        Some((w, h, self.framerates[step.framerate]))
    }

    /// The target bitrate for this stream from now on, in bits per second: what the congestion
    /// controller gives it, less the retransmission reserve (the engine's
    /// `RTCRtpSender::target_bitrates`). 0 pauses the stream until the next nonzero target.
    pub fn set_target_bitrate(&mut self, now: Instant, bps: f64) {
        self.account(now);
        if bps <= 0.0 {
            if !self.paused {
                self.paused = true;
                self.stats.pauses += 1;
            }
            return;
        }
        if self.paused {
            self.paused = false;
            self.budget = 1.0;
            if self.config.key_frame_on_resume && !self.key_pending {
                self.key_pending = true;
                self.stats.resume_key_frames += 1;
            }
        }
        self.target = Some(bps);
        self.stats.target_bitrate = Some(bps);
        self.choose_level();
        self.apply_rates();
    }

    /// A key frame is asked for (`trigger`) at `now`.
    pub fn request_key_frame(
        &mut self,
        now: Instant,
        trigger: KeyFrameTrigger,
    ) -> KeyFrameDecision {
        if trigger == KeyFrameTrigger::PacerDiscard {
            self.stats.pacer_discards += 1;
        }
        if self.key_pending {
            self.stats.key_frame_requests_coalesced += 1;
            return KeyFrameDecision::Coalesced;
        }
        let too_soon = match self.config.key_frame_rate_limit {
            KeyFrameRateLimit::RoundTrips => {
                let window = 2 * self.rtt.unwrap_or(DEFAULT_ROUND_TRIP_TIME);
                self.last_key_frame
                    .is_some_and(|t| now.saturating_duration_since(t) < window)
            }
            KeyFrameRateLimit::MinInterval(interval) => self
                .last_request_served
                .is_some_and(|t| now.saturating_duration_since(t) < interval),
        };
        if too_soon {
            self.stats.key_frame_requests_suppressed += 1;
            return KeyFrameDecision::Suppressed;
        }
        self.last_request_served = Some(now);
        self.key_pending = true;
        self.stats.key_frame_requests_served += 1;
        KeyFrameDecision::Served
    }

    /// Encodes and packetizes `picture`, captured at `capture`, at `now`; or drops it (paused,
    /// the frame-rate step, the encoder's rate control).
    ///
    /// # Errors
    ///
    /// What the encoder or the encoder factory reports; the payloader's errors as
    /// [`EncodeError::Failed`].
    pub fn send_frame(
        &mut self,
        now: Instant,
        capture: Instant,
        picture: &I420<'_>,
    ) -> Result<FrameOutcome, EncodeError> {
        self.account(now);
        self.stats.frames_captured += 1;
        if self.source != Some((picture.width, picture.height)) {
            self.set_source(picture.width, picture.height);
        }
        if self.paused {
            self.stats.frames_dropped_paused += 1;
            self.last_capture = Some(capture);
            return Ok(FrameOutcome::Dropped(DropReason::Paused));
        }
        // The frame-rate step: a budget of pictures that grows with the time between captures.
        let framerate = self.effective_framerate();
        if let Some(last) = self.last_capture {
            let dt = capture.saturating_duration_since(last).as_secs_f64();
            self.budget = (self.budget + dt * framerate).min(1.5);
        }
        self.last_capture = Some(capture);
        // A margin for captures a little early (30 fps in microseconds).
        if self.budget < 0.999 {
            self.stats.frames_dropped_framerate += 1;
            return Ok(FrameOutcome::Dropped(DropReason::Framerate));
        }
        self.budget = (self.budget - 1.0).max(0.0);

        let (w, h, fps) = self.current_format().unwrap_or((
            picture.width,
            picture.height,
            self.config.max_framerate,
        ));
        if self
            .encoder
            .as_ref()
            .is_none_or(|e| (e.width, e.height) != (w, h))
        {
            if self.encoder.is_some() {
                self.stats.quality_limitation_resolution_changes += 1;
            }
            let inner = self.factory.create(w, h, fps, self.encoder_rate())?;
            self.stats.encoder_implementation = Some(inner.implementation_name().to_owned());
            self.encoder = Some(Encoder {
                inner,
                width: w,
                height: h,
                pending: VecDeque::new(),
                next_index: 0,
            });
            self.apply_rates();
        }
        let scaled = (w, h) != (picture.width, picture.height);
        if scaled {
            scale_into(picture, w, h, &mut self.scaled);
        }
        let encoder = self.encoder.as_mut().expect("made above");
        let input = if scaled { self.scaled.view() } else { *picture };
        encoder.pending.push_back((encoder.next_index, capture));
        encoder.next_index += 1;
        let Some(encoded) = encoder.inner.encode(&input, self.key_pending)? else {
            self.stats.frames_dropped_encoder += 1;
            return Ok(FrameOutcome::Dropped(DropReason::Encoder));
        };
        // The capture time of the picture this is (an encoder with look-ahead returns an
        // earlier one).
        let mut picture_capture = capture;
        while let Some(&(index, at)) = encoder.pending.front() {
            if index > encoded.source_index {
                break;
            }
            encoder.pending.pop_front();
            if index == encoded.source_index {
                picture_capture = at;
            }
        }
        if encoded.keyframe {
            self.key_pending = false;
            self.last_key_frame = Some(now);
            self.stats.key_frames_encoded += 1;
        }
        self.stats.frames_encoded += 1;
        self.stats.bytes_encoded += encoded.data.len() as u64;
        self.stats.frame_size = Some((w, h));
        if let Some(qp) = encoded.qp {
            *self.stats.qp_sum.get_or_insert(0) += u64::from(qp);
        }
        let first = *self.first_capture.get_or_insert(picture_capture);
        let ticks = picture_capture
            .saturating_duration_since(first)
            .as_secs_f64()
            * f64::from(VIDEO_CLOCK_RATE);
        let timestamp = self
            .rtp
            .first_timestamp
            .wrapping_add((ticks.round() as u64) as u32);
        let octets = encoded.data.len();
        let payloads = self
            .payloader
            .payload(
                self.rtp.mtu.saturating_sub(12).max(1),
                &Bytes::from(encoded.data),
            )
            .map_err(|e| EncodeError::Failed(format!("payloader: {e}")))?;
        let count = payloads.len();
        let mut packets = Vec::with_capacity(count);
        for (i, payload) in payloads.into_iter().enumerate() {
            packets.push(rtp::Packet {
                header: rtp::header::Header {
                    version: 2,
                    marker: i + 1 == count,
                    payload_type: self.rtp.payload_type,
                    sequence_number: self.sequence_number,
                    timestamp,
                    ssrc: self.rtp.ssrc,
                    ..Default::default()
                },
                payload,
            });
            self.sequence_number = self.sequence_number.wrapping_add(1);
        }
        self.stats.packets_sent += count as u64;
        Ok(FrameOutcome::Sent(SentFrame {
            packets,
            keyframe: encoded.keyframe,
            octets,
            width: w,
            height: h,
            timestamp,
            capture: picture_capture,
        }))
    }

    /// The statistics, with the quality-limitation durations brought up to `now`.
    pub fn stats(&mut self, now: Instant) -> SendStats {
        self.account(now);
        self.stats.clone()
    }

    /// The bitrate the encoder is given: the target, never below the encoder's minimum.
    fn encoder_rate(&self) -> u32 {
        let target = self
            .target
            .unwrap_or(f64::from(self.config.initial_bitrate_bps));
        let min = self
            .encoder
            .as_ref()
            .map_or(0, |e| e.inner.min_bitrate_bps());
        (target.round() as u32).max(min)
    }

    /// The frame rate of the step, lowered in the ratio target / minimum when the target is
    /// under the encoder's minimum.
    fn effective_framerate(&self) -> f64 {
        let step = self
            .current_format()
            .map_or(self.config.max_framerate, |f| f.2);
        let min = self
            .encoder
            .as_ref()
            .map_or(0, |e| e.inner.min_bitrate_bps());
        match self.target {
            Some(target) if min > 0 && target < f64::from(min) => {
                step * (target / f64::from(min)).max(0.0)
            }
            _ => step,
        }
    }

    fn apply_rates(&mut self) {
        let rate = self.encoder_rate();
        let fps = self
            .current_format()
            .map_or(self.config.max_framerate, |f| f.2);
        self.stats.framerate = fps;
        if let Some(e) = &mut self.encoder {
            e.inner.set_rates(rate, fps);
        }
    }

    /// A source of `width` x `height`: the resolution and frame-rate steps, and the order in
    /// which the preference takes them.
    fn set_source(&mut self, width: u32, height: u32) {
        self.source = Some((width, height));
        self.resolutions = vec![(width, height)];
        let source_pixels = u64::from(width) * u64::from(height);
        let mut k = 1;
        loop {
            // 3/5 of the pixels per step: each side by the square root of 0.6.
            let f = 0.6f64.powi(k).sqrt();
            let w = ((f64::from(width) * f / 2.0).round() as u32 * 2).max(2);
            let h = ((f64::from(height) * f / 2.0).round() as u32 * 2).max(2);
            if u64::from(w) * u64::from(h) < MIN_PIXELS.min(source_pixels) {
                break;
            }
            self.resolutions.push((w, h));
            k += 1;
        }
        self.framerates = vec![self.config.max_framerate];
        while let Some(&last) = self.framerates.last() {
            let next = last * 2.0 / 3.0;
            if next < MIN_FRAMERATE {
                break;
            }
            self.framerates.push(next);
        }
        let (nr, nf) = (self.resolutions.len(), self.framerates.len());
        self.path = match self.config.degradation_preference {
            DegradationPreference::MaintainFramerateAndResolution => vec![Step {
                resolution: 0,
                framerate: 0,
            }],
            DegradationPreference::MaintainFramerate => (0..nr)
                .map(|resolution| Step {
                    resolution,
                    framerate: 0,
                })
                .collect(),
            DegradationPreference::MaintainResolution => (0..nf)
                .map(|framerate| Step {
                    resolution: 0,
                    framerate,
                })
                .collect(),
            DegradationPreference::Balanced => {
                let mut path = vec![Step {
                    resolution: 0,
                    framerate: 0,
                }];
                let (mut r, mut f) = (0, 0);
                while r + 1 < nr || f + 1 < nf {
                    // Resolution first, then frame rate, alternately; the other once one
                    // has no steps left.
                    if r + 1 < nr && (r <= f || f + 1 >= nf) {
                        r += 1;
                    } else {
                        f += 1;
                    }
                    path.push(Step {
                        resolution: r,
                        framerate: f,
                    });
                }
                path
            }
        };
        self.level = 0;
        self.choose_level();
        self.apply_rates();
    }

    fn need(&self, step: Step) -> f64 {
        let (w, h) = self.resolutions[step.resolution];
        f64::from(min_bitrate_for(
            u64::from(w) * u64::from(h),
            self.framerates[step.framerate],
        ))
    }

    /// The step for the current target: down at once to the first step the target meets, up
    /// only to a step the target meets with the upgrade margin.
    fn choose_level(&mut self) {
        let Some(target) = self.target else { return };
        if self.path.is_empty() {
            return;
        }
        let last = self.path.len() - 1;
        let meets = |pipeline: &Self, margin: f64| {
            (0..=last)
                .find(|&i| pipeline.need(pipeline.path[i]) * margin <= target)
                .unwrap_or(last)
        };
        let down = meets(self, 1.0);
        let level = if down > self.level {
            down
        } else {
            meets(self, self.config.upgrade_margin).min(self.level)
        };
        self.level = level;
        let quality_limited = level > 0;
        self.stats.quality_limited = quality_limited;
    }

    fn account(&mut self, now: Instant) {
        if let Some(from) = self.accounted_until {
            let dt = now.saturating_duration_since(from).as_secs_f64();
            if self.stats.quality_limited {
                self.stats.quality_limitation_bandwidth += dt;
            } else {
                self.stats.quality_limitation_none += dt;
            }
        }
        self.accounted_until = Some(self.accounted_until.map_or(now, |t| t.max(now)));
    }
}

#[cfg(test)]
#[path = "send_test.rs"]
mod tests;
