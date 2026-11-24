#![allow(dead_code, unused_imports, clippy::all)]
//! A video call between two `rtci` peer connections whose path drops to 300 kbit/s for twenty
//! seconds and then opens again. Virtual time.
//!
//! The scenario is ParolNet's (`parolnet-simnet`, `m1::the_estimate_follows_a_cap_that_comes_
//! and_goes`), ported so the engine checks it without the application: the interceptor chain
//! that application builds (NACK, the RTCP reports, key-frame requests, TWCC with the
//! TWCC-driven GCC and no pacer), VP8 with RTX and Opus each way, a sender whose video follows
//! GCC's estimate, and a receiver that reassembles VP8 frames with the engine's sample builder
//! and asks for a key frame (PLI) when it has lost its reference. The link is the simulated
//! network's: a fixed one-way delay and, while capped, one datagram at a time at the link's
//! rate behind a drop-tail queue of 300 ms.
//!
//! What it measures is what the call's user sees: the longest time without a usable frame on
//! the receiving side, and the estimate after the cap went (its mean from 15 to 25 s after).

use anyhow::{Result, bail};
use bytes::Bytes;
use rtci::crypto::{CryptoError, RTCCrypto, RTCCryptoProvider, RTCRandom, default_provider};
use rtci::interceptor::{
    GccHandle, GccInterceptorBuilder, Interceptor as _, NackGeneratorBuilder, NackResponderBuilder,
    PassThroughInterceptor, Registry, RetransmissionRateLimit, RtcpRandom, RtcpSessionBuilder,
    Slot,
};
use rtci::media::io::sample_builder::SampleBuilder;
use rtci::media_stream::MediaStreamTrack;
use rtci::peer_connection::configuration::RTCConfigurationBuilder;
use rtci::peer_connection::configuration::interceptor_registry::{
    DefaultInterceptorHandles, DefaultInterceptorOptions, configure_key_frame_requests,
    configure_nack, configure_receiver_reference_time, configure_rtcp_reports_with, configure_twcc,
    register_default_interceptors_with_options,
};
use rtci::peer_connection::configuration::media_engine::{
    MIME_TYPE_OPUS, MIME_TYPE_RTX, MIME_TYPE_VP8, MediaEngine,
};
use rtci::peer_connection::configuration::setting_engine::SettingEngineBuilder;
use rtci::peer_connection::event::{RTCPeerConnectionEvent, RTCTrackEvent};
use rtci::peer_connection::message::RTCMessage;
use rtci::peer_connection::state::RTCPeerConnectionState;
use rtci::peer_connection::transport::{
    CandidateConfig, CandidateHostConfig, RTCIceCandidate, RTCIceCandidateInit,
};
use rtci::peer_connection::{RTCPeerConnection, RTCPeerConnectionBuilder};
use rtci::rtcp::payload_feedbacks::full_intra_request::FullIntraRequest;
use rtci::rtcp::payload_feedbacks::picture_loss_indication::PictureLossIndication;
use rtci::rtp::codec::vp8::Vp8Packet;
use rtci::rtp::packetizer::Packetizer;
use rtci::rtp_transceiver::rtp_sender::{
    RTCPFeedback, RTCRtpCodec, RTCRtpCodecParameters, RTCRtpCodingParameters,
    RTCRtpEncodingParameters, RTCRtpRtxParameters, RtpCodecKind,
};
use rtci::rtp_transceiver::{
    RTCRtpReceiverId, RTCRtpSenderId, RTCRtpTransceiverDirection, RTCRtpTransceiverId,
};
use rtci::sansio::Protocol;
use rtci::shared::time::SystemInstant;
use rtci::shared::{TaggedBytesMut, TransportContext, TransportProtocol};
use rtci::statistics::StatsSelector;
use rtci::statistics::report::RTCStatsReportEntry;
use std::cell::Cell;
use std::collections::{BTreeMap, BTreeSet};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// A small deterministic generator (SplitMix64).
struct Rng(u64);

impl Rng {
    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }
}

/// The built-in crypto provider with its random source replaced by a seeded [`Rng`] (ICE,
/// DTLS, SCTP), and the RTCP session's report times drawn from the same seed.
struct SeededProvider {
    inner: Arc<dyn RTCCryptoProvider>,
    rng: Mutex<Rng>,
}

impl RTCCryptoProvider for SeededProvider {
    fn name(&self) -> &'static str {
        self.inner.name()
    }

    fn crypto(&self) -> &dyn RTCCrypto {
        self.inner.crypto()
    }

    fn random(&self) -> &dyn RTCRandom {
        self
    }
}

impl RTCRandom for SeededProvider {
    fn fill(&self, output: &mut [u8]) -> Result<(), CryptoError> {
        let mut rng = self.rng.lock().map_err(|_| CryptoError::RandomnessFailed)?;
        for chunk in output.chunks_mut(8) {
            chunk.copy_from_slice(&rng.next_u64().to_le_bytes()[..chunk.len()]);
        }
        Ok(())
    }
}

struct SeededRtcpRandom(Rng);

impl RtcpRandom for SeededRtcpRandom {
    fn next_u32(&mut self) -> u32 {
        (self.0.next_u64() >> 32) as u32
    }
}

thread_local! {
    /// Whether the next `World`'s caller ignores the target: its video stays at the rate it
    /// had before the cap and does not pause.
    static IGNORE_TARGET: Cell<bool> = const { Cell::new(false) };
}

/// Which interceptor chain the peers of a run use.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Chain {
    /// ParolNet's: NACK, the RTCP reports, key-frame requests, TWCC with the TWCC-driven GCC
    /// (`GccInterceptorBuilder`), no pacer; the video follows `GccHandle::target_bitrate_bps`.
    ParolNet,
    /// The engine's default interceptors (the pacer, GCC on transport-wide feedback, the NACK
    /// pair); the video follows the target the senders are given
    /// (`RTCRtpSender::target_bitrates`).
    Default,
    /// The default interceptors with the pacer's slot passed through.
    DefaultWithoutPacer,
}

/// How a run is set up.
#[derive(Clone, Copy, Debug)]
struct Setup {
    seed: u64,
    /// The NACK responder's rule; the engine's default when `None`.
    rate_limit: Option<RetransmissionRateLimit>,
    chain: Chain,
    /// The wall clock at the instant the peers are built (since the Unix epoch): every NTP
    /// time on the wire follows from it, so a run with one is reproducible to the byte, and
    /// runs with different ones differ in the phase of everything derived from NTP times
    /// (round-trip times to 1/65536 s). The process's wall clock when `None`.
    anchor: Option<Duration>,
    /// How long the cap stays after the estimate went under 400 kbit/s.
    cap: Duration,
    /// The target the caller's encoder has reached when the cap arrives; after 20 s of call,
    /// whatever the target, when `None`.
    cap_at_target: Option<u32>,
    /// Whether each peer (caller, callee) has a video track from the first offer on. One
    /// without gains it by renegotiation ([`World::set_video`]).
    video: [bool; 2],
}

impl Setup {
    fn new(seed: u64, rate_limit: Option<RetransmissionRateLimit>) -> Self {
        Self {
            seed,
            rate_limit,
            chain: Chain::ParolNet,
            anchor: None,
            cap: Duration::from_secs(20),
            cap_at_target: None,
            video: [true, true],
        }
    }

    /// A call that starts with audio alone, either way.
    fn audio_only(mut self) -> Self {
        self.video = [false, false];
        self
    }

    fn chain(mut self, chain: Chain) -> Self {
        self.chain = chain;
        self
    }

    fn anchor(mut self, anchor: Duration) -> Self {
        self.anchor = Some(anchor);
        self
    }

    /// The cap arrives when the caller's target has reached `bps`, not after 20 s.
    fn capped_at_a_target_of(mut self, bps: u32) -> Self {
        self.cap_at_target = Some(bps);
        self
    }
}

/// Three wall clocks a run is repeated on: the same second, a different phase within it.
///
/// A seeded run is reproducible for one wire image only: its figures follow from every
/// packet's size, down to the ICE agent's SOFTWARE text in each STUN message (its length moved
/// the paced chain's target at the cap's end from 212 to 132 kbit/s on one seed), so a bound
/// on them is measured over seeds and wall clocks, never on one run's figure.
const ANCHORS: [Duration; 3] = [
    Duration::new(1_800_000_000, 0),
    Duration::new(1_800_000_000, 333_333_333),
    Duration::new(1_800_000_000, 777_777_777),
];

const VP8_PT: u8 = 96;
const RTX_PT: u8 = 97;
const OPUS_PT: u8 = 111;
/// Payload size of an outgoing RTP packet (ParolNet's `RTP_OUTBOUND_MTU`).
const RTP_MTU: usize = 1200;
const VIDEO_FPS: u32 = 30;
/// What the audio takes of the estimate (ParolNet's `AUDIO_SHARE_BPS`: Opus at about
/// 60 kbit/s with RTP and SRTP overhead, 50 packets a second).
const AUDIO_SHARE_BPS: u32 = 80_000;
/// An Opus packet of 20 ms at about 60 kbit/s.
const OPUS_PAYLOAD: usize = 150;
/// GCC's bounds (ParolNet's `CongestionConfig::default()`).
const MIN_BPS: u32 = 100_000;
const MAX_BPS: u32 = 2_500_000;

/// The video bitrate for an estimate: what is left after the audio, with a tenth held back
/// for retransmissions (ParolNet's `video_bitrate_for`).
fn video_bitrate_for(total_bps: u32) -> u32 {
    let left = total_bps.saturating_sub(AUDIO_SHARE_BPS);
    ((u64::from(left) * 9 / 10) as u32).max(30_000)
}

/// The rate-following video source (ParolNet's `VideoModel`): frames whose sizes add up to
/// the bitrate, a keyframe five times a frame's budget that the following frames pay for. A
/// frame is a VP8 frame tag (bit 0 clear: keyframe), "PN", its number and its length.
#[derive(Default)]
struct VideoModel {
    number: u32,
    debt: i64,
}

impl VideoModel {
    const HEADER: usize = 13;

    fn next_frame(&mut self, bitrate: u32, key: bool) -> Vec<u8> {
        let budget = i64::from(bitrate / 8 / VIDEO_FPS);
        let wanted = if key { budget * 5 } else { budget };
        let size = (wanted - self.debt.clamp(0, budget * 3 / 4)).max(Self::HEADER as i64 + 3);
        self.debt += size - budget;
        self.debt = self.debt.max(-budget);
        let size = size as usize;
        let mut frame = vec![0xa5u8; size];
        frame[0] = if key { 0x10 } else { 0x11 };
        frame[1] = 0;
        frame[2] = 0;
        frame[3] = b'P';
        frame[4] = b'N';
        frame[5..9].copy_from_slice(&self.number.to_be_bytes());
        frame[9..13].copy_from_slice(&(size as u32).to_be_bytes());
        self.number = self.number.wrapping_add(1);
        frame
    }
}

/// A decoder's rule: a delta frame is usable only when the frame before it was.
#[derive(Default)]
struct ModelDecoder {
    last: Option<u32>,
}

impl ModelDecoder {
    /// Whether the reassembled `frame` is usable; `None` for something that is no frame.
    fn accept(&mut self, frame: &[u8]) -> Option<bool> {
        if frame.len() < VideoModel::HEADER || &frame[3..5] != b"PN" {
            return None;
        }
        let number = u32::from_be_bytes(frame[5..9].try_into().ok()?);
        let length = u32::from_be_bytes(frame[9..13].try_into().ok()?) as usize;
        let (key, complete) = (frame[0] & 1 == 0, frame.len() == length);
        let usable = complete && (key || self.last.is_some_and(|l| number == l.wrapping_add(1)));
        if usable {
            self.last = Some(number);
        } else if complete
            && self
                .last
                .is_some_and(|l| number.wrapping_sub(l) > u32::MAX / 2 || number == l)
        {
            return Some(false);
        } else {
            self.last = None;
        }
        Some(usable)
    }
}

/// How one host's uplink treats what it sends.
#[derive(Clone, Copy, Debug)]
struct LinkProfile {
    delay: Duration,
    /// Capacity in bits per second (`None`: unlimited).
    rate_bps: Option<u64>,
    /// The drop-tail queue, as time at the link's rate.
    queue: Duration,
}

impl LinkProfile {
    /// A good link: 10 ms one way, no cap.
    fn open() -> Self {
        Self {
            delay: Duration::from_millis(10),
            rate_bps: None,
            queue: Duration::from_millis(300),
        }
    }

    /// 300 kbit/s, 30 ms one way, 300 ms of queue.
    fn capped_300k() -> Self {
        Self {
            delay: Duration::from_millis(30),
            rate_bps: Some(300_000),
            queue: Duration::from_millis(300),
        }
    }
}

struct Uplink {
    profile: LinkProfile,
    busy_until: Option<Instant>,
    last_delivery: Option<Instant>,
    queue_drops: u64,
    /// Retransmissions (RTX packets that carry a repaired packet), and those of them dropped at
    /// the queue.
    rtx_sent: u64,
    rtx_dropped: u64,
    /// Probe padding on the RTX stream (padding-only RTX packets that carry no media), counted
    /// apart from the retransmissions, and those dropped at the queue.
    padding_sent: u64,
    padding_dropped: u64,
    audio_dropped: u64,
    rtcp_sent: u64,
    rtcp_dropped: u64,
}

impl Uplink {
    fn new() -> Self {
        Self {
            profile: LinkProfile::open(),
            busy_until: None,
            last_delivery: None,
            queue_drops: 0,
            rtx_sent: 0,
            rtx_dropped: 0,
            padding_sent: 0,
            padding_dropped: 0,
            audio_dropped: 0,
            rtcp_sent: 0,
            rtcp_dropped: 0,
        }
    }

    fn set_profile(&mut self, profile: LinkProfile) {
        self.profile = profile;
        self.busy_until = None;
    }

    /// When a datagram of `size` octets sent at `now` arrives, `None` when the queue drops
    /// it. Nothing overtakes: a datagram never arrives before one sent earlier.
    fn send(&mut self, now: Instant, size: usize) -> Option<Instant> {
        let mut leaves = now;
        if let Some(rate) = self.profile.rate_bps.filter(|r| *r > 0) {
            let start = self.busy_until.map_or(now, |t| t.max(now));
            if start.saturating_duration_since(now) > self.profile.queue {
                self.queue_drops += 1;
                return None;
            }
            leaves = start + Duration::from_secs_f64(size as f64 * 8.0 / rate as f64);
            self.busy_until = Some(leaves);
        }
        let at = self
            .last_delivery
            .map_or(leaves + self.profile.delay, |last| {
                (leaves + self.profile.delay).max(last)
            });
        self.last_delivery = Some(at);
        Some(at)
    }
}

/// The RTP payload type of an SRTP datagram (RFC 7983 first byte, RFC 5761 second byte).
fn rtp_payload_type(data: &[u8]) -> Option<u8> {
    match data {
        [b0, b1, ..] if (128..=191).contains(b0) && !(192..=223).contains(b1) => Some(b1 & 0x7f),
        _ => None,
    }
}

struct Peer {
    pc: RTCPeerConnection,
    addr: SocketAddr,
    connected: bool,
    /// ParolNet's chain: its GCC's handle.
    gcc: Option<GccHandle>,
    /// The default chain: its handles.
    handles: Option<DefaultInterceptorHandles>,
    /// The video packets the application wrote, and those that left the host (by sequence
    /// number): the difference never reached the wire (dropped by a pacer).
    video_written: BTreeSet<u16>,
    video_left: BTreeSet<u16>,
    /// The video packets written from 1 s on (the first key frame, written as the connection
    /// comes up, is not the pacer's to lose), and the call's time at the current write.
    video_written_late: BTreeMap<u16, Duration>,
    media_elapsed: Duration,
    audio: RTCRtpSenderId,
    /// The video sender, once the peer has a video track.
    video: Option<RTCRtpSenderId>,
    audio_packetizer: Option<Box<dyn Packetizer>>,
    video_packetizer: Option<Box<dyn Packetizer>>,
    /// The estimate the encoder follows, read every 100 ms.
    target_bps: u32,
    /// (time, estimate) each time it moved.
    targets: Vec<(Duration, u32)>,
    model: VideoModel,
    force_key: bool,
    keyframes_sent: Vec<Duration>,
    /// The receiving side.
    video_receiver: Option<RTCRtpReceiverId>,
    builder: SampleBuilder<Vp8Packet>,
    decoder: ModelDecoder,
    usable_at: Vec<Duration>,
    /// How long after its capture each usable frame came out of the decoder.
    usable_lag: Vec<Duration>,
    unusable: u64,
    last_keyframe_request: Option<Instant>,
    keyframe_requests: Vec<Duration>,
    /// The sending side: every `OnPacerDiscard` (time, frames, packets), and the key-frame
    /// requests (PLI / FIR) it was handed.
    pacer_discards: Vec<(Duration, u32, usize)>,
    key_requests_received: u32,
    /// When the application was told of a selected candidate pair, with the estimate then.
    pair_changes: Vec<(Duration, Option<u32>)>,
    /// The lowest `availableOutgoingBitrate` of the nominated pair (webrtc-stats) and the
    /// lowest estimate of the congestion controller, each read every 100 ms once there is one.
    lowest_outgoing: Option<f64>,
    lowest_estimate: Option<u32>,
    /// Octets of video frames the application wrote.
    video_octets: u64,
    /// (time, estimate) each time the congestion controller's estimate moved, looked at
    /// after every step of the world while it is `sampling`.
    estimates: Vec<(Duration, u32)>,
}

fn video_codec() -> RTCRtpCodec {
    RTCRtpCodec {
        mime_type: MIME_TYPE_VP8.to_owned(),
        clock_rate: 90_000,
        channels: 0,
        sdp_fmtp_line: String::new(),
        rtcp_feedback: [
            ("goog-remb", ""),
            ("ccm", "fir"),
            ("nack", ""),
            ("nack", "pli"),
        ]
        .into_iter()
        .map(|(typ, parameter)| RTCPFeedback {
            typ: typ.to_owned(),
            parameter: parameter.to_owned(),
        })
        .collect(),
    }
}

fn opus_codec() -> RTCRtpCodec {
    RTCRtpCodec {
        mime_type: MIME_TYPE_OPUS.to_owned(),
        clock_rate: 48_000,
        channels: 2,
        sdp_fmtp_line: "minptime=10;useinbandfec=1".to_owned(),
        rtcp_feedback: vec![],
    }
}

fn track(kind: RtpCodecKind, codec: RTCRtpCodec, ssrc: u32, rtx: Option<u32>) -> MediaStreamTrack {
    let name = if kind == RtpCodecKind::Video {
        "video"
    } else {
        "audio"
    };
    MediaStreamTrack::new(
        "call".to_owned(),
        name.to_owned(),
        name.to_owned(),
        kind,
        vec![RTCRtpEncodingParameters {
            rtp_coding_parameters: RTCRtpCodingParameters {
                ssrc: Some(ssrc),
                rtx: rtx.map(|ssrc| RTCRtpRtxParameters { ssrc }),
                ..Default::default()
            },
            codec,
            ..Default::default()
        }],
    )
}

/// A peer's video track: the stream after its audio's, with a retransmission stream.
fn video_track(ssrc_base: u32) -> MediaStreamTrack {
    track(
        RtpCodecKind::Video,
        video_codec(),
        ssrc_base + 1,
        Some(ssrc_base + 2),
    )
}

impl Peer {
    /// A peer with ParolNet's media engine and interceptor chain, sending Opus and VP8; its
    /// NACK responder holds retransmissions to `rate_limit`, the engine's default when `None`.
    fn new(
        addr: &str,
        setup: &Setup,
        salt: u64,
        ssrc_base: u32,
        video: bool,
        start: Instant,
    ) -> Result<Self> {
        let seed = setup.seed ^ salt;
        let rate_limit = setup.rate_limit;
        let wall_clock = setup.anchor.map(|anchor| SystemInstant::at(start, anchor));
        let provider: Arc<dyn RTCCryptoProvider> = Arc::new(SeededProvider {
            inner: default_provider()?,
            rng: Mutex::new(Rng(seed)),
        });
        let mut media_engine = MediaEngine::default();
        media_engine.register_codec(
            RTCRtpCodecParameters {
                rtp_codec: video_codec(),
                payload_type: VP8_PT,
            },
            RtpCodecKind::Video,
        )?;
        media_engine.register_codec(
            RTCRtpCodecParameters {
                rtp_codec: RTCRtpCodec {
                    mime_type: MIME_TYPE_RTX.to_owned(),
                    clock_rate: 90_000,
                    channels: 0,
                    sdp_fmtp_line: format!("apt={VP8_PT}"),
                    rtcp_feedback: vec![],
                },
                payload_type: RTX_PT,
            },
            RtpCodecKind::Video,
        )?;
        media_engine.register_codec(
            RTCRtpCodecParameters {
                rtp_codec: opus_codec(),
                payload_type: OPUS_PT,
            },
            RtpCodecKind::Audio,
        )?;
        if setup.chain != Chain::ParolNet {
            let mut options = DefaultInterceptorOptions::default();
            options.rtcp_random = Some(provider.clone());
            options.wall_clock = wall_clock;
            if let Some(v) = review_knob("REVIEW_PROBING") {
                options.bandwidth_probing = v != 0;
            }
            if let Some(v) = review_knob("REVIEW_ONE_DECREASE") {
                options.gcc_one_decrease_per_round_trip = v != 0;
            }
            if let Some(ms) = review_knob("REVIEW_FB_MAX_MS") {
                options.congestion_feedback_max_interval = Duration::from_millis(ms);
            }
            if let Some(rate_limit) = rate_limit {
                options.nack_retransmission_rate_limit = rate_limit;
            }
            let (mut registry, handles) = register_default_interceptors_with_options(
                Registry::new(),
                &mut media_engine,
                &options,
            )?;
            if setup.chain == Chain::DefaultWithoutPacer {
                registry = registry.with(Slot::Pacer, PassThroughInterceptor::new());
            }
            // The application's bounds, as ParolNet gives its GCC.
            handles
                .congestion_control
                .set_min_bitrate(Some(f64::from(MIN_BPS)));
            handles
                .congestion_control
                .set_session_bitrate_limit(Some(f64::from(MAX_BPS)));
            return Self::with_chain(
                addr,
                provider,
                media_engine,
                registry,
                ssrc_base,
                video,
                None,
                Some(handles),
                start,
            );
        }
        let registry = match rate_limit {
            None => configure_nack(Registry::new(), &mut media_engine),
            // `configure_nack` with the responder's rule set (the codec carries the NACK
            // feedback already).
            Some(rate_limit) => Registry::new()
                .with(
                    Slot::NackResponder,
                    NackResponderBuilder::new()
                        .with_rate_limit(rate_limit)
                        .build(),
                )
                .with(Slot::NackGenerator, NackGeneratorBuilder::new().build()),
        };
        let session = RtcpSessionBuilder::new()
            .with_t_rr_interval(Duration::ZERO)
            .with_random(SeededRtcpRandom(Rng(seed ^ 0x5eed)));
        let session = match wall_clock {
            Some(anchor) => session.with_wall_clock(anchor),
            None => session,
        };
        let registry = configure_rtcp_reports_with(registry, session);
        configure_receiver_reference_time(&mut media_engine);
        let registry = configure_key_frame_requests(registry);
        let (gcc, handle) = GccInterceptorBuilder::new();
        let registry = configure_twcc(registry, &mut media_engine)?.with(
            Slot::CongestionControl,
            PassThroughInterceptor::new().with(
                gcc.with_min_bitrate(MIN_BPS)
                    .with_max_bitrate(MAX_BPS)
                    .build(),
            ),
        );
        Self::with_chain(
            addr,
            provider,
            media_engine,
            registry,
            ssrc_base,
            video,
            Some(handle),
            None,
            start,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn with_chain(
        addr: &str,
        provider: Arc<dyn RTCCryptoProvider>,
        media_engine: MediaEngine,
        registry: Registry,
        ssrc_base: u32,
        video: bool,
        gcc: Option<GccHandle>,
        handles: Option<DefaultInterceptorHandles>,
        start: Instant,
    ) -> Result<Self> {
        let mut pc = RTCPeerConnectionBuilder::new()
            .with_configuration(RTCConfigurationBuilder::new().build())
            .with_setting_engine(
                SettingEngineBuilder::new()
                    .with_crypto_provider(provider)
                    .build(),
            )
            .with_media_engine(media_engine)
            .with_interceptor_registry(registry)
            .build(start)?;
        let audio = pc.add_track(track(RtpCodecKind::Audio, opus_codec(), ssrc_base, None))?;
        let video = if video {
            Some(pc.add_track(video_track(ssrc_base))?)
        } else {
            None
        };
        Ok(Self {
            pc,
            addr: addr.parse()?,
            connected: false,
            gcc,
            handles,
            video_written: BTreeSet::new(),
            video_left: BTreeSet::new(),
            video_written_late: BTreeMap::new(),
            media_elapsed: Duration::ZERO,
            audio,
            video,
            audio_packetizer: None,
            video_packetizer: None,
            target_bps: 300_000,
            targets: Vec::new(),
            model: VideoModel::default(),
            force_key: true,
            keyframes_sent: Vec::new(),
            video_receiver: None,
            builder: review_builder(),
            decoder: ModelDecoder::default(),
            usable_at: Vec::new(),
            usable_lag: Vec::new(),
            unusable: 0,
            last_keyframe_request: None,
            keyframe_requests: Vec::new(),
            pacer_discards: Vec::new(),
            key_requests_received: 0,
            pair_changes: Vec::new(),
            lowest_outgoing: None,
            lowest_estimate: None,
            video_octets: 0,
            estimates: Vec::new(),
        })
    }

    fn candidate(&self) -> Result<RTCIceCandidateInit> {
        let candidate = CandidateHostConfig {
            base_config: CandidateConfig {
                network: "udp".to_owned(),
                address: self.addr.ip().to_string(),
                port: self.addr.port(),
                component: 1,
                ..Default::default()
            },
            ..Default::default()
        }
        .new_candidate_host()?;
        Ok(RTCIceCandidate::from(&candidate).to_json()?)
    }

    /// Packetize one frame of `kind` and hand it to the engine.
    fn send_frame(&mut self, now: Instant, video: bool, data: &[u8], samples: u32) -> Result<()> {
        let Some(id) = (if video { self.video } else { Some(self.audio) }) else {
            return Ok(());
        };
        let Some(mut sender) = self.pc.rtp_sender(id) else {
            return Ok(());
        };
        let packetizer = if video {
            &mut self.video_packetizer
        } else {
            &mut self.audio_packetizer
        };
        if packetizer.is_none() {
            let Some(ssrc) = sender.ssrcs().next() else {
                return Ok(());
            };
            let Some(codec) = sender
                .get_parameters()
                .rtp_parameters
                .codecs
                .iter()
                .find(|c| !c.rtp_codec.mime_type.eq_ignore_ascii_case(MIME_TYPE_RTX))
                .cloned()
            else {
                return Ok(());
            };
            *packetizer = Some(Box::new(rtci::rtp::packetizer::new_packetizer(
                now,
                RTP_MTU,
                codec.payload_type,
                ssrc,
                codec.rtp_codec.payloader()?,
                Box::new(rtci::rtp::sequence::new_fixed_sequencer(
                    (ssrc as u16).wrapping_mul(7),
                )),
                codec.rtp_codec.clock_rate,
            )));
        }
        let Some(packetizer) = packetizer.as_mut() else {
            return Ok(());
        };
        if video {
            self.video_octets += data.len() as u64;
        }
        for packet in packetizer.packetize(now, &Bytes::copy_from_slice(data), samples)? {
            if video {
                self.video_written.insert(packet.header.sequence_number);
                if self.media_elapsed >= Duration::from_secs(1) {
                    self.video_written_late
                        .insert(packet.header.sequence_number, self.media_elapsed);
                }
            }
            sender.write_rtp(now, packet)?;
        }
        Ok(())
    }

    /// The target the encoder follows: GCC's handle in ParolNet's chain; in the default chain
    /// the sum of what the two senders are given.
    fn media_target(&mut self) -> Option<u32> {
        if let Some(gcc) = &self.gcc {
            return gcc.target_bitrate_bps();
        }
        let mut total = 0.0;
        let mut shares = 0;
        for id in [Some(self.audio), self.video].into_iter().flatten() {
            if let Some(sender) = self.pc.rtp_sender(id) {
                let targets = sender.target_bitrates();
                shares += targets.len();
                total += targets.iter().map(|(_, bps)| bps).sum::<f64>();
            }
        }
        // Zero is a target too: the pacer's pause.
        (shares > 0).then_some(total as u32)
    }

    /// The fraction of packets the congestion controller counts as lost (smoothed).
    fn packet_loss(&self) -> Option<f64> {
        match (&self.gcc, &self.handles) {
            (Some(gcc), _) => gcc.stats().packet_loss,
            (None, Some(handles)) => handles.congestion_control.stats().packet_loss,
            _ => None,
        }
    }

    /// The congestion controller's estimate itself.
    fn estimate(&self) -> Option<u32> {
        match (&self.gcc, &self.handles) {
            (Some(gcc), _) => gcc.estimate_bps(),
            (None, Some(handles)) => Some(handles.congestion_control.target_bitrate() as u32),
            _ => None,
        }
    }

    /// `availableOutgoingBitrate` of the nominated candidate pair.
    fn available_outgoing(&mut self, now: Instant) -> Option<f64> {
        self.pc
            .get_stats(now, StatsSelector::None)
            .iter()
            .find_map(|entry| match entry {
                RTCStatsReportEntry::IceCandidatePair(pair) if pair.nominated => {
                    pair.available_outgoing_bitrate
                }
                _ => None,
            })
    }

    /// The estimator's delay-based and loss-based halves.
    fn halves(&self) -> (u32, u32) {
        let stats = match (&self.gcc, &self.handles) {
            (Some(gcc), _) => gcc.stats(),
            (None, Some(handles)) => handles.congestion_control.stats(),
            _ => return (0, 0),
        };
        (
            stats.delay_based_bitrate.unwrap_or(0.0) as u32,
            stats.loss_based_bitrate.unwrap_or(0.0) as u32,
        )
    }

    /// Ask the sender of the received video for a key frame (PLI), as ParolNet's
    /// `request_keyframes` does.
    fn request_keyframe(&mut self, now: Instant) -> Result<()> {
        if let Some(id) = self.video_receiver
            && let Some(mut receiver) = self.pc.rtp_receiver(id)
            && let Some(media_ssrc) = { receiver.track().ssrcs().next() }
        {
            receiver.write_rtcp(
                now,
                vec![Box::new(PictureLossIndication {
                    sender_ssrc: 0,
                    media_ssrc,
                })],
            )?;
        }
        Ok(())
    }
}

struct InFlight {
    at: Instant,
    order: u64,
    from: SocketAddr,
    to: SocketAddr,
    data: bytes::BytesMut,
}

struct World {
    peers: [Peer; 2],
    uplinks: [Uplink; 2],
    start: Instant,
    now: Instant,
    in_flight: Vec<InFlight>,
    order: u64,
    next_audio: Instant,
    next_video: Instant,
    next_target: Instant,
    frame: u64,
    media: bool,
    /// Whether each peer's camera is on: its video source produces frames.
    video_on: [bool; 2],
    /// Every 100 ms: time, the caller's estimate, its uplink's queue and drops, the
    /// retransmissions it sent and lost there, the callee's usable frames so far. Printed
    /// with `RTC_CAP_TRACE=1`.
    trace: Vec<String>,
    /// Nothing sent either way arrives (both hosts' network is gone).
    blackhole: bool,
    /// Only STUN arrives until the caller's application is told of a newly selected pair: the
    /// path the media went on is gone, and the new one carries the restart's checks first.
    stun_only: bool,
    /// The caller's estimate and counted loss after every step, while `sampling`.
    sampling: bool,
    samples: Vec<(Duration, Option<u32>, Option<f64>)>,
}

impl World {
    fn elapsed(&self) -> Duration {
        self.now.duration_since(self.start)
    }

    fn pump(&mut self) -> Result<()> {
        loop {
            let mut moved = false;
            for i in 0..2 {
                while let Some(msg) = self.peers[i].pc.poll_write() {
                    moved = true;
                    let payload_type = rtp_payload_type(&msg.message);
                    if payload_type == Some(VP8_PT)
                        && msg.message.len() >= 12
                        && msg.message[8..12]
                            == (0x1000_0001u32 + 0x1000_0000 * i as u32).to_be_bytes()
                    {
                        let seq = u16::from_be_bytes([msg.message[2], msg.message[3]]);
                        self.peers[i].video_left.insert(seq);
                    }
                    // RFC 7983: a first octet of 0 to 3 is STUN.
                    let stun = msg.message.first().is_some_and(|b| *b <= 3);
                    if self.blackhole
                        || (self.stun_only && !stun && self.peers[0].pair_changes.is_empty())
                    {
                        continue;
                    }
                    let arrives = if (i == 1 && review_reverse_loss())
                        || (i == 0 && review_burst_drop(payload_type == Some(VP8_PT)))
                    {
                        None
                    } else {
                        self.uplinks[i].send(self.now, msg.message.len())
                    };
                    // A bandwidth probe is a padding-only packet of the RTX stream: the RTP
                    // header's padding bit (RFC 3550 section 5.1), in the clear under SRTP, is
                    // set on it and never on a retransmission (RFC 4588 section 4 carries no
                    // padding).
                    if payload_type == Some(RTX_PT) {
                        let link = &mut self.uplinks[i];
                        if msg.message[0] & 0x20 != 0 {
                            link.padding_sent += 1;
                            link.padding_dropped += u64::from(arrives.is_none());
                        } else {
                            link.rtx_sent += 1;
                            link.rtx_dropped += u64::from(arrives.is_none());
                        }
                    }
                    if payload_type == Some(OPUS_PT) {
                        self.uplinks[i].audio_dropped += u64::from(arrives.is_none());
                    }
                    // RFC 5761: an SRTCP datagram's second octet is 192 to 223.
                    if matches!(&msg.message[..], [b0, b1, ..] if (128..=191).contains(b0) && (192..=223).contains(b1))
                    {
                        self.uplinks[i].rtcp_sent += 1;
                        self.uplinks[i].rtcp_dropped += u64::from(arrives.is_none());
                    }
                    let Some(at) = arrives else { continue };
                    self.order += 1;
                    self.in_flight.push(InFlight {
                        at,
                        order: self.order,
                        from: msg.transport.local_addr,
                        to: msg.transport.peer_addr,
                        data: msg.message,
                    });
                }
            }
            let now = self.now;
            let mut due: Vec<InFlight> = Vec::new();
            let mut i = 0;
            while i < self.in_flight.len() {
                if self.in_flight[i].at <= now {
                    due.push(self.in_flight.swap_remove(i));
                } else {
                    i += 1;
                }
            }
            due.sort_by_key(|d| (d.at, d.order));
            moved |= !due.is_empty();
            for d in due {
                let Some(peer) = self.peers.iter_mut().find(|p| p.addr == d.to) else {
                    continue;
                };
                let _ = peer.pc.handle_read(TaggedBytesMut {
                    now,
                    transport: TransportContext {
                        local_addr: d.to,
                        peer_addr: d.from,
                        ecn: None,
                        transport_protocol: TransportProtocol::UDP,
                    },
                    message: d.data,
                });
            }
            for i in 0..2 {
                moved |= self.events(i)?;
            }
            if !moved {
                return Ok(());
            }
        }
    }

    /// The application's side of peer `i`: connection state, tracks, received media and key
    /// frame requests. Whether anything happened.
    fn events(&mut self, i: usize) -> Result<bool> {
        let at = self.elapsed();
        let now = self.now;
        let peer = &mut self.peers[i];
        let mut moved = false;
        while let Some(event) = peer.pc.poll_event() {
            moved = true;
            match event {
                RTCPeerConnectionEvent::OnConnectionStateChangeEvent(state) => {
                    if state == RTCPeerConnectionState::Failed {
                        bail!("peer {i} failed");
                    }
                    peer.connected = state == RTCPeerConnectionState::Connected;
                }
                RTCPeerConnectionEvent::OnSelectedCandidatePairChange(_) => {
                    let estimate = peer.estimate();
                    peer.pair_changes.push((at, estimate));
                }
                RTCPeerConnectionEvent::OnTrack(RTCTrackEvent::OnOpen(init)) => {
                    let video = peer
                        .pc
                        .rtp_receiver(init.receiver_id)
                        .is_some_and(|r| r.track().kind() == RtpCodecKind::Video);
                    if video {
                        peer.video_receiver = Some(init.receiver_id);
                        peer.request_keyframe(now)?;
                    }
                }
                RTCPeerConnectionEvent::OnPacerDiscard {
                    frames, packets, ..
                } => peer.pacer_discards.push((at, frames, packets)),
                _ => {}
            }
        }
        while let Some(message) = peer.pc.poll_read() {
            moved = true;
            match message.message {
                RTCMessage::RtpPacket(_, packet) if packet.header.payload_type == VP8_PT => {
                    peer.builder.push(now, packet);
                    while let Some(sample) = peer.builder.pop(now) {
                        match peer.decoder.accept(&sample.data) {
                            Some(true) => {
                                peer.usable_at.push(at);
                                let data = &sample.data;
                                let captured = u32::from_be_bytes([
                                    0,
                                    data[VideoModel::HEADER],
                                    data[VideoModel::HEADER + 1],
                                    data[VideoModel::HEADER + 2],
                                ]);
                                peer.usable_lag
                                    .push(at.saturating_sub(Duration::from_millis(
                                        u64::from(captured) * 10,
                                    )));
                            }
                            Some(false) => peer.unusable += 1,
                            None => {}
                        }
                    }
                    // A decoder without its reference asks for a key frame, at most once a
                    // second (ParolNet's receive path).
                    if peer.decoder.last.is_none()
                        && peer
                            .last_keyframe_request
                            .is_none_or(|t| now.duration_since(t) >= Duration::from_secs(1))
                    {
                        peer.last_keyframe_request = Some(now);
                        peer.keyframe_requests.push(at);
                        peer.request_keyframe(now)?;
                    }
                }
                RTCMessage::RtcpPacket(_, packets)
                    if packets.iter().any(|p| {
                        p.as_any().is::<PictureLossIndication>()
                            || p.as_any().is::<FullIntraRequest>()
                    }) =>
                {
                    peer.force_key = true;
                    peer.key_requests_received += 1;
                }
                _ => {}
            }
        }
        Ok(moved)
    }

    /// The application's clock: 20 ms audio frames, 30 video frames a second at the
    /// estimate, the estimate read every 100 ms.
    fn tick(&mut self) -> Result<()> {
        let now = self.now;
        let at = self.elapsed();
        if review_knob("REVIEW_GAP_WAIT_MS").is_some_and(|ms| ms > 0) {
            for peer in self.peers.iter_mut() {
                review_drain(peer, now, at)?;
            }
        }
        if self.media && now >= self.next_audio {
            self.next_audio += Duration::from_millis(20);
            for peer in self.peers.iter_mut() {
                peer.send_frame(now, false, &[0x5a; OPUS_PAYLOAD], 960)?;
            }
        }
        if self.media && now >= self.next_video {
            self.frame += 1;
            self.next_video =
                self.start + Duration::from_micros(self.frame * 1_000_000 / u64::from(VIDEO_FPS));
            let ignore = IGNORE_TARGET.with(|i| i.get());
            for (i, peer) in self.peers.iter_mut().enumerate() {
                peer.media_elapsed = at;
                // A target of zero is the pacer's pause: no frame is produced until the next
                // target (a source that ignores the target, the caller under IGNORE_TARGET,
                // carries on at its rate before the cap).
                let ignoring = ignore && i == 0;
                if !self.video_on[i] || (peer.target_bps == 0 && !ignoring) {
                    continue;
                }
                let bitrate = if ignoring { 1_400_000 } else { peer.target_bps };
                let key = std::mem::take(&mut peer.force_key);
                let mut frame = peer.model.next_frame(video_bitrate_for(bitrate), key);
                // When it was captured, in units of 10 ms, after the model's header.
                let captured = (at.as_millis() / 10) as u32;
                frame[VideoModel::HEADER..VideoModel::HEADER + 3]
                    .copy_from_slice(&captured.to_be_bytes()[1..]);
                if key {
                    peer.keyframes_sent.push(at);
                }
                peer.send_frame(now, true, &frame, 90_000 / VIDEO_FPS)?;
            }
        }
        if now >= self.next_target {
            self.next_target += Duration::from_millis(100);
            let link = &self.uplinks[0];
            let (delay_based, loss_based) = self.peers[0].halves();
            self.trace.push(format!(
                "{:6.1} target {:7} estimate {:7} delay {:7} loss {:7} callee {:7} queue {:3} ms drops {:5} audio {:4} rtx {:5}/{:5} lost padding {:5} usable {:5} unusable {:4}",
                at.as_secs_f64(),
                self.peers[0].target_bps,
                self.peers[0].estimate().unwrap_or(0),
                delay_based,
                loss_based,
                self.peers[1].estimate().unwrap_or(0),
                link.busy_until
                    .map_or(0, |t| t.saturating_duration_since(now).as_millis()),
                link.queue_drops,
                link.audio_dropped,
                link.rtx_sent,
                link.rtx_dropped,
                link.padding_sent,
                self.peers[1].usable_at.len(),
                self.peers[1].unusable,
            ));
            {
                let back = &self.uplinks[1];
                let extra = format!(
                    " | rtcp {}/{} lost | back: target {:7} queue {:3} ms drops {:5} audio {:4} rtx {}/{} rtcp {}/{} lost usable0 {}",
                    link.rtcp_sent,
                    link.rtcp_dropped,
                    self.peers[1].target_bps,
                    back.busy_until
                        .map_or(0, |t| t.saturating_duration_since(now).as_millis()),
                    back.queue_drops,
                    back.audio_dropped,
                    back.rtx_sent,
                    back.rtx_dropped,
                    back.rtcp_sent,
                    back.rtcp_dropped,
                    self.peers[0].usable_at.len(),
                );
                if let Some(last) = self.trace.last_mut() {
                    last.push_str(&extra);
                }
            }
            for peer in self.peers.iter_mut() {
                // Only a peer connection whose chain tells it the estimate has one to report.
                // The statistic leaves the member out when the estimate is zero: once it
                // has been there, a report without it is a zero.
                if peer.handles.is_some() {
                    let outgoing = peer.available_outgoing(now);
                    if let Some(outgoing) = outgoing.or(peer.lowest_outgoing.map(|_| 0.0)) {
                        peer.lowest_outgoing = Some(
                            peer.lowest_outgoing
                                .map_or(outgoing, |low| low.min(outgoing)),
                        );
                    }
                }
                if let Some(estimate) = peer.estimate() {
                    peer.lowest_estimate = Some(
                        peer.lowest_estimate
                            .map_or(estimate, |low| low.min(estimate)),
                    );
                }
                if let Some(bps) = peer.media_target()
                    && bps != peer.target_bps
                {
                    peer.target_bps = bps;
                    peer.targets.push((at, bps));
                }
            }
        }
        Ok(())
    }

    fn advance(&mut self, to: Instant) -> Result<()> {
        while self.now < to {
            let mut next = to;
            for peer in self.peers.iter_mut() {
                if let Some(deadline) = peer.pc.poll_timeout() {
                    next = next.min(deadline);
                }
            }
            if let Some(at) = self.in_flight.iter().map(|d| d.at).min() {
                next = next.min(at);
            }
            if self.media {
                next = next.min(self.next_audio).min(self.next_video);
            }
            next = next.min(self.next_target);
            for peer in self.peers.iter() {
                if let Some(t) = peer.builder.poll_timeout().filter(|t| *t > self.now) {
                    next = next.min(t);
                }
            }
            self.now = next.max(self.now).min(to);
            for peer in self.peers.iter_mut() {
                peer.pc.handle_timeout(self.now)?;
            }
            self.tick()?;
            self.pump()?;
            if self.sampling {
                let caller = &self.peers[0];
                let sample = (self.elapsed(), caller.estimate(), caller.packet_loss());
                self.samples.push(sample);
                let at = self.elapsed();
                for peer in self.peers.iter_mut() {
                    if let Some(estimate) = peer.estimate()
                        && peer.estimates.last().is_none_or(|last| last.1 != estimate)
                    {
                        peer.estimates.push((at, estimate));
                    }
                }
            }
            if self.now == next && next < to {
                // Progress even when a deadline repeats at the same instant.
                let quiet = self
                    .peers
                    .iter_mut()
                    .all(|p| p.pc.poll_timeout().is_none_or(|t| t > self.now))
                    && self.in_flight.iter().all(|d| d.at > self.now);
                if !quiet {
                    self.now += Duration::from_micros(100);
                }
            }
        }
        Ok(())
    }

    /// The 100 ms trace, with `RTC_CAP_TRACE` set.
    fn print_trace(&self, what: &str, setup: &Setup) {
        if std::env::var("RTC_CAP_TRACE").is_ok() {
            for line in &self.trace {
                println!("TRACE {what} {:?} seed {} {line}", setup.chain, setup.seed);
            }
        }
    }

    /// Each peer's host candidate to the other, as after gathering.
    fn trickle(&mut self) -> Result<()> {
        for i in 0..2 {
            let candidate = self.peers[i].candidate()?;
            self.peers[i].pc.add_local_candidate(candidate.clone())?;
            self.peers[1 - i].pc.add_remote_candidate(candidate)?;
        }
        Ok(())
    }

    /// An ICE restart from the caller, signalled at once, with the same host candidates.
    fn restart_ice(&mut self) -> Result<()> {
        let now = self.now;
        self.peers[0].pc.restart_ice();
        let offer = self.peers[0].pc.create_offer(None)?;
        self.peers[0].pc.set_local_description(now, offer.clone())?;
        self.peers[1].pc.set_remote_description(now, offer)?;
        let answer = self.peers[1].pc.create_answer(None)?;
        self.peers[1]
            .pc
            .set_local_description(now, answer.clone())?;
        self.peers[0].pc.set_remote_description(now, answer)?;
        self.trickle()
    }

    /// Peer `i` turns its camera on or off and negotiates the change, signalled at once: its
    /// video section's direction, or, for a peer that never had a video track, a track (on the
    /// section the other peer's offer created, when there is one). As ParolNet's
    /// `set_sending`.
    fn set_video(&mut self, i: usize, on: bool) -> Result<()> {
        let now = self.now;
        match self.peers[i].video {
            Some(sender) => {
                let Some(mut transceiver) = self.peers[i]
                    .pc
                    .rtp_transceiver(RTCRtpTransceiverId::from(sender))
                else {
                    bail!("peer {i} has no video transceiver");
                };
                let receive = transceiver.direction().has_recv();
                transceiver
                    .set_direction(RTCRtpTransceiverDirection::from_send_recv(on, receive))?;
            }
            None if on => {
                let ssrc_base = 0x1000_0000 * (i as u32 + 1);
                let sender = self.peers[i].pc.add_track(video_track(ssrc_base))?;
                self.peers[i].video = Some(sender);
            }
            None => return Ok(()),
        }
        let offer = self.peers[i].pc.create_offer(None)?;
        self.peers[i].pc.set_local_description(now, offer.clone())?;
        self.peers[1 - i].pc.set_remote_description(now, offer)?;
        let answer = self.peers[1 - i].pc.create_answer(None)?;
        self.peers[1 - i]
            .pc
            .set_local_description(now, answer.clone())?;
        self.peers[i].pc.set_remote_description(now, answer)?;
        self.video_on[i] = on;
        // A camera turned on starts with a key frame.
        self.peers[i].force_key |= on;
        Ok(())
    }

    /// Two peers over host candidates, audio and video each way, connected.
    fn connected(setup: &Setup) -> Result<Self> {
        let start = Instant::now();
        let mut world = World {
            peers: [
                Peer::new(
                    "10.0.0.1:5000",
                    setup,
                    0x1111,
                    0x1000_0000,
                    setup.video[0],
                    start,
                )?,
                Peer::new(
                    "10.0.0.2:5000",
                    setup,
                    0x2222,
                    0x2000_0000,
                    setup.video[1],
                    start,
                )?,
            ],
            uplinks: [Uplink::new(), Uplink::new()],
            start,
            now: start,
            in_flight: Vec::new(),
            order: 0,
            next_audio: start,
            next_video: start,
            next_target: start,
            frame: 0,
            media: false,
            video_on: setup.video,
            trace: Vec::new(),
            blackhole: false,
            stun_only: false,
            sampling: false,
            samples: Vec::new(),
        };
        let now = world.now;
        let offer = world.peers[0].pc.create_offer(None)?;
        world.peers[0]
            .pc
            .set_local_description(now, offer.clone())?;
        world.peers[1].pc.set_remote_description(now, offer)?;
        let answer = world.peers[1].pc.create_answer(None)?;
        world.peers[1]
            .pc
            .set_local_description(now, answer.clone())?;
        world.peers[0].pc.set_remote_description(now, answer)?;
        world.trickle()?;
        while !world.peers.iter().all(|p| p.connected) {
            if world.elapsed() > Duration::from_secs(10) {
                bail!("not connected");
            }
            let t = world.now + Duration::from_millis(10);
            world.advance(t)?;
        }
        // Media from the connection on; times are counted from here.
        world.media = true;
        world.start = world.now;
        world.next_audio = world.now;
        world.next_video = world.now;
        world.next_target = world.now;
        Ok(world)
    }
}

/// The estimate in force at `at`.
fn target_at(targets: &[(Duration, u32)], at: Duration) -> u32 {
    targets
        .iter()
        .take_while(|t| t.0 <= at)
        .last()
        .map_or(300_000, |t| t.1)
}

/// The longest time between usable frames from `from` to `to`, and when it began.
fn longest_gap(usable_at: &[Duration], from: Duration, to: Duration) -> (Duration, Duration) {
    let mut last = from;
    let mut longest = (Duration::ZERO, from);
    for at in usable_at.iter().filter(|t| **t >= from && **t <= to) {
        if *at - last > longest.0 {
            longest = (*at - last, last);
        }
        last = *at;
    }
    if to.saturating_sub(last) > longest.0 {
        longest = (to - last, last);
    }
    longest
}

#[derive(Debug)]
#[allow(dead_code)] // Read through `Debug`.
struct Outcome {
    /// The caller's estimate before the cap, and how long it took to go under 400 kbit/s.
    before: u32,
    reacted: Duration,
    /// Its median over the last twelve seconds of the cap.
    under: u32,
    /// The target the encoder followed 20 s after the cap went, and the estimate itself then
    /// (the target less the retransmission reserve, the same with nothing to repair).
    after: u32,
    estimate_after: u32,
    /// The estimate when the cap went, and the target the encoder followed 5, 10, 15 and 20 s
    /// later.
    estimate_at_lift: u32,
    recovery: [u32; 4],
    /// The target the encoder followed from 15 to 25 s after the cap went, read every 100 ms:
    /// its lowest, mean and highest. The estimate climbs in a sawtooth (probes, loss cuts), so
    /// a single reading is the phase of the tooth it falls on; the mean over ten seconds is
    /// the level.
    recovery_window: (u32, u32, u32),
    /// The target the encoder followed when the cap went, and every fall of it from 1 s after
    /// that to the end (when, from, to). The capped link's queue (300 ms) and the feedback on
    /// it can still report congestion for some hundreds of milliseconds after the cap goes;
    /// from 1 s on, the path is open and nothing should cut the estimate.
    target_at_lift: u32,
    recovery_falls: Vec<(Duration, u32, u32)>,
    /// The longest freeze of the callee's video, and when it began.
    freeze: Duration,
    freeze_at: Duration,
    /// The oldest picture the callee showed from the cap on: the longest time between a
    /// frame's capture and its coming out of the decoder (a frame held back for a repair is
    /// usable when it comes, and late).
    lag: Duration,
    capped_at: Duration,
    opened_at: Duration,
    keyframe_requests: Vec<Duration>,
    queue_drops: u64,
    /// Retransmissions the caller sent and those of them dropped at the capped link's queue;
    /// its probe padding on the RTX stream apart (not retransmissions: no media in them).
    rtx_sent: u64,
    rtx_dropped: u64,
    padding_sent: u64,
    padding_dropped: u64,
    /// Opus packets dropped at the capped link's queue.
    audio_dropped: u64,
    /// Video packets the caller's application wrote that never left its host, and those of
    /// them written from 1 s on.
    pacer_dropped: usize,
    pacer_dropped_late: usize,
    /// The caller's `OnPacerDiscard` events (time, frames, packets), and the key-frame requests
    /// it was handed (the callee's and the pacer's).
    pacer_discards: Vec<(Duration, u32, usize)>,
    key_requests_received: u32,
    /// The caller's pauses (target zero, as its application read it every 100 ms): start and
    /// end, and how long after each end the callee had its next usable frame.
    pauses: Vec<(Duration, Duration)>,
    resumed_after: Vec<Duration>,
    unusable: u64,
    /// The caller's lowest congestion estimate and lowest `availableOutgoingBitrate` of the
    /// whole call (read every 100 ms): neither is the pause.
    lowest_estimate: Option<u32>,
    lowest_outgoing: Option<f64>,
}

/// The call: open for 20 s (or until the caller's target reaches `Setup::cap_at_target`),
/// the caller's uplink capped at 300 kbit/s until `Setup::cap` (20 s) after its estimate went
/// under 400 kbit/s, then open again for 25 s.
fn run(setup: &Setup) -> Result<Outcome> {
    let seed = setup.seed;
    let mut world = World::connected(setup)?;
    match setup.cap_at_target {
        None => {
            let t = world.now + Duration::from_secs(20);
            world.advance(t)?;
        }
        Some(bps) => {
            while world.peers[0].target_bps < bps {
                if world.elapsed() > Duration::from_secs(40) {
                    bail!("the target did not reach {bps} bit/s in 40 s");
                }
                let t = world.now + Duration::from_millis(100);
                world.advance(t)?;
            }
        }
    }
    let before = target_at(&world.peers[0].targets, world.elapsed());
    world.uplinks[0].set_profile(LinkProfile::capped_300k());
    let capped_at = world.elapsed();
    let mut reacted = None;
    while world.elapsed() < capped_at + Duration::from_secs(5) {
        if target_at(&world.peers[0].targets, world.elapsed()) < 400_000 {
            reacted = Some(world.elapsed() - capped_at);
            break;
        }
        let t = world.now + Duration::from_millis(10);
        world.advance(t)?;
    }
    let Some(reacted) = reacted else {
        bail!("the estimate did not come down within 5 s");
    };
    let t = world.now + setup.cap;
    world.advance(t)?;
    let mut samples = Vec::new();
    let mut at = capped_at + Duration::from_secs(8).min(setup.cap / 2);
    while at <= world.elapsed() {
        samples.push(target_at(&world.peers[0].targets, at));
        at += Duration::from_millis(100);
    }
    samples.sort_unstable();
    let under = samples[samples.len() / 2];
    world.uplinks[0].set_profile(LinkProfile::open());
    let opened_at = world.elapsed();
    let estimate_at_lift = world.peers[0].estimate().unwrap_or(0);
    let mut recovery = [0; 4];
    for after in recovery.iter_mut() {
        let t = world.now + Duration::from_secs(5);
        world.advance(t)?;
        *after = target_at(&world.peers[0].targets, world.elapsed());
    }
    // On to 25 s after the cap went, for the window from 15 to 25 s.
    let t = world.now + Duration::from_secs(5);
    world.advance(t)?;
    let window: Vec<u32> = (150..=250)
        .map(|tenths| {
            target_at(
                &world.peers[0].targets,
                opened_at + Duration::from_millis(tenths * 100),
            )
        })
        .collect();
    let recovery_window = (
        window.iter().copied().min().unwrap_or(0),
        (window.iter().map(|bps| u64::from(*bps)).sum::<u64>() / window.len() as u64) as u32,
        window.iter().copied().max().unwrap_or(0),
    );
    let target_at_lift = target_at(&world.peers[0].targets, opened_at);
    let recovery_falls = world.peers[0]
        .targets
        .windows(2)
        .filter(|pair| pair[1].0 >= opened_at + Duration::from_secs(1) && pair[1].1 < pair[0].1)
        .map(|pair| (pair[1].0 - opened_at, pair[0].1, pair[1].1))
        .collect();
    let end = world.elapsed();
    let after = target_at(&world.peers[0].targets, end);
    let estimate_after = world.peers[0].estimate().unwrap_or(0);
    let caller = &world.peers[0];
    let pacer_dropped = caller.video_written.difference(&caller.video_left).count();
    // Written from 1 s on and at least 1 s before the end (the last frames may still wait in
    // a pacer when the run stops).
    let pacer_dropped_late = caller
        .video_written_late
        .iter()
        .filter(|(seq, at)| {
            **at + Duration::from_secs(1) <= end && !caller.video_left.contains(seq)
        })
        .count();
    if std::env::var("RTC_CAP_TRACE").is_ok() {
        for line in &world.trace {
            println!("TRACE {:?} seed {seed} {line}", setup.chain);
        }
    }
    let callee = &world.peers[1];
    let (freeze, freeze_at) = longest_gap(&callee.usable_at, Duration::from_secs(2), end);
    let lag = callee
        .usable_at
        .iter()
        .zip(&callee.usable_lag)
        .filter(|(at, _)| **at >= capped_at)
        .map(|(_, lag)| *lag)
        .max()
        .unwrap_or_default();
    let mut pauses = Vec::new();
    let mut started = None;
    for &(at, bps) in &caller.targets {
        match (started, bps) {
            (None, 0) => started = Some(at),
            (Some(from), bps) if bps > 0 => {
                pauses.push((from, at));
                started = None;
            }
            _ => {}
        }
    }
    if let Some(from) = started {
        pauses.push((from, end));
    }
    let resumed_after = pauses
        .iter()
        .map(|(_, until)| {
            callee
                .usable_at
                .iter()
                .find(|at| **at >= *until)
                .map_or(end.saturating_sub(*until), |at| *at - *until)
        })
        .collect();
    Ok(Outcome {
        before,
        reacted,
        under,
        after,
        estimate_after,
        estimate_at_lift,
        recovery,
        recovery_window,
        target_at_lift,
        recovery_falls,
        freeze,
        freeze_at,
        lag,
        capped_at,
        opened_at,
        keyframe_requests: callee.keyframe_requests.clone(),
        queue_drops: world.uplinks[0].queue_drops,
        rtx_sent: world.uplinks[0].rtx_sent,
        rtx_dropped: world.uplinks[0].rtx_dropped,
        padding_sent: world.uplinks[0].padding_sent,
        padding_dropped: world.uplinks[0].padding_dropped,
        audio_dropped: world.uplinks[0].audio_dropped,
        pacer_dropped,
        pacer_dropped_late,
        pacer_discards: caller.pacer_discards.clone(),
        key_requests_received: caller.key_requests_received,
        pauses,
        resumed_after,
        unusable: callee.unusable,
        lowest_estimate: caller.lowest_estimate,
        lowest_outgoing: caller.lowest_outgoing,
    })
}

/// Whether the whole matrix runs (`RTC_CAP_FULL` set): every test of this file on all its
/// seeds (two to six times those of an ordinary run, which is sized to take a hosted runner
/// some ninety seconds).
fn full() -> bool {
    std::env::var_os("RTC_CAP_FULL").is_some()
}

/// The seeds of a test: the first `usual`, and the first `whole` under `RTC_CAP_FULL`.
fn seed_range(usual: u64, whole: u64) -> std::ops::RangeInclusive<u64> {
    1..=if full() { whole } else { usual }
}

/// How long the cap is held in the permanent tests: 20 s on three seeds ([`cap_20`]) and 14,
/// 17, 23 and 26 s on one ([`cap_lengths`]), each set a test of its own under each rule so
/// that they run side by side; six and three seeds with `RTC_CAP_FULL` set (the matrix every
/// change to the estimator is measured on: 18 runs per rule, some four minutes). A bound that
/// holds at one length only can be the phase of the estimate's climb at the instant the cap
/// goes (the estimator this engine had until v0.22.0+brainwires.6 gave 945, 1192, 477 to
/// 1316, 549 and 693 kbit/s twenty seconds after caps of these five lengths, whatever the
/// retransmission rule).
fn cap_lengths() -> Vec<(u64, std::ops::RangeInclusive<u64>)> {
    [14, 17, 23, 26]
        .into_iter()
        .map(|cap| (cap, seed_range(1, 3)))
        .collect()
}

fn cap_20() -> Vec<(u64, std::ops::RangeInclusive<u64>)> {
    vec![(20, seed_range(3, 6))]
}

/// The target the caller's encoder has reached when the cap arrives in the permanent tests
/// of the call without a pacer: 1 Mbit/s, some 15.5 s into the call. Their bounds were
/// measured on a cap that arrived at this rate (20 s into the call under the estimator of
/// v0.22.0+brainwires.6's branch, whose estimate stepped down on an open link and climbed
/// that much slower). How much is lost at a cap is a matter of the rate it meets: for
/// some 0.45 s (the capped link's 300 ms of queue, the path and a feedback interval) nothing
/// can tell the sender, and what it sends above the link's rate meanwhile is dropped. The
/// cap that arrives after 20 s, at 1.4 Mbit/s, is
/// [`a_capacity_cap_that_arrives_at_a_higher_rate_costs_an_older_picture`].
const CAP_AT_TARGET: u32 = 1_000_000;

/// The cap `lengths` and their seeds under `rate_limit` (`None`: the engine's default), each
/// outcome printed; with the cap's length and the seed.
fn seeds(
    rate_limit: Option<RetransmissionRateLimit>,
    lengths: &[(u64, std::ops::RangeInclusive<u64>)],
) -> Result<Vec<(u64, u64, Outcome)>> {
    let mut outcomes = Vec::new();
    for (cap, seeds) in lengths.iter().cloned() {
        for seed in seeds {
            let mut setup = Setup::new(seed, rate_limit)
                .anchor(ANCHORS[0])
                .capped_at_a_target_of(CAP_AT_TARGET);
            setup.cap = Duration::from_secs(cap);
            let outcome = run(&setup)?;
            println!("{rate_limit:?} cap {cap} s seed {seed}: {outcome:?}");
            outcomes.push((cap, seed, outcome));
        }
    }
    Ok(outcomes)
}

/// What every run of the call without a pacer is held to, at every cap length:
///
/// - never more than 2 s without a usable frame on the receiving side;
/// - the oldest picture shown from the cap on (capture to decoder) no older than `lag`;
/// - the retransmissions congestion controlled (RFC 4588 section 7): at most 100 sent
///   through the cap (the rules held to the target send 42 to 54, 13 to 17 of them dropped at
///   the link's queue; without a limit 54 to 105 were sent and more than half dropped);
/// - the capped link used: the median target under the cap at least 200 kbit/s of the 300;
/// - the estimate recovered: at least 800 kbit/s on average from 15 to 25 s after the cap
///   went (a single reading is the phase of the estimate's sawtooth: the +20 s target of one
///   seed moved from 777 to 1074 kbit/s with nothing but the wall clock's phase, runs
///   45360145995).
fn assert_the_call_holds(outcomes: &[(u64, u64, Outcome)], lag: Duration) {
    for (cap, seed, outcome) in outcomes {
        assert!(
            outcome.freeze <= Duration::from_secs(2),
            "cap {cap} s seed {seed}: the video froze for {:?}: {outcome:?}",
            outcome.freeze
        );
        assert!(
            outcome.lag <= lag,
            "cap {cap} s seed {seed}: a picture {:?} old: {outcome:?}",
            outcome.lag
        );
        assert!(
            outcome.rtx_sent <= 100,
            "cap {cap} s seed {seed}: {} retransmissions: {outcome:?}",
            outcome.rtx_sent
        );
        assert!(
            outcome.under >= 200_000,
            "cap {cap} s seed {seed}: {} bit/s under the cap: {outcome:?}",
            outcome.under
        );
        assert!(
            outcome.recovery_window.1 >= 800_000,
            "cap {cap} s seed {seed}: {} bit/s on average 15 to 25 s after the cap: {outcome:?}",
            outcome.recovery_window.1
        );
    }
}

/// Video through a 300 kbit/s cap that comes and goes, on six seeds, under the engine's
/// default retransmission rule (RFC 4588 section 7: the original and the retransmitted data
/// share the target, and the target the encoder follows is lowered while repairs are
/// pending): never more than 2 s without a usable frame on the receiving side (engine
/// v0.22.0+brainwires.5 gave at most 0.85 s in ParolNet's simulation of the same call;
/// v0.22.0+brainwires.6 froze for 5.9 to 6.8 s here on every seed; now 1.33 to 1.44 s, and
/// 2.46 to 2.47 s with the RFC's sharing but without the lowered target).
///
/// When the cap comes ([`CAP_AT_TARGET`]), the sender is still at 1 Mbit/s for half a second
/// and some forty video packets are dropped at the link's queue. With the release's NACK request policy (ten
/// requests or two seconds, then a packet is given up) and retransmissions that nothing held
/// to the estimate (about 300, five times the link, three in four of them dropped at the same
/// queue), some of those packets were given up, stayed lost, the sample builder held every
/// later frame back for its 256 packets and the picture froze until a key frame. Now a packet
/// is asked for while it is missing, the retransmissions stay within the estimate, and the
/// encoder leaves them room.
///
/// The cap is held 20 s here and 14, 17, 23 and 26 s in the next test ([`cap_lengths`]), and
/// the same bounds hold at each ([`assert_the_call_holds`]): with the engine's GCC estimator
/// behind the TWCC-driven interceptor (a loss-based estimate of its own, over-use backing off
/// from the received rate, the estimate not increased past one and a half times the received
/// rate: draft-ietf-rmcat-gcc-02 sections 5.5 and 6) the estimate holds about 250 kbit/s of
/// the 300 under the cap and is at 1 to 1.35 Mbit/s twenty seconds after it, whenever the cap
/// goes.
#[test]
#[ignore = "review harness: the tree's own copy of this test is the one that asserts"]
fn video_keeps_playing_through_a_capacity_cap_that_comes_and_goes() -> Result<()> {
    // Measured (hosted run 45334499296, six seeds, and three at each other length): freeze
    // 0.56 to 1.26 s, the oldest picture 1.68 to 2.48 s, 39 to 47 retransmissions (10 to 14
    // dropped), 239 to 257 kbit/s under the cap, 1027 to 1320 kbit/s twenty seconds after
    // it. With one decrease per round trip (libwebrtc's form, the default until this
    // estimate was measured; run 45332800112): 0.85 to 1.36 s, 2.33 to 2.61 s, 42 to 49,
    // 234 to 251, 977 to 1344. With the cap arriving after 20 s at the 0.99 Mbit/s the
    // earlier estimator had reached by then (runs 45315535896, 45312738975): 0.83 to
    // 1.24 s, 2.26 to 3.21 s, 43 to 66, 238 to 266, 988 to 1352.
    assert_the_call_holds(&seeds(None, &cap_20())?, Duration::from_millis(3_500));
    Ok(())
}

/// The same bounds whenever the cap goes: after 14, 17, 23 and 26 s.
#[test]
#[ignore = "review harness: the tree's own copy of this test is the one that asserts"]
fn video_keeps_playing_through_a_capacity_cap_of_any_length() -> Result<()> {
    assert_the_call_holds(&seeds(None, &cap_lengths())?, Duration::from_millis(3_500));
    Ok(())
}

/// The same call under the setting [`RetransmissionRateLimit::UpToTarget`] (the
/// retransmissions alone under the target, the encoder's target not lowered), held to bounds
/// of its own.
#[test]
#[ignore = "review harness: the tree's own copy of this test is the one that asserts"]
fn video_keeps_playing_through_a_capacity_cap_with_retransmissions_up_to_the_target() -> Result<()>
{
    // Measured under this setting (hosted run 45334499296, six seeds, and three at each
    // other length): freeze 0.80 to 1.29 s, the oldest picture 2.30 to 2.57 s, 46 to 57
    // retransmissions (12 to 16 dropped at the link's queue, against 10 to 14 under the
    // default).
    assert_the_call_holds(
        &seeds(
            Some(RetransmissionRateLimit::UpToTarget),
            &[(20, seed_range(2, 6))],
        )?,
        Duration::from_millis(4_000),
    );
    Ok(())
}

/// And under that setting whenever the cap goes: after 14, 17, 23 and 26 s.
#[test]
#[ignore = "review harness: the tree's own copy of this test is the one that asserts"]
fn video_keeps_playing_through_a_capacity_cap_of_any_length_with_retransmissions_up_to_the_target()
-> Result<()> {
    // The shortest and the longest cap in an ordinary run; all four with `RTC_CAP_FULL`.
    let lengths: Vec<_> = cap_lengths()
        .into_iter()
        .filter(|(cap, _)| full() || matches!(cap, 14 | 26))
        .collect();
    assert_the_call_holds(
        &seeds(Some(RetransmissionRateLimit::UpToTarget), &lengths)?,
        Duration::from_millis(4_000),
    );
    Ok(())
}

/// The cap that arrives after 20 s of call, when the estimate is at 1.4 Mbit/s (8% a second
/// from 300 kbit/s: draft-ietf-rmcat-gcc-02 section 5.5), under the default rule. The video
/// keeps playing (never 2 s without a usable frame), the capped link is used and the
/// estimate recovers as at the lower rate; what the higher rate costs is the picture's age
/// and the retransmissions, held here to what was measured so that they do not grow.
///
/// Measured (hosted run 45334499296, six seeds): freeze 1.28 to 1.32 s, the oldest picture
/// 4.40 to 4.51 s, 92 to 101 retransmissions (23 to 32 dropped at the link's queue), 246 to
/// 254 kbit/s under the cap, 1086 to 1361 kbit/s twenty seconds after it. Some sixty video
/// packets are lost before the first feedback about the capped link can arrive and while
/// the received rate's 500 ms window still holds what arrived before the cap (about forty
/// at 1 Mbit/s), and repairing them inside 250 kbit/s, of which the audio takes 76, takes
/// that much longer. Traced repair by repair (hosted runs 45341865225, 45342290711): 20 to
/// 22 of the drops are repairs made 0.42 to 0.62 s after their original, in the first 0.2 s
/// after the first NACKs, into the link's queue still full of media sent at the old rate;
/// and 24 to 28 of the retransmissions repeat a packet whose first repair was still in the
/// queue when the receiver asked again, sent after that repair arrived and, oldest packet
/// first, ahead of first repairs of newer gaps. The release before (v0.22.0+brainwires.6, whose estimator met the cap at
/// 1.38 Mbit/s; the same port, run 45331840230): freeze 0.98 to 1.23 s, the oldest picture
/// 4.24 to 4.39 s, 62 to 67 retransmissions (11 to 12 dropped), 199 to 206 kbit/s under the
/// cap, 473 to 1501 kbit/s twenty seconds after it. So at this rate the freeze is 0.1 to
/// 0.3 s longer than it was, the picture up to 0.3 s older and the retransmissions half
/// again as many, while the capped link carries 45 to 50 kbit/s more and the recovery has
/// no slow seed (473 and 737 kbit/s on two of six before). What shortens it is not in the
/// estimator: no repeat repair of a packet whose first repair transport-wide feedback
/// reports received (planned), and a delay-based detector that reads a queue filling within
/// a feedback interval (a known limit). Giving up repairs older than 1 s and asking for a key
/// frame instead was measured (hosted run 45342372315): frozen 8.36 to 8.49 s, the oldest
/// picture 7.55 to 7.77 s, because this receiver (the sample builder without a time bound)
/// holds the gap for its whole packet window and the key frame waits behind it.
#[test]
#[ignore = "review harness: the tree's own copy of this test is the one that asserts"]
fn a_capacity_cap_that_arrives_at_a_higher_rate_costs_an_older_picture() -> Result<()> {
    for seed in seed_range(1, 6) {
        let outcome = run(&Setup::new(seed, None).anchor(ANCHORS[0]))?;
        println!("cap after 20 s seed {seed}: {outcome:?}");
        assert!(
            outcome.before >= 1_300_000,
            "seed {seed}: the cap met {} bit/s: {outcome:?}",
            outcome.before
        );
        assert!(
            outcome.freeze <= Duration::from_secs(2),
            "seed {seed}: the video froze for {:?}: {outcome:?}",
            outcome.freeze
        );
        assert!(
            outcome.lag <= Duration::from_millis(5_500),
            "seed {seed}: a picture {:?} old: {outcome:?}",
            outcome.lag
        );
        assert!(
            outcome.rtx_sent <= 130,
            "seed {seed}: {} retransmissions: {outcome:?}",
            outcome.rtx_sent
        );
        assert!(
            outcome.under >= 200_000,
            "seed {seed}: {} bit/s under the cap: {outcome:?}",
            outcome.under
        );
        assert!(
            outcome.recovery_window.1 >= 800_000,
            "seed {seed}: {} bit/s on average 15 to 25 s after the cap: {outcome:?}",
            outcome.recovery_window.1
        );
    }
    Ok(())
}

/// The same call with retransmissions not congestion controlled
/// ([`RetransmissionRateLimit::Unlimited`]), for comparison: prints the outcomes, asserts
/// nothing.
#[test]
#[ignore = "measurement: run with --ignored --nocapture"]
fn measure_unlimited_retransmissions_through_a_capacity_cap() -> Result<()> {
    seeds(Some(RetransmissionRateLimit::Unlimited), &cap_20())?;
    seeds(Some(RetransmissionRateLimit::Unlimited), &cap_lengths())?;
    Ok(())
}

/// A measurement over what the environment names, one line per run; asserts nothing.
/// `RTC_CAP_CHAINS` (`parolnet`, `default`, `nopacer`; all three by default), `RTC_CAP_RULES`
/// (`within`, `upto`, `unlimited`), `RTC_CAP_SEEDS` (`1,2,..`; 1 to 6), `RTC_CAP_ANCHORS`
/// (indices into the three wall clocks, `0,1,2`), `RTC_CAP_SECONDS` (how long the cap stays;
/// `20`), each a comma-separated list; `RTC_CAP_AT_TARGET` (the target in bit/s at which the
/// cap arrives, instead of after 20 s).
#[test]
#[ignore = "measurement: run with --ignored --nocapture"]
fn measure_the_capacity_cap() -> Result<()> {
    fn list(name: &str, default: &str) -> Vec<String> {
        std::env::var(name)
            .unwrap_or_else(|_| default.to_owned())
            .split(',')
            .map(|item| item.trim().to_owned())
            .filter(|item| !item.is_empty())
            .collect()
    }
    for chain in list("RTC_CAP_CHAINS", "parolnet,default,nopacer") {
        for rule in list("RTC_CAP_RULES", "within,upto,unlimited") {
            for seconds in list("RTC_CAP_SECONDS", "20") {
                for seed in list("RTC_CAP_SEEDS", "1,2,3,4,5,6") {
                    for anchor in list("RTC_CAP_ANCHORS", "0,1,2") {
                        let rate_limit = match rule.as_str() {
                            "within" => RetransmissionRateLimit::WithinTarget,
                            "upto" => RetransmissionRateLimit::UpToTarget,
                            "unlimited" => RetransmissionRateLimit::Unlimited,
                            other => bail!("unknown rule {other}"),
                        };
                        let at_target = std::env::var("RTC_CAP_AT_TARGET").ok();
                        let mut setup = Setup::new(seed.parse()?, Some(rate_limit))
                            .chain(match chain.as_str() {
                                "parolnet" => Chain::ParolNet,
                                "default" => Chain::Default,
                                "nopacer" => Chain::DefaultWithoutPacer,
                                other => bail!("unknown chain {other}"),
                            })
                            .anchor(ANCHORS[anchor.parse::<usize>()?]);
                        setup.cap = Duration::from_secs(seconds.parse()?);
                        if let Some(bps) = &at_target {
                            setup = setup.capped_at_a_target_of(bps.parse()?);
                        }
                        match run(&setup) {
                            Ok(o) => println!(
                                "ROW chain {chain} rule {rule} cap {seconds} seed {seed} anchor {anchor} | before {} at {:.1} | freeze {:.2} at {:.1} lag {:.2} | rtx {}/{} dropped | padding {}/{} dropped | queue drops {} audio {} | pacer dropped {} late {} discards {} pauses {} | pli {} | under {} lift {} target {} recovery {:?} window {}/{}/{} climb {} falls {} | estimate after {}",
                                o.before / 1000,
                                o.capped_at.as_secs_f64(),
                                o.freeze.as_secs_f64(),
                                o.freeze_at.as_secs_f64(),
                                o.lag.as_secs_f64(),
                                o.rtx_sent,
                                o.rtx_dropped,
                                o.padding_sent,
                                o.padding_dropped,
                                o.queue_drops,
                                o.audio_dropped,
                                o.pacer_dropped,
                                o.pacer_dropped_late,
                                o.pacer_discards.len(),
                                o.pauses.len(),
                                o.keyframe_requests.len(),
                                o.under / 1000,
                                o.estimate_at_lift / 1000,
                                o.target_at_lift / 1000,
                                o.recovery.map(|bps| bps / 1000),
                                o.recovery_window.0 / 1000,
                                o.recovery_window.1 / 1000,
                                o.recovery_window.2 / 1000,
                                draft_climb_mean(o.target_at_lift) / 1000,
                                o.recovery_falls.len(),
                                o.estimate_after / 1000,
                            ),
                            Err(error) => println!(
                                "ROW chain {chain} rule {rule} cap {seconds} seed {seed} anchor {anchor} | failed: {error}"
                            ),
                        }
                    }
                }
            }
        }
    }
    Ok(())
}

/// The mean, over the window of `Outcome::recovery_window` (15 to 25 s after the cap, every
/// 100 ms), of an estimate that climbs from `from` bit/s at the multiplicative increase of
/// draft-ietf-rmcat-gcc-02 section 5.5 ("During multiplicative increase, the estimate is
/// increased by at most 8% per second"), up to `MAX_BPS`.
fn draft_climb_mean(from: u32) -> u32 {
    let samples: Vec<f64> = (150..=250)
        .map(|tenths| {
            (f64::from(from) * 1.08f64.powf(f64::from(tenths) / 10.0)).min(f64::from(MAX_BPS))
        })
        .collect();
    (samples.iter().sum::<f64>() / samples.len() as f64) as u32
}

/// The same call through the engine's default interceptors (the pacer with its default
/// `PacerQueueOverflow::Drop`, GCC on transport-wide feedback, the NACK pair with the RFC 4588
/// section 7 default), the video following the target the senders are given
/// (`RTCRtpSender::target_bitrates`, lowered by the retransmission reserve while repairs wait),
/// on six seeds. When the cap comes the pacer holds video written at the old rate; once it
/// would take half its 2 s bound to send, the target the application reads is zero (the pause)
/// until the queue has drained, and the video produces nothing meanwhile. So nothing is
/// discarded (no video packet written that never left, no `OnPacerDiscard`), the video
/// resumes within a second of each pause's end, and it does not freeze for more than 2 s.
/// Once the cap goes, the target is never cut again and climbs at least about as fast as the
/// draft's multiplicative increase from where the cap left it.
#[test]
#[ignore = "review harness: the tree's own copy of this test is the one that asserts"]
fn a_sender_following_the_target_is_paused_and_loses_nothing_at_the_pacer() -> Result<()> {
    let outcomes: Result<Vec<_>> = seed_range(2, 6)
        .map(|seed| {
            let outcome = run(&Setup::new(seed, None)
                .chain(Chain::Default)
                .anchor(ANCHORS[0]))?;
            println!("default chain seed {seed}: {outcome:?}");
            Ok((seed, outcome))
        })
        .collect();
    let outcomes = outcomes?;
    for (seed, outcome) in &outcomes {
        assert_eq!(0, outcome.pacer_dropped_late, "seed {seed}: {outcome:?}");
        assert!(
            outcome.pacer_discards.is_empty(),
            "seed {seed}: {outcome:?}"
        );
        assert!(
            !outcome.pauses.is_empty(),
            "seed {seed}: never paused: {outcome:?}"
        );
        // The pause is the pacer's word to the source and nothing else: the congestion
        // controller's estimate is never zero, and `availableOutgoingBitrate` reports the
        // estimate through every pause.
        assert!(
            outcome.lowest_estimate.is_some_and(|low| low >= MIN_BPS),
            "seed {seed}: the estimator paused: {outcome:?}"
        );
        assert!(
            outcome
                .lowest_outgoing
                .is_some_and(|low| low >= f64::from(MIN_BPS)),
            "seed {seed}: availableOutgoingBitrate lost the estimate in a pause: {outcome:?}"
        );
        for after in &outcome.resumed_after {
            assert!(
                *after <= Duration::from_secs(1),
                "seed {seed}: no usable frame {after:?} after a pause ended: {outcome:?}"
            );
        }
        assert!(
            outcome.freeze <= Duration::from_secs(2),
            "seed {seed}: the video froze for {:?}: {outcome:?}",
            outcome.freeze
        );
        // Measured (hosted run 45334499296, six seeds): freeze 0.97 to 1.91 s, 1043 to
        // 2500 kbit/s twenty seconds after the cap, and the oldest picture shown 5.59 to
        // 9.84 s old (with one decrease per round trip, run 45332800112: 1.38 to 1.86 s, 946
        // to 2500 kbit/s, 6.46 to 8.87 s; run 45315529565, six seeds on three wall clocks:
        // 1.38 to 1.90 s, 902 to 1484 kbit/s, 5.95 to 8.56 s). That last figure is the known
        // cost of this chain at a sudden drop: the 55 to 62 video packets the path lost while
        // the source was at 2.5 Mbit/s are repaired inside an estimate of 100 to 250 kbit/s,
        // of which the audio takes 76, under every retransmission rule (the pacer holds
        // repairs to the estimate; without one they leave in a burst while the estimate is
        // still falling), and 35 to 41 of the repairs repeat a packet whose first repair was
        // still in flight when the receiver asked again (hosted traces 45341865225,
        // 45342290711). It is a documented known limit (CHANGELOG, "Known limits"), and the
        // bound here guards it against gross regression only: on six seeds and three wall
        // clocks the oldest picture was 5.56 to 9.84 s with the ICE agent's 27-byte SOFTWARE
        // text and 5.56 to 10.23 s with its 14-byte one (hosted runs 45370399055 and
        // 45370404660: the seeded figures follow the wire's packet sizes, so one text length
        // moves a seed by some hundreds of milliseconds). The bound is that maximum, 10.23 s,
        // and some 15 % (11.75 s). The freeze, the retransmissions and the recovery are held
        // more tightly by the other assertions here. Not repeating a repair whose first copy
        // is still in flight (`conf/rtx-1-duplicate-repairs`) brings it to 4.14 to 6.58 s,
        // and the bound down with it.
        assert!(
            outcome.lag <= Duration::from_millis(11_750),
            "seed {seed}: a picture {:?} old: {outcome:?}",
            outcome.lag
        );
        // The retransmissions, apart from the probe clusters' padding on the RTX stream
        // (154 to 330 packets, which this test counted with them until it told them apart):
        // 90 to 103 on six seeds, none dropped at the link (hosted run 45343885944). The bound
        // (as the cap after 20 s without a pacer: some 30 % over the most measured) guards
        // them from growing, and fails if the padding is counted with them again.
        assert!(
            outcome.rtx_sent <= 130,
            "seed {seed}: {} retransmissions: {outcome:?}",
            outcome.rtx_sent
        );
        // The recovery, against the target the cap left: from 1 s after the cap went it never
        // falls, and from 15 to 25 s after it its mean is at least nine tenths of the draft's
        // multiplicative increase from the target at that instant ([`draft_climb_mean`]).
        // Not a fixed figure: once the path is open, a source that follows its target is not
        // application limited and no probe is due (`ProbeController`: the start, a further
        // probe after a confirming result, a large drop within the last 2 s, a sender under
        // 65 % of the target), so the estimate climbs from wherever the cap left it at the
        // draft's 8 % a second. Where it left it is the phase of the sawtooth under the cap,
        // and with that the seeded run's packet sizes and timing, down to the length of the
        // ICE agent's SOFTWARE text in every STUN message: the same seed ended the cap at
        // 212 or 132 kbit/s with that text 27 or 14 bytes long, and was 1150 or 641 kbit/s on
        // average 15 to 25 s later. Measured (hosted runs 45370399055 and 45370404660, six
        // seeds on three wall clocks, with each of the two texts): target at the cap's end
        // 124 to 270 kbit/s, no fall from 1 s on, mean 641 to 2500 kbit/s; 0.99 to 1.21 times
        // the draft's climb where no probe landed, 1.29 to 2.81 where one did (the drop rule
        // firing as the cap went, or a sender held under its target).
        assert!(
            outcome.recovery_falls.is_empty(),
            "seed {seed}: the target fell after the cap went: {:?}: {outcome:?}",
            outcome.recovery_falls
        );
        let climb = draft_climb_mean(outcome.target_at_lift);
        assert!(
            u64::from(outcome.recovery_window.1) * 10 >= u64::from(climb) * 9,
            "seed {seed}: {} bit/s on average 15 to 25 s after the cap, under nine tenths of \
             the draft's climb from {} bit/s ({climb}): {outcome:?}",
            outcome.recovery_window.1,
            outcome.target_at_lift
        );
    }
    Ok(())
}

/// The default chain with a caller that ignores the target (its video stays at 1.4 Mbit/s
/// through the cap and through the pause): what waits the pacer's 2 s bound is discarded whole
/// frames at a time, every video packet that never left was announced (`OnPacerDiscard`), and
/// each discard came with a key-frame request.
#[test]
#[ignore = "review harness: the tree's own copy of this test is the one that asserts"]
fn a_sender_ignoring_the_target_has_whole_frames_discarded_and_is_asked_for_key_frames()
-> Result<()> {
    IGNORE_TARGET.with(|i| i.set(true));
    let outcome = run(&Setup::new(1, None).chain(Chain::Default));
    IGNORE_TARGET.with(|i| i.set(false));
    let outcome = outcome?;
    println!("default chain, target ignored, seed 1: {outcome:?}");
    let announced: usize = outcome.pacer_discards.iter().map(|d| d.2).sum();
    assert!(announced > 0, "{outcome:?}");
    // Every packet announced never left, and every packet that never left was announced or
    // still waited in the pacer when the run ended (at most its 2 s of queue). This source
    // writes 1.4 Mbit/s from the first frame, so the discards begin in the first second,
    // before there is an estimate.
    assert!(announced <= outcome.pacer_dropped, "{outcome:?}");
    assert!(
        outcome.pacer_dropped - announced <= 300,
        "{} packets never left and were not announced: {outcome:?}",
        outcome.pacer_dropped - announced
    );
    let with_frames = outcome.pacer_discards.iter().filter(|d| d.1 > 0).count();
    assert!(
        outcome.key_requests_received as usize >= 2 + with_frames,
        "a key frame asked for with each discard: {outcome:?}"
    );
    Ok(())
}

#[derive(Debug)]
#[allow(dead_code)] // Read through `Debug`.
struct PathChangeOutcome {
    /// The caller's estimate before its network went.
    before: Option<u32>,
    /// When its application was told of the restart's pair, and the estimate then.
    switched_at: Duration,
    at_switch: Option<u32>,
    /// The lowest estimate, and the highest loss the default chain's controller counted, in
    /// the three seconds after the switch; the estimate at their end.
    lowest_after: u32,
    most_loss_after: f64,
    estimate_after: Option<u32>,
    /// The lowest target the caller's encoder was given before the switch (the outage
    /// included).
    lowest_before: Option<u32>,
    /// Each peer's estimate, every time it moved, in the ten seconds from the switch on.
    estimates: [Vec<(Duration, u32)>; 2],
}

/// The call of ParolNet's `an_ice_restart_follows_a_machine_to_another_network`: ten seconds
/// open, then nothing arrives either way for four seconds (the caller's machine left its
/// network, and every packet sent meanwhile went into the dead path), then an ICE restart
/// whose checks reach the other side while the media path still does not, until the caller
/// has selected the new pair. Every datagram keeps the same addresses throughout, as in an
/// application that hands them over with a placeholder pair: only the peer connection's word
/// tells the congestion controllers that the path changed.
fn path_change_run(setup: &Setup) -> Result<PathChangeOutcome> {
    let mut world = World::connected(setup)?;
    let t = world.now + Duration::from_secs(10);
    world.advance(t)?;
    let before = world.peers[0].estimate();
    for peer in world.peers.iter_mut() {
        peer.pair_changes.clear();
    }
    world.blackhole = true;
    let t = world.now + Duration::from_secs(4);
    world.advance(t)?;
    world.blackhole = false;
    world.stun_only = true;
    world.restart_ice()?;
    let restarted_at = world.elapsed();
    while world.peers[0].pair_changes.is_empty() {
        if world.elapsed() > restarted_at + Duration::from_secs(10) {
            bail!("the restart selected no pair");
        }
        let t = world.now + Duration::from_millis(10);
        world.advance(t)?;
    }
    world.stun_only = false;
    let (switched_at, at_switch) = world.peers[0].pair_changes[0];
    world.sampling = true;
    let t = world.now + Duration::from_secs(3);
    world.advance(t)?;
    let after: Vec<_> = world
        .samples
        .iter()
        .filter(|(at, _, _)| *at >= switched_at)
        .cloned()
        .collect();
    let estimate_after = world.peers[0].estimate();
    // And on, to ten seconds after the switch: where the estimate goes on the new path.
    let t = world.now + Duration::from_secs(7);
    world.advance(t)?;
    world.print_trace("path change", setup);
    Ok(PathChangeOutcome {
        before,
        lowest_before: world.peers[0]
            .targets
            .iter()
            .filter(|(at, _)| *at < switched_at)
            .map(|(_, bps)| *bps)
            .min(),
        estimates: [0, 1].map(|i| world.peers[i].estimates.clone()),
        switched_at,
        at_switch,
        lowest_after: after
            .iter()
            .filter_map(|(_, estimate, _)| *estimate)
            .min()
            .unwrap_or(0),
        most_loss_after: after
            .iter()
            .filter_map(|(_, _, loss)| *loss)
            .fold(0.0, f64::max),
        estimate_after,
    })
}

/// A new selected pair is a new path for the congestion controller also when the datagrams
/// keep their addresses (RFC 8836 section 2, requirement 1): the peer connection tells the
/// chain (`PathChanged`), the estimate starts over from the start rate, and the packets sent
/// into the dead path during the outage are not counted as the new path's loss (libwebrtc's
/// `RtpTransportControllerSend::OnNetworkRouteChanged`: `restart_bwe`, and a feedback adapter
/// that reports only packets sent on the new route). ParolNet's simulation of this call saw
/// one feedback report a loss of 0.985 after the restart and its GCC cut the estimate from
/// 437 to 242 kbit/s, and the video froze for 7 s. ParolNet's chain (the TWCC-driven GCC).
#[test]
#[ignore = "review harness: the tree's own copy of this test is the one that asserts"]
fn an_ice_restart_with_the_same_addresses_starts_the_estimate_over() -> Result<()> {
    for seed in seed_range(1, 3) {
        let outcome = path_change_run(&Setup::new(seed, None))?;
        println!("ParolNet chain seed {seed}: {outcome:?}");
        assert!(
            outcome.before.is_some_and(|before| before > 300_000),
            "seed {seed}: the estimate climbed before the outage: {outcome:?}"
        );
        assert_eq!(
            Some(300_000),
            outcome.at_switch,
            "seed {seed}: the estimate starts over at the new pair: {outcome:?}"
        );
        // The estimator's own word on it: the loss it counted after the switch (the packets
        // of the outage counted, some thirty of thirty-five, would read 0.8). And the
        // estimate does not go under the start rate in the three seconds after the switch:
        // the new path loses and queues nothing. (Until the bound by the received rate
        // stopped lowering an estimate, it fell to 178 kbit/s here, one and a half times
        // what arrived once the first key frame had left the measurement window.)
        assert!(
            outcome.most_loss_after < 0.1,
            "seed {seed}: the old path's packets counted as lost: {outcome:?}"
        );
        assert!(
            outcome.lowest_after >= 300_000,
            "seed {seed}: cut to {}: {outcome:?}",
            outcome.lowest_after
        );
    }
    Ok(())
}

/// The same call through the engine's default interceptors (GCC on transport-wide feedback in
/// the congestion control interceptor, the pacer): the packets sent into the dead path are not
/// counted as lost after the switch (the controller's smoothed loss stays under the 10 % at
/// which it starts cutting), and the target is not lower three seconds after the switch than
/// at it.
#[test]
#[ignore = "review harness: the tree's own copy of this test is the one that asserts"]
fn an_ice_restart_with_the_same_addresses_counts_no_old_loss_in_the_default_chain() -> Result<()> {
    let outcomes: Result<Vec<_>> = seed_range(1, 3)
        .map(|seed| {
            let outcome = path_change_run(&Setup::new(seed, None).chain(Chain::Default))?;
            println!("default chain seed {seed}: {outcome:?}");
            Ok((seed, outcome))
        })
        .collect();
    for (seed, outcome) in &outcomes? {
        assert!(
            outcome.most_loss_after < 0.1,
            "seed {seed}: the old path's packets counted as lost: {outcome:?}"
        );
        assert_eq!(
            Some(300_000),
            outcome.at_switch,
            "seed {seed}: the estimate starts over at the new pair: {outcome:?}"
        );
        assert!(
            outcome.lowest_after >= 300_000,
            "seed {seed}: cut to {}: {outcome:?}",
            outcome.lowest_after
        );
    }
    Ok(())
}

/// The first step down of a series of (time, bit rate), with the value before it.
fn first_step_down(series: &[(Duration, u32)]) -> Option<(Duration, u32, u32)> {
    series
        .windows(2)
        .find(|pair| pair[1].1 < pair[0].1)
        .map(|pair| (pair[1].0, pair[0].1, pair[1].1))
}

#[derive(Debug)]
#[allow(dead_code)] // Read through `Debug`.
struct OpenLinkOutcome {
    /// Per peer: when its estimate reached 1 Mbit/s, the first time it stepped down (when,
    /// from, to), where it ended, and the bits of video its application wrote.
    reached_1m: [Option<Duration>; 2],
    step_down: [Option<(Duration, u32, u32)>; 2],
    last: [Option<u32>; 2],
    video_bits: [u64; 2],
    /// The same for the target the encoder followed (read every 100 ms).
    target_step_down: [Option<(Duration, u32, u32)>; 2],
    /// The lowest target the encoder was given (zero is the pacer's pause) and the lowest
    /// `availableOutgoingBitrate`.
    lowest_target: [Option<u32>; 2],
    lowest_outgoing: [Option<f64>; 2],
}

/// The call of ParolNet's `the_estimate_climbs_on_an_open_link`: thirty-five seconds on a
/// link without loss, without a capacity and so without a queue, audio and video each way,
/// the video following the estimate.
fn open_link_run(setup: &Setup) -> Result<OpenLinkOutcome> {
    let mut world = World::connected(setup)?;
    world.sampling = true;
    let t = world.now + Duration::from_secs(35);
    world.advance(t)?;
    world.print_trace("open link", setup);
    let peers = &world.peers;
    Ok(OpenLinkOutcome {
        reached_1m: [0, 1].map(|i| {
            peers[i]
                .estimates
                .iter()
                .find(|(_, bps)| *bps >= 1_000_000)
                .map(|(at, _)| *at)
        }),
        step_down: [0, 1].map(|i| first_step_down(&peers[i].estimates)),
        last: [0, 1].map(|i| peers[i].estimates.last().map(|(_, bps)| *bps)),
        video_bits: [0, 1].map(|i| peers[i].video_octets * 8),
        target_step_down: [0, 1].map(|i| first_step_down(&peers[i].targets)),
        lowest_target: [0, 1].map(|i| peers[i].targets.iter().map(|(_, bps)| *bps).min()),
        lowest_outgoing: [0, 1].map(|i| peers[i].lowest_outgoing),
    })
}

/// What an open link is held to, in both chains: the estimate never steps down (nothing was
/// lost and nothing queued: there is no evidence of congestion to step down for), it starts
/// at the start rate, reaches 1 Mbit/s within `by` and the maximum by the end, and the video
/// followed it.
fn assert_the_estimate_climbs(setup: &Setup, outcome: &OpenLinkOutcome, by: Duration) {
    for (i, who) in ["caller", "callee"].into_iter().enumerate() {
        assert_eq!(
            None, outcome.step_down[i],
            "{setup:?} {who}: the estimate stepped down on a link without loss or queueing: {outcome:?}"
        );
        assert!(
            outcome.reached_1m[i].is_some_and(|at| at <= by),
            "{setup:?} {who}: 1 Mbit/s at {:?}: {outcome:?}",
            outcome.reached_1m[i]
        );
        assert_eq!(
            Some(MAX_BPS),
            outcome.last[i],
            "{setup:?} {who}: up to the maximum: {outcome:?}"
        );
        assert!(
            outcome.video_bits[i] > 20_000_000,
            "{setup:?} {who}: {} bits of video in 35 s: {outcome:?}",
            outcome.video_bits[i]
        );
        // No pause without a pacer queue, and where the peer connection has the estimate
        // (the default chain) `availableOutgoingBitrate` never reports less than the start
        // rate on this link.
        assert!(
            outcome.lowest_target[i].is_none_or(|low| low >= 300_000),
            "{setup:?} {who}: a target under the start rate: {outcome:?}"
        );
        if setup.chain != Chain::ParolNet {
            assert!(
                outcome.lowest_outgoing[i].is_some_and(|low| low >= 300_000.0),
                "{setup:?} {who}: availableOutgoingBitrate: {outcome:?}"
            );
        }
    }
}

/// ParolNet's `the_estimate_climbs_on_an_open_link`, in its chain (the TWCC-driven GCC, no
/// pacer): on a link that loses nothing and queues nothing the estimate never goes down, and
/// it is at 1 Mbit/s no later than the estimator this interceptor had until
/// v0.22.0+brainwires.6 was. draft-ietf-rmcat-gcc-02 section 5.5: the delay-based estimate is
/// decreased "as soon as over-use has been detected", the loss-based one when "more than 10%
/// of the packets have been lost" (section 6); otherwise both "increase the estimate of the
/// available bandwidth".
#[test]
#[ignore = "review harness: the tree's own copy of this test is the one that asserts"]
fn the_estimate_climbs_on_an_open_link_and_never_steps_down() -> Result<()> {
    for seed in seed_range(2, 3) {
        let setup = Setup::new(seed, None).anchor(ANCHORS[0]);
        let outcome = open_link_run(&setup)?;
        println!("open link, ParolNet chain seed {seed}: {outcome:?}");
        assert_the_estimate_climbs(&setup, &outcome, OPEN_LINK_1M_BY);
        for (i, who) in ["caller", "callee"].into_iter().enumerate() {
            assert_eq!(
                None, outcome.target_step_down[i],
                "seed {seed} {who}: the encoder's target stepped down: {outcome:?}"
            );
        }
    }
    Ok(())
}

/// The same call through the engine's default interceptors (GCC in the congestion control
/// interceptor, the pacer, bandwidth probing).
#[test]
#[ignore = "review harness: the tree's own copy of this test is the one that asserts"]
fn the_estimate_climbs_on_an_open_link_in_the_default_chain() -> Result<()> {
    for seed in seed_range(1, 3) {
        let setup = Setup::new(seed, None)
            .chain(Chain::Default)
            .anchor(ANCHORS[0]);
        let outcome = open_link_run(&setup)?;
        println!("open link, default chain seed {seed}: {outcome:?}");
        assert_the_estimate_climbs(&setup, &outcome, OPEN_LINK_1M_BY);
    }
    Ok(())
}

/// When the estimate of an open link has to be at 1 Mbit/s: no later than the estimator of
/// v0.22.0+brainwires.6 was on this call, 15.82 s (hosted run 45331844223; from 300 kbit/s at
/// 8% a second, draft-ietf-rmcat-gcc-02 section 5.5, it is 15.6 s). Measured: 15.47 to
/// 15.52 s without a pacer, 0.37 s in the default chain, whose start-up probes find the
/// open link (run 45334499296).
const OPEN_LINK_1M_BY: Duration = Duration::from_millis(15_820);

#[derive(Debug)]
#[allow(dead_code)] // Read through `Debug`.
struct CameraOutcome {
    /// Per peer: the lowest estimate of the whole call and the first step down of it.
    lowest: [Option<u32>; 2],
    step_down: [Option<(Duration, u32, u32)>; 2],
    /// The caller's estimate when its camera first went on (after five seconds of audio
    /// alone), when it went off, when it came on again five seconds later, and the target
    /// its encoder followed 300 ms after that.
    at_first_on: Option<u32>,
    at_off: Option<u32>,
    at_on_again: Option<u32>,
    target_on_again: u32,
    /// The callee's estimate when its camera went off and at the end, after six seconds of
    /// audio alone.
    callee_at_off: Option<u32>,
    callee_at_end: Option<u32>,
    /// Usable video frames each side decoded.
    usable: [usize; 2],
    /// The lowest target each encoder was given (zero is the pacer's pause) and the lowest
    /// `availableOutgoingBitrate`.
    lowest_target: [Option<u32>; 2],
    lowest_outgoing: [Option<f64>; 2],
}

/// The call of ParolNet's `a_call_gains_and_loses_video_by_renegotiation`, on an open link:
/// five seconds of audio alone, the caller's camera on (a video section by renegotiation),
/// the callee's on five seconds later, the caller's off, then the caller's on again and the
/// callee's off, each five seconds apart, and six seconds more.
fn camera_run(setup: &Setup) -> Result<CameraOutcome> {
    let mut world = World::connected(&setup.audio_only())?;
    world.sampling = true;
    let five = Duration::from_secs(5);
    let t = world.now + five;
    world.advance(t)?;
    let at_first_on = world.peers[0].estimate();
    world.set_video(0, true)?;
    let t = world.now + five;
    world.advance(t)?;
    world.set_video(1, true)?;
    let t = world.now + five;
    world.advance(t)?;
    let at_off = world.peers[0].estimate();
    world.set_video(0, false)?;
    let t = world.now + five;
    world.advance(t)?;
    let at_on_again = world.peers[0].estimate();
    world.set_video(0, true)?;
    let callee_at_off = world.peers[1].estimate();
    world.set_video(1, false)?;
    let on_again = world.elapsed();
    let t = world.now + Duration::from_secs(6);
    world.advance(t)?;
    world.print_trace("camera", setup);
    let peers = &world.peers;
    Ok(CameraOutcome {
        lowest: [0, 1].map(|i| peers[i].estimates.iter().map(|(_, bps)| *bps).min()),
        step_down: [0, 1].map(|i| first_step_down(&peers[i].estimates)),
        at_first_on,
        at_off,
        at_on_again,
        target_on_again: target_at(&peers[0].targets, on_again + Duration::from_millis(300)),
        callee_at_off,
        callee_at_end: peers[1].estimate(),
        usable: [0, 1].map(|i| peers[i].usable_at.len()),
        lowest_target: [0, 1].map(|i| peers[i].targets.iter().map(|(_, bps)| *bps).min()),
        lowest_outgoing: [0, 1].map(|i| peers[i].lowest_outgoing),
    })
}

/// What a call whose cameras go on and off is held to on a link that loses and queues
/// nothing: the estimate never steps down (sending less is no evidence of congestion), so it
/// is never at the floor; it is held while only audio is sent, and the video that comes back
/// starts from the held estimate.
fn assert_the_estimate_is_held(setup: &Setup, outcome: &CameraOutcome) {
    for (i, who) in ["caller", "callee"].into_iter().enumerate() {
        assert_eq!(
            None, outcome.step_down[i],
            "{setup:?} {who}: the estimate stepped down without evidence of congestion: {outcome:?}"
        );
        assert!(
            outcome.lowest[i].is_some_and(|lowest| lowest >= 300_000),
            "{setup:?} {who}: an estimate under the start rate on a perfect link: {outcome:?}"
        );
        assert!(
            outcome.usable[i] > 100,
            "{setup:?} {who}: the other side's video was not seen: {outcome:?}"
        );
        // What the application is told: never a pause (there is no pacer queue to drain),
        // never under the start rate, and in the default chain `availableOutgoingBitrate`
        // says the same.
        assert!(
            outcome.lowest_target[i].is_none_or(|low| low >= 300_000),
            "{setup:?} {who}: a target under the start rate on a perfect link: {outcome:?}"
        );
        if setup.chain != Chain::ParolNet {
            assert!(
                outcome.lowest_outgoing[i].is_some_and(|low| low >= 300_000.0),
                "{setup:?} {who}: availableOutgoingBitrate on a perfect link: {outcome:?}"
            );
        }
    }
    // The start rate, with the one step of 5% the loss-based controller takes on the first
    // receiver report of a call (section 6: "As long as less than 2% of the packets have been
    // lost As_hat(i) will be increased").
    assert!(
        outcome
            .at_first_on
            .is_some_and(|estimate| (300_000..=315_000).contains(&estimate)),
        "{setup:?}: the start rate kept through five seconds of audio alone: {outcome:?}"
    );
    assert!(
        outcome.at_off.is_some_and(|at_off| at_off > 400_000),
        "{setup:?}: the estimate climbed while the video was sent: {outcome:?}"
    );
    assert!(
        outcome.at_on_again >= outcome.at_off,
        "{setup:?}: the estimate was not held while the camera was off: {outcome:?}"
    );
    assert!(
        Some(outcome.target_on_again) >= outcome.at_off,
        "{setup:?}: the video did not start again from the held estimate: {outcome:?}"
    );
    assert!(
        outcome.callee_at_end >= outcome.callee_at_off,
        "{setup:?}: the callee's estimate was not held: {outcome:?}"
    );
}

/// ParolNet's chain: an application-limited sender (audio alone at 76 kbit/s, a camera that
/// is off) keeps its estimate. draft-ietf-rmcat-gcc-02 section 5.5: "if the sender is unable
/// to produce a bit stream with the bitrate the congestion controller is asking for, the
/// available bandwidth estimate should stay within a given bound": the estimate is not
/// increased past 1.5 times the incoming rate; it is decreased when "an over-use is
/// detected" (5.5) or "more than 10% of the packets have been lost" (6), and here neither
/// happens. Before, the estimate was pulled down to 1.5 times the audio (the floor,
/// 100 kbit/s) whenever the video stopped, an application was told of a weak connection on a
/// perfect link, and the video climbed from the floor at 8% a second each time it came back.
#[test]
#[ignore = "review harness: the tree's own copy of this test is the one that asserts"]
fn an_estimate_is_held_while_only_audio_is_sent_and_video_resumes_from_it() -> Result<()> {
    for seed in seed_range(2, 3) {
        let setup = Setup::new(seed, None).anchor(ANCHORS[0]);
        let outcome = camera_run(&setup)?;
        println!("camera, ParolNet chain seed {seed}: {outcome:?}");
        assert_the_estimate_is_held(&setup, &outcome);
    }
    Ok(())
}

/// The same call through the engine's default interceptors.
#[test]
#[ignore = "review harness: the tree's own copy of this test is the one that asserts"]
fn an_estimate_is_held_while_only_audio_is_sent_in_the_default_chain() -> Result<()> {
    for seed in seed_range(1, 3) {
        let setup = Setup::new(seed, None)
            .chain(Chain::Default)
            .anchor(ANCHORS[0]);
        let outcome = camera_run(&setup)?;
        println!("camera, default chain seed {seed}: {outcome:?}");
        assert_the_estimate_is_held(&setup, &outcome);
    }
    Ok(())
}

/// After a path change with a four-second outage the estimate starts over at the start rate
/// and, on a new path that loses and queues nothing, does not go under it: nothing on the
/// new path is evidence of congestion. (ParolNet's
/// `an_ice_restart_follows_a_machine_to_another_network` saw 300 kbit/s at the switch, 100
/// to 110 kbit/s a second later and 200 kbit/s four seconds after the switch.) Both chains.
#[test]
#[ignore = "review harness: the tree's own copy of this test is the one that asserts"]
fn an_estimate_started_over_on_a_new_path_does_not_fall_without_evidence() -> Result<()> {
    for chain in [Chain::ParolNet, Chain::Default] {
        for seed in seed_range(1, 3) {
            let setup = Setup::new(seed, None).chain(chain).anchor(ANCHORS[0]);
            let outcome = path_change_run(&setup)?;
            println!("path change, {chain:?} seed {seed}: {outcome:?}");
            assert_eq!(
                Some(300_000),
                outcome.at_switch,
                "{chain:?} seed {seed}: the estimate starts over at the new pair: {outcome:?}"
            );
            for (i, who) in ["caller", "callee"].into_iter().enumerate() {
                let after: Vec<_> = outcome.estimates[i]
                    .iter()
                    .filter(|(at, _)| *at >= outcome.switched_at)
                    .copied()
                    .collect();
                assert_eq!(
                    None,
                    first_step_down(&after),
                    "{chain:?} seed {seed} {who}: the estimate fell on the new path: {after:?}"
                );
                assert!(
                    after.last().is_some_and(|(_, bps)| *bps > 400_000),
                    "{chain:?} seed {seed} {who}: no climb in ten seconds: {after:?}"
                );
            }
        }
    }
    Ok(())
}

// ===================== review-cap ensemble (independent review harness) =====================

thread_local! {
    static REVIEW_RNG: Cell<u64> = const { Cell::new(1) };
}

/// Whether a datagram on the reverse path (the callee's uplink: its media and all its
/// feedback) is lost: `REVIEW_REV_LOSS_PCT` per cent, from a generator seeded per run.
fn review_reverse_loss() -> bool {
    let Some(pct) = review_knob("REVIEW_REV_LOSS_PCT").filter(|p| *p > 0) else {
        return false;
    };
    REVIEW_RNG.with(|r| {
        let mut rng = Rng(r.get());
        let draw = rng.next_u64();
        r.set(rng.0);
        draw % 100 < pct
    })
}

thread_local! {
    /// Video datagrams of the caller's uplink still to drop in the current burst.
    static REVIEW_BURST: Cell<u32> = const { Cell::new(0) };
}

fn review_burst_drop(video: bool) -> bool {
    video
        && REVIEW_BURST.with(|left| {
            let n = left.get();
            if n > 0 {
                left.set(n - 1);
            }
            n > 0
        })
}

/// An open link that loses a burst of `REVIEW_BURST` (12) consecutive video datagrams every
/// 2 s, ten times from 20 s on: no capacity change, the loss a wireless link has.
fn review_burst_one(chain: &str, seed: u64) -> Result<String> {
    let chain_kind = match chain {
        "parolnet" => Chain::ParolNet,
        "default" => Chain::Default,
        "nopacer" => Chain::DefaultWithoutPacer,
        other => bail!("unknown chain {other}"),
    };
    let setup = Setup::new(seed, None).chain(chain_kind).anchor(ANCHORS[0]);
    let burst = review_knob("REVIEW_BURST").unwrap_or(12) as u32;
    let mut world = World::connected(&setup)?;
    let t = world.now + Duration::from_secs(20);
    world.advance(t)?;
    let before = target_at(&world.peers[0].targets, world.elapsed());
    let from = world.elapsed();
    for _ in 0..10 {
        REVIEW_BURST.with(|left| left.set(burst));
        let t = world.now + Duration::from_secs(2);
        world.advance(t)?;
    }
    let to = world.elapsed();
    let t = world.now + Duration::from_secs(3);
    world.advance(t)?;
    let end = world.elapsed();
    let caller = &world.peers[0];
    let callee = &world.peers[1];
    let (freeze, _) = longest_gap(&callee.usable_at, from, end);
    let frames: Vec<(Duration, Duration)> = callee
        .usable_at
        .iter()
        .zip(&callee.usable_lag)
        .map(|(at, lag)| (*at, at.saturating_sub(*lag)))
        .collect();
    let mut max_age = Duration::ZERO;
    let mut stale = [Duration::ZERO; 3];
    let mut gaps = Vec::new();
    for (i, (shown, captured)) in frames.iter().enumerate() {
        let until = frames.get(i + 1).map_or(end, |next| next.0);
        if until < from {
            continue;
        }
        max_age = max_age.max(until - *captured);
        if until - *shown > Duration::from_millis(100) {
            gaps.push((until - *shown).as_millis() as u64);
        }
        for (limit, total) in [200u64, 500, 1000].into_iter().zip(stale.iter_mut()) {
            let start = (*shown)
                .max(*captured + Duration::from_millis(limit))
                .max(from);
            if until > start {
                *total += until - start;
            }
        }
    }
    gaps.sort_unstable();
    let targets: Vec<u32> = (0..=((to - from).as_millis() as u64 / 100))
        .map(|i| target_at(&caller.targets, from + Duration::from_millis(i * 100)))
        .collect();
    let mean_target = targets.iter().map(|b| u64::from(*b)).sum::<u64>() / targets.len() as u64;
    let min_target = targets.iter().copied().min().unwrap_or(0);
    let link = &world.uplinks[0];
    Ok(format!(
        "BROW chain {chain} seed {seed} | before {} | freeze {:.3} max_age {:.3} stale200 {:.3} stale500 {:.3} stale1000 {:.3} | gaps_over_100ms {} median_gap {} | rtx {} | pli {} unusable {} | mean_target {} min_target {} end_target {}",
        before / 1000,
        freeze.as_secs_f64(),
        max_age.as_secs_f64(),
        stale[0].as_secs_f64(),
        stale[1].as_secs_f64(),
        stale[2].as_secs_f64(),
        gaps.len(),
        gaps.get(gaps.len() / 2).copied().unwrap_or(0),
        link.rtx_sent,
        callee.keyframe_requests.len(),
        callee.unusable,
        mean_target / 1000,
        min_target / 1000,
        target_at(&caller.targets, end) / 1000,
    ))
}

fn review_knob(name: &str) -> Option<u64> {
    std::env::var(name).ok().and_then(|v| v.trim().parse().ok())
}

/// The receiver's sample builder: the test's (256 packets, no time bound), or with a wall-clock
/// bound on a gap (`REVIEW_GAP_WAIT_MS`).
fn review_builder() -> SampleBuilder<Vp8Packet> {
    let builder = SampleBuilder::new(256, Vp8Packet::default(), 90_000);
    match review_knob("REVIEW_GAP_WAIT_MS").filter(|ms| *ms > 0) {
        Some(ms) => builder.with_max_gap_wait(Duration::from_millis(ms)),
        None => builder,
    }
}

/// Pops what the builder has (a gap given up for its time bound included) outside a packet's
/// arrival.
fn review_drain(peer: &mut Peer, now: Instant, at: Duration) -> Result<()> {
    while let Some(sample) = peer.builder.pop(now) {
        match peer.decoder.accept(&sample.data) {
            Some(true) => {
                peer.usable_at.push(at);
                let data = &sample.data;
                let captured = u32::from_be_bytes([
                    0,
                    data[VideoModel::HEADER],
                    data[VideoModel::HEADER + 1],
                    data[VideoModel::HEADER + 2],
                ]);
                peer.usable_lag.push(
                    at.saturating_sub(Duration::from_millis(u64::from(captured) * 10)),
                );
            }
            Some(false) => peer.unusable += 1,
            None => {}
        }
    }
    if peer.video_receiver.is_some()
        && !peer.usable_at.is_empty()
        && peer.decoder.last.is_none()
        && peer
            .last_keyframe_request
            .is_none_or(|t| now.duration_since(t) >= Duration::from_secs(1))
    {
        peer.last_keyframe_request = Some(now);
        peer.keyframe_requests.push(at);
        peer.request_keyframe(now)?;
    }
    Ok(())
}

fn review_one(chain: &str, seed: u64, offset_ms: u64) -> Result<String> {
    let started = std::time::Instant::now();
    let chain_kind = match chain {
        "parolnet" => Chain::ParolNet,
        "default" => Chain::Default,
        "nopacer" => Chain::DefaultWithoutPacer,
        other => bail!("unknown chain {other}"),
    };
    let rule = match std::env::var("REVIEW_RULE").ok().as_deref() {
        Some("within") => Some(RetransmissionRateLimit::WithinTarget),
        Some("upto") => Some(RetransmissionRateLimit::UpToTarget),
        Some("unlimited") => Some(RetransmissionRateLimit::Unlimited),
        _ => None,
    };
    let setup = Setup::new(seed, rule).chain(chain_kind).anchor(ANCHORS[0]);
    REVIEW_RNG.with(|r| r.set(seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) ^ 0xfeed_beef));
    let queue_ms = review_knob("REVIEW_QUEUE_MS").unwrap_or(300);
    let cap_bps = review_knob("REVIEW_CAP_KBPS").unwrap_or(300) * 1000;
    let symmetric = review_knob("REVIEW_SYMMETRIC").unwrap_or(0) != 0;
    let capped = LinkProfile {
        delay: Duration::from_millis(30),
        rate_bps: Some(cap_bps),
        queue: Duration::from_millis(queue_ms),
    };
    let mut world = World::connected(&setup)?;
    let t = world.now + Duration::from_secs(20) + Duration::from_millis(offset_ms);
    world.advance(t)?;
    let before = target_at(&world.peers[0].targets, world.elapsed());
    let estimate_before = world.peers[0].estimate().unwrap_or(0);
    world.sampling = true;
    world.uplinks[0].set_profile(capped);
    if symmetric {
        world.uplinks[1].set_profile(capped);
    }
    let capped_at = world.elapsed();
    let mut reacted = None;
    while world.elapsed() < capped_at + Duration::from_secs(5) {
        if target_at(&world.peers[0].targets, world.elapsed()) < 400_000 {
            reacted = Some(world.elapsed() - capped_at);
            break;
        }
        let t = world.now + Duration::from_millis(10);
        world.advance(t)?;
    }
    let Some(reacted) = reacted else {
        bail!("the estimate did not come down within 5 s");
    };
    let t = world.now + Duration::from_secs(20);
    world.advance(t)?;
    let mut samples = Vec::new();
    let mut at = capped_at + Duration::from_secs(8);
    while at <= world.elapsed() {
        samples.push(target_at(&world.peers[0].targets, at));
        at += Duration::from_millis(100);
    }
    samples.sort_unstable();
    let under = samples[samples.len() / 2];
    let (rtx_cap, rtxd_cap, drops_cap, audio_cap) = {
        let l = &world.uplinks[0];
        (l.rtx_sent, l.rtx_dropped, l.queue_drops, l.audio_dropped)
    };
    world.uplinks[0].set_profile(LinkProfile::open());
    if symmetric {
        world.uplinks[1].set_profile(LinkProfile::open());
    }
    let opened_at = world.elapsed();
    let target_at_lift = target_at(&world.peers[0].targets, opened_at);
    let t = world.now + Duration::from_secs(25);
    world.advance(t)?;
    let end = world.elapsed();
    let window: Vec<u32> = (150..=250)
        .map(|tenths| {
            target_at(
                &world.peers[0].targets,
                opened_at + Duration::from_millis(tenths * 100),
            )
        })
        .collect();
    let window_mean =
        (window.iter().map(|bps| u64::from(*bps)).sum::<u64>() / window.len() as u64) as u32;
    let caller = &world.peers[0];
    let callee = &world.peers[1];
    let first_cut = caller
        .estimates
        .iter()
        .find(|(at, bps)| *at >= capped_at && u64::from(*bps) * 100 < u64::from(estimate_before) * 99)
        .map(|(at, _)| *at - capped_at);
    let under_cap_at = caller
        .estimates
        .iter()
        .find(|(at, bps)| *at >= capped_at && u64::from(*bps) <= cap_bps)
        .map(|(at, _)| *at - capped_at);
    let (freeze, freeze_at) = longest_gap(&callee.usable_at, Duration::from_secs(2), end);
    let (freeze_cap, freeze_cap_at) = longest_gap(&callee.usable_at, capped_at, opened_at);
    let (freeze_lift, _) = longest_gap(&callee.usable_at, opened_at, end);
    let lag = callee
        .usable_at
        .iter()
        .zip(&callee.usable_lag)
        .filter(|(at, _)| **at >= capped_at)
        .map(|(_, lag)| *lag)
        .max()
        .unwrap_or_default();
    // What is on the screen: the last usable frame, until the next one. Its age at an instant
    // is that instant less its capture.
    let frames: Vec<(Duration, Duration)> = callee
        .usable_at
        .iter()
        .zip(&callee.usable_lag)
        .map(|(at, lag)| (*at, at.saturating_sub(*lag)))
        .collect();
    let mut max_age = Duration::ZERO;
    let mut stale = [Duration::ZERO; 2];
    let mut caught_up = None;
    for (i, (shown, captured)) in frames.iter().enumerate() {
        let until = frames.get(i + 1).map_or(end, |next| next.0);
        if until < capped_at {
            continue;
        }
        max_age = max_age.max(until - *captured);
        for (limit, total) in [1u64, 2].into_iter().zip(stale.iter_mut()) {
            let from = (*shown)
                .max(*captured + Duration::from_secs(limit))
                .max(capped_at);
            if until > from {
                *total += until - from;
            }
        }
        // The last instant a frame older than 500 ms came out.
        if *shown >= capped_at && *shown < opened_at && *shown - *captured > Duration::from_millis(500) {
            caught_up = Some(*shown - capped_at);
        }
    }
    let mut pauses = 0;
    let mut paused = Duration::ZERO;
    let mut started_pause = None;
    for &(at, bps) in &caller.targets {
        match (started_pause, bps) {
            (None, 0) => started_pause = Some(at),
            (Some(from), bps) if bps > 0 => {
                pauses += 1;
                paused += at - from;
                started_pause = None;
            }
            _ => {}
        }
    }
    let link = &world.uplinks[0];
    if review_knob("REVIEW_TRACE").is_some_and(|v| v != 0) {
        let from = capped_at.saturating_sub(Duration::from_millis(300)).as_secs_f64();
        let to = (capped_at + Duration::from_secs(review_knob("REVIEW_TRACE_SECS").unwrap_or(11))).as_secs_f64();
        for line in &world.trace {
            let at: f64 = line.split_whitespace().next().and_then(|t| t.parse().ok()).unwrap_or(0.0);
            if at >= from && at <= to {
                println!("RTRACE {chain} seed {seed} {line}");
            }
        }
        println!("RTRACE {chain} seed {seed} targets {:?}", caller.targets.iter().filter(|(at, _)| *at >= capped_at && *at <= capped_at + Duration::from_secs(12)).map(|(at, bps)| (at.as_millis(), bps / 1000)).collect::<Vec<_>>());
        println!("RTRACE {chain} seed {seed} keyframes {:?} pli {:?}", caller.keyframes_sent, callee.keyframe_requests);
    }
    Ok(format!(
        "RROW chain {chain} seed {seed} offset {offset_ms} | before {} est {} cap_at {:.2} | first_cut {:.3} under_cap {:.3} reacted {:.2} | freeze {:.3} at {:.2} freeze_cap {:.3} at {:.2} freeze_lift {:.3} | lag {:.3} max_age {:.3} stale1 {:.3} stale2 {:.3} caught_up {:.2} | rtx {} dropped {} rtx_cap {} dropped {} | qdrops {} qdrops_cap {} audio {} audio_cap {} padding {} dropped {} | pacer_discards {} pauses {} paused {:.2} | pli {} keyframes {} unusable {} | under {} lift {} window {} | wall {:.1}",
        before / 1000,
        estimate_before / 1000,
        capped_at.as_secs_f64(),
        first_cut.map_or(-1.0, |d| d.as_secs_f64()),
        under_cap_at.map_or(-1.0, |d| d.as_secs_f64()),
        reacted.as_secs_f64(),
        freeze.as_secs_f64(),
        freeze_at.as_secs_f64(),
        freeze_cap.as_secs_f64(),
        freeze_cap_at.as_secs_f64(),
        freeze_lift.as_secs_f64(),
        lag.as_secs_f64(),
        max_age.as_secs_f64(),
        stale[0].as_secs_f64(),
        stale[1].as_secs_f64(),
        caught_up.map_or(-1.0, |d| d.as_secs_f64()),
        link.rtx_sent,
        link.rtx_dropped,
        rtx_cap,
        rtxd_cap,
        link.queue_drops,
        drops_cap,
        link.audio_dropped,
        audio_cap,
        link.padding_sent,
        link.padding_dropped,
        caller.pacer_discards.len(),
        pauses,
        paused.as_secs_f64(),
        callee.keyframe_requests.len(),
        caller.keyframes_sent.len(),
        callee.unusable,
        under / 1000,
        target_at_lift / 1000,
        window_mean / 1000,
        started.elapsed().as_secs_f64(),
    ))
}

/// The ensemble: `REVIEW_CHAINS` (default,nopacer), seeds `REVIEW_SEED_LO..=REVIEW_SEED_HI`,
/// `REVIEW_OFFSETS` (ms added to the 20 s before the cap), on `REVIEW_THREADS` threads.
#[test]
#[ignore = "review measurement"]
fn review_ensemble() -> Result<()> {
    let lo = review_knob("REVIEW_SEED_LO").unwrap_or(1);
    let hi = review_knob("REVIEW_SEED_HI").unwrap_or(6);
    let threads = review_knob("REVIEW_THREADS").unwrap_or(4).max(1) as usize;
    let list = |name: &str, default: &str| -> Vec<String> {
        std::env::var(name)
            .unwrap_or_else(|_| default.to_owned())
            .split(',')
            .map(|item| item.trim().to_owned())
            .filter(|item| !item.is_empty())
            .collect()
    };
    let mut jobs = Vec::new();
    for chain in list("REVIEW_CHAINS", "default,nopacer") {
        for offset in list("REVIEW_OFFSETS", "0") {
            for seed in lo..=hi {
                jobs.push((chain.clone(), seed, offset.parse::<u64>()?));
            }
        }
    }
    let jobs = Arc::new(Mutex::new(jobs));
    let workers: Vec<_> = (0..threads)
        .map(|_| {
            let jobs = jobs.clone();
            std::thread::spawn(move || {
                loop {
                    let job = jobs.lock().unwrap().pop();
                    let Some((chain, seed, offset)) = job else {
                        break;
                    };
                    let outcome = if std::env::var("REVIEW_SCENARIO").ok().as_deref() == Some("burst") {
                        review_burst_one(&chain, seed)
                    } else {
                        review_one(&chain, seed, offset)
                    };
                    match outcome {
                        Ok(row) => println!(
                            "{row} | tag {}",
                            std::env::var("REVIEW_TAG").unwrap_or_else(|_| "-".to_owned())
                        ),
                        Err(error) => println!(
                            "RROW chain {chain} seed {seed} offset {offset} | failed: {error}"
                        ),
                    }
                }
            })
        })
        .collect();
    for worker in workers {
        worker.join().map_err(|_| anyhow::anyhow!("a worker panicked"))?;
    }
    Ok(())
}
