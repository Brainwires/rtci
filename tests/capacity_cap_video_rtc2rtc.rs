//! A video call between two `rtc` peer connections whose path drops to 300 kbit/s for twenty
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
//! the receiving side, and the estimate twenty seconds after the cap went.

use anyhow::{Result, bail};
use bytes::Bytes;
use rtc::crypto::{CryptoError, RTCCrypto, RTCCryptoProvider, RTCRandom, default_provider};
use rtc::interceptor::{
    GccHandle, GccInterceptorBuilder, Interceptor as _, NackGeneratorBuilder, NackResponderBuilder,
    PassThroughInterceptor, Registry, RetransmissionRateLimit, RtcpRandom, RtcpSessionBuilder,
    Slot,
};
use rtc::media::io::sample_builder::SampleBuilder;
use rtc::media_stream::MediaStreamTrack;
use rtc::peer_connection::configuration::RTCConfigurationBuilder;
use rtc::peer_connection::configuration::interceptor_registry::{
    DefaultInterceptorHandles, DefaultInterceptorOptions, configure_key_frame_requests,
    configure_nack, configure_receiver_reference_time, configure_rtcp_reports_with, configure_twcc,
    register_default_interceptors_with_options,
};
use rtc::peer_connection::configuration::media_engine::{
    MIME_TYPE_OPUS, MIME_TYPE_RTX, MIME_TYPE_VP8, MediaEngine,
};
use rtc::peer_connection::configuration::setting_engine::SettingEngineBuilder;
use rtc::peer_connection::event::{RTCPeerConnectionEvent, RTCTrackEvent};
use rtc::peer_connection::message::RTCMessage;
use rtc::peer_connection::state::RTCPeerConnectionState;
use rtc::peer_connection::transport::{
    CandidateConfig, CandidateHostConfig, RTCIceCandidate, RTCIceCandidateInit,
};
use rtc::peer_connection::{RTCPeerConnection, RTCPeerConnectionBuilder};
use rtc::rtcp::payload_feedbacks::full_intra_request::FullIntraRequest;
use rtc::rtcp::payload_feedbacks::picture_loss_indication::PictureLossIndication;
use rtc::rtp::codec::vp8::Vp8Packet;
use rtc::rtp::packetizer::Packetizer;
use rtc::rtp_transceiver::rtp_sender::{
    RTCPFeedback, RTCRtpCodec, RTCRtpCodecParameters, RTCRtpCodingParameters,
    RTCRtpEncodingParameters, RTCRtpRtxParameters, RtpCodecKind,
};
use rtc::rtp_transceiver::{RTCRtpReceiverId, RTCRtpSenderId};
use rtc::sansio::Protocol;
use rtc::shared::{TaggedBytesMut, TransportContext, TransportProtocol};
use std::cell::Cell;
use std::collections::BTreeSet;
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
    /// Whether the next `World`'s peers use the engine's default interceptors (the pacer, GCC
    /// on transport-wide feedback, the NACK pair) with the video following the target the
    /// senders are given (`RTCRtpSender::target_bitrates`), instead of ParolNet's chain.
    static DEFAULT_CHAIN: Cell<bool> = const { Cell::new(false) };
}

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
    rtx_sent: u64,
    rtx_dropped: u64,
    audio_dropped: u64,
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
            audio_dropped: 0,
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
    audio: RTCRtpSenderId,
    video: RTCRtpSenderId,
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
    unusable: u64,
    last_keyframe_request: Option<Instant>,
    keyframe_requests: Vec<Duration>,
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

impl Peer {
    /// A peer with ParolNet's media engine and interceptor chain, sending Opus and VP8; its
    /// NACK responder holds retransmissions to `rate_limit`, the engine's default when `None`.
    fn new(
        addr: &str,
        seed: u64,
        ssrc_base: u32,
        rate_limit: Option<RetransmissionRateLimit>,
    ) -> Result<Self> {
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
        if DEFAULT_CHAIN.with(|d| d.get()) {
            let mut options = DefaultInterceptorOptions::default();
            options.rtcp_random = Some(provider.clone());
            let (registry, handles) = register_default_interceptors_with_options(
                Registry::new(),
                &mut media_engine,
                &options,
            )?;
            return Self::with_chain(
                addr,
                provider,
                media_engine,
                registry,
                ssrc_base,
                None,
                Some(handles),
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
        let registry = configure_rtcp_reports_with(
            registry,
            RtcpSessionBuilder::new()
                .with_t_rr_interval(Duration::ZERO)
                .with_random(SeededRtcpRandom(Rng(seed ^ 0x5eed))),
        );
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
            Some(handle),
            None,
        )
    }

    fn with_chain(
        addr: &str,
        provider: Arc<dyn RTCCryptoProvider>,
        media_engine: MediaEngine,
        registry: Registry,
        ssrc_base: u32,
        gcc: Option<GccHandle>,
        handles: Option<DefaultInterceptorHandles>,
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
            .build(Instant::now())?;
        let audio = pc.add_track(track(RtpCodecKind::Audio, opus_codec(), ssrc_base, None))?;
        let video = pc.add_track(track(
            RtpCodecKind::Video,
            video_codec(),
            ssrc_base + 1,
            Some(ssrc_base + 2),
        ))?;
        Ok(Self {
            pc,
            addr: addr.parse()?,
            connected: false,
            gcc,
            handles,
            video_written: BTreeSet::new(),
            video_left: BTreeSet::new(),
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
            builder: SampleBuilder::new(256, Vp8Packet::default(), 90_000),
            decoder: ModelDecoder::default(),
            usable_at: Vec::new(),
            unusable: 0,
            last_keyframe_request: None,
            keyframe_requests: Vec::new(),
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
        let id = if video { self.video } else { self.audio };
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
            *packetizer = Some(Box::new(rtc::rtp::packetizer::new_packetizer(
                now,
                RTP_MTU,
                codec.payload_type,
                ssrc,
                codec.rtp_codec.payloader()?,
                Box::new(rtc::rtp::sequence::new_fixed_sequencer(
                    (ssrc as u16).wrapping_mul(7),
                )),
                codec.rtp_codec.clock_rate,
            )));
        }
        let Some(packetizer) = packetizer.as_mut() else {
            return Ok(());
        };
        for packet in packetizer.packetize(now, &Bytes::copy_from_slice(data), samples)? {
            if video {
                self.video_written.insert(packet.header.sequence_number);
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
        for id in [self.audio, self.video] {
            if let Some(sender) = self.pc.rtp_sender(id) {
                total += sender
                    .target_bitrates()
                    .iter()
                    .map(|(_, bps)| bps)
                    .sum::<f64>();
            }
        }
        (total > 0.0).then_some(total as u32)
    }

    /// The congestion controller's estimate itself.
    fn estimate(&self) -> Option<u32> {
        match (&self.gcc, &self.handles) {
            (Some(gcc), _) => gcc.estimate_bps(),
            (None, Some(handles)) => Some(handles.congestion_control.target_bitrate() as u32),
            _ => None,
        }
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
    /// Every 100 ms: time, the caller's estimate, its uplink's queue and drops, the
    /// retransmissions it sent and lost there, the callee's usable frames so far. Printed
    /// with `RTC_CAP_TRACE=1`.
    trace: Vec<String>,
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
                    let arrives = self.uplinks[i].send(self.now, msg.message.len());
                    if payload_type == Some(RTX_PT) {
                        self.uplinks[i].rtx_sent += 1;
                        self.uplinks[i].rtx_dropped += u64::from(arrives.is_none());
                    }
                    if payload_type == Some(OPUS_PT) {
                        self.uplinks[i].audio_dropped += u64::from(arrives.is_none());
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
                            Some(true) => peer.usable_at.push(at),
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
            for peer in self.peers.iter_mut() {
                let key = std::mem::take(&mut peer.force_key);
                let frame = peer
                    .model
                    .next_frame(video_bitrate_for(peer.target_bps), key);
                if key {
                    peer.keyframes_sent.push(at);
                }
                peer.send_frame(now, true, &frame, 90_000 / VIDEO_FPS)?;
            }
        }
        if now >= self.next_target {
            self.next_target += Duration::from_millis(100);
            let link = &self.uplinks[0];
            self.trace.push(format!(
                "{:6.1} target {:7} estimate {:7} queue {:3} ms drops {:5} audio {:4} rtx {:5}/{:5} lost usable {:5} unusable {:4}",
                at.as_secs_f64(),
                self.peers[0].target_bps,
                self.peers[0].estimate().unwrap_or(0),
                link.busy_until
                    .map_or(0, |t| t.saturating_duration_since(now).as_millis()),
                link.queue_drops,
                link.audio_dropped,
                link.rtx_sent,
                link.rtx_dropped,
                self.peers[1].usable_at.len(),
                self.peers[1].unusable,
            ));
            for peer in self.peers.iter_mut() {
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
            self.now = next.max(self.now).min(to);
            for peer in self.peers.iter_mut() {
                peer.pc.handle_timeout(self.now)?;
            }
            self.tick()?;
            self.pump()?;
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

    /// Two peers over host candidates, audio and video each way, connected.
    fn connected(seed: u64, rate_limit: Option<RetransmissionRateLimit>) -> Result<Self> {
        let start = Instant::now();
        let mut world = World {
            peers: [
                Peer::new("10.0.0.1:5000", seed ^ 0x1111, 0x1000_0000, rate_limit)?,
                Peer::new("10.0.0.2:5000", seed ^ 0x2222, 0x2000_0000, rate_limit)?,
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
            trace: Vec::new(),
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
        for i in 0..2 {
            let candidate = world.peers[i].candidate()?;
            world.peers[i].pc.add_local_candidate(candidate.clone())?;
            world.peers[1 - i].pc.add_remote_candidate(candidate)?;
        }
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
    /// The longest freeze of the callee's video, and when it began.
    freeze: Duration,
    freeze_at: Duration,
    capped_at: Duration,
    opened_at: Duration,
    keyframe_requests: Vec<Duration>,
    queue_drops: u64,
    rtx_sent: u64,
    rtx_dropped: u64,
    /// Opus packets dropped at the capped link's queue.
    audio_dropped: u64,
    /// Video packets the caller's application wrote that never left its host.
    pacer_dropped: usize,
    unusable: u64,
}

/// The call: 20 s open, the caller's uplink capped at 300 kbit/s until 20 s after its
/// estimate went under 400 kbit/s, then open again for 20 s.
fn run(seed: u64, rate_limit: Option<RetransmissionRateLimit>) -> Result<Outcome> {
    let mut world = World::connected(seed, rate_limit)?;
    let t = world.now + Duration::from_secs(20);
    world.advance(t)?;
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
    world.uplinks[0].set_profile(LinkProfile::open());
    let opened_at = world.elapsed();
    let t = world.now + Duration::from_secs(20);
    world.advance(t)?;
    let end = world.elapsed();
    let after = target_at(&world.peers[0].targets, end);
    let estimate_after = world.peers[0].estimate().unwrap_or(0);
    let caller = &world.peers[0];
    let pacer_dropped = caller.video_written.difference(&caller.video_left).count();
    if std::env::var("RTC_CAP_TRACE").is_ok() {
        for line in &world.trace {
            println!("TRACE seed {seed} {line}");
        }
    }
    let callee = &world.peers[1];
    let (freeze, freeze_at) = longest_gap(&callee.usable_at, Duration::from_secs(2), end);
    Ok(Outcome {
        before,
        reacted,
        under,
        after,
        estimate_after,
        freeze,
        freeze_at,
        capped_at,
        opened_at,
        keyframe_requests: callee.keyframe_requests.clone(),
        queue_drops: world.uplinks[0].queue_drops,
        rtx_sent: world.uplinks[0].rtx_sent,
        rtx_dropped: world.uplinks[0].rtx_dropped,
        audio_dropped: world.uplinks[0].audio_dropped,
        pacer_dropped,
        unusable: callee.unusable,
    })
}

/// The six seeds under `rate_limit` (`None`: the engine's default), each outcome printed.
fn seeds(rate_limit: Option<RetransmissionRateLimit>) -> Result<Vec<(u64, Outcome)>> {
    let mut outcomes = Vec::new();
    for seed in 1..=6 {
        let outcome = run(seed, rate_limit)?;
        println!("{rate_limit:?} seed {seed}: {outcome:?}");
        outcomes.push((seed, outcome));
    }
    Ok(outcomes)
}

/// Never more than 2 s without a usable frame on the receiving side, and the retransmissions
/// congestion controlled (RFC 4588 section 7): at most 100 sent through the cap, on every seed
/// (the rules held to the target sent 61 to 70, 11 to 14 of them dropped at the link's queue;
/// without a limit 257 to 367 were sent and three in four dropped).
fn assert_no_long_freeze(outcomes: &[(u64, Outcome)]) {
    for (seed, outcome) in outcomes {
        assert!(
            outcome.freeze <= Duration::from_secs(2),
            "seed {seed}: the video froze for {:?}: {outcome:?}",
            outcome.freeze
        );
        assert!(
            outcome.rtx_sent <= 100,
            "seed {seed}: {} retransmissions: {outcome:?}",
            outcome.rtx_sent
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
/// When the cap comes, the sender is still at 1.4 Mbit/s for half a second and some fifty
/// video packets are dropped at the link's queue. With the release's NACK request policy (ten
/// requests or two seconds, then a packet is given up) and retransmissions that nothing held
/// to the estimate (about 300, five times the link, three in four of them dropped at the same
/// queue), some of those packets were given up, stayed lost, the sample builder held every
/// later frame back for its 256 packets and the picture froze until a key frame. Now a packet
/// is asked for while it is missing, the retransmissions stay within the estimate, and the
/// encoder leaves them room.
///
/// Not asserted: the estimate 20 s after the cap went (`estimate_after` in the output). In
/// ParolNet's simulation v0.22.0+brainwires.5 was at 1.18 Mbit/s there; here it depends on
/// the seed: GCC climbs from its floor at 8% a second, and when it has reached the capacity
/// again before the cap goes, the loss at the overflowing queue cuts it back to the floor on
/// every feedback (draft-ietf-rmcat-gcc-02 section 6) just before the path opens.
#[test]
fn video_keeps_playing_through_a_capacity_cap_that_comes_and_goes() -> Result<()> {
    assert_no_long_freeze(&seeds(None)?);
    Ok(())
}

/// The same call with libwebrtc's retransmission rule
/// ([`RetransmissionRateLimit::UpToTarget`]: the retransmissions alone under the target, the
/// encoder's target not lowered), the `Chrome` and `Performance` profiles' setting.
#[test]
fn video_keeps_playing_through_a_capacity_cap_with_retransmissions_up_to_the_target() -> Result<()>
{
    assert_no_long_freeze(&seeds(Some(RetransmissionRateLimit::UpToTarget))?);
    Ok(())
}

/// The same call with retransmissions not congestion controlled
/// ([`RetransmissionRateLimit::Unlimited`]), for comparison: prints the outcomes, asserts
/// nothing.
#[test]
#[ignore = "measurement: run with --ignored --nocapture"]
fn measure_unlimited_retransmissions_through_a_capacity_cap() -> Result<()> {
    seeds(Some(RetransmissionRateLimit::Unlimited))?;
    Ok(())
}

/// The same call through the engine's default interceptors (the pacer with its default
/// `PacerQueueOverflow::Drop`, GCC on transport-wide feedback, the NACK pair with the RFC 4588
/// section 7 default), the video following the target the senders are given
/// (`RTCRtpSender::target_bitrates`, lowered by the retransmission reserve while repairs wait):
/// an application that follows the target never has a packet dropped by the pacer, on three
/// seeds, and the video does not freeze for more than 2 s.
#[test]
fn a_sender_following_the_lowered_target_loses_nothing_at_the_pacer() -> Result<()> {
    DEFAULT_CHAIN.with(|d| d.set(true));
    let outcomes: Result<Vec<_>> = (1..=3)
        .map(|seed| {
            let outcome = run(seed, None)?;
            println!("default chain seed {seed}: {outcome:?}");
            Ok((seed, outcome))
        })
        .collect();
    DEFAULT_CHAIN.with(|d| d.set(false));
    let outcomes = outcomes?;
    for (seed, outcome) in &outcomes {
        assert_eq!(0, outcome.pacer_dropped, "seed {seed}: {outcome:?}");
        assert!(
            outcome.freeze <= Duration::from_secs(2),
            "seed {seed}: the video froze for {:?}: {outcome:?}",
            outcome.freeze
        );
    }
    Ok(())
}
