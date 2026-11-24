//! The send pipeline end to end, in virtual time: a camera-like source (640x360, 30 fps) through
//! `rtc_video::engine::VideoSender` with the pure-Rust VP8 encoder (feature `vp8`), the
//! engine's default interceptors on both peers (the pacer, GCC on transport-wide feedback, the
//! NACK pair, RTX), a simulated uplink, and on the far side `VideoReceiver` with the VP8
//! decoder, each picture "rendered" at its render time.
//!
//! The uplink is the network model of the engine's `tests/capacity_cap_video_rtc2rtc.rs`: a
//! fixed one-way delay (10 ms open), and when capped one datagram at a time at 300 kbit/s
//! behind a drop-tail queue of 300 ms with 30 ms one way; for the loss scenario it also drops
//! datagrams at random and delays them by a uniform jitter (and so reorders them), as the
//! receive pipeline's `tests/receive_rtc2rtc.rs`. RTCP from the receiver comes back after the
//! one-way delay, unimpaired.
//!
//! What is asserted is what a viewer sees (the longest time between rendered pictures, the
//! oldest picture shown: capture to render), what the sender does with the engine's signals
//! (its encoded rate against the target, no picture encoded in a pause, a key frame when it
//! ends, no frame discarded by the pacer, the key-frame requests served), and the integrity of
//! the pictures (the VP8 decoder decodes every picture released, close to its source).
//! `MEASURE` lines print every figure (`--nocapture`).

use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Result, anyhow, bail};
use bytes::BytesMut;
use rtc::crypto::{CryptoError, RTCCrypto, RTCCryptoProvider, RTCRandom, default_provider};
use rtc::interceptor::Registry;
use rtc::media_stream::MediaStreamTrack;
use rtc::peer_connection::configuration::RTCConfigurationBuilder;
use rtc::peer_connection::configuration::interceptor_registry::{
    DefaultInterceptorHandles, DefaultInterceptorOptions,
    register_default_interceptors_with_options,
};
use rtc::peer_connection::configuration::media_engine::{
    MIME_TYPE_RTX, MIME_TYPE_VP8, MediaEngine,
};
use rtc::peer_connection::configuration::setting_engine::SettingEngineBuilder;
use rtc::peer_connection::event::{RTCPeerConnectionEvent, RTCTrackEvent};
use rtc::peer_connection::message::RTCMessage;
use rtc::peer_connection::state::RTCPeerConnectionState;
use rtc::peer_connection::transport::{
    CandidateConfig, CandidateHostConfig, RTCIceCandidate, RTCIceCandidateInit,
};
use rtc::peer_connection::{RTCPeerConnection, RTCPeerConnectionBuilder};
use rtc::rtp_transceiver::rtp_sender::{
    RTCPFeedback, RTCRtpCodec, RTCRtpCodecParameters, RTCRtpCodingParameters,
    RTCRtpEncodingParameters, RTCRtpRtxParameters, RtpCodecKind,
};
use rtc::rtp_transceiver::{RTCRtpReceiverId, RTCRtpSenderId};
use rtc::sansio::Protocol;
use rtc::shared::time::SystemInstant;
use rtc::shared::{TaggedBytesMut, TransportContext, TransportProtocol};
use rtc_video::codec::vp8::{Vp8Decoder, Vp8Encoder};
use rtc_video::decoder::{DecodeError, VideoDecoder};
use rtc_video::encoder::{EncodeError, VideoEncoder};
use rtc_video::engine::{RtpStart, VideoReceiver, VideoSender};
use rtc_video::picture::{I420Buffer, TestSource, psnr};
use rtc_video::send::{FrameOutcome, KeyFrameDecision, SendConfig, SendStats};
use rtc_video::stats::ReceiveStats;
use rtc_video::{DecodeOutcome, ReceiveConfig};

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

    fn unit(&mut self) -> f64 {
        (self.next_u64() >> 11) as f64 / (1u64 << 53) as f64
    }
}

/// The built-in crypto provider with its random source replaced by a seeded [`Rng`].
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

const VP8_PT: u8 = 96;
const RTX_PT: u8 = 97;
const MEDIA_SSRC: u32 = 1001;
const FPS: u32 = 30;
const WIDTH: u32 = 640;
const HEIGHT: u32 = 360;
/// The congestion controller's bounds, as the capacity test gives them.
const MIN_BPS: f64 = 100_000.0;
const MAX_BPS: f64 = 2_500_000.0;
/// The wall clock at the start (every NTP time on the wire follows from it).
const ANCHOR: Duration = Duration::new(1_800_000_000, 0);

fn video_codec() -> RTCRtpCodec {
    RTCRtpCodec {
        mime_type: MIME_TYPE_VP8.to_owned(),
        clock_rate: 90_000,
        channels: 0,
        sdp_fmtp_line: String::new(),
        rtcp_feedback: [("ccm", "fir"), ("nack", ""), ("nack", "pli")]
            .into_iter()
            .map(|(typ, parameter)| RTCPFeedback {
                typ: typ.to_owned(),
                parameter: parameter.to_owned(),
            })
            .collect(),
    }
}

/// The uplink: delay, optional loss and jitter, optional rate cap behind a drop-tail queue.
#[derive(Clone, Copy, Debug)]
struct Link {
    delay: Duration,
    loss: f64,
    jitter: Duration,
    rate_bps: Option<u64>,
    queue: Duration,
}

impl Link {
    /// The capacity test's open link: 10 ms one way, no cap.
    fn open() -> Self {
        Self {
            delay: Duration::from_millis(10),
            loss: 0.0,
            jitter: Duration::ZERO,
            rate_bps: None,
            queue: Duration::from_millis(300),
        }
    }

    /// The capacity test's cap: 300 kbit/s, 30 ms one way, 300 ms of queue.
    fn capped_300k() -> Self {
        Self {
            delay: Duration::from_millis(30),
            rate_bps: Some(300_000),
            ..Self::open()
        }
    }

    /// The receive test's lossy link: 25 ms one way plus 0 to `jitter_ms`.
    fn lossy(loss: f64, jitter_ms: u64) -> Self {
        Self {
            delay: Duration::from_millis(25),
            loss,
            jitter: Duration::from_millis(jitter_ms),
            ..Self::open()
        }
    }
}

fn build_pc(
    seed: u64,
    send: bool,
) -> Result<(
    RTCPeerConnection,
    DefaultInterceptorHandles,
    Option<RTCRtpSenderId>,
)> {
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
    let start = Instant::now();
    let mut options = DefaultInterceptorOptions::default();
    options.rtcp_random = Some(provider.clone());
    options.wall_clock = Some(SystemInstant::at(start, ANCHOR));
    let (registry, handles) =
        register_default_interceptors_with_options(Registry::new(), &mut media_engine, &options)?;
    handles.congestion_control.set_min_bitrate(Some(MIN_BPS));
    handles
        .congestion_control
        .set_session_bitrate_limit(Some(MAX_BPS));
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
    let track = if send {
        Some(pc.add_track(MediaStreamTrack::new(
            "call".to_owned(),
            "video".to_owned(),
            "video".to_owned(),
            RtpCodecKind::Video,
            vec![RTCRtpEncodingParameters {
                rtp_coding_parameters: RTCRtpCodingParameters {
                    ssrc: Some(MEDIA_SSRC),
                    rtx: Some(RTCRtpRtxParameters { ssrc: 1002 }),
                    ..Default::default()
                },
                codec: video_codec(),
                ..Default::default()
            }],
        ))?)
    } else {
        None
    };
    Ok((pc, handles, track))
}

fn candidate(addr: SocketAddr) -> Result<RTCIceCandidateInit> {
    let candidate = CandidateHostConfig {
        base_config: CandidateConfig {
            network: "udp".to_owned(),
            address: addr.ip().to_string(),
            port: addr.port(),
            component: 1,
            ..Default::default()
        },
        ..Default::default()
    }
    .new_candidate_host()?;
    Ok(RTCIceCandidate::from(&candidate).to_json()?)
}

fn vp8_factory(w: u32, h: u32, fps: f64, bps: u32) -> Result<Box<dyn VideoEncoder>, EncodeError> {
    Ok(Box::new(Vp8Encoder::new(w, h, fps.round() as u32, bps)?))
}

/// One picture sent: its capture time and the source picture.
struct Sent {
    capture: Instant,
    source: I420Buffer,
}

struct Call {
    now: Instant,
    start: Instant,
    spc: RTCPeerConnection,
    rpc: RTCPeerConnection,
    shandles: DefaultInterceptorHandles,
    saddr: SocketAddr,
    raddr: SocketAddr,
    connected: [bool; 2],
    sender_id: RTCRtpSenderId,
    video: Option<VideoSender>,
    config: SendConfig,
    source: TestSource,
    next_frame: Instant,
    link: Link,
    rng: Rng,
    busy_until: Option<Instant>,
    last_delivery: Option<Instant>,
    in_flight: Vec<(Instant, u64, bool, BytesMut)>,
    order: u64,
    media: bool,
    /// Sending side.
    sent: HashMap<u32, Sent>,
    /// (time, target) each time the target the sender read changed.
    targets: Vec<(Duration, f64)>,
    /// (time, octets, key frame, width, height) of each picture sent.
    frames: Vec<(Duration, usize, bool, u32, u32)>,
    /// Pictures the pipeline encoded while the target it last read was 0.
    sent_in_pause: u32,
    decisions: Vec<(Duration, KeyFrameDecision)>,
    pacer_discards: u32,
    queue_drops: u64,
    /// Receiving side.
    receiver_id: Option<RTCRtpReceiverId>,
    receiver: Option<VideoReceiver>,
    decoder: Vp8Decoder,
    decode_errors: u32,
    psnr: Vec<f64>,
    renders: VecDeque<(Instant, u32)>,
    /// (render time, capture time) of each picture rendered.
    rendered: Vec<(Duration, Duration)>,
}

fn is_rtp(data: &[u8]) -> bool {
    matches!(data.first(), Some(128..=191))
}

impl Call {
    fn new(link: Link, seed: u64, config: SendConfig) -> Result<Self> {
        let (spc, shandles, track) = build_pc(seed, true)?;
        let (rpc, _, _) = build_pc(seed ^ 0xabcd, false)?;
        let now = Instant::now();
        let mut call = Self {
            now,
            start: now,
            spc,
            rpc,
            shandles,
            saddr: "10.0.0.1:5000".parse()?,
            raddr: "10.0.0.2:5000".parse()?,
            connected: [false; 2],
            sender_id: track.ok_or_else(|| anyhow!("no track"))?,
            video: None,
            config,
            source: TestSource::new(WIDTH, HEIGHT),
            next_frame: now,
            link: Link::open(),
            rng: Rng(seed ^ 0x1155),
            busy_until: None,
            last_delivery: None,
            in_flight: Vec::new(),
            order: 0,
            media: false,
            sent: HashMap::new(),
            targets: Vec::new(),
            frames: Vec::new(),
            sent_in_pause: 0,
            decisions: Vec::new(),
            pacer_discards: 0,
            queue_drops: 0,
            receiver_id: None,
            receiver: None,
            decoder: Vp8Decoder::new(),
            decode_errors: 0,
            psnr: Vec::new(),
            renders: VecDeque::new(),
            rendered: Vec::new(),
        };
        let offer = call.spc.create_offer(None)?;
        call.spc.set_local_description(now, offer.clone())?;
        call.rpc.set_remote_description(now, offer)?;
        let answer = call.rpc.create_answer(None)?;
        call.rpc.set_local_description(now, answer.clone())?;
        call.spc.set_remote_description(now, answer)?;
        let (sa, ra) = (call.saddr, call.raddr);
        call.spc.add_local_candidate(candidate(sa)?)?;
        call.rpc.add_remote_candidate(candidate(sa)?)?;
        call.rpc.add_local_candidate(candidate(ra)?)?;
        call.spc.add_remote_candidate(candidate(ra)?)?;
        while !(call.connected[0] && call.connected[1]) {
            if call.now.duration_since(now) > Duration::from_secs(10) {
                bail!("not connected");
            }
            call.step()?;
        }
        let video = VideoSender::new(
            &mut call.spc,
            call.sender_id,
            Box::new(vp8_factory),
            RtpStart {
                first_sequence_number: (seed as u16).wrapping_mul(7),
                first_timestamp: (seed as u32).wrapping_mul(0x9e37_79b9),
            },
            call.config.clone(),
        )?;
        call.video = Some(video);
        call.link = link;
        call.media = true;
        call.start = call.now;
        call.next_frame = call.now;
        Ok(call)
    }

    fn elapsed(&self) -> Duration {
        self.now.duration_since(self.start)
    }

    fn set_link(&mut self, link: Link) {
        self.link = link;
        self.busy_until = None;
    }

    /// When a datagram the sender sends now arrives; `None` when it is lost.
    fn uplink(&mut self, size: usize) -> Option<Instant> {
        let mut leaves = self.now;
        if let Some(rate) = self.link.rate_bps {
            let start = self.busy_until.map_or(self.now, |t| t.max(self.now));
            if start.saturating_duration_since(self.now) > self.link.queue {
                self.queue_drops += 1;
                return None;
            }
            leaves = start + Duration::from_secs_f64(size as f64 * 8.0 / rate as f64);
            self.busy_until = Some(leaves);
        }
        if self.link.loss > 0.0 && self.rng.unit() < self.link.loss {
            return None;
        }
        let jitter = Duration::from_secs_f64(self.link.jitter.as_secs_f64() * self.rng.unit());
        let at = leaves + self.link.delay + jitter;
        // Without jitter nothing overtakes (the capacity test's link).
        if self.link.jitter.is_zero() {
            let at = self.last_delivery.map_or(at, |last| at.max(last));
            self.last_delivery = Some(at);
            return Some(at);
        }
        Some(at)
    }

    fn send_frame(&mut self) -> Result<()> {
        let picture = self.source.next_picture();
        let now = self.now;
        let at = self.elapsed();
        let video = self.video.as_mut().expect("bound");
        if let Some(target) = video.poll(&mut self.spc, now) {
            self.targets.push((at, target));
        }
        let paused = self.targets.last().is_some_and(|t| t.1 == 0.0);
        if let FrameOutcome::Sent(frame) =
            video.send_frame(&mut self.spc, now, now, &picture.view())?
        {
            if paused {
                self.sent_in_pause += 1;
            }
            self.frames
                .push((at, frame.octets, frame.keyframe, frame.width, frame.height));
            self.sent.insert(
                frame.timestamp,
                Sent {
                    capture: frame.capture,
                    source: picture,
                },
            );
        }
        Ok(())
    }

    fn step(&mut self) -> Result<()> {
        self.now += Duration::from_millis(1);
        let now = self.now;
        self.spc.handle_timeout(now)?;
        self.rpc.handle_timeout(now)?;
        if self.media && now >= self.next_frame {
            self.next_frame += Duration::from_micros(1_000_000 / u64::from(FPS));
            self.send_frame()?;
        }
        while let Some(msg) = self.spc.poll_write() {
            let at = if self.media && is_rtp(&msg.message) {
                self.uplink(msg.message.len())
            } else {
                Some(now + self.link.delay)
            };
            if let Some(at) = at {
                self.order += 1;
                self.in_flight.push((at, self.order, true, msg.message));
            }
        }
        while let Some(msg) = self.rpc.poll_write() {
            self.order += 1;
            self.in_flight
                .push((now + self.link.delay, self.order, false, msg.message));
        }
        self.in_flight.sort_by_key(|d| (d.0, d.1));
        let due = self.in_flight.iter().take_while(|d| d.0 <= now).count();
        for (_, _, to_receiver, data) in self.in_flight.drain(..due).collect::<Vec<_>>() {
            let (pc, from, to) = if to_receiver {
                (&mut self.rpc, self.saddr, self.raddr)
            } else {
                (&mut self.spc, self.raddr, self.saddr)
            };
            let _ = pc.handle_read(TaggedBytesMut {
                now,
                transport: TransportContext {
                    local_addr: to,
                    peer_addr: from,
                    ecn: None,
                    transport_protocol: TransportProtocol::UDP,
                },
                message: data,
            });
        }
        let at = self.elapsed();
        while let Some(event) = self.spc.poll_event() {
            match &event {
                RTCPeerConnectionEvent::OnConnectionStateChangeEvent(state) => {
                    if *state == RTCPeerConnectionState::Failed {
                        bail!("sender failed");
                    }
                    self.connected[0] = *state == RTCPeerConnectionState::Connected;
                }
                RTCPeerConnectionEvent::OnPacerDiscard { .. } => self.pacer_discards += 1,
                _ => {}
            }
            if let Some(video) = &mut self.video
                && let Some(decision) = video.handle_event(now, &event)
            {
                self.decisions.push((at, decision));
            }
        }
        while let Some(event) = self.rpc.poll_event() {
            match event {
                RTCPeerConnectionEvent::OnConnectionStateChangeEvent(state) => {
                    if state == RTCPeerConnectionState::Failed {
                        bail!("receiver failed");
                    }
                    self.connected[1] = state == RTCPeerConnectionState::Connected;
                }
                RTCPeerConnectionEvent::OnTrack(RTCTrackEvent::OnOpen(init)) => {
                    self.receiver_id = Some(init.receiver_id);
                }
                _ => {}
            }
        }
        if self.receiver.is_none()
            && let Some(id) = self.receiver_id
        {
            let mut v = VideoReceiver::new(&mut self.rpc, id, ReceiveConfig::default())?;
            v.set_rtt(2 * self.link.delay);
            self.receiver = Some(v);
        }
        while self.spc.poll_read().is_some() {}
        while let Some(message) = self.rpc.poll_read() {
            if let RTCMessage::RtpPacket(_, packet) = message.message
                && let Some(v) = &mut self.receiver
            {
                v.handle_rtp(now, &packet);
            }
        }
        self.receive(now)?;
        if self.media && self.elapsed().as_millis().is_multiple_of(1000) {
            let now = self.now;
            if let Some(video) = &mut self.video {
                video.update_stats(&mut self.spc, now);
            }
            if let Some(v) = &mut self.receiver {
                v.update_stats(&mut self.rpc, now);
            }
        }
        Ok(())
    }

    fn receive(&mut self, now: Instant) -> Result<()> {
        let Some(v) = &mut self.receiver else {
            return Ok(());
        };
        v.poll(&mut self.rpc, now)?;
        while let Some((ssrc, request)) = v.poll_frame(now) {
            let outcome = match self.decoder.decode(&request.frame) {
                Ok(Some(p)) => {
                    if let (Some(sent), Some(picture)) = (
                        self.sent.get(&request.frame.frame.rtp_timestamp),
                        self.decoder.picture(),
                    ) {
                        // A degraded picture is compared with its source scaled the same way.
                        let mut reference = I420Buffer::default();
                        rtc_video::picture::scale_into(
                            &sent.source.view(),
                            p.width,
                            p.height,
                            &mut reference,
                        );
                        self.psnr.extend(psnr(&reference.view(), &picture));
                    }
                    DecodeOutcome::Decoded {
                        width: p.width,
                        height: p.height,
                        qp: None,
                        decode_time: Duration::from_millis(2),
                        request_key_frame: false,
                    }
                }
                Ok(None) => DecodeOutcome::Failed,
                Err(DecodeError::NeedKeyFrame) | Err(DecodeError::Corrupt(_)) => {
                    self.decode_errors += 1;
                    DecodeOutcome::Failed
                }
            };
            v.on_decoded(&mut self.rpc, now, ssrc, request.token, outcome);
            if matches!(outcome, DecodeOutcome::Decoded { .. }) {
                let at = request.render_time.map_or(now, |t| t.max(now));
                self.renders
                    .push_back((at, request.frame.frame.rtp_timestamp));
            }
        }
        let mut due: Vec<_> = self.renders.drain(..).collect();
        due.sort_by_key(|r| r.0);
        for (at, ts) in due {
            if at <= now {
                v.on_rendered(MEDIA_SSRC, at);
                if let Some(sent) = self.sent.get(&ts) {
                    self.rendered.push((
                        at.duration_since(self.start),
                        sent.capture.saturating_duration_since(self.start),
                    ));
                }
            } else {
                self.renders.push_back((at, ts));
            }
        }
        Ok(())
    }

    fn run_for(&mut self, d: Duration) -> Result<()> {
        let end = self.now + d;
        while self.now < end {
            self.step()?;
        }
        Ok(())
    }

    fn send_stats(&mut self) -> SendStats {
        let now = self.now;
        self.video
            .as_mut()
            .expect("bound")
            .update_stats(&mut self.spc, now)
    }

    fn receive_stats(&mut self) -> ReceiveStats {
        let now = self.now;
        let v = self.receiver.as_mut().expect("receiving");
        v.stats(MEDIA_SSRC, now).expect("a stream")
    }

    /// The target in force at `at` (0 before the first).
    fn target_at(&self, at: Duration) -> f64 {
        self.targets
            .iter()
            .take_while(|t| t.0 <= at)
            .last()
            .map_or(0.0, |t| t.1)
    }

    /// The pauses: (start, end) of each stretch the target read 0.
    fn pauses(&self) -> Vec<(Duration, Duration)> {
        let mut pauses = Vec::new();
        let mut started = None;
        for &(at, bps) in &self.targets {
            match (started, bps == 0.0) {
                (None, true) => started = Some(at),
                (Some(from), false) => {
                    pauses.push((from, at));
                    started = None;
                }
                _ => {}
            }
        }
        if let Some(from) = started {
            pauses.push((from, self.elapsed()));
        }
        pauses
    }

    /// The encoded bitrate over [from, to) against the mean target over the same time.
    fn rate_vs_target(&self, from: Duration, to: Duration) -> (f64, f64) {
        let octets: usize = self
            .frames
            .iter()
            .filter(|f| f.0 >= from && f.0 < to)
            .map(|f| f.1)
            .sum();
        let secs = (to - from).as_secs_f64();
        let mut target = 0.0;
        let mut t = from;
        while t < to {
            target += self.target_at(t);
            t += Duration::from_millis(10);
        }
        let samples = ((to - from).as_millis() / 10).max(1) as f64;
        (octets as f64 * 8.0 / secs, target / samples)
    }

    /// The longest time between rendered pictures in [from, to], and when it began.
    fn longest_gap(&self, from: Duration, to: Duration) -> (Duration, Duration) {
        let mut last = from;
        let mut longest = (Duration::ZERO, from);
        for &(at, _) in self.rendered.iter().filter(|r| r.0 >= from && r.0 <= to) {
            if at - last > longest.0 {
                longest = (at - last, last);
            }
            last = at;
        }
        if to.saturating_sub(last) > longest.0 {
            longest = (to - last, last);
        }
        longest
    }

    /// The oldest picture shown from `from` on: render time less capture time.
    fn oldest_shown(&self, from: Duration) -> Duration {
        self.rendered
            .iter()
            .filter(|r| r.0 >= from)
            .map(|r| r.0.saturating_sub(r.1))
            .max()
            .unwrap_or_default()
    }

    fn psnr_summary(&self) -> (f64, f64) {
        let mean = self.psnr.iter().sum::<f64>() / self.psnr.len().max(1) as f64;
        let worst = self.psnr.iter().copied().fold(f64::INFINITY, f64::min);
        (mean, worst)
    }

    fn estimate(&self) -> f64 {
        self.shandles.congestion_control.target_bitrate()
    }
}

fn kbps(bps: f64) -> f64 {
    (bps / 1000.0).round()
}

/// The capacity test's call: open 20 s, the uplink capped at 300 kbit/s for 20 s, open again
/// for 20 s.
struct CapOutcome {
    capped_at: Duration,
    opened_at: Duration,
    before: f64,
    under: f64,
    recovery: f64,
    freeze: (Duration, Duration),
    lag: Duration,
    pauses: Vec<(Duration, Duration)>,
    /// For each pause, whether the first picture sent after it was a key frame, and how long
    /// after its end the receiver rendered a picture.
    resumed_with_key: Vec<bool>,
    resumed_after: Vec<Duration>,
    send: SendStats,
    receive: ReceiveStats,
}

fn cap_run(seed: u64, config: SendConfig, name: &str) -> Result<(Call, CapOutcome)> {
    let mut call = Call::new(Link::open(), seed, config)?;
    call.run_for(Duration::from_secs(20))?;
    let capped_at = call.elapsed();
    let before = call.target_at(capped_at);
    call.set_link(Link::capped_300k());
    call.run_for(Duration::from_secs(20))?;
    let opened_at = call.elapsed();
    call.set_link(Link::open());
    call.run_for(Duration::from_secs(20))?;
    let end = call.elapsed();
    // The median target over the last twelve seconds of the cap.
    let mut samples: Vec<f64> = (0..120)
        .map(|i| {
            call.target_at(capped_at + Duration::from_secs(8) + Duration::from_millis(100 * i))
        })
        .collect();
    samples.sort_by(f64::total_cmp);
    let under = samples[samples.len() / 2];
    let recovery = call.target_at(end);
    let freeze = call.longest_gap(Duration::from_secs(2), end);
    let lag = call.oldest_shown(capped_at);
    let pauses = call.pauses();
    let resumed_with_key = pauses
        .iter()
        .map(|(_, until)| {
            call.frames
                .iter()
                .find(|f| f.0 >= *until)
                .is_some_and(|f| f.2)
        })
        .collect();
    let resumed_after = pauses
        .iter()
        .map(|(_, until)| {
            call.rendered
                .iter()
                .find(|r| r.0 >= *until)
                .map_or(end.saturating_sub(*until), |r| r.0 - *until)
        })
        .collect();
    let send = call.send_stats();
    let receive = call.receive_stats();
    let o = CapOutcome {
        capped_at,
        opened_at,
        before,
        under,
        recovery,
        freeze,
        lag,
        pauses,
        resumed_with_key,
        resumed_after,
        send,
        receive,
    };
    let (mean, worst) = call.psnr_summary();
    println!(
        "MEASURE {name} seed {seed}: target before cap {} k, median under {} k, +20 s {} k (estimate {} k); \
         freeze {:.2} s at {:.1} s; oldest picture from the cap {:.2} s; pauses {:?} key on resume {:?} \
         resumed after {:?}; sent in pause {}; pacer discards {}; queue drops {}; key frames {} \
         (requests served {} coalesced {} suppressed {}); resolution changes {}, bandwidth-limited {:.1} s; \
         frames encoded {} dropped paused {} framerate {} encoder {}; decoded {} decode errors {} PSNR mean {mean:.1} worst {worst:.1}; \
         receive freezes {} longest {:.0} ms retransmitted {}",
        kbps(o.before),
        kbps(o.under),
        kbps(o.recovery),
        kbps(call.estimate()),
        o.freeze.0.as_secs_f64(),
        o.freeze.1.as_secs_f64(),
        o.lag.as_secs_f64(),
        o.pauses
            .iter()
            .map(|p| (p.0.as_secs_f64(), p.1.as_secs_f64()))
            .collect::<Vec<_>>(),
        o.resumed_with_key,
        o.resumed_after,
        call.sent_in_pause,
        call.pacer_discards,
        call.queue_drops,
        o.send.key_frames_encoded,
        o.send.key_frame_requests_served,
        o.send.key_frame_requests_coalesced,
        o.send.key_frame_requests_suppressed,
        o.send.quality_limitation_resolution_changes,
        o.send.quality_limitation_bandwidth,
        o.send.frames_encoded,
        o.send.frames_dropped_paused,
        o.send.frames_dropped_framerate,
        o.send.frames_dropped_encoder,
        o.receive.frames_decoded,
        call.decode_errors,
        o.receive.freeze_count,
        o.receive.longest_render_interval * 1000.0,
        o.receive.packets_retransmitted,
    );
    for w in 0..6u64 {
        let (from, to) = (
            Duration::from_secs(10 * w),
            Duration::from_secs(10 * w + 10),
        );
        let (rate, target) = call.rate_vs_target(from, to);
        println!(
            "MEASURE {name} seed {seed}: {}-{} s encoded {} k target {} k ratio {:.3}",
            10 * w,
            10 * w + 10,
            kbps(rate),
            kbps(target),
            rate / target.max(1.0)
        );
    }
    Ok((call, o))
}

/// An open link: the target climbs, the encoder follows it (encoded bitrate within 15 % of
/// the target over 10 s windows once the target is above what the source needs), nothing
/// degrades, every picture decodes close to its source.
#[test]
fn on_an_open_link_the_encoder_follows_the_target() -> Result<()> {
    let mut call = Call::new(Link::open(), 1, SendConfig::default())?;
    call.run_for(Duration::from_secs(30))?;
    let send = call.send_stats();
    let receive = call.receive_stats();
    let (mean, worst) = call.psnr_summary();
    let freeze = call.longest_gap(Duration::from_secs(2), call.elapsed());
    let reached_1m = call
        .targets
        .iter()
        .find(|t| t.1 >= 1_000_000.0)
        .map(|t| t.0);
    println!(
        "MEASURE open link: target {} k at 30 s, 1 Mbit/s at {reached_1m:?}; key frames {} frames {} \
         degraded {:.1} s; decoded {} errors {} PSNR mean {mean:.1} worst {worst:.1}; freeze {:.3} s; \
         oldest picture {:.3} s",
        kbps(call.target_at(call.elapsed())),
        send.key_frames_encoded,
        send.frames_encoded,
        send.quality_limitation_bandwidth,
        receive.frames_decoded,
        call.decode_errors,
        freeze.0.as_secs_f64(),
        call.oldest_shown(Duration::ZERO).as_secs_f64(),
    );
    let mut ratios = Vec::new();
    for w in 0..3u64 {
        let (from, to) = (
            Duration::from_secs(10 * w),
            Duration::from_secs(10 * w + 10),
        );
        let (rate, target) = call.rate_vs_target(from, to);
        println!(
            "MEASURE open link: {}-{} s encoded {} k target {} k ratio {:.3}",
            10 * w,
            10 * w + 10,
            kbps(rate),
            kbps(target),
            rate / target
        );
        ratios.push(rate / target);
    }
    assert!(reached_1m.is_some(), "the target reached 1 Mbit/s");
    for (w, r) in ratios.iter().enumerate().skip(1) {
        assert!(
            (0.85..=1.15).contains(r),
            "window {w}: encoded / target {r:.3}"
        );
    }
    assert_eq!(call.decode_errors, 0);
    assert_eq!(call.pacer_discards, 0);
    assert!(worst > 25.0, "worst picture {worst:.1} dB");
    assert!(
        receive.frames_decoded > 850,
        "decoded {}",
        receive.frames_decoded
    );
    assert!(
        freeze.0 < Duration::from_millis(500),
        "freeze {:?}",
        freeze.0
    );
    Ok(())
}

/// The capacity test's cap, comes and goes (20 s open, 20 s at 300 kbit/s, 20 s open), with
/// the engine's default chain: the video keeps playing, the capped link is used, the target
/// recovers, nothing is discarded by the pacer.
#[test]
fn video_keeps_playing_through_a_capacity_cap_that_comes_and_goes() -> Result<()> {
    let (call, o) = cap_run(2, SendConfig::default(), "cap")?;
    assert_eq!(call.decode_errors, 0, "every picture released decodes");
    assert_eq!(
        call.pacer_discards, 0,
        "a sender following the target loses nothing at the pacer"
    );
    assert!(
        o.freeze.0 <= Duration::from_secs(2),
        "froze {:?} at {:?}",
        o.freeze.0,
        o.freeze.1
    );
    assert!(
        o.lag <= Duration::from_secs(10),
        "a picture {:?} old",
        o.lag
    );
    assert!(o.under >= 150_000.0, "{} bit/s under the cap", o.under);
    assert!(
        o.recovery >= 800_000.0,
        "{} bit/s 20 s after the cap",
        o.recovery
    );
    assert!(
        o.before >= 1_000_000.0,
        "{} bit/s when the cap came",
        o.before
    );
    let (rate, target) = call.rate_vs_target(o.capped_at + Duration::from_secs(8), o.opened_at);
    assert!(
        rate <= target * 1.15,
        "under the cap: encoded {rate} against {target}"
    );
    Ok(())
}

/// The pacer's pause in the same call (a target of 0 when the pacer holds a second of media):
/// no picture is encoded while the target reads 0, the first picture after each pause is a key
/// frame (the default), and the receiver renders within a second of each pause's end. The
/// `Chrome` profile (no key frame on resume, libwebrtc's form) is run alongside for the
/// comparison.
#[test]
fn a_pacer_pause_stops_the_encoder_and_the_video_resumes_with_a_key_frame() -> Result<()> {
    let (call, o) = cap_run(3, SendConfig::default(), "pause")?;
    assert!(!o.pauses.is_empty(), "the pacer paused the sender");
    assert_eq!(call.sent_in_pause, 0, "nothing encoded in a pause");
    assert!(o.send.frames_dropped_paused > 0);
    assert!(
        o.resumed_with_key.iter().all(|k| *k),
        "{:?}",
        o.resumed_with_key
    );
    for after in &o.resumed_after {
        assert!(
            *after <= Duration::from_secs(1),
            "rendered {after:?} after a pause"
        );
    }
    assert_eq!(call.pacer_discards, 0);
    assert_eq!(call.decode_errors, 0);
    let (chrome, oc) = cap_run(3, SendConfig::chrome(), "pause chrome")?;
    assert_eq!(chrome.sent_in_pause, 0);
    assert_eq!(chrome.decode_errors, 0);
    assert!(
        oc.freeze.0 <= Duration::from_secs(2),
        "chrome froze {:?}",
        oc.freeze.0
    );
    Ok(())
}

/// 2 % loss with 0 to 40 ms of jitter (reordering) at 25 ms: the lost packets come back by
/// NACK and RTX, every released picture decodes, and the longest wait is the slowest repair.
#[test]
fn loss_is_repaired_by_nack_and_every_picture_decodes() -> Result<()> {
    let mut call = Call::new(Link::lossy(0.02, 40), 4, SendConfig::default())?;
    call.run_for(Duration::from_secs(30))?;
    let send = call.send_stats();
    let receive = call.receive_stats();
    let (mean, worst) = call.psnr_summary();
    let requests = call
        .decisions
        .iter()
        .filter(|d| d.1 == KeyFrameDecision::Served)
        .count();
    println!(
        "MEASURE loss 2%: decoded {} received {} dropped {} errors {}; retransmitted {} repair mean {:.0} ms \
         max {:.0} ms; longest render interval {:.0} ms freezes {}; key frames {} (requests served {requests} \
         suppressed {}); target at 30 s {} k; PSNR mean {mean:.1} worst {worst:.1}",
        receive.frames_decoded,
        receive.frames_received,
        receive.frames_dropped,
        call.decode_errors,
        receive.packets_retransmitted,
        1000.0 * receive.total_repair_delay / receive.packets_retransmitted.max(1) as f64,
        1000.0 * receive.max_repair_delay,
        1000.0 * receive.longest_render_interval,
        receive.freeze_count,
        send.key_frames_encoded,
        send.key_frame_requests_suppressed,
        kbps(call.target_at(call.elapsed())),
    );
    assert!(receive.packets_retransmitted > 0, "NACK repaired packets");
    assert_eq!(call.decode_errors, 0);
    assert!(worst > 25.0, "worst picture {worst:.1} dB");
    assert!(
        receive.frames_decoded > 800,
        "decoded {}",
        receive.frames_decoded
    );
    assert!(
        receive.longest_render_interval <= receive.max_repair_delay + 0.1,
        "longest interval {:.0} ms, slowest repair {:.0} ms",
        receive.longest_render_interval * 1000.0,
        receive.max_repair_delay * 1000.0
    );
    Ok(())
}
