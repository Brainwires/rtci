//! The receive pipeline in a call between two `rtc` peer connections, in virtual time.
//!
//! One peer sends VP8 (with RTX) at a bitrate, from a source that makes a key frame when
//! asked (PLI); the other receives it through `rtc_video::engine::VideoReceiver`, decodes with
//! the reference-checking decoder and "renders" each picture at its render time. The uplink
//! drops and delays (and so reorders) datagrams from a fixed seed, and can be capped to a rate
//! behind a drop-tail queue, as `tests/capacity_cap_video_rtc2rtc.rs` of the engine does. The
//! interceptor chain is the one that test uses: NACK, the RTCP reports, key-frame requests,
//! transport-cc with GCC.
//!
//! What is asserted is what a viewer sees (W3C `freezeCount`, the longest interval between
//! rendered frames) and the integrity of every picture decoded (byte for byte what was sent,
//! in an order its references allow). The acceptance figures are `docs/video-pipeline.md`
//! section 6, phase 1.

use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Result, bail};
use bytes::{Bytes, BytesMut};
use rtc::crypto::{CryptoError, RTCCrypto, RTCCryptoProvider, RTCRandom, default_provider};
use rtc::interceptor::{
    GccHandle, GccInterceptorBuilder, Interceptor as _, PassThroughInterceptor, Registry,
    RtcpRandom, RtcpSessionBuilder, Slot,
};
use rtc::media_stream::MediaStreamTrack;
use rtc::peer_connection::configuration::RTCConfigurationBuilder;
use rtc::peer_connection::configuration::interceptor_registry::{
    configure_key_frame_requests, configure_nack, configure_receiver_reference_time,
    configure_rtcp_reports_with, configure_twcc,
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
use rtc::rtp::packetizer::Packetizer;
use rtc::rtp_transceiver::rtp_sender::{
    RTCPFeedback, RTCRtpCodec, RTCRtpCodecParameters, RTCRtpCodingParameters,
    RTCRtpEncodingParameters, RTCRtpRtxParameters, RtpCodecKind,
};
use rtc::rtp_transceiver::{RTCRtpReceiverId, RTCRtpSenderId};
use rtc::sansio::Protocol;
use rtc::shared::{TaggedBytesMut, TransportContext, TransportProtocol};
use rtc_video::decoder::{DecodeError, ReferenceCheckingDecoder, VideoDecoder};
use rtc_video::engine::VideoReceiver;
use rtc_video::keyframe::KeyFrameReason;
use rtc_video::stats::ReceiveStats;
use rtc_video::{DecodeOutcome, ReceiveConfig};

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
        let mut rng = self.rng.lock().expect("not poisoned");
        for chunk in output.chunks_mut(8) {
            let bytes = rng.next_u64().to_le_bytes();
            chunk.copy_from_slice(&bytes[..chunk.len()]);
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

const VP8_PT: u8 = 96;
const RTX_PT: u8 = 97;
const RTP_MTU: usize = 1200;
const FPS: u32 = 30;
const FRAME_INTERVAL: Duration = Duration::from_micros(33_333);

fn video_codec() -> RTCRtpCodec {
    RTCRtpCodec {
        mime_type: MIME_TYPE_VP8.to_owned(),
        clock_rate: 90_000,
        channels: 0,
        sdp_fmtp_line: String::new(),
        rtcp_feedback: [
            ("ccm", "fir"),
            ("nack", ""),
            ("nack", "pli"),
            ("transport-cc", ""),
        ]
        .into_iter()
        .map(|(typ, parameter)| RTCPFeedback {
            typ: typ.to_owned(),
            parameter: parameter.to_owned(),
        })
        .collect(),
    }
}

/// The uplink of the sending peer: loss, uniform jitter (reordering), and an optional rate cap
/// behind a drop-tail queue.
#[derive(Clone, Copy, Debug)]
struct Link {
    loss: f64,
    delay: Duration,
    jitter: Duration,
    rate_bps: Option<u64>,
    queue: Duration,
}

impl Link {
    fn lossy(loss: f64, jitter_ms: u64) -> Self {
        Self {
            loss,
            delay: Duration::from_millis(25),
            jitter: Duration::from_millis(jitter_ms),
            rate_bps: None,
            queue: Duration::from_millis(300),
        }
    }
}

/// The rate-following source: frames whose sizes add up to the bitrate, a key frame five
/// frames' budget. A frame is a VP8 frame tag (bit 0 clear: key frame), for a key frame the
/// start code and 320x240, then its number and filler.
#[derive(Default)]
struct Source {
    number: u32,
}

impl Source {
    fn next_frame(&mut self, bitrate: u32, key: bool) -> Vec<u8> {
        let budget = (bitrate / 8 / FPS) as usize;
        let size = if key { budget * 5 } else { budget }.max(24);
        let mut frame = vec![0u8; size];
        for (i, b) in frame.iter_mut().enumerate() {
            *b = (i as u32).wrapping_mul(31).wrapping_add(self.number) as u8;
        }
        if key {
            frame[..10]
                .copy_from_slice(&[0x10, 0x02, 0x00, 0x9d, 0x01, 0x2a, 0x40, 0x01, 0xf0, 0x00]);
        } else {
            frame[0] = 0x11;
        }
        frame[10..14].copy_from_slice(&self.number.to_be_bytes());
        self.number += 1;
        frame
    }
}

struct Sender {
    pc: RTCPeerConnection,
    addr: SocketAddr,
    gcc: GccHandle,
    track: RTCRtpSenderId,
    packetizer: Option<Box<dyn Packetizer>>,
    source: Source,
    force_key: bool,
    sent: HashMap<u32, Bytes>,
    plis: u32,
}

struct Receiver {
    pc: RTCPeerConnection,
    addr: SocketAddr,
    video: Option<VideoReceiver>,
    receiver_id: Option<RTCRtpReceiverId>,
    decoder: ReferenceCheckingDecoder,
    renders: VecDeque<(Instant, u32)>,
    corrupt: u32,
    reasons: Vec<(Duration, KeyFrameReason)>,
    first_render: Option<Instant>,
}

fn build_pc(
    seed: u64,
    send: bool,
) -> Result<(RTCPeerConnection, GccHandle, Option<RTCRtpSenderId>)> {
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
    let registry = configure_nack(Registry::new(), &mut media_engine);
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
            gcc.with_min_bitrate(100_000)
                .with_max_bitrate(2_500_000)
                .build(),
        ),
    );
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
    let track = if send {
        Some(pc.add_track(MediaStreamTrack::new(
            "call".to_owned(),
            "video".to_owned(),
            "video".to_owned(),
            RtpCodecKind::Video,
            vec![RTCRtpEncodingParameters {
                rtp_coding_parameters: RTCRtpCodingParameters {
                    ssrc: Some(1001),
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
    Ok((pc, handle, track))
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

struct Call {
    now: Instant,
    start: Instant,
    sender: Sender,
    receiver: Receiver,
    link: Link,
    impaired: bool,
    rng: Rng,
    busy_until: Option<Instant>,
    in_flight: Vec<(Instant, bool, BytesMut)>,
    fixed_bitrate: Option<u32>,
    next_frame: Instant,
    connected: [bool; 2],
}

fn is_rtp(data: &[u8]) -> bool {
    matches!(data.first(), Some(128..=191))
}

impl Call {
    fn new(link: Link, seed: u64, fixed_bitrate: Option<u32>) -> Result<Self> {
        let (spc, gcc, track) = build_pc(seed, true)?;
        let (rpc, _, _) = build_pc(seed ^ 0xabcd, false)?;
        let now = Instant::now();
        let mut call = Self {
            now,
            start: now,
            sender: Sender {
                pc: spc,
                addr: "10.0.0.1:5000".parse()?,
                gcc,
                track: track.expect("the sender has a track"),
                packetizer: None,
                source: Source::default(),
                force_key: true,
                sent: HashMap::new(),
                plis: 0,
            },
            receiver: Receiver {
                pc: rpc,
                addr: "10.0.0.2:5000".parse()?,
                video: None,
                receiver_id: None,
                decoder: ReferenceCheckingDecoder::new((320, 240)),
                renders: VecDeque::new(),
                corrupt: 0,
                reasons: Vec::new(),
                first_render: None,
            },
            link,
            impaired: false,
            rng: Rng(seed),
            busy_until: None,
            in_flight: Vec::new(),
            fixed_bitrate,
            next_frame: now,
            connected: [false; 2],
        };
        let offer = call.sender.pc.create_offer(None)?;
        call.sender.pc.set_local_description(now, offer.clone())?;
        call.receiver.pc.set_remote_description(now, offer)?;
        let answer = call.receiver.pc.create_answer(None)?;
        call.receiver
            .pc
            .set_local_description(now, answer.clone())?;
        call.sender.pc.set_remote_description(now, answer)?;
        let (sa, ra) = (call.sender.addr, call.receiver.addr);
        call.sender.pc.add_local_candidate(candidate(sa)?)?;
        call.receiver.pc.add_remote_candidate(candidate(sa)?)?;
        call.receiver.pc.add_local_candidate(candidate(ra)?)?;
        call.sender.pc.add_remote_candidate(candidate(ra)?)?;
        while !(call.connected[0] && call.connected[1] && call.receiver.video.is_some()) {
            if call.now.duration_since(now) > Duration::from_secs(10) {
                bail!("not connected");
            }
            call.step()?;
        }
        call.impaired = true;
        call.start = call.now;
        call.next_frame = call.now;
        Ok(call)
    }

    fn elapsed(&self) -> Duration {
        self.now.duration_since(self.start)
    }

    /// When a datagram the sender sends now arrives; `None` when it is lost.
    fn uplink(&mut self, size: usize) -> Option<Instant> {
        if !self.impaired {
            return Some(self.now + Duration::from_millis(10));
        }
        let mut leaves = self.now;
        if let Some(rate) = self.link.rate_bps {
            let start = self.busy_until.map_or(self.now, |t| t.max(self.now));
            if start.saturating_duration_since(self.now) > self.link.queue {
                return None;
            }
            leaves = start + Duration::from_secs_f64(size as f64 * 8.0 / rate as f64);
            self.busy_until = Some(leaves);
        }
        if self.rng.unit() < self.link.loss {
            return None;
        }
        let jitter = Duration::from_secs_f64(self.link.jitter.as_secs_f64() * self.rng.unit());
        Some(leaves + self.link.delay + jitter)
    }

    fn send_frame(&mut self) -> Result<()> {
        let bitrate = self.fixed_bitrate.unwrap_or_else(|| {
            let bps = self.sender.gcc.target_bitrate_bps().unwrap_or(300_000);
            (bps as u64 * 9 / 10) as u32
        });
        let key = std::mem::take(&mut self.sender.force_key);
        let data = Bytes::from(self.sender.source.next_frame(bitrate, key));
        let now = self.now;
        let Some(mut s) = self.sender.pc.rtp_sender(self.sender.track) else {
            return Ok(());
        };
        if self.sender.packetizer.is_none() {
            let ssrc = s.ssrcs().next().expect("an SSRC");
            let codec = s
                .get_parameters()
                .rtp_parameters
                .codecs
                .iter()
                .find(|c| !c.rtp_codec.mime_type.eq_ignore_ascii_case(MIME_TYPE_RTX))
                .cloned()
                .expect("a codec");
            self.sender.packetizer = Some(Box::new(rtc::rtp::packetizer::new_packetizer(
                now,
                RTP_MTU,
                codec.payload_type,
                ssrc,
                codec.rtp_codec.payloader()?,
                Box::new(rtc::rtp::sequence::new_fixed_sequencer(4000)),
                90_000,
            )));
        }
        let packets =
            self.sender
                .packetizer
                .as_mut()
                .expect("set")
                .packetize(now, &data, 90_000 / FPS)?;
        if let Some(p) = packets.first() {
            self.sender.sent.insert(p.header.timestamp, data.clone());
        }
        for p in packets {
            s.write_rtp(now, p)?;
        }
        Ok(())
    }

    fn step(&mut self) -> Result<()> {
        self.now += Duration::from_millis(1);
        let now = self.now;
        self.sender.pc.handle_timeout(now)?;
        self.receiver.pc.handle_timeout(now)?;
        if self.impaired && now >= self.next_frame {
            self.next_frame += FRAME_INTERVAL;
            self.send_frame()?;
        }
        // Sender to receiver: the impaired uplink for media.
        while let Some(msg) = self.sender.pc.poll_write() {
            let at = if is_rtp(&msg.message) {
                self.uplink(msg.message.len())
            } else {
                Some(now + self.link.delay)
            };
            if let Some(at) = at {
                self.in_flight.push((at, true, msg.message));
            }
        }
        while let Some(msg) = self.receiver.pc.poll_write() {
            self.in_flight
                .push((now + self.link.delay, false, msg.message));
        }
        self.in_flight.sort_by_key(|d| d.0);
        let due = self.in_flight.iter().take_while(|d| d.0 <= now).count();
        for (_, to_receiver, data) in self.in_flight.drain(..due).collect::<Vec<_>>() {
            let (pc, from, to) = if to_receiver {
                (&mut self.receiver.pc, self.sender.addr, self.receiver.addr)
            } else {
                (&mut self.sender.pc, self.receiver.addr, self.sender.addr)
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
        for i in 0..2 {
            let pc = if i == 0 {
                &mut self.sender.pc
            } else {
                &mut self.receiver.pc
            };
            while let Some(event) = pc.poll_event() {
                match event {
                    RTCPeerConnectionEvent::OnConnectionStateChangeEvent(state) => {
                        if state == RTCPeerConnectionState::Failed {
                            bail!("peer {i} failed");
                        }
                        self.connected[i] = state == RTCPeerConnectionState::Connected;
                    }
                    RTCPeerConnectionEvent::OnTrack(RTCTrackEvent::OnOpen(init)) if i == 1 => {
                        self.receiver.receiver_id = Some(init.receiver_id);
                    }
                    RTCPeerConnectionEvent::OnKeyFrameRequest { .. } if i == 0 => {
                        self.sender.force_key = true;
                        self.sender.plis += 1;
                    }
                    _ => {}
                }
            }
        }
        if self.receiver.video.is_none()
            && let Some(id) = self.receiver.receiver_id
        {
            let mut v = VideoReceiver::new(&mut self.receiver.pc, id, ReceiveConfig::default())?;
            v.set_rtt(2 * self.link.delay + self.link.jitter / 2);
            self.receiver.video = Some(v);
        }
        while self.sender.pc.poll_read().is_some() {}
        while let Some(message) = self.receiver.pc.poll_read() {
            if let RTCMessage::RtpPacket(_, packet) = message.message
                && let Some(v) = &mut self.receiver.video
            {
                v.handle_rtp(now, &packet);
            }
        }
        self.receive(now)
    }

    fn receive(&mut self, now: Instant) -> Result<()> {
        let elapsed = self.elapsed();
        let r = &mut self.receiver;
        let Some(v) = &mut r.video else {
            return Ok(());
        };
        for reason in v.poll(&mut r.pc, now)? {
            r.reasons.push((elapsed, reason));
        }
        while let Some((ssrc, request)) = v.poll_frame(now) {
            let sent = self.sender.sent.get(&request.frame.frame.rtp_timestamp);
            if sent != Some(request.frame.data()) {
                r.corrupt += 1;
            }
            let outcome = match r.decoder.decode(&request.frame) {
                Ok(Some(p)) => DecodeOutcome::Decoded {
                    width: p.width,
                    height: p.height,
                    qp: None,
                    decode_time: Duration::from_millis(2),
                    request_key_frame: false,
                },
                Ok(None) | Err(DecodeError::NeedKeyFrame) | Err(DecodeError::Corrupt(_)) => {
                    DecodeOutcome::Failed
                }
            };
            v.on_decoded(&mut r.pc, now, ssrc, request.token, outcome);
            if matches!(outcome, DecodeOutcome::Decoded { .. }) {
                let at = request.render_time.map_or(now, |t| t.max(now));
                r.renders.push_back((at, ssrc));
            }
        }
        let mut renders: Vec<_> = r.renders.drain(..).collect();
        renders.sort_by_key(|x| x.0);
        for (at, ssrc) in renders {
            if at <= now {
                v.on_rendered(ssrc, at);
                r.first_render.get_or_insert(at);
            } else {
                r.renders.push_back((at, ssrc));
            }
        }
        if now
            .duration_since(self.start)
            .as_millis()
            .is_multiple_of(1000)
        {
            v.update_stats(&mut r.pc, now);
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

    fn stats(&mut self) -> ReceiveStats {
        let now = self.now;
        let v = self.receiver.video.as_mut().expect("receiving");
        let ssrc = v.ssrcs()[0];
        v.stats(ssrc, now).expect("a stream")
    }
}

fn report(name: &str, call: &mut Call) -> ReceiveStats {
    let s = call.stats();
    println!(
        "MEASURE {name}: decoded {} received {} dropped {} freezes {} ({:.3} s) longest {:.0} ms \
         jitter buffer mean {:.1} ms target {:.1} ms emitted {} key frame requests {:?} PLIs at \
         sender {} corrupt {} decoder errors {}",
        s.frames_decoded,
        s.frames_received,
        s.frames_dropped,
        s.freeze_count,
        s.total_freezes_duration,
        s.longest_render_interval * 1000.0,
        1000.0 * s.jitter_buffer_delay / s.jitter_buffer_emitted_count.max(1) as f64,
        1000.0 * s.jitter_buffer_target_delay / s.jitter_buffer_emitted_count.max(1) as f64,
        s.jitter_buffer_emitted_count,
        s.key_frame_requests,
        call.sender.plis,
        call.receiver.corrupt,
        call.receiver.decoder.errors,
    );
    s
}

#[test]
fn two_percent_loss_with_reordering_has_no_freeze() -> Result<()> {
    let mut call = Call::new(Link::lossy(0.02, 40), 11, Some(500_000))?;
    call.run_for(Duration::from_secs(30))?;
    let s = report("2% loss, 25 ms + 0..40 ms, 500 kbit/s, 30 s", &mut call);
    assert_eq!(call.receiver.corrupt, 0, "every picture decoded as sent");
    assert_eq!(
        call.receiver.decoder.errors, 0,
        "decode order allowed by the references"
    );
    assert!(s.frames_decoded > 870, "decoded {}", s.frames_decoded);
    assert_eq!(s.freeze_count, 0, "W3C freezes");
    Ok(())
}

#[test]
fn ten_percent_loss_recovers_within_half_a_second() -> Result<()> {
    let mut call = Call::new(Link::lossy(0.10, 40), 12, Some(500_000))?;
    call.run_for(Duration::from_secs(30))?;
    let s = report("10% loss, 25 ms + 0..40 ms, 500 kbit/s, 30 s", &mut call);
    assert_eq!(call.receiver.corrupt, 0);
    assert_eq!(call.receiver.decoder.errors, 0);
    assert!(
        s.longest_render_interval < 0.5,
        "longest interval {:.0} ms",
        s.longest_render_interval * 1000.0
    );
    Ok(())
}

#[test]
fn a_capacity_drop_and_recovery_leaves_no_long_freeze() -> Result<()> {
    let mut call = Call::new(Link::lossy(0.0, 0), 13, None)?;
    call.run_for(Duration::from_secs(10))?;
    call.link.rate_bps = Some(300_000);
    call.link.delay = Duration::from_millis(30);
    call.run_for(Duration::from_secs(20))?;
    let before = call.stats();
    call.link.rate_bps = None;
    call.link.delay = Duration::from_millis(10);
    call.busy_until = None;
    call.run_for(Duration::from_secs(20))?;
    let s = report("300 kbit/s for 20 s, then open", &mut call);
    assert_eq!(call.receiver.corrupt, 0);
    assert_eq!(call.receiver.decoder.errors, 0);
    // The longest interval after the cap lifted (the release before this froze 7 s): the
    // interval may have started under the cap, so the whole run's longest is the bound.
    assert!(
        s.longest_render_interval < 1.0,
        "longest interval {:.0} ms (under the cap {:.0} ms)",
        s.longest_render_interval * 1000.0,
        before.longest_render_interval * 1000.0
    );
    assert!(s.frames_decoded > before.frames_decoded + 500);
    Ok(())
}

#[test]
fn the_jitter_buffer_holds_about_the_network_jitter() -> Result<()> {
    let mut call = Call::new(Link::lossy(0.0, 40), 14, Some(500_000))?;
    call.run_for(Duration::from_secs(20))?;
    let s = report("clean, 25 ms + 0..40 ms jitter", &mut call);
    let mean = 1000.0 * s.jitter_buffer_delay / s.jitter_buffer_emitted_count as f64;
    assert!(
        (30.0..=90.0).contains(&mean),
        "mean jitter buffer delay {mean:.1} ms"
    );
    assert_eq!(s.freeze_count, 0);
    Ok(())
}
