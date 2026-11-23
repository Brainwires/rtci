//! The default interceptor chain (congestion control, the RTP circuit breaker of RFC 8083,
//! NACK, the RTCP reports) between two `rtc` peer connections over a link that reorders: a
//! random share of the media datagrams (SRTP and SRTCP) is held back by up to a given time, so
//! later packets overtake them, with or without loss. Virtual time.
//!
//! RFC 8083's breakers fire on a media timeout (section 4.2), an RTCP timeout (4.1) or
//! persistent congestion against the TCP-friendly rate from the reported loss (4.3). Reordering
//! loses nothing, so none of them may fire on a lossless link, and the receiver's cumulative
//! loss (RFC 3550 6.4.1, A.3) returns to zero.

use anyhow::{Result, bail};
use bytes::{Bytes, BytesMut};
use rtc::interceptor::{CircuitBreakerPacketSize, PassThroughInterceptor, Slot};
use std::cell::Cell;

thread_local! {
    /// Whether the next `World`'s peers run without the pacer.
    static WITHOUT_PACER: Cell<bool> = const { Cell::new(false) };
}
use rtc::crypto::{CryptoError, RTCCrypto, RTCCryptoProvider, RTCRandom, default_provider};
use rtc::interceptor::Registry;
use rtc::peer_connection::configuration::RTCConfigurationBuilder;
use rtc::peer_connection::configuration::interceptor_registry::{
    DefaultInterceptorHandles, DefaultInterceptorOptions,
    register_default_interceptors_with_options,
};
use rtc::peer_connection::configuration::media_engine::MediaEngine;
use rtc::peer_connection::configuration::setting_engine::SettingEngineBuilder;
use rtc::peer_connection::event::RTCPeerConnectionEvent;
use rtc::peer_connection::state::RTCPeerConnectionState;
use rtc::peer_connection::transport::{
    CandidateConfig, CandidateHostConfig, RTCIceCandidate, RTCIceCandidateInit,
};
use rtc::peer_connection::{RTCPeerConnection, RTCPeerConnectionBuilder};
use rtc::rtp::header::Header;
use rtc::rtp_transceiver::rtp_sender::{RTCRtpEncodingParameters, RtpCodecKind};
use rtc::rtp_transceiver::{RTCRtpSenderId, RTCRtpTransceiverDirection, RTCRtpTransceiverInit};
use rtc::sansio::Protocol;
use rtc::shared::{TaggedBytesMut, TransportContext, TransportProtocol};
use rtc::statistics::StatsSelector;
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

    /// Uniform in [0, 1).
    fn unit(&mut self) -> f64 {
        (self.next_u64() >> 11) as f64 / (1u64 << 53) as f64
    }
}

/// The built-in crypto provider with its random source replaced by a seeded [`Rng`]: what
/// the engine draws through `RTCCryptoProvider::random()` (ICE, DTLS, SCTP and, through
/// `DefaultInterceptorOptions::rtcp_random`, the RTCP report times) is the same in every run.
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

/// The link both directions share once the connection is up.
#[derive(Clone, Copy, Debug)]
struct Link {
    /// One-way delay of every datagram.
    delay: Duration,
    /// Share of the media datagrams held back.
    reorder_share: f64,
    /// A held-back datagram waits up to this much longer, uniformly.
    reorder: Duration,
    /// Share of the media datagrams dropped.
    loss: f64,
}

impl Link {
    /// 25 ms one way; half the media datagrams held back by up to `reorder_ms`.
    fn reordering(reorder_ms: u64, loss: f64) -> Self {
        Self {
            delay: Duration::from_millis(25),
            reorder_share: 0.5,
            reorder: Duration::from_millis(reorder_ms),
            loss,
        }
    }

    /// 25 ms one way; every media datagram held back by up to `jitter_ms` (the link of the
    /// audio pipeline's test).
    fn jittered(jitter_ms: u64, loss: f64) -> Self {
        Self {
            reorder_share: 1.0,
            ..Self::reordering(jitter_ms, loss)
        }
    }
}

struct Peer {
    pc: RTCPeerConnection,
    addr: SocketAddr,
    connected: bool,
    handles: DefaultInterceptorHandles,
}

impl Peer {
    fn new(addr: &str, seed: u64) -> Result<Self> {
        let provider: Arc<dyn RTCCryptoProvider> = Arc::new(SeededProvider {
            inner: default_provider()?,
            rng: Mutex::new(Rng(seed)),
        });
        let mut media_engine = MediaEngine::default();
        media_engine.register_default_codecs()?;
        // The sweep's `RTC_CB_PACKET_SIZE=last-frames` runs RFC 8083 section 3's s.
        let mut options = DefaultInterceptorOptions::default();
        options.rtcp_random = Some(provider.clone());
        if std::env::var("RTC_CB_PACKET_SIZE").as_deref() == Ok("last-frames") {
            options.circuit_breaker_packet_size = CircuitBreakerPacketSize::LastFrames;
        }
        let (mut registry, handles) = register_default_interceptors_with_options(
            Registry::new(),
            &mut media_engine,
            &options,
        )?;
        if WITHOUT_PACER.with(|w| w.get()) {
            // A sender whose packets are not held to the congestion controller's target.
            registry = registry.with(Slot::Pacer, PassThroughInterceptor::new());
        }
        let pc = RTCPeerConnectionBuilder::new()
            .with_configuration(RTCConfigurationBuilder::new().build())
            .with_setting_engine(
                SettingEngineBuilder::new()
                    .with_crypto_provider(provider)
                    .build(),
            )
            .with_media_engine(media_engine)
            .with_interceptor_registry(registry)
            .build(Instant::now())?;
        Ok(Self {
            pc,
            addr: addr.parse()?,
            connected: false,
            handles,
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
}

/// SRTP or SRTCP (RFC 7983: first byte 128 to 191).
fn is_media(data: &[u8]) -> bool {
    matches!(data.first(), Some(128..=191))
}

/// SRTP, not SRTCP (RFC 5761 4: RTCP packet types 192 to 223 in the second byte).
fn is_rtp(data: &[u8]) -> bool {
    is_media(data) && data.len() > 1 && !(192..=223).contains(&data[1])
}

struct InFlight {
    at: Instant,
    order: u64,
    from: SocketAddr,
    to: SocketAddr,
    data: BytesMut,
}

struct World {
    peers: [Peer; 2],
    now: Instant,
    link: Link,
    impaired: bool,
    rng: Rng,
    in_flight: Vec<InFlight>,
    order: u64,
    /// When the first peer put each RTP datagram on the wire.
    wire_rtp: Vec<Instant>,
    /// The SSRC and sequence number of each RTP datagram the first peer put on the wire
    /// (SRTP leaves the header in the clear).
    wire_sequence: Vec<(u32, u16)>,
    media_datagrams: u64,
    dropped: u64,
}

impl World {
    fn pump(&mut self) -> Result<()> {
        for i in 0..2 {
            while let Some(msg) = self.peers[i].pc.poll_write() {
                let mut at = self.now + self.link.delay;
                if self.impaired && is_media(&msg.message) {
                    self.media_datagrams += 1;
                    if self.rng.unit() < self.link.loss {
                        self.dropped += 1;
                        continue;
                    }
                    if self.rng.unit() < self.link.reorder_share {
                        at += self.link.reorder.mul_f64(self.rng.unit());
                    }
                }
                if i == 0 && is_rtp(&msg.message) {
                    self.wire_rtp.push(self.now);
                    let d = &msg.message;
                    if d.len() >= 12 {
                        self.wire_sequence.push((
                            u32::from_be_bytes([d[8], d[9], d[10], d[11]]),
                            u16::from_be_bytes([d[2], d[3]]),
                        ));
                    }
                }
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
            while let Some(event) = self.peers[i].pc.poll_event() {
                if let RTCPeerConnectionEvent::OnConnectionStateChangeEvent(state) = event {
                    if state == RTCPeerConnectionState::Failed {
                        bail!("peer {i} failed");
                    }
                    self.peers[i].connected = state == RTCPeerConnectionState::Connected;
                }
            }
            while self.peers[i].pc.poll_read().is_some() {}
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
            self.now = next.max(self.now + Duration::from_micros(100)).min(to);
            for peer in self.peers.iter_mut() {
                peer.pc.handle_timeout(self.now)?;
            }
            self.pump()?;
        }
        Ok(())
    }

    /// Two peers over host candidates, the first with a sendonly `kind` transceiver; the
    /// link's impairment starts once both are connected.
    fn connected(kind: RtpCodecKind, link: Link, seed: u64) -> Result<(Self, RTCRtpSenderId)> {
        let mut world = World {
            peers: [
                Peer::new("10.0.0.1:5000", seed ^ 0x1111)?,
                Peer::new("10.0.0.2:5000", seed ^ 0x2222)?,
            ],
            now: Instant::now(),
            link,
            impaired: false,
            rng: Rng(seed),
            in_flight: Vec::new(),
            order: 0,
            wire_rtp: Vec::new(),
            wire_sequence: Vec::new(),
            media_datagrams: 0,
            dropped: 0,
        };
        let transceiver = world.peers[0].pc.add_transceiver_from_kind(
            kind,
            Some(RTCRtpTransceiverInit {
                direction: RTCRtpTransceiverDirection::Sendonly,
                streams: vec![],
                send_encodings: vec![RTCRtpEncodingParameters {
                    active: true,
                    ..Default::default()
                }],
            }),
        )?;
        let sender = world.peers[0]
            .pc
            .rtp_transceiver(transceiver)
            .and_then(|t| t.sender())
            .expect("a sendonly transceiver has a sender");
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
        let start = world.now;
        while !world.peers.iter().all(|p| p.connected) {
            if world.now.duration_since(start) > Duration::from_secs(10) {
                bail!("not connected");
            }
            let t = world.now + Duration::from_millis(10);
            world.advance(t)?;
        }
        world.impaired = true;
        Ok((world, sender))
    }
}

/// What the sender writes every 20 ms.
#[derive(Clone, Copy, Debug)]
enum Shape {
    /// A constant rate, in kbit/s, split into packets of at most 1100 bytes.
    Constant(u32),
    /// Speech from an encoder that follows the congestion controller's target (about
    /// 300 kbit/s at the start): 400 ms of 750-byte frames, then 600 ms of 11-byte silence
    /// frames, over and over (the flow of the audio pipeline that found the false trip).
    Talkspurts,
}

impl Shape {
    /// The payload sizes of frame `frame`.
    fn frame(self, frame: u64) -> Vec<usize> {
        match self {
            Shape::Constant(kbps) => {
                let frame_bytes = (kbps as usize * 1000 / 8) / 50;
                let packets = frame_bytes.div_ceil(1100).max(1);
                vec![frame_bytes / packets; packets]
            }
            Shape::Talkspurts => vec![if frame % 50 < 20 { 750 } else { 11 }],
        }
    }
}

/// What one run measured.
#[derive(Debug)]
struct Outcome {
    /// The flows the breaker ceased, with when the first one did.
    ceased: Vec<(u32, String)>,
    ceased_at: Option<Duration>,
    /// RTP datagrams on the wire in the last second.
    sent_last_second: usize,
    /// The receiver's cumulative loss (RFC 3550) and its NACK count, the sender's
    /// retransmissions, from the stats.
    packets_lost: i64,
    nack_count: u32,
    retransmitted: u64,
    measured_loss: f64,
    /// RTP packets the application wrote, and how many of them left the sender (distinct
    /// sequence numbers of the media SSRC on the wire); how long after the last write the last
    /// one left, how many RTP datagrams left after the last write (the pacer's backlog), and
    /// the congestion controller's target at the last write.
    written: usize,
    left: usize,
    drained_in: Option<Duration>,
    left_after_end: usize,
    target_at_end: f64,
}

/// Writes `kind` RTP shaped as `shape` (20 ms frames, as Opus at 20 ms ptime) for `seconds`,
/// through the default interceptors, and reads what the breaker and the stats say.
fn run(kind: RtpCodecKind, shape: Shape, link: Link, seconds: u64, seed: u64) -> Result<Outcome> {
    let (mut world, sender) = World::connected(kind, link, seed)?;
    let (ssrc, pt, clock) = {
        let mut sender = world.peers[0].pc.rtp_sender(sender).expect("sender");
        let parameters = sender.get_parameters();
        let codec = &parameters.rtp_parameters.codecs[0];
        (
            parameters.encodings[0]
                .rtp_coding_parameters
                .ssrc
                .expect("an SSRC"),
            codec.payload_type,
            codec.rtp_codec.clock_rate,
        )
    };
    let start = world.now;
    let mut seq: u16 = 1;
    let mut written = 0usize;
    let mut ceased_at = None;
    for frame in 0..seconds * 50 {
        let now = start + Duration::from_millis(frame * 20);
        world.advance(now)?;
        let sizes = shape.frame(frame);
        let packets = sizes.len();
        for (part, size) in sizes.into_iter().enumerate() {
            written += 1;
            let header = Header {
                version: 2,
                payload_type: pt,
                sequence_number: seq,
                timestamp: (frame as u32).wrapping_mul(clock / 50),
                ssrc,
                marker: part + 1 == packets,
                ..Default::default()
            };
            seq = seq.wrapping_add(1);
            world.peers[0]
                .pc
                .rtp_sender(sender)
                .expect("sender")
                .write_rtp(
                    now,
                    rtc::rtp::Packet {
                        header,
                        payload: Bytes::from(vec![0x5au8; size]),
                    },
                )?;
        }
        world.pump()?;
        if ceased_at.is_none() && !world.peers[0].handles.circuit_breaker.ceased().is_empty() {
            ceased_at = Some(now.duration_since(start));
        }
    }
    let end = start + Duration::from_secs(seconds);
    let target_at_end = world.peers[0].handles.congestion_control.target_bitrate();
    let wire_before_end = world.wire_rtp.len();
    // Drain: what the pacer still holds leaves (the flows here write at a fixed rate whatever
    // the congestion controller's target, so it may hold seconds of media), then the last
    // packets arrive and the receiver reports them. A receiver report taken while a packet is
    // still on its way counts it lost (RFC 3550 6.4.1 at that instant), so the stats are read
    // only after this.
    let media_left = |world: &World| {
        world
            .wire_sequence
            .iter()
            .filter(|(s, _)| *s == ssrc)
            .map(|(_, seq)| *seq)
            .collect::<std::collections::HashSet<u16>>()
            .len()
    };
    let mut drained_in = None;
    while world.now < end + Duration::from_secs(60) {
        if media_left(&world) >= written {
            drained_in = Some(world.now.saturating_duration_since(end));
            break;
        }
        if !world.peers[0].handles.circuit_breaker.ceased().is_empty() {
            break;
        }
        let step = world.now + Duration::from_millis(100);
        world.advance(step)?;
    }
    let settled = world.now + Duration::from_secs(3);
    world.advance(settled)?;
    let left_after_end = world.wire_rtp.len() - wire_before_end;
    let ceased = world.peers[0]
        .handles
        .circuit_breaker
        .ceased()
        .into_iter()
        .map(|(ssrc, reason)| (ssrc, format!("{reason:?}")))
        .collect();
    let sent_last_second = world
        .wire_rtp
        .iter()
        .filter(|at| **at + Duration::from_secs(1) >= end && **at < end)
        .count();
    let now = world.now;
    let received = world.peers[1].pc.get_stats(now, StatsSelector::None);
    let (packets_lost, nack_count) = received
        .inbound_rtp_streams()
        .map(|s| (s.received_rtp_stream_stats.packets_lost, s.nack_count))
        .fold((0, 0), |(l, n), (a, b)| (l + a, n + b));
    let sent = world.peers[0].pc.get_stats(now, StatsSelector::None);
    let retransmitted = sent
        .outbound_rtp_streams()
        .map(|s| s.retransmitted_packets_sent)
        .sum();
    let left = media_left(&world);
    Ok(Outcome {
        ceased,
        ceased_at,
        sent_last_second,
        packets_lost,
        nack_count,
        retransmitted,
        measured_loss: world.dropped as f64 / world.media_datagrams.max(1) as f64,
        written,
        left,
        drained_in,
        left_after_end,
        target_at_end,
    })
}

/// RFC 8083: a 64 kbit/s audio flow (20 ms packets, as Opus) over a link that loses nothing
/// and holds half its datagrams back by up to 40 ms runs for a minute with the default
/// interceptors: no breaker fires (nothing times out, and reordering is not loss, so the
/// congestion breaker has nothing to compare), the sender is still sending at the end, and
/// the receiver's cumulative loss is back at zero (RFC 3550 6.4.1).
#[test]
fn an_audio_flow_over_a_lossless_reordering_link_is_never_stopped() -> Result<()> {
    let _ = env_logger::builder().is_test(true).try_init();
    let outcome = run(
        RtpCodecKind::Audio,
        Shape::Constant(64),
        Link::reordering(40, 0.0),
        60,
        7,
    )?;
    println!("{outcome:?}");
    assert!(outcome.ceased.is_empty(), "{outcome:?}");
    // The sender is still sending: every packet the application wrote left it (the pacer
    // may hold the last ones a moment past the last write).
    assert_eq!(outcome.left, outcome.written, "{outcome:?}");
    assert_eq!(outcome.packets_lost, 0, "{outcome:?}");
    Ok(())
}

/// The flow that found the false trip: speech at the congestion controller's starting target
/// and silence frames in between, over a link that delays every datagram by 0 to 40 ms and
/// loses none. Reordering left one report's fraction lost at 25/256 and the next at 0 (the
/// cumulative count back at 0); averaged over CB_INTERVAL with the silence frames' 23-byte
/// packet size, ten times TCP came out under the flow's rate and the congestion breaker
/// ceased the flow about a second in. The loss the breaker compares is now at most the share
/// the cumulative count says was lost, which is none.
#[test]
fn a_talkspurt_flow_over_a_lossless_jittered_link_is_never_stopped() -> Result<()> {
    let _ = env_logger::builder().is_test(true).try_init();
    for seed in [7, 11, 13] {
        let outcome = run(
            RtpCodecKind::Audio,
            Shape::Talkspurts,
            Link::jittered(40, 0.0),
            60,
            seed,
        )?;
        println!("seed {seed}: {outcome:?}");
        assert!(outcome.ceased.is_empty(), "seed {seed}: {outcome:?}");
        // Everything the application wrote left the sender. (Not packets per second in the
        // last second: when the congestion controller's target is below a talkspurt's rate
        // the pacer spreads it, and the last second can end mid-backlog.)
        assert_eq!(outcome.left, outcome.written, "seed {seed}: {outcome:?}");
        assert_eq!(outcome.packets_lost, 0, "seed {seed}: {outcome:?}");
    }
    Ok(())
}

/// RFC 8083 section 4.3 where it must fire: a sender that ignores the congestion controller
/// (the pacer taken out of the chain, so 8 Mbit/s reaches the wire whatever the target), over a
/// path that loses 20 % of its datagrams with a 50 ms round trip. Ten times the TCP throughput
/// for that loss is about 0.45 MB/s against the flow's 1 MB/s: the congestion breaker ceases
/// the flow. The same sender over 1 % loss (ten times TCP about 2 MB/s) keeps running.
#[test]
fn a_flow_far_above_the_tcp_rate_over_a_lossy_link_is_ceased() -> Result<()> {
    let _ = env_logger::builder().is_test(true).try_init();
    WITHOUT_PACER.with(|w| w.set(true));
    let congested = run(
        RtpCodecKind::Video,
        Shape::Constant(8000),
        Link::reordering(0, 0.2),
        30,
        7,
    );
    let light = run(
        RtpCodecKind::Video,
        Shape::Constant(8000),
        Link::reordering(0, 0.01),
        30,
        7,
    );
    WITHOUT_PACER.with(|w| w.set(false));
    let (congested, light) = (congested?, light?);
    println!("20 %: {congested:?}\n1 %: {light:?}");
    assert!(
        congested
            .ceased
            .iter()
            .any(|(_, reason)| reason == "Congestion"),
        "{congested:?}"
    );
    assert!(light.ceased.is_empty(), "{light:?}");
    Ok(())
}

/// The pacer's queue time is bounded at 2 s (libwebrtc's expected queue length). A 2 Mbit/s
/// source that ignores the target over a link that holds every datagram back by up to 40 ms,
/// where the congestion
/// controller settles under 1 Mbit/s: every packet leaves, the last one within about 2 s of its
/// write, and none is refused (the pacer once refused packets at a full queue of 4096, and the
/// receiver counted the holes as 4419 lost on a path that lost nothing).
#[test]
fn a_source_above_the_target_is_queued_two_seconds_at_most_and_loses_nothing() -> Result<()> {
    let _ = env_logger::builder().is_test(true).try_init();
    let outcome = run(
        RtpCodecKind::Video,
        Shape::Constant(2000),
        Link::jittered(40, 0.0),
        60,
        7,
    )?;
    println!("{outcome:?}");
    assert!(outcome.ceased.is_empty(), "{outcome:?}");
    assert_eq!(outcome.left, outcome.written, "{outcome:?}");
    assert!(
        outcome
            .drained_in
            .is_some_and(|d| d <= Duration::from_millis(2_100)),
        "{outcome:?}"
    );
    assert_eq!(outcome.packets_lost, 0, "{outcome:?}");
    Ok(())
}

/// A run is reproducible from its seed: the link's randomness, and everything the engine draws
/// (ICE, DTLS, SCTP through the setting engine's crypto provider, and the RTCP report times
/// through `DefaultInterceptorOptions::rtcp_random`), come from it. Two runs of one seed end
/// the same, to the packet.
#[test]
fn the_same_seed_gives_the_same_run() -> Result<()> {
    let once = || {
        run(
            RtpCodecKind::Video,
            Shape::Constant(500),
            Link::jittered(40, 0.02),
            20,
            3,
        )
        .map(|outcome| format!("{outcome:?}"))
    };
    let (first, second) = (once()?, once()?);
    assert_eq!(first, second);
    Ok(())
}

/// RFC 4585 / the NACK generator: reordering by up to 40 ms on a lossless link asks for no
/// retransmission storm. A 500 kbit/s video flow (VP8, NACK negotiated) over the same link.
#[test]
fn a_video_flow_over_a_lossless_reordering_link_is_not_repaired() -> Result<()> {
    let _ = env_logger::builder().is_test(true).try_init();
    let outcome = run(
        RtpCodecKind::Video,
        Shape::Constant(500),
        Link::reordering(40, 0.0),
        60,
        7,
    )?;
    println!("{outcome:?}");
    assert!(outcome.ceased.is_empty(), "{outcome:?}");
    // The sender is still sending: every packet the application wrote left it (the pacer
    // may hold the last ones a moment past the last write).
    assert_eq!(outcome.left, outcome.written, "{outcome:?}");
    assert_eq!(outcome.packets_lost, 0, "{outcome:?}");
    // About 3000 packets: the generator asks for the first few gaps, until it has seen how
    // late this path's overtaken packets come.
    assert!(outcome.nack_count <= 20, "{outcome:?}");
    assert!(outcome.retransmitted <= 20, "{outcome:?}");
    Ok(())
}

/// The video flow of the test above for the seeds in `RTC_CB_SEEDS` (default 1 to 20): each
/// run's outcome, for tracing a run that ends with a packet counted lost.
#[test]
#[ignore = "an investigation tool: prints one outcome per seed"]
fn video_seeds() -> Result<()> {
    let seeds: Vec<u64> = std::env::var("RTC_CB_SEEDS")
        .map(|s| s.split(',').filter_map(|x| x.parse().ok()).collect())
        .unwrap_or_else(|_| (1..=20).collect());
    for seed in seeds {
        let o = run(
            RtpCodecKind::Video,
            Shape::Constant(500),
            Link::reordering(40, 0.0),
            60,
            seed,
        )?;
        println!("seed {seed}: {o:?}");
    }
    Ok(())
}

/// Reordering 0/10/40/100 ms (every datagram held back by up to that) x loss 0/1/2/5/20/30 %
/// x 24/64/500/2000 kbit/s and the talkspurt flow, for 60 s each: where the breaker fires,
/// with the receiver's numbers. `RTC_CB_SWEEP_SECONDS` shortens the runs, `RTC_CB_SHAPES`
/// (`24,64,500,2000,speech`) picks the flows, `RTC_CB_PACKET_SIZE=last-frames` runs RFC 8083
/// section 3's packet size.
/// `cargo test --test circuit_breaker_reordering_rtc2rtc sweep -- --ignored --nocapture`
#[test]
#[ignore = "an investigation tool: prints the sweep table"]
fn sweep() -> Result<()> {
    let seconds: u64 = std::env::var("RTC_CB_SWEEP_SECONDS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(60);
    let shapes: Vec<Shape> = std::env::var("RTC_CB_SHAPES")
        .unwrap_or_else(|_| "24,64,500,2000,speech".to_owned())
        .split(',')
        .filter_map(|name| match name {
            "speech" => Some(Shape::Talkspurts),
            kbps => kbps.parse().ok().map(Shape::Constant),
        })
        .collect();
    println!(
        "| reorder ms | loss % (measured) | kbit/s | ceased | at s | RTP sent in the last s | target kbit/s at the end | backlog left in s | packetsLost |"
    );
    println!("|---|---|---|---|---|---|---|---|---|");
    for reorder in [0u64, 10, 40, 100] {
        for loss in [0.0, 0.01, 0.02, 0.05, 0.2, 0.3] {
            for shape in shapes.iter().copied() {
                let kbps = match shape {
                    Shape::Constant(kbps) => kbps.to_string(),
                    Shape::Talkspurts => "speech".to_owned(),
                };
                let o = run(
                    RtpCodecKind::Audio,
                    shape,
                    Link::jittered(reorder, loss),
                    seconds,
                    11,
                )?;
                println!(
                    "| {reorder} | {:.0} ({:.1}) | {kbps} | {} | {} | {} | {:.0} | {} ({} pkts) | {} |",
                    loss * 100.0,
                    o.measured_loss * 100.0,
                    if o.ceased.is_empty() {
                        "-".to_owned()
                    } else {
                        o.ceased
                            .iter()
                            .map(|(_, r)| r.clone())
                            .collect::<Vec<_>>()
                            .join(",")
                    },
                    o.ceased_at
                        .map_or("-".to_owned(), |d| format!("{:.1}", d.as_secs_f64())),
                    o.sent_last_second,
                    o.target_at_end / 1000.0,
                    o.drained_in
                        .map_or("-".to_owned(), |d| format!("{:.1}", d.as_secs_f64())),
                    o.left_after_end,
                    o.packets_lost,
                );
            }
        }
    }
    Ok(())
}
