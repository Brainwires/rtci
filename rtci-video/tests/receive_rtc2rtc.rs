//! The receive pipeline in a call between two `rtci` peer connections, in virtual time.
//!
//! One peer sends VP8 (with RTX) at a bitrate, from a source that makes a key frame when
//! asked (PLI); the other receives it through `rtci_video::engine::VideoReceiver`, decodes with
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

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Result, bail};
use bytes::{Bytes, BytesMut};
use rtci::crypto::{CryptoError, RTCCrypto, RTCCryptoProvider, RTCRandom, default_provider};
use rtci::interceptor::{
    GccHandle, GccInterceptorBuilder, Interceptor as _, NackGeneratorBuilder, Packet,
    PassThroughInterceptor, Registry, RtcpRandom, RtcpSessionBuilder, Slot, StreamInfo,
    TaggedPacket,
};
use rtci::media_stream::MediaStreamTrack;
use rtci::peer_connection::configuration::RTCConfigurationBuilder;
use rtci::peer_connection::configuration::interceptor_registry::{
    configure_key_frame_requests, configure_nack, configure_receiver_reference_time,
    configure_rtcp_reports_with, configure_twcc,
};
use rtci::peer_connection::configuration::media_engine::{
    MIME_TYPE_RTX, MIME_TYPE_VP8, MediaEngine,
};
use rtci::peer_connection::configuration::setting_engine::SettingEngineBuilder;
use rtci::peer_connection::event::{RTCPeerConnectionEvent, RTCTrackEvent};
use rtci::peer_connection::message::RTCMessage;
use rtci::peer_connection::state::RTCPeerConnectionState;
use rtci::peer_connection::transport::{
    CandidateConfig, CandidateHostConfig, RTCIceCandidate, RTCIceCandidateInit,
};
use rtci::peer_connection::{RTCPeerConnection, RTCPeerConnectionBuilder};
use rtci::rtcp::transport_feedbacks::transport_layer_nack::TransportLayerNack;
use rtci::rtp::packetizer::Packetizer;
use rtci::rtp_transceiver::rtp_sender::{
    RTCPFeedback, RTCRtpCodec, RTCRtpCodecParameters, RTCRtpCodingParameters,
    RTCRtpEncodingParameters, RTCRtpRtxParameters, RtpCodecKind,
};
use rtci::rtp_transceiver::{RTCRtpReceiverId, RTCRtpSenderId};
use rtci::sansio::Protocol;
use rtci::shared::{TaggedBytesMut, TransportContext, TransportProtocol};
use rtci_video::decoder::{DecodeError, ReferenceCheckingDecoder, VideoDecoder};
use rtci_video::engine::VideoReceiver;
use rtci_video::keyframe::KeyFrameReason;
use rtci_video::stats::ReceiveStats;
use rtci_video::{DecodeOutcome, ReceiveConfig};

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
const MEDIA_SSRC: u32 = 1001;
const RTX_SSRC: u32 = 1002;

/// The SSRC and sequence number of an SRTP packet (its header is in the clear).
fn rtp_header(data: &[u8]) -> Option<(u32, u16)> {
    if data.len() < 12 || !is_rtp(data) || (192..=223).contains(&data[1]) {
        return None;
    }
    let seq = u16::from_be_bytes([data[2], data[3]]);
    let ssrc = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);
    Some((ssrc, seq))
}

/// Whether `a` comes before `b` (RFC 3550 A.1 wrap-around).
fn before(a: u16, b: u16) -> bool {
    (1..0x8000).contains(&b.wrapping_sub(a))
}

/// Where a tap sits in an interceptor chain, which says what it records.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TapPoint {
    /// The receiver, right after its NACK generator (`Slot::Custom(10_550)`): NACKs as they are
    /// generated.
    ReceiverGenerator,
    /// The receiver, at the wire (`Slot::Custom(100)`, below the RTCP session): NACKs as they
    /// leave.
    ReceiverWire,
    /// The sender, at the wire: NACKs as they arrive (read leg), and RTX packets as they leave,
    /// by the original sequence number they carry (RFC 4588 4: the payload's first two bytes;
    /// still in the clear here, SRTP is applied after the chain).
    SenderWire,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TapEvent {
    NackGenerated,
    NackLeft,
    NackArrived,
    RtxLeft,
}

type TapLog = Arc<Mutex<Vec<(Instant, TapEvent, Vec<u16>)>>>;
/// Media sequence numbers lost for good: the uplink drops the original, and the sender's tap
/// every RTX copy.
type Doomed = Arc<Mutex<Vec<u16>>>;

struct Tap {
    point: TapPoint,
    log: TapLog,
    doomed: Doomed,
    read_queue: VecDeque<TaggedPacket>,
    write_queue: VecDeque<TaggedPacket>,
}

impl Tap {
    fn new(point: TapPoint, log: TapLog, doomed: Doomed) -> Self {
        Self {
            point,
            log,
            doomed,
            read_queue: VecDeque::new(),
            write_queue: VecDeque::new(),
        }
    }

    fn nacks(packet: &Packet) -> Vec<u16> {
        let Packet::Rtcp(packets) = packet else {
            return Vec::new();
        };
        packets
            .iter()
            .filter_map(|p| p.as_any().downcast_ref::<TransportLayerNack>())
            .filter(|n| n.media_ssrc == MEDIA_SSRC)
            .flat_map(|n| n.nacks.iter().flat_map(|pair| pair.packet_list()))
            .collect()
    }

    fn record(&self, at: Instant, event: TapEvent, seqs: Vec<u16>) {
        if !seqs.is_empty() {
            self.log.lock().expect("tap").push((at, event, seqs));
        }
    }
}

impl Protocol<TaggedPacket, TaggedPacket, ()> for Tap {
    type Rout = TaggedPacket;
    type Wout = TaggedPacket;
    type Eout = ();
    type Error = rtci::shared::error::Error;
    type Time = Instant;

    fn handle_read(&mut self, msg: TaggedPacket) -> Result<(), Self::Error> {
        if self.point == TapPoint::SenderWire {
            self.record(
                msg.now,
                TapEvent::NackArrived,
                Self::nacks(&msg.message.packet),
            );
        }
        self.read_queue.push_back(msg);
        Ok(())
    }
    fn poll_read(&mut self) -> Option<TaggedPacket> {
        self.read_queue.pop_front()
    }
    fn handle_write(&mut self, msg: TaggedPacket) -> Result<(), Self::Error> {
        match self.point {
            TapPoint::ReceiverGenerator => {
                self.record(
                    msg.now,
                    TapEvent::NackGenerated,
                    Self::nacks(&msg.message.packet),
                );
            }
            TapPoint::ReceiverWire => {
                self.record(
                    msg.now,
                    TapEvent::NackLeft,
                    Self::nacks(&msg.message.packet),
                );
            }
            TapPoint::SenderWire => {
                if let Packet::Rtp(p) = &msg.message.packet
                    && p.header.ssrc == RTX_SSRC
                    && p.payload.len() >= 2
                {
                    let osn = u16::from_be_bytes([p.payload[0], p.payload[1]]);
                    self.record(msg.now, TapEvent::RtxLeft, vec![osn]);
                    if self.doomed.lock().expect("doomed").contains(&osn) {
                        return Ok(());
                    }
                }
            }
        }
        self.write_queue.push_back(msg);
        Ok(())
    }
    fn poll_write(&mut self) -> Option<TaggedPacket> {
        self.write_queue.pop_front()
    }
}

impl rtci::interceptor::Interceptor for Tap {
    fn bind_local_stream(&mut self, _info: &StreamInfo) {}
    fn unbind_local_stream(&mut self, _info: &StreamInfo) {}
    fn bind_remote_stream(&mut self, _info: &StreamInfo) {}
    fn unbind_remote_stream(&mut self, _info: &StreamInfo) {}
}

/// What happened to one media packet the uplink lost, for the repair-latency trace.
#[derive(Debug, Default, Clone)]
struct Repair {
    /// When the uplink dropped it.
    dropped: Option<Instant>,
    /// When the first packet after it reached the receiver (the gap became visible).
    gap_seen: Option<Instant>,
    /// When its retransmission reached the receiving application.
    rtx_arrived: Option<Instant>,
}

/// The per-packet repair trace, and the NACKs for packets behind the receiver's NACK horizon.
#[derive(Debug, Default)]
struct RepairTrace {
    lost: BTreeMap<u16, Repair>,
    /// The receiver's NACK horizon over time.
    horizons: Vec<(Instant, u16)>,
    /// Both peers' taps.
    log: TapLog,
    /// Packets lost for good.
    doomed: Doomed,
}

/// What the taps saw, summed.
#[derive(Debug, Default)]
struct NackCounts {
    /// Sequence numbers the receiver's NACK generator asked for.
    asked: u64,
    /// Of those, the ones behind the horizon the pipeline had given before the NACK was made.
    behind_horizon: u64,
}

impl RepairTrace {
    fn horizon_at(&self, at: Instant) -> Option<u16> {
        self.horizons
            .iter()
            .rev()
            .find(|(t, _)| *t <= at)
            .map(|(_, h)| *h)
    }

    fn first(&self, event: TapEvent, seq: u16) -> Option<Instant> {
        self.log
            .lock()
            .expect("tap")
            .iter()
            .find(|(_, e, seqs)| *e == event && seqs.contains(&seq))
            .map(|(t, _, _)| *t)
    }

    fn count(&self, event: TapEvent, seq: u16) -> usize {
        self.log
            .lock()
            .expect("tap")
            .iter()
            .filter(|(_, e, seqs)| *e == event && seqs.contains(&seq))
            .count()
    }

    /// The last RTX packet carrying `seq` that left before `arrived`: the one that repaired it.
    fn rtx_left(&self, seq: u16, arrived: Option<Instant>) -> Option<Instant> {
        let arrived = arrived?;
        self.log
            .lock()
            .expect("tap")
            .iter()
            .filter(|(t, e, seqs)| *e == TapEvent::RtxLeft && *t <= arrived && seqs.contains(&seq))
            .map(|(t, _, _)| *t)
            .next_back()
    }

    fn nack_counts(&self) -> NackCounts {
        let mut c = NackCounts::default();
        for (t, e, seqs) in self.log.lock().expect("tap").iter() {
            if *e != TapEvent::NackGenerated {
                continue;
            }
            // The pipeline moves the horizon after the engine's timers of a millisecond, so a
            // NACK made at `t` was made with the horizon of the millisecond before at the latest.
            let horizon = t
                .checked_sub(Duration::from_millis(1))
                .and_then(|at| self.horizon_at(at));
            for &seq in seqs {
                c.asked += 1;
                if horizon.is_some_and(|h| before(seq, h)) {
                    c.behind_horizon += 1;
                }
            }
        }
        c
    }

    fn print(&self, name: &str, start: Instant) {
        let ms = |a: Option<Instant>, b: Option<Instant>| match (a, b) {
            (Some(a), Some(b)) if b >= a => format!("{:.0}", (b - a).as_secs_f64() * 1000.0),
            (Some(a), Some(b)) => format!("-{:.0}", (a - b).as_secs_f64() * 1000.0),
            _ => "-".to_owned(),
        };
        println!(
            "MEASURE TRACE {name}: seq | dropped at (ms into the call) | then ms after the gap \
             was seen: first NACK generated, first NACK left, first NACK arrived, RTX left (the \
             one that repaired), RTX arrived | NACKs generated for it, RTX packets sent"
        );
        for (&seq, r) in &self.lost {
            println!(
                "MEASURE TRACE {name}: {seq} | {} | {} {} {} {} {} | {} {}",
                ms(Some(start), r.dropped),
                ms(r.gap_seen, self.first(TapEvent::NackGenerated, seq)),
                ms(r.gap_seen, self.first(TapEvent::NackLeft, seq)),
                ms(r.gap_seen, self.first(TapEvent::NackArrived, seq)),
                ms(r.gap_seen, self.rtx_left(seq, r.rtx_arrived)),
                ms(r.gap_seen, r.rtx_arrived),
                self.count(TapEvent::NackGenerated, seq),
                self.count(TapEvent::RtxLeft, seq),
            );
        }
    }
}

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
    /// The real VP8 encoder and the synthetic source (feature `vp8`), instead of the
    /// rate-following fake frames; and each source picture by RTP timestamp.
    #[cfg(feature = "vp8")]
    real: Option<(
        rtci_video::codec::vp8::Vp8Encoder,
        rtci_video::picture::TestSource,
    )>,
    #[cfg(feature = "vp8")]
    sources: HashMap<u32, rtci_video::picture::I420Buffer>,
}

struct Receiver {
    pc: RTCPeerConnection,
    addr: SocketAddr,
    video: Option<VideoReceiver>,
    receiver_id: Option<RTCRtpReceiverId>,
    decoder: ReferenceCheckingDecoder,
    /// The real VP8 decoder, with the PSNR of each picture against its source.
    #[cfg(feature = "vp8")]
    real: Option<rtci_video::codec::vp8::Vp8Decoder>,
    #[cfg(feature = "vp8")]
    psnr: Vec<f64>,
    #[cfg(feature = "vp8")]
    real_errors: u32,
    renders: VecDeque<(Instant, u32)>,
    corrupt: u32,
    /// Delta pictures decoded without the picture before them (the source's own numbering).
    broken_chain: u32,
    last_number: Option<u32>,
    reasons: Vec<(Duration, KeyFrameReason)>,
    first_render: Option<Instant>,
}

fn build_pc(
    seed: u64,
    send: bool,
    nack_interval: Option<Duration>,
    log: TapLog,
    doomed: Doomed,
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
    let mut registry = configure_nack(Registry::new(), &mut media_engine);
    if let Some(interval) = nack_interval {
        registry = registry.with(
            Slot::NackGenerator,
            NackGeneratorBuilder::new().with_interval(interval).build(),
        );
    }
    let registry = configure_rtcp_reports_with(
        registry,
        RtcpSessionBuilder::new()
            .with_t_rr_interval(Duration::ZERO)
            .with_random(SeededRtcpRandom(Rng(seed ^ 0x5eed))),
    );
    configure_receiver_reference_time(&mut media_engine);
    let registry = configure_key_frame_requests(registry);
    let (gcc, handle) = GccInterceptorBuilder::new();
    // Without bandwidth probing (the builder probes by default). This file is about the
    // receiving pipeline, and its calls are those of a sender that does not probe: most send
    // at a fixed rate, and the one that follows the estimate
    // (`a_capacity_drop_and_recovery_leaves_no_long_freeze`) meets its cap 10 s into the call
    // while the estimate is still climbing at 8% a second, which is the call its one-second
    // bound was set on. With the start-up clusters that call stands at 2.5 Mbit/s when the
    // cap comes and its one seed renders nothing for 1.13 s: the price of a collapse from
    // the path's rate, which `tests/capacity_instrument.rs` measures over ensembles (cells
    // `cap/parolnet/..`) and the changelog states.
    let registry = configure_twcc(registry, &mut media_engine)?.with(
        Slot::CongestionControl,
        PassThroughInterceptor::new().with(
            gcc.with_min_bitrate(100_000)
                .with_max_bitrate(2_500_000)
                .with_bandwidth_probing(false)
                .build(),
        ),
    );
    let registry = if send {
        registry.with(
            Slot::Custom(100),
            Tap::new(TapPoint::SenderWire, log, doomed),
        )
    } else {
        registry
            .with(
                Slot::Custom(100),
                Tap::new(TapPoint::ReceiverWire, log.clone(), doomed.clone()),
            )
            .with(
                Slot::Custom(10_550),
                Tap::new(TapPoint::ReceiverGenerator, log, doomed),
            )
    };
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
    trace: RepairTrace,
}

fn is_rtp(data: &[u8]) -> bool {
    matches!(data.first(), Some(128..=191))
}

impl Call {
    fn new(link: Link, seed: u64, fixed_bitrate: Option<u32>) -> Result<Self> {
        Self::with_nack(link, seed, fixed_bitrate, None)
    }

    /// `nack_interval`: the receiver's NACK generator cycle (`None`: the engine default,
    /// 100 ms).
    fn with_nack(
        link: Link,
        seed: u64,
        fixed_bitrate: Option<u32>,
        nack_interval: Option<Duration>,
    ) -> Result<Self> {
        let trace = RepairTrace::default();
        let (spc, gcc, track) =
            build_pc(seed, true, None, trace.log.clone(), trace.doomed.clone())?;
        let (rpc, _, _) = build_pc(
            seed ^ 0xabcd,
            false,
            nack_interval,
            trace.log.clone(),
            trace.doomed.clone(),
        )?;
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
                #[cfg(feature = "vp8")]
                real: None,
                #[cfg(feature = "vp8")]
                sources: HashMap::new(),
            },
            receiver: Receiver {
                pc: rpc,
                addr: "10.0.0.2:5000".parse()?,
                video: None,
                receiver_id: None,
                decoder: ReferenceCheckingDecoder::new((320, 240)),
                #[cfg(feature = "vp8")]
                real: None,
                #[cfg(feature = "vp8")]
                psnr: Vec::new(),
                #[cfg(feature = "vp8")]
                real_errors: 0,
                renders: VecDeque::new(),
                corrupt: 0,
                broken_chain: 0,
                last_number: None,
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
            trace,
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
        while !(call.connected[0] && call.connected[1]) {
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
        #[cfg(feature = "vp8")]
        let mut source_picture = None;
        #[cfg(feature = "vp8")]
        let data = if let Some((enc, src)) = &mut self.sender.real {
            use rtci_video::encoder::VideoEncoder;
            enc.set_bitrate(bitrate);
            let picture = src.next_picture();
            let Some(f) = enc
                .encode(&picture.view(), key)
                .map_err(|e| anyhow::anyhow!("{e}"))?
            else {
                return Ok(());
            };
            source_picture = Some(picture);
            Bytes::from(f.data)
        } else {
            Bytes::from(self.sender.source.next_frame(bitrate, key))
        };
        #[cfg(not(feature = "vp8"))]
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
            self.sender.packetizer = Some(Box::new(rtci::rtp::packetizer::new_packetizer(
                now,
                RTP_MTU,
                codec.payload_type,
                ssrc,
                codec.rtp_codec.payloader()?,
                Box::new(rtci::rtp::sequence::new_fixed_sequencer(4000)),
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
            #[cfg(feature = "vp8")]
            if let Some(picture) = source_picture {
                self.sender.sources.insert(p.header.timestamp, picture);
            }
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
            let header = rtp_header(&msg.message);
            let doomed = header.is_some_and(|(ssrc, seq)| {
                ssrc == MEDIA_SSRC && self.trace.doomed.lock().expect("doomed").contains(&seq)
            });
            let at = if doomed {
                None
            } else if is_rtp(&msg.message) {
                self.uplink(msg.message.len())
            } else {
                Some(now + self.link.delay)
            };
            if (self.impaired || doomed)
                && let Some((MEDIA_SSRC, seq)) = header
                && at.is_none()
            {
                self.trace.lost.entry(seq).or_default().dropped = Some(now);
            }
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
            if to_receiver && let Some((MEDIA_SSRC, seq)) = rtp_header(&data) {
                for (_, r) in self
                    .trace
                    .lost
                    .iter_mut()
                    .filter(|(lost, r)| r.gap_seen.is_none() && before(**lost, seq))
                {
                    r.gap_seen = Some(now);
                }
            }
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
                let seq = packet.header.sequence_number;
                if packet.header.ssrc == MEDIA_SSRC
                    && let Some(r) = self.trace.lost.get_mut(&seq)
                    && r.rtx_arrived.is_none()
                {
                    // The original was dropped: this is its retransmission.
                    r.rtx_arrived = Some(now);
                }
                v.handle_rtp(now, &packet);
            }
        }
        self.receive(now)?;
        if let Some(h) = self
            .receiver
            .video
            .as_mut()
            .and_then(|v| v.pipeline(MEDIA_SSRC))
            .and_then(|p| p.nack_horizon())
            .map(|seq| seq as u16)
            && self
                .trace
                .horizons
                .last()
                .is_none_or(|(_, last)| *last != h)
        {
            self.trace.horizons.push((now, h));
        }
        Ok(())
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
            let data = request.frame.data();
            if data.len() >= 14 {
                let number = u32::from_be_bytes([data[10], data[11], data[12], data[13]]);
                let key = data[0] & 1 == 0;
                if !key && r.last_number.is_none_or(|l| number != l + 1) {
                    r.broken_chain += 1;
                }
                r.last_number = Some(number);
            }
            #[cfg(feature = "vp8")]
            if let Some(real) = &mut r.real {
                match real.decode(&request.frame) {
                    Ok(Some(_)) => {
                        let src = self.sender.sources.get(&request.frame.frame.rtp_timestamp);
                        if let (Some(src), Some(p)) = (src, real.picture()) {
                            r.psnr.extend(rtci_video::picture::psnr(&src.view(), &p));
                        }
                    }
                    Ok(None) => {}
                    Err(_) => r.real_errors += 1,
                }
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
         sender {} corrupt {} decoder errors {} retransmitted packets {} repair delay mean {:.0} ms max {:.0} ms",
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
        s.packets_retransmitted,
        1000.0 * s.total_repair_delay / s.packets_retransmitted.max(1) as f64,
        1000.0 * s.max_repair_delay,
    );
    s
}

/// The pipeline adds no wait of its own to a repair: the longest interval between rendered
/// pictures is at most the slowest retransmission plus a frame interval and the render delay's
/// margin. (The freezes themselves are the repairs' latency: the engine's NACK generator and
/// responder bring a lost packet back 0.2-0.4 s after its gap on this link, against one round
/// trip, about 70 ms; docs/video-pipeline.md, phase 1.)
fn assert_no_wait_beyond_repair(s: &ReceiveStats) {
    let bound = s.max_repair_delay + 0.1;
    assert!(
        s.longest_render_interval <= bound,
        "longest interval {:.0} ms, slowest repair {:.0} ms",
        s.longest_render_interval * 1000.0,
        s.max_repair_delay * 1000.0
    );
}

#[test]
fn two_percent_loss_with_reordering_waits_only_for_repairs() -> Result<()> {
    let mut call = Call::new(Link::lossy(0.02, 40), 11, Some(500_000))?;
    call.run_for(Duration::from_secs(30))?;
    let s = report("2% loss, 25 ms + 0..40 ms, 500 kbit/s, 30 s", &mut call);
    call.trace.print("2% loss", call.start);
    let nacks = call.trace.nack_counts();
    println!(
        "MEASURE horizon, 2% loss: sequence numbers asked for {}, behind the horizon {}",
        nacks.asked, nacks.behind_horizon
    );
    assert!(nacks.asked > 0, "the taps see the NACKs");
    assert_eq!(
        nacks.behind_horizon, 0,
        "NACKs for packets behind the horizon"
    );
    assert_eq!(call.receiver.corrupt, 0, "every picture decoded as sent");
    assert_eq!(
        call.receiver.decoder.errors, 0,
        "decode order allowed by the references"
    );
    assert_eq!(
        call.receiver.broken_chain, 0,
        "no delta picture without its predecessor"
    );
    assert!(s.frames_decoded > 870, "decoded {}", s.frames_decoded);
    assert_eq!(s.frames_dropped, 0);
    assert_no_wait_beyond_repair(&s);
    Ok(())
}

#[test]
fn ten_percent_loss_waits_only_for_repairs() -> Result<()> {
    let mut call = Call::new(Link::lossy(0.10, 40), 12, Some(500_000))?;
    call.run_for(Duration::from_secs(30))?;
    let s = report("10% loss, 25 ms + 0..40 ms, 500 kbit/s, 30 s", &mut call);
    assert_eq!(call.receiver.corrupt, 0);
    assert_eq!(call.receiver.decoder.errors, 0);
    assert_eq!(call.receiver.broken_chain, 0);
    assert!(s.frames_decoded > 800, "decoded {}", s.frames_decoded);
    assert_no_wait_beyond_repair(&s);
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
    let nacks = call.trace.nack_counts();
    println!(
        "MEASURE horizon, capacity: sequence numbers asked for {}, behind the horizon {}, \
         horizon moves {}",
        nacks.asked,
        nacks.behind_horizon,
        call.trace.horizons.len()
    );
    // Phase 1b acceptance (docs/video-pipeline.md): the receiver's NACK generator asks for no
    // packet of a picture the pipeline already released or gave up.
    assert!(nacks.asked > 0, "the taps see the NACKs");
    assert!(!call.trace.horizons.is_empty(), "the horizon moves");
    assert_eq!(
        nacks.behind_horizon, 0,
        "NACKs for packets behind the horizon"
    );
    assert_eq!(call.receiver.corrupt, 0);
    assert_eq!(call.receiver.decoder.errors, 0);
    assert_eq!(call.receiver.broken_chain, 0);
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
    // libwebrtc's estimate for uniform 0..40 ms jitter is about 20 ms (2.33 sigma - 30 ms
    // + 10 ms, sigma = 40 / sqrt(6)); the buffer holds what that leaves of each frame's
    // lateness. No frame is lost to it and none freezes.
    assert!(
        (10.0..=60.0).contains(&mean),
        "mean jitter buffer delay {mean:.1} ms"
    );
    assert_eq!(s.freeze_count, 0);
    assert_eq!(s.frames_dropped, 0);
    Ok(())
}

/// RFC 4588 6.3 in a call: a packet lost for good (the original and every retransmission)
/// leaves the pictures after it undecodable; the pipeline asks for a key frame after its
/// repair window and plays on from it. From the moment playout has passed the lost packet,
/// the receiver's NACK generator asks for it no more (phase 1b: `set_nack_horizon`); without
/// the horizon it would keep asking for as long as its receive log holds the packet.
#[test]
fn a_packet_lost_for_good_is_not_asked_for_once_playout_has_passed_it() -> Result<()> {
    let mut call = Call::new(Link::lossy(0.0, 0), 15, Some(500_000))?;
    call.run_for(Duration::from_secs(3))?;
    let next = call
        .trace
        .horizons
        .last()
        .map(|(_, h)| *h)
        .expect("pictures played");
    // A packet about a second ahead of playout, lost for good.
    let doomed = next.wrapping_add(60);
    call.trace.doomed.lock().expect("doomed").push(doomed);
    call.run_for(Duration::from_secs(10))?;
    let s = report("a packet lost for good", &mut call);
    let nacks = call.trace.nack_counts();
    let asked = call.trace.count(TapEvent::NackGenerated, doomed);
    let passed = call
        .trace
        .horizons
        .iter()
        .find(|(_, h)| before(doomed, *h))
        .map(|(t, _)| *t);
    println!(
        "MEASURE horizon, lost for good: seq {doomed} asked for {asked} times, playout passed it \
         {:?} ms into the call, sequence numbers asked for {} of which behind the horizon {}",
        passed.map(|t| t.duration_since(call.start).as_millis()),
        nacks.asked,
        nacks.behind_horizon
    );
    assert!(asked > 0, "the lost packet was asked for");
    assert!(passed.is_some(), "playout went past the lost packet");
    assert!(
        s.key_frame_requests
            .contains_key(&KeyFrameReason::RepairWindow),
        "a key frame after the repair window: {:?}",
        s.key_frame_requests
    );
    assert_eq!(call.receiver.corrupt, 0);
    assert_eq!(call.receiver.decoder.errors, 0);
    assert_eq!(
        nacks.behind_horizon, 0,
        "NACKs for packets behind the horizon"
    );
    Ok(())
}

/// The real VP8 encoder and decoder (feature `vp8`) in the two-peer call at 2 % loss: the
/// encoder follows the rate the test sets, the pipeline releases only what decodes, and every
/// picture the real decoder makes is close to its source (no corrupt picture, no decoder
/// error); freezes are the repairs', as in the call without real codecs.
#[cfg(feature = "vp8")]
#[test]
fn a_call_with_the_real_vp8_codecs_decodes_every_released_picture() -> Result<()> {
    use rtci_video::codec::vp8::{Vp8Decoder, Vp8Encoder};
    use rtci_video::picture::TestSource;
    let mut call = Call::new(Link::lossy(0.02, 40), 16, Some(500_000))?;
    call.sender.real = Some((
        Vp8Encoder::new(320, 240, FPS, 500_000).map_err(|e| anyhow::anyhow!("{e}"))?,
        TestSource::new(320, 240),
    ));
    call.sender.force_key = true;
    call.receiver.real = Some(Vp8Decoder::new());
    call.run_for(Duration::from_secs(20))?;
    let s = report("real VP8, 2% loss, 320x240, 500 kbit/s, 20 s", &mut call);
    let psnr = &call.receiver.psnr;
    let mean = psnr.iter().sum::<f64>() / psnr.len().max(1) as f64;
    let worst = psnr.iter().copied().fold(f64::INFINITY, f64::min);
    println!(
        "MEASURE real VP8 call: {} pictures decoded by vp8-decoder, PSNR mean {mean:.2} dB worst \
         {worst:.2} dB, decoder errors {}",
        psnr.len(),
        call.receiver.real_errors
    );
    assert_eq!(call.receiver.corrupt, 0, "every picture as sent");
    assert_eq!(
        call.receiver.real_errors, 0,
        "the real decoder decodes every released picture"
    );
    assert!(
        psnr.len() as u32 + 5 >= s.frames_decoded,
        "{} of {}",
        psnr.len(),
        s.frames_decoded
    );
    assert!(s.frames_decoded > 550, "decoded {}", s.frames_decoded);
    assert!(worst > 28.0, "worst picture {worst:.2} dB");
    assert_no_wait_beyond_repair(&s);
    Ok(())
}
