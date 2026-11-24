//! The VP8 stream of `testenv_impairment::vp8_file_through_nack_and_jitter_buffer` (NACK, a
//! jitter buffer, depacketized into an IVF file) between two `rtc` peers in virtual time, over a
//! model of the netem link that test runs on: `delay 40ms 20ms distribution normal loss 2%
//! reorder 10% 50%` on each host's egress, the testenv driver's loop (a pass every 0.5 to 0.8
//! ms, `handle_timeout` only when `poll_timeout` is due) and frames like its fixture's (one RTP
//! packet each). Seeded: a seed fails the same way every time, and each loss can be traced
//! (`vp8_seeds`).
//!
//! The netem test asked for 98 % of the frames with a 250 ms jitter buffer and failed now and
//! then (292 of 300 once, 240 of 300 once). Traced here over seeds 1 to 400, a 250 ms buffer
//! plays only about 45 % of the packets the link lost: the retransmission of the others comes
//! after the buffer has played past them. Neither the NACK generator nor the responder is
//! slow by mistake; the time goes to:
//!
//! - RFC 4585 section 3.5.2, step 6: after an Early RTCP packet the receiver "MUST set
//!   allow_early = FALSE, MUST recalculate tn = tp + 2*T_rr", so feedback for the next loss
//!   waits for the next Regular packet. A 70 kbit/s stream measures a session bandwidth of
//!   about that, 5 % of it for RTCP (RFC 3550 6.2), so T_rr is about 370 ms here and a second
//!   loss within about 750 ms of a first waits up to that long. About half the late
//!   retransmissions (64 of 125 over seeds 1 to 40) had their NACK held so.
//! - The other half: the gap is seen when the next packet arrives (median 76 ms after the
//!   lost one was sent), the first request waits for the reordering the stream has shown (RFC
//!   4588 section 6.3; about 50 ms on this link) on the generator's 100 ms ticks (median 159 ms
//!   from the gap), then a round trip of 80 +- 28 ms: past the deadline, about 280 ms after
//!   the lost packet was sent.
//!
//! So how many frames a 250 ms buffer plays on this link is luck (the number of losses and
//! how close together they come): 43 of seeds 1 to 400 play fewer than 98 %. What the engine
//! does guarantee is tested here instead: every frame played is one that was sent, whole and in
//! order; every loss the receiver can detect is retransmitted; a packet that reaches the
//! receiver before the jitter buffer has played past its place is played; and with a jitter
//! buffer deeper than the feedback delay above (2 s), every loss the receiver can detect is
//! repaired (seeds 1 to 200: all 1162 of them). A loss no receiver can detect is the first
//! packet of the stream (RFC 4585 section 6.2.1: a Generic NACK names packets missing between
//! ones received; nothing tells the receiver a packet came before its first) and the last.

use anyhow::{Result, bail};
use bytes::{Bytes, BytesMut};
use rtc::crypto::{CryptoError, RTCCrypto, RTCCryptoProvider, RTCRandom, default_provider};
use rtc::interceptor::{JitterBufferBuilder, Registry, Slot};
use rtc::media::io::Writer;
use rtc::media::io::ivf_reader::{IVFFileHeader, IVFReader};
use rtc::media::io::ivf_writer::IVFWriter;
use rtc::media_stream::MediaStreamTrack;
use rtc::peer_connection::configuration::interceptor_registry::configure_nack;
use rtc::peer_connection::configuration::media_engine::{MIME_TYPE_VP8, MediaEngine};
use rtc::peer_connection::configuration::setting_engine::SettingEngineBuilder;
use rtc::peer_connection::event::RTCPeerConnectionEvent;
use rtc::peer_connection::message::RTCMessage;
use rtc::peer_connection::state::RTCPeerConnectionState;
use rtc::peer_connection::transport::{
    CandidateConfig, CandidateHostConfig, RTCIceCandidate, RTCIceCandidateInit,
};
use rtc::peer_connection::{RTCPeerConnection, RTCPeerConnectionBuilder};
use rtc::rtp::packetizer::Packetizer;
use rtc::rtp_transceiver::RTCRtpSenderId;
use rtc::rtp_transceiver::rtp_sender::{
    RTCRtpCodec, RTCRtpCodecParameters, RTCRtpCodingParameters, RTCRtpEncodingParameters,
    RtpCodecKind,
};
use rtc::sansio::Protocol;
use rtc::shared::{TaggedBytesMut, TransportContext, TransportProtocol};
use std::collections::BTreeMap;
use std::io::Cursor;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// SplitMix64: reproducible, not good.
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

    /// Standard normal (Box-Muller).
    fn normal(&mut self) -> f64 {
        let u1 = self.unit().max(f64::MIN_POSITIVE);
        let u2 = self.unit();
        (-2.0 * u1.ln()).sqrt() * (2.0 * std::f64::consts::PI * u2).cos()
    }
}

/// The built-in crypto provider drawing its randomness from a seeded [`Rng`].
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

/// One host's netem qdisc: `delay D J distribution normal loss L reorder R C`. As netem does
/// it: loss first; then (reorder with gap 1) a correlated draw sends the packet at once, else it
/// waits D plus J times a normal deviate (never less than nothing); packets leave in the order
/// of their time to send, so jitter reorders too.
#[derive(Clone, Copy, Debug)]
struct NetemSpec {
    delay: Duration,
    jitter: Duration,
    loss: f64,
    reorder: f64,
    reorder_correlation: f64,
}

impl NetemSpec {
    /// The impairment of `vp8_file_through_nack_and_jitter_buffer`.
    fn testenv() -> Self {
        Self {
            delay: Duration::from_millis(40),
            jitter: Duration::from_millis(20),
            loss: 0.02,
            reorder: 0.10,
            reorder_correlation: 0.5,
        }
    }
}

struct Netem {
    spec: NetemSpec,
    rng: Rng,
    reorder_last: f64,
}

impl Netem {
    /// The delay of the next packet, `None` when it is lost.
    fn delay(&mut self) -> Option<Duration> {
        if self.rng.unit() < self.spec.loss {
            return None;
        }
        // netem's get_crandom: value = rnd * (1 - rho) + last * rho.
        let rho = self.spec.reorder_correlation;
        let value = self.rng.unit() * (1.0 - rho) + self.reorder_last * rho;
        self.reorder_last = value;
        if value < self.spec.reorder {
            return Some(Duration::ZERO);
        }
        let ms = self.spec.delay.as_secs_f64() * 1000.0
            + self.spec.jitter.as_secs_f64() * 1000.0 * self.rng.normal();
        Some(Duration::from_secs_f64(ms.max(0.0) / 1000.0))
    }
}

const VP8_PT: u8 = 96;
const SSRC: u32 = 0x0bad_cafe;

fn vp8_codec() -> RTCRtpCodec {
    RTCRtpCodec {
        mime_type: MIME_TYPE_VP8.to_owned(),
        clock_rate: 90000,
        channels: 0,
        sdp_fmtp_line: String::new(),
        rtcp_feedback: vec![],
    }
}

/// What a run is set up with.
#[derive(Clone, Copy, Debug)]
struct Setup {
    netem: NetemSpec,
    depth: Duration,
    /// The driver's loop: `sleep(500 us)` plus the time a pass takes, drawn per pass up to this.
    loop_overhead: Duration,
}

impl Setup {
    fn testenv() -> Self {
        Self {
            netem: NetemSpec::testenv(),
            depth: Duration::from_millis(250),
            loop_overhead: Duration::from_micros(300),
        }
    }
}

struct Peer {
    pc: RTCPeerConnection,
    addr: SocketAddr,
    connected: bool,
}

impl Peer {
    fn new(addr: &str, now: Instant, seed: u64, depth: Duration) -> Result<Self> {
        let mut me = MediaEngine::default();
        me.register_codec(
            RTCRtpCodecParameters {
                rtp_codec: vp8_codec(),
                payload_type: VP8_PT,
            },
            RtpCodecKind::Video,
        )?;
        let registry = configure_nack(Registry::new(), &mut me).with(
            Slot::JitterBuffer,
            JitterBufferBuilder::new().with_depth(depth).build(),
        );
        let provider = Arc::new(SeededProvider {
            inner: default_provider()?,
            rng: Mutex::new(Rng(seed)),
        });
        let pc = RTCPeerConnectionBuilder::new()
            .with_media_engine(me)
            .with_interceptor_registry(registry)
            .with_setting_engine(
                SettingEngineBuilder::new()
                    .with_crypto_provider(provider)
                    .build(),
            )
            .build(now)?;
        Ok(Self {
            pc,
            addr: addr.parse()?,
            connected: false,
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

/// SRTP or SRTCP (RFC 7983).
fn is_media(data: &[u8]) -> bool {
    matches!(data.first(), Some(128..=191))
}

/// SRTCP: RFC 5761 4, the packet type in the second byte.
fn rtcp_type(data: &[u8]) -> Option<u8> {
    (is_media(data) && data.len() > 1 && (192..=223).contains(&data[1])).then(|| data[1])
}

/// The SSRC and sequence number of an SRTP packet (the header is in the clear).
fn rtp_id(data: &[u8]) -> Option<(u32, u16)> {
    (is_media(data) && rtcp_type(data).is_none() && data.len() >= 12).then(|| {
        (
            u32::from_be_bytes([data[8], data[9], data[10], data[11]]),
            u16::from_be_bytes([data[2], data[3]]),
        )
    })
}

/// A datagram on the link and what became of it.
#[derive(Clone, Debug)]
struct Wire {
    sent: Instant,
    arrived: Option<Instant>,
}

struct InFlight {
    at: Instant,
    order: u64,
    from: SocketAddr,
    to: SocketAddr,
    data: BytesMut,
}

/// 300 frames like the fixture's (`videotestsrc pattern=ball`, 640x480 at 30 fps, a key frame
/// every 60): a black picture with a small ball, so every frame fits one RTP packet (the
/// test-env logs show as many packets written as frames): key frames of 700 to 1100 bytes, the
/// others 60 to 500. Each is unique, and the first byte carries the VP8 frame tag's key-frame
/// bit (RFC 6386 section 9.1: 0 for a key frame).
fn frames() -> Vec<Bytes> {
    let mut rng = Rng(0xf7a3_0001);
    (0..300u32)
        .map(|i| {
            let key = i % 60 == 0;
            let len = if key {
                700 + (rng.next_u64() % 400) as usize
            } else {
                60 + (rng.next_u64() % 440) as usize
            };
            let mut f: Vec<u8> = (0..len).map(|_| rng.next_u64() as u8).collect();
            f[0] = if key { 0x10 } else { 0x11 };
            f[1..5].copy_from_slice(&i.to_be_bytes());
            Bytes::from(f)
        })
        .collect()
}

/// What one run saw.
struct Run {
    /// The frames written, and the sequence number of each one's packet.
    frames: Vec<Bytes>,
    sequence_numbers: Vec<u16>,
    /// The frames of the IVF file the receiver wrote, in order.
    played: Vec<Bytes>,
    /// Each copy of each RTP packet the sender put on the link: when, and when it arrived.
    rtp_wire: BTreeMap<u16, Vec<Wire>>,
    /// When the receiver first read each packet, and when its jitter buffer released it.
    delivered: BTreeMap<u16, Instant>,
    released: BTreeMap<u16, Instant>,
    /// Each RTCP packet the receiver sent: its packet type, when, and when it arrived.
    rtcp_wire: Vec<(u8, Wire)>,
    start: Instant,
}

impl Run {
    /// The packets the link lost on their first transmission.
    fn lost(&self) -> Vec<u16> {
        self.rtp_wire
            .iter()
            .filter(|(_, sends)| sends[0].arrived.is_none())
            .map(|(seq, _)| *seq)
            .collect()
    }

    /// Whether the receiver can tell `seq` is missing: it read a packet before it and one
    /// after it (RFC 4585 section 6.2.1).
    fn detectable(&self, seq: u16) -> bool {
        self.delivered.range(..seq).next().is_some()
            && self.delivered.range(seq + 1..).next().is_some()
    }

    /// The frame indices of what the receiver played; an error for a frame that was never
    /// sent (a corrupt or merged one).
    fn played_indices(&self) -> Result<Vec<usize>, String> {
        self.played
            .iter()
            .map(|f| {
                self.frames
                    .iter()
                    .position(|s| s == f)
                    .ok_or_else(|| format!("a played frame of {} bytes was never sent", f.len()))
            })
            .collect()
    }

    /// Every frame played is a sent one, whole, and they are played in the order sent.
    fn check_played_frames_are_sent_frames_in_order(&self) -> Result<(), String> {
        let played = self.played_indices()?;
        if let Some(w) = played.windows(2).find(|w| w[0] >= w[1]) {
            return Err(format!("frame {} played after frame {}", w[1], w[0]));
        }
        Ok(())
    }

    /// Every loss the receiver can detect is retransmitted: the generator asks for it and the
    /// responder sends it again (RFC 4585 section 6.2.1, RFC 4588 section 3).
    fn check_every_detectable_loss_is_retransmitted(&self) -> Result<(), String> {
        let missing: Vec<u16> = self
            .lost()
            .into_iter()
            .filter(|seq| self.detectable(*seq) && self.rtp_wire[seq].len() < 2)
            .collect();
        if missing.is_empty() {
            Ok(())
        } else {
            Err(format!("lost and never retransmitted: {missing:?}"))
        }
    }

    /// A packet the receiver read before its jitter buffer released a later one is played: the
    /// buffer drops only what comes after it has played past its place.
    fn check_every_packet_in_time_is_played(&self) -> Result<(), String> {
        let dropped: Vec<String> = self
            .sequence_numbers
            .iter()
            .filter_map(|seq| {
                let read = *self.delivered.get(seq)?;
                let passed = self.released.range(seq + 1..).map(|(_, t)| *t).min();
                (passed.is_none_or(|passed| read <= passed) && !self.released.contains_key(seq))
                    .then(|| format!("seq {seq} read at {}", self.ms(read)))
            })
            .collect();
        if dropped.is_empty() {
            Ok(())
        } else {
            Err(format!("read in time and not played: {dropped:?}"))
        }
    }

    /// Every packet whose loss the receiver can detect is played: the frames played are the
    /// frames sent from the first key frame the receiver read, apart from frames whose
    /// packet's loss no receiver can detect (the first and the last of the stream).
    fn check_every_detectable_loss_is_repaired(&self) -> Result<(), String> {
        let unrepaired: Vec<u16> = self
            .lost()
            .into_iter()
            .filter(|seq| self.detectable(*seq) && !self.released.contains_key(seq))
            .collect();
        if !unrepaired.is_empty() {
            return Err(format!("lost, detectable and not played: {unrepaired:?}"));
        }
        let played = self.played_indices()?;
        let first = *played.first().ok_or("nothing played")?;
        // The stream's last packets, lost with nothing after them to show it.
        let undetectable = |i: &usize| {
            let seq = self.sequence_numbers[*i];
            !self.detectable(seq) && !self.released.contains_key(&seq)
        };
        let expected: Vec<usize> = (first..self.frames.len())
            .filter(|i| !undetectable(i))
            .collect();
        if played != expected {
            return Err(format!(
                "played frames {first}.. are not every frame from there: {} played, {} expected",
                played.len(),
                expected.len()
            ));
        }
        Ok(())
    }

    fn ms(&self, t: Instant) -> String {
        format!("{:.1}", (t - self.start).as_secs_f64() * 1000.0)
    }

    /// One line per lost packet that was not played, with its course.
    fn trace(&self) -> Vec<String> {
        let mut lines = vec![];
        for seq in self.lost() {
            if self.released.contains_key(&seq) {
                continue;
            }
            let sends = &self.rtp_wire[&seq];
            let class = if !self.detectable(seq) {
                "not detectable"
            } else if sends.len() == 1 {
                "never retransmitted"
            } else if sends[1..].iter().all(|w| w.arrived.is_none()) {
                "every retransmission lost"
            } else {
                "retransmitted after the jitter buffer played past it"
            };
            let gap = self.delivered.range(seq + 1..).map(|(_, t)| *t).min();
            let passed = self.released.range(seq + 1..).map(|(_, t)| *t).min();
            let wire = |w: &Wire| match w.arrived {
                Some(a) => format!("{}->{}", self.ms(w.sent), self.ms(a)),
                None => format!("{}->lost", self.ms(w.sent)),
            };
            let rtcp: Vec<String> = self
                .rtcp_wire
                .iter()
                .filter(|(_, w)| {
                    gap.is_some_and(|g| w.sent >= g)
                        && w.sent <= sends[0].sent + Duration::from_secs(1)
                })
                .map(|(pt, w)| format!("{pt}:{}", wire(w)))
                .collect();
            lines.push(format!(
                "seq {seq}: {class}: sent {} (lost); gap seen {}; receiver RTCP {}; \
                 retransmissions {}; buffer past it at {}",
                self.ms(sends[0].sent),
                gap.map_or("-".to_owned(), |t| self.ms(t)),
                rtcp.join(" "),
                sends[1..].iter().map(wire).collect::<Vec<_>>().join(" "),
                passed.map_or("-".to_owned(), |t| self.ms(t)),
            ));
        }
        lines
    }
}

fn run(setup: Setup, seed: u64) -> Result<Run> {
    let mut seeds = Rng(seed ^ 0x5eed);
    let start = Instant::now();
    let mut peers = [
        Peer::new("10.0.0.1:5000", start, seeds.next_u64(), setup.depth)?,
        Peer::new("10.0.0.2:5000", start, seeds.next_u64(), setup.depth)?,
    ];
    let mut netem = [0u64, 1].map(|i| Netem {
        spec: setup.netem,
        rng: Rng(seed.wrapping_mul(31).wrapping_add(i)),
        reorder_last: 0.0,
    });
    let mut loop_rng = Rng(seed ^ 0x100);
    let sender: RTCRtpSenderId = peers[0].pc.add_track(MediaStreamTrack::new(
        "env-stream".to_owned(),
        "env-video".to_owned(),
        "env-video".to_owned(),
        RtpCodecKind::Video,
        vec![RTCRtpEncodingParameters {
            rtp_coding_parameters: RTCRtpCodingParameters {
                ssrc: Some(SSRC),
                ..Default::default()
            },
            codec: vp8_codec(),
            ..Default::default()
        }],
    ))?;
    let offer = peers[0].pc.create_offer(None)?;
    peers[0].pc.set_local_description(start, offer.clone())?;
    peers[1].pc.set_remote_description(start, offer)?;
    let answer = peers[1].pc.create_answer(None)?;
    peers[1].pc.set_local_description(start, answer.clone())?;
    peers[0].pc.set_remote_description(start, answer)?;
    for i in 0..2 {
        let c = peers[i].candidate()?;
        peers[i].pc.add_local_candidate(c.clone())?;
        peers[1 - i].pc.add_remote_candidate(c)?;
    }

    let frames = frames();
    let header = IVFFileHeader {
        signature: *b"DKIF",
        version: 0,
        header_size: 32,
        four_cc: *b"VP80",
        width: 640,
        height: 480,
        timebase_denominator: 30,
        timebase_numerator: 1,
        num_frames: 0,
        unused: 0,
    };
    let file = SharedFile::default();
    let mut writer = IVFWriter::new(file.clone(), &header)?;
    let mut packetizer = None;
    let mut next = 0usize;
    let mut last_frame: Option<Instant> = None;
    let mut done_at: Option<Instant> = None;
    let mut now = start;
    let mut in_flight: Vec<InFlight> = vec![];
    let mut order = 0u64;
    // Trace records.
    let mut rtp_wire: BTreeMap<u16, Vec<Wire>> = BTreeMap::new();
    let mut rtcp_wire: Vec<(u8, Wire)> = vec![];
    let mut released: BTreeMap<u16, Instant> = BTreeMap::new();
    // When the receiver read each RTP packet first (handle_read, before the same pass's
    // handle_timeout).
    let mut delivered: BTreeMap<u16, Instant> = BTreeMap::new();
    let mut frame_packets: Vec<(Instant, Vec<u16>)> = vec![];

    loop {
        for i in 0..2 {
            // poll_write: onto the link.
            while let Some(m) = peers[i].pc.poll_write() {
                let delay = netem[i].delay();
                let data = m.message;
                let wire = Wire {
                    sent: now,
                    arrived: delay.map(|d| now + d),
                };
                if i == 0
                    && let Some((ssrc, seq)) = rtp_id(&data)
                    && ssrc == SSRC
                {
                    rtp_wire.entry(seq).or_default().push(wire.clone());
                }
                if i == 1
                    && let Some(pt) = rtcp_type(&data)
                {
                    rtcp_wire.push((pt, wire));
                }
                if let Some(d) = delay {
                    order += 1;
                    in_flight.push(InFlight {
                        at: now + d,
                        order,
                        from: m.transport.local_addr,
                        to: m.transport.peer_addr,
                        data,
                    });
                }
            }
            // recv: what has arrived for this peer.
            let addr = peers[i].addr;
            let mut due: Vec<InFlight> = vec![];
            let mut k = 0;
            while k < in_flight.len() {
                if in_flight[k].to == addr && in_flight[k].at <= now {
                    due.push(in_flight.swap_remove(k));
                } else {
                    k += 1;
                }
            }
            due.sort_by_key(|d| (d.at, d.order));
            for d in due {
                if i == 1
                    && let Some((ssrc, seq)) = rtp_id(&d.data)
                    && ssrc == SSRC
                {
                    delivered.entry(seq).or_insert(now);
                }
                let _ = peers[i].pc.handle_read(TaggedBytesMut {
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
            if peers[i].pc.poll_timeout().is_some_and(|t| t <= now) {
                let _ = peers[i].pc.handle_timeout(now);
            }
            while let Some(event) = peers[i].pc.poll_event() {
                if let RTCPeerConnectionEvent::OnConnectionStateChangeEvent(state) = event {
                    if state == RTCPeerConnectionState::Failed {
                        bail!("seed {seed}: peer {i} failed");
                    }
                    peers[i].connected = state == RTCPeerConnectionState::Connected;
                }
            }
            while let Some(m) = peers[i].pc.poll_read() {
                if i == 1
                    && let RTCMessage::RtpPacket(_, pkt) = m.message
                {
                    released.entry(pkt.header.sequence_number).or_insert(now);
                    let _ = writer.write_rtp(&pkt);
                }
            }
        }
        // The test's body: a frame every 33 ms once both are connected.
        if peers[0].connected
            && peers[1].connected
            && next < frames.len()
            && last_frame.is_none_or(|l| now - l >= Duration::from_millis(33))
        {
            let pk = packetizer.get_or_insert_with(|| {
                rtc::rtp::packetizer::new_packetizer(
                    now,
                    1200,
                    VP8_PT,
                    SSRC,
                    vp8_codec().payloader().unwrap(),
                    Box::new(rtc::rtp::sequence::new_fixed_sequencer(1000)),
                    90000,
                )
            });
            let packets = pk.packetize(now, &frames[next], 3000)?;
            frame_packets.push((
                now,
                packets.iter().map(|p| p.header.sequence_number).collect(),
            ));
            let mut s = peers[0].pc.rtp_sender(sender).expect("sender");
            for pkt in packets {
                let _ = s.write_rtp(now, pkt);
            }
            next += 1;
            last_frame = Some(now);
            if next == frames.len() {
                done_at = Some(now);
            }
        }
        if done_at.is_some_and(|t| now - t > Duration::from_secs(3)) {
            break;
        }
        if now - start > Duration::from_secs(90) {
            bail!("seed {seed}: not done after 90 s (sent {next} frames)");
        }
        now += Duration::from_micros(500) + setup.loop_overhead.mul_f64(loop_rng.unit());
    }
    writer.close()?;
    let bytes = file.0.borrow().get_ref().clone();
    let (mut reader, _) = IVFReader::new(Cursor::new(bytes))?;
    let mut played = vec![];
    while let Ok((f, _)) = reader.parse_next_frame() {
        played.push(f.freeze());
    }
    let sequence_numbers = frame_packets
        .iter()
        .map(|(_, seqs)| {
            assert_eq!(seqs.len(), 1, "a frame is one packet, as the fixture's");
            seqs[0]
        })
        .collect();
    Ok(Run {
        frames,
        sequence_numbers,
        played,
        rtp_wire,
        delivered,
        released,
        rtcp_wire,
        start,
    })
}

/// An in-memory file the IVF writer writes and the test reads back.
#[derive(Clone, Default)]
struct SharedFile(std::rc::Rc<std::cell::RefCell<Cursor<Vec<u8>>>>);

impl std::io::Write for SharedFile {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.borrow_mut().write(buf)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl std::io::Seek for SharedFile {
    fn seek(&mut self, pos: std::io::SeekFrom) -> std::io::Result<u64> {
        self.0.borrow_mut().seek(pos)
    }
}

fn summary(seed: u64, r: &Run) -> String {
    let lost = r.lost();
    let repaired = lost.iter().filter(|s| r.released.contains_key(s)).count();
    format!(
        "seed {seed}: {} of {} frames played; the link lost {} packets, {repaired} played after \
         a retransmission",
        r.played.len(),
        r.frames.len(),
        lost.len()
    )
}

/// The testenv's 250 ms jitter buffer on its link: every frame played is a sent one, in
/// order; every loss the receiver can detect is retransmitted; and the jitter buffer drops
/// only what reaches it after it has played past its place. (How many frames that leaves
/// is luck: see the module documentation.)
#[test]
fn on_the_testenv_link_what_is_played_is_whole_in_order_and_everything_in_time() -> Result<()> {
    for seed in 1..=10 {
        let r = run(Setup::testenv(), seed)?;
        println!("{}", summary(seed, &r));
        let checks = [
            r.check_played_frames_are_sent_frames_in_order(),
            r.check_every_detectable_loss_is_retransmitted(),
            r.check_every_packet_in_time_is_played(),
        ];
        for check in checks {
            if let Err(e) = check {
                bail!("seed {seed}: {e}\n{}", r.trace().join("\n"));
            }
        }
    }
    Ok(())
}

/// A jitter buffer deeper than the feedback delay on that link (2 s: up to 750 ms of RFC 4585
/// Early RTCP hold, the reordering allowance, the generator's tick and a round trip, twice
/// over for a request or retransmission the link lost) plays every packet whose loss the
/// receiver can detect, and every frame from the first key frame it read.
#[test]
fn a_jitter_buffer_deeper_than_the_feedback_delay_repairs_every_detectable_loss() -> Result<()> {
    let setup = Setup {
        depth: Duration::from_secs(2),
        ..Setup::testenv()
    };
    for seed in 1..=10 {
        let r = run(setup, seed)?;
        println!("{}", summary(seed, &r));
        let checks = [
            r.check_played_frames_are_sent_frames_in_order(),
            r.check_every_detectable_loss_is_repaired(),
        ];
        for check in checks {
            if let Err(e) = check {
                bail!("seed {seed}: {e}\n{}", r.trace().join("\n"));
            }
        }
    }
    Ok(())
}

/// Investigation tool: one line per seed of `RTC_VP8_SEEDS` (`a..b`, default `1..21`), with the
/// course of every lost packet that was not played; `RTC_VP8_DEPTH_MS` sets the jitter buffer
/// (default 250).
/// `RTC_VP8_SEEDS=1..201 cargo test --test vp8_nack_jitter_buffer_rtc2rtc vp8_seeds -- --ignored --nocapture`
#[test]
#[ignore = "an investigation tool: prints one outcome per seed"]
fn vp8_seeds() -> Result<()> {
    let range = std::env::var("RTC_VP8_SEEDS").unwrap_or_else(|_| "1..21".to_owned());
    let (a, b) = range.split_once("..").expect("RTC_VP8_SEEDS is a..b");
    let (a, b): (u64, u64) = (a.parse()?, b.parse()?);
    let depth_ms: u64 = std::env::var("RTC_VP8_DEPTH_MS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(250);
    let setup = Setup {
        depth: Duration::from_millis(depth_ms),
        ..Setup::testenv()
    };
    let (mut under, mut broken) = (0, 0);
    for seed in a..b {
        let r = run(setup, seed)?;
        let below = r.played.len() * 50 < r.frames.len() * 49;
        under += usize::from(below);
        let mut checks = vec![
            r.check_played_frames_are_sent_frames_in_order(),
            r.check_every_detectable_loss_is_retransmitted(),
            r.check_every_packet_in_time_is_played(),
        ];
        if depth_ms >= 2000 {
            checks.push(r.check_every_detectable_loss_is_repaired());
        }
        let failed: Vec<String> = checks.into_iter().filter_map(Result::err).collect();
        broken += usize::from(!failed.is_empty());
        println!(
            "VP8 {}{}{}",
            summary(seed, &r),
            if below { " (under 98 %)" } else { "" },
            if failed.is_empty() {
                String::new()
            } else {
                format!(" GUARANTEE BROKEN: {failed:?}")
            }
        );
        for l in r.trace() {
            println!("VP8 seed {seed}:   {l}");
        }
    }
    println!(
        "VP8 seeds {a}..{b}, {depth_ms} ms: {under} played under 98 % of the frames, {broken} broke a guarantee"
    );
    Ok(())
}
