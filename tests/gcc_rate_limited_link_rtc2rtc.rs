//! GCC over a link limited to 600 kbit/s, with a source that ignores the target: the virtual
//! clock form of `testenv_impairment::gcc_follows_a_rate_limited_link` (netem "delay 20ms rate
//! 600kbit limit 200"). The chain is that test's (`configure_congestion_control` with GCC on
//! transport-wide feedback, no NACK), the sender writes a 1200-byte packet every 4 ms (about
//! 2.4 Mbit/s), and the bottleneck serves one datagram at a time at the link rate behind a
//! drop-tail queue of 200 packets. Seeded: ICE, DTLS and SCTP draw from the seed.

use anyhow::{Result, bail};
use bytes::Bytes;
use rtc::crypto::{CryptoError, RTCCrypto, RTCCryptoProvider, RTCRandom, default_provider};
use rtc::interceptor::{Gcc, Registry, RtcpRandom, RtcpSessionBuilder};
use rtc::media_stream::MediaStreamTrack;
use rtc::peer_connection::configuration::interceptor_registry::{
    CongestionFeedback, configure_congestion_control, configure_rtcp_reports_with,
};
use rtc::peer_connection::configuration::media_engine::{MIME_TYPE_VP8, MediaEngine};
use rtc::peer_connection::configuration::setting_engine::SettingEngineBuilder;
use rtc::peer_connection::event::RTCPeerConnectionEvent;
use rtc::peer_connection::state::RTCPeerConnectionState;
use rtc::peer_connection::transport::{CandidateConfig, CandidateHostConfig, RTCIceCandidate};
use rtc::peer_connection::{RTCPeerConnection, RTCPeerConnectionBuilder};
use rtc::rtp_transceiver::rtp_sender::{
    RTCRtpCodec, RTCRtpCodecParameters, RTCRtpCodingParameters, RTCRtpEncodingParameters,
    RtpCodecKind,
};
use rtc::sansio::Protocol;
use rtc::shared::time::SystemInstant;
use rtc::shared::{TaggedBytesMut, TransportContext, TransportProtocol};
use rtc::statistics::StatsSelector;
use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const VP8_PT: u8 = 96;
const SSRC: u32 = 0x6cc0_0001;
const LINK_BPS: f64 = 600_000.0;
const LINK_LIMIT: usize = 200;
const DELAY: Duration = Duration::from_millis(20);

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

/// The RTCP session's random numbers from the seeded provider, as the peer connection draws
/// them for the session it adds itself.
struct ProviderRtcpRandom(Arc<dyn RTCCryptoProvider>);

impl RtcpRandom for ProviderRtcpRandom {
    fn next_u32(&mut self) -> u32 {
        let mut bytes = [0u8; 4];
        let _ = self.0.random().fill(&mut bytes);
        u32::from_be_bytes(bytes)
    }
}

fn peer(seed: u64, now: Instant) -> Result<RTCPeerConnection> {
    let mut me = MediaEngine::default();
    me.register_codec(
        RTCRtpCodecParameters {
            rtp_codec: RTCRtpCodec {
                mime_type: MIME_TYPE_VP8.to_owned(),
                clock_rate: 90000,
                channels: 0,
                sdp_fmtp_line: String::new(),
                rtcp_feedback: vec![],
            },
            payload_type: VP8_PT,
        },
        RtpCodecKind::Video,
    )?;
    let registry = configure_congestion_control(
        Registry::new(),
        Gcc::default(),
        CongestionFeedback::Twcc,
        &mut me,
    )?;
    let provider: Arc<dyn RTCCryptoProvider> = Arc::new(SeededProvider {
        inner: default_provider()?,
        rng: Mutex::new(Rng(seed)),
    });
    // The RTCP session the peer connection would add (`configure_rtcp_reports`, its random
    // numbers from the provider), with its NTP times anchored to the run's start rather than
    // the process-wide anchor: the same seed then writes the same reports in every run.
    let registry = configure_rtcp_reports_with(
        registry,
        RtcpSessionBuilder::new()
            .with_t_rr_interval(Duration::ZERO)
            .with_random(ProviderRtcpRandom(provider.clone()))
            .with_wall_clock(SystemInstant::at(now, Duration::from_secs(1_700_000_000))),
    );
    Ok(RTCPeerConnectionBuilder::new()
        .with_media_engine(me)
        .with_interceptor_registry(registry)
        .with_setting_engine(
            SettingEngineBuilder::new()
                .with_crypto_provider(provider)
                .build(),
        )
        .build(now)?)
}

struct Datagram {
    at: Instant,
    order: u64,
    from: SocketAddr,
    to: SocketAddr,
    data: bytes::BytesMut,
}

struct World {
    pcs: [RTCPeerConnection; 2],
    addrs: [SocketAddr; 2],
    connected: [bool; 2],
    now: Instant,
    in_flight: Vec<Datagram>,
    order: u64,
    /// The bottleneck on the first peer's way out: when each queued datagram leaves it.
    queue: VecDeque<Instant>,
    free_at: Instant,
    limited: bool,
    dropped: u64,
    sent: u64,
}

impl World {
    fn pump(&mut self) -> Result<()> {
        for i in 0..2 {
            while let Some(msg) = self.pcs[i].poll_write() {
                let mut at = self.now + DELAY;
                if i == 0 && self.limited {
                    self.sent += 1;
                    while self.queue.front().is_some_and(|left| *left <= self.now) {
                        self.queue.pop_front();
                    }
                    if self.queue.len() >= LINK_LIMIT {
                        self.dropped += 1;
                        continue;
                    }
                    let start = self.free_at.max(self.now);
                    let leaves =
                        start + Duration::from_secs_f64(msg.message.len() as f64 * 8.0 / LINK_BPS);
                    self.free_at = leaves;
                    self.queue.push_back(leaves);
                    at = leaves + DELAY;
                }
                self.order += 1;
                self.in_flight.push(Datagram {
                    at,
                    order: self.order,
                    from: msg.transport.local_addr,
                    to: msg.transport.peer_addr,
                    data: msg.message,
                });
            }
        }
        let now = self.now;
        let mut due: Vec<Datagram> = Vec::new();
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
            let Some(index) = self.addrs.iter().position(|a| *a == d.to) else {
                continue;
            };
            let _ = self.pcs[index].handle_read(TaggedBytesMut {
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
            while let Some(event) = self.pcs[i].poll_event() {
                if let RTCPeerConnectionEvent::OnConnectionStateChangeEvent(state) = event {
                    if state == RTCPeerConnectionState::Failed {
                        bail!("peer {i} failed");
                    }
                    self.connected[i] = state == RTCPeerConnectionState::Connected;
                }
            }
            while self.pcs[i].poll_read().is_some() {}
        }
        Ok(())
    }

    fn advance(&mut self, to: Instant) -> Result<()> {
        while self.now < to {
            let mut next = to;
            for pc in self.pcs.iter_mut() {
                if let Some(deadline) = pc.poll_timeout() {
                    next = next.min(deadline);
                }
            }
            if let Some(at) = self.in_flight.iter().map(|d| d.at).min() {
                next = next.min(at);
            }
            self.now = next.max(self.now + Duration::from_micros(100)).min(to);
            for pc in self.pcs.iter_mut() {
                pc.handle_timeout(self.now)?;
            }
            self.pump()?;
        }
        Ok(())
    }
}

/// The congestion controller's target once a second for 30 s of a ~2.4 Mbit/s source.
fn targets(seed: u64) -> Result<Vec<f64>> {
    let start = Instant::now();
    let addrs: [SocketAddr; 2] = ["10.0.0.1:5000".parse()?, "10.0.0.2:5000".parse()?];
    let mut world = World {
        pcs: [peer(seed ^ 0x1111, start)?, peer(seed ^ 0x2222, start)?],
        addrs,
        connected: [false; 2],
        now: start,
        in_flight: Vec::new(),
        order: 0,
        queue: VecDeque::new(),
        free_at: start,
        limited: false,
        dropped: 0,
        sent: 0,
    };
    let sender = world.pcs[0].add_track(MediaStreamTrack::new(
        "stream".to_owned(),
        "video".to_owned(),
        "video".to_owned(),
        RtpCodecKind::Video,
        vec![RTCRtpEncodingParameters {
            rtp_coding_parameters: RTCRtpCodingParameters {
                ssrc: Some(SSRC),
                ..Default::default()
            },
            active: true,
            ..Default::default()
        }],
    ))?;
    let offer = world.pcs[0].create_offer(None)?;
    world.pcs[0].set_local_description(start, offer.clone())?;
    world.pcs[1].set_remote_description(start, offer)?;
    let answer = world.pcs[1].create_answer(None)?;
    world.pcs[1].set_local_description(start, answer.clone())?;
    world.pcs[0].set_remote_description(start, answer)?;
    for (i, addr) in addrs.iter().enumerate() {
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
        let init = RTCIceCandidate::from(&candidate).to_json()?;
        world.pcs[i].add_local_candidate(init.clone())?;
        world.pcs[1 - i].add_remote_candidate(init)?;
    }
    while !world.connected.iter().all(|c| *c) {
        if world.now.duration_since(start) > Duration::from_secs(10) {
            bail!("not connected");
        }
        let t = world.now + Duration::from_millis(10);
        world.advance(t)?;
    }
    world.limited = true;
    let begin = world.now;
    let mut samples = Vec::new();
    for n in 0..7500u32 {
        let now = begin + Duration::from_millis(4 * u64::from(n));
        world.advance(now)?;
        world.pcs[0]
            .rtp_sender(sender)
            .expect("the sender")
            .write_rtp(
                now,
                rtc::rtp::Packet {
                    header: rtc::rtp::header::Header {
                        version: 2,
                        payload_type: VP8_PT,
                        sequence_number: n as u16,
                        timestamp: n * 360,
                        ssrc: SSRC,
                        ..Default::default()
                    },
                    payload: Bytes::from(vec![0u8; 1200]),
                },
            )?;
        world.pump()?;
        if n % 250 == 249 {
            let report = world.pcs[0].get_stats(now, StatsSelector::None);
            let target = report
                .outbound_rtp_streams()
                .find(|o| o.sent_rtp_stream_stats.rtp_stream_stats.ssrc == SSRC)
                .and_then(|o| o.target_bitrate)
                .unwrap_or(0.0);
            samples.push(target);
        }
    }
    eprintln!(
        "seed {seed}: GCC target once a second {samples:?}; {} of {} datagrams dropped at the bottleneck",
        world.dropped, world.sent
    );
    Ok(samples)
}

/// The target settles near the 600 kbit/s the link carries, as the env test asks (the mean of
/// the last five seconds between 300 and 660 kbit/s), however far above it the source writes.
#[test]
fn gcc_follows_a_rate_limited_link_with_a_source_above_it() -> Result<()> {
    for seed in 1..=3 {
        let samples = targets(seed)?;
        let tail = &samples[samples.len() - 5..];
        let mean = tail.iter().sum::<f64>() / tail.len() as f64;
        assert!(
            (300_000.0..=660_000.0).contains(&mean),
            "seed {seed}: GCC's target over the last 5 s is {mean:.0} bit/s on a 600 kbit/s link: {samples:?}"
        );
    }
    Ok(())
}
