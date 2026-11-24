//! NACK brings back every lost packet over a lossy, jittery path: the virtual-clock twin of
//! `tests/testenv_impairment.rs::nack_recovers_lost_rtp` (netem `delay 30ms 5ms loss 5%`),
//! which needs the real-network test environment.
//!
//! One engine sends 200 packets a second of 1000 octets; the path delays each datagram by
//! 30 ms plus up to 5 ms of jitter (so packets also overtake each other, as netem's jitter
//! does) and drops 5% of them each way, RTCP and retransmissions included, from a seeded
//! generator. The receiver asks for what it misses (RFC 4585 section 6.2.1) and the sender
//! resends it under the same SSRC, as the test environment's chain does. After the last
//! packet the run goes on for three seconds; by then every packet must have arrived.
//!
//! Two chains: the NACK generator and responder alone (the test environment's), and the same
//! with the RTCP session at both ends, which sends the NACKs as RTP/AVPF early feedback
//! within the RTCP bandwidth (RFC 4585 section 3.5) and measures the round-trip time the
//! generator paces its repeats by.

use rtci_interceptor::{
    AttributedPacket, Interceptor, NackGeneratorBuilder, NackResponderBuilder, Packet,
    RTCPFeedback, Registry, RtcpRandom, RtcpSessionBuilder, RtcpSessionControl, Slot, StreamInfo,
    TaggedPacket,
};
use sansio::Protocol;
use shared::TransportContext;
use std::collections::HashSet;
use std::time::{Duration, Instant};

const MEDIA_SSRC: u32 = 0x1234_5678;
const PACKETS: u16 = 2000;
/// Sent after the counted packets, so that the loss of the last counted one is noticed.
const TAIL: u16 = 20;
const SPACING: Duration = Duration::from_millis(5);
const DELAY: Duration = Duration::from_millis(30);
const JITTER_MICROS: u64 = 5_000;
const LOSS: f64 = 0.05;
const SETTLE: Duration = Duration::from_secs(3);

/// A repeatable source of numbers: the path's losses and jitter, and the RTCP session's
/// randomised intervals.
struct Lcg(u64);

impl Lcg {
    fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        self.0 >> 33
    }

    /// Uniform in [0, 1).
    fn unit(&mut self) -> f64 {
        self.next() as f64 / (1u64 << 31) as f64
    }
}

impl RtcpRandom for Lcg {
    fn next_u32(&mut self) -> u32 {
        self.next() as u32 | 1
    }
}

fn stream() -> StreamInfo {
    StreamInfo {
        ssrc: MEDIA_SSRC,
        clock_rate: 90_000,
        mime_type: "video/VP8".to_owned(),
        payload_type: 96,
        rtcp_feedback: vec![RTCPFeedback {
            typ: "nack".to_owned(),
            parameter: String::new(),
        }],
        ..Default::default()
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
enum Chain {
    /// The NACK generator and responder only.
    NackOnly,
    /// The same behind the RTCP session, `T_rr_interval` zero (RFC 4585 section 3.4).
    WithRtcpSession,
}

fn endpoint(chain: Chain, seed: u64) -> Box<dyn Interceptor> {
    let registry = Registry::new()
        .with(Slot::NackResponder, NackResponderBuilder::new().build())
        .with(Slot::NackGenerator, NackGeneratorBuilder::new().build());
    let registry = match chain {
        Chain::NackOnly => registry,
        Chain::WithRtcpSession => registry.with(
            Slot::RtcpSession,
            RtcpSessionBuilder::new()
                .with_random(Lcg(seed))
                .with_t_rr_interval(Duration::ZERO)
                .build(),
        ),
    };
    Box::new(registry.build())
}

/// A path in one direction: delay, jitter and loss. Datagrams leave it in order of arrival.
struct Path {
    random: Lcg,
    in_flight: Vec<(Instant, TaggedPacket)>,
}

impl Path {
    fn offer(&mut self, now: Instant, packet: TaggedPacket) {
        if self.random.unit() < LOSS {
            return;
        }
        let jitter = Duration::from_micros(self.random.next() % JITTER_MICROS);
        self.in_flight.push((now + DELAY + jitter, packet));
    }

    fn arrived(&mut self, now: Instant) -> Vec<TaggedPacket> {
        self.in_flight.sort_by_key(|(at, _)| *at);
        let due = self.in_flight.partition_point(|(at, _)| *at <= now);
        self.in_flight
            .drain(..due)
            .map(|(_, mut packet)| {
                packet.now = now;
                packet
            })
            .collect()
    }
}

/// The sequence numbers among the counted ones that never arrived, and the first one that
/// did (no receiver can know of packets sent before the first it receives).
fn run(chain: Chain, seed: u64) -> (Vec<u16>, u16) {
    let epoch = Instant::now();
    let mut sender = endpoint(chain, seed);
    let mut receiver = endpoint(chain, seed.wrapping_add(1));
    if chain == Chain::WithRtcpSession {
        for (endpoint, cname) in [(&mut sender, "sender"), (&mut receiver, "receiver")] {
            endpoint
                .handle_write(RtcpSessionControl::Cname(cname.to_owned()).into_packet(epoch))
                .unwrap();
            endpoint
                .handle_write(RtcpSessionControl::Start.into_packet(epoch))
                .unwrap();
        }
    }
    let info = stream();
    sender.bind_local_stream(&info);
    receiver.bind_remote_stream(&info);

    let mut forward = Path {
        random: Lcg(seed.wrapping_mul(31).wrapping_add(7)),
        in_flight: Vec::new(),
    };
    let mut backward = Path {
        random: Lcg(seed.wrapping_mul(17).wrapping_add(3)),
        in_flight: Vec::new(),
    };

    let total = PACKETS + TAIL;
    let mut sent = 0u16;
    let mut received: HashSet<u16> = HashSet::new();
    let mut first_received: Option<u16> = None;
    let end = SPACING * u32::from(total) + SETTLE;
    let step = Duration::from_millis(1);
    let mut elapsed = Duration::ZERO;
    while elapsed < end {
        let now = epoch + elapsed;

        while sent < total && SPACING * u32::from(sent) <= elapsed {
            let packet = rtp::Packet {
                header: rtp::header::Header {
                    version: 2,
                    payload_type: 96,
                    sequence_number: sent,
                    timestamp: u32::from(sent) * 450,
                    ssrc: MEDIA_SSRC,
                    marker: true,
                    ..Default::default()
                },
                payload: vec![0x10u8; 1000].into(),
            };
            sender
                .handle_write(TaggedPacket {
                    now,
                    transport: TransportContext::default(),
                    message: AttributedPacket::new(Packet::Rtp(packet)),
                })
                .unwrap();
            sent += 1;
        }

        for packet in forward.arrived(now) {
            receiver.handle_read(packet).unwrap();
        }
        for packet in backward.arrived(now) {
            sender.handle_read(packet).unwrap();
        }
        while let Some(packet) = receiver.poll_read() {
            if let Packet::Rtp(rtp) = &packet.message.packet
                && rtp.header.ssrc == MEDIA_SSRC
            {
                first_received.get_or_insert(rtp.header.sequence_number);
                received.insert(rtp.header.sequence_number);
            }
        }
        while sender.poll_read().is_some() {}

        for endpoint in [&mut sender, &mut receiver] {
            for _ in 0..64 {
                match endpoint.poll_timeout() {
                    Some(at) if at <= now => endpoint.handle_timeout(now).unwrap(),
                    _ => break,
                }
            }
        }

        while let Some(packet) = sender.poll_write() {
            if matches!(&packet.message.packet, Packet::Rtcp(packets) if packets.is_empty()) {
                continue;
            }
            forward.offer(now, packet);
        }
        while let Some(packet) = receiver.poll_write() {
            if matches!(&packet.message.packet, Packet::Rtcp(packets) if packets.is_empty()) {
                continue;
            }
            backward.offer(now, packet);
        }

        elapsed += step;
    }

    let first = first_received.expect("some packet arrived");
    let lost = (first..PACKETS)
        .filter(|sequence| !received.contains(sequence))
        .collect();
    (lost, first)
}

fn assert_full_recovery(chain: Chain) {
    for seed in 1..=12u64 {
        let (lost, first) = run(chain, seed);
        assert!(
            lost.is_empty(),
            "{chain:?}, seed {seed}: {} of {} packets never arrived: {lost:?}",
            lost.len(),
            PACKETS - first
        );
    }
}

/// RFC 4585 section 6.2.1 and RFC 4588 section 6.3: over 5% loss each way, with jitter that
/// reorders, the generator keeps asking until each packet is back, and three seconds after
/// the last one nothing is missing.
#[test]
fn nack_alone_recovers_every_packet_over_five_percent_loss() {
    assert_full_recovery(Chain::NackOnly);
}

/// The same with the RTCP session at both ends: the NACKs leave as early feedback or with the
/// next regular report inside the RTCP bandwidth, and repeats wait for the measured round
/// trip, and still every packet comes back.
#[test]
fn nack_behind_the_rtcp_session_recovers_every_packet_over_five_percent_loss() {
    assert_full_recovery(Chain::WithRtcpSession);
}
