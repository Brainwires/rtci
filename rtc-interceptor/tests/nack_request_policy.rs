//! When a lost packet is asked for, how often, and when the receiver gives up (RFC 4585
//! 6.2.1, RFC 4588 6.3 and Appendix A), and how long the sender keeps a packet to answer
//! with (`rtx-time`, RFC 4588 8.1).

use rtc_interceptor::{
    Attribute, AttributedPacket, Interceptor, NACK_SUGGESTED_MAX_NACKS_PER_PACKET,
    NACK_SUGGESTED_MAX_PACKET_AGE, NackGeneratorBuilder, NackResponderBuilder, Packet,
    RTCPFeedback, Registry, RtcpSessionEvent, Slot, StreamInfo, TaggedPacket,
};
use rtcp::transport_feedbacks::transport_layer_nack::{NackPair, TransportLayerNack};
use sansio::Protocol;
use shared::TransportContext;
use std::sync::Arc;
use std::time::{Duration, Instant};

const SSRC: u32 = 0x1234;
const TICK: Duration = Duration::from_millis(100);

fn stream_info() -> StreamInfo {
    StreamInfo {
        ssrc: SSRC,
        clock_rate: 90000,
        mime_type: "video/VP8".to_string(),
        payload_type: 96,
        rtcp_feedback: vec![RTCPFeedback {
            typ: "nack".to_string(),
            parameter: String::new(),
        }],
        ..Default::default()
    }
}

fn rtp(now: Instant, sequence_number: u16) -> TaggedPacket {
    TaggedPacket {
        now,
        transport: TransportContext::default(),
        message: AttributedPacket::new(Packet::Rtp(rtp::Packet {
            header: rtp::header::Header {
                version: 2,
                payload_type: 96,
                sequence_number,
                ssrc: SSRC,
                ..Default::default()
            },
            payload: vec![0u8; 10].into(),
        })),
    }
}

fn generator(builder: NackGeneratorBuilder) -> impl Interceptor {
    let mut chain = Registry::new()
        .with(Slot::NackGenerator, builder.build())
        .build();
    chain.bind_remote_stream(&stream_info());
    chain
}

/// Receives 1 and 3 at `base` (2 is missing) and returns, for each of `ticks` NACK cycles,
/// whether 2 was asked for.
fn requests(chain: &mut impl Interceptor, base: Instant, ticks: u32) -> Vec<bool> {
    chain.handle_read(rtp(base, 1)).unwrap();
    chain.handle_read(rtp(base, 3)).unwrap();
    while chain.poll_read().is_some() {}
    cycles(chain, base, 1..=ticks)
}

fn cycles(
    chain: &mut impl Interceptor,
    base: Instant,
    ticks: std::ops::RangeInclusive<u32>,
) -> Vec<bool> {
    ticks
        .map(|tick| {
            chain.handle_timeout(base + TICK * tick).unwrap();
            let mut asked = false;
            while let Some(tagged) = chain.poll_write() {
                if let Packet::Rtcp(packets) = tagged.message.packet {
                    for packet in packets {
                        if let Some(nack) = packet.as_any().downcast_ref::<TransportLayerNack>() {
                            assert_eq!(SSRC, nack.media_ssrc);
                            asked |= nack.nacks.iter().any(|p| p.packet_list().contains(&2));
                        }
                    }
                }
            }
            asked
        })
        .collect()
}

fn count(asked: &[bool]) -> usize {
    asked.iter().filter(|asked| **asked).count()
}

/// RFC 4588 Appendix A: a receiver may limit how often it asks for one packet. With a limit
/// of ten requests (`NACK_SUGGESTED_MAX_NACKS_PER_PACKET`; libwebrtc's is 100), it gives the
/// packet up after the tenth.
#[test]
fn a_lost_packet_is_asked_for_ten_times_then_given_up() {
    let mut chain = generator(
        NackGeneratorBuilder::new().with_max_nacks_per_packet(NACK_SUGGESTED_MAX_NACKS_PER_PACKET),
    );
    let asked = requests(&mut chain, Instant::now(), 50);
    assert_eq!(10, count(&asked));
    assert!(asked[..10].iter().all(|asked| *asked));
}

/// RFC 4588 6.3: a retransmission is asked for only while it can be of use, as long as the
/// application says: here half a second, then two seconds.
#[test]
fn a_lost_packet_is_not_asked_for_past_its_age() {
    let mut chain = generator(
        NackGeneratorBuilder::new()
            .with_max_nacks_per_packet(0)
            .with_max_packet_age(Some(Duration::from_millis(500))),
    );
    let asked = requests(&mut chain, Instant::now(), 50);
    // Found missing at the first cycle, asked for then and for the half second after.
    assert_eq!(6, count(&asked));
    assert!(asked[..6].iter().all(|asked| *asked));

    let mut chain = generator(
        NackGeneratorBuilder::new().with_max_packet_age(Some(NACK_SUGGESTED_MAX_PACKET_AGE)),
    );
    let asked = requests(&mut chain, Instant::now(), 50);
    assert_eq!(21, count(&asked), "two seconds");
}

/// By default a lost packet is asked for, a round trip after each request, for as long as it
/// is missing: the interceptor does not know how long the application waits for it (RFC 4588
/// 6.3), and a packet given up while the application still waits leaves its picture frozen
/// (`tests/capacity_cap_video_rtc2rtc.rs`).
#[test]
fn by_default_a_lost_packet_is_asked_for_while_it_is_missing() {
    let mut chain = generator(NackGeneratorBuilder::new());
    let asked = requests(&mut chain, Instant::now(), 50);
    assert_eq!(50, count(&asked));
}

/// The limits can be lifted: the request repeats for as long as the packet is missing.
#[test]
fn without_limits_the_request_repeats() {
    let mut chain = generator(
        NackGeneratorBuilder::new()
            .with_max_nacks_per_packet(0)
            .with_max_packet_age(None),
    );
    assert_eq!(50, count(&requests(&mut chain, Instant::now(), 50)));
}

/// RFC 4588 6.3: "the timer value shall be based on the observed round-trip time": a packet
/// is not asked for again before a retransmission could have arrived.
#[test]
fn a_repeated_request_waits_for_a_round_trip() {
    let mut chain = generator(
        NackGeneratorBuilder::new()
            .with_max_nacks_per_packet(0)
            .with_max_packet_age(None)
            .with_round_trip_time(Duration::from_millis(250)),
    );
    let asked = requests(&mut chain, Instant::now(), 10);
    assert_eq!(
        vec![
            true, false, false, true, false, false, true, false, false, true
        ],
        asked
    );
}

/// The round-trip time the RTCP session measures reaches the generator.
#[test]
fn the_measured_round_trip_time_paces_the_requests() {
    let mut chain = generator(
        NackGeneratorBuilder::new()
            .with_max_nacks_per_packet(0)
            .with_max_packet_age(None),
    );
    let base = Instant::now();
    let asked = requests(&mut chain, base, 3);
    assert_eq!(vec![true, true, true], asked);

    chain
        .handle_read(TaggedPacket {
            now: base + TICK * 3,
            transport: TransportContext::default(),
            message: AttributedPacket::new(Packet::Rtcp(vec![])).with(Attribute::Custom(Arc::new(
                RtcpSessionEvent::RoundTripTime {
                    ssrc: 1,
                    rtt: Duration::from_millis(250),
                },
            ))),
        })
        .unwrap();
    while chain.poll_read().is_some() {}

    // Last asked at cycle 3: again at 6 and 9.
    let asked = cycles(&mut chain, base, 4..=9);
    assert_eq!(vec![false, false, true, false, false, true], asked);
}

/// RFC 4588 6.3: the first request is delayed to allow for reordering.
#[test]
fn the_first_request_waits_out_the_reordering_allowance() {
    let builder = || {
        NackGeneratorBuilder::new()
            .with_max_packet_age(None)
            .with_reorder_delay(Duration::from_millis(150))
    };
    let mut chain = generator(builder());
    let asked = requests(&mut chain, Instant::now(), 4);
    // Missing at the first cycle, 200 ms old at the third.
    assert_eq!(vec![false, false, true, true], asked);

    // A packet that was only late is never asked for.
    let mut chain = generator(builder());
    let base = Instant::now();
    assert_eq!(vec![false], requests(&mut chain, base, 1));
    chain
        .handle_read(rtp(base + Duration::from_millis(150), 2))
        .unwrap();
    while chain.poll_read().is_some() {}
    assert_eq!(0, count(&cycles(&mut chain, base, 2..=10)));
}

/// RFC 4588 8.1: `rtx-time` is how long the sender keeps a packet for retransmission.
#[test]
fn a_packet_past_rtx_time_is_not_retransmitted() {
    let retransmitted = |max_packet_age: Option<Duration>, nack_after: Duration| {
        let mut chain = Registry::new()
            .with(
                Slot::NackResponder,
                NackResponderBuilder::new()
                    .with_max_packet_age(max_packet_age)
                    .build(),
            )
            .build();
        chain.bind_local_stream(&stream_info());
        let base = Instant::now();
        chain.handle_write(rtp(base, 5)).unwrap();
        while chain.poll_write().is_some() {}

        chain
            .handle_read(TaggedPacket {
                now: base + nack_after,
                transport: TransportContext::default(),
                message: AttributedPacket::new(Packet::Rtcp(vec![Box::new(TransportLayerNack {
                    sender_ssrc: 1,
                    media_ssrc: SSRC,
                    nacks: vec![NackPair {
                        packet_id: 5,
                        lost_packets: 0,
                    }],
                })])),
            })
            .unwrap();
        while chain.poll_read().is_some() {}
        std::iter::from_fn(|| chain.poll_write())
            .filter(|tagged| matches!(tagged.message.packet, Packet::Rtp(_)))
            .count()
    };

    let rtx_time = Some(Duration::from_millis(500));
    assert_eq!(1, retransmitted(rtx_time, Duration::from_millis(400)));
    assert_eq!(0, retransmitted(rtx_time, Duration::from_millis(600)));
    assert_eq!(1, retransmitted(None, Duration::from_secs(60)));
}

/// The sequence numbers each NACK cycle at `base + TICK * tick` asked for.
fn asked_at(
    chain: &mut impl Interceptor,
    base: Instant,
    ticks: std::ops::RangeInclusive<u32>,
) -> Vec<Vec<u16>> {
    ticks
        .map(|tick| {
            chain.handle_timeout(base + TICK * tick).unwrap();
            let mut asked = vec![];
            while let Some(tagged) = chain.poll_write() {
                if let Packet::Rtcp(packets) = tagged.message.packet {
                    for packet in packets {
                        if let Some(nack) = packet.as_any().downcast_ref::<TransportLayerNack>() {
                            asked.extend(nack.nacks.iter().flat_map(|p| p.packet_list()));
                        }
                    }
                }
            }
            asked
        })
        .collect()
}

/// RFC 4588 6.3: the first request is delayed "to allow for reordering". The generator learns
/// how much a stream reorders: after 2 came 60 ms behind 3, a later gap (5) is not asked for
/// at the cycle that first finds it missing, only once 75 ms (60 ms and a quarter) have passed
/// since; a packet that the path only reordered is then never asked for. Without that
/// history (a fresh generator), the gap is asked for at once.
#[test]
fn a_stream_that_reorders_has_its_gaps_asked_for_after_its_reordering() {
    let feed = |chain: &mut dyn FnMut(Instant, u16), base: Instant| {
        chain(base, 1);
        chain(base, 3);
        chain(base + Duration::from_millis(60), 2);
    };
    let builder = || NackGeneratorBuilder::new().with_max_packet_age(None);

    let base = Instant::now();
    let mut chain = generator(builder());
    feed(
        &mut |now, seq| {
            chain.handle_read(rtp(now, seq)).unwrap();
        },
        base,
    );
    while chain.poll_read().is_some() {}
    assert_eq!(vec![Vec::<u16>::new()], asked_at(&mut chain, base, 1..=1));
    for seq in [4, 6] {
        chain
            .handle_read(rtp(base + Duration::from_millis(150), seq))
            .unwrap();
    }
    while chain.poll_read().is_some() {}
    // Found missing at 200 ms, asked for at 300 ms (100 ms later, past 75 ms).
    assert_eq!(
        vec![vec![], vec![5]],
        asked_at(&mut chain, base, 2..=3),
        "the learned allowance holds the first request back one cycle"
    );

    // The retransmission of 5 arrives (it says nothing about reordering).
    chain
        .handle_read(rtp(base + Duration::from_millis(310), 5))
        .unwrap();
    // A late packet within the allowance is never asked for.
    chain
        .handle_read(rtp(base + Duration::from_millis(350), 7))
        .unwrap();
    chain
        .handle_read(rtp(base + Duration::from_millis(350), 9))
        .unwrap();
    while chain.poll_read().is_some() {}
    assert_eq!(vec![Vec::<u16>::new()], asked_at(&mut chain, base, 4..=4));
    chain
        .handle_read(rtp(base + Duration::from_millis(420), 8))
        .unwrap();
    while chain.poll_read().is_some() {}
    let later: Vec<u16> = asked_at(&mut chain, base, 5..=8)
        .into_iter()
        .flatten()
        .collect();
    assert!(!later.contains(&8), "8 came 70 ms late: {later:?}");

    // Without reordering seen, the first cycle asks.
    let mut chain = generator(builder());
    for seq in [4, 6] {
        chain.handle_read(rtp(base, seq)).unwrap();
    }
    while chain.poll_read().is_some() {}
    assert_eq!(vec![vec![5]], asked_at(&mut chain, base, 1..=1));
}
