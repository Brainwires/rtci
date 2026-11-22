//! The `rtx-time` a session description negotiates (RFC 4588 8.1) reaches the NACK
//! interceptors while they run, as a [`NackControl`]: the generator stops asking for a packet
//! the remote sender no longer keeps, and the responder keeps a sent packet for as long as
//! this endpoint announced.

use rtc_interceptor::{
    AttributedPacket, Interceptor, NackControl, NackGeneratorBuilder, NackResponderBuilder, Packet,
    RTCPFeedback, Registry, Slot, StreamInfo, TaggedPacket,
};
use rtcp::transport_feedbacks::transport_layer_nack::{NackPair, TransportLayerNack};
use sansio::Protocol;
use shared::TransportContext;
use std::time::{Duration, Instant};

const SSRC: u32 = 0x1234;
const RTX_SSRC: u32 = 0x5678;
const RTX_PAYLOAD_TYPE: u8 = 97;
const TICK: Duration = Duration::from_millis(100);

fn stream_info(payload_type_rtx: Option<u8>) -> StreamInfo {
    StreamInfo {
        ssrc: SSRC,
        ssrc_rtx: payload_type_rtx.map(|_| RTX_SSRC),
        payload_type_rtx,
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

/// Receives 1 and 3 (2 is missing) and counts the NACK cycles, of fifty, that ask for 2.
fn times_asked(chain: &mut impl Interceptor, base: Instant) -> usize {
    chain.handle_read(rtp(base, 1)).unwrap();
    chain.handle_read(rtp(base, 3)).unwrap();
    while chain.poll_read().is_some() {}
    (1..=50u32)
        .filter(|tick| {
            chain.handle_timeout(base + TICK * *tick).unwrap();
            let mut asked = false;
            while let Some(tagged) = chain.poll_write() {
                if let Packet::Rtcp(packets) = tagged.message.packet {
                    for packet in packets {
                        if let Some(nack) = packet.as_any().downcast_ref::<TransportLayerNack>() {
                            asked |= nack.nacks.iter().any(|p| p.packet_list().contains(&2));
                        }
                    }
                }
            }
            asked
        })
        .count()
}

fn generator(payload_type_rtx: Option<u8>, max_packet_age: Option<Duration>) -> impl Interceptor {
    let mut chain = Registry::new()
        .with(
            Slot::NackGenerator,
            NackGeneratorBuilder::new()
                .with_max_nacks_per_packet(0)
                .with_max_packet_age(max_packet_age)
                .build(),
        )
        .build();
    chain.bind_remote_stream(&stream_info(payload_type_rtx));
    chain
}

fn remote_rtx_time(chain: &mut impl Interceptor, now: Instant, payload_type_rtx: u8, ms: u64) {
    chain
        .handle_write(
            NackControl::RemoteRtxTime {
                payload_type_rtx,
                rtx_time: Some(Duration::from_millis(ms)),
            }
            .into_packet(now),
        )
        .unwrap();
    // The carrier goes on down the chain; nothing is sent for it here.
    while chain.poll_write().is_some() {}
}

#[test]
fn the_generator_stops_asking_at_the_remote_rtx_time() {
    let base = Instant::now();

    // No limit configured, none announced: asked for at every cycle.
    let mut chain = generator(Some(RTX_PAYLOAD_TYPE), None);
    assert_eq!(50, times_asked(&mut chain, base));

    // The remote sender keeps packets for half a second: found missing at the first cycle,
    // asked for then and for the half second after.
    let mut chain = generator(Some(RTX_PAYLOAD_TYPE), None);
    remote_rtx_time(&mut chain, base, RTX_PAYLOAD_TYPE, 500);
    assert_eq!(6, times_asked(&mut chain, base));

    // The shorter of the announced time and the configured age.
    let mut chain = generator(Some(RTX_PAYLOAD_TYPE), Some(Duration::from_millis(300)));
    remote_rtx_time(&mut chain, base, RTX_PAYLOAD_TYPE, 500);
    assert_eq!(4, times_asked(&mut chain, base));
    let mut chain = generator(Some(RTX_PAYLOAD_TYPE), Some(Duration::from_millis(1000)));
    remote_rtx_time(&mut chain, base, RTX_PAYLOAD_TYPE, 500);
    assert_eq!(6, times_asked(&mut chain, base));
}

#[test]
fn a_remote_rtx_time_is_for_the_streams_of_its_retransmission_format() {
    let base = Instant::now();

    // Another retransmission format's time is not this stream's.
    let mut chain = generator(Some(RTX_PAYLOAD_TYPE), None);
    remote_rtx_time(&mut chain, base, 99, 500);
    assert_eq!(50, times_asked(&mut chain, base));

    // A stream with no retransmission format has no rtx-time.
    let mut chain = generator(None, None);
    remote_rtx_time(&mut chain, base, RTX_PAYLOAD_TYPE, 500);
    assert_eq!(50, times_asked(&mut chain, base));

    // Withdrawn (a renegotiation without the parameter): the configured age again.
    let mut chain = generator(Some(RTX_PAYLOAD_TYPE), None);
    remote_rtx_time(&mut chain, base, RTX_PAYLOAD_TYPE, 500);
    chain
        .handle_write(
            NackControl::RemoteRtxTime {
                payload_type_rtx: RTX_PAYLOAD_TYPE,
                rtx_time: None,
            }
            .into_packet(base),
        )
        .unwrap();
    while chain.poll_write().is_some() {}
    assert_eq!(50, times_asked(&mut chain, base));
}

/// How many packets the responder sends again when packet 5, sent at the start, is asked
/// for `nack_after` later.
fn retransmitted(
    configured: Option<Duration>,
    announced: Option<(u8, Duration)>,
    nack_after: Duration,
) -> usize {
    let mut chain = Registry::new()
        .with(
            Slot::NackResponder,
            NackResponderBuilder::new()
                .with_max_packet_age(configured)
                .build(),
        )
        .build();
    chain.bind_local_stream(&stream_info(Some(RTX_PAYLOAD_TYPE)));
    let base = Instant::now();
    if let Some((payload_type_rtx, rtx_time)) = announced {
        chain
            .handle_write(
                NackControl::LocalRtxTime {
                    payload_type_rtx,
                    rtx_time: Some(rtx_time),
                }
                .into_packet(base),
            )
            .unwrap();
    }
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
}

#[test]
fn the_responder_keeps_a_packet_for_the_announced_rtx_time() {
    let ms = Duration::from_millis;
    let announced = Some((RTX_PAYLOAD_TYPE, ms(500)));

    // Nothing configured: without an announced time a packet is kept as long as the buffer
    // holds it; with one, for that long.
    assert_eq!(1, retransmitted(None, None, ms(60_000)));
    assert_eq!(1, retransmitted(None, announced, ms(400)));
    assert_eq!(0, retransmitted(None, announced, ms(600)));

    // What was announced is what the remote side counts on: it replaces the configured age,
    // shorter or longer.
    assert_eq!(1, retransmitted(Some(ms(100)), announced, ms(400)));
    assert_eq!(0, retransmitted(Some(ms(5000)), announced, ms(600)));

    // Another retransmission format's time is not this stream's.
    assert_eq!(1, retransmitted(None, Some((99, ms(500))), ms(600)));
}
