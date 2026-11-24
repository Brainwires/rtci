//! The receiving application tells the NACK generator how old a missing packet may be and still
//! be useful, as a [`NackControl::Horizon`] (RFC 4588 6.3: "the receiver should generally
//! assess whether the retransmitted packet would still be useful at the time it is
//! received"): packets older than the horizon are not asked for, newer ones still are.

use rtc_interceptor::{
    AttributedPacket, Interceptor, NackControl, NackGeneratorBuilder, Packet, RTCPFeedback,
    Registry, Slot, StreamInfo, TaggedPacket,
};
use rtcp::transport_feedbacks::transport_layer_nack::TransportLayerNack;
use sansio::Protocol;
use shared::TransportContext;
use std::collections::BTreeSet;
use std::time::{Duration, Instant};

const SSRC: u32 = 0x1234;
const OTHER_SSRC: u32 = 0x9999;
const TICK: Duration = Duration::from_millis(100);

fn stream_info(ssrc: u32) -> StreamInfo {
    StreamInfo {
        ssrc,
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

fn rtp(now: Instant, ssrc: u32, sequence_number: u16) -> TaggedPacket {
    TaggedPacket {
        now,
        transport: TransportContext::default(),
        message: AttributedPacket::new(Packet::Rtp(rtp::Packet {
            header: rtp::header::Header {
                version: 2,
                payload_type: 96,
                sequence_number,
                ssrc,
                ..Default::default()
            },
            payload: vec![0u8; 10].into(),
        })),
    }
}

fn generator() -> impl Interceptor {
    let mut chain = Registry::new()
        .with(Slot::NackGenerator, NackGeneratorBuilder::new().build())
        .build();
    chain.bind_remote_stream(&stream_info(SSRC));
    chain.bind_remote_stream(&stream_info(OTHER_SSRC));
    chain
}

fn receive(chain: &mut impl Interceptor, now: Instant, ssrc: u32, sequence_numbers: &[u16]) {
    for &sequence_number in sequence_numbers {
        chain.handle_read(rtp(now, ssrc, sequence_number)).unwrap();
    }
    while chain.poll_read().is_some() {}
}

fn horizon(chain: &mut impl Interceptor, now: Instant, media_ssrc: u32, oldest: Option<u16>) {
    chain
        .handle_write(
            NackControl::Horizon {
                media_ssrc,
                oldest_useful: oldest,
            }
            .into_packet(now),
        )
        .unwrap();
    // The carrier goes on down the chain; no NACK is written for it.
    while let Some(tagged) = chain.poll_write() {
        if let Packet::Rtcp(packets) = tagged.message.packet {
            assert!(packets.is_empty(), "only the carrier: {packets:?}");
        }
    }
}

/// The sequence numbers of `ssrc` the NACK cycle at `now` asks for.
fn asked(chain: &mut impl Interceptor, now: Instant, ssrc: u32) -> BTreeSet<u16> {
    chain.handle_timeout(now).unwrap();
    let mut asked = BTreeSet::new();
    while let Some(tagged) = chain.poll_write() {
        if let Packet::Rtcp(packets) = tagged.message.packet {
            for packet in packets {
                if let Some(nack) = packet.as_any().downcast_ref::<TransportLayerNack>()
                    && nack.media_ssrc == ssrc
                {
                    for pair in &nack.nacks {
                        asked.extend(pair.packet_list());
                    }
                }
            }
        }
    }
    asked
}

#[test]
fn packets_older_than_the_horizon_are_not_asked_for() {
    let base = Instant::now();

    // Without a horizon both gaps are asked for.
    let mut chain = generator();
    receive(&mut chain, base, SSRC, &[1, 3, 4, 6]);
    assert_eq!(asked(&mut chain, base + TICK, SSRC), BTreeSet::from([2, 5]));

    // The application can still use 4 and later: 2 is not asked for, 5 is.
    let mut chain = generator();
    receive(&mut chain, base, SSRC, &[1, 3, 4, 6]);
    horizon(&mut chain, base, SSRC, Some(4));
    assert_eq!(asked(&mut chain, base + TICK, SSRC), BTreeSet::from([5]));
    assert_eq!(
        asked(&mut chain, base + TICK * 2, SSRC),
        BTreeSet::from([5])
    );
}

#[test]
fn a_horizon_moved_past_a_packet_already_asked_for_ends_its_requests() {
    let base = Instant::now();
    let mut chain = generator();
    receive(&mut chain, base, SSRC, &[10, 12, 13, 15]);
    assert_eq!(
        asked(&mut chain, base + TICK, SSRC),
        BTreeSet::from([11, 14])
    );

    // Playout passed 11 (its frame was dropped): only 14 is asked for again.
    horizon(&mut chain, base + TICK, SSRC, Some(12));
    assert_eq!(
        asked(&mut chain, base + TICK * 2, SSRC),
        BTreeSet::from([14])
    );

    // And past 14: nothing left to ask for.
    horizon(&mut chain, base + TICK * 2, SSRC, Some(15));
    assert!(asked(&mut chain, base + TICK * 3, SSRC).is_empty());

    // Removing the horizon returns the generator to its own limits.
    horizon(&mut chain, base + TICK * 3, SSRC, None);
    assert_eq!(
        asked(&mut chain, base + TICK * 4, SSRC),
        BTreeSet::from([11, 14])
    );
}

#[test]
fn the_horizon_compares_sequence_numbers_across_the_wrap() {
    let base = Instant::now();
    let mut chain = generator();
    // 65535 and 1 are missing; the horizon is 0, after the wrap.
    receive(&mut chain, base, SSRC, &[65533, 65534, 0, 2]);
    horizon(&mut chain, base, SSRC, Some(0));
    assert_eq!(asked(&mut chain, base + TICK, SSRC), BTreeSet::from([1]));
}

#[test]
fn a_horizon_is_for_its_own_stream_only() {
    let base = Instant::now();
    let mut chain = generator();
    receive(&mut chain, base, SSRC, &[1, 3]);
    receive(&mut chain, base, OTHER_SSRC, &[1, 3]);
    horizon(&mut chain, base, OTHER_SSRC, Some(3));
    chain.handle_timeout(base + TICK).unwrap();
    let mut by_ssrc: Vec<(u32, Vec<u16>)> = Vec::new();
    while let Some(tagged) = chain.poll_write() {
        if let Packet::Rtcp(packets) = tagged.message.packet {
            for packet in packets {
                if let Some(nack) = packet.as_any().downcast_ref::<TransportLayerNack>() {
                    let list = nack.nacks.iter().flat_map(|p| p.packet_list()).collect();
                    by_ssrc.push((nack.media_ssrc, list));
                }
            }
        }
    }
    assert_eq!(by_ssrc, vec![(SSRC, vec![2])]);
}
