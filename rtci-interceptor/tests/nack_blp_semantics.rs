//! RFC 4585 section 6.2.1: a bit of the BLP that is 0 says nothing about a packet. "The
//! sender MUST NOT assume that a receiver has received a packet because its bit was 0": a
//! packet left out of one NACK is still retransmitted when a later NACK asks for it.

use rtci_interceptor::{
    AttributedPacket, Interceptor, NackResponderBuilder, Packet, RTCPFeedback, Registry, Slot,
    StreamInfo, TaggedPacket,
};
use rtcp::transport_feedbacks::transport_layer_nack::{NackPair, TransportLayerNack};
use sansio::Protocol;
use shared::TransportContext;
use std::time::{Duration, Instant};

const SSRC: u32 = 7;

fn info() -> StreamInfo {
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
                ssrc: SSRC,
                sequence_number,
                payload_type: 96,
                ..Default::default()
            },
            payload: vec![0u8; 10].into(),
        })),
    }
}

fn nack(now: Instant, packet_id: u16, lost_packets: u16) -> TaggedPacket {
    TaggedPacket {
        now,
        transport: TransportContext::default(),
        message: AttributedPacket::new(Packet::Rtcp(vec![Box::new(TransportLayerNack {
            sender_ssrc: 1,
            media_ssrc: SSRC,
            nacks: vec![NackPair {
                packet_id,
                lost_packets,
            }],
        })])),
    }
}

/// The sequence numbers retransmitted in answer to `message`.
fn retransmitted(chain: &mut impl Interceptor, message: TaggedPacket) -> Vec<u16> {
    chain.handle_read(message).unwrap();
    while chain.poll_read().is_some() {}
    std::iter::from_fn(|| chain.poll_write())
        .filter_map(|tagged| match tagged.message.packet {
            Packet::Rtp(packet) => Some(packet.header.sequence_number),
            _ => None,
        })
        .collect()
}

#[test]
fn a_packet_whose_blp_bit_was_zero_is_still_retransmitted_later() {
    let mut chain = Registry::new()
        .with(Slot::NackResponder, NackResponderBuilder::new().build())
        .build();
    chain.bind_local_stream(&info());
    let mut now = Instant::now();
    for seq in 100..120 {
        chain.handle_write(rtp(now, seq)).unwrap();
    }
    while chain.poll_write().is_some() {}

    // 100 and 102 (bit 1); the bit of 101 is 0.
    assert_eq!(
        vec![100, 102],
        retransmitted(&mut chain, nack(now, 100, 0b10))
    );
    now += Duration::from_millis(100);
    assert_eq!(vec![101], retransmitted(&mut chain, nack(now, 101, 0)));
}
