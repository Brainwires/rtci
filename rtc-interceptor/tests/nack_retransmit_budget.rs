//! Repeated NACKs cannot make a stream retransmit faster than it sends: past one full answer of
//! the send buffer, each retransmission needs an original packet sent since.

use rtc_interceptor::{
    AttributedPacket, Interceptor, NackResponderBuilder, Packet, RTCPFeedback, Registry, Slot,
    StreamInfo, TaggedPacket,
};
use rtcp::transport_feedbacks::transport_layer_nack::{NackPair, TransportLayerNack};
use sansio::Protocol;
use shared::TransportContext;
use std::time::{Duration, Instant};

const SSRC: u32 = 7;
const SIZE: u16 = 64;

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

/// A NACK naming every sequence number in `from..to`, 17 per pair.
fn nack(now: Instant, from: u16, to: u16) -> TaggedPacket {
    let mut nacks = vec![];
    let mut base = from;
    while base < to {
        let mut lost_packets = 0u16;
        for bit in 0..16u16 {
            if base + 1 + bit < to {
                lost_packets |= 1 << bit;
            }
        }
        nacks.push(NackPair {
            packet_id: base,
            lost_packets,
        });
        base += 17;
    }
    TaggedPacket {
        now,
        transport: TransportContext::default(),
        message: AttributedPacket::new(Packet::Rtcp(vec![Box::new(TransportLayerNack {
            sender_ssrc: 1,
            media_ssrc: SSRC,
            nacks,
        })])),
    }
}

fn retransmissions(chain: &mut impl Interceptor, message: TaggedPacket) -> usize {
    chain.handle_read(message).unwrap();
    while chain.poll_read().is_some() {}
    std::iter::from_fn(|| chain.poll_write())
        .filter(|tagged| matches!(tagged.message.packet, Packet::Rtp(_)))
        .count()
}

#[test]
fn repeated_nacks_are_held_to_the_send_rate() {
    let mut chain = Registry::new()
        .with(
            Slot::NackResponder,
            NackResponderBuilder::new().with_size(SIZE).build(),
        )
        .build();
    chain.bind_local_stream(&info());

    let mut now = Instant::now();
    for seq in 0..SIZE {
        chain.handle_write(rtp(now, seq)).unwrap();
    }
    while chain.poll_write().is_some() {}

    // The first NACK of the whole buffer is answered in full.
    assert_eq!(
        usize::from(SIZE),
        retransmissions(&mut chain, nack(now, 0, SIZE))
    );

    // Again, past the per-packet suppression interval: nothing sent since, nothing to spend.
    now += Duration::from_millis(50);
    assert_eq!(0, retransmissions(&mut chain, nack(now, 0, SIZE)));

    // Ten originals sent buy ten retransmissions.
    for seq in SIZE..SIZE + 10 {
        chain.handle_write(rtp(now, seq)).unwrap();
    }
    while chain.poll_write().is_some() {}
    now += Duration::from_millis(50);
    assert_eq!(10, retransmissions(&mut chain, nack(now, 10, SIZE + 10)));
}
