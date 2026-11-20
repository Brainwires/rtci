//! A packet evicted from a full buffer takes its deadline with it.

use super::*;
use crate::AttributedPacket;
use sansio::Protocol;
use shared::TransportContext;

fn rtp(now: Instant, sequence_number: u16) -> TaggedPacket {
    TaggedPacket {
        now,
        transport: TransportContext::default(),
        message: AttributedPacket::new(Packet::Rtp(rtp::Packet {
            header: rtp::header::Header {
                version: 2,
                ssrc: 1,
                sequence_number,
                timestamp: u32::from(sequence_number) * 3000,
                payload_type: 96,
                ..Default::default()
            },
            payload: vec![0u8; 4].into(),
        })),
    }
}

#[test]
fn deadlines_never_outnumber_the_held_packets() {
    let mut interceptor = JitterBufferBuilder::new()
        .with_capacity(4)
        .with_depth(Duration::from_secs(10))
        .build();
    interceptor.bind_remote_stream(&StreamInfo {
        ssrc: 1,
        clock_rate: 90_000,
        ..Default::default()
    });

    let now = Instant::now();
    for sequence_number in 0..50u16 {
        interceptor.handle_read(rtp(now, sequence_number)).unwrap();
    }

    let stream = &interceptor.streams[&1];
    assert!(stream.buffer.len() <= 4);
    assert!(
        stream.deadlines.len() <= stream.buffer.len(),
        "{} deadlines for {} packets",
        stream.deadlines.len(),
        stream.buffer.len()
    );
}
