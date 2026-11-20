//! A stream holds at most `MAX_BUFFERED_PACKETS`, whatever order the sequence numbers come in.

use super::*;
use crate::AttributedPacket;
use shared::{TransportContext, TransportMessage};

fn make_rtp(seq: u16, now: Instant) -> TaggedPacket {
    TransportMessage {
        now,
        transport: TransportContext::default(),
        message: AttributedPacket::new(Packet::Rtp(rtp::Packet {
            header: rtp::header::Header {
                ssrc: 1,
                sequence_number: seq,
                timestamp: u32::from(seq) * 90,
                ..Default::default()
            },
            ..Default::default()
        })),
    }
}

fn stream() -> JitterBufferStream {
    let delay = Duration::from_millis(50);
    JitterBufferStream::new(90_000, None, delay, delay, Duration::from_millis(500))
}

/// Strictly decreasing sequence numbers each sort first. They are held only up to the bound,
/// and once the head has waited the maximum delay the whole buffer drains.
#[test]
fn decreasing_sequence_numbers_are_held_only_up_to_the_bound() {
    let mut s = stream();
    let now = Instant::now();
    for step in 0..(MAX_BUFFERED_PACKETS as u16 + 100) {
        s.insert(now, make_rtp(60_000 - step, now));
    }
    assert_eq!(MAX_BUFFERED_PACKETS, s.buffer.len());
    assert!(
        !s.insert(now, make_rtp(60_001, now)),
        "a full buffer takes nothing"
    );

    let later = now + Duration::from_millis(500);
    let mut released = 0;
    while s.pop_ready(later).is_some() {
        released += 1;
    }
    assert_eq!(MAX_BUFFERED_PACKETS, released);
    assert!(s.buffer.is_empty());
}

#[test]
fn a_duplicate_is_refused_wherever_it_lands() {
    let mut s = stream();
    let now = Instant::now();
    for seq in [10u16, 12, 14] {
        assert!(s.insert(now, make_rtp(seq, now)));
    }
    assert!(!s.insert(now, make_rtp(12, now)));
    assert!(!s.insert(now, make_rtp(14, now)));
    assert!(!s.insert(now, make_rtp(10, now)));
    assert!(s.insert(now, make_rtp(11, now)));
    assert_eq!(
        vec![10, 11, 12, 14],
        s.buffer.iter().map(|(seq, ..)| *seq).collect::<Vec<_>>()
    );
}
