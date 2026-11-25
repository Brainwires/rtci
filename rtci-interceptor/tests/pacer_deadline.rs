//! The pacer's deadline is an instant at which something happens.
//!
//! A driver calls `handle_timeout` at the instant `poll_timeout` names and asks again. If the
//! packet the deadline was for does not leave at it and the next deadline is that same
//! instant, the driver spins. That happened at rates where a packet's wait is not a whole
//! number of nanoseconds (12 000 bits at 840 kbit/s: 14 285 714.28 ns): refilled to the named
//! instant the budget was a fraction of a nanosecond's worth short.

use bytes::Bytes;
use rtci_interceptor::{AttributedPacket, PacerBuilder, Packet, TaggedPacket};
use sansio::Protocol;
use shared::TransportContext;
use std::time::Instant;

fn media(now: Instant, sequence_number: u16) -> TaggedPacket {
    TaggedPacket {
        now,
        transport: TransportContext::default(),
        message: AttributedPacket::new(Packet::Rtp(rtp::Packet {
            header: rtp::header::Header {
                version: 2,
                payload_type: 96,
                sequence_number,
                timestamp: u32::from(sequence_number) * 3000,
                ssrc: 1,
                ..Default::default()
            },
            payload: Bytes::from(vec![0u8; 1488]),
        })),
    }
}

/// Sixty packets queued, at several rates; the driver follows the deadlines exactly, with no
/// allowance of its own. Every call at a deadline releases a packet, and the next deadline is
/// later than the one just served.
#[test]
fn every_deadline_the_pacer_names_releases_a_packet_and_the_next_is_later() {
    for bitrate in [840_000.0, 333_333.0, 123_457.3, 1_200_000.0, 2_499_999.0] {
        let epoch = Instant::now();
        let mut pacer = PacerBuilder::new().with_target_bitrate(bitrate).build();
        for sequence_number in 0..60u16 {
            pacer.handle_write(media(epoch, sequence_number)).unwrap();
        }
        let mut left = std::iter::from_fn(|| pacer.poll_write()).count();
        let mut calls = 0;
        while let Some(deadline) = pacer.poll_timeout() {
            calls += 1;
            assert!(
                calls <= 60,
                "at {bitrate} bit/s the pacer still names deadlines"
            );
            pacer.handle_timeout(deadline).unwrap();
            let released = std::iter::from_fn(|| pacer.poll_write()).count();
            assert!(
                released >= 1,
                "at {bitrate} bit/s nothing left at the deadline the pacer named (call {calls})"
            );
            left += released;
            if let Some(next) = pacer.poll_timeout() {
                assert!(
                    next > deadline,
                    "at {bitrate} bit/s the next deadline is not later (call {calls})"
                );
            }
        }
        assert_eq!(60, left, "at {bitrate} bit/s every packet left");
    }
}
