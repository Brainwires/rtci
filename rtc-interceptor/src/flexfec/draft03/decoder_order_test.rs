//! The decoder keeps its packets ordered by a key that is a total order whatever sequence
//! numbers arrive, so sorting them can never meet an inconsistent comparator.

use super::*;

const MEDIA_SSRC: u32 = 0x1111_1111;
const REPAIR_SSRC: u32 = 0x2222_2222;

fn media(sequence_number: u16) -> rtp::Packet {
    rtp::Packet {
        header: rtp::header::Header {
            version: 2,
            payload_type: 96,
            sequence_number,
            ssrc: MEDIA_SSRC,
            ..Default::default()
        },
        payload: bytes::Bytes::from_static(&[1, 2, 3, 4]),
    }
}

#[test]
fn the_key_orders_oldest_first_across_the_wrap() {
    let newest = 2u16;
    let mut held = vec![1u16, 65535, 2, 0, 65534];
    held.sort_by_key(|&sequence_number| sequence_key(newest, sequence_number));
    assert_eq!(vec![65534, 65535, 0, 1, 2], held);
}

/// Media sequence numbers spread over the whole 16-bit space form a cycle under a pairwise
/// "is newer" comparison. Every one of them must still be held, without a panic.
#[test]
fn media_spread_over_the_whole_space_is_held_without_panicking() {
    let mut decoder = FlexFec03Decoder::new(REPAIR_SSRC, MEDIA_SSRC);
    let count = MAX_MEDIA_PACKETS as u16 - 1;
    for index in 0..count {
        let recovered = decoder.decode(media(index.wrapping_mul(659)));
        assert!(recovered.is_empty());
    }
    assert_eq!(count as usize, decoder.recovered_len());
}
