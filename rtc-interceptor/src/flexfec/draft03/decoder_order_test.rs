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

/// Draft-03 sections 5.1 and 5.2.1: with a `repair-window`, media held longer than the window
/// is not used to rebuild a loss, and the buffers hold only what the window spans. Without the
/// window the same late repair packet recovers.
#[test]
fn the_repair_window_bounds_what_is_held_for_recovery() {
    let block: Vec<rtp::Packet> = (10..14).map(media).collect();
    let repair = super::super::encoder::FlexFec03Encoder::new(118, REPAIR_SSRC)
        .encode(&block, 1, 0)
        .remove(0);
    let epoch = Instant::now();
    let run = |window: Option<Duration>, repair_after: Duration| {
        let mut decoder = FlexFec03Decoder::new(REPAIR_SSRC, MEDIA_SSRC);
        if let Some(window) = window {
            decoder = decoder.with_repair_window(window);
        }
        // 12 is lost.
        for packet in block.iter().filter(|p| p.header.sequence_number != 12) {
            assert!(decoder.decode_at(epoch, packet.clone()).is_empty());
        }
        let recovered = decoder.decode_at(epoch + repair_after, repair.clone());
        (recovered, decoder.recovered_len())
    };

    let (recovered, _) = run(Some(Duration::from_millis(200)), Duration::from_millis(100));
    assert_eq!(
        recovered
            .iter()
            .map(|p| p.header.sequence_number)
            .collect::<Vec<_>>(),
        vec![12],
        "inside the window"
    );
    let (recovered, held) = run(Some(Duration::from_millis(200)), Duration::from_millis(300));
    assert!(recovered.is_empty(), "the media is older than the window");
    assert_eq!(held, 0, "nothing older than the window is held");
    let (recovered, _) = run(None, Duration::from_millis(300));
    assert_eq!(recovered.len(), 1, "no window: the count limits only");
}
