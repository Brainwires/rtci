//! The constant-time completeness check of a fragment set (audit finding R-L11).

use super::reassembly_queue::{Chunks, ReassemblyQueue};
use crate::chunk::chunk_payload_data::{ChunkPayloadData, PayloadProtocolIdentifier};
use bytes::Bytes;

fn fragment(tsn: u32, beginning: bool, ending: bool) -> ChunkPayloadData {
    ChunkPayloadData {
        tsn,
        beginning_fragment: beginning,
        ending_fragment: ending,
        user_data: Bytes::from_static(b"x"),
        ..Default::default()
    }
}

/// Contiguity is judged across the TSN wrap: u32::MAX - 1, u32::MAX, 0 is one message.
#[test]
fn fragments_across_the_tsn_wrap_complete_the_message() {
    let mut set = Chunks::new(0, 0, PayloadProtocolIdentifier::Binary, vec![]);
    assert!(!set.push(fragment(0, false, true)));
    assert!(!set.push(fragment(u32::MAX - 1, true, false)));
    assert!(set.push(fragment(u32::MAX, false, false)));
    assert!(set.is_complete());
}

/// A gap anywhere leaves the set incomplete, however many fragments surround it, and the
/// fragment that fills it completes the set.
#[test]
fn a_gap_among_many_fragments_is_found_and_filled() {
    const N: u32 = 20_000;
    let mut set = Chunks::new(0, 0, PayloadProtocolIdentifier::Binary, vec![]);
    let missing = N / 2;
    for tsn in (0..N).rev() {
        if tsn == missing {
            continue;
        }
        assert!(!set.push(fragment(1000 + tsn, tsn == 0, tsn == N - 1)));
    }
    assert!(!set.is_complete(), "TSN {} is missing", 1000 + missing);
    assert!(set.push(fragment(1000 + missing, false, false)));
}

/// The same through an ordered reassembly queue: a message of many fragments arriving in
/// reverse becomes readable exactly when its first fragment lands.
#[test]
fn ordered_message_of_many_fragments_becomes_readable_when_complete() {
    const N: u32 = 10_000;
    let mut queue = ReassemblyQueue::new(0);
    for tsn in (1..N).rev() {
        let mut c = fragment(tsn, false, tsn == N - 1);
        c.stream_identifier = 0;
        c.stream_sequence_number = 0;
        assert!(!queue.push(c));
        assert!(!queue.is_readable());
    }
    let mut first = fragment(0, true, false);
    first.stream_identifier = 0;
    assert!(queue.push(first));
    assert!(queue.is_readable());
    assert_eq!(N as usize, queue.read().unwrap().len());
}
