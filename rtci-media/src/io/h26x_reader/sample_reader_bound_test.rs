//! An access unit is bounded: a stream whose slices never start a new picture is refused once
//! the access unit reaches `MAX_ACCESS_UNIT_NALS`, and reading resumes after it.

use super::*;
use std::io::Cursor;

const SC: [u8; 4] = [0x00, 0x00, 0x00, 0x01];

/// A non-IDR slice whose `first_mb_in_slice` is not 0 (the first bit of the slice header is 0),
/// so it never starts an access unit (H.264 7.4.1.2.4).
const NON_FIRST_SLICE: [u8; 3] = [0x01, 0x40, 0xAA];
const SPS: [u8; 3] = [0x67, 0x42, 0xC0];
/// An IDR slice with `first_mb_in_slice == 0`.
const FIRST_IDR_SLICE: [u8; 3] = [0x65, 0x88, 0x84];

fn push(out: &mut Vec<u8>, nal: &[u8]) {
    out.extend_from_slice(&SC);
    out.extend_from_slice(nal);
}

#[test]
fn a_stream_of_non_first_slices_is_refused() {
    let mut stream = vec![];
    for _ in 0..100_000 {
        push(&mut stream, &NON_FIRST_SLICE);
    }
    let mut reader = H26xSampleReader::new(Cursor::new(stream), 4096, false);
    assert!(matches!(reader.next_sample(), Err(Error::ErrBufferFull)));
}

#[test]
fn reading_resumes_after_an_oversized_access_unit() {
    let extra = 903;
    let mut stream = vec![];
    for _ in 0..(MAX_ACCESS_UNIT_NALS + 1 + extra) {
        push(&mut stream, &NON_FIRST_SLICE);
    }
    push(&mut stream, &SPS);
    push(&mut stream, &FIRST_IDR_SLICE);
    let mut reader = H26xSampleReader::new(Cursor::new(stream), 4096, false);

    // The first MAX_ACCESS_UNIT_NALS slices and the one that overflowed are dropped.
    assert!(matches!(reader.next_sample(), Err(Error::ErrBufferFull)));

    // The rest of the slices form the next sample, ended by the SPS.
    let rest = reader.next_sample().expect("the remaining slices");
    assert!(rest.timed);
    assert_eq!(extra * (SC.len() + NON_FIRST_SLICE.len()), rest.data.len());

    let mut picture = vec![];
    push(&mut picture, &SPS);
    push(&mut picture, &FIRST_IDR_SLICE);
    let next = reader.next_sample().expect("the next picture");
    assert!(next.timed);
    assert_eq!(Bytes::from(picture), next.data);

    assert!(matches!(reader.next_sample(), Err(Error::ErrIoEOF)));
}
