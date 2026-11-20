//! A stream that ends on `00 00` and then resumes with `01` must not underflow.

use super::*;
use std::collections::VecDeque;

/// Hands out its chunks one per `read`, with an end of stream (a zero-length read) between them.
struct Chunks(VecDeque<Option<Vec<u8>>>);

impl Read for Chunks {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self.0.pop_front() {
            Some(Some(chunk)) => {
                buf[..chunk.len()].copy_from_slice(&chunk);
                Ok(chunk.len())
            }
            Some(None) | None => Ok(0),
        }
    }
}

#[test]
fn resuming_after_trailing_zeros_does_not_panic() {
    let mut reader = H26xReader::new(
        Chunks(VecDeque::from(vec![
            Some(vec![0, 0, 0, 1, 0x65, 0xAA, 0x00, 0x00]),
            None,
            Some(vec![0x01, 0x41, 0xBB]),
        ])),
        64,
        false,
    );
    // Whatever the reader makes of it, reading to the end must not panic.
    for _ in 0..8 {
        if reader.next_nal().is_err() && reader.next_nal().is_err() {
            break;
        }
    }
}
