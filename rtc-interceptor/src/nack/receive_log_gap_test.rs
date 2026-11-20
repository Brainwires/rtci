//! A forward gap wider than the window clears the whole window and keeps the new packet.

use super::*;

#[test]
fn a_gap_wider_than_the_window_clears_it() {
    let mut log = ReceiveLog::new(128).unwrap();
    for seq in 0..100u16 {
        log.add(seq);
    }
    log.add(30_000);

    assert!(log.get(30_000));
    for seq in (30_000 - 127)..30_000u16 {
        assert!(!log.get(seq), "{seq} was never received");
    }
    log.add(30_001);
    assert!(log.get(30_001));
}

#[test]
fn a_gap_exactly_the_window_wide_matches_the_walk() {
    let mut log = ReceiveLog::new(64).unwrap();
    log.add(10);
    log.add(10 + 64);
    assert!(log.get(10 + 64));
    for seq in 11..(10 + 64u16) {
        assert!(!log.get(seq));
    }
}
