//! RFC 3550 Appendix A.1 and A.3: sequence number validation and loss.

use super::*;

/// A source past its probation whose last packet was `first + 1`.
fn established(first: u16) -> SourceSequence {
    let mut source = SourceSequence::new(first);
    assert!(!source.update(first));
    assert!(source.update(first.wrapping_add(1)));
    source
}

#[test]
fn a_new_source_is_on_probation_until_two_packets_arrive_in_sequence() {
    let mut source = SourceSequence::new(100);
    assert!(source.on_probation());
    assert!(!source.update(100), "the first packet does not validate");
    assert!(source.on_probation());
    assert!(source.update(101), "the second in sequence does");
    assert!(!source.on_probation());
    assert_eq!(1, source.received());
    assert_eq!(101, source.extended_max());
}

#[test]
fn a_gap_during_probation_starts_the_probation_again() {
    let mut source = SourceSequence::new(100);
    assert!(!source.update(100));
    assert!(!source.update(105), "not sequential: probation restarts");
    assert!(source.on_probation());
    assert!(source.update(106));
    assert!(!source.on_probation());
}

#[test]
fn the_sequence_number_wrapping_counts_a_cycle() {
    let mut source = established(65533);
    assert!(source.update(65535));
    assert!(source.update(0));
    assert!(source.update(1));
    assert_eq!((1 << 16) + 1, source.extended_max());
    // 65534 (validated), 65535, 0, 1 were received.
    assert_eq!(4, source.received());
    assert_eq!(4, source.expected());
    assert_eq!(0, source.cumulative_lost());
}

#[test]
fn a_gap_below_max_dropout_is_loss() {
    let mut source = established(10);
    assert!(source.update(11 + 2999));
    assert_eq!(3000, source.expected());
    assert_eq!(2, source.received());
    assert_eq!(2998, source.cumulative_lost());
}

#[test]
fn a_late_packet_is_not_lost_and_a_duplicate_makes_the_loss_negative() {
    let mut source = established(10);
    assert!(source.update(13));
    assert_eq!(1, source.cumulative_lost(), "12 is missing");
    assert!(source.update(12), "late, within MAX_MISORDER");
    assert_eq!(0, source.cumulative_lost());
    assert_eq!(13, source.extended_max(), "the highest does not go back");
    assert!(source.update(12), "a duplicate");
    assert_eq!(-1, source.cumulative_lost());
}

#[test]
fn a_large_jump_is_accepted_only_when_the_next_packet_confirms_a_restart() {
    let mut source = established(10);
    // A lone packet far away is dropped and changes nothing.
    assert!(!source.update(40_000));
    assert_eq!(11, source.extended_max());
    assert!(source.update(12));
    // Two in a row: the source restarted; the state starts over at the second.
    assert!(!source.update(40_000));
    assert!(source.update(40_001));
    assert_eq!(40_001, source.extended_max());
    assert_eq!(1, source.received());
    assert_eq!(1, source.expected());
}

#[test]
fn a_jump_of_exactly_max_dropout_is_not_taken_for_loss() {
    let mut source = established(10);
    assert!(!source.update(11 + MAX_DROPOUT));
    assert_eq!(11, source.extended_max());
}

#[test]
fn a_packet_just_past_max_misorder_behind_is_refused() {
    let mut source = established(1000);
    // 100 behind the highest (1001) is late; 101 behind is a jump.
    assert!(source.update(1001 - MAX_MISORDER + 1));
    assert!(!source.update(1001 - MAX_MISORDER - 1));
}
