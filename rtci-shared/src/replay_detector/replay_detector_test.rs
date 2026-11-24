use super::*;

#[test]
fn test_replay_detector() {
    const LARGE_SEQ: u64 = 0x100000000000;

    #[allow(clippy::type_complexity)]
    let tests: Vec<(&str, usize, u64, Vec<u64>, Vec<bool>, Vec<u64>, Vec<u64>)> = vec![
        (
            "Continuous",
            16,
            0x0000FFFFFFFFFFFF,
            vec![
                0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20,
            ],
            vec![
                true, true, true, true, true, true, true, true, true, true, true, true, true, true,
                true, true, true, true, true, true, true,
            ],
            vec![
                0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20,
            ],
            vec![],
        ),
        (
            "ValidLargeJump",
            16,
            0x0000FFFFFFFFFFFF,
            vec![
                0,
                1,
                2,
                3,
                4,
                5,
                6,
                7,
                8,
                9,
                LARGE_SEQ,
                11,
                LARGE_SEQ + 1,
                LARGE_SEQ + 2,
                LARGE_SEQ + 3,
            ],
            vec![
                true, true, true, true, true, true, true, true, true, true, true, true, true, true,
                true,
            ],
            vec![
                0,
                1,
                2,
                3,
                4,
                5,
                6,
                7,
                8,
                9,
                LARGE_SEQ,
                LARGE_SEQ + 1,
                LARGE_SEQ + 2,
                LARGE_SEQ + 3,
            ],
            vec![],
        ),
        (
            "InvalidLargeJump",
            16,
            0x0000FFFFFFFFFFFF,
            vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9, LARGE_SEQ, 11, 12, 13, 14, 15],
            vec![
                true, true, true, true, true, true, true, true, true, true, false, true, true,
                true, true, true,
            ],
            vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 11, 12, 13, 14, 15],
            vec![],
        ),
        (
            "DuplicateAfterValidJump",
            196,
            0x0000FFFFFFFFFFFF,
            vec![0, 1, 2, 129, 0, 1, 2],
            vec![true, true, true, true, true, true, true],
            vec![0, 1, 2, 129],
            vec![],
        ),
        (
            "DuplicateAfterInvalidJump",
            196,
            0x0000FFFFFFFFFFFF,
            vec![0, 1, 2, 128, 0, 1, 2],
            vec![true, true, true, false, true, true, true],
            vec![0, 1, 2],
            vec![],
        ),
        (
            "ContinuousOffset",
            16,
            0x0000FFFFFFFFFFFF,
            vec![
                100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114,
            ],
            vec![
                true, true, true, true, true, true, true, true, true, true, true, true, true, true,
                true,
            ],
            vec![
                100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114,
            ],
            vec![],
        ),
        (
            "Reordered",
            128,
            0x0000FFFFFFFFFFFF,
            vec![
                96, 64, 16, 80, 32, 48, 8, 24, 88, 40, 128, 56, 72, 112, 104, 120,
            ],
            vec![
                true, true, true, true, true, true, true, true, true, true, true, true, true, true,
                true, true,
            ],
            vec![
                96, 64, 16, 80, 32, 48, 8, 24, 88, 40, 128, 56, 72, 112, 104, 120,
            ],
            vec![],
        ),
        (
            "Old",
            100,
            0x0000FFFFFFFFFFFF,
            vec![
                24, 32, 40, 48, 56, 64, 72, 80, 88, 96, 104, 112, 120, 128, 8, 16,
            ],
            vec![
                true, true, true, true, true, true, true, true, true, true, true, true, true, true,
                true, true,
            ],
            vec![24, 32, 40, 48, 56, 64, 72, 80, 88, 96, 104, 112, 120, 128],
            vec![],
        ),
        (
            "ContinuouesReplayed",
            8,
            0x0000FFFFFFFFFFFF,
            vec![
                16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
            ],
            vec![
                true, true, true, true, true, true, true, true, true, true, true, true, true, true,
                true, true, true, true, true, true,
            ],
            vec![16, 17, 18, 19, 20, 21, 22, 23, 24, 25],
            vec![],
        ),
        (
            "ReplayedLater",
            128,
            0x0000FFFFFFFFFFFF,
            vec![
                16, 32, 48, 64, 80, 96, 112, 128, 16, 32, 48, 64, 80, 96, 112, 128,
            ],
            vec![
                true, true, true, true, true, true, true, true, true, true, true, true, true, true,
                true, true,
            ],
            vec![16, 32, 48, 64, 80, 96, 112, 128],
            vec![],
        ),
        (
            "ReplayedQuick",
            128,
            0x0000FFFFFFFFFFFF,
            vec![
                16, 16, 32, 32, 48, 48, 64, 64, 80, 80, 96, 96, 112, 112, 128, 128,
            ],
            vec![
                true, true, true, true, true, true, true, true, true, true, true, true, true, true,
                true, true,
            ],
            vec![16, 32, 48, 64, 80, 96, 112, 128],
            vec![],
        ),
        (
            "Strict",
            0,
            0x0000FFFFFFFFFFFF,
            vec![1, 3, 2, 4, 5, 6, 7, 8, 9, 10],
            vec![true, true, true, true, true, true, true, true, true, true],
            vec![1, 3, 4, 5, 6, 7, 8, 9, 10],
            vec![],
        ),
        (
            "Overflow",
            128,
            0x0000FFFFFFFFFFFF,
            vec![
                0x0000FFFFFFFFFFFE,
                0x0000FFFFFFFFFFFF,
                0x0001000000000000,
                0x0001000000000001,
            ],
            vec![true, true, true, true],
            vec![0x0000FFFFFFFFFFFE, 0x0000FFFFFFFFFFFF],
            vec![],
        ),
        (
            "WrapContinuous",
            64,
            0xFFFF,
            vec![
                0xFFFC, 0xFFFD, 0xFFFE, 0xFFFF, 0x0000, 0x0001, 0x0002, 0x0003,
            ],
            vec![true, true, true, true, true, true, true, true],
            vec![0xFFFC, 0xFFFD, 0xFFFE, 0xFFFF],
            vec![
                0xFFFC, 0xFFFD, 0xFFFE, 0xFFFF, 0x0000, 0x0001, 0x0002, 0x0003,
            ],
        ),
        (
            "WrapReordered",
            64,
            0xFFFF,
            vec![
                0xFFFD, 0xFFFC, 0x0002, 0xFFFE, 0x0000, 0x0001, 0xFFFF, 0x0003,
            ],
            vec![true, true, true, true, true, true, true, true],
            vec![0xFFFD, 0xFFFC, 0xFFFE, 0xFFFF],
            vec![
                0xFFFD, 0xFFFC, 0x0002, 0xFFFE, 0x0000, 0x0001, 0xFFFF, 0x0003,
            ],
        ),
        (
            "WrapReorderedReplayed",
            64,
            0xFFFF,
            vec![
                0xFFFD, 0xFFFC, 0xFFFC, 0x0002, 0xFFFE, 0xFFFC, 0x0000, 0x0001, 0x0001, 0xFFFF,
                0x0001, 0x0003,
            ],
            vec![
                true, true, true, true, true, true, true, true, true, true, true, true,
            ],
            vec![0xFFFD, 0xFFFC, 0xFFFE, 0xFFFF],
            vec![
                0xFFFD, 0xFFFC, 0x0002, 0xFFFE, 0x0000, 0x0001, 0xFFFF, 0x0003,
            ],
        ),
        (
            "RepeatedReorderedAfterWrap",
            4,
            0xFFFF,
            vec![0x0, 0xFFFF, 0xFFFF],
            vec![true, true, true],
            vec![0x0, 0xFFFF],
            vec![0x0, 0xFFFF],
        ),
    ];

    for (name, windows_size, max_seq, input, valid, expected, mut expected_wrap) in tests {
        if expected_wrap.is_empty() {
            expected_wrap.extend_from_slice(&expected);
        }

        for k in 0..2 {
            let mut det: Box<dyn ReplayDetector> = if k == 0 {
                Box::new(SlidingWindowDetector::new(windows_size, max_seq))
            } else {
                Box::new(WrappedSlidingWindowDetector::new(windows_size, max_seq))
            };
            let exp = if k == 0 { &expected } else { &expected_wrap };

            let mut out = vec![];
            for (i, seq) in input.iter().enumerate() {
                let ok = det.check(*seq);
                if ok && valid[i] {
                    out.push(*seq);
                    det.accept();
                }
            }

            assert_eq!(&out, exp, "{name} failed");
        }
    }
}

/// A sequence number exactly half the range behind the head is old, as in the SRTP rollover
/// estimate (RFC 3711 Appendix A).
#[test]
fn test_wrapped_half_range_behind_is_too_old() {
    let mut det = WrappedSlidingWindowDetector::new(64, 0xFFFF);
    for seq in 32768..=40000u64 {
        assert!(det.check(seq), "{seq}");
        det.accept();
    }

    assert!(
        !det.check(40000 - 32768),
        "a packet half the range behind the head must be too old"
    );
    det.accept(); // must be a no-op after a failed check

    // The head did not move, so the next packet is still new.
    assert!(det.check(40001));
    det.accept();

    // Just under half the range ahead of the head is still a forward jump.
    assert!(det.check((40001 + 32767) & 0xFFFF));
    det.accept();
    assert!(!det.check(40001), "the old head is now behind the window");
}

/// A number accepted before the head moves on must stay refused while it is inside the window,
/// for window sizes whose last word is more than half full (`n % 64 > 32`) too.
#[test]
fn test_replay_refused_after_head_moves_any_window_size() {
    // The case the fuzzer found: window 53, accept 0, jump to 12, then 0 again.
    let mut det = SlidingWindowDetector::new(53, (1 << 48) - 1);
    assert!(det.check(0));
    det.accept();
    assert!(det.check(12));
    det.accept();
    assert!(det.check(9));
    det.accept();
    assert!(det.check(6));
    det.accept();
    assert!(
        !det.check(0),
        "0 was accepted already and is inside the window"
    );

    for window in 1..=200usize {
        for k in 0..2 {
            let mut det: Box<dyn ReplayDetector> = if k == 0 {
                Box::new(SlidingWindowDetector::new(window, (1 << 48) - 1))
            } else {
                Box::new(WrappedSlidingWindowDetector::new(window, 0xFFFF))
            };
            assert!(det.check(0));
            det.accept();
            for head in 1..window as u64 {
                assert!(det.check(head));
                det.accept();
                assert!(
                    !det.check(0),
                    "window {window} (detector {k}): 0 replayed with the head at {head}"
                );
            }
            assert!(det.check(window as u64));
            det.accept();
            assert!(
                !det.check(0),
                "window {window} (detector {k}): 0 is out of the window"
            );
        }
    }
}
