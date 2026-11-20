use super::*;

#[test]
fn test_fixed_big_int_set_bit() {
    let mut bi = FixedBigInt::new(224);

    bi.set_bit(0);
    assert_eq!(
        bi.to_string(),
        "0000000000000000000000000000000000000000000000000000000000000001"
    );

    bi.lsh(1);
    assert_eq!(
        bi.to_string(),
        "0000000000000000000000000000000000000000000000000000000000000002"
    );

    bi.lsh(0);
    assert_eq!(
        bi.to_string(),
        "0000000000000000000000000000000000000000000000000000000000000002"
    );

    bi.set_bit(10);
    assert_eq!(
        bi.to_string(),
        "0000000000000000000000000000000000000000000000000000000000000402"
    );
    bi.lsh(20);
    assert_eq!(
        bi.to_string(),
        "0000000000000000000000000000000000000000000000000000000040200000"
    );

    bi.set_bit(80);
    assert_eq!(
        bi.to_string(),
        "0000000000000000000000000000000000000000000100000000000040200000"
    );
    bi.lsh(4);
    assert_eq!(
        bi.to_string(),
        "0000000000000000000000000000000000000000001000000000000402000000"
    );

    bi.set_bit(130);
    assert_eq!(
        bi.to_string(),
        "0000000000000000000000000000000400000000001000000000000402000000"
    );
    bi.lsh(64);
    assert_eq!(
        bi.to_string(),
        "0000000000000004000000000010000000000004020000000000000000000000"
    );

    bi.set_bit(7);
    assert_eq!(
        bi.to_string(),
        "0000000000000004000000000010000000000004020000000000000000000080"
    );

    bi.lsh(129);
    assert_eq!(
        bi.to_string(),
        "0000000004000000000000000000010000000000000000000000000000000000"
    );

    for _ in 0..256 {
        bi.lsh(1);
        bi.set_bit(0);
    }
    assert_eq!(
        bi.to_string(),
        "00000000FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
    );
}

/// A shift keeps every bit below `n`, whatever `n % 64` is, and drops the ones at or above it.
#[test]
fn test_fixed_big_int_lsh_keeps_bits_below_n() {
    for n in 1..=200usize {
        let mut bi = FixedBigInt::new(n);
        bi.set_bit(0);
        for i in 1..n {
            bi.lsh(1);
            assert_eq!(bi.bit(i), 1, "n = {n}: bit {i} lost by a shift");
            assert_eq!(bi.bit(i - 1), 0, "n = {n}: bit {} kept", i - 1);
        }
        // One more shift moves the bit out of the window, and out of the storage too.
        bi.lsh(1);
        assert!(bi.bits.iter().all(|w| *w == 0), "n = {n}: {bi}");
    }
}
