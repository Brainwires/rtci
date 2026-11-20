//! Block cipher padding for the CBC suites (RFC 5246 section 6.2.3.2): `n + 1` bytes, each `n`.
//!
//! The check runs the same steps whatever the padding claims, so how long it takes says nothing
//! about the plaintext (the Lucky Thirteen family of timing differences). It reads the last 256
//! bytes (or the whole record, when shorter) and folds every comparison into one result instead
//! of returning at the first mismatch.

/// Pads `block` from `pos` to its end: every byte from `pos` on becomes the padding length, the
/// number of padding bytes excluding the length byte itself.
///
/// # Panics
///
/// If `pos` is not inside `block` (there must be room for the length byte), or the padding would
/// be longer than 255 bytes plus the length byte.
pub(crate) fn pad(block: &mut [u8], pos: usize) {
    assert!(pos < block.len(), "`pos` is bigger or equal to block size");
    let padding_length = block.len() - pos - 1;
    assert!(padding_length <= 255, "block size is too big for DTLS");
    block[pos..].fill(padding_length as u8);
}

/// Checks the padding at the end of `data`, which must also leave `reserved` bytes (the MAC) in
/// front of it. Returns the padding's length, length byte included, and whether it is valid;
/// the length means nothing when it is not.
///
/// Only `data.len()`, which is public (the record's length), changes what this does; the padding
/// bytes themselves do not.
pub(crate) fn check_padding(data: &[u8], reserved: usize) -> (usize, bool) {
    let Some(&padding_value) = data.last() else {
        return (0, false);
    };
    let len = data.len();
    let padding_len = usize::from(padding_value) + 1;

    // 1 when the claimed padding leaves `reserved` bytes in front of it, else 0.
    let fits = 1 ^ lt_bit(len, padding_len + reserved);

    // Every byte that could be padding is read; those inside the claimed padding must equal
    // the length byte.
    let mut mismatch = 0u8;
    for i in 0..len.min(256) {
        let in_padding = 0u8.wrapping_sub(lt_bit(i, padding_len));
        mismatch |= in_padding & (data[len - 1 - i] ^ padding_value);
    }

    let valid = fits & is_zero_bit(mismatch);
    (padding_len, valid == 1)
}

/// 1 when `a < b`, else 0, with no branch. Both are far below 2^63.
fn lt_bit(a: usize, b: usize) -> u8 {
    ((a as u64).wrapping_sub(b as u64) >> 63) as u8
}

/// 1 when `x` is zero, else 0, with no branch.
fn is_zero_bit(x: u8) -> u8 {
    ((u16::from(x).wrapping_sub(1) >> 8) & 1) as u8
}
