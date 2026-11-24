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

/// The `N` bytes of `data` that start at `offset`, read without the memory accesses
/// depending on `offset`: every start from `first` to `last` (both included, `offset` among
/// them) is read, and only the bytes at `offset` are kept, by a mask.
pub(crate) fn extract_constant_time<const N: usize>(
    data: &[u8],
    offset: usize,
    first: usize,
    last: usize,
) -> [u8; N] {
    let mut out = [0u8; N];
    for start in first..=last {
        if start + N > data.len() {
            break;
        }
        let mask = 0u8.wrapping_sub(is_zero_bit_usize(start ^ offset));
        for (j, byte) in out.iter_mut().enumerate() {
            *byte |= data[start + j] & mask;
        }
    }
    out
}

/// SHA-1 compression functions an HMAC-SHA1 inner hash runs over a message of `len` bytes,
/// after its key block: the message, the 0x80 byte and the 8-byte length, in 64-byte blocks.
pub(crate) fn sha1_blocks(len: usize) -> usize {
    (len + 9).div_ceil(64)
}

/// How many bytes an equalizing HMAC-SHA1 hashes so that the MAC of a record whose content
/// is `content_len` bytes and the equalizer together run as many compression functions as the
/// record with `max_content_len` bytes of content and an empty equalizer would: one block plus
/// the blocks the padding took off. (`additional_data_len`: what the MAC hashes in front of
/// the content.)
pub(crate) fn equalizer_len(
    additional_data_len: usize,
    content_len: usize,
    max_content_len: usize,
) -> usize {
    let missing = sha1_blocks(additional_data_len + max_content_len)
        - sha1_blocks(additional_data_len + content_len);
    64 * (missing + 1) - 9
}

/// 1 when `x` is zero, else 0, with no branch.
fn is_zero_bit_usize(x: usize) -> u8 {
    (((x as u64) | (x as u64).wrapping_neg()) >> 63) as u8 ^ 1
}

/// 1 when `a < b`, else 0, with no branch. Both are far below 2^63.
fn lt_bit(a: usize, b: usize) -> u8 {
    ((a as u64).wrapping_sub(b as u64) >> 63) as u8
}

/// 1 when `x` is zero, else 0, with no branch.
fn is_zero_bit(x: u8) -> u8 {
    ((u16::from(x).wrapping_sub(1) >> 8) & 1) as u8
}

#[cfg(test)]
mod constant_time_test {
    use super::*;

    /// RFC 5246 6.2.3.2: for every padding a record of a given length may claim, the MAC of
    /// its content and the equalizer run the same number of SHA-1 compression functions.
    #[test]
    fn the_mac_work_is_the_same_for_every_padding_length() {
        for additional_data_len in [13, 13 + 8 + 1] {
            for record in [21usize, 64, 100, 300, 1024, 16_404] {
                let max_content = record - 20;
                let expected = sha1_blocks(additional_data_len + max_content)
                    + sha1_blocks(equalizer_len(additional_data_len, max_content, max_content));
                for padding in 0..=max_content.min(256) {
                    let content = max_content - padding;
                    let work = sha1_blocks(additional_data_len + content)
                        + sha1_blocks(equalizer_len(additional_data_len, content, max_content));
                    assert_eq!(work, expected, "record {record}, padding {padding}");
                }
            }
        }
    }

    /// The MAC is read from where the padding puts it, whichever place in the window that is.
    #[test]
    fn the_mac_is_extracted_from_any_offset_in_the_window() {
        let data: Vec<u8> = (0..=255u8).cycle().take(600).collect();
        for offset in 300..=556 {
            let mac = extract_constant_time::<20>(&data, offset, 300, 580);
            assert_eq!(&mac[..], &data[offset..offset + 20]);
        }
    }
}
