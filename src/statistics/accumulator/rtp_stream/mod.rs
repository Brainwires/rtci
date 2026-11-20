//! RTP stream statistics accumulators for inbound and outbound streams.

pub mod inbound;
pub mod outbound;

/// The cumulative number of packets lost of a reception report, as the signed 24-bit value
/// RFC 3550 section 6.4.1 defines (negative when duplicates make more packets arrive than were
/// expected).
///
/// Takes the parsed field as it is: a raw 24-bit value in an unsigned integer is sign-extended,
/// and an already sign-extended signed value passes through unchanged.
pub(crate) fn cumulative_lost(total_lost: impl Into<i64>) -> i64 {
    let value = total_lost.into();
    if (0x80_0000..=0xFF_FFFF).contains(&value) {
        value - 0x100_0000
    } else {
        value
    }
}
