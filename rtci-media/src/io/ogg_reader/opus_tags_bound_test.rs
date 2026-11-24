//! A huge declared comment count is refused for lack of data, not by allocating for it.

use super::*;

#[test]
fn a_huge_comment_count_is_refused() {
    let mut payload = b"OpusTags".to_vec();
    payload.extend_from_slice(&0u32.to_le_bytes()); // vendor length
    payload.extend_from_slice(&u32::MAX.to_le_bytes()); // comment count
    assert!(parse_opus_tags(&payload).is_err());
}
