//! A NAL unit shorter than the two-byte H.265 header is skipped, not read past its end.

use super::*;

#[test]
fn a_one_byte_nal_unit_is_skipped() -> Result<()> {
    let mut payloader = HevcPayloader::default();
    let payloads = payloader.payload(1200, &Bytes::from_static(&[0x40]))?;
    assert!(payloads.is_empty());
    Ok(())
}
