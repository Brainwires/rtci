//! An OBU whose size field claims more than follows is an error, not an out-of-range slice.

use super::*;

#[test]
fn an_obu_size_past_the_payload_is_refused() {
    // OBU_FRAME with the size bit, size 127, nothing after it.
    assert!(matches!(
        parse_obus(&Bytes::from_static(&[0x32, 0x7F])),
        Err(Error::ErrPayloadTooSmallForObuPayloadSize)
    ));
}

#[test]
fn an_obu_whose_size_fits_parses() -> Result<()> {
    let obus = parse_obus(&Bytes::from_static(&[0x32, 0x02, 0xAA, 0xBB]))?;
    assert_eq!(1, obus.len());
    assert_eq!(&[0xAA, 0xBB], &obus[0].payload[..]);
    Ok(())
}
