use super::*;
use crate::header::Header;
use bytes::Bytes;

#[test]
fn the_capture_time_alone_is_eight_bytes() -> Result<()> {
    let extension = AbsCaptureTimeExtension {
        timestamp: 0x0102_0304_0506_0708,
        estimated_capture_clock_offset: None,
    };
    let raw = extension.marshal()?.freeze();
    assert_eq!(&[1, 2, 3, 4, 5, 6, 7, 8], &raw[..]);
    assert_eq!(
        extension,
        AbsCaptureTimeExtension::unmarshal(&mut raw.clone())?
    );

    // Through a header, in the one-byte form: len = 7.
    let mut header = Header::default();
    header.set_extension(9, raw)?;
    let wire = header.marshal()?;
    assert_eq!(0x97, wire[16]);
    let parsed = Header::unmarshal(&mut wire.freeze())?;
    assert_eq!(
        extension,
        AbsCaptureTimeExtension::unmarshal(&mut parsed.get_extension(9).unwrap())?
    );
    Ok(())
}

#[test]
fn the_clock_offset_is_signed_and_makes_sixteen_bytes() -> Result<()> {
    // Minus half a second in Q32.32.
    let extension = AbsCaptureTimeExtension {
        timestamp: u64::MAX,
        estimated_capture_clock_offset: Some(-(1 << 31)),
    };
    let raw = extension.marshal()?.freeze();
    assert_eq!(16, raw.len());
    assert_eq!(&[0xFF, 0xFF, 0xFF, 0xFF, 0x80, 0, 0, 0], &raw[8..]);
    assert_eq!(
        extension,
        AbsCaptureTimeExtension::unmarshal(&mut raw.clone())?
    );
    Ok(())
}

#[test]
fn an_element_of_another_length_is_refused() {
    for len in [0usize, 7, 9, 15, 17] {
        assert!(AbsCaptureTimeExtension::unmarshal(&mut Bytes::from(vec![0u8; len])).is_err());
    }
    let extension = AbsCaptureTimeExtension::default();
    assert!(extension.marshal_to(&mut [0u8; 7]).is_err());
}
