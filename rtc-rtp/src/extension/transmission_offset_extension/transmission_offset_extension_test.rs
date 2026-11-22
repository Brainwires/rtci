use super::*;
use crate::header::Header;
use bytes::Bytes;

fn offset(offset: i32) -> TransmissionOffsetExtension {
    TransmissionOffsetExtension { offset }
}

#[test]
fn the_offset_is_a_signed_24_bit_number() -> Result<()> {
    for (value, bytes) in [
        (0i32, [0u8, 0, 0]),
        (1, [0, 0, 1]),
        (3000, [0x00, 0x0B, 0xB8]),
        (-1, [0xFF, 0xFF, 0xFF]),
        (-3000, [0xFF, 0xF4, 0x48]),
        (TRANSMISSION_OFFSET_MAX, [0x7F, 0xFF, 0xFF]),
        (TRANSMISSION_OFFSET_MIN, [0x80, 0x00, 0x00]),
    ] {
        let raw = offset(value).marshal()?.freeze();
        assert_eq!(&bytes, &raw[..], "{value}");
        assert_eq!(
            offset(value),
            TransmissionOffsetExtension::unmarshal(&mut raw.clone())?
        );
    }
    Ok(())
}

#[test]
fn an_offset_outside_24_bits_is_refused() {
    assert!(offset(TRANSMISSION_OFFSET_MAX + 1).marshal().is_err());
    assert!(offset(TRANSMISSION_OFFSET_MIN - 1).marshal().is_err());
}

#[test]
fn a_short_element_is_refused() {
    assert!(TransmissionOffsetExtension::unmarshal(&mut Bytes::from_static(&[0, 1])).is_err());
}

#[test]
fn the_offset_travels_in_a_header_with_len_2() -> Result<()> {
    // RFC 5450 section 3: the one-byte form, len=2.
    let mut header = Header::default();
    header.set_extension(2, offset(-90).marshal()?.freeze())?;
    let raw = header.marshal()?;
    assert_eq!(
        &[0xBE, 0xDE, 0x00, 0x01, 0x22, 0xFF, 0xFF, 0xA6],
        &raw[12..]
    );
    let parsed = Header::unmarshal(&mut raw.freeze())?;
    assert_eq!(
        offset(-90),
        TransmissionOffsetExtension::unmarshal(&mut parsed.get_extension(2).unwrap())?
    );
    Ok(())
}
