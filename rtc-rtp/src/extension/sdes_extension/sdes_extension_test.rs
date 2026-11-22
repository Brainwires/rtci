use super::*;
use crate::header::{EXTENSION_PROFILE_ONE_BYTE, EXTENSION_PROFILE_TWO_BYTE, Header};
use bytes::Bytes;

#[test]
fn a_mid_travels_in_the_one_byte_form_as_its_text() -> Result<()> {
    // RFC 7941 4.1.1: ID, len = bytes - 1, the UTF-8 text.
    let mut header = Header::default();
    header.set_extension(4, Mid::new("0")?.marshal()?.freeze())?;
    let raw = header.marshal()?;
    assert_eq!(&[0xBE, 0xDE, 0x00, 0x01, 0x40, b'0', 0, 0], &raw[12..]);
    let parsed = Header::unmarshal(&mut raw.freeze())?;
    let mid = Mid::unmarshal(&mut parsed.get_extension(4).unwrap())?;
    assert_eq!("0", mid.as_str());
    Ok(())
}

#[test]
fn a_mid_and_a_rid_travel_in_the_two_byte_form() -> Result<()> {
    // RFC 7941 4.1.2: ID, len = bytes, the UTF-8 text.
    let mut header = Header {
        extension: true,
        extension_profile: EXTENSION_PROFILE_TWO_BYTE,
        ..Default::default()
    };
    header.set_extension(4, Mid::new("audio")?.marshal()?.freeze())?;
    header.set_extension(10, RtpStreamId::new("hi")?.marshal()?.freeze())?;
    let raw = header.marshal()?;
    assert_eq!(
        &[
            0x10, 0x00, 0x00, 0x03, 4, 5, b'a', b'u', b'd', b'i', b'o', 10, 2, b'h', b'i', 0
        ],
        &raw[12..]
    );
    let parsed = Header::unmarshal(&mut raw.freeze())?;
    assert_eq!(
        "audio",
        Mid::unmarshal(&mut parsed.get_extension(4).unwrap())?.as_str()
    );
    assert_eq!(
        "hi",
        RtpStreamId::unmarshal(&mut parsed.get_extension(10).unwrap())?.as_str()
    );
    Ok(())
}

#[test]
fn a_value_over_16_bytes_needs_the_two_byte_form_for_the_whole_packet() -> Result<()> {
    // RFC 7941 4.2.1.
    let short = RtpStreamId::new("q")?;
    let long = RtpStreamId::new("abcdefghijklmnopq")?;
    assert!(short.fits_one_byte_form());
    assert!(!long.fits_one_byte_form());

    let mut header = Header::default();
    header.set_extension(1, short.marshal()?.freeze())?;
    assert_eq!(EXTENSION_PROFILE_ONE_BYTE, header.extension_profile);
    // The plain setter keeps the stream's form; the upgrading one moves every element.
    assert!(header.set_extension(2, long.marshal()?.freeze()).is_err());
    header.set_extension_upgrading(2, long.marshal()?.freeze())?;
    assert_eq!(EXTENSION_PROFILE_TWO_BYTE, header.extension_profile);
    let parsed = Header::unmarshal(&mut header.marshal()?.freeze())?;
    assert_eq!(
        short,
        RtpStreamId::unmarshal(&mut parsed.get_extension(1).unwrap())?
    );
    assert_eq!(
        long,
        RtpStreamId::unmarshal(&mut parsed.get_extension(2).unwrap())?
    );
    Ok(())
}

#[test]
fn text_that_is_not_utf8_is_an_error_not_an_empty_value() {
    // The audit's S3: 0xFF read as "".
    assert!(Mid::unmarshal(&mut Bytes::from_static(&[0xFF])).is_err());
    assert!(RtpStreamId::unmarshal(&mut Bytes::from_static(&[0xC3, 0x28])).is_err());
}

#[test]
fn a_stream_id_is_ascii_letters_and_digits_only() {
    // RFC 8852 3.
    for good in ["1", "h", "Layer2", "a1B2c3"] {
        assert!(RtpStreamId::new(good).is_ok());
        assert!(RepairedRtpStreamId::new(good).is_ok());
    }
    for bad in ["", "a-b", "a_b", "a b", "é", "~q"] {
        assert!(RtpStreamId::new(bad).is_err(), "{bad:?}");
        assert!(RepairedRtpStreamId::new(bad).is_err(), "{bad:?}");
        assert!(RtpStreamId::unmarshal(&mut Bytes::copy_from_slice(bad.as_bytes())).is_err());
    }
    // A MID is any UTF-8 token.
    assert!(Mid::new("a-b_é").is_ok());
}

#[test]
fn a_value_is_1_to_255_bytes() {
    assert!(Mid::new("").is_err());
    assert!(Mid::unmarshal(&mut Bytes::new()).is_err());
    assert!(Mid::new("m".repeat(255)).is_ok());
    assert!(Mid::new("m".repeat(256)).is_err());
    assert!(RtpStreamId::new("r".repeat(255)).is_ok());
    assert!(RtpStreamId::new("r".repeat(256)).is_err());
}

#[test]
fn the_text_is_not_null_terminated_on_the_wire() -> Result<()> {
    let rrid = RepairedRtpStreamId::new("hi")?;
    assert_eq!(&b"hi"[..], &rrid.marshal()?[..]);
    assert_eq!(2, rrid.marshal_size());
    // A trailing NUL would be part of the value, and is not a letter or a digit.
    assert!(RepairedRtpStreamId::unmarshal(&mut Bytes::from_static(b"hi\0")).is_err());
    Ok(())
}
