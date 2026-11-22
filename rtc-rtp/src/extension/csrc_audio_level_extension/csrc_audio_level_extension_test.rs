use super::*;
use crate::header::{EXTENSION_PROFILE_TWO_BYTE, Header};
use bytes::Bytes;

fn levels(levels: &[u8]) -> CsrcAudioLevelExtension {
    CsrcAudioLevelExtension {
        levels: levels.to_vec(),
    }
}

#[test]
fn the_one_byte_form_of_rfc6465_has_len_count_minus_one() -> Result<()> {
    // RFC 6465 section 4, Figure 1: three CSRCs, len=2.
    let mut header = Header {
        csrc: vec![0x11, 0x22, 0x33],
        ..Default::default()
    };
    header.set_extension(6, levels(&[10, 60, 127]).marshal()?.freeze())?;
    let raw = header.marshal()?;
    assert_eq!(&[0xBE, 0xDE, 0x00, 0x01, 0x62, 10, 60, 127], &raw[24..]);

    let parsed = Header::unmarshal(&mut raw.freeze())?;
    let element = parsed.get_extension(6).expect("the element");
    let decoded = CsrcAudioLevelExtension::unmarshal(&mut element.clone())?;
    assert_eq!(
        vec![(0x11, 10), (0x22, 60), (0x33, 127)],
        decoded.pair_with(&parsed.csrc)?
    );
    Ok(())
}

#[test]
fn the_two_byte_form_of_rfc6465_has_len_count() -> Result<()> {
    // RFC 6465 section 4, Figure 2.
    let mut header = Header {
        csrc: vec![1, 2, 3],
        extension: true,
        extension_profile: EXTENSION_PROFILE_TWO_BYTE,
        ..Default::default()
    };
    header.set_extension(6, levels(&[1, 2, 3]).marshal()?.freeze())?;
    let raw = header.marshal()?;
    assert_eq!(
        &[0x10, 0x00, 0x00, 0x02, 0x06, 0x03, 1, 2, 3, 0, 0, 0],
        &raw[24..]
    );
    let parsed = Header::unmarshal(&mut raw.freeze())?;
    let decoded = CsrcAudioLevelExtension::unmarshal(&mut parsed.get_extension(6).unwrap())?;
    assert_eq!(levels(&[1, 2, 3]), decoded);
    Ok(())
}

#[test]
fn the_reserved_bit_is_ignored_when_read_and_never_written() -> Result<()> {
    let decoded = CsrcAudioLevelExtension::unmarshal(&mut Bytes::from_static(&[0x85, 0xFF]))?;
    assert_eq!(levels(&[5, 127]), decoded);
    assert_eq!(&[5, 127], &decoded.marshal()?[..]);
    assert_eq!(
        Err(Error::AudioLevelOverflow),
        levels(&[128]).marshal().map(|_| ())
    );
    Ok(())
}

#[test]
fn more_than_15_levels_are_refused_both_ways() {
    assert!(levels(&[0; 15]).marshal().is_ok());
    assert!(levels(&[0; 16]).marshal().is_err());
    assert!(CsrcAudioLevelExtension::unmarshal(&mut Bytes::from(vec![0u8; 15])).is_ok());
    assert!(CsrcAudioLevelExtension::unmarshal(&mut Bytes::from(vec![0u8; 16])).is_err());
}

#[test]
fn levels_that_do_not_match_the_csrc_list_cannot_be_paired() {
    assert!(levels(&[1, 2]).pair_with(&[7]).is_err());
    assert!(levels(&[1]).pair_with(&[7, 8]).is_err());
    assert_eq!(Ok(vec![]), levels(&[]).pair_with(&[]));
}
