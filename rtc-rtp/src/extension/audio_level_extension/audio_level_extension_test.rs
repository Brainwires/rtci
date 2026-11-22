use super::*;
use bytes::{Bytes, BytesMut};
use shared::error::Result;

#[test]
fn test_audio_level_extension_too_small() -> Result<()> {
    let mut buf = &vec![0u8; 0][..];
    let result = AudioLevelExtension::unmarshal(&mut buf);
    assert!(result.is_err());

    Ok(())
}

#[test]
fn test_audio_level_extension_voice_true() -> Result<()> {
    let raw = Bytes::from_static(&[0x88]);
    let buf = &mut raw.clone();
    let a1 = AudioLevelExtension::unmarshal(buf)?;
    let a2 = AudioLevelExtension {
        level: 8,
        voice: true,
    };
    assert_eq!(a1, a2);

    let mut dst = BytesMut::with_capacity(a2.marshal_size());
    dst.resize(a2.marshal_size(), 0);
    a2.marshal_to(&mut dst)?;
    assert_eq!(raw, dst.freeze());

    Ok(())
}

#[test]
fn test_audio_level_extension_voice_false() -> Result<()> {
    let raw = Bytes::from_static(&[0x8]);
    let buf = &mut raw.clone();
    let a1 = AudioLevelExtension::unmarshal(buf)?;
    let a2 = AudioLevelExtension {
        level: 8,
        voice: false,
    };
    assert_eq!(a1, a2);

    let mut dst = BytesMut::with_capacity(a2.marshal_size());
    dst.resize(a2.marshal_size(), 0);
    a2.marshal_to(&mut dst)?;
    assert_eq!(raw, dst.freeze());

    Ok(())
}

#[test]
fn test_audio_level_extension_level_overflow() -> Result<()> {
    let a = AudioLevelExtension {
        level: 128,
        voice: false,
    };

    let mut dst = BytesMut::with_capacity(a.marshal_size());
    dst.resize(a.marshal_size(), 0);
    let result = a.marshal_to(&mut dst);
    assert!(result.is_err());

    Ok(())
}

#[test]
fn the_level_travels_in_both_header_forms_of_rfc6464() -> Result<()> {
    use crate::header::{EXTENSION_PROFILE_TWO_BYTE, Header};

    let level = AudioLevelExtension {
        level: 45,
        voice: true,
    };
    // Section 3, the one-byte form: ID, len=0, V and the level.
    let mut header = Header::default();
    header.set_extension(1, level.marshal()?.freeze())?;
    let raw = header.marshal()?;
    assert_eq!(
        &[0xBE, 0xDE, 0x00, 0x01, 0x10, 0xAD, 0x00, 0x00],
        &raw[12..]
    );
    let parsed = Header::unmarshal(&mut raw.freeze())?;
    assert_eq!(
        level,
        AudioLevelExtension::unmarshal(&mut parsed.get_extension(1).unwrap())?
    );

    // The two-byte form: ID, len=1, V and the level, a padding byte.
    let mut header = Header {
        extension: true,
        extension_profile: EXTENSION_PROFILE_TWO_BYTE,
        ..Default::default()
    };
    header.set_extension(1, level.marshal()?.freeze())?;
    let raw = header.marshal()?;
    assert_eq!(
        &[0x10, 0x00, 0x00, 0x01, 0x01, 0x01, 0xAD, 0x00],
        &raw[12..]
    );
    let parsed = Header::unmarshal(&mut raw.freeze())?;
    assert_eq!(
        level,
        AudioLevelExtension::unmarshal(&mut parsed.get_extension(1).unwrap())?
    );
    Ok(())
}

#[test]
fn the_v_bit_is_ignored_when_vad_is_off() -> Result<()> {
    let level = AudioLevelExtension::unmarshal(&mut Bytes::from_static(&[0x80 | 30]))?;
    assert_eq!(Some(true), level.voice_activity(true));
    assert_eq!(None, level.voice_activity(false));
    assert_eq!(30, level.level);
    Ok(())
}

#[test]
fn vad_is_on_unless_the_extmap_says_off() {
    assert_eq!(Ok(true), parse_vad_attribute(None));
    assert_eq!(Ok(true), parse_vad_attribute(Some("vad=on")));
    assert_eq!(Ok(false), parse_vad_attribute(Some("vad=off")));
    assert!(parse_vad_attribute(Some("vad=maybe")).is_err());
}

#[test]
fn digital_silence_is_the_lowest_level() -> Result<()> {
    let silence = AudioLevelExtension {
        level: AUDIO_LEVEL_SILENCE,
        voice: false,
    };
    assert_eq!(&[0x7F], &silence.marshal()?[..]);
    Ok(())
}
