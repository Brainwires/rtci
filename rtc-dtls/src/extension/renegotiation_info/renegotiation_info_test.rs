use super::*;

use std::io::{BufReader, BufWriter};

#[test]
fn test_renegotiation_info() -> Result<()> {
    let extension = ExtensionRenegotiationInfo {
        renegotiated_connection: vec![],
    };

    let mut raw = vec![];
    {
        let mut writer = BufWriter::<&mut Vec<u8>>::new(raw.as_mut());
        extension.marshal(&mut writer)?;
    }

    let mut reader = BufReader::new(raw.as_slice());
    let new_extension = ExtensionRenegotiationInfo::unmarshal(&mut reader)?;

    assert_eq!(
        new_extension.renegotiated_connection,
        extension.renegotiated_connection
    );

    Ok(())
}

/// RFC 5746 3.2: the extension carries `renegotiated_connection<0..255>`, of any length (it is
/// only ever empty in the handshakes this crate performs; a peer's is read whatever it holds).
#[test]
fn test_renegotiation_info_carries_a_renegotiated_connection() -> Result<()> {
    assert_eq!(
        ExtensionRenegotiationInfo::unmarshal(&mut [0x00u8, 0x01, 0x00].as_slice())?,
        ExtensionRenegotiationInfo::default()
    );

    let raw = [0x00u8, 0x04, 0x03, 0xaa, 0xbb, 0xcc];
    let extension = ExtensionRenegotiationInfo::unmarshal(&mut raw.as_slice())?;
    assert_eq!(extension.renegotiated_connection, vec![0xaa, 0xbb, 0xcc]);
    let mut out = vec![];
    extension.marshal(&mut out)?;
    assert_eq!(out, raw);

    // The outer and inner lengths disagree.
    assert!(
        ExtensionRenegotiationInfo::unmarshal(&mut [0x00u8, 0x02, 0x03, 0xaa].as_slice()).is_err()
    );
    Ok(())
}
