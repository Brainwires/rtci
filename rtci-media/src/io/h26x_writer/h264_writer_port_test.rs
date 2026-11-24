//! webrtc-rs `media` v0.17.1 `h264_writer` tests, ported to `H26xWriter` (H.264 mode).

use super::*;

#[test]
fn test_is_key_frame() {
    // A non-key frame.
    assert!(!is_key_frame(&[0x27, 0x90, 0x90]));
    // An SPS packetized with STAP-A.
    assert!(is_key_frame(&[
        0x38, 0x00, 0x03, 0x27, 0x90, 0x90, 0x00, 0x05, 0x28, 0x90, 0x90, 0x90, 0x90,
    ]));
    // An SPS with no packetization.
    assert!(is_key_frame(&[0x27, 0x90, 0x90, 0x00]));
}

fn written(payloads: &[&[u8]], has_key_frame: bool) -> Result<Vec<u8>> {
    let mut writer = H26xWriter::new(Vec::<u8>::new(), false);
    writer.has_key_frame = has_key_frame;
    for payload in payloads {
        writer.write_rtp(&rtp::Packet {
            payload: Bytes::copy_from_slice(payload),
            ..Default::default()
        })?;
    }
    writer.close()?;
    Ok(writer.writer)
}

#[test]
fn test_write_rtp() -> Result<()> {
    // An empty payload writes nothing.
    assert_eq!(Vec::<u8>::new(), written(&[&[]], false)?);
    // No key frame yet: the packet is discarded.
    assert_eq!(Vec::<u8>::new(), written(&[&[0x25, 0x90, 0x90]], false)?);
    // A single NAL unit packet.
    assert_eq!(
        vec![0x00, 0x00, 0x00, 0x01, 0x27, 0x90, 0x90],
        written(&[&[0x27, 0x90, 0x90]], true)?
    );
    // A STAP-A packet.
    assert_eq!(
        vec![
            0x00, 0x00, 0x00, 0x01, 0x27, 0x90, 0x90, 0x00, 0x00, 0x00, 0x01, 0x28, 0x90, 0x90,
            0x90, 0x90,
        ],
        written(
            &[&[
                0x38, 0x00, 0x03, 0x27, 0x90, 0x90, 0x00, 0x05, 0x28, 0x90, 0x90, 0x90, 0x90,
            ]],
            true
        )?
    );
    Ok(())
}

#[test]
fn test_write_rtp_fu() -> Result<()> {
    assert_eq!(
        vec![
            0x00, 0x00, 0x00, 0x01, 0x25, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
        ],
        written(
            &[
                &[0x3C, 0x85, 0x90, 0x90, 0x90],
                &[0x3C, 0x45, 0x90, 0x90, 0x90]
            ],
            true
        )?
    );
    Ok(())
}
