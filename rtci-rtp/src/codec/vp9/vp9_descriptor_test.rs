//! RFC 9628 section 4.2 (payload descriptor), both directions.

use super::*;

/// A VP9 inter frame's uncompressed header: profile 0, shown, not error resilient; it refreshes
/// slot `refresh` (a bit mask) and predicts from slot `reference` for all three references.
pub(super) fn vp9_inter_frame(refresh: u8, reference: u8) -> Bytes {
    // frame_marker 10, profile 00, show_existing_frame 0, frame_type 1, show_frame 1,
    // error_resilient_mode 0.
    let mut bits: Vec<u8> = vec![1, 0, 0, 0, 0, 1, 1, 0];
    bits.extend_from_slice(&[0, 0]); // reset_frame_context
    for i in (0..8).rev() {
        bits.push((refresh >> i) & 1); // refresh_frame_flags
    }
    for _ in 0..3 {
        for i in (0..3).rev() {
            bits.push((reference >> i) & 1); // ref_frame_idx
        }
        bits.push(0); // ref_frame_sign_bias
    }
    let mut out = vec![0u8; bits.len().div_ceil(8)];
    for (i, bit) in bits.iter().enumerate() {
        out[i / 8] |= bit << (7 - i % 8);
    }
    out.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
    Bytes::from(out)
}

/// RFC 9628 4.2: F is only meaningful with I=1 ("if the I bit is set to zero, then this bit
/// MUST also be set to zero and ignored by receivers").
#[test]
fn f_is_ignored_when_there_is_no_picture_id() -> Result<()> {
    let mut packet = Vp9Packet::default();
    // I=0, P=1, F=1: one descriptor octet; with F honoured, 0x02 was read as a P_DIFF.
    assert_eq!(
        packet.depacketize(&Bytes::from_static(&[0x50, 0x02, 0xAA]))?,
        Bytes::from_static(&[0x02, 0xAA])
    );
    assert!(packet.pdiff.is_empty());

    // I=0, L=1, F=1: non-flexible layer indices are two octets (TID 1, SID 1; TL0PICIDX 7).
    assert_eq!(
        packet.depacketize(&Bytes::from_static(&[0x30, 0x22, 0x07, 0xAA]))?,
        Bytes::from_static(&[0xAA])
    );
    assert_eq!((packet.tid, packet.sid, packet.tl0picidx), (1, 1, 7));
    Ok(())
}

/// RFC 9628 4.2: SID is a three-bit field; every value is a legal spatial layer.
#[test]
fn every_spatial_layer_id_is_accepted() -> Result<()> {
    for sid in 0..8u8 {
        let mut packet = Vp9Packet::default();
        // I=0, L=1, F=0; layer octet TID 0, U 0, SID, D 0; TL0PICIDX 0.
        packet.depacketize(&Bytes::copy_from_slice(&[0x20, sid << 1, 0x00, 0xAA]))?;
        assert_eq!(packet.sid, sid);
    }
    Ok(())
}

/// RFC 9628 4.2.1: with Y=0 the SS carries no resolution; the fields describe this packet's SS,
/// not an earlier one's.
#[test]
fn a_scalability_structure_without_resolutions_has_none() -> Result<()> {
    let mut packet = Vp9Packet::default();
    // V=1; N_S=0, Y=1; 640x480.
    packet.depacketize(&Bytes::from_static(&[
        0x02, 0x10, 0x02, 0x80, 0x01, 0xE0, 0xAA,
    ]))?;
    assert_eq!(
        (packet.width.clone(), packet.height.clone()),
        (vec![640], vec![480])
    );
    // V=1; N_S=0, Y=0.
    packet.depacketize(&Bytes::from_static(&[0x02, 0x00, 0xAA]))?;
    assert!(packet.width.is_empty() && packet.height.is_empty());
    Ok(())
}

/// RFC 9628 4.2: "The value of the F bit MUST only change on the first packet of a key
/// picture." A frame whose header does not parse used to go out in flexible mode in the middle
/// of a non-flexible stream.
#[test]
fn the_mode_does_not_change_between_key_pictures() -> Result<()> {
    let mut payloader = Vp9Payloader {
        initial_picture_id_fn: Some(Arc::new(|| 0)),
        ..Default::default()
    };
    let key = payloader.payload(1200, &Bytes::from(super::vp9_test::vp9_key_frame_640x480()))?;
    assert_eq!(
        key[0][0] & 0x10,
        0,
        "the key frame is sent in non-flexible mode"
    );

    // Not a VP9 frame: the frame marker is wrong.
    let odd = payloader.payload(1200, &Bytes::from_static(&[0x01, 0x02, 0x03]))?;
    assert_eq!(odd.len(), 1);
    assert_eq!(odd[0][0] & 0x10, 0, "F stays 0 until the next key picture");
    assert_ne!(
        odd[0][0] & 0x40,
        0,
        "an unknown frame is not offered as a switch point"
    );
    Ok(())
}

/// RFC 9628 4.2: P=0 only for a frame without inter-picture prediction, and with P=1 and F=1
/// at least one reference index follows.
#[test]
fn flexible_mode_marks_an_inter_frame_as_predicted() -> Result<()> {
    let mut payloader = Vp9Payloader {
        initial_picture_id_fn: Some(Arc::new(|| 10)),
        flexible_mode: true,
        ..Default::default()
    };
    let key = payloader.payload(1200, &Bytes::from(super::vp9_test::vp9_key_frame_640x480()))?;
    assert_eq!(key[0][0] & 0xD0, 0x90, "key frame: I=1, P=0, F=1");

    let inter = payloader.payload(1200, &vp9_inter_frame(0x01, 0))?;
    assert_eq!(inter.len(), 1);
    assert_eq!(inter[0][0] & 0xD0, 0xD0, "inter frame: I=1, P=1, F=1");

    let mut packet = Vp9Packet::default();
    let data = packet.depacketize(&inter[0])?;
    assert_eq!(data, vp9_inter_frame(0x01, 0));
    assert_eq!(packet.picture_id, 11);
    assert_eq!(
        packet.pdiff,
        vec![1],
        "the frame predicts from the key frame, one picture back"
    );
    Ok(())
}
