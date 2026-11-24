//! RFC 7741 section 4.2 (payload descriptor) and 4.5 (frame reconstruction), receive side.

use super::*;

/// RFC 7741 4.2: a packet is the one-octet descriptor and at least one octet of VP8 data. The
/// payloader emits such packets for a fragment's tail; they were refused as "short".
#[test]
fn a_continuation_packet_of_two_or_three_octets_is_accepted() -> Result<()> {
    let mut packet = Vp8Packet::default();
    assert_eq!(
        packet.depacketize(&Bytes::from_static(&[0x00, 0xAB]))?,
        Bytes::from_static(&[0xAB])
    );
    assert_eq!(
        packet.depacketize(&Bytes::from_static(&[0x00, 0xAB, 0xCD]))?,
        Bytes::from_static(&[0xAB, 0xCD])
    );
    // A descriptor with nothing after it carries no frame data.
    assert!(packet.depacketize(&Bytes::from_static(&[0x00])).is_err());
    assert!(
        packet
            .depacketize(&Bytes::from_static(&[0x80, 0x80, 0x11]))
            .is_err()
    );
    Ok(())
}

/// Whatever the payloader emits, at any MTU, the depacketizer reads back: the frame is the
/// concatenation of the packets' payloads.
#[test]
fn every_packet_the_payloader_emits_depacketizes() -> Result<()> {
    let frame = Bytes::from_static(&[0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96]);
    for enable_picture_id in [false, true] {
        for mtu in 2..=12 {
            let mut payloader = Vp8Payloader {
                enable_picture_id,
                ..Default::default()
            };
            let payloads = payloader.payload(mtu, &frame)?;
            if payloads.is_empty() {
                continue;
            }
            let mut packet = Vp8Packet::default();
            let mut out = vec![];
            for payload in &payloads {
                out.extend_from_slice(&packet.depacketize(payload)?);
            }
            assert_eq!(out, frame, "mtu {mtu}, picture id {enable_picture_id}");
        }
    }
    Ok(())
}

/// RFC 7741 4.2: with X=0 there is no extension octet and no I/L/T/K field. One depacketizer
/// reads a whole stream, so the previous packet's flags must not leak into this one.
#[test]
fn a_packet_without_extensions_after_one_with_them_has_none() -> Result<()> {
    let mut packet = Vp8Packet::default();
    // X=1, S=1; I=1 L=1 T=1 K=1; PictureID 5; TL0PICIDX 9; TID 2, Y 1, KEYIDX 3.
    assert_eq!(
        packet.depacketize(&Bytes::from_static(&[
            0x90, 0xF0, 0x05, 0x09, 0xA3, 0xAA, 0xBB
        ]))?,
        Bytes::from_static(&[0xAA, 0xBB])
    );
    assert_eq!(
        (
            packet.picture_id,
            packet.tl0_pic_idx,
            packet.tid,
            packet.y,
            packet.key_idx
        ),
        (5, 9, 2, 1, 3)
    );

    // X=0: every octet after the first is VP8 data.
    assert_eq!(
        packet.depacketize(&Bytes::from_static(&[0x00, 0x11, 0x22, 0x33, 0x44]))?,
        Bytes::from_static(&[0x11, 0x22, 0x33, 0x44])
    );
    assert_eq!(
        (packet.x, packet.i, packet.l, packet.t, packet.k),
        (0, 0, 0, 0, 0)
    );
    assert_eq!(
        (
            packet.picture_id,
            packet.tl0_pic_idx,
            packet.tid,
            packet.y,
            packet.key_idx
        ),
        (0, 0, 0, 0, 0)
    );
    Ok(())
}

/// RFC 7741 4.2: TID and Y are ignored when T=0, KEYIDX when K=0.
#[test]
fn tid_is_ignored_without_t_and_keyidx_without_k() -> Result<()> {
    let mut packet = Vp8Packet::default();
    // X=1; T=1 K=1; TID 3, Y 1, KEYIDX 31.
    packet.depacketize(&Bytes::from_static(&[0x80, 0x30, 0xFF, 0xAA]))?;
    assert_eq!((packet.tid, packet.y, packet.key_idx), (3, 1, 31));
    // X=1; K=1 only: the TID and Y bits of the octet mean nothing.
    packet.depacketize(&Bytes::from_static(&[0x80, 0x10, 0xE7, 0xAA]))?;
    assert_eq!((packet.tid, packet.y, packet.key_idx), (0, 0, 7));
    // X=1; T=1 only: the KEYIDX bits mean nothing.
    packet.depacketize(&Bytes::from_static(&[0x80, 0x20, 0x5F, 0xAA]))?;
    assert_eq!((packet.tid, packet.y, packet.key_idx), (1, 0, 0));
    Ok(())
}

/// RFC 7741 4.2: the R bits of the first octet and the RSV bits of the extension octet are
/// ignored on receipt.
#[test]
fn reserved_bits_are_ignored() -> Result<()> {
    let mut packet = Vp8Packet::default();
    // First octet 0xD8 = X, R, S, R; extension octet 0x8F = I plus all four RSV bits.
    assert_eq!(
        packet.depacketize(&Bytes::from_static(&[0xD8, 0x8F, 0x7F, 0xAA]))?,
        Bytes::from_static(&[0xAA])
    );
    assert_eq!((packet.x, packet.n, packet.s, packet.pid), (1, 0, 1, 0));
    assert_eq!((packet.i, packet.l, packet.t, packet.k), (1, 0, 0, 0));
    assert_eq!(packet.picture_id, 0x7F);
    Ok(())
}

/// RFC 7741 4.5.1: a frame begins at a packet with S=1 and PID=0. S=1 with another PID starts a
/// later partition of the same frame.
#[test]
fn only_the_first_partition_starts_a_frame() {
    let packet = Vp8Packet::default();
    assert!(packet.is_partition_head(&Bytes::from_static(&[0x10, 0x00])));
    for pid in 1..=7u8 {
        assert!(
            !packet.is_partition_head(&Bytes::copy_from_slice(&[0x10 | pid, 0x00])),
            "S=1 with PID {pid} is not a frame start"
        );
    }
    assert!(!packet.is_partition_head(&Bytes::from_static(&[0x00, 0x00])));
}
