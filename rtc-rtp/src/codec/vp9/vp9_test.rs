use super::*;

#[test]
fn test_vp9_packet_unmarshal() -> Result<()> {
    let tests = vec![
        (
            "Empty",
            Bytes::from_static(&[]),
            Vp9Packet::default(),
            Bytes::new(),
            Some(Error::ErrShortPacket),
        ),
        (
            "NonFlexible",
            Bytes::from_static(&[0x00, 0xAA]),
            Vp9Packet::default(),
            Bytes::from_static(&[0xAA]),
            None,
        ),
        (
            "NonFlexiblePictureID",
            Bytes::from_static(&[0x80, 0x02, 0xAA]),
            Vp9Packet {
                i: true,
                picture_id: 0x02,
                ..Default::default()
            },
            Bytes::from_static(&[0xAA]),
            None,
        ),
        (
            "NonFlexiblePictureIDExt",
            Bytes::from_static(&[0x80, 0x81, 0xFF, 0xAA]),
            Vp9Packet {
                i: true,
                picture_id: 0x01FF,
                ..Default::default()
            },
            Bytes::from_static(&[0xAA]),
            None,
        ),
        (
            "NonFlexiblePictureIDExt_ShortPacket0",
            Bytes::from_static(&[0x80, 0x81]),
            Vp9Packet::default(),
            Bytes::new(),
            Some(Error::ErrShortPacket),
        ),
        (
            "NonFlexiblePictureIDExt_ShortPacket1",
            Bytes::from_static(&[0x80]),
            Vp9Packet::default(),
            Bytes::new(),
            Some(Error::ErrShortPacket),
        ),
        (
            "NonFlexibleLayerIndicePictureID",
            Bytes::from_static(&[0xA0, 0x02, 0x23, 0x01, 0xAA]),
            Vp9Packet {
                i: true,
                l: true,
                picture_id: 0x02,
                tid: 0x01,
                sid: 0x01,
                d: true,
                tl0picidx: 0x01,
                ..Default::default()
            },
            Bytes::from_static(&[0xAA]),
            None,
        ),
        (
            "FlexibleLayerIndicePictureID",
            Bytes::from_static(&[0xB0, 0x02, 0x23, 0x01, 0xAA]),
            Vp9Packet {
                f: true,
                i: true,
                l: true,
                picture_id: 0x02,
                tid: 0x01,
                sid: 0x01,
                d: true,
                ..Default::default()
            },
            Bytes::from_static(&[0x01, 0xAA]),
            None,
        ),
        (
            "NonFlexibleLayerIndicePictureID_ShortPacket0",
            Bytes::from_static(&[0xA0, 0x02, 0x23]),
            Vp9Packet::default(),
            Bytes::new(),
            Some(Error::ErrShortPacket),
        ),
        (
            "NonFlexibleLayerIndicePictureID_ShortPacket1",
            Bytes::from_static(&[0xA0, 0x02]),
            Vp9Packet::default(),
            Bytes::new(),
            Some(Error::ErrShortPacket),
        ),
        (
            "FlexiblePictureIDRefIndex",
            Bytes::from_static(&[0xD0, 0x02, 0x03, 0x04, 0xAA]),
            Vp9Packet {
                i: true,
                p: true,
                f: true,
                picture_id: 0x02,
                pdiff: vec![0x01, 0x02],
                ..Default::default()
            },
            Bytes::from_static(&[0xAA]),
            None,
        ),
        (
            "FlexiblePictureIDRefIndex_TooManyPDiff",
            Bytes::from_static(&[0xD0, 0x02, 0x03, 0x05, 0x07, 0x09, 0x10, 0xAA]),
            Vp9Packet::default(),
            Bytes::new(),
            Some(Error::ErrTooManyPDiff),
        ),
        (
            "FlexiblePictureIDRefIndexNoPayload",
            Bytes::from_static(&[0xD0, 0x02, 0x03, 0x04]),
            Vp9Packet {
                i: true,
                p: true,
                f: true,
                picture_id: 0x02,
                pdiff: vec![0x01, 0x02],
                ..Default::default()
            },
            Bytes::from_static(&[]),
            None,
        ),
        (
            "FlexiblePictureIDRefIndex_ShortPacket0",
            Bytes::from_static(&[0xD0, 0x02, 0x03]),
            Vp9Packet::default(),
            Bytes::new(),
            Some(Error::ErrShortPacket),
        ),
        (
            "FlexiblePictureIDRefIndex_ShortPacket1",
            Bytes::from_static(&[0xD0, 0x02]),
            Vp9Packet::default(),
            Bytes::new(),
            Some(Error::ErrShortPacket),
        ),
        (
            "FlexiblePictureIDRefIndex_ShortPacket2",
            Bytes::from_static(&[0xD0]),
            Vp9Packet::default(),
            Bytes::new(),
            Some(Error::ErrShortPacket),
        ),
        (
            "ScalabilityStructureResolutionsNoPayload",
            Bytes::from_static(&[
                0x0A,
                (1 << 5) | (1 << 4), // NS:1 Y:1 G:0
                (640 >> 8) as u8,
                (640 & 0xff) as u8,
                (360 >> 8) as u8,
                (360 & 0xff) as u8,
                (1280 >> 8) as u8,
                (1280 & 0xff) as u8,
                (720 >> 8) as u8,
                (720 & 0xff) as u8,
            ]),
            Vp9Packet {
                b: true,
                v: true,
                ns: 1,
                y: true,
                g: false,
                ng: 0,
                width: vec![640, 1280],
                height: vec![360, 720],
                ..Default::default()
            },
            Bytes::new(),
            None,
        ),
        (
            "ScalabilityStructureNoPayload",
            Bytes::from_static(&[
                0x0A,
                (1 << 5) | (1 << 3), // NS:1 Y:0 G:1
                2,
                (1 << 4),            // T:0 U:1 R:0 -
                (2 << 5) | (1 << 2), // T:2 U:0 R:1 -
                33,
            ]),
            Vp9Packet {
                b: true,
                v: true,
                ns: 1,
                y: false,
                g: true,
                ng: 2,
                pgtid: vec![0, 2],
                pgu: vec![true, false],
                pgpdiff: vec![vec![], vec![33]],
                ..Default::default()
            },
            Bytes::new(),
            None,
        ),
    ];

    for (name, b, pkt, expected, err) in tests {
        let mut p = Vp9Packet::default();

        if let Some(expected) = err {
            if let Err(actual) = p.depacketize(&b) {
                assert_eq!(
                    expected, actual,
                    "{name}: expected {expected}, but got {actual}"
                );
            } else {
                panic!("{name}: expected error, but got passed");
            }
        } else {
            let payload = p.depacketize(&b)?;
            assert_eq!(pkt, p, "{name}: expected {pkt:?}, but got {p:?}");
            assert_eq!(payload, expected);
        }
    }

    Ok(())
}

#[test]
fn test_vp9_payloader_payload() -> Result<()> {
    let mut r0 = 8692;
    let mut rands = vec![];
    for _ in 0..10 {
        rands.push(vec![(r0 >> 8) as u8 | 0x80, (r0 & 0xFF) as u8]);
        r0 += 1;
    }

    let tests = vec![
        ("NilPayload", vec![Bytes::new()], 100, vec![]),
        ("SmallMTU", vec![Bytes::from(vec![0x00, 0x00])], 1, vec![]),
        (
            "NegativeMTU",
            vec![Bytes::from(vec![0x00, 0x00])],
            0,
            vec![],
        ),
        (
            "OnePacket",
            vec![Bytes::from(vec![0x01, 0x02])],
            10,
            vec![Bytes::from(vec![
                0x9C,
                rands[0][0],
                rands[0][1],
                0x01,
                0x02,
            ])],
        ),
        (
            "TwoPackets",
            vec![Bytes::from(vec![0x01, 0x02])],
            4,
            vec![
                Bytes::from(vec![0x98, rands[0][0], rands[0][1], 0x01]),
                Bytes::from(vec![0x94, rands[0][0], rands[0][1], 0x02]),
            ],
        ),
        (
            "ThreePackets",
            vec![Bytes::from(vec![0x01, 0x02, 0x03])],
            4,
            vec![
                Bytes::from(vec![0x98, rands[0][0], rands[0][1], 0x01]),
                Bytes::from(vec![0x90, rands[0][0], rands[0][1], 0x02]),
                Bytes::from(vec![0x94, rands[0][0], rands[0][1], 0x03]),
            ],
        ),
        (
            "TwoFramesFourPackets",
            vec![Bytes::from(vec![0x01, 0x02, 0x03]), Bytes::from(vec![0x04])],
            5,
            vec![
                Bytes::from(vec![0x98, rands[0][0], rands[0][1], 0x01, 0x02]),
                Bytes::from(vec![0x94, rands[0][0], rands[0][1], 0x03]),
                Bytes::from(vec![0x9C, rands[1][0], rands[1][1], 0x04]),
            ],
        ),
    ];

    for (name, bs, mtu, expected) in tests {
        let mut pck = Vp9Payloader {
            initial_picture_id_fn: Some(Arc::new(|| -> u16 { 8692 })),
            ..Default::default()
        };

        let mut actual = vec![];
        for b in &bs {
            actual.extend(pck.payload(mtu, b)?);
        }
        assert_eq!(actual, expected, "{name}: Payloaded packet");
    }

    //"PictureIDOverflow"
    {
        let mut pck = Vp9Payloader {
            initial_picture_id_fn: Some(Arc::new(|| -> u16 { 8692 })),
            ..Default::default()
        };
        let mut p_prev = Vp9Packet::default();
        for i in 0..0x8000 {
            let res = pck.payload(4, &Bytes::from_static(&[0x01]))?;
            let mut p = Vp9Packet::default();
            p.depacketize(&res[0])?;

            if i > 0 {
                if p_prev.picture_id == 0x7FFF {
                    assert_eq!(
                        p.picture_id, 0,
                        "Picture ID next to 0x7FFF must be 0, got {}",
                        p.picture_id
                    );
                } else if p_prev.picture_id + 1 != p.picture_id {
                    panic!(
                        "Picture ID next must be incremented by 1: {} -> {}",
                        p_prev.picture_id, p.picture_id,
                    );
                }
            }

            p_prev = p;
        }
    }

    Ok(())
}

#[test]
fn test_vp9_partition_head_checker_is_partition_head() -> Result<()> {
    let vp9 = Vp9Packet::default();

    //"SmallPacket"
    assert!(
        !vp9.is_partition_head(&Bytes::new()),
        "Small packet should not be the head of a new partition"
    );

    //"NormalPacket"
    assert!(
        vp9.is_partition_head(&Bytes::from_static(&[0x18, 0x00, 0x00])),
        "VP9 RTP packet with B flag should be head of a new partition"
    );
    assert!(
        !vp9.is_partition_head(&Bytes::from_static(&[0x10, 0x00, 0x00])),
        "VP9 RTP packet without B flag should not be head of a new partition"
    );

    Ok(())
}

/// A depacketizer is used for a whole stream. The reference indices of one flexible-mode packet
/// used to stay in `pdiff`, so after two packets every further one failed with
/// `ErrTooManyPDiff`; and each scalability structure appended its picture group to the last
/// one's, without bound.
#[test]
fn test_vp9_per_picture_state_does_not_accumulate() -> Result<()> {
    let mut pck = Vp9Packet::default();
    // P=1, F=1; two P_DIFFs (1 with N=1, then 1 with N=0); one payload byte.
    let flexible = Bytes::from_static(&[0x50, 0x03, 0x02, 0xaa]);
    for _ in 0..10 {
        let payload = pck.depacketize(&flexible)?;
        assert_eq!(&payload[..], &[0xaa]);
        assert_eq!(pck.pdiff, vec![1, 1]);
    }

    // V=1; SS with N_S=0, G=1, N_G=255 pictures (T=0, U=0, R=0 each).
    let mut ss = vec![0x02, 0x02, 0xff];
    ss.extend(std::iter::repeat_n(0x00, 255));
    ss.push(0xaa);
    let ss = Bytes::from(ss);
    for _ in 0..10 {
        pck.depacketize(&ss)?;
        assert_eq!(pck.pgtid.len(), 255);
        assert_eq!(pck.pgu.len(), 255);
        assert_eq!(pck.pgpdiff.len(), 255);
    }
    // A packet without reference indices reports none.
    pck.depacketize(&Bytes::from_static(&[0x00, 0xaa]))?;
    assert!(pck.pdiff.is_empty());
    Ok(())
}

/// A VP9 key frame header: frame_marker 2, profile 0, show_existing_frame 0,
/// frame_type 0 (key), show_frame 1, error_resilient_mode 0, the sync code,
/// color_space 1 (BT.601), color_range 0, then width-1 = 639 and
/// height-1 = 479 (16 bits each), then frame data.
fn vp9_key_frame_640x480() -> Vec<u8> {
    // Bits: 10 0 0 0 0 1 0 | 0x49 0x83 0x42 | 001 0 | 0x027F | 0x01DF | pad
    let mut bits: Vec<u8> = vec![1, 0, 0, 0, 0, 0, 1, 0];
    for byte in [0x49u8, 0x83, 0x42] {
        for i in (0..8).rev() {
            bits.push((byte >> i) & 1);
        }
    }
    bits.extend([0, 0, 1, 0]);
    for value in [639u16, 479] {
        for i in (0..16).rev() {
            bits.push(((value >> i) & 1) as u8);
        }
    }
    while bits.len() % 8 != 0 {
        bits.push(0);
    }
    let mut out: Vec<u8> = bits
        .chunks(8)
        .map(|c| c.iter().fold(0u8, |acc, b| (acc << 1) | b))
        .collect();
    out.extend([0xaa, 0xbb, 0xcc]);
    out
}

#[test]
fn test_vp9_frame_header_parse() {
    let header = Vp9FrameHeader::parse(&vp9_key_frame_640x480()).unwrap();
    assert_eq!(
        header,
        Vp9FrameHeader {
            key_frame: true,
            width: 640,
            height: 480
        }
    );
    // An inter frame: frame_type 1.
    let inter = Vp9FrameHeader::parse(&[0x86, 0x00]).unwrap();
    assert!(!inter.key_frame);
    // Not VP9: frame_marker isn't 2.
    assert!(Vp9FrameHeader::parse(&[0x01, 0x02]).is_none());
}

/// Firefox decodes only non-flexible VP9 with the scalability structure on
/// key frames; the payloader used to send flexible mode with P=0 and no SS.
#[test]
fn test_vp9_payloader_non_flexible_mode() -> Result<()> {
    let mut pck = Vp9Payloader {
        initial_picture_id_fn: Some(Arc::new(|| -> u16 { 8692 })),
        ..Default::default()
    };
    let key = Bytes::from(vp9_key_frame_640x480());
    let out = pck.payload(100, &key)?;
    assert_eq!(out.len(), 1);
    // I=1 B=1 E=1 V=1 Z=1, P=0, F=0; picture id 8692 (M=1).
    assert_eq!(out[0][0], 0x8F);
    assert_eq!(
        &out[0][1..3],
        &[(8692u16 >> 8) as u8 | 0x80, (8692 & 0xFF) as u8]
    );
    // SS: N_S=0 Y=1 G=1, 640x480, N_G=1, T=0 U=1 R=1, P_DIFF=1.
    assert_eq!(
        &out[0][3..11],
        &[0x18, 0x02, 0x80, 0x01, 0xE0, 0x01, 0x14, 0x01]
    );
    assert_eq!(&out[0][11..], &key[..]);
    let mut depacketizer = Vp9Packet::default();
    assert_eq!(depacketizer.depacketize(&out[0])?, key);
    assert!(!depacketizer.f && !depacketizer.p && depacketizer.v);
    assert_eq!(depacketizer.width, vec![640]);
    assert_eq!(depacketizer.height, vec![480]);

    // An inter frame across two packets: P=1, no SS; B on the first, E on the
    // last; the next picture id.
    let inter = Bytes::from_static(&[0x86, 0x01, 0x02, 0x03]);
    let out = pck.payload(5, &inter)?;
    assert_eq!(out.len(), 2);
    assert_eq!(out[0][0], 0xC9); // I P B Z
    assert_eq!(out[1][0], 0xC5); // I P E Z
    assert_eq!(
        &out[0][1..3],
        &[(8693u16 >> 8) as u8 | 0x80, (8693 & 0xFF) as u8]
    );
    assert_eq!(&out[0][3..], &[0x86, 0x01]);
    assert_eq!(&out[1][3..], &[0x02, 0x03]);

    // flexible_mode keeps the old format.
    let mut flexible = Vp9Payloader {
        initial_picture_id_fn: Some(Arc::new(|| -> u16 { 8692 })),
        flexible_mode: true,
        ..Default::default()
    };
    let out = flexible.payload(100, &key)?;
    assert_eq!(out[0][0], 0x9C);
    assert_eq!(&out[0][3..], &key[..]);
    Ok(())
}
