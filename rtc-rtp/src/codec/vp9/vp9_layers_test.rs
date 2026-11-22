//! RFC 9628 sections 4.1, 4.2 and 4.2.1 with layers: layer indices, TL0PICIDX, reference
//! indices, the scalability structure, and layer selection in a forwarder.

use super::vp9_descriptor_test::vp9_inter_frame;
use super::vp9_test::vp9_key_frame_640x480;
use super::*;

fn payloader(flexible_mode: bool) -> Vp9Payloader {
    Vp9Payloader {
        initial_picture_id_fn: Some(Arc::new(|| 0x1234)),
        initial_tl0_pic_idx: Some(7),
        flexible_mode,
        ..Default::default()
    }
}

fn layer(tid: u8, sid: u8, d: bool, z: bool, end_of_picture: bool) -> Vp9FrameInfo {
    Vp9FrameInfo {
        temporal_id: tid,
        spatial_id: sid,
        switching_up_point: true,
        inter_layer_dependency: d,
        not_reference_for_upper_layers: z,
        end_of_picture,
        ..Default::default()
    }
}

/// Two spatial layers (320x180, 640x360) and two temporal layers: T0 predicts from the T0 two
/// pictures back, T1 from the picture before.
fn l2t2_structure() -> Vp9ScalabilityStructure {
    Vp9ScalabilityStructure {
        spatial_layers: 2,
        resolutions: vec![(320, 180), (640, 360)],
        picture_group: vec![
            Vp9PictureGroupEntry {
                temporal_id: 0,
                switching_up_point: true,
                reference_diffs: vec![2],
            },
            Vp9PictureGroupEntry {
                temporal_id: 1,
                switching_up_point: true,
                reference_diffs: vec![1],
            },
        ],
    }
}

/// An intra-only frame's uncompressed header (profile 0): not shown, `intra_only` 1, the sync
/// code, then `refresh_frame_flags`.
fn vp9_intra_only_frame(refresh: u8) -> Bytes {
    // frame_marker 10, profile 00, show_existing_frame 0, frame_type 1, show_frame 0,
    // error_resilient_mode 0; intra_only 1; reset_frame_context 00.
    let mut bits: Vec<u8> = vec![1, 0, 0, 0, 0, 1, 0, 0, 1, 0, 0];
    for byte in [0x49u8, 0x83, 0x42, refresh] {
        for i in (0..8).rev() {
            bits.push((byte >> i) & 1);
        }
    }
    let mut out = vec![0u8; bits.len().div_ceil(8)];
    for (i, bit) in bits.iter().enumerate() {
        out[i / 8] |= bit << (7 - i % 8);
    }
    out.extend_from_slice(&[0x11; 4]);
    Bytes::from(out)
}

/// RFC 9628 4.2 / 4.2.1, non-flexible mode with two spatial and two temporal layers: the
/// descriptors of a key picture and the two pictures after it, octet for octet.
#[test]
fn non_flexible_mode_writes_layer_indices_tl0picidx_and_the_structure() -> Result<()> {
    let mut pck = payloader(false);
    pck.set_scalability_structure(Some(l2t2_structure()))?;
    let key = Bytes::from(vp9_key_frame_640x480());
    // A frame of the upper layer in a key picture predicts from the key frame only (same
    // picture): no inter-picture prediction.
    let upper = vp9_inter_frame(0x02, 0);

    // Key picture, spatial layer 0: I L B E V; PID 0x1234; TID 0 U 1 SID 0 D 0; TL0PICIDX 7.
    let out = pck.payload_layer_frame(1200, &key, &layer(0, 0, false, false, false))?;
    assert_eq!(out.len(), 1);
    let ss = [
        0x38, // N_S 1, Y 1, G 1
        0x01, 0x40, 0x00, 0xB4, // 320 x 180
        0x02, 0x80, 0x01, 0x68, // 640 x 360
        0x02, // N_G
        0x14, 0x02, // TID 0, U 1, R 1; P_DIFF 2
        0x34, 0x01, // TID 1, U 1, R 1; P_DIFF 1
    ];
    assert_eq!(&out[0][..5], &[0xAE, 0x92, 0x34, 0x10, 0x07]);
    assert_eq!(&out[0][5..5 + ss.len()], &ss);
    assert_eq!(&out[0][5 + ss.len()..], &key[..]);

    // Key picture, spatial layer 1: I L B E Z, P 0; the same PID; SID 1 D 1; the same
    // TL0PICIDX; no SS.
    let out = pck.payload_layer_frame(1200, &upper, &layer(0, 1, true, true, true))?;
    assert_eq!(&out[0][..5], &[0xAD, 0x92, 0x34, 0x13, 0x07]);
    assert_eq!(&out[0][5..], &upper[..]);

    // The next picture, temporal layer 1: P 1, the next PID, TL0PICIDX unchanged.
    let inter = vp9_inter_frame(0x00, 0);
    let out = pck.payload_layer_frame(1200, &inter, &layer(1, 0, false, false, false))?;
    assert_eq!(&out[0][..5], &[0xEC, 0x92, 0x35, 0x30, 0x07]);
    let out = pck.payload_layer_frame(1200, &inter, &layer(1, 1, true, true, true))?;
    assert_eq!(&out[0][..5], &[0xED, 0x92, 0x35, 0x33, 0x07]);

    // Temporal layer 0 again: TL0PICIDX is incremented, once for the picture.
    let out = pck.payload_layer_frame(1200, &inter, &layer(0, 0, false, false, false))?;
    assert_eq!(&out[0][..5], &[0xEC, 0x92, 0x36, 0x10, 0x08]);
    let out = pck.payload_layer_frame(1200, &inter, &layer(0, 1, true, true, true))?;
    assert_eq!(&out[0][..5], &[0xED, 0x92, 0x36, 0x13, 0x08]);

    // RFC 9628 4.2: "the value of the TID MUST match the corresponding TID value of the
    // mapped picture in the PG". The fourth picture maps to the second entry: TID 1.
    assert!(
        pck.payload_layer_frame(1200, &inter, &layer(0, 0, false, false, true))
            .is_err()
    );
    assert!(
        pck.payload_layer_frame(1200, &inter, &layer(1, 0, false, false, true))
            .is_ok()
    );
    Ok(())
}

/// What a receiver reads back from the same stream: every field of the descriptor, and the
/// frame bytes untouched whatever the MTU.
#[test]
fn a_layered_non_flexible_stream_reads_back() -> Result<()> {
    for mtu in [24, 40, 1200] {
        let mut pck = payloader(false);
        pck.set_scalability_structure(Some(l2t2_structure()))?;
        let key = Bytes::from(vp9_key_frame_640x480());
        let payloads = pck.payload_layer_frame(mtu, &key, &layer(0, 0, false, false, false))?;
        let mut packet = Vp9Packet::default();
        let mut data = vec![];
        for (i, payload) in payloads.iter().enumerate() {
            assert!(payload.len() <= mtu);
            data.extend_from_slice(&packet.depacketize(payload)?);
            assert!(packet.i && packet.l && !packet.p && !packet.f && !packet.z);
            assert_eq!(packet.b, i == 0);
            assert_eq!(packet.e, i == payloads.len() - 1);
            assert_eq!(packet.v, i == 0);
            assert_eq!(
                (packet.picture_id, packet.picture_id_15_bits),
                (0x1234, true)
            );
            assert_eq!(
                (packet.tid, packet.u, packet.sid, packet.d),
                (0, true, 0, false)
            );
            assert_eq!(packet.tl0picidx, 7);
            assert_eq!(
                packet.scalability_structure(),
                (i == 0).then(l2t2_structure)
            );
        }
        assert_eq!(data, key, "mtu {mtu}");
    }
    Ok(())
}

/// RFC 9628 4.2, flexible mode: one layer octet (no TL0PICIDX), and the reference indices of
/// each predicted frame, read from the reference slots the frame's header names. A three
/// temporal layer pattern: T0 (key), T2, T1, T2, T0.
#[test]
fn flexible_mode_writes_one_layer_octet_and_the_reference_indices() -> Result<()> {
    let mut pck = payloader(true);
    let key = Bytes::from(vp9_key_frame_640x480());
    let mut first_octets = vec![];
    let mut push = |pck: &mut Vp9Payloader, frame: &Bytes, tid: u8| -> Result<()> {
        let out = pck.payload_layer_frame(1200, frame, &layer(tid, 0, false, true, true))?;
        assert_eq!(out.len(), 1);
        first_octets.push(out[0][..out[0].len() - frame.len()].to_vec());
        Ok(())
    };
    push(&mut pck, &key, 0)?;
    push(&mut pck, &vp9_inter_frame(0x00, 0), 2)?; // from the key picture, stored nowhere
    push(&mut pck, &vp9_inter_frame(0x02, 0), 1)?; // from the key picture, into slot 1
    push(&mut pck, &vp9_inter_frame(0x00, 1), 2)?; // from the T1 picture
    push(&mut pck, &vp9_inter_frame(0x01, 0), 0)?; // from the key picture, into slot 0
    push(&mut pck, &vp9_inter_frame(0x00, 0), 2)?; // from the T0 picture before it

    // I L F B E Z (P 0); PID; TID 0 U 1 SID 0.
    assert_eq!(first_octets[0], [0xBD, 0x92, 0x34, 0x10]);
    // I P L F B E Z; PID; layer octet; P_DIFF << 1 | N.
    assert_eq!(first_octets[1], [0xFD, 0x92, 0x35, 0x50, 0x02]);
    assert_eq!(first_octets[2], [0xFD, 0x92, 0x36, 0x30, 0x04]);
    assert_eq!(first_octets[3], [0xFD, 0x92, 0x37, 0x50, 0x02]);
    assert_eq!(first_octets[4], [0xFD, 0x92, 0x38, 0x10, 0x08]);
    assert_eq!(first_octets[5], [0xFD, 0x92, 0x39, 0x50, 0x02]);
    Ok(())
}

/// RFC 9628 4.2: up to three reference indices chained by N; the encoder's own values are
/// written as given.
#[test]
fn the_encoders_reference_indices_are_chained_with_n() -> Result<()> {
    let mut pck = payloader(true);
    pck.payload_layer_frame(
        1200,
        &Bytes::from(vp9_key_frame_640x480()),
        &layer(0, 0, false, true, true),
    )?;
    let info = Vp9FrameInfo {
        inter_picture_predicted: Some(true),
        reference_diffs: vec![1, 2, 127],
        ..layer(0, 0, false, true, true)
    };
    let out = pck.payload_layer_frame(1200, &Bytes::from_static(&[0xAA]), &info)?;
    assert_eq!(
        out[0],
        Bytes::from_static(&[0xFD, 0x92, 0x35, 0x10, 0x03, 0x05, 0xFE, 0xAA])
    );
    let mut packet = Vp9Packet::default();
    packet.depacketize(&out[0])?;
    assert_eq!(packet.pdiff, vec![1, 2, 127]);
    assert_eq!(packet.referenced_picture_id(2), 0x1233);
    Ok(())
}

/// RFC 9628 4.2: what the layer indices cannot say is refused, not sent wrong.
#[test]
fn layer_information_the_rfc_forbids_is_refused() -> Result<()> {
    let key = Bytes::from(vp9_key_frame_640x480());
    let inter = vp9_inter_frame(0x00, 0);

    // "For the base-layer frame (with SID equal to zero), the D bit MUST be set to zero."
    let mut pck = payloader(true);
    assert!(
        pck.payload_layer_frame(1200, &key, &layer(0, 0, true, false, true))
            .is_err()
    );
    // TID and SID are three bits.
    assert!(
        pck.payload_layer_frame(1200, &key, &layer(8, 0, false, false, true))
            .is_err()
    );
    assert!(
        pck.payload_layer_frame(1200, &key, &layer(0, 8, false, false, true))
            .is_err()
    );
    // "When P is set to zero, the TID field (if present) MUST also be set to 0."
    assert!(
        pck.payload_layer_frame(1200, &key, &layer(1, 0, false, false, true))
            .is_err()
    );
    // "A P_DIFF value of zero is invalid"; at most three.
    for diffs in [vec![0], vec![128], vec![1, 2, 3, 4]] {
        let info = Vp9FrameInfo {
            reference_diffs: diffs,
            ..layer(0, 0, false, false, true)
        };
        assert!(pck.payload_layer_frame(1200, &inter, &info).is_err());
    }
    // "Frames' spatial layers MUST appear in increasing order" within a picture.
    pck.payload_layer_frame(1200, &key, &layer(0, 1, false, false, false))?;
    assert!(
        pck.payload_layer_frame(1200, &inter, &layer(0, 1, false, false, true))
            .is_err()
    );
    assert!(
        pck.payload_layer_frame(1200, &inter, &layer(0, 0, false, false, true))
            .is_err()
    );
    assert!(
        pck.payload_layer_frame(1200, &inter, &layer(0, 2, false, false, true))
            .is_ok()
    );
    Ok(())
}

/// An MTU that leaves no room for the frame is an error for a described frame, not an empty
/// result that looks like a frame without packets.
#[test]
fn an_mtu_too_small_for_the_descriptor_is_an_error() -> Result<()> {
    let mut pck = payloader(false);
    pck.set_scalability_structure(Some(l2t2_structure()))?;
    let key = Bytes::from(vp9_key_frame_640x480());
    // The descriptor is 5 octets and the SS 14.
    assert!(
        pck.payload_layer_frame(19, &key, &layer(0, 0, false, false, true))
            .is_err()
    );
    let out = pck.payload_layer_frame(20, &key, &layer(0, 0, false, false, true))?;
    assert_eq!(out[0].len(), 20);
    // The refused call consumed nothing: this is the first picture.
    assert_eq!(&out[0][1..3], &[0x92, 0x34]);
    // Without layer information the old answer stands: no packets.
    assert!(payloader(false).payload(5, &key)?.is_empty());
    Ok(())
}

/// RFC 9628 4.2: "All frames of the same picture MUST have the same PID value", it is
/// incremented by one per picture, and it wraps after 0x7FFF.
#[test]
fn the_picture_id_is_per_picture_and_wraps() -> Result<()> {
    let mut pck = Vp9Payloader {
        initial_picture_id_fn: Some(Arc::new(|| 0x7FFE)),
        flexible_mode: true,
        ..Default::default()
    };
    let key = Bytes::from(vp9_key_frame_640x480());
    let inter = vp9_inter_frame(0x00, 0);
    let mut packet = Vp9Packet::default();
    let mut ids = vec![];
    for picture in 0..3 {
        for sid in 0..3u8 {
            let frame = if picture == 0 && sid == 0 {
                &key
            } else {
                &inter
            };
            let out =
                pck.payload_layer_frame(1200, frame, &layer(0, sid, sid > 0, sid == 2, sid == 2))?;
            packet.depacketize(&out[0])?;
            ids.push(packet.picture_id);
        }
    }
    assert_eq!(
        ids,
        [0x7FFE, 0x7FFE, 0x7FFE, 0x7FFF, 0x7FFF, 0x7FFF, 0, 0, 0]
    );
    Ok(())
}

/// RFC 9628 4.2: TL0PICIDX "MUST be incremented by one when the TID is equal to zero" and
/// "MUST restart at zero after reaching the maximum number 255".
#[test]
fn tl0picidx_wraps_after_255() -> Result<()> {
    let mut pck = Vp9Payloader {
        initial_picture_id_fn: Some(Arc::new(|| 0)),
        initial_tl0_pic_idx: Some(254),
        ..Default::default()
    };
    pck.set_scalability_structure(Some(Vp9ScalabilityStructure {
        spatial_layers: 1,
        resolutions: vec![],
        picture_group: vec![],
    }))?;
    let key = Bytes::from(vp9_key_frame_640x480());
    let inter = vp9_inter_frame(0x01, 0);
    let mut packet = Vp9Packet::default();
    let mut seen = vec![];
    for n in 0..3 {
        let frame = if n == 0 { &key } else { &inter };
        let out = pck.payload_layer_frame(1200, frame, &layer(0, 0, false, true, true))?;
        packet.depacketize(&out[0])?;
        seen.push(packet.tl0picidx);
    }
    assert_eq!(seen, [254, 255, 0]);
    Ok(())
}

/// RFC 9628 4.2: P=0 for a frame without inter-picture prediction. An intra-only frame is one
/// (it used to be sent with P=1), and so is the upper spatial layer of a key picture.
#[test]
fn an_intra_only_frame_is_not_inter_picture_predicted() -> Result<()> {
    for flexible in [false, true] {
        let mut pck = payloader(flexible);
        pck.payload(1200, &Bytes::from(vp9_key_frame_640x480()))?;
        let out = pck.payload(1200, &vp9_inter_frame(0x01, 0))?;
        assert_ne!(out[0][0] & 0x40, 0, "an inter frame has P=1");
        let out = pck.payload(1200, &vp9_intra_only_frame(0x02))?;
        assert_eq!(out[0][0] & 0x40, 0, "an intra-only frame has P=0");
        assert_eq!(out[0][0] & 0x02, 0, "but it is not a key frame: no SS");
    }

    // The slot the intra-only frame refreshed is a reference like any other.
    let mut pck = payloader(true);
    pck.payload(1200, &Bytes::from(vp9_key_frame_640x480()))?;
    pck.payload(1200, &vp9_inter_frame(0x01, 0))?;
    pck.payload(1200, &vp9_intra_only_frame(0x02))?;
    pck.payload(1200, &vp9_inter_frame(0x00, 0))?;
    let out = pck.payload(1200, &vp9_inter_frame(0x00, 1))?;
    let mut packet = Vp9Packet::default();
    packet.depacketize(&out[0])?;
    assert_eq!(
        packet.pdiff,
        vec![2],
        "slot 1 holds the intra-only frame, two pictures back"
    );
    Ok(())
}

/// A `show_existing_frame` frame shows a frame decoded earlier: it depends on that picture.
#[test]
fn a_show_existing_frame_refers_to_the_picture_it_shows() -> Result<()> {
    let mut pck = payloader(true);
    pck.payload(1200, &Bytes::from(vp9_key_frame_640x480()))?;
    pck.payload(1200, &vp9_inter_frame(0x04, 0))?; // into slot 2
    pck.payload(1200, &vp9_inter_frame(0x00, 0))?;
    // frame_marker 10, profile 00, show_existing_frame 1, frame_to_show_map_idx 010.
    let out = pck.payload(1200, &Bytes::from_static(&[0x8A]))?;
    let mut packet = Vp9Packet::default();
    packet.depacketize(&out[0])?;
    assert!(packet.p);
    assert_eq!(packet.pdiff, vec![2]);
    Ok(())
}

/// RFC 9628 4.2.1: WIDTH and HEIGHT are 16 bits. A key frame too large for them is announced
/// without resolutions (Y=0); it used to switch the stream to flexible mode.
#[test]
fn a_key_frame_wider_than_16_bits_keeps_the_mode() -> Result<()> {
    let mut key = vp9_key_frame_640x480();
    // width_minus_1 and height_minus_1 follow the 4 bits after the sync code: 0xFFFF both.
    key[4] |= 0x0F;
    key[5] = 0xFF;
    key[6] = 0xFF;
    key[7] = 0xFF;
    key[8] |= 0xF0;
    let mut pck = payloader(false);
    let out = pck.payload(1200, &Bytes::from(key))?;
    // I B E V Z, F 0; PID; SS: N_S 0, Y 0, G 1; N_G 1; TID 0 U 1 R 1; P_DIFF 1.
    assert_eq!(&out[0][..7], &[0x8F, 0x92, 0x34, 0x08, 0x01, 0x14, 0x01]);
    Ok(())
}

/// An end-to-end encrypted frame cannot be parsed: the caller says what it is, and the
/// payloader still sends the mode asked for and the structure set.
#[test]
fn an_opaque_frame_is_described_by_the_caller() -> Result<()> {
    let mut pck = payloader(false);
    pck.set_scalability_structure(Some(Vp9ScalabilityStructure {
        spatial_layers: 1,
        resolutions: vec![(640, 480)],
        picture_group: vec![],
    }))?;
    let opaque = Bytes::from_static(&[0x01, 0x02, 0x03]);
    let key = Vp9FrameInfo {
        key_frame: Some(true),
        inter_picture_predicted: Some(false),
        ..layer(0, 0, false, true, true)
    };
    let out = pck.payload_layer_frame(1200, &opaque, &key)?;
    // I L B E V Z, P 0, F 0; PID; layer; TL0PICIDX; SS: N_S 0, Y 1; 640 x 480.
    assert_eq!(
        &out[0][..10],
        &[0xAF, 0x92, 0x34, 0x10, 0x07, 0x10, 0x02, 0x80, 0x01, 0xE0]
    );
    let delta = Vp9FrameInfo {
        key_frame: Some(false),
        inter_picture_predicted: Some(true),
        ..layer(0, 0, false, true, true)
    };
    let out = pck.payload_layer_frame(1200, &opaque, &delta)?;
    assert_eq!(&out[0][..5], &[0xED, 0x92, 0x35, 0x10, 0x08]);
    Ok(())
}

/// RFC 9628 4.2.1: the SS in both directions, for every number of spatial layers, with and
/// without resolutions and picture group; what the fields cannot carry is refused.
#[test]
fn the_scalability_structure_round_trips() -> Result<()> {
    for spatial_layers in 1..=8u8 {
        for with_resolutions in [false, true] {
            for group in [0usize, 1, 4, 255] {
                let structure = Vp9ScalabilityStructure {
                    spatial_layers,
                    resolutions: if with_resolutions {
                        (0..spatial_layers as u16)
                            .map(|i| (160 << i, 90 + i))
                            .collect()
                    } else {
                        vec![]
                    },
                    picture_group: (0..group)
                        .map(|i| Vp9PictureGroupEntry {
                            temporal_id: (i % 4) as u8 * (i != 0) as u8,
                            switching_up_point: i % 2 == 0,
                            reference_diffs: (1..=(i % 4) as u8).collect(),
                        })
                        .collect(),
                };
                let mut payload = BytesMut::new();
                payload.put_u8(0x0A); // B V
                structure.marshal_to(&mut payload)?;
                assert_eq!(payload.len(), 1 + structure.marshal_size());
                payload.put_u8(0xAA);
                let mut packet = Vp9Packet::default();
                assert_eq!(
                    packet.depacketize(&payload.freeze())?,
                    Bytes::from_static(&[0xAA])
                );
                assert_eq!(packet.scalability_structure(), Some(structure));
            }
        }
    }

    let good = l2t2_structure();
    let mut out = BytesMut::new();
    for bad in [
        Vp9ScalabilityStructure {
            spatial_layers: 0,
            ..good.clone()
        },
        Vp9ScalabilityStructure {
            spatial_layers: 9,
            resolutions: vec![],
            ..good.clone()
        },
        Vp9ScalabilityStructure {
            resolutions: vec![(1, 1)],
            ..good.clone()
        },
        // "The first picture specified in the PG MUST have a TID set to zero."
        Vp9ScalabilityStructure {
            picture_group: vec![Vp9PictureGroupEntry {
                temporal_id: 1,
                ..Default::default()
            }],
            ..good.clone()
        },
        Vp9ScalabilityStructure {
            picture_group: vec![Vp9PictureGroupEntry {
                reference_diffs: vec![1, 2, 3, 4],
                ..Default::default()
            }],
            ..good.clone()
        },
    ] {
        assert!(bad.marshal_to(&mut out).is_err(), "{bad:?}");
    }
    assert!(out.is_empty());
    Ok(())
}

/// RFC 9628 4.2: a reference index is "modulo the size of the PID field, i.e., either 7 or 15
/// bits".
#[test]
fn a_reference_index_wraps_at_the_picture_ids_width() -> Result<()> {
    let mut packet = Vp9Packet::default();
    // I P F; 7-bit PID 3; P_DIFF 5.
    packet.depacketize(&Bytes::from_static(&[0xD0, 0x03, 0x0A, 0xAA]))?;
    assert_eq!(packet.referenced_picture_id(packet.pdiff[0]), 126);
    // I P F; 15-bit PID 3; P_DIFF 5.
    packet.depacketize(&Bytes::from_static(&[0xD0, 0x80, 0x03, 0x0A, 0xAA]))?;
    assert_eq!(packet.referenced_picture_id(packet.pdiff[0]), 0x7FFE);
    Ok(())
}

/// RFC 9628 4.3: a picture begins at a frame start (B=1). A frame with D=1 depends on a frame
/// of the same picture that comes before it, so a run of packets cannot begin there.
#[test]
fn a_frame_that_depends_on_a_lower_layer_does_not_start_a_picture() {
    let packet = Vp9Packet::default();
    // I L B; PID (7 and 15 bits); layer octet with and without D.
    assert!(packet.is_partition_head(&Bytes::from_static(&[0xA8, 0x05, 0x12, 0x00, 0xAA])));
    assert!(!packet.is_partition_head(&Bytes::from_static(&[0xA8, 0x05, 0x13, 0x00, 0xAA])));
    assert!(!packet.is_partition_head(&Bytes::from_static(&[0xA8, 0x85, 0x05, 0x13, 0x00, 0xAA])));
    // L B without a picture ID.
    assert!(!packet.is_partition_head(&Bytes::from_static(&[0x28, 0x13, 0x00, 0xAA])));
    // B without layer indices; and no B.
    assert!(packet.is_partition_head(&Bytes::from_static(&[0x88, 0x05, 0xAA])));
    assert!(!packet.is_partition_head(&Bytes::from_static(&[0xA0, 0x05, 0x12, 0x00, 0xAA])));
}

/// A descriptor of a single-packet frame, for the filter tests.
#[allow(clippy::too_many_arguments)]
fn descriptor(pid: u16, sid: u8, tid: u8, p: bool, d: bool, z: bool, u: bool) -> Vp9Packet {
    Vp9Packet {
        i: true,
        l: true,
        b: true,
        e: true,
        picture_id: pid,
        picture_id_15_bits: true,
        p,
        d,
        z,
        u,
        sid,
        tid,
        ..Default::default()
    }
}

/// The pictures of a full SVC stream with `spatial` layers and the temporal pattern
/// `0 2 1 2`: every frame depends on the layer below (D=1), a key picture first.
fn full_svc(spatial: u8, pictures: u16) -> Vec<(Vp9Packet, bool)> {
    let mut out = vec![];
    for n in 0..pictures {
        let tid = [0, 2, 1, 2][n as usize % 4];
        for sid in 0..spatial {
            let key = n == 0;
            let d = descriptor(100 + n, sid, tid, !key, sid > 0, sid == spatial - 1, true);
            out.push((d, sid == spatial - 1));
        }
    }
    out
}

/// The same with inter-layer prediction at the key picture only (K-SVC): after it a layer's
/// frames are no reference for the layers above (Z=1) and depend on none below (D=0).
fn k_svc(spatial: u8, first_picture: u16, pictures: u16) -> Vec<(Vp9Packet, bool)> {
    let mut out = vec![];
    for n in 0..pictures {
        for sid in 0..spatial {
            let key = n == 0;
            let top = sid == spatial - 1;
            let d = descriptor(
                first_picture + n,
                sid,
                0,
                !key,
                key && sid > 0,
                !key || top,
                true,
            );
            out.push((d, top));
        }
    }
    out
}

fn run(filter: &mut Vp9LayerFilter, stream: &[(Vp9Packet, bool)]) -> Vec<(u16, u8, u8, bool)> {
    stream
        .iter()
        .filter_map(|(d, marker)| {
            let decision = filter.forward(d, *marker);
            decision
                .forward
                .then_some((d.picture_id, d.sid, d.tid, decision.marker))
        })
        .collect()
}

/// RFC 9628 4.1 and 9: a receiver of the lowest spatial layer and the two lower temporal
/// layers gets those frames only, each with the marker (it ends the picture for that
/// receiver).
#[test]
fn the_filter_selects_a_spatial_and_a_temporal_layer() {
    let mut filter = Vp9LayerFilter::new(0, 1);
    let forwarded = run(&mut filter, &full_svc(3, 8));
    assert_eq!(
        forwarded,
        [
            (100, 0, 0, true),
            (102, 0, 1, true),
            (104, 0, 0, true),
            (106, 0, 1, true)
        ]
    );

    // The top layer of full SVC needs every layer below it; the marker stays where it was.
    let mut filter = Vp9LayerFilter::new(2, 2);
    let forwarded = run(&mut filter, &full_svc(3, 2));
    assert_eq!(
        forwarded,
        [
            (100, 0, 0, false),
            (100, 1, 0, false),
            (100, 2, 0, true),
            (101, 0, 2, false),
            (101, 1, 2, false),
            (101, 2, 2, true)
        ]
    );
}

/// With Z=1 on the lower layers (K-SVC), the receiver of the top layer gets the whole key
/// picture and then its own layer only.
#[test]
fn the_filter_drops_lower_layers_that_are_not_references() {
    let mut filter = Vp9LayerFilter::new(2, 0);
    let forwarded = run(&mut filter, &k_svc(3, 100, 3));
    assert_eq!(
        forwarded,
        [
            (100, 0, 0, false),
            (100, 1, 0, false),
            (100, 2, 0, true),
            (101, 2, 0, true),
            (102, 2, 0, true)
        ]
    );
}

/// Going up a spatial layer waits for a frame of that layer that predicts from no earlier
/// picture (P=0); going down in full SVC is immediate, because the lower layers were being
/// forwarded all along.
#[test]
fn the_filter_switches_spatial_layer_where_the_stream_allows() {
    let mut filter = Vp9LayerFilter::new(0, 2);
    let stream = full_svc(2, 12);
    run(&mut filter, &stream[..4]);
    filter.set_target(1, 2);
    // Pictures 102 and 103: the upper layer predicts from its own earlier frames.
    let forwarded = run(&mut filter, &stream[4..8]);
    assert_eq!(forwarded, [(102, 0, 1, true), (103, 0, 2, true)]);
    assert_eq!(filter.current(), (0, 2));

    // A picture whose frames predict from no earlier picture: the upper layer is joined, and
    // the marker stays on the picture's last packet.
    let sync = [
        (descriptor(104, 0, 0, false, false, false, true), false),
        (descriptor(104, 1, 0, false, true, true, true), true),
    ];
    let forwarded = run(&mut filter, &sync);
    assert_eq!(forwarded, [(104, 0, 0, false), (104, 1, 0, true)]);
    assert_eq!(filter.current(), (1, 2));

    // Down again: at the next picture.
    filter.set_target(0, 2);
    let forwarded = run(&mut filter, &stream[10..12]);
    assert_eq!(forwarded, [(105, 0, 2, true)]);
    assert_eq!(filter.current(), (0, 2));
    assert!(!filter.needs_key_frame());
}

/// In K-SVC the lower layers are not forwarded to a receiver of the top layer, so going down
/// needs a key picture; the filter says so and keeps the old layer until then.
#[test]
fn the_filter_waits_for_a_key_picture_to_go_down_in_k_svc() {
    let mut filter = Vp9LayerFilter::new(1, 0);
    run(&mut filter, &k_svc(2, 100, 3));
    assert!(!filter.needs_key_frame());

    filter.set_target(0, 0);
    let forwarded = run(&mut filter, &k_svc(2, 100, 5)[6..]);
    assert_eq!(forwarded, [(103, 1, 0, true), (104, 1, 0, true)]);
    assert!(filter.needs_key_frame());

    let forwarded = run(&mut filter, &k_svc(2, 200, 2));
    assert_eq!(forwarded, [(200, 0, 0, true), (201, 0, 0, true)]);
    assert!(!filter.needs_key_frame());
}

/// Going up a temporal layer waits for a switching up point (U=1) on a forwarded picture.
#[test]
fn the_filter_switches_temporal_layer_at_a_switching_up_point() {
    let mut filter = Vp9LayerFilter::new(0, 0);
    // A key picture without U, then T1 pictures that chain on each other.
    assert!(
        filter
            .forward(&descriptor(1, 0, 0, false, false, true, false), true)
            .forward
    );
    assert!(
        !filter
            .forward(&descriptor(2, 0, 1, true, false, true, false), true)
            .forward
    );
    filter.set_target(0, 1);
    assert!(
        !filter
            .forward(&descriptor(3, 0, 1, true, false, true, false), true)
            .forward
    );
    assert!(
        filter
            .forward(&descriptor(4, 0, 0, true, false, true, false), true)
            .forward
    );
    assert!(
        !filter
            .forward(&descriptor(5, 0, 1, true, false, true, false), true)
            .forward
    );
    // A T0 picture that is a switching up point: the T1 pictures after it are forwarded.
    assert!(
        filter
            .forward(&descriptor(6, 0, 0, true, false, true, true), true)
            .forward
    );
    assert!(
        filter
            .forward(&descriptor(7, 0, 1, true, false, true, false), true)
            .forward
    );
    assert_eq!(filter.current(), (0, 1));
    // Down is immediate.
    filter.set_target(0, 0);
    assert!(
        !filter
            .forward(&descriptor(8, 0, 1, true, false, true, false), true)
            .forward
    );
}

/// Nothing is forwarded until a frame the receiver can start from; a stream without layer
/// indices is not filtered at all.
#[test]
fn the_filter_starts_at_a_frame_without_dependencies() {
    let mut filter = Vp9LayerFilter::new(1, 2);
    assert!(filter.needs_key_frame());
    let stream = full_svc(2, 6);
    assert!(run(&mut filter, &stream[2..]).is_empty());
    assert!(filter.needs_key_frame());
    assert_eq!(run(&mut filter, &stream[..2]).len(), 2);
    assert!(!filter.needs_key_frame());

    let mut filter = Vp9LayerFilter::new(0, 0);
    let mut plain = Vp9Packet::default();
    plain
        .depacketize(&Bytes::from_static(&[0xC8, 0x05, 0xAA]))
        .unwrap();
    assert_eq!(
        filter.forward(&plain, false),
        Vp9Forward {
            forward: true,
            marker: false
        }
    );
}

/// The payloader's own descriptors drive the filter, packet by packet: of a two-layer full
/// SVC stream a receiver of spatial layer 0 gets that layer's packets, the marker on the last
/// packet of each of its frames.
#[test]
fn a_payloaded_stream_filters_down_to_its_base_layer() -> Result<()> {
    let mut pck = payloader(true);
    let mut filter = Vp9LayerFilter::new(0, 7);
    let mut packet = Vp9Packet::default();
    let key = Bytes::from(vp9_key_frame_640x480());
    let mut forwarded = vec![];
    for picture in 0..3 {
        for sid in 0..2u8 {
            let frame = if picture == 0 && sid == 0 {
                key.clone()
            } else {
                vp9_inter_frame(0x03, sid)
            };
            let info = layer(0, sid, sid == 1, sid == 1, sid == 1);
            let payloads = pck.payload_layer_frame(12, &frame, &info)?;
            let last = payloads.len() - 1;
            for (i, payload) in payloads.iter().enumerate() {
                packet.depacketize(payload)?;
                // The sender's marker: the last packet of the picture's last frame.
                let decision = filter.forward(&packet, sid == 1 && i == last);
                if decision.forward {
                    forwarded.push((packet.sid, packet.e, decision.marker));
                }
            }
        }
    }
    assert!(
        forwarded
            .iter()
            .all(|(sid, e, marker)| *sid == 0 && e == marker)
    );
    assert_eq!(forwarded.iter().filter(|(_, e, _)| *e).count(), 3);
    Ok(())
}
