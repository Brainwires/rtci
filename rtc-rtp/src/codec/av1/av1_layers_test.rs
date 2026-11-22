//! AV1 RTP payload format, sections 4.2, 4.4 and 5, send side: layers, sequence headers, the
//! N bit and the marker.

use bytes::Bytes;
use std::time::Instant;

use super::av1_test::{Av1Obu, build_av1_frame};
use crate::codec::av1::obu::{
    OBU_TYPE_FRAME, OBU_TYPE_FRAME_HEADER, OBU_TYPE_METADATA, OBU_TYPE_PADDING,
    OBU_TYPE_SEQUENCE_HEADER, OBU_TYPE_TEMPORAL_DELIMITER, OBU_TYPE_TILE_GROUP,
};
use crate::codec::av1::{Av1Depacketizer, Av1Payloader};
use crate::packetizer::{Depacketizer, Packetizer, Payloader, new_packetizer};
use crate::sequence::new_fixed_sequencer;
use shared::error::Result;

/// An OBU extension header: temporal_id, spatial_id.
fn layer(temporal_id: u8, spatial_id: u8) -> u8 {
    temporal_id << 5 | spatial_id << 3
}

/// The (OBU type, extension header) of every OBU in a payload, read back through the
/// depacketizer (which writes each OBU with a size field).
fn obus_of(payload: &Bytes) -> Vec<(u8, Option<u8>)> {
    let out = Av1Depacketizer::new().depacketize(payload).unwrap();
    let mut obus = vec![];
    let mut i = 0;
    while i < out.len() {
        let header = out[i];
        let has_extension = header & 0x04 != 0;
        let extension = has_extension.then(|| out[i + 1]);
        let size_at = i + 1 + has_extension as usize;
        // The test OBUs are shorter than 128 bytes: one size byte.
        i = size_at + 1 + out[size_at] as usize;
        obus.push(((header >> 3) & 0x0F, extension));
    }
    obus
}

/// AV1 RTP 5.1, the specification's own example: of
/// `TD SH MD MD(0,0) FH(0,0) TG(0,0) MD(0,1) FH(0,1) TG(0,1)` the temporal delimiter is
/// dropped and the grouping is `[ SH MD MD(0,0) FH(0,0) TG(0,0) ] [ MD(0,1) FH(0,1) TG(0,1) ]`;
/// one packet with both spatial layers "would not be allowed".
#[test]
fn the_specifications_example_is_packetized_by_spatial_layer() -> Result<()> {
    let unit = build_av1_frame(&vec![
        Av1Obu::new(OBU_TYPE_TEMPORAL_DELIMITER),
        Av1Obu::new(OBU_TYPE_SEQUENCE_HEADER).with_payload(vec![1, 2]),
        Av1Obu::new(OBU_TYPE_METADATA).with_payload(vec![3]),
        Av1Obu::new(OBU_TYPE_METADATA)
            .with_extension(layer(0, 0))
            .with_payload(vec![4]),
        Av1Obu::new(OBU_TYPE_FRAME_HEADER)
            .with_extension(layer(0, 0))
            .with_payload(vec![5]),
        Av1Obu::new(OBU_TYPE_TILE_GROUP)
            .with_extension(layer(0, 0))
            .with_payload(vec![6, 7]),
        Av1Obu::new(OBU_TYPE_METADATA)
            .with_extension(layer(0, 1))
            .with_payload(vec![8]),
        Av1Obu::new(OBU_TYPE_FRAME_HEADER)
            .with_extension(layer(0, 1))
            .with_payload(vec![9]),
        Av1Obu::new(OBU_TYPE_TILE_GROUP)
            .with_extension(layer(0, 1))
            .with_payload(vec![10, 11]),
    ]);
    let payloads = Av1Payloader::default().payload(1200, &unit)?;
    assert_eq!(payloads.len(), 2);
    assert_eq!(
        obus_of(&payloads[0]),
        [
            (OBU_TYPE_SEQUENCE_HEADER, None),
            (OBU_TYPE_METADATA, None),
            (OBU_TYPE_METADATA, Some(layer(0, 0))),
            (OBU_TYPE_FRAME_HEADER, Some(layer(0, 0))),
            (OBU_TYPE_TILE_GROUP, Some(layer(0, 0))),
        ]
    );
    assert_eq!(
        obus_of(&payloads[1]),
        [
            (OBU_TYPE_METADATA, Some(layer(0, 1))),
            (OBU_TYPE_FRAME_HEADER, Some(layer(0, 1))),
            (OBU_TYPE_TILE_GROUP, Some(layer(0, 1))),
        ]
    );
    // Five elements: W = 0. Three: W = 3.
    assert_eq!(payloads[0][0] & 0x30, 0x00);
    assert_eq!(payloads[1][0] & 0x30, 0x30);

    // The same unit by frame, as the Dependency Descriptor counts them.
    let frames = Av1Payloader::default().payload_frames(1200, &unit)?;
    assert_eq!(frames.len(), 2);
    assert_eq!((frames[0].spatial_id, frames[0].temporal_id), (0, 0));
    assert_eq!((frames[1].spatial_id, frames[1].temporal_id), (1, 0));
    assert_eq!(frames[0].payloads, payloads[..1]);
    assert_eq!(frames[1].payloads, payloads[1..]);
    Ok(())
}

/// AV1 RTP 5: "the values of the temporal_id and spatial_id MUST be the same in all such OBUs
/// in the RTP packet", at every MTU, also when the OBUs are fragmented.
#[test]
fn no_packet_mixes_layers_at_any_mtu() -> Result<()> {
    let unit = build_av1_frame(&vec![
        Av1Obu::new(OBU_TYPE_FRAME)
            .with_extension(layer(1, 0))
            .with_payload((0..40).collect()),
        Av1Obu::new(OBU_TYPE_FRAME)
            .with_extension(layer(1, 1))
            .with_payload((40..50).collect()),
        Av1Obu::new(OBU_TYPE_FRAME)
            .with_extension(layer(1, 2))
            .with_payload((50..120).collect()),
    ]);
    for mtu in 3..=140 {
        let frames = Av1Payloader::default().payload_frames(mtu, &unit)?;
        let spatial: Vec<u8> = frames.iter().map(|f| f.spatial_id).collect();
        assert_eq!(spatial, [0, 1, 2], "mtu {mtu}");
        assert!(frames.iter().all(|f| f.temporal_id == 1));
        // Each frame's packets reassemble to exactly its own OBU.
        for (i, frame) in frames.iter().enumerate() {
            let mut depacketizer = Av1Depacketizer::new();
            let mut out = vec![];
            for payload in &frame.payloads {
                assert!(payload.len() <= mtu);
                out.extend_from_slice(&depacketizer.depacketize(payload)?);
            }
            assert_eq!(out[1], layer(1, i as u8), "mtu {mtu}");
            let expected: Vec<u8> = match i {
                0 => (0..40).collect(),
                1 => (40..50).collect(),
                _ => (50..120).collect(),
            };
            assert_eq!(&out[3..], &expected[..], "mtu {mtu}");
        }
    }
    Ok(())
}

/// AV1 RTP 5: a sequence header "SHOULD be the first OBU in the packet", and in an "S" mode
/// one "SHOULD be aggregated with each spatial layer".
#[test]
fn a_sequence_header_starts_its_packet_and_goes_with_its_layer() -> Result<()> {
    let unit = build_av1_frame(&vec![
        Av1Obu::new(OBU_TYPE_SEQUENCE_HEADER).with_payload(vec![0x00]),
        Av1Obu::new(OBU_TYPE_FRAME)
            .with_extension(layer(0, 0))
            .with_payload(vec![0x10, 1]),
        Av1Obu::new(OBU_TYPE_SEQUENCE_HEADER).with_payload(vec![0x00]),
        Av1Obu::new(OBU_TYPE_FRAME)
            .with_extension(layer(0, 1))
            .with_payload(vec![0x10, 2]),
    ]);
    let frames = Av1Payloader::default().payload_frames(1200, &unit)?;
    assert_eq!(frames.len(), 2);
    for (i, frame) in frames.iter().enumerate() {
        assert_eq!(frame.payloads.len(), 1);
        assert_eq!(
            obus_of(&frame.payloads[0]),
            [
                (OBU_TYPE_SEQUENCE_HEADER, None),
                (OBU_TYPE_FRAME, Some(layer(0, i as u8)))
            ]
        );
    }
    // N marks the first packet of the coded video sequence, and only it.
    assert_ne!(frames[0].payloads[0][0] & 0x08, 0);
    assert_eq!(frames[1].payloads[0][0] & 0x08, 0);
    Ok(())
}

/// AV1 RTP 5: OBUs without an extension header "SHOULD be in the beginning of a packet": one
/// that follows layered OBUs starts the next packet.
#[test]
fn an_obu_of_no_layer_after_layered_ones_starts_a_packet() -> Result<()> {
    let unit = build_av1_frame(&vec![
        Av1Obu::new(OBU_TYPE_FRAME)
            .with_extension(layer(0, 0))
            .with_payload(vec![1]),
        Av1Obu::new(OBU_TYPE_METADATA).with_payload(vec![2]),
        Av1Obu::new(OBU_TYPE_FRAME)
            .with_extension(layer(0, 0))
            .with_payload(vec![3]),
    ]);
    let payloads = Av1Payloader::default().payload(1200, &unit)?;
    assert_eq!(payloads.len(), 2);
    assert_eq!(obus_of(&payloads[0]), [(OBU_TYPE_FRAME, Some(layer(0, 0)))]);
    assert_eq!(
        obus_of(&payloads[1]),
        [
            (OBU_TYPE_METADATA, None),
            (OBU_TYPE_FRAME, Some(layer(0, 0)))
        ]
    );
    // One spatial layer: one frame.
    assert_eq!(
        Av1Payloader::default().payload_frames(1200, &unit)?.len(),
        1
    );
    Ok(())
}

/// AV1 RTP 5: "Each RTP packet MUST NOT contain OBUs that belong to different temporal
/// units." One call is one unit; a second temporal delimiter is refused. Padding OBUs are
/// not sent.
#[test]
fn two_temporal_units_in_one_call_are_refused() -> Result<()> {
    let two = build_av1_frame(&vec![
        Av1Obu::new(OBU_TYPE_TEMPORAL_DELIMITER),
        Av1Obu::new(OBU_TYPE_FRAME).with_payload(vec![1]),
        Av1Obu::new(OBU_TYPE_TEMPORAL_DELIMITER),
        Av1Obu::new(OBU_TYPE_FRAME).with_payload(vec![2]),
    ]);
    assert!(Av1Payloader::default().payload(1200, &two).is_err());

    let one = build_av1_frame(&vec![
        Av1Obu::new(OBU_TYPE_TEMPORAL_DELIMITER),
        Av1Obu::new(OBU_TYPE_PADDING).with_payload(vec![0; 9]),
        Av1Obu::new(OBU_TYPE_FRAME).with_payload(vec![1]),
    ]);
    assert_eq!(
        Av1Payloader::default().payload(1200, &one)?,
        vec![Bytes::from_static(&[0x10, 0x30, 1])]
    );
    Ok(())
}

/// An OBU that exactly fills the packet goes out whole; it used to be cut in two.
#[test]
fn an_obu_that_exactly_fills_the_packet_is_not_fragmented() -> Result<()> {
    let unit = build_av1_frame(&vec![
        Av1Obu::new(OBU_TYPE_FRAME).with_payload(vec![1, 2, 3, 4, 5, 6]),
    ]);
    assert_eq!(
        Av1Payloader::default().payload(8, &unit)?,
        vec![Bytes::from_static(&[0x10, 0x30, 1, 2, 3, 4, 5, 6])]
    );
    // One octet less of room: two packets, Y then Z.
    let payloads = Av1Payloader::default().payload(7, &unit)?;
    assert_eq!(payloads.len(), 2);
    assert_eq!((payloads[0][0] & 0xC0, payloads[1][0] & 0xC0), (0x40, 0x80));
    Ok(())
}

/// AV1 RTP 4.4 with AV1 7.5: with a reduced still picture header every frame is a shown key
/// frame, so a sequence header followed by a frame starts a coded video sequence (N = 1).
#[test]
fn a_reduced_still_picture_sets_n() -> Result<()> {
    // seq_profile 000, still_picture 1, reduced_still_picture_header 1.
    let unit = build_av1_frame(&vec![
        Av1Obu::new(OBU_TYPE_SEQUENCE_HEADER).with_payload(vec![0x18, 0x00]),
        // A frame header whose first bits would read as show_existing_frame in a normal
        // stream; a reduced still picture header has no such field.
        Av1Obu::new(OBU_TYPE_FRAME).with_payload(vec![0xFF, 0x00]),
    ]);
    let payloads = Av1Payloader::default().payload(1200, &unit)?;
    assert_ne!(payloads[0][0] & 0x08, 0);
    Ok(())
}

/// AV1 RTP 4.2: "The RTP header Marker bit MUST be set equal to 0 if the packet is not the
/// last packet of the temporal unit, it SHOULD be set equal to 1 otherwise." All packets of
/// the unit have one timestamp.
#[test]
fn the_marker_is_on_the_last_packet_of_the_temporal_unit_only() -> Result<()> {
    let unit = build_av1_frame(&vec![
        Av1Obu::new(OBU_TYPE_FRAME)
            .with_extension(layer(0, 0))
            .with_payload((0..100).collect()),
        Av1Obu::new(OBU_TYPE_FRAME)
            .with_extension(layer(0, 1))
            .with_payload((0..100).collect()),
    ]);
    let now = Instant::now();
    let mut packetizer = new_packetizer(
        now,
        12 + 40,
        45,
        0x1234,
        Box::new(Av1Payloader::default()),
        Box::new(new_fixed_sequencer(1)),
        90000,
    );
    let packets = packetizer.packetize(now, &unit, 3000)?;
    assert!(packets.len() > 4);
    let markers: Vec<bool> = packets.iter().map(|p| p.header.marker).collect();
    let mut expected = vec![false; packets.len()];
    *expected.last_mut().unwrap() = true;
    assert_eq!(markers, expected);
    assert!(
        packets
            .iter()
            .all(|p| p.header.timestamp == packets[0].header.timestamp)
    );
    Ok(())
}

/// AV1 RTP 5 and 6.1: in an "S" mode "a sequence header OBU SHOULD be aggregated with each
/// spatial layer". With `sequence_header_per_spatial_layer` the payloader repeats the unit's
/// sequence header for the layers that come without one, so each layer's packets stand alone.
#[test]
fn the_sequence_header_can_be_repeated_for_every_spatial_layer() -> Result<()> {
    let unit = build_av1_frame(&vec![
        Av1Obu::new(OBU_TYPE_TEMPORAL_DELIMITER),
        Av1Obu::new(OBU_TYPE_SEQUENCE_HEADER).with_payload(vec![0x00, 0x42]),
        Av1Obu::new(OBU_TYPE_FRAME)
            .with_extension(layer(0, 0))
            .with_payload(vec![0x10, 1]),
        Av1Obu::new(OBU_TYPE_METADATA).with_payload(vec![9]),
        Av1Obu::new(OBU_TYPE_FRAME)
            .with_extension(layer(0, 1))
            .with_payload(vec![0x10, 2]),
        Av1Obu::new(OBU_TYPE_FRAME)
            .with_extension(layer(0, 2))
            .with_payload(vec![0x10, 3]),
    ]);
    let mut payloader = Av1Payloader {
        sequence_header_per_spatial_layer: true,
    };
    let frames = payloader.payload_frames(1200, &unit)?;
    assert_eq!(frames.len(), 3);
    assert_eq!(
        obus_of(&frames[0].payloads[0]),
        [
            (OBU_TYPE_SEQUENCE_HEADER, None),
            (OBU_TYPE_FRAME, Some(layer(0, 0)))
        ]
    );
    // The sequence header leads the layer's packet, before the metadata that came with it.
    assert_eq!(
        obus_of(&frames[1].payloads[0]),
        [
            (OBU_TYPE_SEQUENCE_HEADER, None),
            (OBU_TYPE_METADATA, None),
            (OBU_TYPE_FRAME, Some(layer(0, 1)))
        ]
    );
    assert_eq!(
        obus_of(&frames[2].payloads[0]),
        [
            (OBU_TYPE_SEQUENCE_HEADER, None),
            (OBU_TYPE_FRAME, Some(layer(0, 2)))
        ]
    );
    // The copy is the unit's sequence header, byte for byte.
    for frame in &frames {
        let out = Av1Depacketizer::new().depacketize(&frame.payloads[0])?;
        assert_eq!(&out[..4], &[0x0A, 0x02, 0x00, 0x42]);
    }
    // Still one coded video sequence: N on its first packet only.
    let n: Vec<bool> = frames
        .iter()
        .map(|f| f.payloads[0][0] & 0x08 != 0)
        .collect();
    assert_eq!(n, [true, false, false]);

    // Off by default: the layers after the first have none; a unit without a sequence
    // header gets none either.
    let frames = Av1Payloader::default().payload_frames(1200, &unit)?;
    assert_eq!(
        obus_of(&frames[2].payloads[0]),
        [(OBU_TYPE_FRAME, Some(layer(0, 2)))]
    );
    Ok(())
}
