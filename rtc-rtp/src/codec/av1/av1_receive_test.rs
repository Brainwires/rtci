//! AV1 RTP payload format, sections 4.4, 4.5 and 5: malformed input and the receive side.

use bytes::Bytes;

use crate::codec::av1::{Av1Depacketizer, Av1Payloader};
use crate::packetizer::{Depacketizer, Payloader};

/// AV1 4.10.5: a leb128 value ends with a byte whose top bit is clear. An `obu_size` with no
/// such byte used to be read as "size 0, no bytes consumed".
#[test]
fn an_unterminated_obu_size_is_refused() {
    // A frame OBU with `obu_has_size_field` and a size that never ends.
    assert!(
        Av1Payloader::default()
            .payload(1200, &Bytes::from_static(&[0x32, 0x80]))
            .is_err()
    );
    assert!(
        Av1Payloader::default()
            .payload(1200, &Bytes::from_static(&[0x32, 0xFF, 0xFF, 0xFF]))
            .is_err()
    );
}

/// AV1 4.10.5: a leb128 value fits 32 bits. An element length of 2^32 used to wrap to 0.
#[test]
fn an_element_length_of_two_to_the_32_is_refused() {
    let mut depacketizer = Av1Depacketizer::new();
    assert!(
        depacketizer
            .depacketize(&Bytes::from_static(&[
                0x00, 0x80, 0x80, 0x80, 0x80, 0x10, 0x02, 0x30, 0x01
            ]))
            .is_err()
    );
}

/// AV1 4.10.5: a leb128 value is at most 8 bytes long.
#[test]
fn a_leb128_longer_than_eight_bytes_is_refused() {
    let mut depacketizer = Av1Depacketizer::new();
    // W=0; the length 2 written with eight continuation bytes (nine bytes), then a frame OBU.
    // (Read with the first byte shifted out, it was an empty element followed by a good one.)
    let mut payload = vec![0x00, 0x82, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x00];
    payload.extend_from_slice(&[0x02, 0x30, 0x01]);
    assert!(depacketizer.depacketize(&Bytes::from(payload)).is_err());

    // The same length in eight bytes is the longest legal form.
    let mut depacketizer = Av1Depacketizer::new();
    let mut payload = vec![0x00, 0x82, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x00];
    payload.extend_from_slice(&[0x30, 0x01]);
    assert_eq!(
        depacketizer.depacketize(&Bytes::from(payload)).unwrap(),
        Bytes::from_static(&[0x32, 0x01, 0x01])
    );
}

/// AV1 RTP 4.4: W is 0 or the number of OBU elements in the packet.
#[test]
fn w_must_match_the_number_of_elements() {
    let mut depacketizer = Av1Depacketizer::new();
    // W=2, but the first element (length 2) is the whole packet.
    assert!(
        depacketizer
            .depacketize(&Bytes::from_static(&[0x20, 0x02, 0x30, 0x01]))
            .is_err()
    );
    // W=3 with two elements.
    assert!(
        depacketizer
            .depacketize(&Bytes::from_static(&[
                0x30, 0x02, 0x30, 0x01, 0x02, 0x30, 0x02
            ]))
            .is_err()
    );
}

/// A temporal unit starts with a sequence header, a frame header, a frame or metadata. A
/// packet whose first OBU is a tile group belongs to a frame that started earlier, even though
/// Z=0 (the OBU itself is whole).
#[test]
fn a_packet_starting_with_a_tile_group_does_not_start_a_temporal_unit() {
    let depacketizer = Av1Depacketizer::new();
    // W=1: frame header OBU.
    assert!(depacketizer.is_partition_head(&Bytes::from_static(&[0x10, 0x18, 0x10])));
    // W=1: tile group OBU.
    assert!(!depacketizer.is_partition_head(&Bytes::from_static(&[0x10, 0x20, 0xAA])));
    // W=0 and W=2: a length field comes before the OBU header.
    assert!(!depacketizer.is_partition_head(&Bytes::from_static(&[0x00, 0x02, 0x20, 0xAA])));
    assert!(depacketizer.is_partition_head(&Bytes::from_static(&[0x00, 0x02, 0x30, 0xAA])));
    assert!(
        !depacketizer.is_partition_head(&Bytes::from_static(&[0x20, 0x02, 0x20, 0xAA, 0x20, 0xBB]))
    );
    // Z=1 never starts one.
    assert!(!depacketizer.is_partition_head(&Bytes::from_static(&[0x90, 0x30, 0xAA])));
}

/// AV1 RTP 4.4: with W = 0 every OBU element, the last included, has a length field.
#[test]
fn w_zero_reads_a_length_before_every_element() {
    let mut depacketizer = Av1Depacketizer::new();
    // A frame OBU of one payload byte, then a frame header OBU of two.
    let out = depacketizer
        .depacketize(&Bytes::from_static(&[
            0x00, 0x02, 0x30, 0x01, 0x03, 0x18, 0x0A, 0x0B,
        ]))
        .unwrap();
    assert_eq!(&out[..], &[0x32, 0x01, 0x01, 0x1A, 0x02, 0x0A, 0x0B]);
}

/// AV1 RTP 4.4: with W = 2 or 3 the last element has no length field; its length is what is
/// left of the packet.
#[test]
fn w_two_and_three_take_the_last_element_from_the_packet_size() {
    let mut depacketizer = Av1Depacketizer::new();
    let out = depacketizer
        .depacketize(&Bytes::from_static(&[
            0x20, 0x02, 0x30, 0x01, 0x18, 0x0A, 0x0B,
        ]))
        .unwrap();
    assert_eq!(&out[..], &[0x32, 0x01, 0x01, 0x1A, 0x02, 0x0A, 0x0B]);

    let out = depacketizer
        .depacketize(&Bytes::from_static(&[
            0x30, 0x02, 0x30, 0x01, 0x02, 0x30, 0x02, 0x18, 0x0A, 0x0B,
        ]))
        .unwrap();
    assert_eq!(
        &out[..],
        &[0x32, 0x01, 0x01, 0x32, 0x01, 0x02, 0x1A, 0x02, 0x0A, 0x0B]
    );
}

/// AV1 RTP 4.5: an OBU can be fragmented whatever W is. Here the second of two elements
/// (W = 2) continues into a packet with W = 0, and ends in one with W = 2 whose second
/// element is another OBU.
#[test]
fn fragments_reassemble_under_every_w() {
    let mut depacketizer = Av1Depacketizer::new();
    // Z=0 Y=1 W=2: a whole frame header OBU, then the start of a frame OBU.
    let out = depacketizer
        .depacketize(&Bytes::from_static(&[0x60, 0x02, 0x18, 0x0A, 0x30, 0x01]))
        .unwrap();
    assert_eq!(&out[..], &[0x1A, 0x01, 0x0A]);
    // Z=1 Y=1 W=0: the middle of it, with a length field.
    let out = depacketizer
        .depacketize(&Bytes::from_static(&[0xC0, 0x02, 0x02, 0x03]))
        .unwrap();
    assert!(out.is_empty());
    // Z=1 Y=0 W=2: its end, then a tile group OBU.
    let out = depacketizer
        .depacketize(&Bytes::from_static(&[0xA0, 0x01, 0x04, 0x20, 0x0C]))
        .unwrap();
    assert_eq!(
        &out[..],
        &[0x32, 0x04, 0x01, 0x02, 0x03, 0x04, 0x22, 0x01, 0x0C]
    );
}

/// AV1 RTP 5 and 10: "Tile list OBUs ... MUST be ignored by receivers", like the temporal
/// delimiter.
#[test]
fn tile_list_and_temporal_delimiter_obus_are_ignored() {
    let mut depacketizer = Av1Depacketizer::new();
    // W=3: a temporal delimiter (type 2), a tile list (type 8) with two bytes, a frame.
    let out = depacketizer
        .depacketize(&Bytes::from_static(&[
            0x30, 0x01, 0x10, 0x03, 0x40, 0xAA, 0xBB, 0x30, 0x01,
        ]))
        .unwrap();
    assert_eq!(&out[..], &[0x32, 0x01, 0x01]);
    // A tile list alone leaves nothing.
    let out = depacketizer
        .depacketize(&Bytes::from_static(&[0x10, 0x40, 0xAA]))
        .unwrap();
    assert!(out.is_empty());
}

/// A malformed packet ends the reassembly in progress: the fragment that follows it is not
/// appended to what came before it.
#[test]
fn a_malformed_packet_drops_the_obu_being_reassembled() {
    let mut depacketizer = Av1Depacketizer::new();
    // Z=0 Y=1 W=1: the start of a frame OBU.
    assert!(
        depacketizer
            .depacketize(&Bytes::from_static(&[0x50, 0x30, 0x01]))
            .unwrap()
            .is_empty()
    );
    // Z=1 Y=1 W=0 with a length field that never ends.
    assert!(
        depacketizer
            .depacketize(&Bytes::from_static(&[0xC0, 0x80, 0x80]))
            .is_err()
    );
    // Z=1 Y=0 W=1: the end of an OBU whose start is gone.
    assert!(
        depacketizer
            .depacketize(&Bytes::from_static(&[0x90, 0x02]))
            .unwrap()
            .is_empty()
    );
}

/// What the payloader sends, the depacketizer gives back: the temporal unit in low overhead
/// format without its temporal delimiter, at every MTU.
#[test]
fn a_temporal_unit_round_trips_at_every_mtu() {
    use crate::codec::av1::av1_test::{Av1Obu, build_av1_frame};
    use crate::codec::av1::obu::{
        OBU_TYPE_FRAME, OBU_TYPE_FRAME_HEADER, OBU_TYPE_METADATA, OBU_TYPE_SEQUENCE_HEADER,
        OBU_TYPE_TEMPORAL_DELIMITER, OBU_TYPE_TILE_GROUP,
    };
    let body = vec![
        Av1Obu::new(OBU_TYPE_SEQUENCE_HEADER).with_payload(vec![0x00, 0x01, 0x02]),
        Av1Obu::new(OBU_TYPE_METADATA).with_payload((0..7).collect()),
        Av1Obu::new(OBU_TYPE_FRAME_HEADER).with_payload(vec![0x10, 0x20]),
        Av1Obu::new(OBU_TYPE_TILE_GROUP).with_payload((0..200).map(|i| i as u8).collect()),
        Av1Obu::new(OBU_TYPE_TILE_GROUP).with_payload(vec![]),
        Av1Obu::new(OBU_TYPE_FRAME).with_payload((0..90).collect()),
        Av1Obu::new(OBU_TYPE_FRAME).with_payload(vec![0x77]),
    ];
    let expected = build_av1_frame(&body);
    let mut unit = build_av1_frame(&vec![Av1Obu::new(OBU_TYPE_TEMPORAL_DELIMITER)]).to_vec();
    unit.extend_from_slice(&expected);
    let unit = Bytes::from(unit);

    for mtu in 3..=300 {
        let payloads = Av1Payloader::default().payload(mtu, &unit).unwrap();
        let mut depacketizer = Av1Depacketizer::new();
        let mut out = vec![];
        for (i, payload) in payloads.iter().enumerate() {
            assert!(payload.len() <= mtu, "mtu {mtu}");
            // Only the first packet of the unit can start it.
            if i == 0 {
                assert!(depacketizer.is_partition_head(payload), "mtu {mtu}");
            }
            out.extend_from_slice(&depacketizer.depacketize(payload).unwrap());
        }
        assert_eq!(out, expected, "mtu {mtu}");
    }
}
