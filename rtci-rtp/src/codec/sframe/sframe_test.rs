use super::*;
use crate::header::Header;
use crate::packet::Packet;

fn packet(seq: u16, payload: Bytes, pt: u8, marker: bool) -> Packet {
    Packet {
        header: Header {
            version: 2,
            sequence_number: seq,
            payload_type: pt,
            marker,
            timestamp: 90_000,
            ssrc: 0x1234,
            csrc: vec![7],
            ..Default::default()
        },
        payload,
    }
}

/// Section 4 and 5.1: S on the first fragment only, E on the last only, T from the origin
/// on every one, the reserved bits 0; a frame that fits is one fragment with both S and E.
#[test]
fn the_descriptor_marks_the_first_and_last_fragment_and_the_origin() {
    let frame = Bytes::from((0u8..=250).collect::<Vec<_>>());
    let mut raw = SFramePayloader::new(SFramePayloadOrigin::Raw);
    let fragments = raw.payload(101, &frame).expect("payloads");
    assert_eq!(fragments.len(), 3, "100 bytes each after the descriptor");
    let descriptors: Vec<u8> = fragments.iter().map(|f| f[0]).collect();
    assert_eq!(descriptors, [SFRAME_START, 0, SFRAME_END]);
    let joined: Vec<u8> = fragments.iter().flat_map(|f| f[1..].to_vec()).collect();
    assert_eq!(joined, frame.as_ref());

    let mut packetized = SFramePayloader::new(SFramePayloadOrigin::Packetized);
    let one = packetized.payload(1200, &frame).expect("payloads");
    assert_eq!(one.len(), 1);
    assert_eq!(one[0][0], SFRAME_START | SFRAME_END | SFRAME_PACKETIZED);
    assert_eq!(one[0][0] & 0x1f, 0, "reserved bits are 0");
    assert!(SFramePayloader::default().payload(1, &frame).is_err());
}

/// Section 5.2 in order: the fragments from S to E are concatenated without descriptors,
/// the reserved bits are ignored, and a frame whose fragments disagree on T is discarded.
#[test]
fn the_depacketizer_joins_s_to_e_and_discards_mixed_t() {
    let mut depacketizer = SFrameDepacketizer::default();
    let reserved = 0x1f;
    assert!(
        depacketizer
            .depacketize(&Bytes::from(vec![SFRAME_START | reserved, 1, 2]))
            .expect("ok")
            .is_empty()
    );
    let frame = depacketizer
        .depacketize(&Bytes::from_static(&[SFRAME_END, 3]))
        .expect("ok");
    assert_eq!(frame.as_ref(), [1, 2, 3]);
    assert_eq!(depacketizer.origin(), SFramePayloadOrigin::Raw);

    depacketizer
        .depacketize(&Bytes::from_static(&[SFRAME_START | SFRAME_PACKETIZED, 1]))
        .expect("ok");
    let mixed = depacketizer
        .depacketize(&Bytes::from_static(&[SFRAME_END, 2]))
        .expect("ok");
    assert!(mixed.is_empty(), "T differs: discarded");
    assert!(depacketizer.is_partition_head(&Bytes::from_static(&[SFRAME_START])));
    assert!(depacketizer.is_partition_tail(false, &Bytes::from_static(&[SFRAME_END])));
}

/// Section 5.2 out of order: the smallest consecutive S..E run completes a frame whatever
/// the arrival order, with the metadata of steps 10 (marker of the last packet, the payload
/// origin); inconsistent payload types discard the frame (step 7).
#[test]
fn the_reassembler_completes_frames_in_any_order() {
    let mut payloader = SFramePayloader::new(SFramePayloadOrigin::Packetized);
    let frame = Bytes::from(vec![9u8; 250]);
    let fragments = payloader.payload(101, &frame).expect("payloads");
    let mut reassembler = SFrameReassembler::default();
    let seqs = [65534u16, 65535, 0];
    assert!(
        reassembler
            .push(&packet(seqs[2], fragments[2].clone(), 96, true))
            .is_none()
    );
    assert!(
        reassembler
            .push(&packet(seqs[0], fragments[0].clone(), 96, false))
            .is_none()
    );
    let done = reassembler
        .push(&packet(seqs[1], fragments[1].clone(), 96, false))
        .expect("the frame completes across the wrap");
    assert_eq!(done.payload, frame);
    assert_eq!(done.origin, SFramePayloadOrigin::Packetized);
    assert!(done.marker);
    assert_eq!(done.sequence_numbers, (65534, 0));
    assert_eq!(
        (done.ssrc, done.payload_type, done.csrc.clone()),
        (0x1234, 96, vec![7])
    );
    assert_eq!(reassembler.buffered(), 0);

    let fragments = payloader.payload(101, &frame).expect("payloads");
    reassembler.push(&packet(10, fragments[0].clone(), 96, false));
    reassembler.push(&packet(11, fragments[1].clone(), 97, false));
    assert!(
        reassembler
            .push(&packet(12, fragments[2].clone(), 96, true))
            .is_none()
    );
    assert_eq!(reassembler.discarded(), 1, "payload types differ");
}

/// Section 9.7: the buffer is bounded, the oldest fragments evicted first; fragments older
/// than a completed frame stay, and a late packet still completes their frame.
#[test]
fn the_reassembler_bounds_what_it_holds() {
    let mut reassembler = SFrameReassembler::new(4);
    for seq in 0..10u16 {
        reassembler.push(&packet(
            seq,
            Bytes::from_static(&[SFRAME_START, 1]),
            96,
            false,
        ));
    }
    assert_eq!(reassembler.buffered(), 4);
    assert_eq!(reassembler.discarded(), 6);

    let mut reassembler = SFrameReassembler::default();
    reassembler.push(&packet(
        30,
        Bytes::from_static(&[SFRAME_START, 1]),
        96,
        false,
    ));
    let newer = reassembler
        .push(&packet(
            32,
            Bytes::from_static(&[SFRAME_START | SFRAME_END, 5]),
            96,
            true,
        ))
        .expect("a one-packet frame");
    assert_eq!(newer.payload.as_ref(), [5]);
    let late = reassembler
        .push(&packet(31, Bytes::from_static(&[SFRAME_END, 2]), 96, true))
        .expect("the older frame completes late");
    assert_eq!(late.payload.as_ref(), [1, 2]);
    assert_eq!(reassembler.buffered(), 0);
}
