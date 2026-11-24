//! RFC 7741 section 4.2, send side: PictureID, TL0PICIDX, TID / Y and KEYIDX from per-frame
//! layer information, and section 8 ("discard by descriptor") in a forwarder.

use super::*;

fn temporal(tid: u8, layer_sync: bool) -> Vp8FrameInfo {
    Vp8FrameInfo {
        temporal: Some(Vp8TemporalLayer { tid, layer_sync }),
        ..Default::default()
    }
}

/// The first packet of each frame of `frames`, payloaded at an MTU that fits it whole.
fn first_packets(payloader: &mut Vp8Payloader, frames: &[Vp8FrameInfo]) -> Vec<Vec<u8>> {
    frames
        .iter()
        .map(|info| {
            let payloads = payloader
                .payload_frame(1200, &Bytes::from_static(&[0x01, 0xBB]), info)
                .unwrap();
            assert_eq!(payloads.len(), 1);
            payloads[0].to_vec()
        })
        .collect()
}

/// RFC 7741 4.6.1 ("Key Frame in a Single RTP Packet") and 4.6.2 ("... No PictureID"): the
/// descriptors the RFC draws, octet for octet.
#[test]
fn the_rfc_examples_without_layers_are_reproduced() -> Result<()> {
    // 4.6.1: X = 1; S = 1; PID = 0 | I = 1 | PictureID = 17.
    let mut payloader = Vp8Payloader {
        enable_picture_id: true,
        ..Default::default()
    };
    payloader.set_initial_picture_id(17);
    let frame = Bytes::from_static(&[0x10, 0x02, 0x00, 0x9D]);
    assert_eq!(
        payloader.payload(1200, &frame)?,
        vec![Bytes::from_static(&[
            0x90, 0x80, 0x11, 0x10, 0x02, 0x00, 0x9D
        ])]
    );

    // 4.6.2: X = 0; S = 1; PID = 0.
    let mut payloader = Vp8Payloader::default();
    let frame = Bytes::from_static(&[0x11, 0x02, 0x00, 0x9D]);
    assert_eq!(
        payloader.payload(1200, &frame)?,
        vec![Bytes::from_static(&[0x10, 0x11, 0x02, 0x00, 0x9D])]
    );
    Ok(())
}

/// RFC 7741 4.2: with temporal layers the sender writes L, T, TL0PICIDX, TID and Y. Four
/// frames of a three-layer pattern (TID 0, 2, 1, 2) and the next base layer frame.
#[test]
fn temporal_layers_are_written_as_tl0picidx_tid_and_y() {
    let mut payloader = Vp8Payloader {
        enable_picture_id: true,
        ..Default::default()
    };
    payloader.set_initial_picture_id(0x11);
    let packets = first_packets(
        &mut payloader,
        &[
            temporal(0, false),
            temporal(2, true),
            temporal(1, true),
            temporal(2, false),
            temporal(0, false),
        ],
    );
    // X S | I L T | PictureID | TL0PICIDX | TID Y KEYIDX | VP8 data.
    assert_eq!(packets[0], [0x90, 0xE0, 0x11, 0x01, 0x00, 0x01, 0xBB]);
    assert_eq!(packets[1], [0x90, 0xE0, 0x12, 0x01, 0xA0, 0x01, 0xBB]);
    assert_eq!(packets[2], [0x90, 0xE0, 0x13, 0x01, 0x60, 0x01, 0xBB]);
    assert_eq!(packets[3], [0x90, 0xE0, 0x14, 0x01, 0x80, 0x01, 0xBB]);
    // TL0PICIDX is incremented when TID is 0, and only then.
    assert_eq!(packets[4], [0x90, 0xE0, 0x15, 0x02, 0x00, 0x01, 0xBB]);
}

/// The descriptor is repeated on every packet of a fragmented frame; S is on the first only.
#[test]
fn every_fragment_carries_the_layer_fields() -> Result<()> {
    let mut payloader = Vp8Payloader::default();
    let frame = Bytes::from_static(&[0x01, 0x02, 0x03, 0x04, 0x05]);
    let info = Vp8FrameInfo {
        non_reference: true,
        temporal: Some(Vp8TemporalLayer {
            tid: 1,
            layer_sync: true,
        }),
        key_idx: Some(9),
    };
    // Descriptor: X N S | L T K | TL0PICIDX | TID Y KEYIDX = 4 octets; 2 octets of data each.
    let payloads = payloader.payload_frame(6, &frame, &info)?;
    assert_eq!(
        payloads,
        vec![
            Bytes::from_static(&[0xB0, 0x70, 0x00, 0x69, 0x01, 0x02]),
            Bytes::from_static(&[0xA0, 0x70, 0x00, 0x69, 0x03, 0x04]),
            Bytes::from_static(&[0xA0, 0x70, 0x00, 0x69, 0x05]),
        ]
    );

    let mut packet = Vp8Packet::default();
    let mut data = vec![];
    for payload in &payloads {
        data.extend_from_slice(&packet.depacketize(payload)?);
        assert_eq!((packet.n, packet.l, packet.t, packet.k), (1, 1, 1, 1));
        assert_eq!(
            (packet.tl0_pic_idx, packet.tid, packet.y, packet.key_idx),
            (0, 1, 1, 9)
        );
        assert_eq!(packet.i, 0);
    }
    assert_eq!(data, frame);
    Ok(())
}

/// RFC 7741 4.2: KEYIDX alone is K without T or L; the TID bits of the octet are 0.
#[test]
fn keyidx_alone_sets_k_only() -> Result<()> {
    let mut payloader = Vp8Payloader::default();
    let info = Vp8FrameInfo {
        key_idx: Some(31),
        ..Default::default()
    };
    assert_eq!(
        payloader.payload_frame(1200, &Bytes::from_static(&[0xAA]), &info)?,
        vec![Bytes::from_static(&[0x90, 0x10, 0x1F, 0xAA])]
    );
    Ok(())
}

/// RFC 7741 4.2: the two-bit TID and the five-bit KEYIDX cannot carry more.
#[test]
fn values_that_do_not_fit_their_field_are_refused() {
    let mut payloader = Vp8Payloader::default();
    let frame = Bytes::from_static(&[0xAA]);
    assert!(
        payloader
            .payload_frame(1200, &frame, &temporal(4, false))
            .is_err()
    );
    let info = Vp8FrameInfo {
        key_idx: Some(32),
        ..Default::default()
    };
    assert!(payloader.payload_frame(1200, &frame, &info).is_err());
    // Nothing was sent, so nothing was counted.
    assert_eq!(payloader.picture_id(), 0);
}

/// RFC 7741 4.2: TL0PICIDX "MAY start at a random value, and it MUST wrap to 0 after reaching
/// the maximum number 255".
#[test]
fn tl0picidx_starts_where_it_is_told_and_wraps_after_255() {
    let mut payloader = Vp8Payloader::default();
    payloader.set_initial_tl0_pic_idx(254);
    let packets = first_packets(
        &mut payloader,
        &[
            temporal(0, false),
            temporal(1, true),
            temporal(0, false),
            temporal(1, true),
            temporal(0, false),
        ],
    );
    let tl0: Vec<u8> = packets.iter().map(|p| p[2]).collect();
    assert_eq!(tl0, [254, 254, 255, 255, 0]);
}

/// RFC 7741 4.2: the PictureID "MAY start at a random value, MUST increase by 1 for each
/// subsequent frame, and MUST wrap to 0 after reaching the maximum ID"; the sender may extend
/// a 7-bit id to 15 bits, and the receiver reads the width from M on every packet.
#[test]
fn the_picture_id_grows_from_7_to_15_bits_and_wraps_to_0() -> Result<()> {
    let mut payloader = Vp8Payloader {
        enable_picture_id: true,
        ..Default::default()
    };
    let frame = Bytes::from_static(&[0xAA]);

    payloader.set_initial_picture_id(126);
    let mut seen = vec![];
    let mut packet = Vp8Packet::default();
    for _ in 0..3 {
        let payloads = payloader.payload(1200, &frame)?;
        packet.depacketize(&payloads[0])?;
        seen.push((
            payloads[0].len(),
            packet.picture_id,
            packet.picture_id_15_bits,
        ));
    }
    // 126 and 127 in one octet, 128 in two.
    assert_eq!(seen, [(4, 126, false), (4, 127, false), (5, 128, true)]);

    payloader.set_initial_picture_id(0x7FFE);
    let mut seen = vec![];
    for _ in 0..3 {
        let payloads = payloader.payload(1200, &frame)?;
        packet.depacketize(&payloads[0])?;
        seen.push((packet.picture_id, packet.picture_id_15_bits));
    }
    assert_eq!(seen, [(0x7FFE, true), (0x7FFF, true), (0, false)]);
    Ok(())
}

/// One parsed packet of a temporal-layer stream, for the filter tests.
fn layer_packet(tid: u8, y: u8, start: bool) -> Vp8Packet {
    Vp8Packet {
        x: 1,
        s: start as u8,
        l: 1,
        t: 1,
        tid,
        y,
        ..Default::default()
    }
}

const INTER: &[u8] = &[0x01, 0x00];
const KEY: &[u8] = &[0x00, 0x00];

/// RFC 7741 8: a forwarder adapts by discarding the layers above a target TID.
#[test]
fn the_filter_forwards_the_layers_up_to_its_target() {
    let mut filter = Vp8TemporalLayerFilter::new(1);
    // A key frame, then the pattern 0 2 1 2 twice.
    assert!(filter.forward(&layer_packet(0, 0, true), KEY));
    let pattern = [
        (0u8, 0u8),
        (2, 1),
        (1, 1),
        (2, 0),
        (0, 0),
        (2, 1),
        (1, 1),
        (2, 0),
    ];
    let forwarded: Vec<bool> = pattern
        .iter()
        .map(|&(tid, y)| filter.forward(&layer_packet(tid, y, true), INTER))
        .collect();
    assert_eq!(
        forwarded,
        [true, false, true, false, true, false, true, false]
    );

    filter.set_target(0);
    assert!(!filter.forward(&layer_packet(1, 1, true), INTER));
    assert!(filter.forward(&layer_packet(0, 0, true), INTER));
}

/// Going up waits for a layer sync frame (Y=1): a frame of a higher layer without it may
/// depend on frames the receiver was never sent.
#[test]
fn the_filter_switches_up_at_a_layer_sync_frame_only() {
    let mut filter = Vp8TemporalLayerFilter::new(0);
    assert!(filter.forward(&layer_packet(0, 0, true), KEY));
    assert!(!filter.forward(&layer_packet(1, 1, true), INTER));

    filter.set_target(1);
    assert_eq!(filter.current(), 0);
    // Not a sync frame: withheld.
    assert!(!filter.forward(&layer_packet(1, 0, true), INTER));
    // A sync frame, but a frame of its layer was withheld since the base layer frame it
    // depends on, and the frames after it may depend on that one.
    assert!(!filter.forward(&layer_packet(1, 1, true), INTER));
    // After the next base layer frame the sync frame opens the layer, for all its packets.
    assert!(filter.forward(&layer_packet(0, 0, true), INTER));
    assert!(filter.forward(&layer_packet(1, 1, true), INTER));
    assert!(filter.forward(&layer_packet(1, 1, false), INTER));
    assert_eq!(filter.current(), 1);
    assert!(filter.forward(&layer_packet(1, 0, true), INTER));
}

/// A key frame restarts every layer, so the target applies from it on.
#[test]
fn the_filter_switches_up_at_a_key_frame() {
    let mut filter = Vp8TemporalLayerFilter::new(2);
    assert!(filter.forward(&layer_packet(0, 0, true), INTER));
    assert!(!filter.forward(&layer_packet(2, 0, true), INTER));
    assert!(filter.forward(&layer_packet(0, 0, true), KEY));
    assert_eq!(filter.current(), 2);
    assert!(filter.forward(&layer_packet(2, 0, true), INTER));
    assert!(filter.forward(&layer_packet(1, 0, true), INTER));
}

/// Without T there is no layer to select on: everything is forwarded.
#[test]
fn the_filter_forwards_a_stream_without_tid() {
    let mut filter = Vp8TemporalLayerFilter::new(0);
    let mut packet = Vp8Packet::default();
    packet
        .depacketize(&Bytes::from_static(&[0x10, 0x01, 0x02]))
        .unwrap();
    assert!(filter.forward(&packet, INTER));
}

/// The payloader's descriptors drive the filter: of an L1T3 stream sent with layer
/// information, a receiver at TID 0 gets exactly the base layer frames.
#[test]
fn a_payloaded_three_layer_stream_filters_down_to_its_base_layer() -> Result<()> {
    let mut payloader = Vp8Payloader {
        enable_picture_id: true,
        ..Default::default()
    };
    let mut filter = Vp8TemporalLayerFilter::new(0);
    let mut packet = Vp8Packet::default();
    let pattern = [
        temporal(0, false),
        temporal(2, true),
        temporal(1, true),
        temporal(2, false),
    ];
    let mut forwarded_tids = vec![];
    for n in 0..12usize {
        // The first frame is a key frame (frame tag bit 0 clear).
        let frame = Bytes::from(vec![if n == 0 { 0x00 } else { 0x01 }; 10]);
        for payload in payloader.payload_frame(7, &frame, &pattern[n % 4])? {
            let data = packet.depacketize(&payload)?;
            if filter.forward(&packet, &data) {
                forwarded_tids.push(packet.tid);
            }
        }
    }
    // 3 base layer frames, each in 5 packets (descriptor 5 octets, 2 of data).
    assert_eq!(forwarded_tids, vec![0; 15]);
    Ok(())
}
