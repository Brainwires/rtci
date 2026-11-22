#![no_main]
//! Stateful target: layer signalling in the VP8 and VP9 payload descriptors (RFC 7741 4.2, RFC
//! 9628 4.2) and the forwarder-side filters that read it.
//!
//! Mode 0 and 1: one depacketizer and one layer filter (VP8 temporal, VP9 spatial and
//! temporal) fed a sequence of fuzzed payloads, with target changes in between.
//! Mode 2 and 3: the payloaders given fuzzed per-frame layer information; oracle: every
//! payload stays within the MTU and the depacketized payloads are the frame.
//! Mode 4: the scalability patterns driven by fuzzed key frame requests, through the VP9
//! payloader into a filter with fuzzed targets; oracle: no frame is forwarded whose
//! reference was withheld.
//!
//! Input: a mode byte, a configuration byte, then records of a flags byte, a length byte and
//! that many bytes.

use bytes::Bytes;
use libfuzzer_sys::fuzz_target;
use rtc_rtp::codec::svc::{ScalabilityMode, ScalabilityPattern};
use rtc_rtp::codec::vp8::{
    Vp8FrameInfo, Vp8Packet, Vp8Payloader, Vp8TemporalLayer, Vp8TemporalLayerFilter,
};
use rtc_rtp::codec::vp9::{
    InitialPictureIDFn, Vp9FrameInfo, Vp9LayerFilter, Vp9Packet, Vp9Payloader,
};
use rtc_rtp::packetizer::Depacketizer;
use std::collections::BTreeSet;
use std::sync::Arc;

fn vp9_payloader(flexible: bool) -> Vp9Payloader {
    let mut payloader = Vp9Payloader::default();
    // Fixed starting values: no randomness, so an input replays identically.
    let initial_picture_id: InitialPictureIDFn = Arc::new(|| 0x7FF8u16);
    payloader.initial_picture_id_fn = Some(initial_picture_id);
    payloader.initial_tl0_pic_idx = Some(250);
    payloader.flexible_mode = flexible;
    payloader
}

fn check_round_trip(
    payloads: &[Bytes],
    depacketizer: &mut dyn Depacketizer,
    mtu: usize,
    frame: &[u8],
) {
    if payloads.is_empty() {
        return;
    }
    let mut out = vec![];
    for payload in payloads {
        assert!(payload.len() <= mtu);
        out.extend_from_slice(&depacketizer.depacketize(payload).expect("own payload"));
    }
    assert_eq!(out, frame);
}

fuzz_target!(|data: &[u8]| {
    if data.len() < 2 {
        return;
    }
    let (mode, config) = (data[0] % 5, data[1]);
    let mut data = &data[2..];

    let mut vp8_filter = Vp8TemporalLayerFilter::new(config & 0x03);
    let mut vp8_packet = Vp8Packet::default();
    let mut vp9_filter = Vp9LayerFilter::new(config & 0x07, (config >> 3) & 0x07);
    let mut vp9_packet = Vp9Packet::default();
    let mut vp8_payloader = Vp8Payloader::default();
    vp8_payloader.enable_picture_id = config & 0x80 != 0;
    let mut vp9 = vp9_payloader(config & 0x80 != 0);
    let scalability_mode = ScalabilityMode::ALL[usize::from(config) % ScalabilityMode::ALL.len()];
    let mut pattern = ScalabilityPattern::new(scalability_mode);
    let mut pattern_payloader = vp9_payloader(true);
    let mut sent: BTreeSet<u64> = BTreeSet::new();
    let mut frame_number = 0u64;

    let mut records = 0;
    while data.len() >= 2 {
        let flags = data[0];
        let len = usize::from(data[1]).min(data.len() - 2);
        let record = Bytes::copy_from_slice(&data[2..2 + len]);
        data = &data[2 + len..];
        records += 1;
        if records > 512 {
            break;
        }

        match mode {
            0 => {
                if flags & 0x80 != 0 {
                    vp8_filter.set_target(flags & 0x03);
                }
                if let Ok(vp8_data) = vp8_packet.depacketize(&record) {
                    let _ = vp8_filter.forward(&vp8_packet, &vp8_data);
                    assert!(vp8_filter.current() <= vp8_filter.target());
                }
            }
            1 => {
                if flags & 0x80 != 0 {
                    vp9_filter.set_target(flags & 0x07, (flags >> 3) & 0x07);
                }
                if vp9_packet.depacketize(&record).is_ok() {
                    let decision = vp9_filter.forward(&vp9_packet, flags & 0x40 != 0);
                    assert!(decision.forward || !decision.marker);
                    let _ = vp9_filter.needs_key_frame();
                    if let Some(structure) = vp9_packet.scalability_structure() {
                        let _ = structure.validate();
                    }
                }
            }
            2 => {
                let info = Vp8FrameInfo {
                    non_reference: flags & 0x01 != 0,
                    temporal: (flags & 0x02 != 0).then_some(Vp8TemporalLayer {
                        tid: (flags >> 2) & 0x07,
                        layer_sync: flags & 0x20 != 0,
                    }),
                    key_idx: (flags & 0x40 != 0).then_some(flags >> 1),
                };
                let mtu = usize::from(config & 0x3F) + 1;
                if let Ok(payloads) = vp8_payloader.payload_frame(mtu, &record, &info) {
                    check_round_trip(&payloads, &mut Vp8Packet::default(), mtu, &record);
                }
            }
            3 => {
                let info = Vp9FrameInfo {
                    temporal_id: flags & 0x07,
                    spatial_id: (flags >> 3) & 0x03,
                    switching_up_point: flags & 0x20 != 0,
                    inter_layer_dependency: flags & 0x40 != 0,
                    not_reference_for_upper_layers: flags & 0x80 != 0,
                    end_of_picture: record.first().is_some_and(|b| b & 0x01 != 0),
                    key_frame: None,
                    inter_picture_predicted: None,
                    reference_diffs: record
                        .iter()
                        .take(usize::from(flags & 0x03))
                        .copied()
                        .collect(),
                };
                let mtu = usize::from(config & 0x3F) + 1;
                if let Ok(payloads) = vp9.payload_layer_frame(mtu, &record, &info) {
                    check_round_trip(&payloads, &mut Vp9Packet::default(), mtu, &record);
                }
            }
            _ => {
                if flags & 0x80 != 0 {
                    vp9_filter.set_target(flags & 0x03, (flags >> 2) & 0x03);
                }
                for frame in pattern.next_picture(flags & 0x40 != 0) {
                    let payloads = pattern_payloader
                        .payload_layer_frame(
                            1200,
                            &Bytes::from_static(&[1, 2, 3]),
                            &frame.vp9_info(),
                        )
                        .expect("a pattern frame is describable");
                    vp9_packet.depacketize(&payloads[0]).expect("own payload");
                    if vp9_filter
                        .forward(&vp9_packet, frame.end_of_picture)
                        .forward
                    {
                        for fdiff in &frame.fdiffs {
                            assert!(sent.contains(&(frame_number - u64::from(*fdiff))));
                        }
                        sent.insert(frame_number);
                    }
                    frame_number += 1;
                }
            }
        }
    }
});
