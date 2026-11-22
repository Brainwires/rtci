//! The dependency structure of every scalability mode (W3C webrtc-svc sections 5 and 9, AV1
//! RTP specification A.3 to A.5 and A.10.2), and its signalling end to end: VP8 and VP9
//! payload descriptors and the Dependency Descriptor, each through its payloader and into its
//! forwarder-side selector.

use std::collections::{BTreeSet, HashMap};

use bytes::Bytes;

use super::*;
use crate::codec::dependency_descriptor::dependency_descriptor_test::{
    l1t3_structure, l3t3_key_shift_templates, l3t3_structure,
};
use crate::codec::dependency_descriptor::{
    DecodeTargetSelector, DependencyDescriptorReader, DependencyDescriptorWriter,
};
use crate::codec::vp8::{Vp8Packet, Vp8Payloader, Vp8TemporalLayerFilter};
use crate::codec::vp9::{Vp9LayerFilter, Vp9Packet, Vp9Payloader};
use crate::packetizer::Depacketizer;

/// `pictures` pictures of a mode, a key picture first, as (frame number, frame).
fn stream(mode: ScalabilityMode, pictures: usize) -> Vec<(u64, LayerFrame)> {
    let mut pattern = ScalabilityPattern::new(mode);
    let mut out = vec![];
    for _ in 0..pictures {
        for frame in pattern.next_picture(false) {
            out.push((out.len() as u64, frame));
        }
    }
    out
}

/// A.10.2.1, A.10.2.2 and A.10.2.3: the structures the AV1 RTP specification gives for L1T3,
/// L3T3 and L3T3 K-SVC with temporal shift are the ones the pattern produces, template for
/// template, with the same chains and decode target order.
#[test]
fn the_specifications_example_structures_are_reproduced() {
    assert_eq!(
        ScalabilityPattern::dependency_structure(ScalabilityMode::L1T3, None),
        l1t3_structure()
    );
    assert_eq!(
        ScalabilityPattern::dependency_structure(ScalabilityMode::L3T3, None),
        l3t3_structure()
    );
    assert_eq!(
        ScalabilityPattern::dependency_structure(ScalabilityMode::L3T3_KEY_SHIFT, None),
        FrameDependencyStructure {
            templates: l3t3_key_shift_templates(),
            ..l3t3_structure()
        }
    );
    // The 1.5:1 modes have the structure of their 2:1 counterparts; only resolutions differ.
    assert_eq!(
        ScalabilityPattern::dependency_structure(ScalabilityMode::L3T3h, None),
        l3t3_structure()
    );
    let with_resolutions =
        ScalabilityPattern::dependency_structure(ScalabilityMode::L3T3h, Some((1280, 720)));
    assert_eq!(
        with_resolutions
            .resolutions
            .iter()
            .map(|r| (r.width, r.height))
            .collect::<Vec<_>>(),
        [(568, 320), (853, 480), (1280, 720)]
    );
}

/// Section 5 and 9 of webrtc-svc: every mode has its number of spatial and temporal layers,
/// with the temporal patterns of the diagrams, and the inter-layer dependency its name says.
#[test]
fn every_mode_has_its_layers_and_its_inter_layer_dependency() {
    for &mode in ScalabilityMode::ALL {
        let frames = stream(mode, 33);
        let spatial = mode.spatial_layers();
        let temporal = mode.temporal_layers();
        // Each picture has one frame per spatial layer, in order, the last marked.
        for picture in frames.chunks(spatial as usize) {
            for (s, (_, frame)) in picture.iter().enumerate() {
                assert_eq!(frame.spatial_id, s as u8, "{mode}");
                assert_eq!(frame.end_of_picture, s as u8 == spatial - 1, "{mode}");
            }
        }
        // Every temporal layer of every spatial layer occurs, and no other.
        let layers: BTreeSet<(u8, u8)> = frames
            .iter()
            .map(|(_, f)| (f.spatial_id, f.temporal_id))
            .collect();
        let expected: BTreeSet<(u8, u8)> = (0..spatial)
            .flat_map(|s| (0..temporal).map(move |t| (s, t)))
            .collect();
        assert_eq!(layers, expected, "{mode}");

        // The share of each temporal layer: 1; 1/2 and 1/2; 1/4, 1/4 and 1/2.
        for s in 0..spatial {
            let tids: Vec<u8> = frames
                .iter()
                .filter(|(_, f)| f.spatial_id == s)
                .map(|(_, f)| f.temporal_id)
                .skip(5)
                .take(24)
                .collect();
            let count = |t: u8| tids.iter().filter(|x| **x == t).count();
            match temporal {
                1 => assert_eq!(count(0), 24, "{mode}"),
                2 => assert_eq!((count(0), count(1)), (12, 12), "{mode}"),
                _ => assert_eq!((count(0), count(1), count(2)), (6, 6, 12), "{mode}"),
            }
        }

        for (number, frame) in &frames {
            let key_picture = *number < spatial as u64;
            assert_eq!(frame.key_picture, key_picture, "{mode}");
            // Inter-layer dependency: always (LxTy), at the key picture (LxTy_KEY), never
            // (SxTy).
            let expected = frame.spatial_id > 0
                && match mode.inter_layer_prediction() {
                    InterLayerPrediction::Full => true,
                    InterLayerPrediction::KeyPicture => key_picture,
                    InterLayerPrediction::None => false,
                };
            assert_eq!(
                frame.inter_layer_dependency, expected,
                "{mode} frame {number}"
            );
            // A key frame depends on nothing: the first frame, and in an "S" mode each
            // encoding's first frame.
            let key_frame = key_picture && (frame.spatial_id == 0 || mode.is_simulcast());
            assert_eq!(frame.key_frame, key_frame, "{mode} frame {number}");
            assert_eq!(frame.starts_coded_video_sequence(), *number == 0, "{mode}");
            // A key picture is of temporal layer 0.
            if key_picture {
                assert_eq!(frame.temporal_id, 0, "{mode}");
            }
        }

        // With shifted temporal layers the base layer frames of the spatial layers fall in
        // different pictures; without, a picture's frames are all of one temporal layer.
        let mixed = frames
            .chunks(spatial as usize)
            .any(|p| p.iter().any(|(_, f)| f.temporal_id != p[0].1.temporal_id));
        assert_eq!(mixed, mode.has_temporal_shift(), "{mode}");
    }
}

/// The frames each frame depends on, by frame number.
fn references(frames: &[(u64, LayerFrame)]) -> HashMap<u64, Vec<u64>> {
    frames
        .iter()
        .map(|(number, frame)| {
            (
                *number,
                frame.fdiffs.iter().map(|d| number - *d as u64).collect(),
            )
        })
        .collect()
}

/// A.2 to A.5 for every mode: what the decode target indications and the chains promise is
/// true of the frames' dependencies.
#[test]
fn the_indications_and_chains_of_every_mode_hold() {
    for &mode in ScalabilityMode::ALL {
        let frames = stream(mode, 41);
        let refs = references(&frames);
        let by_number: HashMap<u64, &LayerFrame> = frames.iter().map(|(n, f)| (*n, f)).collect();
        let pattern = ScalabilityPattern::new(mode);
        let targets = pattern.decode_target_layers();
        assert_eq!(
            targets.len(),
            mode.spatial_layers() as usize * mode.temporal_layers() as usize
        );

        for (number, frame) in &frames {
            // A frame depends on frames of its own or a lower temporal layer, and of its own
            // spatial layer or the one below; a frame that depends on nothing is a key frame.
            for reference in &refs[number] {
                let referred = by_number[reference];
                assert!(referred.temporal_id <= frame.temporal_id, "{mode} {number}");
                assert!(
                    referred.spatial_id == frame.spatial_id
                        || referred.spatial_id + 1 == frame.spatial_id,
                    "{mode} {number}"
                );
            }
            assert_eq!(refs[number].is_empty(), frame.key_frame, "{mode} {number}");
        }

        for (dt, (ds, dtemporal)) in targets.iter().enumerate() {
            let present = |n: &u64| by_number[n].dtis[dt].is_present();
            // "Decode target: the set of frames needed to decode a coded video sequence at a
            // given spatial and temporal fidelity": the set is closed under dependency, and
            // it has the target's layer in every picture that has it at all.
            for (number, frame) in &frames {
                if !present(number) {
                    continue;
                }
                assert!(frame.spatial_id <= *ds && frame.temporal_id <= *dtemporal);
                for reference in &refs[number] {
                    assert!(
                        present(reference),
                        "{mode} DT{dt}: {number} needs {reference}"
                    );
                }
            }
            for (number, frame) in &frames {
                if frame.spatial_id == *ds && frame.temporal_id <= *dtemporal {
                    assert!(present(number), "{mode} DT{dt} lacks frame {number}");
                }
            }

            for (number, frame) in &frames {
                match frame.dtis[dt] {
                    // "It will not be a Referred frame for any frame belonging to that
                    // Decode target."
                    DecodeTargetIndication::Discardable => {
                        for (later, _) in frames.iter().filter(|(n, _)| present(n)) {
                            assert!(!refs[later].contains(number), "{mode} DT{dt} {number}");
                        }
                    }
                    // "All subsequent frames for that Decode target will be decodable if the
                    // frame containing the indication is decodable."
                    DecodeTargetIndication::Switch => {
                        let mut decodable: BTreeSet<u64> = BTreeSet::new();
                        let mut pending = vec![*number];
                        while let Some(n) = pending.pop() {
                            if decodable.insert(n) {
                                pending.extend(&refs[&n]);
                            }
                        }
                        for (later, _) in frames.iter().filter(|(n, _)| n > number && present(n)) {
                            assert!(
                                refs[later].iter().all(|r| decodable.contains(r)),
                                "{mode} DT{dt}: after the switch at {number}, {later} is not decodable"
                            );
                            decodable.insert(*later);
                        }
                    }
                    _ => {}
                }
            }
        }

        // Chains (A.5). The frames of a chain are those the chain differences point at. A
        // receiver that has all of them "need not request additional information ... to
        // resume decoding": a chain frame depends on chain frames only, and every frame of a
        // protected target depends, in the end, on chain frames and frames after the last
        // chain frame before it.
        let structure = ScalabilityPattern::dependency_structure(mode, None);
        for chain in 0..mode.spatial_layers() as usize {
            let mut members: BTreeSet<u64> = BTreeSet::new();
            for (number, frame) in &frames {
                let diff = frame.chain_fdiffs[chain] as u64;
                if diff > 0 {
                    members.insert(number - diff);
                }
            }
            for member in &members {
                for reference in &refs[member] {
                    assert!(
                        members.contains(reference),
                        "{mode} chain {chain}: {member}"
                    );
                }
            }
            // The chain difference names the latest member before the frame.
            for (number, frame) in &frames {
                let previous = members.range(..*number).next_back().copied();
                let diff = frame.chain_fdiffs[chain] as u64;
                assert_eq!(
                    previous,
                    (diff > 0).then(|| number - diff),
                    "{mode} {number}"
                );
            }
            // The targets it protects are the chain's spatial layer's.
            for (dt, (ds, _)) in targets.iter().enumerate() {
                assert_eq!(
                    structure.decode_target_protected_by[dt] as usize == chain,
                    *ds as usize == chain,
                    "{mode}"
                );
            }
            // Every base layer frame of the chain's spatial layer is a member (but for the
            // last, which no later frame points at yet).
            let last = *members.iter().next_back().unwrap();
            for (number, frame) in &frames {
                if frame.spatial_id as usize == chain && frame.temporal_id == 0 && *number < last {
                    assert!(members.contains(number), "{mode} chain {chain}: {number}");
                }
            }
        }
    }
}

/// The Dependency Descriptor of every mode, end to end: the structure validates, every frame
/// after the first packet takes three bytes (it follows a template), the receiver reads back
/// what the pattern said, and a forwarder selecting any layer forwards exactly the frames of
/// that layer's decode target.
#[test]
fn every_mode_is_carried_by_the_dependency_descriptor() {
    for &mode in ScalabilityMode::ALL {
        let structure = ScalabilityPattern::dependency_structure(mode, Some((1280, 720)));
        structure.validate().unwrap();
        assert_eq!(
            structure.decode_target_layers(),
            ScalabilityPattern::new(mode).decode_target_layers(),
            "{mode}: the decode targets derived from the templates are the pattern's"
        );
        let frames = stream(mode, 60);

        // One reader, and one selector per decode target's layer.
        let targets = structure.decode_target_layers();
        let mut reader = DependencyDescriptorReader::new();
        let mut selectors: Vec<DecodeTargetSelector> = targets
            .iter()
            .map(|(s, t)| DecodeTargetSelector::new(*s, *t))
            .collect();
        let mut forwarded: Vec<Vec<u64>> = vec![vec![]; targets.len()];

        let mut writer = DependencyDescriptorWriter::new(structure.clone(), 65500).unwrap();
        for (number, frame) in &frames {
            let descriptor = writer
                .next_frame(&frame.dependencies(), frame.starts_coded_video_sequence())
                .unwrap();
            assert_eq!(
                descriptor.frame_number(),
                65500u16.wrapping_add(*number as u16)
            );
            for (first, last) in [(true, false), (false, true)] {
                let bytes = descriptor.packet(first, last).unwrap();
                if *number > 0 || !first {
                    assert_eq!(bytes.len(), 3, "{mode} frame {number}");
                }
                let read = reader.read(&bytes).unwrap().unwrap();
                assert_eq!((read.start_of_frame, read.end_of_frame), (first, last));
                assert_eq!(
                    (read.spatial_id, read.temporal_id),
                    (frame.spatial_id, frame.temporal_id)
                );
                assert_eq!(read.dtis, frame.dtis, "{mode} frame {number}");
                assert_eq!(read.fdiffs, frame.fdiffs, "{mode} frame {number}");
                assert_eq!(
                    read.chain_fdiffs, frame.chain_fdiffs,
                    "{mode} frame {number}"
                );
                let expected_resolution = mode.layer_resolution(frame.spatial_id, 1280, 720);
                assert_eq!(
                    read.resolution.map(|r| (r.width, r.height)),
                    Some(expected_resolution)
                );
                for (dt, selector) in selectors.iter_mut().enumerate() {
                    let forward = selector.forward(&read, &reader);
                    if forward && first {
                        forwarded[dt].push(*number);
                    }
                    assert!(selector.chain_intact(&reader), "{mode} DT{dt}");
                }
            }
        }
        for (dt, selector) in selectors.iter().enumerate() {
            assert_eq!(selector.current_decode_target(), Some(dt), "{mode}");
            let expected: Vec<u64> = frames
                .iter()
                .filter(|(_, f)| f.dtis[dt].is_present())
                .map(|(n, _)| *n)
                .collect();
            assert_eq!(forwarded[dt], expected, "{mode} DT{dt}");
        }
    }
}

/// A forwarder that changes a receiver's layers at arbitrary moments never sends it a frame
/// that depends on one it was not sent, in any mode, and reaches the wanted layers at the
/// next key picture at the latest.
#[test]
fn a_receiver_switched_between_layers_only_gets_decodable_frames() {
    let mut seed = 0x2545_F491u32;
    let mut random = move |n: u32| {
        // xorshift: the same choices on every run.
        seed ^= seed << 13;
        seed ^= seed >> 17;
        seed ^= seed << 5;
        seed % n
    };
    for &mode in ScalabilityMode::ALL {
        let structure = ScalabilityPattern::dependency_structure(mode, None);
        let mut pattern = ScalabilityPattern::new(mode);
        let mut writer = DependencyDescriptorWriter::new(structure.clone(), 0).unwrap();
        let mut reader = DependencyDescriptorReader::new();
        let mut selector = DecodeTargetSelector::new(0, 0);
        let mut sent: BTreeSet<u64> = BTreeSet::new();
        let mut number = 0u64;
        for picture in 0..400 {
            if random(7) == 0 {
                selector.set_target(random(3) as u8, random(3) as u8);
            }
            // A key picture now and then, as after a PLI.
            let key = picture % 97 == 96;
            for frame in pattern.next_picture(key) {
                let descriptor = writer
                    .next_frame(&frame.dependencies(), frame.starts_coded_video_sequence())
                    .unwrap();
                let read = reader
                    .read(&descriptor.packet(true, true).unwrap())
                    .unwrap()
                    .unwrap();
                if selector.forward(&read, &reader) {
                    for fdiff in &frame.fdiffs {
                        assert!(
                            sent.contains(&(number - *fdiff as u64)),
                            "{mode}: frame {number} was forwarded without frame {}",
                            number - *fdiff as u64
                        );
                    }
                    sent.insert(number);
                }
                number += 1;
            }
            if key {
                assert!(
                    !selector.switch_pending(&reader),
                    "{mode}: a key picture switches"
                );
            }
        }
        assert!(sent.len() > 100, "{mode}");
    }
}

/// VP8 (RFC 7741 4.2) carries the temporal modes: TID, Y, TL0PICIDX and N from the pattern,
/// and a forwarder at each temporal layer gets that layer's decode target.
#[test]
fn vp8_carries_the_temporal_modes() {
    for mode in [
        ScalabilityMode::L1T1,
        ScalabilityMode::L1T2,
        ScalabilityMode::L1T3,
    ] {
        let frames = stream(mode, 40);
        let targets = ScalabilityPattern::new(mode).decode_target_layers();
        let mut payloader = Vp8Payloader::default();
        payloader.enable_picture_id = true;
        let mut packet = Vp8Packet::default();
        let mut filters: Vec<Vp8TemporalLayerFilter> = targets
            .iter()
            .map(|(_, t)| Vp8TemporalLayerFilter::new(*t))
            .collect();
        let mut forwarded: Vec<Vec<u64>> = vec![vec![]; targets.len()];
        let mut base_frames = 0u8;
        for (number, frame) in &frames {
            // The VP8 frame tag's low bit: 0 on a key frame.
            let data = Bytes::from(vec![!frame.key_frame as u8, 0xAA, 0xBB, 0xCC, 0xDD]);
            let payloads = payloader
                .payload_frame(6, &data, &frame.vp8_info(mode))
                .unwrap();
            assert!(payloads.len() > 1);
            if frame.temporal_id == 0 {
                base_frames = base_frames.wrapping_add(1);
            }
            for (i, payload) in payloads.iter().enumerate() {
                let vp8_data = packet.depacketize(payload).unwrap();
                if mode == ScalabilityMode::L1T1 {
                    // No layers: no L, T or TID.
                    assert_eq!((packet.l, packet.t), (0, 0));
                } else {
                    assert_eq!((packet.l, packet.t), (1, 1), "{mode}");
                    assert_eq!(packet.tid, frame.temporal_id, "{mode} frame {number}");
                    assert_eq!(packet.y == 1, frame.layer_sync, "{mode} frame {number}");
                    assert_eq!(packet.tl0_pic_idx, base_frames, "{mode} frame {number}");
                }
                assert_eq!(packet.n == 1, frame.discardable, "{mode} frame {number}");
                for (dt, filter) in filters.iter_mut().enumerate() {
                    if filter.forward(&packet, &vp8_data) && i == 0 {
                        forwarded[dt].push(*number);
                    }
                }
            }
        }
        for dt in 0..targets.len() {
            let expected: Vec<u64> = frames
                .iter()
                .filter(|(_, f)| f.dtis[dt].is_present())
                .map(|(n, _)| *n)
                .collect();
            assert_eq!(forwarded[dt], expected, "{mode} DT{dt}");
        }
    }
    // In the three-layer pattern the first T2 frame and the T1 frame depend on the base layer
    // frame only (Y = 1); the second T2 frame depends on the T1 frame.
    let sync: Vec<(u8, bool)> = stream(ScalabilityMode::L1T3, 9)[1..]
        .iter()
        .map(|(_, f)| (f.temporal_id, f.layer_sync))
        .collect();
    assert_eq!(
        sync,
        [
            (2, true),
            (1, true),
            (2, false),
            (0, false),
            (2, true),
            (1, true),
            (2, false),
            (0, false)
        ]
    );
}

/// A VP9 frame as the receiver saw it, for the comparison below.
#[derive(Debug, PartialEq)]
struct Vp9Seen {
    tid: u8,
    sid: u8,
    p: bool,
    d: bool,
    z: bool,
    pdiff: Vec<u8>,
}

/// VP9 (RFC 9628 4.2) carries every mode: the layer indices, P, D and Z of each frame from
/// the pattern, in flexible mode the reference indices, in non-flexible mode the picture
/// group (which a shifted mode does not have), one picture ID per picture. A forwarder
/// selecting any layer forwards that layer's decode target, the marker on the last packet it
/// forwards of each picture.
#[test]
fn vp9_carries_every_mode() {
    for &mode in ScalabilityMode::ALL {
        for flexible in [false, true] {
            let structure =
                ScalabilityPattern::vp9_scalability_structure(mode, Some((1280, 720)), flexible);
            if !flexible && mode.has_temporal_shift() {
                assert!(structure.is_err(), "{mode}");
                continue;
            }
            let structure = structure.unwrap();
            assert_eq!(structure.spatial_layers, mode.spatial_layers());
            assert_eq!(
                structure.resolutions.last().copied(),
                Some((1280, 720)),
                "{mode}"
            );
            assert_eq!(structure.picture_group.is_empty(), flexible, "{mode}");

            let mut payloader = Vp9Payloader::default();
            payloader.initial_picture_id_fn = Some(std::sync::Arc::new(|| 0x7FF0));
            payloader.initial_tl0_pic_idx = Some(250);
            payloader.flexible_mode = flexible;
            payloader
                .set_scalability_structure(Some(structure.clone()))
                .unwrap();

            let frames = stream(mode, 40);
            let targets = ScalabilityPattern::new(mode).decode_target_layers();
            let mut filters: Vec<Vp9LayerFilter> = targets
                .iter()
                .map(|(s, t)| Vp9LayerFilter::new(*s, *t))
                .collect();
            let mut forwarded: Vec<Vec<u64>> = vec![vec![]; targets.len()];
            let mut markers: Vec<Vec<u64>> = vec![vec![]; targets.len()];
            let mut packet = Vp9Packet::default();
            let mut base_pictures = 249u8;
            let spatial = mode.spatial_layers() as u64;

            for (number, frame) in &frames {
                // Opaque frame data: the pattern says what the frame is.
                let data = Bytes::from(vec![0x01; 9]);
                let payloads = payloader
                    .payload_layer_frame(
                        if *number == 0 { 40 } else { 12 },
                        &data,
                        &frame.vp9_info(),
                    )
                    .unwrap_or_else(|e| panic!("{mode} flexible {flexible} frame {number}: {e}"));
                let picture = number / spatial;
                if frame.spatial_id == 0 && frame.temporal_id == 0 {
                    base_pictures = base_pictures.wrapping_add(1);
                }
                let last = payloads.len() - 1;
                for (i, payload) in payloads.iter().enumerate() {
                    packet.depacketize(payload).unwrap();
                    assert_eq!(packet.f, flexible);
                    assert!(packet.i && packet.l);
                    assert_eq!(
                        packet.picture_id as u64,
                        (0x7FF0 + picture) % 0x8000,
                        "{mode}"
                    );
                    assert_eq!((packet.b, packet.e), (i == 0, i == last));
                    // The SS: on the first packet of the key picture only.
                    assert_eq!(packet.v, *number == 0 && i == 0, "{mode} frame {number}");
                    if packet.v {
                        assert_eq!(packet.scalability_structure(), Some(structure.clone()));
                    }
                    let seen = Vp9Seen {
                        tid: packet.tid,
                        sid: packet.sid,
                        p: packet.p,
                        d: packet.d,
                        z: packet.z,
                        pdiff: packet.pdiff.clone(),
                    };
                    let expected = Vp9Seen {
                        tid: frame.temporal_id,
                        sid: frame.spatial_id,
                        p: frame.temporal_reference.is_some(),
                        d: frame.inter_layer_dependency,
                        z: !frame.referenced_by_upper_layers,
                        pdiff: if flexible {
                            frame.temporal_reference.into_iter().collect()
                        } else {
                            vec![]
                        },
                    };
                    assert_eq!(seen, expected, "{mode} flexible {flexible} frame {number}");
                    assert!(packet.u);
                    if !flexible {
                        assert_eq!(packet.tl0picidx, base_pictures, "{mode} frame {number}");
                    }
                    // The sender's marker: the last packet of the picture.
                    let marker = frame.end_of_picture && i == last;
                    for (dt, filter) in filters.iter_mut().enumerate() {
                        let decision = filter.forward(&packet, marker);
                        if decision.forward && i == 0 {
                            forwarded[dt].push(*number);
                        }
                        if decision.marker {
                            assert!(decision.forward && i == last);
                            markers[dt].push(*number);
                        }
                    }
                }
            }

            for (dt, (ds, _)) in targets.iter().enumerate() {
                let mut expected: Vec<u64> = frames
                    .iter()
                    .filter(|(_, f)| f.dtis[dt].is_present())
                    .map(|(n, _)| *n)
                    .collect();
                if mode.is_simulcast() {
                    // The payload descriptor has no decode targets: the filter starts at the
                    // first frame it can and moves up within the key picture, so the key
                    // frames of the encodings below the wanted one are forwarded too.
                    expected.extend(0..*ds as u64);
                    expected.sort_unstable();
                }
                assert_eq!(forwarded[dt], expected, "{mode} flexible {flexible} DT{dt}");
                assert!(!filters[dt].needs_key_frame(), "{mode}");
                assert_eq!(filters[dt].current(), targets[dt], "{mode}");

                // The marker: on the last forwarded frame of each picture.
                let mut last_of_picture: Vec<u64> = vec![];
                for n in &forwarded[dt] {
                    match last_of_picture.last_mut() {
                        Some(l) if *l / spatial == n / spatial => *l = *n,
                        _ => last_of_picture.push(*n),
                    }
                }
                assert_eq!(
                    markers[dt], last_of_picture,
                    "{mode} flexible {flexible} DT{dt}"
                );
            }
        }
    }
}

/// The VP9 filter under arbitrary layer changes: it never forwards a frame that depends on
/// one it withheld, in any mode.
#[test]
fn a_vp9_receiver_switched_between_layers_only_gets_decodable_frames() {
    let mut seed = 0x9E37_79B9u32;
    let mut random = move |n: u32| {
        seed ^= seed << 13;
        seed ^= seed >> 17;
        seed ^= seed << 5;
        seed % n
    };
    for &mode in ScalabilityMode::ALL {
        let mut pattern = ScalabilityPattern::new(mode);
        let mut payloader = Vp9Payloader::default();
        payloader.initial_picture_id_fn = Some(std::sync::Arc::new(|| 0));
        payloader.flexible_mode = true;
        let mut filter = Vp9LayerFilter::new(0, 0);
        let mut packet = Vp9Packet::default();
        let mut sent: BTreeSet<u64> = BTreeSet::new();
        let mut number = 0u64;
        for picture in 0..400 {
            if random(7) == 0 {
                filter.set_target(random(3) as u8, random(3) as u8);
            }
            let key = picture % 97 == 96;
            for frame in pattern.next_picture(key) {
                let payloads = payloader
                    .payload_layer_frame(
                        1200,
                        &Bytes::from_static(&[0x01, 0x02]),
                        &frame.vp9_info(),
                    )
                    .unwrap();
                packet.depacketize(&payloads[0]).unwrap();
                if filter.forward(&packet, frame.end_of_picture).forward {
                    for fdiff in &frame.fdiffs {
                        assert!(
                            sent.contains(&(number - *fdiff as u64)),
                            "{mode}: frame {number} was forwarded without frame {}",
                            number - *fdiff as u64
                        );
                    }
                    sent.insert(number);
                }
                number += 1;
            }
        }
        assert!(sent.len() > 100, "{mode}");
    }
}
