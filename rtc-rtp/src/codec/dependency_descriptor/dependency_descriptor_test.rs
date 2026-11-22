//! The Dependency Descriptor's syntax and semantics (AV1 RTP specification A.4 to A.9), with
//! the structures of the specification's examples (A.10).
//!
//! The specification gives its examples as tables, not as bytes. The byte vectors here were
//! produced from those tables by a separate script written from the pseudo-code of A.8.2, not
//! by the code under test.

use super::bits::BitWriter;
use super::*;

/// A template as a row of the specification's tables: spatial id, temporal id, Fdiffs,
/// Chain(s), DTI symbols.
pub(crate) fn template(
    spatial_id: u8,
    temporal_id: u8,
    fdiffs: &[u16],
    chain_fdiffs: &[u8],
    dtis: &str,
) -> FrameDependencyTemplate {
    FrameDependencyTemplate {
        spatial_id,
        temporal_id,
        dtis: DecodeTargetIndication::from_symbols(dtis).unwrap(),
        fdiffs: fdiffs.to_vec(),
        chain_fdiffs: chain_fdiffs.to_vec(),
    }
}

/// A.10.2.1, "L1T3 Single Spatial Layer with 3 Temporal Layers": decode targets 30 fps, 15
/// fps, 7.5 fps; one chain.
pub(crate) fn l1t3_templates() -> Vec<FrameDependencyTemplate> {
    vec![
        template(0, 0, &[], &[0], "SSS"),
        template(0, 0, &[4], &[4], "SSS"),
        template(0, 1, &[2], &[2], "SD-"),
        template(0, 2, &[1], &[1], "D--"),
        template(0, 2, &[1], &[3], "D--"),
    ]
}

pub(crate) fn l1t3_structure() -> FrameDependencyStructure {
    FrameDependencyStructure {
        template_id_offset: 0,
        num_decode_targets: 3,
        num_chains: 1,
        decode_target_protected_by: vec![0, 0, 0],
        resolutions: vec![],
        templates: l1t3_templates(),
    }
}

/// A.10.2.2, "L3T3 Full SVC": decode targets HD 30 / 15 / 7.5 fps, VGA 30 / 15 / 7.5 fps,
/// QVGA 30 / 15 / 7.5 fps; three chains.
pub(crate) fn l3t3_templates() -> Vec<FrameDependencyTemplate> {
    vec![
        template(0, 0, &[], &[0, 0, 0], "SSSSSSSSS"),
        template(0, 0, &[12], &[12, 11, 10], "RRRRRRSSS"),
        template(0, 1, &[6], &[6, 5, 4], "RR-RR-SD-"),
        template(0, 2, &[3], &[3, 2, 1], "R--R--D--"),
        template(0, 2, &[3], &[9, 8, 7], "R--R--D--"),
        template(1, 0, &[1], &[1, 1, 1], "SSSSSS---"),
        template(1, 0, &[12, 1], &[1, 1, 1], "RRRSSS---"),
        template(1, 1, &[6, 1], &[7, 6, 5], "RR-SD----"),
        template(1, 2, &[3, 1], &[4, 3, 2], "R--D-----"),
        template(1, 2, &[3, 1], &[10, 9, 8], "R--D-----"),
        template(2, 0, &[1], &[2, 1, 1], "SSS------"),
        template(2, 0, &[12, 1], &[2, 1, 1], "SSS------"),
        template(2, 1, &[6, 1], &[8, 7, 6], "SD-------"),
        template(2, 2, &[3, 1], &[5, 4, 3], "D--------"),
        template(2, 2, &[3, 1], &[11, 10, 9], "D--------"),
    ]
}

pub(crate) fn l3t3_structure() -> FrameDependencyStructure {
    FrameDependencyStructure {
        template_id_offset: 0,
        num_decode_targets: 9,
        num_chains: 3,
        decode_target_protected_by: vec![2, 2, 2, 1, 1, 1, 0, 0, 0],
        resolutions: vec![],
        templates: l3t3_templates(),
    }
}

/// A.10.2.3, "L3T3 K-SVC with Temporal Shift": the same decode targets and chains.
pub(crate) fn l3t3_key_shift_templates() -> Vec<FrameDependencyTemplate> {
    vec![
        template(0, 0, &[], &[0, 0, 0], "SSSSSSSSS"),
        template(0, 0, &[3], &[3, 2, 1], "------SSS"),
        template(0, 0, &[12], &[12, 8, 1], "------SSS"),
        template(0, 1, &[6], &[6, 2, 7], "------SD-"),
        template(0, 2, &[3], &[3, 5, 4], "------D--"),
        template(0, 2, &[3], &[9, 5, 10], "------D--"),
        template(0, 2, &[3], &[3, 11, 4], "------D--"),
        template(1, 0, &[1], &[1, 1, 1], "SSSSSS---"),
        template(1, 0, &[6], &[4, 6, 5], "---SSS---"),
        template(1, 0, &[12], &[4, 12, 5], "---SSS---"),
        template(1, 1, &[6], &[10, 6, 11], "---SD----"),
        template(1, 2, &[3], &[1, 3, 2], "---D-----"),
        template(1, 2, &[3], &[7, 3, 8], "---D-----"),
        template(1, 2, &[3], &[1, 9, 2], "---D-----"),
        template(2, 0, &[1], &[2, 1, 1], "SSS------"),
        template(2, 0, &[12], &[11, 7, 12], "SSS------"),
        template(2, 1, &[6], &[5, 1, 6], "SD-------"),
        template(2, 2, &[3], &[2, 4, 3], "D--------"),
        template(2, 2, &[3], &[8, 4, 9], "D--------"),
        template(2, 2, &[3], &[2, 10, 3], "D--------"),
    ]
}

/// A.9: the extmap URI.
#[test]
fn the_extmap_uri_is_the_specifications() {
    assert_eq!(
        DEPENDENCY_DESCRIPTOR_URI,
        "https://aomediacodec.github.io/av1-rtp-spec/#dependency-descriptor-rtp-header-extension"
    );
}

/// A.8.2 with the structure of A.10.2.1: the first packet of a key frame (one-packet frame
/// 100, template 0, the structure attached), bit for bit, and back.
#[test]
fn the_l1t3_example_structure_is_written_bit_for_bit() -> Result<()> {
    let structure = l1t3_structure();
    let mut descriptor = DependencyDescriptor::from_template(&structure, 0, 100).unwrap();
    descriptor.start_of_frame = true;
    descriptor.end_of_frame = true;
    descriptor.attached_structure = Some(structure.clone());

    let bytes = descriptor.marshal(&structure)?;
    assert_eq!(
        &bytes[..],
        &[
            0xC0, 0x00, 0x64, 0x80, 0x02, 0x14, 0xEA, 0xAA, 0x44, 0x10, 0x4D, 0x14, 0x10, 0x20,
            0x84, 0x26
        ]
    );

    let read = DependencyDescriptor::unmarshal(&bytes, None)?.unwrap();
    assert_eq!(read, descriptor);
    assert_eq!((read.spatial_id, read.temporal_id), (0, 0));
    assert_eq!(
        read.dtis,
        DecodeTargetIndication::from_symbols("SSS").unwrap()
    );
    assert!(read.fdiffs.is_empty());
    assert_eq!(read.chain_fdiffs, [0]);
    // decode_target_layers(): 30 fps is temporal layer 2, 15 fps layer 1, 7.5 fps layer 0.
    assert_eq!(structure.decode_target_layers(), [(0, 2), (0, 1), (0, 0)]);
    assert_eq!(
        (structure.max_spatial_id(), structure.max_temporal_id()),
        (0, 2)
    );
    Ok(())
}

/// A.8.2: `template_id_offset` shifts the template ids, and `render_resolutions` follows
/// `resolutions_present_flag`. Frame number 65535, template id 5 (the first template), a
/// packet that starts a frame and does not end it.
#[test]
fn template_id_offset_and_resolutions_are_written_bit_for_bit() -> Result<()> {
    let structure = FrameDependencyStructure {
        template_id_offset: 5,
        resolutions: vec![RenderResolution {
            width: 1280,
            height: 720,
        }],
        ..l1t3_structure()
    };
    let mut descriptor = DependencyDescriptor::from_template(&structure, 0, 0xFFFF).unwrap();
    assert_eq!(descriptor.template_id, 5);
    descriptor.start_of_frame = true;
    descriptor.attached_structure = Some(structure.clone());

    let bytes = descriptor.marshal(&structure)?;
    assert_eq!(
        &bytes[..],
        &[
            0x85, 0xFF, 0xFF, 0x80, 0xA2, 0x14, 0xEA, 0xAA, 0x44, 0x10, 0x4D, 0x14, 0x10, 0x20,
            0x84, 0x27, 0x04, 0xFF, 0x02, 0xCF
        ]
    );
    let read = DependencyDescriptor::unmarshal(&bytes, None)?.unwrap();
    assert_eq!(read, descriptor);
    assert_eq!(
        read.resolution,
        Some(RenderResolution {
            width: 1280,
            height: 720
        })
    );
    Ok(())
}

/// A.1: "the typical DD payload requires three bytes". A frame that follows a template: the
/// first T2 frame after the key frame, template 3 of A.10.2.1.
#[test]
fn a_frame_that_follows_a_template_is_three_bytes() -> Result<()> {
    let structure = l1t3_structure();
    let mut descriptor = DependencyDescriptor::from_template(&structure, 3, 101).unwrap();
    descriptor.start_of_frame = true;
    descriptor.end_of_frame = true;
    let bytes = descriptor.marshal(&structure)?;
    assert_eq!(&bytes[..], &[0xC3, 0x00, 0x65]);

    let read = DependencyDescriptor::unmarshal(&bytes, Some(&structure))?.unwrap();
    assert_eq!(read, descriptor);
    assert_eq!((read.spatial_id, read.temporal_id), (0, 2));
    assert_eq!(read.fdiffs, [1]);
    assert_eq!(read.chain_fdiffs, [1]);
    assert_eq!(
        read.dtis,
        DecodeTargetIndication::from_symbols("D--").unwrap()
    );
    assert_eq!(read.active_decode_targets_bitmask, None);
    Ok(())
}

/// A.8.2 `frame_fdiffs()`: `next_fdiff_size` 1, 2 and 3 for frame differences of 5, 17 and
/// 300 on a frame that uses template 1 (whose own frame difference is 4).
#[test]
fn custom_frame_differences_are_written_bit_for_bit() -> Result<()> {
    let structure = l1t3_structure();
    let mut descriptor = DependencyDescriptor::from_template(&structure, 1, 0x70).unwrap();
    descriptor.start_of_frame = true;
    descriptor.fdiffs = vec![5, 17, 300];
    let bytes = descriptor.marshal(&structure)?;
    assert_eq!(
        &bytes[..],
        &[0x81, 0x00, 0x70, 0x12, 0x90, 0x86, 0x25, 0x60]
    );
    assert_eq!(
        DependencyDescriptor::unmarshal(&bytes, Some(&structure))?.unwrap(),
        descriptor
    );
    Ok(())
}

/// A.8.2: `active_decode_targets_bitmask`, `frame_dtis()` and `frame_chains()` together, on a
/// packet that ends a frame using template 2. The last two bits are `zero_padding`, written
/// as 0 (A.8.3).
#[test]
fn custom_indications_chains_and_the_bitmask_are_written_bit_for_bit() -> Result<()> {
    let structure = l1t3_structure();
    let mut descriptor = DependencyDescriptor::from_template(&structure, 2, 0x1234).unwrap();
    descriptor.end_of_frame = true;
    descriptor.active_decode_targets_bitmask = Some(0b011);
    descriptor.dtis = DecodeTargetIndication::from_symbols("S--").unwrap();
    descriptor.chain_fdiffs = vec![9];
    let bytes = descriptor.marshal(&structure)?;
    assert_eq!(&bytes[..], &[0x42, 0x12, 0x34, 0x6B, 0x80, 0x24]);
    assert_eq!(
        DependencyDescriptor::unmarshal(&bytes, Some(&structure))?.unwrap(),
        descriptor
    );

    // The bitmask alone: four bytes.
    let mut descriptor = DependencyDescriptor::from_template(&structure, 1, 1).unwrap();
    descriptor.active_decode_targets_bitmask = Some(0b101);
    let bytes = descriptor.marshal(&structure)?;
    assert_eq!(&bytes[..], &[0x01, 0x00, 0x01, 0x45]);
    assert_eq!(
        DependencyDescriptor::unmarshal(&bytes, Some(&structure))?.unwrap(),
        descriptor
    );
    Ok(())
}

/// A.8.2 with the structure of A.10.2.2 and three resolutions: 95 bytes, bit for bit, and all
/// fifteen templates, the chains and the decode target layers back.
#[test]
fn the_l3t3_example_structure_is_written_bit_for_bit() -> Result<()> {
    let structure = FrameDependencyStructure {
        resolutions: [(320, 180), (640, 360), (1280, 720)]
            .map(|(width, height)| RenderResolution { width, height })
            .to_vec(),
        ..l3t3_structure()
    };
    let mut descriptor = DependencyDescriptor::from_template(&structure, 0, 1).unwrap();
    descriptor.start_of_frame = true;
    descriptor.attached_structure = Some(structure.clone());
    let bytes = descriptor.marshal(&structure)?;
    let expected: [u8; 95] = [
        0x80, 0x00, 0x01, 0x80, 0x08, 0x14, 0x85, 0x21, 0x4E, 0xAA, 0xAA, 0xFF, 0xFA, 0xBC, 0xF2,
        0x4C, 0x30, 0x43, 0x0C, 0x10, 0xAA, 0xA0, 0x3F, 0xA8, 0x0F, 0x24, 0x03, 0x04, 0x00, 0xC1,
        0x00, 0x2A, 0x00, 0x0A, 0x80, 0x02, 0x40, 0x00, 0x40, 0x00, 0x10, 0x00, 0x06, 0xD5, 0x49,
        0x24, 0x1B, 0x82, 0xB0, 0x4A, 0x09, 0x41, 0x06, 0xE0, 0xAC, 0x12, 0x82, 0x50, 0x3F, 0xEA,
        0x00, 0x01, 0x97, 0x4C, 0xA8, 0x64, 0x33, 0x0E, 0x22, 0x22, 0x22, 0xEC, 0xA8, 0x65, 0x53,
        0x04, 0x22, 0x42, 0x30, 0xEC, 0xA8, 0x77, 0x53, 0x01, 0x3F, 0x00, 0xB3, 0x02, 0x7F, 0x01,
        0x67, 0x04, 0xFF, 0x02, 0xCF,
    ];
    assert_eq!(&bytes[..], &expected[..]);

    let read = DependencyDescriptor::unmarshal(&bytes, None)?.unwrap();
    let read_structure = read.attached_structure.as_ref().unwrap();
    assert_eq!(read_structure, &structure);
    assert_eq!(read_structure.templates, l3t3_templates());
    assert_eq!(
        read_structure.decode_target_layers(),
        [
            (2, 2),
            (2, 1),
            (2, 0),
            (1, 2),
            (1, 1),
            (1, 0),
            (0, 2),
            (0, 1),
            (0, 0)
        ]
    );
    assert_eq!(read_structure.decode_target_for(1, 1), Some(4));
    assert_eq!(read_structure.decode_target_for(3, 7), Some(0));
    Ok(())
}

/// The twenty templates of A.10.2.3 (K-SVC with temporal shift) and every frame that uses
/// one of them read back as written.
#[test]
fn the_l3t3_key_shift_example_structure_round_trips() -> Result<()> {
    let structure = FrameDependencyStructure {
        template_id_offset: 40,
        templates: l3t3_key_shift_templates(),
        ..l3t3_structure()
    };
    structure.validate()?;
    let mut key = DependencyDescriptor::from_template(&structure, 0, 7).unwrap();
    key.attached_structure = Some(structure.clone());
    let bytes = key.marshal(&structure)?;
    let read = DependencyDescriptor::unmarshal(&bytes, None)?.unwrap();
    assert_eq!(read.attached_structure.as_ref(), Some(&structure));

    for index in 0..structure.templates.len() {
        let descriptor = DependencyDescriptor::from_template(&structure, index, 9).unwrap();
        // Ids wrap at 64: template 24 has id 0.
        assert_eq!(descriptor.template_id as usize, (40 + index) % 64);
        let bytes = descriptor.marshal(&structure)?;
        assert_eq!(bytes.len(), 3);
        assert_eq!(
            DependencyDescriptor::unmarshal(&bytes, Some(&structure))?.unwrap(),
            descriptor
        );
    }
    Ok(())
}

/// A.10.1.3, "Dynamic Prediction Structure": two quality layers, the first set of templates,
/// and frames 105 to 108 with the custom chain and frame differences of the example's table.
#[test]
fn the_dynamic_prediction_example_uses_custom_differences() -> Result<()> {
    // Template id, layer, Chain0 diff, Frame diff, as in the example. One decode target per
    // layer; both are protected by the one chain the example tracks.
    let structure = FrameDependencyStructure {
        template_id_offset: 0,
        num_decode_targets: 2,
        num_chains: 1,
        decode_target_protected_by: vec![0, 0],
        resolutions: vec![],
        templates: vec![
            template(0, 0, &[], &[0], "SS"),
            template(0, 0, &[2], &[2], "SR"),
            template(1, 0, &[1], &[1], "-S"),
            template(1, 0, &[1, 2], &[1], "-R"),
        ],
    };
    let mut reader = DependencyDescriptorReader::new();
    let mut key = DependencyDescriptor::from_template(&structure, 0, 1).unwrap();
    key.attached_structure = Some(structure.clone());
    reader.read(&key.marshal(&structure)?)?.unwrap();

    // frame_number, template, custom FrameFdiff[], custom frame_chain_fdiff[0], and the size.
    let frames: [(u16, usize, Option<&[u16]>, Option<u8>, usize); 5] = [
        (104, 3, None, None, 3),
        (105, 2, None, Some(2), 5),
        (106, 2, None, Some(3), 5),
        (107, 2, None, Some(4), 5),
        (108, 1, Some(&[5]), Some(5), 6),
    ];
    for (frame_number, index, fdiffs, chain, size) in frames {
        let mut descriptor =
            DependencyDescriptor::from_template(&structure, index, frame_number).unwrap();
        if let Some(fdiffs) = fdiffs {
            descriptor.fdiffs = fdiffs.to_vec();
        }
        if let Some(chain) = chain {
            descriptor.chain_fdiffs = vec![chain];
        }
        let bytes = descriptor.marshal(&structure)?;
        assert_eq!(bytes.len(), size, "frame {frame_number}");
        let read = reader.read(&bytes)?.unwrap();
        assert_eq!(read, descriptor, "frame {frame_number}");
        // "Previous Frame in Chain0" of the example: 103 for all of them.
        assert_eq!(
            read.referred_frame_number(read.chain_fdiffs[0] as u16),
            103,
            "frame {frame_number}"
        );
    }
    // Frame 108 depends on frame 103.
    assert_eq!(108u16.wrapping_sub(5), 103);

    // The example's second way: ten templates, and no frame needs a custom field.
    let larger = FrameDependencyStructure {
        template_id_offset: structure.next_template_id_offset(),
        templates: vec![
            template(0, 0, &[], &[0], "SS"),
            template(0, 0, &[2], &[2], "SR"),
            template(0, 0, &[3], &[3], "SR"),
            template(0, 0, &[4], &[4], "SR"),
            template(0, 0, &[5], &[5], "SR"),
            template(1, 0, &[1], &[1], "-S"),
            template(1, 0, &[1, 2], &[1], "-R"),
            template(1, 0, &[1], &[2], "-R"),
            template(1, 0, &[1], &[3], "-R"),
            template(1, 0, &[1], &[4], "-R"),
        ],
        ..structure.clone()
    };
    for (frame_number, index) in [(105u16, 7usize), (106, 8), (107, 9), (108, 4)] {
        let descriptor = DependencyDescriptor::from_template(&larger, index, frame_number).unwrap();
        let bytes = descriptor.marshal(&larger)?;
        assert_eq!(bytes.len(), 3);
        let read = DependencyDescriptor::unmarshal(&bytes, Some(&larger))?.unwrap();
        assert_eq!(read.referred_frame_number(read.chain_fdiffs[0] as u16), 103);
    }
    Ok(())
}

/// A.8.3: "fdiff_minus_one ... The calculation is done modulo the size of the frame_number
/// field", and every size `next_fdiff_size` selects reads back at its limits.
#[test]
fn frame_differences_round_trip_at_their_limits_and_wrap() -> Result<()> {
    let structure = l1t3_structure();
    let mut descriptor = DependencyDescriptor::from_template(&structure, 1, 2).unwrap();
    descriptor.fdiffs = vec![1, 16, 17, 256, 257, 4096];
    let bytes = descriptor.marshal(&structure)?;
    let read = DependencyDescriptor::unmarshal(&bytes, Some(&structure))?.unwrap();
    assert_eq!(read.fdiffs, [1, 16, 17, 256, 257, 4096]);
    // Frame 2 referring 5 frames back refers to frame 65533.
    assert_eq!(read.referred_frame_number(5), 65533);

    for bad in [vec![0u16], vec![4097]] {
        descriptor.fdiffs = bad;
        assert!(descriptor.marshal(&structure).is_err());
    }
    Ok(())
}

/// A.8.3: "zero_padding MUST be set to 0 and be ignored by receivers."
#[test]
fn zero_padding_is_ignored_on_receipt() -> Result<()> {
    let structure = l1t3_structure();
    let mut descriptor = DependencyDescriptor::from_template(&structure, 2, 0x1234).unwrap();
    descriptor.chain_fdiffs = vec![9];
    let mut bytes = descriptor.marshal(&structure)?.to_vec();
    // 24 + 5 + 8 bits: the last three bits of the fifth byte are padding.
    assert_eq!(bytes.len(), 5);
    assert_eq!(bytes[4] & 0x07, 0);
    bytes[4] |= 0x07;
    bytes.extend_from_slice(&[0xFF, 0xA5]);
    assert_eq!(
        DependencyDescriptor::unmarshal(&bytes, Some(&structure))?.unwrap(),
        descriptor
    );
    Ok(())
}

/// A.8.3: a template id outside the structure's range "may be caused by a change of the
/// template dependency structure, that is a packet with the new template dependency structure
/// was lost or delayed". Such a packet, and any packet before a structure is known, cannot be
/// interpreted; its mandatory fields can.
#[test]
fn a_descriptor_without_its_structure_is_not_interpreted() -> Result<()> {
    let structure = l1t3_structure();
    let mut reader = DependencyDescriptorReader::new();

    // No structure yet.
    assert_eq!(reader.read(&[0xC3, 0x00, 0x65])?, None);
    assert_eq!(
        DependencyDescriptor::unmarshal_mandatory(&[0xC3, 0x00, 0x65])?,
        (true, true, 3, 101)
    );

    let mut key = DependencyDescriptor::from_template(&structure, 0, 100).unwrap();
    key.attached_structure = Some(structure.clone());
    assert!(reader.read(&key.marshal(&structure)?)?.is_some());
    assert_eq!(reader.structure(), Some(&structure));
    assert!(reader.read(&[0xC3, 0x00, 0x65])?.is_some());

    // Template id 5 is one past this structure's five templates; so is 63.
    assert_eq!(reader.read(&[0xC5, 0x00, 0x66])?, None);
    assert_eq!(reader.read(&[0xFF, 0x00, 0x66])?, None);
    // The writer refuses to produce one (A.8.3: "MUST be in the range").
    let mut descriptor = DependencyDescriptor::from_template(&structure, 4, 1).unwrap();
    descriptor.template_id = 5;
    assert!(descriptor.marshal(&structure).is_err());
    Ok(())
}

/// A.4: a structure without a bitmask makes every decode target active; a bitmask replaces
/// the set, and it holds "until the next update".
#[test]
fn active_decode_targets_hold_until_the_next_update() -> Result<()> {
    let structure = l1t3_structure();
    let mut reader = DependencyDescriptorReader::new();
    assert_eq!(reader.active_decode_targets(), 0);

    let mut key = DependencyDescriptor::from_template(&structure, 0, 100).unwrap();
    key.attached_structure = Some(structure.clone());
    let read = reader.read(&key.marshal(&structure)?)?.unwrap();
    assert_eq!(read.active_decode_targets_bitmask, None);
    assert_eq!(reader.active_decode_targets(), 0b111);

    // "Bit i is equal to 1 if Decode target i is available ... The least significant bit
    // corresponds to Decode target 0": only the 7.5 fps target (index 2) stays.
    let mut delta = DependencyDescriptor::from_template(&structure, 1, 104).unwrap();
    delta.active_decode_targets_bitmask = Some(0b100);
    reader.read(&delta.marshal(&structure)?)?.unwrap();
    assert_eq!(reader.active_decode_targets(), 0b100);
    reader.read(&[0xC3, 0x00, 0x69])?.unwrap();
    assert_eq!(reader.active_decode_targets(), 0b100);

    // A structure with a bitmask in the same packet: the bitmask wins over "all active".
    key.active_decode_targets_bitmask = Some(0b110);
    let bytes = key.marshal(&structure)?;
    let read = reader.read(&bytes)?.unwrap();
    assert_eq!(read.active_decode_targets_bitmask, Some(0b110));
    assert_eq!(reader.active_decode_targets(), 0b110);

    // A bitmask of all targets next to a structure says nothing new and is not written.
    key.active_decode_targets_bitmask = Some(0b111);
    let all = key.marshal(&structure)?;
    assert_eq!(all.len(), 16);
    let read = reader.read(&all)?.unwrap();
    assert_eq!(read.active_decode_targets_bitmask, None);
    assert_eq!(reader.active_decode_targets(), 0b111);

    // A bit beyond the decode targets cannot be written.
    delta.active_decode_targets_bitmask = Some(0b1000);
    assert!(delta.marshal(&structure).is_err());
    Ok(())
}

/// A.5 and A.6: "Chains protecting no active Decode targets MUST be ignored", and
/// `PartOfActiveChain` for a frame of the L3T3 example.
#[test]
fn a_chain_without_an_active_decode_target_is_ignored() -> Result<()> {
    let structure = l3t3_structure();
    let mut reader = DependencyDescriptorReader::new();
    let mut key = DependencyDescriptor::from_template(&structure, 0, 1).unwrap();
    key.attached_structure = Some(structure.clone());
    let key_read = reader.read(&key.marshal(&structure)?)?.unwrap();
    for chain in 0..3 {
        assert!(reader.chain_has_active_decode_target(chain));
        // The key frame is a Switch for every target: part of every chain.
        assert!(reader.part_of_active_chain(&key_read, chain));
    }

    // A T1 frame of spatial layer 0 ("RR-RR-SD-"): not present or discardable for one target
    // of each chain, so part of none.
    let t1 = DependencyDescriptor::from_template(&structure, 2, 7).unwrap();
    let t1_read = reader.read(&t1.marshal(&structure)?)?.unwrap();
    for chain in 0..3 {
        assert!(!reader.part_of_active_chain(&t1_read, chain));
    }

    // Only the QVGA targets (6, 7, 8; chain 0) stay active: chains 1 and 2 are ignored.
    let mut update = DependencyDescriptor::from_template(&structure, 1, 13).unwrap();
    update.active_decode_targets_bitmask = Some(0b1_1100_0000);
    let update_read = reader.read(&update.marshal(&structure)?)?.unwrap();
    assert!(reader.chain_has_active_decode_target(0));
    assert!(!reader.chain_has_active_decode_target(1));
    assert!(!reader.chain_has_active_decode_target(2));
    assert!(reader.part_of_active_chain(&update_read, 0));
    assert!(!reader.part_of_active_chain(&update_read, 2));
    Ok(())
}

/// A descriptor that ends before its fields do is an error at every length, never a panic or
/// a guess; three bytes are a descriptor without extended fields.
#[test]
fn a_truncated_descriptor_is_refused() -> Result<()> {
    let structure = FrameDependencyStructure {
        resolutions: [(320, 180), (640, 360), (1280, 720)]
            .map(|(width, height)| RenderResolution { width, height })
            .to_vec(),
        ..l3t3_structure()
    };
    let mut descriptor = DependencyDescriptor::from_template(&structure, 1, 1).unwrap();
    descriptor.attached_structure = Some(structure.clone());
    descriptor.active_decode_targets_bitmask = Some(0b1);
    descriptor.dtis = DecodeTargetIndication::from_symbols("---------").unwrap();
    descriptor.fdiffs = vec![3000];
    descriptor.chain_fdiffs = vec![200, 201, 202];
    let bytes = descriptor.marshal(&structure)?;
    assert_eq!(
        DependencyDescriptor::unmarshal(&bytes, None)?.unwrap(),
        descriptor
    );
    for len in 0..bytes.len() {
        let result = DependencyDescriptor::unmarshal(&bytes[..len], None);
        match len {
            0..=2 => assert!(result.is_err(), "{len} bytes"),
            3 => assert_eq!(result?, None, "no structure in three bytes"),
            _ => assert!(result.is_err(), "{len} bytes"),
        }
    }
    assert!(DependencyDescriptor::unmarshal_mandatory(&[0xC3, 0x00]).is_err());
    Ok(())
}

/// A template id is six bits, so a structure can have 64 templates; a 65th is refused when
/// reading (it could never be named) and when writing.
#[test]
fn a_structure_has_at_most_64_templates() -> Result<()> {
    let build = |templates: usize| {
        let mut w = BitWriter::default();
        w.f(8, 0); // start_of_frame 0, end_of_frame 0, template id 0
        w.f(16, 1); // frame_number
        w.f(5, 0b10000); // a structure and nothing else
        w.f(6, 0); // template_id_offset
        w.f(5, 0); // dt_cnt_minus_one
        for i in 0..templates {
            w.f(2, if i + 1 == templates { 3 } else { 0 }); // next_layer_idc
        }
        for _ in 0..templates {
            w.f(2, 2); // template_dti: Switch
        }
        for _ in 0..templates {
            w.f(1, 0); // fdiff_follows_flag
        }
        w.f(1, 0); // chain_cnt = ns(2) -> 0
        w.f(1, 0); // resolutions_present_flag
        w.finish()
    };
    let read = DependencyDescriptor::unmarshal(&build(64), None)?.unwrap();
    assert_eq!(read.attached_structure.unwrap().templates.len(), 64);
    assert!(DependencyDescriptor::unmarshal(&build(65), None).is_err());

    let mut structure = FrameDependencyStructure {
        template_id_offset: 0,
        num_decode_targets: 1,
        num_chains: 0,
        decode_target_protected_by: vec![],
        resolutions: vec![],
        templates: vec![template(0, 0, &[], &[], "S"); 64],
    };
    structure.validate()?;
    structure.templates.push(template(0, 0, &[], &[], "S"));
    assert!(structure.validate().is_err());
    Ok(())
}

/// A.8.3 and the syntax of A.8.2: a structure the syntax cannot carry or the semantics forbid
/// does not validate, so it is never written.
#[test]
fn a_structure_the_syntax_cannot_carry_does_not_validate() {
    let good = l3t3_structure();
    assert!(good.validate().is_ok());
    let cases: Vec<(&str, Box<dyn Fn(&mut FrameDependencyStructure)>)> = vec![
        (
            "template_id_offset 64",
            Box::new(|s| s.template_id_offset = 64),
        ),
        ("no decode target", Box::new(|s| s.num_decode_targets = 0)),
        ("33 decode targets", Box::new(|s| s.num_decode_targets = 33)),
        ("no template", Box::new(|s| s.templates.clear())),
        ("more chains than targets", Box::new(|s| s.num_chains = 10)),
        // "Each Decode target MUST be protected by exactly one Chain."
        (
            "a target without a chain",
            Box::new(|s| s.decode_target_protected_by.truncate(8)),
        ),
        (
            "a chain that does not exist",
            Box::new(|s| s.decode_target_protected_by[0] = 3),
        ),
        (
            "first template not of layer 0, 0",
            Box::new(|s| s.templates[0].temporal_id = 1),
        ),
        (
            "a temporal layer skipped",
            Box::new(|s| s.templates[2].temporal_id = 2),
        ),
        (
            "a spatial layer out of order",
            Box::new(|s| s.templates.swap(4, 5)),
        ),
        (
            "an indication missing",
            Box::new(|s| s.templates[3].dtis.truncate(8)),
        ),
        (
            "a frame difference of 0",
            Box::new(|s| s.templates[1].fdiffs = vec![0]),
        ),
        (
            "a frame difference of 17",
            Box::new(|s| s.templates[1].fdiffs = vec![17]),
        ),
        (
            "a chain difference of 16",
            Box::new(|s| s.templates[1].chain_fdiffs[0] = 16),
        ),
        (
            "a chain difference missing",
            Box::new(|s| s.templates[1].chain_fdiffs.truncate(2)),
        ),
        (
            "two resolutions for three layers",
            Box::new(|s| {
                s.resolutions = vec![
                    RenderResolution {
                        width: 1,
                        height: 1
                    };
                    2
                ]
            }),
        ),
        (
            "a resolution of 65537",
            Box::new(|s| {
                s.resolutions = vec![
                    RenderResolution {
                        width: 65537,
                        height: 1
                    };
                    3
                ]
            }),
        ),
    ];
    for (name, break_it) in cases {
        let mut structure = good.clone();
        break_it(&mut structure);
        assert!(structure.validate().is_err(), "{name}");
        // And it is not written.
        let mut descriptor = DependencyDescriptor::from_template(&good, 0, 1).unwrap();
        descriptor.attached_structure = Some(structure.clone());
        assert!(descriptor.marshal(&structure).is_err(), "{name}");
    }

    // A structure without chains has no protection table, and reads back that way.
    let chainless = FrameDependencyStructure {
        num_chains: 0,
        decode_target_protected_by: vec![],
        templates: l1t3_templates()
            .into_iter()
            .map(|mut t| {
                t.chain_fdiffs.clear();
                t
            })
            .collect(),
        ..l1t3_structure()
    };
    let mut descriptor = DependencyDescriptor::from_template(&chainless, 0, 1).unwrap();
    descriptor.attached_structure = Some(chainless.clone());
    let bytes = descriptor.marshal(&chainless).unwrap();
    let read = DependencyDescriptor::unmarshal(&bytes, None)
        .unwrap()
        .unwrap();
    assert_eq!(read.attached_structure, Some(chainless));
    assert!(read.chain_fdiffs.is_empty());
}

/// What a frame's descriptor cannot say is refused: a layer other than its template's, the
/// wrong number of indications or chain differences, a structure that is not the one in
/// force.
#[test]
fn a_frame_that_contradicts_its_structure_is_refused() {
    let structure = l1t3_structure();
    let good = DependencyDescriptor::from_template(&structure, 2, 9).unwrap();
    assert!(good.marshal(&structure).is_ok());

    let mut bad = good.clone();
    bad.temporal_id = 2;
    assert!(bad.marshal(&structure).is_err());
    let mut bad = good.clone();
    bad.dtis.pop();
    assert!(bad.marshal(&structure).is_err());
    let mut bad = good.clone();
    bad.chain_fdiffs.push(1);
    assert!(bad.marshal(&structure).is_err());
    let mut bad = good.clone();
    bad.attached_structure = Some(l3t3_structure());
    assert!(bad.marshal(&structure).is_err());
}
