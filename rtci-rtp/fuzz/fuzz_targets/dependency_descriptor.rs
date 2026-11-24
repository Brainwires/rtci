#![no_main]
//! Stateful target: the Dependency Descriptor header extension (AV1 RTP specification,
//! appendix A) as a forwarder reads it. One reader and three decode target selectors are fed a
//! sequence of fuzzed descriptors, so the structure, the active decode targets and the
//! selectors' frame history build up as on a real stream.
//!
//! Oracle: a descriptor that parses is written back and parses to the same descriptor.
//!
//! Input: three bytes of selector targets, then records of a length byte and that many bytes.

use libfuzzer_sys::fuzz_target;
use rtci_rtp::codec::dependency_descriptor::{
    DecodeTargetSelector, DependencyDescriptor, DependencyDescriptorReader,
    DependencyDescriptorWriter,
};

fuzz_target!(|data: &[u8]| {
    if data.len() < 3 {
        return;
    }
    let mut selectors: Vec<DecodeTargetSelector> = data[..3]
        .iter()
        .map(|b| DecodeTargetSelector::new(b >> 4, b & 0x0F))
        .collect();
    let mut reader = DependencyDescriptorReader::new();
    let mut writer: Option<DependencyDescriptorWriter> = None;
    let mut data = &data[3..];

    let mut records = 0;
    while let Some((&len, rest)) = data.split_first() {
        let len = usize::from(len).min(rest.len());
        let (record, rest) = rest.split_at(len);
        data = rest;
        records += 1;
        if records > 512 {
            break;
        }

        let _ = DependencyDescriptor::unmarshal_mandatory(record);
        let Ok(Some(descriptor)) = reader.read(record) else {
            continue;
        };
        let structure = reader
            .structure()
            .expect("a descriptor was interpreted")
            .clone();

        // What was read can be written, and reads back the same. (A bitmask of all decode
        // targets next to a structure says nothing and is not written.)
        let bytes = descriptor
            .marshal(&structure)
            .expect("a parsed descriptor is writable");
        let again = DependencyDescriptor::unmarshal(&bytes, Some(&structure))
            .expect("a written descriptor parses")
            .expect("its structure is known");
        let mut expected = descriptor.clone();
        if expected.attached_structure.is_some()
            && expected.active_decode_targets_bitmask == Some(structure.all_decode_targets())
        {
            expected.active_decode_targets_bitmask = None;
        }
        assert_eq!(again, expected);

        for selector in &mut selectors {
            let _ = selector.forward(&descriptor, &reader);
            let _ = selector.chain_intact(&reader);
            let _ = selector.switch_pending(&reader);
        }
        for chain in 0..structure.num_chains {
            let _ = reader.part_of_active_chain(&descriptor, chain);
        }

        // The send side with the same frame: a writer for the structure in force.
        if descriptor.attached_structure.is_some() {
            writer =
                DependencyDescriptorWriter::new(structure.clone(), descriptor.frame_number).ok();
        }
        if let Some(writer) = &mut writer {
            let frame = rtci_rtp::codec::dependency_descriptor::FrameDependencyTemplate {
                spatial_id: descriptor.spatial_id,
                temporal_id: descriptor.temporal_id,
                dtis: descriptor.dtis.clone(),
                fdiffs: descriptor.fdiffs.clone(),
                chain_fdiffs: descriptor.chain_fdiffs.clone(),
            };
            let key = descriptor.attached_structure.is_some();
            if let Ok(frame_descriptor) = writer.next_frame(&frame, key) {
                let bytes = frame_descriptor
                    .packet(true, true)
                    .expect("a described frame is writable");
                let read = DependencyDescriptor::unmarshal(&bytes, Some(writer.structure()))
                    .expect("a written descriptor parses")
                    .expect("its structure is known");
                assert_eq!(read.dtis, descriptor.dtis);
                assert_eq!(read.fdiffs, descriptor.fdiffs);
                assert_eq!(read.chain_fdiffs, descriptor.chain_fdiffs);
            }
        }
    }
});
