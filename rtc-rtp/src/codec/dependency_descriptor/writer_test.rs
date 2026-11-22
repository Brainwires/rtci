//! The send side of the Dependency Descriptor (AV1 RTP specification A.4, A.8.3).

use super::dependency_descriptor_test::{l1t3_structure, l3t3_structure, template};
use super::*;

/// The frames of the L1T3 example in decode order: the key frame, then the pattern T2, T1,
/// T2, T0 with the templates of A.10.2.1.
fn l1t3_frame(n: usize) -> FrameDependencyTemplate {
    let templates = l1t3_structure().templates;
    match n {
        0 => templates[0].clone(),
        _ => templates[[1, 3, 2, 4][n % 4]].clone(),
    }
}

/// A.8.3: `start_of_frame` is 1 on the packet that begins a frame and 0 on the others,
/// `end_of_frame` 1 on the frame's final packet and 0 on the others; all packets of a frame
/// have the same `frame_number` and the same `frame_dependency_template_id`.
#[test]
fn every_packet_of_a_frame_has_its_number_template_and_position() -> Result<()> {
    let mut writer = DependencyDescriptorWriter::new(l1t3_structure(), 500)?;
    let mut reader = DependencyDescriptorReader::new();
    let frame = writer.next_frame(&l1t3_frame(0), true)?;
    assert_eq!(frame.frame_number(), 500);

    let packets = 4;
    for i in 0..packets {
        let bytes = frame.packet(i == 0, i == packets - 1)?;
        let read = reader.read(&bytes)?.unwrap();
        assert_eq!(read.start_of_frame, i == 0);
        assert_eq!(read.end_of_frame, i == packets - 1);
        assert_eq!(read.frame_number, 500);
        assert_eq!(read.template_id, 0);
        // "template_dependency_structure_present_flag MUST be set to 1 for the first packet of
        // a coded video sequence, and MUST be set to 0 otherwise."
        assert_eq!(read.attached_structure.is_some(), i == 0);
        assert_eq!(bytes.len(), if i == 0 { 16 } else { 3 });
    }

    // A one-packet frame is both.
    let frame = writer.next_frame(&l1t3_frame(1), false)?;
    let read = reader.read(&frame.packet(true, true)?)?.unwrap();
    assert!(read.start_of_frame && read.end_of_frame);
    assert_eq!(read.attached_structure, None);
    Ok(())
}

/// A.8.3: `frame_number` "increases strictly monotonically in decode order", "MAY start on a
/// random number, and MUST wrap after reaching the maximum value".
#[test]
fn frame_numbers_count_up_from_the_start_and_wrap() -> Result<()> {
    let mut writer = DependencyDescriptorWriter::new(l1t3_structure(), 65534)?;
    let numbers: Vec<u16> = (0..4)
        .map(|n| {
            writer
                .next_frame(&l1t3_frame(n), n == 0)
                .unwrap()
                .frame_number()
        })
        .collect();
    assert_eq!(numbers, [65534, 65535, 0, 1]);
    assert_eq!(writer.next_frame_number(), 2);
    Ok(())
}

/// A frame that follows a template takes three bytes, whatever the template; the receiver
/// reads back what the encoder said.
#[test]
fn frames_that_follow_the_structure_take_three_bytes() -> Result<()> {
    let mut writer = DependencyDescriptorWriter::new(l1t3_structure(), 0)?;
    let mut reader = DependencyDescriptorReader::new();
    for n in 0..24 {
        let frame = l1t3_frame(n);
        let descriptor = writer.next_frame(&frame, n == 0)?;
        let bytes = descriptor.packet(true, true)?;
        if n > 0 {
            assert_eq!(bytes.len(), 3, "frame {n}");
        }
        let read = reader.read(&bytes)?.unwrap();
        assert_eq!(
            (read.spatial_id, read.temporal_id),
            (frame.spatial_id, frame.temporal_id)
        );
        assert_eq!(read.dtis, frame.dtis, "frame {n}");
        assert_eq!(read.fdiffs, frame.fdiffs, "frame {n}");
        assert_eq!(read.chain_fdiffs, frame.chain_fdiffs, "frame {n}");
    }
    Ok(())
}

/// A frame the templates do not describe is written with the template of its layer that
/// needs the least correcting, and read back exactly.
#[test]
fn a_frame_off_the_pattern_gets_the_cheapest_template_and_custom_fields() -> Result<()> {
    let structure = l1t3_structure();
    let mut writer = DependencyDescriptorWriter::new(structure.clone(), 0)?;
    let mut reader = DependencyDescriptorReader::new();
    reader.read(
        &writer
            .next_frame(&l1t3_frame(0), true)?
            .packet(true, true)?,
    )?;

    // A T2 frame whose chain difference is 3: that is template 4, not template 3.
    let frame = template(0, 2, &[1], &[3], "D--");
    let descriptor = writer.next_frame(&frame, false)?;
    assert_eq!(descriptor.descriptor().template_id, 4);
    assert_eq!(descriptor.packet(true, true)?.len(), 3);

    // A T0 frame two frames after the last one (a frame was skipped): a T0 template with a
    // custom frame difference and chain difference.
    let frame = template(0, 0, &[2], &[2], "SSS");
    let descriptor = writer.next_frame(&frame, false)?;
    assert!(descriptor.descriptor().template_id <= 1);
    let bytes = descriptor.packet(true, true)?;
    // 24 + 5 flags + (2 + 4 + 2) + 8 bits.
    assert_eq!(bytes.len(), 6);
    let read = reader.read(&bytes)?.unwrap();
    assert_eq!(
        (read.fdiffs, read.chain_fdiffs, read.dtis),
        (frame.fdiffs, frame.chain_fdiffs, frame.dtis)
    );

    // A T1 frame that is only discardable for the 30 fps target: custom indications alone.
    let frame = template(0, 1, &[2], &[2], "DD-");
    let descriptor = writer.next_frame(&frame, false)?;
    assert_eq!(descriptor.descriptor().template_id, 2);
    let bytes = descriptor.packet(true, true)?;
    assert_eq!(bytes.len(), 5);
    assert_eq!(reader.read(&bytes)?.unwrap().dtis, frame.dtis);

    // No template has spatial layer 1: the frame cannot be described.
    assert!(
        writer
            .next_frame(&template(1, 0, &[1], &[1], "SSS"), false)
            .is_err()
    );
    // A refused frame takes no frame number.
    assert_eq!(writer.next_frame_number(), 4);
    Ok(())
}

/// A.8.3: the structure goes out on the first packet of a coded video sequence. A stream, or
/// a new structure, cannot begin on any other frame: the receiver would never get it.
#[test]
fn the_structure_goes_out_with_a_coded_video_sequence() -> Result<()> {
    let mut writer = DependencyDescriptorWriter::new(l1t3_structure(), 0)?;
    assert!(writer.next_frame(&l1t3_frame(1), false).is_err());
    assert!(
        writer
            .next_frame(&l1t3_frame(0), true)?
            .starts_coded_video_sequence()
    );
    assert!(
        !writer
            .next_frame(&l1t3_frame(1), false)?
            .starts_coded_video_sequence()
    );

    // Every later key frame carries it again.
    let key = writer.next_frame(&l1t3_frame(0), true)?;
    let read = DependencyDescriptor::unmarshal(&key.packet(true, false)?, None)?.unwrap();
    assert_eq!(read.attached_structure, Some(l1t3_structure()));
    // Its other packets do not.
    let read = DependencyDescriptor::unmarshal(&key.packet(false, true)?, Some(&l1t3_structure()))?
        .unwrap();
    assert_eq!(read.attached_structure, None);
    Ok(())
}

/// A.8.3: a new structure SHOULD use template ids the existing one does not, and one with the
/// same `template_id_offset` MUST be identical.
#[test]
fn a_new_structure_takes_new_template_ids() -> Result<()> {
    let first = l1t3_structure();
    let mut writer = DependencyDescriptorWriter::new(first.clone(), 0)?;
    writer.next_frame(&l1t3_frame(0), true)?;

    // The same offset with other contents is refused; the same structure again is fine.
    assert!(writer.set_structure(l3t3_structure()).is_err());
    assert!(writer.set_structure(first.clone()).is_ok());
    writer.next_frame(&l1t3_frame(0), true)?;

    // The ids after the first structure's five: 5 to 19, no overlap with 0 to 4.
    assert_eq!(first.next_template_id_offset(), 5);
    let second = FrameDependencyStructure {
        template_id_offset: first.next_template_id_offset(),
        ..l3t3_structure()
    };
    writer.set_structure(second.clone())?;
    // The new structure needs a new coded video sequence.
    assert!(writer.next_frame(&second.templates[1], false).is_err());
    let key = writer.next_frame(&second.templates[0], true)?;
    assert_eq!(key.descriptor().template_id, 5);

    // A receiver that missed the new structure cannot mistake its frames for the old one's:
    // their ids are outside the old range.
    let delta = writer.next_frame(&second.templates[5], false)?;
    assert_eq!(delta.descriptor().template_id, 10);
    assert_eq!(
        DependencyDescriptor::unmarshal(&delta.packet(true, true)?, Some(&first))?,
        None
    );
    // Offsets wrap at 64.
    let late = FrameDependencyStructure {
        template_id_offset: 61,
        ..l1t3_structure()
    };
    assert_eq!(late.next_template_id_offset(), 2);
    assert_eq!(late.template_index(1), Some(4));
    assert_eq!(late.template_index(2), None);
    Ok(())
}

/// A.4: "Whenever the set of active Decode targets changes, the sender MUST signal the new
/// set", in a way that survives the loss of a packet: on every packet until it is known to
/// have arrived, or until a key frame makes all targets active again.
#[test]
fn a_change_of_active_decode_targets_is_signalled_until_acknowledged() -> Result<()> {
    let mut writer = DependencyDescriptorWriter::new(l1t3_structure(), 0)?;
    let mut reader = DependencyDescriptorReader::new();
    let mut send = |writer: &mut DependencyDescriptorWriter, n: usize, key: bool| {
        let frame = writer.next_frame(&l1t3_frame(n), key).unwrap();
        (0..2)
            .map(|i| {
                reader
                    .read(&frame.packet(i == 0, i == 1).unwrap())
                    .unwrap()
                    .unwrap()
                    .active_decode_targets_bitmask
            })
            .collect::<Vec<_>>()
    };

    // All active: the structure says so, nothing more is sent.
    assert_eq!(send(&mut writer, 0, true), [None, None]);
    assert_eq!(send(&mut writer, 1, false), [None, None]);

    // The 30 fps target (index 0) goes away.
    writer.set_active_decode_targets(0b110)?;
    assert_eq!(writer.active_decode_targets(), 0b110);
    assert_eq!(send(&mut writer, 2, false), [Some(0b110), Some(0b110)]);
    assert_eq!(send(&mut writer, 3, false), [Some(0b110), Some(0b110)]);
    // A key frame with fewer than all targets active says so next to the structure.
    assert_eq!(send(&mut writer, 0, true), [Some(0b110), Some(0b110)]);

    // Acknowledged: the bitmask is no longer repeated. Setting the same set changes nothing.
    writer.active_decode_targets_acknowledged();
    writer.set_active_decode_targets(0b110)?;
    assert_eq!(send(&mut writer, 1, false), [None, None]);

    // All active again: signalled, and a key frame then says it by itself.
    writer.set_active_decode_targets(0b111)?;
    assert_eq!(send(&mut writer, 2, false), [Some(0b111), Some(0b111)]);
    assert_eq!(send(&mut writer, 0, true), [None, None]);
    assert_eq!(send(&mut writer, 1, false), [None, None]);

    assert!(writer.set_active_decode_targets(0b1000).is_err());
    Ok(())
}
