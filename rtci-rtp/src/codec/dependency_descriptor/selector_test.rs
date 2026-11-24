//! Forwarding by decode target (AV1 RTP specification A.5 to A.7), with the scenarios of
//! A.10.1.

use super::dependency_descriptor_test::template;
use super::*;

/// Reads `descriptor` as a receiver would and returns what the selector decides.
fn feed(
    reader: &mut DependencyDescriptorReader,
    selector: &mut DecodeTargetSelector,
    structure: &FrameDependencyStructure,
    descriptor: &DependencyDescriptor,
) -> bool {
    let bytes = descriptor.marshal(structure).unwrap();
    let read = reader.read(&bytes).unwrap().unwrap();
    selector.forward(&read, reader)
}

fn frame(
    structure: &FrameDependencyStructure,
    frame_number: u16,
    spatial_id: u8,
    fdiffs: &[u16],
    chain_fdiffs: &[u8],
    dtis: &str,
) -> DependencyDescriptor {
    let index = structure
        .templates
        .iter()
        .position(|t| t.spatial_id == spatial_id)
        .unwrap();
    let mut descriptor =
        DependencyDescriptor::from_template(structure, index, frame_number).unwrap();
    descriptor.fdiffs = fdiffs.to_vec();
    descriptor.chain_fdiffs = chain_fdiffs.to_vec();
    descriptor.dtis = DecodeTargetIndication::from_symbols(dtis).unwrap();
    descriptor
}

/// A.10.1.2: two spatial layers, DT0 = S0 protected by Chain0, DT1 = S0 and S1 protected by
/// Chain1.
fn l2t1_structure() -> FrameDependencyStructure {
    FrameDependencyStructure {
        template_id_offset: 0,
        num_decode_targets: 2,
        num_chains: 2,
        decode_target_protected_by: vec![0, 1],
        resolutions: vec![],
        templates: vec![
            template(0, 0, &[], &[0, 0], "SS"),
            template(0, 0, &[2], &[2, 1], "SR"),
            template(1, 0, &[1], &[1, 1], "-S"),
            template(1, 0, &[1, 2], &[1, 1], "-R"),
        ],
    }
}

/// The start of the stream for a receiver of S0: the key picture (frames 1 and 2), then
/// frames up to 104 in steady state. Returns the frame numbers forwarded.
fn l2t1_up_to_104(
    reader: &mut DependencyDescriptorReader,
    selector: &mut DecodeTargetSelector,
    structure: &FrameDependencyStructure,
) -> Vec<u16> {
    let mut forwarded = vec![];
    let mut key = DependencyDescriptor::from_template(structure, 0, 1).unwrap();
    key.attached_structure = Some(structure.clone());
    let mut stream = vec![
        key,
        DependencyDescriptor::from_template(structure, 2, 2).unwrap(),
    ];
    for frame_number in 3..=104u16 {
        let index = if frame_number % 2 == 1 { 1 } else { 3 };
        stream.push(DependencyDescriptor::from_template(structure, index, frame_number).unwrap());
    }
    for descriptor in &stream {
        if feed(reader, selector, structure, descriptor) {
            forwarded.push(descriptor.frame_number);
        }
    }
    forwarded
}

/// A.10.1.2, "Spatial Upswitch", first way: the sender makes frame 106 independent of earlier
/// S1 frames, sets a Switch indication for DT1 on frame 105 and resets Chain1 there. A
/// receiver that had S0 only is switched to DT1 at frame 105 (A.7: "beginning with a
/// decodable frame containing a Switch indication").
#[test]
fn the_upswitch_example_switches_at_the_frame_with_the_switch_indication() {
    let structure = l2t1_structure();
    let mut reader = DependencyDescriptorReader::new();
    let mut selector = DecodeTargetSelector::new(0, 0);
    let forwarded = l2t1_up_to_104(&mut reader, &mut selector, &structure);
    // S0 only: the odd frame numbers.
    assert_eq!(forwarded, (1..=103).step_by(2).collect::<Vec<u16>>());
    assert_eq!(selector.current_decode_target(), Some(0));

    selector.set_target(1, 0);
    assert!(selector.switch_pending(&reader));
    // frame_number, layer, Indication for DT1, Previous Frame in Chain1, Frame dependencies:
    // 105 S0 Switch 105 {103}; 106 S1 Required 105 {105}; 107 S0 Required 106 {105};
    // 108 S1 Required 107 {107, 106}.
    let table = [
        frame(&structure, 105, 0, &[2], &[2, 0], "SS"),
        frame(&structure, 106, 1, &[1], &[1, 1], "-R"),
        frame(&structure, 107, 0, &[2], &[2, 1], "SR"),
        frame(&structure, 108, 1, &[1, 2], &[1, 1], "-R"),
    ];
    let decisions: Vec<bool> = table
        .iter()
        .map(|d| feed(&mut reader, &mut selector, &structure, d))
        .collect();
    assert_eq!(decisions, [true, true, true, true]);
    assert_eq!(selector.current_decode_target(), Some(1));
    assert!(!selector.switch_pending(&reader));
    assert!(selector.chain_intact(&reader));
}

/// A.10.1.2, second way: the Switch indication and the Chain1 reset are on frame 106.
#[test]
fn the_upswitch_example_switches_at_frame_106_the_other_way() {
    let structure = l2t1_structure();
    let mut reader = DependencyDescriptorReader::new();
    let mut selector = DecodeTargetSelector::new(0, 0);
    l2t1_up_to_104(&mut reader, &mut selector, &structure);
    selector.set_target(1, 0);
    // 105 S0 Required 104 {103}; 106 S1 Switch 106 {105}; 107 S0 Required 106 {105};
    // 108 S1 Required 107 {107, 106}.
    let table = [
        frame(&structure, 105, 0, &[2], &[2, 1], "SR"),
        frame(&structure, 106, 1, &[1], &[1, 0], "-S"),
        frame(&structure, 107, 0, &[2], &[2, 1], "SR"),
        frame(&structure, 108, 1, &[1, 2], &[1, 1], "-R"),
    ];
    let mut decodable_targets = vec![];
    for descriptor in &table {
        assert!(feed(&mut reader, &mut selector, &structure, descriptor));
        decodable_targets.push(selector.current_decode_target());
    }
    assert_eq!(decodable_targets, [Some(0), Some(1), Some(1), Some(1)]);
}

/// Without a switch point the receiver stays where it is: S1 frames that depend on S1 frames
/// it was not sent are not forwarded, however long it waits.
#[test]
fn no_switch_happens_without_a_switch_indication_or_an_intact_chain() {
    let structure = l2t1_structure();
    let mut reader = DependencyDescriptorReader::new();
    let mut selector = DecodeTargetSelector::new(0, 0);
    l2t1_up_to_104(&mut reader, &mut selector, &structure);
    selector.set_target(1, 0);
    let mut forwarded = vec![];
    for frame_number in 105..=140u16 {
        let index = if frame_number % 2 == 1 { 1 } else { 3 };
        let descriptor =
            DependencyDescriptor::from_template(&structure, index, frame_number).unwrap();
        if feed(&mut reader, &mut selector, &structure, &descriptor) {
            forwarded.push(frame_number);
        }
    }
    assert_eq!(forwarded, (105..=139).step_by(2).collect::<Vec<u16>>());
    assert_eq!(selector.current_decode_target(), Some(0));
    assert!(selector.switch_pending(&reader));

    // Going down needs no switch point in this structure: S0 frames carry a Switch
    // indication for DT0 and the receiver has all of them.
    let mut reader = DependencyDescriptorReader::new();
    let mut selector = DecodeTargetSelector::new(1, 0);
    let forwarded = l2t1_up_to_104(&mut reader, &mut selector, &structure);
    assert_eq!(forwarded, (1..=104).collect::<Vec<u16>>());
    selector.set_target(0, 0);
    let s0 = DependencyDescriptor::from_template(&structure, 1, 105).unwrap();
    let s1 = DependencyDescriptor::from_template(&structure, 3, 106).unwrap();
    assert!(feed(&mut reader, &mut selector, &structure, &s0));
    assert!(!feed(&mut reader, &mut selector, &structure, &s1));
    assert_eq!(selector.current_decode_target(), Some(0));
}

/// A.10.1.1: the L2T3 structure with four decode targets (DT0 HD 15 fps, DT1 VGA 30 fps, DT2
/// VGA 60 fps, DT3 HD 60 fps) and two chains (Chain0 protects the VGA targets, Chain1 the HD
/// ones).
fn l2t3_structure() -> FrameDependencyStructure {
    FrameDependencyStructure {
        template_id_offset: 0,
        num_decode_targets: 4,
        num_chains: 2,
        decode_target_protected_by: vec![1, 0, 0, 1],
        resolutions: vec![],
        templates: vec![
            template(0, 0, &[], &[0, 0], "SSSS"),
            template(0, 1, &[4], &[4, 3], "-DSR"),
            template(0, 2, &[2], &[2, 1], "--DR"),
            template(1, 0, &[1], &[1, 1], "S--S"),
            template(1, 1, &[4, 1], &[5, 4], "---R"),
            template(1, 2, &[2, 1], &[3, 2], "---D"),
        ],
    }
}

/// A.10.1.1 and A.6: both clients have received F1 and then receive F5, which depends on F1
/// only; F2 was lost. "The DT2 client would track Chain0 ... it is safe to start decoding
/// F5." "The DT3 client would track Chain1 ... the last essential frame is F2. Thus it is not
/// safe": the client waits for F2 and may send a NACK.
#[test]
fn the_chain_example_tells_a_needed_loss_from_a_harmless_one() {
    let structure = l2t3_structure();
    assert_eq!(
        structure.decode_target_layers(),
        [(1, 0), (0, 1), (0, 2), (1, 2)]
    );

    let mut f1 = DependencyDescriptor::from_template(&structure, 0, 1).unwrap();
    f1.attached_structure = Some(structure.clone());
    let f2 = DependencyDescriptor::from_template(&structure, 3, 2).unwrap();
    // F5: "the last frame in Chain0 is F1, and the last frame in Chain1 is F2"; its
    // indications are Not present, Discardable, Switch, Required.
    let f5 = DependencyDescriptor::from_template(&structure, 1, 5).unwrap();
    assert_eq!(
        (f5.referred_frame_number(4), f5.referred_frame_number(3)),
        (1, 2)
    );

    // The DT2 client: VGA at 60 fps.
    let mut reader = DependencyDescriptorReader::new();
    let mut vga = DecodeTargetSelector::new(0, 2);
    assert!(feed(&mut reader, &mut vga, &structure, &f1));
    assert_eq!(vga.current_decode_target(), Some(2));
    assert!(feed(&mut reader, &mut vga, &structure, &f5));
    assert!(vga.chain_intact(&reader), "F2 is not in Chain0");

    // The DT3 client: HD at 60 fps.
    let mut reader = DependencyDescriptorReader::new();
    let mut hd = DecodeTargetSelector::new(1, 2);
    assert!(feed(&mut reader, &mut hd, &structure, &f1));
    assert_eq!(hd.current_decode_target(), Some(3));
    assert!(hd.chain_intact(&reader));
    assert!(feed(&mut reader, &mut hd, &structure, &f5));
    assert!(
        !hd.chain_intact(&reader),
        "F2, a frame of Chain1, is missing"
    );
    // The retransmitted F2 arrives: the chain is whole again.
    assert!(feed(&mut reader, &mut hd, &structure, &f2));
    assert!(hd.chain_intact(&reader));

    // A.5: a chain that protects no active decode target is ignored. With the HD targets
    // inactive, the same loss is nobody's problem.
    let mut reader = DependencyDescriptorReader::new();
    let mut hd = DecodeTargetSelector::new(1, 2);
    let mut key = f1.clone();
    key.active_decode_targets_bitmask = Some(0b0110);
    assert!(feed(&mut reader, &mut hd, &structure, &key));
    // The best active target within HD at 60 fps is VGA at 60 fps.
    assert_eq!(hd.current_decode_target(), Some(2));
    assert!(feed(&mut reader, &mut hd, &structure, &f5));
    assert!(hd.chain_intact(&reader));
}

/// A frame's packets all get the frame's decision, and so does a repeated packet; nothing is
/// forwarded before a structure is known.
#[test]
fn a_decision_is_per_frame() {
    let structure = l2t1_structure();
    let mut reader = DependencyDescriptorReader::new();
    let mut selector = DecodeTargetSelector::new(0, 0);

    // A delta frame before any structure: the reader cannot interpret it.
    let delta = DependencyDescriptor::from_template(&structure, 1, 9).unwrap();
    assert_eq!(
        reader.read(&delta.marshal(&structure).unwrap()).unwrap(),
        None
    );
    assert!(selector.switch_pending(&reader));

    let mut key = DependencyDescriptor::from_template(&structure, 0, 10).unwrap();
    key.attached_structure = Some(structure.clone());
    key.start_of_frame = true;
    assert!(feed(&mut reader, &mut selector, &structure, &key));
    let mut rest = DependencyDescriptor::from_template(&structure, 0, 10).unwrap();
    rest.end_of_frame = true;
    assert!(feed(&mut reader, &mut selector, &structure, &rest));
    // The S1 frame of the key picture: not for a receiver of S0, on both its packets.
    let s1 = DependencyDescriptor::from_template(&structure, 2, 11).unwrap();
    assert!(!feed(&mut reader, &mut selector, &structure, &s1));
    assert!(!feed(&mut reader, &mut selector, &structure, &s1));
    // The key frame's first packet again (a retransmission): the same answer, and the
    // selector does not start over.
    assert!(feed(&mut reader, &mut selector, &structure, &key));
    assert_eq!(selector.current_decode_target(), Some(0));
}
