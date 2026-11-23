//! What the payloads of a frame say of it, and the Dependency Descriptor's frame ids
//! (webrtc-encoded-transform 4.2, 4.3).

use super::*;
use rtp::codec::dependency_descriptor::{
    DecodeTargetIndication, DependencyDescriptorWriter, FrameDependencyStructure,
    FrameDependencyTemplate, RenderResolution,
};

/// A big-endian bit writer with exp-Golomb codes, to build the bitstream headers.
#[derive(Default)]
struct Bits {
    bytes: Vec<u8>,
    len: usize,
}

impl Bits {
    fn bit(&mut self, bit: u32) -> &mut Self {
        if self.len % 8 == 0 {
            self.bytes.push(0);
        }
        if bit != 0 {
            *self.bytes.last_mut().unwrap() |= 0x80 >> (self.len % 8);
        }
        self.len += 1;
        self
    }
    fn bits(&mut self, n: u32, value: u32) -> &mut Self {
        for i in (0..n).rev() {
            self.bit((value >> i) & 1);
        }
        self
    }
    fn ue(&mut self, value: u32) -> &mut Self {
        let coded = value + 1;
        let width = 32 - coded.leading_zeros();
        self.bits(width - 1, 0).bits(width, coded)
    }
    fn done(&mut self) -> Vec<u8> {
        // rbsp_trailing_bits
        self.bit(1);
        std::mem::take(&mut self.bytes)
    }
}

/// An H.264 SPS RBSP (after the NAL header) of `profile` for a frame of `mbs_w` x
/// `map_units_h` macroblocks / map units, with an optional cropping rectangle.
fn sps(
    profile: u32,
    mbs_w: u32,
    map_units_h: u32,
    frame_mbs_only: bool,
    crop: [u32; 4],
) -> Vec<u8> {
    let mut b = Bits::default();
    b.bits(8, profile).bits(8, 0).bits(8, 40).ue(0);
    if profile == 100 {
        b.ue(1).ue(0).ue(0).bit(0).bit(0); // 4:2:0, 8 bit, no scaling matrices
    }
    b.ue(0); // log2_max_frame_num_minus4
    b.ue(0).ue(2); // pic_order_cnt_type 0, log2_max_pic_order_cnt_lsb_minus4
    b.ue(4).bit(0); // max_num_ref_frames, gaps
    b.ue(mbs_w - 1).ue(map_units_h - 1);
    b.bit(u32::from(frame_mbs_only));
    if !frame_mbs_only {
        b.bit(0);
    }
    b.bit(1); // direct_8x8_inference_flag
    if crop == [0; 4] {
        b.bit(0);
    } else {
        b.bit(1).ue(crop[0]).ue(crop[1]).ue(crop[2]).ue(crop[3]);
    }
    b.bit(0); // vui_parameters_present_flag
    b.done()
}

/// ITU-T H.264 7.3.2.1.1 with 7.4.2.1.1: 1920x1080 High profile is 120x68 macroblocks
/// cropped by 4 chroma rows (8 luma rows) at the bottom; Baseline 640x480 uncropped; an
/// interlaced 720x576 counts map units in field pairs.
#[test]
fn the_sequence_parameter_set_gives_the_cropped_frame_size() {
    assert_eq!(
        h264_sps_size(&sps(100, 120, 68, true, [0, 0, 0, 4])),
        Some((1920, 1080))
    );
    assert_eq!(
        h264_sps_size(&sps(66, 40, 30, true, [0; 4])),
        Some((640, 480))
    );
    assert_eq!(
        h264_sps_size(&sps(77, 45, 18, false, [0; 4])),
        Some((720, 576))
    );
    assert_eq!(h264_sps_size(&[0x42]), None, "truncated");
}

/// An emulation prevention byte (0x000003) is not part of the RBSP.
#[test]
fn emulation_prevention_bytes_are_removed_before_the_sps_is_read() {
    let raw = sps(66, 40, 30, true, [0; 4]);
    // profile 66, constraint flags 0, level 0 would read 0x42 0x00 0x00: stuffed on the wire.
    let mut stuffed = raw.clone();
    stuffed[2] = 0;
    let unstuffed_size = h264_sps_size(&stuffed);
    let mut on_the_wire = stuffed[..3].to_vec();
    on_the_wire.push(0x03);
    on_the_wire.extend_from_slice(&stuffed[3..]);
    assert_eq!(h264_sps_size(&on_the_wire), unstuffed_size);
    assert_eq!(unstuffed_size, Some((640, 480)));
}

/// The H.264 payloads of a frame: a STAP-A with SPS, PPS and an IDR slice is a key frame of
/// the SPS's size; an FU-A whose first fragment is a non-IDR slice a delta frame.
#[test]
fn h264_key_and_delta_frames_are_told_apart_by_their_slices() {
    let mut sps_nal = vec![0x67];
    sps_nal.extend(sps(66, 80, 45, true, [0; 4]));
    let pps_nal = vec![0x68, 0xce, 0x38, 0x80];
    let idr = vec![0x65, 0x88, 0x84, 0x00];
    let mut stap = vec![0x78];
    for nal in [&sps_nal, &pps_nal, &idr] {
        stap.extend((nal.len() as u16).to_be_bytes());
        stap.extend(nal.iter());
    }
    let key = inspect_video_payloads("video/H264", &[&Bytes::from(stap)]);
    assert_eq!(key.key_frame, Some(true));
    assert_eq!(key.size, Some((1280, 720)));
    assert_eq!((key.spatial_id, key.temporal_id), (Some(0), Some(0)));

    // FU indicator (NRI 3, type 28), FU header S=1 type 1; then a middle fragment.
    let first = Bytes::from_static(&[0x7c, 0x81, 0x9a, 0x00]);
    let middle = Bytes::from_static(&[0x7c, 0x01, 0x11, 0x22]);
    let delta = inspect_video_payloads("video/H264", &[&first, &middle]);
    assert_eq!(delta.key_frame, Some(false));
    assert_eq!(delta.size, None);
}

/// RFC 7741 / RFC 6386 9.1: the frame tag's P bit; a key frame's start code and 14-bit sizes;
/// the payload descriptor's TID.
#[test]
fn vp8_key_frames_give_their_size_and_the_descriptor_its_temporal_layer() {
    // X=1, S=1, PID=0; extension: T=1; TID=2 (bits 7-6 of the TL0 / TID byte).
    let mut key = vec![0x90, 0x20, 0x80];
    // Frame tag: key frame (P=0), version 0, show_frame, partition size; start code; 640 x 360.
    key.extend([0x10, 0x02, 0x00, 0x9d, 0x01, 0x2a]);
    key.extend(640u16.to_le_bytes());
    key.extend(360u16.to_le_bytes());
    key.extend([0u8; 8]);
    let info = inspect_video_payloads("video/VP8", &[&Bytes::from(key)]);
    assert_eq!(info.key_frame, Some(true));
    assert_eq!(info.size, Some((640, 360)));
    assert_eq!(info.temporal_id, Some(2));

    let delta = Bytes::from_static(&[0x10, 0x11, 0x02, 0x00, 0x00, 0x00]);
    let info = inspect_video_payloads("video/VP8", &[&delta]);
    assert_eq!(info.key_frame, Some(false));
    assert_eq!(info.size, None);
    assert_eq!(info.temporal_id, Some(0));
}

/// RFC 9628: the descriptor's P bit, SID / TID, and the scalability structure's resolution of
/// the frame's spatial layer.
#[test]
fn vp9_frames_read_type_layers_and_size_from_the_descriptor() {
    // I=0 P=0 L=1 F=0 B=1 E=1 V=1 Z=0; layer byte TID=1 U=0 SID=1 D=0; TL0PICIDX;
    // SS: N_S=1 (2 layers) Y=1 G=0; 320x180, 640x360.
    let payload = Bytes::from(vec![
        0x2e, 0x22, 0x00, 0x30, 0x01, 0x40, 0x00, 0xb4, 0x02, 0x80, 0x01, 0x68, 0xaa,
    ]);
    let info = inspect_video_payloads("video/VP9", &[&payload]);
    assert_eq!(info.key_frame, Some(true));
    assert_eq!((info.spatial_id, info.temporal_id), (Some(1), Some(1)));
    assert_eq!(info.size, Some((640, 360)));

    // P=1, B=1, E=1, no layer indices.
    let delta = Bytes::from_static(&[0x4c, 0xaa]);
    let info = inspect_video_payloads("video/VP9", &[&delta]);
    assert_eq!(info.key_frame, Some(false));
    assert_eq!((info.spatial_id, info.temporal_id), (Some(0), Some(0)));
}

/// An AV1 sequence header OBU payload (AV1 5.5.1), reduced still picture header off, no
/// timing info, one operating point, for `width` x `height`.
fn av1_sequence_header(width: u32, height: u32) -> Vec<u8> {
    let mut b = Bits::default();
    b.bits(3, 0).bit(0).bit(0); // profile, still_picture, reduced_still_picture_header
    b.bit(0).bit(0); // timing_info_present_flag, initial_display_delay_present_flag
    b.bits(5, 0).bits(12, 0).bits(5, 8).bit(0); // 1 operating point, idc, level 8 + tier
    b.bits(4, 15).bits(4, 15); // 16-bit sizes
    b.bits(16, width - 1).bits(16, height - 1);
    b.bytes.clone()
}

/// The AV1 RTP specification: N begins a coded video sequence (a key frame); the OBU
/// extension header gives the layer; the sequence header the size.
#[test]
fn av1_frames_read_the_new_sequence_bit_layers_and_sequence_header() {
    let sequence_header = av1_sequence_header(1280, 720);
    // Aggregation header: W=2, N=1. Element 1 (length-prefixed): sequence header OBU without
    // obu_size. Element 2 (the last, no length): a frame OBU with an extension header
    // (temporal_id 1, spatial_id 2).
    let mut payload = vec![0x28];
    payload.push(1 + sequence_header.len() as u8);
    payload.push(0x08); // OBU_SEQUENCE_HEADER
    payload.extend(&sequence_header);
    payload.extend([0x34, 0x30, 0xaa, 0xbb]); // OBU_FRAME with extension: tid 1, sid 2
    let info = inspect_video_payloads("video/AV1", &[&Bytes::from(payload)]);
    assert_eq!(info.key_frame, Some(true));
    assert_eq!(info.size, Some((1280, 720)));
    assert_eq!((info.spatial_id, info.temporal_id), (Some(2), Some(1)));

    // N=0, one OBU (W=1) without extension.
    let delta = Bytes::from_static(&[0x10, 0x30, 0xaa]);
    let info = inspect_video_payloads("video/AV1", &[&delta]);
    assert_eq!(info.key_frame, Some(false));
    assert_eq!((info.spatial_id, info.temporal_id), (Some(0), Some(0)));
}

fn l1t3() -> FrameDependencyStructure {
    let template = |temporal_id, fdiffs: &[u16], chain: u8, dtis: &str| FrameDependencyTemplate {
        spatial_id: 0,
        temporal_id,
        dtis: DecodeTargetIndication::from_symbols(dtis).unwrap(),
        fdiffs: fdiffs.to_vec(),
        chain_fdiffs: vec![chain],
    };
    FrameDependencyStructure {
        template_id_offset: 0,
        num_decode_targets: 3,
        num_chains: 1,
        decode_target_protected_by: vec![0, 0, 0],
        resolutions: vec![RenderResolution {
            width: 640,
            height: 360,
        }],
        templates: vec![
            template(0, &[], 0, "SSS"),
            template(0, &[4], 4, "SSS"),
            template(1, &[2], 2, "SD-"),
            template(2, &[1], 1, "D--"),
            template(2, &[1], 3, "D--"),
        ],
    }
}

fn header(seq: u16, timestamp: u32) -> rtp::Header {
    rtp::Header {
        version: 2,
        ssrc: 7,
        sequence_number: seq,
        timestamp,
        ..Default::default()
    }
}

/// 4.2.1: `frameId` increases in decode order with the descriptor's `frame_number` as its
/// lower 16 bits, across the wrap; `dependencies` are the frame ids the frame differences
/// name; the structure's resolution and the template's layers come with them; a frame whose
/// structure was lost (nothing read yet) is not described.
#[test]
fn dependency_descriptor_frame_numbers_become_increasing_frame_ids() {
    let now = Instant::now();
    let structure = l1t3();
    let mut writer = DependencyDescriptorWriter::new(structure.clone(), 65533).unwrap();
    let mut records = FrameRecords::default();
    // Decode order: key (T0), T2, T1, T2, T0 — numbers 65533, 65534, 65535, 0, 1.
    let frames = [(0, 0), (3, 2), (2, 1), (4, 2), (1, 0)];
    let mut ids = Vec::new();
    for (n, (template, _)) in frames.iter().enumerate() {
        let frame = writer
            .next_frame(&structure.templates[*template], n == 0)
            .unwrap();
        let number = frame.frame_number();
        // Two packets per frame.
        for part in 0..2 {
            let seq = (n * 2 + part) as u16;
            records.record(
                now,
                &header(seq, n as u32 * 3000),
                (None, None),
                Some(&frame.packet(part == 0, part == 1).unwrap()),
            );
        }
        let described = records
            .described_frame(7, number)
            .expect("described")
            .clone();
        assert_eq!(described.frame_number, number);
        assert_eq!(described.frame_id & 0xffff, u64::from(number));
        assert_eq!(described.temporal_id, frames[n].1);
        assert_eq!(described.resolution, Some((640, 360)));
        assert_eq!(described.structure_attached, n == 0);
        ids.push(described);
    }
    let frame_ids: Vec<u64> = ids.iter().map(|d| d.frame_id).collect();
    assert_eq!(frame_ids, vec![65533, 65534, 65535, 65536, 65537]);
    assert!(
        ids[0].dependencies.is_empty(),
        "the key frame refers to none"
    );
    assert_eq!(ids[1].dependencies, vec![65533], "T2: one back");
    assert_eq!(ids[2].dependencies, vec![65533], "T1: two back");
    assert_eq!(
        ids[3].dependencies,
        vec![65535],
        "T2 after the wrap: one back"
    );
    assert_eq!(ids[4].dependencies, vec![65533], "T0: four back");

    // Another stream's descriptor without its structure says nothing.
    let lone = writer.next_frame(&structure.templates[3], false).unwrap();
    let mut other = header(100, 0);
    other.ssrc = 8;
    records.record(
        now,
        &other,
        (None, None),
        Some(&lone.packet(true, true).unwrap()),
    );
    assert_eq!(records.described_frame(8, lone.frame_number()), None);
}

/// 4.1.1 `receiveTime`: the arrival of the frame's last packet; `captureTime` and the offset
/// as the first packet that had them.
#[test]
fn a_frames_receive_time_is_its_last_packets_arrival() {
    let start = Instant::now();
    let mut records = FrameRecords::default();
    records.record(start, &header(1, 900), (Some(1000.0), Some(-2.5)), None);
    records.record(
        start + std::time::Duration::from_millis(7),
        &header(2, 900),
        (None, None),
        None,
    );
    records.record(
        start + std::time::Duration::from_millis(9),
        &header(3, 1800),
        (None, None),
        None,
    );
    let common = records.common(&header(1, 900), "video/VP8".to_owned());
    assert_eq!(
        common.receive_time,
        Some(start + std::time::Duration::from_millis(7))
    );
    assert_eq!(common.capture_time, Some(1000.0));
    assert_eq!(common.sender_capture_time_offset, Some(-2.5));
    assert_eq!(common.rtp_timestamp, 900);
    assert_eq!(common.synchronization_source, 7);
    assert_eq!(
        records.common(&header(9, 5), String::new()).receive_time,
        None
    );
}
