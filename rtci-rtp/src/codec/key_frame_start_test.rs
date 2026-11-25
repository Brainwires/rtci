//! `Depacketizer::is_key_frame_start` and `has_key_frames`: which payload is the first packet
//! of a key frame, by each payload format's own rule (RFC 7741 section 4.3, RFC 9628 section
//! 4.2, the AV1 RTP specification section 4.4, RFC 6184 with ITU-T H.264, RFC 7798 with ITU-T
//! H.265), and which formats have key frames at all.

use bytes::Bytes;

use crate::codec::av1::Av1Depacketizer;
use crate::codec::h264::H264Packet;
use crate::codec::h265::H265Packet;
use crate::codec::opus::OpusPacket;
use crate::codec::vp8::Vp8Packet;
use crate::codec::vp9::Vp9Packet;
use crate::packetizer::Depacketizer;

fn key<T: Depacketizer>(depacketizer: &T, payload: &[u8]) -> bool {
    depacketizer.is_key_frame_start(&Bytes::copy_from_slice(payload))
}

/// VP8: the first packet of a frame (S=1, PID=0) whose payload header, behind the descriptor
/// whatever its length, has P=0.
#[test]
fn vp8_key_frame_start_is_the_first_packet_of_a_frame_with_p_clear() {
    let d = Vp8Packet::default();
    assert!(d.has_key_frames());
    assert!(key(&d, &[0x10, 0x00, 0xAA]), "S=1, PID=0, P=0");
    assert!(!key(&d, &[0x10, 0x01, 0xAA]), "P=1: an interframe");
    assert!(!key(&d, &[0x00, 0x00, 0xAA]), "S=0: not the first packet");
    assert!(!key(&d, &[0x11, 0x00, 0xAA]), "a later partition");
    // X=1 with I (15-bit picture ID), L, T and K: descriptor of 6 octets.
    assert!(key(&d, &[0x90, 0xF0, 0x81, 0x02, 0x03, 0x04, 0x00]));
    assert!(!key(&d, &[0x90, 0xF0, 0x81, 0x02, 0x03, 0x04, 0x01]));
    // X=1 with I alone, a 7-bit picture ID: 3 octets.
    assert!(key(&d, &[0x90, 0x80, 0x05, 0x00]));
    assert!(!key(&d, &[0x90, 0x80, 0x05, 0x01]));
    assert!(!key(&d, &[0x90, 0x80, 0x05]), "no payload header");
    assert!(!key(&d, &[0x10]), "no payload header");
    assert!(!key(&d, &[]));
}

/// VP9: the first packet (B=1) of a base-layer frame with P=0.
#[test]
fn vp9_key_frame_start_is_the_start_of_a_base_layer_frame_with_p_clear() {
    let d = Vp9Packet::default();
    assert!(d.has_key_frames());
    assert!(key(&d, &[0x08, 0xAA]), "B=1, P=0");
    assert!(!key(&d, &[0x48, 0xAA]), "P=1");
    assert!(!key(&d, &[0x00, 0xAA]), "B=0: a continuation");
    // I=1 (7-bit picture ID), L=1: the layer octet is the third.
    assert!(key(&d, &[0xA8, 0x05, 0x00, 0x00, 0xAA]), "SID=0");
    assert!(!key(&d, &[0xA8, 0x05, 0x02, 0x00, 0xAA]), "SID=1, P=0");
    assert!(!key(&d, &[0xA8, 0x05, 0x03, 0x00, 0xAA]), "SID=1, D=1");
    // A 15-bit picture ID moves the layer octet on by one.
    assert!(key(&d, &[0xA8, 0x85, 0x05, 0x00, 0x00, 0xAA]));
    assert!(!key(&d, &[0xA8, 0x85, 0x05, 0x02, 0x00, 0xAA]));
    assert!(!key(&d, &[]));
}

/// AV1: the N bit of the aggregation header, on a packet that starts a temporal unit.
#[test]
fn av1_key_frame_start_is_the_n_bit() {
    let d = Av1Depacketizer::new();
    assert!(d.has_key_frames());
    // W=1, one OBU element without a length: a sequence header (type 1).
    assert!(key(&d, &[0x18, 0x08, 0x00]), "N=1");
    assert!(!key(&d, &[0x10, 0x08, 0x00]), "N=0");
    assert!(!key(&d, &[0x98, 0x08, 0x00]), "Z=1: a continuation");
    assert!(!key(&d, &[]));
}

/// H.264: the first slice of an IDR picture, alone, as the first fragment of an FU-A, or in
/// an STAP-A behind parameter sets.
#[test]
fn h264_key_frame_start_is_the_first_slice_of_an_idr_picture() {
    let d = H264Packet::default();
    assert!(d.has_key_frames());
    assert!(key(&d, &[0x65, 0x88, 0x80]), "IDR, first_mb_in_slice 0");
    assert!(
        !key(&d, &[0x65, 0x08, 0x80]),
        "a later slice of the picture"
    );
    assert!(!key(&d, &[0x41, 0x9A, 0x80]), "a non-IDR slice");
    assert!(!key(&d, &[0x67, 0x42, 0x00]), "a parameter set alone");
    // FU-A: indicator (type 28), header (S, type 5), then the slice.
    assert!(key(&d, &[0x7C, 0x85, 0x88, 0x80]));
    assert!(!key(&d, &[0x7C, 0x05, 0x88, 0x80]), "S=0: a later fragment");
    assert!(
        !key(&d, &[0x7C, 0x45, 0x88, 0x80]),
        "E=1: the last fragment"
    );
    assert!(!key(&d, &[0x7C, 0x81, 0x88, 0x80]), "a fragmented non-IDR");
    // STAP-A: SPS (2 octets), PPS (2 octets), IDR slice.
    assert!(key(
        &d,
        &[
            0x78, 0x00, 0x02, 0x67, 0x42, 0x00, 0x02, 0x68, 0xCE, 0x00, 0x03, 0x65, 0x88, 0x80
        ]
    ));
    // The same with a non-IDR slice.
    assert!(!key(
        &d,
        &[
            0x78, 0x00, 0x02, 0x67, 0x42, 0x00, 0x02, 0x68, 0xCE, 0x00, 0x03, 0x41, 0x9A, 0x80
        ]
    ));
    // A non-IDR slice before the IDR one: not the start of the picture's access unit.
    assert!(!key(
        &d,
        &[0x78, 0x00, 0x02, 0x41, 0x9A, 0x00, 0x03, 0x65, 0x88, 0x80]
    ));
    // A length that runs past the packet.
    assert!(!key(&d, &[0x78, 0x00, 0x09, 0x65, 0x88]));
    assert!(!key(&d, &[]));
}

/// H.265: the first slice segment of an IRAP picture (types 16 to 21), alone, as the first
/// fragment of a fragmentation unit, or in an aggregation packet behind parameter sets.
#[test]
fn h265_key_frame_start_is_the_first_slice_segment_of_an_irap_picture() {
    let d = H265Packet::default();
    assert!(d.has_key_frames());
    assert!(key(&d, &[0x26, 0x01, 0x80]), "IDR_W_RADL, first segment");
    assert!(key(&d, &[0x2A, 0x01, 0x80]), "CRA");
    assert!(!key(&d, &[0x26, 0x01, 0x00]), "a later slice segment");
    assert!(!key(&d, &[0x02, 0x01, 0x80]), "a trailing picture");
    assert!(!key(&d, &[0x42, 0x01, 0x01]), "a parameter set alone");
    // FU (type 49): payload header, FU header (S, type 19), the slice.
    assert!(key(&d, &[0x62, 0x01, 0x93, 0x80]));
    assert!(!key(&d, &[0x62, 0x01, 0x13, 0x80]), "S=0");
    assert!(
        !key(&d, &[0x62, 0x01, 0x81, 0x80]),
        "a fragmented trailing picture"
    );
    // AP (type 48): VPS (3 octets), SPS (3 octets), IDR slice.
    assert!(key(
        &d,
        &[
            0x60, 0x01, 0x00, 0x03, 0x40, 0x01, 0x0C, 0x00, 0x03, 0x42, 0x01, 0x01, 0x00, 0x03,
            0x26, 0x01, 0x80
        ]
    ));
    assert!(!key(
        &d,
        &[
            0x60, 0x01, 0x00, 0x03, 0x40, 0x01, 0x0C, 0x00, 0x03, 0x02, 0x01, 0x80
        ]
    ));
    // With DONL (sprop-max-don-diff > 0): two more octets before the slice.
    let mut with_donl = H265Packet::default();
    with_donl.with_donl(true);
    assert!(key(&with_donl, &[0x26, 0x01, 0x00, 0x07, 0x80]));
    assert!(!key(&with_donl, &[0x26, 0x01, 0x80, 0x07, 0x00]));
    assert!(key(&with_donl, &[0x62, 0x01, 0x93, 0x00, 0x07, 0x80]));
    assert!(!key(&d, &[0x26]));
}

/// A format without key frames says so, and no payload of it starts one.
#[test]
fn a_format_without_key_frames_never_names_one() {
    let d = OpusPacket;
    assert!(!d.has_key_frames());
    assert!(!key(&d, &[0x00, 0x00, 0x00]));
    assert!(!key(&d, &[0x10, 0x00, 0x00]));
}
