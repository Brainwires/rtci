//! What each payload format says about frame boundaries and key frames, and the bitstream of a
//! complete frame. Built on the engine's depacketizers (`rtp::codec`).

use bytes::{Bytes, BytesMut};
use rtp::codec::av1::Av1Depacketizer;
use rtp::codec::h264::H264Packet;
use rtp::codec::h265::H265Packet;
use rtp::codec::vp8::Vp8Packet;
use rtp::codec::vp9::Vp9Packet;
use rtp::packetizer::Depacketizer;

use crate::frame::{Codec, CodecHeader};

/// Where a packet sits in its frame, as far as the packet alone says.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PacketPosition {
    /// The packet starts a frame. `None` when the format does not say (H.264, H.265: a frame
    /// starts after a packet of another RTP timestamp).
    pub starts_frame: Option<bool>,
    /// The packet ends a frame.
    pub ends_frame: bool,
    /// The packet carries (part of) a key frame.
    pub keyframe: bool,
    /// The coded size, when the packet carries a key frame header with it.
    pub resolution: Option<(u32, u32)>,
    /// The codec descriptor, read from a packet that starts a frame.
    pub header: CodecHeader,
}

/// Reads a packet's position in its frame. `marker` is the RTP marker bit; a Dependency
/// Descriptor, when the packet has one, is applied by the caller (it overrides the start and
/// end of frame).
pub fn read_position(codec: Codec, marker: bool, payload: &Bytes) -> Option<PacketPosition> {
    if payload.is_empty() {
        return None;
    }
    match codec {
        Codec::Vp8 => read_vp8(marker, payload),
        Codec::Vp9 => read_vp9(payload),
        Codec::Av1 => Some(read_av1(marker, payload)),
        Codec::H264 => Some(PacketPosition {
            starts_frame: None,
            ends_frame: marker,
            keyframe: h264_has_idr(payload),
            ..Default::default()
        }),
        Codec::H265 => Some(PacketPosition {
            starts_frame: None,
            ends_frame: marker,
            keyframe: h265_has_irap(payload),
            ..Default::default()
        }),
    }
}

fn read_vp8(marker: bool, payload: &Bytes) -> Option<PacketPosition> {
    let mut d = Vp8Packet::default();
    let data = d.depacketize(payload).ok()?;
    let starts = d.s == 1 && d.pid == 0;
    let mut position = PacketPosition {
        starts_frame: Some(starts),
        ends_frame: marker,
        ..Default::default()
    };
    if starts {
        // RFC 6386 section 9.1: the frame tag's first bit is 0 for a key frame, whose
        // header carries the start code 9d 01 2a and the 14-bit width and height.
        position.keyframe = data.first().is_some_and(|b| b & 0x01 == 0);
        if position.keyframe && data.len() >= 10 && data[3..6] == [0x9d, 0x01, 0x2a] {
            let w = u32::from(u16::from_le_bytes([data[6], data[7]]) & 0x3fff);
            let h = u32::from(u16::from_le_bytes([data[8], data[9]]) & 0x3fff);
            position.resolution = Some((w, h));
        }
        position.header = CodecHeader::Vp8 {
            picture_id: (d.i == 1).then_some((d.picture_id, d.picture_id_15_bits)),
            tl0_pic_idx: (d.l == 1).then_some(d.tl0_pic_idx),
            temporal_id: (d.t == 1).then_some(d.tid),
            layer_sync: d.y == 1,
        };
    }
    Some(position)
}

fn read_vp9(payload: &Bytes) -> Option<PacketPosition> {
    let mut d = Vp9Packet::default();
    d.depacketize(payload).ok()?;
    let mut position = PacketPosition {
        starts_frame: Some(d.b),
        ends_frame: d.e,
        keyframe: !d.p && (d.sid == 0 || !d.d),
        ..Default::default()
    };
    if d.v && d.y && !d.width.is_empty() {
        let layer = usize::from(d.sid).min(d.width.len() - 1);
        position.resolution = Some((u32::from(d.width[layer]), u32::from(d.height[layer])));
    }
    if d.b {
        let gof = (d.v && d.g).then(|| {
            d.pgtid
                .iter()
                .zip(d.pgpdiff.iter())
                .map(|(t, p)| (*t, p.clone()))
                .collect()
        });
        position.header = CodecHeader::Vp9 {
            picture_id: d.i.then_some((d.picture_id, d.picture_id_15_bits)),
            flexible: d.f,
            inter_picture_predicted: d.p,
            temporal_id: d.l.then_some(d.tid),
            spatial_id: if d.l { d.sid } else { 0 },
            inter_layer_dependency: d.d,
            tl0_pic_idx: (d.l && !d.f).then_some(d.tl0picidx),
            p_diff: d.pdiff.clone(),
            gof,
            end_of_layer_frame: d.e,
        };
    }
    Some(position)
}

fn read_av1(marker: bool, payload: &Bytes) -> PacketPosition {
    let d = Av1Depacketizer::default();
    PacketPosition {
        starts_frame: Some(d.is_partition_head(payload)),
        ends_frame: marker,
        // The AV1 RTP specification 4.4: N "MUST be set to 1 if the packet is the first packet
        // of a coded video sequence".
        keyframe: payload[0] & 0x08 != 0,
        ..Default::default()
    }
}

/// Whether an H.264 RTP payload carries an IDR slice (NAL unit type 5): a single NAL unit,
/// a STAP-A (24) aggregate, or the first fragment of an FU-A (28) (RFC 6184 section 5).
pub fn h264_has_idr(payload: &[u8]) -> bool {
    let Some(&b0) = payload.first() else {
        return false;
    };
    match b0 & 0x1f {
        5 => true,
        24 => {
            let mut i = 1;
            while i + 2 < payload.len() {
                let size = usize::from(u16::from_be_bytes([payload[i], payload[i + 1]]));
                if payload[i + 2] & 0x1f == 5 {
                    return true;
                }
                i += 2 + size;
            }
            false
        }
        28 => payload
            .get(1)
            .is_some_and(|fu| fu & 0x80 != 0 && fu & 0x1f == 5),
        _ => false,
    }
}

/// Whether an H.265 RTP payload carries an IRAP picture's NAL unit (types 16 to 21): a single
/// NAL unit, an aggregation packet (48) or the first fragment of a fragmentation unit (49)
/// (RFC 7798 section 4.4).
pub fn h265_has_irap(payload: &[u8]) -> bool {
    let irap = |t: u8| (16..=21).contains(&t);
    let Some(&b0) = payload.first() else {
        return false;
    };
    match (b0 >> 1) & 0x3f {
        48 => {
            let mut i = 2;
            while i + 2 < payload.len() {
                let size = usize::from(u16::from_be_bytes([payload[i], payload[i + 1]]));
                if irap((payload[i + 2] >> 1) & 0x3f) {
                    return true;
                }
                i += 2 + size;
            }
            false
        }
        49 => payload
            .get(2)
            .is_some_and(|fu| fu & 0x80 != 0 && irap(fu & 0x3f)),
        t => irap(t),
    }
}

/// The bitstream of a frame from its packets' payloads, in sequence-number order with their
/// sequence numbers: the depacketized payloads joined (Annex B for H.264 and H.265, OBUs with
/// size fields for AV1). `None` when a payload does not parse.
pub fn depacketize_frame(codec: Codec, packets: &[(u16, Bytes)]) -> Option<Bytes> {
    let mut out = BytesMut::new();
    match codec {
        Codec::Vp8 => {
            let mut d = Vp8Packet::default();
            for (_, p) in packets {
                out.extend_from_slice(&d.depacketize(p).ok()?);
            }
        }
        Codec::Vp9 => {
            let mut d = Vp9Packet::default();
            for (_, p) in packets {
                out.extend_from_slice(&d.depacketize(p).ok()?);
            }
        }
        Codec::Av1 => {
            let mut d = Av1Depacketizer::default();
            for (_, p) in packets {
                out.extend_from_slice(&d.depacketize(p).ok()?);
            }
        }
        Codec::H264 => {
            let mut d = H264Packet::default();
            for (seq, p) in packets {
                out.extend_from_slice(&d.depacketize_with_sequence_number(*seq, p).ok()?);
            }
        }
        Codec::H265 => {
            let mut d = H265Packet::default();
            for (seq, p) in packets {
                out.extend_from_slice(&d.depacketize_with_sequence_number(*seq, p).ok()?);
            }
        }
    }
    Some(out.freeze())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_idr_is_found_alone_aggregated_and_fragmented() {
        assert!(h264_has_idr(&[0x65, 0x88]));
        assert!(!h264_has_idr(&[0x41, 0x9a]));
        // STAP-A: SPS (7) then IDR (5).
        assert!(h264_has_idr(&[0x18, 0, 2, 0x67, 0x42, 0, 2, 0x65, 0x88]));
        assert!(!h264_has_idr(&[0x18, 0, 2, 0x67, 0x42, 0, 2, 0x41, 0x88]));
        // FU-A start of an IDR, and a middle fragment of one.
        assert!(h264_has_idr(&[0x7c, 0x85, 0x01]));
        assert!(!h264_has_idr(&[0x7c, 0x05, 0x01]));
    }

    #[test]
    fn an_irap_is_found_alone_aggregated_and_fragmented() {
        // IDR_W_RADL (19) << 1.
        assert!(h265_has_irap(&[19 << 1, 1, 0xaf]));
        assert!(!h265_has_irap(&[1 << 1, 1, 0xaf]));
        // AP (48): VPS (32) then CRA (21).
        assert!(h265_has_irap(&[
            48 << 1,
            1,
            0,
            2,
            32 << 1,
            1,
            0,
            2,
            21 << 1,
            1
        ]));
        // FU (49) start of an IDR_N_LP (20).
        assert!(h265_has_irap(&[49 << 1, 1, 0x80 | 20, 0xaa]));
        assert!(!h265_has_irap(&[49 << 1, 1, 20, 0xaa]));
    }

    #[test]
    fn a_vp8_key_frame_gives_its_size() {
        // Descriptor: X=0, S=1, PID=0; then a key frame tag and 640x480.
        let payload = Bytes::from_static(&[
            0x10, 0x50, 0x2a, 0x00, 0x9d, 0x01, 0x2a, 0x80, 0x02, 0xe0, 0x01, 0x00,
        ]);
        let p = read_position(Codec::Vp8, true, &payload).unwrap();
        assert_eq!(p.starts_frame, Some(true));
        assert!(p.keyframe);
        assert_eq!(p.resolution, Some((640, 480)));
        // The same with the inter-frame bit set.
        let payload = Bytes::from_static(&[0x10, 0x51, 0x2a, 0x00]);
        assert!(!read_position(Codec::Vp8, true, &payload).unwrap().keyframe);
    }
}
