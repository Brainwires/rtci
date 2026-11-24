//! Helpers of the unit tests.

use std::time::Instant;

use bytes::Bytes;

use crate::frame::{AssembledFrame, Codec, CodecHeader, VideoPacket};

/// A small deterministic generator (SplitMix64).
pub struct Rng(pub u64);

impl Rng {
    pub fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    pub fn below(&mut self, n: u64) -> u64 {
        if n == 0 { 0 } else { self.next_u64() % n }
    }
}

/// A VP8 packet with a 15-bit PictureID; `starts` sets S (PID 0), `delta` the inter-frame
/// bit of the frame tag when it starts a frame.
pub fn vp8_packet(
    arrival: Instant,
    seq: u16,
    ts: u32,
    starts: bool,
    delta: bool,
    marker: bool,
    picture_id: u16,
) -> VideoPacket {
    let mut payload = vec![
        0x80 | if starts { 0x10 } else { 0 },
        0x80,
        0x80 | ((picture_id >> 8) as u8 & 0x7f),
        picture_id as u8,
    ];
    payload.push(if delta { 0x01 } else { 0x00 });
    payload.extend_from_slice(&[0, 0, 0x9d, 0x01, 0x2a, 0x40, 0x01, 0xf0, 0x00]);
    VideoPacket {
        arrival,
        sequence_number: seq,
        timestamp: ts,
        marker,
        payload_type: 96,
        ssrc: 1,
        payload: Bytes::from(payload),
        dependency_descriptor: None,
        playout_delay_ms: None,
        retransmitted: false,
    }
}

/// A complete frame of one packet at sequence number `seq`.
pub fn assembled(seq: i64, keyframe: bool, header: CodecHeader) -> AssembledFrame {
    let t = Instant::now();
    AssembledFrame {
        codec: Codec::Vp8,
        payload_type: 96,
        ssrc: 1,
        rtp_timestamp: (seq as u32).wrapping_mul(3000),
        first_sequence: seq,
        last_sequence: seq,
        packet_count: 1,
        first_arrival: t,
        last_arrival: t,
        retransmitted: false,
        end_of_picture: true,
        keyframe,
        resolution: None,
        header,
        playout_delay_ms: None,
        data: Bytes::from_static(&[0]),
    }
}
