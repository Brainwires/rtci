//! H.264 (RFC 6184) and H.265 (RFC 7798) through the sample builder: NAL units come out in
//! RTP sequence-number order whatever order their packets arrive in, a fragmented NAL unit
//! is reassembled in that order, duplicates are dropped, and an access unit ends at a new
//! timestamp even when the marker bit that should have ended it never came.

use bytes::Bytes;
use rtp::codec::h264::H264Packet;
use rtp::codec::h265::H265Packet;
use rtp::packetizer::Depacketizer;
use rtp::{Header, Packet};
use std::time::Instant;

use super::*;

fn packet(sequence_number: u16, timestamp: u32, marker: bool, payload: &[u8]) -> Packet {
    Packet {
        header: Header {
            sequence_number,
            timestamp,
            marker,
            ..Default::default()
        },
        payload: Bytes::copy_from_slice(payload),
    }
}

/// The samples (data, RTP timestamp) that come out of pushing `packets` in the given order.
fn samples<T: Depacketizer>(depacketizer: T, packets: Vec<Packet>) -> Vec<(Bytes, u32)> {
    let now = Instant::now();
    let mut builder = SampleBuilder::new(10, depacketizer, 90000);
    let mut out = vec![];
    for p in packets {
        builder.push(now, p);
        while let Some((sample, timestamp)) = builder.pop_with_timestamp(now) {
            out.push((sample.data, timestamp));
        }
    }
    out
}

fn annex_b(units: &[&[u8]]) -> Bytes {
    let mut out = vec![];
    for unit in units {
        out.extend_from_slice(&[0, 0, 0, 1]);
        out.extend_from_slice(unit);
    }
    Bytes::from(out)
}

const IDR: &[u8] = &[0x65, 0xA0, 0xA1];
const SLICE_1: &[u8] = &[0x41, 0xB0];
const SLICE_2: &[u8] = &[0x41, 0xB1];
const NEXT: &[u8] = &[0x41, 0xC0];

/// RFC 6184 sections 5.6 and 7.1: in the single NAL unit and non-interleaved modes NAL units
/// are passed to the decoder in RTP sequence-number order. Packets that arrive 3, 1, 2 come
/// out 1, 2, 3.
#[test]
fn h264_nal_units_come_out_in_sequence_number_order() {
    let out = samples(
        H264Packet::default(),
        vec![
            packet(3, 3000, true, SLICE_2),
            packet(1, 3000, false, IDR),
            packet(2, 3000, false, SLICE_1),
            packet(4, 6000, true, NEXT),
            packet(5, 9000, true, NEXT),
        ],
    );
    assert_eq!((annex_b(&[IDR, SLICE_1, SLICE_2]), 3000), out[0]);
}

/// RFC 6184 section 5.8: the fragments of an FU-A are put together in sequence-number order.
#[test]
fn h264_fragments_are_reassembled_in_sequence_number_order() {
    // An IDR NAL unit (header 0x65) in three FU-A fragments: indicator 0x7C, headers with the
    // start (0x85), middle (0x05) and end (0x45) bits.
    let out = samples(
        H264Packet::default(),
        vec![
            packet(12, 3000, true, &[0x7C, 0x45, 0x05, 0x06]),
            packet(10, 3000, false, &[0x7C, 0x85, 0x01, 0x02]),
            packet(11, 3000, false, &[0x7C, 0x05, 0x03, 0x04]),
            packet(13, 6000, true, NEXT),
            packet(14, 9000, true, NEXT),
        ],
    );
    assert_eq!(
        (
            annex_b(&[&[0x65, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06]]),
            3000
        ),
        out[0]
    );
}

/// RFC 6184 section 5.1: "decoders MUST NOT rely on this property" (the marker bit on the
/// last packet of an access unit): an access unit whose marker never came ends where the
/// next timestamp begins.
#[test]
fn an_h264_access_unit_ends_at_the_next_timestamp_without_a_marker() {
    let out = samples(
        H264Packet::default(),
        vec![
            packet(1, 3000, false, IDR),
            packet(2, 3000, false, SLICE_1),
            packet(3, 6000, true, NEXT),
            packet(4, 9000, true, NEXT),
        ],
    );
    assert_eq!((annex_b(&[IDR, SLICE_1]), 3000), out[0]);
    assert_eq!((annex_b(&[NEXT]), 6000), out[1]);
}

const H265_IDR: &[u8] = &[0x26, 0x01, 0xD0];
const H265_TRAIL_1: &[u8] = &[0x02, 0x01, 0xE0];
const H265_TRAIL_2: &[u8] = &[0x02, 0x01, 0xE1];

/// RFC 7798 section 6: with `sprop-max-don-diff` 0 "NAL units ... are passed in RTP
/// sequence number order" and "duplicated or outdated RTP packets ... are removed": packets
/// 3, 1, 2, 1 again come out 1, 2, 3, once each.
#[test]
fn h265_nal_units_come_out_in_order_and_duplicates_once() {
    let out = samples(
        H265Packet::default(),
        vec![
            packet(3, 3000, true, H265_TRAIL_2),
            packet(1, 3000, false, H265_IDR),
            packet(2, 3000, false, H265_TRAIL_1),
            packet(1, 3000, false, H265_IDR),
            packet(4, 6000, true, H265_TRAIL_1),
            packet(5, 9000, true, H265_TRAIL_1),
        ],
    );
    assert_eq!(
        (annex_b(&[H265_IDR, H265_TRAIL_1, H265_TRAIL_2]), 3000),
        out[0]
    );
    assert_eq!(1, out.iter().filter(|(_, ts)| *ts == 3000).count());
}
