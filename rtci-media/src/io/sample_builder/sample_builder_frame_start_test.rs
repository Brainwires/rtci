//! A sample is built only from a run of packets that begins a frame (RFC 7741 4.5.1, AV1 RTP
//! 4.4): when a frame's first packet is lost, the rest of it is dropped, not emitted headless.

use bytes::Bytes;
use rtp::codec::av1::Av1Depacketizer;
use rtp::codec::vp8::Vp8Packet;
use rtp::packetizer::Depacketizer;
use rtp::{Header, Packet};
use std::time::Instant;

use super::*;

fn packet(sequence_number: u16, timestamp: u32, marker: bool, payload: &'static [u8]) -> Packet {
    Packet {
        header: Header {
            sequence_number,
            timestamp,
            marker,
            ..Default::default()
        },
        payload: Bytes::from_static(payload),
    }
}

/// Pushes `packets` and returns the timestamps of the samples that come out.
fn sample_timestamps<T: Depacketizer>(depacketizer: T, packets: Vec<Packet>) -> Vec<u32> {
    let now = Instant::now();
    let mut builder = SampleBuilder::new(2, depacketizer, 90000);
    let mut out = vec![];
    for p in packets {
        builder.push(now, p);
        while let Some((_, timestamp)) = builder.pop_with_timestamp(now) {
            out.push(timestamp);
        }
    }
    out
}

/// RFC 7741 4.6.3 packetization: one partition per packet, each with S=1 and its own PID. With
/// the first partition (the frame header) lost, the other two are not a frame.
#[test]
fn a_vp8_frame_without_its_first_partition_is_dropped() {
    let timestamps = sample_timestamps(
        Vp8Packet::default(),
        vec![
            packet(1, 1000, true, &[0x10, 0x01, 0x02, 0x03]),
            // Sequence number 2 (S=1, PID=0, timestamp 2000) is lost.
            packet(3, 2000, false, &[0x11, 0x04, 0x05, 0x06]),
            packet(4, 2000, true, &[0x12, 0x07, 0x08, 0x09]),
            packet(5, 3000, true, &[0x10, 0x0A, 0x0B, 0x0C]),
            packet(6, 4000, true, &[0x10, 0x0D, 0x0E, 0x0F]),
            packet(7, 5000, true, &[0x10, 0x10, 0x11, 0x12]),
            packet(8, 6000, true, &[0x10, 0x13, 0x14, 0x15]),
        ],
    );
    assert!(
        !timestamps.contains(&2000),
        "the frame at 2000 lacks its first partition: {timestamps:?}"
    );
    assert!(timestamps.contains(&1000) && timestamps.contains(&3000));
}

/// A temporal unit sent as frame header, tile group, tile group in three packets, all with
/// Z=0. With the frame header lost, the two tile groups are not a temporal unit.
#[test]
fn an_av1_temporal_unit_without_its_frame_header_is_dropped() {
    let timestamps = sample_timestamps(
        Av1Depacketizer::new(),
        vec![
            packet(1, 1000, true, &[0x10, 0x30, 0x01]),
            // Sequence number 2 ([0x10, 0x18, 0x10], the frame header, timestamp 2000) is lost.
            packet(3, 2000, false, &[0x10, 0x20, 0xAA]),
            packet(4, 2000, true, &[0x10, 0x20, 0xBB]),
            packet(5, 3000, true, &[0x10, 0x30, 0x02]),
            packet(6, 4000, true, &[0x10, 0x30, 0x03]),
            packet(7, 5000, true, &[0x10, 0x30, 0x04]),
            packet(8, 6000, true, &[0x10, 0x30, 0x05]),
        ],
    );
    assert!(
        !timestamps.contains(&2000),
        "the unit at 2000 lacks its frame header: {timestamps:?}"
    );
    assert!(timestamps.contains(&1000) && timestamps.contains(&3000));
}
