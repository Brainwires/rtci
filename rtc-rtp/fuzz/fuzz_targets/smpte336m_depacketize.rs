#![no_main]
//! Stateful target: the SMPTE ST 336 (KLV metadata) depacketizer fed fuzzed RTP payloads in
//! sequence, the one depacketizer `depacketize_sequence` does not cover. Each payload is a flags
//! byte (bit 0 is the marker), a two-byte length and the payload.

use bytes::Bytes;
use libfuzzer_sys::fuzz_target;
use rtc_rtp::codec::smpte336m::Smpte336mDepacketizer;
use rtc_rtp::packetizer::Depacketizer;

fuzz_target!(|data: &[u8]| {
    let mut data = data;
    let mut depacketizer = Smpte336mDepacketizer;
    let mut packets = 0;
    while data.len() >= 3 {
        let marker = data[0] & 0x01 != 0;
        let len = usize::from(u16::from_be_bytes([data[1], data[2]])).min(data.len() - 3);
        let payload = Bytes::copy_from_slice(&data[3..3 + len]);
        data = &data[3 + len..];
        packets += 1;
        if packets > 1024 {
            break;
        }
        let _ = depacketizer.is_partition_head(&payload);
        let _ = depacketizer.depacketize(&payload);
        let _ = depacketizer.is_partition_tail(marker, &payload);
    }
});
