#![no_main]
//! Parser and stateful target: RFC 2198 RED payloads. The raw input is parsed as one payload
//! (and, when it parses, marshalled back and parsed again: the result must not change) and as
//! a RED fmtp list. Then it is read as a sequence of packets fed to the RED decoder, each
//! primary also going through a RED encoder: a packet is a two-byte sequence number, a
//! four-byte RTP timestamp, a two-byte length and the payload.

use bytes::Bytes;
use libfuzzer_sys::fuzz_target;
use rtc_rtp::codec::red::{
    RedDecoder, RedDepacketizer, RedEncoder, RedPacket, format_red_fmtp, parse_red_fmtp,
};
use rtc_rtp::packetizer::Depacketizer;
use rtc_shared::marshal::Marshal;

fuzz_target!(|data: &[u8]| {
    let payload = Bytes::copy_from_slice(data);
    if let Ok(packet) = RedPacket::parse(&payload) {
        let raw = packet
            .marshal()
            .expect("a parsed payload marshals")
            .freeze();
        assert_eq!(raw, payload);
        assert_eq!(RedPacket::parse(&raw).ok(), Some(packet));
    }
    let _ = RedDepacketizer.depacketize(&payload);

    if let Ok(list) = std::str::from_utf8(data)
        && let Ok(pts) = parse_red_fmtp(list)
    {
        assert_eq!(parse_red_fmtp(&format_red_fmtp(&pts)).ok(), Some(pts));
    }

    let mut decoder = RedDecoder::new(16);
    let mut encoder = RedEncoder::new(2, 1200);
    let mut rest = data;
    let mut packets = 0;
    while rest.len() >= 8 && packets < 1024 {
        let sequence_number = u16::from_be_bytes([rest[0], rest[1]]);
        let timestamp = u32::from_be_bytes([rest[2], rest[3], rest[4], rest[5]]);
        let len = usize::from(u16::from_be_bytes([rest[6], rest[7]])).min(rest.len() - 8);
        let payload = Bytes::copy_from_slice(&rest[8..8 + len]);
        rest = &rest[8 + len..];
        packets += 1;
        if let Ok(blocks) = decoder.decode(sequence_number, timestamp, &payload) {
            for block in blocks.into_iter().filter(|b| b.primary) {
                if let Ok(raw) = encoder.encode(block.payload_type, block.timestamp, block.data) {
                    let encoded = RedPacket::parse(&raw).expect("an encoded payload parses");
                    assert!(raw.len() <= 1200);
                    assert!(encoded.redundant().len() <= 2);
                }
            }
        }
    }
});
