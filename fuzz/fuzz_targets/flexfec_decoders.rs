#![no_main]
//! Stateful target: the two FlexFEC decoders (draft-03 `flexfec-03` and RFC 8627 `flexfec`), fed
//! what a peer sends on the source and repair streams: source packets parsed from fuzzed bytes,
//! repair packets with fuzzed FEC headers (masks, L and D, R and F bits, CSRC lists, length
//! recovery), time steps past the repair window, and stream changes. The buffers must stay
//! within their bounds, and nothing may panic.
//!
//! One op is an oracle: a block built by the matching encoder with one source packet dropped
//! must come back byte for byte from a fresh decoder.

#[path = "common.rs"]
mod common;

use bytes::Bytes;
use libfuzzer_sys::fuzz_target;
use rtc::interceptor::{
    FlexFec03Decoder, FlexFec03Encoder, FlexFecDecoder, FlexFecDecoderConfig, FlexFecEncoder,
    FlexFecProtection,
};
use rtc::rtp::header::Header;
use rtc::shared::marshal::{Marshal, MarshalSize, Unmarshal};
use std::time::Duration;

const MEDIA_SSRC: u32 = 0x1111_1111;
const OTHER_SSRC: u32 = 0x2222_2222;
const REPAIR_SSRC: u32 = 0x3333_3333;
const REPAIR_PT: u8 = 98;

fn byte(arg: &[u8], i: usize) -> u8 {
    arg.get(i).copied().unwrap_or(0)
}

fn take_arg<'a>(data: &mut &'a [u8]) -> &'a [u8] {
    if data.len() < 2 {
        *data = &[];
        return &[];
    }
    let len = usize::from(u16::from_be_bytes([data[0], data[1]])).min(data.len() - 2);
    let (arg, rest) = data[2..].split_at(len);
    *data = rest;
    arg
}

fn wire(packet: &rtc::rtp::packet::Packet) -> Vec<u8> {
    let mut buffer = vec![0u8; packet.marshal_size()];
    let _ = packet.marshal_to(&mut buffer);
    buffer
}

fn source(ssrc: u32, sequence_number: u16, arg: &[u8]) -> rtc::rtp::packet::Packet {
    rtc::rtp::packet::Packet {
        header: Header {
            version: 2,
            marker: byte(arg, 0) & 1 != 0,
            payload_type: 96 + (byte(arg, 0) >> 6),
            sequence_number,
            timestamp: u32::from(sequence_number) * 3000,
            ssrc,
            ..Default::default()
        },
        payload: Bytes::copy_from_slice(
            &arg[..arg.len().min(1 + usize::from(sequence_number % 13))],
        ),
    }
}

fn repair(arg: &[u8]) -> rtc::rtp::packet::Packet {
    let csrc = match byte(arg, 2) & 0x07 {
        0 => vec![],
        1 | 2 | 3 => vec![MEDIA_SSRC],
        4 => vec![MEDIA_SSRC, OTHER_SSRC],
        5 => vec![OTHER_SSRC, MEDIA_SSRC],
        6 => vec![0xDEAD_BEEF],
        _ => vec![MEDIA_SSRC; 15],
    };
    rtc::rtp::packet::Packet {
        header: Header {
            version: 2,
            marker: byte(arg, 2) & 0x08 != 0,
            payload_type: REPAIR_PT,
            sequence_number: u16::from_be_bytes([byte(arg, 0), byte(arg, 1)]),
            ssrc: REPAIR_SSRC,
            csrc,
            ..Default::default()
        },
        payload: Bytes::copy_from_slice(arg.get(3..).unwrap_or(&[])),
    }
}

/// Encode a block with the RFC 8627 encoder, drop one packet, and require it back.
fn rfc8627_oracle(arg: &[u8]) {
    let protection = match byte(arg, 0) % 4 {
        0 => FlexFecProtection::Row {
            l: 1 + byte(arg, 1) % 12,
        },
        1 => FlexFecProtection::Column {
            l: 1 + byte(arg, 1) % 6,
            d: 2 + byte(arg, 2) % 5,
        },
        2 => FlexFecProtection::RowAndColumn {
            l: 1 + byte(arg, 1) % 6,
            d: 2 + byte(arg, 2) % 5,
        },
        _ => FlexFecProtection::Mask {
            media_packets: 1 + u32::from(byte(arg, 1)) % 110,
            fec_packets: 1 + u32::from(byte(arg, 2)) % 4,
        },
    };
    let first = u16::from_be_bytes([byte(arg, 3), byte(arg, 4)]);
    let block: Vec<_> = (0..protection.block_len() as u16)
        .map(|offset| source(MEDIA_SSRC, first.wrapping_add(offset), arg))
        .collect();
    let repair = FlexFecEncoder::new(REPAIR_PT, REPAIR_SSRC).encode_block(protection, &block, 0);
    assert_eq!(protection.repair_packets_per_block(), repair.len());

    let lost = usize::from(byte(arg, 5)) % block.len();
    let mut decoder = FlexFecDecoder::new(FlexFecDecoderConfig::default());
    decoder.add_source_stream(MEDIA_SSRC);
    let now = common::start();
    let mut recovered = Vec::new();
    for (index, packet) in block.iter().enumerate() {
        if index != lost {
            recovered.extend(decoder.push_source(now, packet));
        }
    }
    for packet in &repair {
        recovered.extend(decoder.push_repair(now, packet));
    }
    assert_eq!(
        1,
        recovered.len(),
        "one loss in a block is always recoverable"
    );
    assert_eq!(wire(&block[lost]), wire(&recovered[0]));
}

/// The same for draft-03.
fn draft03_oracle(arg: &[u8]) {
    let count = 1 + u16::from(byte(arg, 1)) % 109;
    let first = u16::from_be_bytes([byte(arg, 3), byte(arg, 4)]);
    let block: Vec<_> = (0..count)
        .map(|offset| source(MEDIA_SSRC, first.wrapping_add(offset), arg))
        .collect();
    let repair = FlexFec03Encoder::new(REPAIR_PT, REPAIR_SSRC).encode(
        &block,
        1 + u32::from(byte(arg, 2)) % 4,
        0,
    );
    assert!(!repair.is_empty());

    let lost = usize::from(byte(arg, 5)) % block.len();
    let mut decoder = FlexFec03Decoder::new(REPAIR_SSRC, MEDIA_SSRC);
    let mut recovered = Vec::new();
    for (index, packet) in block.iter().enumerate() {
        if index != lost {
            recovered.extend(decoder.decode(packet.clone()));
        }
    }
    for packet in &repair {
        recovered.extend(decoder.decode(packet.clone()));
    }
    assert_eq!(
        1,
        recovered.len(),
        "one loss in a block is always recoverable"
    );
    assert_eq!(wire(&block[lost]), wire(&recovered[0]));
}

fuzz_target!(|data: &[u8]| {
    let mut data = data;
    let Some((&config, rest)) = data.split_first() else {
        return;
    };
    data = rest;
    let rfc8627 = config & 0x01 != 0;

    let window = Duration::from_millis(1 + u64::from(config >> 1) * 8);
    let bounds = FlexFecDecoderConfig::for_repair_window(window);
    let mut decoder = FlexFecDecoder::new(bounds);
    decoder.add_source_stream(MEDIA_SSRC);
    if config & 0x02 != 0 {
        decoder.add_source_stream(OTHER_SSRC);
    }
    let mut draft03 = FlexFec03Decoder::new(REPAIR_SSRC, MEDIA_SSRC);

    let mut now = common::start();
    let mut sequence_number: u16 = u16::from(config) << 8;
    let mut ops = 0;
    while let Some((&op, rest)) = data.split_first() {
        data = rest;
        ops += 1;
        if ops > 512 {
            break;
        }
        let arg = take_arg(&mut data);
        match op % 6 {
            // A source packet as the peer framed it.
            0 => {
                if let Ok(mut packet) = rtc::rtp::packet::Packet::unmarshal(&mut &arg[..]) {
                    packet.header.ssrc = if op & 0x80 == 0 {
                        MEDIA_SSRC
                    } else {
                        OTHER_SSRC
                    };
                    if rfc8627 {
                        let _ = decoder.push_source(now, &packet);
                    } else {
                        let _ = draft03.decode(packet);
                    }
                }
            }
            // A source packet in sequence, so repair packets have something to complete.
            1 => {
                sequence_number = sequence_number.wrapping_add(1 + u16::from(byte(arg, 0) & 0x03));
                let ssrc = if op & 0x80 == 0 {
                    MEDIA_SSRC
                } else {
                    OTHER_SSRC
                };
                let packet = source(ssrc, sequence_number, arg);
                if rfc8627 {
                    let _ = decoder.push_source(now, &packet);
                } else {
                    let _ = draft03.decode(packet);
                }
            }
            // A repair packet with a fuzzed FEC header.
            2 | 3 => {
                let packet = repair(arg);
                if rfc8627 {
                    for recovered in decoder.push_repair(now, &packet) {
                        assert!(decoder.protects(recovered.header.ssrc));
                    }
                } else {
                    for recovered in draft03.decode(packet) {
                        assert_eq!(MEDIA_SSRC, recovered.header.ssrc);
                    }
                }
            }
            4 => {
                now += Duration::from_millis(u64::from(u16::from_be_bytes([
                    byte(arg, 0),
                    byte(arg, 1),
                ])));
                if op & 0x80 != 0 {
                    decoder.remove_source_stream(OTHER_SSRC);
                    decoder.add_source_stream(OTHER_SSRC);
                }
            }
            _ => {
                if rfc8627 {
                    rfc8627_oracle(arg);
                } else {
                    draft03_oracle(arg);
                }
            }
        }

        let streams = decoder.source_streams().count();
        assert!(decoder.held_source_packets() <= streams * bounds.max_source_packets);
        assert!(decoder.pending_repair_packets() <= bounds.max_repair_packets);
        assert!(draft03.recovered_len() <= 256);
        assert!(draft03.pending_repair_packets() <= 128);
    }
});
