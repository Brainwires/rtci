#![no_main]
//! Stateful target: the RFC 4571 framing decoder ICE-TCP reads a peer's stream with.
//!
//! The first byte picks the mode. Raw mode pushes fuzzed bytes in fuzzed chunk sizes and pops
//! whatever frames come out. Round-trip mode frames fuzzed packets with `frame_packet`, splits the
//! stream at fuzzed points and checks that the decoder hands back exactly those packets, in order:
//! a frame boundary lost or invented across a chunk split is a finding.

use libfuzzer_sys::fuzz_target;
use rtci_shared::tcp_framing::{TcpFrameDecoder, frame_packet};

fn byte(data: &[u8], i: usize) -> u8 {
    data.get(i).copied().unwrap_or(0)
}

fuzz_target!(|data: &[u8]| {
    let Some((&config, mut data)) = data.split_first() else {
        return;
    };
    let mut decoder = if config & 0x02 == 0 {
        TcpFrameDecoder::new()
    } else {
        TcpFrameDecoder::with_capacity(usize::from(config))
            .with_max_buffered(usize::from(config) << 8)
    };

    if config & 0x01 == 0 {
        // Raw: each chunk is a one-byte length and that many bytes.
        let mut steps = 0;
        while let Some((&len, rest)) = data.split_first() {
            steps += 1;
            if steps > 4096 {
                break;
            }
            let len = usize::from(len).min(rest.len());
            let (chunk, rest) = rest.split_at(len);
            data = rest;
            if decoder.push(chunk).is_err() {
                decoder.clear();
            }
            while decoder.next_packet().is_some() {}
            let _ = decoder.buffered_len();
            let _ = decoder.is_empty();
        }
        return;
    }

    // Round trip: packets are a one-byte length and that many bytes; the split points come from
    // the byte after each packet.
    let mut packets = Vec::new();
    let mut splits = Vec::new();
    while let Some((&len, rest)) = data.split_first() {
        let len = usize::from(len).min(rest.len());
        let (packet, rest) = rest.split_at(len);
        packets.push(packet.to_vec());
        splits.push(usize::from(byte(rest, 0)));
        data = rest.get(1..).unwrap_or(&[]);
        if packets.len() > 1024 {
            break;
        }
    }
    let stream: Vec<u8> = packets.iter().flat_map(|p| frame_packet(p)).collect();

    let mut decoder = TcpFrameDecoder::new();
    let mut out = Vec::new();
    let mut at = 0;
    let mut i = 0;
    while at < stream.len() {
        let step = (splits.get(i).copied().unwrap_or(7) + 1).min(stream.len() - at);
        i += 1;
        decoder.extend_from_slice(&stream[at..at + step]);
        at += step;
        while let Some(packet) = decoder.next_packet() {
            out.push(packet);
        }
    }
    assert_eq!(
        out, packets,
        "framed packets did not come back as they were sent"
    );
    assert!(decoder.is_empty(), "bytes left over after the last frame");
});
