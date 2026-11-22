#![no_main]
//! Stateful target: the ULPFEC decoder and the receive interceptor (RFC 5109 section 9, 14) fed
//! what a peer sends. Each op is an RTP packet with fuzzed header fields and payload: media, RED
//! (media, FEC, or broken), bare FEC, or a packet of a separate FEC stream. Both carriages run
//! side by side on the same input. Oracles: whatever the interceptors deliver belongs to the
//! media stream; a packet marked recovered was never an arrival of that sequence number in RED
//! form; the decoder's stores stay within their bounds.

use bytes::Bytes;
use libfuzzer_sys::fuzz_target;
use rtc::interceptor::{
    Attribute, AttributedPacket, Interceptor, Packet, Registry, Slot, StreamInfo, TaggedPacket,
    ULPFEC_MAX_HELD_FEC, ULPFEC_MEDIA_WINDOW, UlpfecDecoder, UlpfecReceiveBuilder, UlpfecRepair,
};
use rtc::rtp::header::Header;
use rtc::shared::TransportContext;
use rtc::shared::marshal::Unmarshal;
use std::time::Instant;

const MEDIA_SSRC: u32 = 0x1111_1111;
const FEC_SSRC: u32 = 0x2222_2222;
const MEDIA_PT: u8 = 96;
const RED_PT: u8 = 116;
const FEC_PT: u8 = 117;

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

fn info(separate: bool) -> StreamInfo {
    StreamInfo {
        ssrc: MEDIA_SSRC,
        ssrc_fec: separate.then_some(FEC_SSRC),
        payload_type: MEDIA_PT,
        payload_type_fec: separate.then_some(FEC_PT),
        mime_type: "video/VP8".to_owned(),
        clock_rate: 90_000,
        ..Default::default()
    }
}

fn feed(chain: &mut impl Interceptor, now: Instant, packet: &rtc::rtp::packet::Packet) {
    let _ = chain.handle_read(TaggedPacket {
        now,
        transport: TransportContext::default(),
        message: AttributedPacket::new(Packet::Rtp(packet.clone())),
    });
    let mut budget = 4096;
    while budget > 0 {
        let Some(out) = chain.poll_read() else {
            break;
        };
        budget -= 1;
        if let Packet::Rtp(delivered) = &out.message.packet {
            assert_eq!(MEDIA_SSRC, delivered.header.ssrc, "only media is delivered");
            if out.message.custom::<UlpfecRepair>().is_some() {
                assert!(delivered.payload.is_empty());
                assert!(!out.message.has(&Attribute::RecoveredByFec));
            }
        }
    }
    while chain.poll_write().is_some() {}
}

fuzz_target!(|data: &[u8]| {
    let mut data = data;
    let Some((&config, rest)) = data.split_first() else {
        return;
    };
    data = rest;

    let mut red = Registry::new()
        .with(
            Slot::FecDecoder,
            UlpfecReceiveBuilder::red(RED_PT, FEC_PT)
                .with_one_level_only(config & 0x01 != 0)
                .with_repair_forwarding(config & 0x02 == 0)
                .build(),
        )
        .build();
    red.bind_remote_stream(&info(false));
    let mut stream = Registry::new()
        .with(
            Slot::FecDecoder,
            UlpfecReceiveBuilder::stream()
                .with_one_level_only(config & 0x01 != 0)
                .build(),
        )
        .build();
    stream.bind_remote_stream(&info(true));
    let mut decoder = UlpfecDecoder::new(MEDIA_SSRC).with_one_level_only(config & 0x04 != 0);

    let now = Instant::now();
    let mut sequence_number = u16::from(config) << 8;
    let mut ops = 0;
    while let Some((&op, rest)) = data.split_first() {
        data = rest;
        ops += 1;
        if ops > 256 {
            break;
        }
        let arg = take_arg(&mut data);
        let (control, payload) = arg.split_at(arg.len().min(2));
        let step = control.first().copied().unwrap_or(0);
        // Mostly near the last sequence number, so masks and media meet; sometimes far away.
        sequence_number = if step & 0x80 != 0 {
            u16::from_be_bytes([step, control.get(1).copied().unwrap_or(0)])
        } else {
            sequence_number.wrapping_add(u16::from(step & 0x07))
        };
        let mut packet = rtc::rtp::packet::Packet {
            header: Header {
                version: 2,
                marker: op & 0x40 != 0,
                payload_type: MEDIA_PT,
                sequence_number,
                timestamp: u32::from(sequence_number) * 3000,
                ssrc: MEDIA_SSRC,
                ..Default::default()
            },
            payload: Bytes::copy_from_slice(payload),
        };
        match op % 6 {
            // Media, bare.
            0 => {}
            // RED on the media stream, whatever the payload says its blocks are.
            1 => packet.header.payload_type = RED_PT,
            // RED with one FEC block: the payload is the FEC data.
            2 => {
                packet.header.payload_type = RED_PT;
                let mut red_payload = vec![FEC_PT];
                red_payload.extend_from_slice(payload);
                packet.payload = Bytes::from(red_payload);
            }
            // FEC by itself on the media stream.
            3 => packet.header.payload_type = FEC_PT,
            // A packet of the separate FEC stream.
            4 => {
                packet.header.ssrc = FEC_SSRC;
                packet.header.payload_type = FEC_PT;
            }
            // A whole RTP packet from the input, on the media stream.
            _ => {
                if let Ok(mut parsed) = rtc::rtp::packet::Packet::unmarshal(&mut &payload[..]) {
                    parsed.header.ssrc = MEDIA_SSRC;
                    packet = parsed;
                }
            }
        }

        feed(&mut red, now, &packet);
        feed(&mut stream, now, &packet);

        let recovered = if op % 6 == 2 || op % 6 == 4 {
            decoder.push_fec(payload).unwrap_or_default()
        } else {
            decoder.push_media(&packet)
        };
        for packet in &recovered {
            assert_eq!(MEDIA_SSRC, packet.header.ssrc);
            assert_eq!(2, packet.header.version);
        }
        assert!(decoder.held_fec_packets() <= ULPFEC_MAX_HELD_FEC);
        assert!(decoder.held_media_packets() <= 2 * usize::from(ULPFEC_MEDIA_WINDOW) + 1);
    }
});
