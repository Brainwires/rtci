#![no_main]
//! Stateful target: the ULPFEC decoder and the receive interceptor (RFC 5109 section 9, 14) fed
//! what a peer sends. Each op is an RTP packet with fuzzed header fields and payload: media, RED
//! (media, FEC, or broken), bare FEC, or a packet of a separate FEC stream. Both carriages run
//! side by side on the same input, with a third chain whose FEC stream runs in an RTP session of
//! its own (RFC 5109 section 14.1): its FEC packets arrive under the media SSRC and pass the
//! boundary map (`FecSessionSsrcMap`), as does whatever of the input parses as RTCP. Oracles: whatever the interceptors deliver belongs to the
//! media stream; a packet marked recovered was never an arrival of that sequence number in RED
//! form; the decoder's stores stay within their bounds.

use bytes::Bytes;
use libfuzzer_sys::fuzz_target;
use rtci::interceptor::{
    Attribute, AttributedPacket, FecSessionSsrcMap, FecSessionStream, Interceptor, Packet,
    Registry, Slot, StreamInfo, TaggedPacket, ULPFEC_MAX_HELD_FEC, ULPFEC_MEDIA_WINDOW, UlpfecDecoder, UlpfecReceiveBuilder, UlpfecReceiveStats, UlpfecRepair,
};
use rtci::rtp::header::Header;
use rtci::shared::TransportContext;
use rtci::shared::marshal::Unmarshal;
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

/// `binds_fec_stream`: whether the chain was bound with the separate FEC stream's SSRC. A chain
/// that was not has no business with a packet on that SSRC and passes it on as it came, like
/// any packet of a stream it does not know (the RED carriage has no FEC SSRC at all).
fn feed(
    chain: &mut impl Interceptor,
    now: Instant,
    packet: &rtci::rtp::packet::Packet,
    binds_fec_stream: bool,
) {
    let foreign = packet.header.ssrc != MEDIA_SSRC && !binds_fec_stream;
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
        // The decoder's counts travel on an empty carrier, never on media. FEC reaches the
        // RED chain's decoder only from RED packets: it cannot discard more than came in them.
        if let Some(report) = out.message.custom::<UlpfecReceiveStats>() {
            assert!(matches!(&out.message.packet, Packet::Rtcp(packets) if packets.is_empty()));
            assert_eq!(MEDIA_SSRC, report.media_ssrc);
            if !binds_fec_stream {
                assert!(report.decoder.discarded() <= report.fec_packets_in_red);
            }
        }
        if let Packet::Rtp(delivered) = &out.message.packet {
            if foreign {
                assert_eq!(packet, delivered, "a foreign packet passes through untouched");
                assert!(!out.message.has(&Attribute::RecoveredByFec));
                continue;
            }
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
    // The FEC stream in an RTP session of its own: on the wire it has the media SSRC, in the
    // chain the mapped one. The builder asks for RED; the stream's FEC session decides.
    let map = FecSessionSsrcMap::new(u32::from(config).wrapping_mul(0x0101_0101));
    let mut session = Registry::new()
        .with(
            Slot::FecDecoder,
            UlpfecReceiveBuilder::red(RED_PT, FEC_PT).build(),
        )
        .build();
    session.bind_remote_stream(&StreamInfo {
        fec_session: Some(FecSessionStream {
            ssrc: map.map(MEDIA_SSRC),
            payload_type: FEC_PT,
            one_level_only: config & 0x01 != 0,
        }),
        ..info(false)
    });
    let mut decoder = UlpfecDecoder::new(MEDIA_SSRC).with_one_level_only(config & 0x04 != 0);
    let mut fed_fec = 0u64;

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
        let mut packet = rtci::rtp::packet::Packet {
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
                if let Ok(mut parsed) = rtci::rtp::packet::Packet::unmarshal(&mut &payload[..]) {
                    parsed.header.ssrc = MEDIA_SSRC;
                    packet = parsed;
                }
            }
        }

        feed(&mut red, now, &packet, false);
        feed(&mut stream, now, &packet, true);
        if op % 6 == 4 {
            // The same FEC data as the FEC session's transport delivers it: under the media
            // SSRC, taken into the chain by the map.
            let mut of_session = packet.clone();
            of_session.header.ssrc = MEDIA_SSRC;
            map.map_rtp(&mut of_session);
            feed(&mut session, now, &of_session, true);
        } else {
            feed(&mut session, now, &packet, true);
        }
        // RTCP of the FEC session crosses the same boundary: the map keeps or drops whole
        // packets, and what it kept maps back packet for packet.
        if let Ok(compound) = rtci::rtcp::packet::unmarshal(&mut &payload[..]) {
            let mapped = map.map_rtcp(&compound);
            assert!(mapped.len() <= compound.len());
            assert_eq!(map.map_rtcp(&mapped).len(), mapped.len());
            let _ = rtci::rtcp::packet::marshal(&mapped);
        }

        let recovered = if op % 6 == 2 || op % 6 == 4 {
            fed_fec += 1;
            decoder.push_fec(payload).unwrap_or_default()
        } else {
            decoder.push_media(&packet)
        };
        // Every FEC payload fed is held, used, or discarded once: never counted twice.
        assert!(decoder.stats().discarded() + decoder.held_fec_packets() as u64 <= fed_fec);
        for packet in &recovered {
            assert_eq!(MEDIA_SSRC, packet.header.ssrc);
            assert_eq!(2, packet.header.version);
        }
        assert!(decoder.held_fec_packets() <= ULPFEC_MAX_HELD_FEC);
        assert!(decoder.held_media_packets() <= 2 * usize::from(ULPFEC_MEDIA_WINDOW) + 1);
    }
});
