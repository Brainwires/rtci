//! The logic of the `ulpfec_receive` and `flexfec_receive` fuzz targets, run over a fixed
//! corpus.
//!
//! The fuzz targets run in CI's fuzz job only. These are the same drivers and the same oracles
//! as unit tests, over inputs that never change: the input the `ulpfec_receive` target stopped
//! on, and a few thousand generated ones (a fixed linear congruential sequence shaped into
//! plausible RTP, RED, ULPFEC and FlexFEC packets, so they reach past the first length check).
//! Nothing may panic, a chain delivers only what belongs to the streams it was bound with, and
//! the decoders' tables stay inside their bounds.

use bytes::Bytes;
use rtc_interceptor::{
    Attribute, AttributedPacket, FlexFec03ReceiveBuilder, FlexFecReceiveBuilder, Interceptor,
    Packet, Registry, Slot, StreamInfo, TaggedPacket, ULPFEC_MAX_HELD_FEC, ULPFEC_MEDIA_WINDOW,
    UlpfecDecoder, UlpfecReceiveBuilder, UlpfecRepair,
};
use rtp::header::Header;
use sansio::Protocol;
use shared::TransportContext;
use shared::marshal::{Marshal, Unmarshal};
use std::time::{Duration, Instant};

const MEDIA_SSRC: u32 = 0x1111_1111;
const SECOND_SSRC: u32 = 0x2222_2222;
const REPAIR_SSRC: u32 = 0x3333_3333;
const MEDIA_PT: u8 = 96;
const RED_PT: u8 = 116;
const FEC_PT: u8 = 117;

/// The fixed sequence the corpus is made from.
struct Lcg(u32);

impl Lcg {
    fn next(&mut self) -> u32 {
        self.0 = self.0.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        self.0 >> 8
    }
    fn byte(&mut self) -> u8 {
        self.next() as u8
    }
    fn below(&mut self, bound: u32) -> u32 {
        self.next() % bound
    }
    fn bytes(&mut self, length: usize) -> Vec<u8> {
        (0..length).map(|_| self.byte()).collect()
    }
}

fn byte(arg: &[u8], index: usize) -> u8 {
    arg.get(index).copied().unwrap_or(0)
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

fn tagged(now: Instant, packet: Packet) -> TaggedPacket {
    TaggedPacket {
        now,
        transport: TransportContext::default(),
        message: AttributedPacket::new(packet),
    }
}

/// One op of a fuzz input: the op octet, a two-octet length, the argument.
fn op(input: &mut Vec<u8>, op: u8, arg: &[u8]) {
    input.push(op);
    input.extend_from_slice(&(arg.len() as u16).to_be_bytes());
    input.extend_from_slice(arg);
}

// ---------------------------------------------------------------------------------------------
// ulpfec_receive
// ---------------------------------------------------------------------------------------------

fn ulpfec_info(separate: bool) -> StreamInfo {
    StreamInfo {
        ssrc: MEDIA_SSRC,
        ssrc_fec: separate.then_some(SECOND_SSRC),
        payload_type: MEDIA_PT,
        payload_type_fec: separate.then_some(FEC_PT),
        mime_type: "video/VP8".to_owned(),
        clock_rate: 90_000,
        ..Default::default()
    }
}

fn ulpfec_feed(
    chain: &mut impl Interceptor,
    now: Instant,
    packet: &rtp::Packet,
    binds_fec_stream: bool,
) {
    let foreign = packet.header.ssrc != MEDIA_SSRC && !binds_fec_stream;
    let _ = chain.handle_read(tagged(now, Packet::Rtp(packet.clone())));
    let mut budget = 4096;
    while budget > 0 {
        let Some(out) = chain.poll_read() else {
            break;
        };
        budget -= 1;
        if let Packet::Rtp(delivered) = &out.message.packet {
            if foreign {
                assert_eq!(
                    packet, delivered,
                    "a foreign packet passes through untouched"
                );
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

/// The body of the `ulpfec_receive` fuzz target.
fn ulpfec_receive(data: &[u8]) {
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
    red.bind_remote_stream(&ulpfec_info(false));
    let mut stream = Registry::new()
        .with(
            Slot::FecDecoder,
            UlpfecReceiveBuilder::stream()
                .with_one_level_only(config & 0x01 != 0)
                .build(),
        )
        .build();
    stream.bind_remote_stream(&ulpfec_info(true));
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
        sequence_number = if step & 0x80 != 0 {
            u16::from_be_bytes([step, control.get(1).copied().unwrap_or(0)])
        } else {
            sequence_number.wrapping_add(u16::from(step & 0x07))
        };
        let mut packet = rtp::Packet {
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
            0 => {}
            1 => packet.header.payload_type = RED_PT,
            2 => {
                packet.header.payload_type = RED_PT;
                let mut red_payload = vec![FEC_PT];
                red_payload.extend_from_slice(payload);
                packet.payload = Bytes::from(red_payload);
            }
            3 => packet.header.payload_type = FEC_PT,
            4 => {
                packet.header.ssrc = SECOND_SSRC;
                packet.header.payload_type = FEC_PT;
            }
            _ => {
                if let Ok(mut parsed) = rtp::Packet::unmarshal(&mut &payload[..]) {
                    parsed.header.ssrc = MEDIA_SSRC;
                    packet = parsed;
                }
            }
        }

        ulpfec_feed(&mut red, now, &packet, false);
        ulpfec_feed(&mut stream, now, &packet, true);

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
}

/// A plausible ULPFEC payload: FEC header, then one to three levels, lengths sometimes wrong.
fn ulpfec_payload(rng: &mut Lcg, sn_base: u16) -> Vec<u8> {
    let long_mask = rng.below(4) == 0;
    let mut payload = vec![(u8::from(long_mask) << 6) | (rng.byte() & 0x3F), rng.byte()];
    payload.extend_from_slice(&sn_base.to_be_bytes());
    payload.extend_from_slice(&rng.bytes(4));
    let length_recovery = if rng.below(8) == 0 {
        rng.next() as u16
    } else {
        rng.below(64) as u16
    };
    payload.extend_from_slice(&length_recovery.to_be_bytes());
    for _ in 0..=rng.below(3) {
        let length = rng.below(48) as usize;
        let claimed = if rng.below(10) == 0 {
            rng.next() as u16
        } else {
            length as u16
        };
        payload.extend_from_slice(&claimed.to_be_bytes());
        payload.extend_from_slice(&rng.bytes(if long_mask { 6 } else { 2 }));
        payload.extend_from_slice(&rng.bytes(length));
    }
    payload
}

fn ulpfec_input(rng: &mut Lcg) -> Vec<u8> {
    let mut input = vec![rng.byte()];
    // Sequence numbers walk forward from wherever the config byte starts them, sometimes jump.
    let mut sequence = u16::from(input[0]) << 8;
    for _ in 0..rng.below(40) {
        let kind = rng.below(6) as u8;
        let step = if rng.below(20) == 0 {
            [0x80 | rng.byte(), rng.byte()]
        } else {
            [rng.below(3) as u8, 0]
        };
        sequence = if step[0] & 0x80 != 0 {
            u16::from_be_bytes(step)
        } else {
            sequence.wrapping_add(u16::from(step[0] & 0x07))
        };
        let mut arg = step.to_vec();
        match kind {
            // FEC, as a RED block or on the FEC stream: its SN base near the media.
            2 | 4 => {
                let sn_base = sequence.wrapping_sub(rng.below(12) as u16);
                arg.extend_from_slice(&ulpfec_payload(rng, sn_base));
            }
            // RED with whatever block headers come out.
            1 => {
                for _ in 0..rng.below(3) {
                    arg.extend_from_slice(&[
                        0x80 | FEC_PT,
                        rng.byte(),
                        rng.byte() & 0xFC,
                        rng.byte() & 0x3F,
                    ]);
                }
                arg.push(if rng.below(2) == 0 { MEDIA_PT } else { FEC_PT });
                let length = rng.below(80) as usize;
                arg.extend_from_slice(&rng.bytes(length));
            }
            _ => {
                let length = rng.below(60) as usize;
                arg.extend_from_slice(&rng.bytes(length));
            }
        }
        // The op octet: the kind in `op % 6`, the marker bit at random.
        let base = (rng.below(40) as u8) * 6;
        op(&mut input, base.wrapping_add(kind), &arg);
    }
    input
}

#[test]
fn the_ulpfec_receive_fuzz_logic_holds_over_a_fixed_corpus() {
    // What the target stopped on in CI, and the degenerate inputs around it.
    for input in [
        &[10u8, 10][..],
        &[],
        &[0],
        &[10, 10, 0],
        &[255, 4, 0, 0],
        &[2, 3, 0, 1, 9],
    ] {
        ulpfec_receive(input);
    }
    for seed in [0x0A0A_0A0A, 0x5EED_FEC1, 0x5EED_FEC2, 0x5EED_FEC3] {
        let mut rng = Lcg(seed);
        for _ in 0..3_000 {
            ulpfec_receive(&ulpfec_input(&mut rng));
        }
    }
}

// ---------------------------------------------------------------------------------------------
// flexfec_receive
// ---------------------------------------------------------------------------------------------

const FLEX_REPAIR_PT: u8 = 98;

fn flexfec_stream(ssrc: u32, rfc8627: bool, window: u8) -> StreamInfo {
    StreamInfo {
        ssrc,
        ssrc_fec: Some(REPAIR_SSRC),
        payload_type: MEDIA_PT,
        payload_type_fec: Some(FLEX_REPAIR_PT),
        clock_rate: 90_000,
        mime_type: "video/VP8".to_owned(),
        mime_type_fec: if rfc8627 {
            "video/flexfec".to_owned()
        } else {
            "video/flexfec-03".to_owned()
        },
        sdp_fmtp_line_fec: format!("repair-window={}", u32::from(window) * 10_000),
        ..Default::default()
    }
}

/// The body of the `flexfec_receive` fuzz target.
fn flexfec_receive(data: &[u8]) {
    let mut data = data;
    let Some((&config, rest)) = data.split_first() else {
        return;
    };
    data = rest;
    let rfc8627 = config & 0x01 != 0;
    let in_band = config & 0x02 != 0;

    let registry = if rfc8627 {
        let mut builder = FlexFecReceiveBuilder::new();
        if in_band {
            builder = builder.with_in_band_ssrc_mapping(FLEX_REPAIR_PT);
        }
        Registry::new().with(Slot::FecDecoder, builder.build())
    } else {
        Registry::new().with(Slot::FecDecoder, FlexFec03ReceiveBuilder::new().build())
    };
    let mut chain = registry.build();
    let first = flexfec_stream(MEDIA_SSRC, rfc8627, config >> 2);
    let mut second = flexfec_stream(SECOND_SSRC, rfc8627, config >> 2);
    if in_band {
        second.ssrc_fec = None;
        second.payload_type_fec = None;
    }
    chain.bind_remote_stream(&first);
    chain.bind_remote_stream(&second);
    let mut second_bound = true;

    let mut now = Instant::now();
    let mut ops = 0;
    while let Some((&op, rest)) = data.split_first() {
        data = rest;
        ops += 1;
        if ops > 256 {
            break;
        }
        let arg = take_arg(&mut data);
        match op % 6 {
            0..=2 => {
                if let Ok(mut packet) = rtp::Packet::unmarshal(&mut &arg[..]) {
                    match op >> 5 {
                        0 | 1 => {
                            packet.header.ssrc = MEDIA_SSRC;
                            packet.header.payload_type = MEDIA_PT;
                        }
                        2 => packet.header.ssrc = SECOND_SSRC,
                        3 | 4 => {
                            packet.header.ssrc = REPAIR_SSRC;
                            packet.header.payload_type = FLEX_REPAIR_PT;
                        }
                        5 => packet.header.payload_type = FLEX_REPAIR_PT,
                        _ => {}
                    }
                    let _ = chain.handle_read(tagged(now, Packet::Rtp(packet)));
                }
            }
            3 => {
                if let Ok(packets) = rtcp::packet::unmarshal(&mut &arg[..]) {
                    let _ = chain.handle_read(tagged(now, Packet::Rtcp(packets)));
                }
            }
            4 => {
                now += Duration::from_millis(u64::from(u16::from_be_bytes([
                    byte(arg, 0),
                    byte(arg, 1),
                ])));
                let _ = chain.handle_timeout(now);
            }
            _ => {
                if second_bound {
                    chain.unbind_remote_stream(&second);
                } else {
                    chain.bind_remote_stream(&second);
                }
                second_bound = !second_bound;
            }
        }

        let mut budget = 8192;
        while budget > 0
            && let Some(out) = chain.poll_read()
        {
            budget -= 1;
            if out.message.has(&Attribute::RecoveredByFec)
                && let Packet::Rtp(packet) = &out.message.packet
            {
                assert!(
                    packet.header.ssrc == MEDIA_SSRC || packet.header.ssrc == SECOND_SSRC,
                    "recovered a packet of a stream that was never bound"
                );
            }
        }
        while budget > 0 && chain.poll_write().is_some() {
            budget -= 1;
        }
    }
}

/// An RTP packet as bytes: media, or a repair packet with a FlexFEC header whose fields are
/// mostly sane and sometimes not.
fn flexfec_packet(rng: &mut Lcg, sequence: u16, repair: bool) -> Vec<u8> {
    let mut payload = Vec::new();
    let mut csrc = Vec::new();
    if repair {
        for _ in 0..rng.below(3) {
            csrc.push(if rng.below(4) == 0 {
                SECOND_SSRC
            } else {
                MEDIA_SSRC
            });
        }
        // R and F: mostly a flexible-mask repair packet.
        let variant = match rng.below(10) {
            0 => 0x80,
            1 => 0xC0,
            2 | 3 => 0x40,
            _ => 0x00,
        };
        payload.push(variant | (rng.byte() & 0x3F));
        payload.push(rng.byte());
        let length_recovery = if rng.below(8) == 0 {
            rng.next() as u16
        } else {
            rng.below(64) as u16
        };
        payload.extend_from_slice(&length_recovery.to_be_bytes());
        payload.extend_from_slice(&rng.bytes(4));
        for _ in 0..csrc.len().max(1) {
            payload.extend_from_slice(&sequence.wrapping_sub(rng.below(10) as u16).to_be_bytes());
            let mask = rng.bytes(2);
            payload.extend_from_slice(&mask);
            // The k bit says more mask follows; sometimes it lies.
            if mask[0] & 0x80 != 0 && rng.below(5) != 0 {
                let second = rng.bytes(4);
                payload.extend_from_slice(&second);
                if second[0] & 0x80 != 0 && rng.below(5) != 0 {
                    payload.extend_from_slice(&rng.bytes(8));
                }
            }
        }
    }
    let length = rng.below(60) as usize;
    payload.extend_from_slice(&rng.bytes(length));
    rtp::Packet {
        header: Header {
            version: 2,
            marker: rng.below(2) == 0,
            payload_type: MEDIA_PT,
            sequence_number: sequence,
            timestamp: u32::from(sequence) * 3000,
            ssrc: MEDIA_SSRC,
            csrc,
            ..Default::default()
        },
        payload: Bytes::from(payload),
    }
    .marshal()
    .expect("marshal")
    .to_vec()
}

fn flexfec_input(rng: &mut Lcg) -> Vec<u8> {
    let mut input = vec![rng.byte()];
    let mut sequence = rng.next() as u16;
    for _ in 0..rng.below(40) {
        match rng.below(12) {
            // Time passing, a stream going and coming back, stray RTCP.
            0 => op(&mut input, 4, &[rng.byte() & 0x03, rng.byte()]),
            1 => op(&mut input, 5, &[]),
            2 => {
                let bytes = rng.bytes(12);
                op(&mut input, 3, &bytes);
            }
            kind => {
                sequence = sequence.wrapping_add(rng.below(3) as u16);
                let repair = kind >= 8;
                // `op >> 5` steers the packet: 0 media, 2 the second stream, 3 the repair
                // stream, 5 the repair payload type on the media stream.
                let steer: u8 = if repair {
                    if rng.below(6) == 0 { 5 } else { 3 }
                } else if rng.below(4) == 0 {
                    2
                } else {
                    0
                };
                let packet = flexfec_packet(rng, sequence, repair);
                // An op octet that is a multiple of 6 after the steering bits: op % 6 == 0.
                let mut octet = steer << 5;
                while octet % 6 > 2 {
                    octet += 1;
                }
                op(&mut input, octet, &packet);
            }
        }
    }
    input
}

#[test]
fn the_flexfec_receive_fuzz_logic_holds_over_a_fixed_corpus() {
    for input in [&[][..], &[0], &[1], &[3, 5, 0, 0], &[1, 0, 0, 0]] {
        flexfec_receive(input);
    }
    for seed in [0xF1E8_FEC0, 0x5EED_F1E1, 0x5EED_F1E2, 0x5EED_F1E3] {
        let mut rng = Lcg(seed);
        for _ in 0..3_000 {
            flexfec_receive(&flexfec_input(&mut rng));
        }
    }
}
