#![no_main]
//! Stateful target: the FlexFEC receive interceptors (`FlexFec03ReceiveInterceptor` for
//! `flexfec-03`, `FlexFecReceiveInterceptor` for RFC 8627 `flexfec`, with and without in-band
//! SSRC mapping) in a chain, fed an inbound stream: RTP parsed from fuzzed bytes on the media
//! SSRC, on the repair SSRC and on SSRCs nothing was bound for, RTCP, streams unbound and bound
//! again, and time. A recovered packet must belong to a bound media stream.

#[path = "common.rs"]
mod common;

use libfuzzer_sys::fuzz_target;
use rtci::interceptor::{
    Attribute, AttributedPacket, FlexFec03ReceiveBuilder, FlexFecReceiveBuilder, Interceptor,
    Packet, Registry, Slot, StreamInfo, TaggedPacket,
};
use rtci::sansio::Protocol;
use rtci::shared::TransportContext;
use rtci::shared::marshal::Unmarshal;
use std::time::{Duration, Instant};

const MEDIA_SSRC: u32 = 0x1111_1111;
const SECOND_SSRC: u32 = 0x2222_2222;
const REPAIR_SSRC: u32 = 0x3333_3333;
const MEDIA_PT: u8 = 96;
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

fn tagged(now: Instant, packet: Packet) -> TaggedPacket {
    TaggedPacket {
        now,
        transport: TransportContext::default(),
        message: AttributedPacket::new(packet),
    }
}

fn stream(ssrc: u32, rfc8627: bool, window: u8) -> StreamInfo {
    StreamInfo {
        ssrc,
        ssrc_fec: Some(REPAIR_SSRC),
        payload_type: MEDIA_PT,
        payload_type_fec: Some(REPAIR_PT),
        clock_rate: 90000,
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

fuzz_target!(|data: &[u8]| {
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
            builder = builder.with_in_band_ssrc_mapping(REPAIR_PT);
        }
        Registry::new().with(Slot::FecDecoder, builder.build())
    } else {
        Registry::new().with(Slot::FecDecoder, FlexFec03ReceiveBuilder::new().build())
    };
    let mut chain = registry.build();
    let first = stream(MEDIA_SSRC, rfc8627, config >> 2);
    // The second stream shares the repair stream (RFC 8627), or is bound without one (in-band).
    let mut second = stream(SECOND_SSRC, rfc8627, config >> 2);
    if in_band {
        second.ssrc_fec = None;
        second.payload_type_fec = None;
    }
    chain.bind_remote_stream(&first);
    chain.bind_remote_stream(&second);
    let mut second_bound = true;

    let mut now = common::start();
    let mut ops = 0;
    while let Some((&op, rest)) = data.split_first() {
        data = rest;
        ops += 1;
        if ops > 512 {
            break;
        }
        let arg = take_arg(&mut data);
        match op % 6 {
            // Inbound RTP: whatever the bytes parse as, steered onto one of the streams.
            0..=2 => {
                if let Ok(mut packet) = rtci::rtp::packet::Packet::unmarshal(&mut &arg[..]) {
                    match op >> 5 {
                        0 | 1 => {
                            packet.header.ssrc = MEDIA_SSRC;
                            packet.header.payload_type = MEDIA_PT;
                        }
                        2 => packet.header.ssrc = SECOND_SSRC,
                        3 | 4 => {
                            packet.header.ssrc = REPAIR_SSRC;
                            packet.header.payload_type = REPAIR_PT;
                        }
                        5 => packet.header.payload_type = REPAIR_PT,
                        _ => {}
                    }
                    let _ = chain.handle_read(tagged(now, Packet::Rtp(packet)));
                }
            }
            3 => {
                if let Ok(packets) = rtci::rtcp::packet::unmarshal(&mut &arg[..]) {
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
});
