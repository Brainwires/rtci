#![no_main]
//! Stateful target: the interceptor chain a peer connection builds by default (NACK generator and
//! responder, TWCC, RTCP reports, key-frame requests, optionally the TWCC sender), fed what a peer
//! sends: RTCP compound packets parsed from fuzzed bytes (NACK, TWCC, receiver and sender reports,
//! PLI / FIR, SDES, BYE, XR), and RTP on the bound remote stream with fuzzed sequence numbers.
//! Outbound media fills the send history the NACK responder answers from. The clock advances by
//! input-chosen steps so every generator's timer fires. No randomness beyond the chain's own.

#[path = "common.rs"]
mod common;

use bytes::Bytes;
use libfuzzer_sys::fuzz_target;
use rtc::interceptor::{
    AttributedPacket, Interceptor, Packet, RTCPFeedback, RTPHeaderExtension, Registry, StreamInfo,
    TaggedPacket,
};
use rtc::peer_connection::configuration::interceptor_registry::{
    configure_twcc, register_default_interceptors,
};
use rtc::peer_connection::configuration::media_engine::MediaEngine;
use rtc::rtp::header::Header;
use rtc::sansio::Protocol;
use rtc::sdp::extmap::TRANSPORT_CC_URI;
use rtc::shared::TransportContext;
use rtc::shared::marshal::Unmarshal;
use std::time::{Duration, Instant};

const LOCAL_SSRC: u32 = 0x1111_1111;
const LOCAL_RTX_SSRC: u32 = 0x2222_2222;
const REMOTE_SSRC: u32 = 0x3333_3333;
const TWCC_ID: u16 = 5;

fn byte(arg: &[u8], i: usize) -> u8 {
    arg.get(i).copied().unwrap_or(0)
}

/// Splits the next op argument off `data`: a two-byte length, then that many bytes.
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

fn stream_info(ssrc: u32, rtx: Option<u32>) -> StreamInfo {
    let feedback = |typ: &str, parameter: &str| RTCPFeedback {
        typ: typ.to_owned(),
        parameter: parameter.to_owned(),
    };
    StreamInfo {
        ssrc,
        ssrc_rtx: rtx,
        payload_type: 96,
        payload_type_rtx: rtx.map(|_| 97),
        rtp_header_extensions: vec![RTPHeaderExtension {
            uri: TRANSPORT_CC_URI.to_owned(),
            id: TWCC_ID,
        }],
        mime_type: "video/VP8".to_owned(),
        clock_rate: 90000,
        rtcp_feedback: vec![
            feedback("nack", ""),
            feedback("nack", "pli"),
            feedback("ccm", "fir"),
            feedback("transport-cc", ""),
        ],
        ..Default::default()
    }
}

fn tagged(now: Instant, packet: Packet) -> TaggedPacket {
    TaggedPacket {
        now,
        transport: TransportContext::default(),
        message: AttributedPacket::new(packet),
    }
}

fn drain(chain: &mut impl Interceptor) {
    let mut budget = 8192;
    while budget > 0 && chain.poll_read().is_some() {
        budget -= 1;
    }
    while budget > 0 && chain.poll_write().is_some() {
        budget -= 1;
    }
}

fuzz_target!(|data: &[u8]| {
    let mut data = data;
    let Some((&config, rest)) = data.split_first() else {
        return;
    };
    data = rest;

    let mut media_engine = MediaEngine::default();
    if media_engine.register_default_codecs().is_err() {
        return;
    }
    let Ok(mut registry) = register_default_interceptors(Registry::new(), &mut media_engine) else {
        return;
    };
    if config & 0x01 != 0 {
        let Ok(with_twcc) = configure_twcc(registry, &mut media_engine) else {
            return;
        };
        registry = with_twcc;
    }
    let mut chain = registry.build();
    let local = stream_info(LOCAL_SSRC, Some(LOCAL_RTX_SSRC));
    let remote = stream_info(REMOTE_SSRC, None);
    chain.bind_local_stream(&local);
    chain.bind_remote_stream(&remote);

    let mut now = common::start();
    let mut local_seq: u16 = u16::from(config) << 8;
    let mut ops = 0;
    while let Some((&op, rest)) = data.split_first() {
        data = rest;
        ops += 1;
        if ops > 512 {
            break;
        }
        let arg = take_arg(&mut data);
        match op % 6 {
            // Inbound RTCP, as parsed from what the peer sent.
            0 | 1 => {
                if let Ok(packets) = rtc::rtcp::packet::unmarshal(&mut &arg[..]) {
                    let _ = chain.handle_read(tagged(now, Packet::Rtcp(packets)));
                }
            }
            // Inbound RTP: parsed from the input, on the remote stream unless the op says not.
            2 => {
                if let Ok(mut packet) = rtc::rtp::packet::Packet::unmarshal(&mut &arg[..]) {
                    if op & 0x80 == 0 {
                        packet.header.ssrc = REMOTE_SSRC;
                    }
                    let _ = chain.handle_read(tagged(now, Packet::Rtp(packet)));
                }
            }
            // Outbound RTP on the local stream, so the send history has something in it.
            3 => {
                local_seq = local_seq.wrapping_add(1 + u16::from(byte(arg, 0) & 0x03));
                let packet = rtc::rtp::packet::Packet {
                    header: Header {
                        version: 2,
                        marker: byte(arg, 1) & 0x01 != 0,
                        payload_type: 96,
                        sequence_number: local_seq,
                        timestamp: u32::from(local_seq) * 3000,
                        ssrc: LOCAL_SSRC,
                        ..Default::default()
                    },
                    payload: Bytes::copy_from_slice(arg.get(2..).unwrap_or(&[])),
                };
                let _ = chain.handle_write(tagged(now, Packet::Rtp(packet)));
            }
            4 => {
                now += Duration::from_millis(u64::from(u16::from_be_bytes([
                    byte(arg, 0),
                    byte(arg, 1),
                ])));
                let _ = chain.handle_timeout(now);
                if let Some(deadline) = chain.poll_timeout()
                    && deadline <= now
                {
                    let _ = chain.handle_timeout(now);
                }
            }
            _ => {
                // The remote stream goes away and comes back (renegotiation, a new track).
                chain.unbind_remote_stream(&remote);
                if op & 0x80 == 0 {
                    chain.bind_remote_stream(&remote);
                }
            }
        }
        drain(&mut chain);
    }
});
