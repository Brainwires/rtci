//! The logic of the `interceptor_inbound` fuzz target, run over a fixed corpus.
//!
//! The fuzz target runs in CI's fuzz job only. This is the same driver as a unit test, over
//! inputs that never change: a fixed linear congruential sequence shaped into what a peer sends
//! at the congestion controller (transport-wide and RFC 8888 feedback, REMB, TMMBR, receiver
//! reports, NACK, BYE, some of it damaged), RTP in both directions and steps of the clock. The
//! chain is the one a peer connection builds by default, with its settings varied: both
//! feedback formats or one, bandwidth probing on or off, a stream that negotiated RFC 8888 or
//! transport-wide congestion control. Nothing may panic, the chain's queues drain, and the
//! congestion controller's target stays a finite number that is not negative.

use bytes::Bytes;
use rtc::interceptor::{
    AttributedPacket, Interceptor, Packet, RTCPFeedback, RTPHeaderExtension, Registry, StreamInfo,
    TaggedPacket,
};
use rtc::peer_connection::configuration::interceptor_registry::{
    CongestionFeedback, DefaultInterceptorOptions, register_default_interceptors_with_options,
};
use rtc::peer_connection::configuration::media_engine::MediaEngine;
use rtc::rtcp::goodbye::Goodbye;
use rtc::rtcp::payload_feedbacks::receiver_estimated_maximum_bitrate::ReceiverEstimatedMaximumBitrate;
use rtc::rtcp::raw_packet::RawPacket;
use rtc::rtcp::receiver_report::ReceiverReport;
use rtc::rtcp::reception_report::ReceptionReport;
use rtc::rtcp::transport_feedbacks::cc_feedback_report::{
    CcFeedbackMetricBlock, CcFeedbackReport, CcFeedbackReportBlock, Ecn,
};
use rtc::rtcp::transport_feedbacks::transport_layer_cc::{
    PacketStatusChunk, RecvDelta, RunLengthChunk, StatusChunkTypeTcc, SymbolTypeTcc,
    TransportLayerCc,
};
use rtc::rtcp::transport_feedbacks::transport_layer_nack::{NackPair, TransportLayerNack};
use rtc::rtp::header::Header;
use rtc::sansio::Protocol;
use rtc::sdp::extmap::TRANSPORT_CC_URI;
use rtc::shared::TransportContext;
use rtc::shared::marshal::{Marshal, Unmarshal};
use std::time::{Duration, Instant};

const LOCAL_SSRC: u32 = 0x1111_1111;
const LOCAL_RTX_SSRC: u32 = 0x2222_2222;
const REMOTE_SSRC: u32 = 0x3333_3333;
const TWCC_ID: u16 = 5;

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
        self.next() % bound.max(1)
    }
}

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

fn stream_info(ssrc: u32, rtx: Option<u32>, ccfb: bool) -> StreamInfo {
    let feedback = |typ: &str, parameter: &str| RTCPFeedback {
        typ: typ.to_owned(),
        parameter: parameter.to_owned(),
    };
    let mut rtcp_feedback = vec![
        feedback("nack", ""),
        feedback("nack", "pli"),
        feedback("ccm", "fir"),
        feedback("ccm", "tmmbr"),
        feedback("transport-cc", ""),
    ];
    if ccfb {
        rtcp_feedback.push(feedback("ack", "ccfb"));
    }
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
        rtcp_feedback,
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

/// Drains the chain, and says whether it emptied within the budget.
fn drain(chain: &mut impl Interceptor) -> bool {
    let mut budget = 8192;
    while budget > 0 && chain.poll_read().is_some() {
        budget -= 1;
    }
    while budget > 0 && chain.poll_write().is_some() {
        budget -= 1;
    }
    budget > 0
}

/// The fuzz target's body, with the chain's settings taken from the first byte.
fn interceptor_inbound(data: &[u8]) {
    let mut data = data;
    let Some((&config, rest)) = data.split_first() else {
        return;
    };
    data = rest;

    let mut media_engine = MediaEngine::default();
    media_engine
        .register_default_codecs()
        .expect("default codecs");
    let mut options = DefaultInterceptorOptions::default();
    options.congestion_feedback = match config & 0x03 {
        0 | 1 => CongestionFeedback::Negotiated,
        2 => CongestionFeedback::Twcc,
        _ => CongestionFeedback::Rfc8888,
    };
    options.bandwidth_probing = config & 0x04 != 0;
    options.unnegotiated_tmmbr = config & 0x08 != 0;
    options.pacer_immediate_release = config & 0x10 == 0;
    let (registry, handles) =
        register_default_interceptors_with_options(Registry::new(), &mut media_engine, &options)
            .expect("default interceptors");
    let mut chain = registry.build();
    let ccfb = config & 0x20 != 0;
    let local = stream_info(LOCAL_SSRC, Some(LOCAL_RTX_SSRC), ccfb);
    let remote = stream_info(REMOTE_SSRC, None, ccfb);
    chain.bind_local_stream(&local);
    chain.bind_remote_stream(&remote);

    let mut now = Instant::now();
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
        assert!(drain(&mut chain), "the chain's queues did not drain");

        // Zero is a target too: the circuit breaker has stopped the flow (RFC 8083).
        let target = handles.congestion_control.target_bitrate();
        assert!(
            target.is_finite() && target >= 0.0,
            "the target bit rate is {target}"
        );
    }
}

// ---------------------------------------------------------------------------------------------
// The corpus
// ---------------------------------------------------------------------------------------------

/// Transport-wide feedback about sequence numbers near `base`.
fn twcc(rng: &mut Lcg, base: u16) -> Box<dyn rtc::rtcp::packet::Packet> {
    let count = 1 + rng.below(12) as u16;
    let mut packet_chunks = Vec::new();
    let mut recv_deltas = Vec::new();
    for _ in 0..count {
        let symbol = match rng.below(8) {
            0 => SymbolTypeTcc::PacketNotReceived,
            1 => SymbolTypeTcc::PacketReceivedLargeDelta,
            _ => SymbolTypeTcc::PacketReceivedSmallDelta,
        };
        match symbol {
            SymbolTypeTcc::PacketReceivedSmallDelta => recv_deltas.push(RecvDelta {
                type_tcc_packet: symbol,
                delta: i64::from(rng.below(256)) * 250,
            }),
            SymbolTypeTcc::PacketReceivedLargeDelta => recv_deltas.push(RecvDelta {
                type_tcc_packet: symbol,
                delta: (i64::from(rng.below(65_536)) - 32_768) * 250,
            }),
            _ => {}
        }
        packet_chunks.push(PacketStatusChunk::RunLengthChunk(RunLengthChunk {
            type_tcc: StatusChunkTypeTcc::RunLengthChunk,
            packet_status_symbol: symbol,
            run_length: 1,
        }));
    }
    Box::new(TransportLayerCc {
        sender_ssrc: REMOTE_SSRC,
        media_ssrc: LOCAL_SSRC,
        base_sequence_number: base.wrapping_add(rng.below(4) as u16),
        packet_status_count: count,
        // Near the 24-bit wrap now and then.
        reference_time: if rng.below(16) == 0 {
            0x00FF_FFF0 + rng.below(32)
        } else {
            rng.below(4096)
        } & 0x00FF_FFFF,
        fb_pkt_count: rng.byte(),
        packet_chunks,
        recv_deltas,
    })
}

/// RFC 8888 feedback about RTP sequence numbers near `base`.
fn ccfb(rng: &mut Lcg, base: u16) -> Box<dyn rtc::rtcp::packet::Packet> {
    let blocks = 1 + rng.below(3);
    let report_blocks = (0..blocks)
        .map(|index| CcFeedbackReportBlock {
            media_ssrc: match (index, rng.below(6)) {
                (0, _) => LOCAL_SSRC,
                (_, 0) => LOCAL_RTX_SSRC,
                (_, 1) => rng.next(),
                _ => LOCAL_SSRC,
            },
            begin_sequence: base.wrapping_sub(rng.below(8) as u16),
            metric_blocks: (0..rng.below(24))
                .map(|_| CcFeedbackMetricBlock {
                    received: rng.below(6) != 0,
                    ecn: match rng.below(4) {
                        0 => Ecn::NotEct,
                        1 => Ecn::Ect1,
                        2 => Ecn::Ect0,
                        _ => Ecn::Ce,
                    },
                    // The reserved values 0x1FFE and 0x1FFF among them.
                    arrival_time_offset: if rng.below(12) == 0 {
                        0x1FFE + rng.below(2) as u16
                    } else {
                        rng.below(0x1FFE) as u16
                    },
                })
                .collect(),
        })
        .collect();
    Box::new(CcFeedbackReport {
        sender_ssrc: REMOTE_SSRC,
        report_blocks,
        report_timestamp: if rng.below(16) == 0 {
            0xFFFF_FF00 + rng.below(256)
        } else {
            rng.next() << 4
        },
    })
}

/// A TMMBR (RFC 5104 section 4.2.1) with one entry, as raw octets.
fn tmmbr(rng: &mut Lcg) -> Box<dyn rtc::rtcp::packet::Packet> {
    let mut raw = vec![0x83, 205, 0, 4];
    raw.extend_from_slice(&REMOTE_SSRC.to_be_bytes());
    raw.extend_from_slice(&0u32.to_be_bytes());
    let target = if rng.below(4) == 0 {
        rng.next()
    } else {
        LOCAL_SSRC
    };
    raw.extend_from_slice(&target.to_be_bytes());
    let exponent = rng.below(64);
    let mantissa = rng.below(1 << 17);
    let overhead = rng.below(512);
    raw.extend_from_slice(&(exponent << 26 | mantissa << 9 | overhead).to_be_bytes());
    Box::new(RawPacket(Bytes::from(raw)))
}

fn rtcp_argument(rng: &mut Lcg, local_seq: u16) -> Vec<u8> {
    let mut packets: Vec<Box<dyn rtc::rtcp::packet::Packet>> = Vec::new();
    for _ in 0..1 + rng.below(3) {
        packets.push(match rng.below(9) {
            0..=2 => {
                let base = rng.below(64) as u16;
                twcc(rng, base)
            }
            3 | 4 => ccfb(rng, local_seq),
            5 => Box::new(ReceiverEstimatedMaximumBitrate {
                sender_ssrc: REMOTE_SSRC,
                bitrate: match rng.below(6) {
                    0 => 0.0,
                    1 => f32::MAX,
                    _ => rng.below(10_000_000) as f32,
                },
                ssrcs: if rng.below(3) == 0 {
                    vec![]
                } else {
                    vec![LOCAL_SSRC]
                },
            }),
            6 => tmmbr(rng),
            7 => Box::new(ReceiverReport {
                ssrc: REMOTE_SSRC,
                reports: vec![ReceptionReport {
                    ssrc: LOCAL_SSRC,
                    fraction_lost: rng.byte(),
                    total_lost: rng.below(1 << 24),
                    last_sequence_number: u32::from(local_seq),
                    jitter: rng.below(10_000),
                    last_sender_report: rng.next(),
                    delay: rng.below(1 << 16),
                }],
                ..Default::default()
            }),
            _ => {
                if rng.below(4) == 0 {
                    Box::new(Goodbye {
                        sources: vec![REMOTE_SSRC],
                        ..Default::default()
                    })
                } else {
                    Box::new(TransportLayerNack {
                        sender_ssrc: REMOTE_SSRC,
                        media_ssrc: LOCAL_SSRC,
                        nacks: vec![NackPair {
                            packet_id: local_seq.wrapping_sub(rng.below(32) as u16),
                            lost_packets: rng.next() as u16,
                        }],
                    })
                }
            }
        });
    }
    let mut raw = rtc::rtcp::packet::marshal(&packets)
        .map(|bytes| bytes.to_vec())
        .unwrap_or_default();
    // One input in six is damaged: a byte changed, or the end cut off.
    if !raw.is_empty() {
        match rng.below(12) {
            0 => {
                let at = rng.below(raw.len() as u32) as usize;
                raw[at] ^= 1 << rng.below(8);
            }
            1 => {
                let keep = rng.below(raw.len() as u32) as usize;
                raw.truncate(keep);
            }
            _ => {}
        }
    }
    raw
}

fn rtp_argument(rng: &mut Lcg, sequence_number: u16) -> Vec<u8> {
    let mut header = Header {
        version: 2,
        payload_type: 96,
        sequence_number,
        timestamp: rng.next(),
        ssrc: REMOTE_SSRC,
        ..Default::default()
    };
    if rng.below(8) != 0 {
        let extension = rtc::rtp::extension::transport_cc_extension::TransportCcExtension {
            transport_sequence: sequence_number.wrapping_add(rng.below(3) as u16),
        };
        if let Ok(payload) = extension.marshal() {
            let _ = header.set_extension(TWCC_ID as u8, payload.freeze());
        }
    }
    let packet = rtc::rtp::packet::Packet {
        header,
        payload: Bytes::from(vec![0u8; rng.below(64) as usize]),
    };
    packet
        .marshal()
        .map(|bytes| bytes.to_vec())
        .unwrap_or_default()
}

fn op(input: &mut Vec<u8>, op: u8, arg: &[u8]) {
    input.push(op);
    input.extend_from_slice(&(arg.len() as u16).to_be_bytes());
    input.extend_from_slice(arg);
}

/// One input: a configuration byte, then a session of sixty to two hundred operations in
/// which media flows both ways, the clock moves and the peer reports.
fn input(rng: &mut Lcg) -> Vec<u8> {
    let config = rng.byte();
    let mut input = vec![config];
    let mut local_seq: u16 = u16::from(config) << 8;
    let mut remote_seq = rng.next() as u16;
    for _ in 0..60 + rng.below(140) {
        match rng.below(16) {
            0..=4 => {
                let argument = rtcp_argument(rng, local_seq);
                op(&mut input, rng.below(2) as u8, &argument);
            }
            5..=7 => {
                remote_seq = remote_seq.wrapping_add(1 + rng.below(3) as u16);
                let argument = rtp_argument(rng, remote_seq);
                let stray = if rng.below(16) == 0 { 0x80 } else { 0 };
                op(&mut input, 2 | stray, &argument);
            }
            8..=12 => {
                let step = rng.below(4) as u8;
                local_seq = local_seq.wrapping_add(1 + u16::from(step));
                let mut argument = vec![step, rng.byte()];
                argument.extend((0..rng.below(1200)).map(|_| 0u8));
                op(&mut input, 3, &argument);
            }
            13 | 14 => {
                // Mostly a few milliseconds, sometimes seconds.
                let millis = if rng.below(8) == 0 {
                    rng.below(8_000)
                } else {
                    rng.below(120)
                } as u16;
                op(&mut input, 4, &millis.to_be_bytes());
            }
            _ => {
                let rebind = if rng.below(2) == 0 { 0x80 } else { 0 };
                op(&mut input, 5 | rebind, &[]);
            }
        }
    }
    input
}

#[test]
fn the_interceptor_inbound_fuzz_logic_holds_over_a_fixed_corpus() {
    // The degenerate inputs first.
    for input in [
        &[][..],
        &[0],
        &[0xFF, 0, 0, 0],
        &[4, 4, 0, 2, 0xFF, 0xFF, 4, 0, 2, 0xFF, 0xFF],
        &[0x24, 3, 0, 0, 3, 0, 0, 4, 0, 2, 0x13, 0x88, 0, 0, 0],
    ] {
        interceptor_inbound(input);
    }
    let mut rng = Lcg(0xC0FF_EE01);
    for _ in 0..1_500 {
        interceptor_inbound(&input(&mut rng));
    }
}
