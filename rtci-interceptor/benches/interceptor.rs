//! Per-packet cost of the interceptors on a call's hot path.
//!
//! Run with `cargo bench --package rtci-interceptor --bench interceptor`.
//!
//! Each benchmark drives one interceptor by itself, as an application drives it without a chain,
//! with the clock handed in (no sleeping, no socket):
//!
//! * `Pacer/write+poll` hands the pacer one full-sized packet, fires its timeout and takes what it
//!   releases. The target rate is far above the offered rate, so every packet leaves at once and
//!   the figure is the pacer's bookkeeping, not its schedule (`tests/pacing.rs` holds that).
//! * `NackResponder/buffer` is the cost the responder adds to every packet sent: it keeps a copy
//!   for retransmission. `NackResponder/buffer+answer` adds a NACK for a packet sent 16 packets
//!   earlier and the retransmission it makes.
//! * `Gcc/feedback-10` is the estimator's handling of one feedback report naming ten packets (a
//!   100 ms feedback interval at about 1 Mbit/s).
//! * `Ulpfec/encode-10x1200` makes one ULPFEC packet over ten 1200-byte media packets.
//!
//! `benches/congestion_control.rs` is not a timing benchmark: it reports how well GCC uses a
//! simulated path. The pull-request job of `.github/workflows/bench.yml` compares these figures
//! with the base branch (`scripts/bench-compare.py`; `docs/performance.md`).

use std::time::{Duration, Instant};

use bytes::Bytes;
use criterion::{Criterion, criterion_group, criterion_main};
use rtci_interceptor::{
    AttributedPacket, BandwidthEstimator, GCC_MAX_BITRATE, GCC_MIN_BITRATE, Gcc, Interceptor,
    NackResponderBuilder, PacerBuilder, Packet, PacketReport, RTCPFeedback, StreamInfo,
    TaggedPacket, UlpfecEncoder, UlpfecProtectionLevel,
};
use rtcp::transport_feedbacks::transport_layer_nack::{NackPair, TransportLayerNack};
use sansio::Protocol;
use shared::TransportContext;

const SSRC: u32 = 0x1234;
const RTX_SSRC: u32 = 0x5678;
/// 12-byte RTP header plus this payload is 1200 bytes, the usual video packet.
const PAYLOAD_BYTES: usize = 1188;

fn video_packet(now: Instant, sequence_number: u16, payload: &Bytes) -> TaggedPacket {
    TaggedPacket {
        now,
        transport: TransportContext::default(),
        message: AttributedPacket::new(Packet::Rtp(rtp::Packet {
            header: rtp::header::Header {
                version: 2,
                payload_type: 96,
                sequence_number,
                timestamp: u32::from(sequence_number).wrapping_mul(3000),
                ssrc: SSRC,
                ..Default::default()
            },
            payload: payload.clone(),
        })),
    }
}

fn nack(now: Instant, sequence_number: u16) -> TaggedPacket {
    TaggedPacket {
        now,
        transport: TransportContext::default(),
        message: AttributedPacket::new(Packet::Rtcp(vec![Box::new(TransportLayerNack {
            sender_ssrc: 1,
            media_ssrc: SSRC,
            nacks: vec![NackPair {
                packet_id: sequence_number,
                lost_packets: 0,
            }],
        })])),
    }
}

fn video_stream() -> StreamInfo {
    StreamInfo {
        ssrc: SSRC,
        ssrc_rtx: Some(RTX_SSRC),
        clock_rate: 90000,
        mime_type: "video/VP8".to_string(),
        payload_type: 96,
        payload_type_rtx: Some(97),
        rtcp_feedback: vec![RTCPFeedback {
            typ: "nack".to_string(),
            parameter: String::new(),
        }],
        ..Default::default()
    }
}

/// Everything the interceptor hands on, written and read; how many written.
fn drain(chain: &mut impl Interceptor) -> usize {
    let mut written = 0;
    while chain.poll_write().is_some() {
        written += 1;
    }
    while chain.poll_read().is_some() {}
    written
}

fn pacer(c: &mut Criterion) {
    let payload = Bytes::from(vec![0u8; PAYLOAD_BYTES]);
    let mut chain = PacerBuilder::new()
        .with_target_bitrate(1e9)
        .with_burst_bits(1e6)
        .build();
    let epoch = Instant::now();
    let mut now = epoch;
    let mut sequence_number = 0u16;

    // What is timed is a release: a packet that waited would make the figure the queue's.
    chain
        .handle_write(video_packet(now, sequence_number, &payload))
        .unwrap();
    chain.handle_timeout(now).unwrap();
    assert_eq!(
        1,
        drain(&mut chain),
        "the pacer released the packet at once"
    );

    c.bench_function("Interceptor/Pacer/write+poll", |b| {
        b.iter(|| {
            now += Duration::from_millis(1);
            sequence_number = sequence_number.wrapping_add(1);
            chain
                .handle_write(video_packet(now, sequence_number, &payload))
                .unwrap();
            chain.handle_timeout(now).unwrap();
            drain(&mut chain)
        });
    });
}

fn nack_responder(c: &mut Criterion) {
    let payload = Bytes::from(vec![0u8; PAYLOAD_BYTES]);

    let mut chain = NackResponderBuilder::new().build();
    chain.bind_local_stream(&video_stream());
    let mut now = Instant::now();
    let mut sequence_number = 0u16;
    c.bench_function("Interceptor/NackResponder/buffer", |b| {
        b.iter(|| {
            now += Duration::from_millis(1);
            sequence_number = sequence_number.wrapping_add(1);
            chain
                .handle_write(video_packet(now, sequence_number, &payload))
                .unwrap();
            drain(&mut chain)
        });
    });

    let mut chain = NackResponderBuilder::new().build();
    chain.bind_local_stream(&video_stream());
    let mut now = Instant::now();
    let mut sequence_number = 0u16;
    for _ in 0..32 {
        now += Duration::from_millis(1);
        sequence_number = sequence_number.wrapping_add(1);
        chain
            .handle_write(video_packet(now, sequence_number, &payload))
            .unwrap();
        drain(&mut chain);
    }
    chain
        .handle_read(nack(now, sequence_number.wrapping_sub(16)))
        .unwrap();
    chain.handle_timeout(now).unwrap();
    assert_eq!(1, drain(&mut chain), "the NACK was answered");

    c.bench_function("Interceptor/NackResponder/buffer+answer", |b| {
        b.iter(|| {
            now += Duration::from_millis(1);
            sequence_number = sequence_number.wrapping_add(1);
            chain
                .handle_write(video_packet(now, sequence_number, &payload))
                .unwrap();
            drain(&mut chain);
            chain
                .handle_read(nack(now, sequence_number.wrapping_sub(16)))
                .unwrap();
            chain.handle_timeout(now).unwrap();
            drain(&mut chain)
        });
    });
}

fn gcc(c: &mut Criterion) {
    const PACKETS: u64 = 10;
    const SPACING: Duration = Duration::from_millis(10);
    const ONE_WAY: Duration = Duration::from_millis(20);

    let epoch = Instant::now();
    let mut gcc = Gcc::new(1_000_000.0, GCC_MIN_BITRATE, GCC_MAX_BITRATE);
    let mut next_id = 0u64;
    let mut reports = Vec::with_capacity(PACKETS as usize);

    c.bench_function("Interceptor/Gcc/feedback-10", |b| {
        b.iter(|| {
            reports.clear();
            for _ in 0..PACKETS {
                let departure = epoch + SPACING * next_id as u32;
                let sequence = next_id as u16;
                reports.push(PacketReport {
                    ssrc: SSRC,
                    id: next_id,
                    rtp_sequence_number: sequence,
                    is_twcc: true,
                    twcc_sequence_number: sequence,
                    size: 1200,
                    arrived: true,
                    departure,
                    arrival: Some(departure.duration_since(epoch) + ONE_WAY),
                    ecn: rtcp::transport_feedbacks::cc_feedback_report::Ecn::default(),
                });
                next_id += 1;
            }
            let now = epoch + SPACING * next_id as u32 + ONE_WAY;
            gcc.on_reports(now, &reports);
            gcc.target_bitrate()
        });
    });
}

fn ulpfec(c: &mut Criterion) {
    let media: Vec<rtp::Packet> = (0..10u16)
        .map(|sequence_number| rtp::Packet {
            header: rtp::header::Header {
                version: 2,
                payload_type: 96,
                sequence_number,
                timestamp: 3000,
                ssrc: SSRC,
                marker: sequence_number == 9,
                ..Default::default()
            },
            payload: Bytes::from(vec![sequence_number as u8; PAYLOAD_BYTES]),
        })
        .collect();
    let length = UlpfecEncoder::full_protection_length(&media).unwrap();
    let levels = [UlpfecProtectionLevel::new(
        length,
        (0..10u16).collect::<Vec<_>>(),
    )];
    let encoder = UlpfecEncoder::new();
    encoder.encode(&media, &levels).unwrap();

    c.bench_function("Interceptor/Ulpfec/encode-10x1200", |b| {
        b.iter(|| encoder.encode(&media, &levels).unwrap());
    });
}

criterion_group!(benches, pacer, nack_responder, gcc, ulpfec);
criterion_main!(benches);
