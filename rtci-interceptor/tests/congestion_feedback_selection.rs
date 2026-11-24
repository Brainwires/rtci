//! One congestion control feedback mechanism per stream (RFC 8888 section 6).
//!
//! An offer may name RFC 8888 (`ack ccfb`) beside transport-wide congestion control
//! (`transport-cc`); the answer SHOULD keep one. A chain that carries the interceptors of both
//! runs every stream on exactly one: RFC 8888 when it is among the stream's negotiated feedback,
//! transport-wide congestion control otherwise. These tests drive the chain the default
//! interceptor set builds, in both directions.

use rtci_interceptor::{
    AttributedPacket, BandwidthEstimator, CongestionControlBuilder, CongestionFeedbackFormat,
    Interceptor, Packet, PacketReport, RTCPFeedback, RTPHeaderExtension, Registry, Rfc8888Builder,
    Slot, StreamInfo, TaggedPacket, TwccReceiverBuilder, TwccSenderBuilder,
    negotiated_congestion_feedback,
};
use rtcp::transport_feedbacks::cc_feedback_report::{
    CcFeedbackMetricBlock, CcFeedbackReport, CcFeedbackReportBlock, Ecn,
};
use rtcp::transport_feedbacks::transport_layer_cc::{
    PacketStatusChunk, RecvDelta, RunLengthChunk, StatusChunkTypeTcc, SymbolTypeTcc,
    TransportLayerCc,
};
use sansio::Protocol;
use shared::TransportContext;
use shared::marshal::{Marshal, Unmarshal};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const TRANSPORT_CC_URI: &str =
    "http://www.ietf.org/id/draft-holmer-rmcat-transport-wide-cc-extensions-01";
const TWCC_ID: u8 = 5;
const BOTH: u32 = 0x1111_0001;
const TWCC_ONLY: u32 = 0x2222_0002;
const REMOTE: u32 = 0x5E5E_5E5E;

/// A stream as negotiation leaves it: the transport-cc header extension, `transport-cc`
/// feedback unless the answer dropped it for RFC 8888, and `ack ccfb` when the peer took it.
fn stream(ssrc: u32, ccfb: bool) -> StreamInfo {
    let mut rtcp_feedback = vec![RTCPFeedback {
        typ: "transport-cc".to_owned(),
        parameter: String::new(),
    }];
    if ccfb {
        rtcp_feedback.push(RTCPFeedback {
            typ: "ack".to_owned(),
            parameter: "ccfb".to_owned(),
        });
    }
    StreamInfo {
        ssrc,
        clock_rate: 90_000,
        payload_type: 96,
        rtcp_feedback,
        rtp_header_extensions: vec![RTPHeaderExtension {
            uri: TRANSPORT_CC_URI.to_owned(),
            id: u16::from(TWCC_ID),
        }],
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

/// An RTP packet as a peer that numbers everything sends it: with a transport-wide sequence
/// number, whatever feedback the stream runs on.
fn numbered(ssrc: u32, sequence_number: u16, transport_sequence: u16) -> rtp::Packet {
    let mut header = rtp::header::Header {
        version: 2,
        payload_type: 96,
        sequence_number,
        ssrc,
        ..Default::default()
    };
    let extension =
        rtp::extension::transport_cc_extension::TransportCcExtension { transport_sequence };
    header
        .set_extension(TWCC_ID, extension.marshal().expect("marshal").freeze())
        .expect("set extension");
    rtp::Packet {
        header,
        payload: vec![0u8; 100].into(),
    }
}

fn transport_sequence_of(packet: &rtp::Packet) -> Option<u16> {
    let mut extension = packet.header.get_extension(TWCC_ID)?;
    rtp::extension::transport_cc_extension::TransportCcExtension::unmarshal(&mut extension)
        .ok()
        .map(|extension| extension.transport_sequence)
}

#[test]
fn the_selection_is_exported_for_the_layer_that_writes_the_description() {
    assert_eq!(
        Some(CongestionFeedbackFormat::Rfc8888),
        negotiated_congestion_feedback(&stream(BOTH, true))
    );
    assert_eq!(
        Some(CongestionFeedbackFormat::TransportCc),
        negotiated_congestion_feedback(&stream(TWCC_ONLY, false))
    );
}

/// The receiving half. Both recorders are in the chain; the stream that negotiated RFC 8888 is
/// reported in RFC 8888 reports only, the other in transport-wide feedback only, and no packet
/// is reported twice.
#[test]
fn a_stream_is_reported_in_one_feedback_format() {
    let epoch = Instant::now();
    let mut chain = Registry::new()
        .with(Slot::TwccReceiver, TwccReceiverBuilder::new().build())
        .with(Slot::Rfc8888, Rfc8888Builder::new().build())
        .build();
    chain.bind_remote_stream(&stream(BOTH, true));
    chain.bind_remote_stream(&stream(TWCC_ONLY, false));

    // Ten packets of each stream, interleaved, all carrying a transport-wide sequence number.
    for index in 0..10u16 {
        let at = epoch + Duration::from_millis(u64::from(index) * 5);
        chain
            .handle_read(tagged(
                at,
                Packet::Rtp(numbered(BOTH, 100 + index, index * 2)),
            ))
            .expect("read");
        chain
            .handle_read(tagged(
                at,
                Packet::Rtp(numbered(TWCC_ONLY, 500 + index, index * 2 + 1)),
            ))
            .expect("read");
        while chain.poll_read().is_some() {}
    }

    let mut ccfb_ssrcs = Vec::new();
    let mut ccfb_packets = 0usize;
    let mut twcc_received = 0usize;
    for step in 1..=4u64 {
        chain
            .handle_timeout(epoch + Duration::from_millis(100 * step))
            .expect("timeout");
        while let Some(out) = chain.poll_write() {
            let Packet::Rtcp(packets) = out.message.packet else {
                continue;
            };
            for packet in packets {
                if let Some(report) = packet.as_any().downcast_ref::<CcFeedbackReport>() {
                    for block in &report.report_blocks {
                        ccfb_ssrcs.push(block.media_ssrc);
                        ccfb_packets += block
                            .metric_blocks
                            .iter()
                            .filter(|metric| metric.received)
                            .count();
                    }
                }
                if let Some(feedback) = packet.as_any().downcast_ref::<TransportLayerCc>() {
                    twcc_received += feedback.recv_deltas.len();
                }
            }
        }
    }

    ccfb_ssrcs.dedup();
    assert_eq!(
        vec![BOTH],
        ccfb_ssrcs,
        "RFC 8888 reports the stream that negotiated it"
    );
    assert_eq!(10, ccfb_packets);
    assert_eq!(
        10, twcc_received,
        "transport-wide feedback reports the other stream's ten packets and no more"
    );
}

/// The sending half, part one: a stream that runs on RFC 8888 is not given transport-wide
/// sequence numbers, so there is nothing for a second report to name.
#[test]
fn a_stream_on_rfc8888_is_not_numbered_transport_wide() {
    let epoch = Instant::now();
    let mut chain = Registry::new()
        .with(Slot::TwccSender, TwccSenderBuilder::new().build())
        .build();
    chain.bind_local_stream(&stream(BOTH, true));
    chain.bind_local_stream(&stream(TWCC_ONLY, false));

    let plain = |ssrc: u32| rtp::Packet {
        header: rtp::header::Header {
            version: 2,
            payload_type: 96,
            sequence_number: 1,
            ssrc,
            ..Default::default()
        },
        payload: vec![0u8; 100].into(),
    };
    chain
        .handle_write(tagged(epoch, Packet::Rtp(plain(BOTH))))
        .expect("write");
    chain
        .handle_write(tagged(epoch, Packet::Rtp(plain(TWCC_ONLY))))
        .expect("write");

    let mut numbers = Vec::new();
    while let Some(out) = chain.poll_write() {
        if let Packet::Rtp(packet) = &out.message.packet {
            numbers.push((packet.header.ssrc, transport_sequence_of(packet)));
        }
    }
    assert_eq!(vec![(BOTH, None), (TWCC_ONLY, Some(0))], numbers);
}

/// Every report the estimator is handed.
#[derive(Clone, Default)]
struct Seen(Arc<Mutex<Vec<PacketReport>>>);

impl BandwidthEstimator for Seen {
    fn on_reports(&mut self, _now: Instant, reports: &[PacketReport]) {
        self.0.lock().unwrap().extend_from_slice(reports);
    }
    fn target_bitrate(&self) -> f64 {
        1_000_000.0
    }
}

/// The sending half, part two: a peer that answered both mechanisms and reports in both. The
/// estimator hears about each packet once: the transport-wide stream from transport-wide
/// feedback, the RFC 8888 stream from RFC 8888 reports.
#[test]
fn the_estimator_counts_a_packet_once_when_the_peer_reports_in_both_formats() {
    let epoch = Instant::now();
    let seen = Seen::default();
    let mut chain = Registry::new()
        .with(
            Slot::CongestionControl,
            CongestionControlBuilder::new(seen.clone()).build(),
        )
        .with(Slot::TwccSender, TwccSenderBuilder::new().build())
        .build();
    chain.bind_local_stream(&stream(BOTH, true));
    chain.bind_local_stream(&stream(TWCC_ONLY, false));

    for index in 0..4u16 {
        for ssrc in [BOTH, TWCC_ONLY] {
            let packet = rtp::Packet {
                header: rtp::header::Header {
                    version: 2,
                    payload_type: 96,
                    sequence_number: 10 + index,
                    ssrc,
                    ..Default::default()
                },
                payload: vec![0u8; 100].into(),
            };
            chain
                .handle_write(tagged(
                    epoch + Duration::from_millis(u64::from(index) * 10),
                    Packet::Rtp(packet),
                ))
                .expect("write");
        }
        while chain.poll_write().is_some() {}
    }

    let metric = CcFeedbackMetricBlock {
        received: true,
        ecn: Ecn::NotEct,
        arrival_time_offset: 10,
    };
    let block = |media_ssrc: u32| CcFeedbackReportBlock {
        media_ssrc,
        begin_sequence: 10,
        metric_blocks: vec![metric; 4],
    };
    // RFC 8888 reports about both streams: only the RFC 8888 stream's is to be read.
    let ccfb = CcFeedbackReport {
        sender_ssrc: REMOTE,
        report_blocks: vec![block(BOTH), block(TWCC_ONLY)],
        report_timestamp: 0x0001_0000,
    };
    // Transport-wide feedback for the four numbered packets (the transport-wide stream's).
    let twcc = TransportLayerCc {
        sender_ssrc: REMOTE,
        media_ssrc: TWCC_ONLY,
        base_sequence_number: 0,
        packet_status_count: 4,
        reference_time: 1,
        fb_pkt_count: 0,
        packet_chunks: vec![PacketStatusChunk::RunLengthChunk(RunLengthChunk {
            type_tcc: StatusChunkTypeTcc::RunLengthChunk,
            packet_status_symbol: SymbolTypeTcc::PacketReceivedSmallDelta,
            run_length: 4,
        })],
        recv_deltas: (0..4)
            .map(|_| RecvDelta {
                type_tcc_packet: SymbolTypeTcc::PacketReceivedSmallDelta,
                delta: 10_000,
            })
            .collect(),
    };
    chain
        .handle_read(tagged(
            epoch + Duration::from_millis(100),
            Packet::Rtcp(vec![Box::new(ccfb), Box::new(twcc)]),
        ))
        .expect("read");
    while chain.poll_read().is_some() {}

    let reports = seen.0.lock().unwrap();
    assert_eq!(
        8,
        reports.len(),
        "four packets of each stream, each reported once: {reports:?}"
    );
}
