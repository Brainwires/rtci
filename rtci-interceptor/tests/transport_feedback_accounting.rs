//! What the congestion controller is told about the packets it sent.
//!
//! The estimator can only be as right as its input. These tests pin the accounting rules of
//! draft-holmer-rmcat-transport-wide-cc-extensions-01 and RFC 8888 that the input depends on: a
//! packet no feedback described has no verdict, every packet on the transport is numbered, and
//! the pacer starts from the estimator's rate.

use rtci_interceptor::{
    AttributedPacket, BandwidthEstimator, CongestionControlBuilder, Gcc, Interceptor, PacerBuilder,
    Packet, PacketReport, RTCPFeedback, RTPHeaderExtension, Registry, Slot, StreamInfo,
    TaggedPacket, TwccSenderBuilder,
};
use rtcp::transport_feedbacks::transport_layer_cc::{
    PacketStatusChunk, RecvDelta, RunLengthChunk, StatusChunkTypeTcc, SymbolTypeTcc,
    TransportLayerCc,
};
use sansio::Protocol;
use shared::TransportContext;
use shared::marshal::{MarshalSize, Unmarshal};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const TRANSPORT_CC_URI: &str =
    "http://www.ietf.org/id/draft-holmer-rmcat-transport-wide-cc-extensions-01";
const TWCC_ID: u8 = 5;

const MEDIA_SSRC: u32 = 0x0A0B_0C0D;
const RTX_SSRC: u32 = 0x0A0B_0C0E;
const FEC_SSRC: u32 = 0x0A0B_0C0F;

/// An estimator that records what it was told.
#[derive(Clone, Default)]
struct Recorder {
    seen: Arc<Mutex<Vec<PacketReport>>>,
}

impl Recorder {
    fn reports(&self) -> Vec<PacketReport> {
        self.seen.lock().unwrap().clone()
    }
}

impl BandwidthEstimator for Recorder {
    fn on_reports(&mut self, _now: Instant, reports: &[PacketReport]) {
        self.seen.lock().unwrap().extend_from_slice(reports);
    }
    fn target_bitrate(&self) -> f64 {
        1_000_000.0
    }
}

fn chain(estimator: Recorder) -> impl Interceptor {
    Registry::new()
        .with(
            Slot::CongestionControl,
            CongestionControlBuilder::new(estimator).build(),
        )
        .with(Slot::TwccSender, TwccSenderBuilder::new().build())
        .build()
}

fn transport_cc(ssrc: u32) -> StreamInfo {
    StreamInfo {
        ssrc,
        clock_rate: 90_000,
        mime_type: "video/VP8".to_owned(),
        payload_type: 96,
        rtcp_feedback: vec![RTCPFeedback {
            typ: "transport-cc".to_owned(),
            parameter: String::new(),
        }],
        rtp_header_extensions: vec![RTPHeaderExtension {
            uri: TRANSPORT_CC_URI.to_owned(),
            id: u16::from(TWCC_ID),
        }],
        ..Default::default()
    }
}

fn rtp(now: Instant, ssrc: u32, sequence_number: u16) -> TaggedPacket {
    TaggedPacket {
        now,
        transport: TransportContext::default(),
        message: AttributedPacket::new(Packet::Rtp(rtp::Packet {
            header: rtp::header::Header {
                version: 2,
                payload_type: 96,
                sequence_number,
                ssrc,
                ..Default::default()
            },
            payload: vec![0xAB; 1000].into(),
        })),
    }
}

/// The transport-wide sequence number a departed packet carries.
fn transport_sequence(packet: &TaggedPacket) -> Option<u16> {
    let Packet::Rtp(rtp) = &packet.message.packet else {
        return None;
    };
    let data = rtp.header.get_extension(TWCC_ID)?;
    rtp::extension::transport_cc_extension::TransportCcExtension::unmarshal(&mut data.as_ref())
        .ok()
        .map(|extension| extension.transport_sequence)
}

/// TWCC feedback saying the `count` packets from `base` all arrived, 250 us apart.
fn all_received(now: Instant, base: u16, count: u16, feedback_count: u8) -> TaggedPacket {
    let feedback = TransportLayerCc {
        sender_ssrc: 1,
        media_ssrc: MEDIA_SSRC,
        base_sequence_number: base,
        packet_status_count: count,
        reference_time: 1,
        fb_pkt_count: feedback_count,
        packet_chunks: vec![PacketStatusChunk::RunLengthChunk(RunLengthChunk {
            type_tcc: StatusChunkTypeTcc::RunLengthChunk,
            packet_status_symbol: SymbolTypeTcc::PacketReceivedSmallDelta,
            run_length: count,
        })],
        recv_deltas: (0..count)
            .map(|_| RecvDelta {
                type_tcc_packet: SymbolTypeTcc::PacketReceivedSmallDelta,
                delta: 250,
            })
            .collect(),
    };
    TaggedPacket {
        now,
        transport: TransportContext::default(),
        message: AttributedPacket::new(Packet::Rtcp(vec![Box::new(feedback)])),
    }
}

fn send(chain: &mut impl Interceptor, packet: TaggedPacket) -> TaggedPacket {
    chain.handle_write(packet).expect("write");
    chain.poll_write().expect("the packet leaves")
}

/// draft-holmer-rmcat-transport-wide-cc-extensions-01 section 3: when a feedback packet is lost
/// the packets it would have reported are ignored, not counted as lost or received
/// (audit bug T2: they were all reported to the estimator as lost).
#[test]
fn packets_of_a_lost_feedback_packet_are_not_reported_as_lost() {
    let epoch = Instant::now();
    let estimator = Recorder::default();
    let mut chain = chain(estimator.clone());
    chain.bind_local_stream(&transport_cc(MEDIA_SSRC));

    for sequence_number in 0..20u16 {
        send(&mut chain, rtp(epoch, MEDIA_SSRC, sequence_number));
    }

    // The feedback for transport sequence numbers 0..=9 never arrives. The next one does.
    chain
        .handle_read(all_received(epoch + Duration::from_millis(200), 10, 10, 1))
        .expect("read");
    while chain.poll_read().is_some() {}

    let reports = estimator.reports();
    assert_eq!(
        (10..20).collect::<Vec<u16>>(),
        reports
            .iter()
            .map(|report| report.twcc_sequence_number)
            .collect::<Vec<_>>(),
        "only the packets the feedback described"
    );
    assert!(
        reports.iter().all(|report| report.arrived),
        "the receiver reported no loss"
    );
}

/// draft-holmer-rmcat-transport-wide-cc-extensions-01 section 2.2: the number is attached to
/// every packet sent. A retransmission on the RTX SSRC and a repair packet on the FEC SSRC are
/// packets on the transport like any other (audit bug T1: they left unnumbered and unrecorded).
#[test]
fn rtx_and_fec_packets_are_numbered_and_recorded() {
    let epoch = Instant::now();
    let estimator = Recorder::default();
    let mut chain = chain(estimator.clone());
    chain.bind_local_stream(&StreamInfo {
        ssrc_rtx: Some(RTX_SSRC),
        payload_type_rtx: Some(97),
        ssrc_fec: Some(FEC_SSRC),
        payload_type_fec: Some(118),
        ..transport_cc(MEDIA_SSRC)
    });

    let media = send(&mut chain, rtp(epoch, MEDIA_SSRC, 100));
    let rtx = send(&mut chain, rtp(epoch, RTX_SSRC, 7));
    let fec = send(&mut chain, rtp(epoch, FEC_SSRC, 9000));

    assert_eq!(Some(0), transport_sequence(&media));
    assert_eq!(Some(1), transport_sequence(&rtx), "the retransmission");
    assert_eq!(Some(2), transport_sequence(&fec), "the repair packet");

    chain
        .handle_read(all_received(epoch + Duration::from_millis(100), 0, 3, 0))
        .expect("read");
    while chain.poll_read().is_some() {}

    let reports = estimator.reports();
    assert_eq!(
        vec![MEDIA_SSRC, RTX_SSRC, FEC_SSRC],
        reports.iter().map(|report| report.ssrc).collect::<Vec<_>>(),
        "all three departures are in the send history the estimator reads"
    );
    let Packet::Rtp(fec_rtp) = &fec.message.packet else {
        unreachable!()
    };
    assert_eq!(
        fec_rtp.marshal_size(),
        reports[2].size,
        "with the bytes it put on the wire"
    );
}

/// A stream the receiver does not report on is not a stream that lost everything
/// (draft-ietf-rmcat-gcc.md bug G2): its packets have no verdict.
#[test]
fn a_stream_the_feedback_does_not_cover_is_not_counted_as_lost() {
    let epoch = Instant::now();
    let estimator = Recorder::default();
    let mut chain = chain(estimator.clone());
    chain.bind_local_stream(&transport_cc(MEDIA_SSRC));
    // Audio, without the transport-cc extension: the remote's TWCC feedback never names it.
    chain.bind_local_stream(&StreamInfo {
        ssrc: 0x00A0_D100,
        clock_rate: 48_000,
        payload_type: 111,
        ..Default::default()
    });

    for sequence_number in 0..10u16 {
        send(&mut chain, rtp(epoch, 0x00A0_D100, sequence_number));
        send(&mut chain, rtp(epoch, MEDIA_SSRC, sequence_number));
    }
    chain
        .handle_read(all_received(epoch + Duration::from_millis(100), 0, 10, 0))
        .expect("read");
    while chain.poll_read().is_some() {}

    let reports = estimator.reports();
    assert_eq!(10, reports.len(), "the ten packets the feedback described");
    assert!(reports.iter().all(|report| report.arrived));
    assert!(reports.iter().all(|report| report.ssrc == MEDIA_SSRC));
}

/// The pacer runs at the estimator's rate from the start, not at its own default until the
/// estimate first changes (draft-ietf-rmcat-gcc.md bug G4: 1 Mbit/s against a 300 kbit/s target).
#[test]
fn the_pacer_follows_the_estimators_starting_rate() {
    let epoch = Instant::now();
    let gcc = Gcc::default();
    let target = gcc.target_bitrate();
    assert_eq!(300_000.0, target);

    let mut chain = Registry::new()
        .with(
            Slot::CongestionControl,
            CongestionControlBuilder::new(gcc).build(),
        )
        .with(Slot::TwccSender, TwccSenderBuilder::new().build())
        // Without the queue time limit: the two seconds offered at once below would otherwise be
        // drained within two seconds whatever the target (`no_packet_waits_longer_than_the_queue_time_limit`).
        .with(
            Slot::Pacer,
            PacerBuilder::new().with_queue_time_limit(None).build(),
        )
        .build();
    chain.bind_local_stream(&transport_cc(MEDIA_SSRC));

    // Anything inbound: the estimate reaches the pacer on the read leg.
    chain
        .handle_read(TaggedPacket {
            now: epoch,
            transport: TransportContext::default(),
            message: AttributedPacket::new(Packet::Rtcp(vec![Box::new(
                rtcp::receiver_report::ReceiverReport::default(),
            )])),
        })
        .expect("read");
    while chain.poll_read().is_some() {}

    // Two seconds of media at 1 Mbit/s offered at once; count what leaves in two seconds.
    for sequence_number in 0..250u16 {
        chain
            .handle_write(rtp(epoch, MEDIA_SSRC, sequence_number))
            .expect("write");
    }
    let mut released_bits = 0usize;
    for step in 0..=2_000u64 {
        chain
            .handle_timeout(epoch + Duration::from_millis(step))
            .expect("timeout");
        while let Some(packet) = chain.poll_write() {
            if let Packet::Rtp(rtp) = &packet.message.packet {
                released_bits += rtp.marshal_size() * 8;
            }
        }
    }

    let rate = released_bits as f64 / 2.0;
    assert!(
        rate <= target * 1.15,
        "released at {rate} bit/s against a target of {target}"
    );
    assert!(rate >= target * 0.8, "and not starved either: {rate} bit/s");
}

fn ccfb_stream(ssrc: u32) -> StreamInfo {
    StreamInfo {
        ssrc,
        clock_rate: 90_000,
        payload_type: 96,
        rtcp_feedback: vec![RTCPFeedback {
            typ: "ack".to_owned(),
            parameter: "ccfb".to_owned(),
        }],
        ..Default::default()
    }
}

/// An RFC 8888 report for `MEDIA_SSRC`: packets from `begin`, each with its arrival time offset.
fn ccfb(now: Instant, report_timestamp: u32, begin: u16, offsets: &[u16]) -> TaggedPacket {
    use rtcp::transport_feedbacks::cc_feedback_report::{
        CcFeedbackMetricBlock, CcFeedbackReport, CcFeedbackReportBlock, Ecn,
    };
    let report = CcFeedbackReport {
        sender_ssrc: 1,
        report_blocks: vec![CcFeedbackReportBlock {
            media_ssrc: MEDIA_SSRC,
            begin_sequence: begin,
            metric_blocks: offsets
                .iter()
                .map(|offset| CcFeedbackMetricBlock {
                    received: true,
                    ecn: Ecn::NotEct,
                    arrival_time_offset: *offset,
                })
                .collect(),
        }],
        report_timestamp,
    };
    TaggedPacket {
        now,
        transport: TransportContext::default(),
        message: AttributedPacket::new(Packet::Rtcp(vec![Box::new(report)])),
    }
}

/// RFC 8888 section 3.1: the arrival time offset counts back from the report timestamp. A
/// packet that arrived later has the smaller offset, and must reach the estimator with the later
/// arrival time, within a report and from one report to the next. (Found while making GCC run
/// over RFC 8888: the offset itself was handed over as the arrival time, so every report's
/// arrivals ran backwards and the delay controller saw a queue draining for ever.)
#[test]
fn ccfb_arrival_times_increase_with_arrival_order() {
    let epoch = Instant::now();
    let estimator = Recorder::default();
    let mut chain = chain(estimator.clone());
    chain.bind_local_stream(&ccfb_stream(MEDIA_SSRC));

    for sequence_number in 0..4u16 {
        send(
            &mut chain,
            rtp(
                epoch + Duration::from_millis(u64::from(sequence_number) * 10),
                MEDIA_SSRC,
                sequence_number,
            ),
        );
    }

    // First report: packets 0, 1, 2 arrived 30, 20 and 10 units of 1/1024 s before it.
    let report_timestamp = 0x0020_0000u32;
    chain
        .handle_read(ccfb(
            epoch + Duration::from_millis(60),
            report_timestamp,
            0,
            &[30, 20, 10],
        ))
        .expect("read");
    // Second report, 100 ms later (6554 units of 1/65536 s): packet 3 arrived 5 units before it.
    chain
        .handle_read(ccfb(
            epoch + Duration::from_millis(160),
            report_timestamp + 6554,
            3,
            &[5],
        ))
        .expect("read");
    while chain.poll_read().is_some() {}

    let arrivals: Vec<Duration> = estimator
        .reports()
        .iter()
        .map(|report| report.arrival.expect("an arrival time"))
        .collect();
    assert_eq!(4, arrivals.len());
    let unit = Duration::from_secs_f64(1.0 / 1024.0);
    let close = |actual: Duration, expected: Duration| {
        actual.abs_diff(expected) < Duration::from_micros(50)
    };
    assert!(
        close(arrivals[1] - arrivals[0], unit * 10),
        "packet 1 arrived 10 units after packet 0: {arrivals:?}"
    );
    assert!(close(arrivals[2] - arrivals[1], unit * 10), "{arrivals:?}");
    assert!(
        close(
            arrivals[3] - arrivals[2],
            Duration::from_secs_f64(6554.0 / 65536.0) + unit * 5
        ),
        "packet 3 arrived 100 ms and 5 units after packet 2: {arrivals:?}"
    );
}

/// TWCC feedback with one received packet and the given 24-bit reference time.
fn one_received(now: Instant, base: u16, reference_time: u32, feedback_count: u8) -> TaggedPacket {
    let feedback = TransportLayerCc {
        sender_ssrc: 1,
        media_ssrc: MEDIA_SSRC,
        base_sequence_number: base,
        packet_status_count: 1,
        reference_time,
        fb_pkt_count: feedback_count,
        packet_chunks: vec![PacketStatusChunk::RunLengthChunk(RunLengthChunk {
            type_tcc: StatusChunkTypeTcc::RunLengthChunk,
            packet_status_symbol: SymbolTypeTcc::PacketReceivedSmallDelta,
            run_length: 1,
        })],
        recv_deltas: vec![RecvDelta {
            type_tcc_packet: SymbolTypeTcc::PacketReceivedSmallDelta,
            delta: 0,
        }],
    };
    TaggedPacket {
        now,
        transport: TransportContext::default(),
        message: AttributedPacket::new(Packet::Rtcp(vec![Box::new(feedback)])),
    }
}

/// draft-holmer-rmcat-transport-wide-cc-extensions-01 section 3.1: the reference time is a
/// 24-bit count of 64 ms. When it wraps, the next feedback is 64 ms later, not 12.4 days
/// earlier (audit bug T5).
#[test]
fn the_twcc_reference_time_wrap_does_not_send_arrivals_back_in_time() {
    let epoch = Instant::now();
    let estimator = Recorder::default();
    let mut chain = chain(estimator.clone());
    chain.bind_local_stream(&transport_cc(MEDIA_SSRC));

    send(&mut chain, rtp(epoch, MEDIA_SSRC, 0));
    send(
        &mut chain,
        rtp(epoch + Duration::from_millis(64), MEDIA_SSRC, 1),
    );

    chain
        .handle_read(one_received(
            epoch + Duration::from_millis(100),
            0,
            0x00FF_FFFF,
            0,
        ))
        .expect("read");
    chain
        .handle_read(one_received(epoch + Duration::from_millis(164), 1, 0, 1))
        .expect("read");
    while chain.poll_read().is_some() {}

    let reports = estimator.reports();
    assert_eq!(2, reports.len());
    assert_eq!(
        Duration::from_millis(64),
        reports[1].arrival.unwrap() - reports[0].arrival.unwrap(),
        "one reference tick later"
    );
}
