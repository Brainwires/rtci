//! RFC 6679 section 7.3.3 at the congestion controller: the CE marks a receiver counts in its
//! RTCP ECN Feedback packets (section 5.1) and XR ECN Summary Reports (section 5.2) reach the
//! estimator as congestion, counted from one report to the next, for a stream that is not
//! reported in RFC 8888 (whose per-packet reports carry the marks themselves).

use rtc_interceptor::{
    AttributedPacket, BandwidthEstimator, CongestionControlBuilder, Interceptor, Packet,
    PacketReport, RTCPFeedback, Registry, Slot, StreamInfo, TaggedPacket,
};
use rtcp::extended_report::{EcnSummaryReport, EcnSummaryReportBlock, ExtendedReport};
use rtcp::transport_feedbacks::ecn_feedback::{EcnCounters, EcnFeedback};
use shared::TransportContext;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const TWCC_STREAM: u32 = 0x1000;
const CCFB_STREAM: u32 = 0x2000;

#[derive(Clone, Default)]
struct Marks(Arc<Mutex<Vec<(u64, u64)>>>);

impl BandwidthEstimator for Marks {
    fn on_reports(&mut self, _now: Instant, _reports: &[PacketReport]) {}
    fn target_bitrate(&self) -> f64 {
        1_000_000.0
    }
    fn on_congestion_marks(&mut self, _now: Instant, marked: u64, packets: u64) {
        self.0.lock().unwrap().push((marked, packets));
    }
}

fn stream(ssrc: u32, feedback: &[(&str, &str)]) -> StreamInfo {
    StreamInfo {
        ssrc,
        clock_rate: 90_000,
        payload_type: 96,
        rtcp_feedback: feedback
            .iter()
            .map(|(typ, parameter)| RTCPFeedback {
                typ: (*typ).to_owned(),
                parameter: (*parameter).to_owned(),
            })
            .collect(),
        ..Default::default()
    }
}

fn read(chain: &mut impl Interceptor, now: Instant, packets: Vec<Box<dyn rtcp::Packet>>) {
    chain
        .handle_read(TaggedPacket {
            now,
            transport: TransportContext::default(),
            message: AttributedPacket::new(Packet::Rtcp(packets)),
        })
        .unwrap();
    while chain.poll_read().is_some() {}
}

fn counters(ect1: u32, ce: u16, not_ect: u16) -> EcnCounters {
    EcnCounters {
        ect1,
        ce,
        not_ect,
        ..Default::default()
    }
}

#[test]
fn ce_marks_of_successive_ecn_reports_reach_the_estimator_as_deltas() {
    let marks = Marks::default();
    let mut chain = Registry::new()
        .with(
            Slot::CongestionControl,
            CongestionControlBuilder::new(marks.clone()).build(),
        )
        .build();
    chain.bind_local_stream(&stream(
        TWCC_STREAM,
        &[("transport-cc", ""), ("nack", "ecn")],
    ));
    chain.bind_local_stream(&stream(CCFB_STREAM, &[("ack", "ccfb"), ("nack", "ecn")]));
    let epoch = Instant::now();

    // First report: 20 packets, 2 of them CE (counted from zero).
    read(
        &mut chain,
        epoch,
        vec![Box::new(EcnFeedback {
            sender_ssrc: 9,
            media_ssrc: TWCC_STREAM,
            extended_highest_sequence_number: 19,
            counters: counters(18, 2, 0),
        })],
    );
    // A summary 30 packets later, 3 more CE; the RFC 8888 stream's summary is not counted.
    read(
        &mut chain,
        epoch + Duration::from_secs(1),
        vec![Box::new(ExtendedReport {
            sender_ssrc: 9,
            reports: vec![Box::new(EcnSummaryReportBlock {
                reports: vec![
                    EcnSummaryReport {
                        ssrc: TWCC_STREAM,
                        counters: counters(45, 5, 0),
                    },
                    EcnSummaryReport {
                        ssrc: CCFB_STREAM,
                        counters: counters(10, 10, 0),
                    },
                ],
            })],
        })],
    );
    // A report about a stream this endpoint does not send counts for nothing.
    read(
        &mut chain,
        epoch + Duration::from_secs(2),
        vec![Box::new(EcnFeedback {
            sender_ssrc: 9,
            media_ssrc: 0xdead,
            extended_highest_sequence_number: 5,
            counters: counters(0, 5, 0),
        })],
    );

    assert_eq!(*marks.0.lock().unwrap(), vec![(2, 20), (3, 30)]);
}

/// The 16-bit ECN-CE counter wraps: the delta across the wrap is what arrived.
#[test]
fn a_wrapped_ce_counter_still_gives_the_marks_since_the_last_report() {
    let marks = Marks::default();
    let mut chain = Registry::new()
        .with(
            Slot::CongestionControl,
            CongestionControlBuilder::new(marks.clone()).build(),
        )
        .build();
    chain.bind_local_stream(&stream(
        TWCC_STREAM,
        &[("transport-cc", ""), ("nack", "ecn")],
    ));
    let epoch = Instant::now();
    let report = |ce: u16, not_ect: u16| -> Vec<Box<dyn rtcp::Packet>> {
        vec![Box::new(EcnFeedback {
            sender_ssrc: 9,
            media_ssrc: TWCC_STREAM,
            extended_highest_sequence_number: 0,
            counters: counters(0, ce, not_ect),
        })]
    };
    read(&mut chain, epoch, report(65530, 65530));
    read(&mut chain, epoch + Duration::from_secs(1), report(4, 4));
    let seen = marks.0.lock().unwrap().clone();
    assert_eq!(seen[1], (10, 20));
}
