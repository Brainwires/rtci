//! RFC 8888 congestion control feedback, in a chain.
//!
//! The report this produces is the input a remote sender's congestion control runs on, so what
//! matters is that it says what actually happened: which packets arrived, which did not, and how
//! long before the report each one did. The reports are also round-tripped through the wire codec
//! from PRE-01, since a report that cannot be encoded and decoded is worth nothing.

use rtc_interceptor::{
    Attribute, AttributedPacket, Interceptor, Packet, RTCPFeedback, Registry, Rfc8888Builder, Slot,
    StreamInfo, TaggedPacket,
};
use rtcp::transport_feedbacks::cc_feedback_report::CcFeedbackReport;
use rtcp::transport_feedbacks::cc_feedback_report::Ecn;
use sansio::Protocol;
use shared::marshal::{Marshal, MarshalSize, Unmarshal};
use shared::{EcnCodepoint, TransportContext};
use std::time::{Duration, Instant};

const SSRC: u32 = 1000;
const SENDER_SSRC: u32 = 7;
const INTERVAL: Duration = Duration::from_millis(100);

/// A stream whose payload type carries `a=rtcp-fb:<pt> ack ccfb`.
fn negotiated(ssrc: u32) -> StreamInfo {
    StreamInfo {
        ssrc,
        clock_rate: 90_000,
        rtcp_feedback: vec![RTCPFeedback {
            typ: "ack".to_owned(),
            parameter: "ccfb".to_owned(),
        }],
        ..Default::default()
    }
}

struct Harness {
    chain: Box<dyn Interceptor>,
    epoch: Instant,
}

impl Harness {
    fn new() -> Self {
        let chain = Registry::new()
            .with(
                Slot::Rfc8888,
                Rfc8888Builder::new()
                    .with_interval(INTERVAL)
                    // These tests are about what a report says, at a fixed rhythm. (By
                    // default the interval stretches to the RTCP bandwidth, which for a few
                    // test packets is that of one audio stream.)
                    .with_adaptive_interval(false)
                    .with_sender_ssrc(SENDER_SSRC)
                    .build(),
            )
            .build();

        Self {
            chain: Box::new(chain),
            epoch: Instant::now(),
        }
    }

    fn bind(&mut self, ssrc: u32) {
        self.chain.bind_remote_stream(&negotiated(ssrc));
    }

    fn arrive(&mut self, at: Duration, ssrc: u32, sequence_number: u16) {
        self.arrive_with_ecn(at, ssrc, sequence_number, None);
    }

    /// A packet whose datagram arrived with the ECN codepoint `ecn` (from the socket layer).
    fn arrive_with_ecn(
        &mut self,
        at: Duration,
        ssrc: u32,
        sequence_number: u16,
        ecn: Option<EcnCodepoint>,
    ) {
        self.chain
            .handle_read(TaggedPacket {
                now: self.epoch + at,
                transport: TransportContext {
                    ecn,
                    ..TransportContext::default()
                },
                message: AttributedPacket::new(Packet::Rtp(rtp::Packet {
                    header: rtp::header::Header {
                        version: 2,
                        payload_type: 96,
                        sequence_number,
                        ssrc,
                        ..Default::default()
                    },
                    payload: vec![1, 2, 3].into(),
                })),
            })
            .expect("handle_read");
    }

    fn tick(&mut self, at: Duration) {
        self.chain
            .handle_timeout(self.epoch + at)
            .expect("handle_timeout");
    }

    /// Drain whatever feedback the interceptor has produced.
    fn drain_reports(&mut self) -> Vec<CcFeedbackReport> {
        let mut reports = Vec::new();
        while let Some(packet) = self.chain.poll_write() {
            if let Packet::Rtcp(rtcp_packets) = &packet.message.packet {
                for rtcp_packet in rtcp_packets {
                    if let Some(report) = rtcp_packet.as_any().downcast_ref::<CcFeedbackReport>() {
                        reports.push(report.clone());
                    }
                }
            }
        }
        reports
    }

    fn next_timeout(&mut self) -> Option<Duration> {
        self.chain
            .poll_timeout()
            .map(|instant| instant.saturating_duration_since(self.epoch))
    }
}

fn ms(milliseconds: u64) -> Duration {
    Duration::from_millis(milliseconds)
}

/// Which packets a report block says arrived.
fn received(report: &CcFeedbackReport, index: usize) -> Vec<bool> {
    report.report_blocks[index]
        .metric_blocks
        .iter()
        .map(|metric| metric.received)
        .collect()
}

// ---------------------------------------------------------------------------------------
// What the report says
// ---------------------------------------------------------------------------------------

#[test]
fn arrivals_are_reported_on_the_interval() {
    let mut harness = Harness::new();
    harness.bind(SSRC);

    harness.arrive(ms(0), SSRC, 100);
    harness.arrive(ms(10), SSRC, 101);
    assert!(
        harness.drain_reports().is_empty(),
        "arrival alone does not send feedback; the interval does"
    );

    harness.tick(ms(100));
    let reports = harness.drain_reports();
    assert_eq!(1, reports.len());
    assert_eq!(SENDER_SSRC, reports[0].sender_ssrc);
    assert_eq!(SSRC, reports[0].report_blocks[0].media_ssrc);
    assert_eq!(100, reports[0].report_blocks[0].begin_sequence);
    assert_eq!(vec![true, true], received(&reports[0], 0));
}

/// Each packet is reported with the ECN codepoint its datagram arrived with, which the
/// application's socket layer hands over in the transport context (RFC 8888 section 3.1).
#[test]
fn each_packet_is_reported_with_the_ecn_codepoint_it_arrived_with() {
    let mut harness = Harness::new();
    harness.bind(SSRC);

    harness.arrive_with_ecn(ms(0), SSRC, 100, Some(EcnCodepoint::Ect1));
    harness.arrive_with_ecn(ms(1), SSRC, 101, Some(EcnCodepoint::Ce));
    harness.arrive_with_ecn(ms(2), SSRC, 102, Some(EcnCodepoint::Ect0));
    harness.arrive_with_ecn(ms(3), SSRC, 103, None);

    harness.tick(ms(100));
    let reports = harness.drain_reports();
    let ecn: Vec<Ecn> = reports[0].report_blocks[0]
        .metric_blocks
        .iter()
        .map(|metric| metric.ecn)
        .collect();
    assert_eq!(vec![Ecn::Ect1, Ecn::Ce, Ecn::Ect0, Ecn::NotEct], ecn);
}

/// The whole point of the format: telling the sender which packets did *not* arrive.
#[test]
fn a_gap_is_reported_as_a_packet_that_did_not_arrive() {
    let mut harness = Harness::new();
    harness.bind(SSRC);

    harness.arrive(ms(0), SSRC, 100);
    harness.arrive(ms(10), SSRC, 102);
    harness.tick(ms(100));

    let reports = harness.drain_reports();
    assert_eq!(
        vec![true, false, true],
        received(&reports[0], 0),
        "101 never came"
    );
}

/// Arrival-time offsets are what congestion control actually reads: the spread between them is
/// the delay variation the path is imposing.
#[test]
fn arrival_time_offsets_reflect_when_each_packet_arrived() {
    let mut harness = Harness::new();
    harness.bind(SSRC);

    // Two packets, 50 ms apart, reported at 100 ms.
    harness.arrive(ms(0), SSRC, 100);
    harness.arrive(ms(50), SSRC, 101);
    harness.tick(ms(100));

    let reports = harness.drain_reports();
    let metrics = &reports[0].report_blocks[0].metric_blocks;

    // Units of 1/1024 s: 100 ms ≈ 102, 50 ms ≈ 51.
    assert!(
        (100..=104).contains(&metrics[0].arrival_time_offset),
        "the older packet is ~100 ms back, got {}",
        metrics[0].arrival_time_offset
    );
    assert!(
        (49..=53).contains(&metrics[1].arrival_time_offset),
        "the newer one ~50 ms, got {}",
        metrics[1].arrival_time_offset
    );
    assert!(
        metrics[0].arrival_time_offset > metrics[1].arrival_time_offset,
        "an older packet is further back than a newer one"
    );
}

#[test]
fn several_streams_each_get_a_report_block() {
    let mut harness = Harness::new();
    harness.bind(SSRC);
    harness.bind(SSRC + 1);

    harness.arrive(ms(0), SSRC, 100);
    harness.arrive(ms(0), SSRC + 1, 500);
    harness.tick(ms(100));

    let reports = harness.drain_reports();
    assert_eq!(2, reports[0].report_blocks.len());
    assert_eq!(
        vec![SSRC, SSRC + 1],
        rtcp::packet::Packet::destination_ssrc(&reports[0]),
        "and every reported stream is a destination"
    );
}

#[test]
fn a_second_report_covers_only_what_arrived_since_the_first() {
    let mut harness = Harness::new();
    harness.bind(SSRC);

    harness.arrive(ms(0), SSRC, 100);
    harness.tick(ms(100));
    assert_eq!(1, harness.drain_reports().len());

    harness.arrive(ms(110), SSRC, 101);
    harness.tick(ms(200));

    let reports = harness.drain_reports();
    assert_eq!(
        101, reports[0].report_blocks[0].begin_sequence,
        "100 was already reported; saying so again would claim it arrived twice"
    );
    assert_eq!(vec![true], received(&reports[0], 0));
}

// ---------------------------------------------------------------------------------------
// When nothing is reported
// ---------------------------------------------------------------------------------------

#[test]
fn nothing_is_reported_when_nothing_arrived() {
    let mut harness = Harness::new();
    harness.bind(SSRC);

    harness.tick(ms(100));
    harness.tick(ms(200));

    assert!(harness.drain_reports().is_empty());
}

#[test]
fn packets_from_unbound_streams_are_not_reported() {
    let mut harness = Harness::new();
    harness.bind(SSRC);

    harness.arrive(ms(0), 9999, 1);
    harness.tick(ms(100));

    assert!(
        harness.drain_reports().is_empty(),
        "nothing bound has arrived, so there is nothing to feed back"
    );
}

#[test]
fn unbinding_stops_the_reports() {
    let mut harness = Harness::new();
    harness.bind(SSRC);
    harness.arrive(ms(0), SSRC, 100);

    harness.chain.unbind_remote_stream(&StreamInfo {
        ssrc: SSRC,
        ..Default::default()
    });

    harness.tick(ms(100));
    assert!(harness.drain_reports().is_empty());
    assert_eq!(None, harness.next_timeout(), "and the timer is disarmed");
}

/// Delivery rule 3: idle means `None`, and an armed timeout advances rather than repeating.
#[test]
fn poll_timeout_is_none_until_something_arrives() {
    let mut harness = Harness::new();

    assert_eq!(None, harness.next_timeout(), "nothing bound");

    harness.bind(SSRC);
    assert_eq!(
        None,
        harness.next_timeout(),
        "bound, but no instant has been handed over yet"
    );

    harness.arrive(ms(0), SSRC, 100);
    assert_eq!(Some(INTERVAL), harness.next_timeout());

    harness.tick(ms(100));
    assert_eq!(
        Some(INTERVAL * 2),
        harness.next_timeout(),
        "advances rather than repeating a past instant"
    );
}

// ---------------------------------------------------------------------------------------
// The wire
// ---------------------------------------------------------------------------------------

/// A report that cannot survive the wire codec is worth nothing. This closes the loop with
/// PRE-01: build a report from observed arrivals, marshal it, and unmarshal it back.
#[test]
fn a_generated_report_round_trips_through_the_wire_codec() {
    let mut harness = Harness::new();
    harness.bind(SSRC);

    harness.arrive(ms(0), SSRC, 100);
    harness.arrive(ms(10), SSRC, 102);
    harness.arrive(ms(20), SSRC, 103);
    harness.tick(ms(100));

    let reports = harness.drain_reports();
    let report = &reports[0];

    let mut buffer = vec![0u8; report.marshal_size()];
    report.marshal_to(&mut buffer).expect("marshal");

    let mut raw = buffer.as_slice();
    let decoded = CcFeedbackReport::unmarshal(&mut raw).expect("decode");

    assert_eq!(report, &decoded, "byte round trip preserves the report");
    assert_eq!(vec![SSRC], rtcp::packet::Packet::destination_ssrc(&decoded));
    assert_eq!(
        vec![true, false, true, true],
        decoded.report_blocks[0]
            .metric_blocks
            .iter()
            .map(|metric| metric.received)
            .collect::<Vec<_>>(),
        "including the gap"
    );
}

/// A report is terminal — complete when built, with nothing below to transform it — so it comes
/// out of `poll_write` rather than traversing `inner`.
#[test]
fn reports_are_drained_from_the_write_side() {
    let mut harness = Harness::new();
    harness.bind(SSRC);
    harness.arrive(ms(0), SSRC, 100);
    harness.tick(ms(100));

    assert_eq!(1, harness.drain_reports().len());
    assert!(
        harness.drain_reports().is_empty(),
        "drained once, not queued forever"
    );
}

// ---------------------------------------------------------------------------------------------
// Negotiation and identity (RFC 8888 sections 3.1 and 6)
// ---------------------------------------------------------------------------------------------

/// RFC 8888 section 6 / RFC 4585 section 4.2: feedback is sent only for a stream whose payload
/// type negotiated it. A peer that declined `ack ccfb` gets no report (rfc8888.md bug B2).
#[test]
fn a_stream_that_did_not_negotiate_ccfb_gets_no_report() {
    let mut harness = Harness::new();
    harness.chain.bind_remote_stream(&StreamInfo {
        ssrc: SSRC,
        clock_rate: 90_000,
        ..Default::default()
    });

    for sequence_number in 0..5 {
        harness.arrive(ms(0), SSRC, sequence_number);
    }
    harness.tick(INTERVAL);
    harness.tick(INTERVAL * 2);

    assert!(
        harness.drain_reports().is_empty(),
        "no `ack ccfb` on the stream, so nothing is reported"
    );
    assert_eq!(None, harness.next_timeout(), "and no timer runs for it");
}

/// The same chain reports the stream that did negotiate it and not the one that did not.
#[test]
fn only_the_streams_that_negotiated_ccfb_are_reported() {
    let mut harness = Harness::new();
    harness.bind(SSRC);
    harness.chain.bind_remote_stream(&StreamInfo {
        ssrc: 2000,
        clock_rate: 48_000,
        ..Default::default()
    });

    harness.arrive(ms(0), SSRC, 1);
    harness.arrive(ms(0), 2000, 1);
    harness.tick(INTERVAL);

    let reports = harness.drain_reports();
    assert_eq!(1, reports.len());
    assert_eq!(
        vec![SSRC],
        reports[0]
            .report_blocks
            .iter()
            .map(|block| block.media_ssrc)
            .collect::<Vec<_>>()
    );
}

fn unconfigured_chain() -> Box<dyn Interceptor> {
    Box::new(
        Registry::new()
            .with(
                Slot::Rfc8888,
                Rfc8888Builder::new()
                    .with_interval(INTERVAL)
                    .with_adaptive_interval(false)
                    .build(),
            )
            .build(),
    )
}

/// RFC 8888 section 3.1: the header SSRC is the SSRC of the RTCP packet sender. Built without
/// one, the interceptor must not claim SSRC 0 (rfc8888.md bug B3): a receive-only endpoint
/// reports from a random SSRC of its own.
#[test]
fn a_receive_only_endpoint_reports_from_a_non_zero_ssrc_of_its_own() {
    let mut harness = Harness {
        chain: unconfigured_chain(),
        epoch: Instant::now(),
    };
    harness.bind(SSRC);

    harness.arrive(ms(0), SSRC, 1);
    harness.tick(INTERVAL);
    harness.arrive(ms(150), SSRC, 2);
    harness.tick(INTERVAL * 2);

    let reports = harness.drain_reports();
    assert_eq!(2, reports.len());
    assert_ne!(0, reports[0].sender_ssrc);
    assert_ne!(SSRC, reports[0].sender_ssrc, "not the media source's");
    assert_eq!(
        reports[0].sender_ssrc, reports[1].sender_ssrc,
        "one participant, one SSRC"
    );
}

/// An endpoint that sends media reports from its media SSRC: that is the SSRC of the RTCP
/// packet sender the peer already knows.
#[test]
fn an_endpoint_that_sends_media_reports_from_its_media_ssrc() {
    let mut harness = Harness {
        chain: unconfigured_chain(),
        epoch: Instant::now(),
    };
    harness.chain.bind_local_stream(&StreamInfo {
        ssrc: 0x5E4D_E401,
        clock_rate: 90_000,
        ..Default::default()
    });
    harness.bind(SSRC);

    harness.arrive(ms(0), SSRC, 1);
    harness.tick(INTERVAL);

    let reports = harness.drain_reports();
    assert_eq!(1, reports.len());
    assert_eq!(0x5E4D_E401, reports[0].sender_ssrc);
}

// ---------------------------------------------------------------------------------------------
// Duplicates, gaps and report size (RFC 8888 section 3.1)
// ---------------------------------------------------------------------------------------------

/// RFC 8888 section 3.1: for duplicate copies the arrival time of the first copy is reported,
/// and ECN-CE if any copy was CE-marked (rfc8888.md bug B4).
#[test]
fn a_duplicate_reports_the_first_arrival_and_ce_if_any_copy_was_marked() {
    let mut harness = Harness::new();
    harness.bind(SSRC);

    // The report goes out one interval after the first arrival, at 140 ms.
    harness.arrive_with_ecn(ms(40), SSRC, 100, Some(EcnCodepoint::Ce));
    harness.arrive_with_ecn(ms(90), SSRC, 100, Some(EcnCodepoint::Ect1));
    harness.tick(ms(140));

    let reports = harness.drain_reports();
    let metric = &reports[0].report_blocks[0].metric_blocks[0];
    assert_eq!(1, reports[0].report_blocks[0].metric_blocks.len());
    assert_eq!(Ecn::Ce, metric.ecn, "one copy was CE");
    // 100 ms before the report is 102 units of 1/1024 s; the second copy would be 51.
    assert!(
        (101..=103).contains(&metric.arrival_time_offset),
        "the first copy arrived 100 ms before the report, got {}",
        metric.arrival_time_offset
    );
}

/// One packet that never arrives must not make every later report describe everything since
/// (rfc8888.md bug B6): each arrival is reported once, the gap once.
#[test]
fn one_lost_packet_does_not_make_every_report_repeat_the_window() {
    let mut harness = Harness::new();
    harness.bind(SSRC);

    // 50 packets per 100 ms; sequence number 5 is lost.
    let mut sequence_number = 0u16;
    let mut described = Vec::new();
    for interval in 0..10u32 {
        for index in 0..50u32 {
            if sequence_number != 5 {
                harness.arrive(
                    INTERVAL * interval + ms(u64::from(index) * 2),
                    SSRC,
                    sequence_number,
                );
            }
            sequence_number += 1;
        }
        harness.tick(INTERVAL * (interval + 1));
        for report in harness.drain_reports() {
            described.push(report.report_blocks[0].metric_blocks.len());
        }
    }

    assert_eq!(10, described.len(), "one report per interval");
    assert!(
        described.iter().all(|count| *count <= 50),
        "each report describes one interval's packets: {described:?}"
    );
    assert_eq!(500, described.iter().sum::<usize>());
}

/// RFC 8888 section 3.1: overlapping reports are sent when a packet is reordered across a
/// report boundary, and what was reported received stays reported received.
#[test]
fn a_packet_reordered_across_a_report_boundary_is_reported_in_an_overlapping_report() {
    let mut harness = Harness::new();
    harness.bind(SSRC);

    harness.arrive(ms(0), SSRC, 100);
    harness.arrive(ms(20), SSRC, 102);
    harness.tick(INTERVAL);
    let first = harness.drain_reports();
    assert_eq!(vec![true, false, true], received(&first[0], 0));

    harness.arrive(ms(120), SSRC, 101);
    harness.arrive(ms(130), SSRC, 103);
    harness.tick(INTERVAL * 2);
    let second = harness.drain_reports();
    assert_eq!(101, second[0].report_blocks[0].begin_sequence);
    assert_eq!(vec![true, true, true], received(&second[0], 0));
}

/// RFC 8888 section 3.1: feedback too large for the path MTU is split into several feedback
/// packets rather than cut.
#[test]
fn feedback_too_large_for_the_report_size_is_split_into_several_packets() {
    let chain = Registry::new()
        .with(
            Slot::Rfc8888,
            Rfc8888Builder::new()
                .with_interval(INTERVAL)
                .with_adaptive_interval(false)
                .with_sender_ssrc(SENDER_SSRC)
                // 12 + 8 bytes of overhead and 100 two-byte metric blocks.
                .with_max_report_size(220)
                .build(),
        )
        .build();
    let mut harness = Harness {
        chain: Box::new(chain),
        epoch: Instant::now(),
    };
    harness.bind(SSRC);

    for sequence_number in 0..250u16 {
        harness.arrive(ms(0), SSRC, sequence_number);
    }
    harness.tick(INTERVAL);

    let reports = harness.drain_reports();
    assert_eq!(
        vec![(0u16, 100usize), (100, 100), (200, 50)],
        reports
            .iter()
            .map(|report| (
                report.report_blocks[0].begin_sequence,
                report.report_blocks[0].metric_blocks.len()
            ))
            .collect::<Vec<_>>()
    );
    for report in &reports {
        assert!(report.marshal_size() <= 220, "each within the budget");
        assert_eq!(reports[0].report_timestamp, report.report_timestamp);
    }
}

/// RFC 8888 section 6: the feedback covers every packet of the session's payload types, FEC
/// and retransmission included. The repair flows of a stream are reported under their own SSRC.
#[test]
fn the_repair_flows_of_a_negotiated_stream_are_reported_under_their_own_ssrc() {
    let mut harness = Harness::new();
    harness.chain.bind_remote_stream(&StreamInfo {
        ssrc_fec: Some(3000),
        payload_type_fec: Some(118),
        ..negotiated(SSRC)
    });

    harness.arrive(ms(0), SSRC, 10);
    harness.arrive(ms(1), 3000, 700);
    harness.tick(INTERVAL);

    let reports = harness.drain_reports();
    assert_eq!(
        vec![(SSRC, 10u16), (3000, 700)],
        reports[0]
            .report_blocks
            .iter()
            .map(|block| (block.media_ssrc, block.begin_sequence))
            .collect::<Vec<_>>()
    );
}

/// RFC 8888 sections 3.1 and 6: a retransmission is reported as what arrived on the wire, a
/// packet of the RTX stream under its own SSRC and sequence number, although the chain sees it
/// rewritten into the original (RFC 4588 de-encapsulation happens before the chain). Reporting
/// it as the original would tell the sender that a packet the path lost arrived, at the time
/// the retransmission did.
#[test]
fn a_retransmission_is_reported_under_the_rtx_ssrc_and_sequence_number() {
    let mut harness = Harness::new();
    harness.chain.bind_remote_stream(&StreamInfo {
        ssrc_rtx: Some(4000),
        payload_type_rtx: Some(97),
        ..negotiated(SSRC)
    });

    harness.arrive(ms(0), SSRC, 10);
    harness.arrive(ms(1), SSRC, 12);
    // Sequence number 11 was lost; the RTX packet 900 carries it, rewritten before the chain.
    harness
        .chain
        .handle_read(TaggedPacket {
            now: harness.epoch + ms(30),
            transport: TransportContext::default(),
            message: AttributedPacket::new(Packet::Rtp(rtp::Packet {
                header: rtp::header::Header {
                    version: 2,
                    payload_type: 96,
                    sequence_number: 11,
                    ssrc: SSRC,
                    ..Default::default()
                },
                payload: vec![1, 2, 3].into(),
            }))
            .with(Attribute::Retransmitted {
                ssrc: 4000,
                sequence_number: 900,
            }),
        })
        .expect("handle_read");
    harness.tick(INTERVAL);

    let reports = harness.drain_reports();
    let blocks: Vec<(u32, u16, Vec<bool>)> = reports
        .iter()
        .flat_map(|report| &report.report_blocks)
        .map(|block| {
            (
                block.media_ssrc,
                block.begin_sequence,
                block.metric_blocks.iter().map(|m| m.received).collect(),
            )
        })
        .collect();
    assert_eq!(
        vec![
            (SSRC, 10u16, vec![true, false, true]),
            (4000, 900, vec![true])
        ],
        blocks,
        "11 stays lost on the media stream; the RTX stream's 900 arrived"
    );
}
