//! RFC 6679 receiver side through the RTCP session: the RTCP ECN Feedback packet (section
//! 5.1) where `nack ecn` was negotiated, sent early on the first ECT packet of a source, on
//! every ECN-CE mark and on a detected loss (sections 7.2.1, 7.3.2); the XR ECN Summary
//! Report (section 5.2) in every regular compound packet where `xr ecn-sum` was negotiated.

mod rtcp_session_common;

use rtc_interceptor::{
    Interceptor, RTCP_FB_NACK_ECN, RTCP_FB_XR, RTCP_XR_ECN_SUMMARY, RtcpSessionControl,
};
use rtcp::extended_report::{EcnSummaryReportBlock, ExtendedReport};
use rtcp::transport_feedbacks::ecn_feedback::{EcnCounters, EcnFeedback};
use rtcp_session_common::*;
use sansio::Protocol;
use shared::EcnCodepoint;
use std::time::Instant;

const REMOTE: u32 = 0x1234;

fn ecn_video(nack_ecn: bool, ecn_sum: bool) -> rtc_interceptor::StreamInfo {
    let mut info = video(REMOTE);
    if nack_ecn {
        info.rtcp_feedback.push(feedback("nack", RTCP_FB_NACK_ECN));
    }
    if ecn_sum {
        info.rtcp_feedback
            .push(feedback(RTCP_FB_XR, RTCP_XR_ECN_SUMMARY));
    }
    info
}

fn marked(
    now: Instant,
    sequence_number: u16,
    ecn: Option<EcnCodepoint>,
) -> rtc_interceptor::TaggedPacket {
    let mut packet = rtp(
        now,
        REMOTE,
        sequence_number,
        u32::from(sequence_number) * 3000,
    );
    packet.transport.ecn = ecn;
    packet
}

fn ecn_feedback(sent: &[Sent]) -> Vec<(Instant, EcnFeedback)> {
    sent.iter()
        .flat_map(|s| {
            s.get::<EcnFeedback>()
                .into_iter()
                .map(|f| (s.at, f.clone()))
        })
        .collect()
}

fn summaries(sent: &[Sent]) -> Vec<EcnSummaryReportBlock> {
    sent.iter()
        .flat_map(|s| s.get::<ExtendedReport>())
        .flat_map(|xr| &xr.reports)
        .filter_map(|block| {
            block
                .as_any()
                .downcast_ref::<EcnSummaryReportBlock>()
                .cloned()
        })
        .collect()
}

fn session(nack_ecn: bool, ecn_sum: bool) -> (impl Interceptor, Instant) {
    let mut chain = chain(builder());
    let base = Instant::now();
    chain.bind_remote_stream(&ecn_video(nack_ecn, ecn_sum));
    control(&mut chain, base, RtcpSessionControl::Start);
    (chain, base)
}

#[test]
fn the_first_ect_packet_of_a_source_is_reported_at_once_in_an_ecn_feedback_packet() {
    let (mut chain, base) = session(true, false);
    for seq in 0..5u16 {
        chain
            .handle_read(marked(base + secs(0.02 * f64::from(seq)), seq, None))
            .unwrap();
    }
    assert!(
        ecn_feedback(&written(&mut chain)).is_empty(),
        "not-ECT alone is not urgent"
    );

    let at = base + secs(0.2);
    // The session's own timers up to the arrival first, as a driver runs them.
    let _ = run(&mut chain, at);
    chain
        .handle_read(marked(at, 5, Some(EcnCodepoint::Ect1)))
        .unwrap();
    let sent = run(&mut chain, at);
    let feedback = ecn_feedback(&sent);
    assert_eq!(feedback.len(), 1, "one early ECN feedback packet");
    let (when, report) = &feedback[0];
    assert_eq!(
        *when, at,
        "between two parties feedback leaves without dither"
    );
    assert_eq!(report.media_ssrc, REMOTE);
    assert_eq!(report.sender_ssrc, REPORTER);
    assert_eq!(report.extended_highest_sequence_number, 5);
    assert_eq!(
        report.counters,
        EcnCounters {
            ect1: 1,
            not_ect: 5,
            ..Default::default()
        }
    );
}

#[test]
fn every_ce_mark_and_every_loss_asks_for_ecn_feedback() {
    let (mut chain, base) = session(true, false);
    chain
        .handle_read(marked(base, 0, Some(EcnCodepoint::Ect1)))
        .unwrap();
    let _ = run(&mut chain, base + secs(5.0));

    // A CE mark, past the early allowance of the first one: reported early or with the next
    // compound packet, and reported.
    let at = base + secs(5.0);
    chain
        .handle_read(marked(at, 1, Some(EcnCodepoint::Ce)))
        .unwrap();
    let sent = run(&mut chain, at + secs(10.0));
    let reports = ecn_feedback(&sent);
    assert!(
        reports.iter().any(|(_, f)| f.counters.ce == 1),
        "the CE mark is reported: {reports:?}"
    );

    // A gap: 2 never arrives.
    let at = at + secs(10.0);
    chain
        .handle_read(marked(at, 3, Some(EcnCodepoint::Ect1)))
        .unwrap();
    let sent = run(&mut chain, at + secs(10.0));
    let reports = ecn_feedback(&sent);
    assert!(
        reports
            .iter()
            .any(|(_, f)| f.counters.lost == 1 && f.extended_highest_sequence_number == 3),
        "the loss is reported: {reports:?}"
    );
}

#[test]
fn every_regular_compound_packet_carries_an_ecn_summary_when_ecn_sum_was_negotiated() {
    let (mut chain, base) = session(false, true);
    // Before any packet: the block is sent with no entry and length zero.
    let sent = run(&mut chain, base + secs(3.0));
    let regular: Vec<&Sent> = sent.iter().filter(|s| s.is_compound()).collect();
    assert!(!regular.is_empty());
    assert!(regular.iter().all(|s| s.has::<ExtendedReport>()));
    assert!(
        summaries(&sent)
            .iter()
            .all(|block| block.reports.is_empty())
    );

    let start = base + secs(3.0);
    chain
        .handle_read(marked(start, 0, Some(EcnCodepoint::Ect0)))
        .unwrap();
    chain
        .handle_read(marked(start, 1, Some(EcnCodepoint::Ce)))
        .unwrap();
    chain.handle_read(marked(start, 1, None)).unwrap();
    let sent = run(&mut chain, start + secs(6.0));
    let compound: Vec<&Sent> = sent
        .iter()
        .filter(|s| s.is_compound() && !s.reported().is_empty())
        .collect();
    assert!(!compound.is_empty());
    for s in &compound {
        let blocks: Vec<EcnSummaryReportBlock> = s
            .get::<ExtendedReport>()
            .iter()
            .flat_map(|xr| &xr.reports)
            .filter_map(|b| b.as_any().downcast_ref::<EcnSummaryReportBlock>().cloned())
            .collect();
        assert_eq!(blocks.len(), 1, "one summary per regular packet");
        assert_eq!(blocks[0].reports.len(), 1);
        assert_eq!(blocks[0].reports[0].ssrc, REMOTE);
        assert_eq!(
            blocks[0].reports[0].counters,
            EcnCounters {
                ect0: 1,
                ce: 1,
                not_ect: 1,
                duplicates: 1,
                ..Default::default()
            }
        );
    }
    assert!(
        ecn_feedback(&sent).is_empty(),
        "no feedback packet without nack ecn"
    );
}

#[test]
fn a_stream_that_negotiated_neither_gets_no_ecn_reports() {
    let (mut chain, base) = session(false, false);
    for seq in 0..20u16 {
        chain
            .handle_read(marked(
                base + secs(0.05 * f64::from(seq)),
                seq * 2,
                Some(EcnCodepoint::Ce),
            ))
            .unwrap();
    }
    let sent = run(&mut chain, base + secs(10.0));
    assert!(ecn_feedback(&sent).is_empty());
    assert!(summaries(&sent).is_empty());
}
