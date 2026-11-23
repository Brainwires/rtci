//! RFC 3611 report blocks through a chain with the RTCP session: the XR the receiver writes
//! leaves inside the session's compound packets (RFC 3611 section 2: XR is an RTCP packet and
//! follows RFC 3550's rules for them), from the reporting SSRC, for the streams that
//! negotiated it.

mod rtcp_session_common;

use rtc_interceptor::{
    Interceptor, RTCP_FB_XR, Registry, RtcpSessionControl, Slot, XrReportBuilder,
};
use rtcp::extended_report::{ExtendedReport, RLEReportBlock, StatisticsSummaryReportBlock};
use rtcp_session_common::*;
use sansio::Protocol;
use std::time::Instant;

fn chain_with_xr() -> impl Interceptor {
    Registry::new()
        .with(Slot::RtcpSession, builder().build())
        .with(Slot::ExtendedReports, XrReportBuilder::new().build())
        .build()
}

/// A remote stream that negotiated `a=rtcp-xr:pkt-loss-rle stat-summary=loss` gets both
/// blocks in a compound packet led by a receiver report; a stream that negotiated nothing gets
/// none.
#[test]
fn negotiated_xr_blocks_leave_in_the_sessions_compound_packets() {
    let base = Instant::now();
    let mut chain = chain_with_xr();
    let mut asked = video(200);
    asked
        .rtcp_feedback
        .push(feedback(RTCP_FB_XR, "pkt-loss-rle"));
    asked
        .rtcp_feedback
        .push(feedback(RTCP_FB_XR, "stat-summary=loss"));
    chain.bind_remote_stream(&asked);
    chain.bind_remote_stream(&video(201));
    control(&mut chain, base, RtcpSessionControl::Start);
    for seq in 1..=20u16 {
        if seq == 7 {
            continue;
        }
        let at = base + secs(0.02 * f64::from(seq));
        chain
            .handle_read(rtp(at, 200, seq, u32::from(seq) * 1_800))
            .unwrap();
        chain
            .handle_read(rtp(at, 201, seq, u32::from(seq) * 1_800))
            .unwrap();
    }
    read(&mut chain);

    let sent = run(&mut chain, base + secs(3.0));
    let carrier = sent
        .iter()
        .find(|sent| {
            sent.get::<ExtendedReport>()
                .iter()
                .any(|xr| xr.reports.iter().any(|b| b.as_any().is::<RLEReportBlock>()))
        })
        .expect("an XR with the loss block");
    assert!(carrier.is_compound());
    assert_eq!(Some(REPORTER), carrier.leader());
    assert!(
        carrier
            .get::<ExtendedReport>()
            .iter()
            .all(|xr| xr.sender_ssrc == REPORTER)
    );
    let blocks: Vec<_> = carrier
        .get::<ExtendedReport>()
        .into_iter()
        .flat_map(|xr| xr.reports.iter())
        .collect();
    let loss: Vec<&RLEReportBlock> = blocks
        .iter()
        .filter_map(|b| b.as_any().downcast_ref::<RLEReportBlock>())
        .collect();
    assert_eq!(1, loss.len(), "stream 201 asked for nothing");
    assert_eq!(200, loss[0].ssrc);
    assert_eq!((1, 21), (loss[0].begin_seq, loss[0].end_seq));
    assert_eq!(Some(false), loss[0].flags().get(6).copied());
    let summary: Vec<&StatisticsSummaryReportBlock> = blocks
        .iter()
        .filter_map(|b| b.as_any().downcast_ref::<StatisticsSummaryReportBlock>())
        .collect();
    assert_eq!(1, summary[0].lost_packets);
}
