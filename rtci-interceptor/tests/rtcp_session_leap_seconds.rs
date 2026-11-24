//! RTP and leap seconds (RFC 7164 section 5): no NTP timestamp is generated, and none received
//! is used, in the two seconds a positive leap second at the end of a month would make
//! ambiguous (the session assumes one at the end of every month, as section 5.1 allows).

mod rtcp_session_common;

use rtci_interceptor::{Interceptor, RtcpBandwidth, RtcpSessionControl};
use rtcp::extended_report::{ExtendedReport, ReceiverReferenceTimeReportBlock};
use rtcp::receiver_report::ReceiverReport;
use rtcp::sender_report::SenderReport;
use rtcp_session_common::*;
use sansio::Protocol;
use shared::time::{SystemInstant, near_leap_second};
use std::time::{Duration, Instant};

/// 2026-12-31 23:59:59 UTC, the last second of a month, as seconds since the Unix epoch.
const LAST_SECOND: u64 = 1_798_761_599;

fn busy_session() -> RtcpBandwidth {
    RtcpBandwidth {
        session: Some(2_000_000),
        ..Default::default()
    }
}

/// RFC 7164 section 5.1: senders "SHOULD NOT generate sender reports containing an
/// originating NTP timestamp in the vicinity of a positive leap second" and "MAY send receiver
/// reports in place of sender reports". A sender reporting about once a second from
/// 23:59:55 to 00:00:05 on the last day of a month sends sender reports before and after,
/// none stamped 23:59:59 or 00:00:00, and receiver reports in those two seconds; its
/// receiver reference times (section 5) skip them too.
#[test]
fn no_timestamp_is_generated_near_a_leap_second() {
    let base = Instant::now();
    let anchor = SystemInstant::at(base, Duration::from_secs(LAST_SECOND - 4));
    let mut chain = chain(
        builder()
            .with_wall_clock(anchor)
            .with_bandwidth(busy_session()),
    );
    chain.bind_local_stream(&video(100));
    let mut remote = video(200);
    remote.rtcp_feedback = vec![feedback("rrtr", "")];
    chain.bind_remote_stream(&remote);
    control(&mut chain, base, RtcpSessionControl::Start);
    let mut sent = vec![];
    for step in 0..500u32 {
        let now = base + Duration::from_millis(20) * step;
        chain
            .handle_write(rtp(now, 100, step as u16, step * 1800))
            .unwrap();
        chain
            .handle_read(rtp(now, 200, step as u16, step * 1800))
            .unwrap();
        sent.extend(run(&mut chain, now));
    }
    let leap_window = base + Duration::from_secs(4)..base + Duration::from_secs(6);
    let mut before = false;
    let mut after = false;
    let mut in_window = 0;
    for sent in &sent {
        for sr in sent.get::<SenderReport>() {
            assert!(
                !near_leap_second(sr.ntp_time),
                "an SR at {:?}",
                sent.at - base
            );
            if sent.at < leap_window.start {
                before = true;
            }
            if sent.at >= leap_window.end {
                after = true;
            }
        }
        for xr in sent.get::<ExtendedReport>() {
            for block in &xr.reports {
                if let Some(rrtr) = block
                    .as_any()
                    .downcast_ref::<ReceiverReferenceTimeReportBlock>()
                {
                    assert!(!near_leap_second(rrtr.ntp_timestamp));
                }
            }
        }
        if leap_window.contains(&sent.at) && sent.leader() == Some(100) {
            in_window += 1;
            assert!(
                sent.get::<ReceiverReport>().iter().any(|rr| rr.ssrc == 100),
                "a receiver report in place of the sender report at {:?}",
                sent.at - base
            );
        }
    }
    assert!(
        before && after,
        "sender reports before and after the leap second"
    );
    assert!(in_window >= 1, "the schedule kept in the two seconds");
}

/// RFC 7164 section 5.1: receivers "SHOULD ignore timestamps in any sender reports generated
/// in the vicinity of a positive leap second". A sender report stamped 23:59:59.5 on the last
/// day of a month does not replace the last one before it: the report block about its sender
/// keeps that one's LSR.
#[test]
fn a_sender_report_from_near_a_leap_second_is_ignored() {
    let base = Instant::now();
    let mut chain = chain(builder().with_bandwidth(busy_session()));
    chain.bind_remote_stream(&video(200));
    control(&mut chain, base, RtcpSessionControl::Start);
    let sr = |seconds: u64, millis: u64| -> Box<dyn rtcp::Packet> {
        Box::new(SenderReport {
            ssrc: 200,
            ntp_time: SystemInstant::unix2ntp(Duration::from_millis(seconds * 1000 + millis)),
            ..Default::default()
        })
    };
    chain.handle_read(rtp(base, 200, 1, 0)).unwrap();
    let earlier = sr(LAST_SECOND - 10, 0);
    let lsr = (earlier
        .as_any()
        .downcast_ref::<SenderReport>()
        .unwrap()
        .ntp_time
        >> 16) as u32;
    chain.handle_read(rtcp(base, vec![earlier])).unwrap();
    chain
        .handle_read(rtcp(
            base + Duration::from_millis(100),
            vec![sr(LAST_SECOND, 500)],
        ))
        .unwrap();
    chain
        .handle_read(rtp(base + Duration::from_millis(100), 200, 2, 90))
        .unwrap();
    read(&mut chain);
    let sent = run(&mut chain, base + Duration::from_secs(3));
    let blocks: Vec<u32> = sent
        .iter()
        .flat_map(|sent| {
            sent.get::<ReceiverReport>()
                .into_iter()
                .flat_map(|rr| rr.reports.iter().map(|block| block.last_sender_report))
                .collect::<Vec<_>>()
        })
        .collect();
    assert!(!blocks.is_empty());
    assert!(
        blocks.iter().all(|&block| block == lsr),
        "{blocks:?} against {lsr}"
    );
}
