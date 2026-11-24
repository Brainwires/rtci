//! RFC 3550 6.4: a sender report is issued only "if a site has sent any data packets during the
//! interval since issuing the last report or the previous one". A stream that stopped sending
//! stops issuing sender reports after two intervals, and issues them again when it sends again.

use rtci_interceptor::{
    AttributedPacket, Interceptor, Packet, Registry, SenderReportBuilder, Slot, StreamInfo,
    TaggedPacket,
};
use rtcp::goodbye::Goodbye;
use rtcp::receiver_report::ReceiverReport;
use rtcp::sender_report::SenderReport;
use sansio::Protocol;
use shared::TransportContext;
use std::time::{Duration, Instant};

const SSRC: u32 = 77;

fn info() -> StreamInfo {
    StreamInfo {
        ssrc: SSRC,
        clock_rate: 90000,
        mime_type: "video/VP8".to_string(),
        payload_type: 96,
        ..Default::default()
    }
}

fn rtp(now: Instant, sequence_number: u16) -> TaggedPacket {
    TaggedPacket {
        now,
        transport: TransportContext::default(),
        message: AttributedPacket::new(Packet::Rtp(rtp::Packet {
            header: rtp::header::Header {
                version: 2,
                ssrc: SSRC,
                payload_type: 96,
                sequence_number,
                ..Default::default()
            },
            payload: vec![0u8; 100].into(),
        })),
    }
}

fn chain() -> impl Interceptor {
    Registry::new()
        .with(Slot::SenderReport, SenderReportBuilder::new().build())
        .build()
}

/// The sender reports issued while the chain runs over the seconds `seconds` after `base`.
fn sender_reports(
    chain: &mut impl Interceptor,
    base: Instant,
    seconds: std::ops::RangeInclusive<u64>,
) -> usize {
    let mut count = 0;
    for second in seconds {
        chain
            .handle_timeout(base + Duration::from_secs(second))
            .unwrap();
        while let Some(tagged) = chain.poll_write() {
            if let Packet::Rtcp(packets) = tagged.message.packet {
                count += packets
                    .iter()
                    .filter(|packet| packet.as_any().is::<SenderReport>())
                    .count();
            }
        }
    }
    count
}

#[test]
fn a_stream_that_fell_silent_stops_sending_sender_reports() {
    let mut chain = chain();
    chain.bind_local_stream(&info());
    let base = Instant::now();
    chain.handle_write(rtp(base, 1)).unwrap();
    while chain.poll_write().is_some() {}

    // Ten report intervals with nothing sent: the interval the packet was sent in and the one
    // after it, no more.
    assert_eq!(2, sender_reports(&mut chain, base, 1..=10));
}

#[test]
fn a_stream_that_sends_again_reports_again() {
    let mut chain = chain();
    chain.bind_local_stream(&info());
    let base = Instant::now();
    chain.handle_write(rtp(base, 1)).unwrap();
    while chain.poll_write().is_some() {}
    assert_eq!(2, sender_reports(&mut chain, base, 1..=10));

    chain
        .handle_write(rtp(base + Duration::from_millis(10_500), 2))
        .unwrap();
    while chain.poll_write().is_some() {}
    assert_eq!(2, sender_reports(&mut chain, base, 11..=20));
}

#[test]
fn a_stream_that_keeps_sending_reports_every_interval() {
    let mut chain = chain();
    chain.bind_local_stream(&info());
    let base = Instant::now();
    let mut reports = 0;
    for second in 0..10u64 {
        chain
            .handle_write(rtp(
                base + Duration::from_secs(second) + Duration::from_millis(500),
                second as u16,
            ))
            .unwrap();
        while chain.poll_write().is_some() {}
        reports += sender_reports(&mut chain, base, second + 1..=second + 1);
    }
    // The timer is armed one interval after the first packet (0.5 s), so the first tick at
    // 1 s is early and the rest fire one per second.
    assert!(reports >= 9, "{reports} sender reports in ten seconds");
}

/// A stream that fell silent and is then stopped leads its goodbye with a receiver report: it
/// is no longer a sender, so it has no sender report to give (RFC 3550 6.4), and a BYE still
/// has to follow a report in its compound packet (6.1).
#[test]
fn a_silent_stream_says_goodbye_behind_a_receiver_report() {
    let mut chain = chain();
    chain.bind_local_stream(&info());
    let base = Instant::now();
    chain.handle_write(rtp(base, 1)).unwrap();
    while chain.poll_write().is_some() {}
    assert_eq!(2, sender_reports(&mut chain, base, 1..=10));

    chain.unbind_local_stream(&info());
    let compound = std::iter::from_fn(|| chain.poll_write())
        .find_map(|tagged| match tagged.message.packet {
            Packet::Rtcp(packets) => Some(packets),
            _ => None,
        })
        .expect("a goodbye compound packet");
    assert_eq!(2, compound.len());
    let report = compound[0]
        .as_any()
        .downcast_ref::<ReceiverReport>()
        .expect("a receiver report first");
    assert_eq!(SSRC, report.ssrc);
    assert!(report.reports.is_empty());
    let goodbye = compound[1]
        .as_any()
        .downcast_ref::<Goodbye>()
        .expect("a BYE");
    assert_eq!(vec![SSRC], goodbye.sources);
}
