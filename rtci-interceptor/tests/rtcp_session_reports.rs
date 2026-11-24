//! What the RTCP session says and who it says it as: one CNAME (RFC 7022), reports from the
//! endpoint's own SSRCs (RFC 8108), SR or RR by sender status (RFC 3550 6.4), BYE (6.6),
//! membership (6.2.1, 6.3.5) and SSRC collisions (8.2).

mod rtcp_session_common;

use rtci_interceptor::{
    Attribute, Interceptor, Packet, RtcpBandwidth, RtcpProfile, RtcpSessionControl,
    RtcpSessionEvent, StreamInfo,
};
use rtcp::extended_report::{DLRRReportBlock, ExtendedReport, ReceiverReferenceTimeReportBlock};
use rtcp::goodbye::Goodbye;
use rtcp::receiver_report::ReceiverReport;
use rtcp::reception_report::ReceptionReport;
use rtcp::sender_report::SenderReport;
use rtcp::source_description::{
    SdesType, SourceDescription, SourceDescriptionChunk, SourceDescriptionItem,
};
use rtcp_session_common::*;
use sansio::Protocol;
use std::time::{Duration, Instant};

fn sdes(source: u32, cname: &str) -> Box<dyn rtcp::Packet> {
    Box::new(SourceDescription {
        chunks: vec![SourceDescriptionChunk {
            source,
            items: vec![SourceDescriptionItem {
                sdes_type: SdesType::SdesCname,
                text: cname.to_string().into(),
            }],
        }],
    })
}

/// A session with room for the RTCP of many streams: 2 Mbit/s, so 12500 octets/s of RTCP.
fn busy_session() -> RtcpBandwidth {
    RtcpBandwidth {
        session: Some(2_000_000),
        ..Default::default()
    }
}

fn video_with_repair(ssrc: u32, rtx: u32, fec: u32) -> StreamInfo {
    StreamInfo {
        ssrc_rtx: Some(rtx),
        ssrc_fec: Some(fec),
        payload_type_rtx: Some(97),
        payload_type_fec: Some(98),
        ..video(ssrc)
    }
}

/// RFC 3550 6.1, RFC 8108 5.1, RFC 7022 4.2: an endpoint that only receives reports on every
/// stream from one SSRC of its own (not zero), in compound packets that name one CNAME of 96
/// random bits in Base64.
#[test]
fn a_receive_only_endpoint_reports_from_one_ssrc_under_one_cname() {
    let mut chain = chain(builder());
    let base = Instant::now();
    chain.bind_remote_stream(&video(200));
    chain.bind_remote_stream(&audio(300));
    control(&mut chain, base, RtcpSessionControl::Start);
    for sequence_number in 1..=5u16 {
        chain
            .handle_read(rtp(base, 200, sequence_number, 0))
            .unwrap();
        chain
            .handle_read(rtp(base, 300, sequence_number, 0))
            .unwrap();
    }
    read(&mut chain);

    let sent = run(&mut chain, base + secs(5.0));
    assert!(sent.len() >= 3);
    let mut cnames = vec![];
    for sent in &sent {
        assert!(sent.is_compound());
        assert_eq!(Some(REPORTER), sent.leader());
        assert_ne!(Some(0), sent.leader());
        // Both streams in the one receiver report.
        let mut reported = sent.reported();
        reported.sort_unstable();
        assert_eq!(vec![200, 300], reported);
        assert_eq!(1, sent.get::<ReceiverReport>().len());
        // The SDES follows the report and names the reporting SSRC.
        assert!(sent.packets[1].as_any().is::<SourceDescription>());
        let named = sent.cnames();
        assert_eq!(1, named.len());
        assert_eq!(REPORTER, named[0].0);
        cnames.push(named[0].1.clone());
    }
    assert_eq!(16, cnames[0].len());
    assert!(
        cnames[0]
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'+' || b == b'/')
    );
    assert!(cnames.iter().all(|cname| *cname == cnames[0]));
}

/// RFC 3550 6.1 and 6.4.2: with nothing to report, an empty RR heads the compound packet;
/// RFC 5506 4: compound RTCP is sent for the whole session, received media or not.
#[test]
fn an_endpoint_that_received_nothing_sends_an_empty_receiver_report() {
    let mut chain = chain(builder());
    let base = Instant::now();
    control(&mut chain, base, RtcpSessionControl::Start);

    let sent = run(&mut chain, base + secs(3.0));
    assert!(sent.len() >= 2);
    for sent in &sent {
        let reports = sent.get::<ReceiverReport>();
        assert_eq!(1, reports.len());
        assert!(reports[0].reports.is_empty());
        assert_eq!(1, sent.cnames().len());
    }
}

/// RFC 7022 4.2 / RFC 8834 4.9: the CNAME given to the session (the connection's) is the one
/// every SSRC is described with.
#[test]
fn the_cname_can_be_given() {
    let mut chain = chain(builder());
    let base = Instant::now();
    chain.bind_local_stream(&video(100));
    control(
        &mut chain,
        base,
        RtcpSessionControl::Cname("c0nnect1onCNAME+".to_string()),
    );
    control(&mut chain, base, RtcpSessionControl::Start);

    let sent = run(&mut chain, base + secs(1.0));
    assert_eq!(
        vec![(100, "c0nnect1onCNAME+".to_string())],
        sent[0].cnames()
    );
}

/// RFC 3550 6.4 and RFC 4588 6.1: every SSRC that sends RTP issues sender reports, the
/// retransmission and FEC SSRCs included, each with the CNAME (RFC 4588 5.2), aggregated in
/// one compound packet (RFC 8108 5.3).
#[test]
fn media_rtx_and_fec_ssrcs_all_send_sender_reports() {
    let mut chain = chain(builder());
    let base = Instant::now();
    chain.bind_local_stream(&video_with_repair(100, 101, 102));
    control(&mut chain, base, RtcpSessionControl::Start);
    for ssrc in [100, 101, 102] {
        chain.handle_write(rtp(base, ssrc, 1, 3000)).unwrap();
        chain.handle_write(rtp(base, ssrc, 2, 3000)).unwrap();
    }

    let sent = run(&mut chain, base + secs(1.0));
    assert!(!sent.is_empty());
    let first = &sent[0];
    let mut reports: Vec<(u32, u32, u32)> = first
        .get::<SenderReport>()
        .iter()
        .map(|sr| (sr.ssrc, sr.packet_count, sr.octet_count))
        .collect();
    reports.sort_unstable();
    assert_eq!(vec![(100, 2, 200), (101, 2, 200), (102, 2, 200)], reports);

    let mut cnames = first.cnames();
    cnames.sort();
    assert_eq!(3, cnames.len());
    assert_eq!(
        vec![100, 101, 102],
        cnames.iter().map(|c| c.0).collect::<Vec<_>>()
    );
    assert!(cnames.iter().all(|c| c.1 == cnames[0].1));
    assert_eq!(1, first.get::<SourceDescription>().len());
}

/// A repair SSRC that has sent nothing is not a participant: no report, no CNAME, no BYE.
#[test]
fn a_repair_ssrc_that_never_sent_stays_silent() {
    let mut chain = chain(builder());
    let base = Instant::now();
    chain.bind_local_stream(&video_with_repair(100, 101, 102));
    control(&mut chain, base, RtcpSessionControl::Start);
    chain.handle_write(rtp(base, 100, 1, 3000)).unwrap();

    let sent = run(&mut chain, base + secs(1.0));
    assert_eq!(
        vec![100],
        sent[0].cnames().iter().map(|c| c.0).collect::<Vec<_>>()
    );

    chain.unbind_local_stream(&video_with_repair(100, 101, 102));
    let sent = run(&mut chain, base + secs(1.1));
    let goodbye = sent
        .iter()
        .find_map(Sent::goodbye)
        .expect("the stream says BYE");
    assert_eq!(vec![100], goodbye.sources);
}

/// RFC 3550 6.4: the reception report blocks ride in the sender report of a sending SSRC.
#[test]
fn a_sender_carries_the_reception_reports_in_its_sender_report() {
    let mut chain = chain(builder());
    let base = Instant::now();
    chain.bind_local_stream(&video(100));
    chain.bind_remote_stream(&video(200));
    control(&mut chain, base, RtcpSessionControl::Start);
    chain.handle_write(rtp(base, 100, 1, 3000)).unwrap();
    chain.handle_read(rtp(base, 200, 7, 0)).unwrap();
    chain.handle_read(rtp(base, 200, 9, 0)).unwrap();
    read(&mut chain);

    let sent = run(&mut chain, base + secs(1.0));
    let reports = sent[0].get::<SenderReport>();
    assert_eq!(1, reports.len());
    assert_eq!(100, reports[0].ssrc);
    assert_eq!(1, reports[0].reports.len());
    assert_eq!(200, reports[0].reports[0].ssrc);
    assert_eq!(9, reports[0].reports[0].last_sequence_number);
    assert_eq!(1, reports[0].reports[0].cumulative_lost());
    assert!(sent[0].get::<ReceiverReport>().is_empty());
}

/// RFC 3550 6.4, 6.3.5 and 6.3.8: a participant that has not sent RTP for two report
/// intervals is no longer a sender and issues receiver reports.
#[test]
fn a_sender_that_falls_silent_goes_back_to_receiver_reports() {
    let mut chain = chain(builder());
    let base = Instant::now();
    chain.bind_local_stream(&video(100));
    control(&mut chain, base, RtcpSessionControl::Start);
    chain.handle_write(rtp(base, 100, 1, 3000)).unwrap();

    let sent = run(&mut chain, base + secs(10.0));
    let sender_reports: Vec<f64> = sent
        .iter()
        .filter(|sent| sent.has::<SenderReport>())
        .map(|sent| sent.at.duration_since(base).as_secs_f64())
        .collect();
    assert!(!sender_reports.is_empty());
    // Two report intervals of one second.
    assert!(
        sender_reports.iter().all(|at| *at <= 2.0),
        "{sender_reports:?}"
    );
    let receiver_reports: Vec<&Sent> = sent
        .iter()
        .filter(|sent| sent.has::<ReceiverReport>())
        .collect();
    assert!(receiver_reports.len() >= 5);
    assert!(
        receiver_reports
            .iter()
            .all(|sent| sent.leader() == Some(100))
    );

    // It sends again: sender reports again.
    chain
        .handle_write(rtp(base + secs(10.0), 100, 2, 6000))
        .unwrap();
    let sent = run(&mut chain, base + secs(11.5));
    assert!(sent.iter().any(|sent| sent.has::<SenderReport>()));
}

/// RFC 3550 6.6 and 6.1: an SSRC that stops says BYE, last in a compound packet behind its
/// report and CNAME; one that never sent RTP or RTCP says nothing (6.3.7).
#[test]
fn a_stream_that_stops_says_bye() {
    let mut chain = chain(builder());
    let base = Instant::now();
    chain.bind_local_stream(&video(100));
    control(&mut chain, base, RtcpSessionControl::Start);
    chain.handle_write(rtp(base, 100, 1, 3000)).unwrap();
    run(&mut chain, base + secs(0.5));

    chain.unbind_local_stream(&video(100));
    let sent = run(&mut chain, base + secs(0.6));
    let farewell = sent
        .iter()
        .find(|sent| sent.goodbye().is_some())
        .expect("a BYE");
    assert!(farewell.is_compound());
    assert_eq!(Some(100), farewell.leader());
    assert!(farewell.has::<SenderReport>());
    assert_eq!(
        vec![100],
        farewell.cnames().iter().map(|c| c.0).collect::<Vec<_>>()
    );
    assert_eq!(vec![100], farewell.goodbye().unwrap().sources);

    // The endpoint goes on reporting, from an SSRC of its own now.
    let sent = run(&mut chain, base + secs(3.0));
    assert!(sent.iter().any(|sent| sent.leader() == Some(REPORTER)));
    assert!(sent.iter().all(|sent| sent.leader() != Some(100)));
}

#[test]
fn a_stream_that_never_sent_anything_leaves_without_a_bye() {
    let mut chain = chain(builder());
    let base = Instant::now();
    chain.bind_local_stream(&video(100));
    control(&mut chain, base, RtcpSessionControl::Start);
    chain.unbind_local_stream(&video(100));

    let sent = run(&mut chain, base + secs(3.0));
    assert!(sent.iter().all(|sent| sent.goodbye().is_none()));
}

/// A renegotiation unbinds a stream and binds it again with the same SSRC: no BYE, and the
/// sender report's counts carry on.
#[test]
fn a_stream_bound_again_says_no_bye_and_keeps_its_counts() {
    let mut chain = chain(builder());
    let base = Instant::now();
    chain.bind_local_stream(&video(100));
    control(&mut chain, base, RtcpSessionControl::Start);
    chain.handle_write(rtp(base, 100, 1, 3000)).unwrap();

    chain.unbind_local_stream(&video(100));
    chain.bind_local_stream(&StreamInfo {
        payload_type: 102,
        mime_type: "video/H264".to_string(),
        ..video(100)
    });
    chain
        .handle_write(rtp(base + secs(0.01), 100, 2, 6000))
        .unwrap();

    let sent = run(&mut chain, base + secs(1.5));
    assert!(sent.iter().all(|sent| sent.goodbye().is_none()));
    let report = sent
        .iter()
        .find_map(|sent| sent.get::<SenderReport>().first().copied())
        .expect("a sender report");
    assert_eq!(2, report.packet_count);
}

/// RFC 8108 6.1: "An endpoint that has never sent an RTP stream will have an SSRC that it
/// uses for RTCP reporting. If that endpoint wants to start sending an RTP stream, it is
/// RECOMMENDED that it use its existing SSRC for that stream". The session reports from the
/// SSRC it was given for the first stream; when that stream is bound and sends, the SSRC
/// goes on as the same participant: no BYE, no second SSRC, and its reports become sender
/// reports.
#[test]
fn the_first_stream_takes_over_the_reporting_ssrc() {
    const FIRST_STREAM: u32 = 0x0bad_cafe;
    let mut chain = chain(builder());
    let base = Instant::now();
    chain.bind_remote_stream(&video(200));
    control(
        &mut chain,
        base,
        RtcpSessionControl::ReportingSsrc(FIRST_STREAM),
    );
    control(&mut chain, base, RtcpSessionControl::Start);
    chain.handle_read(rtp(base, 200, 1, 0)).unwrap();
    read(&mut chain);
    let sent = run(&mut chain, base + secs(3.0));
    assert!(!sent.is_empty());
    assert!(sent.iter().all(|sent| sent.leader() == Some(FIRST_STREAM)));
    assert!(sent.iter().all(|sent| sent.has::<ReceiverReport>()));

    chain.bind_local_stream(&video(FIRST_STREAM));
    for n in 0..50u16 {
        let at = base + secs(3.0) + Duration::from_millis(20 * u64::from(n));
        chain
            .handle_write(rtp(at, FIRST_STREAM, n, 3000 * u32::from(n)))
            .unwrap();
    }
    let sent = run(&mut chain, base + secs(8.0));
    assert!(
        sent.iter().all(|sent| sent.goodbye().is_none()),
        "the reporting SSRC said BYE"
    );
    assert!(sent.iter().all(|sent| sent.leader() == Some(FIRST_STREAM)));
    let report = sent
        .iter()
        .find_map(|sent| sent.get::<SenderReport>().first().copied())
        .expect("a sender report from the stream");
    assert_eq!(FIRST_STREAM, report.ssrc);

    // A second stream gets an SSRC of its own; the first one stays a sender (it was a
    // reporting SSRC once, it is a stream now) and says no BYE.
    const SECOND_STREAM: u32 = 0x0bad_caff;
    chain.bind_local_stream(&video(SECOND_STREAM));
    for n in 50..100u16 {
        let at = base + secs(8.0) + Duration::from_millis(20 * u64::from(n - 50));
        for ssrc in [FIRST_STREAM, SECOND_STREAM] {
            chain
                .handle_write(rtp(at, ssrc, n, 3000 * u32::from(n)))
                .unwrap();
        }
    }
    let sent = run(&mut chain, base + secs(12.0));
    assert!(
        sent.iter().all(|sent| sent.goodbye().is_none()),
        "the first stream said BYE when the second came"
    );
    assert!(sent.iter().any(|sent| {
        sent.get::<SenderReport>()
            .iter()
            .any(|sr| sr.ssrc == FIRST_STREAM)
    }));
}

/// RFC 8108 6.2: an SSRC that said BYE is not used again. The reporting SSRC the session was
/// given is for its first join: after it left (BYE from that SSRC) and joins again, it
/// reports from a new SSRC even when given the same one.
#[test]
fn the_given_reporting_ssrc_is_not_used_again_after_a_bye() {
    const FIRST_STREAM: u32 = 0x0bad_cafe;
    let mut chain = chain(builder());
    let base = Instant::now();
    control(
        &mut chain,
        base,
        RtcpSessionControl::ReportingSsrc(FIRST_STREAM),
    );
    control(&mut chain, base, RtcpSessionControl::Start);
    let sent = run(&mut chain, base + secs(1.0));
    assert_eq!(Some(FIRST_STREAM), sent[0].leader());
    control(&mut chain, base + secs(1.0), RtcpSessionControl::Leave);
    let sent = written(&mut chain);
    assert_eq!(
        vec![FIRST_STREAM],
        sent[0].goodbye().expect("a BYE").sources
    );

    control(
        &mut chain,
        base + secs(2.0),
        RtcpSessionControl::ReportingSsrc(FIRST_STREAM),
    );
    control(&mut chain, base + secs(2.0), RtcpSessionControl::Start);
    let sent = run(&mut chain, base + secs(5.0));
    assert!(!sent.is_empty());
    assert!(sent.iter().all(|sent| sent.leader() != Some(FIRST_STREAM)));
}

/// RFC 3550 6.6: when the endpoint leaves, every SSRC it used says BYE, the reporting SSRC of
/// a receive-only endpoint included, and nothing follows the BYE.
#[test]
fn every_ssrc_says_bye_when_the_endpoint_leaves() {
    let mut chain = chain(builder());
    let base = Instant::now();
    chain.bind_local_stream(&video_with_repair(100, 101, 102));
    control(&mut chain, base, RtcpSessionControl::Start);
    chain.handle_write(rtp(base, 100, 1, 3000)).unwrap();
    chain.handle_write(rtp(base, 101, 1, 3000)).unwrap();
    run(&mut chain, base + secs(1.0));

    control(&mut chain, base + secs(1.0), RtcpSessionControl::Leave);
    let sent = written(&mut chain);
    assert_eq!(1, sent.len());
    let mut sources = sent[0].goodbye().expect("a BYE").sources.clone();
    sources.sort_unstable();
    // 102 never sent a packet: it says nothing.
    assert_eq!(vec![100, 101], sources);
    assert!(sent[0].is_compound());

    assert!(run(&mut chain, base + secs(10.0)).is_empty());

    let mut receiver = self::chain(builder());
    control(&mut receiver, base, RtcpSessionControl::Start);
    run(&mut receiver, base + secs(1.0));
    control(&mut receiver, base + secs(1.0), RtcpSessionControl::Leave);
    let sent = written(&mut receiver);
    assert_eq!(vec![REPORTER], sent[0].goodbye().expect("a BYE").sources);
}

/// RFC 3550 6.6 / 6.2.1: a source that said BYE is gone: it is not reported on, and a packet
/// that the BYE overtook does not bring it back.
#[test]
fn a_source_that_said_bye_is_no_longer_reported() {
    let mut chain = chain(builder());
    let base = Instant::now();
    chain.bind_remote_stream(&video(200));
    chain.bind_remote_stream(&video(201));
    control(&mut chain, base, RtcpSessionControl::Start);
    chain.handle_read(rtp(base, 200, 1, 0)).unwrap();
    chain.handle_read(rtp(base, 201, 1, 0)).unwrap();
    let sent = run(&mut chain, base + secs(1.0));
    let mut reported = sent[0].reported();
    reported.sort_unstable();
    assert_eq!(vec![200, 201], reported);

    chain
        .handle_read(rtcp(
            base + secs(1.0),
            vec![Box::new(Goodbye {
                sources: vec![200],
                reason: Default::default(),
            })],
        ))
        .unwrap();
    chain.handle_read(rtp(base + secs(1.1), 200, 2, 0)).unwrap();
    read(&mut chain);

    let sent = run(&mut chain, base + secs(4.0));
    assert!(!sent.is_empty());
    assert!(sent.iter().all(|sent| sent.reported() == vec![201]));
}

/// RFC 3550 6.3.5 with RFC 8108 7.1.4: a source nothing was heard from for five intervals
/// (of at least five seconds each) is timed out.
#[test]
fn a_source_that_fell_silent_times_out_after_five_intervals() {
    let mut chain = chain(builder());
    let base = Instant::now();
    chain.bind_remote_stream(&video(200));
    control(&mut chain, base, RtcpSessionControl::Start);
    chain.handle_read(rtp(base, 200, 1, 0)).unwrap();
    read(&mut chain);

    let before = run(&mut chain, base + secs(24.0));
    assert!(before.iter().all(|sent| sent.reported() == vec![200]));
    let (_, events) = read(&mut chain);
    assert!(events.is_empty(), "{events:?}");

    let after = run(&mut chain, base + secs(30.0));
    let (_, events) = read(&mut chain);
    assert_eq!(vec![RtcpSessionEvent::SourceTimedOut { ssrc: 200 }], events);
    assert!(after.last().unwrap().reported().is_empty());

    // Heard again, it is reported again.
    chain
        .handle_read(rtp(base + secs(30.0), 200, 2, 0))
        .unwrap();
    let sent = run(&mut chain, base + secs(32.0));
    assert_eq!(vec![200], sent.last().unwrap().reported());
}

/// RFC 8834 section 4.1 (RFC 3550 6.2 and 6.3.5): with the reduced minimum interval in use
/// (half a second at 720 kbit/s), the participant timeout still counts five intervals of the
/// fixed five-second minimum. A source heard once is reported for 25 seconds, not timed out
/// after 2.5.
#[test]
fn the_participant_timeout_keeps_the_fixed_minimum_under_the_reduced_minimum() {
    let mut chain = chain(
        builder()
            .with_profile(RtcpProfile::Avp)
            .with_reduced_minimum(true)
            .with_bandwidth(RtcpBandwidth {
                session: Some(720_000),
                ..Default::default()
            }),
    );
    let base = Instant::now();
    chain.bind_remote_stream(&video(200));
    control(&mut chain, base, RtcpSessionControl::Start);
    chain.handle_read(rtp(base, 200, 1, 0)).unwrap();
    read(&mut chain);

    let before = run(&mut chain, base + secs(20.0));
    assert!(before.len() > 20, "reports come every half second or so");
    assert!(
        before.iter().all(|sent| sent.reported() == vec![200]),
        "still a member after 20 s"
    );
    let (_, events) = read(&mut chain);
    assert!(events.is_empty(), "{events:?}");

    run(&mut chain, base + secs(30.0));
    let (_, events) = read(&mut chain);
    assert_eq!(vec![RtcpSessionEvent::SourceTimedOut { ssrc: 200 }], events);
}

/// RFC 7160 section 4.3: a source that switches payload type, and with it clock rate, on one
/// SSRC (Opus at 48 kHz to PCMU at 8 kHz) is timed with each packet's own rate: perfectly
/// paced packets show no jitter in the receiver report.
#[test]
fn a_switch_of_clock_rate_on_one_ssrc_shows_no_jitter_on_a_steady_path() {
    let mut chain = chain(builder());
    let base = Instant::now();
    let mut remote = audio(200);
    remote.payload_clock_rates = vec![(0, 8_000)];
    chain.bind_remote_stream(&remote);
    control(&mut chain, base, RtcpSessionControl::Start);
    let mut timestamp = 1_000u32;
    for seq in 0..50u16 {
        let at = base + Duration::from_millis(20 * u64::from(seq));
        let mut packet = rtp(at, 200, seq, timestamp);
        let pcmu = seq >= 25;
        if let Packet::Rtp(p) = &mut packet.message.packet {
            p.header.payload_type = if pcmu { 0 } else { 111 };
        }
        chain.handle_read(packet).unwrap();
        // 20 ms: 960 ticks at 48 kHz, 160 at 8 kHz.
        timestamp = timestamp.wrapping_add(if pcmu { 160 } else { 960 });
    }
    read(&mut chain);
    let sent = run(&mut chain, base + secs(1.5));
    let jitter: Vec<u32> = sent
        .iter()
        .flat_map(|sent| sent.get::<ReceiverReport>())
        .flat_map(|rr| rr.reports.iter())
        .filter(|report| report.ssrc == 200)
        .map(|report| report.jitter)
        .collect();
    assert!(!jitter.is_empty());
    assert!(jitter.iter().all(|j| *j <= 60), "{jitter:?}");
}

/// RFC 3550 6.5.1: the CNAME a remote source names is what binds its streams together; the
/// session reports it.
#[test]
fn a_remote_cname_is_reported_once_and_when_it_changes() {
    let mut chain = chain(builder());
    let base = Instant::now();
    control(&mut chain, base, RtcpSessionControl::Start);
    for _ in 0..2 {
        chain
            .handle_read(rtcp(base, vec![sdes(200, "peer"), sdes(201, "peer")]))
            .unwrap();
    }
    chain
        .handle_read(rtcp(base, vec![sdes(200, "other")]))
        .unwrap();

    let (_, events) = read(&mut chain);
    let cname = |ssrc, cname: &str| RtcpSessionEvent::RemoteCname {
        ssrc,
        cname: cname.to_string(),
    };
    assert_eq!(
        vec![cname(200, "peer"), cname(201, "peer"), cname(200, "other")],
        events
    );
}

/// RFC 3550 8.2: a packet from the network under the endpoint's own reporting SSRC is a
/// collision: BYE with the old identifier, a new one that nobody uses, and the packet is not
/// taken for a stream.
#[test]
fn a_collision_with_the_reporting_ssrc_moves_it() {
    let mut chain = chain(builder());
    let base = Instant::now();
    control(&mut chain, base, RtcpSessionControl::Start);
    let sent = run(&mut chain, base + secs(0.5));
    assert_eq!(Some(REPORTER), sent[0].leader());

    chain
        .handle_read(rtp(base + secs(0.5), REPORTER, 1, 0))
        .unwrap();
    let (packets, events) = read(&mut chain);
    assert!(packets.is_empty(), "the colliding packet is dropped");
    let replacement = REPORTER + 1;
    assert_eq!(
        vec![RtcpSessionEvent::SsrcCollision {
            ssrc: REPORTER,
            replacement
        }],
        events
    );

    let sent = written(&mut chain);
    assert_eq!(vec![REPORTER], sent[0].goodbye().expect("a BYE").sources);
    assert_eq!(Some(REPORTER), sent[0].leader());

    let sent = run(&mut chain, base + secs(3.0));
    assert!(!sent.is_empty());
    assert!(sent.iter().all(|sent| sent.leader() == Some(replacement)));
}

/// RFC 3550 8.2 for a sender's SSRC: the collision is reported once, with an SSRC that is
/// free, and the packets are dropped (the endpoint's own packets looped back look the same).
/// RTCP under a local SSRC is a collision too.
#[test]
fn a_collision_with_a_sender_ssrc_is_reported_and_the_packets_dropped() {
    let mut chain = chain(builder());
    let base = Instant::now();
    chain.bind_local_stream(&video(100));
    control(&mut chain, base, RtcpSessionControl::Start);

    chain.handle_read(rtp(base, 100, 1, 0)).unwrap();
    chain.handle_read(rtp(base, 100, 2, 0)).unwrap();
    let (packets, events) = read(&mut chain);
    assert!(packets.is_empty());
    assert_eq!(1, events.len());
    let RtcpSessionEvent::SsrcCollision { ssrc, replacement } = &events[0] else {
        panic!("{events:?}");
    };
    assert_eq!(100, *ssrc);
    assert!(*replacement != 0 && *replacement != 100);

    // A second session: the collision shows in RTCP.
    let mut chain = self::chain(builder());
    chain.bind_local_stream(&video(100));
    control(&mut chain, base, RtcpSessionControl::Start);
    chain
        .handle_read(rtcp(
            base,
            vec![Box::new(ReceiverReport {
                ssrc: 100,
                ..Default::default()
            })],
        ))
        .unwrap();
    let (_, events) = read(&mut chain);
    assert!(matches!(
        events[..],
        [RtcpSessionEvent::SsrcCollision { ssrc: 100, .. }]
    ));
}

/// RFC 4588 6.2 (and section 3): a retransmission is counted on the RTX stream it arrived
/// on, so the report on the original stream keeps showing what the path lost.
#[test]
fn a_retransmission_counts_on_the_rtx_stream_not_on_the_stream_it_repairs() {
    let mut chain = chain(builder());
    let base = Instant::now();
    chain.bind_remote_stream(&video(200));
    chain.bind_remote_stream(&video(201));
    control(&mut chain, base, RtcpSessionControl::Start);
    for sequence_number in [1u16, 2, 4] {
        chain
            .handle_read(rtp(base, 200, sequence_number, 0))
            .unwrap();
    }
    // Sequence number 3 again, as the handler hands it over: rewritten into the original,
    // tagged with what it was on the wire.
    let mut repaired = rtp(base, 200, 3, 0);
    repaired.message.add(Attribute::Retransmitted {
        ssrc: 201,
        sequence_number: 77,
    });
    chain.handle_read(repaired).unwrap();
    let (packets, _) = read(&mut chain);
    assert_eq!(4, packets.len(), "the repaired packet goes on to the chain");
    assert!(matches!(&packets[3].message.packet, Packet::Rtp(p) if p.header.sequence_number == 3));

    let sent = run(&mut chain, base + secs(1.0));
    let blocks: Vec<&ReceptionReport> = sent[0]
        .get::<ReceiverReport>()
        .iter()
        .flat_map(|rr| &rr.reports)
        .collect();
    let primary = blocks.iter().find(|block| block.ssrc == 200).unwrap();
    assert_eq!(4, primary.last_sequence_number);
    assert_eq!(1, primary.cumulative_lost());
    let rtx = blocks.iter().find(|block| block.ssrc == 201).unwrap();
    assert_eq!(77, rtx.last_sequence_number);
    assert_eq!(0, rtx.cumulative_lost());
}

/// RFC 3550 6.1: a report carries 31 blocks; with more sources, further RR packets follow in
/// the same compound packet.
#[test]
fn more_than_31_streams_are_reported_in_additional_receiver_reports() {
    let mut chain = chain(builder().with_bandwidth(busy_session()));
    let base = Instant::now();
    control(&mut chain, base, RtcpSessionControl::Start);
    for stream in 0..40u32 {
        chain.bind_remote_stream(&video(1000 + stream));
        chain.handle_read(rtp(base, 1000 + stream, 1, 0)).unwrap();
    }
    read(&mut chain);

    let sent = run(&mut chain, base + secs(4.0));
    let first = &sent[0];
    let reports = first.get::<ReceiverReport>();
    assert_eq!(2, reports.len());
    assert_eq!(31, reports[0].reports.len());
    assert_eq!(9, reports[1].reports.len());
    assert!(reports.iter().all(|rr| rr.ssrc == REPORTER));
    let mut reported = first.reported();
    reported.sort_unstable();
    reported.dedup();
    assert_eq!(40, reported.len());
    assert_eq!(1, first.cnames().len());
}

/// RFC 3550 6.1: a compound packet stays under the MTU; the streams that do not fit are
/// reported in the next one, in turn.
#[test]
fn reports_that_do_not_fit_the_mtu_take_turns() {
    let mut chain = chain(builder().with_mtu(300).with_bandwidth(busy_session()));
    let base = Instant::now();
    control(&mut chain, base, RtcpSessionControl::Start);
    for stream in 0..20u32 {
        chain.bind_remote_stream(&video(1000 + stream));
        chain.handle_read(rtp(base, 1000 + stream, 1, 0)).unwrap();
    }
    read(&mut chain);

    let sent = run(&mut chain, base + secs(6.0));
    assert!(sent.len() >= 3);
    let mut seen = std::collections::HashSet::new();
    for sent in &sent {
        let size: usize = sent.packets.iter().map(|p| p.marshal_size()).sum();
        assert!(size <= 300, "{size} octets");
        assert!(sent.reported().len() < 20);
        seen.extend(sent.reported());
    }
    assert_eq!(
        20,
        seen.len(),
        "every stream is reported over the intervals"
    );
}

/// RFC 8083 section 4.3: when the reports do not all fit, "priority SHOULD be given to
/// reports on sources that have high packet loss rates". Of twenty streams, two lose a quarter
/// of their packets; they are in every compound packet, and the others still take turns.
#[test]
fn reports_on_lossy_sources_go_first_when_not_all_fit() {
    let mut chain = chain(builder().with_mtu(300).with_bandwidth(busy_session()));
    let base = Instant::now();
    control(&mut chain, base, RtcpSessionControl::Start);
    for stream in 0..20u32 {
        chain.bind_remote_stream(&video(1000 + stream));
    }
    // Every stream sends one packet each 50 ms; 1007 and 1013 lose one in four.
    let mut seq = 0u16;
    let mut at = base;
    let mut sent = Vec::new();
    while at < base + secs(6.0) {
        seq = seq.wrapping_add(1);
        for stream in 0..20u32 {
            let ssrc = 1000 + stream;
            if (ssrc == 1007 || ssrc == 1013) && seq.is_multiple_of(4) {
                continue;
            }
            chain.handle_read(rtp(at, ssrc, seq, 0)).unwrap();
        }
        read(&mut chain);
        at += Duration::from_millis(50);
        sent.extend(run(&mut chain, at));
    }
    let with_blocks: Vec<&Sent> = sent.iter().filter(|s| !s.reported().is_empty()).collect();
    assert!(with_blocks.len() >= 3);
    for packet in &with_blocks[1..] {
        let reported = packet.reported();
        assert!(reported.len() < 20, "not all fit");
        assert!(
            reported.contains(&1007) && reported.contains(&1013),
            "the lossy sources in every report: {reported:?}"
        );
    }
    let mut seen = std::collections::HashSet::new();
    for packet in &with_blocks {
        seen.extend(packet.reported());
    }
    assert_eq!(
        20,
        seen.len(),
        "every stream is still reported over the intervals"
    );
}

/// RFC 8108 5.1 to the letter, as an option: every local SSRC reports on every remote one.
#[test]
fn every_local_ssrc_can_report_on_every_remote_one() {
    let mut chain = chain(builder().with_report_from_every_ssrc(true));
    let base = Instant::now();
    chain.bind_local_stream(&audio(10));
    chain.bind_local_stream(&video(20));
    chain.bind_remote_stream(&video(200));
    control(&mut chain, base, RtcpSessionControl::Start);
    chain.handle_read(rtp(base, 200, 1, 0)).unwrap();
    read(&mut chain);

    let sent = run(&mut chain, base + secs(1.5));
    let reports = sent[0].get::<ReceiverReport>();
    assert_eq!(2, reports.len());
    assert!(
        reports
            .iter()
            .all(|rr| rr.reports.len() == 1 && rr.reports[0].ssrc == 200)
    );

    // By default the blocks are carried once, by the first media SSRC.
    let mut chain = self::chain(builder());
    chain.bind_local_stream(&audio(10));
    chain.bind_local_stream(&video(20));
    chain.bind_remote_stream(&video(200));
    control(&mut chain, base, RtcpSessionControl::Start);
    chain.handle_read(rtp(base, 200, 1, 0)).unwrap();
    read(&mut chain);
    let sent = run(&mut chain, base + secs(1.5));
    assert_eq!(vec![200], sent[0].reported());
    let carrier = sent[0]
        .get::<ReceiverReport>()
        .into_iter()
        .find(|rr| !rr.reports.is_empty())
        .unwrap();
    assert_eq!(10, carrier.ssrc);
}

/// RFC 3611 4.4 and 4.5: the receiver reference time rides the regular report when the stream
/// negotiated it, and a sender answers the reference times it received with a DLRR block.
#[test]
fn reference_times_are_sent_and_answered_in_the_regular_report() {
    let mut chain = chain(builder());
    let base = Instant::now();
    let mut remote = video(200);
    remote.rtcp_feedback.push(feedback("rrtr", ""));
    chain.bind_remote_stream(&remote);
    control(&mut chain, base, RtcpSessionControl::Start);
    chain.handle_read(rtp(base, 200, 1, 0)).unwrap();
    read(&mut chain);

    let sent = run(&mut chain, base + secs(1.0));
    let xr = sent[0].get::<ExtendedReport>();
    assert_eq!(1, xr.len());
    assert_eq!(REPORTER, xr[0].sender_ssrc);
    assert!(
        xr[0].reports[0]
            .as_any()
            .is::<ReceiverReferenceTimeReportBlock>()
    );

    // The other side: a sender that is sent a reference time.
    let mut chain = self::chain(builder().with_bandwidth(RtcpBandwidth {
        session: Some(64_000),
        ..Default::default()
    }));
    chain.bind_local_stream(&video(100));
    control(&mut chain, base, RtcpSessionControl::Start);
    chain.handle_write(rtp(base, 100, 1, 0)).unwrap();
    chain
        .handle_read(rtcp(
            base + secs(0.1),
            vec![Box::new(ExtendedReport {
                sender_ssrc: 300,
                reports: vec![Box::new(ReceiverReferenceTimeReportBlock {
                    ntp_timestamp: 0x1234_5678_9abc_def0,
                })],
            })],
        ))
        .unwrap();
    read(&mut chain);
    let sent = run(&mut chain, base + secs(1.0));
    let answered = sent
        .iter()
        .flat_map(|sent| sent.get::<ExtendedReport>())
        .next()
        .expect("an XR with the answer");
    let dlrr = answered.reports[0]
        .as_any()
        .downcast_ref::<DLRRReportBlock>()
        .expect("a DLRR block");
    assert_eq!(300, dlrr.reports[0].ssrc);
    assert_eq!(0x5678_9abc, dlrr.reports[0].last_rr);
    // RFC 3611 4.5: the delay between receiving the reference time and sending this, in
    // 1/65536 s.
    let carrier = sent
        .iter()
        .find(|sent| sent.has::<ExtendedReport>())
        .unwrap();
    let held = carrier.at.duration_since(base + secs(0.1)).as_secs_f64();
    assert!(held > 0.0);
    assert!(
        (f64::from(dlrr.reports[0].dlrr) - held * 65536.0).abs() <= 1.0,
        "{} for {held} s",
        dlrr.reports[0].dlrr
    );
}

/// RFC 8834 section 8 (RFC 3611 section 3): an XR block of a type this endpoint does not
/// understand is ignored, and the blocks around it are still acted on. Here an unknown block
/// type (99) comes before a receiver reference time, which is still answered with a DLRR.
#[test]
fn an_unknown_xr_block_is_ignored_and_the_next_block_answered() {
    let base = Instant::now();
    let mut chain = chain(builder().with_bandwidth(RtcpBandwidth {
        session: Some(64_000),
        ..Default::default()
    }));
    chain.bind_local_stream(&video(100));
    control(&mut chain, base, RtcpSessionControl::Start);
    chain.handle_write(rtp(base, 100, 1, 0)).unwrap();
    let raw: [u8; 28] = [
        0x80, 207, 0, 6, // XR, length 6 words
        0, 0, 1, 44, // sender SSRC 300
        99, 0, 0, 1, // block type 99, one word
        0xde, 0xad, 0xbe, 0xef, //
        4, 0, 0, 2, // receiver reference time, two words
        0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
    ];
    let packets = rtcp::packet::unmarshal(&mut &raw[..]).unwrap();
    let xr = packets[0]
        .as_any()
        .downcast_ref::<ExtendedReport>()
        .expect("an XR");
    assert_eq!(2, xr.reports.len(), "the unknown block is kept apart");
    chain.handle_read(rtcp(base + secs(0.1), packets)).unwrap();
    read(&mut chain);

    let sent = run(&mut chain, base + secs(1.0));
    let answered = sent
        .iter()
        .flat_map(|sent| sent.get::<ExtendedReport>())
        .next()
        .expect("an XR with the answer");
    let dlrr = answered
        .reports
        .iter()
        .find_map(|block| block.as_any().downcast_ref::<DLRRReportBlock>())
        .expect("a DLRR block");
    assert_eq!(300, dlrr.reports[0].ssrc);
    assert_eq!(0x5678_9abc, dlrr.reports[0].last_rr);
}

fn reference_time(at: Instant, from: u32) -> rtci_interceptor::TaggedPacket {
    rtcp(
        at,
        vec![Box::new(ExtendedReport {
            sender_ssrc: from,
            reports: vec![Box::new(ReceiverReferenceTimeReportBlock {
                ntp_timestamp: u64::from(from) << 32,
            })],
        })],
    )
}

/// RFC 3611 section 5.1: under `rcvr-rtt=sender` "non RTP senders SHALL NOT send DLRR
/// blocks". An endpoint that only receives is sent reference times and answers none.
#[test]
fn a_receive_only_endpoint_answers_no_reference_time() {
    let base = Instant::now();
    let mut chain = chain(builder());
    let mut remote = video(200);
    remote
        .rtcp_feedback
        .push(feedback("rrtr", "rcvr-rtt=sender"));
    chain.bind_remote_stream(&remote);
    control(&mut chain, base, RtcpSessionControl::Start);
    chain.handle_read(rtp(base, 200, 1, 0)).unwrap();
    chain.handle_read(reference_time(base, 200)).unwrap();
    read(&mut chain);

    let sent = run(&mut chain, base + secs(5.0));
    assert!(!sent.is_empty());
    for sent in &sent {
        for xr in sent.get::<ExtendedReport>() {
            assert!(
                !xr.reports
                    .iter()
                    .any(|b| b.as_any().is::<DLRRReportBlock>()),
                "{xr:?}"
            );
        }
    }
}

/// RFC 3611 section 5.1: "any DLRR Report Blocks that are sent SHALL NOT exceed the specified
/// size"; what does not fit is reported on in a later interval. `rcvr-rtt=sender:28` holds
/// two sub-blocks (4 octets of header, 12 each): of three reference times, the two oldest go
/// first and the third in the next report.
#[test]
fn a_dlrr_block_keeps_to_the_signalled_size_and_the_rest_waits() {
    let base = Instant::now();
    let mut chain = chain(builder().with_bandwidth(RtcpBandwidth {
        session: Some(64_000),
        ..Default::default()
    }));
    let mut local = video(100);
    local
        .rtcp_feedback
        .push(feedback("rrtr", "rcvr-rtt=sender:28"));
    chain.bind_local_stream(&local);
    control(&mut chain, base, RtcpSessionControl::Start);
    chain.handle_write(rtp(base, 100, 1, 0)).unwrap();
    for (i, from) in [300u32, 301, 302].into_iter().enumerate() {
        chain
            .handle_read(reference_time(base + secs(0.01 * i as f64), from))
            .unwrap();
    }
    read(&mut chain);

    // Sending all along, so the endpoint stays a sender.
    let mut sent = vec![];
    for k in 1..100u16 {
        let at = base + secs(0.1 * f64::from(k));
        chain
            .handle_write(rtp(at, 100, k + 1, u32::from(k) * 9_000))
            .unwrap();
        sent.extend(run(&mut chain, at));
    }
    let answers: Vec<Vec<u32>> = sent
        .iter()
        .flat_map(|sent| sent.get::<ExtendedReport>())
        .flat_map(|xr| xr.reports.iter())
        .filter_map(|b| b.as_any().downcast_ref::<DLRRReportBlock>())
        .map(|dlrr| dlrr.reports.iter().map(|r| r.ssrc).collect())
        .collect();
    assert_eq!(vec![vec![300, 301], vec![302]], answers);
}

/// RFC 3550 6.4.1: the round trip is the time since the sender report less the delay the
/// receiver held it for.
#[test]
fn a_report_block_about_a_local_stream_gives_the_round_trip_time() {
    let mut chain = chain(builder());
    let base = Instant::now();
    chain.bind_local_stream(&video(100));
    control(&mut chain, base, RtcpSessionControl::Start);
    chain.handle_write(rtp(base, 100, 1, 0)).unwrap();
    let sent = run(&mut chain, base + secs(1.0));
    let (sent_at, report) = sent
        .iter()
        .find_map(|sent| {
            sent.get::<SenderReport>()
                .first()
                .map(|sr| (sent.at, (*sr).clone()))
        })
        .expect("a sender report");

    // The peer answers 300 ms later, having held the report for 100 ms.
    chain
        .handle_read(rtcp(
            sent_at + Duration::from_millis(300),
            vec![Box::new(ReceiverReport {
                ssrc: 900,
                reports: vec![ReceptionReport {
                    ssrc: 100,
                    last_sender_report: (report.ntp_time >> 16) as u32,
                    delay: 6554,
                    ..Default::default()
                }],
                ..Default::default()
            })],
        ))
        .unwrap();
    let (_, events) = read(&mut chain);
    let rtt = events
        .iter()
        .find_map(|event| match event {
            RtcpSessionEvent::RoundTripTime { ssrc: 100, rtt } => Some(*rtt),
            _ => None,
        })
        .expect("a round-trip time");
    assert!((rtt.as_secs_f64() - 0.2).abs() < 0.001, "{rtt:?}");
}

/// RFC 3550 6.1 under RTP/AVP: feedback has no early packet; it rides the next regular one.
#[test]
fn under_avp_what_is_written_waits_for_the_regular_report() {
    let mut chain = chain(builder().with_profile(RtcpProfile::Avp));
    let base = Instant::now();
    control(&mut chain, base, RtcpSessionControl::Start);
    chain
        .handle_write(rtcp(
            base + secs(0.1),
            vec![Box::new(
                rtcp::payload_feedbacks::picture_loss_indication::PictureLossIndication {
                    sender_ssrc: 0,
                    media_ssrc: 200,
                },
            )],
        ))
        .unwrap();
    assert!(written(&mut chain).is_empty());

    let sent = run(&mut chain, base + secs(3.0));
    assert_eq!(1, sent.len());
    assert!(sent[0].is_compound());
    assert!(
        sent[0].has::<rtcp::payload_feedbacks::picture_loss_indication::PictureLossIndication>()
    );
}

/// The `(source, item type, text)` of every SDES item after the CNAME.
fn identifiers(sent: &Sent) -> Vec<(u32, SdesType, String)> {
    sent.get::<SourceDescription>()
        .iter()
        .flat_map(|sdes| &sdes.chunks)
        .flat_map(|chunk| {
            chunk
                .items
                .iter()
                .filter(|item| item.sdes_type != SdesType::SdesCname)
                .map(|item| {
                    (
                        chunk.source,
                        item.sdes_type,
                        String::from_utf8(item.text.to_vec()).unwrap(),
                    )
                })
        })
        .collect()
}

/// RFC 9143 section 15: "The RTCP MID SDES item SHOULD be sent in the first few RTCP packets
/// after joining the session and SHOULD be sent regularly thereafter"; RFC 8852 sections 3.1
/// and 3.2: a source stream's RtpStreamId and a redundancy stream's RepairedRtpStreamId are
/// SDES items too. Each compound packet describes each SSRC with what it was given; all `None`
/// takes the items back.
#[test]
fn every_compound_packet_carries_the_mid_and_rids_of_each_stream() {
    let mut chain = chain(builder().with_bandwidth(busy_session()));
    let base = Instant::now();
    chain.bind_local_stream(&video_with_repair(100, 101, 102));
    let identify =
        |ssrc, rid: Option<&str>, repaired: Option<&str>| RtcpSessionControl::StreamIdentifiers {
            ssrc,
            mid: Some("v0".to_owned()),
            rid: rid.map(str::to_owned),
            repaired_rid: repaired.map(str::to_owned),
        };
    control(&mut chain, base, identify(100, Some("hi"), None));
    control(&mut chain, base, identify(101, None, Some("hi")));
    control(&mut chain, base, RtcpSessionControl::Start);
    for ssrc in [100, 101, 102] {
        chain.handle_write(rtp(base, ssrc, 1, 3000)).unwrap();
    }

    let sent = run(&mut chain, base + secs(10.0));
    let compound: Vec<&Sent> = sent.iter().filter(|s| s.is_compound()).collect();
    assert!(compound.len() > 2, "{} compound packets", compound.len());
    for packet in &compound {
        let mut items = identifiers(packet);
        items.sort_by_key(|(ssrc, typ, _)| (*ssrc, u8::from(*typ)));
        assert_eq!(
            items,
            vec![
                (100, SdesType::SdesRtpStreamId, "hi".to_owned()),
                (100, SdesType::SdesMid, "v0".to_owned()),
                (101, SdesType::SdesRepairedRtpStreamId, "hi".to_owned()),
                (101, SdesType::SdesMid, "v0".to_owned()),
            ]
        );
    }

    let later = base + secs(10.0);
    for ssrc in [100, 101] {
        control(
            &mut chain,
            later,
            RtcpSessionControl::StreamIdentifiers {
                ssrc,
                mid: None,
                rid: None,
                repaired_rid: None,
            },
        );
    }
    let sent = run(&mut chain, later + secs(10.0));
    assert!(sent.iter().any(Sent::is_compound));
    assert!(sent.iter().all(|s| identifiers(s).is_empty()));
}

/// RFC 7160 section 4.3: "receivers MUST be prepared to receive" a compound RTCP packet
/// with several SR packets (a sender that switched clock rate reports each of its SSRCs).
/// Each SR is taken: the next report blocks echo both, each with its own LSR.
#[test]
fn a_compound_packet_with_several_sender_reports_is_taken_in_full() {
    let mut chain = chain(builder());
    let base = Instant::now();
    chain.bind_remote_stream(&audio(0x0A));
    chain.bind_remote_stream(&audio(0x0B));
    control(&mut chain, base, RtcpSessionControl::Start);
    for (ssrc, seq) in [(0x0Au32, 1u16), (0x0B, 1)] {
        chain.handle_read(rtp(base, ssrc, seq, 960)).unwrap();
    }
    let sr = |ssrc: u32, ntp_time: u64| -> Box<dyn rtcp::Packet> {
        Box::new(SenderReport {
            ssrc,
            ntp_time,
            rtp_time: 960,
            packet_count: 1,
            octet_count: 100,
            ..Default::default()
        })
    };
    let at = base + secs(0.1);
    let _ = run(&mut chain, at);
    chain
        .handle_read(rtcp(
            at,
            vec![
                sr(0x0A, 0x0001_0002_0003_0004),
                sr(0x0B, 0x0005_0006_0007_0008),
                sdes(0x0A, "remote"),
            ],
        ))
        .unwrap();
    while chain.poll_read().is_some() {}
    let sent = run(&mut chain, at + secs(10.0));
    let lsr = |ssrc: u32| -> Option<u32> {
        sent.iter()
            .flat_map(|s| s.get::<ReceiverReport>())
            .flat_map(|rr| &rr.reports)
            .chain(
                sent.iter()
                    .flat_map(|s| s.get::<SenderReport>())
                    .flat_map(|sr| &sr.reports),
            )
            .filter(|block| block.ssrc == ssrc)
            .map(|block| block.last_sender_report)
            .find(|lsr| *lsr != 0)
    };
    assert_eq!(Some(0x0002_0003), lsr(0x0A));
    assert_eq!(Some(0x0006_0007), lsr(0x0B));
}

/// RFC 7160 section 4.1: "the next compound RTCP packet sent by the RTP sender MUST contain
/// multiple SR packets, the first one containing the mapping for the current clock rate and
/// the subsequent SR packet(s) containing the mapping for the other clock rates seen during the
/// last period". Two local audio streams (one SSRC per clock rate, 48 kHz and 8 kHz) both sent
/// lately; left to their timers the packet leads with one of them. Told that the stream
/// switched to the other, the next compound packet leads with the other's SR and carries the
/// first's right behind it.
#[test]
fn after_a_clock_rate_switch_the_current_rates_sender_report_leads() {
    let sr_order = |switch_to: Option<(u32, u32)>| -> Vec<u32> {
        let mut chain = chain(builder());
        let base = Instant::now();
        let narrow = StreamInfo {
            clock_rate: 8_000,
            mime_type: "audio/PCMU".to_string(),
            payload_type: 0,
            ..audio(200)
        };
        chain.bind_local_stream(&audio(100));
        chain.bind_local_stream(&narrow);
        control(&mut chain, base, RtcpSessionControl::Start);
        for (seq, ssrc) in [(1, 100), (2, 100), (1, 200), (2, 200)] {
            chain.handle_write(rtp(base, ssrc, seq, 960)).unwrap();
        }
        if let Some((current, previous)) = switch_to {
            control(
                &mut chain,
                base,
                RtcpSessionControl::ClockRateSwitch {
                    current,
                    previous: vec![previous],
                },
            );
        }
        let sent = run(&mut chain, base + secs(2.0));
        let first = sent
            .iter()
            .find(|sent| sent.is_compound())
            .expect("a compound packet");
        first
            .get::<SenderReport>()
            .iter()
            .map(|sr| sr.ssrc)
            .collect()
    };
    let natural = sr_order(None);
    assert_eq!(natural.len(), 2, "both streams sent lately: {natural:?}");
    let (leader, other) = (natural[0], natural[1]);
    assert_eq!(
        sr_order(Some((other, leader))),
        vec![other, leader],
        "the current clock rate's SR first, the previous one's behind it"
    );
}

/// RFC 3550 section 6.4.1: the sender's packet and octet counts "SHOULD be reset if the
/// sender changes its SSRC identifier". A stream that moved from SSRC 100 (three packets sent)
/// to SSRC 200 (one packet) reports one packet under 200.
#[test]
fn a_sender_that_changes_its_ssrc_counts_from_zero() {
    let mut chain = chain(builder());
    let base = Instant::now();
    chain.bind_local_stream(&audio(100));
    control(&mut chain, base, RtcpSessionControl::Start);
    for seq in 1..=3 {
        chain.handle_write(rtp(base, 100, seq, 960)).unwrap();
    }
    chain.unbind_local_stream(&audio(100));
    chain.bind_local_stream(&audio(200));
    chain.handle_write(rtp(base, 200, 1, 960)).unwrap();
    let sent = run(&mut chain, base + secs(3.0));
    let counts: Vec<(u32, u32)> = sent
        .iter()
        .flat_map(|sent| sent.get::<SenderReport>())
        .filter(|sr| sr.ssrc == 200)
        .map(|sr| (sr.packet_count, sr.octet_count))
        .collect();
    assert_eq!(counts.first(), Some(&(1, 100)), "{counts:?}");
}

/// RFC 8834 section 8: the use of XR "SHOULD be signalled". The receiver reference time goes
/// out only for a stream that negotiated it (`rtcp-fb rrtr`, as libwebrtc signals RFC 3611
/// 4.4): without, the regular report carries no XR.
#[test]
fn no_reference_time_without_its_signalling() {
    let mut chain = chain(builder());
    let base = Instant::now();
    chain.bind_remote_stream(&video(200));
    control(&mut chain, base, RtcpSessionControl::Start);
    chain.handle_read(rtp(base, 200, 1, 0)).unwrap();
    read(&mut chain);
    let sent = run(&mut chain, base + secs(3.0));
    assert!(!sent.is_empty());
    assert!(sent.iter().all(|sent| !sent.has::<ExtendedReport>()));
}
