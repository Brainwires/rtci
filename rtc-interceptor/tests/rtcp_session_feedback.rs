//! Feedback through the RTCP session: compound packets (RFC 4585 3.1), the packet sender
//! SSRC (RFC 4585 6.1, RFC 8108 5.4.1), early RTCP and its allowance (RFC 4585 3.5.2) and
//! reduced-size RTCP (RFC 5506).

mod rtcp_session_common;

use rtc_interceptor::{Interceptor, RtcpBandwidth, RtcpSessionControl};
use rtcp::payload_feedbacks::picture_loss_indication::PictureLossIndication;
use rtcp::payload_feedbacks::receiver_estimated_maximum_bitrate::ReceiverEstimatedMaximumBitrate;
use rtcp::receiver_report::ReceiverReport;
use rtcp::sender_report::SenderReport;
use rtcp::source_description::{
    SdesType, SourceDescription, SourceDescriptionChunk, SourceDescriptionItem,
};
use rtcp::transport_feedbacks::transport_layer_nack::{NackPair, TransportLayerNack};
use rtcp_session_common::*;
use sansio::Protocol;
use std::time::Instant;

fn pli(media_ssrc: u32) -> Vec<Box<dyn rtcp::Packet>> {
    vec![Box::new(PictureLossIndication {
        // What an application or an interceptor that knows no better fills in.
        sender_ssrc: 0,
        media_ssrc,
    })]
}

fn nack(media_ssrc: u32, sequence_number: u16) -> Vec<Box<dyn rtcp::Packet>> {
    vec![Box::new(TransportLayerNack {
        sender_ssrc: 0xDEAD_BEEF,
        media_ssrc,
        nacks: vec![NackPair {
            packet_id: sequence_number,
            lost_packets: 0,
        }],
    })]
}

fn remb(media_ssrc: u32) -> Vec<Box<dyn rtcp::Packet>> {
    vec![Box::new(ReceiverEstimatedMaximumBitrate {
        sender_ssrc: 0,
        bitrate: 1_000_000.0,
        ssrcs: vec![media_ssrc],
    })]
}

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

/// RFC 4585 3.1 (and RFC 3550 6.1): feedback leaves in a compound packet: RR, SDES with the
/// CNAME, then the feedback message, whose packet sender is the endpoint's own SSRC. Between
/// two parties it leaves at once (RFC 4585 3.5.2: no dither).
#[test]
fn feedback_leaves_at_once_in_a_minimal_compound_packet_from_the_endpoints_ssrc() {
    let mut chain = chain(builder());
    let base = Instant::now();
    control(&mut chain, base, RtcpSessionControl::Start);

    let now = base + secs(0.01);
    chain.handle_write(rtcp(now, pli(200))).unwrap();
    let sent = written(&mut chain);
    assert_eq!(1, sent.len());
    assert_eq!(now, sent[0].at);
    assert_eq!(3, sent[0].packets.len());
    let report = sent[0].packets[0]
        .as_any()
        .downcast_ref::<ReceiverReport>()
        .expect("a receiver report first");
    assert_eq!(REPORTER, report.ssrc);
    assert!(report.reports.is_empty(), "the minimal compound packet");
    assert_eq!(
        vec![REPORTER],
        sent[0].cnames().iter().map(|c| c.0).collect::<Vec<_>>()
    );
    assert!(sent[0].packets[1].as_any().is::<SourceDescription>());
    let pli = sent[0].packets[2]
        .as_any()
        .downcast_ref::<PictureLossIndication>()
        .expect("then the feedback");
    assert_eq!(REPORTER, pli.sender_ssrc);
    assert_eq!(200, pli.media_ssrc);
}

/// RFC 4585 3.5.2: after an Early packet no other is allowed until the next regular one is
/// due (put off by one interval). Feedback detected meanwhile is stored and goes with it,
/// merged into as few messages as possible.
#[test]
fn a_second_feedback_waits_for_the_regular_packet_and_is_merged() {
    let mut chain = chain(builder().with_bandwidth(RtcpBandwidth {
        session: Some(64_000),
        ..Default::default()
    }));
    let base = Instant::now();
    chain.bind_remote_stream(&video(200));
    control(&mut chain, base, RtcpSessionControl::Start);

    chain
        .handle_write(rtcp(base + secs(0.01), nack(200, 10)))
        .unwrap();
    assert_eq!(1, written(&mut chain).len());

    // No early packet is allowed now.
    chain
        .handle_write(rtcp(base + secs(0.02), nack(200, 12)))
        .unwrap();
    chain
        .handle_write(rtcp(base + secs(0.03), nack(200, 11)))
        .unwrap();
    chain
        .handle_write(rtcp(base + secs(0.03), pli(200)))
        .unwrap();
    chain
        .handle_write(rtcp(base + secs(0.04), pli(200)))
        .unwrap();
    assert!(written(&mut chain).is_empty());

    let sent = run(&mut chain, base + secs(0.9));
    assert_eq!(1, sent.len(), "one packet carries what was stored");
    assert!(sent[0].at > base + secs(0.04));
    assert!(sent[0].is_compound());
    let nacks = sent[0].get::<TransportLayerNack>();
    assert_eq!(1, nacks.len(), "the two NACKs are one message");
    let mut requested: Vec<u16> = nacks[0]
        .nacks
        .iter()
        .flat_map(|p| p.packet_list())
        .collect();
    requested.sort_unstable();
    assert_eq!(vec![11, 12], requested);
    assert_eq!(REPORTER, nacks[0].sender_ssrc);
    assert_eq!(1, sent[0].get::<PictureLossIndication>().len());

    // The regular packet went: early feedback is allowed again.
    let now = base + secs(0.91);
    chain.handle_write(rtcp(now, pli(200))).unwrap();
    let sent = written(&mut chain);
    assert_eq!(1, sent.len());
    assert_eq!(now, sent[0].at);

    // And not again right after. The next regular packet is not due yet (`T_rr_interval`),
    // so what is stored leaves with a packet of its own when the timer expires (RFC 4585
    // 3.5.3, case 2b): the minimal compound packet, no report blocks.
    chain
        .handle_write(rtcp(now + secs(0.001), nack(200, 30)))
        .unwrap();
    assert!(written(&mut chain).is_empty());
    let sent = run(&mut chain, now + secs(0.6));
    assert_eq!(1, sent.len());
    assert!(sent[0].is_compound());
    assert_eq!(1, sent[0].get::<TransportLayerNack>().len());
    assert!(sent[0].reported().is_empty());
}

/// RFC 5506 4.2.2: a large feedback packet goes out compound even when reduced-size RTCP was
/// negotiated.
#[test]
fn a_large_feedback_packet_is_sent_compound() {
    let mut chain = chain(builder().with_reduced_size(true));
    let base = Instant::now();
    chain.bind_remote_stream(&video(200));
    control(&mut chain, base, RtcpSessionControl::Start);
    chain
        .handle_write(rtcp(base + secs(0.01), pli(200)))
        .unwrap();
    written(&mut chain);
    run(&mut chain, base + secs(2.0));

    // 150 separate losses: 150 PID/BLP pairs, 600 octets of FCI.
    let large: Vec<Box<dyn rtcp::Packet>> = vec![Box::new(TransportLayerNack {
        sender_ssrc: 0,
        media_ssrc: 200,
        nacks: (0..150u16)
            .map(|n| NackPair {
                packet_id: n * 20,
                lost_packets: 0,
            })
            .collect(),
    })];
    chain.handle_write(rtcp(base + secs(2.0), large)).unwrap();
    let sent = written(&mut chain);
    assert_eq!(1, sent.len());
    assert!(sent[0].is_compound());
}

/// RFC 4585 3.5.2 step 3: when the next regular packet is due within the dither of an Early
/// one, no Early packet is scheduled; the feedback goes with the regular packet.
#[test]
fn feedback_close_to_the_regular_packet_waits_for_it() {
    let mut chain = chain(builder());
    let base = Instant::now();
    control(&mut chain, base, RtcpSessionControl::Start);
    // Two CNAMEs: a multiparty session, so an Early packet would be dithered by up to half
    // the regular interval (about 88 ms here; the first regular packet is due at 175 ms).
    chain
        .handle_read(rtcp(base, vec![sdes(200, "alice"), sdes(201, "bob")]))
        .unwrap();
    read(&mut chain);

    chain
        .handle_write(rtcp(base + secs(0.12), pli(200)))
        .unwrap();
    assert!(written(&mut chain).is_empty());
    let sent = run(&mut chain, base + secs(3.0));
    let carrier = sent
        .iter()
        .find(|sent| sent.has::<PictureLossIndication>())
        .expect("the PLI is sent");
    // Not as an Early packet (that would have left by 208 ms): with the first regular one.
    assert!(carrier.at > base + secs(0.25), "{:?}", carrier.at - base);
    assert_eq!(carrier.at, sent[0].at);
}

/// RFC 8108 5.4.1: feedback about a media type comes from an SSRC of that media type when
/// the endpoint sends one; RFC 3550 6.4: a sending SSRC leads with its sender report.
#[test]
fn feedback_about_video_comes_from_the_video_ssrc() {
    let mut chain = chain(builder());
    let base = Instant::now();
    chain.bind_local_stream(&audio(10));
    chain.bind_local_stream(&video(20));
    chain.bind_remote_stream(&video(200));
    chain.bind_remote_stream(&audio(300));
    control(&mut chain, base, RtcpSessionControl::Start);
    chain.handle_write(rtp(base, 20, 1, 0)).unwrap();

    chain
        .handle_write(rtcp(base + secs(0.01), pli(200)))
        .unwrap();
    let sent = written(&mut chain);
    assert_eq!(20, sent[0].get::<PictureLossIndication>()[0].sender_ssrc);
    let report = sent[0].packets[0]
        .as_any()
        .downcast_ref::<SenderReport>()
        .expect("the video SSRC is sending: a sender report");
    assert_eq!(20, report.ssrc);
    assert!(report.reports.is_empty());

    // Feedback about audio, and about a stream the session does not know, from the first
    // media SSRC.
    let mut chain = self::chain(builder());
    chain.bind_local_stream(&audio(10));
    chain.bind_local_stream(&video(20));
    chain.bind_remote_stream(&audio(300));
    control(&mut chain, base, RtcpSessionControl::Start);
    chain
        .handle_write(rtcp(base + secs(0.01), nack(300, 1)))
        .unwrap();
    let sent = written(&mut chain);
    assert_eq!(10, sent[0].get::<TransportLayerNack>()[0].sender_ssrc);
}

/// RFC 5506: reduced-size RTCP only when negotiated, never before a compound packet was
/// sent, and not for feedback whose delivery cannot be seen.
#[test]
fn reduced_size_feedback_needs_negotiation_and_a_first_compound_packet() {
    let mut chain = chain(builder().with_reduced_size(true));
    let base = Instant::now();
    chain.bind_remote_stream(&video(200));
    control(&mut chain, base, RtcpSessionControl::Start);

    // The first RTCP packet of the session: compound.
    chain
        .handle_write(rtcp(base + secs(0.01), pli(200)))
        .unwrap();
    let sent = written(&mut chain);
    assert!(sent[0].is_compound());

    // Later, with early feedback allowed again: the PLI alone.
    run(&mut chain, base + secs(2.0));
    chain
        .handle_write(rtcp(base + secs(2.0), pli(200)))
        .unwrap();
    let sent = written(&mut chain);
    assert_eq!(1, sent.len());
    assert_eq!(1, sent[0].packets.len());
    assert_eq!(
        REPORTER,
        sent[0].get::<PictureLossIndication>()[0].sender_ssrc
    );

    // A bitrate estimate gets no visible answer: it travels compound (RFC 5506 4.2.1).
    run(&mut chain, base + secs(4.0));
    chain
        .handle_write(rtcp(base + secs(4.0), remb(200)))
        .unwrap();
    let sent = written(&mut chain);
    assert_eq!(1, sent.len());
    assert!(sent[0].is_compound());
    assert_eq!(
        REPORTER,
        sent[0].get::<ReceiverEstimatedMaximumBitrate>()[0].sender_ssrc
    );
}

#[test]
fn without_negotiation_feedback_is_always_compound() {
    let mut chain = chain(builder());
    let base = Instant::now();
    control(&mut chain, base, RtcpSessionControl::Start);
    for step in 1..=5u32 {
        let now = base + secs(2.0) * step;
        run(&mut chain, now);
        chain.handle_write(rtcp(now, pli(200))).unwrap();
        let sent = written(&mut chain);
        assert_eq!(1, sent.len());
        assert!(sent[0].is_compound());
    }

    // Negotiated while running.
    control(
        &mut chain,
        base + secs(11.0),
        RtcpSessionControl::ReducedSize(true),
    );
    run(&mut chain, base + secs(12.0));
    chain
        .handle_write(rtcp(base + secs(12.0), pli(200)))
        .unwrap();
    assert_eq!(1, written(&mut chain)[0].packets.len());
}

/// RFC 5506 4.2.1: when reduced-size NACKs consistently get no answer, the session goes back
/// to compound packets; an answer (a requested packet arriving) shows they get through.
#[test]
fn reduced_size_is_given_up_when_nacks_get_no_answer() {
    let mut chain = chain(builder().with_reduced_size(true));
    let base = Instant::now();
    chain.bind_remote_stream(&video(200));
    control(&mut chain, base, RtcpSessionControl::Start);
    chain
        .handle_write(rtcp(base + secs(0.01), pli(200)))
        .unwrap();
    written(&mut chain);

    let mut shapes = vec![];
    for step in 1..=12u32 {
        let now = base + secs(2.0) * step;
        run(&mut chain, now);
        chain
            .handle_write(rtcp(now, nack(200, step as u16)))
            .unwrap();
        let sent = written(&mut chain);
        assert_eq!(1, sent.len());
        shapes.push(sent[0].is_compound());
    }
    // Nine reduced-size NACKs, eight of them sent while the one before was unanswered.
    assert_eq!(
        vec![
            false, false, false, false, false, false, false, false, false, true, true, true
        ],
        shapes
    );

    // With answers arriving, it stays reduced-size.
    let mut chain = self::chain(builder().with_reduced_size(true));
    chain.bind_remote_stream(&video(200));
    control(&mut chain, base, RtcpSessionControl::Start);
    chain
        .handle_write(rtcp(base + secs(0.01), pli(200)))
        .unwrap();
    written(&mut chain);
    for step in 1..=12u32 {
        let now = base + secs(2.0) * step;
        run(&mut chain, now);
        chain
            .handle_write(rtcp(now, nack(200, step as u16)))
            .unwrap();
        let sent = written(&mut chain);
        assert!(!sent[0].is_compound(), "step {step}");
        // The retransmission.
        chain
            .handle_read(rtp(now + secs(0.05), 200, step as u16, 0))
            .unwrap();
        read(&mut chain);
    }
}

/// RFC 8108 5.4.2 and RFC 4585 3.5.2: with remote sources under more than one CNAME the
/// session is multiparty, and an Early packet is dithered instead of leaving at once.
#[test]
fn early_feedback_is_dithered_in_a_multiparty_session() {
    let mut chain = chain(builder());
    let base = Instant::now();
    control(&mut chain, base, RtcpSessionControl::Start);
    chain
        .handle_read(rtcp(base, vec![sdes(200, "alice"), sdes(201, "bob")]))
        .unwrap();
    read(&mut chain);

    let now = base + secs(0.01);
    chain.handle_write(rtcp(now, pli(200))).unwrap();
    assert!(written(&mut chain).is_empty(), "not at once");
    // Feedback detected while that packet is scheduled joins it (step 2a).
    chain
        .handle_write(rtcp(now + secs(0.005), nack(201, 4)))
        .unwrap();
    assert!(written(&mut chain).is_empty());
    let sent = run(&mut chain, base + secs(2.0));
    let early = sent
        .iter()
        .find(|sent| sent.has::<PictureLossIndication>())
        .expect("the PLI is sent");
    assert!(early.at > now);
    assert!(early.at < now + secs(0.1), "{:?}", early.at - now);
    assert!(early.has::<TransportLayerNack>(), "one packet carries both");

    // Said to be point to point (RFC 8108 5.4.2: "unless signaling indicates"), it is not.
    let mut chain = self::chain(builder().with_point_to_point(true));
    control(&mut chain, base, RtcpSessionControl::Start);
    chain
        .handle_read(rtcp(base, vec![sdes(200, "alice"), sdes(201, "bob")]))
        .unwrap();
    read(&mut chain);
    chain.handle_write(rtcp(now, pli(200))).unwrap();
    assert_eq!(1, written(&mut chain).len());
}

/// Reports written by anything but the session are not sent beside its own: one voice.
#[test]
fn reports_written_from_above_are_replaced_by_the_sessions_own() {
    let mut chain = chain(builder());
    let base = Instant::now();
    control(&mut chain, base, RtcpSessionControl::Start);
    chain
        .handle_write(rtcp(
            base + secs(0.01),
            vec![
                Box::new(ReceiverReport {
                    ssrc: 0x7777,
                    ..Default::default()
                }),
                sdes(0x7777, "someone-else"),
            ],
        ))
        .unwrap();

    let sent = run(&mut chain, base + secs(3.0));
    assert!(!sent.is_empty());
    for sent in &sent {
        assert_eq!(Some(REPORTER), sent.leader());
        assert!(sent.cnames().iter().all(|c| c.0 == REPORTER));
    }
}

/// RTP passes the session untouched in both directions, and inbound RTCP goes on to the
/// interceptors behind it.
#[test]
fn media_and_inbound_rtcp_pass_through() {
    let mut chain = rtc_interceptor::Registry::new()
        .with(rtc_interceptor::Slot::RtcpSession, builder().build())
        .with(
            rtc_interceptor::Slot::KeyFrameRequests,
            rtc_interceptor::KeyFrameRequestInterceptor::new(),
        )
        .build();
    let base = Instant::now();
    chain.bind_local_stream(&video(100));
    chain.handle_write(rtp(base, 100, 5, 0)).unwrap();
    let out = chain.poll_write().expect("the packet");
    assert!(
        matches!(out.message.packet, rtc_interceptor::Packet::Rtp(p) if p.header.sequence_number == 5)
    );

    chain.handle_read(rtcp(base, pli(100))).unwrap();
    let (packets, _) = read(&mut chain);
    assert_eq!(
        1,
        packets.len(),
        "the key-frame request reaches the application"
    );
}

fn sender_report_request(media_ssrc: u32) -> Vec<Box<dyn rtcp::Packet>> {
    vec![Box::new(
        rtcp::transport_feedbacks::rapid_resynchronization_request::RapidResynchronizationRequest {
            sender_ssrc: 200,
            media_ssrc,
        },
    )]
}

/// RFC 6051 section 3.2: "a media source that understands the RTCP-SR-REQ packet SHOULD
/// generate an RTCP SR packet as soon as possible while complying with the RTCP early feedback
/// rules". Between two parties (no dither) the SR of the SSRC the request names leaves at
/// once, in an Early compound packet, long before the first regular one; a request for an
/// SSRC this side does not send gets nothing early.
#[test]
fn an_rtcp_sr_req_is_answered_with_a_sender_report_at_once() {
    let mut chain = chain(builder().with_bandwidth(RtcpBandwidth {
        session: Some(64_000),
        ..Default::default()
    }));
    let base = Instant::now();
    chain.bind_local_stream(&video(100));
    chain.bind_remote_stream(&video(200));
    control(&mut chain, base, RtcpSessionControl::Start);
    chain.handle_write(rtp(base, 100, 1, 3000)).unwrap();
    assert!(
        written(&mut chain)
            .iter()
            .all(|sent| !sent.has::<SenderReport>())
    );

    let other = base + secs(0.02);
    chain
        .handle_read(rtcp(other, sender_report_request(4242)))
        .unwrap();
    read(&mut chain);
    assert!(written(&mut chain).is_empty(), "not an SSRC of ours");

    let now = base + secs(0.05);
    chain
        .handle_read(rtcp(now, sender_report_request(100)))
        .unwrap();
    read(&mut chain);
    let sent = written(&mut chain);
    assert_eq!(1, sent.len(), "an Early packet");
    assert_eq!(now, sent[0].at);
    let reports = sent[0].get::<SenderReport>();
    assert_eq!(1, reports.len());
    assert_eq!(100, reports[0].ssrc);
}

/// RFC 5104 sections 4.3.2.3 and 4.3.3.3: a TSTR "is not time critical and SHOULD be sent
/// using regular RTCP timing", and so does the TSTN that acknowledges it. Written where a PLI
/// would leave at once in an Early packet, each waits for the next regular compound packet.
#[test]
fn a_tstr_and_a_tstn_wait_for_the_regular_packet() {
    use rtcp::payload_feedbacks::temporal_spatial_tradeoff::{
        TemporalSpatialTradeoffNotification, TemporalSpatialTradeoffRequest, TstEntry,
    };
    for request in [true, false] {
        let mut chain = chain(builder());
        let base = Instant::now();
        chain.bind_remote_stream(&video(200));
        control(&mut chain, base, RtcpSessionControl::Start);
        let entries = vec![TstEntry {
            ssrc: 200,
            sequence_number: 0,
            index: 7,
        }];
        let packet: Box<dyn rtcp::Packet> = if request {
            Box::new(TemporalSpatialTradeoffRequest {
                sender_ssrc: 0,
                entries,
            })
        } else {
            Box::new(TemporalSpatialTradeoffNotification {
                sender_ssrc: 0,
                entries,
            })
        };
        let now = base + secs(0.01);
        chain.handle_write(rtcp(now, vec![packet])).unwrap();
        assert!(
            written(&mut chain).is_empty(),
            "no Early packet (TSTR: {request})"
        );

        let sent = run(&mut chain, base + secs(10.0));
        let first = sent.first().expect("a regular packet");
        assert!(first.is_compound());
        let carried = if request {
            first.has::<TemporalSpatialTradeoffRequest>()
        } else {
            first.has::<TemporalSpatialTradeoffNotification>()
        };
        assert!(carried, "the regular packet carries it (TSTR: {request})");
    }
}

fn twcc(media_ssrc: u32, count: u8) -> Vec<Box<dyn rtcp::Packet>> {
    use rtcp::transport_feedbacks::transport_layer_cc::TransportLayerCc;
    vec![Box::new(TransportLayerCc {
        sender_ssrc: 0,
        media_ssrc,
        fb_pkt_count: count,
        ..Default::default()
    })]
}

/// RFC 4585 section 3.5.2, as written, for congestion control feedback too
/// (`with_immediate_congestion_feedback(false)`): after an Early packet a second transport-wide
/// feedback message is held for the next regular packet ("allow_early == FALSE"), not sent
/// at once. With the default (`true`) each leaves as it is built.
#[test]
fn with_rfc_4585_timing_a_second_congestion_feedback_waits_for_the_regular_packet() {
    use rtcp::transport_feedbacks::transport_layer_cc::TransportLayerCc;
    for immediate in [false, true] {
        let mut chain = chain(
            builder()
                .with_bandwidth(RtcpBandwidth {
                    session: Some(64_000),
                    ..Default::default()
                })
                .with_immediate_congestion_feedback(immediate),
        );
        let base = Instant::now();
        chain.bind_remote_stream(&video(200));
        control(&mut chain, base, RtcpSessionControl::Start);

        chain
            .handle_write(rtcp(base + secs(0.01), twcc(200, 1)))
            .unwrap();
        assert_eq!(1, written(&mut chain).len(), "immediate {immediate}");
        chain
            .handle_write(rtcp(base + secs(0.02), twcc(200, 2)))
            .unwrap();
        let second = written(&mut chain);
        if immediate {
            assert_eq!(1, second.len(), "leaves as it is built");
            assert_eq!(1, second[0].get::<TransportLayerCc>().len());
        } else {
            assert!(second.is_empty(), "no second Early packet");
            let sent = run(&mut chain, base + secs(0.9));
            assert!(!sent.is_empty());
            assert!(sent[0].at > base + secs(0.02));
            assert!(sent[0].is_compound(), "with the regular packet");
            assert_eq!(1, sent[0].get::<TransportLayerCc>().len());
        }
    }
}
