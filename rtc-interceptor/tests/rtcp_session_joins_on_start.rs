//! `RtcpSessionBuilder::with_joins_on_start`: a session that joins the RTP session only when
//! told `RtcpSessionControl::Start` (RFC 3550 section 6: RTCP is the control protocol of an RTP
//! session; RFC 8834 section 4.1: there is one where an RTP m= section is negotiated). Before
//! `Start` it sends nothing, whatever it is given; `Leave` says BYE once (RFC 3550 section 6.6);
//! a `Start` after `Leave` joins again.

mod rtcp_session_common;

use rtc_interceptor::{Interceptor, RtcpBandwidth, RtcpSessionControl};
use rtcp::payload_feedbacks::picture_loss_indication::PictureLossIndication;
use rtcp::receiver_report::ReceiverReport;
use rtcp_session_common::*;
use sansio::Protocol;
use std::time::Instant;

fn remote_report(now: Instant) -> rtc_interceptor::TaggedPacket {
    rtcp(
        now,
        vec![Box::new(ReceiverReport {
            ssrc: 0x0bad_cafe,
            ..Default::default()
        })],
    )
}

fn pli(now: Instant) -> rtc_interceptor::TaggedPacket {
    rtcp(
        now,
        vec![Box::new(PictureLossIndication {
            sender_ssrc: 0,
            media_ssrc: 200,
        })],
    )
}

/// Until `Start`, a session that joins on it sends nothing: not for the controls a negotiation
/// hands it, not for a remote stream, a remote report or feedback written to it, and it has no
/// timer. `Start` joins it, and it reports.
#[test]
fn a_session_that_joins_on_start_sends_nothing_before_it() {
    let mut chain = chain(builder().with_joins_on_start(true));
    let base = Instant::now();
    control(
        &mut chain,
        base,
        RtcpSessionControl::Cname("cname".to_owned()),
    );
    control(&mut chain, base, RtcpSessionControl::SrtcpOverhead(20));
    control(
        &mut chain,
        base,
        RtcpSessionControl::Bandwidth(RtcpBandwidth::default()),
    );
    control(&mut chain, base, RtcpSessionControl::ReducedSize(false));
    control(&mut chain, base, RtcpSessionControl::TrrIntCleared);
    chain.bind_remote_stream(&video(200));
    chain.handle_read(remote_report(base)).unwrap();
    while chain.poll_read().is_some() {}
    chain.handle_write(pli(base)).unwrap();
    assert_eq!(None, chain.poll_timeout(), "no timer before Start");
    assert!(run(&mut chain, base + secs(60.0)).is_empty());

    let start = base + secs(60.0);
    control(&mut chain, start, RtcpSessionControl::Start);
    let sent = run(&mut chain, start + secs(10.0));
    assert!(sent.len() >= 2, "{} packets after Start", sent.len());
    assert!(sent.iter().all(|s| s.is_compound()));
    assert_eq!(Some(REPORTER), sent[0].leader());
    assert_eq!(vec![(REPORTER, "cname".to_owned())], sent[0].cnames());
    // The PLI written before the session joined was dropped, not held for it.
    assert!(sent.iter().all(|s| !s.has::<PictureLossIndication>()));
}

/// `Leave` says BYE once, from every SSRC that spoke, and nothing follows it, feedback written
/// after it included. A `Start` after it joins the session again, reporting from a new SSRC.
#[test]
fn leave_says_bye_once_and_start_joins_again() {
    let mut chain = chain(builder().with_joins_on_start(true));
    let base = Instant::now();
    chain.bind_remote_stream(&video(200));
    control(&mut chain, base, RtcpSessionControl::Start);
    assert!(!run(&mut chain, base + secs(5.0)).is_empty());

    let leave = base + secs(5.0);
    control(&mut chain, leave, RtcpSessionControl::Leave);
    let sent = written(&mut chain);
    assert_eq!(1, sent.len());
    assert_eq!(vec![REPORTER], sent[0].goodbye().expect("a BYE").sources);
    // A second Leave, feedback and a remote report after the BYE: nothing.
    control(&mut chain, leave, RtcpSessionControl::Leave);
    chain.handle_write(pli(leave)).unwrap();
    chain.handle_read(remote_report(leave)).unwrap();
    while chain.poll_read().is_some() {}
    assert!(run(&mut chain, leave + secs(60.0)).is_empty());

    let again = leave + secs(60.0);
    control(&mut chain, again, RtcpSessionControl::Start);
    let sent = run(&mut chain, again + secs(10.0));
    assert!(
        sent.len() >= 2,
        "{} packets after the second Start",
        sent.len()
    );
    let leader = sent[0].leader().expect("a report");
    assert_ne!(REPORTER, leader, "a new reporting SSRC");
    assert!(sent.iter().all(|s| s.goodbye().is_none()));
    assert!(sent.iter().all(|s| s.leader() == Some(leader)));
}

/// A session that joins on `Start` and is told `Leave` before it has nothing to leave: no BYE.
#[test]
fn leave_before_start_sends_nothing() {
    let mut chain = chain(builder().with_joins_on_start(true));
    let base = Instant::now();
    chain.bind_remote_stream(&video(200));
    control(&mut chain, base, RtcpSessionControl::Leave);
    assert!(run(&mut chain, base + secs(30.0)).is_empty());
}

/// Without the setting the session joins at the first control it is given, as it always did.
#[test]
fn by_default_the_session_joins_at_the_first_control() {
    let mut chain = chain(builder());
    let base = Instant::now();
    control(&mut chain, base, RtcpSessionControl::TrrIntCleared);
    assert!(!run(&mut chain, base + secs(5.0)).is_empty());
}
