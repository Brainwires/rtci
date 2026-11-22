//! RTCP transmission timing through the session interceptor: RFC 3550 6.2 and 6.3 (interval,
//! minimum, initial delay, timer reconsideration, reverse reconsideration, BYE back-off,
//! RTCP bandwidth) and the regular-packet rules of RFC 4585 3.5.3, in virtual time with fixed
//! random numbers.

mod rtcp_session_common;

use rtc_interceptor::{Interceptor, RtcpBandwidth, RtcpProfile, RtcpSessionControl};
use rtcp::goodbye::Goodbye;
use rtcp::receiver_report::ReceiverReport;
use rtcp_session_common::*;
use sansio::Protocol;
use std::time::{Duration, Instant};

/// `e - 3/2`, the compensation of RFC 3550 6.3.1.
const COMPENSATION: f64 = std::f64::consts::E - 1.5;

fn offsets(sent: &[Sent], base: Instant) -> Vec<f64> {
    sent.iter()
        .map(|sent| sent.at.duration_since(base).as_secs_f64())
        .collect()
}

fn near(actual: f64, expected: f64) -> bool {
    (actual - expected).abs() < 0.002
}

fn remote_receiver_report(ssrc: u32) -> Vec<Box<dyn rtcp::Packet>> {
    vec![Box::new(ReceiverReport {
        ssrc,
        ..Default::default()
    })]
}

/// RFC 3550 6.2 under RTP/AVP: a five second minimum, halved for the first packet, and the
/// interval divided by 1.21828 (the random factor is fixed at 1.0 here).
#[test]
fn avp_reports_keep_the_five_second_minimum_and_half_of_it_at_first() {
    let mut chain = chain(
        builder()
            .with_profile(RtcpProfile::Avp)
            .with_bandwidth(RtcpBandwidth {
                session: Some(64_000),
                ..Default::default()
            }),
    );
    let base = Instant::now();
    control(&mut chain, base, RtcpSessionControl::Start);

    let sent = run(&mut chain, base + secs(11.0));
    let at = offsets(&sent, base);
    assert_eq!(3, at.len(), "{at:?}");
    assert!(near(at[0], 2.5 / COMPENSATION), "{at:?}");
    assert!(near(at[1] - at[0], 5.0 / COMPENSATION), "{at:?}");
    assert!(near(at[2] - at[1], 5.0 / COMPENSATION), "{at:?}");
}

/// RFC 3550 6.2: the reduced minimum is 360 divided by the session bandwidth in kbit/s: half
/// a second at 720 kbit/s.
#[test]
fn avp_reports_can_use_the_reduced_minimum() {
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
    control(&mut chain, base, RtcpSessionControl::Start);

    let sent = run(&mut chain, base + secs(1.5));
    let at = offsets(&sent, base);
    assert!(at.len() >= 3, "{at:?}");
    assert!(near(at[0], 0.25 / COMPENSATION), "{at:?}");
    assert!(near(at[1] - at[0], 0.5 / COMPENSATION), "{at:?}");
}

/// RFC 3550 6.2, 6.3.3 and 6.3.6: the interval scales with the number of members heard, and
/// a timer that expires after the membership grew is reconsidered, not fired.
#[test]
fn the_interval_grows_with_the_membership_by_timer_reconsideration() {
    let mut chain = chain(
        builder()
            .with_profile(RtcpProfile::Avp)
            .with_bandwidth(RtcpBandwidth {
                session: Some(8_000),
                ..Default::default()
            }),
    );
    let base = Instant::now();
    control(&mut chain, base, RtcpSessionControl::Start);

    // Alone, the first report would leave after 2.05 s. Ten more members are heard first.
    for member in 0..10u32 {
        chain
            .handle_read(rtcp(
                base + secs(1.0),
                remote_receiver_report(7000 + member),
            ))
            .unwrap();
    }
    read(&mut chain);

    let sent = run(&mut chain, base + secs(40.0));
    let at = offsets(&sent, base);
    assert!(!at.is_empty());
    // 50 octets/s of RTCP, three quarters of it for 11 receivers with packets of about 50
    // octets: around 15 s, over 1.21828.
    assert!(at[0] > 9.0 && at[0] < 16.0, "{at:?}");
}

/// RFC 3550 6.3.4: when members leave, the time to the next report shrinks with the
/// membership (reverse reconsideration).
#[test]
fn the_next_report_comes_sooner_when_members_say_bye() {
    let mut chain = chain(
        builder()
            .with_profile(RtcpProfile::Avp)
            .with_bandwidth(RtcpBandwidth {
                session: Some(8_000),
                ..Default::default()
            }),
    );
    let base = Instant::now();
    control(&mut chain, base, RtcpSessionControl::Start);
    for member in 0..10u32 {
        chain
            .handle_read(rtcp(
                base + secs(1.0),
                remote_receiver_report(7000 + member),
            ))
            .unwrap();
    }
    // The first timer expires at 2.05 s and is put off past 9 s (the test above).
    assert!(run(&mut chain, base + secs(3.0)).is_empty());

    chain
        .handle_read(rtcp(
            base + secs(3.0),
            vec![Box::new(Goodbye {
                sources: (0..10u32).map(|member| 7000 + member).collect(),
                reason: Default::default(),
            })],
        ))
        .unwrap();
    read(&mut chain);

    let sent = run(&mut chain, base + secs(40.0));
    let at = offsets(&sent, base);
    assert!(!at.is_empty());
    assert!(at[0] > 3.0 && at[0] < 6.5, "{at:?}");
}

/// RFC 4585 3.5.3: under RTP/AVPF regular reports are suppressed until `T_rr_interval` has
/// passed since the last one (one second by default here, dithered over [0.5, 1.5]).
#[test]
fn avpf_regular_reports_keep_t_rr_interval() {
    let mut chain = chain(builder());
    let base = Instant::now();
    control(&mut chain, base, RtcpSessionControl::Start);

    let sent = run(&mut chain, base + secs(10.0));
    let at = offsets(&sent, base);
    // The first leaves within the first calculated interval (no minimum between two
    // parties, RFC 4585 3.5.1), the others at least `T_rr_interval` apart.
    assert!(at[0] < 0.5, "{at:?}");
    assert!((8..=11).contains(&at.len()), "{at:?}");
    for pair in at.windows(2) {
        let gap = pair[1] - pair[0];
        assert!((1.0..1.3).contains(&gap), "{at:?}");
    }
    assert!(sent.iter().all(Sent::is_compound));
}

/// RFC 4585 4.2: a negotiated `trr-int` is the minimum interval between regular reports.
#[test]
fn a_negotiated_trr_int_spaces_the_regular_reports() {
    let mut chain = chain(builder());
    let base = Instant::now();
    control(&mut chain, base, RtcpSessionControl::Start);
    control(
        &mut chain,
        base,
        RtcpSessionControl::TrrInt(Duration::from_secs(5)),
    );

    let sent = run(&mut chain, base + secs(21.0));
    let at = offsets(&sent, base);
    assert!((4..=5).contains(&at.len()), "{at:?}");
    for pair in at.windows(2) {
        assert!(pair[1] - pair[0] >= 5.0, "{at:?}");
    }
}

/// A `trr-int` a later negotiation no longer has stops spacing the reports: the interval the
/// session was built with applies again (RFC 4585 4.2).
#[test]
fn a_cleared_trr_int_gives_back_the_configured_interval() {
    let mut chain = chain(builder());
    let base = Instant::now();
    control(&mut chain, base, RtcpSessionControl::Start);
    control(
        &mut chain,
        base,
        RtcpSessionControl::TrrInt(Duration::from_secs(5)),
    );
    let sent = run(&mut chain, base + secs(11.0));
    assert!(
        offsets(&sent, base).len() <= 3,
        "{:?}",
        offsets(&sent, base)
    );

    let later = base + secs(11.0);
    control(&mut chain, later, RtcpSessionControl::TrrIntCleared);
    let sent = run(&mut chain, later + secs(10.0));
    // The builder's one-second interval: about ten reports in ten seconds.
    let at = offsets(&sent, later);
    assert!((8..=11).contains(&at.len()), "{at:?}");
}

/// RFC 4585 3.5.3 with `T_rr_interval` zero (its default when `trr-int` is not signalled):
/// every regular packet is sent, at the interval the RTCP bandwidth gives. RFC 3556: `b=RS`
/// and `b=RR` are that bandwidth. 8000 + 24000 bit/s, a lone receiver with 64-octet packets:
/// 64 / 3000 s, over 1.21828.
#[test]
fn rs_and_rr_set_the_rtcp_bandwidth() {
    let mut chain = chain(builder().with_t_rr_interval(Duration::ZERO).with_bandwidth(
        RtcpBandwidth {
            session: None,
            rs: Some(8_000),
            rr: Some(24_000),
        },
    ));
    let base = Instant::now();
    control(&mut chain, base, RtcpSessionControl::Start);

    let sent = run(&mut chain, base + secs(1.0));
    let at = offsets(&sent, base);
    let expected = 64.0 / 3000.0 / COMPENSATION;
    assert!(at.len() > 40, "{} reports", at.len());
    for pair in at.windows(2) {
        assert!(near(pair[1] - pair[0], expected), "{at:?}");
    }
}

/// RFC 3556: `b=RR:0` turns the receivers' RTCP off.
#[test]
fn rr_zero_silences_a_receiver() {
    let mut chain = chain(builder().with_bandwidth(RtcpBandwidth {
        session: None,
        rs: Some(8_000),
        rr: Some(0),
    }));
    let base = Instant::now();
    control(&mut chain, base, RtcpSessionControl::Start);
    assert!(run(&mut chain, base + secs(120.0)).is_empty());
}

/// The bandwidth can arrive after the session started, when the description is negotiated.
#[test]
fn the_negotiated_bandwidth_can_be_set_while_running() {
    let mut chain = chain(builder().with_t_rr_interval(Duration::ZERO));
    let base = Instant::now();
    control(&mut chain, base, RtcpSessionControl::Start);
    control(
        &mut chain,
        base,
        RtcpSessionControl::Bandwidth(RtcpBandwidth {
            session: None,
            rs: Some(8_000),
            rr: Some(24_000),
        }),
    );
    run(&mut chain, base + secs(1.0));

    let sent = run(&mut chain, base + secs(2.0));
    let at = offsets(&sent, base);
    let expected = 64.0 / 3000.0 / COMPENSATION;
    assert!(near(at[1] - at[0], expected), "{at:?}");
}

/// RFC 3550 6.2: a session that is told nothing starts without waiting for a first packet
/// once started, and without being started, with the first packet it sees.
#[test]
fn a_session_that_was_not_started_joins_with_its_first_packet() {
    let mut chain = chain(builder());
    assert!(chain.poll_timeout().is_none());
    let base = Instant::now();
    chain.bind_remote_stream(&video(200));
    chain.handle_read(rtp(base, 200, 1, 0)).unwrap();
    read(&mut chain);

    let sent = run(&mut chain, base + secs(1.0));
    assert!(!sent.is_empty());
    assert_eq!(vec![200], sent[0].reported());
}

/// RFC 3550 6.3.7: with more than fifty members a BYE is not sent at once; it takes its turn
/// like a report (and is sent, a little later).
#[test]
fn a_bye_in_a_large_session_waits_for_its_turn() {
    let mut chain = chain(builder());
    let base = Instant::now();
    chain.bind_local_stream(&video(100));
    control(&mut chain, base, RtcpSessionControl::Start);
    chain.handle_write(rtp(base, 100, 1, 0)).unwrap();
    for member in 0..60u32 {
        chain
            .handle_read(rtcp(base, remote_receiver_report(7000 + member)))
            .unwrap();
    }
    read(&mut chain);
    run(&mut chain, base + secs(5.0));

    chain.unbind_local_stream(&video(100));
    let now = base + secs(5.0);
    chain.handle_timeout(now).unwrap();
    let at_once = written(&mut chain);
    assert!(at_once.iter().all(|sent| sent.goodbye().is_none()));

    let later = run(&mut chain, now + secs(5.0));
    let goodbye = later
        .iter()
        .find_map(|sent| sent.goodbye().map(|goodbye| (sent.at, goodbye)))
        .expect("the BYE is sent after its back-off");
    assert_eq!(vec![100], goodbye.1.sources);
    assert!(goodbye.0 > now);
}

/// RFC 3550 6.2: RTCP gets five percent of the session bandwidth. At 64 kbit/s that is 400
/// octets a second; a lone receiver shares three quarters of it (300), and with 64-octet
/// packets reports every 64 / 300 s, over 1.21828.
#[test]
fn rtcp_gets_five_percent_of_the_session_bandwidth() {
    let mut chain = chain(builder().with_t_rr_interval(Duration::ZERO).with_bandwidth(
        RtcpBandwidth {
            session: Some(64_000),
            ..Default::default()
        },
    ));
    let base = Instant::now();
    control(&mut chain, base, RtcpSessionControl::Start);

    let sent = run(&mut chain, base + secs(2.0));
    let at = offsets(&sent, base);
    let expected = 64.0 / 300.0 / COMPENSATION;
    assert!(near(at[0], expected), "{at:?}");
    for pair in at.windows(2) {
        assert!(near(pair[1] - pair[0], expected), "{at:?}");
    }

    // Another share: ten percent halves the interval.
    let mut chain = self::chain(
        builder()
            .with_t_rr_interval(Duration::ZERO)
            .with_rtcp_fraction(0.10)
            .with_bandwidth(RtcpBandwidth {
                session: Some(64_000),
                ..Default::default()
            }),
    );
    control(&mut chain, base, RtcpSessionControl::Start);
    let sent = run(&mut chain, base + secs(1.0));
    assert!(near(offsets(&sent, base)[0], expected / 2.0));
}

/// RFC 8108 5.3: the reports of several local SSRCs leave in one compound packet per
/// interval, each SSRC keeping its own timer (5.3.2), not one packet per SSRC.
#[test]
fn several_local_ssrcs_report_together_once_per_interval() {
    let mut chain = chain(builder());
    let base = Instant::now();
    for ssrc in [10, 20, 30] {
        chain.bind_local_stream(&video(ssrc));
    }
    control(&mut chain, base, RtcpSessionControl::Start);

    let mut sent = vec![];
    for step in 0..100u32 {
        let now = base + secs(0.05) * step;
        for ssrc in [10, 20, 30] {
            chain
                .handle_write(rtp(now, ssrc, step as u16, step * 4500))
                .unwrap();
        }
        sent.extend(run(&mut chain, now));
    }

    // Five seconds: about one compound packet a second, each with all three sender reports.
    assert!((4..=7).contains(&sent.len()), "{} packets", sent.len());
    for sent in &sent {
        let mut reporting: Vec<u32> = sent
            .get::<rtcp::sender_report::SenderReport>()
            .iter()
            .map(|sr| sr.ssrc)
            .collect();
        reporting.sort_unstable();
        assert_eq!(vec![10, 20, 30], reporting);
        assert_eq!(3, sent.cnames().len());
    }
    for pair in offsets(&sent, base).windows(2) {
        assert!(pair[1] - pair[0] >= 0.9, "{:?}", offsets(&sent, base));
    }
}
