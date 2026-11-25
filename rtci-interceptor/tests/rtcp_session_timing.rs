//! RTCP transmission timing through the session interceptor: RFC 3550 6.2 and 6.3 (interval,
//! minimum, initial delay, timer reconsideration, reverse reconsideration, BYE back-off,
//! RTCP bandwidth) and the regular-packet rules of RFC 4585 3.5.3, in virtual time with fixed
//! random numbers.

mod rtcp_session_common;

use rtci_interceptor::{Interceptor, RtcpBandwidth, RtcpProfile, RtcpSessionControl};
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

/// RFC 8108 5.2: when an endpoint's SSRCs cannot all report in one packet, "the initial
/// ones ... SHOULD be those most useful to the peers": the senders. Four SSRCs that only
/// receive join first, four that send join a second later; the first compound packet, with
/// room for four reports, carries the receiving SSRC whose timer expired and three sender
/// reports, though the other receiving SSRCs' timers expire sooner.
#[test]
fn senders_report_first_when_not_every_ssrc_fits() {
    let mut chain = chain(builder().with_profile(RtcpProfile::Avp).with_mtu(202));
    let base = Instant::now();
    for ssrc in [10, 20, 30, 40] {
        chain.bind_local_stream(&video(ssrc));
    }
    control(&mut chain, base, RtcpSessionControl::Start);
    let later = base + secs(1.0);
    for ssrc in [50, 60, 70, 80] {
        chain.bind_local_stream(&video(ssrc));
    }
    for ssrc in [50, 60, 70, 80] {
        chain.handle_write(rtp(later, ssrc, 1, 3000)).unwrap();
    }
    let sent = run(&mut chain, base + secs(3.0));
    let first = sent.first().expect("a compound packet");
    assert_eq!(Some(10), first.leader());
    let mut senders: Vec<u32> = first
        .get::<rtcp::sender_report::SenderReport>()
        .iter()
        .map(|sr| sr.ssrc)
        .collect();
    senders.sort_unstable();
    assert_eq!(vec![50, 60, 70], senders, "{:?}", first.packets);
}

/// Regular (no feedback) packets among `sent` after `from`.
fn regular_after(sent: &[Sent], from: Instant) -> usize {
    sent.iter()
        .filter(|sent| sent.at >= from)
        .filter(|sent| {
            !sent.has::<rtcp::transport_feedbacks::transport_layer_cc::TransportLayerCc>()
        })
        .count()
}

/// Twenty seconds of a receive-only session at a 16 kbit/s session bandwidth (100 octets of
/// RTCP a second), writing a 100-octet congestion control feedback packet every 250 ms (400
/// octets a second, more than the whole RTCP bandwidth). Returns the regular packets sent
/// after the first two seconds.
fn regular_reports_beside_congestion_feedback(in_budget: bool) -> usize {
    use rtcp::transport_feedbacks::transport_layer_cc::{
        PacketStatusChunk, RunLengthChunk, StatusChunkTypeTcc, SymbolTypeTcc, TransportLayerCc,
    };
    let mut chain = chain(
        builder()
            .with_t_rr_interval(Duration::ZERO)
            .with_congestion_feedback_in_budget(in_budget)
            .with_bandwidth(RtcpBandwidth {
                session: Some(16_000),
                ..Default::default()
            }),
    );
    let base = Instant::now();
    control(&mut chain, base, RtcpSessionControl::Start);
    let mut sent = vec![];
    for step in 0..80u32 {
        let now = base + secs(0.25) * step;
        sent.extend(run(&mut chain, now));
        let feedback = TransportLayerCc {
            sender_ssrc: 0,
            media_ssrc: 0x1234,
            base_sequence_number: step as u16 * 10,
            packet_status_count: 10,
            reference_time: step,
            fb_pkt_count: step as u8,
            packet_chunks: vec![
                PacketStatusChunk::RunLengthChunk(RunLengthChunk {
                    type_tcc: StatusChunkTypeTcc::RunLengthChunk,
                    packet_status_symbol: SymbolTypeTcc::PacketReceivedSmallDelta,
                    run_length: 10,
                });
                20
            ],
            recv_deltas: vec![],
        };
        chain
            .handle_write(rtcp(now, vec![Box::new(feedback)]))
            .unwrap();
        sent.extend(written(&mut chain));
    }
    sent.extend(run(&mut chain, base + secs(20.0)));
    regular_after(&sent, base + secs(2.0))
}

/// `RtcpSessionBuilder::with_congestion_feedback_in_budget` (the `Performance` behaviour
/// profile): congestion control feedback that leaves at once counts against the RTCP
/// bandwidth, and the regular reports space out (as a `T_rr_interval`, RFC 4585 3.5.3) to
/// what it leaves, here nothing: one every five seconds, the most it stretches to. Without
/// it (the default) the regular reports keep RFC 3550's interval for the whole bandwidth.
#[test]
fn congestion_feedback_in_the_budget_spaces_the_regular_reports() {
    let outside = regular_reports_beside_congestion_feedback(false);
    let inside = regular_reports_beside_congestion_feedback(true);
    assert!(outside >= 15, "default: {outside} regular reports in 18 s");
    assert!(
        (3..=5).contains(&inside),
        "in the budget: {inside} regular reports in 18 s (default {outside})"
    );
}

/// The regular packets of a sender of about 27 kbit/s (thirty 112-octet packets a second), no
/// `b=` line, over seconds 4 to 24.
fn regular_reports_at_low_media(minimum: Option<u64>) -> usize {
    let builder = builder().with_t_rr_interval(Duration::ZERO);
    let builder = match minimum {
        Some(minimum) => builder.with_minimum_session_bandwidth(minimum),
        None => builder,
    };
    let mut chain = chain(builder);
    let base = Instant::now();
    chain.bind_local_stream(&video(10));
    control(&mut chain, base, RtcpSessionControl::Start);
    let mut sent = vec![];
    for step in 0..720u32 {
        let now = base + secs(1.0 / 30.0) * step;
        chain
            .handle_write(rtp(now, 10, step as u16, step * 3000))
            .unwrap();
        sent.extend(run(&mut chain, now));
    }
    regular_after(&sent, base + secs(4.0))
}

/// RFC 3550 6.2 with the media measured: by default the session bandwidth is never taken
/// below 64 kbit/s, so a 27 kbit/s sender reports as a 64 kbit/s one would; with
/// `with_minimum_session_bandwidth(16_000)` (the `Performance` profile) the RTCP bandwidth
/// follows the media, and the sender reports about 27/64 as often.
#[test]
fn the_minimum_session_bandwidth_lets_rtcp_follow_low_media() {
    let floor = regular_reports_at_low_media(None) as f64;
    let follows = regular_reports_at_low_media(Some(16_000)) as f64;
    assert!(floor >= 40.0, "{floor}");
    let ratio = follows / floor;
    assert!(
        (0.3..=0.6).contains(&ratio),
        "{follows} / {floor} = {ratio:.2}"
    );
}

/// What a sender of about 270 kbit/s (three hundred 112-octet packets a second), no `b=`
/// line, does over seconds 4 to 20: its regular packets, and the reporting interval the
/// session calculates for a member that sends, as it rides on the last RTCP handed
/// application-ward.
fn reports_of_a_sender_told_its_send_rate(follows: bool, told: Option<u64>) -> (usize, Duration) {
    let mut chain = chain(
        builder()
            .with_t_rr_interval(Duration::ZERO)
            .with_share_following_send_rate(follows),
    );
    let base = Instant::now();
    chain.bind_local_stream(&video(10));
    control(&mut chain, base, RtcpSessionControl::Start);
    if let Some(bits_per_second) = told {
        control(
            &mut chain,
            base,
            RtcpSessionControl::SendRate(bits_per_second),
        );
    }
    let mut sent = vec![];
    let mut calculated = Duration::ZERO;
    for step in 0..6000u32 {
        let now = base + secs(1.0 / 300.0) * step;
        chain
            .handle_write(rtp(now, 10, step as u16, step * 300))
            .unwrap();
        sent.extend(run(&mut chain, now));
        if step % 300 == 299 {
            chain
                .handle_read(rtcp(now, remote_receiver_report(77)))
                .unwrap();
            let (packets, _) = read(&mut chain);
            for packet in packets {
                if let Some(interval) = packet
                    .message
                    .custom::<rtci_interceptor::RtcpReportingInterval>()
                {
                    calculated = interval.sender;
                }
            }
        }
    }
    (regular_after(&sent, base + secs(4.0)), calculated)
}

/// `with_share_following_send_rate` (tuning, no specification asks for it; the `Performance`
/// profile): an endpoint whose congestion controller allows it 100 kbit/s while the session
/// measures about 270 kbit/s schedules its own regular reports with 5% of 100 kbit/s for each
/// of its SSRCs' places among the members, here with one remote member twice that: fewer
/// reports. Without the option the rate it is told changes nothing, and with the option but
/// no rate told nothing changes either.
#[test]
fn the_rtcp_share_follows_the_send_rate_the_session_is_told() {
    let (plain, _) = reports_of_a_sender_told_its_send_rate(false, None);
    let (ignored, _) = reports_of_a_sender_told_its_send_rate(false, Some(100_000));
    let (untold, _) = reports_of_a_sender_told_its_send_rate(true, None);
    let (follows, _) = reports_of_a_sender_told_its_send_rate(true, Some(100_000));
    assert!(plain >= 40, "{plain}");
    assert_eq!(
        plain, ignored,
        "the option is off: the rate told is not used"
    );
    assert_eq!(plain, untold, "no rate was told: nothing to follow");
    let ratio = follows as f64 / plain as f64;
    assert!(
        (0.4..=0.9).contains(&ratio),
        "{follows} / {plain} = {ratio:.2}: two members, so the bound is 5% of 200 kbit/s \
         against 5% of the 270 to 340 kbit/s measured"
    );
    // A rate above what the session measures bounds nothing.
    let (high, _) = reports_of_a_sender_told_its_send_rate(true, Some(5_000_000));
    assert_eq!(plain, high);
}

/// The interval the session calculates for the OTHER members (what the circuit breaker
/// takes for the peer's reporting interval) is RFC 3550's for the whole RTCP bandwidth
/// whether or not this endpoint's own share follows its send rate: the peer does not slow
/// its reports because this endpoint's uplink collapsed.
#[test]
fn the_interval_calculated_for_the_peer_does_not_follow_the_send_rate() {
    let (_, plain) = reports_of_a_sender_told_its_send_rate(false, None);
    let (_, follows) = reports_of_a_sender_told_its_send_rate(true, Some(100_000));
    assert!(plain > Duration::ZERO, "an interval rode on the RTCP read");
    // (The average packet size the interval is computed from differs a little between the
    // two runs, which send different numbers of reports; the bound would lengthen it by a
    // third or more.)
    let ratio = follows.as_secs_f64() / plain.as_secs_f64();
    assert!(
        (0.87..=1.15).contains(&ratio),
        "{follows:?} / {plain:?} = {ratio:.2}"
    );
}
