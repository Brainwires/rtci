//! The bounds draft-ietf-rmcat-gcc-02 section 5.5 puts on the delay-based estimate.

use rtci_interceptor::{
    BandwidthEstimator, Gcc, PacketReport, RateController, ReceivedRateBound, Usage,
};
use rtcp::transport_feedbacks::cc_feedback_report::Ecn;
use std::time::{Duration, Instant};

/// One acknowledged packet that crossed a path with a constant 20 ms delay.
fn report(epoch: Instant, id: u64, departure: Duration, size: usize) -> PacketReport {
    PacketReport {
        ssrc: 1,
        id,
        rtp_sequence_number: id as u16,
        is_twcc: true,
        twcc_sequence_number: id as u16,
        size,
        arrived: true,
        departure: epoch + departure,
        arrival: Some(Duration::from_secs(1_000) + departure + Duration::from_millis(20)),
        ecn: Ecn::NotEct,
    }
}

/// 100 kbit/s on a clean path for a minute: a 250-byte packet every 20 ms, feedback every
/// 100 ms.
fn a_minute_at_100_kbit_per_second(epoch: Instant, gcc: &mut Gcc) -> (f64, f64) {
    let mut id = 0u64;
    let (mut lowest, mut highest) = (f64::INFINITY, 0.0f64);
    for feedback in 0..600u64 {
        let reports: Vec<PacketReport> = (0..5)
            .map(|_| {
                let departure = Duration::from_millis(id * 20);
                id += 1;
                report(epoch, id, departure, 250)
            })
            .collect();
        gcc.on_reports(
            epoch + Duration::from_millis(feedback * 100 + 120),
            &reports,
        );
        lowest = lowest.min(gcc.target_bitrate());
        highest = highest.max(gcc.target_bitrate());
    }
    (lowest, highest)
}

/// Section 5.5: "we must make sure that our estimate does not diverge from the rate at which
/// the sender is actually sending ... A_hat(i) < 1.5 * R_hat(i)". A source with less to send
/// than the estimate allows (a muted or static source) must not inflate it
/// (draft-ietf-rmcat-gcc.md bug G1: it climbed 8% per second to the configured maximum): an
/// estimate under the bound climbs to it and stops there, and one that starts above it (the
/// start rate of 300 kbit/s) is not increased at all.
#[test]
fn an_application_limited_sender_does_not_inflate_the_delay_estimate() {
    let epoch = Instant::now();
    let mut gcc = Gcc::new(110_000.0, 100_000.0, 100_000_000.0);
    a_minute_at_100_kbit_per_second(epoch, &mut gcc);
    assert!(
        gcc.delay_based_bitrate() > 140_000.0 && gcc.delay_based_bitrate() <= 1.5 * 100_000.0 * 1.1,
        "the delay-based estimate is {} bit/s for a sender of 100 kbit/s",
        gcc.delay_based_bitrate()
    );
    assert!(
        gcc.target_bitrate() <= 1.5 * 100_000.0 * 1.1,
        "and the target is {}",
        gcc.target_bitrate()
    );

    let mut gcc = Gcc::default();
    let (_, highest) = a_minute_at_100_kbit_per_second(epoch, &mut gcc);
    assert_eq!(
        300_000.0, highest,
        "an estimate above the bound was increased"
    );
}

/// Section 5.5 lowers the delay-based estimate "As soon as over-use has been detected", and
/// section 6 the loss-based one when "more than 10% of the packets have been lost". A sender
/// that goes down to 100 kbit/s on a clean path gives neither: the estimate it had
/// (1 Mbit/s here, and the start rate of a call that begins with audio alone) is kept for the
/// whole minute. With the bound as a clamp ([`ReceivedRateBound::Clamps`]) it is brought down
/// to one and a half times what is sent.
#[test]
fn an_application_limited_sender_keeps_the_estimate_it_had() {
    let epoch = Instant::now();
    for start in [1_000_000.0, 300_000.0] {
        let mut gcc = Gcc::new(start, 100_000.0, 100_000_000.0);
        let (lowest, highest) = a_minute_at_100_kbit_per_second(epoch, &mut gcc);
        assert_eq!(
            (start, start),
            (lowest, highest),
            "from {start}: the estimate moved without evidence of congestion"
        );
    }

    let mut gcc = Gcc::new(1_000_000.0, 100_000.0, 100_000_000.0)
        .with_received_rate_bound(ReceivedRateBound::Clamps);
    let (lowest, _) = a_minute_at_100_kbit_per_second(epoch, &mut gcc);
    assert!(
        lowest <= 1.5 * 100_000.0 * 1.1,
        "the clamp left the estimate at {lowest}"
    );
}

/// Section 5.5: when the incoming rate rises above three standard deviations of the average
/// measured at decrease, "we assume that the congestion level has changed", the average is reset
/// and the increase is multiplicative again (draft-ietf-rmcat-gcc.md bug G3: after the first
/// over-use the controller stayed additive, 60 kbit/s per second, for as long as the target
/// stayed above 85% of that old rate).
#[test]
fn the_controller_leaves_additive_increase_when_the_path_widens() {
    let epoch = Instant::now();
    let mut controller = RateController::new(2_000_000.0, 100_000.0, 100_000_000.0);

    // Over-use while 1 Mbit/s is arriving.
    let mut received = controller.update(epoch, Usage::Over, Some(1_000_000.0));
    assert!((received - 850_000.0).abs() < 1.0);

    // The path widens to far more than this; the sender follows its target, so what arrives is
    // what the target was.
    for step in 1..=400u64 {
        received = controller.update(
            epoch + Duration::from_millis(step * 100),
            Usage::Normal,
            Some(received),
        );
    }

    assert!(
        controller.target() > 5_000_000.0,
        "forty seconds on a wide path reached only {} bit/s",
        controller.target()
    );
}
