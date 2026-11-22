//! The bounds draft-ietf-rmcat-gcc-02 section 5.5 puts on the delay-based estimate.

use rtc_interceptor::{BandwidthEstimator, Gcc, PacketReport, RateController, Usage};
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

/// Section 5.5: "we must make sure that our estimate doesn't diverge from the rate at which the
/// sender is actually sending ... A_hat(i) < 1.5 * R_hat(i)". A source with less to send than
/// the estimate allows (a muted or static source) must not inflate it
/// (draft-ietf-rmcat-gcc.md bug G1: it climbed 8% per second to the configured maximum).
#[test]
fn an_application_limited_sender_does_not_inflate_the_delay_estimate() {
    let epoch = Instant::now();
    let mut gcc = Gcc::default();

    // 100 kbit/s: a 250-byte packet every 20 ms, on a clean path, for a minute. Feedback every
    // 100 ms.
    let mut id = 0u64;
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
    }

    assert!(
        gcc.delay_based_bitrate() <= 1.5 * 100_000.0 * 1.1,
        "the delay-based estimate is {} bit/s for a sender of 100 kbit/s",
        gcc.delay_based_bitrate()
    );
    assert!(
        gcc.target_bitrate() <= 1.5 * 100_000.0 * 1.1,
        "and the target is {}",
        gcc.target_bitrate()
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
