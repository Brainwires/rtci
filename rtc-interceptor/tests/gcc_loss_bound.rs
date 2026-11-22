//! What bounding the loss-based estimate by the delay-based one does (draft-ietf-rmcat-gcc-02
//! section 6), measured on the recovery fixture and on a path that loses without queueing.
//!
//! Prints, once a second, the delay-based estimate A_hat, the loss-based estimate As_hat, the
//! target and the loss the path reported, with As_hat free (the draft's "minimum of the two")
//! and with As_hat capped at A_hat. Run with `--nocapture` to read it.

mod path_simulator;

use path_simulator::{Path, PathProfile};
use rtc_interceptor::{BandwidthEstimator, Gcc, PacketReport};
use rtcp::transport_feedbacks::cc_feedback_report::Ecn;
use std::time::{Duration, Instant};

const PACKET_BITS: f64 = 12_000.0;

/// The fixture of `gcc_climbs_back_after_the_path_widens`: 1.2 Mbit/s offered whatever the
/// target, a 600 kbit/s bottleneck that widens fivefold after three seconds.
fn run(label: &str, profile: PathProfile, widen: Option<Duration>, capped: bool) -> Vec<f64> {
    let epoch = Instant::now();
    let mut path = Path::new(profile, epoch);
    if let Some(after) = widen {
        path = path.widening_after(after);
    }
    let mut gcc = Gcc::new(1_200_000.0, 100_000.0, 100_000_000.0)
        .with_loss_estimate_capped_by_delay_estimate(capped);
    let mut offered = Vec::new();
    let mut targets = Vec::new();
    let (mut lost, mut total) = (0usize, 0usize);

    println!(
        "{label}, loss-based estimate {}",
        if capped { "capped" } else { "free" }
    );
    println!("    t     A_hat    As_hat    target  lost/reported");
    for step in 0..1_200u64 {
        let at = epoch + Duration::from_millis(step * 10);
        path.offer(at, step as u16, PACKET_BITS);
        offered.push(at);
        path.drain_to(at);
        if step % 10 == 9 {
            let reports: Vec<PacketReport> = path
                .take_arrivals()
                .into_iter()
                .map(|arrival| {
                    let index = usize::from(arrival.twcc_sequence_number);
                    PacketReport {
                        ssrc: 1,
                        id: index as u64,
                        rtp_sequence_number: arrival.twcc_sequence_number,
                        is_twcc: true,
                        twcc_sequence_number: arrival.twcc_sequence_number,
                        size: (PACKET_BITS / 8.0) as usize,
                        arrived: arrival.at.is_some(),
                        departure: offered[index],
                        arrival: arrival.at.map(|at| at.duration_since(epoch)),
                        ecn: Ecn::default(),
                    }
                })
                .collect();
            lost += reports.iter().filter(|report| !report.arrived).count();
            total += reports.len();
            if !reports.is_empty() {
                gcc.on_reports(at, &reports);
            }
            targets.push(gcc.target_bitrate());
        }
        if step % 100 == 99 {
            println!(
                "{:>5} {:>9.0} {:>9.0} {:>9.0}  {lost}/{total}",
                (step + 1) / 100,
                gcc.delay_based_bitrate(),
                gcc.loss_based_bitrate(),
                gcc.target_bitrate()
            );
            lost = 0;
            total = 0;
        }
    }
    targets
}

#[test]
fn the_loss_based_estimate_free_and_capped_on_the_recovery_and_lossy_fixtures() {
    for capped in [false, true] {
        run(
            "recovering path",
            PathProfile::recovering(),
            Some(Duration::from_secs(3)),
            capped,
        );
        run(
            "lossy path without queueing",
            PathProfile::lossy_without_queueing(),
            None,
            capped,
        );
    }

    // The recovery fixture loses 180 packets between the fifth and the seventh second (its
    // sender ignores the target and overflows the queue it built). Left free, As_hat has
    // drifted to several times the rate being sent by then, so the loss cuts barely reach the
    // target; capped, they are taken from the rate being sent.
    let free = run(
        "recovering",
        PathProfile::recovering(),
        Some(Duration::from_secs(3)),
        false,
    );
    let capped = run(
        "recovering",
        PathProfile::recovering(),
        Some(Duration::from_secs(3)),
        true,
    );
    let lowest = |targets: &[f64]| targets.iter().copied().fold(f64::INFINITY, f64::min);
    assert!(
        lowest(&capped) < lowest(&free),
        "a loss episode cuts the rate being sent when As_hat is capped: {} against {}",
        lowest(&capped),
        lowest(&free)
    );
    assert!(
        lowest(&capped) <= 0.5 * 530_400.0,
        "39% of the packets of two seconds were lost: the target comes well below the 530 kbit/s \
         it was at, got {}",
        lowest(&capped)
    );
}
