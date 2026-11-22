//! How fast GCC converges when the receiver sends transport-wide feedback less often.
//!
//! The RTCP session holds feedback to the RTCP bandwidth (RFC 3550 section 6.2: 5% of the
//! session bandwidth), which at about 100 kbit/s of media is a few feedback packets per second
//! instead of ten. This drives `Gcc` over a rate-limited path with the sender following the
//! target, at several feedback intervals, and prints what each interval costs (run with
//! `--nocapture` to read the table). The assertions are the floor the default has to keep.

mod path_simulator;

use path_simulator::{Path, PathProfile};
use rtc_interceptor::{BandwidthEstimator, Gcc, PacketReport};
use rtcp::transport_feedbacks::cc_feedback_report::Ecn;
use std::time::{Duration, Instant};

const PACKET_BYTES: usize = 1200;
const RUN: Duration = Duration::from_secs(60);

struct Outcome {
    /// When the target first reached 90% of the capacity, if it started below it; when it first
    /// came down to 110% of it, if it started above.
    settled_after: Option<Duration>,
    /// Mean target over the last 20 s, as a fraction of the capacity.
    mean_share: f64,
    /// Lowest and highest target over the last 20 s, as fractions of the capacity.
    low_share: f64,
    high_share: f64,
    /// Fraction of offered packets the path dropped over the whole run.
    loss: f64,
}

fn run(capacity: f64, initial: f64, feedback_interval: Duration) -> Outcome {
    let epoch = Instant::now();
    let mut path = Path::new(
        PathProfile {
            capacity_bits_per_second: capacity,
            // Half a second of queue at the bottleneck rate, then tail drop.
            queue_capacity_bits: capacity * 0.5,
            ..PathProfile::steady()
        },
        epoch,
    );
    let mut gcc = Gcc::new(initial, 30_000.0, 10_000_000.0);

    let packet_bits = (PACKET_BYTES * 8) as f64;
    let mut departures: Vec<Instant> = Vec::new();
    let mut next_send = Duration::ZERO;
    let mut next_feedback = feedback_interval;
    let mut offered = 0u64;
    let mut dropped = 0u64;
    let mut settled_after = None;
    let mut tail: Vec<f64> = Vec::new();
    let starts_below = initial < capacity;

    let step = Duration::from_millis(1);
    let mut now = Duration::ZERO;
    while now < RUN {
        // The sender follows the target: one packet every packet_bits / target seconds.
        while next_send <= now && departures.len() < usize::from(u16::MAX) {
            let at = epoch + next_send;
            path.offer(at, departures.len() as u16, packet_bits);
            departures.push(at);
            offered += 1;
            next_send += Duration::from_secs_f64(packet_bits / gcc.target_bitrate());
        }
        path.drain_to(epoch + now);

        if now >= next_feedback {
            next_feedback += feedback_interval;
            let reports: Vec<PacketReport> = path
                .take_arrivals()
                .into_iter()
                .map(|arrival| {
                    let index = usize::from(arrival.twcc_sequence_number);
                    if arrival.at.is_none() {
                        dropped += 1;
                    }
                    PacketReport {
                        ssrc: 1,
                        id: index as u64,
                        rtp_sequence_number: arrival.twcc_sequence_number,
                        is_twcc: true,
                        twcc_sequence_number: arrival.twcc_sequence_number,
                        size: PACKET_BYTES,
                        arrived: arrival.at.is_some(),
                        departure: departures[index],
                        arrival: arrival.at.map(|at| at.duration_since(epoch)),
                        ecn: Ecn::default(),
                    }
                })
                .collect();
            if !reports.is_empty() {
                gcc.on_reports(epoch + now, &reports);
            }
            let target = gcc.target_bitrate();
            let reached = if starts_below {
                target >= 0.9 * capacity
            } else {
                target <= 1.1 * capacity
            };
            if settled_after.is_none() && reached {
                settled_after = Some(now);
            }
            if now >= RUN - Duration::from_secs(20) {
                tail.push(target / capacity);
            }
        }
        now += step;
    }

    Outcome {
        settled_after,
        mean_share: tail.iter().sum::<f64>() / tail.len().max(1) as f64,
        low_share: tail.iter().copied().fold(f64::INFINITY, f64::min),
        high_share: tail.iter().copied().fold(0.0, f64::max),
        loss: dropped as f64 / offered.max(1) as f64,
    }
}

#[test]
fn gcc_convergence_against_the_feedback_interval() {
    println!("capacity  start     feedback  settled   mean   low    high   loss");
    let mut outcomes = Vec::new();
    for (capacity, initial) in [
        (150_000.0, 300_000.0),
        (500_000.0, 300_000.0),
        (1_000_000.0, 300_000.0),
        (2_500_000.0, 300_000.0),
    ] {
        for millis in [50u64, 100, 250, 500, 1000] {
            let outcome = run(capacity, initial, Duration::from_millis(millis));
            println!(
                "{:>8} {:>8} {:>7}ms {:>8} {:>6.2} {:>6.2} {:>6.2} {:>6.3}",
                capacity,
                initial,
                millis,
                outcome
                    .settled_after
                    .map_or("never".to_owned(), |at| format!("{:.1}s", at.as_secs_f64())),
                outcome.mean_share,
                outcome.low_share,
                outcome.high_share,
                outcome.loss
            );
            outcomes.push((capacity, millis, outcome));
        }
    }

    // The floor, at the 100 ms the draft takes as its upper bound for feedback: the estimate
    // ends between half the path and a little over it. The other intervals are measurements.
    for (capacity, millis, outcome) in &outcomes {
        if *millis == 100 {
            assert!(
                (0.5..=1.15).contains(&outcome.mean_share),
                "capacity {capacity}, feedback every {millis} ms: mean share {:.2}",
                outcome.mean_share
            );
        }
    }
}
