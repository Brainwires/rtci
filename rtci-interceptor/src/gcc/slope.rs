//! Turning grouped acknowledgements into a filtered delay trend.

use super::arrival_group::{ArrivalGroupAccumulator, InterGroupDelay};
use super::kalman::Kalman;
use crate::rtpfb::acknowledgement::PacketReport;
use std::time::{Duration, Instant};

/// One filtered delay-gradient reading.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct DelayTrend {
    /// The raw inter-group measurement, in milliseconds.
    pub measurement_ms: f64,
    /// The filtered trend, in milliseconds. This is what the overuse detector compares.
    pub estimate_ms: f64,
    /// When the measurement belongs to.
    pub at: Instant,
    /// Bytes in the group this reading closed, for the received-rate calculation.
    pub size: usize,
    /// When the group's last packet arrived, on the receiver's clock (t(i), section 5.3).
    pub arrival: Duration,
}

/// Grouping plus filtering: acknowledgements in, a delay trend out.
///
/// The two halves are separate types because they are separately testable — the accumulator against
/// hand-built arrival patterns, the filter against numeric sequences — and this joins them without
/// adding behaviour of its own.
#[derive(Debug, Clone, Default)]
pub struct SlopeEstimator {
    groups: ArrivalGroupAccumulator,
    kalman: Kalman,
    /// When the last group closed departed, for the group period the filter's noise weight
    /// follows (draft-ietf-rmcat-gcc-02 section 5.3, `f_max`).
    last_departure: Option<Instant>,
}

impl SlopeEstimator {
    /// A slope estimator with the draft's default grouping and tuning.
    pub fn new() -> Self {
        Self::default()
    }

    /// A slope estimator grouping packets sent within `burst_interval` of each other.
    pub fn with_burst_interval(burst_interval: Duration) -> Self {
        Self {
            groups: ArrivalGroupAccumulator::new(burst_interval),
            kalman: Kalman::new(),
            last_departure: None,
        }
    }

    /// Whether reports are fed in arrival order
    /// ([`ArrivalGroupAccumulator::with_arrival_order`]).
    pub fn with_arrival_order(mut self, arrival_order: bool) -> Self {
        self.groups = self.groups.with_arrival_order(arrival_order);
        self
    }

    /// The current filtered trend, in milliseconds.
    pub fn estimate_ms(&self) -> f64 {
        self.kalman.estimate()
    }

    /// Feed one report; returns a reading when a group closed.
    pub fn accumulate(&mut self, report: &PacketReport) -> Option<DelayTrend> {
        let delay = self.groups.accumulate(report)?;
        Some(self.filter(delay))
    }

    /// Close the stream, emitting the reading for the group still open.
    pub fn flush(&mut self) -> Option<DelayTrend> {
        let delay = self.groups.flush()?;
        Some(self.filter(delay))
    }

    fn filter(&mut self, delay: InterGroupDelay) -> DelayTrend {
        let period_ms = self.last_departure.map_or(0.0, |last| {
            delay.at.saturating_duration_since(last).as_secs_f64() * 1_000.0
        });
        self.last_departure = Some(delay.at);
        DelayTrend {
            measurement_ms: delay.delta_ms,
            estimate_ms: self.kalman.update_with_period(delay.delta_ms, period_ms),
            at: delay.at,
            arrival: delay.arrival,
            size: delay.size,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rtcp::transport_feedbacks::cc_feedback_report::Ecn;

    fn report(departure: Instant, arrival_ms: u64) -> PacketReport {
        PacketReport {
            ssrc: 1,
            id: 0,
            rtp_sequence_number: 0,
            is_twcc: true,
            twcc_sequence_number: 0,
            size: 1200,
            arrived: true,
            departure,
            arrival: Some(Duration::from_millis(arrival_ms)),
            ecn: Ecn::default(),
        }
    }

    /// End to end over the two halves: a non-queueing path reads flat.
    #[test]
    fn a_steady_path_reads_flat() {
        let epoch = Instant::now();
        let mut slope = SlopeEstimator::new();

        for burst in 0..40u64 {
            slope.accumulate(&report(
                epoch + Duration::from_millis(burst * 20),
                100 + burst * 20,
            ));
        }

        assert!(
            slope.estimate_ms().abs() < 1.0,
            "a steady path should read about zero, got {}",
            slope.estimate_ms()
        );
    }

    /// And a queue building reads positive and rising — the signal P7-05's detector triggers on.
    #[test]
    fn a_queueing_path_reads_positive() {
        let epoch = Instant::now();
        let mut slope = SlopeEstimator::new();

        for burst in 0..40u64 {
            slope.accumulate(&report(
                epoch + Duration::from_millis(burst * 20),
                100 + burst * 26,
            ));
        }

        assert!(
            slope.estimate_ms() > 3.0,
            "6 ms of queue per group should read clearly positive, got {}",
            slope.estimate_ms()
        );
    }

    /// The reading carries the group's size, which is what the received-rate calculation consumes.
    #[test]
    fn a_reading_carries_the_group_size() {
        let epoch = Instant::now();
        let mut slope = SlopeEstimator::new();

        slope.accumulate(&report(epoch, 100));
        slope.accumulate(&report(epoch + Duration::from_millis(20), 120));
        let reading = slope
            .accumulate(&report(epoch + Duration::from_millis(40), 140))
            .expect("the second group closes against the first");

        assert_eq!(1200, reading.size);
    }

    /// An investigation, not a check: the delay-gradient readings of a reorder-only path (one
    /// way 25 ms, a share of the packets held back by up to `hold` more, nothing queued) as our
    /// grouping makes them, against libwebrtc's (`delay_based_bwe.cc`: feedback
    /// `SortedByReceiveTime()`, then `InterArrivalDelta` with 5 ms send-time groups, a packet
    /// sent before its group's first discarded as reordered, a group whose arrival goes
    /// backwards discarded). Each sequence goes through the same Kalman filter and overuse
    /// detector. `cargo test -p rtci-interceptor --lib reorder_trace -- --ignored --nocapture`
    #[test]
    #[ignore = "an investigation tool: prints the two groupings' readings"]
    fn reorder_trace_against_libwebrtc_grouping() {
        use crate::gcc::overuse::{OveruseDetector, Usage};
        struct Rng(u64);
        impl Rng {
            fn unit(&mut self) -> f64 {
                self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
                let mut z = self.0;
                z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
                z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
                ((z ^ (z >> 31)) >> 11) as f64 / (1u64 << 53) as f64
            }
        }
        let epoch = Instant::now();
        for (share, hold_ms) in [(0.0, 0.0), (0.5, 40.0), (1.0, 40.0), (0.5, 100.0)] {
            let mut rng = Rng(7);
            // 60 s of 100 packets a second (a 500 kbit/s video flow's packet rate).
            let packets: Vec<(f64, f64)> = (0..6000u64)
                .map(|n| {
                    let sent = n as f64 * 10.0;
                    let hold = if rng.unit() < share {
                        hold_ms * rng.unit()
                    } else {
                        0.0
                    };
                    (sent, sent + 25.0 + hold)
                })
                .collect();
            let at = |ms: f64| epoch + Duration::from_secs_f64(ms / 1000.0);

            // Ours: reports in send (transport sequence) order.
            let mut ours = Vec::new();
            let mut groups = ArrivalGroupAccumulator::default();
            for (sent, arrived) in &packets {
                let mut r = report(at(*sent), 0);
                r.arrival = Some(Duration::from_secs_f64(arrived / 1000.0));
                if let Some(delay) = groups.accumulate(&r) {
                    ours.push((delay.at, delay.delta_ms));
                }
            }

            // libwebrtc: sorted by arrival, InterArrivalDelta.
            let mut sorted = packets.clone();
            sorted.sort_by(|a, b| a.1.total_cmp(&b.1));
            #[derive(Clone, Copy)]
            struct Group {
                first_send: f64,
                send: f64,
                first_arrival: f64,
                complete: f64,
            }
            let mut current: Option<Group> = None;
            let mut previous: Option<Group> = None;
            let mut theirs = Vec::new();
            let mut discarded = 0usize;
            let mut reordered_groups = 0usize;
            for (sent, arrived) in sorted {
                let Some(mut group) = current else {
                    current = Some(Group {
                        first_send: sent,
                        send: sent,
                        first_arrival: arrived,
                        complete: arrived,
                    });
                    continue;
                };
                if group.first_send > sent {
                    discarded += 1;
                    continue;
                }
                let arrival_delta = arrived - group.complete;
                let send_delta = sent - group.send;
                let burst = send_delta == 0.0
                    || (arrival_delta - send_delta < 0.0
                        && arrival_delta <= 5.0
                        && arrived - group.first_arrival < 100.0);
                if !burst && sent - group.first_send > 5.0 {
                    if let Some(prev) = previous {
                        let a = group.complete - prev.complete;
                        let d = group.send - prev.send;
                        if a < 0.0 {
                            reordered_groups += 1;
                        } else {
                            theirs.push((at(group.send), a - d));
                        }
                    }
                    previous = Some(group);
                    group = Group {
                        first_send: sent,
                        send: sent,
                        first_arrival: arrived,
                        complete: arrived,
                    };
                } else {
                    group.send = group.send.max(sent);
                    group.complete = arrived;
                }
                current = Some(group);
            }

            let summarise = |name: &str, readings: &[(Instant, f64)]| {
                let n = readings.len() as f64;
                let mean = readings.iter().map(|r| r.1).sum::<f64>() / n;
                let sd = (readings.iter().map(|r| (r.1 - mean).powi(2)).sum::<f64>() / n).sqrt();
                let mut kalman = Kalman::new();
                let mut detector = OveruseDetector::new();
                let (mut over, mut under, mut last) = (0, 0, None);
                let mut max_estimate: f64 = 0.0;
                for (when, delta) in readings {
                    let period = last.map_or(0.0, |l: Instant| {
                        when.saturating_duration_since(l).as_secs_f64() * 1000.0
                    });
                    last = Some(*when);
                    let estimate = kalman.update_with_period(*delta, period);
                    max_estimate = max_estimate.max(estimate.abs());
                    match detector.update(*when, estimate) {
                        Usage::Over => over += 1,
                        Usage::Under => under += 1,
                        Usage::Normal => {}
                    }
                }
                println!(
                    "  {name}: {} readings, delta mean {mean:+.3} ms sd {sd:.2} ms, |estimate| max {max_estimate:.2} ms, readings in overuse {over}, underuse {under}",
                    readings.len()
                );
                let first: Vec<String> = readings
                    .iter()
                    .take(12)
                    .map(|r| format!("{:+.1}", r.1))
                    .collect();
                println!("    first deltas: {}", first.join(" "));
            };
            println!("share {share}, hold up to {hold_ms} ms:");
            summarise("ours (send order, arrival-before-group ignored)", &ours);
            summarise("libwebrtc (arrival order, InterArrivalDelta)", &theirs);
            println!(
                "    libwebrtc discarded {discarded} reordered packets, {reordered_groups} groups"
            );
        }
    }
}
