//! `Gcc`: the delay half and the loss half, combined.

use super::loss::LossController;
use super::overuse::OveruseDetector;
use super::rate_calc::RateCalculator;
use super::rate_control::RateController;
use super::slope::SlopeEstimator;
use crate::cc::estimator::{BandwidthEstimator, EstimatorStats};
use crate::rtpfb::acknowledgement::PacketReport;
use std::time::{Duration, Instant};

/// The most delay-gradient readings the trend is scaled by before it meets the threshold.
///
/// The detector compares `min(readings, 60) × m(i)` against the adaptive threshold, as pion's
/// `adaptiveThreshold.compare` and libwebrtc's `OveruseDetector::Detect` do: the Kalman estimate
/// `m(i)` is a per-group delay gradient, a few milliseconds when a link is oversubscribed by half
/// again, while the threshold starts at 12.5 ms (draft-ietf-rmcat-gcc-02 5.4). Compared unscaled,
/// a sender at 1.8 times a 600 kbit/s link never reads as overusing.
const MAX_SCALED_DELTAS: u32 = 60;

/// Rate to start from when nothing is known yet.
pub const DEFAULT_INITIAL_BITRATE: f64 = 300_000.0;
/// Floor. Below this a video call is not worth having.
pub const DEFAULT_MIN_BITRATE: f64 = 100_000.0;
/// Ceiling.
pub const DEFAULT_MAX_BITRATE: f64 = 100_000_000.0;

/// How long feedback may be missing, while packets are being sent, before the target is cut.
///
/// RFC 8888 section 5 has the congestion control algorithm specify its response to lost
/// feedback, and asks that several consecutive lost feedback packets rapidly reduce the sending
/// rate; RFC 8836 requirement 10 treats an unexpected lack of backchannel information as
/// possible over-use. Feedback is sent every 100 ms at most (draft-ietf-rmcat-gcc-02
/// section 3), so half a second is five reports in a row.
pub const DEFAULT_FEEDBACK_TIMEOUT: Duration = Duration::from_millis(500);

/// What the target is multiplied by each time [`DEFAULT_FEEDBACK_TIMEOUT`] passes without
/// feedback.
pub const FEEDBACK_TIMEOUT_DECREASE: f64 = 0.5;

/// Google Congestion Control.
///
/// # The two halves
///
/// ```text
/// reports ─┬─▶ SlopeEstimator ─▶ OveruseDetector ─▶ RateController ─┐
///          │   group, filter      usage + adaptive   AIMD           ├─▶ min ─▶ target
///          │                      threshold                         │
///          ├─▶ RateCalculator ────────────────────────────────────▶─┘
///          │   what is actually arriving
///          └─▶ LossController ────────────────────────────────────▶─┘
/// ```
///
/// The two are combined by **`min`**: whichever signal is more pessimistic wins. A path can be
/// congested in either way independently — a deep buffer queues without losing, a shallow or lossy
/// one loses without queueing — so neither half alone is sufficient and taking the lower of the two
/// is the only combination that responds to both.
///
/// # Deliberate divergences from upstream
///
/// - **D3 — one clamp.** Applied once, here, from configuration. Upstream clamps inside the loss
///   controller to a hard-coded 100 kb/s–100 Mb/s *and* again in the rate controller to the
///   configured range, and the two disagree.
/// - **D4 — loss may move the target alone.** See [`LossController`].
/// - **No hidden headroom.** [`target_bitrate`](Self::target_bitrate) is what the pacer is asked
///   for. Upstream's pacer silently multiplies by 1.5, so its reported target and its wire rate
///   differ by half again.
/// - **No clock.** Every instant is a parameter, which is what makes a bitrate trajectory
///   reproducible.
pub struct Gcc {
    slope: SlopeEstimator,
    detector: OveruseDetector,
    rate: RateCalculator,
    delay_control: RateController,
    loss_control: LossController,
    min: f64,
    max: f64,
    target: f64,
    /// Delay-gradient readings so far, capped at [`MAX_SCALED_DELTAS`].
    deltas: u32,
    /// One report's arrival on the receiver's clock and the local instant it is placed at, so
    /// later arrivals can be placed on this endpoint's timeline for the received-rate window.
    arrival_anchor: Option<(Duration, Instant)>,
    /// The newest arrival placed so far.
    newest_arrival: Option<Instant>,
    /// The range the application configured; `min` and `max` are this, narrowed by the limits
    /// from outside.
    configured: (f64, f64),
    /// When feedback was last read, once any has been.
    last_feedback: Option<Instant>,
    /// When a packet was last sent.
    last_sent: Option<Instant>,
    /// When the missing-feedback cut next applies: set while packets sent after the last
    /// feedback are waiting for theirs.
    feedback_deadline: Option<Instant>,
    feedback_timeout: Duration,
    /// Smoothed interval between feedback reports, as the receiver actually sends them.
    feedback_interval: Option<Duration>,
    round_trip_time: Option<Duration>,
}

impl Default for Gcc {
    fn default() -> Self {
        Self::new(
            DEFAULT_INITIAL_BITRATE,
            DEFAULT_MIN_BITRATE,
            DEFAULT_MAX_BITRATE,
        )
    }
}

impl Gcc {
    /// An estimator starting at `initial`, held within `min..=max`.
    pub fn new(initial: f64, min: f64, max: f64) -> Self {
        let initial = initial.clamp(min, max);
        Self {
            slope: SlopeEstimator::new(),
            detector: OveruseDetector::new(),
            rate: RateCalculator::default(),
            delay_control: RateController::new(initial, min, max),
            loss_control: LossController::new(initial, min, max),
            min,
            max,
            target: initial,
            deltas: 0,
            arrival_anchor: None,
            newest_arrival: None,
            configured: (min, max),
            last_feedback: None,
            last_sent: None,
            feedback_deadline: None,
            feedback_timeout: DEFAULT_FEEDBACK_TIMEOUT,
            feedback_interval: None,
            round_trip_time: None,
        }
    }

    /// How long feedback may be missing, while packets are being sent, before the target is
    /// halved (and halved again each time the same period passes).
    pub fn with_feedback_timeout(mut self, feedback_timeout: Duration) -> Self {
        self.feedback_timeout = feedback_timeout;
        self
    }

    /// How long feedback may be missing before the target is cut: the configured timeout, or
    /// three of the receiver's own feedback intervals when those are longer.
    ///
    /// A receiver that keeps its feedback inside the RTCP bandwidth (RFC 3550 section 6.2; at
    /// 100 kbit/s of media that is a few packets per second) reports every few hundred
    /// milliseconds, not every hundred. Its regular rhythm is not missing feedback.
    fn effective_feedback_timeout(&self) -> Duration {
        self.feedback_interval
            .map_or(self.feedback_timeout, |interval| {
                self.feedback_timeout.max(interval * 3)
            })
    }

    /// Bring both controllers and the target into the current range.
    fn apply_range(&mut self) {
        self.delay_control.set_bounds(self.min, self.max);
        self.loss_control.set_bounds(self.min, self.max);
        self.target = self.target.clamp(self.min, self.max);
    }

    /// Place an arrival on the receiver's clock onto this endpoint's timeline.
    ///
    /// Only differences between arrivals mean anything, so the first one seen is pinned to the
    /// instant its feedback was read and every later one keeps its distance from it.
    fn place_arrival(&mut self, now: Instant, arrival: Duration) -> Instant {
        let (anchor_arrival, anchor_instant) = *self.arrival_anchor.get_or_insert((arrival, now));
        if arrival >= anchor_arrival {
            anchor_instant + (arrival - anchor_arrival)
        } else {
            anchor_instant
                .checked_sub(anchor_arrival - arrival)
                .unwrap_or(anchor_instant)
        }
    }

    /// The delay-based half's current target, in bits per second.
    pub fn delay_based_bitrate(&self) -> f64 {
        self.delay_control.target()
    }

    /// The loss-based half's current target, in bits per second.
    pub fn loss_based_bitrate(&self) -> f64 {
        self.loss_control.target()
    }
}

impl BandwidthEstimator for Gcc {
    fn on_reports(&mut self, now: Instant, reports: &[PacketReport]) {
        if reports.is_empty() {
            return;
        }

        // Delay: group, filter, detect, control.
        let mut usage = self.detector.usage();
        for report in reports {
            // The received rate is what arrived per unit of the *receiver's* time
            // (draft-ietf-rmcat-gcc-02 5.5). Counting acknowledged bytes at the instant their
            // feedback was read instead measures one more feedback interval of bytes than of
            // time, which reads 20 to 25% high at a 100 ms cadence — enough that backing off to
            // 0.85 of it lands above the link.
            if report.arrived
                && let Some(arrival) = report.arrival
            {
                let at = self.place_arrival(now, arrival);
                self.rate.add(at, report.size);
                self.newest_arrival = Some(self.newest_arrival.map_or(at, |newest| newest.max(at)));
            }
            if let Some(trend) = self.slope.accumulate(report) {
                self.deltas = (self.deltas + 1).min(MAX_SCALED_DELTAS);
                usage = self
                    .detector
                    .update(trend.at, trend.estimate_ms * f64::from(self.deltas));
            }
        }

        let received = self
            .newest_arrival
            .and_then(|newest| self.rate.rate_bits_per_second(newest));
        let delay_target = self.delay_control.update(now, usage, received);

        // Loss: a fraction over this batch.
        let lost = reports.iter().filter(|report| !report.arrived).count();
        let loss_target = self.loss_control.update(now, lost, reports.len());

        // Whichever half is more pessimistic wins, clamped once (D3).
        self.target = delay_target.min(loss_target).clamp(self.min, self.max);

        // Feedback arrived: the missing-feedback clock starts again when the next packet
        // leaves.
        if let Some(last) = self.last_feedback {
            let interval = now.saturating_duration_since(last);
            self.feedback_interval = Some(match self.feedback_interval {
                Some(previous) => previous.mul_f64(0.8) + interval.mul_f64(0.2),
                None => interval,
            });
        }
        self.last_feedback = Some(now);
        self.feedback_deadline = None;
    }

    fn on_packet_sent(&mut self, now: Instant, _size: usize) {
        self.last_sent = Some(now);
        // Only once feedback has a rhythm (two reports) is its absence unexpected: a receiver
        // that never sends any is handled by the receiver-report fallback, and one that has
        // sent a single report has not yet shown how often it reports.
        if self.feedback_interval.is_some() && self.feedback_deadline.is_none() {
            self.feedback_deadline = Some(now + self.effective_feedback_timeout());
        }
    }

    fn on_round_trip_time(&mut self, _now: Instant, round_trip_time: Duration) {
        self.round_trip_time = Some(round_trip_time);
        self.delay_control.set_round_trip_time(round_trip_time);
    }

    fn set_external_bounds(&mut self, min: Option<f64>, max: Option<f64>) {
        let (configured_min, configured_max) = self.configured;
        self.max = max.map_or(configured_max, |max| max.min(configured_max));
        // A limit below the floor wins: the floor is a preference, the limit is not.
        self.min = min.unwrap_or(configured_min).min(self.max);
        self.apply_range();
    }

    fn on_receiver_report(&mut self, now: Instant, fraction_lost: f64) {
        // No per-packet feedback: the delay-based controller has nothing to run on, and the
        // loss-based one runs on the fraction lost the receiver reports (section 7).
        self.loss_control.update_fraction(now, fraction_lost);
        self.target = self.loss_control.target().clamp(self.min, self.max);
        self.delay_control.set_target(self.target);
    }

    fn on_path_change(&mut self, _now: Instant) {
        // Delay measurements across two paths mean nothing, and neither does where the old
        // path converged: start the delay side over, at the current target.
        self.slope = SlopeEstimator::new();
        self.detector = OveruseDetector::new();
        self.rate = RateCalculator::default();
        self.deltas = 0;
        self.arrival_anchor = None;
        self.newest_arrival = None;
        self.delay_control.reset_convergence();
        self.feedback_deadline = None;
    }

    fn handle_timeout(&mut self, now: Instant) {
        // Packets were sent and nothing has been heard about them for a whole timeout: treat
        // it as over-use. Halve, and again for each further timeout without feedback.
        while let Some(deadline) = self.feedback_deadline
            && now >= deadline
        {
            self.target = (self.target * FEEDBACK_TIMEOUT_DECREASE).clamp(self.min, self.max);
            self.delay_control.set_target(self.target);
            self.loss_control.cap(self.target);
            // Keep counting only while packets are still going out.
            let timeout = self.effective_feedback_timeout();
            self.feedback_deadline = self
                .last_sent
                .is_some_and(|sent| sent + timeout > deadline)
                .then(|| deadline + timeout);
        }
    }

    fn poll_timeout(&self) -> Option<Instant> {
        self.feedback_deadline
    }

    fn target_bitrate(&self) -> f64 {
        self.target
    }

    fn stats(&self) -> EstimatorStats {
        EstimatorStats {
            delay_based_bitrate: Some(self.delay_control.target()),
            loss_based_bitrate: Some(self.loss_control.target()),
            packet_loss: self.loss_control.average_loss(),
            round_trip_time: self.round_trip_time,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rtcp::transport_feedbacks::cc_feedback_report::Ecn;
    use std::time::Duration;

    fn report(id: u64, departure: Instant, arrival_ms: Option<u64>) -> PacketReport {
        PacketReport {
            ssrc: 1,
            id,
            rtp_sequence_number: id as u16,
            is_twcc: true,
            twcc_sequence_number: id as u16,
            size: 1500,
            arrived: arrival_ms.is_some(),
            departure,
            arrival: arrival_ms.map(Duration::from_millis),
            ecn: Ecn::default(),
        }
    }

    /// Empty feedback says nothing and must not move anything.
    #[test]
    fn empty_feedback_changes_nothing() {
        let epoch = Instant::now();
        let mut gcc = Gcc::default();
        let before = gcc.target_bitrate();

        gcc.on_reports(epoch, &[]);

        assert_eq!(before, gcc.target_bitrate());
    }

    /// The more pessimistic half wins. Here loss is catastrophic while delay is quiet, so the
    /// combined target must follow loss — which is the whole point of the `min`.
    #[test]
    fn the_more_pessimistic_half_wins() {
        let epoch = Instant::now();
        let mut gcc = Gcc::default();

        let mut at;
        for batch in 0..20u64 {
            at = epoch + Duration::from_millis(batch * 200);
            // Half the packets vanish; the ones that arrive do so promptly.
            let reports: Vec<PacketReport> = (0..10)
                .map(|index| {
                    let id = batch * 10 + index;
                    let departure = at + Duration::from_millis(index * 10);
                    let arrival = (index % 2 == 0).then(|| batch * 200 + index * 10 + 20);
                    report(id, departure, arrival)
                })
                .collect();
            gcc.on_reports(at, &reports);
        }

        assert!(
            gcc.target_bitrate() <= gcc.loss_based_bitrate() + 1.0,
            "the combined target must not exceed the loss half: {} vs {}",
            gcc.target_bitrate(),
            gcc.loss_based_bitrate()
        );
        assert!(
            gcc.target_bitrate() < DEFAULT_INITIAL_BITRATE,
            "50% loss must bring the target down, got {}",
            gcc.target_bitrate()
        );
    }

    /// One clamp, applied once at the combination point (D3).
    #[test]
    fn the_target_stays_within_configured_bounds() {
        let epoch = Instant::now();
        let mut gcc = Gcc::new(200_000.0, 150_000.0, 250_000.0);

        let mut at;
        for batch in 0..50u64 {
            at = epoch + Duration::from_millis(batch * 200);
            let reports: Vec<PacketReport> = (0..10)
                .map(|index| {
                    let id = batch * 10 + index;
                    let departure = at + Duration::from_millis(index * 10);
                    report(id, departure, Some(batch * 200 + index * 10 + 20))
                })
                .collect();
            gcc.on_reports(at, &reports);

            assert!(
                (150_000.0..=250_000.0).contains(&gcc.target_bitrate()),
                "target left its bounds: {}",
                gcc.target_bitrate()
            );
        }
    }

    /// The stats expose both halves, so an application can see *why* the target is where it is
    /// rather than only what it is.
    #[test]
    fn stats_report_both_halves() {
        let epoch = Instant::now();
        let mut gcc = Gcc::default();
        gcc.on_reports(epoch, &[report(0, epoch, Some(20)), report(1, epoch, None)]);

        let stats = gcc.stats();
        assert!(stats.delay_based_bitrate.is_some());
        assert!(stats.loss_based_bitrate.is_some());
        assert!(stats.packet_loss.is_some());
    }
}
