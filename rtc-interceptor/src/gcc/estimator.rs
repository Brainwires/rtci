//! `Gcc`: the delay half and the loss half, combined.

use super::loss::LossController;
use super::overuse::{OveruseDetector, Usage};
use super::queue_limit::QueueLimitDetector;
use super::rate_calc::RateCalculator;
use super::rate_control::RateController;
use super::slope::SlopeEstimator;
use super::threshold::ThresholdTimeBase;
use crate::cc::estimator::{BandwidthEstimator, EstimatorStats};
use crate::rtpfb::acknowledgement::PacketReport;
use rtcp::transport_feedbacks::cc_feedback_report::Ecn;
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

/// How long a probe result stands in for the received rate in the bound of the estimate by
/// one and a half times what is received (section 5.5). A sender that follows the target is
/// received at the new rate within a window of the received-rate measurement and the bound
/// is the draft's again. A sender with less to send than the target is probed again every
/// five seconds: the result stands until the next one is due and has had its second to
/// arrive, so the estimate rests on a measurement no older than that instead of falling back
/// to one and a half times what the application happens to send and jumping up again with
/// every probe. A probe that confirms the estimate renews it; over-use lowers it with the
/// estimate.
pub const PROBE_RESULT_HOLD: Duration = Duration::from_secs(6);

/// A probe result at least this share of the estimate confirms it (see
/// [`PROBE_RESULT_HOLD`]): the cluster arrived at about the rate the estimate already is.
pub const PROBE_CONFIRMS_ESTIMATE: f64 = 0.9;

/// A pause in sending up to this long keeps the estimate (RFC 8836 section 2, requirement
/// 5a: the flow regains its share fast).
pub const PAUSE_KEEPS_SHARE: Duration = Duration::from_secs(2);
/// Beyond [`PAUSE_KEEPS_SHARE`], each such stretch of pause halves the estimate the flow resumes
/// at (requirement 5a: less aggressively the longer the interruption).
pub const PAUSE_HALVING: Duration = Duration::from_secs(10);

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
    /// The starting estimate, which a long pause in sending falls back towards.
    initial: f64,
    /// When feedback was last read, once any has been.
    last_feedback: Option<Instant>,
    /// When a packet was last sent.
    last_sent: Option<Instant>,
    /// When the missing-feedback cut next applies: set while packets sent after the last
    /// feedback are waiting for theirs.
    feedback_deadline: Option<Instant>,
    feedback_timeout: Duration,
    /// Whether the loss-based estimate is held at or below the delay-based one.
    loss_capped_by_delay: bool,
    /// Smoothed interval between feedback reports, as the receiver actually sends them.
    feedback_interval: Option<Duration>,
    round_trip_time: Option<Duration>,
    /// When the last probe result was taken.
    probed_at: Option<Instant>,
    /// Whether a loss out of a queue at its limit is over-use (see
    /// [`with_loss_at_queue_limit_as_overuse`](Self::with_loss_at_queue_limit_as_overuse)).
    loss_at_queue_limit_is_overuse: bool,
    queue_limit: QueueLimitDetector,
    threshold_time_base: ThresholdTimeBase,
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
    /// RFC 8836 section 2, requirement 5a: after a pause in sending the flow "SHOULD [...]
    /// regain [its previous share] fast, but [...] less aggressively the longer the
    /// interruption". A pause up to [`PAUSE_KEEPS_SHARE`] keeps the estimate; a longer one
    /// halves it for every [`PAUSE_HALVING`] beyond that (the path may have changed meanwhile),
    /// down to the starting estimate at most, from where the controller (and bandwidth probing)
    /// climbs again.
    fn resume_after(&mut self, pause: Duration) {
        let Some(beyond) = pause.checked_sub(PAUSE_KEEPS_SHARE) else {
            return;
        };
        let factor = 0.5f64.powf(beyond.as_secs_f64() / PAUSE_HALVING.as_secs_f64());
        let floor = self.initial.min(self.target);
        let resumed = (self.target * factor).max(floor).clamp(self.min, self.max);
        if resumed < self.target {
            self.target = resumed;
            self.delay_control.set_target(resumed);
            self.delay_control.reset_convergence();
            self.loss_control.cap(resumed);
        }
    }
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
            initial,
            last_feedback: None,
            last_sent: None,
            feedback_deadline: None,
            feedback_timeout: DEFAULT_FEEDBACK_TIMEOUT,
            loss_capped_by_delay: true,
            feedback_interval: None,
            round_trip_time: None,
            probed_at: None,
            loss_at_queue_limit_is_overuse: true,
            queue_limit: QueueLimitDetector::new(),
            threshold_time_base: ThresholdTimeBase::default(),
        }
    }

    /// Whether a packet lost out of a queue at its limit counts as over-use for the
    /// delay-based controller (the default), or only for the loss-based one as
    /// draft-ietf-rmcat-gcc-02 has it.
    ///
    /// The draft's over-use signal is the delay *gradient*: a queue that is growing. A
    /// tail-drop queue that has filled to its limit no longer grows, whatever is sent into
    /// it: the gradient is zero, the detector reads normal and the delay-based estimate keeps
    /// climbing, while the loss-based controller holds anywhere between 2% and 10% loss
    /// (section 6). A flow in that state never yields. Measured on a shared FIFO bottleneck
    /// (`rtc-interceptor/tests/rfc8836_multi_flow.rs`): a second flow joining an established
    /// one fell to the floor, and against a Reno-like transfer `Gcc` took 97% of the path,
    /// both against RFC 8836 section 2 (requirements 2a, a MUST, and 3). With the default, a
    /// feedback batch that lost a packet while every packet of it that arrived waited near the
    /// highest queueing delay seen of late ([`QueueLimitDetector`]) is over-use: the
    /// estimate backs off as from a growing queue, and the queue drains. Loss with little or
    /// no queue (a radio link, a policer) is left to the loss-based controller, as before.
    /// `false` is the draft as written.
    pub fn with_loss_at_queue_limit_as_overuse(mut self, enabled: bool) -> Self {
        self.loss_at_queue_limit_is_overuse = enabled;
        self
    }

    /// Whether over-use lowers the estimate at most once per round trip (the default) or on
    /// every update while it lasts, as draft-ietf-rmcat-gcc-02 section 5.5 has it. See
    /// [`RateController::with_one_decrease_per_round_trip`].
    pub fn with_one_decrease_per_round_trip(mut self, enabled: bool) -> Self {
        self.delay_control = self.delay_control.with_one_decrease_per_round_trip(enabled);
        self
    }

    /// How long feedback may be missing, while packets are being sent, before the target is
    /// halved (and halved again each time the same period passes).
    pub fn with_feedback_timeout(mut self, feedback_timeout: Duration) -> Self {
        self.feedback_timeout = feedback_timeout;
        self
    }

    /// The time step of the adaptive threshold (draft-ietf-rmcat-gcc-02 section 5.4):
    /// [`ThresholdTimeBase::Departure`] (libwebrtc, the default) or the draft's
    /// [`ThresholdTimeBase::Arrival`].
    pub fn with_threshold_time_base(mut self, time_base: ThresholdTimeBase) -> Self {
        self.threshold_time_base = time_base;
        self.detector = self.detector.with_threshold_time_base(time_base);
        self
    }

    /// See [`ThresholdTimeBase`]: the time step of the adaptive threshold (draft-ietf-rmcat-gcc-02
    /// section 5.4), libwebrtc's departure gaps by default.
    pub fn threshold_time_base(&self) -> ThresholdTimeBase {
        self.threshold_time_base
    }

    /// Whether the loss-based estimate As_hat is held at or below the delay-based estimate
    /// A_hat after every update (the default), or left free with only the minimum of the two
    /// taken as the sending rate.
    ///
    /// draft-ietf-rmcat-gcc-02 section 6 has the loss-based controller work from the available
    /// bandwidth estimate of the delay-based one. Left free, As_hat grows 5% per interval
    /// whenever loss is under 2%, whatever the path carries: after five quiet seconds it is
    /// several times the rate being sent, and `As_hat(i) = As_hat(i-1)(1 - 0.5p)` then has to
    /// cut it back through all of that before the sending rate moves at all. Capped, a loss
    /// cut is taken from the rate actually being sent, and the climb back starts from there.
    pub fn with_loss_estimate_capped_by_delay_estimate(mut self, capped: bool) -> Self {
        self.loss_capped_by_delay = capped;
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
    /// RFC 6679 section 7.3.3: CE marks counted by the receiver's ECN reports go to the
    /// loss-based controller as losses would; the target can only fall by them.
    fn on_congestion_marks(&mut self, now: Instant, marked: u64, packets: u64) {
        if marked == 0 || packets == 0 {
            return;
        }
        let packets = packets.min(usize::MAX as u64) as usize;
        let marked = (marked.min(packets as u64)) as usize;
        self.loss_control.update(now, marked, packets);
        let loss_target = self.loss_control.target();
        self.target = self.target.min(loss_target).clamp(self.min, self.max);
    }

    fn on_reports(&mut self, now: Instant, reports: &[PacketReport]) {
        if reports.is_empty() {
            return;
        }
        // A probe's measurement stands in for the received rate until the received rate has
        // had its window to follow.
        if let Some(probed_at) = self.probed_at
            && now.saturating_duration_since(probed_at) > PROBE_RESULT_HOLD
        {
            self.probed_at = None;
            self.delay_control.set_measured_rate(None);
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
                usage = self.detector.update_with_arrival(
                    trend.at,
                    trend.arrival,
                    trend.estimate_ms * f64::from(self.deltas),
                );
            }
        }

        let received = self
            .newest_arrival
            .and_then(|newest| self.rate.rate_bits_per_second(newest));
        // A loss out of a queue at its limit: the queue would be growing, had it room.
        if self.queue_limit.on_reports(now, reports) && self.loss_at_queue_limit_is_overuse {
            usage = Usage::Over;
        }
        let delay_target = self.delay_control.update(now, usage, received);

        // Loss: a fraction over this batch. A packet that arrived marked ECN-CE counts as one
        // that did not: "a CE mark is a congestion signal" (RFC 8888 section 7 with RFC 6679
        // section 7.3.3: the sender reacts to it as to a lost packet, without retransmitting).
        let lost = reports
            .iter()
            .filter(|report| !report.arrived || report.ecn == Ecn::Ce)
            .count();
        self.loss_control.update(now, lost, reports.len());
        if self.loss_capped_by_delay {
            self.loss_control.cap(delay_target);
        }
        let loss_target = self.loss_control.target();

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
        if let Some(last) = self.last_sent {
            self.resume_after(now.saturating_duration_since(last));
        }
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

    fn on_probe_result(&mut self, now: Instant, bits_per_second: f64) {
        if !bits_per_second.is_finite() || bits_per_second <= 0.0 {
            return;
        }
        if bits_per_second <= self.target {
            // A probe only ever raises the estimate: one that came out well below it says the
            // cluster met a queue, which the delay-based controller hears about by itself.
            // One that the path carried at about the estimate confirms it: the measurement is
            // renewed, so that an application sending less than the target keeps resting on
            // it rather than falling back, once the last raise is older than the hold, to one
            // and a half times what it sends (and from there, by the same bound, lower with
            // every update).
            if bits_per_second >= PROBE_CONFIRMS_ESTIMATE * self.target {
                self.delay_control.set_measured_rate(Some(bits_per_second));
                self.probed_at = Some(now);
            }
            return;
        }
        // The path carried the cluster at this rate. Both halves start from it, the climb
        // from here is multiplicative again, and for a while the measurement stands in for
        // the received rate, which only follows once the application sends at the new target.
        self.delay_control.set_target(bits_per_second);
        self.delay_control.reset_convergence();
        self.delay_control.set_measured_rate(Some(bits_per_second));
        self.probed_at = Some(now);
        self.loss_control.raise(bits_per_second);
        self.target = self
            .delay_control
            .target()
            .min(self.loss_control.target())
            .clamp(self.min, self.max);
    }

    fn on_path_change(&mut self, _now: Instant) {
        // Delay measurements across two paths mean nothing, and neither does where the old
        // path converged: start the delay side over, at the current target.
        self.slope = SlopeEstimator::new();
        self.detector = OveruseDetector::new().with_threshold_time_base(self.threshold_time_base);
        self.rate = RateCalculator::default();
        self.deltas = 0;
        self.arrival_anchor = None;
        self.newest_arrival = None;
        self.queue_limit = QueueLimitDetector::new();
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

    /// RFC 8836 section 2, requirement 5a: a short pause keeps the estimate, a long one brings
    /// it down, the more the longer the pause, never below the starting estimate.
    #[test]
    fn a_pause_in_sending_keeps_the_estimate_and_a_long_one_lowers_it() {
        let epoch = Instant::now();
        let resumed_after = |pause: Duration| {
            let mut gcc = Gcc::new(300_000.0, 100_000.0, 10_000_000.0);
            gcc.on_probe_result(epoch, 2_000_000.0);
            gcc.on_packet_sent(epoch, 1200);
            gcc.on_packet_sent(epoch + pause, 1200);
            gcc.target_bitrate()
        };
        assert_eq!(resumed_after(Duration::from_millis(500)), 2_000_000.0);
        assert_eq!(resumed_after(PAUSE_KEEPS_SHARE), 2_000_000.0);
        let twelve = resumed_after(PAUSE_KEEPS_SHARE + PAUSE_HALVING);
        assert!((twelve - 1_000_000.0).abs() < 1.0, "{twelve}");
        let long = resumed_after(Duration::from_secs(120));
        assert_eq!(long, 300_000.0, "down to the starting estimate, not below");
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

    /// RFC 8888 section 7 / RFC 6679 section 7.3.3: a packet the receiver reports as arrived
    /// with ECN-CE is a congestion signal, answered as a loss is. Every packet arrives, and
    /// promptly; three in twenty carry the mark; the loss-based half backs off. The same
    /// arrivals without marks leave it where it was or higher.
    #[test]
    fn congestion_experienced_marks_lower_the_target_as_losses_do() {
        let run = |marked: bool| {
            let epoch = Instant::now();
            let mut gcc = Gcc::new(1_000_000.0, 100_000.0, 10_000_000.0);
            for batch in 0..20u64 {
                let at = epoch + Duration::from_millis(batch * 200);
                let reports: Vec<PacketReport> = (0..20)
                    .map(|index| {
                        let id = batch * 20 + index;
                        let departure = at + Duration::from_millis(index * 10);
                        let mut report = report(id, departure, Some(batch * 200 + index * 10 + 20));
                        if marked && index % 7 == 0 {
                            report.ecn = Ecn::Ce;
                        }
                        report
                    })
                    .collect();
                gcc.on_reports(at + Duration::from_millis(200), &reports);
            }
            gcc.loss_based_bitrate()
        };

        let marked = run(true);
        let clean = run(false);
        assert!(marked < 1_000_000.0, "15% marked: {marked}");
        assert!(clean >= 1_000_000.0, "no marks, no losses: {clean}");
        assert!(marked < 0.8 * clean, "{marked} vs {clean}");
    }

    /// RFC 6679 section 7.3.3: CE marks counted by RFC 6679 ECN reports (no per-packet
    /// marks) bring the target down as the same share of losses would; reports without marks
    /// leave it where it was.
    #[test]
    fn ce_marks_from_ecn_counters_lower_the_target_as_losses_do() {
        let epoch = Instant::now();
        let run = |marked: u64| {
            let mut gcc = Gcc::new(1_000_000.0, 100_000.0, 10_000_000.0);
            for batch in 0..20u64 {
                gcc.on_congestion_marks(epoch + Duration::from_millis(batch * 200), marked, 20);
            }
            gcc.target_bitrate()
        };
        let marked = run(3);
        let clean = run(0);
        assert!(marked < 0.8 * 1_000_000.0, "15% marked: {marked}");
        assert_eq!(clean, 1_000_000.0, "no marks: {clean}");
    }

    /// RFC 5104 section 5: after a TMMBR raises (or lifts) the limit, "the sender ... SHALL
    /// use congestion control" to go up: the target does not jump to the new limit but climbs
    /// by the estimator's own increase as feedback shows the path carries it.
    #[test]
    fn a_raised_limit_is_climbed_to_by_congestion_control_not_jumped_to() {
        let epoch = Instant::now();
        let mut gcc = Gcc::new(300_000.0, 50_000.0, 10_000_000.0);
        gcc.set_external_bounds(None, Some(300_000.0));
        let mut id = 0u64;
        let mut batch = |gcc: &mut Gcc, index: u64| {
            let at = epoch + Duration::from_millis(index * 100);
            let reports: Vec<PacketReport> = (0..10)
                .map(|n| {
                    id += 1;
                    let departure = at + Duration::from_millis(n * 10);
                    report(id, departure, Some(index * 100 + n * 10 + 20))
                })
                .collect();
            gcc.on_reports(at + Duration::from_millis(100), &reports);
        };
        for index in 0..20 {
            batch(&mut gcc, index);
        }
        assert!(gcc.target_bitrate() <= 300_000.0);

        gcc.set_external_bounds(None, Some(5_000_000.0));
        let right_after = gcc.target_bitrate();
        assert!(
            right_after <= 300_000.0 * 1.01,
            "no jump to the new limit: {right_after}"
        );
        for index in 20..60 {
            batch(&mut gcc, index);
        }
        let later = gcc.target_bitrate();
        assert!(
            later > right_after,
            "the target climbs: {right_after} -> {later}"
        );
        assert!(
            later < 5_000_000.0,
            "by the increase, not to the limit: {later}"
        );
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
