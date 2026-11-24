//! AIMD: what the target bitrate does in each state (draft-ietf-rmcat-gcc-02 section 5.5).

use super::overuse::Usage;
use super::state::RateControlState;
use std::time::{Duration, Instant};

/// Multiplier applied to the *received* rate when backing off (beta, section 5.5).
pub const DEFAULT_DECREASE_FACTOR: f64 = 0.85;

/// Multiplicative growth per second while far from convergence (the 1.08 of eta, section 5.5).
pub const DEFAULT_INCREASE_FACTOR: f64 = 1.08;

/// The step the first update of a controller is taken to cover, before there is a previous
/// update to measure from.
pub const DEFAULT_RATE_CONTROL_INTERVAL: Duration = Duration::from_millis(200);

/// The round trip time assumed until one has been measured.
pub const DEFAULT_ROUND_TRIP_TIME: Duration = Duration::from_millis(200);

/// How far the estimate may be above the received rate: `A_hat(i) < 1.5 * R_hat(i)`.
pub const MAX_ESTIMATE_TO_RECEIVED_RATIO: f64 = 1.5;

/// What the bound of the estimate by the received rate (`A_hat(i) < 1.5 * R_hat(i)`,
/// draft-ietf-rmcat-gcc-02 section 5.5) does to an estimate that is above it.
///
/// The draft introduces the bound for a sender that has less to send than the estimate
/// allows: "we must make sure that our estimate does not diverge from the rate at which the
/// sender is actually sending. Thus, if the sender is unable to produce a bit stream with the
/// bitrate the congestion controller is asking for, the available bandwidth estimate should
/// stay within a given bound. Therefore we introduce a threshold `A_hat(i) < 1.5 * R_hat(i)`".
/// It does not say what becomes of an estimate that the received rate has fallen away from:
/// a camera that was turned off, a key frame that has left the measurement window, a call
/// that has only just started at the start rate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ReceivedRateBound {
    /// The bound limits the increase: an estimate at or above it is not increased, and is
    /// left where it is until over-use sets it to `beta * R_hat` (which is within the
    /// bound). The default.
    ///
    /// The same section lowers the estimate for one reason, "As soon as over-use has been
    /// detected", holds it "constant" in the Hold state and has it "increased" on "every
    /// update" in the Increase state; lowering it because the application sends less does
    /// none of these, and tells an application whose camera is off that a path which has
    /// shown no congestion carries one and a half times its audio. libwebrtc, the
    /// implementation the draft's section 8 names, limits the increase as well
    /// (`modules/remote_bitrate_estimator/aimd_rate_control.cc:235-249, 266`: "We limit the
    /// new bitrate based on the troughput to avoid unlimited bitrate increases",
    /// `if (current_bitrate_ < increase_limit)`, `std::min(increased_bitrate,
    /// increase_limit)`).
    #[default]
    LimitsIncrease,
    /// The inequality holds after every update: an estimate above the bound is brought down
    /// to it, in every state, with no congestion signal. The inequality read by itself.
    Clamps,
}

/// Smoothing of the average and the variance of the received rate measured at each decrease
/// ("an exponential moving average with smoothing factor 0.95", section 5.5).
const CONVERGENCE_SMOOTHING: f64 = 0.95;

/// The average received rate seen in the Decrease state, and its variance: the estimate of where
/// the path's capacity is.
///
/// Rates are kept in kbit/s and the variance is normalised by the average, as libwebrtc's
/// `LinkCapacityEstimator` keeps them, so the deviation scales with the rate and the constants
/// below mean the same at 100 kbit/s and at 100 Mbit/s.
#[derive(Debug, Clone, Copy)]
struct Convergence {
    average_kbps: Option<f64>,
    /// Variance of the samples around the average, divided by the average.
    normalised_variance_kbps: f64,
}

impl Convergence {
    const INITIAL_VARIANCE: f64 = 0.4;
    const MIN_VARIANCE: f64 = 0.4;
    const MAX_VARIANCE: f64 = 2.5;

    fn new() -> Self {
        Self {
            average_kbps: None,
            normalised_variance_kbps: Self::INITIAL_VARIANCE,
        }
    }

    /// Three standard deviations, in kbit/s, around `average_kbps`.
    fn three_sigma(&self, average_kbps: f64) -> f64 {
        3.0 * (self.normalised_variance_kbps * average_kbps).sqrt()
    }

    /// The band of received rates that count as "close to convergence", in bits per second.
    fn band(&self) -> Option<(f64, f64)> {
        let average = self.average_kbps?;
        let spread = self.three_sigma(average);
        Some((
            (average - spread).max(0.0) * 1_000.0,
            (average + spread) * 1_000.0,
        ))
    }

    fn reset(&mut self) {
        self.average_kbps = None;
    }

    /// Fold in the received rate measured at a decrease.
    fn on_decrease(&mut self, received: f64) {
        let sample = received / 1_000.0;
        let average = match self.average_kbps {
            None => sample,
            Some(average) => {
                CONVERGENCE_SMOOTHING * average + (1.0 - CONVERGENCE_SMOOTHING) * sample
            }
        };
        let error = average - sample;
        self.normalised_variance_kbps = (CONVERGENCE_SMOOTHING * self.normalised_variance_kbps
            + (1.0 - CONVERGENCE_SMOOTHING) * error * error / average.max(1.0))
        .clamp(Self::MIN_VARIANCE, Self::MAX_VARIANCE);
        self.average_kbps = Some(average);
    }
}

/// The AIMD controller: a usage signal and a received rate in, a target bitrate out.
///
/// # Additive versus multiplicative increase
///
/// Climbing multiplicatively is fast but overshoots, which on a path already known to be near its
/// limit means congesting it again immediately. So the controller keeps the average and the
/// deviation of the received rate measured each time it backed off, and climbs additively, about
/// half a packet per response time, while the received rate is within three deviations of that
/// average ("close to convergence"). When the received rate rises above the band the path has
/// changed: the average is forgotten and the climb is multiplicative again, 8% per second.
///
/// # The bound
///
/// The estimate is verified by over-using the path, so it must not drift away from what is
/// actually sent: it is not increased past 1.5 times the received rate. Without the bound a
/// sender that has less to send than the estimate allows (a muted source, a static screen) lets
/// the estimate climb to the configured maximum, and overshoots by that much when it has
/// something to send again. An estimate that is above the bound because the sender now sends
/// less than it did is held, not lowered ([`ReceivedRateBound`]): only over-use lowers it.
#[derive(Debug, Clone)]
pub struct RateController {
    state: RateControlState,
    /// Current target, in bits per second.
    target: f64,
    min: f64,
    max: f64,
    decrease_factor: f64,
    increase_factor: f64,
    round_trip_time: Duration,
    /// What a probe measured the path to deliver, while that is news the received rate has
    /// not caught up with.
    measured_rate: Option<f64>,
    convergence: Convergence,
    last_change: Option<Instant>,
    /// Whether a decrease is taken at most once per round trip (see
    /// [`with_one_decrease_per_round_trip`](Self::with_one_decrease_per_round_trip)).
    one_decrease_per_round_trip: bool,
    /// When the target was last decreased.
    last_decrease: Option<Instant>,
    received_rate_bound: ReceivedRateBound,
}

impl RateController {
    /// A controller starting at `initial`, clamped to `min..=max`.
    ///
    /// **One clamp, from configuration** — see D3. Upstream clamps in two places with two different
    /// hard-coded ranges, and they disagree.
    pub fn new(initial: f64, min: f64, max: f64) -> Self {
        Self {
            state: RateControlState::default(),
            target: initial.clamp(min, max),
            min,
            max,
            decrease_factor: DEFAULT_DECREASE_FACTOR,
            increase_factor: DEFAULT_INCREASE_FACTOR,
            round_trip_time: DEFAULT_ROUND_TRIP_TIME,
            measured_rate: None,
            convergence: Convergence::new(),
            last_change: None,
            one_decrease_per_round_trip: false,
            last_decrease: None,
            received_rate_bound: ReceivedRateBound::default(),
        }
    }

    /// What the bound by the received rate does to an estimate above it: see
    /// [`ReceivedRateBound`].
    pub fn with_received_rate_bound(mut self, received_rate_bound: ReceivedRateBound) -> Self {
        self.received_rate_bound = received_rate_bound;
        self
    }

    /// Whether over-use lowers the target at most once per round trip, or on every update
    /// while it lasts (the default).
    ///
    /// draft-ietf-rmcat-gcc-02 section 5.5 stays in Decrease while over-use lasts and sets
    /// `A_hat = beta * R_hat` on each update: `false`, the default. The estimate then follows
    /// the received rate down as its measurement window empties of what arrived before the
    /// path changed, which is what matters when a path loses most of its capacity at once
    /// (`tests/capacity_cap_video_rtc2rtc.rs`: a 300 kbit/s cap under a sender at 1 Mbit/s
    /// freezes the video 0.56 to 1.26 s and leaves the oldest picture 1.68 to 2.48 s old;
    /// with one decrease per round trip 0.85 to 1.36 s and 2.33 to 2.61 s).
    ///
    /// `true` is libwebrtc's form (`AimdRateControl::TimeToReduceFurther`): a further cut
    /// waits one round trip (held within 10 to 200 ms) unless the received rate has fallen
    /// below half the target. Two flows sharing a bottleneck then keep a shorter queue
    /// (`rtci-interceptor/tests/rfc8836_multi_flow.rs`: mean 2.8 ms and 95th percentile 10.8 ms
    /// of queueing delay, against 18.5 ms and 93 ms with the draft's form; the shares are
    /// 0.48 / 0.50 and 0.49 / 0.49).
    pub fn with_one_decrease_per_round_trip(mut self, enabled: bool) -> Self {
        self.one_decrease_per_round_trip = enabled;
        self
    }

    /// How hard to back off, as a fraction of the received rate.
    pub fn with_decrease_factor(mut self, decrease_factor: f64) -> Self {
        self.decrease_factor = decrease_factor;
        self
    }

    /// The current target, in bits per second.
    pub fn target(&self) -> f64 {
        self.target
    }

    /// The current state.
    pub fn state(&self) -> RateControlState {
        self.state
    }

    /// The round trip time the additive increase is scaled by (`response_time = 100 ms + rtt`).
    pub fn set_round_trip_time(&mut self, round_trip_time: Duration) {
        self.round_trip_time = round_trip_time;
    }

    /// Change the range the target is held in, and bring the target into it.
    pub fn set_bounds(&mut self, min: f64, max: f64) {
        self.min = min;
        self.max = max.max(min);
        self.target = self.target.clamp(self.min, self.max);
    }

    /// Replace the target, as when the path changed and the old estimate describes nothing.
    pub fn set_target(&mut self, target: f64) {
        self.target = target.clamp(self.min, self.max);
    }

    /// A rate the path was measured to deliver apart from the running received rate (a probe
    /// cluster), or `None` to forget it. While set, the estimate may be as high as this
    /// measurement even where one and a half times the received rate (the bound of section
    /// 5.5) is less: the received rate lags a sender that has only just been told it may
    /// send more, and would pull the estimate straight back to where it was. Over-use lowers
    /// it to where the estimate backs off to.
    pub fn set_measured_rate(&mut self, measured: Option<f64>) {
        self.measured_rate = measured;
    }

    /// Forget where the path's capacity was thought to be: the next climb is multiplicative.
    pub fn reset_convergence(&mut self) {
        self.convergence.reset();
    }

    /// The band of received rates within which the controller considers itself close to
    /// convergence, in bits per second, once a decrease has measured one.
    pub fn convergence_band(&self) -> Option<(f64, f64)> {
        self.convergence.band()
    }

    /// Advance the state with a usage signal and move the target accordingly.
    ///
    /// `received` is what the remote is actually getting (R_hat), from
    /// [`RateCalculator`](super::rate_calc::RateCalculator). It is `None` until enough has
    /// arrived to measure, and while it is unknown a decrease holds and an increase is unbounded
    /// by it — there is no meaningful figure to act on.
    pub fn update(&mut self, now: Instant, usage: Usage, received: Option<f64>) -> f64 {
        self.state = self.state.next(usage);

        // Both increases are scaled by the time since the last update, so how often this is
        // called does not change how fast the target climbs.
        let elapsed = self
            .last_change
            .map_or(DEFAULT_RATE_CONTROL_INTERVAL, |last| {
                now.saturating_duration_since(last)
            });

        match self.state {
            RateControlState::Hold => {}

            RateControlState::Decrease => {
                // Back off from what is being *received*, not from the current target. If the
                // path is delivering less than the target, the target is the wrong thing to
                // scale.
                let Some(received) = received else {
                    return self.target;
                };
                if self.one_decrease_per_round_trip
                    && let Some(last) = self.last_decrease
                    && now.saturating_duration_since(last)
                        < self
                            .round_trip_time
                            .clamp(Duration::from_millis(10), Duration::from_millis(200))
                    && received >= 0.5 * self.target
                {
                    return self.target;
                }
                self.last_decrease = Some(now);
                // A rate far below the average means the path lost capacity: the old average
                // describes a path that is gone.
                if let Some((low, _)) = self.convergence.band()
                    && received < low
                {
                    self.convergence.reset();
                }
                self.convergence.on_decrease(received);
                // What the path delivers is the received rate (`A_hat(i) = beta * R_hat(i)`,
                // section 5.5), or what a probe measured when the sender has less to send
                // than that: backing off from the received rate of an application-limited
                // sender would cut the estimate to a fraction of what it sends, and the bound
                // below would then cut it again on every update (1.5 times a fifth of the
                // target is less than the target). The measurement backs off with the
                // estimate: over-use says the path carries less than the probe saw, so the
                // estimate never climbs back above where it backed off to until a new probe
                // measures the path, and over-use that lasts with a sender that still sends
                // less than the measurement brings both down by the decrease factor each
                // time.
                //
                // A sender received at the measurement or above it is not application
                // limited: the received rate is the path's, and the estimate follows it as
                // the draft has it, however many updates the over-use lasts. (Taking the
                // measurement there, which is the estimate itself from the second update on,
                // multiplied the estimate by the decrease factor on every feedback report:
                // 268 to 100 kbit/s in six reports, 0.3 s, while 213 to 252 kbit/s arrived.)
                // The measurement only ever lowers the estimate here: over-use does not raise
                // an estimate that rests on a probe.
                let decreased = match self.measured_rate {
                    Some(measured) if received < measured => {
                        measured.min(self.target) * self.decrease_factor
                    }
                    Some(measured) => measured.max(received).min(self.target) * self.decrease_factor,
                    None => received * self.decrease_factor,
                };
                self.target = decreased.clamp(self.min, self.max);
                if self.measured_rate.is_some() {
                    self.measured_rate = Some(self.target);
                }
                self.last_change = Some(now);
            }

            RateControlState::Increase => {
                // The received rate rising above the band means the congestion level changed:
                // forget the average and go back to a multiplicative increase.
                if let (Some(received), Some((_, high))) = (received, self.convergence.band())
                    && received > high
                {
                    self.convergence.reset();
                }

                // A_hat(i) < 1.5 * R_hat(i): the estimate does not run away from what is
                // sent. One and a half times what is received, or what a probe measured the
                // path to deliver when that is more: a measurement is a bound in itself,
                // with no margin on top, so an estimate that rests on a probe never passes
                // what the probe saw. An estimate already at or above the bound stays where
                // it is.
                let bound = self.bound(received);
                if self.received_rate_bound == ReceivedRateBound::LimitsIncrease
                    && bound.is_some_and(|bound| self.target >= bound)
                {
                    self.last_change = Some(now);
                    return self.target;
                }

                let increased = if self.convergence.band().is_some() {
                    // Close to convergence: about half a packet per response time.
                    let response_time = Duration::from_millis(100) + self.round_trip_time;
                    let alpha =
                        0.5 * (elapsed.as_secs_f64() / response_time.as_secs_f64()).min(1.0);
                    self.target + (alpha * self.expected_packet_size_bits()).max(1_000.0)
                } else {
                    // `increase_factor` is per second; scale it to the time actually elapsed.
                    let eta = self.increase_factor.powf(elapsed.as_secs_f64().min(1.0));
                    (self.target * eta).max(self.target + 1_000.0)
                };
                self.target = increased
                    .min(bound.unwrap_or(f64::INFINITY))
                    .clamp(self.min, self.max);
                self.last_change = Some(now);
            }
        }

        // The inequality as a clamp: in every state.
        if self.received_rate_bound == ReceivedRateBound::Clamps
            && let Some(bound) = self.bound(received)
        {
            self.target = self.target.min(bound).clamp(self.min, self.max);
        }

        self.target
    }

    /// The bound of section 5.5 for a received rate: one and a half times it, or what a probe
    /// measured when that is more. `None` while the received rate is unknown.
    fn bound(&self, received: Option<f64>) -> Option<f64> {
        received.map(|received| {
            (MAX_ESTIMATE_TO_RECEIVED_RATIO * received).max(self.measured_rate.unwrap_or(0.0))
        })
    }

    /// The size of a packet of a 30 frames-per-second stream at the current target, in bits
    /// (section 5.5: `bits_per_frame = A_hat / 30`, split into packets of at most 1200 bytes).
    fn expected_packet_size_bits(&self) -> f64 {
        let bits_per_frame = self.target / 30.0;
        let packets_per_frame = (bits_per_frame / (1_200.0 * 8.0)).ceil().max(1.0);
        bits_per_frame / packets_per_frame
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MIN: f64 = 100_000.0;
    const MAX: f64 = 10_000_000.0;

    fn controller() -> RateController {
        RateController::new(1_000_000.0, MIN, MAX)
    }

    /// Overuse backs off to a fraction of what is being **received**, not of the target. On a path
    /// delivering far less than the sender is aiming for, those differ by the whole overshoot.
    #[test]
    fn overuse_backs_off_from_the_received_rate() {
        let epoch = Instant::now();
        let mut controller = RateController::new(2_000_000.0, MIN, MAX);

        let target = controller.update(epoch, Usage::Over, Some(600_000.0));

        assert!(
            (target - 510_000.0).abs() < 1.0,
            "expected 0.85 × 600 kb/s, got {target}"
        );
    }

    /// A quiet path climbs.
    #[test]
    fn a_quiet_path_increases() {
        let epoch = Instant::now();
        let mut controller = controller();

        let mut at = epoch;
        let before = controller.target();
        for _ in 0..10 {
            at += DEFAULT_RATE_CONTROL_INTERVAL;
            controller.update(at, Usage::Normal, Some(1_000_000.0));
        }

        assert!(
            controller.target() > before,
            "a healthy path should be probed for more: {before} → {}",
            controller.target()
        );
    }

    /// And climbs **carefully** once near a ceiling it has already hit, rather than overshooting
    /// straight back into congestion.
    #[test]
    fn it_climbs_carefully_near_a_known_ceiling() {
        let epoch = Instant::now();
        let mut controller = controller();

        // Establish a ceiling.
        let mut at = epoch;
        controller.update(at, Usage::Over, Some(1_000_000.0));
        let after_backoff = controller.target();

        // Climb back towards it.
        let mut steps = 0;
        while controller.target() < after_backoff * 1.5 && steps < 200 {
            at += DEFAULT_RATE_CONTROL_INTERVAL;
            controller.update(at, Usage::Normal, Some(1_000_000.0));
            steps += 1;
        }

        assert!(
            steps > 5,
            "approaching a known ceiling should take several steps, took {steps}"
        );
    }

    /// Without a received rate the controller holds. Guessing here is how an estimate collapses on
    /// a feedback gap.
    #[test]
    fn it_holds_when_the_received_rate_is_unknown() {
        let epoch = Instant::now();
        let mut controller = controller();
        let before = controller.target();

        let target = controller.update(epoch, Usage::Over, None);

        assert_eq!(before, target, "no rate to back off from means no change");
    }

    /// One clamp, from configuration (D3). Upstream clamps twice with two different hard-coded
    /// ranges that disagree.
    #[test]
    fn the_target_stays_within_configured_bounds() {
        let epoch = Instant::now();
        let mut controller = RateController::new(MIN, MIN, 500_000.0);

        let mut at = epoch;
        for _ in 0..500 {
            at += DEFAULT_RATE_CONTROL_INTERVAL;
            controller.update(at, Usage::Normal, Some(10_000_000.0));
        }
        assert!(
            controller.target() <= 500_000.0,
            "ceiling breached: {}",
            controller.target()
        );

        for _ in 0..50 {
            at += DEFAULT_RATE_CONTROL_INTERVAL;
            controller.update(at, Usage::Over, Some(1.0));
        }
        assert!(
            controller.target() >= MIN,
            "floor breached: {}",
            controller.target()
        );
    }

    /// A decrease is immediate, and an increase is proportional to the time since the last
    /// update (section 5.5: eta = 1.08^min(dt, 1 s)), so how often the controller runs does not
    /// change how fast it climbs.
    #[test]
    fn an_increase_scales_with_elapsed_time_and_a_decrease_is_immediate() {
        let epoch = Instant::now();
        let mut controller = controller();

        controller.update(epoch, Usage::Normal, Some(1_000_000.0));
        let after_first = controller.target();
        controller.update(
            epoch + Duration::from_millis(500),
            Usage::Normal,
            Some(1_000_000.0),
        );
        let expected = after_first * 1.08f64.powf(0.5);
        assert!(
            (controller.target() - expected).abs() < 1.0,
            "half a second is 1.08^0.5: expected {expected}, got {}",
            controller.target()
        );

        let before_backoff = controller.target();
        controller.update(
            epoch + Duration::from_millis(501),
            Usage::Over,
            Some(500_000.0),
        );
        assert!(
            (controller.target() - 425_000.0).abs() < 1.0,
            "a decrease is not delayed: {before_backoff} to {}",
            controller.target()
        );
    }

    /// Section 5.5: A_hat(i) < 1.5 * R_hat(i). A sender with less to send than the estimate
    /// allows must not let the estimate climb to the maximum (draft-ietf-rmcat-gcc.md bug G1).
    #[test]
    fn the_estimate_stays_within_one_and_a_half_times_the_received_rate() {
        let epoch = Instant::now();
        let mut controller = RateController::new(300_000.0, MIN, MAX);

        let mut at = epoch;
        for _ in 0..600 {
            at += Duration::from_millis(100);
            controller.update(at, Usage::Normal, Some(200_000.0));
        }

        assert!(
            (controller.target() - 300_000.0).abs() < 1.0,
            "1.5 x 200 kbit/s, got {}",
            controller.target()
        );
    }

    /// Section 5.5: the bound is for a sender that "is unable to produce a bit stream with the
    /// bitrate the congestion controller is asking for"; the estimate is lowered "As soon as
    /// over-use has been detected" and for nothing else. An estimate of 1 Mbit/s whose sender
    /// goes down to its audio (76 kbit/s received, no over-use) is held for as long as that
    /// lasts, is not increased meanwhile, and climbs again from where it was held once the
    /// sender sends more.
    #[test]
    fn an_estimate_above_the_bound_is_held_and_not_lowered() {
        let epoch = Instant::now();
        let mut controller = RateController::new(1_000_000.0, MIN, MAX);

        let mut at = epoch;
        for _ in 0..600 {
            at += Duration::from_millis(100);
            let target = controller.update(at, Usage::Normal, Some(76_000.0));
            assert_eq!(1_000_000.0, target, "held, neither lowered nor increased");
        }

        // The video is back at the held estimate: the climb goes on from there, at 8% a
        // second and not by the whole minute at once.
        at += Duration::from_millis(100);
        let target = controller.update(at, Usage::Normal, Some(900_000.0));
        assert!(
            target > 1_000_000.0 && target < 1_010_000.0,
            "one step of 100 ms at 8% a second from the held estimate, got {target}"
        );
    }

    /// Held is not frozen: over-use while the sender sends less than the estimate lowers it
    /// as section 5.5 has it, to beta times the received rate.
    #[test]
    fn over_use_lowers_an_estimate_that_was_held_above_the_bound() {
        let epoch = Instant::now();
        let mut controller = RateController::new(1_000_000.0, MIN, MAX);
        let mut at = epoch;
        for _ in 0..10 {
            at += Duration::from_millis(100);
            controller.update(at, Usage::Normal, Some(400_000.0));
        }
        assert_eq!(1_000_000.0, controller.target());

        at += Duration::from_millis(100);
        let target = controller.update(at, Usage::Over, Some(400_000.0));
        assert!(
            (target - 340_000.0).abs() < 1.0,
            "0.85 x 400 kbit/s, got {target}"
        );
    }

    /// The inequality read as a clamp ([`ReceivedRateBound::Clamps`]): the same estimate is
    /// brought down to one and a half times what is received, with usage normal.
    #[test]
    fn the_bound_as_a_clamp_lowers_an_estimate_to_one_and_a_half_times_the_received_rate() {
        let epoch = Instant::now();
        let mut controller = RateController::new(1_000_000.0, MIN, MAX)
            .with_received_rate_bound(ReceivedRateBound::Clamps);

        let target = controller.update(
            epoch + Duration::from_millis(100),
            Usage::Normal,
            Some(76_000.0),
        );

        assert!(
            (target - 114_000.0).abs() < 1.0,
            "1.5 x 76 kbit/s, got {target}"
        );

        // In every state: under-use holds the estimate (section 5.5), and the clamp still
        // brings it to the bound.
        let mut controller = RateController::new(1_000_000.0, MIN, MAX)
            .with_received_rate_bound(ReceivedRateBound::Clamps);
        let target = controller.update(
            epoch + Duration::from_millis(100),
            Usage::Under,
            Some(76_000.0),
        );
        assert_eq!(RateControlState::Hold, controller.state());
        assert!(
            (target - 114_000.0).abs() < 1.0,
            "1.5 x 76 kbit/s held, got {target}"
        );
    }

    /// Section 5.5: close to convergence the increase is additive,
    /// `A_hat += max(1000, alpha * expected_packet_size_bits)` with
    /// `alpha = 0.5 * min(dt / (100 ms + rtt), 1)`.
    #[test]
    fn the_additive_increase_is_half_a_packet_per_response_time() {
        let epoch = Instant::now();
        let mut controller = RateController::new(2_000_000.0, MIN, MAX);
        controller.set_round_trip_time(Duration::from_millis(100));

        // A decrease at 1 Mbit/s measures the convergence point; the target is 850 kbit/s.
        controller.update(epoch, Usage::Over, Some(1_000_000.0));
        assert!((controller.target() - 850_000.0).abs() < 1.0);
        // Decrease, then Hold for one normal reading.
        controller.update(
            epoch + Duration::from_millis(100),
            Usage::Normal,
            Some(1_000_000.0),
        );
        assert_eq!(RateControlState::Hold, controller.state());
        assert!((controller.target() - 850_000.0).abs() < 1.0);

        // 100 ms after the last change with a 200 ms response time: alpha = 0.25. At 850 kbit/s
        // a frame is 28 333 bits in three packets of 9 444 bits.
        controller.update(
            epoch + Duration::from_millis(100),
            Usage::Normal,
            Some(1_000_000.0),
        );
        assert_eq!(RateControlState::Increase, controller.state());
        let expected = 850_000.0 + 0.25 * (850_000.0 / 30.0 / 3.0);
        assert!(
            (controller.target() - expected).abs() < 1.0,
            "expected {expected}, got {}",
            controller.target()
        );
    }

    /// Section 5.5: a received rate above three deviations of the average seen at decrease means
    /// the congestion level changed: the average is reset and the increase is multiplicative
    /// again (draft-ietf-rmcat-gcc.md bug G3: the controller stayed additive for ever).
    #[test]
    fn a_received_rate_above_the_convergence_band_returns_to_multiplicative_increase() {
        let epoch = Instant::now();
        let mut controller = RateController::new(2_000_000.0, MIN, 100_000_000.0);

        controller.update(epoch, Usage::Over, Some(1_000_000.0));
        let (low, high) = controller
            .convergence_band()
            .expect("measured at the decrease");
        assert!(low < 1_000_000.0 && high > 1_000_000.0);
        assert!(
            high < 1_100_000.0,
            "three deviations at 1 Mbit/s is about 60 kbit/s"
        );

        // The path widens and the sender follows its target: the received rate is the target.
        let mut at = epoch;
        let mut received = controller.target();
        while controller.convergence_band().is_some() {
            at += Duration::from_millis(100);
            received = controller.update(at, Usage::Normal, Some(received));
            assert!(
                at < epoch + Duration::from_secs(60),
                "the band was never left: target {}",
                controller.target()
            );
        }

        // From here one second of quiet is 8%.
        let before = controller.target();
        for _ in 0..10 {
            at += Duration::from_millis(100);
            received = controller.update(at, Usage::Normal, Some(received));
        }
        assert!(
            (controller.target() / before - 1.08).abs() < 0.001,
            "expected 8% in a second, got {}",
            controller.target() / before
        );
    }

    /// A decrease far below the average seen so far means the path lost capacity: the average
    /// restarts from the new rate.
    #[test]
    fn a_decrease_far_below_the_band_restarts_the_average() {
        let epoch = Instant::now();
        let mut controller = RateController::new(2_000_000.0, MIN, MAX);

        controller.update(epoch, Usage::Over, Some(1_000_000.0));
        controller.update(
            epoch + Duration::from_millis(100),
            Usage::Over,
            Some(300_000.0),
        );

        let (low, high) = controller.convergence_band().expect("still measured");
        assert!(
            low < 300_000.0 && high > 300_000.0 && high < 400_000.0,
            "the band is around 300 kbit/s, not an average with 1 Mbit/s: {low}..{high}"
        );
    }

    /// An application-limited sender (a fifth of the target) over-uses the path with a probe
    /// cluster: the estimate backs off from the probe's measurement, not from what the
    /// application sends, and the updates that follow keep it there instead of cutting it to
    /// one and a half times the received rate again and again (which spiralled the target
    /// down to the minimum).
    #[test]
    fn over_use_after_a_probe_backs_off_from_the_measurement_and_stays() {
        let epoch = Instant::now();
        let mut controller = RateController::new(2_000_000.0, MIN, MAX);
        controller.set_measured_rate(Some(2_000_000.0));
        let received = Some(400_000.0);

        let mut at = epoch;
        let backed_off = controller.update(at, Usage::Over, received);
        assert!(
            (backed_off - 1_700_000.0).abs() < 1.0,
            "0.85 × the measured 2 Mbit/s, got {backed_off}"
        );
        for usage in [Usage::Normal, Usage::Normal, Usage::Normal, Usage::Under] {
            at += DEFAULT_RATE_CONTROL_INTERVAL;
            let target = controller.update(at, usage, received);
            assert!(
                (target - backed_off).abs() < 1.0,
                "the estimate rests where it backed off to: {target} after {usage:?}"
            );
        }

        // Over-use that lasts brings it down by the decrease factor each time.
        at += DEFAULT_RATE_CONTROL_INTERVAL;
        let again = controller.update(at, Usage::Over, received);
        assert!((again - 0.85 * backed_off).abs() < 1.0, "{again}");
    }

    /// draft-ietf-rmcat-gcc-02 section 5.5, `A_hat(i) = beta * R_hat(i)`, while a probe's
    /// measurement is held and the sender is received at that measurement or above it (it is
    /// not application limited): over-use that lasts through several feedback reports keeps
    /// the estimate at 0.85 times the received rate. It was multiplied by 0.85 on every
    /// report instead (the measurement, which is the estimate itself after the first cut,
    /// was taken for what the path delivers): 268 kbit/s fell to the 100 kbit/s floor in six
    /// reports while 213 to 252 kbit/s arrived (`tests/capacity_cap_video_rtc2rtc.rs`'s
    /// path, trace of run 45489776509).
    #[test]
    fn lasting_over_use_with_a_probe_measurement_follows_the_received_rate() {
        let epoch = Instant::now();
        let mut controller = RateController::new(268_000.0, MIN, MAX);
        controller.set_measured_rate(Some(238_000.0));
        let received = [
            252_000.0, 242_000.0, 242_000.0, 252_000.0, 232_000.0, 213_000.0,
        ];
        let mut targets = Vec::new();
        for (index, received) in received.into_iter().enumerate() {
            let at = epoch + Duration::from_millis(60 * index as u64);
            targets.push(controller.update(at, Usage::Over, Some(received)).round());
        }
        // 0.85 times what arrived, never raised by a later report that shows more.
        assert_eq!(
            vec![
                214_200.0, 205_700.0, 205_700.0, 205_700.0, 197_200.0, 181_050.0
            ],
            targets
        );
    }

    /// Over-use that lasts through several updates, answered by the first cut: with the
    /// default, a second cut waits a round trip (here 100 ms, so the update 50 ms later holds
    /// and the one 100 ms later cuts again), as libwebrtc's `TimeToReduceFurther` does; with
    /// the draft as written every update cuts.
    #[test]
    fn lasting_over_use_cuts_once_per_round_trip() {
        let epoch = Instant::now();
        let run = |once: bool| {
            let mut controller =
                RateController::new(1_000_000.0, MIN, MAX).with_one_decrease_per_round_trip(once);
            controller.set_round_trip_time(Duration::from_millis(100));
            [0u64, 50, 100].map(|ms| {
                controller.update(
                    epoch + Duration::from_millis(ms),
                    Usage::Over,
                    Some(900_000.0),
                )
            })
        };
        assert_eq!([765_000.0, 765_000.0, 765_000.0], run(true).map(f64::round));
        assert_eq!(
            [765_000.0, 765_000.0, 765_000.0],
            run(false).map(f64::round)
        );
        // The cut is from the received rate: repeated, it compounds only as the received
        // rate follows. With the received rate falling with the target, the draft cuts again
        // on every update.
        let follow = |once: bool| {
            let mut controller =
                RateController::new(1_000_000.0, MIN, MAX).with_one_decrease_per_round_trip(once);
            controller.set_round_trip_time(Duration::from_millis(100));
            let mut received = 900_000.0;
            let mut targets = Vec::new();
            for ms in [0u64, 50, 100] {
                let target = controller.update(
                    epoch + Duration::from_millis(ms),
                    Usage::Over,
                    Some(received),
                );
                targets.push(target.round());
                received = target;
            }
            targets
        };
        assert_eq!(vec![765_000.0, 765_000.0, 650_250.0], follow(true));
        assert_eq!(vec![765_000.0, 650_250.0, 552_713.0], follow(false));
    }

    /// The received rate falling below half the target is news: the cut is not held back.
    #[test]
    fn a_collapse_of_the_received_rate_cuts_at_once() {
        let epoch = Instant::now();
        let mut controller = RateController::new(1_000_000.0, MIN, MAX);
        controller.set_round_trip_time(Duration::from_millis(200));
        controller.update(epoch, Usage::Over, Some(900_000.0));
        let target = controller.update(
            epoch + Duration::from_millis(20),
            Usage::Over,
            Some(300_000.0),
        );
        assert_eq!(255_000.0, target.round());
    }
}
