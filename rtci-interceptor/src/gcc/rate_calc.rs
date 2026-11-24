//! What the receiver is actually getting, over a sliding window.

use std::collections::VecDeque;
use std::time::{Duration, Instant};

/// How far back the received rate is measured over.
///
/// Long enough that one late group does not halve the reading, short enough to follow a real
/// change within a round trip or two.
pub const DEFAULT_WINDOW: Duration = Duration::from_millis(500);

/// The rate the far end is receiving, from acknowledged bytes over a sliding window.
///
/// # Why the controller needs this and not the target
///
/// On a decrease, AIMD backs off to a fraction of what the path is *delivering*, not of what the
/// sender was *aiming for*. Those differ exactly when it matters: a sender aiming at 2 Mb/s over a
/// path carrying 600 kb/s must drop to about 500 kb/s, not to 1.7 Mb/s. Backing off from the target
/// would take several rounds to reach the same place, queueing the whole way down.
#[derive(Debug, Clone)]
pub struct RateCalculator {
    window: Duration,
    /// Acknowledged packets in the window: when they arrived here, and how big they were.
    samples: VecDeque<(Instant, usize)>,
    bytes_in_window: usize,
}

impl Default for RateCalculator {
    fn default() -> Self {
        Self::new(DEFAULT_WINDOW)
    }
}

impl RateCalculator {
    /// A calculator over `window`.
    pub fn new(window: Duration) -> Self {
        Self {
            window,
            samples: VecDeque::new(),
            bytes_in_window: 0,
        }
    }

    /// Record `size` bytes acknowledged at `now`.
    pub fn add(&mut self, now: Instant, size: usize) {
        self.samples.push_back((now, size));
        self.bytes_in_window += size;
        self.expire(now);
    }

    /// The received rate in bits per second, or `None` when the window holds too little to say.
    ///
    /// `None` rather than zero: a controller that reads an empty window as "the path is delivering
    /// nothing" would back off to its floor on the first feedback gap.
    pub fn rate_bits_per_second(&mut self, now: Instant) -> Option<f64> {
        self.expire(now);

        // One sample measures nothing — a rate needs a span.
        if self.samples.len() < 2 {
            return None;
        }

        let oldest = self.samples.front()?.0;
        let span = now.saturating_duration_since(oldest);
        if span.is_zero() {
            return None;
        }

        Some((self.bytes_in_window * 8) as f64 / span.as_secs_f64())
    }

    fn expire(&mut self, now: Instant) {
        let cutoff = now.checked_sub(self.window).unwrap_or(now);
        while let Some((at, size)) = self.samples.front().copied() {
            if at >= cutoff {
                break;
            }
            self.samples.pop_front();
            self.bytes_in_window -= size;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A steady stream reads its own rate back.
    #[test]
    fn it_measures_a_steady_stream() {
        let epoch = Instant::now();
        let mut calculator = RateCalculator::default();

        // 1500 bytes every 10 ms = 1.2 Mb/s.
        for step in 0..50u64 {
            calculator.add(epoch + Duration::from_millis(step * 10), 1500);
        }

        let rate = calculator
            .rate_bits_per_second(epoch + Duration::from_millis(490))
            .expect("a full window has a rate");
        assert!(
            (rate - 1_200_000.0).abs() < 100_000.0,
            "expected about 1.2 Mb/s, got {rate}"
        );
    }

    /// Too little to go on reads `None`, not zero — a controller must not mistake a feedback gap
    /// for a dead path and back off to its floor.
    #[test]
    fn an_empty_window_has_no_rate() {
        let epoch = Instant::now();
        let mut calculator = RateCalculator::default();

        assert_eq!(None, calculator.rate_bits_per_second(epoch));
        calculator.add(epoch, 1500);
        assert_eq!(
            None,
            calculator.rate_bits_per_second(epoch),
            "one sample is not a rate"
        );
    }

    /// Samples fall out of the window, so the reading follows a change rather than averaging over
    /// all history.
    #[test]
    fn old_samples_expire() {
        let epoch = Instant::now();
        let mut calculator = RateCalculator::new(Duration::from_millis(200));

        for step in 0..20u64 {
            calculator.add(epoch + Duration::from_millis(step * 10), 1500);
        }
        let busy = calculator
            .rate_bits_per_second(epoch + Duration::from_millis(190))
            .expect("rate");

        // Nothing for a while, then two packets: the busy period must have aged out.
        calculator.add(epoch + Duration::from_millis(1_000), 1500);
        calculator.add(epoch + Duration::from_millis(1_100), 1500);
        let quiet = calculator
            .rate_bits_per_second(epoch + Duration::from_millis(1_100))
            .expect("rate");

        assert!(
            quiet < busy / 2.0,
            "the window should have forgotten the busy period: {busy} then {quiet}"
        );
    }

    /// Halving the offered rate halves the reading, which is the property the controller relies on
    /// when it backs off to a fraction of what is being delivered.
    #[test]
    fn it_follows_a_halved_rate() {
        let epoch = Instant::now();
        let mut fast = RateCalculator::default();
        let mut slow = RateCalculator::default();

        for step in 0..50u64 {
            fast.add(epoch + Duration::from_millis(step * 10), 1500);
        }
        for step in 0..25u64 {
            slow.add(epoch + Duration::from_millis(step * 20), 1500);
        }

        let at = epoch + Duration::from_millis(490);
        let fast_rate = fast.rate_bits_per_second(at).expect("rate");
        let slow_rate = slow.rate_bits_per_second(at).expect("rate");

        assert!(
            (fast_rate / slow_rate - 2.0).abs() < 0.2,
            "one should be twice the other: {fast_rate} vs {slow_rate}"
        );
    }
}

/// libwebrtc's acknowledged-bitrate estimator (`modules/congestion_controller/goog_cc/
/// bitrate_estimator.cc` at a222406d): the acknowledged octets are summed over windows of
/// 150 ms of arrival time (500 ms for the first sample), and each window's rate updates a
/// Bayesian estimate whose sample uncertainty is ten times the sample's distance from the
/// estimate, relative to it, and whose own variance grows by 5 (kbit/s)^2 per update:
/// "The bitrate estimate uncertainty is increased with each update to model that the bitrate
/// changes over time." draft-ietf-rmcat-gcc-02 section 5.5 measures R_hat over "a T seconds
/// window ... A window between 0.5 and 1 second is RECOMMENDED"; this one is shorter and
/// smoothed, so it follows a sudden drop of the path's rate sooner.
#[derive(Debug, Clone)]
pub struct AcknowledgedRateEstimator {
    sum: usize,
    current_window_ms: i64,
    prev_time_ms: Option<i64>,
    /// kbit/s; negative until the first window closed.
    estimate_kbps: f64,
    estimate_var: f64,
    /// The instant the arrival times are counted from.
    epoch: Option<Instant>,
}

impl Default for AcknowledgedRateEstimator {
    fn default() -> Self {
        Self {
            sum: 0,
            current_window_ms: 0,
            prev_time_ms: None,
            estimate_kbps: -10.0,
            estimate_var: 50.0,
            epoch: None,
        }
    }
}

/// libwebrtc's `kInitialRateWindowMs` and `kRateWindowMs`.
const INITIAL_RATE_WINDOW_MS: i64 = 500;
const RATE_WINDOW_MS: i64 = 150;
/// libwebrtc's `uncertainty_scale_`.
const UNCERTAINTY_SCALE: f64 = 10.0;

impl AcknowledgedRateEstimator {
    /// `size` octets arrived at `at` (on this endpoint's reading of the receiver's clock).
    pub fn add(&mut self, at: Instant, size: usize) {
        let epoch = *self.epoch.get_or_insert(at);
        let now_ms = at.saturating_duration_since(epoch).as_millis() as i64;
        let window = if self.estimate_kbps < 0.0 {
            INITIAL_RATE_WINDOW_MS
        } else {
            RATE_WINDOW_MS
        };
        let Some(sample) = self.update_window(now_ms, size, window) else {
            return;
        };
        if self.estimate_kbps < 0.0 {
            self.estimate_kbps = sample;
            return;
        }
        let uncertainty =
            UNCERTAINTY_SCALE * (self.estimate_kbps - sample).abs() / self.estimate_kbps.max(1e-9);
        let sample_var = uncertainty * uncertainty;
        let predicted_var = self.estimate_var + 5.0;
        self.estimate_kbps = (sample_var * self.estimate_kbps + predicted_var * sample)
            / (sample_var + predicted_var);
        self.estimate_kbps = self.estimate_kbps.max(0.0);
        self.estimate_var = sample_var * predicted_var / (sample_var + predicted_var);
    }

    /// The estimate, bits per second, once a window has closed.
    pub fn rate_bits_per_second(&self) -> Option<f64> {
        (self.estimate_kbps >= 0.0).then_some(self.estimate_kbps * 1000.0)
    }

    fn update_window(&mut self, now_ms: i64, size: usize, window_ms: i64) -> Option<f64> {
        if self.prev_time_ms.is_some_and(|prev| now_ms < prev) {
            self.prev_time_ms = None;
            self.sum = 0;
            self.current_window_ms = 0;
        }
        if let Some(prev) = self.prev_time_ms {
            self.current_window_ms += now_ms - prev;
            if now_ms - prev > window_ms {
                self.sum = 0;
                self.current_window_ms %= window_ms;
            }
        }
        self.prev_time_ms = Some(now_ms);
        let mut sample = None;
        if self.current_window_ms >= window_ms {
            sample = Some(8.0 * self.sum as f64 / window_ms as f64);
            self.current_window_ms -= window_ms;
            self.sum = 0;
        }
        self.sum += size;
        sample
    }
}
