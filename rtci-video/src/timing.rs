//! Playout timing: when each picture is decoded and rendered.
//!
//! A port of libwebrtc's model (a222406d):
//!
//! - [`JitterEstimator`]: `video/timing/jitter_estimator.cc` with its Kalman filter
//!   (`frame_delay_variation_kalman_filter.cc`): the frame delay variation explained by frame
//!   size, the rest as noise; the estimate is the size term for the largest frames plus
//!   `max(2.33 sigma - 30 ms, 1 ms)`, plus 10 ms of operating-system jitter, plus
//!   `min(0.9 RTT, 200 ms)` once three frames needed retransmission, scaled down below 10 fps.
//! - [`TimestampExtrapolator`]: `video/timing/timestamp_extrapolator.cc`, a recursive least
//!   squares fit of local arrival time to RTP time, with outlier rejection and a CUSUM delay
//!   change detector.
//! - [`Timing`]: `modules/video_coding/timing/timing.cc`: target delay
//!   `max(min_playout, jitter + decode + render)`, the current delay that rises when pictures
//!   are late, render time `local(rtp) + clamp(current, min_playout, max_playout)`, and the
//!   low-latency path (render at once) when the playout-delay extension says `min = 0, max <=
//!   500 ms`.

use std::collections::VecDeque;
use std::time::{Duration, Instant};

use crate::seq::Unwrapper;

fn ms(d: Duration) -> f64 {
    d.as_secs_f64() * 1000.0
}

fn signed_ms(a: Instant, b: Instant) -> f64 {
    if a >= b { ms(a - b) } else { -ms(b - a) }
}

fn add_ms(t: Instant, offset_ms: f64) -> Instant {
    if offset_ms >= 0.0 {
        t + Duration::from_secs_f64(offset_ms / 1000.0)
    } else {
        t.checked_sub(Duration::from_secs_f64(-offset_ms / 1000.0))
            .unwrap_or(t)
    }
}

/// The frame delay variation against frame size (libwebrtc
/// `FrameDelayVariationKalmanFilter`).
#[derive(Debug, Clone)]
struct KalmanFilter {
    estimate: [f64; 2],
    cov: [[f64; 2]; 2],
    process_noise: [f64; 2],
}

const MAX_BANDWIDTH: f64 = 0.000001;

impl Default for KalmanFilter {
    fn default() -> Self {
        Self {
            estimate: [1.0 / (512e3 / 8.0), 0.0],
            cov: [[1e-4, 0.0], [0.0, 1e2]],
            process_noise: [2.5e-10, 1e-10],
        }
    }
}

impl KalmanFilter {
    fn predict_and_update(&mut self, delay_ms: f64, size_delta: f64, max_size: f64, var: f64) {
        if max_size < 1.0 || var <= 0.0 {
            return;
        }
        self.cov[0][0] += self.process_noise[0];
        self.cov[1][1] += self.process_noise[1];
        let innovation = delay_ms - self.total(size_delta);
        let c = [
            self.cov[0][0] * size_delta + self.cov[0][1],
            self.cov[1][0] * size_delta + self.cov[1][1],
        ];
        let obs_noise =
            ((300.0 * (-size_delta.abs() / max_size).exp() + 1.0) * var.sqrt()).max(1.0);
        let innovation_var = size_delta * c[0] + c[1] + obs_noise;
        if innovation_var.abs() < 1e-9 {
            return;
        }
        let k = [c[0] / innovation_var, c[1] / innovation_var];
        self.estimate[0] += k[0] * innovation;
        self.estimate[1] += k[1] * innovation;
        if self.estimate[0] < MAX_BANDWIDTH {
            self.estimate[0] = MAX_BANDWIDTH;
        }
        let (t00, t01) = (self.cov[0][0], self.cov[0][1]);
        self.cov[0][0] = (1.0 - k[0] * size_delta) * t00 - k[0] * self.cov[1][0];
        self.cov[0][1] = (1.0 - k[0] * size_delta) * t01 - k[0] * self.cov[1][1];
        self.cov[1][0] = self.cov[1][0] * (1.0 - k[1]) - k[1] * size_delta * t00;
        self.cov[1][1] = self.cov[1][1] * (1.0 - k[1]) - k[1] * size_delta * t01;
    }

    fn size_based(&self, size_delta: f64) -> f64 {
        self.estimate[0] * size_delta
    }

    fn total(&self, size_delta: f64) -> f64 {
        self.size_based(size_delta) + self.estimate[1]
    }
}

const STARTUP_COUNT: usize = 30;
const FRAMES_UNTIL_SIZE_FILTERING: usize = 5;
const PHI: f64 = 0.97;
const PSI: f64 = 0.9999;
const STDDEV_DELAY_CLAMP: f64 = 3.5;
const STDDEV_DELAY_OUTLIER: f64 = 15.0;
const STDDEV_SIZE_OUTLIER: f64 = 3.0;
const CONGESTION_REJECTION: f64 = -0.25;
const ALPHA_COUNT_MAX: u32 = 400;
const NOISE_STDDEVS: f64 = 2.33;
const NOISE_STDDEV_OFFSET: f64 = 30.0;
const MIN_ESTIMATE_MS: f64 = 1.0;
const MAX_ESTIMATE_MS: f64 = 10_000.0;
const OS_JITTER_MS: f64 = 10.0;
const NACK_TIMEOUT: Duration = Duration::from_secs(60);
const NACK_LIMIT: u32 = 3;
const RTT_MULT: f64 = 0.9;
const RTT_MULT_ADD_CAP_MS: f64 = 200.0;
const MAX_FRAMERATE: f64 = 200.0;
const FPS_WINDOW: usize = 30;

/// The network jitter estimate (libwebrtc `JitterEstimator`).
#[derive(Debug, Clone)]
pub struct JitterEstimator {
    kalman: KalmanFilter,
    avg_size: f64,
    var_size: f64,
    max_size: f64,
    startup_size_sum: f64,
    startup_size_count: usize,
    prev_size: Option<f64>,
    avg_noise: f64,
    var_noise: f64,
    alpha_count: u32,
    filtered: f64,
    prev_estimate: Option<f64>,
    startup_count: usize,
    last_update: Option<Instant>,
    frame_periods: VecDeque<f64>,
    latest_nack: Option<Instant>,
    nack_count: u32,
    rtt_ms: f64,
}

impl Default for JitterEstimator {
    fn default() -> Self {
        Self {
            kalman: KalmanFilter::default(),
            avg_size: 500.0,
            var_size: 100.0,
            max_size: 500.0,
            startup_size_sum: 0.0,
            startup_size_count: 0,
            prev_size: None,
            avg_noise: 0.0,
            var_noise: 4.0,
            alpha_count: 1,
            filtered: 0.0,
            prev_estimate: None,
            startup_count: 0,
            last_update: None,
            frame_periods: VecDeque::new(),
            latest_nack: None,
            nack_count: 0,
            rtt_ms: 0.0,
        }
    }
}

impl JitterEstimator {
    /// Takes the delay variation of a picture against the one before it and its size.
    pub fn update(&mut self, now: Instant, delay_ms: f64, size_bytes: f64) {
        if size_bytes <= 0.0 {
            return;
        }
        let delta_bytes = size_bytes - self.prev_size.unwrap_or(0.0);
        if self.startup_size_count < FRAMES_UNTIL_SIZE_FILTERING {
            self.startup_size_sum += size_bytes;
            self.startup_size_count += 1;
        } else if self.startup_size_count == FRAMES_UNTIL_SIZE_FILTERING {
            self.avg_size = self.startup_size_sum / self.startup_size_count as f64;
            self.startup_size_count += 1;
        }
        let avg = PHI * self.avg_size + (1.0 - PHI) * size_bytes;
        let deviation = 2.0 * self.var_size.sqrt();
        if size_bytes < self.avg_size + deviation {
            self.avg_size = avg;
        }
        let d = size_bytes - avg;
        self.var_size = (PHI * self.var_size + (1.0 - PHI) * d * d).max(1.0);
        self.max_size = (PSI * self.max_size).max(size_bytes);
        if self.prev_size.is_none() {
            self.prev_size = Some(size_bytes);
            return;
        }
        self.prev_size = Some(size_bytes);

        let max_dev = (STDDEV_DELAY_CLAMP * self.var_noise.sqrt() + 0.5).floor();
        let delay_ms = delay_ms.clamp(-max_dev, max_dev);
        let deviation_ms = delay_ms - self.kalman.total(delta_bytes);
        let not_delay_outlier = deviation_ms.abs() < STDDEV_DELAY_OUTLIER * self.var_noise.sqrt();
        let size_outlier = size_bytes > self.avg_size + STDDEV_SIZE_OUTLIER * self.var_size.sqrt();
        if not_delay_outlier || size_outlier {
            let not_congested = delta_bytes > CONGESTION_REJECTION * self.max_size;
            if not_congested {
                self.estimate_random_jitter(now, deviation_ms);
                self.kalman.predict_and_update(
                    delay_ms,
                    delta_bytes,
                    self.max_size,
                    self.var_noise,
                );
            }
        } else {
            let n = if deviation_ms >= 0.0 {
                STDDEV_DELAY_OUTLIER
            } else {
                -STDDEV_DELAY_OUTLIER
            };
            let sample = n * self.var_noise.sqrt();
            self.estimate_random_jitter(now, sample);
        }
        if self.startup_count >= STARTUP_COUNT {
            self.filtered = self.calculate();
        } else {
            self.startup_count += 1;
        }
    }

    /// A picture needed a retransmission.
    pub fn frame_nacked(&mut self, now: Instant) {
        if self.nack_count < NACK_LIMIT {
            self.nack_count += 1;
        }
        self.latest_nack = Some(now);
    }

    /// The round-trip time.
    pub fn update_rtt(&mut self, rtt: Duration) {
        self.rtt_ms = ms(rtt);
    }

    fn frame_rate(&self) -> f64 {
        if self.frame_periods.is_empty() {
            return 0.0;
        }
        let mean = self.frame_periods.iter().sum::<f64>() / self.frame_periods.len() as f64;
        if mean <= 0.0 {
            0.0
        } else {
            (1000.0 / mean).min(MAX_FRAMERATE)
        }
    }

    fn estimate_random_jitter(&mut self, now: Instant, d: f64) {
        if let Some(last) = self.last_update {
            self.frame_periods
                .push_back(ms(now.saturating_duration_since(last)));
            if self.frame_periods.len() > FPS_WINDOW {
                self.frame_periods.pop_front();
            }
        }
        self.last_update = Some(now);
        let mut alpha = f64::from(self.alpha_count - 1) / f64::from(self.alpha_count);
        self.alpha_count = (self.alpha_count + 1).min(ALPHA_COUNT_MAX);
        let fps = self.frame_rate();
        if fps > 0.0 {
            let mut rate_scale = 30.0 / fps;
            if (self.alpha_count as usize) < STARTUP_COUNT {
                let a = f64::from(self.alpha_count);
                let s = STARTUP_COUNT as f64;
                rate_scale = (a * rate_scale + (s - a)) / s;
            }
            alpha = alpha.powf(rate_scale);
        }
        let avg = alpha * self.avg_noise + (1.0 - alpha) * d;
        let var =
            alpha * self.var_noise + (1.0 - alpha) * (d - self.avg_noise) * (d - self.avg_noise);
        self.avg_noise = avg;
        self.var_noise = var.max(1.0);
    }

    fn noise_threshold(&self) -> f64 {
        (NOISE_STDDEVS * self.var_noise.sqrt() - NOISE_STDDEV_OFFSET).max(1.0)
    }

    fn calculate(&mut self) -> f64 {
        let worst = self.max_size - self.avg_size;
        let mut ret = self.kalman.size_based(worst) + self.noise_threshold();
        if ret < MIN_ESTIMATE_MS {
            ret = self.prev_estimate.unwrap_or(MIN_ESTIMATE_MS);
        } else if ret > MAX_ESTIMATE_MS {
            ret = MAX_ESTIMATE_MS;
        }
        self.prev_estimate = Some(ret);
        ret
    }

    /// The jitter estimate.
    pub fn estimate(&mut self, now: Instant) -> Duration {
        let mut jitter = self.calculate() + OS_JITTER_MS;
        if self
            .latest_nack
            .is_none_or(|t| now.saturating_duration_since(t) > NACK_TIMEOUT)
        {
            self.nack_count = 0;
        }
        if self.filtered > jitter {
            jitter = self.filtered;
        }
        if self.nack_count >= NACK_LIMIT {
            jitter += (self.rtt_ms * RTT_MULT).min(RTT_MULT_ADD_CAP_MS);
        }
        let fps = self.frame_rate();
        if fps < 5.0 {
            if fps == 0.0 {
                return Duration::from_secs_f64(jitter.max(0.0) / 1000.0);
            }
            return Duration::ZERO;
        }
        if fps < 10.0 {
            jitter *= (fps - 5.0) / 5.0;
        }
        Duration::from_secs_f64(jitter.max(0.0) / 1000.0)
    }
}

/// The inter-frame delay variation: local time between two pictures minus their RTP time
/// (libwebrtc `InterFrameDelayVariationCalculator`).
#[derive(Debug, Clone)]
pub struct DelayVariation {
    unwrapper: Unwrapper,
    prev: Option<(Instant, i64)>,
}

impl Default for DelayVariation {
    fn default() -> Self {
        Self {
            unwrapper: Unwrapper::timestamp(),
            prev: None,
        }
    }
}

impl DelayVariation {
    /// The variation of the picture with RTP timestamp `rtp` received at `at`, in ms; `None`
    /// for a picture older than the last one.
    pub fn calculate(&mut self, rtp: u32, at: Instant) -> Option<f64> {
        let ts = self.unwrapper.unwrap(rtp);
        let Some((prev_at, prev_ts)) = self.prev else {
            self.prev = Some((at, ts));
            return Some(0.0);
        };
        if ts <= prev_ts {
            return None;
        }
        let variation = signed_ms(at, prev_at) - (ts - prev_ts) as f64 / 90.0;
        self.prev = Some((at, ts));
        Some(variation)
    }
}

const P11: f64 = 1e10;
const START_RESIDUAL_VARIANCE: f64 = 3000.0 * 3000.0;
const START_UP_FILTER_DELAY: u32 = 2;
const HARD_RESET_TIMEOUT: Duration = Duration::from_secs(10);
const HARD_RESET_JUMP: f64 = 900_000.0;
const OUTLIER_STARTUP_DELAY: u32 = 300;
const OUTLIER_MAX_CONSECUTIVE: u32 = 150;
const OUTLIER_FORGETTING: f64 = 0.999;
const OUTLIER_STDDEV: f64 = 2.0;
const ALARM_THRESHOLD: f64 = 60_000.0;
const ACC_DRIFT: f64 = 6600.0;
const ACC_MAX_ERROR: f64 = 7000.0;

/// The local time of an RTP timestamp (libwebrtc `TimestampExtrapolator`, default
/// configuration: outlier rejection at 2 standard deviations).
#[derive(Debug, Clone)]
pub struct TimestampExtrapolator {
    start: Instant,
    prev: Instant,
    first_ts: Option<i64>,
    prev_ts: Option<i64>,
    w: [f64; 2],
    p: [[f64; 2]; 2],
    unwrapper: Unwrapper,
    packet_count: u32,
    residual_mean: f64,
    residual_variance: f64,
    outliers: u32,
    acc_pos: f64,
    acc_neg: f64,
}

impl TimestampExtrapolator {
    /// An extrapolator starting at `start`.
    pub fn new(start: Instant) -> Self {
        let mut x = Self {
            start,
            prev: start,
            first_ts: None,
            prev_ts: None,
            w: [90.0, 0.0],
            p: [[1.0, 0.0], [0.0, P11]],
            unwrapper: Unwrapper::timestamp(),
            packet_count: 0,
            residual_mean: 0.0,
            residual_variance: START_RESIDUAL_VARIANCE,
            outliers: 0,
            acc_pos: 0.0,
            acc_neg: 0.0,
        };
        x.reset(start);
        x
    }

    /// Starts again.
    pub fn reset(&mut self, start: Instant) {
        *self = Self {
            start,
            prev: start,
            first_ts: None,
            prev_ts: None,
            w: [90.0, 0.0],
            p: [[1.0, 0.0], [0.0, P11]],
            unwrapper: Unwrapper::timestamp(),
            packet_count: 0,
            residual_mean: 0.0,
            residual_variance: START_RESIDUAL_VARIANCE,
            outliers: 0,
            acc_pos: 0.0,
            acc_neg: 0.0,
        };
    }

    /// A picture with RTP timestamp `rtp` completed at `now`.
    pub fn update(&mut self, now: Instant, rtp: u32) {
        if now.saturating_duration_since(self.prev) > HARD_RESET_TIMEOUT {
            self.reset(now);
        } else {
            self.prev = now;
        }
        let ts = self.unwrapper.unwrap(rtp);
        if let Some(prev_ts) = self.prev_ts {
            let expected = (signed_ms(now, self.prev).floor()) * self.w[0];
            let jump = (ts - prev_ts) as f64 - expected;
            if jump.abs() > HARD_RESET_JUMP {
                self.reset(now);
                self.unwrapper.unwrap(rtp);
            }
        }
        let t_ms = signed_ms(now, self.start).floor();
        let first = *self.first_ts.get_or_insert_with(|| {
            self.w[1] = -self.w[0] * t_ms;
            ts
        });
        let residual = (ts - first) as f64 - t_ms * self.w[0] - self.w[1];
        if self.outlier(residual) {
            self.outliers += 1;
            if self.outliers <= OUTLIER_MAX_CONSECUTIVE {
                return;
            }
            self.soft_reset();
        }
        self.outliers = 0;
        if self.delay_change(residual) && self.packet_count >= START_UP_FILTER_DELAY {
            self.soft_reset();
        }
        let mut k = [
            self.p[0][0] * t_ms + self.p[0][1],
            self.p[1][0] * t_ms + self.p[1][1],
        ];
        let tpt = 1.0 + t_ms * k[0] + k[1];
        k[0] /= tpt;
        k[1] /= tpt;
        self.w[0] += k[0] * residual;
        self.w[1] += k[1] * residual;
        let p00 = self.p[0][0] - (k[0] * t_ms * self.p[0][0] + k[0] * self.p[1][0]);
        let p01 = self.p[0][1] - (k[0] * t_ms * self.p[0][1] + k[0] * self.p[1][1]);
        self.p[1][0] -= k[1] * t_ms * self.p[0][0] + k[1] * self.p[1][0];
        self.p[1][1] -= k[1] * t_ms * self.p[0][1] + k[1] * self.p[1][1];
        self.p[0][0] = p00;
        self.p[0][1] = p01;
        self.prev_ts = Some(ts);
        if self.packet_count < 3000 {
            self.packet_count += 1;
        }
    }

    /// The local time of RTP timestamp `rtp`.
    pub fn local_time(&self, rtp: u32) -> Option<Instant> {
        let ts = self.unwrapper.peek(rtp);
        let first = self.first_ts?;
        if self.packet_count < START_UP_FILTER_DELAY {
            let prev_ts = self.prev_ts?;
            return Some(add_ms(self.prev, ((ts - prev_ts) as f64 / 90.0).trunc()));
        }
        if self.w[0] < 1e-3 {
            return Some(self.start);
        }
        let diff = ((ts - first) as f64 - self.w[1]) / self.w[0];
        Some(add_ms(self.start, (diff + 0.5).floor()))
    }

    fn soft_reset(&mut self) {
        self.p[1][1] = P11;
    }

    fn outlier(&mut self, residual: f64) -> bool {
        if self.packet_count >= OUTLIER_STARTUP_DELAY {
            let threshold = OUTLIER_STDDEV * self.residual_variance.sqrt();
            if (residual - self.residual_mean).abs() > threshold {
                return true;
            }
        }
        self.residual_mean =
            OUTLIER_FORGETTING * self.residual_mean + (1.0 - OUTLIER_FORGETTING) * residual;
        let dev = residual - self.residual_mean;
        self.residual_variance = (OUTLIER_FORGETTING * self.residual_variance
            + (1.0 - OUTLIER_FORGETTING) * dev * dev)
            .max(1.0);
        false
    }

    fn delay_change(&mut self, residual: f64) -> bool {
        let r = residual.clamp(-ACC_MAX_ERROR, ACC_MAX_ERROR);
        self.acc_pos = (self.acc_pos + r - ACC_DRIFT).max(0.0);
        self.acc_neg = (self.acc_neg + r + ACC_DRIFT).min(0.0);
        if self.acc_pos > ALARM_THRESHOLD || self.acc_neg < -ALARM_THRESHOLD {
            self.acc_pos = 0.0;
            self.acc_neg = 0.0;
            return true;
        }
        false
    }
}

/// The 95th percentile of the decode times of the last 10 s, the first 5 ignored (libwebrtc
/// `DecodeTimePercentileFilter`).
#[derive(Debug, Clone, Default)]
pub struct DecodeTimeFilter {
    ignored: u32,
    samples: VecDeque<(Instant, f64)>,
}

impl DecodeTimeFilter {
    /// Adds a decode time.
    pub fn add(&mut self, now: Instant, decode_ms: f64) {
        if self.ignored < 5 {
            self.ignored += 1;
            return;
        }
        self.samples.push_back((now, decode_ms.max(0.0)));
        while let Some((t, _)) = self.samples.front() {
            if now.saturating_duration_since(*t) > Duration::from_secs(10) {
                self.samples.pop_front();
            } else {
                break;
            }
        }
    }

    /// The 95th percentile, in ms.
    pub fn percentile_ms(&self) -> f64 {
        if self.samples.is_empty() {
            return 0.0;
        }
        let mut v: Vec<f64> = self.samples.iter().map(|(_, d)| *d).collect();
        v.sort_by(|a, b| a.total_cmp(b));
        let index = ((v.len() - 1) as f64 * 0.95) as usize;
        v[index]
    }
}

/// libwebrtc's render delay (`VCMTiming::VideoDelayTimings::kDefaultRenderDelay`).
pub const DEFAULT_RENDER_DELAY: Duration = Duration::from_millis(10);
/// A `max_playout_delay` at or below this, with `min_playout_delay` zero, renders at once
/// (libwebrtc `kLowLatencyStreamMaxPlayoutDelayThreshold`, `timing.cc:37-38`).
pub const LOW_LATENCY_MAX_PLAYOUT_DELAY: Duration = Duration::from_millis(500);
/// A render time or target delay further off than this resets the timing (libwebrtc
/// `kMaxVideoDelay`, `frame_helpers.cc:32`).
pub const MAX_VIDEO_DELAY: Duration = Duration::from_secs(10);

/// The delays a picture's render time is made of (libwebrtc `VCMTiming`).
#[derive(Debug, Clone)]
pub struct Timing {
    extrapolator: TimestampExtrapolator,
    jitter: JitterEstimator,
    delay_variation: DelayVariation,
    decode_times: DecodeTimeFilter,
    /// The network jitter delay (`minimum_delay`).
    pub minimum_delay: Duration,
    /// The decode time estimate.
    pub decode_time: Duration,
    /// The render delay.
    pub render_delay: Duration,
    /// The minimum playout delay: from the playout-delay extension, `jitterBufferTarget`
    /// and A/V synchronisation, the largest.
    pub min_playout_delay: Duration,
    /// The maximum playout delay (playout-delay extension).
    pub max_playout_delay: Duration,
    /// The current delay, smoothed towards the target.
    pub current_delay: Duration,
}

impl Timing {
    /// Timing starting at `now`.
    pub fn new(now: Instant) -> Self {
        Self {
            extrapolator: TimestampExtrapolator::new(now),
            jitter: JitterEstimator::default(),
            delay_variation: DelayVariation::default(),
            decode_times: DecodeTimeFilter::default(),
            minimum_delay: Duration::ZERO,
            decode_time: Duration::ZERO,
            render_delay: DEFAULT_RENDER_DELAY,
            min_playout_delay: Duration::ZERO,
            max_playout_delay: MAX_VIDEO_DELAY,
            current_delay: Duration::ZERO,
        }
    }

    /// Starts again from `now`, keeping the playout delay bounds.
    pub fn reset(&mut self, now: Instant) {
        let (min, max, render) = (
            self.min_playout_delay,
            self.max_playout_delay,
            self.render_delay,
        );
        *self = Self::new(now);
        self.min_playout_delay = min;
        self.max_playout_delay = max;
        self.render_delay = render;
    }

    /// The target delay: `max(min_playout, minimum + decode + render)`.
    pub fn target_delay(&self) -> Duration {
        self.min_playout_delay
            .max(self.minimum_delay + self.decode_time + self.render_delay)
    }

    /// The target minus decode and render time (W3C `jitterBufferTargetDelay` per picture).
    pub fn stats_target_delay(&self) -> Duration {
        self.target_delay()
            .saturating_sub(self.decode_time + self.render_delay)
    }

    /// Whether pictures render as soon as they are decoded.
    pub fn low_latency(&self) -> bool {
        self.min_playout_delay.is_zero() && self.max_playout_delay <= LOW_LATENCY_MAX_PLAYOUT_DELAY
    }

    /// A complete frame: updates the RTP-to-local mapping (not from retransmitted frames, and
    /// only from a picture's last frame).
    pub fn on_complete_frame(&mut self, rtp: u32, at: Instant, retransmitted: bool, last: bool) {
        if !retransmitted && last {
            self.extrapolator.update(at, rtp);
        }
    }

    /// A picture became decodable: updates the jitter estimate and the minimum delay.
    pub fn on_decodable(
        &mut self,
        now: Instant,
        rtp: u32,
        size: usize,
        received: Instant,
        retransmitted: bool,
    ) {
        if retransmitted {
            self.jitter.frame_nacked(now);
            return;
        }
        if let Some(v) = self.delay_variation.calculate(rtp, received) {
            self.jitter.update(now, v, size as f64);
        }
        let estimate = self.jitter.estimate(now);
        if self.current_delay.is_zero() {
            self.current_delay = estimate;
        }
        self.minimum_delay = estimate;
    }

    /// The round-trip time (for the retransmission term of the estimate).
    pub fn update_rtt(&mut self, rtt: Duration) {
        self.jitter.update_rtt(rtt);
    }

    /// A picture was released at `actual` with render time `render`: the current delay rises
    /// by how late it was, up to the target.
    pub fn update_current_delay(&mut self, render: Instant, actual: Instant) {
        let target = self.target_delay();
        let delayed = signed_ms(actual, render) + ms(self.decode_time) + ms(self.render_delay);
        if delayed < 0.0 {
            return;
        }
        let delayed = Duration::from_secs_f64(delayed / 1000.0);
        if self.current_delay + delayed <= target {
            self.current_delay += delayed;
        } else {
            self.current_delay = target;
        }
    }

    /// A decode took `decode`.
    pub fn on_decode_time(&mut self, now: Instant, decode: Duration) {
        self.decode_times.add(now, ms(decode));
        self.decode_time = Duration::from_secs_f64(self.decode_times.percentile_ms() / 1000.0);
    }

    /// The render time of RTP timestamp `rtp`; `None` on the low-latency path (render at once).
    pub fn render_time(&self, rtp: u32, now: Instant) -> Option<Instant> {
        if self.low_latency() {
            return None;
        }
        let Some(local) = self.extrapolator.local_time(rtp) else {
            return Some(now);
        };
        let delay = self.current_delay.clamp(
            self.min_playout_delay,
            self.max_playout_delay.max(self.min_playout_delay),
        );
        Some(local + delay)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_extrapolator_maps_a_steady_stream_to_its_arrival_times() {
        let t0 = Instant::now();
        let mut x = TimestampExtrapolator::new(t0);
        for i in 0..100u32 {
            x.update(t0 + Duration::from_millis(u64::from(i) * 33), i * 2970);
        }
        let predicted = x.local_time(100 * 2970).unwrap();
        let expected = t0 + Duration::from_millis(3300);
        let error = signed_ms(predicted, expected).abs();
        assert!(error <= 2.0, "error {error} ms");
    }

    #[test]
    fn jitter_grows_with_the_arrival_jitter() {
        let t0 = Instant::now();
        let estimate = |spread_ms: u64| {
            let mut e = JitterEstimator::default();
            let mut dv = DelayVariation::default();
            let mut rng = crate::test_util::Rng(7);
            for i in 0..600u64 {
                let at = t0 + Duration::from_millis(i * 33 + rng.below(spread_ms + 1));
                let now = t0 + Duration::from_millis(i * 33 + spread_ms);
                if let Some(v) = dv.calculate((i * 2970) as u32, at) {
                    e.update(now, v, 1200.0);
                }
            }
            e.estimate(t0 + Duration::from_millis(600 * 33 + spread_ms))
        };
        let quiet = estimate(0);
        let noisy = estimate(40);
        assert!(quiet < Duration::from_millis(15), "{quiet:?}");
        // Uniform 0..40 ms arrival jitter: consecutive delay differences have a standard
        // deviation of 40 / sqrt(6) = 16.3 ms, so 2.33 sigma - 30 ms + 10 ms is about 18 ms.
        assert!(
            noisy > quiet + Duration::from_millis(5),
            "{quiet:?} {noisy:?}"
        );
        assert!(noisy > Duration::from_millis(15), "{noisy:?}");
        assert!(noisy < Duration::from_millis(120), "{noisy:?}");
    }

    #[test]
    fn the_retransmission_term_follows_three_nacked_frames() {
        let t0 = Instant::now();
        let mut e = JitterEstimator::default();
        e.update_rtt(Duration::from_millis(100));
        let before = e.estimate(t0);
        for _ in 0..3 {
            e.frame_nacked(t0);
        }
        let after = e.estimate(t0);
        let added = after.saturating_sub(before);
        assert!(
            added >= Duration::from_millis(89) && added <= Duration::from_millis(91),
            "{added:?}"
        );
    }

    #[test]
    fn low_latency_rendering_needs_zero_minimum_and_small_maximum() {
        let mut t = Timing::new(Instant::now());
        assert!(!t.low_latency());
        t.max_playout_delay = Duration::from_millis(500);
        assert!(t.low_latency());
        t.min_playout_delay = Duration::from_millis(10);
        assert!(!t.low_latency());
    }
}
