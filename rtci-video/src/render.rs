//! What the viewer saw: frames rendered, freezes, pauses, inter-frame delay.
//!
//! W3C webrtc-stats `freezeCount`: "It is a freeze if frame duration, which is time interval
//! between two consecutively rendered frames, is equal or exceeds Max(3 *
//! avg_frame_duration_ms, avg_frame_duration_ms + 150), where avg_frame_duration_ms is linear
//! average of durations of last 30 rendered frames." `pauseCount`: "paused if time passed since
//! last rendered frame exceeds 5 seconds". libwebrtc (`video/video_quality_observer2.cc:155-176`,
//! a222406d) averages over the last 30 intervals with the current one included, and judges
//! freezes only once 5 intervals are known (`kMinFrameSamplesToDetectFreeze`); the latter is
//! the `Chrome` behaviour, the former the default here as well.

use std::collections::VecDeque;
use std::time::{Duration, Instant};

/// The W3C pause threshold.
pub const PAUSE_THRESHOLD: Duration = Duration::from_secs(5);
/// The intervals averaged (W3C: "last 30 rendered frames").
pub const AVERAGE_WINDOW: usize = 30;
/// The W3C freeze margin over the average, in ms.
pub const FREEZE_MIN_INCREASE_MS: f64 = 150.0;
/// libwebrtc's warm-up before freezes are judged (`kMinFrameSamplesToDetectFreeze`).
pub const CHROME_MIN_FREEZE_SAMPLES: usize = 5;

/// The render-side statistics of one stream.
#[derive(Debug, Clone)]
pub struct RenderStats {
    min_samples: usize,
    last: Option<Instant>,
    intervals: VecDeque<f64>,
    /// `framesRendered`.
    pub frames_rendered: u32,
    /// `totalInterFrameDelay`, seconds.
    pub total_inter_frame_delay: f64,
    /// `totalSquaredInterFrameDelay`, seconds squared.
    pub total_squared_inter_frame_delay: f64,
    /// `freezeCount`.
    pub freeze_count: u32,
    /// `totalFreezesDuration`, seconds.
    pub total_freezes_duration: f64,
    /// `pauseCount`.
    pub pause_count: u32,
    /// `totalPausesDuration`, seconds.
    pub total_pauses_duration: f64,
    /// The longest interval between two rendered frames, pauses included.
    pub longest_interval: Duration,
}

impl RenderStats {
    /// Statistics that judge freezes from the `min_samples`-th interval (1: the W3C
    /// definition; [`CHROME_MIN_FREEZE_SAMPLES`]: libwebrtc's).
    pub fn new(min_samples: usize) -> Self {
        Self {
            min_samples: min_samples.max(1),
            last: None,
            intervals: VecDeque::new(),
            frames_rendered: 0,
            total_inter_frame_delay: 0.0,
            total_squared_inter_frame_delay: 0.0,
            freeze_count: 0,
            total_freezes_duration: 0.0,
            pause_count: 0,
            total_pauses_duration: 0.0,
            longest_interval: Duration::ZERO,
        }
    }

    /// A frame was rendered at `now`.
    pub fn on_rendered(&mut self, now: Instant) {
        self.frames_rendered += 1;
        let Some(last) = self.last.replace(now) else {
            return;
        };
        let interval = now.saturating_duration_since(last);
        self.longest_interval = self.longest_interval.max(interval);
        let secs = interval.as_secs_f64();
        self.total_inter_frame_delay += secs;
        self.total_squared_inter_frame_delay += secs * secs;
        if interval > PAUSE_THRESHOLD {
            self.pause_count += 1;
            self.total_pauses_duration += secs;
            return;
        }
        let ms = secs * 1000.0;
        self.intervals.push_back(ms);
        if self.intervals.len() > AVERAGE_WINDOW {
            self.intervals.pop_front();
        }
        if self.intervals.len() >= self.min_samples {
            let avg = self.intervals.iter().sum::<f64>() / self.intervals.len() as f64;
            if ms >= (3.0 * avg).max(avg + FREEZE_MIN_INCREASE_MS) {
                self.freeze_count += 1;
                self.total_freezes_duration += secs;
            }
        }
    }
}

impl Default for RenderStats {
    fn default() -> Self {
        Self::new(1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(stats: &mut RenderStats, t0: Instant, gaps_ms: &[u64]) {
        let mut t = t0;
        stats.on_rendered(t);
        for g in gaps_ms {
            t += Duration::from_millis(*g);
            stats.on_rendered(t);
        }
    }

    #[test]
    fn a_long_interval_after_steady_frames_is_a_freeze() {
        let mut s = RenderStats::default();
        let mut gaps = vec![33; 40];
        gaps.push(300);
        run(&mut s, Instant::now(), &gaps);
        assert_eq!(s.freeze_count, 1);
        assert!((s.total_freezes_duration - 0.3).abs() < 1e-9);
        assert_eq!(s.frames_rendered, 42);
    }

    #[test]
    fn an_interval_just_under_the_threshold_is_not_a_freeze() {
        let mut s = RenderStats::default();
        // 30 intervals of 33 ms with the current one included: the threshold is avg + 150.
        let mut gaps = vec![33; 40];
        gaps.push(180);
        run(&mut s, Instant::now(), &gaps);
        assert_eq!(s.freeze_count, 0);
    }

    #[test]
    fn six_seconds_without_frames_is_a_pause_not_a_freeze() {
        let mut s = RenderStats::default();
        let mut gaps = vec![33; 10];
        gaps.push(6000);
        run(&mut s, Instant::now(), &gaps);
        assert_eq!((s.pause_count, s.freeze_count), (1, 0));
        assert!((s.total_pauses_duration - 6.0).abs() < 1e-9);
    }

    #[test]
    fn the_chrome_warm_up_ignores_an_early_long_interval() {
        let gaps = [33, 33, 33, 1000];
        let mut w3c = RenderStats::new(1);
        run(&mut w3c, Instant::now(), &gaps);
        let mut chrome = RenderStats::new(CHROME_MIN_FREEZE_SAMPLES);
        run(&mut chrome, Instant::now(), &gaps);
        assert_eq!((w3c.freeze_count, chrome.freeze_count), (1, 0));
    }
}
