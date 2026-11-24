//! The network part of the target delay: how late packets arrive relative to the fastest
//! one of the last two seconds, as a histogram with forgetting, and its 95th percentile
//! (the method of libwebrtc NetEq's delay manager).

use std::collections::VecDeque;
use std::time::{Duration, Instant};

/// Histogram bucket width (2.5 ms, the shortest Opus frame).
const BUCKET: f64 = 0.0025;
/// Histogram range: 0 to 3 s.
const BUCKETS: usize = 1200;
/// The window of the reference (fastest) packet.
const REFERENCE_WINDOW: Duration = Duration::from_secs(2);
/// The forgetting factor in steady state (NetEq's 0.9993: a time constant of about 1400
/// packets); smaller at the start so the first packets count.
const FORGET: f64 = 0.9993;
/// The quantile the estimate is.
const QUANTILE: f64 = 0.95;

/// The arrival-delay statistics of one stream.
#[derive(Debug, Clone)]
pub(crate) struct DelayManager {
    histogram: Vec<f64>,
    packets: u64,
    window: VecDeque<(Instant, f64)>,
    base: Option<Instant>,
    estimate: f64,
}

impl DelayManager {
    pub(crate) fn new() -> Self {
        let mut histogram = vec![0.0; BUCKETS];
        histogram[0] = 1.0;
        Self {
            histogram,
            packets: 0,
            window: VecDeque::new(),
            base: None,
            estimate: 0.0,
        }
    }

    /// Takes a packet that arrived at `arrival` with media time `media_secs` (its unwrapped
    /// RTP timestamp over the clock rate). Reordered packets count with their lateness.
    pub(crate) fn update(&mut self, arrival: Instant, media_secs: f64) {
        let base = *self.base.get_or_insert(arrival);
        let d = arrival.saturating_duration_since(base).as_secs_f64() - media_secs;
        while let Some(&(t, _)) = self.window.front() {
            if arrival.saturating_duration_since(t) > REFERENCE_WINDOW {
                self.window.pop_front();
            } else {
                break;
            }
        }
        self.window.push_back((arrival, d));
        let fastest = self
            .window
            .iter()
            .map(|(_, d)| *d)
            .fold(f64::INFINITY, f64::min);
        let relative = (d - fastest).max(0.0);
        let bucket = ((relative / BUCKET) as usize).min(BUCKETS - 1);
        self.packets += 1;
        let forget = FORGET.min(1.0 - 1.0 / (self.packets as f64 + 1.0));
        for h in &mut self.histogram {
            *h *= forget;
        }
        self.histogram[bucket] += 1.0 - forget;
        let total: f64 = self.histogram.iter().sum();
        let mut acc = 0.0;
        let mut q = BUCKETS - 1;
        for (i, h) in self.histogram.iter().enumerate() {
            acc += h;
            if acc >= QUANTILE * total {
                q = i;
                break;
            }
        }
        // The bucket's upper edge: a packet that late still plays in time.
        self.estimate = (q + 1) as f64 * BUCKET;
    }

    /// The 95th percentile of the relative arrival delay, in seconds.
    pub(crate) fn jitter_estimate(&self) -> f64 {
        self.estimate
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn steady_arrivals_need_no_extra_delay_and_jitter_raises_it() {
        let t0 = Instant::now();
        let mut d = DelayManager::new();
        for i in 0..500u32 {
            d.update(
                t0 + Duration::from_millis(u64::from(i) * 20),
                f64::from(i) * 0.02,
            );
        }
        // One bucket: the estimate is its upper edge.
        assert_eq!(d.jitter_estimate(), 0.0025);
        // Every fifth packet 60 ms late.
        for i in 500..2500u32 {
            let late = if i % 5 == 0 { 60 } else { 0 };
            d.update(
                t0 + Duration::from_millis(u64::from(i) * 20 + late),
                f64::from(i) * 0.02,
            );
        }
        let e = d.jitter_estimate();
        assert!((0.06..=0.08).contains(&e), "{e}");
    }
}
