//! Render-to-capture delay estimation: how long after a frame is played its echo reaches the
//! microphone (playout buffering, device latency, the acoustic path, capture buffering).
//!
//! Both signals are low-passed and decimated to 4 kHz; the cross-correlation of the capture
//! against the render history, for every lag from 0 to [`MAX_DELAY_SECS`], is accumulated
//! with exponential forgetting, and its peak is the estimate once it stands out from the rest
//! of the correlation and has held for a few frames (the role AEC3's matched-filter delay
//! estimator plays).

use std::collections::VecDeque;

use crate::dsp::filter::Biquad;

/// The longest delay looked for.
pub const MAX_DELAY_SECS: f64 = 0.5;
const DECIMATION: usize = 12;
const LOW_RATE: f64 = 4000.0;
/// Peak over the mean of the correlation's magnitude for an estimate to count.
const CONFIDENCE: f32 = 6.0;
/// Frames an estimate must hold before it is reported (250 ms).
const HOLD: u32 = 25;

/// The estimator's state (48 kHz input).
#[derive(Debug, Clone)]
pub struct DelayEstimator {
    render_lp: [Biquad; 2],
    capture_lp: [Biquad; 2],
    render_phase: usize,
    capture_phase: usize,
    render: VecDeque<f32>,
    correlation: Vec<f32>,
    lags: usize,
    candidate: Option<usize>,
    held: u32,
    estimate: Option<usize>,
    render_energy: f32,
}

impl Default for DelayEstimator {
    fn default() -> Self {
        Self::new()
    }
}

impl DelayEstimator {
    /// An estimator for 48 kHz audio.
    pub fn new() -> Self {
        let lp = || {
            [
                Biquad::low_pass_q(48_000, 1800.0, 0.541_196_1),
                Biquad::low_pass_q(48_000, 1800.0, 1.306_563),
            ]
        };
        let lags = (MAX_DELAY_SECS * LOW_RATE) as usize;
        Self {
            render_lp: lp(),
            capture_lp: lp(),
            render_phase: 0,
            capture_phase: 0,
            render: VecDeque::with_capacity(lags + 64),
            correlation: vec![0.0; lags],
            lags,
            candidate: None,
            held: 0,
            estimate: None,
            render_energy: 0.0,
        }
    }

    fn decimate(lp: &mut [Biquad; 2], phase: &mut usize, input: &[f32], out: &mut Vec<f32>) {
        for &x in input {
            let a = lp[0].process(x);
            let y = lp[1].process(a);
            if *phase == 0 {
                out.push(y);
            }
            *phase = (*phase + 1) % DECIMATION;
        }
    }

    /// Takes a render frame (the audio about to be played).
    pub fn push_render(&mut self, frame: &[f32]) {
        let mut low = Vec::with_capacity(frame.len() / DECIMATION + 1);
        Self::decimate(&mut self.render_lp, &mut self.render_phase, frame, &mut low);
        for v in low {
            self.render_energy = 0.999 * self.render_energy + 0.001 * v * v;
            self.render.push_back(v);
        }
        let keep = self.lags + 64;
        while self.render.len() > keep {
            self.render.pop_front();
        }
    }

    /// Takes the capture frame recorded while the last render frame played, and updates the
    /// estimate.
    pub fn push_capture(&mut self, frame: &[f32]) {
        let mut low = Vec::with_capacity(frame.len() / DECIMATION + 1);
        Self::decimate(
            &mut self.capture_lp,
            &mut self.capture_phase,
            frame,
            &mut low,
        );
        let n = low.len();
        let r = self.render.len();
        if r < n + 1 || self.render_energy < 1e-7 {
            return;
        }
        // Capture sample i of this frame is simultaneous with render sample r - n + i.
        // About one second of memory at 4 kHz.
        let forget = 0.99975f32.powi(n as i32);
        let max_lag = self.lags.min(r - n);
        for lag in 0..max_lag {
            let mut acc = 0.0f32;
            for (i, c) in low.iter().enumerate() {
                acc += c * self.render[r - n + i - lag];
            }
            self.correlation[lag] = forget * self.correlation[lag] + acc;
        }
        let (mut best, mut peak, mut sum) = (0usize, 0.0f32, 0.0f32);
        for (lag, c) in self.correlation[..max_lag].iter().enumerate() {
            let a = c.abs();
            sum += a;
            if a > peak {
                peak = a;
                best = lag;
            }
        }
        let mean = sum / max_lag.max(1) as f32;
        if mean <= 0.0 || peak < CONFIDENCE * mean {
            return;
        }
        match self.candidate {
            Some(c) if c.abs_diff(best) <= 2 => self.held += 1,
            _ => {
                self.candidate = Some(best);
                self.held = 1;
            }
        }
        if self.held >= HOLD {
            self.estimate = Some(best);
        }
    }

    /// The estimated delay in 48 kHz samples, once there is one.
    pub fn estimate(&self) -> Option<usize> {
        self.estimate.map(|lag| lag * DECIMATION)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signal::SpeechLike;

    #[test]
    fn the_delay_of_an_echo_is_found() {
        for delay_ms in [12usize, 80, 230] {
            let delay = delay_ms * 48;
            let mut est = DelayEstimator::new();
            let mut src = SpeechLike::new(48_000, delay_ms as u64);
            let mut history = vec![0.0f32; delay];
            let mut frame = vec![0.0f32; 480];
            for _ in 0..400 {
                src.fill(&mut frame);
                est.push_render(&frame);
                history.extend_from_slice(&frame);
                let start = history.len() - 480 - delay;
                let capture: Vec<f32> = history[start..start + 480]
                    .iter()
                    .map(|v| 0.3 * v)
                    .collect();
                est.push_capture(&capture);
            }
            let got = est.estimate().expect("an estimate");
            assert!(
                got.abs_diff(delay) <= 2 * DECIMATION,
                "{delay_ms} ms: {got} samples"
            );
        }
    }
}
