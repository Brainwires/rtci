//! Acoustic echo cancellation: a partitioned-block frequency-domain adaptive filter (overlap-
//! save, constrained, NLMS-normalised per bin) behind a bulk delay found by the
//! [`DelayEstimator`](super::delay::DelayEstimator), with two filters in the manner of AEC3's
//! refined and coarse filters: a background filter that adapts on every block and a
//! foreground filter that produces the output and takes the background's coefficients only
//! when they cancel better. Near-end speech (double talk) makes the background diverge; the
//! foreground is untouched by it. The residual echo the linear filter leaves is removed by
//! the [`Suppressor`](super::suppressor::Suppressor), which takes this stage's echo estimate.
//!
//! 48 kHz mono, 10 ms blocks (480 samples), FFT of 1024, 13 partitions: 130 ms of echo tail
//! after the bulk delay (which can be up to 500 ms).

use std::collections::VecDeque;

use crate::dsp::fft::{Complex, Fft};

const BLOCK: usize = 480;
const N: usize = 1024;
const BINS: usize = N / 2 + 1;
/// Partitions of the adaptive filter (130 ms tail).
pub const PARTITIONS: usize = 13;
const MU: f32 = 0.5;
/// Headroom left before the estimated bulk delay, so the filter also covers a slightly
/// shorter path.
const HEADROOM: usize = 480;

/// The echo canceller's linear stage.
#[derive(Debug, Clone)]
pub struct EchoCanceller {
    fft: Fft,
    foreground: Vec<Vec<Complex>>,
    background: Vec<Vec<Complex>>,
    spectra: VecDeque<Vec<Complex>>,
    window: Vec<f32>,
    power: Vec<f32>,
    render: VecDeque<f32>,
    render_total: u64,
    bulk_delay: usize,
    energy_fg: f32,
    energy_bg: f32,
    /// The last block's echo estimate (foreground), for the suppressor.
    echo: Vec<f32>,
    /// Smoothed powers for ERL / ERLE.
    p_render: f64,
    p_capture: f64,
    p_output: f64,
    scratch: Vec<Complex>,
    time: Vec<f32>,
}

impl Default for EchoCanceller {
    fn default() -> Self {
        Self::new()
    }
}

impl EchoCanceller {
    /// A canceller with zero coefficients and no delay.
    pub fn new() -> Self {
        let zero = vec![Complex::default(); BINS];
        Self {
            fft: Fft::new(N),
            foreground: vec![zero.clone(); PARTITIONS],
            background: vec![zero.clone(); PARTITIONS],
            spectra: (0..PARTITIONS).map(|_| zero.clone()).collect(),
            window: vec![0.0; N],
            power: vec![0.0; BINS],
            render: VecDeque::new(),
            render_total: 0,
            bulk_delay: 0,
            energy_fg: 0.0,
            energy_bg: 0.0,
            echo: vec![0.0; BLOCK],
            p_render: 0.0,
            p_capture: 0.0,
            p_output: 0.0,
            scratch: vec![Complex::default(); BINS],
            time: vec![0.0; N],
        }
    }

    /// Takes a render block (480 samples about to be played).
    pub fn push_render(&mut self, block: &[f32]) {
        self.render.extend(block.iter().copied());
        self.render_total += block.len() as u64;
        let keep = (super::delay::MAX_DELAY_SECS * 48_000.0) as usize + 4 * BLOCK;
        while self.render.len() > keep {
            self.render.pop_front();
        }
    }

    /// Sets the bulk delay (in samples) the render is delayed by before the filter.
    pub fn set_bulk_delay(&mut self, samples: usize) {
        let samples = samples.saturating_sub(HEADROOM);
        // Within the headroom the filter covers the change itself; moving the bulk delay
        // misaligns everything it learnt.
        if samples.abs_diff(self.bulk_delay) > HEADROOM {
            self.bulk_delay = samples;
        }
    }

    /// The bulk delay in use.
    pub fn bulk_delay(&self) -> usize {
        self.bulk_delay
    }

    /// The echo estimate of the last block (what was subtracted).
    pub fn echo_estimate(&self) -> &[f32] {
        &self.echo
    }

    /// Echo return loss (render over capture power) and its enhancement (capture over
    /// output power), in dB, smoothed over about a second.
    pub fn erl_erle(&self) -> (f64, f64) {
        let db = |a: f64, b: f64| 10.0 * ((a + 1e-12) / (b + 1e-12)).log10();
        (
            db(self.p_render, self.p_capture),
            db(self.p_capture, self.p_output),
        )
    }

    fn aligned_render(&self) -> Vec<f32> {
        let n = self.render.len();
        let end = n.saturating_sub(self.bulk_delay);
        let start = end.saturating_sub(BLOCK);
        let mut out = vec![0.0; BLOCK - (end - start)];
        out.extend(self.render.range(start..end));
        out
    }

    fn filter(&mut self, which: bool) -> Vec<f32> {
        let w = if which {
            &self.foreground
        } else {
            &self.background
        };
        let mut acc = vec![Complex::default(); BINS];
        for (p, x) in self.spectra.iter().enumerate() {
            for ((a, &wk), &xk) in acc.iter_mut().zip(&w[p]).zip(x) {
                *a += wk * xk;
            }
        }
        self.fft.real_inverse(&acc, &mut self.time);
        self.time[N - BLOCK..].to_vec()
    }

    /// Cancels the echo in a capture block (480 samples) in place.
    pub fn process(&mut self, capture: &mut [f32]) {
        if capture.len() != BLOCK {
            return;
        }
        let x = self.aligned_render();
        self.window.copy_within(BLOCK.., 0);
        self.window[N - BLOCK..].copy_from_slice(&x);
        let mut spectrum = vec![Complex::default(); BINS];
        self.fft.real_forward(&self.window, &mut spectrum);
        self.spectra.pop_back();
        self.spectra.push_front(spectrum);

        let y_fg = self.filter(true);
        let y_bg = self.filter(false);
        let mut e_fg = vec![0.0f32; BLOCK];
        let mut e_bg = vec![0.0f32; BLOCK];
        let (mut sum_fg, mut sum_bg, mut sum_d, mut sum_x) = (0.0f32, 0.0f32, 0.0f32, 0.0f32);
        for i in 0..BLOCK {
            e_fg[i] = capture[i] - y_fg[i];
            e_bg[i] = capture[i] - y_bg[i];
            sum_fg += e_fg[i] * e_fg[i];
            sum_bg += e_bg[i] * e_bg[i];
            sum_d += capture[i] * capture[i];
            sum_x += x[i] * x[i];
        }

        // Per-bin render power over the filter's span.
        let render_active = sum_x / BLOCK as f32 > 1e-8;
        for k in 0..BINS {
            let p: f32 = self.spectra.iter().map(|s| s[k].norm_sqr()).sum();
            self.power[k] = 0.7 * self.power[k] + 0.3 * p;
        }
        if render_active {
            // Background update: E = FFT([0; N - B], e_bg), G_p = conj(X_p) E / P.
            self.time[..N - BLOCK].iter_mut().for_each(|v| *v = 0.0);
            self.time[N - BLOCK..].copy_from_slice(&e_bg);
            let mut err = std::mem::take(&mut self.scratch);
            self.fft.real_forward(&self.time, &mut err);
            let mean_power = self.power.iter().sum::<f32>() / BINS as f32;
            let reg = 1e-3 * mean_power + 1e-6;
            for p in 0..PARTITIONS {
                let mut g: Vec<Complex> = self.spectra[p]
                    .iter()
                    .zip(&err)
                    .zip(&self.power)
                    .map(|((x, &e), &pk)| (x.conj() * e).scale(MU / (pk + reg)))
                    .collect();
                // Constrain: keep the first BLOCK taps of the gradient.
                self.fft.real_inverse(&g, &mut self.time);
                self.time[BLOCK..].iter_mut().for_each(|v| *v = 0.0);
                self.fft.real_forward(&self.time, &mut g);
                for (w, &gk) in self.background[p].iter_mut().zip(&g) {
                    *w += gk;
                }
            }
            self.scratch = err;
        }

        // Which filter to trust.
        self.energy_fg = 0.6 * self.energy_fg + 0.4 * sum_fg;
        self.energy_bg = 0.6 * self.energy_bg + 0.4 * sum_bg;
        if render_active && self.energy_bg < 0.8 * self.energy_fg && sum_bg < sum_d {
            self.foreground = self.background.clone();
            self.energy_fg = self.energy_bg;
            e_fg.copy_from_slice(&e_bg);
            self.echo.copy_from_slice(&y_bg);
        } else {
            self.echo.copy_from_slice(&y_fg);
            if self.energy_bg > 8.0 * self.energy_fg + 1e-9 {
                // The background diverged (double talk, a path change it chased): restart it
                // from the foreground.
                self.background = self.foreground.clone();
                self.energy_bg = self.energy_fg;
            }
        }
        // Never make the capture louder than it was.
        let sum_out: f32 = e_fg.iter().map(|v| v * v).sum();
        if sum_out > sum_d * 1.05 {
            self.echo.iter_mut().for_each(|v| *v = 0.0);
        } else {
            capture.copy_from_slice(&e_fg);
        }
        let out: f32 = capture.iter().map(|v| v * v).sum();
        if render_active {
            let a = 0.97;
            self.p_render = a * self.p_render + (1.0 - a) * f64::from(sum_x);
            self.p_capture = a * self.p_capture + (1.0 - a) * f64::from(sum_d);
            self.p_output = a * self.p_output + (1.0 - a) * f64::from(out);
        }
    }
}
