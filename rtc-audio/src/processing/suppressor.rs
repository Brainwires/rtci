//! Spectral suppression of what the linear echo canceller left and of stationary noise, in
//! one short-time Fourier transform (sqrt-Hann windows, 50 % overlap, 20 ms windows, 10 ms
//! hop, 10 ms of delay).
//!
//! - **Residual echo**: the echo canceller's estimate `Y` of the echo it removed tells where
//!   echo is; the residual is taken as `leak * |Y|^2` per bin, with `leak` the ratio of the
//!   output's power to `|Y|^2` measured while only the far end talks (tracked as a slowly
//!   rising minimum, so near-end speech does not inflate it). The gain is
//!   `1 - 2 * residual / |E|^2`, floored at -40 dB.
//! - **Noise**: the noise spectrum is a minimum-tracking estimate of the output's smoothed
//!   power; the gain is the Wiener gain of a decision-directed a priori SNR (Ephraim-Malah),
//!   floored at the level's attenuation.
//!
//! Each bin's gain is the smaller of the two, smoothed over time against musical noise.

use crate::dsp::fft::{Complex, Fft};

const HOP: usize = 480;
const WIN: usize = 960;
const N: usize = 1024;
const BINS: usize = N / 2 + 1;

/// How hard the noise is suppressed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NoiseSuppressionLevel {
    /// At most 6 dB.
    Low,
    /// At most 12 dB.
    Moderate,
    /// At most 18 dB.
    High,
    /// At most 21 dB.
    VeryHigh,
}

impl NoiseSuppressionLevel {
    fn floor(self) -> f32 {
        let db: f32 = match self {
            Self::Low => -6.0,
            Self::Moderate => -12.0,
            Self::High => -18.0,
            Self::VeryHigh => -21.0,
        };
        10f32.powf(db / 20.0)
    }
}

/// The suppressor's state.
#[derive(Debug, Clone)]
pub struct Suppressor {
    fft: Fft,
    window: Vec<f32>,
    input: Vec<f32>,
    echo_input: Vec<f32>,
    overlap: Vec<f32>,
    noise: Vec<f32>,
    smoothed: Vec<f32>,
    prev_clean: Vec<f32>,
    gains: Vec<f32>,
    leak: Vec<f32>,
    frames: u64,
    noise_floor: Option<f32>,
    echo: bool,
}

impl Suppressor {
    /// A suppressor of noise (`noise`, at a level) and of residual echo (`echo`).
    pub fn new(noise: Option<NoiseSuppressionLevel>, echo: bool) -> Self {
        let window = (0..WIN)
            .map(|i| (std::f32::consts::PI * (i as f32 + 0.5) / WIN as f32).sin())
            .collect();
        Self {
            fft: Fft::new(N),
            window,
            input: vec![0.0; WIN],
            echo_input: vec![0.0; WIN],
            overlap: vec![0.0; HOP],
            noise: vec![1e-9; BINS],
            smoothed: vec![0.0; BINS],
            prev_clean: vec![0.0; BINS],
            gains: vec![1.0; BINS],
            leak: vec![0.05; BINS],
            frames: 0,
            noise_floor: noise.map(NoiseSuppressionLevel::floor),
            echo,
        }
    }

    fn spectrum(&mut self, time: &[f32]) -> Vec<Complex> {
        let mut buf = vec![0.0f32; N];
        for i in 0..WIN {
            buf[i] = time[i] * self.window[i];
        }
        let mut out = vec![Complex::default(); BINS];
        self.fft.real_forward(&buf, &mut out);
        out
    }

    /// Processes one 10 ms block (480 samples) in place; `echo` is the echo canceller's
    /// estimate for the same block (or `None`). The output is delayed by one block.
    pub fn process(&mut self, block: &mut [f32], echo: Option<&[f32]>, far_end_only: bool) {
        if block.len() != HOP {
            return;
        }
        self.frames += 1;
        self.input.copy_within(HOP.., 0);
        self.input[WIN - HOP..].copy_from_slice(block);
        self.echo_input.copy_within(HOP.., 0);
        match echo {
            Some(e) if e.len() == HOP => self.echo_input[WIN - HOP..].copy_from_slice(e),
            _ => self.echo_input[WIN - HOP..]
                .iter_mut()
                .for_each(|v| *v = 0.0),
        }
        let input = self.input.clone();
        let mut spec = self.spectrum(&input);
        let echo_in = self.echo_input.clone();
        let echo_spec = self.spectrum(&echo_in);

        for k in 0..BINS {
            let p = spec[k].norm_sqr();
            let mut gain = 1.0f32;
            if let Some(floor) = self.noise_floor {
                // Noise: minimum tracking on the smoothed power.
                self.smoothed[k] = 0.8 * self.smoothed[k] + 0.2 * p;
                let s = self.smoothed[k];
                if self.frames < 20 {
                    self.noise[k] = if self.frames == 1 {
                        s
                    } else {
                        self.noise[k].min(s).max(1e-12)
                    };
                } else if s < self.noise[k] {
                    self.noise[k] = 0.9 * self.noise[k] + 0.1 * s;
                } else {
                    // Rise about 3 dB a second.
                    self.noise[k] *= 1.007;
                }
                let n = self.noise[k].max(1e-12);
                let post = p / n;
                let prio = (0.98 * self.prev_clean[k] / n + 0.02 * (post - 1.0).max(0.0)).max(1e-3);
                let wiener = prio / (1.0 + prio);
                gain = gain.min(wiener.max(floor));
            }
            if self.echo {
                let y = echo_spec[k].norm_sqr();
                if far_end_only && y > 1e-12 {
                    let ratio = (p / y).min(1.0);
                    // A slowly rising minimum of the output-to-echo ratio.
                    self.leak[k] = if ratio < self.leak[k] {
                        0.7 * self.leak[k] + 0.3 * ratio
                    } else {
                        (self.leak[k] * 1.01).min(ratio)
                    };
                }
                let residual = self.leak[k] * y;
                let g = (1.0 - 2.0 * residual / (p + 1e-12)).max(0.01);
                gain = gain.min(g);
            }
            // Smooth: fast down, slower up.
            let prev = self.gains[k];
            let g = if gain < prev {
                gain
            } else {
                0.6 * prev + 0.4 * gain
            };
            self.gains[k] = g;
            self.prev_clean[k] = g * g * p;
            spec[k] = spec[k].scale(g);
        }

        let mut time = vec![0.0f32; N];
        self.fft.real_inverse(&spec, &mut time);
        for i in 0..HOP {
            block[i] = self.overlap[i] + time[i] * self.window[i];
            self.overlap[i] = time[i + HOP] * self.window[i + HOP];
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signal::{Noise, SpeechLike, best_lag, snr_db};

    #[test]
    fn with_nothing_to_suppress_the_output_is_the_input_one_block_later() {
        let mut s = Suppressor::new(None, false);
        let mut src = SpeechLike::new(48_000, 2);
        let mut x = vec![0.0f32; 48_000];
        src.fill(&mut x);
        let mut y = x.clone();
        for b in y.as_chunks_mut::<HOP>().0 {
            s.process(b, None, false);
        }
        assert_eq!(best_lag(&x[..9600], &y[..9600], 1000), HOP);
        assert!(snr_db(&x[..48_000 - HOP], &y[HOP..]) > 60.0);
    }

    #[test]
    fn steady_noise_is_reduced_and_speech_kept() {
        let mut s = Suppressor::new(Some(NoiseSuppressionLevel::High), false);
        let mut noise = Noise::new(5, 0.01);
        let mut src = SpeechLike::new(48_000, 6);
        let secs = 8;
        let mut clean = vec![0.0f32; 48_000 * secs];
        src.fill(&mut clean);
        let mut n = vec![0.0f32; 48_000 * secs];
        noise.fill(&mut n);
        let mut y: Vec<f32> = clean.iter().zip(&n).map(|(a, b)| a + b).collect();
        for b in y.as_chunks_mut::<HOP>().0 {
            s.process(b, None, false);
        }
        // Noise power where the source pauses, before and after.
        let mut before = 0.0f64;
        let mut after = 0.0f64;
        let mut count = 0;
        for i in (48_000 * 2)..(48_000 * secs - HOP) {
            if clean[i] == 0.0
                && clean[i.saturating_sub(4800)..(i + 4800).min(clean.len())]
                    .iter()
                    .all(|v| *v == 0.0)
            {
                before += f64::from(n[i]).powi(2);
                after += f64::from(y[i + HOP]).powi(2);
                count += 1;
            }
        }
        assert!(count > 10_000, "{count}");
        let reduction = 10.0 * (before / after).log10();
        assert!(reduction > 12.0, "noise reduced by {reduction:.1} dB");
        println!("MEASURE noise suppression (High): {reduction:.1} dB in pauses");
    }
}
