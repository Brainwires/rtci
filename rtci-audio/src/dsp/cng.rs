//! Comfort noise (RFC 3389): the analysis that turns background noise into a noise level and
//! reflection coefficients (an all-pole model, computed with the Levinson-Durbin recursion),
//! and the synthesis that turns them back into noise.
//!
//! Sign convention: the prediction-error filter is `A(z) = 1 + sum a_j z^-j` and the
//! recursion's reflection coefficients are `k_i = -(r_i + sum a_j r_(i-j)) / E`, the
//! convention of the RFC 3389 appendix's example (and of G.729 Annex B, which it follows).

use rtp::codec::comfort_noise::{ComfortNoise, quantize_reflection_coefficient};

use crate::signal::Rng;

/// The model order this crate's analysis writes.
pub const CN_ORDER: usize = 8;

/// Autocorrelation `r[0..=order]` of `x` (Hann-windowed).
pub fn autocorrelation(x: &[f32], order: usize) -> Vec<f64> {
    let n = x.len();
    let w: Vec<f64> = (0..n)
        .map(|i| {
            let v = f64::from(x[i]);
            if n > 1 {
                v * (0.5 - 0.5 * (2.0 * std::f64::consts::PI * i as f64 / (n - 1) as f64).cos())
            } else {
                v
            }
        })
        .collect();
    (0..=order)
        .map(|lag| (lag..n).map(|i| w[i] * w[i - lag]).sum())
        .collect()
}

/// The Levinson-Durbin recursion on `r` (`r[0] > 0`): the reflection coefficients
/// `k_1..k_order` and the predictor `a_1..a_order`. Stops early (remaining `k` zero) when the
/// error stops being positive.
pub fn levinson(r: &[f64], order: usize) -> (Vec<f64>, Vec<f64>) {
    let mut a = vec![0.0f64; order + 1];
    let mut k = vec![0.0f64; order];
    if r.is_empty() || r[0] <= 0.0 {
        return (k, a[1..].to_vec());
    }
    // A little white-noise correction keeps the recursion stable on tonal input.
    let mut e = r[0] * 1.0001;
    a[0] = 1.0;
    for i in 1..=order.min(r.len() - 1) {
        let mut acc = r[i];
        for j in 1..i {
            acc += a[j] * r[i - j];
        }
        let ki = -acc / e;
        if !ki.is_finite() || ki.abs() >= 1.0 {
            break;
        }
        k[i - 1] = ki;
        let prev = a.clone();
        for j in 1..i {
            a[j] = prev[j] + ki * prev[i - j];
        }
        a[i] = ki;
        e *= 1.0 - ki * ki;
        if e <= 0.0 {
            break;
        }
    }
    (k, a[1..].to_vec())
}

/// The predictor `a_1..a_n` of reflection coefficients `k` (the step-up recursion).
pub fn reflection_to_lpc(k: &[f64]) -> Vec<f64> {
    let mut a: Vec<f64> = Vec::with_capacity(k.len());
    for (i, &ki) in k.iter().enumerate() {
        let prev = a.clone();
        for j in 0..i {
            a[j] = prev[j] + ki * prev[i - 1 - j];
        }
        a.push(ki);
    }
    a
}

/// The RFC 3389 parameters of a frame of background noise.
pub fn analyze(noise: &[f32]) -> ComfortNoise {
    let level = crate::dsp::level::rfc6464_level(noise);
    let r = autocorrelation(noise, CN_ORDER);
    let (k, _) = levinson(&r, CN_ORDER);
    ComfortNoise {
        level,
        coefficients: k
            .iter()
            .map(|&k| quantize_reflection_coefficient(k))
            .collect::<Vec<u8>>()
            .into(),
    }
}

/// Generates comfort noise from RFC 3389 parameters: white noise through the all-pole
/// synthesis filter `1 / A(z)`, scaled to the parameters' level; a new parameter set is
/// faded in over one frame.
#[derive(Debug, Clone)]
pub struct ComfortNoiseGenerator {
    rng: Rng,
    lpc: Vec<f64>,
    memory: Vec<f64>,
    target_rms: f64,
    gain: f64,
    /// Running output power estimate for the level normalisation.
    power: f64,
}

impl Default for ComfortNoiseGenerator {
    fn default() -> Self {
        Self::new(0x5eed)
    }
}

impl ComfortNoiseGenerator {
    /// A generator with silence as its parameters.
    pub fn new(seed: u64) -> Self {
        Self {
            rng: Rng::new(seed),
            lpc: Vec::new(),
            memory: vec![0.0; CN_ORDER],
            target_rms: 0.0,
            gain: 0.0,
            power: 1e-6,
        }
    }

    /// Takes new parameters (an SID payload's).
    pub fn update(&mut self, params: &ComfortNoise) {
        let order = params.model_order().min(16);
        self.lpc = reflection_to_lpc(&params.reflection_coefficients(order));
        if self.memory.len() < self.lpc.len() {
            self.memory.resize(self.lpc.len(), 0.0);
        }
        self.target_rms = crate::dsp::level::linear_from_rfc6464(params.level);
    }

    /// Takes a level and spectrum directly (from the analysis of decoded background noise).
    pub fn update_from_noise(&mut self, noise: &[f32]) {
        self.update(&analyze(noise));
    }

    /// The RMS level the output is scaled to.
    pub fn target_rms(&self) -> f64 {
        self.target_rms
    }

    /// Fills `out` (mono) with comfort noise.
    pub fn generate(&mut self, out: &mut [f32]) {
        for s in out.iter_mut() {
            let e = self.rng.gaussian();
            // y[n] = e[n] - sum a_j y[n-j]
            let mut y = e;
            for (j, a) in self.lpc.iter().enumerate() {
                y -= a * self.memory[j];
            }
            if !y.is_finite() || y.abs() > 1e6 {
                y = 0.0;
                self.memory.iter_mut().for_each(|m| *m = 0.0);
            }
            for j in (1..self.memory.len()).rev() {
                self.memory[j] = self.memory[j - 1];
            }
            if !self.memory.is_empty() {
                self.memory[0] = y;
            }
            self.power = 0.999 * self.power + 0.001 * y * y;
            let want = self.target_rms / self.power.sqrt().max(1e-9);
            self.gain += (want - self.gain) * 0.01;
            *s = (y * self.gain).clamp(-1.0, 1.0) as f32;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signal::Noise;

    #[test]
    fn levinson_inverts_the_step_up_recursion() {
        let k = [0.5, -0.3, 0.2];
        let a = reflection_to_lpc(&k);
        // r of the AR process with these coefficients, from a long synthetic run.
        let mut rng = Rng::new(1);
        let mut y = vec![0.0f32; 200_000];
        let mut mem = [0.0f64; 3];
        for s in y.iter_mut() {
            let mut v = rng.gaussian();
            for j in 0..3 {
                v -= a[j] * mem[j];
            }
            mem = [v, mem[0], mem[1]];
            *s = (v * 0.01) as f32;
        }
        let r = autocorrelation(&y, 3);
        let (k2, _) = levinson(&r, 3);
        for (want, got) in k.iter().zip(&k2) {
            assert!((want - got).abs() < 0.02, "{k:?} vs {k2:?}");
        }
    }

    #[test]
    fn comfort_noise_has_the_level_of_the_noise_it_models() {
        let mut noise = Noise::new(9, 0.01);
        let mut frame = vec![0.0f32; 4800];
        noise.fill(&mut frame);
        let params = analyze(&frame);
        // 0.01 RMS is -40 dBov.
        assert_eq!(params.level, 40);
        let mut cng = ComfortNoiseGenerator::new(3);
        cng.update(&params);
        let mut out = vec![0.0f32; 48_000];
        cng.generate(&mut out);
        let tail = &out[24_000..];
        let rms =
            (tail.iter().map(|s| f64::from(*s).powi(2)).sum::<f64>() / tail.len() as f64).sqrt();
        assert!((rms / 0.01 - 1.0).abs() < 0.25, "{rms}");
    }
}
