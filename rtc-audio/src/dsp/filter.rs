//! Biquad filters (RBJ audio EQ cookbook), transposed direct form II.

/// One second-order section.
#[derive(Debug, Clone)]
pub struct Biquad {
    b0: f64,
    b1: f64,
    b2: f64,
    a1: f64,
    a2: f64,
    z1: f64,
    z2: f64,
}

impl Biquad {
    /// A Butterworth-Q (1/sqrt 2) high-pass at `cutoff` Hz for `sample_rate`.
    pub fn high_pass(sample_rate: u32, cutoff: f64) -> Self {
        Self::high_pass_q(sample_rate, cutoff, std::f64::consts::FRAC_1_SQRT_2)
    }

    /// A high-pass at `cutoff` Hz with quality `q`.
    pub fn high_pass_q(sample_rate: u32, cutoff: f64, q: f64) -> Self {
        let w0 = 2.0 * std::f64::consts::PI * cutoff / f64::from(sample_rate.max(1));
        let (sin, cos) = w0.sin_cos();
        let alpha = sin / (2.0 * q);
        let a0 = 1.0 + alpha;
        Self {
            b0: (1.0 + cos) / 2.0 / a0,
            b1: -(1.0 + cos) / a0,
            b2: (1.0 + cos) / 2.0 / a0,
            a1: -2.0 * cos / a0,
            a2: (1.0 - alpha) / a0,
            z1: 0.0,
            z2: 0.0,
        }
    }

    /// A low-pass at `cutoff` Hz with quality `q`.
    pub fn low_pass_q(sample_rate: u32, cutoff: f64, q: f64) -> Self {
        let w0 = 2.0 * std::f64::consts::PI * cutoff / f64::from(sample_rate.max(1));
        let (sin, cos) = w0.sin_cos();
        let alpha = sin / (2.0 * q);
        let a0 = 1.0 + alpha;
        Self {
            b0: (1.0 - cos) / 2.0 / a0,
            b1: (1.0 - cos) / a0,
            b2: (1.0 - cos) / 2.0 / a0,
            a1: -2.0 * cos / a0,
            a2: (1.0 - alpha) / a0,
            z1: 0.0,
            z2: 0.0,
        }
    }

    /// Filters one sample.
    #[inline]
    pub fn process(&mut self, x: f32) -> f32 {
        let x = f64::from(x);
        let y = self.b0 * x + self.z1;
        self.z1 = self.b1 * x - self.a1 * y + self.z2;
        self.z2 = self.b2 * x - self.a2 * y;
        y as f32
    }

    /// Filters `samples` in place.
    pub fn process_slice(&mut self, samples: &mut [f32]) {
        for s in samples {
            *s = self.process(*s);
        }
    }

    /// Clears the state.
    pub fn reset(&mut self) {
        self.z1 = 0.0;
        self.z2 = 0.0;
    }
}

/// The capture high-pass filter: DC and rumble below the voice band (two cascaded sections,
/// fourth order, 80 Hz), per channel of interleaved audio.
#[derive(Debug, Clone)]
pub struct HighPassFilter {
    sections: Vec<[Biquad; 2]>,
}

impl HighPassFilter {
    /// The cutoff, in Hz.
    pub const CUTOFF_HZ: f64 = 80.0;

    /// A filter for `channels` interleaved channels at `sample_rate`.
    pub fn new(sample_rate: u32, channels: u16) -> Self {
        // Fourth-order Butterworth: two sections with Q 0.541 and 1.307.
        let make = || {
            [
                Biquad::high_pass_q(sample_rate, Self::CUTOFF_HZ, 0.541_196_1),
                Biquad::high_pass_q(sample_rate, Self::CUTOFF_HZ, 1.306_563),
            ]
        };
        Self {
            sections: (0..channels.max(1)).map(|_| make()).collect(),
        }
    }

    /// Filters interleaved `samples` in place.
    pub fn process(&mut self, samples: &mut [f32]) {
        let n = self.sections.len();
        for (i, s) in samples.iter_mut().enumerate() {
            let [a, b] = &mut self.sections[i % n];
            *s = b.process(a.process(*s));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn gain(filter: &mut HighPassFilter, hz: f64) -> f64 {
        let x: Vec<f32> = (0..48_000)
            .map(|i| (2.0 * std::f64::consts::PI * hz * f64::from(i) / 48_000.0).sin() as f32)
            .collect();
        let mut y = x.clone();
        filter.process(&mut y);
        let p = |v: &[f32]| v.iter().map(|s| f64::from(*s).powi(2)).sum::<f64>();
        10.0 * (p(&y[24_000..]) / p(&x[24_000..])).log10()
    }

    #[test]
    fn the_high_pass_removes_rumble_and_keeps_speech() {
        assert!(gain(&mut HighPassFilter::new(48_000, 1), 20.0) < -40.0);
        assert!(gain(&mut HighPassFilter::new(48_000, 1), 80.0) > -3.5);
        assert!(gain(&mut HighPassFilter::new(48_000, 1), 300.0).abs() < 0.2);
        let mut f = HighPassFilter::new(48_000, 1);
        let mut dc = vec![0.5f32; 48_000];
        f.process(&mut dc);
        assert!(dc[47_999].abs() < 1e-4);
    }
}
