//! A radix-2 FFT for the spectral stages (echo canceller, suppressor, delay estimation).

/// A complex number.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct Complex {
    /// Real part.
    pub re: f32,
    /// Imaginary part.
    pub im: f32,
}

impl Complex {
    /// `re + i im`.
    pub const fn new(re: f32, im: f32) -> Self {
        Self { re, im }
    }

    /// The complex conjugate.
    pub fn conj(self) -> Self {
        Self::new(self.re, -self.im)
    }

    /// `|z|^2`.
    pub fn norm_sqr(self) -> f32 {
        self.re * self.re + self.im * self.im
    }

    /// `self * k`.
    pub fn scale(self, k: f32) -> Self {
        Self::new(self.re * k, self.im * k)
    }
}

impl std::ops::Mul for Complex {
    type Output = Self;

    fn mul(self, o: Self) -> Self {
        Self::new(
            self.re * o.re - self.im * o.im,
            self.re * o.im + self.im * o.re,
        )
    }
}

impl std::ops::Add for Complex {
    type Output = Self;

    fn add(self, o: Self) -> Self {
        Self::new(self.re + o.re, self.im + o.im)
    }
}

impl std::ops::AddAssign for Complex {
    fn add_assign(&mut self, o: Self) {
        self.re += o.re;
        self.im += o.im;
    }
}

/// A complex FFT of one power-of-two size, with its twiddles and bit-reversal table.
#[derive(Debug, Clone)]
pub struct Fft {
    n: usize,
    twiddles: Vec<Complex>,
    reversed: Vec<usize>,
    scratch: Vec<Complex>,
}

impl Fft {
    /// An FFT of `n` points; `n` is a power of two of at least 2.
    pub fn new(n: usize) -> Self {
        assert!(n >= 2 && n.is_power_of_two(), "FFT size {n}");
        let twiddles = (0..n / 2)
            .map(|k| {
                let a = -2.0 * std::f64::consts::PI * k as f64 / n as f64;
                Complex::new(a.cos() as f32, a.sin() as f32)
            })
            .collect();
        let bits = n.trailing_zeros();
        let reversed = (0..n)
            .map(|i| i.reverse_bits() >> (usize::BITS - bits))
            .collect();
        Self {
            n,
            twiddles,
            reversed,
            scratch: vec![Complex::default(); n],
        }
    }

    /// The transform size.
    pub fn len(&self) -> usize {
        self.n
    }

    /// Always false: an FFT has at least two points.
    pub fn is_empty(&self) -> bool {
        false
    }

    /// The forward transform in place (no scaling).
    pub fn forward(&self, data: &mut [Complex]) {
        self.transform(data, false);
    }

    /// The inverse transform in place, scaled by `1 / n` (so `inverse(forward(x)) == x`).
    pub fn inverse(&self, data: &mut [Complex]) {
        self.transform(data, true);
        let k = 1.0 / self.n as f32;
        for v in data.iter_mut() {
            *v = v.scale(k);
        }
    }

    fn transform(&self, data: &mut [Complex], inverse: bool) {
        let n = self.n;
        assert_eq!(data.len(), n);
        for i in 0..n {
            let j = self.reversed[i];
            if j > i {
                data.swap(i, j);
            }
        }
        let mut len = 2;
        while len <= n {
            let half = len / 2;
            let step = n / len;
            for start in (0..n).step_by(len) {
                for k in 0..half {
                    let mut w = self.twiddles[k * step];
                    if inverse {
                        w = w.conj();
                    }
                    let a = data[start + k];
                    let b = data[start + k + half] * w;
                    data[start + k] = a + b;
                    data[start + k + half] = Complex::new(a.re - b.re, a.im - b.im);
                }
            }
            len *= 2;
        }
    }

    /// The spectrum of the real signal `input` (`n` samples): bins `0..=n/2` into `out`.
    pub fn real_forward(&mut self, input: &[f32], out: &mut [Complex]) {
        assert_eq!(input.len(), self.n);
        assert_eq!(out.len(), self.n / 2 + 1);
        let mut scratch = std::mem::take(&mut self.scratch);
        for (s, &x) in scratch.iter_mut().zip(input) {
            *s = Complex::new(x, 0.0);
        }
        self.forward(&mut scratch);
        out.copy_from_slice(&scratch[..=self.n / 2]);
        self.scratch = scratch;
    }

    /// The real signal (`n` samples) of the half spectrum `input` (bins `0..=n/2`).
    pub fn real_inverse(&mut self, input: &[Complex], out: &mut [f32]) {
        assert_eq!(input.len(), self.n / 2 + 1);
        assert_eq!(out.len(), self.n);
        let n = self.n;
        let mut scratch = std::mem::take(&mut self.scratch);
        scratch[..=n / 2].copy_from_slice(input);
        for k in 1..n / 2 {
            scratch[n - k] = input[k].conj();
        }
        self.inverse(&mut scratch);
        for (o, s) in out.iter_mut().zip(&scratch) {
            *o = s.re;
        }
        self.scratch = scratch;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_sine_lands_in_its_bin_and_comes_back() {
        let n = 64;
        let mut fft = Fft::new(n);
        let x: Vec<f32> = (0..n)
            .map(|i| (2.0 * std::f32::consts::PI * 5.0 * i as f32 / n as f32).sin())
            .collect();
        let mut spec = vec![Complex::default(); n / 2 + 1];
        fft.real_forward(&x, &mut spec);
        let peak = (0..spec.len())
            .max_by(|&a, &b| spec[a].norm_sqr().total_cmp(&spec[b].norm_sqr()))
            .unwrap();
        assert_eq!(peak, 5);
        assert!((spec[5].norm_sqr().sqrt() - n as f32 / 2.0).abs() < 1e-3);
        let mut back = vec![0.0; n];
        fft.real_inverse(&spec, &mut back);
        for (a, b) in x.iter().zip(&back) {
            assert!((a - b).abs() < 1e-5);
        }
    }
}
