//! Synthetic, deterministic test signals: tones, noise and a speech-like source.
//!
//! The tests, the measurements in `docs/media-pipeline.md` and the headless example use these
//! instead of recordings, so every run hears the same thing on every platform.
//!
//! [`SpeechLike`] imitates the statistics that matter to a voice pipeline: talkspurts of
//! syllables separated by pauses (about 60 % activity, as in conversational speech), a voiced
//! excitation at a moving pitch (90 to 220 Hz) shaped by three formant resonators that change
//! from syllable to syllable, unvoiced fricatives, and a syllabic envelope. It is not speech,
//! but codecs, concealment, time-stretching and voice activity detection treat it as such.

/// A small deterministic generator (SplitMix64).
#[derive(Debug, Clone)]
pub struct Rng(u64);

impl Rng {
    /// A generator from `seed`.
    pub fn new(seed: u64) -> Self {
        Self(seed)
    }

    /// The next 64 random bits.
    pub fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    /// Uniform in [0, 1).
    pub fn unit(&mut self) -> f64 {
        (self.next_u64() >> 11) as f64 / (1u64 << 53) as f64
    }

    /// Uniform in [lo, hi).
    pub fn range(&mut self, lo: f64, hi: f64) -> f64 {
        lo + (hi - lo) * self.unit()
    }

    /// Approximately standard normal (sum of four uniforms, scaled).
    pub fn gaussian(&mut self) -> f64 {
        let s: f64 = (0..4).map(|_| self.unit()).sum();
        (s - 2.0) * (3.0f64).sqrt()
    }
}

/// A sine tone.
#[derive(Debug, Clone)]
pub struct Tone {
    phase: f64,
    step: f64,
    amplitude: f32,
}

impl Tone {
    /// A tone of `hz` at `sample_rate` with peak `amplitude`.
    pub fn new(sample_rate: u32, hz: f64, amplitude: f32) -> Self {
        Self {
            phase: 0.0,
            step: 2.0 * std::f64::consts::PI * hz / f64::from(sample_rate.max(1)),
            amplitude,
        }
    }

    /// Fills `out` (mono) with the next samples.
    pub fn fill(&mut self, out: &mut [f32]) {
        for s in out {
            *s = self.amplitude * self.phase.sin() as f32;
            self.phase += self.step;
            if self.phase > 2.0 * std::f64::consts::PI {
                self.phase -= 2.0 * std::f64::consts::PI;
            }
        }
    }
}

/// White noise of a given RMS level.
#[derive(Debug, Clone)]
pub struct Noise {
    rng: Rng,
    rms: f32,
}

impl Noise {
    /// Noise from `seed` with RMS `rms`.
    pub fn new(seed: u64, rms: f32) -> Self {
        Self {
            rng: Rng::new(seed),
            rms,
        }
    }

    /// Fills `out` (mono) with the next samples.
    pub fn fill(&mut self, out: &mut [f32]) {
        for s in out {
            *s = self.rms * self.rng.gaussian() as f32;
        }
    }
}

/// A two-pole resonator (one formant).
#[derive(Debug, Clone, Default)]
struct Resonator {
    a1: f64,
    a2: f64,
    gain: f64,
    y1: f64,
    y2: f64,
}

impl Resonator {
    fn set(&mut self, rate: f64, hz: f64, bandwidth: f64) {
        let r = (-std::f64::consts::PI * bandwidth / rate).exp();
        let theta = 2.0 * std::f64::consts::PI * hz / rate;
        self.a1 = 2.0 * r * theta.cos();
        self.a2 = -r * r;
        // Unity gain at the centre frequency, roughly.
        self.gain = (1.0 - r) * (1.0 + r * r - 2.0 * r * (2.0 * theta).cos()).sqrt();
    }

    fn process(&mut self, x: f64) -> f64 {
        let y = self.gain * x + self.a1 * self.y1 + self.a2 * self.y2;
        self.y2 = self.y1;
        self.y1 = y;
        y
    }
}

/// Vowel formants (F1, F2, F3 in Hz).
const VOWELS: [[f64; 3]; 6] = [
    [730.0, 1090.0, 2440.0],
    [270.0, 2290.0, 3010.0],
    [530.0, 1840.0, 2480.0],
    [570.0, 840.0, 2410.0],
    [300.0, 870.0, 2240.0],
    [660.0, 1720.0, 2410.0],
];

#[derive(Debug, Clone, Copy, PartialEq)]
enum Segment {
    Pause,
    Voiced,
    Fricative,
}

/// A deterministic speech-like source (see the module documentation), mono.
#[derive(Debug, Clone)]
pub struct SpeechLike {
    rate: f64,
    rng: Rng,
    segment: Segment,
    /// Samples left in the current segment, and its length.
    left: usize,
    length: usize,
    /// Syllables left in the current talkspurt.
    syllables: u32,
    f0: f64,
    f0_target: f64,
    pulse_phase: f64,
    formants: [Resonator; 3],
    fricative: crate::dsp::filter::Biquad,
    amplitude: f64,
    last_voiced: bool,
}

impl SpeechLike {
    /// The RMS level of the voiced segments, about -20 dBFS.
    pub const LEVEL: f64 = 0.1;

    /// A source at `sample_rate` from `seed`.
    pub fn new(sample_rate: u32, seed: u64) -> Self {
        let rate = f64::from(sample_rate.max(8000));
        let mut s = Self {
            rate,
            rng: Rng::new(seed),
            segment: Segment::Pause,
            left: 0,
            length: 1,
            syllables: 0,
            f0: 140.0,
            f0_target: 140.0,
            pulse_phase: 0.0,
            formants: Default::default(),
            fricative: crate::dsp::filter::Biquad::high_pass_q(
                sample_rate.max(8000),
                (rate * 0.4).min(4000.0),
                0.7,
            ),
            amplitude: 0.0,
            last_voiced: false,
        };
        s.next_segment();
        s
    }

    /// Whether the last sample of the last [`fill`](Self::fill) was inside a syllable.
    pub fn voiced(&self) -> bool {
        self.last_voiced
    }

    fn next_segment(&mut self) {
        if self.syllables == 0 {
            if self.segment != Segment::Pause {
                // End of a talkspurt: a pause.
                self.segment = Segment::Pause;
                self.length = (self.rng.range(0.3, 1.2) * self.rate) as usize;
                self.left = self.length;
                return;
            }
            self.syllables = self.rng.range(4.0, 12.0) as u32;
        }
        self.syllables -= 1;
        if self.rng.unit() < 0.2 {
            self.segment = Segment::Fricative;
            self.length = (self.rng.range(0.06, 0.14) * self.rate) as usize;
        } else {
            self.segment = Segment::Voiced;
            self.length = (self.rng.range(0.12, 0.28) * self.rate) as usize;
            let v = VOWELS[(self.rng.next_u64() % VOWELS.len() as u64) as usize];
            for (r, (hz, bw)) in self
                .formants
                .iter_mut()
                .zip(v.iter().zip([90.0, 110.0, 170.0]))
            {
                let top = self.rate * 0.45;
                r.set(self.rate, hz.min(top), bw);
            }
            self.f0_target = self.rng.range(90.0, 220.0);
        }
        self.left = self.length;
    }

    /// Fills `out` (mono) with the next samples.
    pub fn fill(&mut self, out: &mut [f32]) {
        for s in out.iter_mut() {
            if self.left == 0 {
                self.next_segment();
            }
            let pos = 1.0 - self.left as f64 / self.length as f64;
            // Syllabic envelope: raised-cosine attack and decay over a quarter each.
            let env = if pos < 0.25 {
                0.5 - 0.5 * (std::f64::consts::PI * pos / 0.25).cos()
            } else if pos > 0.75 {
                0.5 - 0.5 * (std::f64::consts::PI * (1.0 - pos) / 0.25).cos()
            } else {
                1.0
            };
            let v = match self.segment {
                Segment::Pause => 0.0,
                Segment::Voiced => {
                    self.f0 += (self.f0_target - self.f0) * 0.0005;
                    self.pulse_phase += self.f0 / self.rate;
                    // A glottal-like pulse: a decaying spike once per period, plus aspiration.
                    let excitation = if self.pulse_phase >= 1.0 {
                        self.pulse_phase -= 1.0;
                        1.0
                    } else {
                        0.0
                    } + 0.02 * self.rng.gaussian();
                    let mut y = 0.0;
                    for r in &mut self.formants {
                        y += r.process(excitation);
                    }
                    // Scale so that the voiced RMS is about LEVEL.
                    y * 66.0 * Self::LEVEL * (self.f0 / 140.0).sqrt().recip()
                }
                Segment::Fricative => {
                    0.4 * Self::LEVEL
                        * f64::from(self.fricative.process(self.rng.gaussian() as f32))
                }
            };
            self.amplitude = env;
            *s = (v * env).clamp(-1.0, 1.0) as f32;
            self.last_voiced = self.segment != Segment::Pause;
            self.left -= 1;
        }
    }
}

/// Signal-to-noise ratio of `test` against `reference`, in dB (`reference` power over the
/// power of their difference), over equal lengths.
pub fn snr_db(reference: &[f32], test: &[f32]) -> f64 {
    let n = reference.len().min(test.len());
    let (mut signal, mut noise) = (0.0f64, 0.0f64);
    for i in 0..n {
        let r = f64::from(reference[i]);
        let d = r - f64::from(test[i]);
        signal += r * r;
        noise += d * d;
    }
    if noise <= 1e-20 {
        return 200.0;
    }
    10.0 * (signal / noise).log10()
}

/// Segmental SNR in dB: the mean of per-segment SNRs (`segment` samples each), each clamped
/// to -10..35 dB, over segments whose reference is above -60 dBFS (ITU-T P-series practice).
pub fn segmental_snr_db(reference: &[f32], test: &[f32], segment: usize) -> f64 {
    let n = reference.len().min(test.len());
    let mut total = 0.0;
    let mut count = 0usize;
    let mut i = 0;
    while i + segment <= n {
        let r = &reference[i..i + segment];
        let power = r.iter().map(|s| f64::from(*s).powi(2)).sum::<f64>() / segment as f64;
        if power > 1e-6 {
            total += snr_db(r, &test[i..i + segment]).clamp(-10.0, 35.0);
            count += 1;
        }
        i += segment;
    }
    if count == 0 {
        0.0
    } else {
        total / count as f64
    }
}

/// The lag (in samples, `0..=max_lag`) at which `test` best matches `reference` delayed:
/// the peak of their normalised cross-correlation over the same window of `reference` at
/// every lag. For aligning a codec's output with its input.
pub fn best_lag(reference: &[f32], test: &[f32], max_lag: usize) -> usize {
    let n = reference.len().min(test.len());
    let max_lag = max_lag.min(n.saturating_sub(1));
    let w = n - max_lag;
    let mut best = (0usize, f64::MIN);
    for lag in 0..=max_lag {
        let (mut c, mut e) = (0.0f64, 0.0f64);
        for i in 0..w {
            let t = f64::from(test[i + lag]);
            c += f64::from(reference[i]) * t;
            e += t * t;
        }
        let c = c / e.sqrt().max(1e-12);
        if c > best.1 {
            best = (lag, c);
        }
    }
    best.0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_speech_like_source_talks_about_sixty_percent_of_the_time_at_its_level() {
        let mut s = SpeechLike::new(48_000, 3);
        let mut frame = vec![0.0f32; 480];
        let (mut active, mut total, mut energy) = (0, 0, 0.0f64);
        for _ in 0..3000 {
            s.fill(&mut frame);
            total += 1;
            if s.voiced() {
                active += 1;
                energy += frame.iter().map(|x| f64::from(*x).powi(2)).sum::<f64>() / 480.0;
            }
        }
        let share = active as f64 / total as f64;
        let rms = (energy / active as f64).sqrt();
        println!(
            "MEASURE speech-like source: active {:.0} % of the time, RMS {rms:.3} while active",
            100.0 * share
        );
        assert!((0.45..0.9).contains(&share), "{share}");
        assert!((0.02..0.3).contains(&rms), "{rms}");
    }

    #[test]
    fn snr_of_a_copy_is_large_and_of_noise_is_zero() {
        let mut x = vec![0.0f32; 1000];
        Noise::new(8, 0.3).fill(&mut x);
        assert!(snr_db(&x, &x) > 100.0);
        let zeros = vec![0.0f32; 1000];
        assert!(snr_db(&x, &zeros).abs() < 1e-9);
        let delayed: Vec<f32> = std::iter::repeat_n(0.0, 7)
            .chain(x.iter().copied())
            .collect();
        assert_eq!(best_lag(&x, &delayed, 20), 7);
    }
}
