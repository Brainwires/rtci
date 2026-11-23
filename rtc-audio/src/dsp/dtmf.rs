//! In-band DTMF: the dual tones of ITU-T Q.23, generated and detected (Goertzel).
//!
//! WebRTC carries DTMF as RFC 4733 telephone events (`RTCRtpSender::dtmf()` sends them, the
//! receive pipeline reports the ones it receives). These are for the audio itself: a gateway
//! that must play a received event into a legacy audio path, or detect tones a peer sent in
//! band instead of as events.

/// The low (row) frequencies, Hz.
pub const ROWS: [f64; 4] = [697.0, 770.0, 852.0, 941.0];
/// The high (column) frequencies, Hz.
pub const COLUMNS: [f64; 4] = [1209.0, 1336.0, 1477.0, 1633.0];
/// The keypad, by row and column.
pub const KEYS: [[char; 4]; 4] = [
    ['1', '2', '3', 'A'],
    ['4', '5', '6', 'B'],
    ['7', '8', '9', 'C'],
    ['*', '0', '#', 'D'],
];

fn key_position(key: char) -> Option<(usize, usize)> {
    let key = key.to_ascii_uppercase();
    for (r, row) in KEYS.iter().enumerate() {
        if let Some(c) = row.iter().position(|&k| k == key) {
            return Some((r, c));
        }
    }
    None
}

/// Generates the tone pair of a key.
#[derive(Debug, Clone)]
pub struct DtmfGenerator {
    rate: f64,
    low: f64,
    high: f64,
    phase: [f64; 2],
    amplitude: f64,
}

impl DtmfGenerator {
    /// A generator of `key` (`0-9`, `A-D`, `*`, `#`) at `sample_rate`, each tone at
    /// `level_dbov` (Q.23 sends each between -4 and -11 dBm0; -10 dBov is typical).
    pub fn new(key: char, sample_rate: u32, level_dbov: f64) -> Option<Self> {
        let (r, c) = key_position(key)?;
        Some(Self {
            rate: f64::from(sample_rate.max(1)),
            low: ROWS[r],
            high: COLUMNS[c],
            phase: [0.0; 2],
            // A sine's RMS is its peak over sqrt 2.
            amplitude: 10f64.powf(level_dbov / 20.0) * std::f64::consts::SQRT_2,
        })
    }

    /// Adds the next samples of the tone pair to `out` (mono).
    pub fn mix_into(&mut self, out: &mut [f32]) {
        let tau = 2.0 * std::f64::consts::PI;
        for s in out {
            let v = self.amplitude * (self.phase[0].sin() + self.phase[1].sin());
            *s = (f64::from(*s) + v).clamp(-1.0, 1.0) as f32;
            self.phase[0] = (self.phase[0] + tau * self.low / self.rate) % tau;
            self.phase[1] = (self.phase[1] + tau * self.high / self.rate) % tau;
        }
    }
}

/// The mean-square power of the `hz` component of `x` (Goertzel).
fn goertzel(x: &[f32], rate: f64, hz: f64) -> f64 {
    let coeff = 2.0 * (2.0 * std::f64::consts::PI * hz / rate).cos();
    let (mut s1, mut s2) = (0.0f64, 0.0f64);
    for &v in x {
        let s0 = f64::from(v) + coeff * s1 - s2;
        s2 = s1;
        s1 = s0;
    }
    let n = x.len() as f64;
    2.0 * (s1 * s1 + s2 * s2 - coeff * s1 * s2) / (n * n)
}

/// Detects in-band DTMF in 20 ms blocks: a key is reported once its pair has been the
/// strongest, with an acceptable twist and most of the block's power, in two blocks in a
/// row (40 ms, Q.24's shortest tone), and released after two blocks without it.
#[derive(Debug, Clone)]
pub struct DtmfDetector {
    rate: f64,
    block: usize,
    pending: Vec<f32>,
    candidate: Option<char>,
    hits: u32,
    misses: u32,
    current: Option<char>,
}

impl DtmfDetector {
    /// A detector for audio at `sample_rate`.
    pub fn new(sample_rate: u32) -> Self {
        Self {
            rate: f64::from(sample_rate.max(1)),
            block: (sample_rate / 50) as usize,
            pending: Vec::new(),
            candidate: None,
            hits: 0,
            misses: 0,
            current: None,
        }
    }

    /// The key being held, if any.
    pub fn current(&self) -> Option<char> {
        self.current
    }

    /// Takes the next samples (mono); returns each key that began in them.
    pub fn process(&mut self, samples: &[f32]) -> Vec<char> {
        self.pending.extend_from_slice(samples);
        let mut started = Vec::new();
        while self.pending.len() >= self.block {
            let block: Vec<f32> = self.pending.drain(..self.block).collect();
            let key = self.classify(&block);
            match key {
                Some(k) if Some(k) == self.candidate => self.hits += 1,
                Some(k) => {
                    self.candidate = Some(k);
                    self.hits = 1;
                }
                None => {
                    self.candidate = None;
                    self.hits = 0;
                }
            }
            if key.is_some() && key == self.current {
                self.misses = 0;
            } else if self.current.is_some() {
                self.misses += 1;
                if self.misses >= 2 {
                    self.current = None;
                    self.misses = 0;
                }
            }
            if self.current.is_none() && self.hits >= 2 {
                self.current = self.candidate;
                if let Some(k) = self.current {
                    started.push(k);
                }
            }
        }
        started
    }

    fn classify(&self, block: &[f32]) -> Option<char> {
        let total = block.iter().map(|v| f64::from(*v).powi(2)).sum::<f64>() / block.len() as f64;
        // Below about -40 dBov for the pair nothing is a tone.
        if total < 1e-4 {
            return None;
        }
        let rows: Vec<f64> = ROWS
            .iter()
            .map(|&f| goertzel(block, self.rate, f))
            .collect();
        let cols: Vec<f64> = COLUMNS
            .iter()
            .map(|&f| goertzel(block, self.rate, f))
            .collect();
        let best = |v: &[f64]| {
            let (i, &p) = v
                .iter()
                .enumerate()
                .max_by(|a, b| a.1.total_cmp(b.1))
                .expect("four bins");
            let second = v
                .iter()
                .enumerate()
                .filter(|(j, _)| *j != i)
                .map(|(_, &q)| q)
                .fold(0.0, f64::max);
            (i, p, second)
        };
        let (r, pr, r2) = best(&rows);
        let (c, pc, c2) = best(&cols);
        // Each tone clearly above the others of its group (6 dB).
        if pr < 4.0 * r2 || pc < 4.0 * c2 {
            return None;
        }
        // Twist: the high tone at most 4 dB below or 8 dB above the low one (Q.24 ranges).
        let twist = 10.0 * (pc / pr).log10();
        if !(-8.0..=4.0).contains(&twist) {
            return None;
        }
        // The pair is most of the block's power (each Goertzel power is its sine's mean
        // square).
        if pr + pc < 0.6 * total {
            return None;
        }
        Some(KEYS[r][c])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signal::Noise;

    #[test]
    fn every_key_generated_is_detected_once_and_noise_is_not_a_key() {
        for rate in [8000u32, 16_000, 48_000] {
            let mut det = DtmfDetector::new(rate);
            let mut keys = Vec::new();
            let block = (rate / 100) as usize;
            for key in "123A456B789C*0#D".chars() {
                let mut tone = DtmfGenerator::new(key, rate, -10.0).unwrap();
                // 80 ms of tone, 60 ms of quiet noise.
                for _ in 0..8 {
                    let mut f = vec![0.0f32; block];
                    tone.mix_into(&mut f);
                    keys.extend(det.process(&f));
                }
                let mut noise = Noise::new(u64::from(key), 0.001);
                for _ in 0..6 {
                    let mut f = vec![0.0f32; block];
                    noise.fill(&mut f);
                    keys.extend(det.process(&f));
                }
            }
            assert_eq!(
                keys.iter().collect::<String>(),
                "123A456B789C*0#D",
                "{rate} Hz"
            );
        }
        let mut det = DtmfDetector::new(8000);
        let mut noise = Noise::new(1, 0.1);
        let mut f = vec![0.0f32; 8000];
        noise.fill(&mut f);
        assert!(det.process(&f).is_empty());
    }
}
