//! Voice activity detection on 10 ms frames: frame energy against a tracked noise floor, with
//! a hangover so that speech is not cut between words.
//!
//! It drives the RFC 6464 voice activity flag, discontinuous transmission for codecs that
//! have none of their own (G.711 and G.722 with RFC 3389 comfort noise) and the automatic gain
//! control, which only adapts to speech.

/// The detector's state.
#[derive(Debug, Clone)]
pub struct VoiceActivityDetector {
    /// The tracked noise floor, in dBFS.
    noise_db: f64,
    /// Frames of hangover left after the last speech frame.
    hang: u32,
    /// Speech frames in a row, for the onset rule.
    onset: u32,
    frames: u64,
    active: bool,
}

impl Default for VoiceActivityDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl VoiceActivityDetector {
    /// Frames of speech the hangover keeps after the last speech frame (200 ms).
    pub const HANGOVER_FRAMES: u32 = 20;
    /// How far above the noise floor a frame must be to be speech, in dB.
    pub const MARGIN_DB: f64 = 9.0;
    /// Frames below this are never speech (dBFS).
    pub const ABSOLUTE_FLOOR_DB: f64 = -62.0;
    /// How fast the floor rises while the level stays above it, dB per 10 ms frame (3 dB/s):
    /// steady noise is absorbed within seconds, speech's pauses keep it down.
    pub const RISE_DB_PER_FRAME: f64 = 0.03;

    /// A detector that has seen nothing.
    pub fn new() -> Self {
        Self {
            noise_db: -70.0,
            hang: 0,
            onset: 0,
            frames: 0,
            active: false,
        }
    }

    /// The level of a frame in dBFS (mean square of `samples`, -120 for silence).
    pub fn frame_db(samples: &[f32]) -> f64 {
        if samples.is_empty() {
            return -120.0;
        }
        let ms = samples.iter().map(|s| f64::from(*s).powi(2)).sum::<f64>() / samples.len() as f64;
        if ms <= 1e-12 {
            -120.0
        } else {
            10.0 * ms.log10()
        }
    }

    /// Classifies one 10 ms frame (mono, any rate). Returns whether it is speech, the
    /// hangover included.
    pub fn process(&mut self, samples: &[f32]) -> bool {
        let db = Self::frame_db(samples);
        self.frames += 1;
        // Noise floor: follow the level down at once, up slowly. The first frames set it.
        if self.frames <= 5 {
            self.noise_db = if self.frames == 1 {
                db
            } else {
                self.noise_db.min(db)
            };
        } else if db < self.noise_db {
            self.noise_db = 0.7 * self.noise_db + 0.3 * db;
        } else {
            self.noise_db = (self.noise_db + Self::RISE_DB_PER_FRAME).min(db);
        }
        let speech = db > Self::ABSOLUTE_FLOOR_DB && db > self.noise_db + Self::MARGIN_DB;
        if speech {
            self.onset += 1;
        } else {
            self.onset = 0;
        }
        if speech && (self.active || self.onset >= 2) {
            self.active = true;
            self.hang = Self::HANGOVER_FRAMES;
        } else if self.hang > 0 {
            self.hang -= 1;
        } else {
            self.active = false;
        }
        self.active
    }

    /// The last decision.
    pub fn is_active(&self) -> bool {
        self.active
    }

    /// The tracked noise floor in dBFS.
    pub fn noise_floor_db(&self) -> f64 {
        self.noise_db
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signal::{Noise, SpeechLike};

    #[test]
    fn speech_over_noise_is_found_and_noise_alone_is_not() {
        let mut vad = VoiceActivityDetector::new();
        let mut noise = Noise::new(1, 0.003);
        let mut speech = SpeechLike::new(48_000, 7);
        let mut frame = vec![0.0f32; 480];
        // Two seconds of noise: never speech once the floor is set.
        let mut noise_active = 0;
        for _ in 0..200 {
            noise.fill(&mut frame);
            if vad.process(&frame) {
                noise_active += 1;
            }
        }
        assert!(noise_active <= 2, "{noise_active} noise frames as speech");
        // Speech-like bursts over the same noise: most voiced frames are found.
        let mut found = 0;
        let mut voiced = 0;
        for _ in 0..300 {
            speech.fill(&mut frame);
            let is_voiced = speech.voiced();
            let mut n = vec![0.0f32; 480];
            noise.fill(&mut n);
            for (s, v) in frame.iter_mut().zip(&n) {
                *s += v;
            }
            let active = vad.process(&frame);
            if is_voiced {
                voiced += 1;
                if active {
                    found += 1;
                }
            }
        }
        println!(
            "MEASURE VAD: {found} of {voiced} speech frames found, {noise_active} of 200 noise frames taken for speech"
        );
        assert!(voiced > 100);
        // The syllables' attacks and decays and the quiet fricatives are below the margin.
        assert!(found as f64 / voiced as f64 > 0.8, "{found} / {voiced}");
    }
}
