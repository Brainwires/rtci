//! Automatic gain control: an adaptive digital gain that brings the speech level to a
//! target and a limiter that keeps peaks below -1 dBFS.
//!
//! The level follows speech frames only (the voice activity detector's), so pauses and
//! background noise are not amplified to the target. The default target is RFC 7874
//! section 4's -19 dBm0, an RMS of 2600 in 16-bit samples (-22 dBFS); the gain moves at most
//! 6 dB a second up and 30 dB a second down, between -10 and +30 dB.

/// The gain controller's state.
#[derive(Debug, Clone)]
pub struct GainController {
    target_db: f64,
    /// The speech level as a mean square (despite the name).
    level_db: Option<f64>,
    gain_db: f64,
    applied: f32,
    max_gain_db: f64,
    min_gain_db: f64,
}

impl Default for GainController {
    fn default() -> Self {
        Self::new(Self::RFC7874_TARGET_DBFS)
    }
}

impl GainController {
    /// RFC 7874's -19 dBm0 (RMS 2600 of 32768) in dBFS.
    pub const RFC7874_TARGET_DBFS: f64 = -21.98;
    const LIMIT: f32 = 0.891; // -1 dBFS

    /// A controller aiming at `target_dbfs` (RMS of speech).
    pub fn new(target_dbfs: f64) -> Self {
        Self {
            target_db: target_dbfs,
            level_db: None,
            gain_db: 0.0,
            applied: 1.0,
            max_gain_db: 30.0,
            min_gain_db: -10.0,
        }
    }

    /// The gain applied now, in dB.
    pub fn gain_db(&self) -> f64 {
        self.gain_db
    }

    /// Processes one 10 ms frame in place; `speech` is the voice activity decision for it.
    pub fn process(&mut self, frame: &mut [f32], speech: bool) {
        if speech {
            // The speech level is its RMS (a mean of powers, not of decibels), as RFC 7874's
            // target is.
            let p = 10f64.powf(crate::dsp::vad::VoiceActivityDetector::frame_db(frame) / 10.0);
            self.level_db = Some(match self.level_db {
                None => p,
                Some(l) => 0.97 * l + 0.03 * p,
            });
        }
        if let Some(level) = self.level_db.map(|p| 10.0 * p.max(1e-12).log10()) {
            let want = (self.target_db - level).clamp(self.min_gain_db, self.max_gain_db);
            let step = if want > self.gain_db { 0.06 } else { 0.3 };
            self.gain_db += (want - self.gain_db).clamp(-step, step);
        }
        let target = 10f64.powf(self.gain_db / 20.0) as f32;
        // Ramp the gain over the frame, then limit.
        let n = frame.len().max(1) as f32;
        let start = self.applied;
        let peak = frame
            .iter()
            .enumerate()
            .map(|(i, v)| (v * (start + (target - start) * (i as f32 + 1.0) / n)).abs())
            .fold(0.0f32, f32::max);
        let limit = if peak > Self::LIMIT {
            Self::LIMIT / peak
        } else {
            1.0
        };
        for (i, v) in frame.iter_mut().enumerate() {
            let g = start + (target - start) * (i as f32 + 1.0) / n;
            *v *= g * limit;
        }
        self.applied = target;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dsp::vad::VoiceActivityDetector;
    use crate::signal::SpeechLike;

    fn speech_level_after(scale: f32) -> (f64, f32) {
        let mut agc = GainController::default();
        let mut vad = VoiceActivityDetector::new();
        let mut src = SpeechLike::new(48_000, 12);
        let mut frame = vec![0.0f32; 480];
        let (mut energy, mut count, mut peak) = (0.0f64, 0usize, 0.0f32);
        for i in 0..3000 {
            src.fill(&mut frame);
            frame.iter_mut().for_each(|v| *v *= scale);
            let voiced = src.voiced();
            let speech = vad.process(&frame);
            agc.process(&mut frame, speech);
            if i > 1500 && voiced {
                energy += frame.iter().map(|v| f64::from(*v).powi(2)).sum::<f64>() / 480.0;
                count += 1;
            }
            peak = frame.iter().fold(peak, |p, v| p.max(v.abs()));
        }
        (10.0 * (energy / count as f64).log10(), peak)
    }

    #[test]
    fn quiet_and_loud_speech_end_near_the_target_and_never_clip() {
        for scale in [0.05f32, 0.5, 3.0] {
            let (db, peak) = speech_level_after(scale);
            assert!(
                (db - GainController::RFC7874_TARGET_DBFS).abs() < 4.0,
                "x{scale}: {db:.1} dBFS"
            );
            assert!(peak <= 0.9, "x{scale}: peak {peak}");
        }
    }
}
