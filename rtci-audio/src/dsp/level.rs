//! Audio levels: the W3C `audioLevel` / `totalAudioEnergy` / `totalSamplesDuration` meters
//! (webrtc-stats 8.6, 8.20) and the RFC 6464 client-to-mixer level.

/// The W3C audio level meter of a stream (`RTCInboundRtpStreamStats` for received audio,
/// `RTCAudioSourceStats` for captured audio).
///
/// - `audioLevel` is the peak absolute sample over the last 100 ms window, linear, 0 to 1
///   (1 is 0 dBov), as libwebrtc measures it; updated at the end of each window.
/// - `totalAudioEnergy` adds, for each sample time, its duration multiplied by the square of
///   its level (webrtc-stats: "for each audio sample ... the duration of the sample in seconds
///   multiplied by the square of the audioLevel of the sample"): `sum(x^2) / rate`, with `x^2`
///   the mean square across channels. So `sqrt(dEnergy / dDuration)` is the RMS level over an
///   interval.
/// - `totalSamplesDuration` adds every sample time's duration.
#[derive(Debug, Clone, Default)]
pub struct LevelMeter {
    window_peak: f32,
    window_samples: usize,
    level: f64,
    total_energy: f64,
    total_duration: f64,
}

impl LevelMeter {
    /// The window `audioLevel` is the peak of.
    pub const WINDOW_SECS: f64 = 0.1;

    /// A meter with nothing measured.
    pub fn new() -> Self {
        Self::default()
    }

    /// Measures interleaved `samples` of `channels` channels at `sample_rate`.
    pub fn process(&mut self, samples: &[f32], channels: u16, sample_rate: u32) {
        let channels = usize::from(channels.max(1));
        let rate = f64::from(sample_rate.max(1));
        let window = (rate * Self::WINDOW_SECS) as usize;
        let mut energy = 0.0f64;
        for frame in samples.chunks_exact(channels) {
            let mut sq = 0.0f64;
            for &s in frame {
                let a = s.abs().min(1.0);
                self.window_peak = self.window_peak.max(a);
                sq += f64::from(a) * f64::from(a);
            }
            energy += sq / channels as f64;
            self.window_samples += 1;
            if self.window_samples >= window {
                self.level = f64::from(self.window_peak);
                self.window_peak = 0.0;
                self.window_samples = 0;
            }
        }
        let n = samples.len() / channels;
        self.total_energy += energy / rate;
        self.total_duration += n as f64 / rate;
    }

    /// `audioLevel`, 0 to 1.
    pub fn audio_level(&self) -> f64 {
        self.level
    }

    /// `totalAudioEnergy`.
    pub fn total_audio_energy(&self) -> f64 {
        self.total_energy
    }

    /// `totalSamplesDuration`, in seconds.
    pub fn total_samples_duration(&self) -> f64 {
        self.total_duration
    }
}

/// The RFC 6464 audio level of a packet's audio: its RMS in -dBov (0 is a full-scale square
/// wave, 127 is silence or below -127 dBov), rounded.
pub fn rfc6464_level(samples: &[f32]) -> u8 {
    if samples.is_empty() {
        return 127;
    }
    let ms = samples.iter().map(|s| f64::from(*s).powi(2)).sum::<f64>() / samples.len() as f64;
    if ms <= 0.0 {
        return 127;
    }
    let db = -10.0 * ms.log10();
    db.round().clamp(0.0, 127.0) as u8
}

/// The linear level (0 to 1, as `audioLevel`) of an RFC 6464 level in -dBov.
pub fn linear_from_rfc6464(level: u8) -> f64 {
    if level >= 127 {
        0.0
    } else {
        10f64.powf(-f64::from(level) / 20.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn energy_over_duration_is_the_mean_square() {
        let mut m = LevelMeter::new();
        let x: Vec<f32> = (0..48_000)
            .map(|i| {
                (0.5 * (2.0 * std::f64::consts::PI * 440.0 * f64::from(i) / 48_000.0).sin()) as f32
            })
            .collect();
        m.process(&x, 1, 48_000);
        assert!((m.total_samples_duration() - 1.0).abs() < 1e-9);
        // A sine of amplitude 0.5 has mean square 0.125.
        assert!((m.total_audio_energy() - 0.125).abs() < 1e-3);
        assert!((m.audio_level() - 0.5).abs() < 1e-3);
    }

    #[test]
    fn the_level_is_the_peak_of_the_last_window() {
        let mut m = LevelMeter::new();
        let mut x = vec![0.0f32; 4800];
        x[100] = 0.8;
        m.process(&x, 1, 48_000);
        assert!((m.audio_level() - 0.8).abs() < 1e-6);
        m.process(&[0.1; 4800], 1, 48_000);
        assert!((m.audio_level() - 0.1).abs() < 1e-6);
    }

    #[test]
    fn rfc6464_levels_are_minus_dbov() {
        assert_eq!(rfc6464_level(&[1.0; 100]), 0);
        assert_eq!(rfc6464_level(&[0.0; 100]), 127);
        assert_eq!(rfc6464_level(&[0.1; 100]), 20);
        assert!((linear_from_rfc6464(20) - 0.1).abs() < 1e-9);
        assert_eq!(linear_from_rfc6464(127), 0.0);
    }
}
