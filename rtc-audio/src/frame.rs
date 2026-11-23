//! PCM frames: interleaved `f32` samples at a stated rate and channel count.
//!
//! Samples are linear, full scale at ±1.0 (0 dBFS; `i16::MAX` maps to 1.0 - 2^-15). Every
//! stage of the pipeline works on 10 ms frames ([`frame_samples`]).

use crate::{Error, Result};

/// The samples per channel in 10 ms at `sample_rate`.
pub const fn frame_samples(sample_rate: u32) -> usize {
    (sample_rate / 100) as usize
}

/// Interleaved PCM: `samples.len()` is a multiple of `channels`.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct AudioFrame {
    /// Interleaved samples, ±1.0 full scale.
    pub samples: Vec<f32>,
    /// Samples per second, per channel.
    pub sample_rate: u32,
    /// Interleaved channels (1 or 2 in this crate).
    pub channels: u16,
}

impl AudioFrame {
    /// A frame of `samples_per_channel` zeroes.
    pub fn silence(sample_rate: u32, channels: u16, samples_per_channel: usize) -> Self {
        Self {
            samples: vec![0.0; samples_per_channel * usize::from(channels.max(1))],
            sample_rate,
            channels: channels.max(1),
        }
    }

    /// A frame of `samples` (interleaved). Fails when their count is not a multiple of
    /// `channels`, or `channels` is 0.
    pub fn new(samples: Vec<f32>, sample_rate: u32, channels: u16) -> Result<Self> {
        if channels == 0 || !samples.len().is_multiple_of(usize::from(channels)) {
            return Err(Error::Format(format!(
                "{} samples are not a whole number of {channels}-channel frames",
                samples.len()
            )));
        }
        Ok(Self {
            samples,
            sample_rate,
            channels,
        })
    }

    /// Samples per channel.
    pub fn samples_per_channel(&self) -> usize {
        self.samples.len() / usize::from(self.channels.max(1))
    }

    /// The frame's duration in seconds.
    pub fn duration_secs(&self) -> f64 {
        self.samples_per_channel() as f64 / f64::from(self.sample_rate.max(1))
    }
}

/// `f32` to 16-bit PCM, rounded and saturated.
pub fn f32_to_i16(v: f32) -> i16 {
    (v * 32768.0).round().clamp(-32768.0, 32767.0) as i16
}

/// 16-bit PCM to `f32`.
pub fn i16_to_f32(v: i16) -> f32 {
    f32::from(v) / 32768.0
}

/// Converts interleaved audio from `from` to `to` channels: a stereo source is mixed down to
/// mono by averaging, a mono source is copied to both channels. Other counts are refused.
pub fn convert_channels(input: &[f32], from: u16, to: u16, out: &mut Vec<f32>) -> Result<()> {
    match (from, to) {
        (a, b) if a == b => out.extend_from_slice(input),
        (2, 1) => out.extend(input.as_chunks::<2>().0.iter().map(|p| 0.5 * (p[0] + p[1]))),
        (1, 2) => {
            for &s in input {
                out.push(s);
                out.push(s);
            }
        }
        _ => {
            return Err(Error::Format(format!(
                "no conversion from {from} to {to} channels"
            )));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stereo_mixes_down_and_mono_spreads() {
        let mut out = Vec::new();
        convert_channels(&[1.0, 0.0, 0.5, 0.5], 2, 1, &mut out).unwrap();
        assert_eq!(out, [0.5, 0.5]);
        out.clear();
        convert_channels(&[0.25, -0.5], 1, 2, &mut out).unwrap();
        assert_eq!(out, [0.25, 0.25, -0.5, -0.5]);
        assert!(convert_channels(&[0.0; 6], 3, 1, &mut out).is_err());
    }

    #[test]
    fn a_frame_must_hold_whole_sample_frames() {
        assert!(AudioFrame::new(vec![0.0; 3], 48_000, 2).is_err());
        let f = AudioFrame::new(vec![0.0; 960], 48_000, 2).unwrap();
        assert_eq!(f.samples_per_channel(), 480);
        assert!((f.duration_secs() - 0.01).abs() < 1e-12);
    }

    #[test]
    fn sixteen_bit_conversion_saturates() {
        assert_eq!(f32_to_i16(2.0), i16::MAX);
        assert_eq!(f32_to_i16(-2.0), i16::MIN);
        assert_eq!(f32_to_i16(i16_to_f32(1234)), 1234);
    }
}
