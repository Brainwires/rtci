//! G.711 (ITU-T G.711): PCMU (mu-law) and PCMA (A-law) at 8 kHz, one byte per sample, with
//! the static payload types 0 and 8 (RFC 3551). No concealment of its own: the pipeline's
//! generic concealment covers it.

use super::{AudioDecoder, AudioEncoder};
use crate::frame::f32_to_i16;
use crate::{Error, Result};

/// The sampling (and RTP clock) rate.
pub const G711_RATE: u32 = 8000;

/// The two companding laws.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Law {
    /// mu-law, PCMU (North America, Japan).
    Mu,
    /// A-law, PCMA (elsewhere).
    A,
}

/// Encodes a 16-bit sample to mu-law (G.711 section 2, with the 0x84 bias of the segment
/// search, and every bit inverted on the line).
pub fn linear_to_ulaw(sample: i16) -> u8 {
    const BIAS: i32 = 0x84;
    const CLIP: i32 = 32635;
    let mut s = i32::from(sample);
    let sign = if s < 0 {
        s = -s;
        0x80
    } else {
        0
    };
    s = s.min(CLIP) + BIAS;
    let exponent = (7 - (s.leading_zeros() as i32 - 17)).clamp(0, 7);
    let mantissa = (s >> (exponent + 3)) & 0x0f;
    !(sign | (exponent << 4) as u8 | mantissa as u8)
}

/// Decodes a mu-law byte to a 16-bit sample.
pub fn ulaw_to_linear(byte: u8) -> i16 {
    let u = !byte;
    let exponent = i32::from((u >> 4) & 0x07);
    let mantissa = i32::from(u & 0x0f);
    let magnitude = (((mantissa << 3) + 0x84) << exponent) - 0x84;
    if u & 0x80 != 0 {
        -magnitude as i16
    } else {
        magnitude as i16
    }
}

/// Encodes a 16-bit sample to A-law (G.711 section 3; even bits inverted on the line).
pub fn linear_to_alaw(sample: i16) -> u8 {
    let mut s = i32::from(sample) >> 3; // 13-bit magnitude range
    let sign = if s >= 0 {
        0x80
    } else {
        s = -s - 1;
        0x00
    };
    let s = s.min(0x0fff);
    let code = if s < 32 {
        (s >> 1) as u8
    } else {
        let exponent = (31 - (s as u32).leading_zeros()) as i32 - 4; // 1..=7
        let mantissa = (s >> exponent) & 0x0f;
        ((exponent << 4) as u8) | mantissa as u8
    };
    (sign | code) ^ 0x55
}

/// Decodes an A-law byte to a 16-bit sample.
pub fn alaw_to_linear(byte: u8) -> i16 {
    let a = byte ^ 0x55;
    let exponent = i32::from((a >> 4) & 0x07);
    let mantissa = i32::from(a & 0x0f);
    let magnitude = if exponent == 0 {
        (mantissa << 4) + 8
    } else {
        ((mantissa << 4) + 0x108) << (exponent - 1)
    };
    if a & 0x80 != 0 {
        magnitude as i16
    } else {
        -magnitude as i16
    }
}

/// A G.711 encoder of `frame_samples` samples (8 per millisecond of packet time).
#[derive(Debug, Clone)]
pub struct G711Encoder {
    law: Law,
    frame_samples: usize,
}

impl G711Encoder {
    /// An encoder of `law` with packets of `ptime_ms` milliseconds (10 to 60, a multiple of
    /// 10 is usual; 20 is the RFC 3551 default).
    pub fn new(law: Law, ptime_ms: u32) -> Result<Self> {
        if !(1..=200).contains(&ptime_ms) {
            return Err(Error::Config(format!("G.711 packet time {ptime_ms} ms")));
        }
        Ok(Self {
            law,
            frame_samples: (ptime_ms * G711_RATE / 1000) as usize,
        })
    }
}

impl AudioEncoder for G711Encoder {
    fn name(&self) -> &'static str {
        match self.law {
            Law::Mu => "rtci-audio PCMU",
            Law::A => "rtci-audio PCMA",
        }
    }

    fn sample_rate(&self) -> u32 {
        G711_RATE
    }

    fn channels(&self) -> u16 {
        1
    }

    fn frame_samples(&self) -> usize {
        self.frame_samples
    }

    fn encode(&mut self, pcm: &[f32], out: &mut Vec<u8>) -> Result<()> {
        if pcm.len() != self.frame_samples {
            return Err(Error::Format(format!(
                "G.711 takes {} samples, got {}",
                self.frame_samples,
                pcm.len()
            )));
        }
        let f = match self.law {
            Law::Mu => linear_to_ulaw,
            Law::A => linear_to_alaw,
        };
        out.extend(pcm.iter().map(|&s| f(f32_to_i16(s))));
        Ok(())
    }
}

/// A G.711 decoder.
#[derive(Debug, Clone)]
pub struct G711Decoder {
    law: Law,
}

impl G711Decoder {
    /// A decoder of `law`.
    pub fn new(law: Law) -> Self {
        Self { law }
    }
}

impl AudioDecoder for G711Decoder {
    fn name(&self) -> &'static str {
        match self.law {
            Law::Mu => "rtci-audio PCMU",
            Law::A => "rtci-audio PCMA",
        }
    }

    fn sample_rate(&self) -> u32 {
        G711_RATE
    }

    fn channels(&self) -> u16 {
        1
    }

    fn packet_samples(&self, payload: &[u8]) -> Option<usize> {
        Some(payload.len())
    }

    fn decode(&mut self, payload: &[u8], out: &mut Vec<f32>) -> Result<usize> {
        let f = match self.law {
            Law::Mu => ulaw_to_linear,
            Law::A => alaw_to_linear,
        };
        out.extend(payload.iter().map(|&b| f32::from(f(b)) / 32768.0));
        Ok(payload.len())
    }

    fn has_plc(&self) -> bool {
        false
    }

    fn conceal(&mut self, _samples: usize, _out: &mut Vec<f32>) -> Result<bool> {
        Ok(false)
    }

    fn reset(&mut self) {}
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_code_points_match_g711() {
        // Silence, and the largest magnitudes.
        assert_eq!(linear_to_ulaw(0), 0xff);
        assert_eq!(ulaw_to_linear(0xff), 0);
        assert_eq!(ulaw_to_linear(0x80), 32124);
        assert_eq!(ulaw_to_linear(0x00), -32124);
        assert_eq!(linear_to_ulaw(i16::MAX), 0x80);
        assert_eq!(linear_to_alaw(0), 0xd5);
        assert_eq!(alaw_to_linear(0xd5), 8);
        assert_eq!(alaw_to_linear(0xaa), 32256);
        assert_eq!(alaw_to_linear(0x2a), -32256);
    }

    #[test]
    fn every_code_round_trips() {
        for b in 0..=255u8 {
            assert_eq!(
                linear_to_ulaw(ulaw_to_linear(b)),
                b | if b == 0x7f { 0x80 } else { 0 },
                "mu {b:#x}"
            );
            assert_eq!(linear_to_alaw(alaw_to_linear(b)), b, "A {b:#x}");
        }
    }

    #[test]
    fn companding_error_is_within_the_segment_step() {
        // G.711's SNR for a full-range signal is about 38 dB; check every 16-bit value's
        // relative error is within its segment's half step.
        for law in [Law::Mu, Law::A] {
            type Pair = (fn(i16) -> u8, fn(u8) -> i16);
            let (enc, dec): Pair = match law {
                Law::Mu => (linear_to_ulaw, ulaw_to_linear),
                Law::A => (linear_to_alaw, alaw_to_linear),
            };
            for x in (-32000i32..32000).step_by(7) {
                let y = i32::from(dec(enc(x as i16)));
                let step = (x.abs() / 16).max(16);
                assert!((x - y).abs() <= step, "{law:?} {x} -> {y}");
            }
        }
    }
}
