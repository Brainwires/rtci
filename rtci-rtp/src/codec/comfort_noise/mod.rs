//! Comfort noise payload format ([RFC 3389]).
//!
//! A CN payload is a noise level byte followed by `M` quantised reflection coefficients of an
//! all-pole noise model (any model order, `M = 0` included):
//!
//! ```text
//!   Byte    1      2    3    ...   M+1
//!        +-----+-----+-----+-----+-----+
//!        |level|  N1 |  N2 | ... |  NM |
//!        +-----+-----+-----+-----+-----+
//! ```
//!
//! RTP usage (section 4): the static payload type `CN_STATIC_PAYLOAD_TYPE` (13) is CN at
//! `CN_STATIC_CLOCK_RATE` (8000 Hz); any other clock rate MUST use a dynamic payload type.
//! The RTP timestamp is the start of the noise period, the marker bit SHOULD NOT be set on CN
//! packets, and each packet carries exactly one CN payload per channel, every channel with the
//! same model order (`unmarshal_channels`, `marshal_channels`).
//!
//! Noise analysis and synthesis are the codec's job; this module only carries the parameters.
//!
//! [RFC 3389]: https://datatracker.ietf.org/doc/html/rfc3389
#[cfg(test)]
mod comfort_noise_test;

use crate::packetizer::{Depacketizer, MarkerRule, Payloader};
use bytes::{Buf, BufMut, Bytes, BytesMut};
use shared::error::{Error, Result};
use shared::marshal::{Marshal, MarshalSize, Unmarshal};

/// The static RTP payload type of CN at 8000 Hz (RFC 3389 section 4, RFC 3551).
pub const CN_STATIC_PAYLOAD_TYPE: u8 = 13;
/// Clock rate of [`CN_STATIC_PAYLOAD_TYPE`]. Other rates use dynamic payload types.
pub const CN_STATIC_CLOCK_RATE: u32 = 8000;
/// The largest noise level, in -dBov (section 3.1).
pub const CN_MAX_LEVEL: u8 = 127;
/// The largest valid quantised reflection coefficient index; 255 is reserved (section 3.2).
pub const CN_MAX_COEFFICIENT_INDEX: u8 = 254;
/// The quantised index of a zero reflection coefficient: `k(127) = 0`.
pub const CN_ZERO_COEFFICIENT_INDEX: u8 = 127;

/// One comfort-noise payload (sections 3.1 to 3.3).
#[derive(PartialEq, Eq, Debug, Default, Clone)]
pub struct ComfortNoise {
    /// Noise level in -dBov, 0 to 127 (0 to -127 dBov).
    pub level: u8,
    /// Quantised reflection coefficients `N_1 ... N_M`, ascending order; the model order `M`
    /// is their count.
    pub coefficients: Bytes,
}

impl ComfortNoise {
    /// The model order `M`.
    pub fn model_order(&self) -> usize {
        self.coefficients.len()
    }

    /// The quantised coefficients a decoder of model order `order` uses: extra coefficients
    /// are ignored and missing ones are zero (section 3.2), a zero coefficient being index
    /// [`CN_ZERO_COEFFICIENT_INDEX`].
    pub fn coefficients_for_order(&self, order: usize) -> Vec<u8> {
        let mut out: Vec<u8> = self.coefficients.iter().copied().take(order).collect();
        out.resize(order, CN_ZERO_COEFFICIENT_INDEX);
        out
    }

    /// The reflection coefficients `k_1 ... k_order` (extra ignored, missing ones 0.0). A
    /// reserved index (255) is taken as 0.0.
    pub fn reflection_coefficients(&self, order: usize) -> Vec<f64> {
        self.coefficients_for_order(order)
            .into_iter()
            .map(|n| reflection_coefficient(n).unwrap_or(0.0))
            .collect()
    }
}

/// The reflection coefficient of a quantised index (section 3.2):
/// `k_i = 258 * (N_i - 127) / 32768`. `None` for the reserved index 255.
pub fn reflection_coefficient(index: u8) -> Option<f64> {
    if index > CN_MAX_COEFFICIENT_INDEX {
        return None;
    }
    Some(258.0 * (f64::from(index) - 127.0) / 32768.0)
}

/// The quantised index of a reflection coefficient, the inverse of
/// [`reflection_coefficient`]: `N_i = round(k_i * 32768 / 258) + 127`, clamped to 0..=254.
/// A NaN maps to the zero coefficient.
pub fn quantize_reflection_coefficient(k: f64) -> u8 {
    if k.is_nan() {
        return CN_ZERO_COEFFICIENT_INDEX;
    }
    let n = (k * 32768.0 / 258.0).round() + 127.0;
    n.clamp(0.0, f64::from(CN_MAX_COEFFICIENT_INDEX)) as u8
}

impl MarshalSize for ComfortNoise {
    fn marshal_size(&self) -> usize {
        1 + self.coefficients.len()
    }
}

impl Marshal for ComfortNoise {
    /// Writes the level byte (MSB zero) and the coefficients. Fails on a level above 127.
    fn marshal_to(&self, mut buf: &mut [u8]) -> Result<usize> {
        let size = self.marshal_size();
        if buf.remaining_mut() < size {
            return Err(Error::ErrBufferTooSmall);
        }
        if self.level > CN_MAX_LEVEL {
            return Err(Error::Other(format!(
                "comfort-noise level {} exceeds {CN_MAX_LEVEL}",
                self.level
            )));
        }
        buf.put_u8(self.level);
        buf.put_slice(&self.coefficients);
        Ok(size)
    }
}

impl Unmarshal for ComfortNoise {
    /// Reads a whole CN payload: everything remaining in `buf`.
    ///
    /// Receiver-lenient on the level byte: section 3.1 says its MSB is "unused and always set
    /// to 0", so a set MSB is masked off rather than rejected (the level is the seven low
    /// bits). The sender side ([`Marshal`]) never sets it. Coefficient bytes are kept as
    /// received, the reserved index 255 included.
    ///
    /// Fails on an empty payload.
    fn unmarshal<B>(buf: &mut B) -> Result<Self>
    where
        Self: Sized,
        B: Buf,
    {
        if !buf.has_remaining() {
            return Err(Error::ErrShortPacket);
        }
        let level = buf.get_u8() & 0x7F;
        let coefficients = buf.copy_to_bytes(buf.remaining());
        Ok(ComfortNoise {
            level,
            coefficients,
        })
    }
}

/// Splits a packet's payload into one CN payload per channel (section 4).
///
/// All channels have the same model order, so the payload length must be a non-zero multiple
/// of `channels`.
///
/// # Errors
///
/// Fails with zero channels, an empty payload, or a length that does not divide evenly.
pub fn unmarshal_channels(payload: &Bytes, channels: usize) -> Result<Vec<ComfortNoise>> {
    if channels == 0 {
        return Err(Error::Other(
            "comfort noise needs at least one channel".into(),
        ));
    }
    if payload.is_empty() || !payload.len().is_multiple_of(channels) {
        return Err(Error::ErrShortPacket);
    }
    let per_channel = payload.len() / channels;
    (0..channels)
        .map(|i| {
            let mut chunk = payload.slice(i * per_channel..(i + 1) * per_channel);
            ComfortNoise::unmarshal(&mut chunk)
        })
        .collect()
}

/// Concatenates one CN payload per channel, channel order as given (section 4).
///
/// # Errors
///
/// Fails on an empty list, channels whose model orders differ, or a level above 127.
pub fn marshal_channels(channels: &[ComfortNoise]) -> Result<Bytes> {
    let Some(first) = channels.first() else {
        return Err(Error::Other(
            "comfort noise needs at least one channel".into(),
        ));
    };
    let order = first.model_order();
    if channels.iter().any(|c| c.model_order() != order) {
        return Err(Error::Other(
            "every comfort-noise channel must use the same model order".into(),
        ));
    }
    let mut out = BytesMut::zeroed(channels.len() * (order + 1));
    for (i, channel) in channels.iter().enumerate() {
        let start = i * (order + 1);
        channel.marshal_to(&mut out[start..start + order + 1])?;
    }
    Ok(out.freeze())
}

/// Payloads CN: one CN payload per RTP packet, never fragmented.
///
/// CN packets do not have the marker bit set (RFC 3389 section 4): the payloader's
/// [`marker_rule`](Payloader::marker_rule) is [`MarkerRule::Never`], which is what a
/// [`Packetizer`](crate::packetizer::Packetizer) built on it follows.
#[derive(Default, Debug, Copy, Clone)]
pub struct ComfortNoisePayloader;

impl Payloader for ComfortNoisePayloader {
    fn payload(&mut self, mtu: usize, payload: &Bytes) -> Result<Vec<Bytes>> {
        if payload.is_empty() || mtu == 0 {
            return Ok(vec![]);
        }
        Ok(vec![payload.clone()])
    }

    fn marker_rule(&self) -> MarkerRule {
        MarkerRule::Never
    }

    fn clone_to(&self) -> Box<dyn Payloader> {
        Box::new(*self)
    }
}

/// Depacketizes CN: the payload is one CN payload (or one per channel), returned as is.
#[derive(PartialEq, Eq, Debug, Default, Clone)]
pub struct ComfortNoisePacket;

impl Depacketizer for ComfortNoisePacket {
    fn depacketize(&mut self, packet: &Bytes) -> Result<Bytes> {
        if packet.is_empty() {
            Err(Error::ErrShortPacket)
        } else {
            Ok(packet.clone())
        }
    }

    fn is_partition_head(&self, _payload: &Bytes) -> bool {
        true
    }

    fn is_partition_tail(&self, _marker: bool, _payload: &Bytes) -> bool {
        true
    }
}
