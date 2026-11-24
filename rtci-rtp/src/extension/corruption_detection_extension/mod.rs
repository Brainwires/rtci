#[cfg(test)]
mod corruption_detection_extension_test;

use shared::{
    error::{Error, Result},
    marshal::{Marshal, MarshalSize, Unmarshal},
};

use bytes::{Buf, BufMut};

/// The size of a synchronization message: the first byte only.
pub const CORRUPTION_DETECTION_SYNC_SIZE: usize = 1;
/// The size of a full message's fixed part, before the samples.
pub const CORRUPTION_DETECTION_HEADER_SIZE: usize = 3;
/// The most samples a message carries.
pub const CORRUPTION_DETECTION_MAX_SAMPLES: usize = 13;
/// The largest Halton sequence index (14 bits) plus one: the index wraps here.
pub const CORRUPTION_DETECTION_SEQUENCE_INDEX_MODULO: u16 = 1 << 14;

/// The corruption detection extension
/// (`http://www.webrtc.org/experiments/rtp-hdrext/corruption-detection`, a libwebrtc
/// experiment that W3C webrtc-stats 8.5 names for `corruptionMeasurements`): samples of the
/// sender's source image a receiver compares with its decoded frame to estimate whether the
/// frame is corrupted. Carried in at most one packet of a video frame.
///
/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |B|  seq index  |    std dev    | Y err | UV err|    sample 0   |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |    sample 1   |   sample 2    |    …   up to sample 12        |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
///
/// A synchronization message is the first byte alone: it carries the sequence index and no
/// samples.
#[derive(PartialEq, Eq, Debug, Default, Clone)]
pub struct CorruptionDetectionExtension {
    /// B: the 7 bits of `sequence_index` are the most significant of the 14-bit Halton
    /// sequence index (its 7 least significant bits are 0). Set on key frames.
    pub interpret_sequence_index_as_most_significant_bits: bool,
    /// The 7 bits of the Halton sequence index of the first sample (the low ones unless B).
    pub sequence_index: u8,
    /// The standard deviation of the Gaussian filter the samples were taken with, as sent:
    /// 0..=255 maps linearly onto 0.0..=40.0 ([`Self::std_dev`]); 0 means no filtering.
    pub std_dev: u8,
    /// The error allowed for a luma sample (4 bits).
    pub luma_error_threshold: u8,
    /// The error allowed for a chroma sample (4 bits).
    pub chroma_error_threshold: u8,
    /// The filtered sample values of the source image, at most
    /// [`CORRUPTION_DETECTION_MAX_SAMPLES`]; empty in a synchronization message.
    pub sample_values: Vec<u8>,
    /// A synchronization message (the first byte only).
    pub synchronization: bool,
}

impl CorruptionDetectionExtension {
    /// The standard deviation of the Gaussian filter, 0.0..=40.0.
    pub fn std_dev(&self) -> f64 {
        f64::from(self.std_dev) / 255.0 * 40.0
    }

    /// The 14-bit Halton sequence index of the first sample, given the receiver's last
    /// known index (`previous`): with B set the 7 bits are the high ones and the low ones 0;
    /// without, they replace the low 7 bits of `previous`, carrying into the high ones when
    /// they wrapped.
    pub fn full_sequence_index(&self, previous: u16) -> u16 {
        let bits = u16::from(self.sequence_index & 0x7f);
        if self.interpret_sequence_index_as_most_significant_bits {
            return bits << 7;
        }
        let previous = previous % CORRUPTION_DETECTION_SEQUENCE_INDEX_MODULO;
        let mut index = (previous & !0x7f) | bits;
        if index < previous {
            index = (index + 0x80) % CORRUPTION_DETECTION_SEQUENCE_INDEX_MODULO;
        }
        index
    }
}

impl Unmarshal for CorruptionDetectionExtension {
    /// # Errors
    ///
    /// Fails for an element of 2 bytes or of more than 16 (a fixed part and at most 13
    /// samples), and for an empty one.
    fn unmarshal<B>(buf: &mut B) -> Result<Self>
    where
        Self: Sized,
        B: Buf,
    {
        let len = buf.remaining();
        if len == 0
            || len == 2
            || len > CORRUPTION_DETECTION_HEADER_SIZE + CORRUPTION_DETECTION_MAX_SAMPLES
        {
            return Err(Error::ErrBufferTooSmall);
        }
        let first = buf.get_u8();
        let mut extension = CorruptionDetectionExtension {
            interpret_sequence_index_as_most_significant_bits: first & 0x80 != 0,
            sequence_index: first & 0x7f,
            synchronization: len == CORRUPTION_DETECTION_SYNC_SIZE,
            ..Default::default()
        };
        if len == CORRUPTION_DETECTION_SYNC_SIZE {
            return Ok(extension);
        }
        extension.std_dev = buf.get_u8();
        let errors = buf.get_u8();
        extension.luma_error_threshold = errors >> 4;
        extension.chroma_error_threshold = errors & 0x0f;
        extension.sample_values = buf.copy_to_bytes(buf.remaining()).to_vec();
        Ok(extension)
    }
}

impl MarshalSize for CorruptionDetectionExtension {
    fn marshal_size(&self) -> usize {
        if self.synchronization {
            CORRUPTION_DETECTION_SYNC_SIZE
        } else {
            CORRUPTION_DETECTION_HEADER_SIZE + self.sample_values.len()
        }
    }
}

impl Marshal for CorruptionDetectionExtension {
    /// # Errors
    ///
    /// Fails for more than [`CORRUPTION_DETECTION_MAX_SAMPLES`] samples, a synchronization
    /// message with samples, or a buffer too small.
    fn marshal_to(&self, mut buf: &mut [u8]) -> Result<usize> {
        if self.sample_values.len() > CORRUPTION_DETECTION_MAX_SAMPLES
            || (self.synchronization && !self.sample_values.is_empty())
            || buf.remaining_mut() < self.marshal_size()
        {
            return Err(Error::ErrBufferTooSmall);
        }
        let b = if self.interpret_sequence_index_as_most_significant_bits {
            0x80
        } else {
            0
        };
        buf.put_u8(b | (self.sequence_index & 0x7f));
        if !self.synchronization {
            buf.put_u8(self.std_dev);
            buf.put_u8((self.luma_error_threshold << 4) | (self.chroma_error_threshold & 0x0f));
            buf.put_slice(&self.sample_values);
        }
        Ok(self.marshal_size())
    }
}
