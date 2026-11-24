#[cfg(test)]
mod transmission_offset_extension_test;

use shared::{
    error::{Error, Result},
    marshal::{Marshal, MarshalSize, Unmarshal},
};

use bytes::{Buf, BufMut};

/// The extension's encoded size in bytes.
pub const TRANSMISSION_OFFSET_EXTENSION_SIZE: usize = 3;
/// The largest offset: 2^23 - 1.
pub const TRANSMISSION_OFFSET_MAX: i32 = (1 << 23) - 1;
/// The smallest offset: -2^23.
pub const TRANSMISSION_OFFSET_MIN: i32 = -(1 << 23);

/// The transmission time offset extension ([RFC 5450],
/// `urn:ietf:params:rtp-hdrext:toffset`): how long after its RTP timestamp's instant the
/// packet was sent, in RTP timestamp units, as a signed 24-bit number.
///
/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |  ID   | len=2 |              transmission offset              |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
///
/// [RFC 5450]: https://datatracker.ietf.org/doc/html/rfc5450
#[derive(PartialEq, Eq, Debug, Default, Copy, Clone)]
pub struct TransmissionOffsetExtension {
    /// The offset in RTP timestamp units: positive for a packet sent after its timestamp's
    /// instant. -2^23 to 2^23 - 1.
    pub offset: i32,
}

impl Unmarshal for TransmissionOffsetExtension {
    fn unmarshal<B>(buf: &mut B) -> Result<Self>
    where
        Self: Sized,
        B: Buf,
    {
        if buf.remaining() < TRANSMISSION_OFFSET_EXTENSION_SIZE {
            return Err(Error::ErrBufferTooSmall);
        }
        let raw = (u32::from(buf.get_u8()) << 16) | u32::from(buf.get_u16());
        // Sign-extend the 24-bit two's complement value.
        Ok(TransmissionOffsetExtension {
            offset: ((raw << 8) as i32) >> 8,
        })
    }
}

impl MarshalSize for TransmissionOffsetExtension {
    fn marshal_size(&self) -> usize {
        TRANSMISSION_OFFSET_EXTENSION_SIZE
    }
}

impl Marshal for TransmissionOffsetExtension {
    /// # Errors
    ///
    /// Fails for an offset that does not fit 24 bits.
    fn marshal_to(&self, mut buf: &mut [u8]) -> Result<usize> {
        if buf.remaining_mut() < TRANSMISSION_OFFSET_EXTENSION_SIZE {
            return Err(Error::ErrBufferTooSmall);
        }
        if !(TRANSMISSION_OFFSET_MIN..=TRANSMISSION_OFFSET_MAX).contains(&self.offset) {
            return Err(Error::Other(format!(
                "toffset: {} does not fit a signed 24-bit field",
                self.offset
            )));
        }
        buf.put_u8((self.offset >> 16) as u8);
        buf.put_u16(self.offset as u16);
        Ok(TRANSMISSION_OFFSET_EXTENSION_SIZE)
    }
}
