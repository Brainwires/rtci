#[cfg(test)]
mod abs_capture_time_extension_test;

use shared::{
    error::{Error, Result},
    marshal::{Marshal, MarshalSize, Unmarshal},
};

use bytes::{Buf, BufMut};

/// The element's size without the clock offset.
pub const ABS_CAPTURE_TIME_EXTENSION_SIZE: usize = 8;
/// The element's size with the clock offset.
pub const ABS_CAPTURE_TIME_EXTENDED_EXTENSION_SIZE: usize = 16;

/// The absolute capture time extension
/// (`http://www.webrtc.org/experiments/rtp-hdrext/abs-capture-time`, a libwebrtc experiment):
/// when the first frame of the packet was captured, on the capturer's NTP clock, and
/// optionally that clock's estimated offset from the sender's.
///
/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |  ID   | len=7 |     absolute capture timestamp (bit 0-23)     |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |             absolute capture timestamp (bit 24-55)            |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |  ... (56-63)  |
/// +-+-+-+-+-+-+-+-+
/// ```
///
/// With the offset the element is 16 bytes (`len=15`): the timestamp, then the offset.
#[derive(PartialEq, Eq, Debug, Default, Copy, Clone)]
pub struct AbsCaptureTimeExtension {
    /// The capture time as an NTP timestamp: unsigned 32.32 fixed point seconds since 1900.
    pub timestamp: u64,
    /// The estimated offset of the capturer's clock from the sender's, signed 32.32 fixed
    /// point seconds, when the sender knows it.
    pub estimated_capture_clock_offset: Option<i64>,
}

impl Unmarshal for AbsCaptureTimeExtension {
    /// # Errors
    ///
    /// Fails for an element that is neither 8 nor 16 bytes.
    fn unmarshal<B>(buf: &mut B) -> Result<Self>
    where
        Self: Sized,
        B: Buf,
    {
        match buf.remaining() {
            ABS_CAPTURE_TIME_EXTENSION_SIZE => Ok(AbsCaptureTimeExtension {
                timestamp: buf.get_u64(),
                estimated_capture_clock_offset: None,
            }),
            ABS_CAPTURE_TIME_EXTENDED_EXTENSION_SIZE => Ok(AbsCaptureTimeExtension {
                timestamp: buf.get_u64(),
                estimated_capture_clock_offset: Some(buf.get_i64()),
            }),
            _ => Err(Error::ErrBufferTooSmall),
        }
    }
}

impl MarshalSize for AbsCaptureTimeExtension {
    fn marshal_size(&self) -> usize {
        if self.estimated_capture_clock_offset.is_some() {
            ABS_CAPTURE_TIME_EXTENDED_EXTENSION_SIZE
        } else {
            ABS_CAPTURE_TIME_EXTENSION_SIZE
        }
    }
}

impl Marshal for AbsCaptureTimeExtension {
    fn marshal_to(&self, mut buf: &mut [u8]) -> Result<usize> {
        if buf.remaining_mut() < self.marshal_size() {
            return Err(Error::ErrBufferTooSmall);
        }
        buf.put_u64(self.timestamp);
        if let Some(offset) = self.estimated_capture_clock_offset {
            buf.put_i64(offset);
        }
        Ok(self.marshal_size())
    }
}
