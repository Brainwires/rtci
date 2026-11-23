//! In-band synchronisation metadata (RFC 6051 section 3.3): an NTP-format timestamp in an RTP
//! header extension, for the same instant as the packet's RTP timestamp and from the clock the
//! sender's RTCP SRs use. A receiver takes it as it would an extra SR for the stream.

#[cfg(test)]
mod ntp_timestamp_extension_test;

use bytes::{Buf, BufMut};
use shared::{
    error::{Error, Result},
    marshal::{Marshal, MarshalSize, Unmarshal},
};

/// The URI of Variant A, the 64-bit NTP timestamp (RFC 6051 section 3.3).
pub const NTP_64_URI: &str = "urn:ietf:params:rtp-hdrext:ntp-64";
/// The URI of Variant B, the 56-bit NTP timestamp (RFC 6051 section 3.3).
pub const NTP_56_URI: &str = "urn:ietf:params:rtp-hdrext:ntp-56";

/// The encoded size of [`Ntp64Extension`].
pub const NTP_64_EXTENSION_SIZE: usize = 8;
/// The encoded size of [`Ntp56Extension`].
pub const NTP_56_EXTENSION_SIZE: usize = 7;

/// Variant A (RFC 6051 Figure 5): a whole 64-bit NTP-format timestamp, 32 bits of seconds
/// then 32 of fraction.
#[derive(PartialEq, Eq, Debug, Default, Copy, Clone)]
pub struct Ntp64Extension {
    /// The NTP-format timestamp.
    pub ntp_time: u64,
}

impl Unmarshal for Ntp64Extension {
    fn unmarshal<B>(raw: &mut B) -> Result<Self>
    where
        Self: Sized,
        B: Buf,
    {
        if raw.remaining() < NTP_64_EXTENSION_SIZE {
            return Err(Error::ErrBufferTooSmall);
        }
        Ok(Self {
            ntp_time: raw.get_u64(),
        })
    }
}

impl MarshalSize for Ntp64Extension {
    fn marshal_size(&self) -> usize {
        NTP_64_EXTENSION_SIZE
    }
}

impl Marshal for Ntp64Extension {
    fn marshal_to(&self, mut buf: &mut [u8]) -> Result<usize> {
        if buf.remaining_mut() < NTP_64_EXTENSION_SIZE {
            return Err(Error::ErrBufferTooSmall);
        }
        buf.put_u64(self.ntp_time);
        Ok(NTP_64_EXTENSION_SIZE)
    }
}

/// Variant B (RFC 6051 Figure 6): the low 24 bits of the NTP seconds and the 32 bits of
/// fraction. "RTCP sender reports MUST be used to derive the upper 8 bits of the Seconds"
/// ([`Ntp56Extension::ntp_time`]).
#[derive(PartialEq, Eq, Debug, Default, Copy, Clone)]
pub struct Ntp56Extension {
    /// The low 56 bits of the NTP-format timestamp.
    pub low_bits: u64,
}

impl Ntp56Extension {
    /// The extension for the NTP-format timestamp `ntp_time`: its low 56 bits.
    pub fn new(ntp_time: u64) -> Self {
        Self {
            low_bits: ntp_time & 0x00FF_FFFF_FFFF_FFFF,
        }
    }

    /// The whole NTP-format timestamp, its upper 8 bits of seconds taken from
    /// `sender_report_ntp`, the NTP timestamp of an SR of the same source: the one of the
    /// three candidates (that upper byte, one less, one more) nearest the report, so a
    /// timestamp just across a 2^24-second boundary from the report is read on its side.
    pub fn ntp_time(&self, sender_report_ntp: u64) -> u64 {
        let base = sender_report_ntp & 0xFF00_0000_0000_0000;
        let step = 1u64 << 56;
        [base.wrapping_sub(step), base, base.wrapping_add(step)]
            .into_iter()
            .map(|upper| upper | self.low_bits)
            .min_by_key(|candidate| candidate.abs_diff(sender_report_ntp))
            .unwrap_or(base | self.low_bits)
    }
}

impl Unmarshal for Ntp56Extension {
    fn unmarshal<B>(raw: &mut B) -> Result<Self>
    where
        Self: Sized,
        B: Buf,
    {
        if raw.remaining() < NTP_56_EXTENSION_SIZE {
            return Err(Error::ErrBufferTooSmall);
        }
        let mut low_bits = 0u64;
        for _ in 0..NTP_56_EXTENSION_SIZE {
            low_bits = (low_bits << 8) | u64::from(raw.get_u8());
        }
        Ok(Self { low_bits })
    }
}

impl MarshalSize for Ntp56Extension {
    fn marshal_size(&self) -> usize {
        NTP_56_EXTENSION_SIZE
    }
}

impl Marshal for Ntp56Extension {
    fn marshal_to(&self, mut buf: &mut [u8]) -> Result<usize> {
        if buf.remaining_mut() < NTP_56_EXTENSION_SIZE {
            return Err(Error::ErrBufferTooSmall);
        }
        for shift in (0..NTP_56_EXTENSION_SIZE).rev() {
            buf.put_u8((self.low_bits >> (8 * shift)) as u8);
        }
        Ok(NTP_56_EXTENSION_SIZE)
    }
}
