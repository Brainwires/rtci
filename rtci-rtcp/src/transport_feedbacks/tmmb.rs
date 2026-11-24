//! Temporary Maximum Media Stream Bit Rate Request and Notification ([RFC 5104] §4.2).
//!
//! A receiver asks a media sender to stay under a bit rate with a TMMBR; the sender answers
//! with a TMMBN that lists the bounding set of limits it now obeys. Both carry the same FCI
//! entry.
//!
//! [RFC 5104]: https://datatracker.ietf.org/doc/html/rfc5104#section-4.2
use crate::{header::*, packet::*, util::*};
use shared::{
    error::{Error, Result},
    marshal::{Marshal, MarshalSize, Unmarshal},
};

use bytes::{Buf, BufMut, Bytes};
use std::fmt;

const TMMB_ENTRY_LENGTH: usize = 8;
const TMMB_EXP_MAX: u8 = (1 << 6) - 1;
const TMMB_MANTISSA_MAX: u32 = (1 << 17) - 1;
const TMMB_OVERHEAD_MAX: u16 = (1 << 9) - 1;

/// One FCI entry of a TMMBR or a TMMBN: a bit rate limit and the per-packet overhead it was
/// measured with.
///
/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                              SSRC                             |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// | MxTBR Exp |  MxTBR Mantissa                 |Measured Overhead|
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[derive(Debug, PartialEq, Eq, Default, Clone, Copy)]
pub struct TmmbEntry {
    /// In a TMMBR, the media sender the limit is asked of. In a TMMBN, the owner of the limit:
    /// the source whose request put it in the bounding set.
    pub ssrc: u32,
    /// The exponent of the bit rate, 6 bits.
    pub exp: u8,
    /// The mantissa of the bit rate, 17 bits. The limit is `mantissa * 2^exp` bits per second.
    pub mantissa: u32,
    /// The measured per-packet overhead in octets, 9 bits.
    pub measured_overhead: u16,
}

impl TmmbEntry {
    /// An entry limiting `ssrc` to `bitrate` bits per second.
    ///
    /// The wire carries 17 significant bits. A rate that needs more is rounded down, so the
    /// value on the wire never allows more than was asked for.
    pub fn new(ssrc: u32, bitrate: u64, measured_overhead: u16) -> Self {
        let mut exp = 0u8;
        let mut mantissa = bitrate;
        while mantissa > TMMB_MANTISSA_MAX as u64 {
            mantissa >>= 1;
            exp += 1;
        }
        TmmbEntry {
            ssrc,
            exp,
            mantissa: mantissa as u32,
            measured_overhead: measured_overhead.min(TMMB_OVERHEAD_MAX),
        }
    }

    /// The limit in bits per second: `mantissa * 2^exp`, saturating at `u64::MAX`.
    pub fn bitrate(&self) -> u64 {
        let rate = (self.mantissa as u128) << (self.exp & TMMB_EXP_MAX);
        u64::try_from(rate).unwrap_or(u64::MAX)
    }

    fn marshal_to(&self, buf: &mut &mut [u8]) -> Result<()> {
        if self.exp > TMMB_EXP_MAX
            || self.mantissa > TMMB_MANTISSA_MAX
            || self.measured_overhead > TMMB_OVERHEAD_MAX
        {
            return Err(Error::InvalidBitrate);
        }
        buf.put_u32(self.ssrc);
        buf.put_u32(
            ((self.exp as u32) << 26) | (self.mantissa << 9) | self.measured_overhead as u32,
        );
        Ok(())
    }

    fn unmarshal(fci: &mut Bytes) -> Self {
        let ssrc = fci.get_u32();
        let word = fci.get_u32();
        TmmbEntry {
            ssrc,
            exp: (word >> 26) as u8,
            mantissa: (word >> 9) & TMMB_MANTISSA_MAX,
            measured_overhead: (word & TMMB_OVERHEAD_MAX as u32) as u16,
        }
    }
}

fn marshal_tmmb(
    buf: &mut [u8],
    format: u8,
    size: usize,
    sender_ssrc: u32,
    entries: &[TmmbEntry],
) -> Result<usize> {
    // RFC 5104 4.2.1.2 / 4.2.2.2: the "SSRC of media source" is not used and SHALL be 0.
    let mut buf = put_feedback_start(
        buf,
        PacketType::TransportSpecificFeedback,
        format,
        size,
        sender_ssrc,
        0,
    )?;
    for entry in entries {
        entry.marshal_to(&mut buf)?;
    }
    Ok(size)
}

fn unmarshal_tmmb<B: Buf>(raw_packet: &mut B, format: u8) -> Result<(u32, Vec<TmmbEntry>)> {
    let (sender_ssrc, _media_ssrc, mut fci) =
        read_feedback(raw_packet, PacketType::TransportSpecificFeedback, format)?;
    // RFC 5104 4.2.1.1 / 4.2.2.1: the length is 2 + 2 * N.
    if !fci.len().is_multiple_of(TMMB_ENTRY_LENGTH) {
        return Err(Error::InvalidHeader);
    }
    let mut entries = Vec::with_capacity(fci.len() / TMMB_ENTRY_LENGTH);
    while fci.has_remaining() {
        entries.push(TmmbEntry::unmarshal(&mut fci));
    }
    Ok((sender_ssrc, entries))
}

/// Temporary Maximum Media Stream Bit Rate Request (TMMBR, RTPFB FMT=3, RFC 5104 §4.2.1): a
/// receiver asks one or more media senders to stay under a bit rate.
#[derive(Debug, PartialEq, Eq, Default, Clone)]
pub struct TemporaryMaximumBitrateRequest {
    /// The source that makes the request.
    pub sender_ssrc: u32,
    /// One entry per media sender asked. At least one.
    pub entries: Vec<TmmbEntry>,
}

impl fmt::Display for TemporaryMaximumBitrateRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "TMMBR {:x}", self.sender_ssrc)?;
        for e in &self.entries {
            write!(
                f,
                " ({:x} {} b/s +{})",
                e.ssrc,
                e.bitrate(),
                e.measured_overhead
            )?;
        }
        Ok(())
    }
}

impl Packet for TemporaryMaximumBitrateRequest {
    fn header(&self) -> Header {
        Header {
            padding: false,
            count: FORMAT_TMMBR,
            packet_type: PacketType::TransportSpecificFeedback,
            length: ((self.marshal_size() / 4) - 1) as u16,
        }
    }

    fn destination_ssrc(&self) -> Vec<u32> {
        self.entries.iter().map(|e| e.ssrc).collect()
    }

    fn raw_size(&self) -> usize {
        HEADER_LENGTH + FEEDBACK_SSRCS_LENGTH + self.entries.len() * TMMB_ENTRY_LENGTH
    }

    packet_any!(TemporaryMaximumBitrateRequest);
}

impl MarshalSize for TemporaryMaximumBitrateRequest {
    fn marshal_size(&self) -> usize {
        self.raw_size()
    }
}

impl Marshal for TemporaryMaximumBitrateRequest {
    fn marshal_to(&self, buf: &mut [u8]) -> Result<usize> {
        // RFC 5104 4.2.1.1: the FCI "SHALL contain one or more FCI entries".
        if self.entries.is_empty() {
            return Err(Error::PacketTooShort);
        }
        marshal_tmmb(
            buf,
            FORMAT_TMMBR,
            self.raw_size(),
            self.sender_ssrc,
            &self.entries,
        )
    }
}

impl Unmarshal for TemporaryMaximumBitrateRequest {
    fn unmarshal<B>(raw_packet: &mut B) -> Result<Self>
    where
        Self: Sized,
        B: Buf,
    {
        let (sender_ssrc, entries) = unmarshal_tmmb(raw_packet, FORMAT_TMMBR)?;
        if entries.is_empty() {
            return Err(Error::PacketTooShort);
        }
        Ok(TemporaryMaximumBitrateRequest {
            sender_ssrc,
            entries,
        })
    }
}

/// Temporary Maximum Media Stream Bit Rate Notification (TMMBN, RTPFB FMT=4, RFC 5104 §4.2.2):
/// a media sender announces the bounding set of limits it obeys.
#[derive(Debug, PartialEq, Eq, Default, Clone)]
pub struct TemporaryMaximumBitrateNotification {
    /// The media sender that makes the announcement.
    pub sender_ssrc: u32,
    /// The bounding set. Empty when no limit is in force (RFC 5104 §4.2.2.1).
    pub entries: Vec<TmmbEntry>,
}

impl fmt::Display for TemporaryMaximumBitrateNotification {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "TMMBN {:x}", self.sender_ssrc)?;
        for e in &self.entries {
            write!(
                f,
                " ({:x} {} b/s +{})",
                e.ssrc,
                e.bitrate(),
                e.measured_overhead
            )?;
        }
        Ok(())
    }
}

impl Packet for TemporaryMaximumBitrateNotification {
    fn header(&self) -> Header {
        Header {
            padding: false,
            count: FORMAT_TMMBN,
            packet_type: PacketType::TransportSpecificFeedback,
            length: ((self.marshal_size() / 4) - 1) as u16,
        }
    }

    fn destination_ssrc(&self) -> Vec<u32> {
        self.entries.iter().map(|e| e.ssrc).collect()
    }

    fn raw_size(&self) -> usize {
        HEADER_LENGTH + FEEDBACK_SSRCS_LENGTH + self.entries.len() * TMMB_ENTRY_LENGTH
    }

    packet_any!(TemporaryMaximumBitrateNotification);
}

impl MarshalSize for TemporaryMaximumBitrateNotification {
    fn marshal_size(&self) -> usize {
        self.raw_size()
    }
}

impl Marshal for TemporaryMaximumBitrateNotification {
    fn marshal_to(&self, buf: &mut [u8]) -> Result<usize> {
        marshal_tmmb(
            buf,
            FORMAT_TMMBN,
            self.raw_size(),
            self.sender_ssrc,
            &self.entries,
        )
    }
}

impl Unmarshal for TemporaryMaximumBitrateNotification {
    fn unmarshal<B>(raw_packet: &mut B) -> Result<Self>
    where
        Self: Sized,
        B: Buf,
    {
        let (sender_ssrc, entries) = unmarshal_tmmb(raw_packet, FORMAT_TMMBN)?;
        Ok(TemporaryMaximumBitrateNotification {
            sender_ssrc,
            entries,
        })
    }
}

#[cfg(test)]
mod test {
    use super::*;

    // RFC 5104 4.2.1.1: FMT 3, PT 205, length 2 + 2 * N, media SSRC 0.
    #[test]
    fn tmmbr_round_trips_with_the_wire_layout_of_rfc5104() {
        let tmmbr = TemporaryMaximumBitrateRequest {
            sender_ssrc: 0x01020304,
            entries: vec![TmmbEntry {
                ssrc: 0x0a0b0c0d,
                exp: 3,
                mantissa: 0x1abcd,
                measured_overhead: 40,
            }],
        };
        let raw = tmmbr.marshal().unwrap();
        assert_eq!(
            &[
                0x83, 0xcd, 0x00, 0x04, // v=2, FMT=3, RTPFB, len=4
                0x01, 0x02, 0x03, 0x04, // sender
                0x00, 0x00, 0x00, 0x00, // media source: not used, zero
                0x0a, 0x0b, 0x0c, 0x0d, // entry ssrc
                0x0f, 0x57, 0x9a, 0x28, // exp=3, mantissa=0x1abcd, overhead=40
            ][..],
            &raw[..]
        );
        assert_eq!(
            tmmbr,
            TemporaryMaximumBitrateRequest::unmarshal(&mut raw.freeze()).unwrap()
        );
        assert_eq!(0x1abcd << 3, tmmbr.entries[0].bitrate());
        assert_eq!(vec![0x0a0b0c0d], tmmbr.destination_ssrc());
    }

    #[test]
    fn tmmbr_needs_an_entry_and_whole_entries() {
        let empty = TemporaryMaximumBitrateRequest::default();
        assert_eq!(Err(Error::PacketTooShort), empty.marshal());

        // No FCI.
        let mut raw = Bytes::from_static(&[0x83, 0xcd, 0, 2, 0, 0, 0, 1, 0, 0, 0, 0]);
        assert_eq!(
            Err(Error::PacketTooShort),
            TemporaryMaximumBitrateRequest::unmarshal(&mut raw)
        );
        // Half an entry.
        let mut raw = Bytes::from_static(&[0x83, 0xcd, 0, 3, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 2]);
        assert_eq!(
            Err(Error::InvalidHeader),
            TemporaryMaximumBitrateRequest::unmarshal(&mut raw)
        );
        // A TMMBN is not a TMMBR.
        let mut raw = Bytes::from_static(&[0x84, 0xcd, 0, 2, 0, 0, 0, 1, 0, 0, 0, 0]);
        assert_eq!(
            Err(Error::WrongType),
            TemporaryMaximumBitrateRequest::unmarshal(&mut raw)
        );
    }

    // RFC 5104 4.2.2.1: a TMMBN may have no entry (no limit in force).
    #[test]
    fn tmmbn_round_trips_with_and_without_entries() {
        let empty = TemporaryMaximumBitrateNotification {
            sender_ssrc: 7,
            entries: vec![],
        };
        let raw = empty.marshal().unwrap();
        assert_eq!(&[0x84, 0xcd, 0, 2, 0, 0, 0, 7, 0, 0, 0, 0][..], &raw[..]);
        assert_eq!(
            empty,
            TemporaryMaximumBitrateNotification::unmarshal(&mut raw.freeze()).unwrap()
        );

        let set = TemporaryMaximumBitrateNotification {
            sender_ssrc: 7,
            entries: vec![
                TmmbEntry::new(1, 1_000_000, 28),
                TmmbEntry::new(2, 64_000, 40),
            ],
        };
        let raw = set.marshal().unwrap();
        assert_eq!(28, raw.len());
        assert_eq!(6, raw[3], "length = 2 + 2 * 2");
        assert_eq!(
            set,
            TemporaryMaximumBitrateNotification::unmarshal(&mut raw.freeze()).unwrap()
        );
    }

    #[test]
    fn a_bit_rate_is_rounded_down_to_17_significant_bits() {
        let exact = TmmbEntry::new(1, 131_071, 0);
        assert_eq!((0, 131_071), (exact.exp, exact.mantissa));

        let rounded = TmmbEntry::new(1, 1_000_001, 0);
        assert!(rounded.bitrate() <= 1_000_001);
        assert!(1_000_001 - rounded.bitrate() < 1 << rounded.exp);

        let huge = TmmbEntry::new(1, u64::MAX, 600);
        assert_eq!(47, huge.exp);
        assert_eq!(TMMB_MANTISSA_MAX, huge.mantissa);
        assert_eq!(TMMB_OVERHEAD_MAX, huge.measured_overhead);

        let saturated = TmmbEntry {
            exp: 63,
            mantissa: TMMB_MANTISSA_MAX,
            ..Default::default()
        };
        assert_eq!(u64::MAX, saturated.bitrate());
    }

    #[test]
    fn fields_wider_than_the_wire_are_refused() {
        for entry in [
            TmmbEntry {
                exp: 64,
                ..Default::default()
            },
            TmmbEntry {
                mantissa: 1 << 17,
                ..Default::default()
            },
            TmmbEntry {
                measured_overhead: 512,
                ..Default::default()
            },
        ] {
            let tmmbn = TemporaryMaximumBitrateNotification {
                sender_ssrc: 1,
                entries: vec![entry],
            };
            assert_eq!(Err(Error::InvalidBitrate), tmmbn.marshal());
        }
    }
}
