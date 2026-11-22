//! Temporal-Spatial Trade-off Request and Notification ([RFC 5104] §4.3.2, §4.3.3).
//!
//! A receiver tells an encoder which way to lean between frame rate and picture quality with a
//! TSTR; the encoder answers with a TSTN that echoes the request and states the index it uses.
//! Both carry the same FCI entry.
//!
//! [RFC 5104]: https://datatracker.ietf.org/doc/html/rfc5104#section-4.3.2
use crate::{header::*, packet::*, util::*};
use shared::{
    error::{Error, Result},
    marshal::{Marshal, MarshalSize, Unmarshal},
};

use bytes::{Buf, BufMut};
use std::fmt;

const TST_ENTRY_LENGTH: usize = 8;
const TST_INDEX_MAX: u8 = (1 << 5) - 1;

/// One FCI entry of a TSTR or a TSTN.
///
/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                              SSRC                             |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |  Seq nr.      |  Reserved                           | Index   |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[derive(Debug, PartialEq, Eq, Default, Clone, Copy)]
pub struct TstEntry {
    /// In a TSTR, the media sender asked. In a TSTN, the source whose request is answered.
    pub ssrc: u32,
    /// The request's sequence number: it goes up with each new request, a repetition keeps it,
    /// and a notification echoes it.
    pub sequence_number: u8,
    /// The trade-off, 5 bits: 0 is the highest picture quality, 31 the highest frame rate.
    pub index: u8,
}

fn marshal_tst(
    buf: &mut [u8],
    format: u8,
    size: usize,
    sender_ssrc: u32,
    entries: &[TstEntry],
) -> Result<usize> {
    // RFC 5104 4.3.2.1 / 4.3.3.1: the FCI "SHALL contain one or more" entries.
    if entries.is_empty() {
        return Err(Error::PacketTooShort);
    }
    if entries.iter().any(|e| e.index > TST_INDEX_MAX) {
        return Err(Error::InvalidHeader);
    }
    // RFC 5104 4.3.2.2 / 4.3.3.2: the "SSRC of media source" is not used and SHALL be 0.
    let mut buf = put_feedback_start(
        buf,
        PacketType::PayloadSpecificFeedback,
        format,
        size,
        sender_ssrc,
        0,
    )?;
    for entry in entries {
        buf.put_u32(entry.ssrc);
        // The 19 reserved bits are sent as zero.
        buf.put_u32(((entry.sequence_number as u32) << 24) | entry.index as u32);
    }
    Ok(size)
}

fn unmarshal_tst<B: Buf>(raw_packet: &mut B, format: u8) -> Result<(u32, Vec<TstEntry>)> {
    let (sender_ssrc, _media_ssrc, mut fci) =
        read_feedback(raw_packet, PacketType::PayloadSpecificFeedback, format)?;
    if fci.is_empty() {
        return Err(Error::PacketTooShort);
    }
    // The length is 2 + 2 * N.
    if !fci.len().is_multiple_of(TST_ENTRY_LENGTH) {
        return Err(Error::InvalidHeader);
    }
    let mut entries = Vec::with_capacity(fci.len() / TST_ENTRY_LENGTH);
    while fci.has_remaining() {
        let ssrc = fci.get_u32();
        let word = fci.get_u32();
        entries.push(TstEntry {
            ssrc,
            sequence_number: (word >> 24) as u8,
            // The reserved bits are ignored.
            index: (word as u8) & TST_INDEX_MAX,
        });
    }
    Ok((sender_ssrc, entries))
}

fn fmt_tst(
    f: &mut fmt::Formatter<'_>,
    name: &str,
    sender_ssrc: u32,
    entries: &[TstEntry],
) -> fmt::Result {
    write!(f, "{name} {sender_ssrc:x}")?;
    for e in entries {
        write!(f, " ({:x} {} {})", e.ssrc, e.sequence_number, e.index)?;
    }
    Ok(())
}

macro_rules! tst_packet {
    ($(#[$doc:meta])* $name:ident, $format:expr, $label:literal) => {
        $(#[$doc])*
        #[derive(Debug, PartialEq, Eq, Default, Clone)]
        pub struct $name {
            /// The source that sends this message.
            pub sender_ssrc: u32,
            /// At least one entry.
            pub entries: Vec<TstEntry>,
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                fmt_tst(f, $label, self.sender_ssrc, &self.entries)
            }
        }

        impl Packet for $name {
            fn header(&self) -> Header {
                Header {
                    padding: false,
                    count: $format,
                    packet_type: PacketType::PayloadSpecificFeedback,
                    length: ((self.marshal_size() / 4) - 1) as u16,
                }
            }

            fn destination_ssrc(&self) -> Vec<u32> {
                self.entries.iter().map(|e| e.ssrc).collect()
            }

            fn raw_size(&self) -> usize {
                HEADER_LENGTH + FEEDBACK_SSRCS_LENGTH + self.entries.len() * TST_ENTRY_LENGTH
            }

            packet_any!($name);
        }

        impl MarshalSize for $name {
            fn marshal_size(&self) -> usize {
                self.raw_size()
            }
        }

        impl Marshal for $name {
            fn marshal_to(&self, buf: &mut [u8]) -> Result<usize> {
                marshal_tst(buf, $format, self.raw_size(), self.sender_ssrc, &self.entries)
            }
        }

        impl Unmarshal for $name {
            fn unmarshal<B>(raw_packet: &mut B) -> Result<Self>
            where
                Self: Sized,
                B: Buf,
            {
                let (sender_ssrc, entries) = unmarshal_tst(raw_packet, $format)?;
                Ok($name {
                    sender_ssrc,
                    entries,
                })
            }
        }
    };
}

tst_packet!(
    /// Temporal-Spatial Trade-off Request (TSTR, PSFB FMT=5, RFC 5104 §4.3.2).
    TemporalSpatialTradeoffRequest,
    FORMAT_TSTR,
    "TSTR"
);
tst_packet!(
    /// Temporal-Spatial Trade-off Notification (TSTN, PSFB FMT=6, RFC 5104 §4.3.3).
    TemporalSpatialTradeoffNotification,
    FORMAT_TSTN,
    "TSTN"
);

#[cfg(test)]
mod test {
    use super::*;
    use bytes::Bytes;

    #[test]
    fn tstr_round_trips_with_the_wire_layout_of_rfc5104() {
        let tstr = TemporalSpatialTradeoffRequest {
            sender_ssrc: 0x01020304,
            entries: vec![
                TstEntry {
                    ssrc: 0x0a0b0c0d,
                    sequence_number: 9,
                    index: 31,
                },
                TstEntry {
                    ssrc: 0x0a0b0c0e,
                    sequence_number: 255,
                    index: 0,
                },
            ],
        };
        let raw = tstr.marshal().unwrap();
        assert_eq!(
            &[
                0x85, 0xce, 0x00, 0x06, // v=2, FMT=5, PSFB, len = 2 + 2 * 2
                0x01, 0x02, 0x03, 0x04, // sender
                0x00, 0x00, 0x00, 0x00, // media source: not used, zero
                0x0a, 0x0b, 0x0c, 0x0d, 0x09, 0x00, 0x00, 0x1f, //
                0x0a, 0x0b, 0x0c, 0x0e, 0xff, 0x00, 0x00, 0x00,
            ][..],
            &raw[..]
        );
        assert_eq!(
            tstr,
            TemporalSpatialTradeoffRequest::unmarshal(&mut raw.freeze()).unwrap()
        );
        assert_eq!(vec![0x0a0b0c0d, 0x0a0b0c0e], tstr.destination_ssrc());
    }

    #[test]
    fn tstn_round_trips_and_is_not_a_tstr() {
        let tstn = TemporalSpatialTradeoffNotification {
            sender_ssrc: 1,
            entries: vec![TstEntry {
                ssrc: 2,
                sequence_number: 3,
                index: 4,
            }],
        };
        let raw = tstn.marshal().unwrap().freeze();
        assert_eq!(0x86, raw[0]);
        assert_eq!(
            tstn,
            TemporalSpatialTradeoffNotification::unmarshal(&mut raw.clone()).unwrap()
        );
        assert_eq!(
            Err(Error::WrongType),
            TemporalSpatialTradeoffRequest::unmarshal(&mut raw.clone())
        );
    }

    // RFC 5104 4.3.2.1: reserved bits are ignored on reception.
    #[test]
    fn reserved_bits_are_ignored() {
        let mut raw = Bytes::from_static(&[
            0x85, 0xce, 0x00, 0x04, 0, 0, 0, 1, 0xff, 0xff, 0xff, 0xff, 0, 0, 0, 2, 0x07, 0xff,
            0xff, 0xe5,
        ]);
        let tstr = TemporalSpatialTradeoffRequest::unmarshal(&mut raw).unwrap();
        assert_eq!(
            vec![TstEntry {
                ssrc: 2,
                sequence_number: 7,
                index: 5
            }],
            tstr.entries
        );
    }

    #[test]
    fn an_entry_is_required_and_must_be_whole() {
        assert_eq!(
            Err(Error::PacketTooShort),
            TemporalSpatialTradeoffRequest::default().marshal()
        );
        let over = TemporalSpatialTradeoffNotification {
            sender_ssrc: 1,
            entries: vec![TstEntry {
                index: 32,
                ..Default::default()
            }],
        };
        assert_eq!(Err(Error::InvalidHeader), over.marshal());

        let mut none = Bytes::from_static(&[0x85, 0xce, 0, 2, 0, 0, 0, 1, 0, 0, 0, 0]);
        assert_eq!(
            Err(Error::PacketTooShort),
            TemporalSpatialTradeoffRequest::unmarshal(&mut none)
        );
        let mut half = Bytes::from_static(&[0x86, 0xce, 0, 3, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 2]);
        assert_eq!(
            Err(Error::InvalidHeader),
            TemporalSpatialTradeoffNotification::unmarshal(&mut half)
        );
    }
}
