//! H.271 Video Back Channel Message ([RFC 5104] §4.3.4).
//!
//! [RFC 5104]: https://datatracker.ietf.org/doc/html/rfc5104#section-4.3.4
use crate::{header::*, packet::*, util::*};
use shared::{
    error::{Error, Result},
    marshal::{Marshal, MarshalSize, Unmarshal},
};

use bytes::{Buf, BufMut, Bytes};
use std::fmt;

/// SSRC, sequence number, payload type and length: what precedes the octet string.
const VBCM_ENTRY_HEADER_LENGTH: usize = 8;
const VBCM_PAYLOAD_TYPE_MAX: u8 = 0x7f;

/// One FCI entry of a VBCM: an H.271 message for one media sender.
///
/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                              SSRC                             |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// | Seq nr.       |0| Payload Type| Length                        |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                    VBCM Octet String....      |    Padding    |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[derive(Debug, PartialEq, Eq, Default, Clone)]
pub struct VbcmEntry {
    /// The media sender the message is for.
    pub ssrc: u32,
    /// The message's sequence number: it goes up with each new message, a repetition keeps it.
    pub sequence_number: u8,
    /// The RTP payload type that says how the octet string is to be read, 7 bits.
    pub payload_type: u8,
    /// The message, as H.271 defines it for the codec of that payload type.
    pub octet_string: Bytes,
}

impl VbcmEntry {
    fn raw_size(&self) -> usize {
        let l = VBCM_ENTRY_HEADER_LENGTH + self.octet_string.len();
        l + get_padding_size(l)
    }
}

/// H.271 Video Back Channel Message (VBCM, PSFB FMT=7, RFC 5104 §4.3.4).
#[derive(Debug, PartialEq, Eq, Default, Clone)]
pub struct VideoBackChannelMessage {
    /// The source that sends the message.
    pub sender_ssrc: u32,
    /// At least one entry.
    pub entries: Vec<VbcmEntry>,
}

impl fmt::Display for VideoBackChannelMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "VBCM {:x}", self.sender_ssrc)?;
        for e in &self.entries {
            write!(
                f,
                " ({:x} {} pt={} {} octets)",
                e.ssrc,
                e.sequence_number,
                e.payload_type,
                e.octet_string.len()
            )?;
        }
        Ok(())
    }
}

impl Packet for VideoBackChannelMessage {
    fn header(&self) -> Header {
        Header {
            padding: false,
            count: FORMAT_VBCM,
            packet_type: PacketType::PayloadSpecificFeedback,
            length: ((self.marshal_size() / 4) - 1) as u16,
        }
    }

    fn destination_ssrc(&self) -> Vec<u32> {
        self.entries.iter().map(|e| e.ssrc).collect()
    }

    fn raw_size(&self) -> usize {
        HEADER_LENGTH
            + FEEDBACK_SSRCS_LENGTH
            + self.entries.iter().map(|e| e.raw_size()).sum::<usize>()
    }

    packet_any!(VideoBackChannelMessage);
}

impl MarshalSize for VideoBackChannelMessage {
    fn marshal_size(&self) -> usize {
        self.raw_size()
    }
}

impl Marshal for VideoBackChannelMessage {
    fn marshal_to(&self, buf: &mut [u8]) -> Result<usize> {
        // RFC 5104 4.3.4.1: the FCI "MUST contain one or more" entries.
        if self.entries.is_empty() {
            return Err(Error::PacketTooShort);
        }
        for e in &self.entries {
            if e.payload_type > VBCM_PAYLOAD_TYPE_MAX {
                return Err(Error::WrongPayloadType);
            }
            if e.octet_string.len() > u16::MAX as usize {
                return Err(Error::WrongMarshalSize);
            }
        }

        let size = self.raw_size();
        // The "SSRC of media source" is not used and SHALL be 0.
        let mut buf = put_feedback_start(
            buf,
            PacketType::PayloadSpecificFeedback,
            FORMAT_VBCM,
            size,
            self.sender_ssrc,
            0,
        )?;
        for e in &self.entries {
            buf.put_u32(e.ssrc);
            buf.put_u8(e.sequence_number);
            buf.put_u8(e.payload_type);
            buf.put_u16(e.octet_string.len() as u16);
            buf.put_slice(&e.octet_string);
            // Padding to the next 32-bit boundary, zero.
            let unpadded = VBCM_ENTRY_HEADER_LENGTH + e.octet_string.len();
            buf.put_bytes(0, get_padding_size(unpadded));
        }
        Ok(size)
    }
}

impl Unmarshal for VideoBackChannelMessage {
    fn unmarshal<B>(raw_packet: &mut B) -> Result<Self>
    where
        Self: Sized,
        B: Buf,
    {
        let (sender_ssrc, _media_ssrc, mut fci) =
            read_feedback(raw_packet, PacketType::PayloadSpecificFeedback, FORMAT_VBCM)?;
        if fci.is_empty() {
            return Err(Error::PacketTooShort);
        }

        let mut entries = vec![];
        while fci.has_remaining() {
            if fci.len() < VBCM_ENTRY_HEADER_LENGTH {
                return Err(Error::PacketTooShort);
            }
            let ssrc = fci.get_u32();
            let sequence_number = fci.get_u8();
            // The bit before the payload type is zero when sent and ignored when received.
            let payload_type = fci.get_u8() & VBCM_PAYLOAD_TYPE_MAX;
            let length = fci.get_u16() as usize;
            let padded = length + get_padding_size(length);
            if fci.len() < padded {
                return Err(Error::PacketTooShort);
            }
            let octet_string = fci.split_to(length);
            fci.advance(padded - length);
            entries.push(VbcmEntry {
                ssrc,
                sequence_number,
                payload_type,
                octet_string,
            });
        }

        Ok(VideoBackChannelMessage {
            sender_ssrc,
            entries,
        })
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn vbcm_round_trips_with_each_entry_padded_to_a_word() {
        let vbcm = VideoBackChannelMessage {
            sender_ssrc: 0x01020304,
            entries: vec![
                VbcmEntry {
                    ssrc: 0x0a0b0c0d,
                    sequence_number: 5,
                    payload_type: 96,
                    octet_string: Bytes::from_static(&[0xde, 0xad, 0xbe, 0xef, 0x01]),
                },
                VbcmEntry {
                    ssrc: 0x0a0b0c0e,
                    sequence_number: 6,
                    payload_type: 97,
                    octet_string: Bytes::from_static(&[0x11, 0x22, 0x33, 0x44]),
                },
            ],
        };
        let raw = vbcm.marshal().unwrap();
        assert_eq!(
            &[
                0x87, 0xce, 0x00, 0x09, // v=2, FMT=7, PSFB, len=9
                0x01, 0x02, 0x03, 0x04, // sender
                0x00, 0x00, 0x00, 0x00, // media source: not used, zero
                0x0a, 0x0b, 0x0c, 0x0d, 0x05, 0x60, 0x00, 0x05, // ssrc, seq, pt, length 5
                0xde, 0xad, 0xbe, 0xef, 0x01, 0x00, 0x00, 0x00, // string + 3 padding
                0x0a, 0x0b, 0x0c, 0x0e, 0x06, 0x61, 0x00, 0x04, //
                0x11, 0x22, 0x33, 0x44,
            ][..],
            &raw[..]
        );
        assert_eq!(
            vbcm,
            VideoBackChannelMessage::unmarshal(&mut raw.freeze()).unwrap()
        );
        assert_eq!(vec![0x0a0b0c0d, 0x0a0b0c0e], vbcm.destination_ssrc());
    }

    #[test]
    fn the_zero_bit_before_the_payload_type_is_ignored() {
        let mut raw = Bytes::from_static(&[
            0x87, 0xce, 0x00, 0x04, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 2, 0x01, 0xe0, 0x00, 0x00,
        ]);
        let vbcm = VideoBackChannelMessage::unmarshal(&mut raw).unwrap();
        assert_eq!(96, vbcm.entries[0].payload_type);
        assert!(vbcm.entries[0].octet_string.is_empty());
    }

    #[test]
    fn malformed_messages_are_refused() {
        assert_eq!(
            Err(Error::PacketTooShort),
            VideoBackChannelMessage::default().marshal()
        );
        let bad_pt = VideoBackChannelMessage {
            sender_ssrc: 1,
            entries: vec![VbcmEntry {
                payload_type: 128,
                ..Default::default()
            }],
        };
        assert_eq!(Err(Error::WrongPayloadType), bad_pt.marshal());

        // No entry.
        let mut raw = Bytes::from_static(&[0x87, 0xce, 0, 2, 0, 0, 0, 1, 0, 0, 0, 0]);
        assert_eq!(
            Err(Error::PacketTooShort),
            VideoBackChannelMessage::unmarshal(&mut raw)
        );
        // An entry cut inside its header.
        let mut raw = Bytes::from_static(&[0x87, 0xce, 0, 3, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 2]);
        assert_eq!(
            Err(Error::PacketTooShort),
            VideoBackChannelMessage::unmarshal(&mut raw)
        );
        // A length that runs past the packet.
        let mut raw = Bytes::from_static(&[
            0x87, 0xce, 0, 5, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 2, 1, 96, 0, 5, 1, 2, 3, 4,
        ]);
        assert_eq!(
            Err(Error::PacketTooShort),
            VideoBackChannelMessage::unmarshal(&mut raw)
        );
    }
}
