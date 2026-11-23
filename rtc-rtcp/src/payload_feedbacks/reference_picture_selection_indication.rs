//! Reference Picture Selection Indication (RPSI, [RFC 4585] §6.3.3).
//!
//! [RFC 4585]: https://datatracker.ietf.org/doc/html/rfc4585#section-6.3.3
use crate::{header::*, packet::*, util::*};
use shared::{
    error::{Error, Result},
    marshal::{Marshal, MarshalSize, Unmarshal},
};

use bytes::{Buf, BufMut, Bytes};
use std::fmt;

/// The PB octet and the payload type octet that precede the bit string.
const RPSI_FCI_HEADER_LENGTH: usize = 2;
const RPSI_PAYLOAD_TYPE_MAX: u8 = 0x7f;

/// Reference Picture Selection Indication (PSFB FMT=3): the receiver names a reference picture
/// in the codec's own terms. Exactly one indication per packet.
///
/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |      PB       |0| Payload Type|    Native RPSI bit string     |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |   defined per codec          ...                | Padding (0) |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[derive(Debug, PartialEq, Eq, Default, Clone)]
pub struct ReferencePictureSelectionIndication {
    /// The source that sends the indication.
    pub sender_ssrc: u32,
    /// The media sender it is for.
    pub media_ssrc: u32,
    /// The RTP payload type that says how the bit string is to be read, 7 bits.
    pub payload_type: u8,
    /// The native RPSI bit string, as the codec defines it, most significant bit first. When
    /// its length is not a whole number of octets, the last octet's low bits are padding.
    pub native_rpsi: Bytes,
    /// How many low bits of the last octet of `native_rpsi` are not part of the bit string,
    /// 0 to 7. They are sent as zero.
    pub unused_bits: u8,
}

impl ReferencePictureSelectionIndication {
    /// An RPSI for an H.265 stream (RFC 7798 section 8.3): a request that the encoder use the
    /// picture with `nuh_layer_id` (6 bits) and `pic_order_cnt_val` as its reference. The
    /// native bit string is "a base16 representation of the 8 bits consisting of the 2 most
    /// significant bits equal to 0 and 6 bits of nuh_layer_id, ... followed by the 32 bits
    /// representing the value of the PicOrderCntVal (in network byte order)": ten hexadecimal
    /// digits. RFC 7798 deprecates RPSI as a positive acknowledgement; this is the request
    /// form, the only one it allows. A `nuh_layer_id` over 63 is refused.
    pub fn hevc(
        sender_ssrc: u32,
        media_ssrc: u32,
        payload_type: u8,
        nuh_layer_id: u8,
        pic_order_cnt_val: u32,
    ) -> Result<Self> {
        if nuh_layer_id > 0x3f {
            return Err(Error::InvalidHeader);
        }
        if payload_type > RPSI_PAYLOAD_TYPE_MAX {
            return Err(Error::WrongPayloadType);
        }
        let mut octets = [0u8; 5];
        octets[0] = nuh_layer_id;
        octets[1..].copy_from_slice(&pic_order_cnt_val.to_be_bytes());
        let hex: String = octets.iter().map(|o| format!("{o:02X}")).collect();
        Ok(Self {
            sender_ssrc,
            media_ssrc,
            payload_type,
            native_rpsi: Bytes::from(hex.into_bytes()),
            unused_bits: 0,
        })
    }

    /// The `(nuh_layer_id, PicOrderCntVal)` of an H.265 RPSI's native bit string (RFC 7798
    /// section 8.3), `None` when it is not ten hexadecimal digits with the two high bits of
    /// the layer octet zero.
    pub fn hevc_picture(&self) -> Option<(u8, u32)> {
        if self.native_rpsi.len() != 10 || self.unused_bits != 0 {
            return None;
        }
        let text = std::str::from_utf8(&self.native_rpsi).ok()?;
        let layer = u8::from_str_radix(&text[..2], 16).ok()?;
        let poc = u32::from_str_radix(&text[2..], 16).ok()?;
        (layer <= 0x3f).then_some((layer, poc))
    }

    /// The length of the native bit string in bits.
    pub fn native_rpsi_bits(&self) -> usize {
        (self.native_rpsi.len() * 8).saturating_sub(self.unused_bits as usize)
    }

    fn padding_octets(&self) -> usize {
        get_padding_size(RPSI_FCI_HEADER_LENGTH + self.native_rpsi.len())
    }
}

impl fmt::Display for ReferencePictureSelectionIndication {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ReferencePictureSelectionIndication {:x} {:x} pt={} {} bits",
            self.sender_ssrc,
            self.media_ssrc,
            self.payload_type,
            self.native_rpsi_bits()
        )
    }
}

impl Packet for ReferencePictureSelectionIndication {
    fn header(&self) -> Header {
        Header {
            padding: false,
            count: FORMAT_RPSI,
            packet_type: PacketType::PayloadSpecificFeedback,
            length: ((self.marshal_size() / 4) - 1) as u16,
        }
    }

    fn destination_ssrc(&self) -> Vec<u32> {
        vec![self.media_ssrc]
    }

    fn raw_size(&self) -> usize {
        HEADER_LENGTH
            + FEEDBACK_SSRCS_LENGTH
            + RPSI_FCI_HEADER_LENGTH
            + self.native_rpsi.len()
            + self.padding_octets()
    }

    packet_any!(ReferencePictureSelectionIndication);
}

impl MarshalSize for ReferencePictureSelectionIndication {
    fn marshal_size(&self) -> usize {
        self.raw_size()
    }
}

impl Marshal for ReferencePictureSelectionIndication {
    fn marshal_to(&self, buf: &mut [u8]) -> Result<usize> {
        if self.payload_type > RPSI_PAYLOAD_TYPE_MAX {
            return Err(Error::WrongPayloadType);
        }
        if self.unused_bits > 7 || (self.native_rpsi.is_empty() && self.unused_bits != 0) {
            return Err(Error::WrongPadding);
        }

        let size = self.raw_size();
        let mut buf = put_feedback_start(
            buf,
            PacketType::PayloadSpecificFeedback,
            FORMAT_RPSI,
            size,
            self.sender_ssrc,
            self.media_ssrc,
        )?;

        // PB: the number of unused bits that pad the message to a multiple of 32 bits.
        let padding_octets = self.padding_octets();
        buf.put_u8(self.unused_bits + 8 * padding_octets as u8);
        buf.put_u8(self.payload_type);
        if let Some((last, head)) = self.native_rpsi.split_last() {
            buf.put_slice(head);
            // RFC 4585 6.3.3.2: the padding bits are set to 0.
            buf.put_u8(last & (0xffu8 << self.unused_bits));
        }
        buf.put_bytes(0, padding_octets);
        Ok(size)
    }
}

impl Unmarshal for ReferencePictureSelectionIndication {
    fn unmarshal<B>(raw_packet: &mut B) -> Result<Self>
    where
        Self: Sized,
        B: Buf,
    {
        let (sender_ssrc, media_ssrc, mut fci) =
            read_feedback(raw_packet, PacketType::PayloadSpecificFeedback, FORMAT_RPSI)?;
        // One indication: PB, payload type, and the string padded to a word.
        if fci.len() < 4 {
            return Err(Error::PacketTooShort);
        }
        if !fci.len().is_multiple_of(4) {
            return Err(Error::WrongPadding);
        }

        let padding_bits = fci.get_u8() as usize;
        // The bit before the payload type is ignored on reception.
        let payload_type = fci.get_u8() & RPSI_PAYLOAD_TYPE_MAX;
        if padding_bits > fci.len() * 8 {
            return Err(Error::WrongPadding);
        }

        let mut native_rpsi = fci.split_to(fci.len() - padding_bits / 8);
        let unused_bits = (padding_bits % 8) as u8;
        if unused_bits != 0 {
            // The padding bits are not part of the string, whatever the sender put there.
            let mut octets = native_rpsi.to_vec();
            if let Some(last) = octets.last_mut() {
                *last &= 0xffu8 << unused_bits;
            }
            native_rpsi = Bytes::from(octets);
        }

        Ok(ReferencePictureSelectionIndication {
            sender_ssrc,
            media_ssrc,
            payload_type,
            native_rpsi,
            unused_bits,
        })
    }
}

#[cfg(test)]
mod hevc_test {
    use super::*;

    /// RFC 7798 section 8.3: the H.265 native RPSI bit string is the base16 text of the layer
    /// octet (two zero bits, six of `nuh_layer_id`) and the 32-bit PicOrderCntVal, network
    /// order; RPSI is a reference picture selection request.
    #[test]
    fn an_hevc_rpsi_names_the_layer_and_picture_order_count_in_base16() {
        let rpsi =
            ReferencePictureSelectionIndication::hevc(0x0102_0304, 0x0a0b_0c0d, 49, 5, 0x0012_34ab)
                .unwrap();
        assert_eq!(&b"05001234AB"[..], &rpsi.native_rpsi[..]);
        assert_eq!(80, rpsi.native_rpsi_bits());
        let raw = rpsi.marshal().unwrap();
        let read = ReferencePictureSelectionIndication::unmarshal(&mut raw.freeze()).unwrap();
        assert_eq!(Some((5, 0x0012_34ab)), read.hevc_picture());
        assert_eq!(49, read.payload_type);

        assert!(ReferencePictureSelectionIndication::hevc(1, 2, 49, 64, 0).is_err());
        let not_hevc = ReferencePictureSelectionIndication {
            native_rpsi: Bytes::from_static(b"C0000000000"),
            ..rpsi
        };
        assert_eq!(None, not_hevc.hevc_picture());
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn rpsi_round_trips_with_pb_counting_the_padding_bits() {
        // 13 bits of native string: two octets, three bits unused, no padding octet.
        let rpsi = ReferencePictureSelectionIndication {
            sender_ssrc: 0x01020304,
            media_ssrc: 0x0a0b0c0d,
            payload_type: 96,
            native_rpsi: Bytes::from_static(&[0xab, 0xc8]),
            unused_bits: 3,
        };
        let raw = rpsi.marshal().unwrap();
        assert_eq!(
            &[
                0x83, 0xce, 0x00, 0x03, // v=2, FMT=3, PSFB, len=3
                0x01, 0x02, 0x03, 0x04, // sender
                0x0a, 0x0b, 0x0c, 0x0d, // media source
                0x03, 0x60, 0xab, 0xc8, // PB=3, pt 96, 13 bits + 3 padding bits
            ][..],
            &raw[..]
        );
        assert_eq!(13, rpsi.native_rpsi_bits());
        assert_eq!(
            rpsi,
            ReferencePictureSelectionIndication::unmarshal(&mut raw.freeze()).unwrap()
        );

        // Three whole octets: three octets of padding, PB = 24.
        let rpsi = ReferencePictureSelectionIndication {
            native_rpsi: Bytes::from_static(&[1, 2, 3]),
            unused_bits: 0,
            ..rpsi
        };
        let raw = rpsi.marshal().unwrap();
        assert_eq!(&[0x18, 0x60, 1, 2, 3, 0, 0, 0][..], &raw[12..]);
        assert_eq!(
            rpsi,
            ReferencePictureSelectionIndication::unmarshal(&mut raw.freeze()).unwrap()
        );
    }

    // RFC 4585 6.3.3.2: padding bits are zero when sent and are not part of the string.
    #[test]
    fn padding_bits_are_sent_as_zero_and_ignored_when_received() {
        let dirty = ReferencePictureSelectionIndication {
            sender_ssrc: 1,
            media_ssrc: 2,
            payload_type: 96,
            native_rpsi: Bytes::from_static(&[0xff, 0xff]),
            unused_bits: 4,
        };
        let raw = dirty.marshal().unwrap();
        assert_eq!(&[0x04, 0x60, 0xff, 0xf0][..], &raw[12..]);

        // Padding bits set, and the zero bit before the payload type set.
        let mut raw = Bytes::from_static(&[
            0x83, 0xce, 0x00, 0x03, 0, 0, 0, 1, 0, 0, 0, 2, 0x04, 0xe0, 0xff, 0xff,
        ]);
        let rpsi = ReferencePictureSelectionIndication::unmarshal(&mut raw).unwrap();
        assert_eq!(96, rpsi.payload_type);
        assert_eq!(&[0xff, 0xf0][..], &rpsi.native_rpsi[..]);
        assert_eq!(4, rpsi.unused_bits);
    }

    #[test]
    fn malformed_indications_are_refused() {
        let bad_pt = ReferencePictureSelectionIndication {
            payload_type: 128,
            ..Default::default()
        };
        assert_eq!(Err(Error::WrongPayloadType), bad_pt.marshal());
        let bad_bits = ReferencePictureSelectionIndication {
            unused_bits: 1,
            ..Default::default()
        };
        assert_eq!(Err(Error::WrongPadding), bad_bits.marshal());

        // No FCI.
        let mut raw = Bytes::from_static(&[0x83, 0xce, 0, 2, 0, 0, 0, 1, 0, 0, 0, 2]);
        assert_eq!(
            Err(Error::PacketTooShort),
            ReferencePictureSelectionIndication::unmarshal(&mut raw)
        );
        // PB claims more padding bits than the message has after its two fixed octets.
        let mut raw = Bytes::from_static(&[0x83, 0xce, 0, 3, 0, 0, 0, 1, 0, 0, 0, 2, 17, 96, 0, 0]);
        assert_eq!(
            Err(Error::WrongPadding),
            ReferencePictureSelectionIndication::unmarshal(&mut raw)
        );
    }
}
