#[cfg(test)]
mod receiver_estimated_maximum_bitrate_test;

use crate::{header::*, packet::*, util::*};
use shared::{
    error::{Error, Result},
    marshal::{Marshal, MarshalSize, Unmarshal},
};

use bytes::{Buf, BufMut};
use std::any::Any;
use std::fmt;

/// ReceiverEstimatedMaximumBitrate contains the receiver's estimated maximum bitrate.
///
/// ## Specifications
///
/// * [draft-alvestrand-rmcat-remb-03]
///
/// [draft-alvestrand-rmcat-remb-03]: https://tools.ietf.org/html/draft-alvestrand-rmcat-remb-03
#[derive(Debug, PartialEq, Default, Clone)]
pub struct ReceiverEstimatedMaximumBitrate {
    /// SSRC of sender
    pub sender_ssrc: u32,

    /// Estimated maximum bitrate
    pub bitrate: f32,

    /// SSRC entries which this packet applies to
    pub ssrcs: Vec<u32>,
}

const REMB_OFFSET: usize = 16;
const SSRC_ENTRY_OFFSET: usize = 20;

/// Keep a table of powers to units for fast conversion.
const BIT_UNITS: [&str; 7] = ["b", "Kb", "Mb", "Gb", "Tb", "Pb", "Eb"];
const UNIQUE_IDENTIFIER: [u8; 4] = *b"REMB";

/// String prints the REMB packet in a human-readable format.
impl fmt::Display for ReceiverEstimatedMaximumBitrate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Do some unit conversions because b/s is far too difficult to read.
        let mut bitrate = self.bitrate;
        let mut powers = 0;

        // Keep dividing the bitrate until it's under 1000
        // (and stop at the last unit: a peer can state a bit rate far beyond exabits, and the
        // table must not be indexed past its end)
        while bitrate >= 1000.0 && powers < BIT_UNITS.len() - 1 {
            bitrate /= 1000.0;
            powers += 1;
        }

        let unit = BIT_UNITS[powers];

        write!(
            f,
            "ReceiverEstimatedMaximumBitrate {:x} {:.2} {}/s",
            self.sender_ssrc, bitrate, unit,
        )
    }
}

impl Packet for ReceiverEstimatedMaximumBitrate {
    /// Header returns the Header associated with this packet.
    fn header(&self) -> Header {
        Header {
            padding: get_padding_size(self.raw_size()) != 0,
            count: FORMAT_REMB,
            packet_type: PacketType::PayloadSpecificFeedback,
            length: ((self.marshal_size() / 4) - 1) as u16,
        }
    }

    /// destination_ssrc returns an array of SSRC values that this packet refers to.
    fn destination_ssrc(&self) -> Vec<u32> {
        self.ssrcs.clone()
    }

    fn raw_size(&self) -> usize {
        HEADER_LENGTH + REMB_OFFSET + self.ssrcs.len() * 4
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn equal(&self, other: &dyn Packet) -> bool {
        other
            .as_any()
            .downcast_ref::<ReceiverEstimatedMaximumBitrate>()
            == Some(self)
    }

    fn cloned(&self) -> Box<dyn Packet> {
        Box::new(self.clone())
    }
}

impl MarshalSize for ReceiverEstimatedMaximumBitrate {
    fn marshal_size(&self) -> usize {
        let l = self.raw_size();
        // align to 32-bit boundary
        l + get_padding_size(l)
    }
}

impl Marshal for ReceiverEstimatedMaximumBitrate {
    /// Marshal serializes the packet and returns a byte slice.
    fn marshal_to(&self, mut buf: &mut [u8]) -> Result<usize> {
        const BITRATE_MAX: f32 = 2.417_842_4e24; //0x3FFFFp+63;

        /*
            0                   1                   2                   3
            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |V=2|P| FMT=15  |   PT=206      |             length            |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                  SSRC of packet sender                        |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                  SSRC of media source                         |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |  Unique identifier 'R' 'E' 'M' 'B'                            |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |  Num SSRC     | BR Exp    |  BR Mantissa                      |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |   SSRC feedback                                               |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |  ...                                                          |
        */

        // Num SSRC is one octet.
        if self.ssrcs.len() > u8::MAX as usize {
            return Err(Error::TooManySources);
        }
        if buf.remaining_mut() < self.marshal_size() {
            return Err(Error::BufferTooShort);
        }

        let h = self.header();
        let n = h.marshal_to(buf)?;
        buf = &mut buf[n..];

        buf.put_u32(self.sender_ssrc);
        buf.put_u32(0); // always zero

        buf.put_slice(&UNIQUE_IDENTIFIER);

        // Write the length of the ssrcs to follow at the end
        buf.put_u8(self.ssrcs.len() as u8);

        let mut exp = 0;
        let mut bitrate = self.bitrate;
        if bitrate >= BITRATE_MAX {
            bitrate = BITRATE_MAX
        }

        if bitrate < 0.0 {
            return Err(Error::InvalidBitrate);
        }

        while bitrate >= (1 << 18) as f32 {
            bitrate /= 2.0;
            exp += 1;
        }

        if exp >= (1 << 6) {
            return Err(Error::InvalidBitrate);
        }

        let mantissa = bitrate.floor() as u32;

        // We can't quite use the binary package because
        // a) it's a uint24 and b) the exponent is only 6-bits
        // Just trust me; this is big-endian encoding.
        buf.put_u8((exp << 2) as u8 | (mantissa >> 16) as u8);
        buf.put_u8((mantissa >> 8) as u8);
        buf.put_u8(mantissa as u8);

        // Write the SSRCs at the very end.
        for ssrc in &self.ssrcs {
            buf.put_u32(*ssrc);
        }

        if h.padding {
            put_padding(buf, self.raw_size());
        }

        Ok(self.marshal_size())
    }
}

/// Whether `body`, what follows the header of a PSFB FMT=15 packet, is a REMB: after the two
/// SSRCs its FCI opens with `REMB`.
pub(crate) fn is_remb(body: &[u8]) -> bool {
    body.get(FEEDBACK_SSRCS_LENGTH..FEEDBACK_SSRCS_LENGTH + UNIQUE_IDENTIFIER.len())
        == Some(&UNIQUE_IDENTIFIER[..])
}

impl Unmarshal for ReceiverEstimatedMaximumBitrate {
    /// Unmarshal reads a REMB packet from the given byte slice.
    fn unmarshal<B>(raw_packet: &mut B) -> Result<Self>
    where
        Self: Sized,
        B: Buf,
    {
        const MANTISSA_MAX: u32 = 0x7FFFFF;
        /*
            0                   1                   2                   3
            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |V=2|P| FMT=15  |   PT=206      |             length            |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                  SSRC of packet sender                        |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                  SSRC of media source                         |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |  Unique identifier 'R' 'E' 'M' 'B'                            |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |  Num SSRC     | BR Exp    |  BR Mantissa                      |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |   SSRC feedback                                               |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |  ...                                                          |
        */
        let (sender_ssrc, media_ssrc, mut fci) =
            read_feedback(raw_packet, PacketType::PayloadSpecificFeedback, FORMAT_REMB)?;
        // The identifier and the word with the SSRC count and the bit rate.
        if fci.len() < SSRC_ENTRY_OFFSET - HEADER_LENGTH - FEEDBACK_SSRCS_LENGTH {
            return Err(Error::PacketTooShort);
        }
        if media_ssrc != 0 {
            return Err(Error::SsrcMustBeZero);
        }

        let mut unique_identifier = [0; 4];
        fci.copy_to_slice(&mut unique_identifier);
        if unique_identifier != UNIQUE_IDENTIFIER {
            return Err(Error::MissingRembIdentifier);
        }

        let ssrcs_len = fci.get_u8() as usize;

        let b17 = fci.get_u8();
        let mut exp = (b17 as u64) >> 2;
        exp += 127; // bias for IEEE754
        exp += 23; // IEEE754 biases the decimal to the left, abs-send-time biases it to the right

        let b18 = fci.get_u8();
        let b19 = fci.get_u8();
        let mut mantissa = ((b17 & 3) as u32) << 16 | (b18 as u32) << 8 | b19 as u32;

        if mantissa != 0 {
            // ieee754 requires an implicit leading bit
            while (mantissa & (MANTISSA_MAX + 1)) == 0 {
                exp -= 1;
                mantissa *= 2;
            }
        }

        // bitrate = mantissa * 2^exp. A mantissa of zero is a bit rate of zero whatever the
        // exponent: it has no leading bit to normalise, and the bits below would read as
        // 2^(exp + 23).
        let bitrate = if mantissa == 0 {
            0.0
        } else {
            f32::from_bits(((exp as u32) << 23) | (mantissa & MANTISSA_MAX))
        };

        // draft-alvestrand-rmcat-remb-03 2.2: Num SSRC entries follow, and nothing else.
        if fci.len() != ssrcs_len * SSRC_LENGTH {
            return Err(Error::SsrcNumAndLengthMismatch);
        }
        let mut ssrcs = Vec::with_capacity(ssrcs_len);
        for _ in 0..ssrcs_len {
            ssrcs.push(fci.get_u32());
        }

        Ok(ReceiverEstimatedMaximumBitrate {
            sender_ssrc,
            bitrate,
            ssrcs,
        })
    }
}
