#[cfg(test)]
mod goodbye_test;

use crate::{header::*, packet::*, util::*};
use shared::{
    error::{Error, Result},
    marshal::{Marshal, MarshalSize, Unmarshal},
};

use bytes::{Buf, BufMut, Bytes};
use std::any::Any;
use std::fmt;

/// The Goodbye packet indicates that one or more sources are no longer active.
#[derive(Debug, PartialEq, Eq, Default, Clone)]
pub struct Goodbye {
    /// The SSRC/CSRC identifiers that are no longer active
    pub sources: Vec<u32>,
    /// Optional text indicating the reason for leaving, e.g., "camera malfunction" or "RTP loop detected"
    pub reason: Bytes,
}

impl fmt::Display for Goodbye {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut out = "Goodbye:\n\tSources:\n".to_string();
        for s in &self.sources {
            out += format!("\t{}\n", *s).as_str();
        }
        out += format!("\tReason: {:?}\n", self.reason).as_str();

        write!(f, "{out}")
    }
}

impl Packet for Goodbye {
    /// Header returns the Header associated with this packet.
    fn header(&self) -> Header {
        Header {
            // The null octets after the reason are not the padding of the P bit (RFC 3550 6.6).
            padding: false,
            count: self.sources.len() as u8,
            packet_type: PacketType::Goodbye,
            length: ((self.marshal_size() / 4) - 1) as u16,
        }
    }

    /// destination_ssrc returns an array of SSRC values that this packet refers to.
    fn destination_ssrc(&self) -> Vec<u32> {
        self.sources.to_vec()
    }

    fn raw_size(&self) -> usize {
        let srcs_length = self.sources.len() * SSRC_LENGTH;
        // The reason is optional: without one there is no length octet either.
        let reason_length = if self.reason.is_empty() {
            0
        } else {
            self.reason.len() + 1
        };

        HEADER_LENGTH + srcs_length + reason_length
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn equal(&self, other: &dyn Packet) -> bool {
        other.as_any().downcast_ref::<Goodbye>() == Some(self)
    }

    fn cloned(&self) -> Box<dyn Packet> {
        Box::new(self.clone())
    }
}

impl MarshalSize for Goodbye {
    fn marshal_size(&self) -> usize {
        let l = self.raw_size();
        // align to 32-bit boundary
        l + get_padding_size(l)
    }
}

impl Marshal for Goodbye {
    /// marshal_to encodes the packet in binary.
    fn marshal_to(&self, mut buf: &mut [u8]) -> Result<usize> {
        if self.sources.len() > COUNT_MAX {
            return Err(Error::TooManySources);
        }

        if self.reason.len() > SDES_MAX_OCTET_COUNT {
            return Err(Error::ReasonTooLong);
        }

        if buf.remaining_mut() < self.marshal_size() {
            return Err(Error::BufferTooShort);
        }

        /*
         *        0                   1                   2                   3
         *        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
         *       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         *       |V=2|P|    SC   |   PT=BYE=203  |             length            |
         *       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         *       |                           SSRC/CSRC                           |
         *       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         *       :                              ...                              :
         *       +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
         * (opt) |     length    |               reason for leaving            ...
         *       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         */

        let h = self.header();
        let n = h.marshal_to(buf)?;
        buf = &mut buf[n..];

        for source in &self.sources {
            buf.put_u32(*source);
        }

        if !self.reason.is_empty() {
            buf.put_u8(self.reason.len() as u8);
            buf.put(self.reason.clone());
            // "If the string fills the packet to the next 32-bit boundary, the string is not
            // null terminated. If not, the BYE packet MUST be padded with null octets to the
            // next 32-bit boundary. This padding is separate from that indicated by the P bit"
            buf.put_bytes(0, get_padding_size(self.raw_size()));
        }

        Ok(self.marshal_size())
    }
}

impl Unmarshal for Goodbye {
    fn unmarshal<B>(raw_packet: &mut B) -> Result<Self>
    where
        Self: Sized,
        B: Buf,
    {
        /*
         *        0                   1                   2                   3
         *        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
         *       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         *       |V=2|P|    SC   |   PT=BYE=203  |             length            |
         *       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         *       |                           SSRC/CSRC                           |
         *       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         *       :                              ...                              :
         *       +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
         * (opt) |     length    |               reason for leaving            ...
         *       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         */
        let (header, mut body) = read_packet(raw_packet)?;
        if header.packet_type != PacketType::Goodbye {
            return Err(Error::WrongType);
        }

        // SC sources, four octets each.
        if body.len() < header.count as usize * SSRC_LENGTH {
            return Err(Error::PacketTooShort);
        }
        let mut sources = Vec::with_capacity(header.count as usize);
        for _ in 0..header.count {
            sources.push(body.get_u32());
        }

        // Then, optionally, a length octet and that many octets of reason. What is left after
        // them pads the packet to a 32-bit boundary.
        let reason = if body.has_remaining() {
            let reason_len = body.get_u8() as usize;
            if reason_len > body.len() {
                return Err(Error::PacketTooShort);
            }
            body.split_to(reason_len)
        } else {
            Bytes::new()
        };

        Ok(Goodbye { sources, reason })
    }
}
