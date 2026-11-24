//! The APP packet ([RFC 3550] §6.7): application-defined data under a four-character name.
//!
//! [RFC 3550]: https://datatracker.ietf.org/doc/html/rfc3550#section-6.7
#[cfg(test)]
mod application_defined_test;

use crate::{header::*, packet::*, util::*};
use shared::{
    error::{Error, Result},
    marshal::{Marshal, MarshalSize, Unmarshal},
};

use bytes::{Buf, BufMut, Bytes};
use std::fmt;

const APP_NAME_LENGTH: usize = 4;

/// An APP packet: experimental or application-specific data that needs no registered packet
/// type.
///
/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |V=2|P| subtype |   PT=APP=204  |             length            |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                           SSRC/CSRC                           |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                          name (ASCII)                         |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                   application-dependent data                ...
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
///
/// A receiver that does not recognise the name ignores the packet (RFC 3550 §6.7); this type
/// is the parsed form either way, so the application can look at `name` and decide.
#[derive(Debug, PartialEq, Eq, Default, Clone)]
pub struct ApplicationDefined {
    /// Five bits the application may use to tell its own packets apart.
    pub subtype: u8,
    /// The source the packet comes from.
    pub ssrc: u32,
    /// The name the application chose, four ASCII characters, case significant.
    pub name: [u8; 4],
    /// The application's data. Its length is a multiple of four octets.
    pub data: Bytes,
}

impl ApplicationDefined {
    /// The name as text, when it is the four ASCII characters RFC 3550 asks for.
    pub fn name_str(&self) -> Option<&str> {
        if self.name.is_ascii() {
            std::str::from_utf8(&self.name).ok()
        } else {
            None
        }
    }
}

impl fmt::Display for ApplicationDefined {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ApplicationDefined {:x} subtype={} name={:?} data={} octets",
            self.ssrc,
            self.subtype,
            self.name_str().unwrap_or("?"),
            self.data.len()
        )
    }
}

impl Packet for ApplicationDefined {
    fn header(&self) -> Header {
        Header {
            padding: false,
            count: self.subtype,
            packet_type: PacketType::ApplicationDefined,
            length: ((self.marshal_size() / 4) - 1) as u16,
        }
    }

    fn destination_ssrc(&self) -> Vec<u32> {
        vec![self.ssrc]
    }

    fn raw_size(&self) -> usize {
        HEADER_LENGTH + SSRC_LENGTH + APP_NAME_LENGTH + self.data.len()
    }

    packet_any!(ApplicationDefined);
}

impl MarshalSize for ApplicationDefined {
    fn marshal_size(&self) -> usize {
        let l = self.raw_size();
        l + get_padding_size(l)
    }
}

impl Marshal for ApplicationDefined {
    fn marshal_to(&self, mut buf: &mut [u8]) -> Result<usize> {
        // The subtype shares the first octet with the version and the P bit.
        if self.subtype as usize > COUNT_MAX || !self.name.is_ascii() {
            return Err(Error::InvalidHeader);
        }
        // RFC 3550 6.7: the data "must be a multiple of 32 bits long". How to fill a shorter
        // value up is the application's format, so it is not padded here.
        if !self.data.len().is_multiple_of(4) {
            return Err(Error::WrongMarshalSize);
        }
        let size = self.raw_size();
        if buf.remaining_mut() < size {
            return Err(Error::BufferTooShort);
        }

        let h = header_for(PacketType::ApplicationDefined, self.subtype, size)?;
        let n = h.marshal_to(buf)?;
        buf = &mut buf[n..];

        buf.put_u32(self.ssrc);
        buf.put_slice(&self.name);
        buf.put_slice(&self.data);

        Ok(size)
    }
}

impl Unmarshal for ApplicationDefined {
    fn unmarshal<B>(raw_packet: &mut B) -> Result<Self>
    where
        Self: Sized,
        B: Buf,
    {
        let (header, mut body) = read_packet(raw_packet)?;
        if header.packet_type != PacketType::ApplicationDefined {
            return Err(Error::WrongType);
        }
        if body.len() < SSRC_LENGTH + APP_NAME_LENGTH {
            return Err(Error::PacketTooShort);
        }

        let ssrc = body.get_u32();
        let mut name = [0u8; APP_NAME_LENGTH];
        body.copy_to_slice(&mut name);
        // Padding that was not a whole number of words leaves data that is not one either.
        if !body.len().is_multiple_of(4) {
            return Err(Error::WrongPadding);
        }

        Ok(ApplicationDefined {
            subtype: header.count,
            ssrc,
            name,
            data: body,
        })
    }
}
