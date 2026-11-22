use super::{chunk_header::*, chunk_type::*, *};

use bytes::{Bytes, BytesMut};
use std::fmt;

/// A chunk of a type this implementation does not recognize, kept as it arrived.
///
/// RFC 9260 section 3.2: what the receiver does with it is encoded in the upper two bits of
/// the type ([`ChunkUnknown::stops_processing`], [`ChunkUnknown::is_reported`]).
#[derive(Default, Debug, Clone)]
pub(crate) struct ChunkUnknown {
    pub(crate) typ: ChunkType,
    pub(crate) flags: u8,
    pub(crate) value: Bytes,
}

impl fmt::Display for ChunkUnknown {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.header())
    }
}

impl ChunkUnknown {
    /// Upper bits 00 and 01: stop processing the packet and discard the chunks that follow.
    pub(crate) fn stops_processing(&self) -> bool {
        self.typ.0 & 0x80 == 0
    }

    /// Upper bits 01 and 11: report the chunk in an ERROR "Unrecognized Chunk Type".
    pub(crate) fn is_reported(&self) -> bool {
        self.typ.0 & 0x40 != 0
    }
}

impl Chunk for ChunkUnknown {
    fn header(&self) -> ChunkHeader {
        ChunkHeader {
            typ: self.typ,
            flags: self.flags,
            value_length: self.value.len() as u16,
        }
    }

    fn unmarshal(raw: &Bytes) -> Result<Self> {
        let header = ChunkHeader::unmarshal(raw)?;
        Ok(ChunkUnknown {
            typ: header.typ,
            flags: header.flags,
            value: raw.slice(CHUNK_HEADER_SIZE..CHUNK_HEADER_SIZE + header.value_length()),
        })
    }

    fn marshal_to(&self, buf: &mut BytesMut) -> Result<usize> {
        self.header().marshal_to(buf)?;
        buf.extend_from_slice(&self.value);
        Ok(buf.len())
    }

    fn check(&self) -> Result<()> {
        Ok(())
    }

    fn value_length(&self) -> usize {
        self.value.len()
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}
