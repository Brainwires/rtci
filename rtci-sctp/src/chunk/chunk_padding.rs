use super::{chunk_header::*, chunk_type::*, *};

use bytes::{Bytes, BytesMut};
use std::fmt;

/// The PAD chunk (RFC 4820 section 3, type 132): padding that makes a packet larger, as a
/// path MTU probe needs (RFC 8899 section 6.2: a HEARTBEAT and a PAD chunk).
///
///```text
/// 0                   1                   2                   3
/// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
///+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///| Type = 0x84   |   Flags=0     |             Length            |
///+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///\                         Padding Data                          /
///+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///```
///
/// Its flags are 0 on transmit (a SHOULD) and ignored on receipt; the Padding Data is
/// ignored by the receiver, which discards the chunk and goes on with the rest of the packet
/// (RFC 4820 section 3: MUSTs).
#[derive(Default, Debug, Clone)]
pub(crate) struct ChunkPadding {
    /// Bytes of Padding Data (zeros on transmit).
    pub(crate) padding_length: usize,
}

impl fmt::Display for ChunkPadding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} ({} bytes of padding)",
            self.header(),
            self.padding_length
        )
    }
}

impl Chunk for ChunkPadding {
    fn header(&self) -> ChunkHeader {
        ChunkHeader {
            typ: CT_PAD,
            flags: 0,
            value_length: self.padding_length as u16,
        }
    }

    fn unmarshal(raw: &Bytes) -> Result<Self> {
        // The flags and the padding are ignored on receipt.
        let header = ChunkHeader::unmarshal(raw)?;
        Ok(ChunkPadding {
            padding_length: header.value_length(),
        })
    }

    fn marshal_to(&self, buf: &mut BytesMut) -> Result<usize> {
        self.header().marshal_to(buf)?;
        buf.resize(buf.len() + self.padding_length, 0);
        Ok(buf.len())
    }

    fn check(&self) -> Result<()> {
        Ok(())
    }

    fn value_length(&self) -> usize {
        self.padding_length
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}
