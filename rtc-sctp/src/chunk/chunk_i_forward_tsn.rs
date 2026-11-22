use super::{chunk_header::*, chunk_type::*, *};

use bytes::{Buf, BufMut, Bytes, BytesMut};
use std::fmt;

/// The I-FORWARD-TSN chunk (RFC 8260 2.3.1): the FORWARD TSN of an association that uses
/// I-DATA. Each entry names the largest Message Identifier skipped on a stream, for its
/// ordered or for its unordered messages.
///
/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |   Type = 194  | Flags = 0x00  |      Length = Variable        |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                       New Cumulative TSN                      |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |       Stream Identifier       |          Reserved           |U|
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                       Message Identifier                      |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[derive(Default, Debug, Clone, PartialEq)]
pub(crate) struct ChunkIForwardTsn {
    pub(crate) new_cumulative_tsn: u32,
    pub(crate) streams: Vec<ChunkIForwardTsnStream>,
}

/// One entry of an I-FORWARD-TSN chunk.
#[derive(Default, Debug, Clone, PartialEq)]
pub(crate) struct ChunkIForwardTsnStream {
    pub(crate) identifier: u16,
    /// The entry is about the stream's unordered messages.
    pub(crate) unordered: bool,
    /// The largest Message Identifier skipped.
    pub(crate) mid: u32,
}

pub(crate) const I_FORWARD_TSN_STREAM_LENGTH: usize = 8;

impl fmt::Display for ChunkIForwardTsn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut res = vec![self.header().to_string()];
        res.push(format!("New Cumulative TSN: {}", self.new_cumulative_tsn));
        for s in &self.streams {
            res.push(format!(
                " - si={}, {}mid={}",
                s.identifier,
                if s.unordered { "unordered " } else { "" },
                s.mid
            ));
        }
        write!(f, "{}", res.join("\n"))
    }
}

impl Chunk for ChunkIForwardTsn {
    fn header(&self) -> ChunkHeader {
        ChunkHeader {
            typ: CT_I_FORWARD_TSN,
            flags: 0,
            value_length: self.value_length() as u16,
        }
    }

    fn unmarshal(buf: &Bytes) -> Result<Self> {
        let header = ChunkHeader::unmarshal(buf)?;
        if header.typ != CT_I_FORWARD_TSN {
            return Err(Error::ErrChunkTypeNotForwardTsn);
        }
        // The New Cumulative TSN, then whole entries.
        if header.value_length() < 4
            || !(header.value_length() - 4).is_multiple_of(I_FORWARD_TSN_STREAM_LENGTH)
        {
            return Err(Error::ErrChunkTooShort);
        }
        let reader = &mut buf.slice(CHUNK_HEADER_SIZE..CHUNK_HEADER_SIZE + header.value_length());
        let new_cumulative_tsn = reader.get_u32();
        let mut streams = Vec::with_capacity(reader.remaining() / I_FORWARD_TSN_STREAM_LENGTH);
        while reader.remaining() >= I_FORWARD_TSN_STREAM_LENGTH {
            let identifier = reader.get_u16();
            // Fifteen reserved bits, ignored on receipt, and the U bit.
            let unordered = reader.get_u16() & 1 != 0;
            let mid = reader.get_u32();
            streams.push(ChunkIForwardTsnStream {
                identifier,
                unordered,
                mid,
            });
        }
        Ok(ChunkIForwardTsn {
            new_cumulative_tsn,
            streams,
        })
    }

    fn marshal_to(&self, writer: &mut BytesMut) -> Result<usize> {
        self.header().marshal_to(writer)?;
        writer.put_u32(self.new_cumulative_tsn);
        for s in &self.streams {
            writer.put_u16(s.identifier);
            writer.put_u16(u16::from(s.unordered));
            writer.put_u32(s.mid);
        }
        Ok(writer.len())
    }

    fn check(&self) -> Result<()> {
        Ok(())
    }

    fn value_length(&self) -> usize {
        4 + I_FORWARD_TSN_STREAM_LENGTH * self.streams.len()
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}
