use super::{chunk_header::*, chunk_type::*, *};

use bytes::{Bytes, BytesMut};
use std::fmt;

///Operation Error (ERROR) (9)
///
///An endpoint sends this chunk to its peer endpoint to notify it of
///certain error conditions.  It contains one or more error causes.  An
///Operation Error is not considered fatal in and of itself, but may be
///used with an ERROR chunk to report a fatal condition.  It has the
///following parameters:
/// 0                   1                   2                   3
/// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
///+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///|   Type = 9    | Chunk  Flags  |           Length              |
///+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///|                                                               |
///|                    one or more Error Causes                   |
///|                                                               |
///+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///Chunk Flags: 8 bits
///  Set to 0 on transmit and ignored on receipt.
///Length: 16 bits (unsigned integer)
///  Set to the size of the chunk in bytes, including the chunk header
///  and all the Error Cause fields present.
#[derive(Default, Debug, Clone)]
pub(crate) struct ChunkError {
    pub(crate) error_causes: Vec<ErrorCause>,
}

/// makes ChunkError printable
impl fmt::Display for ChunkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut res = vec![self.header().to_string()];

        for cause in &self.error_causes {
            res.push(format!(" - {}", cause));
        }

        write!(f, "{}", res.join("\n"))
    }
}

impl Chunk for ChunkError {
    fn header(&self) -> ChunkHeader {
        ChunkHeader {
            typ: CT_ERROR,
            flags: 0,
            value_length: self.value_length() as u16,
        }
    }

    fn unmarshal(raw: &Bytes) -> Result<Self> {
        let header = ChunkHeader::unmarshal(raw)?;

        if header.typ != CT_ERROR {
            return Err(Error::ErrChunkTypeNotCt);
        }

        let mut error_causes = vec![];
        let mut offset = CHUNK_HEADER_SIZE;
        let end = CHUNK_HEADER_SIZE + header.value_length();
        while offset + ERROR_CAUSE_HEADER_LENGTH <= end {
            let e = ErrorCause::unmarshal(&raw.slice(offset..end))?;
            // RFC 9260 3.3.10: causes are padded to four bytes, as parameters are.
            offset += e.length() + get_padding_size(e.length());
            error_causes.push(e);
        }

        Ok(ChunkError { error_causes })
    }

    fn marshal_to(&self, buf: &mut BytesMut) -> Result<usize> {
        self.header().marshal_to(buf)?;
        marshal_error_causes(&self.error_causes, buf);
        Ok(buf.len())
    }

    fn check(&self) -> Result<()> {
        Ok(())
    }

    fn value_length(&self) -> usize {
        error_causes_length(&self.error_causes)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}
