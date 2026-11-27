use super::{chunk_header::*, chunk_type::*, *};

use bytes::{Bytes, BytesMut};
use std::fmt;

///Abort represents an SCTP Chunk of type ABORT
///
///The ABORT chunk is sent to the peer of an association to close the
///association.  The ABORT chunk may contain Cause Parameters to inform
///the receiver about the reason of the abort.  DATA chunks MUST NOT be
///bundled with ABORT.  Control chunks (except for INIT, INIT ACK, and
///SHUTDOWN COMPLETE) MAY be bundled with an ABORT, but they MUST be
///placed before the ABORT in the SCTP packet or they will be ignored by
///the receiver.
///
/// 0                   1                   2                   3
/// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
///+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///|   Type = 6    |Reserved     |T|           Length              |
///+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///|                                                               |
///|                   zero or more Error Causes                   |
///|                                                               |
///+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#[derive(Default, Debug, Clone)]
pub(crate) struct ChunkAbort {
    pub(crate) error_causes: Vec<ErrorCause>,
    /// The T bit (RFC 9260 3.3.7): the sender had no TCB and filled in the Verification Tag
    /// of the packet it answers ("reflected") instead of the receiver's own tag.
    pub(crate) tag_reflected: bool,
}

/// String makes chunkAbort printable
impl fmt::Display for ChunkAbort {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut res = vec![self.header().to_string()];

        for cause in &self.error_causes {
            res.push(format!(" - {}", cause));
        }

        write!(f, "{}", res.join("\n"))
    }
}

impl Chunk for ChunkAbort {
    fn header(&self) -> ChunkHeader {
        ChunkHeader {
            typ: CT_ABORT,
            flags: u8::from(self.tag_reflected),
            value_length: self.value_length() as u16,
        }
    }

    fn unmarshal(raw: &Bytes) -> Result<Self> {
        let header = ChunkHeader::unmarshal(raw)?;

        if header.typ != CT_ABORT {
            return Err(Error::ErrChunkTypeNotAbort);
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
        // RFC 9260 3.3.7: the value is error causes and the padding of the last one; bytes
        // past that are no cause, a format error, and such an ABORT "MUST [be] silently
        // discard[ed]". A value of one to three bytes used to read as an ABORT without causes.
        if offset < end {
            return Err(Error::ErrErrorCauseTooSmall);
        }

        Ok(ChunkAbort {
            error_causes,
            tag_reflected: header.flags & 1 != 0,
        })
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
