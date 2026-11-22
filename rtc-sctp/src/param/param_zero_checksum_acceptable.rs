use super::{param_header::*, param_type::*, *};

use bytes::{Buf, BufMut, Bytes, BytesMut};

/// The Error Detection Method Identifier of "SCTP over DTLS" (RFC 9653 section 6): DTLS
/// below SCTP detects errors better than the CRC32c does.
pub(crate) const EDMID_SCTP_OVER_DTLS: u32 = 1;

/// The Zero Checksum Acceptable parameter (RFC 9653 section 4): its sender takes packets
/// whose checksum is zero, relying on the error detection method it names instead.
///
/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |          Type = 0x8001        |          Length = 8           |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |           Error Detection Method Identifier (EDMID)           |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[derive(Default, Debug, Clone, PartialEq)]
pub(crate) struct ParamZeroChecksumAcceptable {
    pub(crate) edmid: u32,
}

impl fmt::Display for ParamZeroChecksumAcceptable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}", self.header(), self.edmid)
    }
}

impl Param for ParamZeroChecksumAcceptable {
    fn header(&self) -> ParamHeader {
        ParamHeader {
            typ: ParamType::ZeroChecksumAcceptable,
            value_length: self.value_length() as u16,
        }
    }

    fn unmarshal(raw: &Bytes) -> Result<Self> {
        let header = ParamHeader::unmarshal(raw)?;
        // RFC 9653 4: "the value MUST be 8".
        if header.value_length() != 4 {
            return Err(Error::ErrParamHeaderTooShort);
        }
        let reader =
            &mut raw.slice(PARAM_HEADER_LENGTH..PARAM_HEADER_LENGTH + header.value_length());
        Ok(ParamZeroChecksumAcceptable {
            edmid: reader.get_u32(),
        })
    }

    fn marshal_to(&self, buf: &mut BytesMut) -> Result<usize> {
        self.header().marshal_to(buf)?;
        buf.put_u32(self.edmid);
        Ok(buf.len())
    }

    fn value_length(&self) -> usize {
        4
    }

    fn clone_to(&self) -> Box<dyn Param> {
        Box::new(self.clone())
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}
