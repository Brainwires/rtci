use super::{param_header::*, param_type::*, *};

use bytes::{Buf, BufMut, Bytes, BytesMut};

/// The SSN/TSN Reset Request Parameter (RFC 6525 4.3): asks for the TSNs of both directions
/// and the SSNs of every stream to start over.
///
/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |     Parameter Type = 15       |      Parameter Length = 8     |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |         Re-configuration Request Sequence Number              |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[derive(Default, Debug, Clone, PartialEq)]
pub(crate) struct ParamSsnTsnResetRequest {
    pub(crate) reconfig_request_sequence_number: u32,
}

impl fmt::Display for ParamSsnTsnResetRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} {}",
            self.header(),
            self.reconfig_request_sequence_number
        )
    }
}

impl Param for ParamSsnTsnResetRequest {
    fn header(&self) -> ParamHeader {
        ParamHeader {
            typ: ParamType::SsnTsnResetReq,
            value_length: self.value_length() as u16,
        }
    }

    fn unmarshal(raw: &Bytes) -> Result<Self> {
        let header = ParamHeader::unmarshal(raw)?;
        // RFC 6525 4.3: the length is 8.
        if header.value_length() != 4 {
            return Err(Error::ErrSsnResetRequestParamTooShort);
        }
        let reader =
            &mut raw.slice(PARAM_HEADER_LENGTH..PARAM_HEADER_LENGTH + header.value_length());
        Ok(ParamSsnTsnResetRequest {
            reconfig_request_sequence_number: reader.get_u32(),
        })
    }

    fn marshal_to(&self, buf: &mut BytesMut) -> Result<usize> {
        self.header().marshal_to(buf)?;
        buf.put_u32(self.reconfig_request_sequence_number);
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
