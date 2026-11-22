use super::{param_header::*, param_type::*, *};

use bytes::{Buf, BufMut, Bytes, BytesMut};

/// The Incoming SSN Reset Request Parameter (RFC 6525 4.2): asks the peer to reset some or
/// all of its outgoing streams, which are this side's incoming ones.
///
/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |     Parameter Type = 14       |  Parameter Length = 8 + 2 * N |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |          Re-configuration Request Sequence Number             |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |  Stream Number 1 (optional)   |    Stream Number 2 (optional) |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[derive(Default, Debug, Clone, PartialEq)]
pub(crate) struct ParamIncomingResetRequest {
    pub(crate) reconfig_request_sequence_number: u32,
    /// The streams to reset; none listed means all of them.
    pub(crate) stream_identifiers: Vec<u16>,
}

impl fmt::Display for ParamIncomingResetRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} {} {:?}",
            self.header(),
            self.reconfig_request_sequence_number,
            self.stream_identifiers
        )
    }
}

impl Param for ParamIncomingResetRequest {
    fn header(&self) -> ParamHeader {
        ParamHeader {
            typ: ParamType::IncSsnResetReq,
            value_length: self.value_length() as u16,
        }
    }

    fn unmarshal(raw: &Bytes) -> Result<Self> {
        let header = ParamHeader::unmarshal(raw)?;
        // RFC 6525 4.2: the length is 8 + 2 * N.
        if header.value_length() < 4 || !(header.value_length() - 4).is_multiple_of(2) {
            return Err(Error::ErrSsnResetRequestParamTooShort);
        }
        let reader =
            &mut raw.slice(PARAM_HEADER_LENGTH..PARAM_HEADER_LENGTH + header.value_length());
        let reconfig_request_sequence_number = reader.get_u32();
        let mut stream_identifiers = Vec::with_capacity(reader.remaining() / 2);
        while reader.remaining() >= 2 {
            stream_identifiers.push(reader.get_u16());
        }
        Ok(ParamIncomingResetRequest {
            reconfig_request_sequence_number,
            stream_identifiers,
        })
    }

    fn marshal_to(&self, buf: &mut BytesMut) -> Result<usize> {
        self.header().marshal_to(buf)?;
        buf.put_u32(self.reconfig_request_sequence_number);
        for sid in &self.stream_identifiers {
            buf.put_u16(*sid);
        }
        Ok(buf.len())
    }

    fn value_length(&self) -> usize {
        4 + self.stream_identifiers.len() * 2
    }

    fn clone_to(&self) -> Box<dyn Param> {
        Box::new(self.clone())
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}
