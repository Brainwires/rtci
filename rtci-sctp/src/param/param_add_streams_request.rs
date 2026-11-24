use super::{param_header::*, param_type::*, *};

use bytes::{Buf, BufMut, Bytes, BytesMut};

/// The Add Outgoing Streams Request Parameter (RFC 6525 4.5, type 17) and the Add Incoming
/// Streams Request Parameter (4.6, type 18), which differ in their type only.
///
/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |     Parameter Type = 17 / 18  |      Parameter Length = 12    |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |          Re-configuration Request Sequence Number             |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |      Number of new streams    |         Reserved              |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[derive(Default, Debug, Clone, PartialEq)]
pub(crate) struct ParamAddStreamsRequest {
    /// Type 18 (the sender asks for more of its incoming streams) rather than type 17 (the
    /// sender adds outgoing streams of its own).
    pub(crate) incoming: bool,
    pub(crate) reconfig_request_sequence_number: u32,
    pub(crate) number_of_new_streams: u16,
}

impl fmt::Display for ParamAddStreamsRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} {} {}",
            self.header(),
            self.reconfig_request_sequence_number,
            self.number_of_new_streams
        )
    }
}

impl Param for ParamAddStreamsRequest {
    fn header(&self) -> ParamHeader {
        ParamHeader {
            typ: if self.incoming {
                ParamType::AddIncStreamsReq
            } else {
                ParamType::AddOutStreamsReq
            },
            value_length: self.value_length() as u16,
        }
    }

    fn unmarshal(raw: &Bytes) -> Result<Self> {
        let header = ParamHeader::unmarshal(raw)?;
        let incoming = match header.typ {
            ParamType::AddOutStreamsReq => false,
            ParamType::AddIncStreamsReq => true,
            _ => return Err(Error::ErrParamTypeUnexpected),
        };
        // RFC 6525 4.5, 4.6: the length is 12.
        if header.value_length() != 8 {
            return Err(Error::ErrSsnResetRequestParamTooShort);
        }
        let reader =
            &mut raw.slice(PARAM_HEADER_LENGTH..PARAM_HEADER_LENGTH + header.value_length());
        let reconfig_request_sequence_number = reader.get_u32();
        let number_of_new_streams = reader.get_u16();
        // The Reserved field is ignored on receipt.
        Ok(ParamAddStreamsRequest {
            incoming,
            reconfig_request_sequence_number,
            number_of_new_streams,
        })
    }

    fn marshal_to(&self, buf: &mut BytesMut) -> Result<usize> {
        self.header().marshal_to(buf)?;
        buf.put_u32(self.reconfig_request_sequence_number);
        buf.put_u16(self.number_of_new_streams);
        // Reserved: zero on send.
        buf.put_u16(0);
        Ok(buf.len())
    }

    fn value_length(&self) -> usize {
        8
    }

    fn clone_to(&self) -> Box<dyn Param> {
        Box::new(self.clone())
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}
