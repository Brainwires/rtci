use super::{param_header::*, param_type::*, *};

use bytes::{Buf, BufMut, Bytes, BytesMut};

/// Cookie Preservative (RFC 9260 3.3.2.1.3): the INIT's suggestion of how many milliseconds
/// to add to the State Cookie's lifetime, sent after a Stale Cookie error (5.2.6).
#[derive(Default, Debug, Clone, PartialEq)]
pub(crate) struct ParamCookiePreservative {
    pub(crate) suggested_increment_ms: u32,
}

impl fmt::Display for ParamCookiePreservative {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {} ms", self.header(), self.suggested_increment_ms)
    }
}

impl Param for ParamCookiePreservative {
    fn header(&self) -> ParamHeader {
        ParamHeader {
            typ: ParamType::CookiePreservative,
            value_length: self.value_length() as u16,
        }
    }

    fn unmarshal(raw: &Bytes) -> Result<Self> {
        let header = ParamHeader::unmarshal(raw)?;
        if header.value_length() != 4 {
            return Err(Error::ErrParamHeaderTooShort);
        }
        let mut value = raw.slice(PARAM_HEADER_LENGTH..PARAM_HEADER_LENGTH + 4);
        Ok(ParamCookiePreservative {
            suggested_increment_ms: value.get_u32(),
        })
    }

    fn marshal_to(&self, buf: &mut BytesMut) -> Result<usize> {
        self.header().marshal_to(buf)?;
        buf.put_u32(self.suggested_increment_ms);
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
