use super::*;

/// UnknownReportBlock stores a report block that is not parsed: one of a type this crate does
/// not model, or one of a known type that is malformed.
///
/// It keeps what the block header said, so the block is written back as what it was.
#[derive(Debug, Default, PartialEq, Eq, Clone)]
pub struct UnknownReportBlock {
    /// The block's type.
    pub block_type: BlockType,
    /// The type-specific octet of the block header.
    pub type_specific: TypeSpecificField,
    /// The block's bytes after its header, left unparsed. A whole number of 32-bit words.
    pub bytes: Bytes,
}

impl fmt::Display for UnknownReportBlock {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl UnknownReportBlock {
    /// The XR block header describing this block's type and length.
    pub fn xr_header(&self) -> XRHeader {
        XRHeader {
            block_type: self.block_type,
            type_specific: self.type_specific,
            block_length: (self.raw_size() / 4 - 1) as u16,
        }
    }
}

impl Packet for UnknownReportBlock {
    fn header(&self) -> Header {
        Header::default()
    }

    /// destination_ssrc returns an array of ssrc values that this report block refers to.
    fn destination_ssrc(&self) -> Vec<u32> {
        vec![]
    }

    fn raw_size(&self) -> usize {
        XR_HEADER_LENGTH + self.bytes.len()
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
    fn equal(&self, other: &dyn Packet) -> bool {
        other.as_any().downcast_ref::<UnknownReportBlock>() == Some(self)
    }
    fn cloned(&self) -> Box<dyn Packet> {
        Box::new(self.clone())
    }
}

impl MarshalSize for UnknownReportBlock {
    fn marshal_size(&self) -> usize {
        self.raw_size()
    }
}

impl Marshal for UnknownReportBlock {
    /// marshal_to encodes the UnknownReportBlock in binary
    fn marshal_to(&self, mut buf: &mut [u8]) -> Result<usize> {
        // RFC 3611 3: the block length counts 32-bit words, in 16 bits.
        if !self.bytes.len().is_multiple_of(4) || self.bytes.len() / 4 > u16::MAX as usize {
            return Err(Error::InvalidBlockSize);
        }
        if buf.remaining_mut() < self.marshal_size() {
            return Err(Error::BufferTooShort);
        }

        let h = self.xr_header();
        let n = h.marshal_to(buf)?;
        buf = &mut buf[n..];

        buf.put(self.bytes.clone());

        Ok(self.marshal_size())
    }
}

impl Unmarshal for UnknownReportBlock {
    /// Unmarshal decodes the UnknownReportBlock from binary
    fn unmarshal<B>(raw_packet: &mut B) -> Result<Self>
    where
        Self: Sized,
        B: Buf,
    {
        if raw_packet.remaining() < XR_HEADER_LENGTH {
            return Err(Error::PacketTooShort);
        }

        let xr_header = XRHeader::unmarshal(raw_packet)?;
        let block_length = match xr_header.block_length.checked_mul(4) {
            Some(length) => length,
            None => return Err(Error::InvalidBlockSize),
        };
        if raw_packet.remaining() < block_length as usize {
            return Err(Error::PacketTooShort);
        }

        let bytes = raw_packet.copy_to_bytes(block_length as usize);

        Ok(UnknownReportBlock {
            block_type: xr_header.block_type,
            type_specific: xr_header.type_specific,
            bytes,
        })
    }
}
