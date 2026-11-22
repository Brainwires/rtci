#[cfg(test)]
mod renegotiation_info_test;

use super::*;
use shared::error::Error;

/// RenegotiationInfo allows a Client/Server to
/// communicate their renegotiation support
///
/// ## Specifications
///
/// * [RFC 5746]
///
/// [RFC 5746]: https://tools.ietf.org/html/rfc5746
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct ExtensionRenegotiationInfo {
    /// `renegotiated_connection<0..255>` (RFC 5746 3.2): empty in an initial handshake, the
    /// only kind this crate performs.
    pub(crate) renegotiated_connection: Vec<u8>,
}

impl ExtensionRenegotiationInfo {
    // TypeValue returns the extension TypeValue
    /// The extension type this value is carried under.
    pub fn extension_value(&self) -> ExtensionValue {
        ExtensionValue::RenegotiationInfo
    }

    /// The encoded size of this message in bytes.
    pub fn size(&self) -> usize {
        2 + 1 + self.renegotiated_connection.len()
    }

    /// marshal encodes the extension
    pub fn marshal<W: Write>(&self, writer: &mut W) -> Result<()> {
        if self.renegotiated_connection.len() > 255 {
            return Err(Error::ErrInvalidPacketLength);
        }
        writer.write_u16::<BigEndian>(1 + self.renegotiated_connection.len() as u16)?; //length
        writer.write_u8(self.renegotiated_connection.len() as u8)?;
        writer.write_all(&self.renegotiated_connection)?;

        Ok(writer.flush()?)
    }

    /// Unmarshal populates the extension from encoded data
    pub fn unmarshal<R: Read>(reader: &mut R) -> Result<Self> {
        let l = reader.read_u16::<BigEndian>()? as usize; //length
        let renegotiated_connection_len = reader.read_u8()? as usize;
        if l != 1 + renegotiated_connection_len {
            return Err(Error::ErrInvalidPacketLength);
        }
        let mut renegotiated_connection = vec![0u8; renegotiated_connection_len];
        reader.read_exact(&mut renegotiated_connection)?;

        Ok(ExtensionRenegotiationInfo {
            renegotiated_connection,
        })
    }
}
