use super::*;

use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use std::io::{Read, Write};

/// NewSessionTicket (RFC 5077 section 3.3), DTLS 1.2: a ticket the server gives the client
/// in its last flight, for the client to resume the session with later. The ticket is opaque
/// to the client; an empty one says the server issues none after all.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HandshakeMessageNewSessionTicket {
    /// How long the client may keep the ticket, in seconds; 0 for unspecified.
    pub(crate) ticket_lifetime_hint: u32,
    pub(crate) ticket: Vec<u8>,
}

impl HandshakeMessageNewSessionTicket {
    /// The handshake type that identifies this message on the wire.
    pub fn handshake_type(&self) -> HandshakeType {
        HandshakeType::NewSessionTicket
    }

    /// The encoded size of this message in bytes.
    pub fn size(&self) -> usize {
        4 + 2 + self.ticket.len()
    }

    /// Encodes this message to `writer`.
    ///
    /// # Errors
    ///
    /// Fails on a write error, or if the ticket is longer than 65535 bytes.
    pub fn marshal<W: Write>(&self, writer: &mut W) -> Result<()> {
        let length = u16::try_from(self.ticket.len()).map_err(|_| Error::ErrInvalidPacketLength)?;
        writer.write_u32::<BigEndian>(self.ticket_lifetime_hint)?;
        writer.write_u16::<BigEndian>(length)?;
        writer.write_all(&self.ticket)?;
        Ok(writer.flush()?)
    }

    /// Decodes one of these messages from `reader`, which holds exactly the message body.
    ///
    /// # Errors
    ///
    /// Fails if `reader` is truncated, or holds more than the message.
    pub fn unmarshal<R: Read>(reader: &mut R) -> Result<Self> {
        let ticket_lifetime_hint = reader.read_u32::<BigEndian>()?;
        let length = reader.read_u16::<BigEndian>()? as usize;
        let mut ticket = vec![0u8; length];
        reader.read_exact(&mut ticket)?;
        let mut rest = [0u8; 1];
        if reader.read(&mut rest)? != 0 {
            return Err(Error::ErrInvalidPacketLength);
        }
        Ok(HandshakeMessageNewSessionTicket {
            ticket_lifetime_hint,
            ticket,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 5077 section 3.3: `uint32 ticket_lifetime_hint; opaque ticket<0..2^16-1>;`, and
    /// nothing after it.
    #[test]
    fn a_new_session_ticket_is_a_lifetime_hint_and_a_ticket() -> Result<()> {
        let message = HandshakeMessageNewSessionTicket {
            ticket_lifetime_hint: 7200,
            ticket: vec![1, 2, 3],
        };
        let mut raw = vec![];
        message.marshal(&mut raw)?;
        assert_eq!(raw, [0, 0, 0x1c, 0x20, 0, 3, 1, 2, 3]);
        assert_eq!(message.size(), raw.len());
        assert_eq!(
            HandshakeMessageNewSessionTicket::unmarshal(&mut raw.as_slice())?,
            message
        );
        let mut longer = raw.clone();
        longer.push(0);
        assert!(HandshakeMessageNewSessionTicket::unmarshal(&mut longer.as_slice()).is_err());
        assert!(HandshakeMessageNewSessionTicket::unmarshal(&mut &raw[..8]).is_err());
        Ok(())
    }
}
