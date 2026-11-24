#[cfg(test)]
mod connid_test;

use std::fmt;

use stun::attributes::*;
use stun::checks::*;
use stun::message::*;

use shared::error::Result;

/// `ConnectionId` represents the `CONNECTION-ID` attribute as defined in
/// [RFC 6062 Section 6.2.1](https://www.rfc-editor.org/rfc/rfc6062#section-6.2.1).
///
/// The server names a peer's TCP connection with it, in a Connect success response or a
/// ConnectionAttempt indication; the client echoes it in the ConnectionBind request that
/// turns a new connection to the server into the data connection for that peer.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ConnectionId(pub u32);

impl fmt::Display for ConnectionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

const CONNECTION_ID_SIZE: usize = 4; // a 32-bit unsigned value

impl Setter for ConnectionId {
    /// Adds `CONNECTION-ID` to message.
    fn add_to(&self, m: &mut Message) -> Result<()> {
        m.add(ATTR_CONNECTION_ID, &self.0.to_be_bytes());
        Ok(())
    }
}

impl Getter for ConnectionId {
    /// Decodes `CONNECTION-ID` from message.
    fn get_from(&mut self, m: &Message) -> Result<()> {
        let v = m.get(ATTR_CONNECTION_ID)?;
        check_size(ATTR_CONNECTION_ID, v.len(), CONNECTION_ID_SIZE)?;
        self.0 = u32::from_be_bytes([v[0], v[1], v[2], v[3]]);
        Ok(())
    }
}
