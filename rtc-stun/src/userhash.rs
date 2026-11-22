//! The `USERHASH` attribute (RFC 8489 section 14.4), which replaces USERNAME when the server
//! supports username anonymity.

use crate::attributes::*;
use crate::integrity::CREDENTIALS_SEP;
use crate::message::*;
use crate::opaque::opaque_string;
use crypto::{HashAlgorithm, RTCCrypto};
use shared::error::*;

/// The length of a USERHASH value in bytes.
pub const USERHASH_SIZE: usize = 32;

/// The `USERHASH` attribute:
/// `SHA-256(OpaqueString(username) ":" OpaqueString(realm))`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Userhash(pub [u8; USERHASH_SIZE]);

impl Userhash {
    /// Hashes `username` in `realm`.
    ///
    /// # Errors
    ///
    /// Fails when either is not an OpaqueString (RFC 8265), or the provider fails.
    pub fn new(username: &str, realm: &str, crypto: &dyn RTCCrypto) -> Result<Self> {
        let input = [opaque_string(username)?, opaque_string(realm)?].join(CREDENTIALS_SEP);
        let hash = crypto
            .hash(HashAlgorithm::Sha256, input.as_bytes())
            .map_err(|e| Error::Crypto(e.to_string()))?;
        let value: [u8; USERHASH_SIZE] = hash.as_slice().try_into().map_err(|_| {
            Error::Crypto(format!(
                "provider returned an invalid SHA-256 digest length: {}",
                hash.len()
            ))
        })?;
        Ok(Self(value))
    }
}

impl Setter for Userhash {
    /// Adds USERHASH to `m`.
    fn add_to(&self, m: &mut Message) -> Result<()> {
        m.add(ATTR_USER_HASH, &self.0);
        Ok(())
    }
}

impl Getter for Userhash {
    /// Reads USERHASH from `m`.
    ///
    /// # Errors
    ///
    /// Fails when the attribute is absent or not 32 bytes.
    fn get_from(&mut self, m: &Message) -> Result<()> {
        let v = m.get(ATTR_USER_HASH)?;
        self.0 = v
            .as_slice()
            .try_into()
            .map_err(|_| Error::ErrAttributeSizeInvalid)?;
        Ok(())
    }
}
