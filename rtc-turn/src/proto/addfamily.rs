#[cfg(test)]
mod addfamily_test;

use stun::attributes::*;
use stun::checks::*;
use stun::message::*;

use super::reqfamily::{REQUESTED_FAMILY_IPV4, REQUESTED_FAMILY_IPV6, RequestedAddressFamily};
use shared::error::{Error, Result};

/// The `ADDITIONAL-ADDRESS-FAMILY` attribute type (0x8000), comprehension-optional.
pub const ATTR_ADDITIONAL_ADDRESS_FAMILY: AttrType = AttrType(0x8000);

/// `AdditionalAddressFamily` represents the `ADDITIONAL-ADDRESS-FAMILY` attribute as defined in
/// [RFC 8656 Section 18.11](https://www.rfc-editor.org/rfc/rfc8656#section-18.11).
///
/// In an Allocate request it asks for an IPv6 relayed address beside the IPv4 one. It is
/// encoded as `REQUESTED-ADDRESS-FAMILY` is, and IPv6 is its only valid value.
#[derive(Debug, PartialEq, Eq)]
pub struct AdditionalAddressFamily(pub RequestedAddressFamily);

impl Default for AdditionalAddressFamily {
    fn default() -> Self {
        Self(REQUESTED_FAMILY_IPV6)
    }
}

const ADDITIONAL_FAMILY_SIZE: usize = 4;

impl Setter for AdditionalAddressFamily {
    /// Adds `ADDITIONAL-ADDRESS-FAMILY` to message.
    ///
    /// # Errors
    ///
    /// Fails for any family but IPv6: RFC 8656 §7.1 has the value be 0x02.
    fn add_to(&self, m: &mut Message) -> Result<()> {
        if self.0 != REQUESTED_FAMILY_IPV6 {
            return Err(Error::ErrInvalidRequestedFamilyValue);
        }
        let mut v = vec![0; ADDITIONAL_FAMILY_SIZE];
        v[0] = self.0.0;
        // The other three bytes are reserved: zero when sent.
        m.add(ATTR_ADDITIONAL_ADDRESS_FAMILY, &v);
        Ok(())
    }
}

impl Getter for AdditionalAddressFamily {
    /// Decodes `ADDITIONAL-ADDRESS-FAMILY` from message. The reserved bytes are ignored.
    fn get_from(&mut self, m: &Message) -> Result<()> {
        let v = m.get(ATTR_ADDITIONAL_ADDRESS_FAMILY)?;
        check_size(
            ATTR_ADDITIONAL_ADDRESS_FAMILY,
            v.len(),
            ADDITIONAL_FAMILY_SIZE,
        )?;
        if v[0] != REQUESTED_FAMILY_IPV4.0 && v[0] != REQUESTED_FAMILY_IPV6.0 {
            return Err(Error::ErrInvalidRequestedFamilyValue);
        }
        self.0 = RequestedAddressFamily(v[0]);
        Ok(())
    }
}
