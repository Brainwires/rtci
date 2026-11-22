#[cfg(test)]
mod addrerror_test;

use std::fmt;

use stun::attributes::*;
use stun::error_code::ErrorCode;
use stun::message::*;

use super::reqfamily::{REQUESTED_FAMILY_IPV4, REQUESTED_FAMILY_IPV6, RequestedAddressFamily};
use shared::error::{Error, Result};

/// The `ADDRESS-ERROR-CODE` attribute type (0x8001), comprehension-optional.
pub const ATTR_ADDRESS_ERROR_CODE: AttrType = AttrType(0x8001);

/// `AddressErrorCode` represents the `ADDRESS-ERROR-CODE` attribute as defined in
/// [RFC 8656 Section 18.12](https://www.rfc-editor.org/rfc/rfc8656#section-18.12).
///
/// A server puts it in the success response to an Allocate that asked for two address
/// families when it could allocate only one: it names the family it did not allocate and why,
/// with 440 (Address Family not Supported) or 508 (Insufficient Capacity).
#[derive(Default, PartialEq, Eq, Clone)]
pub struct AddressErrorCode {
    /// The address family that was not allocated.
    pub family: RequestedAddressFamily,
    /// Why: the error code, as in `ERROR-CODE`.
    pub code: ErrorCode,
    /// The reason phrase, UTF-8.
    pub reason: Vec<u8>,
}

impl fmt::Debug for AddressErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AddressErrorCode")
            .field("family", &self.family)
            .field("code", &self.code.0)
            .field("reason", &String::from_utf8_lossy(&self.reason))
            .finish()
    }
}

impl fmt::Display for AddressErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}: {} {}",
            self.family,
            self.code.0,
            String::from_utf8_lossy(&self.reason)
        )
    }
}

const ADDRESS_ERROR_CODE_HEADER: usize = 4;
/// RFC 8656 §18.12: fewer than 128 characters, at most 763 bytes when decoding.
const ADDRESS_ERROR_CODE_REASON_MAX: usize = 763;
const ERROR_CODE_MODULO: u16 = 100;

impl Setter for AddressErrorCode {
    /// Adds `ADDRESS-ERROR-CODE` to message. The reserved bits are zero.
    fn add_to(&self, m: &mut Message) -> Result<()> {
        if self.family != REQUESTED_FAMILY_IPV4 && self.family != REQUESTED_FAMILY_IPV6 {
            return Err(Error::ErrInvalidRequestedFamilyValue);
        }
        let (class, number) = (
            self.code.0 / ERROR_CODE_MODULO,
            self.code.0 % ERROR_CODE_MODULO,
        );
        if !(3..=6).contains(&class) || self.reason.len() > ADDRESS_ERROR_CODE_REASON_MAX {
            return Err(Error::Other(format!(
                "ADDRESS-ERROR-CODE cannot carry {}",
                self.code.0
            )));
        }
        let mut v = Vec::with_capacity(ADDRESS_ERROR_CODE_HEADER + self.reason.len());
        v.extend_from_slice(&[self.family.0, 0, class as u8, number as u8]);
        v.extend_from_slice(&self.reason);
        m.add(ATTR_ADDRESS_ERROR_CODE, &v);
        Ok(())
    }
}

impl Getter for AddressErrorCode {
    /// Decodes `ADDRESS-ERROR-CODE` from message. The 13 reserved bits are ignored, as
    /// RFC 8656 §18.12 has a client do.
    fn get_from(&mut self, m: &Message) -> Result<()> {
        let v = m.get(ATTR_ADDRESS_ERROR_CODE)?;
        if v.len() < ADDRESS_ERROR_CODE_HEADER {
            return Err(Error::ErrUnexpectedEof);
        }
        if v[0] != REQUESTED_FAMILY_IPV4.0 && v[0] != REQUESTED_FAMILY_IPV6.0 {
            return Err(Error::ErrInvalidRequestedFamilyValue);
        }
        // Byte 1 and the upper five bits of byte 2 are reserved; the class is three bits.
        let class = u16::from(v[2] & 0x07);
        let number = u16::from(v[3]);
        self.family = RequestedAddressFamily(v[0]);
        self.code = ErrorCode(class * ERROR_CODE_MODULO + number);
        self.reason = v[ADDRESS_ERROR_CODE_HEADER..].to_vec();
        Ok(())
    }
}
