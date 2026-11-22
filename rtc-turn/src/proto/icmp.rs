#[cfg(test)]
mod icmp_test;

use std::fmt;

use stun::attributes::*;
use stun::checks::*;
use stun::message::*;

use shared::error::{Error, Result};

/// The `ICMP` attribute type (0x8004), comprehension-optional.
pub const ATTR_ICMP: AttrType = AttrType(0x8004);

/// `Icmp` represents the `ICMP` attribute as defined in
/// [RFC 8656 Section 18.13](https://www.rfc-editor.org/rfc/rfc8656#section-18.13).
///
/// A server puts it in a Data indication, in place of `DATA`, to tell the client that a UDP
/// datagram it relayed to the peer was answered with an ICMP error (RFC 8656 §11.5).
///
/// The value is 16 reserved bits, the ICMP type in 7 bits, the ICMP code in 9 bits, then 32
/// bits of error data, as Figure 11 of the RFC draws it.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Icmp {
    /// The ICMP type. What it means depends on whether the ICMP message was IPv4 or IPv6,
    /// which the peer address of the indication tells.
    pub icmp_type: u8,
    /// The ICMP code.
    pub code: u16,
    /// The next-hop MTU for an ICMPv6 type 2 (Packet Too Big) or an ICMPv4 type 3 code 4
    /// (fragmentation needed and DF set); zero otherwise.
    pub error_data: u32,
}

impl fmt::Display for Icmp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ICMP type {} code {} data {}",
            self.icmp_type, self.code, self.error_data
        )
    }
}

const ICMP_SIZE: usize = 8;
const ICMP_TYPE_MAX: u8 = 0x7f;
const ICMP_CODE_MAX: u16 = 0x1ff;

impl Setter for Icmp {
    /// Adds `ICMP` to message. The reserved field is zero.
    ///
    /// # Errors
    ///
    /// Fails if the type does not fit 7 bits or the code 9 bits.
    fn add_to(&self, m: &mut Message) -> Result<()> {
        if self.icmp_type > ICMP_TYPE_MAX || self.code > ICMP_CODE_MAX {
            return Err(Error::Other(format!("{self} does not fit the attribute")));
        }
        let mut v = vec![0; ICMP_SIZE];
        let type_and_code = (u16::from(self.icmp_type) << 9) | self.code;
        v[2..4].copy_from_slice(&type_and_code.to_be_bytes());
        v[4..8].copy_from_slice(&self.error_data.to_be_bytes());
        m.add(ATTR_ICMP, &v);
        Ok(())
    }
}

impl Getter for Icmp {
    /// Decodes `ICMP` from message. The reserved field is ignored.
    fn get_from(&mut self, m: &Message) -> Result<()> {
        let v = m.get(ATTR_ICMP)?;
        check_size(ATTR_ICMP, v.len(), ICMP_SIZE)?;
        let type_and_code = u16::from_be_bytes([v[2], v[3]]);
        self.icmp_type = (type_and_code >> 9) as u8;
        self.code = type_and_code & ICMP_CODE_MAX;
        self.error_data = u32::from_be_bytes([v[4], v[5], v[6], v[7]]);
        Ok(())
    }
}
