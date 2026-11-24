#[cfg(test)]
mod addr_test;

use crate::attributes::*;
use crate::message::*;
use shared::error::*;

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub(crate) const FAMILY_IPV4: u16 = 0x01;
pub(crate) const FAMILY_IPV6: u16 = 0x02;
pub(crate) const IPV4LEN: usize = 4;
pub(crate) const IPV6LEN: usize = 16;

/// Splits the value of an address attribute (MAPPED-ADDRESS, XOR-MAPPED-ADDRESS and the
/// attributes encoded like them) into its family, its port field and its address field.
///
/// RFC 8489 section 14.1: the first 8 bits are ignored, the family is 0x01 or 0x02, and the
/// address is exactly 32 bits (IPv4) or 128 bits (IPv6).
pub(crate) fn split_address_value(v: &[u8]) -> Result<(u16, u16, &[u8])> {
    if v.len() <= 4 {
        return Err(Error::ErrUnexpectedEof);
    }
    let family = u16::from(v[1]);
    let expected = match family {
        FAMILY_IPV4 => IPV4LEN,
        FAMILY_IPV6 => IPV6LEN,
        _ => return Err(Error::Other(format!("bad value {family}"))),
    };
    let address = &v[4..];
    if address.len() < expected {
        return Err(Error::ErrUnexpectedEof);
    }
    if address.len() > expected {
        return Err(Error::ErrAttributeSizeOverflow);
    }
    Ok((family, u16::from_be_bytes([v[2], v[3]]), address))
}

/// MappedAddress represents MAPPED-ADDRESS attribute.
///
/// This attribute is used only by servers for achieving backwards
/// compatibility with RFC 3489 clients.
///
/// RFC 8489 Section 14.1
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MappedAddress {
    /// The IP address.
    pub ip: IpAddr,
    /// The port.
    pub port: u16,
}

impl fmt::Display for MappedAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.ip {
            IpAddr::V4(ipv4) => write!(f, "{}:{}", ipv4, self.port),
            IpAddr::V6(ipv6) => write!(f, "[{}]:{}", ipv6, self.port),
        }
    }
}

impl Default for MappedAddress {
    fn default() -> Self {
        MappedAddress {
            ip: IpAddr::V4(Ipv4Addr::from(0)),
            port: 0,
        }
    }
}

impl Setter for MappedAddress {
    /// add_to adds MAPPED-ADDRESS to message.
    fn add_to(&self, m: &mut Message) -> Result<()> {
        self.add_to_as(m, ATTR_MAPPED_ADDRESS)
    }
}

impl Getter for MappedAddress {
    /// get_from decodes MAPPED-ADDRESS from message.
    fn get_from(&mut self, m: &Message) -> Result<()> {
        self.get_from_as(m, ATTR_MAPPED_ADDRESS)
    }
}

impl MappedAddress {
    /// get_from_as decodes MAPPED-ADDRESS value in message m as an attribute of type t.
    pub fn get_from_as(&mut self, m: &Message, t: AttrType) -> Result<()> {
        let v = m.get(t)?;
        let (family, port, address) = split_address_value(&v)?;
        self.port = port;

        if family == FAMILY_IPV6 {
            let mut ip = [0; IPV6LEN];
            ip.copy_from_slice(address);
            self.ip = IpAddr::V6(Ipv6Addr::from(ip));
        } else {
            let mut ip = [0; IPV4LEN];
            ip.copy_from_slice(address);
            self.ip = IpAddr::V4(Ipv4Addr::from(ip));
        };

        Ok(())
    }

    /// add_to_as adds MAPPED-ADDRESS value to m as t attribute.
    pub fn add_to_as(&self, m: &mut Message, t: AttrType) -> Result<()> {
        let family = match self.ip {
            IpAddr::V4(_) => FAMILY_IPV4,
            IpAddr::V6(_) => FAMILY_IPV6,
        };

        let mut value = vec![0u8; 4];
        //value[0] = 0 // first 8 bits are zeroes
        value[0..2].copy_from_slice(&family.to_be_bytes());
        value[2..4].copy_from_slice(&self.port.to_be_bytes());

        match self.ip {
            IpAddr::V4(ipv4) => value.extend_from_slice(&ipv4.octets()),
            IpAddr::V6(ipv6) => value.extend_from_slice(&ipv6.octets()),
        };

        m.add(t, &value);
        Ok(())
    }
}

/// Defines an attribute that is encoded as MAPPED-ADDRESS under its own attribute type.
macro_rules! address_attribute {
    ($(#[$doc:meta])* $name:ident, $attr:expr) => {
        $(#[$doc])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        pub struct $name {
            /// The IP address.
            pub ip: IpAddr,
            /// The port.
            pub port: u16,
        }

        impl Default for $name {
            fn default() -> Self {
                $name {
                    ip: IpAddr::V4(Ipv4Addr::from(0)),
                    port: 0,
                }
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}", std::net::SocketAddr::new(self.ip, self.port))
            }
        }

        impl Setter for $name {
            fn add_to(&self, m: &mut Message) -> Result<()> {
                MappedAddress {
                    ip: self.ip,
                    port: self.port,
                }
                .add_to_as(m, $attr)
            }
        }

        impl Getter for $name {
            fn get_from(&mut self, m: &Message) -> Result<()> {
                let mut a = MappedAddress::default();
                a.get_from_as(m, $attr)?;
                self.ip = a.ip;
                self.port = a.port;
                Ok(())
            }
        }
    };
}

address_attribute!(
    /// AlternateServer represents the ALTERNATE-SERVER attribute (type 0x8023): the server a
    /// 300 (Try Alternate) error response redirects to.
    ///
    /// It is encoded as MAPPED-ADDRESS. RFC 8489 Section 14.15; see
    /// [`alternate`](crate::alternate) for the client side of the mechanism.
    AlternateServer,
    ATTR_ALTERNATE_SERVER
);

address_attribute!(
    /// ResponseOrigin represents the RESPONSE-ORIGIN attribute (type 0x802b), encoded as
    /// MAPPED-ADDRESS.
    ///
    /// RFC 5780 Section 7.3
    ResponseOrigin,
    ATTR_RESPONSE_ORIGIN
);

address_attribute!(
    /// OtherAddress represents the OTHER-ADDRESS attribute (type 0x802c), encoded as
    /// MAPPED-ADDRESS.
    ///
    /// RFC 5780 Section 7.4
    OtherAddress,
    ATTR_OTHER_ADDRESS
);
