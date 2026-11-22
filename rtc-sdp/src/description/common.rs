//! Fields shared by session and media descriptions.
//!
//! `c=` connection data ([`ConnectionInformation`](crate::description::common::ConnectionInformation), [`Address`](crate::description::common::Address)), `b=` bandwidth
//! ([`Bandwidth`](crate::description::common::Bandwidth)) and `a=` attributes ([`Attribute`](crate::description::common::Attribute)) may appear at either level in SDP, with
//! the media-level value overriding the session-level one — so they are modelled once here.
//!
//! An [`Attribute`](crate::description::common::Attribute) with no value is a flag, which is how `a=rtcp-mux` and the direction
//! attributes are expressed.
use std::fmt;

use shared::error::Result;

use super::session::ATTR_KEY_CANDIDATE;
use crate::grammar::{self, invalid, syntax};

/// Information describes the "i=" field which provides textual information
/// about the session.
pub type Information = String;

/// ConnectionInformation defines the representation for the "c=" field
/// containing connection data.
#[derive(Debug, Default, Clone)]
pub struct ConnectionInformation {
    /// The network type, always `IN` (Internet) in practice.
    pub network_type: String,
    /// The address type, `IP4` or `IP6`.
    pub address_type: String,
    /// The connection address. The grammar requires one: the parser always sets it, and a
    /// description built without one is not valid SDP.
    pub address: Option<Address>,
}

impl fmt::Display for ConnectionInformation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(address) = &self.address {
            write!(f, "{} {} {}", self.network_type, self.address_type, address,)
        } else {
            write!(f, "{} {}", self.network_type, self.address_type,)
        }
    }
}

impl ConnectionInformation {
    /// Parses the value of a `c=` line: `nettype SP addrtype SP connection-address`.
    ///
    /// The network and address types are tokens: RFC 8866 section 5.7 lets more be
    /// registered than `IN`, `IP4` and `IP6`, so an unknown one is kept, with its address
    /// unchecked beyond being free of white space. For `IP4` and `IP6` the address is
    /// checked against the grammar: a unicast address has no `/` (section 5.7: "the slash
    /// notation ... MUST NOT be used for IP unicast addresses"), an IPv4 multicast address
    /// has a TTL of 0 to 255, an IPv6 one has none.
    pub fn parse(value: &str) -> Result<Self> {
        Self::parse_fields(&grammar::fields("c=", value)?, value)
    }

    pub(crate) fn parse_fields(fields: &[&str], value: &str) -> Result<Self> {
        let [network_type, address_type, address] = fields else {
            return Err(syntax("c=", value));
        };
        if !grammar::is_token(network_type) || !grammar::is_token(address_type) {
            return Err(syntax("c=", value));
        }
        Ok(ConnectionInformation {
            network_type: (*network_type).to_owned(),
            address_type: (*address_type).to_owned(),
            address: Some(Address::parse(address_type, address)?),
        })
    }
}

/// Address describes a structured address token from within the "c=" field.
#[derive(Debug, Default, Clone)]
pub struct Address {
    /// The address itself: a host name, IPv4/IPv6 literal, or multicast group.
    pub address: String,
    /// The multicast TTL, for multicast addresses.
    pub ttl: Option<isize>,
    /// The number of consecutive multicast addresses in the range.
    pub range: Option<isize>,
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.address)?;
        if let Some(t) = &self.ttl {
            write!(f, "/{t}")?;
        }
        if let Some(r) = &self.range {
            write!(f, "/{r}")?;
        }
        Ok(())
    }
}

impl Address {
    /// Parses a `connection-address` of the given address type (`IP4`, `IP6`, or another
    /// registered type, whose addresses are kept as they are).
    pub fn parse(address_type: &str, value: &str) -> Result<Self> {
        let plain = |address: &str| Address {
            address: address.to_owned(),
            ttl: None,
            range: None,
        };
        let number = |what: &str, v: &str| -> Result<isize> {
            if !grammar::is_integer(v) {
                return Err(syntax(what, value));
            }
            v.parse::<u32>()
                .map(|n| n as isize)
                .map_err(|_| invalid(what, value))
        };

        let mut parts = value.split('/');
        let base = parts.next().unwrap_or_default();
        let (second, third) = (parts.next(), parts.next());
        if parts.next().is_some() {
            return Err(syntax("connection-address", value));
        }

        match (address_type, second, third) {
            ("IP4", None, None) => {
                if grammar::is_ip4_address(base) || grammar::is_fqdn(base) {
                    Ok(plain(base))
                } else {
                    Err(syntax("IP4 connection-address", value))
                }
            }
            ("IP4", Some(ttl), numaddr) => {
                if !grammar::is_ip4_multicast_address(base) {
                    return Err(syntax("IP4 multicast connection-address", value));
                }
                // ttl = (POS-DIGIT *2DIGIT) / "0", and section 5.7 bounds it to 0-255.
                let ttl = grammar::digits_no_leading_zero::<u8>("multicast TTL", ttl)
                    .map_err(|_| invalid("multicast TTL", value))?;
                Ok(Address {
                    address: base.to_owned(),
                    ttl: Some(ttl as isize),
                    range: numaddr
                        .map(|n| number("number of addresses", n))
                        .transpose()?,
                })
            }
            ("IP6", None, None) => {
                if grammar::is_ip6_address(base) || grammar::is_fqdn(base) {
                    Ok(plain(base))
                } else {
                    Err(syntax("IP6 connection-address", value))
                }
            }
            ("IP6", Some(numaddr), None) => {
                if !grammar::is_ip6_multicast_address(base) {
                    return Err(syntax("IP6 multicast connection-address", value));
                }
                Ok(Address {
                    address: base.to_owned(),
                    ttl: None,
                    range: Some(number("number of addresses", numaddr)?),
                })
            }
            ("IP4" | "IP6", _, _) => Err(syntax("connection-address", value)),
            _ => {
                if grammar::is_non_ws_string(value) {
                    Ok(plain(value))
                } else {
                    Err(syntax("connection-address", value))
                }
            }
        }
    }
}

/// The bandwidth modifiers (`bwtype`) the WebRTC specifications use.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BandwidthKind {
    /// `CT`, conference total, in kilobits per second (RFC 8866 section 5.8).
    ConferenceTotal,
    /// `AS`, application specific maximum, in kilobits per second (RFC 8866 section 5.8).
    ApplicationSpecific,
    /// `TIAS`, transport independent application specific maximum, in bits per second
    /// (RFC 3890).
    Tias,
    /// `RS`, RTCP bandwidth for active senders, in bits per second (RFC 3556).
    RtcpSenders,
    /// `RR`, RTCP bandwidth for receivers, in bits per second (RFC 3556).
    RtcpReceivers,
    /// Any other modifier. RFC 8866 section 5.8: a parser ignores it.
    Other,
}

impl Bandwidth {
    /// Parses the value of a `b=` line: `bwtype ":" bandwidth`, a token and digits.
    pub fn parse(value: &str) -> Result<Self> {
        let Some((bwtype, bandwidth)) = value.split_once(':') else {
            return Err(syntax("b=", value));
        };
        if !grammar::is_token(bwtype) {
            return Err(syntax("b=", value));
        }
        let bandwidth = grammar::digits::<u64>("b=", bandwidth)?;
        let (experimental, bandwidth_type) = match bwtype.strip_prefix("X-") {
            Some(rest) if !rest.is_empty() => (true, rest),
            _ => (false, bwtype),
        };
        Ok(Bandwidth {
            experimental,
            bandwidth_type: bandwidth_type.to_owned(),
            bandwidth,
        })
    }

    /// Which modifier this line carries.
    pub fn kind(&self) -> BandwidthKind {
        if self.experimental {
            return BandwidthKind::Other;
        }
        match self.bandwidth_type.as_str() {
            "CT" => BandwidthKind::ConferenceTotal,
            "AS" => BandwidthKind::ApplicationSpecific,
            "TIAS" => BandwidthKind::Tias,
            "RS" => BandwidthKind::RtcpSenders,
            "RR" => BandwidthKind::RtcpReceivers,
            _ => BandwidthKind::Other,
        }
    }

    /// The value in bits per second: `CT` and `AS` are in kilobits per second, `TIAS`, `RS`
    /// and `RR` in bits per second. `None` for a modifier whose unit is not known.
    pub fn bits_per_second(&self) -> Option<u64> {
        match self.kind() {
            BandwidthKind::ConferenceTotal | BandwidthKind::ApplicationSpecific => {
                Some(self.bandwidth.saturating_mul(1000))
            }
            BandwidthKind::Tias | BandwidthKind::RtcpSenders | BandwidthKind::RtcpReceivers => {
                Some(self.bandwidth)
            }
            BandwidthKind::Other => None,
        }
    }
}

/// The first `b=` line of `kind` among `lines`.
pub(crate) fn find_bandwidth(lines: &[Bandwidth], kind: BandwidthKind) -> Option<u64> {
    lines.iter().find(|b| b.kind() == kind).map(|b| b.bandwidth)
}

/// Bandwidth describes an optional field which denotes the proposed bandwidth
/// to be used by the session or media.
#[derive(Debug, Default, Clone)]
pub struct Bandwidth {
    /// Whether the bandwidth type is experimental, written with an `X-` prefix.
    pub experimental: bool,
    /// The bandwidth modifier, such as `AS` (application-specific) or `CT` (conference total).
    pub bandwidth_type: String,
    /// The proposed bandwidth, in the unit of the modifier: kilobits per second for `CT` and
    /// `AS`, bits per second for `TIAS`, `RS` and `RR`. See [`Bandwidth::bits_per_second`].
    pub bandwidth: u64,
}

impl fmt::Display for Bandwidth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let output = if self.experimental { "X-" } else { "" };
        write!(f, "{}{}:{}", output, self.bandwidth_type, self.bandwidth)
    }
}

/// EncryptionKey describes the "k=" line. RFC 8866 section 5.12 made it obsolete: it "MUST
/// NOT be included in an SDP description and MUST be discarded if received", so the parser
/// checks its syntax and drops it, and nothing writes one.
pub type EncryptionKey = String;

/// Attribute describes the "a=" field which represents the primary means for
/// extending SDP.
#[derive(Debug, Default, Clone)]
pub struct Attribute {
    /// The attribute name, the part before the `:`.
    pub key: String,
    /// The attribute value, or `None` for a flag attribute such as `a=rtcp-mux`.
    pub value: Option<String>,
}

impl fmt::Display for Attribute {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(value) = &self.value {
            write!(f, "{}:{}", self.key, value)
        } else {
            write!(f, "{}", self.key)
        }
    }
}

impl Attribute {
    /// new constructs a new attribute
    pub fn new(key: String, value: Option<String>) -> Self {
        Attribute { key, value }
    }

    /// The attribute's name and value, whichever way it was built.
    ///
    /// A parsed attribute has its name in [`Attribute::key`] and what follows the first
    /// colon in [`Attribute::value`]. An attribute built with the whole line as its key
    /// (`with_property_attribute("msid:stream track")`, which prints the same line) is
    /// split at its first colon here, so that both forms read alike.
    pub fn parts(&self) -> (&str, Option<&str>) {
        match &self.value {
            Some(value) => (self.key.as_str(), Some(value.as_str())),
            None => match self.key.split_once(':') {
                Some((name, value)) => (name, Some(value)),
                None => (self.key.as_str(), None),
            },
        }
    }

    /// is_ice_candidate returns true if the attribute key equals "candidate".
    pub fn is_ice_candidate(&self) -> bool {
        self.key.as_str() == ATTR_KEY_CANDIDATE
    }
}
