//! The ICE attributes of RFC 8839 section 5: `candidate`, `remote-candidates`,
//! `ice-ufrag`, `ice-pwd`, `ice-options` and `ice-pacing`. (`ice-lite` and
//! `end-of-candidates` have no value: see `flag()`.)

use std::fmt;

use shared::error::Result;

use super::{TypedAttribute, string_attribute};
use crate::grammar::{self, invalid, syntax};

/// `component-id = 1*3DIGIT`, "a positive integer between 1 and 256".
fn component_id(what: &str, value: &str) -> Result<u16> {
    if value.len() > 3 {
        return Err(syntax(what, value));
    }
    let id: u16 = grammar::digits(what, value)?;
    if !(1..=256).contains(&id) {
        return Err(invalid(what, value));
    }
    Ok(id)
}

/// `a=candidate:...` (RFC 8839 section 5.1).
///
/// ```text
/// candidate-attribute = "candidate" ":" foundation SP component-id SP transport SP
///                       priority SP connection-address SP port SP cand-type
///                       [SP rel-addr] [SP rel-port] *(SP cand-extension)
/// foundation          = 1*32ice-char
/// component-id        = 1*3DIGIT
/// transport           = "UDP" / transport-extension
/// priority            = 1*10DIGIT
/// cand-type           = "typ" SP candidate-types
/// candidate-types     = "host" / "srflx" / "prflx" / "relay" / token
/// rel-addr            = "raddr" SP connection-address
/// rel-port            = "rport" SP port
/// cand-extension      = extension-att-name SP extension-att-value
/// ```
///
/// The address is an IPv4 address, an IPv6 address or a domain name (an mDNS name ends in
/// `.local`). What follows the type is read as name and value pairs: `raddr` and `rport`
/// fill [`Candidate::related_address`] and [`Candidate::related_port`], everything else
/// (`tcptype`, `generation`, `ufrag`, `network-id`, `network-cost`, ...) is kept in
/// [`Candidate::extensions`] in the order written.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Candidate {
    /// The foundation: 1 to 32 ice-chars.
    pub foundation: String,
    /// The component: 1 for RTP (and for everything when RTCP is multiplexed), 2 for RTCP.
    pub component: u16,
    /// The transport, as written: `UDP`, `udp`, `TCP`, ... Compare without regard to case.
    pub transport: String,
    /// The priority.
    pub priority: u32,
    /// The connection address.
    pub address: String,
    /// The port.
    pub port: u16,
    /// The candidate type: `host`, `srflx`, `prflx`, `relay`, or another token.
    pub typ: String,
    /// `raddr`: the related address (the base of a reflexive candidate, the mapped address
    /// of a relayed one).
    pub related_address: Option<String>,
    /// `rport`: the related port.
    pub related_port: Option<u16>,
    /// The other extension attributes, as `(name, value)`, in order.
    pub extensions: Vec<(String, String)>,
}

impl Candidate {
    /// The value of the extension attribute `name`.
    pub fn extension(&self, name: &str) -> Option<&str> {
        self.extensions
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
    }
}

impl TypedAttribute for Candidate {
    const NAME: &'static str = "candidate";

    fn parse(value: &str) -> Result<Self> {
        let fields = grammar::fields("a=candidate", value)?;
        let [
            foundation,
            component,
            transport,
            priority,
            address,
            port,
            typ_keyword,
            typ,
            rest @ ..,
        ] = &fields[..]
        else {
            return Err(syntax("a=candidate", value));
        };
        if !grammar::is_ice_chars(foundation)
            || foundation.len() > 32
            || !grammar::is_token(transport)
            || !grammar::is_candidate_address(address)
            || *typ_keyword != "typ"
            || !grammar::is_token(typ)
            || priority.len() > 10
            || !rest.len().is_multiple_of(2)
        {
            return Err(syntax("a=candidate", value));
        }

        let mut candidate = Candidate {
            foundation: (*foundation).to_owned(),
            component: component_id("a=candidate component", component)?,
            transport: (*transport).to_owned(),
            priority: grammar::digits("a=candidate priority", priority)?,
            address: (*address).to_owned(),
            port: grammar::port(port)?,
            typ: (*typ).to_owned(),
            related_address: None,
            related_port: None,
            extensions: Vec::with_capacity(rest.len() / 2),
        };
        for pair in rest.chunks(2) {
            let (name, extension_value) = (pair[0], pair[1]);
            match name {
                "raddr" if candidate.related_address.is_none() => {
                    if !grammar::is_candidate_address(extension_value) {
                        return Err(syntax("a=candidate raddr", value));
                    }
                    candidate.related_address = Some(extension_value.to_owned());
                }
                "rport" if candidate.related_port.is_none() => {
                    candidate.related_port = Some(grammar::port(extension_value)?);
                }
                "raddr" | "rport" => return Err(syntax("a=candidate", value)),
                _ => {
                    if !grammar::is_token(name) || !grammar::is_vchars(extension_value) {
                        return Err(syntax("a=candidate extension", value));
                    }
                    candidate
                        .extensions
                        .push((name.to_owned(), extension_value.to_owned()));
                }
            }
        }
        Ok(candidate)
    }
}

impl fmt::Display for Candidate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} {} {} {} {} {} typ {}",
            self.foundation,
            self.component,
            self.transport,
            self.priority,
            self.address,
            self.port,
            self.typ
        )?;
        if let Some(address) = &self.related_address {
            write!(f, " raddr {address}")?;
        }
        if let Some(port) = self.related_port {
            write!(f, " rport {port}")?;
        }
        for (name, value) in &self.extensions {
            write!(f, " {name} {value}")?;
        }
        Ok(())
    }
}

/// One `component-id SP connection-address SP port` of an `a=remote-candidates` line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteCandidate {
    /// The component.
    pub component: u16,
    /// The address of the remote candidate.
    pub address: String,
    /// Its port.
    pub port: u16,
}

/// `a=remote-candidates:<component> <address> <port> ...` (RFC 8839 section 5.2): the remote
/// candidates the controlling agent uses, one per component.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteCandidates {
    /// The remote candidates, in order. Never empty.
    pub candidates: Vec<RemoteCandidate>,
}

impl TypedAttribute for RemoteCandidates {
    const NAME: &'static str = "remote-candidates";

    fn parse(value: &str) -> Result<Self> {
        let fields = grammar::fields("a=remote-candidates", value)?;
        if !fields.len().is_multiple_of(3) {
            return Err(syntax("a=remote-candidates", value));
        }
        let mut candidates = Vec::with_capacity(fields.len() / 3);
        for triple in fields.chunks(3) {
            if !grammar::is_candidate_address(triple[1]) {
                return Err(syntax("a=remote-candidates", value));
            }
            candidates.push(RemoteCandidate {
                component: component_id("a=remote-candidates component", triple[0])?,
                address: triple[1].to_owned(),
                port: grammar::port(triple[2])?,
            });
        }
        Ok(RemoteCandidates { candidates })
    }
}

impl fmt::Display for RemoteCandidates {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, c) in self.candidates.iter().enumerate() {
            if i > 0 {
                f.write_str(" ")?;
            }
            write!(f, "{} {} {}", c.component, c.address, c.port)?;
        }
        Ok(())
    }
}

string_attribute!(
    /// `a=ice-ufrag:<ufrag>` (RFC 8839 section 5.4): `4*256ice-char`.
    IceUfrag,
    "ice-ufrag",
    "a=ice-ufrag",
    |v| (4..=256).contains(&v.len()) && grammar::is_ice_chars(v)
);

string_attribute!(
    /// `a=ice-pwd:<password>` (RFC 8839 section 5.4): `22*256ice-char`.
    ///
    /// `Debug` prints the password: do not log this type.
    IcePwd,
    "ice-pwd",
    "a=ice-pwd",
    |v| (22..=256).contains(&v.len()) && grammar::is_ice_chars(v)
);

/// `a=ice-options:<tag> *(SP <tag>)` (RFC 8839 section 5.6), each tag `1*ice-char`:
/// `trickle` (RFC 8840), `ice2` (RFC 8445), `renomination`, ...
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IceOptions {
    /// The option tags, in order. Never empty.
    pub tags: Vec<String>,
}

impl IceOptions {
    /// Whether the option `tag` is listed.
    pub fn contains(&self, tag: &str) -> bool {
        self.tags.iter().any(|t| t == tag)
    }
}

impl TypedAttribute for IceOptions {
    const NAME: &'static str = "ice-options";

    fn parse(value: &str) -> Result<Self> {
        let tags = grammar::fields("a=ice-options", value)?;
        if !tags.iter().all(|tag| grammar::is_ice_chars(tag)) {
            return Err(syntax("a=ice-options", value));
        }
        Ok(IceOptions {
            tags: tags.into_iter().map(str::to_owned).collect(),
        })
    }
}

impl fmt::Display for IceOptions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.tags.join(" "))
    }
}

/// `a=ice-pacing:<ms>` (RFC 8839 section 5.5): `1*10DIGIT`, the pacing of connectivity
/// checks in milliseconds; 50 when the attribute is absent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct IcePacing(pub u64);

impl TypedAttribute for IcePacing {
    const NAME: &'static str = "ice-pacing";

    fn parse(value: &str) -> Result<Self> {
        if value.len() > 10 {
            return Err(syntax("a=ice-pacing", value));
        }
        grammar::digits("a=ice-pacing", value).map(IcePacing)
    }
}

impl fmt::Display for IcePacing {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}
