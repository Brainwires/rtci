#[cfg(test)]
mod uri_test;

use shared::error::*;

use std::fmt;

// SCHEME definitions from RFC 7064 Section 3.2.

/// The `stun:` URI scheme.
pub const SCHEME: &str = "stun";
/// The `stuns:` URI scheme, for STUN over TLS or DTLS.
pub const SCHEME_SECURE: &str = "stuns";

// URI as defined in RFC 7064.
#[derive(PartialEq, Eq, Debug)]
/// A parsed `stun:` or `stuns:` URI.
pub struct Uri {
    /// The scheme, `stun` or `stuns`.
    pub scheme: String,
    /// The server host name or address.
    pub host: String,
    /// The port, if the URI specified one.
    pub port: Option<u16>,
}

impl fmt::Display for Uri {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // An IPv6 address is the only host with a colon in it (RFC 3986 IP-literal).
        let host = if self.host.contains(':') {
            format!("[{}]", self.host)
        } else {
            self.host.clone()
        };

        if let Some(port) = self.port {
            write!(f, "{}:{}:{}", self.scheme, host, port)
        } else {
            write!(f, "{}:{}", self.scheme, host)
        }
    }
}

impl Uri {
    /// Whether the scheme is `stuns`: STUN over TLS or DTLS.
    #[must_use]
    pub fn is_secure(&self) -> bool {
        self.scheme == SCHEME_SECURE
    }

    /// Whether the host is an IP address rather than a domain name.
    #[must_use]
    pub fn host_is_ip(&self) -> bool {
        self.host.parse::<std::net::IpAddr>().is_ok()
    }

    /// The port to contact: the URI's own, or the default of its scheme, 3478 for `stun` and
    /// 5349 for `stuns` (RFC 8489 section 8.1).
    #[must_use]
    pub fn port_or_default(&self) -> u16 {
        self.port.unwrap_or(if self.is_secure() {
            crate::DEFAULT_TLS_PORT
        } else {
            crate::DEFAULT_PORT
        })
    }

    /// The name to query for SRV records when the host is a domain name (RFC 8489 section
    /// 8.1, RFC 2782): the service is the scheme and the protocol is the transport STUN runs
    /// over, for instance `_stun._udp.example.org` or `_stuns._tcp.example.org`. `None` when
    /// the host is an IP address, which is used as it is, or the transport is neither UDP
    /// nor TCP.
    ///
    /// This crate performs no I/O: the application sends the query, tries the targets in the
    /// order RFC 2782 gives (the next one when a transaction times out), and falls back to
    /// the A and AAAA records of the host with [`port_or_default`](Self::port_or_default)
    /// when there is no SRV record.
    #[must_use]
    pub fn srv_query_name(&self, transport: shared::TransportProtocol) -> Option<String> {
        if self.host_is_ip() {
            return None;
        }
        let protocol = match transport {
            shared::TransportProtocol::UDP => "udp",
            shared::TransportProtocol::TCP => "tcp",
            // A transport this crate does not know has no SRV protocol label.
            _ => return None,
        };
        Some(format!(
            "_{}._{}.{}",
            self.scheme,
            protocol,
            self.host.trim_end_matches('.')
        ))
    }

    /// Parses a URI and applies the rule of RFC 8489 section 8.1 that
    /// [`parse_uri`](Self::parse_uri) leaves out: "A 'stuns' URI containing an IP address MUST
    /// be rejected", since a certificate is checked against a domain name.
    ///
    /// `parse_uri` accepts such a URI because browsers do; an application that validates the
    /// server's certificate itself, by IP address or by a name it holds, depends on that.
    ///
    /// # Errors
    ///
    /// As `parse_uri`, and `ErrHost` for a `stuns` URI whose host is an IP address.
    pub fn parse_uri_strict(raw: &str) -> Result<Self> {
        let uri = Self::parse_uri(raw)?;
        if uri.is_secure() && uri.host_is_ip() {
            return Err(Error::ErrHost);
        }
        Ok(uri)
    }

    /// Parse_uri parses URI from string.
    pub fn parse_uri(raw: &str) -> Result<Self> {
        // work around for url crate
        if raw.contains("//") {
            return Err(Error::ErrInvalidUrl);
        }

        let mut s = raw.to_string();
        let pos = raw.find(':');
        let p = pos.ok_or(Error::ErrSchemeType)?;
        s.replace_range(p..p + 1, "://");

        let raw_parts = url::Url::parse(&s)?;

        let scheme = raw_parts.scheme().into();
        if scheme != SCHEME && scheme != SCHEME_SECURE {
            return Err(Error::ErrSchemeType);
        }

        let host = raw_parts
            .host_str()
            .ok_or(Error::ErrHost)?
            .trim()
            .trim_start_matches('[')
            .trim_end_matches(']')
            .to_owned();

        let port = raw_parts.port();

        Ok(Uri { scheme, host, port })
    }
}
