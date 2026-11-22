//! The client side of the ALTERNATE-SERVER mechanism (RFC 8489 section 10): reading a 300
//! (Try Alternate) error response, and refusing a redirection loop.
//!
//! This crate performs no I/O, so it does not dial the alternate server. It gives the caller
//! what the redirection says ([`TryAlternate`](crate::alternate::TryAlternate)) and the rule that stops a loop
//! ([`RedirectGuard`](crate::alternate::RedirectGuard)); the caller sends the same request, with the same credentials, to the
//! new address over the same transport protocol. Over (D)TLS the caller validates the
//! server's certificate against [`TryAlternate::domain`](crate::alternate::TryAlternate::domain) when it is there, and against the
//! original domain when it is not.

#[cfg(test)]
mod alternate_test;

use crate::addr::{AlternateServer, MappedAddress};
use crate::attributes::*;
use crate::error_code::{CODE_TRY_ALTERNATE, ErrorCodeAttribute};
use crate::message::*;
use crate::textattrs::TextAttribute;
use crate::validated::ValidatedMessage;
use shared::error::*;

use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

/// How long a server counts as already tried (RFC 8489 section 10: "within the last five
/// minutes").
pub const REDIRECT_LOOP_WINDOW: Duration = Duration::from_secs(300);

/// What a 300 (Try Alternate) error response says.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TryAlternate {
    /// The ALTERNATE-SERVER attributes, in the order the server sent them: the first has the
    /// address family the request was sent to, a second one, if any, the other family.
    pub servers: Vec<SocketAddr>,
    /// ALTERNATE-DOMAIN: the name the alternate server's certificate is checked against when
    /// the transport is TLS or DTLS. `None`: the domain of the original request applies.
    pub domain: Option<String>,
}

impl TryAlternate {
    /// Reads the redirection out of `response`.
    ///
    /// `Ok(None)` when the response is not a 300 error response, when it has no
    /// ALTERNATE-SERVER, or when it is not authenticated: RFC 8489 section 14.8 lets a client
    /// follow a 300 only after validating its integrity attribute (a forged one would point
    /// the client's requests, credentials included, at a victim), and a
    /// [`ValidatedMessage`] shows only the attributes that integrity covers. The transaction
    /// has failed in each of those cases, as with any other error response.
    ///
    /// # Errors
    ///
    /// Fails when an ALTERNATE-SERVER or the ALTERNATE-DOMAIN is malformed.
    pub fn from_response(response: &ValidatedMessage) -> Result<Option<Self>> {
        if response.typ.class != CLASS_ERROR_RESPONSE || !response.is_authenticated() {
            return Ok(None);
        }
        let mut code = ErrorCodeAttribute::default();
        if code.get_from(response).is_err() || code.code != CODE_TRY_ALTERNATE {
            return Ok(None);
        }
        let mut servers = vec![];
        for attribute in &response.attributes.0 {
            if attribute.typ != ATTR_ALTERNATE_SERVER {
                continue;
            }
            // Each ALTERNATE-SERVER is decoded on its own: `Message::get` finds the first.
            let mut one = Message::new();
            one.write_header();
            one.add(ATTR_ALTERNATE_SERVER, &attribute.value);
            let mut server = MappedAddress::default();
            server.get_from_as(&one, ATTR_ALTERNATE_SERVER)?;
            servers.push(SocketAddr::new(server.ip, server.port));
        }
        if servers.is_empty() {
            return Ok(None);
        }
        let domain = match TextAttribute::get_from_as(response, ATTR_ALTERNATE_DOMAIN) {
            Ok(domain) => Some(domain.text),
            Err(Error::ErrAttributeNotFound) => None,
            Err(error) => return Err(error),
        };
        Ok(Some(Self { servers, domain }))
    }

    /// The alternate server of the address family of `original`, the server the request was
    /// sent to; the first alternate of any family when there is none.
    #[must_use]
    pub fn server_for(&self, original: IpAddr) -> Option<SocketAddr> {
        self.servers
            .iter()
            .find(|s| s.is_ipv4() == original.is_ipv4())
            .or(self.servers.first())
            .copied()
    }

    /// The ALTERNATE-SERVER attributes of this redirection, for a server (or a test) that
    /// builds the 300 response.
    #[must_use]
    pub fn server_attributes(&self) -> Vec<AlternateServer> {
        self.servers
            .iter()
            .map(|s| AlternateServer {
                ip: s.ip(),
                port: s.port(),
            })
            .collect()
    }
}

/// Remembers which servers a request went to, so that a redirection back to one of them
/// within five minutes is refused (RFC 8489 section 10: the client "MUST ignore the
/// redirection and consider the transaction to have failed").
///
/// One guard per request that may be redirected. Time is the caller's.
#[derive(Debug, Clone, Default)]
pub struct RedirectGuard {
    sent: Vec<(SocketAddr, Instant)>,
}

impl RedirectGuard {
    /// A guard that has seen no server.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Records that the request was sent to `server` at `now`: the original server first,
    /// then each alternate that is followed.
    pub fn sent_to(&mut self, server: SocketAddr, now: Instant) {
        self.forget_before(now);
        self.sent.retain(|(s, _)| *s != server);
        self.sent.push((server, now));
    }

    /// Whether a redirection to `server` at `now` may be followed: not when the request was
    /// sent there within the last five minutes.
    #[must_use]
    pub fn allows(&self, server: SocketAddr, now: Instant) -> bool {
        !self.sent.iter().any(|(s, at)| {
            *s == server && now.saturating_duration_since(*at) < REDIRECT_LOOP_WINDOW
        })
    }

    /// Follows a redirection if the rule allows it: records `server` and returns `true`, or
    /// returns `false` when it would be a loop.
    pub fn follow(&mut self, server: SocketAddr, now: Instant) -> bool {
        if !self.allows(server, now) {
            return false;
        }
        self.sent_to(server, now);
        true
    }

    fn forget_before(&mut self, now: Instant) {
        self.sent
            .retain(|(_, at)| now.saturating_duration_since(*at) < REDIRECT_LOOP_WINDOW);
    }
}
