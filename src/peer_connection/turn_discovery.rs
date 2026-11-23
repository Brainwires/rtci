//! TURN server auto-discovery (RFC 8155), as an opt-in helper: the URLs an application adds
//! to its configuration when it has no TURN server of its own, which the engine then
//! resolves and uses like any other.
//!
//! - **Service resolution** (RFC 8155 section 4): a domain (the access network's, learned by
//!   the application from DHCP options `OPTION_V4_ACCESS_DOMAIN` / `OPTION_V6_ACCESS_DOMAIN`,
//!   or the domain of the user's identity, [`domain_of_identity`]) becomes port-less `turn:` /
//!   `turns:` URLs ([`urls_for_domain`]); the engine looks them up with S-NAPTR (application
//!   service `RELAY`) and SRV (RFC 5928 section 3, `dns_discovery`).
//! - **Anycast** (section 6): an Allocate to [`TURN_ANYCAST_IPV4`] / [`TURN_ANYCAST_IPV6`],
//!   which the anycast server answers with 300 (Try Alternate) naming its unicast address; the
//!   engine follows ALTERNATE-SERVER (RFC 8656 section 7.4) and allocates there
//!   ([`anycast_urls`]).
//! - **mDNS** (section 5): the service names a driver's multicast DNS browser asks for
//!   ([`MDNS_SERVICES`]); what it finds it adds as URLs. Running the multicast queries is the
//!   driver's (sockets), not the engine's.
//!
//! Getting the access network's domain from DHCP is the operating system's and stays with the
//! application. Without STUN authentication a client "MUST use (D)TLS unless it trusts the
//! network infrastructure" (section 3): [`urls_for_domain`] lists the secure transports first.

use std::net::{Ipv4Addr, Ipv6Addr};

/// The IPv4 TURN anycast address (RFC 8155 section 8, 192.0.0.10/32).
pub const TURN_ANYCAST_IPV4: Ipv4Addr = Ipv4Addr::new(192, 0, 0, 10);

/// The IPv6 TURN anycast address (RFC 8155 section 8, 2001:1::2/128).
pub const TURN_ANYCAST_IPV6: Ipv6Addr = Ipv6Addr::new(0x2001, 0x1, 0, 0, 0, 0, 0, 0x2);

/// The DNS-SD service names of TURN servers on the local link (RFC 8155 section 5.1).
pub const MDNS_SERVICES: [&str; 4] = [
    "_turn._udp.local.",
    "_turn._tcp.local.",
    "_turns._udp.local.",
    "_turns._tcp.local.",
];

/// The domain of a user identity (RFC 8155 section 4.1.2): the part after the last `@` of a
/// SIP URI, a bare JID or an e-mail address, without a `sip:` / `sips:` / `xmpp:` scheme or
/// any parameter. `None` when there is none.
pub fn domain_of_identity(identity: &str) -> Option<String> {
    let rest = identity
        .strip_prefix("sips:")
        .or_else(|| identity.strip_prefix("sip:"))
        .or_else(|| identity.strip_prefix("xmpp:"))
        .unwrap_or(identity);
    let (_, domain) = rest.rsplit_once('@')?;
    let domain = domain
        .split([';', '?', '/', '>', ':'])
        .next()?
        .trim()
        .trim_end_matches('.')
        .to_ascii_lowercase();
    (!domain.is_empty() && domain.contains('.')).then_some(domain)
}

/// The port-less TURN URLs of `domain` (RFC 8155 section 4.2 with RFC 5928): the engine finds
/// each server by S-NAPTR (`RELAY` with the transport's tag) and SRV. TLS and DTLS first.
pub fn urls_for_domain(domain: &str) -> Vec<String> {
    vec![
        format!("turns:{domain}?transport=tcp"),
        format!("turns:{domain}?transport=udp"),
        format!("turn:{domain}?transport=tcp"),
    ]
}

/// The URLs of the TURN anycast addresses (RFC 8155 section 6) over TCP: the anycast server
/// answers the Allocate with 300 (Try Alternate), and the engine allocates on the unicast
/// server it names. Port 3478, the default of `turn:`.
pub fn anycast_urls() -> Vec<String> {
    vec![
        format!("turn:{TURN_ANYCAST_IPV4}:3478?transport=tcp"),
        format!("turn:[{TURN_ANYCAST_IPV6}]:3478?transport=tcp"),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 8155 section 4.1.2: the domain is taken from a SIP URI, a bare JID or an e-mail
    /// address.
    #[test]
    fn the_domain_of_an_identity_is_what_follows_the_at_sign() {
        assert_eq!(
            domain_of_identity("sip:alice@Example.COM;transport=tls").as_deref(),
            Some("example.com")
        );
        assert_eq!(
            domain_of_identity("bob@jabber.example.org").as_deref(),
            Some("jabber.example.org")
        );
        assert_eq!(
            domain_of_identity("xmpp:carol@example.net/home").as_deref(),
            Some("example.net")
        );
        assert_eq!(domain_of_identity("no-domain"), None);
    }

    /// RFC 8155 sections 4.2, 6 and 8: port-less URLs for the engine's S-NAPTR resolution, the
    /// IANA anycast addresses.
    #[test]
    fn discovery_urls_are_port_less_for_a_domain_and_the_iana_anycast_addresses() {
        for url in urls_for_domain("example.com") {
            let parsed = ice::url::Url::parse_url(&url).unwrap();
            assert!(!parsed.explicit_port, "{url}: found by S-NAPTR / SRV");
        }
        assert_eq!(
            anycast_urls(),
            vec![
                "turn:192.0.0.10:3478?transport=tcp".to_owned(),
                "turn:[2001:1::2]:3478?transport=tcp".to_owned(),
            ]
        );
    }
}
