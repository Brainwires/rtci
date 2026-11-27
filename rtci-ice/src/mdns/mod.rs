pub mod exposure;
#[cfg(test)]
mod mdns_exposure_test;
#[cfg(test)]
mod mdns_local_name_test;
#[cfg(test)]
mod mdns_name_test;
#[cfg(test)]
mod mdns_test;

pub use exposure::is_global_unicast;
use mdns::Mdns;
use mdns::MdnsConfig;
/// The limit on mDNS messages one or several agents share (`AgentConfig::multicast_dns_rate_limit`).
pub use mdns::MdnsRateLimit;
use std::net::IpAddr;
use std::time::{Duration, Instant};
use uuid::Uuid;

use shared::error::Result;

/// Represents the different Multicast modes that ICE can run.
#[derive(Default, PartialEq, Eq, Debug, Copy, Clone)]
#[non_exhaustive]
pub enum MulticastDnsMode {
    /// Means remote mDNS candidates will be discarded, and local host candidates will use IPs.
    /// No mDNS message is sent: the mode for an application that wants no mDNS traffic.
    Disabled,

    /// Means remote mDNS candidates will be accepted, and local host candidates will use IPs.
    /// The default (draft-ietf-mmusic-mdns-ice-candidates Section 3.2.1 step 3: "Otherwise,
    /// resolve the candidate using mDNS"): a remote `<uuid>.local` name is queried, and one
    /// that does not resolve is ignored when its query ends (step 5), logged at debug.
    #[default]
    QueryOnly,

    /// Means remote mDNS candidates will be accepted, and local host candidates will use mDNS:
    /// with `multicast_dns_local_ip` set, the candidates on that IPv4 address are published
    /// under `multicast_dns_local_name`; without it, every local address (IPv4 and IPv6) under
    /// a `<uuid>.local` name of its own, as browsers do.
    QueryAndGather,
}

/// Whether the application can send the agent's mDNS messages, per address family: an mDNS
/// socket of that family is open (the agent writes its announcements and answers from port
/// 5353 to 224.0.0.251 or ff02::fb). Both by default. An application that has none for a
/// family tells the agent ([`Agent::set_multicast_dns_publishing`](crate::Agent::set_multicast_dns_publishing))
/// before it adds the host candidates of that family: a name of such an address cannot be
/// registered on the network (draft-ietf-mmusic-mdns-ice-candidates Section 3.1.1 step 4),
/// and [`AgentConfig::multicast_dns_fail_closed`](crate::agent::agent_config::AgentConfig::multicast_dns_fail_closed)
/// says what its candidates become.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct MulticastDnsPublishing {
    /// mDNS can be sent over IPv4.
    pub ipv4: bool,
    /// mDNS can be sent over IPv6.
    pub ipv6: bool,
}

impl Default for MulticastDnsPublishing {
    fn default() -> Self {
        Self {
            ipv4: true,
            ipv6: true,
        }
    }
}

impl MulticastDnsPublishing {
    /// Whether a name of `ip` can be published.
    pub fn covers(&self, ip: IpAddr) -> bool {
        if ip.is_ipv4() { self.ipv4 } else { self.ipv6 }
    }
}

pub(crate) fn generate_multicast_dns_name() -> String {
    // https://tools.ietf.org/id/draft-ietf-rtcweb-mdns-ice-candidates-02.html#gathering
    // The unique name MUST consist of a version 4 UUID as defined in [RFC4122], followed by “.local”.
    // This is a short-lived privacy alias, not a credential. `Uuid::new_v4` obtains randomness
    // from the UUID crate's secure random source without forcing provider ownership into mDNS.
    let u = Uuid::new_v4();
    format!("{u}.local")
}

/// Whether `name` is an ICE mDNS candidate name: a UUID in its hyphenated form followed by
/// `.local` (draft-ietf-mmusic-mdns-ice-candidates §3.1.1: "The unique name MUST consist of a
/// version 4 UUID as defined in [RFC4122], followed by \".local\""). The version nibble is not
/// checked, and either case is accepted.
///
/// A remote candidate's name is resolved only when it has this shape, so a remote description
/// cannot make the agent look up arbitrary names on the local network (`printer.local`, or the
/// bare `.local`).
pub(crate) fn is_ice_mdns_name(name: &str) -> bool {
    let Some(label) = name.strip_suffix(".local") else {
        return false;
    };
    let bytes = label.as_bytes();
    bytes.len() == 36
        && bytes.iter().enumerate().all(|(i, b)| match i {
            8 | 13 | 18 | 23 => *b == b'-',
            _ => b.is_ascii_hexdigit(),
        })
}

/// Whether `name` can be published as this agent's own mDNS name: exactly one label before
/// `.local` (RFC 6762 §3: names in the `.local.` domain), the label 1 to 63 letters, digits or
/// hyphens, not starting or ending with a hyphen (RFC 1123 §2.1). The bare `.local` has an
/// empty label and is the domain itself, not a host name.
pub(crate) fn is_valid_local_mdns_name(name: &str) -> bool {
    let Some(label) = name.strip_suffix(".local") else {
        return false;
    };
    !label.is_empty()
        && label.len() <= 63
        && !label.starts_with('-')
        && !label.ends_with('-')
        && label
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-')
}

/// What the agent's configuration says about its mDNS connection beyond names and addresses.
#[derive(Default, Clone)]
pub(crate) struct MdnsOptions {
    /// RFC 6762 Section 5.2: the first query of a series waits 20 to 120 ms.
    pub(crate) first_query_delay: bool,
    /// RFC 6762 Section 6.3: answers to a multi-question query wait 20 to 120 ms.
    pub(crate) multi_question_delay: bool,
    /// The driver reports each datagram's destination address.
    pub(crate) destination_reported: bool,
    /// The first query asks for a unicast response (QU).
    pub(crate) unicast_response: bool,
    /// A message limit shared with other connections.
    pub(crate) rate_limit: Option<mdns::MdnsRateLimit>,
}

pub(crate) fn create_multicast_dns(
    now: Instant,
    mdns_mode: MulticastDnsMode,
    mdns_local_name: &str,
    mdns_local_ip: &Option<IpAddr>,
    mdns_query_timeout: &Option<Duration>,
    options: MdnsOptions,
) -> Result<Option<Mdns>> {
    if mdns_mode == MulticastDnsMode::Disabled {
        return Ok(None);
    }

    // With a fixed local IP, its one name answers with it. Without one, each local address is
    // published under a name of its own as its host candidates are added
    // (`Mdns::add_local_name`), so the responder starts with none.
    let mut config = match (mdns_mode, mdns_local_ip) {
        (MulticastDnsMode::QueryAndGather, Some(local_ip)) => {
            log::info!("mDNS is using {local_ip} as local ip");
            MdnsConfig::new()
                .with_local_names(vec![mdns_local_name.to_owned()])
                .with_local_ip(*local_ip)
        }
        _ => MdnsConfig::new(),
    };

    if let Some(query_timeout) = mdns_query_timeout {
        config = config.with_query_timeout(*query_timeout);
    }
    config = config
        .with_first_query_delay(options.first_query_delay)
        .with_multi_question_delay(options.multi_question_delay)
        .with_destination_reported(options.destination_reported)
        .with_unicast_response(options.unicast_response);
    if let Some(rate_limit) = options.rate_limit {
        config = config.with_rate_limit(rate_limit);
    }

    let mdns_server = Mdns::new(now, config);

    Ok(Some(mdns_server))
}
