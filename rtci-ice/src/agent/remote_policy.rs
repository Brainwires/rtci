//! Where connectivity checks may be sent: the remote-address policy.
//!
//! Remote candidates come from whoever wrote the remote description (or trickled candidates,
//! or answered an mDNS query), so the destination of every connectivity check is chosen by the
//! peer. RFC 8445 §5.1.1.1 says what a candidate address may be (never the unspecified address,
//! a multicast group or a broadcast address), and §5.1.1.1 also leaves loopback addresses out
//! unless they are the only ones in use. The agent enforces that here:
//!
//! - a remote candidate on an address that cannot be a unicast destination (unspecified,
//!   `0.0.0.0/8`, multicast, the limited broadcast address) or on port 0 is dropped when it is
//!   added, whatever the settings;
//! - a loopback remote address is paired only with a loopback local candidate, and a
//!   link-local one (`169.254.0.0/16`, `fe80::/10`) only with a link-local local candidate,
//!   unless [`AgentConfig::allow_loopback_remote_candidates`] /
//!   [`AgentConfig::allow_link_local_remote_candidates`] say otherwise. An application that
//!   adds a loopback host candidate has chosen loopback; one that hasn't is never made to send
//!   checks into the host's own services or the link's metadata address;
//! - [`AgentConfig::remote_address_filter`], when set, is asked about every remote candidate's
//!   address and can refuse it.
//!
//! IPv4-mapped IPv6 addresses (`::ffff:a.b.c.d`) are judged as the IPv4 address they carry.
//!
//! [`AgentConfig::allow_loopback_remote_candidates`]: super::agent_config::AgentConfig::allow_loopback_remote_candidates
//! [`AgentConfig::allow_link_local_remote_candidates`]: super::agent_config::AgentConfig::allow_link_local_remote_candidates
//! [`AgentConfig::remote_address_filter`]: super::agent_config::AgentConfig::remote_address_filter

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

/// Decides whether connectivity checks may be sent to a remote candidate's address.
///
/// Called with the candidate's resolved address (an mDNS candidate's after it resolves) when the
/// candidate is added; returning `false` drops the candidate. See [`AgentConfig::remote_address_filter`](super::agent_config::AgentConfig::remote_address_filter).
pub type RemoteAddressFilter = Arc<dyn Fn(SocketAddr) -> bool + Send + Sync>;

/// What kind of destination an address is, for the policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AddressScope {
    /// Never a valid unicast destination (or port 0).
    Invalid,
    /// `127.0.0.0/8`, `::1`.
    Loopback,
    /// `169.254.0.0/16`, `fe80::/10`.
    LinkLocal,
    /// Anything else.
    Other,
}

/// Classifies `addr` as a destination: port 0 is [`AddressScope::Invalid`] too.
pub(crate) fn address_scope(addr: SocketAddr) -> AddressScope {
    if addr.port() == 0 {
        return AddressScope::Invalid;
    }
    ip_scope(addr.ip())
}

/// Classifies `ip`; an IPv4-mapped IPv6 address is judged as its IPv4 address.
pub(crate) fn ip_scope(ip: IpAddr) -> AddressScope {
    match ip.to_canonical() {
        IpAddr::V4(v4) => {
            if v4.octets()[0] == 0 || v4.is_multicast() || v4.is_broadcast() {
                // 0.0.0.0/8 is "this network" (RFC 1122 §3.2.1.3): a source, never a
                // destination; 0.0.0.0 itself is the unspecified address.
                AddressScope::Invalid
            } else if v4.is_loopback() {
                AddressScope::Loopback
            } else if v4.is_link_local() {
                AddressScope::LinkLocal
            } else {
                AddressScope::Other
            }
        }
        IpAddr::V6(v6) => {
            if v6.is_unspecified() || v6.is_multicast() {
                AddressScope::Invalid
            } else if v6.is_loopback() {
                AddressScope::Loopback
            } else if v6.is_unicast_link_local() {
                AddressScope::LinkLocal
            } else {
                AddressScope::Other
            }
        }
    }
}

/// The agent's remote-address policy, built once from its [`AgentConfig`](super::agent_config::AgentConfig).
#[derive(Clone, Default)]
pub(crate) struct RemotePolicy {
    pub(crate) allow_loopback: bool,
    pub(crate) allow_link_local: bool,
    pub(crate) filter: Option<RemoteAddressFilter>,
}

impl RemotePolicy {
    /// Whether a remote candidate on `remote` may be held at all.
    pub(crate) fn allows_candidate(&self, remote: SocketAddr) -> bool {
        if address_scope(remote) == AddressScope::Invalid {
            return false;
        }
        self.filter.as_ref().is_none_or(|filter| filter(remote))
    }

    /// Whether checks may be sent from the local candidate based at `local` to `remote`.
    pub(crate) fn allows_pair(&self, local: SocketAddr, remote: SocketAddr) -> bool {
        // RFC 8445 Section 6.1.2.2: "IPv6 link-local addresses MUST NOT be paired with other
        // than link-local addresses", in either direction, whatever the settings say.
        let v6_link_local =
            |ip: IpAddr| matches!(ip.to_canonical(), IpAddr::V6(v6) if v6.is_unicast_link_local());
        if v6_link_local(local.ip()) != v6_link_local(remote.ip())
            && address_scope(remote) != AddressScope::Invalid
        {
            return false;
        }
        match address_scope(remote) {
            AddressScope::Invalid => false,
            AddressScope::Loopback => {
                self.allow_loopback || ip_scope(local.ip()) == AddressScope::Loopback
            }
            AddressScope::LinkLocal => {
                self.allow_link_local || ip_scope(local.ip()) == AddressScope::LinkLocal
            }
            AddressScope::Other => true,
        }
    }
}
