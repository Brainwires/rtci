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
//!   address and can refuse it;
//! - [`AgentConfig::address_policy`], an [`IceAddressPolicy`], is the embedder's policy for
//!   both directions: it is asked about remote candidates, peer-reflexive sources and the
//!   source of every datagram that reaches the agent (and, in the peer connection, about STUN
//!   and TURN servers and ICE-TCP connections), and what it refuses the agent never holds,
//!   answers or takes in.
//!
//! IPv4-mapped IPv6 addresses (`::ffff:a.b.c.d`) are judged as the IPv4 address they carry.
//!
//! [`AgentConfig::allow_loopback_remote_candidates`]: super::agent_config::AgentConfig::allow_loopback_remote_candidates
//! [`AgentConfig::allow_link_local_remote_candidates`]: super::agent_config::AgentConfig::allow_link_local_remote_candidates
//! [`AgentConfig::remote_address_filter`]: super::agent_config::AgentConfig::remote_address_filter
//! [`AgentConfig::address_policy`]: super::agent_config::AgentConfig::address_policy

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

/// Decides whether connectivity checks may be sent to a remote candidate's address.
///
/// Called with the candidate's resolved address (an mDNS candidate's after it resolves) when the
/// candidate is added; returning `false` drops the candidate. See [`AgentConfig::remote_address_filter`](super::agent_config::AgentConfig::remote_address_filter).
pub type RemoteAddressFilter = Arc<dyn Fn(SocketAddr) -> bool + Send + Sync>;

/// Which way an address is used, as an [`IceAddressPolicy`] is asked about it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AddressDirection {
    /// Traffic from the address would be taken in.
    Inbound,
    /// Traffic would be sent to the address.
    Outbound,
}

/// Why an [`IceAddressPolicy`] is asked about an address: the point where the address enters
/// the ICE agent or the peer connection. Each purpose has one direction
/// ([`AddressPurpose::direction`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum AddressPurpose {
    /// A remote candidate the peer signalled (in a description or trickled), an mDNS candidate
    /// once its name resolved, or a remote TCP candidate a TURN TCP allocation would open a
    /// permission or a connection for: a destination of connectivity checks. Outbound.
    RemoteCandidate,
    /// The source of an authenticated Binding request that is no known remote candidate, about
    /// to be learned as a peer-reflexive remote candidate (RFC 8445 Section 7.3.1.3). Inbound.
    PeerReflexiveSource,
    /// A STUN or TURN server's address, after its name resolved (or its literal address),
    /// before the engine sends it anything. Outbound.
    StunTurnServer,
    /// The source of a datagram (or of ICE-TCP stream data, or of a peer's connection to a
    /// listener or a relayed TCP address) about to reach the ICE agent or the peer
    /// connection's media and DTLS. Inbound.
    InboundDatagramSource,
}

impl AddressPurpose {
    /// The direction the address is used in for this purpose.
    pub const fn direction(self) -> AddressDirection {
        match self {
            AddressPurpose::RemoteCandidate | AddressPurpose::StunTurnServer => {
                AddressDirection::Outbound
            }
            AddressPurpose::PeerReflexiveSource | AddressPurpose::InboundDatagramSource => {
                AddressDirection::Inbound
            }
        }
    }
}

/// The predicate of an [`IceAddressPolicy`]: `true` lets the address be used.
pub type AddressPolicyFn =
    dyn Fn(SocketAddr, AddressDirection, AddressPurpose) -> bool + Send + Sync;

/// An embedder's address policy for ICE: one predicate asked at every point where an address
/// enters the ICE agent or the peer connection's stream, TURN and server-reflexive code,
/// whichever way traffic would go.
///
/// - [`AddressPurpose::InboundDatagramSource`]: a datagram (or ICE-TCP stream data) from a
///   refused source is dropped before the agent reads it: it gets no STUN response, teaches no
///   peer-reflexive candidate, refreshes no consent, creates no pair, and no DTLS record or
///   media from it is taken. An ICE-TCP connection from such a source is refused when the
///   driver reports it accepted, and one a TURN server announces for a relayed TCP address is
///   not bound.
/// - [`AddressPurpose::RemoteCandidate`]: a remote candidate on a refused address is never
///   held or paired (the peer connection treats it as W3C webrtc-pc 4.4.2 "administratively
///   prohibited": `addIceCandidate` succeeds, no check is ever sent there).
/// - [`AddressPurpose::PeerReflexiveSource`]: a refused source is not learned as a
///   peer-reflexive remote candidate, so its request is not answered.
/// - [`AddressPurpose::StunTurnServer`]: a server address the engine would send its Binding
///   request or its Allocate to (after the name's resolution) is skipped, as if it had failed.
///
/// The predicate sees the address with an IPv4-mapped IPv6 address (`::ffff:a.b.c.d`) given as
/// the IPv4 address it carries, so one rule covers both forms. The default allows everything
/// and asks nothing: the agent behaves as it does without a policy.
///
/// RFC 8445's procedures (Section 7.3: answer every authenticated request, Section 7.3.1.3:
/// learn its source as a peer-reflexive candidate) apply to what reaches the agent; a datagram
/// the policy refuses is dropped before that, as a host firewall would drop it. This is how an
/// embedder carries out the address handling of RFC 8828 (which modes of address exposure and
/// which routes are allowed) beyond what the candidate types alone can say.
#[derive(Clone, Default)]
pub struct IceAddressPolicy(Option<Arc<AddressPolicyFn>>);

impl IceAddressPolicy {
    /// A policy asking `predicate` about every address; `false` refuses it.
    pub fn new(
        predicate: impl Fn(SocketAddr, AddressDirection, AddressPurpose) -> bool + Send + Sync + 'static,
    ) -> Self {
        Self(Some(Arc::new(predicate)))
    }

    /// The default: every address is allowed and the predicate is never asked.
    pub fn allow_all() -> Self {
        Self(None)
    }

    /// Whether this is the allow-everything default.
    pub fn is_allow_all(&self) -> bool {
        self.0.is_none()
    }

    /// Whether `addr` may be used for `purpose` (in that purpose's direction).
    pub fn allows(&self, addr: SocketAddr, purpose: AddressPurpose) -> bool {
        let Some(predicate) = &self.0 else {
            return true;
        };
        let addr = SocketAddr::new(addr.ip().to_canonical(), addr.port());
        predicate(addr, purpose.direction(), purpose)
    }
}

impl std::fmt::Debug for IceAddressPolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(if self.0.is_some() {
            "IceAddressPolicy(predicate)"
        } else {
            "IceAddressPolicy(allow all)"
        })
    }
}

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
    /// The embedder's address policy ([`AgentConfig::address_policy`](super::agent_config::AgentConfig::address_policy)).
    pub(crate) address: IceAddressPolicy,
}

impl RemotePolicy {
    /// Whether a remote candidate on `remote` may be held, for `purpose` (a signalled or
    /// resolved candidate, or a peer-reflexive source): [`Self::allows_candidate`] and the
    /// embedder's address policy.
    pub(crate) fn allows_remote(&self, remote: SocketAddr, purpose: AddressPurpose) -> bool {
        self.allows_candidate(remote) && self.address.allows(remote, purpose)
    }

    /// Whether traffic from `source` may reach the agent at all.
    pub(crate) fn allows_source(&self, source: SocketAddr) -> bool {
        self.address
            .allows(source, AddressPurpose::InboundDatagramSource)
    }

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
