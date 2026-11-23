//! ICE candidates: the addresses an agent can be reached at.
//!
//! A [`Candidate`](crate::candidate::Candidate) pairs a transport address with a [`CandidateType`](crate::candidate::CandidateType) — host, server-reflexive,
//! peer-reflexive or relay — and the bookkeeping ICE needs: a priority, a foundation, and
//! last-sent/last-received times that feed consent freshness.
//!
//! Type drives priority, and priority drives check order: host candidates are tried first
//! because they need no traversal, relay candidates last because they always cost an extra hop.
//! The [`foundation`](crate::candidate::Candidate::foundation) groups candidates that share a base and transport,
//! so redundant checks can be skipped.
//!
//! Each type has its own constructor module (`candidate_host`, `candidate_relay`, …), all
//! built on the shared [`CandidateConfig`](crate::candidate::CandidateConfig).

#[cfg(test)]
mod candidate_pair_test;
#[cfg(test)]
mod candidate_test;

// Upstream's candidate_relay_test and candidate_server_reflexive_test ran a TURN server in
// process; they live on as tests/testenv_ice.rs (test_relay_only_connection_{udp,tcp,tls},
// test_server_reflexive_only_connection), against coturn through real NATs.

/// Host candidates: an address on a local interface.
pub mod candidate_host;
/// A local/remote candidate pair and its check state.
pub mod candidate_pair;
/// Peer-reflexive candidates, learned from an inbound check's source address.
pub mod candidate_peer_reflexive;
/// Relay candidates, allocated on a TURN server.
pub mod candidate_relay;
/// Server-reflexive candidates, learned from a STUN Binding response.
pub mod candidate_server_reflexive;

use crate::network_type::NetworkType;
use crate::tcp_type::TcpType;
use crc::{CRC_32_ISCSI, Crc};
use serde::{Deserialize, Serialize};
use shared::error::*;
use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::time::Instant;

use crate::candidate::candidate_host::CandidateHostConfig;
use crate::candidate::candidate_peer_reflexive::CandidatePeerReflexiveConfig;
use crate::candidate::candidate_relay::CandidateRelayConfig;
use crate::candidate::candidate_server_reflexive::CandidateServerReflexiveConfig;
use crate::network_type::determine_network_type;

pub(crate) const RECEIVE_MTU: usize = 8192;
pub(crate) const DEFAULT_LOCAL_PREFERENCE: u16 = 65535;

/// Indicates that the candidate is used for RTP.
pub(crate) const COMPONENT_RTP: u16 = 1;
/// Indicates that the candidate is used for RTCP (RFC 8445 Section 5.1.1.1: component 2).
pub(crate) const COMPONENT_RTCP: u16 = 2;

/// The largest candidate priority (RFC 8445 Section 5.1.2: 1 to 2^31 - 1).
pub(crate) const MAX_CANDIDATE_PRIORITY: u32 = (1 << 31) - 1;

/// The component and priority of a candidate being constructed, checked against RFC 8445
/// Sections 5.1.2 and 5.1.2.1: a component is 1 to 256 (0, the `Default`, means RTP, 1), and a
/// given priority is at most 2^31 - 1 (0 means "compute it").
pub(crate) fn checked_component_and_priority(config: &CandidateConfig) -> Result<u16> {
    if config.priority > MAX_CANDIDATE_PRIORITY {
        return Err(Error::Other(format!(
            "{:?}: priority {} is above 2^31 - 1",
            Error::ErrParsePriority,
            config.priority
        )));
    }
    match config.component {
        0 => Ok(COMPONENT_RTP),
        1..=256 => Ok(config.component),
        other => Err(Error::Other(format!(
            "{:?}: component {other} is outside 1..=256",
            Error::ErrParseComponent
        ))),
    }
}

/// Represents the type of candidate `CandidateType` enum.
#[derive(Default, Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum CandidateType {
    #[default]
    #[serde(rename = "unspecified")]
    /// No candidate type was set.
    Unspecified,
    #[serde(rename = "host")]
    /// An address on one of this host's own interfaces.
    ///
    /// Highest priority: reachable without traversal when both peers share a network.
    Host,
    #[serde(rename = "srflx")]
    /// This host's address as seen by a STUN server — its public mapping through the NAT.
    ServerReflexive,
    #[serde(rename = "prflx")]
    /// An address learned from a peer's inbound connectivity check.
    ///
    /// Discovered during checking rather than gathering, when a NAT maps a different port per
    /// destination.
    PeerReflexive,
    #[serde(rename = "relay")]
    /// An address allocated on a TURN server, which forwards on this host's behalf.
    ///
    /// Lowest priority: it always costs an extra hop.
    Relay,
}

// String makes CandidateType printable
impl fmt::Display for CandidateType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match *self {
            CandidateType::Host => "host",
            CandidateType::ServerReflexive => "srflx",
            CandidateType::PeerReflexive => "prflx",
            CandidateType::Relay => "relay",
            CandidateType::Unspecified => "Unknown candidate type",
        };
        write!(f, "{s}")
    }
}

impl CandidateType {
    /// Returns the preference weight of a `CandidateType`.
    ///
    /// 4.1.2.2.  Guidelines for Choosing Type and Local Preferences
    /// The RECOMMENDED values are 126 for host candidates, 100
    /// for server reflexive candidates, 110 for peer reflexive candidates,
    /// and 0 for relayed candidates.
    #[must_use]
    pub const fn preference(self) -> u16 {
        match self {
            Self::Host => 126,
            Self::PeerReflexive => 110,
            Self::ServerReflexive => 100,
            Self::Relay | CandidateType::Unspecified => 0,
        }
    }
}

pub(crate) fn contains_candidate_type(
    candidate_type: CandidateType,
    candidate_type_list: &[CandidateType],
) -> bool {
    if candidate_type_list.is_empty() {
        return false;
    }
    for ct in candidate_type_list {
        if *ct == candidate_type {
            return true;
        }
    }
    false
}

/// Convey transport addresses related to the candidate, useful for diagnostics and other purposes.
#[derive(PartialEq, Eq, Debug, Clone)]
pub struct CandidateRelatedAddress {
    /// The address of the related candidate — the base this one was derived from.
    /// The candidate's address.
    pub address: String,
    /// The port of the related candidate.
    /// The candidate's port.
    pub port: u16,
}

// String makes CandidateRelatedAddress printable
impl fmt::Display for CandidateRelatedAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, " related {}:{}", self.address, self.port)
    }
}

#[derive(Default)]
/// The fields common to every candidate type, used when constructing one.
pub struct CandidateConfig {
    /// A unique identifier for this candidate; generated when left empty.
    pub candidate_id: String,
    /// The transport, `udp` or `tcp`.
    pub network: String,
    /// The candidate's address.
    pub address: String,
    /// The candidate's port.
    pub port: u16,
    /// The RTP component id: `1` for RTP, `2` for RTCP when not multiplexed.
    pub component: u16,
    /// The candidate priority; computed from the type and local preference when zero.
    pub priority: u32,
    /// The foundation, which groups candidates that share a base and transport.
    ///
    /// Pairs with the same foundation are checked together, so redundant checks are avoided.
    pub foundation: String,
}

#[derive(Clone, Debug)]
/// One ICE candidate: a transport address this agent can be reached at, or can reach a peer
/// at, together with its type, priority and liveness bookkeeping.
pub struct Candidate {
    pub(crate) id: String,
    pub(crate) network_type: NetworkType,
    pub(crate) candidate_type: CandidateType,

    pub(crate) component: u16,
    pub(crate) address: String,
    pub(crate) port: u16,
    pub(crate) related_address: Option<CandidateRelatedAddress>,
    pub(crate) tcp_type: TcpType,

    pub(crate) resolved_addr: SocketAddr,

    /// When traffic was last sent on this candidate, or `None` if none ever has been.
    pub(crate) last_sent: Option<Instant>,
    /// When traffic was last received on this candidate, or `None` if none ever has been.
    pub(crate) last_received: Option<Instant>,
    /// When an authenticated (MESSAGE-INTEGRITY checked) Binding request or response last
    /// arrived from this candidate. Consent freshness (RFC 7675) is judged on this alone, so
    /// unauthenticated traffic from the address cannot keep a dead pair alive.
    pub(crate) last_authenticated: Option<Instant>,
    /// When an authenticated success response to one of our own pending Binding requests last
    /// arrived from this candidate. This is consent (RFC 7675 §5.1): the peer's own requests do
    /// not grant it.
    pub(crate) last_consent: Option<Instant>,

    pub(crate) foundation_override: String,
    pub(crate) priority_override: u32,
    /// Where this candidate stands among the local candidates of its type (0 is the most
    /// preferred): the local preference is the largest value less this rank. `None` until the
    /// application or the agent ranks it. See [`Candidate::set_local_preference_rank`].
    pub(crate) local_preference_rank: Option<u16>,
    /// The related address (the base) is a host address hidden behind an mDNS name: it is
    /// not signalled. See [`Candidate::signalled_related_address`].
    pub(crate) hide_related_address: bool,
    /// A local candidate the agent holds but has not been told is conveyed to the peer yet:
    /// it is not paired until it is (RFC 8838 Section 10). See
    /// [`Agent::add_unconveyed_local_candidate`](crate::agent::Agent::add_unconveyed_local_candidate).
    pub(crate) unconveyed: bool,

    pub(crate) network: String,

    pub(crate) url: Option<String>,
}

impl Default for Candidate {
    fn default() -> Self {
        Self {
            id: String::new(),
            network_type: NetworkType::Unspecified,
            candidate_type: CandidateType::default(),

            component: 0,
            address: String::new(),
            port: 0,
            related_address: None,
            tcp_type: TcpType::default(),

            resolved_addr: SocketAddr::new(IpAddr::from([0, 0, 0, 0]), 0),

            last_sent: None,
            last_received: None,
            last_authenticated: None,
            last_consent: None,

            foundation_override: String::new(),
            priority_override: 0,
            local_preference_rank: None,
            hide_related_address: false,
            unconveyed: false,
            network: String::new(),

            url: None,
        }
    }
}

// String makes the candidateBase printable
impl fmt::Display for Candidate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(related_address) = self.related_address() {
            write!(
                f,
                "{} {} {}:{}{}",
                self.network_type(),
                self.candidate_type(),
                self.address(),
                self.port(),
                related_address,
            )
        } else {
            write!(
                f,
                "{} {} {}:{}",
                self.network_type(),
                self.candidate_type(),
                self.address(),
                self.port(),
            )
        }
    }
}

impl Candidate {
    /// The candidate's foundation (RFC 8445 Section 5.1.1.3): two candidates have the same one
    /// when they have the same type, their bases have the same IP address (ports may differ),
    /// they came from the same STUN or TURN server (reflexive and relayed ones) and they use
    /// the same transport protocol.
    ///
    /// A host candidate's base is itself (an mDNS name stands for its address); a reflexive
    /// candidate's base is its related address; a relayed candidate's base is the relayed
    /// address. A foundation groups equivalent candidates; it is deterministic bookkeeping
    /// rather than a secret, random identifier. CRC-32C is therefore intentional here.
    pub fn foundation(&self) -> String {
        if !self.foundation_override.is_empty() {
            return self.foundation_override.clone();
        }

        let base = match (self.candidate_type, &self.related_address) {
            (CandidateType::ServerReflexive | CandidateType::PeerReflexive, Some(related))
                if !related.address.is_empty() =>
            {
                related.address.as_str()
            }
            _ => self.address.as_str(),
        };

        let mut buf = vec![];
        buf.extend_from_slice(self.candidate_type().to_string().as_bytes());
        buf.extend_from_slice(base.as_bytes());
        buf.extend_from_slice(self.network_type().to_string().as_bytes());
        if let Some(url) = &self.url {
            buf.extend_from_slice(url.as_bytes());
        }

        let checksum = Crc::<u32>::new(&CRC_32_ISCSI).checksum(&buf);

        format!("{checksum}")
    }

    /// Returns Candidate ID.
    pub fn id(&self) -> &str {
        self.id.as_str()
    }

    /// Returns candidate component.
    pub fn component(&self) -> u16 {
        self.component
    }

    /// Sets candidate component.
    pub fn set_component(&mut self, component: u16) {
        self.component = component;
    }

    /// When traffic was last received on this candidate.
    ///
    /// `None` until the first packet arrives. A freshly constructed or freshly parsed candidate
    /// has not received anything, and previously said it had — it was seeded with the
    /// construction instant, which also meant every candidate constructor needed a clock.
    pub fn last_received(&self) -> Option<Instant> {
        self.last_received
    }

    /// When traffic was last sent on this candidate, or `None` if none ever has been.
    pub fn last_sent(&self) -> Option<Instant> {
        self.last_sent
    }

    /// Returns candidate NetworkType.
    pub fn network_type(&self) -> NetworkType {
        self.network_type
    }

    /// Returns Candidate Address.
    pub fn address(&self) -> &str {
        self.address.as_str()
    }

    /// Returns Candidate Port.
    pub fn port(&self) -> u16 {
        self.port
    }

    /// Computes the priority for this ICE Candidate.
    pub fn priority(&self) -> u32 {
        if self.priority_override != 0 {
            return self.priority_override;
        }

        // The local preference MUST be an integer from 0 (lowest preference) to
        // 65535 (highest preference) inclusive.  When there is only a single IP
        // address, this value SHOULD be set to 65535.  If there are multiple
        // candidates for a particular component for a particular data stream
        // that have the same type, the local preference MUST be unique for each
        // one.
        (1 << 24) * u32::from(self.type_preference(self.candidate_type()))
            + (1 << 8) * u32::from(self.local_preference())
            + 256u32.saturating_sub(u32::from(self.component()))
    }

    /// The type preference of `candidate_type` on this candidate's transport. RFC 6544
    /// section 4.2: "the type preferences for the preferred transport protocol candidates
    /// SHOULD be increased and/or the type preferences for the other transport protocol
    /// candidates SHOULD be decreased ... changing type preference values by one for the other
    /// transport protocol candidates is enough" when the candidate type matters more, and "For
    /// RTP-based media streams, it is RECOMMENDED that UDP candidates are preferred over TCP
    /// candidates". A TCP candidate takes the UDP type preference less one (host 125,
    /// peer-reflexive 109, server-reflexive 99): a TCP host candidate still outranks a UDP
    /// server-reflexive one, a UDP candidate outranks the TCP one of its type. A relayed TCP
    /// candidate stays at 0 ("relayed candidates are still preferred lower than the other
    /// candidate types"), below the UDP relayed one by its local preference.
    pub fn type_preference(&self, candidate_type: CandidateType) -> u16 {
        let preference = candidate_type.preference();
        if self.network_type().is_tcp() {
            preference.saturating_sub(1)
        } else {
            preference
        }
    }

    /// The priority this candidate would have as a peer-reflexive one: the value of the
    /// PRIORITY attribute in a connectivity check sent from it (RFC 8445 Section 7.1.1). The
    /// peer-reflexive type preference (of its transport, RFC 6544 section 4.2), with this
    /// candidate's local preference and component.
    pub fn peer_reflexive_priority(&self) -> u32 {
        (u32::from(self.type_preference(CandidateType::PeerReflexive)) << 24)
            | (self.priority() & 0x00ff_ffff)
    }

    /// Returns `Option<CandidateRelatedAddress>`.
    pub fn related_address(&self) -> Option<CandidateRelatedAddress> {
        self.related_address.as_ref().cloned()
    }

    /// Returns candidate type.
    pub fn candidate_type(&self) -> CandidateType {
        self.candidate_type
    }

    /// The TCP role for ICE-TCP candidates; `Unspecified` for UDP.
    pub fn tcp_type(&self) -> TcpType {
        self.tcp_type
    }

    /// Sets the TCP role of an ICE-TCP candidate of any type (RFC 6544 Section 4.5: every TCP
    /// candidate is signalled with a `tcptype`).
    pub fn set_tcp_type(&mut self, tcp_type: TcpType) {
        self.tcp_type = tcp_type;
    }

    /// The STUN or TURN server this candidate was gathered from, if any.
    pub fn url(&self) -> Option<&str> {
        self.url.as_deref()
    }

    /// Returns the string representation of the ICECandidate.
    pub fn marshal(&self) -> String {
        let mut val = format!(
            "{} {} {} {} {} {} typ {}",
            self.foundation(),
            self.component(),
            self.network_type().network_short(),
            self.priority(),
            self.address(),
            self.port(),
            self.candidate_type()
        );

        // RFC 8839 Section 5.1: rel-addr and rel-port come before the extension attributes,
        // of which `tcptype` (RFC 6544 Section 4.5) is one, for every candidate type.
        if let Some(related_address) = self.signalled_related_address() {
            val += format!(
                " raddr {} rport {}",
                related_address.address, related_address.port,
            )
            .as_str();
        }

        if self.tcp_type != TcpType::Unspecified {
            val += format!(" tcptype {}", self.tcp_type()).as_str();
        }

        val
    }

    /// The related address to signal and to show in statistics: the candidate's own, or,
    /// when its base is a host address hidden behind an mDNS name, `0.0.0.0` (`::`) and port
    /// 9 (draft-ietf-mmusic-mdns-ice-candidates Section 3.1.2.2: "the agent MUST set the
    /// rel-addr and rel-port fields of the candidate to 0.0.0.0/:: and 9").
    pub fn signalled_related_address(&self) -> Option<CandidateRelatedAddress> {
        let related = self.related_address()?;
        if !self.hide_related_address {
            return Some(related);
        }
        Some(CandidateRelatedAddress {
            address: if self.network_type().is_ipv6() {
                "::".to_owned()
            } else {
                "0.0.0.0".to_owned()
            },
            port: 9,
        })
    }

    /// The candidate's socket address.
    pub fn addr(&self) -> SocketAddr {
        self.resolved_addr
    }

    /// Returns the candidate's base address: the local transport address the
    /// candidate was derived from, i.e. the address packets for this candidate
    /// must be sent from (RFC 8445 §5.1.1).
    ///
    /// For server-reflexive and peer-reflexive candidates this is the related
    /// (host) address; for host and relay candidates the base is the candidate
    /// address itself.
    pub fn base_addr(&self) -> SocketAddr {
        match self.candidate_type {
            CandidateType::ServerReflexive | CandidateType::PeerReflexive => self
                .related_address
                .as_ref()
                .and_then(|ra| {
                    ra.address
                        .parse::<IpAddr>()
                        .ok()
                        .map(|ip| SocketAddr::new(ip, ra.port))
                })
                .unwrap_or(self.resolved_addr),
            _ => self.resolved_addr,
        }
    }

    /// Records traffic on this candidate, updating its last-sent or last-received time.
    ///
    /// Feeds consent freshness — a pair that stops seeing traffic is eventually abandoned.
    pub fn seen(&mut self, now: Instant, outbound: bool) {
        if outbound {
            self.set_last_sent(now);
        } else {
            self.set_last_received(now);
        }
    }

    /// Used to compare two candidateBases.
    pub fn equal(&self, other: &Candidate) -> bool {
        self.network_type() == other.network_type()
            && self.candidate_type() == other.candidate_type()
            && self.address() == other.address()
            && self.port() == other.port()
            && self.tcp_type() == other.tcp_type()
            && self.related_address() == other.related_address()
    }

    /// Returns true if this candidate can be paired with `other` according to
    /// ICE candidate pairing rules.
    ///
    /// Candidates must share the same network type (protocol and address family)
    /// and have compatible TCP types (RFC 6544). UDP candidates use
    /// `TcpType::Unspecified`.
    pub(crate) fn can_pair_with(&self, other: &Candidate) -> bool {
        if self.network_type() != other.network_type() {
            return false;
        }

        match (self.tcp_type(), other.tcp_type()) {
            (TcpType::Active, TcpType::Passive) => true,
            (TcpType::Passive, TcpType::Active) => true,
            (TcpType::SimultaneousOpen, TcpType::SimultaneousOpen) => true,
            (TcpType::Unspecified, TcpType::Unspecified) => true, // UDP candidates
            _ => false,
        }
    }

    /// Sets the resolved IP, deriving the network type from it.
    ///
    /// # Errors
    ///
    /// Fails if `ip`'s family does not match this candidate's network type.
    pub fn set_ip(&mut self, ip: &IpAddr) -> Result<()> {
        self.network_type = determine_network_type(&self.network, ip)?;
        self.resolved_addr = SocketAddr::new(*ip, self.port); //TODO:  create_addr(network_type, *ip, self.port);
        Ok(())
    }
}

impl Candidate {
    /// When an authenticated Binding request or response last arrived from this candidate.
    pub fn last_authenticated(&self) -> Option<Instant> {
        self.last_authenticated
    }

    /// When a success response to one of our Binding requests last arrived from this candidate:
    /// the last time the peer granted consent (RFC 7675).
    pub fn last_consent(&self) -> Option<Instant> {
        self.last_consent
    }

    /// Records that traffic was received on this candidate at `now`.
    pub fn set_last_received(&mut self, now: Instant) {
        self.last_received = Some(now);
    }

    /// Records that traffic was sent on this candidate at `now`.
    pub fn set_last_sent(&mut self, now: Instant) {
        self.last_sent = Some(now);
    }

    /// Ranks this candidate among the local candidates of its type: 0 is the most preferred
    /// (local preference 65535 for UDP, other-pref 8191 for TCP), each further rank one less.
    ///
    /// RFC 8445 Section 5.1.2.1 wants a unique local preference for each candidate of a type,
    /// and RFC 8421 wants candidates from an unreliable interface last. A candidate the
    /// application does not rank (and gives no priority) is ranked by
    /// [`Agent::add_local_candidate`](crate::Agent::add_local_candidate), in the order it is
    /// added, IPv4 and IPv6 interleaved.
    pub fn set_local_preference_rank(&mut self, rank: u16) {
        self.local_preference_rank = Some(rank);
    }

    /// The rank set by [`Candidate::set_local_preference_rank`] or by the agent.
    pub fn local_preference_rank(&self) -> Option<u16> {
        self.local_preference_rank
    }

    /// Returns the local preference for this candidate.
    pub fn local_preference(&self) -> u16 {
        let rank = self.local_preference_rank.unwrap_or(0);
        if self.network_type().is_tcp() {
            // RFC 6544, section 4.2
            //
            // In Section 4.1.2.1 of [RFC5245], a recommended formula for UDP ICE
            // candidate prioritization is defined.  For TCP candidates, the same
            // formula and candidate type preferences SHOULD be used, and the
            // RECOMMENDED type preferences for the new candidate types defined in
            // this document (see Section 5) are 105 for NAT-assisted candidates and
            // 75 for UDP-tunneled candidates.
            //
            // (...)
            //
            // With TCP candidates, the local preference part of the recommended
            // priority formula is updated to also include the directionality
            // (active, passive, or simultaneous-open) of the TCP connection.  The
            // RECOMMENDED local preference is then defined as:
            //
            //     local preference = (2^13) * direction-pref + other-pref
            //
            // The direction-pref MUST be between 0 and 7 (both inclusive), with 7
            // being the most preferred.  The other-pref MUST be between 0 and 8191
            // (both inclusive), with 8191 being the most preferred.  It is
            // RECOMMENDED that the host, UDP-tunneled, and relayed TCP candidates
            // have the direction-pref assigned as follows: 6 for active, 4 for
            // passive, and 2 for S-O.  For the NAT-assisted and server reflexive
            // candidates, the RECOMMENDED values are: 6 for S-O, 4 for active, and
            // 2 for passive.
            //
            // (...)
            //
            // If any two candidates have the same type-preference and direction-
            // pref, they MUST have a unique other-pref.  With this specification,
            // this usually only happens with multi-homed hosts, in which case
            // other-pref is the preference for the particular IP address from which
            // the candidate was obtained.  When there is only a single IP address,
            // this value SHOULD be set to the maximum allowed value (8191).
            let other_pref: u16 = 8191u16.saturating_sub(rank);

            let direction_pref: u16 = match self.candidate_type() {
                CandidateType::Host | CandidateType::Relay => match self.tcp_type() {
                    TcpType::Active => 6,
                    TcpType::Passive => 4,
                    TcpType::SimultaneousOpen => 2,
                    TcpType::Unspecified => 0,
                },
                CandidateType::PeerReflexive | CandidateType::ServerReflexive => {
                    match self.tcp_type() {
                        TcpType::SimultaneousOpen => 6,
                        TcpType::Active => 4,
                        TcpType::Passive => 2,
                        TcpType::Unspecified => 0,
                    }
                }
                CandidateType::Unspecified => 0,
            };

            (1 << 13) * direction_pref + other_pref
        } else {
            DEFAULT_LOCAL_PREFERENCE.saturating_sub(rank)
        }
    }
}

/// Whether two local candidates compete for local preferences: same type, component,
/// transport and TCP direction (RFC 8445 Section 5.1.2.1, RFC 6544 Section 4.2), neither with a
/// whole priority of its own.
pub(crate) fn same_rank_group(a: &Candidate, b: &Candidate) -> bool {
    a.candidate_type() == b.candidate_type()
        && a.component() == b.component()
        && a.network_type().is_tcp() == b.network_type().is_tcp()
        && a.tcp_type() == b.tcp_type()
        && a.priority_override == 0
        && b.priority_override == 0
}

/// Ranks a set of local candidates gathered together, as RFC 8421 Section 4 recommends for a
/// dual-stack host: within each type, the IPv6 candidates get a head start of
/// `Hi = (N_4 + N_6) / N_4` places ("If a host has two IPv4 addresses and six IPv6 addresses,
/// it will insert an IPv4 address after four IPv6 addresses"), then the two families
/// alternate, so that both get checks early. Candidates that have a rank or a priority keep
/// it, and their ranks are not given out again (RFC 8445 Section 5.1.2.1: unique local
/// preferences); a set of one family is ranked in its order, the first keeping 65535 (Section
/// 5.1.2.1: "When there is only a single IP address, this value SHOULD be set to 65535").
///
/// For candidates added one at a time the agent can only rank in the order they come (a
/// priority once signalled does not change); an application that has its host candidates
/// together ranks them here before it signals them, or adds them with
/// [`Agent::add_local_candidates`](crate::Agent::add_local_candidates), which does this
/// against the candidates the agent holds.
pub fn rank_local_candidates(candidates: &mut [Candidate]) {
    assign_dual_stack_ranks(&[], candidates);
}

/// [`rank_local_candidates`] for `batch`, with the ranks of `held` (candidates already
/// ranked) taken.
pub(crate) fn assign_dual_stack_ranks(held: &[Candidate], batch: &mut [Candidate]) {
    let unranked = |c: &Candidate| c.priority_override == 0 && c.local_preference_rank.is_none();
    let mut done = vec![false; batch.len()];
    for first in 0..batch.len() {
        if done[first] || !unranked(&batch[first]) {
            continue;
        }
        // The group of `first`: its unranked members in the batch, by family, in order.
        let members: Vec<usize> = (first..batch.len())
            .filter(|&i| {
                !done[i] && unranked(&batch[i]) && same_rank_group(&batch[first], &batch[i])
            })
            .collect();
        for &i in &members {
            done[i] = true;
        }
        let (v6, v4): (Vec<usize>, Vec<usize>) = members
            .iter()
            .partition(|&&i| batch[i].network_type().is_ipv6());
        let head_start = if v4.is_empty() {
            v6.len()
        } else {
            (v4.len() + v6.len()) / v4.len()
        };
        let mut order: Vec<usize> = v6.iter().take(head_start).copied().collect();
        let (mut rest6, mut rest4) = (v6.iter().skip(head_start), v4.iter());
        loop {
            let (a, b) = (rest4.next(), rest6.next());
            if a.is_none() && b.is_none() {
                break;
            }
            order.extend(a.into_iter().chain(b).copied());
        }
        let mut taken: Vec<u16> = held
            .iter()
            .chain(batch.iter())
            .filter(|c| same_rank_group(&batch[first], c))
            .filter_map(|c| c.local_preference_rank)
            .collect();
        let mut rank = 0u16;
        for i in order {
            while taken.contains(&rank) {
                rank = rank.saturating_add(1);
            }
            batch[i].local_preference_rank = Some(rank);
            taken.push(rank);
        }
    }
}

/// Creates a Candidate from its string representation.
pub fn unmarshal_candidate(raw: &str) -> Result<Candidate> {
    let split: Vec<&str> = raw.split_whitespace().collect();
    if split.len() < 8 {
        return Err(Error::Other(format!(
            "{:?} ({})",
            Error::ErrAttributeTooShortIceCandidate,
            split.len()
        )));
    }

    // Foundation
    let foundation = split[0].to_owned();

    // Component: RFC 8445 §5.1.1.1 numbers components from 1 to 256, and priority() relies on
    // the bound (its last term is `256 - component`).
    let component: u16 = split[1].parse()?;
    if !(1..=256).contains(&component) {
        return Err(Error::Other(format!(
            "{:?}: component {component} is outside 1..=256",
            Error::ErrParseComponent
        )));
    }

    // Network
    let network = split[2].to_owned();

    // Priority
    let priority: u32 = split[3].parse()?;

    // Address
    let address = split[4].to_owned();

    // Port
    let port: u16 = split[5].parse()?;

    let typ = split[7];

    let mut rel_addr = String::new();
    let mut rel_port = 0;
    let mut tcp_type = TcpType::Unspecified;

    if split.len() > 8 {
        let mut split2 = &split[8..];

        if split2[0] == "raddr" {
            if split2.len() < 4 {
                return Err(Error::Other(format!(
                    "{:?}: incorrect length",
                    Error::ErrParseRelatedAddr
                )));
            }

            // RelatedAddress
            split2[1].clone_into(&mut rel_addr);

            // RelatedPort
            rel_port = split2[3].parse()?;
            split2 = &split2[4..];
        }

        // The extension attributes are name / value pairs in any order (RFC 8839 Section
        // 5.1); `tcptype` (RFC 6544 Section 4.5) is one of them, for every candidate type.
        for extension in split2.chunks(2) {
            if extension[0] == "tcptype" {
                if extension.len() < 2 {
                    return Err(Error::Other(format!(
                        "{:?}: incorrect length",
                        Error::ErrParseType
                    )));
                }
                tcp_type = TcpType::from(extension[1]);
            }
        }
    }

    match typ {
        "host" => {
            let config = CandidateHostConfig {
                base_config: CandidateConfig {
                    network,
                    address,
                    port,
                    component,
                    priority,
                    foundation,
                    ..CandidateConfig::default()
                },
                tcp_type,
            };
            config.new_candidate_host()
        }
        "srflx" => {
            let config = CandidateServerReflexiveConfig {
                base_config: CandidateConfig {
                    network,
                    address,
                    port,
                    component,
                    priority,
                    foundation,
                    ..CandidateConfig::default()
                },
                rel_addr,
                rel_port,
                url: None,
            };
            config.new_candidate_server_reflexive().map(|mut c| {
                c.tcp_type = tcp_type;
                c
            })
        }
        "prflx" => {
            let config = CandidatePeerReflexiveConfig {
                base_config: CandidateConfig {
                    network,
                    address,
                    port,
                    component,
                    priority,
                    foundation,
                    ..CandidateConfig::default()
                },
                rel_addr,
                rel_port,
            };

            config.new_candidate_peer_reflexive().map(|mut c| {
                c.tcp_type = tcp_type;
                c
            })
        }
        "relay" => {
            let config = CandidateRelayConfig {
                base_config: CandidateConfig {
                    network,
                    address,
                    port,
                    component,
                    priority,
                    foundation,
                    ..CandidateConfig::default()
                },
                rel_addr,
                rel_port,
                url: None,
            };
            config.new_candidate_relay().map(|mut c| {
                c.tcp_type = tcp_type;
                c
            })
        }
        _ => Err(Error::Other(format!(
            "{:?} ({})",
            Error::ErrUnknownCandidateType,
            typ
        ))),
    }
}
