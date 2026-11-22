use std::net::IpAddr;
use std::time::Duration;

use super::*;
use crate::agent::remote_policy::RemoteAddressFilter;
use crate::external_ip_mapper::ExternalIpMapper;
use crate::mdns::*;
use crate::network_type::NetworkType;
use crate::url::*;

/// The interval at which the agent performs candidate checks in the connecting phase.
pub(crate) const DEFAULT_CHECK_INTERVAL: Duration = Duration::from_millis(200);

/// The basic period of the consent checks on the selected pair (RFC 7675 Section 5.1:
/// "Implementations SHOULD set a default interval of 5 seconds, resulting in a period between
/// checks of 4 to 6 seconds"). Also the smallest period that can be configured.
pub(crate) const DEFAULT_KEEPALIVE_INTERVAL: Duration = Duration::from_secs(5);

/// RFC 7675 Section 5.1: "Implementations MUST NOT set the period between checks to less than 4
/// seconds."
pub(crate) const MIN_CONSENT_INTERVAL: Duration = Duration::from_secs(4);

/// RFC 8445 Section 11: "Tr SHOULD be configurable and SHOULD have a default of 15 seconds",
/// and never less. A full agent's consent checks are its keepalives and come sooner; this is
/// how long a lite agent stays silent on its selected pair before a Binding indication.
pub(crate) const KEEPALIVE_TR: Duration = Duration::from_secs(15);

/// RFC 7675 Section 5.1: "Consent expires after 30 seconds."
pub(crate) const CONSENT_EXPIRY: Duration = Duration::from_secs(30);

/// The default time till an Agent transitions disconnected.
pub(crate) const DEFAULT_DISCONNECTED_TIMEOUT: Duration = Duration::from_secs(5);

/// The default time till an Agent transitions to failed after disconnected.
pub(crate) const DEFAULT_FAILED_TIMEOUT: Duration = Duration::from_secs(25);

/// Wait time before nominating a host candidate.
pub(crate) const DEFAULT_HOST_ACCEPTANCE_MIN_WAIT: Duration = Duration::from_secs(0);

/// Wait time before nominating a srflx candidate.
pub(crate) const DEFAULT_SRFLX_ACCEPTANCE_MIN_WAIT: Duration = Duration::from_millis(500);

/// Wait time before nominating a prflx candidate.
pub(crate) const DEFAULT_PRFLX_ACCEPTANCE_MIN_WAIT: Duration = Duration::from_millis(1000);

/// Wait time before nominating a relay candidate.
pub(crate) const DEFAULT_RELAY_ACCEPTANCE_MIN_WAIT: Duration = Duration::from_millis(2000);

/// Max binding request before considering a pair failed.
pub(crate) const DEFAULT_MAX_BINDING_REQUESTS: u16 = 7;

/// The number of bytes that can be buffered before we start to error.
pub(crate) const MAX_BUFFER_SIZE: usize = 1000 * 1000; // 1MB

/// Wait time before binding requests can be deleted.
pub(crate) const MAX_BINDING_REQUEST_TIMEOUT: Duration = Duration::from_millis(4000);

/// The most outstanding Binding requests the agent tracks; sending one more forgets the oldest
/// (its response, if it ever arrives, is then ignored).
pub(crate) const MAX_PENDING_BINDING_REQUESTS: usize = 50;

impl AgentConfig {
    /// Builds the 1:1 NAT mapper and checks it can take effect: a `Host` mapping cannot be used
    /// with mDNS host names (the address would be hidden anyway) and needs host candidates, a
    /// `ServerReflexive` one needs server-reflexive candidates.
    pub(crate) fn init_ext_ip_mapping(
        &self,
        mdns_mode: MulticastDnsMode,
        candidate_types: &[CandidateType],
    ) -> Result<Option<ExternalIpMapper>> {
        let Some(ext_ip_mapper) =
            ExternalIpMapper::new(self.nat_1to1_ip_candidate_type, &self.nat_1to1_ips)?
        else {
            return Ok(None);
        };
        if ext_ip_mapper.candidate_type == CandidateType::Host {
            if mdns_mode == MulticastDnsMode::QueryAndGather {
                return Err(Error::ErrMulticastDnsWithNat1to1IpMapping);
            }
            if !candidate_types.contains(&CandidateType::Host) {
                return Err(Error::ErrIneffectiveNat1to1IpMappingHost);
            }
        } else if ext_ip_mapper.candidate_type == CandidateType::ServerReflexive
            && !candidate_types.contains(&CandidateType::ServerReflexive)
        {
            return Err(Error::ErrIneffectiveNat1to1IpMappingSrflx);
        }
        Ok(Some(ext_ip_mapper))
    }
}

pub(crate) fn default_candidate_types() -> Vec<CandidateType> {
    vec![
        CandidateType::Host,
        CandidateType::ServerReflexive,
        CandidateType::Relay,
    ]
}

/// Collects the arguments to `ice::Agent` construction into a single structure, for
/// future-proofness of the interface.
#[derive(Default)]
pub struct AgentConfig {
    /// The STUN and TURN servers to gather reflexive and relay candidates from.
    pub urls: Vec<Url>,

    /// It is used to perform connectivity checks. The values MUST be unguessable, with at least
    /// 128 bits of random number generator output used to generate the password, and at least 24
    /// bits of output to generate the username fragment.
    pub local_ufrag: String,
    /// It is used to perform connectivity checks. The values MUST be unguessable, with at least
    /// 128 bits of random number generator output used to generate the password, and at least 24
    /// bits of output to generate the username fragment.
    pub local_pwd: String,

    /// Controls mDNS query timeout
    /// If the duration is 0, we will never go to failed.
    pub multicast_dns_query_timeout: Option<Duration>,

    /// Controls mDNS behavior for the ICE agent.
    pub multicast_dns_mode: MulticastDnsMode,

    /// Controls the local name for this agent. If none is specified a random one will be generated.
    pub multicast_dns_local_name: String,

    /// Control mDNS local IP address
    pub multicast_dns_local_ip: Option<IpAddr>,

    /// How long a consent request on the selected pair may go unanswered before the agent is
    /// `Disconnected` (a lite agent: how long without an authenticated request from the peer).
    /// Defaults to 5 seconds when this property is nil.
    /// If the duration is 0, the ICE Agent will never go to disconnected.
    pub disconnected_timeout: Option<Duration>,

    /// With `disconnected_timeout`, how long the agent goes without the peer's consent before
    /// it is `Failed`, and how long it may stay `Checking`. Defaults to 25 seconds when this
    /// property is nil. If the duration is 0, a checking agent never goes to failed.
    ///
    /// A connected full agent fails 30 seconds after the last consent response at the latest,
    /// whatever is configured here, a zero included: RFC 7675 Section 5.1 forbids sending
    /// without consent for longer. A shorter sum fails it sooner.
    pub failed_timeout: Option<Duration>,

    /// The basic period of the consent checks on the selected pair (RFC 7675), which are also
    /// the keepalives of RFC 8445 Section 11. Each interval is drawn from 0.8 to 1.2 times
    /// this. Defaults to 5 seconds when this is nil, and a shorter period is raised to 5
    /// seconds: RFC 7675 forbids less than 4 seconds between two checks.
    /// A keepalive interval of 0 means we never send keepalive packets (and consent then
    /// expires 30 seconds after the pair was validated).
    pub keepalive_interval: Option<Duration>,

    /// An optional configuration for disabling or enabling support for specific candidate types.
    pub candidate_types: Vec<CandidateType>,

    /// An optional configuration for disabling or enabling support for specific network types.
    /// If empty, all network types are supported.
    pub network_types: Vec<NetworkType>,

    /// Controls how often our internal task loop runs when in the connecting state.
    /// Only useful for testing.
    pub check_interval: Duration,

    /// The max amount of binding requests the agent will send over a candidate pair for validation
    /// or nomination, if after max_binding_requests the candidate is yet to answer a binding
    /// request or a nomination we set the pair as failed.
    pub max_binding_requests: Option<u16>,

    /// Whether this agent takes the controlling role.
    pub is_controlling: bool,

    /// lite agents do not perform connectivity check and only provide host candidates.
    pub lite: bool,

    /// Specify a minimum wait time before selecting host candidates.
    pub host_acceptance_min_wait: Option<Duration>,
    /// Specify a minimum wait time before selecting srflx candidates.
    pub srflx_acceptance_min_wait: Option<Duration>,
    /// Specify a minimum wait time before selecting prflx candidates.
    pub prflx_acceptance_min_wait: Option<Duration>,
    /// Specify a minimum wait time before selecting relay candidates.
    pub relay_acceptance_min_wait: Option<Duration>,

    /// Controls if self-signed certificates are accepted when connecting to TURN servers via TLS or
    /// DTLS.
    pub insecure_skip_verify: bool,

    /// External addresses a 1:1 NAT gives this host (a cloud instance's public IP), each
    /// `"<external ip>"` or `"<external ip>/<local ip>"`. The host candidates the application
    /// adds are advertised with them, as `nat_1to1_ip_candidate_type` says. Empty: no mapping.
    pub nat_1to1_ips: Vec<String>,

    /// How `nat_1to1_ips` are advertised: [`CandidateType::Host`] (the default, also for
    /// `Unspecified`) replaces a mapped host candidate's address with the external one;
    /// [`CandidateType::ServerReflexive`] adds a server-reflexive candidate on the external
    /// address beside it. Any other type is refused by [`Agent::new`](crate::Agent::new).
    pub nat_1to1_ip_candidate_type: CandidateType,

    /// Lets connectivity checks go to a loopback remote address (`127.0.0.0/8`, `::1`) from a
    /// local candidate that is not itself on loopback. Off by default: a loopback remote
    /// candidate is then paired only with a loopback local candidate, so a peer cannot make
    /// this host send checks to its own services. See the [`remote_policy`](super::remote_policy) module.
    pub allow_loopback_remote_candidates: bool,

    /// Lets connectivity checks go to a link-local remote address (`169.254.0.0/16`,
    /// `fe80::/10`) from a local candidate that is not itself link-local. Off by default.
    pub allow_link_local_remote_candidates: bool,

    /// Asked about every remote candidate's address (an mDNS candidate's once resolved) before
    /// the agent holds it; `false` drops the candidate. Addresses that are never a valid unicast
    /// destination (unspecified, multicast, broadcast, port 0) are dropped before it is asked.
    pub remote_address_filter: Option<RemoteAddressFilter>,
}
