use std::net::IpAddr;
use std::time::Duration;

use super::*;
use crate::agent::remote_policy::RemoteAddressFilter;
use crate::external_ip_mapper::ExternalIpMapper;
use crate::mdns::*;
use crate::network_type::NetworkType;
use crate::url::*;

/// How often the agent looks at its state while connecting, when nothing else wakes it sooner
/// (a check to send, a retransmission, a transaction that times out).
pub(crate) const DEFAULT_CHECK_INTERVAL: Duration = Duration::from_millis(200);

/// Ta, the pacing timer of connectivity checks (RFC 8445 Section 14.2: "ICE agents SHOULD use a
/// default Ta value, 50 ms").
pub(crate) const DEFAULT_TA: Duration = Duration::from_millis(50);

/// RFC 8445 Section 14.2: "regardless of the Ta value chosen for each agent, the combination of
/// all transactions from all agents (if a given implementation runs several concurrent agents)
/// will not be sent more often than once every 5 ms".
pub(crate) const MIN_TA: Duration = Duration::from_millis(5);

/// RFC 8445 Section 14.3: "RTO = MAX (500ms, Ta * N * (Num-Waiting + Num-In-Progress))", and
/// the RTO is never under 500 ms.
pub(crate) const MIN_RTO: Duration = Duration::from_millis(500);

/// Rm of RFC 8489 Section 6.2.1: after the last request of a transaction the agent waits
/// Rm times the RTO for a response.
pub(crate) const STUN_RM: u32 = 16;

/// Ti of RFC 8489 Section 6.2.2: how long a transaction over a reliable transport (TCP) waits
/// for its response; such a request is never retransmitted (RFC 6544 Section 7.1).
pub(crate) const STUN_TI: Duration = Duration::from_millis(39_500);

/// RFC 8445 Section 6.1.2.5: "The limit MUST default to 100" candidate pairs.
pub(crate) const DEFAULT_MAX_CANDIDATE_PAIRS: usize = 100;

/// Most local peer-reflexive candidates learned from the mapped addresses of responses.
pub(crate) const MAX_LOCAL_PEER_REFLEXIVE_CANDIDATES: usize = 16;

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

/// Rc of RFC 8489 Section 6.2.1: the requests of one STUN transaction (the first and its
/// retransmissions) before the pair is considered failed. "Rc SHOULD be configurable and SHOULD
/// have a default of 7."
pub(crate) const DEFAULT_MAX_BINDING_REQUESTS: u16 = 7;

/// The number of bytes that can be buffered before we start to error.
pub(crate) const MAX_BUFFER_SIZE: usize = 1000 * 1000; // 1MB

/// The most open transactions the agent tracks beyond one per candidate pair: consent requests
/// and cancelled transactions still waiting out their timeout. Past it the oldest of those is
/// forgotten (its response, if it ever arrives, is then ignored). Consent requests alone stay
/// far under it: they are at least 4 seconds apart and none is kept past the consent expiry
/// (30 seconds) with [`ConsentResponseWait::Rto`], or past the fixed wait otherwise.
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

/// Which nomination a controlled agent uses when the controlling agent makes more than one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum NominationAcceptance {
    /// RFC 8445 Section 8.1.1: "If more than one candidate pair is nominated by the
    /// controlling agent, and if the controlled agent accepts multiple nominations requests,
    /// the agents MUST produce the selected pairs and use the pairs with the highest
    /// priority." Every nomination is accepted; the selected pair is the nominated valid pair
    /// with the highest priority. A nominated pair of lower priority takes over only when
    /// consent is lost on the selected one (RFC 7675: that pair may no longer be sent on).
    #[default]
    HighestPriority,
    /// libwebrtc's behaviour: the latest nomination wins, and with the `NOMINATION` attribute
    /// (libwebrtc's renomination) the highest value does. libwebrtc moves a session to another
    /// pair after it connected by nominating that pair, whatever its priority.
    Latest,
}

/// A pacing budget several agents share (RFC 8445 Section 14.2: "all agents together send
/// no more than one transaction per 5 ms" — the "global" Ta of an implementation that runs
/// several agents). Give the same `Arc` to every agent (through
/// [`AgentConfig::pacing_group`] or the peer connection's
/// `SettingEngineBuilder::with_ice_pacing_group`): each starts a connectivity check only when
/// none of them has started one in the last 5 ms, on top of its own Ta. An agent without a
/// group paces alone, by its Ta.
#[derive(Debug, Default)]
pub struct PacingGroup {
    next: std::sync::Mutex<Option<std::time::Instant>>,
}

impl PacingGroup {
    /// A new budget, shared by every agent given it.
    pub fn new() -> std::sync::Arc<Self> {
        std::sync::Arc::new(Self::default())
    }

    /// Takes the budget at `now` if it is free: `Ok(())`, or `Err(at)` with when it next is.
    pub(crate) fn take(
        &self,
        now: std::time::Instant,
    ) -> std::result::Result<(), std::time::Instant> {
        let mut next = self
            .next
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        match *next {
            Some(at) if at > now => Err(at),
            _ => {
                *next = Some(now + MIN_TA);
                Ok(())
            }
        }
    }
}

/// How long a consent request (RFC 7675) waits for its response: how long its transaction is
/// in progress, so that a matching, authenticated success response still renews consent (RFC
/// 8489 Section 6.3: a response is processed when "the transaction ID matches a transaction
/// that is still in progress"). A consent request is sent once; a response to an earlier one
/// than the latest counts as well (RFC 7675 Section 5.1: "a response might be for a previous
/// request (rather than for the most recently sent request)").
///
/// Whatever the wait, consent expires 30 seconds after the last response that renewed it, and
/// every open consent transaction is discarded then.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum ConsentResponseWait {
    /// RFC 7675 Section 5.1 (the default): "An endpoint SHOULD await a binding response for
    /// each request it sends for a time based on the estimated round-trip time (RTT) (see
    /// Section 7.2.1 of [RFC5389]) with an allowance for variation in network delay." The
    /// wait is what RFC 8489 Section 6.2.1 gives a transaction after its last request, `Rm`
    /// (16) times the RTO, the RTO being the pair's (RFC 6298: the smoothed round-trip time
    /// plus four times its variation, 500 ms at least, from every request that was answered
    /// without having been retransmitted): 8 seconds at least, and never longer than the
    /// consent expiry.
    #[default]
    Rto,
    /// A fixed time, whatever the round-trip time is. libwebrtc's is 60 seconds.
    Fixed(Duration),
}

/// What an agent does when a nomination fails (RFC 8445 Section 7.2.5.2): the controlling
/// agent's check with USE-CANDIDATE on a valid pair, or the controlled agent's check that a
/// received USE-CANDIDATE triggered (Section 7.3.1.5). The check fails when its transaction times out (`Rc` requests, the
/// last given `Rm` times the RTO, Section 14.3 and RFC 8489 Section 6.2.1: 39.5 seconds at an
/// RTO of 500 ms), it is answered with an unrecoverable error response, or the response is
/// not symmetric.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum FailedNomination {
    /// RFC 8445 Section 7.2.5.3.4 (the default), for both roles: "If the request fails
    /// (Section 7.2.5.2), the agent MUST remove the candidate pair from the valid list, set
    /// the candidate pair state to Failed, and set the checklist state to Failed", and for
    /// the controlled agent "If the triggered request fails, [...] set the checklist state to
    /// Failed". The agent fails; the peer may stay connected until its consent expires (RFC
    /// 7675).
    #[default]
    FailChecklist,
    /// The pair stays valid (it has received a success response, RFC 8445 Section
    /// 7.2.5.3.3) and a nomination that times out is sent again, for as long as the peer is
    /// heard from on it (an authenticated request or response less than the consent expiry,
    /// 30 seconds, ago). Once the peer has not been heard from for that long, or the
    /// nomination is answered with an error or from the wrong address, the pair fails and
    /// the next valid pair is nominated; with none left the checklist fails. Under heavy
    /// loss every request of a transaction, or every response, can be lost while the peer is
    /// there and has accepted the nomination: this keeps both sides connected then. A
    /// controlled agent whose triggered check fails fails that pair only: the checklist keeps
    /// running, and the controlling agent may nominate another pair.
    Retry,
}

/// What the agent does with a Binding request that fails the short-term credential check.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum UnauthenticatedRequests {
    /// RFC 8489 Section 9.1.3 (which RFC 8445 Section 7.3 makes the ICE procedure): a request
    /// without MESSAGE-INTEGRITY or USERNAME is answered 400 (Bad Request), one with an
    /// unknown username or a wrong MESSAGE-INTEGRITY 401 (Unauthenticated). The error
    /// responses are rate limited (a token bucket of
    /// [`MAX_UNAUTHENTICATED_RESPONSE_BURST`] responses, one more every
    /// [`UNAUTHENTICATED_RESPONSE_INTERVAL`]), each is smaller than the request it answers,
    /// and past the limit the request is dropped: the agent cannot be made to reflect traffic
    /// at a spoofed source.
    #[default]
    Reject,
    /// Such a request is dropped without an answer (what this crate did before, and what
    /// libwebrtc does for a request whose username is not for it).
    Drop,
}

/// The error responses to unauthenticated requests the agent may send in a burst.
pub const MAX_UNAUTHENTICATED_RESPONSE_BURST: u32 = 5;

/// How often the agent may send one more error response to an unauthenticated request.
pub const UNAUTHENTICATED_RESPONSE_INTERVAL: Duration = Duration::from_millis(200);

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

    /// Controls how often our internal task loop runs when in the connecting state and nothing
    /// is due sooner. Only useful for testing.
    pub check_interval: Duration,

    /// Ta, the pacing of connectivity checks: one check is started per Ta (RFC 8445 Section
    /// 6.1.4.2). 50 ms when nil; never under 5 ms (Section 14.2).
    pub ta: Option<Duration>,

    /// The most candidate pairs the checklist holds (RFC 8445 Section 6.1.2.5). 100 when nil.
    /// When it is full a new pair replaces a Failed one, else a lower-priority one that has
    /// not been checked yet, else it is dropped.
    pub max_candidate_pairs: Option<usize>,

    /// The requests of one connectivity-check transaction, the first and its retransmissions
    /// (Rc of RFC 8489 Section 6.2.1; 7 when nil). They go out RTO, 2 RTO, 4 RTO, ... apart
    /// (RTO is at least 500 ms), and the pair fails 16 RTO after the last one. Over TCP a
    /// request is sent once.
    pub max_binding_requests: Option<u16>,

    /// Whether this agent takes the controlling role.
    pub is_controlling: bool,

    /// lite agents do not perform connectivity check and only provide host candidates.
    pub lite: bool,

    /// webrtc-extensions 7 `icecandidatepairnominate`, cancelable: when true, a controlling
    /// agent that has picked a pair to nominate proposes it first
    /// ([`Event::CandidatePairNominationProposed`](crate::agent::Event)) and waits for
    /// [`Agent::resolve_nomination_proposal`](crate::agent::Agent::resolve_nomination_proposal);
    /// a declined pair is not nominated, and the agent keeps checking. False (the default):
    /// the agent nominates at once, as for an event nobody cancels.
    pub candidate_pair_proposals: bool,

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
    /// this host send checks to its own services. See the [`remote_policy`] module.
    pub allow_loopback_remote_candidates: bool,

    /// Lets connectivity checks go to a link-local remote address (`169.254.0.0/16`,
    /// `fe80::/10`) from a local candidate that is not itself link-local. Off by default.
    pub allow_link_local_remote_candidates: bool,

    /// Asked about every remote candidate's address (an mDNS candidate's once resolved) before
    /// the agent holds it; `false` drops the candidate. Addresses that are never a valid unicast
    /// destination (unspecified, multicast, broadcast, port 0) are dropped before it is asked.
    pub remote_address_filter: Option<RemoteAddressFilter>,

    /// The tiebreaker of RFC 8445 Section 5.2 ("a random number between 0 and 2**64 - 1",
    /// drawn when nil). A fixed one makes the outcome of a role conflict reproducible; the
    /// agent still draws a new one when a 487 (Role Conflict) tells it to (Section 7.2.5.1).
    pub tie_breaker: Option<u64>,

    /// Whether an ICE restart draws a new tiebreaker (RFC 8445 Section 16.1: "The agent MAY
    /// change the number when an ICE restart occurs"). Off by default: the tiebreaker stays
    /// for the agent's life, as libwebrtc keeps it; a fixed [`AgentConfig::tie_breaker`] is
    /// replaced at the first restart when this is on.
    pub new_tie_breaker_on_restart: bool,

    /// Which of several nominations a controlled agent uses. The default is RFC 8445's rule
    /// (the nominated pair with the highest priority); [`NominationAcceptance::Latest`] is
    /// libwebrtc's.
    pub nomination_acceptance: NominationAcceptance,

    /// What the controlling agent does when its nomination fails:
    /// [`FailedNomination::FailChecklist`] (the default) is RFC 8445 Section 7.2.5.3.4, the
    /// pair and the checklist fail; [`FailedNomination::Retry`] nominates the pair again
    /// while the peer is heard from.
    pub failed_nomination: FailedNomination,

    /// A pacing budget shared with other agents (RFC 8445 Section 14.2), if the application
    /// runs several: see [`PacingGroup`]. `None`, the default, paces this agent alone.
    pub pacing_group: Option<std::sync::Arc<PacingGroup>>,

    /// The controlling agent's consent checks on the selected pair carry USE-CANDIDATE, as
    /// libwebrtc's do. Off by default: RFC 8445 Section 7.1.2 asks for the attribute "in order
    /// to nominate a candidate pair", which is done once (Section 8.1.1), and RFC 7675 asks
    /// for nothing more than a Binding request. The agent repeats its nomination by itself
    /// where the peer has shown that it lost it (a role conflict the agent wins after it
    /// nominated).
    pub nominate_on_consent_checks: bool,

    /// How long a consent request waits for its response: see [`ConsentResponseWait`].
    pub consent_response_wait: ConsentResponseWait,

    /// What a Binding request that fails authentication gets: an error response (RFC 8489
    /// Section 9.1.3, rate limited; the default) or nothing.
    pub unauthenticated_requests: UnauthenticatedRequests,

    /// Accept data (DTLS, SRTP) only from the selected pair's remote address. Off by default:
    /// RFC 8445 Section 12.2 says an agent "SHOULD by default be prepared to receive data on
    /// any of the candidates provided in the most recent candidate exchange", and the agent
    /// accepts it from the remote candidate of any valid pair (a pair one of its own checks
    /// succeeded on). See [`Agent::accepts_data`].
    pub data_from_selected_pair_only: bool,

    /// Whether the first mDNS query for a remote `.local` candidate waits a random 20 to 120
    /// ms (RFC 6762 Section 5.2: every participant of a call is told of the name at the same
    /// moment). `None` is on, as the RFC recommends; `Some(false)` sends it from the
    /// `handle_timeout` that follows the candidate.
    pub multicast_dns_first_query_delay: Option<bool>,

    /// Whether the agent's mDNS answers to a query of more than one question (an A and an
    /// AAAA question for its name, as browsers ask) wait a random 20 to 120 ms (RFC 6762
    /// Section 6.3). `None` is on, as the RFC recommends; `Some(false)` answers a query about
    /// its own names only at once.
    pub multicast_dns_multi_question_delay: Option<bool>,

    /// The driver hands every mDNS datagram to `handle_read` with the datagram's destination
    /// in `local_addr` (from `IP_PKTINFO` / `IPV6_PKTINFO`): `224.0.0.251:5353` or
    /// `[ff02::fb]:5353` for one that arrived on the group, the host's own address for one
    /// sent to it by unicast. The mDNS connection then holds a unicast arrival to the rules
    /// RFC 6762 has for it (Sections 5.5 and 6). Off by default: a socket's bound address
    /// says nothing about how a datagram reached it.
    pub multicast_dns_destination_reported: bool,

    /// The first query for a name asks for a unicast response (the QU bit, RFC 6762 Section
    /// 5.4, which draft-ietf-mmusic-mdns-ice-candidates Section 3.2.1 suggests). Off by
    /// default: a unicast response reaches one socket on port 5353 only (RFC 6762 Section
    /// 15.1), so beside a system responder the answer can be lost. Turn it on, with
    /// `multicast_dns_destination_reported`, when the application's socket is the only one.
    pub multicast_dns_unicast_response: bool,

    /// The limit on the mDNS messages sent, to share between every agent of a process
    /// (draft-ietf-mmusic-mdns-ice-candidates Section 7.1: the limit is the implementation's,
    /// not one agent's): give each agent a clone of one [`mdns::MdnsRateLimit`]. `None`: a
    /// limit of this agent's own (40 messages at once, 10 a second). The crate keeps no
    /// process-wide state of its own, so it cannot share one unasked.
    pub multicast_dns_rate_limit: Option<mdns::MdnsRateLimit>,

    /// `QueryAndGather`: what a host candidate becomes when the name of its address cannot be
    /// registered (no mDNS for its address family, [`MulticastDnsPublishing`]; or the
    /// responder holds the most names it can, 64). Off, the default: the candidate is provided
    /// under a `<uuid>.local` name that is not published, so neither its address nor the
    /// failure shows (draft-ietf-mmusic-mdns-ice-candidates Section 3.1.1: "the ICE agent
    /// SHOULD still provide mDNS candidates in step 6 even if the local network does not
    /// support mDNS or mDNS registration fails in step 4"). On: the agent provides no host
    /// candidate for that address at all (UDP and TCP), as an embedder that must never offer
    /// a candidate the peer cannot resolve may want; its server-reflexive and relayed
    /// candidates are still gathered from it. A page that sees host candidates appear or
    /// not learns whether mDNS works on the host, which is what the draft's form avoids.
    pub multicast_dns_fail_closed: bool,

    /// `QueryAndGather`: leave unwrapped a host address that the gathering before the current
    /// ICE generation showed to be public (draft-ietf-mmusic-mdns-ice-candidates Section
    /// 3.1.2.2: "once an address has been identified as public, the ICE agent MAY cache this
    /// information and skip mDNS protection for that address in future ICE gathering
    /// phases"). Off by default, in every behaviour profile; no effect in the other modes.
    ///
    /// An address is shown public when the application adds a server-reflexive candidate
    /// whose address is its base's ("If the STUN response returns the same value as the local
    /// IP address, this indicates the address is in fact public") and that base is the
    /// address of a host candidate this agent holds: a STUN server cannot make the agent
    /// unwrap an address it does not have. It is never one [`crate::mdns::is_global_unicast`]
    /// refuses. The gathering that shows it is not changed: its mDNS candidate has been
    /// provided already, and the server-reflexive candidate on the same address follows it
    /// as Section 3.1.2.2 describes (raddr `0.0.0.0` / `::`, rport 9). From the next ICE
    /// restart on, host candidates on that address go out with the address itself, while
    /// each restart's own gathering shows it again; the knowledge is the agent's alone (no
    /// process-wide cache) and is dropped by [`crate::Agent::set_ice_servers`] when the set
    /// of STUN / TURN servers changes.
    ///
    /// What it exposes, and to whom: the address is already the server-reflexive candidate's,
    /// which the remote peer and the application (a web page, in a browser) received in the
    /// earlier generation; what the later host candidates add is that the address is the
    /// host's own interface (type `host`, no NAT), the same thing an equal port already
    /// suggested.
    pub multicast_dns_expose_known_public_addresses: bool,

    /// `QueryAndGather`: leave unwrapped a host address the application marked as an RFC 4941
    /// temporary IPv6 address ([`crate::Agent::set_temporary_ipv6_addresses`])
    /// (draft-ietf-mmusic-mdns-ice-candidates Section 3.1.2.3: "implementations MAY choose to
    /// not conceal [RFC4941] addresses with mDNS names as a tradeoff for improved
    /// peer-to-peer connectivity"). Off by default, in every behaviour profile; no effect in
    /// the other modes. The engine cannot tell a temporary address from a stable one by its
    /// bits: only an address the application marked is unwrapped, and never one
    /// [`crate::mdns::is_global_unicast`] refuses. An address not marked stays hidden.
    ///
    /// What it exposes, and to whom: the temporary address itself, to the remote peer and to
    /// the application (a web page, in a browser), for as long as the operating system keeps
    /// it (a day of preferred lifetime by default on most systems); not the host's stable
    /// address, nor the private IPv4 ones.
    pub multicast_dns_expose_temporary_ipv6_addresses: bool,

    /// Whether the application can send mDNS for each address family (both by default); see
    /// [`MulticastDnsPublishing`] and [`Agent::set_multicast_dns_publishing`](crate::Agent::set_multicast_dns_publishing).
    pub multicast_dns_publishing: MulticastDnsPublishing,

    /// Send data on the best valid pair before a pair is selected (RFC 8445 Section 12.1: "An
    /// ICE agent MAY send data on any valid pair before selected pairs have been produced").
    /// Off by default: data is sent once a pair is selected.
    pub send_data_before_nomination: bool,

    /// [`Agent::add_local_candidate`](crate::agent::Agent::add_local_candidate) holds the
    /// candidate as [`Agent::add_unconveyed_local_candidate`](crate::agent::Agent::add_unconveyed_local_candidate)
    /// does: unpaired until the caller says it has been conveyed to the peer (RFC 8838
    /// Section 10). Off by default: a caller of `add_local_candidate` conveys the candidate
    /// with that call. A driver that hands candidates to an application to trickle (the peer
    /// connection does) turns it on.
    pub hold_local_candidates_until_conveyed: bool,

    /// The path MTU in bytes, when the application knows it. RFC 8489 Section 6.1: a STUN
    /// message over UDP fits it; `None` assumes 576 bytes for IPv4 and 1280 for IPv6, the
    /// RFC's figures when it is not known. A check that would not fit is not sent and its pair
    /// fails; no other STUN message larger than that is sent over UDP.
    pub path_mtu: Option<usize>,

    /// The SOFTWARE attribute of the agent's connectivity checks and of its success responses
    /// to the peer's (RFC 8489 Sections 6.1, 6.3.1.1: requests and responses "SHOULD" carry
    /// one; Section 16.1.2: its use "SHOULD" be configurable). `None`: `rtci-ice` and its
    /// version. `Some("")`: none, for an application that would not tell its software to the
    /// path (Section 16.1.2).
    pub software: Option<String>,
}
