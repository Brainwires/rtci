//! The Sans-I/O ICE agent.
//!
//! An [`Agent`] is given local and remote candidates and inbound datagrams; it produces the
//! connectivity checks to send, the state transitions to report, and eventually a selected
//! candidate pair. It owns no sockets and no clock — the caller drives time with
//! `handle_timeout`.
//!
//! Two roles exist: the controlling agent nominates the pair that will carry media, the
//! controlled agent accepts that choice. Which side controls is decided by which offered, and the
//! two must not agree — see [`Credentials`] and [`Agent::set_role`].
#[cfg(test)]
mod agent_candidate_pair_test;
#[cfg(test)]
mod agent_checklist_test;
#[cfg(test)]
mod agent_consent_test;
#[cfg(test)]
mod agent_nat_1to1_test;
#[cfg(test)]
mod agent_nomination_test;
#[cfg(test)]
mod agent_open_rows_test;
#[cfg(test)]
mod agent_ported_test;
#[cfg(test)]
mod agent_rfc6544_mdns_test;
#[cfg(test)]
mod agent_rfc7675_test;
#[cfg(test)]
mod agent_rfc8445_test;
#[cfg(test)]
mod agent_stun_rows_test;
#[cfg(test)]
mod agent_test;
#[cfg(test)]
mod agent_trickle_test;

/// Configuration for a new [`Agent`]: servers, timeouts and role.
pub mod agent_config;
mod agent_proto;
/// Pair selection and nomination — which candidate pair becomes the selected one.
pub mod agent_selector;
/// Snapshot statistics for an agent's candidates and pairs.
pub mod agent_stats;
/// Where connectivity checks may be sent (RFC 8445 §5.1.1.1 address rules).
pub mod remote_policy;
#[cfg(test)]
mod remote_policy_test;
mod restart_undo;

use agent_config::*;
use bytes::BytesMut;
use crypto::{RTCCrypto, RTCCryptoProvider};
use log::{debug, error, info, trace, warn};
use mdns::{Mdns, QueryId};
use sansio::Protocol;
use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};
use stun::attributes::*;
use stun::fingerprint::*;
use stun::integrity::*;
use stun::message::*;
use stun::textattrs::*;
use stun::xoraddr::*;

use crate::candidate::candidate_peer_reflexive::CandidatePeerReflexiveConfig;
use crate::candidate::candidate_server_reflexive::CandidateServerReflexiveConfig;
use crate::candidate::{candidate_pair::*, *};
use crate::external_ip_mapper::ExternalIpMapper;
use crate::mdns::{
    MdnsOptions, MulticastDnsMode, create_multicast_dns, generate_multicast_dns_name,
    is_ice_mdns_name, is_valid_local_mdns_name,
};
use crate::network_type::NetworkType;
use crate::rand::*;
use crate::state::*;
use crate::tcp_type::TcpType;
use crate::url::*;
use remote_policy::RemotePolicy;
use shared::error::*;
use shared::{TaggedBytesMut, TransportContext, TransportProtocol};

const ZERO_DURATION: Duration = Duration::from_secs(0);

#[derive(Debug, Clone)]
pub(crate) struct BindingRequest {
    pub(crate) timestamp: Instant,
    pub(crate) transaction_id: TransactionId,
    pub(crate) destination: SocketAddr,
    pub(crate) is_use_candidate: bool,
    /// The pair the request was sent on.
    pub(crate) local_index: usize,
    pub(crate) remote_index: usize,
    /// The role attribute the request carried: ICE-CONTROLLING (true) or ICE-CONTROLLED. A 487
    /// answer switches the role away from this one (RFC 8445 Section 7.2.5.1).
    pub(crate) sent_as_controlling: bool,
    /// The request as sent: a retransmission is the same message, transaction id included.
    pub(crate) raw: BytesMut,
    /// The RTO the transaction started with (RFC 8445 Section 14.3).
    pub(crate) rto: Duration,
    /// The wait before the next retransmission; doubles each time (RFC 8489 Section 6.2.1).
    pub(crate) interval: Duration,
    /// Requests sent so far, the first included.
    pub(crate) transmissions: u16,
    /// When the next retransmission is due, or, after the last one, when the transaction ends
    /// without a response.
    pub(crate) next_event: Instant,
    /// Whether the request is retransmitted: not over TCP, not a consent request.
    pub(crate) retransmit: bool,
    /// Cancelled (RFC 8445 Section 7.3.1.4): no retransmission, no failure when it times out,
    /// but a response is still taken.
    pub(crate) cancelled: bool,
    /// A consent request on the selected pair (RFC 7675), sent once.
    pub(crate) consent: bool,
    /// The PRIORITY the request carried: the priority of a local peer-reflexive candidate its
    /// response may reveal (RFC 8445 Section 7.2.5.3.1).
    pub(crate) priority: u32,
    /// A response to it arrived and was discarded because its integrity check failed: if
    /// the transaction ends without one that passes, that is an integrity violation, not a
    /// timeout (RFC 8489 Section 9.1.4).
    pub(crate) unauthentic_response: bool,
}

impl BindingRequest {
    /// A consent-style transaction (sent once) to `destination`, waiting until `timeout`.
    #[cfg(test)]
    pub(crate) fn sent_once(
        now: Instant,
        transaction_id: TransactionId,
        destination: SocketAddr,
        timeout: Duration,
    ) -> Self {
        Self {
            timestamp: now,
            transaction_id,
            destination,
            is_use_candidate: false,
            local_index: 0,
            remote_index: 0,
            sent_as_controlling: true,
            raw: BytesMut::new(),
            rto: timeout,
            interval: timeout,
            transmissions: 1,
            next_event: now + timeout,
            retransmit: false,
            cancelled: false,
            consent: true,
            priority: 0,
            unauthentic_response: false,
        }
    }
}

/// A Binding request that arrived, authenticated, before the peer's credentials were known
/// (RFC 8445 Section 7.3). It was answered at once; the rest of its processing (Sections
/// 7.3.1.3 to 7.3.1.5) waits for the credentials.
#[derive(Debug, Clone)]
pub(crate) struct EarlyRequest {
    pub(crate) message: Message,
    pub(crate) local_addr: SocketAddr,
    pub(crate) transport_protocol: TransportProtocol,
    pub(crate) remote_addr: SocketAddr,
}

/// What an ICE restart keeps of the generation it replaces, for as long as data still flows on
/// that generation's selected pair ([`Agent::media_path`]).
///
/// RFC 7675 Section 5.1: "an endpoint that continues to send traffic on the previously
/// validated candidate pair during ICE restart MUST continue to perform consent freshness on
/// that candidate pair". Consent on that pair is asked for, and given to the peer, with the
/// credentials the pair was validated with: the old ones, on both sides.
#[derive(Clone)]
pub(crate) struct PreviousGeneration {
    /// The local credentials of the replaced generation: the peer's consent requests on the
    /// old pair name this fragment and are signed with this password.
    pub(crate) local_credentials: Credentials,
    /// The peer's credentials of the replaced generation, for our own consent requests.
    pub(crate) remote_credentials: Credentials,
    /// The PRIORITY attribute of the consent requests.
    pub(crate) priority: u32,
    /// When the peer last consented (a lite agent: when it last sent an authenticated request).
    pub(crate) last_consent: Instant,
    pub(crate) next_consent_at: Instant,
    /// Consent requests sent on the old pair that may still be answered.
    pub(crate) pending: Vec<TransactionId>,
}

/// Most consent transactions of a replaced generation kept open at a time.
pub(crate) const MAX_PREVIOUS_GENERATION_TRANSACTIONS: usize = 8;

/// Most early requests remembered: one per (local, remote) address pair, so this bounds how
/// many paths a peer can have probed before its description arrives.
pub(crate) const MAX_EARLY_REQUESTS: usize = 16;

#[derive(Default, Clone)]
/// The ICE credentials for one side of a session, exchanged in SDP.
pub struct Credentials {
    /// The username fragment, echoed in every STUN check so a receiver can demultiplex.
    pub ufrag: String,
    /// The password, used as the `MESSAGE-INTEGRITY` key.
    pub pwd: String,
}

#[derive(Default, Clone)]
pub(crate) struct UfragPwd {
    pub(crate) local_credentials: Credentials,
    pub(crate) remote_credentials: Option<Credentials>,
    /// Credentials generated for an ICE restart that has not been applied yet.
    ///
    /// JSEP requires `createOffer` to be free of side effects, so the offer advertises these
    /// while the live session keeps authenticating with `local_credentials`. They are installed
    /// by [`Agent::apply_restart`] when the local description is set. If the offer is discarded,
    /// they are simply dropped and the existing session is undisturbed.
    pub(crate) pending_local_credentials: Option<Credentials>,
}

/// RFC 8445 Section 7.3: "the agent MUST consider the username to be valid if it consists of
/// two values separated by a colon, where the first value is equal to the username fragment
/// generated by the agent".
fn assert_inbound_username(m: &Message, local_ufrag: &str) -> Result<()> {
    let mut username = Username::new(ATTR_USERNAME, String::new());
    username.get_from(m)?;

    let text = username.to_string();
    match text.split_once(':') {
        Some((first, _)) if first == local_ufrag => Ok(()),
        _ => Err(Error::Other(format!(
            "{:?} expected({}:<remote fragment>) actual({})",
            Error::ErrMismatchUsername,
            local_ufrag,
            username,
        ))),
    }
}

/// The comprehension-required attributes the ICE usage understands: STUN's own and ICE's
/// (RFC 8445 Section 16.1). A request with another one is answered 420 (Unknown Attribute), a
/// response with one is discarded (RFC 8489 Section 6.3). ICE-CONTROLLED, ICE-CONTROLLING and
/// libwebrtc's NOMINATION are comprehension-optional.
fn ice_known_attributes() -> Vec<AttrType> {
    let mut known = stun::attributes::STUN_ATTRIBUTES.to_vec();
    known.extend([ATTR_PRIORITY, ATTR_USE_CANDIDATE]);
    known
}

/// What a received message is refused with, as the error the agent reports.
fn rejection_error(rejection: &stun::validated::Rejection) -> Error {
    use stun::validated::Rejection;
    match rejection {
        Rejection::IntegrityMismatch => Error::ErrIntegrityMismatch,
        Rejection::IntegrityMissing => Error::ErrAttributeNotFound,
        Rejection::FingerprintMissing | Rejection::FingerprintMismatch => {
            Error::ErrFingerprintMismatch
        }
        other => Error::Other(other.to_string()),
    }
}

/// Most remote candidates an agent holds. Browsers signal a few dozen at most; each one is paired
/// with every local candidate, so an unbounded list is quadratic work for whoever sends it.
pub(crate) const MAX_REMOTE_CANDIDATES: usize = 256;

/// Most mDNS (`.local`) remote candidates waiting on a query at once.
pub(crate) const MAX_PENDING_MDNS_QUERIES: usize = 32;

fn assert_inbound_message_integrity(
    m: &mut Message,
    key: &[u8],
    crypto: &dyn RTCCrypto,
) -> Result<()> {
    MessageIntegrity::check(m, key, crypto)
}

/// The SOFTWARE attribute the agent sends unless configured otherwise
/// ([`AgentConfig::software`]).
pub const DEFAULT_SOFTWARE: &str = concat!("rtc-ice ", env!("CARGO_PKG_VERSION"));

/// What the agent reports to its caller.
#[non_exhaustive]
pub enum Event {
    /// The agent's connection state changed.
    ConnectionStateChange(ConnectionState),
    /// A new pair was selected, carrying the local and remote candidates.
    ///
    /// Media should be sent on this pair from now on.
    SelectedCandidatePairChange(Box<Candidate>, Box<Candidate>),
    /// Emitted when the ICE role switches due to a role conflict (RFC 8445 §7.3.1.1).
    /// The bool is `true` if the agent is now controlling, `false` if now controlled.
    RoleChange(bool),
    /// A local candidate is signalled differently from now on and has to be conveyed to the
    /// peer again: its mDNS name was lost to another host (RFC 6762 Section 9) and it has a
    /// new one. The candidate keeps its id.
    LocalCandidateRenamed(Box<Candidate>),
    /// Two lite agents, this one controlling, and more than one candidate pair: the agent
    /// chose this pair (local, remote), and RFC 8445 Section 8.2 has the controlling agent
    /// "send an updated candidate list to reconcile different agents selecting different
    /// candidate pairs": an updated candidate exchange with these two candidates only.
    LiteCandidateUpdate(Box<Candidate>, Box<Candidate>),
    /// A candidate pair (local, remote) was put on the agent's list of pairs: formed from a
    /// local and a remote candidate, from a peer's request, or as the valid pair a response
    /// produced (webrtc-extensions 7, `icecandidatepairadd`).
    CandidatePairAdded(Box<Candidate>, Box<Candidate>),
    /// A candidate pair (local, remote) left the agent's list: another pair took its place
    /// on a full checklist, an ICE restart dropped the pairs, or the application removed it
    /// with [`Agent::remove_candidate_pair`] (webrtc-extensions 7, `icecandidatepairremove`).
    CandidatePairRemoved(Box<Candidate>, Box<Candidate>),
    /// With [`AgentConfig::candidate_pair_proposals`]: the controlling agent picked this pair
    /// (local, remote) to nominate and waits for [`Agent::resolve_nomination_proposal`]
    /// (webrtc-extensions 7, `icecandidatepairnominate`).
    CandidatePairNominationProposed(Box<Candidate>, Box<Candidate>),
    /// A check (or consent request) on this pair (local, remote) ended without a response
    /// that passed its integrity check, and at least one response arrived that failed it:
    /// RFC 8489 Section 9.1.4 has the transaction signal "an integrity protection violation"
    /// instead of a timeout. The pair fails as it would on a timeout; the event says why.
    IntegrityViolation(Box<Candidate>, Box<Candidate>),
}

/// An [`Event`] together with the instant its condition was observed at.
///
/// The agent's events are produced inside `handle_read` / `handle_timeout` / `close`, all of
/// which know the time, but they are consumed from `poll_event`, which does not. Carrying the
/// instant in the payload means the consumer is *told* when the condition happened rather than
/// having to retain an instant of its own and guess — the same channel `TaggedBytesMut` already
/// provides on the read path.
pub struct TaggedEvent {
    /// When the condition this event reports was observed.
    pub now: Instant,
    /// The event itself.
    pub event: Event,
}

/// The addresses and transport data is sent on and accepted from. See [`Agent::media_path`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MediaPath {
    /// The bound local address (a candidate's base).
    pub local_addr: SocketAddr,
    /// The remote candidate's address.
    pub peer_addr: SocketAddr,
    /// UDP or TCP.
    pub transport_protocol: TransportProtocol,
}

/// The pair data arrived on. See [`Agent::data_path`].
#[derive(Debug, Clone, Copy)]
pub enum DataPath<'a> {
    /// The path data is sent on: the selected pair's ([`Agent::media_path`]).
    InUse,
    /// Another valid pair: its local and remote candidates.
    Valid(&'a Candidate, &'a Candidate),
}

/// Represents the ICE agent.
pub struct Agent {
    pub(crate) crypto_provider: Arc<dyn RTCCryptoProvider>,
    pub(crate) tie_breaker: u64,
    pub(crate) is_controlling: bool,
    pub(crate) lite: bool,

    pub(crate) start_time: Instant,

    pub(crate) connection_state: ConnectionState,
    pub(crate) last_connection_state: ConnectionState,

    //pub(crate) started_ch_tx: Mutex<Option<broadcast::Sender<()>>>,
    pub(crate) ufrag_pwd: UfragPwd,

    pub(crate) local_candidates: Vec<Candidate>,
    pub(crate) remote_candidates: Vec<Candidate>,
    pub(crate) candidate_pairs: Vec<CandidatePair>,
    pub(crate) nominated_pair: Option<usize>,
    /// [`AgentConfig::candidate_pair_proposals`].
    pub(crate) candidate_pair_proposals: bool,
    /// The pair proposed for nomination, waiting for the application's decision.
    pub(crate) nomination_proposal: Option<usize>,
    /// Pairs whose nomination the application declined (this ICE session).
    pub(crate) declined_nominations: Vec<usize>,
    /// When the controlling agent nominated `nominated_pair`.
    pub(crate) nomination_started: Option<Instant>,
    pub(crate) selected_pair: Option<usize>,
    /// The selected pair's path at the moment an ICE restart was applied, kept until the
    /// restart selects a pair (or the agent fails or closes). See [`Agent::media_path`].
    pub(crate) previous_media_path: Option<MediaPath>,
    /// The credentials and consent state that go with `previous_media_path`.
    pub(crate) previous_generation: Option<PreviousGeneration>,
    /// The session an ICE restart replaced, while that restart can be taken back
    /// ([`Agent::apply_restart_revertible`]).
    pub(crate) restart_undo: Option<Box<restart_undo::RestartUndo>>,

    /// The open STUN transactions: one per check in flight, the consent requests, and the
    /// cancelled ones still waiting out their timeout.
    pub(crate) pending_binding_requests: Vec<BindingRequest>,
    /// The triggered-check queue (RFC 8445 Section 6.1.4.1), FIFO, a pair named by its local
    /// and remote candidate.
    pub(crate) triggered_queue: VecDeque<(usize, usize)>,
    /// Ta, the pacing of checks (Section 6.1.4.2), and when the next check may start.
    pub(crate) ta: Duration,
    pub(crate) next_check_at: Instant,
    /// The most pairs on the checklist (Section 6.1.2.5).
    pub(crate) max_candidate_pairs: usize,
    /// The peer signalled end-of-candidates for this generation (RFC 8838 Section 14).
    pub(crate) remote_end_of_candidates: bool,
    /// Local gathering is complete for this generation (RFC 8838 Section 13).
    pub(crate) local_gathering_complete: bool,
    /// Requests answered before the peer's credentials arrived, to finish processing then.
    pub(crate) early_requests: Vec<EarlyRequest>,

    // the following variables won't be changed after init_with_defaults()
    pub(crate) insecure_skip_verify: bool,
    pub(crate) max_binding_requests: u16,
    pub(crate) host_acceptance_min_wait: Duration,
    pub(crate) srflx_acceptance_min_wait: Duration,
    pub(crate) prflx_acceptance_min_wait: Duration,
    pub(crate) relay_acceptance_min_wait: Duration,
    // How long connectivity checks can fail before the ICE Agent
    // goes to disconnected
    pub(crate) disconnected_timeout: Duration,
    // How long connectivity checks can fail before the ICE Agent
    // goes to failed
    pub(crate) failed_timeout: Duration,
    // The basic period of the consent checks (RFC 7675 Section 5.1), at least 5 seconds.
    // 0 means never
    pub(crate) keepalive_interval: Duration,
    /// When the next consent request goes out on the selected pair: the last one plus an
    /// interval drawn from 0.8 to 1.2 times the period. `None` until a pair is selected.
    pub(crate) next_consent_at: Option<Instant>,
    /// When the oldest consent request that no response has followed was sent. `None` while
    /// the peer answers. The agent is `Disconnected` once this is `disconnected_timeout` old.
    pub(crate) consent_unanswered_since: Option<Instant>,
    // How often should we run our internal taskLoop to check for state changes when connecting
    pub(crate) check_interval: Duration,
    pub(crate) checking_duration: Instant,
    pub(crate) last_checking_time: Instant,
    /// The latest instant the agent was given (construction, `handle_read`, `handle_timeout`):
    /// what the candidate-pair events of a call that is not given one are tagged with.
    pub(crate) clock: Instant,
    // When set, a connectivity check has been requested and must be run on the next
    // `handle_timeout`. Checks are deferred (rather than run inline) so that adding a
    // candidate can never re-enter `contact()` and mutate agent state - e.g. transition
    // to `Failed` and drop candidates - while a caller still holds indices into the
    // candidate vectors. See issue #88.
    pub(crate) force_candidate_contact: bool,

    pub(crate) mdns: Option<Mdns>,
    pub(crate) mdns_queries: HashMap<QueryId, Candidate>,

    pub(crate) mdns_mode: MulticastDnsMode,
    pub(crate) mdns_local_name: String,
    pub(crate) mdns_local_ip: Option<IpAddr>,
    /// `QueryAndGather` without a fixed `mdns_local_ip`: the `<uuid>.local` name each local
    /// address is published under, one per address, made when its first host candidate is added.
    pub(crate) mdns_local_names: Vec<(IpAddr, String)>,

    pub(crate) candidate_types: Vec<CandidateType>,
    pub(crate) network_types: Vec<NetworkType>,
    pub(crate) urls: Vec<Url>,

    /// Which remote addresses checks may be sent to. See [`remote_policy`].
    pub(crate) remote_policy: RemotePolicy,

    /// The peer is a lite implementation (RFC 8445 Section 6.1.1; set by the using protocol).
    pub(crate) remote_lite: bool,
    /// The `LiteCandidateUpdate` event of this generation was raised.
    pub(crate) lite_update_raised: bool,
    /// Ta as configured, before the peer's proposal (Section 14.2).
    pub(crate) configured_ta: Option<Duration>,
    /// Which of several nominations the controlled agent uses.
    pub(crate) nomination_acceptance: NominationAcceptance,
    /// What a nomination that times out leads to.
    pub(crate) failed_nomination: FailedNomination,
    pub(crate) pacing_group: Option<Arc<PacingGroup>>,
    /// The controlling agent's consent checks carry USE-CANDIDATE (libwebrtc).
    pub(crate) nominate_on_consent_checks: bool,
    /// Error responses to unauthenticated requests, or nothing.
    pub(crate) unauthenticated_requests: UnauthenticatedRequests,
    /// The token bucket of those error responses: tokens left, and when it was last filled.
    pub(crate) unauthenticated_response_tokens: u32,
    pub(crate) unauthenticated_response_refill: Instant,
    /// The integrity attribute of the request being answered: its responses carry the same one
    /// and no other (RFC 8489 Section 9.1.3).
    pub(crate) answer_integrity: IntegrityAlgorithm,
    /// Data only from the selected pair's remote address (not RFC 8445 Section 12.2).
    pub(crate) data_from_selected_pair_only: bool,
    /// Data on the best valid pair before a pair is selected (RFC 8445 Section 12.1).
    pub(crate) send_data_before_nomination: bool,
    /// [`AgentConfig::hold_local_candidates_until_conveyed`].
    pub(crate) hold_local_candidates_until_conveyed: bool,
    /// [`AgentConfig::path_mtu`].
    pub(crate) path_mtu: Option<usize>,
    /// [`AgentConfig::software`], resolved: `None` sends no SOFTWARE attribute.
    pub(crate) software: Option<String>,

    /// The 1:1 NAT mapping applied to the host candidates the application adds.
    pub(crate) ext_ip_mapper: Option<ExternalIpMapper>,

    pub(crate) write_outs: VecDeque<TaggedBytesMut>,
    pub(crate) event_outs: VecDeque<TaggedEvent>,
}

/// What [`Agent::mdns_name_for`] decided for a host candidate.
enum MdnsHostName {
    /// Publish it under this name.
    Hide(String),
    /// Keep its address.
    Literal,
    /// Too many names are published already: the candidate takes this name, which is not
    /// published, and so keeps its address private.
    Unpublished(String),
}

impl Agent {
    /// Creates a new Agent.
    ///
    /// The crypto provider is supplied by the caller; this crate never resolves a default.
    /// Builds an agent whose clock starts at `now`.
    ///
    /// `now` is a constructor argument rather than an `AgentConfig` field because it is a value
    /// consumed once at construction, not a setting that persists for the agent's lifetime — and
    /// because `Instant` has no `Default`, so a config field would force `AgentConfig` to drop
    /// `#[derive(Default)]` and break every `..Default::default()` in its 31 call sites.
    pub fn new(
        now: Instant,
        config: Arc<AgentConfig>,
        crypto_provider: Arc<dyn RTCCryptoProvider>,
    ) -> Result<Self> {
        let tie_breaker = match config.tie_breaker {
            Some(tie_breaker) => tie_breaker,
            None => generate_tie_breaker(crypto_provider.random())?,
        };

        let mut mdns_local_name = config.multicast_dns_local_name.clone();
        if mdns_local_name.is_empty() {
            mdns_local_name = generate_multicast_dns_name();
        }

        if !is_valid_local_mdns_name(&mdns_local_name) {
            return Err(Error::ErrInvalidMulticastDnshostName);
        }

        let mdns_mode = config.multicast_dns_mode;
        let mdns = create_multicast_dns(
            now,
            mdns_mode,
            &mdns_local_name,
            &config.multicast_dns_local_ip,
            &config.multicast_dns_query_timeout,
            MdnsOptions {
                first_query_delay: config.multicast_dns_first_query_delay.unwrap_or(true),
                multi_question_delay: config.multicast_dns_multi_question_delay.unwrap_or(true),
                destination_reported: config.multicast_dns_destination_reported,
                unicast_response: config.multicast_dns_unicast_response,
                rate_limit: config.multicast_dns_rate_limit.clone(),
            },
        )
        .unwrap_or_else(|err| {
            // Opportunistic mDNS: If we can't open the connection, that's ok: we
            // can continue without it.
            warn!("Failed to initialize mDNS {mdns_local_name}: {err}");
            None
        });

        let candidate_types = if config.candidate_types.is_empty() {
            default_candidate_types()
        } else {
            config.candidate_types.clone()
        };

        if config.lite && (candidate_types.len() != 1 || candidate_types[0] != CandidateType::Host)
        {
            return Err(Error::ErrLiteUsingNonHostCandidates);
        }

        if !config.urls.is_empty()
            && !contains_candidate_type(CandidateType::ServerReflexive, &candidate_types)
            && !contains_candidate_type(CandidateType::Relay, &candidate_types)
        {
            return Err(Error::ErrUselessUrlsProvided);
        }

        let ext_ip_mapper = config.init_ext_ip_mapping(mdns_mode, &candidate_types)?;

        let mut agent = Self {
            crypto_provider,
            tie_breaker,
            is_controlling: config.is_controlling,
            lite: config.lite,

            start_time: now,

            nominated_pair: None,
            candidate_pair_proposals: config.candidate_pair_proposals,
            nomination_proposal: None,
            declined_nominations: Vec::new(),
            nomination_started: None,
            selected_pair: None,
            previous_media_path: None,
            previous_generation: None,
            restart_undo: None,
            candidate_pairs: vec![],

            connection_state: ConnectionState::New,

            insecure_skip_verify: config.insecure_skip_verify,

            //started_ch_tx: MuteSome(started_ch_tx)),

            //won't change after init_with_defaults()
            max_binding_requests: if let Some(max_binding_requests) = config.max_binding_requests {
                max_binding_requests
            } else {
                DEFAULT_MAX_BINDING_REQUESTS
            },
            host_acceptance_min_wait: if let Some(host_acceptance_min_wait) =
                config.host_acceptance_min_wait
            {
                host_acceptance_min_wait
            } else {
                DEFAULT_HOST_ACCEPTANCE_MIN_WAIT
            },
            srflx_acceptance_min_wait: if let Some(srflx_acceptance_min_wait) =
                config.srflx_acceptance_min_wait
            {
                srflx_acceptance_min_wait
            } else {
                DEFAULT_SRFLX_ACCEPTANCE_MIN_WAIT
            },
            prflx_acceptance_min_wait: if let Some(prflx_acceptance_min_wait) =
                config.prflx_acceptance_min_wait
            {
                prflx_acceptance_min_wait
            } else {
                DEFAULT_PRFLX_ACCEPTANCE_MIN_WAIT
            },
            relay_acceptance_min_wait: if let Some(relay_acceptance_min_wait) =
                config.relay_acceptance_min_wait
            {
                relay_acceptance_min_wait
            } else {
                DEFAULT_RELAY_ACCEPTANCE_MIN_WAIT
            },

            // How long connectivity checks can fail before the ICE Agent
            // goes to disconnected
            disconnected_timeout: if let Some(disconnected_timeout) = config.disconnected_timeout {
                disconnected_timeout
            } else {
                DEFAULT_DISCONNECTED_TIMEOUT
            },

            // How long connectivity checks can fail before the ICE Agent
            // goes to failed
            failed_timeout: if let Some(failed_timeout) = config.failed_timeout {
                failed_timeout
            } else {
                DEFAULT_FAILED_TIMEOUT
            },

            // The basic period of the consent checks; 0 means never. RFC 7675 Section 5.1:
            // "Implementations MUST NOT set the period between checks to less than 4 seconds",
            // and each interval is 0.8 to 1.2 times the basic period, so the basic period is
            // at least 5 seconds.
            keepalive_interval: match config.keepalive_interval {
                Some(ZERO_DURATION) => ZERO_DURATION,
                Some(keepalive_interval) => keepalive_interval.max(DEFAULT_KEEPALIVE_INTERVAL),
                None => DEFAULT_KEEPALIVE_INTERVAL,
            },

            // How often should we run our internal taskLoop to check for state changes when connecting
            check_interval: if config.check_interval == Duration::from_secs(0) {
                DEFAULT_CHECK_INTERVAL
            } else {
                config.check_interval
            },
            next_consent_at: None,
            consent_unanswered_since: None,
            checking_duration: now,
            last_checking_time: now,
            clock: now,
            force_candidate_contact: false,
            last_connection_state: ConnectionState::Unspecified,

            mdns,
            mdns_queries: HashMap::new(),

            mdns_mode,
            mdns_local_name,
            mdns_local_ip: config.multicast_dns_local_ip,
            mdns_local_names: Vec::new(),

            ufrag_pwd: UfragPwd::default(),

            local_candidates: vec![],
            remote_candidates: vec![],

            pending_binding_requests: vec![],
            triggered_queue: VecDeque::new(),
            // RFC 8445 Section 14.2: 50 ms by default, never under 5 ms.
            ta: config.ta.unwrap_or(DEFAULT_TA).max(MIN_TA),
            next_check_at: now,
            max_candidate_pairs: config
                .max_candidate_pairs
                .unwrap_or(DEFAULT_MAX_CANDIDATE_PAIRS)
                .max(1),
            remote_end_of_candidates: false,
            local_gathering_complete: false,
            early_requests: vec![],

            candidate_types,
            network_types: config.network_types.clone(),
            urls: config.urls.clone(),

            remote_policy: RemotePolicy {
                allow_loopback: config.allow_loopback_remote_candidates,
                allow_link_local: config.allow_link_local_remote_candidates,
                filter: config.remote_address_filter.clone(),
            },
            ext_ip_mapper,

            remote_lite: false,
            lite_update_raised: false,
            configured_ta: config.ta,
            nomination_acceptance: config.nomination_acceptance,
            failed_nomination: config.failed_nomination,
            pacing_group: config.pacing_group.clone(),
            nominate_on_consent_checks: config.nominate_on_consent_checks,
            unauthenticated_requests: config.unauthenticated_requests,
            unauthenticated_response_tokens: MAX_UNAUTHENTICATED_RESPONSE_BURST,
            unauthenticated_response_refill: now,
            answer_integrity: IntegrityAlgorithm::Sha1,
            data_from_selected_pair_only: config.data_from_selected_pair_only,
            send_data_before_nomination: config.send_data_before_nomination,
            hold_local_candidates_until_conveyed: config.hold_local_candidates_until_conveyed,
            path_mtu: config.path_mtu,
            software: match &config.software {
                None => Some(DEFAULT_SOFTWARE.to_owned()),
                Some(s) if s.is_empty() => None,
                Some(s) => Some(s.clone()),
            },

            write_outs: VecDeque::new(),
            event_outs: VecDeque::new(),
        };

        // Restart is also used to initialize the agent for the first time
        if let Err(err) = agent.restart(
            now,
            config.local_ufrag.clone(),
            config.local_pwd.clone(),
            false,
        ) {
            let _ = agent.close();
            return Err(err);
        }

        Ok(agent)
    }

    /// Adds a new local candidate that the caller conveys to the peer with this call (trickles
    /// it, or writes it into the description it sends): the agent pairs it at once.
    ///
    /// RFC 8838 Section 10: "A Trickle ICE agent MUST NOT pair a local candidate until it has
    /// been trickled to the remote party." A caller that gathers a candidate before it can
    /// convey it adds it with [`Agent::add_unconveyed_local_candidate`] and tells the agent
    /// with [`Agent::local_candidate_conveyed`] when it has.
    ///
    /// With [`AgentConfig::hold_local_candidates_until_conveyed`] this is
    /// [`Agent::add_unconveyed_local_candidate`].
    pub fn add_local_candidate(&mut self, c: Candidate) -> Result<bool> {
        let hold = self.hold_local_candidates_until_conveyed;
        self.add_gathered_local_candidate(c, hold)
    }

    /// Adds a new local candidate that is not conveyed to the peer yet: the agent holds it,
    /// answers checks that reach it, and pairs it once [`Agent::local_candidate_conveyed`]
    /// (or [`Agent::all_local_candidates_conveyed`]) says it has been trickled (RFC 8838
    /// Section 10). Otherwise as [`Agent::add_local_candidate`]; a server-reflexive candidate
    /// the agent adds next to it for a 1:1 NAT mapping is held too.
    pub fn add_unconveyed_local_candidate(&mut self, c: Candidate) -> Result<bool> {
        self.add_gathered_local_candidate(c, true)
    }

    /// The local candidate `id` has been conveyed to the peer: it is paired now with the
    /// remote candidates known (RFC 8838 Section 10, steps 2 and 3). Returns whether the
    /// agent held such a candidate unconveyed.
    pub fn local_candidate_conveyed(&mut self, id: &str) -> bool {
        let Some(local_index) = self
            .local_candidates
            .iter()
            .position(|c| c.unconveyed && c.id() == id)
        else {
            return false;
        };
        self.convey_local_candidate(local_index);
        true
    }

    /// Every local candidate the agent holds has been conveyed to the peer (a description
    /// listing them was applied, say): each one held unconveyed is paired now.
    pub fn all_local_candidates_conveyed(&mut self) {
        for local_index in 0..self.local_candidates.len() {
            if self.local_candidates[local_index].unconveyed {
                self.convey_local_candidate(local_index);
            }
        }
    }

    /// RFC 8839 Sections 4.2.5, 4.3.3 and 5.3: the answer carries `a=ice-mismatch` for the
    /// data stream this agent serves (the offer arrived at the peer with a default destination
    /// that no candidate matched), so "ICE procedures MUST NOT be used for this data stream".
    /// The agent stops: no more checks or consent requests, no candidates, state `Failed`.
    /// The RFC 3264 fallback the RFC then calls for (media to the `m=` / `c=` destination
    /// without checks) is not taken: a WebRTC endpoint sends nothing without consent (RFC
    /// 7675 Section 5.1), so the stream ends with the agent. Returns whether the agent was
    /// running.
    pub fn stop_for_ice_mismatch(&mut self, now: Instant) -> bool {
        if matches!(
            self.connection_state,
            ConnectionState::Failed | ConnectionState::Closed
        ) {
            return false;
        }
        warn!(
            "[{}]: the answer says ice-mismatch: ICE is not used for this stream",
            self.get_name()
        );
        self.update_connection_state(Some(now), ConnectionState::Failed);
        true
    }

    /// Whether the local candidate `id` is held unconveyed (and so unpaired).
    pub fn is_local_candidate_unconveyed(&self, id: &str) -> bool {
        self.local_candidates
            .iter()
            .any(|c| c.unconveyed && c.id() == id)
    }

    fn convey_local_candidate(&mut self, local_index: usize) {
        self.local_candidates[local_index].unconveyed = false;
        self.pair_local_candidate(local_index);
    }

    /// Pairs a conveyed local candidate with every remote candidate it can be paired with.
    fn pair_local_candidate(&mut self, local_index: usize) {
        if self.local_candidates[local_index].unconveyed {
            return;
        }
        for remote_index in 0..self.remote_candidates.len() {
            if self.local_candidates[local_index]
                .can_pair_with(&self.remote_candidates[remote_index])
            {
                self.add_pair(local_index, remote_index);
            }
        }
        self.request_connectivity_check();
    }

    fn add_gathered_local_candidate(&mut self, mut c: Candidate, unconveyed: bool) -> Result<bool> {
        // Filter by network type if network_types is configured
        if !self.network_types.is_empty() {
            let candidate_network_type = c.network_type();
            if !self.network_types.contains(&candidate_network_type) {
                debug!(
                    "Ignoring local candidate with network type {:?} (not in configured network types: {:?})",
                    candidate_network_type, self.network_types
                );
                return Ok(false);
            }
        }

        // Filter by candidate type if candidate_types is configured.
        let candidate_type = c.candidate_type();
        if !self.candidate_types.is_empty() && !self.candidate_types.contains(&candidate_type) {
            debug!(
                "Ignoring local candidate with type {:?} (not in configured candidate types: {:?})",
                candidate_type, self.candidate_types
            );
            return Ok(false);
        }

        if c.candidate_type() == CandidateType::Host
            && self.mdns_mode == MulticastDnsMode::QueryAndGather
            && !c.address.ends_with(".local")
        {
            match self.mdns_name_for(c.addr().ip(), c.network_type()) {
                MdnsHostName::Hide(name) => {
                    trace!("mDNS hides local ip {} with local name {}", c.address, name);
                    c.address = name;
                }
                MdnsHostName::Literal => {}
                MdnsHostName::Unpublished(name) => {
                    // draft-ietf-mmusic-mdns-ice-candidates Section 3.1.1: "the ICE agent
                    // SHOULD still provide mDNS candidates in step 6 even if [...] mDNS
                    // registration fails in step 4": the candidate goes out under a name
                    // that is never published (it does not resolve), so neither its address
                    // nor the failure shows.
                    warn!(
                        "[{}]: local host candidate {} goes out under an unpublished mDNS name: {} names already published (the cap)",
                        self.get_name(),
                        c.address,
                        mdns::MAX_LOCAL_NAMES
                    );
                    c.address = name;
                }
            }
        }

        // 1:1 NAT (`nat_1to1_ips`): the host candidate is advertised on, or joined by a
        // server-reflexive candidate on, the external address of its local one.
        let nat_srflx = self.apply_nat_1to1(&mut c);

        // RFC 8838 Section 13: no candidate follows the end-of-candidates indication of its
        // generation.
        if self.local_gathering_complete {
            warn!(
                "[{}]: ignoring local candidate {}: gathering was declared complete",
                self.get_name(),
                c
            );
            return Ok(false);
        }
        // RFC 8838 Section 13: "In all cases, an agent MUST NOT trickle any new candidates
        // within an ICE session after nomination of a candidate pair". A candidate gathered
        // after it is not taken (so not announced either); an ICE restart takes it.
        if self.selected_pair.is_some() {
            debug!(
                "[{}]: ignoring local candidate {}: a pair has been nominated",
                self.get_name(),
                c
            );
            return Ok(false);
        }

        // RFC 8445 Section 5.2: a lite implementation has only host candidates, "zero or one
        // candidate per IP address": another type, or a second candidate on an address it
        // already has a candidate on, is not taken.
        if self.lite
            && (c.candidate_type() != CandidateType::Host
                || self
                    .local_candidates
                    .iter()
                    .any(|cand| cand.addr().ip() == c.addr().ip()))
        {
            warn!(
                "[{}]: ignoring local candidate {}: a lite agent has one host candidate per IP address",
                self.get_name(),
                c
            );
            return Ok(false);
        }

        for cand in &self.local_candidates {
            if cand.equal(&c) {
                return Ok(false);
            }
            // RFC 8445 Section 5.1.3: "A candidate is redundant if and only if its transport
            // address and base equal those of another candidate" (a server-reflexive candidate
            // equal to its host candidate, a relayed one identical to a host candidate). An
            // mDNS host candidate hides its address: a reflexive candidate on that address is
            // not redundant with it (draft-ietf-mmusic-mdns-ice-candidates Section 3.1.2.2).
            if cand.network_type() == c.network_type()
                && cand.tcp_type() == c.tcp_type()
                && cand.addr() == c.addr()
                && cand.base_addr() == c.base_addr()
                && !cand.addr().ip().is_unspecified()
                && !cand.address().ends_with(".local")
                && !c.address().ends_with(".local")
                && cand.address() == c.address()
            {
                debug!(
                    "[{}]: ignoring redundant local candidate {} (same address and base as {})",
                    self.get_name(),
                    c,
                    cand
                );
                return Ok(false);
            }
        }

        self.rank_local_candidate(&mut c);

        // With host addresses hidden behind mDNS names, a reflexive or relayed candidate does
        // not give its base away in raddr / rport (mDNS draft Section 3.1.2.2).
        if self.mdns_mode == MulticastDnsMode::QueryAndGather
            && c.candidate_type() != CandidateType::Host
            && c.related_address().is_some()
        {
            c.hide_related_address = true;
        }

        c.unconveyed = unconveyed;
        self.local_candidates.push(c);
        let local_index = self.local_candidates.len() - 1;

        // RFC 8838 Section 10: a candidate not yet conveyed to the peer is not paired.
        self.pair_local_candidate(local_index);

        if let Some(srflx) = nat_srflx {
            self.add_gathered_local_candidate(srflx, unconveyed)?;
        }

        Ok(true)
    }

    /// Adds local candidates gathered together: those without a priority or a rank of their
    /// own are ranked first as RFC 8421 Section 4 recommends for a dual-stack host (an IPv6
    /// head start, then the families alternating; see
    /// [`rank_local_candidates`](crate::candidate::rank_local_candidates)), around the ranks
    /// of the candidates the agent holds, and then each is added as by
    /// [`Agent::add_local_candidate`], whose results are returned in order.
    pub fn add_local_candidates(&mut self, mut candidates: Vec<Candidate>) -> Result<Vec<bool>> {
        crate::candidate::assign_dual_stack_ranks(&self.local_candidates, &mut candidates);
        candidates
            .into_iter()
            .map(|c| self.add_local_candidate(c))
            .collect()
    }

    /// Gives a local candidate that has neither a priority nor a rank of its own a local
    /// preference no other local candidate of its type has (RFC 8445 Section 5.1.2.1: "If
    /// there are multiple candidates for a particular component for a particular data stream
    /// that have the same type, the local preference MUST be unique for each one"; RFC 6544
    /// Section 4.2 says the same of a TCP candidate's other-pref).
    ///
    /// Candidates are ranked in the order they are added, the two address families
    /// interleaved (RFC 8421 Section 4): the family of the first candidate of a type takes the
    /// even ranks, the other family the odd ones, so neither family's candidates are all
    /// checked before the other's. The first candidate keeps the largest value (65535), as
    /// Section 5.1.2.1 asks of an agent with one address. A priority that has been signalled
    /// never changes, which is why a later candidate cannot go ahead of an earlier one: an
    /// application that wants IPv6 first adds its candidates together with
    /// [`Agent::add_local_candidates`] (RFC 8421's IPv6 head start), adds an IPv6 candidate
    /// first, or ranks candidates itself with [`Candidate::set_local_preference_rank`].
    fn rank_local_candidate(&self, c: &mut Candidate) {
        if c.priority_override != 0 || c.local_preference_rank.is_some() {
            return;
        }
        let same_group = |other: &&Candidate| {
            other.candidate_type() == c.candidate_type()
                && other.component() == c.component()
                && other.network_type().is_tcp() == c.network_type().is_tcp()
                && other.tcp_type() == c.tcp_type()
                // (A lite agent's ranked candidates carry their priority as an override.)
                && (other.priority_override == 0 || other.local_preference_rank.is_some())
        };
        let ranked: Vec<&Candidate> = self.local_candidates.iter().filter(same_group).collect();
        let is_v6 = |x: &Candidate| x.network_type().is_ipv6();
        let parity = match ranked.first() {
            Some(first) if is_v6(first) != is_v6(c) => 1u16,
            _ => 0,
        };
        let mut rank = parity;
        while ranked
            .iter()
            .any(|other| other.local_preference_rank.unwrap_or(0) == rank)
        {
            match rank.checked_add(2) {
                Some(next) => rank = next,
                None => break,
            }
        }
        c.local_preference_rank = Some(rank);

        // RFC 8445 Section 5.2: "If an ICE lite agent is dual-stack or IPv6-only, the local
        // preference SHOULD be set to the precedence value for IP addresses described in [RFC
        // 6724]" (an IPv4-only lite agent keeps 65535). The precedence takes the high byte, so
        // it orders the candidates, and the rank the low one, so that two candidates of one
        // precedence still have unique priorities (Section 5.2: "each candidate MUST have a
        // unique priority").
        if self.lite && self.is_dual_stack_or_ipv6(c) {
            let precedence = rfc6724_precedence(c.addr().ip());
            let local_preference = (u16::from(precedence) << 8) | (255 - rank.min(255));
            c.priority_override = (u32::from(c.candidate_type().preference()) << 24)
                + (u32::from(local_preference) << 8)
                + 256u32.saturating_sub(u32::from(c.component()));
        }
    }

    /// Whether the agent is dual-stack or IPv6-only: its network types include an IPv6 one,
    /// or it holds (or is given) an IPv6 candidate.
    fn is_dual_stack_or_ipv6(&self, c: &Candidate) -> bool {
        self.network_types.iter().any(|t| t.is_ipv6())
            || c.network_type().is_ipv6()
            || self
                .local_candidates
                .iter()
                .any(|other| other.network_type().is_ipv6())
    }

    /// Applies the 1:1 NAT mapping to a host candidate the application adds. With a `Host`
    /// mapping the candidate's advertised address becomes the external one (its base, the
    /// socket it is bound to, is kept, as an mDNS name keeps it); with a `ServerReflexive`
    /// mapping the server-reflexive candidate to add beside it is returned.
    fn apply_nat_1to1(&self, c: &mut Candidate) -> Option<Candidate> {
        let mapper = self.ext_ip_mapper.as_ref()?;
        // An application-added `.local` candidate has no resolved address to map.
        if c.candidate_type() != CandidateType::Host || c.addr().ip().is_unspecified() {
            return None;
        }
        let local_ip = c.addr().ip();
        let external_ip = match mapper.find_external(local_ip) {
            Ok(ip) => ip,
            Err(_) => {
                warn!(
                    "[{}]: 1:1 NAT mapping is enabled but no external IP is found for {}",
                    self.get_name(),
                    local_ip
                );
                return None;
            }
        };
        if mapper.candidate_type == CandidateType::Host {
            c.address = external_ip.to_string();
            return None;
        }
        let mut srflx = match (CandidateServerReflexiveConfig {
            base_config: CandidateConfig {
                network: c.network.clone(),
                address: external_ip.to_string(),
                port: c.port(),
                component: c.component(),
                ..CandidateConfig::default()
            },
            rel_addr: local_ip.to_string(),
            rel_port: c.port(),
            url: None,
        })
        .new_candidate_server_reflexive()
        {
            Ok(srflx) => srflx,
            Err(err) => {
                warn!(
                    "[{}]: cannot make the 1:1 NAT server-reflexive candidate for {}: {}",
                    self.get_name(),
                    c,
                    err
                );
                return None;
            }
        };
        srflx.tcp_type = c.tcp_type();
        Some(srflx)
    }

    /// The name a host candidate on `ip` is published under in `QueryAndGather` mode.
    ///
    /// With a fixed `mdns_local_ip` (the original behaviour), only that IPv4 address is hidden,
    /// behind `mdns_local_name`, for UDP and TCP alike. Without one, every local address gets its
    /// own `<uuid>.local` name, IPv4 and IPv6, as browsers publish host candidates: made when its
    /// first candidate is added, registered with the mDNS responder, reused for the address's
    /// other candidates (and across ICE restarts).
    fn mdns_name_for(&mut self, ip: IpAddr, network_type: NetworkType) -> MdnsHostName {
        if let Some(local_ip) = self.mdns_local_ip {
            let v4 = matches!(network_type, NetworkType::Udp4 | NetworkType::Tcp4);
            return if v4 && local_ip == ip {
                MdnsHostName::Hide(self.mdns_local_name.clone())
            } else {
                MdnsHostName::Literal
            };
        }
        if let Some((_, name)) = self.mdns_local_names.iter().find(|(i, _)| *i == ip) {
            return MdnsHostName::Hide(name.clone());
        }
        let Some(mdns_conn) = &mut self.mdns else {
            return MdnsHostName::Literal;
        };
        let name = generate_multicast_dns_name();
        if !mdns_conn.add_local_name(&name, ip) {
            return MdnsHostName::Unpublished(name);
        }
        self.mdns_local_names.push((ip, name.clone()));
        MdnsHostName::Hide(name)
    }

    /// Adds a new remote candidate.
    pub fn add_remote_candidate(&mut self, c: Candidate) -> Result<bool> {
        // RFC 8838 Section 14: "After an agent has received an end-of-candidates indication,
        // it MUST ignore any newly received candidates for that data stream".
        if self.remote_end_of_candidates {
            warn!(
                "[{}]: ignoring remote candidate {}: it follows end-of-candidates",
                self.get_name(),
                c.address()
            );
            return Ok(false);
        }
        // Bound what the remote description (or a stream of peer-reflexive checks) can make us
        // hold: every remote candidate is paired with every local one, and each `.local` name
        // is an mDNS query kept until it resolves.
        if self.remote_candidates.len() >= MAX_REMOTE_CANDIDATES {
            warn!(
                "[{}]: ignoring remote candidate {}: already holding {} (the cap)",
                self.get_name(),
                c.address(),
                MAX_REMOTE_CANDIDATES
            );
            return Ok(false);
        }

        // The agent has one component (RTP; the engine is rtcp-mux only), and candidates are
        // paired within a component (RFC 8445 Section 6.1.2.2). A peer that also signals each
        // candidate for the RTCP component (pion and webrtc-rs do, with the same address)
        // gets those ignored: held, they could never be paired, and they would stand in the
        // way of the RTP candidate with the same transport address.
        if c.component() != COMPONENT_RTP {
            debug!(
                "[{}]: ignoring remote candidate {} of component {}",
                self.get_name(),
                c.address(),
                c.component()
            );
            return Ok(false);
        }

        // Filter by network type if network_types is configured
        if !self.network_types.is_empty() {
            let candidate_network_type = c.network_type();
            if !self.network_types.contains(&candidate_network_type) {
                debug!(
                    "Ignoring remote candidate with network type {:?} (not in configured network types: {:?})",
                    candidate_network_type, self.network_types
                );
                return Ok(false);
            }
        }

        // A signalled TCP active candidate has no listening port (RFC 6544 §4.5: port 9): it
        // initiates connections and is reached as the peer-reflexive candidate its checks
        // create on one of our passive candidates. That peer-reflexive one, which carries the
        // connection's real source port, is kept.
        if c.tcp_type() == TcpType::Active && c.candidate_type() != CandidateType::PeerReflexive {
            debug!(
                "Ignoring remote candidate with tcptype active: {}",
                c.address()
            );
            return Ok(false);
        }

        // If we have a mDNS Candidate lets fully resolve it before adding it locally
        if c.candidate_type() == CandidateType::Host && c.address().ends_with(".local") {
            if self.mdns_mode == MulticastDnsMode::Disabled {
                warn!(
                    "remote mDNS candidate added, but mDNS is disabled: ({})",
                    c.address()
                );
                return Ok(false);
            }

            // draft-ietf-mmusic-mdns-ice-candidates Section 3.2.1, step 2: "If the ICE
            // candidate policy is 'relay', as defined in [RFC8829], ignore the candidate":
            // it could only be paired with a relayed candidate, which Section 3.3.2 forbids,
            // and resolving it would tell the local network who is being called.
            if self.candidate_types == [CandidateType::Relay] {
                debug!(
                    "[{}]: ignoring mDNS candidate {}: relay-only policy",
                    self.get_name(),
                    c.address()
                );
                return Ok(false);
            }

            if c.candidate_type() != CandidateType::Host {
                return Err(Error::ErrAddressParseFailed);
            }

            if !is_ice_mdns_name(c.address()) {
                warn!(
                    "[{}]: ignoring mDNS candidate {}: not a <uuid>.local name",
                    self.get_name(),
                    c.address()
                );
                return Ok(false);
            }

            if self.mdns_queries.len() >= MAX_PENDING_MDNS_QUERIES {
                warn!(
                    "[{}]: ignoring mDNS candidate {}: {} queries already pending (the cap)",
                    self.get_name(),
                    c.address(),
                    MAX_PENDING_MDNS_QUERIES
                );
                return Ok(false);
            }

            if let Some(mdns_conn) = &mut self.mdns {
                let query_id = mdns_conn.schedule_query(c.address());
                self.mdns_queries.insert(query_id, c);
            }

            return Ok(false);
        }

        Ok(self.trigger_request_connectivity_check(vec![c]) > 0)
    }

    /// Takes remote candidates into the list and pairs them; returns how many are now held.
    fn trigger_request_connectivity_check(&mut self, remote_candidates: Vec<Candidate>) -> usize {
        let mut held = 0;
        for c in remote_candidates {
            // Every path that adds a remote candidate comes through here, mDNS-resolved ones
            // included (their query was capped, not the candidate list).
            if self.remote_candidates.len() >= MAX_REMOTE_CANDIDATES {
                warn!(
                    "[{}]: ignoring remote candidate {}: already holding {} (the cap)",
                    self.get_name(),
                    c.address(),
                    MAX_REMOTE_CANDIDATES
                );
                continue;
            }
            // RFC 8445 §5.1.1.1: a candidate is a unicast transport address. One that can't be
            // a destination, or that the application's filter refuses, is never held or paired.
            if !self.remote_policy.allows_candidate(c.addr()) {
                warn!(
                    "[{}]: ignoring remote candidate {}: its address {} is not an allowed destination",
                    self.get_name(),
                    c.address(),
                    c.addr()
                );
                continue;
            }
            // One remote candidate per transport address: a second one could never be told
            // apart from the first by the source of what it sends.
            if let Some(known) = self
                .remote_candidates
                .iter()
                .position(|cand| cand.addr() == c.addr() && cand.network_type() == c.network_type())
            {
                if self.remote_candidates[known].candidate_type() == CandidateType::PeerReflexive
                    && c.candidate_type() != CandidateType::PeerReflexive
                {
                    self.replace_peer_reflexive_remote_candidate(known, c);
                    held += 1;
                }
                continue;
            }
            if !self.remote_candidates.iter().any(|cand| cand.equal(&c)) {
                held += 1;
                self.remote_candidates.push(c);
                let remote_index = self.remote_candidates.len() - 1;

                for local_index in 0..self.local_candidates.len() {
                    if !self.local_candidates[local_index].unconveyed
                        && self.local_candidates[local_index]
                            .can_pair_with(&self.remote_candidates[remote_index])
                    {
                        self.add_pair(local_index, remote_index);
                    }
                }

                self.request_connectivity_check();
            }
        }
        held
    }

    /// RFC 8838 Section 11: a signalled candidate with the address of a peer-reflexive one the
    /// agent learned from a check takes its place. The pairs that candidate is in are kept,
    /// with the signalled priority (and so their place in the checklist), and the candidate
    /// is now paired with the other local candidates too.
    fn replace_peer_reflexive_remote_candidate(&mut self, remote_index: usize, mut c: Candidate) {
        let learned = &self.remote_candidates[remote_index];
        c.last_sent = learned.last_sent;
        c.last_received = learned.last_received;
        c.last_authenticated = learned.last_authenticated;
        c.last_consent = learned.last_consent;
        // The candidate keeps the identity its pairs are known by: the statistics of a pair
        // (and its packet counters) are keyed by the two candidates' ids, and a pair that is
        // carrying data must not become another pair because its remote candidate was
        // signalled after all.
        c.id = learned.id.clone();
        if c.tcp_type() == TcpType::Unspecified {
            c.tcp_type = learned.tcp_type();
        }
        let priority = c.priority();
        self.remote_candidates[remote_index] = c;
        for index in 0..self.candidate_pairs.len() {
            if self.candidate_pairs[index].remote_index == remote_index {
                let local_index = self.candidate_pairs[index].local_index;
                let foundation = self.pair_foundation(local_index, remote_index);
                let p = &mut self.candidate_pairs[index];
                p.remote_priority = priority;
                p.foundation = foundation;
            }
        }
        for local_index in 0..self.local_candidates.len() {
            if !self.local_candidates[local_index].unconveyed
                && self.local_candidates[local_index]
                    .can_pair_with(&self.remote_candidates[remote_index])
            {
                self.add_pair(local_index, remote_index);
            }
        }
        self.request_connectivity_check();
    }

    /// Takes what the mDNS connection has to report: the remote candidates whose names
    /// resolved (returned), the queries that ended without an address, and the local names
    /// lost to another host, which are replaced.
    pub(crate) fn drain_mdns_events(&mut self, now: Instant) -> Vec<Candidate> {
        use mdns::MdnsEvent;

        let mut resolved = vec![];
        let mut lost = vec![];
        if let Some(mdns_conn) = &mut self.mdns {
            while let Some(event) = mdns_conn.poll_event() {
                match event {
                    MdnsEvent::QueryAnswered(id, addr) => {
                        if let Some(mut c) = self.mdns_queries.remove(&id)
                            && c.set_ip(&addr).is_ok()
                        {
                            debug!(
                                "mDNS query id {} answered Candidate {} with resolved_addr {} is added into remote candidates",
                                id,
                                c,
                                c.addr()
                            );
                            resolved.push(c);
                        }
                    }
                    MdnsEvent::QueryTimeout(id) => {
                        if let Some(c) = self.mdns_queries.remove(&id) {
                            error!("mDNS Query {} timed out for {}", id, c.address());
                        }
                    }
                    MdnsEvent::LocalNameConflict(name) => lost.push(name),
                    _ => {}
                }
            }
        }
        for name in lost {
            self.replace_local_mdns_name(now, &name);
        }
        resolved
    }

    /// RFC 6762 Section 9: a host that loses a name to another "MUST [...] choose a new
    /// name". The local candidates published under `lost` get a new `<uuid>.local` name,
    /// registered with the responder, and are reported with
    /// [`Event::LocalCandidateRenamed`] so that they are conveyed to the peer again: the
    /// name it holds resolves to the other host, or to nothing.
    fn replace_local_mdns_name(&mut self, now: Instant, lost: &str) {
        let ip = if self.mdns_local_name == lost {
            self.mdns_local_ip
        } else {
            self.mdns_local_names
                .iter()
                .find(|(_, name)| name == lost)
                .map(|(ip, _)| *ip)
        };
        let (Some(ip), Some(mdns_conn)) = (ip, &mut self.mdns) else {
            return;
        };
        let name = generate_multicast_dns_name();
        if !mdns_conn.add_local_name(&name, ip) {
            warn!(
                "[{}]: the mDNS name {} was lost to another host and no new one could be registered",
                self.get_name(),
                lost
            );
            return;
        }
        warn!(
            "[{}]: the mDNS name {} was lost to another host: its candidates are now {}",
            self.get_name(),
            lost,
            name
        );
        if self.mdns_local_name == lost {
            self.mdns_local_name = name.clone();
        }
        for (_, published) in &mut self.mdns_local_names {
            if published == lost {
                *published = name.clone();
            }
        }
        for c in &mut self.local_candidates {
            if c.address == lost {
                c.address = name.clone();
                self.event_outs.push_back(TaggedEvent {
                    now,
                    event: Event::LocalCandidateRenamed(Box::new(c.clone())),
                });
            }
        }
    }

    /// The remote mDNS candidates whose names have not resolved yet. They are held by no
    /// pair, but they were submitted: statistics list them (mDNS draft Section 3.3.1).
    pub fn pending_mdns_candidates(&self) -> impl Iterator<Item = &Candidate> {
        self.mdns_queries.values()
    }

    /// The peer has no more candidates for this generation (an end-of-candidates indication,
    /// RFC 8838 Section 14). Remote candidates signalled after it are ignored, and a checking
    /// agent whose pairs have all failed fails without waiting for its timeout, once local
    /// gathering is complete too. An ICE restart starts a new generation.
    pub fn set_remote_end_of_candidates(&mut self) {
        self.remote_end_of_candidates = true;
        self.request_connectivity_check();
    }

    /// Local gathering is complete for this generation (RFC 8838 Section 13): no local
    /// candidate is accepted after it. An ICE restart starts a new generation.
    pub fn set_local_gathering_complete(&mut self) {
        self.local_gathering_complete = true;
        self.request_connectivity_check();
    }

    /// Whether this IP address is one the peer's signalling led to: the address of a candidate
    /// it signalled, or the address a `.local` name it signalled has been resolved to. A
    /// peer-reflexive remote candidate's address may be shown in statistics only then
    /// (draft-ietf-mmusic-mdns-ice-candidates Section 3.3.1: "a peer-reflexive remote
    /// candidate could be constructed from a remote host IP address as a result of an ICE
    /// connectivity check"; before the peer's name resolves, such a candidate would reveal
    /// what the name hides). Once the agent has resolved the name itself, the address is no
    /// news; the mDNS candidate's own entry still shows the name, never the address.
    pub fn is_signalled_remote_ip(&self, ip: IpAddr) -> bool {
        self.remote_candidates
            .iter()
            .any(|c| c.candidate_type() != CandidateType::PeerReflexive && c.addr().ip() == ip)
    }

    /// The local candidates to signal to the peer: the ones the application added (with their
    /// 1:1 NAT companions), not the peer-reflexive ones the agent learned from the mapped
    /// address of a response (RFC 8445 Section 7.2.5.3.1), which need no signalling.
    pub fn get_local_candidates_to_signal(&self) -> Vec<Candidate> {
        self.local_candidates
            .iter()
            .filter(|c| c.candidate_type() != CandidateType::PeerReflexive)
            .cloned()
            .collect()
    }

    /// Sets the credentials of the remote agent.
    pub fn set_remote_credentials(
        &mut self,
        remote_ufrag: String,
        remote_pwd: String,
    ) -> Result<()> {
        if remote_ufrag.is_empty() {
            return Err(Error::ErrRemoteUfragEmpty);
        } else if remote_pwd.is_empty() {
            return Err(Error::ErrRemotePwdEmpty);
        }

        self.ufrag_pwd.remote_credentials = Some(Credentials {
            ufrag: remote_ufrag,
            pwd: remote_pwd,
        });

        // Checks can start: the pairs formed so far get their initial states (RFC 8445
        // Section 6.1.2.6).
        self.compute_initial_pair_states();

        // Requests answered before these credentials were known are processed on the next
        // `handle_timeout` (RFC 8445 Section 7.3), which is asked for at once.
        self.request_connectivity_check();

        Ok(())
    }

    /// Returns the remote credentials.
    pub fn get_remote_credentials(&self) -> Option<&Credentials> {
        self.ufrag_pwd.remote_credentials.as_ref()
    }

    /// Returns the local credentials.
    /// The credentials to advertise, which is what SDP generation wants.
    ///
    /// Returns credentials staged by [`Agent::generate_restart_credentials`] when an ICE restart
    /// is pending, so an offer carries the new ufrag/pwd. Inbound STUN validation deliberately
    /// does *not* go through here — it reads `local_credentials` directly, so the live session
    /// keeps working until [`Agent::apply_restart`] installs the new pair.
    pub fn get_local_credentials(&self) -> &Credentials {
        self.ufrag_pwd
            .pending_local_credentials
            .as_ref()
            .unwrap_or(&self.ufrag_pwd.local_credentials)
    }

    /// Queues `CandidatePairRemoved` for every listed pair, before the list is cleared.
    pub(crate) fn announce_all_pairs_removed(&mut self) {
        for index in 0..self.candidate_pairs.len() {
            self.announce_pair(index, false);
        }
    }

    /// The candidate pairs on the agent's list (webrtc-extensions 7 `[[CandidatePairs]]`):
    /// (local, remote), in the order they were formed. A pair the application removed is not
    /// listed.
    pub fn get_candidate_pairs(&self) -> Vec<(Candidate, Candidate)> {
        self.candidate_pairs
            .iter()
            .filter(|p| !p.removed)
            .filter_map(|p| {
                Some((
                    self.local_candidates.get(p.local_index)?.clone(),
                    self.remote_candidates.get(p.remote_index)?.clone(),
                ))
            })
            .collect()
    }

    fn listed_pair(&self, local: &Candidate, remote: &Candidate) -> Option<usize> {
        self.candidate_pairs.iter().position(|p| {
            !p.removed
                && self
                    .local_candidates
                    .get(p.local_index)
                    .is_some_and(|c| c.equal(local))
                && self
                    .remote_candidates
                    .get(p.remote_index)
                    .is_some_and(|c| c.equal(remote))
        })
    }

    /// The InvalidStateError checks of `selectCandidatePair` / `removeCandidatePair`: the
    /// agent is closed, or its state is new or failed.
    fn check_pair_call_state(&self) -> Result<()> {
        if matches!(
            self.connection_state,
            ConnectionState::New | ConnectionState::Failed | ConnectionState::Closed
        ) {
            return Err(Error::InvalidStateError);
        }
        Ok(())
    }

    /// Whether a nomination proposal waits for [`Self::resolve_nomination_proposal`]
    /// (webrtc-extensions 7 `[[ProposalPending]]`).
    pub fn proposal_pending(&self) -> bool {
        self.nomination_proposal.is_some()
    }

    /// Answers the pending nomination proposal: `accept` nominates the pair (a check with
    /// USE-CANDIDATE); otherwise the pair is not nominated and the agent keeps checking
    /// (webrtc-extensions 7, a cancelled `icecandidatepairnominate`). Nothing when no
    /// proposal is pending.
    pub fn resolve_nomination_proposal(&mut self, now: Instant, accept: bool) {
        let Some(pair_index) = self.nomination_proposal.take() else {
            return;
        };
        if accept && self.selected_pair.is_none() && self.nominated_pair.is_none() {
            self.candidate_pairs[pair_index].nominate = true;
            self.nominated_pair = Some(pair_index);
            self.enqueue_triggered(pair_index);
        } else if !accept {
            self.declined_nominations.push(pair_index);
        }
        let _ = now;
    }

    /// webrtc-extensions 7 `selectCandidatePair(pair)`: the agent sends data on the pair of
    /// `local` and `remote` from now on; the selected pair changes, with its
    /// `SelectedCandidatePairChange` event, and the state with its event when it was not
    /// connected. Connectivity checks on other pairs stop, as they do once a pair is
    /// selected; consent keeps being checked on this one.
    ///
    /// # Errors
    ///
    /// `InvalidStateError` when the agent is closed, or new or failed; `NotFoundError` when
    /// the pair is not on the list ([`Self::get_candidate_pairs`]).
    pub fn select_candidate_pair(
        &mut self,
        now: Instant,
        local: &Candidate,
        remote: &Candidate,
    ) -> Result<()> {
        self.check_pair_call_state()?;
        let index = self
            .listed_pair(local, remote)
            .ok_or(Error::NotFoundError)?;
        self.clock = self.clock.max(now);
        if self.selected_pair != Some(index) {
            self.nominated_pair = Some(index);
            self.set_selected_pair(Some(now), Some(index));
        }
        Ok(())
    }

    /// webrtc-extensions 7 `removeCandidatePair(pair)`: the agent stops the checks on the
    /// pair of `local` and `remote` (an In-Progress transaction is cancelled, no check is
    /// sent or answered on it any more, data from it is not accepted through it), then
    /// queues `CandidatePairRemoved`. When it was the selected pair the best other valid pair
    /// takes its place, or none: the state then follows consent as for a lost path.
    ///
    /// # Errors
    ///
    /// As [`Self::select_candidate_pair`].
    pub fn remove_candidate_pair(
        &mut self,
        now: Instant,
        local: &Candidate,
        remote: &Candidate,
    ) -> Result<()> {
        self.check_pair_call_state()?;
        let index = self
            .listed_pair(local, remote)
            .ok_or(Error::NotFoundError)?;
        self.clock = self.clock.max(now);
        let pair = self.candidate_pairs[index];
        self.cancel_pair_checks(pair.local_index, pair.remote_index);
        {
            let p = &mut self.candidate_pairs[index];
            p.state = CandidatePairState::Failed;
            p.valid = false;
            p.nominate = false;
            p.triggered = false;
            p.nomination_pending = false;
        }
        self.announce_pair(index, false);
        self.candidate_pairs[index].removed = true;
        if self.nominated_pair == Some(index) {
            self.nominated_pair = None;
        }
        if self.selected_pair == Some(index) {
            let next = self
                .candidate_pairs
                .iter()
                .enumerate()
                .filter(|(_, p)| p.valid && !p.removed && p.state == CandidatePairState::Succeeded)
                .max_by_key(|(_, p)| p.priority())
                .map(|(i, _)| i);
            match next {
                Some(next) => {
                    self.nominated_pair = Some(next);
                    self.set_selected_pair(Some(now), Some(next));
                }
                None => {
                    self.selected_pair = None;
                    self.request_connectivity_check();
                }
            }
        }
        Ok(())
    }

    /// Whether this agent is the controlling one, which decides nomination.
    pub fn role(&self) -> bool {
        self.is_controlling
    }

    /// Sets the role, when the roles are determined (RFC 8445 Section 6.1.1): the agent that
    /// started the ICE processing is controlling, unless exactly one of the two is lite (the
    /// full one is controlling then).
    ///
    /// "Once the roles are determined for a session, they persist throughout the lifetime of
    /// the session": an ICE restart keeps them (the agent does, by itself), and they are
    /// determined again at a restart only when an agent changed between full and lite. A role
    /// conflict is repaired by the agent (Section 7.3.1.1).
    ///
    /// The pairs the agent holds get the priority of the new role (Section 6.1.2.3), and a
    /// nomination that was being made is dropped: only the controlling agent nominates.
    pub fn set_role(&mut self, is_controlling: bool) {
        if self.is_controlling == is_controlling {
            return;
        }
        self.is_controlling = is_controlling;
        for pair in &mut self.candidate_pairs {
            pair.ice_role_controlling = is_controlling;
            pair.nominate = false;
        }
        self.nominated_pair = None;
        self.nomination_proposal = None;
        self.declined_nominations.clear();
    }

    /// The tiebreaker the agent's checks carry (RFC 8445 Section 5.2).
    pub fn tie_breaker(&self) -> u64 {
        self.tie_breaker
    }

    /// Whether this agent is a lite implementation.
    pub fn is_lite(&self) -> bool {
        self.lite
    }

    /// Tells the agent whether the peer is a lite implementation (in SDP, `a=ice-lite`).
    ///
    /// It matters to a lite agent: with a full peer it answers checks and waits for the
    /// nomination; with a lite peer "no connectivity checks are ever sent. Rather, once the
    /// candidates are exchanged, each agent performs the processing described in Section 8
    /// without connectivity checks" (RFC 8445 Section 6.1.1). See
    /// [`Event::LiteCandidateUpdate`] and [`Agent::replace_remote_candidates`].
    pub fn set_remote_lite(&mut self, lite: bool) {
        self.remote_lite = lite;
        self.request_connectivity_check();
    }

    /// Ta, the pacing of connectivity checks in use (RFC 8445 Section 14.2).
    pub fn pacing(&self) -> Duration {
        self.ta
    }

    /// The Ta this agent proposes to its peer, when it is not the default of 50 ms: "If an
    /// agent wants to use a Ta value other than the default value, the agent MUST indicate the
    /// proposed value to its peer during the establishment of the ICE session" (RFC 8445
    /// Section 14.2; in SDP, `a=ice-pacing`, RFC 8839 Section 5.5, in milliseconds).
    pub fn proposed_pacing(&self) -> Option<Duration> {
        self.configured_ta
            .map(|ta| ta.max(MIN_TA))
            .filter(|ta| *ta != DEFAULT_TA)
    }

    /// The peer's proposal for Ta (`None`: it proposed nothing, which is the default, 50 ms).
    /// "Both agents MUST use the higher out of the two proposed values" (RFC 8445 Section
    /// 14.2): from now on Ta is the larger of this agent's own and the peer's.
    ///
    /// Until this is called the agent paces by its own configuration alone: it cannot know
    /// that the peer was told. An application that configures a Ta under 50 ms and never
    /// calls this is pacing faster than the peer agreed to.
    pub fn set_remote_pacing(&mut self, proposed: Option<Duration>) {
        let own = self.configured_ta.unwrap_or(DEFAULT_TA);
        self.ta = own.max(proposed.unwrap_or(DEFAULT_TA)).max(MIN_TA);
    }

    /// Two lite agents: replaces the remote candidates with those of an updated candidate
    /// exchange (RFC 8445 Section 8.2: "the controlling agent MUST send an updated candidate
    /// list to reconcile different agents selecting different candidate pairs. ICE processing
    /// is complete after and only after the updated candidate exchange is complete"), and
    /// selects again. Returns `false`, and changes nothing, unless both agents are lite.
    pub fn replace_remote_candidates(&mut self, now: Instant, candidates: Vec<Candidate>) -> bool {
        if !(self.lite && self.remote_lite) {
            return false;
        }
        self.set_selected_pair(Some(now), None);
        self.announce_all_pairs_removed();
        self.candidate_pairs = Vec::new();
        self.nominated_pair = None;
        self.nomination_proposal = None;
        self.declined_nominations.clear();
        self.triggered_queue.clear();
        self.remote_candidates.clear();
        self.remote_end_of_candidates = false;
        self.trigger_request_connectivity_check(candidates);
        self.request_connectivity_check();
        true
    }

    /// Replaces the candidate types the agent accepts as local candidates from now on
    /// (`AgentConfig::candidate_types`; empty means the default set).
    ///
    /// Candidates already added stay: a new ICE transport policy takes effect at the next
    /// gathering (RFC 9429, Section 4.1.18). A lite agent keeps host candidates only.
    pub fn set_candidate_types(&mut self, candidate_types: Vec<CandidateType>) {
        if self.lite {
            return;
        }
        self.candidate_types = if candidate_types.is_empty() {
            default_candidate_types()
        } else {
            candidate_types
        };
    }

    /// The agent's current connection state.
    pub fn state(&self) -> ConnectionState {
        self.connection_state
    }

    /// Whether a non-STUN datagram on `transport` should be accepted as media.
    ///
    /// Guards against accepting media from an address that has not passed a connectivity check.
    pub fn is_valid_non_stun_traffic(&mut self, now: Instant, transport: TransportContext) -> bool {
        self.find_local_candidate(transport.local_addr, transport.transport_protocol)
            .is_some()
            && self.validate_non_stun_traffic(now, transport.peer_addr)
    }

    fn get_timeout_interval(&self) -> Duration {
        let (check_interval, keepalive_interval, disconnected_timeout, failed_timeout) = (
            self.check_interval,
            self.keepalive_interval,
            self.disconnected_timeout,
            self.failed_timeout,
        );
        let mut interval = DEFAULT_CHECK_INTERVAL;

        let mut update_interval = |x: Duration| {
            if x != ZERO_DURATION && (interval == ZERO_DURATION || interval > x) {
                interval = x;
            }
        };

        match self.last_connection_state {
            ConnectionState::New | ConnectionState::Checking => {
                // While connecting, check candidates more frequently
                update_interval(check_interval);
            }
            ConnectionState::Connected | ConnectionState::Disconnected => {
                update_interval(keepalive_interval);
            }
            _ => {}
        };
        // Ensure we run our task loop as quickly as the minimum of our various configured timeouts
        update_interval(disconnected_timeout);
        update_interval(failed_timeout);
        interval
    }

    /// The path data (DTLS, SRTP) is sent on and accepted from: the selected pair's, and
    /// during an ICE restart, until the restart selects a pair, the one the session had when
    /// the restart was applied.
    ///
    /// RFC 8445 Section 9: "the ICE agent continues to use the previously selected candidate
    /// pair until a new pair is selected by the restart". Without it every packet between
    /// `apply_restart` and the first nomination of the new generation was dropped, on both
    /// sides, for as long as the offer/answer exchange took.
    ///
    /// With [`AgentConfig::send_data_before_nomination`], and before the first pair is
    /// selected, it is the best valid pair's (Section 12.1: "An ICE agent MAY send data on any
    /// valid pair before selected pairs have been produced for the data stream").
    pub fn media_path(&self) -> Option<MediaPath> {
        self.selected_media_path()
            .or(self.previous_media_path)
            .or_else(|| self.valid_media_path())
    }

    /// The best valid pair's path, when data may be sent before a pair is selected. A lite
    /// agent has no valid pair before a nomination (Section 12.1.1).
    fn valid_media_path(&self) -> Option<MediaPath> {
        if !self.send_data_before_nomination {
            return None;
        }
        let pair = &self.candidate_pairs[self.get_best_valid_candidate_pair()?];
        Some(self.path_of(pair.local_index, pair.remote_index))
    }

    fn path_of(&self, local_index: usize, remote_index: usize) -> MediaPath {
        let local = &self.local_candidates[local_index];
        MediaPath {
            local_addr: local.base_addr(),
            peer_addr: self.remote_candidates[remote_index].addr(),
            transport_protocol: local.network_type().to_protocol(),
        }
    }

    /// Whether data (anything that is not STUN: DTLS, SRTP) that arrived on `transport` is
    /// accepted.
    ///
    /// RFC 8445 Section 12.2: "ICE implementations SHOULD by default be prepared to receive
    /// data on any of the candidates provided in the most recent candidate exchange with the
    /// peer", and "an agent will be able to determine that a data stream is from the same peer
    /// as a consequence of the STUN exchange that proceeds media data transmission". So, once
    /// there is a path to send on ([`Agent::media_path`]), data is accepted on any local
    /// candidate, from that path's remote address and from the remote candidate of any valid
    /// pair: an address one of the agent's own checks was answered from, by someone who holds
    /// the peer's password. A source that only sent requests, or that no check reached, is
    /// not accepted.
    ///
    /// With [`AgentConfig::data_from_selected_pair_only`] only the remote address of the path
    /// data is sent on is accepted.
    pub fn accepts_data(&self, transport: TransportContext) -> bool {
        self.data_path(transport).is_some()
    }

    /// As [`Agent::accepts_data`], saying which pair the data arrived on: the one in use, or
    /// another valid pair (its local and remote candidates).
    pub fn data_path(&self, transport: TransportContext) -> Option<DataPath<'_>> {
        let path = self.media_path()?;
        if self.data_from_selected_pair_only {
            // (The hardening compares the source only, as it always did.)
            return (transport.peer_addr == path.peer_addr).then_some(DataPath::InUse);
        }
        if transport.peer_addr == path.peer_addr
            && transport.local_addr == path.local_addr
            && transport.transport_protocol == path.transport_protocol
        {
            return Some(DataPath::InUse);
        }
        // "On any of the candidates provided": the datagram arrived on one of them.
        self.find_local_candidate(transport.local_addr, transport.transport_protocol)?;
        let valid = |p: &&CandidatePair| {
            p.valid
                && p.state == CandidatePairState::Succeeded
                && self.remote_candidates[p.remote_index].addr() == transport.peer_addr
                && self.local_candidates[p.local_index]
                    .network_type()
                    .to_protocol()
                    == transport.transport_protocol
        };
        // The valid pair it arrived on, when there is one for this local candidate too.
        let exact = self
            .candidate_pairs
            .iter()
            .filter(valid)
            .find(|p| self.local_candidates[p.local_index].base_addr() == transport.local_addr);
        if let Some(p) = exact.or_else(|| self.candidate_pairs.iter().find(valid)) {
            return Some(DataPath::Valid(
                &self.local_candidates[p.local_index],
                &self.remote_candidates[p.remote_index],
            ));
        }
        // From the remote address of the path in use, on another local candidate.
        (transport.peer_addr == path.peer_addr
            && transport.transport_protocol == path.transport_protocol)
            .then_some(DataPath::InUse)
    }

    fn selected_media_path(&self) -> Option<MediaPath> {
        self.get_selected_candidate_pair()
            .map(|(local, remote)| MediaPath {
                // The local candidate's base: for a (server/peer-)reflexive candidate the
                // candidate address is the NAT mapping, not a bound local socket
                // (RFC 8445 Section 5.1.1).
                local_addr: local.base_addr(),
                peer_addr: remote.addr(),
                transport_protocol: local.network_type().to_protocol(),
            })
    }

    /// Returns the selected pair (local_candidate, remote_candidate) or none
    pub fn get_selected_candidate_pair(&self) -> Option<(&Candidate, &Candidate)> {
        if let Some(pair_index) = self.get_selected_pair() {
            let candidate_pair = &self.candidate_pairs[pair_index];
            Some((
                &self.local_candidates[candidate_pair.local_index],
                &self.remote_candidates[candidate_pair.remote_index],
            ))
        } else {
            None
        }
    }

    /// The highest-priority pair that is still usable, whether or not it has been nominated.
    pub fn get_best_available_candidate_pair(&self) -> Option<(&Candidate, &Candidate)> {
        if let Some(pair_index) = self.get_best_available_pair() {
            let candidate_pair = &self.candidate_pairs[pair_index];
            Some((
                &self.local_candidates[candidate_pair.local_index],
                &self.remote_candidates[candidate_pair.remote_index],
            ))
        } else {
            None
        }
    }

    /// start connectivity checks
    pub fn start_connectivity_checks(
        &mut self,
        now: Instant,
        is_controlling: bool,
        remote_ufrag: String,
        remote_pwd: String,
    ) -> Result<()> {
        debug!(
            "Started agent: isControlling? {}, remoteUfrag: {}, remotePwd: {}",
            is_controlling, remote_ufrag, remote_pwd
        );
        self.set_remote_credentials(remote_ufrag, remote_pwd)?;
        self.is_controlling = is_controlling;
        self.start(now);

        self.update_connection_state(Some(now), ConnectionState::Checking);
        self.request_connectivity_check();

        Ok(())
    }

    /// Restarts the ICE Agent with the provided ufrag/pwd
    /// If no ufrag/pwd is provided the Agent will generate one itself.
    /// Stages new local credentials for an ICE restart, without disturbing the live session.
    ///
    /// This is the half of an ICE restart that an offerer needs *before* generating SDP: the offer
    /// must carry the new ufrag/pwd. It deliberately does not touch `local_credentials`,
    /// candidate pairs, or connection state, because JSEP requires `createOffer` to be free of
    /// side effects — and because inbound STUN is still being validated against the current
    /// credentials until the local description is applied.
    ///
    /// Empty `ufrag` / `pwd` are filled from the crypto provider's RNG. Call
    /// [`Agent::apply_restart`] to install them.
    pub fn generate_restart_credentials(
        &mut self,
        mut ufrag: String,
        mut pwd: String,
    ) -> Result<()> {
        if ufrag.is_empty() {
            ufrag = generate_ufrag_with_random(self.crypto_provider.random())?;
        }
        if pwd.is_empty() {
            pwd = generate_pwd_with_random(self.crypto_provider.random())?;
        }

        // RFC 8445 Section 9: an ICE restart changes both the fragment and the password. An
        // application that pins its credentials would otherwise offer the ones in use: the
        // peer sees no restart while this side has flushed its pairs. The pinned pair then
        // names the first generation only.
        let current = &self.ufrag_pwd.local_credentials;
        if !current.ufrag.is_empty() && (ufrag == current.ufrag || pwd == current.pwd) {
            warn!(
                "[{}]: an ICE restart was given the credentials in use; generating new ones",
                self.get_name()
            );
            ufrag = generate_ufrag_with_random(self.crypto_provider.random())?;
            pwd = generate_pwd_with_random(self.crypto_provider.random())?;
        }

        if ufrag.len() * 8 < 24 {
            return Err(Error::ErrLocalUfragInsufficientBits);
        }
        if pwd.len() * 8 < 128 {
            return Err(Error::ErrLocalPwdInsufficientBits);
        }

        self.ufrag_pwd.pending_local_credentials = Some(Credentials { ufrag, pwd });

        Ok(())
    }

    /// Whether [`Agent::generate_restart_credentials`] has staged a restart that is not yet applied.
    pub fn has_pending_restart(&self) -> bool {
        self.ufrag_pwd.pending_local_credentials.is_some()
    }

    /// Forgets the credentials [`Agent::generate_restart_credentials`] staged, so that no
    /// restart is pending: the description they were staged for was abandoned (a rolled-back
    /// remote offer, RFC 9429 section 5.7). The live session is untouched.
    pub fn discard_restart_credentials(&mut self) {
        self.ufrag_pwd.pending_local_credentials = None;
    }

    /// Applies a staged ICE restart, tearing down the old session and starting a new one at `now`.
    ///
    /// Installs the credentials staged by [`Agent::generate_restart_credentials`], if any, then
    /// discards the remote credentials, pending binding requests, candidate pairs and selected
    /// pair, and restarts the agent's timers. With nothing staged, the current credentials are
    /// kept and only the session is restarted.
    pub fn apply_restart(&mut self, now: Instant, keep_local_candidates: bool) -> Result<()> {
        // A closed agent has shut its mDNS connection and dropped its candidates for good; a
        // restart must not bring it back to `Checking`.
        if self.connection_state == ConnectionState::Closed {
            return Err(Error::ErrClosed);
        }
        // A restart that is not revertible commits an earlier one.
        self.restart_undo = None;
        // Data keeps the path it has until the new generation selects a pair (RFC 8445
        // Section 9), whether or not the local candidates are kept: discarding them forgets
        // what was signalled, not the socket the path's packets leave from. An application
        // that closed that socket (a rebind) drops what is written to it, as before.
        let previous_media_path = self.media_path();
        // Consent goes on being checked on that path (RFC 7675 Section 5.1), with the
        // credentials of the generation that validated it. A second restart before the first
        // one selected a pair keeps what the first one kept.
        let previous_generation = match (self.selected_pair, &self.ufrag_pwd.remote_credentials) {
            (Some(pair_index), Some(remote_credentials)) => {
                let pair = self.candidate_pairs[pair_index];
                let remote = &self.remote_candidates[pair.remote_index];
                let last_consent = if self.lite {
                    remote.last_authenticated()
                } else {
                    remote.last_consent()
                };
                Some(PreviousGeneration {
                    local_credentials: self.ufrag_pwd.local_credentials.clone(),
                    remote_credentials: remote_credentials.clone(),
                    priority: self.local_candidates[pair.local_index].peer_reflexive_priority(),
                    last_consent: last_consent.unwrap_or(now),
                    next_consent_at: self
                        .next_consent_at
                        .unwrap_or_else(|| now + self.next_consent_interval()),
                    pending: vec![],
                })
            }
            _ => self.previous_generation.take(),
        };

        if let Some(credentials) = self.ufrag_pwd.pending_local_credentials.take() {
            self.ufrag_pwd.local_credentials = credentials;
        }
        self.ufrag_pwd.remote_credentials = None;

        self.pending_binding_requests = vec![];
        self.early_requests = vec![];
        self.triggered_queue.clear();
        // A new generation: its candidates and its end-of-candidates are still to come.
        self.lite_update_raised = false;
        self.remote_end_of_candidates = false;
        self.local_gathering_complete = false;

        self.announce_all_pairs_removed();
        self.candidate_pairs = Vec::new();

        self.set_selected_pair(Some(now), None);
        self.delete_all_candidates(keep_local_candidates);
        self.previous_media_path = previous_media_path;
        self.previous_generation = previous_media_path.and(previous_generation);
        self.start(now);

        // Restart is used by NewAgent. Accept/Connect should be used to move to checking
        // for new Agents. W3C webrtc-pc 5.6.4: "An ICE restart [...] causing a transition to
        // connected if begun in the completed state. If begun in the transient disconnected
        // state, it causes a transition to checking": a connected or completed agent that keeps
        // its path (RFC 8445 Section 9) is connected; a disconnected or failed one, or one
        // without a path, checks.
        let was_connected = matches!(
            self.connection_state,
            ConnectionState::Connected | ConnectionState::Completed
        );
        if was_connected && self.previous_media_path.is_some() {
            self.update_connection_state(Some(now), ConnectionState::Connected);
        } else if self.connection_state != ConnectionState::New {
            self.update_connection_state(Some(now), ConnectionState::Checking);
        }

        Ok(())
    }

    /// Generates and immediately applies an ICE restart.
    ///
    /// Equivalent to [`Agent::generate_restart_credentials`] followed by
    /// [`Agent::apply_restart`]. A JSEP-conformant offerer wants the two halves separately —
    /// credentials at `createOffer`, application at `setLocalDescription` — but this remains the
    /// right call for anything that restarts in one step.
    pub fn restart(
        &mut self,
        now: Instant,
        ufrag: String,
        pwd: String,
        keep_local_candidates: bool,
    ) -> Result<()> {
        self.generate_restart_credentials(ufrag, pwd)?;
        self.apply_restart(now, keep_local_candidates)
    }

    /// Returns the local candidates.
    pub fn get_local_candidates(&self) -> &[Candidate] {
        &self.local_candidates
    }

    /// The remote candidates this agent has been given, in the order they were added.
    pub fn get_remote_candidates(&self) -> &[Candidate] {
        &self.remote_candidates
    }

    /// One pass over everything the agent does on its own: retransmissions and timeouts, the
    /// selected pair's consent, nomination, the next check Ta allows, and the checklist's
    /// state.
    fn contact(&mut self, now: Instant) {
        // Consume any pending deferred-check request now that we are running one.
        // Reset before the early returns below so a failed/settled agent does not
        // keep asking `poll_timeout` for an immediate wake-up.
        self.force_candidate_contact = false;

        if matches!(
            self.connection_state,
            ConnectionState::Failed | ConnectionState::Closed
        ) {
            // The connection is currently failed so don't send any checks
            // In the future it may be restarted though
            self.last_connection_state = self.connection_state;
            return;
        }
        if self.connection_state == ConnectionState::Checking {
            // We have just entered checking for the first time so update our checking timer
            if self.last_connection_state != self.connection_state {
                self.checking_duration = now;
            }

            // A nomination the peer has not been heard from for the consent expiry ends: its
            // pair fails, and the next valid pair is nominated.
            self.expire_unanswered_nomination(now);

            // Past `disconnected_timeout + failed_timeout` in checking, the agent fails, but
            // only once nothing is left that may still produce a selected pair (RFC 8445
            // Sections 6.1.4.2 and 8.1.2: the checklist fails when every pair has failed). A
            // pair that is still being checked fails by its own transaction (Section 14.3), a
            // nomination by `expire_unanswered_nomination`.
            if self.failed_timeout != ZERO_DURATION
                && now
                    .checked_duration_since(self.checking_duration)
                    .unwrap_or_else(|| Duration::from_secs(0))
                    > self.disconnected_timeout + self.failed_timeout
                && !self.checks_in_progress(now)
            {
                self.update_connection_state(Some(now), ConnectionState::Failed);
                self.last_connection_state = self.connection_state;
                return;
            }
        }

        self.run_transactions(now);

        // Two lite agents: no checks, the pair comes from the candidate exchange (Section 8.2).
        if self.lite && self.remote_lite {
            self.conclude_lite_to_lite(now);
        }

        if self.selected_pair.is_some() && self.validate_selected_pair(now) {
            if self.lite && (!self.is_controlling || self.remote_lite) {
                self.lite_keepalive(now);
            } else {
                self.check_keepalive(now);
            }
        }

        if !matches!(
            self.connection_state,
            ConnectionState::Failed | ConnectionState::Closed
        ) {
            self.maybe_nominate(now);
            self.run_ta(now);
            self.update_checklist_failure(now);
        }

        self.last_connection_state = self.connection_state;
        self.last_checking_time = now;
    }

    /// When `contact` next has something to do. `None` when the agent has no peer credentials
    /// or is failed or closed.
    pub(crate) fn ice_deadline(&self) -> Option<Instant> {
        if self.ufrag_pwd.remote_credentials.is_none()
            || matches!(
                self.connection_state,
                ConnectionState::Failed | ConnectionState::Closed
            )
        {
            return None;
        }
        if self.force_candidate_contact {
            // A check or a look at the state was requested: as soon as possible.
            // `last_checking_time` is in the past, so the resulting deadline is immediate.
            return Some(self.last_checking_time);
        }
        let mut deadline: Option<Instant> = None;
        let mut by = |at: Instant| deadline = Some(deadline.map_or(at, |d| d.min(at)));
        // A retransmission, or a transaction that ends.
        for request in &self.pending_binding_requests {
            by(request.next_event);
        }
        // Connected: the next consent request, or the moment its silence counts.
        if let Some(at) = self.selected_pair_deadline() {
            by(at);
        }
        // Connecting (and a lite agent always): a periodic look at the state.
        if self.selected_pair.is_none() || self.lite {
            by(self.last_checking_time + self.get_timeout_interval());
        }
        // The next check, when Ta allows it.
        if self.has_check_to_start() {
            by(self.next_check_at);
        }
        deadline
    }

    pub(crate) fn update_connection_state(
        &mut self,
        now: Option<Instant>,
        new_state: ConnectionState,
    ) {
        if self.connection_state != new_state {
            // Connection has gone to failed, release all gathered candidates
            if new_state == ConnectionState::Failed {
                self.set_selected_pair(now, None);
                self.delete_all_candidates(false);
            }
            // A failed or closed agent has no path, a restart's previous one included, and no
            // open transactions (RFC 7675 Section 5.1: "All outstanding STUN consent
            // transactions for a candidate pair MUST be discarded when consent expires").
            if matches!(new_state, ConnectionState::Failed | ConnectionState::Closed) {
                self.previous_media_path = None;
                self.previous_generation = None;
                self.pending_binding_requests.clear();
                self.triggered_queue.clear();
                self.next_consent_at = None;
                self.consent_unanswered_since = None;
            }

            info!(
                "[{}]: Setting new connection state: {}",
                self.get_name(),
                new_state
            );
            self.connection_state = new_state;
            if let Some(now) = now {
                self.event_outs.push_back(TaggedEvent {
                    now,
                    event: Event::ConnectionStateChange(new_state),
                });
            }
        }
    }

    pub(crate) fn set_selected_pair(&mut self, now: Option<Instant>, selected_pair: Option<usize>) {
        if let Some(pair_index) = selected_pair {
            trace!(
                "[{}]: Set selected candidate pair: {:?}",
                self.get_name(),
                self.candidate_pairs[pair_index]
            );

            self.candidate_pairs[pair_index].nominated = true;
            if self.selected_pair != Some(pair_index) {
                // Consent on the new pair was given by the response that validated it; the
                // first consent check follows one interval later.
                self.next_consent_at = now.map(|now| now + self.next_consent_interval());
                self.consent_unanswered_since = None;
            }
            self.selected_pair = Some(pair_index);
            // The restart (if any) has its pair: the previous generation's path is retired.
            self.previous_media_path = None;
            self.previous_generation = None;

            if !matches!(
                self.connection_state,
                ConnectionState::Connected | ConnectionState::Completed
            ) {
                self.update_connection_state(now, ConnectionState::Connected);
            }

            // Notify when the selected pair changes
            let candidate_pair = &self.candidate_pairs[pair_index];
            if let Some(now) = now {
                self.event_outs.push_back(TaggedEvent {
                    now,
                    event: Event::SelectedCandidatePairChange(
                        Box::new(self.local_candidates[candidate_pair.local_index].clone()),
                        Box::new(self.remote_candidates[candidate_pair.remote_index].clone()),
                    ),
                });
            }
        } else {
            self.selected_pair = None;
            self.next_consent_at = None;
            self.consent_unanswered_since = None;
        }
    }

    /// The state of a connected agent whose consent is fresh: `Completed` once both sides
    /// have said they have no more candidates (W3C `RTCIceTransportState`: "finished
    /// gathering, received an indication that there are no more remote candidates, finished
    /// checking all candidate pairs and found a connection"), `Connected` until then.
    fn healthy_state(&self) -> ConnectionState {
        if self.remote_end_of_candidates && self.local_gathering_complete {
            ConnectionState::Completed
        } else {
            ConnectionState::Connected
        }
    }

    /// One interval between two consent checks: 0.8 to 1.2 times the basic period, drawn from
    /// the crypto provider's RNG, and never under 4 seconds (RFC 7675 Section 5.1: "To prevent
    /// synchronization of consent checks, each interval MUST be randomized from between 0.8
    /// and 1.2 times the basic period. [...] Implementations MUST NOT set the period between
    /// checks to less than 4 seconds").
    pub(crate) fn next_consent_interval(&self) -> Duration {
        let mut bytes = [0_u8; 4];
        // Without randomness the period itself is the interval.
        let r = match self.crypto_provider.random().fill(&mut bytes) {
            Ok(()) => u64::from(u32::from_be_bytes(bytes)),
            Err(_) => u64::from(u32::MAX / 2),
        };
        // 0.8 + 0.4 * r / (2^32 - 1), in millionths.
        let factor = 800_000 + (r * 400_000) / u64::from(u32::MAX);
        let nanos = self.keepalive_interval.as_nanos() * u128::from(factor) / 1_000_000;
        Duration::from_nanos(u64::try_from(nanos).unwrap_or(u64::MAX)).max(MIN_CONSENT_INTERVAL)
    }

    /// How long after the last consent response the agent stops sending: the configured
    /// `disconnected_timeout + failed_timeout`, and 30 seconds at most (RFC 7675 Section 5.1:
    /// "Consent expires after 30 seconds. That is, if a valid STUN binding response has not
    /// been received from the remote peer's transport address in 30 seconds, the endpoint MUST
    /// cease transmission on that 5-tuple"). A `failed_timeout` of zero, which keeps a
    /// checking agent from failing, does not keep consent alive.
    pub(crate) fn consent_expiry(&self) -> Duration {
        if self.failed_timeout == ZERO_DURATION {
            CONSENT_EXPIRY
        } else {
            (self.disconnected_timeout + self.failed_timeout).min(CONSENT_EXPIRY)
        }
    }

    /// Checks if the selected pair is (still) valid.
    /// Re-evaluates the selected pair's liveness as of `now`.
    ///
    /// `now` comes from the caller so that this decision and the keepalive decision below are
    /// made against the same instant as the `contact(now)` that reached them.
    pub(crate) fn validate_selected_pair(&mut self, now: Instant) -> bool {
        let Some(pair_index) = self.selected_pair else {
            return false;
        };
        let remote_index = self.candidate_pairs[pair_index].remote_index;
        let remote = &self.remote_candidates[remote_index];

        if self.lite && self.remote_lite {
            // Two lite agents exchange no Binding requests at all (Section 6.1.1: "no
            // connectivity checks are ever sent"): ICE has no sign of life to judge by.
            self.update_connection_state(Some(now), self.healthy_state());
            return true;
        }

        if self.lite {
            // A lite agent sends no checks (RFC 8445 §2.5), so for it an authenticated request
            // from the peer is the only sign of life, judged by the configured timeouts.
            let last_received = remote.last_authenticated().unwrap_or(self.start_time);
            let disconnected_time = now.saturating_duration_since(last_received);

            // Only allow transitions to fail if a.failedTimeout is non-zero
            let mut total_time_to_failure = self.failed_timeout;
            if total_time_to_failure != ZERO_DURATION {
                total_time_to_failure += self.disconnected_timeout;
            }

            if total_time_to_failure != ZERO_DURATION && disconnected_time > total_time_to_failure {
                self.update_connection_state(Some(now), ConnectionState::Failed);
            } else if self.disconnected_timeout != ZERO_DURATION
                && disconnected_time > self.disconnected_timeout
            {
                self.update_connection_state(Some(now), ConnectionState::Disconnected);
            } else {
                self.update_connection_state(Some(now), self.healthy_state());
            }
            return true;
        }

        // Consent (RFC 7675 §5.1) is refreshed only by an authenticated success response to
        // one of our own checks: not by non-STUN datagrams, not by unauthenticated
        // indications, and not by the peer's own requests, which say the peer is there but not
        // that it still wants our traffic.
        let last_consent = remote.last_consent().unwrap_or(self.start_time);
        let since_consent = now.saturating_duration_since(last_consent);

        // Disconnected: a consent request has gone unanswered for `disconnected_timeout`.
        // (Consent requests are at least 4 seconds apart, so "no response for 5 seconds" alone
        // would be true between two answered requests.) With keepalives off nothing is ever
        // asked, and the time since the last response decides.
        let unanswered = if self.keepalive_interval == ZERO_DURATION {
            since_consent
        } else {
            self.consent_unanswered_since
                .map(|since| now.saturating_duration_since(since))
                .unwrap_or(ZERO_DURATION)
        };

        if since_consent >= self.consent_expiry() {
            self.update_connection_state(Some(now), ConnectionState::Failed);
        } else if self.disconnected_timeout != ZERO_DURATION
            && unanswered >= self.disconnected_timeout
        {
            let was = self.connection_state;
            self.update_connection_state(Some(now), ConnectionState::Disconnected);
            if was != ConnectionState::Disconnected {
                self.fall_back_to_another_nominated_pair(now);
            }
        } else {
            self.update_connection_state(Some(now), self.healthy_state());
        }

        true
    }

    /// Sends a STUN Binding request on the selected pair when the consent interval has run
    /// out (RFC 7675). Each one is a new transaction, sent once.
    pub(crate) fn check_keepalive(&mut self, now: Instant) {
        if self.keepalive_interval == ZERO_DURATION {
            return;
        }
        let Some(pair_index) = self.selected_pair else {
            return;
        };
        match self.next_consent_at {
            None => self.next_consent_at = Some(now + self.next_consent_interval()),
            Some(at) if now >= at => {
                self.next_consent_at = Some(now + self.next_consent_interval());
                self.consent_unanswered_since.get_or_insert(now);
                self.candidate_pairs[pair_index].on_consent_request_sent();
                // A consent check is a plain Binding request (RFC 7675 Section 5.1); RFC 8445
                // Section 7.1.2 asks for USE-CANDIDATE "in order to nominate a candidate
                // pair", which was done. libwebrtc's controlling agent repeats it on every
                // check of its selected pair: `nominate_on_consent_checks`.
                let use_candidate = self.is_controlling && self.nominate_on_consent_checks;
                self.send_check(now, pair_index, use_candidate, true);
            }
            Some(_) => {}
        }
    }

    /// When the agent next has something to do for its selected pair: send a consent request,
    /// notice that one went unanswered, or let consent expire. `None` without a selected pair
    /// and for a lite agent, whose timer is the periodic one.
    pub(crate) fn selected_pair_deadline(&self) -> Option<Instant> {
        let pair_index = self.selected_pair?;
        if self.lite {
            return None;
        }
        let remote = &self.remote_candidates[self.candidate_pairs[pair_index].remote_index];
        let last_consent = remote.last_consent().unwrap_or(self.start_time);

        let mut deadline = last_consent + self.consent_expiry();
        if self.keepalive_interval != ZERO_DURATION {
            // Before the first `handle_timeout` after selection there is no schedule yet.
            deadline = deadline.min(self.next_consent_at.unwrap_or(self.last_checking_time));
        }
        if self.disconnected_timeout != ZERO_DURATION
            && self.connection_state != ConnectionState::Disconnected
        {
            let unanswered_since = if self.keepalive_interval == ZERO_DURATION {
                Some(last_consent)
            } else {
                self.consent_unanswered_since
            };
            if let Some(since) = unanswered_since {
                deadline = deadline.min(since + self.disconnected_timeout);
            }
        }
        Some(deadline)
    }

    /// Consent on the path an ICE restart left in use (RFC 7675 Section 5.1): sends the consent
    /// requests of the replaced generation, and retires the path when its consent expires.
    pub(crate) fn maintain_previous_generation(&mut self, now: Instant) {
        let Some(path) = self.previous_media_path else {
            self.previous_generation = None;
            return;
        };
        let expiry = self.consent_expiry();
        let interval = self.next_consent_interval();
        let (lite, keepalive, controlling, tie_breaker) = (
            self.lite,
            self.keepalive_interval != ZERO_DURATION,
            self.is_controlling,
            self.tie_breaker,
        );
        let Some(previous) = &mut self.previous_generation else {
            return;
        };

        if now.saturating_duration_since(previous.last_consent) >= expiry {
            warn!(
                "consent expired on the path kept across the ICE restart ({} -> {}): no longer sending on it",
                path.local_addr, path.peer_addr
            );
            self.previous_media_path = None;
            self.previous_generation = None;
            // The kept path was what made the agent connected through the restart; without it
            // and with no pair of the new generation selected, the agent is checking.
            if self.selected_pair.is_none() && self.connection_state == ConnectionState::Connected {
                self.update_connection_state(Some(now), ConnectionState::Checking);
            }
            return;
        }

        if lite || !keepalive || now < previous.next_consent_at {
            return;
        }
        previous.next_consent_at = now + interval;

        let username = previous.remote_credentials.ufrag.clone()
            + ":"
            + previous.local_credentials.ufrag.as_str();
        let role: Box<dyn Setter> = if controlling {
            Box::new(crate::attributes::control::AttrControlling(tie_breaker))
        } else {
            Box::new(crate::attributes::control::AttrControlled(tie_breaker))
        };
        let mut msg = Message::new();
        if let Err(err) = msg.build(&[
            Box::new(BINDING_REQUEST),
            Box::new(TransactionId::new()),
            Box::new(Username::new(ATTR_USERNAME, username)),
            role,
            Box::new(crate::attributes::priority::PriorityAttr(previous.priority)),
            Box::new(MessageIntegrity::new_short_term_integrity_with_provider(
                previous.remote_credentials.pwd.clone(),
                self.crypto_provider.crypto(),
            )),
            Box::new(FINGERPRINT),
        ]) {
            error!("{}", err);
            return;
        }
        if previous.pending.len() >= MAX_PREVIOUS_GENERATION_TRANSACTIONS {
            previous.pending.remove(0);
        }
        previous.pending.push(msg.transaction_id);
        self.write_outs.push_back(TaggedBytesMut {
            now,
            transport: TransportContext {
                local_addr: path.local_addr,
                peer_addr: path.peer_addr,
                ecn: None,
                transport_protocol: path.transport_protocol,
            },
            message: BytesMut::from(&msg.raw[..]),
        });
    }

    /// When `maintain_previous_generation` next has something to do.
    pub(crate) fn previous_generation_deadline(&self) -> Option<Instant> {
        let previous = self.previous_generation.as_ref()?;
        self.previous_media_path?;
        let expires = previous.last_consent + self.consent_expiry();
        if self.lite || self.keepalive_interval == ZERO_DURATION {
            Some(expires)
        } else {
            Some(expires.min(previous.next_consent_at))
        }
    }

    /// STUN on the path an ICE restart left in use that belongs to the replaced generation:
    /// the peer's consent requests, which name the old local fragment and are answered with
    /// the old password, and the responses to ours. Returns whether `msg` was one of them.
    pub(crate) fn handle_previous_generation(&mut self, msg: &TaggedBytesMut) -> bool {
        let (Some(path), Some(previous)) = (self.previous_media_path, &self.previous_generation)
        else {
            return false;
        };
        if msg.transport.local_addr != path.local_addr
            || msg.transport.peer_addr != path.peer_addr
            || msg.transport.transport_protocol != path.transport_protocol
            || !is_stun_message(&msg.message)
        {
            return false;
        }
        let mut m = Message {
            raw: msg.message.to_vec(),
            ..Message::default()
        };
        if m.decode().is_err() || m.typ.method != METHOD_BINDING {
            return false;
        }

        if m.typ.class == CLASS_REQUEST {
            if assert_inbound_username(&m, &previous.local_credentials.ufrag).is_err()
                || assert_inbound_message_integrity(
                    &mut m,
                    previous.local_credentials.pwd.as_bytes(),
                    self.crypto_provider.crypto(),
                )
                .is_err()
            {
                return false;
            }
            let mut out = Message::new();
            if let Err(err) = out.build(&[
                Box::new(m.clone()),
                Box::new(BINDING_SUCCESS),
                Box::new(XorMappedAddress {
                    ip: path.peer_addr.ip(),
                    port: path.peer_addr.port(),
                }),
                Box::new(MessageIntegrity::new_short_term_integrity_with_provider(
                    previous.local_credentials.pwd.clone(),
                    self.crypto_provider.crypto(),
                )),
                Box::new(FINGERPRINT),
            ]) {
                error!("{}", err);
                return true;
            }
            self.write_outs.push_back(TaggedBytesMut {
                now: msg.now,
                transport: TransportContext {
                    local_addr: path.local_addr,
                    peer_addr: path.peer_addr,
                    ecn: None,
                    transport_protocol: path.transport_protocol,
                },
                message: BytesMut::from(&out.raw[..]),
            });
            if self.lite
                && let Some(previous) = &mut self.previous_generation
            {
                previous.last_consent = msg.now;
            }
            return true;
        }

        if m.typ.class == CLASS_SUCCESS_RESPONSE || m.typ.class == CLASS_ERROR_RESPONSE {
            let Some(position) = previous
                .pending
                .iter()
                .position(|id| *id == m.transaction_id)
            else {
                return false;
            };
            if assert_inbound_message_integrity(
                &mut m,
                previous.remote_credentials.pwd.as_bytes(),
                self.crypto_provider.crypto(),
            )
            .is_err()
            {
                // Claims to answer our transaction but is not signed by the peer: dropped.
                return true;
            }
            let is_success = m.typ.class == CLASS_SUCCESS_RESPONSE;
            if is_success && !m.contains(stun::attributes::ATTR_XORMAPPED_ADDRESS) {
                // RFC 8489 Section 6.3.3: a Binding success response without
                // XOR-MAPPED-ADDRESS fails the client's checks; discarded, no consent.
                return true;
            }
            if let Some(previous) = &mut self.previous_generation {
                previous.pending.remove(position);
                if is_success {
                    previous.last_consent = msg.now;
                }
            }
            return true;
        }

        false
    }

    pub(crate) fn request_connectivity_check(&mut self) {
        // Defer the connectivity check to `handle_timeout` instead of running it
        // inline. Running `contact()` here is re-entrant: it can advance the state
        // to `Failed`, which calls `delete_all_candidates()` and wipes the candidate
        // and pair vectors while a caller still holds indices into them (for example
        // `handle_inbound` while adding a peer-reflexive candidate). See issue #88.
        self.force_candidate_contact = true;
    }

    /// Remove all candidates.
    /// This closes any listening sockets and removes both the local and remote candidate lists.
    ///
    /// This is used for restarts, failures and on close.
    pub(crate) fn delete_all_candidates(&mut self, keep_local_candidates: bool) {
        if !keep_local_candidates {
            self.local_candidates.clear();
        } else {
            // What the agent learned from the mapped addresses of the old generation's
            // responses goes with that generation.
            self.local_candidates
                .retain(|c| c.candidate_type() != CandidateType::PeerReflexive);
        }
        self.remote_candidates.clear();
        self.triggered_queue.clear();

        // Candidate pairs reference candidates by index, so once the candidates are
        // removed every pair - and the `selected_pair`/`nominated_pair` indices into
        // the pair list - is dangling and must be dropped to avoid out-of-bounds
        // access. `remote_candidates` is always cleared here, so no pair can remain
        // valid even when the local candidates are kept. See issue #88.
        self.announce_all_pairs_removed();
        self.candidate_pairs = Vec::new();
        self.selected_pair = None;
        self.nominated_pair = None;
        self.nomination_proposal = None;
        self.declined_nominations.clear();
    }

    pub(crate) fn find_remote_candidate(&self, addr: SocketAddr) -> Option<usize> {
        for (index, c) in self.remote_candidates.iter().enumerate() {
            if c.addr() == addr {
                return Some(index);
            }
        }
        None
    }

    /// The local candidate a datagram that arrived on `addr` belongs to.
    ///
    /// RFC 8445 Section 7.3.1.4: "The local candidate will be either a host candidate [...] or
    /// a relayed candidate [...]. The local candidate can never be a server-reflexive
    /// candidate." A reflexive candidate is returned only when the application never added
    /// the host candidate that is its base.
    pub(crate) fn find_local_candidate(
        &self,
        addr: SocketAddr,
        transport_protocol: TransportProtocol,
    ) -> Option<usize> {
        // An exact address match wins over the TCP active candidates' IP-only match: a
        // connection accepted on a passive candidate arrives on that candidate's own address,
        // and must not be credited to an active candidate on the same IP that happens to be
        // listed first.
        let mut active_on_ip = None;
        let mut reflexive_on_base = None;
        for (index, c) in self.local_candidates.iter().enumerate() {
            if c.network_type().to_protocol() != transport_protocol {
                continue;
            }
            let reflexive = matches!(
                c.candidate_type(),
                CandidateType::ServerReflexive | CandidateType::PeerReflexive
            );

            // TCP active candidates use port 9 as a placeholder in signalling, but each
            // connection they open has its own ephemeral port: they match by IP alone.
            if c.tcp_type() == TcpType::Active && transport_protocol == TransportProtocol::TCP {
                if active_on_ip.is_none() && !reflexive && c.addr().ip() == addr.ip() {
                    active_on_ip = Some(index);
                }
            } else if reflexive {
                if reflexive_on_base.is_none()
                    && c.candidate_type() == CandidateType::ServerReflexive
                    && c.related_address().is_some_and(|related| {
                        related.address == addr.ip().to_string() && related.port == addr.port()
                    })
                {
                    reflexive_on_base = Some(index);
                }
            } else if c.addr() == addr {
                return Some(index);
            }
        }
        active_on_ip.or(reflexive_on_base)
    }

    /// Answers the Binding request `m`, which arrived on `local_index` from `remote_addr`, with
    /// a success response: XOR-MAPPED-ADDRESS is the request's source (RFC 8445 Section
    /// 7.3.1.2), MESSAGE-INTEGRITY uses the local password, FINGERPRINT closes it.
    pub(crate) fn send_binding_success(
        &mut self,
        now: Instant,
        m: &Message,
        local_index: usize,
        remote_addr: SocketAddr,
    ) {
        let (ip, port) = (remote_addr.ip(), remote_addr.port());

        let (out, result) = {
            let mut out = Message::new();
            let result = self.answer_integrity_setter().and_then(|integrity| {
                let mut setters: Vec<Box<dyn Setter + '_>> = vec![
                    Box::new(m.clone()),
                    Box::new(BINDING_SUCCESS),
                    Box::new(XorMappedAddress { ip, port }),
                ];
                // RFC 8489 Section 6.3.1.1: a success response SHOULD carry SOFTWARE.
                if let Some(software) = &self.software {
                    setters.push(Box::new(Software::new(ATTR_SOFTWARE, software.clone())));
                }
                setters.push(integrity);
                setters.push(Box::new(FINGERPRINT));
                out.build(&setters)
            });
            (out, result)
        };

        if let Err(err) = result {
            warn!(
                "[{}]: Failed to handle inbound ICE from: {} to: {} error: {}",
                self.get_name(),
                self.local_candidates[local_index],
                remote_addr,
                err
            );
        } else {
            // Track response sent on the candidate pair
            if let Some(remote_index) = self.find_remote_candidate(remote_addr)
                && let Some(pair_index) = self.find_pair(local_index, remote_index)
            {
                self.candidate_pairs[pair_index].on_response_sent();
            }
            self.send_stun_to(now, &out, local_index, remote_addr);
        }
    }

    /// The integrity attribute of a response to the request being answered, with the local
    /// password: MESSAGE-INTEGRITY-SHA256 when the request was authenticated by one, else
    /// MESSAGE-INTEGRITY (RFC 8489 Section 9.1.3: "A response to a request that contains
    /// a MESSAGE-INTEGRITY-SHA256 attribute MUST include the MESSAGE-INTEGRITY-SHA256
    /// attribute [...] only one of these attributes can appear in a response").
    fn answer_integrity_setter(&self) -> Result<Box<dyn Setter + '_>> {
        let local_pwd = self.ufrag_pwd.local_credentials.pwd.clone();
        let crypto = self.crypto_provider.crypto();
        Ok(match self.answer_integrity {
            IntegrityAlgorithm::Sha1 => Box::new(
                MessageIntegrity::new_short_term_integrity_with_provider(local_pwd, crypto),
            ),
            IntegrityAlgorithm::Sha256 => {
                Box::new(MessageIntegritySha256::short_term(&local_pwd, crypto)?)
            }
        })
    }

    /// Sends a 487 (Role Conflict) error response.
    /// RFC 8445 Section 7.3.1.1
    pub(crate) fn send_role_conflict_error(
        &mut self,
        now: Instant,
        m: &Message,
        local_index: usize,
        remote_addr: SocketAddr,
    ) {
        use stun::error_code::*;

        let (out, result) = {
            let mut out = Message::new();
            let result = self.answer_integrity_setter().and_then(|integrity| {
                out.build(&[
                    Box::new(m.clone()),
                    Box::new(stun::message::BINDING_ERROR),
                    Box::new(CODE_ROLE_CONFLICT),
                    integrity,
                    Box::new(FINGERPRINT),
                ])
            });
            (out, result)
        };

        if let Err(err) = result {
            warn!(
                "[{}]: Failed to send role conflict error from: {} to: {} error: {}",
                self.get_name(),
                self.local_candidates[local_index],
                remote_addr,
                err
            );
        } else {
            debug!(
                "[{}]: Sent 487 Role Conflict error from {} to {}",
                self.get_name(),
                self.local_candidates[local_index],
                remote_addr
            );
            self.send_stun_to(now, &out, local_index, remote_addr);
        }
    }

    /// Answers a request that carries unknown comprehension-required attributes with a 420
    /// (Unknown Attribute) error response listing them (RFC 8489 Section 6.3.1), signed like
    /// every response.
    fn send_unknown_attributes_error(
        &mut self,
        now: Instant,
        m: &Message,
        unknown: &[AttrType],
        local_index: usize,
        remote_addr: SocketAddr,
    ) {
        let response = self.answer_integrity_setter().and_then(|integrity| {
            stun::validated::unknown_attributes_response(
                m,
                unknown,
                &[integrity, Box::new(FINGERPRINT)],
            )
        });
        match response {
            Ok(out) => self.send_stun_to(now, &out, local_index, remote_addr),
            Err(err) => warn!(
                "[{}]: cannot build the 420 response for {}: {}",
                self.get_name(),
                remote_addr,
                err
            ),
        }
    }

    /// Switches the ICE agent role and recomputes all candidate pair priorities.
    /// RFC 8445 Section 7.3.1.1
    pub(crate) fn switch_role(&mut self, now: Instant) {
        self.is_controlling = !self.is_controlling;

        // Recompute priorities for all candidate pairs
        // The priority calculation depends on ice_role_controlling
        for pair in &mut self.candidate_pairs {
            pair.ice_role_controlling = self.is_controlling;
        }

        // Clear nominated pair when switching roles: only the controlling agent nominates.
        self.nominated_pair = None;
        self.nomination_proposal = None;
        self.declined_nominations.clear();
        for pair in &mut self.candidate_pairs {
            pair.nominate = false;
        }

        info!(
            "[{}]: Role switched, recomputed {} candidate pair priorities",
            self.get_name(),
            self.candidate_pairs.len()
        );

        self.event_outs.push_back(TaggedEvent {
            now,
            event: Event::RoleChange(self.is_controlling),
        });
    }

    /// RFC 8445 Section 7.3.1.1, Detecting and Repairing Role Conflicts, for an authenticated
    /// Binding request. Returns `true` when the request must be answered with a 487 (Role
    /// Conflict) error response and nothing else; otherwise the agent has kept or switched its
    /// role and the request is processed as usual.
    fn detect_role_conflict(&mut self, now: Instant, m: &Message) -> Result<bool> {
        if self.is_controlling {
            if m.contains(ATTR_ICE_CONTROLLING) {
                let mut remote = crate::attributes::control::AttrControlling::default();
                remote.get_from(m)?;
                debug!(
                    "[{}]: Role conflict detected (both controlling), local tiebreaker: {}, remote tiebreaker: {}",
                    self.get_name(),
                    self.tie_breaker,
                    remote.0
                );
                // "If the agent's tiebreaker value is larger than or equal to the contents of
                // the ICE-CONTROLLING attribute, the agent generates a Binding error response
                // and includes an ERROR-CODE attribute with a value of 487 (Role Conflict) but
                // retains its role."
                if self.tie_breaker >= remote.0 {
                    return Ok(true);
                }
                // "If the agent's tiebreaker value is less than the contents of the
                // ICE-CONTROLLING attribute, the agent switches to the controlled role."
                self.switch_role(now);
            } else if m.contains(ATTR_USE_CANDIDATE) {
                // USE-CANDIDATE only has meaning on the controlled side (RFC 8445 7.3.1.5), and
                // role conflicts are decided by ICE-CONTROLLING/ICE-CONTROLLED alone. Like
                // libwebrtc, ignore it and answer the check.
                debug!(
                    "[{}]: USE-CANDIDATE without ICE-CONTROLLING while controlling; ignoring USE-CANDIDATE and answering the check",
                    self.get_name(),
                );
            }
        } else if m.contains(ATTR_ICE_CONTROLLED) {
            let mut remote = crate::attributes::control::AttrControlled::default();
            remote.get_from(m)?;
            debug!(
                "[{}]: Role conflict detected (both controlled), local tiebreaker: {}, remote tiebreaker: {}",
                self.get_name(),
                self.tie_breaker,
                remote.0
            );
            // "If the agent's tiebreaker value is larger than or equal to the contents of the
            // ICE-CONTROLLED attribute, the agent switches to the controlling role."
            if self.tie_breaker >= remote.0 {
                self.switch_role(now);
            } else {
                // "... less than ...: the agent generates a Binding error response and
                // includes an ERROR-CODE attribute with a value of 487 (Role Conflict) but
                // retains its role."
                return Ok(true);
            }
        }

        Ok(false)
    }

    pub(crate) fn handle_inbound(
        &mut self,
        now: Instant,
        m: &mut Message,
        local_index: usize,
        remote_addr: SocketAddr,
    ) -> Result<()> {
        if m.typ.method != METHOD_BINDING
            || !(m.typ.class == CLASS_SUCCESS_RESPONSE
                || m.typ.class == CLASS_ERROR_RESPONSE
                || m.typ.class == CLASS_REQUEST
                || m.typ.class == CLASS_INDICATION)
        {
            trace!(
                "[{}]: unhandled STUN from {} to {} class({}) method({})",
                self.get_name(),
                remote_addr,
                self.local_candidates[local_index],
                m.typ.class,
                m.typ.method
            );
            return Err(Error::ErrUnhandledStunpacket);
        }

        if m.typ.class == CLASS_REQUEST {
            return self.handle_inbound_request(now, m, local_index, remote_addr);
        }

        let Some(remote_credentials) = &self.ufrag_pwd.remote_credentials else {
            debug!(
                "[{}]: ufrag_pwd.remote_credentials.is_none",
                self.get_name(),
            );
            return Err(Error::ErrPasswordEmpty);
        };

        let remote_candidate_index = self.find_remote_candidate(remote_addr);
        if m.typ.class == CLASS_SUCCESS_RESPONSE || m.typ.class == CLASS_ERROR_RESPONSE {
            // A response: FINGERPRINT when present, MESSAGE-INTEGRITY with the peer's
            // password, no unknown comprehension-required attribute, or it is discarded (RFC
            // 8489 Sections 6.3.3 and 9.1.4). Only what the integrity covers is read.
            //
            // The agent's requests carry MESSAGE-INTEGRITY only, so a response is checked by
            // that attribute only (RFC 8489 Section 9.1.4: "the algorithm in the response has
            // to match; otherwise, the response MUST be discarded"), and so is every later
            // transaction with the peer (Section 9.1.5).
            let known = ice_known_attributes();
            match stun::validated::Validator::new()
                .known_attributes(&known)
                .authenticate_with(
                    m,
                    IntegrityAlgorithm::Sha1,
                    remote_credentials.pwd.as_bytes(),
                    self.crypto_provider.crypto(),
                ) {
                Ok(valid) => *m = valid.into_message(),
                Err(rejection) => {
                    warn!(
                        "[{}]: discard message from ({}), {}",
                        self.get_name(),
                        remote_addr,
                        rejection
                    );
                    if !matches!(rejection, stun::validated::Rejection::UnknownAttributes(_)) {
                        self.note_unauthentic_response(m.transaction_id);
                    }
                    // RFC 8489 Section 6.3.4: an (authenticated) error response with unknown
                    // comprehension-required attributes means the transaction failed. (A
                    // success response with them is discarded, Section 6.3.3, and the
                    // transaction goes on.)
                    if m.typ.class == CLASS_ERROR_RESPONSE
                        && matches!(rejection, stun::validated::Rejection::UnknownAttributes(_))
                    {
                        self.handle_failed_transaction(now, m.transaction_id, remote_addr);
                    }
                    return Err(rejection_error(&rejection));
                }
            }

            // A response is matched to its request by transaction id (RFC 8445 Section
            // 7.2.5); where it came from is then checked against where the request went.
            if m.typ.class == CLASS_SUCCESS_RESPONSE {
                self.handle_success_response(now, m, local_index, remote_addr);
            } else {
                self.handle_error_response(now, m, remote_addr);
            }

            if remote_candidate_index.is_none() {
                warn!(
                    "[{}]: discard response from ({}), no such remote",
                    self.get_name(),
                    remote_addr
                );
                return Err(Error::ErrUnhandledStunpacket);
            }
        }

        // RFC 8489 Section 6.3.2: an indication (a lite peer's keepalive) with unknown
        // comprehension-required attributes, or a wrong FINGERPRINT, is discarded.
        if m.typ.class == CLASS_INDICATION
            && let Err(rejection) = stun::validated::Validator::new()
                .known_attributes(&ice_known_attributes())
                .unauthenticated(m)
        {
            debug!(
                "[{}]: discard indication from ({}), {}",
                self.get_name(),
                remote_addr,
                rejection
            );
            return Err(rejection_error(&rejection));
        }

        if let Some(remote) = remote_candidate_index.and_then(|i| self.remote_candidates.get_mut(i))
        {
            remote.seen(now, false);
            // Responses reaching here passed MESSAGE-INTEGRITY; indications did not and carry
            // none.
            if m.typ.class != CLASS_INDICATION {
                remote.last_authenticated = Some(now);
            }
        }

        Ok(())
    }

    /// A Binding request (RFC 8445 Section 7.3): authenticated with the short-term credential,
    /// then answered and processed, or, before the peer's credentials are known, answered and
    /// remembered.
    fn handle_inbound_request(
        &mut self,
        now: Instant,
        m: &mut Message,
        local_index: usize,
        remote_addr: SocketAddr,
    ) -> Result<()> {
        // RFC 8489 Sections 6.3 and 9.1.3, through `rtc-stun`'s validator: FINGERPRINT is
        // verified when present, MESSAGE-INTEGRITY with the local password, and from here on
        // only what the integrity covers is read: USERNAME, the role attributes, PRIORITY,
        // USE-CANDIDATE. An attribute appended after it does not exist for the agent.
        // The validator verifies MESSAGE-INTEGRITY-SHA256 when the request has it, and the
        // answers carry the attribute that was verified (Section 9.1.3).
        self.answer_integrity = if m.contains(ATTR_MESSAGE_INTEGRITY_SHA256) {
            IntegrityAlgorithm::Sha256
        } else {
            IntegrityAlgorithm::Sha1
        };
        let known = ice_known_attributes();
        let validated = stun::validated::Validator::new()
            .known_attributes(&known)
            .authenticate(
                m,
                self.ufrag_pwd.local_credentials.pwd.as_bytes(),
                self.crypto_provider.crypto(),
            );
        match validated {
            Ok(valid) => *m = valid.into_message(),
            Err(stun::validated::Rejection::UnknownAttributes(unknown)) => {
                // RFC 8489 Section 6.3.1: an authenticated request with a comprehension-
                // required attribute the agent does not know is answered 420 with the list.
                self.send_unknown_attributes_error(now, m, &unknown, local_index, remote_addr);
                return Err(Error::ErrUnhandledStunpacket);
            }
            Err(rejection) => {
                warn!(
                    "[{}]: discard message from ({}), {}",
                    self.get_name(),
                    remote_addr,
                    rejection
                );
                // RFC 8489 Section 9.1.3, in its order: no MESSAGE-INTEGRITY or no USERNAME
                // is 400; a username that is not valid here is 401; a MESSAGE-INTEGRITY that
                // does not match is 401. (A FINGERPRINT that does not match is not answered:
                // the datagram is not STUN for this agent, Section 7.3.)
                use stun::error_code::{CODE_BAD_REQUEST, CODE_UNAUTHENTICATED};
                use stun::validated::Rejection;
                let code = match rejection {
                    Rejection::IntegrityMissing => Some(CODE_BAD_REQUEST),
                    Rejection::IntegrityMismatch if !m.contains(ATTR_USERNAME) => {
                        Some(CODE_BAD_REQUEST)
                    }
                    Rejection::IntegrityMismatch => Some(CODE_UNAUTHENTICATED),
                    _ => None,
                };
                if let Some(code) = code {
                    self.reject_unauthenticated_request(now, m, code, local_index, remote_addr);
                }
                return Err(rejection_error(&rejection));
            }
        }
        if let Err(err) = assert_inbound_username(m, &self.ufrag_pwd.local_credentials.ufrag) {
            warn!(
                "[{}]: discard message from ({}), {}",
                self.get_name(),
                remote_addr,
                err
            );
            // The integrity matched, so the sender holds the password: the username is
            // absent (400) or not this agent's (401).
            let code = if m.contains(ATTR_USERNAME) {
                stun::error_code::CODE_UNAUTHENTICATED
            } else {
                stun::error_code::CODE_BAD_REQUEST
            };
            self.reject_unauthenticated_request(now, m, code, local_index, remote_addr);
            return Err(err);
        }

        if self.ufrag_pwd.remote_credentials.is_none() {
            // RFC 8445 Section 7.3: "it is possible (and in fact very likely) that the
            // initiating agent will receive a Binding request prior to receiving the candidates
            // from its peer. If this happens, the agent MUST immediately generate a response
            // [...] Once the answer is received, it MUST proceed with the remaining steps."
            // A source the destination policy refuses is not answered, now or later.
            if !self.remote_policy.allows_candidate(remote_addr) {
                return Err(Error::ErrUnhandledStunpacket);
            }
            self.send_binding_success(now, m, local_index, remote_addr);
            self.remember_early_request(m, local_index, remote_addr);
            return Ok(());
        }

        self.process_binding_request(now, m, local_index, remote_addr, true)
    }

    /// Answers a Binding request that failed the short-term credential check with `code` (400
    /// or 401, RFC 8489 Section 9.1.3), unless the agent is set to drop such requests.
    ///
    /// The source of such a request is unverified, so the answer must be of no use to someone
    /// who forged it: the response carries the error code and FINGERPRINT only (no reason
    /// phrase, and no MESSAGE-INTEGRITY: there is no key the two share), it is sent only when
    /// it is no longer than the request, and at most [`MAX_UNAUTHENTICATED_RESPONSE_BURST`]
    /// of them go out in a burst, one more per [`UNAUTHENTICATED_RESPONSE_INTERVAL`]. Past
    /// that the request is dropped.
    fn reject_unauthenticated_request(
        &mut self,
        now: Instant,
        m: &Message,
        code: stun::error_code::ErrorCode,
        local_index: usize,
        remote_addr: SocketAddr,
    ) {
        if self.unauthenticated_requests == UnauthenticatedRequests::Drop
            || !self.remote_policy.allows_candidate(remote_addr)
            || !self
                .remote_policy
                .allows_pair(self.local_candidates[local_index].base_addr(), remote_addr)
        {
            return;
        }
        // The token bucket: one token per interval since the last refill, up to the burst.
        let elapsed = now.saturating_duration_since(self.unauthenticated_response_refill);
        let earned = elapsed.as_nanos() / UNAUTHENTICATED_RESPONSE_INTERVAL.as_nanos();
        if earned > 0 {
            let earned = u32::try_from(earned).unwrap_or(u32::MAX);
            self.unauthenticated_response_tokens = self
                .unauthenticated_response_tokens
                .saturating_add(earned)
                .min(MAX_UNAUTHENTICATED_RESPONSE_BURST);
            self.unauthenticated_response_refill = if self.unauthenticated_response_tokens
                == MAX_UNAUTHENTICATED_RESPONSE_BURST
            {
                now
            } else {
                self.unauthenticated_response_refill + UNAUTHENTICATED_RESPONSE_INTERVAL * earned
            };
        }
        if self.unauthenticated_response_tokens == 0 {
            return;
        }

        let mut out = Message::new();
        let built = out.build(&[
            Box::new(MessageType::new(METHOD_BINDING, CLASS_ERROR_RESPONSE)),
            Box::new(m.transaction_id),
            Box::new(stun::error_code::ErrorCodeAttribute {
                code,
                reason: vec![],
            }),
            Box::new(FINGERPRINT),
        ]);
        if let Err(err) = built {
            warn!(
                "[{}]: cannot build the {} response for {}: {}",
                self.get_name(),
                code.0,
                remote_addr,
                err
            );
            return;
        }
        if out.raw.len() > m.raw.len() {
            // Never more bytes out than came in.
            return;
        }
        self.unauthenticated_response_tokens -= 1;
        self.send_stun_to(now, &out, local_index, remote_addr);
    }

    fn remember_early_request(&mut self, m: &Message, local_index: usize, remote_addr: SocketAddr) {
        use crate::attributes::nomination::nomination_of;

        let local = &self.local_candidates[local_index];
        let request = EarlyRequest {
            message: m.clone(),
            // What the datagram arrived on is the candidate's base.
            local_addr: local.base_addr(),
            transport_protocol: local.network_type().to_protocol(),
            remote_addr,
        };
        if let Some(known) = self.early_requests.iter_mut().find(|r| {
            r.local_addr == request.local_addr
                && r.transport_protocol == request.transport_protocol
                && r.remote_addr == remote_addr
        }) {
            // One entry per path; a nomination is not forgotten for a later plain check.
            if nomination_of(&request.message) >= nomination_of(&known.message) {
                *known = request;
            }
        } else if self.early_requests.len() < MAX_EARLY_REQUESTS {
            self.early_requests.push(request);
        }
    }

    /// Runs RFC 8445 Sections 7.3.1.3 to 7.3.1.5 for the requests that were answered before the
    /// peer's credentials arrived.
    pub(crate) fn process_early_requests(&mut self, now: Instant) {
        if self.ufrag_pwd.remote_credentials.is_none() {
            return;
        }
        for request in std::mem::take(&mut self.early_requests) {
            let Some(local_index) =
                self.find_local_candidate(request.local_addr, request.transport_protocol)
            else {
                continue;
            };
            let _ = self.process_binding_request(
                now,
                &request.message,
                local_index,
                request.remote_addr,
                false,
            );
        }
    }

    /// Processes an authenticated Binding request: role conflict (Section 7.3.1.1), the
    /// response (7.3.1.2), a peer-reflexive remote candidate (7.3.1.3), the triggered check
    /// (7.3.1.4) and the nominated flag (7.3.1.5). `respond` is false for a request that was
    /// answered when it arrived, before the peer's credentials were known.
    fn process_binding_request(
        &mut self,
        now: Instant,
        m: &Message,
        local_index: usize,
        remote_addr: SocketAddr,
        respond: bool,
    ) -> Result<()> {
        // Role conflicts are acted on only for a request that passed the username and
        // MESSAGE-INTEGRITY checks: an unauthenticated datagram must not be able to flip our
        // ICE role, re-prioritise every pair and clear the nomination. A request that gets the
        // 487 gets nothing else: no success response, no candidate, no triggered check.
        if respond && self.detect_role_conflict(now, m)? {
            self.send_role_conflict_error(now, m, local_index, remote_addr);
            // A peer that claimed the controlling role holds no nomination of ours: it was
            // not the controlled agent. If this agent, which keeps the controlling role, has
            // concluded, its nomination is lost on the peer (a peer that lost its state
            // without an ICE restart), and nothing else would bring it back: the pair is
            // nominated again, the same one (RFC 8445 Section 8.1.1: "the agent MUST NOT
            // nominate another pair").
            if self.is_controlling {
                self.repeat_nomination();
            }
            return Ok(());
        }

        let mut remote_candidate_index = self.find_remote_candidate(remote_addr);
        if remote_candidate_index.is_none() {
            remote_candidate_index =
                self.add_peer_reflexive_remote_candidate(m, local_index, remote_addr)?;
            if remote_candidate_index.is_some() {
                debug!(
                    "[{}]: adding a new peer-reflexive candidate: {} ",
                    self.get_name(),
                    remote_addr
                );
            }
        }

        trace!(
            "[{}]: inbound STUN (Request) from {} to {}",
            self.get_name(),
            remote_addr,
            self.local_candidates[local_index]
        );

        let Some(remote_index) = remote_candidate_index else {
            return Ok(());
        };

        // RFC 8445 Section 7.3.1.4: the pair is (the local candidate the request arrived on,
        // its source); a pair that is not on the checklist is added to it.
        if self.find_pair(local_index, remote_index).is_none() {
            self.add_pair(local_index, remote_index);
        }
        if self.find_pair(local_index, remote_index).is_none() {
            // The checklist is full of better pairs, but this one the peer is checking: it
            // takes the place of the worst pair that has not been checked.
            self.add_triggered_pair(local_index, remote_index);
        }
        if let Some(pair_index) = self.find_pair(local_index, remote_index) {
            self.candidate_pairs[pair_index].on_request_received();
            // An authenticated request is answered whatever the pair's state (unless the
            // destination policy refused the pair).
            if respond {
                self.send_binding_success(now, m, local_index, remote_addr);
            }
            self.handle_binding_request(now, m, local_index, remote_index);
        }

        if let Some(remote) = self.remote_candidates.get_mut(remote_index) {
            remote.seen(now, false);
            remote.last_authenticated = Some(now);
        }

        Ok(())
    }

    /// RFC 8445 Section 7.3.1.3: the source of an authenticated request that is no known remote
    /// candidate becomes a peer-reflexive one. Its priority is the request's PRIORITY
    /// attribute, its component that of the local candidate the request arrived on, and it is
    /// paired with that local candidate only (the caller does that).
    fn add_peer_reflexive_remote_candidate(
        &mut self,
        m: &Message,
        local_index: usize,
        remote_addr: SocketAddr,
    ) -> Result<Option<usize>> {
        use crate::attributes::priority::PriorityAttr;

        if self.remote_candidates.len() >= MAX_REMOTE_CANDIDATES {
            warn!(
                "[{}]: ignoring peer-reflexive candidate {}: already holding {} (the cap)",
                self.get_name(),
                remote_addr,
                MAX_REMOTE_CANDIDATES
            );
            return Ok(None);
        }
        if !self.remote_policy.allows_candidate(remote_addr) {
            warn!(
                "[{}]: ignoring peer-reflexive candidate {}: not an allowed destination",
                self.get_name(),
                remote_addr
            );
            return Ok(None);
        }

        // Use the local candidate's network type for the peer-reflexive candidate
        let network_type = self.local_candidates[local_index].network_type();
        if !self.network_types.is_empty() && !self.network_types.contains(&network_type) {
            return Ok(None);
        }

        // A request without PRIORITY (or with one outside 1..2^31-1) is not refused: the
        // candidate then gets the priority this agent would compute for it.
        let mut priority = PriorityAttr::default();
        let priority = match priority.get_from(m) {
            Ok(()) if (1..=MAX_CANDIDATE_PRIORITY).contains(&priority.0) => priority.0,
            _ => 0,
        };

        let prflx_candidate_config = CandidatePeerReflexiveConfig {
            base_config: CandidateConfig {
                network: network_type.to_string(),
                address: remote_addr.ip().to_string(),
                port: remote_addr.port(),
                component: self.local_candidates[local_index].component(),
                priority,
                ..CandidateConfig::default()
            },
            rel_addr: "".to_owned(),
            rel_port: 0,
        };

        let mut prflx_candidate = match prflx_candidate_config.new_candidate_peer_reflexive() {
            Ok(c) => c,
            Err(err) => {
                error!(
                    "[{}]: Failed to create new remote prflx candidate ({})",
                    self.get_name(),
                    err
                );
                return Err(err);
            }
        };
        // RFC 6544 §7: a peer-reflexive candidate learned over TCP takes the TCP type that
        // pairs with the local candidate the check arrived on (a check on our passive
        // candidate comes from an active one), or it could never form a pair and the
        // controlling agent would never nominate the connection.
        prflx_candidate.tcp_type = self.local_candidates[local_index].tcp_type().complement();

        self.remote_candidates.push(prflx_candidate);
        Ok(Some(self.remote_candidates.len() - 1))
    }

    // Processes non STUN traffic from a remote candidate, and returns true if it is an actual
    // remote candidate.
    pub(crate) fn validate_non_stun_traffic(
        &mut self,
        now: Instant,
        remote_addr: SocketAddr,
    ) -> bool {
        self.find_remote_candidate(remote_addr)
            .is_some_and(|remote_index| {
                self.remote_candidates[remote_index].seen(now, false);
                true
            })
    }

    pub(crate) fn send_stun(
        &mut self,
        now: Instant,
        msg: &Message,
        local_index: usize,
        remote_index: usize,
    ) {
        let peer_addr = self.remote_candidates[remote_index].addr();
        self.send_stun_to(now, msg, local_index, peer_addr);
    }

    /// Queues `msg` from the local candidate's base to `peer_addr`.
    pub(crate) fn send_stun_to(
        &mut self,
        now: Instant,
        msg: &Message,
        local_index: usize,
        peer_addr: SocketAddr,
    ) {
        self.send_raw_stun(now, BytesMut::from(&msg.raw[..]), local_index, peer_addr);
    }

    /// Queues an encoded STUN message from the local candidate's base to `peer_addr`.
    pub(crate) fn send_raw_stun(
        &mut self,
        now: Instant,
        message: BytesMut,
        local_index: usize,
        peer_addr: SocketAddr,
    ) {
        // RFC 8445 §6.1.2: checks for a (server/peer-)reflexive candidate must
        // be sent from its base, the bound local socket the candidate was
        // derived from; the mapped address is not a local socket.
        let local_addr = self.local_candidates[local_index].base_addr();
        let transport_protocol = if self.local_candidates[local_index].network_type().is_tcp() {
            TransportProtocol::TCP
        } else {
            TransportProtocol::UDP
        };
        // RFC 8489 Section 6.1: "the STUN usage MUST follow the MTU constraint" outside MTU
        // probing. Nothing over UDP leaves larger than the path MTU allows.
        if transport_protocol == TransportProtocol::UDP
            && message.len() > self.max_udp_stun_size(peer_addr)
        {
            warn!(
                "[{}]: not sending a STUN message of {} bytes to {}: larger than the path MTU allows",
                self.get_name(),
                message.len(),
                peer_addr
            );
            return;
        }

        self.write_outs.push_back(TaggedBytesMut {
            now,
            transport: TransportContext {
                local_addr,
                peer_addr,
                ecn: None,
                transport_protocol,
            },
            message,
        });

        self.local_candidates[local_index].seen(now, true);
    }

    /// The largest STUN message sent over UDP to `peer`: the path MTU
    /// ([`AgentConfig::path_mtu`]), else the RFC 8489 Section 6.1 assumption (576 bytes for
    /// IPv4, 1280 for IPv6), less the IP and UDP headers.
    pub(crate) fn max_udp_stun_size(&self, peer: SocketAddr) -> usize {
        let (assumed, overhead) = if peer.is_ipv4() {
            (576, 20 + 8)
        } else {
            (1280, 40 + 8)
        };
        self.path_mtu.unwrap_or(assumed).saturating_sub(overhead)
    }

    fn handle_inbound_candidate_msg(
        &mut self,
        local_index: usize,
        msg: TaggedBytesMut,
    ) -> Result<()> {
        if is_stun_message(&msg.message) {
            let mut m = Message {
                raw: msg.message.to_vec(),
                ..Message::default()
            };

            if let Err(err) = m.decode() {
                warn!(
                    "[{}]: Failed to handle decode ICE from {} to {}: {}",
                    self.get_name(),
                    msg.transport.local_addr,
                    msg.transport.peer_addr,
                    err
                );
                Err(err)
            } else {
                self.handle_inbound(msg.now, &mut m, local_index, msg.transport.peer_addr)
            }
        } else {
            if !self.validate_non_stun_traffic(msg.now, msg.transport.peer_addr) {
                warn!(
                    "[{}]: Discarded message, not a valid remote candidate from {}",
                    self.get_name(),
                    msg.transport.peer_addr,
                );
            } else {
                warn!(
                    "[{}]: non-STUN traffic message from a valid remote candidate from {}",
                    self.get_name(),
                    msg.transport.peer_addr
                );
            }
            Err(Error::ErrNonStunmessage)
        }
    }

    pub(crate) fn get_name(&self) -> &str {
        if self.is_controlling {
            "controlling"
        } else {
            "controlled"
        }
    }

    pub(crate) fn get_selected_pair(&self) -> Option<usize> {
        self.selected_pair
    }

    pub(crate) fn get_best_available_pair(&self) -> Option<usize> {
        let mut best_pair_index: Option<usize> = None;

        for (index, p) in self.candidate_pairs.iter().enumerate() {
            if p.state == CandidatePairState::Failed {
                continue;
            }

            if let Some(pair_index) = &mut best_pair_index {
                let b = &self.candidate_pairs[*pair_index];
                if b.priority() < p.priority() {
                    *pair_index = index;
                }
            } else {
                best_pair_index = Some(index);
            }
        }

        best_pair_index
    }

    pub(crate) fn get_best_valid_candidate_pair(&self) -> Option<usize> {
        let mut best_pair_index: Option<usize> = None;

        for (index, p) in self.candidate_pairs.iter().enumerate() {
            if p.state != CandidatePairState::Succeeded || !p.valid {
                continue;
            }

            if let Some(pair_index) = &mut best_pair_index {
                let b = &self.candidate_pairs[*pair_index];
                if b.priority() < p.priority() {
                    *pair_index = index;
                }
            } else {
                best_pair_index = Some(index);
            }
        }

        best_pair_index
    }
}

/// The precedence of RFC 6724 Section 2.1's default policy table for `ip` (an IPv4 address
/// as its IPv4-mapped form, `::ffff:0:0/96`).
pub(crate) fn rfc6724_precedence(ip: IpAddr) -> u8 {
    let v6 = match ip {
        IpAddr::V4(_) => return 35,
        IpAddr::V6(v6) => v6,
    };
    if let Some(v4) = v6.to_ipv4_mapped() {
        return rfc6724_precedence(IpAddr::V4(v4));
    }
    let s = v6.segments();
    if v6.is_loopback() {
        50
    } else if s[0] == 0x2002 {
        30
    } else if s[0] == 0x2001 && s[1] == 0 {
        5
    } else if s[0] & 0xfe00 == 0xfc00 {
        3
    } else if s[..6] == [0; 6] || s[0] & 0xffc0 == 0xfec0 || s[0] == 0x3ffe {
        1
    } else {
        40
    }
}
