//! The Sans-I/O TURN client.
//!
//! Using a relay takes three steps: Allocate to obtain a public address, CreatePermission for
//! each peer you intend to exchange data with, and then Send/Data indications (or a bound channel)
//! to move bytes. Each step is a STUN transaction, so every [`Event`] carries the
//! transaction id of the request it answers.
//!
//! The three address kinds are easy to confuse: [`RelayedAddr`] is what peers send to,
//! [`ReflexiveAddr`] is how the server sees this client, and [`PeerAddr`] is the far end.
#[cfg(test)]
mod client_allocate_options_test;
#[cfg(test)]
mod client_allocate_test;
#[cfg(test)]
mod client_channel_test;
#[cfg(test)]
mod client_data_source_test;
#[cfg(test)]
mod client_lifecycle_test;
#[cfg(test)]
mod client_permission_refresh_test;
#[cfg(test)]
mod client_permission_test;
#[cfg(test)]
mod client_retry_test;
#[cfg(test)]
mod client_software_mtu_test;
#[cfg(test)]
mod client_stale_nonce_test;
#[cfg(test)]
mod client_stun8489_config_test;
#[cfg(test)]
mod client_stun8489_test;
#[cfg(test)]
mod client_tcp_allocation_test;
#[cfg(test)]
mod client_test;
#[cfg(test)]
mod test_server;

mod allocation;
/// Channel bindings, which replace the 36-byte Data indication header with a 4-byte one.
pub mod binding;
pub(crate) mod credential;
/// The data connections of a TCP allocation (RFC 6062).
pub mod data_connection;
mod error;
/// Per-peer send permissions, which a relay requires before it will forward to an address.
pub mod permission;
mod proto;
/// A live allocation on the server, and sending or receiving through it.
pub mod relay;
/// Outstanding request tracking, with the RFC's retransmission schedule.
pub mod transaction;

use bytes::BytesMut;
use crypto::RTCCryptoProvider;
use log::{debug, trace};
use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::Arc;
use std::time::{Duration, Instant};

use stun::alternate::RedirectGuard;
/// The redirection of an authenticated 300 (Try Alternate): see
/// [`ErrorResponse::try_alternate`] and [`Client::follow_alternate`].
pub use stun::alternate::TryAlternate;
use stun::attributes::*;
#[cfg(test)]
use stun::integrity::*;
use stun::message::*;
use stun::textattrs::*;
use stun::timer::Schedule;
use stun::validated::{Rejection, ValidatedMessage, Validator};
use stun::xoraddr::*;

use allocation::FamilyBlock;
pub use allocation::{AllocateOptions, RelayTransport};
use credential::{Credential, Login};
pub use error::{ErrorResponse, RequestError};
use transaction::*;

use crate::client::relay::{Relay, RelayState};
use crate::proto::chandata::*;
use crate::proto::channum::ChannelNumber;
use crate::proto::connid::ConnectionId;
use crate::proto::data::*;
use crate::proto::icmp::Icmp;
use crate::proto::lifetime::Lifetime;
use crate::proto::peeraddr::*;
#[cfg(test)]
use crate::proto::{PROTO_UDP, relayaddr::RelayedAddress, reqtrans::RequestedTransport};
use shared::error::{Error, Result};
use shared::util::lookup_host;
use shared::{TransportContext, TransportMessage, TransportProtocol};
use stun::error_code::ErrorCodeAttribute;
use stun::fingerprint::FINGERPRINT;

/// The comprehension-required attributes the TURN client understands in what it receives:
/// those of STUN, of TURN (RFC 8656 §18) and of TCP allocations (RFC 6062 §6.2), and the three
/// of RFC 3489 that old STUN servers still put in a Binding response. A message with any other
/// is not processed (RFC 8489 §6.3.2 to §6.3.4).
pub(crate) const KNOWN_ATTRIBUTES: &[AttrType] = &[
    ATTR_MAPPED_ADDRESS,
    ATTR_USERNAME,
    ATTR_MESSAGE_INTEGRITY,
    ATTR_ERROR_CODE,
    ATTR_UNKNOWN_ATTRIBUTES,
    ATTR_REALM,
    ATTR_NONCE,
    ATTR_MESSAGE_INTEGRITY_SHA256,
    ATTR_PASSWORD_ALGORITHM,
    ATTR_USER_HASH,
    ATTR_XORMAPPED_ADDRESS,
    ATTR_CHANNEL_NUMBER,
    ATTR_LIFETIME,
    ATTR_XOR_PEER_ADDRESS,
    ATTR_DATA,
    ATTR_XOR_RELAYED_ADDRESS,
    ATTR_REQUESTED_ADDRESS_FAMILY,
    ATTR_EVEN_PORT,
    ATTR_REQUESTED_TRANSPORT,
    ATTR_DONT_FRAGMENT,
    ATTR_RESERVATION_TOKEN,
    ATTR_CONNECTION_ID,
    ATTR_SOURCE_ADDRESS,
    ATTR_CHANGED_ADDRESS,
    AttrType(0x000b),
];

/// The validator every received STUN message goes through.
pub(crate) fn validator() -> Validator<'static> {
    Validator::new().known_attributes(KNOWN_ATTRIBUTES)
}

/// A response that passed the checks, and the request it answers.
pub(crate) struct Response {
    /// The response, reduced to the attributes ahead of its integrity attribute: nothing
    /// that follows it is read (RFC 8489 §9).
    pub(crate) msg: ValidatedMessage,
    /// The request as it was sent.
    pub(crate) request: BytesMut,
}

impl Response {
    /// The request the response answers, decoded.
    pub(crate) fn request(&self) -> Message {
        let mut request = Message::new();
        request.raw = self.request.to_vec();
        // What the client built decodes; if it does not, the request counts as unsigned.
        let _ = request.decode();
        request
    }

    /// The error of an error response.
    pub(crate) fn error(&self) -> RequestError {
        RequestError::of(&self.msg)
    }

    /// A response nothing checked, to a request without a credential: for tests that hand a
    /// handler its response directly.
    #[cfg(test)]
    pub(crate) fn unchecked(msg: &Message) -> Self {
        Self {
            msg: Validator::new()
                .unauthenticated(msg)
                .expect("the response has no wrong FINGERPRINT"),
            request: BytesMut::new(),
        }
    }
}

impl std::ops::Deref for Response {
    type Target = Message;

    fn deref(&self) -> &Message {
        &self.msg
    }
}

/// Why a transaction ended without a response the client could act on.
pub(crate) enum Failure {
    /// Nothing arrived in time.
    Timeout,
    /// Every response that arrived failed the integrity check, or, over a reliable
    /// transport, one did (RFC 8489 §9.2.5).
    IntegrityViolation,
    /// The response carried comprehension-required attributes the client does not know
    /// (RFC 8489 §6.3.3, §6.3.4).
    UnknownAttributes(Vec<AttrType>),
}

impl Failure {
    fn error(&self) -> Error {
        match self {
            Self::Timeout => Error::ErrTimeout,
            Self::IntegrityViolation => Error::ErrIntegrityMismatch,
            Self::UnknownAttributes(unknown) => {
                Error::Other(Rejection::UnknownAttributes(unknown.clone()).to_string())
            }
        }
    }
}

/// The retransmission timer of the client's requests (RFC 8489 §6.2), the one `rtci-stun` has
/// ([`stun::timer`]). The default is the RFC's.
///
/// Over UDP a request is sent again after RTO, then after twice that, and so on, `rc` times in
/// all, and its transaction fails `rm` x RTO after the last: with the defaults and an RTO of
/// 500 ms, at 0, 0.5, 1.5, 3.5, 7.5, 15.5 and 31.5 s, failing at 39.5 s. Over TCP or TLS it is
/// sent once and fails after `ti`. The initial RTO is [`ClientConfig::rto_in_ms`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetransmissionConfig {
    /// Rc: how many times a request is sent over UDP (RFC 8489 §6.2.1; 7). Values below 1
    /// are 1.
    pub rc: u32,
    /// Rm: the transaction fails Rm x RTO after the last request (RFC 8489 §6.2.1; 16).
    pub rm: u32,
    /// Ti: how long a request waits over a reliable transport (RFC 8489 §6.2.2; 39.5 s).
    pub ti: Duration,
    /// Whether the RTO follows the server's round-trip times as RFC 6298 computes it, never
    /// below the initial RTO, kept per server and dropped after ten minutes without a
    /// transaction (RFC 8489 §6.2.1; on). Off: every transaction starts at the initial RTO.
    pub rto_estimation: bool,
    /// Most transactions outstanding to one server (RFC 8489 §6.2; 10). A request past the
    /// limit is sent when one of them ends. `0` lifts the limit, for an application that
    /// limits its rate some other way.
    pub max_outstanding_transactions: usize,
}

impl Default for RetransmissionConfig {
    fn default() -> Self {
        let schedule = Schedule::default();
        Self {
            rc: schedule.rc,
            rm: schedule.rm,
            ti: schedule.ti,
            rto_estimation: true,
            max_outstanding_transactions: stun::timer::DEFAULT_MAX_OUTSTANDING,
        }
    }
}
const MAX_DATA_BUFFER_SIZE: usize = u16::MAX as usize; // message size limit for Chromium
const MAX_READ_QUEUE_SIZE: usize = 1024;

/// The public address the TURN server allocated on this client's behalf.
///
/// Peers send here; the server forwards to the client.
pub type RelayedAddr = SocketAddr;
/// The client's own address as seen by the server — its server-reflexive address.
pub type ReflexiveAddr = SocketAddr;
/// The address of a remote peer the client exchanges data with through the relay.
pub type PeerAddr = SocketAddr;

#[derive(Debug)]
/// What the client produces in response to inbound datagrams and elapsed time.
///
/// A variant that answers a request the caller made carries the [`TransactionId`] that
/// request returned, so responses can be matched to requests. A variant about an allocation
/// as a whole (lost, released, a refresh or a channel bind the client made by itself) names
/// the allocation by its relayed address instead.
#[non_exhaustive]
pub enum Event {
    /// A request exhausted its retransmissions without a response.
    ///
    /// A request whose every response was discarded for its integrity, or whose response
    /// carried attributes the client must but does not understand, does not end here: it is
    /// reported by the error event of its kind ([`Event::AllocateError`],
    /// [`Event::RefreshError`], ...) with [`RequestError::Failed`], an
    /// `ErrIntegrityMismatch` in the first case (RFC 8489 §9.2.5: an integrity violation is
    /// not a timeout).
    TransactionTimeout(TransactionId),

    /// A STUN Binding succeeded, reporting this client's server-reflexive address.
    BindingResponse(TransactionId, ReflexiveAddr),
    /// A STUN Binding failed.
    BindingError(TransactionId, Error),

    /// An Allocate succeeded; the relayed address is now usable.
    AllocateResponse(TransactionId, RelayedAddr),
    /// An Allocate failed — commonly authentication, or the server being out of ports. The
    /// error carries the server's code (RFC 8656 §7.4 says what each one asks of the client).
    AllocateError(TransactionId, RequestError),

    /// A CreatePermission succeeded; the relay will now forward to and from this peer.
    CreatePermissionResponse(TransactionId, PeerAddr),
    /// A CreatePermission failed; there is no permission for the peer.
    CreatePermissionError(TransactionId, RequestError),

    /// The server no longer holds the allocation: it answered 437 (Allocation Mismatch) to a
    /// request for it (RFC 8656 §5), or the allocation's lifetime ran out with no Refresh
    /// answered. The client has dropped it, with its permissions and channel bindings;
    /// [`Client::relay`] no longer finds it.
    AllocationLost(RelayedAddr, RequestError),
    /// An allocation the application released with [`Relay::close`] is done with: the server
    /// confirmed, no longer had it, or never answered.
    AllocationReleased(RelayedAddr),
    /// A Refresh of the allocation failed. The allocation is kept and refreshed again while
    /// its lifetime lasts; [`Event::AllocationLost`] follows if that runs out.
    RefreshError(RelayedAddr, RequestError),
    /// The server refused to refresh the permission for a peer's IP address. The client has
    /// dropped it: nothing is sent to that address until a new permission is created.
    PermissionLost(RelayedAddr, IpAddr, RequestError),
    /// A Connect succeeded: the server has a TCP connection to the peer, named by the
    /// CONNECTION-ID (RFC 6062 §4.3). The application now opens a new TCP connection to the
    /// server and binds it with [`Relay::data_connection`]; the server gives it 30 seconds.
    ConnectResponse(TransactionId, PeerAddr, ConnectionId),
    /// A Connect failed. After a 447 (Connection Timeout or Failure) the same peer can be
    /// tried again, ten seconds later at the earliest.
    ConnectError(TransactionId, PeerAddr, RequestError),
    /// A peer with a permission connected to the relayed address of a TCP allocation
    /// (RFC 6062 §4.4). To accept, the application opens a new TCP connection to the server
    /// and binds it with [`Relay::data_connection`] within 30 seconds; to refuse, it does
    /// nothing.
    ConnectionAttempt(RelayedAddr, PeerAddr, ConnectionId),
    /// A datagram the server relayed to this peer was answered with an ICMP error, for
    /// example "fragmentation needed" with the path MTU after a send with DONT-FRAGMENT
    /// (RFC 8656 §11.6). The peer address tells whether the type and code are ICMPv4 or
    /// ICMPv6.
    IcmpError(PeerAddr, Icmp),
    /// A ChannelBind for a peer failed. Data to it keeps going as Send indications, and the
    /// bind is tried again later. After a 437, or a 400 (the channels of client and server are
    /// out of step, RFC 8656 §12.3), [`Event::AllocationLost`] follows.
    ChannelBindError(RelayedAddr, PeerAddr, RequestError),

    /// Data arrived from a peer through the relay.
    ///
    /// The channel number is `Some` when it came as ChannelData and `None` when it came as a
    /// Data indication.
    DataIndicationOrChannelData(Option<ChannelNumber>, PeerAddr, BytesMut),
}

/// ClientConfig is a bag of config parameters for Client.
pub struct ClientConfig {
    /// The STUN server to use for Binding requests, as `host:port`. May be empty.
    pub stun_serv_addr: String, // STUN server address (e.g. "stun.abc.com:3478")
    /// The TURN server to allocate from, as `host:port`.
    pub turn_serv_addr: String, // TURN server address (e.g. "turn.abc.com:3478")
    /// The local address the client sends from.
    pub local_addr: SocketAddr,
    /// Whether to reach the server over UDP or TCP.
    pub transport_protocol: TransportProtocol,
    /// The long-term credential username for the TURN server. It is sent as USERNAME, or
    /// hashed as USERHASH when the server's nonce says it supports that (RFC 8489 §9.2.5).
    pub username: String,
    /// The long-term credential password.
    pub password: String,
    /// Not used: the realm is the one the server names in its 401 (RFC 8489 §9.2.5).
    pub realm: String,
    /// The `SOFTWARE` attribute of every request (RFC 8489 Section 6.1: requests "SHOULD"
    /// carry one; Section 16.1.2: its use "SHOULD" be configurable). The default is
    /// [`DEFAULT_SOFTWARE`] (`rtci-turn` and its version); empty sends none, for an
    /// application that would not tell its software to the path.
    pub software: String,
    /// Whether Send indications carry [`ClientConfig::software`] too (RFC 8489 Section 6.1:
    /// "Indications MAY include a SOFTWARE attribute"). Off by default: Send indications are
    /// the relayed data path, and the attribute would cost its bytes on every packet sent
    /// before a channel is bound, for no effect on the protocol. Nothing is added when
    /// `software` is empty.
    pub software_in_indications: bool,
    /// The initial retransmission timeout in milliseconds; each retransmission doubles the
    /// wait. `0` selects the default, the 500 ms RFC 8489 §6.2.1 asks for at least.
    pub rto_in_ms: u64,
    /// The rest of the retransmission timer: Rc, Rm, Ti, the RTO estimate and the number of
    /// outstanding transactions.
    pub retransmission: RetransmissionConfig,
    /// The password algorithms accepted from the server's PASSWORD-ALGORITHMS
    /// (`stun::password_algorithm`), the first of the server's list that is in here being
    /// used. Empty for all the client implements, SHA-256 and MD5. Without MD5, a server
    /// that offers no list (RFC 5389) or MD5 alone is not authenticated to: RFC 8489
    /// §18.5.1.1 keeps MD5 for such servers only.
    pub password_algorithms: Vec<u16>,
    /// Optional upper bound for the interval between allocation Refresh requests.
    ///
    /// By default, allocations are refreshed at half the lifetime advertised by the server.
    /// A shorter cap can also keep the client-to-server NAT mapping active when an allocation
    /// waits without carrying application traffic. Values below one second are rounded up.
    pub allocation_refresh_interval_cap: Option<Duration>,
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            stun_serv_addr: "".to_string(),
            turn_serv_addr: "".to_string(),
            local_addr: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)),
            transport_protocol: Default::default(),
            username: "".to_string(),
            password: "".to_string(),
            realm: "".to_string(),
            software: DEFAULT_SOFTWARE.to_string(),
            software_in_indications: false,
            rto_in_ms: 0,
            retransmission: RetransmissionConfig::default(),
            password_algorithms: vec![],
            allocation_refresh_interval_cap: None,
        }
    }
}

/// The default `SOFTWARE` of the TURN client's requests ([`ClientConfig::software`]).
pub const DEFAULT_SOFTWARE: &str = concat!("rtci-turn ", env!("CARGO_PKG_VERSION"));

/// RFC 8489 Section 6.1: with the path MTU unknown, a STUN message over UDP is at most 576
/// bytes of IPv4 datagram, 1280 of IPv6 (the IP and UDP headers taken off).
const UNKNOWN_PATH_MTU_V4: usize = 576;
const UNKNOWN_PATH_MTU_V6: usize = 1280;
const IP_UDP_OVERHEAD_V4: usize = 28;
const IP_UDP_OVERHEAD_V6: usize = 48;

/// Client is a STUN client
pub struct Client {
    crypto_provider: Arc<dyn RTCCryptoProvider>,
    stun_serv_addr: Option<SocketAddr>,
    turn_serv_addr: Option<SocketAddr>,
    local_addr: SocketAddr,
    transport_protocol: TransportProtocol,
    /// What the application authenticates with; each allocation has its own state of it.
    login: Arc<Login>,
    software: Software,
    /// [`ClientConfig::software_in_indications`].
    software_in_indications: bool,
    /// The path MTU for requests over UDP ([`Client::set_path_mtu`]); `None`: unknown.
    path_mtu: Option<usize>,
    tr_map: TransactionMap,
    /// The TURN servers an Allocate was sent to, against redirection loops (RFC 8489 §10).
    redirects: RedirectGuard,
    allocation_refresh_interval_cap: Option<Duration>,

    /// Allocations, each under the first relayed address it was given.
    relays: HashMap<RelayedAddr, RelayState>,
    /// Address families the server refused, by `REQUESTED-ADDRESS-FAMILY` value less one.
    family_blocks: [Option<FamilyBlock>; 2],
    /// Whether the server answered an Allocate with a family that was not asked for.
    family_mismatch: bool,
    transmits: VecDeque<TransportMessage<BytesMut>>,
    events: VecDeque<Event>,
}

impl Client {
    /// Returns a new TURN client.
    ///
    /// The crypto provider is supplied by the caller; this crate never resolves a default.
    pub fn new(config: ClientConfig, crypto_provider: Arc<dyn RTCCryptoProvider>) -> Result<Self> {
        let stun_serv_addr = if config.stun_serv_addr.is_empty() {
            None
        } else {
            Some(lookup_host(
                config.local_addr.is_ipv4(),
                config.stun_serv_addr.as_str(),
            )?)
        };

        let turn_serv_addr = if config.turn_serv_addr.is_empty() {
            None
        } else {
            Some(lookup_host(
                config.local_addr.is_ipv4(),
                config.turn_serv_addr.as_str(),
            )?)
        };

        Ok(Client {
            crypto_provider: crypto_provider.clone(),
            stun_serv_addr,
            turn_serv_addr,
            local_addr: config.local_addr,
            transport_protocol: config.transport_protocol,
            login: Arc::new(Login {
                username: config.username,
                password: config.password,
                password_algorithms: config.password_algorithms,
            }),
            software: Software::new(ATTR_SOFTWARE, config.software),
            software_in_indications: config.software_in_indications,
            path_mtu: None,
            tr_map: TransactionMap::new(TimerSettings {
                initial_rto: if config.rto_in_ms != 0 {
                    Duration::from_millis(config.rto_in_ms)
                } else {
                    stun::timer::DEFAULT_RTO
                },
                schedule: Schedule {
                    rc: config.retransmission.rc.max(1),
                    rm: config.retransmission.rm,
                    ti: config.retransmission.ti,
                },
                estimate_rto: config.retransmission.rto_estimation,
                max_outstanding: config.retransmission.max_outstanding_transactions,
            }),
            redirects: RedirectGuard::new(),
            allocation_refresh_interval_cap: config.allocation_refresh_interval_cap,
            relays: HashMap::new(),
            family_blocks: [None, None],
            family_mismatch: false,
            transmits: VecDeque::new(),
            events: VecDeque::new(),
        })
    }

    // handle_inbound handles data received.
    // This method handles incoming packet demultiplex it by the source address
    // and the types of the message.
    // This return Ok(handled or not) and if there was an error.
    // Caller should check if the packet was handled by this client or not.
    // If not handled, it is assumed that the packet is application data.
    // If an error is returned, the caller should discard the packet regardless.
    fn handle_inbound(&mut self, now: Instant, data: &[u8], from: SocketAddr) -> Result<()> {
        // +-------------------+-------------------------------+
        // |   Return Values   |                               |
        // +-------------------+       Meaning / Action        |
        // | handled |  error  |                               |
        // |=========+=========+===============================+
        // |  false  |   nil   | Handle the packet as app data |
        // |---------+---------+-------------------------------+
        // |  true   |   nil   |        Nothing to do          |
        // |---------+---------+-------------------------------+
        // |  false  |  error  |     (shouldn't happen)        |
        // |---------+---------+-------------------------------+
        // |  true   |  error  | Error occurred while handling |
        // +---------+---------+-------------------------------+
        // Possible causes of the error:
        //  - Malformed packet (parse error)
        //  - STUN message was a request
        //  - Non-STUN message from the STUN server

        // TURN and STUN messages are only ever sent to us by the servers we talk to. Anything
        // else that looks like one — a spoofed Data indication, ChannelData or a forged
        // response — is not from the server and must not be acted on or relayed as peer data.
        let from_turn_server = self.turn_serv_addr == Some(from);
        let from_a_server = from_turn_server || self.stun_serv_addr == Some(from);
        if is_stun_message(data) {
            // A response to a request sent to some other address (`send_binding_request_to`)
            // is accepted from that address only.
            if !from_a_server && !self.is_response_from_transaction_peer(data, from) {
                debug!("discarding STUN message from {from}: not a configured server");
                return Ok(());
            }
            self.handle_stun_message(now, data, from_turn_server)
        } else if ChannelData::is_channel_data(data) {
            if !from_turn_server {
                debug!("discarding ChannelData from {from}: not the TURN server");
                return Ok(());
            }
            self.handle_channel_data(now, data)
        } else if self.stun_serv_addr.is_some() && &from == self.stun_serv_addr.as_ref().unwrap() {
            // received from STUN server, but it is not a STUN message
            Err(Error::ErrNonStunmessage)
        } else {
            // assume, this is an application data
            trace!("non-STUN/TURN packet, unhandled");
            Ok(())
        }
    }

    /// Whether `data` is a STUN response to an outstanding transaction whose request went to
    /// `from`.
    fn is_response_from_transaction_peer(&self, data: &[u8], from: SocketAddr) -> bool {
        let mut msg = Message::new();
        msg.raw = data.to_vec();
        if msg.decode().is_err() {
            return false;
        }
        (msg.typ.class == CLASS_SUCCESS_RESPONSE || msg.typ.class == CLASS_ERROR_RESPONSE)
            && self
                .tr_map
                .find(&msg.transaction_id)
                .is_some_and(|tr| tr.peer_addr == from)
    }

    fn handle_stun_message(
        &mut self,
        now: Instant,
        data: &[u8],
        from_turn_server: bool,
    ) -> Result<()> {
        let mut msg = Message::new();
        msg.raw = data.to_vec();
        msg.decode()?;

        if msg.typ.class == CLASS_REQUEST {
            return Err(Error::Other(format!(
                "{:?} : {}",
                Error::ErrUnexpectedStunrequestMessage,
                msg
            )));
        }

        if msg.typ.class == CLASS_INDICATION {
            return self.handle_indication(now, &msg, from_turn_server);
        }

        // This is a STUN response message (transactional)
        // The type is either:
        // - stun.ClassSuccessResponse
        // - stun.ClassErrorResponse

        let Some(tr) = self.tr_map.find(&msg.transaction_id) else {
            // silently discard
            debug!("no transaction for {}", msg);
            return Ok(());
        };

        // Only a response of the request's method answers it (RFC 8489 §6.3). Anything else
        // with its transaction id is not its response, and the transaction goes on.
        if tr.method != msg.typ.method {
            debug!(
                "discarding {}: its transaction is a {} request",
                msg, tr.method
            );
            return Ok(());
        }

        // One place for the checks of RFC 8489 §6.3, §9 and §9.2.5: FINGERPRINT, the
        // integrity attribute the request's credential asks for, and no attribute the client
        // has to but does not understand. What comes out holds the attributes ahead of the
        // integrity attribute and nothing else.
        let crypto = self.crypto_provider.crypto();
        let checked = match &tr.credential {
            Some(credential) => credential.check_response(&msg, &validator(), crypto),
            None => validator().unauthenticated(&msg),
        };
        let valid = match checked {
            Ok(valid) => valid,
            Err(Rejection::IntegrityMissing | Rejection::IntegrityMismatch) => {
                // A response to a signed request is believed only if it is signed with the
                // same key (RFC 8489 §9.2.5). Over UDP it is dropped as if never received,
                // so the transaction stays open and its retransmissions continue; over a
                // reliable transport the transaction ends at once. Either way its failure
                // is an integrity violation, not a timeout.
                debug!("discarding {}: integrity attribute missing or wrong", msg);
                if tr.is_reliable() {
                    if let Some(tr) = self.tr_map.delete(&msg.transaction_id) {
                        self.handle_transaction_failure(now, tr, Failure::IntegrityViolation);
                    }
                } else if let Some(tr) = self.tr_map.get(&msg.transaction_id) {
                    tr.discarded = true;
                }
                return Ok(());
            }
            Err(Rejection::UnknownAttributes(unknown)) => {
                // RFC 8489 §6.3.3, §6.3.4: the response is discarded and the transaction
                // has failed.
                debug!("discarding {}: unknown attributes {:?}", msg, unknown);
                if let Some(tr) = self.tr_map.answered(&msg.transaction_id, now) {
                    self.handle_transaction_failure(now, tr, Failure::UnknownAttributes(unknown));
                }
                return Ok(());
            }
            Err(rejection) => {
                debug!("discarding {}: {}", msg, rejection);
                return Ok(());
            }
        };

        let Some(tr) = self.tr_map.answered(&msg.transaction_id, now) else {
            return Ok(());
        };
        let id = tr.transaction_id;
        let res = Response {
            msg: valid,
            request: tr.raw,
        };
        match tr.transaction_type {
            TransactionType::BindingRequest => {
                if res.typ.class == CLASS_ERROR_RESPONSE {
                    let mut code = ErrorCodeAttribute::default();
                    let err = if code.get_from(&res).is_err() {
                        Error::Other(format!("{}", res.typ))
                    } else {
                        Error::Other(format!("{} (error {})", res.typ, code))
                    };
                    self.events.push_back(Event::BindingError(id, err));
                } else {
                    let mut refl_addr = XorMappedAddress::default();
                    match refl_addr.get_from(&res) {
                        Ok(_) => {
                            self.events.push_back(Event::BindingResponse(
                                id,
                                ReflexiveAddr::new(refl_addr.ip, refl_addr.port),
                            ));
                        }
                        Err(err) => {
                            self.events.push_back(Event::BindingError(id, err));
                        }
                    }
                }
            }
            TransactionType::AllocateAttempt(state) | TransactionType::AllocateRequest(state) => {
                self.handle_allocate_response(now, res, *state)?;
            }
            // A release of an allocation the client did not keep: nothing to do.
            TransactionType::OrphanRelease => {}
            TransactionType::FamilyRelease(relayed_addr, family, retry) => {
                let mut relay = Relay {
                    relayed_addr,
                    client: self,
                };
                relay.handle_family_release_response(now, res, family, retry)?;
            }
            TransactionType::CreatePermissionRequest(
                relayed_addr,
                peer_addr,
                peer_addrs,
                retry,
            ) => {
                let mut relay = Relay {
                    relayed_addr,
                    client: self,
                };
                relay.handle_create_permission_response(now, res, peer_addr, peer_addrs, retry)?;
            }
            TransactionType::RefreshRequest(relayed_addr, lifetime, retry) => {
                let mut relay = Relay {
                    relayed_addr,
                    client: self,
                };
                relay.handle_refresh_response(now, res, lifetime, retry)?;
            }
            TransactionType::ConnectRequest(relayed_addr, peer_addr, retry) => {
                let mut relay = Relay {
                    relayed_addr,
                    client: self,
                };
                relay.handle_connect_response(now, res, peer_addr, retry)?;
            }
            TransactionType::ChannelBindRequest(relayed_addr, bind_addr, retry) => {
                let mut relay = Relay {
                    relayed_addr,
                    client: self,
                };
                relay.handle_channel_bind_response(now, res, bind_addr, retry)?;
            }
        }

        Ok(())
    }

    /// Handles an indication from a server: the peer's data, the ICMP error a datagram to a
    /// peer met, or a peer's connection to a TCP allocation.
    fn handle_indication(
        &mut self,
        now: Instant,
        msg: &Message,
        from_turn_server: bool,
    ) -> Result<()> {
        // RFC 8489 §6.3.2: an indication with a wrong FINGERPRINT, or with an attribute the
        // client has to but does not understand, is discarded. TURN indications are not
        // signed (RFC 8656 §11); if one carries an integrity attribute all the same, what
        // follows it is not read (RFC 8489 §9).
        let msg = match validator().unauthenticated(msg) {
            Ok(msg) => msg,
            Err(rejection) => {
                debug!("discarding {}: {}", msg, rejection);
                return Ok(());
            }
        };

        if msg.typ.method == METHOD_CONNECTION_ATTEMPT {
            // Like relayed data, a peer's connection is announced by the server holding the
            // allocation and by nobody else.
            if !from_turn_server {
                debug!("discarding ConnectionAttempt indication: not from the TURN server");
                return Ok(());
            }
            let mut connection_id = ConnectionId::default();
            connection_id.get_from(&msg)?;
            let mut peer_addr = PeerAddress::default();
            peer_addr.get_from(&msg)?;
            let from = SocketAddr::new(peer_addr.ip, peer_addr.port);
            // The server accepts connections only from peers the client installed a
            // permission for (RFC 6062 §5.3), on a TCP allocation.
            let Some(relayed) = self
                .relays
                .values()
                .find(|relay| {
                    relay.transport == RelayTransport::Tcp
                        && relay.expects_data_from(&from.ip(), now)
                })
                .map(RelayState::name)
            else {
                debug!("discarding ConnectionAttempt from {from}: no permission");
                return Ok(());
            };
            self.events
                .push_back(Event::ConnectionAttempt(relayed, from, connection_id));
            return Ok(());
        }

        // Only the TURN server holding the allocation relays peer data. The STUN server,
        // when it is a different address, has no allocation and is not believed for it.
        if msg.typ.method == METHOD_DATA && !from_turn_server {
            debug!("discarding Data indication: not from the TURN server");
            return Ok(());
        }
        if msg.typ.method == METHOD_DATA {
            let mut peer_addr = PeerAddress::default();
            peer_addr.get_from(&msg)?;
            let from = SocketAddr::new(peer_addr.ip, peer_addr.port);

            // A Data indication carries the peer's data, or the ICMP error a datagram
            // relayed to that peer met (RFC 8656 §11.4, §11.6). One with neither is
            // discarded.
            let mut data = Data::default();
            let mut icmp = Icmp::default();
            let has_data = msg.contains(ATTR_DATA);
            if has_data {
                data.get_from(&msg)?;
            } else {
                icmp.get_from(&msg)?;
            }

            // The server relays only from addresses the client installed a permission
            // for, so anything else is not what it claims to be (RFC 8656 §11.4, §11.6).
            if !self
                .relays
                .values()
                .any(|relay| relay.expects_data_from(&from.ip(), now))
            {
                debug!("discarding Data indication from {from}: no permission");
                return Ok(());
            }

            if has_data {
                debug!("data indication received from {}", from);
                self.events.push_back(Event::DataIndicationOrChannelData(
                    None,
                    from,
                    BytesMut::from(&data.0[..]),
                ))
            } else {
                debug!("{icmp} reported for {from}");
                self.events.push_back(Event::IcmpError(from, icmp))
            }
        }

        Ok(())
    }

    /// Deals with a transaction that ended without a response the client could act on.
    ///
    /// One that exhausted its retransmissions: a Refresh or ChannelBind is started once more
    /// as a new transaction, so one lost burst does not let the allocation lapse or leave a
    /// channel unbound for good. A ChannelBind that fails again returns its binding to idle,
    /// so the next send binds it again. Anything not started again is reported as
    /// [`Event::TransactionTimeout`], under the id its caller knows.
    ///
    /// One that failed for another reason (its responses were not authentic, or carried
    /// attributes the client does not understand) is not started again, and is reported by
    /// the error event of its kind.
    fn handle_transaction_failure(&mut self, now: Instant, tr: Transaction, failure: Failure) {
        // RFC 8489 §9.2.5: when every response that arrived was discarded, the failure is an
        // integrity violation, not a timeout.
        let failure = match failure {
            Failure::Timeout if tr.discarded => Failure::IntegrityViolation,
            other => other,
        };
        let timed_out = matches!(failure, Failure::Timeout);
        let id = tr.transaction_type.report_id(tr.transaction_id);
        match tr.transaction_type {
            TransactionType::RefreshRequest(relayed_addr, lifetime, retry) => {
                if timed_out
                    && !retry.timeout
                    && let Some(mut relay) = self.relay_by_key(relayed_addr)
                    && relay
                        .refresh_allocation_with(
                            now,
                            lifetime,
                            retry.after_timeout(tr.transaction_id),
                        )
                        .is_ok()
                {
                    debug!("refresh timed out; sent again");
                    return;
                }
                let Some(mut relay) = self.relay_by_key(relayed_addr) else {
                    return;
                };
                let releasing = lifetime.is_zero();
                relay.refresh_failed(now, lifetime, RequestError::Failed(failure.error()));
                if releasing || !timed_out {
                    // The release is over, and reported as that; a failure that is not a
                    // timeout was reported as the refresh error it is.
                    return;
                }
            }
            TransactionType::ChannelBindRequest(relayed_addr, bind_addr, retry) => {
                if timed_out
                    && !retry.timeout
                    && let Some(mut relay) = self.relay_by_key(relayed_addr)
                    && relay
                        .rebind_channel(now, bind_addr, retry.after_timeout(tr.transaction_id))
                        .is_ok()
                {
                    debug!("channel bind for {bind_addr} timed out; sent again");
                    return;
                }
                if let Some(mut relay) = self.relay_by_key(relayed_addr) {
                    if timed_out {
                        relay.channel_bind_timed_out(bind_addr);
                    } else {
                        relay.channel_bind_failed(
                            now,
                            bind_addr,
                            RequestError::Failed(failure.error()),
                        );
                        return;
                    }
                }
            }
            TransactionType::FamilyRelease(relayed_addr, family, retry) => {
                if timed_out
                    && !retry.timeout
                    && let Some(mut relay) = self.relay_by_key(relayed_addr)
                    && relay
                        .release_family_with(
                            now,
                            crate::proto::reqfamily::RequestedAddressFamily(family),
                            retry.after_timeout(tr.transaction_id),
                        )
                        .is_ok()
                {
                    return;
                }
                // Nothing says the server deleted the address, so it is kept; the periodic
                // Refresh keeps the whole allocation alive.
                if let Some(relay) = self.relays.get(&relayed_addr) {
                    self.events.push_back(Event::RefreshError(
                        relay.name(),
                        RequestError::Failed(failure.error()),
                    ));
                }
                return;
            }
            TransactionType::ConnectRequest(relayed_addr, peer_addr, _) => {
                // Nothing is outstanding for the peer any more.
                if let Some(relay) = self.relays.get_mut(&relayed_addr) {
                    relay.connecting.remove(&peer_addr);
                }
                if !timed_out {
                    self.events.push_back(Event::ConnectError(
                        id,
                        peer_addr,
                        RequestError::Failed(failure.error()),
                    ));
                    return;
                }
            }
            TransactionType::CreatePermissionRequest(relayed_addr, peer_addr, _, _) => {
                if !timed_out {
                    // A permission the application asked for is not there; a refresh that
                    // failed this way leaves the permissions the time the server last
                    // granted, and they are asked for again.
                    if let Some(peer_addr) = peer_addr {
                        if let Some(relay) = self.relays.get_mut(&relayed_addr) {
                            relay.perm_map.remove(&peer_addr.ip());
                        }
                        self.events.push_back(Event::CreatePermissionError(
                            id,
                            RequestError::Failed(failure.error()),
                        ));
                    }
                    return;
                }
            }
            TransactionType::AllocateAttempt(_) | TransactionType::AllocateRequest(_) => {
                if !timed_out {
                    self.events.push_back(Event::AllocateError(
                        id,
                        RequestError::Failed(failure.error()),
                    ));
                    return;
                }
            }
            TransactionType::BindingRequest => {
                if !timed_out {
                    self.events
                        .push_back(Event::BindingError(id, failure.error()));
                    return;
                }
            }
            TransactionType::OrphanRelease => return,
        }
        self.events.push_back(Event::TransactionTimeout(id));
    }

    fn handle_channel_data(&mut self, now: Instant, data: &[u8]) -> Result<()> {
        let mut ch_data = ChannelData {
            raw: data.to_vec(),
            ..Default::default()
        };
        ch_data.decode()?;

        // A channel is the binding of one allocation; it is accepted from the moment its
        // ChannelBind is sent (RFC 8656 §12).
        let (relay, addr) = self
            .relays
            .values_mut()
            .find_map(|relay| {
                let addr = relay.binding_mgr.find_by_number(ch_data.number.0)?.addr;
                Some((relay, addr))
            })
            .ok_or(Error::ErrChannelBindNotFound)?;

        // The server relays only from addresses the client holds a permission for
        // (RFC 8656 §12.6).
        if !relay.expects_data_from(&addr.ip(), now) {
            debug!(
                "discarding ChannelData from {addr} (ch={}): no permission",
                ch_data.number.0
            );
            return Ok(());
        }
        if let Some(b) = relay.binding_mgr.get_by_number(ch_data.number.0) {
            b.used = true;
        }

        trace!(
            "channel data received from {} (ch={})",
            addr, ch_data.number.0
        );

        self.events.push_back(Event::DataIndicationOrChannelData(
            Some(ch_data.number),
            addr,
            BytesMut::from(&ch_data.data[..]),
        ));

        Ok(())
    }

    /// Borrows the allocation for `relayed_addr` so data can be sent or permissions created.
    ///
    /// # Errors
    ///
    /// Fails if this client has no allocation for that address — it was never allocated, or has
    /// already been closed.
    pub fn relay(&mut self, relayed_addr: SocketAddr) -> Result<Relay<'_>> {
        // An allocation is kept under its first relayed address and found by any address it
        // has now: either of the two of a dual allocation.
        let key = self
            .relays
            .iter()
            .find(|(_, relay)| relay.addrs.contains(&relayed_addr))
            .map(|(key, _)| *key)
            .ok_or(Error::ErrStreamNotExisted)?;
        Ok(Relay {
            relayed_addr: key,
            client: self,
        })
    }

    /// The allocation kept under `key`, whatever relayed addresses it has now.
    fn relay_by_key(&mut self, key: RelayedAddr) -> Option<Relay<'_>> {
        self.relays.contains_key(&key).then_some(Relay {
            relayed_addr: key,
            client: self,
        })
    }

    /// Whether this client is waiting on a response for transaction `id`.
    ///
    /// A STUN response belongs to whoever sent the matching request — [RFC 5389 §7.3.3] matches
    /// them by transaction ID, and nothing else identifies the owner. That is only a question
    /// worth asking when several STUN users share one socket, which is exactly the situation a
    /// host is in when it points a STUN gatherer and this client at the same server address: both
    /// see every response, and the four-tuple is identical for both, so addresses cannot say whose
    /// a response is.
    ///
    /// Such a host calls this to route a response, rather than guessing from the peer address and
    /// handing it to a client that will silently discard it — [`handle_read`](sansio::Protocol::handle_read)
    /// drops a response with no matching transaction, as it must.
    ///
    /// Applies to responses only. TURN ChannelData carries no transaction ID at all, and
    /// indications are not transaction-matched; both are routed by address.
    ///
    /// [RFC 5389 §7.3.3]: https://www.rfc-editor.org/rfc/rfc5389#section-7.3.3
    #[must_use]
    pub fn has_transaction(&self, id: &TransactionId) -> bool {
        self.tr_map.find(id).is_some()
    }

    /// send_binding_request_to sends a new STUN request to the given transport address
    /// return key to find out corresponding Event either BindingResponse or BindingRequestTimeout
    pub fn send_binding_request_to(
        &mut self,
        now: Instant,
        to: SocketAddr,
    ) -> Result<TransactionId> {
        let msg = {
            // RFC 8489 section 7: "When the FINGERPRINT extension is used, an agent includes
            // the FINGERPRINT attribute in messages it sends to another agent": the client
            // ends every other message with it, and this one shares their socket.
            let mut attrs: Vec<Box<dyn Setter + '_>> =
                vec![Box::new(TransactionId::new()), Box::new(BINDING_REQUEST)];
            if !self.software.text.is_empty() {
                attrs.push(Box::new(self.software.clone()));
            }
            attrs.push(Box::new(FINGERPRINT));

            let mut msg = Message::new();
            msg.build(&attrs)?;
            msg
        };

        debug!("client.SendBindingRequestTo call PerformTransaction 1");
        self.perform_transaction(now, &msg, to, TransactionType::BindingRequest, None)
    }

    /// send_binding_request sends a new STUN request to the STUN server
    /// return key to find out corresponding Event either BindingResponse or BindingRequestTimeout
    pub fn send_binding_request(&mut self, now: Instant) -> Result<TransactionId> {
        if let Some(stun_serv_addr) = &self.stun_serv_addr {
            self.send_binding_request_to(now, *stun_serv_addr)
        } else {
            Err(Error::ErrStunserverAddressNotSet)
        }
    }

    // stun_server_addr return the STUN server address
    fn stun_server_addr(&self) -> Option<SocketAddr> {
        self.stun_serv_addr
    }

    /* https://datatracker.ietf.org/doc/html/rfc8656#section-20
    TURN                                 TURN          Peer         Peer
    client                               server         A            B
      |                                    |            |            |
      |--- Allocate request -------------->|            |            |
      |    Transaction-Id=0xA56250D3F17ABE679422DE85    |            |
      |    SOFTWARE="Example client, version 1.03"      |            |
      |    LIFETIME=3600 (1 hour)          |            |            |
      |    REQUESTED-TRANSPORT=17 (UDP)    |            |            |
      |    DONT-FRAGMENT                   |            |            |
      |                                    |            |            |
      |<-- Allocate error response --------|            |            |
      |    Transaction-Id=0xA56250D3F17ABE679422DE85    |            |
      |    SOFTWARE="Example server, version 1.17"      |            |
      |    ERROR-CODE=401 (Unauthorized)   |            |            |
      |    REALM="example.com"             |            |            |
      |    NONCE="obMatJos2gAAAadl7W7PeDU4hKE72jda"     |            |
      |    PASSWORD-ALGORITHMS=MD5 and SHA256           |            |
      |                                    |            |            |
      |--- Allocate request -------------->|            |            |
      |    Transaction-Id=0xC271E932AD7446A32C234492    |            |
      |    SOFTWARE="Example client 1.03"  |            |            |
      |    LIFETIME=3600 (1 hour)          |            |            |
      |    REQUESTED-TRANSPORT=17 (UDP)    |            |            |
      |    DONT-FRAGMENT                   |            |            |
      |    USERNAME="George"               |            |            |
      |    REALM="example.com"             |            |            |
      |    NONCE="obMatJos2gAAAadl7W7PeDU4hKE72jda"     |            |
      |    PASSWORD-ALGORITHMS=MD5 and SHA256           |            |
      |    PASSWORD-ALGORITHM=SHA256       |            |            |
      |    MESSAGE-INTEGRITY=...           |            |            |
      |    MESSAGE-INTEGRITY-SHA256=...    |            |            |
      |                                    |            |            |
      |<-- Allocate success response ------|            |            |
      |    Transaction-Id=0xC271E932AD7446A32C234492    |            |
      |    SOFTWARE="Example server, version 1.17"      |            |
      |    LIFETIME=1200 (20 minutes)      |            |            |
      |    XOR-RELAYED-ADDRESS=192.0.2.15:50000         |            |
      |    XOR-MAPPED-ADDRESS=192.0.2.1:7000            |            |
      |    MESSAGE-INTEGRITY-SHA256=...    |            |            |
    */
    /// Replaces the long-term credential used to sign subsequent requests, **keeping any
    /// existing allocation**.
    ///
    /// This is for a new **password** for the same username. An allocation belongs to the
    /// username that created it: [RFC 8656 §5] has the server answer a request for it made
    /// under another username with **441 (Wrong Credentials)**. Giving up the allocation and
    /// allocating again is no way round a rotation either, since the server still holds the
    /// allocation for the 5-tuple and answers the new Allocate with 437 (Allocation Mismatch).
    /// So with a new password the existing allocation is re-signed, and its permissions and
    /// channel bindings survive.
    ///
    /// A new username takes effect for the next [`allocate`](Self::allocate) only: RFC 8656
    /// section 5 has every request about an allocation use the username that created it, so
    /// live allocations keep signing with theirs (and their password). To move to the new
    /// username, [`Relay::close`] an allocation, wait for [`Event::AllocationReleased`], and
    /// allocate again.
    ///
    /// The realm is *not* re-negotiated. It was learned from the server's 401 during the
    /// first `Allocate`, and a credential rotation keeps the same server, so it still
    /// applies. Follow this with [`Self::refresh_allocations`] so the server sees the new
    /// credential before the allocation would otherwise expire.
    ///
    /// [RFC 8656 §5]: https://datatracker.ietf.org/doc/html/rfc8656#section-5
    pub fn update_credentials(&mut self, username: String, password: String) -> Result<()> {
        // RFC 8656 section 5: an allocation's requests stay under the username that created
        // it; only a new password for that username re-keys it.
        let same_username = username == self.login.username;
        let login = Arc::new(Login {
            username,
            password,
            password_algorithms: self.login.password_algorithms.clone(),
        });
        if !same_username {
            self.login = login;
            return Ok(());
        }

        // Each allocation carries the credential it will sign its own Refresh /
        // CreatePermission / ChannelBind with, so they have to be re-keyed too — otherwise
        // the next refresh would still present the retired credential. The realm, the nonce
        // and the password algorithm stay what the server last asked for. An allocation the
        // server gave without a credential stays unsigned until the server asks for one.
        let mut rekeyed = Vec::with_capacity(self.relays.len());
        for (key, relay) in &self.relays {
            rekeyed.push((
                *key,
                relay
                    .credential
                    .with_login(login.clone(), self.crypto_provider.crypto())?,
            ));
        }
        for (key, credential) in rekeyed {
            if let Some(relay) = self.relays.get_mut(&key) {
                relay.credential = Arc::new(credential);
            }
        }
        self.login = login;

        Ok(())
    }

    /// Refreshes every live allocation, re-signing each with the current credential.
    ///
    /// Each allocation is refreshed with its own current lifetime, so this extends rather
    /// than changes it. Intended to follow [`update_credentials`](Self::update_credentials).
    pub fn refresh_allocations(&mut self, now: Instant) -> Result<()> {
        let relays: Vec<(RelayedAddr, Duration)> = self
            .relays
            .iter()
            .filter(|(_, relay)| !relay.releasing)
            .map(|(addr, relay)| (*addr, relay.lifetime))
            .collect();

        for (relayed_addr, lifetime) in relays {
            if let Some(mut relay) = self.relay_by_key(relayed_addr) {
                relay.refresh_allocation(now, lifetime)?;
            }
        }

        Ok(())
    }

    /// Builds a request about `relay`: `attrs`, then the allocation's credential when it has
    /// one, then FINGERPRINT.
    pub(crate) fn build_request(
        &self,
        method: Method,
        attrs: Vec<Box<dyn Setter>>,
        relay: &RelayState,
    ) -> Result<Message> {
        self.build_request_with(method, attrs, &relay.credential)
    }

    /// Builds a request made with `credential`; without one until the server asked for it.
    pub(crate) fn build_request_with(
        &self,
        method: Method,
        attrs: Vec<Box<dyn Setter>>,
        credential: &Credential,
    ) -> Result<Message> {
        self.build_request_as(TransactionId::new(), method, attrs, credential)
    }

    /// Builds the request `id`: `attrs`, SOFTWARE when the client has one (RFC 8656 §5: in
    /// every Allocate and Refresh, and allowed in any other request), what the long-term
    /// credential mechanism adds once the server asked for the credential (RFC 8489 §9.2.3,
    /// §9.2.5: USERNAME or USERHASH, REALM, NONCE, PASSWORD-ALGORITHMS and
    /// PASSWORD-ALGORITHM when the server offered algorithms, and MESSAGE-INTEGRITY-SHA256
    /// then, MESSAGE-INTEGRITY otherwise), and FINGERPRINT.
    pub(crate) fn build_request_as(
        &self,
        id: TransactionId,
        method: Method,
        attrs: Vec<Box<dyn Setter>>,
        credential: &Credential,
    ) -> Result<Message> {
        let mut setters: Vec<Box<dyn Setter + '_>> = vec![
            Box::new(id),
            Box::new(MessageType::new(method, CLASS_REQUEST)),
        ];
        setters.extend(attrs.into_iter().map(|a| a as Box<dyn Setter + '_>));
        if !self.software.text.is_empty() {
            setters.push(Box::new(self.software.clone()));
        }
        if let Some(authentication) = credential.setter(self.crypto_provider.crypto()) {
            setters.push(authentication);
        }
        setters.push(Box::new(FINGERPRINT));

        let mut msg = Message::new();
        msg.build(&setters)?;
        Ok(msg)
    }

    /// Deletes the allocation the server holds for this client's 5-tuple, with a Refresh of
    /// LIFETIME 0 (RFC 8656 §8), when the client keeps no copy of it. Nothing is reported.
    pub(crate) fn release_orphan(
        &mut self,
        now: Instant,
        credential: &Arc<Credential>,
    ) -> Result<()> {
        let msg = self.build_request_with(
            METHOD_REFRESH,
            vec![Box::new(Lifetime(Duration::ZERO))],
            credential,
        )?;
        let to = self.turn_server_addr_or_err()?;
        self.perform_transaction(
            now,
            &msg,
            to,
            TransactionType::OrphanRelease,
            Some(credential.clone()),
        )?;
        Ok(())
    }

    /// Points the client at the alternate server of a 300 (Try Alternate), for an
    /// application that chooses to follow the redirection (RFC 8489 §10, RFC 8656 §7.4). The
    /// client never follows one by itself: the application owns the socket and the choice of
    /// server.
    ///
    /// `redirect` comes from [`ErrorResponse::try_alternate`], which is there only for a 300
    /// that was authenticated with the allocation's credential; RFC 8489 §14.8 has a client
    /// validate the response before it redirects itself. (An application that trusts the
    /// address of an unauthenticated 300, [`ErrorResponse::alternate_server`], makes the
    /// `TryAlternate` itself.) The server of the address family the client reached the old
    /// one over is taken, and becomes [`Client::turn_server_addr`]. The application then
    /// calls [`Client::allocate`] again: the request goes to the alternate server over the
    /// same transport protocol and with the same credentials. Over TLS or DTLS the
    /// application checks the new server's certificate against
    /// [`TryAlternate::domain`] when it is there, and against the name it used for the old
    /// server when it is not.
    ///
    /// # Errors
    ///
    /// Fails, and leaves the server as it is, when an Allocate was already sent to the
    /// alternate server within the last five minutes: the redirection is a loop and RFC 8489
    /// §10 has the client ignore it and take the transaction as failed. Fails as well while
    /// the client holds an allocation (its server cannot change), or when no TURN server is
    /// configured.
    pub fn follow_alternate(
        &mut self,
        now: Instant,
        redirect: &TryAlternate,
    ) -> Result<SocketAddr> {
        let current = self.turn_server_addr_or_err()?;
        if !self.relays.is_empty() {
            return Err(Error::Other(
                "the TURN server cannot change while the client holds an allocation".to_owned(),
            ));
        }
        let server = redirect
            .server_for(current.ip())
            .ok_or(Error::ErrAttributeNotFound)?;
        if !self.redirects.follow(server, now) {
            return Err(Error::Other(format!(
                "redirection loop: an Allocate was sent to {server} within the last five \
                 minutes (RFC 8489 section 10)"
            )));
        }
        debug!("TURN server {current} redirects to {server}");
        self.turn_serv_addr = Some(server);
        Ok(server)
    }

    /// The path MTU to the server, when the application knows it (RFC 8489 Section 6.1): a
    /// request over UDP larger than it allows is refused with `ErrPacketTooBig`. `None` (the
    /// default): unknown, 576 bytes for IPv4 and 1280 for IPv6.
    pub fn set_path_mtu(&mut self, mtu: Option<usize>) {
        self.path_mtu = mtu;
    }

    /// Returns the TURN server address, if configured.
    pub fn turn_server_addr(&self) -> Option<SocketAddr> {
        self.turn_serv_addr
    }

    /// Returns the TURN server address or an error if not configured.
    fn turn_server_addr_or_err(&self) -> Result<SocketAddr> {
        self.turn_serv_addr.ok_or(Error::ErrNilTurnSocket)
    }

    /// Returns the local address this client is bound to.
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// WriteTo sends data to the specified destination using the base socket.
    fn write_to(&mut self, now: Instant, data: &[u8], remote: SocketAddr) {
        self.transmits.push_back(TransportMessage {
            now,
            transport: TransportContext {
                local_addr: self.local_addr,
                peer_addr: remote,
                transport_protocol: self.transport_protocol,
                ecn: None,
            },
            message: BytesMut::from(data),
        });
    }

    // PerformTransaction performs STUN transaction
    fn perform_transaction(
        &mut self,
        now: Instant,
        msg: &Message,
        to: SocketAddr,
        transaction_type: TransactionType,
        credential: Option<Arc<Credential>>,
    ) -> Result<TransactionId> {
        // RFC 8489 Section 6.1: outside MTU probing, a request over UDP does not exceed the
        // path MTU (configured with `set_path_mtu`, else the RFC's 576 / 1280 bytes). Data
        // indications are not requests and are left to the path.
        if self.transport_protocol == TransportProtocol::UDP {
            let (unknown, overhead) = if to.is_ipv4() {
                (UNKNOWN_PATH_MTU_V4, IP_UDP_OVERHEAD_V4)
            } else {
                (UNKNOWN_PATH_MTU_V6, IP_UDP_OVERHEAD_V6)
            };
            let limit = self.path_mtu.unwrap_or(unknown).saturating_sub(overhead);
            if msg.raw.len() > limit {
                debug!(
                    "{} request of {} bytes not sent: the path takes {limit}",
                    msg.typ,
                    msg.raw.len()
                );
                return Err(Error::ErrPacketTooBig);
            }
        }
        trace!(
            "start {} transaction {:?} to {}",
            msg.typ, msg.transaction_id, to
        );
        self.tr_map.start(
            now,
            TransactionConfig {
                transaction_id: msg.transaction_id,
                method: msg.typ.method,
                transaction_type,
                raw: BytesMut::from(&msg.raw[..]),
                local_addr: self.local_addr,
                peer_addr: to,
                transport_protocol: self.transport_protocol,
                credential,
            },
        );
        // In the order it was asked for, with whatever else the client sends.
        while let Some(transmit) = self.tr_map.poll_transmit() {
            self.transmits.push_back(transmit);
        }

        Ok(msg.transaction_id)
    }
}
