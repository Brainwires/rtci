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
mod client_stale_nonce_test;
#[cfg(test)]
mod client_tcp_allocation_test;
#[cfg(test)]
mod client_test;
#[cfg(test)]
mod test_server;

mod allocation;
/// Channel bindings, which replace the 36-byte Data indication header with a 4-byte one.
pub mod binding;
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

use stun::attributes::*;
use stun::integrity::*;
use stun::message::*;
use stun::textattrs::*;
use stun::xoraddr::*;

use allocation::FamilyBlock;
pub use allocation::{AllocateOptions, RelayTransport};
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

const DEFAULT_RTO_IN_MS: u64 = 200;
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
/// Every variant carries the [`TransactionId`] of the request it answers, so a caller can
/// match responses to the requests it issued.
#[non_exhaustive]
pub enum Event {
    /// A request exhausted its retransmissions without a response.
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

enum AllocateState {
    Attempting,
    Requesting(TextAttribute),
}

//              interval [msec]
// 0: 0 ms      +500
// 1: 500 ms	+1000
// 2: 1500 ms   +2000
// 3: 3500 ms   +4000
// 4: 7500 ms   +8000
// 5: 15500 ms  +16000
// 6: 31500 ms  +32000
// -: 63500 ms  failed

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
    /// The long-term credential username for the TURN server.
    pub username: String,
    /// The long-term credential password.
    pub password: String,
    /// The authentication realm, used in the `MESSAGE-INTEGRITY` computation.
    pub realm: String,
    /// An optional `SOFTWARE` attribute value, sent for diagnostics.
    pub software: String,
    /// The initial retransmission timeout in milliseconds; each retry doubles it.
    pub rto_in_ms: u64,
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
            software: "".to_string(),
            rto_in_ms: 0,
            allocation_refresh_interval_cap: None,
        }
    }
}

/// Client is a STUN client
pub struct Client {
    crypto_provider: Arc<dyn RTCCryptoProvider>,
    stun_serv_addr: Option<SocketAddr>,
    turn_serv_addr: Option<SocketAddr>,
    local_addr: SocketAddr,
    transport_protocol: TransportProtocol,
    username: Username,
    password: String,
    realm: Realm,
    software: Software,
    tr_map: TransactionMap,
    rto_in_ms: u64,
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
            username: Username::new(ATTR_USERNAME, config.username),
            password: config.password,
            realm: Realm::new(ATTR_REALM, config.realm),
            software: Software::new(ATTR_SOFTWARE, config.software),
            tr_map: TransactionMap::new(),
            rto_in_ms: if config.rto_in_ms != 0 {
                config.rto_in_ms
            } else {
                DEFAULT_RTO_IN_MS
            },
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

        if msg.typ.class == CLASS_INDICATION && msg.typ.method == METHOD_CONNECTION_ATTEMPT {
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

        if msg.typ.class == CLASS_INDICATION {
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

            return Ok(());
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

        // A response to a signed request is believed only if it is signed with the same key
        // (RFC 8489 §9.2.5); anything else is dropped as if never received, so the
        // transaction stays open and its retransmissions continue.
        if let Some(key) = &tr.integrity_key
            && !response_is_authentic(&mut msg, key, self.crypto_provider.crypto())
        {
            debug!("discarding {}: MESSAGE-INTEGRITY missing or wrong", msg);
            return Ok(());
        }

        if let Some(tr) = self.tr_map.delete(&msg.transaction_id) {
            match msg.typ.method {
                METHOD_BINDING => {
                    if msg.typ.class == CLASS_ERROR_RESPONSE {
                        let mut code = ErrorCodeAttribute::default();
                        let err = if code.get_from(&msg).is_err() {
                            Error::Other(format!("{}", msg.typ))
                        } else {
                            Error::Other(format!("{} (error {})", msg.typ, code))
                        };
                        self.events
                            .push_back(Event::BindingError(tr.transaction_id, err));
                    } else {
                        let mut refl_addr = XorMappedAddress::default();
                        match refl_addr.get_from(&msg) {
                            Ok(_) => {
                                self.events.push_back(Event::BindingResponse(
                                    tr.transaction_id,
                                    ReflexiveAddr::new(refl_addr.ip, refl_addr.port),
                                ));
                            }
                            Err(err) => {
                                self.events
                                    .push_back(Event::BindingError(tr.transaction_id, err));
                            }
                        }
                    }
                }
                METHOD_ALLOCATE => match tr.transaction_type {
                    TransactionType::AllocateAttempt(state) => {
                        self.handle_allocate_response(now, msg, *state, false)?;
                    }
                    TransactionType::AllocateRequest(state) => {
                        self.handle_allocate_response(now, msg, *state, true)?;
                    }
                    _ => {}
                },
                // A release of an allocation the client did not keep: nothing to do.
                METHOD_REFRESH if matches!(tr.transaction_type, TransactionType::OrphanRelease) => {
                }
                METHOD_REFRESH
                    if matches!(tr.transaction_type, TransactionType::FamilyRelease(..)) =>
                {
                    if let TransactionType::FamilyRelease(relayed_addr, family, retry) =
                        tr.transaction_type
                    {
                        let mut relay = Relay {
                            relayed_addr,
                            client: self,
                        };
                        relay.handle_family_release_response(now, msg, family, retry)?;
                    }
                }
                METHOD_CREATE_PERMISSION => {
                    if let TransactionType::CreatePermissionRequest(
                        relayed_addr,
                        peer_addr,
                        peer_addrs,
                        retry,
                    ) = tr.transaction_type
                    {
                        let mut relay = Relay {
                            relayed_addr,
                            client: self,
                        };
                        relay.handle_create_permission_response(
                            now, msg, peer_addr, peer_addrs, retry,
                        )?;
                    }
                }
                METHOD_REFRESH => {
                    if let TransactionType::RefreshRequest(relayed_addr, lifetime, retry) =
                        tr.transaction_type
                    {
                        let mut relay = Relay {
                            relayed_addr,
                            client: self,
                        };
                        relay.handle_refresh_response(now, msg, lifetime, retry)?;
                    }
                }
                METHOD_CONNECT => {
                    if let TransactionType::ConnectRequest(relayed_addr, peer_addr, retry) =
                        tr.transaction_type
                    {
                        let mut relay = Relay {
                            relayed_addr,
                            client: self,
                        };
                        relay.handle_connect_response(now, msg, peer_addr, retry)?;
                    }
                }
                METHOD_CHANNEL_BIND => {
                    if let TransactionType::ChannelBindRequest(relayed_addr, bind_addr, retry) =
                        tr.transaction_type
                    {
                        let mut relay = Relay {
                            relayed_addr,
                            client: self,
                        };
                        relay.handle_channel_bind_response(now, msg, bind_addr, retry)?;
                    }
                }
                _ => {}
            }
        }

        Ok(())
    }

    /// Deals with a transaction that exhausted its retransmissions.
    ///
    /// A Refresh or ChannelBind is started once more as a new transaction, so one lost burst
    /// does not let the allocation lapse or leave a channel unbound for good. A ChannelBind that
    /// fails again returns its binding to idle, so the next send binds it again. Anything not
    /// started again is reported as [`Event::TransactionTimeout`], under the id its caller
    /// knows.
    fn handle_transaction_timeout(&mut self, now: Instant, tr: Transaction) {
        let id = tr.transaction_type.report_id(tr.transaction_id);
        match tr.transaction_type {
            TransactionType::RefreshRequest(relayed_addr, lifetime, retry) => {
                if !retry.timeout
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
                relay.refresh_failed(now, lifetime, RequestError::Failed(Error::ErrTimeout));
                if releasing {
                    // The release is over, and reported as that.
                    return;
                }
            }
            TransactionType::ChannelBindRequest(relayed_addr, bind_addr, retry) => {
                if !retry.timeout
                    && let Some(mut relay) = self.relay_by_key(relayed_addr)
                    && relay
                        .rebind_channel(now, bind_addr, retry.after_timeout(tr.transaction_id))
                        .is_ok()
                {
                    debug!("channel bind for {bind_addr} timed out; sent again");
                    return;
                }
                if let Some(mut relay) = self.relay_by_key(relayed_addr) {
                    relay.channel_bind_timed_out(bind_addr);
                }
            }
            TransactionType::FamilyRelease(relayed_addr, family, retry) => {
                if !retry.timeout
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
                        RequestError::Failed(Error::ErrTimeout),
                    ));
                }
                return;
            }
            TransactionType::ConnectRequest(relayed_addr, peer_addr, _) => {
                // Nothing is outstanding for the peer any more.
                if let Some(relay) = self.relays.get_mut(&relayed_addr) {
                    relay.connecting.remove(&peer_addr);
                }
            }
            TransactionType::OrphanRelease => return,
            _ => {}
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
    /// handing it to a client that will silently discard it — [`handle_read`](Self::handle_read)
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
            let attrs: Vec<Box<dyn Setter + '_>> = if !self.software.text.is_empty() {
                vec![
                    Box::new(TransactionId::new()),
                    Box::new(BINDING_REQUEST),
                    Box::new(self.software.clone()),
                ]
            } else {
                vec![Box::new(TransactionId::new()), Box::new(BINDING_REQUEST)]
            };

            let mut msg = Message::new();
            msg.build(&attrs)?;
            msg
        };

        debug!("client.SendBindingRequestTo call PerformTransaction 1");
        Ok(self.perform_transaction(now, &msg, to, TransactionType::BindingRequest, None))
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
    /// A new username takes effect for the next [`allocate`](Self::allocate). On a live
    /// allocation it makes the next Refresh fail: the 441 is reported as
    /// [`Event::RefreshError`], and the allocation ends when its lifetime runs out
    /// ([`Event::AllocationLost`]). To change the username, [`Relay::close`] the allocation,
    /// wait for [`Event::AllocationReleased`], then update the credential and allocate.
    ///
    /// The realm is *not* re-negotiated. It was learned from the server's 401 during the
    /// first `Allocate`, and a credential rotation keeps the same server, so it still
    /// applies. Follow this with [`Self::refresh_allocations`] so the server sees the new
    /// credential before the allocation would otherwise expire.
    ///
    /// [RFC 8656 §5]: https://datatracker.ietf.org/doc/html/rfc8656#section-5
    pub fn update_credentials(&mut self, username: String, password: String) -> Result<()> {
        let username = Username::new(ATTR_USERNAME, username);
        let long_term_integrity_key = MessageIntegrity::long_term_integrity_key(
            username.text.clone(),
            self.realm.text.clone(),
            password.clone(),
            self.crypto_provider.crypto(),
        )?;
        self.username = username;
        self.password = password;

        // Each allocation carries the integrity it will sign its own Refresh /
        // CreatePermission / ChannelBind with, so they have to be re-signed too — otherwise
        // the next refresh would still present the retired credential.
        for relay in self.relays.values_mut() {
            // An allocation the server gave without a credential stays unsigned until the
            // server asks for one.
            if relay.key().is_some() {
                relay.long_term_integrity_key = long_term_integrity_key.clone();
            }
        }

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
        self.build_request_with(method, attrs, &relay.long_term_integrity_key, &relay.nonce)
    }

    /// Builds a request signed with `key` and `nonce`; unsigned when `key` is empty.
    pub(crate) fn build_request_with(
        &self,
        method: Method,
        attrs: Vec<Box<dyn Setter>>,
        key: &[u8],
        nonce: &Nonce,
    ) -> Result<Message> {
        self.build_request_as(TransactionId::new(), method, attrs, key, nonce)
    }

    /// Builds the request `id`: `attrs`, SOFTWARE when the client has one (RFC 8656 §5: in
    /// every Allocate and Refresh, and allowed in any other request), the credential when
    /// `key` is not empty, and FINGERPRINT.
    pub(crate) fn build_request_as(
        &self,
        id: TransactionId,
        method: Method,
        attrs: Vec<Box<dyn Setter>>,
        key: &[u8],
        nonce: &Nonce,
    ) -> Result<Message> {
        let mut setters: Vec<Box<dyn Setter + '_>> = vec![
            Box::new(id),
            Box::new(MessageType::new(method, CLASS_REQUEST)),
        ];
        setters.extend(attrs);
        if !self.software.text.is_empty() {
            setters.push(Box::new(self.software.clone()));
        }
        if !key.is_empty() {
            setters.push(Box::new(self.username.clone()));
            setters.push(Box::new(self.realm.clone()));
            setters.push(Box::new(nonce.clone()));
            setters.push(Box::new(MessageIntegrity::new_raw_integrity_with_provider(
                key.to_vec(),
                self.crypto_provider.crypto(),
            )));
        }
        setters.push(Box::new(FINGERPRINT));

        let mut msg = Message::new();
        msg.build(&setters)?;
        Ok(msg)
    }

    /// Deletes the allocation the server holds for this client's 5-tuple, with a Refresh of
    /// LIFETIME 0 (RFC 8656 §8), when the client keeps no copy of it. Nothing is reported.
    pub(crate) fn release_orphan(&mut self, now: Instant, key: &[u8], nonce: &Nonce) -> Result<()> {
        let msg = self.build_request_with(
            METHOD_REFRESH,
            vec![Box::new(Lifetime(Duration::ZERO))],
            key,
            nonce,
        )?;
        let to = self.turn_server_addr_or_err()?;
        self.perform_transaction(
            now,
            &msg,
            to,
            TransactionType::OrphanRelease,
            (!key.is_empty()).then(|| key.to_vec()),
        );
        Ok(())
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

    /// username returns username
    fn username(&self) -> Username {
        self.username.clone()
    }

    /// realm return realm
    fn realm(&self) -> Realm {
        self.realm.clone()
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
        integrity_key: Option<Vec<u8>>,
    ) -> TransactionId {
        let tr = Transaction::new(TransactionConfig {
            now,
            transaction_id: msg.transaction_id,
            transaction_type,
            raw: BytesMut::from(&msg.raw[..]),
            local_addr: self.local_addr,
            peer_addr: to,
            transport_protocol: self.transport_protocol,
            interval: self.rto_in_ms,
            integrity_key,
        });

        trace!(
            "start {} transaction {:?} to {}",
            msg.typ, msg.transaction_id, tr.peer_addr
        );
        self.tr_map.insert(msg.transaction_id, tr);

        self.write_to(now, &msg.raw, to);

        msg.transaction_id
    }
}

/// Whether a response to a request signed with `key` may be acted on.
///
/// It must carry a MESSAGE-INTEGRITY computed with that key. The one exception is a 401
/// (Unauthorized) or 438 (Stale Nonce) error without one: the server cannot or must not sign
/// those, since they report that the credential or nonce it would sign with is not accepted
/// (RFC 8489 §9.2.4 and §10.2.3 put their handling before the integrity check). A 401 or 438
/// that does carry a MESSAGE-INTEGRITY must still verify.
pub(crate) fn response_is_authentic(
    msg: &mut Message,
    key: &[u8],
    crypto: &dyn crypto::RTCCrypto,
) -> bool {
    if !msg.contains(ATTR_MESSAGE_INTEGRITY) {
        if msg.typ.class != CLASS_ERROR_RESPONSE {
            return false;
        }
        let mut code = ErrorCodeAttribute::default();
        return code.get_from(msg).is_ok()
            && (code.code == stun::error_code::CODE_UNAUTHORIZED
                || code.code == stun::error_code::CODE_STALE_NONCE);
    }
    MessageIntegrity::check(msg, key, crypto).is_ok()
}
