//! Allocate: what the request asks for, the exchange that authenticates it, and what the
//! client takes from the success response (RFC 8656 §7).
use std::net::SocketAddr;
use std::ops::Add;
use std::time::{Duration, Instant};

use log::debug;
use stun::attributes::*;
use stun::error_code::*;
use stun::integrity::MessageIntegrity;
use stun::message::*;
use stun::textattrs::*;
use stun::xoraddr::XorMappedAddress;

use super::relay::RelayState;
use super::transaction::TransactionType;
use super::{Client, Event, RelayedAddr, RequestError};
use crate::proto::addfamily::AdditionalAddressFamily;
use crate::proto::addrerror::AddressErrorCode;
use crate::proto::dontfrag::DontFragmentAttr;
use crate::proto::evenport::EvenPort;
use crate::proto::lifetime::Lifetime;
use crate::proto::reqfamily::{
    REQUESTED_FAMILY_IPV4, REQUESTED_FAMILY_IPV6, RequestedAddressFamily,
};
use crate::proto::reqtrans::RequestedTransport;
use crate::proto::rsrvtoken::ReservationToken;
use crate::proto::{PROTO_TCP, PROTO_UDP};
use shared::TransportProtocol;
use shared::error::{Error, Result};

/// What an allocation relays to and from peers: the REQUESTED-TRANSPORT of its Allocate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum RelayTransport {
    /// UDP datagrams (RFC 8656): permissions, Send and Data indications, channels.
    #[default]
    Udp,
    /// TCP connections (RFC 6062): the client connects to peers with
    /// [`Relay::connect`](super::relay::Relay::connect) and accepts their connections from
    /// [`Event::ConnectionAttempt`], each over a
    /// [`DataConnection`](super::data_connection::DataConnection) of its own. The client must
    /// reach the server over TCP or TLS.
    Tcp,
}

/// How long an address family the server had no capacity for is not asked for again
/// (RFC 8656 §7.3: "at least 1 minute").
const INSUFFICIENT_CAPACITY_WAIT: Duration = Duration::from_secs(60);

/// What an Allocate request asks for beyond a UDP relayed address (RFC 8656 §7.1).
///
/// The default asks for nothing more: one relayed address, IPv4 unless the server decides
/// otherwise, for the server's default lifetime.
///
/// The RFC forbids some combinations, and [`Client::allocate_with`] refuses them before
/// anything is sent: `address_family` with `additional_ipv6` or `reservation_token`;
/// `additional_ipv6` with `reservation_token` or with an `even_port` that reserves the next
/// port; `reservation_token` with `even_port`.
///
/// A TCP allocation ([`RelayTransport::Tcp`], RFC 6062 §4.1) takes none of `dont_fragment`,
/// `even_port` and `reservation_token`, and cannot be asked for over UDP.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AllocateOptions {
    /// REQUESTED-TRANSPORT: what the allocation relays, UDP datagrams by default.
    pub transport: RelayTransport,
    /// REQUESTED-ADDRESS-FAMILY: the family of the one relayed address, for example
    /// [`REQUESTED_FAMILY_IPV6`] for an IPv6 relayed address.
    pub address_family: Option<RequestedAddressFamily>,
    /// ADDITIONAL-ADDRESS-FAMILY: an IPv6 relayed address beside the IPv4 one. The server
    /// may give only one of the two; [`Relay::address_error`](super::relay::Relay) then says
    /// why.
    pub additional_ipv6: bool,
    /// LIFETIME: how long the allocation should last without a refresh. A hint; the server
    /// answers with what it grants, which the client then goes by.
    pub lifetime: Option<Duration>,
    /// DONT-FRAGMENT, to find out whether the server supports it and so whether
    /// [`Relay::send_to_dont_fragment`](super::relay::Relay::send_to_dont_fragment) can be
    /// used. A server that does not know the attribute answers 420; the client then makes
    /// the request again without it.
    pub dont_fragment: bool,
    /// EVEN-PORT: an even relayed port, and with `reserve_port` the next port held for a
    /// later allocation, which the response's RESERVATION-TOKEN names.
    pub even_port: Option<EvenPort>,
    /// RESERVATION-TOKEN: use the port a previous allocation reserved.
    pub reservation_token: Option<ReservationToken>,
}

impl AllocateOptions {
    /// Whether RFC 8656 §7.1 lets these go into one request.
    fn check(&self) -> Result<()> {
        let refuse = |why: &str| Err(Error::Other(format!("Allocate options: {why}")));
        if let Some(family) = self.address_family
            && family != REQUESTED_FAMILY_IPV4
            && family != REQUESTED_FAMILY_IPV6
        {
            return Err(Error::ErrInvalidRequestedFamilyValue);
        }
        if self.address_family.is_some() && self.additional_ipv6 {
            return refuse(
                "REQUESTED-ADDRESS-FAMILY and ADDITIONAL-ADDRESS-FAMILY exclude each other",
            );
        }
        if self.address_family.is_some() && self.reservation_token.is_some() {
            return refuse("REQUESTED-ADDRESS-FAMILY cannot go with RESERVATION-TOKEN");
        }
        if self.additional_ipv6 && self.reservation_token.is_some() {
            return refuse("ADDITIONAL-ADDRESS-FAMILY cannot go with RESERVATION-TOKEN");
        }
        if self.additional_ipv6 && self.even_port.is_some_and(|even| even.reserve_port) {
            return refuse("ADDITIONAL-ADDRESS-FAMILY cannot go with EVEN-PORT reserving a port");
        }
        if self.reservation_token.is_some() && self.even_port.is_some() {
            return refuse("EVEN-PORT is left out with RESERVATION-TOKEN");
        }
        // RFC 6062 §4.1: these are UDP's and never go into the Allocate of a TCP allocation.
        if self.transport == RelayTransport::Tcp
            && (self.dont_fragment || self.even_port.is_some() || self.reservation_token.is_some())
        {
            return refuse(
                "a TCP allocation takes no DONT-FRAGMENT, EVEN-PORT or RESERVATION-TOKEN",
            );
        }
        Ok(())
    }

    /// The address family a refusal of this request is about: the one it asked for, IPv6 for
    /// the additional address, IPv4 when it named none. `None` with a reservation token,
    /// which fixes the address.
    fn refused_family(&self) -> Option<RequestedAddressFamily> {
        if self.reservation_token.is_some() {
            None
        } else if self.additional_ipv6 {
            Some(REQUESTED_FAMILY_IPV6)
        } else {
            Some(self.address_family.unwrap_or(REQUESTED_FAMILY_IPV4))
        }
    }

    /// Whether the server may answer this request with a relayed address `addr`.
    fn expects(&self, addr: &SocketAddr) -> bool {
        if self.reservation_token.is_some() || self.additional_ipv6 {
            return true;
        }
        let ipv6 = self.address_family == Some(REQUESTED_FAMILY_IPV6);
        addr.is_ipv6() == ipv6
    }
}

/// An Allocate under way: what it asks for and how far its exchange has come.
pub(crate) struct AllocateState {
    /// The id [`Client::allocate`] handed to its caller, which everything said about the
    /// allocation names.
    pub(crate) report_id: TransactionId,
    pub(crate) options: AllocateOptions,
    /// The long-term key, once the server asked for the credential with a 401.
    pub(crate) key: Vec<u8>,
    pub(crate) nonce: Nonce,
    /// Whether the request was already sent again after a 438 (Stale Nonce).
    stale_nonce_retried: bool,
}

#[cfg(test)]
impl AllocateState {
    /// A default Allocate that has reached its authenticated request, for tests that hand
    /// the client a response directly.
    pub(crate) fn authenticated() -> Self {
        Self {
            report_id: TransactionId::new(),
            options: AllocateOptions::default(),
            key: vec![0u8; 16],
            nonce: Nonce::new(ATTR_NONCE, "nonce".to_owned()),
            stale_nonce_retried: false,
        }
    }
}

/// Why an address family is not asked for.
#[derive(Clone, Copy)]
pub(crate) enum FamilyBlock {
    /// The server does not support it (440).
    Unsupported,
    /// The server had no capacity for it (508): not before this instant.
    Until(Instant),
}

fn family_index(family: RequestedAddressFamily) -> usize {
    usize::from(family == REQUESTED_FAMILY_IPV6)
}

/// Every address `m` carries in attributes of type `t`, XOR-decoded.
fn xor_addresses(m: &Message, t: AttrType) -> Result<Vec<SocketAddr>> {
    let mut out = vec![];
    for attr in m.attributes.0.iter().filter(|a| a.typ == t) {
        let mut one = Message::new();
        one.transaction_id = m.transaction_id;
        one.add(attr.typ, &attr.value);
        let mut addr = XorMappedAddress::default();
        addr.get_from_as(&one, t)?;
        out.push(SocketAddr::new(addr.ip, addr.port));
    }
    Ok(out)
}

impl Client {
    /// Sends an Allocate request for a UDP relayed address to the TURN server.
    ///
    /// Returns the id that [`Event::AllocateResponse`], [`Event::AllocateError`] or
    /// [`Event::TransactionTimeout`] will name.
    pub fn allocate(&mut self, now: Instant) -> Result<TransactionId> {
        self.allocate_with(now, AllocateOptions::default())
    }

    /// Sends an Allocate request with `options` (RFC 8656 §7.1): an address family, a second
    /// (IPv6) address, a lifetime, DONT-FRAGMENT, an even port, a reserved port.
    ///
    /// # Errors
    ///
    /// Fails, with nothing sent, if the RFC forbids the combination of options (see
    /// [`AllocateOptions`]), or if the server has refused the address family and may not be
    /// asked again: for good after a 440 (Address Family not Supported), for a minute after
    /// it had no capacity for one of two families, and after it answered with an address of
    /// a family that was not asked for (RFC 8656 §7.3, §7.4). An application that believes
    /// the cause is gone calls [`Client::clear_allocate_restrictions`].
    pub fn allocate_with(
        &mut self,
        now: Instant,
        options: AllocateOptions,
    ) -> Result<TransactionId> {
        options.check()?;
        // RFC 6062 §4.1: a TCP allocation cannot be had over a UDP association with the
        // server.
        if options.transport == RelayTransport::Tcp
            && self.transport_protocol == TransportProtocol::UDP
        {
            return Err(Error::Other(
                "a TCP allocation is asked for over TCP or TLS to the server, never over UDP"
                    .to_owned(),
            ));
        }
        if self.family_mismatch {
            return Err(Error::Other(
                "the server answered an Allocate with an address family that was not asked for"
                    .to_owned(),
            ));
        }
        if let Some(family) = options.refused_family() {
            let mut families = vec![family];
            if options.additional_ipv6 {
                families.push(REQUESTED_FAMILY_IPV4);
            }
            for family in families {
                match self.family_blocks[family_index(family)] {
                    Some(FamilyBlock::Unsupported) => {
                        return Err(Error::Other(format!(
                            "the server does not support {family} relayed addresses (440)"
                        )));
                    }
                    Some(FamilyBlock::Until(until)) if now < until => {
                        return Err(Error::Other(format!(
                            "the server had no capacity for a {family} relayed address (508)"
                        )));
                    }
                    _ => {}
                }
            }
        }

        // The authenticated request that follows the 401 goes out under an id of its own,
        // drawn here at random rather than derived from this request's (RFC 8489 §6.3.1:
        // every new request takes a new transaction id). It is the one the caller is handed,
        // because that request is the one that carries the allocation.
        let allocation_id = TransactionId::new();
        let state = AllocateState {
            report_id: allocation_id,
            options,
            key: vec![],
            nonce: Nonce::new(ATTR_NONCE, String::new()),
            stale_nonce_retried: false,
        };
        debug!("client.Allocate call PerformTransaction 1");
        self.send_allocate(now, TransactionId::new(), state)?;
        Ok(allocation_id)
    }

    /// Lets [`Client::allocate_with`] ask the server again for what it refused: an address
    /// family it answered 440 or 508 for, or any allocation after it answered with a family
    /// that was not asked for. RFC 8656 §7.3 and §7.4 forbid asking again until the client
    /// "believes the mismatch has been fixed"; calling this says the application does.
    pub fn clear_allocate_restrictions(&mut self) {
        self.family_blocks = [None, None];
        self.family_mismatch = false;
    }

    /// Sends the Allocate of `state` under `id`: with the credential once the server asked
    /// for it, without before.
    fn send_allocate(
        &mut self,
        now: Instant,
        id: TransactionId,
        state: AllocateState,
    ) -> Result<()> {
        let options = &state.options;
        let mut attrs: Vec<Box<dyn Setter>> = vec![Box::new(RequestedTransport {
            // REQUESTED-TRANSPORT names what the allocation relays, not the client-to-server
            // transport (RFC 8656 §7.1): UDP, or TCP for a TCP allocation (RFC 6062 §4.1).
            protocol: match options.transport {
                RelayTransport::Udp => PROTO_UDP,
                RelayTransport::Tcp => PROTO_TCP,
            },
        })];
        if let Some(lifetime) = options.lifetime {
            attrs.push(Box::new(Lifetime(lifetime)));
        }
        if let Some(family) = options.address_family {
            attrs.push(Box::new(family));
        }
        if options.additional_ipv6 {
            attrs.push(Box::new(AdditionalAddressFamily::default()));
        }
        if options.dont_fragment {
            attrs.push(Box::new(DontFragmentAttr));
        }
        if let Some(even_port) = options.even_port {
            attrs.push(Box::new(even_port));
        }
        if let Some(token) = &options.reservation_token {
            attrs.push(Box::new(token.clone()));
        }
        let msg = self.build_request_as(id, METHOD_ALLOCATE, attrs, &state.key, &state.nonce)?;

        let to = self.turn_server_addr_or_err()?;
        let key = (!state.key.is_empty()).then(|| state.key.clone());
        let transaction_type = if key.is_some() {
            TransactionType::AllocateRequest(Box::new(state))
        } else {
            TransactionType::AllocateAttempt(Box::new(state))
        };
        self.perform_transaction(now, &msg, to, transaction_type, key);
        Ok(())
    }

    /// Handles the response to an Allocate; `authenticated` says whether that request
    /// carried the credential.
    pub(super) fn handle_allocate_response(
        &mut self,
        now: Instant,
        response: Message,
        mut state: AllocateState,
        authenticated: bool,
    ) -> Result<()> {
        // A server that wants no credential answers the first request with the allocation
        // (RFC 8656 §7.2 step 1).
        if response.typ.class != CLASS_ERROR_RESPONSE {
            return self.handle_allocate_success(now, &response, state);
        }
        let id = state.report_id;
        let err = RequestError::of(&response);

        // 420 naming DONT-FRAGMENT: the server does not support it. The request is made
        // again without it (RFC 8656 §7.4), and the allocation will not have it.
        if state.options.dont_fragment
            && matches!(&err, RequestError::Rejected(rejected)
                if rejected.code == CODE_UNKNOWN_ATTRIBUTE
                    && rejected.unknown_attributes.contains(&ATTR_DONT_FRAGMENT))
        {
            debug!("the server does not know DONT-FRAGMENT; allocating without it");
            state.options.dont_fragment = false;
            return self.send_allocate(now, TransactionId::new(), state);
        }

        if !authenticated {
            // Only a 401 (Unauthorized) asks for the credential (RFC 8489 §9.2.5). Any other
            // error is the answer to the Allocate, reported with its code under the id
            // allocate() handed out.
            if !err.is(CODE_UNAUTHORIZED) {
                self.allocate_failed(now, &state.options, id, err);
                return Ok(());
            }
            let nonce = match Nonce::get_from_as(&response, ATTR_NONCE) {
                Ok(nonce) => nonce,
                Err(err) => {
                    self.events.push_back(Event::AllocateError(id, err.into()));
                    return Ok(());
                }
            };
            self.realm = match Realm::get_from_as(&response, ATTR_REALM) {
                Ok(realm) => realm,
                Err(err) => {
                    self.events.push_back(Event::AllocateError(id, err.into()));
                    return Ok(());
                }
            };
            state.key = MessageIntegrity::long_term_integrity_key(
                self.username.text.clone(),
                self.realm.text.clone(),
                self.password.clone(),
                self.crypto_provider.crypto(),
            )?;
            state.nonce = nonce;

            // Trying to authorize, under the id allocate() returned, so the caller can
            // match Event::AllocateResponse with it.
            debug!("client.Allocate call PerformTransaction 2");
            return self.send_allocate(now, id, state);
        }

        // 438 (Stale Nonce): the same request once more with the new nonce, and the new
        // realm if there is one, under a new transaction id (RFC 8489 §9.2.5).
        if err.is(CODE_STALE_NONCE)
            && !state.stale_nonce_retried
            && let Ok(nonce) = Nonce::get_from_as(&response, ATTR_NONCE)
        {
            if let Ok(realm) = Realm::get_from_as(&response, ATTR_REALM)
                && !realm.text.is_empty()
                && realm.text != self.realm.text
            {
                state.key = MessageIntegrity::long_term_integrity_key(
                    self.username.text.clone(),
                    realm.text.clone(),
                    self.password.clone(),
                    self.crypto_provider.crypto(),
                )?;
                self.realm = realm;
            }
            state.nonce = nonce;
            state.stale_nonce_retried = true;
            return self.send_allocate(now, TransactionId::new(), state);
        }

        self.allocate_failed(now, &state.options, id, err);
        Ok(())
    }

    /// Reports an Allocate the server refused, and remembers what RFC 8656 §7.4 has the
    /// client not ask again.
    fn allocate_failed(
        &mut self,
        _now: Instant,
        options: &AllocateOptions,
        id: TransactionId,
        err: RequestError,
    ) {
        // 440 (Address Family not Supported): "the client MUST NOT retry the request".
        if err.is(CODE_ADDR_FAMILY_NOT_SUPPORTED)
            && let Some(family) = options.refused_family()
        {
            self.family_blocks[family_index(family)] = Some(FamilyBlock::Unsupported);
        }
        self.events.push_back(Event::AllocateError(id, err));
    }

    /// Takes the allocation of an Allocate success response. `state.key` and `state.nonce`
    /// are the credential the request was made with; the key is empty when the server asked
    /// for none.
    fn handle_allocate_success(
        &mut self,
        now: Instant,
        response: &Message,
        state: AllocateState,
    ) -> Result<()> {
        let id = state.report_id;

        // The relayed address or addresses, the lifetime, and how the server sees us.
        let mut lifetime = Lifetime::default();
        let decoded = xor_addresses(response, ATTR_XOR_RELAYED_ADDRESS).and_then(|relayed| {
            if relayed.is_empty() {
                return Err(Error::ErrAttributeNotFound);
            }
            lifetime.get_from(response)?;
            let mapped = if response.contains(ATTR_XORMAPPED_ADDRESS) {
                xor_addresses(response, ATTR_XORMAPPED_ADDRESS)?
                    .into_iter()
                    .next()
            } else {
                None
            };
            Ok((relayed, mapped))
        });
        let (mut relayed, mapped) = match decoded {
            Ok(decoded) => decoded,
            Err(err) => {
                // The server made an allocation this client cannot use: it is deleted, not
                // left to hold the 5-tuple until it expires (RFC 8656 §7.3), and the caller
                // is told.
                let _ = self.release_orphan(now, &state.key, &state.nonce);
                self.events
                    .push_back(Event::AllocateError(id, RequestError::Failed(err)));
                return Ok(());
            }
        };

        // RFC 8656 §7.3: the addresses must be of families the client is prepared to handle,
        // which are the ones it asked for: one address of the requested family (IPv4 when
        // none was named), or with ADDITIONAL-ADDRESS-FAMILY at most one of each. If not,
        // the allocation is deleted and no other is asked for until the cause is gone.
        relayed.sort_by_key(SocketAddr::is_ipv6);
        let max = if state.options.additional_ipv6 { 2 } else { 1 };
        let one_per_family = relayed.len() == 1 || relayed[0].is_ipv6() != relayed[1].is_ipv6();
        if relayed.len() > max
            || !one_per_family
            || !relayed.iter().all(|addr| state.options.expects(addr))
        {
            let _ = self.release_orphan(now, &state.key, &state.nonce);
            self.family_mismatch = true;
            self.events.push_back(Event::AllocateError(
                id,
                RequestError::Failed(Error::Other(format!(
                    "the server allocated {relayed:?}, not the address family asked for"
                ))),
            ));
            return Ok(());
        }
        let relayed_addr: RelayedAddr = relayed[0];

        // A zero lifetime here is a protocol violation, not a degenerate allocation.
        // RFC 8656 §7.2 has the server take `min(client proposed, server maximum)` and
        // fall back to the *default* lifetime (600 s) whenever that computation does
        // not exceed it — so the value returned by a successful Allocate is never
        // below the default, and certainly never zero. Zero is meaningful only on the
        // Refresh path (§8), where it means "allocation deleted".
        //
        // Accepting it would build a `RelayState` whose `refresh_alloc_timer` is
        // `now.add(0)` — expired the instant it is created — for an allocation that is
        // already gone. That relay then reports an expired refresh deadline forever,
        // which is what a caller polling deadlines hot-loops on. See
        // [webrtc#862](https://github.com/webrtc-rs/webrtc/issues/862).
        if lifetime.0.is_zero() {
            self.events.push_back(Event::AllocateError(
                id,
                RequestError::Failed(Error::Other(
                    "Allocate success response carried LIFETIME=0; RFC 8656 §7.2 \
                     requires at least the default lifetime"
                        .to_owned(),
                )),
            ));
            return Ok(());
        }

        // With two families asked for, the server says in ADDRESS-ERROR-CODE why one is
        // missing: after 440 that family is not asked for again, after 508 not for a minute
        // (RFC 8656 §7.3).
        let mut address_error = AddressErrorCode::default();
        let address_error = address_error
            .get_from(response)
            .is_ok()
            .then_some(address_error);
        if let Some(refused) = &address_error {
            let block = if refused.code == CODE_ADDR_FAMILY_NOT_SUPPORTED {
                Some(FamilyBlock::Unsupported)
            } else if refused.code == CODE_INSUFFICIENT_CAPACITY {
                Some(FamilyBlock::Until(now.add(INSUFFICIENT_CAPACITY_WAIT)))
            } else {
                None
            };
            if block.is_some() {
                self.family_blocks[family_index(refused.family)] = block;
            }
        }

        let mut token = ReservationToken::default();
        let reservation_token = token.get_from(response).is_ok().then_some(token);

        let mut relay = RelayState::new(
            now,
            relayed_addr,
            state.key,
            state.nonce,
            lifetime.0,
            self.allocation_refresh_interval_cap,
        );
        relay.addrs = relayed;
        relay.mapped_addr = mapped;
        relay.reservation_token = reservation_token;
        relay.address_error = address_error;
        // The server took the request with DONT-FRAGMENT in it, so it supports it.
        relay.dont_fragment = state.options.dont_fragment;
        relay.transport = state.options.transport;
        self.relays.insert(relayed_addr, relay);
        self.events
            .push_back(Event::AllocateResponse(id, relayed_addr));
        Ok(())
    }
}
