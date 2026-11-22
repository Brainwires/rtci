//! A Sans-I/O STUN client.
//!
//! Sends requests to one server and matches the responses, with the retransmission timer of
//! RFC 8489 section 6.2: over UDP a request is sent again at RTO, 2 RTO, 4 RTO and so on, Rc
//! times in all, and the transaction fails Rm x RTO after the last one; over TCP it is sent
//! once and fails after Ti. The RTO starts at a configurable value (500 ms) and then follows
//! the round-trip times the server shows (RFC 6298). Build one with
//! [`ClientBuilder`](crate::client::ClientBuilder); drive it with datagrams and time.
//!
//! What counts as the response is checked as section 6.3 says: it comes from the server, is a
//! success or error response of the request's method, has a valid FINGERPRINT if it has one,
//! and carries no comprehension-required attribute the client does not know.
use bytes::BytesMut;
use shared::error::*;
use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::agent::*;
use crate::attributes::*;
use crate::error_code::ErrorCodeAttribute;
use crate::message::*;
use crate::timer::{
    DEFAULT_MAX_OUTSTANDING, DEFAULT_RC, DEFAULT_RM, DEFAULT_RTO, DEFAULT_TI, RtoEstimator,
    Schedule,
};
use crate::validated::{Rejection, Validator};
use crypto::{RTCCryptoProvider, SecretVec};
use shared::{TaggedBytesMut, TransportContext, TransportMessage, TransportProtocol};

const DEFAULT_TIMEOUT_RATE: Duration = Duration::from_millis(5);
const DEFAULT_MAX_BUFFER_SIZE: usize = 8;
/// RFC 8489 section 6.1: with an unknown path MTU, the IP packet of a STUN message over UDP is
/// at most 576 bytes for IPv4 and 1280 bytes for IPv6.
const UNKNOWN_PATH_MTU_V4: usize = 576;
const UNKNOWN_PATH_MTU_V6: usize = 1280;
/// IP and UDP headers: 20 + 8 bytes for IPv4, 40 + 8 for IPv6.
const IP_UDP_OVERHEAD_V4: usize = 28;
const IP_UDP_OVERHEAD_V6: usize = 48;

/// A [`Message`] together with the instant the caller is sending it at.
///
/// `Rin` is a [`TaggedBytesMut`], which carries a timestamp; without this the write channel
/// would not, and `handle_write` would have to ask the clock for one. A STUN client's first
/// action is typically a write before any read, so a retained instant is not an option here —
/// it would still be the construction seed.
pub struct TaggedMessage {
    /// When the caller is sending this message.
    pub now: Instant,
    /// The STUN message to send.
    pub message: Message,
}

/// ClientTransaction represents transaction in progress.
/// If transaction is succeed or failed, f will be called
/// provided by event.
/// Concurrent access is invalid.
#[derive(Debug, Clone)]
pub struct ClientTransaction {
    id: TransactionId,
    method: Method,
    /// How many times the request has been sent.
    sent: u32,
    start: Instant,
    /// The RTO this transaction started with; each retransmission waits twice as long as the
    /// one before it.
    rto: Duration,
    /// When the request is sent again or, after the last one, the transaction fails.
    deadline: Instant,
    /// A response was discarded because its integrity did not hold.
    discarded: bool,
    raw: Vec<u8>,
}

struct ClientSettings {
    buffer_size: usize,
    rto: Duration,
    rto_rate: Duration,
    rc: u32,
    rm: u32,
    ti: Duration,
    estimate_rto: bool,
    max_outstanding: usize,
    path_mtu: Option<usize>,
    known_attributes: Vec<AttrType>,
    integrity: Option<(SecretVec, Arc<dyn RTCCryptoProvider>)>,
    closed: bool,
}

impl Default for ClientSettings {
    fn default() -> Self {
        ClientSettings {
            buffer_size: DEFAULT_MAX_BUFFER_SIZE,
            rto: DEFAULT_RTO,
            rto_rate: DEFAULT_TIMEOUT_RATE,
            rc: DEFAULT_RC,
            rm: DEFAULT_RM,
            ti: DEFAULT_TI,
            estimate_rto: true,
            max_outstanding: DEFAULT_MAX_OUTSTANDING,
            path_mtu: None,
            known_attributes: default_known_attributes(),
            integrity: None,
            closed: false,
        }
    }
}

/// The comprehension-required attributes a Binding client understands: those of RFC 8489,
/// and the three of RFC 3489 that servers of that generation still put in a Binding response
/// (SOURCE-ADDRESS, CHANGED-ADDRESS, REFLECTED-FROM), which are read past.
fn default_known_attributes() -> Vec<AttrType> {
    let mut known = STUN_ATTRIBUTES.to_vec();
    known.extend_from_slice(&[ATTR_SOURCE_ADDRESS, ATTR_CHANGED_ADDRESS, AttrType(0x000b)]);
    known
}

#[derive(Default)]
/// Builds a [`Client`] with a chosen transaction timeout, retransmission schedule and
/// handler.
pub struct ClientBuilder {
    settings: ClientSettings,
}

impl ClientBuilder {
    /// Sets the initial RTO (RFC 8489 section 6.2.1; 500 ms by default, and the RFC asks for
    /// no less unless something else bounds the rate, as ICE's pacing does).
    ///
    /// It is the RTO of the first transaction and the floor of every later one: the RTO then
    /// follows the server's round-trip time upwards (see
    /// [`with_rto_estimation`](Self::with_rto_estimation)).
    pub fn with_rto(mut self, rto: Duration) -> Self {
        self.settings.rto = rto;
        self
    }

    /// Sets Rc, how many times a request is sent before the transaction fails (RFC 8489
    /// section 6.2.1; 7 by default). Values below 1 are 1.
    pub fn with_rc(mut self, rc: u32) -> Self {
        self.settings.rc = rc.max(1);
        self
    }

    /// Sets Rm: the transaction fails Rm x RTO after the last request (RFC 8489 section
    /// 6.2.1; 16 by default).
    pub fn with_rm(mut self, rm: u32) -> Self {
        self.settings.rm = rm;
        self
    }

    /// Sets Ti, how long a request waits for its response over a reliable transport, where it
    /// is never retransmitted (RFC 8489 section 6.2.2; 39.5 s by default).
    pub fn with_ti(mut self, ti: Duration) -> Self {
        self.settings.ti = ti;
        self
    }

    /// Turns the RFC 6298 computation of the RTO on or off (on by default).
    ///
    /// On: a request answered without a retransmission gives a round-trip sample, and the RTO
    /// of the next transaction is `SRTT + 4 x RTTVAR`, to 1 ms, never below the initial RTO.
    /// It is kept for the server and dropped after ten minutes without a transaction.
    /// Off: every transaction starts at the initial RTO.
    pub fn with_rto_estimation(mut self, on: bool) -> Self {
        self.settings.estimate_rto = on;
        self
    }

    /// Sets how many transactions may be outstanding at once (RFC 8489 section 6.2; 10 by
    /// default). A request past the limit is refused by `handle_write`. `0` lifts the limit,
    /// for a caller that limits its rate some other way.
    pub fn with_max_outstanding_transactions(mut self, max: usize) -> Self {
        self.settings.max_outstanding = max;
        self
    }

    /// Sets the path MTU to the server, when the caller knows it: a message over UDP then has
    /// to fit an IP packet of that size (RFC 8489 section 6.1).
    ///
    /// Without it the RFC's sizes for an unknown path MTU apply: an IP packet of 576 bytes
    /// for IPv4 and 1280 bytes for IPv6, which is a STUN message of 548 or 1232 bytes.
    /// `handle_write` refuses a larger one, so that it is never fragmented on the way. A
    /// message that probes the path MTU is the one case where the RFC lets the rule go: set
    /// `usize::MAX` for the client that sends it.
    pub fn with_path_mtu(mut self, mtu: usize) -> Self {
        self.settings.path_mtu = Some(mtu);
        self
    }

    /// Sets the comprehension-required attributes the usage understands in a response:
    /// [`STUN_ATTRIBUTES`] plus its own. A response that carries any other fails its
    /// transaction with [`TransactionFailure::UnknownAttributes`] (RFC 8489 sections 6.3.3 and
    /// 6.3.4).
    ///
    /// The default is `STUN_ATTRIBUTES` and RFC 3489's SOURCE-ADDRESS, CHANGED-ADDRESS and
    /// REFLECTED-FROM, which old servers still send in a Binding response.
    pub fn with_known_attributes(mut self, known: &[AttrType]) -> Self {
        self.settings.known_attributes = known.to_vec();
        self
    }

    /// Requires every response to be authenticated with `key` (the short-term credential
    /// mechanism, RFC 8489 section 9.1.4).
    ///
    /// A response whose integrity attribute is absent or wrong is discarded as if it had
    /// never arrived, so retransmissions continue; if the transaction then ends without an
    /// authentic response, it ends with [`TransactionFailure::IntegrityViolation`] rather than
    /// a timeout. Over a reliable transport such a response ends the transaction at once.
    /// The message of [`StunEvent::Message`] then holds the authenticated attributes only.
    ///
    /// The long-term mechanism has responses that are valid unsigned (401, 438): its caller
    /// leaves this off and uses
    /// [`LongTermCredentials::check_response`](crate::long_term::LongTermCredentials::check_response).
    pub fn with_response_integrity(
        mut self,
        key: impl Into<Vec<u8>>,
        provider: Arc<dyn RTCCryptoProvider>,
    ) -> Self {
        self.settings.integrity = Some((SecretVec::new(key.into()), provider));
        self
    }

    /// with_timeout_rate sets RTO timer minimum resolution.
    #[deprecated(
        note = "has no effect: a sans-I/O client has no timer of its own, the caller's \
                `handle_timeout` calls set the resolution"
    )]
    pub fn with_timeout_rate(mut self, d: Duration) -> Self {
        self.settings.rto_rate = d;
        self
    }

    /// with_buffer_size sets buffer size.
    #[deprecated(note = "has no effect: the client buffers nothing of a fixed size")]
    pub fn with_buffer_size(mut self, buffer_size: usize) -> Self {
        self.settings.buffer_size = buffer_size;
        self
    }

    /// Disables retransmissions: each request is sent once (Rc = 1) and its transaction fails
    /// Rm x RTO later.
    ///
    /// A client built for [`TransportProtocol::TCP`] never retransmits and waits Ti, with or
    /// without this (RFC 8489 section 6.2.2).
    pub fn with_no_retransmit(mut self) -> Self {
        self.settings.rc = 1;
        self
    }

    /// A builder with the RFC's default timings.
    pub fn new() -> Self {
        ClientBuilder {
            settings: ClientSettings::default(),
        }
    }

    /// Builds the client for the given local and remote addresses.
    ///
    /// # Errors
    ///
    /// Fails if the configured timings are inconsistent.
    pub fn build(
        self,
        now: Instant,
        local: SocketAddr,
        remote: SocketAddr,
        protocol: TransportProtocol,
    ) -> Result<Client> {
        Ok(Client::new(now, local, remote, protocol, self.settings))
    }
}

/// Client simulates "connection" to STUN server.
pub struct Client {
    local: SocketAddr,
    remote: SocketAddr,
    transport_protocol: TransportProtocol,
    settings: ClientSettings,
    rto: RtoEstimator,
    transactions: HashMap<TransactionId, ClientTransaction>,
    transmits: VecDeque<TransportMessage<BytesMut>>,
    events: VecDeque<StunEvent>,

    /// The newest instant a caller has supplied, seeded at construction.
    now: Instant,
}

impl Client {
    fn new(
        now: Instant,
        local: SocketAddr,
        remote: SocketAddr,
        transport_protocol: TransportProtocol,
        settings: ClientSettings,
    ) -> Self {
        Self {
            local,
            remote,
            transport_protocol,
            rto: RtoEstimator::new(settings.rto, settings.estimate_rto),
            settings,
            transactions: HashMap::new(),
            transmits: VecDeque::new(),
            events: VecDeque::new(),
            now,
        }
    }

    /// Records the newest instant a caller has supplied.
    ///
    /// `max` rather than assignment: an outbound message carries the instant of the input that
    /// caused it, so a caller can legitimately present an older one than the newest seen.
    fn observe(&mut self, now: Instant) {
        self.now = now.max(self.now);
    }

    /// The address this client sends from.
    pub fn local_addr(&self) -> SocketAddr {
        self.local
    }

    /// The STUN server this client talks to.
    pub fn peer_addr(&self) -> SocketAddr {
        self.remote
    }

    /// The RTO the next transaction starts with: the initial RTO, or what the server's
    /// round-trip times have made of it.
    pub fn rto(&self) -> Duration {
        self.rto.rto()
    }

    /// How many transactions are waiting for their response.
    pub fn outstanding_transactions(&self) -> usize {
        self.transactions.len()
    }

    /// The largest STUN message this client sends: unbounded over a reliable transport, and
    /// over UDP what fits the path MTU, known or assumed (RFC 8489 section 6.1).
    pub fn max_message_size(&self) -> usize {
        if self.is_reliable() {
            return usize::MAX;
        }
        let (unknown, overhead) = if self.remote.is_ipv4() {
            (UNKNOWN_PATH_MTU_V4, IP_UDP_OVERHEAD_V4)
        } else {
            (UNKNOWN_PATH_MTU_V6, IP_UDP_OVERHEAD_V6)
        };
        self.settings
            .path_mtu
            .unwrap_or(unknown)
            .saturating_sub(overhead)
    }

    /// RFC 8489 section 6.2.2: a reliable transport retransmits for the client.
    fn is_reliable(&self) -> bool {
        self.transport_protocol == TransportProtocol::TCP
    }

    fn transmit(&mut self, now: Instant, raw: &[u8]) {
        self.transmits.push_back(TransportMessage {
            now,
            transport: TransportContext {
                local_addr: self.local,
                peer_addr: self.remote,
                ecn: None,
                transport_protocol: self.transport_protocol,
            },
            message: BytesMut::from(raw),
        });
    }

    /// When the request of `ct`, just sent at `now` for the `ct.sent`-th time, is due again
    /// (RFC 8489 sections 6.2.1 and 6.2.2).
    fn next_deadline(&self, ct: &ClientTransaction, now: Instant) -> Instant {
        Schedule {
            rc: self.settings.rc,
            rm: self.settings.rm,
            ti: self.settings.ti,
        }
        .next_deadline(self.is_reliable(), ct.start, ct.rto, ct.sent, now)
    }

    /// Ends a transaction with `event`.
    fn finish(&mut self, id: TransactionId, event: StunEvent) {
        self.transactions.remove(&id);
        self.events.push_back(event);
    }

    /// The transactions whose deadline has come, in the order of their deadlines.
    fn due(&self, now: Instant) -> Vec<TransactionId> {
        let mut due: Vec<(Instant, TransactionId)> = self
            .transactions
            .values()
            .filter(|ct| ct.deadline <= now)
            .map(|ct| (ct.deadline, ct.id))
            .collect();
        due.sort_by_key(|(deadline, id)| (*deadline, id.0));
        due.into_iter().map(|(_, id)| id).collect()
    }
}

impl sansio::Protocol<TaggedBytesMut, TaggedMessage, ()> for Client {
    type Rout = ();
    type Wout = TaggedBytesMut;
    type Eout = StunEvent;
    type Error = Error;
    type Time = Instant;

    /// Takes a datagram (or one framed message of a stream) from the network.
    ///
    /// What is not the response to an outstanding request is dropped without an event (RFC
    /// 8489 section 6.3): a message from another address than the server's, a request or an
    /// indication, a response with an unknown transaction id or of another method, and a
    /// message whose FINGERPRINT does not match.
    ///
    /// # Errors
    ///
    /// Fails when the server's datagram is not a STUN message.
    fn handle_read(&mut self, msg: TaggedBytesMut) -> Result<()> {
        self.observe(msg.now);
        if msg.transport.peer_addr != self.remote {
            return Ok(());
        }
        let mut stun_msg = Message::new();
        stun_msg.unmarshal_binary(&msg.message)?;

        let class = stun_msg.typ.class;
        if class != CLASS_SUCCESS_RESPONSE && class != CLASS_ERROR_RESPONSE {
            return Ok(());
        }
        let id = stun_msg.transaction_id;
        let Some(ct) = self.transactions.get(&id) else {
            return Ok(());
        };
        if ct.method != stun_msg.typ.method {
            return Ok(());
        }
        let (sent, start) = (ct.sent, ct.start);

        let validator = Validator::new().known_attributes(&self.settings.known_attributes);
        let checked = match &self.settings.integrity {
            Some((key, provider)) => {
                validator.authenticate(&stun_msg, key.as_ref(), provider.crypto())
            }
            None => validator.unauthenticated(&stun_msg),
        };
        let valid = match checked {
            Ok(valid) => valid,
            Err(Rejection::FingerprintMissing | Rejection::FingerprintMismatch) => return Ok(()),
            Err(Rejection::IntegrityMissing | Rejection::IntegrityMismatch) => {
                if self.is_reliable() {
                    // RFC 8489 section 9.1.4: over a reliable transport the transaction ends
                    // at once.
                    self.finish(
                        id,
                        StunEvent::TransactionFailed {
                            id,
                            reason: TransactionFailure::IntegrityViolation,
                        },
                    );
                } else if let Some(ct) = self.transactions.get_mut(&id) {
                    // Discarded as if it had never arrived; retransmissions continue.
                    ct.discarded = true;
                }
                return Ok(());
            }
            Err(Rejection::UnknownAttributes(unknown)) => {
                self.finish(
                    id,
                    StunEvent::TransactionFailed {
                        id,
                        reason: TransactionFailure::UnknownAttributes(unknown),
                    },
                );
                return Ok(());
            }
            Err(Rejection::Crypto(error)) => return Err(Error::Crypto(error)),
        };

        // Karn's algorithm: only a request that was sent once gives a round-trip time.
        if sent == 1 {
            self.rto
                .sample(msg.now.saturating_duration_since(start), msg.now);
        }

        // RFC 8489 section 6.3.4: an error response without ERROR-CODE fails the transaction.
        if class == CLASS_ERROR_RESPONSE && ErrorCodeAttribute::default().get_from(&valid).is_err()
        {
            self.finish(
                id,
                StunEvent::TransactionFailed {
                    id,
                    reason: TransactionFailure::MissingErrorCode,
                },
            );
            return Ok(());
        }

        let message = if self.settings.integrity.is_some() {
            valid.into_message()
        } else {
            stun_msg
        };
        self.finish(id, StunEvent::Message(message));
        Ok(())
    }

    fn poll_read(&mut self) -> Option<Self::Rout> {
        None
    }

    /// Sends a message to the server.
    ///
    /// A request starts a transaction, which ends with one event: the response, a timeout or
    /// a failure. An indication is sent and forgotten: it has no response and no timeout (RFC
    /// 8489 section 6.3.2).
    ///
    /// # Errors
    ///
    /// Fails when the client is closed, when the message is larger than the path MTU allows
    /// over UDP (`ErrPacketTooBig`; RFC 8489 section 6.1,
    /// [`with_path_mtu`](ClientBuilder::with_path_mtu)), when a request reuses the
    /// transaction id of an outstanding one, and when the limit of outstanding transactions
    /// is reached (RFC 8489 section 6.2;
    /// [`with_max_outstanding_transactions`](ClientBuilder::with_max_outstanding_transactions)).
    fn handle_write(&mut self, msg: TaggedMessage) -> Result<()> {
        if self.settings.closed {
            return Err(Error::ErrClientClosed);
        }

        let now = msg.now;
        self.observe(now);
        let m = msg.message;

        if m.raw.len() > self.max_message_size() {
            return Err(Error::ErrPacketTooBig);
        }
        if m.typ.class != CLASS_REQUEST {
            self.transmit(now, &m.raw);
            return Ok(());
        }
        if self.transactions.contains_key(&m.transaction_id) {
            return Err(Error::ErrTransactionExists);
        }
        if self.settings.max_outstanding != 0
            && self.transactions.len() >= self.settings.max_outstanding
        {
            return Err(Error::Other(format!(
                "{} transactions are outstanding to {}, the limit of RFC 8489 section 6.2",
                self.transactions.len(),
                self.remote
            )));
        }

        let mut ct = ClientTransaction {
            id: m.transaction_id,
            method: m.typ.method,
            sent: 1,
            start: now,
            rto: self.rto.start(now),
            deadline: now,
            discarded: false,
            raw: m.raw,
        };
        ct.deadline = self.next_deadline(&ct, now);
        self.transmit(now, &ct.raw);
        self.transactions.insert(ct.id, ct);

        Ok(())
    }

    /// Returns packets to transmit
    ///
    /// It should be polled for transmit after:
    /// - the application performed some I/O
    /// - a call was made to `handle_read`
    /// - a call was made to `handle_write`
    /// - a call was made to `handle_timeout`
    fn poll_write(&mut self) -> Option<Self::Wout> {
        self.transmits.pop_front()
    }

    fn poll_event(&mut self) -> Option<Self::Eout> {
        self.events.pop_front()
    }

    /// When `handle_timeout` is next due: the earliest retransmission or transaction end.
    fn poll_timeout(&mut self) -> Option<Self::Time> {
        self.transactions.values().map(|ct| ct.deadline).min()
    }

    /// Advances time: every request whose interval has passed (`deadline <= now`) is sent
    /// again, or, after its last transmission, its transaction ends with
    /// [`StunEvent::TransactionTimeOut`].
    fn handle_timeout(&mut self, now: Instant) -> Result<()> {
        if self.settings.closed {
            return Err(Error::ErrClientClosed);
        }
        self.observe(now);
        for id in self.due(now) {
            let Some(mut ct) = self.transactions.remove(&id) else {
                continue;
            };
            if self.is_reliable() || ct.sent >= self.settings.rc {
                // RFC 8489 section 9.1.4: when every response was discarded, the failure is an
                // integrity violation, not a timeout.
                self.events.push_back(if ct.discarded {
                    StunEvent::TransactionFailed {
                        id,
                        reason: TransactionFailure::IntegrityViolation,
                    }
                } else {
                    StunEvent::TransactionTimeOut
                });
                continue;
            }
            ct.sent += 1;
            ct.deadline = self.next_deadline(&ct, now);
            self.transmit(now, &ct.raw);
            self.transactions.insert(id, ct);
        }
        Ok(())
    }

    fn close(&mut self) -> Result<()> {
        if self.settings.closed {
            return Err(Error::ErrClientClosed);
        }
        self.settings.closed = true;
        let mut ids: Vec<TransactionId> = self.transactions.keys().copied().collect();
        ids.sort_by_key(|id| id.0);
        for _ in ids {
            self.events.push_back(StunEvent::AgentClosed);
        }
        self.transactions.clear();
        Ok(())
    }
}

#[cfg(test)]
mod client_conformance_test;

#[cfg(test)]
mod client_test {
    use super::*;
    use sansio::Protocol;

    fn addrs() -> (SocketAddr, SocketAddr) {
        (
            "127.0.0.1:5000".parse().unwrap(),
            "127.0.0.1:3478".parse().unwrap(),
        )
    }

    fn binding_request() -> Message {
        let mut msg = Message::new();
        msg.build(&[Box::<TransactionId>::default(), Box::new(BINDING_REQUEST)])
            .expect("a binding request encodes");
        msg
    }

    /// The transaction deadline is computed from the instant the caller supplied to
    /// `handle_write`, not from an ambient reading, so a retransmission can be observed by
    /// arithmetic on a base instant with no wall-clock time passing and no sleeping.
    #[test]
    fn test_transaction_retransmits_on_injected_time() -> Result<()> {
        let base = Instant::now();
        let t = |millis| base + Duration::from_millis(millis);

        let (local, remote) = addrs();
        let mut client = ClientBuilder::new()
            .with_rto(Duration::from_millis(100))
            .build(t(0), local, remote, TransportProtocol::UDP)?;

        // The write is stamped at t(10), so the first attempt's deadline is t(10) + 1 * rto.
        client.handle_write(TaggedMessage {
            now: t(10),
            message: binding_request(),
        })?;

        let transmit = client.poll_write().expect("the request is queued");
        assert_eq!(
            transmit.now,
            t(10),
            "the request carries the caller's instant, not an ambient reading"
        );
        assert!(client.poll_write().is_none());

        assert_eq!(
            client.poll_timeout(),
            Some(t(110)),
            "the deadline is one RTO after the instant the caller wrote at"
        );

        // Before the deadline nothing is retransmitted.
        client.handle_timeout(t(109))?;
        while client.poll_event().is_some() {}
        assert!(
            client.poll_write().is_none(),
            "the deadline is not yet reached one millisecond before it"
        );

        // At the deadline the request goes out again, stamped with that same instant: a
        // driver that sleeps until `poll_timeout` and then calls `handle_timeout` makes
        // progress.
        client.handle_timeout(t(110))?;
        while client.poll_event().is_some() {}
        let retransmit = client.poll_write().expect("the request is retransmitted");
        assert_eq!(retransmit.now, t(110));
        assert_eq!(
            retransmit.message, transmit.message,
            "a retransmission repeats the original request verbatim"
        );

        // The second interval is twice the first, from the instant it was scheduled at.
        assert_eq!(client.poll_timeout(), Some(t(310)));

        client.close()
    }
}
