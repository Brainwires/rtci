use bytes::BytesMut;
use log::trace;
use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use stun::message::*;
use stun::timer::{RtoEstimator, Schedule};

use crate::client::RelayedAddr;
use crate::client::allocation::AllocateState;
use crate::client::credential::Credential;
use shared::{TransportContext, TransportMessage, TransportProtocol};

/// What a re-sendable TURN request carries from one attempt to the next.
///
/// A CreatePermission, Refresh or ChannelBind answered with 438 (Stale Nonce) is sent again
/// with the new nonce under a new transaction id (RFC 8489 §9.2.5, RFC 8656 §4.4), once. A
/// Refresh or ChannelBind that exhausts its retransmissions is started again, once, as a new
/// transaction.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Retry {
    /// The id of the first request of the chain: the one its caller was handed, and the one
    /// every event about the chain names. `None` on that first request itself.
    pub(crate) origin: Option<TransactionId>,
    /// Whether this request already re-sends one that was answered with 438 (Stale Nonce).
    pub(crate) stale_nonce: bool,
    /// Whether this request already re-sends one that timed out.
    pub(crate) timeout: bool,
}

impl Retry {
    /// The id events about the request sent as `wire` are reported under.
    pub(crate) fn report_id(&self, wire: TransactionId) -> TransactionId {
        self.origin.unwrap_or(wire)
    }

    /// The state for re-sending the request sent as `wire` after it was answered with 438.
    pub(crate) fn after_stale_nonce(self, wire: TransactionId) -> Self {
        Self {
            origin: Some(self.report_id(wire)),
            stale_nonce: true,
            ..self
        }
    }

    /// The state for starting the request sent as `wire` again after it timed out.
    pub(crate) fn after_timeout(self, wire: TransactionId) -> Self {
        Self {
            origin: Some(self.report_id(wire)),
            timeout: true,
            ..self
        }
    }
}

pub(crate) enum TransactionType {
    BindingRequest,
    /// The Allocate without a credential. Its state carries the id
    /// [`Client::allocate`](crate::client::Client::allocate) handed to its caller, which
    /// everything the caller is told about that allocation names.
    AllocateAttempt(Box<AllocateState>),
    /// The Allocate with the credential the server asked for.
    AllocateRequest(Box<AllocateState>),
    /// The relay, the peer a caller asked for (`None` for a permission refresh), every peer
    /// the request names, and its retry state.
    CreatePermissionRequest(RelayedAddr, Option<SocketAddr>, Vec<SocketAddr>, Retry),
    /// The relay, the LIFETIME the request asks for, and its retry state.
    RefreshRequest(RelayedAddr, Duration, Retry),
    /// The relay, the peer being bound, and the retry state.
    ChannelBindRequest(RelayedAddr, SocketAddr, Retry),
    /// A Connect to a peer through a TCP allocation (RFC 6062 §4.3): the relay, the peer, and
    /// the retry state.
    ConnectRequest(RelayedAddr, SocketAddr, Retry),
    /// The Refresh with LIFETIME 0 that deletes one address family (its
    /// REQUESTED-ADDRESS-FAMILY value) of an allocation that has two, and its retry state.
    FamilyRelease(RelayedAddr, u8, Retry),
    /// A Refresh with LIFETIME 0 for an allocation the client does not keep: the server made
    /// it, but its success response was unusable. Nothing is reported about it.
    OrphanRelease,
}

impl TransactionType {
    /// The allocation the request is about, if it is about one.
    pub(crate) fn relay(&self) -> Option<RelayedAddr> {
        match self {
            Self::CreatePermissionRequest(relayed, ..)
            | Self::RefreshRequest(relayed, ..)
            | Self::FamilyRelease(relayed, ..)
            | Self::ConnectRequest(relayed, ..)
            | Self::ChannelBindRequest(relayed, ..) => Some(*relayed),
            Self::BindingRequest
            | Self::AllocateAttempt(_)
            | Self::AllocateRequest(_)
            | Self::OrphanRelease => None,
        }
    }

    /// The id events about the request sent as `wire` are reported under: the id its caller
    /// was handed, which a retry or the Allocate exchange does not put on the wire.
    pub(crate) fn report_id(&self, wire: TransactionId) -> TransactionId {
        match self {
            Self::AllocateAttempt(state) | Self::AllocateRequest(state) => state.report_id,
            Self::CreatePermissionRequest(_, _, _, retry)
            | Self::RefreshRequest(_, _, retry)
            | Self::FamilyRelease(_, _, retry)
            | Self::ConnectRequest(_, _, retry)
            | Self::ChannelBindRequest(_, _, retry) => retry.report_id(wire),
            Self::BindingRequest | Self::OrphanRelease => wire,
        }
    }
}

/// What starts a transaction.
pub(crate) struct TransactionConfig {
    pub(crate) transaction_id: TransactionId,
    pub(crate) method: Method,
    pub(crate) transaction_type: TransactionType,
    pub(crate) raw: BytesMut,
    pub(crate) local_addr: SocketAddr,
    pub(crate) peer_addr: SocketAddr,
    pub(crate) transport_protocol: TransportProtocol,
    /// The credential the request was made with; `None` for a request that never carries one
    /// (a Binding request).
    pub(crate) credential: Option<Arc<Credential>>,
}

/// A request and the wait for its response.
pub(crate) struct Transaction {
    pub(crate) transaction_id: TransactionId,
    /// The method of the request: only a response of the same method answers it
    /// (RFC 8489 §6.3).
    pub(crate) method: Method,
    pub(crate) transaction_type: TransactionType,
    pub(crate) raw: BytesMut,
    pub(crate) local_addr: SocketAddr,
    pub(crate) peer_addr: SocketAddr,
    pub(crate) transport_protocol: TransportProtocol,
    /// The credential the request was made with. A response to a request that carried one
    /// must be signed with the same key (RFC 8489 §9.2.5).
    pub(crate) credential: Option<Arc<Credential>>,
    /// Whether a response was discarded because its integrity did not hold: if none is
    /// accepted, the transaction ends as an integrity violation, not as a timeout
    /// (RFC 8489 §9.2.5).
    pub(crate) discarded: bool,
    /// How many times the request was sent; 0 while it waits for one of the ten transactions
    /// the server is sent at a time to end (RFC 8489 §6.2).
    sent: u32,
    start: Instant,
    /// The RTO the transaction started with.
    rto: Duration,
    /// When the request is sent again or, after the last time, the transaction fails.
    deadline: Instant,
}

impl Transaction {
    /// Whether the transport delivers reliably on its own, so that the request is sent once.
    pub(crate) fn is_reliable(&self) -> bool {
        is_reliable(self.transport_protocol)
    }

    fn transmit(&self, now: Instant) -> TransportMessage<BytesMut> {
        TransportMessage {
            now,
            transport: TransportContext {
                local_addr: self.local_addr,
                peer_addr: self.peer_addr,
                transport_protocol: self.transport_protocol,
                ecn: None,
            },
            message: self.raw.clone(),
        }
    }
}

/// Whether the transport delivers reliably on its own, so a request must not be
/// retransmitted over it. Anything that is not UDP is a stream.
fn is_reliable(transport_protocol: TransportProtocol) -> bool {
    transport_protocol != TransportProtocol::UDP
}

/// The retransmission timer of the client's transactions (RFC 8489 §6.2): the one `rtci-stun`
/// has ([`stun::timer`]), with the client's settings.
#[derive(Debug, Clone, Copy)]
pub(crate) struct TimerSettings {
    pub(crate) initial_rto: Duration,
    pub(crate) schedule: Schedule,
    pub(crate) estimate_rto: bool,
    /// Most transactions outstanding to one server; 0 for no limit.
    pub(crate) max_outstanding: usize,
}

/// The client's outstanding transactions.
pub(crate) struct TransactionMap {
    tr_map: HashMap<TransactionId, Transaction>,
    /// Transactions that are not sent yet, oldest first: the server already has
    /// `max_outstanding` to answer.
    waiting: VecDeque<TransactionId>,
    /// How many transactions are sent and unanswered, by server.
    outstanding: HashMap<SocketAddr, usize>,
    /// The RTO of each server, as its round-trip times made it (RFC 6298).
    rto: HashMap<SocketAddr, RtoEstimator>,
    settings: TimerSettings,
    transmits: VecDeque<TransportMessage<BytesMut>>,
    /// The newest instant the client was given.
    now: Option<Instant>,
}

impl TransactionMap {
    pub(crate) fn new(settings: TimerSettings) -> TransactionMap {
        TransactionMap {
            tr_map: HashMap::new(),
            waiting: VecDeque::new(),
            outstanding: HashMap::new(),
            rto: HashMap::new(),
            settings,
            transmits: VecDeque::new(),
            now: None,
        }
    }

    fn observe(&mut self, now: Instant) -> Instant {
        let now = self.now.map_or(now, |seen| seen.max(now));
        self.now = Some(now);
        now
    }

    /// When the earliest retransmission or transaction end is due.
    pub(crate) fn poll_timeout(&self) -> Option<Instant> {
        self.tr_map
            .values()
            .filter(|tr| tr.sent > 0)
            .map(|tr| tr.deadline)
            .min()
    }

    /// Advances every transaction to `now`: a request whose interval has passed is sent
    /// again, and the transactions that were sent for the last time and waited that out are
    /// removed and returned, in the order of their deadlines. The client decides whether each
    /// is started again or reported.
    pub(crate) fn handle_timeout(&mut self, now: Instant) -> Vec<Transaction> {
        self.observe(now);
        let schedule = self.settings.schedule;
        let mut due: Vec<(Instant, TransactionId)> = self
            .tr_map
            .values()
            .filter(|tr| tr.sent > 0 && tr.deadline <= now)
            .map(|tr| (tr.deadline, tr.transaction_id))
            .collect();
        due.sort_by_key(|(deadline, id)| (*deadline, id.0));

        let mut exhausted = vec![];
        for (_, id) in due {
            let Some(tr) = self.tr_map.get_mut(&id) else {
                continue;
            };
            if schedule.is_last(tr.is_reliable(), tr.sent) {
                if let Some(tr) = self.remove(&id) {
                    exhausted.push(tr);
                }
                continue;
            }
            tr.sent += 1;
            tr.deadline = schedule.next_deadline(false, tr.start, tr.rto, tr.sent, now);
            trace!(
                "retransmitting transaction {:?} to {} (sent {} times)",
                tr.transaction_id, tr.peer_addr, tr.sent
            );
            let transmit = tr.transmit(now);
            self.transmits.push_back(transmit);
        }
        self.start_waiting();
        exhausted
    }

    pub(crate) fn poll_transmit(&mut self) -> Option<TransportMessage<BytesMut>> {
        self.transmits.pop_front()
    }

    /// Starts a transaction at `now`: its request is queued for sending, unless the server
    /// already has as many to answer as it is sent at a time; then it waits for one to end.
    pub(crate) fn start(&mut self, now: Instant, config: TransactionConfig) {
        let now = self.observe(now);
        let id = config.transaction_id;
        let tr = Transaction {
            transaction_id: id,
            method: config.method,
            transaction_type: config.transaction_type,
            raw: config.raw,
            local_addr: config.local_addr,
            peer_addr: config.peer_addr,
            transport_protocol: config.transport_protocol,
            credential: config.credential,
            discarded: false,
            sent: 0,
            start: now,
            rto: self.settings.initial_rto,
            deadline: now,
        };
        let server = tr.peer_addr;
        if let Some(replaced) = self.tr_map.insert(id, tr)
            && replaced.sent > 0
        {
            self.release(replaced.peer_addr);
        }
        if self.has_room(server) {
            self.send(&id, now);
        } else {
            self.waiting.push_back(id);
        }
    }

    fn has_room(&self, server: SocketAddr) -> bool {
        self.settings.max_outstanding == 0
            || self.outstanding.get(&server).copied().unwrap_or(0) < self.settings.max_outstanding
    }

    /// Sends the request of the waiting transaction `id` for the first time.
    fn send(&mut self, id: &TransactionId, now: Instant) {
        let settings = self.settings;
        let Some(tr) = self.tr_map.get_mut(id) else {
            return;
        };
        // Servers nothing was sent to for ten minutes have no estimate worth keeping.
        if self.rto.len() > 16 {
            self.rto.retain(|_, estimator| !estimator.is_stale(now));
        }
        tr.rto = self
            .rto
            .entry(tr.peer_addr)
            .or_insert_with(|| RtoEstimator::new(settings.initial_rto, settings.estimate_rto))
            .start(now);
        tr.sent = 1;
        tr.start = now;
        tr.deadline = settings
            .schedule
            .next_deadline(tr.is_reliable(), now, tr.rto, 1, now);
        *self.outstanding.entry(tr.peer_addr).or_insert(0) += 1;
        let transmit = tr.transmit(now);
        self.transmits.push_back(transmit);
    }

    /// One transaction to `server` fewer is outstanding.
    fn release(&mut self, server: SocketAddr) {
        if let Some(count) = self.outstanding.get_mut(&server) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                self.outstanding.remove(&server);
            }
        }
    }

    /// Sends the requests that waited for room, oldest first.
    fn start_waiting(&mut self) {
        if self.waiting.is_empty() {
            return;
        }
        let Some(now) = self.now else {
            return;
        };
        let mut still_waiting = VecDeque::new();
        while let Some(id) = self.waiting.pop_front() {
            let Some(tr) = self.tr_map.get(&id) else {
                continue;
            };
            if tr.sent > 0 {
                continue;
            }
            if self.has_room(tr.peer_addr) {
                self.send(&id, now);
            } else {
                still_waiting.push_back(id);
            }
        }
        self.waiting = still_waiting;
    }

    fn remove(&mut self, tid: &TransactionId) -> Option<Transaction> {
        let tr = self.tr_map.remove(tid)?;
        if tr.sent > 0 {
            self.release(tr.peer_addr);
        }
        Some(tr)
    }

    // Find looks up a transaction by its key
    pub(crate) fn find(&self, tid: &TransactionId) -> Option<&Transaction> {
        self.tr_map.get(tid)
    }

    pub(crate) fn get(&mut self, tid: &TransactionId) -> Option<&mut Transaction> {
        self.tr_map.get_mut(tid)
    }

    /// Ends the transaction `tid` with the response that arrived at `now`. A request that was
    /// sent once gives the server's round-trip time (RFC 8489 §6.2.1: none from a request
    /// that was retransmitted).
    pub(crate) fn answered(&mut self, tid: &TransactionId, now: Instant) -> Option<Transaction> {
        self.observe(now);
        let tr = self.remove(tid)?;
        if tr.sent == 1
            && !tr.is_reliable()
            && let Some(estimator) = self.rto.get_mut(&tr.peer_addr)
        {
            estimator.sample(now.saturating_duration_since(tr.start), now);
        }
        self.start_waiting();
        Some(tr)
    }

    /// Ends the transaction `tid` without a response.
    pub(crate) fn delete(&mut self, tid: &TransactionId) -> Option<Transaction> {
        let tr = self.remove(tid)?;
        self.start_waiting();
        Some(tr)
    }

    /// Drops every transaction `gone` says belongs to something that no longer exists, so
    /// nothing is retransmitted or reported for it.
    pub(crate) fn delete_where(&mut self, gone: impl Fn(&TransactionType) -> bool) {
        let ids: Vec<TransactionId> = self
            .tr_map
            .values()
            .filter(|tr| gone(&tr.transaction_type))
            .map(|tr| tr.transaction_id)
            .collect();
        for id in ids {
            self.remove(&id);
        }
        self.start_waiting();
    }

    // close_and_delete_all closes and deletes all transactions
    pub(crate) fn delete_all(&mut self) {
        self.tr_map.clear();
        self.waiting.clear();
        self.outstanding.clear();
    }

    // Size returns the length of the transaction map
    pub(crate) fn size(&self) -> usize {
        self.tr_map.len()
    }

    /// The RTO the next transaction to `server` starts with.
    pub(crate) fn rto(&self, server: SocketAddr) -> Duration {
        self.rto
            .get(&server)
            .map_or(self.settings.initial_rto, RtoEstimator::rto)
    }
}
