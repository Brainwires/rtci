//! One DTLS session per peer connection (RFC 5764 section 3), when the application turns it on
//! (`SettingEngineBuilder::with_dtls_session_resumption(true)`; off by default).
//!
//! A peer connection whose m= sections are not bundled has a DTLS association per transport.
//! RFC 5764 section 3: "As an optimization, the DTLS-SRTP implementation SHOULD use the
//! following strategy: a single DTLS association is established, and all other DTLS
//! associations wait until that connection is established before proceeding with their
//! handshakes. This establishes a single session and all other associations can take advantage
//! of TLS session resumption."
//!
//! A [`DtlsSessionGroup`] is that session's home: one per peer connection, never shared with
//! another, holding what the transports of the connection resume from:
//!
//! - as the DTLS client, a session store: the DTLS 1.3 tickets (RFC 8446 section 4.6.1) the
//!   peer gave this connection, each kept at most [`SESSION_LIFETIME`], and the store emptied
//!   for good once every member has started its handshake;
//! - as the DTLS server, the keys its tickets are sealed under, so that a ticket one
//!   transport's handshake issued is accepted (once) by another.
//!
//! What takes part:
//!
//! - DTLS 1.3 only, with `psk_dhe_ke` (the PSK is combined with a fresh (EC)DHE exchange). No
//!   DTLS 1.2 session id or ticket is asked for, given or accepted by the peer connection in
//!   any configuration (`rtci-dtls`'s `with_dtls12_resumption(false)`): a DTLS 1.2 ticket would
//!   carry the leader association's master secret, and a resumed DTLS 1.2 association runs no
//!   key exchange. A transport whose configuration cannot negotiate DTLS 1.3 takes no part.
//! - Only the first association of the transports set up by the negotiation that set up the
//!   transports ([`DtlsSessionGroup::close_admission`]): a later association (a new one for
//!   SRTP re-keying, an ICE restart with new DTLS parameters, a transport added later) runs a
//!   full handshake.
//! - Only when that negotiation set up more than one transport in the same DTLS role
//!   ([`DtlsSessionGroup::engages`]): a bundled connection, or one with a single transport in
//!   a role, asks for no ticket, issues none and keeps nothing.
//! - Only transports whose section names the same remote fingerprints as the first transport
//!   of the same DTLS role that took part ([`DtlsSessionGroup::admit`]): the session was made
//!   with a peer certificate those fingerprints matched. Each transport's configured
//!   certificate check (its own section's fingerprints) also runs on the certificates stored
//!   with the ticket (`rtci-dtls`, which refuses a resumption that carries none), and the
//!   store keeps no ticket without certificates ([`GroupSessionStore`]).
//! - A server transport accepts a resumption for its first handshake only: once that is
//!   complete its endpoint takes new handshakes (a peer re-handshaking in place) without the
//!   ticket keys, so a later handshake there is a full one.
//!
//! The wait, on the client side: the first client transport to start a handshake leads; every
//! other one waits until the leader's handshake is complete (for a DTLS 1.3 client that
//! authenticates, when the server has confirmed it: its ACK or its first record under the
//! application keys, which follows its tickets), and starts at once then. It waits no longer
//! for tickets when none came before that confirmation (a peer that issues none, as every
//! browser), when the association is DTLS 1.2 (nothing to resume), or when enough came for
//! every transport waiting; when some but not enough came, the rest of the same flight is
//! given at most one flight interval. A transport never waits more than
//! [`LEADER_WAIT_FLIGHTS`] of its own initial flight intervals for a leader whose handshake does
//! not complete, nor at all once the leader failed, was closed or could not start: it then runs
//! a full handshake.

use crate::peer_connection::transport::dtls::fingerprint::RTCDtlsFingerprint;
use crate::peer_connection::transport::dtls::role::RTCDtlsRole;
use crate::peer_connection::transport::dtls::same_fingerprints;
use crypto::RTCCryptoProvider;
use dtls::session::{
    Dtls12Session, MemorySessionStore, SessionStore, SessionTicketIssuer, Tls13Session,
};
use shared::error::Result;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::time::{Duration, Instant};

/// How many DTLS 1.3 tickets the server side sends after each handshake: one per other
/// transport the peer may resume with (a ticket is offered once, RFC 8446 appendix C.4).
pub(crate) const TICKETS_PER_HANDSHAKE: u8 = 4;
/// How long the group's tickets may be resumed, on either side: they are made for the
/// transports of one negotiation, which start their handshakes as soon as the first one has
/// finished.
pub(crate) const SESSION_LIFETIME: Duration = Duration::from_secs(5 * 60);
/// A client transport waits for the leader's handshake at most this many of its own initial
/// flight intervals (RFC 9147 section 5.8.2: 1.5 times the round trip time ICE measured, or
/// 400 ms) from the moment its own handshake was due, then runs a full handshake. A leader
/// that started no later than the waiter completes a DTLS 1.3 handshake with a cookie
/// exchange in about 2.5 round trips.
pub(crate) const LEADER_WAIT_FLIGHTS: u32 = 3;

/// The client side's session store: the DTLS 1.3 tickets the peer issued to this connection.
/// It keeps no ticket without the peer certificates of the handshake that made it (so that
/// every resumption has certificates for the transport's fingerprint check to run on), keeps
/// none longer than [`SESSION_LIFETIME`], and no DTLS 1.2 session at all. Once
/// [emptied](Self::empty) it holds and takes nothing more.
#[derive(Default)]
pub(crate) struct GroupSessionStore {
    /// `None` once emptied.
    inner: Mutex<Option<MemorySessionStore>>,
    /// How many tickets were kept so far.
    stored: AtomicUsize,
}

impl GroupSessionStore {
    fn new() -> Self {
        Self {
            inner: Mutex::new(Some(MemorySessionStore::new())),
            stored: AtomicUsize::new(0),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Option<MemorySessionStore>> {
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// How many tickets were kept so far.
    pub(crate) fn stored(&self) -> usize {
        self.stored.load(Ordering::Relaxed)
    }

    /// Drops every ticket held, and keeps none from now on.
    pub(crate) fn empty(&self) {
        self.lock().take();
    }

    /// Whether the store was emptied for good.
    #[cfg(test)]
    pub(crate) fn is_emptied(&self) -> bool {
        self.lock().is_none()
    }
}

impl SessionStore for GroupSessionStore {
    fn put(&self, server_name: &str, mut session: Tls13Session) {
        if session.peer_certificates().is_empty() {
            return;
        }
        session.limit_lifetime(SESSION_LIFETIME);
        if let Some(inner) = self.lock().as_ref() {
            inner.put(server_name, session);
            self.stored.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn take(&self, server_name: &str) -> Option<Tls13Session> {
        let guard = self.lock();
        let inner = guard.as_ref()?;
        loop {
            let session = inner.take(server_name)?;
            if !session.peer_certificates().is_empty() {
                return Some(session);
            }
        }
    }

    // DTLS 1.2 takes no part (the configurations say so too: `with_dtls12_resumption(false)`).
    fn put_dtls12(&self, _server_name: &str, _session: Dtls12Session) {}

    fn take_dtls12(&self, _server_name: &str) -> Option<Dtls12Session> {
        None
    }
}

/// Whether a client transport of the group may start its handshake.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StartGate {
    /// Now: it leads, or the leader is done.
    Now,
    /// Not yet: the leader's handshake is under way.
    Wait,
}

/// The client transport whose handshake makes the session.
struct Leader {
    token: Weak<()>,
    /// The store's count of tickets when it started: what came since is its handshake's.
    stored_at_start: usize,
    /// Its handshake completed with some of the tickets the others need: they wait for the
    /// rest of that flight until this instant at the latest.
    partial_until: Option<Instant>,
    /// When the others may start.
    ready_at: Option<Instant>,
}

impl Leader {
    fn is(&self, token: &Arc<()>) -> bool {
        std::ptr::eq(self.token.as_ptr(), Arc::as_ptr(token))
    }
}

fn is(weak: &Weak<()>, token: &Arc<()>) -> bool {
    std::ptr::eq(weak.as_ptr(), Arc::as_ptr(token))
}

struct GroupState {
    /// Transports may still join: the negotiation that set up the transports is under way.
    admission_open: bool,
    /// The remote fingerprints of the first client transport admitted.
    client_origin: Option<Vec<RTCDtlsFingerprint>>,
    /// The remote fingerprints of the first server transport admitted.
    server_origin: Option<Vec<RTCDtlsFingerprint>>,
    /// The transports admitted, with their DTLS role: they take part when their role has
    /// more than one ([`DtlsSessionGroup::engages`]).
    candidates: Vec<(Weak<()>, RTCDtlsRole)>,
    /// The client transports taking part that have not started their handshake yet.
    pending: Vec<Weak<()>>,
    /// The client transports waiting for the leader.
    waiting: Vec<Weak<()>>,
    leader: Option<Leader>,
    /// The latest instant a transport of the connection was given.
    last_now: Option<Instant>,
}

/// The DTLS session of one peer connection (RFC 5764 section 3): see the module.
pub(crate) struct DtlsSessionGroup {
    store: Arc<GroupSessionStore>,
    tickets: SessionTicketIssuer,
    state: Mutex<GroupState>,
}

impl std::fmt::Debug for DtlsSessionGroup {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DtlsSessionGroup").finish_non_exhaustive()
    }
}

impl DtlsSessionGroup {
    /// The group of a new peer connection: an empty store and new ticket keys from
    /// `provider`.
    pub(crate) fn new(provider: &dyn RTCCryptoProvider) -> Result<Self> {
        Ok(Self {
            store: Arc::new(GroupSessionStore::new()),
            tickets: SessionTicketIssuer::new(provider, TICKETS_PER_HANDSHAKE, SESSION_LIFETIME)?,
            state: Mutex::new(GroupState {
                admission_open: true,
                client_origin: None,
                server_origin: None,
                candidates: vec![],
                pending: vec![],
                waiting: vec![],
                leader: None,
                last_now: None,
            }),
        })
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, GroupState> {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// The client side's store (for tests and the wait).
    pub(crate) fn store(&self) -> &GroupSessionStore {
        &self.store
    }

    /// Whether the first association of the transport `token` in `role`, for a section
    /// naming the remote fingerprints `remote`, is admitted: admission is open and `remote`
    /// names the same certificates as the first transport of that role admitted (which it
    /// becomes, when it is the first). It takes part only once the negotiation is over and
    /// its role has more than one ([`Self::engages`]).
    pub(crate) fn admit(
        &self,
        token: &Arc<()>,
        role: RTCDtlsRole,
        remote: &[RTCDtlsFingerprint],
    ) -> bool {
        let mut state = self.lock();
        if !state.admission_open || remote.is_empty() {
            return false;
        }
        let origin = match role {
            RTCDtlsRole::Client => &mut state.client_origin,
            RTCDtlsRole::Server => &mut state.server_origin,
            _ => return false,
        };
        let admitted = match origin {
            None => {
                *origin = Some(remote.to_vec());
                true
            }
            Some(origin) => same_fingerprints(origin, remote),
        };
        if admitted && !state.candidates.iter().any(|(weak, _)| is(weak, token)) {
            state.candidates.push((Arc::downgrade(token), role));
        }
        admitted
    }

    /// The negotiation that set up the transports is done: no association is admitted from
    /// now on.
    pub(crate) fn close_admission(&self) {
        self.lock().admission_open = false;
    }

    /// Whether the transports admitted in `role` take part: there is more than one, so that
    /// one may resume what another's handshake brings. A single transport in a role (a
    /// bundled connection) takes no part, and asks for or issues no ticket.
    pub(crate) fn engages(&self, role: RTCDtlsRole) -> bool {
        self.lock()
            .candidates
            .iter()
            .filter(|(weak, candidate)| *candidate == role && weak.strong_count() > 0)
            .count()
            >= 2
    }

    /// The transport `token`, admitted in `role`, takes part.
    pub(crate) fn join(&self, token: &Arc<()>, role: RTCDtlsRole) {
        if role == RTCDtlsRole::Client {
            let mut state = self.lock();
            if !state.pending.iter().any(|weak| is(weak, token)) {
                state.pending.push(Arc::downgrade(token));
            }
        }
    }

    /// Every transport of the negotiation has joined or not: the store is emptied as soon as
    /// nothing will be taken from it any more.
    pub(crate) fn settle(&self) {
        let mut state = self.lock();
        self.empty_when_done(&mut state);
    }

    /// Admission is closed and every client transport taking part has started (or ended):
    /// no ticket will be offered again, and none is kept.
    fn empty_when_done(&self, state: &mut GroupState) {
        state.pending.retain(|weak| weak.strong_count() > 0);
        if !state.admission_open && state.pending.is_empty() {
            self.store.empty();
        }
    }

    /// `builder`, configured to resume from the group in `role`: as the client with the
    /// store, as the server with the shared ticket keys. DTLS 1.2 takes no part either way.
    pub(crate) fn configure(
        &self,
        builder: dtls::config::ConfigBuilder,
        role: RTCDtlsRole,
    ) -> dtls::config::ConfigBuilder {
        let builder = builder.with_dtls12_resumption(false);
        if role == RTCDtlsRole::Client {
            builder.with_session_store(Some(self.store.clone() as Arc<dyn SessionStore>))
        } else {
            builder
                .with_session_ticket_issuer(Some(self.tickets.clone()))
                .with_session_ticket_lifetime(SESSION_LIFETIME)
        }
    }

    /// A transport of the connection was given `now`.
    pub(crate) fn observe(&self, now: Instant) {
        let mut state = self.lock();
        state.last_now = Some(state.last_now.map_or(now, |last| last.max(now)));
    }

    /// Whether the leader is done (ready), noting a leader that went away.
    fn leader_ready(state: &mut GroupState) -> Option<Instant> {
        let last_now = state.last_now;
        let leader = state.leader.as_mut()?;
        if leader.ready_at.is_none() && leader.token.strong_count() == 0 {
            leader.ready_at = last_now;
        }
        leader.ready_at
    }

    /// The client transport `token` would start its handshake at `now`: it leads when no
    /// transport does, and waits while the leader's handshake is under way.
    pub(crate) fn start_gate(&self, token: &Arc<()>, now: Instant) -> StartGate {
        let stored = self.store.stored();
        let mut state = self.lock();
        state.last_now = Some(state.last_now.map_or(now, |last| last.max(now)));
        match &state.leader {
            None => {
                state.leader = Some(Leader {
                    token: Arc::downgrade(token),
                    stored_at_start: stored,
                    partial_until: None,
                    ready_at: None,
                });
                StartGate::Now
            }
            Some(leader) if leader.is(token) => StartGate::Now,
            Some(_) => {
                if Self::leader_ready(&mut state).is_some() {
                    StartGate::Now
                } else {
                    if !state.waiting.iter().any(|weak| is(weak, token)) {
                        state.waiting.push(Arc::downgrade(token));
                    }
                    StartGate::Wait
                }
            }
        }
    }

    /// The client transport `token` started its handshake (with a ticket if the store had
    /// one).
    pub(crate) fn started(&self, token: &Arc<()>) {
        let mut state = self.lock();
        state.waiting.retain(|weak| !is(weak, token));
        state.pending.retain(|weak| !is(weak, token));
        self.empty_when_done(&mut state);
    }

    /// When a waiting transport may start: `None` while the leader's handshake is under way.
    pub(crate) fn ready_at(&self) -> Option<Instant> {
        Self::leader_ready(&mut self.lock())
    }

    /// How many tickets came since the leader started, and how many the transports waiting
    /// need.
    fn tickets(&self, state: &mut GroupState, leader_stored_at_start: usize) -> (usize, usize) {
        state.waiting.retain(|weak| weak.strong_count() > 0);
        let came = self.store.stored().saturating_sub(leader_stored_at_start);
        (came, state.waiting.len().max(1))
    }

    /// The handshake of `token` completed at `now`, as DTLS 1.3 (`dtls13`) or not: when it
    /// leads, the others start now, unless some but not all of the tickets they need have
    /// come, in which case they wait for the rest of the flight at most `ticket_wait`.
    pub(crate) fn leader_connected(
        &self,
        token: &Arc<()>,
        now: Instant,
        dtls13: bool,
        ticket_wait: Duration,
    ) {
        let mut state = self.lock();
        let Some(stored_at_start) = state
            .leader
            .as_ref()
            .filter(|leader| leader.is(token) && leader.ready_at.is_none())
            .map(|leader| leader.stored_at_start)
        else {
            return;
        };
        let (came, wanted) = self.tickets(&mut state, stored_at_start);
        let leader = state.leader.as_mut().expect("the leader");
        // No ticket before the server confirmed the handshake: the peer issues none. DTLS
        // 1.2: nothing is resumed. Enough tickets: nothing to wait for.
        if !dtls13 || came == 0 || came >= wanted {
            leader.ready_at = Some(now);
        } else {
            leader.partial_until = Some(now + ticket_wait);
        }
    }

    /// The leader `token` at `now`: the others may start once enough tickets have come, or
    /// the wait for the rest of them is over.
    pub(crate) fn poll_leader(&self, token: &Arc<()>, now: Instant) {
        let mut state = self.lock();
        let Some((stored_at_start, until)) = state
            .leader
            .as_ref()
            .filter(|leader| leader.is(token) && leader.ready_at.is_none())
            .and_then(|leader| Some((leader.stored_at_start, leader.partial_until?)))
        else {
            return;
        };
        let (came, wanted) = self.tickets(&mut state, stored_at_start);
        if came >= wanted || now >= until {
            state.leader.as_mut().expect("the leader").ready_at = Some(now);
        }
    }

    /// When the leader `token` stops waiting for the rest of the tickets.
    pub(crate) fn leader_deadline(&self, token: &Arc<()>) -> Option<Instant> {
        let state = self.lock();
        let leader = state.leader.as_ref()?;
        if !leader.is(token) || leader.ready_at.is_some() {
            return None;
        }
        leader.partial_until
    }

    /// The association of `token` ended (failed, closed, replaced, or its handshake could not
    /// start): when it led and the others still wait, they start now, with full handshakes
    /// if no ticket came. It no longer counts as a transport to start.
    pub(crate) fn ended(&self, token: &Arc<()>, now: Option<Instant>) {
        let mut state = self.lock();
        let at = now.or(state.last_now);
        if let Some(leader) = state.leader.as_mut()
            && leader.is(token)
            && leader.ready_at.is_none()
        {
            leader.ready_at = at;
            if leader.ready_at.is_none() {
                // Never given a time: nothing waits on an instant either.
                leader.token = Weak::new();
            }
        }
        state.waiting.retain(|weak| !is(weak, token));
        state.pending.retain(|weak| !is(weak, token));
        self.empty_when_done(&mut state);
    }
}

#[cfg(test)]
mod tests {
    //! The session of a connection between two engine transports, driven endpoint to
    //! endpoint: what resumes and what does not.

    use super::*;
    use crate::peer_connection::certificate::RTCCertificate;
    use crate::peer_connection::configuration::setting_engine::ReplayProtection;
    use crate::peer_connection::transport::dtls::parameters::RTCDtlsParameters;
    use crate::peer_connection::transport::dtls::role::DEFAULT_DTLS_ROLE_ANSWER;
    use crate::peer_connection::transport::dtls::{
        DtlsAssociationUpdate, DtlsRemoteUpdate, DtlsTransport, RTCDtlsTransportConfig,
    };
    use crate::peer_connection::transport::ice::role::RTCIceRole;
    use crate::peer_connection::transport::{RTCTransportId, TransportKind};
    use dtls::config::HandshakeConfig;
    use dtls::endpoint::{Endpoint, EndpointEvent};
    use shared::TransportProtocol;
    use std::net::SocketAddr;

    fn provider() -> Arc<dyn RTCCryptoProvider> {
        crypto::default_provider().expect("a built-in crypto provider")
    }

    fn certificate() -> RTCCertificate {
        RTCCertificate::generate_certificate(
            provider().crypto(),
            crypto::SignatureScheme::EcdsaP256Sha256,
            None,
            std::time::SystemTime::now(),
        )
        .expect("a certificate")
    }

    fn group() -> Arc<DtlsSessionGroup> {
        Arc::new(DtlsSessionGroup::new(provider().as_ref()).expect("a group"))
    }

    /// A transport of a connection whose certificate is `local` and whose session is `group`.
    fn engine_transport(local: &RTCCertificate, group: &Arc<DtlsSessionGroup>) -> DtlsTransport {
        let mut transport = DtlsTransport::new(RTCDtlsTransportConfig {
            id: RTCTransportId::new(1, TransportKind::Dtls),
            ice_transport_id: RTCTransportId::new(1, TransportKind::Ice),
            certificates: vec![local.clone()],
            answering_dtls_role: DEFAULT_DTLS_ROLE_ANSWER,
            srtp_protection_profiles: vec![],
            use_srtp_always: true,
            dtls_cipher_suites: vec![],
            allow_insecure_verification_algorithm: false,
            disable_certificate_fingerprint_verification: false,
            replay_protection: ReplayProtection::default(),
            crypto_provider: provider(),
        })
        .expect("a transport");
        transport.resumption = Some(group.clone());
        transport
    }

    /// The remote parameters of a peer whose certificate is `remote`, in `role`.
    fn params(role: RTCDtlsRole, remote: &RTCCertificate) -> RTCDtlsParameters {
        RTCDtlsParameters {
            role,
            fingerprints: remote
                .get_fingerprints(provider().crypto())
                .expect("fingerprints"),
        }
    }

    /// The ICE role and the remote DTLS role that make a transport the DTLS `role`.
    fn roles(role: RTCDtlsRole) -> (RTCIceRole, RTCDtlsRole) {
        if role == RTCDtlsRole::Client {
            (RTCIceRole::Controlled, RTCDtlsRole::Server)
        } else {
            (RTCIceRole::Controlling, RTCDtlsRole::Client)
        }
    }

    /// The first association of a new transport of the connection with certificate `local`
    /// and session `group`, in `role`, for a section naming `remote`, started by the
    /// negotiation, beside another transport of the same role: what `engage_session` makes
    /// of it.
    fn negotiated(
        local: &RTCCertificate,
        group: &Arc<DtlsSessionGroup>,
        remote: &RTCCertificate,
        role: RTCDtlsRole,
    ) -> DtlsTransport {
        let (ice_role, remote_role) = roles(role);
        let mut sibling = engine_transport(local, group);
        let mut transport = engine_transport(local, group);
        for t in [&mut sibling, &mut transport] {
            t.start(ice_role, params(remote_role, remote))
                .expect("the transport starts");
        }
        transport.engage_session().expect("it takes part");
        transport
    }

    /// The handshake config of `transport`'s association, as its handshake uses it.
    fn config_of(transport: &DtlsTransport) -> Arc<HandshakeConfig> {
        if transport.dtls_role == RTCDtlsRole::Client {
            transport
                .dtls_handshake_config
                .clone()
                .expect("a client config")
        } else {
            transport
                .make_handshake_config(
                    transport.remote_dtls_parameters.as_ref().expect("remote"),
                    transport.resumption_member,
                )
                .expect("a server config")
        }
    }

    /// As the DTLS client of a peer with certificate `remote`, taking part in `group`.
    fn client(
        local: &RTCCertificate,
        group: &Arc<DtlsSessionGroup>,
        remote: &RTCCertificate,
    ) -> Arc<HandshakeConfig> {
        let transport = negotiated(local, group, remote, RTCDtlsRole::Client);
        assert!(transport.resumption_member);
        config_of(&transport)
    }

    /// The same as the DTLS server.
    fn server(
        local: &RTCCertificate,
        group: &Arc<DtlsSessionGroup>,
        remote: &RTCCertificate,
    ) -> Arc<HandshakeConfig> {
        let transport = negotiated(local, group, remote, RTCDtlsRole::Server);
        assert!(transport.resumption_member);
        config_of(&transport)
    }

    /// Runs a handshake between `client` and `server` (and the tickets after it): whether it
    /// completed on both sides, and whether the client's association was a resumption.
    fn handshake(client: Arc<HandshakeConfig>, server: Arc<HandshakeConfig>) -> (bool, bool) {
        let client_addr: SocketAddr = "127.0.0.1:47001".parse().unwrap();
        let server_addr: SocketAddr = "127.0.0.1:47002".parse().unwrap();
        let mut a = Endpoint::new(client_addr, TransportProtocol::UDP, None);
        let mut b = Endpoint::new(server_addr, TransportProtocol::UDP, Some(server));
        let now = Instant::now();
        a.connect(now, server_addr, client, None)
            .expect("the client starts");
        let (mut client_done, mut server_done) = (false, false);
        for _ in 0..12 {
            while let Some(transmit) = a.poll_transmit() {
                if let Ok(events) = b.read(now, client_addr, None, transmit.message) {
                    server_done |= events
                        .iter()
                        .any(|e| matches!(e, EndpointEvent::HandshakeComplete));
                }
            }
            while let Some(transmit) = b.poll_transmit() {
                if let Ok(events) = a.read(now, server_addr, None, transmit.message) {
                    client_done |= events
                        .iter()
                        .any(|e| matches!(e, EndpointEvent::HandshakeComplete));
                }
            }
        }
        let resumed = a
            .get_connection_state(server_addr)
            .is_some_and(|state| state.resumed());
        (client_done && server_done, resumed)
    }

    /// RFC 5764 section 3 is about the associations of one connection: a session or ticket
    /// that one connection's handshake made resumes another association of that connection,
    /// and nothing of another connection's, as the client (whose store has nothing of the
    /// other's) and as the server (whose ticket keys cannot open the other's tickets), even
    /// between the same two certificates.
    #[test]
    fn a_session_of_one_connection_does_not_resume_on_another() {
        let (ours, theirs) = (certificate(), certificate());
        let (clients_1, servers_1) = (group(), group());
        let (clients_2, servers_2) = (group(), group());

        assert_eq!(
            handshake(
                client(&ours, &clients_1, &theirs),
                server(&theirs, &servers_1, &ours)
            ),
            (true, false),
            "the connection's first association: a full handshake"
        );
        assert!(clients_1.store().stored() > 0, "it brought the session");
        assert_eq!(clients_2.store().stored(), 0, "to that connection only");
        assert_eq!(
            handshake(
                client(&ours, &clients_1, &theirs),
                server(&theirs, &servers_1, &ours)
            ),
            (true, true),
            "the connection's next association resumes it"
        );

        assert_eq!(
            handshake(
                client(&ours, &clients_2, &theirs),
                server(&theirs, &servers_1, &ours)
            ),
            (true, false),
            "another connection's client has no session to offer"
        );
        assert_eq!(
            handshake(
                client(&ours, &clients_1, &theirs),
                server(&theirs, &servers_2, &ours)
            ),
            (true, false),
            "another connection's server does not take the session"
        );
    }

    /// RFC 5764 section 4.4 and RFC 8842: a new association of a transport (SRTP re-keying,
    /// new DTLS parameters) is a full handshake with a fresh key exchange, never a
    /// resumption, while the connection holds a session it could resume.
    #[test]
    fn a_new_association_of_a_transport_is_a_full_handshake() {
        let (ours, theirs) = (certificate(), certificate());
        let (clients, servers) = (group(), group());
        assert_eq!(
            handshake(
                client(&ours, &clients, &theirs),
                server(&theirs, &servers, &ours)
            ),
            (true, false)
        );
        assert!(clients.store().stored() > 0);

        let mut transport = negotiated(&ours, &clients, &theirs, RTCDtlsRole::Client);
        transport.remote_tls_id = Some("first".to_owned());
        assert!(transport.session_group().is_some(), "it takes part");
        let update = transport
            .update_remote(
                RTCIceRole::Controlled,
                params(RTCDtlsRole::Server, &theirs),
                Some("second".to_owned()),
                DtlsRemoteUpdate::default(),
            )
            .expect("a new association");
        assert_eq!(update, DtlsAssociationUpdate::New);
        assert!(transport.session_group().is_none(), "the new one does not");
        let renewed = transport
            .dtls_handshake_config
            .clone()
            .expect("the client's new config");
        assert_eq!(
            handshake(renewed, server(&theirs, &servers, &ours)),
            (true, false),
            "a full handshake"
        );
    }

    /// A provisional answer, then the final answer naming other fingerprints for a section
    /// (RFC 9429 section 4.1.10.1: the transport follows the final one): the association the
    /// final answer makes is a new one, outside the session, as the client and as the server:
    /// a full handshake, whose certificate check is that of the final answer.
    #[test]
    fn a_final_answer_with_other_fingerprints_gets_a_full_non_member_association() {
        let (ours, theirs, other) = (certificate(), certificate(), certificate());
        let (clients, servers) = (group(), group());
        assert_eq!(
            handshake(
                client(&ours, &clients, &theirs),
                server(&theirs, &servers, &ours)
            ),
            (true, false)
        );
        for role in [RTCDtlsRole::Client, RTCDtlsRole::Server] {
            let (ice_role, remote_role) = roles(role);
            // The provisional answer set the transports up; they take part.
            let mut transport = if role == RTCDtlsRole::Client {
                negotiated(&ours, &clients, &theirs, role)
            } else {
                negotiated(&theirs, &servers, &ours, role)
            };
            assert!(transport.session_group().is_some(), "{role}");
            let update = transport
                .update_remote(
                    ice_role,
                    params(remote_role, &other),
                    None,
                    DtlsRemoteUpdate::default(),
                )
                .expect("the final answer");
            assert_eq!(update, DtlsAssociationUpdate::New, "{role}");
            assert!(transport.session_group().is_none(), "{role}: not a member");
            assert!(!transport.resumption_member, "{role}");
            let config = config_of(&transport);
            assert!(
                clients.store().stored() > 0,
                "tickets the client could offer"
            );
            if role == RTCDtlsRole::Client {
                // It has no store: its ClientHello offers nothing, and the server's
                // certificate fails the final answer's fingerprints.
                assert_eq!(
                    handshake(config, server(&theirs, &servers, &ours)),
                    (false, false)
                );
            } else {
                // The client offers a ticket; the server, without the session's keys, runs a
                // full handshake, whose client certificate fails the final answer's
                // fingerprints.
                assert_eq!(
                    handshake(client(&ours, &clients, &theirs), config),
                    (false, false)
                );
            }
            assert!(
                transport
                    .fingerprint_mismatch
                    .load(std::sync::atomic::Ordering::Relaxed),
                "{role}: fingerprint-failure, from a full handshake's certificate"
            );
        }
    }

    /// Only the transports of the negotiation that set up the connection's transports are
    /// admitted, and only for the remote certificates the session was made with: a section
    /// naming another certificate's fingerprints is outside it, in both roles.
    #[test]
    fn admission_follows_the_first_negotiation_and_the_fingerprints() {
        let (theirs, other) = (certificate(), certificate());
        let fingerprints = |certificate: &RTCCertificate| {
            certificate
                .get_fingerprints(provider().crypto())
                .expect("fingerprints")
        };
        let session = group();
        let tokens: Vec<Arc<()>> = (0..4).map(|_| Arc::new(())).collect();
        for role in [RTCDtlsRole::Client, RTCDtlsRole::Server] {
            assert!(
                session.admit(&tokens[0], role, &fingerprints(&theirs)),
                "{role}: the first"
            );
            assert!(
                session.admit(&tokens[1], role, &fingerprints(&theirs)),
                "{role}: the same"
            );
            assert!(
                !session.admit(&tokens[2], role, &fingerprints(&other)),
                "{role}: another"
            );
        }
        session.close_admission();
        assert!(!session.admit(&tokens[3], RTCDtlsRole::Client, &fingerprints(&theirs)));
    }

    /// A bundled connection, or a negotiation with a single transport in a DTLS role, has
    /// nothing to share: the transport takes no part, its client asks for no ticket (no
    /// `psk_key_exchange_modes`, so no server sends one) and keeps nothing, its server
    /// issues none. Two transports of a role take part.
    #[test]
    fn a_single_transport_in_a_role_takes_no_part() {
        let (ours, theirs) = (certificate(), certificate());
        let (clients, servers) = (group(), group());
        let alone = |group: &Arc<DtlsSessionGroup>, local, remote, role| {
            let (ice_role, remote_role) = roles(role);
            let mut transport = engine_transport(local, group);
            transport
                .start(ice_role, params(remote_role, remote))
                .expect("it starts");
            assert!(transport.resumption_candidate, "{role}: admitted");
            assert!(!group.engages(role), "{role}");
            transport.engage_session().expect("settled");
            assert!(
                !transport.resumption_member,
                "{role}: alone, it takes no part"
            );
            config_of(&transport)
        };
        let client_config = alone(&clients, &ours, &theirs, RTCDtlsRole::Client);
        let server_config = alone(&servers, &theirs, &ours, RTCDtlsRole::Server);
        assert_eq!(handshake(client_config, server_config), (true, false));
        assert_eq!(clients.store().stored(), 0, "no ticket asked for or issued");
        // Against a server of the group that does issue tickets: still none.
        assert_eq!(
            handshake(
                alone(&group(), &ours, &theirs, RTCDtlsRole::Client),
                server(&theirs, &servers, &ours)
            ),
            (true, false)
        );
        assert_eq!(clients.store().stored(), 0);
    }

    /// The re-check behind the admission gate, as the DTLS client (RFC 8122 section 5, RFC
    /// 8827 section 6.5): a transport given the connection's session for a section that
    /// names another certificate (what the gate would never do; built here directly) offers
    /// the ticket, the server accepts it, and the section's own fingerprint check, run on the
    /// certificates stored with the ticket, fails the handshake with fingerprint-failure.
    /// The same section naming the session's certificate resumes.
    #[test]
    fn behind_the_gate_the_client_checks_the_stored_certificate() {
        let (ours, theirs, other) = (certificate(), certificate(), certificate());
        let (clients, servers) = (group(), group());
        assert_eq!(
            handshake(
                client(&ours, &clients, &theirs),
                server(&theirs, &servers, &ours)
            ),
            (true, false)
        );
        let mut transport = negotiated(&ours, &clients, &theirs, RTCDtlsRole::Client);
        let wrong = transport
            .make_handshake_config(&params(RTCDtlsRole::Server, &other), true)
            .expect("a config with the session");
        let before = clients.store().stored();
        assert_eq!(
            handshake(wrong, server(&theirs, &servers, &ours)),
            (false, false),
            "the stored certificate is not the section's"
        );
        assert!(before > 0, "a ticket was there to offer");
        assert!(
            transport
                .fingerprint_mismatch
                .load(std::sync::atomic::Ordering::Relaxed),
            "fingerprint-failure"
        );
        transport.dtls_handshake_config = None;
        let right = client(&ours, &clients, &theirs);
        assert_eq!(
            handshake(right, server(&theirs, &servers, &ours)),
            (true, true)
        );
    }

    /// The same as the DTLS server (the check a mutation removed unnoticed, review F4): the
    /// client offers a ticket the connection issued to its certificate; a server transport
    /// given the session for a section naming another client certificate runs that section's
    /// fingerprint check on the certificate stored in the ticket, refuses it, and nothing is
    /// resumed. The same section naming the client's certificate resumes.
    #[test]
    fn behind_the_gate_the_server_checks_the_stored_certificate() {
        let (ours, theirs, other) = (certificate(), certificate(), certificate());
        let (clients, servers) = (group(), group());
        assert_eq!(
            handshake(
                client(&ours, &clients, &theirs),
                server(&theirs, &servers, &ours)
            ),
            (true, false)
        );
        let transport = negotiated(&theirs, &servers, &ours, RTCDtlsRole::Server);
        let wrong = transport
            .make_handshake_config(&params(RTCDtlsRole::Client, &other), true)
            .expect("a config with the session");
        assert!(clients.store().stored() > 0, "a ticket to offer");
        assert_eq!(
            handshake(client(&ours, &clients, &theirs), wrong),
            (false, false),
            "the ticket's client certificate is not the section's"
        );
        assert_eq!(
            handshake(
                client(&ours, &clients, &theirs),
                server(&theirs, &servers, &ours)
            ),
            (true, true)
        );
    }

    /// A ticket for the name "peer", with the server's certificate, valid for `lifetime`
    /// from just before the call, from a plain `rtci-dtls` handshake.
    fn plain_ticket(lifetime: Duration) -> Tls13Session {
        use dtls::config::ConfigBuilder;
        let provider = provider();
        let plain = Arc::new(MemorySessionStore::new());
        let client = Arc::new(
            ConfigBuilder::default()
                .with_crypto_provider(provider.clone())
                .with_insecure_skip_verify(true)
                .with_server_name("peer".to_owned())
                .with_session_store(Some(plain.clone() as Arc<dyn SessionStore>))
                .build(true, None)
                .expect("a client"),
        );
        let server = Arc::new(
            ConfigBuilder::default()
                .with_crypto_provider(provider.clone())
                .with_certificates(vec![
                    dtls::crypto::Certificate::generate_self_signed(
                        vec!["peer".to_owned()],
                        provider.crypto(),
                    )
                    .expect("a certificate"),
                ])
                .with_session_tickets(1)
                .with_session_ticket_lifetime(lifetime)
                .build(false, None)
                .expect("a server"),
        );
        assert!(handshake(client, server).0);
        plain.take("peer").expect("a ticket")
    }

    /// A ticket the client side keeps lives at most [`SESSION_LIFETIME`], whatever lifetime
    /// the server gave it (review F8); the store keeps no DTLS 1.2 session.
    #[test]
    fn the_client_keeps_a_ticket_at_most_the_session_lifetime() {
        let before = Instant::now();
        let ticket = plain_ticket(Duration::from_secs(7200));
        let late = before + SESSION_LIFETIME + Duration::from_secs(1);
        assert!(ticket.is_valid_at(late), "the server's lifetime");
        let store = GroupSessionStore::new();
        store.put("peer", ticket);
        let kept = store.take("peer").expect("kept");
        assert!(kept.is_valid_at(before + SESSION_LIFETIME - Duration::from_secs(10)));
        assert!(!kept.is_valid_at(late), "at most the session lifetime");
        assert!(store.take_dtls12("peer").is_none());
    }

    /// The client side's store is emptied once admission is closed and every client
    /// transport taking part has started its handshake (review F8): no ticket is kept for a
    /// handshake that will never come, and none is kept after.
    #[test]
    fn the_store_is_emptied_once_every_member_has_started() {
        let session = group();
        session
            .store()
            .put("peer", plain_ticket(Duration::from_secs(60)));
        let (a, b) = (Arc::new(()), Arc::new(()));
        let fingerprints = params(RTCDtlsRole::Server, &certificate()).fingerprints;
        for token in [&a, &b] {
            assert!(session.admit(token, RTCDtlsRole::Client, &fingerprints));
        }
        session.close_admission();
        assert!(session.engages(RTCDtlsRole::Client));
        session.join(&a, RTCDtlsRole::Client);
        session.join(&b, RTCDtlsRole::Client);
        session.settle();
        assert!(!session.store().is_emptied(), "two to start");
        let now = Instant::now();
        assert_eq!(session.start_gate(&a, now), StartGate::Now, "a leads");
        session.started(&a);
        assert_eq!(session.start_gate(&b, now), StartGate::Wait);
        assert!(!session.store().is_emptied(), "b has yet to start");
        session.leader_connected(&a, now, true, Duration::from_millis(400));
        assert_eq!(session.ready_at(), Some(now));
        session.started(&b);
        assert!(
            session.store().is_emptied(),
            "every member started: nothing kept"
        );
        assert!(session.store().take("peer").is_none());
        let stored = session.store().stored();
        session
            .store()
            .put("peer", plain_ticket(Duration::from_secs(60)));
        assert_eq!(session.store().stored(), stored, "nothing kept after");
        assert!(session.store().take("peer").is_none());

        // A member that ends before it starts counts as done.
        let session = group();
        let (c, d) = (Arc::new(()), Arc::new(()));
        for token in [&c, &d] {
            assert!(session.admit(token, RTCDtlsRole::Client, &fingerprints));
            session.join(token, RTCDtlsRole::Client);
        }
        session.close_admission();
        session.settle();
        session.started(&c);
        assert!(!session.store().is_emptied());
        session.ended(&d, Some(now));
        assert!(session.store().is_emptied());
    }

    /// The wait (review F1, F2, F3, F9): the first client transport to start leads; the
    /// others wait, and start
    ///
    /// - at once when the leader's DTLS 1.3 handshake completes with no ticket before it (a
    ///   peer that issues none), or when it is DTLS 1.2;
    /// - when the leader fails, is closed, goes away or cannot start its handshake.
    #[test]
    fn the_others_start_as_soon_as_the_answer_is_known() {
        let now = Instant::now();
        let fingerprints = params(RTCDtlsRole::Server, &certificate()).fingerprints;
        let setup = || {
            let session = group();
            let tokens: Vec<Arc<()>> = (0..3).map(|_| Arc::new(())).collect();
            for token in &tokens {
                assert!(session.admit(token, RTCDtlsRole::Client, &fingerprints));
            }
            assert_eq!(session.start_gate(&tokens[0], now), StartGate::Now);
            assert_eq!(session.start_gate(&tokens[1], now), StartGate::Wait);
            assert_eq!(session.start_gate(&tokens[2], now), StartGate::Wait);
            assert_eq!(session.ready_at(), None);
            (session, tokens)
        };
        let later = now + Duration::from_millis(50);

        // No ticket before the confirmation: no wait.
        let (session, tokens) = setup();
        session.leader_connected(&tokens[0], later, true, Duration::from_millis(400));
        assert_eq!(session.ready_at(), Some(later));
        assert_eq!(session.leader_deadline(&tokens[0]), None);
        assert_eq!(session.start_gate(&tokens[1], later), StartGate::Now);

        // DTLS 1.2: nothing to wait for, tickets or not.
        let (session, tokens) = setup();
        session
            .store()
            .put("peer", plain_ticket(Duration::from_secs(60)));
        session.leader_connected(&tokens[0], later, false, Duration::from_millis(400));
        assert_eq!(session.ready_at(), Some(later));

        // The leader ended, or could not start.
        let (session, tokens) = setup();
        session.ended(&tokens[0], Some(later));
        assert_eq!(session.ready_at(), Some(later));
        assert_eq!(session.start_gate(&tokens[1], later), StartGate::Now);

        // The leader went away.
        let (session, tokens) = setup();
        let leader = tokens[0].clone();
        drop(tokens);
        drop(leader);
        session.observe(later);
        assert_eq!(session.ready_at(), Some(later), "a leader that went away");
    }

    /// When some but not all of the tickets the waiting transports need came with the
    /// confirmation, they wait for the rest of that flight, at most the stated time; enough
    /// tickets end the wait at once.
    #[test]
    fn some_tickets_wait_for_the_rest_of_the_flight_at_most_a_flight_interval() {
        let now = Instant::now();
        let wait = Duration::from_millis(400);
        let fingerprints = params(RTCDtlsRole::Server, &certificate()).fingerprints;
        let setup = || {
            let session = group();
            let tokens: Vec<Arc<()>> = (0..3).map(|_| Arc::new(())).collect();
            for token in &tokens {
                assert!(session.admit(token, RTCDtlsRole::Client, &fingerprints));
            }
            assert_eq!(session.start_gate(&tokens[0], now), StartGate::Now);
            assert_eq!(session.start_gate(&tokens[1], now), StartGate::Wait);
            assert_eq!(session.start_gate(&tokens[2], now), StartGate::Wait);
            (session, tokens)
        };

        // One ticket of the two needed.
        let (session, tokens) = setup();
        session
            .store()
            .put("peer", plain_ticket(Duration::from_secs(60)));
        session.leader_connected(&tokens[0], now, true, wait);
        assert_eq!(session.ready_at(), None, "one of two");
        assert_eq!(session.leader_deadline(&tokens[0]), Some(now + wait));
        session.poll_leader(&tokens[0], now + wait - Duration::from_millis(1));
        assert_eq!(session.ready_at(), None);
        session.poll_leader(&tokens[0], now + wait);
        assert_eq!(session.ready_at(), Some(now + wait), "the bound");

        // The second comes: at once.
        let (session, tokens) = setup();
        session
            .store()
            .put("peer", plain_ticket(Duration::from_secs(60)));
        session.leader_connected(&tokens[0], now, true, wait);
        assert_eq!(session.ready_at(), None);
        session
            .store()
            .put("peer", plain_ticket(Duration::from_secs(60)));
        let soon = now + Duration::from_millis(1);
        session.poll_leader(&tokens[0], soon);
        assert_eq!(session.ready_at(), Some(soon), "enough for both");

        // Two at once: no wait.
        let (session, tokens) = setup();
        session
            .store()
            .put("peer", plain_ticket(Duration::from_secs(60)));
        session
            .store()
            .put("peer", plain_ticket(Duration::from_secs(60)));
        session.leader_connected(&tokens[0], now, true, wait);
        assert_eq!(session.ready_at(), Some(now));
    }
}
