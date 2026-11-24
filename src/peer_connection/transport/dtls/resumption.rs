//! One DTLS session per peer connection (RFC 5764 section 3).
//!
//! A peer connection whose m= sections are not bundled has a DTLS association per transport.
//! RFC 5764 section 3: "the DTLS-SRTP implementation SHOULD use the following strategy: a
//! single DTLS association is established, and all other DTLS associations wait until that
//! connection is established before proceeding with their handshakes. This establishes a
//! single session and all other associations can take advantage of TLS session resumption."
//!
//! A [`DtlsSessionGroup`] is that session's home: one per peer connection, never shared with
//! another, holding what the transports of the connection resume from:
//!
//! - as the DTLS client, a session store: the DTLS 1.3 tickets (RFC 8446 section 4.6.1) and
//!   DTLS 1.2 sessions (RFC 5246 section 7.3, RFC 5077) the peer gave this connection;
//! - as the DTLS server, the keys its tickets are sealed under and a DTLS 1.2 session cache, so
//!   that a ticket or session one transport's handshake made is accepted by another.
//!
//! What a transport may do with it:
//!
//! - Only the first association of a transport set up by the negotiation that set up the
//!   transports takes part ([`DtlsSessionGroup::close_admission`]): a later association (a new
//!   one for SRTP re-keying, an ICE restart with new DTLS parameters, a transport added later)
//!   runs a full handshake, with a fresh (EC)DHE exchange and no ticket.
//! - Only transports whose section names the same remote fingerprints as the first transport
//!   of the same DTLS role that took part ([`DtlsSessionGroup::admit`]): the session was made
//!   with a peer certificate those fingerprints matched. Each transport's configured
//!   certificate check (its own section's fingerprints) also runs on the certificates stored
//!   with the session or ticket (`rtci-dtls`), and the group keeps no session that has none
//!   ([`GroupSessionStore`], [`GroupSessionCache`]): a resumption is refused, not let through,
//!   when there is nothing to check.
//! - DTLS 1.3 resumes with `psk_dhe_ke` only (the `rtci-dtls` default): the PSK is combined
//!   with a fresh (EC)DHE exchange.
//!
//! The wait: the first client transport to start a handshake leads; every other client
//! transport of the group waits until the leader is connected and the peer's ticket or
//! session has arrived (or a short while has passed without one, or the leader failed or was
//! closed), then starts and offers it. Bundled connections have one transport and do not
//! wait.

use crate::peer_connection::transport::dtls::fingerprint::RTCDtlsFingerprint;
use crate::peer_connection::transport::dtls::role::RTCDtlsRole;
use crate::peer_connection::transport::dtls::same_fingerprints;
use crypto::RTCCryptoProvider;
use dtls::session::{
    Dtls12Session, MemorySessionCache, MemorySessionStore, SessionCache, SessionStore,
    SessionTicketIssuer, Tls13Session,
};
use shared::error::Result;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::time::{Duration, Instant};

/// How many DTLS 1.3 tickets the server side sends after each handshake: one per other
/// transport the peer may resume with (a ticket is offered once, RFC 8446 appendix C.4).
pub(crate) const TICKETS_PER_HANDSHAKE: u8 = 4;
/// How long the group's tickets and DTLS 1.2 sessions may be resumed: they are made for the
/// transports of one negotiation, which start their handshakes as soon as the first one has
/// finished.
pub(crate) const SESSION_LIFETIME: Duration = Duration::from_secs(5 * 60);

/// The client side's session store: what the peer issued to this connection. It keeps no
/// session without the peer certificates of the handshake that made it, so that every
/// resumption has certificates for the transport's fingerprint check to run on.
#[derive(Default)]
pub(crate) struct GroupSessionStore {
    inner: MemorySessionStore,
    /// How many sessions were kept so far.
    stored: AtomicUsize,
}

impl GroupSessionStore {
    /// How many sessions were kept so far.
    pub(crate) fn stored(&self) -> usize {
        self.stored.load(Ordering::Relaxed)
    }
}

impl SessionStore for GroupSessionStore {
    fn put(&self, server_name: &str, session: Tls13Session) {
        if session.peer_certificates().is_empty() {
            return;
        }
        self.inner.put(server_name, session);
        self.stored.fetch_add(1, Ordering::Relaxed);
    }

    fn take(&self, server_name: &str) -> Option<Tls13Session> {
        loop {
            let session = self.inner.take(server_name)?;
            if !session.peer_certificates().is_empty() {
                return Some(session);
            }
        }
    }

    fn put_dtls12(&self, server_name: &str, session: Dtls12Session) {
        if session.peer_certificates().is_empty() {
            return;
        }
        self.inner.put_dtls12(server_name, session);
        self.stored.fetch_add(1, Ordering::Relaxed);
    }

    fn take_dtls12(&self, server_name: &str) -> Option<Dtls12Session> {
        loop {
            let session = self.inner.take_dtls12(server_name)?;
            if !session.peer_certificates().is_empty() {
                return Some(session);
            }
        }
    }

    fn forget_dtls12(&self, server_name: &str, session_id: &[u8]) {
        self.inner.forget_dtls12(server_name, session_id);
    }
}

/// The server side's DTLS 1.2 session cache, with the same rule as [`GroupSessionStore`].
#[derive(Default)]
pub(crate) struct GroupSessionCache {
    inner: MemorySessionCache,
}

impl SessionCache for GroupSessionCache {
    fn put(&self, session: Dtls12Session) {
        if !session.peer_certificates().is_empty() {
            self.inner.put(session);
        }
    }

    fn get(&self, session_id: &[u8]) -> Option<Dtls12Session> {
        self.inner
            .get(session_id)
            .filter(|session| !session.peer_certificates().is_empty())
    }

    fn remove(&self, session_id: &[u8]) {
        self.inner.remove(session_id);
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
    /// When its handshake completed, with the store's count of sessions then and how long
    /// it waits for one after that.
    connected: Option<(Instant, usize, Duration)>,
    /// When the others may start.
    ready_at: Option<Instant>,
}

impl Leader {
    fn is(&self, token: &Arc<()>) -> bool {
        std::ptr::eq(self.token.as_ptr(), Arc::as_ptr(token))
    }
}

struct GroupState {
    /// Transports may still join: the negotiation that set up the transports is under way.
    admission_open: bool,
    /// The remote fingerprints of the first client transport that joined.
    client_origin: Option<Vec<RTCDtlsFingerprint>>,
    /// The remote fingerprints of the first server transport that joined.
    server_origin: Option<Vec<RTCDtlsFingerprint>>,
    leader: Option<Leader>,
    /// The latest instant a transport of the connection was given.
    last_now: Option<Instant>,
}

/// The DTLS session of one peer connection (RFC 5764 section 3): see the module.
pub(crate) struct DtlsSessionGroup {
    store: Arc<GroupSessionStore>,
    cache: Arc<GroupSessionCache>,
    tickets: SessionTicketIssuer,
    state: Mutex<GroupState>,
}

impl std::fmt::Debug for DtlsSessionGroup {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DtlsSessionGroup").finish_non_exhaustive()
    }
}

impl DtlsSessionGroup {
    /// The group of a new peer connection: an empty store and cache, and new ticket keys from
    /// `provider`.
    pub(crate) fn new(provider: &dyn RTCCryptoProvider) -> Result<Self> {
        Ok(Self {
            store: Arc::new(GroupSessionStore::default()),
            cache: Arc::new(GroupSessionCache::default()),
            tickets: SessionTicketIssuer::new(provider, TICKETS_PER_HANDSHAKE, SESSION_LIFETIME)?,
            state: Mutex::new(GroupState {
                admission_open: true,
                client_origin: None,
                server_origin: None,
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

    /// Whether the first association of a transport in `role`, for a section naming the
    /// remote fingerprints `remote`, takes part: admission is open and `remote` names the same
    /// certificates as the first transport of that role that took part (which it becomes,
    /// when it is the first).
    pub(crate) fn admit(&self, role: RTCDtlsRole, remote: &[RTCDtlsFingerprint]) -> bool {
        let mut state = self.lock();
        if !state.admission_open || remote.is_empty() {
            return false;
        }
        let origin = match role {
            RTCDtlsRole::Client => &mut state.client_origin,
            RTCDtlsRole::Server => &mut state.server_origin,
            _ => return false,
        };
        match origin {
            None => {
                *origin = Some(remote.to_vec());
                true
            }
            Some(origin) => same_fingerprints(origin, remote),
        }
    }

    /// The negotiation that set up the transports is done: no association joins from now on.
    pub(crate) fn close_admission(&self) {
        self.lock().admission_open = false;
    }

    /// `builder`, configured to resume from the group in `role`: as the client with the store,
    /// as the server with the shared ticket keys and the session cache.
    pub(crate) fn configure(
        &self,
        builder: dtls::config::ConfigBuilder,
        role: RTCDtlsRole,
    ) -> dtls::config::ConfigBuilder {
        if role == RTCDtlsRole::Client {
            builder.with_session_store(Some(self.store.clone() as Arc<dyn SessionStore>))
        } else {
            builder
                .with_session_ticket_issuer(Some(self.tickets.clone()))
                .with_session_ticket_lifetime(SESSION_LIFETIME)
                .with_session_cache(Some(self.cache.clone() as Arc<dyn SessionCache>))
        }
    }

    /// A transport of the connection was given `now`.
    pub(crate) fn observe(&self, now: Instant) {
        let mut state = self.lock();
        state.last_now = Some(state.last_now.map_or(now, |last| last.max(now)));
    }

    /// The client transport `token` would start its handshake at `now`: it leads when no
    /// transport does, and waits while the leader's handshake (and the session it brings) is
    /// under way.
    pub(crate) fn start_gate(&self, token: &Arc<()>, now: Instant) -> StartGate {
        self.observe(now);
        let mut state = self.lock();
        let last_now = state.last_now.unwrap_or(now);
        match &mut state.leader {
            None => {
                state.leader = Some(Leader {
                    token: Arc::downgrade(token),
                    connected: None,
                    ready_at: None,
                });
                StartGate::Now
            }
            Some(leader) if leader.is(token) => StartGate::Now,
            Some(leader) => {
                if leader.ready_at.is_none() && leader.token.strong_count() == 0 {
                    leader.ready_at = Some(last_now);
                }
                if leader.ready_at.is_some() {
                    StartGate::Now
                } else {
                    StartGate::Wait
                }
            }
        }
    }

    /// When a waiting transport may start: `None` while the leader's handshake is under way.
    pub(crate) fn ready_at(&self) -> Option<Instant> {
        let mut state = self.lock();
        let last_now = state.last_now;
        let leader = state.leader.as_mut()?;
        if leader.ready_at.is_none() && leader.token.strong_count() == 0 {
            leader.ready_at = last_now;
        }
        leader.ready_at
    }

    /// The handshake of `token` completed at `now`: when it is the leader, the others start
    /// once the peer's session has come, or `grace` from now without one.
    pub(crate) fn connected(&self, token: &Arc<()>, now: Instant, grace: Duration) {
        let stored = self.store.stored();
        let mut state = self.lock();
        if let Some(leader) = state.leader.as_mut()
            && leader.is(token)
            && leader.connected.is_none()
        {
            leader.connected = Some((now, stored, grace));
        }
        drop(state);
        self.poll_leader(token, now);
    }

    /// The leader `token` at `now`: the others may start once it is connected and a session
    /// has come since, or its grace is over.
    pub(crate) fn poll_leader(&self, token: &Arc<()>, now: Instant) {
        let stored = self.store.stored();
        let mut state = self.lock();
        if let Some(leader) = state.leader.as_mut()
            && leader.is(token)
            && leader.ready_at.is_none()
            && let Some((at, stored_then, grace)) = leader.connected
            && (stored > stored_then || now >= at + grace)
        {
            leader.ready_at = Some(now);
        }
    }

    /// When the leader `token` stops waiting for the peer's session without one.
    pub(crate) fn leader_deadline(&self, token: &Arc<()>) -> Option<Instant> {
        let state = self.lock();
        let leader = state.leader.as_ref()?;
        if !leader.is(token) || leader.ready_at.is_some() {
            return None;
        }
        leader.connected.map(|(at, _, grace)| at + grace)
    }

    /// The association of `token` ended (failed, closed or replaced): when it led and the
    /// others still wait, they start, with full handshakes if no session came.
    pub(crate) fn ended(&self, token: &Arc<()>) {
        let mut state = self.lock();
        let last_now = state.last_now;
        if let Some(leader) = state.leader.as_mut()
            && leader.is(token)
            && leader.ready_at.is_none()
        {
            leader.ready_at = last_now;
            if leader.ready_at.is_none() {
                // Never given a time: nothing waits on an instant either.
                leader.token = Weak::new();
            }
        }
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

    /// The first association of a new transport of the connection with certificate `local`
    /// and session `group`, as the DTLS client of a peer with certificate `remote`.
    fn client(
        local: &RTCCertificate,
        group: &Arc<DtlsSessionGroup>,
        remote: &RTCCertificate,
    ) -> Arc<HandshakeConfig> {
        engine_transport(local, group)
            .prepare_transport(RTCIceRole::Controlled, params(RTCDtlsRole::Server, remote))
            .expect("a client config")
    }

    /// The same as the DTLS server.
    fn server(
        local: &RTCCertificate,
        group: &Arc<DtlsSessionGroup>,
        remote: &RTCCertificate,
    ) -> Arc<HandshakeConfig> {
        engine_transport(local, group)
            .prepare_transport(RTCIceRole::Controlling, params(RTCDtlsRole::Client, remote))
            .expect("a server config")
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

        let mut transport = engine_transport(&ours, &clients);
        transport
            .prepare_transport(RTCIceRole::Controlled, params(RTCDtlsRole::Server, &theirs))
            .expect("the first association");
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

    /// Only the transports of the negotiation that set up the connection's transports take
    /// part, and only for the remote certificates the session was made with: a section naming
    /// another certificate's fingerprints is outside it, in both roles.
    #[test]
    fn admission_follows_the_first_negotiation_and_the_fingerprints() {
        let (theirs, other) = (certificate(), certificate());
        let fingerprints = |certificate: &RTCCertificate| {
            certificate
                .get_fingerprints(provider().crypto())
                .expect("fingerprints")
        };
        let session = group();
        for role in [RTCDtlsRole::Client, RTCDtlsRole::Server] {
            assert!(
                session.admit(role, &fingerprints(&theirs)),
                "{role}: the first"
            );
            assert!(
                session.admit(role, &fingerprints(&theirs)),
                "{role}: the same"
            );
            assert!(
                !session.admit(role, &fingerprints(&other)),
                "{role}: another"
            );
        }
        session.close_admission();
        assert!(!session.admit(RTCDtlsRole::Client, &fingerprints(&theirs)));
    }
}
