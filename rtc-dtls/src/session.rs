//! Pre-shared keys for DTLS 1.3 (RFC 8446 sections 2.2, 4.2.9 to 4.2.11 and 4.6.1, as RFC
//! 9147 carries them): session resumption with tickets, and external PSKs.
//!
//! A server that is configured to
//! ([`ConfigBuilder::with_session_tickets`](crate::config::ConfigBuilder::with_session_tickets))
//! sends NewSessionTicket messages after a handshake. Each ticket is the server's own,
//! encrypted under a key only the server holds, and carries the resumption secret, so the
//! server keeps no state per ticket beyond the record that a ticket has been used: a ticket is
//! accepted once (RFC 8446 section 8.1, appendix C.4). A client that is given a
//! [`SessionStore`] ([`ConfigBuilder::with_session_store`](crate::config::ConfigBuilder::with_session_store))
//! keeps the tickets it receives, keyed by its configured server name, and offers one (once) in
//! its next ClientHello to that name.
//!
//! A resumed handshake has no Certificate or CertificateVerify: the peer is the one that held
//! the ticket's secret, which was made in a handshake that authenticated it. The certificates
//! of that handshake are carried with the ticket and are what the association reports, and the
//! configured
//! [`ConfigBuilder::with_verify_peer_certificate`](crate::config::ConfigBuilder::with_verify_peer_certificate)
//! check runs on them again.
//!
//! Only the `psk_dhe_ke` mode is offered and accepted by default: the PSK is combined with a
//! fresh (EC)DHE exchange, which keeps forward secrecy. `psk_ke` (the PSK alone) is an explicit
//! option ([`ConfigBuilder::with_psk_without_key_exchange`](crate::config::ConfigBuilder::with_psk_without_key_exchange)).
//!
//! DTLS 1.2 resumes sessions too (RFC 5246 section 7.3, the abbreviated handshake): by session
//! id, from a [`SessionCache`] the server keeps
//! ([`ConfigBuilder::with_session_cache`](crate::config::ConfigBuilder::with_session_cache)),
//! or by a ticket the server seals for the client (RFC 5077, with
//! [`ConfigBuilder::with_session_tickets`](crate::config::ConfigBuilder::with_session_tickets)).
//! A client keeps its [`Dtls12Session`]s in the same [`SessionStore`]. Only sessions made with
//! the extended master secret are resumed (RFC 7627 section 5.3), with the master secret of
//! the session and fresh randoms: no key exchange, no Certificate, no CertificateVerify. The
//! certificates of the full handshake are what the association reports, and the configured
//! peer-certificate checks run on them again. A session is forgotten when an association that
//! used it fails (RFC 5246 sections 7.2 and 7.2.2).
//!
//! WebRTC authenticates every DTLS association by the certificate fingerprints its SDP carries,
//! and makes a new association per session: the peer connection of the `rtc` crate configures
//! no tickets, no session cache and no session store, so it neither offers nor accepts a
//! resumption in either version.

use crate::cipher_suite::{CipherSuiteHash, CipherSuiteId};
use crypto::SecretVec;
use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// The longest a ticket may be used for (RFC 8446 section 4.6.1: seven days).
pub const MAX_TICKET_LIFETIME: Duration = Duration::from_secs(604_800);

/// How many tickets [`MemorySessionStore`] keeps for one server name.
const MAX_SESSIONS_PER_NAME: usize = 8;
/// How many server names [`MemorySessionStore`] keeps tickets for.
const MAX_NAMES: usize = 256;

/// A ticket a client received in a NewSessionTicket, with what it needs to resume: the
/// resumption PSK derived for it, the suite it belongs to, and the certificates of the
/// handshake it came from. Opaque to applications; a [`SessionStore`] keeps it.
#[derive(Clone)]
pub struct Tls13Session {
    pub(crate) ticket: Vec<u8>,
    pub(crate) secret: SecretVec,
    pub(crate) suite: CipherSuiteId,
    pub(crate) received: Instant,
    pub(crate) lifetime: Duration,
    pub(crate) age_add: u32,
    pub(crate) max_early_data: u32,
    pub(crate) peer_certificates: Vec<Vec<u8>>,
}

impl Tls13Session {
    /// Whether the ticket may still be offered at `now` (RFC 8446 section 4.6.1: not after
    /// its lifetime, and never after seven days).
    pub fn is_valid_at(&self, now: Instant) -> bool {
        now.saturating_duration_since(self.received) < self.lifetime.min(MAX_TICKET_LIFETIME)
    }

    /// The cipher suite of the handshake that issued the ticket. It may be resumed only with
    /// a suite of the same hash (RFC 8446 section 4.6.1).
    pub fn cipher_suite(&self) -> CipherSuiteId {
        self.suite
    }

    /// The most early data the server said it would take with this ticket, 0 for none.
    pub fn max_early_data(&self) -> u32 {
        self.max_early_data
    }

    /// The `obfuscated_ticket_age` of an offer made at `now` (RFC 8446 section 4.2.11.1): the
    /// milliseconds since the ticket arrived, plus `ticket_age_add`, modulo 2^32.
    pub(crate) fn obfuscated_age(&self, now: Instant) -> u32 {
        let age = now.saturating_duration_since(self.received).as_millis() as u32;
        age.wrapping_add(self.age_add)
    }
}

impl fmt::Debug for Tls13Session {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Tls13Session")
            .field("suite", &self.suite)
            .field("lifetime", &self.lifetime)
            .field("max_early_data", &self.max_early_data)
            .field("ticket_len", &self.ticket.len())
            .finish_non_exhaustive()
    }
}

/// How many sessions [`MemorySessionCache`] keeps by default.
const DEFAULT_SESSION_CACHE_CAPACITY: usize = 1024;

/// A DTLS 1.2 session (RFC 5246 section 7.3) that a handshake may resume: what the full
/// handshake that made it agreed on. A server keeps it in its [`SessionCache`] under its
/// session id, or seals it into a ticket (RFC 5077); a client keeps it in its
/// [`SessionStore`], with the ticket if the server gave one. Opaque to applications.
#[derive(Clone)]
pub struct Dtls12Session {
    /// The session id of the ServerHello that established or last resumed it (empty when the
    /// server gave a ticket and no id).
    pub(crate) session_id: Vec<u8>,
    /// Client: the ticket (RFC 5077) to present, if the server gave one.
    pub(crate) ticket: Option<Vec<u8>>,
    pub(crate) master_secret: SecretVec,
    pub(crate) cipher_suite: CipherSuiteId,
    /// Made with the extended master secret (RFC 7627). A session made without it is never
    /// resumed by this crate (section 5.3); the flag is kept so that the rules can be applied
    /// to one from elsewhere.
    pub(crate) extended_master_secret: bool,
    /// The peer's certificate chain in the full handshake.
    pub(crate) peer_certificates: Vec<Vec<u8>>,
    /// Server: the client's chain was verified (client authentication).
    pub(crate) peer_certificates_verified: bool,
    /// The server name of the full handshake (RFC 6066 section 3: a server does not resume a
    /// session for another name).
    pub(crate) server_name: String,
    pub(crate) created: Instant,
    pub(crate) lifetime: Duration,
}

impl Dtls12Session {
    /// Whether the session may still be resumed at `now`: not after its lifetime (RFC 5246
    /// appendix F.1.4 suggests no more than 24 hours).
    pub fn is_valid_at(&self, now: Instant) -> bool {
        now.saturating_duration_since(self.created) < self.lifetime
    }

    /// The cipher suite of the session: a resumption uses the same (RFC 5246 7.4.1.3).
    pub fn cipher_suite(&self) -> CipherSuiteId {
        self.cipher_suite
    }

    /// The session id, empty for a session known by its ticket only.
    pub fn session_id(&self) -> &[u8] {
        &self.session_id
    }

    /// Whether the client holds a ticket (RFC 5077) for the session.
    pub fn has_ticket(&self) -> bool {
        self.ticket.is_some()
    }
}

impl fmt::Debug for Dtls12Session {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Dtls12Session")
            .field("session_id", &self.session_id)
            .field("cipher_suite", &self.cipher_suite)
            .field("extended_master_secret", &self.extended_master_secret)
            .field("has_ticket", &self.ticket.is_some())
            .field("lifetime", &self.lifetime)
            .finish_non_exhaustive()
    }
}

/// Where a client keeps the tickets servers give it, keyed by server name.
///
/// [`take`](SessionStore::take) removes what it returns: a ticket is offered once (RFC 8446
/// appendix C.4), so that two handshakes cannot be linked by it.
///
/// The DTLS 1.2 methods have defaults that keep nothing, so a store written for DTLS 1.3 only
/// resumes no DTLS 1.2 session. A store that keeps DTLS 1.2 sessions must implement
/// [`forget_dtls12`](SessionStore::forget_dtls12): RFC 5246 section 7.2.2 forbids resuming
/// a session whose connection ended with a fatal alert.
pub trait SessionStore: Send + Sync {
    /// Keeps `session`, received from the server configured as `server_name`.
    fn put(&self, server_name: &str, session: Tls13Session);
    /// Takes the most recent session for `server_name`, if there is one.
    fn take(&self, server_name: &str) -> Option<Tls13Session>;

    /// Keeps a DTLS 1.2 session made with the server configured as `server_name`.
    fn put_dtls12(&self, _server_name: &str, _session: Dtls12Session) {}
    /// Takes the most recent DTLS 1.2 session for `server_name`. A session id session that
    /// is resumed is put back; a ticket is offered once.
    fn take_dtls12(&self, _server_name: &str) -> Option<Dtls12Session> {
        None
    }
    /// Forgets the DTLS 1.2 session `session_id` of `server_name`: its connection failed.
    fn forget_dtls12(&self, _server_name: &str, _session_id: &[u8]) {}
}

/// A [`SessionStore`] in memory: a few tickets per server name, most recent first.
#[derive(Default)]
pub struct MemorySessionStore {
    sessions: Mutex<HashMap<String, VecDeque<Tls13Session>>>,
    dtls12: Mutex<HashMap<String, VecDeque<Dtls12Session>>>,
}

impl MemorySessionStore {
    /// An empty store.
    pub fn new() -> Self {
        Self::default()
    }

    /// How many tickets the store holds for `server_name`.
    pub fn len(&self, server_name: &str) -> usize {
        self.sessions
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get(server_name)
            .map_or(0, VecDeque::len)
    }

    /// How many DTLS 1.2 sessions the store holds for `server_name`.
    pub fn len_dtls12(&self, server_name: &str) -> usize {
        self.dtls12
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get(server_name)
            .map_or(0, VecDeque::len)
    }
}

impl fmt::Debug for MemorySessionStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MemorySessionStore").finish_non_exhaustive()
    }
}

impl SessionStore for MemorySessionStore {
    fn put(&self, server_name: &str, session: Tls13Session) {
        let mut sessions = self
            .sessions
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if !sessions.contains_key(server_name) && sessions.len() >= MAX_NAMES {
            return;
        }
        let list = sessions.entry(server_name.to_owned()).or_default();
        list.push_front(session);
        list.truncate(MAX_SESSIONS_PER_NAME);
    }

    fn take(&self, server_name: &str) -> Option<Tls13Session> {
        let mut sessions = self
            .sessions
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let list = sessions.get_mut(server_name)?;
        let session = list.pop_front();
        if list.is_empty() {
            sessions.remove(server_name);
        }
        session
    }

    fn put_dtls12(&self, server_name: &str, session: Dtls12Session) {
        let mut sessions = self
            .dtls12
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if !sessions.contains_key(server_name) && sessions.len() >= MAX_NAMES {
            return;
        }
        let list = sessions.entry(server_name.to_owned()).or_default();
        list.push_front(session);
        list.truncate(MAX_SESSIONS_PER_NAME);
    }

    fn take_dtls12(&self, server_name: &str) -> Option<Dtls12Session> {
        let mut sessions = self
            .dtls12
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let list = sessions.get_mut(server_name)?;
        let session = list.pop_front();
        if list.is_empty() {
            sessions.remove(server_name);
        }
        session
    }

    fn forget_dtls12(&self, server_name: &str, session_id: &[u8]) {
        let mut sessions = self
            .dtls12
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(list) = sessions.get_mut(server_name) {
            list.retain(|session| session.session_id != session_id);
            if list.is_empty() {
                sessions.remove(server_name);
            }
        }
    }
}

/// Where a DTLS 1.2 server keeps the sessions it may resume by session id (RFC 5246 sections
/// 7.3, 7.4.1.3). A server without one gives no session id and resumes by ticket only, if
/// it issues tickets.
pub trait SessionCache: Send + Sync {
    /// Keeps `session` under its session id.
    fn put(&self, session: Dtls12Session);
    /// The session `session_id`, if it is kept.
    fn get(&self, session_id: &[u8]) -> Option<Dtls12Session>;
    /// Forgets the session `session_id` (RFC 5246 7.2: its connection failed).
    fn remove(&self, session_id: &[u8]);
}

/// The sessions of a [`MemorySessionCache`], by id, and their ids oldest first.
#[derive(Default)]
struct CachedSessions {
    by_id: HashMap<Vec<u8>, Dtls12Session>,
    order: VecDeque<Vec<u8>>,
}

/// A [`SessionCache`] in memory, of a bounded size: the oldest session goes first.
pub struct MemorySessionCache {
    capacity: usize,
    sessions: Mutex<CachedSessions>,
}

impl MemorySessionCache {
    /// A cache of at most `capacity` sessions.
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity: capacity.max(1),
            sessions: Mutex::new(CachedSessions::default()),
        }
    }

    /// How many sessions the cache holds.
    pub fn len(&self) -> usize {
        self.sessions
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .by_id
            .len()
    }

    /// Whether the cache holds no session.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl Default for MemorySessionCache {
    fn default() -> Self {
        Self::new(DEFAULT_SESSION_CACHE_CAPACITY)
    }
}

impl fmt::Debug for MemorySessionCache {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MemorySessionCache")
            .field("capacity", &self.capacity)
            .finish_non_exhaustive()
    }
}

impl SessionCache for MemorySessionCache {
    fn put(&self, session: Dtls12Session) {
        let mut guard = self
            .sessions
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let CachedSessions { by_id, order } = &mut *guard;
        let id = session.session_id.clone();
        if by_id.insert(id.clone(), session).is_none() {
            order.push_back(id);
        }
        while by_id.len() > self.capacity {
            let Some(oldest) = order.pop_front() else {
                break;
            };
            by_id.remove(&oldest);
        }
    }

    fn get(&self, session_id: &[u8]) -> Option<Dtls12Session> {
        self.sessions
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .by_id
            .get(session_id)
            .cloned()
    }

    fn remove(&self, session_id: &[u8]) {
        let mut guard = self
            .sessions
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let CachedSessions { by_id, order } = &mut *guard;
        if by_id.remove(session_id).is_some() {
            order.retain(|id| id.as_slice() != session_id);
        }
    }
}

/// An external pre-shared key for DTLS 1.3 (RFC 8446 section 2.2): an identity both sides
/// know and a secret both hold, provisioned out of band. A client offers each it is configured
/// with; a server accepts the one whose identity it has, in place of certificates.
///
/// The secret should have at least 128 bits of entropy (RFC 9257 section 4): a low-entropy
/// key, such as a password, can be found by anyone who sees one handshake.
#[derive(Clone)]
pub struct ExternalPsk {
    pub(crate) identity: Vec<u8>,
    pub(crate) secret: SecretVec,
    pub(crate) hash: CipherSuiteHash,
}

impl ExternalPsk {
    /// A PSK for the SHA-256 suites.
    pub fn new(identity: Vec<u8>, secret: Vec<u8>) -> Self {
        Self {
            identity,
            secret: SecretVec::new(secret),
            hash: CipherSuiteHash::Sha256,
        }
    }

    /// The same PSK for the SHA-384 suite (`TLS_AES_256_GCM_SHA384`) instead: a PSK is bound
    /// to one hash (RFC 8446 section 4.2.11).
    pub fn with_hash(mut self, hash: CipherSuiteHash) -> Self {
        self.hash = hash;
        self
    }

    /// The identity.
    pub fn identity(&self) -> &[u8] {
        &self.identity
    }
}

impl fmt::Debug for ExternalPsk {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ExternalPsk")
            .field("identity", &self.identity)
            .field("hash", &self.hash)
            .finish_non_exhaustive()
    }
}
