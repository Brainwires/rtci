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
//! WebRTC authenticates every DTLS association by the certificate fingerprints its SDP carries,
//! and makes a new association per session: the peer connection of the `rtc` crate configures
//! no tickets and no session store, so it neither sends nor accepts them.

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

/// Where a client keeps the tickets servers give it, keyed by server name.
///
/// [`take`](SessionStore::take) removes what it returns: a ticket is offered once (RFC 8446
/// appendix C.4), so that two handshakes cannot be linked by it.
pub trait SessionStore: Send + Sync {
    /// Keeps `session`, received from the server configured as `server_name`.
    fn put(&self, server_name: &str, session: Tls13Session);
    /// Takes the most recent session for `server_name`, if there is one.
    fn take(&self, server_name: &str) -> Option<Tls13Session>;
}

/// A [`SessionStore`] in memory: a few tickets per server name, most recent first.
#[derive(Default)]
pub struct MemorySessionStore {
    sessions: Mutex<HashMap<String, VecDeque<Tls13Session>>>,
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
