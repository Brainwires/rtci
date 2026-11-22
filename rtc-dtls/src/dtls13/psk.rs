//! The machinery of DTLS 1.3 pre-shared keys (RFC 8446 sections 4.2.9 to 4.2.11, 4.6.1 and
//! 8.1): the `psk_key_exchange_modes` and `pre_shared_key` extensions, the binders, the
//! server's self-encrypted tickets and the record of the tickets it has accepted.

use super::codec::*;
use super::key_schedule::{DTLS13_LABEL_PREFIX, KeySchedule, Transcript};
use super::messages::CLIENT_HELLO;
use super::suite::Suite13;
use crate::cipher_suite::{CipherSuiteHash, CipherSuiteId};
use crate::session::{ExternalPsk, MAX_TICKET_LIFETIME, Tls13Session};
use crypto::{AeadAlgorithm, HashAlgorithm, RTCCrypto, RTCCryptoProvider, SecretVec};
use shared::error::{Error, Result};
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// `psk_ke`: the PSK alone, no (EC)DHE (RFC 8446 section 4.2.9).
pub(crate) const PSK_KE: u8 = 0;
/// `psk_dhe_ke`: the PSK with an (EC)DHE exchange.
pub(crate) const PSK_DHE_KE: u8 = 1;

/// The default lifetime of the tickets a server issues.
pub(crate) const DEFAULT_TICKET_LIFETIME: Duration = Duration::from_secs(2 * 60 * 60);
/// How many accepted tickets a server remembers, to refuse them a second time. A server with
/// that many unexpired ones refuses the next resumption (a full handshake instead) rather than
/// forget one.
const MAX_USED_TICKETS: usize = 65_536;
/// The longest certificate chain a ticket carries; a server whose peer sent a longer one
/// issues no ticket.
const MAX_TICKET_CHAIN: usize = 16 * 1024;

const TICKET_VERSION: u8 = 1;
const TICKET_NONCE_LEN: usize = 12;
const TICKET_TAG_LEN: usize = 16;
const TICKET_KEY_LEN: usize = 32;
const TICKET_AAD: &[u8] = b"rtc-dtls dtls13 ticket";

fn crypto_error(error: crypto::CryptoError) -> Error {
    Error::Crypto(error.to_string())
}

pub(crate) fn hash_of(hash: CipherSuiteHash) -> HashAlgorithm {
    match hash {
        CipherSuiteHash::Sha384 => HashAlgorithm::Sha384,
        _ => HashAlgorithm::Sha256,
    }
}

/// One PSK a client offers.
#[derive(Clone)]
pub(crate) struct OfferedPsk {
    pub(crate) identity: Vec<u8>,
    pub(crate) obfuscated_age: u32,
    pub(crate) secret: SecretVec,
    /// The suite whose hash the PSK belongs to: the ticket's, or for an external PSK the
    /// first of this side's suites with its hash.
    pub(crate) suite: Suite13,
    pub(crate) external: bool,
    /// The certificates of the handshake that issued the ticket.
    pub(crate) peer_certificates: Vec<Vec<u8>>,
}

impl OfferedPsk {
    pub(crate) fn from_session(session: Tls13Session, now: Instant) -> Option<Self> {
        Some(Self {
            obfuscated_age: session.obfuscated_age(now),
            suite: Suite13::for_id(session.suite)?,
            identity: session.ticket,
            secret: session.secret,
            external: false,
            peer_certificates: session.peer_certificates,
        })
    }

    pub(crate) fn from_external(psk: &ExternalPsk, suites: &[CipherSuiteId]) -> Option<Self> {
        let hash = hash_of(psk.hash);
        let suite = suites
            .iter()
            .filter_map(|suite| Suite13::for_id(*suite))
            .find(|suite| suite.hash() == hash)?;
        Some(Self {
            identity: psk.identity.clone(),
            obfuscated_age: 0,
            secret: psk.secret.clone(),
            suite,
            external: true,
            peer_certificates: vec![],
        })
    }
}

/// The extension_data of `psk_key_exchange_modes`.
pub(crate) fn psk_key_exchange_modes_data(modes: &[u8]) -> Vec<u8> {
    let mut data = vec![];
    put_vec8(&mut data, |out| out.extend_from_slice(modes));
    data
}

/// The modes of a `psk_key_exchange_modes` extension.
pub(crate) fn parse_psk_key_exchange_modes(data: &[u8]) -> Result<&[u8]> {
    let mut reader = Reader::new(data);
    let modes = reader.vec8()?;
    reader.finish()?;
    if modes.is_empty() {
        return Err(Error::ErrLengthMismatch);
    }
    Ok(modes)
}

/// The extension_data of a ClientHello's `pre_shared_key`: the identities with their
/// obfuscated ages, then the binders (RFC 8446 section 4.2.11).
pub(crate) fn pre_shared_key_data(psks: &[OfferedPsk], binders: &[Vec<u8>]) -> Vec<u8> {
    let mut data = vec![];
    put_vec16(&mut data, |list| {
        for psk in psks {
            put_vec16(list, |out| out.extend_from_slice(&psk.identity));
            list.extend_from_slice(&psk.obfuscated_age.to_be_bytes());
        }
    });
    put_binders(&mut data, binders);
    data
}

fn put_binders(out: &mut Vec<u8>, binders: &[Vec<u8>]) {
    put_vec16(out, |list| {
        for binder in binders {
            put_vec8(list, |out| out.extend_from_slice(binder));
        }
    });
}

/// Zero binders of the right lengths, which the real ones replace once the ClientHello they
/// cover is written.
pub(crate) fn placeholder_binders(psks: &[OfferedPsk]) -> Vec<Vec<u8>> {
    psks.iter()
        .map(|psk| vec![0u8; psk.suite.hash_len()])
        .collect()
}

/// How many bytes the binders list (with its length) takes at the end of a ClientHello.
pub(crate) fn binders_len(psks: &[OfferedPsk]) -> usize {
    2 + psks
        .iter()
        .map(|psk| 1 + psk.suite.hash_len())
        .sum::<usize>()
}

/// A ClientHello's `pre_shared_key`, as received.
pub(crate) struct ClientPsks<'a> {
    pub(crate) identities: Vec<(&'a [u8], u32)>,
    pub(crate) binders: Vec<&'a [u8]>,
    /// The length of the binders list with its length field: what the binders' transcript
    /// leaves out at the end of the ClientHello.
    pub(crate) binders_len: usize,
}

/// Reads a ClientHello's `pre_shared_key` (RFC 8446 section 4.2.11): at least one identity,
/// and one binder of 32 to 255 bytes for each.
pub(crate) fn parse_client_pre_shared_key(data: &[u8]) -> Result<ClientPsks<'_>> {
    let mut reader = Reader::new(data);
    let mut identities_reader = Reader::new(reader.vec16()?);
    let rest = reader.rest();
    let mut reader = Reader::new(rest);
    let mut binders_reader = Reader::new(reader.vec16()?);
    reader.finish()?;
    let mut identities = vec![];
    while !identities_reader.is_empty() {
        let identity = identities_reader.vec16()?;
        if identity.is_empty() {
            return Err(Error::ErrLengthMismatch);
        }
        identities.push((identity, identities_reader.u32()?));
    }
    let mut binders = vec![];
    while !binders_reader.is_empty() {
        let binder = binders_reader.vec8()?;
        if binder.len() < 32 {
            return Err(Error::ErrLengthMismatch);
        }
        binders.push(binder);
    }
    if identities.is_empty() || identities.len() != binders.len() {
        return Err(Error::ErrLengthMismatch);
    }
    Ok(ClientPsks {
        identities,
        binders,
        binders_len: rest.len(),
    })
}

/// The binder of one PSK over a ClientHello (RFC 8446 section 4.2.11.2):
/// `HMAC(finished_key of binder_key, Transcript-Hash(prefix, Truncate(ClientHello)))`, where
/// the truncated ClientHello is the message in its TLS 1.3 form (RFC 9147 section 5.2), header
/// with the length of the whole, up to the binders list. `prefix` holds what comes before the
/// ClientHello in the transcript: nothing, or the message_hash and HelloRetryRequest.
pub(crate) fn binder(
    crypto: &dyn RTCCrypto,
    suite: Suite13,
    secret: &[u8],
    external: bool,
    prefix: &Transcript,
    client_hello: &[u8],
    binders_len: usize,
) -> Result<Vec<u8>> {
    binder_with_label_prefix(
        crypto,
        suite,
        secret,
        external,
        prefix,
        client_hello,
        binders_len,
        DTLS13_LABEL_PREFIX,
    )
}

/// [`binder`] with the label prefix given: TLS 1.3's for the RFC 8448 trace.
#[allow(clippy::too_many_arguments)]
pub(crate) fn binder_with_label_prefix(
    crypto: &dyn RTCCrypto,
    suite: Suite13,
    secret: &[u8],
    external: bool,
    prefix: &Transcript,
    client_hello: &[u8],
    binders_len: usize,
    label_prefix: &'static str,
) -> Result<Vec<u8>> {
    let truncated = client_hello
        .len()
        .checked_sub(binders_len)
        .ok_or(Error::ErrLengthMismatch)?;
    let mut message = vec![CLIENT_HELLO];
    put_u24(&mut message, client_hello.len());
    message.extend_from_slice(&client_hello[..truncated]);
    let transcript_hash = prefix.hash_with(crypto, suite, &message)?;
    let schedule = KeySchedule::with_psk(crypto, suite, label_prefix, secret)?;
    let binder_key = schedule.binder_key(crypto, external)?;
    schedule.finished_verify_data(crypto, binder_key.as_ref(), &transcript_hash)
}

/// Writes the binders of `psks` over `client_hello` into its last bytes, the binders list.
pub(crate) fn bind(
    crypto: &dyn RTCCrypto,
    psks: &[OfferedPsk],
    prefix: &Transcript,
    client_hello: &mut [u8],
) -> Result<()> {
    let length = binders_len(psks);
    let mut binders = vec![];
    for psk in psks {
        binders.push(binder(
            crypto,
            psk.suite,
            psk.secret.as_ref(),
            psk.external,
            prefix,
            client_hello,
            length,
        )?);
    }
    let mut list = vec![];
    put_binders(&mut list, &binders);
    let at = client_hello
        .len()
        .checked_sub(length)
        .filter(|_| list.len() == length)
        .ok_or(Error::ErrLengthMismatch)?;
    client_hello[at..].copy_from_slice(&list);
    Ok(())
}

/// What a server's ticket holds, once opened.
pub(crate) struct TicketContents {
    /// The AEAD nonce of the ticket: random, so it names the ticket for the record of used
    /// ones.
    pub(crate) id: [u8; TICKET_NONCE_LEN],
    pub(crate) suite: CipherSuiteId,
    pub(crate) issued_ms: u64,
    pub(crate) lifetime: u32,
    pub(crate) age_add: u32,
    pub(crate) secret: SecretVec,
    pub(crate) server_name: String,
    pub(crate) peer_certificates: Vec<Vec<u8>>,
    pub(crate) max_early_data: u32,
}

/// A server's tickets: the key they are sealed under, the clock they are dated by, and the
/// tickets already accepted.
pub(crate) struct TicketIssuer {
    pub(crate) count: u8,
    pub(crate) lifetime: Duration,
    key: SecretVec,
    /// The `now` the first ticket of this configuration was dated by: ticket times are
    /// milliseconds from it (the engine reads no clock, and an `Instant` has no value outside
    /// the process).
    origin: Mutex<Option<Instant>>,
    /// The tickets accepted, by id, with when each stops being valid (ms from `origin`).
    used: Mutex<HashMap<[u8; TICKET_NONCE_LEN], u64>>,
}

impl TicketIssuer {
    pub(crate) fn new(
        provider: &dyn RTCCryptoProvider,
        count: u8,
        lifetime: Duration,
    ) -> Result<Self> {
        let mut key = vec![0u8; TICKET_KEY_LEN];
        provider.random().fill(&mut key).map_err(crypto_error)?;
        Ok(Self {
            count,
            lifetime: lifetime.min(MAX_TICKET_LIFETIME),
            key: SecretVec::new(key),
            origin: Mutex::new(None),
            used: Mutex::new(HashMap::new()),
        })
    }

    /// `now` in milliseconds from the first time this issuer was given.
    pub(crate) fn ms(&self, now: Instant) -> u64 {
        let mut origin = self
            .origin
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let origin = *origin.get_or_insert(now);
        now.saturating_duration_since(origin).as_millis() as u64
    }

    /// Seals a ticket.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn seal(
        &self,
        provider: &dyn RTCCryptoProvider,
        suite: CipherSuiteId,
        now: Instant,
        age_add: u32,
        secret: &[u8],
        server_name: &str,
        peer_certificates: &[Vec<u8>],
        max_early_data: u32,
    ) -> Result<Vec<u8>> {
        let mut plaintext = vec![TICKET_VERSION];
        put_u16(&mut plaintext, suite as u16);
        plaintext.extend_from_slice(&self.ms(now).to_be_bytes());
        plaintext.extend_from_slice(&(self.lifetime.as_secs() as u32).to_be_bytes());
        plaintext.extend_from_slice(&age_add.to_be_bytes());
        put_vec8(&mut plaintext, |out| out.extend_from_slice(secret));
        put_vec16(&mut plaintext, |out| {
            out.extend_from_slice(server_name.as_bytes())
        });
        put_vec24(&mut plaintext, |list| {
            for der in peer_certificates {
                put_vec24(list, |out| out.extend_from_slice(der));
            }
        });
        plaintext.extend_from_slice(&max_early_data.to_be_bytes());
        let plaintext = SecretVec::new(plaintext);

        let mut nonce = [0u8; TICKET_NONCE_LEN];
        provider.random().fill(&mut nonce).map_err(crypto_error)?;
        let mut aead = provider
            .crypto()
            .new_aead(AeadAlgorithm::Aes256Gcm, self.key.as_ref())
            .map_err(crypto_error)?;
        let mut ticket = nonce.to_vec();
        ticket.extend_from_slice(plaintext.as_ref());
        let mut tag = [0u8; TICKET_TAG_LEN];
        aead.seal_in_place(
            &nonce,
            TICKET_AAD,
            &mut ticket[TICKET_NONCE_LEN..],
            &mut tag,
        )
        .map_err(crypto_error)?;
        ticket.extend_from_slice(&tag);
        Ok(ticket)
    }

    /// Opens a ticket of this issuer. `None` for anything else: another server's ticket, a
    /// forged or altered one, or one of an unknown version.
    pub(crate) fn open(
        &self,
        provider: &dyn RTCCryptoProvider,
        ticket: &[u8],
    ) -> Option<TicketContents> {
        if ticket.len() < TICKET_NONCE_LEN + TICKET_TAG_LEN + 1 {
            return None;
        }
        let (nonce, rest) = ticket.split_at(TICKET_NONCE_LEN);
        let (ciphertext, tag) = rest.split_at(rest.len() - TICKET_TAG_LEN);
        let mut aead = provider
            .crypto()
            .new_aead(AeadAlgorithm::Aes256Gcm, self.key.as_ref())
            .ok()?;
        let mut plaintext = SecretVec::new(ciphertext.to_vec());
        aead.open_in_place(nonce, TICKET_AAD, plaintext.as_mut(), tag)
            .ok()?;
        let mut reader = Reader::new(plaintext.as_ref());
        let parse = |reader: &mut Reader<'_>| -> Result<TicketContents> {
            if reader.u8()? != TICKET_VERSION {
                return Err(Error::ErrInvalidCipherSuite);
            }
            let suite = CipherSuiteId::from(reader.u16()?);
            let issued_ms = reader.u64()?;
            let lifetime = reader.u32()?;
            let age_add = reader.u32()?;
            let secret = SecretVec::new(reader.vec8()?.to_vec());
            let server_name = String::from_utf8(reader.vec16()?.to_vec())
                .map_err(|_| Error::ErrInvalidSniFormat)?;
            let mut chain_reader = Reader::new(reader.vec24()?);
            let mut peer_certificates = vec![];
            while !chain_reader.is_empty() {
                peer_certificates.push(chain_reader.vec24()?.to_vec());
            }
            let max_early_data = reader.u32()?;
            reader.finish()?;
            let mut id = [0u8; TICKET_NONCE_LEN];
            id.copy_from_slice(nonce);
            Ok(TicketContents {
                id,
                suite,
                issued_ms,
                lifetime,
                age_add,
                secret,
                server_name,
                peer_certificates,
                max_early_data,
            })
        };
        parse(&mut reader).ok()
    }

    /// Records that the ticket `id`, valid until `expires_ms`, has been accepted. `false` if
    /// it had been before, or if the record is full: a ticket is used once (RFC 8446 section
    /// 8.1, appendix C.4).
    pub(crate) fn claim(&self, id: [u8; TICKET_NONCE_LEN], now_ms: u64, expires_ms: u64) -> bool {
        let mut used = self
            .used
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if used.contains_key(&id) {
            return false;
        }
        if used.len() >= MAX_USED_TICKETS {
            used.retain(|_, expires| *expires > now_ms);
            if used.len() >= MAX_USED_TICKETS {
                return false;
            }
        }
        used.insert(id, expires_ms);
        true
    }

    /// Whether a chain is small enough to go in a ticket.
    pub(crate) fn carries(peer_certificates: &[Vec<u8>]) -> bool {
        peer_certificates.iter().map(Vec::len).sum::<usize>() <= MAX_TICKET_CHAIN
    }
}

/// A NewSessionTicket message (RFC 8446 section 4.6.1).
pub(crate) fn new_session_ticket(
    lifetime: u32,
    age_add: u32,
    nonce: &[u8],
    ticket: &[u8],
    max_early_data: Option<u32>,
) -> Vec<u8> {
    let mut body = vec![];
    body.extend_from_slice(&lifetime.to_be_bytes());
    body.extend_from_slice(&age_add.to_be_bytes());
    put_vec8(&mut body, |out| out.extend_from_slice(nonce));
    put_vec16(&mut body, |out| out.extend_from_slice(ticket));
    put_vec16(&mut body, |extensions| {
        if let Some(size) = max_early_data {
            put_extension(extensions, super::messages::EXT_EARLY_DATA, |data| {
                data.extend_from_slice(&size.to_be_bytes())
            });
        }
    });
    body
}

/// A NewSessionTicket as received.
pub(crate) struct NewSessionTicket<'a> {
    pub(crate) lifetime: u32,
    pub(crate) age_add: u32,
    pub(crate) nonce: &'a [u8],
    pub(crate) ticket: &'a [u8],
    pub(crate) max_early_data: Option<u32>,
}

/// Reads a NewSessionTicket (RFC 8446 section 4.6.1): a ticket of at least one byte, and of
/// the extensions only early_data, with its four-byte size, is understood; others are ignored.
pub(crate) fn parse_new_session_ticket(body: &[u8]) -> Result<NewSessionTicket<'_>> {
    let mut reader = Reader::new(body);
    let lifetime = reader.u32()?;
    let age_add = reader.u32()?;
    let nonce = reader.vec8()?;
    let ticket = reader.vec16()?;
    if ticket.is_empty() {
        return Err(Error::ErrLengthMismatch);
    }
    let extensions = read_extensions(reader.vec16()?)?;
    reader.finish()?;
    let max_early_data = match find_extension(&extensions, super::messages::EXT_EARLY_DATA) {
        Some(data) => {
            let mut reader = Reader::new(data);
            let size = reader.u32()?;
            reader.finish()?;
            Some(size)
        }
        None => None,
    };
    Ok(NewSessionTicket {
        lifetime,
        age_add,
        nonce,
        ticket,
        max_early_data,
    })
}
