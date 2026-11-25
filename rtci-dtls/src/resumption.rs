//! DTLS 1.2 session resumption: the abbreviated handshake of RFC 5246 section 7.3 (RFC 6347
//! section 4.2.4, figure 2), by session id or by an RFC 5077 ticket, with the rules RFC 7627
//! section 5.3 sets for the extended master secret and RFC 6066 section 3 for the server name.
//!
//! ```text
//!   Client                                           Server
//!   ClientHello (session id or ticket)  -------->
//!                                       <--------    HelloVerifyRequest
//!   ClientHello (with cookie)           -------->
//!                                                    ServerHello (same session id)
//!                                                    [NewSessionTicket]
//!                                                    [ChangeCipherSpec]
//!                                       <--------    Finished
//!   [ChangeCipherSpec]
//!   Finished                            -------->
//! ```
//!
//! The keys come from the session's master secret and the new randoms; no key exchange,
//! Certificate or CertificateVerify is sent. The server sends its Finished first, and the
//! client's flight is the last one, which it sends again when the server's comes again.

use crate::alert::{Alert, AlertDescription, AlertLevel};
use crate::cipher_suite::{CipherSuiteId, cipher_suite_for_id};
use crate::config::{ClientAuthType, ExtendedMasterSecretType, HandshakeConfig};
use crate::crypto::verify_server_cert;
use crate::extension::Extension;
use crate::flight::flight1::client_hello_cipher_suites;
use crate::handshake::handshake_cache::{HandshakeCache, HandshakeCachePullRule};
use crate::handshake::handshake_message_client_hello::HandshakeMessageClientHello;
use crate::handshake::handshake_message_new_session_ticket::HandshakeMessageNewSessionTicket;
use crate::handshake::{Handshake, HandshakeMessage, HandshakeType};
use crate::session::Dtls12Session;
use crate::state::State;
use shared::error::Error;
use std::io::BufWriter;

/// The SessionTicket extension (RFC 5077 section 3.2).
pub(crate) const EXTENSION_SESSION_TICKET: u16 = 35;

/// The length of the session ids this crate makes (RFC 5246 7.4.1.2: at most 32 bytes).
pub(crate) const SESSION_ID_LENGTH: usize = 32;

/// How many sessions a client looks at in its store before it gives up offering one.
const MAX_SESSIONS_TRIED: usize = 8;

pub(crate) type FlightError = (Option<Alert>, Option<Error>);

#[cfg(test)]
mod resumption_test;

pub(crate) fn fatal(description: AlertDescription, err: Error) -> FlightError {
    (
        Some(Alert {
            alert_level: AlertLevel::Fatal,
            alert_description: description,
        }),
        Some(err),
    )
}

/// A SessionTicket extension carrying `data`: a ticket, or nothing.
pub(crate) fn session_ticket_extension(data: &[u8]) -> Extension {
    Extension::Unknown {
        extension_type: EXTENSION_SESSION_TICKET,
        data: data.to_vec(),
    }
}

/// What a hello's SessionTicket extension carries, if it has one.
pub(crate) fn session_ticket_of(extensions: &[Extension]) -> Option<&[u8]> {
    extensions.iter().find_map(|extension| match extension {
        Extension::Unknown {
            extension_type: EXTENSION_SESSION_TICKET,
            data,
        } => Some(data.as_slice()),
        _ => None,
    })
}

fn random_session_id(cfg: &HandshakeConfig) -> Result<Vec<u8>, Error> {
    let mut id = vec![0u8; SESSION_ID_LENGTH];
    cfg.provider()
        .random()
        .fill(&mut id)
        .map_err(|error| Error::Crypto(error.to_string()))?;
    Ok(id)
}

/// Whether this side resumes DTLS 1.2 sessions at all: not switched off
/// (`ConfigBuilder::with_dtls12_resumption`), a certificate handshake (the PSK suites are not
/// resumed), with the extended master secret possible (RFC 7627 section 5.3: a client that
/// offers an abbreviated handshake sends the extension).
fn resumes(cfg: &HandshakeConfig) -> bool {
    cfg.dtls12_resumption
        && cfg.supports_dtls12()
        && cfg.local_psk_callback.is_none()
        && cfg.extended_master_secret != ExtendedMasterSecretType::Disable
}

/// Client, first ClientHello: the session it offers to resume, and whether it asks for a
/// ticket. A client with a session store asks for a ticket (an empty SessionTicket
/// extension, RFC 5077 section 3.2) and offers the most recent session for its server name
/// that is still valid, was made with the extended master secret (RFC 7627 section 5.3: the
/// client SHOULD NOT offer to resume one that was not) and whose cipher suite it offers (RFC
/// 5246 7.4.1.2). With a ticket the session id is new and random (RFC 5077 section 3.4), so
/// that the server's echo of it says the ticket was accepted.
pub(crate) fn client_offer(state: &mut State, cfg: &HandshakeConfig) -> Result<(), Error> {
    state.dtls12_offer = None;
    state.session_id = vec![];
    state.session_ticket_offer = None;
    state.resuming = None;
    state.new_session_ticket = false;
    state.received_ticket = None;
    let Some(store) = &cfg.session_store else {
        return Ok(());
    };
    if !resumes(cfg) {
        return Ok(());
    }
    state.session_ticket_offer = Some(vec![]);
    let Some(now) = state.clock else {
        return Ok(());
    };
    let suites = client_hello_cipher_suites(cfg);
    for _ in 0..MAX_SESSIONS_TRIED {
        let Some(session) = store.take_dtls12(&cfg.server_name) else {
            break;
        };
        let usable = session.is_valid_at(now)
            && session.extended_master_secret
            && suites.contains(&session.cipher_suite)
            && (session.ticket.is_some() || !session.session_id.is_empty());
        if !usable {
            continue;
        }
        if let Some(ticket) = &session.ticket {
            state.session_ticket_offer = Some(ticket.clone());
            state.session_id = random_session_id(cfg)?;
        } else {
            state.session_id.clone_from(&session.session_id);
        }
        state.dtls12_offer = Some(session);
        break;
    }
    Ok(())
}

/// Server, on the ClientHello it negotiates from (`negotiate_client_hello` has run): whether
/// it resumes a session, and if not, the session id and ticket this full handshake makes.
///
/// A ticket the client presents (RFC 5077 section 3.4) or a session id it offers (RFC 5246
/// 7.4.1.3) is resumed when this server sealed or keeps it, it is still valid, its cipher suite
/// is in both lists, it was made for the same server name (RFC 6066 section 3), it meets the
/// configured client authentication, the ticket has not been used before (each is accepted
/// once), and the extended master secret allows it (RFC 7627 section 5.3):
///
/// - the session used it and the ClientHello does not offer it: the handshake is aborted
///   (MUST);
/// - the session did not use it and the ClientHello offers it: a full handshake (MUST NOT
///   resume);
/// - neither: the handshake is aborted (SHOULD).
///
/// Otherwise the full handshake goes on as if nothing had been offered. Returns whether the
/// session is resumed; it then is `state.resuming`, the keys are made, and the ServerHello
/// echoes the ClientHello's session id.
pub(crate) fn server_resume(
    state: &mut State,
    client_hello: &HandshakeMessageClientHello,
    cfg: &HandshakeConfig,
) -> Result<bool, FlightError> {
    state.resuming = None;
    state.session_id = vec![];
    state.new_session_ticket = false;
    state.issued_ticket = None;
    if !resumes(cfg)
        || state
            .cipher_suite
            .as_ref()
            .is_some_and(|cipher_suite| cipher_suite.is_psk())
    {
        return Ok(false);
    }
    let client_ticket = session_ticket_of(&client_hello.extensions);
    let client_ems = client_hello
        .extensions
        .iter()
        .any(|extension| matches!(extension, Extension::UseExtendedMasterSecret(_)));
    let issuer = cfg.ticket_issuer.as_ref();
    let now = state.clock;

    let mut candidate = None;
    if let (Some(issuer), Some(ticket), Some(now)) = (issuer, client_ticket, now)
        && !ticket.is_empty()
        && let Some((id, expires_ms, session)) =
            issuer.open_dtls12(cfg.provider().as_ref(), ticket, now)
    {
        candidate = Some((session, Some((id, expires_ms))));
    }
    // RFC 5077 section 3.4: "If a ticket is presented by the client, the server MUST NOT
    // attempt to use the Session ID in the ClientHello for stateful session resumption."
    if candidate.is_none()
        && client_ticket.is_none_or(<[u8]>::is_empty)
        && !client_hello.session_id.is_empty()
        && let (Some(cache), Some(now)) = (&cfg.session_cache, now)
        && let Some(session) = cache.get(&client_hello.session_id)
        && session.is_valid_at(now)
    {
        candidate = Some((session, None));
    }

    if let Some((session, ticket_id)) = candidate
        && acceptable(&session, client_hello, state, cfg)
    {
        // RFC 7627 section 5.3.
        match (session.extended_master_secret, client_ems) {
            (true, false) => {
                return Err(fatal(
                    AlertDescription::HandshakeFailure,
                    Error::ErrServerRequiredButNoClientEms,
                ));
            }
            (false, false) => {
                return Err(fatal(
                    AlertDescription::HandshakeFailure,
                    Error::Other(
                        "a session without the extended master secret is not resumed".to_owned(),
                    ),
                ));
            }
            (false, true) => {}
            (true, true) => {
                // A ticket is accepted once.
                let claimed = match (ticket_id, issuer, now) {
                    (Some((id, expires_ms)), Some(issuer), Some(now)) => {
                        issuer.claim(id, issuer.ms(now), expires_ms)
                    }
                    (Some(_), _, _) => false,
                    (None, _, _) => true,
                };
                if claimed {
                    resume(state, client_hello, cfg, session)?;
                    // A ticket used is spent: the client gets a new one.
                    state.new_session_ticket = issuer.is_some() && client_ticket.is_some();
                    return Ok(true);
                }
            }
        }
    }

    // A full handshake. It makes a session only with the extended master secret (this crate
    // resumes no other): a ticket when the client asks for one, an id when there is a cache.
    // RFC 5077 section 3.4: a server that issues a ticket to a client that presented none
    // SHOULD give an empty session id; one that refused a ticket may give an id.
    if state.extended_master_secret {
        state.new_session_ticket = issuer.is_some() && client_ticket.is_some();
        let ticket_instead =
            state.new_session_ticket && client_ticket.is_some_and(<[u8]>::is_empty);
        if cfg.session_cache.is_some() && !ticket_instead {
            state.session_id = random_session_id(cfg)
                .map_err(|err| fatal(AlertDescription::InternalError, err))?;
        }
    }
    Ok(false)
}

/// Whether `session` may be resumed for this ClientHello, short of the extended master
/// secret rules: its suite offered and configured, the same server name, the configured client
/// authentication met.
fn acceptable(
    session: &Dtls12Session,
    client_hello: &HandshakeMessageClientHello,
    state: &State,
    cfg: &HandshakeConfig,
) -> bool {
    let suite = session.cipher_suite;
    let suite_ok = client_hello.cipher_suites.contains(&suite)
        && cfg.local_cipher_suites.contains(&suite)
        && cipher_suite_for_id(suite).is_ok_and(|cipher_suite| !cipher_suite.is_psk());
    let name_ok = session.server_name == state.server_name;
    // A configured peer-certificate check is run again on the session's certificates
    // (`resume`). A server that asks its clients for a certificate resumes no session
    // without one: the handshake is a full one, in which it asks again and the check runs on
    // what comes. A server that asks for none (`NoClientCert`) had no client certificate in
    // the full handshake either: there is nothing to check again, and the session resumes.
    let checkable = cfg.verify_peer_certificate.is_none()
        || cfg.client_auth == ClientAuthType::NoClientCert
        || !session.peer_certificates.is_empty();
    let authentication_ok = checkable
        && match cfg.client_auth {
            ClientAuthType::NoClientCert | ClientAuthType::RequestClientCert => true,
            ClientAuthType::RequireAnyClientCert => !session.peer_certificates.is_empty(),
            ClientAuthType::VerifyClientCertIfGiven => {
                session.peer_certificates.is_empty() || session.peer_certificates_verified
            }
            ClientAuthType::RequireAndVerifyClientCert => {
                !session.peer_certificates.is_empty() && session.peer_certificates_verified
            }
        };
    suite_ok && name_ok && authentication_ok
}

/// Server: takes `session` up for this handshake: its suite, master secret and the peer's
/// certificates, keys from the new randoms. The configured peer-certificate check runs again
/// on the client's certificates. A session without any reaches here only at a server that
/// asks its clients for none (`acceptable`): the full handshake had no client certificate
/// for the check either, and it is not called with an empty list.
fn resume(
    state: &mut State,
    client_hello: &HandshakeMessageClientHello,
    cfg: &HandshakeConfig,
    session: Dtls12Session,
) -> Result<(), FlightError> {
    let checked =
        !session.peer_certificates.is_empty() || cfg.client_auth != ClientAuthType::NoClientCert;
    if checked
        && let Some(verify_peer_certificate) = &cfg.verify_peer_certificate
        && let Err(err) = verify_peer_certificate(&session.peer_certificates, &[])
    {
        return Err(fatal(AlertDescription::BadCertificate, err));
    }
    let cipher_suite = cipher_suite_for_id(session.cipher_suite)
        .map_err(|err| fatal(AlertDescription::InternalError, err))?;
    state.cipher_suite = Some(cipher_suite);
    state.master_secret = session.master_secret.clone();
    state.extended_master_secret = true;
    state
        .peer_certificates
        .clone_from(&session.peer_certificates);
    state.peer_certificates_verified = session.peer_certificates_verified;
    state.session_id.clone_from(&client_hello.session_id);
    state.resumed = true;
    init_keys(state, cfg)?;
    state.resuming = Some(session);
    Ok(())
}

/// Makes the record keys from the master secret and the two randoms, once.
pub(crate) fn init_keys(state: &mut State, cfg: &HandshakeConfig) -> Result<(), FlightError> {
    let mut local_random = vec![];
    let mut remote_random = vec![];
    {
        let mut writer = BufWriter::<&mut Vec<u8>>::new(local_random.as_mut());
        state
            .local_random
            .marshal(&mut writer)
            .map_err(|err| fatal(AlertDescription::InternalError, Error::from(err)))?;
    }
    {
        let mut writer = BufWriter::<&mut Vec<u8>>::new(remote_random.as_mut());
        state
            .remote_random
            .marshal(&mut writer)
            .map_err(|err| fatal(AlertDescription::InternalError, Error::from(err)))?;
    }
    let (client_random, server_random) = if state.is_client {
        (local_random, remote_random)
    } else {
        (remote_random, local_random)
    };
    let is_client = state.is_client;
    let master_secret = state.master_secret.clone();
    if let Some(cipher_suite) = &mut state.cipher_suite
        && !cipher_suite.is_initialized()
    {
        cipher_suite
            .init(
                cfg.provider().clone(),
                master_secret.as_ref(),
                &client_random,
                &server_random,
                is_client,
            )
            .map_err(|err| fatal(AlertDescription::InternalError, err))?;
    }
    Ok(())
}

/// Client: the ServerHello echoes the session id this client offered, so the server resumes
/// it. The suite must be the session's (RFC 5246 7.4.1.3) and the extended master secret as
/// the session had it (RFC 7627 section 5.3: either difference aborts the handshake); the
/// certificates of the session are checked again as they were in its full handshake (the CA
/// chain unless that is switched off, and the configured peer-certificate check); then the
/// keys are made from the session's master secret.
pub(crate) fn client_resume(state: &mut State, cfg: &HandshakeConfig) -> Result<(), FlightError> {
    let Some(session) = state.dtls12_offer.clone() else {
        return Err(fatal(
            AlertDescription::InternalError,
            Error::Other("no session was offered".to_owned()),
        ));
    };
    let suite = state
        .cipher_suite
        .as_ref()
        .map(|cipher_suite| cipher_suite.id());
    if suite != Some(session.cipher_suite) {
        return Err(fatal(
            AlertDescription::IllegalParameter,
            Error::ErrInvalidCipherSuite,
        ));
    }
    if session.extended_master_secret != state.extended_master_secret {
        return Err(fatal(
            AlertDescription::HandshakeFailure,
            if session.extended_master_secret {
                Error::ErrClientRequiredButNoServerEms
            } else {
                Error::Other(
                    "the server resumed a session without the extended master secret with it"
                        .to_owned(),
                )
            },
        ));
    }
    if state.resuming.is_none() {
        let mut chains = vec![];
        if !cfg.insecure_skip_verify {
            let Some(cert_verifier) = cfg.server_cert_verifier.as_ref() else {
                return Err(fatal(
                    AlertDescription::BadCertificate,
                    Error::Crypto(
                        "CA-chain verification has no configured verifier adapter".to_owned(),
                    ),
                ));
            };
            chains =
                verify_server_cert(&session.peer_certificates, cert_verifier, &cfg.server_name)
                    .map_err(|err| fatal(AlertDescription::BadCertificate, err))?;
        }
        if let Some(verify_peer_certificate) = &cfg.verify_peer_certificate {
            // Fails closed: a session that carries no certificate is not checked as if it
            // had passed.
            if session.peer_certificates.is_empty() {
                return Err(fatal(
                    AlertDescription::BadCertificate,
                    Error::Other(
                        "a resumption carries no certificate for the configured check".to_owned(),
                    ),
                ));
            }
            verify_peer_certificate(&session.peer_certificates, &chains)
                .map_err(|err| fatal(AlertDescription::BadCertificate, err))?;
        }
        state.master_secret = session.master_secret.clone();
        state
            .peer_certificates
            .clone_from(&session.peer_certificates);
        state.resumed = true;
        state.resuming = Some(session);
    }
    init_keys(state, cfg)
}

/// A handshake message as it goes on the wire as message `sequence`: what a transcript holds
/// for a message of the flight being made, before it is sent.
pub(crate) fn marshal_handshake(
    message: HandshakeMessage,
    sequence: isize,
) -> Result<Vec<u8>, FlightError> {
    let mut handshake = Handshake::new(message);
    handshake.handshake_header.message_sequence = sequence as u16;
    let mut raw = vec![];
    {
        let mut writer = BufWriter::<&mut Vec<u8>>::new(raw.as_mut());
        handshake
            .marshal(&mut writer)
            .map_err(|err| fatal(AlertDescription::InternalError, err))?;
    }
    Ok(raw)
}

/// Server: the NewSessionTicket of this handshake (RFC 5077 section 3.3), sealing the session
/// it makes or resumes. Made once and kept, so that a flight made again carries the same.
pub(crate) fn new_session_ticket(
    state: &mut State,
    cfg: &HandshakeConfig,
) -> Result<HandshakeMessageNewSessionTicket, FlightError> {
    if let Some(ticket) = &state.pending_ticket {
        return Ok(ticket.clone());
    }
    // A ServerHello that announced a ticket is followed by one; an empty ticket says there
    // is none after all (RFC 5077 section 3.3): without an issuer or a clock, and from an
    // issuer whose keys were wiped (`SessionTicketIssuer::retire`).
    let none = HandshakeMessageNewSessionTicket {
        ticket_lifetime_hint: 0,
        ticket: vec![],
    };
    let (Some(issuer), Some(now)) = (cfg.ticket_issuer.as_ref(), state.clock) else {
        return Ok(none);
    };
    let session = session_of(state, cfg, now);
    let Some(ticket) = issuer
        .seal_dtls12(cfg.provider().as_ref(), now, &session)
        .map_err(|err| fatal(AlertDescription::InternalError, err))?
    else {
        return Ok(none);
    };
    // The ticket's id is its AEAD nonce, its first bytes.
    let mut id = [0u8; 12];
    id.copy_from_slice(&ticket[..12]);
    let expires_ms = issuer
        .ms(now)
        .saturating_add(issuer.lifetime.as_millis() as u64);
    state.issued_ticket = Some((id, expires_ms));
    let message = HandshakeMessageNewSessionTicket {
        ticket_lifetime_hint: issuer.lifetime.as_secs() as u32,
        ticket,
    };
    state.pending_ticket = Some(message.clone());
    Ok(message)
}

/// The session this handshake makes (or resumes), as a server keeps it or a client stores it.
pub(crate) fn session_of(
    state: &State,
    cfg: &HandshakeConfig,
    now: std::time::Instant,
) -> Dtls12Session {
    Dtls12Session {
        session_id: state.session_id.clone(),
        ticket: None,
        master_secret: state.master_secret.clone(),
        cipher_suite: state
            .cipher_suite
            .as_ref()
            .map_or(CipherSuiteId::Unsupported, |cipher_suite| cipher_suite.id()),
        extended_master_secret: state.extended_master_secret,
        peer_certificates: state.peer_certificates.clone(),
        peer_certificates_verified: state.peer_certificates_verified,
        server_name: if state.is_client {
            cfg.server_name.clone()
        } else {
            state.server_name.clone()
        },
        created: now,
        lifetime: cfg.session_lifetime,
    }
}

/// The transcript of an abbreviated handshake: the ClientHello, the ServerHello and the
/// NewSessionTicket, with the server's Finished when `with_server_finished` (what the client's
/// Finished covers).
pub(crate) fn abbreviated_transcript(
    cache: &HandshakeCache,
    cfg: &HandshakeConfig,
    with_server_finished: bool,
) -> Vec<u8> {
    let rule = |typ, epoch, is_client| HandshakeCachePullRule {
        typ,
        epoch,
        is_client,
        optional: false,
    };
    let mut rules = vec![
        rule(HandshakeType::ClientHello, cfg.initial_epoch, true),
        rule(HandshakeType::ServerHello, cfg.initial_epoch, false),
        rule(HandshakeType::NewSessionTicket, cfg.initial_epoch, false),
    ];
    if with_server_finished {
        rules.push(rule(HandshakeType::Finished, cfg.initial_epoch + 1, false));
    }
    cache.pull_and_merge(&rules)
}

/// What a DTLS 1.2 association does with its session once its handshake has completed: a
/// server keeps a new one in its cache; a client stores a new or renewed one, or puts back
/// the one it resumed by session id. Only sessions made with the extended master secret.
pub(crate) fn on_completed(state: &mut State, cfg: &HandshakeConfig) {
    let Some(now) = state.clock else {
        return;
    };
    if !resumes(cfg) || !state.extended_master_secret {
        return;
    }
    if state
        .cipher_suite
        .as_ref()
        .is_none_or(|cipher_suite| cipher_suite.is_psk())
    {
        return;
    }
    if !state.is_client {
        if !state.resumed
            && !state.session_id.is_empty()
            && let Some(cache) = &cfg.session_cache
        {
            cache.put(session_of(state, cfg, now));
        }
        return;
    }
    let Some(store) = &cfg.session_store else {
        return;
    };
    let session = match (state.received_ticket.take(), state.resuming.take()) {
        // A new ticket, for a new session or the one resumed. RFC 5077 section 3.4: with a
        // ticket the ServerHello's session id is discarded (the session is kept under a name of
        // this client's own). Section 3.3: kept no longer than the server's lifetime hint (0:
        // unspecified, the client's own lifetime).
        (Some((ticket, lifetime_hint)), resumed) => {
            let mut session = resumed.unwrap_or_else(|| session_of(state, cfg, now));
            session.ticket = Some(ticket);
            session.created = now;
            session.session_id = vec![];
            session.lifetime = cfg.session_lifetime;
            if lifetime_hint > 0 {
                session.lifetime = session
                    .lifetime
                    .min(std::time::Duration::from_secs(u64::from(lifetime_hint)));
            }
            session
        }
        // A session resumed by its id stays resumable.
        (None, Some(resumed)) if resumed.ticket.is_none() => resumed,
        (None, Some(_)) => return,
        (None, None) if !state.session_id.is_empty() => session_of(state, cfg, now),
        (None, None) => return,
    };
    // Kept under a name this association can forget it by, also when the server gave no id.
    let mut session = session;
    if session.session_id.is_empty() {
        match random_session_id(cfg) {
            Ok(id) => session.session_id = id,
            Err(_) => return,
        }
    }
    state.stored_session_id = Some(session.session_id.clone());
    store.put_dtls12(&cfg.server_name, session);
}

/// What a DTLS 1.2 association that failed does with its session (RFC 5246 7.2: "the session
/// identifier of a failed connection is invalidated"; 7.2.2: a connection ended by a fatal
/// alert is not resumed): a server forgets it in its cache and retires the ticket it issued;
/// a client forgets the one it stored.
pub(crate) fn on_failed(state: &mut State, cfg: &HandshakeConfig) {
    if state.is_client {
        if let (Some(store), Some(id)) = (&cfg.session_store, state.stored_session_id.take()) {
            store.forget_dtls12(&cfg.server_name, &id);
        }
        state.dtls12_offer = None;
        return;
    }
    if !state.session_id.is_empty()
        && let Some(cache) = &cfg.session_cache
    {
        cache.remove(&state.session_id);
    }
    if let (Some((id, expires_ms)), Some(issuer), Some(now)) = (
        state.issued_ticket.take(),
        cfg.ticket_issuer.as_ref(),
        state.clock,
    ) {
        issuer.claim(id, issuer.ms(now), expires_ms);
    }
}
