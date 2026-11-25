//! DTLS 1.3 pre-shared keys (RFC 8446 sections 2.2, 4.2.9 to 4.2.11 and 4.6.1): tickets
//! issued, kept and resumed with, external PSKs, and what each step of their authentication
//! refuses. The known answers are RFC 8448 section 4 (TLS 1.3, so with the `"tls13 "` label
//! prefix).

use super::codec::*;
use super::handshake_test::*;
use super::hello;
use super::key_schedule::{TLS13_LABEL_PREFIX, Transcript};
use super::key_schedule_test::hex;
use super::messages::{ClientHello, EXT_PRE_SHARED_KEY, EXT_PSK_KEY_EXCHANGE_MODES, alert};
use super::psk::*;
use super::suite::Suite13;
use crate::cipher_suite::{CipherSuiteHash, CipherSuiteId};
use crate::config::{DtlsVersion, HandshakeConfig};
use crate::endpoint::Endpoint;
use crate::session::{ExternalPsk, MAX_TICKET_LIFETIME, MemorySessionStore, SessionStore};
use shared::TransportProtocol;
use shared::error::{Error, Result};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

/// The server name a client of `client_builder` is configured with by default.
const NAME: &str = "localhost";

fn store() -> Arc<MemorySessionStore> {
    Arc::new(MemorySessionStore::new())
}

fn resuming_client(store: &Arc<MemorySessionStore>) -> Result<Arc<HandshakeConfig>> {
    Ok(Arc::new(
        client_builder()
            .with_session_store(Some(store.clone()))
            .build(true, None)?,
    ))
}

fn ticket_server(count: u8) -> Result<Arc<HandshakeConfig>> {
    Ok(Arc::new(
        server_builder()
            .with_session_tickets(count)
            .build(false, None)?,
    ))
}

/// A pair as [`Pair::with`] makes it, with its clock at `now`.
fn pair_at(
    client: Arc<HandshakeConfig>,
    server: Arc<HandshakeConfig>,
    now: Instant,
) -> Result<Pair> {
    let mut pair = Pair {
        client: Endpoint::new(client_addr(), TransportProtocol::UDP, None),
        server: Endpoint::new(server_addr(), TransportProtocol::UDP, Some(server)),
        now,
        client_complete: false,
        server_complete: false,
        client_error: None,
        server_error: None,
        to_client: vec![],
        to_server: vec![],
    };
    pair.client.connect(now, server_addr(), client, None)?;
    Ok(pair)
}

fn resumed(pair: &Pair) -> (bool, bool) {
    (
        pair.client
            .get_connection_state(server_addr())
            .is_some_and(|state| state.resumed()),
        pair.server
            .get_connection_state(client_addr())
            .is_some_and(|state| state.resumed()),
    )
}

fn exported(pair: &Pair) -> (Vec<u8>, Vec<u8>) {
    let export = |endpoint: &Endpoint, remote| {
        endpoint
            .get_connection_state(remote)
            .expect("an association")
            .export_keying_material("EXTRACTOR-dtls_srtp", &[], 32)
            .expect("an exporter")
            .as_ref()
            .to_vec()
    };
    (
        export(&pair.client, server_addr()),
        export(&pair.server, client_addr()),
    )
}

/// Empties `store` of the tickets for [`NAME`] and returns them, most recent first.
fn drain(store: &MemorySessionStore) -> Vec<crate::session::Tls13Session> {
    let mut sessions = vec![];
    while let Some(session) = store.take(NAME) {
        sessions.push(session);
    }
    sessions
}

/// RFC 8446 sections 2.2 and 4.6.1: the server's tickets are kept by the client and the next
/// handshake resumes with one: no Certificate or CertificateVerify, the certificates of the
/// first handshake reported, fresh keys, and new tickets in place of the one used.
#[test]
fn a_ticket_from_one_handshake_resumes_the_next_without_certificates() -> Result<()> {
    let store = store();
    let (client, server) = (resuming_client(&store)?, ticket_server(2)?);
    let mut first = Pair::with(client.clone(), server.clone())?.complete();
    assert_eq!(resumed(&first), (false, false));
    assert_eq!(store.len(NAME), 2, "two tickets sent, and kept");
    assert!(first.client_conn().peer_signature_scheme.is_some());
    let server_chain = first.client_conn().peer_certificates.clone();
    assert!(!server_chain.is_empty());
    let first_keys = exported(&first);

    // The default server runs the cookie exchange: the ticket goes in the ClientHello that
    // answers the HelloRetryRequest, with its binder computed again over the new transcript.
    let mut second = Pair::with(client, server)?.complete();
    assert_eq!(resumed(&second), (true, true));
    assert!(
        second.client_conn().peer_signature_scheme.is_none(),
        "no CertificateVerify was sent"
    );
    assert!(second.server_conn().resumed);
    assert_eq!(second.client_conn().peer_certificates, server_chain);
    assert_eq!(
        second
            .client
            .get_connection_state(server_addr())
            .map(|state| state.peer_certificates.clone()),
        Some(server_chain)
    );
    let second_keys = exported(&second);
    assert_eq!(second_keys.0, second_keys.1);
    assert_ne!(
        first_keys.0, second_keys.0,
        "a resumption has keys of its own"
    );
    assert_eq!(second.client_sends(b"resumed"), vec![b"resumed".to_vec()]);
    assert_eq!(second.server_sends(b"back"), vec![b"back".to_vec()]);
    assert_eq!(store.len(NAME), 3, "one ticket used, two new ones");
    // RFC 8446 section 4.6.1: the server name reported is the resumption ClientHello's.
    assert_eq!(second.server_conn().server_name, NAME);
    Ok(())
}

/// RFC 8446 section 4.6.1: each ticket has its own ticket_age_add, nonce, and so PSK, and the
/// server's tickets are opaque, random-looking bytes.
#[test]
fn each_ticket_has_its_own_age_add_and_psk() -> Result<()> {
    let store = store();
    let _ = Pair::with(resuming_client(&store)?, ticket_server(3)?)?.complete();
    let sessions = drain(&store);
    assert_eq!(sessions.len(), 3);
    for (index, session) in sessions.iter().enumerate() {
        for other in &sessions[index + 1..] {
            assert_ne!(session.age_add, other.age_add);
            assert_ne!(session.secret.as_ref(), other.secret.as_ref());
            assert_ne!(session.ticket, other.ticket);
        }
        assert!(
            !session
                .ticket
                .windows(NAME.len())
                .any(|window| window == NAME.as_bytes()),
            "the ticket is sealed: the server name is not in the clear"
        );
    }
    Ok(())
}

/// Without the cookie exchange the ticket is in the first ClientHello, and its binder covers
/// it alone.
#[test]
fn a_ticket_resumes_in_one_round_trip_without_the_cookie_exchange() -> Result<()> {
    let store = store();
    let client = resuming_client(&store)?;
    let server = Arc::new(
        server_builder()
            .with_session_tickets(1)
            .with_cookie_exchange(false)
            .build(false, None)?,
    );
    let _ = Pair::with(client.clone(), server.clone())?.complete();
    let second = Pair::with(client, server)?.complete();
    assert_eq!(resumed(&second), (true, true));
    Ok(())
}

/// RFC 8446 section 4.2.11: a binder that does not verify ends the handshake with
/// decrypt_error.
#[test]
fn a_binder_altered_by_one_bit_is_a_decrypt_error() -> Result<()> {
    let store = store();
    let client = resuming_client(&store)?;
    let server = Arc::new(
        server_builder()
            .with_session_tickets(1)
            .with_cookie_exchange(false)
            .build(false, None)?,
    );
    let _ = Pair::with(client.clone(), server.clone())?.complete();
    let mut pair = Pair::with(client, server)?;
    let mut hello = take(&mut pair.client);
    assert_eq!(hello.len(), 1);
    assert_eq!(record_first_bytes(&hello[0]).len(), 1, "one record");
    // The binders end the ClientHello, which ends the record.
    let last = hello[0].len() - 1;
    hello[0][last] ^= 1;
    pair.deliver_to_server(hello);
    let answer = take(&mut pair.server);
    assert_eq!(plaintext_alerts(&answer), [(2, alert::DECRYPT_ERROR)]);
    assert!(!pair.server_complete);
    pair.deliver_to_client(answer);
    assert!(pair.client.is_connection_failed(&server_addr()));
    Ok(())
}

/// A ticket another server made does not open: a full handshake.
#[test]
fn a_ticket_of_another_server_gets_a_full_handshake() -> Result<()> {
    let store = store();
    let client = resuming_client(&store)?;
    let _ = Pair::with(client.clone(), ticket_server(1)?)?.complete();
    assert_eq!(store.len(NAME), 1);
    let mut other = Pair::with(client, ticket_server(1)?)?.complete();
    assert_eq!(resumed(&other), (false, false));
    assert!(other.client_conn().peer_signature_scheme.is_some());
    assert!(
        other
            .client_conn()
            .offered_extensions
            .contains(&EXT_PRE_SHARED_KEY),
        "the ticket was offered"
    );
    Ok(())
}

/// A ticket whose bytes were altered does not open either.
#[test]
fn a_forged_ticket_gets_a_full_handshake() -> Result<()> {
    let store = store();
    let (client, server) = (resuming_client(&store)?, ticket_server(1)?);
    let _ = Pair::with(client.clone(), server.clone())?.complete();
    let mut session = store.take(NAME).expect("a ticket");
    session.ticket[20] ^= 0x80;
    store.put(NAME, session);
    let pair = Pair::with(client, server)?.complete();
    assert_eq!(resumed(&pair), (false, false));
    Ok(())
}

/// RFC 8446 section 4.6.1: the server takes no ticket past its lifetime, whatever the client
/// believes, and the client offers none past the lifetime it was given.
#[test]
fn a_ticket_past_its_lifetime_is_not_used() -> Result<()> {
    let store = store();
    let client = resuming_client(&store)?;
    let server = Arc::new(
        server_builder()
            .with_session_tickets(2)
            .with_session_ticket_lifetime(Duration::from_secs(10))
            .build(false, None)?,
    );
    let start = Instant::now();
    let _ = pair_at(client.clone(), server.clone(), start)?.complete();
    let later = start + Duration::from_secs(11);

    // The server's view: a client that kept the ticket for longer than it was told to.
    let mut session = store.take(NAME).expect("a ticket");
    assert_eq!(session.lifetime, Duration::from_secs(10));
    session.lifetime = Duration::from_secs(3600);
    store.put(NAME, session);
    let mut pair = pair_at(client.clone(), server.clone(), later)?.complete();
    assert_eq!(resumed(&pair), (false, false));
    assert!(
        pair.client_conn()
            .offered_extensions
            .contains(&EXT_PRE_SHARED_KEY)
    );

    // The client's view: the tickets of that handshake are over; it offers none of them, and
    // drops them.
    drain(&store);
    let _ = pair_at(client.clone(), server.clone(), later)?.complete();
    assert_eq!(store.len(NAME), 2);
    let mut pair = pair_at(client, server, later + Duration::from_secs(11))?.complete();
    assert_eq!(resumed(&pair), (false, false));
    assert!(
        !pair
            .client_conn()
            .offered_extensions
            .contains(&EXT_PRE_SHARED_KEY),
        "nothing offered"
    );
    assert_eq!(store.len(NAME), 2, "the two expired dropped, two new");
    Ok(())
}

/// RFC 8446 section 4.6.1: a lifetime of zero says not to keep the ticket; none is longer
/// than seven days.
#[test]
fn a_ticket_lifetime_of_zero_is_not_kept_and_none_is_over_seven_days() -> Result<()> {
    let store = store();
    let client = resuming_client(&store)?;
    let server = Arc::new(
        server_builder()
            .with_session_tickets(1)
            .with_session_ticket_lifetime(Duration::ZERO)
            .build(false, None)?,
    );
    let _ = Pair::with(client.clone(), server)?.complete();
    assert_eq!(store.len(NAME), 0);

    let server = Arc::new(
        server_builder()
            .with_session_tickets(1)
            .with_session_ticket_lifetime(Duration::from_secs(30 * 24 * 3600))
            .build(false, None)?,
    );
    let _ = Pair::with(client, server)?.complete();
    let session = store.take(NAME).expect("a ticket");
    assert_eq!(session.lifetime, MAX_TICKET_LIFETIME);
    Ok(())
}

/// RFC 8446 section 8.1 and appendix C.4: a ticket is accepted once; offered again it gets a
/// full handshake. The client takes each ticket from its store, so it offers each once.
#[test]
fn a_ticket_is_accepted_once() -> Result<()> {
    let store = store();
    let (client, server) = (resuming_client(&store)?, ticket_server(1)?);
    let _ = Pair::with(client.clone(), server.clone())?.complete();
    let ticket = drain(&store).remove(0);

    store.put(NAME, ticket.clone());
    let pair = Pair::with(client.clone(), server.clone())?.complete();
    assert_eq!(resumed(&pair), (true, true));
    assert_eq!(
        store.len(NAME),
        1,
        "the ticket used is gone, a new one came"
    );

    drain(&store);
    store.put(NAME, ticket);
    let pair = Pair::with(client, server)?.complete();
    assert_eq!(resumed(&pair), (false, false), "a replayed ticket");
    Ok(())
}

/// RFC 8446 section 4.2.9: psk_ke, the PSK without (EC)DHE, is used only where both sides
/// allow it. A client that offers it alone gets a full handshake from a default server, and
/// no tickets.
#[test]
fn psk_ke_is_refused_unless_the_server_allows_it() -> Result<()> {
    let store = store();
    let server = ticket_server(1)?;
    let _ = Pair::with(resuming_client(&store)?, server.clone())?.complete();
    assert_eq!(store.len(NAME), 1);

    let mut psk_ke_only = client_builder()
        .with_session_store(Some(store.clone()))
        .with_psk_without_key_exchange(true)
        .build(true, None)?;
    psk_ke_only.psk_modes_for_test = Some(vec![PSK_KE]);
    let pair = Pair::with(Arc::new(psk_ke_only), server)?.complete();
    assert_eq!(resumed(&pair), (false, false));
    assert_eq!(
        store.len(NAME),
        0,
        "the ticket offered is gone and none came"
    );
    Ok(())
}

/// psk_ke where both sides allow it: no key_share in the ServerHello, the PSK alone keys the
/// handshake.
#[test]
fn psk_ke_resumes_where_both_sides_allow_it() -> Result<()> {
    let store = store();
    let server = Arc::new(
        server_builder()
            .with_session_tickets(1)
            .with_psk_without_key_exchange(true)
            .build(false, None)?,
    );
    let _ = Pair::with(resuming_client(&store)?, server.clone())?.complete();
    let mut psk_ke_only = client_builder()
        .with_session_store(Some(store.clone()))
        .with_psk_without_key_exchange(true)
        .build(true, None)?;
    psk_ke_only.psk_modes_for_test = Some(vec![PSK_KE]);
    let mut pair = Pair::with(Arc::new(psk_ke_only), server.clone())?.complete();
    assert_eq!(resumed(&pair), (true, true));
    assert!(pair.client_conn().psk_without_key_exchange);
    assert!(pair.server_conn().psk_without_key_exchange);
    assert_eq!(pair.client_sends(b"psk_ke"), vec![b"psk_ke".to_vec()]);

    // A client that offers both modes gets psk_dhe_ke, which keeps forward secrecy.
    let both = Arc::new(
        client_builder()
            .with_session_store(Some(store.clone()))
            .with_psk_without_key_exchange(true)
            .build(true, None)?,
    );
    let mut pair = Pair::with(both, server)?.complete();
    assert_eq!(resumed(&pair), (true, true));
    assert!(!pair.server_conn().psk_without_key_exchange);
    Ok(())
}

/// A server that negotiates DTLS 1.2 ignores psk_key_exchange_modes and pre_shared_key.
#[test]
fn a_dtls_1_2_server_ignores_the_psk_offer() -> Result<()> {
    let store = store();
    let client = resuming_client(&store)?;
    let _ = Pair::with(client.clone(), ticket_server(1)?)?.complete();
    assert_eq!(store.len(NAME), 1);
    let pair = Pair::new(
        client_builder().with_session_store(Some(store.clone())),
        server_builder().with_protocol_versions(DtlsVersion::Dtls1_2, DtlsVersion::Dtls1_2),
    )?
    .complete();
    assert_eq!(
        pair.versions(),
        (Some(DtlsVersion::Dtls1_2), Some(DtlsVersion::Dtls1_2))
    );
    assert_eq!(resumed(&pair), (false, false));
    Ok(())
}

/// The peer-certificate check of the configuration runs again on the certificates a ticket
/// carries: an application that no longer accepts that peer does not get it back by
/// resumption.
#[test]
fn the_peer_certificate_check_runs_again_on_resumption() -> Result<()> {
    let store = store();
    let refuse = Arc::new(AtomicBool::new(false));
    let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let (refuse_in, calls_in) = (refuse.clone(), calls.clone());
    let client = Arc::new(
        client_builder()
            .with_session_store(Some(store.clone()))
            .with_verify_peer_certificate(Some(Arc::new(move |chain: &[Vec<u8>], _| {
                calls_in.fetch_add(1, Ordering::SeqCst);
                assert!(!chain.is_empty());
                if refuse_in.load(Ordering::SeqCst) {
                    Err(Error::Other("no longer trusted".to_owned()))
                } else {
                    Ok(())
                }
            })))
            .build(true, None)?,
    );
    let server = ticket_server(2)?;
    let _ = Pair::with(client.clone(), server.clone())?.complete();
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    let pair = Pair::with(client.clone(), server.clone())?.complete();
    assert_eq!(resumed(&pair), (true, true));
    assert_eq!(calls.load(Ordering::SeqCst), 2);

    refuse.store(true, Ordering::SeqCst);
    let mut pair = Pair::with(client, server)?;
    pair.run();
    assert!(!pair.client_complete);
    assert!(matches!(pair.client_error, Some(Error::Other(_))));
    assert!(pair.client.is_connection_failed(&server_addr()));
    Ok(())
}

/// RFC 8446 section 4.2.11: the selected_identity is one the client offered; any other is an
/// illegal_parameter.
#[test]
fn a_selected_identity_out_of_range_is_an_illegal_parameter() -> Result<()> {
    let store = store();
    let client = resuming_client(&store)?;
    let server = Arc::new(
        server_builder()
            .with_session_tickets(1)
            .with_cookie_exchange(false)
            .build(false, None)?,
    );
    let _ = Pair::with(client.clone(), server.clone())?.complete();
    let mut pair = Pair::with(client, server)?;
    let hello = take(&mut pair.client);
    pair.deliver_to_server(hello);
    let mut flight = take(&mut pair.server);
    // The ServerHello is in the clear: its pre_shared_key extension, selected_identity 0.
    let extension = [0x00, 0x29, 0x00, 0x02, 0x00, 0x00];
    let datagram = &mut flight[0];
    let at = datagram
        .windows(extension.len())
        .position(|window| window == extension)
        .expect("the ServerHello selects the PSK");
    datagram[at + 5] = 1;
    pair.deliver_to_client(flight);
    assert!(!pair.client_complete);
    assert!(pair.client.is_connection_failed(&server_addr()));
    // The protected records after the ServerHello draw the alert again (RFC 9147 section
    // 5.10), a bounded number of times.
    let alerts = plaintext_alerts(&take(&mut pair.client));
    assert!(!alerts.is_empty());
    assert!(
        alerts
            .iter()
            .all(|sent| *sent == (2, alert::ILLEGAL_PARAMETER)),
        "{alerts:?}"
    );
    Ok(())
}

/// External PSKs (RFC 8446 section 2.2): the same identity and secret on both sides is a
/// handshake without certificates.
#[test]
fn an_external_psk_authenticates_without_certificates() -> Result<()> {
    let psk = ExternalPsk::new(b"device-7".to_vec(), vec![0x42; 32]);
    let mut pair = Pair::new(
        client_builder().with_external_psks(vec![psk.clone()]),
        server_builder().with_external_psks(vec![psk]),
    )?
    .complete();
    assert_eq!(resumed(&pair), (true, true));
    assert!(pair.client_conn().peer_signature_scheme.is_none());
    assert!(pair.client_conn().peer_certificates.is_empty());
    assert_eq!(pair.client_sends(b"external"), vec![b"external".to_vec()]);
    let keys = exported(&pair);
    assert_eq!(keys.0, keys.1);
    Ok(())
}

/// The external binder uses "ext binder" (RFC 8446 section 7.1): a client with the same
/// identity and another secret ends the handshake with decrypt_error; an identity the server
/// does not have gets a full handshake.
#[test]
fn an_external_psk_with_another_secret_is_a_decrypt_error() -> Result<()> {
    let server = server_builder()
        .with_cookie_exchange(false)
        .with_external_psks(vec![ExternalPsk::new(b"device-7".to_vec(), vec![0x42; 32])]);
    let mut pair = Pair::new(
        client_builder()
            .with_external_psks(vec![ExternalPsk::new(b"device-7".to_vec(), vec![0x43; 32])]),
        server.clone(),
    )?;
    let hello = take(&mut pair.client);
    pair.deliver_to_server(hello);
    assert_eq!(
        plaintext_alerts(&take(&mut pair.server)),
        [(2, alert::DECRYPT_ERROR)]
    );

    let pair = Pair::new(
        client_builder()
            .with_external_psks(vec![ExternalPsk::new(b"device-8".to_vec(), vec![0x42; 32])]),
        server,
    )?
    .complete();
    assert_eq!(resumed(&pair), (false, false));
    Ok(())
}

/// A PSK is bound to one hash (RFC 8446 section 4.2.11): a SHA-384 PSK keys a handshake of
/// the SHA-384 suite, and is not used with a SHA-256 one. Offered, it makes the server take
/// the client's SHA-384 suite over its first (section 4.2.11: external PSKs influence the
/// suite).
#[test]
fn an_external_psk_is_used_only_with_a_suite_of_its_hash() -> Result<()> {
    let psk =
        ExternalPsk::new(b"sha384".to_vec(), vec![0x24; 48]).with_hash(CipherSuiteHash::Sha384);
    // By default the client lists TLS_AES_128_GCM_SHA256 first and TLS_AES_256_GCM_SHA384
    // last; the PSK makes the server take the latter.
    let mut pair = Pair::new(
        client_builder().with_external_psks(vec![psk.clone()]),
        server_builder().with_external_psks(vec![psk.clone()]),
    )?
    .complete();
    assert_eq!(resumed(&pair), (true, true));
    assert_eq!(
        pair.server_conn().suite.map(|suite| suite.id),
        Some(CipherSuiteId::Tls_Aes_256_Gcm_Sha384)
    );

    // Without a suite of its hash on the client the PSK is not offered; without one on the
    // server it is not taken.
    let sha256_only = vec![
        CipherSuiteId::Tls_Aes_128_Gcm_Sha256,
        CipherSuiteId::Tls_ChaCha20_Poly1305_Sha256,
    ];
    let mut pair = Pair::new(
        client_builder()
            .with_cipher_suites(sha256_only.clone())
            .with_external_psks(vec![psk.clone()]),
        server_builder().with_external_psks(vec![psk.clone()]),
    )?
    .complete();
    assert_eq!(resumed(&pair), (false, false));
    assert!(
        !pair
            .client_conn()
            .offered_extensions
            .contains(&EXT_PRE_SHARED_KEY)
    );
    let pair = Pair::new(
        client_builder().with_external_psks(vec![psk.clone()]),
        server_builder()
            .with_cipher_suites(sha256_only)
            .with_external_psks(vec![psk]),
    )?
    .complete();
    assert_eq!(resumed(&pair), (false, false));
    Ok(())
}

/// The ClientHello `first`, written again with `extensions` in place of its own.
fn with_extensions(first: &ClientHello<'_>, extensions: &[(u16, &[u8])]) -> Vec<u8> {
    let mut body = vec![];
    put_u16(&mut body, first.legacy_version);
    body.extend_from_slice(first.random);
    put_vec8(&mut body, |out| {
        out.extend_from_slice(first.legacy_session_id)
    });
    put_vec8(&mut body, |out| out.extend_from_slice(first.legacy_cookie));
    put_vec16(&mut body, |out| {
        for suite in &first.cipher_suites {
            put_u16(out, *suite);
        }
    });
    put_vec8(&mut body, |out| {
        out.extend_from_slice(first.legacy_compression_methods)
    });
    put_vec16(&mut body, |out| {
        for (extension_type, data) in extensions {
            put_extension(out, *extension_type, |out| out.extend_from_slice(data));
        }
    });
    body
}

fn refusal_of(cfg: &HandshakeConfig, body: &[u8]) -> Option<u8> {
    let hello = ClientHello::parse(body).expect("a ClientHello");
    hello::negotiate(cfg, &hello)
        .err()
        .map(|refusal| refusal.alert)
}

/// RFC 8446 sections 4.2.9 and 4.2.11: pre_shared_key is the last extension (otherwise
/// illegal_parameter), and comes with psk_key_exchange_modes (otherwise the handshake is
/// aborted: missing_extension).
#[test]
fn a_pre_shared_key_that_is_not_last_or_comes_without_modes_is_refused() -> Result<()> {
    let psk = ExternalPsk::new(b"device-7".to_vec(), vec![0x42; 32]);
    let mut pair = Pair::new(
        client_builder().with_external_psks(vec![psk.clone()]),
        server_builder(),
    )?;
    let datagram = take(&mut pair.client).remove(0);
    let (body, _, _) = hello::whole_client_hello(&datagram).expect("one ClientHello");
    let first = ClientHello::parse(body)?;
    let server = server_builder()
        .with_external_psks(vec![psk])
        .build(false, None)?;
    assert_eq!(
        first
            .extensions
            .last()
            .map(|(extension_type, _)| *extension_type),
        Some(EXT_PRE_SHARED_KEY),
        "this client puts it last"
    );
    assert!(refusal_of(&server, body).is_none());

    let mut reordered = first.extensions.clone();
    let last = reordered.pop().expect("an extension");
    reordered.insert(0, last);
    assert_eq!(
        refusal_of(&server, &with_extensions(&first, &reordered)),
        Some(alert::ILLEGAL_PARAMETER)
    );

    let without_modes: Vec<(u16, &[u8])> = first
        .extensions
        .iter()
        .copied()
        .filter(|(extension_type, _)| *extension_type != EXT_PSK_KEY_EXCHANGE_MODES)
        .collect();
    assert_eq!(
        refusal_of(&server, &with_extensions(&first, &without_modes)),
        Some(alert::MISSING_EXTENSION)
    );
    Ok(())
}

/// RFC 8446 section 4.1.4: after a HelloRetryRequest for a suite of another hash, the
/// ClientHello offers no PSK of the old one, and the handshake is a full one.
#[test]
fn a_psk_of_another_hash_is_dropped_after_a_hello_retry_request() -> Result<()> {
    let store = store();
    let client = resuming_client(&store)?;
    let _ = Pair::with(client.clone(), ticket_server(1)?)?.complete();
    let sha384_server = Arc::new(
        server_builder()
            .with_cipher_suites(vec![CipherSuiteId::Tls_Aes_256_Gcm_Sha384])
            .with_session_tickets(1)
            .build(false, None)?,
    );
    let mut pair = Pair::with(client, sha384_server)?.complete();
    assert_eq!(resumed(&pair), (false, false));
    assert!(pair.client_conn().hello_retry_seen);
    assert!(
        !pair
            .client_conn()
            .offered_extensions
            .contains(&EXT_PRE_SHARED_KEY),
        "the second ClientHello offers no PSK"
    );
    Ok(())
}

/// A ticket carries the client certificate of the handshake it came from: a server that
/// requires one resumes without asking for it again (RFC 8446 section 4.3.2: no
/// CertificateRequest with a PSK) and reports the same chain.
#[test]
fn a_ticket_carries_the_client_certificate_and_the_server_asks_for_none() -> Result<()> {
    let provider = provider();
    let store = store();
    let client = Arc::new(
        client_builder()
            .with_certificates(vec![crate::crypto::Certificate::generate_self_signed(
                vec!["client".to_owned()],
                provider.crypto(),
            )?])
            .with_session_store(Some(store.clone()))
            .build(true, None)?,
    );
    let server = Arc::new(
        server_builder()
            .with_client_auth(crate::config::ClientAuthType::RequireAnyClientCert)
            .with_session_tickets(1)
            .build(false, None)?,
    );
    let mut first = Pair::with(client.clone(), server.clone())?.complete();
    let client_chain = first.server_conn().peer_certificates.clone();
    assert!(!client_chain.is_empty());
    let mut second = Pair::with(client, server)?.complete();
    assert_eq!(resumed(&second), (true, true));
    assert!(!second.server_conn().client_certificate_expected);
    assert!(second.client_conn().certificate_requested.is_none());
    assert_eq!(second.server_conn().peer_certificates, client_chain);
    Ok(())
}

/// RFC 8446 sections 4.2.11 and 4.6.1: tickets are kept by the server name they came from,
/// and offered only to it.
#[test]
fn a_ticket_is_offered_only_to_the_server_name_it_came_from() -> Result<()> {
    let store = store();
    let server = ticket_server(1)?;
    let _ = Pair::with(resuming_client(&store)?, server.clone())?.complete();
    assert_eq!(store.len(NAME), 1);
    let other_name = Arc::new(
        client_builder()
            .with_server_name("other.example".to_owned())
            .with_session_store(Some(store.clone()))
            .build(true, None)?,
    );
    let mut pair = Pair::with(other_name, server)?.complete();
    assert_eq!(resumed(&pair), (false, false));
    assert!(
        !pair
            .client_conn()
            .offered_extensions
            .contains(&EXT_PRE_SHARED_KEY)
    );
    assert_eq!(
        store.len(NAME),
        1,
        "the ticket for localhost is still there"
    );
    assert_eq!(store.len("other.example"), 1);
    Ok(())
}

/// RFC 8448 section 4: the binder of the resumed ClientHello, from the resumption secret of
/// section 3 (`"tls13 "` labels).
#[test]
fn the_binder_of_rfc_8448_is_reproduced() -> Result<()> {
    let provider = provider();
    let message = hex(RFC8448_RESUMED_CLIENT_HELLO);
    let body = &message[4..];
    let psk = hex("4ecd0eb6ec3b4d87f5d6028f922ca4c5851a277fd41311c9e62d2c9492e1c4f3");
    let suite = Suite13 {
        id: CipherSuiteId::Tls_Aes_128_Gcm_Sha256,
    };
    let binder = binder_with_label_prefix(
        provider.crypto(),
        suite,
        &psk,
        false,
        &Transcript::default(),
        body,
        35,
        TLS13_LABEL_PREFIX,
    )?;
    assert_eq!(
        binder,
        hex("3add4fb2d8fdf822a0ca3cf7678ef5e88dae990141c5924d57bb6fa31b9e5f9d")
    );
    assert_eq!(&body[body.len() - 32..], binder.as_slice());

    // The pre_shared_key extension of that ClientHello, as a server reads it.
    let at = body
        .windows(4)
        .position(|window| window == [0x00, 0x29, 0x00, 0xdd])
        .expect("pre_shared_key");
    let offered = parse_client_pre_shared_key(&body[at + 4..])?;
    assert_eq!(offered.identities.len(), 1);
    assert_eq!(offered.identities[0].0.len(), 0xb2);
    assert_eq!(offered.identities[0].1, 0xfad6_aacb);
    assert_eq!(offered.binders, [binder.as_slice()]);
    assert_eq!(offered.binders_len, 35);
    Ok(())
}

/// RFC 8448 section 3: the NewSessionTicket, read and written.
#[test]
fn the_new_session_ticket_of_rfc_8448_is_read_and_written() -> Result<()> {
    let message = hex(RFC8448_NEW_SESSION_TICKET);
    let body = &message[4..];
    let ticket = parse_new_session_ticket(body)?;
    assert_eq!(ticket.lifetime, 30);
    assert_eq!(ticket.age_add, 0xfad6_aac5);
    assert_eq!(ticket.nonce, [0, 0]);
    assert_eq!(ticket.ticket.len(), 0xb2);
    assert_eq!(ticket.max_early_data, Some(1024));
    assert_eq!(
        new_session_ticket(30, 0xfad6_aac5, &[0, 0], ticket.ticket, Some(1024)),
        body
    );
    // RFC 8446 section 4.6.1: a ticket has at least one byte, and an extension the client
    // does not know is ignored.
    let empty = new_session_ticket(30, 1, &[0], &[], None);
    assert!(parse_new_session_ticket(&empty).is_err());
    let mut unknown = new_session_ticket(30, 1, &[0], &[9], None);
    unknown.truncate(unknown.len() - 2);
    unknown.extend_from_slice(&[0, 6, 0xfe, 0xfe, 0, 2, 1, 2]);
    let parsed = parse_new_session_ticket(&unknown)?;
    assert_eq!((parsed.ticket, parsed.max_early_data), (&[9][..], None));
    Ok(())
}

/// The parsers of the ClientHello's PSK extensions refuse what RFC 8446 section 4.2.11 does
/// not allow: no identity, an empty identity, binders that do not match the identities in
/// number, a binder shorter than 32 bytes.
#[test]
fn malformed_pre_shared_key_extensions_are_refused() {
    let identity = |identity: &[u8]| {
        let mut out = vec![];
        out.extend_from_slice(&(identity.len() as u16).to_be_bytes());
        out.extend_from_slice(identity);
        out.extend_from_slice(&[0, 0, 0, 0]);
        out
    };
    let extension = |identities: &[Vec<u8>], binders: &[Vec<u8>]| {
        let identities: Vec<u8> = identities.concat();
        let mut out = (identities.len() as u16).to_be_bytes().to_vec();
        out.extend_from_slice(&identities);
        let binders: Vec<u8> = binders
            .iter()
            .flat_map(|binder| {
                let mut item = vec![binder.len() as u8];
                item.extend_from_slice(binder);
                item
            })
            .collect();
        out.extend_from_slice(&(binders.len() as u16).to_be_bytes());
        out.extend_from_slice(&binders);
        out
    };
    let good = extension(&[identity(b"id")], &[vec![1; 32]]);
    assert!(parse_client_pre_shared_key(&good).is_ok());
    for bad in [
        extension(&[], &[]),
        extension(&[identity(b"")], &[vec![1; 32]]),
        extension(&[identity(b"id")], &[]),
        extension(&[identity(b"id")], &[vec![1; 32], vec![1; 32]]),
        extension(&[identity(b"id")], &[vec![1; 31]]),
    ] {
        assert!(parse_client_pre_shared_key(&bad).is_err());
    }
    assert!(parse_psk_key_exchange_modes(&[0]).is_err(), "no mode");
    assert_eq!(
        parse_psk_key_exchange_modes(&[1, PSK_DHE_KE]).ok(),
        Some(&[PSK_DHE_KE][..])
    );
}

/// A server issues tickets only to a client that sent psk_key_exchange_modes (RFC 8446
/// section 4.2.9), and a client without a store sends none: by default nothing is sent.
#[test]
fn without_a_session_store_no_ticket_is_asked_for_or_sent() -> Result<()> {
    let mut pair = Pair::with(
        Arc::new(client_builder().build(true, None)?),
        ticket_server(2)?,
    )?;
    pair.run();
    assert!(pair.client_complete && pair.server_complete);
    assert!(
        !pair
            .client_conn()
            .offered_extensions
            .contains(&EXT_PSK_KEY_EXCHANGE_MODES)
    );
    assert_eq!(pair.server_conn().tickets_issued, 0);

    // With a store the same server sends its two.
    let store = store();
    let mut pair = Pair::with(resuming_client(&store)?, ticket_server(2)?)?.complete();
    assert_eq!(pair.server_conn().tickets_issued, 2);
    Ok(())
}

/// RFC 8448 section 4, "send handshake record" of the resumed ClientHello: 512 octets, the
/// handshake header first.
const RFC8448_RESUMED_CLIENT_HELLO: &str = "010001fc03031bc3ceb6bbe39cff938355b5a50adb6db21b7a6af649d7b4bc419d7876487d95000006130113031302010001cd0000000b0009000006736572766572ff01000100000a00140012001d00170018001901000101010201030104003300260024001d0020e4ffb68ac05f8d96c99da26698346c6be16482badddafe051a66b4f18d668f0b002a0000002b0003020304000d0020001e040305030603020308040805080604010501060102010402050206020202002d00020101001c0002400100150057000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002900dd00b800b22c035d829359ee5ff7af4ec900000000262a6494dc486d2c8a34cb33fa90bf1b0070ad3c498883c9367c09a2be785abc55cd226097a3a982117283f82a03a143efd3ff5dd36d64e861be7fd61d2827db279cce145077d454a3664d4e6da4d29ee03725a6a4dafcd0fc67d2aea70529513e3da2677fa5906c5b3f7d8f92f228bda40dda721470f9fbf297b5aea617646fac5c03272e970727c621a79141ef5f7de6505e5bfbc388e93343694093934ae4d357fad6aacb0021203add4fb2d8fdf822a0ca3cf7678ef5e88dae990141c5924d57bb6fa31b9e5f9d";

/// RFC 8448 section 3, "construct a NewSessionTicket handshake message": 205 octets.
const RFC8448_NEW_SESSION_TICKET: &str = "040000c90000001efad6aac502000000b22c035d829359ee5ff7af4ec900000000262a6494dc486d2c8a34cb33fa90bf1b0070ad3c498883c9367c09a2be785abc55cd226097a3a982117283f82a03a143efd3ff5dd36d64e861be7fd61d2827db279cce145077d454a3664d4e6da4d29ee03725a6a4dafcd0fc67d2aea70529513e3da2677fa5906c5b3f7d8f92f228bda40dda721470f9fbf297b5aea617646fac5c03272e970727c621a79141ef5f7de6505e5bfbc388e93343694093934ae4d3570008002a000400000400";

/// A store that keeps tickets without the certificates of the handshake they came from:
/// what a resumption with nothing to check looks like.
struct WithoutCertificates(MemorySessionStore);

impl SessionStore for WithoutCertificates {
    fn put(&self, server_name: &str, mut session: crate::session::Tls13Session) {
        session.peer_certificates.clear();
        self.0.put(server_name, session);
    }

    fn take(&self, server_name: &str) -> Option<crate::session::Tls13Session> {
        self.0.take(server_name)
    }
}

/// A configured peer-certificate check that answers as `refuse` says, counting its calls,
/// and the chain it was last given.
type Check = (
    Arc<AtomicBool>,
    Arc<std::sync::atomic::AtomicUsize>,
    Arc<std::sync::Mutex<Vec<Vec<u8>>>>,
);

fn counting_check() -> (Check, crate::config::VerifyPeerCertificateFn) {
    let refuse = Arc::new(AtomicBool::new(false));
    let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let chain = Arc::new(std::sync::Mutex::new(vec![]));
    let (refuse_in, calls_in, chain_in) = (refuse.clone(), calls.clone(), chain.clone());
    let check: crate::config::VerifyPeerCertificateFn = Arc::new(move |given: &[Vec<u8>], _| {
        calls_in.fetch_add(1, Ordering::SeqCst);
        *chain_in.lock().unwrap() = given.to_vec();
        if refuse_in.load(Ordering::SeqCst) {
            Err(Error::Other("no longer trusted".to_owned()))
        } else {
            Ok(())
        }
    });
    ((refuse, calls, chain), check)
}

/// The server side of the re-check (RFC 8446 section 4.6.1: a ticket carries the client's
/// identity; RFC 5764 section 3 in WebRTC: on a resumed handshake the DTLS server's only
/// check of the client is this one). The server's configured peer-certificate check runs
/// again on the client certificate the ticket carries, before the server answers: accepted,
/// the association resumes; refused, the handshake ends with bad_certificate and nothing is
/// resumed.
#[test]
fn the_server_runs_its_peer_certificate_check_again_on_a_resumed_client() -> Result<()> {
    let provider = provider();
    let store = store();
    let client = Arc::new(
        client_builder()
            .with_certificates(vec![crate::crypto::Certificate::generate_self_signed(
                vec!["client".to_owned()],
                provider.crypto(),
            )?])
            .with_session_store(Some(store.clone()))
            .build(true, None)?,
    );
    let ((refuse, calls, chain), check) = counting_check();
    let server = Arc::new(
        server_builder()
            .with_client_auth(crate::config::ClientAuthType::RequireAnyClientCert)
            .with_verify_peer_certificate(Some(check))
            .with_session_tickets(2)
            .build(false, None)?,
    );
    let mut first = Pair::with(client.clone(), server.clone())?.complete();
    let client_chain = first.server_conn().peer_certificates.clone();
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "the full handshake's check"
    );
    let second = Pair::with(client.clone(), server.clone())?.complete();
    assert_eq!(resumed(&second), (true, true));
    assert_eq!(
        calls.load(Ordering::SeqCst),
        2,
        "run again on the resumption"
    );
    assert_eq!(
        *chain.lock().unwrap(),
        client_chain,
        "on the ticket's chain"
    );

    refuse.store(true, Ordering::SeqCst);
    assert!(store.len(NAME) > 0, "a ticket to offer");
    let mut third = Pair::with(client, server)?;
    third.run();
    assert_eq!(calls.load(Ordering::SeqCst), 3);
    assert!(
        !third.server_complete && !third.client_complete,
        "the resumption is refused"
    );
    assert!(third.server.is_connection_failed(&client_addr()));
    assert!(third.server_error.is_some(), "the server refused it");
    assert!(
        !third
            .server
            .get_connection_state(client_addr())
            .is_some_and(|state| state.resumed() && third.server_complete),
        "nothing resumed"
    );
    Ok(())
}

/// A client with a configured peer-certificate check does not take a resumption whose
/// ticket carries no certificate as checked: the check cannot run, so the handshake fails
/// with bad_certificate (it fails closed), where a client without a check resumes.
#[test]
fn a_client_with_a_check_refuses_a_resumption_that_carries_no_certificate() -> Result<()> {
    let store = Arc::new(WithoutCertificates(MemorySessionStore::new()));
    let ((_, calls, _), check) = counting_check();
    let client = Arc::new(
        client_builder()
            .with_session_store(Some(store.clone()))
            .with_verify_peer_certificate(Some(check))
            .build(true, None)?,
    );
    let server = ticket_server(2)?;
    let _ = Pair::with(client.clone(), server.clone())?.complete();
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(store.0.len(NAME), 2, "tickets kept, without certificates");
    let mut pair = Pair::with(client, server.clone())?;
    pair.run();
    assert!(!pair.client_complete, "the resumption is refused");
    assert!(pair.client.is_connection_failed(&server_addr()));
    assert_eq!(calls.load(Ordering::SeqCst), 1, "nothing was checked");

    // Without a check the same ticket resumes.
    let unchecked = Arc::new(
        client_builder()
            .with_session_store(Some(store.clone()))
            .build(true, None)?,
    );
    let pair = Pair::with(unchecked, server)?.complete();
    assert_eq!(resumed(&pair), (true, true));
    Ok(())
}

/// A server that asks its clients for a certificate and has a configured peer-certificate
/// check resumes no ticket that carries no client certificate (one it issued to a client
/// that sent none): the check could not run again, so the handshake is a full one, in which
/// the server asks again; a server without a check resumes the same kind of ticket.
#[test]
fn a_server_that_asks_for_a_certificate_resumes_no_ticket_without_one_for_its_check() -> Result<()>
{
    use crate::config::ClientAuthType;
    let store = store();
    let client = resuming_client(&store)?;
    let ((_, calls, _), check) = counting_check();
    let server = Arc::new(
        server_builder()
            .with_client_auth(ClientAuthType::RequestClientCert)
            .with_verify_peer_certificate(Some(check))
            .with_session_tickets(2)
            .build(false, None)?,
    );
    let _ = Pair::with(client.clone(), server.clone())?.complete();
    assert_eq!(
        store.len(NAME),
        2,
        "tickets for a client without a certificate"
    );
    let pair = Pair::with(client.clone(), server)?.complete();
    assert_eq!(resumed(&pair), (false, false), "a full handshake");
    assert_eq!(
        calls.load(Ordering::SeqCst),
        0,
        "no client certificate, ever"
    );

    let unchecked = Arc::new(
        server_builder()
            .with_client_auth(ClientAuthType::RequestClientCert)
            .with_session_tickets(2)
            .build(false, None)?,
    );
    let _ = Pair::with(client.clone(), unchecked.clone())?.complete();
    let pair = Pair::with(client, unchecked)?.complete();
    assert_eq!(resumed(&pair), (true, true));
    Ok(())
}

/// A server that asks its clients for no certificate (`NoClientCert`, the default) resumes
/// its tickets whether or not a peer-certificate check is configured: the first handshake
/// had no client certificate for the check either, so there is nothing to check again
/// (RFC 8446 section 4.6.1: the resumption carries over the authentication of the handshake
/// the ticket came from). The check is not called.
#[test]
fn a_server_that_asks_for_no_certificate_resumes_with_a_check_configured() -> Result<()> {
    let store = store();
    let client = resuming_client(&store)?;
    let ((_, calls, _), check) = counting_check();
    let server = Arc::new(
        server_builder()
            .with_verify_peer_certificate(Some(check))
            .with_session_tickets(2)
            .build(false, None)?,
    );
    let _ = Pair::with(client.clone(), server.clone())?.complete();
    assert_eq!(store.len(NAME), 2, "tickets without a client certificate");
    let pair = Pair::with(client, server)?.complete();
    assert_eq!(resumed(&pair), (true, true), "resumed");
    assert_eq!(
        calls.load(Ordering::SeqCst),
        0,
        "no client certificate, ever: nothing for the check"
    );
    Ok(())
}

/// Whether an external-PSK handshake completes on each side when one side also has a
/// peer-certificate check (for the handshakes that do carry a certificate). `client_checks`:
/// the check is the client's, else the server's, which has `client_auth`. Also how often
/// the check was called.
fn external_psk_with_a_check(
    client_checks: bool,
    client_auth: crate::config::ClientAuthType,
) -> Result<((bool, bool), usize)> {
    let psk = ExternalPsk::new(b"device-7".to_vec(), vec![0x42; 32]);
    let ((_, calls, _), check) = counting_check();
    let mut client = client_builder().with_external_psks(vec![psk.clone()]);
    let mut server = server_builder()
        .with_external_psks(vec![psk])
        .with_client_auth(client_auth);
    if client_checks {
        client = client.with_verify_peer_certificate(Some(check));
    } else {
        server = server.with_verify_peer_certificate(Some(check));
    }
    let mut pair = Pair::new(client, server)?;
    pair.run();
    assert_eq!(
        resumed(&pair),
        (pair.client_complete, pair.server_complete),
        "a PSK handshake where it completed: {:?} {:?}",
        pair.client_error,
        pair.server_error
    );
    Ok((
        (pair.client_complete, pair.server_complete),
        calls.load(Ordering::SeqCst),
    ))
}

/// RFC 8446 sections 2.2 and 4.2.11: an external PSK authenticates both sides by possession
/// of the key; no certificate is sent with it. A client that also has a peer-certificate
/// check (for its certificate handshakes) completes an external-PSK handshake, and the check
/// is not called: the refusal of a resumption "that carries no certificate" is about
/// tickets, not external PSKs (review 2, R1).
#[test]
fn an_external_psk_handshake_completes_for_a_client_with_a_certificate_check() -> Result<()> {
    use crate::config::ClientAuthType;
    assert_eq!(
        external_psk_with_a_check(true, ClientAuthType::NoClientCert)?,
        ((true, true), 0)
    );
    Ok(())
}

/// The same for a server with a peer-certificate check: it accepts the external PSK and
/// neither aborts with bad_certificate nor calls the check (review 2, R1).
#[test]
fn an_external_psk_handshake_completes_for_a_server_with_a_certificate_check() -> Result<()> {
    use crate::config::ClientAuthType;
    assert_eq!(
        external_psk_with_a_check(false, ClientAuthType::NoClientCert)?,
        ((true, true), 0)
    );
    Ok(())
}

/// And for a server that otherwise requires a client certificate: an external PSK takes the
/// place of the certificate exchange (RFC 8446 section 2.2), where one of this server's
/// tickets without a certificate would get a full handshake.
#[test]
fn an_external_psk_handshake_completes_for_a_server_that_requires_client_certificates() -> Result<()>
{
    use crate::config::ClientAuthType;
    assert_eq!(
        external_psk_with_a_check(false, ClientAuthType::RequireAnyClientCert)?,
        ((true, true), 0)
    );
    Ok(())
}
