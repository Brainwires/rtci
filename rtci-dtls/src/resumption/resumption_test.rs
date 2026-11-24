//! DTLS 1.2 session resumption (RFC 5246 section 7.3, RFC 6347 section 4.2.4 figure 2) by
//! session id and by RFC 5077 ticket, the RFC 7627 section 5.3 rules for the extended master
//! secret, and what each authentication step refuses. Driven through the production
//! connection, flight and handshaker code (`Exchange`: `feed` does what `Endpoint::read`
//! does), and through two endpoints where timers and the stateless cookie come in.

use super::*;
use crate::cipher_suite::CipherSuiteId;
use crate::config::{ConfigBuilder, DtlsVersion, HandshakeConfig};
use crate::conn::DTLSConn;
use crate::conn::conn_conformance_test::{
    CLIENT_HELLO, ECDSA_GCM, Exchange, SERVER_HELLO, builder, client_hello_body,
    client_hello_datagram, drain, extensions_after, feed, plaintext_alerts,
    plaintext_handshake_messages, provider, self_signed, usual_client_extensions,
};
use crate::content::ContentType;
use crate::crypto::Certificate;
use crate::handshake::handshake_message_server_hello::HandshakeMessageServerHello;
use crate::record_layer::record_layer_header::RECORD_LAYER_HEADER_SIZE;
use crate::record_layer::unpack_datagram;
use crate::session::{MemorySessionCache, MemorySessionStore, SessionCache, SessionStore};
use shared::error::Result;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

const NAME: &str = "localhost";

const HELLO_VERIFY_REQUEST: u8 = 3;
const NEW_SESSION_TICKET: u8 = 4;
const CERTIFICATE: u8 = 11;
const SERVER_KEY_EXCHANGE: u8 = 12;
const SERVER_HELLO_DONE: u8 = 14;
const CLIENT_KEY_EXCHANGE: u8 = 16;

const EXT_EXTENDED_MASTER_SECRET: u16 = 23;
const EXT_SESSION_TICKET: u16 = 35;

const ALERT_FATAL: u8 = 2;
const ALERT_UNEXPECTED_MESSAGE: u8 = 10;
const ALERT_HANDSHAKE_FAILURE: u8 = 40;
const ALERT_BAD_CERTIFICATE: u8 = 42;
const ALERT_ILLEGAL_PARAMETER: u8 = 47;
const ALERT_DECRYPT_ERROR: u8 = 51;
const ALERT_UNSUPPORTED_EXTENSION: u8 = 110;

const ECDSA_CHACHA: u16 = 0xcca9;

fn store() -> Arc<MemorySessionStore> {
    Arc::new(MemorySessionStore::new())
}

fn cache() -> Arc<MemorySessionCache> {
    Arc::new(MemorySessionCache::default())
}

/// A DTLS 1.2 client keeping its sessions in `store`.
fn client_config(store: &Arc<MemorySessionStore>, builder: ConfigBuilder) -> Arc<HandshakeConfig> {
    Arc::new(
        builder
            .with_protocol_versions(DtlsVersion::Dtls1_2, DtlsVersion::Dtls1_2)
            .with_insecure_skip_verify(true)
            .with_server_name(NAME.to_owned())
            .with_session_store(Some(store.clone()))
            .build(true, None)
            .expect("a client configuration"),
    )
}

/// A DTLS 1.2 server with `certificate`, resuming from `cache` and, with `tickets`, by
/// ticket.
fn server_config(
    cache: Option<&Arc<MemorySessionCache>>,
    tickets: bool,
    certificate: &Certificate,
    builder: ConfigBuilder,
) -> Arc<HandshakeConfig> {
    Arc::new(
        builder
            .with_protocol_versions(DtlsVersion::Dtls1_2, DtlsVersion::Dtls1_2)
            .with_certificates(vec![certificate.clone()])
            .with_session_cache(cache.map(|cache| cache.clone() as Arc<dyn SessionCache>))
            .with_session_tickets(if tickets { 1 } else { 0 })
            .build(false, None)
            .expect("a server configuration"),
    )
}

fn handshake(client: &Arc<HandshakeConfig>, server: &Arc<HandshakeConfig>) -> Exchange {
    Exchange::run(
        DTLSConn::new(client.clone(), true, None),
        DTLSConn::new(server.clone(), false, None),
    )
}

fn types(datagrams: &[Vec<u8>]) -> Vec<u8> {
    plaintext_handshake_messages(datagrams)
        .into_iter()
        .map(|(typ, _)| typ)
        .collect()
}

/// The body of the last plaintext handshake message of `typ`.
fn last_body(datagrams: &[Vec<u8>], typ: u8) -> Option<Vec<u8>> {
    plaintext_handshake_messages(datagrams)
        .into_iter()
        .rev()
        .find(|(t, _)| *t == typ)
        .map(|(_, body)| body)
}

fn hello_session_id(body: &[u8]) -> Vec<u8> {
    body[35..35 + body[34] as usize].to_vec()
}

fn client_hello_extensions(body: &[u8]) -> Vec<(u16, Vec<u8>)> {
    let session_end = 35 + body[34] as usize;
    let cookie_end = session_end + 1 + body[session_end] as usize;
    let suites = u16::from_be_bytes([body[cookie_end], body[cookie_end + 1]]) as usize;
    let compression_at = cookie_end + 2 + suites;
    extensions_after(body, compression_at + 1 + body[compression_at] as usize)
}

fn server_hello_extensions(body: &[u8]) -> Vec<(u16, Vec<u8>)> {
    extensions_after(body, 35 + body[34] as usize + 2 + 1)
}

fn exported(exchange: &Exchange) -> (Vec<u8>, Vec<u8>) {
    let export = |conn: &DTLSConn| {
        conn.connection_state()
            .export_keying_material("EXTRACTOR-dtls_srtp", &[], 32)
            .expect("an exporter")
            .as_ref()
            .to_vec()
    };
    (export(&exchange.client), export(&exchange.server))
}

/// The server_name extension for [`NAME`] (RFC 6066 section 3).
fn server_name_extension() -> Vec<u8> {
    let mut data = vec![0, NAME.len() as u8 + 3, 0, 0, NAME.len() as u8];
    data.extend_from_slice(NAME.as_bytes());
    let mut out = vec![0, 0, 0, data.len() as u8];
    out.extend_from_slice(&data);
    out
}

/// A plaintext fatal alert `description` among `datagrams`.
fn assert_alert(datagrams: &[Vec<u8>], description: u8, what: &str) {
    let alerts = plaintext_alerts(datagrams);
    assert!(
        alerts.contains(&(ALERT_FATAL, description)),
        "{what}: expected fatal alert {description}, sent {alerts:?}"
    );
}

/// The fatal alert `conn` sent, protected or not.
fn alert_of(conn: &DTLSConn) -> Option<u8> {
    conn.fatal_alert_sent
        .as_ref()
        .map(|(alert, _)| alert.alert_description as u8)
}

/// Rewrites the first plaintext ServerHello in `datagram` with `change`, keeping the record and
/// handshake headers' lengths right.
fn rewrite_server_hello(datagram: &mut Vec<u8>, change: impl Fn(&mut HandshakeMessageServerHello)) {
    let Ok(records) = unpack_datagram(datagram) else {
        return;
    };
    let mut out = vec![];
    for record in records {
        let is_server_hello = record[0] == ContentType::Handshake as u8
            && record[3..5] == [0, 0]
            && record.get(RECORD_LAYER_HEADER_SIZE) == Some(&SERVER_HELLO);
        if !is_server_hello {
            out.extend_from_slice(&record);
            continue;
        }
        let mut reader = &record[RECORD_LAYER_HEADER_SIZE..];
        let mut handshake = Handshake::unmarshal(&mut reader).expect("a ServerHello");
        if let HandshakeMessage::ServerHello(server_hello) = &mut handshake.handshake_message {
            change(server_hello);
        }
        let sequence = handshake.handshake_header.message_sequence;
        let rebuilt = marshal_handshake(handshake.handshake_message, sequence as isize)
            .expect("the ServerHello encodes");
        out.extend_from_slice(&record[..11]);
        out.extend_from_slice(&(rebuilt.len() as u16).to_be_bytes());
        out.extend_from_slice(&rebuilt);
    }
    *datagram = out;
}

/// The session the client stored, put back (`take_dtls12` takes it).
fn stored(store: &MemorySessionStore) -> Dtls12Session {
    let session = store.take_dtls12(NAME).expect("a stored session");
    store.put_dtls12(NAME, session.clone());
    session
}

// ---------------------------------------------------------------------------------------------
// The abbreviated handshake (RFC 5246 7.3)
// ---------------------------------------------------------------------------------------------

/// RFC 5246 7.3 and 7.4.1.3: a server with a session cache gives each full handshake a session
/// id; a ClientHello that offers it gets the abbreviated handshake: ServerHello with the same
/// session id, then the server's ChangeCipherSpec and Finished, the client's last. No
/// Certificate, ServerKeyExchange, ServerHelloDone or ClientKeyExchange; keys of its own from
/// the session's master secret and the new randoms; the server's certificate reported again.
/// A session resumed by its id can be resumed again.
#[test]
fn a_session_id_from_one_handshake_resumes_the_next_with_the_abbreviated_handshake() {
    let (store, cache) = (store(), cache());
    let certificate = self_signed();
    let client = client_config(&store, builder());
    let server = server_config(Some(&cache), false, &certificate, builder());

    let first = handshake(&client, &server);
    assert!(
        first.completed(),
        "{:?} {:?}",
        first.client_err,
        first.server_err
    );
    assert!(!first.client.connection_state().resumed());
    let server_hello = last_body(&first.from_server, SERVER_HELLO).expect("a ServerHello");
    let session_id = hello_session_id(&server_hello);
    assert_eq!(session_id.len(), SESSION_ID_LENGTH, "a new session id");
    assert_eq!(cache.len(), 1, "the server keeps the session");
    assert_eq!(store.len_dtls12(NAME), 1, "the client keeps the session");
    let first_keys = exported(&first);
    let server_chain = first.client.connection_state().peer_certificates.clone();

    for round in 0..2 {
        let resumed = handshake(&client, &server);
        assert!(
            resumed.completed(),
            "round {round}: {:?} {:?}",
            resumed.client_err,
            resumed.server_err
        );
        assert!(resumed.client.connection_state().resumed(), "round {round}");
        assert!(resumed.server.connection_state().resumed(), "round {round}");
        let client_hello = last_body(&resumed.from_client, CLIENT_HELLO).expect("a ClientHello");
        assert_eq!(
            hello_session_id(&client_hello),
            session_id,
            "the session is offered"
        );
        let server_hello = last_body(&resumed.from_server, SERVER_HELLO).expect("a ServerHello");
        assert_eq!(hello_session_id(&server_hello), session_id, "and resumed");
        assert_eq!(
            types(&resumed.from_server),
            [HELLO_VERIFY_REQUEST, SERVER_HELLO],
            "round {round}: the server's abbreviated flight has no key exchange in the clear"
        );
        assert_eq!(
            types(&resumed.from_client),
            [CLIENT_HELLO, CLIENT_HELLO],
            "round {round}: nor the client's"
        );
        assert_eq!(
            resumed.client.connection_state().peer_certificates,
            server_chain,
            "the session's certificates are reported"
        );
        let keys = exported(&resumed);
        assert_eq!(keys.0, keys.1);
        assert_ne!(keys.0, first_keys.0, "a resumption has keys of its own");
    }
}

/// RFC 6347 4.2.4 figure 2: in a resumed handshake the server's Finished comes first, the
/// client's flight is the last one, and on the wire the server's flight is ServerHello,
/// ChangeCipherSpec and Finished.
#[test]
fn the_server_finishes_first_in_an_abbreviated_handshake() {
    let (store, cache) = (store(), cache());
    let certificate = self_signed();
    let client = client_config(&store, builder());
    let server = server_config(Some(&cache), false, &certificate, builder());
    assert!(handshake(&client, &server).completed());

    let now = Instant::now();
    let mut client_conn = DTLSConn::new(client.clone(), true, None);
    let mut server_conn = DTLSConn::new(server.clone(), false, None);
    client_conn.handshake(now).unwrap();
    for datagram in drain(&mut client_conn) {
        feed(&mut server_conn, now, &datagram).unwrap();
    }
    for datagram in drain(&mut server_conn) {
        feed(&mut client_conn, now, &datagram).unwrap();
    }
    for datagram in drain(&mut client_conn) {
        feed(&mut server_conn, now, &datagram).unwrap();
    }
    let server_flight = drain(&mut server_conn);
    let content_types: Vec<u8> = server_flight
        .iter()
        .flat_map(|datagram| unpack_datagram(datagram).unwrap())
        .map(|record| record[0])
        .collect();
    assert_eq!(
        content_types,
        [22, 20, 22],
        "ServerHello, ChangeCipherSpec, Finished"
    );
    assert!(
        !server_conn.is_handshake_completed(),
        "the server waits for the client"
    );
    for datagram in &server_flight {
        feed(&mut client_conn, now, datagram).unwrap();
    }
    assert!(
        client_conn.is_handshake_completed(),
        "the client completes on the server's Finished"
    );
    let client_flight = drain(&mut client_conn);
    for datagram in &client_flight {
        feed(&mut server_conn, now, datagram).unwrap();
    }
    assert!(server_conn.is_handshake_completed());
}

/// RFC 5077 sections 3.2 to 3.4: a client with a store asks for a ticket (an empty SessionTicket
/// extension); the server announces one (an empty SessionTicket extension in its ServerHello)
/// and sends it as NewSessionTicket ahead of its ChangeCipherSpec. The next ClientHello presents
/// the ticket with a new session id, which the server echoes to resume; the ticket used is
/// replaced by a new one. A server with tickets and no cache keeps nothing.
#[test]
fn a_ticket_from_one_handshake_resumes_the_next() {
    let store = store();
    let certificate = self_signed();
    let client = client_config(&store, builder());
    let server = server_config(None, true, &certificate, builder());

    let first = handshake(&client, &server);
    assert!(
        first.completed(),
        "{:?} {:?}",
        first.client_err,
        first.server_err
    );
    let client_hello = last_body(&first.from_client, CLIENT_HELLO).unwrap();
    assert!(
        client_hello_extensions(&client_hello).contains(&(EXT_SESSION_TICKET, vec![])),
        "the client asks for a ticket"
    );
    let server_hello = last_body(&first.from_server, SERVER_HELLO).unwrap();
    assert!(server_hello_extensions(&server_hello).contains(&(EXT_SESSION_TICKET, vec![])));
    let server_types = types(&first.from_server);
    assert_eq!(
        server_types.last(),
        Some(&NEW_SESSION_TICKET),
        "the ticket comes after the ServerHelloDone, ahead of the ChangeCipherSpec: {server_types:?}"
    );
    let ticket = stored(&store).ticket.expect("the client keeps the ticket");

    let resumed = handshake(&client, &server);
    assert!(
        resumed.completed(),
        "{:?} {:?}",
        resumed.client_err,
        resumed.server_err
    );
    assert!(resumed.client.connection_state().resumed());
    assert!(resumed.server.connection_state().resumed());
    let client_hello = last_body(&resumed.from_client, CLIENT_HELLO).unwrap();
    assert!(client_hello_extensions(&client_hello).contains(&(EXT_SESSION_TICKET, ticket.clone())));
    let offered_id = hello_session_id(&client_hello);
    assert_eq!(offered_id.len(), SESSION_ID_LENGTH);
    let server_hello = last_body(&resumed.from_server, SERVER_HELLO).unwrap();
    assert_eq!(
        hello_session_id(&server_hello),
        offered_id,
        "the echo says it is resumed"
    );
    assert_eq!(
        types(&resumed.from_server),
        [HELLO_VERIFY_REQUEST, SERVER_HELLO, NEW_SESSION_TICKET]
    );
    assert_eq!(store.len_dtls12(NAME), 1);
    let renewed = stored(&store).ticket.expect("a new ticket");
    assert_ne!(renewed, ticket);
    let keys = exported(&resumed);
    assert_eq!(keys.0, keys.1);
}

/// RFC 9147 section 5.3: a client offering DTLS 1.3 and 1.2 puts its DTLS 1.2 session id in the
/// legacy_session_id, and a DTLS 1.2 server resumes it.
#[test]
fn a_client_offering_both_versions_resumes_a_dtls12_session() {
    let (store, cache) = (store(), cache());
    let certificate = self_signed();
    let dual = Arc::new(
        crate::dtls13::handshake_test::client_builder()
            .with_server_name(NAME.to_owned())
            .with_session_store(Some(store.clone()))
            .build(true, None)
            .unwrap(),
    );
    let server = server_config(Some(&cache), false, &certificate, builder());
    let first = handshake(&dual, &server);
    assert!(
        first.completed(),
        "{:?} {:?}",
        first.client_err,
        first.server_err
    );
    let resumed = handshake(&dual, &server);
    assert!(
        resumed.completed(),
        "{:?} {:?}",
        resumed.client_err,
        resumed.server_err
    );
    assert!(resumed.client.connection_state().resumed());
    assert_eq!(
        resumed.client.connection_state().negotiated_version(),
        Some(DtlsVersion::Dtls1_2)
    );
}

// ---------------------------------------------------------------------------------------------
// What is not resumed: a full handshake instead
// ---------------------------------------------------------------------------------------------

/// RFC 5246 7.4.1.3: a session id the server does not know gets a full handshake under a new
/// one. RFC 5077 section 3.4: so does a ticket the server cannot open (another server's, an
/// altered one, a DTLS 1.3 one), and one already used.
#[test]
fn an_unknown_session_or_ticket_gets_a_full_handshake() {
    let certificate = self_signed();
    let (store, cache) = (store(), cache());
    let client = client_config(&store, builder());
    let server = server_config(Some(&cache), true, &certificate, builder());
    let other_server = server_config(Some(&self::cache()), true, &certificate, builder());
    assert!(handshake(&client, &server).completed());
    let session = stored(&store);

    let full = |store: &MemorySessionStore, session: Dtls12Session, server, what: &str| {
        while store.take_dtls12(NAME).is_some() {}
        store.put_dtls12(NAME, session);
        let exchange = handshake(&client, server);
        assert!(exchange.completed(), "{what}");
        assert!(!exchange.server.connection_state().resumed(), "{what}");
        assert!(!exchange.client.connection_state().resumed(), "{what}");
        assert!(
            types(&exchange.from_server).contains(&CERTIFICATE),
            "{what}: a full handshake"
        );
    };

    let mut altered = session.clone();
    if let Some(ticket) = &mut altered.ticket {
        ticket[20] ^= 1;
    }
    full(&store, altered, &server, "an altered ticket");
    full(
        &store,
        session.clone(),
        &other_server,
        "another server's ticket",
    );
    let mut unknown = session.clone();
    unknown.ticket = None;
    unknown.session_id = vec![0x42; SESSION_ID_LENGTH];
    full(&store, unknown, &server, "an unknown session id");
    let mut dtls13 = session.clone();
    dtls13.ticket = Some(
        server
            .ticket_issuer
            .as_ref()
            .unwrap()
            .seal(
                provider().as_ref(),
                CipherSuiteId::Tls_Aes_128_Gcm_Sha256,
                Instant::now(),
                0,
                session.master_secret.as_ref(),
                NAME,
                &[],
                0,
            )
            .unwrap()
            .expect("an issuer with its keys"),
    );
    full(&store, dtls13, &server, "a DTLS 1.3 ticket");

    // A ticket is accepted once.
    while store.take_dtls12(NAME).is_some() {}
    store.put_dtls12(NAME, session.clone());
    let resumed = handshake(&client, &server);
    assert!(resumed.server.connection_state().resumed());
    full(&store, session, &server, "a ticket used before");
}

/// RFC 5246 appendix F.1.4: a session is resumed for its lifetime only, by id and by ticket.
#[test]
fn an_expired_session_gets_a_full_handshake() {
    let certificate = self_signed();
    for tickets in [false, true] {
        let (store, cache) = (store(), cache());
        let client = client_config(&store, builder());
        let server = server_config(
            (!tickets).then_some(&cache),
            tickets,
            &certificate,
            builder().with_session_ticket_lifetime(Duration::from_secs(1)),
        );
        let now = Instant::now();
        assert!(handshake(&client, &server).completed());

        let later = now + Duration::from_secs(2);
        let mut client_conn = DTLSConn::new(client.clone(), true, None);
        let mut server_conn = DTLSConn::new(server.clone(), false, None);
        client_conn.handshake(now).unwrap();
        let mut from_server = vec![];
        for _ in 0..8 {
            for datagram in drain(&mut client_conn) {
                let _ = feed(&mut server_conn, later, &datagram);
            }
            let sent = drain(&mut server_conn);
            for datagram in &sent {
                let _ = feed(&mut client_conn, later, datagram);
            }
            from_server.extend(sent);
        }
        assert!(
            types(&from_server).contains(&CERTIFICATE),
            "tickets {tickets}: a full handshake"
        );
        assert!(!server_conn.connection_state().resumed());
    }
}

/// RFC 6066 section 3: a server does not resume a session for a different server name.
#[test]
fn a_session_of_another_server_name_gets_a_full_handshake() {
    let certificate = self_signed();
    let (store, cache) = (store(), cache());
    let server = server_config(Some(&cache), false, &certificate, builder());
    assert!(handshake(&client_config(&store, builder()), &server).completed());
    let session = store.take_dtls12(NAME).unwrap();
    store.put_dtls12("other.example", session);
    let other = Arc::new(
        builder()
            .with_protocol_versions(DtlsVersion::Dtls1_2, DtlsVersion::Dtls1_2)
            .with_insecure_skip_verify(true)
            .with_server_name("other.example".to_owned())
            .with_session_store(Some(store.clone()))
            .build(true, None)
            .unwrap(),
    );
    let exchange = handshake(&other, &server);
    assert!(exchange.completed());
    let client_hello = last_body(&exchange.from_client, CLIENT_HELLO).unwrap();
    assert!(
        !hello_session_id(&client_hello).is_empty(),
        "the session is offered"
    );
    assert!(!exchange.server.connection_state().resumed());
}

/// RFC 5246 7.4.1.2: a client offers a session only with its cipher suite among the ones it
/// offers; 7.4.1.3: a server resumes one only if the ClientHello offers its suite.
#[test]
fn a_session_whose_cipher_suite_is_not_offered_is_not_resumed() {
    let certificate = self_signed();
    let (store, cache) = (store(), cache());
    let server_builder = || {
        builder().with_cipher_suites(vec![
            CipherSuiteId::Tls_Ecdhe_Ecdsa_With_Aes_128_Gcm_Sha256,
            CipherSuiteId::Tls_Ecdhe_Ecdsa_With_ChaCha20_Poly1305_Sha256,
        ])
    };
    let server = server_config(Some(&cache), false, &certificate, server_builder());
    assert!(handshake(&client_config(&store, builder()), &server).completed());
    let session = stored(&store);
    assert_eq!(
        session.cipher_suite(),
        CipherSuiteId::Tls_Ecdhe_Ecdsa_With_Aes_128_Gcm_Sha256
    );

    // The client: a configuration without the suite does not offer the session.
    let chacha_client = client_config(
        &store,
        builder().with_cipher_suites(vec![
            CipherSuiteId::Tls_Ecdhe_Ecdsa_With_ChaCha20_Poly1305_Sha256,
        ]),
    );
    let exchange = handshake(&chacha_client, &server);
    assert!(exchange.completed());
    let client_hello = last_body(&exchange.from_client, CLIENT_HELLO).unwrap();
    assert!(hello_session_id(&client_hello).is_empty());

    // The server: a ClientHello offering the session id with another suite gets a full
    // handshake under a new id.
    let now = Instant::now();
    let mut server_conn = DTLSConn::new(server.clone(), false, None);
    server_conn.handshake(now).unwrap();
    let body = |cookie: &[u8]| {
        let mut extensions = usual_client_extensions();
        extensions.extend_from_slice(&[0, 23, 0, 0]);
        extensions.extend_from_slice(&server_name_extension());
        client_hello_body(
            &session.session_id,
            cookie,
            &[ECDSA_CHACHA],
            Some(&extensions),
        )
    };
    feed(&mut server_conn, now, &client_hello_datagram(0, &body(&[]))).unwrap();
    let hello_verify_request = last_body(&drain(&mut server_conn), HELLO_VERIFY_REQUEST).unwrap();
    let cookie = hello_verify_request[3..3 + hello_verify_request[2] as usize].to_vec();
    feed(
        &mut server_conn,
        now,
        &client_hello_datagram(1, &body(&cookie)),
    )
    .unwrap();
    let answer = drain(&mut server_conn);
    let server_hello = last_body(&answer, SERVER_HELLO).unwrap();
    assert_ne!(hello_session_id(&server_hello), session.session_id);
    assert!(types(&answer).contains(&CERTIFICATE));
}

/// A session is resumed only where the configured client authentication would have accepted
/// its full handshake: a server that requires a client certificate does not resume a session
/// that had none.
#[test]
fn a_session_without_the_required_client_certificate_is_not_resumed() {
    let certificate = self_signed();
    let (store, cache) = (store(), cache());
    let client = client_config(&store, builder());
    let open = server_config(Some(&cache), false, &certificate, builder());
    assert!(handshake(&client, &open).completed());
    let strict = server_config(
        Some(&cache),
        false,
        &certificate,
        builder().with_client_auth(crate::config::ClientAuthType::RequireAnyClientCert),
    );
    let exchange = handshake(&client, &strict);
    assert!(!exchange.server.connection_state().resumed());
    assert!(types(&exchange.from_server).contains(&CERTIFICATE));
}

/// RFC 5077 section 3.4: a server that issues a ticket to a client that presented none gives
/// an empty session id (SHOULD), keeping no state for it; and when a ticket is presented the
/// session id is not used for stateful resumption (MUST NOT), even one in the cache.
#[test]
fn tickets_and_session_ids_do_not_mix() {
    let certificate = self_signed();
    let (store, cache) = (store(), cache());
    let server = server_config(Some(&cache), true, &certificate, builder());
    let exchange = handshake(&client_config(&store, builder()), &server);
    assert!(exchange.completed());
    let server_hello = last_body(&exchange.from_server, SERVER_HELLO).unwrap();
    assert!(
        hello_session_id(&server_hello).is_empty(),
        "no session id with a ticket"
    );
    assert!(types(&exchange.from_server).contains(&NEW_SESSION_TICKET));
    assert_eq!(cache.len(), 0, "the ticket is the state");

    // A session in the cache, from a client that asks for no ticket.
    let plain = Arc::new(
        builder()
            .with_protocol_versions(DtlsVersion::Dtls1_2, DtlsVersion::Dtls1_2)
            .with_insecure_skip_verify(true)
            .with_server_name(NAME.to_owned())
            .build(true, None)
            .unwrap(),
    );
    let exchange = handshake(&plain, &server);
    assert!(exchange.completed());
    // RFC 5077 section 3.2: no SessionTicket extension and no ticket for a client that sent
    // none.
    assert!(!types(&exchange.from_server).contains(&NEW_SESSION_TICKET));
    let server_hello = last_body(&exchange.from_server, SERVER_HELLO).unwrap();
    assert!(
        !server_hello_extensions(&server_hello)
            .iter()
            .any(|(typ, _)| *typ == EXT_SESSION_TICKET)
    );
    let cached = hello_session_id(&server_hello);
    assert_eq!(cached.len(), SESSION_ID_LENGTH);
    assert_eq!(cache.len(), 1);
    // Offered by id with a ticket the server cannot open: a full handshake, not the cached one.
    let mut garbage_ticket = EXT_SESSION_TICKET.to_be_bytes().to_vec();
    garbage_ticket.extend_from_slice(&[0, 40]);
    garbage_ticket.extend_from_slice(&[0x33; 40]);
    let (result, answer, conn) = answer_to_offer_with(&server, &cached, true, &garbage_ticket);
    result.unwrap();
    assert!(!conn.connection_state().resumed);
    assert!(types(&answer).contains(&CERTIFICATE));
    // And without the ticket, the same id resumes.
    let (result, _, conn) = answer_to_offer(&server, &cached, true);
    result.unwrap();
    assert!(conn.connection_state().resumed);

    // A ticket refused: the server may give a session id and a new ticket; the client, given a
    // ticket, keeps the session by the ticket and not by the ServerHello's id.
    while store.take_dtls12(NAME).is_some() {}
    let mut refused = session_of_cache(&cache, &cached);
    refused.ticket = Some(vec![0x44; 60]);
    store.put_dtls12(NAME, refused);
    let exchange = handshake(&client_config(&store, builder()), &server);
    assert!(exchange.completed());
    assert!(!exchange.server.connection_state().resumed);
    let server_hello = last_body(&exchange.from_server, SERVER_HELLO).unwrap();
    let given = hello_session_id(&server_hello);
    assert_eq!(
        given.len(),
        SESSION_ID_LENGTH,
        "a session id for the refused ticket"
    );
    let kept = stored(&store);
    assert!(kept.has_ticket());
    assert_ne!(kept.session_id, given, "the ServerHello's id is discarded");
}

fn session_of_cache(cache: &MemorySessionCache, id: &[u8]) -> Dtls12Session {
    cache.get(id).expect("a cached session")
}

/// RFC 5077 section 3.3: the client keeps a ticket no longer than the server's
/// ticket_lifetime_hint.
#[test]
fn a_ticket_is_kept_for_its_lifetime_hint() {
    let certificate = self_signed();
    let store = store();
    let server = server_config(
        None,
        true,
        &certificate,
        builder().with_session_ticket_lifetime(Duration::from_secs(90)),
    );
    assert!(handshake(&client_config(&store, builder()), &server).completed());
    let session = stored(&store);
    assert!(session.has_ticket());
    assert_eq!(session.lifetime, Duration::from_secs(90));
}

/// RFC 5246 7.3: "a SessionID becomes valid when the handshake negotiating it completes with
/// the exchange of Finished messages": a server whose full handshake fails at the client's
/// Finished keeps no session.
#[test]
fn a_session_is_kept_only_once_its_handshake_completes() {
    let certificate = self_signed();
    let (store, cache) = (store(), cache());
    let server = server_config(Some(&cache), false, &certificate, builder());
    let mut client_conn = DTLSConn::new(client_config(&store, builder()), true, None);
    client_conn.state.local_verify_data = vec![0; 12];
    let exchange = Exchange::run(client_conn, DTLSConn::new(server, false, None));
    assert!(!exchange.server.is_handshake_completed());
    assert_eq!(alert_of(&exchange.server), Some(ALERT_DECRYPT_ERROR));
    assert_eq!(cache.len(), 0);
    assert_eq!(store.len_dtls12(NAME), 0);

    // RFC 5077 section 3.3: in a full handshake the server checks the client's Finished before
    // it sends a ticket.
    let server = server_config(None, true, &certificate, builder());
    let mut client_conn = DTLSConn::new(client_config(&store, builder()), true, None);
    client_conn.state.local_verify_data = vec![0; 12];
    let exchange = Exchange::run(client_conn, DTLSConn::new(server, false, None));
    assert_eq!(alert_of(&exchange.server), Some(ALERT_DECRYPT_ERROR));
    assert!(!types(&exchange.from_server).contains(&NEW_SESSION_TICKET));
}

// ---------------------------------------------------------------------------------------------
// Authentication: what an abbreviated handshake refuses
// ---------------------------------------------------------------------------------------------

/// RFC 5246 7.4.9: the client checks the server's Finished of an abbreviated handshake over
/// ClientHello and ServerHello, and the server the client's over those and the server's
/// Finished: a wrong one is refused with decrypt_error and the association fails.
#[test]
fn a_wrong_finished_in_an_abbreviated_handshake_is_refused() {
    let certificate = self_signed();
    let (store, cache) = (store(), cache());
    let client = client_config(&store, builder());
    let server = server_config(Some(&cache), false, &certificate, builder());
    assert!(handshake(&client, &server).completed());

    // The server's Finished (generate reuses a verify_data that is already there).
    let mut server_conn = DTLSConn::new(server.clone(), false, None);
    server_conn.state.local_verify_data = vec![0; 12];
    let exchange = Exchange::run(DTLSConn::new(client.clone(), true, None), server_conn);
    assert!(exchange.client.connection_state().resumed, "it was resumed");
    assert!(!exchange.client.is_handshake_completed());
    assert!(exchange.client_err.is_some());
    assert_eq!(alert_of(&exchange.client), Some(ALERT_DECRYPT_ERROR));

    // The client's.
    assert!(
        handshake(&client, &server).completed(),
        "the session is kept anew"
    );
    let mut client_conn = DTLSConn::new(client.clone(), true, None);
    client_conn.state.local_verify_data = vec![0; 12];
    let exchange = Exchange::run(client_conn, DTLSConn::new(server.clone(), false, None));
    assert!(exchange.server.connection_state().resumed);
    assert!(!exchange.server.is_handshake_completed());
    assert_eq!(alert_of(&exchange.server), Some(ALERT_DECRYPT_ERROR));
}

/// RFC 5246 7.4.9: the Finished of an abbreviated handshake covers the hellos as each side
/// saw them. A ServerHello altered on the way (an extension the server did not send is taken
/// out by someone on the path, here the point formats) makes the client refuse the server's
/// Finished. RFC 5077 section 3.3: the NewSessionTicket is covered too.
#[test]
fn an_altered_hello_or_ticket_fails_the_abbreviated_handshake() {
    let certificate = self_signed();
    for tickets in [false, true] {
        let (store, cache) = (store(), cache());
        let client = client_config(&store, builder());
        let server = server_config(Some(&cache), tickets, &certificate, builder());
        assert!(handshake(&client, &server).completed());
        let exchange = Exchange::run_altering(
            DTLSConn::new(client.clone(), true, None),
            DTLSConn::new(server.clone(), false, None),
            |_| {},
            |datagram| {
                rewrite_server_hello(datagram, |server_hello| {
                    server_hello.extensions.retain(|extension| {
                        !matches!(extension, Extension::SupportedPointFormats(_))
                    })
                })
            },
        );
        assert!(
            !exchange.client.is_handshake_completed(),
            "tickets {tickets}"
        );
        assert_eq!(
            alert_of(&exchange.client),
            Some(ALERT_DECRYPT_ERROR),
            "tickets {tickets}"
        );
        // RFC 5077 section 3.2: a ticket accepted for a handshake that then failed is deleted.
        assert_eq!(store.len_dtls12(NAME), 0, "tickets {tickets}");
    }

    // The ticket of a full handshake, altered: the client's check of the server's Finished.
    let (store, cache) = (store(), cache());
    let client = client_config(&store, builder());
    let server = server_config(Some(&cache), true, &certificate, builder());
    let exchange = Exchange::run_altering(
        DTLSConn::new(client.clone(), true, None),
        DTLSConn::new(server.clone(), false, None),
        |_| {},
        |datagram| {
            for range in ticket_ranges(datagram) {
                datagram[range.start + 6] ^= 1;
            }
        },
    );
    assert!(!exchange.client.is_handshake_completed());
    assert_eq!(alert_of(&exchange.client), Some(ALERT_DECRYPT_ERROR));
    assert_eq!(store.len_dtls12(NAME), 0, "nothing is kept");
}

/// Where the bodies of the plaintext NewSessionTickets of `datagram` lie.
fn ticket_ranges(datagram: &[u8]) -> Vec<std::ops::Range<usize>> {
    let mut ranges = vec![];
    let mut at = 0;
    while at + RECORD_LAYER_HEADER_SIZE <= datagram.len() {
        let length = u16::from_be_bytes([datagram[at + 11], datagram[at + 12]]) as usize;
        let body = at + RECORD_LAYER_HEADER_SIZE;
        if datagram[at] == 22
            && datagram[at + 3..at + 5] == [0, 0]
            && datagram.get(body) == Some(&NEW_SESSION_TICKET)
        {
            ranges.push(body + 12..body + length);
        }
        at = body + length;
    }
    ranges
}

/// RFC 5246 7.4.1.3: a resumption keeps the session's cipher suite. A ServerHello that echoes
/// the session id with another suite (one the client offered) is refused with
/// illegal_parameter.
#[test]
fn a_resumption_with_another_cipher_suite_is_refused() {
    let certificate = self_signed();
    let (store, cache) = (store(), cache());
    let both = || {
        builder().with_cipher_suites(vec![
            CipherSuiteId::Tls_Ecdhe_Ecdsa_With_Aes_128_Gcm_Sha256,
            CipherSuiteId::Tls_Ecdhe_Ecdsa_With_ChaCha20_Poly1305_Sha256,
        ])
    };
    let client = client_config(&store, both());
    let server = server_config(Some(&cache), false, &certificate, both());
    assert!(handshake(&client, &server).completed());
    let exchange = Exchange::run_altering(
        DTLSConn::new(client.clone(), true, None),
        DTLSConn::new(server.clone(), false, None),
        |_| {},
        |datagram| {
            rewrite_server_hello(datagram, |server_hello| {
                server_hello.cipher_suite =
                    CipherSuiteId::Tls_Ecdhe_Ecdsa_With_ChaCha20_Poly1305_Sha256
            })
        },
    );
    assert!(!exchange.client.is_handshake_completed());
    assert_alert(
        &exchange.from_client,
        ALERT_ILLEGAL_PARAMETER,
        "another suite",
    );
}

/// The certificates of a resumed session are checked as in its full handshake: a client whose
/// peer-certificate check refuses them refuses the resumption with bad_certificate.
#[test]
fn a_resumed_session_whose_certificate_is_refused_fails() {
    let certificate = self_signed();
    let (store, cache) = (store(), cache());
    let server = server_config(Some(&cache), false, &certificate, builder());
    assert!(handshake(&client_config(&store, builder()), &server).completed());
    let refusing = client_config(
        &store,
        builder().with_verify_peer_certificate(Some(Arc::new(
            |_: &[Vec<u8>], _: &[rustls::pki_types::CertificateDer<'static>]| {
                Err(Error::Other("not this one".to_owned()))
            },
        ))),
    );
    let exchange = handshake(&refusing, &server);
    assert!(!exchange.client.is_handshake_completed());
    assert_alert(
        &exchange.from_client,
        ALERT_BAD_CERTIFICATE,
        "refused certificate",
    );
}

/// RFC 5077 section 3.3: a NewSessionTicket comes only after a ServerHello that announced one,
/// else unexpected_message; RFC 5246 7.4.1.4: a SessionTicket extension the client did not
/// send is unsupported_extension.
#[test]
fn a_ticket_or_its_extension_the_client_did_not_ask_for_is_refused() {
    // A server that sends a ticket it did not announce (on the wire, an announcement taken
    // out of the ServerHello is caught by the Finished checks first): the client's last
    // wait, for the server's ChangeCipherSpec and Finished, finds a NewSessionTicket.
    let store = store();
    let certificate = self_signed();
    let client = client_config(&store, builder());
    let mut state = State::new(provider(), true);
    state.handshake_recv_sequence = 4;
    let mut messages = HandshakeCache::new();
    let ticket = HandshakeMessageNewSessionTicket {
        ticket_lifetime_hint: 60,
        ticket: vec![7; 40],
    };
    let raw = marshal_handshake(HandshakeMessage::NewSessionTicket(ticket), 4).unwrap();
    assert!(messages.push(raw, 0, 4, HandshakeType::NewSessionTicket, false));
    let finished = marshal_handshake(
        HandshakeMessage::Finished(
            crate::handshake::handshake_message_finished::HandshakeMessageFinished {
                verify_data: vec![0; 12],
            },
        ),
        5,
    )
    .unwrap();
    assert!(messages.push(finished, 1, 5, HandshakeType::Finished, false));
    let parsed = crate::flight::Flight::parse(
        &crate::flight::flight5::Flight5 {},
        &mut state,
        &messages,
        &client,
    );
    match parsed {
        Err((Some(alert), Some(_))) => {
            assert_eq!(alert.alert_description, AlertDescription::UnexpectedMessage)
        }
        Err((alert, err)) => panic!("not refused: {alert:?} {err:?}"),
        Ok(next) => panic!("accepted, next {next}"),
    }
    assert!(state.received_ticket.is_none());
    // An announced ticket that is empty (the server issues none after all) is no error, and
    // nothing is kept.
    state.new_session_ticket = true;
    let mut announced = HashMap::new();
    announced.insert(
        HandshakeType::NewSessionTicket,
        HandshakeMessage::NewSessionTicket(HandshakeMessageNewSessionTicket {
            ticket_lifetime_hint: 0,
            ticket: vec![],
        }),
    );
    crate::flight::flight3::take_new_session_ticket(&mut state, &announced).unwrap();
    assert!(state.received_ticket.is_none());
    let server = server_config(Some(&cache()), true, &certificate, builder());

    let plain = Arc::new(
        builder()
            .with_protocol_versions(DtlsVersion::Dtls1_2, DtlsVersion::Dtls1_2)
            .with_insecure_skip_verify(true)
            .build(true, None)
            .unwrap(),
    );
    let exchange = Exchange::run_altering(
        DTLSConn::new(plain, true, None),
        DTLSConn::new(server.clone(), false, None),
        |_| {},
        |datagram| {
            rewrite_server_hello(datagram, |server_hello| {
                server_hello.extensions.push(session_ticket_extension(&[]))
            })
        },
    );
    assert!(!exchange.client.is_handshake_completed());
    assert_alert(
        &exchange.from_client,
        ALERT_UNSUPPORTED_EXTENSION,
        "an unsolicited SessionTicket extension",
    );
}

// ---------------------------------------------------------------------------------------------
// The extended master secret (RFC 7627 section 5.3)
// ---------------------------------------------------------------------------------------------

/// A server's answer to a hand-written ClientHello offering `session_id`, with or without the
/// extended_master_secret extension, after the cookie exchange.
fn answer_to_offer(
    server: &Arc<HandshakeConfig>,
    session_id: &[u8],
    with_ems: bool,
) -> (Result<()>, Vec<Vec<u8>>, DTLSConn) {
    answer_to_offer_with(server, session_id, with_ems, &[])
}

/// [`answer_to_offer`], with `more` extensions (whole, with their headers) in the ClientHello.
fn answer_to_offer_with(
    server: &Arc<HandshakeConfig>,
    session_id: &[u8],
    with_ems: bool,
    more: &[u8],
) -> (Result<()>, Vec<Vec<u8>>, DTLSConn) {
    let now = Instant::now();
    let mut server_conn = DTLSConn::new(server.clone(), false, None);
    server_conn.handshake(now).unwrap();
    let body = |cookie: &[u8]| {
        let mut extensions = usual_client_extensions();
        extensions.extend_from_slice(&server_name_extension());
        if with_ems {
            extensions.extend_from_slice(&EXT_EXTENDED_MASTER_SECRET.to_be_bytes());
            extensions.extend_from_slice(&[0, 0]);
        }
        extensions.extend_from_slice(more);
        client_hello_body(session_id, cookie, &[ECDSA_GCM], Some(&extensions))
    };
    feed(&mut server_conn, now, &client_hello_datagram(0, &body(&[]))).unwrap();
    let hello_verify_request = last_body(&drain(&mut server_conn), HELLO_VERIFY_REQUEST).unwrap();
    let cookie = hello_verify_request[3..3 + hello_verify_request[2] as usize].to_vec();
    let result = feed(
        &mut server_conn,
        now,
        &client_hello_datagram(1, &body(&cookie)),
    );
    (result, drain(&mut server_conn), server_conn)
}

/// RFC 7627 section 5.3, server: a session made with the extended master secret offered in a
/// ClientHello without the extension is aborted (MUST); a session made without it is not
/// resumed by a ClientHello with the extension (MUST NOT: a full handshake instead) and
/// aborted by one without (SHOULD); a resumption with the extension puts it in the ServerHello
/// (MUST).
#[test]
fn the_server_applies_the_extended_master_secret_rules_to_a_resumption() {
    let certificate = self_signed();
    let (store, cache) = (store(), cache());
    let server = server_config(Some(&cache), false, &certificate, builder());
    assert!(handshake(&client_config(&store, builder()), &server).completed());
    let session = stored(&store);
    assert!(session.extended_master_secret);

    // The session used it, the ClientHello does not offer it: aborted.
    let (result, answer, _) = answer_to_offer(&server, &session.session_id, false);
    assert!(result.is_err());
    assert_alert(
        &answer,
        ALERT_HANDSHAKE_FAILURE,
        "EMS session, no EMS in the hello",
    );

    // Both: resumed, with the extension in the ServerHello.
    let (result, answer, conn) = answer_to_offer(&server, &session.session_id, true);
    result.unwrap();
    assert!(conn.connection_state().resumed);
    let server_hello = last_body(&answer, SERVER_HELLO).unwrap();
    assert_eq!(hello_session_id(&server_hello), session.session_id);
    assert!(
        server_hello_extensions(&server_hello)
            .iter()
            .any(|(typ, _)| *typ == EXT_EXTENDED_MASTER_SECRET)
    );

    // A session made without it (from elsewhere: this crate makes none).
    let mut legacy = session.clone();
    legacy.session_id = vec![0x17; SESSION_ID_LENGTH];
    legacy.extended_master_secret = false;
    cache.put(legacy.clone());
    let (result, answer, conn) = answer_to_offer(&server, &legacy.session_id, true);
    result.unwrap();
    assert!(
        !conn.connection_state().resumed,
        "not resumed with the extension"
    );
    assert!(types(&answer).contains(&CERTIFICATE), "a full handshake");
    let (result, answer, _) = answer_to_offer(&server, &legacy.session_id, false);
    assert!(result.is_err());
    assert_alert(&answer, ALERT_HANDSHAKE_FAILURE, "neither");
}

/// RFC 7627 section 5.3, client: it does not offer a session made without the extended
/// master secret (SHOULD NOT), offers one only with the extension in its ClientHello (MUST:
/// a client that may not send it offers none), and aborts a resumption whose ServerHello has
/// the extension other than the session had it (MUST, both ways).
#[test]
fn the_client_applies_the_extended_master_secret_rules_to_a_resumption() {
    let certificate = self_signed();
    let (store, cache) = (store(), cache());
    let server = server_config(Some(&cache), false, &certificate, builder());
    assert!(handshake(&client_config(&store, builder()), &server).completed());
    let session = store.take_dtls12(NAME).unwrap();

    // Not offered: a session without it, and any session by a client that does not send it.
    let mut legacy = session.clone();
    legacy.extended_master_secret = false;
    store.put_dtls12(NAME, legacy);
    let exchange = handshake(&client_config(&store, builder()), &server);
    let client_hello = last_body(&exchange.from_client, CLIENT_HELLO).unwrap();
    assert!(
        hello_session_id(&client_hello).is_empty(),
        "a session without the EMS"
    );
    while store.take_dtls12(NAME).is_some() {}
    store.put_dtls12(NAME, session.clone());
    let no_ems = client_config(
        &store,
        builder().with_extended_master_secret(ExtendedMasterSecretType::Disable),
    );
    let exchange = handshake(&no_ems, &server);
    let client_hello = last_body(&exchange.from_client, CLIENT_HELLO).unwrap();
    assert!(
        hello_session_id(&client_hello).is_empty(),
        "a client without the EMS"
    );
    assert!(
        !client_hello_extensions(&client_hello)
            .iter()
            .any(|(typ, _)| *typ == EXT_SESSION_TICKET)
    );
    assert_eq!(store.len_dtls12(NAME), 1, "the session stays");

    // The session used it; the ServerHello that resumes it does not have it.
    let exchange = Exchange::run_altering(
        DTLSConn::new(client_config(&store, builder()), true, None),
        DTLSConn::new(server.clone(), false, None),
        |_| {},
        |datagram| {
            rewrite_server_hello(datagram, |server_hello| {
                server_hello
                    .extensions
                    .retain(|extension| !matches!(extension, Extension::UseExtendedMasterSecret(_)))
            })
        },
    );
    assert!(!exchange.client.is_handshake_completed());
    assert_alert(
        &exchange.from_client,
        ALERT_HANDSHAKE_FAILURE,
        "EMS dropped",
    );

    // The session did not use it; the ServerHello has it. (This client offers no such
    // session, so the rule is driven directly.)
    let cfg = client_config(&store, builder());
    let mut state = State::new(provider(), true);
    let mut legacy = session;
    legacy.extended_master_secret = false;
    state.dtls12_offer = Some(legacy.clone());
    state.cipher_suite = Some(cipher_suite_for_id(legacy.cipher_suite).unwrap());
    state.extended_master_secret = true;
    match client_resume(&mut state, &cfg) {
        Err((Some(alert), Some(_))) => {
            assert_eq!(alert.alert_description, AlertDescription::HandshakeFailure)
        }
        other => panic!("not refused: {:?}", other.err()),
    }
}

// ---------------------------------------------------------------------------------------------
// A failed connection's session is not resumed (RFC 5246 7.2, 7.2.2)
// ---------------------------------------------------------------------------------------------

/// RFC 5246 7.2: "the session identifier of a failed connection is invalidated"; 7.2.2: a
/// connection ended by a fatal alert is not resumed. The server forgets the session in its
/// cache and retires the ticket it issued; the client forgets the session it stored.
#[test]
fn the_session_of_a_connection_ended_by_a_fatal_alert_is_not_resumed() {
    let certificate = self_signed();
    for tickets in [false, true] {
        let (store, cache) = (store(), cache());
        let client = client_config(&store, builder());
        let server = server_config(
            (!tickets).then_some(&cache),
            tickets,
            &certificate,
            builder(),
        );
        let mut exchange = handshake(&client, &server);
        assert!(exchange.completed());
        let session = stored(&store);

        // The client ends the association with a fatal alert, and the server receives it.
        exchange
            .client
            .notify(AlertLevel::Fatal, AlertDescription::InternalError);
        assert_eq!(
            store.len_dtls12(NAME),
            0,
            "tickets {tickets}: the client forgets it"
        );
        let now = Instant::now();
        for datagram in drain(&mut exchange.client) {
            let _ = feed(&mut exchange.server, now, &datagram);
        }
        assert!(
            exchange.server.failed,
            "tickets {tickets}: the server got the alert"
        );
        assert_eq!(cache.len(), 0, "tickets {tickets}: the server forgets it");

        // Offered again all the same: a full handshake.
        store.put_dtls12(NAME, session);
        let exchange = handshake(&client, &server);
        assert!(exchange.completed());
        assert!(
            !exchange.server.connection_state().resumed(),
            "tickets {tickets}: not resumed"
        );
    }
}

// ---------------------------------------------------------------------------------------------
// The last flight (RFC 6347 4.2.4)
// ---------------------------------------------------------------------------------------------

/// RFC 6347 4.2.4: in a resumed handshake the client sends the last flight. When it is lost
/// the server sends its flight again on its timer, and the client, which has completed,
/// answers with its last flight again; the server then completes. Through two endpoints, with
/// the stateless cookie exchange.
#[test]
fn a_lost_last_flight_of_a_resumption_is_sent_again() -> Result<()> {
    use crate::dtls13::handshake_test::{Pair, client_addr, take};
    let certificate = self_signed();
    let (store, cache) = (store(), cache());
    let client = client_config(&store, builder());
    let server = server_config(Some(&cache), false, &certificate, builder());
    Pair::with(client.clone(), server.clone())?.complete();

    let mut pair = Pair::with(client, server)?;
    // ClientHello, HelloVerifyRequest, ClientHello, the server's flight.
    pair.round();
    pair.round();
    assert!(
        pair.client_complete,
        "the client completes on the server's Finished"
    );
    let lost = take(&mut pair.client);
    assert!(!lost.is_empty(), "the client's last flight");
    assert!(!pair.server_complete);

    let wake = pair
        .server
        .poll_timeout(&client_addr())
        .expect("the server's timer");
    pair.now = wake;
    pair.server.handle_timeout(client_addr(), wake)?;
    let again = take(&mut pair.server);
    assert!(!again.is_empty(), "the server's flight again");
    pair.deliver_to_client(again);
    let answer = take(&mut pair.client);
    assert!(!answer.is_empty(), "the client's last flight again");
    pair.deliver_to_server(answer);
    assert!(pair.server_complete);
    assert!(
        pair.server
            .get_connection_state(client_addr())
            .is_some_and(|state| state.resumed())
    );
    Ok(())
}

/// A configured peer-certificate check that answers as the flag says, counting its calls.
fn flagged_check() -> (
    Arc<std::sync::atomic::AtomicBool>,
    Arc<std::sync::atomic::AtomicUsize>,
    crate::config::VerifyPeerCertificateFn,
) {
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    let refuse = Arc::new(AtomicBool::new(false));
    let calls = Arc::new(AtomicUsize::new(0));
    let (refuse_in, calls_in) = (refuse.clone(), calls.clone());
    let check: crate::config::VerifyPeerCertificateFn = Arc::new(
        move |chain: &[Vec<u8>], _: &[rustls::pki_types::CertificateDer<'static>]| {
            calls_in.fetch_add(1, Ordering::SeqCst);
            assert!(!chain.is_empty(), "the check is given a chain");
            if refuse_in.load(Ordering::SeqCst) {
                Err(Error::Other("no longer trusted".to_owned()))
            } else {
                Ok(())
            }
        },
    );
    (refuse, calls, check)
}

/// The server side of the re-check (RFC 5246 section 7.3: the session carries the client's
/// certificate; RFC 5764 section 3 in WebRTC: on a resumed handshake the DTLS server's only
/// check of the client is this one): the server's configured peer-certificate check runs
/// again on the client certificate of the cached session before it resumes it; refused, the
/// handshake ends with bad_certificate.
#[test]
fn the_server_runs_its_peer_certificate_check_again_on_a_resumed_client() {
    use std::sync::atomic::Ordering;
    let certificate = self_signed();
    let (store, cache) = (store(), cache());
    let client = client_config(&store, builder().with_certificates(vec![self_signed()]));
    let (refuse, calls, check) = flagged_check();
    let server = server_config(
        Some(&cache),
        false,
        &certificate,
        builder()
            .with_client_auth(crate::config::ClientAuthType::RequireAnyClientCert)
            .with_verify_peer_certificate(Some(check)),
    );
    let first = handshake(&client, &server);
    assert!(
        first.completed(),
        "{:?} {:?}",
        first.client_err,
        first.server_err
    );
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "the full handshake's check"
    );
    let second = handshake(&client, &server);
    assert!(second.completed());
    assert!(second.server.connection_state().resumed());
    assert_eq!(
        calls.load(Ordering::SeqCst),
        2,
        "run again on the resumption"
    );

    refuse.store(true, Ordering::SeqCst);
    let third = handshake(&client, &server);
    assert_eq!(calls.load(Ordering::SeqCst), 3);
    assert!(
        !third.server.is_handshake_completed(),
        "the resumption is refused"
    );
    assert!(!third.client.is_handshake_completed());
    assert!(!third.server.connection_state().resumed());
    assert_alert(
        &third.from_server,
        ALERT_BAD_CERTIFICATE,
        "the server's re-check refused the client",
    );
}

/// A server that asks its clients for a certificate and has a configured peer-certificate
/// check resumes no session that carries no client certificate: the check could not run
/// again, so the handshake is a full one, in which the server asks again.
#[test]
fn a_server_that_asks_for_a_certificate_resumes_no_session_without_one_for_its_check() {
    use crate::config::ClientAuthType;
    use std::sync::atomic::Ordering;
    let certificate = self_signed();
    let (store, cache) = (store(), cache());
    let client = client_config(&store, builder());
    let (_, calls, check) = flagged_check();
    let checking = server_config(
        Some(&cache),
        false,
        &certificate,
        builder()
            .with_client_auth(ClientAuthType::RequestClientCert)
            .with_verify_peer_certificate(Some(check)),
    );
    assert!(handshake(&client, &checking).completed());
    assert_eq!(cache.len(), 1, "a session without a client certificate");
    let exchange = handshake(&client, &checking);
    assert!(exchange.completed());
    assert!(!exchange.server.connection_state().resumed(), "a full one");
    assert!(types(&exchange.from_server).contains(&CERTIFICATE));
    assert_eq!(calls.load(Ordering::SeqCst), 0);

    // Without a check, the same kind of session resumes.
    let open = server_config(
        Some(&cache),
        false,
        &certificate,
        builder().with_client_auth(ClientAuthType::RequestClientCert),
    );
    assert!(handshake(&client, &open).completed());
    assert!(
        handshake(&client, &open)
            .server
            .connection_state()
            .resumed()
    );
}

/// A server that asks its clients for no certificate (`NoClientCert`, the default) resumes
/// its sessions whether or not a peer-certificate check is configured: the full handshake
/// had no client certificate for the check either, so there is nothing to check again. The
/// check is not called (`flagged_check` refuses an empty chain).
#[test]
fn a_server_that_asks_for_no_certificate_resumes_with_a_check_configured() {
    use std::sync::atomic::Ordering;
    let certificate = self_signed();
    let (store, cache) = (store(), cache());
    let client = client_config(&store, builder());
    let (_, calls, check) = flagged_check();
    let checking = server_config(
        Some(&cache),
        false,
        &certificate,
        builder().with_verify_peer_certificate(Some(check)),
    );
    assert!(handshake(&client, &checking).completed());
    assert_eq!(cache.len(), 1, "a session without a client certificate");
    let exchange = handshake(&client, &checking);
    assert!(exchange.completed());
    assert!(exchange.server.connection_state().resumed(), "resumed");
    assert!(!types(&exchange.from_server).contains(&CERTIFICATE));
    assert_eq!(
        calls.load(Ordering::SeqCst),
        0,
        "no client certificate, ever: nothing for the check"
    );
}

/// A store that keeps DTLS 1.2 sessions without the certificates of their full handshake.
struct WithoutCertificates(MemorySessionStore);

impl SessionStore for WithoutCertificates {
    fn put(&self, server_name: &str, session: crate::session::Tls13Session) {
        self.0.put(server_name, session);
    }

    fn take(&self, server_name: &str) -> Option<crate::session::Tls13Session> {
        self.0.take(server_name)
    }

    fn put_dtls12(&self, server_name: &str, mut session: Dtls12Session) {
        session.peer_certificates.clear();
        self.0.put_dtls12(server_name, session);
    }

    fn take_dtls12(&self, server_name: &str) -> Option<Dtls12Session> {
        self.0.take_dtls12(server_name)
    }

    fn forget_dtls12(&self, server_name: &str, session_id: &[u8]) {
        self.0.forget_dtls12(server_name, session_id);
    }
}

/// A client with a configured peer-certificate check does not take a resumed session that
/// carries no certificate as checked: the handshake fails with bad_certificate (it fails
/// closed).
#[test]
fn a_client_with_a_check_refuses_a_resumption_that_carries_no_certificate() {
    use std::sync::atomic::Ordering;
    let certificate = self_signed();
    let cache = cache();
    let store = Arc::new(WithoutCertificates(MemorySessionStore::new()));
    let (_, calls, check) = flagged_check();
    let client = Arc::new(
        builder()
            .with_protocol_versions(DtlsVersion::Dtls1_2, DtlsVersion::Dtls1_2)
            .with_insecure_skip_verify(true)
            .with_server_name(NAME.to_owned())
            .with_session_store(Some(store.clone() as Arc<dyn SessionStore>))
            .with_verify_peer_certificate(Some(check))
            .build(true, None)
            .expect("a client configuration"),
    );
    let server = server_config(Some(&cache), false, &certificate, builder());
    assert!(handshake(&client, &server).completed());
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(store.0.len_dtls12(NAME), 1, "kept without certificates");
    let exchange = handshake(&client, &server);
    assert!(!exchange.client.is_handshake_completed(), "refused");
    assert_eq!(calls.load(Ordering::SeqCst), 1, "nothing was checked");
    assert_eq!(alert_of(&exchange.client), Some(ALERT_BAD_CERTIFICATE));
}

/// `ConfigBuilder::with_dtls12_resumption(false)`: DTLS 1.2 takes no part in resumption,
/// whatever store, cache or tickets are configured. The client asks for no ticket and
/// offers no session id; the server gives no session id and no ticket and resumes no
/// session it would otherwise resume.
#[test]
fn without_dtls12_resumption_nothing_is_asked_for_given_or_resumed() {
    let certificate = self_signed();
    let (store, cache) = (store(), cache());
    let off = |builder: ConfigBuilder| builder.with_dtls12_resumption(false);
    let client = client_config(&store, off(builder()));
    let server = server_config(Some(&cache), true, &certificate, off(builder()));
    for round in 0..2 {
        let exchange = handshake(&client, &server);
        assert!(exchange.completed(), "round {round}");
        assert!(
            !exchange.server.connection_state().resumed(),
            "round {round}"
        );
        let client_hello = last_body(&exchange.from_client, CLIENT_HELLO).unwrap();
        assert!(hello_session_id(&client_hello).is_empty(), "round {round}");
        assert!(
            !client_hello_extensions(&client_hello)
                .iter()
                .any(|(kind, _)| *kind == EXT_SESSION_TICKET),
            "round {round}: no ticket asked for"
        );
        let server_hello = last_body(&exchange.from_server, SERVER_HELLO).unwrap();
        assert!(hello_session_id(&server_hello).is_empty(), "round {round}");
        assert!(!types(&exchange.from_server).contains(&NEW_SESSION_TICKET));
    }
    assert_eq!(store.len_dtls12(NAME), 0);
    assert_eq!(cache.len(), 0);

    // A resuming server and client of their own: each still resumes, and resumes with
    // neither side switched off.
    let resuming_server = server_config(Some(&cache), true, &certificate, builder());
    let resuming_client = client_config(&store, builder());
    assert!(handshake(&resuming_client, &resuming_server).completed());
    assert!(
        handshake(&resuming_client, &resuming_server)
            .server
            .connection_state()
            .resumed()
    );
    // A session the client holds is not offered by a client with it off, nor resumed by a
    // server with it off.
    assert!(store.len_dtls12(NAME) > 0);
    let exchange = handshake(&client, &resuming_server);
    assert!(!exchange.server.connection_state().resumed());
    let exchange = handshake(&resuming_client, &server);
    assert!(exchange.completed());
    assert!(!exchange.server.connection_state().resumed());
}
