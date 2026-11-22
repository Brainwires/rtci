//! DTLS 1.3 0-RTT data (RFC 8446 sections 2.3, 4.2.10 and 8; RFC 9147 sections 5.6 and 6.1):
//! sent with the ClientHello under a ticket that allows it, taken by the server only where
//! it can tell the ClientHello is not a replay (the ticket used once, its age fresh), and
//! never after a HelloRetryRequest.

use super::conn::EPOCH_EARLY;
use super::handshake_test::*;
use super::messages::alert;
use crate::config::HandshakeConfig;
use crate::endpoint::{Endpoint, EndpointEvent};
use crate::session::{MemorySessionStore, SessionStore};
use bytes::BytesMut;
use shared::TransportProtocol;
use shared::error::Result;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

const NAME: &str = "localhost";

fn store() -> Arc<MemorySessionStore> {
    Arc::new(MemorySessionStore::new())
}

fn client(store: &Arc<MemorySessionStore>) -> Result<Arc<HandshakeConfig>> {
    Ok(Arc::new(
        client_builder()
            .with_session_store(Some(store.clone()))
            .build(true, None)?,
    ))
}

/// A server that issues tickets allowing `max` bytes of 0-RTT data, without the cookie
/// exchange (or 0-RTT would never be taken: a HelloRetryRequest rules it out).
fn early_server(max: u32, cookie_exchange: bool) -> Result<Arc<HandshakeConfig>> {
    Ok(Arc::new(
        server_builder()
            .with_session_tickets(1)
            .with_max_early_data(max)
            .with_cookie_exchange(cookie_exchange)
            .build(false, None)?,
    ))
}

/// A pair whose client connects at `now` with `early` as 0-RTT data.
fn early_pair(
    client: Arc<HandshakeConfig>,
    server: Arc<HandshakeConfig>,
    now: Instant,
    early: &[u8],
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
    pair.client
        .connect_with_early_data(now, server_addr(), client, None, early)?;
    Ok(pair)
}

fn early_data(events: &[EndpointEvent]) -> Vec<Vec<u8>> {
    events
        .iter()
        .filter_map(|event| match event {
            EndpointEvent::EarlyData(data) => Some(data.to_vec()),
            _ => None,
        })
        .collect()
}

fn accepted(pair: &Pair) -> (Option<bool>, Option<bool>) {
    (
        pair.client
            .get_connection_state(server_addr())
            .and_then(|state| state.early_data_accepted()),
        pair.server
            .get_connection_state(client_addr())
            .and_then(|state| state.early_data_accepted()),
    )
}

/// RFC 8446 section 2.3: with a ticket that allows it, the client's data goes with its
/// ClientHello, in epoch 1, and the server has it before the handshake is complete. The
/// handshake completes as a resumption; once a record of the client's epoch 3 arrives the
/// server keeps no epoch 1 keys (RFC 9147 section 5.6).
#[test]
fn early_data_arrives_with_the_client_hello() -> Result<()> {
    let store = store();
    let (client, server) = (client(&store)?, early_server(1024, false)?);
    let start = Instant::now();
    let _ = early_pair(client.clone(), server.clone(), start, &[])?.complete();
    assert_eq!(
        store.take(NAME).map(|session| session.max_early_data()),
        Some(1024)
    );
    let _ = early_pair(client.clone(), server.clone(), start, &[])?.complete();

    let mut pair = early_pair(
        client,
        server,
        start + Duration::from_secs(1),
        b"zero round trips",
    )?;
    let first = take(&mut pair.client);
    assert_eq!(first.len(), 2, "the ClientHello, then the 0-RTT record");
    assert_eq!(first[1][0] & 0x03, 1, "epoch 1");
    pair.deliver_to_server(first);
    assert!(!pair.server_complete);
    assert_eq!(early_data(&pair.to_server), [b"zero round trips".to_vec()]);
    assert!(pair.server_conn().has_read_epoch(EPOCH_EARLY));
    let mut pair = pair.complete();
    assert_eq!(accepted(&pair), (Some(true), Some(true)));
    assert!(pair.server_conn().resumed);
    // The client's first records of epoch 3 (its ACK) ended epoch 1.
    assert!(!pair.server_conn().has_read_epoch(EPOCH_EARLY));
    assert_eq!(pair.client_sends(b"1-rtt"), vec![b"1-rtt".to_vec()]);
    assert_eq!(
        early_data(&pair.to_server),
        Vec::<Vec<u8>>::new(),
        "not twice"
    );
    Ok(())
}

/// RFC 8446 section 8.1: the ClientHello and its 0-RTT record, sent again (to this server
/// from another address, or to another server with the same configuration), get no 0-RTT:
/// the ticket has been used.
#[test]
fn a_replayed_client_hello_gets_no_early_data() -> Result<()> {
    let store = store();
    let (client, server) = (client(&store)?, early_server(1024, false)?);
    let now = Instant::now();
    let _ = early_pair(client.clone(), server.clone(), now, &[])?.complete();
    let mut pair = early_pair(client, server.clone(), now, b"transfer 100")?;
    let first = take(&mut pair.client);
    pair.deliver_to_server(first.clone());
    assert_eq!(early_data(&pair.to_server), [b"transfer 100".to_vec()]);

    let attacker: SocketAddr = "127.0.0.1:7777".parse().unwrap();
    let mut replayed = vec![];
    for datagram in first.clone() {
        replayed.extend(pair.server.read(now, attacker, None, datagram)?);
    }
    assert!(early_data(&replayed).is_empty(), "the same server");
    let mut other = Endpoint::new(server_addr(), TransportProtocol::UDP, Some(server));
    let mut replayed = vec![];
    for datagram in first {
        replayed.extend(other.read(now, attacker, None, datagram)?);
    }
    assert!(
        early_data(&replayed).is_empty(),
        "another server of the configuration"
    );
    Ok(())
}

/// RFC 8446 section 4.2.10: a ClientHello after a HelloRetryRequest has no early_data, so
/// with the cookie exchange the 0-RTT data is not taken, and the resumption goes on.
#[test]
fn after_a_hello_retry_request_there_is_no_early_data() -> Result<()> {
    let store = store();
    let (client, server) = (client(&store)?, early_server(1024, true)?);
    let now = Instant::now();
    let _ = early_pair(client.clone(), server.clone(), now, &[])?.complete();
    let mut pair = early_pair(client, server, now, b"too early")?.complete();
    assert!(early_data(&pair.to_server).is_empty());
    assert_eq!(accepted(&pair), (Some(false), None));
    assert!(pair.server_conn().resumed);
    Ok(())
}

/// A ticket that allows no 0-RTT data (the server takes none) is not offered any: the
/// ClientHello goes alone.
#[test]
fn without_max_early_data_none_is_offered() -> Result<()> {
    let store = store();
    let (client, server) = (client(&store)?, early_server(0, false)?);
    let now = Instant::now();
    let _ = early_pair(client.clone(), server.clone(), now, &[])?.complete();
    let mut pair = early_pair(client, server, now, b"nothing")?;
    assert_eq!(take(&mut pair.client).len(), 1);
    Ok(())
}

/// RFC 8446 section 8.3: a ticket age that does not agree with the server's view, by more
/// than the window, rules 0-RTT out; the handshake goes on (section 4.2.10) and resumes.
#[test]
fn a_ticket_age_out_of_the_window_rules_out_early_data() -> Result<()> {
    let store = store();
    let (client, server) = (client(&store)?, early_server(1024, false)?);
    let now = Instant::now();
    let _ = early_pair(client.clone(), server.clone(), now, &[])?.complete();
    let mut session = store.take(NAME).expect("a ticket");
    session.age_add = session.age_add.wrapping_add(20_000);
    store.put(NAME, session);
    let mut pair = early_pair(client, server, now, b"stale")?.complete();
    assert!(early_data(&pair.to_server).is_empty());
    assert_eq!(accepted(&pair), (Some(false), Some(false)));
    assert!(pair.server_conn().resumed);
    Ok(())
}

/// RFC 8446 section 4.6.1: more 0-RTT data than the ticket allows ends the handshake with
/// unexpected_message.
#[test]
fn more_early_data_than_allowed_is_an_unexpected_message() -> Result<()> {
    let store = store();
    let (client, server) = (client(&store)?, early_server(16, false)?);
    let now = Instant::now();
    let _ = early_pair(client.clone(), server.clone(), now, &[])?.complete();
    let mut session = store.take(NAME).expect("a ticket");
    session.max_early_data = 1024;
    store.put(NAME, session);
    let mut pair = early_pair(client, server, now, &[7; 100])?;
    let first = take(&mut pair.client);
    pair.deliver_to_server(first);
    assert!(early_data(&pair.to_server).is_empty());
    assert!(pair.server.is_connection_failed(&client_addr()));
    let _ = alert::UNEXPECTED_MESSAGE;
    Ok(())
}

/// RFC 8446 section 4.2.11: early_data in EncryptedExtensions with a selected_identity
/// other than 0 is an illegal_parameter.
#[test]
fn accepted_early_data_with_another_identity_is_an_illegal_parameter() -> Result<()> {
    let store = store();
    let (client, server) = (client(&store)?, early_server(1024, false)?);
    let now = Instant::now();
    let _ = early_pair(client.clone(), server.clone(), now, &[])?.complete();
    let mut pair = early_pair(client, server, now, b"x")?;
    let first = take(&mut pair.client);
    pair.deliver_to_server(first);
    let flight = take(&mut pair.server);
    // The ServerHello alone first, then the client is made to believe it selected another.
    let split = 13 + u16::from_be_bytes([flight[0][11], flight[0][12]]) as usize;
    pair.deliver_to_client(vec![BytesMut::from(&flight[0][..split])]);
    pair.client_conn().psk_index = Some(1);
    pair.deliver_to_client(vec![BytesMut::from(&flight[0][split..])]);
    assert!(pair.client.is_connection_failed(&server_addr()));
    assert!(!pair.client_complete);
    Ok(())
}

/// RFC 8446 section 4.2.10: 0-RTT is taken only with the cipher suite of the handshake that
/// made the ticket. A client that now prefers another suite of the same hash resumes, without
/// 0-RTT.
#[test]
fn early_data_needs_the_suite_of_the_ticket() -> Result<()> {
    use crate::cipher_suite::CipherSuiteId;
    let store = store();
    let server = early_server(1024, false)?;
    let now = Instant::now();
    let _ = early_pair(client(&store)?, server.clone(), now, &[])?.complete();
    let chacha_first = Arc::new(
        client_builder()
            .with_session_store(Some(store.clone()))
            .with_cipher_suites(vec![
                CipherSuiteId::Tls_ChaCha20_Poly1305_Sha256,
                CipherSuiteId::Tls_Aes_128_Gcm_Sha256,
            ])
            .build(true, None)?,
    );
    let mut pair = early_pair(chacha_first, server, now, b"other suite")?.complete();
    assert_eq!(
        pair.server_conn().suite.map(|suite| suite.id),
        Some(CipherSuiteId::Tls_ChaCha20_Poly1305_Sha256)
    );
    assert!(pair.server_conn().resumed);
    assert!(early_data(&pair.to_server).is_empty());
    assert_eq!(accepted(&pair), (Some(false), Some(false)));
    Ok(())
}
