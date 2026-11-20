//! Endpoint-level tests for how an association ends, and for what an unauthenticated peer can
//! make a handshake do. The helpers repeat the ones in `endpoint.rs`'s own test module, which
//! are private to it.

use super::*;
use crate::cipher_suite::CipherSuiteId;
use crate::config::ConfigBuilder;
use crate::crypto::Certificate;
use crypto::RTCCryptoProvider;

fn client_addr() -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], 5444))
}

fn server_addr() -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], 5445))
}

fn provider() -> Arc<dyn RTCCryptoProvider> {
    crypto::default_provider().expect("a built-in crypto provider is enabled for tests")
}

const SUITE: CipherSuiteId = CipherSuiteId::Tls_Ecdhe_Ecdsa_With_Aes_128_Gcm_Sha256;

fn client_builder() -> ConfigBuilder {
    ConfigBuilder::default()
        .with_crypto_provider(provider())
        .with_cipher_suites(vec![SUITE])
        .with_insecure_skip_verify(true)
}

fn client_config() -> Result<Arc<HandshakeConfig>> {
    Ok(Arc::new(client_builder().build(true, None)?))
}

fn server_config() -> Result<Arc<HandshakeConfig>> {
    let provider = provider();
    Ok(Arc::new(
        ConfigBuilder::default()
            .with_crypto_provider(provider.clone())
            .with_cipher_suites(vec![SUITE])
            .with_insecure_skip_verify(true)
            .with_certificates(vec![Certificate::generate_self_signed(
                vec!["localhost".to_owned()],
                provider.crypto(),
            )?])
            .build(false, None)?,
    ))
}

/// Takes every datagram `endpoint` has queued.
fn take_transmits(endpoint: &mut Endpoint) -> Vec<BytesMut> {
    let mut datagrams = vec![];
    while let Some(transmit) = endpoint.poll_transmit() {
        datagrams.push(transmit.message);
    }
    datagrams
}

/// Hands `datagrams` to `destination` as coming from `source_addr`, collecting the events and
/// whether any read failed.
fn deliver(
    destination: &mut Endpoint,
    source_addr: SocketAddr,
    datagrams: Vec<BytesMut>,
    now: Instant,
) -> (Vec<EndpointEvent>, bool) {
    let mut events = vec![];
    let mut errored = false;
    for datagram in datagrams {
        match destination.read(now, source_addr, None, datagram) {
            Ok(more) => events.extend(more),
            Err(_) => errored = true,
        }
    }
    (events, errored)
}

/// Runs a handshake between `client` (already connected) and `server` to completion, failing the
/// test if it does not complete.
fn complete_handshake(client: &mut Endpoint, server: &mut Endpoint, now: Instant) {
    let mut client_complete = false;
    let mut server_complete = false;
    for _ in 0..32 {
        let to_server = take_transmits(client);
        let (events, _) = deliver(server, client_addr(), to_server, now);
        server_complete |= events
            .iter()
            .any(|event| matches!(event, EndpointEvent::HandshakeComplete));
        let to_client = take_transmits(server);
        let (events, _) = deliver(client, server_addr(), to_client, now);
        client_complete |= events
            .iter()
            .any(|event| matches!(event, EndpointEvent::HandshakeComplete));
        if client_complete && server_complete {
            return;
        }
    }
    panic!("the handshake did not complete (client: {client_complete}, server: {server_complete})");
}

/// The content type of every record in `datagram`.
fn record_content_types(datagram: &[u8]) -> Vec<u8> {
    crate::record_layer::unpack_datagram(datagram)
        .expect("a datagram splits into records")
        .into_iter()
        .map(|record| record[0])
        .collect()
}

const ALERT: u8 = 21;
const HANDSHAKE: u8 = 22;

// ---------------------------------------------------------------------------------------------
// The association fails on a fatal alert or a handshake that gives up, and only then
// (W3C webrtc 5.5.1 RTCDtlsTransport "failed", RFC 5246 7.2.2).
// ---------------------------------------------------------------------------------------------

/// A client that rejects the server's certificate (as a WebRTC fingerprint mismatch does) sends a
/// fatal alert and fails; the server, receiving it, fails too.
#[test]
fn a_rejected_certificate_fails_both_associations() -> Result<()> {
    let now = Instant::now();
    let reject: crate::config::VerifyPeerCertificateFn = Arc::new(
        |_certs: &[Vec<u8>], _chains: &[rustls::pki_types::CertificateDer<'static>]| {
            Err(Error::ErrNoMatchingCertificateFingerprint)
        },
    );
    let client_config = Arc::new(
        client_builder()
            .with_verify_peer_certificate(Some(reject))
            .build(true, None)?,
    );
    let mut client = Endpoint::new(client_addr(), TransportProtocol::UDP, None);
    let mut server = Endpoint::new(
        server_addr(),
        TransportProtocol::UDP,
        Some(server_config()?),
    );
    client.connect(now, server_addr(), client_config, None)?;

    let mut client_failed = false;
    let mut server_failed = false;
    let mut client_sent_alert = false;
    for _ in 0..16 {
        let to_server = take_transmits(&mut client);
        client_sent_alert |= client_failed
            && to_server
                .iter()
                .any(|datagram| record_content_types(datagram).contains(&ALERT));
        for datagram in to_server {
            let _ = server.read(now, client_addr(), None, datagram);
            server_failed |= server.is_connection_failed(&client_addr());
        }
        let to_client = take_transmits(&mut server);
        for datagram in to_client {
            let _ = client.read(now, server_addr(), None, datagram);
            client_failed |= client.is_connection_failed(&server_addr());
        }
        if client_failed && server_failed {
            break;
        }
    }
    assert!(
        client_failed,
        "the client that rejected the certificate failed"
    );
    assert!(
        client_sent_alert,
        "the client told the server with a fatal alert"
    );
    assert!(
        server_failed,
        "the server that received the fatal alert failed"
    );
    assert_eq!(
        client.poll_timeout(&server_addr()),
        None,
        "a failed association retransmits nothing"
    );
    assert!(
        client
            .write(now, server_addr(), b"after the failure")
            .is_err(),
        "a failed association carries no data"
    );
    Ok(())
}

/// A lost flight is retransmitted, and the handshake completes without failing.
#[test]
fn an_ordinary_retransmission_does_not_fail_the_association() -> Result<()> {
    let now = Instant::now();
    let mut client = Endpoint::new(client_addr(), TransportProtocol::UDP, None);
    let mut server = Endpoint::new(
        server_addr(),
        TransportProtocol::UDP,
        Some(server_config()?),
    );
    client.connect(now, server_addr(), client_config()?, None)?;

    // Lose the first ClientHello; the client's timer fires and it sends it again.
    assert!(!take_transmits(&mut client).is_empty());
    let deadline = client
        .poll_timeout(&server_addr())
        .expect("a client waiting for an answer arms its retransmit timer");
    client.handle_timeout(server_addr(), deadline)?;
    assert!(
        !client.is_connection_failed(&server_addr()),
        "a retransmission is not a failure"
    );

    complete_handshake(&mut client, &mut server, deadline);
    assert!(!client.is_connection_failed(&server_addr()));
    assert!(!server.is_connection_failed(&client_addr()));
    Ok(())
}

/// A handshake whose peer never answers gives up once its retransmissions run out, and only then.
#[test]
fn a_handshake_whose_retransmissions_run_out_fails() -> Result<()> {
    let mut now = Instant::now();
    let mut client = Endpoint::new(client_addr(), TransportProtocol::UDP, None);
    client.connect(now, server_addr(), client_config()?, None)?;
    let retries = client.connections[&server_addr()].maximum_retransmit_number;
    take_transmits(&mut client);

    for retry in 0..retries {
        now = client
            .poll_timeout(&server_addr())
            .expect("the retransmit timer stays armed while retries remain");
        client.handle_timeout(server_addr(), now)?;
        assert!(
            !take_transmits(&mut client).is_empty(),
            "retry {retry} retransmits the flight"
        );
        assert!(
            !client.is_connection_failed(&server_addr()),
            "retry {retry} is an ordinary retransmission, not a failure"
        );
    }

    now = client
        .poll_timeout(&server_addr())
        .expect("the last retransmission arms the timer once more");
    assert!(
        client.handle_timeout(server_addr(), now).is_err(),
        "the handshake gives up once its retransmissions run out"
    );
    assert!(client.is_connection_failed(&server_addr()));
    assert_eq!(client.poll_timeout(&server_addr()), None);
    Ok(())
}

/// A record that is silently discarded (here an undecodable one) fails nothing.
#[test]
fn a_discarded_record_does_not_fail_the_association() -> Result<()> {
    let now = Instant::now();
    let mut client = Endpoint::new(client_addr(), TransportProtocol::UDP, None);
    let mut server = Endpoint::new(
        server_addr(),
        TransportProtocol::UDP,
        Some(server_config()?),
    );
    client.connect(now, server_addr(), client_config()?, None)?;

    // Thirteen bytes that do not form a record header the server can use.
    let _ = server.read(now, client_addr(), None, BytesMut::from(&[0xffu8; 13][..]));
    assert!(!server.is_connection_failed(&client_addr()));

    complete_handshake(&mut client, &mut server, now);
    assert!(!server.is_connection_failed(&client_addr()));
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// RFC 6347 4.2.4: a peer that repeats a flight we already processed gets our answer again at
// once, not when our timer fires.
// ---------------------------------------------------------------------------------------------

/// Runs flights 1 to 3, then loses the server's Flight 4. Returns the client's repeat of
/// Flight 3, sent when its own timer fired.
fn lose_flight_four(client: &mut Endpoint, server: &mut Endpoint, now: Instant) -> Vec<BytesMut> {
    let flight1 = take_transmits(client);
    deliver(server, client_addr(), flight1, now);
    let flight2 = take_transmits(server);
    deliver(client, server_addr(), flight2, now);
    let flight3 = take_transmits(client);
    assert!(!flight3.is_empty(), "the client sends Flight 3");
    deliver(server, client_addr(), flight3, now);
    let flight4 = take_transmits(server);
    assert!(
        !flight4.is_empty(),
        "the server answers with Flight 4, which is lost"
    );
    assert!(
        server.poll_timeout(&client_addr()).is_some(),
        "the server waits for Flight 5 with its timer armed"
    );

    let client_timer = client
        .poll_timeout(&server_addr())
        .expect("the client waits for Flight 4 with its timer armed");
    client
        .handle_timeout(server_addr(), client_timer)
        .expect("the client retransmits Flight 3");
    let repeat = take_transmits(client);
    assert!(!repeat.is_empty(), "the client repeats Flight 3");
    repeat
}

/// The server, which already processed Flight 3, answers its repeat with Flight 4 at once,
/// before its own timer fires.
#[test]
fn a_repeated_flight_is_answered_at_once() -> Result<()> {
    let now = Instant::now();
    let mut client = Endpoint::new(client_addr(), TransportProtocol::UDP, None);
    let mut server = Endpoint::new(
        server_addr(),
        TransportProtocol::UDP,
        Some(server_config()?),
    );
    client.connect(now, server_addr(), client_config()?, None)?;
    let repeat = lose_flight_four(&mut client, &mut server, now);

    // Delivered before the server's own timer fires.
    let (_, errored) = deliver(&mut server, client_addr(), repeat, now);
    assert!(!errored);
    let answer = take_transmits(&mut server);
    assert!(
        !answer.is_empty(),
        "the server retransmits Flight 4 as soon as the client repeats Flight 3"
    );
    assert!(
        answer.iter().all(|datagram| record_content_types(datagram)
            .iter()
            .all(|content_type| *content_type == HANDSHAKE)),
        "the answer is the handshake flight"
    );
    assert_eq!(
        server.connections[&client_addr()].current_retransmit_count,
        1,
        "the immediate retransmission comes out of the retransmission budget"
    );
    assert!(!server.is_connection_failed(&client_addr()));

    // The client completes from the retransmitted flight.
    deliver(&mut client, server_addr(), answer, now);
    complete_handshake(&mut client, &mut server, now);
    Ok(())
}

/// A different message under a sequence number already processed is not a repeat: it provokes
/// no retransmission.
#[test]
fn a_changed_message_under_an_old_sequence_number_is_not_a_repeat() -> Result<()> {
    let now = Instant::now();
    let mut client = Endpoint::new(client_addr(), TransportProtocol::UDP, None);
    let mut server = Endpoint::new(
        server_addr(),
        TransportProtocol::UDP,
        Some(server_config()?),
    );
    client.connect(now, server_addr(), client_config()?, None)?;
    let mut repeat = lose_flight_four(&mut client, &mut server, now);

    // Change one byte of the ClientHello's random: record header (13), handshake header (12),
    // client version (2), then the random.
    let datagram = repeat.first_mut().expect("the repeat has a datagram");
    datagram[13 + 12 + 2 + 5] ^= 0xff;
    deliver(&mut server, client_addr(), repeat, now);
    assert!(
        take_transmits(&mut server).is_empty(),
        "a changed message is not answered"
    );
    assert_eq!(
        server.connections[&client_addr()].current_retransmit_count,
        0
    );
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// Received alerts are never echoed; a received fatal alert ends the association
// (RFC 5246 7.2, 7.2.2).
// ---------------------------------------------------------------------------------------------

/// A plaintext (epoch 0) alert record, as anyone who can spoof the peer's address can send.
fn plaintext_alert(level: u8, description: u8, sequence_number: u64) -> BytesMut {
    use crate::content::ContentType;
    use crate::record_layer::record_layer_header::{PROTOCOL_VERSION1_2, RecordLayerHeader};

    let header = RecordLayerHeader {
        content_type: ContentType::Alert,
        protocol_version: PROTOCOL_VERSION1_2,
        epoch: 0,
        sequence_number,
        content_len: 2,
    };
    let mut raw = vec![];
    header.marshal(&mut raw).expect("a record header marshals");
    raw.extend_from_slice(&[level, description]);
    BytesMut::from(&raw[..])
}

const WARNING: u8 = 1;
const FATAL: u8 = 2;
const NO_RENEGOTIATION: u8 = 100;
const HANDSHAKE_FAILURE: u8 = 40;

/// A warning alert is not answered and changes nothing: two instances of this stack used to
/// bounce one such alert between them, each echoing the other's.
#[test]
fn a_received_warning_alert_is_neither_echoed_nor_fatal() -> Result<()> {
    let now = Instant::now();
    let mut client = Endpoint::new(client_addr(), TransportProtocol::UDP, None);
    let mut server = Endpoint::new(
        server_addr(),
        TransportProtocol::UDP,
        Some(server_config()?),
    );
    client.connect(now, server_addr(), client_config()?, None)?;
    let flight1 = take_transmits(&mut client);
    deliver(&mut server, client_addr(), flight1, now);
    let flight2 = take_transmits(&mut server);
    deliver(&mut client, server_addr(), flight2, now);

    // Both ends get one, as a spoofer on either side would send.
    let events = server.read(
        now,
        client_addr(),
        None,
        plaintext_alert(WARNING, NO_RENEGOTIATION, 5),
    )?;
    assert!(events.is_empty());
    assert!(
        take_transmits(&mut server).is_empty(),
        "the server answered a warning alert"
    );
    let flight3 = take_transmits(&mut client);
    client.read(
        now,
        server_addr(),
        None,
        plaintext_alert(WARNING, NO_RENEGOTIATION, 5),
    )?;
    assert!(
        take_transmits(&mut client).is_empty(),
        "the client answered a warning alert"
    );
    assert!(!server.is_connection_failed(&client_addr()));
    assert!(!client.is_connection_failed(&server_addr()));

    // The handshake goes on, and no alert crosses in either direction while it does.
    deliver(&mut server, client_addr(), flight3, now);
    for _ in 0..8 {
        let to_client = take_transmits(&mut server);
        assert!(
            to_client
                .iter()
                .all(|datagram| !record_content_types(datagram).contains(&ALERT))
        );
        deliver(&mut client, server_addr(), to_client, now);
        let to_server = take_transmits(&mut client);
        assert!(
            to_server
                .iter()
                .all(|datagram| !record_content_types(datagram).contains(&ALERT))
        );
        deliver(&mut server, client_addr(), to_server, now);
    }
    assert!(client.connections[&server_addr()].is_handshake_completed());
    assert!(server.connections[&client_addr()].is_handshake_completed());
    Ok(())
}

/// A fatal alert ends the association at once and is not answered.
#[test]
fn a_received_fatal_alert_closes_the_association_unanswered() -> Result<()> {
    let now = Instant::now();
    let mut client = Endpoint::new(client_addr(), TransportProtocol::UDP, None);
    let mut server = Endpoint::new(
        server_addr(),
        TransportProtocol::UDP,
        Some(server_config()?),
    );
    client.connect(now, server_addr(), client_config()?, None)?;
    let flight1 = take_transmits(&mut client);
    deliver(&mut server, client_addr(), flight1, now);
    take_transmits(&mut server);

    let result = server.read(
        now,
        client_addr(),
        None,
        plaintext_alert(FATAL, HANDSHAKE_FAILURE, 5),
    );
    assert_eq!(result.err(), Some(Error::ErrAlertFatalOrClose));
    assert!(
        take_transmits(&mut server).is_empty(),
        "a fatal alert is not answered"
    );
    assert!(server.is_connection_failed(&client_addr()));
    assert_eq!(
        server.poll_timeout(&client_addr()),
        None,
        "nothing is retransmitted after a fatal alert"
    );
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// One forged epoch-0 record before the handshake must not stall it (RFC 6347 4.1.2.6, 4.1.2.7).
// ---------------------------------------------------------------------------------------------

/// An epoch-0 handshake record whose body is a well-formed fragment header (type 0xff, an
/// unknown message, so it never parses) over a four-byte payload, at message sequence 0.
fn junk_handshake_datagram(record_sequence: u64) -> BytesMut {
    use crate::content::ContentType;
    use crate::record_layer::record_layer_header::{PROTOCOL_VERSION1_2, RecordLayerHeader};

    let header = RecordLayerHeader {
        content_type: ContentType::Handshake,
        protocol_version: PROTOCOL_VERSION1_2,
        epoch: 0,
        sequence_number: record_sequence,
        content_len: 16,
    };
    let mut raw = vec![];
    header.marshal(&mut raw).expect("a record header marshals");
    raw.extend_from_slice(&[
        0xff, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00,
        0x00,
    ]);
    BytesMut::from(&raw[..])
}

/// A forged record far ahead in the record sequence used to move the replay window past every
/// genuine record, and its unparseable message used to take message sequence 0 for good.
#[test]
fn a_forged_record_before_the_handshake_does_not_stall_it() -> Result<()> {
    let now = Instant::now();
    let mut client = Endpoint::new(client_addr(), TransportProtocol::UDP, None);
    let mut server = Endpoint::new(
        server_addr(),
        TransportProtocol::UDP,
        Some(server_config()?),
    );
    client.connect(now, server_addr(), client_config()?, None)?;

    let _ = server.read(now, client_addr(), None, junk_handshake_datagram(1 << 40));
    assert!(
        take_transmits(&mut server).is_empty(),
        "a forged record is not answered"
    );
    assert!(!server.is_connection_failed(&client_addr()));

    complete_handshake(&mut client, &mut server, now);
    Ok(())
}

/// A forged first fragment of the client's first message, disagreeing with its real length, used
/// to win offset 0 and keep the real ClientHello from ever reassembling.
#[test]
fn a_forged_conflicting_fragment_before_the_handshake_does_not_stall_it() -> Result<()> {
    let now = Instant::now();
    let mut client = Endpoint::new(client_addr(), TransportProtocol::UDP, None);
    let mut server = Endpoint::new(
        server_addr(),
        TransportProtocol::UDP,
        Some(server_config()?),
    );
    client.connect(now, server_addr(), client_config()?, None)?;

    // ClientHello (1), length 1000, message sequence 0, offset 0, ten bytes of it.
    let mut forged = vec![
        HANDSHAKE, 0xfe, 0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, 0x00, 22,
    ];
    forged.extend_from_slice(&[
        0x01, 0x00, 0x03, 0xe8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0a,
    ]);
    forged.extend_from_slice(&[0xee; 10]);
    let _ = server.read(now, client_addr(), None, BytesMut::from(&forged[..]));
    assert!(take_transmits(&mut server).is_empty());

    complete_handshake(&mut client, &mut server, now);
    Ok(())
}

/// An undecodable plaintext record (a one-byte alert) is silently discarded, not answered with a
/// fatal alert that would end the handshake.
#[test]
fn an_undecodable_plaintext_record_is_discarded_not_fatal() -> Result<()> {
    let now = Instant::now();
    let mut client = Endpoint::new(client_addr(), TransportProtocol::UDP, None);
    let mut server = Endpoint::new(
        server_addr(),
        TransportProtocol::UDP,
        Some(server_config()?),
    );
    client.connect(now, server_addr(), client_config()?, None)?;
    let flight1 = take_transmits(&mut client);
    deliver(&mut server, client_addr(), flight1, now);
    let flight2 = take_transmits(&mut server);
    deliver(&mut client, server_addr(), flight2, now);

    let truncated_alert = BytesMut::from(
        &[
            ALERT, 0xfe, 0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x09, 0x00, 0x01, FATAL,
        ][..],
    );
    let _ = server.read(now, client_addr(), None, truncated_alert);
    assert!(
        take_transmits(&mut server).is_empty(),
        "an undecodable plaintext record is not answered"
    );
    assert!(!server.is_connection_failed(&client_addr()));

    complete_handshake(&mut client, &mut server, now);
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// A standalone server does per-association work only for addresses that echoed a cookie
// (RFC 6347 4.2.1).
// ---------------------------------------------------------------------------------------------

fn spoofed_addr(index: usize) -> SocketAddr {
    SocketAddr::from(([10, 0, (index >> 8) as u8, index as u8], 7000))
}

/// One cookieless ClientHello replayed from more source addresses than the cap: the server keeps
/// at most `MAX_UNVERIFIED_ASSOCIATIONS` of them, generates no key pair for any, still answers
/// each with a HelloVerifyRequest, and still completes a genuine client's handshake, which then
/// survives a second flood.
#[test]
fn unverified_source_addresses_are_capped_and_cost_no_key_pair() -> Result<()> {
    let now = Instant::now();
    let mut genuine = Endpoint::new(client_addr(), TransportProtocol::UDP, None);
    let mut server = Endpoint::new(
        server_addr(),
        TransportProtocol::UDP,
        Some(server_config()?),
    );

    let mut prober = Endpoint::new(client_addr(), TransportProtocol::UDP, None);
    prober.connect(now, server_addr(), client_config()?, None)?;
    let client_hello = take_transmits(&mut prober);
    assert!(!client_hello.is_empty());

    let flood = MAX_UNVERIFIED_ASSOCIATIONS + 10;
    for index in 0..flood {
        let (_, errored) = deliver(&mut server, spoofed_addr(index), client_hello.clone(), now);
        assert!(!errored, "a cookieless ClientHello is not an error");
        assert!(
            !take_transmits(&mut server).is_empty(),
            "each one is answered with a HelloVerifyRequest"
        );
    }
    assert!(
        server.connections.len() <= MAX_UNVERIFIED_ASSOCIATIONS,
        "{} associations kept for unverified addresses",
        server.connections.len()
    );
    assert!(
        server
            .connections
            .values()
            .all(|conn| conn.state.local_keypair.is_none()),
        "no key pair is generated before the cookie comes back"
    );

    genuine.connect(now, server_addr(), client_config()?, None)?;
    complete_handshake(&mut genuine, &mut server, now);
    assert!(server.connections[&client_addr()].is_address_verified());

    for index in flood..2 * flood {
        deliver(&mut server, spoofed_addr(index), client_hello.clone(), now);
        take_transmits(&mut server);
    }
    assert!(
        server.connections.contains_key(&client_addr()),
        "a verified association is never displaced by unverified ones"
    );
    assert!(server.connections.len() <= MAX_UNVERIFIED_ASSOCIATIONS + 1);
    Ok(())
}
