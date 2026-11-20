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
