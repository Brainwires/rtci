//! RFC 9147 SHOULD clauses about the record layer and the handshake's retransmission: what
//! the layer above learns of the record expansion (4.4), smaller records after unanswered
//! retransmissions (4.4), the timer value kept across a retransmitted flight (5.8.2), at most
//! ten records per transmission (5.8.3), an alert repeated for a repeated offending record
//! (5.10), and a HelloRetryRequest cookie that does not carry the ClientHello (11).

use super::handshake_test::*;
use super::messages;
use crate::config::ConfigBuilder;
use crate::crypto::Certificate;
use bytes::BytesMut;

use shared::error::Result;
use std::sync::Arc;
use std::time::{Duration, Instant};

fn record_count(datagrams: &[BytesMut]) -> usize {
    datagrams
        .iter()
        .map(|datagram| record_first_bytes(datagram).len())
        .sum()
}

/// Fires the next timer of the client (`client`) or the server.
fn fire(pair: &mut Pair, client: bool) -> Instant {
    let (endpoint, remote) = if client {
        (&mut pair.client, server_addr())
    } else {
        (&mut pair.server, client_addr())
    };
    let at = endpoint.poll_timeout(&remote).expect("a timer is armed");
    pair.now = pair.now.max(at);
    if let Err(err) = endpoint.handle_timeout(remote, at) {
        panic!("the timer at {:?} failed: {err}", at - pair.now);
    }
    at
}

/// A server whose Certificate message is large: its certificate followed by `extra` copies of
/// itself (extraneous certificates, which RFC 8446 section 4.4.2 has a peer accept).
fn server_with_a_long_chain(extra: usize) -> ConfigBuilder {
    let provider = provider();
    let certificate =
        Certificate::generate_self_signed(vec!["localhost".to_owned()], provider.crypto())
            .expect("a self-signed certificate");
    let mut chain = certificate.certificate.clone();
    for _ in 0..extra {
        chain.push(certificate.certificate[0].clone());
    }
    let certificate = Certificate {
        certificate: chain,
        private_key: certificate.private_key,
    };
    ConfigBuilder::default()
        .with_crypto_provider(provider)
        .with_insecure_skip_verify(true)
        .with_cookie_exchange(false)
        .with_certificates(vec![certificate])
}

/// RFC 9147 section 4.4: "The DTLS record layer SHOULD also allow the upper layer protocol to
/// discover the amount of record expansion expected by the DTLS processing". What the
/// endpoint reports is exactly what a protected record adds to its content, for every length.
#[test]
fn the_record_expansion_the_endpoint_reports_is_what_a_record_adds() -> Result<()> {
    let mut pair = Pair::new(client_builder(), server_builder())?.complete();
    let overhead = pair
        .client
        .record_overhead(server_addr())
        .expect("the association has keys");
    for len in [0usize, 1, 100, 1000] {
        pair.client
            .write(pair.now, server_addr(), &vec![0x5a; len])
            .expect("the client writes");
        let datagrams = take(&mut pair.client);
        assert_eq!(datagrams.len(), 1, "{len} bytes in one record");
        assert_eq!(datagrams[0].len() - len, overhead, "{len} bytes");
    }
    Ok(())
}

/// RFC 9147 section 4.4: "If repeated retransmissions do not result in a response, and the
/// PMTU is unknown, subsequent retransmissions SHOULD back off to a smaller record size". The
/// server's flight, never answered, goes out in datagrams of up to the configured MTU at
/// first and its first two retransmissions, and in datagrams of half of it from the third on.
#[test]
fn unanswered_retransmissions_make_the_records_smaller() -> Result<()> {
    let mut pair = Pair::new(client_builder(), server_with_a_long_chain(3))?;
    let client_hello = take(&mut pair.client);
    pair.deliver_to_server(client_hello);
    // The largest record (datagrams may hold several records).
    let largest = |datagrams: &[BytesMut]| {
        let mut largest = 0;
        for datagram in datagrams {
            let mut rest = &datagram[..];
            while !rest.is_empty() {
                let (_, taken) = super::record::next_record(rest, 0).expect("whole records");
                largest = largest.max(taken);
                rest = &rest[taken..];
            }
        }
        largest
    };
    let first = take(&mut pair.server);
    assert!(
        largest(&first) > 600,
        "the Certificate fills records of the 1200-byte MTU: {}",
        largest(&first)
    );
    for retransmission in 1..=2 {
        fire(&mut pair, false);
        let again = take(&mut pair.server);
        assert!(
            largest(&again) > 600,
            "retransmission {retransmission} is cut as the first was"
        );
    }
    fire(&mut pair, false);
    let smaller = take(&mut pair.server);
    assert!(!smaller.is_empty());
    assert!(
        largest(&smaller) <= 600,
        "the third retransmission is cut to half the MTU: {}",
        largest(&smaller)
    );
    // The smaller records complete the handshake.
    pair.deliver_to_client(smaller);
    let mut pair = pair.complete();
    assert_eq!(pair.client_sends(b"through"), vec![b"through".to_vec()]);
    Ok(())
}

/// RFC 9147 section 5.8.2: "Implementations SHOULD retain the current timer value until a
/// message is transmitted and acknowledged without having to be retransmitted". The client's
/// ClientHello is lost once, so its timer doubles to two seconds; the retransmission is
/// answered at once, but the timer of the client's next flight keeps the two seconds (it was
/// the initial second: the backed-off value was lost when the association went on as DTLS
/// 1.3). Without the loss the next flight has the initial value.
#[test]
fn the_backed_off_timer_is_kept_until_a_flight_goes_through_the_first_time() -> Result<()> {
    let mut pair = Pair::new(
        client_builder(),
        server_builder().with_cookie_exchange(false),
    )?;
    let _lost = take(&mut pair.client);
    let first = fire(&mut pair, true);
    let again = take(&mut pair.client);
    assert_eq!(again.len(), 1, "the ClientHello again");
    pair.deliver_to_server(again);
    let flight = take(&mut pair.server);
    pair.deliver_to_client(flight);
    assert!(pair.client_complete);
    let finished_timer = pair
        .client
        .poll_timeout(&server_addr())
        .expect("the client's last flight waits for its ACK");
    assert_eq!(
        finished_timer - first,
        Duration::from_secs(2),
        "the doubled value, not one reset by the answer to a retransmitted flight"
    );

    // Without the loss the timer of the client's next flight is the initial value.
    let mut pair = Pair::new(
        client_builder(),
        server_builder().with_cookie_exchange(false),
    )?;
    let start = pair.now;
    pair.round();
    assert!(pair.client_complete);
    let finished_timer = pair
        .client
        .poll_timeout(&server_addr())
        .expect("the client's last flight waits for its ACK");
    assert_eq!(finished_timer - start, Duration::from_secs(1));
    Ok(())
}

/// RFC 9147 section 5.8.3: "DTLS stacks SHOULD NOT send more than 10 records in a single
/// transmission." A flight of more pieces than that, at a small MTU, goes out ten records at
/// a time; the next transmission goes on with the pieces not sent yet, and the handshake
/// completes.
#[test]
fn a_transmission_carries_at_most_ten_records() -> Result<()> {
    let mut pair = Pair::new(client_builder(), server_with_a_long_chain(3).with_mtu(200))?;
    let client_hello = take(&mut pair.client);
    pair.deliver_to_server(client_hello);
    let first = take(&mut pair.server);
    assert_eq!(record_count(&first), 10, "ten records, of a flight of more");
    // The client acknowledges what it has after a quarter of its timer; what the server
    // sends then is again at most ten records, and none of the first ten.
    pair.deliver_to_client(first);
    assert!(!pair.client_complete);
    let mut transmissions = 1;
    for _ in 0..16 {
        if pair.client_complete {
            break;
        }
        fire(&mut pair, true);
        let ack = take(&mut pair.client);
        pair.deliver_to_server(ack);
        let next = take(&mut pair.server);
        if next.is_empty() {
            continue;
        }
        transmissions += 1;
        assert!(record_count(&next) <= 10, "{} records", record_count(&next));
        pair.deliver_to_client(next);
    }
    assert!(
        transmissions > 1,
        "the flight took more than one transmission"
    );
    let mut pair = pair.complete();
    assert_eq!(pair.client_sends(b"done"), vec![b"done".to_vec()]);
    Ok(())
}

/// RFC 9147 section 5.10: "a DTLS implementation which would ordinarily issue an alert SHOULD
/// generate a new alert message if the offending record is received again". A server flight
/// with a CertificateVerify that does not verify ends the client's association with an alert;
/// the same flight again (the server did not get the alert and retransmits) draws another.
#[test]
fn a_repeated_offending_flight_draws_the_alert_again() -> Result<()> {
    let provider = provider();
    let certificate =
        Certificate::generate_self_signed(vec!["localhost".to_owned()], provider.crypto())?;
    let mut pair = Pair::new(
        client_builder(),
        ConfigBuilder::default()
            .with_crypto_provider(provider)
            .with_cookie_exchange(false)
            .with_certificates(vec![Certificate::from_signing_key(
                certificate.certificate.clone(),
                Arc::new(super::reliability_test::WrongSigner(
                    certificate.private_key.signing_key.clone(),
                )),
            )]),
    )?;
    let client_hello = take(&mut pair.client);
    pair.deliver_to_server(client_hello);
    let flight = take(&mut pair.server);
    pair.deliver_to_client(flight.clone());
    assert!(pair.client.is_connection_failed(&server_addr()));
    let alert = take(&mut pair.client);
    assert_eq!(alert.len(), 1, "the alert");
    pair.deliver_to_client(flight.clone());
    let again = take(&mut pair.client);
    assert_eq!(again.len(), 1, "a new alert for the repeated flight");
    assert_ne!(
        again[0], alert[0],
        "a new record, not the old one sent again"
    );

    // RFC 8446 section 6.2: "The implementation SHOULD provide a way to facilitate logging
    // the sending and receiving of alerts": the application reads them from each side.
    assert_eq!(
        pair.client.connection_fatal_alerts(&server_addr()),
        Some((Some(messages::alert::DECRYPT_ERROR), None)),
        "the alert the client sent"
    );
    pair.deliver_to_server(alert);
    assert_eq!(
        pair.server.connection_fatal_alerts(&client_addr()),
        Some((None, Some(messages::alert::DECRYPT_ERROR))),
        "the alert the server received"
    );
    Ok(())
}

/// RFC 9147 section 11: the HelloRetryRequest cookie "SHOULD be constructed so that knowledge
/// of the cookie is insufficient to reproduce the ClientHello contents". The cookie holds the
/// hash of the first ClientHello and what the HelloRetryRequest said: it has the same length
/// for a ClientHello with a long server name as for one without, and contains neither the
/// client's random nor the name.
#[test]
fn the_cookie_does_not_carry_the_client_hello() -> Result<()> {
    let cookie_for = |client: ConfigBuilder| -> Result<(Vec<u8>, Vec<u8>)> {
        let mut pair = Pair::new(client, server_builder())?;
        let first = take(&mut pair.client);
        let random = client_hello(&first[0]).random.to_vec();
        pair.deliver_to_server(first);
        let hello_retry_request = take(&mut pair.server);
        pair.deliver_to_client(hello_retry_request);
        let second = take(&mut pair.client);
        let cookie = client_hello(&second[0])
            .extension(messages::EXT_COOKIE)
            .expect("the second ClientHello carries the cookie")
            .to_vec();
        Ok((random, cookie))
    };
    let name = "a-rather-long-server-name-that-a-cookie-holding-the-hello-would-hold.example";
    let (random, plain) = cookie_for(client_builder())?;
    let (named_random, named) = cookie_for(client_builder().with_server_name(name.to_owned()))?;
    assert_eq!(
        plain.len(),
        named.len(),
        "the cookie does not grow with the ClientHello"
    );
    for (random, cookie) in [(&random, &plain), (&named_random, &named)] {
        assert!(
            !cookie.windows(random.len()).any(|w| w == random.as_slice()),
            "the cookie holds the client's random"
        );
    }
    assert!(!named.windows(name.len()).any(|w| w == name.as_bytes()));
    Ok(())
}

/// The ClientHello in `datagram` (one plaintext record holding the whole message).
fn client_hello(datagram: &[u8]) -> messages::ClientHello<'_> {
    assert_eq!(datagram[13], 1, "a ClientHello");
    let length = usize::from(datagram[14]) << 16
        | usize::from(datagram[15]) << 8
        | usize::from(datagram[16]);
    messages::ClientHello::parse(&datagram[25..25 + length]).expect("the ClientHello parses")
}

/// RFC 6347 section 4.2.7 for DTLS 1.2, as RFC 9147 section 5.10 for 1.3: a peer that keeps
/// sending records that fail authentication is given up on where the configuration sets a
/// limit (off by default: such records are unauthenticated, see
/// `ConfigBuilder::with_invalid_record_limit`), without an alert.
#[test]
fn a_dtls_1_2_peer_that_keeps_sending_bad_records_is_given_up_on_where_configured() -> Result<()> {
    use crate::config::DtlsVersion;
    let dtls12 = |builder: ConfigBuilder| {
        builder.with_protocol_versions(DtlsVersion::Dtls1_2, DtlsVersion::Dtls1_2)
    };
    let mut pair = Pair::new(
        dtls12(client_builder()),
        dtls12(server_builder())
            .with_cookie_exchange(false)
            .with_invalid_record_limit(Some(3)),
    )?
    .complete();
    assert_eq!(pair.versions().0, Some(DtlsVersion::Dtls1_2));
    pair.client
        .write(pair.now, server_addr(), b"genuine")
        .expect("the client writes");
    let genuine = take(&mut pair.client);
    for attempt in 1..=4u8 {
        let mut forged = genuine[0].to_vec();
        let last = forged.len() - 1;
        forged[last] ^= attempt;
        let _ = pair
            .server
            .read(pair.now, client_addr(), None, BytesMut::from(&forged[..]));
        assert_eq!(
            pair.server.is_connection_failed(&client_addr()),
            attempt == 4,
            "after {attempt} invalid records"
        );
        assert!(take(&mut pair.server).is_empty(), "no alert for them");
    }
    // The client, which has no limit, takes any number.
    for attempt in 0..100u8 {
        let mut forged = genuine[0].to_vec();
        let last = forged.len() - 1;
        forged[last] ^= attempt | 1;
        let _ = pair
            .client
            .read(pair.now, server_addr(), None, BytesMut::from(&forged[..]));
    }
    assert!(!pair.client.is_connection_failed(&server_addr()));
    Ok(())
}

/// RFC 8446 section 4.4.2: "all implementations SHOULD be prepared to handle potentially
/// extraneous certificates and arbitrary orderings". A DTLS 1.3 server whose Certificate
/// message has, after its end-entity certificate, a certificate that has nothing to do with
/// the chain and a copy of its own, is verified against the client's root all the same; the
/// same chain against another root is refused.
#[test]
fn extraneous_certificates_in_the_chain_are_tolerated() -> Result<()> {
    let provider = provider();
    let generate = |name: &str| {
        Certificate::generate_self_signed(vec![name.to_owned()], provider.crypto())
            .expect("a self-signed certificate")
    };
    let server = generate("localhost");
    let unrelated = generate("unrelated.example");
    let chain = vec![
        server.certificate[0].clone(),
        unrelated.certificate[0].clone(),
        server.certificate[0].clone(),
    ];
    let root_of = |certificate: &Certificate| {
        let mut roots = rustls::RootCertStore::empty();
        roots
            .add(certificate.certificate[0].clone())
            .expect("a root");
        roots
    };
    let server_config = || {
        ConfigBuilder::default()
            .with_crypto_provider(provider.clone())
            .with_cookie_exchange(false)
            .with_certificates(vec![Certificate {
                certificate: chain.clone(),
                private_key: server.private_key.clone(),
            }])
    };
    let client = |roots| {
        ConfigBuilder::default()
            .with_crypto_provider(provider.clone())
            .with_post_quantum_key_share(false)
            .with_server_name("localhost".to_owned())
            .with_roots_cas(roots)
    };
    let mut pair = Pair::new(client(root_of(&server)), server_config())?;
    pair.run();
    assert!(
        pair.client_complete && pair.server_complete,
        "{:?}",
        pair.client_error
    );

    let mut pair = Pair::new(client(root_of(&unrelated)), server_config())?;
    pair.run();
    assert!(
        !pair.client_complete,
        "verified against a root it does not chain to"
    );
    Ok(())
}
