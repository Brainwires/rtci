//! DTLS 1.3 post-handshake authentication (RFC 8446 sections 4.2.6 and 4.6.2): a server asks
//! for the client's certificate after the handshake, the client answers at once, and each
//! step of the answer is checked.

use super::conn::{Conn13, FlightKind};
use super::handshake_test::*;
use super::messages::*;
use crate::config::{ClientAuthType, ConfigBuilder};
use crate::crypto::Certificate;
use crate::endpoint::EndpointEvent;
use shared::error::{Error, Result};
use std::sync::Arc;

fn certificate(name: &str) -> Certificate {
    Certificate::generate_self_signed(vec![name.to_owned()], provider().crypto())
        .expect("a self-signed certificate")
}

fn authenticating_client(certificate: Option<Certificate>) -> ConfigBuilder {
    let builder = client_builder().with_post_handshake_auth(true);
    match certificate {
        Some(certificate) => builder.with_certificates(vec![certificate]),
        None => builder,
    }
}

fn der_chain(certificate: &Certificate) -> Vec<Vec<u8>> {
    certificate
        .certificate
        .iter()
        .map(|der| der.as_ref().to_vec())
        .collect()
}

fn authenticated(pair: &Pair) -> usize {
    pair.to_server
        .iter()
        .filter(|event| matches!(event, EndpointEvent::PeerAuthenticated))
        .count()
}

/// The messages of the latest post-handshake flight of `conn`, of the kind given.
fn last_flight(conn: &Conn13, kind: FlightKind) -> Vec<(u8, Vec<u8>)> {
    conn.post_handshake
        .iter()
        .rev()
        .find(|flight| flight.kind == kind)
        .expect("a flight of that kind")
        .messages
        .iter()
        .map(|message| (message.handshake_type, message.body.clone()))
        .collect()
}

/// RFC 8446 section 4.6.2: a client that sent post_handshake_auth is asked for its
/// certificate after the handshake, by a server that asked for none in it, and answers with
/// Certificate, CertificateVerify and Finished; the server takes the chain. It can ask again.
#[test]
fn a_server_asks_for_the_client_certificate_after_the_handshake() -> Result<()> {
    let client_certificate = certificate("client");
    let mut pair = Pair::new(
        authenticating_client(Some(client_certificate.clone())),
        server_builder(),
    )?
    .complete();
    assert!(
        pair.server_conn().peer_certificates.is_empty(),
        "no certificate in the handshake"
    );
    assert!(pair.server_conn().post_handshake_auth_offered());

    pair.server
        .request_client_certificate(pair.now, client_addr())?;
    // RFC 8446 section 4.6.2: other messages may come between the request and its answer.
    assert_eq!(pair.client_sends(b"between"), vec![b"between".to_vec()]);
    assert_eq!(authenticated(&pair), 1);
    assert_eq!(
        pair.server
            .get_connection_state(client_addr())
            .map(|state| state.peer_certificates.clone()),
        Some(der_chain(&client_certificate))
    );
    assert_eq!(
        pair.server
            .connection_mut(&client_addr())
            .map(|conn| conn.post_handshake_authentications()),
        Some(1)
    );
    // Both flights were acknowledged, and the association goes on.
    assert_eq!(
        pair.server_conn().unacknowledged_post_handshake_messages(),
        0
    );
    assert_eq!(
        pair.client_conn().unacknowledged_post_handshake_messages(),
        0
    );
    assert_eq!(pair.client_sends(b"after"), vec![b"after".to_vec()]);

    pair.to_server.clear();
    pair.server
        .request_client_certificate(pair.now, client_addr())?;
    pair.run();
    assert_eq!(authenticated(&pair), 1, "a second request, a second answer");
    Ok(())
}

/// RFC 8446 section 4.2.6: a server does not ask a client that did not offer it; and a
/// client does not offer it unless configured to. A DTLS 1.2 association has no such thing.
#[test]
fn a_client_that_did_not_offer_post_handshake_auth_is_not_asked() -> Result<()> {
    let mut pair = Pair::new(
        client_builder().with_certificates(vec![certificate("client")]),
        server_builder(),
    )?
    .complete();
    assert!(!pair.server_conn().post_handshake_auth_offered());
    assert!(
        pair.server
            .request_client_certificate(pair.now, client_addr())
            .is_err()
    );
    // A client cannot ask.
    assert!(
        pair.client
            .request_client_certificate(pair.now, server_addr())
            .is_err()
    );
    Ok(())
}

/// RFC 8446 section 4.6.2: a client without a certificate the request allows declines with
/// an empty Certificate and its Finished; a server that does not require one goes on.
#[test]
fn a_client_without_a_certificate_declines_with_an_empty_one() -> Result<()> {
    let mut pair = Pair::new(authenticating_client(None), server_builder())?.complete();
    pair.server
        .request_client_certificate(pair.now, client_addr())?;
    pair.run();
    assert_eq!(authenticated(&pair), 1);
    assert!(pair.server_conn().peer_certificates.is_empty());
    assert!(!pair.server.is_connection_failed(&client_addr()));
    assert_eq!(pair.server_sends(b"still"), vec![b"still".to_vec()]);
    Ok(())
}

/// Each step of the answer refuses what does not hold up: a CertificateVerify that does not
/// verify and a Finished that does not are decrypt_error; a context of no outstanding
/// request is an illegal_parameter; a Finished before the CertificateVerify, or anything else
/// in the middle of the answer, an unexpected_message; an empty Certificate where the server
/// requires one a certificate_required.
#[test]
fn each_step_of_the_answer_is_checked() -> Result<()> {
    let answer = |pair: &mut Pair| -> Result<Vec<(u8, Vec<u8>)>> {
        pair.server_conn().request_client_certificate()?;
        let request = last_flight(pair.server_conn(), FlightKind::CertificateRequest);
        assert_eq!(request[0].0, CERTIFICATE_REQUEST);
        pair.client_conn()
            .on_post_handshake_certificate_request(&request[0].1)
            .map_err(|refusal| refusal.error)?;
        Ok(last_flight(pair.client_conn(), FlightKind::Authentication))
    };
    let new_pair = || -> Result<Pair> {
        Ok(Pair::new(
            authenticating_client(Some(certificate("client"))),
            server_builder(),
        )?
        .complete())
    };
    let alert_of = |result: std::result::Result<(), Refusal>| result.err().map(|r| r.alert);

    // The answer as the client makes it verifies.
    let mut pair = new_pair()?;
    let messages = answer(&mut pair)?;
    assert_eq!(
        messages.iter().map(|(t, _)| *t).collect::<Vec<_>>(),
        [CERTIFICATE, CERTIFICATE_VERIFY, FINISHED]
    );
    for (handshake_type, body) in &messages {
        pair.server_conn()
            .on_post_handshake_authentication(*handshake_type, body)
            .map_err(|refusal| refusal.error)?;
    }
    assert_eq!(pair.server_conn().post_handshake_authentications, 1);

    // A CertificateVerify altered.
    let mut pair = new_pair()?;
    let messages = answer(&mut pair)?;
    let server = pair.server_conn();
    assert!(
        server
            .on_post_handshake_authentication(CERTIFICATE, &messages[0].1)
            .is_ok()
    );
    let mut verify = messages[1].1.clone();
    let last = verify.len() - 1;
    verify[last] ^= 1;
    assert_eq!(
        alert_of(server.on_post_handshake_authentication(CERTIFICATE_VERIFY, &verify)),
        Some(alert::DECRYPT_ERROR)
    );

    // A Finished altered.
    let mut pair = new_pair()?;
    let messages = answer(&mut pair)?;
    let server = pair.server_conn();
    for (handshake_type, body) in &messages[..2] {
        assert!(
            server
                .on_post_handshake_authentication(*handshake_type, body)
                .is_ok()
        );
    }
    let mut finished = messages[2].1.clone();
    finished[0] ^= 1;
    assert_eq!(
        alert_of(server.on_post_handshake_authentication(FINISHED, &finished)),
        Some(alert::DECRYPT_ERROR)
    );
    assert_eq!(server.post_handshake_authentications, 0);

    // A Certificate with a context of no request.
    let mut pair = new_pair()?;
    let messages = answer(&mut pair)?;
    let mut certificate_message = messages[0].1.clone();
    certificate_message[1] ^= 0xff;
    assert_eq!(
        alert_of(
            pair.server_conn()
                .on_post_handshake_authentication(CERTIFICATE, &certificate_message)
        ),
        Some(alert::ILLEGAL_PARAMETER)
    );

    // The Finished ahead of the CertificateVerify; a KeyUpdate in the middle of the answer.
    let mut pair = new_pair()?;
    let messages = answer(&mut pair)?;
    let server = pair.server_conn();
    assert!(
        server
            .on_post_handshake_authentication(CERTIFICATE, &messages[0].1)
            .is_ok()
    );
    assert_eq!(
        alert_of(server.on_post_handshake_authentication(FINISHED, &messages[2].1)),
        Some(alert::UNEXPECTED_MESSAGE)
    );
    let mut pair = new_pair()?;
    let messages = answer(&mut pair)?;
    let server = pair.server_conn();
    assert!(
        server
            .on_post_handshake_message(CERTIFICATE, &messages[0].1)
            .is_ok()
    );
    assert_eq!(
        alert_of(server.on_post_handshake_message(KEY_UPDATE, &key_update(false))),
        Some(alert::UNEXPECTED_MESSAGE)
    );

    // An empty Certificate to a server that requires one.
    let mut pair = Pair::new(
        authenticating_client(Some(certificate("client"))),
        server_builder().with_client_auth(ClientAuthType::RequireAnyClientCert),
    )?
    .complete();
    pair.server_conn().request_client_certificate()?;
    let context = pair.server_conn().pending_certificate_requests[0].0.clone();
    assert_eq!(
        alert_of(pair.server_conn().on_post_handshake_authentication(
            CERTIFICATE,
            &super::messages::certificate(&context, &[])
        )),
        Some(alert::CERTIFICATE_REQUIRED)
    );
    Ok(())
}

/// RFC 8446 section 4.3.2: after the handshake a CertificateRequest has a context; one
/// without is an illegal_parameter. Without post_handshake_auth one is an
/// unexpected_message (`reliability_test.rs::post_handshake_messages_are_checked`).
#[test]
fn a_certificate_request_without_a_context_is_an_illegal_parameter() -> Result<()> {
    let mut pair = Pair::new(
        authenticating_client(Some(certificate("client"))),
        server_builder(),
    )?
    .complete();
    let refusal = pair
        .client_conn()
        .on_post_handshake_message(CERTIFICATE_REQUEST, &certificate_request(&[], &[0x0403]))
        .err()
        .map(|refusal| refusal.alert);
    assert_eq!(refusal, Some(alert::ILLEGAL_PARAMETER));
    Ok(())
}

/// The configured peer-certificate check runs on the chain of an answer, as in the
/// handshake: a chain it refuses ends the association with bad_certificate.
#[test]
fn the_peer_certificate_check_decides_on_the_answer() -> Result<()> {
    let mut pair = Pair::new(
        authenticating_client(Some(certificate("client"))),
        server_builder().with_verify_peer_certificate(Some(Arc::new(|_, _| {
            Err(Error::Other("not this client".to_owned()))
        }))),
    )?
    .complete();
    pair.server
        .request_client_certificate(pair.now, client_addr())?;
    pair.run();
    assert_eq!(authenticated(&pair), 0);
    assert!(pair.server.is_connection_failed(&client_addr()));
    assert!(
        pair.client.is_connection_failed(&server_addr()),
        "told by the alert"
    );
    Ok(())
}

/// RFC 9147 section 5.8.4: a server may send several CertificateRequests at once; each has a
/// context of its own, random (RFC 8446 section 4.3.2), and is answered. At most four are left
/// unanswered.
#[test]
fn several_certificate_requests_go_out_at_once_and_are_answered() -> Result<()> {
    let mut pair = Pair::new(
        authenticating_client(Some(certificate("client"))),
        server_builder(),
    )?
    .complete();
    for _ in 0..super::handshake::MAX_PENDING_CERTIFICATE_REQUESTS {
        pair.server
            .request_client_certificate(pair.now, client_addr())?;
    }
    let contexts: Vec<Vec<u8>> = pair
        .server_conn()
        .pending_certificate_requests
        .iter()
        .map(|(context, _)| context.clone())
        .collect();
    for (index, context) in contexts.iter().enumerate() {
        assert_eq!(context.len(), 16);
        assert!(!contexts[index + 1..].contains(context), "unique");
    }
    assert!(pair.server_conn().request_client_certificate().is_err());
    pair.run();
    assert_eq!(
        authenticated(&pair),
        super::handshake::MAX_PENDING_CERTIFICATE_REQUESTS,
        "one event per answer"
    );
    assert_eq!(
        pair.server_conn().post_handshake_authentications,
        super::handshake::MAX_PENDING_CERTIFICATE_REQUESTS as u64
    );
    assert!(pair.server_conn().pending_certificate_requests.is_empty());
    Ok(())
}

/// RFC 8446 section 4.4: the Finished of a post-handshake answer is keyed from the client's
/// current application traffic secret. In DTLS (RFC 9147 section 8) a client that sent a
/// KeyUpdate keeps sending under its old keys until the KeyUpdate is acknowledged, while the
/// server reads the client's next keys from the KeyUpdate on. A client that answers in that
/// window keys its Finished from the old secret, the one its answer is protected under, and
/// the server checks it with the secret of the epoch the answer arrived in: before, it used
/// its newest secret of the client's and refused a genuine answer with decrypt_error.
#[test]
fn an_answer_sent_while_the_clients_key_update_is_unacknowledged_verifies() -> Result<()> {
    let client_certificate = certificate("client");
    let mut pair = Pair::new(
        authenticating_client(Some(client_certificate.clone())),
        server_builder(),
    )?
    .complete();

    // The client's KeyUpdate reaches the server; the server's ACK of it is lost.
    pair.client.update_keys(pair.now, server_addr(), false)?;
    let key_update = take(&mut pair.client);
    assert!(!key_update.is_empty());
    pair.deliver_to_server(key_update);
    let _lost_ack = take(&mut pair.server);
    assert_eq!(
        pair.client_conn().unacknowledged_post_handshake_messages(),
        1
    );

    pair.server
        .request_client_certificate(pair.now, client_addr())?;
    let request = take(&mut pair.server);
    pair.deliver_to_client(request);
    assert_eq!(
        pair.client_conn().unacknowledged_post_handshake_messages(),
        2,
        "the KeyUpdate, still unacknowledged, and the answer"
    );
    let answer = take(&mut pair.client);
    pair.deliver_to_server(answer);
    assert!(
        pair.server_error.is_none(),
        "the answer verifies: {:?}",
        pair.server_error
    );
    assert_eq!(authenticated(&pair), 1);
    assert_eq!(
        pair.server
            .get_connection_state(client_addr())
            .map(|state| state.peer_certificates.clone()),
        Some(der_chain(&client_certificate))
    );

    // Everything is acknowledged in the end, and data goes both ways under the new keys.
    pair.run();
    assert_eq!(pair.client_sends(b"after"), vec![b"after".to_vec()]);
    assert_eq!(pair.server_sends(b"back"), vec![b"back".to_vec()]);
    Ok(())
}
