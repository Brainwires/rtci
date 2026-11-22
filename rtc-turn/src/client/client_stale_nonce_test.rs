//! A 438 (Stale Nonce) answer to CreatePermission, Refresh or ChannelBind is retried once with
//! the new nonce and a new transaction id (RFC 8489 §9.2.5, RFC 8656 §4.4).
use super::test_server::*;
use super::*;
use sansio::Protocol;

fn lifetime_of(request: &Message) -> Result<Duration> {
    let mut lifetime = Lifetime::default();
    lifetime.get_from(request)?;
    Ok(lifetime.0)
}

fn channel_number_of(request: &Message) -> Result<u16> {
    let mut number = ChannelNumber::default();
    number.get_from(request)?;
    Ok(number.0)
}

/// Port of upstream webrtc-rs `test_client_nonce_expiration`. There the server clears its nonces
/// after the allocation, the way an expired nonce looks to the client, and the next send must
/// still go through. Here the scripted server answers the first request after the allocation
/// with 438: the client takes the new nonce, sends the CreatePermission again under a new
/// transaction id, reports the permission under the id it handed out, and keeps using the new
/// nonce afterwards.
#[test]
fn test_client_nonce_expiration() -> Result<()> {
    let now = Instant::now();
    let server = TestServer::new()?;
    let mut client = new_client(TransportProtocol::UDP)?;
    let relayed = server.allocate(&mut client, now)?;
    let peer: SocketAddr = "127.0.0.1:8080".parse().unwrap();

    let tid = client
        .relay(relayed)?
        .create_permission(now, peer)?
        .expect("a new permission is requested");
    let first = server.next_request(&mut client);
    assert_eq!(first.transaction_id, tid);
    assert_eq!(nonce_of(&first), "nonce");

    server.stale_nonce(&mut client, now, &first, "renewed", REALM)?;
    assert!(
        client.poll_event().is_none(),
        "a 438 the client can retry is not reported as a failure"
    );

    let mut retry = server.next_request(&mut client);
    assert_eq!(retry.typ.method, METHOD_CREATE_PERMISSION);
    assert_ne!(
        retry.transaction_id, first.transaction_id,
        "the retry is a new transaction"
    );
    assert_eq!(nonce_of(&retry), "renewed");
    assert_eq!(peers_of(&retry), vec![peer]);
    MessageIntegrity::check(&mut retry, &server.key, test_crypto_provider().crypto())?;

    server.succeed(&mut client, now, &retry)?;
    assert!(
        matches!(
            client.poll_event(),
            Some(Event::CreatePermissionResponse(id, addr)) if id == tid && addr == peer
        ),
        "the permission is reported under the id create_permission() returned"
    );

    client.relay(relayed)?.send_to(now, &[0x00], peer)?;
    let bind = server.next_request(&mut client);
    assert_eq!(bind.typ.method, METHOD_CHANNEL_BIND);
    assert_eq!(
        nonce_of(&bind),
        "renewed",
        "later requests carry the new nonce"
    );

    client.close()
}

/// One retry per request: a second 438 is reported, and nothing more is sent.
#[test]
fn test_create_permission_stale_nonce_is_retried_once() -> Result<()> {
    let now = Instant::now();
    let server = TestServer::new()?;
    let mut client = new_client(TransportProtocol::UDP)?;
    let relayed = server.allocate(&mut client, now)?;
    let peer: SocketAddr = "198.51.100.7:4000".parse().unwrap();

    let tid = client
        .relay(relayed)?
        .create_permission(now, peer)?
        .expect("a new permission is requested");
    let first = server.next_request(&mut client);
    server.stale_nonce(&mut client, now, &first, "n1", REALM)?;
    let retry = server.next_request(&mut client);
    assert_eq!(nonce_of(&retry), "n1");
    server.stale_nonce(&mut client, now, &retry, "n2", REALM)?;

    assert!(
        server.requests(&mut client).is_empty(),
        "the request is sent again once, not for every 438"
    );
    match client.poll_event() {
        Some(Event::CreatePermissionError(id, err)) => {
            assert_eq!(
                id, tid,
                "the failure names the id create_permission() returned"
            );
            assert_eq!(err, RequestError::Failed(Error::ErrTryAgain));
        }
        other => panic!("expected CreatePermissionError, got {other:?}"),
    }

    // The permission was not kept, so asking again sends a new request with the latest nonce.
    assert!(
        client
            .relay(relayed)?
            .create_permission(now, peer)?
            .is_some()
    );
    let again = server.next_request(&mut client);
    assert_eq!(nonce_of(&again), "n2");

    client.close()
}

/// An allocation Refresh answered with 438 is sent again with the new nonce and the same
/// LIFETIME, so the allocation does not lapse when the server rotates nonces.
#[test]
fn test_refresh_stale_nonce_is_retried() -> Result<()> {
    let now = Instant::now();
    let server = TestServer::new()?;
    let mut client = new_client(TransportProtocol::UDP)?;
    let relayed = server.allocate(&mut client, now)?;

    client.refresh_allocations(now)?;
    let first = server.next_request(&mut client);
    assert_eq!(first.typ.method, METHOD_REFRESH);
    server.stale_nonce(&mut client, now, &first, "renewed", REALM)?;

    let mut retry = server.next_request(&mut client);
    assert_eq!(retry.typ.method, METHOD_REFRESH);
    assert_ne!(retry.transaction_id, first.transaction_id);
    assert_eq!(nonce_of(&retry), "renewed");
    assert_eq!(lifetime_of(&retry)?, lifetime_of(&first)?);
    MessageIntegrity::check(&mut retry, &server.key, test_crypto_provider().crypto())?;

    server.answer(
        &mut client,
        now,
        &retry,
        CLASS_SUCCESS_RESPONSE,
        vec![Box::new(Lifetime(Duration::from_secs(300)))],
        Some(&server.key),
    )?;
    assert_eq!(
        client.relays.get(&relayed).map(|relay| relay.lifetime),
        Some(Duration::from_secs(300)),
        "the retried Refresh renewed the allocation"
    );

    client.close()
}

/// Releasing an allocation is a Refresh with LIFETIME=0; after a 438 it is sent again with zero,
/// not with the allocation's lifetime.
#[test]
fn test_release_stale_nonce_is_retried_with_zero_lifetime() -> Result<()> {
    let now = Instant::now();
    let server = TestServer::new()?;
    let mut client = new_client(TransportProtocol::UDP)?;
    let relayed = server.allocate(&mut client, now)?;

    client.relay(relayed)?.close(now)?;
    let first = server.next_request(&mut client);
    assert_eq!(lifetime_of(&first)?, Duration::ZERO);
    server.stale_nonce(&mut client, now, &first, "renewed", REALM)?;

    let retry = server.next_request(&mut client);
    assert_eq!(retry.typ.method, METHOD_REFRESH);
    assert_eq!(lifetime_of(&retry)?, Duration::ZERO);
    assert_eq!(nonce_of(&retry), "renewed");

    server.answer(
        &mut client,
        now,
        &retry,
        CLASS_SUCCESS_RESPONSE,
        vec![Box::new(Lifetime(Duration::ZERO))],
        Some(&server.key),
    )?;
    assert!(
        !client.relays.contains_key(&relayed),
        "the allocation is released"
    );

    client.close()
}

/// A ChannelBind answered with 438 is sent again on the same channel number, and the binding
/// waits for that answer instead of being dropped.
#[test]
fn test_channel_bind_stale_nonce_is_retried() -> Result<()> {
    let now = Instant::now();
    let server = TestServer::new()?;
    let mut client = new_client(TransportProtocol::UDP)?;
    let relayed = server.allocate(&mut client, now)?;
    let peer: SocketAddr = "198.51.100.7:4000".parse().unwrap();
    server.permit(&mut client, now, relayed, peer)?;

    client.relay(relayed)?.send_to(now, b"hi", peer)?;
    let first = server.next_request(&mut client);
    assert_eq!(first.typ.method, METHOD_CHANNEL_BIND);
    server.stale_nonce(&mut client, now, &first, "renewed", REALM)?;

    let binding_state = |client: &Client| binding_state(client, relayed, peer);
    assert_eq!(binding_state(&client), Some(binding::BindingState::Request));

    let mut retry = server.next_request(&mut client);
    assert_eq!(retry.typ.method, METHOD_CHANNEL_BIND);
    assert_ne!(retry.transaction_id, first.transaction_id);
    assert_eq!(nonce_of(&retry), "renewed");
    assert_eq!(channel_number_of(&retry)?, channel_number_of(&first)?);
    assert_eq!(peers_of(&retry), vec![peer]);
    MessageIntegrity::check(&mut retry, &server.key, test_crypto_provider().crypto())?;

    server.succeed(&mut client, now, &retry)?;
    assert_eq!(binding_state(&client), Some(binding::BindingState::Ready));

    client.close()
}

/// A 438 that names another realm re-keys the client: the retry is signed with the key for the
/// new realm and carries it.
#[test]
fn test_stale_nonce_with_a_new_realm_rekeys_the_retry() -> Result<()> {
    let now = Instant::now();
    let server = TestServer::new()?;
    let mut client = new_client(TransportProtocol::UDP)?;
    let relayed = server.allocate(&mut client, now)?;
    let peer: SocketAddr = "198.51.100.7:4000".parse().unwrap();

    client.relay(relayed)?.create_permission(now, peer)?;
    let first = server.next_request(&mut client);
    server.stale_nonce(&mut client, now, &first, "renewed", "realm2")?;

    let mut retry = server.next_request(&mut client);
    assert_eq!(
        Realm::get_from_as(&retry, ATTR_REALM)?.text,
        "realm2",
        "the retry names the new realm"
    );
    assert!(
        MessageIntegrity::check(&mut retry, &server.key, test_crypto_provider().crypto()).is_err(),
        "the retry is not signed with the old realm's key"
    );
    let new_key = key_for("realm2")?;
    MessageIntegrity::check(&mut retry, &new_key, test_crypto_provider().crypto())?;

    server.answer(
        &mut client,
        now,
        &retry,
        CLASS_SUCCESS_RESPONSE,
        vec![],
        Some(&new_key),
    )?;
    assert!(matches!(
        client.poll_event(),
        Some(Event::CreatePermissionResponse(_, addr)) if addr == peer
    ));

    client.close()
}
