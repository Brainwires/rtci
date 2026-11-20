//! The authenticated Allocate that follows the 401 is a new request, under a new random
//! transaction id (RFC 8489 §6.3.1; upstream webrtc-rs PR 332).
use super::test_server::*;
use super::*;
use sansio::Protocol;

#[test]
fn test_authenticated_allocate_uses_a_fresh_transaction_id() -> Result<()> {
    let now = Instant::now();
    let server = TestServer::new()?;
    let mut client = new_client(TransportProtocol::UDP)?;

    let tid = client.allocate(now)?;
    let attempt = server.next_request(&mut client);
    assert_eq!(attempt.typ.method, METHOD_ALLOCATE);
    server.answer(
        &mut client,
        now,
        &attempt,
        CLASS_ERROR_RESPONSE,
        vec![
            Box::new(ErrorCodeAttribute {
                code: stun::error_code::CODE_UNAUTHORIZED,
                reason: b"Unauthorized".to_vec(),
            }),
            Box::new(Nonce::new(ATTR_NONCE, "nonce".to_owned())),
            Box::new(Realm::new(ATTR_REALM, REALM.to_owned())),
        ],
        None,
    )?;
    let retry = server.next_request(&mut client);
    assert_eq!(retry.typ.method, METHOD_ALLOCATE);
    assert!(retry.contains(ATTR_MESSAGE_INTEGRITY));

    assert_ne!(
        retry.transaction_id, attempt.transaction_id,
        "the authenticated Allocate is a new transaction"
    );
    let mut derived = attempt.transaction_id;
    derived.0[TRANSACTION_ID_SIZE - 1] = derived.0[TRANSACTION_ID_SIZE - 1].wrapping_add(1);
    assert_ne!(
        retry.transaction_id, derived,
        "the retry's id is not derived from the first request's"
    );
    assert_eq!(
        retry.transaction_id, tid,
        "the retry goes out under the id allocate() returned"
    );

    // The allocation is still reported under that id.
    server.answer(
        &mut client,
        now,
        &retry,
        CLASS_SUCCESS_RESPONSE,
        vec![
            Box::new(RelayedAddress {
                ip: relayed_addr().ip(),
                port: relayed_addr().port(),
            }),
            Box::new(Lifetime(Duration::from_secs(600))),
        ],
        Some(&server.key),
    )?;
    assert!(matches!(
        client.poll_event(),
        Some(Event::AllocateResponse(id, addr)) if id == tid && addr == relayed_addr()
    ));

    client.close()
}

/// Two allocations draw unrelated ids for their authenticated requests.
#[test]
fn test_each_allocate_draws_its_own_id() -> Result<()> {
    let mut client = new_client(TransportProtocol::UDP)?;
    let a = client.allocate(Instant::now())?;
    let b = client.allocate(Instant::now())?;
    assert_ne!(a, b);
    client.close()
}
