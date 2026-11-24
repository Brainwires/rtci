//! A TURN permission is for a peer's IP address, whatever the port (RFC 8656 §9).
use super::test_server::*;
use super::*;
use sansio::Protocol;
use stun::error_code::CODE_FORBIDDEN;

#[test]
fn test_one_permission_covers_every_port_on_an_ip() -> Result<()> {
    let now = Instant::now();
    let server = TestServer::new()?;
    let mut client = new_client(TransportProtocol::UDP)?;
    let relayed = server.allocate(&mut client, now)?;
    let first: SocketAddr = "198.51.100.7:4000".parse().unwrap();
    let second: SocketAddr = "198.51.100.7:4001".parse().unwrap();
    server.permit(&mut client, now, relayed, first)?;

    assert_eq!(
        client.relay(relayed)?.create_permission(now, second)?,
        None,
        "another port on a permitted address is already permitted"
    );
    assert!(
        server.requests(&mut client).is_empty(),
        "no second CreatePermission is sent for the same address"
    );
    client.relay(relayed)?.send_to(now, b"hi", second)?;
    while client.poll_write().is_some() {}

    // The permission refresh names the address once.
    client
        .relay(relayed)?
        .handle_timeout(now + Duration::from_secs(120));
    let refreshes: Vec<Message> = server
        .requests(&mut client)
        .into_iter()
        .filter(|r| r.typ.method == METHOD_CREATE_PERMISSION)
        .collect();
    assert_eq!(refreshes.len(), 1);
    let peers = peers_of(&refreshes[0]);
    assert_eq!(peers.len(), 1, "one XOR-PEER-ADDRESS per permitted address");
    assert_eq!(peers[0].ip(), first.ip());

    client.close()
}

#[test]
fn test_a_permission_does_not_cover_another_ip() -> Result<()> {
    let now = Instant::now();
    let server = TestServer::new()?;
    let mut client = new_client(TransportProtocol::UDP)?;
    let relayed = server.allocate(&mut client, now)?;
    let permitted: SocketAddr = "198.51.100.7:4000".parse().unwrap();
    let other: SocketAddr = "198.51.100.8:4000".parse().unwrap();
    server.permit(&mut client, now, relayed, permitted)?;

    assert_eq!(
        client.relay(relayed)?.send_to(now, b"hi", other),
        Err(Error::ErrNoPermission)
    );
    assert!(
        client
            .relay(relayed)?
            .create_permission(now, other)?
            .is_some(),
        "another address needs its own permission"
    );

    client.close()
}

/// A permission is per IP address (RFC 8656 §9). Two ports of one address asked for before
/// the first answer make two requests; when the first is granted and the second refused, the
/// address stays permitted: the refusal is reported, and takes nothing from the permission the
/// server installed. (Same defect as webrtc-rs/rtc#316.)
#[test]
fn test_a_refused_request_keeps_a_permission_granted_meanwhile() -> Result<()> {
    let now = Instant::now();
    let server = TestServer::new()?;
    let mut client = new_client(TransportProtocol::UDP)?;
    let relayed = server.allocate(&mut client, now)?;
    let first: SocketAddr = "198.51.100.7:4000".parse().unwrap();
    let second: SocketAddr = "198.51.100.7:4001".parse().unwrap();

    let first_id = client
        .relay(relayed)?
        .create_permission(now, first)?
        .expect("the address has no permission yet");
    let second_id = client
        .relay(relayed)?
        .create_permission(now, second)?
        .expect("the first request is not answered yet");
    let requests: Vec<Message> = server
        .requests(&mut client)
        .into_iter()
        .filter(|r| r.typ.method == METHOD_CREATE_PERMISSION)
        .collect();
    assert_eq!(requests.len(), 2);

    server.succeed(&mut client, now, &requests[0])?;
    server.reject(&mut client, now, &requests[1], CODE_FORBIDDEN)?;
    let events: Vec<Event> = std::iter::from_fn(|| client.poll_event()).collect();
    assert!(
        events
            .iter()
            .any(|e| matches!(e, Event::CreatePermissionResponse(id, _) if *id == first_id)),
        "{events:?}"
    );
    assert!(
        events.iter().any(
            |e| matches!(e, Event::CreatePermissionError(id, err) if *id == second_id && err.is(CODE_FORBIDDEN))
        ),
        "{events:?}"
    );

    // Both ports of the address can be sent to, and the refresh still names the address.
    client.relay(relayed)?.send_to(now, b"hi", first)?;
    client.relay(relayed)?.send_to(now, b"hi", second)?;
    while client.poll_write().is_some() {}
    client
        .relay(relayed)?
        .handle_timeout(now + Duration::from_secs(120));
    let refreshes: Vec<Message> = server
        .requests(&mut client)
        .into_iter()
        .filter(|r| r.typ.method == METHOD_CREATE_PERMISSION)
        .collect();
    assert_eq!(refreshes.len(), 1);
    assert_eq!(peers_of(&refreshes[0])[0].ip(), first.ip());

    client.close()
}
