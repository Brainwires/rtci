//! A TURN permission is for a peer's IP address, whatever the port (RFC 8656 §9).
use super::test_server::*;
use super::*;
use sansio::Protocol;

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
