//! A permission refresh is split into CreatePermission requests of at most
//! `MAX_PEERS_PER_CREATE_PERMISSION` peers each, rather than one request naming them all.
use super::relay::MAX_PEERS_PER_CREATE_PERMISSION;
use super::test_server::*;
use super::*;
use sansio::Protocol;
use std::collections::HashSet;
use std::net::IpAddr;

fn peer(i: usize) -> SocketAddr {
    SocketAddr::new(
        IpAddr::V4(Ipv4Addr::new(198, 51, (i / 200) as u8, (i % 200 + 1) as u8)),
        4000,
    )
}

#[test]
fn test_permission_refresh_is_split_into_bounded_requests() -> Result<()> {
    const PEERS: usize = 40;
    let now = Instant::now();
    let server = TestServer::new()?;
    let mut client = new_client(TransportProtocol::UDP)?;
    let relayed = server.allocate(&mut client, now)?;
    for i in 0..PEERS {
        server.permit(&mut client, now, relayed, peer(i))?;
    }

    client
        .relay(relayed)?
        .handle_timeout(now + Duration::from_secs(120));
    let refreshes: Vec<Message> = server
        .requests(&mut client)
        .into_iter()
        .filter(|r| r.typ.method == METHOD_CREATE_PERMISSION)
        .collect();

    assert_eq!(
        refreshes.len(),
        PEERS.div_ceil(MAX_PEERS_PER_CREATE_PERMISSION),
        "one request per {MAX_PEERS_PER_CREATE_PERMISSION} peers"
    );
    let mut refreshed = HashSet::new();
    for request in &refreshes {
        let peers = peers_of(request);
        assert!(!peers.is_empty());
        assert!(peers.len() <= MAX_PEERS_PER_CREATE_PERMISSION);
        assert!(
            request.raw.len() < 1200,
            "a refresh request fits one datagram ({} bytes)",
            request.raw.len()
        );
        for p in peers {
            assert!(refreshed.insert(p.ip()), "{p} is named twice");
        }
    }
    let expected: HashSet<IpAddr> = (0..PEERS).map(|i| peer(i).ip()).collect();
    assert_eq!(refreshed, expected, "every permitted address is refreshed");

    client.close()
}

/// Each part of a split refresh is its own request: a 438 on one re-sends that part's peers.
#[test]
fn test_split_refresh_part_is_retried_on_its_own() -> Result<()> {
    const PEERS: usize = MAX_PEERS_PER_CREATE_PERMISSION + 3;
    let now = Instant::now();
    let server = TestServer::new()?;
    let mut client = new_client(TransportProtocol::UDP)?;
    let relayed = server.allocate(&mut client, now)?;
    for i in 0..PEERS {
        server.permit(&mut client, now, relayed, peer(i))?;
    }

    client
        .relay(relayed)?
        .handle_timeout(now + Duration::from_secs(120));
    let refreshes = server.requests(&mut client);
    assert_eq!(refreshes.len(), 2);

    server.stale_nonce(&mut client, now, &refreshes[1], "renewed", REALM)?;
    let retry = server.next_request(&mut client);
    assert_eq!(retry.typ.method, METHOD_CREATE_PERMISSION);
    assert_eq!(peers_of(&retry), peers_of(&refreshes[1]));
    assert_eq!(nonce_of(&retry), "renewed");

    client.close()
}
