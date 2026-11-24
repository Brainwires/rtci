//! Integration tests for rtci-mdns
//!
//! These tests verify the interaction between mDNS server and client
//! using the sans-I/O pattern without actual network I/O.

use bytes::BytesMut;
use rtci_mdns::{MDNS_DEST_ADDR, Mdns, MdnsConfig, MdnsEvent, MdnsProbePolicy};
use sansio::Protocol;
use shared::{TaggedBytesMut, TransportContext, TransportProtocol};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};

/// The configuration these tests start from. They exchange packets at one instant, so the
/// names are taken as unique without probing (probing has its own tests, in
/// `src/proto/mdns_responder_test.rs` and below), and the jitter is seeded.
fn test_config() -> MdnsConfig {
    MdnsConfig::default()
        .with_probe_policy(MdnsProbePolicy::Never)
        .with_jitter_seed(1)
}

/// Helper to create a transport context for a message
fn create_transport_context(local: SocketAddr, peer: SocketAddr) -> TransportContext {
    TransportContext {
        local_addr: local,
        peer_addr: peer,
        transport_protocol: TransportProtocol::UDP,
        ecn: None,
    }
}

/// Helper to create a TaggedBytesMut from a packet
fn create_message(
    now: Instant,
    local: SocketAddr,
    peer: SocketAddr,
    data: &[u8],
) -> TaggedBytesMut {
    TaggedBytesMut {
        now,
        transport: create_transport_context(local, peer),
        message: BytesMut::from(data),
    }
}

/// Simulates packet delivery between two mDNS connections.
/// Returns the number of packets delivered.
fn deliver_packets(
    from: &mut Mdns,
    to: &mut Mdns,
    from_addr: SocketAddr,
    to_addr: SocketAddr,
    now: Instant,
) -> usize {
    let mut count = 0;
    while let Some(packet) = from.poll_write() {
        // Only deliver packets destined for multicast (both listen on it)
        if packet.transport.peer_addr == MDNS_DEST_ADDR {
            let msg = create_message(now, to_addr, from_addr, &packet.message);
            let _ = to.handle_read(msg);
            count += 1;
        }
    }
    count
}

/// Simulates bidirectional packet delivery between two connections.
/// Returns (packets_a_to_b, packets_b_to_a).
fn exchange_packets(
    conn_a: &mut Mdns,
    conn_b: &mut Mdns,
    addr_a: SocketAddr,
    addr_b: SocketAddr,
    now: Instant,
) -> (usize, usize) {
    // Collect packets from both before delivering to avoid borrow issues
    let mut packets_a: Vec<TaggedBytesMut> = Vec::new();
    let mut packets_b: Vec<TaggedBytesMut> = Vec::new();

    while let Some(packet) = conn_a.poll_write() {
        packets_a.push(packet);
    }
    while let Some(packet) = conn_b.poll_write() {
        packets_b.push(packet);
    }

    // Deliver A's packets to B
    let count_a_to_b = packets_a.len();
    for packet in packets_a {
        if packet.transport.peer_addr == MDNS_DEST_ADDR {
            let msg = create_message(now, addr_b, addr_a, &packet.message);
            let _ = conn_b.handle_read(msg);
        }
    }

    // Deliver B's packets to A
    let count_b_to_a = packets_b.len();
    for packet in packets_b {
        if packet.transport.peer_addr == MDNS_DEST_ADDR {
            let msg = create_message(now, addr_a, addr_b, &packet.message);
            let _ = conn_a.handle_read(msg);
        }
    }

    (count_a_to_b, count_b_to_a)
}

#[test]
fn test_server_responds_to_query() {
    let now = Instant::now();
    // Server configuration
    let server_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)), 5353);
    let config_server = test_config()
        .with_local_names(vec!["test-server.local".to_string()])
        .with_local_ip(server_addr.ip());
    let mut server = Mdns::new(now, config_server);

    // Client configuration
    let client_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 200)), 5353);
    let config_client = test_config().with_query_interval(Duration::from_secs(1));
    let mut client = Mdns::new(now, config_client);

    // Client starts a query
    let query_id = client.query_now(now, "test-server.local");
    assert!(client.is_query_pending(query_id));

    // Exchange packets: client query -> server, server response -> client
    exchange_packets(&mut client, &mut server, client_addr, server_addr, now);
    exchange_packets(&mut server, &mut client, server_addr, client_addr, now);

    // Client should have received an answer
    let event = client.poll_event();
    assert!(event.is_some(), "Expected QueryAnswered event");

    match event.unwrap() {
        MdnsEvent::QueryAnswered(id, addr) => {
            assert_eq!(id, query_id);
            assert_eq!(addr, server_addr.ip());
        }
        MdnsEvent::QueryTimeout(_) => panic!("Unexpected QueryTimeout"),
        other => panic!("Unexpected event: {other:?}"),
    }

    // Query should no longer be pending
    assert!(!client.is_query_pending(query_id));
}

#[test]
fn test_multiple_local_names() {
    let now = Instant::now();
    // Server with multiple local names
    let server_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 50)), 5353);
    let config_server = test_config()
        .with_local_names(vec![
            "name1.local".to_string(),
            "name2.local".to_string(),
            "name3.local".to_string(),
        ])
        .with_local_ip(server_addr.ip());
    let mut server = Mdns::new(now, config_server);

    let client_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)), 5353);
    let config_client = test_config();
    let mut client = Mdns::new(now, config_client);

    // Query for each name
    let query1 = client.query_now(now, "name1.local");
    let query2 = client.query_now(now, "name2.local");
    let query3 = client.query_now(now, "name3.local");

    assert_eq!(client.pending_query_count(), 3);

    // Exchange packets
    exchange_packets(&mut client, &mut server, client_addr, server_addr, now);
    exchange_packets(&mut server, &mut client, server_addr, client_addr, now);

    // Collect all answers
    let mut answered_ids = Vec::new();
    while let Some(event) = client.poll_event() {
        if let MdnsEvent::QueryAnswered(id, addr) = event {
            answered_ids.push(id);
            assert_eq!(addr, server_addr.ip());
        }
    }

    // All queries should be answered
    assert_eq!(answered_ids.len(), 3);
    assert!(answered_ids.contains(&query1));
    assert!(answered_ids.contains(&query2));
    assert!(answered_ids.contains(&query3));
    assert_eq!(client.pending_query_count(), 0);
}

#[test]
fn test_query_for_unknown_name_remains_pending() {
    let now = Instant::now();
    // Server only knows about "known.local"
    let server_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 5353);
    let config_server = test_config()
        .with_local_names(vec!["known.local".to_string()])
        .with_local_ip(server_addr.ip());
    let mut server = Mdns::new(now, config_server);

    let client_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2)), 5353);
    let config_client = test_config();
    let mut client = Mdns::new(now, config_client);

    // Query for unknown name
    let query_id = client.query_now(now, "unknown.local");

    // Exchange packets
    exchange_packets(&mut client, &mut server, client_addr, server_addr, now);
    exchange_packets(&mut server, &mut client, server_addr, client_addr, now);

    // No answer should be received
    assert!(client.poll_event().is_none());

    // Query should still be pending
    assert!(client.is_query_pending(query_id));
}

#[test]
fn test_query_timeout() {
    let now = Instant::now();
    let config = test_config()
        .with_query_interval(Duration::from_millis(100))
        .with_query_timeout(Duration::from_millis(300));
    let mut client = Mdns::new(now, config);

    let query_id = client.query_now(now, "nonexistent.local");

    // Drain initial packet
    while client.poll_write().is_some() {}

    // Simulate time passing - not yet timed out
    let time_200ms = now + Duration::from_millis(200);
    client.handle_timeout(time_200ms).unwrap();

    // Query should still be pending
    assert!(client.is_query_pending(query_id));
    assert!(client.poll_event().is_none());

    // Simulate time passing - past timeout
    let time_400ms = now + Duration::from_millis(400);
    client.handle_timeout(time_400ms).unwrap();

    // Query should be timed out
    assert!(!client.is_query_pending(query_id));

    let event = client.poll_event();
    assert!(event.is_some());
    match event.unwrap() {
        MdnsEvent::QueryTimeout(id) => assert_eq!(id, query_id),
        _ => panic!("Expected QueryTimeout event"),
    }
}

#[test]
fn test_query_retry() {
    let now = Instant::now();
    let config = test_config().without_query_timeout();
    let mut client = Mdns::new(now, config);

    let _query_id = client.query_now(now, "retry-test.local");

    // Get initial query packet
    let initial_packet = client.poll_write();
    assert!(initial_packet.is_some());

    // No more packets until the retry interval
    assert!(client.poll_write().is_none());

    // RFC 6762 section 5.2: the first retry comes a second after the query, and each
    // interval is twice the one before: retries at 1 s, 3 s, 7 s.
    let mut retries = Vec::new();
    for tenth in 1..=80 {
        client
            .handle_timeout(now + Duration::from_millis(tenth * 100))
            .unwrap();
        while client.poll_write().is_some() {
            retries.push(tenth * 100);
        }
    }
    assert_eq!(retries, vec![1000, 3000, 7000]);
}

#[test]
fn test_cancel_query() {
    let now = Instant::now();
    let config = test_config();
    let mut client = Mdns::new(now, config);

    let query1 = client.query_now(now, "host1.local");
    let query2 = client.query_now(now, "host2.local");
    let query3 = client.query_now(now, "host3.local");

    assert_eq!(client.pending_query_count(), 3);

    // Cancel middle query
    client.cancel_query(query2);

    assert_eq!(client.pending_query_count(), 2);
    assert!(client.is_query_pending(query1));
    assert!(!client.is_query_pending(query2));
    assert!(client.is_query_pending(query3));

    // Cancel remaining queries
    client.cancel_query(query1);
    client.cancel_query(query3);

    assert_eq!(client.pending_query_count(), 0);
}

#[test]
fn test_server_without_local_addr_logs_warning() {
    let now = Instant::now();
    // Server with local names but no local_addr - should not crash
    let config_server = test_config().with_local_names(vec!["test.local".to_string()]);
    // Note: local_addr is not set
    let mut server = Mdns::new(now, config_server);

    let client_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2)), 5353);
    let config_client = test_config();
    let mut client = Mdns::new(now, config_client);

    let _query_id = client.query_now(now, "test.local");

    // Exchange packets - should not panic
    let (client_sent, _) = exchange_packets(
        &mut client,
        &mut server,
        client_addr,
        SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 5353),
        now,
    );

    // Client should have sent the query
    assert_eq!(client_sent, 1);

    // Server should NOT have queued a response (no local_addr)
    assert!(server.poll_write().is_none());
}

#[test]
fn test_close_clears_all_state() {
    let now = Instant::now();
    let server_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 5353);
    let config = test_config()
        .with_local_names(vec!["host.local".to_string()])
        .with_local_ip(server_addr.ip())
        .with_query_interval(Duration::from_secs(1));
    let mut conn = Mdns::new(now, config);

    // Start some queries
    conn.query_now(now, "q1.local");
    conn.query_now(now, "q2.local");

    assert_eq!(conn.pending_query_count(), 2);
    assert!(conn.poll_timeout().is_some());

    // Packets should be queued
    assert!(conn.poll_write().is_some());

    // Close
    conn.close().unwrap();

    // All state should be cleared
    assert_eq!(conn.pending_query_count(), 0);
    assert!(conn.poll_timeout().is_none());
    assert!(conn.poll_write().is_none());
    assert!(conn.poll_event().is_none());
}

#[test]
fn test_closed_connection_rejects_operations() {
    let now = Instant::now();
    let mut conn = Mdns::new(now, test_config());

    conn.close().unwrap();

    // handle_read should fail
    let msg = create_message(
        now,
        SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 5353),
        MDNS_DEST_ADDR,
        &[],
    );
    let result = conn.handle_read(msg);
    assert!(result.is_err());

    // handle_timeout should fail
    let result = conn.handle_timeout(now);
    assert!(result.is_err());
}

#[test]
fn test_sequential_queries() {
    let now = Instant::now();
    // Similar to mdns_server_query.rs example: query1, wait for answer, then query2
    let server_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)), 5353);
    let config_server = test_config()
        .with_local_names(vec!["first.local".to_string(), "second.local".to_string()])
        .with_local_ip(server_addr.ip());
    let mut server = Mdns::new(now, config_server);

    let client_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 20)), 5353);
    let config_client = test_config();
    let mut client = Mdns::new(now, config_client);

    // First query
    let query1 = client.query_now(now, "first.local");

    // Exchange packets for first query
    exchange_packets(&mut client, &mut server, client_addr, server_addr, now);
    exchange_packets(&mut server, &mut client, server_addr, client_addr, now);

    // Verify first answer
    let event = client.poll_event().expect("Expected first answer");
    match event {
        MdnsEvent::QueryAnswered(id, _addr) => {
            assert_eq!(id, query1);
        }
        _ => panic!("Expected QueryAnswered"),
    }

    // Second query (sequential)
    let query2 = client.query_now(now, "second.local");

    // Exchange packets for second query
    exchange_packets(&mut client, &mut server, client_addr, server_addr, now);
    exchange_packets(&mut server, &mut client, server_addr, client_addr, now);

    // Verify second answer
    let event = client.poll_event().expect("Expected second answer");
    match event {
        MdnsEvent::QueryAnswered(id, _addr) => {
            assert_eq!(id, query2);
        }
        _ => panic!("Expected QueryAnswered"),
    }

    assert_eq!(client.pending_query_count(), 0);
}

#[test]
fn test_name_normalization() {
    let now = Instant::now();
    // Names with and without trailing dots should work the same
    let server_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5)), 5353);

    // Server configured with name without trailing dot
    let config_server = test_config()
        .with_local_names(vec!["nodot.local".to_string()])
        .with_local_ip(server_addr.ip());
    let mut server = Mdns::new(now, config_server);

    let client_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 10)), 5353);
    let config_client = test_config();
    let mut client = Mdns::new(now, config_client);

    // Query with trailing dot
    let query_id = client.query_now(now, "nodot.local.");

    exchange_packets(&mut client, &mut server, client_addr, server_addr, now);
    exchange_packets(&mut server, &mut client, server_addr, client_addr, now);

    // Should still get an answer
    let event = client.poll_event();
    assert!(event.is_some());
    match event.unwrap() {
        MdnsEvent::QueryAnswered(id, _addr) => {
            assert_eq!(id, query_id);
        }
        _ => panic!("Expected QueryAnswered"),
    }
}

#[test]
fn test_multiple_clients_single_server() {
    let now = Instant::now();
    // One server, multiple clients querying
    let server_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 0, 1)), 5353);
    let config_server = test_config()
        .with_local_names(vec!["shared-server.local".to_string()])
        .with_local_ip(server_addr.ip());
    let mut server = Mdns::new(now, config_server);

    let client1_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 0, 10)), 5353);
    let client2_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 0, 20)), 5353);

    let mut client1 = Mdns::new(now, test_config());
    let mut client2 = Mdns::new(now, test_config());

    // Both clients query
    let query1 = client1.query_now(now, "shared-server.local");
    let query2 = client2.query_now(now, "shared-server.local");

    // Client1 sends query to server
    deliver_packets(&mut client1, &mut server, client1_addr, server_addr, now);

    // Client2 sends query to server
    deliver_packets(&mut client2, &mut server, client2_addr, server_addr, now);

    // Server responds (may have multiple response packets queued)
    // Collect all server responses
    let mut responses: Vec<TaggedBytesMut> = Vec::new();
    while let Some(packet) = server.poll_write() {
        responses.push(packet);
    }

    // Deliver responses to both clients (multicast behavior)
    for response in &responses {
        let msg1 = create_message(now, client1_addr, server_addr, &response.message);
        let msg2 = create_message(now, client2_addr, server_addr, &response.message);
        let _ = client1.handle_read(msg1);
        let _ = client2.handle_read(msg2);
    }

    // Both clients should have answers
    let event1 = client1.poll_event().expect("Client1 should have answer");
    let event2 = client2.poll_event().expect("Client2 should have answer");

    match event1 {
        MdnsEvent::QueryAnswered(id, _addr) => assert_eq!(id, query1),
        _ => panic!("Expected QueryAnswered for client1"),
    }

    match event2 {
        MdnsEvent::QueryAnswered(id, _addr) => assert_eq!(id, query2),
        _ => panic!("Expected QueryAnswered for client2"),
    }
}

#[test]
fn test_bidirectional_server_client() {
    let now = Instant::now();
    // Two connections that are both server and client (like mdns_server_query.rs)
    let addr_a = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 1, 1, 1)), 5353);
    let addr_b = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 1, 1, 2)), 5353);

    // Connection A: serves "hostA.local", queries for "hostB.local"
    let config_a = test_config()
        .with_local_names(vec!["hostA.local".to_string()])
        .with_local_ip(addr_a.ip());
    let mut conn_a = Mdns::new(now, config_a);

    // Connection B: serves "hostB.local", queries for "hostA.local"
    let config_b = test_config()
        .with_local_names(vec!["hostB.local".to_string()])
        .with_local_ip(addr_b.ip());
    let mut conn_b = Mdns::new(now, config_b);

    // Both start queries
    let query_a = conn_a.query_now(now, "hostB.local");
    let query_b = conn_b.query_now(now, "hostA.local");

    // Exchange packets multiple times to ensure full communication
    for _ in 0..3 {
        exchange_packets(&mut conn_a, &mut conn_b, addr_a, addr_b, now);
    }

    // Both should have answers
    let mut a_answered = false;
    let mut b_answered = false;

    while let Some(event) = conn_a.poll_event() {
        if let MdnsEvent::QueryAnswered(id, addr) = event {
            assert_eq!(id, query_a);
            assert_eq!(addr, addr_b.ip());
            a_answered = true;
        }
    }

    while let Some(event) = conn_b.poll_event() {
        if let MdnsEvent::QueryAnswered(id, addr) = event {
            assert_eq!(id, query_b);
            assert_eq!(addr, addr_a.ip());
            b_answered = true;
        }
    }

    assert!(a_answered, "Connection A should have received answer");
    assert!(b_answered, "Connection B should have received answer");
}

#[test]
fn test_poll_timeout_scheduling() {
    let now = Instant::now();
    let config = test_config().with_query_interval(Duration::from_secs(2));
    let mut conn = Mdns::new(now, config);

    // No queries, no timeout
    assert!(conn.poll_timeout().is_none());

    // Start a query
    let _query = conn.query_now(now, "test.local");

    // Should have a timeout scheduled
    let timeout = conn.poll_timeout();
    assert!(timeout.is_some());

    // Cancel query
    conn.cancel_query(_query);

    // No more timeout needed
    // Note: The timeout might still be set until next handle_timeout call
    // but since query is cancelled, it shouldn't affect anything
    assert_eq!(conn.pending_query_count(), 0);
}

#[test]
fn test_resolves_safari_style_mdns_candidate() {
    let now = Instant::now();
    // Safari and Chrome publish ICE host candidates behind an mDNS name of the
    // form "<uuid-v4>.local" (draft-ietf-mmusic-mdns-ice-candidates) to avoid
    // leaking private IPs. A receiving agent must resolve that name to an IP.
    // This uses a real name captured from Safari 26.5.2, in its exact format.
    let server_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 42));
    let server_addr = SocketAddr::new(server_ip, 5353);
    let safari_name = "61b445d2-6503-41ac-96ce-ee3edac00e9f.local";
    let config_server = test_config()
        .with_local_names(vec![safari_name.to_string()])
        .with_local_ip(server_ip);
    let mut server = Mdns::new(now, config_server);

    let client_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 99)), 5353);
    let mut client = Mdns::new(now, test_config());

    let query_id = client.query_now(now, safari_name);

    exchange_packets(&mut client, &mut server, client_addr, server_addr, now);
    exchange_packets(&mut server, &mut client, server_addr, client_addr, now);

    let event = client
        .poll_event()
        .expect("Safari-style <uuid>.local candidate must resolve");
    assert!(
        matches!(&event, MdnsEvent::QueryAnswered(id, addr) if *id == query_id && *addr == server_ip),
        "expected QueryAnswered({query_id}, {server_ip}), got {event:?}"
    );
    assert!(!client.is_query_pending(query_id));
}

/// Carries what `from` (at `from_addr`) has queued to `to`, as the multicast group would.
fn carry(from: &mut Mdns, from_addr: SocketAddr, to: &mut Mdns, now: Instant) -> usize {
    let mut count = 0;
    while let Some(packet) = from.poll_write() {
        assert_eq!(packet.transport.peer_addr, MDNS_DEST_ADDR);
        let msg = create_message(now, MDNS_DEST_ADDR, from_addr, &packet.message);
        to.handle_read(msg).unwrap();
        count += 1;
    }
    count
}

/// A name's life between two connections, through the public API: probed for and announced
/// (RFC 6762 section 8), resolved by a neighbour from the announcement alone (section 18.1),
/// withdrawn with a goodbye on close (section 10.1).
#[test]
fn test_name_is_probed_announced_resolved_and_withdrawn() {
    let start = Instant::now();
    let owner_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 7)), 5353);
    let mut owner = Mdns::new(
        start,
        MdnsConfig::default()
            .with_jitter_seed(3)
            .with_local_names(vec!["workshop.local".to_string()])
            .with_local_ip(owner_addr.ip()),
    );
    let mut neighbour = Mdns::new(start, MdnsConfig::default().with_jitter_seed(4));

    // Drive the owner's timers for five seconds; the neighbour hears everything.
    let mut now = start;
    let mut carried = 0;
    while let Some(next) = owner.poll_timeout() {
        if next > start + Duration::from_secs(5) {
            break;
        }
        now = next.max(now);
        owner.handle_timeout(now).unwrap();
        carried += carry(&mut owner, owner_addr, &mut neighbour, now);
    }
    assert_eq!(carried, 5, "three probes and two announcements");
    assert!(owner.poll_timeout().is_none());

    // The neighbour heard the announcement: the name resolves without a query.
    let id = neighbour.query_now(now, "Workshop.local");
    assert!(neighbour.poll_write().is_none());
    assert!(matches!(
        neighbour.poll_event(),
        Some(MdnsEvent::QueryAnswered(answered, addr)) if answered == id && addr == owner_addr.ip()
    ));

    // The owner closes: its goodbye empties the neighbour's cache a second later.
    owner.close().unwrap();
    assert_eq!(carry(&mut owner, owner_addr, &mut neighbour, now), 1);
    let later = now + Duration::from_secs(2);
    let id = neighbour.query_now(later, "workshop.local");
    assert!(neighbour.is_query_pending(id));
    assert!(
        neighbour.poll_write().is_some(),
        "the name is asked for again"
    );
}
