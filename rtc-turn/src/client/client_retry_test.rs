//! A Refresh or ChannelBind that exhausts its retransmissions is started again once as a new
//! transaction, and a ChannelBind that fails for good goes back to being attempted on the next
//! send (upstream webrtc-rs PR 295).
use super::test_server::*;
use super::*;
use sansio::Protocol;
use std::collections::HashSet;

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

fn distinct_ids(requests: &[Message], method: Method) -> HashSet<TransactionId> {
    requests
        .iter()
        .filter(|r| r.typ.method == method)
        .map(|r| r.transaction_id)
        .collect()
}

fn timeouts(events: &[Event]) -> Vec<TransactionId> {
    events
        .iter()
        .filter_map(|e| match e {
            Event::TransactionTimeout(id) => Some(*id),
            _ => None,
        })
        .collect()
}

#[test]
fn test_channel_bind_that_times_out_is_sent_again() -> Result<()> {
    let now = Instant::now();
    let server = TestServer::new()?;
    let mut client = new_client(TransportProtocol::UDP)?;
    let relayed = server.allocate(&mut client, now)?;
    let peer: SocketAddr = "198.51.100.7:4000".parse().unwrap();
    server.permit(&mut client, now, relayed, peer)?;

    client.relay(relayed)?.send_to(now, b"hi", peer)?;
    let first = server.next_request(&mut client);
    assert_eq!(first.typ.method, METHOD_CHANNEL_BIND);

    // Nobody answers. Over UDP one transaction gives up after about 8 s at the default RTO, so
    // a minute covers both attempts and stays short of the 120 s permission refresh.
    let (requests, events) = drive_until(&server, &mut client, now + Duration::from_secs(60))?;

    let ids = distinct_ids(&requests, METHOD_CHANNEL_BIND);
    assert_eq!(
        ids.len(),
        2,
        "the first ChannelBind is retransmitted, then started again once as a new transaction"
    );
    assert!(ids.contains(&first.transaction_id));
    let retry = requests
        .iter()
        .find(|r| r.typ.method == METHOD_CHANNEL_BIND && r.transaction_id != first.transaction_id)
        .expect("a second ChannelBind transaction");
    assert_eq!(channel_number_of(retry)?, channel_number_of(&first)?);
    assert_eq!(peers_of(retry), vec![peer]);

    assert_eq!(
        timeouts(&events),
        vec![first.transaction_id],
        "the binding times out once, under the id of its first request"
    );
    assert_eq!(
        binding_state(&client, relayed, peer),
        Some(binding::BindingState::Idle),
        "a binding that failed is attempted again, not left waiting"
    );

    // The next send binds the channel again.
    client
        .relay(relayed)?
        .send_to(now + Duration::from_secs(61), b"again", peer)?;
    let again = server.next_request(&mut client);
    assert_eq!(again.typ.method, METHOD_CHANNEL_BIND);
    assert!(!ids.contains(&again.transaction_id));

    client.close()
}

/// The same over UDP and over TCP, where each transaction is sent once and waits Ti (39.5 s).
#[test]
fn test_refresh_that_times_out_is_sent_again() -> Result<()> {
    for transport_protocol in [TransportProtocol::UDP, TransportProtocol::TCP] {
        let now = Instant::now();
        let server = TestServer::new()?;
        let mut client = new_client(transport_protocol)?;
        let relayed = server.allocate(&mut client, now)?;

        client.refresh_allocations(now)?;
        let first = server.next_request(&mut client);
        assert_eq!(first.typ.method, METHOD_REFRESH);

        // Two attempts fit before the 120 s permission refresh on either transport.
        let (requests, events) = drive_until(&server, &mut client, now + Duration::from_secs(100))?;

        let mut ids = distinct_ids(&requests, METHOD_REFRESH);
        ids.remove(&first.transaction_id);
        assert_eq!(
            ids.len(),
            1,
            "{transport_protocol:?}: the Refresh is started again once as a new transaction"
        );
        let retry = requests
            .iter()
            .find(|r| r.typ.method == METHOD_REFRESH && r.transaction_id != first.transaction_id)
            .expect("a second Refresh transaction");
        assert_eq!(lifetime_of(retry)?, lifetime_of(&first)?);
        if transport_protocol == TransportProtocol::TCP {
            assert_eq!(
                requests.len(),
                1,
                "over TCP the second transaction is sent once, like the first"
            );
        }

        assert_eq!(
            timeouts(&events),
            vec![first.transaction_id],
            "{transport_protocol:?}: one timeout, under the id of the first request"
        );
        assert!(client.relay(relayed).is_ok());
        client.close()?;
    }
    Ok(())
}

/// A Refresh answered after it was started again still renews the allocation.
#[test]
fn test_refresh_answered_after_its_retry_renews_the_allocation() -> Result<()> {
    let now = Instant::now();
    let server = TestServer::new()?;
    let mut client = new_client(TransportProtocol::UDP)?;
    let relayed = server.allocate(&mut client, now)?;

    client.refresh_allocations(now)?;
    let first = server.next_request(&mut client);

    // Run until the second transaction has gone out, but not until it gives up.
    let (requests, _) = drive_until(&server, &mut client, now + Duration::from_secs(9))?;
    let retry = requests
        .iter()
        .find(|r| r.typ.method == METHOD_REFRESH && r.transaction_id != first.transaction_id)
        .expect("a second Refresh transaction")
        .clone();

    server.answer(
        &mut client,
        now + Duration::from_secs(9),
        &retry,
        CLASS_SUCCESS_RESPONSE,
        vec![Box::new(Lifetime(Duration::from_secs(300)))],
        Some(&server.key),
    )?;
    assert_eq!(
        client.relays.get(&relayed).map(|relay| relay.lifetime),
        Some(Duration::from_secs(300))
    );
    assert!(
        !client.has_transaction(&retry.transaction_id),
        "the retry is answered"
    );

    client.close()
}
