//! The client's copy of an allocation follows the server's: an allocation the server no longer
//! holds is dropped and reported, a released one stays released, and permissions and channel
//! bindings end when the RFC says they do (RFC 8656 §5, §8, §9, §12).
use super::test_server::*;
use super::*;
use sansio::Protocol;
use stun::error_code::*;

fn peer() -> SocketAddr {
    "198.51.100.7:4000".parse().unwrap()
}

fn lifetime_of(request: &Message) -> Result<Duration> {
    let mut lifetime = Lifetime::default();
    lifetime.get_from(request)?;
    Ok(lifetime.0)
}

/// An allocation with a permission for [`peer`] and a channel bound to it.
fn bound(server: &TestServer, client: &mut Client, now: Instant) -> Result<RelayedAddr> {
    let relayed = server.allocate(client, now)?;
    server.permit(client, now, relayed, peer())?;
    client.relay(relayed)?.send_to(now, b"first", peer())?;
    let bind = server.next_request(client);
    assert_eq!(bind.typ.method, METHOD_CHANNEL_BIND);
    server.succeed(client, now, &bind)?;
    Ok(relayed)
}

/// RFC 8656 §12.4: the ChannelData length field is 16 bits. A payload it cannot describe is
/// refused; it went out with the length wrapped, which over TCP desynchronises the stream.
#[test]
fn test_channel_data_longer_than_the_length_field_is_refused() -> Result<()> {
    let now = Instant::now();
    let server = TestServer::new()?;
    let mut client = new_client(TransportProtocol::UDP)?;
    let relayed = bound(&server, &mut client, now)?;

    // The largest payload still goes out as ChannelData, with its real length.
    let largest = vec![7u8; usize::from(u16::MAX)];
    client.relay(relayed)?.send_to(now, &largest, peer())?;
    match sent(&mut client).as_slice() {
        [Sent::ChannelData(raw)] => {
            assert_eq!(u16::from_be_bytes([raw[2], raw[3]]), u16::MAX);
            assert_eq!(
                raw.len(),
                4 + usize::from(u16::MAX) + 1,
                "padded to four bytes"
            );
        }
        other => panic!("expected one ChannelData, got {other:?}"),
    }

    let too_long = vec![7u8; usize::from(u16::MAX) + 5];
    assert!(
        client
            .relay(relayed)?
            .send_to(now, &too_long, peer())
            .is_err(),
        "65 540 bytes cannot be described by a 16-bit length"
    );
    assert!(sent(&mut client).is_empty(), "nothing is sent for it");
    client.close()
}

/// RFC 8656 §5, §8.3: a 437 (Allocation Mismatch) to a Refresh means the allocation no longer
/// exists. The client drops it, says so, and stops refreshing it.
#[test]
fn test_a_437_to_a_refresh_ends_the_allocation() -> Result<()> {
    let now = Instant::now();
    let server = TestServer::new()?;
    let mut client = new_client(TransportProtocol::UDP)?;
    let relayed = server.allocate(&mut client, now)?;

    let (requests, _) = drive_until(&server, &mut client, now + Duration::from_secs(300))?;
    let refresh = requests
        .iter()
        .find(|r| r.typ.method == METHOD_REFRESH)
        .expect("a Refresh at half the lifetime");
    let at = now + Duration::from_secs(300);
    let _ = server.reject(&mut client, at, refresh, CODE_ALLOC_MISMATCH);

    assert!(
        client.relay(relayed).is_err(),
        "the allocation the server does not hold is still held by the client"
    );
    match client.poll_event() {
        Some(Event::AllocationLost(addr, err)) => {
            assert_eq!(addr, relayed);
            assert!(err.is(CODE_ALLOC_MISMATCH), "{err}");
        }
        other => panic!("expected AllocationLost, got {other:?}"),
    }
    assert_eq!(
        client.relay(relayed).err(),
        Some(Error::ErrStreamNotExisted)
    );
    let (requests, _) = drive_until(&server, &mut client, at + Duration::from_secs(3600))?;
    assert!(
        requests.is_empty(),
        "the client keeps sending requests for an allocation that is gone: {requests:?}"
    );
    client.close()
}

/// RFC 8656 §8: a release (Refresh with LIFETIME 0) that is never answered must not be undone
/// by the periodic refresh asking for the old lifetime again.
#[test]
fn test_a_lost_release_does_not_revive_the_allocation() -> Result<()> {
    let now = Instant::now();
    let server = TestServer::new()?;
    let mut client = new_client(TransportProtocol::UDP)?;
    let relayed = server.allocate(&mut client, now)?;

    client.relay(relayed)?.close(now)?;
    assert_eq!(
        client.relay(relayed)?.send_to(now, b"x", peer()).err(),
        Some(Error::ErrConnClosed),
        "nothing is sent through an allocation that was released"
    );
    let (requests, events) = drive_until(&server, &mut client, now + Duration::from_secs(3600))?;
    assert!(
        matches!(events.as_slice(), [Event::AllocationReleased(addr)] if *addr == relayed),
        "the end of the release is reported once: {events:?}"
    );
    assert!(!requests.is_empty(), "the release is sent, and sent again");
    for request in requests.iter().filter(|r| r.typ.method == METHOD_REFRESH) {
        assert_eq!(
            lifetime_of(request)?,
            Duration::ZERO,
            "a Refresh asked for a lifetime again after the application released the allocation"
        );
    }
    assert!(
        client.relay(relayed).is_err(),
        "a released allocation is still usable"
    );
    client.close()
}

/// RFC 8656 §12: "If an allocation expires, all its channel bindings expire with it." A new
/// allocation starts without bindings, so data to the same peer goes out as a Send indication
/// with a new ChannelBind, not as ChannelData on a channel the new allocation never bound.
#[test]
fn test_channel_bindings_end_with_their_allocation() -> Result<()> {
    let now = Instant::now();
    let server = TestServer::new()?;
    let mut client = new_client(TransportProtocol::UDP)?;
    let relayed = bound(&server, &mut client, now)?;

    client.relay(relayed)?.close(now)?;
    let release = server.next_request(&mut client);
    assert_eq!(lifetime_of(&release)?, Duration::ZERO);
    server.accept(&mut client, now, &release)?;
    assert!(client.relay(relayed).is_err());

    let later = now + Duration::from_secs(1);
    let relayed = server.allocate(&mut client, later)?;
    server.permit(&mut client, later, relayed, peer())?;
    client.relay(relayed)?.send_to(later, b"again", peer())?;
    let out = sent(&mut client);
    assert!(
        out.iter()
            .any(|s| matches!(s, Sent::Request(r) if r.typ.method == METHOD_CHANNEL_BIND)),
        "the new allocation binds its own channel: {out:?}"
    );
    assert!(
        out.iter()
            .any(|s| matches!(s, Sent::Indication(i) if i.typ.method == METHOD_SEND)),
        "until it is bound the data goes as a Send indication: {out:?}"
    );
    assert!(
        !out.iter().any(|s| matches!(s, Sent::ChannelData(_))),
        "ChannelData was sent on a channel of the previous allocation"
    );
    client.close()
}

/// RFC 8656 §9: a permission lasts 300 s from its last refresh. One whose refreshes are refused
/// ends, and the client stops sending to that peer.
#[test]
fn test_a_permission_whose_refresh_is_refused_ends() -> Result<()> {
    let now = Instant::now();
    let server = TestServer::new()?;
    let mut client = new_client(TransportProtocol::UDP)?;
    let relayed = server.allocate(&mut client, now)?;
    server.permit(&mut client, now, relayed, peer())?;

    let (requests, _) = drive_until(&server, &mut client, now + Duration::from_secs(120))?;
    let refresh = requests
        .iter()
        .find(|r| r.typ.method == METHOD_CREATE_PERMISSION)
        .expect("the permission is refreshed at 120 s");
    let at = now + Duration::from_secs(120);
    server.reject(&mut client, at, refresh, CODE_FORBIDDEN)?;

    assert_eq!(
        client.relay(relayed)?.send_to(at, b"x", peer()).err(),
        Some(Error::ErrNoPermission),
        "the client still sends to a peer whose permission the server refused to refresh"
    );
    match client.poll_event() {
        Some(Event::PermissionLost(addr, ip, err)) => {
            assert_eq!(addr, relayed);
            assert_eq!(ip, peer().ip());
            assert!(err.is(CODE_FORBIDDEN), "{err}");
        }
        other => panic!("expected PermissionLost, got {other:?}"),
    }
    let (requests, _) = drive_until(&server, &mut client, at + Duration::from_secs(250))?;
    assert!(
        !requests
            .iter()
            .any(|r| r.typ.method == METHOD_CREATE_PERMISSION),
        "a permission the server refused is not refreshed again"
    );
    client.close()
}

/// RFC 8656 §9: a permission nobody refreshed for 300 s is gone on the server, so it is gone
/// on the client.
#[test]
fn test_a_permission_that_is_not_refreshed_expires() -> Result<()> {
    let now = Instant::now();
    let server = TestServer::new()?;
    let mut client = new_client(TransportProtocol::UDP)?;
    let relayed = server.allocate(&mut client, now)?;
    server.permit(&mut client, now, relayed, peer())?;

    // The server answers the allocation's Refresh but none of the permission refreshes.
    let end = now + Duration::from_secs(301);
    while let Some(at) = client.poll_timeout() {
        if at > end {
            break;
        }
        client.handle_timeout(at)?;
        for request in server.requests(&mut client) {
            if request.typ.method == METHOD_REFRESH {
                server.accept(&mut client, at, &request)?;
            }
        }
    }
    assert!(client.relay(relayed).is_ok(), "the allocation is alive");
    let just_before = now + Duration::from_secs(299);
    client.relay(relayed)?.send_to(just_before, b"x", peer())?;
    assert_eq!(
        client.relay(relayed)?.send_to(end, b"x", peer()).err(),
        Some(Error::ErrNoPermission),
        "the client still sends on a permission that lapsed {:?} ago",
        end.saturating_duration_since(now + Duration::from_secs(300))
    );
    let _ = sent(&mut client);

    // It is still asked for, and a refresh that gets through installs it again.
    let (requests, _) = drive_until(&server, &mut client, now + Duration::from_secs(360))?;
    let refresh = requests
        .iter()
        .rfind(|r| r.typ.method == METHOD_CREATE_PERMISSION)
        .expect("the permission is still refreshed");
    let at = now + Duration::from_secs(360);
    server.succeed(&mut client, at, refresh)?;
    client.relay(relayed)?.send_to(at, b"x", peer())?;
    client.close()
}

/// RFC 8656 §12: a channel binding lasts 10 minutes unless refreshed. One left idle is unbound
/// on the server, so the next data goes as a Send indication while the channel is bound again.
#[test]
fn test_an_idle_channel_binding_expires_after_ten_minutes() -> Result<()> {
    let now = Instant::now();
    let server = TestServer::new()?;
    let mut client = new_client(TransportProtocol::UDP)?;
    let relayed = bound(&server, &mut client, now)?;
    while client.poll_event().is_some() {}

    let later = now + Duration::from_secs(601);
    let (out, _) = drive_accepting(&server, &mut client, later)?;
    assert!(
        !out.iter()
            .any(|s| matches!(s, Sent::Request(r) if r.typ.method == METHOD_CHANNEL_BIND)),
        "a binding nothing used is not refreshed"
    );

    client.relay(relayed)?.send_to(later, b"late", peer())?;
    let out = sent(&mut client);
    assert!(
        !out.iter().any(|s| matches!(s, Sent::ChannelData(_))),
        "ChannelData went out on a binding that expired on the server: {out:?}"
    );
    assert!(
        out.iter()
            .any(|s| matches!(s, Sent::Indication(i) if i.typ.method == METHOD_SEND))
    );
    assert!(
        out.iter()
            .any(|s| matches!(s, Sent::Request(r) if r.typ.method == METHOD_CHANNEL_BIND))
    );
    client.close()
}

/// RFC 8656 §12: a binding in use is rebound before its 10 minutes run out, without waiting
/// for the application to send: data only ever received on it keeps it alive too.
#[test]
fn test_a_channel_binding_in_use_is_refreshed_by_the_timer() -> Result<()> {
    let now = Instant::now();
    let server = TestServer::new()?;
    let mut client = new_client(TransportProtocol::UDP)?;
    let relayed = bound(&server, &mut client, now)?;
    let number = client_channel_number(&mut client, relayed, now)?;

    // The peer talks; the client only listens.
    let mut data = ChannelData {
        data: b"from the peer".to_vec(),
        number: ChannelNumber(number),
        ..Default::default()
    };
    data.encode()?;
    client.handle_read(TransportMessage {
        now: now + Duration::from_secs(10),
        transport: TransportContext {
            local_addr: local_addr(),
            peer_addr: server_addr(),
            transport_protocol: TransportProtocol::UDP,
            ecn: None,
        },
        message: BytesMut::from(&data.raw[..]),
    })?;

    let (out, _) = drive_accepting(&server, &mut client, now + Duration::from_secs(590))?;
    let rebinds: Vec<&Message> = out
        .iter()
        .filter_map(|s| match s {
            Sent::Request(r) if r.typ.method == METHOD_CHANNEL_BIND => Some(r),
            _ => None,
        })
        .collect();
    assert_eq!(
        rebinds.len(),
        1,
        "one rebind inside the 10 minutes: {out:?}"
    );
    assert_eq!(peers_of(rebinds[0]), vec![peer()]);
    let mut rebound = ChannelNumber::default();
    rebound.get_from(rebinds[0])?;
    assert_eq!(rebound.0, number, "a rebind keeps the channel number");
    client.close()
}

/// The channel number the next data to [`peer`] goes out on.
fn client_channel_number(client: &mut Client, relayed: RelayedAddr, now: Instant) -> Result<u16> {
    client.relay(relayed)?.send_to(now, b"probe", peer())?;
    match sent(client).as_slice() {
        [Sent::ChannelData(raw)] => Ok(u16::from_be_bytes([raw[0], raw[1]])),
        other => panic!("expected ChannelData on the bound channel, got {other:?}"),
    }
}

/// RFC 8656 §7.2 step 1: a server may accept an unauthenticated Allocate. The first response is
/// then a success, and the allocation it reports exists.
#[test]
fn test_a_success_to_the_first_allocate_is_an_allocation() -> Result<()> {
    let now = Instant::now();
    let server = TestServer::new()?;
    let mut client = new_client(TransportProtocol::UDP)?;
    let tid = client.allocate(now)?;
    let first = server.next_request(&mut client);
    server.answer(
        &mut client,
        now,
        &first,
        CLASS_SUCCESS_RESPONSE,
        vec![
            Box::new(RelayedAddress {
                ip: relayed_addr().ip(),
                port: relayed_addr().port(),
            }),
            Box::new(Lifetime(Duration::from_secs(600))),
        ],
        None,
    )?;
    match client.poll_event() {
        Some(Event::AllocateResponse(id, addr)) => {
            assert_eq!(id, tid);
            assert_eq!(addr, relayed_addr());
        }
        other => panic!("expected AllocateResponse, got {other:?}"),
    }
    assert!(client.relay(relayed_addr()).is_ok());
    client.close()
}

/// RFC 8656 §12: binding a channel is optional. With all 4096 numbers taken, data to one more
/// peer address goes as a Send indication.
#[test]
fn test_without_a_free_channel_number_data_goes_as_send_indications() -> Result<()> {
    let now = Instant::now();
    let server = TestServer::new()?;
    let mut client = new_client(TransportProtocol::UDP)?;
    let relayed = server.allocate(&mut client, now)?;
    server.permit(&mut client, now, relayed, peer())?;

    for port in 0..4096u16 {
        let to = SocketAddr::new(peer().ip(), 10_000 + port);
        client.relay(relayed)?.send_to(now, b"x", to)?;
    }
    let _ = sent(&mut client);

    let one_more = SocketAddr::new(peer().ip(), 20_000);
    client.relay(relayed)?.send_to(now, b"x", one_more)?;
    match sent(&mut client).as_slice() {
        [Sent::Indication(i)] => {
            assert_eq!(i.typ.method, METHOD_SEND);
            assert_eq!(peers_of(i), vec![one_more]);
        }
        other => panic!("expected one Send indication, got {other:?}"),
    }
    client.close()
}

/// RFC 8656 §8.3: a 437 to the Refresh that releases an allocation means it was gone already;
/// the release is done.
#[test]
fn test_a_437_to_a_release_is_a_release() -> Result<()> {
    let now = Instant::now();
    let server = TestServer::new()?;
    let mut client = new_client(TransportProtocol::UDP)?;
    let relayed = server.allocate(&mut client, now)?;

    client.relay(relayed)?.close(now)?;
    let release = server.next_request(&mut client);
    assert_eq!(lifetime_of(&release)?, Duration::ZERO);
    server.reject(&mut client, now, &release, CODE_ALLOC_MISMATCH)?;

    assert!(matches!(
        client.poll_event(),
        Some(Event::AllocationReleased(addr)) if addr == relayed
    ));
    assert!(client.poll_event().is_none());
    assert!(client.relay(relayed).is_err());
    let (requests, _) = drive_until(&server, &mut client, now + Duration::from_secs(3600))?;
    assert!(
        requests.is_empty(),
        "nothing more is sent for it: {requests:?}"
    );
    client.close()
}

/// RFC 8656 §5: a 437 to a CreatePermission means the allocation no longer exists.
#[test]
fn test_a_437_to_a_create_permission_ends_the_allocation() -> Result<()> {
    let now = Instant::now();
    let server = TestServer::new()?;
    let mut client = new_client(TransportProtocol::UDP)?;
    let relayed = server.allocate(&mut client, now)?;

    let tid = client
        .relay(relayed)?
        .create_permission(now, peer())?
        .expect("a new permission is requested");
    let request = server.next_request(&mut client);
    server.reject(&mut client, now, &request, CODE_ALLOC_MISMATCH)?;

    match client.poll_event() {
        Some(Event::CreatePermissionError(id, err)) => {
            assert_eq!(id, tid);
            assert!(err.is(CODE_ALLOC_MISMATCH), "{err}");
        }
        other => panic!("expected CreatePermissionError, got {other:?}"),
    }
    assert!(matches!(
        client.poll_event(),
        Some(Event::AllocationLost(addr, err)) if addr == relayed && err.is(CODE_ALLOC_MISMATCH)
    ));
    assert!(client.relay(relayed).is_err());
    client.close()
}

/// The same for a permission refresh, which no caller waits on.
#[test]
fn test_a_437_to_a_permission_refresh_ends_the_allocation() -> Result<()> {
    let now = Instant::now();
    let server = TestServer::new()?;
    let mut client = new_client(TransportProtocol::UDP)?;
    let relayed = server.allocate(&mut client, now)?;
    server.permit(&mut client, now, relayed, peer())?;

    let (requests, _) = drive_until(&server, &mut client, now + Duration::from_secs(120))?;
    let refresh = requests
        .iter()
        .find(|r| r.typ.method == METHOD_CREATE_PERMISSION)
        .expect("the permission is refreshed at 120 s");
    let at = now + Duration::from_secs(120);
    server.reject(&mut client, at, refresh, CODE_ALLOC_MISMATCH)?;

    assert!(matches!(
        client.poll_event(),
        Some(Event::AllocationLost(addr, err)) if addr == relayed && err.is(CODE_ALLOC_MISMATCH)
    ));
    assert!(client.relay(relayed).is_err());
    client.close()
}

/// RFC 8656 §8: an allocation whose Refresh requests all go unanswered is refreshed sooner
/// than the usual interval while it has time left, and is gone when its lifetime has run out.
#[test]
fn test_an_allocation_no_refresh_reaches_ends_with_its_lifetime() -> Result<()> {
    let now = Instant::now();
    let server = TestServer::new()?;
    let mut client = new_client(TransportProtocol::UDP)?;
    let relayed = server.allocate(&mut client, now)?;

    // Nobody answers. The first Refresh goes out at half the 600 s lifetime.
    let (requests, events) = drive_until(&server, &mut client, now + Duration::from_secs(599))?;
    let attempts: std::collections::HashSet<TransactionId> = requests
        .iter()
        .filter(|r| r.typ.method == METHOD_REFRESH)
        .map(|r| r.transaction_id)
        .collect();
    // Each transaction waits the 39.5 s of RFC 8489 §6.2.1 and is started again once: the
    // Refresh of 300 s, the one at half the time then left, and the one at half of that.
    assert!(
        attempts.len() >= 4,
        "the Refresh is tried again before the lifetime ends, not once: {} transactions",
        attempts.len()
    );
    assert!(
        events
            .iter()
            .any(|e| matches!(e, Event::RefreshError(addr, RequestError::Failed(Error::ErrTimeout)) if *addr == relayed)),
        "a Refresh that fails is reported: {events:?}"
    );
    assert!(
        !events
            .iter()
            .any(|e| matches!(e, Event::AllocationLost(..))),
        "the allocation is kept while its lifetime lasts"
    );
    assert!(client.relay(relayed).is_ok());

    let (_, events) = drive_until(&server, &mut client, now + Duration::from_secs(700))?;
    assert!(
        events
            .iter()
            .any(|e| matches!(e, Event::AllocationLost(addr, _) if *addr == relayed)),
        "an allocation whose lifetime ran out with no Refresh answered is lost: {events:?}"
    );
    assert!(client.relay(relayed).is_err());
    let (requests, _) = drive_until(&server, &mut client, now + Duration::from_secs(7200))?;
    assert!(requests.is_empty(), "nothing more is sent for it");
    client.close()
}

/// A Refresh the server refuses with something other than 437 is reported with its code and
/// the allocation is kept: only 437 says it is gone (RFC 8656 §8.3).
#[test]
fn test_a_refused_refresh_is_reported_and_the_allocation_kept() -> Result<()> {
    let now = Instant::now();
    let server = TestServer::new()?;
    let mut client = new_client(TransportProtocol::UDP)?;
    let relayed = server.allocate(&mut client, now)?;

    client.refresh_allocations(now)?;
    let refresh = server.next_request(&mut client);
    server.reject(&mut client, now, &refresh, CODE_WRONG_CREDENTIALS)?;
    match client.poll_event() {
        Some(Event::RefreshError(addr, err)) => {
            assert_eq!(addr, relayed);
            assert!(err.is(CODE_WRONG_CREDENTIALS), "{err}");
        }
        other => panic!("expected RefreshError, got {other:?}"),
    }
    assert!(client.relay(relayed).is_ok());
    client.close()
}

/// RFC 8656 §10.2: the server refuses a CreatePermission for one address it will not permit,
/// and with it every other address in the request. A refused refresh is repeated address by
/// address, so the permissions the server does grant stay.
#[test]
fn test_a_refused_refresh_batch_ends_only_the_refused_permission() -> Result<()> {
    let now = Instant::now();
    let server = TestServer::new()?;
    let mut client = new_client(TransportProtocol::UDP)?;
    let relayed = server.allocate(&mut client, now)?;
    let good: SocketAddr = "198.51.100.7:4000".parse().unwrap();
    let bad: SocketAddr = "198.51.100.66:4000".parse().unwrap();
    server.permit(&mut client, now, relayed, good)?;
    server.permit(&mut client, now, relayed, bad)?;

    let (requests, _) = drive_until(&server, &mut client, now + Duration::from_secs(120))?;
    let batch = requests
        .iter()
        .find(|r| r.typ.method == METHOD_CREATE_PERMISSION)
        .expect("the permissions are refreshed at 120 s");
    assert_eq!(peers_of(batch).len(), 2);
    let at = now + Duration::from_secs(120);
    server.reject(&mut client, at, batch, CODE_FORBIDDEN)?;
    assert!(client.poll_event().is_none(), "nothing ended yet");

    let singles = server.requests(&mut client);
    assert_eq!(singles.len(), 2, "one request per address: {singles:?}");
    for request in &singles {
        match peers_of(request).as_slice() {
            [one] if one.ip() == good.ip() => server.succeed(&mut client, at, request)?,
            [one] if one.ip() == bad.ip() => {
                server.reject(&mut client, at, request, CODE_FORBIDDEN)?
            }
            other => panic!("expected one peer per request, got {other:?}"),
        }
    }
    assert!(matches!(
        client.poll_event(),
        Some(Event::PermissionLost(addr, ip, err))
            if addr == relayed && ip == bad.ip() && err.is(CODE_FORBIDDEN)
    ));
    assert!(client.poll_event().is_none());

    // 300 s after the first grant the good permission lives on its refresh.
    let later = now + Duration::from_secs(310);
    client.relay(relayed)?.send_to(later, b"x", good)?;
    assert_eq!(
        client.relay(relayed)?.send_to(later, b"x", bad).err(),
        Some(Error::ErrNoPermission)
    );
    client.close()
}

/// RFC 8656 §7.3: a success response the client cannot use still made an allocation on the
/// server. The caller is told under its id, and the allocation is deleted with a Refresh of
/// LIFETIME 0 instead of holding the 5-tuple until it expires.
#[test]
fn test_an_unusable_allocate_success_is_reported_and_the_allocation_deleted() -> Result<()> {
    let now = Instant::now();
    let server = TestServer::new()?;
    let mut client = new_client(TransportProtocol::UDP)?;
    let tid = client.allocate(now)?;
    let attempt = server.next_request(&mut client);
    server.answer(
        &mut client,
        now,
        &attempt,
        CLASS_ERROR_RESPONSE,
        vec![
            Box::new(ErrorCodeAttribute {
                code: CODE_UNAUTHORIZED,
                reason: b"Unauthorized".to_vec(),
            }),
            Box::new(Nonce::new(ATTR_NONCE, "nonce".to_owned())),
            Box::new(Realm::new(ATTR_REALM, REALM.to_owned())),
        ],
        None,
    )?;
    let allocate = server.next_request(&mut client);
    // A relayed address and no LIFETIME.
    server.answer(
        &mut client,
        now,
        &allocate,
        CLASS_SUCCESS_RESPONSE,
        vec![Box::new(RelayedAddress {
            ip: relayed_addr().ip(),
            port: relayed_addr().port(),
        })],
        Some(&server.key),
    )?;

    match client.poll_event() {
        Some(Event::AllocateError(id, RequestError::Failed(_))) => assert_eq!(id, tid),
        other => panic!("expected AllocateError, got {other:?}"),
    }
    assert!(client.relay(relayed_addr()).is_err());

    let mut release = server.next_request(&mut client);
    assert_eq!(release.typ.method, METHOD_REFRESH);
    assert_eq!(lifetime_of(&release)?, Duration::ZERO);
    MessageIntegrity::check(&mut release, &server.key, test_crypto_provider().crypto())?;
    server.accept(&mut client, now, &release)?;
    assert!(
        client.poll_event().is_none(),
        "the clean-up is not an event"
    );

    // Unanswered, it ends without an event either.
    let (_, events) = drive_until(&server, &mut client, now + Duration::from_secs(120))?;
    assert!(events.is_empty(), "{events:?}");
    client.close()
}

/// RFC 8656 §7.4: an error response fails the Allocate, and the application learns which
/// error. Whatever the code, known or not, the client sends nothing more to the server by
/// itself (RFC 8489 §6.3.4: an unknown code is handled by its class).
#[test]
fn test_an_allocate_error_carries_its_code_and_is_not_retried() -> Result<()> {
    // After authenticating: 400, a second 401, 403, 440, 441, 442, 486, 508, and codes no
    // RFC defines, one in the 4xx class and one in the 5xx.
    for code in [400u16, 401, 403, 440, 441, 442, 486, 508, 499, 599] {
        let now = Instant::now();
        let server = TestServer::new()?;
        let mut client = new_client(TransportProtocol::UDP)?;
        let tid = client.allocate(now)?;
        let attempt = server.next_request(&mut client);
        server.answer(
            &mut client,
            now,
            &attempt,
            CLASS_ERROR_RESPONSE,
            vec![
                Box::new(ErrorCodeAttribute {
                    code: CODE_UNAUTHORIZED,
                    reason: b"Unauthorized".to_vec(),
                }),
                Box::new(Nonce::new(ATTR_NONCE, "nonce".to_owned())),
                Box::new(Realm::new(ATTR_REALM, REALM.to_owned())),
            ],
            None,
        )?;
        let allocate = server.next_request(&mut client);
        // A 401 is the one error the server may leave unsigned.
        let key = (code != 401).then_some(server.key.as_slice());
        server.answer(
            &mut client,
            now,
            &allocate,
            CLASS_ERROR_RESPONSE,
            vec![Box::new(ErrorCodeAttribute {
                code: ErrorCode(code),
                reason: b"no".to_vec(),
            })],
            key,
        )?;
        match client.poll_event() {
            Some(Event::AllocateError(id, RequestError::Rejected(response))) => {
                assert_eq!(id, tid, "{code}");
                assert!(response.code == ErrorCode(code), "{response}");
                assert_eq!(response.reason, "no");
            }
            other => panic!("{code}: expected AllocateError, got {other:?}"),
        }
        let (requests, events) =
            drive_until(&server, &mut client, now + Duration::from_secs(3600))?;
        assert!(requests.is_empty(), "{code}: {requests:?}");
        assert!(events.is_empty(), "{code}: {events:?}");
        client.close()?;
    }
    Ok(())
}

/// The first Allocate carries no credential, and only a 401 asks for one. Any other error is
/// the answer to the Allocate and keeps its code; it used to be read as a challenge and
/// reported as a missing attribute.
#[test]
fn test_an_error_to_the_first_allocate_keeps_its_code() -> Result<()> {
    for code in [300u16, 403, 442, 486, 508] {
        let now = Instant::now();
        let server = TestServer::new()?;
        let mut client = new_client(TransportProtocol::UDP)?;
        let tid = client.allocate(now)?;
        let first = server.next_request(&mut client);
        server.answer(
            &mut client,
            now,
            &first,
            CLASS_ERROR_RESPONSE,
            vec![
                Box::new(ErrorCodeAttribute {
                    code: ErrorCode(code),
                    reason: b"no".to_vec(),
                }),
                // Even with these, it is not a challenge.
                Box::new(Nonce::new(ATTR_NONCE, "nonce".to_owned())),
                Box::new(Realm::new(ATTR_REALM, REALM.to_owned())),
            ],
            None,
        )?;
        match client.poll_event() {
            Some(Event::AllocateError(id, err)) => {
                assert_eq!(id, tid, "{code}");
                assert!(err.is(ErrorCode(code)), "{err}");
            }
            other => panic!("{code}: expected AllocateError, got {other:?}"),
        }
        assert!(
            server.requests(&mut client).is_empty(),
            "{code}: no authenticated Allocate follows"
        );
        client.close()?;
    }
    Ok(())
}

/// An allocation the server gave without a credential is used without one, until the server
/// asks: a 401 with a realm and a nonce is then answered with the long-term credential.
#[test]
fn test_an_allocation_made_without_a_credential_authenticates_when_asked() -> Result<()> {
    let now = Instant::now();
    let server = TestServer::new()?;
    let mut client = new_client(TransportProtocol::UDP)?;
    client.allocate(now)?;
    let first = server.next_request(&mut client);
    server.answer(
        &mut client,
        now,
        &first,
        CLASS_SUCCESS_RESPONSE,
        vec![
            Box::new(RelayedAddress {
                ip: relayed_addr().ip(),
                port: relayed_addr().port(),
            }),
            Box::new(Lifetime(Duration::from_secs(600))),
        ],
        None,
    )?;
    while client.poll_event().is_some() {}

    let tid = client
        .relay(relayed_addr())?
        .create_permission(now, peer())?
        .expect("a new permission is requested");
    let unsigned = server.next_request(&mut client);
    assert!(!unsigned.contains(ATTR_MESSAGE_INTEGRITY));
    assert!(!unsigned.contains(ATTR_USERNAME));
    assert!(unsigned.contains(ATTR_FINGERPRINT));

    server.answer(
        &mut client,
        now,
        &unsigned,
        CLASS_ERROR_RESPONSE,
        vec![
            Box::new(ErrorCodeAttribute {
                code: CODE_UNAUTHORIZED,
                reason: b"Unauthorized".to_vec(),
            }),
            Box::new(Nonce::new(ATTR_NONCE, "asked".to_owned())),
            Box::new(Realm::new(ATTR_REALM, REALM.to_owned())),
        ],
        None,
    )?;
    let mut signed = server.next_request(&mut client);
    assert_eq!(nonce_of(&signed), "asked");
    MessageIntegrity::check(&mut signed, &server.key, test_crypto_provider().crypto())?;
    server.succeed(&mut client, now, &signed)?;
    assert!(matches!(
        client.poll_event(),
        Some(Event::CreatePermissionResponse(id, addr)) if id == tid && addr == peer()
    ));
    client.close()
}
