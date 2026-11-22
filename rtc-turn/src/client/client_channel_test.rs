//! Channels and relayed data (RFC 8656 §11, §12): what goes out as ChannelData and what as a
//! Send indication, what a ChannelBind failure does, and which relayed data is delivered.
use super::test_server::*;
use super::*;
use sansio::Protocol;
use stun::error_code::*;

fn peer() -> SocketAddr {
    "198.51.100.7:4000".parse().unwrap()
}

fn from_server(now: Instant, bytes: &[u8]) -> TransportMessage<BytesMut> {
    TransportMessage {
        now,
        transport: TransportContext {
            local_addr: local_addr(),
            peer_addr: server_addr(),
            transport_protocol: TransportProtocol::UDP,
            ecn: None,
        },
        message: BytesMut::from(bytes),
    }
}

fn channel_data(number: u16, payload: &[u8]) -> Result<Vec<u8>> {
    let mut data = ChannelData {
        data: payload.to_vec(),
        number: ChannelNumber(number),
        ..Default::default()
    };
    data.encode()?;
    Ok(data.raw)
}

fn data_indication(from: SocketAddr, payload: &[u8]) -> Result<Vec<u8>> {
    let mut msg = Message::new();
    msg.build(&[
        Box::new(MessageType::new(METHOD_DATA, CLASS_INDICATION)),
        Box::new(TransactionId::new()),
        Box::new(PeerAddress {
            ip: from.ip(),
            port: from.port(),
        }),
        Box::new(Data(payload.to_vec())),
    ])?;
    Ok(msg.raw)
}

fn channel_number_of(request: &Message) -> Result<u16> {
    let mut number = ChannelNumber::default();
    number.get_from(request)?;
    Ok(number.0)
}

/// An allocation with a permission for [`peer`] and a ChannelBind for it on the wire.
fn binding(
    server: &TestServer,
    client: &mut Client,
    now: Instant,
) -> Result<(RelayedAddr, Message)> {
    let relayed = server.allocate(client, now)?;
    server.permit(client, now, relayed, peer())?;
    client.relay(relayed)?.send_to(now, b"first", peer())?;
    let bind = server.next_request(client);
    assert_eq!(bind.typ.method, METHOD_CHANNEL_BIND);
    Ok((relayed, bind))
}

/// RFC 8656 §11.1: a Send indication carries XOR-PEER-ADDRESS and DATA, and is what data goes
/// in until the channel is bound.
#[test]
fn test_a_send_indication_carries_the_peer_address_and_the_data() -> Result<()> {
    let now = Instant::now();
    let server = TestServer::new()?;
    let mut client = new_client(TransportProtocol::UDP)?;
    let relayed = server.allocate(&mut client, now)?;
    server.permit(&mut client, now, relayed, peer())?;

    client.relay(relayed)?.send_to(now, b"payload", peer())?;
    let out = sent(&mut client);
    let indication = out
        .iter()
        .find_map(|s| match s {
            Sent::Indication(i) => Some(i),
            _ => None,
        })
        .expect("a Send indication");
    assert_eq!(
        indication.typ,
        MessageType::new(METHOD_SEND, CLASS_INDICATION)
    );
    assert_eq!(peers_of(indication), vec![peer()]);
    let mut data = Data::default();
    data.get_from(indication)?;
    assert_eq!(data.0, b"payload");
    assert!(
        indication.contains(ATTR_FINGERPRINT),
        "the client's STUN messages carry FINGERPRINT"
    );
    assert!(out.iter().all(|s| !matches!(s, Sent::ChannelData(_))));
    client.close()
}

/// RFC 8656 §12.4, §12.5: once the channel is bound the data goes as ChannelData: the channel
/// number, the length of the data without padding, the data, and padding to four bytes.
#[test]
fn test_data_on_a_bound_channel_goes_as_padded_channel_data() -> Result<()> {
    let now = Instant::now();
    let server = TestServer::new()?;
    let mut client = new_client(TransportProtocol::UDP)?;
    let (relayed, bind) = binding(&server, &mut client, now)?;
    let number = channel_number_of(&bind)?;
    assert!((0x4000..=0x4FFF).contains(&number));
    server.succeed(&mut client, now, &bind)?;

    for payload in [&b""[..], b"a", b"ab", b"abc", b"abcd", b"abcde"] {
        client.relay(relayed)?.send_to(now, payload, peer())?;
        match sent(&mut client).as_slice() {
            [Sent::ChannelData(raw)] => {
                assert_eq!(u16::from_be_bytes([raw[0], raw[1]]), number);
                assert_eq!(
                    usize::from(u16::from_be_bytes([raw[2], raw[3]])),
                    payload.len(),
                    "the length leaves the padding out"
                );
                assert_eq!(&raw[4..4 + payload.len()], payload);
                assert_eq!(raw.len() % 4, 0, "padded to a multiple of four");
                assert_eq!(raw.len(), 4 + payload.len().div_ceil(4) * 4);
                assert!(raw[4 + payload.len()..].iter().all(|b| *b == 0));
            }
            other => panic!("expected one ChannelData, got {other:?}"),
        }
    }
    client.close()
}

/// RFC 8656 §12: the client is prepared to receive ChannelData on a channel as soon as it has
/// sent the ChannelBind, before the response.
#[test]
fn test_channel_data_is_accepted_while_the_channel_bind_is_outstanding() -> Result<()> {
    let now = Instant::now();
    let server = TestServer::new()?;
    let mut client = new_client(TransportProtocol::UDP)?;
    let (relayed, bind) = binding(&server, &mut client, now)?;
    let number = channel_number_of(&bind)?;
    assert_eq!(
        binding_state(&client, relayed, peer()),
        Some(binding::BindingState::Request)
    );

    client.handle_read(from_server(now, &channel_data(number, b"early")?))?;
    match client.poll_event() {
        Some(Event::DataIndicationOrChannelData(Some(n), from, data)) => {
            assert_eq!(n.0, number);
            assert_eq!(from, peer());
            assert_eq!(&data[..], b"early");
        }
        other => panic!("expected the data, got {other:?}"),
    }
    client.close()
}

/// RFC 8656 §12.6: ChannelData on a channel that is not bound is discarded.
#[test]
fn test_channel_data_on_an_unbound_channel_is_discarded() -> Result<()> {
    let now = Instant::now();
    let server = TestServer::new()?;
    let mut client = new_client(TransportProtocol::UDP)?;
    let (_, bind) = binding(&server, &mut client, now)?;
    let other = channel_number_of(&bind)? + 1;

    let _ = client.handle_read(from_server(now, &channel_data(other, b"stray")?));
    assert!(client.poll_event().is_none(), "nothing is delivered for it");
    client.close()
}

/// RFC 8656 §11.4, §12.6: the server relays only from peers the client installed a permission
/// for, so the client discards a Data indication or ChannelData from any other address.
#[test]
fn test_relayed_data_from_a_peer_without_a_permission_is_discarded() -> Result<()> {
    let now = Instant::now();
    let server = TestServer::new()?;
    let mut client = new_client(TransportProtocol::UDP)?;
    let (relayed, bind) = binding(&server, &mut client, now)?;
    let number = channel_number_of(&bind)?;
    server.succeed(&mut client, now, &bind)?;

    let stranger: SocketAddr = "203.0.113.99:7".parse().unwrap();
    client.handle_read(from_server(now, &data_indication(stranger, b"x")?))?;
    assert!(
        client.poll_event().is_none(),
        "a Data indication from an address with no permission was delivered"
    );
    // Another port of a permitted address is covered by its permission.
    let sibling = SocketAddr::new(peer().ip(), 9);
    client.handle_read(from_server(now, &data_indication(sibling, b"x")?))?;
    assert!(matches!(
        client.poll_event(),
        Some(Event::DataIndicationOrChannelData(None, from, _)) if from == sibling
    ));

    // The permission goes: the server refuses its refresh.
    let (requests, _) = drive_until(&server, &mut client, now + Duration::from_secs(120))?;
    let at = now + Duration::from_secs(120);
    let refresh = requests
        .iter()
        .find(|r| r.typ.method == METHOD_CREATE_PERMISSION)
        .expect("the permission is refreshed at 120 s");
    server.reject(&mut client, at, refresh, CODE_FORBIDDEN)?;
    while client.poll_event().is_some() {}
    assert!(client.relay(relayed).is_ok());

    client.handle_read(from_server(at, &channel_data(number, b"x")?))?;
    assert!(
        client.poll_event().is_none(),
        "ChannelData from a peer whose permission ended was delivered"
    );
    client.handle_read(from_server(at, &data_indication(peer(), b"x")?))?;
    assert!(client.poll_event().is_none());
    client.close()
}

/// RFC 8656 §11.4: a Data indication without XOR-PEER-ADDRESS, or without DATA, is discarded.
#[test]
fn test_a_data_indication_missing_an_attribute_is_discarded() -> Result<()> {
    let now = Instant::now();
    let server = TestServer::new()?;
    let mut client = new_client(TransportProtocol::UDP)?;
    let relayed = server.allocate(&mut client, now)?;
    server.permit(&mut client, now, relayed, peer())?;

    let mut no_peer = Message::new();
    no_peer.build(&[
        Box::new(MessageType::new(METHOD_DATA, CLASS_INDICATION)),
        Box::new(TransactionId::new()),
        Box::new(Data(b"x".to_vec())),
    ])?;
    let _ = client.handle_read(from_server(now, &no_peer.raw));
    assert!(client.poll_event().is_none());

    let mut no_data = Message::new();
    no_data.build(&[
        Box::new(MessageType::new(METHOD_DATA, CLASS_INDICATION)),
        Box::new(TransactionId::new()),
        Box::new(PeerAddress {
            ip: peer().ip(),
            port: peer().port(),
        }),
    ])?;
    let _ = client.handle_read(from_server(now, &no_data.raw));
    assert!(client.poll_event().is_none());
    client.close()
}

/// RFC 8656 §12.3: a ChannelBind the server refuses is reported with its code. The data keeps
/// going as Send indications, and the ChannelBind is not sent again with every one of them.
#[test]
fn test_a_refused_channel_bind_is_reported_and_not_repeated_per_packet() -> Result<()> {
    let now = Instant::now();
    let server = TestServer::new()?;
    let mut client = new_client(TransportProtocol::UDP)?;
    let (relayed, bind) = binding(&server, &mut client, now)?;
    server.reject(&mut client, now, &bind, CODE_INSUFFICIENT_CAPACITY)?;

    match client.poll_event() {
        Some(Event::ChannelBindError(addr, to, err)) => {
            assert_eq!(addr, relayed);
            assert_eq!(to, peer());
            assert!(err.is(CODE_INSUFFICIENT_CAPACITY), "{err}");
        }
        other => panic!("expected ChannelBindError, got {other:?}"),
    }
    assert!(client.poll_event().is_none(), "the allocation is kept");

    for i in 0..5u64 {
        client
            .relay(relayed)?
            .send_to(now + Duration::from_secs(i), b"x", peer())?;
    }
    let out = sent(&mut client);
    assert_eq!(out.len(), 5, "{out:?}");
    assert!(out.iter().all(|s| matches!(s, Sent::Indication(_))));

    // Later it is tried again, on the same number.
    let later = now + Duration::from_secs(61);
    client.relay(relayed)?.send_to(later, b"x", peer())?;
    let again = server.next_request(&mut client);
    assert_eq!(again.typ.method, METHOD_CHANNEL_BIND);
    assert_eq!(channel_number_of(&again)?, channel_number_of(&bind)?);
    client.close()
}

/// RFC 8656 §5: a 437 to a ChannelBind means the allocation no longer exists.
#[test]
fn test_a_437_to_a_channel_bind_ends_the_allocation() -> Result<()> {
    let now = Instant::now();
    let server = TestServer::new()?;
    let mut client = new_client(TransportProtocol::UDP)?;
    let (relayed, bind) = binding(&server, &mut client, now)?;
    server.reject(&mut client, now, &bind, CODE_ALLOC_MISMATCH)?;

    assert!(matches!(
        client.poll_event(),
        Some(Event::ChannelBindError(addr, to, err))
            if addr == relayed && to == peer() && err.is(CODE_ALLOC_MISMATCH)
    ));
    assert!(matches!(
        client.poll_event(),
        Some(Event::AllocationLost(addr, err)) if addr == relayed && err.is(CODE_ALLOC_MISMATCH)
    ));
    assert!(client.relay(relayed).is_err());
    assert!(server.requests(&mut client).is_empty());
    client.close()
}

/// RFC 8656 §12.3: a 400 to a ChannelBind shows the channels of client and server out of
/// step; the client deletes the allocation at once, so the application can start afresh.
#[test]
fn test_a_400_to_a_channel_bind_deletes_the_allocation() -> Result<()> {
    let now = Instant::now();
    let server = TestServer::new()?;
    let mut client = new_client(TransportProtocol::UDP)?;
    let (relayed, bind) = binding(&server, &mut client, now)?;
    let _ = sent(&mut client);
    server.reject(&mut client, now, &bind, CODE_BAD_REQUEST)?;

    assert!(matches!(
        client.poll_event(),
        Some(Event::ChannelBindError(addr, to, err))
            if addr == relayed && to == peer() && err.is(CODE_BAD_REQUEST)
    ));
    assert!(matches!(
        client.poll_event(),
        Some(Event::AllocationLost(addr, err)) if addr == relayed && err.is(CODE_BAD_REQUEST)
    ));
    assert!(client.relay(relayed).is_err());

    let mut release = server.next_request(&mut client);
    assert_eq!(release.typ.method, METHOD_REFRESH);
    let mut lifetime = Lifetime::default();
    lifetime.get_from(&release)?;
    assert_eq!(lifetime.0, Duration::ZERO, "the allocation is deleted");
    MessageIntegrity::check(&mut release, &server.key, test_crypto_provider().crypto())?;
    client.close()
}

/// RFC 8656 §12.3: a ChannelBind success also installs or refreshes the permission for the
/// peer's address.
#[test]
fn test_a_channel_bind_success_refreshes_the_permission() -> Result<()> {
    let now = Instant::now();
    let server = TestServer::new()?;
    let mut client = new_client(TransportProtocol::UDP)?;
    let relayed = server.allocate(&mut client, now)?;
    server.permit(&mut client, now, relayed, peer())?;

    // The bind is answered 200 s after the permission was installed; no permission refresh
    // is ever answered.
    let at = now + Duration::from_secs(200);
    let _ = drive_until(&server, &mut client, at)?;
    client.relay(relayed)?.send_to(at, b"x", peer())?;
    let bind = server.next_request(&mut client);
    assert_eq!(bind.typ.method, METHOD_CHANNEL_BIND);
    server.succeed(&mut client, at, &bind)?;

    let later = now + Duration::from_secs(450);
    client.relay(relayed)?.send_to(later, b"x", peer())?;
    let much_later = now + Duration::from_secs(501);
    assert_eq!(
        client
            .relay(relayed)?
            .send_to(much_later, b"x", peer())
            .err(),
        Some(Error::ErrNoPermission),
        "300 s after the bind, with nothing refreshed since"
    );
    client.close()
}

/// RFC 8656 §12: a channel number is not bound to another peer address, nor a peer address
/// to another number, until 5 minutes after the binding expired: 15 minutes after the last
/// ChannelBind sent for it.
#[test]
fn test_a_channel_number_is_reused_only_after_the_binding_expired_and_five_minutes() -> Result<()> {
    let now = Instant::now();
    let server = TestServer::new()?;
    let mut client = new_client(TransportProtocol::UDP)?;
    let relayed = server.allocate(&mut client, now)?;
    server.permit(&mut client, now, relayed, peer())?;

    // Every number is bound at `now`; the first of them once more, five minutes later.
    let mut numbers = std::collections::HashMap::new();
    for port in 0..4096u16 {
        let to = SocketAddr::new(peer().ip(), 10_000 + port);
        client.relay(relayed)?.send_to(now, b"x", to)?;
        for one in sent(&mut client) {
            if let Sent::Request(bind) = one {
                numbers.insert(channel_number_of(&bind)?, to);
                server.succeed(&mut client, now, &bind)?;
            }
        }
    }
    assert_eq!(numbers.len(), 4096, "every channel number is in use");
    let kept = SocketAddr::new(peer().ip(), 10_000);
    let rebound_at = now + Duration::from_secs(301);
    let (_, _) = drive_accepting(&server, &mut client, rebound_at)?;
    client.relay(relayed)?.send_to(rebound_at, b"x", kept)?;
    let (out, _) = drive_accepting(&server, &mut client, rebound_at)?;
    assert!(
        out.iter().any(
            |s| matches!(s, Sent::Request(r) if r.typ.method == METHOD_CHANNEL_BIND && peers_of(r) == vec![kept])
        ),
        "a binding older than five minutes is rebound by a send"
    );

    // Just short of 15 minutes after the binds: no number is free for a new peer address.
    let newcomer = SocketAddr::new(peer().ip(), 20_000);
    let early = now + Duration::from_secs(899);
    let (_, _) = drive_accepting(&server, &mut client, early)?;
    client.relay(relayed)?.send_to(early, b"x", newcomer)?;
    let out = sent(&mut client);
    assert!(
        matches!(out.as_slice(), [Sent::Indication(_)]),
        "no ChannelBind while every number is bound or waiting: {out:?}"
    );

    // At 15 minutes the numbers bound at `now` are free; the one rebound later is not.
    let late = now + Duration::from_secs(900);
    client.relay(relayed)?.send_to(late, b"x", newcomer)?;
    let bind = sent(&mut client)
        .into_iter()
        .find_map(|s| match s {
            Sent::Request(r) if r.typ.method == METHOD_CHANNEL_BIND => Some(r),
            _ => None,
        })
        .expect("a ChannelBind for the new peer address");
    assert_eq!(peers_of(&bind), vec![newcomer]);
    let number = channel_number_of(&bind)?;
    assert_ne!(
        numbers[&number], kept,
        "the number of a binding refreshed 10 minutes ago was taken"
    );
    client.close()
}
