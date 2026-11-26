//! TCP allocations (RFC 6062, client side): the Allocate on the control connection, Connect,
//! ConnectionAttempt, and the data connections that carry each peer's bytes.
use super::data_connection::{CONNECTION_BIND_TIMEOUT, DataConnection, DataConnectionEvent};
use super::test_server::*;
use super::*;
use crate::proto::connid::ConnectionId;
use crate::proto::evenport::EvenPort;
use crate::proto::rsrvtoken::ReservationToken;
use sansio::Protocol;
use stun::error_code::*;

fn peer() -> SocketAddr {
    "198.51.100.7:4000".parse().unwrap()
}

fn other_peer() -> SocketAddr {
    "198.51.100.8:4000".parse().unwrap()
}

/// The local address of a data connection: the control connection's host, another port.
fn data_local() -> SocketAddr {
    "127.0.0.1:50001".parse().unwrap()
}

fn tcp() -> AllocateOptions {
    AllocateOptions {
        transport: RelayTransport::Tcp,
        ..Default::default()
    }
}

/// A client over TCP holding a TCP allocation.
fn tcp_allocation(server: &TestServer, now: Instant) -> Result<Client> {
    let mut client = new_client(TransportProtocol::TCP)?;
    let (tid, _) = server.allocate_with(
        &mut client,
        now,
        tcp(),
        vec![relayed(relayed_addr()), lifetime(600)],
    )?;
    assert!(matches!(
        client.poll_event(),
        Some(Event::AllocateResponse(id, addr)) if id == tid && addr == relayed_addr()
    ));
    Ok(client)
}

fn connection_id_of(m: &Message) -> Result<u32> {
    let mut id = ConnectionId::default();
    id.get_from(m)?;
    Ok(id.0)
}

/// The next message a data connection queued, decoded, and where it goes.
fn next_bind(connection: &mut DataConnection) -> (Message, TransportContext) {
    let out = connection.poll_write().expect("a ConnectionBind is queued");
    let mut msg = Message::new();
    msg.raw = out.message.to_vec();
    msg.decode().expect("the data connection's message decodes");
    (msg, out.transport)
}

fn chunk(now: Instant, bytes: &[u8]) -> TransportMessage<BytesMut> {
    TransportMessage {
        now,
        transport: TransportContext {
            local_addr: data_local(),
            peer_addr: server_addr(),
            transport_protocol: TransportProtocol::TCP,
            ecn: None,
        },
        message: BytesMut::from(bytes),
    }
}

/// A bound data connection for connection 7 of a TCP allocation.
fn bound(server: &TestServer, client: &mut Client, now: Instant) -> Result<DataConnection> {
    let mut connection =
        client
            .relay(relayed_addr())?
            .data_connection(now, ConnectionId(7), data_local())?;
    let (bind, _) = next_bind(&mut connection);
    let success = server.reply(&bind, CLASS_SUCCESS_RESPONSE, vec![], Some(&server.key))?;
    connection.handle_read(chunk(now, &success))?;
    assert_eq!(connection.poll_event(), Some(DataConnectionEvent::Bound));
    Ok(connection)
}

/// RFC 6062 §4.1: a TCP allocation is asked for over TCP (or TLS) to the server, never over
/// UDP; its Allocate carries REQUESTED-TRANSPORT 6, and authenticates as any Allocate does.
#[test]
fn test_a_tcp_allocation_is_requested_over_tcp_with_requested_transport_tcp() -> Result<()> {
    let now = Instant::now();
    let server = TestServer::new()?;

    let mut over_udp = new_client(TransportProtocol::UDP)?;
    assert!(
        over_udp.allocate_with(now, tcp()).is_err(),
        "a TCP allocation cannot be had over UDP"
    );
    assert!(over_udp.poll_write().is_none(), "nothing is sent");

    let mut client = new_client(TransportProtocol::TCP)?;
    let options = AllocateOptions {
        lifetime: Some(Duration::from_secs(1800)),
        ..tcp()
    };
    let (tid, first, authenticated) = server.begin_allocate(&mut client, now, options)?;
    for request in [&first, &authenticated] {
        assert_eq!(
            request.typ,
            MessageType::new(METHOD_ALLOCATE, CLASS_REQUEST)
        );
        assert_eq!(
            values_of(request, ATTR_REQUESTED_TRANSPORT),
            vec![vec![6, 0, 0, 0]],
            "REQUESTED-TRANSPORT is 6 (TCP)"
        );
        // LIFETIME may be included (RFC 6062 §4.1).
        let mut lifetime = Lifetime::default();
        lifetime.get_from(request)?;
        assert_eq!(lifetime.0, Duration::from_secs(1800));
        for udp_only in [ATTR_DONT_FRAGMENT, ATTR_EVEN_PORT, ATTR_RESERVATION_TOKEN] {
            assert!(!request.contains(udp_only));
        }
    }
    let mut signed = authenticated.clone();
    MessageIntegrity::check(&mut signed, &server.key, test_crypto_provider().crypto())?;

    server.answer(
        &mut client,
        now,
        &authenticated,
        CLASS_SUCCESS_RESPONSE,
        vec![relayed(relayed_addr()), lifetime(600)],
        Some(&server.key),
    )?;
    assert!(matches!(
        client.poll_event(),
        Some(Event::AllocateResponse(id, addr)) if id == tid && addr == relayed_addr()
    ));
    assert_eq!(
        client.relay(relayed_addr())?.transport(),
        RelayTransport::Tcp
    );
    client.close()
}

/// RFC 6062 §4.1: the Allocate of a TCP allocation "MUST NOT include a DONT-FRAGMENT,
/// RESERVATION-TOKEN, or EVEN-PORT attribute".
#[test]
fn test_a_tcp_allocation_takes_none_of_the_udp_only_options() -> Result<()> {
    let now = Instant::now();
    let mut client = new_client(TransportProtocol::TCP)?;
    let refused = [
        AllocateOptions {
            dont_fragment: true,
            ..tcp()
        },
        AllocateOptions {
            even_port: Some(EvenPort {
                reserve_port: false,
            }),
            ..tcp()
        },
        AllocateOptions {
            reservation_token: Some(ReservationToken(vec![0; 8])),
            ..tcp()
        },
    ];
    for options in refused {
        assert!(
            client.allocate_with(now, options.clone()).is_err(),
            "{options:?}"
        );
        assert!(
            client.poll_write().is_none(),
            "{options:?}: nothing is sent"
        );
    }
    client.close()
}

/// RFC 6062 §4.2, §4.6: the allocation is refreshed as a UDP one is, on the control
/// connection, for as long as it is wanted.
#[test]
fn test_a_tcp_allocation_is_refreshed_on_the_control_connection() -> Result<()> {
    let now = Instant::now();
    let server = TestServer::new()?;
    let mut client = tcp_allocation(&server, now)?;
    // A data connection is up; it sends nothing about the allocation.
    let mut connection = bound(&server, &mut client, now)?;

    let at = now + Duration::from_secs(300);
    client.handle_timeout(at)?;
    let out = client
        .poll_write()
        .expect("the Refresh at half the lifetime");
    assert_eq!(
        out.transport.local_addr,
        local_addr(),
        "the control connection"
    );
    assert_eq!(out.transport.peer_addr, server_addr());
    assert_eq!(out.transport.transport_protocol, TransportProtocol::TCP);
    let mut refresh = Message::new();
    refresh.raw = out.message.to_vec();
    refresh.decode()?;
    assert_eq!(refresh.typ.method, METHOD_REFRESH);
    let mut asked = Lifetime::default();
    asked.get_from(&refresh)?;
    assert_eq!(asked.0, Duration::from_secs(600));
    assert!(connection.poll_write().is_none());
    assert!(connection.poll_timeout().is_none());

    server.accept(&mut client, at, &refresh)?;
    assert!(client.poll_event().is_none());
    assert!(client.relay(relayed_addr()).is_ok());
    client.close()
}

/// RFC 6062 §4.3: Connect, on the control connection, with the peer's XOR-PEER-ADDRESS; the
/// success response's CONNECTION-ID names the connection the server made.
#[test]
fn test_connect_carries_the_peer_address_and_yields_the_connection_id() -> Result<()> {
    let now = Instant::now();
    let server = TestServer::new()?;
    let mut client = tcp_allocation(&server, now)?;

    let tid = client.relay(relayed_addr())?.connect(now, peer())?;
    let out = client.poll_write().expect("the Connect request");
    assert_eq!(
        out.transport.local_addr,
        local_addr(),
        "the control connection"
    );
    assert_eq!(out.transport.peer_addr, server_addr());
    let mut connect = Message::new();
    connect.raw = out.message.to_vec();
    connect.decode()?;
    assert_eq!(connect.transaction_id, tid);
    assert_eq!(connect.typ, MessageType::new(METHOD_CONNECT, CLASS_REQUEST));
    assert_eq!(&connect.raw[..2], &[0x00, 0x0a], "method 0x00a, a request");
    assert_eq!(peers_of(&connect), vec![peer()]);
    let mut signed = connect.clone();
    MessageIntegrity::check(&mut signed, &server.key, test_crypto_provider().crypto())?;

    server.answer(
        &mut client,
        now,
        &connect,
        CLASS_SUCCESS_RESPONSE,
        vec![Box::new(ConnectionId(0x0102_0304))],
        Some(&server.key),
    )?;
    match client.poll_event() {
        Some(Event::ConnectResponse(id, to, connection_id)) => {
            assert_eq!(id, tid);
            assert_eq!(to, peer());
            assert_eq!(connection_id, ConnectionId(0x0102_0304));
        }
        other => panic!("expected ConnectResponse, got {other:?}"),
    }
    client.close()
}

/// RFC 6062 §4.3: several Connect requests may be outstanding, but never two for the same
/// peer address.
#[test]
fn test_one_connect_per_peer_address_at_a_time() -> Result<()> {
    let now = Instant::now();
    let server = TestServer::new()?;
    let mut client = tcp_allocation(&server, now)?;

    client.relay(relayed_addr())?.connect(now, peer())?;
    client.relay(relayed_addr())?.connect(now, other_peer())?;
    let requests = server.requests(&mut client);
    assert_eq!(requests.len(), 2, "to different peers at once");
    assert!(
        client.relay(relayed_addr())?.connect(now, peer()).is_err(),
        "a second Connect to a peer with one outstanding"
    );
    assert!(
        server.requests(&mut client).is_empty(),
        "nothing is sent for it"
    );

    // Answered, the peer can be connected to again (another connection to it).
    let first = requests
        .iter()
        .find(|r| peers_of(r) == vec![peer()])
        .expect("the Connect to the first peer");
    server.answer(
        &mut client,
        now,
        first,
        CLASS_SUCCESS_RESPONSE,
        vec![Box::new(ConnectionId(1))],
        Some(&server.key),
    )?;
    client.relay(relayed_addr())?.connect(now, peer())?;
    assert_eq!(server.requests(&mut client).len(), 1);

    // One that times out frees the peer as well.
    let (_, events) = drive_until(&server, &mut client, now + Duration::from_secs(40))?;
    assert!(
        events
            .iter()
            .any(|e| matches!(e, Event::TransactionTimeout(_)))
    );
    let later = now + Duration::from_secs(40);
    client.relay(relayed_addr())?.connect(later, other_peer())?;
    client.close()
}

/// RFC 6062 §4.3: after a 447 (Connection Timeout or Failure) the client may try the same
/// peer again, "but MUST wait at least 10 seconds".
#[test]
fn test_after_a_447_the_peer_is_not_tried_again_for_ten_seconds() -> Result<()> {
    let now = Instant::now();
    let server = TestServer::new()?;
    let mut client = tcp_allocation(&server, now)?;

    let tid = client.relay(relayed_addr())?.connect(now, peer())?;
    let connect = server.next_request(&mut client);
    server.reject(&mut client, now, &connect, CODE_CONN_TIMEOUT_OR_FAILURE)?;
    match client.poll_event() {
        Some(Event::ConnectError(id, to, err)) => {
            assert_eq!(id, tid);
            assert_eq!(to, peer());
            assert!(err.is(CODE_CONN_TIMEOUT_OR_FAILURE), "{err}");
            assert!(err.is(ErrorCode(447)));
        }
        other => panic!("expected ConnectError, got {other:?}"),
    }

    let too_soon = now + Duration::from_millis(9_999);
    assert!(
        client
            .relay(relayed_addr())?
            .connect(too_soon, peer())
            .is_err()
    );
    assert!(server.requests(&mut client).is_empty());
    // Another peer is not held back.
    client
        .relay(relayed_addr())?
        .connect(too_soon, other_peer())?;
    assert_eq!(server.requests(&mut client).len(), 1);

    let in_time = now + Duration::from_secs(10);
    client.relay(relayed_addr())?.connect(in_time, peer())?;
    let again = server.next_request(&mut client);
    assert_eq!(again.typ.method, METHOD_CONNECT);
    assert_eq!(peers_of(&again), vec![peer()]);

    // 446 (Connection Already Exists) is reported, with no wait.
    server.reject(&mut client, in_time, &again, CODE_CONN_ALREADY_EXISTS)?;
    assert!(matches!(
        client.poll_event(),
        Some(Event::ConnectError(_, to, err)) if to == peer() && err.is(ErrorCode(446))
    ));
    client.relay(relayed_addr())?.connect(in_time, peer())?;
    client.close()
}

/// RFC 6062 §4.3: the data connection goes to the server address the control connection
/// goes to, from another local address, and opens with a ConnectionBind carrying the
/// CONNECTION-ID and the control connection's credential. After the success response it is
/// the client data connection for the peer; §4.5: bytes pass over it as they are, both ways.
#[test]
fn test_a_data_connection_binds_with_the_connection_id_and_then_carries_bytes_as_they_are()
-> Result<()> {
    let now = Instant::now();
    let server = TestServer::new()?;
    let mut client = tcp_allocation(&server, now)?;

    assert!(
        client
            .relay(relayed_addr())?
            .data_connection(now, ConnectionId(7), local_addr())
            .is_err(),
        "a data connection is made from a different local address"
    );

    let mut connection =
        client
            .relay(relayed_addr())?
            .data_connection(now, ConnectionId(7), data_local())?;
    assert_eq!(connection.server_addr(), server_addr());
    assert_eq!(connection.local_addr(), data_local());
    assert_eq!(connection.connection_id(), ConnectionId(7));
    assert!(
        client.poll_write().is_none(),
        "nothing on the control connection"
    );

    let (mut bind, transport) = next_bind(&mut connection);
    assert_eq!(
        transport.peer_addr,
        server_addr(),
        "the same server address"
    );
    assert_eq!(transport.local_addr, data_local());
    assert_eq!(transport.transport_protocol, TransportProtocol::TCP);
    assert_eq!(
        bind.typ,
        MessageType::new(METHOD_CONNECTION_BIND, CLASS_REQUEST)
    );
    assert_eq!(&bind.raw[..2], &[0x00, 0x0b], "method 0x00b, a request");
    assert_eq!(connection_id_of(&bind)?, 7);
    // The control connection's method and credential.
    assert_eq!(Username::get_from_as(&bind, ATTR_USERNAME)?.text, USERNAME);
    assert_eq!(Realm::get_from_as(&bind, ATTR_REALM)?.text, REALM);
    assert_eq!(nonce_of(&bind), "nonce");
    MessageIntegrity::check(&mut bind, &server.key, test_crypto_provider().crypto())?;
    assert!(connection.poll_write().is_none(), "one request, sent once");

    // Not bound yet: nothing can be written to the peer.
    assert!(!connection.is_bound());
    assert!(connection.send(now, b"too early").is_err());
    assert!(connection.handle_write(chunk(now, b"too early")).is_err());
    assert_eq!(
        connection.poll_timeout(),
        Some(now + CONNECTION_BIND_TIMEOUT)
    );

    // The response arrives in pieces, with the peer's first bytes right behind it.
    let mut stream = server.reply(&bind, CLASS_SUCCESS_RESPONSE, vec![], Some(&server.key))?;
    stream.extend_from_slice(b"hello from the peer");
    let (head, tail) = stream.split_at(11);
    connection.handle_read(chunk(now, head))?;
    assert!(connection.poll_event().is_none());
    assert!(connection.poll_read().is_none());
    connection.handle_read(chunk(now, tail))?;
    assert_eq!(connection.poll_event(), Some(DataConnectionEvent::Bound));
    assert!(connection.is_bound());
    assert!(connection.poll_timeout().is_none());
    assert_eq!(
        connection.poll_read().as_deref(),
        Some(&b"hello from the peer"[..]),
        "what follows the response is the peer's"
    );

    // From here on the connection is the peer's byte stream: no framing either way, and
    // bytes that look like STUN or ChannelData are data like any other.
    let stun_like = server.reply(&bind, CLASS_SUCCESS_RESPONSE, vec![], None)?;
    for bytes in [&b"x"[..], &[0x40, 0x00, 0x00, 0x01, 0xff], &stun_like] {
        connection.handle_read(chunk(now, bytes))?;
        assert_eq!(connection.poll_read().as_deref(), Some(bytes));

        connection.send(now, bytes)?;
        let out = connection.poll_write().expect("the bytes go out");
        assert_eq!(&out.message[..], bytes);
        assert_eq!(out.transport.peer_addr, server_addr());
        assert_eq!(out.transport.local_addr, data_local());
    }
    connection.handle_write(chunk(now, b"written"))?;
    assert_eq!(
        connection.poll_write().map(|out| out.message.to_vec()),
        Some(b"written".to_vec())
    );
    assert!(connection.poll_event().is_none());

    // Closing it ends the relayed connection (RFC 6062 §4.6): nothing more passes.
    connection.close()?;
    assert!(connection.send(now, b"late").is_err());
    connection.handle_read(chunk(now, b"late"))?;
    assert!(connection.poll_read().is_none());
    client.close()
}

/// RFC 6062 §4.3: the data connection authenticates with the control connection's method and
/// credential. A server whose nonces are per connection answers the first ConnectionBind with
/// a 438 (Stale Nonce) and a nonce, or with a 401 that names its realm when that is another
/// one; the request is made again with it (RFC 8489 §9.2.5).
#[test]
fn test_a_connection_bind_is_made_again_with_the_servers_nonce() -> Result<()> {
    let now = Instant::now();
    let server = TestServer::new()?;
    for (code, realm) in [
        (CODE_UNAUTHORIZED, "another realm"),
        (CODE_STALE_NONCE, REALM),
    ] {
        let key = key_for(realm)?;
        let mut client = tcp_allocation(&server, now)?;
        let mut connection =
            client
                .relay(relayed_addr())?
                .data_connection(now, ConnectionId(9), data_local())?;
        let (first, _) = next_bind(&mut connection);

        let challenge = server.reply(
            &first,
            CLASS_ERROR_RESPONSE,
            vec![
                Box::new(ErrorCodeAttribute {
                    code,
                    reason: b"nonce".to_vec(),
                }),
                Box::new(Nonce::new(ATTR_NONCE, "of this connection".to_owned())),
                Box::new(Realm::new(ATTR_REALM, realm.to_owned())),
            ],
            None,
        )?;
        connection.handle_read(chunk(now, &challenge))?;
        assert!(
            connection.poll_event().is_none(),
            "{}: not a failure",
            code.0
        );

        let (mut again, _) = next_bind(&mut connection);
        assert_ne!(again.transaction_id, first.transaction_id);
        assert_eq!(again.typ.method, METHOD_CONNECTION_BIND);
        assert_eq!(connection_id_of(&again)?, 9);
        assert_eq!(nonce_of(&again), "of this connection");
        MessageIntegrity::check(&mut again, &key, test_crypto_provider().crypto())?;

        // A second refusal of the same kind ends it.
        let refused = server.reply(
            &again,
            CLASS_ERROR_RESPONSE,
            vec![
                Box::new(ErrorCodeAttribute {
                    code,
                    reason: b"no".to_vec(),
                }),
                Box::new(Nonce::new(ATTR_NONCE, "another".to_owned())),
                Box::new(Realm::new(ATTR_REALM, realm.to_owned())),
            ],
            None,
        )?;
        connection.handle_read(chunk(now, &refused))?;
        match connection.poll_event() {
            Some(DataConnectionEvent::BindError(err)) => assert!(err.is(code), "{err}"),
            other => panic!("expected BindError, got {other:?}"),
        }
        assert!(connection.poll_write().is_none());
        assert!(!connection.is_bound());
        client.close()?;
    }
    Ok(())
}

/// A ConnectionBind the server refuses, a response that is not signed with the control
/// connection's key, and a stream that is not STUN before the bind.
#[test]
fn test_a_connection_bind_that_fails_is_reported() -> Result<()> {
    let now = Instant::now();
    let server = TestServer::new()?;
    let mut client = tcp_allocation(&server, now)?;

    // Refused: 400 (the server knows no such connection, or its 30 seconds are over).
    let mut connection =
        client
            .relay(relayed_addr())?
            .data_connection(now, ConnectionId(1), data_local())?;
    let (bind, _) = next_bind(&mut connection);
    let refused = server.reply(
        &bind,
        CLASS_ERROR_RESPONSE,
        vec![Box::new(ErrorCodeAttribute {
            code: CODE_BAD_REQUEST,
            reason: b"Bad Request".to_vec(),
        })],
        Some(&server.key),
    )?;
    connection.handle_read(chunk(now, &refused))?;
    match connection.poll_event() {
        Some(DataConnectionEvent::BindError(err)) => assert!(err.is(CODE_BAD_REQUEST)),
        other => panic!("expected BindError, got {other:?}"),
    }

    // A success nobody signed, or signed with another key, binds nothing. The transport is
    // reliable, so the transaction ends at once, as an integrity violation (RFC 8489 §9.2.5).
    for forged in [None, Some(&b"another key!"[..])] {
        let mut connection =
            client
                .relay(relayed_addr())?
                .data_connection(now, ConnectionId(2), data_local())?;
        let (bind, _) = next_bind(&mut connection);
        let reply = server.reply(&bind, CLASS_SUCCESS_RESPONSE, vec![], forged)?;
        connection.handle_read(chunk(now, &reply))?;
        assert_eq!(
            connection.poll_event(),
            Some(DataConnectionEvent::BindError(RequestError::Failed(
                Error::ErrIntegrityMismatch
            )))
        );
        assert!(!connection.is_bound());
        assert!(connection.poll_timeout().is_none(), "nothing is waited for");
    }

    // Bytes that are not STUN before the bind is answered.
    let mut connection =
        client
            .relay(relayed_addr())?
            .data_connection(now, ConnectionId(3), data_local())?;
    let _ = next_bind(&mut connection);
    assert!(
        connection
            .handle_read(chunk(now, b"GET / HTTP/1.1\r\nHost: example\r\n\r\n"))
            .is_err()
    );
    assert!(matches!(
        connection.poll_event(),
        Some(DataConnectionEvent::BindError(RequestError::Failed(_)))
    ));
    assert!(connection.poll_read().is_none());
    client.close()
}

/// RFC 6062 §4.4, §5.3: the server waits 30 seconds for the ConnectionBind and then closes the
/// peer's connection, so a bind that is not answered by then has failed.
#[test]
fn test_a_connection_bind_unanswered_for_thirty_seconds_has_failed() -> Result<()> {
    let now = Instant::now();
    let server = TestServer::new()?;
    let mut client = tcp_allocation(&server, now)?;
    let mut connection =
        client
            .relay(relayed_addr())?
            .data_connection(now, ConnectionId(5), data_local())?;
    let _ = next_bind(&mut connection);

    let deadline = connection.poll_timeout().expect("a deadline for the bind");
    assert_eq!(deadline, now + Duration::from_secs(30));
    connection.handle_timeout(deadline - Duration::from_millis(1))?;
    assert!(connection.poll_event().is_none());
    connection.handle_timeout(deadline)?;
    assert_eq!(
        connection.poll_event(),
        Some(DataConnectionEvent::BindError(RequestError::Failed(
            Error::ErrTimeout
        )))
    );
    assert!(connection.poll_timeout().is_none());
    assert!(
        connection.poll_write().is_none(),
        "sent once: TCP delivers it"
    );
    client.close()
}

/// RFC 8489 §9.2.5: a 400 without an integrity attribute is discarded "as if it were never
/// received", on a data connection too: the ConnectionBind is still answered by the response
/// that follows, and one answered by nothing else times out (RFC 6062 §5.3's 30 seconds), not
/// as the 400 and not as an integrity violation.
#[test]
fn test_an_unsigned_400_to_a_connection_bind_is_never_received() -> Result<()> {
    let now = Instant::now();
    let server = TestServer::new()?;
    let mut client = tcp_allocation(&server, now)?;
    let unsigned_400 = |bind: &Message| {
        server.reply(
            bind,
            CLASS_ERROR_RESPONSE,
            vec![Box::new(ErrorCodeAttribute {
                code: CODE_BAD_REQUEST,
                reason: b"Bad Request".to_vec(),
            })],
            None,
        )
    };

    // The signed success after it binds the connection.
    let mut connection =
        client
            .relay(relayed_addr())?
            .data_connection(now, ConnectionId(6), data_local())?;
    let (bind, _) = next_bind(&mut connection);
    connection.handle_read(chunk(now, &unsigned_400(&bind)?))?;
    assert_eq!(connection.poll_event(), None, "the 400 was acted on");
    assert!(!connection.is_bound());
    let success = server.reply(&bind, CLASS_SUCCESS_RESPONSE, vec![], Some(&server.key))?;
    connection.handle_read(chunk(now, &success))?;
    assert_eq!(connection.poll_event(), Some(DataConnectionEvent::Bound));

    // Nothing after it: the bind times out.
    let mut connection =
        client
            .relay(relayed_addr())?
            .data_connection(now, ConnectionId(7), data_local())?;
    let (bind, _) = next_bind(&mut connection);
    connection.handle_read(chunk(now, &unsigned_400(&bind)?))?;
    assert_eq!(connection.poll_event(), None, "the 400 was acted on");
    let deadline = connection
        .poll_timeout()
        .expect("the bind is still waited for");
    assert_eq!(deadline, now + CONNECTION_BIND_TIMEOUT);
    connection.handle_timeout(deadline)?;
    assert_eq!(
        connection.poll_event(),
        Some(DataConnectionEvent::BindError(RequestError::Failed(
            Error::ErrTimeout
        )))
    );
    client.close()
}

fn connection_attempt(
    now: Instant,
    from: SocketAddr,
    connection_id: u32,
    sender: SocketAddr,
) -> Result<TransportMessage<BytesMut>> {
    let mut msg = Message::new();
    msg.build(&[
        Box::new(MessageType::new(
            METHOD_CONNECTION_ATTEMPT,
            CLASS_INDICATION,
        )),
        Box::new(TransactionId::new()),
        Box::new(ConnectionId(connection_id)),
        Box::new(PeerAddress {
            ip: from.ip(),
            port: from.port(),
        }),
    ])?;
    Ok(TransportMessage {
        now,
        transport: TransportContext {
            local_addr: local_addr(),
            peer_addr: sender,
            transport_protocol: TransportProtocol::TCP,
            ecn: None,
        },
        message: BytesMut::from(&msg.raw[..]),
    })
}

/// RFC 6062 §4.4: a ConnectionAttempt indication announces a peer's connection, with its
/// CONNECTION-ID and XOR-PEER-ADDRESS. To accept it the client binds a new connection with
/// that CONNECTION-ID, authenticated as the control connection is.
#[test]
fn test_a_connection_attempt_from_a_permitted_peer_is_offered_and_accepted() -> Result<()> {
    let now = Instant::now();
    let server = TestServer::new()?;
    let mut client = tcp_allocation(&server, now)?;
    server.permit(&mut client, now, relayed_addr(), peer())?;

    // The peer connects from a port of its own choosing.
    let from = SocketAddr::new(peer().ip(), 61_000);
    let indication = connection_attempt(now, from, 42, server_addr())?;
    assert_eq!(
        &indication.message[..2],
        &[0x00, 0x1c],
        "method 0x00c, an indication"
    );
    client.handle_read(indication)?;
    match client.poll_event() {
        Some(Event::ConnectionAttempt(relayed, peer_addr, connection_id)) => {
            assert_eq!(relayed, relayed_addr());
            assert_eq!(peer_addr, from);
            assert_eq!(connection_id, ConnectionId(42));
        }
        other => panic!("expected ConnectionAttempt, got {other:?}"),
    }

    let mut connection =
        client
            .relay(relayed_addr())?
            .data_connection(now, ConnectionId(42), data_local())?;
    let (mut bind, transport) = next_bind(&mut connection);
    assert_eq!(transport.peer_addr, server_addr());
    assert_ne!(transport.local_addr, local_addr());
    assert_eq!(bind.typ.method, METHOD_CONNECTION_BIND);
    assert_eq!(connection_id_of(&bind)?, 42);
    MessageIntegrity::check(&mut bind, &server.key, test_crypto_provider().crypto())?;
    let success = server.reply(&bind, CLASS_SUCCESS_RESPONSE, vec![], Some(&server.key))?;
    connection.handle_read(chunk(now, &success))?;
    assert_eq!(connection.poll_event(), Some(DataConnectionEvent::Bound));

    // Not from a peer with a permission, not from the server, or missing an attribute:
    // nothing is offered.
    let stranger: SocketAddr = "203.0.113.99:7".parse().unwrap();
    client.handle_read(connection_attempt(now, stranger, 43, server_addr())?)?;
    assert!(client.poll_event().is_none());
    let elsewhere: SocketAddr = "127.0.0.1:9".parse().unwrap();
    client.handle_read(connection_attempt(now, from, 44, elsewhere)?)?;
    assert!(client.poll_event().is_none());
    let mut no_id = Message::new();
    no_id.build(&[
        Box::new(MessageType::new(
            METHOD_CONNECTION_ATTEMPT,
            CLASS_INDICATION,
        )),
        Box::new(TransactionId::new()),
        Box::new(PeerAddress {
            ip: from.ip(),
            port: from.port(),
        }),
    ])?;
    let mut bare = connection_attempt(now, from, 0, server_addr())?;
    bare.message = BytesMut::from(&no_id.raw[..]);
    let _ = client.handle_read(bare);
    assert!(client.poll_event().is_none());
    client.close()
}

/// A TCP allocation relays connections, a UDP one datagrams: neither takes the other's
/// requests.
#[test]
fn test_tcp_and_udp_allocations_keep_to_their_own_requests() -> Result<()> {
    let now = Instant::now();
    let server = TestServer::new()?;

    let mut client = tcp_allocation(&server, now)?;
    server.permit(&mut client, now, relayed_addr(), peer())?;
    assert!(
        client
            .relay(relayed_addr())?
            .send_to(now, b"x", peer())
            .is_err(),
        "no Send indications or channels on a TCP allocation"
    );
    assert!(sent(&mut client).is_empty());
    client.close()?;

    let mut udp = new_client(TransportProtocol::UDP)?;
    let relayed = server.allocate(&mut udp, now)?;
    assert_eq!(udp.relay(relayed)?.transport(), RelayTransport::Udp);
    assert!(udp.relay(relayed)?.connect(now, peer()).is_err());
    assert!(
        udp.relay(relayed)?
            .data_connection(now, ConnectionId(1), data_local())
            .is_err()
    );
    assert!(sent(&mut udp).is_empty());
    // A ConnectionAttempt means nothing to it.
    server.permit(&mut udp, now, relayed, peer())?;
    udp.handle_read(connection_attempt(now, peer(), 1, server_addr())?)?;
    assert!(udp.poll_event().is_none());
    udp.close()
}

/// RFC 8656 §5 holds for Connect as for any request: a 437 means the allocation is gone.
#[test]
fn test_a_437_to_a_connect_ends_the_allocation() -> Result<()> {
    let now = Instant::now();
    let server = TestServer::new()?;
    let mut client = tcp_allocation(&server, now)?;
    let tid = client.relay(relayed_addr())?.connect(now, peer())?;
    let connect = server.next_request(&mut client);
    server.reject(&mut client, now, &connect, CODE_ALLOC_MISMATCH)?;
    assert!(matches!(
        client.poll_event(),
        Some(Event::ConnectError(id, to, err))
            if id == tid && to == peer() && err.is(CODE_ALLOC_MISMATCH)
    ));
    assert!(matches!(
        client.poll_event(),
        Some(Event::AllocationLost(addr, _)) if addr == relayed_addr()
    ));
    assert!(client.relay(relayed_addr()).is_err());
    client.close()
}
