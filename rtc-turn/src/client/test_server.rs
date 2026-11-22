//! A scripted TURN server for the client's sans-I/O tests: it reads the requests the client
//! queued and answers them with whatever the test asks for. No sockets, no wall clock beyond
//! the instants the test passes in.
use super::*;
use sansio::Protocol;

pub(super) const USERNAME: &str = "user";
pub(super) const PASSWORD: &str = "pass";
pub(super) const REALM: &str = "realm";

/// Tests may resolve the built-in provider; library code never does.
pub(super) fn test_crypto_provider() -> Arc<dyn RTCCryptoProvider> {
    crypto::default_provider().expect("a built-in crypto provider must be enabled for tests")
}

pub(super) fn local_addr() -> SocketAddr {
    "127.0.0.1:50000".parse().unwrap()
}

pub(super) fn server_addr() -> SocketAddr {
    "127.0.0.1:3478".parse().unwrap()
}

pub(super) fn relayed_addr() -> RelayedAddr {
    "192.0.2.15:50000".parse().unwrap()
}

/// A client of the server at [`server_addr`], with the long-term credential the server knows.
pub(super) fn new_client(transport_protocol: TransportProtocol) -> Result<Client> {
    Client::new(
        ClientConfig {
            turn_serv_addr: server_addr().to_string(),
            local_addr: local_addr(),
            transport_protocol,
            username: USERNAME.to_owned(),
            password: PASSWORD.to_owned(),
            ..Default::default()
        },
        test_crypto_provider(),
    )
}

/// The long-term key for `realm` and the test credential.
pub(super) fn key_for(realm: &str) -> Result<Vec<u8>> {
    MessageIntegrity::long_term_integrity_key(
        USERNAME.to_owned(),
        realm.to_owned(),
        PASSWORD.to_owned(),
        test_crypto_provider().crypto(),
    )
}

pub(super) struct TestServer {
    /// The key the server signs with and checks requests against.
    pub(super) key: Vec<u8>,
}

impl TestServer {
    pub(super) fn new() -> Result<Self> {
        Ok(TestServer {
            key: key_for(REALM)?,
        })
    }

    /// The STUN requests the client has queued, decoded, in order. Indications and ChannelData
    /// are skipped.
    pub(super) fn requests(&self, client: &mut Client) -> Vec<Message> {
        let mut requests = vec![];
        while let Some(transmit) = client.poll_write() {
            if !is_stun_message(&transmit.message) {
                continue;
            }
            let mut msg = Message::new();
            msg.raw = transmit.message.to_vec();
            msg.decode().expect("the client's message decodes");
            if msg.typ.class == CLASS_REQUEST {
                requests.push(msg);
            }
        }
        requests
    }

    /// The next STUN request the client queued, decoded; anything queued after it is dropped.
    pub(super) fn next_request(&self, client: &mut Client) -> Message {
        self.requests(client)
            .into_iter()
            .next()
            .expect("the client sent a request")
    }

    /// The response to `request` with `class` and `attrs`, signed with `key` when given.
    pub(super) fn reply(
        &self,
        request: &Message,
        class: MessageClass,
        attrs: Vec<Box<dyn Setter>>,
        key: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        let provider = test_crypto_provider();
        let mut setters: Vec<Box<dyn Setter + '_>> = vec![
            Box::new(request.transaction_id),
            Box::new(MessageType::new(request.typ.method, class)),
        ];
        setters.extend(attrs);
        if let Some(key) = key {
            setters.push(Box::new(MessageIntegrity::new_raw_integrity_with_provider(
                key.to_vec(),
                provider.crypto(),
            )));
        }
        setters.push(Box::new(FINGERPRINT));
        let mut reply = Message::new();
        reply.build(&setters)?;
        Ok(reply.raw)
    }

    /// Answers `request` at `now` with `class` and `attrs`, signed with `key` when given.
    pub(super) fn answer(
        &self,
        client: &mut Client,
        now: Instant,
        request: &Message,
        class: MessageClass,
        attrs: Vec<Box<dyn Setter>>,
        key: Option<&[u8]>,
    ) -> Result<()> {
        let reply = self.reply(request, class, attrs, key)?;
        client.handle_read(TransportMessage {
            now,
            transport: TransportContext {
                local_addr: local_addr(),
                peer_addr: server_addr(),
                transport_protocol: TransportProtocol::UDP,
                ecn: None,
            },
            message: BytesMut::from(&reply[..]),
        })
    }

    /// A signed success response with no attributes of its own.
    pub(super) fn succeed(
        &self,
        client: &mut Client,
        now: Instant,
        request: &Message,
    ) -> Result<()> {
        self.answer(
            client,
            now,
            request,
            CLASS_SUCCESS_RESPONSE,
            vec![],
            Some(&self.key),
        )
    }

    /// A 438 (Stale Nonce) carrying `nonce` and `realm`, unsigned as servers send it.
    pub(super) fn stale_nonce(
        &self,
        client: &mut Client,
        now: Instant,
        request: &Message,
        nonce: &str,
        realm: &str,
    ) -> Result<()> {
        self.answer(
            client,
            now,
            request,
            CLASS_ERROR_RESPONSE,
            vec![
                Box::new(ErrorCodeAttribute {
                    code: stun::error_code::CODE_STALE_NONCE,
                    reason: b"Stale Nonce".to_vec(),
                }),
                Box::new(Nonce::new(ATTR_NONCE, nonce.to_owned())),
                Box::new(Realm::new(ATTR_REALM, realm.to_owned())),
            ],
            None,
        )
    }

    /// Runs the Allocate exchange at `now` (the 401 nonce exchange, then a signed success with a
    /// 600 s lifetime) and returns the relayed address. Events are drained.
    pub(super) fn allocate(&self, client: &mut Client, now: Instant) -> Result<RelayedAddr> {
        let tid = client.allocate(now)?;
        let attempt = self.next_request(client);
        self.answer(
            client,
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
        let allocate = self.next_request(client);
        self.answer(
            client,
            now,
            &allocate,
            CLASS_SUCCESS_RESPONSE,
            vec![
                Box::new(RelayedAddress {
                    ip: relayed_addr().ip(),
                    port: relayed_addr().port(),
                }),
                Box::new(Lifetime(Duration::from_secs(600))),
            ],
            Some(&self.key),
        )?;
        let mut allocated = None;
        while let Some(event) = client.poll_event() {
            if let Event::AllocateResponse(id, addr) = event {
                assert_eq!(id, tid, "the allocation is reported under allocate()'s id");
                allocated = Some(addr);
            }
        }
        Ok(allocated.expect("the allocation succeeded"))
    }

    /// Asks for a permission for `peer` at `now` and grants it. Events are drained.
    pub(super) fn permit(
        &self,
        client: &mut Client,
        now: Instant,
        relayed: RelayedAddr,
        peer: SocketAddr,
    ) -> Result<()> {
        client
            .relay(relayed)?
            .create_permission(now, peer)?
            .expect("a new permission is requested");
        let request = self.next_request(client);
        assert_eq!(request.typ.method, METHOD_CREATE_PERMISSION);
        self.succeed(client, now, &request)?;
        while client.poll_event().is_some() {}
        Ok(())
    }
}

/// Handles every deadline the client asks for up to `until`, and returns the STUN requests it
/// sent and the events it raised meanwhile.
pub(super) fn drive_until(
    server: &TestServer,
    client: &mut Client,
    until: Instant,
) -> Result<(Vec<Message>, Vec<Event>)> {
    let mut requests = server.requests(client);
    let mut events = vec![];
    let mut handled = 0;
    while let Some(deadline) = client.poll_timeout() {
        if deadline > until {
            break;
        }
        handled += 1;
        assert!(handled < 10_000, "the client's deadline does not advance");
        client.handle_timeout(deadline)?;
        requests.extend(server.requests(client));
        while let Some(event) = client.poll_event() {
            events.push(event);
        }
    }
    Ok((requests, events))
}

/// The peers a CreatePermission or ChannelBind names.
pub(super) fn peers_of(request: &Message) -> Vec<SocketAddr> {
    request
        .attributes
        .0
        .iter()
        .filter(|a| a.typ == ATTR_XOR_PEER_ADDRESS)
        .map(|a| {
            let mut one = Message::new();
            one.transaction_id = request.transaction_id;
            one.add(a.typ, &a.value);
            let mut peer = PeerAddress::default();
            peer.get_from(&one).expect("XOR-PEER-ADDRESS decodes");
            SocketAddr::new(peer.ip, peer.port)
        })
        .collect()
}

/// The state of the channel binding the allocation `relayed` holds for `peer`.
pub(super) fn binding_state(
    client: &Client,
    relayed: RelayedAddr,
    peer: SocketAddr,
) -> Option<binding::BindingState> {
    client
        .relays
        .get(&relayed)?
        .binding_mgr
        .find_by_addr(&peer)
        .map(|b| b.state())
}

/// Gives `client` an allocation holding a permission for `peer`, without the exchanges: for
/// tests about what the client does with data the server relays.
pub(super) fn hold_permission(client: &mut Client, now: Instant, peer: IpAddr) {
    let mut relay = relay::RelayState::new(
        now,
        relayed_addr(),
        vec![0u8; 16],
        Nonce::new(ATTR_NONCE, "nonce".to_owned()),
        Duration::from_secs(600),
        None,
    );
    let mut permission = permission::Permission::default();
    permission.permit_until(now + Duration::from_secs(300));
    relay.perm_map.insert(peer, permission);
    client.relays.insert(relayed_addr(), relay);
}

/// The NONCE a request carries.
pub(super) fn nonce_of(request: &Message) -> String {
    Nonce::get_from_as(request, ATTR_NONCE)
        .expect("the request carries a NONCE")
        .text
}

/// What the client put on the wire, told apart the way a server does.
#[derive(Debug)]
pub(super) enum Sent {
    /// A STUN request.
    Request(Message),
    /// A STUN indication.
    Indication(Message),
    /// A ChannelData message, as raw bytes.
    ChannelData(Vec<u8>),
}

/// Everything the client has queued, in order.
pub(super) fn sent(client: &mut Client) -> Vec<Sent> {
    let mut out = vec![];
    while let Some(transmit) = client.poll_write() {
        if is_stun_message(&transmit.message) {
            let mut msg = Message::new();
            msg.raw = transmit.message.to_vec();
            msg.decode().expect("the client's message decodes");
            if msg.typ.class == CLASS_REQUEST {
                out.push(Sent::Request(msg));
            } else {
                out.push(Sent::Indication(msg));
            }
        } else {
            out.push(Sent::ChannelData(transmit.message.to_vec()));
        }
    }
    out
}

impl TestServer {
    /// A signed error response with `code`.
    pub(super) fn reject(
        &self,
        client: &mut Client,
        now: Instant,
        request: &Message,
        code: stun::error_code::ErrorCode,
    ) -> Result<()> {
        self.answer(
            client,
            now,
            request,
            CLASS_ERROR_RESPONSE,
            vec![Box::new(ErrorCodeAttribute {
                code,
                reason: b"refused".to_vec(),
            })],
            Some(&self.key),
        )
    }

    /// Answers `request` the way a server that accepts everything does: a Refresh gets the
    /// LIFETIME it asked for, anything else a bare success.
    pub(super) fn accept(
        &self,
        client: &mut Client,
        now: Instant,
        request: &Message,
    ) -> Result<()> {
        if request.typ.method == METHOD_REFRESH {
            let mut lifetime = Lifetime::default();
            lifetime.get_from(request)?;
            self.answer(
                client,
                now,
                request,
                CLASS_SUCCESS_RESPONSE,
                vec![Box::new(lifetime)],
                Some(&self.key),
            )
        } else {
            self.succeed(client, now, request)
        }
    }
}

/// Handles every deadline the client asks for up to `until`, accepting every request it sends
/// on the way, and returns what it sent and the events it raised.
pub(super) fn drive_accepting(
    server: &TestServer,
    client: &mut Client,
    until: Instant,
) -> Result<(Vec<Sent>, Vec<Event>)> {
    let mut all = vec![];
    let mut events = vec![];
    let mut handled = 0;
    let mut now = None;
    loop {
        let batch = sent(client);
        for one in &batch {
            if let Sent::Request(request) = one
                && let Some(now) = now
            {
                server.accept(client, now, request)?;
            }
        }
        let quiet = batch.is_empty();
        all.extend(batch);
        while let Some(event) = client.poll_event() {
            events.push(event);
        }
        if !quiet {
            continue;
        }
        match client.poll_timeout() {
            Some(deadline) if deadline <= until => {
                handled += 1;
                assert!(handled < 10_000, "the client's deadline does not advance");
                client.handle_timeout(deadline)?;
                now = Some(deadline);
            }
            _ => break,
        }
    }
    Ok((all, events))
}

impl TestServer {
    /// The 401 (Unauthorized) that asks for the long-term credential, with a nonce and the
    /// realm, unsigned as a server sends it.
    pub(super) fn challenge(
        &self,
        client: &mut Client,
        now: Instant,
        request: &Message,
    ) -> Result<()> {
        self.answer(
            client,
            now,
            request,
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
        )
    }

    /// Starts an Allocate with `options` and takes it through the 401: returns the id the
    /// client handed out, the first request and the authenticated one.
    pub(super) fn begin_allocate(
        &self,
        client: &mut Client,
        now: Instant,
        options: AllocateOptions,
    ) -> Result<(TransactionId, Message, Message)> {
        let tid = client.allocate_with(now, options)?;
        let first = self.next_request(client);
        self.challenge(client, now, &first)?;
        let authenticated = self.next_request(client);
        Ok((tid, first, authenticated))
    }

    /// Runs an Allocate with `options` that the server answers with `attrs`, signed.
    pub(super) fn allocate_with(
        &self,
        client: &mut Client,
        now: Instant,
        options: AllocateOptions,
        attrs: Vec<Box<dyn Setter>>,
    ) -> Result<(TransactionId, Message)> {
        let (tid, _, authenticated) = self.begin_allocate(client, now, options)?;
        self.answer(
            client,
            now,
            &authenticated,
            CLASS_SUCCESS_RESPONSE,
            attrs,
            Some(&self.key),
        )?;
        Ok((tid, authenticated))
    }
}

/// An XOR-RELAYED-ADDRESS for `addr`.
pub(super) fn relayed(addr: SocketAddr) -> Box<dyn Setter> {
    Box::new(RelayedAddress {
        ip: addr.ip(),
        port: addr.port(),
    })
}

/// A LIFETIME of `secs` seconds.
pub(super) fn lifetime(secs: u64) -> Box<dyn Setter> {
    Box::new(Lifetime(Duration::from_secs(secs)))
}

/// The values of every attribute of type `t` in `m`.
pub(super) fn values_of(m: &Message, t: AttrType) -> Vec<Vec<u8>> {
    m.attributes
        .0
        .iter()
        .filter(|a| a.typ == t)
        .map(|a| a.value.clone())
        .collect()
}
