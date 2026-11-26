//! The TURN client as a STUN client of RFC 8489: every received message goes through
//! `stun::validated::Validator` (sections 6.3 and 9), the long-term credential mechanism is
//! `stun::long_term::LongTermCredentials` (section 9.2: SHA-256 password algorithm, USERHASH,
//! the nonce cookie and its bid-down protection, MESSAGE-INTEGRITY-SHA256), and requests are
//! sent on the timer of section 6.2 (`stun::timer`).
//!
//! The server is scripted: it reads what the client queued and answers with what the test
//! asks for. No sockets, no wall clock beyond the instants the tests pass in.
use super::test_server::*;
use super::*;
use crate::proto::connid::ConnectionId;
use sansio::Protocol;
use stun::error_code::*;
use stun::integrity::{MessageIntegritySha256, long_term_key};
use stun::nonce_cookie::SecurityFeatures;
use stun::password_algorithm::{
    PASSWORD_ALGORITHM_MD5, PASSWORD_ALGORITHM_SHA256, PasswordAlgorithm, PasswordAlgorithms,
};
use stun::userhash::Userhash;

/// How the scripted server signs a response.
pub(super) enum Sign {
    Nothing,
    /// MESSAGE-INTEGRITY with this key.
    Sha1(Vec<u8>),
    /// MESSAGE-INTEGRITY-SHA256 with this key.
    Sha256(Vec<u8>),
}

/// An attribute by its type and bytes.
pub(super) struct Raw(pub(super) AttrType, pub(super) Vec<u8>);

impl Setter for Raw {
    fn add_to(&self, m: &mut Message) -> Result<()> {
        m.add(self.0, &self.1);
        Ok(())
    }
}

/// The response to `request`: `attrs`, the integrity attribute, `after` (what somebody on the
/// path appended to a signed message), FINGERPRINT.
pub(super) fn respond(
    request: &Message,
    class: MessageClass,
    attrs: Vec<Box<dyn Setter>>,
    sign: &Sign,
    after: Vec<Box<dyn Setter>>,
) -> Result<Vec<u8>> {
    let provider = test_crypto_provider();
    let mut setters: Vec<Box<dyn Setter + '_>> = vec![
        Box::new(request.transaction_id),
        Box::new(MessageType::new(request.typ.method, class)),
    ];
    setters.extend(attrs);
    match sign {
        Sign::Nothing => {}
        Sign::Sha1(key) => setters.push(Box::new(
            MessageIntegrity::new_raw_integrity_with_provider(key.clone(), provider.crypto()),
        )),
        Sign::Sha256(key) => setters.push(Box::new(MessageIntegritySha256::new_raw(
            key.clone(),
            provider.crypto(),
        ))),
    }
    setters.extend(after);
    setters.push(Box::new(FINGERPRINT));
    let mut response = Message::new();
    response.build(&setters)?;
    Ok(response.raw)
}

/// Hands the client `raw` as received from `from` at `now`.
pub(super) fn deliver_from(
    client: &mut Client,
    now: Instant,
    from: SocketAddr,
    raw: &[u8],
) -> Result<()> {
    client.handle_read(TransportMessage {
        now,
        transport: TransportContext {
            local_addr: local_addr(),
            peer_addr: from,
            transport_protocol: TransportProtocol::UDP,
            ecn: None,
        },
        message: BytesMut::from(raw),
    })
}

/// Hands the client `raw` as received from the server at `now`.
pub(super) fn deliver(client: &mut Client, now: Instant, raw: &[u8]) -> Result<()> {
    deliver_from(client, now, server_addr(), raw)
}

pub(super) fn error(code: ErrorCode) -> Box<dyn Setter> {
    Box::new(ErrorCodeAttribute {
        code,
        reason: b"scripted".to_vec(),
    })
}

pub(super) fn text(attr: AttrType, value: &str) -> Box<dyn Setter> {
    Box::new(TextAttribute::new(attr, value.to_owned()))
}

/// A nonce that starts with the nonce cookie of `features` (RFC 8489 §9.2).
pub(super) fn nonce_with(features: SecurityFeatures, value: &str) -> String {
    format!("{}{value}", features.cookie())
}

/// MD5 first, as the examples of RFC 8656 list them.
pub(super) fn md5_and_sha256() -> PasswordAlgorithms {
    PasswordAlgorithms(vec![
        PasswordAlgorithm::new(PASSWORD_ALGORITHM_MD5),
        PasswordAlgorithm::new(PASSWORD_ALGORITHM_SHA256),
    ])
}

/// The SHA-256 long-term key of the test credential in `realm`.
pub(super) fn sha256_key(realm: &str, password: &str) -> Result<Vec<u8>> {
    long_term_key(
        PASSWORD_ALGORITHM_SHA256,
        USERNAME,
        realm,
        password,
        test_crypto_provider().crypto(),
    )
}

/// The 401 of a server of RFC 8489 that offers MD5 and SHA-256.
pub(super) fn challenge_8489(request: &Message, nonce: &str) -> Result<Vec<u8>> {
    respond(
        request,
        CLASS_ERROR_RESPONSE,
        vec![
            error(CODE_UNAUTHORIZED),
            text(ATTR_NONCE, nonce),
            text(ATTR_REALM, REALM),
            Box::new(md5_and_sha256()),
        ],
        &Sign::Nothing,
        vec![],
    )
}

/// Runs an Allocate with `options` against a server of RFC 8489 that offers MD5 and SHA-256:
/// returns the relayed address and the key both sides then use.
pub(super) fn allocate_sha256(
    client: &mut Client,
    now: Instant,
    options: AllocateOptions,
) -> Result<(RelayedAddr, Vec<u8>)> {
    let server = TestServer::new()?;
    let key = sha256_key(REALM, PASSWORD)?;
    let nonce = nonce_with(SecurityFeatures::PASSWORD_ALGORITHMS, "first");
    client.allocate_with(now, options)?;
    let first = server.next_request(client);
    deliver(client, now, &challenge_8489(&first, &nonce)?)?;
    let second = server.next_request(client);
    deliver(
        client,
        now,
        &respond(
            &second,
            CLASS_SUCCESS_RESPONSE,
            vec![relayed(relayed_addr()), lifetime(600)],
            &Sign::Sha256(key.clone()),
            vec![],
        )?,
    )?;
    match client.poll_event() {
        Some(Event::AllocateResponse(_, addr)) => Ok((addr, key)),
        other => panic!("expected AllocateResponse, got {other:?}"),
    }
}

fn password_algorithm_of(request: &Message) -> Result<u16> {
    let mut algorithm = PasswordAlgorithm::default();
    algorithm.get_from(request)?;
    Ok(algorithm.algorithm)
}

/// A Data indication from `peer` carrying `data`, with `extra` after it.
fn data_indication(peer: SocketAddr, extra: Vec<Box<dyn Setter>>) -> Result<Vec<u8>> {
    let mut setters: Vec<Box<dyn Setter>> = vec![
        Box::new(TransactionId::new()),
        Box::new(MessageType::new(METHOD_DATA, CLASS_INDICATION)),
        Box::new(PeerAddress {
            ip: peer.ip(),
            port: peer.port(),
        }),
    ];
    setters.extend(extra);
    setters.push(Box::new(FINGERPRINT));
    let mut indication = Message::new();
    indication.build(&setters)?;
    Ok(indication.raw)
}

// --- The receive path: RFC 8489 §6.3, §9 --------------------------------------------------

/// RFC 8489 §9: attributes that follow MESSAGE-INTEGRITY are ignored. Anyone on the path can
/// append one to a genuine response without breaking its HMAC; here an XOR-MAPPED-ADDRESS,
/// which the client would hand out as its server-reflexive address.
#[test]
fn test_attribute_appended_after_the_integrity_of_a_response_is_not_read() -> Result<()> {
    let now = Instant::now();
    let server = TestServer::new()?;
    let mut client = new_client(TransportProtocol::UDP)?;
    let (tid, _, authenticated) =
        server.begin_allocate(&mut client, now, AllocateOptions::default())?;

    let forged: SocketAddr = "203.0.113.66:6666".parse().unwrap();
    let response = respond(
        &authenticated,
        CLASS_SUCCESS_RESPONSE,
        vec![relayed(relayed_addr()), lifetime(600)],
        &Sign::Sha1(server.key.clone()),
        vec![Box::new(XorMappedAddress {
            ip: forged.ip(),
            port: forged.port(),
        })],
    )?;
    deliver(&mut client, now, &response)?;

    assert!(
        matches!(
            client.poll_event(),
            Some(Event::AllocateResponse(id, addr)) if id == tid && addr == relayed_addr()
        ),
        "the genuine part of the response is the allocation"
    );
    assert_eq!(
        client.relay(relayed_addr())?.mapped_addr(),
        None,
        "an attribute appended after MESSAGE-INTEGRITY was obeyed"
    );
    client.close()
}

/// RFC 8489 §6.3.2: an indication with a comprehension-required attribute the agent does not
/// understand is discarded. A Data indication without it is delivered.
#[test]
fn test_data_indication_with_an_unknown_comprehension_required_attribute_is_discarded() -> Result<()>
{
    let now = Instant::now();
    let mut client = new_client(TransportProtocol::UDP)?;
    let peer: SocketAddr = "198.51.100.7:4000".parse().unwrap();
    hold_permission(&mut client, now, peer.ip());

    let unknown = data_indication(
        peer,
        vec![
            Box::new(Data(b"payload".to_vec())),
            Box::new(Raw(AttrType(0x7f77), vec![1, 2, 3, 4])),
        ],
    )?;
    deliver(&mut client, now, &unknown)?;
    assert!(
        client.poll_event().is_none(),
        "an indication the client cannot fully understand was delivered"
    );

    // The same with a comprehension-optional attribute is read past.
    let optional = data_indication(
        peer,
        vec![
            Box::new(Data(b"payload".to_vec())),
            Box::new(Raw(AttrType(0xff77), vec![1, 2, 3, 4])),
        ],
    )?;
    deliver(&mut client, now, &optional)?;
    assert!(matches!(
        client.poll_event(),
        Some(Event::DataIndicationOrChannelData(None, from, data))
            if from == peer && &data[..] == b"payload"
    ));
    client.close()
}

/// RFC 8489 §9 holds for every agent and message: whatever follows an integrity attribute is
/// not read, in an indication (which TURN does not sign) as anywhere else.
#[test]
fn test_data_indication_is_read_only_ahead_of_an_integrity_attribute() -> Result<()> {
    let now = Instant::now();
    let mut client = new_client(TransportProtocol::UDP)?;
    let peer: SocketAddr = "198.51.100.7:4000".parse().unwrap();
    hold_permission(&mut client, now, peer.ip());

    let indication = data_indication(
        peer,
        vec![
            Box::new(Raw(ATTR_MESSAGE_INTEGRITY, vec![0; 20])),
            Box::new(Data(b"after".to_vec())),
        ],
    )?;
    // With nothing it may read but the peer address, the indication carries neither data nor
    // an ICMP error.
    let _ = deliver(&mut client, now, &indication);
    assert!(
        client.poll_event().is_none(),
        "DATA after an integrity attribute was delivered"
    );
    client.close()
}

/// RFC 8489 §6.3.3: a success response with a comprehension-required attribute the client
/// does not understand is discarded and the transaction has failed.
#[test]
fn test_success_response_with_an_unknown_comprehension_required_attribute_fails_the_allocate()
-> Result<()> {
    let now = Instant::now();
    let server = TestServer::new()?;
    let mut client = new_client(TransportProtocol::UDP)?;
    let (tid, _, authenticated) =
        server.begin_allocate(&mut client, now, AllocateOptions::default())?;

    let response = respond(
        &authenticated,
        CLASS_SUCCESS_RESPONSE,
        vec![
            relayed(relayed_addr()),
            lifetime(600),
            Box::new(Raw(AttrType(0x7f01), vec![0; 4])),
        ],
        &Sign::Sha1(server.key.clone()),
        vec![],
    )?;
    deliver(&mut client, now, &response)?;

    match client.poll_event() {
        Some(Event::AllocateError(id, RequestError::Failed(err))) => {
            assert_eq!(id, tid);
            assert!(err.to_string().contains("unknown"), "{err}");
        }
        other => panic!("expected AllocateError, got {other:?}"),
    }
    assert!(client.relay(relayed_addr()).is_err(), "no allocation");
    assert!(!client.has_transaction(&tid), "the transaction has failed");
    assert!(
        server.requests(&mut client).is_empty(),
        "nothing is retried"
    );
    client.close()
}

/// RFC 8489 §6.3.4: the same for an error response. Its code is not acted on: a 437 with an
/// attribute the client does not understand fails the request and leaves the allocation.
#[test]
fn test_error_response_with_an_unknown_comprehension_required_attribute_fails_the_request()
-> Result<()> {
    let now = Instant::now();
    let server = TestServer::new()?;
    let mut client = new_client(TransportProtocol::UDP)?;
    let relayed = server.allocate(&mut client, now)?;

    client.refresh_allocations(now)?;
    let refresh = server.next_request(&mut client);
    let response = respond(
        &refresh,
        CLASS_ERROR_RESPONSE,
        vec![
            error(CODE_ALLOC_MISMATCH),
            Box::new(Raw(AttrType(0x7f01), vec![0; 4])),
        ],
        &Sign::Sha1(server.key.clone()),
        vec![],
    )?;
    deliver(&mut client, now, &response)?;

    match client.poll_event() {
        Some(Event::RefreshError(addr, RequestError::Failed(err))) => {
            assert_eq!(addr, relayed);
            assert!(err.to_string().contains("unknown"), "{err}");
        }
        other => panic!("expected RefreshError, got {other:?}"),
    }
    assert!(!client.has_transaction(&refresh.transaction_id));
    assert!(
        client.relay(relayed).is_ok(),
        "an error response the client must not process ended the allocation"
    );
    client.close()
}

/// RFC 8489 §14.7, §6.3: a message whose FINGERPRINT does not match is not a STUN message for
/// this agent. The 401 that would start the authenticated Allocate is dropped when its
/// FINGERPRINT is wrong, and taken when it is right.
#[test]
fn test_response_with_a_wrong_fingerprint_is_dropped() -> Result<()> {
    let now = Instant::now();
    let server = TestServer::new()?;
    let mut client = new_client(TransportProtocol::UDP)?;
    let tid = client.allocate(now)?;
    let first = server.next_request(&mut client);

    let challenge = respond(
        &first,
        CLASS_ERROR_RESPONSE,
        vec![
            error(CODE_UNAUTHORIZED),
            text(ATTR_NONCE, "nonce"),
            text(ATTR_REALM, REALM),
        ],
        &Sign::Nothing,
        vec![],
    )?;
    let mut damaged = challenge.clone();
    *damaged.last_mut().unwrap() ^= 0x01;
    let _ = deliver(&mut client, now, &damaged);
    assert!(
        server.requests(&mut client).is_empty(),
        "a response with a wrong FINGERPRINT was acted on"
    );
    assert!(client.has_transaction(&first.transaction_id));

    deliver(&mut client, now, &challenge)?;
    let authenticated = server.next_request(&mut client);
    assert_eq!(authenticated.transaction_id, tid);
    client.close()
}

/// RFC 8489 §6.3: a response is processed for the method of its request. One of another
/// method with the transaction id of an outstanding request does not answer it; the
/// transaction goes on and its real response is taken. (It used to end the transaction with
/// no event at all.)
#[test]
fn test_response_of_another_method_does_not_end_the_transaction() -> Result<()> {
    let now = Instant::now();
    let mut client = new_client(TransportProtocol::UDP)?;
    let tid = client.send_binding_request_to(now, server_addr())?;
    let request = TestServer::new()?.next_request(&mut client);
    assert_eq!(request.typ.method, METHOD_BINDING);

    let mut other = Message::new();
    other.build(&[
        Box::new(tid),
        Box::new(MessageType::new(METHOD_ALLOCATE, CLASS_SUCCESS_RESPONSE)),
        relayed(relayed_addr()),
        lifetime(600),
        Box::new(FINGERPRINT),
    ])?;
    deliver(&mut client, now, &other.raw)?;
    assert!(client.poll_event().is_none());
    assert!(
        client.has_transaction(&tid),
        "an Allocate response ended a Binding transaction"
    );

    let mapped: SocketAddr = "203.0.113.5:40000".parse().unwrap();
    let answer = respond(
        &request,
        CLASS_SUCCESS_RESPONSE,
        vec![Box::new(XorMappedAddress {
            ip: mapped.ip(),
            port: mapped.port(),
        })],
        &Sign::Nothing,
        vec![],
    )?;
    deliver(&mut client, now, &answer)?;
    assert!(matches!(
        client.poll_event(),
        Some(Event::BindingResponse(id, addr)) if id == tid && addr == mapped
    ));
    client.close()
}

// --- The long-term credential mechanism: RFC 8489 §9.2 -------------------------------------

/// RFC 8489 §9.2.3.1: the first request to a server carries no USERNAME, USERHASH, REALM,
/// NONCE, PASSWORD-ALGORITHMS, PASSWORD-ALGORITHM or integrity attribute.
#[test]
fn test_first_allocate_request_carries_no_credentials() -> Result<()> {
    let now = Instant::now();
    let mut client = new_client(TransportProtocol::UDP)?;
    client.allocate(now)?;
    let first = TestServer::new()?.next_request(&mut client);
    for attr in [
        ATTR_USERNAME,
        ATTR_USER_HASH,
        ATTR_REALM,
        ATTR_NONCE,
        ATTR_PASSWORD_ALGORITHMS,
        ATTR_PASSWORD_ALGORITHM,
        ATTR_MESSAGE_INTEGRITY,
        ATTR_MESSAGE_INTEGRITY_SHA256,
    ] {
        assert!(!first.contains(attr), "the first request carries {attr}");
    }
    client.close()
}

/// RFC 8656 §6, RFC 8489 §9.2.5: when the 401 offers MD5 and SHA-256, the retry echoes
/// PASSWORD-ALGORITHMS, names SHA-256 in PASSWORD-ALGORITHM (wherever the server listed it),
/// and is authenticated with MESSAGE-INTEGRITY-SHA256 under the SHA-256 key. So is every
/// request after it, and a response must carry the same attribute (§9.1.4, §9.2.5).
#[test]
fn test_sha256_password_algorithm_and_message_integrity_sha256_are_used_when_offered() -> Result<()>
{
    let now = Instant::now();
    let server = TestServer::new()?;
    let provider = test_crypto_provider();
    let mut client = new_client(TransportProtocol::UDP)?;
    let key = sha256_key(REALM, PASSWORD)?;
    let nonce = nonce_with(SecurityFeatures::PASSWORD_ALGORITHMS, "first");

    let tid = client.allocate(now)?;
    let first = server.next_request(&mut client);
    deliver(&mut client, now, &challenge_8489(&first, &nonce)?)?;

    let second = server.next_request(&mut client);
    assert_eq!(second.transaction_id, tid);
    let mut echoed = PasswordAlgorithms::default();
    echoed.get_from(&second)?;
    assert_eq!(echoed, md5_and_sha256(), "PASSWORD-ALGORITHMS is echoed");
    assert_eq!(password_algorithm_of(&second)?, PASSWORD_ALGORITHM_SHA256);
    assert_eq!(nonce_of(&second), nonce);
    assert_eq!(
        Username::get_from_as(&second, ATTR_USERNAME)?.text,
        USERNAME
    );
    assert!(!second.contains(ATTR_USER_HASH));
    assert!(
        !second.contains(ATTR_MESSAGE_INTEGRITY),
        "after PASSWORD-ALGORITHMS, MESSAGE-INTEGRITY-SHA256 only"
    );
    MessageIntegritySha256::check(&second, &key, provider.crypto())?;

    // A response signed with MESSAGE-INTEGRITY alone does not match the request.
    let success = |sign: &Sign| {
        respond(
            &second,
            CLASS_SUCCESS_RESPONSE,
            vec![relayed(relayed_addr()), lifetime(600)],
            sign,
            vec![],
        )
    };
    deliver(&mut client, now, &success(&Sign::Sha1(key.clone()))?)?;
    assert!(client.poll_event().is_none());
    assert!(client.has_transaction(&tid));
    deliver(&mut client, now, &success(&Sign::Sha256(key.clone()))?)?;
    assert!(matches!(
        client.poll_event(),
        Some(Event::AllocateResponse(id, addr)) if id == tid && addr == relayed_addr()
    ));

    // A subsequent request.
    client.refresh_allocations(now)?;
    let refresh = server.next_request(&mut client);
    assert_eq!(refresh.typ.method, METHOD_REFRESH);
    assert_eq!(password_algorithm_of(&refresh)?, PASSWORD_ALGORITHM_SHA256);
    assert!(refresh.contains(ATTR_PASSWORD_ALGORITHMS));
    assert!(!refresh.contains(ATTR_MESSAGE_INTEGRITY));
    MessageIntegritySha256::check(&refresh, &key, provider.crypto())?;
    client.close()
}

/// RFC 8489 §9.2.5: with the "username anonymity" bit in the nonce cookie, the request
/// carries USERHASH, SHA-256(username ":" realm), and no USERNAME.
#[test]
fn test_userhash_replaces_username_when_the_nonce_cookie_announces_it() -> Result<()> {
    let now = Instant::now();
    let server = TestServer::new()?;
    let provider = test_crypto_provider();
    let mut client = new_client(TransportProtocol::UDP)?;
    let nonce = nonce_with(
        SecurityFeatures::PASSWORD_ALGORITHMS.with(SecurityFeatures::USERNAME_ANONYMITY),
        "anonymous",
    );

    client.allocate(now)?;
    let first = server.next_request(&mut client);
    deliver(&mut client, now, &challenge_8489(&first, &nonce)?)?;

    let second = server.next_request(&mut client);
    assert!(
        !second.contains(ATTR_USERNAME),
        "the user name goes in the clear"
    );
    let mut userhash = Userhash::default();
    userhash.get_from(&second)?;
    assert_eq!(userhash, Userhash::new(USERNAME, REALM, provider.crypto())?);
    MessageIntegritySha256::check(&second, &sha256_key(REALM, PASSWORD)?, provider.crypto())?;
    client.close()
}

/// RFC 8489 §9.2.5: a 401 whose nonce cookie has the "password algorithms" bit but which
/// carries no PASSWORD-ALGORITHMS had the attribute removed on the way, to make the client
/// fall back to MD5. The client MUST NOT retry.
#[test]
fn test_bid_down_challenge_is_not_retried() -> Result<()> {
    let now = Instant::now();
    let server = TestServer::new()?;
    let mut client = new_client(TransportProtocol::UDP)?;
    let tid = client.allocate(now)?;
    let first = server.next_request(&mut client);

    let stripped = respond(
        &first,
        CLASS_ERROR_RESPONSE,
        vec![
            error(CODE_UNAUTHORIZED),
            text(
                ATTR_NONCE,
                &nonce_with(SecurityFeatures::PASSWORD_ALGORITHMS, "x"),
            ),
            text(ATTR_REALM, REALM),
        ],
        &Sign::Nothing,
        vec![],
    )?;
    deliver(&mut client, now, &stripped)?;

    assert!(
        server.requests(&mut client).is_empty(),
        "the client authenticated with MD5 to a server that offered more"
    );
    assert!(matches!(
        client.poll_event(),
        Some(Event::AllocateError(id, RequestError::Failed(_))) if id == tid
    ));
    client.close()
}

/// RFC 8489 §9.2.5: when PASSWORD-ALGORITHMS lists no algorithm the client supports, the
/// client MUST NOT retry.
#[test]
fn test_challenge_without_a_supported_password_algorithm_is_not_retried() -> Result<()> {
    let now = Instant::now();
    let server = TestServer::new()?;
    let mut client = new_client(TransportProtocol::UDP)?;
    let tid = client.allocate(now)?;
    let first = server.next_request(&mut client);

    let challenge = respond(
        &first,
        CLASS_ERROR_RESPONSE,
        vec![
            error(CODE_UNAUTHORIZED),
            text(
                ATTR_NONCE,
                &nonce_with(SecurityFeatures::PASSWORD_ALGORITHMS, "x"),
            ),
            text(ATTR_REALM, REALM),
            Box::new(PasswordAlgorithms(vec![PasswordAlgorithm::new(0x0099)])),
        ],
        &Sign::Nothing,
        vec![],
    )?;
    deliver(&mut client, now, &challenge)?;

    assert!(server.requests(&mut client).is_empty());
    assert!(matches!(
        client.poll_event(),
        Some(Event::AllocateError(id, RequestError::Failed(_))) if id == tid
    ));
    client.close()
}

/// RFC 8489 §9.2.5: a 401 to a request that carried the credential is not answered with the
/// same credential again; the server's 401 is the result.
#[test]
fn test_a_401_to_the_credential_just_sent_is_not_retried() -> Result<()> {
    let now = Instant::now();
    let server = TestServer::new()?;
    let mut client = new_client(TransportProtocol::UDP)?;
    let (tid, _, authenticated) =
        server.begin_allocate(&mut client, now, AllocateOptions::default())?;

    let refused = respond(
        &authenticated,
        CLASS_ERROR_RESPONSE,
        vec![
            error(CODE_UNAUTHORIZED),
            text(ATTR_NONCE, "another nonce"),
            text(ATTR_REALM, REALM),
        ],
        &Sign::Nothing,
        vec![],
    )?;
    deliver(&mut client, now, &refused)?;

    assert!(
        server.requests(&mut client).is_empty(),
        "the refused credential was sent again"
    );
    assert!(matches!(
        client.poll_event(),
        Some(Event::AllocateError(id, err)) if id == tid && err.is(CODE_UNAUTHORIZED)
    ));
    client.close()
}

/// RFC 8489 §9.2.5: the retry after a 401 is allowed when the realm, and so the key, is
/// another one. The request goes out again under a new transaction id, with the realm and
/// nonce of that 401, and still ends as the allocation `allocate()` named.
#[test]
fn test_a_401_naming_another_realm_is_retried_with_the_key_of_that_realm() -> Result<()> {
    let now = Instant::now();
    let server = TestServer::new()?;
    let provider = test_crypto_provider();
    let mut client = new_client(TransportProtocol::UDP)?;
    let (tid, _, authenticated) =
        server.begin_allocate(&mut client, now, AllocateOptions::default())?;

    let other_realm = respond(
        &authenticated,
        CLASS_ERROR_RESPONSE,
        vec![
            error(CODE_UNAUTHORIZED),
            text(ATTR_NONCE, "nonce of the other realm"),
            text(ATTR_REALM, "other.example"),
        ],
        &Sign::Nothing,
        vec![],
    )?;
    deliver(&mut client, now, &other_realm)?;

    let mut again = server.next_request(&mut client);
    assert_ne!(again.transaction_id, authenticated.transaction_id);
    assert_eq!(
        Realm::get_from_as(&again, ATTR_REALM)?.text,
        "other.example"
    );
    assert_eq!(nonce_of(&again), "nonce of the other realm");
    let key = key_for("other.example")?;
    MessageIntegrity::check(&mut again, &key, provider.crypto())?;

    deliver(
        &mut client,
        now,
        &respond(
            &again,
            CLASS_SUCCESS_RESPONSE,
            vec![relayed(relayed_addr()), lifetime(600)],
            &Sign::Sha1(key),
            vec![],
        )?,
    )?;
    assert!(matches!(
        client.poll_event(),
        Some(Event::AllocateResponse(id, addr)) if id == tid && addr == relayed_addr()
    ));
    client.close()
}

/// RFC 8489 §9.2.5: a 438 (Stale Nonce) is answered with the same request and the new nonce,
/// in the form the server negotiated: here SHA-256, with PASSWORD-ALGORITHMS echoed.
#[test]
fn test_stale_nonce_retry_keeps_the_negotiated_algorithm() -> Result<()> {
    let now = Instant::now();
    let server = TestServer::new()?;
    let provider = test_crypto_provider();
    let mut client = new_client(TransportProtocol::UDP)?;
    let (relayed, key) = allocate_sha256(&mut client, now, AllocateOptions::default())?;

    let peer: SocketAddr = "198.51.100.7:4000".parse().unwrap();
    let tid = client
        .relay(relayed)?
        .create_permission(now, peer)?
        .expect("a permission is asked for");
    let request = server.next_request(&mut client);
    let renewed = nonce_with(SecurityFeatures::PASSWORD_ALGORITHMS, "second");
    let stale = respond(
        &request,
        CLASS_ERROR_RESPONSE,
        vec![
            error(CODE_STALE_NONCE),
            text(ATTR_NONCE, &renewed),
            text(ATTR_REALM, REALM),
            Box::new(md5_and_sha256()),
        ],
        &Sign::Nothing,
        vec![],
    )?;
    deliver(&mut client, now, &stale)?;

    let again = server.next_request(&mut client);
    assert_eq!(again.typ.method, METHOD_CREATE_PERMISSION);
    assert_ne!(again.transaction_id, request.transaction_id);
    assert_eq!(nonce_of(&again), renewed);
    assert_eq!(password_algorithm_of(&again)?, PASSWORD_ALGORITHM_SHA256);
    assert!(!again.contains(ATTR_MESSAGE_INTEGRITY));
    MessageIntegritySha256::check(&again, &key, provider.crypto())?;

    deliver(
        &mut client,
        now,
        &respond(
            &again,
            CLASS_SUCCESS_RESPONSE,
            vec![],
            &Sign::Sha256(key),
            vec![],
        )?,
    )?;
    assert!(matches!(
        client.poll_event(),
        Some(Event::CreatePermissionResponse(id, addr)) if id == tid && addr == peer
    ));
    client.close()
}

/// RFC 8489 §9.2.5: a response that is neither a 401 nor a 438, whose NONCE has a cookie with
/// the "password algorithms" bit while PASSWORD-ALGORITHMS is absent, MUST be ignored.
#[test]
fn test_response_whose_nonce_cookie_promises_algorithms_it_lacks_is_ignored() -> Result<()> {
    let now = Instant::now();
    let server = TestServer::new()?;
    let mut client = new_client(TransportProtocol::UDP)?;
    let relayed = server.allocate(&mut client, now)?;

    client.refresh_allocations(now)?;
    let refresh = server.next_request(&mut client);
    let tampered = respond(
        &refresh,
        CLASS_SUCCESS_RESPONSE,
        vec![
            lifetime(300),
            text(
                ATTR_NONCE,
                &nonce_with(SecurityFeatures::PASSWORD_ALGORITHMS, "x"),
            ),
        ],
        &Sign::Sha1(server.key.clone()),
        vec![],
    )?;
    deliver(&mut client, now, &tampered)?;
    assert_eq!(
        client.relays.get(&relayed).map(|relay| relay.lifetime),
        Some(Duration::from_secs(600)),
        "the response was acted on"
    );
    assert!(client.has_transaction(&refresh.transaction_id));

    deliver(
        &mut client,
        now,
        &respond(
            &refresh,
            CLASS_SUCCESS_RESPONSE,
            vec![lifetime(300)],
            &Sign::Sha1(server.key.clone()),
            vec![],
        )?,
    )?;
    assert_eq!(
        client.relays.get(&relayed).map(|relay| relay.lifetime),
        Some(Duration::from_secs(300))
    );
    client.close()
}

/// RFC 8489 §9.2.5: over an unreliable transport a response that is not authentic (here a 403
/// without an integrity attribute) is discarded as if it had never been received and the
/// retransmissions go on; when nothing better arrives, the transaction ends as an integrity
/// violation, not as a timeout. (A 400 without one has its own rule and ends in a timeout:
/// `test_an_unsigned_400_to_a_signed_request_is_never_received`.)
#[test]
fn test_discarded_responses_end_the_transaction_as_an_integrity_violation() -> Result<()> {
    let now = Instant::now();
    let server = TestServer::new()?;
    let mut client = new_client(TransportProtocol::UDP)?;
    let relayed = server.allocate(&mut client, now)?;

    client.refresh_allocations(now)?;
    let refresh = server.next_request(&mut client);
    let unsigned = respond(
        &refresh,
        CLASS_ERROR_RESPONSE,
        vec![error(CODE_FORBIDDEN)],
        &Sign::Nothing,
        vec![],
    )?;
    deliver(&mut client, now, &unsigned)?;
    assert!(client.poll_event().is_none());
    assert!(client.has_transaction(&refresh.transaction_id));

    let (requests, events) = drive_until(&server, &mut client, now + Duration::from_secs(60))?;
    assert!(
        !requests.is_empty(),
        "the request is retransmitted after the discarded response"
    );
    assert!(
        requests
            .iter()
            .all(|r| r.transaction_id == refresh.transaction_id),
        "an integrity violation is not a lost request to start again"
    );
    assert!(
        matches!(
            events.as_slice(),
            [Event::RefreshError(
                addr,
                RequestError::Failed(Error::ErrIntegrityMismatch)
            )] if *addr == relayed
        ),
        "expected the integrity violation alone, got {events:?}"
    );
    client.close()
}

/// RFC 8489 §9.2.5: over a reliable transport a response that is not authentic is discarded
/// and the transaction ends at once, as an integrity violation.
#[test]
fn test_over_tcp_an_unauthentic_response_ends_the_transaction_at_once() -> Result<()> {
    let now = Instant::now();
    let server = TestServer::new()?;
    let mut client = new_client(TransportProtocol::TCP)?;
    let relayed = server.allocate(&mut client, now)?;

    client.refresh_allocations(now)?;
    let refresh = server.next_request(&mut client);
    let unsigned = respond(
        &refresh,
        CLASS_SUCCESS_RESPONSE,
        vec![lifetime(0)],
        &Sign::Nothing,
        vec![],
    )?;
    deliver(&mut client, now, &unsigned)?;

    assert!(
        matches!(
            client.poll_event(),
            Some(Event::RefreshError(
                addr,
                RequestError::Failed(Error::ErrIntegrityMismatch)
            )) if addr == relayed
        ),
        "the violation is reported at once"
    );
    assert!(!client.has_transaction(&refresh.transaction_id));
    assert!(
        client.relay(relayed).is_ok(),
        "the forged release did nothing"
    );
    client.close()
}

/// RFC 6062 §4.3 with RFC 8489 §9.2.5: the ConnectionBind of a data connection carries the
/// control connection's credential as the server negotiated it, here SHA-256, and its
/// response is checked the same way.
#[test]
fn test_connection_bind_carries_the_sha256_credential_of_the_control_connection() -> Result<()> {
    let now = Instant::now();
    let provider = test_crypto_provider();
    let mut client = new_client(TransportProtocol::TCP)?;
    let (relayed, key) = allocate_sha256(
        &mut client,
        now,
        AllocateOptions {
            transport: RelayTransport::Tcp,
            ..Default::default()
        },
    )?;

    let data_local: SocketAddr = "127.0.0.1:50001".parse().unwrap();
    let mut connection =
        client
            .relay(relayed)?
            .data_connection(now, ConnectionId(5), data_local)?;
    let out = connection.poll_write().expect("a ConnectionBind is queued");
    let mut bind = Message::new();
    bind.raw = out.message.to_vec();
    bind.decode()?;
    assert_eq!(bind.typ.method, METHOD_CONNECTION_BIND);
    assert_eq!(password_algorithm_of(&bind)?, PASSWORD_ALGORITHM_SHA256);
    assert!(!bind.contains(ATTR_MESSAGE_INTEGRITY));
    MessageIntegritySha256::check(&bind, &key, provider.crypto())?;

    let success = respond(
        &bind,
        CLASS_SUCCESS_RESPONSE,
        vec![],
        &Sign::Sha256(key),
        vec![],
    )?;
    connection.handle_read(TransportMessage {
        now,
        transport: TransportContext {
            local_addr: data_local,
            peer_addr: server_addr(),
            transport_protocol: TransportProtocol::TCP,
            ecn: None,
        },
        message: BytesMut::from(&success[..]),
    })?;
    assert_eq!(
        connection.poll_event(),
        Some(data_connection::DataConnectionEvent::Bound)
    );
    client.close()
}

// --- The retransmission timer: RFC 8489 §6.2 ------------------------------------------------

/// What the client queued, as offsets from `start`.
fn sent_at(client: &mut Client, start: Instant) -> Vec<Duration> {
    let mut at = vec![];
    while let Some(transmit) = client.poll_write() {
        at.push(transmit.now.saturating_duration_since(start));
    }
    at
}

/// RFC 8489 §6.2.1: with the default RTO of 500 ms, Rc of 7 and Rm of 16, a request over UDP
/// is sent at 0, 500, 1500, 3500, 7500, 15500 and 31500 ms, and its transaction fails at
/// 39500 ms.
#[test]
fn test_requests_are_sent_on_the_rfc8489_schedule_and_fail_after_39500_ms() -> Result<()> {
    let start = Instant::now();
    let mut client = new_client(TransportProtocol::UDP)?;
    let tid = client.send_binding_request_to(start, server_addr())?;

    let mut sent = vec![];
    let mut timed_out = None;
    let mut last = start;
    loop {
        sent.extend(sent_at(&mut client, start));
        while let Some(event) = client.poll_event() {
            match event {
                Event::TransactionTimeout(id) => {
                    assert_eq!(id, tid);
                    timed_out = Some(last.saturating_duration_since(start));
                }
                other => panic!("unexpected {other:?}"),
            }
        }
        let Some(deadline) = client.poll_timeout() else {
            break;
        };
        client.handle_timeout(deadline)?;
        last = deadline;
    }

    let millis: Vec<u128> = sent.iter().map(Duration::as_millis).collect();
    assert_eq!(millis, [0, 500, 1500, 3500, 7500, 15_500, 31_500]);
    assert_eq!(timed_out, Some(Duration::from_millis(39_500)));
    client.close()
}

/// A Binding success response to `request`.
fn binding_success(request: &Message) -> Result<Vec<u8>> {
    respond(
        request,
        CLASS_SUCCESS_RESPONSE,
        vec![Box::new(XorMappedAddress {
            ip: local_addr().ip(),
            port: local_addr().port(),
        })],
        &Sign::Nothing,
        vec![],
    )
}

/// RFC 8489 §6.2.1: the RTO is computed as RFC 6298 has it from the server's round-trip
/// times, never from a request that was retransmitted (Karn), kept for the server, and
/// dropped after ten minutes without a transaction.
#[test]
fn test_rto_follows_the_servers_round_trip_time_and_is_forgotten_after_ten_minutes() -> Result<()> {
    let start = Instant::now();
    let at = |millis: u64| start + Duration::from_millis(millis);
    let server = TestServer::new()?;
    let mut client = new_client(TransportProtocol::UDP)?;

    // A round trip of 400 ms: SRTT 400 ms, RTTVAR 200 ms, RTO 400 + 4 x 200 = 1200 ms.
    client.send_binding_request_to(at(0), server_addr())?;
    let request = server.next_request(&mut client);
    deliver(&mut client, at(400), &binding_success(&request)?)?;
    assert!(matches!(
        client.poll_event(),
        Some(Event::BindingResponse(..))
    ));

    client.send_binding_request_to(at(1_000), server_addr())?;
    let request = server.next_request(&mut client);
    assert_eq!(
        client.poll_timeout(),
        Some(at(2_200)),
        "the second transaction starts at the measured RTO"
    );

    // Its response arrives after a retransmission: no sample comes of it.
    client.handle_timeout(at(2_200))?;
    assert_eq!(server.requests(&mut client).len(), 1, "retransmitted");
    deliver(&mut client, at(2_300), &binding_success(&request)?)?;
    while client.poll_event().is_some() {}
    client.send_binding_request_to(at(10_000), server_addr())?;
    let _ = server.next_request(&mut client);
    assert_eq!(
        client.poll_timeout(),
        Some(at(11_200)),
        "a retransmitted request changed the RTO"
    );

    // Unanswered. Ten minutes after it started, the estimate is gone.
    let (_, events) = drive_until(&server, &mut client, at(200_000))?;
    assert!(matches!(events.as_slice(), [Event::TransactionTimeout(_)]));
    let later = 10_000 + 601_000;
    client.send_binding_request_to(at(later), server_addr())?;
    let _ = server.next_request(&mut client);
    assert_eq!(client.poll_timeout(), Some(at(later + 500)));
    client.close()
}

/// RFC 8489 §6.2: at most ten transactions are outstanding to a server. One more waits, and
/// is sent when one of them ends.
#[test]
fn test_at_most_ten_transactions_are_outstanding_to_a_server() -> Result<()> {
    let now = Instant::now();
    let server = TestServer::new()?;
    let mut client = new_client(TransportProtocol::UDP)?;
    let ids: Vec<TransactionId> = (0..12)
        .map(|_| client.send_binding_request_to(now, server_addr()))
        .collect::<Result<_>>()?;

    let first_ten = server.requests(&mut client);
    assert_eq!(first_ten.len(), 10, "ten requests go out");
    assert!(
        ids.iter().all(|id| client.has_transaction(id)),
        "the other two are transactions that wait"
    );

    let later = now + Duration::from_millis(20);
    deliver(&mut client, later, &binding_success(&first_ten[0])?)?;
    let next = server.requests(&mut client);
    assert_eq!(next.len(), 1, "one ended, one more is sent");
    assert!(
        !first_ten
            .iter()
            .any(|r| r.transaction_id == next[0].transaction_id)
    );

    // A request that waits is answered as any other once it is sent.
    deliver(&mut client, later, &binding_success(&next[0])?)?;
    let mut answered = vec![];
    while let Some(event) = client.poll_event() {
        if let Event::BindingResponse(id, _) = event {
            answered.push(id);
        }
    }
    assert_eq!(answered.len(), 2);
    assert!(answered.contains(&next[0].transaction_id));
    client.close()
}

// --- FINGERPRINT on the wire: RFC 8489 §7 -----------------------------------------------

/// Every datagram the client has queued, raw, in order.
fn wire(client: &mut Client) -> Vec<Vec<u8>> {
    let mut out = vec![];
    while let Some(transmit) = client.poll_write() {
        out.push(transmit.message.to_vec());
    }
    out
}

/// The STUN requests among `datagrams`, decoded.
fn requests_in(datagrams: &[Vec<u8>]) -> Vec<Message> {
    datagrams
        .iter()
        .filter(|raw| is_stun_message(raw))
        .map(|raw| {
            let mut m = Message::new();
            m.raw = raw.clone();
            m.decode().expect("the client's message decodes");
            m
        })
        .filter(|m| m.typ.class == CLASS_REQUEST)
        .collect()
}

/// RFC 8489 §7: "When present, the FINGERPRINT attribute MUST be the last attribute in the
/// message", and the client uses it on every message (RFC 8656 §3 lets a TURN client do so,
/// and an ICE agent sharing the socket needs it to tell TURN apart). Read off the wire: a
/// Binding request (which had none) and its retransmissions, both Allocates of the 401 exchange,
/// CreatePermission, a Send indication, ChannelBind, Refresh and the deallocating Refresh all
/// end with a FINGERPRINT that verifies. (ChannelData is not STUN and carries none.)
#[test]
fn test_every_stun_message_the_client_sends_ends_with_a_valid_fingerprint() -> Result<()> {
    let now = Instant::now();
    let server = TestServer::new()?;
    let mut client = new_client(TransportProtocol::UDP)?;
    let peer: SocketAddr = "192.0.2.99:4000".parse().unwrap();
    let mut all: Vec<Vec<u8>> = vec![];

    // A Binding request, retransmitted on its timer and never answered.
    client.send_binding_request_to(now, server_addr())?;
    all.extend(wire(&mut client));
    let mut at = now;
    for _ in 0..3 {
        at = client.poll_timeout().expect("a retransmission is due");
        client.handle_timeout(at)?;
        all.extend(wire(&mut client));
    }

    // Allocate: the 401 exchange, then success.
    client.allocate(at)?;
    let sent = wire(&mut client);
    let first = requests_in(&sent).pop().expect("an Allocate");
    all.extend(sent);
    server.answer(
        &mut client,
        at,
        &first,
        CLASS_ERROR_RESPONSE,
        vec![
            error(CODE_UNAUTHORIZED),
            text(ATTR_NONCE, "nonce"),
            text(ATTR_REALM, REALM),
        ],
        None,
    )?;
    let sent = wire(&mut client);
    let second = requests_in(&sent)
        .pop()
        .expect("the Allocate with credentials");
    all.extend(sent);
    server.answer(
        &mut client,
        at,
        &second,
        CLASS_SUCCESS_RESPONSE,
        vec![relayed(relayed_addr()), lifetime(600)],
        Some(&server.key),
    )?;
    while client.poll_event().is_some() {}

    // CreatePermission.
    client.relay(relayed_addr())?.create_permission(at, peer)?;
    let sent = wire(&mut client);
    let permission = requests_in(&sent).pop().expect("a CreatePermission");
    all.extend(sent);
    server.succeed(&mut client, at, &permission)?;

    // The first data: a Send indication and a ChannelBind; once bound, ChannelData.
    client.relay(relayed_addr())?.send_to(at, b"first", peer)?;
    let sent = wire(&mut client);
    let bind = requests_in(&sent)
        .into_iter()
        .find(|m| m.typ.method == METHOD_CHANNEL_BIND)
        .expect("a ChannelBind");
    all.extend(sent);
    server.succeed(&mut client, at, &bind)?;
    client.relay(relayed_addr())?.send_to(at, b"second", peer)?;
    all.extend(wire(&mut client));

    // Refresh, then the Refresh with LIFETIME 0 that releases the allocation.
    client.refresh_allocations(at)?;
    let sent = wire(&mut client);
    let refresh = requests_in(&sent)
        .into_iter()
        .find(|m| m.typ.method == METHOD_REFRESH)
        .expect("a Refresh");
    all.extend(sent);
    server.answer(
        &mut client,
        at,
        &refresh,
        CLASS_SUCCESS_RESPONSE,
        vec![lifetime(600)],
        Some(&server.key),
    )?;
    client.relay(relayed_addr())?.close(at)?;
    all.extend(wire(&mut client));

    let mut methods = vec![];
    let mut stun_messages = 0;
    for raw in &all {
        if !is_stun_message(raw) {
            continue;
        }
        stun_messages += 1;
        let mut m = Message::new();
        m.raw = raw.clone();
        m.decode()?;
        assert_eq!(
            m.attributes.0.last().map(|a| a.typ),
            Some(ATTR_FINGERPRINT),
            "{m} ends with FINGERPRINT"
        );
        FINGERPRINT.check(&m)?;
        methods.push((m.typ.method, m.typ.class));
    }
    for expected in [
        (METHOD_BINDING, CLASS_REQUEST),
        (METHOD_ALLOCATE, CLASS_REQUEST),
        (METHOD_CREATE_PERMISSION, CLASS_REQUEST),
        (METHOD_SEND, CLASS_INDICATION),
        (METHOD_CHANNEL_BIND, CLASS_REQUEST),
        (METHOD_REFRESH, CLASS_REQUEST),
    ] {
        assert!(methods.contains(&expected), "{expected:?} was sent");
    }
    let bindings = methods
        .iter()
        .filter(|m| **m == (METHOD_BINDING, CLASS_REQUEST))
        .count();
    assert_eq!(bindings, 4, "the Binding request and three retransmissions");
    let refreshes = methods
        .iter()
        .filter(|m| **m == (METHOD_REFRESH, CLASS_REQUEST))
        .count();
    assert_eq!(refreshes, 2, "the refresh and the release");
    assert!(
        all.iter().any(|raw| !is_stun_message(raw)),
        "ChannelData went out too"
    );
    assert!(stun_messages >= 11);
    Ok(())
}

/// An error response with `code` and no integrity attribute, to `request`.
fn unsigned_error(request: &Message, code: ErrorCode) -> Result<Vec<u8>> {
    respond(
        request,
        CLASS_ERROR_RESPONSE,
        vec![error(code)],
        &Sign::Nothing,
        vec![],
    )
}

/// RFC 8489 §9.2.5: "If the response is an error response with an error code of 400 (Bad
/// Request) and does not contain either the MESSAGE-INTEGRITY or MESSAGE-INTEGRITY-SHA256
/// attribute, then the response MUST be discarded, as if it were never received." The rule
/// names no exception for the first Allocate, which carries no credential: the 400 does not
/// end it, and the server's 401 to it is still taken, over UDP and over TCP.
#[test]
fn test_an_unsigned_400_to_the_first_allocate_is_never_received() -> Result<()> {
    for transport in [TransportProtocol::UDP, TransportProtocol::TCP] {
        let now = Instant::now();
        let server = TestServer::new()?;
        let mut client = new_client(transport)?;
        client.allocate(now)?;
        let first = server.next_request(&mut client);
        assert!(!first.contains(ATTR_MESSAGE_INTEGRITY), "{transport:?}");

        deliver(&mut client, now, &unsigned_error(&first, CODE_BAD_REQUEST)?)?;
        assert!(
            client.poll_event().is_none(),
            "{transport:?}: the 400 reached the application"
        );
        assert!(
            client.has_transaction(&first.transaction_id),
            "{transport:?}: the 400 ended the Allocate"
        );

        server.challenge(&mut client, now, &first)?;
        let authenticated = server.next_request(&mut client);
        assert_ne!(authenticated.transaction_id, first.transaction_id);
        assert!(
            authenticated.contains(ATTR_MESSAGE_INTEGRITY),
            "{transport:?}: the 401 after the 400 is answered with the credential"
        );
        client.close()?;
    }
    Ok(())
}

/// RFC 8489 §9.2.5, the note to the 400 rule: "the 400 response will never reach the
/// application, resulting in a timeout." A first Allocate answered by nothing but an unsigned
/// 400 is retransmitted and ends as a timeout, not as the 400.
#[test]
fn test_a_first_allocate_answered_only_by_an_unsigned_400_times_out() -> Result<()> {
    let now = Instant::now();
    let server = TestServer::new()?;
    let mut client = new_client(TransportProtocol::UDP)?;
    let tid = client.allocate(now)?;
    let first = server.next_request(&mut client);
    deliver(&mut client, now, &unsigned_error(&first, CODE_BAD_REQUEST)?)?;

    let (requests, events) = drive_until(&server, &mut client, now + Duration::from_secs(60))?;
    assert!(
        !requests.is_empty()
            && requests
                .iter()
                .all(|r| r.transaction_id == first.transaction_id),
        "the retransmissions continue: {requests:?}"
    );
    assert!(
        matches!(events.as_slice(), [Event::TransactionTimeout(id)] if *id == tid),
        "expected the timeout alone, got {events:?}"
    );
    client.close()
}

/// RFC 8489 §9.2.5: an unsigned 400 to a request that carried the credential is discarded "as
/// if it were never received" too, by the 400 rule rather than by the general one for
/// responses that are not authentic: it is not counted as a discarded response (the request
/// ends in a timeout, as the rule's note says, not in an integrity violation) and over TCP it
/// does not end the transaction at once.
#[test]
fn test_an_unsigned_400_to_a_signed_request_is_never_received() -> Result<()> {
    for transport in [TransportProtocol::UDP, TransportProtocol::TCP] {
        let now = Instant::now();
        let server = TestServer::new()?;
        let mut client = new_client(transport)?;
        let (tid, _, authenticated) =
            server.begin_allocate(&mut client, now, AllocateOptions::default())?;
        assert!(authenticated.contains(ATTR_MESSAGE_INTEGRITY));

        deliver(
            &mut client,
            now,
            &unsigned_error(&authenticated, CODE_BAD_REQUEST)?,
        )?;
        assert!(
            client.poll_event().is_none(),
            "{transport:?}: the 400 reached the application"
        );
        assert!(
            client.has_transaction(&authenticated.transaction_id),
            "{transport:?}: the 400 ended the Allocate"
        );

        let (requests, events) = drive_until(&server, &mut client, now + Duration::from_secs(120))?;
        assert!(
            requests
                .iter()
                .all(|r| r.transaction_id == authenticated.transaction_id),
            "{transport:?}: {requests:?}"
        );
        if transport == TransportProtocol::UDP {
            assert!(!requests.is_empty(), "the retransmissions continue");
        }
        assert!(
            matches!(events.as_slice(), [Event::TransactionTimeout(id)] if *id == tid),
            "{transport:?}: expected the timeout alone, got {events:?}"
        );
        client.close()?;
    }
    Ok(())
}

/// RFC 8489 §9.2.5: "For all other responses [than 401 and 438], if the NONCE attribute starts
/// with the "nonce cookie" with the STUN Security Feature "Password algorithms" bit set to 1
/// but PASSWORD-ALGORITHMS is not present, the response MUST be ignored." That holds for the
/// response to the first Allocate as well: such a 403 does not end it (one without the cookie
/// does: `test_an_error_to_the_first_allocate_keeps_its_code`).
#[test]
fn test_an_error_to_the_first_allocate_whose_nonce_cookie_promises_algorithms_is_ignored()
-> Result<()> {
    let now = Instant::now();
    let server = TestServer::new()?;
    let mut client = new_client(TransportProtocol::UDP)?;
    client.allocate(now)?;
    let first = server.next_request(&mut client);
    let tampered = respond(
        &first,
        CLASS_ERROR_RESPONSE,
        vec![
            error(CODE_FORBIDDEN),
            text(
                ATTR_NONCE,
                &nonce_with(SecurityFeatures::PASSWORD_ALGORITHMS, "x"),
            ),
            text(ATTR_REALM, REALM),
        ],
        &Sign::Nothing,
        vec![],
    )?;
    deliver(&mut client, now, &tampered)?;
    assert!(
        client.poll_event().is_none(),
        "the 403 reached the application"
    );
    assert!(client.has_transaction(&first.transaction_id));

    server.challenge(&mut client, now, &first)?;
    let authenticated = server.next_request(&mut client);
    assert!(authenticated.contains(ATTR_MESSAGE_INTEGRITY));
    client.close()
}
