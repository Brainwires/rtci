//! What the application chooses about the TURN client's RFC 8489 behaviour: the timer's
//! parameters (section 6.2), the password algorithms it accepts (section 18.5.1.1), new
//! credentials for a live allocation, and following a 300 (Try Alternate) (section 10).
use super::client_stun8489_test::*;
use super::test_server::*;
use super::*;
use sansio::Protocol;
use stun::addr::AlternateServer;
use stun::error_code::*;
use stun::integrity::{MessageIntegritySha256, long_term_key};
use stun::nonce_cookie::SecurityFeatures;
use stun::password_algorithm::{
    PASSWORD_ALGORITHM_MD5, PASSWORD_ALGORITHM_SHA256, PasswordAlgorithm,
};

fn client_with(
    transport_protocol: TransportProtocol,
    configure: impl FnOnce(&mut ClientConfig),
) -> Result<Client> {
    let mut config = ClientConfig {
        turn_serv_addr: server_addr().to_string(),
        local_addr: local_addr(),
        transport_protocol,
        username: USERNAME.to_owned(),
        password: PASSWORD.to_owned(),
        ..Default::default()
    };
    configure(&mut config);
    Client::new(config, test_crypto_provider())
}

/// When the client sent, and when its one transaction timed out, as milliseconds from
/// `start`.
fn run_to_the_end(client: &mut Client, start: Instant) -> Result<(Vec<u128>, Option<u128>)> {
    let mut sent = vec![];
    let mut timed_out = None;
    let mut last = start;
    loop {
        while let Some(transmit) = client.poll_write() {
            sent.push(transmit.now.saturating_duration_since(start).as_millis());
        }
        while let Some(event) = client.poll_event() {
            if matches!(event, Event::TransactionTimeout(_)) {
                timed_out = Some(last.saturating_duration_since(start).as_millis());
            }
        }
        let Some(deadline) = client.poll_timeout() else {
            break;
        };
        client.handle_timeout(deadline)?;
        last = deadline;
    }
    Ok((sent, timed_out))
}

/// RFC 8489 §6.2.1, §6.2.2: the initial RTO, Rc, Rm and Ti are configurable.
#[test]
fn test_rto_rc_rm_and_ti_are_configurable() -> Result<()> {
    let start = Instant::now();

    // Three requests 100 and 200 ms apart, failing 4 x 100 ms after the last.
    let mut client = client_with(TransportProtocol::UDP, |config| {
        config.rto_in_ms = 100;
        config.retransmission.rc = 3;
        config.retransmission.rm = 4;
    })?;
    client.send_binding_request_to(start, server_addr())?;
    assert_eq!(
        run_to_the_end(&mut client, start)?,
        (vec![0, 100, 300], Some(700))
    );

    // Over a reliable transport: sent once, failing after Ti.
    let mut client = client_with(TransportProtocol::TCP, |config| {
        config.retransmission.ti = Duration::from_secs(5);
    })?;
    client.send_binding_request_to(start, server_addr())?;
    assert_eq!(run_to_the_end(&mut client, start)?, (vec![0], Some(5_000)));
    Ok(())
}

/// RFC 8489 §6.2.1: without the RFC 6298 estimate every transaction starts at the initial
/// RTO, whatever the server's round-trip time was.
#[test]
fn test_rto_estimation_can_be_turned_off() -> Result<()> {
    let start = Instant::now();
    let at = |millis: u64| start + Duration::from_millis(millis);
    let server = TestServer::new()?;
    let mut client = client_with(TransportProtocol::UDP, |config| {
        config.retransmission.rto_estimation = false;
    })?;

    client.send_binding_request_to(at(0), server_addr())?;
    let request = server.next_request(&mut client);
    let answer = respond(
        &request,
        CLASS_SUCCESS_RESPONSE,
        vec![Box::new(XorMappedAddress {
            ip: local_addr().ip(),
            port: local_addr().port(),
        })],
        &Sign::Nothing,
        vec![],
    )?;
    deliver(&mut client, at(400), &answer)?;
    client.send_binding_request_to(at(1_000), server_addr())?;
    assert_eq!(client.poll_timeout(), Some(at(1_500)));
    client.close()
}

/// RFC 8489 §6.2: the limit of ten outstanding transactions is for a client without another
/// rate limit; one that has its own lifts it.
#[test]
fn test_outstanding_transaction_limit_is_configurable() -> Result<()> {
    let now = Instant::now();
    let server = TestServer::new()?;

    let mut client = client_with(TransportProtocol::UDP, |config| {
        config.retransmission.max_outstanding_transactions = 0;
    })?;
    for _ in 0..12 {
        client.send_binding_request_to(now, server_addr())?;
    }
    assert_eq!(server.requests(&mut client).len(), 12);

    let mut client = client_with(TransportProtocol::UDP, |config| {
        config.retransmission.max_outstanding_transactions = 2;
    })?;
    for _ in 0..12 {
        client.send_binding_request_to(now, server_addr())?;
    }
    assert_eq!(server.requests(&mut client).len(), 2);

    // A transaction that times out makes room as one that is answered does.
    let (requests, _) = drive_until(&server, &mut client, now + Duration::from_secs(40))?;
    let distinct: std::collections::HashSet<TransactionId> =
        requests.iter().map(|r| r.transaction_id).collect();
    assert_eq!(
        distinct.len(),
        4,
        "the first two, and the two sent when they timed out"
    );
    client.close()
}

/// RFC 8489 §18.5.1.1: MD5 is for servers that have nothing else. A client told to accept
/// SHA-256 only does not authenticate to a server that offers no PASSWORD-ALGORITHMS (an RFC
/// 5389 server, which means MD5); one told to accept MD5 only uses MD5 where both are on
/// offer, which RFC 8656 §6 allows a client that does not support both.
#[test]
fn test_accepted_password_algorithms_are_the_applications_choice() -> Result<()> {
    let now = Instant::now();
    let server = TestServer::new()?;
    let provider = test_crypto_provider();

    let mut client = client_with(TransportProtocol::UDP, |config| {
        config.password_algorithms = vec![PASSWORD_ALGORITHM_SHA256];
    })?;
    let tid = client.allocate(now)?;
    let first = server.next_request(&mut client);
    server.challenge(&mut client, now, &first)?;
    assert!(
        server.requests(&mut client).is_empty(),
        "the client fell back to MD5"
    );
    assert!(matches!(
        client.poll_event(),
        Some(Event::AllocateError(id, RequestError::Failed(_))) if id == tid
    ));

    let mut client = client_with(TransportProtocol::UDP, |config| {
        config.password_algorithms = vec![PASSWORD_ALGORITHM_MD5];
    })?;
    client.allocate(now)?;
    let first = server.next_request(&mut client);
    let nonce = nonce_with(SecurityFeatures::PASSWORD_ALGORITHMS, "n");
    deliver(&mut client, now, &challenge_8489(&first, &nonce)?)?;
    let second = server.next_request(&mut client);
    let mut algorithm = PasswordAlgorithm::default();
    algorithm.get_from(&second)?;
    assert_eq!(algorithm.algorithm, PASSWORD_ALGORITHM_MD5);
    // The MD5 key, under the integrity attribute a server with PASSWORD-ALGORITHMS takes.
    let key = long_term_key(
        PASSWORD_ALGORITHM_MD5,
        USERNAME,
        REALM,
        PASSWORD,
        provider.crypto(),
    )?;
    MessageIntegritySha256::check(&second, &key, provider.crypto())?;
    client.close()
}

/// `Client::update_credentials` gives a live allocation a new password within what the server
/// negotiated: the realm, the nonce and the password algorithm stay, the key changes.
#[test]
fn test_new_password_keeps_the_negotiated_realm_nonce_and_algorithm() -> Result<()> {
    let now = Instant::now();
    let server = TestServer::new()?;
    let provider = test_crypto_provider();
    let mut client = new_client(TransportProtocol::UDP)?;
    allocate_sha256(&mut client, now, AllocateOptions::default())?;

    client.update_credentials(USERNAME.to_owned(), "rotated".to_owned())?;
    client.refresh_allocations(now)?;
    let refresh = server.next_request(&mut client);
    assert_eq!(
        nonce_of(&refresh),
        nonce_with(SecurityFeatures::PASSWORD_ALGORITHMS, "first")
    );
    assert!(!refresh.contains(ATTR_MESSAGE_INTEGRITY));
    MessageIntegritySha256::check(&refresh, &sha256_key(REALM, "rotated")?, provider.crypto())?;
    client.close()
}

/// RFC 8489 §14.3, §9.2.2: the USERNAME is an OpaqueString (RFC 8265): what the application
/// gave is sent in Unicode normalization form C, and the key is made of that.
#[test]
fn test_username_is_sent_as_an_opaque_string() -> Result<()> {
    let now = Instant::now();
    let server = TestServer::new()?;
    let provider = test_crypto_provider();
    // "e" and a combining acute accent; NFC has one code point for the two.
    let mut client = client_with(TransportProtocol::UDP, |config| {
        config.username = "ren\u{0065}\u{0301}".to_owned();
    })?;
    client.allocate(now)?;
    let first = server.next_request(&mut client);
    server.challenge(&mut client, now, &first)?;

    let mut second = server.next_request(&mut client);
    assert_eq!(
        Username::get_from_as(&second, ATTR_USERNAME)?.text,
        "ren\u{00e9}"
    );
    let key = long_term_key(
        PASSWORD_ALGORITHM_MD5,
        "ren\u{00e9}",
        REALM,
        PASSWORD,
        provider.crypto(),
    )?;
    MessageIntegrity::check(&mut second, &key, provider.crypto())?;
    client.close()
}

// --- 300 (Try Alternate): RFC 8489 §10, RFC 8656 §7.4 --------------------------------------

fn alternate_v4() -> SocketAddr {
    "192.0.2.77:3478".parse().unwrap()
}

fn alternate_v6() -> SocketAddr {
    "[2001:db8::77]:3478".parse().unwrap()
}

fn alternate(addr: SocketAddr) -> Box<dyn Setter> {
    Box::new(AlternateServer {
        ip: addr.ip(),
        port: addr.port(),
    })
}

/// Takes an Allocate through the 401 of the server at `from` and answers the authenticated
/// request with a signed 300 naming `to`: returns the redirection the client reports.
fn redirected(
    client: &mut Client,
    now: Instant,
    from: SocketAddr,
    to: Vec<SocketAddr>,
) -> Result<stun::alternate::TryAlternate> {
    let server = TestServer::new()?;
    let tid = client.allocate(now)?;
    let first = server.next_request(client);
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
    deliver_from(client, now, from, &challenge)?;
    let authenticated = server.next_request(client);
    let mut attrs = vec![error(CODE_TRY_ALTERNATE)];
    attrs.extend(to.into_iter().map(alternate));
    attrs.push(text(ATTR_ALTERNATE_DOMAIN, "alternate.example"));
    let redirect = respond(
        &authenticated,
        CLASS_ERROR_RESPONSE,
        attrs,
        &Sign::Sha1(server.key.clone()),
        vec![],
    )?;
    deliver_from(client, now, from, &redirect)?;
    match client.poll_event() {
        Some(Event::AllocateError(id, RequestError::Rejected(rejected))) => {
            assert_eq!(id, tid);
            assert_eq!(rejected.code, CODE_TRY_ALTERNATE);
            Ok(rejected
                .try_alternate
                .expect("an authenticated 300 gives the redirection"))
        }
        other => panic!("expected AllocateError, got {other:?}"),
    }
}

/// RFC 8489 §10, §14.8: a 300 that was authenticated with the request's credential gives
/// the alternate servers and the ALTERNATE-DOMAIN. The client does not follow it by itself;
/// an application that does gets the server of the family it used, the same transport, and
/// the same credentials in the request it makes there.
#[test]
fn test_an_authenticated_300_is_reported_and_can_be_followed() -> Result<()> {
    let now = Instant::now();
    let server = TestServer::new()?;
    let mut client = new_client(TransportProtocol::UDP)?;
    let redirect = redirected(
        &mut client,
        now,
        server_addr(),
        vec![alternate_v4(), alternate_v6()],
    )?;
    assert_eq!(redirect.servers, vec![alternate_v4(), alternate_v6()]);
    assert_eq!(redirect.domain.as_deref(), Some("alternate.example"));

    assert!(
        server.requests(&mut client).is_empty(),
        "the client followed the redirection by itself"
    );
    assert_eq!(client.turn_server_addr(), Some(server_addr()));

    assert_eq!(client.follow_alternate(now, &redirect)?, alternate_v4());
    assert_eq!(client.turn_server_addr(), Some(alternate_v4()));

    client.allocate(now)?;
    let out = client.poll_write().expect("an Allocate for the alternate");
    assert_eq!(out.transport.peer_addr, alternate_v4());
    assert_eq!(out.transport.transport_protocol, TransportProtocol::UDP);
    let mut first = Message::new();
    first.raw = out.message.to_vec();
    first.decode()?;
    assert_eq!(first.typ.method, METHOD_ALLOCATE);

    // The alternate asks for the credential and gets the one the first server was given.
    let challenge = respond(
        &first,
        CLASS_ERROR_RESPONSE,
        vec![
            error(CODE_UNAUTHORIZED),
            text(ATTR_NONCE, "nonce of the alternate"),
            text(ATTR_REALM, REALM),
        ],
        &Sign::Nothing,
        vec![],
    )?;
    deliver_from(&mut client, now, alternate_v4(), &challenge)?;
    let mut authenticated = server.next_request(&mut client);
    assert_eq!(
        Username::get_from_as(&authenticated, ATTR_USERNAME)?.text,
        USERNAME
    );
    MessageIntegrity::check(
        &mut authenticated,
        &server.key,
        test_crypto_provider().crypto(),
    )?;
    client.close()
}

/// RFC 8489 §14.8: a client validates a 300 before it redirects itself. One that is not
/// signed (to the first Allocate, say, which carries no credential) is reported with its
/// ALTERNATE-SERVER and gives no redirection to follow.
#[test]
fn test_an_unauthenticated_300_gives_no_redirection() -> Result<()> {
    let now = Instant::now();
    let server = TestServer::new()?;
    let mut client = new_client(TransportProtocol::UDP)?;
    let tid = client.allocate(now)?;
    let first = server.next_request(&mut client);
    let redirect = respond(
        &first,
        CLASS_ERROR_RESPONSE,
        vec![error(CODE_TRY_ALTERNATE), alternate(alternate_v4())],
        &Sign::Nothing,
        vec![],
    )?;
    deliver(&mut client, now, &redirect)?;

    match client.poll_event() {
        Some(Event::AllocateError(id, RequestError::Rejected(rejected))) => {
            assert_eq!(id, tid);
            assert_eq!(rejected.alternate_server, Some(alternate_v4()));
            assert_eq!(rejected.try_alternate, None);
        }
        other => panic!("expected AllocateError, got {other:?}"),
    }
    assert!(server.requests(&mut client).is_empty());
    assert_eq!(client.turn_server_addr(), Some(server_addr()));
    client.close()
}

/// RFC 8489 §10: a redirection to a server the request was sent to within the last five
/// minutes is ignored, and the transaction has failed. After that it may be followed.
#[test]
fn test_a_redirection_back_within_five_minutes_is_refused() -> Result<()> {
    let now = Instant::now();
    let mut client = new_client(TransportProtocol::UDP)?;
    let there = redirected(&mut client, now, server_addr(), vec![alternate_v4()])?;
    client.follow_alternate(now, &there)?;

    let soon = now + Duration::from_secs(10);
    let back = redirected(&mut client, soon, alternate_v4(), vec![server_addr()])?;
    assert!(
        client.follow_alternate(soon, &back).is_err(),
        "a redirection loop was followed"
    );
    assert_eq!(
        client.turn_server_addr(),
        Some(alternate_v4()),
        "a refused redirection changes nothing"
    );

    // Five minutes after the Allocate that went to the first server.
    let later = now + Duration::from_secs(300);
    assert_eq!(client.follow_alternate(later, &back)?, server_addr());
    assert_eq!(client.turn_server_addr(), Some(server_addr()));
    client.close()
}

/// The server of a client that holds an allocation does not change under it.
#[test]
fn test_a_redirection_is_not_followed_while_an_allocation_is_held() -> Result<()> {
    let now = Instant::now();
    let server = TestServer::new()?;
    let mut client = new_client(TransportProtocol::UDP)?;
    server.allocate(&mut client, now)?;
    let redirect = stun::alternate::TryAlternate {
        servers: vec![alternate_v4()],
        domain: None,
    };
    assert!(client.follow_alternate(now, &redirect).is_err());
    assert_eq!(client.turn_server_addr(), Some(server_addr()));
    client.close()
}
