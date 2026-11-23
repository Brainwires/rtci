//! RFC 8489 Sections 6.1 and 14.8 for the TURN client: SOFTWARE by default, no request over
//! UDP beyond the path MTU, a 400 not retried.

use super::test_server::*;
use super::*;
use sansio::Protocol;
use stun::error_code::CODE_BAD_REQUEST;

fn software_of(request: &Message) -> Option<String> {
    Software::get_from_as(request, ATTR_SOFTWARE)
        .ok()
        .map(|s| s.text)
}

/// Section 6.1: requests "SHOULD" carry SOFTWARE; Section 16.1.2: configurable. By default it
/// names this crate and its version; an empty value sends none.
#[test]
fn test_requests_carry_rtc_turn_and_its_version_by_default_and_none_when_set_empty() -> Result<()> {
    let now = Instant::now();
    let server = TestServer::new()?;
    let mut client = new_client(TransportProtocol::UDP)?;
    let (_, first, authenticated) =
        server.begin_allocate(&mut client, now, AllocateOptions::default())?;
    assert_eq!(software_of(&first).as_deref(), Some(DEFAULT_SOFTWARE));
    assert_eq!(
        software_of(&authenticated).as_deref(),
        Some(DEFAULT_SOFTWARE)
    );
    assert!(DEFAULT_SOFTWARE.starts_with("rtc-turn "));

    let mut quiet = Client::new(
        ClientConfig {
            turn_serv_addr: server_addr().to_string(),
            local_addr: local_addr(),
            transport_protocol: TransportProtocol::UDP,
            username: USERNAME.to_owned(),
            password: PASSWORD.to_owned(),
            software: String::new(),
            ..Default::default()
        },
        test_crypto_provider(),
    )?;
    quiet.allocate(now)?;
    assert_eq!(software_of(&server.next_request(&mut quiet)), None);
    Ok(())
}

/// Section 6.1: outside MTU probing, a STUN message over UDP keeps within the path MTU. A
/// request that would not is refused before anything is sent; over TCP there is no such
/// limit.
#[test]
fn test_a_request_beyond_the_path_mtu_is_not_sent_over_udp() -> Result<()> {
    let now = Instant::now();
    let server = TestServer::new()?;
    let mut client = new_client(TransportProtocol::UDP)?;
    // Smaller than an Allocate (20-byte header, REQUESTED-TRANSPORT, SOFTWARE, FINGERPRINT)
    // plus 28 bytes of IPv4 and UDP.
    client.set_path_mtu(Some(60));
    assert_eq!(client.allocate(now), Err(Error::ErrPacketTooBig));
    assert!(client.poll_write().is_none(), "nothing left");
    // With the path's real MTU it goes.
    client.set_path_mtu(None);
    client.allocate(now)?;
    assert!(!server.requests(&mut client).is_empty());

    let mut tcp = new_client(TransportProtocol::TCP)?;
    tcp.set_path_mtu(Some(60));
    tcp.allocate(now)?;
    assert!(
        tcp.poll_write().is_some(),
        "over TCP the MTU does not limit STUN"
    );
    Ok(())
}

/// Section 14.8: a request answered 400 "SHOULD NOT" be retried unmodified. The Allocate's
/// 400 ends it with an error event; nothing is sent again, also when the timers run.
#[test]
fn test_an_allocate_answered_400_is_not_retried() -> Result<()> {
    let now = Instant::now();
    let server = TestServer::new()?;
    let mut client = new_client(TransportProtocol::UDP)?;
    let (_, _, authenticated) =
        server.begin_allocate(&mut client, now, AllocateOptions::default())?;
    server.reject(&mut client, now, &authenticated, CODE_BAD_REQUEST)?;
    let events: Vec<Event> = std::iter::from_fn(|| client.poll_event()).collect();
    assert!(
        events
            .iter()
            .any(|e| matches!(e, Event::AllocateError(_, err) if err.is(CODE_BAD_REQUEST))),
        "{events:?}"
    );
    let (later, _) = drive_until(&server, &mut client, now + Duration::from_secs(60))?;
    assert!(
        later.iter().all(|m| m.typ.method != METHOD_ALLOCATE),
        "the refused request is not sent again: {later:?}"
    );
    Ok(())
}
