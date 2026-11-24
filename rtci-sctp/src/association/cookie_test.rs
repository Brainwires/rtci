//! RFC 9260 5.1.3 and 5.1.5: the State Cookie with a MAC, and the handshake in which the
//! accepting side keeps nothing between the INIT and the COOKIE ECHO.

use super::robustness_test::*;
use super::*;
use crate::chunk::chunk_type::*;
use crate::cookie::COOKIE_LENGTH;
use crate::endpoint::link_test::Link;
use crate::endpoint::{DatagramEvent, Endpoint};
use crate::{EndpointConfig, ServerConfig};

const CLIENT_TAG: u32 = 0x0c11_e47a;
const CLIENT_TSN: u32 = 9000;

fn remote() -> SocketAddr {
    SocketAddr::from(([10, 0, 0, 1], 5000))
}

fn server_config(transport: TransportConfig) -> ServerConfig {
    let mut config = ServerConfig::new(transport);
    config.cookie_authentication(crypto::default_provider().expect("a crypto provider"));
    config
}

fn accepting_endpoint(transport: TransportConfig) -> Endpoint {
    Endpoint::new(
        SocketAddr::from(([10, 0, 0, 2], 5000)),
        TransportProtocol::UDP,
        Arc::new(EndpointConfig::default()),
        Some(Arc::new(server_config(transport))),
    )
}

/// An INIT with the Supported Extensions the engine itself sends.
fn init_packet() -> Bytes {
    let extensions = raw_tlv(0x8008, &[CT_RECONFIG.0, CT_FORWARD_TSN.0]);
    raw_packet(
        5000,
        5000,
        0,
        &[init_chunk(CT_INIT.0, CLIENT_TAG, CLIENT_TSN, &[extensions])],
    )
}

fn endpoint_output(endpoint: &mut Endpoint) -> Vec<Bytes> {
    let mut out = vec![];
    while let Some(transmit) = endpoint.poll_transmit() {
        if let Payload::RawEncode(contents) = transmit.message {
            out.extend(contents);
        }
    }
    out
}

/// Sends the INIT and returns the server's Initiate Tag and the State Cookie of its INIT ACK.
fn init_ack_of(endpoint: &mut Endpoint, now: Instant) -> (u32, Vec<u8>) {
    assert!(
        endpoint
            .handle(now, remote(), None, init_packet())
            .is_none(),
        "no association is made for an INIT"
    );
    let sent = endpoint_output(endpoint);
    assert_eq!(1, sent.len(), "the INIT ACK");
    let init_ack = &chunks_of_type(&sent, CT_INIT_ACK.0)[0];
    let tag = u32::from_be_bytes(init_ack[4..8].try_into().unwrap());
    let cookie = tlvs(&init_ack[20..])
        .into_iter()
        .find(|(typ, _)| *typ == 7)
        .expect("a State Cookie")
        .1;
    (tag, cookie)
}

fn cookie_echo(tag: u32, cookie: &[u8], more: &[Vec<u8>]) -> Bytes {
    let mut chunks = vec![raw_chunk(CT_COOKIE_ECHO.0, 0, cookie)];
    chunks.extend_from_slice(more);
    raw_packet(5000, 5000, tag, &chunks)
}

/// RFC 9260 5.1 B, 5.1.3, 5.1.5: the INIT is answered and nothing is kept; the State Cookie
/// carries what the association is made from, with a MAC; the COOKIE ECHO that brings it
/// back makes the association, established at once, and the DATA bundled with it is taken.
#[test]
fn the_association_is_made_from_the_cookie_alone() {
    let mut endpoint = accepting_endpoint(TransportConfig::default());
    let now = Instant::now();
    let (tag, cookie) = init_ack_of(&mut endpoint, now);
    assert_eq!(COOKIE_LENGTH, cookie.len());
    assert_eq!(
        0,
        endpoint.association_count(),
        "state was kept after the INIT ACK"
    );
    // A second INIT is answered the same way: another tag, another cookie, still no state.
    let (other_tag, other_cookie) = init_ack_of(&mut endpoint, now);
    assert_ne!(tag, other_tag);
    assert_ne!(cookie, other_cookie);
    assert_eq!(0, endpoint.association_count());

    let later = now + Duration::from_secs(5);
    let data = data_chunk(CLIENT_TSN, 3, 0, b"with the cookie");
    let Some((_, DatagramEvent::NewAssociation(mut a))) =
        endpoint.handle(later, remote(), None, cookie_echo(tag, &cookie, &[data]))
    else {
        panic!("the COOKIE ECHO makes the association");
    };
    assert_eq!(1, endpoint.association_count());
    assert_eq!(AssociationState::Established, a.state());
    assert!(matches!(a.poll(), Some(Event::Connected)));
    // What the INIT said came back with the cookie.
    assert_eq!(tag, a.verification_tag());
    assert_eq!(CLIENT_TAG, a.peer_verification_tag);
    assert_eq!(Some(1024), a.negotiated_max_streams());
    assert!(a.partial_reliability() && a.peer_supports_reconfig());
    assert_eq!(CLIENT_TSN, a.peer_last_tsn, "the DATA that came with it");
    assert_eq!(
        vec![Bytes::from_static(b"with the cookie")],
        read_all(&mut a, 3)
    );
    let sent = sent_datagrams(&mut a, later);
    assert_eq!(1, chunks_of_type(&sent, CT_COOKIE_ACK.0).len());
    assert_eq!(1, chunks_of_type(&sent, CT_SACK.0).len());
    // RFC 9260 3.3.12, 5.1 D, 5.1.5: the COOKIE ACK "MAY be bundled with any pending DATA
    // chunks (and/or SACK chunks)": the SACK for the DATA that came with the cookie shares
    // its packet.
    assert_eq!(1, sent.len(), "the COOKIE ACK and the SACK in one packet");
    assert!(
        sent.iter().all(|d| d[4..8] == CLIENT_TAG.to_be_bytes()),
        "the peer's tag, from the cookie"
    );

    // The COOKIE ECHO again (the COOKIE ACK was lost) goes to the association, which
    // acknowledges it again.
    let Some((_, DatagramEvent::AssociationEvent(event))) =
        endpoint.handle(later, remote(), None, cookie_echo(tag, &cookie, &[]))
    else {
        panic!("the association exists now");
    };
    a.handle_event(event);
    assert_eq!(
        1,
        chunks_of_type(&sent_datagrams(&mut a, later), CT_COOKIE_ACK.0).len()
    );
    assert_eq!(1, endpoint.association_count());
}

/// RFC 9260 5.1.5 1) to 3): a cookie whose MAC does not verify, or that comes with another
/// tag or between other ports, is discarded silently.
#[test]
fn a_cookie_that_does_not_verify_is_discarded() {
    let mut endpoint = accepting_endpoint(TransportConfig::default());
    let now = Instant::now();
    let (tag, cookie) = init_ack_of(&mut endpoint, now);

    // One bit of the MAC; one bit of what it protects (the peer's window, the stream
    // counts, the time it was made); a cookie cut short; one of another version.
    let mut forged = vec![];
    for at in [COOKIE_LENGTH - 1, 24, 28, 4] {
        let mut changed = cookie.clone();
        changed[at] ^= 1;
        forged.push(changed);
    }
    forged.push(cookie[..COOKIE_LENGTH - 4].to_vec());
    let mut version = cookie.clone();
    version[0] = 2;
    forged.push(version);
    for (n, bad) in forged.iter().enumerate() {
        assert!(
            endpoint
                .handle(now, remote(), None, cookie_echo(tag, bad, &[]))
                .is_none(),
            "forged cookie {n}"
        );
    }
    // The cookie itself, with another Verification Tag and from another port.
    assert!(
        endpoint
            .handle(now, remote(), None, cookie_echo(tag ^ 1, &cookie, &[]))
            .is_none()
    );
    let other_port = raw_packet(5001, 5000, tag, &[raw_chunk(CT_COOKIE_ECHO.0, 0, &cookie)]);
    assert!(endpoint.handle(now, remote(), None, other_port).is_none());
    assert!(
        endpoint_output(&mut endpoint).is_empty(),
        "nothing is answered"
    );
    assert_eq!(0, endpoint.association_count());

    assert!(
        endpoint
            .handle(now, remote(), None, cookie_echo(tag, &cookie, &[]))
            .is_some(),
        "the cookie as it was sent is good"
    );
}

/// RFC 9260 5.1.5 4): a cookie older than Valid.Cookie.Life is answered with an ERROR
/// "Stale Cookie Error" that says by how many microseconds, and makes no association.
#[test]
fn a_stale_signed_cookie_is_refused_with_its_staleness() {
    let life = Duration::from_secs(10);
    let mut endpoint = accepting_endpoint(TransportConfig::default().with_valid_cookie_life(life));
    let now = Instant::now();
    let (tag, cookie) = init_ack_of(&mut endpoint, now);

    let late = now + life + Duration::from_millis(250);
    assert!(
        endpoint
            .handle(late, remote(), None, cookie_echo(tag, &cookie, &[]))
            .is_none()
    );
    let sent = endpoint_output(&mut endpoint);
    assert_eq!(1, sent.len());
    assert_eq!(
        CLIENT_TAG.to_be_bytes(),
        sent[0][4..8],
        "sent with the peer's tag, which the cookie holds"
    );
    let causes = tlvs(&chunks_of_type(&sent, CT_ERROR.0)[0][4..]);
    assert_eq!(vec![(3u16, 250_000u32.to_be_bytes().to_vec())], causes);
    assert_eq!(0, endpoint.association_count());

    // Within its life it is good.
    let (tag, cookie) = init_ack_of(&mut endpoint, late);
    assert!(
        endpoint
            .handle(late + life, remote(), None, cookie_echo(tag, &cookie, &[]))
            .is_some()
    );
}

/// RFC 9260 5.1.3: the key is changed reasonably often, and the cookie says which key made
/// it. A cookie of the key before the current one is still good; one of a key that is gone
/// is discarded silently (5.1.5 1).
#[test]
fn the_cookie_key_is_replaced_and_the_one_before_it_kept() {
    let hours = |n: u64| Duration::from_secs(3600 * n + n);
    let mut endpoint =
        accepting_endpoint(TransportConfig::default().with_valid_cookie_life(hours(10)));
    let now = Instant::now();
    let (first_tag, first) = init_ack_of(&mut endpoint, now);
    let (_, same_key) = init_ack_of(&mut endpoint, now + Duration::from_secs(60));
    assert_eq!(first[1], same_key[1], "one key");

    // An hour later the next INIT is answered under a new key, and an hour after that
    // under a third.
    let (second_tag, second) = init_ack_of(&mut endpoint, now + hours(1));
    assert_ne!(first[1], second[1], "the key id the cookie names");
    let (_, third) = init_ack_of(&mut endpoint, now + hours(2));
    assert_ne!(second[1], third[1]);

    let at = now + hours(2);
    assert!(
        endpoint
            .handle(at, remote(), None, cookie_echo(first_tag, &first, &[]))
            .is_none(),
        "the first key is gone"
    );
    assert!(endpoint_output(&mut endpoint).is_empty(), "silently");
    assert!(
        endpoint
            .handle(at, remote(), None, cookie_echo(second_tag, &second, &[]))
            .is_some(),
        "a cookie of the key before the current one is good"
    );
}

/// The whole handshake over a link that loses the first COOKIE ECHO: the accepting endpoint
/// holds no association until the cookie arrives, then both sides exchange data.
#[test]
fn a_stateless_handshake_completes_and_carries_data() {
    let mut link = Link::with_server_config(
        TransportConfig::default(),
        server_config(TransportConfig::default()),
        951,
    );
    link.server.endpoint_answers = true;
    let mut dropped = false;
    link.filter = Some(Box::new(move |from_client, datagram: &Bytes| {
        let first = from_client && datagram.get(12) == Some(&CT_COOKIE_ECHO.0) && !dropped;
        dropped |= first;
        first
    }));
    link.begin_connect();
    link.run_for(Duration::from_millis(500));
    assert!(link.server.association.is_none());
    assert_eq!(0, link.server.endpoint_associations());

    let deadline = link.now + Duration::from_secs(30);
    assert!(link.run_until(deadline, |l| l.client.connected()
        && l.server.association.is_some()
        && l.server.connected()));
    assert_eq!(1, link.server.endpoint_associations());

    let now = link.now;
    link.client
        .conn()
        .open_stream(1, PayloadProtocolIdentifier::Binary)
        .unwrap()
        .write_sctp(
            now,
            &Bytes::from_static(b"ping"),
            PayloadProtocolIdentifier::Binary,
        )
        .unwrap();
    let deadline = link.now + Duration::from_secs(5);
    assert!(link.run_until(deadline, |l| !l.server.received.is_empty()));
    let now = link.now;
    link.server
        .conn()
        .stream(1)
        .unwrap()
        .write_sctp(
            now,
            &Bytes::from_static(b"pong"),
            PayloadProtocolIdentifier::Binary,
        )
        .unwrap();
    let deadline = link.now + Duration::from_secs(5);
    assert!(link.run_until(deadline, |l| !l.client.received.is_empty()));
}
