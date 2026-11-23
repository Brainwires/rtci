//! A lost COOKIE ACK (RFC 9260 5.1, 5.2.4): the side that sent the COOKIE ECHO stays in
//! COOKIE-ECHOED and discards the DATA that reaches it (5.1: it SHOULD), while its peer is
//! ESTABLISHED and has DATA outstanding; the handshake timers (5.1, 6.3, 16).

use super::robustness_test::*;
use super::*;
use crate::chunk::chunk_type::*;
use crate::endpoint::link_test::{Link, first_chunk_type};
use std::cell::RefCell;
use std::rc::Rc;

const PPI: PayloadProtocolIdentifier = PayloadProtocolIdentifier::Binary;

/// Every datagram on the link, with whether it came from the client; `drop` decides which are
/// lost.
fn capture(
    link: &mut Link,
    mut drop: impl FnMut(bool, &Bytes) -> bool + 'static,
) -> Rc<RefCell<Vec<(bool, Bytes)>>> {
    let seen: Rc<RefCell<Vec<(bool, Bytes)>>> = Rc::default();
    let record = seen.clone();
    link.filter = Some(Box::new(move |from_client, datagram: &Bytes| {
        record.borrow_mut().push((from_client, datagram.clone()));
        drop(from_client, datagram)
    }));
    seen
}

fn types(datagram: &Bytes) -> Vec<u8> {
    chunks_of(datagram).iter().map(|chunk| chunk[0]).collect()
}

/// RFC 9260 5.2.4 D, 5.1 D: the server's COOKIE ACK is lost and the DATA it then sends reaches
/// a client still in COOKIE-ECHOED, which discards it. The client's T1-cookie retransmits the
/// COOKIE ECHO; the server answers it with a COOKIE ACK that carries the outstanding DATA
/// after it. The client takes the COOKIE ACK first, enters ESTABLISHED, and accepts the
/// DATA from the same packet: the message arrives at once, not at the server's T3-rtx (whose
/// RTO the discarded copies backed off), and is acknowledged.
#[test]
fn outstanding_data_follows_the_cookie_ack_that_answers_a_repeated_cookie_echo() {
    let mut link = Link::new(TransportConfig::default(), TransportConfig::default(), 7);
    let mut cookie_acks = 0;
    let seen = capture(&mut link, move |from_client, datagram| {
        if !from_client && first_chunk_type(datagram) == Some(CT_COOKIE_ACK.0) {
            cookie_acks += 1;
            return cookie_acks == 1;
        }
        false
    });
    link.begin_connect();
    let deadline = link.now + Duration::from_secs(5);
    assert!(link.run_until(deadline, |l| l.server.connected()));
    assert_eq!(
        AssociationState::CookieEchoed,
        link.client.conn().state(),
        "the first COOKIE ACK is lost"
    );
    let now = link.now;
    link.server
        .conn()
        .open_stream(1, PPI)
        .unwrap()
        .write_sctp(now, &Bytes::from_static(b"before the cookie ack"), PPI)
        .unwrap();
    let deadline = link.now + Duration::from_secs(30);
    assert!(link.run_until(deadline, |l| !l.client.received.is_empty()));
    let arrived = link.now;

    let seen = seen.borrow();
    let from_server: Vec<Vec<u8>> = seen
        .iter()
        .filter(|(from_client, _)| !from_client)
        .map(|(_, datagram)| types(datagram))
        .collect();
    let second_ack = from_server
        .iter()
        .filter(|t| t.first() == Some(&CT_COOKIE_ACK.0))
        .nth(1)
        .expect("a second COOKIE ACK");
    assert_eq!(
        &vec![CT_COOKIE_ACK.0, CT_PAYLOAD_DATA.0],
        second_ack,
        "the COOKIE ACK first, then the DATA"
    );
    assert_eq!(
        vec![(1, Bytes::from_static(b"before the cookie ack"))],
        link.client.received
    );
    assert_eq!(AssociationState::Established, link.client.conn().state());
    // The DATA went three times (first, at T3-rtx a second after it, with the COOKIE ACK):
    // the second COOKIE ECHO came two seconds after the first (T1-cookie, 1 s then 2 s).
    let server = link.server.conn();
    assert!(
        server
            .timers
            .get(Timer::T3RTX)
            .is_none_or(|t3| t3 > arrived),
        "the message did not wait for T3-rtx"
    );
    let deadline = link.now + Duration::from_secs(5);
    assert!(link.run_until(deadline, |l| l.server.conn().inflight_queue.is_empty()));
}

/// RFC 9260 5.1 E: on the COOKIE ACK the client is ESTABLISHED, and DATA written as it learns
/// so (what the data channel's DATA_CHANNEL_OPEN is) leaves at that instant, not on a timer.
/// (The stream refuses DATA before: COOKIE-ECHOED sends no packet but the COOKIE ECHO, 5.1 C,
/// and this side does not bundle DATA with it, the MAY of 5.1 C.)
#[test]
fn data_written_when_the_cookie_ack_arrives_leaves_at_once() {
    let mut link = Link::new(TransportConfig::default(), TransportConfig::default(), 8);
    let seen = capture(&mut link, |_, _| false);
    link.begin_connect();
    let deadline = link.now + Duration::from_secs(5);
    assert!(link.run_until(deadline, |l| l.client.conn().state()
        == AssociationState::CookieEchoed));
    let now = link.now;
    assert!(
        link.client
            .conn()
            .open_stream(1, PPI)
            .unwrap()
            .write_sctp(now, &Bytes::from_static(b"too early"), PPI)
            .is_err(),
        "no DATA in COOKIE-ECHOED"
    );
    let deadline = link.now + Duration::from_secs(5);
    assert!(link.run_until(deadline, |l| l.client.connected()));
    let connected_at = link.now;
    link.client
        .conn()
        .stream(1)
        .unwrap()
        .write_sctp(connected_at, &Bytes::from_static(b"open"), PPI)
        .unwrap();
    let client_data = |seen: &Rc<RefCell<Vec<(bool, Bytes)>>>| {
        seen.borrow()
            .iter()
            .filter(|(from_client, d)| *from_client && types(d).contains(&CT_PAYLOAD_DATA.0))
            .count()
    };
    assert_eq!(0, client_data(&seen));
    link.run_until(connected_at, |_| false);
    assert_eq!(connected_at, link.now);
    assert_eq!(
        1,
        client_data(&seen),
        "on the link at the instant of the COOKIE ACK"
    );
    let deadline = link.now + link.latency + Duration::from_millis(1);
    assert!(link.run_until(deadline, |l| !l.server.received.is_empty()));
}

/// RFC 9260 5.1, 6.3 and 16: T1-init and T1-cookie start at RTO.Initial (1 s) and double on
/// each expiry by themselves; T1-cookie starts over at RTO.Initial, whatever T1-init went
/// through. Their expiries are not T3-rtx expiries: they back off no RTO, and the first DATA
/// after the handshake has its T3-rtx an RTO.Initial ahead.
#[test]
fn handshake_timers_back_off_on_their_own_and_leave_the_rto_alone() {
    let mut endpoint = crate::endpoint::Endpoint::new(
        remote(),
        TransportProtocol::UDP,
        Arc::new(crate::EndpointConfig::default()),
        None,
    );
    let start = Instant::now();
    let (_, mut a) = endpoint
        .connect(
            start,
            crate::ClientConfig::new(TransportConfig::default()),
            "10.0.0.2:5000".parse().unwrap(),
        )
        .unwrap();
    let second = Duration::from_secs(1);
    let expiries = |a: &mut Association, timer: Timer, typ: u8, from: Instant| {
        let mut at = from;
        for backoff in [1, 2, 4] {
            let due = a.timers.get(timer).expect("the timer runs");
            assert_eq!(at + second * backoff, due, "{timer:?}, expiry {backoff}");
            a.handle_timeout(due);
            assert_eq!(1, chunks_of_type(&sent_datagrams(a, due), typ).len());
            at = due;
        }
        at
    };
    assert_eq!(
        1,
        chunks_of_type(&sent_datagrams(&mut a, start), CT_INIT.0).len()
    );
    let now = expiries(&mut a, Timer::T1Init, CT_INIT.0, start);

    let init_ack = init_chunk(CT_INIT_ACK.0, 4242, 9000, &[raw_tlv(7, b"cookie")]);
    let raw = packet_to(&a, &[init_ack]);
    inject(&mut a, now, raw);
    assert_eq!(AssociationState::CookieEchoed, a.state());
    assert_eq!(
        1,
        chunks_of_type(&sent_datagrams(&mut a, now), CT_COOKIE_ECHO.0).len()
    );
    let now = expiries(&mut a, Timer::T1Cookie, CT_COOKIE_ECHO.0, now);

    let raw = packet_to(&a, &[raw_chunk(CT_COOKIE_ACK.0, 0, &[])]);
    inject(&mut a, now, raw);
    assert_eq!(AssociationState::Established, a.state());
    assert_eq!(1000, a.rto_mgr.get_rto(), "no backoff carried over");
    a.open_stream(1, PPI)
        .unwrap()
        .write_sctp(now, &Bytes::from_static(b"first"), PPI)
        .unwrap();
    assert_eq!(1, transmitted_data(&a.gather_outbound(now).0).len());
    assert_eq!(Some(now + second), a.timers.get(Timer::T3RTX));
}
