//! Path MTU discovery (RFC 8899 section 6.2, RFC 4820, RFC 8261 section 4) between two
//! associations over the in-memory link of `endpoint::link_test`, on its virtual clock. The
//! link drops every datagram larger than its MTU, as a path with the DF bit set does, and the
//! MTU changes while the association runs.

use super::robustness_test::{inject, sent_datagrams};
use super::*;
use crate::association::pmtud::{PROBE_OVERHEAD, PathMtuDiscoveryConfig, PathMtuState};
use crate::chunk::chunk_type::{CT_COOKIE_ECHO, CT_HEARTBEAT, CT_PAD};
use crate::endpoint::link_test::{Link, first_chunk_type};
use std::cell::Cell;
use std::rc::Rc;

const BASE: u32 = 1100;
const MAX: u32 = 1400;

/// The chunk types of an SCTP packet, in order.
fn chunk_types(datagram: &Bytes) -> Vec<u8> {
    let mut types = vec![];
    let mut offset = 12;
    while offset + 4 <= datagram.len() {
        types.push(datagram[offset]);
        let length = u16::from_be_bytes([datagram[offset + 2], datagram[offset + 3]]) as usize;
        offset += length.max(4).next_multiple_of(4);
    }
    types
}

/// Two associations that use `BASE` and search up to `MAX`, over a link that carries
/// datagrams up to `mtu` (shared, so the test can change it). Every datagram sent is
/// recorded: whether it was the client's, its size, and whether the link carried it.
fn link_with_mtu(
    mtu: Rc<Cell<usize>>,
    sent: Rc<std::cell::RefCell<Vec<(bool, Bytes, bool)>>>,
) -> Link {
    let config = TransportConfig::default().with_path_mtu_discovery(Some(
        PathMtuDiscoveryConfig::default().with_max_path_mtu(MAX),
    ));
    let mut link = Link::new(config.clone(), config, 0x8899);
    link.filter = Some(Box::new(move |from_client, datagram| {
        let fits = datagram.len() <= mtu.get();
        sent.borrow_mut()
            .push((from_client, datagram.clone(), fits));
        !fits
    }));
    link.begin_connect();
    link.client.conn().set_path_mtu(BASE);
    link
}

fn is_probe(datagram: &Bytes) -> bool {
    chunk_types(datagram) == [CT_HEARTBEAT.0, CT_PAD.0]
}

/// Writes `count` messages of `size` bytes on stream 0 of the client.
fn write(link: &mut Link, count: usize, size: usize) {
    let now = link.now;
    let conn = link.client.conn();
    let mut stream = match conn.stream(0) {
        Ok(stream) => stream,
        Err(_) => conn
            .open_stream(0, PayloadProtocolIdentifier::Binary)
            .expect("stream 0"),
    };
    for i in 0..count {
        stream
            .write_sctp(
                now,
                &Bytes::from(vec![i as u8; size]),
                PayloadProtocolIdentifier::Binary,
            )
            .expect("write");
    }
}

/// The search: once established, the client confirms BASE_PLPMTU with a probe, then probes
/// larger sizes (MAX_PLPMTU first) and settles on the largest that crosses the link, within
/// one search step. Each probe is a HEARTBEAT and a PAD chunk, exactly the size probed; no
/// probe goes before the association is established. Data sent afterwards fills packets of
/// the size found, and nothing but probes is ever larger than the PLPMTU in use.
#[test]
fn the_association_discovers_the_path_mtu_with_heartbeat_and_pad_probes() {
    let mtu = Rc::new(Cell::new(1300usize));
    let sent = Rc::new(std::cell::RefCell::new(vec![]));
    let mut link = link_with_mtu(mtu.clone(), sent.clone());
    let deadline = link.now + Duration::from_secs(300);
    assert!(link.run_until(deadline, |l| {
        l.client.connected()
            && l.server.connected()
            && l.client.conn().path_mtu_state() == Some(PathMtuState::SearchComplete)
    }));
    let found = link.client.conn().path_mtu();
    assert!(
        found <= 1300 && found > 1300 - 16,
        "found {found} for a path of 1300"
    );

    let probes: Vec<usize> = sent
        .borrow()
        .iter()
        .filter(|(from_client, d, _)| *from_client && is_probe(d))
        .map(|(_, d, _)| d.len())
        .collect();
    assert_eq!(
        probes.first(),
        Some(&(BASE as usize)),
        "BASE_PLPMTU is confirmed first: {probes:?}"
    );
    assert_eq!(
        probes.get(1),
        Some(&(MAX as usize)),
        "then MAX_PLPMTU: {probes:?}"
    );
    assert!(
        probes
            .iter()
            .all(|size| size % 4 == 0 && *size >= PROBE_OVERHEAD as usize)
    );
    let first_probe = sent
        .borrow()
        .iter()
        .position(|(from_client, d, _)| *from_client && is_probe(d))
        .expect("a probe");
    assert!(
        sent.borrow()[..first_probe].iter().any(
            |(from_client, d, _)| *from_client && first_chunk_type(d) == Some(CT_COOKIE_ECHO.0)
        ),
        "the first probe follows the handshake"
    );

    // Data now goes in packets of the size found, and never larger.
    let before = sent.borrow().len();
    write(&mut link, 40, 600);
    let deadline = link.now + Duration::from_secs(30);
    assert!(link.run_until(deadline, |l| l.server.received.len() == 40));
    let data: Vec<usize> = sent.borrow()[before..]
        .iter()
        .filter(|(from_client, d, _)| *from_client && !is_probe(d))
        .map(|(_, d, _)| d.len())
        .collect();
    assert!(data.iter().all(|size| *size <= found as usize), "{data:?}");
    assert!(
        data.iter().any(|size| *size > BASE as usize),
        "packets larger than the base: {data:?}"
    );
}

/// The link's MTU shrinks below the PLPMTU found: full packets are lost, two retransmission
/// timeouts in a row without progress are taken as a black hole, the PLPMTU falls back to
/// BASE_PLPMTU and the data gets through, re-bundled; the search runs again and settles below
/// the new MTU. Then the MTU grows: at PMTU_RAISE_TIMER the search climbs to it.
#[test]
fn a_shrinking_path_is_detected_as_a_black_hole_and_a_growing_one_at_the_raise_timer() {
    let mtu = Rc::new(Cell::new(1400usize));
    let sent = Rc::new(std::cell::RefCell::new(vec![]));
    let mut link = link_with_mtu(mtu.clone(), sent.clone());
    let deadline = link.now + Duration::from_secs(300);
    assert!(link.run_until(deadline, |l| {
        l.client.connected()
            && l.client.conn().path_mtu_state() == Some(PathMtuState::SearchComplete)
    }));
    assert_eq!(
        link.client.conn().path_mtu(),
        MAX,
        "the whole link at first"
    );

    mtu.set(1200);
    write(&mut link, 60, 300);
    let deadline = link.now + Duration::from_secs(120);
    assert!(
        link.run_until(deadline, |l| l.server.received.len() == 60),
        "the data did not get through after the MTU shrank: {} of 60",
        link.server.received.len()
    );
    assert!(link.client.conn().path_mtu() <= 1200);
    let deadline = link.now + Duration::from_secs(300);
    assert!(link.run_until(deadline, |l| {
        l.client.conn().path_mtu_state() == Some(PathMtuState::SearchComplete)
    }));
    let found = link.client.conn().path_mtu();
    assert!(found <= 1200 && found > 1200 - 16, "found {found} for 1200");
    assert!(
        !link.client.events.iter().any(|e| matches!(
            e,
            Event::AssociationLost { .. } | Event::AssociationClosed { .. }
        )),
        "{:?}",
        link.client.events
    );

    // The path widens again; the raise timer (600 s) finds it.
    mtu.set(1400);
    link.run_for(Duration::from_secs(590));
    assert_eq!(
        link.client.conn().path_mtu(),
        found,
        "not before the raise timer"
    );
    let deadline = link.now + Duration::from_secs(120);
    assert!(link.run_until(deadline, |l| l.client.conn().path_mtu() == MAX));
}

/// A lost probe is no congestion signal and no path failure (RFC 8899 section 3 item 7,
/// section 6.2.1.2): when every probe above the base is lost, the congestion window, the
/// error counters and the association are untouched, and the search ends after MAX_PROBES
/// failures in a row with the PLPMTU at the base.
#[test]
fn lost_probes_change_neither_congestion_control_nor_the_path_state() {
    let mtu = Rc::new(Cell::new(BASE as usize));
    let sent = Rc::new(std::cell::RefCell::new(vec![]));
    let mut link = link_with_mtu(mtu, sent);
    let deadline = link.now + Duration::from_secs(60);
    assert!(link.run_until(deadline, |l| {
        l.client.connected() && l.client.conn().path_mtu_state() == Some(PathMtuState::Searching)
    }));
    let cwnd = link.client.conn().cwnd;
    let deadline = link.now + Duration::from_secs(300);
    assert!(link.run_until(deadline, |l| {
        l.client.conn().path_mtu_state() == Some(PathMtuState::SearchComplete)
    }));
    let conn = link.client.conn();
    assert_eq!(conn.path_mtu(), BASE);
    assert_eq!(conn.cwnd, cwnd);
    assert_eq!(conn.path_error_count, 0);
    assert!(
        !link
            .client
            .events
            .iter()
            .any(|e| matches!(e, Event::PathInactive))
    );
}

/// Without discovery the association sends no probe and keeps the size it was given.
#[test]
fn without_discovery_no_probe_is_sent() {
    let sent = Rc::new(std::cell::RefCell::new(vec![]));
    let sent2 = sent.clone();
    let config = TransportConfig::default().with_path_mtu_discovery(None);
    let mut link = Link::new(config.clone(), config, 1);
    link.filter = Some(Box::new(move |_, datagram| {
        sent2.borrow_mut().push((true, datagram.clone(), true));
        false
    }));
    link.connect();
    link.run_for(Duration::from_secs(120));
    assert!(!sent.borrow().iter().any(|(_, d, _)| is_probe(d)));
    assert_eq!(link.client.conn().path_mtu_state(), None);
}

/// RFC 4820 section 3: a PAD chunk is discarded and the rest of the packet processed: the
/// HEARTBEAT before it is answered, and with the padding in front of a DATA chunk the DATA
/// is delivered.
#[test]
fn a_pad_chunk_is_skipped_and_the_rest_of_the_packet_processed() {
    let config = TransportConfig::default().with_path_mtu_discovery(None);
    let mut link = Link::new(config.clone(), config, 2);
    link.connect();
    let now = link.now;
    let server = link.server.conn();
    let packet = server.create_packet(vec![
        Box::new(ChunkPadding { padding_length: 40 }),
        Box::new(ChunkHeartbeat {
            params: vec![Box::new(ParamHeartbeatInfo {
                heartbeat_information: Bytes::from_static(b"padded heartbeat"),
            })],
        }),
    ]);
    let raw = server.marshal_packet(&packet).expect("marshal");
    let client = link.client.conn();
    inject(client, now, raw);
    let contents = sent_datagrams(client, now);
    assert!(
        contents
            .iter()
            .any(|d| chunk_types(d).contains(&crate::chunk::chunk_type::CT_HEARTBEAT_ACK.0)),
        "the HEARTBEAT after the PAD chunk is answered"
    );
    assert!(
        !contents
            .iter()
            .any(|d| chunk_types(d).contains(&crate::chunk::chunk_type::CT_ERROR.0)),
        "no Unrecognized Chunk Type error"
    );
}
