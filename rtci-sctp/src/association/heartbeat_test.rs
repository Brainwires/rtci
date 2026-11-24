//! RFC 9260 sections 8.1 to 8.3: HEARTBEAT on an idle path, what its acknowledgement does,
//! and when the path and the peer are given up.

use super::robustness_test::*;
use super::*;
use crate::TimerConfig;
use crate::chunk::chunk_type::*;
use crate::endpoint::link_test::{Link, first_chunk_type};
use std::cell::Cell;
use std::rc::Rc;

/// Runs the association's timers until it has something to send, and returns that with the
/// time. `None` when no timer is left.
fn next_transmission(a: &mut Association, limit: Instant) -> Option<(Instant, Vec<Bytes>)> {
    while let Some(at) = a.poll_timeout() {
        if at > limit {
            return None;
        }
        a.handle_timeout(at);
        let sent = sent_datagrams(a, at);
        if !sent.is_empty() || a.is_ended() {
            return Some((at, sent));
        }
    }
    None
}

fn heartbeat_ack_for(heartbeat: &[u8]) -> Vec<u8> {
    raw_chunk(CT_HEARTBEAT_ACK.0, 0, &heartbeat[4..])
}

fn events(a: &mut Association) -> Vec<Event> {
    let mut out = vec![];
    while let Some(e) = a.poll() {
        out.push(e);
    }
    out
}

/// RFC 9260 8.3: an established association whose path is idle sends a HEARTBEAT after
/// RTO + HB.interval (30 s), give or take half an RTO, and the HEARTBEAT carries the time it
/// was sent. No HEARTBEAT was ever sent.
#[test]
fn an_idle_association_sends_a_heartbeat() {
    let mut link = connected_link(201);
    let start = link.now;
    let a = link.server.conn();
    let rto = Duration::from_millis(a.rto_mgr.get_rto());
    let (at, sent) = next_transmission(a, start + Duration::from_secs(120)).expect("a HEARTBEAT");

    let idle = at - start;
    // The timer started when the association was established, a link latency or two before
    // the handshake was seen complete from here.
    let slack = Duration::from_millis(100);
    assert!(
        idle + slack >= Duration::from_secs(30) + rto / 2
            && idle <= Duration::from_secs(30) + rto * 3 / 2,
        "sent after {idle:?} with an RTO of {rto:?}"
    );
    let heartbeats = chunks_of_type(&sent, CT_HEARTBEAT.0);
    assert_eq!(1, heartbeats.len());
    let info = tlvs(&heartbeats[0][4..]);
    assert_eq!(1, info[0].0, "a Heartbeat Info parameter");
    let sent_ms = u64::from_be_bytes(info[0].1[..8].try_into().unwrap());
    let age = a.created_at.map(|t| (at - t).as_millis() as u64).unwrap();
    assert_eq!(age, sent_ms, "the time the HEARTBEAT was sent");
}

/// RFC 9260 8.3: the HEARTBEAT ACK gives a round-trip measurement, and the next HEARTBEAT
/// follows a heartbeat period later.
#[test]
fn a_heartbeat_ack_measures_the_round_trip() {
    let mut link = connected_link(202);
    let start = link.now;
    let a = link.server.conn();
    let (at, sent) = next_transmission(a, start + Duration::from_secs(120)).unwrap();
    let heartbeat = chunks_of_type(&sent, CT_HEARTBEAT.0).remove(0);
    let srtt_before = a.rto_mgr.srtt;

    let answered = at + Duration::from_millis(400);
    let raw = packet_to(a, &[heartbeat_ack_for(&heartbeat)]);
    inject(a, answered, raw);
    assert_ne!(srtt_before, a.rto_mgr.srtt, "a new RTT sample");
    assert!(a.rto_mgr.srtt > srtt_before && a.rto_mgr.srtt <= 400);

    let (next, sent) = next_transmission(a, answered + Duration::from_secs(120)).unwrap();
    assert_eq!(1, chunks_of_type(&sent, CT_HEARTBEAT.0).len());
    assert!(next - answered >= Duration::from_secs(30));
}

/// RFC 9260 8.1, 8.3: each HEARTBEAT not acknowledged within an RTO counts against the peer;
/// a HEARTBEAT ACK clears the count. An acknowledgement that is not for the HEARTBEAT
/// outstanding counts for nothing.
#[test]
fn a_heartbeat_ack_clears_the_error_count() {
    let config = TransportConfig::default().with_timer_config(TimerConfig {
        max_t3_rtx_retrans: 2,
        ..TimerConfig::default()
    });
    let mut link = Link::new(TransportConfig::default(), config, 203);
    link.connect();
    let limit = link.now + Duration::from_secs(3600);
    let a = link.server.conn();

    // Two unanswered, then one answered, three times over: never three in a row.
    for round in 0..3 {
        for _ in 0..2 {
            let (_, sent) = next_transmission(a, limit).unwrap();
            assert_eq!(1, chunks_of_type(&sent, CT_HEARTBEAT.0).len());
        }
        let (at, sent) = next_transmission(a, limit).unwrap();
        let heartbeat = chunks_of_type(&sent, CT_HEARTBEAT.0).remove(0);

        // A HEARTBEAT ACK that echoes something else changes nothing.
        let raw = packet_to(
            a,
            &[raw_chunk(CT_HEARTBEAT_ACK.0, 0, &raw_tlv(1, &[9; 16]))],
        );
        inject(a, at, raw);
        assert!(a.heartbeat_outstanding.is_some(), "round {round}");

        let raw = packet_to(a, &[heartbeat_ack_for(&heartbeat)]);
        inject(a, at + Duration::from_millis(50), raw);
        assert!(a.heartbeat_outstanding.is_none());
        assert!(!a.is_ended(), "round {round}");
    }

    // Three in a row pass the limit of two.
    let mut heartbeats = 0;
    while let Some((_, sent)) = next_transmission(a, limit) {
        heartbeats += chunks_of_type(&sent, CT_HEARTBEAT.0).len();
    }
    assert_eq!(3, heartbeats);
    assert!(a.is_ended());
}

/// RFC 9260 8.1, 8.2, 8.3, 16: with a peer that answers nothing, the path is reported
/// inactive past Path.Max.Retrans (5) and HEARTBEATs go on; past Association.Max.Retrans (10)
/// the peer is unreachable and the association ends.
#[test]
fn unanswered_heartbeats_end_the_association() {
    let mut link = connected_link(204);
    let limit = link.now + Duration::from_secs(3600);
    let a = link.server.conn();
    let _ = events(a);

    let mut heartbeats = 0;
    let mut inactive_after = None;
    while let Some(at) = a.poll_timeout() {
        assert!(at < limit);
        a.handle_timeout(at);
        heartbeats += chunks_of_type(&sent_datagrams(a, at), CT_HEARTBEAT.0).len();
        for e in events(a) {
            if matches!(e, Event::PathInactive) {
                inactive_after = Some(heartbeats);
            }
            if let Event::AssociationClosed { reason } = e {
                assert_eq!(AssociationError::TimedOut, reason);
            }
        }
    }
    assert!(a.is_ended());
    assert_eq!(11, heartbeats, "Association.Max.Retrans + 1 unanswered");
    assert_eq!(
        Some(6),
        inactive_after,
        "inactive once Path.Max.Retrans + 1 went unanswered; HEARTBEATs went on"
    );
}

/// The same limit for DATA: ten T3-rtx expiries without an acknowledgement by default, the
/// path reported inactive on the way.
#[test]
fn unacknowledged_data_ends_the_association_by_default() {
    // Without HEARTBEATs, which count against the same limit when they go unanswered.
    let config = TransportConfig::default().with_heartbeat_interval(None);
    let mut link = Link::new(config, TransportConfig::default(), 205);
    link.connect();
    let now = link.now;
    let limit = now + Duration::from_secs(3600);
    let a = link.client.conn();
    let _ = events(a);
    let ppi = PayloadProtocolIdentifier::Binary;
    a.open_stream(1, ppi)
        .unwrap()
        .write_sctp(now, &Bytes::from_static(b"never acknowledged"), ppi)
        .unwrap();
    assert_eq!(1, chunks_of_type(&sent_datagrams(a, now), 0).len());

    let mut retransmissions = 0;
    let mut inactive = false;
    while let Some((_, sent)) = next_transmission(a, limit) {
        retransmissions += chunks_of_type(&sent, 0).len();
        inactive |= events(a).iter().any(|e| matches!(e, Event::PathInactive));
    }
    assert!(a.is_ended());
    assert_eq!(10, retransmissions, "Association.Max.Retrans");
    assert!(inactive);
}

/// The path is reported active again when the peer answers.
#[test]
fn a_path_that_answers_again_is_reported_active() {
    let mut link = connected_link(206);
    let limit = link.now + Duration::from_secs(3600);
    let a = link.server.conn();
    let _ = events(a);
    let mut last = None;
    for _ in 0..7 {
        last = next_transmission(a, limit);
    }
    assert!(events(a).iter().any(|e| matches!(e, Event::PathInactive)));

    let (at, sent) = last.unwrap();
    let heartbeat = chunks_of_type(&sent, CT_HEARTBEAT.0).remove(0);
    let raw = packet_to(a, &[heartbeat_ack_for(&heartbeat)]);
    inject(a, at, raw);
    assert!(events(a).iter().any(|e| matches!(e, Event::PathActive)));
    assert!(!a.is_ended());
}

/// Two idle associations keep each other alive: HEARTBEATs are answered, nothing is reported
/// inactive, nobody gives up.
#[test]
fn idle_associations_stay_up_on_heartbeats() {
    let mut link = connected_link(207);
    let heartbeats = Rc::new(Cell::new((0usize, 0usize)));
    let seen = heartbeats.clone();
    link.filter = Some(Box::new(move |_from_client: bool, datagram: &Bytes| {
        let (sent, acked) = seen.get();
        match first_chunk_type(datagram) {
            Some(4) => seen.set((sent + 1, acked)),
            Some(5) => seen.set((sent, acked + 1)),
            _ => {}
        }
        false
    }));
    link.run_for(Duration::from_secs(600));

    let (sent, acked) = heartbeats.get();
    assert!(
        sent >= 30,
        "about one per 31 s from each side in ten minutes: {sent}"
    );
    assert!(
        acked + 2 >= sent,
        "each one answered, but for those still on the link: {acked} of {sent}"
    );
    assert!(!link.client.conn().is_ended());
    assert!(!link.server.conn().is_ended());
    for peer in [&link.client, &link.server] {
        assert!(!peer.events.iter().any(|e| matches!(e, Event::PathInactive)));
    }
}

/// RFC 9260 8.3: a HEARTBEAT is for an idle path. While DATA is being sent (each first
/// transmission measures the round trip) none goes out.
#[test]
fn a_path_that_carries_data_sends_no_heartbeat() {
    let mut link = connected_link(208);
    let heartbeats = Rc::new(Cell::new(0usize));
    let seen = heartbeats.clone();
    link.filter = Some(Box::new(move |from_client: bool, datagram: &Bytes| {
        if from_client && first_chunk_type(datagram) == Some(4) {
            seen.set(seen.get() + 1);
        }
        false
    }));
    let ppi = PayloadProtocolIdentifier::Binary;
    let now = link.now;
    link.client.conn().open_stream(1, ppi).unwrap();
    for _ in 0..30 {
        let now = link.now;
        link.client
            .conn()
            .stream(1)
            .unwrap()
            .write_sctp(now, &Bytes::from_static(b"tick"), ppi)
            .unwrap();
        link.run_for(Duration::from_secs(10));
    }
    assert!(link.now - now >= Duration::from_secs(300));
    assert_eq!(0, heartbeats.get(), "the sender of DATA sent HEARTBEATs");
    assert_eq!(30, link.server.received.len());
}

/// HB.interval is configurable, and HEARTBEATs can be turned off, for an association that is
/// being set up and for one that exists.
#[test]
fn the_heartbeat_interval_is_configurable() {
    let config = TransportConfig::default().with_heartbeat_interval(None);
    let mut link = Link::new(config.clone(), config, 209);
    link.connect();
    assert!(
        link.server.conn().poll_timeout().is_none(),
        "no HEARTBEAT timer when they are off"
    );

    let config = TransportConfig::default().with_heartbeat_interval(Some(Duration::from_secs(5)));
    let mut link = Link::new(TransportConfig::default(), config, 210);
    link.connect();
    let start = link.now;
    let a = link.server.conn();
    let (at, sent) = next_transmission(a, start + Duration::from_secs(60)).unwrap();
    assert_eq!(1, chunks_of_type(&sent, CT_HEARTBEAT.0).len());
    assert!(at - start < Duration::from_secs(7));

    a.set_heartbeat_interval(None, at);
    assert!(a.poll_timeout().is_none(), "turned off");
    a.set_heartbeat_interval(Some(Duration::from_secs(2)), at);
    let (next, sent) = next_transmission(a, at + Duration::from_secs(60)).unwrap();
    assert_eq!(1, chunks_of_type(&sent, CT_HEARTBEAT.0).len());
    assert!(next - at < Duration::from_secs(4));
}
