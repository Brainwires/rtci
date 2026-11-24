//! RFC 9260 8.1 (report the failure and the outstanding user data), 11.1.8 (Status), 11.1.10
//! (Request Heartbeat), 11.1.14 / 11.1.15 (Receive Unsent / Unacknowledged Message) and 11.2.2
//! (SEND FAILURE).

use super::robustness_test::*;
use super::*;
use crate::TimerConfig;
use crate::chunk::chunk_type::*;
use crate::endpoint::link_test::{Link, first_chunk_type};
use std::cell::Cell;
use std::rc::Rc;

const PPI: PayloadProtocolIdentifier = PayloadProtocolIdentifier::Binary;

/// A link whose client gives the peer up after two T3-rtx expiries.
fn failing_link(seed: u64) -> Link {
    let client = TransportConfig::default().with_timer_config(TimerConfig {
        max_t3_rtx_retrans: 2,
        ..TimerConfig::default()
    });
    let mut link = Link::new(client, TransportConfig::default(), seed);
    link.connect();
    link
}

/// RFC 9260 8.1: past Association.Max.Retrans the peer is unreachable, the association closes,
/// and "the endpoint SHOULD report the failure to the upper layer and optionally report back
/// all outstanding user data remaining in its outbound queue". Ten 1000-byte messages are
/// written once the server stops answering: the congestion window takes the first ones, the
/// rest wait. One SEND FAILURE (11.2.2) counts both kinds, and the messages come back in the
/// order written, those that left as Unacknowledged (11.1.15), the others as Unsent (11.1.14),
/// each with its stream, PPI and bytes.
#[test]
fn a_failed_association_hands_back_its_unacknowledged_and_unsent_messages() {
    let mut link = failing_link(401);
    link.filter = Some(Box::new(|from_client, _| !from_client));
    let now = link.now;
    let messages: Vec<Bytes> = (0..10u8).map(|i| Bytes::from(vec![i; 1000])).collect();
    {
        let a = link.client.conn();
        let mut s = a.open_stream(3, PPI).unwrap();
        for m in &messages {
            s.write_sctp(now, m, PPI).unwrap();
        }
    }
    let deadline = link.now + Duration::from_secs(600);
    assert!(link.run_until(deadline, |l| l.client.conn().is_ended()));

    let failure = link
        .client
        .events
        .iter()
        .find_map(|e| match e {
            Event::SendFailure {
                unsent,
                unacknowledged,
            } => Some((*unsent, *unacknowledged)),
            _ => None,
        })
        .expect("a SEND FAILURE");
    let (unsent, unacknowledged) = failure;
    assert!(unacknowledged >= 1 && unsent >= 1, "{failure:?}");
    assert_eq!(10, unsent + unacknowledged);
    let send_failure_at = link
        .client
        .events
        .iter()
        .position(|e| matches!(e, Event::SendFailure { .. }))
        .unwrap();
    let closed_at = link
        .client
        .events
        .iter()
        .position(|e| matches!(e, Event::AssociationClosed { .. }))
        .unwrap();
    assert!(send_failure_at < closed_at, "reported before the close");

    let back = link.client.conn().take_undelivered_messages();
    assert_eq!(10, back.len());
    for (i, m) in back.iter().enumerate() {
        assert_eq!(messages[i], m.data, "message {i}");
        assert_eq!(3, m.stream_identifier);
        assert_eq!(PPI, m.payload_type);
        assert!(!m.partial);
        let expected = if i < unacknowledged {
            UndeliveredMode::Unacknowledged
        } else {
            UndeliveredMode::Unsent
        };
        assert_eq!(expected, m.mode, "message {i}");
    }
    assert!(
        link.client.conn().take_undelivered_messages().is_empty(),
        "taken once"
    );
}

/// RFC 9260 11.1.15 "partial flag": a message larger than a packet, whose first fragments the
/// peer acknowledged before it stopped answering, comes back with the bytes not acknowledged
/// and marked partial; the unsent tail of a message joins the fragments that left.
#[test]
fn a_part_acknowledged_message_comes_back_partial() {
    let mut link = failing_link(402);
    let now = link.now;
    let big = Bytes::from((0..20_000u32).map(|i| i as u8).collect::<Vec<u8>>());
    link.client
        .conn()
        .open_stream(1, PPI)
        .unwrap()
        .write_sctp(now, &big, PPI)
        .unwrap();
    // The server takes what reaches it in the first round trip, then stops answering.
    let cut = link.now + link.latency * 2 + Duration::from_millis(1);
    link.run_until(cut, |_| false);
    link.filter = Some(Box::new(|from_client, _| !from_client));
    let deadline = link.now + Duration::from_secs(600);
    assert!(link.run_until(deadline, |l| l.client.conn().is_ended()));

    let back = link.client.conn().take_undelivered_messages();
    assert_eq!(1, back.len(), "one message");
    let m = &back[0];
    assert_eq!(UndeliveredMode::Unacknowledged, m.mode);
    assert!(m.partial, "the acknowledged part is not here");
    assert!(!m.data.is_empty() && m.data.len() < big.len());
    assert!(
        big.ends_with(&m.data),
        "the bytes not acknowledged are the end of the message"
    );
}

/// A graceful shutdown leaves nothing to hand back and reports no SEND FAILURE.
#[test]
fn a_graceful_shutdown_reports_no_send_failure() {
    let mut link = Link::new(TransportConfig::default(), TransportConfig::default(), 403);
    link.connect();
    let now = link.now;
    link.client
        .conn()
        .open_stream(1, PPI)
        .unwrap()
        .write_sctp(now, &Bytes::from_static(b"bye"), PPI)
        .unwrap();
    link.client.conn().shutdown().unwrap();
    let deadline = link.now + Duration::from_secs(30);
    assert!(link.run_until(deadline, |l| l.client.conn().is_ended()));
    assert!(
        !link
            .client
            .events
            .iter()
            .any(|e| matches!(e, Event::SendFailure { .. }))
    );
    assert!(link.client.conn().take_undelivered_messages().is_empty());
}

/// RFC 9260 11.1.10 Request Heartbeat: a HEARTBEAT leaves at once, even with heartbeats
/// disabled, and its HEARTBEAT ACK measures the round trip; a second request while one is
/// outstanding sends none.
#[test]
fn a_requested_heartbeat_leaves_at_once_and_measures_the_round_trip() {
    let quiet = TransportConfig::default().with_heartbeat_interval(None);
    let mut link = Link::new(quiet.clone(), quiet, 404);
    link.connect();
    let heartbeats = Rc::new(Cell::new(0usize));
    let count = heartbeats.clone();
    link.filter = Some(Box::new(move |from_client, d| {
        if from_client && first_chunk_type(d) == Some(CT_HEARTBEAT.0) {
            count.set(count.get() + 1);
        }
        false
    }));
    let now = link.now;
    let a = link.client.conn();
    assert_eq!(Duration::ZERO, a.rtt(), "nothing measured yet");
    assert!(a.request_heartbeat(now));
    assert!(!a.request_heartbeat(now), "one outstanding");
    link.run_until(now, |_| false);
    assert_eq!(1, heartbeats.get(), "on the link at once");
    let round_trip = link.latency * 2;
    link.run_for(round_trip + Duration::from_millis(1));
    let a = link.client.conn();
    assert_eq!(round_trip, a.rtt(), "the HEARTBEAT ACK measured it");
    assert!(a.request_heartbeat(link.now), "answered: another may go");
}

/// RFC 9260 11.1.8 Status: the receiver window, congestion window, unacknowledged and pending
/// DATA chunks, SRTT and RTO in one call.
#[test]
fn status_reports_the_windows_and_the_queues() {
    let mut link = connected_link(405);
    let now = link.now;
    let a = link.client.conn();
    let idle = a.status();
    assert!(!idle.closed);
    assert_eq!(0, idle.unacknowledged_data_chunks);
    assert_eq!(0, idle.pending_data_chunks);
    assert_eq!(a.peer_receive_window(), idle.peer_receive_window);
    assert!(idle.peer_receive_window > 0);
    let mut s = a.open_stream(1, PPI).unwrap();
    for _ in 0..10 {
        s.write_sctp(now, &Bytes::from(vec![0u8; 1000]), PPI)
            .unwrap();
    }
    let _ = sent_datagrams(a, now);
    let busy = a.status();
    assert!(busy.unacknowledged_data_chunks >= 1);
    assert!(busy.pending_data_chunks >= 1);
    assert_eq!(
        10,
        busy.unacknowledged_data_chunks + busy.pending_data_chunks
    );
    assert!(busy.peer_receive_window < idle.peer_receive_window);
    assert_eq!(a.congestion_window(), busy.congestion_window);
    assert_eq!(a.rto(), busy.rto);
    assert_eq!(a.rtt(), busy.srtt);
}

/// RFC 9260 11.2.5 COMMUNICATION ERROR: an ERROR chunk from the peer is reported with its
/// causes, code and cause-specific information, in order; the association goes on.
#[test]
fn an_error_chunk_from_the_peer_is_reported() {
    let mut link = connected_link(406);
    let now = link.now;
    let a = link.client.conn();
    while a.poll().is_some() {}
    let causes = [raw_tlv(6, &[0xc1, 0, 0, 4]), raw_tlv(0x0d, b"why")].concat();
    let raw = packet_to(a, &[raw_chunk(CT_ERROR.0, 0, &causes)]);
    inject(a, now, raw);
    let mut reported = vec![];
    while let Some(e) = a.poll() {
        if let Event::CommunicationError { causes } = e {
            reported.extend(
                causes
                    .into_iter()
                    .map(|(code, info)| (code.value(), info.to_vec())),
            );
        }
    }
    assert_eq!(
        vec![(6, vec![0xc1, 0, 0, 4]), (0x0d, b"why".to_vec())],
        reported
    );
    assert!(!a.is_ended());
}
