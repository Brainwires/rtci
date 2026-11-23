//! RFC 6525: the reset this side sends in answer to a peer's reset is retransmitted, a request
//! is never given up in silence, an empty stream list means every stream, and every request
//! parameter is answered.

use super::robustness_test::*;
use super::*;
use crate::endpoint::link_test::Link;

const PPI: PayloadProtocolIdentifier = PayloadProtocolIdentifier::Binary;

/// The parameters (type, value) of the RE-CONFIG chunks among `datagrams`.
pub(super) fn reconfig_params(datagrams: &[Bytes]) -> Vec<(u16, Vec<u8>)> {
    chunks_of_type(datagrams, CT_RECONFIG.0)
        .iter()
        .flat_map(|chunk| tlvs(&chunk[4..]))
        .collect()
}

/// RFC 6525 5.1.1: every request is retransmitted until it is answered. The Outgoing SSN
/// Reset Request this side sends in answer to the peer's (closing a data channel resets both
/// directions, RFC 8831 6.7) had no timer: lost once, the peer's channel stayed closing for
/// good.
#[test]
fn the_reset_sent_in_answer_to_a_reset_is_retransmitted() {
    let mut link = Link::new(TransportConfig::default(), TransportConfig::default(), 501);
    let mut dropped = false;
    link.filter = Some(Box::new(move |from_client: bool, datagram: &Bytes| {
        let request = datagram.get(12) == Some(&CT_RECONFIG.0)
            && datagram.get(16..18) == Some(&[0u8, 13][..]);
        if !from_client && request && !dropped {
            dropped = true;
            return true;
        }
        false
    }));
    link.connect();
    let now = link.now;
    link.client
        .conn()
        .open_stream(1, PPI)
        .unwrap()
        .write_sctp(now, &Bytes::from_static(b"hello"), PPI)
        .unwrap();
    let deadline = link.now + Duration::from_secs(5);
    assert!(link.run_until(deadline, |l| !l.server.received.is_empty()));

    let now = link.now;
    link.client.conn().stream(1).unwrap().close(now).unwrap();
    link.run_for(Duration::from_secs(60));

    assert!(
        link.client.events.iter().any(|e| matches!(
            e,
            Event::AssociationLost {
                reason: AssociationError::Reset,
                id: 1
            }
        )),
        "the peer's reset of its own direction never arrived"
    );
    assert!(
        link.server.conn().reconfigs.is_empty(),
        "the answering reset is still waiting for its response"
    );
}

/// RFC 6525 5.1.1: a request is not given up in silence. After five expiries of its timer
/// the request stayed outstanding with no timer running, and "In progress" answers, which
/// only say that the peer is waiting for its application, counted against it too.
#[test]
fn a_reset_request_is_retransmitted_until_it_is_answered() -> Result<()> {
    let mut a = timed_test_association();
    let mut now = Instant::now();
    let mut stream = a.open_stream(3, PPI)?;
    stream.write_sctp(now, &Bytes::from_static(b"one"), PPI)?;
    stream.stop(now)?;
    let first = a.my_next_tsn;
    let sent = a.gather_outbound(now).0;
    assert_eq!(1, reconfig_params(&sent).len(), "the request is sent");
    a.handle_sack(
        &ChunkSelectiveAck {
            cumulative_tsn_ack: first,
            advertised_receiver_window_credit: 1 << 20,
            gap_ack_blocks: vec![],
            duplicate_tsn: vec![],
        },
        now,
    )?;
    let rsn = *a.reconfigs.keys().next().expect("a request outstanding");

    // Twelve expiries, each answered "In progress".
    let mut retransmissions = 0;
    for _ in 0..12 {
        now = a
            .timers
            .get(Timer::Reconfig)
            .expect("the reconfiguration timer runs while a request is outstanding");
        a.handle_timeout(now);
        retransmissions += reconfig_params(&a.gather_outbound(now).0)
            .iter()
            .filter(|(typ, _)| *typ == 13)
            .count();
        a.handle_reconfig(&ChunkReconfig {
            param_a: Some(Box::new(ParamReconfigResponse {
                reconfig_response_sequence_number: rsn,
                result: ReconfigResult::InProgress,
                next_tsns: None,
            })),
            param_b: None,
        })?;
        let _ = a.gather_outbound(now);
        assert!(a.reconfigs.contains_key(&rsn));
    }
    assert_eq!(12, retransmissions);

    // And five more with no answer at all: these count against the association (5.1.1),
    // which has ten to lose.
    for _ in 0..5 {
        now = a
            .timers
            .get(Timer::Reconfig)
            .expect("the request is not given up");
        a.handle_timeout(now);
        retransmissions += reconfig_params(&a.gather_outbound(now).0)
            .iter()
            .filter(|(typ, _)| *typ == 13)
            .count();
    }
    assert_eq!(17, retransmissions);
    assert!(!a.is_ended());

    a.handle_reconfig(&ChunkReconfig {
        param_a: Some(Box::new(ParamReconfigResponse {
            reconfig_response_sequence_number: rsn,
            result: ReconfigResult::SuccessPerformed,
            next_tsns: None,
        })),
        param_b: None,
    })?;
    let _ = a.gather_outbound(now);
    assert!(a.reconfigs.is_empty());
    assert!(
        a.timers.get(Timer::Reconfig).is_none(),
        "answered: the timer stops"
    );
    Ok(())
}

/// RFC 6525 5.2.2: an Outgoing SSN Reset Request without stream numbers resets every stream.
/// It reset none and was answered "Success - Performed", after which the peer's SSN 0 was
/// dropped as stale.
#[test]
fn a_reset_request_without_streams_resets_every_stream() -> Result<()> {
    let mut a = timed_test_association();
    let base = a.peer_last_tsn;
    for (i, stream) in [(1u32, 1u16), (2, 1), (3, 2)] {
        a.handle_data(&ChunkPayloadData {
            tsn: base.wrapping_add(i),
            stream_identifier: stream,
            stream_sequence_number: if i == 2 { 1 } else { 0 },
            beginning_fragment: true,
            ending_fragment: true,
            payload_type: PPI,
            user_data: Bytes::from_static(b"before"),
            ..Default::default()
        })?;
    }
    for stream in [1u16, 2] {
        while a.stream(stream)?.read_sctp()?.is_some() {}
    }

    let reply = a.handle_reconfig(&ChunkReconfig {
        param_a: Some(Box::new(ParamOutgoingResetRequest {
            reconfig_request_sequence_number: 7,
            reconfig_response_sequence_number: 0,
            sender_last_tsn: a.peer_last_tsn,
            stream_identifiers: vec![],
        })),
        param_b: None,
    })?;
    assert!(!reply.is_empty());

    // The peer starts both streams again at SSN 0.
    for (i, stream) in [(4u32, 1u16), (5, 2)] {
        a.handle_data(&ChunkPayloadData {
            tsn: base.wrapping_add(i),
            stream_identifier: stream,
            stream_sequence_number: 0,
            beginning_fragment: true,
            ending_fragment: true,
            payload_type: PPI,
            user_data: Bytes::from_static(b"after"),
            ..Default::default()
        })?;
        assert!(
            a.streams[&stream].reassembly_queue.is_readable(),
            "stream {stream} was not reset: SSN 0 is held as stale"
        );
    }
    Ok(())
}

/// RFC 6525 5.2.1: every request parameter is answered, and what is bundled with it is not
/// lost. A RE-CONFIG with an Incoming SSN Reset (14), SSN/TSN Reset (15), Add Outgoing
/// Streams (17) or Add Incoming Streams (18) request used to fail the parse of its whole
/// packet: the DATA in it was dropped and the request never answered.
#[test]
fn every_request_parameter_is_answered() {
    // Incoming reset of a stream that has sent nothing: nothing to do (0). SSN/TSN reset
    // with nothing outstanding: performed (1). More streams than the 65535 there are:
    // denied (2).
    for (typ, extra, result) in [
        (14u16, &[0u8, 1][..], 0u8),
        (15, &[][..], 1),
        (17, &[0, 1, 0, 0][..], 2),
        (18, &[0, 1, 0, 0][..], 2),
    ] {
        let mut link = connected_link(502);
        let now = link.now;
        let a = link.server.conn();
        let tsn = a.peer_last_tsn.wrapping_add(1);
        let rsn = a.peer_rsn_window.expect("known from the INIT").1;
        let mut value = rsn.to_be_bytes().to_vec();
        value.extend_from_slice(extra);
        let request = raw_chunk(CT_RECONFIG.0, 0, &raw_tlv(typ, &value));
        let raw = packet_to(a, &[data_chunk(tsn, 1, 0, b"bundled"), request]);
        inject(a, now, raw);

        assert!(!a.is_ended());
        assert_eq!(
            vec![Bytes::from_static(b"bundled")],
            read_all(a, 1),
            "the DATA bundled with request {typ}"
        );
        let responses: Vec<Vec<u8>> = reconfig_params(&sent_datagrams(a, now))
            .into_iter()
            .filter(|(t, _)| *t == 16)
            .map(|(_, value)| value)
            .collect();
        assert_eq!(1, responses.len(), "request {typ}");
        assert_eq!(&rsn.to_be_bytes()[..], &responses[0][..4], "request {typ}");
        assert_eq!(&[0, 0, 0, result][..], &responses[0][4..8], "request {typ}");
    }
}

/// RFC 6525 4.1 and 4.4: the Outgoing SSN Reset Request (13) and the Re-configuration
/// Response (16) "MUST NOT appear in any other chunk" than RE-CONFIG. A data channel closed
/// in both directions over a link exchanges both; every chunk either side sends that carries
/// parameters (INIT, INIT ACK, HEARTBEAT, HEARTBEAT ACK, RE-CONFIG) is looked at, and the two
/// types appear in RE-CONFIG chunks only.
#[test]
fn reset_requests_and_responses_travel_in_re_config_chunks_only() {
    use std::cell::RefCell;
    use std::rc::Rc;
    let seen: Rc<RefCell<Vec<Bytes>>> = Rc::new(RefCell::new(vec![]));
    let record = seen.clone();
    let mut link = Link::new(TransportConfig::default(), TransportConfig::default(), 503);
    link.filter = Some(Box::new(move |_, datagram: &Bytes| {
        record.borrow_mut().push(datagram.clone());
        false
    }));
    link.connect();
    let now = link.now;
    link.client
        .conn()
        .open_stream(1, PPI)
        .unwrap()
        .write_sctp(now, &Bytes::from_static(b"hello"), PPI)
        .unwrap();
    let deadline = link.now + Duration::from_secs(5);
    assert!(link.run_until(deadline, |l| !l.server.received.is_empty()));
    let now = link.now;
    link.client.conn().stream(1).unwrap().close(now).unwrap();
    link.run_for(Duration::from_secs(40));

    let datagrams = seen.borrow().clone();
    let mut in_reconfig = vec![];
    for datagram in &datagrams {
        for chunk in chunks_of(datagram) {
            let params_at = match chunk[0] {
                1 | 2 => 20, // INIT, INIT ACK: the fixed fields first
                4 | 5 => 4,  // HEARTBEAT, HEARTBEAT ACK
                130 => 4,    // RE-CONFIG
                _ => continue,
            };
            let types: Vec<u16> = tlvs(&chunk[params_at.min(chunk.len())..])
                .into_iter()
                .map(|(t, _)| t)
                .collect();
            if chunk[0] == CT_RECONFIG.0 {
                in_reconfig.extend(types);
            } else {
                assert!(
                    !types.iter().any(|t| *t == 13 || *t == 16),
                    "chunk type {} carries {types:?}",
                    chunk[0]
                );
            }
        }
    }
    assert!(in_reconfig.contains(&13), "{in_reconfig:?}");
    assert!(in_reconfig.contains(&16), "{in_reconfig:?}");
}
