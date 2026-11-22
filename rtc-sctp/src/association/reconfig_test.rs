//! RFC 6525 beyond the Outgoing SSN Reset Request: one request in flight, the request
//! sequence numbers, data held on either side of a reset, and the Incoming SSN Reset, SSN/TSN
//! Reset and Add Streams requests.

use super::robustness_test::*;
use super::stream_reconfig_test::reconfig_params;
use super::*;
use crate::chunk::chunk_type::*;
use crate::endpoint::link_test::Link;
use crate::param::param_add_streams_request::ParamAddStreamsRequest;
use crate::param::param_incoming_reset_request::ParamIncomingResetRequest;
use crate::param::param_ssn_tsn_reset_request::ParamSsnTsnResetRequest;

const PPI: PayloadProtocolIdentifier = PayloadProtocolIdentifier::Binary;

fn chunk_of(param: impl Param + 'static) -> ChunkReconfig {
    ChunkReconfig {
        param_a: Some(Box::new(param)),
        param_b: None,
    }
}

fn response(rsn: u32, result: ReconfigResult) -> ChunkReconfig {
    chunk_of(ParamReconfigResponse {
        reconfig_response_sequence_number: rsn,
        result,
        next_tsns: None,
    })
}

fn u32_at(value: &[u8], offset: usize) -> u32 {
    u32::from_be_bytes(value[offset..offset + 4].try_into().unwrap())
}

/// The (response sequence number, result) of each Re-configuration Response in `packets`.
fn responses(packets: &[Packet]) -> Vec<(u32, u32)> {
    let raw: Vec<Bytes> = packets.iter().map(|p| p.marshal().unwrap()).collect();
    reconfig_params(&raw)
        .into_iter()
        .filter(|(typ, _)| *typ == 16)
        .map(|(_, value)| (u32_at(&value, 0), u32_at(&value, 4)))
        .collect()
}

/// The request parameters (type, value) among what the association sends now.
fn requests_sent(a: &mut Association, now: Instant) -> Vec<(u16, Vec<u8>)> {
    reconfig_params(&a.gather_outbound(now).0)
        .into_iter()
        .filter(|(typ, _)| *typ != 16)
        .collect()
}

fn ack_everything(a: &mut Association, now: Instant) {
    let last = a.my_next_tsn.wrapping_sub(1);
    if sna32gt(last, a.cumulative_tsn_ack_point) {
        a.handle_sack(
            &ChunkSelectiveAck {
                cumulative_tsn_ack: last,
                advertised_receiver_window_credit: 1 << 20,
                gap_ack_blocks: vec![],
                duplicate_tsn: vec![],
            },
            now,
        )
        .unwrap();
    }
}

fn ordered(tsn: u32, stream: u16, ssn: u16, payload: &'static [u8]) -> ChunkPayloadData {
    ChunkPayloadData {
        tsn,
        stream_identifier: stream,
        stream_sequence_number: ssn,
        beginning_fragment: true,
        ending_fragment: true,
        payload_type: PPI,
        user_data: Bytes::from_static(payload),
        ..Default::default()
    }
}

fn reconfig_events(events: &[Event]) -> Vec<ReconfigEvent> {
    events
        .iter()
        .filter_map(|e| match e {
            Event::Reconfig(r) => Some(r.clone()),
            _ => None,
        })
        .collect()
}

// ---- parameters ---------------------------------------------------------------------------

/// RFC 6525 4.2, 4.3, 4.5, 4.6: the request parameters as they are on the wire. The Reserved
/// field of the Add Streams requests is zero when sent and ignored when received.
#[test]
fn the_request_parameters_are_encoded_and_decoded() -> Result<()> {
    let incoming = ParamIncomingResetRequest {
        reconfig_request_sequence_number: 0x0102_0304,
        stream_identifiers: vec![5, 6],
    };
    let raw = incoming.marshal()?;
    assert_eq!(&[0, 14, 0, 12, 1, 2, 3, 4, 0, 5, 0, 6][..], &raw[..]);
    assert_eq!(incoming, ParamIncomingResetRequest::unmarshal(&raw)?);
    assert!(
        ParamIncomingResetRequest::unmarshal(&Bytes::from_static(&[0, 14, 0, 9, 1, 2, 3, 4, 0]))
            .is_err(),
        "the length is 8 + 2 * N"
    );

    let reset = ParamSsnTsnResetRequest {
        reconfig_request_sequence_number: 7,
    };
    let raw = reset.marshal()?;
    assert_eq!(&[0, 15, 0, 8, 0, 0, 0, 7][..], &raw[..]);
    assert_eq!(reset, ParamSsnTsnResetRequest::unmarshal(&raw)?);
    assert!(
        ParamSsnTsnResetRequest::unmarshal(&Bytes::from_static(&[
            0, 15, 0, 12, 0, 0, 0, 7, 0, 0, 0, 0
        ]))
        .is_err(),
        "the length is 8"
    );

    for (typ, incoming) in [(17u8, false), (18, true)] {
        let add = ParamAddStreamsRequest {
            incoming,
            reconfig_request_sequence_number: 9,
            number_of_new_streams: 3,
        };
        let raw = add.marshal()?;
        assert_eq!(&[0, typ, 0, 12, 0, 0, 0, 9, 0, 3, 0, 0][..], &raw[..]);
        // A Reserved field that is not zero is ignored.
        let received = Bytes::from(vec![0, typ, 0, 12, 0, 0, 0, 9, 0, 3, 0xff, 0xff]);
        assert_eq!(add, ParamAddStreamsRequest::unmarshal(&received)?);
        // And each is what a RE-CONFIG chunk yields for its type.
        let built = crate::param::build_param(&raw)?;
        assert_eq!(
            Some(&add),
            built.as_any().downcast_ref::<ParamAddStreamsRequest>()
        );
    }
    Ok(())
}

/// RFC 6525 4.4: a Re-configuration Response is 12 bytes, or 20 with both the Sender's Next
/// TSN and the Receiver's Next TSN.
#[test]
fn a_response_carries_both_next_tsns_or_neither() -> Result<()> {
    let with = ParamReconfigResponse {
        reconfig_response_sequence_number: 1,
        result: ReconfigResult::SuccessPerformed,
        next_tsns: Some((0x1111_1111, 0x2222_2222)),
    };
    let raw = with.marshal()?;
    assert_eq!(20, raw.len());
    assert_eq!(&[0, 16, 0, 20][..], &raw[..4]);
    assert_eq!(
        &[0x11, 0x11, 0x11, 0x11, 0x22, 0x22, 0x22, 0x22][..],
        &raw[12..]
    );
    assert_eq!(with, ParamReconfigResponse::unmarshal(&raw)?);

    let mut one_tsn = raw.to_vec();
    one_tsn.truncate(16);
    one_tsn[3] = 16;
    assert!(
        ParamReconfigResponse::unmarshal(&Bytes::from(one_tsn)).is_err(),
        "one TSN field alone is not a response"
    );
    Ok(())
}

// ---- negotiation --------------------------------------------------------------------------

/// RFC 6525 5.1.1: the INIT and the INIT ACK list the RE-CONFIG chunk (130) in their
/// Supported Extensions parameter, and each side takes the other's listing.
#[test]
fn both_sides_announce_the_reconfig_chunk() {
    let mut link = Link::new(TransportConfig::default(), TransportConfig::default(), 601);
    let seen = std::rc::Rc::new(std::cell::RefCell::new(vec![]));
    let record = seen.clone();
    link.filter = Some(Box::new(move |_, datagram: &Bytes| {
        for chunk in chunks_of(datagram) {
            if chunk[0] == CT_INIT.0 || chunk[0] == CT_INIT_ACK.0 {
                let extensions: Vec<u8> = tlvs(&chunk[20..])
                    .into_iter()
                    .filter(|(typ, _)| *typ == 0x8008)
                    .flat_map(|(_, value)| value)
                    .collect();
                record.borrow_mut().push((chunk[0], extensions));
            }
        }
        false
    }));
    link.connect();
    let seen = seen.borrow();
    for typ in [CT_INIT.0, CT_INIT_ACK.0] {
        assert!(
            seen.iter()
                .any(|(t, extensions)| *t == typ && extensions.contains(&CT_RECONFIG.0)),
            "chunk type {typ} lists RE-CONFIG: {seen:?}"
        );
    }
    assert!(link.client.conn().peer_supports_reconfig());
    assert!(link.server.conn().peer_supports_reconfig());
}

/// RFC 6525 5.1.1: no re-configuration request goes to a peer that did not list the RE-CONFIG
/// chunk, and the application's request is answered with an error. The request used to be
/// sent anyway, to a peer that skips the chunk: the reset never completed.
#[test]
fn no_request_is_sent_to_a_peer_without_the_extension() -> Result<()> {
    let mut a = create_association(TransportConfig::default());
    let now = Instant::now();
    let _ = sent_datagrams(&mut a, now);
    // An INIT ACK with a State Cookie and no Supported Extensions parameter.
    let init_ack = init_chunk(CT_INIT_ACK.0, 4242, 9000, &[raw_tlv(7, b"cookie")]);
    let raw = packet_to(&a, &[init_ack]);
    inject(&mut a, now, raw);
    let raw = packet_to(&a, &[raw_chunk(CT_COOKIE_ACK.0, 0, &[])]);
    inject(&mut a, now, raw);
    assert_eq!(AssociationState::Established, a.state());
    assert!(!a.peer_supports_reconfig());
    let _ = sent_datagrams(&mut a, now);

    let mut stream = a.open_stream(1, PPI)?;
    stream.write_sctp(now, &Bytes::from_static(b"data"), PPI)?;
    let refused = stream.stop(now);
    assert!(
        matches!(&refused, Err(Error::OtherSctpErr(text)) if text.contains("re-configuration")),
        "{refused:?}"
    );
    assert!(a.request_incoming_stream_reset(&[1]).is_err());
    assert!(a.request_ssn_tsn_reset(now).is_err());
    assert!(a.add_outgoing_streams(1).is_err());
    assert!(a.add_incoming_streams(1).is_err());
    let sent = sent_after(&mut a, now, Duration::from_secs(5));
    assert!(
        chunks_of_type(&sent, CT_RECONFIG.0).is_empty(),
        "a RE-CONFIG went to a peer that does not support it"
    );
    Ok(())
}

// ---- this side's requests -----------------------------------------------------------------

/// RFC 6525 5.1.2 A2, A4: the first request carries the initial TSN as its sequence number,
/// the next one that plus 1; the Response Sequence Number field is the peer's next expected
/// request sequence number minus 1 (it was always 0).
#[test]
fn a_request_carries_the_next_sequence_number_and_the_peers_last() -> Result<()> {
    let mut a = timed_test_association();
    let now = Instant::now();
    let initial_tsn = a.my_next_tsn;
    a.peer_rsn_window = Some((700, 705));

    a.open_stream(1, PPI)?.stop(now)?;
    let sent = requests_sent(&mut a, now);
    assert_eq!(1, sent.len());
    let (typ, value) = &sent[0];
    assert_eq!(13, *typ);
    assert_eq!(initial_tsn, u32_at(value, 0), "the request sequence number");
    assert_eq!(704, u32_at(value, 4), "the response sequence number");
    assert_eq!(a.my_next_tsn.wrapping_sub(1), u32_at(value, 8));

    a.handle_reconfig(&response(initial_tsn, ReconfigResult::SuccessPerformed))?;
    a.open_stream(2, PPI)?.stop(now)?;
    let sent = requests_sent(&mut a, now);
    assert_eq!(initial_tsn.wrapping_add(1), u32_at(&sent[0].1, 0));
    Ok(())
}

/// RFC 6525 5.1.1: "At any given time, there MUST NOT be more than one request in flight."
/// Each reset used to go out as it was asked for, so closing channels one after another put
/// several requests in flight. The ones that wait leave together when the answer is in.
#[test]
fn one_request_is_in_flight_and_the_others_wait() -> Result<()> {
    let mut a = timed_test_association();
    let now = Instant::now();
    for id in 1..=4 {
        a.open_stream(id, PPI)?;
    }

    a.stream(1)?.stop(now)?;
    let first = requests_sent(&mut a, now);
    assert_eq!(1, first.len());
    let rsn = u32_at(&first[0].1, 0);

    for id in 2..=4 {
        a.stream(id)?.stop(now)?;
        assert!(
            requests_sent(&mut a, now).is_empty(),
            "a second request left while the first is not answered"
        );
    }
    assert_eq!(1, a.reconfigs.len());

    // "In progress" is not the answer: the others still wait.
    a.handle_reconfig(&response(rsn, ReconfigResult::InProgress))?;
    assert!(requests_sent(&mut a, now).is_empty());

    a.handle_reconfig(&response(rsn, ReconfigResult::SuccessPerformed))?;
    let second = requests_sent(&mut a, now);
    assert_eq!(1, second.len(), "the waiting resets leave as one request");
    assert_eq!(rsn.wrapping_add(1), u32_at(&second[0].1, 0));
    assert_eq!(&[0, 2, 0, 3, 0, 4][..], &second[0].1[12..]);
    assert!(a.timers.get(Timer::Reconfig).is_some());
    Ok(())
}

/// RFC 9260 6.10: a RE-CONFIG fits one packet. Resets of more streams than a packet has room
/// for leave as several requests, one after the other; they used to leave as one chunk of
/// any size.
#[test]
fn a_reset_of_many_streams_is_split_to_fit_the_packet() -> Result<()> {
    let mut a = timed_test_association();
    let now = Instant::now();
    for id in 0..800u16 {
        a.open_stream(id, PPI)?.stop(now)?;
    }
    let out = a.gather_outbound(now).0;
    assert!(out.iter().all(|p| p.len() <= a.mtu as usize));
    let sent = reconfig_params(&out);
    assert_eq!(1, sent.len());
    let first = (sent[0].1.len() - 12) / 2;
    assert!(first > 600 && first < 800, "{first} streams in the request");
    let rsn = u32_at(&sent[0].1, 0);

    a.handle_reconfig(&response(rsn, ReconfigResult::SuccessPerformed))?;
    let out = a.gather_outbound(now).0;
    let sent = reconfig_params(&out);
    assert_eq!(1, sent.len());
    assert_eq!(800, first + (sent[0].1.len() - 12) / 2, "the rest of them");
    Ok(())
}

/// RFC 6525 5.1.2 A1 and 5.2.7 H4: data written to a stream while its reset is not answered
/// gets no Stream Sequence Number and waits. It used to go out at once with the old
/// sequence, which the peer, having reset to 0, held back for good.
#[test]
fn data_written_during_a_reset_waits_for_the_answer() -> Result<()> {
    for performed in [true, false] {
        let mut a = timed_test_association();
        let now = Instant::now();
        let mut stream = a.open_stream(3, PPI)?;
        stream.write_sctp(now, &Bytes::from_static(b"one"), PPI)?;
        stream.write_sctp(now, &Bytes::from_static(b"two"), PPI)?;
        stream.stop(now)?;
        let sent = a.gather_outbound(now).0;
        assert_eq!(2, transmitted_data(&sent).len());
        let rsn = *a.reconfigs.keys().next().expect("the request is sent");

        a.stream(3)?
            .write_sctp(now, &Bytes::from_static(b"three"), PPI)?;
        a.stream(3)?
            .write_sctp(now, &Bytes::from_static(b"four"), PPI)?;
        ack_everything(&mut a, now);
        assert!(
            transmitted_data(&a.gather_outbound(now).0).is_empty(),
            "data left before the reset was answered"
        );
        assert_eq!(9, a.streams[&3].buffered_amount, "it is buffered");

        let result = if performed {
            ReconfigResult::SuccessPerformed
        } else {
            ReconfigResult::Denied
        };
        a.handle_reconfig(&response(rsn, result))?;
        let after = transmitted_data(&a.gather_outbound(now).0);
        let expected = if performed { vec![0, 1] } else { vec![2, 3] };
        assert_eq!(
            expected,
            after
                .iter()
                .map(|c| c.stream_sequence_number)
                .collect::<Vec<_>>(),
            "performed: {performed}"
        );
        assert_eq!(
            vec![&b"three"[..], &b"four"[..]],
            after.iter().map(|c| &c.user_data[..]).collect::<Vec<_>>()
        );
        let events = reconfig_events(&a.events.iter().map(clone_event).collect::<Vec<_>>());
        if performed {
            assert_eq!(
                vec![ReconfigEvent::OutgoingStreamsReset { streams: vec![3] }],
                events
            );
        } else {
            assert_eq!(
                vec![ReconfigEvent::OutgoingStreamsResetFailed {
                    streams: vec![3],
                    denied: true
                }],
                events
            );
        }
    }
    Ok(())
}

fn clone_event(e: &Event) -> Event {
    match e {
        Event::Reconfig(r) => Event::Reconfig(r.clone()),
        _ => Event::DatagramReceived,
    }
}

/// RFC 6525 5.1.1: an expiry of the Re-configuration Timer counts against the association,
/// which ends past Association.Max.Retrans. 5.2.7 H2: not while the peer answers "In
/// progress".
#[test]
fn unanswered_requests_end_the_association_at_the_retransmission_limit() -> Result<()> {
    let mut a = timed_test_association();
    let mut now = Instant::now();
    a.open_stream(3, PPI)?.stop(now)?;
    assert_eq!(1, requests_sent(&mut a, now).len());

    let mut retransmissions = 0;
    for _ in 0..40 {
        let Some(at) = a.timers.get(Timer::Reconfig) else {
            break;
        };
        now = at;
        a.handle_timeout(now);
        retransmissions += requests_sent(&mut a, now).len();
    }
    assert_eq!(
        10, retransmissions,
        "Association.Max.Retrans retransmissions, then the association ends"
    );
    assert!(a.is_ended());
    assert!(a.events.iter().any(|e| matches!(
        e,
        Event::AssociationClosed {
            reason: AssociationError::TimedOut
        }
    )));
    Ok(())
}

// ---- the peer's requests ------------------------------------------------------------------

/// RFC 6525 5.2.1: the request sequence number tells a new request from one seen before. A
/// number from before the ones the peer can be using is answered "Error - Bad Sequence
/// Number" and not performed; the last one is answered with the same chunk again.
#[test]
fn request_sequence_numbers_are_checked() -> Result<()> {
    let mut a = timed_test_association();
    a.peer_rsn_window = Some((1000, 1000));
    a.create_stream(4, true, PPI);

    let stale = a.handle_reconfig(&reset_request_chunk(999, a.peer_last_tsn, vec![4]))?;
    assert_eq!(vec![(999, 5)], responses(&stale));
    assert!(a.streams.contains_key(&4), "a stale request was performed");

    let far = a.handle_reconfig(&reset_request_chunk(1000 + 500, a.peer_last_tsn, vec![4]))?;
    assert_eq!(vec![(1500, 5)], responses(&far));
    assert!(a.streams.contains_key(&4));

    let performed = a.handle_reconfig(&reset_request_chunk(1000, a.peer_last_tsn, vec![4]))?;
    assert_eq!(vec![(1000, 1)], responses(&performed));
    assert!(!a.streams.contains_key(&4));

    // The stream is used again; the retransmission of the request does not reset it.
    a.create_stream(4, true, PPI);
    let again = a.handle_reconfig(&reset_request_chunk(1000, a.peer_last_tsn, vec![4]))?;
    assert_eq!(
        performed[0].marshal()?,
        again[0].marshal()?,
        "the same RE-CONFIG chunk as before"
    );
    assert!(a.streams.contains_key(&4));
    Ok(())
}

/// A request older than the answers remembered used to be performed a second time, resetting
/// a stream that had since been used again.
#[test]
fn a_request_older_than_the_ones_remembered_is_not_performed_again() -> Result<()> {
    let mut a = timed_test_association();
    a.peer_rsn_window = Some((0, 0));
    for rsn in 0..=200u32 {
        a.create_stream(4, true, PPI);
        a.streams.get_mut(&4).unwrap().state = RecvSendState::Closed;
        let reply = a.handle_reconfig(&reset_request_chunk(rsn, a.peer_last_tsn, vec![4]))?;
        assert_eq!(vec![(rsn, 1)], responses(&reply));
    }
    a.create_stream(4, true, PPI);
    let base = a.peer_last_tsn;
    a.handle_data(&ordered(base.wrapping_add(1), 4, 0, b"new use"))?;

    let replay = a.handle_reconfig(&reset_request_chunk(0, a.peer_last_tsn, vec![4]))?;
    assert_eq!(vec![(0, 5)], responses(&replay), "Bad Sequence Number");
    assert_eq!(vec![Bytes::from_static(b"new use")], read_all(&mut a, 4));
    Ok(())
}

/// RFC 6525 5.2.2 E2, E4: while a reset is deferred, DATA of its streams with a TSN beyond
/// the Sender's Last Assigned TSN is held, and processed once the reset is done: it is the
/// stream's next use. It used to be handed to the stream as it was before the reset, which
/// dropped it as an old sequence number.
#[test]
fn data_sent_after_a_deferred_reset_is_held_for_the_stream_as_reset() -> Result<()> {
    let mut a = timed_test_association();
    let base = a.peer_last_tsn;
    a.handle_data(&ordered(base.wrapping_add(1), 1, 0, b"first"))?;
    assert_eq!(vec![Bytes::from_static(b"first")], read_all(&mut a, 1));

    // The reset arrives ahead of the last DATA it covers (TSN base + 2).
    let reply = a.handle_reconfig(&reset_request_chunk(50, base.wrapping_add(2), vec![1]))?;
    assert_eq!(vec![(50, 6)], responses(&reply), "In progress");

    // The peer's next message on the stream, sent after its request: SSN 0 again.
    a.handle_data(&ordered(base.wrapping_add(3), 1, 0, b"next use"))?;
    // DATA of another stream is not held.
    a.handle_data(&ordered(base.wrapping_add(4), 2, 0, b"other"))?;
    assert_eq!(vec![Bytes::from_static(b"other")], read_all(&mut a, 2));
    assert!(read_all(&mut a, 1).is_empty());
    let window_while_held = a.get_my_receiver_window_credit();
    assert!(
        window_while_held < a.max_receive_buffer_size,
        "held DATA counts against the receive window"
    );

    // The last DATA before the reset arrives: the reset is performed once it is read.
    a.handle_data(&ordered(base.wrapping_add(2), 1, 1, b"last"))?;
    assert_eq!(base.wrapping_add(4), a.peer_last_tsn);
    // Reading the last message of the stream as it was lets the reset happen, and the
    // message that was held is the first of the stream as reset.
    assert_eq!(
        vec![Bytes::from_static(b"last"), Bytes::from_static(b"next use")],
        read_all(&mut a, 1)
    );
    assert!(a.events.iter().any(|e| matches!(
        e,
        Event::AssociationLost {
            reason: AssociationError::Reset,
            id: 1
        }
    )));
    assert_eq!(a.max_receive_buffer_size, a.get_my_receiver_window_credit());
    assert!(a.held_reset_data.is_empty());
    Ok(())
}

/// RFC 6525 3.1: a combination of parameters that is not one of the ten allowed is answered
/// with an ERROR chunk, "Protocol Violation", and not performed. The chunk's flags are
/// ignored (3.1), and a chunk with a request is acknowledged with a SACK too (5.2.1).
#[test]
fn a_reconfig_chunk_is_checked_before_it_is_performed() {
    let mut link = connected_link(602);
    let now = link.now;
    let a = link.server.conn();
    a.create_stream(4, true, PPI);
    let rsn = a.peer_rsn_window.expect("known from the INIT").1;
    let outgoing = chunk_bytes(&reset_request_chunk(rsn, a.peer_last_tsn, vec![4]));
    let outgoing_param = outgoing[4..].to_vec();

    // SSN/TSN Reset Request together with an Outgoing SSN Reset Request.
    let mut value = raw_tlv(15, &rsn.to_be_bytes());
    value.extend_from_slice(&outgoing_param);
    let raw = packet_to(a, &[raw_chunk(CT_RECONFIG.0, 0, &value)]);
    inject(a, now, raw);
    let sent = sent_datagrams(a, now);
    let causes: Vec<u16> = chunks_of_type(&sent, CT_ERROR.0)
        .iter()
        .flat_map(|c| tlvs(&c[4..]))
        .map(|(code, _)| code)
        .collect();
    assert_eq!(vec![13], causes, "Protocol Violation");
    assert!(chunks_of_type(&sent, CT_RECONFIG.0).is_empty());
    assert!(a.streams.contains_key(&4), "nothing of it is performed");
    assert!(!a.is_ended());

    // The allowed chunk, with flags that are not zero.
    let raw = packet_to(a, &[raw_chunk(CT_RECONFIG.0, 0xff, &outgoing_param)]);
    inject(a, now, raw);
    let sent = sent_datagrams(a, now);
    assert!(!a.streams.contains_key(&4), "the reset is performed");
    assert_eq!(
        1,
        chunks_of_type(&sent, CT_RECONFIG.0).len(),
        "one chunk answers it"
    );
    assert_eq!(
        1,
        chunks_of_type(&sent, CT_SACK.0).len(),
        "a SACK goes back with the answer"
    );
}

/// RFC 6525 5.2.1: each parameter of a chunk is processed, here a response to this side's
/// request and a request of the peer's; and 5.1.1: a chunk that holds no request starts no
/// timer.
#[test]
fn both_parameters_of_a_chunk_are_processed() -> Result<()> {
    let mut a = timed_test_association();
    let now = Instant::now();
    a.open_stream(1, PPI)?.stop(now)?;
    a.create_stream(2, true, PPI);
    a.streams.get_mut(&2).unwrap().state = RecvSendState::Closed;
    let sent = requests_sent(&mut a, now);
    let rsn = u32_at(&sent[0].1, 0);

    let reply = a.handle_reconfig(&ChunkReconfig {
        param_a: Some(Box::new(ParamReconfigResponse {
            reconfig_response_sequence_number: rsn,
            result: ReconfigResult::SuccessPerformed,
            next_tsns: None,
        })),
        param_b: Some(Box::new(ParamOutgoingResetRequest {
            reconfig_request_sequence_number: 77,
            reconfig_response_sequence_number: rsn,
            sender_last_tsn: a.peer_last_tsn,
            stream_identifiers: vec![2],
        })),
    })?;
    assert!(a.reconfigs.is_empty(), "the response is taken");
    assert!(!a.streams.contains_key(&2), "the request is performed");
    assert_eq!(vec![(77, 1)], responses(&reply));
    for packet in reply {
        a.control_queue.push_back(packet);
    }
    let _ = a.gather_outbound(now);
    assert!(
        a.timers.get(Timer::Reconfig).is_none(),
        "a RE-CONFIG without a request starts no timer"
    );
    Ok(())
}

/// RFC 6525 5.2.3: an Incoming SSN Reset Request is answered with an Outgoing SSN Reset
/// Request for the same streams, whose Response Sequence Number is the request's (5.1.2 A4),
/// once the data written before has been sent. It used to be denied.
#[test]
fn an_incoming_reset_request_is_answered_with_an_outgoing_reset() -> Result<()> {
    let mut a = timed_test_association();
    let now = Instant::now();
    a.peer_rsn_window = Some((300, 300));
    for id in [1u16, 2] {
        a.open_stream(id, PPI)?
            .write_sctp(now, &Bytes::from_static(b"sent"), PPI)?;
    }
    let _ = a.gather_outbound(now);
    // More data than the window lets out: the reset waits behind it.
    a.cwnd = 0;
    a.stream(1)?
        .write_sctp(now, &Bytes::from_static(b"queued"), PPI)?;

    let request = chunk_of(ParamIncomingResetRequest {
        reconfig_request_sequence_number: 300,
        stream_identifiers: vec![1, 9],
    });
    assert!(a.handle_reconfig(&request)?.is_empty());
    assert!(requests_sent(&mut a, now).is_empty(), "the data goes first");
    // A retransmission meanwhile is told the request is in progress.
    assert_eq!(vec![(300, 6)], responses(&a.handle_reconfig(&request)?));
    // New data on the stream waits for the reset (5.1.2 A1).
    a.stream(1)?
        .write_sctp(now, &Bytes::from_static(b"later"), PPI)?;

    a.cwnd = 1 << 20;
    ack_everything(&mut a, now);
    let out = a.gather_outbound(now).0;
    assert_eq!(
        vec![&b"queued"[..]],
        transmitted_data(&out)
            .iter()
            .map(|c| &c.user_data[..])
            .collect::<Vec<_>>()
    );
    let sent: Vec<_> = reconfig_params(&out);
    assert_eq!(1, sent.len());
    let (typ, value) = &sent[0];
    assert_eq!(13, *typ);
    assert_eq!(300, u32_at(value, 4), "the request it answers");
    assert_eq!(a.my_next_tsn.wrapping_sub(1), u32_at(value, 8));
    assert_eq!(
        &[0, 1, 0, 9][..],
        &value[12..],
        "the stream numbers, copied"
    );
    let own = u32_at(value, 0);

    // The retransmitted request now gets that same chunk.
    let again = a.handle_reconfig(&request)?;
    assert_eq!(1, again.len());
    assert_eq!(
        vec![13],
        reconfig_param_types(&again[0]),
        "the same answer as before"
    );

    a.handle_reconfig(&response(own, ReconfigResult::SuccessPerformed))?;
    let after = transmitted_data(&a.gather_outbound(now).0);
    assert_eq!(1, after.len());
    assert_eq!(0, after[0].stream_sequence_number, "stream 1 starts over");
    assert_eq!(1, a.streams[&2].sequence_number, "stream 2 was not named");
    Ok(())
}

/// RFC 6525 5.2.3: when this side's Outgoing SSN Reset Request in flight covers the streams
/// of the peer's Incoming SSN Reset Request, or the streams are at sequence number 0 already,
/// the answer is "Success - Nothing to do".
#[test]
fn an_incoming_reset_request_with_nothing_to_do_says_so() -> Result<()> {
    let mut a = timed_test_association();
    let now = Instant::now();
    a.peer_rsn_window = Some((300, 300));
    a.open_stream(5, PPI)?;
    let request = |rsn, streams: Vec<u16>| {
        chunk_of(ParamIncomingResetRequest {
            reconfig_request_sequence_number: rsn,
            stream_identifiers: streams,
        })
    };

    // Nothing was sent on stream 5, and stream 6 does not exist.
    let reply = a.handle_reconfig(&request(300, vec![5, 6]))?;
    assert_eq!(vec![(300, 0)], responses(&reply));

    // This side is resetting streams 5 and 7 itself.
    a.stream(5)?
        .write_sctp(now, &Bytes::from_static(b"data"), PPI)?;
    a.open_stream(7, PPI)?
        .write_sctp(now, &Bytes::from_static(b"data"), PPI)?;
    a.stream(5)?.stop(now)?;
    a.stream(7)?.stop(now)?;
    assert_eq!(1, requests_sent(&mut a, now).len());
    let reply = a.handle_reconfig(&request(301, vec![7, 5]))?;
    assert_eq!(vec![(301, 0)], responses(&reply));
    assert!(a.reconfig_queue.is_empty(), "no second reset is queued");

    // A request that this side's own only partly covers is processed normally.
    a.open_stream(8, PPI)?
        .write_sctp(now, &Bytes::from_static(b"data"), PPI)?;
    let _ = a.gather_outbound(now);
    let reply = a.handle_reconfig(&request(302, vec![5, 8]))?;
    assert!(responses(&reply).is_empty(), "not answered Nothing to do");
    assert!(a.streams[&8].outgoing_reset_pending);
    assert_eq!(1, requests_sent(&mut a, now).len() + a.reconfig_queue.len());
    Ok(())
}

/// RFC 6525 5.1.3 and 5.2.2 E1: this side's Incoming SSN Reset Request is acknowledged by the
/// peer's Outgoing SSN Reset Request that names it, which stops its timer; a response says
/// the peer did not perform it.
#[test]
fn an_incoming_reset_request_of_this_side_is_answered_by_the_peers_reset() -> Result<()> {
    let mut a = timed_test_association();
    let now = Instant::now();
    a.peer_rsn_window = Some((40, 40));
    a.create_stream(3, true, PPI);
    a.streams.get_mut(&3).unwrap().state = RecvSendState::Closed;

    a.request_incoming_stream_reset(&[3])?;
    let sent = requests_sent(&mut a, now);
    assert_eq!(1, sent.len());
    assert_eq!(14, sent[0].0);
    let rsn = u32_at(&sent[0].1, 0);
    assert_eq!(&[0, 3][..], &sent[0].1[4..]);
    assert!(a.timers.get(Timer::Reconfig).is_some());

    let reply = a.handle_reconfig(&chunk_of(ParamOutgoingResetRequest {
        reconfig_request_sequence_number: 40,
        reconfig_response_sequence_number: rsn,
        sender_last_tsn: a.peer_last_tsn,
        stream_identifiers: vec![3],
    }))?;
    assert_eq!(vec![(40, 1)], responses(&reply));
    assert!(a.reconfigs.is_empty(), "the request is acknowledged");
    assert!(a.timers.get(Timer::Reconfig).is_none());
    assert!(!a.streams.contains_key(&3), "the stream is reset");

    // Refused: the application is told.
    a.request_incoming_stream_reset(&[])?;
    let sent = requests_sent(&mut a, now);
    assert_eq!(4, sent[0].1.len(), "no stream numbers: all streams");
    let rsn = u32_at(&sent[0].1, 0);
    a.handle_reconfig(&response(rsn, ReconfigResult::Denied))?;
    assert!(a.events.iter().any(|e| matches!(
        e,
        Event::Reconfig(ReconfigEvent::IncomingStreamsResetNotPerformed { denied: true, .. })
    )));
    Ok(())
}

/// End to end: one side asks the other to reset its outgoing stream. Under RFC 8831 6.7 the
/// reset of one direction is followed by the reset of the other, so the stream closes on
/// both sides.
#[test]
fn an_incoming_reset_request_resets_the_stream_end_to_end() {
    let mut link = connected_link(603);
    let now = link.now;
    link.client
        .conn()
        .open_stream(1, PPI)
        .unwrap()
        .write_sctp(now, &Bytes::from_static(b"ping"), PPI)
        .unwrap();
    let deadline = link.now + Duration::from_secs(5);
    assert!(link.run_until(deadline, |l| !l.server.received.is_empty()));
    let now = link.now;
    link.server
        .conn()
        .stream(1)
        .unwrap()
        .write_sctp(now, &Bytes::from_static(b"pong"), PPI)
        .unwrap();
    let deadline = link.now + Duration::from_secs(5);
    assert!(link.run_until(deadline, |l| !l.client.received.is_empty()));

    link.client
        .conn()
        .request_incoming_stream_reset(&[1])
        .unwrap();
    link.run_for(Duration::from_secs(10));

    assert!(
        reconfig_events(&link.server.events)
            .contains(&ReconfigEvent::OutgoingResetRequestedByPeer { streams: vec![1] })
    );
    for (name, peer) in [("client", &mut link.client), ("server", &mut link.server)] {
        assert!(
            peer.events.iter().any(|e| matches!(
                e,
                Event::AssociationLost {
                    reason: AssociationError::Reset,
                    id: 1
                }
            )),
            "{name}: the stream was not reset"
        );
        assert!(peer.conn().reconfigs.is_empty(), "{name}");
        assert!(peer.conn().reconfig_queue.is_empty(), "{name}");
        assert!(!peer.conn().is_ended(), "{name}");
    }
}

// ---- SSN/TSN reset ------------------------------------------------------------------------

/// RFC 6525 5.2.4: the SSN/TSN Reset Request. With DATA of this side's own outstanding the
/// reset waits ("In progress") and no new DATA is sent; then the response carries this
/// side's next TSN and, for the peer, the smallest TSN not acknowledged plus 2^31; the peer's
/// TSNs go on from there and every stream starts at sequence number 0, in both directions.
#[test]
fn an_ssn_tsn_reset_request_is_performed_when_nothing_is_outstanding() -> Result<()> {
    let mut a = timed_test_association();
    let now = Instant::now();
    a.peer_rsn_window = Some((20, 20));
    let base = a.peer_last_tsn;
    // Stream 1 has delivered SSN 0 and holds SSN 2, complete but out of order.
    a.handle_data(&ordered(base.wrapping_add(1), 1, 0, b"zero"))?;
    a.handle_data(&ordered(base.wrapping_add(2), 1, 2, b"two"))?;
    assert_eq!(vec![Bytes::from_static(b"zero")], read_all(&mut a, 1));

    a.stream(1)?
        .write_sctp(now, &Bytes::from_static(b"out 0"), PPI)?;
    let _ = a.gather_outbound(now);
    a.cwnd = 0;
    a.stream(1)?
        .write_sctp(now, &Bytes::from_static(b"out 1"), PPI)?;
    a.cwnd = 1 << 20;

    let request = chunk_of(ParamSsnTsnResetRequest {
        reconfig_request_sequence_number: 20,
    });
    assert_eq!(vec![(20, 6)], responses(&a.handle_reconfig(&request)?));
    assert!(
        transmitted_data(&a.gather_outbound(now).0).is_empty(),
        "new DATA was sent while the reset waits"
    );

    // The SACK for what was outstanding lets the reset happen.
    let next_tsn = a.my_next_tsn;
    let reply = a.handle_sack(
        &ChunkSelectiveAck {
            cumulative_tsn_ack: next_tsn.wrapping_sub(1),
            advertised_receiver_window_credit: 1 << 20,
            gap_ack_blocks: vec![],
            duplicate_tsn: vec![],
        },
        now,
    )?;
    let raw: Vec<Bytes> = reply.iter().map(|p| p.marshal().unwrap()).collect();
    let params = reconfig_params(&raw);
    assert_eq!(1, params.len());
    let value = &params[0].1;
    assert_eq!(16, value.len(), "a response with both TSNs");
    assert_eq!((20, 1), (u32_at(value, 0), u32_at(value, 4)));
    assert_eq!(next_tsn, u32_at(value, 8), "Sender's Next TSN");
    let receiver_next = base.wrapping_add(3).wrapping_add(1 << 31);
    assert_eq!(receiver_next, u32_at(value, 12), "Receiver's Next TSN");
    assert_eq!(receiver_next.wrapping_sub(1), a.peer_last_tsn);

    // What was complete is delivered; the peer's next message is SSN 0 at the new TSN.
    assert_eq!(vec![Bytes::from_static(b"two")], read_all(&mut a, 1));
    a.handle_data(&ordered(receiver_next, 1, 0, b"after"))?;
    assert_eq!(vec![Bytes::from_static(b"after")], read_all(&mut a, 1));

    // This side's queued message goes out with SSN 0 and the TSN it announced.
    let sent = transmitted_data(&a.gather_outbound(now).0);
    assert_eq!(1, sent.len());
    assert_eq!((next_tsn, 0), (sent[0].tsn, sent[0].stream_sequence_number));
    assert_eq!(1, a.streams[&1].sequence_number);

    // The request again: the same response.
    let again = a.handle_reconfig(&request)?;
    assert_eq!(reply[0].marshal()?, again[0].marshal()?);
    Ok(())
}

/// RFC 6525 5.1.4 and 5.2.7 H5: this side's SSN/TSN Reset Request leaves when nothing is
/// outstanding, no new DATA is sent until it is answered, and then DATA is sent from the
/// Receiver's Next TSN with sequence number 0 on every stream. One request per 30 seconds.
#[test]
fn an_ssn_tsn_reset_of_this_side_suspends_sending_until_it_is_answered() -> Result<()> {
    let mut a = timed_test_association();
    let now = Instant::now();
    let base = a.peer_last_tsn;
    a.open_stream(1, PPI)?
        .write_sctp(now, &Bytes::from_static(b"before"), PPI)?;
    let _ = a.gather_outbound(now);

    a.request_ssn_tsn_reset(now)?;
    assert!(a.request_ssn_tsn_reset(now).is_err(), "one at a time");
    a.stream(1)?
        .write_sctp(now, &Bytes::from_static(b"after"), PPI)?;
    let out = a.gather_outbound(now).0;
    assert!(transmitted_data(&out).is_empty(), "C2: no new transmission");
    assert!(
        reconfig_params(&out).is_empty(),
        "the request waits for the outstanding DATA"
    );

    ack_everything(&mut a, now);
    let out = a.gather_outbound(now).0;
    assert!(transmitted_data(&out).is_empty());
    let sent = reconfig_params(&out);
    assert_eq!(1, sent.len());
    assert_eq!(15, sent[0].0);
    let rsn = u32_at(&sent[0].1, 0);

    // DATA from the peer meanwhile: it is from before the peer's reset.
    a.handle_data(&ordered(base.wrapping_add(1), 2, 0, b"old numbering"))?;

    let (sender_next, receiver_next) = (base.wrapping_add(2), 0x9000_0000u32);
    a.handle_reconfig(&chunk_of(ParamReconfigResponse {
        reconfig_response_sequence_number: rsn,
        result: ReconfigResult::SuccessPerformed,
        next_tsns: Some((sender_next, receiver_next)),
    }))?;
    assert_eq!(
        vec![Bytes::from_static(b"old numbering")],
        read_all(&mut a, 2)
    );
    let sent = transmitted_data(&a.gather_outbound(now).0);
    assert_eq!(1, sent.len());
    assert_eq!(
        (receiver_next, 0),
        (sent[0].tsn, sent[0].stream_sequence_number)
    );
    a.handle_data(&ordered(sender_next, 2, 0, b"new numbering"))?;
    assert_eq!(
        vec![Bytes::from_static(b"new numbering")],
        read_all(&mut a, 2)
    );
    assert!(a.events.iter().any(|e| matches!(
        e,
        Event::Reconfig(ReconfigEvent::AssociationReset { local_next_tsn, remote_next_tsn })
            if *local_next_tsn == receiver_next && *remote_next_tsn == sender_next
    )));

    assert!(
        a.request_ssn_tsn_reset(now + Duration::from_secs(29))
            .is_err(),
        "one request per 30 seconds"
    );
    assert!(
        a.request_ssn_tsn_reset(now + Duration::from_secs(31))
            .is_ok()
    );
    // Both sides asking at once: the peer's request is refused.
    a.peer_rsn_window = Some((5, 5));
    let reply = a.handle_reconfig(&chunk_of(ParamSsnTsnResetRequest {
        reconfig_request_sequence_number: 5,
    }))?;
    assert_eq!(
        vec![(5, 4)],
        responses(&reply),
        "Request already in progress"
    );
    Ok(())
}

/// End to end: an SSN/TSN reset between two associations with traffic on both sides, and
/// messages in both directions afterwards.
#[test]
fn an_ssn_tsn_reset_works_end_to_end() {
    let mut link = connected_link(604);
    let now = link.now;
    link.client.conn().open_stream(1, PPI).unwrap();
    for i in 0..5u8 {
        link.client
            .conn()
            .stream(1)
            .unwrap()
            .write_sctp(now, &Bytes::from(vec![i; 3000]), PPI)
            .unwrap();
    }
    let deadline = link.now + Duration::from_secs(10);
    assert!(link.run_until(deadline, |l| l.server.received.len() == 5));
    let now = link.now;
    link.server
        .conn()
        .stream(1)
        .unwrap()
        .write_sctp(now, &Bytes::from_static(b"reply"), PPI)
        .unwrap();
    link.client.conn().request_ssn_tsn_reset(now).unwrap();
    link.client
        .conn()
        .stream(1)
        .unwrap()
        .write_sctp(now, &Bytes::from_static(b"after the reset"), PPI)
        .unwrap();
    link.run_for(Duration::from_secs(10));

    let client = reconfig_events(&link.client.events);
    let server = reconfig_events(&link.server.events);
    let (
        [
            ReconfigEvent::AssociationReset {
                local_next_tsn: client_local,
                remote_next_tsn: client_remote,
            },
        ],
        [
            ReconfigEvent::AssociationReset {
                local_next_tsn: server_local,
                remote_next_tsn: server_remote,
            },
        ],
    ) = (&client[..], &server[..])
    else {
        panic!("client {client:?}, server {server:?}");
    };
    assert_eq!(client_local, server_remote);
    assert_eq!(client_remote, server_local);
    assert_eq!(
        Some(&(1, Bytes::from_static(b"after the reset"))),
        link.server.received.last()
    );
    assert_eq!(
        vec![(1, Bytes::from_static(b"reply"))],
        link.client.received
    );

    // Ordered messages both ways on the new numbering.
    let now = link.now;
    for (i, peer) in [&mut link.client, &mut link.server].into_iter().enumerate() {
        for n in 0..3u8 {
            peer.conn()
                .stream(1)
                .unwrap()
                .write_sctp(now, &Bytes::from(vec![n + i as u8 * 10; 2000]), PPI)
                .unwrap();
        }
    }
    link.run_for(Duration::from_secs(10));
    assert_eq!(9, link.server.received.len());
    assert_eq!(4, link.client.received.len());
    assert!(sna32gte(link.client.conn().my_next_tsn, *client_local));
}

// ---- adding streams -----------------------------------------------------------------------

/// RFC 6525 5.1.5, 5.2.5, 5.2.7 H6: outgoing streams are added when the peer accepts, and
/// not before; the peer accepts up to its limit and denies past it.
#[test]
fn outgoing_streams_are_added_when_the_peer_accepts() {
    let mut link = Link::new(
        TransportConfig::default().with_max_num_outbound_streams(4),
        TransportConfig::default(),
        605,
    );
    link.connect();
    assert_eq!(Some(4), link.client.conn().negotiated_max_streams());
    assert!(link.client.conn().open_stream(5, PPI).is_err());

    link.client.conn().add_outgoing_streams(2).unwrap();
    assert!(
        link.client.conn().open_stream(5, PPI).is_err(),
        "the streams are not used before the peer's answer"
    );
    link.run_for(Duration::from_secs(5));
    let added = ReconfigEvent::StreamsAdded {
        inbound_streams: 6,
        outbound_streams: 65535,
    };
    assert!(reconfig_events(&link.server.events).contains(&added));
    assert!(matches!(
        &reconfig_events(&link.client.events)[..],
        [ReconfigEvent::StreamsAdded {
            outbound_streams: 6,
            ..
        }]
    ));
    let now = link.now;
    link.client
        .conn()
        .open_stream(5, PPI)
        .unwrap()
        .write_sctp(now, &Bytes::from_static(b"on a new stream"), PPI)
        .unwrap();
    link.run_for(Duration::from_secs(5));
    assert_eq!(
        vec![(5, Bytes::from_static(b"on a new stream"))],
        link.server.received
    );

    // Past the limit the application set, the request is denied.
    link.server.conn().set_stream_limits(7, 65535);
    link.client.conn().add_outgoing_streams(2).unwrap();
    link.run_for(Duration::from_secs(5));
    assert_eq!(
        Some(&ReconfigEvent::AddStreamsFailed { denied: true }),
        reconfig_events(&link.client.events).last()
    );
    assert!(link.client.conn().open_stream(6, PPI).is_err());
}

/// RFC 6525 5.1.6, 5.2.6: a request for more incoming streams is performed by the peer with
/// an Add Outgoing Streams Request of its own, or denied.
#[test]
fn incoming_streams_are_added_by_the_peers_own_request() {
    let mut link = Link::new(
        TransportConfig::default().with_max_num_inbound_streams(4),
        TransportConfig::default(),
        606,
    );
    link.connect();
    assert!(link.server.conn().open_stream(5, PPI).is_err());

    link.client.conn().add_incoming_streams(2).unwrap();
    link.run_for(Duration::from_secs(5));
    assert!(matches!(
        &reconfig_events(&link.client.events)[..],
        [ReconfigEvent::StreamsAdded {
            inbound_streams: 6,
            ..
        }]
    ));
    assert!(matches!(
        &reconfig_events(&link.server.events)[..],
        [ReconfigEvent::StreamsAdded {
            outbound_streams: 6,
            ..
        }]
    ));
    assert!(link.client.conn().reconfigs.is_empty());
    assert!(link.server.conn().reconfigs.is_empty());
    let now = link.now;
    link.server
        .conn()
        .open_stream(5, PPI)
        .unwrap()
        .write_sctp(now, &Bytes::from_static(b"on a new stream"), PPI)
        .unwrap();
    link.run_for(Duration::from_secs(5));
    assert_eq!(
        vec![(5, Bytes::from_static(b"on a new stream"))],
        link.client.received
    );

    // The peer's limit on its own outgoing streams: denied.
    link.server.conn().set_stream_limits(65535, 6);
    link.client.conn().add_incoming_streams(1).unwrap();
    link.run_for(Duration::from_secs(5));
    assert_eq!(
        Some(&ReconfigEvent::AddStreamsFailed { denied: true }),
        reconfig_events(&link.client.events).last()
    );
}
