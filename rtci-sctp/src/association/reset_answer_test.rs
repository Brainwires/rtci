//! The answer to the peer's stream reset, and what it does to this side's own direction.
//!
//! RFC 8831 6.7: "Closing of a data channel MUST be signaled by resetting the corresponding
//! outgoing streams [RFC6525]. This means that if one side decides to close the data channel,
//! it resets the corresponding outgoing stream. When the peer sees that an incoming stream was
//! reset, it also resets its corresponding outgoing stream." RFC 6525 5.2.2: a request whose
//! Sender's Last Assigned TSN is beyond the cumulative TSN is performed later, once that TSN is
//! reached ("the receiver MUST ... respond with In progress ... and perform the reset when the
//! cumulative TSN reaches it" is the substance of E2).
//!
//! Two faults:
//! - A reset performed late, from the DATA (or FORWARD TSN) path, was never answered with this
//!   side's own reset: the peer's channel stayed "closing" for good, and an idle stream's reset
//!   was not even reported.
//! - Whether this side had already reset its direction was read from the Readable bit of the
//!   stream's `RecvSendState`, which an Incoming SSN Reset Request of the peer cleared: the
//!   stream stopped being readable although the peer had not reset its own direction, and the
//!   messages it held and still sent were never delivered.

use super::reconfig_test::{ack_everything, chunk_of, ordered, responses};
use super::robustness_test::read_all;
use super::stream_reconfig_test::reconfig_params;
use super::*;
use crate::AssociationError;
use crate::param::param_incoming_reset_request::ParamIncomingResetRequest;

const PPI: PayloadProtocolIdentifier = PayloadProtocolIdentifier::Binary;

/// This side's Outgoing SSN Reset Requests among `packets` and what it sends now, as the
/// stream numbers each names.
fn own_resets(a: &mut Association, packets: Vec<Packet>, now: Instant) -> Vec<Vec<u16>> {
    for p in packets {
        a.control_queue.push_back(p);
    }
    reconfig_params(&a.gather_outbound(now).0)
        .into_iter()
        .filter(|(typ, _)| *typ == 13)
        .map(|(_, value)| {
            value[12..]
                .chunks(2)
                .map(|b| u16::from_be_bytes([b[0], b[1]]))
                .collect()
        })
        .collect()
}

fn lost(events: &VecDeque<Event>, id: u16) -> bool {
    events.iter().any(|e| {
        matches!(
            e,
            Event::AssociationLost {
                reason: AssociationError::Reset,
                id: got,
            } if *got == id
        )
    })
}

/// RFC 6525 5.2.2 with RFC 8831 6.7: the peer's reset of stream 1 arrives ahead of the last
/// DATA it covers, which is on another stream. When that DATA (or a FORWARD TSN past it)
/// arrives the reset is performed, and this side resets its own direction of the stream as
/// well, as it does for a reset performed at once.
#[test]
fn a_reset_performed_when_its_last_tsn_arrives_is_answered_with_this_sides_reset() -> Result<()> {
    for by_forward_tsn in [false, true] {
        let mut a = timed_test_association();
        let now = Instant::now();
        let base = a.peer_last_tsn;
        a.handle_data(&ordered(base.wrapping_add(1), 1, 0, b"first"))?;
        assert_eq!(vec![Bytes::from_static(b"first")], read_all(&mut a, 1));

        let reply = a.handle_reconfig(&reset_request_chunk(50, base.wrapping_add(2), vec![1]))?;
        assert_eq!(vec![(50, 6)], responses(&reply), "In progress");
        let _ = a.gather_outbound(now);

        let reply = if by_forward_tsn {
            a.handle_forward_tsn(&ChunkForwardTsn {
                new_cumulative_tsn: base.wrapping_add(2),
                streams: vec![],
            })?
        } else {
            a.handle_data(&ordered(base.wrapping_add(2), 2, 0, b"other stream"))?
        };
        assert_eq!(vec![(50, 1)], responses(&reply), "performed");
        assert!(!a.streams.contains_key(&1), "the stream is reset");
        assert!(lost(&a.events, 1));
        assert_eq!(
            vec![vec![1u16]],
            own_resets(&mut a, reply, now),
            "by FORWARD TSN: {by_forward_tsn}: this side's direction is reset too"
        );
    }
    Ok(())
}

/// The same for a stream this side holds no state for (an idle pre-negotiated channel): the
/// reset performed late is reported, and answered with this side's own, as one performed at
/// once is (`test_reset_request_for_an_unknown_stream_is_reported_and_echoed`).
#[test]
fn a_late_reset_of_an_idle_stream_is_reported_and_answered() -> Result<()> {
    let mut a = timed_test_association();
    let now = Instant::now();
    let base = a.peer_last_tsn;
    let reply = a.handle_reconfig(&reset_request_chunk(50, base.wrapping_add(1), vec![4]))?;
    assert_eq!(vec![(50, 6)], responses(&reply));
    let _ = a.gather_outbound(now);
    assert!(!lost(&a.events, 4));

    let reply = a.handle_data(&ordered(base.wrapping_add(1), 2, 0, b"other stream"))?;
    assert_eq!(vec![(50, 1)], responses(&reply));
    assert!(lost(&a.events, 4), "the reset is reported");
    assert_eq!(vec![vec![4u16]], own_resets(&mut a, reply, now));
    Ok(())
}

/// A late reset of a stream this side has closed itself completes that close and is not
/// answered with a second reset (RFC 8831 6.7; `d24c0aac`).
#[test]
fn a_late_reset_of_a_stream_this_side_closed_is_not_answered_again() -> Result<()> {
    let mut a = timed_test_association();
    let now = Instant::now();
    let base = a.peer_last_tsn;
    a.handle_data(&ordered(base.wrapping_add(1), 1, 0, b"first"))?;
    assert_eq!(vec![Bytes::from_static(b"first")], read_all(&mut a, 1));
    a.stream(1)?.close(now)?;
    let _ = a.gather_outbound(now);

    let reply = a.handle_reconfig(&reset_request_chunk(50, base.wrapping_add(2), vec![1]))?;
    assert_eq!(vec![(50, 6)], responses(&reply));
    let reply = a.handle_data(&ordered(base.wrapping_add(2), 2, 0, b"other stream"))?;
    assert_eq!(vec![(50, 1)], responses(&reply));
    assert!(own_resets(&mut a, reply, now).is_empty());
    assert!(!a.streams.contains_key(&1));
    Ok(())
}

/// RFC 6525 5.2.3: an Incoming SSN Reset Request asks this side to reset its *outgoing*
/// stream. The peer's direction stays as it was: what it sent before is read, and so is what
/// it sends after, until it resets its own direction. The stream used to stop being readable
/// at once (its `RecvSendState` lost the Readable bit, which also stood for "this side reset
/// its direction"), and what it held was dropped with it when the peer's reset came.
#[test]
fn an_incoming_reset_request_leaves_the_peers_direction_readable() -> Result<()> {
    let mut a = timed_test_association();
    let now = Instant::now();
    a.peer_rsn_window = Some((300, 300));
    let base = a.peer_last_tsn;
    a.open_stream(1, PPI)?
        .write_sctp(now, &Bytes::from_static(b"sent"), PPI)?;
    let _ = a.gather_outbound(now);
    ack_everything(&mut a, now);
    a.handle_data(&ordered(base.wrapping_add(1), 1, 0, b"unread"))?;

    let reply = a.handle_reconfig(&chunk_of(ParamIncomingResetRequest {
        reconfig_request_sequence_number: 300,
        stream_identifiers: vec![1],
    }))?;
    assert_eq!(vec![vec![1u16]], own_resets(&mut a, reply, now));
    assert!(a.stream(1)?.is_readable());
    a.handle_data(&ordered(base.wrapping_add(2), 1, 1, b"after"))?;
    assert_eq!(
        vec![Bytes::from_static(b"unread"), Bytes::from_static(b"after")],
        read_all(&mut a, 1)
    );

    // The peer resets its own direction: performed, and not answered with a second reset of
    // this side's, which it reset already.
    let reply = a.handle_reconfig(&reset_request_chunk(301, base.wrapping_add(2), vec![1]))?;
    assert_eq!(vec![(301, 1)], responses(&reply));
    assert!(own_resets(&mut a, reply, now).is_empty());
    assert!(!a.streams.contains_key(&1));
    Ok(())
}

/// A message the peer sent before its reset is delivered when the reset comes while it is not
/// read yet, after an Incoming SSN Reset Request reset this side's direction: the reset waits
/// for it (RFC 6525 5.2.2, "[RFC6525] also guarantees that all the messages are delivered (or
/// abandoned) before the stream is reset", RFC 8831 6.7).
#[test]
fn a_held_message_outlives_an_incoming_reset_request_and_the_peers_reset() -> Result<()> {
    let mut a = timed_test_association();
    let now = Instant::now();
    a.peer_rsn_window = Some((300, 300));
    let base = a.peer_last_tsn;
    a.open_stream(1, PPI)?
        .write_sctp(now, &Bytes::from_static(b"sent"), PPI)?;
    let _ = a.gather_outbound(now);
    ack_everything(&mut a, now);
    a.handle_data(&ordered(base.wrapping_add(1), 1, 0, b"unread"))?;
    let reply = a.handle_reconfig(&chunk_of(ParamIncomingResetRequest {
        reconfig_request_sequence_number: 300,
        stream_identifiers: vec![1],
    }))?;
    assert_eq!(vec![vec![1u16]], own_resets(&mut a, reply, now));

    let reply = a.handle_reconfig(&reset_request_chunk(301, base.wrapping_add(1), vec![1]))?;
    assert_eq!(vec![(301, 6)], responses(&reply), "waits for the message");
    assert_eq!(vec![Bytes::from_static(b"unread")], read_all(&mut a, 1));
    assert!(!a.streams.contains_key(&1), "then performed");
    Ok(())
}
