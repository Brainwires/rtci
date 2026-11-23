//! Partial delivery (RFC 9260 section 6.9; RFC 6458 sections 3.1.4, 6.1.7 and 8.1.21): a
//! message whose start the receiver holds is given to the application in parts, through
//! `Stream::read_part`, before it is complete, so the receive buffer it would fill is free
//! again.

use super::*;
use crate::chunk::chunk_i_forward_tsn::ChunkIForwardTsnStream;
use crate::{MessagePart, TransportConfig};

const BUFFER: u32 = 16 * 1024;
const POINT: u32 = 4096;
const FRAGMENT: usize = 1024;

/// An established association with a 16 KiB receive buffer, a partial delivery point of
/// 4 KiB, and the streams given.
fn receiver(config: TransportConfig, interleaving: bool, streams: &[u16]) -> Association {
    let mut a = create_association(config);
    a.set_state(AssociationState::Established);
    a.set_interleaving(interleaving);
    a.use_forward_tsn = true;
    for &id in streams {
        assert!(
            a.create_stream(id, true, PayloadProtocolIdentifier::Binary)
                .is_some()
        );
    }
    a
}

fn config() -> TransportConfig {
    TransportConfig::default()
        .with_max_receive_buffer_size(BUFFER)
        .with_max_receive_message_size(1024 * 1024)
        .with_partial_delivery_point(POINT)
}

/// The bytes of fragment `index` of a message: they say which fragment they are.
fn fragment_bytes(index: u32) -> Bytes {
    Bytes::from(vec![index as u8; FRAGMENT])
}

/// Fragment `index` of a DATA message of `count` fragments on stream `stream`.
fn data(
    tsn: u32,
    stream: u16,
    ssn: u16,
    unordered: bool,
    index: u32,
    count: u32,
) -> ChunkPayloadData {
    ChunkPayloadData {
        tsn,
        stream_identifier: stream,
        stream_sequence_number: ssn,
        unordered,
        beginning_fragment: index == 0,
        ending_fragment: index + 1 == count,
        payload_type: PayloadProtocolIdentifier::Binary,
        user_data: fragment_bytes(index),
        ..Default::default()
    }
}

/// Fragment `fsn` of an I-DATA message of `count` fragments.
fn i_data(
    tsn: u32,
    stream: u16,
    mid: u32,
    unordered: bool,
    fsn: u32,
    count: u32,
) -> ChunkPayloadData {
    ChunkPayloadData {
        i_data: true,
        tsn,
        stream_identifier: stream,
        mid,
        fsn,
        unordered,
        beginning_fragment: fsn == 0,
        ending_fragment: fsn + 1 == count,
        payload_type: PayloadProtocolIdentifier::Binary,
        user_data: fragment_bytes(fsn),
        ..Default::default()
    }
}

fn part(a: &mut Association, stream: u16) -> Option<MessagePart> {
    a.stream(stream).expect("stream").read_part().expect("read")
}

fn bytes_of(part: &MessagePart) -> Vec<u8> {
    part.chunks
        .chunks
        .iter()
        .flat_map(|c| c.user_data.iter().copied())
        .collect()
}

/// The fragments `range` of a message, as the bytes `fragment_bytes` gives them.
fn expected(range: std::ops::Range<u32>) -> Vec<u8> {
    range.flat_map(|i| fragment_bytes(i).to_vec()).collect()
}

fn readable_events(a: &mut Association) -> Vec<StreamId> {
    let mut ids = vec![];
    while let Some(e) = a.poll() {
        if let Event::Stream(StreamEvent::Readable { id }) = e {
            ids.push(id);
        }
    }
    ids
}

fn aborts(a: &mut Association) -> Vec<(StreamId, bool, u32)> {
    let mut found = vec![];
    while let Some(e) = a.poll() {
        if let Event::Stream(StreamEvent::PartialDeliveryAborted {
            id,
            unordered,
            sequence,
        }) = e
        {
            found.push((id, unordered, sequence));
        }
    }
    found
}

/// RFC 9260 6.9 and RFC 6458 8.1.21: once the fragments held of a message from its first on
/// come to the partial delivery point, they are read as its first part (no end of record) and
/// leave the receive buffer at once (RFC 9260 6.2 C: the window grows by what is delivered).
/// From then on each fragment that continues the message without a gap is read as it
/// arrives; one after a gap waits for the gap. The last part has the end of record, and the
/// parts together are the message.
#[test]
fn a_message_whose_start_reaches_the_partial_delivery_point_is_read_in_parts() -> Result<()> {
    let mut a = receiver(config(), false, &[0]);
    let first = a.peer_last_tsn.wrapping_add(1);
    let tsn = |i: u32| first.wrapping_add(i);
    for i in 0..3 {
        a.handle_data(&data(tsn(i), 0, 0, false, i, 8))?;
    }
    assert!(part(&mut a, 0).is_none(), "3 KiB is below the point");
    let _ = readable_events(&mut a);
    a.handle_data(&data(tsn(3), 0, 0, false, 3, 8))?;
    assert_eq!(readable_events(&mut a), vec![0], "announced at the point");
    assert_eq!(a.get_my_receiver_window_credit(), BUFFER - POINT);
    let p = part(&mut a, 0).expect("the first part");
    assert!(p.first && !p.end_of_record);
    assert_eq!(bytes_of(&p), expected(0..4));
    assert_eq!(
        a.get_my_receiver_window_credit(),
        BUFFER,
        "what was read left the buffer"
    );
    assert!(a.stream(0)?.in_partial_delivery());

    a.handle_data(&data(tsn(4), 0, 0, false, 4, 8))?;
    let p = part(&mut a, 0).expect("the next fragment at once");
    assert!(!p.first && !p.end_of_record);
    assert_eq!(bytes_of(&p), expected(4..5));

    a.handle_data(&data(tsn(6), 0, 0, false, 6, 8))?;
    assert!(part(&mut a, 0).is_none(), "fragment 5 is missing");
    a.handle_data(&data(tsn(5), 0, 0, false, 5, 8))?;
    assert_eq!(bytes_of(&part(&mut a, 0).expect("5 and 6")), expected(5..7));
    a.handle_data(&data(tsn(7), 0, 0, false, 7, 8))?;
    let p = part(&mut a, 0).expect("the last part");
    assert!(p.end_of_record && !p.first);
    assert_eq!(bytes_of(&p), expected(7..8));
    assert!(!a.stream(0)?.in_partial_delivery());
    assert!(part(&mut a, 0).is_none());
    assert_eq!(a.bytes_in_reassembly_queues(), 0);
    Ok(())
}

/// RFC 6458 8.1.21: "any single message having a length smaller than or equal to the SCTP
/// partial delivery point will be delivered in a single read call": a 4 KiB message is read
/// whole, one part with the end of record, by `read_part` as by `read_sctp`, and nothing of it
/// before it is complete.
#[test]
fn a_message_no_larger_than_the_partial_delivery_point_is_read_whole() -> Result<()> {
    for by_parts in [true, false] {
        let mut a = receiver(config(), false, &[0]);
        let first = a.peer_last_tsn.wrapping_add(1);
        for i in 0..3 {
            a.handle_data(&data(first.wrapping_add(i), 0, 0, false, i, 4))?;
        }
        assert!(part(&mut a, 0).is_none());
        assert!(a.stream(0)?.read_sctp()?.is_none());
        a.handle_data(&data(first.wrapping_add(3), 0, 0, false, 3, 4))?;
        if by_parts {
            let p = part(&mut a, 0).expect("the message");
            assert!(p.first && p.end_of_record);
            assert_eq!(bytes_of(&p), expected(0..4));
        } else {
            let whole = a.stream(0)?.read_sctp()?.expect("the message");
            assert_eq!(whole.len(), 4 * FRAGMENT);
        }
        assert_eq!(a.bytes_in_reassembly_queues(), 0);
    }
    Ok(())
}

/// RFC 9260 6.9: "If the data receiver runs out of buffer space while still waiting for more
/// fragments to complete the reassembly of the message, it SHOULD dispatch part of its
/// inbound message through a partial delivery API". Interleaved messages (RFC 8260) on four
/// streams fill the buffer with a quarter each, below the partial delivery point: until the
/// window would be advertised closed nothing is given out, and then every stream is announced
/// and gives its message's first part, whatever its size, and the buffer is empty again.
#[test]
fn a_receive_buffer_out_of_space_dispatches_messages_below_the_point() -> Result<()> {
    let mut a = receiver(
        config()
            .with_message_interleaving(true)
            .with_partial_delivery_point(BUFFER),
        true,
        &[0, 1, 2, 3],
    );
    let mut tsn = a.peer_last_tsn.wrapping_add(1);
    let mut fsn = [0u32; 4];
    let mut stream = 0usize;
    while a.partial_delivery_threshold() > 1 {
        assert!(readable_events(&mut a).is_empty(), "nothing before");
        a.handle_data(&i_data(tsn, stream as u16, 0, false, fsn[stream], 64))?;
        fsn[stream] += 1;
        stream = (stream + 1) % 4;
        tsn = tsn.wrapping_add(1);
    }
    let mut announced = readable_events(&mut a);
    announced.sort_unstable();
    let holding: Vec<u16> = (0..4u16).filter(|s| fsn[usize::from(*s)] > 0).collect();
    assert_eq!(announced, holding, "every stream holding a message start");
    // The first one read frees its share of the buffer: the window opens, and the others,
    // below the point again, wait for more of their message.
    let s = holding[0];
    let p = part(&mut a, s).expect("a first part");
    assert!(p.first && !p.end_of_record);
    assert_eq!(bytes_of(&p), expected(0..fsn[usize::from(s)]));
    assert!(a.partial_delivery_threshold() > 1, "space again");
    assert!(a.advertised_window() > 0, "the window is open again");
    Ok(())
}

/// RFC 6458 3.1.4: "Only one message at a time can be partially delivered in any stream";
/// 8.1.20: "no other messages would be delivered for association "X" stream "Y" until all of
/// stream "Y"'s partially delivered message was read". While the ordered message 0 is in
/// partial delivery, message 1 and an unordered message of the same stream are complete but
/// neither `read_part` nor `read_sctp` gives them; once message 0's last part is read, they
/// are.
#[test]
fn no_other_message_of_a_stream_is_read_while_one_is_in_partial_delivery() -> Result<()> {
    let mut a = receiver(config(), false, &[0]);
    let first = a.peer_last_tsn.wrapping_add(1);
    let tsn = |i: u32| first.wrapping_add(i);
    for i in 0..5 {
        a.handle_data(&data(tsn(i), 0, 0, false, i, 8))?;
    }
    assert!(part(&mut a, 0).expect("first part").first);
    // Fragments 5 to 7 are late; message 1 and an unordered message arrive after them.
    a.handle_data(&data(tsn(8), 0, 1, false, 0, 1))?;
    a.handle_data(&data(tsn(9), 0, 0, true, 0, 1))?;
    assert!(part(&mut a, 0).is_none(), "message 0 waits for fragment 5");
    assert!(
        a.stream(0)?.read_sctp()?.is_none(),
        "nor are the others read"
    );
    for i in 5..8 {
        a.handle_data(&data(tsn(i), 0, 0, false, i, 8))?;
    }
    let p = part(&mut a, 0).expect("the rest of message 0");
    assert!(p.end_of_record);
    assert_eq!(bytes_of(&p), expected(5..8));
    let mut whole = vec![];
    while let Some(p) = part(&mut a, 0) {
        assert!(p.first && p.end_of_record);
        whole.push((p.unordered, p.chunks.ssn));
    }
    whole.sort_unstable();
    assert_eq!(whole, vec![(false, 1), (true, 0)]);
    Ok(())
}

/// Ordered delivery (RFC 9260 6.6) holds for parts: an ordered message after one that has not
/// all arrived is not given out in parts, however much of it is held, until the one before it
/// has been read.
#[test]
fn an_ordered_message_is_delivered_in_parts_only_when_it_is_due() -> Result<()> {
    let mut a = receiver(config(), false, &[0]);
    let first = a.peer_last_tsn.wrapping_add(1);
    for i in 0..6 {
        a.handle_data(&data(first.wrapping_add(1 + i), 0, 1, false, i, 8))?;
    }
    assert!(part(&mut a, 0).is_none(), "message 0 is missing");
    a.handle_data(&data(first, 0, 0, false, 0, 1))?;
    let p = part(&mut a, 0).expect("message 0");
    assert_eq!((p.chunks.ssn, p.end_of_record), (0, true));
    let p = part(&mut a, 0).expect("message 1 in parts");
    assert_eq!((p.chunks.ssn, p.first, p.end_of_record), (1, true, false));
    assert_eq!(bytes_of(&p), expected(0..6));
    Ok(())
}

/// RFC 8260 section 4.3.1: with user message interleaving the application takes "the
/// interleaving of user messages from different streams" (RFC 6458 fragment interleave level
/// 2), so each stream has a message of its own in partial delivery at the same time, and the
/// parts of each come in order.
#[test]
fn interleaved_streams_each_deliver_a_message_in_parts_at_once() -> Result<()> {
    let mut a = receiver(config().with_message_interleaving(true), true, &[1, 2]);
    let mut tsn = a.peer_last_tsn.wrapping_add(1);
    let mut got: [Vec<u8>; 2] = [vec![], vec![]];
    for fsn in 0..8u32 {
        for (i, s) in [1u16, 2].into_iter().enumerate() {
            a.handle_data(&i_data(tsn, s, 0, i == 1, fsn, 8))?;
            tsn = tsn.wrapping_add(1);
            if fsn >= 3 {
                let p = part(&mut a, s).expect("a part");
                assert_eq!(p.first, fsn == 3);
                assert_eq!(p.end_of_record, fsn == 7);
                assert_eq!(p.unordered, i == 1);
                got[i].extend(bytes_of(&p));
            }
        }
        if fsn >= 3 && fsn < 7 {
            assert!(a.stream(1)?.in_partial_delivery() && a.stream(2)?.in_partial_delivery());
        }
    }
    assert_eq!(got[0], expected(0..8));
    assert_eq!(got[1], expected(0..8));
    Ok(())
}

/// RFC 3758 3.6 with RFC 6458 6.1.7 (`SCTP_PARTIAL_DELIVERY_ABORTED`: "the user message gets
/// abandoned using PR-SCTP while the partial delivery of this message is going on"). A
/// FORWARD TSN skips the rest of the ordered message in partial delivery: the abort is
/// reported with the stream and the message's Stream Sequence Number, nothing more of it is
/// read, what was held of it leaves the buffer, and the next message of the stream is read.
/// Unordered: the FORWARD TSN names no stream, its new cumulative TSN passes the fragment the
/// message needs next.
#[test]
fn a_forward_tsn_that_skips_a_message_in_partial_delivery_aborts_it() -> Result<()> {
    for unordered in [false, true] {
        let mut a = receiver(config(), false, &[0]);
        let first = a.peer_last_tsn.wrapping_add(1);
        let tsn = |i: u32| first.wrapping_add(i);
        for i in 0..5 {
            a.handle_data(&data(tsn(i), 0, 0, unordered, i, 8))?;
        }
        assert!(part(&mut a, 0).expect("first part").first);
        a.handle_data(&data(tsn(6), 0, 0, unordered, 6, 8))?;
        let _ = aborts(&mut a);
        a.handle_forward_tsn(&ChunkForwardTsn {
            new_cumulative_tsn: tsn(7),
            streams: if unordered {
                vec![]
            } else {
                vec![ChunkForwardTsnStream {
                    identifier: 0,
                    sequence: 0,
                }]
            },
        })?;
        assert_eq!(aborts(&mut a), vec![(0, unordered, 0)], "{unordered}");
        assert!(!a.stream(0)?.in_partial_delivery());
        assert!(part(&mut a, 0).is_none());
        assert_eq!(a.bytes_in_reassembly_queues(), 0);
        a.handle_data(&data(tsn(8), 0, 1, unordered, 0, 1))?;
        let p = part(&mut a, 0).expect("the next message");
        assert!(p.first && p.end_of_record);
    }
    Ok(())
}

/// RFC 8260 2.3.1 with RFC 6458 6.1.7: an I-FORWARD-TSN entry for the ordered or the
/// unordered message in partial delivery (its stream, U bit and Message Identifier) aborts it,
/// reported with its Message Identifier. An entry for the other kind of message of the stream
/// does not.
#[test]
fn an_i_forward_tsn_that_skips_a_message_in_partial_delivery_aborts_it() -> Result<()> {
    for unordered in [false, true] {
        let mut a = receiver(config().with_message_interleaving(true), true, &[3]);
        let first = a.peer_last_tsn.wrapping_add(1);
        for fsn in 0..5 {
            a.handle_data(&i_data(first.wrapping_add(fsn), 3, 0, unordered, fsn, 8))?;
        }
        assert!(part(&mut a, 3).expect("first part").first);
        let _ = aborts(&mut a);
        a.handle_i_forward_tsn(&ChunkIForwardTsn {
            new_cumulative_tsn: first.wrapping_add(5),
            streams: vec![ChunkIForwardTsnStream {
                identifier: 3,
                unordered: !unordered,
                mid: 0,
            }],
        })?;
        assert!(aborts(&mut a).is_empty(), "the other kind's entry");
        assert!(a.stream(3)?.in_partial_delivery());
        a.handle_i_forward_tsn(&ChunkIForwardTsn {
            new_cumulative_tsn: first.wrapping_add(7),
            streams: vec![ChunkIForwardTsnStream {
                identifier: 3,
                unordered,
                mid: 0,
            }],
        })?;
        assert_eq!(aborts(&mut a), vec![(3, unordered, 0)]);
        assert!(!a.stream(3)?.in_partial_delivery());
        assert_eq!(a.bytes_in_reassembly_queues(), 0);
    }
    Ok(())
}

/// A FORWARD TSN whose entry reaches the message in partial delivery when every fragment of
/// it has arrived (the entry is for a later message of the stream, RFC 3758 3.6) aborts
/// nothing: the rest of the message is read, with the end of record.
#[test]
fn a_forward_tsn_does_not_abort_a_message_whose_rest_has_arrived() -> Result<()> {
    let mut a = receiver(config(), false, &[0]);
    let first = a.peer_last_tsn.wrapping_add(1);
    for i in 0..5 {
        a.handle_data(&data(first.wrapping_add(i), 0, 0, false, i, 8))?;
    }
    assert!(part(&mut a, 0).is_some());
    for i in 5..8 {
        a.handle_data(&data(first.wrapping_add(i), 0, 0, false, i, 8))?;
    }
    let _ = aborts(&mut a);
    a.handle_forward_tsn(&ChunkForwardTsn {
        new_cumulative_tsn: first.wrapping_add(9),
        streams: vec![ChunkForwardTsnStream {
            identifier: 0,
            sequence: 1,
        }],
    })?;
    assert!(aborts(&mut a).is_empty());
    let p = part(&mut a, 0).expect("the rest");
    assert!(p.end_of_record);
    assert_eq!(bytes_of(&p), expected(5..8));
    Ok(())
}

/// RFC 3758 with RFC 9260 6.9 over a link: a partially reliable stream (no retransmission,
/// RFC 3758 `max_retransmits` 0) sends three 64 KiB messages to a receiver with a 16 KiB
/// buffer that reads in parts. One DATA packet of the first message is lost once it is in
/// partial delivery: the sender abandons the message and its FORWARD TSN reaches the
/// receiver, which reports the abort for that message (RFC 6458 6.1.7), puts nothing of it
/// together, and gets the two messages after it whole.
#[test]
fn a_message_abandoned_while_it_is_read_in_parts_is_reported_and_the_next_ones_arrive() -> Result<()>
{
    use crate::endpoint::link_test::{Link, first_chunk_type};
    const SIZE: usize = 64 * 1024;
    let mut link = Link::new(
        TransportConfig::default().with_max_message_size(SIZE as u32),
        TransportConfig::default()
            .with_max_receive_buffer_size(BUFFER)
            .with_max_receive_message_size(SIZE as u32),
        11,
    );
    let mut data_packets = 0;
    link.filter = Some(Box::new(move |from_client, datagram| {
        if from_client && first_chunk_type(datagram) == Some(0) {
            data_packets += 1;
            return data_packets == 20;
        }
        false
    }));
    link.connect();
    let start = link.now;
    let ppi = PayloadProtocolIdentifier::Binary;
    let messages: Vec<Bytes> = (0..3u8).map(|i| Bytes::from(vec![i + 1; SIZE])).collect();
    {
        let mut stream = link.client.conn().open_stream(1, ppi)?;
        stream.set_reliability_params(false, ReliabilityType::Rexmit, 0)?;
        for m in &messages {
            stream.write_sctp(start, m, ppi)?;
        }
    }
    let arrived = link.run_until(start + Duration::from_secs(60), |l| {
        l.server.received.len() == 2
    });
    assert!(arrived, "{} messages arrived", link.server.received.len());
    let aborted: Vec<(StreamId, bool, u32)> = link
        .server
        .events
        .iter()
        .filter_map(|e| match e {
            Event::Stream(StreamEvent::PartialDeliveryAborted {
                id,
                unordered,
                sequence,
            }) => Some((*id, *unordered, *sequence)),
            _ => None,
        })
        .collect();
    assert_eq!(aborted, vec![(1, false, 0)], "message 0 aborted");
    assert!(link.server.parts_before_end > 0);
    let got: Vec<&Bytes> = link.server.received.iter().map(|(_, m)| m).collect();
    assert_eq!(got, vec![&messages[1], &messages[2]]);
    Ok(())
}
