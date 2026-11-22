//! RFC 8260: user message interleaving (I-DATA, I-FORWARD-TSN) and the stream schedulers as
//! an association uses them. The schedulers' ordering rules are tested with the queue they
//! live in (`queue/pending_queue.rs`).

use super::robustness_test::*;
use super::*;
use crate::StreamScheduler;
use crate::chunk::chunk_i_forward_tsn::ChunkIForwardTsnStream;
use crate::chunk::chunk_type::*;
use crate::config::INITIAL_MTU;
use crate::endpoint::link_test::Link;
use crate::queue::reassembly_queue::ReassemblyQueue;
use std::cell::RefCell;
use std::rc::Rc;

const PPI: PayloadProtocolIdentifier = PayloadProtocolIdentifier::Binary;

fn interleaving() -> TransportConfig {
    TransportConfig::default().with_message_interleaving(true)
}

/// Every chunk each side puts on the link: (from the client, the chunk as on the wire).
type Capture = Rc<RefCell<Vec<(bool, Vec<u8>)>>>;

fn capture(link: &mut Link) -> Capture {
    let seen: Capture = Rc::default();
    let record = seen.clone();
    link.filter = Some(Box::new(move |from_client, datagram: &Bytes| {
        assert!(
            datagram.len() <= INITIAL_MTU as usize,
            "a packet of {} bytes",
            datagram.len()
        );
        for chunk in chunks_of(datagram) {
            record.borrow_mut().push((from_client, chunk));
        }
        false
    }));
    seen
}

/// An I-DATA chunk as the wire has it.
struct IData {
    flags: u8,
    tsn: u32,
    stream: u16,
    mid: u32,
    ppid_or_fsn: u32,
    len: usize,
}

fn u32_at(bytes: &[u8], offset: usize) -> u32 {
    u32::from_be_bytes(bytes[offset..offset + 4].try_into().unwrap())
}

fn i_data_chunks(seen: &Capture, from_client: bool) -> Vec<IData> {
    seen.borrow()
        .iter()
        .filter(|(client, chunk)| *client == from_client && chunk[0] == CT_I_DATA.0)
        .map(|(_, c)| IData {
            flags: c[1],
            tsn: u32_at(c, 4),
            stream: u16::from_be_bytes([c[8], c[9]]),
            mid: u32_at(c, 12),
            ppid_or_fsn: u32_at(c, 16),
            len: c.len() - 20,
        })
        .collect()
}

fn count_of(seen: &Capture, typ: ChunkType) -> usize {
    seen.borrow().iter().filter(|(_, c)| c[0] == typ.0).count()
}

fn i_data(
    tsn: u32,
    stream: u16,
    mid: u32,
    fsn: u32,
    flags: (bool, bool, bool),
) -> ChunkPayloadData {
    let (unordered, beginning_fragment, ending_fragment) = flags;
    ChunkPayloadData {
        i_data: true,
        tsn,
        stream_identifier: stream,
        mid,
        fsn,
        unordered,
        beginning_fragment,
        ending_fragment,
        payload_type: PPI,
        user_data: Bytes::from(vec![fsn as u8 + 1; 10]),
        ..Default::default()
    }
}

fn interleaved_association() -> Association {
    let mut a = timed_test_association();
    a.set_interleaving(true);
    a
}

fn message_bytes(chunks: &crate::Chunks) -> Vec<u8> {
    let mut buf = vec![0u8; chunks.len()];
    let n = chunks.read(&mut buf).unwrap();
    buf.truncate(n);
    buf
}

// ---- wire formats -------------------------------------------------------------------------

/// RFC 8260 2.1: the I-DATA chunk. Type 64, a 20-byte header; the first fragment carries the
/// PPID, the others the Fragment Sequence Number in its place. The four Res flag bits and the
/// Reserved field are sent as 0 and ignored when received.
#[test]
fn the_i_data_chunk_is_encoded_and_decoded() -> Result<()> {
    let first = ChunkPayloadData {
        i_data: true,
        tsn: 0x0a0b_0c0d,
        stream_identifier: 5,
        mid: 0x0102_0304,
        unordered: true,
        beginning_fragment: true,
        immediate_sack: true,
        payload_type: PPI,
        user_data: Bytes::from_static(b"abc"),
        ..Default::default()
    };
    let raw = first.marshal()?;
    assert_eq!(
        &[
            64, 0x0e, 0, 23, 0x0a, 0x0b, 0x0c, 0x0d, 0, 5, 0, 0, 1, 2, 3, 4, 0, 0, 0, 53, b'a',
            b'b', b'c'
        ][..],
        &raw[..]
    );
    assert_eq!(20, first.header_size());
    assert_eq!(24, first.wire_size());

    // Reserved bits set by the sender are ignored.
    let mut received = raw.to_vec();
    received[1] |= 0xf0;
    received[10] = 0xff;
    received[11] = 0xff;
    let parsed = ChunkPayloadData::unmarshal(&Bytes::from(received))?;
    assert!(parsed.i_data && parsed.unordered && parsed.beginning_fragment);
    assert!(parsed.immediate_sack && !parsed.ending_fragment);
    assert_eq!(
        (0x0a0b_0c0d, 5, 0x0102_0304, 0, 53),
        (
            parsed.tsn,
            parsed.stream_identifier,
            parsed.mid,
            parsed.fsn,
            parsed.ppid()
        )
    );
    assert_eq!(&b"abc"[..], &parsed.user_data[..]);

    // A later fragment: the field holds the FSN.
    let last = ChunkPayloadData {
        beginning_fragment: false,
        ending_fragment: true,
        immediate_sack: false,
        fsn: 7,
        ..first.clone()
    };
    let raw = last.marshal()?;
    assert_eq!(&[64, 0x05, 0, 23][..], &raw[..4]);
    assert_eq!(&[0, 0, 0, 7][..], &raw[16..20]);
    let parsed = ChunkPayloadData::unmarshal(&raw)?;
    assert_eq!(
        (7, true, false),
        (
            parsed.fsn,
            parsed.ending_fragment,
            parsed.beginning_fragment
        )
    );

    // As part of a packet, and too short to be one.
    let packet = Packet::unmarshal(&raw_packet(5000, 5000, 1, &[raw.to_vec()]))?;
    let chunk = packet.chunks[0]
        .as_any()
        .downcast_ref::<ChunkPayloadData>()
        .expect("an I-DATA chunk");
    assert!(chunk.i_data);
    assert!(
        ChunkPayloadData::unmarshal(&Bytes::from_static(&[
            64, 3, 0, 16, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0
        ]))
        .is_err()
    );
    Ok(())
}

/// RFC 8260 2.3.1: the I-FORWARD-TSN chunk. Type 194; each entry is a stream, the U bit and
/// the largest Message Identifier skipped. Flags and the 15 reserved bits are sent as 0 and
/// ignored when received.
#[test]
fn the_i_forward_tsn_chunk_is_encoded_and_decoded() -> Result<()> {
    let chunk = ChunkIForwardTsn {
        new_cumulative_tsn: 0x0102_0304,
        streams: vec![
            ChunkIForwardTsnStream {
                identifier: 3,
                unordered: true,
                mid: 9,
            },
            ChunkIForwardTsnStream {
                identifier: 4,
                unordered: false,
                mid: 0xffff_fff0,
            },
        ],
    };
    let raw = chunk.marshal()?;
    assert_eq!(
        &[
            194, 0, 0, 24, 1, 2, 3, 4, 0, 3, 0, 1, 0, 0, 0, 9, 0, 4, 0, 0, 0xff, 0xff, 0xff, 0xf0
        ][..],
        &raw[..]
    );
    let mut received = raw.to_vec();
    received[1] = 0xff;
    received[10] = 0xff;
    received[11] = 0xff;
    received[18] = 0xff;
    received[19] = 0xfe;
    assert_eq!(chunk, ChunkIForwardTsn::unmarshal(&Bytes::from(received))?);
    // Half an entry is not a chunk.
    assert!(ChunkIForwardTsn::unmarshal(&raw.slice(..20)).is_err());
    let packet = Packet::unmarshal(&raw_packet(5000, 5000, 1, &[raw.to_vec()]))?;
    assert!(packet.chunks[0].as_any().is::<ChunkIForwardTsn>());
    Ok(())
}

// ---- reassembly ---------------------------------------------------------------------------

/// RFC 8260 2.2.3: a message is put together by stream, U bit, Message Identifier and
/// Fragment Sequence Number. The TSNs say nothing: fragments arrive in any TSN order and with
/// the TSNs of other messages between them.
#[test]
fn i_data_is_reassembled_by_message_identifier_and_fragment_number() {
    let mut q = ReassemblyQueue::new(1);
    q.interleaved = true;

    // Ordered message 1 is complete before message 0: it waits.
    assert!(q.push(i_data(40, 1, 1, 0, (false, true, true))));
    assert!(!q.is_readable());
    // Message 0: its last fragment first, with TSNs that are neither in order nor adjacent.
    assert!(!q.push(i_data(90, 1, 0, 2, (false, false, true))));
    assert!(!q.push(i_data(7, 1, 0, 0, (false, true, false))));
    // A repeated fragment is not taken twice.
    assert!(!q.push(i_data(8, 1, 0, 0, (false, true, false))));
    assert_eq!(30, q.get_num_bytes());
    assert!(!q.is_readable());
    assert!(q.push(i_data(55, 1, 0, 1, (false, false, false))));
    assert!(q.is_readable());

    let first = q.read().unwrap();
    assert_eq!(0, first.mid);
    assert_eq!(PPI, first.ppi);
    let mut expected = vec![1u8; 10];
    expected.extend_from_slice(&[2; 10]);
    expected.extend_from_slice(&[3; 10]);
    assert_eq!(expected, message_bytes(&first), "in fragment order");
    assert_eq!(1, q.read().unwrap().mid);
    assert!(q.read().is_none());
    assert_eq!(0, q.get_num_bytes());

    // Unordered messages have Message Identifiers of their own and are delivered as they
    // complete; two of them interleave their fragments.
    assert!(!q.push(i_data(100, 1, 0, 0, (true, true, false))));
    assert!(!q.push(i_data(101, 1, 1, 0, (true, true, false))));
    assert!(q.push(i_data(102, 1, 1, 1, (true, false, true))));
    assert_eq!(1, q.read().unwrap().mid);
    assert!(q.push(i_data(103, 1, 0, 1, (true, false, true))));
    assert_eq!(0, q.read().unwrap().mid);
    // An old ordered Message Identifier is not taken again.
    assert!(!q.push(i_data(104, 1, 1, 0, (false, true, true))));
    assert!(q.is_empty());
}

/// RFC 8260 2.3.1: an I-FORWARD-TSN entry names the largest Message Identifier skipped on a
/// stream, for ordered or for unordered messages.
#[test]
fn an_i_forward_tsn_entry_skips_messages_by_identifier() -> Result<()> {
    let mut a = interleaved_association();
    let base = a.peer_last_tsn;
    let tsn = |n: u32| base.wrapping_add(n);
    // Stream 1, ordered: message 0 misses its middle (TSN 2), message 1 is complete.
    a.handle_data(&i_data(tsn(1), 1, 0, 0, (false, true, false)))?;
    a.handle_data(&i_data(tsn(3), 1, 0, 2, (false, false, true)))?;
    a.handle_data(&i_data(tsn(4), 1, 1, 0, (false, true, true)))?;
    // Stream 1, unordered: message 5 misses its end (TSN 6).
    a.handle_data(&i_data(tsn(5), 1, 5, 0, (true, true, false)))?;
    // Stream 2, ordered: message 0 misses its end (TSN 8); it is not skipped.
    a.handle_data(&i_data(tsn(7), 2, 0, 0, (false, true, false)))?;
    assert!(read_all(&mut a, 1).is_empty());
    assert_eq!(50, a.bytes_in_reassembly_queues());

    a.handle_i_forward_tsn(&ChunkIForwardTsn {
        new_cumulative_tsn: tsn(6),
        streams: vec![
            ChunkIForwardTsnStream {
                identifier: 1,
                unordered: false,
                mid: 0,
            },
            ChunkIForwardTsnStream {
                identifier: 1,
                unordered: true,
                mid: 5,
            },
        ],
    })?;
    assert_eq!(tsn(7), a.peer_last_tsn, "TSN 7 was received");
    assert_eq!(1, read_all(&mut a, 1).len(), "message 1 is delivered");
    assert_eq!(1, a.streams[&1].reassembly_queue.next_mid.wrapping_sub(1));
    assert_eq!(
        10,
        a.bytes_in_reassembly_queues(),
        "the fragments of the skipped messages are gone, stream 2's is kept"
    );
    a.handle_data(&i_data(tsn(8), 2, 0, 1, (false, false, true)))?;
    assert_eq!(1, read_all(&mut a, 2).len());

    // One that is behind the cumulative TSN changes nothing and is answered with a SACK.
    a.handle_i_forward_tsn(&ChunkIForwardTsn {
        new_cumulative_tsn: tsn(2),
        streams: vec![],
    })?;
    assert_eq!(tsn(8), a.peer_last_tsn);
    assert_eq!(AckState::Immediate, a.ack_state);
    Ok(())
}

// ---- negotiation --------------------------------------------------------------------------

/// The chunk types each side's INIT or INIT ACK lists in Supported Extensions.
fn announced(seen: &Capture) -> (Vec<u8>, Vec<u8>) {
    let of = |typ: ChunkType| -> Vec<u8> {
        seen.borrow()
            .iter()
            .filter(|(_, c)| c[0] == typ.0)
            .flat_map(|(_, c)| tlvs(&c[20..]))
            .filter(|(t, _)| *t == 0x8008)
            .flat_map(|(_, value)| value)
            .collect()
    };
    (of(CT_INIT), of(CT_INIT_ACK))
}

/// RFC 8260 2.2.1, 2.3.1: user message interleaving is used when both sides list the I-DATA
/// chunk, PR-SCTP with it when both list I-FORWARD-TSN too. By default neither is listed.
#[test]
fn interleaving_is_negotiated_by_the_supported_extensions() {
    let both = |seen: &Capture, typ: ChunkType| {
        let (init, init_ack) = announced(seen);
        (init.contains(&typ.0), init_ack.contains(&typ.0))
    };

    // The default: not announced, DATA and FORWARD TSN as ever.
    let mut link = Link::new(TransportConfig::default(), TransportConfig::default(), 801);
    let seen = capture(&mut link);
    link.connect();
    assert_eq!((false, false), both(&seen, CT_I_DATA));
    assert_eq!((false, false), both(&seen, CT_I_FORWARD_TSN));
    assert!(!link.client.conn().message_interleaving());
    assert!(link.client.conn().partial_reliability());

    // Both sides.
    let mut link = Link::new(interleaving(), interleaving(), 802);
    let seen = capture(&mut link);
    link.connect();
    assert_eq!((true, true), both(&seen, CT_I_DATA));
    assert_eq!((true, true), both(&seen, CT_I_FORWARD_TSN));
    for peer in [&mut link.client, &mut link.server] {
        assert!(peer.conn().message_interleaving());
        assert!(peer.conn().partial_reliability());
    }

    // One side only, either way round: DATA is used.
    for (n, (client, server)) in [
        (interleaving(), TransportConfig::default()),
        (TransportConfig::default(), interleaving()),
    ]
    .into_iter()
    .enumerate()
    {
        let mut link = Link::new(client, server, 803 + n as u64);
        let seen = capture(&mut link);
        link.connect();
        let now = link.now;
        link.client
            .conn()
            .open_stream(1, PPI)
            .unwrap()
            .write_sctp(now, &Bytes::from(vec![7; 5000]), PPI)
            .unwrap();
        link.run_for(Duration::from_secs(5));
        assert_eq!(1, link.server.received.len());
        assert!(!link.client.conn().message_interleaving());
        assert!(!link.server.conn().message_interleaving());
        assert!(link.client.conn().partial_reliability());
        assert_eq!(0, count_of(&seen, CT_I_DATA));
        assert!(count_of(&seen, CT_PAYLOAD_DATA) >= 5);
    }

    // Interleaving on both sides, PR-SCTP on one: I-FORWARD-TSN is not listed by the side
    // without, and partial reliability is not used.
    let mut link = Link::new(
        interleaving(),
        interleaving().with_partial_reliability(false),
        805,
    );
    let seen = capture(&mut link);
    link.connect();
    assert_eq!((true, true), both(&seen, CT_I_DATA));
    assert_eq!((true, false), both(&seen, CT_I_FORWARD_TSN));
    for peer in [&mut link.client, &mut link.server] {
        assert!(peer.conn().message_interleaving());
        assert!(!peer.conn().partial_reliability());
    }
}

// ---- sending ------------------------------------------------------------------------------

/// RFC 8260 2.2.2, 3.6 and RFC 8831 6.4: with interleaving and weighted fair queueing, small
/// messages on one stream pass through the middle of a large message on another. On the
/// wire: I-DATA only; one message of a stream at a time; the first fragment has the B bit
/// and the PPID, the last the E bit, and the fragments count from 0.
#[test]
fn small_messages_interleave_with_a_large_one() {
    let config = || interleaving().with_stream_scheduler(StreamScheduler::WeightedFairQueueing);
    let mut link = Link::new(config(), config(), 810);
    let seen = capture(&mut link);
    link.connect();
    let now = link.now;
    let large: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
    link.client
        .conn()
        .open_stream(1, PPI)
        .unwrap()
        .write_sctp(now, &Bytes::from(large.clone()), PPI)
        .unwrap();
    link.client.conn().open_stream(2, PPI).unwrap();
    // The large message is under way before the small ones are written.
    link.run_for(Duration::from_millis(100));
    assert!(link.server.received.is_empty());
    let now = link.now;
    for n in 0..5u8 {
        link.client
            .conn()
            .stream(2)
            .unwrap()
            .write_sctp(now, &Bytes::from(vec![n; 100]), PPI)
            .unwrap();
    }
    let deadline = link.now + Duration::from_secs(60);
    assert!(link.run_until(deadline, |l| l.server.received.len() == 6));

    let order: Vec<u16> = link.server.received.iter().map(|(id, _)| *id).collect();
    assert_eq!(
        vec![2, 2, 2, 2, 2, 1],
        order,
        "the small messages are not held up"
    );
    assert_eq!(large, link.server.received[5].1.to_vec());
    for n in 0..5u8 {
        assert_eq!(vec![n; 100], link.server.received[n as usize].1.to_vec());
    }

    assert_eq!(0, count_of(&seen, CT_PAYLOAD_DATA), "DATA is not used");
    let sent = i_data_chunks(&seen, true);
    let of_large: Vec<&IData> = sent.iter().filter(|c| c.stream == 1).collect();
    let of_small: Vec<&IData> = sent.iter().filter(|c| c.stream == 2).collect();
    assert!(of_large.iter().all(|c| c.mid == 0));
    assert_eq!(200_000, of_large.iter().map(|c| c.len).sum::<usize>());
    // No retransmission on this lossless link: the fragments are in order.
    assert_eq!(0x02, of_large[0].flags & 0x03, "B on the first fragment");
    assert_eq!(53, of_large[0].ppid_or_fsn, "which carries the PPID");
    for (n, c) in of_large.iter().enumerate().skip(1) {
        assert_eq!(n as u32, c.ppid_or_fsn, "the FSN counts from 0");
        let last = n + 1 == of_large.len();
        assert_eq!(if last { 0x01 } else { 0 }, c.flags & 0x03, "fragment {n}");
    }
    assert_eq!(
        vec![0, 1, 2, 3, 4],
        of_small.iter().map(|c| c.mid).collect::<Vec<_>>()
    );
    assert!(
        of_small
            .iter()
            .all(|c| c.flags & 0x03 == 0x03 && c.ppid_or_fsn == 53)
    );
    // The small messages have TSNs between those of the large message's fragments.
    let (first, last) = (of_large[0].tsn, of_large[of_large.len() - 1].tsn);
    assert!(
        of_small
            .iter()
            .all(|c| sna32gt(c.tsn, first) && sna32lt(c.tsn, last))
    );
}

/// RFC 8260 2.1: each outgoing stream counts its ordered and its unordered messages
/// separately, both from 0. 2.3.2: a stream reset sets both counters back to 0.
#[test]
fn ordered_and_unordered_messages_have_their_own_identifiers() -> Result<()> {
    let mut a = interleaved_association();
    let now = Instant::now();
    a.open_stream(3, PPI)?;
    let write = |a: &mut Association, unordered: bool| -> Result<()> {
        let mut stream = a.stream(3)?;
        stream.set_reliability_params(unordered, ReliabilityType::Reliable, 0)?;
        stream.write_sctp(now, &Bytes::from_static(b"message"), PPI)?;
        Ok(())
    };
    for unordered in [false, true, true, false, false, true] {
        write(&mut a, unordered)?;
    }
    let sent = transmitted_data(&a.gather_outbound(now).0);
    assert!(sent.iter().all(|c| c.i_data));
    assert_eq!(
        vec![
            (false, 0),
            (true, 0),
            (true, 1),
            (false, 1),
            (false, 2),
            (true, 2)
        ],
        sent.iter()
            .map(|c| (c.unordered, c.mid))
            .collect::<Vec<_>>()
    );

    a.stream(3)?.stop(now)?;
    let _ = a.gather_outbound(now);
    let rsn = *a.reconfigs.keys().next().expect("the reset is asked for");
    a.handle_reconfig(&ChunkReconfig {
        param_a: Some(Box::new(ParamReconfigResponse {
            reconfig_response_sequence_number: rsn,
            result: ReconfigResult::SuccessPerformed,
            next_tsns: None,
        })),
        param_b: None,
    })?;
    write(&mut a, false)?;
    write(&mut a, true)?;
    let sent = transmitted_data(&a.gather_outbound(now).0);
    assert_eq!(
        vec![(false, 0), (true, 0)],
        sent.iter()
            .map(|c| (c.unordered, c.mid))
            .collect::<Vec<_>>(),
        "both counters start over after the reset"
    );
    Ok(())
}

/// RFC 8260 2.2.2: the congestion window and the fragment size hold for I-DATA as for DATA:
/// a chunk with its 20-byte header fits the packet a DATA chunk with its 16 bytes fits.
#[test]
fn i_data_respects_the_window_and_the_packet_size() -> Result<()> {
    let mut a = interleaved_association();
    let now = Instant::now();
    a.cwnd = 3 * a.pmdcs;
    a.rwnd = 1 << 20;
    a.open_stream(1, PPI)?
        .write_sctp(now, &Bytes::from(vec![1; 50_000]), PPI)?;
    let packets = a.gather_outbound(now).0;
    let sent = transmitted_data(&packets);
    assert!(packets.iter().all(|p| p.len() <= a.mtu as usize));
    assert_eq!(a.fragment_size() as usize, sent[0].user_data.len());
    assert_eq!(a.max_payload_size - 4, a.fragment_size());
    let bytes: usize = sent.iter().map(|c| c.user_data.len()).sum();
    assert!(
        bytes >= a.cwnd as usize && bytes < (a.cwnd + a.pmdcs) as usize,
        "{bytes} bytes sent with a window of {}",
        a.cwnd
    );
    Ok(())
}

/// RFC 8260 2.1: an I-DATA chunk with the I bit is acknowledged without delay.
#[test]
fn an_i_data_chunk_with_the_i_bit_is_acknowledged_at_once() {
    let mut link = Link::new(interleaving(), interleaving(), 811);
    link.connect();
    let now = link.now;
    let a = link.server.conn();
    let base = a.peer_last_tsn;
    let chunk = |n: u32, immediate: bool| {
        chunk_bytes(&ChunkPayloadData {
            immediate_sack: immediate,
            ..i_data(base.wrapping_add(n), 1, n - 1, 0, (false, true, true))
        })
    };
    // The first DATA of an association is acknowledged at once whatever its flags.
    let raw = packet_to(a, &[chunk(1, false)]);
    inject(a, now, raw);
    assert_eq!(1, chunks_of_type(&sent_datagrams(a, now), CT_SACK.0).len());
    let raw = packet_to(a, &[chunk(2, false)]);
    inject(a, now, raw);
    assert!(chunks_of_type(&sent_datagrams(a, now), CT_SACK.0).is_empty());
    let raw = packet_to(a, &[chunk(3, true)]);
    inject(a, now, raw);
    assert_eq!(1, chunks_of_type(&sent_datagrams(a, now), CT_SACK.0).len());
    assert_eq!(3, read_all(a, 1).len());
}

/// RFC 8260 2.2.3, 2.3.1: a chunk of the family that was not negotiated ends the
/// association with an ABORT, "Protocol Violation". An I-DATA or I-FORWARD-TSN chunk on an
/// association without interleaving used to take its whole packet with it, unanswered.
#[test]
fn a_chunk_of_the_wrong_family_aborts_the_association() {
    let data = |a: &Association| data_chunk(a.peer_last_tsn.wrapping_add(1), 1, 0, b"data");
    let interleaved = |a: &Association| {
        chunk_bytes(&i_data(
            a.peer_last_tsn.wrapping_add(1),
            1,
            0,
            0,
            (false, true, true),
        ))
    };
    let forward = |a: &Association| {
        raw_chunk(
            CT_FORWARD_TSN.0,
            0,
            &a.peer_last_tsn.wrapping_add(1).to_be_bytes(),
        )
    };
    let i_forward = |a: &Association| {
        raw_chunk(
            CT_I_FORWARD_TSN.0,
            0,
            &a.peer_last_tsn.wrapping_add(1).to_be_bytes(),
        )
    };
    type MakeChunk = dyn Fn(&Association) -> Vec<u8>;
    let cases: [(&str, bool, &MakeChunk); 4] = [
        ("I-DATA without interleaving", false, &interleaved),
        ("DATA with interleaving", true, &data),
        ("FORWARD-TSN with interleaving", true, &forward),
        ("I-FORWARD-TSN without interleaving", false, &i_forward),
    ];
    for (n, (name, with_interleaving, chunk)) in cases.into_iter().enumerate() {
        let config = || {
            if with_interleaving {
                interleaving()
            } else {
                TransportConfig::default()
            }
        };
        let mut link = Link::new(config(), config(), 820 + n as u64);
        link.connect();
        let now = link.now;
        let a = link.server.conn();
        let raw = packet_to(a, &[chunk(a)]);
        inject(a, now, raw);
        let sent = sent_datagrams(a, now);
        let aborts = chunks_of_type(&sent, CT_ABORT.0);
        assert_eq!(1, aborts.len(), "{name}");
        let causes: Vec<u16> = tlvs(&aborts[0][4..]).into_iter().map(|(c, _)| c).collect();
        assert_eq!(vec![13], causes, "{name}: Protocol Violation");
        assert!(a.is_ended(), "{name}");
        assert!(read_all(a, 1).is_empty(), "{name}");
    }
}

// ---- partial reliability ------------------------------------------------------------------

/// RFC 8260 2.3.1: with I-DATA, abandoned messages are reported with I-FORWARD-TSN, which
/// names the largest Message Identifier skipped per stream for ordered and for unordered
/// messages; FORWARD TSN is not used.
#[test]
fn abandoned_i_data_is_reported_with_i_forward_tsn() -> Result<()> {
    let mut a = interleaved_association();
    let now = Instant::now();
    let first = a.my_next_tsn;
    for (stream, unordered) in [(1u16, false), (2, true)] {
        let mut s = a.open_stream(stream, PPI)?;
        s.set_reliability_params(unordered, ReliabilityType::Rexmit, 0)?;
        for _ in 0..3 {
            s.write_sctp(now, &Bytes::from_static(b"unreliable"), PPI)?;
        }
    }
    let sent = transmitted_data(&a.gather_outbound(now).0);
    assert_eq!(6, sent.len());

    // Nothing is acknowledged: at the T3-rtx expiry every message has used its one
    // transmission.
    let expiry = a.timers.get(Timer::T3RTX).expect("T3-rtx runs");
    a.handle_timeout(expiry);
    let out = a.gather_outbound(expiry).0;
    assert!(chunks_of_type(&out, CT_FORWARD_TSN.0).is_empty());
    let chunks = chunks_of_type(&out, CT_I_FORWARD_TSN.0);
    assert_eq!(1, chunks.len());
    let chunk = ChunkIForwardTsn::unmarshal(&Bytes::from(chunks[0].clone()))?;
    assert_eq!(first.wrapping_add(5), chunk.new_cumulative_tsn);
    assert_eq!(
        vec![
            ChunkIForwardTsnStream {
                identifier: 1,
                unordered: false,
                mid: 2
            },
            ChunkIForwardTsnStream {
                identifier: 2,
                unordered: true,
                mid: 2
            },
        ],
        chunk.streams
    );
    Ok(())
}

/// End to end over a lossy link: unreliable ordered and unordered streams with I-DATA. What
/// arrives arrives once and, on the ordered stream, in order; nothing stays in the reassembly
/// queues; a reliable message after the losses gets through.
#[test]
fn partial_reliability_works_with_interleaving_over_a_lossy_link() {
    let config = || interleaving().with_stream_scheduler(StreamScheduler::RoundRobin);
    let mut link = Link::new(config(), config(), 830);
    let seen = capture(&mut link);
    link.connect();
    link.loss_percent = 15;
    for (stream, unordered) in [(1u16, false), (2, true)] {
        link.client
            .conn()
            .open_stream(stream, PPI)
            .unwrap()
            .set_reliability_params(unordered, ReliabilityType::Rexmit, 0)
            .unwrap();
    }
    for n in 0..150u32 {
        let now = link.now;
        for stream in [1u16, 2] {
            // Every third message is large enough to be fragmented.
            let mut payload = vec![stream as u8; if n % 3 == 0 { 3000 } else { 200 }];
            payload[..4].copy_from_slice(&n.to_be_bytes());
            link.client
                .conn()
                .stream(stream)
                .unwrap()
                .write_sctp(now, &Bytes::from(payload), PPI)
                .unwrap();
        }
        link.run_for(Duration::from_millis(20));
    }
    link.run_for(Duration::from_secs(30));
    link.loss_percent = 0;
    let now = link.now;
    for stream in [1u16, 2] {
        let mut s = link.client.conn().stream(stream).unwrap();
        s.set_reliability_params(stream == 2, ReliabilityType::Reliable, 0)
            .unwrap();
        s.write_sctp(now, &Bytes::from_static(b"the last one"), PPI)
            .unwrap();
    }
    link.run_for(Duration::from_secs(30));

    assert!(
        count_of(&seen, CT_I_FORWARD_TSN) > 0,
        "messages were abandoned"
    );
    assert_eq!(0, count_of(&seen, CT_FORWARD_TSN));
    assert_eq!(0, count_of(&seen, CT_PAYLOAD_DATA));
    for stream in [1u16, 2] {
        let received: Vec<&Bytes> = link
            .server
            .received
            .iter()
            .filter(|(id, _)| *id == stream)
            .map(|(_, data)| data)
            .collect();
        assert_eq!(
            &b"the last one"[..],
            &received.last().expect("something arrived")[..],
            "stream {stream} is not stuck"
        );
        let numbers: Vec<u32> = received[..received.len() - 1]
            .iter()
            .map(|data| u32_at(data, 0))
            .collect();
        assert!(
            numbers.len() > 50 && numbers.len() < 150,
            "stream {stream}: {} of 150 arrived",
            numbers.len()
        );
        let mut sorted = numbers.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(
            numbers.len(),
            sorted.len(),
            "stream {stream}: no message twice"
        );
        if stream == 1 {
            assert_eq!(sorted, numbers, "the ordered stream delivers in order");
        }
        for data in &received[..received.len() - 1] {
            let n = u32_at(data, 0);
            assert_eq!(if n % 3 == 0 { 3000 } else { 200 }, data.len());
            assert!(data[4..].iter().all(|b| *b == stream as u8));
        }
    }
    assert_eq!(0, link.server.conn().bytes_in_reassembly_queues());
    assert_eq!(0, link.client.conn().buffered_amount());
}

// ---- the schedulers, as an association uses them -------------------------------------------

fn sender(config: TransportConfig) -> Association {
    let mut a = create_association(config);
    a.control_queue.clear();
    a.timers.stop(Timer::T1Init);
    a.set_state(AssociationState::Established);
    a.cwnd = 1 << 20;
    a.rwnd = 1 << 20;
    a
}

/// The default scheduler sends in the order of writing (RFC 8260 3.1). Unordered messages
/// used to go ahead of every ordered one, so a steady flow of them starved the ordered
/// messages, DCEP and stream resets included.
#[test]
fn unordered_messages_do_not_starve_ordered_ones() -> Result<()> {
    let mut a = sender(TransportConfig::default());
    let now = Instant::now();
    a.open_stream(1, PPI)?
        .set_reliability_params(true, ReliabilityType::Reliable, 0)?;
    a.open_stream(2, PPI)?;
    a.open_stream(3, PPI)?;
    for _ in 0..20 {
        a.stream(1)?
            .write_sctp(now, &Bytes::from_static(b"unordered"), PPI)?;
    }
    a.stream(2)?
        .write_sctp(now, &Bytes::from_static(b"ordered"), PPI)?;
    a.stream(3)?.stop(now)?;
    for _ in 0..20 {
        a.stream(1)?
            .write_sctp(now, &Bytes::from_static(b"unordered"), PPI)?;
    }
    // A window that lets 25 of the 41 messages out.
    a.cwnd = 25 * 9 - 4;
    let out = a.gather_outbound(now).0;
    let order: Vec<u16> = transmitted_data(&out)
        .iter()
        .map(|c| c.stream_identifier)
        .collect();
    assert_eq!(25, order.len());
    assert_eq!(Some(20), order.iter().position(|s| *s == 2));
    assert_eq!(
        1,
        chunks_of_type(&out, CT_RECONFIG.0).len(),
        "the stream reset is not held up either"
    );
    Ok(())
}

/// RFC 8260 3.4 and RFC 8831 6.4: `Stream::set_priority` is the input of the priority
/// scheduler (the higher value first) and of weighted fair queueing (the larger share).
#[test]
fn a_streams_priority_drives_the_priority_scheduler() -> Result<()> {
    let mut a = sender(TransportConfig::default().with_stream_scheduler(StreamScheduler::Priority));
    let now = Instant::now();
    a.open_stream(1, PPI)?.set_priority(128)?;
    a.open_stream(2, PPI)?.set_priority(1024)?;
    a.open_stream(3, PPI)?;
    for _ in 0..3 {
        for stream in [1u16, 2, 3] {
            a.stream(stream)?
                .write_sctp(now, &Bytes::from_static(b"message"), PPI)?;
        }
    }
    let order: Vec<u16> = transmitted_data(&a.gather_outbound(now).0)
        .iter()
        .map(|c| c.stream_identifier)
        .collect();
    assert_eq!(vec![2, 2, 2, 3, 3, 3, 1, 1, 1], order);
    Ok(())
}

/// RFC 8260 3.3: with round robin per packet, a packet bundles the chunks of one stream.
#[test]
fn round_robin_per_packet_bundles_one_stream_in_a_packet() -> Result<()> {
    let mut a = sender(
        TransportConfig::default().with_stream_scheduler(StreamScheduler::RoundRobinPerPacket),
    );
    let now = Instant::now();
    for stream in [1u16, 2, 3] {
        a.open_stream(stream, PPI)?;
    }
    for _ in 0..12 {
        for stream in [1u16, 2, 3] {
            a.stream(stream)?
                .write_sctp(now, &Bytes::from(vec![stream as u8; 200]), PPI)?;
        }
    }
    let packets = a.gather_outbound(now).0;
    let mut per_packet = vec![];
    for raw in &packets {
        let streams: Vec<u16> = transmitted_data(std::slice::from_ref(raw))
            .iter()
            .map(|c| c.stream_identifier)
            .collect();
        assert!(
            streams.windows(2).all(|w| w[0] == w[1]),
            "a packet with chunks of streams {streams:?}"
        );
        per_packet.push((streams[0], streams.len()));
    }
    // Six 216-byte chunks fill a packet; the streams take the packets in turn.
    assert_eq!(
        vec![(1, 6), (2, 6), (3, 6), (1, 6), (2, 6), (3, 6)],
        per_packet
    );
    Ok(())
}
