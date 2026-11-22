//! Packets that used to break or kill an association (RFC 9260): chunks and parameters the
//! engine does not know, late or invalid handshake chunks, DATA on a stream that does not
//! exist, sequence numbers that wrap, a closed association that kept processing.
//!
//! Each test drives production code with packets as they arrive on the wire.

use super::*;
use crate::chunk::chunk_type::*;
use crate::endpoint::link_test::{Link, first_chunk_type};
use crate::endpoint::{DatagramEvent, Endpoint};
use crate::packet::PartialDecode;
use crate::{ClientConfig, EndpointConfig, TimerConfig};
use std::cell::RefCell;
use std::rc::Rc;

pub(super) const CAUSE_INVALID_STREAM_IDENTIFIER: u16 = 1;
pub(super) const CAUSE_UNRECOGNIZED_CHUNK_TYPE: u16 = 6;
pub(super) const PARAM_UNRECOGNIZED_PARAMETER: u16 = 8;

/// A chunk as it is on the wire: type, flags, length, value. No padding.
pub(super) fn raw_chunk(typ: u8, flags: u8, value: &[u8]) -> Vec<u8> {
    let mut c = vec![typ, flags];
    c.extend_from_slice(&((value.len() + 4) as u16).to_be_bytes());
    c.extend_from_slice(value);
    c
}

/// A parameter (or an error cause) as it is on the wire, without padding.
pub(super) fn raw_tlv(typ: u16, value: &[u8]) -> Vec<u8> {
    let mut p = typ.to_be_bytes().to_vec();
    p.extend_from_slice(&((value.len() + 4) as u16).to_be_bytes());
    p.extend_from_slice(value);
    p
}

fn padded(mut bytes: Vec<u8>) -> Vec<u8> {
    while bytes.len() % 4 != 0 {
        bytes.push(0);
    }
    bytes
}

/// A packet with a correct CRC32c, each chunk padded to four bytes.
pub(super) fn raw_packet(src: u16, dst: u16, tag: u32, chunks: &[Vec<u8>]) -> Bytes {
    let mut raw = vec![];
    raw.extend_from_slice(&src.to_be_bytes());
    raw.extend_from_slice(&dst.to_be_bytes());
    raw.extend_from_slice(&tag.to_be_bytes());
    raw.extend_from_slice(&[0; 4]);
    for c in chunks {
        raw.extend_from_slice(&padded(c.clone()));
    }
    let checksum = crc32c::crc32c(&raw);
    raw[8..12].copy_from_slice(&checksum.to_le_bytes());
    Bytes::from(raw)
}

/// A packet from the peer of `a`, with the Verification Tag `a` expects.
pub(super) fn packet_to(a: &Association, chunks: &[Vec<u8>]) -> Bytes {
    raw_packet(
        a.destination_port,
        a.source_port,
        a.my_verification_tag,
        chunks,
    )
}

pub(super) fn chunk_bytes(c: &dyn Chunk) -> Vec<u8> {
    c.marshal().expect("chunk marshals").to_vec()
}

pub(super) fn data_chunk(tsn: u32, stream: u16, ssn: u16, payload: &'static [u8]) -> Vec<u8> {
    chunk_bytes(&ChunkPayloadData {
        tsn,
        stream_identifier: stream,
        stream_sequence_number: ssn,
        beginning_fragment: true,
        ending_fragment: true,
        payload_type: PayloadProtocolIdentifier::Binary,
        user_data: Bytes::from_static(payload),
        ..Default::default()
    })
}

/// An INIT (or INIT ACK) chunk with the given raw parameters appended.
pub(super) fn init_chunk(typ: u8, tag: u32, initial_tsn: u32, params: &[Vec<u8>]) -> Vec<u8> {
    let mut value = vec![];
    value.extend_from_slice(&tag.to_be_bytes());
    value.extend_from_slice(&(128 * 1024u32).to_be_bytes());
    value.extend_from_slice(&1024u16.to_be_bytes());
    value.extend_from_slice(&1024u16.to_be_bytes());
    value.extend_from_slice(&initial_tsn.to_be_bytes());
    for (i, p) in params.iter().enumerate() {
        if i + 1 == params.len() {
            value.extend_from_slice(p);
        } else {
            value.extend_from_slice(&padded(p.clone()));
        }
    }
    raw_chunk(typ, 0, &value)
}

/// Hands `raw` to the association as a datagram from its peer.
pub(super) fn inject(a: &mut Association, now: Instant, raw: Bytes) {
    let partial_decode = PartialDecode::unmarshal(&raw).expect("a well-formed packet");
    a.handle_event(AssociationEvent(AssociationEventInner::Datagram(
        TransportMessage {
            now,
            transport: TransportContext::default(),
            message: Payload::PartialDecode(partial_decode),
        },
    )));
}

/// Everything the association has to send now, as raw datagrams.
pub(super) fn sent_datagrams(a: &mut Association, now: Instant) -> Vec<Bytes> {
    let mut out = vec![];
    while let Some(transmit) = a.poll_transmit(now) {
        if let Payload::RawEncode(contents) = transmit.message {
            out.extend(contents);
        }
    }
    out
}

/// What the association sends once `after` has passed: its timers run first (a delayed SACK).
pub(super) fn sent_after(a: &mut Association, now: Instant, after: Duration) -> Vec<Bytes> {
    let mut out = sent_datagrams(a, now);
    a.handle_timeout(now + after);
    out.extend(sent_datagrams(a, now + after));
    out
}

/// The raw chunks (header included, padding stripped) of a datagram.
pub(super) fn chunks_of(datagram: &Bytes) -> Vec<Vec<u8>> {
    let mut chunks = vec![];
    let mut offset = 12;
    while offset + 4 <= datagram.len() {
        let len = u16::from_be_bytes([datagram[offset + 2], datagram[offset + 3]]) as usize;
        chunks.push(datagram[offset..offset + len].to_vec());
        offset += len.next_multiple_of(4);
    }
    chunks
}

/// The chunks of type `typ` among `datagrams`.
pub(super) fn chunks_of_type(datagrams: &[Bytes], typ: u8) -> Vec<Vec<u8>> {
    datagrams
        .iter()
        .flat_map(chunks_of)
        .filter(|c| c[0] == typ)
        .collect()
}

/// The TLVs (parameters or error causes) in `bytes`: type and value of each.
pub(super) fn tlvs(mut bytes: &[u8]) -> Vec<(u16, Vec<u8>)> {
    let mut out = vec![];
    while bytes.len() >= 4 {
        let typ = u16::from_be_bytes([bytes[0], bytes[1]]);
        let len = u16::from_be_bytes([bytes[2], bytes[3]]) as usize;
        out.push((typ, bytes[4..len].to_vec()));
        bytes = &bytes[len.next_multiple_of(4).min(bytes.len())..];
    }
    out
}

pub(super) fn connected_link(seed: u64) -> Link {
    let mut link = Link::new(TransportConfig::default(), TransportConfig::default(), seed);
    link.connect();
    link
}

fn read_all(a: &mut Association, stream: u16) -> Vec<Bytes> {
    let mut out = vec![];
    let Ok(mut s) = a.stream(stream) else {
        return out;
    };
    while let Ok(Some(chunks)) = s.read_sctp() {
        let mut buf = vec![0u8; chunks.len()];
        let n = chunks.read(&mut buf).unwrap();
        buf.truncate(n);
        out.push(Bytes::from(buf));
    }
    out
}

// ---- B1: Gap Ack Blocks across the TSN wrap ------------------------------------------------

/// RFC 9260 3.3.4: a Gap Ack Block is an offset from the Cumulative TSN Ack, in serial number
/// arithmetic. Received TSNs that have wrapped past zero while the cumulative TSN has not got
/// offset 0, which named a TSN the peer never sent.
#[test]
fn gap_ack_blocks_are_offsets_across_the_tsn_wrap() {
    let mut q = PayloadQueue::new();
    for tsn in [u32::MAX, 1] {
        q.push_no_check(ChunkPayloadData {
            tsn,
            user_data: Bytes::from_static(b"x"),
            ..Default::default()
        });
    }
    let blocks = q.get_gap_ack_blocks(u32::MAX - 2);
    let offsets: Vec<(u16, u16)> = blocks.iter().map(|b| (b.start, b.end)).collect();
    assert_eq!(vec![(2, 2), (4, 4)], offsets);
}

/// The same end to end: a loss while the sender's TSNs wrap is repaired, and the sender is
/// not closed by a SACK it cannot make sense of.
#[test]
fn a_loss_across_the_tsn_wrap_is_recovered() {
    let mut link = Link::new(TransportConfig::default(), TransportConfig::default(), 7);
    link.begin_connect();
    {
        // Start the client's TSNs three before the wrap, before its INIT leaves.
        let a = link.client.conn();
        let tsn = u32::MAX - 3;
        a.my_next_tsn = tsn;
        a.min_tsn2measure_rtt = tsn;
        a.cumulative_tsn_ack_point = tsn.wrapping_sub(1);
        a.advanced_peer_tsn_ack_point = tsn.wrapping_sub(1);
        a.stored_init.as_mut().unwrap().initial_tsn = tsn;
        a.control_queue.clear();
        a.send_init().unwrap();
    }
    let deadline = link.now + Duration::from_secs(60);
    assert!(link.run_until(deadline, |l| l.client.connected() && l.server.connected()));

    let mut data_packets = 0;
    link.filter = Some(Box::new(move |from_client: bool, datagram: &Bytes| {
        if from_client && first_chunk_type(datagram) == Some(0) {
            data_packets += 1;
            return data_packets == 2;
        }
        false
    }));
    let now = link.now;
    let ppi = PayloadProtocolIdentifier::Binary;
    let payload = Bytes::from(vec![7u8; 1000]);
    {
        let a = link.client.conn();
        let mut s = a.open_stream(1, ppi).unwrap();
        for _ in 0..6 {
            s.write_sctp(now, &payload, ppi).unwrap();
        }
    }
    let deadline = link.now + Duration::from_secs(60);
    assert!(
        link.run_until(deadline, |l| l.server.received.len() == 6),
        "six messages across the TSN wrap, one packet lost: {} arrived",
        link.server.received.len()
    );
    assert!(!link.client.conn().is_ended(), "the sender was closed");
    assert!(!link.server.conn().is_ended(), "the receiver was closed");
}

// ---- B2: stream counts -----------------------------------------------------------------------

/// RFC 9260 5.1.1: this side sends on min(own OS, peer's MIS) streams and receives on
/// min(own MIS, peer's OS). The counts were paired OS with OS and MIS with MIS.
#[test]
fn stream_counts_pair_own_outbound_with_the_peers_inbound() -> Result<()> {
    let mut a = create_association(TransportConfig::default());
    a.set_state(AssociationState::Closed);
    let pkt = Packet {
        common_header: CommonHeader {
            source_port: 5001,
            destination_port: 5002,
            ..Default::default()
        },
        ..Default::default()
    };
    let mut init = ChunkInit {
        initial_tsn: 1234,
        num_outbound_streams: 2048,
        num_inbound_streams: 16,
        initiate_tag: 5678,
        advertised_receiver_window_credit: 512 * 1024,
        ..Default::default()
    };
    init.set_supported_extensions();
    let reply = a.handle_init(&pkt, &init, Instant::now())?;

    assert_eq!(2048, a.my_max_num_inbound_streams, "the peer sends on 2048");
    assert_eq!(16, a.my_max_num_outbound_streams, "the peer receives on 16");
    let init_ack = reply[0].chunks[0]
        .as_any()
        .downcast_ref::<ChunkInit>()
        .expect("an INIT ACK");
    assert_eq!(
        16, init_ack.num_outbound_streams,
        "OS within the peer's MIS"
    );
    assert_eq!(2048, init_ack.num_inbound_streams);
    Ok(())
}

/// The INIT ACK side of the same rule.
#[test]
fn stream_counts_from_an_init_ack_are_paired_the_same_way() -> Result<()> {
    let mut a = create_association(TransportConfig::default());
    let pkt = Packet {
        common_header: CommonHeader {
            source_port: a.destination_port,
            destination_port: a.source_port,
            ..Default::default()
        },
        ..Default::default()
    };
    let init_ack = ChunkInit {
        is_ack: true,
        initiate_tag: 123,
        advertised_receiver_window_credit: 128 * 1024,
        num_outbound_streams: 300,
        num_inbound_streams: 20,
        initial_tsn: 123,
        params: vec![Box::new(ParamStateCookie::new())],
    };
    a.handle_init_ack(&pkt, &init_ack, Instant::now())?;
    assert_eq!(300, a.my_max_num_inbound_streams);
    assert_eq!(20, a.my_max_num_outbound_streams);
    Ok(())
}

/// A peer that offers many outbound streams and few inbound ones may use its outbound streams.
#[test]
fn data_on_a_stream_within_the_peers_outbound_count_is_delivered() {
    let client = TransportConfig::default()
        .with_max_num_outbound_streams(2048)
        .with_max_num_inbound_streams(16);
    let mut link = Link::new(client, TransportConfig::default(), 3);
    link.connect();
    let now = link.now;
    let ppi = PayloadProtocolIdentifier::Binary;
    link.client
        .conn()
        .open_stream(100, ppi)
        .unwrap()
        .write_sctp(now, &Bytes::from_static(b"on stream 100"), ppi)
        .unwrap();
    let deadline = link.now + Duration::from_secs(10);
    assert!(
        link.run_until(deadline, |l| !l.server.received.is_empty()),
        "DATA on stream 100 of 2048 was not delivered"
    );
    assert_eq!(100, link.server.received[0].0);
}

// ---- B3: unknown chunk types, HEARTBEAT ACK ---------------------------------------------------

/// RFC 9260 3.2, upper bits 10: skip the chunk and go on. A PAD chunk (0x84, RFC 4820) bundled
/// with DATA cost the whole packet.
#[test]
fn data_bundled_with_a_skippable_unknown_chunk_is_delivered() {
    let mut link = connected_link(11);
    let now = link.now;
    let a = link.server.conn();
    let tsn = a.peer_last_tsn.wrapping_add(1);
    let raw = packet_to(
        a,
        &[raw_chunk(0x84, 0, &[0; 6]), data_chunk(tsn, 1, 0, b"hello")],
    );
    inject(a, now, raw);

    assert!(!a.is_ended());
    assert_eq!(tsn, a.peer_last_tsn, "the DATA was not taken");
    assert_eq!(vec![Bytes::from_static(b"hello")], read_all(a, 1));
    let sent = sent_after(a, now, Duration::from_secs(1));
    assert_eq!(
        1,
        chunks_of_type(&sent, CT_SACK.0).len(),
        "the DATA is SACKed"
    );
    assert!(
        chunks_of_type(&sent, CT_ERROR.0).is_empty(),
        "no report asked"
    );
}

/// Upper bits 11: skip, go on, and report the chunk in an ERROR "Unrecognized Chunk Type".
#[test]
fn an_unknown_chunk_asking_for_a_report_is_skipped_and_reported() {
    let mut link = connected_link(12);
    let now = link.now;
    let a = link.server.conn();
    let tsn = a.peer_last_tsn.wrapping_add(1);
    let unknown = raw_chunk(0xC5, 0x03, &[1, 2, 3, 4, 5]);
    let raw = packet_to(a, &[unknown.clone(), data_chunk(tsn, 1, 0, b"hello")]);
    inject(a, now, raw);

    assert_eq!(
        tsn, a.peer_last_tsn,
        "the DATA after the chunk was not taken"
    );
    let sent = sent_datagrams(a, now);
    let errors = chunks_of_type(&sent, CT_ERROR.0);
    assert_eq!(1, errors.len(), "one ERROR chunk");
    assert_eq!(
        vec![(CAUSE_UNRECOGNIZED_CHUNK_TYPE, unknown)],
        tlvs(&errors[0][4..]),
        "the cause carries the unrecognized chunk"
    );
}

/// Upper bits 00: stop processing the packet. What came before the chunk stands, what follows
/// is discarded, nothing is reported and the association lives.
#[test]
fn an_unknown_chunk_with_stop_bits_ends_the_packet_only() {
    let mut link = connected_link(13);
    let now = link.now;
    let a = link.server.conn();
    let tsn = a.peer_last_tsn.wrapping_add(1);
    let raw = packet_to(
        a,
        &[
            data_chunk(tsn, 1, 0, b"before"),
            raw_chunk(0x3F, 0, &[9; 4]),
            data_chunk(tsn.wrapping_add(1), 1, 1, b"after"),
        ],
    );
    inject(a, now, raw);

    assert!(!a.is_ended());
    assert_eq!(tsn, a.peer_last_tsn, "only the DATA before the chunk");
    assert_eq!(vec![Bytes::from_static(b"before")], read_all(a, 1));
    let sent = sent_after(a, now, Duration::from_secs(1));
    assert!(chunks_of_type(&sent, CT_ERROR.0).is_empty());
    assert_eq!(
        1,
        chunks_of_type(&sent, CT_SACK.0).len(),
        "the DATA is SACKed"
    );
}

/// Upper bits 01: stop processing the packet and report the chunk.
#[test]
fn an_unknown_chunk_with_stop_and_report_bits_is_reported() {
    let mut link = connected_link(14);
    let now = link.now;
    let a = link.server.conn();
    let tsn = a.peer_last_tsn.wrapping_add(1);
    let unknown = raw_chunk(0x7F, 0, &[9; 4]);
    let raw = packet_to(a, &[unknown.clone(), data_chunk(tsn, 1, 0, b"after")]);
    inject(a, now, raw);

    assert!(!a.is_ended());
    assert_eq!(
        tsn.wrapping_sub(1),
        a.peer_last_tsn,
        "nothing after the chunk"
    );
    let errors = chunks_of_type(&sent_datagrams(a, now), CT_ERROR.0);
    assert_eq!(1, errors.len());
    assert_eq!(
        vec![(CAUSE_UNRECOGNIZED_CHUNK_TYPE, unknown)],
        tlvs(&errors[0][4..])
    );
}

/// A HEARTBEAT ACK is a chunk the engine knows: the packet carrying one is processed.
#[test]
fn a_packet_with_a_heartbeat_ack_is_processed() {
    let mut link = connected_link(15);
    let now = link.now;
    let a = link.server.conn();
    let tsn = a.peer_last_tsn.wrapping_add(1);
    let heartbeat_ack = chunk_bytes(&ChunkHeartbeatAck {
        params: vec![Box::new(ParamHeartbeatInfo {
            heartbeat_information: Bytes::from_static(b"12345678"),
        })],
    });
    let raw = packet_to(a, &[heartbeat_ack, data_chunk(tsn, 1, 0, b"hello")]);
    inject(a, now, raw);

    assert!(!a.is_ended());
    assert_eq!(tsn, a.peer_last_tsn, "the DATA bundled with HEARTBEAT ACK");
}

// ---- B5: INIT parameters ----------------------------------------------------------------------

fn accepting_endpoint() -> Endpoint {
    let mut server = ServerConfig::new(TransportConfig::default());
    server.concurrent_associations(1);
    Endpoint::new(
        "10.0.0.2:5000".parse().unwrap(),
        TransportProtocol::UDP,
        Arc::new(EndpointConfig::default()),
        Some(Arc::new(server)),
    )
}

fn remote() -> SocketAddr {
    "10.0.0.1:5000".parse().unwrap()
}

/// Delivers an INIT to a fresh accepting endpoint and returns the association and its answer.
fn accept_init(params: &[Vec<u8>]) -> (Endpoint, Option<Association>, Vec<Bytes>) {
    let mut endpoint = accepting_endpoint();
    let now = Instant::now();
    let init = raw_packet(
        5000,
        5000,
        0,
        &[init_chunk(CT_INIT.0, 0xAABB_CCDD, 100, params)],
    );
    match endpoint.handle(now, remote(), None, init) {
        Some((_, DatagramEvent::NewAssociation(mut a))) => {
            let sent = sent_datagrams(&mut a, now);
            (endpoint, Some(a), sent)
        }
        _ => (endpoint, None, vec![]),
    }
}

/// RFC 9260 3.3.2.1: Supported Address Types (12), an IPv4 address (5) and Cookie Preservative
/// (9) are standard INIT parameters. A peer sending one could not connect: the INIT did not
/// parse.
#[test]
fn an_init_with_standard_optional_parameters_is_answered() {
    for param in [
        raw_tlv(12, &[0, 5]),
        raw_tlv(5, &[10, 0, 0, 1]),
        raw_tlv(9, &[0, 0, 0, 100]),
    ] {
        let chunk = init_chunk(CT_INIT.0, 77, 100, std::slice::from_ref(&param));
        assert!(
            ChunkInit::unmarshal(&Bytes::from(chunk)).is_ok(),
            "INIT with parameter {param:?} did not parse"
        );
        let (_, a, sent) = accept_init(&[param.clone()]);
        assert!(a.is_some(), "no association for INIT with {param:?}");
        let init_acks = chunks_of_type(&sent, CT_INIT_ACK.0);
        assert_eq!(1, init_acks.len(), "an INIT ACK for INIT with {param:?}");
        assert!(
            tlvs(&init_acks[0][20..])
                .iter()
                .all(|(typ, _)| *typ != PARAM_UNRECOGNIZED_PARAMETER),
            "a parameter the RFC defines is not reported as unrecognized"
        );
    }
}

/// RFC 9260 3.2.1: an unrecognized parameter is handled by the upper two bits of its type:
/// stop or skip, with or without a report in the INIT ACK (3.3.3: "Unrecognized Parameter").
#[test]
fn an_unknown_init_parameter_is_handled_by_its_action_bits() {
    let forward_tsn = raw_tlv(49152, &[]);
    for (typ, reported, later_params_processed) in [
        (0x00F0u16, false, false),
        (0x40F0, true, false),
        (0x80F0, false, true),
        (0xC0F0, true, true),
    ] {
        let unknown = raw_tlv(typ, &[1, 2, 3, 4, 5]);
        // The unknown parameter, then Forward-TSN-Supported: whether that one is still
        // processed shows whether processing stopped.
        let (_, a, sent) = accept_init(&[unknown.clone(), forward_tsn.clone()]);
        let a = a.unwrap_or_else(|| panic!("INIT with parameter {typ:#06x} was dropped"));
        let init_acks = chunks_of_type(&sent, CT_INIT_ACK.0);
        assert_eq!(1, init_acks.len(), "INIT ACK for parameter {typ:#06x}");
        let reports: Vec<Vec<u8>> = tlvs(&init_acks[0][20..])
            .into_iter()
            .filter(|(t, _)| *t == PARAM_UNRECOGNIZED_PARAMETER)
            .map(|(_, value)| value)
            .collect();
        if reported {
            assert_eq!(vec![unknown], reports, "parameter {typ:#06x} is reported");
        } else {
            assert!(reports.is_empty(), "parameter {typ:#06x} is not reported");
        }
        assert_eq!(
            later_params_processed, a.use_forward_tsn,
            "parameters after {typ:#06x}"
        );
    }
}

/// RFC 9260 3.3.3: unrecognized parameters of an INIT ACK that ask for a report are reported
/// in an ERROR chunk bundled with the COOKIE ECHO, and the handshake goes on.
#[test]
fn an_unknown_init_ack_parameter_is_reported_with_the_cookie_echo() {
    let mut endpoint = Endpoint::new(
        remote(),
        TransportProtocol::UDP,
        Arc::new(EndpointConfig::default()),
        None,
    );
    let now = Instant::now();
    let (_, mut a) = endpoint
        .connect(
            now,
            ClientConfig::new(TransportConfig::default()),
            "10.0.0.2:5000".parse().unwrap(),
        )
        .unwrap();
    let _ = sent_datagrams(&mut a, now);

    let unknown = raw_tlv(0xC0F0, &[1, 2, 3]);
    let cookie = raw_tlv(7, b"a state cookie..");
    let init_ack = init_chunk(CT_INIT_ACK.0, 4242, 9000, &[unknown.clone(), cookie]);
    let raw = packet_to(&a, &[init_ack]);
    inject(&mut a, now, raw);

    assert!(!a.is_ended(), "the INIT ACK ended the association");
    let sent = sent_datagrams(&mut a, now);
    assert_eq!(1, chunks_of_type(&sent, CT_COOKIE_ECHO.0).len());
    let with_cookie: Vec<&Bytes> = sent
        .iter()
        .filter(|d| first_chunk_type(d) == Some(CT_COOKIE_ECHO.0))
        .collect();
    let errors = chunks_of_type(&[with_cookie[0].clone()], CT_ERROR.0);
    assert_eq!(1, errors.len(), "an ERROR bundled after the COOKIE ECHO");
    let causes = tlvs(&errors[0][4..]);
    assert_eq!(1, causes.len());
    assert_eq!(8, causes[0].0, "cause Unrecognized Parameters");
    assert_eq!(unknown, causes[0].1[..unknown.len()].to_vec());
}

// ---- B6: late INIT, chunks that fail their checks ---------------------------------------------

/// RFC 9260 5.2.2: an INIT for an association that exists is answered with an INIT ACK and
/// changes nothing. A late copy of the peer's own INIT closed the established association.
#[test]
fn a_late_copy_of_the_init_leaves_the_association_established() {
    let captured = Rc::new(RefCell::new(None));
    let seen = captured.clone();
    let mut link = Link::new(TransportConfig::default(), TransportConfig::default(), 21);
    link.filter = Some(Box::new(move |from_client: bool, datagram: &Bytes| {
        if from_client && first_chunk_type(datagram) == Some(CT_INIT.0) {
            *seen.borrow_mut() = Some(datagram.clone());
        }
        false
    }));
    link.connect();
    let init = captured.borrow().clone().expect("the client's INIT");
    let initiate_tag = u32::from_be_bytes([init[16], init[17], init[18], init[19]]);

    let now = link.now;
    let a = link.server.conn();
    let (peer_tag, peer_last_tsn) = (a.peer_verification_tag, a.peer_last_tsn);
    inject(a, now, init);

    assert!(!a.is_ended(), "the late INIT closed the association");
    assert_eq!(AssociationState::Established, a.state());
    assert_eq!(peer_tag, a.peer_verification_tag, "the TCB is untouched");
    assert_eq!(peer_last_tsn, a.peer_last_tsn);
    let sent = sent_datagrams(a, now);
    assert_eq!(1, chunks_of_type(&sent, CT_INIT_ACK.0).len(), "an INIT ACK");
    let tag = u32::from_be_bytes([sent[0][4], sent[0][5], sent[0][6], sent[0][7]]);
    assert_eq!(initiate_tag, tag, "sent with the INIT's Initiate Tag");
    let own_tag = u32::from_be_bytes([sent[0][16], sent[0][17], sent[0][18], sent[0][19]]);
    assert_ne!(0, own_tag);
    assert_ne!(a.my_verification_tag, own_tag, "with a new Initiate Tag");

    // The association still carries data.
    let ppi = PayloadProtocolIdentifier::Binary;
    link.client
        .conn()
        .open_stream(1, ppi)
        .unwrap()
        .write_sctp(now, &Bytes::from_static(b"still here"), ppi)
        .unwrap();
    let deadline = link.now + Duration::from_secs(10);
    assert!(link.run_until(deadline, |l| !l.server.received.is_empty()));
}

/// A chunk that fails its own validity checks is discarded with its packet. An INIT ACK with
/// an a_rwnd below 1500 arriving in ESTABLISHED closed the association.
#[test]
fn a_chunk_that_fails_its_checks_does_not_close_an_established_association() {
    let mut link = connected_link(22);
    let now = link.now;
    let a = link.server.conn();
    let mut value = vec![];
    value.extend_from_slice(&99u32.to_be_bytes());
    value.extend_from_slice(&1000u32.to_be_bytes()); // a_rwnd below the 1500 minimum
    value.extend_from_slice(&[0, 1, 0, 1]);
    value.extend_from_slice(&7u32.to_be_bytes());
    value.extend_from_slice(&raw_tlv(7, b"cookie"));
    let raw = packet_to(a, &[raw_chunk(CT_INIT_ACK.0, 0, &value)]);
    inject(a, now, raw);

    assert!(!a.is_ended(), "an invalid INIT ACK closed the association");
    assert_eq!(AssociationState::Established, a.state());
}

// ---- B8: a closed association -----------------------------------------------------------------

fn user_initiated_abort() -> Vec<u8> {
    chunk_bytes(&ChunkAbort {
        error_causes: vec![ErrorCause {
            code: USER_INITIATED_ABORT,
            ..Default::default()
        }],
    })
}

/// RFC 9260 3.3.7 and 9.1: after an ABORT the association is gone. A copy of the COOKIE ECHO
/// that followed re-established the closed association and reported `Connected` again.
#[test]
fn a_closed_association_processes_nothing_more() {
    let mut link = connected_link(31);
    let now = link.now;
    let a = link.server.conn();
    let cookie_echo = chunk_bytes(&ChunkCookieEcho {
        cookie: a.my_cookie.as_ref().unwrap().cookie.clone(),
    });
    let tsn = a.peer_last_tsn.wrapping_add(1);

    // Chunks after the ABORT in its own packet are ignored too.
    let raw = packet_to(a, &[user_initiated_abort(), data_chunk(tsn, 1, 0, b"x")]);
    inject(a, now, raw);
    assert!(a.is_ended());
    assert_eq!(tsn.wrapping_sub(1), a.peer_last_tsn, "DATA after the ABORT");
    while a.poll().is_some() {}

    let raw = packet_to(a, &[cookie_echo]);
    inject(a, now, raw);
    assert!(a.is_ended());
    assert_eq!(AssociationState::Closed, a.state());
    let mut events = vec![];
    while let Some(e) = a.poll() {
        events.push(e);
    }
    assert!(
        events.is_empty(),
        "a closed association reported {events:?}"
    );
    assert!(sent_datagrams(a, now).is_empty(), "and answered");
}

/// RFC 9260 9.1: an association that has ended is removed from the endpoint's record. The
/// endpoint kept routing packets to it and kept counting it, so with one association allowed
/// (SCTP over DTLS) no later INIT was ever accepted. The owner need not report anything, and
/// may keep the association to read how it ended.
#[test]
fn an_ended_association_frees_its_endpoint_slot() {
    let (mut endpoint, a, _) = accept_init(&[]);
    let mut a = a.unwrap();
    let now = Instant::now();
    let next_init = raw_packet(5001, 5000, 0, &[init_chunk(CT_INIT.0, 0x1111_2222, 5, &[])]);
    let other: SocketAddr = "10.0.0.9:5000".parse().unwrap();
    assert!(
        endpoint
            .handle(now, other, None, next_init.clone())
            .is_none(),
        "a second association while the first is alive"
    );
    assert_eq!(1, endpoint.live_associations());

    a.abort().unwrap();
    assert!(a.is_ended());
    // A packet for the ended association is no longer routed to it.
    let stray = packet_to(&a, &[data_chunk(1, 1, 0, b"late")]);
    assert!(endpoint.handle(now, remote(), None, stray).is_none());
    assert_eq!(0, endpoint.live_associations());

    assert!(
        matches!(
            endpoint.handle(now, other, None, next_init),
            Some((_, DatagramEvent::NewAssociation(_)))
        ),
        "the place of the aborted association was not given back"
    );
}

/// An owner that does report an ended association drained, or reports one twice, or reports a
/// handle the endpoint never issued, changes nothing: removing a vacant entry used to panic,
/// and must never take the place of a live association.
#[test]
fn reporting_an_ended_association_drained_is_harmless() {
    let (mut endpoint, a, _) = accept_init(&[]);
    let mut a = a.unwrap();
    a.abort().unwrap();
    assert!(
        a.poll_endpoint_event().is_none(),
        "the owner keeps an ended association to read its end state"
    );
    let now = Instant::now();
    let init = raw_packet(5000, 5000, 0, &[init_chunk(CT_INIT.0, 0x2222_3333, 5, &[])]);
    let Some((second, DatagramEvent::NewAssociation(_live))) =
        endpoint.handle(now, remote(), None, init)
    else {
        panic!("the next INIT was not accepted");
    };
    assert_ne!(
        crate::AssociationHandle(0),
        second,
        "the handle is not reused"
    );

    for _ in 0..2 {
        endpoint.handle_event(crate::AssociationHandle(0), crate::EndpointEvent::drained());
    }
    endpoint.handle_event(
        crate::AssociationHandle(77),
        crate::EndpointEvent::drained(),
    );
    assert_eq!(1, endpoint.live_associations(), "the live one is untouched");
}

// ---- B9: half-open associations ---------------------------------------------------------------

/// A peer that starts over with a new INIT (another Initiate Tag) before sending COOKIE ECHO
/// is answered by the association its first INIT created, instead of being refused for the
/// life of the endpoint.
#[test]
fn a_new_init_from_the_same_peer_restarts_a_half_open_association() {
    let (mut endpoint, a, _) = accept_init(&[]);
    let mut a = a.unwrap();
    let now = Instant::now();
    let second = raw_packet(
        5000,
        5000,
        0,
        &[init_chunk(CT_INIT.0, 0x0102_0304, 900, &[])],
    );
    match endpoint.handle(now, remote(), None, second) {
        Some((_, DatagramEvent::AssociationEvent(event))) => a.handle_event(event),
        Some((_, DatagramEvent::NewAssociation(_))) => panic!("a second association"),
        None => panic!("the second INIT was refused"),
    }
    let sent = sent_datagrams(&mut a, now);
    assert_eq!(1, chunks_of_type(&sent, CT_INIT_ACK.0).len());
    let tag = u32::from_be_bytes([sent[0][4], sent[0][5], sent[0][6], sent[0][7]]);
    assert_eq!(0x0102_0304, tag, "the INIT ACK answers the new INIT");
    assert_eq!(899, a.peer_last_tsn);
}

/// An INIT never followed by a COOKIE ECHO leaves nothing behind: the association ends by
/// itself and gives its endpoint slot back.
#[test]
fn a_half_open_association_is_reaped() {
    let (mut endpoint, a, _) = accept_init(&[]);
    let mut a = a.unwrap();
    let mut now = Instant::now();
    let mut rounds = 0;
    while let Some(at) = a.poll_timeout() {
        now = at;
        a.handle_timeout(now);
        let _ = sent_datagrams(&mut a, now);
        rounds += 1;
        assert!(rounds < 100, "the half-open association never ended");
    }
    assert!(
        a.is_ended(),
        "a half-open association runs no timer and never ends"
    );
    let mut closed = false;
    while let Some(e) = a.poll() {
        closed |= matches!(
            e,
            Event::AssociationClosed {
                reason: AssociationError::HandshakeFailed(_)
            }
        );
    }
    assert!(closed, "the owner is told");

    let init = raw_packet(5000, 5000, 0, &[init_chunk(CT_INIT.0, 0x0A0B_0C0D, 1, &[])]);
    assert!(matches!(
        endpoint.handle(now, remote(), None, init),
        Some((_, DatagramEvent::NewAssociation(_)))
    ));
}

// ---- B10: DATA on an invalid stream ----------------------------------------------------------

/// RFC 9260 6.5: DATA on a stream the peer may not use is acknowledged like any DATA,
/// answered with ERROR "Invalid Stream Identifier", and discarded. It was dropped unrecorded,
/// so the cumulative TSN stopped for good and the peer retransmitted for ever.
#[test]
fn data_on_an_invalid_stream_is_acknowledged_and_reported() {
    let mut link = connected_link(41);
    let now = link.now;
    let a = link.server.conn();
    a.my_max_num_inbound_streams = 16;
    let tsn = a.peer_last_tsn.wrapping_add(1);
    let raw = packet_to(
        a,
        &[
            data_chunk(tsn, 1000, 0, b"nowhere"),
            data_chunk(tsn.wrapping_add(1), 1, 0, b"valid"),
        ],
    );
    inject(a, now, raw);

    assert!(!a.streams.contains_key(&1000), "no state for the stream");
    assert_eq!(tsn.wrapping_add(1), a.peer_last_tsn, "the cumulative TSN");
    assert_eq!(vec![Bytes::from_static(b"valid")], read_all(a, 1));
    assert_eq!(
        a.max_receive_buffer_size,
        a.get_my_receiver_window_credit(),
        "discarded DATA takes no receive window"
    );

    let sent = sent_after(a, now, Duration::from_secs(1));
    let sacks = chunks_of_type(&sent, CT_SACK.0);
    assert_eq!(
        tsn.wrapping_add(1),
        u32::from_be_bytes([sacks[0][4], sacks[0][5], sacks[0][6], sacks[0][7]]),
        "the SACK acknowledges the discarded chunk"
    );
    let errors = chunks_of_type(&sent, CT_ERROR.0);
    assert_eq!(1, errors.len(), "one ERROR chunk");
    assert_eq!(
        vec![(CAUSE_INVALID_STREAM_IDENTIFIER, vec![0x03, 0xE8, 0, 0])],
        tlvs(&errors[0][4..]),
        "Invalid Stream Identifier naming stream 1000"
    );
}

// ---- B11: SSN wrap -----------------------------------------------------------------------------

/// RFC 9260 6.1: the sender keeps fewer ordered messages of a stream outstanding than the
/// Stream Sequence Number space holds. With small messages and a large window a full SSN
/// cycle was in flight at once, and after a loss the receiver could not tell SSN n from
/// n + 65536.
#[test]
fn ordered_messages_in_flight_never_span_the_ssn_space() {
    const MESSAGES: u32 = 70_000;
    let mut link = connected_link(51);
    let mut dropped = false;
    link.filter = Some(Box::new(move |from_client: bool, datagram: &Bytes| {
        if from_client && !dropped && first_chunk_type(datagram) == Some(0) {
            dropped = true;
            return true;
        }
        false
    }));
    let now = link.now;
    let ppi = PayloadProtocolIdentifier::Binary;
    {
        let a = link.client.conn();
        a.cwnd = 4 << 20;
        a.ssthresh = 4 << 20;
        a.rwnd = 4 << 20;
        let mut s = a.open_stream(1, ppi).unwrap();
        for i in 0..MESSAGES {
            s.write_sctp(now, &Bytes::copy_from_slice(&i.to_be_bytes()), ppi)
                .unwrap();
        }
    }
    let deadline = link.now + Duration::from_secs(300);
    let all = link.run_until(deadline, |l| l.server.received.len() >= MESSAGES as usize);
    assert!(
        all,
        "{} of {MESSAGES} ordered messages arrived",
        link.server.received.len()
    );
    for (i, (_, message)) in link.server.received.iter().enumerate() {
        assert_eq!(&(i as u32).to_be_bytes()[..], &message[..], "message {i}");
    }
}

// ---- B12: shutdown retransmission limit ----------------------------------------------------

/// RFC 9260 9.2: past the retransmission limit for SHUTDOWN the peer is unreachable and the
/// association is over. It stayed in SHUTDOWN-SENT for good with no timer running.
#[test]
fn an_unanswered_shutdown_ends_the_association_at_its_limit() -> Result<()> {
    let mut a = create_association(TransportConfig::default().with_timer_config(TimerConfig {
        max_t2_shutdown_retrans: 2,
        ..TimerConfig::default()
    }));
    a.control_queue.clear();
    a.timers.stop(Timer::T1Init);
    a.set_state(AssociationState::Established);
    a.rto_mgr.set_rto(1000, true);
    let mut now = Instant::now();

    a.shutdown()?;
    let mut shutdowns = chunks_of_type(&sent_datagrams(&mut a, now), CT_SHUTDOWN.0).len();
    let mut rounds = 0;
    while let Some(at) = a.poll_timeout() {
        now = at;
        a.handle_timeout(now);
        shutdowns += chunks_of_type(&sent_datagrams(&mut a, now), CT_SHUTDOWN.0).len();
        rounds += 1;
        assert!(rounds < 20);
    }
    assert_eq!(3, shutdowns, "the SHUTDOWN and two retransmissions");
    assert!(a.is_ended(), "the association is left in {}", a.state());
    let mut timed_out = false;
    while let Some(e) = a.poll() {
        timed_out |= matches!(
            e,
            Event::AssociationClosed {
                reason: AssociationError::TimedOut
            }
        );
    }
    assert!(timed_out, "the owner is told the peer is unreachable");
    Ok(())
}

// ---- B13: error cause padding ------------------------------------------------------------------

/// RFC 9260 3.3.10: error causes are padded to a multiple of four bytes like parameters. The
/// cause after one of odd length was read from the wrong offset.
#[test]
fn error_causes_are_padded_to_four_bytes() -> Result<()> {
    for typ in [CT_ABORT.0, CT_ERROR.0] {
        let mut value = padded(raw_tlv(13, b"x"));
        value.extend_from_slice(&raw_tlv(12, &[]));
        let raw = Bytes::from(raw_chunk(typ, 0, &value));

        let causes: Vec<(u16, Bytes)> = if typ == CT_ABORT.0 {
            let c = ChunkAbort::unmarshal(&raw)?;
            assert_eq!(raw, c.marshal()?, "an ABORT is written as it was read");
            c.error_causes
                .iter()
                .map(|e| (e.code.0, e.raw.clone()))
                .collect()
        } else {
            let c = ChunkError::unmarshal(&raw)?;
            assert_eq!(raw, c.marshal()?, "an ERROR is written as it was read");
            c.error_causes
                .iter()
                .map(|e| (e.code.0, e.raw.clone()))
                .collect()
        };
        assert_eq!(
            vec![(13, Bytes::from_static(b"x")), (12, Bytes::new())],
            causes
        );
    }
    Ok(())
}

/// An ABORT whose first cause has an odd length still ends the association as the abort it
/// is, with the cause that follows read correctly.
#[test]
fn an_abort_with_an_odd_length_cause_is_understood() {
    let mut link = connected_link(61);
    let now = link.now;
    let a = link.server.conn();
    let mut value = padded(raw_tlv(13, b"odd"));
    value.extend_from_slice(&raw_tlv(12, &[]));
    let raw = packet_to(a, &[raw_chunk(CT_ABORT.0, 0, &value)]);
    inject(a, now, raw);
    assert!(a.is_ended());
    let mut reasons = vec![];
    while let Some(e) = a.poll() {
        if let Event::AssociationClosed { reason } = e {
            reasons.push(reason);
        }
    }
    assert_eq!(vec![AssociationError::AssociationClosed], reasons);
}

// ---- B4: zero-length write -------------------------------------------------------------------

/// RFC 9260 3.3.1: a DATA chunk carries at least one byte, so an empty user message cannot be
/// sent. It was accepted, sent nothing and still used a Stream Sequence Number, which held
/// back every later ordered message of the stream at the receiver.
#[test]
fn a_zero_length_write_is_refused_and_uses_no_sequence_number() {
    let mut link = connected_link(71);
    let now = link.now;
    let ppi = PayloadProtocolIdentifier::Binary;
    {
        let a = link.client.conn();
        let mut s = a.open_stream(1, ppi).unwrap();
        assert!(
            s.write_sctp(now, &Bytes::new(), ppi).is_err(),
            "an empty message was accepted"
        );
        s.write_sctp(now, &Bytes::from_static(b"x"), ppi).unwrap();
    }
    let deadline = link.now + Duration::from_secs(10);
    assert!(
        link.run_until(deadline, |l| !l.server.received.is_empty()),
        "the message after the empty one never became readable"
    );
}

// ---- B7: payload protocol identifiers -------------------------------------------------------

/// RFC 9260 3.3.1: the Payload Protocol Identifier is the application's, passed through
/// unchanged. Any value other than the five WebRTC ones was read as "unknown" and written
/// as 58.
#[test]
fn any_payload_protocol_identifier_is_carried_unchanged() -> Result<()> {
    for ppid in [0u32, 52, 58, 0x1234_5678, u32::MAX] {
        let mut value = vec![];
        value.extend_from_slice(&1u32.to_be_bytes());
        value.extend_from_slice(&[0, 1, 0, 0]);
        value.extend_from_slice(&ppid.to_be_bytes());
        value.extend_from_slice(b"data");
        let raw = Bytes::from(raw_chunk(0, 3, &value));
        let chunk = ChunkPayloadData::unmarshal(&raw)?;
        assert_eq!(raw, chunk.marshal()?, "PPID {ppid} through the codec");
    }

    // End to end: the number the sender gives is the number the receiver reads.
    let mut link = connected_link(81);
    let now = link.now;
    link.server.auto_read = false;
    link.client
        .conn()
        .open_stream(1, PayloadProtocolIdentifier::Binary)
        .unwrap()
        .write_sctp_with_ppid(now, &Bytes::from_static(b"x"), 52)
        .unwrap();
    let deadline = link.now + Duration::from_secs(10);
    assert!(link.run_until(deadline, |l| {
        l.server
            .association
            .as_ref()
            .is_some_and(|(_, a)| a.readable_streams.contains(&1))
    }));
    let message = link
        .server
        .conn()
        .stream(1)
        .unwrap()
        .read_sctp()?
        .expect("a message");
    assert_eq!(52, message.ppid);
    assert_eq!(PayloadProtocolIdentifier::Unknown, message.ppi);
    assert_eq!(
        53,
        crate::Chunks::new(0, 0, PayloadProtocolIdentifier::Binary, vec![]).ppid,
        "a named identifier reads as its number"
    );
    Ok(())
}

// ---- Smaller rules of the same sections ------------------------------------------------------

/// RFC 9260 3.3.2, 3.3.3: the Chunk Flags of INIT and INIT ACK are reserved and ignored by the
/// receiver. Non-zero flags failed the parse and the packet was dropped.
#[test]
fn init_and_init_ack_chunk_flags_are_ignored() {
    let mut endpoint = accepting_endpoint();
    let now = Instant::now();
    let mut init = init_chunk(CT_INIT.0, 0xAABB_CCDD, 100, &[]);
    init[1] = 0xFF;
    let Some((_, DatagramEvent::NewAssociation(mut a))) =
        endpoint.handle(now, remote(), None, raw_packet(5000, 5000, 0, &[init]))
    else {
        panic!("an INIT with flags set was refused");
    };
    assert_eq!(
        1,
        chunks_of_type(&sent_datagrams(&mut a, now), CT_INIT_ACK.0).len()
    );

    let mut client = Endpoint::new(
        remote(),
        TransportProtocol::UDP,
        Arc::new(EndpointConfig::default()),
        None,
    );
    let (_, mut a) = client
        .connect(
            now,
            ClientConfig::new(TransportConfig::default()),
            "10.0.0.2:5000".parse().unwrap(),
        )
        .unwrap();
    let _ = sent_datagrams(&mut a, now);
    let mut init_ack = init_chunk(CT_INIT_ACK.0, 4242, 9000, &[raw_tlv(7, b"cookie")]);
    init_ack[1] = 0xFF;
    let raw = packet_to(&a, &[init_ack]);
    inject(&mut a, now, raw);
    assert_eq!(
        1,
        chunks_of_type(&sent_datagrams(&mut a, now), CT_COOKIE_ECHO.0).len(),
        "an INIT ACK with flags set was not taken"
    );
}

/// RFC 9260 6.10: a partial chunk (the packet is too short for the length it states) is
/// dropped; the chunks before it are processed. The whole packet was dropped.
#[test]
fn a_partial_chunk_at_the_end_of_a_packet_is_dropped_alone() {
    let mut link = connected_link(91);
    let now = link.now;
    let a = link.server.conn();
    let tsn = a.peer_last_tsn.wrapping_add(1);
    // A DATA chunk that says 40 bytes and has 16.
    let mut partial = data_chunk(tsn.wrapping_add(1), 1, 1, b"cut off");
    partial[2..4].copy_from_slice(&40u16.to_be_bytes());
    partial.truncate(16);
    let raw = packet_to(a, &[data_chunk(tsn, 1, 0, b"whole"), partial]);
    inject(a, now, raw);

    assert!(!a.is_ended());
    assert_eq!(tsn, a.peer_last_tsn, "the complete chunk before it");
    assert_eq!(vec![Bytes::from_static(b"whole")], read_all(a, 1));
}

/// RFC 9260 5.1.1, 6.5: the outgoing streams are 0 to min(own OS, peer's MIS) - 1. A stream
/// past that could be opened, and its DATA was thrown away by the peer.
#[test]
fn a_stream_beyond_the_negotiated_outbound_count_cannot_be_opened() {
    let server = TransportConfig::default().with_max_num_inbound_streams(8);
    let mut link = Link::new(TransportConfig::default(), server, 92);
    link.connect();
    let a = link.client.conn();
    assert_eq!(8, a.my_max_num_outbound_streams);
    let ppi = PayloadProtocolIdentifier::Binary;
    assert!(a.open_stream(7, ppi).is_ok(), "the last valid stream");
    assert!(a.open_stream(8, ppi).is_err(), "one past the peer's MIS");
    assert!(a.open_stream(u16::MAX, ppi).is_err());
}

/// RFC 9260 6.1: the TSNs outstanding stay within what the receiver can acknowledge and order
/// (see `MAX_OUTSTANDING_TSNS`), however large the congestion and receive windows are.
#[test]
fn the_tsns_outstanding_are_bounded_whatever_the_windows() -> Result<()> {
    let mut a = create_association(TransportConfig::default());
    a.control_queue.clear();
    a.timers.stop(Timer::T1Init);
    a.set_state(AssociationState::Established);
    a.cwnd = 64 << 20;
    a.rwnd = 64 << 20;
    let now = Instant::now();
    let ppi = PayloadProtocolIdentifier::Binary;
    let first = a.my_next_tsn;
    {
        let mut s = a.open_stream(1, ppi)?;
        for _ in 0..40_000 {
            s.write_sctp(now, &Bytes::from_static(b"x"), ppi)?;
        }
    }
    let _ = a.gather_outbound(now);
    assert_eq!(
        MAX_OUTSTANDING_TSNS,
        a.my_next_tsn.wrapping_sub(first),
        "TSNs sent before any acknowledgement"
    );

    // Acknowledging some of them lets as many more go.
    a.handle_sack(
        &ChunkSelectiveAck {
            cumulative_tsn_ack: first.wrapping_add(999),
            advertised_receiver_window_credit: 64 << 20,
            gap_ack_blocks: vec![],
            duplicate_tsn: vec![],
        },
        now,
    )?;
    let _ = a.gather_outbound(now);
    assert_eq!(
        MAX_OUTSTANDING_TSNS + 1000,
        a.my_next_tsn.wrapping_sub(first)
    );
    Ok(())
}

/// RFC 9260 9.2: an INIT in SHUTDOWN-ACK-SENT (the SHUTDOWN COMPLETE was lost and the peer
/// starts over) is discarded and the SHUTDOWN ACK is sent again. It closed the association.
#[test]
fn an_init_in_shutdown_ack_sent_repeats_the_shutdown_ack() {
    let mut link = connected_link(93);
    let now = link.now;
    let a = link.server.conn();
    a.set_state(AssociationState::ShutdownAckSent);
    let tag = a.peer_verification_tag;
    let raw = raw_packet(
        a.destination_port,
        a.source_port,
        0,
        &[init_chunk(CT_INIT.0, 0x0BAD_CAFE, 1, &[])],
    );
    inject(a, now, raw);

    assert!(!a.is_ended());
    assert_eq!(AssociationState::ShutdownAckSent, a.state());
    assert_eq!(tag, a.peer_verification_tag);
    let sent = sent_datagrams(a, now);
    assert_eq!(1, chunks_of_type(&sent, CT_SHUTDOWN_ACK.0).len());
    assert!(chunks_of_type(&sent, CT_INIT_ACK.0).is_empty());
}

/// RFC 9260 3.3.2, 3.3.3: an INIT or INIT ACK with a zero Initiate Tag, an a_rwnd below 1500
/// or no streams is discarded, and the state of an existing association does not change.
/// Each of them closed the association it reached.
#[test]
fn invalid_handshake_chunks_leave_the_association_as_it_is() {
    // (Initiate Tag, a_rwnd, outbound streams, inbound streams)
    let invalid = [
        (0u32, 128 * 1024u32, 10u16, 10u16),
        (7, 1499, 10, 10),
        (7, 128 * 1024, 0, 10),
        (7, 128 * 1024, 10, 0),
    ];
    for typ in [CT_INIT.0, CT_INIT_ACK.0] {
        for (tag, a_rwnd, os, mis) in invalid {
            let mut link = connected_link(94);
            let now = link.now;
            let a = link.server.conn();
            let before = (a.peer_verification_tag, a.peer_last_tsn, a.rwnd);
            let mut value = vec![];
            value.extend_from_slice(&tag.to_be_bytes());
            value.extend_from_slice(&a_rwnd.to_be_bytes());
            value.extend_from_slice(&os.to_be_bytes());
            value.extend_from_slice(&mis.to_be_bytes());
            value.extend_from_slice(&9u32.to_be_bytes());
            value.extend_from_slice(&raw_tlv(7, b"cookie"));
            let vtag = if typ == CT_INIT.0 {
                0
            } else {
                a.my_verification_tag
            };
            let raw = raw_packet(
                a.destination_port,
                a.source_port,
                vtag,
                &[raw_chunk(typ, 0, &value)],
            );
            inject(a, now, raw);

            let what = format!("chunk {typ} with tag {tag}, a_rwnd {a_rwnd}, OS {os}, MIS {mis}");
            assert!(!a.is_ended(), "{what} closed the association");
            assert_eq!(AssociationState::Established, a.state(), "{what}");
            assert_eq!(
                before,
                (a.peer_verification_tag, a.peer_last_tsn, a.rwnd),
                "{what}"
            );
        }
    }
}

/// An INIT that is not valid starts no handshake: nothing is answered, and the association
/// the endpoint made for it does not stay for ever.
#[test]
fn an_invalid_first_init_is_not_answered_and_its_association_ends() {
    let mut endpoint = accepting_endpoint();
    let mut now = Instant::now();
    let mut value = vec![];
    value.extend_from_slice(&7u32.to_be_bytes());
    value.extend_from_slice(&100u32.to_be_bytes()); // a_rwnd below 1500
    value.extend_from_slice(&[0, 1, 0, 1]);
    value.extend_from_slice(&9u32.to_be_bytes());
    let init = raw_packet(5000, 5000, 0, &[raw_chunk(CT_INIT.0, 0, &value)]);
    let Some((_, DatagramEvent::NewAssociation(mut a))) =
        endpoint.handle(now, remote(), None, init)
    else {
        panic!("no association");
    };
    assert!(
        sent_datagrams(&mut a, now).is_empty(),
        "nothing is answered"
    );
    let at = a.poll_timeout().expect("the wait for a handshake is timed");
    now = at;
    a.handle_timeout(now);
    assert!(a.is_ended());
}

/// RFC 3758 3.3.2: the Forward-TSN-Supported parameter in an INIT announces PR-SCTP by
/// itself; an INIT without it (and without chunk 192 in Supported Extensions) does not.
#[test]
fn forward_tsn_supported_in_an_init_is_the_peers_support() {
    let (_, a, sent) = accept_init(&[raw_tlv(49152, &[])]);
    assert!(a.unwrap().use_forward_tsn, "parameter 49152 alone");
    assert_eq!(1, chunks_of_type(&sent, CT_INIT_ACK.0).len());

    let (_, a, _) = accept_init(&[]);
    assert!(
        !a.unwrap().use_forward_tsn,
        "an INIT that announces nothing"
    );
}

/// RFC 9260 3.3.3: an INIT ACK in COOKIE-WAIT with Initiate Tag 0, or with no outbound or no
/// inbound streams, ends the attempt: the TCB is destroyed.
#[test]
fn an_init_ack_with_no_tag_or_no_streams_ends_the_handshake() {
    for (tag, os, mis) in [(0u32, 10u16, 10u16), (7, 0, 10), (7, 10, 0)] {
        let mut endpoint = Endpoint::new(
            remote(),
            TransportProtocol::UDP,
            Arc::new(EndpointConfig::default()),
            None,
        );
        let now = Instant::now();
        let (_, mut a) = endpoint
            .connect(
                now,
                ClientConfig::new(TransportConfig::default()),
                "10.0.0.2:5000".parse().unwrap(),
            )
            .unwrap();
        let _ = sent_datagrams(&mut a, now);
        let mut value = vec![];
        value.extend_from_slice(&tag.to_be_bytes());
        value.extend_from_slice(&(128 * 1024u32).to_be_bytes());
        value.extend_from_slice(&os.to_be_bytes());
        value.extend_from_slice(&mis.to_be_bytes());
        value.extend_from_slice(&9u32.to_be_bytes());
        value.extend_from_slice(&raw_tlv(7, b"cookie"));
        let raw = packet_to(&a, &[raw_chunk(CT_INIT_ACK.0, 0, &value)]);
        inject(&mut a, now, raw);

        assert!(a.is_ended(), "INIT ACK with tag {tag}, OS {os}, MIS {mis}");
        assert!(a.poll_timeout().is_none(), "T1-init is stopped");
        let mut failed = false;
        while let Some(e) = a.poll() {
            failed |= matches!(e, Event::HandshakeFailed { .. });
        }
        assert!(failed, "the owner is told the handshake failed");
        assert!(
            chunks_of_type(&sent_datagrams(&mut a, now), CT_COOKIE_ECHO.0).is_empty(),
            "no COOKIE ECHO follows"
        );
    }
}

/// RFC 9260 3.3.6, 8.3: a HEARTBEAT is answered with a HEARTBEAT ACK that carries the
/// Heartbeat Info it was sent with.
#[test]
fn a_heartbeat_is_answered_with_its_own_information() {
    let mut link = connected_link(95);
    let now = link.now;
    let a = link.server.conn();
    let info = raw_tlv(1, b"opaque to the receiver");
    let raw = packet_to(a, &[raw_chunk(CT_HEARTBEAT.0, 0, &info)]);
    inject(a, now, raw);

    let acks = chunks_of_type(&sent_datagrams(a, now), CT_HEARTBEAT_ACK.0);
    assert_eq!(1, acks.len(), "one HEARTBEAT ACK");
    assert_eq!(info, acks[0][4..].to_vec(), "the Heartbeat Info, unchanged");
}
