//! Behaviour the engine had and no test held: clauses of RFC 9260, RFC 3758, RFC 7496 and
//! RFC 9653 that the conformance audit found implemented and untested.

use super::robustness_test::*;
use super::*;
use crate::chunk::chunk_type::*;
use crate::endpoint::{DatagramEvent, Endpoint};
use crate::{ClientConfig, EndpointConfig, TimerConfig};

const PPI: PayloadProtocolIdentifier = PayloadProtocolIdentifier::Binary;

fn established(config: TransportConfig) -> Association {
    let mut a = create_association(config);
    a.control_queue.clear();
    a.timers.stop(Timer::T1Init);
    a.set_state(AssociationState::Established);
    a.use_forward_tsn = true;
    a.rwnd = 1 << 20;
    a.ssthresh = 1 << 20;
    a.rto_mgr.set_rto(1000, true);
    a
}

fn connecting() -> (Association, Instant) {
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
    (a, now)
}

/// RFC 9260 6.8 (and RFC 9653 5.3 for an endpoint that has not announced zero checksum): a
/// packet whose CRC32c is wrong, or zero, is discarded without an answer.
#[test]
fn a_packet_with_a_wrong_or_zero_checksum_is_discarded() {
    let good = raw_packet(
        5000,
        5000,
        0,
        &[init_chunk(CT_INIT.0, 0xAABB_CCDD, 100, &[])],
    );
    let mut wrong = good.to_vec();
    wrong[8] ^= 0x01;
    let mut zero = good.to_vec();
    zero[8..12].fill(0);

    let mut endpoint = accepting_endpoint();
    let now = Instant::now();
    for bad in [wrong, zero] {
        assert!(
            endpoint
                .handle(now, remote(), None, Bytes::from(bad))
                .is_none(),
            "a packet with a bad checksum was taken"
        );
        assert!(endpoint.poll_transmit().is_none(), "and answered");
    }
    assert!(matches!(
        endpoint.handle(now, remote(), None, good),
        Some((_, DatagramEvent::NewAssociation(_)))
    ));
}

/// RFC 9260 3.1: port 0 is not used. A packet from or to port 0 is not answered.
#[test]
fn a_packet_with_port_zero_is_not_answered() {
    for (source, destination) in [(0u16, 5000u16), (5000, 0)] {
        let mut endpoint = accepting_endpoint();
        let now = Instant::now();
        let init = raw_packet(
            source,
            destination,
            0,
            &[init_chunk(CT_INIT.0, 0xAABB_CCDD, 100, &[])],
        );
        if let Some((_, DatagramEvent::NewAssociation(mut a))) =
            endpoint.handle(now, remote(), None, init)
        {
            assert!(
                sent_datagrams(&mut a, now).is_empty(),
                "an INIT between ports {source} and {destination} was answered"
            );
        }
    }
}

/// RFC 9653 4: an endpoint that does not do zero checksum takes an INIT that offers it
/// (parameter 0x8001) like any other, and does not report the parameter.
#[test]
fn an_init_offering_zero_checksum_is_accepted() {
    let zero_checksum = raw_tlv(0x8001, &[0, 0, 0, 1]);
    let (_, a, sent) = accept_init(&[zero_checksum]);
    assert!(a.is_some());
    let init_acks = chunks_of_type(&sent, CT_INIT_ACK.0);
    assert_eq!(1, init_acks.len());
    let params = tlvs(&init_acks[0][20..]);
    assert!(
        params.iter().all(|(typ, _)| *typ != 8 && *typ != 0x8001),
        "neither reported nor echoed: {params:?}"
    );
    // The INIT ACK carries a CRC32c, as everything this endpoint sends.
    assert!(crate::packet::PartialDecode::unmarshal(&sent[0]).is_ok());
}

/// RFC 9260 6.5: the Stream Sequence Number after 65535 is 0.
#[test]
fn the_stream_sequence_number_wraps_to_zero() -> Result<()> {
    let mut a = established(TransportConfig::default());
    let now = Instant::now();
    a.open_stream(1, PPI)?;
    a.streams.get_mut(&1).unwrap().sequence_number = 65535;
    for _ in 0..2 {
        a.stream(1)?
            .write_sctp(now, &Bytes::from_static(b"x"), PPI)?;
    }
    let sent = transmitted_data(&a.gather_outbound(now).0);
    assert_eq!(
        vec![65535, 0],
        sent.iter()
            .map(|c| c.stream_sequence_number)
            .collect::<Vec<_>>()
    );
    Ok(())
}

/// RFC 9260 6.10: the DATA chunks bundled in a packet are in increasing TSN order.
#[test]
fn data_chunks_in_a_packet_are_in_tsn_order() -> Result<()> {
    let mut a = established(TransportConfig::default());
    let now = Instant::now();
    let first = a.my_next_tsn;
    {
        let mut s = a.open_stream(1, PPI)?;
        for _ in 0..10 {
            s.write_sctp(now, &Bytes::from_static(b"small"), PPI)?;
        }
    }
    let datagrams = a.gather_outbound(now).0;
    assert_eq!(1, datagrams.len(), "ten small chunks share a packet");
    let tsns: Vec<u32> = transmitted_data(&datagrams).iter().map(|c| c.tsn).collect();
    assert_eq!(
        (0..10).map(|i| first.wrapping_add(i)).collect::<Vec<_>>(),
        tsns
    );
    Ok(())
}

/// RFC 9260 5, 5.1, 6: no DATA before the association is established. While the handshake
/// runs a write is refused and nothing but the handshake chunks is sent.
#[test]
fn no_data_is_sent_before_the_association_is_established() {
    let (mut a, now) = connecting();
    assert_eq!(AssociationState::CookieWait, a.state());
    let mut s = a.open_stream(1, PPI).unwrap();
    assert!(
        s.write_sctp(now, &Bytes::from_static(b"early"), PPI)
            .is_err()
    );
    assert!(sent_datagrams(&mut a, now).is_empty());

    let init_ack = init_chunk(CT_INIT_ACK.0, 4242, 9000, &[raw_tlv(7, b"cookie")]);
    let raw = packet_to(&a, &[init_ack]);
    inject(&mut a, now, raw);
    assert_eq!(AssociationState::CookieEchoed, a.state());
    assert!(
        a.stream(1)
            .unwrap()
            .write_sctp(now, &Bytes::from_static(b"early"), PPI)
            .is_err()
    );
    let sent = sent_datagrams(&mut a, now);
    assert_eq!(1, sent.len(), "the COOKIE ECHO and nothing else");
    assert_eq!(
        vec![CT_COOKIE_ECHO.0],
        chunks_of(&sent[0]).iter().map(|c| c[0]).collect::<Vec<_>>()
    );
}

/// RFC 9260 6: a SACK outside ESTABLISHED, SHUTDOWN-PENDING and SHUTDOWN-RECEIVED is
/// discarded.
#[test]
fn a_sack_outside_the_data_states_is_discarded() -> Result<()> {
    for state in [
        AssociationState::CookieEchoed,
        AssociationState::ShutdownSent,
        AssociationState::ShutdownAckSent,
    ] {
        let mut a = established(TransportConfig::default());
        let now = Instant::now();
        let first = a.my_next_tsn;
        a.open_stream(1, PPI)?
            .write_sctp(now, &Bytes::from_static(b"x"), PPI)?;
        let _ = a.gather_outbound(now);
        a.set_state(state);
        a.handle_sack(
            &ChunkSelectiveAck {
                cumulative_tsn_ack: first,
                advertised_receiver_window_credit: 5,
                gap_ack_blocks: vec![],
                duplicate_tsn: vec![],
            },
            now,
        )?;
        assert_eq!(first.wrapping_sub(1), a.cumulative_tsn_ack_point, "{state}");
        assert_eq!(1, a.inflight_queue.len(), "{state}");
    }
    Ok(())
}

/// RFC 9260 6.2.1 (D i): a SACK whose Cumulative TSN Ack is behind the ack point is out of
/// order and is dropped: its a_rwnd is not taken.
#[test]
fn a_sack_behind_the_ack_point_is_dropped() -> Result<()> {
    let mut a = established(TransportConfig::default());
    let now = Instant::now();
    let first = a.my_next_tsn;
    {
        let mut s = a.open_stream(1, PPI)?;
        for _ in 0..3 {
            s.write_sctp(now, &Bytes::from_static(b"x"), PPI)?;
        }
    }
    let _ = a.gather_outbound(now);
    let sack = |cumulative: u32, a_rwnd: u32| ChunkSelectiveAck {
        cumulative_tsn_ack: cumulative,
        advertised_receiver_window_credit: a_rwnd,
        gap_ack_blocks: vec![],
        duplicate_tsn: vec![],
    };
    a.handle_sack(&sack(first.wrapping_add(1), 50_000), now)?;
    let rwnd = a.rwnd;
    a.handle_sack(&sack(first, 7), now)?;
    assert_eq!(first.wrapping_add(1), a.cumulative_tsn_ack_point);
    assert_eq!(rwnd, a.rwnd, "the window of an old SACK is not taken");
    Ok(())
}

/// RFC 9260 3.3.2, 3.3.3, 5.3.1: the initial TSN and the Verification Tag are random, and
/// each association gets its own.
#[test]
fn initial_tsns_and_tags_differ_between_associations() {
    let mut endpoint = Endpoint::new(
        remote(),
        TransportProtocol::UDP,
        Arc::new(EndpointConfig::default()),
        None,
    );
    let now = Instant::now();
    let mut tsns = std::collections::HashSet::new();
    let mut tags = std::collections::HashSet::new();
    for port in 0..16u16 {
        let peer: SocketAddr = format!("10.0.0.2:{}", 6000 + port).parse().unwrap();
        let (_, a) = endpoint
            .connect(now, ClientConfig::new(TransportConfig::default()), peer)
            .unwrap();
        assert_ne!(0, a.verification_tag());
        tsns.insert(a.my_next_tsn);
        tags.insert(a.verification_tag());
    }
    assert_eq!(16, tags.len(), "a tag of its own for each association");
    assert!(tsns.len() >= 15, "initial TSNs are not random: {tsns:?}");
}

/// RFC 9260 9.2: an unanswered SHUTDOWN ACK is retransmitted on T2-shutdown, a limited number
/// of times, and then the association is over.
#[test]
fn an_unanswered_shutdown_ack_is_given_up() -> Result<()> {
    let mut a = established(TransportConfig::default().with_timer_config(TimerConfig {
        max_t2_shutdown_retrans: 3,
        ..TimerConfig::default()
    }));
    let mut now = Instant::now();
    a.handle_shutdown(
        &ChunkShutdown {
            cumulative_tsn_ack: a.my_next_tsn.wrapping_sub(1),
        },
        now,
    )?;
    assert_eq!(AssociationState::ShutdownAckSent, a.state());
    let mut acks = chunks_of_type(&sent_datagrams(&mut a, now), CT_SHUTDOWN_ACK.0).len();
    while let Some(at) = a.poll_timeout() {
        now = at;
        a.handle_timeout(now);
        acks += chunks_of_type(&sent_datagrams(&mut a, now), CT_SHUTDOWN_ACK.0).len();
        assert!(acks < 20);
    }
    assert_eq!(4, acks, "the SHUTDOWN ACK and three retransmissions");
    assert!(a.is_ended());
    Ok(())
}

/// RFC 9260 6.10: DATA is not bundled with SHUTDOWN. The SHUTDOWN follows the last
/// acknowledgement, alone in its packet.
#[test]
fn a_shutdown_travels_without_data() -> Result<()> {
    let mut a = established(TransportConfig::default());
    let now = Instant::now();
    let first = a.my_next_tsn;
    a.open_stream(1, PPI)?
        .write_sctp(now, &Bytes::from_static(b"last"), PPI)?;
    a.shutdown()?;
    let sent = a.gather_outbound(now).0;
    assert!(
        chunks_of_type(&sent, CT_SHUTDOWN.0).is_empty(),
        "DATA first"
    );
    a.handle_sack(
        &ChunkSelectiveAck {
            cumulative_tsn_ack: first,
            advertised_receiver_window_credit: 1 << 20,
            gap_ack_blocks: vec![],
            duplicate_tsn: vec![],
        },
        now,
    )?;
    let sent = a.gather_outbound(now).0;
    let with_shutdown: Vec<&Bytes> = sent
        .iter()
        .filter(|d| chunks_of(d).iter().any(|c| c[0] == CT_SHUTDOWN.0))
        .collect();
    assert_eq!(1, with_shutdown.len());
    assert_eq!(1, chunks_of(with_shutdown[0]).len(), "SHUTDOWN is alone");
    Ok(())
}

/// RFC 3758 3.2: the flags of a FORWARD TSN are ignored on receipt.
#[test]
fn forward_tsn_flags_are_ignored() {
    let mut link = connected_link(601);
    let now = link.now;
    let a = link.server.conn();
    let target = a.peer_last_tsn.wrapping_add(3);
    let raw = packet_to(
        a,
        &[raw_chunk(CT_FORWARD_TSN.0, 0xFF, &target.to_be_bytes())],
    );
    inject(a, now, raw);
    assert_eq!(target, a.peer_last_tsn);
}

/// RFC 3758 3.5 (F5), RFC 7496 3.1: abandoning a message at a retransmission timeout, in
/// place of retransmitting it, still does what the timeout does to the congestion window and
/// the RTO.
#[test]
fn abandoning_at_a_timeout_still_adjusts_the_window_and_the_rto() -> Result<()> {
    let mut a = established(TransportConfig::default());
    a.rto_mgr.set_rto(1000, false);
    let now = Instant::now();
    a.cwnd = 20 * a.pmdcs;
    {
        let mut s = a.open_stream(1, PPI)?;
        s.set_reliability_params(false, ReliabilityType::Rexmit, 0)?;
        s.write_sctp(now, &Bytes::from(vec![0u8; 1000]), PPI)?;
    }
    assert_eq!(1, transmitted_data(&a.gather_outbound(now).0).len());
    let (cwnd, pmdcs) = (a.cwnd, a.pmdcs);

    let at = a.timers.get(Timer::T3RTX).expect("T3-rtx runs");
    a.handle_timeout(at);
    let datagrams = a.gather_outbound(at).0;
    assert!(
        transmitted_data(&datagrams).is_empty(),
        "abandoned, not retransmitted"
    );
    assert_eq!(1, chunks_of_type(&datagrams, CT_FORWARD_TSN.0).len());
    assert_eq!(pmdcs, a.cwnd);
    assert_eq!(std::cmp::max(cwnd / 2, 4 * pmdcs), a.ssthresh);
    assert_eq!(Duration::from_secs(2), a.rto(), "the RTO backed off");
    Ok(())
}

/// RFC 7496 3.1: the retransmission limit of a message does not change Association.Max.Retrans.
/// A FORWARD TSN the peer never acknowledges still ends the association at the limit.
#[test]
fn a_limited_retransmission_stream_still_reaches_the_association_limit() -> Result<()> {
    let mut a = established(TransportConfig::default().with_timer_config(TimerConfig {
        max_t3_rtx_retrans: 3,
        ..TimerConfig::default()
    }));
    let now = Instant::now();
    {
        let mut s = a.open_stream(1, PPI)?;
        s.set_reliability_params(false, ReliabilityType::Rexmit, 0)?;
        s.write_sctp(now, &Bytes::from_static(b"never acknowledged"), PPI)?;
    }
    let _ = a.gather_outbound(now);
    let mut expiries = 0;
    while let Some(at) = a.poll_timeout() {
        a.handle_timeout(at);
        let _ = a.gather_outbound(at);
        expiries += 1;
        assert!(expiries < 20);
    }
    assert_eq!(4, expiries, "three tolerated, the fourth ends it");
    assert!(a.is_ended());
    Ok(())
}

// ---- Rows the third audit sweep found untested (2026-11-26) ---------------------------------

/// Hands `raw` to `a` as a datagram from its peer, as the endpoint would: a packet whose first
/// chunk header does not decode goes to no association. Whether it got there.
fn deliver(a: &mut Association, now: Instant, raw: Bytes) -> bool {
    if crate::packet::PartialDecode::unmarshal(&raw).is_err() {
        return false;
    }
    inject(a, now, raw);
    true
}

/// Whether `a` closed: ended, or an `AssociationClosed` event waiting.
fn closed(a: &mut Association) -> bool {
    let mut closed = a.is_ended();
    while let Some(e) = a.poll() {
        closed |= matches!(e, Event::AssociationClosed { .. });
    }
    closed
}

/// After a packet the association had to leave alone: it still stands, it sent no ABORT, and
/// the next DATA from the peer is delivered. Each departure as a line of `failures`.
fn still_stands(a: &mut Association, now: Instant, case: &str, failures: &mut Vec<String>) {
    if closed(a) {
        failures.push(format!("{case}: the association closed"));
        return;
    }
    if !chunks_of_type(&sent_after(a, now, Duration::from_secs(1)), CT_ABORT.0).is_empty() {
        failures.push(format!("{case}: an ABORT was sent"));
    }
    let tsn = a.peer_last_tsn.wrapping_add(1);
    let raw = packet_to(a, &[data_chunk(tsn, 1, 0, b"after")]);
    inject(a, now + Duration::from_secs(1), raw);
    if read_all(a, 1) != vec![Bytes::from_static(b"after")] {
        failures.push(format!("{case}: the DATA after it was not delivered"));
    }
}

/// RFC 9260 3.2: the Chunk Length counts the Type, Flags and Length fields, so "if the Chunk
/// Value field is zero-length, the Length field will be set to 4". A Chunk Length below 4 is
/// no chunk: an ABORT whose Chunk Length says 0, 2 or 3, first in its packet or after a PAD
/// chunk, is not taken as an ABORT (the packet is dropped), and nothing is answered.
#[test]
fn a_chunk_length_below_four_is_no_chunk() {
    let mut failures = vec![];
    for length in [0u16, 2, 3] {
        for after_pad in [false, true] {
            let case = format!("Chunk Length {length}, after a PAD chunk: {after_pad}");
            let mut link = connected_link(97);
            let now = link.now;
            let a = link.server.conn();
            let _ = sent_datagrams(a, now);
            let mut abort = raw_chunk(CT_ABORT.0, 0, &[]);
            abort[2..4].copy_from_slice(&length.to_be_bytes());
            let mut chunks = vec![];
            if after_pad {
                chunks.push(raw_chunk(CT_PAD.0, 0, &[0; 4]));
            }
            chunks.push(abort);
            let raw = packet_to(a, &chunks);
            deliver(a, now, raw);
            still_stands(a, now, &case, &mut failures);
        }
    }
    assert!(failures.is_empty(), "{failures:#?}");
}

/// RFC 9260 3.3.7: "If an endpoint receives an ABORT chunk with a format error [...], it MUST
/// silently discard it." The value of an ABORT is zero or more error causes (3.3.10), each a
/// four-byte header and its value: an ABORT holding two bytes that are no cause, one whose
/// cause says it is longer than the chunk, and one whose cause says it is shorter than its
/// own header all end nothing and are not answered.
#[test]
fn an_abort_with_a_format_error_is_silently_discarded() {
    let mut overrun = raw_tlv(12, b"why");
    overrun[2..4].copy_from_slice(&40u16.to_be_bytes());
    let mut short = raw_tlv(12, b"why");
    short[2..4].copy_from_slice(&2u16.to_be_bytes());
    let cases = [
        ("two bytes that are no error cause", vec![0u8, 12]),
        ("a cause longer than the chunk", overrun),
        ("a cause shorter than its header", short),
    ];
    let mut failures = vec![];
    for (case, value) in cases {
        let mut link = connected_link(98);
        let now = link.now;
        let a = link.server.conn();
        let _ = sent_datagrams(a, now);
        let raw = packet_to(a, &[raw_chunk(CT_ABORT.0, 0, &value)]);
        deliver(a, now, raw);
        still_stands(a, now, case, &mut failures);
    }
    assert!(failures.is_empty(), "{failures:#?}");

    // The same chunk well formed (one cause, padded or not) still ends the association.
    for value in [raw_tlv(12, b"why"), raw_tlv(12, b"why!")] {
        let mut link = connected_link(99);
        let now = link.now;
        let a = link.server.conn();
        let raw = packet_to(a, &[raw_chunk(CT_ABORT.0, 0, &value)]);
        inject(a, now, raw);
        assert!(
            closed(a),
            "a well-formed ABORT ({} bytes of cause)",
            value.len()
        );
    }
}

/// RFC 9260 3.3.2.1.5: in Supported Address Types, "the value indicating the Host Name
/// Address parameter [...] MUST be ignored when receiving this parameter". An INIT listing
/// type 11 among its address types is answered with an INIT ACK like any other: no ABORT
/// (that answers a Host Name Address parameter, 3.3.2.1.4), no Unresolvable Address, no
/// report.
#[test]
fn a_host_name_in_supported_address_types_is_ignored() {
    let mut failures = vec![];
    for types in [vec![5u16, 11], vec![11], vec![11, 6], vec![5, 6, 11]] {
        let value: Vec<u8> = types.iter().flat_map(|t| t.to_be_bytes()).collect();
        let (_, a, sent) = accept_init(&[raw_tlv(12, &value)]);
        let Some(mut a) = a else {
            failures.push(format!("{types:?}: no association"));
            continue;
        };
        if closed(&mut a) {
            failures.push(format!("{types:?}: the association closed"));
        }
        if !chunks_of_type(&sent, CT_ABORT.0).is_empty() {
            failures.push(format!("{types:?}: answered with an ABORT"));
        }
        let init_acks = chunks_of_type(&sent, CT_INIT_ACK.0);
        match init_acks.as_slice() {
            [init_ack] => {
                if tlvs(&init_ack[20..])
                    .iter()
                    .any(|(typ, _)| *typ == PARAM_UNRECOGNIZED_PARAMETER)
                {
                    failures.push(format!("{types:?}: reported as unrecognized"));
                }
            }
            _ => failures.push(format!("{types:?}: {} INIT ACKs", init_acks.len())),
        }
    }
    assert!(failures.is_empty(), "{failures:#?}");
}
