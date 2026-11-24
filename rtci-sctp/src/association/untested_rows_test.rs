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
