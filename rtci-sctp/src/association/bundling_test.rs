//! RFC 9260 rows closed after the first seven branches: the states DATA and SACK are taken
//! in (section 6), the RTT measurement rules C4, C5 and G1 (6.3.1), and the bundling of
//! control chunks (6.10, 12.4; RFC 3758 3.5 F2).

use super::robustness_test::*;
use super::*;
use crate::chunk::chunk_type::*;

const PPI: PayloadProtocolIdentifier = PayloadProtocolIdentifier::Binary;

fn sack(cumulative: u32, gaps: &[(u16, u16)]) -> ChunkSelectiveAck {
    ChunkSelectiveAck {
        cumulative_tsn_ack: cumulative,
        advertised_receiver_window_credit: 1 << 20,
        gap_ack_blocks: gaps
            .iter()
            .map(
                |(start, end)| crate::chunk::chunk_selective_ack::GapAckBlock {
                    start: *start,
                    end: *end,
                },
            )
            .collect(),
        duplicate_tsn: vec![],
    }
}

fn types_of(datagram: &Bytes) -> Vec<u8> {
    chunks_of(datagram).iter().map(|c| c[0]).collect()
}

// ---- section 6: states --------------------------------------------------------------------

/// RFC 9260 section 6: DATA is received by the normal rules in ESTABLISHED,
/// SHUTDOWN-PENDING and SHUTDOWN-SENT. Elsewhere it is
/// discarded; for an association that has seen no COOKIE ECHO it is out of the blue and
/// answered with an ABORT, and so is a SACK. DATA used to be taken in every state.
#[test]
fn data_is_received_only_in_the_states_that_take_it() {
    for (state, taken) in [
        (AssociationState::Established, true),
        (AssociationState::ShutdownPending, true),
        (AssociationState::ShutdownSent, true),
        (AssociationState::CookieEchoed, false),
        (AssociationState::CookieWait, false),
        (AssociationState::ShutdownReceived, false),
        (AssociationState::ShutdownAckSent, false),
        (AssociationState::Closed, false),
    ] {
        let mut link = connected_link(901);
        let now = link.now;
        let a = link.server.conn();
        let tsn = a.peer_last_tsn.wrapping_add(1);
        let _ = sent_datagrams(a, now);
        a.set_state(state);
        let raw = packet_to(a, &[data_chunk(tsn, 1, 0, b"data")]);
        inject(a, now, raw);
        assert_eq!(taken, a.peer_last_tsn == tsn, "{state}: the cumulative TSN");
        assert_eq!(taken, read_all(a, 1).len() == 1, "{state}: delivery");

        let sent = sent_after(a, now, Duration::from_secs(1));
        let aborts = chunks_of_type(&sent, CT_ABORT.0);
        if state == AssociationState::Closed {
            // Out of the blue (8.4): the ABORT reflects the packet's tag, T bit set.
            assert_eq!(1, aborts.len(), "DATA before the COOKIE ECHO");
            assert_eq!(1, aborts[0][1] & 1, "the T bit");
            assert!(!a.is_ended());
            let raw = packet_to(a, &[chunk_bytes(&sack(a.my_next_tsn.wrapping_sub(1), &[]))]);
            inject(a, now, raw);
            let sent = sent_datagrams(a, now);
            assert_eq!(
                1,
                chunks_of_type(&sent, CT_ABORT.0).len(),
                "a SACK likewise"
            );
        } else {
            assert!(aborts.is_empty(), "{state}");
            assert_eq!(
                taken,
                !chunks_of_type(&sent, CT_SACK.0).is_empty(),
                "{state}: only DATA that is taken is acknowledged"
            );
        }
    }
}

// ---- section 6.3.1: RTT measurements --------------------------------------------------------

/// RFC 9260 6.3.1 G1: an RTTVAR of zero is replaced by the clock granularity.
#[test]
fn a_zero_rttvar_becomes_the_clock_granularity() {
    let mut rto = RtoManager::new();
    rto.set_new_rtt(0);
    assert_eq!(1.0, rto.rttvar);
    let mut rto = RtoManager::new();
    rto.set_new_rtt(100);
    assert_eq!(50.0, rto.rttvar, "the first measurement: R / 2");
}

fn four_chunks_sent(a: &mut Association, now: Instant, len: usize) -> u32 {
    a.rto_mgr.set_rto(1000, false);
    let first = a.my_next_tsn;
    let mut stream = a.open_stream(1, PPI).unwrap();
    for _ in 0..4 {
        stream
            .write_sctp(now, &Bytes::from(vec![7; len]), PPI)
            .unwrap();
    }
    assert_eq!(4, transmitted_data(&a.gather_outbound(now).0).len());
    first
}

/// RFC 9260 6.3.1 C4: one RTT measurement per round trip. A SACK that acknowledged one chunk
/// by its Cumulative TSN Ack and others by Gap Ack Blocks used to measure with each.
#[test]
fn one_rtt_measurement_is_made_per_round_trip() -> Result<()> {
    let mut a = timed_test_association();
    let now = Instant::now();
    let first = four_chunks_sent(&mut a, now, 5);

    a.handle_sack(&sack(first, &[(2, 3)]), now + Duration::from_millis(100))?;
    assert_eq!(100, a.rto_mgr.srtt);
    assert_eq!(
        50.0, a.rto_mgr.rttvar,
        "a second measurement from the same SACK would have changed RTTVAR"
    );
    Ok(())
}

/// RFC 9260 6.3.1 C5 (Karn): after a retransmission no RTT is measured with a chunk sent
/// before it, whose acknowledgement may be for what was sent again.
#[test]
fn no_rtt_is_measured_across_a_retransmission() -> Result<()> {
    let mut a = timed_test_association();
    let now = Instant::now();
    // Four full packets: the retransmission after the timeout is the first of them alone.
    let full = a.max_payload_size as usize;
    let first = four_chunks_sent(&mut a, now, full);

    let expiry = a.timers.get(Timer::T3RTX).expect("T3-rtx runs");
    a.handle_timeout(expiry);
    let again = transmitted_data(&a.gather_outbound(expiry).0);
    assert_eq!(1, again.len(), "the retransmission: one packet");
    // The SACK for all four: three of them were sent once, before the retransmission.
    a.handle_sack(
        &sack(first.wrapping_add(3), &[]),
        expiry + Duration::from_millis(30),
    )?;
    assert_eq!(0, a.rto_mgr.srtt, "no measurement");

    // DATA sent after the retransmission measures again.
    let later = expiry + Duration::from_millis(40);
    a.stream(1)?
        .write_sctp(later, &Bytes::from_static(b"chunk"), PPI)?;
    assert_eq!(1, transmitted_data(&a.gather_outbound(later).0).len());
    a.handle_sack(
        &sack(first.wrapping_add(4), &[]),
        later + Duration::from_millis(70),
    )?;
    assert_eq!(70, a.rto_mgr.srtt);
    Ok(())
}

// ---- sections 6.10 and 12.4: bundling -----------------------------------------------------

/// RFC 9260 12.4: one received packet is answered with at most one packet of chunks other
/// than DATA. A packet of HEARTBEATs used to get a packet per HEARTBEAT ACK, and DATA
/// bundled with a stream reset a packet for the response and one for the SACK.
#[test]
fn one_packet_answers_one_received_packet() {
    let mut link = connected_link(902);
    let now = link.now;
    let a = link.server.conn();
    let _ = sent_datagrams(a, now);

    let heartbeat = |n: u8| raw_chunk(CT_HEARTBEAT.0, 0, &raw_tlv(1, &[n; 8]));
    let raw = packet_to(a, &[heartbeat(1), heartbeat(2), heartbeat(3)]);
    inject(a, now, raw);
    let sent = sent_datagrams(a, now);
    assert_eq!(1, sent.len(), "three HEARTBEAT ACKs in one packet");
    assert_eq!(vec![CT_HEARTBEAT_ACK.0; 3], types_of(&sent[0]));

    // DATA, a stream reset and an unknown chunk that is to be reported: the response, the
    // ERROR and the SACK share a packet.
    let tsn = a.peer_last_tsn.wrapping_add(1);
    let rsn = a.peer_rsn_window.expect("known from the INIT").1;
    a.create_stream(1, true, PPI);
    a.streams.get_mut(&1).unwrap().state = RecvSendState::Closed;
    a.streams.get_mut(&1).unwrap().outgoing_reset_started = true;
    let reset = chunk_bytes(&ChunkReconfig {
        param_a: Some(Box::new(ParamOutgoingResetRequest {
            reconfig_request_sequence_number: rsn,
            reconfig_response_sequence_number: 0,
            sender_last_tsn: tsn,
            stream_identifiers: vec![1],
        })),
        param_b: None,
    });
    let unknown = raw_chunk(0x7f, 0, b"what");
    let raw = packet_to(a, &[data_chunk(tsn, 2, 0, b"data"), reset, unknown]);
    inject(a, now, raw);
    let sent = sent_datagrams(a, now);
    assert_eq!(
        1,
        sent.len(),
        "{:?}",
        sent.iter().map(types_of).collect::<Vec<_>>()
    );
    let mut types = types_of(&sent[0]);
    types.sort_unstable();
    assert_eq!(vec![CT_SACK.0, CT_ERROR.0, CT_RECONFIG.0], types);
    assert!(sent[0].len() <= a.mtu as usize);

    // More answers than a packet holds: one packet all the same.
    let many: Vec<Vec<u8>> = (0..100u8)
        .map(|n| raw_chunk(CT_HEARTBEAT.0, 0, &raw_tlv(1, &[n; 40])))
        .collect();
    let raw = raw_packet(
        a.destination_port,
        a.source_port,
        a.my_verification_tag,
        &many,
    );
    inject(a, now, raw);
    let sent = sent_datagrams(a, now);
    assert_eq!(1, sent.len());
    assert!(sent[0].len() <= a.mtu as usize);
    let acks = types_of(&sent[0]);
    assert!(
        acks.len() > 10 && acks.len() < 100,
        "{} HEARTBEAT ACKs",
        acks.len()
    );
    assert!(acks.iter().all(|t| *t == CT_HEARTBEAT_ACK.0));
    assert!(!a.is_ended());
}

/// RFC 9260 6.1, 6.10: a SACK that is due is bundled with outbound DATA when the packet has
/// room, ahead of the DATA chunks; a packet that is full is left alone.
#[test]
fn a_sack_travels_with_outbound_data() -> Result<()> {
    let mut a = timed_test_association();
    let now = Instant::now();
    let base = a.peer_last_tsn;
    a.open_stream(1, PPI)?;

    // DATA arrives (the first is acknowledged at once) and a small message is to be sent.
    a.handle_data(&ChunkPayloadData {
        tsn: base.wrapping_add(1),
        stream_identifier: 2,
        beginning_fragment: true,
        ending_fragment: true,
        payload_type: PPI,
        user_data: Bytes::from_static(b"in"),
        ..Default::default()
    })?;
    a.handle_chunk_end(now);
    a.stream(1)?
        .write_sctp(now, &Bytes::from_static(b"out"), PPI)?;
    let out = a.gather_outbound(now).0;
    assert_eq!(1, out.len());
    assert_eq!(vec![CT_SACK.0, CT_PAYLOAD_DATA.0], types_of(&out[0]));
    let packet = Packet::unmarshal(&out[0])?;
    assert_eq!(
        2,
        packet.chunks.len(),
        "the packet is whole, checksum included"
    );

    // A full packet of DATA: the SACK goes alone.
    a.handle_data(&ChunkPayloadData {
        tsn: base.wrapping_add(2),
        stream_identifier: 2,
        stream_sequence_number: 1,
        beginning_fragment: true,
        ending_fragment: true,
        immediate_sack: true,
        payload_type: PPI,
        user_data: Bytes::from_static(b"in"),
        ..Default::default()
    })?;
    a.handle_chunk_end(now);
    let full = a.max_payload_size as usize;
    a.stream(1)?
        .write_sctp(now, &Bytes::from(vec![1; full]), PPI)?;
    let out = a.gather_outbound(now).0;
    assert_eq!(
        vec![vec![CT_PAYLOAD_DATA.0], vec![CT_SACK.0]],
        out.iter().map(types_of).collect::<Vec<_>>()
    );
    assert!(out.iter().all(|p| p.len() <= a.mtu as usize));
    Ok(())
}

/// RFC 3758 3.5 F4: a SACK is out of order when its Cumulative TSN Ack is behind the
/// Cumulative TSN Ack Point, not when it is behind the Advanced.Peer.Ack.Point: one that
/// lies between the two is processed.
#[test]
fn a_sack_between_the_ack_point_and_the_advanced_point_is_processed() -> Result<()> {
    let mut a = timed_test_association();
    let now = Instant::now();
    let first = a.my_next_tsn;
    let mut stream = a.open_stream(1, PPI)?;
    stream.set_reliability_params(false, ReliabilityType::Rexmit, 0)?;
    for _ in 0..3 {
        stream.write_sctp(now, &Bytes::from_static(b"unreliable"), PPI)?;
    }
    assert_eq!(3, transmitted_data(&a.gather_outbound(now).0).len());
    let expiry = a.timers.get(Timer::T3RTX).expect("T3-rtx runs");
    a.handle_timeout(expiry);
    let _ = a.gather_outbound(expiry);
    assert_eq!(first.wrapping_add(2), a.advanced_peer_tsn_ack_point);
    assert_eq!(first.wrapping_sub(1), a.cumulative_tsn_ack_point);

    a.handle_sack(&sack(first.wrapping_add(1), &[]), expiry)?;
    assert_eq!(first.wrapping_add(1), a.cumulative_tsn_ack_point);
    assert_eq!(first.wrapping_add(2), a.advanced_peer_tsn_ack_point);
    // One behind the Cumulative TSN Ack Point is out of order and changes nothing.
    a.handle_sack(&sack(first, &[]), expiry)?;
    assert_eq!(first.wrapping_add(1), a.cumulative_tsn_ack_point);
    Ok(())
}

/// RFC 3758 3.5 F2: a FORWARD TSN is bundled with outbound DATA when there is some.
#[test]
fn a_forward_tsn_travels_with_outbound_data() -> Result<()> {
    let mut a = timed_test_association();
    let now = Instant::now();
    let mut stream = a.open_stream(1, PPI)?;
    stream.set_reliability_params(false, ReliabilityType::Rexmit, 0)?;
    stream.write_sctp(now, &Bytes::from_static(b"unreliable"), PPI)?;
    assert_eq!(1, transmitted_data(&a.gather_outbound(now).0).len());

    // The message is abandoned at the T3-rtx expiry; new DATA is waiting by then.
    let expiry = a.timers.get(Timer::T3RTX).expect("T3-rtx runs");
    a.stream(1)?
        .write_sctp(expiry, &Bytes::from_static(b"the next one"), PPI)?;
    a.handle_timeout(expiry);
    let out = a.gather_outbound(expiry).0;
    assert_eq!(
        vec![vec![CT_FORWARD_TSN.0, CT_PAYLOAD_DATA.0]],
        out.iter().map(types_of).collect::<Vec<_>>(),
        "the FORWARD TSN ahead of the DATA, in its packet"
    );
    Packet::unmarshal(&out[0])?;
    Ok(())
}
