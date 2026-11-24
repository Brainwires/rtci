//! RFC 9260 section 9.2: the Cumulative TSN Ack a SHUTDOWN carries, both ways.

use super::*;

fn shutdown_chunks(packets: &[Bytes]) -> Vec<u32> {
    packets
        .iter()
        .flat_map(|raw| Packet::unmarshal(raw).unwrap().chunks)
        .filter_map(|c| {
            c.as_any()
                .downcast_ref::<ChunkShutdown>()
                .map(|s| s.cumulative_tsn_ack)
        })
        .collect()
}

/// The SHUTDOWN sender reports the last TSN it received in sequence from the peer
/// (`peer_last_tsn`), not its own acknowledgement point for the DATA it sent.
#[test]
fn shutdown_carries_the_last_tsn_received_from_the_peer() -> Result<()> {
    let mut a = timed_test_association();
    let now = Instant::now();
    a.peer_last_tsn = 1000;
    a.my_next_tsn = 5001;
    a.cumulative_tsn_ack_point = 5000;
    a.advanced_peer_tsn_ack_point = 5000;

    a.shutdown()?;
    assert_eq!(AssociationState::ShutdownSent, a.state());

    let sent = shutdown_chunks(&a.gather_outbound(now).0);
    assert_eq!(vec![1000], sent, "the peer's last in-sequence TSN");
    Ok(())
}

/// A SHUTDOWN acknowledges the receiver's outstanding DATA up to its Cumulative TSN Ack, so an
/// endpoint whose last SACK crossed the peer's SHUTDOWN does not wait for T3-rtx: it drains
/// and answers with SHUTDOWN ACK at once.
#[test]
fn shutdown_acknowledges_outstanding_data() -> Result<()> {
    let mut a = timed_test_association();
    let now = Instant::now();
    a.my_next_tsn = 100;
    a.cumulative_tsn_ack_point = 99;
    a.advanced_peer_tsn_ack_point = 99;
    let ppi = PayloadProtocolIdentifier::Binary;
    a.open_stream(1, ppi)?
        .write_sctp(now, &Bytes::from_static(b"last words"), ppi)?;
    let sent = transmitted_data(&a.gather_outbound(now).0);
    assert_eq!(vec![100], sent.iter().map(|c| c.tsn).collect::<Vec<_>>());

    a.handle_shutdown(
        &ChunkShutdown {
            cumulative_tsn_ack: 100,
        },
        now,
    )?;

    assert!(
        a.inflight_queue.is_empty(),
        "the SHUTDOWN acknowledged TSN 100"
    );
    assert_eq!(100, a.cumulative_tsn_ack_point);
    assert_eq!(AssociationState::ShutdownAckSent, a.state());
    assert!(a.will_send_shutdown_ack);
    assert_eq!(0, a.stream(1)?.buffered_amount()?);
    Ok(())
}

/// A SHUTDOWN that acknowledges only part of what is outstanding leaves the rest in flight and
/// the association in SHUTDOWN-RECEIVED; the SACK for the rest completes it.
#[test]
fn shutdown_with_data_still_outstanding_waits_for_its_acknowledgement() -> Result<()> {
    let mut a = timed_test_association();
    let now = Instant::now();
    a.my_next_tsn = 100;
    a.cumulative_tsn_ack_point = 99;
    a.advanced_peer_tsn_ack_point = 99;
    let ppi = PayloadProtocolIdentifier::Binary;
    let mut stream = a.open_stream(1, ppi)?;
    stream.write_sctp(now, &Bytes::from_static(b"one"), ppi)?;
    stream.write_sctp(now, &Bytes::from_static(b"two"), ppi)?;
    assert_eq!(2, transmitted_data(&a.gather_outbound(now).0).len());

    a.handle_shutdown(
        &ChunkShutdown {
            cumulative_tsn_ack: 100,
        },
        now,
    )?;
    assert_eq!(AssociationState::ShutdownReceived, a.state());
    assert_eq!(1, a.inflight_queue.len());

    a.handle_sack(
        &ChunkSelectiveAck {
            cumulative_tsn_ack: 101,
            advertised_receiver_window_credit: 65536,
            gap_ack_blocks: vec![],
            duplicate_tsn: vec![],
        },
        now,
    )?;
    assert_eq!(AssociationState::ShutdownAckSent, a.state());
    assert!(a.will_send_shutdown_ack);
    Ok(())
}

/// A stale SHUTDOWN (behind the acknowledgement point) or one acknowledging DATA never sent
/// changes nothing beyond the state transition.
#[test]
fn shutdown_ack_point_outside_the_window_is_ignored() -> Result<()> {
    for cumulative_tsn_ack in [50, 200] {
        let mut a = timed_test_association();
        let now = Instant::now();
        a.my_next_tsn = 100;
        a.cumulative_tsn_ack_point = 99;
        a.advanced_peer_tsn_ack_point = 99;
        let ppi = PayloadProtocolIdentifier::Binary;
        a.open_stream(1, ppi)?
            .write_sctp(now, &Bytes::from_static(b"x"), ppi)?;
        assert_eq!(1, transmitted_data(&a.gather_outbound(now).0).len());

        a.handle_shutdown(&ChunkShutdown { cumulative_tsn_ack }, now)?;
        assert_eq!(99, a.cumulative_tsn_ack_point, "{cumulative_tsn_ack}");
        assert_eq!(1, a.inflight_queue.len(), "{cumulative_tsn_ack}");
        assert_eq!(AssociationState::ShutdownReceived, a.state());
    }
    Ok(())
}

/// RFC 9260 3.3.8: a SHUTDOWN cannot report the DATA received beyond its Cumulative TSN Ack;
/// "The sender of the SHUTDOWN chunk MAY bundle a SACK chunk to indicate any gaps in the
/// received TSNs". With a gap, the SHUTDOWN goes with a SACK that reports it; without one, alone.
#[test]
fn a_shutdown_goes_with_a_sack_that_reports_the_gaps() -> Result<()> {
    for gap in [false, true] {
        let mut a = timed_test_association();
        let now = Instant::now();
        let base = a.peer_last_tsn;
        let data = |tsn: u32| ChunkPayloadData {
            tsn,
            stream_identifier: 1,
            beginning_fragment: true,
            ending_fragment: true,
            unordered: true,
            user_data: Bytes::from_static(b"x"),
            ..Default::default()
        };
        a.handle_data(&data(base.wrapping_add(1)))?;
        if gap {
            // TSN base + 2 is missing.
            a.handle_data(&data(base.wrapping_add(3)))?;
        }
        let _ = a.gather_outbound(now);
        a.shutdown()?;

        let packets: Vec<Packet> = a
            .gather_outbound(now)
            .0
            .iter()
            .map(|raw| Packet::unmarshal(raw).unwrap())
            .collect();
        let with_shutdown = packets
            .iter()
            .find(|p| p.chunks.iter().any(|c| c.as_any().is::<ChunkShutdown>()))
            .expect("a SHUTDOWN is sent");
        let sacks: Vec<&ChunkSelectiveAck> = with_shutdown
            .chunks
            .iter()
            .filter_map(|c| c.as_any().downcast_ref::<ChunkSelectiveAck>())
            .collect();
        if gap {
            assert_eq!(1, sacks.len(), "a SACK in the SHUTDOWN's packet");
            assert_eq!(base.wrapping_add(1), sacks[0].cumulative_tsn_ack);
            assert_eq!(1, sacks[0].gap_ack_blocks.len());
            assert_eq!(
                (2, 2),
                (
                    sacks[0].gap_ack_blocks[0].start,
                    sacks[0].gap_ack_blocks[0].end
                )
            );
        } else {
            assert!(sacks.is_empty(), "nothing to report: no SACK");
        }
    }
    Ok(())
}

/// RFC 9260 3.3.1 and RFC 7053: the I bit asks the receiver for a SACK without delay. The last
/// DATA chunk sent while a SHUTDOWN waits for it to be acknowledged (9.2) carries it; DATA
/// sent with more to follow, or outside a shutdown, does not.
#[test]
fn the_last_data_before_a_shutdown_asks_for_an_immediate_sack() -> Result<()> {
    let mut a = timed_test_association();
    let now = Instant::now();
    {
        let mut s = a.open_stream(1, PayloadProtocolIdentifier::Binary)?;
        s.write_sctp(
            now,
            &Bytes::from_static(b"first"),
            PayloadProtocolIdentifier::Binary,
        )?;
    }
    let sent = transmitted_data(&a.gather_outbound(now).0);
    assert_eq!(1, sent.len());
    assert!(!sent[0].immediate_sack, "not while established");

    // Two more messages, of which the window lets one out before the shutdown.
    {
        let mut s = a.stream(1)?;
        for m in [&b"second"[..], b"third"] {
            s.write_sctp(
                now,
                &Bytes::copy_from_slice(m),
                PayloadProtocolIdentifier::Binary,
            )?;
        }
    }
    a.cwnd = 0;
    a.shutdown()?;
    assert_eq!(AssociationState::ShutdownPending, a.state());
    a.cwnd = a.inflight_queue.get_num_bytes() as u32 + 6;
    let sent = transmitted_data(&a.gather_outbound(now).0);
    assert_eq!(1, sent.len());
    assert!(!sent[0].immediate_sack, "more DATA follows it");
    a.cwnd = 1 << 20;
    let sent = transmitted_data(&a.gather_outbound(now).0);
    assert_eq!(1, sent.len());
    assert!(sent[0].immediate_sack, "the last DATA before the SHUTDOWN");
    Ok(())
}
