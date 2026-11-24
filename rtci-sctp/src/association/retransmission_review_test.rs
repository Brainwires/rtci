use super::*;

fn recovery_window(count: u32, now: Instant) -> Result<Association> {
    let mut a = timed_test_association();
    a.my_next_tsn = 100;
    a.cumulative_tsn_ack_point = 99;
    a.advanced_peer_tsn_ack_point = 99;
    a.cwnd = count * a.mtu;
    a.rwnd = a.cwnd;
    let ppi = PayloadProtocolIdentifier::Binary;
    let mut stream = a.open_stream(1, ppi)?;
    stream.set_reliability_params(false, ReliabilityType::Rexmit, 1)?;
    for _ in 0..count {
        stream.write_sctp(now, &Bytes::from(vec![1; 1024]), ppi)?;
    }
    assert_eq!(count as usize, data_chunks(&a.gather_outbound(now).0));
    Ok(a)
}

#[test]
fn recovery_checks_are_bounded_by_candidates_in_large_windows() -> Result<()> {
    for count in [128, 1024, 4096] {
        for fast in [false, true] {
            let now = Instant::now();
            let mut a = recovery_window(count, now)?;
            let at = now + Duration::from_secs(1);
            if !fast {
                a.handle_timeout(at);
            }
            a.cwnd = a.mtu;
            a.inflight_queue.track_lookups = true;
            for _ in 0..32 {
                let tsn = a.cumulative_tsn_ack_point.wrapping_add(1);
                if fast {
                    a.inflight_queue.get_mut(tsn).unwrap().miss_indicator = 3;
                    a.will_retransmit_fast = true;
                    // The next candidate terminates this one-packet pass.
                    a.inflight_queue.get_mut(tsn + 1).unwrap().miss_indicator = 3;
                }
                a.inflight_queue.lookups.set(0);
                let packets = if fast {
                    a.gather_outbound_fast_retransmission_packets(vec![], at)
                } else {
                    a.gather_data_packets_to_retransmit(vec![], at)
                };
                let lookups = a.inflight_queue.lookups.get();
                let sent = transmitted_data(&packets);
                assert_eq!(vec![tsn], sent.iter().map(|c| c.tsn).collect::<Vec<_>>());
                assert!(
                    lookups <= 16,
                    "count={count}, fast={fast}: {lookups} lookups for one retry"
                );
                // Advance the cumulative ACK between recovery flushes without
                // including SACK processing itself in this operation count.
                a.inflight_queue.pop(tsn).unwrap();
                a.cumulative_tsn_ack_point = tsn;
            }
        }
    }
    Ok(())
}

#[test]
fn deferred_retry_rechecks_expiry_without_retiring_unrelated_messages() -> Result<()> {
    for fast in [false, true] {
        let mut a = timed_test_association();
        let now = Instant::now();
        let ppi = PayloadProtocolIdentifier::Binary;
        a.open_stream(1, ppi)?
            .set_reliability_params(false, ReliabilityType::Timed, 1500)?;
        a.open_stream(2, ppi)?
            .set_reliability_params(false, ReliabilityType::Timed, 1500)?;
        a.stream(1)?
            .write_sctp(now, &Bytes::from_static(b"retry"), ppi)?;
        a.stream(2)?
            .write_sctp(now, &Bytes::from_static(b"unrelated"), ppi)?;
        let sent = transmitted_data(&a.gather_outbound(now).0);
        assert_eq!(2, sent.len());
        if fast {
            a.inflight_queue
                .get_mut(sent[0].tsn)
                .unwrap()
                .miss_indicator = 3;
            a.will_retransmit_fast = true;
        } else {
            a.handle_timeout(now + Duration::from_secs(1));
            // New DATA sent after the T3 marking pass is not a retry candidate.
            a.inflight_queue.get_mut(sent[1].tsn).unwrap().retransmit = false;
        }
        let at = now + Duration::from_millis(1500);
        let packets = if fast {
            a.gather_outbound_fast_retransmission_packets(vec![], at)
        } else {
            a.gather_data_packets_to_retransmit(vec![], at)
        };
        assert_eq!(0, data_chunks(&packets));
        assert!(a.inflight_queue.get(sent[0].tsn).unwrap().abandoned());
        assert!(!a.inflight_queue.get(sent[1].tsn).unwrap().abandoned());
        assert_eq!(9, a.stream(2)?.buffered_amount()?);
        assert!(a.will_send_forward_tsn);
    }
    Ok(())
}

#[test]
fn later_exhausted_fragment_cancels_previously_selected_retry() -> Result<()> {
    for unordered in [false, true] {
        let mut a = timed_test_association();
        a.cwnd = 10 * a.mtu;
        let now = Instant::now();
        let ppi = PayloadProtocolIdentifier::Binary;
        let mut stream = a.open_stream(1, ppi)?;
        stream.set_reliability_params(unordered, ReliabilityType::Rexmit, 1)?;
        stream.write_sctp(now, &Bytes::from(vec![7; 3000]), ppi)?;
        let sent = transmitted_data(&a.gather_outbound(now).0);
        assert!(sent.len() >= 3);
        let at = now + Duration::from_secs(1);
        a.handle_timeout(at);
        // A fast retry occurs after T3 marks the message but before a deferred
        // T3 flush. The earlier fragment still has its one retry available.
        a.inflight_queue
            .get_mut(sent[1].tsn)
            .unwrap()
            .miss_indicator = 3;
        a.will_retransmit_fast = true;
        let fast = a.gather_outbound_fast_retransmission_packets(vec![], at);
        assert_eq!(
            vec![sent[1].tsn],
            transmitted_data(&fast)
                .iter()
                .map(|c| c.tsn)
                .collect::<Vec<_>>()
        );
        a.cwnd = 10 * a.mtu;
        let packets = a.gather_data_packets_to_retransmit(vec![], at);
        assert_eq!(
            0,
            data_chunks(&packets),
            "no fragment of the retired message may escape"
        );
        assert_eq!(0, a.buffered_amount());
        for c in &sent {
            assert!(a.inflight_queue.get(c.tsn).unwrap().abandoned());
        }
        assert_eq!(1, a.inflight_queue.get(sent[0].tsn).unwrap().nsent);
    }
    Ok(())
}

#[test]
fn candidate_abandonment_covers_wrapped_fragments_after_partial_ack() -> Result<()> {
    for unordered in [false, true] {
        for fast in [false, true] {
            let mut a = timed_test_association();
            a.my_next_tsn = u32::MAX - 1;
            a.cumulative_tsn_ack_point = u32::MAX - 2;
            a.advanced_peer_tsn_ack_point = u32::MAX - 2;
            a.cwnd = 3 * a.max_payload_size;
            let size = 4 * a.max_payload_size as usize;
            let now = Instant::now();
            let ppi = PayloadProtocolIdentifier::Binary;
            let mut stream = a.open_stream(1, ppi)?;
            stream.set_reliability_params(unordered, ReliabilityType::Timed, 1500)?;
            stream.write_sctp(now, &Bytes::from(vec![1; size]), ppi)?;
            stream.write_sctp(now, &Bytes::from_static(b"next"), ppi)?;
            let sent = transmitted_data(&a.gather_outbound(now).0);
            assert_eq!(
                vec![u32::MAX - 1, u32::MAX, 0],
                sent.iter().map(|c| c.tsn).collect::<Vec<_>>()
            );
            a.handle_sack(
                &ChunkSelectiveAck {
                    cumulative_tsn_ack: u32::MAX - 1,
                    advertised_receiver_window_credit: 65536,
                    gap_ack_blocks: vec![crate::chunk::chunk_selective_ack::GapAckBlock {
                        start: 2,
                        end: 2,
                    }],
                    ..Default::default()
                },
                now,
            )?;
            assert!(a.inflight_queue.get(u32::MAX - 1).is_none());
            assert!(a.inflight_queue.get(0).unwrap().acknowledged);
            if fast {
                a.inflight_queue.get_mut(u32::MAX).unwrap().miss_indicator = 3;
                a.will_retransmit_fast = true;
            } else {
                a.handle_timeout(now + Duration::from_secs(1));
            }
            let at = now + Duration::from_millis(1500);
            let packets = if fast {
                a.gather_outbound_fast_retransmission_packets(vec![], at)
            } else {
                a.gather_data_packets_to_retransmit(vec![], at)
            };
            assert_eq!(0, data_chunks(&packets));
            for tsn in [u32::MAX, 0, 1] {
                assert!(a.inflight_queue.get(tsn).unwrap().abandoned());
            }
            assert_eq!(1, a.advanced_peer_tsn_ack_point);
            assert_eq!(4, a.stream(1)?.buffered_amount()?);
            assert_eq!(
                Bytes::from_static(b"next"),
                a.pending_queue.peek().unwrap().user_data
            );
        }
    }
    Ok(())
}

#[test]
fn t2_backoff_does_not_compound_simultaneous_t3_expirations() -> Result<()> {
    for state in [
        AssociationState::ShutdownSent,
        AssociationState::ShutdownAckSent,
    ] {
        let mut a = timed_test_association();
        a.rto_mgr.set_rto(1000, false);
        a.set_state(state);
        let mut now = Instant::now();
        a.timers.start(Timer::T2Shutdown, now, 1000);
        a.timers.start(Timer::T3RTX, now, 1000);
        for interval in [2, 4, 8, 16] {
            now = a.timers.get(Timer::T2Shutdown).unwrap();
            assert_eq!(Some(now), a.timers.get(Timer::T3RTX));
            a.handle_timeout(now);
            let deadline = now + Duration::from_secs(interval);
            assert_eq!(Some(deadline), a.timers.get(Timer::T2Shutdown));
            let packets = a.gather_outbound(now).0;
            assert!(!packets.is_empty());
            assert_eq!(Some(deadline), a.timers.get(Timer::T2Shutdown));
            assert_eq!(Some(deadline), a.timers.get(Timer::T3RTX));
        }
    }
    Ok(())
}

// The recovery-flush timing comparison that lived here is the `sctp_recovery_bench`
// example (`association::recovery_bench`), so no test is ignored.

#[test]
fn public_rtt_reports_measurements_independently_of_backoff() {
    let mut a = timed_test_association();
    a.rto_mgr.set_rto(1000, false);
    assert_eq!(Duration::ZERO, a.rtt());
    a.rto_mgr.set_new_rtt(80);
    assert_eq!(Duration::from_millis(80), a.rtt());
    for _ in 0..4 {
        a.rto_mgr.backoff();
        assert_eq!(Duration::from_millis(80), a.rtt());
    }
    assert_eq!(16_000, a.rto_mgr.get_rto());
    a.rto_mgr.set_new_rtt(160);
    assert_eq!(Duration::from_millis(90), a.rtt());
}

#[test]
fn invalid_pending_message_closes_without_sending_or_rearming_timers() -> Result<()> {
    for t3 in [false, true] {
        let mut a = timed_test_association();
        let now = Instant::now();
        let ppi = PayloadProtocolIdentifier::Binary;
        let mut stream = a.open_stream(1, ppi)?;
        stream.set_reliability_params(true, ReliabilityType::Timed, 100)?;
        stream.write_sctp(now, &Bytes::from_static(b"invalid"), ppi)?;
        let mut invalid = a.pending_queue.pop(true, true).unwrap();
        invalid.ending_fragment = false;
        a.pending_queue.push_message(vec![invalid]);
        if t3 {
            a.cwnd = 0;
            // Retain a sent first fragment and a malformed pending tail.
            let mut first = a.pending_queue.peek().unwrap().clone();
            first.tsn = a.my_next_tsn;
            a.my_next_tsn = a.my_next_tsn.wrapping_add(1);
            first.nsent = 1;
            a.inflight_queue.push_no_check(first);
            a.timers.start(Timer::T3RTX, now, 1000);
            a.handle_timeout(now + Duration::from_secs(1));
        }
        assert!(a.poll_transmit(now + Duration::from_secs(1)).is_none());
        assert_eq!(AssociationState::Closed, a.state());
        assert!(a.poll_timeout().is_none());
        assert!(a.streams.is_empty());
        assert!(a.events.iter().any(|event| matches!(
            event,
            Event::AssociationLost {
                reason: AssociationError::TransportError,
                ..
            }
        )));
    }
    Ok(())
}

/// A second loss of an exhausted partially reliable message during Fast
/// Recovery is abandoned (and forwarded) from later SACKs, not at T3-rtx.
#[test]
fn exhausted_loss_in_fast_recovery_is_abandoned_without_cumulative_advance() -> Result<()> {
    use crate::chunk::chunk_selective_ack::GapAckBlock;
    for unordered in [false, true] {
        let mut a = timed_test_association();
        let now = Instant::now();
        let ppi = PayloadProtocolIdentifier::Binary;
        a.open_stream(1, ppi)?
            .set_reliability_params(unordered, ReliabilityType::Rexmit, 0)?;
        for _ in 0..8 {
            a.stream(1)?
                .write_sctp(now, &Bytes::from_static(b"message"), ppi)?;
        }
        let sent = transmitted_data(&a.gather_outbound(now).0);
        assert_eq!(8, sent.len());
        let first = sent[0].tsn;
        let sack = |blocks: &[(u16, u16)]| ChunkSelectiveAck {
            cumulative_tsn_ack: first - 1,
            advertised_receiver_window_credit: 65536,
            gap_ack_blocks: blocks
                .iter()
                .map(|&(start, end)| GapAckBlock { start, end })
                .collect(),
            ..Default::default()
        };
        // `first` and `first + 2` are lost. Three reports of the first loss
        // enter Fast Recovery; the second loss has two by then.
        a.handle_sack(&sack(&[(2, 2)]), now)?;
        a.handle_sack(&sack(&[(2, 2), (4, 4)]), now)?;
        a.handle_sack(&sack(&[(2, 2), (4, 5)]), now)?;
        assert!(a.in_fast_recovery);
        assert_eq!(0, data_chunks(&a.gather_outbound(now).0));
        assert!(a.inflight_queue.get(first).unwrap().abandoned());
        assert_eq!(2, a.inflight_queue.get(first + 2).unwrap().miss_indicator);
        // The peer has not processed the FORWARD TSN yet: the next SACK does
        // not advance the cumulative ack, but reports newer DATA.
        a.handle_sack(&sack(&[(2, 2), (4, 6)]), now)?;
        assert!(a.in_fast_recovery);
        assert_eq!(3, a.inflight_queue.get(first + 2).unwrap().miss_indicator);
        assert!(a.will_retransmit_fast);
        let packets = a.gather_outbound_fast_retransmission_packets(vec![], now);
        assert_eq!(
            0,
            data_chunks(&packets),
            "an exhausted message is not resent"
        );
        assert!(a.inflight_queue.get(first + 2).unwrap().abandoned());
        // Still outstanding, never reported past the HTNA: untouched.
        assert_eq!(0, a.inflight_queue.get(first + 7).unwrap().miss_indicator);
        assert!(!a.inflight_queue.get(first + 7).unwrap().abandoned());
    }
    Ok(())
}

/// RFC 9260 7.2.4 (the HTNA algorithm): "for each incoming SACK chunk" miss indications are
/// counted for the missing TSNs below the highest TSN it newly acknowledges, in Fast Recovery
/// too, also when the Cumulative TSN Ack Point does not advance. Reliable DATA lost after
/// Fast Recovery began is then retransmitted as soon as cwnd allows (steps 5 and 6), not left
/// to T3-rtx, whose one packet at a doubling RTO held a 10 % loss session's messages back
/// for more than 90 seconds (`tests/lossy_link_rtc2rtc.rs`).
#[test]
fn reliable_loss_in_fast_recovery_is_retransmitted_by_gap_reports() -> Result<()> {
    use crate::chunk::chunk_selective_ack::GapAckBlock;
    let mut a = timed_test_association();
    let now = Instant::now();
    let ppi = PayloadProtocolIdentifier::Binary;
    a.open_stream(1, ppi)?;
    for _ in 0..8 {
        a.stream(1)?
            .write_sctp(now, &Bytes::from_static(b"message"), ppi)?;
    }
    let sent = transmitted_data(&a.gather_outbound(now).0);
    assert_eq!(8, sent.len());
    let first = sent[0].tsn;
    let sack = |blocks: &[(u16, u16)]| ChunkSelectiveAck {
        cumulative_tsn_ack: first - 1,
        advertised_receiver_window_credit: 65536,
        gap_ack_blocks: blocks
            .iter()
            .map(|&(start, end)| GapAckBlock { start, end })
            .collect(),
        ..Default::default()
    };
    // `first` and `first + 2` are lost. Three reports of the first loss enter Fast
    // Recovery, and `first` is fast retransmitted.
    a.handle_sack(&sack(&[(2, 2)]), now)?;
    a.handle_sack(&sack(&[(2, 2), (4, 4)]), now)?;
    a.handle_sack(&sack(&[(2, 2), (4, 5)]), now)?;
    assert!(a.in_fast_recovery);
    let resent = transmitted_data(&a.gather_outbound(now).0);
    assert_eq!(
        vec![first],
        resent.iter().map(|d| d.tsn).collect::<Vec<_>>()
    );
    // The retransmission is still on its way: the next SACK does not advance the cumulative
    // ack, and newly acknowledges `first + 6`. It is the third report of `first + 2`.
    a.handle_sack(&sack(&[(2, 2), (4, 6)]), now)?;
    assert!(a.in_fast_recovery);
    let lost = a.inflight_queue.get(first + 2).unwrap();
    assert_eq!(3, lost.miss_indicator);
    assert!(!lost.abandoned());
    assert!(lost.retransmit, "marked for retransmission");
    assert!(lost.no_fast_retransmit, "and not fast retransmitted again");
    // Still outstanding, never reported past the HTNA: untouched.
    assert_eq!(0, a.inflight_queue.get(first + 7).unwrap().miss_indicator);
    // It goes out with the window, before T3-rtx.
    let resent = transmitted_data(&a.gather_outbound(now).0);
    assert_eq!(
        vec![first + 2],
        resent.iter().map(|d| d.tsn).collect::<Vec<_>>()
    );
    Ok(())
}
