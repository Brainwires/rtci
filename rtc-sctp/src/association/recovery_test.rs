//! Congestion control and fast recovery bookkeeping (RFC 9260 7.2).

use super::*;

/// Ten 100-byte messages in flight as TSNs 100..=109.
fn ten_in_flight(now: Instant) -> Result<Association> {
    let mut a = timed_test_association();
    a.my_next_tsn = 100;
    a.cumulative_tsn_ack_point = 99;
    a.advanced_peer_tsn_ack_point = 99;
    a.min_tsn2measure_rtt = 100;
    a.cwnd = 64 * a.mtu;
    a.ssthresh = a.cwnd;
    let ppi = PayloadProtocolIdentifier::Binary;
    let mut stream = a.open_stream(1, ppi)?;
    for _ in 0..10 {
        stream.write_sctp(now, &Bytes::from(vec![0; 100]), ppi)?;
    }
    assert_eq!(10, transmitted_data(&a.gather_outbound(now).0).len());
    Ok(a)
}

fn sack(cumulative_tsn_ack: u32, gap_ack_blocks: Vec<(u16, u16)>) -> ChunkSelectiveAck {
    ChunkSelectiveAck {
        cumulative_tsn_ack,
        advertised_receiver_window_credit: 1 << 20,
        gap_ack_blocks: gap_ack_blocks
            .into_iter()
            .map(|(start, end)| crate::chunk::chunk_selective_ack::GapAckBlock { start, end })
            .collect(),
        duplicate_tsn: vec![],
    }
}

/// RFC 9260 7.2.4 rule (b): in Fast Recovery, a SACK that advances the Cumulative TSN Ack
/// counts a miss indication for every TSN it reports missing, and only those: the TSNs below
/// the highest TSN it acknowledges. DATA sent after that is merely not acknowledged yet.
#[test]
fn fast_recovery_counts_only_tsns_the_sack_reports_missing() -> Result<()> {
    let now = Instant::now();
    let mut a = ten_in_flight(now)?;
    a.in_fast_recovery = true;
    a.fast_recover_exit_point = 109;

    // Acknowledges 100..=101 cumulatively and 103 by a gap block: 102 is reported missing,
    // 104..=109 are not reported at all.
    a.handle_sack(&sack(101, vec![(2, 2)]), now)?;

    assert_eq!(101, a.cumulative_tsn_ack_point);
    assert_eq!(1, a.inflight_queue.get(102).unwrap().miss_indicator);
    for tsn in 104..=109 {
        assert_eq!(
            0,
            a.inflight_queue.get(tsn).unwrap().miss_indicator,
            "TSN {tsn} was never reported missing"
        );
    }
    Ok(())
}

/// Three SACKs that report a TSN missing retransmit it during Fast Recovery, and nothing sent
/// after it. The two that do not advance the Cumulative TSN Ack count a miss indication too:
/// 101 is below the highest TSN each newly acknowledges (RFC 9260 7.2.4, the HTNA rule holds
/// for every SACK).
#[test]
fn fast_recovery_retransmits_only_the_reported_loss() -> Result<()> {
    let now = Instant::now();
    let mut a = ten_in_flight(now)?;
    a.in_fast_recovery = true;
    a.fast_recover_exit_point = 109;

    a.handle_sack(&sack(100, vec![(2, 2)]), now)?; // 101 missing, 102 acked
    a.handle_sack(&sack(100, vec![(2, 3)]), now)?; // no advance; 103 newly acked
    a.handle_sack(&sack(100, vec![(2, 4)]), now)?; // 104 newly acked
    assert_eq!(3, a.inflight_queue.get(101).unwrap().miss_indicator);
    for tsn in 105..=109 {
        assert_eq!(
            0,
            a.inflight_queue.get(tsn).unwrap().miss_indicator,
            "TSN {tsn}"
        );
    }

    let retransmitted = transmitted_data(&a.gather_outbound(now).0);
    assert_eq!(
        vec![101],
        retransmitted.iter().map(|c| c.tsn).collect::<Vec<_>>(),
        "only the reported loss is retransmitted"
    );
    for tsn in 105..=109 {
        assert_eq!(1, a.inflight_queue.get(tsn).unwrap().nsent, "TSN {tsn}");
    }
    Ok(())
}

/// RFC 9260 7.2.4: "For each incoming SACK chunk, miss indications are incremented only for
/// missing TSNs prior to the HTNA", outside Fast Recovery too: TSNs the SACK reports missing
/// above the highest TSN it newly acknowledges count nothing. "A newly acknowledged DATA
/// chunk is one not previously acknowledged in a SACK chunk": a SACK that repeats what an
/// earlier one acknowledged has no HTNA, and counts nothing.
#[test]
fn miss_indications_count_below_the_highest_tsn_newly_acknowledged_only() -> Result<()> {
    let now = Instant::now();
    let mut a = ten_in_flight(now)?;
    assert!(!a.in_fast_recovery);

    // 105 acknowledged: 100..=104 below it, one indication each.
    a.handle_sack(&sack(99, vec![(6, 6)]), now)?;
    // 102 newly acknowledged, 105 again: the HTNA is 102. 103 and 104 are reported missing
    // but lie above it.
    a.handle_sack(&sack(99, vec![(3, 3), (6, 6)]), now)?;
    let misses = |a: &Association| -> Vec<u32> {
        (100..=109)
            .map(|tsn| a.inflight_queue.get(tsn).unwrap().miss_indicator)
            .collect()
    };
    assert_eq!(vec![2, 2, 1, 1, 1, 0, 0, 0, 0, 0], misses(&a));
    // The same SACK again acknowledges nothing new.
    a.handle_sack(&sack(99, vec![(3, 3), (6, 6)]), now)?;
    assert_eq!(vec![2, 2, 1, 1, 1, 0, 0, 0, 0, 0], misses(&a));
    assert!(!a.in_fast_recovery);
    assert!(transmitted_data(&a.gather_outbound(now).0).is_empty());
    Ok(())
}

/// RFC 9260 7.2.4 steps 1, 3 and 5 in Fast Recovery: a chunk that reaches its third miss
/// indication through a SACK that advances the Cumulative TSN Ack Point is marked for
/// retransmission and is no Fast Retransmit candidate any more, but it is not sent in a
/// packet that ignores cwnd: step 3 is "If not in Fast Recovery". It goes out "as soon as
/// cwnd allows". (It was sent at once, past cwnd.)
#[test]
fn a_third_miss_in_fast_recovery_waits_for_the_window_also_when_the_cumulative_ack_advances()
-> Result<()> {
    let now = Instant::now();
    let mut a = ten_in_flight(now)?;
    a.in_fast_recovery = true;
    a.fast_recover_exit_point = 109;
    let ssthresh = a.ssthresh;

    // 100 and 102 are lost. Three SACKs that do not advance the Cumulative TSN Ack: 100
    // reaches three indications and goes out with the window.
    a.handle_sack(&sack(99, vec![(2, 2)]), now)?;
    a.handle_sack(&sack(99, vec![(2, 2), (4, 4)]), now)?;
    a.handle_sack(&sack(99, vec![(2, 2), (4, 5)]), now)?;
    let resent = transmitted_data(&a.gather_outbound(now).0);
    assert_eq!(vec![100], resent.iter().map(|c| c.tsn).collect::<Vec<_>>());
    assert_eq!(2, a.inflight_queue.get(102).unwrap().miss_indicator);

    // The window is in full use when the retransmission of 100 is acknowledged: the SACK
    // advances the Cumulative TSN Ack to 101 and reports 102 missing a third time.
    a.cwnd = 200;
    a.handle_sack(&sack(101, vec![(2, 4)]), now)?;
    assert!(a.in_fast_recovery);
    assert_eq!(ssthresh, a.ssthresh, "no second reduction");
    let lost = a.inflight_queue.get(102).unwrap();
    assert_eq!(3, lost.miss_indicator);
    assert!(lost.retransmit, "marked for retransmission");
    assert!(!lost.is_fast_retransmit_candidate());
    assert!(
        transmitted_data(&a.gather_outbound(now).0).is_empty(),
        "not sent past cwnd"
    );

    a.cwnd = 64 * a.mtu;
    let resent = transmitted_data(&a.gather_outbound(now).0);
    assert_eq!(vec![102], resent.iter().map(|c| c.tsn).collect::<Vec<_>>());
    Ok(())
}

/// RFC 9260 7.2.4 step 5: a fast-retransmitted chunk is "ineligible for a subsequent Fast
/// Retransmit". The retransmission is lost too: however many SACKs report the chunk missing
/// after it, it is not fast retransmitted again (T3-rtx is what sends it next).
#[test]
fn a_fast_retransmitted_chunk_is_not_fast_retransmitted_again() -> Result<()> {
    let now = Instant::now();
    let mut a = ten_in_flight(now)?;
    for gap_end in 2..=4u16 {
        a.handle_sack(&sack(99, vec![(2, gap_end)]), now)?;
    }
    assert!(a.in_fast_recovery);
    let resent = transmitted_data(&a.gather_outbound(now).0);
    assert_eq!(vec![100], resent.iter().map(|c| c.tsn).collect::<Vec<_>>());

    for gap_end in 5..=10u16 {
        a.handle_sack(&sack(99, vec![(2, gap_end)]), now)?;
        assert!(
            transmitted_data(&a.gather_outbound(now).0).is_empty(),
            "after the SACK acknowledging up to {}",
            99 + u32::from(gap_end)
        );
    }
    assert_eq!(2, a.inflight_queue.get(100).unwrap().nsent);
    Ok(())
}

/// cwnd grows without another bound in slow start (ssthresh is the peer's window, up to
/// u32::MAX), so its additions saturate instead of wrapping to a tiny window after about
/// 2 GiB acknowledged (or panicking with overflow checks on).
#[test]
fn congestion_window_growth_saturates() -> Result<()> {
    let now = Instant::now();
    let mut a = ten_in_flight(now)?;
    // Something still pending, so slow start and congestion avoidance may grow cwnd.
    let ppi = PayloadProtocolIdentifier::Binary;
    a.stream(1)?
        .write_sctp(now, &Bytes::from(vec![0; 100]), ppi)?;
    assert!(!a.pending_queue.is_empty());

    // Slow start: cwnd <= ssthresh, and in full use.
    a.ssthresh = u32::MAX;
    a.cwnd = u32::MAX - 10;
    a.in_fast_recovery = false;
    a.grow_congestion_window(i64::from(u32::MAX), u32::MAX, true);
    assert_eq!(u32::MAX, a.cwnd);

    // Congestion avoidance: cwnd > ssthresh.
    a.ssthresh = 1;
    a.cwnd = u32::MAX - 10;
    a.partial_bytes_acked = u32::MAX - 10;
    a.grow_congestion_window(i64::MAX, u32::MAX, true);
    assert_eq!(u32::MAX, a.cwnd);
    Ok(())
}
