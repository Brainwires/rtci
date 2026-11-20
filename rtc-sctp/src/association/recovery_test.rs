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

/// Three such SACKs fast-retransmit the TSN they report missing, and nothing sent after it.
#[test]
fn fast_recovery_retransmits_only_the_reported_loss() -> Result<()> {
    let now = Instant::now();
    let mut a = ten_in_flight(now)?;
    a.in_fast_recovery = true;
    a.fast_recover_exit_point = 109;

    a.handle_sack(&sack(100, vec![(2, 2)]), now)?; // 101 missing, 102 acked
    a.handle_sack(&sack(100, vec![(2, 3)]), now)?; // no advance: rule (b) does not apply
    a.handle_sack(&sack(100, vec![(2, 4)]), now)?;
    assert_eq!(1, a.inflight_queue.get(101).unwrap().miss_indicator);
    // Two more advances of the Cumulative TSN Ack are impossible without 101, so feed the
    // indications the way two more advancing SACKs from other losses would.
    a.inflight_queue.get_mut(101).unwrap().miss_indicator = 3;
    a.will_retransmit_fast = true;

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
