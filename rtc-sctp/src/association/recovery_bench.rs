//! The recovery-flush benchmark, formerly the ignored `benchmark_recovery_flushes` test.
//!
//! Only recovery flushes are timed; setup and the single T3 marking pass are excluded.
//! Cumulative progress is applied directly to isolate retry selection from SACK parsing and
//! congestion control. This is not an end-to-end throughput test. Reached through
//! `fuzzing::bench_recovery_flushes` and the `sctp_recovery_bench` example.

use super::*;
use crate::association::stream::ReliabilityType;

/// `count` one-fragment messages in flight, each allowed one retransmission.
fn recovery_window(count: u32, now: Instant) -> Result<Association> {
    let mut a = Association::new(
        None,
        Arc::new(TransportConfig::default()),
        1400,
        0,
        SocketAddr::from(([0, 0, 0, 0], 0)),
        SocketAddr::from(([0, 0, 0, 0], 0)),
        TransportProtocol::UDP,
        now,
    );
    a.control_queue.clear();
    a.timers.stop(Timer::T1Init);
    a.set_state(AssociationState::Established);
    a.use_forward_tsn = true;
    a.rto_mgr.set_rto(1000, true);
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
    let _ = a.gather_outbound(now);
    Ok(a)
}

/// The association `recovery_flushes` works on: `count` messages in flight at `now`. Set up
/// apart so the caller times only the flushes, with its own clock (protocol code reads none).
pub(crate) fn recovery_setup(count: u32, now: Instant) -> Result<Association> {
    recovery_window(count, now)
}

/// Runs `count` one-chunk recovery flushes on `a` (from `recovery_setup` at `now`): T3-rtx
/// retransmissions when `fast` is false, fast retransmissions otherwise.
pub(crate) fn recovery_flushes(a: &mut Association, count: u32, fast: bool, now: Instant) {
    let at = now + Duration::from_secs(1);
    if !fast {
        a.handle_timeout(at);
    }
    a.cwnd = a.mtu;
    for _ in 0..count {
        let tsn = a.cumulative_tsn_ack_point.wrapping_add(1);
        if fast {
            if let Some(c) = a.inflight_queue.get_mut(tsn) {
                c.miss_indicator = 3;
            }
            if let Some(next) = a.inflight_queue.get_mut(tsn.wrapping_add(1)) {
                next.miss_indicator = 3;
            }
            a.will_retransmit_fast = true;
        }
        let packets = if fast {
            a.gather_outbound_fast_retransmission_packets(vec![], at)
        } else {
            a.gather_data_packets_to_retransmit(vec![], at)
        };
        std::hint::black_box(packets);
        let _ = a.inflight_queue.pop(tsn);
        a.cumulative_tsn_ack_point = tsn;
    }
}
