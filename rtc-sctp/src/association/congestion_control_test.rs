//! RFC 9260 section 7.2: the congestion window. Slow start, congestion avoidance, what a loss
//! does, Fast Recovery, the idle window, Max.Burst, and a change of path.

use super::robustness_test::*;
use super::*;
use crate::chunk::chunk_type::*;
use crate::endpoint::link_test::Link;

const PPI: PayloadProtocolIdentifier = PayloadProtocolIdentifier::Binary;
/// The payload of a full DATA chunk here: `create_association` gives 1400 bytes.
const CHUNK: usize = 1400;

fn config() -> TransportConfig {
    TransportConfig::default().with_heartbeat_interval(None)
}

/// An established association with `messages` full-size messages written on stream 1 and a
/// peer window that never limits it.
fn sender(config: TransportConfig, messages: usize, now: Instant) -> Association {
    let mut a = create_association(config);
    a.control_queue.clear();
    a.timers.stop(Timer::T1Init);
    a.set_state(AssociationState::Established);
    a.use_forward_tsn = true;
    a.rwnd = u32::MAX / 2;
    a.ssthresh = u32::MAX / 2;
    a.rto_mgr.set_rto(1000, true);
    let payload = Bytes::from(vec![7u8; CHUNK]);
    let mut s = a.open_stream(1, PPI).unwrap();
    for _ in 0..messages {
        s.write_sctp(now, &payload, PPI).unwrap();
    }
    a
}

/// What `a` sends now: the TSNs of its DATA chunks, packet by packet.
fn send(a: &mut Association, now: Instant) -> Vec<Vec<u32>> {
    a.gather_outbound(now)
        .0
        .iter()
        .map(|raw| {
            Packet::unmarshal(raw)
                .unwrap()
                .chunks
                .iter()
                .filter_map(|c| c.as_any().downcast_ref::<ChunkPayloadData>().map(|d| d.tsn))
                .collect::<Vec<u32>>()
        })
        .filter(|tsns| !tsns.is_empty())
        .collect()
}

fn sack(a: &mut Association, cumulative: u32, gaps: &[(u16, u16)], now: Instant) {
    a.handle_sack(
        &ChunkSelectiveAck {
            cumulative_tsn_ack: cumulative,
            advertised_receiver_window_credit: u32::MAX / 2,
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
        },
        now,
    )
    .unwrap();
}

fn flight(a: &Association) -> u32 {
    a.inflight_queue.get_num_bytes() as u32
}

/// RFC 9260 7.2.1: the initial cwnd is min(4 x PMDCS, max(2 x PMDCS, 4404)), 4344 over
/// IPv6, where PMDCS is the largest DATA chunk that fits a packet. It was the RFC 4960
/// formula on the MTU, with 4380 for both families.
#[test]
fn the_initial_congestion_window_is_the_rfc_9260_formula() {
    let v4: SocketAddr = "192.0.2.1:5000".parse().unwrap();
    let v6: SocketAddr = "[2001:db8::1]:5000".parse().unwrap();
    // (payload size, peer, PMDCS, expected cwnd)
    for (payload, peer, pmdcs, cwnd) in [
        (1400u32, v4, 1416u32, 4404u32), // 2 x PMDCS < 4404 < 4 x PMDCS
        (1400, v6, 1416, 4344),
        (484, v4, 500, 2000),   // 4 x PMDCS < 4404
        (2984, v4, 3000, 6000), // 2 x PMDCS > 4404
    ] {
        let a = Association::new(
            None,
            Arc::new(TransportConfig::default()),
            payload,
            0,
            peer,
            "0.0.0.0:0".parse().unwrap(),
            TransportProtocol::UDP,
            Instant::now(),
            crate::util::RandomSource::default(),
        );
        assert_eq!(pmdcs, a.pmdcs, "a packet less the common header");
        assert_eq!(cwnd, a.congestion_window(), "payload {payload} to {peer}");
    }
}

/// RFC 9260 7.2.1: the initial ssthresh is arbitrarily high: the peer's advertised window.
#[test]
fn the_initial_slow_start_threshold_is_the_peers_window() {
    let server = TransportConfig::default().with_max_receive_buffer_size(777_777);
    let mut link = Link::new(TransportConfig::default(), server, 301);
    link.connect();
    assert_eq!(777_777, link.client.conn().slow_start_threshold());
    assert_eq!(
        777_777,
        link.client.conn().rwnd,
        "and rwnd starts there (6.2.1 A)"
    );
}

/// RFC 9260 6.1 B, 7.2.1: new DATA is sent while less than cwnd is outstanding, so the last
/// chunk may cross cwnd, by less than one PMDCS and in one packet. A window that the next
/// chunk did not fit exactly was never in full use.
#[test]
fn the_last_chunk_sent_may_cross_the_window_by_less_than_a_packet() {
    let now = Instant::now();
    let mut a = sender(config(), 20, now);
    let cwnd = a.cwnd;
    assert_eq!(4404, cwnd);
    let sent = send(&mut a, now);
    assert_eq!(
        4,
        sent.len(),
        "three chunks stay under 4404, the fourth crosses it"
    );
    assert!(flight(&a) >= cwnd);
    assert!(flight(&a) - cwnd < a.pmdcs);
    assert!(send(&mut a, now).is_empty(), "nothing more until a SACK");
}

/// RFC 9260 7.2.1: in slow start a SACK grows cwnd by at most the bytes it acknowledges and
/// at most one PMDCS, and only when cwnd was in full use, the SACK advances the cumulative
/// TSN, and the sender is not in Fast Recovery. One SACK could double the window.
#[test]
fn slow_start_grows_by_at_most_one_packet_per_sack() {
    let now = Instant::now();
    let mut a = sender(config(), 50, now);
    let first = a.my_next_tsn;
    let pmdcs = a.pmdcs;
    assert_eq!(4, send(&mut a, now).len());
    let cwnd = a.cwnd;

    // A SACK for three packets at once: one PMDCS, not three.
    sack(&mut a, first.wrapping_add(2), &[], now);
    assert_eq!(cwnd + pmdcs, a.cwnd);

    // A SACK for less than a packet's worth grows it by what it acknowledges.
    let mut small = sender(config(), 0, now);
    let small_first = small.my_next_tsn;
    {
        let mut s = small.stream(1).unwrap();
        for _ in 0..200 {
            s.write_sctp(now, &Bytes::from_static(&[1; 100]), PPI)
                .unwrap();
        }
    }
    let _ = send(&mut small, now);
    let cwnd = small.cwnd;
    assert!(flight(&small) >= cwnd);
    sack(&mut small, small_first, &[], now);
    assert_eq!(cwnd + 100, small.cwnd, "the bytes acknowledged");

    // Not in full use: no growth.
    let mut idle = sender(config(), 1, now);
    let idle_first = idle.my_next_tsn;
    let _ = send(&mut idle, now);
    let cwnd = idle.cwnd;
    assert!(flight(&idle) < cwnd);
    sack(&mut idle, idle_first, &[], now);
    assert_eq!(cwnd, idle.cwnd, "a window that was not full does not grow");

    // The cumulative TSN does not advance (only a gap is acknowledged): no growth.
    let mut gap = sender(config(), 50, now);
    let gap_first = gap.my_next_tsn;
    let _ = send(&mut gap, now);
    let cwnd = gap.cwnd;
    sack(&mut gap, gap_first.wrapping_sub(1), &[(2, 2)], now);
    assert_eq!(cwnd, gap.cwnd, "no growth without a new cumulative TSN");
}

/// L of RFC 9260 7.2.1 is 1 by default and may be configured larger.
#[test]
fn the_slow_start_growth_limit_is_configurable() {
    let now = Instant::now();
    let mut a = sender(config().with_slow_start_growth_limit(2), 50, now);
    let first = a.my_next_tsn;
    let pmdcs = a.pmdcs;
    let _ = send(&mut a, now);
    let cwnd = a.cwnd;
    sack(&mut a, first.wrapping_add(2), &[], now);
    assert_eq!(cwnd + 2 * pmdcs, a.cwnd, "at most L x PMDCS");
}

/// RFC 9260 7.2.2: above ssthresh, partial_bytes_acked counts what every SACK newly
/// acknowledges, gap blocks included; when it reaches cwnd, and cwnd was in full use, cwnd
/// grows by one PMDCS. So at most one PMDCS per round trip.
#[test]
fn congestion_avoidance_grows_one_packet_per_window() {
    let now = Instant::now();
    let mut a = sender(config(), 100, now);
    a.ssthresh = 1000; // below cwnd: congestion avoidance
    let first = a.my_next_tsn;
    let pmdcs = a.pmdcs;
    let cwnd = a.cwnd;
    assert_eq!(4, send(&mut a, now).len());

    // A gap block acknowledges one chunk: counted, though the cumulative TSN stays.
    sack(&mut a, first.wrapping_sub(1), &[(2, 2)], now);
    assert_eq!(CHUNK as u32, a.partial_bytes_acked);
    assert_eq!(cwnd, a.cwnd);
    let _ = send(&mut a, now);

    // Then one chunk per SACK, the window refilled each time. cwnd grows once a window's
    // worth has been acknowledged, by one PMDCS, and the count keeps the remainder.
    let mut acknowledged = CHUNK as u32;
    let mut cumulative = first.wrapping_sub(1);
    let mut sacks = 0;
    while a.cwnd == cwnd {
        cumulative = cumulative.wrapping_add(1);
        // The second chunk was acknowledged by the gap block already.
        if cumulative != first.wrapping_add(1) {
            acknowledged += CHUNK as u32;
        }
        assert!(
            acknowledged - (CHUNK as u32) < cwnd,
            "no growth after a full window was acknowledged"
        );
        // The receiver keeps reporting the gap-acknowledged chunk until the cumulative TSN
        // covers it: a SACK without it would be a renege (RFC 9260 6.2.1 D iii).
        let gaps: &[(u16, u16)] = if cumulative == first { &[(1, 1)] } else { &[] };
        sack(&mut a, cumulative, gaps, now);
        let _ = send(&mut a, now);
        sacks += 1;
        assert!(sacks < 20);
    }
    assert!(acknowledged >= cwnd, "not before a window's worth");
    assert_eq!(cwnd + pmdcs, a.cwnd, "one PMDCS");
    assert_eq!(acknowledged - cwnd, a.partial_bytes_acked);
}

/// RFC 9260 7.2.2: partial_bytes_acked is held at cwnd while cwnd is not in full use, and
/// starts over when everything sent has been acknowledged.
#[test]
fn partial_bytes_acked_is_capped_and_reset() {
    let now = Instant::now();
    let mut a = sender(config(), 3, now);
    a.ssthresh = 1000;
    a.cwnd = 100_000;
    let first = a.my_next_tsn;
    assert_eq!(3, send(&mut a, now).len());
    assert!(flight(&a) < a.cwnd);

    a.partial_bytes_acked = 99_500;
    sack(&mut a, first, &[], now);
    assert_eq!(100_000, a.partial_bytes_acked, "held at cwnd");
    assert_eq!(100_000, a.cwnd, "an unused window does not grow");

    sack(&mut a, first.wrapping_add(2), &[], now);
    assert!(a.inflight_queue.is_empty());
    assert_eq!(0, a.partial_bytes_acked, "all data acknowledged");
}

/// RFC 9260 7.2.3, 6.3.3: a T3-rtx expiry sets ssthresh to max(cwnd / 2, 4 x PMDCS), cwnd to
/// one PMDCS and partial_bytes_acked to 0, and retransmits what fits one packet: one packet
/// is in flight until it is acknowledged.
#[test]
fn a_retransmission_timeout_leaves_one_packet_in_flight() {
    let now = Instant::now();
    let mut a = sender(config(), 0, now);
    a.cwnd = 20 * a.pmdcs;
    a.ssthresh = 1000;
    a.partial_bytes_acked = 5000;
    let first = a.my_next_tsn;
    {
        // Small chunks: several fit a packet, and more than a PMDCS of them would not.
        let mut s = a.stream(1).unwrap();
        for _ in 0..60 {
            s.write_sctp(now, &Bytes::from_static(&[1; 300]), PPI)
                .unwrap();
        }
    }
    let sent: usize = send(&mut a, now).iter().map(Vec::len).sum();
    assert_eq!(60, sent);
    let cwnd = a.cwnd;
    let pmdcs = a.pmdcs;

    let at = a.timers.get(Timer::T3RTX).expect("T3-rtx runs");
    a.handle_timeout(at);
    assert_eq!(std::cmp::max(cwnd / 2, 4 * pmdcs), a.ssthresh);
    assert_eq!(pmdcs, a.cwnd);
    assert_eq!(0, a.partial_bytes_acked);

    let packets = send(&mut a, at);
    assert_eq!(1, packets.len(), "one packet");
    assert_eq!(first, packets[0][0], "of the earliest outstanding chunks");
    assert_eq!(4, packets[0].len(), "as many as fit it");
    assert!(
        send(&mut a, at).is_empty(),
        "and nothing else until it is acknowledged"
    );

    // The acknowledgement opens the window again, in slow start.
    sack(&mut a, packets[0][3], &[], at);
    assert!(a.cwnd > pmdcs);
    assert!(!send(&mut a, at).is_empty());
}

/// Sends `n` full chunks and reports the first missing three times, which puts the sender in
/// Fast Recovery. Returns the first TSN.
fn into_fast_recovery(a: &mut Association, n: u32, now: Instant) -> u32 {
    let first = a.my_next_tsn;
    a.cwnd = n * CHUNK as u32;
    let sent: usize = send(a, now).iter().map(Vec::len).sum();
    assert_eq!(n as usize, sent);
    for gap_end in 2..=4u16 {
        sack(a, first.wrapping_sub(1), &[(2, gap_end)], now);
    }
    assert!(a.in_fast_recovery);
    first
}

/// RFC 9260 7.2.3, 7.2.4: a loss found by SACKs sets ssthresh to max(cwnd / 2, 4 x PMDCS)
/// and cwnd to ssthresh, once. Fast Recovery then lasts until everything that was
/// outstanding is acknowledged: a second loss in that window does not cut cwnd again. The
/// exit point was the highest TSN newly acknowledged, so recovery ended early.
#[test]
fn fast_recovery_lasts_until_what_was_outstanding_is_acknowledged() {
    let now = Instant::now();
    let mut a = sender(config(), 40, now);
    let pmdcs = a.pmdcs;
    let first = into_fast_recovery(&mut a, 20, now);
    let cwnd_before = 20 * CHUNK as u32;
    assert_eq!(std::cmp::max(cwnd_before / 2, 4 * pmdcs), a.ssthresh);
    assert_eq!(a.ssthresh, a.cwnd);
    assert_eq!(0, a.partial_bytes_acked);
    assert_eq!(
        first.wrapping_add(19),
        a.fast_recover_exit_point,
        "the highest TSN outstanding"
    );
    let cut = a.cwnd;
    let retransmitted = send(&mut a, now);
    assert_eq!(
        first, retransmitted[0][0],
        "the lost chunk is retransmitted"
    );

    // The retransmission arrives; a second chunk of the same window (the 9th) is lost too.
    sack(&mut a, first.wrapping_add(7), &[(2, 3)], now);
    sack(&mut a, first.wrapping_add(7), &[(2, 4)], now);
    sack(&mut a, first.wrapping_add(7), &[(2, 5)], now);
    assert!(a.in_fast_recovery, "still recovering the same window");
    assert_eq!(cut, a.ssthresh, "not reduced again");
    assert!(a.cwnd >= cut);

    // Everything that was outstanding at the loss is acknowledged: recovery is over.
    sack(&mut a, first.wrapping_add(19), &[], now);
    assert!(!a.in_fast_recovery);
}

/// RFC 9260 7.2.4 step 4: T3-rtx starts over when the first outstanding chunk is fast
/// retransmitted.
#[test]
fn fast_retransmit_of_the_first_outstanding_chunk_restarts_t3() {
    let start = Instant::now();
    let mut a = sender(config(), 40, start);
    let first = a.my_next_tsn;
    a.cwnd = 20 * CHUNK as u32;
    let _ = send(&mut a, start);
    let t3 = a.timers.get(Timer::T3RTX).expect("T3-rtx runs");

    let later = start + Duration::from_millis(600);
    for gap_end in 2..=4u16 {
        sack(&mut a, first.wrapping_sub(1), &[(2, gap_end)], later);
    }
    let retransmitted = send(&mut a, later);
    assert_eq!(vec![first], retransmitted[0]);
    assert_eq!(
        Some(later + Duration::from_millis(1000)),
        a.timers.get(Timer::T3RTX),
        "a full RTO from the retransmission, not {t3:?}"
    );
}

/// RFC 9260 7.2.4 steps 3 and 5: a Fast Retransmit is one packet that ignores cwnd. Chunks
/// marked for it that do not fit are retransmitted when cwnd allows, not in a second burst
/// that ignores cwnd too.
#[test]
fn chunks_that_do_not_fit_the_fast_retransmit_packet_wait_for_the_window() {
    let now = Instant::now();
    let mut a = sender(config(), 40, now);
    let first = a.my_next_tsn;
    a.cwnd = 20 * CHUNK as u32;
    let _ = send(&mut a, now);
    // The first three chunks are missing: three reports for each.
    for gap_end in 4..=6u16 {
        sack(&mut a, first.wrapping_sub(1), &[(4, gap_end)], now);
    }
    assert!(a.in_fast_recovery);

    let packets = send(&mut a, now);
    assert_eq!(vec![first], packets[0], "one full chunk is the one packet");
    // cwnd is in full use, so the other two wait; they are no Fast Retransmit candidates.
    assert_eq!(1, packets.len());
    for tsn in [first.wrapping_add(1), first.wrapping_add(2)] {
        let c = a.inflight_queue.get(tsn).unwrap();
        assert!(c.retransmit, "marked for retransmission");
        assert!(!c.is_fast_retransmit_candidate());
    }
    // Another SACK in Fast Recovery does not send them past the window either.
    sack(&mut a, first.wrapping_sub(1), &[(4, 7)], now);
    assert!(
        send(&mut a, now)
            .iter()
            .flatten()
            .all(|tsn| *tsn != first.wrapping_add(1))
    );

    // Once the window opens they go out.
    a.cwnd = u32::MAX / 2;
    let sent: Vec<u32> = send(&mut a, now).into_iter().flatten().collect();
    assert!(sent.contains(&first.wrapping_add(1)) && sent.contains(&first.wrapping_add(2)));
}

/// RFC 9260 7.2.1, 7.1: a window that is not used decays, to max(cwnd / 2, 4 x PMDCS) once
/// per RTO, and ssthresh keeps what cwnd was. A burst after a pause used the old window.
#[test]
fn an_idle_congestion_window_decays() {
    let start = Instant::now();
    let mut a = sender(config(), 1, start);
    let first = a.my_next_tsn;
    let pmdcs = a.pmdcs;
    let _ = send(&mut a, start);
    sack(&mut a, first, &[], start);
    assert!(a.inflight_queue.is_empty());
    a.cwnd = 64 * pmdcs;
    a.ssthresh = 1000;

    // Three RTOs (1 s each) without sending: three halvings.
    let later = start + Duration::from_millis(3500);
    a.stream(1)
        .unwrap()
        .write_sctp(later, &Bytes::from_static(b"after the pause"), PPI)
        .unwrap();
    let _ = send(&mut a, later);
    assert_eq!(8 * pmdcs, a.cwnd);
    assert_eq!(
        64 * pmdcs,
        a.ssthresh,
        "what cwnd was before the first step"
    );

    // A long pause stops at 4 x PMDCS.
    sack(&mut a, first.wrapping_add(1), &[], later);
    let much_later = later + Duration::from_secs(3600);
    a.stream(1)
        .unwrap()
        .write_sctp(much_later, &Bytes::from_static(b"x"), PPI)
        .unwrap();
    let _ = send(&mut a, much_later);
    assert_eq!(4 * pmdcs, a.cwnd);

    // A window in use does not decay, however long its DATA has been outstanding.
    let mut busy = sender(config(), 100, start);
    busy.cwnd = 64 * pmdcs;
    let _ = send(&mut busy, start);
    let _ = send(&mut busy, start + Duration::from_secs(30));
    assert_eq!(64 * pmdcs, busy.cwnd);
}

/// RFC 9260 6.1 D, 16: with Max.Burst, cwnd is brought down to what is outstanding plus
/// Max.Burst packets before DATA is sent. Four packets by default.
#[test]
fn max_burst_limits_what_is_released_at_once() {
    assert_eq!(Some(4), TransportConfig::default().max_burst());
    let unlimited = Association::new(
        None,
        Arc::new(TransportConfig::default().with_max_burst(None)),
        1400,
        0,
        SocketAddr::from_str("0.0.0.0:0").unwrap(),
        SocketAddr::from_str("0.0.0.0:0").unwrap(),
        TransportProtocol::UDP,
        Instant::now(),
        crate::util::RandomSource::default(),
    );
    assert_eq!(None, unlimited.max_burst);
    let now = Instant::now();
    for (max_burst, packets) in [(Some(3), 4), (None, 40)] {
        let mut a = sender(config().with_max_burst(max_burst), 40, now);
        let pmdcs = a.pmdcs;
        a.cwnd = 40 * CHUNK as u32;
        let sent = send(&mut a, now);
        assert_eq!(packets, sent.len(), "Max.Burst {max_burst:?}");
        if max_burst.is_some() {
            assert_eq!(3 * pmdcs, a.cwnd, "nothing outstanding plus three packets");
        }
    }
}

/// RFC 9260 7.2.5: when the path changes, congestion control and the RTO start again from
/// their initial values, and the timer of what is outstanding runs on the initial RTO.
#[test]
fn a_path_change_restarts_congestion_control_and_the_rto() {
    let now = Instant::now();
    let mut a = sender(config(), 40, now);
    let first = into_fast_recovery(&mut a, 20, now);
    a.rto_mgr.set_rto(8000, false);
    a.rto_mgr.srtt = 900;
    a.partial_bytes_acked = 777;
    assert!(a.in_fast_recovery && a.cwnd != 4404);

    let later = now + Duration::from_millis(100);
    a.on_path_change(later);

    assert_eq!(4404, a.congestion_window(), "the initial cwnd");
    assert!(a.slow_start_threshold() >= a.rwnd, "arbitrarily high again");
    assert_eq!(0, a.partial_bytes_acked);
    assert!(!a.in_fast_recovery);
    assert_eq!(Duration::from_secs(1), a.rto(), "RTO.Initial");
    assert_eq!(Duration::ZERO, a.rtt(), "no RTT of the old path");
    assert_eq!(
        Some(later + Duration::from_secs(1)),
        a.timers.get(Timer::T3RTX),
        "the outstanding DATA is timed on the new path"
    );
    assert!(
        a.inflight_queue.get(first).is_some(),
        "it stays outstanding"
    );
}

// ---- The receive window and when a SACK is sent (RFC 9260 6.2) ------------------------------

/// A connected link whose server has a receive buffer of `buffer` bytes and an application
/// that does not read.
fn link_with_receive_buffer(buffer: u32, seed: u64) -> Link {
    let server = config().with_max_receive_buffer_size(buffer);
    let mut link = Link::new(config(), server, seed);
    link.connect();
    link.server.auto_read = false;
    link
}

fn a_rwnd_of(sack: &[u8]) -> u32 {
    u32::from_be_bytes(sack[8..12].try_into().unwrap())
}

fn cumulative_of(sack: &[u8]) -> u32 {
    u32::from_be_bytes(sack[4..8].try_into().unwrap())
}

/// RFC 9260 6.2: when the application drains a receive buffer whose window was advertised as
/// closed, a SACK announces the window at once. Reading never sent a SACK, so the sender,
/// stopped by a_rwnd 0, found out from its next window probe, a retransmission timeout later.
#[test]
fn a_sack_announces_the_window_when_the_application_drains_it() {
    let mut link = link_with_receive_buffer(4000, 311);
    let now = link.now;
    {
        let mut s = link.client.conn().open_stream(1, PPI).unwrap();
        for i in 0..30u8 {
            s.write_sctp(now, &Bytes::from(vec![i; 1000]), PPI).unwrap();
        }
    }
    link.run_for(Duration::from_millis(400));
    assert_eq!(
        0,
        link.server.conn().last_advertised_window,
        "the window closed"
    );

    // The application reads everything that is there.
    let mut read = 0;
    while let Ok(Some(_)) = link.server.conn().stream(1).unwrap().read_sctp() {
        read += 1;
    }
    assert!(read > 0);
    let drained_at = link.now;
    let sent = sent_datagrams(link.server.conn(), drained_at);
    let sacks = chunks_of_type(&sent, CT_SACK.0);
    assert_eq!(1, sacks.len(), "a SACK at once");
    assert!(a_rwnd_of(&sacks[0]) > 0, "that announces the window");

    // From the same state, the sender is going again well within its retransmission timeout.
    let mut link = link_with_receive_buffer(4000, 311);
    let now = link.now;
    {
        let mut s = link.client.conn().open_stream(1, PPI).unwrap();
        for i in 0..30u8 {
            s.write_sctp(now, &Bytes::from(vec![i; 1000]), PPI).unwrap();
        }
    }
    link.run_for(Duration::from_millis(400));
    let mut read = 0;
    while let Ok(Some(_)) = link.server.conn().stream(1).unwrap().read_sctp() {
        read += 1;
    }
    let drained_at = link.now;
    let before = link.bytes_sent[0];
    link.run_for(Duration::from_millis(100));
    assert!(read > 0 && link.now - drained_at == Duration::from_millis(100));
    assert!(
        link.bytes_sent[0] - before >= 1000,
        "the sender sent no new DATA in the 100 ms after the window reopened"
    );
}

/// RFC 9260 6.2: a DATA chunk dropped for lack of receive window is answered with a SACK at
/// once, and that SACK does not acknowledge the chunk.
#[test]
fn a_chunk_dropped_for_lack_of_window_is_answered_at_once() {
    let mut link = link_with_receive_buffer(3000, 312);
    let now = link.now;
    let a = link.server.conn();
    let tsn = a.peer_last_tsn.wrapping_add(1);
    for i in 0..2u32 {
        let raw = packet_to(
            a,
            &[data_chunk(tsn.wrapping_add(i), 1, i as u16, &[7u8; 1500])],
        );
        inject(a, now, raw);
    }
    let _ = sent_after(a, now, Duration::from_secs(1));
    assert_eq!(0, a.get_my_receiver_window_credit(), "the buffer is full");

    let later = now + Duration::from_secs(1);
    let raw = packet_to(a, &[data_chunk(tsn.wrapping_add(2), 1, 2, &[7u8; 1500])]);
    inject(a, later, raw);
    let sacks = chunks_of_type(&sent_datagrams(a, later), CT_SACK.0);
    assert_eq!(1, sacks.len(), "a SACK without delay");
    assert_eq!(
        tsn.wrapping_add(1),
        cumulative_of(&sacks[0]),
        "the dropped chunk is not in it"
    );
    assert_eq!(
        0,
        u16::from_be_bytes([sacks[0][12], sacks[0][13]]),
        "nor in a Gap Ack Block"
    );
    assert_eq!(0, a_rwnd_of(&sacks[0]));
}

/// RFC 9260 6.2 (RFC 1122 4.2.3.3): the receiver avoids the silly window syndrome. A window
/// too small for a full packet is advertised as closed; the raw free space was advertised.
#[test]
fn a_window_smaller_than_a_packet_is_advertised_as_closed() {
    let mut link = link_with_receive_buffer(4000, 313);
    let now = link.now;
    let a = link.server.conn();
    let pmdcs = a.pmdcs;
    let tsn = a.peer_last_tsn.wrapping_add(1);
    let raw = packet_to(a, &[data_chunk(tsn, 1, 0, &[7u8; 1000])]);
    inject(a, now, raw);
    let sacks = chunks_of_type(&sent_datagrams(a, now), CT_SACK.0);
    assert_eq!(
        3000,
        a_rwnd_of(&sacks[0]),
        "room for more than a packet: as it is"
    );

    let free = 4000 - 1000 - 2400;
    assert!(free < pmdcs && free > 0);
    let raw = packet_to(a, &[data_chunk(tsn.wrapping_add(1), 1, 1, &[7u8; 2400])]);
    inject(a, now, raw);
    let sacks = chunks_of_type(&sent_after(a, now, Duration::from_secs(1)), CT_SACK.0);
    assert_eq!(0, a_rwnd_of(&sacks[0]), "{free} bytes are not offered");
    assert_eq!(
        free,
        a.get_my_receiver_window_credit(),
        "though they are there"
    );
}

/// RFC 9260 6.2, 16: SACK.Delay is 200 ms, configurable, and never more than 500 ms.
#[test]
fn the_sack_delay_is_configurable_up_to_half_a_second() {
    assert_eq!(
        Duration::from_millis(500),
        TransportConfig::default()
            .with_sack_delay(Duration::from_secs(3))
            .sack_delay()
    );
    for (configured, delay) in [
        (None, 200u64),
        (Some(Duration::from_millis(50)), 50),
        (Some(Duration::from_secs(3)), 500),
    ] {
        let mut server = config();
        if let Some(value) = configured {
            server = server.with_sack_delay(value);
        }
        let mut link = Link::new(config(), server, 314);
        link.connect();
        let now = link.now;
        let a = link.server.conn();
        let tsn = a.peer_last_tsn.wrapping_add(1);
        // The first DATA of the association is acknowledged at once; the second waits.
        let raw = packet_to(a, &[data_chunk(tsn, 1, 0, b"first")]);
        inject(a, now, raw);
        let _ = sent_datagrams(a, now);
        let raw = packet_to(a, &[data_chunk(tsn.wrapping_add(1), 1, 1, b"second")]);
        inject(a, now, raw);
        assert!(chunks_of_type(&sent_datagrams(a, now), CT_SACK.0).is_empty());
        assert_eq!(
            Some(now + Duration::from_millis(delay)),
            a.timers.get(Timer::Ack),
            "SACK.Delay {configured:?}"
        );
        let at = now + Duration::from_millis(delay);
        a.handle_timeout(at);
        assert_eq!(1, chunks_of_type(&sent_datagrams(a, at), CT_SACK.0).len());
    }
}

/// RFC 9260 6.2 (RFC 7053): a DATA chunk with the I bit is acknowledged without delay.
#[test]
fn a_data_chunk_with_the_i_bit_is_acknowledged_at_once() {
    let mut link = connected_link(315);
    let now = link.now;
    let a = link.server.conn();
    a.first_data_received = true;
    let tsn = a.peer_last_tsn.wrapping_add(1);

    let raw = packet_to(a, &[data_chunk(tsn, 1, 0, b"no hurry")]);
    inject(a, now, raw);
    assert!(chunks_of_type(&sent_datagrams(a, now), CT_SACK.0).is_empty());

    let mut urgent = data_chunk(tsn.wrapping_add(1), 1, 1, b"at once");
    urgent[1] |= 0x08;
    let raw = packet_to(a, &[urgent]);
    inject(a, now, raw);
    let sacks = chunks_of_type(&sent_datagrams(a, now), CT_SACK.0);
    assert_eq!(1, sacks.len());
    assert_eq!(tsn.wrapping_add(1), cumulative_of(&sacks[0]));
}
