//! RFC 9260 SHOULD rows of phase four: zero window probing (6.1 A), the rwnd rules B and C of
//! 6.2.1, the receiver's SACKs (6.2), and what this side's INIT ACK carries (5.2.2, 12.4).

use super::robustness_test::*;
use super::*;
use crate::TimerConfig;
use crate::chunk::chunk_type::*;
use crate::endpoint::link_test::{Link, first_chunk_type};
use std::cell::RefCell;
use std::rc::Rc;

fn sack(cumulative_tsn_ack: u32, a_rwnd: u32, gaps: &[(u16, u16)]) -> ChunkSelectiveAck {
    ChunkSelectiveAck {
        cumulative_tsn_ack,
        advertised_receiver_window_credit: a_rwnd,
        gap_ack_blocks: gaps
            .iter()
            .map(|&(start, end)| crate::chunk::chunk_selective_ack::GapAckBlock { start, end })
            .collect(),
        duplicate_tsn: vec![],
    }
}

/// `n` 100-byte messages in flight as TSNs 100 onward, with a wide window.
fn in_flight(n: usize, now: Instant) -> Result<Association> {
    let mut a = timed_test_association();
    a.my_next_tsn = 100;
    a.cumulative_tsn_ack_point = 99;
    a.advanced_peer_tsn_ack_point = 99;
    a.min_tsn2measure_rtt = 100;
    a.cwnd = 64 * a.mtu;
    a.ssthresh = a.cwnd;
    let ppi = PayloadProtocolIdentifier::Binary;
    let mut stream = a.open_stream(1, ppi)?;
    for _ in 0..n {
        stream.write_sctp(now, &Bytes::from(vec![0x5a; 100]), ppi)?;
    }
    assert_eq!(n, transmitted_data(&a.gather_outbound(now).0).len());
    Ok(a)
}

/// RFC 9260 6.1 A: "The sender SHOULD send the first zero window probe after 1 RTO when it
/// detects that the receiver has closed its window and SHOULD increase the probe interval
/// exponentially afterwards." A SACK that acknowledges everything with a_rwnd 0 leaves new
/// DATA queued: nothing goes before one RTO, one chunk goes at it, and the probe's own
/// retransmissions follow T3-rtx, whose interval doubles.
#[test]
fn the_first_zero_window_probe_waits_one_rto() -> Result<()> {
    let start = Instant::now();
    let mut a = in_flight(1, start)?;
    // An RTO that backs off (the test association's is fixed at 1 s).
    a.rto_mgr.set_rto(1000, false);
    a.handle_sack(&sack(100, 0, &[]), start)?;
    assert!(a.inflight_queue.is_empty());
    let rto = Duration::from_millis(a.rto_mgr.get_rto());
    let ppi = PayloadProtocolIdentifier::Binary;
    a.stream(1)?
        .write_sctp(start, &Bytes::from(vec![1; 100]), ppi)?;

    assert!(
        transmitted_data(&a.gather_outbound(start).0).is_empty(),
        "no probe at once"
    );
    let early = start + rto - Duration::from_millis(1);
    assert!(transmitted_data(&a.gather_outbound(early).0).is_empty());
    assert!(
        a.poll_timeout().is_some_and(|at| at <= start + rto),
        "the association wakes for it"
    );
    let at = start + rto;
    a.handle_timeout(at);
    let probe = transmitted_data(&a.gather_outbound(at).0);
    assert_eq!(probe.len(), 1, "one zero window probe after one RTO");

    // Unanswered, the probe goes again at T3-rtx, then twice as late.
    let first = a
        .timers
        .get(Timer::T3RTX)
        .expect("T3-rtx runs for the probe");
    a.handle_timeout(first);
    assert_eq!(transmitted_data(&a.gather_outbound(first).0).len(), 1);
    let second = a.timers.get(Timer::T3RTX).expect("T3-rtx again");
    assert_eq!(second - first, 2 * (first - at), "the interval doubles");
    Ok(())
}

/// RFC 9260 6.1 A: "If the sender continues to receive SACK chunks from the peer while doing
/// zero window probing, the unacknowledged window probes SHOULD NOT increment the error
/// counter for the association or any destination transport address." With a limit of two
/// T3-rtx expiries, a receiver that keeps its window shut and keeps answering with SACKs does
/// not end the association, through many more expiries.
#[test]
fn probes_answered_with_sacks_do_not_count_as_errors() -> Result<()> {
    let start = Instant::now();
    let mut a = in_flight(1, start)?;
    a.timers = TimerTable::new(TimerConfig {
        max_t3_rtx_retrans: 2,
        ..TimerConfig::default()
    });
    a.handle_sack(&sack(100, 0, &[]), start)?;
    let ppi = PayloadProtocolIdentifier::Binary;
    a.stream(1)?
        .write_sctp(start, &Bytes::from(vec![1; 100]), ppi)?;
    let mut now = start + Duration::from_millis(a.rto_mgr.get_rto());
    a.handle_timeout(now);
    assert_eq!(transmitted_data(&a.gather_outbound(now).0).len(), 1);
    for expiry in 0..6 {
        now = a
            .timers
            .get(Timer::T3RTX)
            .expect("T3-rtx runs for the probe");
        a.handle_timeout(now);
        assert!(!a.is_ended(), "ended at probe expiry {expiry}");
        let _ = a.gather_outbound(now);
        // The receiver answers the probe with a SACK that keeps its window shut: it took
        // nothing (the probe's TSN is not acknowledged).
        a.handle_sack(&sack(100, 0, &[]), now)?;
    }
    assert!(!a.is_ended());
    assert_eq!(a.path_error_count, 0, "no error counted while SACKs come");
    Ok(())
}

/// RFC 9260 6.2.1 B: "Any time a DATA chunk is transmitted (or retransmitted) to a peer, the
/// endpoint subtracts the data size of the chunk from the rwnd of that peer", and C: "Any time
/// a DATA chunk is marked for retransmission, either via T3-rtx timer expiration (Section
/// 6.3.3) or via Fast Retransmit (Section 7.2.4), add the data size of those chunks to the
/// rwnd." After a T3-rtx expiry the ten marked chunks are back in rwnd; each one sent again
/// takes its 100 bytes out of it.
#[test]
fn chunks_marked_for_retransmission_go_back_to_rwnd_and_out_again_when_sent() -> Result<()> {
    let now = Instant::now();
    let mut a = in_flight(10, now)?;
    let before = a.rwnd;
    let expiry = a.timers.get(Timer::T3RTX).expect("T3-rtx");
    a.handle_timeout(expiry);
    assert_eq!(a.rwnd, before + 1000, "rule C: the ten marked chunks");
    let sent = transmitted_data(&a.gather_outbound(expiry).0);
    assert!(!sent.is_empty(), "retransmissions after T3-rtx");
    assert_eq!(
        a.rwnd,
        before + 1000 - 100 * sent.len() as u32,
        "rule B: {} chunks retransmitted",
        sent.len()
    );
    Ok(())
}

/// RFC 9260 6.2.1 B and C with Fast Retransmit: three SACKs that report TSN 100 missing mark
/// it (its 100 bytes go back to rwnd, C) and it is sent again at once (they come out again, B).
#[test]
fn a_fast_retransmit_gives_back_and_takes_rwnd() -> Result<()> {
    let now = Instant::now();
    let mut a = in_flight(10, now)?;
    let a_rwnd = 1 << 20;
    let mut marked = None;
    for end in 1..=3u16 {
        // TSN 100 missing; 101 onward acknowledged by the block (offsets from 99).
        a.handle_sack(&sack(99, a_rwnd, &[(2, end + 1)]), now)?;
        if a.fast_retransmit_marked.contains(&100) && marked.is_none() {
            marked = Some(a.rwnd);
        }
    }
    let marked = marked.expect("TSN 100 marked for Fast Retransmit");
    // a_rwnd minus what is outstanding (100 to 109 less the three gap-acknowledged), plus the
    // marked chunk.
    let outstanding = a.inflight_queue.get_num_bytes() as u32;
    assert_eq!(marked, a_rwnd - outstanding + 100, "rule C");
    let again = transmitted_data(&a.gather_outbound(now).0);
    assert!(again.iter().any(|c| c.tsn == 100), "fast retransmitted");
    assert_eq!(a.rwnd, marked - 100, "rule B");
    Ok(())
}

/// RFC 9260 6.2: "An SCTP receiver MUST NOT generate more than one SACK chunk for every
/// incoming packet ... the data receiver SHOULD NOT revoke a SACK", that is, SHOULD NOT drop
/// DATA it acknowledged. TSNs a Gap Ack Block acknowledged stay acknowledged in every later
/// SACK, while the receive buffer fills: the receiver keeps what it reported.
#[test]
fn a_receiver_does_not_revoke_what_its_sacks_acknowledged() {
    let (_, a, _) = accept_init(&[]);
    let mut a = a.expect("an association");
    a.set_state(AssociationState::Established);
    a.peer_last_tsn = 99;
    let now = Instant::now();
    let gap_blocks = |a: &mut Association, chunks: &[Vec<u8>]| {
        let raw = packet_to(a, chunks);
        inject(a, now, raw);
        let sent = sent_after(a, now, Duration::from_secs(1));
        let sacks = chunks_of_type(&sent, CT_SACK.0);
        let sack = sacks.last().expect("a SACK").clone();
        let blocks = u16::from_be_bytes([sack[12], sack[13]]);
        let cumulative = u32::from_be_bytes(sack[4..8].try_into().unwrap());
        (cumulative, blocks)
    };
    // TSN 100 is missing: 101 and 102 are held and acknowledged by a block.
    let (cumulative, blocks) = gap_blocks(
        &mut a,
        &[
            data_chunk(101, 0, 1, b"one hundred and one"),
            data_chunk(102, 0, 2, b"one hundred and two"),
        ],
    );
    assert_eq!((cumulative, blocks), (99, 1));
    for tsn in 103..110u32 {
        let (cumulative, blocks) = gap_blocks(&mut a, &[data_chunk(tsn, 0, 3, b"more")]);
        assert_eq!(cumulative, 99, "TSN 100 still missing");
        assert!(blocks >= 1, "TSN {tsn}: the blocks are still reported");
    }
    let (cumulative, _) = gap_blocks(&mut a, &[data_chunk(100, 0, 0, b"one hundred")]);
    assert_eq!(cumulative, 109, "nothing acknowledged was dropped");
}

/// RFC 9260 12.4: "the INIT ACK chunk ... SHOULD be as small as possible", to limit what an
/// unauthenticated INIT can make this side send. It carries the State Cookie and the extension
/// parameters this side supports, nothing else, and the cookie is the signer's fixed size.
#[test]
fn the_init_ack_carries_the_cookie_and_the_extensions_only() {
    const STATE_COOKIE: u16 = 7;
    const SUPPORTED_EXTENSIONS: u16 = 0x8008;
    const FORWARD_TSN_SUPPORTED: u16 = 0xC000;
    const ZERO_CHECKSUM_ACCEPTABLE: u16 = 0x8001;
    let (_, _, sent) = accept_init(&[]);
    let init_acks = chunks_of_type(&sent, CT_INIT_ACK.0);
    assert_eq!(init_acks.len(), 1);
    let init_ack = &init_acks[0];
    let params = tlvs(&init_ack[20..]);
    for (typ, _) in &params {
        assert!(
            [
                STATE_COOKIE,
                SUPPORTED_EXTENSIONS,
                FORWARD_TSN_SUPPORTED,
                ZERO_CHECKSUM_ACCEPTABLE
            ]
            .contains(typ),
            "parameter {typ:#06x} in the INIT ACK"
        );
    }
    let cookie = params
        .iter()
        .find(|(t, _)| *t == STATE_COOKIE)
        .map(|(_, v)| v.len())
        .expect("a State Cookie");
    let (_, _, again) = accept_init(&[raw_tlv(0x80F0, &[0; 64])]);
    let again = tlvs(&chunks_of_type(&again, CT_INIT_ACK.0)[0][20..]);
    let cookie_again = again
        .iter()
        .find(|(t, _)| *t == STATE_COOKIE)
        .map(|(_, v)| v.len())
        .expect("a State Cookie");
    assert_eq!(
        cookie, cookie_again,
        "the cookie does not grow with what the INIT carries"
    );
    assert!(
        init_ack.len() <= 20 + 4 + cookie + 16 + 4 + 8,
        "{} bytes",
        init_ack.len()
    );
}

/// RFC 9260 5.2.2: the INIT ACK that answers an INIT for an existing association has a new
/// Initiate Tag and its own Tie-Tags; "Other parameters for the endpoint SHOULD be copied from
/// the existing parameters of the association (e.g., number of outbound streams) into the INIT
/// ACK and cookie." Its stream counts, a_rwnd and extension parameters are those of the INIT
/// ACK that set the association up.
#[test]
fn an_init_ack_for_an_existing_association_copies_its_parameters() {
    let captured = Rc::new(RefCell::new((None, None)));
    let seen = captured.clone();
    let mut link = Link::new(TransportConfig::default(), TransportConfig::default(), 23);
    link.filter = Some(Box::new(move |from_client: bool, datagram: &Bytes| {
        let mut seen = seen.borrow_mut();
        match first_chunk_type(datagram) {
            Some(t) if t == CT_INIT.0 && from_client => seen.0 = Some(datagram.clone()),
            Some(t) if t == CT_INIT_ACK.0 && !from_client && seen.1.is_none() => {
                seen.1 = Some(datagram.clone())
            }
            _ => {}
        }
        false
    }));
    link.connect();
    let (init, first) = captured.borrow().clone();
    let (init, first) = (init.expect("the INIT"), first.expect("the INIT ACK"));
    let now = link.now;
    let a = link.server.conn();
    inject(a, now, init);
    let sent = sent_datagrams(a, now);
    let answers = chunks_of_type(&sent, CT_INIT_ACK.0);
    assert_eq!(answers.len(), 1);
    let first = &chunks_of(&first)[0];
    let answer = &answers[0];
    assert_eq!(answer[8..16], first[8..16], "a_rwnd, OS and MIS");
    let kinds = |chunk: &[u8]| -> Vec<(u16, Vec<u8>)> {
        tlvs(&chunk[20..])
            .into_iter()
            .filter(|(t, _)| *t != 7)
            .collect()
    };
    assert_eq!(kinds(answer), kinds(first), "the extension parameters");
}

/// RFC 9653 section 4: the Zero Checksum Acceptable parameter goes in the INIT and the INIT
/// ACK, and "MUST NOT appear in any other chunk". Two associations with the zero checksum
/// turned on exchange their handshake, HEARTBEATs and a stream reset (RE-CONFIG): the
/// parameter is in the INIT and the INIT ACK, and in no HEARTBEAT, HEARTBEAT ACK or RE-CONFIG.
#[test]
fn the_zero_checksum_parameter_is_in_the_init_and_init_ack_only() {
    const ZERO_CHECKSUM_ACCEPTABLE: u16 = 0x8001;
    const HEARTBEAT: u8 = 4;
    const HEARTBEAT_ACK: u8 = 5;
    const RECONFIG: u8 = 130;
    let seen: Rc<RefCell<Vec<Vec<u8>>>> = Rc::new(RefCell::new(vec![]));
    let record = seen.clone();
    let config = || {
        TransportConfig::default()
            .with_zero_checksum(true)
            .with_heartbeat_interval(Some(Duration::from_secs(1)))
    };
    let mut link = Link::new(config(), config(), 24);
    link.filter = Some(Box::new(move |_, datagram: &Bytes| {
        record.borrow_mut().extend(chunks_of(datagram));
        false
    }));
    link.connect();
    let ppi = PayloadProtocolIdentifier::Binary;
    let now = link.now;
    link.client
        .conn()
        .open_stream(3, ppi)
        .unwrap()
        .write_sctp(now, &Bytes::from_static(b"to reset"), ppi)
        .unwrap();
    let deadline = link.now + Duration::from_secs(5);
    link.run_until(deadline, |l| !l.server.received.is_empty());
    let now = link.now;
    link.client.conn().stream(3).unwrap().close(now).unwrap();
    let deadline = link.now + Duration::from_secs(5);
    link.run_until(deadline, |_| false);

    let chunks = seen.borrow();
    let carries = |chunk: &Vec<u8>, skip: usize| {
        chunk.len() > skip
            && tlvs(&chunk[skip..])
                .iter()
                .any(|(t, _)| *t == ZERO_CHECKSUM_ACCEPTABLE)
    };
    for typ in [CT_INIT.0, CT_INIT_ACK.0] {
        let of_type: Vec<&Vec<u8>> = chunks.iter().filter(|c| c[0] == typ).collect();
        assert!(!of_type.is_empty(), "chunk {typ}");
        assert!(
            of_type.iter().all(|c| carries(c, 20)),
            "chunk {typ} announces it"
        );
    }
    for typ in [HEARTBEAT, HEARTBEAT_ACK, RECONFIG] {
        let of_type: Vec<&Vec<u8>> = chunks.iter().filter(|c| c[0] == typ).collect();
        assert!(!of_type.is_empty(), "no chunk {typ} was sent");
        assert!(
            of_type.iter().all(|c| !carries(c, 4)),
            "chunk {typ} carries the parameter"
        );
    }
}
