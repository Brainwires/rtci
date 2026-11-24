//! A closed receive window always makes progress (RFC 9260 6.1 A, 6.2): the sender probes,
//! a probe the receiver takes is progress, and a message larger than the receive buffer is
//! delivered at the pace of the link, not one fragment per retransmission timeout.
//!
//! The sweep at the end runs message sizes from 1 byte to 4 MiB against receive buffers from
//! the smallest a_rwnd an INIT may carry to 1 MiB, ordered and unordered, with and without
//! I-DATA (RFC 8260), at 0, 2 and 10 % loss, in virtual time. Every run delivers everything
//! or ends with a reported error; none may stall.

use super::*;
use crate::endpoint::link_test::Link;
use crate::{AssociationError, TransportConfig};

fn sack(cumulative_tsn_ack: u32, a_rwnd: u32) -> ChunkSelectiveAck {
    ChunkSelectiveAck {
        cumulative_tsn_ack,
        advertised_receiver_window_credit: a_rwnd,
        gap_ack_blocks: vec![],
        duplicate_tsn: vec![],
    }
}

/// RFC 9260 6.1 A: the first zero window probe waits one RTO after the window closed. A
/// SACK that then acknowledges the probe with a_rwnd still 0 shows the receiver taking DATA
/// through its closed window (the chunk that completes a message its full buffer holds the
/// start of, webrtc-rs/webrtc#822): that is progress, and the next probe goes at once.
/// Waiting one RTO again before each one delivered a message larger than the receive buffer
/// at one fragment per second. A probe the receiver drops (its SACK does not acknowledge it)
/// stays outstanding, and only T3-rtx sends it again.
#[test]
fn an_acknowledged_zero_window_probe_lets_the_next_one_go_at_once() -> Result<()> {
    let start = Instant::now();
    let mut a = timed_test_association();
    a.my_next_tsn = 100;
    a.cumulative_tsn_ack_point = 99;
    a.advanced_peer_tsn_ack_point = 99;
    a.min_tsn2measure_rtt = 100;
    a.cwnd = 64 * a.mtu;
    a.ssthresh = a.cwnd;
    let ppi = PayloadProtocolIdentifier::Binary;
    a.open_stream(1, ppi)?
        .write_sctp(start, &Bytes::from(vec![0x5a; 100]), ppi)?;
    assert_eq!(1, transmitted_data(&a.gather_outbound(start).0).len());

    // The window closes with TSN 100 acknowledged; three more messages wait.
    a.handle_sack(&sack(100, 0), start)?;
    for i in 0..3u8 {
        a.stream(1)?
            .write_sctp(start, &Bytes::from(vec![i; 100]), ppi)?;
    }
    assert!(transmitted_data(&a.gather_outbound(start).0).is_empty());
    let rto = Duration::from_millis(a.rto_mgr.get_rto());
    let at = start + rto;
    assert!(a.poll_timeout().is_some_and(|t| t <= at));
    a.handle_timeout(at);
    let probe = transmitted_data(&a.gather_outbound(at).0);
    assert_eq!(probe.len(), 1, "the first probe, one RTO on");
    assert_eq!(probe[0].tsn, 101);

    // The receiver takes it and keeps its window shut.
    let acked = at + Duration::from_millis(20);
    a.handle_sack(&sack(101, 0), acked)?;
    let next = transmitted_data(&a.gather_outbound(acked).0);
    assert_eq!(next.len(), 1, "the next probe goes at once");
    assert_eq!(next[0].tsn, 102);

    // This one it drops: its SACK repeats the cumulative TSN. Nothing new goes; the probe
    // is still outstanding and T3-rtx will send it again.
    let dropped = acked + Duration::from_millis(20);
    a.handle_sack(&sack(101, 0), dropped)?;
    assert!(transmitted_data(&a.gather_outbound(dropped).0).is_empty());
    let t3 = a
        .timers
        .get(Timer::T3RTX)
        .expect("T3-rtx runs for the probe");
    assert!(
        a.poll_timeout().is_some_and(|t| t <= t3),
        "and is woken for"
    );
    a.handle_timeout(t3);
    let again = transmitted_data(&a.gather_outbound(t3).0);
    assert_eq!(again.len(), 1);
    assert_eq!(again[0].tsn, 102, "the same probe, retransmitted");
    Ok(())
}

/// RFC 9260 6.2 (with the zero window overcommit, webrtc-rs/webrtc#822): the receiver
/// advertised a closed window, and the next in-sequence chunk is taken because it is what
/// completes the message the full buffer holds. The sender has that chunk alone in flight as
/// its zero window probe, so it is acknowledged at once rather than after the SACK delay.
#[test]
fn a_chunk_taken_through_a_closed_window_is_acknowledged_at_once() -> Result<()> {
    let mut a = create_association(
        TransportConfig::default()
            .with_max_receive_buffer_size(FULL_BUFFER_RECV_BUFFER)
            .with_max_message_size(FULL_BUFFER_MAX_MESSAGE)
            .with_zero_window_overcommit(true),
    );
    a.set_state(AssociationState::Established);
    assert!(
        a.create_stream(0, true, PayloadProtocolIdentifier::Binary)
            .is_some()
    );
    let first = a.peer_last_tsn.wrapping_add(1);
    let mut tsn = first;
    while a.get_my_receiver_window_credit() > 0 {
        a.handle_data(&ordered_fragment(tsn, tsn == first, false))?;
        tsn = tsn.wrapping_add(1);
    }
    assert_eq!(
        0,
        a.create_selective_ack_chunk()
            .advertised_receiver_window_credit
    );
    a.immediate_ack_triggered = false;
    a.handle_data(&ordered_fragment(tsn, false, false))?;
    assert_eq!(a.peer_last_tsn, tsn, "taken through the closed window");
    assert!(a.immediate_ack_triggered, "and acknowledged at once");
    Ok(())
}

/// An I-DATA fragment of 1024 bytes: message `mid` of `stream`, fragment `fsn`.
fn i_data_fragment(tsn: u32, stream: u16, mid: u32, fsn: u32) -> ChunkPayloadData {
    ChunkPayloadData {
        i_data: true,
        tsn,
        stream_identifier: stream,
        mid,
        fsn,
        beginning_fragment: fsn == 0,
        ending_fragment: false,
        payload_type: PayloadProtocolIdentifier::Binary,
        user_data: Bytes::from(vec![0u8; 1024]),
        ..Default::default()
    }
}

/// RFC 9260 6.2, "When the receiver's advertised window is 0, the receiver MUST drop any new
/// incoming DATA chunk with a TSN larger than the largest TSN received so far", on an
/// association that negotiated I-DATA (RFC 8260). Four interleaved messages fill a 4 KiB
/// buffer with none complete and a SACK advertises a_rwnd 0. The next in-sequence chunk is
/// dropped and a SACK is due at once ("if such a DATA chunk is dropped, the receiver MUST
/// immediately send back a SACK"); with `TransportConfig::with_zero_window_overcommit` (for
/// an application that reads whole messages only) it is taken.
#[test]
fn an_interleaving_receiver_drops_new_data_after_a_closed_window() -> Result<()> {
    for overcommit in [false, true] {
        let mut a = create_association(
            TransportConfig::default()
                .with_max_receive_buffer_size(FULL_BUFFER_RECV_BUFFER)
                .with_max_message_size(FULL_BUFFER_MAX_MESSAGE)
                .with_message_interleaving(true)
                .with_zero_window_overcommit(overcommit),
        );
        a.set_state(AssociationState::Established);
        a.set_interleaving(true);
        for stream in 0..4 {
            assert!(
                a.create_stream(stream, true, PayloadProtocolIdentifier::Binary)
                    .is_some()
            );
        }
        let mut tsn = a.peer_last_tsn.wrapping_add(1);
        let mut fsn = [0u32; 4];
        let mut stream = 0usize;
        while a.get_my_receiver_window_credit() > 0 {
            a.handle_data(&i_data_fragment(tsn, stream as u16, 0, fsn[stream]))?;
            fsn[stream] += 1;
            stream = (stream + 1) % 4;
            tsn = tsn.wrapping_add(1);
        }
        assert!(!a.has_readable_data(), "no message is complete");
        assert_eq!(
            0,
            a.create_selective_ack_chunk()
                .advertised_receiver_window_credit
        );
        a.immediate_ack_triggered = false;
        let last = a.peer_last_tsn;
        a.handle_data(&i_data_fragment(tsn, stream as u16, 0, fsn[stream]))?;
        if overcommit {
            assert_eq!(a.peer_last_tsn, tsn, "taken: it unblocks reassembly");
        } else {
            assert_eq!(a.peer_last_tsn, last, "dropped: above the largest TSN");
            assert!(a.immediate_ack_triggered, "a SACK at once");
        }
    }
    Ok(())
}

/// Builds the receiver of the link tests: a receive buffer of `buffer` bytes that accepts
/// messages up to `message` bytes, with the RFC 9260 6.2 drop (the default). The link reads
/// in parts (RFC 9260 6.9) unless a test says otherwise.
fn receiver(buffer: u32, message: u32, interleaving: bool) -> TransportConfig {
    TransportConfig::default()
        .with_max_receive_buffer_size(buffer)
        .with_max_receive_message_size(message)
        .with_message_interleaving(interleaving)
}

/// Builds the sender of the link tests. Weighted fair queueing is the peer connection's
/// default; with I-DATA it interleaves the streams chunk by chunk (first come, first served
/// would finish each message before the next).
fn sender(message: u32, interleaving: bool) -> TransportConfig {
    TransportConfig::default()
        .with_max_message_size(message)
        .with_message_interleaving(interleaving)
        .with_stream_scheduler(crate::StreamScheduler::WeightedFairQueueing)
}

/// A message's bytes: its number, then a pattern that depends on it, so a delivered message
/// shows which one it is and whether it arrived whole.
fn message(id: u32, len: usize) -> Bytes {
    Bytes::from(
        (0..len)
            .map(|i| {
                if i < 4 && len >= 4 {
                    id.to_be_bytes()[i]
                } else {
                    (i as u32).wrapping_mul(31).wrapping_add(id) as u8
                }
            })
            .collect::<Vec<u8>>(),
    )
}

/// webrtc-rs/webrtc#822 in virtual time: one 64 KiB message to a receiver with a 16 KiB
/// buffer that reads whole messages only, with the zero window overcommit. Once the buffer
/// holds the start of the message, every further fragment is a zero window probe it takes.
/// Each is acknowledged at once and the next goes at once: about one round trip per fragment,
/// so well under a second over a 10 ms link. One RTO per fragment (the stall) is 40 seconds.
#[test]
fn a_message_larger_than_the_receive_buffer_arrives_at_a_round_trip_per_fragment() -> Result<()> {
    const BUFFER: u32 = 16 * 1024;
    const SIZE: usize = 64 * 1024;
    let mut link = Link::new(
        sender(256 * 1024, false),
        receiver(BUFFER, 256 * 1024, false).with_zero_window_overcommit(true),
        1,
    );
    link.server.read_parts = false;
    link.connect();
    let start = link.now;
    let ppi = PayloadProtocolIdentifier::Binary;
    let payload = message(7, SIZE);
    link.client
        .conn()
        .open_stream(1, ppi)?
        .write_sctp(start, &payload, ppi)?;
    let delivered = link.run_until(start + Duration::from_secs(60), |l| {
        !l.server.received.is_empty()
    });
    assert!(delivered, "never delivered");
    let took = link.now - start;
    assert_eq!(link.server.received[0].1, payload);
    assert!(
        took < Duration::from_secs(3),
        "{took:?} for {SIZE} bytes through a {BUFFER}-byte buffer"
    );
    Ok(())
}

/// RFC 8260 and RFC 9260 6.1 A: with I-DATA the sender interleaves its streams chunk by
/// chunk, so six 64 KiB messages are in reassembly at once at a receiver with a 1500-byte
/// buffer that reads whole messages only, with the zero window overcommit. It keeps room for one message beyond its buffer while nothing is
/// readable, and six part-received messages would use that room up without one of them
/// complete. While the window is closed the probes therefore finish a part-sent message
/// before another is started, and every message arrives.
#[test]
fn interleaved_messages_that_fill_the_buffer_together_complete_one_at_a_time() -> Result<()> {
    const SIZE: usize = 64 * 1024;
    const STREAMS: u16 = 6;
    let mut link = Link::new(
        sender(SIZE as u32, true),
        receiver(1500, SIZE as u32, true).with_zero_window_overcommit(true),
        3,
    );
    link.server.read_parts = false;
    link.connect();
    assert!(link.client.conn().use_interleaving, "I-DATA negotiated");
    let start = link.now;
    let ppi = PayloadProtocolIdentifier::Binary;
    for s in 1..=STREAMS {
        link.client.conn().open_stream(s, ppi)?;
    }
    for s in 1..=STREAMS {
        link.client
            .conn()
            .stream(s)?
            .write_sctp(start, &message(u32::from(s), SIZE), ppi)?;
    }
    let delivered = link.run_until(start + Duration::from_secs(300), |l| {
        l.server.received.len() == usize::from(STREAMS)
    });
    assert!(
        delivered,
        "{} of {STREAMS} messages after {:?}; {} bytes in reassembly",
        link.server.received.len(),
        link.now - start,
        link.server.conn().bytes_in_reassembly_queues()
    );
    for (id, m) in &link.server.received {
        assert_eq!(*m, message(u32::from(*id), SIZE));
    }
    Ok(())
}

/// How the receiver of a measurement reads, and what it does with a closed window.
#[derive(Clone, Copy, Debug)]
enum Reader {
    /// In parts (RFC 9260 6.9), with the RFC 9260 6.2 drop: the default.
    Parts,
    /// Whole messages only, with the RFC 9260 6.2 drop.
    WholeMessages,
    /// Whole messages only, with `with_zero_window_overcommit(true)`.
    WholeMessagesWithOvercommit,
}

fn apply(link: &mut Link, reader: Reader) {
    link.server.read_parts = matches!(reader, Reader::Parts);
}

fn receiver_for(reader: Reader, buffer: u32, message: u32, interleaving: bool) -> TransportConfig {
    receiver(buffer, message, interleaving)
        .with_zero_window_overcommit(matches!(reader, Reader::WholeMessagesWithOvercommit))
}

/// Six interleaved 16 KiB messages from one stream each, four in a row, to a receiver
/// with a 16 KiB buffer, over a 10 ms link: how many of the 24 arrive in two virtual
/// minutes, and how many parts were read before their message ended.
fn six_interleaved_streams_into_a_buffer_they_each_fit(
    reader: Reader,
) -> Result<(usize, Duration, usize)> {
    const SIZE: usize = 16 * 1024;
    const STREAMS: u16 = 6;
    let mut link = Link::new(
        sender(SIZE as u32, true),
        receiver_for(reader, SIZE as u32, SIZE as u32, true),
        5,
    );
    apply(&mut link, reader);
    link.connect();
    assert!(link.server.conn().use_interleaving, "I-DATA negotiated");
    let start = link.now;
    let ppi = PayloadProtocolIdentifier::Binary;
    for s in 1..=STREAMS {
        link.client.conn().open_stream(s, ppi)?;
    }
    let mut sent = vec![];
    for i in 0..4u32 {
        for s in 1..=STREAMS {
            let m = message(u32::from(s) * 1000 + i, SIZE);
            link.client.conn().stream(s)?.write_sctp(start, &m, ppi)?;
            sent.push((s, m));
        }
    }
    let total = 4 * usize::from(STREAMS);
    link.run_until(start + Duration::from_secs(120), |l| {
        l.server.received.len() == total
    });
    for (s, m) in &link.server.received {
        assert!(sent.contains(&(*s, m.clone())), "a message arrived whole");
    }
    Ok((
        link.server.received.len(),
        link.now - start,
        link.server.parts_before_end,
    ))
}

/// RFC 9260 6.2 with RFC 9260 6.9 and RFC 8260, measured: six interleaved 16 KiB messages
/// into a 16 KiB buffer. The six part-received messages fill the buffer together with none
/// of them complete. A receiver that reads whole messages only, under the RFC drop, then
/// refuses the in-sequence chunk that would complete one of them on every retransmission: 0 of
/// the 24 messages arrive and the window never reopens (sctp-14). Read in parts, the receiver
/// gives the six message starts out when its buffer runs out of space (RFC 9260 6.9), the
/// window opens, and all 24 arrive under the same drop. (The overcommit, for whole-message
/// readers, gets them there too.)
#[test]
fn interleaved_messages_that_each_fit_the_buffer_arrive_under_the_rfc_drop_when_read_in_parts()
-> Result<()> {
    let (parts, took, part_reads) =
        six_interleaved_streams_into_a_buffer_they_each_fit(Reader::Parts)?;
    let (whole, _, _) = six_interleaved_streams_into_a_buffer_they_each_fit(Reader::WholeMessages)?;
    let (overcommit, overcommit_took, _) =
        six_interleaved_streams_into_a_buffer_they_each_fit(Reader::WholeMessagesWithOvercommit)?;
    println!(
        "RFC drop: in parts {parts} of 24 in {took:?} ({part_reads} parts before an end); \
         whole messages {whole} of 24; whole messages with the overcommit {overcommit} of 24 \
         in {overcommit_took:?}"
    );
    assert_eq!(parts, 24, "read in parts, all arrive");
    assert!(part_reads > 0, "and some were read in parts");
    assert_eq!(whole, 0, "read whole under the drop, none do");
    assert_eq!(overcommit, 24);
    Ok(())
}

/// RFC 9260 6.9 with the RFC 9260 6.2 drop: one 64 KiB message to a receiver with a 16 KiB
/// buffer (webrtc-rs/webrtc#822). Read in parts it arrives at the pace of the link: the start
/// of it is given out at the partial delivery point (half the buffer), so the window never
/// closes. Read whole, under the drop, it never arrives: the buffer fills with its start, the
/// window closes, and the fragment after the largest TSN is dropped on every retransmission.
#[test]
fn a_message_larger_than_the_receive_buffer_arrives_under_the_rfc_drop_when_read_in_parts()
-> Result<()> {
    const BUFFER: u32 = 16 * 1024;
    const SIZE: usize = 64 * 1024;
    let mut took = vec![];
    for reader in [Reader::Parts, Reader::WholeMessages] {
        let mut link = Link::new(
            sender(256 * 1024, false),
            receiver_for(reader, BUFFER, 256 * 1024, false),
            1,
        );
        apply(&mut link, reader);
        link.connect();
        let start = link.now;
        let ppi = PayloadProtocolIdentifier::Binary;
        let payload = message(7, SIZE);
        link.client
            .conn()
            .open_stream(1, ppi)?
            .write_sctp(start, &payload, ppi)?;
        let delivered = link.run_until(start + Duration::from_secs(60), |l| {
            !l.server.received.is_empty()
        });
        if delivered {
            assert_eq!(link.server.received[0].1, payload);
        }
        took.push((delivered, link.now - start, link.server.parts_before_end));
    }
    println!("in parts: {:?}; whole messages: {:?}", took[0], took[1]);
    assert!(took[0].0, "read in parts, it arrives");
    assert!(took[0].1 < Duration::from_secs(3), "{:?}", took[0].1);
    assert!(took[0].2 > 0, "in parts");
    assert!(!took[1].0, "read whole under the drop, it does not");
    Ok(())
}

struct SweepCase {
    size: usize,
    buffer: u32,
    unordered: bool,
    interleaving: bool,
    streams: u16,
    loss: u64,
    seed: u64,
}

/// The virtual time a run may take: a base, plus per DATA chunk (a 1200-byte packet carries
/// about 1100 bytes) a budget that grows with the loss. A receiver whose window stays closed
/// takes one chunk per round trip (20 ms here). Each lost probe or lost SACK costs an RTO
/// (RTO.Min is 1 s), and the RTO backed off by lost retransmissions stays backed off until a
/// chunk sent once is acknowledged (RFC 9260 6.3.1 C5, 6.3.3 E2), so at 10 % loss in each
/// direction probing averages about 0.3 s a chunk with tails of a minute. One chunk per RTO,
/// the stall of webrtc-rs/webrtc#822 with probes that wait an RTO each (sctp-14), takes more
/// than the budget at 0 and 2 %; at 10 % only a run that stops is caught.
fn budget(bytes: usize, loss: u64) -> Duration {
    let chunks = bytes.div_ceil(1100) as u64;
    let (base_s, per_chunk_ms) = match loss {
        0 => (60, 100),
        1..=5 => (60, 200),
        _ => (300, 1000),
    };
    Duration::from_secs(base_s) + Duration::from_millis(chunks * per_chunk_ms)
}

/// What a run came to: everything delivered, an error reported, or a stall (described).
enum Outcome {
    Delivered,
    Failed(String),
    Stalled(String),
}

fn run_case(c: &SweepCase) -> (Outcome, Duration) {
    let streams = c.streams;
    let per_stream: u32 = if c.size <= 64 * 1024 { 4 } else { 1 };
    let message_limit = u32::try_from(c.size).unwrap_or(u32::MAX).max(1);
    let mut link = Link::new(
        sender(message_limit, c.interleaving),
        receiver(c.buffer, message_limit, c.interleaving),
        c.seed,
    );
    link.latency = Duration::from_millis(10);
    link.connect();
    link.loss_percent = c.loss;
    let start = link.now;
    let ppi = PayloadProtocolIdentifier::Binary;
    let mut sent: Vec<(u16, Bytes)> = vec![];
    for s in 1..=streams {
        let opened = link.client.conn().open_stream(s, ppi).and_then(|mut st| {
            st.set_reliability_params(c.unordered, ReliabilityType::Reliable, 0)
        });
        if let Err(e) = opened {
            return (Outcome::Failed(format!("open_stream: {e}")), Duration::ZERO);
        }
    }
    for i in 0..per_stream {
        for s in 1..=streams {
            let id = u32::from(s) * 1000 + i;
            let m = message(id, c.size);
            if let Err(e) = link
                .client
                .conn()
                .stream(s)
                .and_then(|mut st| st.write_sctp(start, &m, ppi))
            {
                return (Outcome::Failed(format!("write: {e}")), Duration::ZERO);
            }
            sent.push((s, m));
        }
    }
    let total = sent.len();
    let lost = |l: &Link| {
        l.client
            .events
            .iter()
            .chain(l.server.events.iter())
            .find_map(|e| match e {
                Event::AssociationLost { reason, .. } => Some(reason.clone()),
                Event::AssociationClosed { reason } => Some(reason.clone()),
                _ => None,
            })
    };
    let deadline = start + budget(c.size * total, c.loss);
    let done = link.run_until(deadline, |l| {
        l.server.received.len() >= total || lost(l).is_some()
    });
    if let Some(reason) = lost(&link) {
        let reason: AssociationError = reason;
        return (
            Outcome::Failed(format!("association lost: {reason:?}")),
            link.now - start,
        );
    }
    if !done {
        let client = link.client.conn();
        let (rwnd, inflight, pending, probe_at, wake) = (
            client.rwnd,
            client.inflight_queue.get_num_bytes(),
            client.buffered_amount(),
            client.zero_window_probe_at.map(|t| t - start),
            client
                .poll_timeout()
                .map(|t| t.saturating_duration_since(start)),
        );
        let (received, elapsed) = (link.server.received.len(), link.now - start);
        let server = link.server.conn();
        return (
            Outcome::Stalled(format!(
                "{} of {total} delivered after {:?}; sender rwnd={rwnd} inflight={inflight} \
             queued={pending} probe_at={probe_at:?} wake={wake:?}; receiver queued={} \
             credit={} advertised={} readable={}",
                received,
                elapsed,
                server.bytes_in_reassembly_queues(),
                server.get_my_receiver_window_credit(),
                server.last_advertised_window,
                server.has_readable_data(),
            )),
            elapsed,
        );
    }
    // Everything arrived whole, each message once, and in order on an ordered stream.
    for s in 1..=streams {
        let want: Vec<&Bytes> = sent
            .iter()
            .filter(|(t, _)| *t == s)
            .map(|(_, m)| m)
            .collect();
        let mut got: Vec<&Bytes> = link
            .server
            .received
            .iter()
            .filter(|(t, _)| *t == s)
            .map(|(_, m)| m)
            .collect();
        if c.unordered {
            let mut want_sorted = want.clone();
            want_sorted.sort();
            got.sort();
            if got != want_sorted {
                return (
                    Outcome::Failed(format!("stream {s}: wrong messages")),
                    link.now - start,
                );
            }
        } else if got != want {
            return (
                Outcome::Failed(format!("stream {s}: wrong messages or order")),
                link.now - start,
            );
        }
    }
    (Outcome::Delivered, link.now - start)
}

/// The sweep: no combination of message size, receive buffer, ordering, I-DATA, stream count
/// and loss may stall. Each run writes its messages at once on two or six streams (four per
/// stream up to 64 KiB, one above), and must deliver all of them within its budget, or end
/// with the association reporting an error. Six streams of I-DATA put six messages in
/// reassembly at once, which together can fill a buffer that each one fits.
///
/// The 4 MiB messages make the sweep take minutes in a debug build; they run with
/// `--ignored` (`zero_window_sweep_up_to_four_mebibytes`).
#[test]
fn zero_window_sweep_delivers_or_fails_never_stalls() {
    sweep(&[
        1,
        1000,
        1200,
        16 * 1024,
        64 * 1024 + 1,
        256 * 1024,
        1024 * 1024,
    ]);
}

/// The sweep with 4 MiB messages.
#[test]
#[ignore = "minutes in a debug build; run with --ignored"]
fn zero_window_sweep_up_to_four_mebibytes() {
    sweep(&[4 * 1024 * 1024]);
}

fn sweep(sizes: &[usize]) {
    const BUFFERS: [u32; 4] = [1500, 16 * 1024, 64 * 1024, 1024 * 1024];
    let mut stalls = vec![];
    let mut failures = vec![];
    let mut runs = 0;
    let mut slowest = (Duration::ZERO, String::new());
    for &size in sizes {
        for &buffer in &BUFFERS {
            for unordered in [false, true] {
                for interleaving in [false, true] {
                    for streams in [2u16, 6] {
                        for loss in [0u64, 2, 10] {
                            let case = SweepCase {
                                size,
                                buffer,
                                unordered,
                                interleaving,
                                streams,
                                loss,
                                seed: 1 + size as u64 * 7919 + u64::from(buffer) + loss,
                            };
                            let what = format!(
                                "size={size} buffer={buffer} unordered={unordered} \
                                 interleaving={interleaving} streams={streams} loss={loss}% \
                                 seed={}",
                                case.seed
                            );
                            runs += 1;
                            let (outcome, took) = run_case(&case);
                            if took > slowest.0 {
                                slowest = (took, what.clone());
                            }
                            match outcome {
                                Outcome::Delivered => {}
                                Outcome::Failed(why) => failures.push(format!("{what}: {why}")),
                                Outcome::Stalled(why) => stalls.push(format!("{what}: {why}")),
                            }
                        }
                    }
                }
            }
        }
    }
    println!(
        "zero window sweep: {runs} runs, {} stalled, {} failed; slowest {:?} ({})",
        stalls.len(),
        failures.len(),
        slowest.0,
        slowest.1
    );
    assert!(
        stalls.is_empty(),
        "{} of {runs} runs stalled:\n{}\n(and {} failed with an error:\n{})",
        stalls.len(),
        stalls.join("\n"),
        failures.len(),
        failures.join("\n")
    );
    assert!(
        failures.is_empty(),
        "{} of {runs} runs failed with an error:\n{}",
        failures.len(),
        failures.join("\n")
    );
}

/// RFC 9260 6.2, "When the window opens up, an SCTP receiver SHOULD send additional SACK
/// chunks to update the window even if no new data is received": a receiver with a
/// 1500-byte buffer that reads in parts takes each chunk out at once, but the sender, with
/// one chunk outstanding, sees no room for the next (RFC 9260 6.1 A) until a SACK says
/// otherwise. That SACK goes as soon as the chunk is read, so a 64 KiB message takes about
/// a round trip (20 ms) per chunk; held for the SACK delay (200 ms) it took over 12 s.
#[test]
fn a_small_buffer_read_in_parts_announces_its_window_as_soon_as_it_is_read() -> Result<()> {
    const SIZE: usize = 64 * 1024;
    let mut link = Link::new(
        sender(SIZE as u32, false),
        receiver(1500, SIZE as u32, false),
        9,
    );
    link.connect();
    let start = link.now;
    let ppi = PayloadProtocolIdentifier::Binary;
    let payload = message(3, SIZE);
    link.client
        .conn()
        .open_stream(1, ppi)?
        .write_sctp(start, &payload, ppi)?;
    let delivered = link.run_until(start + Duration::from_secs(120), |l| {
        !l.server.received.is_empty()
    });
    let took = link.now - start;
    assert!(delivered);
    assert_eq!(link.server.received[0].1, payload);
    assert!(took < Duration::from_secs(4), "{took:?}");
    Ok(())
}
