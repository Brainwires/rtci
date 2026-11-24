//! A stream reset in the middle of a transfer, and the stream used again at once: the close
//! and reopen of a WebRTC data channel (RFC 8831 6.7; a closed channel's stream id is free for
//! the next channel, and the lowest free one is taken).
//!
//! The peer that is asked to reset answers with the reset of its own direction (RFC 8831
//! 6.7). Its request's Sender's Last Assigned TSN is "the next TSN the sender assigns minus 1"
//! (RFC 6525 5.1.2 A3), and the receiver takes everything above it as data of the stream after
//! the reset (5.2.2 E2, E4). That answer used to go out at once, while the rest of a message
//! written to the stream before it was still to be sent: the rest went after it, with the old
//! Stream Sequence Number, and on the receiver it waited in front of the next channel's message
//! with that number, which never completed, and every message after it with it, all of them
//! acknowledged. Now the answer waits behind the data written before it, and a receiver drops
//! such fragments, which can never be part of a complete message, when a peer sends them.

use super::robustness_test::read_all;
use super::*;
use crate::AssociationError;
use crate::endpoint::link_test::Link;
use std::cell::RefCell;
use std::rc::Rc;

const PPI: PayloadProtocolIdentifier = PayloadProtocolIdentifier::Binary;
const SIZE: usize = 64 * 1024;
const STREAM: u16 = 3;

/// A message's bytes: its number, then a pattern that depends on it.
fn msg(id: u32, len: usize) -> Bytes {
    Bytes::from(
        (0..len)
            .map(|i| {
                if i < 4 {
                    id.to_be_bytes()[i]
                } else {
                    (i as u32).wrapping_mul(31).wrapping_add(id) as u8
                }
            })
            .collect::<Vec<u8>>(),
    )
}

fn id_of(m: &Bytes) -> Option<u32> {
    (m.len() == SIZE).then(|| u32::from_be_bytes([m[0], m[1], m[2], m[3]]))
}

fn reset_of<'a>(events: impl IntoIterator<Item = &'a Event>, id: StreamId) -> usize {
    events
        .into_iter()
        .filter(|e| {
            matches!(e, Event::AssociationLost { reason: AssociationError::Reset, id: lost } if *lost == id)
        })
        .count()
}

fn failure(l: &Link) -> Option<String> {
    l.client
        .events
        .iter()
        .chain(l.server.events.iter())
        .find_map(|e| match e {
            Event::AssociationClosed { reason } => Some(format!("association closed: {reason:?}")),
            Event::AssociationLost { reason, id } if *reason != AssociationError::Reset => {
                Some(format!("stream {id} lost: {reason:?}"))
            }
            _ => None,
        })
}

/// The sending application: it writes 64 KiB messages to the stream while no more than
/// `backlog` of them are buffered (written and not acknowledged), as a file transfer under
/// back-pressure does, and stops when the stream is gone.
struct Feed {
    first_id: u32,
    next: u32,
    total: u32,
    backlog: usize,
    unordered: bool,
    stopped: bool,
}

impl Feed {
    fn new(first_id: u32, total: u32, backlog: usize, unordered: bool) -> Self {
        Feed {
            first_id,
            next: 0,
            total,
            backlog,
            unordered,
            stopped: false,
        }
    }

    fn top_up(&mut self, l: &mut Link) {
        let now = l.now;
        while !self.stopped && self.next < self.total {
            let Ok(mut s) = l.server.conn().stream(STREAM) else {
                self.stopped = true;
                return;
            };
            match s.buffered_amount() {
                Ok(b) if b >= self.backlog * SIZE => return,
                Ok(_) => {}
                Err(_) => {
                    self.stopped = true;
                    return;
                }
            }
            let _ = s.set_reliability_params(self.unordered, ReliabilityType::Reliable, 0);
            if s.write_sctp(now, &msg(self.first_id + self.next, SIZE), PPI)
                .is_err()
            {
                self.stopped = true;
                return;
            }
            self.next += 1;
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct Case {
    /// The receiver closes the first channel once it has this many of its 64 KiB messages.
    close_after: usize,
    interleaving: bool,
    unordered: bool,
    read_parts: bool,
    /// How many 64 KiB messages the sender keeps buffered.
    backlog: usize,
    lossy: bool,
    seed: u64,
}

fn config(interleaving: bool) -> TransportConfig {
    TransportConfig::default()
        .with_max_message_size(256 * 1024)
        .with_max_receive_message_size(256 * 1024)
        .with_message_interleaving(interleaving)
        .with_stream_scheduler(crate::StreamScheduler::WeightedFairQueueing)
}

/// Opens (or, when the peer's DATA created it, takes) the stream on the client and writes
/// `first` to it: a data channel's DATA_CHANNEL_OPEN.
fn open_on_client(l: &mut Link, unordered: bool, first: &'static [u8]) -> Result<()> {
    let now = l.now;
    let conn = l.client.conn();
    let mut s = match conn.open_stream(STREAM, PPI) {
        Ok(s) => s,
        Err(Error::ErrStreamAlreadyExist) => conn.stream(STREAM)?,
        Err(e) => return Err(e),
    };
    s.set_reliability_params(unordered, ReliabilityType::Reliable, 0)?;
    s.write_sctp(now, &Bytes::from_static(first), PPI)?;
    Ok(())
}

/// Runs the scenario: the client (the receiving application) opens a channel on stream 3,
/// the server sends 64 KiB messages on it; the client closes it mid-transfer, opens the next
/// channel on the same stream once the close is done, and the server sends fifteen more.
/// `Ok(())` when every message of the second channel arrived, in order on an ordered one, none
/// of the first came after it was opened, and afterwards neither side holds anything
/// acknowledged and undelivered.
fn run(c: Case) -> std::result::Result<(), String> {
    let mut l = Link::new(config(c.interleaving), config(c.interleaving), c.seed);
    l.client.read_parts = c.read_parts;
    l.connect();
    if c.lossy {
        l.loss_percent = 2;
        l.jitter = Duration::from_millis(4);
        l.reorder_percent = 2;
    }
    let deadline = |l: &Link| l.now + Duration::from_secs(300);
    let fail = |what: &str, l: &mut Link| {
        let client = l.client.conn().undelivered();
        let server = l.server.conn().undelivered();
        format!("{what}; client holds {client:?}; server holds {server:?}")
    };

    // The first channel.
    open_on_client(&mut l, c.unordered, b"open-1").map_err(|e| e.to_string())?;
    let d = deadline(&l);
    if !l.run_until(d, |l| {
        l.server.received.iter().any(|(_, m)| &m[..] == b"open-1")
    }) {
        return Err(fail("the first open did not arrive", &mut l));
    }
    let now = l.now;
    l.server
        .conn()
        .stream(STREAM)
        .and_then(|mut s| {
            s.set_reliability_params(c.unordered, ReliabilityType::Reliable, 0)?;
            s.write_sctp(now, &Bytes::from_static(b"ack-1"), PPI)
        })
        .map_err(|e| e.to_string())?;
    let mut first = Feed::new(1000, 40, c.backlog, c.unordered);
    let d = deadline(&l);
    let reached = l.run_until(d, |l| {
        first.top_up(l);
        failure(l).is_some()
            || l.client
                .received
                .iter()
                .filter(|(_, m)| id_of(m).is_some())
                .count()
                >= c.close_after
    });
    if let Some(f) = failure(&l) {
        return Err(f);
    }
    if !reached {
        return Err(fail("the first channel's messages did not arrive", &mut l));
    }

    // The client closes it, and waits for the close to complete (the peer's reset of its own
    // direction, RFC 8831 6.7).
    let now = l.now;
    l.client
        .conn()
        .stream(STREAM)
        .and_then(|mut s| s.close(now))
        .map_err(|e| e.to_string())?;
    let d = deadline(&l);
    let closed = l.run_until(d, |l| {
        if reset_of(&l.server.events, STREAM) == 0 {
            first.top_up(l);
        } else {
            first.stopped = true;
        }
        failure(l).is_some() || reset_of(&l.client.events, STREAM) > 0
    });
    if let Some(f) = failure(&l) {
        return Err(f);
    }
    if !closed {
        return Err(fail("the close did not complete", &mut l));
    }

    // The next channel takes the same stream at once.
    let mark = l.client.received.len();
    open_on_client(&mut l, c.unordered, b"open-2").map_err(|e| e.to_string())?;
    let d = deadline(&l);
    if !l.run_until(d, |l| {
        l.server.received.iter().any(|(_, m)| &m[..] == b"open-2")
    }) {
        return Err(fail("the second open did not arrive", &mut l));
    }
    let now = l.now;
    l.server
        .conn()
        .stream(STREAM)
        .and_then(|mut s| {
            s.set_reliability_params(c.unordered, ReliabilityType::Reliable, 0)?;
            s.write_sctp(now, &Bytes::from_static(b"ack-2"), PPI)
        })
        .map_err(|e| e.to_string())?;
    let mut second = Feed::new(2000, 15, c.backlog, c.unordered);
    let d = deadline(&l);
    let delivered = |l: &Link| {
        l.client.received[mark..]
            .iter()
            .filter(|(_, m)| id_of(m).is_some_and(|id| id >= 2000))
            .count()
    };
    let all = l.run_until(d, |l| {
        second.top_up(l);
        failure(l).is_some() || delivered(l) >= 15
    });
    if let Some(f) = failure(&l) {
        return Err(f);
    }
    if !all {
        let got = delivered(&l);
        return Err(fail(
            &format!("{got} of the second channel's 15 messages delivered (a stall)"),
            &mut l,
        ));
    }

    // What the second channel got: its ACK and its fifteen messages, nothing of the first.
    let got: Vec<Bytes> = l.client.received[mark..]
        .iter()
        .filter(|(id, _)| *id == STREAM)
        .map(|(_, m)| m.clone())
        .collect();
    let mut want = vec![Bytes::from_static(b"ack-2")];
    want.extend((0..15).map(|i| msg(2000 + i, SIZE)));
    let (mut got_sorted, mut want_sorted) = (got.clone(), want.clone());
    if c.unordered {
        got_sorted.sort();
        want_sorted.sort();
    }
    if got_sorted != want_sorted {
        let ids: Vec<Option<u32>> = got.iter().map(id_of).collect();
        return Err(format!(
            "the second channel got the wrong messages: {} of {} (ids {ids:?})",
            got.len(),
            want.len()
        ));
    }

    // Quiet, and drained: nothing acknowledged may be left undelivered.
    l.run_for(Duration::from_secs(5));
    let client = l.client.conn().undelivered();
    let server = l.server.conn().undelivered();
    if client.is_some() || server.is_some() {
        return Err(format!(
            "acknowledged and never delivered: client {client:?}; server {server:?}"
        ));
    }
    Ok(())
}

/// The failing run of the report, pinned: DATA, an ordered channel read whole, the sender
/// keeping eight 64 KiB messages buffered, the close after four of them. The sender's reset of
/// its own direction went out while it was in the middle of a message; the rest of it waited
/// on the receiver in front of the next channel on the stream, and the second channel stalled
/// at the message with that Stream Sequence Number.
#[test]
fn a_channel_reopened_on_a_reset_stream_gets_every_message() {
    let case = Case {
        close_after: 4,
        interleaving: false,
        unordered: false,
        read_parts: false,
        backlog: 8,
        lossy: false,
        seed: 16,
    };
    if let Err(why) = run(case) {
        panic!("{case:?}: {why}");
    }
}

/// The sweep: where the close falls in the transfer, DATA or I-DATA, ordered or unordered,
/// read whole or in parts, a short or a long send backlog, a clean or a lossy and reordering
/// link. Every run must deliver every message of the second channel and leave nothing
/// acknowledged and undelivered on either side.
#[test]
fn closing_and_reopening_a_channel_on_its_stream_never_stalls() {
    let mut failures = vec![];
    let mut runs = 0;
    for close_after in [1usize, 4, 7] {
        for interleaving in [false, true] {
            for unordered in [false, true] {
                for read_parts in [false, true] {
                    for backlog in [2usize, 8] {
                        for lossy in [false, true] {
                            runs += 1;
                            let case = Case {
                                close_after,
                                interleaving,
                                unordered,
                                read_parts,
                                backlog,
                                lossy,
                                seed: 1600 + runs,
                            };
                            if let Err(why) = run(case) {
                                failures.push(format!("{case:?}: {why}"));
                            }
                        }
                    }
                }
            }
        }
    }
    println!("close/reopen sweep: {runs} runs, {} failed", failures.len());
    assert!(
        failures.is_empty(),
        "{} of {runs} runs failed:\n{}",
        failures.len(),
        failures.join("\n")
    );
}

/// RFC 6525 5.1.2 A3 with RFC 8831 6.7: the reset a peer sends in answer to this side's (the
/// close of a data channel) covers every DATA chunk it sends on the stream before the reset:
/// none of them has a TSN above the request's Sender's Last Assigned TSN. Checked on the wire,
/// with the sender in the middle of a message when the close arrives, and with the receiver
/// dropping nothing as a fragment that can never be completed.
#[test]
fn the_answering_reset_covers_the_message_half_sent_on_the_stream() {
    #[derive(Default)]
    struct Wire {
        /// (TSN, stream) of every DATA chunk the server sent, in order.
        data: Vec<(u32, u16)>,
        /// The Sender's Last Assigned TSN of each Outgoing SSN Reset Request of the server's
        /// that names the stream, with how many DATA chunks it had sent before it.
        resets: Vec<(u32, usize)>,
    }
    let wire = Rc::new(RefCell::new(Wire::default()));
    let mut l = Link::new(config(false), config(false), 7);
    let seen = wire.clone();
    l.filter = Some(Box::new(move |from_client, datagram| {
        if from_client {
            return false;
        }
        let Ok(p) = Packet::unmarshal(datagram) else {
            return false;
        };
        let mut w = seen.borrow_mut();
        for c in &p.chunks {
            if let Some(d) = c.as_any().downcast_ref::<ChunkPayloadData>() {
                w.data.push((d.tsn, d.stream_identifier));
            } else if let Some(r) = c.as_any().downcast_ref::<ChunkReconfig>() {
                for param in [&r.param_a, &r.param_b].into_iter().flatten() {
                    if let Some(req) = param.as_any().downcast_ref::<ParamOutgoingResetRequest>()
                        && req.stream_identifiers.contains(&STREAM)
                    {
                        let sent = w.data.len();
                        w.resets.push((req.sender_last_tsn, sent));
                    }
                }
            }
        }
        false
    }));
    l.connect();
    open_on_client(&mut l, false, b"open-1").unwrap();
    let d = l.now + Duration::from_secs(10);
    assert!(l.run_until(d, |l| !l.server.received.is_empty()));
    let mut feed = Feed::new(1000, 40, 8, false);
    let d = l.now + Duration::from_secs(60);
    assert!(l.run_until(d, |l| {
        feed.top_up(l);
        l.client.received.len() >= 4
    }));
    // The close comes while the server has messages of the stream still to send.
    assert!(
        l.server.conn().pending_queue.holds_stream(STREAM),
        "the server has data of the stream queued when the close arrives"
    );
    let now = l.now;
    // From here on the server's application writes nothing more.
    l.client.conn().stream(STREAM).unwrap().close(now).unwrap();
    let d = l.now + Duration::from_secs(60);
    assert!(
        l.run_until(d, |l| reset_of(&l.client.events, STREAM) > 0),
        "the close completes"
    );
    let w = wire.borrow();
    let &(last_assigned, sent_before) = w.resets.first().expect("the server reset its direction");
    let after: Vec<u32> = w.data[sent_before..]
        .iter()
        .filter(|(_, s)| *s == STREAM)
        .map(|(tsn, _)| *tsn)
        .filter(|tsn| sna32gt(*tsn, last_assigned))
        .collect();
    assert!(
        after.is_empty(),
        "DATA of the stream sent after the reset, above its Sender's Last Assigned TSN \
         {last_assigned}: {after:?}"
    );
    assert_eq!(0, l.client.conn().orphans_dropped);
    assert_eq!(None, l.client.conn().undelivered());
}

// ---- the receiver, fed what the sender used to send ----------------------------------------

fn receiver(interleaving: bool) -> Association {
    let mut a = create_association(TransportConfig::default());
    a.control_queue.clear();
    a.timers.stop(Timer::T1Init);
    a.set_state(AssociationState::Established);
    a.set_interleaving(interleaving);
    a.rwnd = 1 << 20;
    a.first_data_received = true;
    a
}

/// A fragment of a message of `count` fragments, `index` from 0, whose bytes say which
/// message (`tag`) and fragment it is. `seq` is the Stream Sequence Number with DATA and the
/// Message Identifier with I-DATA.
fn fragment(
    interleaving: bool,
    unordered: bool,
    tsn: u32,
    seq: u32,
    index: u32,
    count: u32,
    tag: u8,
) -> ChunkPayloadData {
    ChunkPayloadData {
        i_data: interleaving,
        tsn,
        stream_identifier: STREAM,
        stream_sequence_number: if interleaving { 0 } else { seq as u16 },
        mid: if interleaving { seq } else { 0 },
        fsn: if interleaving { index } else { 0 },
        unordered,
        beginning_fragment: index == 0,
        ending_fragment: index + 1 == count,
        payload_type: PPI,
        user_data: Bytes::from(vec![tag, index as u8, 0xee]),
        ..Default::default()
    }
}

fn whole(tag: u8, count: u32) -> Bytes {
    Bytes::from(
        (0..count)
            .flat_map(|i| [tag, i as u8, 0xee])
            .collect::<Vec<u8>>(),
    )
}

/// RFC 9260 6.9 (a message's fragments take consecutive TSNs, the first with the B bit) and
/// RFC 8260 2.1 (I-DATA fragments in FSN order), with RFC 6525 5.2.2 E2/E4: a peer resets the
/// stream while a message on it is half sent, and sends the rest of it after the reset with
/// its old Stream Sequence Number (Message Identifier), as this engine's sender did, and as
/// webrtc 0.17's does (`tests/data_channels_reopen_interop.rs`); on an ordered stream also the
/// whole messages it had queued behind it, numbered after it. Those whole messages were sent
/// before the next channel's first message, numbered 0: a sender sends a stream's ordered
/// messages in the order of their numbers, so they are not the next channel's, and they are
/// dropped when its first message arrives. Those
/// fragments can never be part of a complete message: the TSNs before them have all arrived,
/// their message's start among them, and went to the stream as it was. They are dropped, and
/// the next channel on the stream gets each of its messages, the one with that same number
/// included. They used to be held, in front of it, and the stream stalled there for good.
///
/// `late`: the first of those fragments is lost and arrives after the others, so they are
/// known to be orphans only when the cumulative TSN passes it.
#[test]
fn fragments_sent_after_a_reset_with_the_old_numbers_do_not_hold_the_next_channel() -> Result<()> {
    for interleaving in [false, true] {
        for unordered in [false, true] {
            for late in [false, true] {
                let what = format!("interleaving={interleaving} unordered={unordered} late={late}");
                let mut a = receiver(interleaving);
                let base = a.peer_last_tsn;
                let t = |n: u32| base.wrapping_add(n);
                let f = |tsn, seq, index, count, tag| {
                    fragment(interleaving, unordered, tsn, seq, index, count, tag)
                };
                // The first channel: a message read, then the first two fragments of the next,
                // sequence number 1, four fragments long.
                a.handle_data(&f(t(1), 0, 0, 1, 0xa0))?;
                assert_eq!(vec![whole(0xa0, 1)], read_all(&mut a, STREAM), "{what}");
                a.handle_data(&f(t(2), 1, 0, 4, 0xa1))?;
                a.handle_data(&f(t(3), 1, 1, 4, 0xa1))?;

                // The peer's reset of its direction, Sender's Last Assigned TSN t(3): done.
                a.handle_reconfig(&ChunkReconfig {
                    param_a: Some(Box::new(ParamOutgoingResetRequest {
                        reconfig_request_sequence_number: 9,
                        reconfig_response_sequence_number: 0,
                        sender_last_tsn: t(3),
                        stream_identifiers: vec![STREAM],
                    })),
                    param_b: None,
                })?;
                assert_eq!(1, reset_of(&a.events, STREAM), "{what}");

                // The rest of that message, after the reset, with its old number 1.
                if late {
                    a.handle_data(&f(t(5), 1, 3, 4, 0xa1))?;
                    a.handle_data(&f(t(4), 1, 2, 4, 0xa1))?;
                } else {
                    a.handle_data(&f(t(4), 1, 2, 4, 0xa1))?;
                    a.handle_data(&f(t(5), 1, 3, 4, 0xa1))?;
                }
                assert_eq!(t(5), a.peer_last_tsn, "{what}: all acknowledged");
                // Then a whole message that was queued behind it, numbered 2, and on an
                // ordered stream one numbered 1 as well (two fragments). An unordered message
                // has no number to tell it from the next channel's: not sent in that case.
                let mut n = 6;
                if !unordered {
                    a.handle_data(&f(t(6), 2, 0, 1, 0xa2))?;
                    a.handle_data(&f(t(7), 3, 0, 2, 0xa3))?;
                    a.handle_data(&f(t(8), 3, 1, 2, 0xa3))?;
                    n = 9;
                }

                // The next channel on the stream: its messages 0, 1 (three fragments), 2 and 3.
                match a.open_stream(STREAM, PPI) {
                    Ok(_) | Err(Error::ErrStreamAlreadyExist) => {}
                    Err(e) => return Err(e),
                }
                a.handle_data(&f(t(n), 0, 0, 1, 0xb0))?;
                for i in 0..3 {
                    a.handle_data(&f(t(n + 1 + i), 1, i, 3, 0xb1))?;
                }
                a.handle_data(&f(t(n + 4), 2, 0, 1, 0xb2))?;
                a.handle_data(&f(t(n + 5), 3, 0, 1, 0xb3))?;
                let mut got = read_all(&mut a, STREAM);
                let mut want = vec![
                    whole(0xb0, 1),
                    whole(0xb1, 3),
                    whole(0xb2, 1),
                    whole(0xb3, 1),
                ];
                if unordered {
                    got.sort();
                    want.sort();
                }
                assert_eq!(want, got, "{what}: the next channel's messages");
                assert_eq!(None, a.undelivered(), "{what}: nothing held");
                assert_eq!(
                    a.max_receive_buffer_size,
                    a.get_my_receiver_window_credit(),
                    "{what}"
                );
                assert!(a.orphans_dropped >= 2, "{what}: {}", a.orphans_dropped);
            }
        }
    }
    Ok(())
}

/// The check for orphaned fragments takes nothing that can still be completed: fragments
/// that arrive out of order, the first of a message last, all make their message, on a stream
/// that has messages before them waiting too.
#[test]
fn fragments_out_of_order_are_not_taken_for_orphans() -> Result<()> {
    for interleaving in [false, true] {
        for unordered in [false, true] {
            let what = format!("interleaving={interleaving} unordered={unordered}");
            let mut a = receiver(interleaving);
            let base = a.peer_last_tsn;
            let t = |n: u32| base.wrapping_add(n);
            let f = |tsn, seq, index, count, tag| {
                fragment(interleaving, unordered, tsn, seq, index, count, tag)
            };
            // Message 1's fragments come before message 0, its last first; then message 0,
            // then message 1's first fragment.
            a.handle_data(&f(t(4), 1, 2, 3, 0xc1))?;
            a.handle_data(&f(t(3), 1, 1, 3, 0xc1))?;
            a.handle_data(&f(t(1), 0, 0, 1, 0xc0))?;
            a.handle_data(&f(t(2), 1, 0, 3, 0xc1))?;
            let mut got = read_all(&mut a, STREAM);
            let mut want = vec![whole(0xc0, 1), whole(0xc1, 3)];
            if unordered {
                got.sort();
                want.sort();
            }
            assert_eq!(want, got, "{what}");
            assert_eq!(0, a.orphans_dropped, "{what}");
            assert_eq!(None, a.undelivered(), "{what}");
        }
    }
    Ok(())
}
