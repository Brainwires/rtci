//! RFC 8831 6.7: a data channel is closed by resetting its stream in both directions, and the
//! stream is free for the next channel once that is done. The application here closes a
//! channel in the middle of a file transfer (the receiver refused a record) and opens the next
//! at once, which takes the same stream id (the lowest free one of its parity, RFC 8832 6).
//! The sender writes 64 KiB messages under back-pressure, so the close reaches it with
//! messages written to the channel and not sent yet.
//!
//! Its reset of its own direction used to go out at once, ahead of those messages (or the rest
//! of one half sent): they arrived after the reset with their old Stream Sequence Numbers and
//! were taken, on the receiver, for the next channel's, in front of the next channel's own
//! messages with those numbers: the next channel got the messages before them and none after,
//! all acknowledged (ParolNet `file_tamper`).

mod dc_common;

use anyhow::{Result, bail, ensure};
use bytes::BytesMut;
use dc_common::Pair;
use rtci::data_channel::RTCDataChannelId;
use rtci::peer_connection::transport::RTCDtlsRole;
use std::time::Duration;

const SIZE: usize = 64 * 1024;
/// The messages of the second channel: enough to number past whatever the first channel's
/// sender had queued when the close came (its old numbers would collide with these).
const SECOND: u32 = 80;

/// A message's bytes: its number, then a pattern that depends on it.
fn msg(id: u32) -> Vec<u8> {
    (0..SIZE)
        .map(|i| {
            if i < 4 {
                id.to_be_bytes()[i]
            } else {
                (i as u32).wrapping_mul(31).wrapping_add(id) as u8
            }
        })
        .collect()
}

/// The answerer's application: it writes messages `first..first + total` to its channel `ch`
/// while fewer than `backlog` of them are buffered. Returns false once the channel refuses.
fn top_up(p: &mut Pair, ch: RTCDataChannelId, next: &mut u32, first: u32, total: u32) -> bool {
    top_up_to(p, ch, next, first, total, 8)
}

/// As [`top_up`], with `backlog` messages buffered at most.
fn top_up_to(
    p: &mut Pair,
    ch: RTCDataChannelId,
    next: &mut u32,
    first: u32,
    total: u32,
    backlog: u64,
) -> bool {
    let limit = backlog * SIZE as u64;
    let now = p.now;
    let Some(mut dc) = p.answerer.pc.data_channel(ch) else {
        return false;
    };
    while *next < total && dc.buffered_amount() < limit {
        if dc
            .send(now, BytesMut::from(&msg(first + *next)[..]))
            .is_err()
        {
            return false;
        }
        *next += 1;
    }
    true
}

fn received_on(p: &Pair, ch: RTCDataChannelId) -> Vec<&Vec<u8>> {
    p.offerer
        .received
        .iter()
        .filter(|(id, _, _)| *id == ch)
        .map(|(_, _, data)| data)
        .collect()
}

/// Runs `step` and the pair in 5 ms slices of virtual time until `done`, for at most
/// `limit`. Returns whether `done` came to hold.
fn drive(
    p: &mut Pair,
    limit: Duration,
    mut step: impl FnMut(&mut Pair),
    done: impl Fn(&Pair) -> bool,
) -> Result<bool> {
    let until = p.now + limit;
    while !done(p) {
        if p.now >= until {
            return Ok(false);
        }
        step(p);
        p.run_for(Duration::from_millis(5))?;
    }
    Ok(true)
}

fn close_and_reopen(close_after: usize) -> Result<()> {
    let (mut p, _control) = Pair::connected(RTCDtlsRole::Client, "control")?;

    // The receiving side (the offerer) opens the first file channel.
    let file1 = p.offerer.pc.create_data_channel("file-1", None)?.id();
    let before = p.answerer.opened().len();
    ensure!(
        p.run_until(|p| p.offerer.opened().contains(&file1) && p.answerer.opened().len() > before)?,
        "file-1 never opened"
    );
    let sender1 = *p.answerer.opened().last().expect("opened");
    let stream1 = p
        .offerer
        .pc
        .data_channel(file1)
        .and_then(|dc| dc.stream_id());

    let mut next = 0;
    ensure!(
        drive(
            &mut p,
            Duration::from_secs(60),
            |p| {
                top_up(p, sender1, &mut next, 1000, 60);
            },
            |p| received_on(p, file1).len() >= close_after,
        )?,
        "file-1's messages did not arrive"
    );

    // The receiver refuses the transfer: it closes the channel; the sender's application
    // stops writing when its end of the channel closes. The close reaches the sender with
    // data of the channel in its send queue: it writes more than the receive window holds,
    // and the receiver's acknowledgements of what it sends first are lost, so the rest waits.
    top_up_to(&mut p, sender1, &mut next, 1000, 60, 20);
    p.offerer.drop_outgoing = true;
    p.run_for(Duration::from_millis(1))?;
    p.offerer.drop_outgoing = false;
    p.offerer.pc.data_channel(file1).expect("file-1").close()?;
    ensure!(
        drive(
            &mut p,
            Duration::from_secs(60),
            |p| {
                if !p.answerer.closed(sender1) {
                    top_up(p, sender1, &mut next, 1000, 60);
                }
            },
            |p| p.offerer.closed(file1) && p.answerer.closed(sender1),
        )?,
        "the close of file-1 did not complete"
    );

    // And at once opens the next one, which takes the same stream.
    let file2 = p.offerer.pc.create_data_channel("file-2", None)?.id();
    let before = p.answerer.opened().len();
    ensure!(
        p.run_until(|p| p.offerer.opened().contains(&file2) && p.answerer.opened().len() > before)?,
        "file-2 never opened"
    );
    let sender2 = *p.answerer.opened().last().expect("opened");
    let stream2 = p
        .offerer
        .pc
        .data_channel(file2)
        .and_then(|dc| dc.stream_id());
    assert_eq!(
        stream1, stream2,
        "the next channel takes the stream just freed"
    );

    let mut next = 0;
    let all = drive(
        &mut p,
        Duration::from_secs(120),
        |p| {
            top_up(p, sender2, &mut next, 2000, SECOND);
        },
        |p| received_on(p, file2).len() >= SECOND as usize,
    )?;
    let got = received_on(&p, file2);
    if !all {
        bail!(
            "close after {close_after}: file-2 got {} of its {SECOND} messages (a stall)",
            got.len()
        );
    }
    for (i, data) in got.iter().enumerate() {
        assert!(
            **data == msg(2000 + i as u32),
            "close after {close_after}: file-2's message {i} is not the one sent"
        );
    }
    Ok(())
}

/// The channel opened on the stream of one just closed mid-transfer gets every message, in
/// order, wherever in the transfer the close falls.
#[test]
fn a_channel_opened_on_the_stream_of_one_just_closed_gets_every_message() -> Result<()> {
    for close_after in [1, 3, 6] {
        close_and_reopen(close_after)?;
    }
    Ok(())
}
