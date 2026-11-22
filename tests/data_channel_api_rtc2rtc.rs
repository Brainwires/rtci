//! W3C webrtc-pc 6.1 / 6.2, the data channel API an application sees: `send()` gated on the
//! ready state, `bufferedAmount` and `[[MaxBufferSize]]`, `close()` while closing, the DCEP
//! handshake deadline for a channel created once the association is up, the `id` checks
//! against `maxChannels`, and the closed channel's statistics.

mod dc_common;

use anyhow::Result;
use bytes::BytesMut;
use dc_common::Pair;
use rtc::data_channel::RTCDataChannelInit;
use rtc::peer_connection::configuration::setting_engine::SettingEngineBuilder;
use rtc::peer_connection::event::RTCDataChannelEvent;
use rtc::peer_connection::rtc_error::RTCErrorDetailType;
use rtc::peer_connection::transport::{RTCDtlsRole, RTCSctpTransportState};
use rtc::shared::error::Error;
use rtc::statistics::StatsSelector;
use std::time::Duration;

fn engine(role: RTCDtlsRole) -> SettingEngineBuilder {
    SettingEngineBuilder::new().with_answering_dtls_role(role)
}

/// An in-band channel created once the association is up is dialed at once. Its DCEP
/// handshake has the same deadline as one dialed when the association came up (the bug: it
/// had none, and a lost ACK left it connecting for ever). At the deadline it fails with
/// `data-channel-failure`, then closes (W3C 6.2.7); a closed channel refuses `send()`.
#[test]
fn a_channel_dialed_on_a_live_association_fails_when_its_ack_never_comes() -> Result<()> {
    let mut pair = Pair::with_setting_engines(
        "127.0.0.1:52010",
        engine(RTCDtlsRole::Client).with_dcep_handshake_timeout(Some(Duration::from_secs(5))),
        "127.0.0.1:52011",
        engine(RTCDtlsRole::Server),
    )?;
    pair.offerer.pc.create_data_channel("first", None)?;
    pair.negotiate()?;
    assert!(pair.run_until(|p| !p.offerer.opened().is_empty())?);

    pair.answerer.drop_outgoing = true;
    let late = pair.offerer.pc.create_data_channel("late", None)?.id();

    assert!(
        pair.run_until(|p| p.offerer.closed(late))?,
        "the deadline closes it"
    );
    assert_eq!(
        pair.offerer.events_of(late),
        [
            RTCDataChannelEvent::OnError(late),
            RTCDataChannelEvent::OnClose(late)
        ]
    );
    assert_eq!(
        pair.offerer
            .pc
            .data_channel_error(late)
            .map(|e| e.error_detail),
        Some(RTCErrorDetailType::DataChannelFailure)
    );
    if let Some(mut channel) = pair.offerer.pc.data_channel(late) {
        assert!(matches!(
            channel.send(pair.now, BytesMut::from(&b"too late"[..])),
            Err(Error::ErrDataChannelClosed)
        ));
    }
    Ok(())
}

/// W3C `bufferedAmount` rises by what `send()` queued and falls as SCTP sends it;
/// `bufferedAmountLowThreshold` starts at 0 and is settable. `close()` on a closing channel
/// starts nothing again, and `send()` on it refuses.
#[test]
fn buffered_amount_follows_the_queue_and_close_is_once() -> Result<()> {
    let (mut pair, first) = Pair::connected(RTCDtlsRole::Client, "first")?;
    let now = pair.now;
    let mut channel = pair.offerer.pc.data_channel(first).expect("open");
    assert_eq!(channel.buffered_amount_low_threshold(), 0);
    channel.set_buffered_amount_low_threshold(10);
    assert_eq!(channel.buffered_amount_low_threshold(), 10);
    assert_eq!(channel.buffered_amount(), 0);
    channel.send(now, BytesMut::from(&[7u8; 1000][..]))?;
    channel.send_text(now, "hello")?;
    assert_eq!(
        channel.buffered_amount(),
        1005,
        "what send() queued, no framing"
    );

    pair.run_for(Duration::from_millis(200))?;
    let mut channel = pair.offerer.pc.data_channel(first).expect("open");
    assert_eq!(channel.buffered_amount(), 0, "sent");

    channel.close()?;
    channel.close()?;
    assert!(matches!(
        channel.send(now, BytesMut::from(&b"x"[..])),
        Err(Error::ErrDataChannelNotOpen)
    ));
    assert!(pair.run_until(|p| p.offerer.closed(first))?);
    let closes = pair
        .offerer
        .events_of(first)
        .iter()
        .filter(|e| matches!(e, RTCDataChannelEvent::OnClose(_)))
        .count();
    assert_eq!(closes, 1);
    Ok(())
}

/// W3C `send()`: "If [[BufferedAmount]] increased by the byte size of data is above
/// [[MaxBufferSize]], throw an OperationError"; [[MaxBufferSize]] is the larger of the peer's
/// max-message-size and canSendSize, "the size of the local send buffer" (6.1.1.2), which the
/// spec leaves to the implementation: 16 MiB here, as in Chromium. Between two default peers a
/// bulk sender queues far more than one max-message-size (64 KiB) before it is refused. A
/// fixed limit replaces the rule when the application sets one.
#[test]
fn send_refuses_data_above_the_max_buffer_size() -> Result<()> {
    const SEND_BUFFER: usize = 16 * 1024 * 1024;
    fn fill(
        channel: &mut rtc::data_channel::RTCDataChannel<'_>,
        now: std::time::Instant,
        size: usize,
    ) -> (usize, Error) {
        let mut queued = 0usize;
        loop {
            match channel.send(now, BytesMut::from(&vec![1u8; size][..])) {
                Ok(()) => queued += size,
                Err(err) => break (queued, err),
            }
            assert!(queued <= 2 * SEND_BUFFER, "never refused");
        }
    }

    let (mut pair, first) = Pair::connected(RTCDtlsRole::Client, "first")?;
    let now = pair.now;
    let max_message = pair
        .offerer
        .pc
        .sctp()
        .and_then(|s| s.max_message_size())
        .expect("negotiated") as usize;
    let mut channel = pair.offerer.pc.data_channel(first).expect("open");
    let (queued, refused) = fill(&mut channel, now, max_message);
    assert!(
        matches!(refused, Error::ErrDataChannelBufferFull),
        "{refused:?}"
    );
    assert!(
        queued > SEND_BUFFER - max_message && queued <= SEND_BUFFER,
        "refused at {queued} bytes, not at the 16 MiB send buffer"
    );
    assert!(channel.buffered_amount() as usize <= SEND_BUFFER);

    let mut pair = Pair::with_setting_engines(
        "127.0.0.1:52020",
        engine(RTCDtlsRole::Client).with_data_channel_max_buffer_size(Some(1 << 18)),
        "127.0.0.1:52021",
        engine(RTCDtlsRole::Server),
    )?;
    let id = pair.offerer.pc.create_data_channel("small", None)?.id();
    pair.negotiate()?;
    assert!(pair.run_until(|p| p.offerer.opened().contains(&id))?);
    let now = pair.now;
    let mut channel = pair.offerer.pc.data_channel(id).expect("open");
    let (queued, refused) = fill(&mut channel, now, max_message);
    assert!(matches!(refused, Error::ErrDataChannelBufferFull));
    assert!(queued <= 1 << 18 && queued > (1 << 18) - max_message);
    Ok(())
}

/// W3C createDataChannel: a negotiated id at or above the connected transport's
/// `maxChannels` is an OperationError; below it, the channel opens.
#[test]
fn a_negotiated_id_at_or_above_max_channels_is_refused() -> Result<()> {
    let (mut pair, _) = Pair::connected(RTCDtlsRole::Client, "first")?;
    let sctp = pair.offerer.pc.sctp().expect("sctp");
    assert_eq!(sctp.state(), RTCSctpTransportState::Connected);
    let max_channels = sctp.max_channels().expect("connected");
    if max_channels == u16::MAX {
        // Every stream id an application can name is below it: nothing to refuse here (the
        // handler test `channels_without_a_usable_id_are_closed_with_a_failure_at_connect`
        // covers a smaller count).
        return Ok(());
    }
    let refused = pair.offerer.pc.create_data_channel(
        "above",
        Some(RTCDataChannelInit {
            negotiated: Some(max_channels),
            ..Default::default()
        }),
    );
    assert!(
        matches!(refused, Err(Error::ErrDataChannelIdAboveMaxChannels)),
        "{:?}",
        refused.err()
    );
    let below = max_channels - 2;
    pair.offerer.pc.create_data_channel(
        "below",
        Some(RTCDataChannelInit {
            negotiated: Some(below),
            ..Default::default()
        }),
    )?;
    Ok(())
}

/// webrtc-stats lifetime: a closed channel's stats object stays in the report, "closed", with
/// its last counters.
#[test]
fn a_closed_channel_keeps_its_stats_object() -> Result<()> {
    let (mut pair, first) = Pair::connected(RTCDtlsRole::Client, "first")?;
    let now = pair.now;
    pair.offerer
        .pc
        .data_channel(first)
        .expect("open")
        .send_text(now, "one")?;
    pair.run_for(Duration::from_millis(100))?;
    pair.offerer.pc.data_channel(first).expect("open").close()?;
    assert!(pair.run_until(|p| p.offerer.closed(first))?);
    let now = pair.now;
    let report = pair.offerer.pc.get_stats(now, StatsSelector::None);
    let channels: Vec<_> = report.data_channels().collect();
    assert_eq!(channels.len(), 1, "the closed channel is still reported");
    let channel = channels[0];
    assert_eq!(
        channel.state,
        rtc::data_channel::RTCDataChannelState::Closed
    );
    assert_eq!(channel.messages_sent, 1);
    Ok(())
}

/// The browser interop scenario "data channel 64 KiB binary messages" between two engines:
/// twenty 64 KiB messages sent at once and echoed as they arrive. Every echo is accepted (the
/// echoing side has far more than one message queued at a time: with `[[MaxBufferSize]]` at
/// the 64 KiB max-message-size all but the first were refused), and all twenty come back in
/// order.
#[test]
fn twenty_64_kib_messages_are_echoed() -> Result<()> {
    const SIZE: usize = 64 * 1024;
    let (mut pair, first) = Pair::connected(RTCDtlsRole::Client, "echo")?;
    let theirs = *pair
        .answerer
        .opened()
        .last()
        .expect("the answerer's channel");
    let now = pair.now;
    let mut channel = pair.offerer.pc.data_channel(first).expect("open");
    for i in 0..20u8 {
        channel.send(now, BytesMut::from(&vec![i; SIZE][..]))?;
    }
    let mut echoed = 0;
    let deadline = pair.now + Duration::from_secs(30);
    while pair.offerer.received.len() < 20 && pair.now < deadline {
        pair.run_for(Duration::from_millis(5))?;
        let now = pair.now;
        while echoed < pair.answerer.received.len() {
            let data = pair.answerer.received[echoed].2.clone();
            let mut channel = pair.answerer.pc.data_channel(theirs).expect("open");
            channel.send(now, BytesMut::from(&data[..]))?;
            echoed += 1;
        }
    }
    let back: Vec<(usize, u8)> = pair
        .offerer
        .received
        .iter()
        .map(|(_, _, d)| (d.len(), d[0]))
        .collect();
    let want: Vec<(usize, u8)> = (0..20u8).map(|i| (SIZE, i)).collect();
    assert_eq!(back, want);
    Ok(())
}

/// A bulk sender that paces itself by `bufferedAmount`: 16 MiB queued in one burst is
/// accepted (the send buffer, W3C [[MaxBufferSize]]), one byte more is refused, and a sender
/// that then waits for `bufferedamountlow` before queueing more delivers another 16 MiB, all
/// of it, in order.
#[test]
fn a_16_mib_burst_and_back_pressure_deliver_everything() -> Result<()> {
    const CHUNK: usize = 64 * 1024;
    const BUFFER: usize = 16 * 1024 * 1024;
    let (mut pair, first) = Pair::connected(RTCDtlsRole::Client, "bulk")?;
    let now = pair.now;
    let mut channel = pair.offerer.pc.data_channel(first).expect("open");
    let mut sent: u32 = 0;
    for _ in 0..BUFFER / CHUNK {
        let mut chunk = vec![0u8; CHUNK];
        chunk[..4].copy_from_slice(&sent.to_be_bytes());
        channel.send(now, BytesMut::from(&chunk[..]))?;
        sent += 1;
    }
    assert_eq!(channel.buffered_amount() as usize, BUFFER);
    assert!(matches!(
        channel.send(now, BytesMut::from(&[0u8; 1][..])),
        Err(Error::ErrDataChannelBufferFull)
    ));

    // Back-pressure: keep at most 1 MiB queued, refill at bufferedamountlow (256 KiB).
    channel.set_buffered_amount_low_threshold(256 * 1024);
    let lows = |p: &Pair| {
        p.offerer
            .events
            .iter()
            .filter(|e| matches!(e, RTCDataChannelEvent::OnBufferedAmountLow(id) if *id == first))
            .count()
    };
    let target = 2 * (BUFFER / CHUNK) as u32;
    let deadline = pair.now + Duration::from_secs(600);
    while sent < target && pair.now < deadline {
        let seen = lows(&pair);
        assert!(pair.run_until(|p| lows(p) > seen)?, "bufferedamountlow");
        let now = pair.now;
        let mut channel = pair.offerer.pc.data_channel(first).expect("open");
        while sent < target && channel.buffered_amount() < 1 << 20 {
            let mut chunk = vec![0u8; CHUNK];
            chunk[..4].copy_from_slice(&sent.to_be_bytes());
            channel.send(now, BytesMut::from(&chunk[..]))?;
            sent += 1;
        }
    }
    assert!(pair.run_until(|p| p.answerer.received.len() as u32 >= target)?);
    let order: Vec<u32> = pair
        .answerer
        .received
        .iter()
        .map(|(_, _, d)| u32::from_be_bytes([d[0], d[1], d[2], d[3]]))
        .collect();
    assert_eq!(order, (0..target).collect::<Vec<_>>());
    Ok(())
}
