//! W3C webrtc-pc 6.1 / 6.2, the data channel API an application sees: `send()` gated on the
//! ready state, `bufferedAmount` and `[[MaxBufferSize]]`, `close()` while closing, the DCEP
//! handshake deadline for a channel created once the association is up, the `id` checks
//! against `maxChannels`, and the closed channel's statistics.

mod dc_common;

use anyhow::Result;
use bytes::BytesMut;
use dc_common::Pair;
use rtci::data_channel::{RTCDataChannelInit, RTCDataChannelState};
use rtci::peer_connection::configuration::setting_engine::SettingEngineBuilder;
use rtci::peer_connection::event::RTCDataChannelEvent;
use rtci::peer_connection::rtc_error::RTCErrorDetailType;
use rtci::peer_connection::transport::{RTCDtlsRole, RTCSctpTransportState};
use rtci::shared::error::Error;
use rtci::statistics::StatsSelector;
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

/// W3C webrtc-pc 6.2 `send()`: "If channel.[[ReadyState]] is not "open", throw an
/// InvalidStateError". An in-band channel dialed on a live association is "connecting" until
/// its DATA_CHANNEL_ACK, and refuses data until then (RFC 8832's early send is a setting);
/// once open it sends.
#[test]
fn send_on_a_connecting_channel_is_an_invalid_state_error() -> Result<()> {
    let (mut pair, _first) = Pair::connected(RTCDtlsRole::Client, "first")?;
    let now = pair.now;
    let mut early = pair.offerer.pc.create_data_channel("early", None)?;
    assert_eq!(early.ready_state(), RTCDataChannelState::Connecting);
    assert!(matches!(
        early.send(now, BytesMut::from(&b"too early"[..])),
        Err(Error::ErrDataChannelNotOpen)
    ));
    assert!(matches!(
        early.send_text(now, "too early"),
        Err(Error::ErrDataChannelNotOpen)
    ));
    assert_eq!(early.buffered_amount(), 0, "a refused send queues nothing");
    let early = early.id();
    assert!(pair.run_until(|p| p.offerer.opened().contains(&early))?);
    let before = pair.answerer.received.len();
    assert!(pair.deliver(false, early, b"in time")?);
    assert_eq!(
        pair.answerer.received.len(),
        before + 1,
        "only the open send arrived"
    );
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
        channel: &mut rtci::data_channel::RTCDataChannel<'_>,
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
/// `maxChannels` is an OperationError; below it, the channel opens. The answerer asks for 16
/// streams (`with_sctp_max_streams`), so the association has 16 and `maxChannels` is 16.
#[test]
fn a_negotiated_id_at_or_above_max_channels_is_refused() -> Result<()> {
    let mut pair = Pair::with_setting_engines(
        "127.0.0.1:52030",
        engine(RTCDtlsRole::Client),
        "127.0.0.1:52031",
        engine(RTCDtlsRole::Server).with_sctp_max_streams(16),
    )?;
    pair.offerer.pc.create_data_channel("first", None)?;
    pair.negotiate()?;
    assert!(pair.run_until(|p| !p.offerer.opened().is_empty())?);
    let sctp = pair.offerer.pc.sctp().expect("sctp");
    assert_eq!(sctp.state(), RTCSctpTransportState::Connected);
    assert_eq!(sctp.max_channels(), Some(16), "the smaller stream count");
    for id in [16, 20] {
        let refused = pair.offerer.pc.create_data_channel(
            "above",
            Some(RTCDataChannelInit {
                negotiated: Some(id),
                ..Default::default()
            }),
        );
        assert!(
            matches!(refused, Err(Error::ErrDataChannelIdAboveMaxChannels)),
            "id {id}: {:?}",
            refused.err()
        );
    }
    pair.offerer.pc.create_data_channel(
        "below",
        Some(RTCDataChannelInit {
            negotiated: Some(15),
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
        rtci::data_channel::RTCDataChannelState::Closed
    );
    assert_eq!(channel.messages_sent, 1);
    Ok(())
}

/// W3C 6.2 `bufferedamountlow`: fired when `bufferedAmount` falls from above
/// `bufferedAmountLowThreshold` to at or below it, once per crossing.
#[test]
fn buffered_amount_low_fires_when_the_queue_falls_to_the_threshold() -> Result<()> {
    let (mut pair, first) = Pair::connected(RTCDtlsRole::Client, "first")?;
    let now = pair.now;
    let mut channel = pair.offerer.pc.data_channel(first).expect("open");
    channel.set_buffered_amount_low_threshold(4096);
    for _ in 0..16 {
        channel.send(now, BytesMut::from(&[3u8; 4096][..]))?;
    }
    assert!(channel.buffered_amount() > 4096);
    let lows = |p: &Pair| {
        p.offerer
            .events
            .iter()
            .filter(|e| matches!(e, RTCDataChannelEvent::OnBufferedAmountLow(id) if *id == first))
            .count()
    };
    let before = lows(&pair);
    assert!(pair.run_until(|p| lows(p) > before)?);
    let channel = pair.offerer.pc.data_channel(first).expect("open");
    assert!(channel.buffered_amount() <= 4096);
    pair.run_for(Duration::from_millis(500))?;
    assert_eq!(lows(&pair), before + 1, "one crossing, one event");
    Ok(())
}

/// W3C 6.2.4 closing procedure: messages sent before `close()` are sent first; the peer
/// receives them all before the channel closes.
#[test]
fn close_sends_what_was_queued_before_it() -> Result<()> {
    let (mut pair, first) = Pair::connected(RTCDtlsRole::Client, "first")?;
    let now = pair.now;
    // W3C 6.2.3 announce a data channel instance: the peer's channel is not negotiated.
    let theirs = *pair
        .answerer
        .opened()
        .last()
        .expect("the answerer's channel");
    assert!(
        !pair
            .answerer
            .pc
            .data_channel(theirs)
            .expect("open")
            .negotiated()
    );
    let mut channel = pair.offerer.pc.data_channel(first).expect("open");
    for i in 0..5u8 {
        channel.send(now, BytesMut::from(&[i; 2000][..]))?;
    }
    channel.close()?;
    assert!(pair.run_until(|p| p.offerer.closed(first))?);
    pair.run_for(Duration::from_millis(200))?;
    let received: Vec<u8> = pair
        .answerer
        .received
        .iter()
        .map(|(_, _, d)| d[0])
        .collect();
    assert_eq!(received, [0, 1, 2, 3, 4]);
    Ok(())
}

/// W3C 6.1.1.2 update the data max message size: the remote value is the description's
/// `max-message-size`, 65536 when the attribute is missing; when one of the two is 0 ("any
/// size") the result is the larger, this side's.
#[test]
fn max_message_size_follows_the_remote_attribute() -> Result<()> {
    use rtci::peer_connection::configuration::setting_engine::SctpMaxMessageSize;
    let without = |sdp: &str| {
        sdp.lines()
            .filter(|l| !l.starts_with("a=max-message-size:"))
            .map(|l| format!("{l}\r\n"))
            .collect::<String>()
    };
    let zero = |sdp: &str| {
        sdp.lines()
            .map(|l| {
                if l.starts_with("a=max-message-size:") {
                    "a=max-message-size:0\r\n".to_owned()
                } else {
                    format!("{l}\r\n")
                }
            })
            .collect::<String>()
    };
    let cases: [(&dyn Fn(&str) -> String, u32); 2] = [(&without, 65536), (&zero, 262_144)];
    for (i, (munge, expected)) in cases.into_iter().enumerate() {
        let port = 52040 + 2 * i as u16;
        let mut pair = Pair::with_setting_engines(
            &format!("127.0.0.1:{port}"),
            engine(RTCDtlsRole::Client),
            &format!("127.0.0.1:{}", port + 1),
            engine(RTCDtlsRole::Server)
                .with_sctp_max_message_size(SctpMaxMessageSize::Bounded(262_144)),
        )?;
        pair.offerer.pc.create_data_channel("m", None)?;
        pair.exchange_with(false, munge, |a| a.to_owned())?;
        let connected = |p: &Pair| {
            p.answerer
                .pc
                .sctp()
                .is_some_and(|s| s.state() == RTCSctpTransportState::Connected)
        };
        assert!(pair.run_until(connected)?);
        assert_eq!(
            pair.answerer.pc.sctp().and_then(|s| s.max_message_size()),
            Some(expected),
            "case {i}"
        );
    }
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

/// RFC 8837 section 5: "if the DSCP of an SCTP association is changed, the congestion
/// controller MUST be reset". The association's codepoint is its highest-priority channel's;
/// a channel of higher priority changes it, and the congestion window, grown by a bulk
/// transfer, starts again from its initial value.
#[test]
fn a_new_codepoint_restarts_the_associations_congestion_control() -> Result<()> {
    use rtci::sansio::Protocol;
    let (mut pair, first) = Pair::connected(RTCDtlsRole::Client, "low")?;
    let initial = pair
        .offerer
        .pc
        .sctp()
        .and_then(|s| s.congestion_window())
        .expect("an association");
    let now = pair.now;
    let mut channel = pair.offerer.pc.data_channel(first).expect("open");
    for _ in 0..64 {
        channel.send(now, BytesMut::from(&[5u8; 16 * 1024][..]))?;
    }
    assert!(pair.run_until(|p| p.answerer.received.len() >= 64)?);
    let grown = pair
        .offerer
        .pc
        .sctp()
        .and_then(|s| s.congestion_window())
        .expect("an association");
    assert!(
        grown > initial,
        "the transfer grew the window: {initial} -> {grown}"
    );

    // The default priority is "low" (DSCP 0 for data, RFC 8837 Table 1); a "high" channel
    // makes it AF21.
    let low = pair.offerer.pc.dscp(&rtci::shared::TaggedBytesMut {
        now,
        transport: Default::default(),
        message: BytesMut::from(&[23u8, 0xfe, 0xfd][..]),
    });
    pair.offerer.pc.create_data_channel(
        "high",
        Some(RTCDataChannelInit {
            priority: 1024,
            ..Default::default()
        }),
    )?;
    let now = pair.now + Duration::from_millis(1);
    pair.now = now;
    pair.offerer.pc.handle_timeout(now)?;
    let high = pair.offerer.pc.dscp(&rtci::shared::TaggedBytesMut {
        now,
        transport: Default::default(),
        message: BytesMut::from(&[23u8, 0xfe, 0xfd][..]),
    });
    assert_ne!(low, high, "the association's codepoint changed");
    let reset = pair
        .offerer
        .pc
        .sctp()
        .and_then(|s| s.congestion_window())
        .expect("an association");
    assert_eq!(reset, initial, "the congestion control starts over");
    Ok(())
}

/// webrtc-priority 4.2: RTCDataChannelInit.priority defaults to "low" (DCEP normal, 256);
/// a channel created "medium" reports it on both sides, the peer's from the
/// DATA_CHANNEL_OPEN it received.
#[test]
fn a_data_channels_priority_defaults_to_low_and_reaches_the_peer() -> Result<()> {
    use rtci::peer_connection::priority::RTCPriorityType;
    let (mut pair, first) = Pair::connected(RTCDtlsRole::Client, "default")?;
    assert_eq!(
        pair.offerer
            .pc
            .data_channel(first)
            .expect("open")
            .priority_type(),
        RTCPriorityType::Low
    );
    let theirs = *pair
        .answerer
        .opened()
        .last()
        .expect("the answerer's channel");
    assert_eq!(
        pair.answerer
            .pc
            .data_channel(theirs)
            .expect("open")
            .priority_type(),
        RTCPriorityType::Low
    );
    let before = pair.answerer.opened().len();
    let medium = pair
        .offerer
        .pc
        .create_data_channel(
            "medium",
            Some(RTCDataChannelInit {
                priority: 512,
                ..Default::default()
            }),
        )?
        .id();
    assert!(pair.run_until(|p| p.answerer.opened().len() > before)?);
    assert_eq!(
        pair.offerer
            .pc
            .data_channel(medium)
            .expect("open")
            .priority_type(),
        RTCPriorityType::Medium
    );
    let theirs = *pair
        .answerer
        .opened()
        .last()
        .expect("the answerer's channel");
    let channel = pair.answerer.pc.data_channel(theirs).expect("open");
    assert_eq!(channel.priority(), 512);
    assert_eq!(channel.priority_type(), RTCPriorityType::Medium);
    Ok(())
}

/// W3C 6.2.3 "announce the data channel instance": a channel the peer opened in-band gets a
/// `datachannel` event, then `open`; the channel this side created gets `open` only.
#[test]
fn a_channel_the_peer_opened_is_announced_before_it_opens() -> Result<()> {
    let (pair, first) = Pair::connected(RTCDtlsRole::Client, "first")?;
    let remote = *pair.answerer.opened().first().expect("opened");
    let position = |events: &[RTCDataChannelEvent], wanted: &RTCDataChannelEvent| {
        events.iter().position(|e| e == wanted)
    };
    let announced = position(
        &pair.answerer.events,
        &RTCDataChannelEvent::OnDataChannel(remote),
    )
    .expect("the answerer announces the channel");
    let opened = position(&pair.answerer.events, &RTCDataChannelEvent::OnOpen(remote))
        .expect("and opens it");
    assert!(announced < opened, "{:?}", pair.answerer.events);
    assert!(
        !pair
            .offerer
            .events
            .contains(&RTCDataChannelEvent::OnDataChannel(first)),
        "{:?}",
        pair.offerer.events
    );
    Ok(())
}

/// W3C webrtc-pc 6.2 `bufferedAmount`: "This value does not reset to zero once the channel
/// closes", and a closed channel's other attributes stay readable. The engine forgets a closed
/// channel (`data_channel(id)` is `None`) and keeps its final attributes for the handle:
/// after a closing procedure that sent everything the final amount is 0; when signalling
/// closes the association under data the peer never acknowledged (an answer with
/// `a=sctp-port:0`), the bytes SCTP never took from the stream's queue stay counted, and the
/// ones it sent do not.
#[test]
fn a_closed_channel_keeps_its_final_buffered_amount() -> Result<()> {
    let (mut pair, first) = Pair::connected(RTCDtlsRole::Client, "first")?;
    let now = pair.now;
    let mut channel = pair.offerer.pc.data_channel(first).expect("open");
    channel.set_buffered_amount_low_threshold(7);
    channel.send(now, BytesMut::from(&[1u8; 1000][..]))?;
    channel.close()?;
    assert!(pair.run_until(|p| p.offerer.closed(first))?);
    assert!(pair.offerer.pc.data_channel(first).is_none(), "forgotten");
    let closed = pair
        .offerer
        .pc
        .closed_data_channel(first)
        .expect("the final attributes are kept");
    assert_eq!(closed.label(), "first");
    assert_eq!(closed.ready_state(), RTCDataChannelState::Closed);
    assert_eq!(closed.buffered_amount(), 0, "everything was sent");
    assert_eq!(closed.buffered_amount_low_threshold(), 7);
    assert!(closed.stream_id().is_some());

    const MESSAGE: usize = 10_000;
    const MESSAGES: usize = 20;
    let (mut pair, first) = Pair::connected(RTCDtlsRole::Client, "bulk")?;
    // No SACK comes back: the congestion window stays at its first size and most of the
    // data stays in the stream's queue.
    pair.answerer.drop_outgoing = true;
    let now = pair.now;
    let mut channel = pair.offerer.pc.data_channel(first).expect("open");
    for _ in 0..MESSAGES {
        channel.send(now, BytesMut::from(&[2u8; MESSAGE][..]))?;
    }
    pair.run_for(Duration::from_millis(200))?;
    let before = pair
        .offerer
        .pc
        .data_channel(first)
        .expect("open")
        .buffered_amount();
    assert!(
        before > 0 && before < (MESSAGE * MESSAGES) as u64,
        "some of it went out: {before}"
    );

    pair.exchange_with(
        false,
        |offer| offer.to_owned(),
        |answer| {
            let port = answer
                .lines()
                .find(|l| l.starts_with("a=sctp-port:"))
                .expect("an sctp-port")
                .to_owned();
            answer.replace(&port, "a=sctp-port:0")
        },
    )?;
    assert!(
        pair.run_until(|p| p.offerer.closed(first))?,
        "signalling closed the association and the channel with it"
    );
    assert!(pair.offerer.pc.data_channel(first).is_none(), "closed");
    let closed = pair
        .offerer
        .pc
        .closed_data_channel(first)
        .expect("the final attributes are kept");
    assert_eq!(closed.label(), "bulk");
    assert!(
        closed.buffered_amount() > 0 && closed.buffered_amount() <= before,
        "the unsent bytes, not reset and not counting what was sent: {} (before {before})",
        closed.buffered_amount()
    );
    Ok(())
}

/// W3C webrtc-pc 6.2 `send()`: the data is transmitted on the channel's transport, and "if an
/// error is raised at the SCTP level, the user agent MUST ... run the steps to close the data
/// channel" with an `RTCError` of `sctp-failure`. The offerer's association has short
/// retransmission bounds (`with_sctp_rto`, `with_sctp_max_retransmissions`); the answerer
/// stops answering after a `send()`, so the DATA is retransmitted until the limit fails the
/// association long before ICE consent would: the channel fires `OnError` (`sctp-failure`),
/// then `OnClose`.
#[test]
fn an_sctp_failure_while_sending_fails_the_channel_with_sctp_failure() -> Result<()> {
    let mut pair = Pair::with_setting_engines(
        "127.0.0.1:52040",
        engine(RTCDtlsRole::Client)
            .with_sctp_rto(
                Duration::from_millis(100),
                Duration::from_millis(100),
                Duration::from_millis(200),
            )
            .with_sctp_max_retransmissions(2),
        "127.0.0.1:52041",
        engine(RTCDtlsRole::Server),
    )?;
    let first = pair.offerer.pc.create_data_channel("first", None)?.id();
    pair.negotiate()?;
    assert!(pair.run_until(|p| p.offerer.opened().contains(&first))?);

    pair.answerer.drop_outgoing = true;
    let now = pair.now;
    let started = pair.now;
    pair.offerer
        .pc
        .data_channel(first)
        .expect("open")
        .send(now, BytesMut::from(&b"never acknowledged"[..]))?;
    assert!(
        pair.run_until(|p| p.offerer.closed(first))?,
        "the SCTP failure closes the channel"
    );
    assert!(
        pair.now - started < Duration::from_secs(5),
        "SCTP failed it, not ICE: {:?}",
        pair.now - started
    );
    assert_eq!(
        pair.offerer.events_of(first),
        [
            RTCDataChannelEvent::OnOpen(first),
            RTCDataChannelEvent::OnError(first),
            RTCDataChannelEvent::OnClose(first)
        ],
        "an error, then the close, without the closing procedure"
    );
    assert_eq!(
        pair.offerer
            .pc
            .data_channel_error(first)
            .map(|e| e.error_detail),
        Some(RTCErrorDetailType::SctpFailure)
    );
    Ok(())
}
