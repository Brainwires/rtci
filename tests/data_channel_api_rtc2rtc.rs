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
    let mut channel = pair.offerer.pc.data_channel(late).expect("the channel");
    assert!(channel.stream_id().is_some(), "dialed at once");

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
/// [[MaxBufferSize]], throw an OperationError"; [[MaxBufferSize]] is the larger of the two
/// sides' max-message-size. A fixed limit replaces it when the application sets one.
#[test]
fn send_refuses_data_above_the_max_buffer_size() -> Result<()> {
    let (mut pair, first) = Pair::connected(RTCDtlsRole::Client, "first")?;
    let now = pair.now;
    let max_message = pair
        .offerer
        .pc
        .sctp()
        .and_then(|s| s.max_message_size())
        .expect("negotiated") as usize;
    let mut channel = pair.offerer.pc.data_channel(first).expect("open");
    // 256 KiB: the larger of the two max-message-size values (both sides' default).
    let mut queued = 0usize;
    let refused = loop {
        match channel.send(now, BytesMut::from(&vec![1u8; max_message][..])) {
            Ok(()) => queued += max_message,
            Err(err) => break err,
        }
        assert!(queued <= 1 << 20, "never refused");
    };
    assert!(
        matches!(refused, Error::ErrDataChannelBufferFull),
        "{refused:?}"
    );
    assert!(channel.buffered_amount() <= 256 * 1024);

    let mut pair = Pair::with_setting_engines(
        "127.0.0.1:52020",
        engine(RTCDtlsRole::Client).with_data_channel_max_buffer_size(Some(1 << 22)),
        "127.0.0.1:52021",
        engine(RTCDtlsRole::Server),
    )?;
    let id = pair.offerer.pc.create_data_channel("big", None)?.id();
    pair.negotiate()?;
    assert!(pair.run_until(|p| p.offerer.opened().contains(&id))?);
    let now = pair.now;
    let mut channel = pair.offerer.pc.data_channel(id).expect("open");
    for _ in 0..8 {
        channel.send(now, BytesMut::from(&vec![1u8; max_message][..]))?;
    }
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
