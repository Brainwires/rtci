//! A peer that restarts the SCTP association under an established one, between two engines in
//! memory on a virtual clock.
//!
//! RFC 9260 section 5.2.4 action A: an endpoint that lost its state (a reloaded or crashed
//! peer) sends an INIT, and then a COOKIE ECHO with the Tie-Tags of the association still
//! established on the other side, which "treats it the same as if it received an ABORT chunk
//! followed by a new COOKIE ECHO" and reports a restart. Over WebRTC this happens when a new
//! peer connection takes an old one's place without closing it (no `close_notify`, no ABORT):
//! the new DTLS association is negotiated by fingerprint, and the SCTP association goes on
//! over it (RFC 8841 section 10.5), so the newcomer's INIT on the same `a=sctp-port` reaches
//! an association that is still ESTABLISHED.
//!
//! The data channels of the old association are gone with it: each is closed with an error
//! (W3C webrtc 6.2, "announce the data channel as closed" with `sctp-failure`) and counted as
//! closed; the SCTP transport stays `connected`, and the new association carries the
//! newcomer's channels.

mod dc_common;

use anyhow::Result;
use dc_common::{Pair, Peer};
use rtc::peer_connection::configuration::setting_engine::SettingEngineBuilder;
use rtc::peer_connection::event::RTCDataChannelEvent;
use rtc::peer_connection::rtc_error::RTCErrorDetailType;
use rtc::peer_connection::transport::{RTCDtlsRole, RTCSctpTransportState};
use rtc::statistics::StatsSelector;

const A: &str = "127.0.0.1:50010";
const B: &str = "127.0.0.1:50011";

fn offerer_engine() -> SettingEngineBuilder {
    SettingEngineBuilder::new()
}

/// The offerer is replaced by a new peer connection at its address that never closed the old
/// one. The answerer's association is restarted by the newcomer's INIT: its channel of the old
/// association fails and closes, its SCTP transport stays connected, and a channel the
/// newcomer opens carries data both ways.
#[test]
fn a_peer_that_restarts_the_association_closes_the_old_channels_with_an_error() -> Result<()> {
    for answerer_role in [RTCDtlsRole::Client, RTCDtlsRole::Server] {
        let what = format!("the peer that stays answers as DTLS {answerer_role}");
        let mut pair = Pair::with_setting_engines(
            A,
            offerer_engine(),
            B,
            SettingEngineBuilder::new().with_answering_dtls_role(answerer_role),
        )?;
        let first = pair.open_channel("first")?;
        let first_remote = pair.answerer.opened()[0];
        assert!(pair.deliver(false, first, b"on the first association")?);
        assert!(pair.deliver(true, first_remote, b"and back")?);

        // A new peer connection takes the offerer's place: the old one is not closed, so
        // nothing tells the answerer its association ended.
        pair.offerer = Peer::with_setting_engine(A.parse()?, offerer_engine(), pair.now)?;
        pair.offerer.tolerate_read_errors = true;
        pair.answerer.tolerate_read_errors = true;
        let second = pair.offerer.pc.create_data_channel("second", None)?.id();
        pair.negotiate()?;

        assert!(
            pair.run_until(|p| p.offerer.opened().contains(&second)
                && p.answerer.opened().len() == 2
                && p.answerer.closed(first_remote))?,
            "{what}: {:?} / {:?}, {:?} / {:?}, SCTP {:?} / {:?}, error {:?}",
            pair.offerer.events,
            pair.answerer.events,
            pair.offerer.connection_states,
            pair.answerer.connection_states,
            pair.offerer.pc.sctp().map(|s| s.state()),
            pair.answerer.pc.sctp().map(|s| s.state()),
            pair.answerer.pc.data_channel_error(first_remote),
        );
        assert_eq!(
            pair.answerer.events_of(first_remote),
            [
                RTCDataChannelEvent::OnOpen(first_remote),
                RTCDataChannelEvent::OnError(first_remote),
                RTCDataChannelEvent::OnClose(first_remote),
            ],
            "{what}: the old channel is announced closed with an error"
        );
        let error = pair
            .answerer
            .pc
            .data_channel_error(first_remote)
            .expect("the channel's error is kept");
        assert_eq!(
            error.error_detail,
            RTCErrorDetailType::SctpFailure,
            "{what}"
        );
        assert!(
            pair.answerer.pc.data_channel(first_remote).is_none(),
            "{what}: the old channel is gone"
        );

        let second_remote = pair.answerer.opened()[1];
        assert!(pair.deliver(false, second, b"on the restarted association")?);
        assert!(pair.deliver(true, second_remote, b"and back")?);
        assert_eq!(
            pair.answerer.pc.sctp().expect("SCTP").state(),
            RTCSctpTransportState::Connected,
            "{what}"
        );

        let now = pair.now;
        let report = pair.answerer.pc.get_stats(now, StatsSelector::None);
        let stats = report.peer_connection().expect("peer connection stats");
        assert_eq!(
            (stats.data_channels_opened, stats.data_channels_closed),
            (2, 1),
            "{what}: the old channel is counted as closed"
        );
    }
    Ok(())
}

/// W3C webrtc-pc 6.2: a closed channel's `bufferedAmount` keeps the bytes that were never
/// sent, and only those. The answerer's channel has queued more than the window lets out
/// (the old offerer acknowledges nothing) when the newcomer restarts the association: the
/// channel closes with the bytes still in its queue, not every byte it was given.
#[test]
fn a_channel_closed_by_a_restart_keeps_only_its_unsent_bytes_buffered() -> Result<()> {
    use bytes::BytesMut;
    use std::time::Duration;
    const MESSAGE: usize = 10_000;
    const MESSAGES: usize = 20;
    let mut pair = Pair::with_setting_engines(
        A,
        offerer_engine(),
        B,
        SettingEngineBuilder::new().with_answering_dtls_role(RTCDtlsRole::Client),
    )?;
    let first = pair.open_channel("first")?;
    let first_remote = pair.answerer.opened()[0];
    assert!(pair.deliver(false, first, b"on the first association")?);

    pair.offerer.drop_outgoing = true;
    let now = pair.now;
    let mut channel = pair.answerer.pc.data_channel(first_remote).expect("open");
    for _ in 0..MESSAGES {
        channel.send(now, BytesMut::from(&[3u8; MESSAGE][..]))?;
    }
    pair.run_for(Duration::from_millis(200))?;
    let before = pair
        .answerer
        .pc
        .data_channel(first_remote)
        .expect("open")
        .buffered_amount();
    assert!(
        before > 0 && before < (MESSAGE * MESSAGES) as u64,
        "some of it went out: {before}"
    );

    pair.offerer = Peer::with_setting_engine(A.parse()?, offerer_engine(), pair.now)?;
    pair.offerer.tolerate_read_errors = true;
    pair.answerer.tolerate_read_errors = true;
    pair.offerer.pc.create_data_channel("second", None)?;
    pair.negotiate()?;
    assert!(
        pair.run_until(|p| p.answerer.closed(first_remote))?,
        "the restart closes the old channel"
    );
    let closed = pair
        .answerer
        .pc
        .closed_data_channel(first_remote)
        .expect("the final attributes are kept");
    assert!(
        closed.buffered_amount() > 0 && closed.buffered_amount() <= before,
        "the unsent bytes only: {} (before the restart {before})",
        closed.buffered_amount()
    );
    Ok(())
}
