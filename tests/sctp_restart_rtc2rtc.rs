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
