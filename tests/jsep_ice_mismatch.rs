//! `a=ice-mismatch` in an answer (RFC 8839 sections 4.2.5, 4.3.3 and 5.3): for that data
//! stream "ICE procedures MUST NOT be used" and RFC 3264 procedures are used instead. A WebRTC
//! endpoint has no media path without ICE (RFC 9429 section 5.1.1; consent, RFC 8826 section
//! 4.2 and RFC 7675), so the answer is refused: the offerer stays in `have-local-offer`, runs
//! no ICE for the stream, and takes an answer without the attribute.

mod dtls_sdp_common;

use anyhow::Result;
use dtls_sdp_common::{Peer, World};
use rtc::peer_connection::configuration::setting_engine::SettingEngineBuilder;
use rtc::peer_connection::sdp::RTCSessionDescription;
use rtc::peer_connection::state::RTCSignalingState;

#[test]
fn an_answer_with_ice_mismatch_is_refused() -> Result<()> {
    let mut world = World::new(
        Peer::new("10.0.0.1:5000", SettingEngineBuilder::new().build())?,
        Peer::new("10.0.0.2:5000", SettingEngineBuilder::new().build())?,
    );
    world.peers[0].pc.create_data_channel("data", None)?;
    let now = world.now;
    let offer = world.peers[0].pc.create_offer(None)?;
    world.peers[0]
        .pc
        .set_local_description(now, offer.clone())?;
    world.peers[1].pc.set_remote_description(now, offer)?;
    let answer = world.peers[1].pc.create_answer(None)?;
    world.peers[1]
        .pc
        .set_local_description(now, answer.clone())?;

    let mismatch = answer.sdp.replace("a=mid:", "a=ice-mismatch\r\na=mid:");
    assert_ne!(mismatch, answer.sdp);
    let refused = world.peers[0]
        .pc
        .set_remote_description(now, RTCSessionDescription::answer(mismatch)?);
    assert!(
        refused.is_err(),
        "an answer with a=ice-mismatch was accepted"
    );
    assert_eq!(
        world.peers[0].pc.signaling_state(),
        RTCSignalingState::HaveLocalOffer
    );
    assert!(world.peers[0].pc.remote_description().is_none());

    world.peers[0].pc.set_remote_description(now, answer)?;
    world.trickle()?;
    world.run("the connection", |peers| {
        peers.iter().all(|p| p.connected() && p.channel.is_some())
    })?;
    Ok(())
}
