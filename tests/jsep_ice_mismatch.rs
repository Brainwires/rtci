//! `a=ice-mismatch` in an answer (RFC 8839 sections 4.2.5, 4.3.3 and 5.3): for that data
//! stream "ICE procedures MUST NOT be used" and RFC 3264 procedures are used instead. A WebRTC
//! endpoint has no media path without ICE (RFC 9429 section 5.1.1; consent, RFC 8826 section
//! 4.2 and RFC 7675): the answer is applied and the stream's ICE agent stops (no checks, no
//! consent, failed), so nothing is sent for it.

mod dtls_sdp_common;

use anyhow::Result;
use dtls_sdp_common::{Peer, World};
use rtci::peer_connection::configuration::setting_engine::SettingEngineBuilder;
use rtci::peer_connection::sdp::RTCSessionDescription;
use rtci::peer_connection::state::{RTCIceConnectionState, RTCSignalingState};

#[test]
fn an_answer_with_ice_mismatch_ends_ice_and_sends_nothing() -> Result<()> {
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
    world.peers[0]
        .pc
        .set_remote_description(now, RTCSessionDescription::answer(mismatch)?)?;
    assert_eq!(
        world.peers[0].pc.signaling_state(),
        RTCSignalingState::Stable,
        "the answer is applied"
    );
    world.trickle()?;
    world.run("ICE ends for the stream", |peers| {
        peers[0].pc.ice_connection_state() == RTCIceConnectionState::Failed
    })?;
    assert!(
        !world.peers[0].connected() && world.peers[0].channel.is_none(),
        "no media path without ICE consent"
    );
    Ok(())
}
