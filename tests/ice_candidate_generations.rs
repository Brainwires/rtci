//! W3C webrtc-pc 4.4.2 `addIceCandidate`: a candidate is added "for the ICE generation" its
//! usernameFragment names, the latest when it is null; a usernameFragment no media description
//! of the remote description has is an OperationError. Through an ICE restart: once B has
//! applied A's restart offer, a candidate of A's old generation is refused, and candidates of
//! the new generation (named, or with a null usernameFragment) wait for B's answer and then
//! reach B's agent; the session connects on them.

mod dtls_sdp_common;

use anyhow::Result;
use dtls_sdp_common::{Peer, World, attribute_values};
use rtci::peer_connection::configuration::setting_engine::SettingEngineBuilder;
use rtci::peer_connection::sdp::RTCSessionDescription;

const A: &str = "10.0.0.1:5000";
const B: &str = "10.0.0.2:5000";

#[test]
fn a_candidate_goes_to_the_generation_its_username_fragment_names() -> Result<()> {
    let mut world = World::new(
        Peer::new(A, SettingEngineBuilder::new().build())?,
        Peer::new(B, SettingEngineBuilder::new().build())?,
    );
    let (first_offer, _) = world.connect()?;
    let old_ufrag = attribute_values(&first_offer, "ice-ufrag")
        .into_iter()
        .next()
        .expect("a ufrag");

    // A restarts; B applies the offer.
    world.peers[0].pc.restart_ice();
    let now = world.now;
    let offer = world.peers[0].pc.create_offer(None)?;
    world.peers[0]
        .pc
        .set_local_description(now, offer.clone())?;
    let new_ufrag = attribute_values(&offer.sdp, "ice-ufrag")
        .into_iter()
        .next()
        .expect("a ufrag");
    assert_ne!(new_ufrag, old_ufrag);
    world.peers[1]
        .pc
        .set_remote_description(now, RTCSessionDescription::offer(offer.sdp.clone())?)?;

    let mut candidate = world.peers[0].candidate()?;
    candidate.username_fragment = Some(old_ufrag);
    assert!(
        world.peers[1]
            .pc
            .add_remote_candidate(candidate.clone())
            .is_err(),
        "the old generation is no longer in the remote description: OperationError"
    );
    candidate.username_fragment = Some(new_ufrag);
    world.peers[1].pc.add_remote_candidate(candidate.clone())?;
    candidate.username_fragment = None;
    world.peers[1].pc.add_remote_candidate(candidate)?;

    let answer = world.peers[1].pc.create_answer(None)?;
    world.peers[1]
        .pc
        .set_local_description(now, answer.clone())?;
    world.peers[0]
        .pc
        .set_remote_description(now, RTCSessionDescription::answer(answer.sdp)?)?;
    let b_candidate = world.peers[1].candidate()?;
    world.peers[1].pc.add_local_candidate(b_candidate.clone())?;
    world.peers[0].pc.add_remote_candidate(b_candidate)?;
    let a_candidate = world.peers[0].candidate()?;
    world.peers[0].pc.add_local_candidate(a_candidate)?;

    // B's agent took the new generation's candidate: its pair with A's address is checked
    // and selected.
    world.run("the new generation connects", |peers| {
        peers[1]
            .pc
            .sctp()
            .and_then(|sctp| {
                sctp.transport()
                    .ice_transport()
                    .get_selected_candidate_pair()
            })
            .is_some_and(|pair| pair.remote().address == "10.0.0.1")
    })?;
    world.ping_pong("after the restart")?;
    Ok(())
}
