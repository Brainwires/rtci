//! RFC 8838 section 13 and 18: an end-of-candidates indication names the ICE session it ends
//! (its username fragment); section 5: a description without trickle support is processed by
//! regular ICE.
//!
//! The local indication (W3C `icecandidate` with an empty candidate) carries the username
//! fragment of the generation that finished gathering, and after an ICE restart the new one;
//! `to_json` hands it on with an empty `candidate`.

mod dtls_sdp_common;

use anyhow::Result;
use dtls_sdp_common::{Peer, World, attribute_values, keep, replace_lines};
use rtc::peer_connection::RTCPeerConnection;
use rtc::peer_connection::configuration::setting_engine::SettingEngineBuilder;
use rtc::peer_connection::event::RTCPeerConnectionEvent;
use rtc::peer_connection::transport::{RTCIceCandidate, RTCIceCandidateInit};
use rtc::sansio::Protocol;
use std::time::Instant;

fn end_of_candidates(pc: &mut RTCPeerConnection) -> Option<RTCIceCandidate> {
    let mut found = None;
    while let Some(event) = pc.poll_event() {
        if let RTCPeerConnectionEvent::OnIceCandidateEvent(event) = event
            && let Some(candidate) = event.candidate
            && candidate.end_of_candidates
        {
            found = Some(candidate);
        }
    }
    found
}

#[test]
fn the_local_end_of_candidates_names_its_generation() -> Result<()> {
    let mut peer = Peer::new("10.0.0.1:5000", SettingEngineBuilder::new().build())?;
    peer.pc.create_data_channel("data", None)?;
    let now = Instant::now();
    for round in 0..2 {
        if round == 1 {
            peer.pc.restart_ice();
        }
        let offer = peer.pc.create_offer(None)?;
        peer.pc.set_local_description(now, offer.clone())?;
        let ufrag = attribute_values(&offer.sdp, "ice-ufrag")
            .into_iter()
            .next()
            .expect("a ufrag");
        let candidate = peer.candidate()?;
        peer.pc.add_local_candidate(candidate)?;
        peer.pc
            .add_local_candidate(RTCIceCandidateInit::default())?;
        let end = end_of_candidates(&mut peer.pc).expect("the end-of-candidates indication");
        assert_eq!(
            end.username_fragment.as_deref(),
            Some(ufrag.as_str()),
            "round {round}"
        );
        let json = end.to_json()?;
        assert_eq!(json.candidate, "");
        assert_eq!(json.username_fragment, Some(ufrag));
    }
    Ok(())
}

/// Section 5: a responder that gets an offer without `a=ice-options:trickle` processes it by
/// regular ICE: the same agent, and the session connects.
#[test]
fn an_offer_without_trickle_support_is_processed_by_regular_ice() -> Result<()> {
    let mut world = World::new(
        Peer::new("10.0.0.1:5000", SettingEngineBuilder::new().build())?,
        Peer::new("10.0.0.2:5000", SettingEngineBuilder::new().build())?,
    );
    world.peers[0].pc.create_data_channel("data", None)?;
    let (offer, _) =
        world.exchange_with(0, |sdp| replace_lines(sdp, "a=ice-options:", None), keep)?;
    assert!(
        offer.contains("a=ice-options:trickle"),
        "the engine offers trickle"
    );
    world.trickle()?;
    world.run("connected", |peers| peers.iter().all(|p| p.connected()))?;
    Ok(())
}
