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
use rtci::peer_connection::RTCPeerConnection;
use rtci::peer_connection::configuration::setting_engine::SettingEngineBuilder;
use rtci::peer_connection::event::RTCPeerConnectionEvent;
use rtci::peer_connection::transport::{RTCIceCandidate, RTCIceCandidateInit};
use rtci::sansio::Protocol;
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

/// Section 13: "a controlled agent [...] SHOULD convey an end-of-candidates indication [...]
/// once it has completed gathering", and the controlling agent "SHOULD convey one whenever
/// possible": in either role, the application that ends gathering gets the indication to
/// convey, and the local description, read afterwards, carries `a=end-of-candidates`.
#[test]
fn either_role_conveys_end_of_candidates_when_its_gathering_completes() -> Result<()> {
    let mut world = World::new(
        Peer::new("10.0.0.1:5000", SettingEngineBuilder::new().build())?,
        Peer::new("10.0.0.2:5000", SettingEngineBuilder::new().build())?,
    );
    world.peers[0].pc.create_data_channel("data", None)?;
    world.exchange(0)?;
    for (index, role) in [(0, "controlling offerer"), (1, "controlled answerer")] {
        let peer = &mut world.peers[index];
        let candidate = peer.candidate()?;
        peer.pc.add_local_candidate(candidate)?;
        assert!(
            end_of_candidates(&mut peer.pc).is_none(),
            "{role}: no end before gathering completes"
        );
        peer.pc
            .add_local_candidate(RTCIceCandidateInit::default())?;
        assert!(
            end_of_candidates(&mut peer.pc).is_some(),
            "{role}: the end-of-candidates indication"
        );
        let local = peer
            .pc
            .current_local_description()
            .expect("a local description");
        assert!(
            local.sdp.contains("a=end-of-candidates"),
            "{role}: {}",
            local.sdp
        );
    }
    Ok(())
}

/// Section 13: "an agent using half trickle SHOULD convey end-of-candidates together with its
/// initial description": gathering finished before the offer was made, the offer lists the
/// candidates and `a=end-of-candidates`. An offer made while gathering is not finished does
/// not carry it.
#[test]
fn a_half_trickle_offer_carries_end_of_candidates() -> Result<()> {
    let mut peer = Peer::new("10.0.0.1:5000", SettingEngineBuilder::new().build())?;
    peer.pc.create_data_channel("data", None)?;
    let unfinished = peer.pc.create_offer(None)?;
    assert!(!unfinished.sdp.contains("a=end-of-candidates"));
    let candidate = peer.candidate()?;
    peer.pc.add_local_candidate(candidate)?;
    peer.pc
        .add_local_candidate(RTCIceCandidateInit::default())?;
    let offer = peer.pc.create_offer(None)?;
    peer.pc.set_local_description(Instant::now(), offer)?;
    let offer = peer.pc.pending_local_description().expect("the offer");
    assert!(offer.sdp.contains("a=candidate:"), "{}", offer.sdp);
    assert!(offer.sdp.contains("a=end-of-candidates"), "{}", offer.sdp);
    Ok(())
}

/// Section 3: the agents discover Trickle ICE support from the descriptions. A remote
/// description with `a=ice-options:trickle` at session level or only in a media section says
/// the peer trickles (`can_trickle_ice_candidates` true); one without says it does not
/// (false).
#[test]
fn trickle_support_is_read_from_session_or_media_level_ice_options() -> Result<()> {
    for (munge, expected) in [
        (Box::new(keep) as Box<dyn Fn(&str) -> String>, Some(true)),
        (
            Box::new(|sdp: &str| replace_lines(sdp, "a=ice-options:", None)),
            Some(false),
        ),
        (
            Box::new(|sdp: &str| {
                let without = replace_lines(sdp, "a=ice-options:", None);
                without.replacen("a=mid:", "a=ice-options:trickle\r\na=mid:", 1)
            }),
            Some(true),
        ),
    ] {
        let mut world = World::new(
            Peer::new("10.0.0.1:5000", SettingEngineBuilder::new().build())?,
            Peer::new("10.0.0.2:5000", SettingEngineBuilder::new().build())?,
        );
        world.peers[0].pc.create_data_channel("data", None)?;
        assert_eq!(world.peers[1].pc.can_trickle_ice_candidates(), None);
        let (offer, _) = world.exchange_with(0, &munge, keep)?;
        assert!(offer.contains("a=ice-options:trickle"));
        assert_eq!(
            world.peers[1].pc.can_trickle_ice_candidates(),
            expected,
            "{}",
            munge(&offer)
        );
    }
    Ok(())
}
