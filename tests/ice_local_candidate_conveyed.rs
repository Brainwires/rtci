//! RFC 8838 section 10: "A Trickle ICE agent MUST NOT pair a local candidate until it has been
//! trickled to the remote party." Through the peer connection a local candidate is conveyed
//! when the application takes its `OnIceCandidateEvent` (it is the application's to trickle),
//! or when a local description listing it is set. Until then no connectivity check leaves on
//! it. `with_ice_pairing_before_candidates_are_conveyed(true)` pairs it at once.

mod dtls_sdp_common;

use anyhow::Result;
use dtls_sdp_common::{Peer, World};
use rtci::peer_connection::configuration::setting_engine::SettingEngineBuilder;
use rtci::peer_connection::event::RTCPeerConnectionEvent;
use rtci::sansio::Protocol;
use std::net::SocketAddr;
use std::time::Duration;

const A: &str = "10.0.0.1:5000";
const B: &str = "10.0.0.2:5000";

/// STUN Binding requests `peer` writes to `to` while its timer runs for `span` from `world.now`
/// (its events are not taken).
fn binding_requests_to(world: &mut World, peer: usize, to: SocketAddr, span: Duration) -> usize {
    let end = world.now + span;
    let mut count = 0;
    while world.now < end {
        let now = world.now;
        world.peers[peer].pc.handle_timeout(now).unwrap();
        while let Some(out) = world.peers[peer].pc.poll_write() {
            let m = &out.message;
            if out.transport.peer_addr == to && m.len() >= 20 && m[0] == 0x00 && m[1] == 0x01 {
                count += 1;
            }
        }
        world.now += Duration::from_millis(20);
    }
    count
}

/// A has B's candidate and B's credentials; B's candidate is B's own and conveyed.
fn negotiated(pair_before_conveyed: bool) -> Result<World> {
    let mut world = World::new(
        Peer::new(
            A,
            SettingEngineBuilder::new()
                .with_ice_pairing_before_candidates_are_conveyed(pair_before_conveyed)
                .build(),
        )?,
        Peer::new(B, SettingEngineBuilder::new().build())?,
    );
    world.peers[0].pc.create_data_channel("data", None)?;
    world.exchange(0)?;
    let b = world.peers[1].candidate()?;
    world.peers[1].pc.add_local_candidate(b.clone())?;
    world.peers[0].pc.add_remote_candidate(b)?;
    Ok(world)
}

#[test]
fn a_local_candidate_is_not_paired_until_the_application_has_taken_it_to_trickle() -> Result<()> {
    let mut world = negotiated(false)?;
    let b: SocketAddr = B.parse()?;
    let a = world.peers[0].candidate()?;
    world.peers[0].pc.add_local_candidate(a)?;

    assert_eq!(
        binding_requests_to(&mut world, 0, b, Duration::from_secs(2)),
        0,
        "a check left on a candidate the application has not had to trickle"
    );

    // The application takes the candidate's event: it is conveyed, and checked.
    let mut taken = false;
    while let Some(event) = world.peers[0].pc.poll_event() {
        if let RTCPeerConnectionEvent::OnIceCandidateEvent(e) = event {
            taken |= e.candidate.is_some_and(|c| c.address == "10.0.0.1");
        }
    }
    assert!(taken, "the candidate is announced");
    assert!(binding_requests_to(&mut world, 0, b, Duration::from_secs(2)) > 0);

    // And the session connects on it.
    let a = world.peers[0].candidate()?;
    world.peers[1].pc.add_remote_candidate(a)?;
    world.run("connected", |peers| {
        peers.iter().all(|p| p.connected() && p.channel.is_some())
    })?;
    Ok(())
}

#[test]
fn a_local_candidate_is_conveyed_by_the_local_description_that_lists_it() -> Result<()> {
    let mut world = World::new(
        Peer::new(A, SettingEngineBuilder::new().build())?,
        Peer::new(B, SettingEngineBuilder::new().build())?,
    );
    let b: SocketAddr = B.parse()?;
    world.peers[0].pc.create_data_channel("data", None)?;
    // Gathered before the offer, its event not taken.
    let a = world.peers[0].candidate()?;
    world.peers[0].pc.add_local_candidate(a)?;
    let now = world.now;
    let offer = world.peers[0].pc.create_offer(None)?;
    world.peers[0].pc.set_local_description(now, offer)?;
    let offer = world.peers[0]
        .pc
        .pending_local_description()
        .expect("the offer");
    assert!(
        offer.sdp.contains("10.0.0.1"),
        "the offer lists the candidate"
    );
    world.peers[1].pc.set_remote_description(now, offer)?;
    let answer = world.peers[1].pc.create_answer(None)?;
    world.peers[1]
        .pc
        .set_local_description(now, answer.clone())?;
    world.peers[0].pc.set_remote_description(now, answer)?;
    let b_candidate = world.peers[1].candidate()?;
    world.peers[0].pc.add_remote_candidate(b_candidate)?;

    assert!(
        binding_requests_to(&mut world, 0, b, Duration::from_secs(2)) > 0,
        "the candidate the description conveyed is paired and checked"
    );
    Ok(())
}

#[test]
fn pairing_before_the_candidate_is_conveyed_is_a_setting() -> Result<()> {
    let mut world = negotiated(true)?;
    let b: SocketAddr = B.parse()?;
    let a = world.peers[0].candidate()?;
    world.peers[0].pc.add_local_candidate(a)?;
    assert!(
        binding_requests_to(&mut world, 0, b, Duration::from_secs(2)) > 0,
        "paired at once, its event not taken"
    );
    Ok(())
}
