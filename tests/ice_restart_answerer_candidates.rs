//! The answerer of an ICE restart: the local candidates it is given between applying the
//! remote restart offer (`set_remote_description`) and applying its answer
//! (`set_local_description`) are the new generation's, between two `rtci` peers on an in-memory
//! network and a virtual clock.
//!
//! The engine announces them with the new username fragment (`OnIceCandidateEvent`, W3C
//! webrtc-pc 4.8.1 `usernameFragment`), the one the answer carries, so they are that
//! generation's (RFC 8838 section 2: a generation is "all of the candidates conveyed within an
//! ICE session (correlated with a particular Username Fragment and Password combination)").
//! W3C webrtc-pc 5.6 holds a candidate gathered for a generation whose description is not
//! applied yet ("append candidate to `[[EarlyCandidates]]`") and surfaces it when the
//! description is applied; it never drops it. RFC 9429 section 5.3.1: the answer carries "an
//! `a=candidate` line for each candidate that has been gathered".
//!
//! An answerer with `with_discard_local_candidates_during_ice_restart(true)` used to drop them
//! when the answer applied the restart, after announcing them, and its answer listed none: the
//! new generation had no local candidate unless the application added each one again after
//! `set_local_description`. And with or without that setting, a candidate the agent did not
//! hold yet was refused without an event, because the current session had nominated a pair
//! (RFC 8838 section 13, a rule of that session, not of the one the restart begins).

use anyhow::Result;
use rtci::peer_connection::configuration::setting_engine::SettingEngineBuilder;
use rtci::peer_connection::event::RTCPeerConnectionEvent;
use rtci::peer_connection::transport::RTCIceCandidateInit;
use rtci::sansio::Protocol;

mod dtls_sdp_common;
use dtls_sdp_common::{Peer, World};

/// A second host candidate of the answerer, on a port the application bound for the restart.
const NEW_HOST: &str = "10.0.0.2:5001";

fn sdp_value(sdp: &str, key: &str) -> Vec<String> {
    sdp.lines()
        .filter_map(|line| line.strip_prefix(key))
        .map(str::to_owned)
        .collect()
}

/// The candidates the peer announced since the last call, as (candidate, usernameFragment).
fn announced(world: &mut World, i: usize) -> Vec<(String, Option<String>)> {
    let mut out = vec![];
    while let Some(event) = world.peers[i].pc.poll_event() {
        if let RTCPeerConnectionEvent::OnIceCandidateEvent(event) = event
            && let Some(candidate) = event.candidate
            && !candidate.end_of_candidates
        {
            out.push((
                candidate.to_json().map(|c| c.candidate).unwrap_or_default(),
                candidate.username_fragment.clone(),
            ));
        }
    }
    out
}

fn restart_answer_keeps_candidates_given_before_it(discard: bool) -> Result<()> {
    let mut world = World::new(
        Peer::new("10.0.0.1:5000", SettingEngineBuilder::new().build())?,
        Peer::new(
            "10.0.0.2:5000",
            SettingEngineBuilder::new()
                .with_discard_local_candidates_during_ice_restart(discard)
                .build(),
        )?,
    );
    world.connect()?;
    world.ping_pong("connected")?;
    let _ = announced(&mut world, 1);

    // The offerer restarts ICE; the answerer applies the offer, then gathers for it (its
    // host candidate again, and one on a socket it bound for the restart) before answering.
    let now = world.now;
    world.peers[0].pc.restart_ice();
    let offer = world.peers[0].pc.create_offer(None)?;
    world.peers[0]
        .pc
        .set_local_description(now, offer.clone())?;
    world.peers[1].pc.set_remote_description(now, offer)?;
    let same = world.peers[1].candidate()?;
    world.peers[1].pc.add_local_candidate(same)?;
    let new_host: std::net::SocketAddr = NEW_HOST.parse()?;
    world.peers[1].pc.add_local_candidate(RTCIceCandidateInit {
        candidate: format!(
            "candidate:7 1 udp 2130706431 {} {} typ host",
            new_host.ip(),
            new_host.port()
        ),
        ..Default::default()
    })?;
    let events = announced(&mut world, 1);

    let answer = world.peers[1].pc.create_answer(None)?;
    let ufrag = sdp_value(&answer.sdp, "a=ice-ufrag:");
    assert_eq!(ufrag.len(), 1, "{}", answer.sdp);
    let ufrag = ufrag[0].clone();
    // Both are announced, as the new generation's.
    for port in ["10.0.0.2 5000", "10.0.0.2 5001"] {
        assert!(
            events
                .iter()
                .any(|(c, u)| c.contains(port) && u.as_deref() == Some(ufrag.as_str())),
            "{port} announced with the answer's ufrag {ufrag}: {events:?}"
        );
    }
    // The answer lists both, and so does the local description it becomes.
    world.peers[1]
        .pc
        .set_local_description(now, answer.clone())?;
    let local = world.peers[1]
        .pc
        .local_description()
        .expect("the answer")
        .sdp;
    for sdp in [&answer.sdp, &local] {
        let candidates = sdp_value(sdp, "a=candidate:");
        for port in ["10.0.0.2 5000", "10.0.0.2 5001"] {
            assert!(
                candidates.iter().any(|c| c.contains(port)),
                "{port} listed: {candidates:?}"
            );
        }
    }

    // The offerer takes the answerer's candidates from the answer; it trickles its own. The
    // answerer's application adds nothing after `set_local_description`: the new generation
    // selects a pair and data flows on it.
    world.peers[0].pc.set_remote_description(now, answer)?;
    let offerer = world.peers[0].candidate()?;
    world.peers[0].pc.add_local_candidate(offerer.clone())?;
    world.peers[1].pc.add_remote_candidate(offerer)?;
    let selected_before = selected_pair_changes(&world);
    world.run("the new generation selects a pair", |peers| {
        peers
            .iter()
            .zip(&selected_before)
            .all(|(peer, before)| selected_pair_changes_of(peer) > *before)
    })?;
    world.ping_pong("the restart selected its pair")?;
    Ok(())
}

fn selected_pair_changes_of(peer: &Peer) -> usize {
    peer.events
        .iter()
        .filter(|e| e.starts_with("OnSelectedCandidatePairChange"))
        .count()
}

fn selected_pair_changes(world: &World) -> Vec<usize> {
    world.peers.iter().map(selected_pair_changes_of).collect()
}

/// With `with_discard_local_candidates_during_ice_restart(true)`: the candidates given
/// between the restart offer and the answer survive the restart and are in the answer.
#[test]
fn a_restart_answer_that_discards_keeps_and_lists_the_candidates_given_after_the_offer()
-> Result<()> {
    restart_answer_keeps_candidates_given_before_it(true)
}

/// The default (the restart keeps the local candidates): a candidate new to the agent given
/// in the same window is announced and listed too, not refused for the nomination of the
/// session the restart ends.
#[test]
fn a_restart_answer_lists_a_new_candidate_given_after_the_offer() -> Result<()> {
    restart_answer_keeps_candidates_given_before_it(false)
}

/// The offerer's side of the same rule: candidates it adds between `create_offer` of its
/// restart offer and `set_local_description` of it are announced with the offer's ufrag and
/// kept by the restart, with `with_discard_local_candidates_during_ice_restart(true)`; the
/// application trickles what was announced, and the new generation selects a pair.
#[test]
fn a_restart_offerer_that_discards_keeps_the_candidates_given_before_applying_the_offer()
-> Result<()> {
    let mut world = World::new(
        Peer::new(
            "10.0.0.1:5000",
            SettingEngineBuilder::new()
                .with_discard_local_candidates_during_ice_restart(true)
                .build(),
        )?,
        Peer::new("10.0.0.2:5000", SettingEngineBuilder::new().build())?,
    );
    world.connect()?;
    world.ping_pong("connected")?;
    let _ = announced(&mut world, 0);

    let now = world.now;
    world.peers[0].pc.restart_ice();
    let offer = world.peers[0].pc.create_offer(None)?;
    let ufrag = sdp_value(&offer.sdp, "a=ice-ufrag:")[0].clone();
    let same = world.peers[0].candidate()?;
    world.peers[0].pc.add_local_candidate(same)?;
    let events = announced(&mut world, 0);
    assert!(
        events
            .iter()
            .any(|(c, u)| c.contains("10.0.0.1 5000") && u.as_deref() == Some(ufrag.as_str())),
        "announced with the offer's ufrag {ufrag}: {events:?}"
    );
    world.peers[0]
        .pc
        .set_local_description(now, offer.clone())?;
    world.peers[1].pc.set_remote_description(now, offer)?;
    let answer = world.peers[1].pc.create_answer(None)?;
    world.peers[1]
        .pc
        .set_local_description(now, answer.clone())?;
    world.peers[0].pc.set_remote_description(now, answer)?;
    // Each side trickles what its application was told; the offerer adds nothing again.
    let offerer = world.peers[0].candidate()?;
    world.peers[1].pc.add_remote_candidate(offerer)?;
    let answerer = world.peers[1].candidate()?;
    world.peers[1].pc.add_local_candidate(answerer.clone())?;
    world.peers[0].pc.add_remote_candidate(answerer)?;
    let selected_before = selected_pair_changes(&world);
    world.run("the new generation selects a pair", |peers| {
        peers
            .iter()
            .zip(&selected_before)
            .all(|(peer, before)| selected_pair_changes_of(peer) > *before)
    })?;
    world.ping_pong("the restart selected its pair")?;
    Ok(())
}
