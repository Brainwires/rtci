//! RFC 8839 sections 4.4.1.3 and 4.4.3 (subsequent offers and the answers to them, full and
//! lite agents) and RFC 9429 section 5.1.1 (peers of RFC 5245 ICE), between two `rtci` peers on
//! an in-memory network in virtual time.

mod dtls_sdp_common;

use std::collections::BTreeMap;
use std::time::Duration;

use anyhow::Result;
use dtls_sdp_common::{Peer, World, attribute_values, keep, replace_lines};
use rtci::peer_connection::configuration::setting_engine::SettingEngineBuilder;
use rtci::peer_connection::transport::{RTCIceCandidatePair, RTCIceTransportState};
use rtci::statistics::StatsSelector;
use rtci::statistics::stats::ice_candidate_pair::RTCStatsIceCandidatePairState;

const A: &str = "10.0.0.1:5000";
const B: &str = "10.0.0.2:5000";

fn full() -> rtci::peer_connection::configuration::setting_engine::SettingEngine {
    SettingEngineBuilder::new().build()
}

fn lite() -> rtci::peer_connection::configuration::setting_engine::SettingEngine {
    SettingEngineBuilder::new().with_lite(true).build()
}

/// Each candidate pair of a peer, by its (local, remote) candidate ids: its state, whether it
/// is nominated, and the checks sent on it.
fn pairs(
    world: &mut World,
    peer: usize,
) -> BTreeMap<(String, String), (RTCStatsIceCandidatePairState, bool, u64)> {
    let now = world.now;
    world.peers[peer]
        .pc
        .get_stats(now, StatsSelector::None)
        .candidate_pairs()
        .map(|p| {
            (
                (p.local_candidate_id.clone(), p.remote_candidate_id.clone()),
                (p.state, p.nominated, p.requests_sent),
            )
        })
        .collect()
}

fn ice_state(peer: &Peer) -> RTCIceTransportState {
    peer.pc
        .sctp()
        .expect("the data channel's transport")
        .transport()
        .ice_transport()
        .state()
}

fn selected(peer: &Peer) -> Option<RTCIceCandidatePair> {
    peer.pc
        .sctp()
        .expect("the data channel's transport")
        .transport()
        .ice_transport()
        .get_selected_candidate_pair()
}

/// The events a peer raised since `from` that change or remove a candidate pair.
fn pair_changes(peer: &Peer, from: usize) -> Vec<String> {
    peer.events[from..]
        .iter()
        .filter(|e| {
            e.starts_with("OnSelectedCandidatePairChange")
                || e.starts_with("OnIceCandidatePairRemove")
        })
        .cloned()
        .collect()
}

/// RFC 8839 section 4.4.3.1: "If the checklist state associated with a data stream is
/// Running, the agent recomputes the checklist. If a pair on the new checklist was also on the
/// previous checklist, its candidate pair state is copied over." The checks run with the
/// network cut, so every pair is still being checked; a subsequent offer and its answer (with
/// the same credentials and candidates) leave each pair as it was, on both sides, and once the
/// network is back the checks the pairs already had complete them.
#[test]
fn pairs_that_stay_on_a_running_checklist_keep_their_state() -> Result<()> {
    let mut world = World::new(Peer::new(A, full())?, Peer::new(B, full())?);
    world.peers[0].pc.create_data_channel("data", None)?;
    world.exchange(0)?;
    world.trickle()?;
    world.connected = false;
    world.run_for(Duration::from_millis(300), |_| false);
    let before = [pairs(&mut world, 0), pairs(&mut world, 1)];
    for (peer, pairs) in before.iter().enumerate() {
        assert!(!pairs.is_empty(), "peer {peer} has pairs");
        assert!(
            pairs.values().any(|(_, _, sent)| *sent > 0),
            "peer {peer} checked a pair: {pairs:?}"
        );
        assert!(
            pairs
                .values()
                .all(|(state, _, _)| *state != RTCStatsIceCandidatePairState::Succeeded),
            "peer {peer}: the checklist is still running: {pairs:?}"
        );
    }
    let events = [world.peers[0].events.len(), world.peers[1].events.len()];

    let (offer, answer) = world.exchange(0)?;
    assert!(offer.contains("a=candidate:"), "{offer}");
    assert!(answer.contains("a=candidate:"), "{answer}");
    for (peer, before) in before.iter().enumerate() {
        assert_eq!(&pairs(&mut world, peer), before, "peer {peer}");
    }
    // Nothing of the checklist was removed meanwhile (the events are collected as the peers
    // run, so a short run with the network still cut shows them).
    world.run_for(Duration::from_millis(10), |_| false);
    for (peer, from) in events.iter().enumerate() {
        assert!(
            !pair_changes(&world.peers[peer], *from)
                .iter()
                .any(|e| e.starts_with("OnIceCandidatePairRemove")),
            "peer {peer}: {:?}",
            &world.peers[peer].events[*from..]
        );
    }

    world.connected = true;
    world.run("connected after the subsequent exchange", |peers| {
        peers.iter().all(|p| p.connected() && p.channel.is_some())
    })?;
    world.ping_pong("after the subsequent exchange")?;
    Ok(())
}

/// RFC 8839 section 4.4.3.1: "If the ICE state is Completed, and the SDP answer conforms to
/// Section 4.4.2, the agent MUST remain in the Completed ICE state" (RFC 8445 Completed: a pair
/// is selected). After the connection, a subsequent exchange each way keeps the selected pair
/// on both sides: no pair is removed or changed, it stays succeeded and nominated, the ICE
/// transport stays connected, and data flows.
#[test]
fn a_completed_checklist_stays_completed_through_a_conforming_answer() -> Result<()> {
    let mut world = World::new(Peer::new(A, full())?, Peer::new(B, full())?);
    world.connect()?;
    let selected_before: Vec<_> = world.peers.iter().map(selected).collect();
    assert!(selected_before.iter().all(Option::is_some));
    let states: Vec<_> = world.peers.iter().map(ice_state).collect();
    let events = [world.peers[0].events.len(), world.peers[1].events.len()];

    world.exchange(0)?;
    world.exchange(1)?;
    world.run_for(Duration::from_secs(2), |_| false);
    for peer in 0..2 {
        assert_eq!(
            selected(&world.peers[peer]),
            selected_before[peer],
            "peer {peer}"
        );
        assert_eq!(ice_state(&world.peers[peer]), states[peer], "peer {peer}");
        assert_eq!(
            pair_changes(&world.peers[peer], events[peer]),
            Vec::<String>::new()
        );
        let pairs = pairs(&mut world, peer);
        assert!(
            pairs.values().any(|(state, nominated, _)| *nominated
                && *state == RTCStatsIceCandidatePairState::Succeeded),
            "peer {peer}: {pairs:?}"
        );
    }
    world.ping_pong("after the subsequent exchanges")?;
    Ok(())
}

/// RFC 8839 section 4.4.1.3: "If the ICE state is Running, a lite implementation MUST include
/// all of its candidates for each component of each data stream in 'candidate' attributes in
/// any subsequent offer", and "MUST NOT modify the username fragments and passwords". The lite
/// answerer of the first exchange offers next: its offer lists its candidate (component 1) and
/// keeps its credentials, says `a=ice-lite`, and the session goes on.
#[test]
fn a_lite_agents_subsequent_offer_lists_its_candidates_and_keeps_its_credentials() -> Result<()> {
    let mut world = World::new(Peer::new(A, full())?, Peer::new(B, lite())?);
    let (_, answer) = world.connect()?;
    let (offer, _) = world.exchange(1)?;
    assert!(offer.contains("a=ice-lite"), "{offer}");
    let address = B.split(':').next().expect("an address");
    let candidates = attribute_values(&offer, "candidate");
    assert!(
        candidates
            .iter()
            .any(|c| c.split_whitespace().nth(1) == Some("1") && c.contains(address)),
        "the offer lists the lite agent's candidate: {candidates:?}\n{offer}"
    );
    for key in ["ice-ufrag", "ice-pwd"] {
        assert_eq!(
            attribute_values(&offer, key)[0],
            attribute_values(&answer, key)[0],
            "{key}"
        );
    }
    world.ping_pong("after the lite agent's offer")?;
    Ok(())
}

/// RFC 8839 section 4.4.3.2: when a lite agent's offer restarts ICE, "the agent MUST create a
/// new valid list ... remember the nominated pair in the previous valid list ... and continue
/// to send media there", and "the ICE state MUST be set to Running". The lite peer restarts:
/// once its restart is applied it has no selected pair (a new, empty valid list) while data
/// still flows on the previous pair; when the new generation's candidates arrive,
/// a pair is selected again and data flows on it.
#[test]
fn a_lite_agents_restart_starts_a_new_valid_list_and_keeps_sending_on_the_old_pair() -> Result<()> {
    let mut world = World::new(Peer::new(A, full())?, Peer::new(B, lite())?);
    let (_, first_answer) = world.connect()?;
    assert!(selected(&world.peers[1]).is_some());

    let before = world.peers[1].events.len();
    world.peers[1].pc.restart_ice();
    let (offer, _) = world.exchange(1)?;
    assert_ne!(
        attribute_values(&offer, "ice-ufrag")[0],
        attribute_values(&first_answer, "ice-ufrag")[0],
        "the offer restarts ICE"
    );
    assert_eq!(selected(&world.peers[1]), None, "the valid list is new");
    world.ping_pong("data on the previous pair")?;
    // The previous checklist's pairs are gone (webrtc-extensions `icecandidatepairremove`;
    // the events are collected while the peers run).
    assert!(
        pair_changes(&world.peers[1], before)
            .iter()
            .any(|e| e.starts_with("OnIceCandidatePairRemove")),
        "{:?}",
        &world.peers[1].events[before..]
    );

    world.trickle()?;
    world.run("a pair of the new generation", |peers| {
        peers.iter().all(|p| p.connected()) && selected(&peers[1]).is_some()
    })?;
    world.ping_pong("data on the new pair")?;
    Ok(())
}

/// RFC 9429 section 5.1.1: "remote endpoints that ... implement [RFC5245] ... MUST be
/// handled". A peer of RFC 5245 ICE does not say `ice2` (RFC 8445 section 10 introduced the
/// option): with every `ice2` taken out of the descriptions each way, the two peers connect and
/// carry data, also across a later exchange.
#[test]
fn a_peer_that_does_not_say_ice2_is_handled() -> Result<()> {
    let without_ice2 = |sdp: &str| -> String {
        let options = attribute_values(sdp, "ice-options");
        let mut out = sdp.to_owned();
        for value in options {
            let kept: Vec<&str> = value.split_whitespace().filter(|o| *o != "ice2").collect();
            let line = format!("a=ice-options:{value}");
            out = if kept.is_empty() {
                replace_lines(&out, &line, None)
            } else {
                replace_lines(
                    &out,
                    &line,
                    Some(&format!("a=ice-options:{}", kept.join(" "))),
                )
            };
        }
        assert!(!out.contains("ice2"), "{out}");
        out
    };
    let mut world = World::new(Peer::new(A, full())?, Peer::new(B, full())?);
    world.peers[0].pc.create_data_channel("data", None)?;
    world.exchange_with(0, keep, without_ice2)?;
    world.trickle()?;
    world.run("connected to a peer without ice2", |peers| {
        peers.iter().all(|p| p.connected() && p.channel.is_some())
    })?;
    world.ping_pong("without ice2")?;
    world.exchange_with(0, keep, without_ice2)?;
    world.run_for(Duration::from_secs(2), |_| false);
    world.ping_pong("without ice2, after a later exchange")?;
    Ok(())
}

/// RFC 8839 section 4.4.1.1.1: an offer that restarts ICE "MUST" change both `ice-ufrag` and
/// `ice-pwd`; section 4.4.2.1: so does the answer to it. Both peers pin their credentials
/// (`with_ice_credentials`): a restart still gets new ones on each side, both the fragment and
/// the password, and the session reconnects over them.
#[test]
fn a_restart_changes_pinned_credentials_on_both_sides() -> Result<()> {
    let pinned = |ufrag: &str| {
        SettingEngineBuilder::new()
            .with_ice_credentials(ufrag.to_owned(), format!("{ufrag}passwordpassword1234"))
            .build()
    };
    let mut world = World::new(Peer::new(A, pinned("aaaa"))?, Peer::new(B, pinned("bbbb"))?);
    let (offer, answer) = world.connect()?;
    assert_eq!(attribute_values(&offer, "ice-ufrag")[0], "aaaa", "{offer}");
    assert_eq!(
        attribute_values(&answer, "ice-ufrag")[0],
        "bbbb",
        "{answer}"
    );

    world.peers[0].pc.restart_ice();
    let (restart_offer, restart_answer) = world.exchange(0)?;
    for (first, restart) in [(&offer, &restart_offer), (&answer, &restart_answer)] {
        for key in ["ice-ufrag", "ice-pwd"] {
            assert_ne!(
                attribute_values(restart, key)[0],
                attribute_values(first, key)[0],
                "{key} after the restart:\n{restart}"
            );
        }
    }
    world.trickle()?;
    world.run("a pair of the new generation", |peers| {
        peers.iter().all(|p| p.connected())
    })?;
    world.run_for(Duration::from_secs(3), |_| false);
    world.ping_pong("after the restart")?;
    Ok(())
}

/// RFC 8839 section 4.2.4: an agent "MUST be prepared to receive" Binding requests on its
/// candidates once they are in an offer or answer; RFC 8445 section 7.3: a request that
/// arrives before the peer's credentials "MUST immediately" be answered. The offerer applies
/// its offer and gathers; the answerer applies it, answers, and checks the offerer's
/// candidate at once. Before the answer reaches the offerer, the offerer's ICE agent answers
/// the checks with its own credentials, so the answerer's pair succeeds; once the answer
/// arrives the connection completes.
#[test]
fn an_offerer_answers_checks_that_arrive_before_the_answer() -> Result<()> {
    use rtci::peer_connection::sdp::RTCSessionDescription;
    let mut world = World::new(Peer::new(A, full())?, Peer::new(B, full())?);
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
    // Each peer has its host candidate; the answerer has the offerer's. The offerer, which
    // has no remote description yet, has none of the answerer's.
    let offerer_candidate = world.peers[0].candidate()?;
    world.peers[0]
        .pc
        .add_local_candidate(offerer_candidate.clone())?;
    let answerer_candidate = world.peers[1].candidate()?;
    world.peers[1]
        .pc
        .add_local_candidate(answerer_candidate.clone())?;
    world.peers[1].pc.add_remote_candidate(offerer_candidate)?;
    world.run_for(Duration::from_millis(500), |_| false);
    let answerer = pairs(&mut world, 1);
    assert!(
        answerer
            .values()
            .any(|(state, _, _)| *state == RTCStatsIceCandidatePairState::Succeeded),
        "the offerer answered the answerer's checks before it had the answer: {answerer:?}"
    );
    let now = world.now;
    world.peers[0]
        .pc
        .set_remote_description(now, RTCSessionDescription::answer(answer.sdp)?)?;
    world.peers[0].pc.add_remote_candidate(answerer_candidate)?;
    world.run("connected once the answer arrived", |peers| {
        peers.iter().all(|p| p.connected() && p.channel.is_some())
    })?;
    Ok(())
}
