//! webrtc-extensions section 7, candidate pairs the application sees and steers: each pair
//! the agent forms is announced (`icecandidatepairadd`) and listed; `selectCandidatePair`
//! makes a listed pair the selected one; `removeCandidatePair` stops the checks on one and
//! announces its removal (`icecandidatepairremove`); both refuse in the states the spec names
//! and for a pair that is not listed. An ICE restart removes every pair.

use std::sync::Arc;
use std::time::{Duration, Instant};

use sansio::Protocol;

use super::*;
use crate::candidate::candidate_host::CandidateHostConfig;

fn provider() -> Arc<dyn crypto::RTCCryptoProvider> {
    crypto::default_provider().expect("a built-in crypto provider must be enabled for tests")
}

const LOCAL: &str = "192.168.0.2:1000";
const REMOTE_A: &str = "192.168.0.3:2000";
const REMOTE_B: &str = "192.168.0.4:3000";

fn addr(s: &str) -> SocketAddr {
    s.parse().unwrap()
}

fn host(addr: SocketAddr) -> Candidate {
    CandidateHostConfig {
        base_config: CandidateConfig {
            network: "udp".to_owned(),
            address: addr.ip().to_string(),
            port: addr.port(),
            component: 1,
            ..Default::default()
        },
        ..Default::default()
    }
    .new_candidate_host()
    .unwrap()
}

/// A controlling agent with one local candidate and remote candidates A and B (distinct
/// foundations, so both pairs are checked).
fn agent(base: Instant) -> Agent {
    let config = AgentConfig {
        is_controlling: true,
        ..AgentConfig::default()
    };
    let mut a = Agent::new(base, Arc::new(config), provider()).unwrap();
    a.add_local_candidate(host(addr(LOCAL))).unwrap();
    for (address, foundation) in [(REMOTE_A, "a"), (REMOTE_B, "b")] {
        let mut c = host(addr(address));
        c.foundation_override = foundation.to_owned();
        a.add_remote_candidate(c).unwrap();
    }
    a.set_remote_credentials("remoteufrag".to_owned(), "remotepwd".to_owned())
        .unwrap();
    a
}

/// Both pairs checked and valid, the agent checking.
fn checked(mut a: Agent) -> Agent {
    for (index, p) in a.candidate_pairs.iter_mut().enumerate() {
        p.state = CandidatePairState::Succeeded;
        p.valid = true;
        p.valid_pair = Some(index);
    }
    a.connection_state = ConnectionState::Checking;
    a
}

/// The pair events, as ("add" | "remove", remote address), and the selected-pair changes as
/// ("select", remote address), in order.
fn pair_events(a: &mut Agent) -> Vec<(&'static str, SocketAddr)> {
    let mut out = vec![];
    while let Some(e) = a.poll_event() {
        match e.event {
            Event::CandidatePairAdded(_, remote) => out.push(("add", remote.addr())),
            Event::CandidatePairRemoved(_, remote) => out.push(("remove", remote.addr())),
            Event::SelectedCandidatePairChange(_, remote) => out.push(("select", remote.addr())),
            _ => {}
        }
    }
    out
}

fn listed(a: &Agent) -> Vec<SocketAddr> {
    a.get_candidate_pairs()
        .into_iter()
        .map(|(_, remote)| remote.addr())
        .collect()
}

fn remote_candidate(a: &Agent, address: &str) -> (Candidate, Candidate) {
    a.get_candidate_pairs()
        .into_iter()
        .find(|(_, remote)| remote.addr() == addr(address))
        .expect("a listed pair")
}

#[test]
fn test_every_pair_the_agent_forms_is_announced_and_listed() {
    let mut a = agent(Instant::now());
    assert_eq!(
        pair_events(&mut a),
        [("add", addr(REMOTE_A)), ("add", addr(REMOTE_B))]
    );
    assert_eq!(listed(&a), [addr(REMOTE_A), addr(REMOTE_B)]);
}

#[test]
fn test_select_and_remove_refuse_in_the_new_failed_and_closed_states_and_unknown_pairs() {
    let now = Instant::now();
    let mut a = agent(now);
    let (local, remote) = remote_candidate(&a, REMOTE_A);
    assert_eq!(a.connection_state, ConnectionState::New);
    assert!(matches!(
        a.select_candidate_pair(now, &local, &remote),
        Err(Error::InvalidStateError)
    ));
    assert!(matches!(
        a.remove_candidate_pair(now, &local, &remote),
        Err(Error::InvalidStateError)
    ));

    let mut a = checked(agent(now));
    let stranger = host(addr("192.168.0.9:9000"));
    assert!(matches!(
        a.select_candidate_pair(now, &local, &stranger),
        Err(Error::NotFoundError)
    ));
    assert!(matches!(
        a.remove_candidate_pair(now, &stranger, &remote),
        Err(Error::NotFoundError)
    ));

    a.connection_state = ConnectionState::Failed;
    assert!(matches!(
        a.select_candidate_pair(now, &local, &remote),
        Err(Error::InvalidStateError)
    ));
    a.connection_state = ConnectionState::Checking;
    a.close().unwrap();
    assert!(matches!(
        a.remove_candidate_pair(now, &local, &remote),
        Err(Error::InvalidStateError)
    ));
}

#[test]
fn test_select_candidate_pair_makes_the_pair_the_selected_one() {
    let now = Instant::now();
    let mut a = checked(agent(now));
    pair_events(&mut a);
    let (local, remote) = remote_candidate(&a, REMOTE_B);
    a.select_candidate_pair(now, &local, &remote).unwrap();
    assert_eq!(
        a.get_selected_candidate_pair().map(|(_, r)| r.addr()),
        Some(addr(REMOTE_B))
    );
    assert_eq!(a.state(), ConnectionState::Connected);
    assert_eq!(pair_events(&mut a), [("select", addr(REMOTE_B))]);

    let (local, remote) = remote_candidate(&a, REMOTE_A);
    a.select_candidate_pair(now, &local, &remote).unwrap();
    assert_eq!(
        a.get_selected_candidate_pair().map(|(_, r)| r.addr()),
        Some(addr(REMOTE_A))
    );
    assert_eq!(pair_events(&mut a), [("select", addr(REMOTE_A))]);
    // Data goes to the pair the application selected.
    assert_eq!(a.media_path().map(|p| p.peer_addr), Some(addr(REMOTE_A)));
}

#[test]
fn test_remove_candidate_pair_stops_its_checks_and_announces_the_removal() {
    let now = Instant::now();
    let mut a = agent(now);
    a.connection_state = ConnectionState::Checking;
    pair_events(&mut a);
    let (local, remote) = remote_candidate(&a, REMOTE_A);
    a.remove_candidate_pair(now, &local, &remote).unwrap();
    assert_eq!(pair_events(&mut a), [("remove", addr(REMOTE_A))]);
    assert_eq!(listed(&a), [addr(REMOTE_B)]);
    assert!(matches!(
        a.remove_candidate_pair(now, &local, &remote),
        Err(Error::NotFoundError)
    ));
    assert_eq!(a.get_candidate_pairs_stats(now).len(), 1);

    // The checks go to B only.
    let mut destinations = vec![];
    let mut t = now;
    for _ in 0..20 {
        t += Duration::from_millis(50);
        a.handle_timeout(t).unwrap();
        while let Some(datagram) = a.poll_write() {
            destinations.push(datagram.transport.peer_addr);
        }
    }
    assert!(destinations.contains(&addr(REMOTE_B)), "{destinations:?}");
    assert!(
        !destinations.contains(&addr(REMOTE_A)),
        "no check on a removed pair: {destinations:?}"
    );
    // A triggered check for the removed pair is not queued either.
    let index = a
        .candidate_pairs
        .iter()
        .position(|p| p.removed)
        .expect("the removed pair keeps its slot");
    a.trigger_check(index);
    assert!(!a.candidate_pairs[index].triggered);
}

#[test]
fn test_removing_the_selected_pair_selects_the_best_other_valid_one() {
    let now = Instant::now();
    let mut a = checked(agent(now));
    let (local, remote) = remote_candidate(&a, REMOTE_A);
    a.select_candidate_pair(now, &local, &remote).unwrap();
    pair_events(&mut a);
    a.remove_candidate_pair(now, &local, &remote).unwrap();
    assert_eq!(
        pair_events(&mut a),
        [("remove", addr(REMOTE_A)), ("select", addr(REMOTE_B))]
    );
    assert_eq!(
        a.get_selected_candidate_pair().map(|(_, r)| r.addr()),
        Some(addr(REMOTE_B))
    );
}

#[test]
fn test_an_ice_restart_removes_every_pair() {
    let now = Instant::now();
    let mut a = checked(agent(now));
    pair_events(&mut a);
    a.generate_restart_credentials(String::new(), String::new())
        .unwrap();
    a.apply_restart(now, true).unwrap();
    assert_eq!(
        pair_events(&mut a),
        [("remove", addr(REMOTE_A)), ("remove", addr(REMOTE_B))]
    );
    assert!(a.get_candidate_pairs().is_empty());
}
