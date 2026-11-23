//! RFC 8838 rows of the agent: a local candidate is paired only once it has been conveyed to
//! the peer (Section 10), and candidates are paired in the order they are conveyed (Section
//! 17). Read from the wire in virtual time, as the other agent tests.

use std::sync::Arc;
use std::time::{Duration, Instant};

use super::agent_rfc8445_test::*;
use super::*;

/// An agent with the peer's credentials and its candidate `REMOTE_A`, and no local candidate.
fn agent_without_local_candidates(now: Instant, config: AgentConfig) -> Agent {
    let mut a = Agent::new(now, Arc::new(config), provider()).unwrap();
    a.add_remote_candidate(host(addr(REMOTE_A))).unwrap();
    a.start_connectivity_checks(now, true, REMOTE_UFRAG.to_owned(), REMOTE_PWD.to_owned())
        .unwrap();
    a
}

/// Section 10, item 1: "A Trickle ICE agent MUST NOT pair a local candidate until it has been
/// trickled to the remote party." Items 2 and 3: once conveyed, it is paired with the remote
/// candidates known.
#[test]
fn test_unconveyed_local_candidate_is_paired_and_checked_only_once_conveyed() {
    let now = Instant::now();
    let mut a = agent_without_local_candidates(now, config(true));
    let local = host(addr(LOCAL));
    let id = local.id().to_owned();
    assert!(a.add_unconveyed_local_candidate(local).unwrap());
    assert!(a.is_local_candidate_unconveyed(&id));
    assert!(a.get_candidate_pairs().is_empty(), "paired before conveyed");
    let later = now + Duration::from_secs(2);
    assert!(
        requests(&run(&mut a, now, later)).is_empty(),
        "a check left on an unconveyed candidate"
    );
    // The candidate is still one to signal.
    assert_eq!(a.get_local_candidates_to_signal().len(), 1);

    assert!(a.local_candidate_conveyed(&id));
    assert!(!a.is_local_candidate_unconveyed(&id));
    assert!(!a.local_candidate_conveyed(&id), "conveyed once");
    assert_eq!(a.get_candidate_pairs().len(), 1);
    let out = run(&mut a, later, later + Duration::from_secs(1));
    assert!(
        requests(&out).iter().any(|(_, to)| *to == addr(REMOTE_A)),
        "the conveyed candidate is checked"
    );
}

/// A remote candidate that arrives while a local candidate is held is not paired with it
/// either; `all_local_candidates_conveyed` (a description listing them was set) pairs them.
#[test]
fn test_remote_candidate_waits_for_the_held_local_candidate_to_be_conveyed() {
    let now = Instant::now();
    let cfg = AgentConfig {
        hold_local_candidates_until_conveyed: true,
        ..config(true)
    };
    let mut a = Agent::new(now, Arc::new(cfg), provider()).unwrap();
    // With the setting, `add_local_candidate` holds the candidate too.
    a.add_local_candidate(host(addr(LOCAL))).unwrap();
    a.start_connectivity_checks(now, true, REMOTE_UFRAG.to_owned(), REMOTE_PWD.to_owned())
        .unwrap();
    a.add_remote_candidate(host(addr(REMOTE_A))).unwrap();
    a.add_remote_candidate(host(addr(REMOTE_B))).unwrap();
    assert!(a.get_candidate_pairs().is_empty());
    assert!(requests(&run(&mut a, now, now + Duration::from_secs(1))).is_empty());

    a.all_local_candidates_conveyed();
    assert_eq!(a.get_candidate_pairs().len(), 2);
}

/// Section 17: "an agent SHOULD pair candidates in the order in which they are conveyed":
/// two local candidates conveyed in the opposite order of their gathering are paired (and
/// their pairs listed) in the order conveyed.
#[test]
fn test_local_candidates_are_paired_in_the_order_they_are_conveyed() {
    let now = Instant::now();
    let mut a = agent_without_local_candidates(now, config(true));
    let first = host(addr("192.168.0.2:1000"));
    let second = host(addr("192.168.0.2:1001"));
    let (first_id, second_id) = (first.id().to_owned(), second.id().to_owned());
    a.add_unconveyed_local_candidate(first).unwrap();
    a.add_unconveyed_local_candidate(second).unwrap();
    assert!(a.local_candidate_conveyed(&second_id));
    let pairs = a.get_candidate_pairs();
    assert_eq!(pairs.len(), 1);
    assert_eq!(pairs[0].0.port(), 1001);
    assert!(a.local_candidate_conveyed(&first_id));
    let ports: Vec<u16> = a.get_candidate_pairs().iter().map(|p| p.0.port()).collect();
    assert_eq!(ports, vec![1001, 1000]);
}

// --- RFC 8445 Section 5.2: a lite agent's local preferences ---

fn lite_with(now: Instant, network_types: Vec<NetworkType>) -> Agent {
    let cfg = AgentConfig {
        lite: true,
        candidate_types: vec![CandidateType::Host],
        network_types,
        ..config(false)
    };
    Agent::new(now, Arc::new(cfg), provider()).unwrap()
}

/// Section 5.2: "If an ICE lite agent is dual-stack or IPv6-only, the local preference SHOULD
/// be set to the precedence value for IP addresses described in [RFC 6724]": a global IPv6
/// address (40) before IPv4 (35) before a unique-local one (3), whatever the order they are
/// added in, and every priority unique. An IPv4-only lite agent keeps 65535.
#[test]
fn test_dual_stack_lite_agent_takes_local_preference_from_rfc6724_precedence() {
    let now = Instant::now();
    let mut a = lite_with(now, vec![NetworkType::Udp4, NetworkType::Udp6]);
    for address in [
        "[fd00::1]:1000",
        "192.168.0.2:1000",
        "[2a01:4f8::1]:1000",
        "[2a01:4f8::2]:1000",
    ] {
        assert!(a.add_local_candidate(host(addr(address))).unwrap());
    }
    let priority = |ip: &str| {
        a.get_local_candidates()
            .iter()
            .find(|c| c.addr().ip().to_string() == ip)
            .unwrap()
            .priority()
    };
    let local_preference = |p: u32| (p >> 8) & 0xffff;
    assert_eq!(local_preference(priority("2a01:4f8::1")) >> 8, 40);
    assert_eq!(local_preference(priority("192.168.0.2")) >> 8, 35);
    assert_eq!(local_preference(priority("fd00::1")) >> 8, 3);
    assert!(priority("2a01:4f8::1") > priority("192.168.0.2"));
    assert!(priority("192.168.0.2") > priority("fd00::1"));
    assert_ne!(priority("2a01:4f8::1"), priority("2a01:4f8::2"));

    let mut v4 = lite_with(now, vec![NetworkType::Udp4]);
    v4.add_local_candidate(host(addr("192.168.0.2:1000")))
        .unwrap();
    assert_eq!(
        local_preference(v4.get_local_candidates()[0].priority()),
        65535
    );
}
