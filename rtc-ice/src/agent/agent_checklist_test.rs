//! The checklist of RFC 8445 (pair states, pruning, the pair limit, Ta, the triggered-check
//! queue, STUN transactions, the valid list, nomination, checklist states) and what RFC 8838
//! adds to it, read from the wire in virtual time.

use std::time::{Duration, Instant};

use sansio::Protocol;
use stun::attributes::ATTR_USE_CANDIDATE;
use stun::error_code::CODE_BAD_REQUEST;

use super::agent_rfc8445_test::*;
use super::agent_selector::ChecklistState;
use super::*;
use crate::attributes::control::{AttrControlled, AttrControlling};
use crate::attributes::priority::PriorityAttr;
use crate::attributes::use_candidate::UseCandidateAttr;
use crate::candidate::candidate_host::CandidateHostConfig;

const MS: Duration = Duration::from_millis(1);

/// One datagram the agent sent: when, the decoded message, where to, the raw bytes.
struct Sent {
    at: Duration,
    message: Message,
    to: SocketAddr,
    raw: Vec<u8>,
}

/// What the peer does with a request: nothing, a success response reporting `mapped` as the
/// source it saw, or an error response.
enum Answer {
    Silence,
    Success(SocketAddr),
    Error(stun::error_code::ErrorCode),
}

/// Runs the agent from `start + from` to `start + until`, waking it only when it asks to be,
/// and returns what it sent (times relative to `start`). Each Binding request gets `answer`'s
/// reply, from its destination, at once.
fn run_with(
    a: &mut Agent,
    start: Instant,
    from: Duration,
    until: Duration,
    mut answer: impl FnMut(&Sent) -> Answer,
) -> Vec<Sent> {
    let mut out = vec![];
    let mut now = start + from;
    loop {
        a.handle_timeout(now).unwrap();
        while let Some(t) = a.poll_write() {
            let mut message = Message {
                raw: t.message.to_vec(),
                ..Message::default()
            };
            message.decode().unwrap();
            let sent = Sent {
                at: t.now.duration_since(start),
                message,
                to: t.transport.peer_addr,
                raw: t.message.to_vec(),
            };
            if sent.message.typ == BINDING_REQUEST {
                let id = sent.message.transaction_id;
                let reply = match answer(&sent) {
                    Answer::Silence => None,
                    Answer::Success(mapped) => {
                        Some(peer_response(BINDING_SUCCESS, id, mapped, None))
                    }
                    Answer::Error(code) => {
                        Some(peer_response(BINDING_ERROR, id, addr(LOCAL), Some(code)))
                    }
                };
                if let Some(reply) = reply {
                    let _ = deliver(a, now, &reply, &sent.to.to_string());
                }
            }
            out.push(sent);
        }
        match a.poll_timeout() {
            Some(next) if next <= start + until => now = next.max(now + Duration::from_micros(1)),
            _ => return out,
        }
    }
}

fn silent(a: &mut Agent, start: Instant, from: Duration, until: Duration) -> Vec<Sent> {
    run_with(a, start, from, until, |_| Answer::Silence)
}

fn answered(a: &mut Agent, start: Instant, from: Duration, until: Duration) -> Vec<Sent> {
    run_with(a, start, from, until, |_| Answer::Success(addr(LOCAL)))
}

fn requests_of(sent: &[Sent]) -> Vec<&Sent> {
    sent.iter()
        .filter(|s| s.message.typ == BINDING_REQUEST)
        .collect()
}

/// The first transmission of each transaction, in the order they were started.
fn checks_started(sent: &[Sent]) -> Vec<&Sent> {
    let mut seen = vec![];
    requests_of(sent)
        .into_iter()
        .filter(|s| {
            let new = !seen.contains(&s.message.transaction_id);
            seen.push(s.message.transaction_id);
            new
        })
        .collect()
}

/// A remote host candidate at `10.0.0.<n>:5000` with the given priority and foundation.
fn remote(n: u8, priority: u32, foundation: &str) -> Candidate {
    CandidateHostConfig {
        base_config: CandidateConfig {
            network: "udp".to_owned(),
            address: format!("10.0.0.{n}"),
            port: 5000,
            component: 1,
            priority,
            foundation: foundation.to_owned(),
            ..Default::default()
        },
        ..Default::default()
    }
    .new_candidate_host()
    .unwrap()
}

fn remote_addr(n: u8) -> SocketAddr {
    format!("10.0.0.{n}:5000").parse().unwrap()
}

/// A checking agent with one local candidate and the remote candidates `(n, priority)`, each
/// with a foundation of its own, added in the order given. It never times out of checking.
fn agent_with(start: Instant, cfg: AgentConfig, remotes: &[(u8, u32)]) -> Agent {
    let controlling = cfg.is_controlling;
    let mut a = bare_agent(
        start,
        AgentConfig {
            failed_timeout: Some(Duration::ZERO),
            ..cfg
        },
    );
    for (n, priority) in remotes {
        a.add_remote_candidate(remote(*n, *priority, &format!("f{n}")))
            .unwrap();
    }
    a.start_connectivity_checks(
        start,
        controlling,
        REMOTE_UFRAG.to_owned(),
        REMOTE_PWD.to_owned(),
    )
    .unwrap();
    a
}

fn state_of(a: &Agent, n: u8) -> CandidatePairState {
    let remote_index = a.find_remote_candidate(remote_addr(n)).unwrap();
    a.candidate_pairs[a.find_pair(0, remote_index).unwrap()].state
}

fn states(a: &mut Agent) -> Vec<ConnectionState> {
    std::iter::from_fn(|| a.poll_event())
        .filter_map(|e| match e.event {
            Event::ConnectionStateChange(s) => Some(s),
            _ => None,
        })
        .collect()
}

// --- Sections 6.1.2.3, 6.1.4.2, 14.2: order and pacing ---

/// Section 6.1.4.2: one check per Ta (50 ms by default, Section 14.2), the highest-priority
/// Waiting pair first (the checklist is ordered by pair priority, Section 6.1.2.3), whatever
/// order the candidates arrived in.
#[test]
fn test_checks_are_started_one_per_ta_in_priority_order() {
    let start = Instant::now();
    let mut a = agent_with(
        start,
        config(true),
        &[(3, 300), (1, 500), (5, 100), (2, 400), (4, 200)],
    );
    let out = silent(&mut a, start, Duration::ZERO, 450 * MS);
    let started = checks_started(&out);
    assert_eq!(started.len(), 5);
    assert_eq!(
        started.iter().map(|s| s.to).collect::<Vec<_>>(),
        (1..=5).map(remote_addr).collect::<Vec<_>>(),
        "decreasing pair priority"
    );
    assert_eq!(
        started.iter().map(|s| s.at).collect::<Vec<_>>(),
        (0..5).map(|i| 50 * MS * i).collect::<Vec<_>>(),
        "one check per Ta, none sooner"
    );
    // Nothing else left in the first 450 ms: no retransmission before the RTO.
    assert_eq!(requests_of(&out).len(), 5);
}

/// Section 14.2: Ta is configurable, and never under 5 ms.
#[test]
fn test_ta_is_configurable_and_at_least_five_milliseconds() {
    for (configured, effective) in [(20 * MS, 20 * MS), (MS, 5 * MS)] {
        let start = Instant::now();
        let cfg = AgentConfig {
            ta: Some(configured),
            ..config(false)
        };
        let mut a = agent_with(start, cfg, &[(1, 500), (2, 400), (3, 300)]);
        let out = silent(&mut a, start, Duration::ZERO, 400 * MS);
        let started = checks_started(&out);
        assert_eq!(
            started.iter().map(|s| s.at).collect::<Vec<_>>(),
            vec![Duration::ZERO, effective, effective * 2]
        );
    }
}

/// RFC 8838 Section 8: a checklist without pairs is no reason to send anything.
#[test]
fn test_empty_checklist_sends_nothing() {
    let start = Instant::now();
    let mut a = agent_with(start, config(true), &[]);
    assert!(silent(&mut a, start, Duration::ZERO, Duration::from_secs(5)).is_empty());
    assert_eq!(a.state(), ConnectionState::Checking);
}

// --- Section 14.3 and RFC 8489 Section 6.2.1: the transaction behind a check ---

/// An unanswered check is one STUN transaction: the same request (same transaction id, same
/// bytes) is retransmitted after RTO, 2 RTO, 4 RTO, ... (RTO is 500 ms at least), seven
/// requests in all, and the pair fails 16 RTO after the last one (Section 7.2.5.2.3).
#[test]
fn test_unanswered_check_is_retransmitted_with_backoff_and_then_fails_the_pair() {
    let start = Instant::now();
    let mut a = agent_with(start, config(true), &[(1, 500)]);
    let out = silent(&mut a, start, Duration::ZERO, 39_499 * MS);

    let requests = requests_of(&out);
    assert_eq!(
        requests.iter().map(|s| s.at).collect::<Vec<_>>(),
        [0u32, 500, 1500, 3500, 7500, 15500, 31500]
            .map(|ms| MS * ms)
            .to_vec()
    );
    assert!(
        requests.iter().all(|s| s.raw == requests[0].raw),
        "a retransmission is the same message"
    );
    assert_eq!(state_of(&a, 1), CandidatePairState::InProgress);

    silent(&mut a, start, 39_499 * MS, 39_500 * MS);
    assert_eq!(state_of(&a, 1), CandidatePairState::Failed);
    assert!(a.pending_binding_requests.is_empty());
    // A failed pair is not checked again on the agent's own initiative.
    assert!(silent(&mut a, start, 39_500 * MS, Duration::from_secs(80)).is_empty());
}

/// Section 14.3: RTO = MAX(500 ms, Ta * (pairs Waiting + In-Progress)), taken when the check
/// starts: with 20 pairs to check the first one's is a second.
#[test]
fn test_rto_follows_the_number_of_pairs_still_to_check() {
    let start = Instant::now();
    let remotes: Vec<(u8, u32)> = (1..=20).map(|n| (n, 1000 - u32::from(n))).collect();
    let mut a = agent_with(start, config(true), &remotes);
    let out = silent(&mut a, start, Duration::ZERO, 1500 * MS);
    let to_first: Vec<Duration> = requests_of(&out)
        .iter()
        .filter(|s| s.to == remote_addr(1))
        .map(|s| s.at)
        .collect();
    assert_eq!(to_first, vec![Duration::ZERO, 1000 * MS]);
    // In-Progress pairs count as well as Waiting ones: the eleventh, started at 500 ms with
    // all twenty still unanswered, gets a second too.
    let to_eleventh: Vec<Duration> = requests_of(&out)
        .iter()
        .filter(|s| s.to == remote_addr(11))
        .map(|s| s.at)
        .collect();
    assert_eq!(to_eleventh, vec![500 * MS, 1500 * MS]);
}

/// `max_binding_requests` is Rc: with one request the pair fails 16 RTO later.
#[test]
fn test_request_count_of_a_transaction_is_configurable() {
    let start = Instant::now();
    let cfg = AgentConfig {
        max_binding_requests: Some(1),
        ..config(true)
    };
    let mut a = agent_with(start, cfg, &[(1, 500)]);
    let out = silent(&mut a, start, Duration::ZERO, 8 * Duration::from_secs(1));
    assert_eq!(requests_of(&out).len(), 1);
    assert_eq!(state_of(&a, 1), CandidatePairState::Failed);
}

/// RFC 6544 Section 7.1: over TCP a check is sent once (the transport retransmits) and the
/// transaction waits Ti, 39.5 s.
#[test]
fn test_check_over_tcp_is_sent_once() {
    let start = Instant::now();
    let tcp = |address: &str, port: u16, tcp_type: TcpType| {
        CandidateHostConfig {
            base_config: CandidateConfig {
                network: "tcp".to_owned(),
                address: address.to_owned(),
                port,
                component: 1,
                ..Default::default()
            },
            tcp_type,
        }
        .new_candidate_host()
        .unwrap()
    };
    let cfg = AgentConfig {
        failed_timeout: Some(Duration::ZERO),
        ..config(true)
    };
    let mut a = Agent::new(start, Arc::new(cfg), provider()).unwrap();
    a.add_local_candidate(tcp("192.168.0.2", 9, TcpType::Active))
        .unwrap();
    a.add_remote_candidate(tcp("10.0.0.1", 5000, TcpType::Passive))
        .unwrap();
    a.start_connectivity_checks(start, true, REMOTE_UFRAG.to_owned(), REMOTE_PWD.to_owned())
        .unwrap();
    let out = silent(&mut a, start, Duration::ZERO, 39_499 * MS);
    assert_eq!(requests_of(&out).len(), 1);
    assert_eq!(a.candidate_pairs[0].state, CandidatePairState::InProgress);
    silent(&mut a, start, 39_499 * MS, 39_500 * MS);
    assert_eq!(a.candidate_pairs[0].state, CandidatePairState::Failed);
}

// --- Sections 6.1.2.6, 6.1.4.2, 7.2.5.3.3 and RFC 8838 Section 12: Frozen ---

/// Section 6.1.2.6: of the pairs with one foundation exactly one starts Waiting, the one with
/// the highest priority; the others are Frozen and are not checked while it is in progress.
/// Section 7.2.5.3.3: when it succeeds they become Waiting.
#[test]
fn test_pairs_of_one_foundation_wait_for_the_first_to_succeed() {
    let start = Instant::now();
    let mut a = bare_agent(
        start,
        AgentConfig {
            failed_timeout: Some(Duration::ZERO),
            ..config(false)
        },
    );
    a.add_remote_candidate(remote(2, 400, "shared")).unwrap();
    a.add_remote_candidate(remote(1, 500, "shared")).unwrap();
    a.add_remote_candidate(remote(3, 300, "shared")).unwrap();
    a.add_remote_candidate(remote(4, 100, "other")).unwrap();
    a.start_connectivity_checks(start, false, REMOTE_UFRAG.to_owned(), REMOTE_PWD.to_owned())
        .unwrap();
    assert_eq!(state_of(&a, 1), CandidatePairState::Waiting);
    assert_eq!(state_of(&a, 2), CandidatePairState::Frozen);
    assert_eq!(state_of(&a, 3), CandidatePairState::Frozen);
    assert_eq!(state_of(&a, 4), CandidatePairState::Waiting);

    // Nobody answers for 400 ms: only the two Waiting pairs are checked.
    let out = silent(&mut a, start, Duration::ZERO, 400 * MS);
    assert_eq!(
        checks_started(&out)
            .iter()
            .map(|s| s.to)
            .collect::<Vec<_>>(),
        vec![remote_addr(1), remote_addr(4)]
    );
    assert_eq!(state_of(&a, 2), CandidatePairState::Frozen);

    // The retransmission to 1 (at 500 ms) is answered: its foundation is unfrozen.
    let out = run_with(&mut a, start, 400 * MS, 700 * MS, |s| {
        if s.to == remote_addr(1) {
            Answer::Success(addr(LOCAL))
        } else {
            Answer::Silence
        }
    });
    assert_eq!(state_of(&a, 1), CandidatePairState::Succeeded);
    let started: Vec<SocketAddr> = checks_started(&out)
        .iter()
        .map(|s| s.to)
        .filter(|to| *to == remote_addr(2) || *to == remote_addr(3))
        .collect();
    assert_eq!(started, vec![remote_addr(2), remote_addr(3)]);
}

/// Section 6.1.4.2, step 2: with no pair Waiting, a Frozen pair whose foundation has nothing
/// Waiting or In-Progress is unfrozen, here because the pair ahead of it failed.
#[test]
fn test_frozen_pair_is_unfrozen_when_its_foundation_has_nothing_in_flight() {
    let start = Instant::now();
    let mut a = bare_agent(
        start,
        AgentConfig {
            failed_timeout: Some(Duration::ZERO),
            ..config(false)
        },
    );
    a.add_remote_candidate(remote(1, 500, "shared")).unwrap();
    a.add_remote_candidate(remote(2, 400, "shared")).unwrap();
    a.start_connectivity_checks(start, false, REMOTE_UFRAG.to_owned(), REMOTE_PWD.to_owned())
        .unwrap();
    assert_eq!(state_of(&a, 2), CandidatePairState::Frozen);

    let out = run_with(&mut a, start, Duration::ZERO, 200 * MS, |s| {
        if s.to == remote_addr(1) {
            Answer::Error(CODE_BAD_REQUEST)
        } else {
            Answer::Silence
        }
    });
    assert_eq!(state_of(&a, 1), CandidatePairState::Failed);
    let started = checks_started(&out);
    assert_eq!(
        started.iter().map(|s| s.to).collect::<Vec<_>>(),
        vec![remote_addr(1), remote_addr(2)]
    );
    assert_eq!(started[1].at, 50 * MS, "at the next Ta");
}

/// RFC 8838 Section 12, a pair formed while checks run: Waiting when it is the best of its
/// foundation (rule 1) or a pair of its foundation has succeeded (rule 2), Frozen otherwise
/// (rule 3).
#[test]
fn test_trickled_pair_starts_in_the_state_its_foundation_gives_it() {
    let start = Instant::now();
    let mut a = agent_with(start, config(false), &[]);
    a.add_remote_candidate(remote(1, 500, "shared")).unwrap();
    assert_eq!(state_of(&a, 1), CandidatePairState::Waiting, "rule 1");
    a.add_remote_candidate(remote(2, 400, "shared")).unwrap();
    assert_eq!(state_of(&a, 2), CandidatePairState::Frozen, "rule 3");
    a.add_remote_candidate(remote(3, 600, "shared")).unwrap();
    assert_eq!(state_of(&a, 3), CandidatePairState::Waiting, "rule 1");

    run_with(&mut a, start, Duration::ZERO, 20 * MS, |_| {
        Answer::Success(addr(LOCAL))
    });
    assert_eq!(state_of(&a, 3), CandidatePairState::Succeeded);
    a.add_remote_candidate(remote(4, 100, "shared")).unwrap();
    assert_eq!(state_of(&a, 4), CandidatePairState::Waiting, "rule 2");
}

// --- Sections 5.1.3, 6.1.2.2, 6.1.2.4, 6.1.2.5: which pairs exist ---

fn srflx(address: &str, port: u16, base: SocketAddr) -> Candidate {
    crate::candidate::candidate_server_reflexive::CandidateServerReflexiveConfig {
        base_config: CandidateConfig {
            network: "udp".to_owned(),
            address: address.to_owned(),
            port,
            component: 1,
            ..Default::default()
        },
        rel_addr: base.ip().to_string(),
        rel_port: base.port(),
        url: None,
    }
    .new_candidate_server_reflexive()
    .unwrap()
}

/// Section 6.1.2.4: a server-reflexive local candidate stands for its base, so its pair with
/// a remote candidate is redundant with the host candidate's and is pruned: one pair, one
/// check from the socket, whichever candidate came first.
#[test]
fn test_server_reflexive_pair_is_pruned_for_its_base() {
    for srflx_first in [false, true] {
        let start = Instant::now();
        let cfg = AgentConfig {
            failed_timeout: Some(Duration::ZERO),
            ..config(true)
        };
        let mut a = Agent::new(start, Arc::new(cfg), provider()).unwrap();
        let reflexive = srflx("203.0.113.5", 4000, addr(LOCAL));
        if srflx_first {
            a.add_local_candidate(reflexive).unwrap();
            a.add_remote_candidate(remote(1, 500, "f1")).unwrap();
            a.add_local_candidate(host(addr(LOCAL))).unwrap();
        } else {
            a.add_local_candidate(host(addr(LOCAL))).unwrap();
            a.add_local_candidate(reflexive).unwrap();
            a.add_remote_candidate(remote(1, 500, "f1")).unwrap();
        }
        assert_eq!(a.local_candidates.len(), 2);
        assert_eq!(a.candidate_pairs.len(), 1, "srflx first: {srflx_first}");
        let pair = a.candidate_pairs[0];
        assert_eq!(
            a.local_candidates[pair.local_index].candidate_type(),
            CandidateType::Host,
            "the higher-priority pair stays"
        );

        a.start_connectivity_checks(start, true, REMOTE_UFRAG.to_owned(), REMOTE_PWD.to_owned())
            .unwrap();
        let out = silent(&mut a, start, Duration::ZERO, 400 * MS);
        assert_eq!(
            requests_of(&out).len(),
            1,
            "one check, not one per candidate"
        );
    }
}

/// Section 5.1.3: a candidate whose address and base equal another's is redundant and is not
/// kept: a server-reflexive candidate equal to its host candidate (no NAT), a relayed
/// candidate identical to a host candidate (Section 5.1.1.2).
#[test]
fn test_redundant_local_candidates_are_not_kept() {
    let mut a = Agent::new(Instant::now(), Arc::new(config(true)), provider()).unwrap();
    let local = addr(LOCAL);
    assert!(a.add_local_candidate(host(local)).unwrap());
    assert!(
        !a.add_local_candidate(srflx(&local.ip().to_string(), local.port(), local))
            .unwrap()
    );
    let relay = crate::candidate::candidate_relay::CandidateRelayConfig {
        base_config: CandidateConfig {
            network: "udp".to_owned(),
            address: local.ip().to_string(),
            port: local.port(),
            component: 1,
            ..Default::default()
        },
        rel_addr: "0.0.0.0".to_owned(),
        rel_port: 0,
        url: None,
    }
    .new_candidate_relay()
    .unwrap();
    assert!(!a.add_local_candidate(relay).unwrap());
    // A real mapping is another transport address: kept.
    assert!(
        a.add_local_candidate(srflx("203.0.113.5", 4000, local))
            .unwrap()
    );
    assert_eq!(a.local_candidates.len(), 2);
}

/// Section 6.1.2.2: candidates are paired only within a component. The agent has the RTP
/// component alone, so a candidate the peer signals for RTCP (pion and webrtc-rs signal every
/// candidate for both components, on the same address) is not held, and does not keep the RTP
/// candidate with that address out, whichever of the two arrives or resolves first.
#[test]
fn test_candidates_of_another_component_are_ignored() {
    let mut a = bare_agent(Instant::now(), config(true));
    let mut rtcp = remote(1, 500, "f1");
    rtcp.set_component(2);
    assert!(!a.add_remote_candidate(rtcp).unwrap());
    assert!(a.remote_candidates.is_empty());
    assert!(a.candidate_pairs.is_empty());
    // The RTP candidate on the same address is taken and paired.
    assert!(a.add_remote_candidate(remote(1, 500, "f1")).unwrap());
    assert_eq!(a.candidate_pairs.len(), 1);

    // The same for names: of an RTCP and an RTP candidate behind one mDNS name, only the RTP
    // one is resolved.
    let named = |component: u16| {
        let mut c = CandidateHostConfig {
            base_config: CandidateConfig {
                network: "udp".to_owned(),
                address: "9b36eaac-bb2e-49bb-bb78-21c41c499900.local".to_owned(),
                port: 5000,
                component: 1,
                ..Default::default()
            },
            ..Default::default()
        }
        .new_candidate_host()
        .unwrap();
        c.set_component(component);
        c
    };
    let cfg = AgentConfig {
        multicast_dns_mode: crate::mdns::MulticastDnsMode::QueryOnly,
        ..config(true)
    };
    let mut a = bare_agent(Instant::now(), cfg);
    a.add_remote_candidate(named(2)).unwrap();
    assert!(a.mdns_queries.is_empty());
    a.add_remote_candidate(named(1)).unwrap();
    assert_eq!(a.mdns_queries.len(), 1);
}

/// Section 6.1.2.5: the checklist holds 100 pairs by default, the limit is configurable, and
/// when it is full a better pair takes the place of the worst one that has not been checked
/// (RFC 8838 Section 11: of a Failed one first).
#[test]
fn test_checklist_is_limited_to_100_pairs_and_keeps_the_best() {
    let start = Instant::now();
    let mut a = bare_agent(start, config(true));
    for n in 1..=120u8 {
        a.add_remote_candidate(remote(n, 1000 + u32::from(n), &format!("f{n}")))
            .unwrap();
    }
    assert_eq!(a.candidate_pairs.len(), 100);
    let lowest = a
        .candidate_pairs
        .iter()
        .map(|p| p.remote_priority)
        .min()
        .unwrap();
    assert_eq!(lowest, 1021, "the 100 highest-priority pairs");

    // Configured: 3 pairs. A worse pair is dropped; a Failed pair gives way to any new one.
    let cfg = AgentConfig {
        max_candidate_pairs: Some(3),
        ..config(true)
    };
    let mut a = bare_agent(start, cfg);
    for n in [5u8, 6, 7] {
        a.add_remote_candidate(remote(n, 1000 + u32::from(n), &format!("f{n}")))
            .unwrap();
    }
    a.add_remote_candidate(remote(1, 1001, "f1")).unwrap();
    assert_eq!(a.candidate_pairs.len(), 3);
    assert!(a.find_pair(0, 3).is_none(), "a worse pair does not get in");
    let failed = a
        .find_pair(0, a.find_remote_candidate(remote_addr(7)).unwrap())
        .unwrap();
    a.candidate_pairs[failed].state = CandidatePairState::Failed;
    a.add_remote_candidate(remote(2, 1002, "f2")).unwrap();
    assert_eq!(a.candidate_pairs.len(), 3);
    let priorities: Vec<u32> = a
        .candidate_pairs
        .iter()
        .map(|p| p.remote_priority)
        .collect();
    assert!(priorities.contains(&1002) && !priorities.contains(&1007));
}

// --- Sections 6.1.4.1, 7.3.1.4: the triggered-check queue ---

/// Sections 6.1.4.1 and 6.1.4.2: a request from the peer puts its pair on the triggered-check
/// queue, which is served, first in first out, before the ordinary checks, one check per Ta.
#[test]
fn test_triggered_checks_go_first_in_arrival_order() {
    let start = Instant::now();
    let mut a = agent_with(
        start,
        config(false),
        &[(1, 500), (2, 400), (3, 300), (4, 200), (5, 100)],
    );
    // The first check (to 1) has gone; 2 would be next.
    let out = silent(&mut a, start, Duration::ZERO, 10 * MS);
    assert_eq!(checks_started(&out).len(), 1);

    let from = |n: u8| format!("10.0.0.{n}:5000");
    for n in [5u8, 4] {
        let request = peer_request(
            &a,
            vec![Box::new(AttrControlling(1)), Box::new(PriorityAttr(1000))],
        );
        deliver(&mut a, start + 20 * MS, &request, &from(n)).unwrap();
    }
    assert_eq!(state_of(&a, 5), CandidatePairState::Waiting);
    assert_eq!(a.triggered_queue.len(), 2);

    let out = silent(&mut a, start, 20 * MS, 260 * MS);
    let started = checks_started(&out);
    assert_eq!(
        started.iter().map(|s| s.to).collect::<Vec<_>>(),
        [5u8, 4, 2, 3].map(remote_addr).to_vec()
    );
    assert_eq!(
        started.iter().map(|s| s.at).collect::<Vec<_>>(),
        [50u32, 100, 150, 200].map(|ms| MS * ms).to_vec(),
        "triggered checks are paced by Ta as well"
    );
}

/// Section 7.3.1.4: a request on a pair whose check is In-Progress cancels that transaction
/// (no more retransmissions, no failure) and triggers a new check; a late response to the
/// cancelled transaction is still taken.
#[test]
fn test_request_on_an_in_progress_pair_cancels_the_transaction_and_checks_again() {
    let start = Instant::now();
    let mut a = agent_with(start, config(false), &[(1, 500)]);
    let out = silent(&mut a, start, Duration::ZERO, 100 * MS);
    let first = checks_started(&out)[0].message.transaction_id;
    assert_eq!(state_of(&a, 1), CandidatePairState::InProgress);

    let request = peer_request(
        &a,
        vec![Box::new(AttrControlling(1)), Box::new(PriorityAttr(1000))],
    );
    deliver(&mut a, start + 100 * MS, &request, "10.0.0.1:5000").unwrap();
    assert_eq!(state_of(&a, 1), CandidatePairState::Waiting);

    let out = silent(&mut a, start, 100 * MS, 3000 * MS);
    let ids: Vec<TransactionId> = requests_of(&out)
        .iter()
        .map(|s| s.message.transaction_id)
        .collect();
    assert!(!ids.is_empty());
    assert!(
        !ids.contains(&first),
        "the cancelled transaction is not retransmitted"
    );
    assert_eq!(
        requests_of(&out)[0].at,
        100 * MS,
        "the new check leaves at once"
    );

    // The answer to the first request arrives after all.
    let response = peer_response(BINDING_SUCCESS, first, addr(LOCAL), None);
    deliver(&mut a, start + 3000 * MS, &response, "10.0.0.1:5000").unwrap();
    assert_eq!(state_of(&a, 1), CandidatePairState::Succeeded);
    // And the second transaction, now moot, does not fail the pair when it runs out.
    silent(&mut a, start, 3000 * MS, Duration::from_secs(60));
    assert_eq!(state_of(&a, 1), CandidatePairState::Succeeded);
}

/// Section 7.3.1.4: the pair of a request is (the local candidate it arrived on, its source),
/// and that local candidate is never a server-reflexive one, also when the server-reflexive
/// candidate was added first.
#[test]
fn test_request_is_credited_to_the_host_candidate_not_its_reflexive_one() {
    let start = Instant::now();
    let mut a = Agent::new(start, Arc::new(config(false)), provider()).unwrap();
    a.add_local_candidate(srflx("203.0.113.5", 4000, addr(LOCAL)))
        .unwrap();
    a.add_local_candidate(host(addr(LOCAL))).unwrap();
    a.start_connectivity_checks(start, false, REMOTE_UFRAG.to_owned(), REMOTE_PWD.to_owned())
        .unwrap();
    let request = peer_request(
        &a,
        vec![Box::new(AttrControlling(1)), Box::new(PriorityAttr(1000))],
    );
    deliver(&mut a, start, &request, REMOTE_A).unwrap();
    assert_eq!(a.candidate_pairs.len(), 1);
    let local = &a.local_candidates[a.candidate_pairs[0].local_index];
    assert_eq!(local.candidate_type(), CandidateType::Host);
}

// --- Section 7.2.5: responses ---

/// Section 7.2.5.2.1: the response must come from where the request went. One that carries
/// the right transaction id and the peer's signature but another source fails the pair.
#[test]
fn test_response_from_another_source_fails_the_pair() {
    let start = Instant::now();
    let mut a = agent_with(start, config(true), &[(1, 500), (2, 400)]);
    let out = silent(&mut a, start, Duration::ZERO, 10 * MS);
    let check = checks_started(&out)[0];
    assert_eq!(check.to, remote_addr(1));
    let response = peer_response(
        BINDING_SUCCESS,
        check.message.transaction_id,
        addr(LOCAL),
        None,
    );
    deliver(&mut a, start + 10 * MS, &response, "10.0.0.2:5000").unwrap();
    assert_eq!(state_of(&a, 1), CandidatePairState::Failed);
    assert_ne!(state_of(&a, 2), CandidatePairState::Succeeded);
    assert!(a.remote_candidates[1].last_consent().is_none());
}

/// Section 7.2.5.2.1: ... and must arrive where the request left from. A response on another
/// local candidate fails the pair instead of being credited to that candidate's pair.
#[test]
fn test_response_on_another_local_candidate_fails_the_pair() {
    let start = Instant::now();
    let other_local = "192.168.0.9:1000";
    let cfg = AgentConfig {
        failed_timeout: Some(Duration::ZERO),
        ..config(true)
    };
    let mut a = bare_agent(start, cfg);
    a.add_local_candidate(host(addr(other_local))).unwrap();
    a.add_remote_candidate(remote(1, 500, "f1")).unwrap();
    a.start_connectivity_checks(start, true, REMOTE_UFRAG.to_owned(), REMOTE_PWD.to_owned())
        .unwrap();
    let out = silent(&mut a, start, Duration::ZERO, 10 * MS);
    let check = checks_started(&out)[0];
    let sent_pair = a.find_pair_exact(0, 0).unwrap();
    let other_pair = a.find_pair_exact(1, 0).unwrap();
    assert_eq!(
        a.candidate_pairs[sent_pair].state,
        CandidatePairState::InProgress
    );

    let response = peer_response(
        BINDING_SUCCESS,
        check.message.transaction_id,
        addr(LOCAL),
        None,
    );
    a.handle_read(TaggedBytesMut {
        now: start + 10 * MS,
        transport: TransportContext {
            local_addr: addr(other_local),
            peer_addr: remote_addr(1),
            ecn: None,
            transport_protocol: TransportProtocol::UDP,
        },
        message: BytesMut::from(&response.raw[..]),
    })
    .unwrap();
    assert_eq!(
        a.candidate_pairs[sent_pair].state,
        CandidatePairState::Failed
    );
    assert_ne!(
        a.candidate_pairs[other_pair].state,
        CandidatePairState::Succeeded
    );
}

/// Sections 7.2.5.3.1 and 7.2.5.3.2: a mapped address that is no local candidate is a new
/// local peer-reflexive candidate (base: the candidate the request left from; priority: the
/// request's PRIORITY), and the valid pair is (that candidate, the request's destination).
/// The pair that was checked and the valid pair are both Succeeded; the valid pair is the one
/// nominated and selected, and data leaves from its base. The learned candidate is not one to
/// signal.
#[test]
fn test_mapped_address_makes_a_local_peer_reflexive_candidate_and_the_valid_pair() {
    let start = Instant::now();
    let mapped: SocketAddr = "203.0.113.5:4000".parse().unwrap();
    let mut a = agent_with(start, config(true), &[(1, 500)]);
    run_with(&mut a, start, Duration::ZERO, 300 * MS, |_| {
        Answer::Success(mapped)
    });

    assert_eq!(a.local_candidates.len(), 2);
    let learned = &a.local_candidates[1];
    assert_eq!(learned.candidate_type(), CandidateType::PeerReflexive);
    assert_eq!(learned.addr(), mapped);
    assert_eq!(learned.base_addr(), addr(LOCAL));
    assert_eq!(
        learned.priority(),
        1862270975,
        "the PRIORITY the request carried"
    );
    assert_eq!(a.get_local_candidates_to_signal().len(), 1);

    assert_eq!(a.candidate_pairs.len(), 2);
    let checked = a.candidate_pairs[a.find_pair_exact(0, 0).unwrap()];
    let valid = a.candidate_pairs[a.find_pair_exact(1, 0).unwrap()];
    assert_eq!(checked.state, CandidatePairState::Succeeded);
    assert!(!checked.valid, "the valid list holds the constructed pair");
    assert_eq!(valid.state, CandidatePairState::Succeeded);
    assert!(valid.valid && valid.nominated);

    let (local, remote) = a.get_selected_candidate_pair().unwrap();
    assert_eq!(local.addr(), mapped);
    assert_eq!(remote.addr(), remote_addr(1));
    let path = a.media_path().unwrap();
    assert_eq!(path.local_addr, addr(LOCAL));
    assert_eq!(path.peer_addr, remote_addr(1));

    // An ICE restart that keeps the local candidates does not keep the learned one.
    a.restart(
        start + Duration::from_secs(1),
        String::new(),
        String::new(),
        true,
    )
    .unwrap();
    assert_eq!(a.local_candidates.len(), 1);
}

/// Section 7.2.5.3.2: when the mapped address is a local candidate the agent knows (its
/// server-reflexive one), the valid pair is that candidate's, and no candidate is made.
#[test]
fn test_mapped_address_of_a_known_candidate_makes_its_pair_valid() {
    let start = Instant::now();
    let cfg = AgentConfig {
        failed_timeout: Some(Duration::ZERO),
        ..config(false)
    };
    let mut a = bare_agent(start, cfg);
    a.add_local_candidate(srflx("203.0.113.5", 4000, addr(LOCAL)))
        .unwrap();
    a.add_remote_candidate(remote(1, 500, "f1")).unwrap();
    a.start_connectivity_checks(start, false, REMOTE_UFRAG.to_owned(), REMOTE_PWD.to_owned())
        .unwrap();
    run_with(&mut a, start, Duration::ZERO, 100 * MS, |_| {
        Answer::Success("203.0.113.5:4000".parse().unwrap())
    });
    assert_eq!(a.local_candidates.len(), 2, "no new candidate");
    let valid = a.candidate_pairs[a.find_pair_exact(1, 0).expect("the srflx pair")];
    assert!(valid.valid);
    assert_eq!(valid.state, CandidatePairState::Succeeded);
    assert_eq!(
        a.candidate_pairs[a.find_pair_exact(0, 0).unwrap()].valid_pair,
        a.find_pair_exact(1, 0)
    );
}

// --- Section 8: nomination, checklist and ICE states ---

/// Section 8.1.1: the controlling agent nominates one pair, with one transaction, and no
/// other afterwards. Section 8.1.2: from then on the checklist is Completed, the other pairs'
/// transactions are cancelled and no ordinary check is started; only consent checks go out.
#[test]
fn test_controlling_agent_nominates_once_and_the_checklist_completes() {
    let start = Instant::now();
    let mut a = agent_with(start, config(true), &[(1, 500), (2, 400), (3, 300)]);
    assert_eq!(a.checklist_state(), ChecklistState::Running);

    // 1 answers; 2 and 3 never do.
    let out = run_with(
        &mut a,
        start,
        Duration::ZERO,
        Duration::from_secs(60),
        |s| {
            if s.to == remote_addr(1) {
                Answer::Success(addr(LOCAL))
            } else {
                Answer::Silence
            }
        },
    );
    assert_eq!(a.checklist_state(), ChecklistState::Completed);
    assert_eq!(a.state(), ConnectionState::Connected);
    let (_, remote) = a.get_selected_candidate_pair().unwrap();
    assert_eq!(remote.addr(), remote_addr(1));

    let nominations: Vec<&Sent> = requests_of(&out)
        .into_iter()
        .filter(|s| s.message.contains(ATTR_USE_CANDIDATE))
        .collect();
    // One pair is nominated, with one request: the consent checks that follow are plain
    // Binding requests (RFC 8445 Section 7.1.2: USE-CANDIDATE is sent "in order to nominate").
    assert_eq!(nominations.len(), 1, "one nomination, one request");
    assert_eq!(nominations[0].to, remote_addr(1));
    let nominated_at = nominations[0].at;

    // After the nomination nothing more goes to 2 or 3: no ordinary check for 3, no
    // retransmission for 2, and neither is failed by a timeout.
    assert!(
        requests_of(&out)
            .iter()
            .all(|s| s.to == remote_addr(1) || s.at <= nominated_at),
    );
    assert_ne!(state_of(&a, 2), CandidatePairState::Failed);
    assert_ne!(state_of(&a, 3), CandidatePairState::Failed);
    // What goes to 1 afterwards are consent checks: at least 4 seconds apart.
    let later: Vec<Duration> = requests_of(&out)
        .iter()
        .filter(|s| s.at > nominated_at)
        .map(|s| s.at)
        .collect();
    assert!(later.len() >= 9);
    assert!(
        later
            .windows(2)
            .all(|w| w[1] - w[0] >= Duration::from_secs(4))
    );
}

/// Section 8.1.1: the nomination the controlling agent queued is sent, also when a second
/// success response for the same pair arrives before Ta starts it. Here the pair's first
/// check is cancelled by the peer's request (Section 7.3.1.4) and checked again, and both
/// transactions are answered: the first answer makes the pair valid and queues its
/// nomination, the second used to take the pair off the triggered-check queue as a check
/// done, so the nomination never left and the agent stayed in checking until its failed
/// timeout (seen against the `webrtc` 0.17 peer in `test_data_channel_create_rtc_to_webrtc`).
#[test]
fn test_a_second_success_response_does_not_drop_the_queued_nomination() {
    let start = Instant::now();
    let mut a = agent_with(start, config(true), &[(1, 500)]);
    let out = silent(&mut a, start, Duration::ZERO, 60 * MS);
    let first = checks_started(&out)[0].message.transaction_id;

    let request = peer_request(
        &a,
        vec![Box::new(AttrControlled(1)), Box::new(PriorityAttr(1000))],
    );
    deliver(&mut a, start + 60 * MS, &request, "10.0.0.1:5000").unwrap();
    let out = silent(&mut a, start, 60 * MS, 70 * MS);
    let second = checks_started(&out)
        .iter()
        .map(|s| s.message.transaction_id)
        .find(|id| *id != first)
        .expect("the triggered check");

    for (at, id) in [(71, first), (72, second)] {
        let response = peer_response(BINDING_SUCCESS, id, addr(LOCAL), None);
        deliver(&mut a, start + at * MS, &response, "10.0.0.1:5000").unwrap();
    }
    assert_eq!(state_of(&a, 1), CandidatePairState::Succeeded);

    let out = answered(&mut a, start, 72 * MS, Duration::from_secs(2));
    let nomination = requests_of(&out)
        .into_iter()
        .find(|s| s.message.contains(ATTR_USE_CANDIDATE))
        .expect("the nomination is sent");
    assert!(
        nomination.at <= 200 * MS,
        "the nomination leaves at the next Ta, not at {:?}",
        nomination.at
    );
    assert_eq!(a.state(), ConnectionState::Connected);
}

/// Consent checks are plain Binding requests (RFC 7675 Section 5.1; RFC 8445 Section 7.1.2
/// has USE-CANDIDATE sent to nominate, and "the controlled agent MUST NOT include" it).
/// `nominate_on_consent_checks` is libwebrtc's behaviour: the controlling agent's consent
/// checks carry USE-CANDIDATE. The controlled agent's never do.
#[test]
fn test_consent_checks_carry_use_candidate_only_when_set_to_and_controlling() {
    for (controlling, setting) in [(true, false), (true, true), (false, false), (false, true)] {
        let start = Instant::now();
        let cfg = AgentConfig {
            nominate_on_consent_checks: setting,
            ..config(controlling)
        };
        let mut a = agent_with(start, cfg, &[(1, 500)]);
        if !controlling {
            let nominate = peer_request(
                &a,
                vec![
                    Box::new(AttrControlling(1)),
                    Box::new(PriorityAttr(1000)),
                    Box::new(UseCandidateAttr::new()),
                ],
            );
            deliver(&mut a, start, &nominate, "10.0.0.1:5000").unwrap();
        }
        answered(&mut a, start, Duration::ZERO, Duration::from_secs(1));
        assert!(a.get_selected_candidate_pair().is_some());
        let out = answered(
            &mut a,
            start,
            Duration::from_secs(1),
            Duration::from_secs(20),
        );
        let consent = requests_of(&out);
        assert!(consent.len() >= 3);
        assert!(
            consent
                .iter()
                .all(|s| s.message.contains(ATTR_USE_CANDIDATE) == (controlling && setting)),
            "controlling: {controlling}, nominate_on_consent_checks: {setting}"
        );
        assert_eq!(a.state(), ConnectionState::Connected);
    }
}

/// When consent comes back the agent leaves `Disconnected` with the response, not at its
/// next consent check seconds later.
#[test]
fn test_agent_is_connected_again_as_soon_as_consent_returns() {
    let start = Instant::now();
    let mut a = agent_with(start, config(true), &[(1, 500)]);
    answered(&mut a, start, Duration::ZERO, Duration::from_secs(1));
    silent(
        &mut a,
        start,
        Duration::from_secs(1),
        Duration::from_secs(15),
    );
    assert_eq!(a.state(), ConnectionState::Disconnected);
    let _ = states(&mut a);
    // The next consent check is answered.
    let mut now = start + Duration::from_secs(15);
    let answered_at = loop {
        a.handle_timeout(now).unwrap();
        if let Some((m, to)) = sent(&mut a)
            .into_iter()
            .find(|(m, _)| m.typ == BINDING_REQUEST)
        {
            let response = peer_response(BINDING_SUCCESS, m.transaction_id, addr(LOCAL), None);
            deliver(&mut a, now, &response, &to.to_string()).unwrap();
            break now;
        }
        now = a
            .poll_timeout()
            .unwrap()
            .max(now + Duration::from_micros(1));
    };
    assert_eq!(a.poll_timeout().map(|t| t <= answered_at), Some(true));
    a.handle_timeout(answered_at).unwrap();
    assert_eq!(states(&mut a), vec![ConnectionState::Connected]);
}

/// The transport state is `Connected` once a pair is nominated and `Completed` once, in
/// addition, both sides have no more candidates to offer (W3C `RTCIceTransportState`); a
/// disconnected agent comes back to the state it had.
#[test]
fn test_completed_needs_a_nominated_pair_and_both_ends_of_candidates() {
    let start = Instant::now();
    let mut a = agent_with(start, config(true), &[(1, 500)]);
    a.set_local_gathering_complete();
    answered(&mut a, start, Duration::ZERO, Duration::from_secs(1));
    assert_eq!(
        states(&mut a),
        vec![ConnectionState::Checking, ConnectionState::Connected]
    );

    a.set_remote_end_of_candidates();
    answered(
        &mut a,
        start,
        Duration::from_secs(1),
        Duration::from_secs(2),
    );
    assert_eq!(states(&mut a), vec![ConnectionState::Completed]);
    assert_eq!(a.checklist_state(), ChecklistState::Completed);

    // Silence, then answers again.
    silent(
        &mut a,
        start,
        Duration::from_secs(2),
        Duration::from_secs(20),
    );
    assert_eq!(states(&mut a), vec![ConnectionState::Disconnected]);
    answered(
        &mut a,
        start,
        Duration::from_secs(20),
        Duration::from_secs(30),
    );
    assert_eq!(states(&mut a), vec![ConnectionState::Completed]);
}

/// Section 7.2.5.4 with RFC 8838 Sections 8 and 14: when every pair has failed and none is
/// valid the checklist is Failed, at once, provided no candidate is to come any more (local
/// gathering complete, end-of-candidates received). While candidates may still come it keeps
/// Running.
#[test]
fn test_checklist_fails_when_all_pairs_failed_and_no_candidate_is_to_come() {
    let start = Instant::now();
    let refuse = |_: &Sent| Answer::Error(CODE_BAD_REQUEST);

    // Candidates may still come: Running, with its one pair Failed.
    let mut a = started_agent(start, config(true), &[REMOTE_A]);
    run_with(
        &mut a,
        start,
        Duration::ZERO,
        Duration::from_secs(5),
        refuse,
    );
    assert_eq!(a.candidate_pairs[0].state, CandidatePairState::Failed);
    assert_eq!(a.state(), ConnectionState::Checking);
    assert_eq!(a.checklist_state(), ChecklistState::Running);

    // The same once both sides are done: Failed 5 seconds in, not after the 30 second timer.
    a.set_local_gathering_complete();
    a.set_remote_end_of_candidates();
    run_with(
        &mut a,
        start,
        Duration::from_secs(5),
        Duration::from_secs(5),
        refuse,
    );
    assert_eq!(a.state(), ConnectionState::Failed);
    assert_eq!(a.checklist_state(), ChecklistState::Failed);
    assert!(a.poll_timeout().is_none());

    // No pair at all and nothing to come: Failed at once.
    let mut a = started_agent(start, config(false), &[]);
    a.set_local_gathering_complete();
    silent(&mut a, start, Duration::ZERO, Duration::from_secs(1));
    assert_eq!(a.state(), ConnectionState::Checking);
    a.set_remote_end_of_candidates();
    silent(
        &mut a,
        start,
        Duration::from_secs(1),
        Duration::from_secs(1),
    );
    assert_eq!(a.state(), ConnectionState::Failed);
}

/// RFC 8838 Section 14: "After an agent has received an end-of-candidates indication, it MUST
/// ignore any newly received candidates". Section 13: no local candidate follows the local
/// indication either. An ICE restart starts over.
#[test]
fn test_candidates_after_end_of_candidates_are_ignored() {
    let start = Instant::now();
    let mut a = started_agent(start, config(true), &[REMOTE_A]);
    a.set_remote_end_of_candidates();
    assert!(!a.add_remote_candidate(host(addr(REMOTE_B))).unwrap());
    assert_eq!(a.remote_candidates.len(), 1);
    assert_eq!(a.candidate_pairs.len(), 1);

    a.set_local_gathering_complete();
    assert!(
        !a.add_local_candidate(host(addr("192.168.0.9:1000")))
            .unwrap()
    );
    assert_eq!(a.local_candidates.len(), 1);

    // A peer-reflexive candidate is not a signalled one: checks still teach them.
    let request = peer_request(
        &a,
        vec![Box::new(AttrControlled(1)), Box::new(PriorityAttr(1000))],
    );
    deliver(&mut a, start, &request, REMOTE_B).unwrap();
    assert_eq!(a.remote_candidates.len(), 2);

    a.restart(start, String::new(), String::new(), true)
        .unwrap();
    assert!(a.add_remote_candidate(host(addr(REMOTE_B))).unwrap());
    assert!(
        a.add_local_candidate(host(addr("192.168.0.9:1000")))
            .unwrap()
    );
}

/// RFC 8838 Section 11: a signalled candidate with the address of a peer-reflexive one the
/// agent learned from a check replaces it: one candidate, one pair, with the signalled
/// priority; not a second candidate whose pair could never succeed.
#[test]
fn test_signalled_candidate_replaces_the_peer_reflexive_one_it_duplicates() {
    let start = Instant::now();
    let mut a = started_agent(start, config(false), &[]);
    let request = peer_request(
        &a,
        vec![Box::new(AttrControlling(1)), Box::new(PriorityAttr(1000))],
    );
    deliver(&mut a, start, &request, REMOTE_A).unwrap();
    assert_eq!(
        a.remote_candidates[0].candidate_type(),
        CandidateType::PeerReflexive
    );
    answered(&mut a, start, Duration::ZERO, 100 * MS);
    assert_eq!(a.candidate_pairs[0].state, CandidatePairState::Succeeded);
    let id = a.remote_candidates[0].id().to_owned();

    assert!(
        a.add_remote_candidate(host_with_priority(addr(REMOTE_A), 2130706431))
            .unwrap()
    );
    // The pair keeps its identity (its statistics are keyed by the candidates' ids).
    assert_eq!(a.remote_candidates[0].id(), id);
    assert_eq!(a.remote_candidates.len(), 1);
    assert_eq!(a.remote_candidates[0].candidate_type(), CandidateType::Host);
    assert_eq!(a.remote_candidates[0].priority(), 2130706431);
    assert_eq!(a.candidate_pairs.len(), 1);
    assert_eq!(a.candidate_pairs[0].remote_priority, 2130706431);
    assert_eq!(a.candidate_pairs[0].state, CandidatePairState::Succeeded);
    // No check is spent on a duplicate.
    assert!(requests_of(&silent(&mut a, start, 100 * MS, 3000 * MS)).is_empty());
}

/// Section 7.3.1.5: the controlled agent's check that a nomination triggered fails: the pair
/// is Failed and the nomination with it. (By design the checklist keeps running while the
/// controlling agent can still nominate another pair.)
#[test]
fn test_controlled_nomination_dies_with_its_triggered_check() {
    let start = Instant::now();
    let cfg = AgentConfig {
        max_binding_requests: Some(2),
        ..config(false)
    };
    let mut a = agent_with(start, cfg, &[(1, 500), (2, 400)]);
    let nominate = peer_request(
        &a,
        vec![
            Box::new(AttrControlling(1)),
            Box::new(PriorityAttr(1000)),
            Box::new(UseCandidateAttr::new()),
        ],
    );
    deliver(&mut a, start, &nominate, "10.0.0.1:5000").unwrap();
    let pair = a.find_pair(0, 0).unwrap();
    assert!(a.candidate_pairs[pair].nomination_pending);

    // 1 never answers our checks; 2 does.
    run_with(
        &mut a,
        start,
        Duration::ZERO,
        Duration::from_secs(20),
        |s| {
            if s.to == remote_addr(2) {
                Answer::Success(addr(LOCAL))
            } else {
                Answer::Silence
            }
        },
    );
    assert_eq!(state_of(&a, 1), CandidatePairState::Failed);
    assert!(!a.candidate_pairs[pair].nomination_pending);
    assert!(a.get_selected_candidate_pair().is_none());
    assert_eq!(a.state(), ConnectionState::Checking);

    // The controlling agent nominates the pair that works.
    let nominate = peer_request(
        &a,
        vec![
            Box::new(AttrControlling(1)),
            Box::new(PriorityAttr(1000)),
            Box::new(UseCandidateAttr::new()),
        ],
    );
    deliver(
        &mut a,
        start + Duration::from_secs(20),
        &nominate,
        "10.0.0.2:5000",
    )
    .unwrap();
    assert_eq!(
        a.get_selected_candidate_pair().unwrap().1.addr(),
        remote_addr(2)
    );
}

/// RFC 7675 Section 5.1: a consent request waits for its response for a time based on the
/// round-trip time (four times the last one, 500 ms at least); a response after that is for
/// a transaction the agent no longer has and gives no consent.
#[test]
fn test_consent_response_is_awaited_for_a_time_based_on_the_rtt() {
    let start = Instant::now();
    let mut a = agent_with(start, config(true), &[(1, 500)]);
    answered(&mut a, start, Duration::ZERO, Duration::from_secs(1));
    assert!(a.get_selected_candidate_pair().is_some());
    let consent_before = a.remote_candidates[0].last_consent().unwrap();

    // The next two consent requests, unanswered for now.
    let mut consent: Vec<TransactionId> = vec![];
    let mut now = start + Duration::from_secs(1);
    loop {
        a.handle_timeout(now).unwrap();
        consent.extend(
            sent(&mut a)
                .iter()
                .filter(|(m, _)| m.typ == BINDING_REQUEST)
                .map(|(m, _)| m.transaction_id),
        );
        if consent.len() >= 2 {
            break;
        }
        now = a
            .poll_timeout()
            .unwrap()
            .max(now + Duration::from_micros(1));
    }
    let (late, in_time) = (consent[0], consent[1]);
    assert!(
        a.pending_binding_requests
            .iter()
            .all(|r| r.transaction_id != late),
        "the first one stopped waiting"
    );

    let at = now + 400 * MS;
    let response = peer_response(BINDING_SUCCESS, late, addr(LOCAL), None);
    let _ = deliver(&mut a, at, &response, "10.0.0.1:5000");
    assert_eq!(a.remote_candidates[0].last_consent(), Some(consent_before));

    let response = peer_response(BINDING_SUCCESS, in_time, addr(LOCAL), None);
    deliver(&mut a, at, &response, "10.0.0.1:5000").unwrap();
    assert_eq!(a.remote_candidates[0].last_consent(), Some(at));
}
