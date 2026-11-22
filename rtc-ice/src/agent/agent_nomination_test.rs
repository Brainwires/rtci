//! The controlled agent accepts the controlling agent's nominations (RFC 8445 Section
//! 7.3.1.5). Which nominated pair it uses: by default the one with the highest priority
//! (Section 8.1.1); with `NominationAcceptance::Latest` the latest one, and libwebrtc's
//! renomination (`NOMINATION`, highest value wins).
//!
//! Why `Latest` exists:
//!
//! libwebrtc, controlling, moves a session to another pair after it connects (it gathers on
//! more interfaces once it has camera / microphone permission): it sends `USE-CANDIDATE` on the
//! new pair and stops using the old one. The controlled agent took only the first nomination,
//! so it kept sending on the pair the peer had left, and dropped the peer's DTLS / SRTP from the
//! new one.

use std::sync::Arc;
use std::time::{Duration, Instant};

use sansio::Protocol;
use stun::attributes::{ATTR_USE_CANDIDATE, ATTR_USERNAME};

use super::*;
use crate::attributes::control::AttrControlling;
use crate::attributes::nomination::{ATTR_NOMINATION, NominationAttr};
use crate::attributes::priority::PriorityAttr;
use crate::attributes::use_candidate::UseCandidateAttr;
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

/// A controlled agent with one local candidate and two remote ones, A and B: pairs 0 (to A)
/// and 1 (to B), both still waiting for their checks.
fn controlled_agent(base: Instant) -> Agent {
    agent_accepting(base, NominationAcceptance::Latest, 0, 0)
}

/// A controlled agent with the given rule and the priorities of its remote candidates A and B
/// (0: the one the agent computes).
fn agent_accepting(
    base: Instant,
    nomination_acceptance: NominationAcceptance,
    priority_a: u32,
    priority_b: u32,
) -> Agent {
    let config = AgentConfig {
        is_controlling: false,
        nomination_acceptance,
        ..AgentConfig::default()
    };
    let remote = |address: &str, priority: u32| {
        let mut c = host(addr(address));
        c.priority_override = priority;
        c
    };
    let mut a = Agent::new(base, Arc::new(config), provider()).unwrap();
    a.add_local_candidate(host(addr(LOCAL))).unwrap();
    a.add_remote_candidate(remote(REMOTE_A, priority_a))
        .unwrap();
    a.add_remote_candidate(remote(REMOTE_B, priority_b))
        .unwrap();
    a.set_remote_credentials("remoteufrag".to_owned(), "remotepwd".to_owned())
        .unwrap();
    assert_eq!(a.candidate_pairs.len(), 2);
    a
}

/// `controlled_agent` with both pairs' checks succeeded.
fn checked_agent(base: Instant) -> Agent {
    checked(controlled_agent(base))
}

fn checked(mut a: Agent) -> Agent {
    for (index, p) in a.candidate_pairs.iter_mut().enumerate() {
        p.state = CandidatePairState::Succeeded;
        p.valid = true;
        p.valid_pair = Some(index);
    }
    a
}

/// The default rule (RFC 8445 Section 8.1.1), B's pair having the higher priority.
fn rfc_agent(base: Instant) -> Agent {
    checked(agent_accepting(
        base,
        NominationAcceptance::HighestPriority,
        1000,
        2000,
    ))
}

fn pair_to(a: &Agent, remote: &str) -> usize {
    let remote_index = a.find_remote_candidate(addr(remote)).unwrap();
    a.find_pair(0, remote_index).unwrap()
}

/// The peer's authenticated Binding request, with `USE-CANDIDATE` and / or `NOMINATION`.
fn peer_request(a: &Agent, use_candidate: bool, nomination: Option<u32>) -> Message {
    let username = a.ufrag_pwd.local_credentials.ufrag.clone() + ":remoteufrag";
    let provider = provider();
    let mut setters: Vec<Box<dyn Setter>> = vec![
        Box::new(BINDING_REQUEST),
        Box::new(TransactionId::new()),
        Box::new(Username::new(ATTR_USERNAME, username)),
        Box::new(AttrControlling(1)),
        Box::new(PriorityAttr(1000)),
    ];
    if use_candidate {
        setters.push(Box::new(UseCandidateAttr::new()));
    }
    if let Some(value) = nomination {
        setters.push(Box::new(NominationAttr(value)));
    }
    setters.push(Box::new(
        MessageIntegrity::new_short_term_integrity_with_provider(
            a.ufrag_pwd.local_credentials.pwd.clone(),
            provider.crypto(),
        ),
    ));
    setters.push(Box::new(FINGERPRINT));
    let mut msg = Message::new();
    msg.build(&setters).unwrap();
    msg
}

/// The peer's authenticated success response to our request `id`.
fn peer_response(id: TransactionId) -> Message {
    let local = addr(LOCAL);
    let mut msg = Message::new();
    msg.build(&[
        Box::new(BINDING_SUCCESS),
        Box::new(id),
        Box::new(XorMappedAddress {
            ip: local.ip(),
            port: local.port(),
        }),
        Box::new(MessageIntegrity::new_short_term_integrity_with_provider(
            "remotepwd".to_owned(),
            provider().crypto(),
        )),
        Box::new(FINGERPRINT),
    ])
    .unwrap();
    msg
}

fn deliver(a: &mut Agent, now: Instant, mut m: Message, from: &str) {
    a.handle_inbound(now, &mut m, 0, addr(from)).unwrap();
}

/// What the agent sent: (message type, transaction id, destination).
fn sent(a: &mut Agent) -> Vec<(MessageType, TransactionId, SocketAddr)> {
    let mut out = vec![];
    while let Some(t) = a.poll_write() {
        let mut m = Message {
            raw: t.message.to_vec(),
            ..Message::default()
        };
        if m.decode().is_ok() {
            out.push((m.typ, m.transaction_id, t.transport.peer_addr));
        }
    }
    out
}

/// The remote addresses of the selected-pair changes the agent reported.
fn selected_changes(a: &mut Agent) -> Vec<SocketAddr> {
    let mut out = vec![];
    while let Some(e) = a.poll_event() {
        if let Event::SelectedCandidatePairChange(_, remote) = e.event {
            out.push(remote.addr());
        }
    }
    out
}

fn selected_remote(a: &Agent) -> Option<SocketAddr> {
    a.get_selected_candidate_pair().map(|(_, r)| r.addr())
}

#[test]
fn test_controlled_follows_a_later_nomination() {
    let base = Instant::now();
    let mut a = checked_agent(base);

    let req = peer_request(&a, true, None);
    deliver(&mut a, base, req, REMOTE_A);
    assert_eq!(selected_remote(&a), Some(addr(REMOTE_A)));
    assert_eq!(selected_changes(&mut a), vec![addr(REMOTE_A)]);

    // About a second later the controlling agent nominates another pair.
    let now = base + Duration::from_secs(1);
    let req = peer_request(&a, true, None);
    deliver(&mut a, now, req, REMOTE_B);
    assert_eq!(
        selected_remote(&a),
        Some(addr(REMOTE_B)),
        "the controlled agent kept the pair the controlling agent left"
    );
    assert_eq!(selected_changes(&mut a), vec![addr(REMOTE_B)]);

    // DTLS / SRTP follow at once.
    let path = a.media_path().unwrap();
    assert_eq!(path.peer_addr, addr(REMOTE_B));
    assert_eq!(path.local_addr, addr(LOCAL));

    let (pa, pb) = (pair_to(&a, REMOTE_A), pair_to(&a, REMOTE_B));
    assert!(!a.candidate_pairs[pa].nominated);
    assert!(a.candidate_pairs[pb].nominated);
    assert_eq!(a.connection_state, ConnectionState::Connected);

    // And back again: regular nominations all count as 1, so the latest wins.
    let req = peer_request(&a, true, None);
    deliver(&mut a, now + Duration::from_secs(1), req, REMOTE_A);
    assert_eq!(selected_remote(&a), Some(addr(REMOTE_A)));
}

#[test]
fn test_repeated_nomination_of_the_selected_pair_is_not_a_change() {
    let base = Instant::now();
    let mut a = checked_agent(base);
    for secs in 0..5 {
        let req = peer_request(&a, true, None);
        deliver(&mut a, base + Duration::from_secs(secs), req, REMOTE_A);
    }
    assert_eq!(selected_changes(&mut a), vec![addr(REMOTE_A)]);
}

#[test]
fn test_requests_without_nomination_do_not_switch() {
    let base = Instant::now();
    let mut a = checked_agent(base);
    let req = peer_request(&a, true, None);
    deliver(&mut a, base, req, REMOTE_A);
    let req = peer_request(&a, false, None);
    deliver(&mut a, base + Duration::from_secs(1), req, REMOTE_B);
    assert_eq!(selected_remote(&a), Some(addr(REMOTE_A)));
}

#[test]
fn test_renomination_highest_value_wins() {
    let base = Instant::now();
    let mut a = checked_agent(base);

    let req = peer_request(&a, true, Some(5));
    deliver(&mut a, base, req, REMOTE_B);
    assert_eq!(selected_remote(&a), Some(addr(REMOTE_B)));

    // A delayed earlier nomination does not move the session back.
    let req = peer_request(&a, true, Some(3));
    deliver(&mut a, base + Duration::from_millis(100), req, REMOTE_A);
    assert_eq!(selected_remote(&a), Some(addr(REMOTE_B)));

    // Nor does a plain USE-CANDIDATE (value 1) on a pair below the selected one.
    let req = peer_request(&a, true, None);
    deliver(&mut a, base + Duration::from_millis(200), req, REMOTE_A);
    assert_eq!(selected_remote(&a), Some(addr(REMOTE_B)));

    // A higher value does, with or without USE-CANDIDATE beside it (libwebrtc reads
    // NOMINATION on its own).
    let req = peer_request(&a, false, Some(6));
    deliver(&mut a, base + Duration::from_millis(300), req, REMOTE_A);
    assert_eq!(selected_remote(&a), Some(addr(REMOTE_A)));
    let req = peer_request(&a, true, Some(7));
    deliver(&mut a, base + Duration::from_millis(400), req, REMOTE_B);
    assert_eq!(selected_remote(&a), Some(addr(REMOTE_B)));

    assert_eq!(
        selected_changes(&mut a),
        vec![addr(REMOTE_B), addr(REMOTE_A), addr(REMOTE_B)]
    );
    let pa = pair_to(&a, REMOTE_A);
    assert_eq!(a.candidate_pairs[pa].remote_nomination, 6);
}

#[test]
fn test_nomination_before_the_check_succeeds_applies_when_it_does() {
    let base = Instant::now();
    let mut a = controlled_agent(base);
    let pa = pair_to(&a, REMOTE_A);
    a.candidate_pairs[pa].state = CandidatePairState::Succeeded;
    let req = peer_request(&a, true, None);
    deliver(&mut a, base, req, REMOTE_A);
    assert_eq!(selected_remote(&a), Some(addr(REMOTE_A)));
    let _ = sent(&mut a);

    // The controlling agent nominates B, whose check has not succeeded here yet.
    let now = base + Duration::from_secs(1);
    let req = peer_request(&a, true, None);
    let request_id = req.transaction_id;
    deliver(&mut a, now, req, REMOTE_B);
    // The triggered check leaves the queue when Ta allows it: at once here.
    a.handle_timeout(now).unwrap();
    let out = sent(&mut a);
    assert!(
        out.contains(&(BINDING_SUCCESS, request_id, addr(REMOTE_B))),
        "the nomination must be answered (RFC 8445 Section 7.3.1.4): {out:?}"
    );
    let check = out
        .iter()
        .find(|(typ, _, to)| *typ == BINDING_REQUEST && *to == addr(REMOTE_B))
        .expect("a triggered check on the nominated pair")
        .1;
    assert_eq!(
        selected_remote(&a),
        Some(addr(REMOTE_A)),
        "a pair is used only once its check succeeds"
    );

    deliver(
        &mut a,
        now + Duration::from_millis(20),
        peer_response(check),
        REMOTE_B,
    );
    assert_eq!(selected_remote(&a), Some(addr(REMOTE_B)));
    assert!(!a.candidate_pairs[pair_to(&a, REMOTE_B)].nomination_pending);
}

#[test]
fn test_first_nomination_before_the_check_succeeds() {
    let base = Instant::now();
    let mut a = controlled_agent(base);
    let req = peer_request(&a, true, None);
    deliver(&mut a, base, req, REMOTE_A);
    assert!(a.get_selected_pair().is_none());
    a.handle_timeout(base).unwrap();
    let check = sent(&mut a)
        .into_iter()
        .find(|(typ, _, to)| *typ == BINDING_REQUEST && *to == addr(REMOTE_A))
        .expect("a triggered check")
        .1;
    deliver(
        &mut a,
        base + Duration::from_millis(20),
        peer_response(check),
        REMOTE_A,
    );
    assert_eq!(selected_remote(&a), Some(addr(REMOTE_A)));
}

#[test]
fn test_nomination_outside_message_integrity_is_ignored() {
    let base = Instant::now();
    let mut a = checked_agent(base);
    let req = peer_request(&a, true, None);
    deliver(&mut a, base, req, REMOTE_A);

    // USE-CANDIDATE and NOMINATION appended after MESSAGE-INTEGRITY: the integrity check passes
    // (it covers what precedes it) but neither attribute is authenticated.
    let username = a.ufrag_pwd.local_credentials.ufrag.clone() + ":remoteufrag";
    let mut m = Message::new();
    m.build(&[
        Box::new(BINDING_REQUEST),
        Box::new(TransactionId::new()),
        Box::new(Username::new(ATTR_USERNAME, username)),
        Box::new(AttrControlling(1)),
        Box::new(PriorityAttr(1000)),
        Box::new(MessageIntegrity::new_short_term_integrity_with_provider(
            a.ufrag_pwd.local_credentials.pwd.clone(),
            provider().crypto(),
        )),
    ])
    .unwrap();
    m.add(ATTR_USE_CANDIDATE, &[]);
    m.add(ATTR_NOMINATION, &9u32.to_be_bytes());
    let mut decoded = Message::new();
    decoded.write(&m.raw).unwrap();
    deliver(&mut a, base + Duration::from_secs(1), decoded, REMOTE_B);
    assert_eq!(selected_remote(&a), Some(addr(REMOTE_A)));
}

#[test]
fn test_nomination_from_a_disallowed_loopback_remote_is_not_followed() {
    // W3 / R-13: a loopback remote address pairs only with a loopback local candidate. A
    // nomination arriving from one creates no pair, so it cannot become the selected path.
    let base = Instant::now();
    let mut a = checked_agent(base);
    let req = peer_request(&a, true, None);
    deliver(&mut a, base, req, REMOTE_A);

    let req = peer_request(&a, true, Some(100));
    deliver(&mut a, base + Duration::from_secs(1), req, "127.0.0.1:4000");
    assert_eq!(selected_remote(&a), Some(addr(REMOTE_A)));
    assert!(a.candidate_pairs.iter().all(|p| {
        !a.remote_candidates[p.remote_index]
            .addr()
            .ip()
            .is_loopback()
    }));
}

// --- The default: RFC 8445 Section 8.1.1, the nominated pair with the highest priority ---

/// "If more than one candidate pair is nominated by the controlling agent, and if the
/// controlled agent accepts multiple nominations requests, the agents MUST produce the
/// selected pairs and use the pairs with the highest priority."
#[test]
fn test_controlled_uses_the_nominated_pair_with_the_highest_priority() {
    let base = Instant::now();
    let mut a = rfc_agent(base);
    assert_eq!(
        a.nomination_acceptance,
        NominationAcceptance::HighestPriority
    );
    let (pa, pb) = (pair_to(&a, REMOTE_A), pair_to(&a, REMOTE_B));
    assert!(a.candidate_pairs[pb].priority() > a.candidate_pairs[pa].priority());

    // The first nomination is on the lower-priority pair: it is the only nominated one.
    let req = peer_request(&a, true, None);
    deliver(&mut a, base, req, REMOTE_A);
    assert_eq!(selected_remote(&a), Some(addr(REMOTE_A)));

    // A second nomination, on the higher-priority pair: that one is used.
    let req = peer_request(&a, true, None);
    deliver(&mut a, base + Duration::from_secs(1), req, REMOTE_B);
    assert_eq!(selected_remote(&a), Some(addr(REMOTE_B)));
    assert_eq!(a.media_path().unwrap().peer_addr, addr(REMOTE_B));

    // Nominating the lower-priority pair again, later, changes nothing: it is not the latest
    // nomination that counts.
    let req = peer_request(&a, true, None);
    let id = req.transaction_id;
    deliver(&mut a, base + Duration::from_secs(2), req, REMOTE_A);
    assert_eq!(selected_remote(&a), Some(addr(REMOTE_B)));
    // The nomination is accepted all the same (Section 7.3.1.5): answered with success, and
    // both pairs carry the nominated flag.
    assert!(
        sent(&mut a).contains(&(BINDING_SUCCESS, id, addr(REMOTE_A))),
        "an accepted nomination is answered with a success response"
    );
    assert!(a.candidate_pairs[pa].nominated);
    assert!(a.candidate_pairs[pb].nominated);
    assert_eq!(
        selected_changes(&mut a),
        vec![addr(REMOTE_A), addr(REMOTE_B)]
    );
}

/// libwebrtc's `NOMINATION` value does not outrank the priority under the default rule.
#[test]
fn test_nomination_value_does_not_outrank_priority_by_default() {
    let base = Instant::now();
    let mut a = rfc_agent(base);
    let req = peer_request(&a, true, Some(2));
    deliver(&mut a, base, req, REMOTE_B);
    let req = peer_request(&a, true, Some(9));
    deliver(&mut a, base + Duration::from_secs(1), req, REMOTE_A);
    assert_eq!(selected_remote(&a), Some(addr(REMOTE_B)));
}

/// A nominated pair of lower priority takes over when the selected pair loses the peer's
/// consent: with no response to the consent checks on B, the agent is `Disconnected` and moves
/// to A, which the peer nominated and was heard on since.
#[test]
fn test_lower_priority_nominated_pair_takes_over_when_consent_is_lost() {
    let base = Instant::now();
    let mut a = rfc_agent(base);
    a.update_connection_state(Some(base), ConnectionState::Checking);
    let req = peer_request(&a, true, None);
    deliver(&mut a, base, req, REMOTE_B);
    let req = peer_request(&a, true, None);
    deliver(&mut a, base + Duration::from_secs(1), req, REMOTE_A);
    assert_eq!(selected_remote(&a), Some(addr(REMOTE_B)));
    let _ = selected_changes(&mut a);

    // Nothing answers on B: the consent checks go unanswered.
    let mut now = base + Duration::from_secs(1);
    let until = base + Duration::from_secs(14);
    while now <= until && selected_remote(&a) == Some(addr(REMOTE_B)) {
        a.handle_timeout(now).unwrap();
        let _ = sent(&mut a);
        now = a
            .poll_timeout()
            .map_or(until + Duration::from_secs(1), |t| {
                t.max(now + Duration::from_millis(1))
            });
    }
    assert_eq!(
        selected_remote(&a),
        Some(addr(REMOTE_A)),
        "the session stayed on the pair without consent"
    );
    assert_eq!(selected_changes(&mut a), vec![addr(REMOTE_A)]);
    assert!(
        now < base + Duration::from_secs(14),
        "before consent expires"
    );
}

/// And a nomination that arrives while the agent is `Disconnected` is followed at once,
/// whatever the pair's priority.
#[test]
fn test_nomination_while_disconnected_is_followed() {
    let base = Instant::now();
    let mut a = rfc_agent(base);
    let req = peer_request(&a, true, None);
    deliver(&mut a, base, req, REMOTE_B);
    assert_eq!(selected_remote(&a), Some(addr(REMOTE_B)));
    a.update_connection_state(Some(base), ConnectionState::Disconnected);
    let req = peer_request(&a, true, None);
    deliver(&mut a, base + Duration::from_secs(8), req, REMOTE_A);
    assert_eq!(selected_remote(&a), Some(addr(REMOTE_A)));
}
