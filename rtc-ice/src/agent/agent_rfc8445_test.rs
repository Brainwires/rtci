//! RFC 8445 behaviour, read from what the agent puts on the wire: every test here delivers
//! datagrams through `handle_read`, advances time through `handle_timeout` and decodes what
//! `poll_write` returns.

use std::sync::Arc;
use std::time::{Duration, Instant};

use sansio::Protocol;
use stun::attributes::{
    ATTR_ICE_CONTROLLED, ATTR_ICE_CONTROLLING, ATTR_PRIORITY, ATTR_USE_CANDIDATE, ATTR_USERNAME,
};
use stun::error_code::{CODE_BAD_REQUEST, CODE_ROLE_CONFLICT, ErrorCode, ErrorCodeAttribute};

use super::*;
use crate::attributes::control::{AttrControlled, AttrControlling};
use crate::attributes::priority::PriorityAttr;
use crate::attributes::use_candidate::UseCandidateAttr;
use crate::candidate::candidate_host::CandidateHostConfig;

pub(super) fn provider() -> Arc<dyn crypto::RTCCryptoProvider> {
    crypto::default_provider().expect("a built-in crypto provider must be enabled for tests")
}

pub(super) const LOCAL: &str = "192.168.0.2:1000";
pub(super) const REMOTE_A: &str = "192.168.0.3:2000";
pub(super) const REMOTE_B: &str = "192.168.0.4:3000";
pub(super) const REMOTE_UFRAG: &str = "remoteufrag";
pub(super) const REMOTE_PWD: &str = "remotepwdremotepwdremotepwd";

pub(super) fn addr(s: &str) -> SocketAddr {
    s.parse().unwrap()
}

pub(super) fn host(addr: SocketAddr) -> Candidate {
    host_with_priority(addr, 0)
}

pub(super) fn host_with_priority(addr: SocketAddr, priority: u32) -> Candidate {
    CandidateHostConfig {
        base_config: CandidateConfig {
            network: "udp".to_owned(),
            address: addr.ip().to_string(),
            port: addr.port(),
            component: 1,
            priority,
            ..Default::default()
        },
        ..Default::default()
    }
    .new_candidate_host()
    .unwrap()
}

/// An agent with one local host candidate (`LOCAL`) and nothing from the peer yet.
pub(super) fn bare_agent(now: Instant, config: AgentConfig) -> Agent {
    let mut a = Agent::new(now, Arc::new(config), provider()).unwrap();
    a.add_local_candidate(host(addr(LOCAL))).unwrap();
    a
}

/// `bare_agent` with the peer's credentials and the remote candidates `remotes`, checking.
pub(super) fn started_agent(now: Instant, config: AgentConfig, remotes: &[&str]) -> Agent {
    let controlling = config.is_controlling;
    let mut a = bare_agent(now, config);
    for remote in remotes {
        a.add_remote_candidate(host(addr(remote))).unwrap();
    }
    a.start_connectivity_checks(
        now,
        controlling,
        REMOTE_UFRAG.to_owned(),
        REMOTE_PWD.to_owned(),
    )
    .unwrap();
    a
}

pub(super) fn config(controlling: bool) -> AgentConfig {
    AgentConfig {
        is_controlling: controlling,
        ..AgentConfig::default()
    }
}

/// The peer's Binding request to `a`: USERNAME `<a's ufrag>:<peer's>`, the given attributes,
/// MESSAGE-INTEGRITY with `a`'s password, FINGERPRINT.
pub(super) fn peer_request(a: &Agent, extra: Vec<Box<dyn Setter>>) -> Message {
    let username = a.ufrag_pwd.local_credentials.ufrag.clone() + ":" + REMOTE_UFRAG;
    let provider = provider();
    let mut setters: Vec<Box<dyn Setter>> = vec![
        Box::new(BINDING_REQUEST),
        Box::new(TransactionId::new()),
        Box::new(Username::new(ATTR_USERNAME, username)),
    ];
    setters.extend(extra);
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

/// The peer's response of type `typ` to the agent's request `id`, signed with the peer's
/// password.
pub(super) fn peer_response(
    typ: MessageType,
    id: TransactionId,
    mapped: SocketAddr,
    error: Option<ErrorCode>,
) -> Message {
    let provider = provider();
    let mut setters: Vec<Box<dyn Setter>> = vec![Box::new(typ), Box::new(id)];
    match error {
        Some(code) => setters.push(Box::new(code)),
        None => setters.push(Box::new(XorMappedAddress {
            ip: mapped.ip(),
            port: mapped.port(),
        })),
    }
    setters.push(Box::new(
        MessageIntegrity::new_short_term_integrity_with_provider(
            REMOTE_PWD.to_owned(),
            provider.crypto(),
        ),
    ));
    setters.push(Box::new(FINGERPRINT));
    let mut msg = Message::new();
    msg.build(&setters).unwrap();
    msg
}

/// Delivers `raw` to the agent as a UDP datagram from `from` on its local candidate.
pub(super) fn deliver_raw(a: &mut Agent, now: Instant, raw: &[u8], from: &str) -> Result<()> {
    a.handle_read(TaggedBytesMut {
        now,
        transport: TransportContext {
            local_addr: addr(LOCAL),
            peer_addr: addr(from),
            ecn: None,
            transport_protocol: TransportProtocol::UDP,
        },
        message: BytesMut::from(raw),
    })
}

pub(super) fn deliver(a: &mut Agent, now: Instant, m: &Message, from: &str) -> Result<()> {
    deliver_raw(a, now, &m.raw, from)
}

/// What the agent wrote since the last call: decoded STUN messages with their destination.
pub(super) fn sent(a: &mut Agent) -> Vec<(Message, SocketAddr)> {
    let mut out = vec![];
    while let Some(t) = a.poll_write() {
        let mut m = Message {
            raw: t.message.to_vec(),
            ..Message::default()
        };
        m.decode().unwrap();
        out.push((m, t.transport.peer_addr));
    }
    out
}

pub(super) fn requests(sent: &[(Message, SocketAddr)]) -> Vec<&(Message, SocketAddr)> {
    sent.iter()
        .filter(|(m, _)| m.typ == BINDING_REQUEST)
        .collect()
}

pub(super) fn error_code(m: &Message) -> u16 {
    let mut code = ErrorCodeAttribute::default();
    code.get_from(m).unwrap();
    code.code.0
}

/// Runs the agent's timer up to `until`, answering nothing; returns everything it sent.
pub(super) fn run(a: &mut Agent, from: Instant, until: Instant) -> Vec<(Message, SocketAddr)> {
    let mut out = vec![];
    let mut now = from;
    loop {
        a.handle_timeout(now).unwrap();
        out.extend(sent(a));
        match a.poll_timeout() {
            Some(next) if next <= until => now = next.max(now + Duration::from_millis(1)),
            _ => break,
        }
        if now > until {
            break;
        }
    }
    out
}

/// Runs the agent's timer up to `until`. Every Binding request it sends is answered with a
/// success response from its destination when `answer(request, destination)` says so.
pub(super) fn run_answering(
    a: &mut Agent,
    from: Instant,
    until: Instant,
    mut answer: impl FnMut(&Message, SocketAddr) -> bool,
) -> Vec<(Message, SocketAddr)> {
    let mut out = vec![];
    let mut now = from;
    loop {
        a.handle_timeout(now).unwrap();
        loop {
            let batch = sent(a);
            if batch.is_empty() {
                break;
            }
            for (m, to) in &batch {
                if m.typ == BINDING_REQUEST && answer(m, *to) {
                    let response =
                        peer_response(BINDING_SUCCESS, m.transaction_id, addr(LOCAL), None);
                    let _ = deliver(a, now, &response, &to.to_string());
                }
            }
            out.extend(batch);
        }
        match a.poll_timeout() {
            Some(next) if next <= until => now = next.max(now + Duration::from_millis(1)),
            _ => break,
        }
    }
    out
}

fn first_check(a: &mut Agent, now: Instant) -> (Message, SocketAddr) {
    let out = run(a, now, now + Duration::from_millis(100));
    requests(&out)
        .first()
        .map(|(m, to)| (m.clone(), *to))
        .expect("the agent sends a check")
}

// --- Section 7.3.1.1 and RFC 8489 Section 14.5: role attributes and MESSAGE-INTEGRITY ---

/// Someone on the path replays a valid check with the opposite role attribute appended after
/// MESSAGE-INTEGRITY. Nothing after MESSAGE-INTEGRITY is authenticated: the role must stand.
#[test]
fn test_role_attribute_after_message_integrity_is_ignored() {
    let now = Instant::now();
    let mut a = started_agent(now, config(false), &[REMOTE_A]);
    a.tie_breaker = 100;
    let _ = sent(&mut a);

    let mut m = peer_request(
        &a,
        vec![Box::new(AttrControlling(5)), Box::new(PriorityAttr(1000))],
    );
    // Appended by the attacker: ICE-CONTROLLED with tiebreaker 0 (we would "win" and switch).
    m.add(ATTR_ICE_CONTROLLED, &0u64.to_be_bytes());
    assert!(m.contains(ATTR_ICE_CONTROLLED));

    deliver(&mut a, now, &m, REMOTE_A).unwrap();

    assert!(
        !a.is_controlling,
        "an unauthenticated attribute flipped the role"
    );
    let out = sent(&mut a);
    let answers: Vec<_> = out
        .iter()
        .filter(|(r, _)| r.transaction_id == m.transaction_id)
        .collect();
    assert_eq!(answers.len(), 1);
    assert_eq!(answers[0].0.typ, BINDING_SUCCESS);
}

fn conflict_case(
    controlling: bool,
    own: u64,
    theirs: u64,
) -> (Agent, Vec<(Message, SocketAddr)>, TransactionId) {
    let now = Instant::now();
    let mut a = started_agent(now, config(controlling), &[REMOTE_A]);
    a.tie_breaker = own;
    let _ = sent(&mut a);
    let role: Box<dyn Setter> = if controlling {
        Box::new(AttrControlling(theirs))
    } else {
        Box::new(AttrControlled(theirs))
    };
    let m = peer_request(&a, vec![role, Box::new(PriorityAttr(1000))]);
    deliver(&mut a, now, &m, REMOTE_A).unwrap();
    let out = sent(&mut a)
        .into_iter()
        .filter(|(r, _)| r.transaction_id == m.transaction_id)
        .collect();
    (a, out, m.transaction_id)
}

/// Section 7.3.1.1: controlling, the request has ICE-CONTROLLING, own tiebreaker larger or
/// equal: one answer, the 487, and the role is kept.
#[test]
fn test_role_conflict_controlling_winner_answers_487_only() {
    for theirs in [100, 500] {
        let (a, out, _) = conflict_case(true, 500, theirs);
        assert!(a.is_controlling);
        assert_eq!(out.len(), 1, "one transaction, one response");
        assert_eq!(out[0].0.typ, BINDING_ERROR);
        assert_eq!(error_code(&out[0].0), CODE_ROLE_CONFLICT.0);
        assert_eq!(out[0].1, addr(REMOTE_A));
    }
}

/// Section 7.3.1.1: controlling, own tiebreaker smaller: switch to controlled and answer the
/// request (with success, nothing else).
#[test]
fn test_role_conflict_controlling_loser_switches_and_answers_success_only() {
    let (a, out, _) = conflict_case(true, 100, 500);
    assert!(!a.is_controlling);
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].0.typ, BINDING_SUCCESS);
}

/// Section 7.3.1.1: controlled, the request has ICE-CONTROLLED, own tiebreaker larger *or
/// equal*: switch to controlling, answer with success.
#[test]
fn test_role_conflict_controlled_winner_or_equal_switches_to_controlling() {
    for theirs in [3, 7] {
        let (a, out, _) = conflict_case(false, 7, theirs);
        assert!(a.is_controlling, "tiebreaker 7 against {theirs}");
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].0.typ, BINDING_SUCCESS);
    }
}

/// Section 7.3.1.1: controlled, own tiebreaker smaller: 487 and nothing else, role kept.
#[test]
fn test_role_conflict_controlled_loser_answers_487_only() {
    let (a, out, _) = conflict_case(false, 7, 9);
    assert!(!a.is_controlling);
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].0.typ, BINDING_ERROR);
    assert_eq!(error_code(&out[0].0), CODE_ROLE_CONFLICT.0);
}

/// Section 7.2.5.1: a 487 answer to a request sent with ICE-CONTROLLING makes the agent
/// controlled (with ICE-CONTROLLED: controlling), changes the tiebreaker, and the pair is
/// checked again in the new role.
#[test]
fn test_487_response_switches_role_changes_tiebreaker_and_rechecks() {
    for controlling in [true, false] {
        role_conflict_response_case(controlling);
    }
}

fn role_conflict_response_case(controlling: bool) {
    let (was, becomes) = if controlling {
        (ATTR_ICE_CONTROLLING, ATTR_ICE_CONTROLLED)
    } else {
        (ATTR_ICE_CONTROLLED, ATTR_ICE_CONTROLLING)
    };
    let now = Instant::now();
    let mut a = started_agent(now, config(controlling), &[REMOTE_A]);
    let tie_breaker = a.tie_breaker;
    let (check, to) = first_check(&mut a, now);
    assert!(check.contains(was));

    let later = now + Duration::from_millis(120);
    let response = peer_response(
        BINDING_ERROR,
        check.transaction_id,
        addr(LOCAL),
        Some(CODE_ROLE_CONFLICT),
    );
    deliver(&mut a, later, &response, &to.to_string()).unwrap();

    assert_eq!(
        a.is_controlling, !controlling,
        "a 487 response must switch the role"
    );
    assert_ne!(a.tie_breaker, tie_breaker, "the tiebreaker must change");

    let out = run(&mut a, later, later + Duration::from_secs(1));
    let again = requests(&out);
    let (recheck, recheck_to) = again.first().expect("the pair is checked again");
    assert_eq!(*recheck_to, to);
    assert_ne!(recheck.transaction_id, check.transaction_id);
    assert!(recheck.contains(becomes));
    assert!(!recheck.contains(was));
    let new_tie_breaker = u64::from_be_bytes(recheck.get(becomes).unwrap().try_into().unwrap());
    assert_eq!(new_tie_breaker, a.tie_breaker);
}

/// A 487 nobody signed, or for a transaction the agent does not have, changes nothing.
#[test]
fn test_unauthenticated_or_unsolicited_487_is_ignored() {
    let now = Instant::now();
    let mut a = started_agent(now, config(true), &[REMOTE_A]);
    let (check, to) = first_check(&mut a, now);

    let mut unsigned = Message::new();
    unsigned
        .build(&[
            Box::new(BINDING_ERROR),
            Box::new(check.transaction_id),
            Box::new(CODE_ROLE_CONFLICT),
            Box::new(FINGERPRINT),
        ])
        .unwrap();
    let _ = deliver(&mut a, now, &unsigned, &to.to_string());
    assert!(a.is_controlling);

    let unsolicited = peer_response(
        BINDING_ERROR,
        TransactionId::new(),
        addr(LOCAL),
        Some(CODE_ROLE_CONFLICT),
    );
    let _ = deliver(&mut a, now, &unsolicited, &to.to_string());
    assert!(a.is_controlling);
}

/// Section 7.2.5.2.4: an unrecoverable error response fails the pair.
#[test]
fn test_error_response_fails_the_pair() {
    let now = Instant::now();
    let mut a = started_agent(now, config(true), &[REMOTE_A]);
    let (check, to) = first_check(&mut a, now);
    let response = peer_response(
        BINDING_ERROR,
        check.transaction_id,
        addr(LOCAL),
        Some(CODE_BAD_REQUEST),
    );
    deliver(&mut a, now, &response, &to.to_string()).unwrap();
    assert_eq!(a.candidate_pairs[0].state, CandidatePairState::Failed);
    assert!(a.is_controlling);
}

// --- Section 7.3: requests before the peer's candidate information ---

/// Section 7.3: a Binding request that arrives before the remote description is answered at
/// once (the answerer starts checking as soon as it has sent its answer).
#[test]
fn test_binding_request_before_remote_credentials_is_answered() {
    let now = Instant::now();
    let mut a = bare_agent(now, config(true));
    assert!(a.ufrag_pwd.remote_credentials.is_none());

    let m = peer_request(
        &a,
        vec![Box::new(AttrControlled(1)), Box::new(PriorityAttr(1234))],
    );
    deliver(&mut a, now, &m, REMOTE_A).unwrap();

    let out = sent(&mut a);
    assert_eq!(out.len(), 1, "exactly the response");
    let (response, to) = &out[0];
    assert_eq!(response.typ, BINDING_SUCCESS);
    assert_eq!(response.transaction_id, m.transaction_id);
    assert_eq!(*to, addr(REMOTE_A));
    let mut mapped = XorMappedAddress::default();
    mapped.get_from(response).unwrap();
    assert_eq!(SocketAddr::new(mapped.ip, mapped.port), addr(REMOTE_A));
    // Signed with the local password, as every response is, and closed by FINGERPRINT.
    FINGERPRINT.check(response).unwrap();
    assert_eq!(
        response.attributes.0.last().unwrap().typ,
        stun::attributes::ATTR_FINGERPRINT
    );
    let mut copy = response.clone();
    MessageIntegrity::check(
        &mut copy,
        a.ufrag_pwd.local_credentials.pwd.as_bytes(),
        provider().crypto(),
    )
    .unwrap();
}

/// Without the right password an early request gets nothing.
#[test]
fn test_early_request_with_a_wrong_password_is_not_answered() {
    let now = Instant::now();
    let mut a = bare_agent(now, config(true));
    let mut m = Message::new();
    m.build(&[
        Box::new(BINDING_REQUEST),
        Box::new(TransactionId::new()),
        Box::new(Username::new(
            ATTR_USERNAME,
            a.ufrag_pwd.local_credentials.ufrag.clone() + ":x",
        )),
        Box::new(MessageIntegrity::new_short_term_integrity_with_provider(
            "not the password".to_owned(),
            provider().crypto(),
        )),
        Box::new(FINGERPRINT),
    ])
    .unwrap();
    assert!(deliver(&mut a, now, &m, REMOTE_A).is_err());
    assert!(sent(&mut a).is_empty());
}

/// Section 7.3: once the peer's credentials arrive, the early request is processed as in
/// Sections 7.3.1.3 to 7.3.1.5: its source becomes a peer-reflexive candidate with the
/// request's PRIORITY and a triggered check goes to it.
#[test]
fn test_early_request_triggers_a_check_when_credentials_arrive() {
    let now = Instant::now();
    let mut a = bare_agent(now, config(true));
    let m = peer_request(
        &a,
        vec![Box::new(AttrControlled(1)), Box::new(PriorityAttr(1234))],
    );
    deliver(&mut a, now, &m, REMOTE_A).unwrap();
    let _ = sent(&mut a);
    assert!(a.remote_candidates.is_empty());

    let later = now + Duration::from_millis(30);
    a.start_connectivity_checks(later, true, REMOTE_UFRAG.to_owned(), REMOTE_PWD.to_owned())
        .unwrap();
    let out = run(&mut a, later, later + Duration::from_millis(200));

    assert_eq!(a.remote_candidates.len(), 1);
    assert_eq!(
        a.remote_candidates[0].candidate_type(),
        CandidateType::PeerReflexive
    );
    assert_eq!(a.remote_candidates[0].priority(), 1234);
    let checks = requests(&out);
    assert!(
        checks.iter().any(|(_, to)| *to == addr(REMOTE_A)),
        "a triggered check goes to the early request's source"
    );
    // The early request was answered once, when it arrived: no second response.
    assert!(out.iter().all(|(r, _)| r.typ != BINDING_SUCCESS));
}

/// Section 7.3: the username is valid when its first part is the agent's own fragment.
#[test]
fn test_username_is_valid_when_its_first_part_is_the_local_ufrag() {
    let now = Instant::now();
    let mut a = started_agent(now, config(false), &[REMOTE_A]);
    let _ = sent(&mut a);
    let provider = provider();
    let build = |username: String| {
        let mut m = Message::new();
        m.build(&[
            Box::new(BINDING_REQUEST),
            Box::new(TransactionId::new()),
            Box::new(Username::new(ATTR_USERNAME, username)),
            Box::new(AttrControlling(1)),
            Box::new(PriorityAttr(99)),
            Box::new(MessageIntegrity::new_short_term_integrity_with_provider(
                a.ufrag_pwd.local_credentials.pwd.clone(),
                provider.crypto(),
            )),
            Box::new(FINGERPRINT),
        ])
        .unwrap();
        m
    };
    let ufrag = a.ufrag_pwd.local_credentials.ufrag.clone();
    let other_second_part = build(format!("{ufrag}:someoneelse"));
    let wrong_first_part = build(format!("x{ufrag}:{REMOTE_UFRAG}"));
    let no_colon = build(ufrag.clone());
    let fragment_is_a_prefix_only = build(format!("{ufrag}x:{REMOTE_UFRAG}"));

    deliver(&mut a, now, &other_second_part, REMOTE_A).unwrap();
    assert_eq!(sent(&mut a)[0].0.typ, BINDING_SUCCESS);
    assert!(deliver(&mut a, now, &wrong_first_part, REMOTE_A).is_err());
    assert!(deliver(&mut a, now, &no_colon, REMOTE_A).is_err());
    assert!(deliver(&mut a, now, &fragment_is_a_prefix_only, REMOTE_A).is_err());
    assert!(sent(&mut a).is_empty());
}

// --- Section 7.1.1 and 7.3.1.3: PRIORITY ---

/// Section 7.1.1: PRIORITY is the priority the local candidate would have as a peer-reflexive
/// one: type preference 110 with the candidate's local preference and component.
#[test]
fn test_check_carries_the_peer_reflexive_priority() {
    for controlling in [true, false] {
        let now = Instant::now();
        let mut a = started_agent(now, config(controlling), &[REMOTE_A]);
        let (check, _) = first_check(&mut a, now);
        let mut priority = PriorityAttr::default();
        priority.get_from(&check).unwrap();
        assert_eq!(a.local_candidates[0].priority(), 2130706431);
        assert_eq!(priority.0, (110 << 24) + (65535 << 8) + 255);
        assert_eq!(priority.0, 1862270975);
    }
}

/// Section 7.3.1.3: a peer-reflexive remote candidate takes its priority from the request.
#[test]
fn test_peer_reflexive_remote_candidate_takes_priority_from_the_request() {
    let now = Instant::now();
    let mut a = started_agent(now, config(false), &[REMOTE_A]);
    let m = peer_request(
        &a,
        vec![
            Box::new(AttrControlling(1)),
            Box::new(PriorityAttr(1845501695)),
        ],
    );
    deliver(&mut a, now, &m, REMOTE_B).unwrap();
    let index = a.find_remote_candidate(addr(REMOTE_B)).unwrap();
    let prflx = &a.remote_candidates[index];
    assert_eq!(prflx.candidate_type(), CandidateType::PeerReflexive);
    assert_eq!(prflx.priority(), 1845501695);
    assert_eq!(prflx.component(), a.local_candidates[0].component());
    // Its foundation is no other remote candidate's (Section 7.3.1.3).
    assert_ne!(prflx.foundation(), a.remote_candidates[0].foundation());
}

// --- Section 6.2 / 7.3.2: lite ---

/// Section 7.3.2: a lite agent builds the pair from a request with USE-CANDIDATE, selects it,
/// and sends no connectivity check of its own, then or later.
#[test]
fn test_lite_agent_selects_on_use_candidate_and_sends_no_checks() {
    let now = Instant::now();
    let cfg = AgentConfig {
        lite: true,
        candidate_types: vec![CandidateType::Host],
        ..config(false)
    };
    let mut a = started_agent(now, cfg, &[REMOTE_A]);
    let plain = peer_request(
        &a,
        vec![Box::new(AttrControlling(1)), Box::new(PriorityAttr(1000))],
    );
    deliver(&mut a, now, &plain, REMOTE_A).unwrap();
    assert!(a.get_selected_candidate_pair().is_none());

    let nominating = peer_request(
        &a,
        vec![
            Box::new(AttrControlling(1)),
            Box::new(PriorityAttr(1000)),
            Box::new(UseCandidateAttr::new()),
        ],
    );
    deliver(&mut a, now, &nominating, REMOTE_A).unwrap();

    let (_, remote) = a
        .get_selected_candidate_pair()
        .expect("USE-CANDIDATE alone selects the pair on a lite agent");
    assert_eq!(remote.addr(), addr(REMOTE_A));
    let mut out = sent(&mut a);
    out.extend(run(&mut a, now, now + Duration::from_secs(3)));
    assert!(
        requests(&out).is_empty(),
        "a lite agent sends no Binding requests"
    );
    assert_eq!(
        out.iter().filter(|(m, _)| m.typ == BINDING_SUCCESS).count(),
        2
    );
}

// --- Section 7.3.1.4: triggered checks on the controlled side ---

/// Section 7.3.1.4: a request on a pair that already succeeded needs no check in return: one
/// datagram out, the response.
#[test]
fn test_request_on_a_succeeded_pair_triggers_no_check() {
    for controlling in [true, false] {
        let now = Instant::now();
        let mut a = started_agent(now, config(controlling), &[REMOTE_A]);
        let end = now + Duration::from_millis(300);
        run_answering(&mut a, now, end, |_, _| true);
        assert_eq!(a.candidate_pairs[0].state, CandidatePairState::Succeeded);
        let _ = sent(&mut a);

        let role: Box<dyn Setter> = if controlling {
            Box::new(AttrControlled(1))
        } else {
            Box::new(AttrControlling(1))
        };
        let m = peer_request(&a, vec![role, Box::new(PriorityAttr(1000))]);
        deliver(&mut a, end, &m, REMOTE_A).unwrap();
        let out = sent(&mut a);
        assert_eq!(out.len(), 1, "controlling={controlling}");
        assert_eq!(out[0].0.typ, BINDING_SUCCESS);
    }
}

/// Section 7.3.1.4: a request on a Failed pair puts the pair back to work: it is checked
/// again, with a fresh budget, on the controlled side as well.
#[test]
fn test_request_on_a_failed_pair_rechecks_it() {
    for controlling in [true, false] {
        let now = Instant::now();
        let mut a = started_agent(now, config(controlling), &[REMOTE_A]);
        // Nobody answers: the pair fails.
        let mut end = now;
        while a.candidate_pairs.first().map(|p| p.state) != Some(CandidatePairState::Failed) {
            end += Duration::from_millis(100);
            run(&mut a, end, end);
            assert!(end < now + Duration::from_secs(60), "the pair never failed");
            assert_ne!(a.state(), ConnectionState::Failed, "agent failed first");
        }
        let _ = sent(&mut a);

        let role: Box<dyn Setter> = if controlling {
            Box::new(AttrControlled(1))
        } else {
            Box::new(AttrControlling(1))
        };
        let m = peer_request(&a, vec![role, Box::new(PriorityAttr(1000))]);
        deliver(&mut a, end, &m, REMOTE_A).unwrap();
        assert_ne!(
            a.candidate_pairs[0].state,
            CandidatePairState::Failed,
            "controlling={controlling}"
        );
        // If the first triggered check is lost the pair is still retried.
        let mut out = sent(&mut a);
        out.extend(run(&mut a, end, end + Duration::from_secs(2)));
        assert!(
            requests(&out).len() >= 2,
            "controlling={controlling}: {} requests",
            requests(&out).len()
        );
    }
}

// --- Section 8.1.1 / 7.2.5.3.4: a nomination that fails ---

/// The controlling agent has two valid pairs and nominates the better one; the path dies before
/// the nomination is answered. It gives that pair up and nominates the other one instead of
/// repeating the nomination until the agent fails.
#[test]
fn test_failed_nomination_falls_back_to_the_next_valid_pair() {
    let now = Instant::now();
    let mut a = bare_agent(now, config(true));
    a.add_remote_candidate(host_with_priority(addr(REMOTE_A), 2130706431))
        .unwrap();
    a.add_remote_candidate(host_with_priority(addr(REMOTE_B), 2130706175))
        .unwrap();
    a.start_connectivity_checks(now, true, REMOTE_UFRAG.to_owned(), REMOTE_PWD.to_owned())
        .unwrap();

    let mut states = vec![];
    let mut nominated_a = 0;
    let end = now + Duration::from_secs(70);
    // Plain checks are answered by both; a nomination only by B.
    let out = run_answering(&mut a, now, end, |m, to| {
        if m.contains(ATTR_USE_CANDIDATE) && to == addr(REMOTE_A) {
            nominated_a += 1;
            return false;
        }
        true
    });
    while let Some(e) = a.poll_event() {
        if let Event::ConnectionStateChange(s) = e.event {
            states.push(s);
        }
    }
    assert!(nominated_a >= 1, "the better pair is nominated first");
    assert!(
        !states.contains(&ConnectionState::Failed),
        "the agent failed with a valid pair left: {states:?}"
    );
    let (_, remote) = a
        .get_selected_candidate_pair()
        .expect("the other valid pair is selected");
    assert_eq!(remote.addr(), addr(REMOTE_B));
    assert!(
        out.iter()
            .any(|(m, to)| m.contains(ATTR_USE_CANDIDATE) && *to == addr(REMOTE_B))
    );
}

// --- Section 9: restart ---

/// Section 9: a restart changes both the fragment and the password, also when the application
/// offers the ones in use (pinned credentials).
#[test]
fn test_restart_with_the_credentials_in_use_generates_new_ones() {
    let now = Instant::now();
    let mut a = bare_agent(now, config(true));
    let old = a.get_local_credentials().clone();
    a.generate_restart_credentials(old.ufrag.clone(), old.pwd.clone())
        .unwrap();
    let new = a.get_local_credentials().clone();
    assert_ne!(new.ufrag, old.ufrag);
    assert_ne!(new.pwd, old.pwd);
    assert!(new.ufrag.len() * 8 >= 24 && new.pwd.len() * 8 >= 128);

    // Different ones are taken as given.
    a.generate_restart_credentials(
        "freshufrag".to_owned(),
        "freshpwdfreshpwdfreshpwd".to_owned(),
    )
    .unwrap();
    assert_eq!(a.get_local_credentials().ufrag, "freshufrag");
}

/// Section 6.1.1 / 9: an ICE restart does not redetermine the roles.
#[test]
fn test_restart_keeps_the_role() {
    for controlling in [true, false] {
        let now = Instant::now();
        let mut a = started_agent(now, config(controlling), &[REMOTE_A]);
        a.restart(now, String::new(), String::new(), true).unwrap();
        assert_eq!(a.role(), controlling);
    }
}

// --- What the agent's own messages carry (Sections 7.1, 7.2.4, 7.3, 16.1) ---

/// Sections 7.1.1 to 7.1.3, 7.2.4, 16.1: a check carries PRIORITY, the role attribute with
/// the session's one tiebreaker, MESSAGE-INTEGRITY with the peer's password and FINGERPRINT;
/// the controlled agent never sends USE-CANDIDATE.
#[test]
fn test_checks_carry_role_tiebreaker_integrity_and_fingerprint() {
    for controlling in [true, false] {
        let now = Instant::now();
        let mut a = started_agent(now, config(controlling), &[REMOTE_A, REMOTE_B]);
        let out = run(&mut a, now, now + Duration::from_secs(2));
        let checks = requests(&out);
        assert!(checks.len() >= 2);
        for (m, _) in checks {
            assert!(m.contains(ATTR_PRIORITY));
            let mut username = Username::new(ATTR_USERNAME, String::new());
            username.get_from(m).unwrap();
            assert_eq!(
                username.to_string(),
                format!("{REMOTE_UFRAG}:{}", a.ufrag_pwd.local_credentials.ufrag)
            );
            if controlling {
                let mut attr = AttrControlling::default();
                attr.get_from(m).unwrap();
                assert_eq!(attr.0, a.tie_breaker);
                assert!(!m.contains(ATTR_ICE_CONTROLLED));
            } else {
                let mut attr = AttrControlled::default();
                attr.get_from(m).unwrap();
                assert_eq!(attr.0, a.tie_breaker);
                assert!(!m.contains(ATTR_ICE_CONTROLLING));
                assert!(!m.contains(ATTR_USE_CANDIDATE));
            }
            let mut copy = m.clone();
            MessageIntegrity::check(&mut copy, REMOTE_PWD.as_bytes(), provider().crypto()).unwrap();
            FINGERPRINT.check(m).unwrap();
            assert_eq!(
                m.attributes.0.last().unwrap().typ,
                stun::attributes::ATTR_FINGERPRINT
            );
        }
    }
}

// --- Section 5.1.2.1, RFC 8421 Section 4, RFC 6544 Section 4.2: local preferences ---

fn candidate(network: &str, address: &str, port: u16, tcp_type: TcpType) -> Candidate {
    CandidateHostConfig {
        base_config: CandidateConfig {
            network: network.to_owned(),
            address: address.to_owned(),
            port,
            component: 1,
            ..Default::default()
        },
        tcp_type,
    }
    .new_candidate_host()
    .unwrap()
}

/// Section 5.1.2.1: candidates of one type get a unique local preference each, so no two local
/// candidates share a priority; one address alone keeps 65535. RFC 8421 Section 4: the two
/// address families are interleaved, through the local preference.
#[test]
fn test_local_candidates_of_one_type_get_unique_interleaved_priorities() {
    let mut a = Agent::new(Instant::now(), Arc::new(config(true)), provider()).unwrap();
    for (address, port) in [
        ("192.0.2.1", 1000),
        ("192.0.2.2", 1000),
        ("192.0.2.3", 1000),
        ("2001:db8::1", 1000),
        ("2001:db8::2", 1000),
    ] {
        assert!(
            a.add_local_candidate(candidate("udp", address, port, TcpType::Unspecified))
                .unwrap()
        );
    }
    let local_preference = |i: usize| -> u32 { (a.local_candidates[i].priority() >> 8) & 0xffff };
    // The first candidate of the type keeps the largest value.
    assert_eq!(a.local_candidates[0].priority(), 2130706431);
    // IPv4 came first: IPv4 takes 65535, 65533, 65531; IPv6 takes 65534, 65532.
    assert_eq!(
        (0..5).map(local_preference).collect::<Vec<_>>(),
        vec![65535, 65533, 65531, 65534, 65532]
    );
    // Section 5.1.2.2: relayed candidates from several TURN servers differ as well.
    for (address, server) in [
        ("198.51.100.1", "turn:one.example"),
        ("198.51.100.2", "turn:two.example"),
    ] {
        let relay = crate::candidate::candidate_relay::CandidateRelayConfig {
            base_config: CandidateConfig {
                network: "udp".to_owned(),
                address: address.to_owned(),
                port: 3478,
                component: 1,
                ..Default::default()
            },
            rel_addr: "192.0.2.1".to_owned(),
            rel_port: 1000,
            url: Some(server.to_owned()),
        }
        .new_candidate_relay()
        .unwrap();
        assert!(a.add_local_candidate(relay).unwrap());
    }
    assert_eq!(a.local_candidates[5].priority(), 16777215);
    assert_eq!(a.local_candidates[6].priority(), 16777215 - (2 << 8));
    let mut priorities: Vec<u32> = a.local_candidates.iter().map(|c| c.priority()).collect();
    priorities.sort_unstable();
    priorities.dedup();
    assert_eq!(priorities.len(), 7, "priorities are unique");
    for c in &a.local_candidates {
        assert!((1..=(1u32 << 31) - 1).contains(&c.priority()));
    }
}

/// RFC 6544 Section 4.2: TCP candidates with the same type preference and direction-pref have
/// a unique other-pref; a single one keeps 8191.
#[test]
fn test_tcp_candidates_of_one_direction_get_unique_other_prefs() {
    let mut a = Agent::new(Instant::now(), Arc::new(config(true)), provider()).unwrap();
    a.add_local_candidate(candidate("tcp", "192.168.1.2", 4000, TcpType::Passive))
        .unwrap();
    a.add_local_candidate(candidate("tcp", "10.0.0.2", 4000, TcpType::Passive))
        .unwrap();
    a.add_local_candidate(candidate("tcp", "192.168.1.2", 9, TcpType::Active))
        .unwrap();
    let pref = |i: usize| a.local_candidates[i].local_preference();
    assert_eq!(pref(0), (4 << 13) + 8191);
    // (The odd ranks are the other address family's.)
    assert_eq!(pref(1), (4 << 13) + 8189);
    // Another direction is another group: it starts at 8191 again.
    assert_eq!(pref(2), (6 << 13) + 8191);
    assert_ne!(
        a.local_candidates[0].priority(),
        a.local_candidates[1].priority()
    );
}

/// A priority or a rank the application chose is kept, and the candidates around it still get
/// preferences of their own (RFC 8421 Section 3: an unreliable interface goes last).
#[test]
fn test_application_priorities_and_ranks_are_kept() {
    let mut a = Agent::new(Instant::now(), Arc::new(config(true)), provider()).unwrap();
    a.add_local_candidate(host_with_priority(addr("192.0.2.1:1000"), 12345))
        .unwrap();
    let mut unreliable = host(addr("192.0.2.2:1000"));
    unreliable.set_local_preference_rank(1000);
    a.add_local_candidate(unreliable).unwrap();
    a.add_local_candidate(host(addr("192.0.2.3:1000"))).unwrap();
    assert_eq!(a.local_candidates[0].priority(), 12345);
    assert_eq!(a.local_candidates[1].local_preference(), 65535 - 1000);
    assert_eq!(a.local_candidates[2].local_preference(), 65535);
}

/// Section 7.3.1.3: a peer-reflexive remote candidate is paired with the local candidate the
/// request arrived on, and with no other local candidate.
#[test]
fn test_peer_reflexive_remote_candidate_is_paired_with_the_arrival_candidate_only() {
    let now = Instant::now();
    let mut a = bare_agent(now, config(false));
    a.add_local_candidate(host(addr("192.168.0.9:1000")))
        .unwrap();
    a.start_connectivity_checks(now, false, REMOTE_UFRAG.to_owned(), REMOTE_PWD.to_owned())
        .unwrap();
    assert!(a.candidate_pairs.is_empty());

    let m = peer_request(
        &a,
        vec![Box::new(AttrControlling(1)), Box::new(PriorityAttr(77))],
    );
    deliver(&mut a, now, &m, REMOTE_A).unwrap();

    assert_eq!(a.remote_candidates.len(), 1);
    assert_eq!(a.candidate_pairs.len(), 1);
    let pair = a.candidate_pairs[0];
    assert_eq!(a.local_candidates[pair.local_index].addr(), addr(LOCAL));
    assert_eq!(pair.remote_priority, 77);
}
