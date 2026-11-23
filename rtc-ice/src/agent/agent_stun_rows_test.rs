//! RFC 8489 rows the agent's own STUN transactions answer to: a transaction whose responses
//! all failed their integrity check ends as an integrity violation, not a timeout (Section
//! 9.1.4). Read from the wire in virtual time, as the other agent tests.

use std::time::{Duration, Instant};

use super::agent_rfc8445_test::*;
use super::*;

fn first_check(a: &mut Agent, now: Instant) -> (Message, SocketAddr) {
    let out = run(a, now, now + Duration::from_millis(100));
    requests(&out)
        .first()
        .map(|(m, to)| (m.clone(), *to))
        .expect("the agent sends a check")
}

/// A success response to `id` signed with `key`.
fn response_signed_with(id: TransactionId, mapped: SocketAddr, key: &str) -> Message {
    let provider = provider();
    let mut msg = Message::new();
    msg.build(&[
        Box::new(BINDING_SUCCESS),
        Box::new(id),
        Box::new(XorMappedAddress {
            ip: mapped.ip(),
            port: mapped.port(),
        }),
        Box::new(MessageIntegrity::new_short_term_integrity_with_provider(
            key.to_owned(),
            provider.crypto(),
        )),
        Box::new(FINGERPRINT),
    ])
    .unwrap();
    msg
}

fn integrity_violations(a: &mut Agent) -> Vec<SocketAddr> {
    std::iter::from_fn(|| a.poll_event())
        .filter_map(|e| match e.event {
            Event::IntegrityViolation(_, remote) => Some(remote.addr()),
            _ => None,
        })
        .collect()
}

/// Section 9.1.4: "If all responses received are discarded, then instead of signaling a
/// timeout after ending the transaction, the layer MUST signal an integrity protection
/// violation." A check answered only with responses signed with the wrong password ends with
/// `Event::IntegrityViolation` for its pair; one that is not answered at all does not.
#[test]
fn test_check_answered_only_by_unauthentic_responses_ends_as_an_integrity_violation() {
    let now = Instant::now();
    let mut a = started_agent(now, config(true), &[REMOTE_A, REMOTE_B]);
    let (check, to) = first_check(&mut a, now);
    let forged = response_signed_with(check.transaction_id, addr(LOCAL), "not-the-peers-password");
    assert!(
        deliver(&mut a, now, &forged, &to.to_string()).is_err(),
        "discarded"
    );
    let pair = a
        .candidate_pairs
        .iter()
        .position(|p| a.remote_candidates[p.remote_index].addr() == to)
        .unwrap();
    assert_ne!(
        a.candidate_pairs[pair].state,
        CandidatePairState::Succeeded,
        "a discarded response validates nothing"
    );

    // (Once every pair has failed the agent fails and drops its pairs: the events tell.)
    let _ = run(&mut a, now, now + Duration::from_secs(60));
    let violations = integrity_violations(&mut a);
    assert_eq!(
        violations,
        vec![to],
        "the forged pair is an integrity violation, the unanswered one a timeout"
    );
}

/// A response that passes after one that did not completes the transaction: no violation.
#[test]
fn test_authentic_response_after_an_unauthentic_one_completes_the_check() {
    let now = Instant::now();
    let mut a = started_agent(now, config(true), &[REMOTE_A]);
    let (check, to) = first_check(&mut a, now);
    let forged = response_signed_with(check.transaction_id, addr(LOCAL), "not-the-peers-password");
    let _ = deliver(&mut a, now, &forged, &to.to_string());
    let genuine = response_signed_with(check.transaction_id, addr(LOCAL), REMOTE_PWD);
    deliver(&mut a, now, &genuine, &to.to_string()).unwrap();
    assert_eq!(a.candidate_pairs[0].state, CandidatePairState::Succeeded);
    let _ = run(&mut a, now, now + Duration::from_secs(60));
    assert!(integrity_violations(&mut a).is_empty());
}

/// An agent whose checks carry USERNAME `<250 chars>:<250 chars>` (long ufrags, as RFC 8839
/// allows a peer to receive, within the 509 bytes of a STUN USERNAME): about 580 bytes of
/// STUN, more than fits an IPv4 path of unknown MTU. The agent refuses to be configured with
/// a ufrag longer than the 32 characters it may send (RFC 8839 section 5.4), so the long one is
/// put in place after construction.
fn agent_with_long_ufrags(now: Instant, path_mtu: Option<usize>) -> Agent {
    let cfg = AgentConfig {
        local_pwd: "p".repeat(32),
        path_mtu,
        ..config(true)
    };
    let mut a = bare_agent(now, cfg);
    a.ufrag_pwd.local_credentials.ufrag = "l".repeat(250);
    a.add_remote_candidate(host(addr(REMOTE_A))).unwrap();
    a.start_connectivity_checks(now, true, "r".repeat(250), REMOTE_PWD.to_owned())
        .unwrap();
    a
}

/// Section 6.1: "If the path MTU is unknown for UDP, messages SHOULD be the smaller of 576
/// bytes and the first-hop MTU for IPv4" and "the STUN usage MUST follow the MTU constraint".
/// A check that does not fit is not sent and its pair fails; with the path MTU known to be
/// larger, it is sent.
#[test]
fn test_check_larger_than_the_path_mtu_is_not_sent_and_fails_the_pair() {
    let now = Instant::now();
    let mut a = agent_with_long_ufrags(now, None);
    let out = run(&mut a, now, now + Duration::from_secs(5));
    assert!(
        requests(&out).is_empty(),
        "a check over 548 bytes left over UDP/IPv4"
    );
    assert!(out.iter().all(|(m, _)| m.raw.len() <= 548));
    // The pair failed at once.
    assert_eq!(a.candidate_pairs[0].state, CandidatePairState::Failed);

    let mut a = agent_with_long_ufrags(now, Some(1500));
    let out = run(&mut a, now, now + Duration::from_millis(200));
    let checks = requests(&out);
    assert!(!checks.is_empty(), "the check fits a 1500-byte path");
    assert!(checks[0].0.raw.len() > 548);
}

/// Section 9.1.4: the agent's checks carry MESSAGE-INTEGRITY only, so "the algorithm in the
/// response has to match; otherwise, the response MUST be discarded": a response authenticated
/// with MESSAGE-INTEGRITY-SHA256 (with the right password) validates nothing. Section 9.1.5:
/// every later request to the peer carries MESSAGE-INTEGRITY only too.
#[test]
fn test_checks_carry_message_integrity_only_and_a_sha256_response_is_discarded() {
    let now = Instant::now();
    let mut a = started_agent(now, config(true), &[REMOTE_A]);
    let (check, to) = first_check(&mut a, now);
    let provider = provider();
    let mut sha256 = Message::new();
    sha256
        .build(&[
            Box::new(BINDING_SUCCESS),
            Box::new(check.transaction_id),
            Box::new(XorMappedAddress {
                ip: addr(LOCAL).ip(),
                port: addr(LOCAL).port(),
            }),
            Box::new(MessageIntegritySha256::short_term(REMOTE_PWD, provider.crypto()).unwrap()),
            Box::new(FINGERPRINT),
        ])
        .unwrap();
    assert!(deliver(&mut a, now, &sha256, &to.to_string()).is_err());
    assert_ne!(a.candidate_pairs[0].state, CandidatePairState::Succeeded);

    // The check goes on (retransmitted); answered with MESSAGE-INTEGRITY, it succeeds, and
    // every request sent, the nomination and later ones included, carries that attribute only.
    let genuine = response_signed_with(check.transaction_id, addr(LOCAL), REMOTE_PWD);
    deliver(&mut a, now, &genuine, &to.to_string()).unwrap();
    assert_eq!(a.candidate_pairs[0].state, CandidatePairState::Succeeded);
    let mut sent = vec![check];
    sent.extend(
        requests(&run(&mut a, now, now + Duration::from_secs(5)))
            .into_iter()
            .map(|(m, _)| m.clone()),
    );
    assert!(sent.len() > 1);
    for m in &sent {
        assert!(m.contains(ATTR_MESSAGE_INTEGRITY));
        assert!(!m.contains(ATTR_MESSAGE_INTEGRITY_SHA256));
    }
}

fn software_of(m: &Message) -> Option<String> {
    Software::get_from_as(m, ATTR_SOFTWARE)
        .ok()
        .map(|software| software.text)
}

/// Sections 6.1 and 6.3.1.1: a request "SHOULD" carry SOFTWARE, and so "SHOULD" a server's
/// response; Section 16.1.2: its use "SHOULD" be configurable. The agent's checks and its
/// success responses carry `rtc-ice <version>` by default, the configured text when given,
/// and none with an empty one.
#[test]
fn test_checks_and_responses_carry_software_unless_configured_off() {
    for (software, expected) in [
        (None, Some(DEFAULT_SOFTWARE.to_owned())),
        (Some("my app 1.0".to_owned()), Some("my app 1.0".to_owned())),
        (Some(String::new()), None),
    ] {
        let now = Instant::now();
        let cfg = AgentConfig {
            software: software.clone(),
            ..config(true)
        };
        let mut a = started_agent(now, cfg, &[REMOTE_A]);
        let (check, _) = first_check(&mut a, now);
        assert_eq!(software_of(&check), expected, "check, {software:?}");
        let request = peer_request(&a, vec![]);
        deliver(&mut a, now, &request, REMOTE_A).unwrap();
        let response = sent(&mut a)
            .into_iter()
            .find(|(m, _)| m.typ == BINDING_SUCCESS)
            .expect("the request is answered");
        assert_eq!(software_of(&response.0), expected, "response, {software:?}");
    }
}

/// RFC 5780 Section 6.1: CHANGE-REQUEST (0x0003), RESPONSE-PORT (0x0027) and PADDING (0x0026)
/// are comprehension-required, and an agent that does not support NAT behaviour discovery
/// answers a request carrying one with 420 (Unknown Attribute) listing it.
#[test]
fn test_request_with_rfc5780_attributes_is_answered_420_listing_them() {
    for code in [0x0003u16, 0x0027, 0x0026] {
        let now = Instant::now();
        let mut a = started_agent(now, config(false), &[]);
        let _ = sent(&mut a);
        let attr = stun::attributes::AttrType(code);
        let m = peer_request(
            &a,
            vec![Box::new(stun::attributes::RawAttribute {
                typ: attr,
                length: 4,
                value: vec![0, 0, 0, 0],
            })],
        );
        assert!(deliver(&mut a, now, &m, REMOTE_A).is_err());
        let out = sent(&mut a);
        assert_eq!(out.len(), 1, "{code:#06x}");
        assert_eq!(out[0].0.typ, BINDING_ERROR);
        assert_eq!(error_code(&out[0].0), 420);
        let mut listed = stun::uattrs::UnknownAttributes(vec![]);
        listed.get_from(&out[0].0).unwrap();
        assert_eq!(listed.0, vec![attr]);
    }
}
