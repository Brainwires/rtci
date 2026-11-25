//! The embedder's address policy (`AgentConfig::address_policy`, an [`IceAddressPolicy`]): what
//! it refuses the agent never answers, learns, pairs or takes data from, and what it allows
//! works as without it.
//!
//! Agents are driven sans-I/O on a virtual clock: datagrams are carried by hand from one
//! agent's `poll_write` to the other's `handle_read`.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use sansio::Protocol;
use stun::attributes::ATTR_USERNAME;

use super::remote_policy::{AddressDirection, AddressPurpose, IceAddressPolicy};
use super::*;
use crate::attributes::priority::PriorityAttr;
use crate::candidate::candidate_host::CandidateHostConfig;
use crate::candidate::{CandidateConfig, unmarshal_candidate};
use crate::mdns::MulticastDnsMode;

fn provider() -> Arc<dyn crypto::RTCCryptoProvider> {
    crypto::default_provider().expect("a built-in crypto provider must be enabled for tests")
}

const LOCAL: &str = "192.168.0.2:777";
const A_ADDR: &str = "192.168.0.1:5000";
const B_ADDR: &str = "192.168.0.3:5001";
const STEP: Duration = Duration::from_millis(50);

fn addr(s: &str) -> SocketAddr {
    s.parse().unwrap()
}

fn host(a: &str) -> Candidate {
    let a = addr(a);
    CandidateHostConfig {
        base_config: CandidateConfig {
            network: "udp".to_owned(),
            address: a.ip().to_string(),
            port: a.port(),
            component: 1,
            ..Default::default()
        },
        ..Default::default()
    }
    .new_candidate_host()
    .unwrap()
}

/// Every question the policy was asked, in order.
type Asked = Arc<Mutex<Vec<(SocketAddr, AddressDirection, AddressPurpose)>>>;

/// A policy refusing `refused` (by IP address) for `purpose` only, every other question
/// allowed; it records what it is asked.
fn refusing(refused: &[&str], purpose: AddressPurpose) -> (IceAddressPolicy, Asked) {
    let refused: Vec<IpAddr> = refused.iter().map(|s| s.parse().unwrap()).collect();
    let asked: Asked = Arc::default();
    let log = asked.clone();
    let policy = IceAddressPolicy::new(move |a, direction, p| {
        log.lock().unwrap().push((a, direction, p));
        !(p == purpose && refused.contains(&a.ip()))
    });
    (policy, asked)
}

fn config(policy: IceAddressPolicy) -> AgentConfig {
    AgentConfig {
        multicast_dns_mode: MulticastDnsMode::Disabled,
        address_policy: policy,
        ..Default::default()
    }
}

/// An agent with one local host candidate on `LOCAL` and the peer's credentials, ready for
/// checks from anywhere.
fn listening_agent(policy: IceAddressPolicy) -> Agent {
    let mut a = Agent::new(Instant::now(), Arc::new(config(policy)), provider()).unwrap();
    a.add_local_candidate(host(LOCAL)).unwrap();
    a.set_remote_credentials("remoteufrag".to_owned(), "remotepwd".to_owned())
        .unwrap();
    a
}

/// An authenticated Binding request of the peer to `a` (as RFC 8445 Section 7.2.2 builds it,
/// without a role attribute so that no role conflict is in play).
fn peer_request(a: &Agent) -> BytesMut {
    let mut m = Message::new();
    m.build(&[
        Box::new(BINDING_REQUEST),
        Box::new(TransactionId::new()),
        Box::new(Username::new(
            ATTR_USERNAME,
            a.ufrag_pwd.local_credentials.ufrag.clone() + ":remoteufrag",
        )),
        Box::new(PriorityAttr(1_845_501_695)),
        Box::new(MessageIntegrity::new_short_term_integrity_with_provider(
            a.ufrag_pwd.local_credentials.pwd.clone(),
            provider().crypto(),
        )),
        Box::new(FINGERPRINT),
    ])
    .unwrap();
    BytesMut::from(&m.raw[..])
}

fn udp(local: SocketAddr, peer: SocketAddr) -> TransportContext {
    TransportContext {
        local_addr: local,
        peer_addr: peer,
        ecn: None,
        transport_protocol: TransportProtocol::UDP,
    }
}

/// Hands `message` to `a` as a datagram from `from` to `LOCAL`; returns where what `a` writes
/// goes.
fn read_from(a: &mut Agent, from: &str, message: BytesMut) -> Vec<SocketAddr> {
    let _ = a.handle_read(TaggedBytesMut {
        now: Instant::now(),
        transport: udp(addr(LOCAL), addr(from)),
        message,
    });
    a.handle_timeout(Instant::now()).unwrap();
    std::iter::from_fn(|| a.poll_write())
        .map(|w| w.transport.peer_addr)
        .collect()
}

/// A datagram from a source the policy refuses is dropped before the agent reads it: an
/// authenticated Binding request from it gets no response, teaches no peer-reflexive
/// candidate and creates no pair. The same request from an allowed source is answered and its
/// source learned (RFC 8445 Sections 7.3.1.2 and 7.3.1.3), so the request itself was good.
#[test]
fn test_a_denied_sources_binding_request_gets_no_answer_and_creates_no_candidate_or_pair() {
    let (policy, asked) = refusing(&["172.17.0.66"], AddressPurpose::InboundDatagramSource);
    let mut a = listening_agent(policy);

    let request = peer_request(&a);
    let written = read_from(&mut a, "172.17.0.66:999", request);
    assert!(
        written.is_empty(),
        "nothing answers a refused source: {written:?}"
    );
    assert!(
        a.remote_candidates.is_empty(),
        "no peer-reflexive candidate"
    );
    assert!(a.candidate_pairs.is_empty(), "no pair");
    assert!(a.early_requests.is_empty());
    assert!(
        asked.lock().unwrap().contains(&(
            addr("172.17.0.66:999"),
            AddressDirection::Inbound,
            AddressPurpose::InboundDatagramSource
        )),
        "the policy is asked about the source, inbound"
    );

    let request = peer_request(&a);
    let written = read_from(&mut a, "172.17.0.3:999", request);
    assert!(
        written.iter().any(|to| *to == addr("172.17.0.3:999")),
        "an allowed source is answered: {written:?}"
    );
    assert_eq!(a.remote_candidates.len(), 1);
    assert_eq!(a.remote_candidates[0].addr(), addr("172.17.0.3:999"));
    a.close().unwrap();
}

/// A policy that refuses something else changes nothing for the addresses it allows: two
/// agents under it connect, and the policy was asked about their addresses (so it was in the
/// path).
#[test]
fn test_an_allowed_source_connects_under_an_address_policy() {
    let base = Instant::now();
    let (policy_a, asked_a) = refusing(&["10.9.9.9"], AddressPurpose::InboundDatagramSource);
    let (policy_b, _) = refusing(&["10.9.9.9"], AddressPurpose::RemoteCandidate);
    let mut a = Agent::new(base, Arc::new(config(policy_a)), provider()).unwrap();
    let mut b = Agent::new(base, Arc::new(config(policy_b)), provider()).unwrap();
    a.add_local_candidate(host(A_ADDR)).unwrap();
    b.add_local_candidate(host(B_ADDR)).unwrap();
    a.add_remote_candidate(host(B_ADDR)).unwrap();
    b.add_remote_candidate(host(A_ADDR)).unwrap();
    connect(&mut a, &mut b, base);
    assert!(
        asked_a
            .lock()
            .unwrap()
            .iter()
            .any(|(s, _, p)| *s == addr(B_ADDR) && *p == AddressPurpose::InboundDatagramSource),
        "the policy was asked about the peer's datagrams"
    );
    a.close().unwrap();
    b.close().unwrap();
}

/// A signalled remote candidate on an address the policy refuses (as a remote candidate) is
/// never held or paired, and no check goes there; another one is checked.
#[test]
fn test_a_denied_remote_candidate_is_never_held_or_paired() {
    let (policy, asked) = refusing(&["192.168.1.20"], AddressPurpose::RemoteCandidate);
    let mut a = Agent::new(Instant::now(), Arc::new(config(policy)), provider()).unwrap();
    a.add_local_candidate(host("192.168.1.10:5000")).unwrap();
    let held = a
        .add_remote_candidate(
            unmarshal_candidate("1 1 udp 2130706431 192.168.1.20 5000 typ host").unwrap(),
        )
        .unwrap();
    assert!(!held, "the refused candidate is not held");
    assert!(
        a.add_remote_candidate(
            unmarshal_candidate("2 1 udp 2130706431 192.168.1.21 5000 typ host").unwrap()
        )
        .unwrap()
    );
    assert!(asked.lock().unwrap().contains(&(
        addr("192.168.1.20:5000"),
        AddressDirection::Outbound,
        AddressPurpose::RemoteCandidate
    )));

    let mut now = Instant::now();
    a.start_connectivity_checks(now, true, "remoteufrag".to_owned(), "remotepwd".to_owned())
        .unwrap();
    let mut sent = vec![];
    for _ in 0..10 {
        a.handle_timeout(now).unwrap();
        while let Some(w) = a.poll_write() {
            sent.push(w.transport.peer_addr);
        }
        now += Duration::from_millis(250);
    }
    assert!(sent.contains(&addr("192.168.1.21:5000")), "{sent:?}");
    assert!(!sent.contains(&addr("192.168.1.20:5000")), "{sent:?}");
    assert_eq!(a.get_remote_candidates().len(), 1);
    for p in &a.candidate_pairs {
        assert_eq!(
            a.remote_candidates[p.remote_index].addr(),
            addr("192.168.1.21:5000")
        );
    }
    a.close().unwrap();
}

/// RFC 8445 Section 7.3.1.3 learns the source of a request from an unknown address as a
/// peer-reflexive candidate; one the policy refuses as such is not learned, so the request
/// is not answered and no pair is made. A signalled candidate on an address of the same rule
/// is still answered: it is not a peer-reflexive source.
#[test]
fn test_a_denied_peer_reflexive_source_is_not_learned_or_answered() {
    let (policy, asked) = refusing(
        &["172.17.0.66", "172.17.0.77"],
        AddressPurpose::PeerReflexiveSource,
    );
    let mut a = listening_agent(policy);
    a.add_remote_candidate(host("172.17.0.77:999")).unwrap();

    let request = peer_request(&a);
    let written = read_from(&mut a, "172.17.0.66:999", request);
    assert!(
        !written.iter().any(|to| *to == addr("172.17.0.66:999")),
        "no answer to a refused peer-reflexive source: {written:?}"
    );
    assert!(a.find_remote_candidate(addr("172.17.0.66:999")).is_none());
    assert!(asked.lock().unwrap().contains(&(
        addr("172.17.0.66:999"),
        AddressDirection::Inbound,
        AddressPurpose::PeerReflexiveSource
    )));

    let request = peer_request(&a);
    let written = read_from(&mut a, "172.17.0.77:999", request);
    assert!(
        written.iter().any(|to| *to == addr("172.17.0.77:999")),
        "a signalled candidate is answered: {written:?}"
    );
    assert_eq!(a.remote_candidates.len(), 1);
    a.close().unwrap();
}

/// RFC 8445 Section 7.3 has a request that arrives before the peer's credentials answered at
/// once and processed when they come. The source of such a request is a peer-reflexive
/// candidate in waiting: one the policy refuses as such gets no answer in that window either
/// (the answer would carry its reflexive address before the policy was asked), and is not
/// learned when the credentials arrive. Another source is answered at once.
#[test]
fn test_a_denied_peer_reflexive_source_is_not_answered_before_the_remote_credentials() {
    let (policy, asked) = refusing(&["172.17.0.66"], AddressPurpose::PeerReflexiveSource);
    let mut a = Agent::new(Instant::now(), Arc::new(config(policy)), provider()).unwrap();
    a.add_local_candidate(host(LOCAL)).unwrap();
    assert!(a.ufrag_pwd.remote_credentials.is_none());

    let request = peer_request(&a);
    let written = read_from(&mut a, "172.17.0.66:999", request);
    assert!(
        written.is_empty(),
        "no answer to a refused peer-reflexive source: {written:?}"
    );
    assert!(asked.lock().unwrap().contains(&(
        addr("172.17.0.66:999"),
        AddressDirection::Inbound,
        AddressPurpose::PeerReflexiveSource
    )));

    let request = peer_request(&a);
    let written = read_from(&mut a, "172.17.0.67:999", request);
    assert_eq!(
        written,
        vec![addr("172.17.0.67:999")],
        "an allowed source is answered before the credentials"
    );

    a.set_remote_credentials("remoteufrag".to_owned(), "remotepwd".to_owned())
        .unwrap();
    a.process_early_requests(Instant::now());
    assert!(a.find_remote_candidate(addr("172.17.0.66:999")).is_none());
    assert!(
        a.find_remote_candidate(addr("172.17.0.67:999")).is_some(),
        "the allowed source is learned once the credentials are here"
    );
    a.close().unwrap();
}

/// A policy that comes to refuse the peer of a connected pair cuts it off at once: its data is
/// no longer accepted (`accepts_data`), its consent requests get no answer, and the responses
/// to the agent's own consent checks no longer refresh consent, so the agent leaves the
/// connected state when consent expires (RFC 7675).
#[test]
fn test_a_source_refused_after_connecting_gets_nothing_and_loses_consent() {
    let base = Instant::now();
    let cut = Arc::new(AtomicBool::new(false));
    let flag = cut.clone();
    let b_ip: IpAddr = addr(B_ADDR).ip();
    let policy = IceAddressPolicy::new(move |a, _, purpose| {
        !(flag.load(Ordering::SeqCst)
            && purpose == AddressPurpose::InboundDatagramSource
            && a.ip() == b_ip)
    });
    let mut a = Agent::new(base, Arc::new(config(policy)), provider()).unwrap();
    let mut b = Agent::new(
        base,
        Arc::new(config(IceAddressPolicy::default())),
        provider(),
    )
    .unwrap();
    a.add_local_candidate(host(A_ADDR)).unwrap();
    b.add_local_candidate(host(B_ADDR)).unwrap();
    a.add_remote_candidate(host(B_ADDR)).unwrap();
    b.add_remote_candidate(host(A_ADDR)).unwrap();
    let mut now = connect(&mut a, &mut b, base);
    let from_b = udp(addr(A_ADDR), addr(B_ADDR));
    assert!(a.accepts_data(from_b), "the connected peer's data is taken");
    assert!(a.is_valid_non_stun_traffic(now, from_b));

    cut.store(true, Ordering::SeqCst);
    assert!(!a.accepts_data(from_b), "no data from a refused source");
    assert!(a.data_path(from_b).is_none());
    assert!(!a.is_valid_non_stun_traffic(now, from_b));

    // b's consent requests reach a and are not answered.
    let request = peer_request_to(&a);
    let _ = a.handle_read(TaggedBytesMut {
        now,
        transport: from_b,
        message: request,
    });
    let answered = std::iter::from_fn(|| a.poll_write()).any(|w| is_response(&w.message));
    assert!(!answered, "a refused source gets no response");

    for _ in 0..800 {
        now += STEP;
        a.handle_timeout(now).unwrap();
        b.handle_timeout(now).unwrap();
        settle(&mut a, &mut b, now);
    }
    assert_ne!(
        a.state(),
        ConnectionState::Connected,
        "consent from the refused source is never refreshed"
    );
    a.close().unwrap();
    b.close().unwrap();
}

/// A Binding request to `a` from its connected peer (the peer's credentials are `a`'s remote
/// ones).
fn peer_request_to(a: &Agent) -> BytesMut {
    let remote = a.ufrag_pwd.remote_credentials.clone().unwrap();
    let mut m = Message::new();
    m.build(&[
        Box::new(BINDING_REQUEST),
        Box::new(TransactionId::new()),
        Box::new(Username::new(
            ATTR_USERNAME,
            a.ufrag_pwd.local_credentials.ufrag.clone() + ":" + &remote.ufrag,
        )),
        Box::new(PriorityAttr(1_845_501_695)),
        Box::new(MessageIntegrity::new_short_term_integrity_with_provider(
            a.ufrag_pwd.local_credentials.pwd.clone(),
            provider().crypto(),
        )),
        Box::new(FINGERPRINT),
    ])
    .unwrap();
    BytesMut::from(&m.raw[..])
}

fn is_response(datagram: &[u8]) -> bool {
    let mut m = Message::new();
    m.unmarshal_binary(datagram).is_ok()
        && (m.typ.class == CLASS_SUCCESS_RESPONSE || m.typ.class == CLASS_ERROR_RESPONSE)
}

fn carry(out: TaggedBytesMut, to: &mut Agent, now: Instant) {
    let _ = to.handle_read(TaggedBytesMut {
        now,
        transport: udp(out.transport.peer_addr, out.transport.local_addr),
        message: out.message,
    });
}

fn settle(a: &mut Agent, b: &mut Agent, now: Instant) {
    for _ in 0..64 {
        let mut moved = 0;
        while let Some(out) = a.poll_write() {
            carry(out, b, now);
            moved += 1;
        }
        while let Some(out) = b.poll_write() {
            carry(out, a, now);
            moved += 1;
        }
        if moved == 0 {
            return;
        }
    }
}

/// Starts checks (`a` controls) and ticks both agents until both are connected; returns when.
fn connect(a: &mut Agent, b: &mut Agent, base: Instant) -> Instant {
    let a_credentials = a.get_local_credentials().clone();
    let b_credentials = b.get_local_credentials().clone();
    a.start_connectivity_checks(base, true, b_credentials.ufrag, b_credentials.pwd)
        .unwrap();
    b.start_connectivity_checks(base, false, a_credentials.ufrag, a_credentials.pwd)
        .unwrap();
    let mut now = base;
    for _ in 0..200 {
        a.handle_timeout(now).unwrap();
        b.handle_timeout(now).unwrap();
        settle(a, b, now);
        if a.state() == ConnectionState::Connected && b.state() == ConnectionState::Connected {
            return now;
        }
        now += STEP;
    }
    panic!(
        "the agents did not connect: a {:?}, b {:?}",
        a.state(),
        b.state()
    );
}
