//! ICE-TCP (RFC 6544) and the privacy rules of draft-ietf-mmusic-mdns-ice-candidates, at the
//! agent.

use std::time::{Duration, Instant};

use sansio::Protocol;

use super::agent_rfc8445_test::*;
use super::*;
use crate::attributes::control::AttrControlling;
use crate::attributes::priority::PriorityAttr;
use crate::attributes::use_candidate::UseCandidateAttr;
use crate::candidate::candidate_host::CandidateHostConfig;
use crate::candidate::candidate_relay::CandidateRelayConfig;
use crate::candidate::candidate_server_reflexive::CandidateServerReflexiveConfig;

const MDNS_NAME: &str = "9b36eaac-bb2e-49bb-bb78-21c41c499900.local";

fn relay(address: &str) -> Candidate {
    CandidateRelayConfig {
        base_config: CandidateConfig {
            network: "udp".to_owned(),
            address: address.to_owned(),
            port: 3478,
            component: 1,
            ..Default::default()
        },
        rel_addr: "192.168.0.2".to_owned(),
        rel_port: 1000,
        url: None,
    }
    .new_candidate_relay()
    .unwrap()
}

fn srflx(address: &str, base: SocketAddr) -> Candidate {
    CandidateServerReflexiveConfig {
        base_config: CandidateConfig {
            network: "udp".to_owned(),
            address: address.to_owned(),
            port: 4000,
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

/// A remote mDNS host candidate, as it is once its name has been resolved to `ip`.
fn resolved_mdns_candidate(ip: &str) -> Candidate {
    let mut c = CandidateHostConfig {
        base_config: CandidateConfig {
            network: "udp".to_owned(),
            address: MDNS_NAME.to_owned(),
            port: 5000,
            component: 1,
            ..Default::default()
        },
        ..Default::default()
    }
    .new_candidate_host()
    .unwrap();
    c.set_ip(&ip.parse().unwrap()).unwrap();
    c
}

/// mDNS draft Section 3.3.2: "an ICE agent MUST NOT form candidate pairs between its own relay
/// candidates and remote mDNS candidates" (the TURN server would learn the hidden address).
/// Its host candidates pair with them as usual.
#[test]
fn test_relay_candidate_is_not_paired_with_a_remote_mdns_candidate() {
    let mut a = bare_agent(Instant::now(), config(true));
    a.add_local_candidate(relay("198.51.100.1")).unwrap();
    assert_eq!(a.local_candidates.len(), 2);

    assert_eq!(
        a.trigger_request_connectivity_check(vec![resolved_mdns_candidate("192.168.0.7")]),
        1
    );
    assert_eq!(a.candidate_pairs.len(), 1);
    let pair = a.candidate_pairs[0];
    assert_eq!(
        a.local_candidates[pair.local_index].candidate_type(),
        CandidateType::Host
    );

    // A candidate signalled with its address pairs with both.
    a.add_remote_candidate(host(addr(REMOTE_A))).unwrap();
    assert_eq!(a.candidate_pairs.len(), 3);
}

/// mDNS draft Section 3.2.1, step 2: with the relay-only policy a remote mDNS candidate is
/// ignored: no query for its name leaves the host.
#[test]
fn test_relay_only_agent_does_not_resolve_mdns_candidates() {
    let mdns_candidate = || {
        CandidateHostConfig {
            base_config: CandidateConfig {
                network: "udp".to_owned(),
                address: MDNS_NAME.to_owned(),
                port: 5000,
                component: 1,
                ..Default::default()
            },
            ..Default::default()
        }
        .new_candidate_host()
        .unwrap()
    };
    let queries = |candidate_types: Vec<CandidateType>| {
        let now = Instant::now();
        let cfg = AgentConfig {
            candidate_types,
            multicast_dns_mode: crate::mdns::MulticastDnsMode::QueryOnly,
            ..config(true)
        };
        let mut a = Agent::new(now, Arc::new(cfg), provider()).unwrap();
        a.add_remote_candidate(mdns_candidate()).unwrap();
        a.handle_timeout(now).unwrap();
        let mut sent = 0;
        while a.poll_write().is_some() {
            sent += 1;
        }
        (sent, a.mdns_queries.len())
    };
    assert_eq!(queries(vec![CandidateType::Relay]), (0, 0));
    let (sent, pending) = queries(vec![]);
    assert!(
        sent >= 1 && pending == 1,
        "the default policy resolves the name"
    );
}

/// mDNS draft Section 3.1.2.2: with host addresses hidden behind mDNS names, a
/// server-reflexive candidate is signalled with raddr 0.0.0.0 and rport 9; the agent still
/// sends from its real base.
#[test]
fn test_reflexive_candidate_does_not_signal_a_hidden_base() {
    let local = addr(LOCAL);
    for (mode, hidden) in [
        (crate::mdns::MulticastDnsMode::QueryAndGather, true),
        (crate::mdns::MulticastDnsMode::QueryOnly, false),
    ] {
        let cfg = AgentConfig {
            multicast_dns_mode: mode,
            ..config(true)
        };
        let mut a = Agent::new(Instant::now(), Arc::new(cfg), provider()).unwrap();
        a.add_local_candidate(host(local)).unwrap();
        a.add_local_candidate(srflx("203.0.113.5", local)).unwrap();
        let reflexive = &a.local_candidates[1];
        let line = reflexive.marshal();
        if hidden {
            assert!(a.local_candidates[0].address().ends_with(".local"));
            assert!(line.contains("raddr 0.0.0.0 rport 9"), "{line}");
            assert!(!line.contains("192.168.0.2"), "{line}");
        } else {
            assert!(line.contains("raddr 192.168.0.2 rport 1000"), "{line}");
        }
        assert_eq!(reflexive.base_addr(), local);
        // A server-reflexive candidate is not redundant with the mDNS host candidate.
        assert_eq!(a.get_local_candidates_to_signal().len(), 2);
    }

    // The same for the server-reflexive candidate of a 1:1 NAT mapping.
    let cfg = AgentConfig {
        multicast_dns_mode: crate::mdns::MulticastDnsMode::QueryAndGather,
        nat_1to1_ips: vec!["203.0.113.7".to_owned()],
        nat_1to1_ip_candidate_type: CandidateType::ServerReflexive,
        ..config(true)
    };
    let mut a = Agent::new(Instant::now(), Arc::new(cfg), provider()).unwrap();
    a.add_local_candidate(host(local)).unwrap();
    assert_eq!(a.local_candidates.len(), 2);
    let line = a.local_candidates[1].marshal();
    assert!(line.contains("typ srflx raddr 0.0.0.0 rport 9"), "{line}");
}

/// mDNS draft Section 3.3.1: the address of a peer-reflexive remote candidate is not in the
/// statistics unless the peer signalled that address itself: before the peer's mDNS name
/// resolves, a check from behind it would reveal what the name hides.
#[test]
fn test_peer_reflexive_address_is_not_in_statistics_unless_signalled() {
    let now = Instant::now();
    let mut a = started_agent(now, config(false), &[]);
    let request = peer_request(
        &a,
        vec![Box::new(AttrControlling(1)), Box::new(PriorityAttr(1000))],
    );
    deliver(&mut a, now, &request, REMOTE_A).unwrap();
    let stats = a.get_remote_candidates_stats(now);
    assert_eq!(stats.len(), 1);
    assert_eq!(stats[0].candidate_type, CandidateType::PeerReflexive);
    assert_eq!(stats[0].ip, "", "the address is withheld");
    assert!(!a.is_signalled_remote_ip(addr(REMOTE_A).ip()));

    // The name resolving to that address does not make it "signalled": the candidate that
    // replaces the learned one shows its name.
    a.trigger_request_connectivity_check(vec![{
        let mut c = resolved_mdns_candidate("192.168.0.3");
        c.port = addr(REMOTE_A).port();
        c.resolved_addr = addr(REMOTE_A);
        c
    }]);
    let stats = a.get_remote_candidates_stats(now);
    assert_eq!(stats.len(), 1);
    assert_eq!(stats[0].ip, MDNS_NAME);

    // An address the peer signals is shown, on a learned candidate too.
    let mut b = started_agent(now, config(false), &["192.168.0.3:9999"]);
    let request = peer_request(
        &b,
        vec![Box::new(AttrControlling(1)), Box::new(PriorityAttr(1000))],
    );
    deliver(&mut b, now, &request, REMOTE_A).unwrap();
    let stats = b.get_remote_candidates_stats(now);
    assert_eq!(stats[1].candidate_type, CandidateType::PeerReflexive);
    assert_eq!(stats[1].ip, "192.168.0.3");
}

/// RFC 6544 Section 4.5: every TCP candidate is signalled with `tcptype`, an extension
/// attribute: it follows raddr / rport and may stand anywhere among the extensions.
#[test]
fn test_tcptype_is_read_and_written_for_every_candidate_type() {
    for (line, tcp_type) in [
        (
            "1 1 tcp 1 192.0.2.3 4000 typ srflx raddr 10.0.0.1 rport 4000 tcptype passive",
            TcpType::Passive,
        ),
        (
            "1 1 tcp 1 192.0.2.3 4000 typ host generation 0 tcptype passive",
            TcpType::Passive,
        ),
        (
            "1 1 tcp 1 192.0.2.3 9 typ relay raddr 10.0.0.1 rport 9 generation 0 tcptype active ufrag x",
            TcpType::Active,
        ),
        (
            "1 1 tcp 1 192.0.2.3 4000 typ host tcptype so",
            TcpType::SimultaneousOpen,
        ),
    ] {
        let c = unmarshal_candidate(line).unwrap();
        assert_eq!(c.tcp_type(), tcp_type, "{line}");
    }

    let reflexive = unmarshal_candidate(
        "1 1 tcp 1 192.0.2.3 4000 typ srflx raddr 10.0.0.1 rport 4000 tcptype passive",
    )
    .unwrap();
    let written = reflexive.marshal();
    assert!(
        written.ends_with("typ srflx raddr 10.0.0.1 rport 4000 tcptype passive"),
        "{written}"
    );
    assert_eq!(
        unmarshal_candidate(&written).unwrap().tcp_type(),
        TcpType::Passive
    );
    // Such a candidate pairs with a local active one.
    let active = CandidateHostConfig {
        base_config: CandidateConfig {
            network: "tcp".to_owned(),
            address: "192.168.0.2".to_owned(),
            port: 9,
            component: 1,
            ..Default::default()
        },
        tcp_type: TcpType::Active,
    }
    .new_candidate_host()
    .unwrap();
    assert!(active.can_pair_with(&reflexive));
}

/// RFC 6544 Section 11.1: when the selected pair's connection is lost the active side opens
/// it again; on the passive side the new connection (another source port) becomes the path
/// data is sent on and accepted from.
#[test]
fn test_reopened_tcp_connection_becomes_the_media_path() {
    let now = Instant::now();
    let listener: SocketAddr = "192.168.0.2:7000".parse().unwrap();
    let cfg = AgentConfig {
        failed_timeout: Some(Duration::ZERO),
        ..config(false)
    };
    let mut a = Agent::new(now, Arc::new(cfg), provider()).unwrap();
    a.add_local_candidate(
        CandidateHostConfig {
            base_config: CandidateConfig {
                network: "tcp".to_owned(),
                address: listener.ip().to_string(),
                port: listener.port(),
                component: 1,
                ..Default::default()
            },
            tcp_type: TcpType::Passive,
        }
        .new_candidate_host()
        .unwrap(),
    )
    .unwrap();
    a.start_connectivity_checks(now, false, REMOTE_UFRAG.to_owned(), REMOTE_PWD.to_owned())
        .unwrap();

    // A connection from `from`: the peer's check on it, our triggered check, its answer.
    let connect = |a: &mut Agent, at: Instant, from: &str, nominate: bool| {
        let from: SocketAddr = from.parse().unwrap();
        let read = |a: &mut Agent, m: &Message| {
            a.handle_read(TaggedBytesMut {
                now: at,
                transport: TransportContext {
                    local_addr: listener,
                    peer_addr: from,
                    ecn: None,
                    transport_protocol: TransportProtocol::TCP,
                },
                message: BytesMut::from(&m.raw[..]),
            })
            .unwrap();
        };
        let mut attrs: Vec<Box<dyn Setter>> =
            vec![Box::new(AttrControlling(1)), Box::new(PriorityAttr(1000))];
        if nominate {
            attrs.push(Box::new(UseCandidateAttr::new()));
        }
        read(a, &peer_request(a, attrs));
        a.handle_timeout(at).unwrap();
        let check = sent(a)
            .into_iter()
            .find(|(m, to)| m.typ == BINDING_REQUEST && *to == from)
            .expect("a triggered check on the connection")
            .0;
        read(
            a,
            &peer_response(BINDING_SUCCESS, check.transaction_id, listener, None),
        );
    };

    connect(&mut a, now, "192.168.0.3:40001", true);
    let path = a.media_path().expect("selected");
    assert_eq!(path.peer_addr, addr("192.168.0.3:40001"));
    assert_eq!(path.transport_protocol, TransportProtocol::TCP);

    // The connection drops; the active side dials again, from another port, and checks the
    // new connection (a consent check: no USE-CANDIDATE, the pair is nominated already).
    let later = now + Duration::from_secs(3);
    connect(&mut a, later, "192.168.0.3:40002", false);
    let path = a.media_path().unwrap();
    assert_eq!(path.local_addr, listener);
    assert_eq!(path.peer_addr, addr("192.168.0.3:40002"));
    let changes: Vec<SocketAddr> = std::iter::from_fn(|| a.poll_event())
        .filter_map(|e| match e.event {
            Event::SelectedCandidatePairChange(_, remote) => Some(remote.addr()),
            _ => None,
        })
        .collect();
    assert_eq!(
        changes,
        vec![addr("192.168.0.3:40001"), addr("192.168.0.3:40002")]
    );

    // A connection from another host is another candidate, not a reconnection.
    connect(
        &mut a,
        later + Duration::from_secs(1),
        "192.168.0.99:40003",
        false,
    );
    assert_eq!(a.media_path().unwrap().peer_addr, addr("192.168.0.3:40002"));
}
