//! The remote-address policy: where a peer can make the agent send connectivity checks.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use sansio::Protocol;

use super::agent_config::AgentConfig;
use super::remote_policy::{AddressScope, RemoteAddressFilter, address_scope};
use super::*;
use crate::candidate::candidate_host::CandidateHostConfig;
use crate::candidate::{CandidateConfig, unmarshal_candidate};
use crate::tcp_type::TcpType;

fn provider() -> Arc<dyn crypto::RTCCryptoProvider> {
    crypto::default_provider().expect("a built-in crypto provider must be enabled for tests")
}

fn agent(config: AgentConfig) -> Agent {
    Agent::new(Instant::now(), Arc::new(config), provider()).expect("agent")
}

fn local_host(address: &str, port: u16) -> Candidate {
    CandidateHostConfig {
        base_config: CandidateConfig {
            network: "udp".to_owned(),
            address: address.to_owned(),
            port,
            component: 1,
            ..Default::default()
        },
        tcp_type: TcpType::Unspecified,
    }
    .new_candidate_host()
    .expect("host candidate")
}

/// Starts checks, runs the agent for a few check intervals and returns every destination a
/// datagram was queued for.
fn destinations(a: &mut Agent) -> Vec<SocketAddr> {
    let mut now = Instant::now();
    a.start_connectivity_checks(now, true, "remoteufrag".to_owned(), "remotepwd".to_owned())
        .expect("start");
    let mut out = vec![];
    for _ in 0..5 {
        a.handle_timeout(now).expect("timeout");
        while let Some(msg) = a.poll_write() {
            out.push(msg.transport.peer_addr);
        }
        now += Duration::from_millis(250);
    }
    out
}

const REFUSED: &[&str] = &[
    "1 1 udp 2130706431 127.0.0.1 5000 typ host",
    "2 1 udp 2130706431 0.0.0.0 5000 typ host",
    "3 1 udp 2130706431 169.254.169.254 80 typ host",
    "4 1 udp 2130706431 224.0.0.1 5000 typ host",
    "5 1 udp 2130706431 255.255.255.255 5000 typ host",
    "6 1 udp 2130706431 192.168.1.20 0 typ host",
    "7 1 udp 2130706431 0.1.2.3 5000 typ host",
];

#[test]
fn test_checks_never_go_to_loopback_unspecified_or_link_local_destinations() {
    let mut a = agent(AgentConfig::default());
    a.add_local_candidate(local_host("192.168.1.10", 5000))
        .expect("local");

    for line in REFUSED {
        let _ = a.add_remote_candidate(unmarshal_candidate(line).expect("parse"));
    }
    let allowed: SocketAddr = "192.168.1.20:5000".parse().unwrap();
    assert!(
        a.add_remote_candidate(
            unmarshal_candidate("8 1 udp 2130706431 192.168.1.20 5000 typ host").unwrap()
        )
        .unwrap()
    );

    let sent = destinations(&mut a);
    assert!(
        sent.contains(&allowed),
        "the LAN candidate is checked: {sent:?}"
    );
    for dest in &sent {
        assert_eq!(*dest, allowed, "a check went to a refused destination");
    }
    // Invalid destinations are not even held; loopback and link-local ones are held but unpaired.
    for c in a.get_remote_candidates() {
        assert_ne!(address_scope(c.addr()), AddressScope::Invalid, "{c}");
    }
    for p in &a.candidate_pairs {
        assert_eq!(a.remote_candidates[p.remote_index].addr(), allowed);
    }
    a.close().unwrap();
}

#[test]
fn test_ipv4_mapped_ipv6_is_judged_as_ipv4() {
    let mut a = agent(AgentConfig::default());
    a.add_local_candidate(local_host("2001:db8::10", 5000))
        .expect("local");
    let _ = a.add_remote_candidate(
        unmarshal_candidate("1 1 udp 2130706431 ::ffff:127.0.0.1 5000 typ host").unwrap(),
    );
    let _ = a.add_remote_candidate(
        unmarshal_candidate("2 1 udp 2130706431 ::ffff:0.0.0.0 5000 typ host").unwrap(),
    );
    let _ = a
        .add_remote_candidate(unmarshal_candidate("3 1 udp 2130706431 ::1 5000 typ host").unwrap());
    assert!(destinations(&mut a).is_empty());
    assert!(a.candidate_pairs.is_empty());
    a.close().unwrap();
}

#[test]
fn test_loopback_pairs_with_a_loopback_local_candidate() {
    // An application that adds a loopback host candidate has chosen loopback (the tests and
    // examples of this crate run that way): loopback remote candidates pair with it.
    let mut a = agent(AgentConfig::default());
    a.add_local_candidate(local_host("127.0.0.1", 5000))
        .expect("local");
    let remote: SocketAddr = "127.0.0.1:6000".parse().unwrap();
    assert!(
        a.add_remote_candidate(
            unmarshal_candidate("1 1 udp 2130706431 127.0.0.1 6000 typ host").unwrap()
        )
        .unwrap()
    );
    assert!(destinations(&mut a).contains(&remote));
    a.close().unwrap();
}

#[test]
fn test_settings_allow_loopback_and_link_local() {
    let mut a = agent(AgentConfig {
        allow_loopback_remote_candidates: true,
        allow_link_local_remote_candidates: true,
        ..Default::default()
    });
    a.add_local_candidate(local_host("192.168.1.10", 5000))
        .expect("local");
    let _ = a.add_remote_candidate(
        unmarshal_candidate("1 1 udp 2130706431 127.0.0.1 5000 typ host").unwrap(),
    );
    let _ = a.add_remote_candidate(
        unmarshal_candidate("2 1 udp 2130706431 169.254.10.10 5000 typ host").unwrap(),
    );
    // Never allowed, whatever the settings.
    let _ = a.add_remote_candidate(
        unmarshal_candidate("3 1 udp 2130706431 0.0.0.0 5000 typ host").unwrap(),
    );
    let sent = destinations(&mut a);
    assert!(sent.contains(&"127.0.0.1:5000".parse().unwrap()));
    assert!(sent.contains(&"169.254.10.10:5000".parse().unwrap()));
    assert!(!sent.contains(&"0.0.0.0:5000".parse().unwrap()));
    a.close().unwrap();
}

#[test]
fn test_remote_address_filter_refuses_candidates() {
    let filter: RemoteAddressFilter = Arc::new(|addr: SocketAddr| addr.port() != 6666);
    let mut a = agent(AgentConfig {
        remote_address_filter: Some(filter),
        ..Default::default()
    });
    a.add_local_candidate(local_host("192.168.1.10", 5000))
        .expect("local");
    let _ = a.add_remote_candidate(
        unmarshal_candidate("1 1 udp 2130706431 192.168.1.20 6666 typ host").unwrap(),
    );
    let _ = a.add_remote_candidate(
        unmarshal_candidate("2 1 udp 2130706431 192.168.1.20 5000 typ host").unwrap(),
    );
    let sent = destinations(&mut a);
    assert!(sent.contains(&"192.168.1.20:5000".parse().unwrap()));
    assert!(!sent.contains(&"192.168.1.20:6666".parse().unwrap()));
    assert_eq!(a.get_remote_candidates().len(), 1);
    a.close().unwrap();
}

#[test]
fn test_address_scopes() {
    let scope = |s: &str| address_scope(s.parse().unwrap());
    assert_eq!(scope("0.0.0.0:1"), AddressScope::Invalid);
    assert_eq!(scope("10.0.0.1:0"), AddressScope::Invalid);
    assert_eq!(scope("239.1.1.1:1"), AddressScope::Invalid);
    assert_eq!(scope("[ff02::1]:1"), AddressScope::Invalid);
    assert_eq!(scope("[::]:1"), AddressScope::Invalid);
    assert_eq!(scope("127.8.8.8:1"), AddressScope::Loopback);
    assert_eq!(scope("[::1]:1"), AddressScope::Loopback);
    assert_eq!(scope("[::ffff:127.0.0.1]:1"), AddressScope::Loopback);
    assert_eq!(scope("169.254.169.254:80"), AddressScope::LinkLocal);
    assert_eq!(scope("[fe80::1]:1"), AddressScope::LinkLocal);
    assert_eq!(scope("10.0.0.1:1"), AddressScope::Other);
    assert_eq!(scope("[2001:db8::1]:1"), AddressScope::Other);
}
