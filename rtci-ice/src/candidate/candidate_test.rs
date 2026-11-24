use super::*;
use crate::candidate::candidate_host::CandidateHostConfig;
use crate::candidate::candidate_pair::CandidatePairState;
use crate::candidate::candidate_peer_reflexive::CandidatePeerReflexiveConfig;
use crate::candidate::candidate_relay::CandidateRelayConfig;
use crate::candidate::candidate_server_reflexive::CandidateServerReflexiveConfig;
use crate::candidate::{Candidate, unmarshal_candidate};
use std::time::Instant;

#[test]
fn test_candidate_priority() -> Result<()> {
    let tests = vec![
        (
            Candidate {
                candidate_type: CandidateType::Host,
                component: COMPONENT_RTP,
                ..Default::default()
            },
            2130706431,
        ),
        (
            Candidate {
                candidate_type: CandidateType::Host,
                component: COMPONENT_RTP,
                network_type: NetworkType::Tcp4,
                tcp_type: TcpType::Active,
                ..Default::default()
            },
            2111832063,
        ),
        (
            Candidate {
                candidate_type: CandidateType::Host,
                component: COMPONENT_RTP,
                network_type: NetworkType::Tcp4,
                tcp_type: TcpType::Passive,
                ..Default::default()
            },
            2107637759,
        ),
        (
            Candidate {
                candidate_type: CandidateType::Host,
                component: COMPONENT_RTP,
                network_type: NetworkType::Tcp4,
                tcp_type: TcpType::SimultaneousOpen,
                ..Default::default()
            },
            2103443455,
        ),
        (
            Candidate {
                candidate_type: CandidateType::PeerReflexive,
                component: COMPONENT_RTP,
                ..Default::default()
            },
            1862270975,
        ),
        (
            Candidate {
                candidate_type: CandidateType::PeerReflexive,
                component: COMPONENT_RTP,
                network_type: NetworkType::Tcp6,
                tcp_type: TcpType::SimultaneousOpen,
                ..Default::default()
            },
            1843396607,
        ),
        (
            Candidate {
                candidate_type: CandidateType::PeerReflexive,
                component: COMPONENT_RTP,
                network_type: NetworkType::Tcp6,
                tcp_type: TcpType::Active,
                ..Default::default()
            },
            1839202303,
        ),
        (
            Candidate {
                candidate_type: CandidateType::PeerReflexive,
                component: COMPONENT_RTP,
                network_type: NetworkType::Tcp6,
                tcp_type: TcpType::Passive,
                ..Default::default()
            },
            1835007999,
        ),
        (
            Candidate {
                candidate_type: CandidateType::ServerReflexive,
                component: COMPONENT_RTP,
                ..Default::default()
            },
            1694498815,
        ),
        (
            Candidate {
                candidate_type: CandidateType::Relay,
                component: COMPONENT_RTP,
                ..Default::default()
            },
            16777215,
        ),
    ];

    for (candidate, want) in tests {
        let got = candidate.priority();
        assert_eq!(
            got, want,
            "Candidate({candidate}).Priority() = {got}, want {want}"
        );
    }

    Ok(())
}

#[test]
fn test_candidate_last_sent() -> Result<()> {
    let mut candidate = Candidate::default();
    assert_eq!(
        candidate.last_sent(),
        None,
        "a fresh candidate has sent nothing"
    );

    let now = Instant::now();
    candidate.set_last_sent(now);
    assert_eq!(candidate.last_sent(), Some(now));

    Ok(())
}

#[test]
fn test_candidate_last_received() -> Result<()> {
    let mut candidate = Candidate::default();
    assert_eq!(
        candidate.last_received(),
        None,
        "a fresh candidate has received nothing"
    );

    let now = Instant::now();
    candidate.set_last_received(now);
    assert_eq!(candidate.last_received(), Some(now));

    Ok(())
}

#[test]
fn test_candidate_foundation() -> Result<()> {
    // All fields are the same
    assert_eq!(
        (Candidate {
            candidate_type: CandidateType::Host,
            network_type: NetworkType::Udp4,
            address: "A".to_owned(),
            ..Default::default()
        })
        .foundation(),
        (Candidate {
            candidate_type: CandidateType::Host,
            network_type: NetworkType::Udp4,
            address: "A".to_owned(),
            ..Default::default()
        })
        .foundation()
    );

    // Different Address
    assert_ne!(
        (Candidate {
            candidate_type: CandidateType::Host,
            network_type: NetworkType::Udp4,
            address: "A".to_owned(),
            ..Default::default()
        })
        .foundation(),
        (Candidate {
            candidate_type: CandidateType::Host,
            network_type: NetworkType::Udp4,
            address: "B".to_owned(),
            ..Default::default()
        })
        .foundation(),
    );

    // Different networkType
    assert_ne!(
        (Candidate {
            candidate_type: CandidateType::Host,
            network_type: NetworkType::Udp4,
            address: "A".to_owned(),
            ..Default::default()
        })
        .foundation(),
        (Candidate {
            candidate_type: CandidateType::Host,
            network_type: NetworkType::Udp6,
            address: "A".to_owned(),
            ..Default::default()
        })
        .foundation(),
    );

    // Different candidateType
    assert_ne!(
        (Candidate {
            candidate_type: CandidateType::Host,
            network_type: NetworkType::Udp4,
            address: "A".to_owned(),
            ..Default::default()
        })
        .foundation(),
        (Candidate {
            candidate_type: CandidateType::PeerReflexive,
            network_type: NetworkType::Udp4,
            address: "A".to_owned(),
            ..Default::default()
        })
        .foundation(),
    );

    // Port has no effect
    assert_eq!(
        (Candidate {
            candidate_type: CandidateType::Host,
            network_type: NetworkType::Udp4,
            address: "A".to_owned(),
            port: 8080,
            ..Default::default()
        })
        .foundation(),
        (Candidate {
            candidate_type: CandidateType::Host,
            network_type: NetworkType::Udp4,
            address: "A".to_owned(),
            port: 80,
            ..Default::default()
        })
        .foundation()
    );

    Ok(())
}

#[test]
fn test_candidate_pair_state_serialization() {
    let tests = vec![
        (CandidatePairState::Unspecified, "\"unspecified\""),
        (CandidatePairState::Waiting, "\"waiting\""),
        (CandidatePairState::InProgress, "\"in-progress\""),
        (CandidatePairState::Failed, "\"failed\""),
        (CandidatePairState::Succeeded, "\"succeeded\""),
    ];

    for (candidate_pair_state, expected_string) in tests {
        assert_eq!(
            expected_string.to_string(),
            serde_json::to_string(&candidate_pair_state).unwrap()
        );
    }
}

#[test]
fn test_candidate_pair_state_to_string() {
    let tests = vec![
        (CandidatePairState::Unspecified, "unspecified"),
        (CandidatePairState::Waiting, "waiting"),
        (CandidatePairState::InProgress, "in-progress"),
        (CandidatePairState::Failed, "failed"),
        (CandidatePairState::Succeeded, "succeeded"),
    ];

    for (candidate_pair_state, expected_string) in tests {
        assert_eq!(candidate_pair_state.to_string(), expected_string);
    }
}

#[test]
fn test_candidate_type_serialization() {
    let tests = vec![
        (CandidateType::Unspecified, "\"unspecified\""),
        (CandidateType::Host, "\"host\""),
        (CandidateType::ServerReflexive, "\"srflx\""),
        (CandidateType::PeerReflexive, "\"prflx\""),
        (CandidateType::Relay, "\"relay\""),
    ];

    for (candidate_type, expected_string) in tests {
        assert_eq!(
            serde_json::to_string(&candidate_type).unwrap(),
            expected_string.to_string()
        );
    }
}

#[test]
fn test_candidate_type_to_string() {
    let tests = vec![
        (CandidateType::Unspecified, "Unknown candidate type"),
        (CandidateType::Host, "host"),
        (CandidateType::ServerReflexive, "srflx"),
        (CandidateType::PeerReflexive, "prflx"),
        (CandidateType::Relay, "relay"),
    ];

    for (candidate_type, expected_string) in tests {
        assert_eq!(candidate_type.to_string(), expected_string);
    }
}

#[test]
fn test_candidate_marshal() -> Result<()> {
    let tests = vec![
        (
            Some(Candidate {
                network_type: NetworkType::Udp6,
                candidate_type: CandidateType::Host,
                address: "fcd9:e3b8:12ce:9fc5:74a5:c6bb:d8b:e08a".to_owned(),
                port: 53987,
                priority_override: 500,
                foundation_override: "750".to_owned(),
                ..Default::default()
            }),
            "750 1 udp 500 fcd9:e3b8:12ce:9fc5:74a5:c6bb:d8b:e08a 53987 typ host",
        ),
        (
            Some(Candidate {
                network_type: NetworkType::Udp4,
                candidate_type: CandidateType::Host,
                address: "10.0.75.1".to_owned(),
                port: 53634,
                ..Default::default()
            }),
            "4273957277 1 udp 2130706431 10.0.75.1 53634 typ host",
        ),
        (
            Some(Candidate {
                network_type: NetworkType::Udp4,
                candidate_type: CandidateType::ServerReflexive,
                address: "191.228.238.68".to_owned(),
                port: 53991,
                related_address: Some(CandidateRelatedAddress {
                    address: "192.168.0.274".to_owned(),
                    port: 53991,
                }),
                ..Default::default()
            }),
            "647372371 1 udp 1694498815 191.228.238.68 53991 typ srflx raddr 192.168.0.274 rport 53991",
        ),
        (
            Some(Candidate {
                network_type: NetworkType::Udp4,
                candidate_type: CandidateType::Relay,
                address: "50.0.0.1".to_owned(),
                port: 5000,
                related_address: Some(CandidateRelatedAddress {
                    address: "192.168.0.1".to_owned(),
                    port: 5001,
                }),
                ..Default::default()
            }),
            "848194626 1 udp 16777215 50.0.0.1 5000 typ relay raddr 192.168.0.1 rport 5001",
        ),
        (
            Some(Candidate {
                network_type: NetworkType::Tcp4,
                candidate_type: CandidateType::Host,
                address: "192.168.0.196".to_owned(),
                port: 0,
                tcp_type: TcpType::Active,
                ..Default::default()
            }),
            "1052353102 1 tcp 2128609279 192.168.0.196 0 typ host tcptype active",
        ),
        /*TODO: mDNS (
            Some(Candidate{
                    network_type:   NetworkType::Udp4,
                    candidate_type: CandidateType::Host,
                    address:       "e2494022-4d9a-4c1e-a750-cc48d4f8d6ee.local".to_owned(),
                    port:          60542,
                ..Default::default()
            }),
            "1380287402 1 udp 2130706431 e2494022-4d9a-4c1e-a750-cc48d4f8d6ee.local 60542 typ host",
        ),*/
        // Invalid candidates
        (None, ""),
        (None, "1938809241"),
        (
            None,
            "1986380506 99999999 udp 2122063615 10.0.75.1 53634 typ host generation 0 network-id 2",
        ),
        (
            None,
            "1986380506 1 udp 99999999999 10.0.75.1 53634 typ host",
        ),
        (
            None,
            "4207374051 1 udp 1685790463 191.228.238.68 99999999 typ srflx raddr 192.168.0.278 rport 53991 generation 0 network-id 3",
        ),
        (
            None,
            "4207374051 1 udp 1685790463 191.228.238.68 53991 typ srflx raddr",
        ),
        (
            None,
            "4207374051 1 udp 1685790463 191.228.238.68 53991 typ srflx raddr 192.168.0.278 rport 99999999 generation 0 network-id 3",
        ),
        (
            None,
            "4207374051 INVALID udp 2130706431 10.0.75.1 53634 typ host",
        ),
        (None, "4207374051 1 udp INVALID 10.0.75.1 53634 typ host"),
        (
            None,
            "4207374051 INVALID udp 2130706431 10.0.75.1 INVALID typ host",
        ),
        (
            None,
            "4207374051 1 udp 2130706431 10.0.75.1 53634 typ INVALID",
        ),
    ];

    for (candidate, marshaled) in tests {
        let actual_candidate = unmarshal_candidate(marshaled);
        if let Some(candidate) = candidate {
            if let Ok(actual_candidate) = actual_candidate {
                assert!(
                    candidate.equal(&actual_candidate),
                    "{} vs {}",
                    candidate.marshal(),
                    marshaled
                );
                assert_eq!(marshaled, actual_candidate.marshal());
            } else {
                panic!("expected ok");
            }
        } else {
            assert!(actual_candidate.is_err(), "expected error");
        }
    }

    Ok(())
}

/// Regression test: a candidate's base address must be the local (bound)
/// transport address. For server/peer-reflexive candidates that is the
/// related address, not the NAT-mapped candidate address (RFC 8445 §5.1.1).
#[test]
fn test_candidate_base_addr() -> Result<()> {
    let host = CandidateHostConfig {
        base_config: CandidateConfig {
            network: "udp".to_owned(),
            address: "192.168.0.2".to_owned(),
            port: 5000,
            component: 1,
            ..Default::default()
        },
        ..Default::default()
    }
    .new_candidate_host()?;
    assert_eq!(host.base_addr(), host.addr(), "host base is itself");

    let srflx = CandidateServerReflexiveConfig {
        base_config: CandidateConfig {
            network: "udp".to_owned(),
            address: "10.79.12.1".to_owned(),
            port: 60823,
            component: 1,
            ..Default::default()
        },
        rel_addr: "192.168.0.2".to_owned(),
        rel_port: 5000,
        ..Default::default()
    }
    .new_candidate_server_reflexive()?;
    assert_eq!(
        srflx.base_addr(),
        "192.168.0.2:5000".parse().unwrap(),
        "srflx base must be the related (host) address"
    );
    assert_ne!(srflx.base_addr(), srflx.addr());

    let prflx = CandidatePeerReflexiveConfig {
        base_config: CandidateConfig {
            network: "udp".to_owned(),
            address: "10.79.12.1".to_owned(),
            port: 60824,
            component: 1,
            ..Default::default()
        },
        rel_addr: "192.168.0.2".to_owned(),
        rel_port: 5000,
    }
    .new_candidate_peer_reflexive()?;
    assert_eq!(
        prflx.base_addr(),
        "192.168.0.2:5000".parse().unwrap(),
        "prflx base must be the related (host) address"
    );

    // Missing/unparseable related address falls back to the candidate address.
    let prflx_no_rel = CandidatePeerReflexiveConfig {
        base_config: CandidateConfig {
            network: "udp".to_owned(),
            address: "10.79.12.1".to_owned(),
            port: 60825,
            component: 1,
            ..Default::default()
        },
        rel_addr: "".to_owned(),
        rel_port: 0,
    }
    .new_candidate_peer_reflexive()?;
    assert_eq!(prflx_no_rel.base_addr(), prflx_no_rel.addr());

    let relay = CandidateRelayConfig {
        base_config: CandidateConfig {
            network: "udp".to_owned(),
            address: "50.0.0.1".to_owned(),
            port: 5000,
            component: 1,
            ..Default::default()
        },
        rel_addr: "192.168.0.2".to_owned(),
        rel_port: 5001,
        ..Default::default()
    }
    .new_candidate_relay()?;
    assert_eq!(
        relay.base_addr(),
        relay.addr(),
        "relay base is the relayed address itself"
    );

    Ok(())
}

/// RFC 8445 §5.1.1.1: component ids run from 1 to 256. A remote candidate outside that range
/// is a parse error; it used to parse, and its priority then computed `256 - component` and
/// panicked.
#[test]
fn test_unmarshal_candidate_component_out_of_range() {
    for component in [300u32, 257, 65535, 0] {
        let line = format!("candidate:1 {component} udp 0 1.2.3.4 9 typ host");
        assert!(
            unmarshal_candidate(&line).map(|c| c.priority()).is_err(),
            "component {component} was accepted"
        );
    }
    let c = unmarshal_candidate("candidate:1 256 udp 0 1.2.3.4 9 typ host").unwrap();
    assert_eq!(c.priority() & 0xff, 0);
}

fn srflx(address: &str, port: u16, rel_addr: &str, rel_port: u16, url: Option<&str>) -> Candidate {
    CandidateServerReflexiveConfig {
        base_config: CandidateConfig {
            network: "udp".to_owned(),
            address: address.to_owned(),
            port,
            component: COMPONENT_RTP,
            ..Default::default()
        },
        rel_addr: rel_addr.to_owned(),
        rel_port,
        url: url.map(str::to_owned),
    }
    .new_candidate_server_reflexive()
    .unwrap()
}

/// RFC 8445 Section 5.1.1.3: same foundation when the type, the base's IP address (not its
/// port), the server and the transport are the same; different when one of them differs.
#[test]
fn test_candidate_foundation_follows_base_and_server() {
    let a = srflx(
        "203.0.113.1",
        5000,
        "10.0.0.1",
        4000,
        Some("stun:one.example"),
    );
    // Another mapping from the same base IP (another port) through the same server.
    let same = srflx(
        "203.0.113.9",
        6000,
        "10.0.0.1",
        4001,
        Some("stun:one.example"),
    );
    assert_eq!(a.foundation(), same.foundation());
    // The same base through another server.
    let other_server = srflx(
        "203.0.113.1",
        5000,
        "10.0.0.1",
        4000,
        Some("stun:two.example"),
    );
    assert_ne!(a.foundation(), other_server.foundation());
    // Another base behind the same mapped address.
    let other_base = srflx(
        "203.0.113.1",
        5000,
        "10.0.0.2",
        4000,
        Some("stun:one.example"),
    );
    assert_ne!(a.foundation(), other_base.foundation());

    // Host candidates: the base is the candidate; two ports of one address share it.
    let host = |address: &str, port: u16, network: &str| {
        CandidateHostConfig {
            base_config: CandidateConfig {
                network: network.to_owned(),
                address: address.to_owned(),
                port,
                component: COMPONENT_RTP,
                ..Default::default()
            },
            ..Default::default()
        }
        .new_candidate_host()
        .unwrap()
    };
    assert_eq!(
        host("10.0.0.1", 4000, "udp").foundation(),
        host("10.0.0.1", 4001, "udp").foundation()
    );
    assert_ne!(
        host("10.0.0.1", 4000, "udp").foundation(),
        host("10.0.0.2", 4000, "udp").foundation()
    );
    assert_ne!(
        host("10.0.0.1", 4000, "udp").foundation(),
        host("10.0.0.1", 4000, "tcp").foundation()
    );
    // Type: a server-reflexive candidate does not share its host candidate's foundation.
    assert_ne!(host("10.0.0.1", 4000, "udp").foundation(), a.foundation());
}

/// RFC 8445 Section 5.1.2.1: a component is 1 to 256. The constructors take the `Default` (0)
/// as RTP, component 1, and refuse anything above 256; the RTCP component is 2.
#[test]
fn test_candidate_constructors_check_component_and_priority() {
    let build = |component: u16, priority: u32| {
        CandidateHostConfig {
            base_config: CandidateConfig {
                network: "udp".to_owned(),
                address: "192.0.2.1".to_owned(),
                port: 1,
                component,
                priority,
                ..Default::default()
            },
            ..Default::default()
        }
        .new_candidate_host()
    };
    let default_component = build(0, 0).unwrap();
    assert_eq!(default_component.component(), 1);
    assert_eq!(default_component.priority(), 2130706431);
    let rtcp = build(COMPONENT_RTCP, 0).unwrap();
    assert_eq!(rtcp.component(), 2);
    // 2^24 * 126 + 2^8 * 65535 + (256 - 2)
    assert_eq!(rtcp.priority(), 2130706430);
    assert_eq!(build(256, 0).unwrap().priority(), 2130706176);
    assert!(build(257, 0).is_err());
    // Section 5.1.2: a priority is at most 2^31 - 1.
    assert!(build(1, (1 << 31) - 1).is_ok());
    assert!(build(1, 1 << 31).is_err());
    assert!(unmarshal_candidate("1 1 udp 2147483648 192.0.2.1 1 typ host").is_err());
}

/// RFC 8445 Section 7.1.1: the PRIORITY of a check is the candidate's priority with the
/// peer-reflexive type preference in place of its own.
#[test]
fn test_peer_reflexive_priority_keeps_local_preference_and_component() {
    let relay = Candidate {
        candidate_type: CandidateType::Relay,
        component: COMPONENT_RTP,
        ..Default::default()
    };
    assert_eq!(relay.priority(), 16777215);
    assert_eq!(relay.peer_reflexive_priority(), (110 << 24) + 16777215);
    let tcp = Candidate {
        candidate_type: CandidateType::Host,
        network_type: NetworkType::Tcp4,
        tcp_type: TcpType::Passive,
        component: COMPONENT_RTP,
        ..Default::default()
    };
    assert_eq!(
        tcp.peer_reflexive_priority(),
        (109 << 24) + (u32::from(tcp.local_preference()) << 8) + 255,
        "the TCP peer-reflexive type preference (RFC 6544 section 4.2)"
    );
    // A priority the application chose keeps its low 24 bits.
    let chosen = Candidate {
        candidate_type: CandidateType::Host,
        priority_override: (126 << 24) + (1234 << 8) + 255,
        component: COMPONENT_RTP,
        ..Default::default()
    };
    assert_eq!(
        chosen.peer_reflexive_priority(),
        (110 << 24) + (1234 << 8) + 255
    );
}

/// RFC 6544 section 4.2: with UDP and TCP candidates for one stream, the other transport's type
/// preferences are lowered by one ("For RTP-based media streams, it is RECOMMENDED that UDP
/// candidates are preferred over TCP candidates"; the candidate type still counts first): a
/// TCP candidate has the type preference of its type less one, a TCP host candidate stays above
/// a UDP server-reflexive one, and relayed candidates stay last.
#[test]
fn tcp_candidates_take_the_type_preference_less_one() {
    let candidate =
        |candidate_type: CandidateType, network_type: NetworkType, tcp_type: TcpType| Candidate {
            candidate_type,
            component: COMPONENT_RTP,
            network_type,
            tcp_type,
            ..Default::default()
        };
    for (t, udp) in [
        (CandidateType::Host, 126),
        (CandidateType::PeerReflexive, 110),
        (CandidateType::ServerReflexive, 100),
    ] {
        let tcp = candidate(t, NetworkType::Tcp4, TcpType::Active);
        assert_eq!(tcp.priority() >> 24, udp - 1, "{t:?} over TCP");
        assert_eq!(
            candidate(t, NetworkType::Udp4, TcpType::Unspecified).priority() >> 24,
            udp
        );
    }
    let tcp_host = candidate(CandidateType::Host, NetworkType::Tcp4, TcpType::Passive);
    let udp_srflx = candidate(
        CandidateType::ServerReflexive,
        NetworkType::Udp4,
        TcpType::Unspecified,
    );
    assert!(tcp_host.priority() > udp_srflx.priority());
    let tcp_relay = candidate(CandidateType::Relay, NetworkType::Tcp4, TcpType::Passive);
    let udp_relay = candidate(
        CandidateType::Relay,
        NetworkType::Udp4,
        TcpType::Unspecified,
    );
    assert!(udp_relay.priority() > tcp_relay.priority());
    assert!(tcp_relay.priority() < udp_srflx.priority());
}

/// RFC 8839 section 5.1: an agent "MUST ignore any name/value pairs it doesn't understand"
/// among the extension attributes, which come in any order; `tcptype` (RFC 6544 section 4.5)
/// is one of them. It is read after `raddr` / `rport`, after other extensions (`generation`,
/// `ufrag`, `network-id`) and before them, and the unknown pairs around it are skipped.
#[test]
fn test_tcptype_is_read_wherever_it_stands_among_the_extensions() -> Result<()> {
    for line in [
        "1 1 tcp 1518280447 192.0.2.1 9 typ host tcptype active",
        "1 1 tcp 1518280447 192.0.2.1 9 typ host generation 0 ufrag Qx7a tcptype active",
        "1 1 tcp 1518280447 192.0.2.1 9 typ host tcptype active generation 0 network-id 1",
        "1 1 tcp 1518280447 192.0.2.1 9 typ host x-unknown y tcptype active",
        "1 1 tcp 1518280447 198.51.100.7 9 typ srflx raddr 192.0.2.1 rport 9 generation 0 \
         tcptype active",
    ] {
        let candidate = unmarshal_candidate(line)?;
        assert_eq!(candidate.tcp_type(), TcpType::Active, "{line}");
    }
    let candidate =
        unmarshal_candidate("1 1 udp 2130706431 192.0.2.1 5000 typ host generation 0 ufrag Qx7a")?;
    assert_eq!(candidate.tcp_type(), TcpType::Unspecified);
    assert_eq!(candidate.address(), "192.0.2.1");
    Ok(())
}
