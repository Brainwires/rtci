//! RFC 8489 Section 9.1.4 over a reliable transport: an ICE-TCP check answered with a
//! response that fails its integrity check ends at once, as an integrity violation.

use std::time::{Duration, Instant};

use super::agent_rfc8445_test::*;
use super::*;
use crate::candidate::CandidateConfig;
use crate::candidate::candidate_host::CandidateHostConfig;
use crate::candidate::candidate_pair::CandidatePairState;
use crate::tcp_type::TcpType;
use stun::fingerprint::FINGERPRINT;
use stun::integrity::MessageIntegrity;
use stun::message::{BINDING_SUCCESS, Message};
use stun::xoraddr::XorMappedAddress;

fn tcp_host(ip: &str, port: u16, tcp_type: TcpType) -> Candidate {
    CandidateHostConfig {
        base_config: CandidateConfig {
            network: "tcp".to_owned(),
            address: ip.to_owned(),
            port,
            component: 1,
            ..Default::default()
        },
        tcp_type,
    }
    .new_candidate_host()
    .unwrap()
}

#[test]
fn test_an_unauthentic_response_over_tcp_ends_the_check_at_once_as_an_integrity_violation() {
    let now = Instant::now();
    let mut a = Agent::new(now, Arc::new(config(true)), provider()).unwrap();
    a.add_local_candidate(tcp_host("192.168.0.2", 9, TcpType::Active))
        .unwrap();
    a.add_remote_candidate(tcp_host("192.168.0.3", 2000, TcpType::Passive))
        .unwrap();
    a.start_connectivity_checks(now, true, REMOTE_UFRAG.to_owned(), REMOTE_PWD.to_owned())
        .unwrap();
    let out = run(&mut a, now, now + Duration::from_millis(100));
    let (check, to) = requests(&out)
        .first()
        .map(|(m, to)| (m.clone(), *to))
        .expect("a check over TCP");
    let at = now + Duration::from_millis(100);

    let mut forged = Message::new();
    forged
        .build(&[
            Box::new(BINDING_SUCCESS),
            Box::new(check.transaction_id),
            Box::new(XorMappedAddress {
                ip: "192.168.0.2".parse().unwrap(),
                port: 40000,
            }),
            Box::new(MessageIntegrity::new_short_term_integrity_with_provider(
                "not-the-peers-password".to_owned(),
                provider().crypto(),
            )),
            Box::new(FINGERPRINT),
        ])
        .unwrap();
    let _ = a.handle_read(TaggedBytesMut {
        now: at,
        transport: TransportContext {
            local_addr: "192.168.0.2:40000".parse().unwrap(),
            peer_addr: to,
            ecn: None,
            transport_protocol: TransportProtocol::TCP,
        },
        message: BytesMut::from(&forged.raw[..]),
    });
    // Due now, not after Ti (39.5 s).
    assert!(
        a.poll_timeout().is_some_and(|t| t <= at),
        "the transaction ends at once"
    );
    a.handle_timeout(at).unwrap();
    let violations: Vec<SocketAddr> = std::iter::from_fn(|| a.poll_event())
        .filter_map(|e| match e.event {
            Event::IntegrityViolation(_, remote) => Some(remote.addr()),
            _ => None,
        })
        .collect();
    assert_eq!(violations, vec![to], "signalled as an integrity violation");
    assert_eq!(a.candidate_pairs[0].state, CandidatePairState::Failed);
}
