//! 1:1 NAT mapping (`AgentConfig::nat_1to1_ips`) applied to the host candidates added.

use std::sync::Arc;
use std::time::Instant;

use super::*;
use crate::candidate::candidate_host::CandidateHostConfig;
use crate::mdns::MulticastDnsMode;

fn provider() -> Arc<dyn crypto::RTCCryptoProvider> {
    crypto::default_provider().expect("a built-in crypto provider must be enabled for tests")
}

fn nat_agent(ips: &[&str], candidate_type: CandidateType) -> Result<Agent> {
    Agent::new(
        Instant::now(),
        Arc::new(AgentConfig {
            nat_1to1_ips: ips.iter().map(|s| (*s).to_owned()).collect(),
            nat_1to1_ip_candidate_type: candidate_type,
            ..Default::default()
        }),
        provider(),
    )
}

fn host(address: &str, port: u16) -> Candidate {
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
    .unwrap()
}

#[test]
fn test_nat_1to1_host_advertises_the_external_address() -> Result<()> {
    let mut a = nat_agent(&["54.1.2.3"], CandidateType::Unspecified)?;
    assert!(a.add_local_candidate(host("10.0.1.5", 5000))?);
    assert_eq!(a.local_candidates.len(), 1);
    let c = &a.local_candidates[0];
    assert_eq!(c.address(), "54.1.2.3");
    assert!(c.marshal().contains("54.1.2.3 5000 typ host"));
    // Still bound where it was: checks leave from, and are matched on, the local socket.
    assert_eq!(c.addr(), "10.0.1.5:5000".parse::<SocketAddr>().unwrap());
    assert_eq!(
        c.base_addr(),
        "10.0.1.5:5000".parse::<SocketAddr>().unwrap()
    );
    assert_eq!(
        a.find_local_candidate("10.0.1.5:5000".parse().unwrap(), TransportProtocol::UDP),
        Some(0)
    );
    a.close()?;
    Ok(())
}

#[test]
fn test_nat_1to1_srflx_adds_a_server_reflexive_candidate() -> Result<()> {
    let mut a = nat_agent(&["54.1.2.3"], CandidateType::ServerReflexive)?;
    assert!(a.add_local_candidate(host("10.0.1.5", 5000))?);
    assert_eq!(a.local_candidates.len(), 2);
    assert_eq!(a.local_candidates[0].address(), "10.0.1.5");
    let srflx = &a.local_candidates[1];
    assert_eq!(srflx.candidate_type(), CandidateType::ServerReflexive);
    assert_eq!(srflx.address(), "54.1.2.3");
    assert_eq!(srflx.port(), 5000);
    assert_eq!(
        srflx.related_address(),
        Some(CandidateRelatedAddress {
            address: "10.0.1.5".to_owned(),
            port: 5000
        })
    );
    assert_eq!(
        srflx.base_addr(),
        "10.0.1.5:5000".parse::<SocketAddr>().unwrap()
    );
    a.close()?;
    Ok(())
}

#[test]
fn test_nat_1to1_explicit_mapping_leaves_other_addresses() -> Result<()> {
    let mut a = nat_agent(&["54.1.2.3/10.0.1.5"], CandidateType::Host)?;
    a.add_local_candidate(host("10.0.1.5", 5000))?;
    a.add_local_candidate(host("10.0.1.6", 5000))?;
    a.add_local_candidate(host("2001:db8::5", 5000))?;
    let addresses: Vec<&str> = a.local_candidates.iter().map(|c| c.address()).collect();
    assert_eq!(addresses, vec!["54.1.2.3", "10.0.1.6", "2001:db8::5"]);
    a.close()?;
    Ok(())
}

#[test]
fn test_nat_1to1_configuration_errors() {
    let err = |r: Result<Agent>| r.err().expect("expected an error");
    assert_eq!(
        err(Agent::new(
            Instant::now(),
            Arc::new(AgentConfig {
                nat_1to1_ips: vec!["54.1.2.3".to_owned()],
                multicast_dns_mode: MulticastDnsMode::QueryAndGather,
                ..Default::default()
            }),
            provider(),
        )),
        Error::ErrMulticastDnsWithNat1to1IpMapping
    );
    assert_eq!(
        err(Agent::new(
            Instant::now(),
            Arc::new(AgentConfig {
                nat_1to1_ips: vec!["54.1.2.3".to_owned()],
                nat_1to1_ip_candidate_type: CandidateType::ServerReflexive,
                candidate_types: vec![CandidateType::Host],
                ..Default::default()
            }),
            provider(),
        )),
        Error::ErrIneffectiveNat1to1IpMappingSrflx
    );
    assert_eq!(
        err(nat_agent(&["54.1.2.3"], CandidateType::Relay)),
        Error::ErrUnsupportedNat1to1IpCandidateType
    );
    assert_eq!(
        err(nat_agent(&["not-an-ip"], CandidateType::Host)),
        Error::ErrInvalidNat1to1IpMapping
    );
}
