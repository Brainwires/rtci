//! mDNS name handling. The two connection tests of the old async suite
//! (`test_multicast_dns_only_connection`, `test_multicast_dns_mixed_connection`) need two hosts
//! on a LAN with real multicast; they live in `tests/testenv_mdns.rs` and run in the
//! real-network test environment (`scripts/test-env/run.sh`).

use std::sync::Arc;
use std::time::Instant;

use regex::Regex;

use super::*;
use crate::agent::Agent;
use crate::agent::agent_config::AgentConfig;
use crate::candidate::CandidateType;
use crate::network_type::NetworkType;
use shared::error::Error;

fn provider() -> Arc<dyn crypto::RTCCryptoProvider> {
    crypto::default_provider().expect("a built-in crypto provider must be enabled for tests")
}

fn config(name: &str) -> Arc<AgentConfig> {
    Arc::new(AgentConfig {
        network_types: vec![NetworkType::Udp4],
        candidate_types: vec![CandidateType::Host],
        multicast_dns_mode: MulticastDnsMode::QueryAndGather,
        multicast_dns_local_name: name.to_owned(),
        ..Default::default()
    })
}

#[test]
fn test_multicast_dns_static_host_name() {
    for invalid in ["invalidHostName", "two.labels.local", "name.lan"] {
        match Agent::new(Instant::now(), config(invalid), provider()) {
            Err(err) => assert_eq!(err, Error::ErrInvalidMulticastDnshostName, "{invalid}"),
            Ok(_) => panic!("{invalid}: expected ErrInvalidMulticastDnshostName"),
        }
    }
    Agent::new(Instant::now(), config("validName.local"), provider())
        .expect("a one-label .local name is accepted");
    // No name: the agent makes one up (a UUID, below).
    Agent::new(Instant::now(), config(""), provider()).expect("a generated name is accepted");
}

#[test]
fn test_generate_multicast_dnsname() {
    let name = generate_multicast_dns_name();
    let re = Regex::new(
        r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-4[0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}\.local$",
    )
    .unwrap();
    assert!(
        re.is_match(&name),
        "mDNS name must be UUID v4 + \".local\", got {name}"
    );
    assert_ne!(name, generate_multicast_dns_name(), "names are random");
}
