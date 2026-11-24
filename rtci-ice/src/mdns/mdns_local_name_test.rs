//! The agent's own mDNS name: one label in `.local` (RFC 6762 §3).

use std::sync::Arc;
use std::time::Instant;

use super::*;
use crate::agent::Agent;
use crate::agent::agent_config::AgentConfig;
use crate::network_type::NetworkType;
use shared::error::Error;

fn provider() -> Arc<dyn crypto::RTCCryptoProvider> {
    crypto::default_provider().expect("a built-in crypto provider must be enabled for tests")
}

#[test]
fn test_bare_local_is_not_a_host_name() {
    for invalid in [".local", "-x.local", "x-.local", "a_b.local", "a b.local"] {
        assert!(!is_valid_local_mdns_name(invalid), "{invalid}");
        let config = Arc::new(AgentConfig {
            network_types: vec![NetworkType::Udp4],
            multicast_dns_mode: MulticastDnsMode::QueryAndGather,
            multicast_dns_local_name: invalid.to_owned(),
            ..Default::default()
        });
        match Agent::new(Instant::now(), config, provider()) {
            Err(err) => assert_eq!(err, Error::ErrInvalidMulticastDnshostName, "{invalid}"),
            Ok(_) => panic!("{invalid}: expected ErrInvalidMulticastDnshostName"),
        }
    }
    let long = format!("{}.local", "a".repeat(64));
    assert!(!is_valid_local_mdns_name(&long));
    let valid = [
        "validName.local".to_owned(),
        "a.local".to_owned(),
        "webrtc-rs-test-mdns.local".to_owned(),
        format!("{}.local", "a".repeat(63)),
        generate_multicast_dns_name(),
    ];
    for name in &valid {
        assert!(is_valid_local_mdns_name(name), "{name}");
    }
}
