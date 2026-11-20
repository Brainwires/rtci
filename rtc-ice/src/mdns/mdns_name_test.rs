//! Which remote `.local` names the agent resolves.

use std::sync::Arc;
use std::time::Instant;

use super::*;
use crate::agent::Agent;
use crate::agent::agent_config::AgentConfig;
use crate::candidate::unmarshal_candidate;

fn provider() -> Arc<dyn crypto::RTCCryptoProvider> {
    crypto::default_provider().expect("a built-in crypto provider must be enabled for tests")
}

#[test]
fn test_ice_mdns_names_are_uuids() {
    assert!(is_ice_mdns_name(
        "61b445d2-6503-41ac-96ce-ee3edac00e9f.local"
    ));
    assert!(is_ice_mdns_name(
        "61B445D2-6503-41AC-96CE-EE3EDAC00E9F.local"
    ));
    assert!(is_ice_mdns_name(&generate_multicast_dns_name()));
    for name in [
        ".local",
        "local",
        "printer.local",
        "61b445d2-6503-41ac-96ce-ee3edac00e9f",
        "61b445d2-6503-41ac-96ce-ee3edac00e9f.local.",
        "61b445d2-6503-41ac-96ce-ee3edac00e9.local",
        "61b445d2x6503-41ac-96ce-ee3edac00e9f.local",
        "61b445d2-6503-41ac-96ce-ee3edac00e9g.local",
        "sub.61b445d2-6503-41ac-96ce-ee3edac00e9f.local",
    ] {
        assert!(!is_ice_mdns_name(name), "{name}");
    }
}

#[test]
fn test_agent_resolves_only_uuid_names() {
    let mut agent = Agent::new(
        Instant::now(),
        Arc::new(AgentConfig {
            multicast_dns_mode: MulticastDnsMode::QueryOnly,
            ..Default::default()
        }),
        provider(),
    )
    .unwrap();
    for name in ["printer.local", "my-laptop.local"] {
        let c = unmarshal_candidate(&format!("1 1 udp 2113939711 {name} 5000 typ host")).unwrap();
        assert!(!agent.add_remote_candidate(c).unwrap());
    }
    assert!(
        agent.mdns_queries.is_empty(),
        "no query for a non-UUID name"
    );

    let c = unmarshal_candidate(
        "1 1 udp 2113939711 61b445d2-6503-41ac-96ce-ee3edac00e9f.local 5000 typ host",
    )
    .unwrap();
    assert!(!agent.add_remote_candidate(c).unwrap());
    assert_eq!(agent.mdns_queries.len(), 1, "a UUID name is queried");
    agent.close().unwrap();
}
