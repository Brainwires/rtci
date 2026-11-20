//! `set_configuration` (W3C webrtc 4.4.1.6, "set the configuration").

use std::time::Instant;

use crate::peer_connection::RTCPeerConnectionBuilder;
use crate::peer_connection::configuration::{RTCConfigurationBuilder, RTCIceTransportPolicy};
use crate::peer_connection::transport::{CandidateConfig, CandidateHostConfig, RTCIceCandidate};
use shared::error::Result;

fn host_candidate(port: u16) -> Result<crate::peer_connection::transport::RTCIceCandidateInit> {
    let candidate = CandidateHostConfig {
        base_config: CandidateConfig {
            network: "udp".to_owned(),
            address: "10.0.0.1".to_owned(),
            port,
            component: 1,
            ..Default::default()
        },
        ..Default::default()
    }
    .new_candidate_host()?;
    RTCIceCandidate::from(&candidate).to_json()
}

fn policy(
    policy: RTCIceTransportPolicy,
) -> crate::peer_connection::configuration::RTCConfiguration {
    RTCConfigurationBuilder::new()
        .with_ice_transport_policy(policy)
        .build()
}

/// Step 8: a new `iceTransportPolicy` reaches the ICE agent. With `relay`, a host candidate
/// added afterwards is not used.
#[test]
fn a_relay_policy_set_later_reaches_the_agent() -> Result<()> {
    let mut pc = RTCPeerConnectionBuilder::new()
        .with_configuration(policy(RTCIceTransportPolicy::All))
        .build(Instant::now())?;
    pc.add_local_candidate(host_candidate(5000)?)?;
    assert_eq!(pc.ice_transport().agent.get_local_candidates().len(), 1);

    pc.set_configuration(policy(RTCIceTransportPolicy::Relay))?;
    assert_eq!(
        pc.get_configuration().ice_transport_policy,
        RTCIceTransportPolicy::Relay
    );
    pc.add_local_candidate(host_candidate(5001)?)?;
    assert_eq!(
        pc.ice_transport().agent.get_local_candidates().len(),
        1,
        "the host candidate added under `relay` is not used; the earlier one stays \
         (RFC 9429, Section 4.1.18: the new setting applies from the next gathering)"
    );
    Ok(())
}

/// And back: from `relay` to `all`, host candidates are used again.
#[test]
fn an_all_policy_set_later_lifts_relay() -> Result<()> {
    let mut pc = RTCPeerConnectionBuilder::new()
        .with_configuration(policy(RTCIceTransportPolicy::Relay))
        .build(Instant::now())?;
    pc.add_local_candidate(host_candidate(5000)?)?;
    assert!(pc.ice_transport().agent.get_local_candidates().is_empty());

    pc.set_configuration(policy(RTCIceTransportPolicy::All))?;
    pc.add_local_candidate(host_candidate(5001)?)?;
    assert_eq!(pc.ice_transport().agent.get_local_candidates().len(), 1);
    Ok(())
}
