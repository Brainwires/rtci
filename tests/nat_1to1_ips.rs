//! `SettingEngineBuilder::with_nat_1to1_ips`: the host candidates the application adds are
//! announced on the 1:1 NAT's public address.

use rtc::peer_connection::RTCPeerConnectionBuilder;
use rtc::peer_connection::configuration::RTCConfigurationBuilder;
use rtc::peer_connection::configuration::setting_engine::SettingEngineBuilder;
use rtc::peer_connection::event::RTCPeerConnectionEvent;
use rtc::peer_connection::transport::{RTCIceCandidate, RTCIceCandidateInit, RTCIceCandidateType};
use rtc::sansio::Protocol;
use std::time::Instant;

fn announced(candidate_type: RTCIceCandidateType) -> Vec<RTCIceCandidate> {
    let setting_engine = SettingEngineBuilder::new()
        .with_nat_1to1_ips(vec!["203.0.113.7".to_owned()], candidate_type)
        .build();
    let mut pc = RTCPeerConnectionBuilder::new()
        .with_configuration(RTCConfigurationBuilder::new().build())
        .with_setting_engine(setting_engine)
        .build(Instant::now())
        .expect("peer connection");
    pc.add_local_candidate(RTCIceCandidateInit {
        candidate: "candidate:1 1 udp 2130706431 10.0.1.5 54321 typ host".to_owned(),
        sdp_mid: Some("0".to_owned()),
        sdp_mline_index: Some(0),
        username_fragment: None,
        url: None,
        relay_protocol: None,
    })
    .expect("add local candidate");
    let mut out = vec![];
    while let Some(event) = pc.poll_event() {
        if let RTCPeerConnectionEvent::OnIceCandidateEvent(e) = event {
            out.extend(e.candidate);
        }
    }
    out
}

#[test]
fn nat_1to1_host_announces_the_public_address() {
    let candidates = announced(RTCIceCandidateType::Host);
    assert_eq!(candidates.len(), 1, "{candidates:?}");
    assert_eq!(candidates[0].typ, RTCIceCandidateType::Host);
    assert_eq!(candidates[0].address, "203.0.113.7");
    assert_eq!(candidates[0].port, 54321);
}

#[test]
fn nat_1to1_srflx_announces_a_server_reflexive_candidate_beside_the_host() {
    let candidates = announced(RTCIceCandidateType::Srflx);
    assert_eq!(candidates.len(), 2, "{candidates:?}");
    assert_eq!(candidates[0].typ, RTCIceCandidateType::Host);
    assert_eq!(candidates[0].address, "10.0.1.5");
    assert_eq!(candidates[1].typ, RTCIceCandidateType::Srflx);
    assert_eq!(candidates[1].address, "203.0.113.7");
    assert_eq!(candidates[1].port, 54321);
    assert_eq!(candidates[1].related_address, "10.0.1.5");
}

#[test]
fn nat_1to1_with_mdns_host_names_is_refused() {
    let setting_engine = SettingEngineBuilder::new()
        .with_nat_1to1_ips(vec!["203.0.113.7".to_owned()], RTCIceCandidateType::Host)
        .with_multicast_dns_mode(rtc::ice::mdns::MulticastDnsMode::QueryAndGather)
        .build();
    let pc = RTCPeerConnectionBuilder::new()
        .with_configuration(RTCConfigurationBuilder::new().build())
        .with_setting_engine(setting_engine)
        .build(Instant::now());
    assert!(pc.is_err());
}
