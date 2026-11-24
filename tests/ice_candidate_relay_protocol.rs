//! W3C webrtc-pc 4.8.1 and 4.8.1.5: a local relay candidate surfaced by the peer connection
//! carries `relayProtocol`, the protocol of its TURN server (RTCLocalIceCandidateInit
//! `relayProtocol`, else what its TURN URL names: `turns:` TLS, `?transport=tcp` TCP, UDP
//! otherwise), and the `url` it was gathered from; any other candidate has no relayProtocol,
//! and a host candidate no url.

use rtci::peer_connection::RTCPeerConnectionBuilder;
use rtci::peer_connection::configuration::{RTCConfigurationBuilder, RTCIceTransportPolicy};
use rtci::peer_connection::event::RTCPeerConnectionEvent;
use rtci::peer_connection::transport::{
    RTCIceCandidate, RTCIceCandidateInit, RTCIceServerTransportProtocol,
};
use rtci::sansio::Protocol;
use std::time::Instant;

const RELAY: &str =
    "candidate:3 1 udp 16777215 198.51.100.7 40000 typ relay raddr 203.0.113.1 rport 12345";
const HOST: &str = "candidate:1 1 udp 2130706431 192.168.1.100 54321 typ host";

/// The candidate `add_local_candidate` announces for `init`.
fn surfaced(init: RTCIceCandidateInit) -> RTCIceCandidate {
    let mut pc = RTCPeerConnectionBuilder::new()
        .with_configuration(RTCConfigurationBuilder::new().build())
        .build(Instant::now())
        .expect("a peer connection");
    pc.add_local_candidate(init)
        .expect("the candidate is taken");
    while let Some(event) = pc.poll_event() {
        if let RTCPeerConnectionEvent::OnIceCandidateEvent(event) = event
            && let Some(candidate) = event.candidate
        {
            return candidate;
        }
    }
    panic!("no OnIceCandidateEvent");
}

fn init(
    candidate: &str,
    url: Option<&str>,
    relay_protocol: Option<RTCIceServerTransportProtocol>,
) -> RTCIceCandidateInit {
    RTCIceCandidateInit {
        candidate: candidate.to_owned(),
        sdp_mid: Some("0".to_owned()),
        sdp_mline_index: Some(0),
        username_fragment: None,
        url: url.map(str::to_owned),
        relay_protocol,
    }
}

#[test]
fn a_local_relay_candidate_carries_the_relay_protocol_the_application_gives() {
    for protocol in [
        RTCIceServerTransportProtocol::Udp,
        RTCIceServerTransportProtocol::Tcp,
        RTCIceServerTransportProtocol::Tls,
    ] {
        let candidate = surfaced(init(
            RELAY,
            Some("turn:turn.example.org:3478"),
            Some(protocol),
        ));
        assert_eq!(candidate.relay_protocol, protocol);
        assert_eq!(candidate.url.as_deref(), Some("turn:turn.example.org:3478"));
    }
}

#[test]
fn without_one_the_turn_url_names_the_relay_protocol() {
    for (url, protocol) in [
        (
            "turn:turn.example.org:3478",
            RTCIceServerTransportProtocol::Udp,
        ),
        (
            "turn:turn.example.org:3478?transport=udp",
            RTCIceServerTransportProtocol::Udp,
        ),
        (
            "turn:turn.example.org:3478?transport=tcp",
            RTCIceServerTransportProtocol::Tcp,
        ),
        (
            "turns:turn.example.org:5349",
            RTCIceServerTransportProtocol::Tls,
        ),
    ] {
        assert_eq!(
            surfaced(init(RELAY, Some(url), None)).relay_protocol,
            protocol,
            "{url}"
        );
    }
    assert_eq!(
        surfaced(init(RELAY, None, None)).relay_protocol,
        RTCIceServerTransportProtocol::Unspecified,
        "nothing says"
    );
}

#[test]
fn a_host_candidate_has_no_relay_protocol_and_no_url() {
    let candidate = surfaced(init(
        HOST,
        Some("turn:turn.example.org:3478"),
        Some(RTCIceServerTransportProtocol::Tcp),
    ));
    assert_eq!(
        candidate.relay_protocol,
        RTCIceServerTransportProtocol::Unspecified
    );
    assert_eq!(candidate.url, None);
}

#[test]
fn the_relay_protocol_serializes_as_in_webidl() {
    let json = serde_json::to_string(&init(RELAY, None, Some(RTCIceServerTransportProtocol::Tls)))
        .unwrap();
    assert!(json.contains(r#""relayProtocol":"tls""#), "{json}");
    for (protocol, name) in [
        (RTCIceServerTransportProtocol::Udp, "\"udp\""),
        (RTCIceServerTransportProtocol::Tcp, "\"tcp\""),
        (RTCIceServerTransportProtocol::Tls, "\"tls\""),
    ] {
        assert_eq!(serde_json::to_string(&protocol).unwrap(), name);
    }
    let parsed: RTCIceCandidateInit =
        serde_json::from_str(r#"{"candidate":"","relayProtocol":"tcp"}"#).unwrap();
    assert_eq!(
        parsed.relay_protocol,
        Some(RTCIceServerTransportProtocol::Tcp)
    );
}

/// W3C webrtc-pc 4.2.3 (RTCIceTransportPolicy "relay"): only candidates the policy permits are
/// surfaced and used. A host or server-reflexive candidate added under the relay policy raises
/// no `icecandidate` event; a relay candidate does.
#[test]
fn under_the_relay_policy_only_relay_candidates_are_surfaced() {
    let mut pc = RTCPeerConnectionBuilder::new()
        .with_configuration(
            RTCConfigurationBuilder::new()
                .with_ice_transport_policy(RTCIceTransportPolicy::Relay)
                .build(),
        )
        .build(Instant::now())
        .expect("a peer connection");
    let surfaced = |pc: &mut rtci::peer_connection::RTCPeerConnection| {
        let mut candidates = vec![];
        while let Some(event) = pc.poll_event() {
            if let RTCPeerConnectionEvent::OnIceCandidateEvent(event) = event
                && let Some(candidate) = event.candidate
            {
                candidates.push(candidate);
            }
        }
        candidates
    };
    pc.add_local_candidate(init(HOST, None, None)).unwrap();
    pc.add_local_candidate(init(
        "candidate:2 1 udp 1694498815 203.0.113.1 12345 typ srflx raddr 192.168.1.100 rport 54321",
        Some("stun:stun.example.org:3478"),
        None,
    ))
    .unwrap();
    assert!(
        surfaced(&mut pc).is_empty(),
        "host and srflx are not surfaced"
    );
    pc.add_local_candidate(init(RELAY, Some("turn:turn.example.org:3478"), None))
        .unwrap();
    let candidates = surfaced(&mut pc);
    assert_eq!(candidates.len(), 1);
    assert_eq!(
        candidates[0].typ,
        rtci::peer_connection::transport::RTCIceCandidateType::Relay
    );
}
