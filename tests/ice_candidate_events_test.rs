//! Integration test to verify ICE candidate events are emitted correctly
//!
//! This test verifies that when local candidates (host and srflx) are added
//! via add_local_candidate(), the OnIceCandidateEvent is properly emitted
//! and can be retrieved via poll_event().

use rtci::peer_connection::RTCPeerConnectionBuilder;
use rtci::peer_connection::configuration::RTCConfigurationBuilder;
use rtci::peer_connection::event::RTCPeerConnectionEvent;
use rtci::peer_connection::transport::RTCIceCandidateInit;
use rtci::sansio::Protocol;
use std::time::Instant;

#[test]
fn test_host_candidate_event_emission() {
    // Create a basic RTCPeerConnection
    let config = RTCConfigurationBuilder::new().build();
    let mut pc = RTCPeerConnectionBuilder::new()
        .with_configuration(config)
        .build(Instant::now())
        .expect("Failed to create peer connection");

    // Create a host candidate
    let host_candidate = RTCIceCandidateInit {
        candidate: "candidate:1 1 udp 2130706431 192.168.1.100 54321 typ host".to_string(),
        sdp_mid: Some("0".to_string()),
        sdp_mline_index: Some(0),
        username_fragment: Some("test".to_string()),
        url: None,
        relay_protocol: None,
    };

    println!("🔍 Adding host candidate: {}", host_candidate.candidate);

    // Add the host candidate
    pc.add_local_candidate(host_candidate)
        .expect("Failed to add host candidate");

    // Poll for events
    let mut found_event = false;
    let mut event_count = 0;
    while let Some(event) = pc.poll_event() {
        event_count += 1;
        println!(
            "📨 Polled event #{}: {:?}",
            event_count,
            std::mem::discriminant(&event)
        );

        if let RTCPeerConnectionEvent::OnIceCandidateEvent(ice_event) = event {
            let Some(candidate) = ice_event.candidate else {
                continue;
            };
            println!("✅ Received OnIceCandidateEvent for host candidate");
            println!("   Address: {}:{}", candidate.address, candidate.port);
            println!("   Type: {:?}", candidate.typ);
            println!("   Foundation: {}", candidate.foundation);
            assert_eq!(
                candidate.typ,
                rtci::peer_connection::transport::RTCIceCandidateType::Host
            );
            found_event = true;
        }
    }

    println!("📊 Total events polled: {}", event_count);
    assert!(
        found_event,
        "OnIceCandidateEvent was not emitted for host candidate"
    );
}

#[test]
fn test_srflx_candidate_event_emission() {
    // Create a basic RTCPeerConnection
    let config = RTCConfigurationBuilder::new().build();
    let mut pc = RTCPeerConnectionBuilder::new()
        .with_configuration(config)
        .build(Instant::now())
        .expect("Failed to create peer connection");

    // Create an srflx candidate (server reflexive)
    let srflx_candidate = RTCIceCandidateInit {
        candidate: "candidate:2 1 udp 1694498815 203.0.113.1 12345 typ srflx raddr 192.168.1.100 rport 54321".to_string(),
        sdp_mid: Some("0".to_string()),
        sdp_mline_index: Some(0),
        username_fragment: Some("test".to_string()),
        url: Some("stun:stun.example.com:3478".to_string()),
        relay_protocol: None,
    };

    println!("🔍 Adding srflx candidate: {}", srflx_candidate.candidate);

    // Add the srflx candidate
    pc.add_local_candidate(srflx_candidate)
        .expect("Failed to add srflx candidate");

    // Poll for events
    let mut found_event = false;
    let mut event_count = 0;
    while let Some(event) = pc.poll_event() {
        event_count += 1;
        println!(
            "📨 Polled event #{}: {:?}",
            event_count,
            std::mem::discriminant(&event)
        );

        if let RTCPeerConnectionEvent::OnIceCandidateEvent(ice_event) = event {
            let Some(candidate) = ice_event.candidate else {
                continue;
            };
            println!("✅ Received OnIceCandidateEvent for srflx candidate");
            println!("   Address: {}:{}", candidate.address, candidate.port);
            println!("   Type: {:?}", candidate.typ);
            println!("   Foundation: {}", candidate.foundation);
            println!("   URL: {:?}", ice_event.url);
            assert_eq!(
                candidate.typ,
                rtci::peer_connection::transport::RTCIceCandidateType::Srflx
            );
            assert_eq!(ice_event.url.as_deref(), Some("stun:stun.example.com:3478"));
            found_event = true;
        }
    }

    println!("📊 Total events polled: {}", event_count);
    assert!(
        found_event,
        "OnIceCandidateEvent was not emitted for srflx candidate"
    );
}

#[test]
fn test_multiple_candidates_events() {
    // Create a basic RTCPeerConnection
    let config = RTCConfigurationBuilder::new().build();
    let mut pc = RTCPeerConnectionBuilder::new()
        .with_configuration(config)
        .build(Instant::now())
        .expect("Failed to create peer connection");

    // Add multiple candidates
    let candidates = [RTCIceCandidateInit {
            candidate: "candidate:1 1 udp 2130706431 192.168.1.100 54321 typ host".to_string(),
            sdp_mid: Some("0".to_string()),
            sdp_mline_index: Some(0),
            username_fragment: Some("test".to_string()),
            url: None,
            relay_protocol: None,
        },
        RTCIceCandidateInit {
            candidate: "candidate:2 1 udp 1694498815 203.0.113.1 12345 typ srflx raddr 192.168.1.100 rport 54321".to_string(),
            sdp_mid: Some("0".to_string()),
            sdp_mline_index: Some(0),
            username_fragment: Some("test".to_string()),
            url: Some("stun:stun.example.com:3478".to_string()),
            relay_protocol: None,
        }];

    println!("🔍 Adding {} candidates", candidates.len());
    for (i, candidate) in candidates.iter().enumerate() {
        println!("  [{}] {}", i, candidate.candidate);
        pc.add_local_candidate(candidate.clone())
            .expect("Failed to add candidate");
    }

    // Poll for all events
    let mut total_events = 0;
    let mut ice_events = 0;
    let mut host_found = false;
    let mut srflx_found = false;

    while let Some(event) = pc.poll_event() {
        total_events += 1;
        println!(
            "📨 Event #{}: {:?}",
            total_events,
            std::mem::discriminant(&event)
        );

        if let RTCPeerConnectionEvent::OnIceCandidateEvent(ice_event) = event {
            let Some(candidate) = ice_event.candidate else {
                continue;
            };
            ice_events += 1;
            println!(
                "✅ ICE Event {}: {:?} candidate at {}:{}",
                ice_events, candidate.typ, candidate.address, candidate.port
            );

            match candidate.typ {
                rtci::peer_connection::transport::RTCIceCandidateType::Host => host_found = true,
                rtci::peer_connection::transport::RTCIceCandidateType::Srflx => srflx_found = true,
                _ => {}
            }
        }
    }

    println!(
        "📊 Total events: {}, ICE candidate events: {}",
        total_events, ice_events
    );
    assert_eq!(
        ice_events, 2,
        "Expected 2 OnIceCandidateEvents, got {}",
        ice_events
    );
    assert!(host_found, "Host candidate event not found");
    assert!(srflx_found, "Srflx candidate event not found");
}

/// W3C webrtc-pc 4.8.1 `relayProtocol` and `url`, 4.8.1.5 `RTCIceServerTransportProtocol`: a
/// surfaced local relay candidate carries the protocol to its TURN server, the one the
/// application supplied in `RTCLocalIceCandidateInit.relayProtocol` or, left out, the one its
/// TURN URL names ("udp", "tcp", "tls"); a host candidate has neither member.
#[test]
fn a_local_relay_candidate_carries_its_relay_protocol_and_url() {
    use rtci::peer_connection::transport::{RTCIceCandidateType, RTCIceServerTransportProtocol};

    let mut pc = RTCPeerConnectionBuilder::new()
        .with_configuration(RTCConfigurationBuilder::new().build())
        .build(Instant::now())
        .expect("a peer connection");
    let relay = |port: u16, url: &str, relay_protocol| RTCIceCandidateInit {
        candidate: format!(
            "candidate:{port} 1 udp 16777215 198.51.100.7 {port} typ relay raddr 203.0.113.1 rport 40000"
        ),
        url: Some(url.to_owned()),
        relay_protocol,
        ..Default::default()
    };
    let cases = [
        (
            relay(41001, "turn:turn.example.com:3478", None),
            RTCIceServerTransportProtocol::Udp,
        ),
        (
            relay(41002, "turn:turn.example.com:3478?transport=tcp", None),
            RTCIceServerTransportProtocol::Tcp,
        ),
        (
            relay(41003, "turns:turn.example.com:5349", None),
            RTCIceServerTransportProtocol::Tls,
        ),
        // What the application says wins over what the URL suggests.
        (
            relay(
                41004,
                "turn:turn.example.com:3478",
                Some(RTCIceServerTransportProtocol::Tcp),
            ),
            RTCIceServerTransportProtocol::Tcp,
        ),
    ];
    for (init, expected) in cases {
        let url = init.url.clone();
        pc.add_local_candidate(init).expect("a relay candidate");
        let surfaced = std::iter::from_fn(|| pc.poll_event())
            .find_map(|event| match event {
                RTCPeerConnectionEvent::OnIceCandidateEvent(e) => e.candidate,
                _ => None,
            })
            .expect("the candidate is surfaced");
        assert_eq!(surfaced.typ, RTCIceCandidateType::Relay);
        assert_eq!(surfaced.relay_protocol, expected, "{url:?}");
        assert_eq!(surfaced.url, url);
    }

    pc.add_local_candidate(RTCIceCandidateInit {
        candidate: "candidate:9 1 udp 2130706431 192.168.1.100 54329 typ host".to_owned(),
        url: Some("turn:turn.example.com:3478".to_owned()),
        relay_protocol: Some(RTCIceServerTransportProtocol::Udp),
        ..Default::default()
    })
    .expect("a host candidate");
    let host = std::iter::from_fn(|| pc.poll_event())
        .find_map(|event| match event {
            RTCPeerConnectionEvent::OnIceCandidateEvent(e) => e.candidate,
            _ => None,
        })
        .expect("the host candidate is surfaced");
    assert_eq!(
        host.relay_protocol,
        RTCIceServerTransportProtocol::Unspecified
    );
    assert_eq!(host.url, None);
}

/// W3C webrtc-pc 4.2.3 `iceTransportPolicy` "relay": only the candidates the policy permits
/// are surfaced (and used for checks). A host candidate the application gathers raises no
/// `icecandidate` event; a relay one does.
#[test]
fn under_the_relay_policy_only_relay_candidates_are_surfaced() {
    use rtci::peer_connection::configuration::RTCIceTransportPolicy;
    use rtci::peer_connection::transport::RTCIceCandidateType;

    let mut pc = RTCPeerConnectionBuilder::new()
        .with_configuration(
            RTCConfigurationBuilder::new()
                .with_ice_transport_policy(RTCIceTransportPolicy::Relay)
                .build(),
        )
        .build(Instant::now())
        .expect("a peer connection");
    while pc.poll_event().is_some() {}
    let surfaced = |pc: &mut rtci::peer_connection::RTCPeerConnection| {
        std::iter::from_fn(|| pc.poll_event())
            .filter_map(|event| match event {
                RTCPeerConnectionEvent::OnIceCandidateEvent(e) => e.candidate.map(|c| c.typ),
                _ => None,
            })
            .collect::<Vec<_>>()
    };
    let _ = pc.add_local_candidate(RTCIceCandidateInit {
        candidate: "candidate:1 1 udp 2130706431 192.168.1.100 54321 typ host".to_owned(),
        ..Default::default()
    });
    assert!(
        surfaced(&mut pc).is_empty(),
        "the host candidate is not surfaced"
    );
    pc.add_local_candidate(RTCIceCandidateInit {
        candidate:
            "candidate:2 1 udp 16777215 198.51.100.7 41005 typ relay raddr 203.0.113.1 rport 40000"
                .to_owned(),
        url: Some("turn:turn.example.com:3478".to_owned()),
        ..Default::default()
    })
    .expect("a relay candidate");
    assert_eq!(surfaced(&mut pc), vec![RTCIceCandidateType::Relay]);
}
