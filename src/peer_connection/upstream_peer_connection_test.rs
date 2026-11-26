//! Upstream `webrtc` v0.17.1's `test_set_get_configuration` and `test_peer_connection_state`
//! (`peer_connection/peer_connection_test.rs`), on the sans-I/O peer connection.

use std::time::Instant;

use sansio::Protocol;

use crate::peer_connection::RTCPeerConnectionBuilder;
use crate::peer_connection::configuration::{RTCConfigurationBuilder, RTCIceServer};
use crate::peer_connection::state::{RTCIceConnectionState, RTCPeerConnectionState};
use crate::peer_connection::transport::RTCDtlsTransportState;
use shared::error::Result;

#[test]
fn test_set_get_configuration() -> Result<()> {
    let initial = RTCConfigurationBuilder::new()
        .with_ice_servers(vec![RTCIceServer {
            urls: vec!["stun:stun.invalid:3478".to_owned()],
            ..Default::default()
        }])
        .build();
    let mut pc = RTCPeerConnectionBuilder::new()
        .with_configuration(initial.clone())
        .build(Instant::now())?;
    assert_eq!(pc.get_configuration().ice_servers, initial.ice_servers);

    let updated = RTCConfigurationBuilder::new()
        .with_ice_servers(vec![RTCIceServer {
            urls: vec![
                "turn:turn.example.org".to_owned(),
                "turn:turn2.example.org".to_owned(),
            ],
            username: "user".to_owned(),
            credential: "secret".to_owned(),
        }])
        .build();
    pc.set_configuration(updated.clone())?;
    assert_eq!(pc.get_configuration().ice_servers, updated.ice_servers);
    Ok(())
}

#[test]
fn test_peer_connection_state() -> Result<()> {
    let mut pc = RTCPeerConnectionBuilder::new().build(Instant::now())?;
    assert_eq!(pc.peer_connection_state, RTCPeerConnectionState::New);

    for (ice, dtls, expected) in [
        (
            RTCIceConnectionState::Checking,
            RTCDtlsTransportState::New,
            RTCPeerConnectionState::Connecting,
        ),
        (
            RTCIceConnectionState::Connected,
            RTCDtlsTransportState::New,
            RTCPeerConnectionState::Connecting,
        ),
        (
            RTCIceConnectionState::Connected,
            RTCDtlsTransportState::Connecting,
            RTCPeerConnectionState::Connecting,
        ),
        (
            RTCIceConnectionState::Connected,
            RTCDtlsTransportState::Connected,
            RTCPeerConnectionState::Connected,
        ),
        (
            RTCIceConnectionState::Completed,
            RTCDtlsTransportState::Connected,
            RTCPeerConnectionState::Connected,
        ),
        (
            RTCIceConnectionState::Connected,
            RTCDtlsTransportState::Closed,
            RTCPeerConnectionState::Connected,
        ),
        (
            RTCIceConnectionState::Disconnected,
            RTCDtlsTransportState::Connected,
            RTCPeerConnectionState::Disconnected,
        ),
        (
            RTCIceConnectionState::Failed,
            RTCDtlsTransportState::Connected,
            RTCPeerConnectionState::Failed,
        ),
        (
            RTCIceConnectionState::Connected,
            RTCDtlsTransportState::Failed,
            RTCPeerConnectionState::Failed,
        ),
    ] {
        pc.ice_transport_mut().ice_connection_state = ice;
        pc.dtls_transport_mut().state = dtls;
        pc.update_connection_state(false);
        assert_eq!(pc.peer_connection_state, expected, "ice {ice}, dtls {dtls}");
    }

    pc.close()?;
    assert_eq!(pc.peer_connection_state, RTCPeerConnectionState::Closed);
    Ok(())
}
