//! Application-Layer Protocol Negotiation in the DTLS handshake (RFC 8835 section 3.5,
//! RFC 8833): the DTLS client offers `webrtc` and `c-webrtc`, the server selects `webrtc`, and
//! both peer connections report it, whichever side is the DTLS client. A peer that uses no
//! ALPN (`with_dtls_alpn(false)`) connects all the same, with no protocol selected.
//!
//! Two `rtci` peers on a simulated network; virtual time, no sockets.

mod dtls_sdp_common;

use anyhow::Result;
use dtls_sdp_common::{Peer, World};
use rtci::peer_connection::configuration::setting_engine::SettingEngineBuilder;
use rtci::peer_connection::transport::{RTCDtlsRole, RTCDtlsTransportState};

fn peer(addr: &str, alpn: bool, answering_role: Option<RTCDtlsRole>) -> Result<Peer> {
    let mut setting_engine = SettingEngineBuilder::new().with_dtls_alpn(alpn);
    if let Some(role) = answering_role {
        setting_engine = setting_engine.with_answering_dtls_role(role);
    }
    Peer::new(addr, setting_engine.build())
}

/// RFC 8833 section 2: "A peer in the client role MUST offer both identifiers if it is not
/// aware of a need for confidentiality", and "A peer in the server role SHOULD select
/// "webrtc" if it does not prefer either". Both peer connections report `webrtc`, with the
/// answerer as the DTLS client and as the server.
#[test]
fn the_dtls_handshake_negotiates_the_webrtc_alpn_identifier() -> Result<()> {
    for answering_role in [None, Some(RTCDtlsRole::Server)] {
        let what = format!("the answerer answers as {answering_role:?}");
        let mut world = World::new(
            peer("10.0.0.1:5000", true, None)?,
            peer("10.0.0.2:5000", true, answering_role)?,
        );
        world.connect()?;
        world.ping_pong(&what)?;
        for i in 0..2 {
            assert_eq!(
                world.peers[i].pc.dtls_application_protocol(),
                Some("webrtc"),
                "{what}: peer {i}"
            );
        }
    }
    Ok(())
}

/// RFC 8833 section 2: "A peer that is willing to accept "webrtc" SHOULD assume that a peer
/// that does not support this specification has negotiated "webrtc"". A peer without ALPN, as
/// the DTLS client or the server, connects with one that has it: the data channel carries
/// messages and neither side reports a protocol.
#[test]
fn a_peer_without_alpn_still_connects() -> Result<()> {
    for alpn in [[true, false], [false, true]] {
        for answering_role in [None, Some(RTCDtlsRole::Server)] {
            let what = format!("ALPN {alpn:?}, the answerer answers as {answering_role:?}");
            let mut world = World::new(
                peer("10.0.0.1:5000", alpn[0], None)?,
                peer("10.0.0.2:5000", alpn[1], answering_role)?,
            );
            world.connect()?;
            world.ping_pong(&what)?;
            let now = world.now;
            for i in 0..2 {
                assert_eq!(
                    world.peers[i].dtls_state(now),
                    RTCDtlsTransportState::Connected,
                    "{what}: peer {i}"
                );
                assert_eq!(
                    world.peers[i].pc.dtls_application_protocol(),
                    None,
                    "{what}: peer {i}"
                );
            }
        }
    }
    Ok(())
}
