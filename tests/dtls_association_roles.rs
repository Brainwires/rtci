//! The DTLS roles of an association are fixed for its life (RFC 8842 section 5.3).
//!
//! "If an answerer receives an offer that does not require the establishment of a new DTLS
//! association, and if the answerer determines that a new DTLS association is not to be
//! established, the answerer MUST insert [...] an SDP 'setup' attribute with an attribute value
//! that does not change the previously negotiated DTLS roles". An ICE restart by itself keeps
//! the association (section 6).
//!
//! The answer's `a=setup` used to come from the answering configuration and the offer alone:
//! the peer that offered first, and so was the DTLS server, answered a later `actpass` offer
//! with `active`. Its peer, the client, then either refused the role change (libwebrtc: "Failed
//! to set SSL role for the transport") or, with an ICE restart in the same exchange, both
//! `rtci` peers tore their healthy association down and waited for a ClientHello that the other
//! did not send.

mod dtls_sdp_common;

use anyhow::Result;
use dtls_sdp_common::{Peer, World, attribute_values};
use rtci::peer_connection::configuration::setting_engine::SettingEngineBuilder;
use rtci::peer_connection::transport::{RTCDtlsRole, RTCDtlsTransportState};

/// The one `a=setup` value of a description.
fn setup(sdp: &str) -> String {
    let mut values = attribute_values(sdp, "setup");
    values.dedup();
    assert_eq!(values.len(), 1, "one setup value in\n{sdp}");
    values.remove(0)
}

fn peer(addr: &str, answering_dtls_role: Option<RTCDtlsRole>) -> Result<Peer> {
    let mut setting_engine = SettingEngineBuilder::new();
    if let Some(role) = answering_dtls_role {
        setting_engine = setting_engine.with_answering_dtls_role(role);
    }
    Peer::new(addr, setting_engine.build())
}

/// Connects peer 0 (first offerer) and peer 1, then runs one more exchange offered by
/// `reoffer_by`, with or without an ICE restart, and checks that nothing about the DTLS
/// association changed.
fn roles_are_kept(
    answering_roles: [Option<RTCDtlsRole>; 2],
    reoffer_by: usize,
    ice_restart: bool,
) -> Result<()> {
    let what = format!(
        "answering roles {answering_roles:?}, re-offer by peer {reoffer_by}, ICE restart {ice_restart}"
    );
    let mut world = World::new(
        peer("10.0.0.1:5000", answering_roles[0])?,
        peer("10.0.0.2:5000", answering_roles[1])?,
    );
    let (offer, answer) = world.connect()?;
    assert_eq!(setup(&offer), "actpass", "{what}");
    let first_answer_setup = setup(&answer);
    world.ping_pong(&what)?;

    let now = world.now;
    let roles = [world.peers[0].dtls_role(now), world.peers[1].dtls_role(now)];
    let expected = if first_answer_setup == "active" {
        [RTCDtlsRole::Server, RTCDtlsRole::Client]
    } else {
        [RTCDtlsRole::Client, RTCDtlsRole::Server]
    };
    assert_eq!(
        roles, expected,
        "{what}: the first answer said {first_answer_setup}"
    );
    let certificates = [
        world.peers[0].remote_certificate(),
        world.peers[1].remote_certificate(),
    ];

    if ice_restart {
        world.peers[reoffer_by].pc.restart_ice();
    }
    let (offer, answer) = world.exchange(reoffer_by)?;
    assert_eq!(setup(&offer), "actpass", "{what}: a subsequent offer");
    // The answerer of this exchange states the role it has.
    let answerer_role = roles[1 - reoffer_by];
    assert_eq!(
        setup(&answer),
        if answerer_role == RTCDtlsRole::Client {
            "active"
        } else {
            "passive"
        },
        "{what}: the answer must not change the negotiated roles (the answerer is the DTLS \
         {answerer_role})"
    );
    // Neither peer gave its association up when it applied the other's description.
    for i in 0..2 {
        assert_eq!(
            world.peers[i].dtls_state(now),
            RTCDtlsTransportState::Connected,
            "{what}: peer {i}'s DTLS transport after the exchange"
        );
    }

    if ice_restart {
        world.trickle()?;
        world.run(&format!("{what}: the restart selects a pair"), |peers| {
            peers.iter().all(|p| p.connected())
        })?;
    }
    world.ping_pong(&format!("{what}: after the exchange"))?;
    let now = world.now;
    for i in 0..2 {
        assert_eq!(world.peers[i].dtls_role(now), roles[i], "{what}: peer {i}");
        assert_eq!(
            world.peers[i].dtls_state(now),
            RTCDtlsTransportState::Connected,
            "{what}: peer {i}"
        );
        assert_eq!(
            world.peers[i].remote_certificate(),
            certificates[i],
            "{what}: peer {i}"
        );
        assert!(!world.peers[i].failed(), "{what}: peer {i}");
    }
    Ok(())
}

/// The peer that offered first (the DTLS server by default) answers a later offer `passive`,
/// and the peer that answered first answers a later offer with the role it took, whatever
/// `answering_dtls_role` either was built with.
#[test]
fn the_answer_to_a_later_offer_keeps_the_negotiated_dtls_roles() -> Result<()> {
    for answering_roles in [
        [None, None],
        [None, Some(RTCDtlsRole::Server)],
        [Some(RTCDtlsRole::Client), Some(RTCDtlsRole::Client)],
        [Some(RTCDtlsRole::Server), Some(RTCDtlsRole::Server)],
    ] {
        for reoffer_by in [0, 1] {
            roles_are_kept(answering_roles, reoffer_by, false)?;
        }
    }
    Ok(())
}

/// An ICE restart offered by either peer, the one that answered first included, keeps the DTLS
/// association and its roles (RFC 8842 section 6): data flows over the same association once
/// the restart has selected its pair.
#[test]
fn an_ice_restart_offered_by_either_peer_keeps_the_dtls_association() -> Result<()> {
    for answering_roles in [[None, None], [None, Some(RTCDtlsRole::Server)]] {
        for reoffer_by in [0, 1] {
            roles_are_kept(answering_roles, reoffer_by, true)?;
        }
    }
    Ok(())
}
