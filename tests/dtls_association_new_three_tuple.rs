//! A new DTLS association over UDP runs on a new 3-tuple (RFC 8842 section 5.1):
//!
//! > if an unordered transport is used for the DTLS association, a new 3-tuple
//! > (transport/source address/source port) MUST be allocated by at least one of the
//! > endpoints so that DTLS packets can be demultiplexed.
//! >
//! > When an offerer needs to establish a new DTLS association, and if an unordered transport
//! > (e.g., UDP) is used, the offerer MUST allocate a new 3-tuple for the offer [...]. This
//! > typically means using a local address and/or port, or a set of ICE candidates (see
//! > Section 6), which were not recently used for any other DTLS association.
//! >
//! > When an answerer needs to establish a new DTLS association, if an unordered transport is
//! > used, and the offerer did not allocate a new 3-tuple, the answerer MUST allocate a new
//! > 3-tuple for the answer [...].
//!
//! The engine has no sockets: the application gives it its candidates. What the engine does
//! is to drop, with the ICE restart that comes with the new association, the local candidates
//! of the association it replaces (even when `with_discard_local_candidates_during_ice_restart`
//! is not set), and to refuse a UDP candidate on one of their transport addresses, so that the
//! new association can only run on new ones. Both sides do it: the offerer that asks for the
//! association, and the answerer (with trickle ICE it cannot know whether the offerer did).
//! `with_dtls_new_association_on_previous_addresses(true)` keeps the old behaviour.

mod dtls_sdp_common;

use anyhow::Result;
use dtls_sdp_common::{Peer, World};
use rtc::peer_connection::RTCPeerConnection;
use rtc::peer_connection::configuration::setting_engine::{SettingEngine, SettingEngineBuilder};
use rtc::shared::error::Error;
use std::net::SocketAddr;

const A: &str = "10.0.0.1:5000";
const B: &str = "10.0.0.2:5000";
const A_NEW: &str = "10.0.0.1:5001";
const B_NEW: &str = "10.0.0.2:5001";

/// The transport addresses of the local candidates the peer's ICE transport holds.
fn local_candidates(pc: &RTCPeerConnection) -> Vec<SocketAddr> {
    pc.sctp()
        .expect("sctp")
        .transport()
        .ice_transport()
        .get_local_candidates()
        .iter()
        .map(|c| SocketAddr::new(c.address.parse().expect("an IP"), c.port))
        .collect()
}

/// A and B connected, then A asks for a new DTLS association (`renew_dtls_association`)
/// and the offer is answered: the offer and the answer are an ICE restart with a new
/// `tls-id` (RFC 9429 section 5.8.3, RFC 8842 section 6).
fn renewed(setting_engine: impl Fn() -> SettingEngine) -> Result<World> {
    let mut world = World::new(
        Peer::new(A, setting_engine())?,
        Peer::new(B, setting_engine())?,
    );
    world.connect()?;
    world.ping_pong("the first association")?;
    for p in &world.peers {
        assert_eq!(
            local_candidates(&p.pc),
            [p.addr],
            "before the new association"
        );
    }
    world.peers[0].pc.renew_dtls_association();
    world.exchange(0)?;
    Ok(world)
}

#[test]
fn a_new_association_drops_the_local_candidates_and_refuses_their_addresses() -> Result<()> {
    let mut world = renewed(|| SettingEngineBuilder::new().build())?;
    for (i, who) in ["the offerer", "the answerer"].into_iter().enumerate() {
        let peer = &mut world.peers[i];
        assert_eq!(
            local_candidates(&peer.pc),
            Vec::<SocketAddr>::new(),
            "{who} holds no candidate of the previous association"
        );
        let old = peer.candidate()?;
        match peer.pc.add_local_candidate(old) {
            Err(Error::ErrICECandidateAddressOfPreviousDtlsAssociation(addr)) => {
                assert_eq!(addr, peer.addr, "{who}")
            }
            other => panic!("{who}: the previous address is refused, got {other:?}"),
        }
    }
    // On new ports the new association is established and carries the data channel.
    world.peers[0].addr = A_NEW.parse()?;
    world.peers[1].addr = B_NEW.parse()?;
    world.trickle()?;
    world.run("the new association", |peers| {
        peers.iter().all(|p| p.connected())
    })?;
    world.ping_pong("on the new 3-tuples")?;
    for p in &world.peers {
        assert_eq!(
            local_candidates(&p.pc),
            [p.addr],
            "after the new association"
        );
    }
    Ok(())
}

/// An ICE restart that keeps the DTLS association (RFC 8842 section 6: "an ICE restart does
/// not by default require a new DTLS association") keeps the local candidates.
#[test]
fn an_ice_restart_without_a_new_association_keeps_the_local_candidates() -> Result<()> {
    let mut world = World::new(
        Peer::new(A, SettingEngineBuilder::new().build())?,
        Peer::new(B, SettingEngineBuilder::new().build())?,
    );
    world.connect()?;
    world.peers[0].pc.restart_ice();
    world.exchange(0)?;
    for p in &world.peers {
        assert_eq!(local_candidates(&p.pc), [p.addr], "an ICE restart alone");
    }
    world.ping_pong("after the ICE restart")?;
    Ok(())
}

/// `with_dtls_new_association_on_previous_addresses(true)`: the new association keeps the
/// local candidates and runs on the previous 3-tuples.
#[test]
fn with_dtls_new_association_on_previous_addresses_the_candidates_are_kept() -> Result<()> {
    let mut world = renewed(|| {
        SettingEngineBuilder::new()
            .with_dtls_new_association_on_previous_addresses(true)
            .build()
    })?;
    for p in &mut world.peers {
        assert_eq!(local_candidates(&p.pc), [p.addr], "kept");
        let old = p.candidate()?;
        p.pc.add_local_candidate(old)?;
    }
    world.run("the new association", |peers| {
        peers.iter().all(|p| p.connected())
    })?;
    world.ping_pong("on the previous 3-tuples")?;
    Ok(())
}
