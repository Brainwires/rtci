//! W3C webrtc-pc 4.8.1, `RTCIceCandidate.address`: "By default, the user agent MUST leave the
//! address attribute as null for any exposed remote candidate. Once a RTCPeerConnection
//! instance learns on an address by the web application using addIceCandidate, the user agent
//! can expose the address". Peer B is told no candidate of A: it learns A as a peer-reflexive
//! candidate from A's checks, and the selected pair (and every listed pair) shows that remote
//! candidate without its address, until B's application adds A's candidate.

mod dtls_sdp_common;

use anyhow::Result;
use dtls_sdp_common::{Peer, World};
use rtc::peer_connection::configuration::setting_engine::SettingEngineBuilder;
use rtc::peer_connection::transport::RTCIceCandidateType;

const A: &str = "10.0.0.1:5000";
const B: &str = "10.0.0.2:5000";

fn selected_remote(peer: &Peer) -> rtc::peer_connection::transport::RTCIceCandidate {
    peer.pc
        .sctp()
        .expect("the data channel's transport")
        .transport()
        .ice_transport()
        .get_selected_candidate_pair()
        .expect("a selected pair")
        .remote()
        .clone()
}

#[test]
fn a_peer_reflexive_remote_candidate_is_exposed_without_its_address() -> Result<()> {
    let mut world = World::new(
        Peer::new(A, SettingEngineBuilder::new().build())?,
        Peer::new(B, SettingEngineBuilder::new().build())?,
    );
    world.peers[0].pc.create_data_channel("data", None)?;
    world.exchange(0)?;
    // A learns B's candidate; B is told nothing of A's.
    let a_candidate = world.peers[0].candidate()?;
    world.peers[0].pc.add_local_candidate(a_candidate.clone())?;
    let b_candidate = world.peers[1].candidate()?;
    world.peers[1].pc.add_local_candidate(b_candidate.clone())?;
    world.peers[0].pc.add_remote_candidate(b_candidate)?;
    world.run("connected through a peer-reflexive candidate", |peers| {
        peers.iter().all(|p| p.connected())
    })?;

    let remote = selected_remote(&world.peers[1]);
    assert_eq!(remote.typ, RTCIceCandidateType::Prflx);
    assert_eq!(remote.address, "", "withheld (null)");
    let pairs = world.peers[1]
        .pc
        .sctp()
        .expect("the transport")
        .transport()
        .ice_transport()
        .get_candidate_pairs();
    assert!(!pairs.is_empty());
    assert!(
        pairs
            .iter()
            .filter(|pair| pair.remote().typ == RTCIceCandidateType::Prflx)
            .all(|pair| pair.remote().address.is_empty())
    );
    // A's side: B's candidate was signalled, so it is exposed with its address.
    assert_eq!(selected_remote(&world.peers[0]).address, "10.0.0.2");

    // B's application now supplies A's address: it may be exposed.
    world.peers[1].pc.add_remote_candidate(a_candidate)?;
    world.run_for(std::time::Duration::from_millis(200), |_| false);
    let remote = selected_remote(&world.peers[1]);
    assert_eq!(remote.address, "10.0.0.1", "learned from the application");
    Ok(())
}
