//! RFC 8445 section 6.1.1: "If both agents are lite, the initiating agent MUST take the
//! controlling role"; with one full and one lite, the full one does (6.1.1-2, see
//! `webrtc_pc_signaling_clauses.rs`). Two lite engine peers: the offerer is controlling, the
//! answerer controlled, and both descriptions say `a=ice-lite`.

mod dtls_sdp_common;

use anyhow::Result;
use dtls_sdp_common::{Peer, World};
use rtc::peer_connection::configuration::setting_engine::SettingEngineBuilder;
use rtc::peer_connection::transport::RTCIceRole;

const A: &str = "10.0.0.1:5000";
const B: &str = "10.0.0.2:5000";

#[test]
fn when_both_agents_are_lite_the_offerer_is_controlling() -> Result<()> {
    let lite = || SettingEngineBuilder::new().with_lite(true).build();
    let mut world = World::new(Peer::new(A, lite())?, Peer::new(B, lite())?);
    world.peers[0].pc.create_data_channel("data", None)?;
    let (offer, answer) = world.exchange(0)?;
    assert!(offer.contains("a=ice-lite"), "{offer}");
    assert!(answer.contains("a=ice-lite"), "{answer}");
    let role = |peer: &Peer| {
        peer.pc
            .sctp()
            .expect("the data channel's transport")
            .transport()
            .ice_transport()
            .role()
    };
    assert_eq!(role(&world.peers[0]), RTCIceRole::Controlling);
    assert_eq!(role(&world.peers[1]), RTCIceRole::Controlled);
    Ok(())
}
