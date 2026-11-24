//! W3C webrtc 4.4.1.4: "If description is of type "answer" or "pranswer" ... If description
//! initiates the establishment of a new SCTP association ... or an SCTP association already
//! exists, update the data max message size" (6.1.1.2). A renegotiation that keeps the
//! association but changes the remote `a=max-message-size` (RFC 8841 section 6) changes
//! `maxMessageSize` and what the association lets this side send; a provisional answer
//! does as much.
//!
//! Two `rtci` peers on a simulated network; virtual time, no sockets.

mod dtls_sdp_common;

use anyhow::Result;
use bytes::BytesMut;
use dtls_sdp_common::{Peer, World, replace_lines};
use rtci::peer_connection::configuration::setting_engine::SettingEngineBuilder;
use rtci::peer_connection::sdp::RTCSessionDescription;

fn world() -> Result<World> {
    Ok(World::new(
        Peer::new("10.0.0.1:5000", SettingEngineBuilder::new().build())?,
        Peer::new("10.0.0.2:5000", SettingEngineBuilder::new().build())?,
    ))
}

fn max_message_size(world: &World, peer: usize) -> Option<u32> {
    world.peers[peer]
        .pc
        .sctp()
        .expect("SCTP")
        .max_message_size()
}

fn with_max_message_size(sdp: &str, size: u32) -> String {
    replace_lines(
        sdp,
        "a=max-message-size:",
        Some(&format!("a=max-message-size:{size}")),
    )
}

#[test]
fn a_renegotiated_max_message_size_is_taken_by_the_running_association() -> Result<()> {
    let mut world = world()?;
    // The first answer states 20000: the association starts with that send limit.
    world.peers[0].pc.create_data_channel("data", None)?;
    world.exchange_with(
        0,
        |sdp| sdp.to_owned(),
        |sdp| with_max_message_size(sdp, 20000),
    )?;
    world.trickle()?;
    world.run("connected", |peers| {
        peers.iter().all(|p| p.connected() && p.channel.is_some())
    })?;
    assert_eq!(max_message_size(&world, 0), Some(20000));

    // Peer 0 offers again; the answer states another limit, for the same association.
    world.exchange_with(
        0,
        |sdp| sdp.to_owned(),
        |sdp| with_max_message_size(sdp, 30000),
    )?;
    assert_eq!(max_message_size(&world, 0), Some(30000));
    let channel = world.peers[0].channel.expect("an open channel");
    let now = world.now;
    assert!(
        world.peers[0]
            .pc
            .data_channel(channel)
            .expect("the channel")
            .send(now, BytesMut::from(&vec![7u8; 30001][..]))
            .is_err(),
        "a message over the new limit is refused"
    );
    world.ping_pong("after the renegotiation")?;

    // Higher than the association started with: it lets the larger message through.
    world.exchange_with(
        0,
        |sdp| sdp.to_owned(),
        |sdp| with_max_message_size(sdp, 50000),
    )?;
    assert_eq!(max_message_size(&world, 0), Some(50000));
    let before = world.peers[1].received.len();
    let now = world.now;
    world.peers[0]
        .pc
        .data_channel(channel)
        .expect("the channel")
        .send(now, BytesMut::from(&vec![8u8; 40000][..]))?;
    world.run("the larger message", |peers| {
        peers[1].received.len() > before
    })?;
    assert_eq!(world.peers[1].received.last().map(Vec::len), Some(40000));
    Ok(())
}

#[test]
fn a_provisional_answer_updates_the_max_message_size() -> Result<()> {
    let mut world = world()?;
    world.connect()?;
    let now = world.now;
    let offer = world.peers[0].pc.create_offer(None)?;
    world.peers[0]
        .pc
        .set_local_description(now, offer.clone())?;
    world.peers[1]
        .pc
        .set_remote_description(now, RTCSessionDescription::offer(offer.sdp)?)?;
    let answer = world.peers[1].pc.create_answer(None)?;
    let pranswer = RTCSessionDescription::pranswer(with_max_message_size(&answer.sdp, 20000))?;
    world.peers[0].pc.set_remote_description(now, pranswer)?;
    assert_eq!(max_message_size(&world, 0), Some(20000));
    world.peers[1]
        .pc
        .set_local_description(now, answer.clone())?;
    world.peers[0].pc.set_remote_description(
        now,
        RTCSessionDescription::answer(with_max_message_size(&answer.sdp, 30000))?,
    )?;
    assert_eq!(max_message_size(&world, 0), Some(30000));
    Ok(())
}
