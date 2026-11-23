//! RFC 8842 section 5.2: "the offerer MUST be prepared to receive a DTLS ClientHello message
//! (if a new DTLS association is established by the answerer) before it receives the SDP
//! answer"; RFC 8122 section 6.2: an offerer with `actpass` or `passive` "MUST be prepared to
//! receive" the handshake as soon as it sends the offer.
//!
//! The ClientHello can overtake the answer when the answerer can select a pair on its own:
//! here the offerer is an ICE-lite agent, so the full answerer is controlling, nominates as
//! soon as the offerer has answered its checks (which it does before it has the answer, RFC
//! 8445 section 7.3), and starts the handshake as the DTLS client (`a=setup:active`). The offerer holds the
//! ClientHello and takes it once it has applied the answer: it answers it, as it answers the
//! client's retransmission.
//!
//! Two `rtc` peers on a simulated network; virtual time, no sockets.

mod dtls_sdp_common;

use anyhow::Result;
use dtls_sdp_common::{Peer, World};
use rtc::peer_connection::configuration::setting_engine::SettingEngineBuilder;
use rtc::peer_connection::sdp::RTCSessionDescription;
use rtc::peer_connection::transport::RTCDtlsRole;
use std::time::Duration;

/// Whether `datagram` is a DTLS record carrying the start of a ClientHello whose
/// `message_seq` is `message_seq` (RFC 6347 section 4.2.2, RFC 9147 section 5.2: the first
/// ClientHello is 0, the one after a HelloVerifyRequest or HelloRetryRequest 1).
fn client_hello(datagram: &[u8], message_seq: u16) -> bool {
    datagram.len() > 25
        && datagram[0] == 22
        && datagram[13] == 1
        && u16::from_be_bytes([datagram[17], datagram[18]]) == message_seq
}

#[test]
fn the_offerer_takes_a_client_hello_that_arrives_before_the_answer() -> Result<()> {
    let lite = SettingEngineBuilder::new().with_lite(true).build();
    let mut world = World::new(
        Peer::new("10.0.0.1:5000", lite)?,
        // The answerer takes the DTLS client role (`a=setup:active`): as the controlling
        // agent it would otherwise answer as the server.
        Peer::new(
            "10.0.0.2:5000",
            SettingEngineBuilder::new()
                .with_answering_dtls_role(RTCDtlsRole::Client)
                .build(),
        )?,
    );
    world.peers[0].pc.create_data_channel("data", None)?;
    let now = world.now;
    let offer = world.peers[0].pc.create_offer(None)?;
    world.peers[0]
        .pc
        .set_local_description(now, offer.clone())?;
    world.peers[1]
        .pc
        .set_remote_description(now, RTCSessionDescription::offer(offer.sdp)?)?;
    let answer = world.peers[1].pc.create_answer(None)?;
    world.peers[1]
        .pc
        .set_local_description(now, answer.clone())?;
    // The offerer's candidate reaches the answerer; the answer does not reach the offerer yet.
    let offerer_candidate = world.peers[0].candidate()?;
    world.peers[0]
        .pc
        .add_local_candidate(offerer_candidate.clone())?;
    world.peers[1].pc.add_remote_candidate(offerer_candidate)?;
    let answerer_candidate = world.peers[1].candidate()?;
    world.peers[1]
        .pc
        .add_local_candidate(answerer_candidate.clone())?;

    let sent_client_hello = world.run_for(Duration::from_secs(2), |peers| {
        peers[1].written.iter().any(|d| client_hello(d, 0))
    });
    assert!(sent_client_hello, "the answerer started the handshake");
    let before_answer = world.peers[1].written.len();

    // The answer arrives; the offerer takes the ClientHello it held.
    let now = world.now;
    world.peers[0]
        .pc
        .set_remote_description(now, RTCSessionDescription::answer(answer.sdp)?)?;
    world.peers[0].pc.add_remote_candidate(answerer_candidate)?;
    world.run("connected", |peers| {
        peers.iter().all(|p| p.connected() && p.channel.is_some())
    })?;
    world.ping_pong("after an early ClientHello")?;
    // Every first ClientHello the answerer sent, the one that overtook the answer included,
    // was answered by the offerer (a HelloVerifyRequest, HelloRetryRequest or ServerHello
    // with message_seq 0): the early one was held and taken, not dropped.
    let first_client_hellos = world.peers[1]
        .written
        .iter()
        .filter(|d| client_hello(d, 0))
        .count();
    let first_answers = world.peers[0]
        .written
        .iter()
        .filter(|d| {
            d.len() > 25
                && d[0] == 22
                && matches!(d[13], 2 | 3)
                && u16::from_be_bytes([d[17], d[18]]) == 0
        })
        .count();
    assert!(first_client_hellos >= 1);
    assert_eq!(
        first_answers, first_client_hellos,
        "each first ClientHello answered, the early one too ({before_answer} datagrams before the answer)"
    );
    Ok(())
}
