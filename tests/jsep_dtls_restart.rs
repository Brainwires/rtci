//! A later description that asks for a new DTLS association is part of an ICE restart, by
//! default:
//!
//! - RFC 9429 section 5.8.3: "If this is a re-offer or a response to a re-offer and the
//!   tls-id value is different from that presently in use, the DTLS connection is not being
//!   continued and the remote description MUST be part of an ICE restart, together with new
//!   ufrag and password values."
//! - Section 5.11: "If the remote DTLS fingerprint has been changed or the value of the
//!   'a=tls-id' attribute has changed, tear down the DTLS connection. ... If a DTLS connection
//!   needs to be torn down but the answer does not indicate an ICE restart ..., an error MUST
//!   be generated."
//!
//! RFC 8842 section 6 asks the same over ICE: "at least one of the endpoints MUST allocate a
//! completely new set of ICE candidates". Such a description is refused and changes nothing;
//! with an ICE restart it applies. `with_dtls_new_association_without_ice_restart(true)` takes
//! it on the ICE session it has (RFC 8842 section 3.1 alone, `dtls_association_new.rs`).

mod dtls_sdp_common;

use anyhow::Result;
use dtls_sdp_common::{Peer, World, replace_lines};
use rtc::peer_connection::configuration::setting_engine::SettingEngineBuilder;
use rtc::peer_connection::sdp::RTCSessionDescription;

/// A (peer 0) and B (peer 1) connected, A having offered; B allows a new association without
/// an ICE restart when `b_allows` is set.
fn connected(b_allows: bool) -> Result<World> {
    let mut world = World::new(
        Peer::new("10.0.0.1:5000", SettingEngineBuilder::new().build())?,
        Peer::new(
            "10.0.0.2:5000",
            SettingEngineBuilder::new()
                .with_dtls_new_association_without_ice_restart(b_allows)
                .build(),
        )?,
    );
    world.connect()?;
    Ok(world)
}

fn new_tls_id(sdp: &str) -> String {
    replace_lines(
        sdp,
        "a=tls-id:",
        Some("a=tls-id:AnotherDtlsAssociation0123456789"),
    )
}

fn new_fingerprint(sdp: &str) -> String {
    replace_lines(
        sdp,
        "a=fingerprint:",
        Some(
            "a=fingerprint:sha-256 \
             00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:\
             00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF",
        ),
    )
}

/// New ICE credentials: the description is part of an ICE restart.
fn ice_restart(sdp: &str) -> String {
    replace_lines(
        &replace_lines(sdp, "a=ice-ufrag:", Some("a=ice-ufrag:RestartUfrag")),
        "a=ice-pwd:",
        Some("a=ice-pwd:RestartPasswordRestartPass"),
    )
}

/// A re-offer whose `tls-id` changed and whose ICE credentials did not is refused, and the
/// remote description stays the one before; with new credentials it applies, and so it does
/// without them under the setting.
#[test]
fn a_re_offer_with_a_new_tls_id_needs_an_ice_restart() -> Result<()> {
    let mut world = connected(false)?;
    let before = world.peers[1]
        .pc
        .remote_description()
        .map(|d| d.sdp.clone());
    let now = world.now;
    let offer = world.peers[0].pc.create_offer(None)?;
    world.peers[0]
        .pc
        .set_local_description(now, offer.clone())?;

    let refused = world.peers[1]
        .pc
        .set_remote_description(now, RTCSessionDescription::offer(new_tls_id(&offer.sdp))?);
    assert!(
        refused.is_err(),
        "a new tls-id without an ICE restart was accepted"
    );
    assert_eq!(
        world.peers[1]
            .pc
            .remote_description()
            .map(|d| d.sdp.clone()),
        before,
        "the refused offer changed the remote description"
    );
    world.peers[1].pc.set_remote_description(
        now,
        RTCSessionDescription::offer(ice_restart(&new_tls_id(&offer.sdp)))?,
    )?;

    let mut world = connected(true)?;
    let now = world.now;
    let offer = world.peers[0].pc.create_offer(None)?;
    world.peers[0]
        .pc
        .set_local_description(now, offer.clone())?;
    world.peers[1]
        .pc
        .set_remote_description(now, RTCSessionDescription::offer(new_tls_id(&offer.sdp))?)?;
    Ok(())
}

/// An answer to a re-offer that changes the fingerprint or the `tls-id` without an ICE
/// restart is an error; the offerer stays in `have-local-offer` and takes the real answer.
#[test]
fn an_answer_with_a_new_fingerprint_or_tls_id_needs_an_ice_restart() -> Result<()> {
    let mut world = connected(false)?;
    let now = world.now;
    // B offers this time, so that A, the side under test, takes the answer.
    let offer = world.peers[1].pc.create_offer(None)?;
    world.peers[1]
        .pc
        .set_local_description(now, offer.clone())?;
    world.peers[0].pc.set_remote_description(now, offer)?;
    let answer = world.peers[0].pc.create_answer(None)?;
    world.peers[0]
        .pc
        .set_local_description(now, answer.clone())?;

    // B with the default setting: the changed answers are refused.
    for (what, munged) in [
        ("fingerprint", new_fingerprint(&answer.sdp)),
        ("tls-id", new_tls_id(&answer.sdp)),
    ] {
        assert_ne!(munged, answer.sdp, "{what}: nothing was changed");
        let refused = world.peers[1]
            .pc
            .set_remote_description(now, RTCSessionDescription::answer(munged)?);
        assert!(
            refused.is_err(),
            "an answer with a new {what} and no ICE restart was accepted"
        );
    }
    world.peers[1].pc.set_remote_description(now, answer)?;
    world.ping_pong("after the refused answers")?;
    Ok(())
}
