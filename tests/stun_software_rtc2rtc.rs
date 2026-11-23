//! The SOFTWARE attribute of the STUN messages of a call (RFC 8489 section 14.14), between two
//! `rtc` peers on an in-memory network and a virtual clock: `rtc-ice` and its version by
//! default (sections 6.1 and 6.3.1.1: requests and success responses "SHOULD" carry one),
//! the text `SettingEngineBuilder::with_ice_software` names, or none at all with
//! `with_ice_software(None)` (section 16.1.2: "Implementers SHOULD make usage of the SOFTWARE
//! attribute a configurable option"), for an application that must not put an implementation fingerprint on the wire.

use anyhow::Result;
use rtc::ice::agent::DEFAULT_SOFTWARE;
use rtc::peer_connection::RTCPeerConnectionBuilder;
use rtc::peer_connection::configuration::setting_engine::SettingEngineBuilder;
use rtc::stun::attributes::ATTR_SOFTWARE;
use rtc::stun::message::{CLASS_REQUEST, CLASS_SUCCESS_RESPONSE, Message, MessageClass};
use rtc::stun::textattrs::Software;
use std::time::{Duration, Instant};

mod dtls_sdp_common;
use dtls_sdp_common::{Peer, World};

/// Each STUN message among `datagrams` (RFC 7983: first byte 0 to 3, the magic cookie), as
/// its class and SOFTWARE.
fn stun_software(datagrams: &[Vec<u8>]) -> Vec<(MessageClass, Option<String>)> {
    datagrams
        .iter()
        .filter(|d| d.len() >= 20 && d[0] < 4 && d[4..8] == [0x21, 0x12, 0xa4, 0x42])
        .filter_map(|d| {
            let mut m = Message::new();
            m.unmarshal_binary(d).ok()?;
            let software = Software::get_from_as(&m, ATTR_SOFTWARE)
                .ok()
                .map(|software| software.text);
            Some((m.typ.class, software))
        })
        .collect()
}

/// A call with a data channel, a message each way, then long enough for consent checks
/// (RFC 7675 section 5.1: every 5 s on average); peer 0 has `software` set.
fn call(software: Option<Option<String>>) -> Result<World> {
    let mut settings = SettingEngineBuilder::new();
    if let Some(software) = software {
        settings = settings.with_ice_software(software);
    }
    let mut world = World::new(
        Peer::new("10.0.0.1:5000", settings.build())?,
        Peer::new("10.0.0.2:5000", SettingEngineBuilder::new().build())?,
    );
    world.connect()?;
    world.ping_pong("connected")?;
    let _ = world.run_for(Duration::from_secs(12), |_| false);
    world.ping_pong("after the consent checks")?;
    Ok(world)
}

/// Every STUN request and success response of peer `i` carries `expected` as its SOFTWARE
/// (`None`: no SOFTWARE attribute); there are requests (checks, nomination, consent) and
/// success responses (to the other peer's) among them.
fn assert_software(world: &World, i: usize, expected: Option<&str>) {
    let messages = stun_software(&world.peers[i].written);
    let requests = messages.iter().filter(|(c, _)| *c == CLASS_REQUEST).count();
    let responses = messages
        .iter()
        .filter(|(c, _)| *c == CLASS_SUCCESS_RESPONSE)
        .count();
    assert!(requests >= 3, "peer {i}: {requests} requests");
    assert!(responses >= 3, "peer {i}: {responses} success responses");
    for (class, software) in &messages {
        if *class == CLASS_REQUEST || *class == CLASS_SUCCESS_RESPONSE {
            assert_eq!(software.as_deref(), expected, "peer {i}: a {class}");
        } else {
            assert_eq!(*software, None, "peer {i}: a {class}");
        }
    }
}

/// `with_ice_software(None)`: no STUN message the peer sends in either direction (its checks,
/// nomination and consent requests, its responses to the other peer's) carries SOFTWARE; the
/// other peer, with the default, sends `rtc-ice` and its version in all of its own.
#[test]
fn with_ice_software_none_no_stun_message_of_a_call_carries_software() -> Result<()> {
    let world = call(Some(None))?;
    assert_software(&world, 0, None);
    assert_software(&world, 1, Some(DEFAULT_SOFTWARE));
    Ok(())
}

/// Without the setting the peer's requests and success responses carry `rtc-ice` and its
/// version (RFC 8489 sections 6.1 and 6.3.1.1).
#[test]
fn by_default_the_stun_messages_of_a_call_carry_the_rtc_ice_software() -> Result<()> {
    let world = call(None)?;
    assert_software(&world, 0, Some(DEFAULT_SOFTWARE));
    Ok(())
}

/// `with_ice_software(Some(text))`: `text` in every request and success response.
#[test]
fn with_ice_software_some_the_stun_messages_of_a_call_carry_that_text() -> Result<()> {
    let world = call(Some(Some("app 1.0".to_owned())))?;
    assert_software(&world, 0, Some("app 1.0"));
    Ok(())
}

/// RFC 8489 section 14.14: SOFTWARE "MUST be a UTF-8-encoded [RFC3629] sequence of fewer
/// than 128 characters"; a longer text fails building the peer connection rather than every
/// check.
#[test]
fn an_ice_software_of_128_characters_fails_the_peer_connection() {
    for (software, ok) in [("a".repeat(127), true), ("a".repeat(128), false)] {
        let built = RTCPeerConnectionBuilder::new()
            .with_setting_engine(
                SettingEngineBuilder::new()
                    .with_ice_software(Some(software.clone()))
                    .build(),
            )
            .build(Instant::now());
        assert_eq!(built.is_ok(), ok, "{} characters", software.len());
    }
}
