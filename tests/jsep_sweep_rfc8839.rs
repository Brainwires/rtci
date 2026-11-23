//! RFC 8839 rows of the sweep (jsep13): what the ICE SDP attributes do and do not mean between
//! two connected `rtc` peers in virtual time.

mod dtls_sdp_common;

use anyhow::Result;
use dtls_sdp_common::{Peer, World, attribute_values, keep, replace_lines, with_session_line};
use rtc::peer_connection::configuration::setting_engine::SettingEngineBuilder;
use rtc::peer_connection::transport::RTCIceCandidateInit;

fn world() -> Result<World> {
    Ok(World::new(
        Peer::new("10.0.0.1:5000", SettingEngineBuilder::new().build())?,
        Peer::new("10.0.0.2:5000", SettingEngineBuilder::new().build())?,
    ))
}

/// Section 4.2.5: "the default destination ... can be an FQDN ... an agent MUST NOT treat
/// [it] as an ICE failure". An answer whose `c=` lines name a host by its domain name is
/// applied and the session connects over the candidates.
#[test]
fn a_default_destination_named_by_a_domain_is_not_an_ice_failure() -> Result<()> {
    let mut world = world()?;
    world.peers[0].pc.create_data_channel("data", None)?;
    world.exchange_with(0, keep, |answer| {
        replace_lines(answer, "c=IN IP4 ", Some("c=IN IP4 media.example.com"))
    })?;
    world.trickle()?;
    world.run("connected with an FQDN default destination", |peers| {
        peers.iter().all(|p| p.connected() && p.channel.is_some())
    })?;
    assert!(world.peers.iter().all(|p| !p.failed()));
    world.ping_pong("FQDN c=")?;
    Ok(())
}

/// Section 4.4.1.1.1: "ICE credentials ... moved from the session level to the media level
/// (or vice versa) ... MUST NOT [be treated] as an ICE restart". After the first exchange
/// the offerer sends a later offer with the same credentials at session level instead of in
/// each section: the answerer answers with its own unchanged credentials (an ICE restart
/// would give it new ones, section 4.4.2.1), the session stays connected and carries data.
#[test]
fn credentials_moved_to_the_session_level_are_not_a_restart() -> Result<()> {
    let mut world = world()?;
    let (_, first_answer) = world.connect()?;
    let move_up = |offer: &str| {
        let ufrag = attribute_values(offer, "ice-ufrag").remove(0);
        let pwd = attribute_values(offer, "ice-pwd").remove(0);
        let without = replace_lines(
            &replace_lines(offer, "a=ice-ufrag:", None),
            "a=ice-pwd:",
            None,
        );
        with_session_line(
            &with_session_line(&without, &format!("a=ice-pwd:{pwd}")),
            &format!("a=ice-ufrag:{ufrag}"),
        )
    };
    let (_, answer) = world.exchange_with(0, move_up, keep)?;
    assert_eq!(
        attribute_values(&answer, "ice-ufrag"),
        attribute_values(&first_answer, "ice-ufrag"),
        "the answerer took the offer for an ICE restart:\n{answer}"
    );
    world.run_for(std::time::Duration::from_secs(2), |_| false);
    assert!(
        world.peers.iter().all(|p| p.connected()),
        "{:?}",
        world.peers[0].states
    );
    world.ping_pong("credentials at session level")?;
    Ok(())
}

/// Section 4.4.1.1.1: an agent "MUST NOT" put a stream on hold with `c=0.0.0.0`; hold is the
/// direction attribute. A transceiver made `sendonly` (hold) is offered `a=sendonly`, with
/// the same `c=` lines an offer had just before, while it was `sendrecv`.
#[test]
fn hold_is_a_direction_not_a_connection_address() -> Result<()> {
    use rtc::rtp_transceiver::RTCRtpTransceiverDirection;
    use rtc::rtp_transceiver::rtp_sender::RtpCodecKind;
    let mut world = world()?;
    let transceiver = world.peers[0]
        .pc
        .add_transceiver_from_kind(RtpCodecKind::Audio, None)?;
    world.connect()?;
    // A later offer before the hold: its `c=` lines (the default candidate once gathered).
    let offer = world.peers[0].pc.create_offer(None)?.sdp;
    let connection = |sdp: &str| -> Vec<String> {
        sdp.lines()
            .filter(|l| l.starts_with("c="))
            .map(str::to_owned)
            .collect()
    };
    world.peers[0]
        .pc
        .rtp_transceiver(transceiver)
        .expect("the transceiver")
        .set_direction(RTCRtpTransceiverDirection::Sendonly)?;
    let (held, _) = world.exchange(0)?;
    let audio = held
        .split("\r\nm=")
        .find(|s| s.starts_with("audio "))
        .expect("the audio section");
    assert!(audio.contains("\r\na=sendonly\r\n"), "{held}");
    assert_eq!(connection(&held), connection(&offer), "{held}");
    Ok(())
}

/// Section 5.1: "An agent generating local candidates MUST NOT use FQDN addresses." A host
/// candidate the application hands over with a domain name instead of an address is refused
/// and does not appear in the description.
#[test]
fn a_local_candidate_with_a_domain_name_is_not_used() -> Result<()> {
    let mut world = world()?;
    world.peers[0].pc.create_data_channel("data", None)?;
    let offer = world.peers[0].pc.create_offer(None)?;
    let now = world.now;
    world.peers[0].pc.set_local_description(now, offer)?;
    let refused = world.peers[0].pc.add_local_candidate(RTCIceCandidateInit {
        candidate: "candidate:1 1 udp 2130706431 host.example.com 5000 typ host".to_owned(),
        ..Default::default()
    });
    assert!(refused.is_err(), "{refused:?}");
    let local = world.peers[0]
        .pc
        .pending_local_description()
        .expect("the offer")
        .sdp
        .clone();
    assert!(!local.contains("host.example.com"), "{local}");
    Ok(())
}
