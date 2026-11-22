//! The SDP `tls-id` attribute (RFC 8842 section 4): "The pair of SDP 'tls-id' attribute values
//! (the attribute values of the offerer and the answerer) uniquely identifies the DTLS
//! association".
//!
//! - an offer carries one, a value of 20 to 255 characters with at least 120 random bits
//!   (sections 4 and 5.2), on the BUNDLE-tag m-section only (section 4);
//! - an answer carries one when, and only when, the offer did (section 5.3);
//! - while the association is kept, later offers and answers repeat the values (sections 5.3
//!   and 5.5); a new association gets new ones;
//! - a malformed value is a malformed description.
//!
//! What a *changed* remote value does is in `dtls_association_new.rs`.

mod dtls_sdp_common;

use anyhow::Result;
use dtls_sdp_common::{Peer, World, attribute_values, keep, replace_lines};
use rtc::peer_connection::configuration::setting_engine::SettingEngineBuilder;
use rtc::peer_connection::sdp::RTCSessionDescription;
use rtc::peer_connection::transport::RTCDtlsTransportState;
use rtc::rtp_transceiver::rtp_sender::RtpCodecKind;
use std::collections::HashSet;
use std::time::Instant;

fn peer(addr: &str) -> Result<Peer> {
    Peer::new(addr, SettingEngineBuilder::new().build())
}

fn world() -> Result<World> {
    Ok(World::new(peer("10.0.0.1:5000")?, peer("10.0.0.2:5000")?))
}

/// The one `tls-id` of a description.
fn tls_id(sdp: &str) -> String {
    let mut values = attribute_values(sdp, "tls-id");
    assert_eq!(values.len(), 1, "one a=tls-id in\n{sdp}");
    values.remove(0)
}

/// RFC 8842 section 4: `tls-id-value = 20*255(tls-id-char)`,
/// `tls-id-char = ALPHA / DIGIT / "+" / "/" / "-" / "_"`.
fn assert_syntax(value: &str) {
    assert!((20..=255).contains(&value.len()), "{value}");
    assert!(
        value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"+/-_".contains(&b)),
        "{value}"
    );
}

/// Sections 4 and 5.2: the initial offer has a `tls-id` of the attribute's syntax; "at least
/// 120 bits of randomness" from a strong random function: here 32 hex digits (128 bits), and
/// no two of a few hundred connections share a value or a prefix of 8 digits.
#[test]
fn the_initial_offer_carries_a_random_tls_id() -> Result<()> {
    let mut values = HashSet::new();
    let mut prefixes = HashSet::new();
    for _ in 0..300 {
        let mut offerer = peer("10.0.0.1:5000")?;
        offerer.pc.create_data_channel("data", None)?;
        let value = tls_id(&offerer.pc.create_offer(None)?.sdp);
        assert_syntax(&value);
        assert_eq!(value.len(), 32, "{value}");
        assert!(value.bytes().all(|b| b.is_ascii_hexdigit()), "{value}");
        prefixes.insert(value[..8].to_owned());
        values.insert(value);
    }
    assert_eq!(values.len(), 300);
    assert_eq!(
        prefixes.len(),
        300,
        "32 random bits collided among 300 values"
    );
    Ok(())
}

/// Section 4: the attribute's multiplexing category is IDENTICAL, so with BUNDLE it is "only
/// associated with the 'm=' line representing the offerer/answerer BUNDLE tag": the first
/// m-section, in the offer and in the answer; and it is a media-level attribute, never a
/// session-level or an `a=ssrc` one.
#[test]
fn the_tls_id_sits_on_the_bundle_tag_section_only() -> Result<()> {
    let mut world = world()?;
    world.peers[0]
        .pc
        .add_transceiver_from_kind(RtpCodecKind::Audio, None)?;
    world.peers[0]
        .pc
        .add_transceiver_from_kind(RtpCodecKind::Video, None)?;
    world.peers[0].pc.create_data_channel("data", None)?;
    let (offer, answer) = world.exchange(0)?;
    for sdp in [offer, answer] {
        assert_eq!(
            sdp.matches("\r\nm=").count(),
            3,
            "three m-sections in\n{sdp}"
        );
        assert_eq!(sdp.matches("tls-id").count(), 1, "{sdp}");
        let sections: Vec<&str> = sdp.split("\r\nm=").collect();
        assert!(!sections[0].contains("a=tls-id:"), "session level:\n{sdp}");
        assert!(
            sections[1].contains("\r\na=tls-id:"),
            "first section:\n{sdp}"
        );
        let bundle = attribute_values(&sdp, "group").remove(0);
        let tag = bundle.split(' ').nth(1).expect("a BUNDLE tag");
        assert!(
            sections[1].contains(&format!("\r\na=mid:{tag}\r\n")),
            "the first section is the BUNDLE tag {tag}:\n{sdp}"
        );
    }
    Ok(())
}

/// Section 5.3: "If the answerer receives an offer that does not contain an SDP 'tls-id'
/// attribute, the answerer MUST NOT insert a 'tls-id' attribute in the answer"; when the offer
/// has one, the answer has its own (section 4: an implementation that uses the attribute
/// includes it in offers and answers).
#[test]
fn the_answer_carries_a_tls_id_only_when_the_offer_does() -> Result<()> {
    let mut world = world()?;
    world.peers[0].pc.create_data_channel("data", None)?;
    let (offer, answer) = world.exchange(0)?;
    assert_syntax(&tls_id(&answer));
    assert_ne!(tls_id(&answer), tls_id(&offer), "each endpoint has its own");

    let mut world = self::world()?;
    world.peers[0].pc.create_data_channel("data", None)?;
    let (_, answer) = world.exchange_with(0, |sdp| replace_lines(sdp, "a=tls-id:", None), keep)?;
    assert!(attribute_values(&answer, "tls-id").is_empty(), "{answer}");
    // A later offer from the peer that was sent none still carries its own.
    world.trickle()?;
    world.run("connected", |peers| peers.iter().all(|p| p.connected()))?;
    let (offer, _) = world.exchange(1)?;
    assert_syntax(&tls_id(&offer));
    Ok(())
}

/// Sections 5.3 and 5.5: an offer or answer that keeps the association carries "the previously
/// assigned attribute value". Renegotiation in both directions and an ICE restart (which by
/// itself keeps the association, section 6) repeat each endpoint's value.
#[test]
fn the_tls_id_is_kept_while_the_association_is() -> Result<()> {
    let mut world = world()?;
    let (offer, answer) = world.connect()?;
    let ids = [tls_id(&offer), tls_id(&answer)];

    let (offer, answer) = world.exchange(0)?;
    assert_eq!([tls_id(&offer), tls_id(&answer)], ids, "a second offer");
    let (offer, answer) = world.exchange(1)?;
    assert_eq!(
        [tls_id(&answer), tls_id(&offer)],
        ids,
        "an offer from the first answerer"
    );
    world.peers[1].pc.restart_ice();
    let (offer, answer) = world.exchange(1)?;
    assert_eq!([tls_id(&answer), tls_id(&offer)], ids, "an ICE restart");
    world.trickle()?;
    world.run("the restart", |peers| peers.iter().all(|p| p.connected()))?;
    world.ping_pong("after the restart")?;
    Ok(())
}

/// Sections 3.2, 5.3 and 5.5: when the transport is closed (every m-section rejected) and a
/// later offer sets one up again, that offer asks for a new association: it carries a new
/// `tls-id`, the same one if the offer is created twice, and the answer carries a new one too.
/// The new association is established.
#[test]
fn a_new_association_gets_new_tls_ids() -> Result<()> {
    let mut world = world()?;
    let audio = world.peers[0]
        .pc
        .add_transceiver_from_kind(RtpCodecKind::Audio, None)?;
    let (offer, answer) = world.exchange(0)?;
    let ids = [tls_id(&offer), tls_id(&answer)];
    world.trickle()?;
    world.run("the first association", |peers| {
        peers.iter().all(|p| p.connected())
    })?;

    // Every m-section rejected: the transport is closed. A closed transport has no tls-id.
    world.peers[0]
        .pc
        .rtp_transceiver(audio)
        .expect("the audio transceiver")
        .stop()?;
    let (offer, answer) = world.exchange(0)?;
    assert!(offer.contains("m=audio 0 "), "{offer}");
    assert!(answer.contains("m=audio 0 "), "{answer}");
    assert!(attribute_values(&offer, "tls-id").is_empty(), "{offer}");
    assert!(attribute_values(&answer, "tls-id").is_empty(), "{answer}");

    world.peers[0]
        .pc
        .add_transceiver_from_kind(RtpCodecKind::Video, None)?;
    let first_try = tls_id(&world.peers[0].pc.create_offer(None)?.sdp);
    assert_ne!(first_try, ids[0], "the offer asks for a new association");
    let (offer, answer) = world.exchange(0)?;
    assert_eq!(
        tls_id(&offer),
        first_try,
        "the same request, created again, has the same tls-id"
    );
    assert_syntax(&tls_id(&offer));
    assert_eq!(
        attribute_values(&offer, "setup"),
        ["actpass"],
        "an offer that asks for a new association"
    );
    assert_ne!(tls_id(&answer), ids[1], "the answerer's new association");
    assert_syntax(&tls_id(&answer));
    let new_ids = [tls_id(&offer), tls_id(&answer)];

    // Applying the exchange reset both DTLS transports; a new handshake completes.
    let now = world.now;
    let written = [world.peers[0].written.len(), world.peers[1].written.len()];
    for i in 0..2 {
        assert_eq!(
            world.peers[i].dtls_state(now),
            RTCDtlsTransportState::Connecting,
            "peer {i}"
        );
    }
    world.trickle()?;
    world.run("the new association", |peers| {
        peers
            .iter_mut()
            .all(|p| p.dtls_state(now) == RTCDtlsTransportState::Connected)
    })?;
    for (i, peer) in world.peers.iter().enumerate() {
        // DTLS handshake records have content type 22.
        assert!(
            peer.written[written[i]..]
                .iter()
                .any(|datagram| datagram.first() == Some(&22)),
            "peer {i} took part in a new handshake"
        );
    }
    // And the new values are the association's from then on.
    let (offer, answer) = world.exchange(1)?;
    assert_eq!([tls_id(&answer), tls_id(&offer)], new_ids);
    Ok(())
}

/// A `tls-id` outside the attribute's syntax, or two sections of the one transport with
/// different values, make the description malformed: it is refused and not kept.
#[test]
fn a_malformed_tls_id_is_refused() -> Result<()> {
    let mut offerer = peer("10.0.0.1:5000")?;
    offerer
        .pc
        .add_transceiver_from_kind(RtpCodecKind::Audio, None)?;
    offerer.pc.create_data_channel("data", None)?;
    let offer = offerer.pc.create_offer(None)?.sdp;
    let apply = |sdp: String| -> Result<bool> {
        let mut answerer = peer("10.0.0.2:5000")?;
        let applied = answerer
            .pc
            .set_remote_description(Instant::now(), RTCSessionDescription::offer(sdp)?);
        if applied.is_err() {
            assert!(answerer.pc.remote_description().is_none());
        }
        Ok(applied.is_ok())
    };
    assert!(apply(offer.clone())?);

    let too_long = "a".repeat(256);
    for malformed in [
        "abc3de65cddef001be8",
        too_long.as_str(),
        "abc3de65cddef001be82!",
        "abc3de65 cddef001be82",
        "abc3de65cddef001be82=",
    ] {
        let sdp = replace_lines(&offer, "a=tls-id:", Some(&format!("a=tls-id:{malformed}")));
        assert!(!apply(sdp)?, "a=tls-id:{malformed} was accepted");
    }
    let valueless = replace_lines(&offer, "a=tls-id:", Some("a=tls-id"));
    assert!(!apply(valueless)?, "a=tls-id without a value was accepted");

    // The longest and the shortest values, and every character of the alphabet.
    for valid in [
        "abc3de65cddef001be82".to_owned(),
        "a".repeat(255),
        "ABCxyz0123456789+/-_ABCxyz".to_owned(),
    ] {
        let sdp = replace_lines(&offer, "a=tls-id:", Some(&format!("a=tls-id:{valid}")));
        assert!(apply(sdp)?, "a=tls-id:{valid} was refused");
    }

    // IDENTICAL: a second section that repeats the attribute repeats the value.
    let own = tls_id(&offer);
    assert!(offer.ends_with("\r\n"));
    let both = format!("{offer}a=tls-id:{own}\r\n");
    assert!(apply(both)?, "the same tls-id on both sections was refused");
    let conflicting = format!("{offer}a=tls-id:abc3de65cddef001be82\r\n");
    assert!(
        !apply(conflicting)?,
        "two sections with different tls-ids were accepted"
    );
    Ok(())
}

/// `SettingEngineBuilder::with_disable_sdp_tls_id`: nothing is written, in offers or answers.
#[test]
fn tls_id_can_be_left_out() -> Result<()> {
    let quiet = |addr: &str| {
        Peer::new(
            addr,
            SettingEngineBuilder::new()
                .with_disable_sdp_tls_id(true)
                .build(),
        )
    };
    let mut world = World::new(quiet("10.0.0.1:5000")?, peer("10.0.0.2:5000")?);
    let (offer, answer) = world.connect()?;
    assert!(!offer.contains("tls-id"), "{offer}");
    assert!(!answer.contains("tls-id"), "{answer}");
    // The other peer does write one in its offers; the quiet one's answer has none.
    let (offer, answer) = world.exchange(1)?;
    assert_eq!(attribute_values(&offer, "tls-id").len(), 1);
    assert!(!answer.contains("tls-id"), "{answer}");
    world.ping_pong("without tls-id")?;
    Ok(())
}
