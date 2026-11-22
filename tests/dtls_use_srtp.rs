//! The DTLS `use_srtp` extension is used on an association that carries SRTP media, and only
//! there (RFC 5764 section 4.1: "The use_srtp extension MUST only be used when the data being
//! transported is RTP or RTCP"); media never flows without it (RFC 8827 section 6.5).
//!
//! - A data-channel-only session is set up without `use_srtp`, and works. (A peer that
//!   negotiated no SRTP profile could not connect at all before: the server side stayed in
//!   `connecting`, the client side aborted the handshake.)
//! - A session with a media section negotiates it.
//! - When a data-channel-only session gains a media section, a new association with
//!   `use_srtp` replaces the one that has no SRTP keys; the offer says so with a new `tls-id`
//!   (RFC 8842 section 5.5).
//! - `SettingEngineBuilder::with_dtls_use_srtp_on_every_association` is the browsers' way:
//!   offered on every association, so adding media needs no new one.

mod dtls_sdp_common;

use anyhow::Result;
use dtls_sdp_common::{Peer, World, attribute_values};
use rtc::peer_connection::configuration::setting_engine::SettingEngineBuilder;
use rtc::peer_connection::transport::{RTCDtlsRole, RTCDtlsTransportState};
use rtc::rtp_transceiver::rtp_sender::RtpCodecKind;

const GCM: &str = "SRTP_AEAD_AES_128_GCM";

fn peer(addr: &str, always: bool, answering_role: Option<RTCDtlsRole>) -> Result<Peer> {
    let mut setting_engine =
        SettingEngineBuilder::new().with_dtls_use_srtp_on_every_association(always);
    if let Some(role) = answering_role {
        setting_engine = setting_engine.with_answering_dtls_role(role);
    }
    Peer::new(addr, setting_engine.build())
}

fn world(always: [bool; 2], answering_role: Option<RTCDtlsRole>) -> Result<World> {
    Ok(World::new(
        peer("10.0.0.1:5000", always[0], None)?,
        peer("10.0.0.2:5000", always[1], answering_role)?,
    ))
}

/// By default a data-channel-only session negotiates no `use_srtp`, whichever peer is the DTLS
/// client: the channel opens and carries messages, the DTLS transports are `connected`, and
/// neither reports an SRTP cipher.
#[test]
fn a_data_channel_session_is_set_up_without_use_srtp() -> Result<()> {
    for answering_role in [None, Some(RTCDtlsRole::Server)] {
        let what = format!("the answerer answers as {answering_role:?}");
        let mut world = world([false, false], answering_role)?;
        world.connect()?;
        world.ping_pong(&what)?;
        let now = world.now;
        assert_eq!(
            world.peers[1].dtls_role(now),
            answering_role.unwrap_or(RTCDtlsRole::Client),
            "{what}"
        );
        for i in 0..2 {
            assert_eq!(
                world.peers[i].dtls_state(now),
                RTCDtlsTransportState::Connected,
                "{what}: peer {i}"
            );
            assert_eq!(world.peers[i].srtp_cipher(now), "", "{what}: peer {i}");
            assert!(!world.peers[i].failed(), "{what}: peer {i}");
        }
    }
    Ok(())
}

/// A session with a media section negotiates `use_srtp`, with the data channel next to it.
#[test]
fn a_media_session_negotiates_use_srtp() -> Result<()> {
    for answering_role in [None, Some(RTCDtlsRole::Server)] {
        let mut world = world([false, false], answering_role)?;
        world.peers[0]
            .pc
            .add_transceiver_from_kind(RtpCodecKind::Audio, None)?;
        world.connect()?;
        world.ping_pong("a media session")?;
        let now = world.now;
        for i in 0..2 {
            assert_eq!(world.peers[i].srtp_cipher(now), GCM, "peer {i}");
        }
    }
    Ok(())
}

/// `with_dtls_use_srtp_on_every_association`: the DTLS client offers `use_srtp` on a
/// data-channel-only session too, and the server, with or without the setting, takes a
/// profile. A client without the setting offers none, whatever the server's setting.
#[test]
fn use_srtp_on_every_association_is_an_option() -> Result<()> {
    for always in [[true, true], [true, false], [false, true]] {
        for answering_role in [None, Some(RTCDtlsRole::Server)] {
            let what = format!("always {always:?}, the answerer answers as {answering_role:?}");
            let mut world = world(always, answering_role)?;
            world.connect()?;
            world.ping_pong(&what)?;
            let now = world.now;
            // The answerer is the client unless it answers as the server.
            let client = if answering_role == Some(RTCDtlsRole::Server) {
                0
            } else {
                1
            };
            let expected = if always[client] { GCM } else { "" };
            for i in 0..2 {
                assert_eq!(
                    world.peers[i].srtp_cipher(now),
                    expected,
                    "{what}: peer {i}"
                );
            }
        }
    }
    Ok(())
}

/// A data-channel-only session, set up without `use_srtp`, gains an audio section: the offer
/// that adds it asks for a new association (a new `tls-id`), both peers establish one with
/// `use_srtp`, the DTLS roles stay as they were, and the data channel goes on over it.
#[test]
fn media_added_to_a_data_channel_session_gets_an_association_with_use_srtp() -> Result<()> {
    for answering_role in [None, Some(RTCDtlsRole::Server)] {
        for offering in [0, 1] {
            let what =
                format!("peer {offering} adds audio, the first answerer was {answering_role:?}");
            let mut world = world([false, false], answering_role)?;
            let (first_offer, first_answer) = world.connect()?;
            let now = world.now;
            let roles = [world.peers[0].dtls_role(now), world.peers[1].dtls_role(now)];
            let first_ids = [
                attribute_values(&first_offer, "tls-id"),
                attribute_values(&first_answer, "tls-id"),
            ];
            let written = [world.peers[0].written.len(), world.peers[1].written.len()];

            world.peers[offering]
                .pc
                .add_transceiver_from_kind(RtpCodecKind::Audio, None)?;
            let (offer, answer) = world.exchange(offering)?;
            assert!(offer.contains("m=audio 9 "), "{what}: {offer}");
            assert_ne!(
                attribute_values(&offer, "tls-id"),
                first_ids[offering],
                "{what}: the offer asks for a new association"
            );
            assert_ne!(
                attribute_values(&answer, "tls-id"),
                first_ids[1 - offering],
                "{what}: the answerer's new association"
            );
            world.run(&what, |peers| {
                peers.iter_mut().all(|p| {
                    p.dtls_state(now) == RTCDtlsTransportState::Connected
                        && p.srtp_cipher(now) == GCM
                })
            })?;
            let now = world.now;
            for (i, peer) in world.peers.iter_mut().enumerate() {
                assert_eq!(peer.dtls_role(now), roles[i], "{what}: peer {i}");
                assert!(!peer.failed(), "{what}: peer {i}");
                // DTLS handshake records have content type 22.
                assert!(
                    peer.written[written[i]..]
                        .iter()
                        .any(|datagram| datagram.first() == Some(&22)),
                    "{what}: peer {i} took part in a new handshake"
                );
            }
            world.ping_pong(&format!("{what}: the data channel after it"))?;
        }
    }
    Ok(())
}

/// With `use_srtp` on every association, adding media keeps the association: the same
/// `tls-id`, no new handshake.
#[test]
fn media_added_keeps_an_association_that_has_use_srtp() -> Result<()> {
    let mut world = world([true, true], None)?;
    let (first_offer, _) = world.connect()?;
    let written = world.peers[1].written.len();
    world.peers[0]
        .pc
        .add_transceiver_from_kind(RtpCodecKind::Audio, None)?;
    let (offer, _) = world.exchange(0)?;
    assert_eq!(
        attribute_values(&offer, "tls-id"),
        attribute_values(&first_offer, "tls-id")
    );
    world.ping_pong("after the audio section")?;
    assert!(
        !world.peers[1].written[written..]
            .iter()
            .any(|datagram| datagram.first() == Some(&22)),
        "a handshake record was sent"
    );
    let now = world.now;
    for i in 0..2 {
        assert_eq!(world.peers[i].srtp_cipher(now), GCM, "peer {i}");
    }
    Ok(())
}
