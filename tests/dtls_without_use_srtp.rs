//! A DTLS association without `use_srtp` carries data channels (RFC 5764 section 4.1: the
//! extension is for associations that carry RTP or RTCP), and never media (RFC 8827 section
//! 6.5).
//!
//! A peer that negotiated no SRTP profile could not connect at all: as the DTLS client it sent
//! no `use_srtp` and this engine, the server, completed the handshake, failed to build SRTP
//! contexts and left the transport in `connecting`; as the DTLS server it left the extension
//! out and this engine, the client, aborted the handshake.
//!
//! The data-channel-only peer here is an `rtc` peer built with
//! `SettingEngineBuilder::with_disable_dtls_use_srtp`.

mod dtls_sdp_common;

use anyhow::Result;
use dtls_sdp_common::{Peer, World, keep};
use rtc::peer_connection::configuration::setting_engine::SettingEngineBuilder;
use rtc::peer_connection::sdp::RTCSessionDescription;
use rtc::peer_connection::transport::{RTCDtlsRole, RTCDtlsTransportState};
use rtc::rtp_transceiver::rtp_sender::RtpCodecKind;
use rtc::shared::error::Error;

fn peer(addr: &str, use_srtp: bool, answering_role: Option<RTCDtlsRole>) -> Result<Peer> {
    let mut setting_engine = SettingEngineBuilder::new().with_disable_dtls_use_srtp(!use_srtp);
    if let Some(role) = answering_role {
        setting_engine = setting_engine.with_answering_dtls_role(role);
    }
    Peer::new(addr, setting_engine.build())
}

/// A data-channel-only peer and a default peer connect, whichever of them is the DTLS client:
/// the data channel opens and carries messages, the DTLS transports are `connected`, and
/// neither reports an SRTP cipher.
#[test]
fn a_data_channel_session_works_without_use_srtp() -> Result<()> {
    for data_only in [0, 1] {
        for answering_role in [None, Some(RTCDtlsRole::Server)] {
            let what = format!(
                "peer {data_only} without use_srtp, the answerer answers as {answering_role:?}"
            );
            let mut world = World::new(
                peer("10.0.0.1:5000", data_only != 0, None)?,
                peer("10.0.0.2:5000", data_only != 1, answering_role)?,
            );
            world.connect()?;
            world.ping_pong(&what)?;
            let now = world.now;
            let answerer_role = world.peers[1].dtls_role(now);
            assert_eq!(
                answerer_role,
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
    }
    Ok(())
}

/// Two default peers negotiate `use_srtp` on a data-channel-only session too, as browsers do
/// (media may be added later without a new association).
#[test]
fn default_peers_negotiate_use_srtp_on_every_association() -> Result<()> {
    let mut world = World::new(
        peer("10.0.0.1:5000", true, None)?,
        peer("10.0.0.2:5000", true, None)?,
    );
    world.connect()?;
    let now = world.now;
    for i in 0..2 {
        assert_eq!(
            world.peers[i].srtp_cipher(now),
            "SRTP_AEAD_AES_128_GCM",
            "peer {i}"
        );
    }
    Ok(())
}

/// Media needs SRTP keys. A data-channel-only peer refuses a description with a media section,
/// and a default peer refuses one on an association that negotiated no `use_srtp`; in both
/// cases nothing of the description is applied and the data channel session goes on.
#[test]
fn media_sections_are_refused_without_use_srtp() -> Result<()> {
    // An offer with audio, to a data-channel-only peer.
    let mut offerer = peer("10.0.0.1:5000", true, None)?;
    offerer
        .pc
        .add_transceiver_from_kind(RtpCodecKind::Audio, None)?;
    offerer.pc.create_data_channel("data", None)?;
    let offer = offerer.pc.create_offer(None)?;
    let mut data_only = peer("10.0.0.2:5000", false, None)?;
    assert_eq!(
        data_only
            .pc
            .set_remote_description(std::time::Instant::now(), offer),
        Err(Error::ErrSessionDescriptionMediaWithoutSrtp)
    );
    assert!(data_only.pc.remote_description().is_none());

    // A connected data channel session without `use_srtp`; then each side offers audio.
    let mut world = World::new(
        peer("10.0.0.1:5000", true, None)?,
        peer("10.0.0.2:5000", false, None)?,
    );
    world.connect()?;
    for offering in [0, 1] {
        world.peers[offering]
            .pc
            .add_transceiver_from_kind(RtpCodecKind::Audio, None)?;
        let now = world.now;
        let offer = world.peers[offering].pc.create_offer(None)?;
        assert!(offer.sdp.contains("m=audio 9 "), "{}", offer.sdp);
        assert_eq!(
            world.peers[1 - offering]
                .pc
                .set_remote_description(now, RTCSessionDescription::offer(keep(&offer.sdp))?),
            Err(Error::ErrSessionDescriptionMediaWithoutSrtp),
            "peer {offering} offers audio"
        );
    }
    world.ping_pong("after the refused offers")?;
    Ok(())
}
