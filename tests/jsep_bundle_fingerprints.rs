//! Which `a=fingerprint` lines a bundled description's transport is verified with.
//!
//! `a=fingerprint` is of the TRANSPORT multiplexing category (RFC 8859 section 4.5 and
//! appendix A): "the attribute value MUST be taken from the m= line whose information is used
//! to set up the underlying transport", which with BUNDLE is the tagged section (RFC 9143
//! section 7.1.3). By default the tagged section's fingerprints are the group's and what the
//! other bundled sections carry is not used; `SettingEngineBuilder::with_bundled_fingerprints_agreeing(true)`
//! is a hardening that refuses a description whose bundled sections disagree.

mod dtls_sdp_common;

use std::time::Instant;

use anyhow::Result;
use dtls_sdp_common::{Peer, World, keep};
use rtc::peer_connection::certificate::{CertificateParams, RTCCertificate};
use rtc::peer_connection::configuration::RTCConfigurationBuilder;
use rtc::peer_connection::configuration::setting_engine::SettingEngineBuilder;
use rtc::peer_connection::sdp::RTCSessionDescription;
use rtc::rtp_transceiver::RTCRtpTransceiverInit;
use rtc::rtp_transceiver::rtp_sender::RtpCodecKind;
use rtc::shared::error::Error;

/// The text with the `a=fingerprint` lines of m= section `index` replaced by a well-formed
/// fingerprint of no certificate this test has.
fn other_fingerprint_in_section(sdp: &str, index: usize) -> String {
    let wrong = format!("a=fingerprint:sha-256 {}", ["01"; 32].join(":"));
    let mut section = None;
    let mut replaced = false;
    let lines: Vec<String> = sdp
        .split("\r\n")
        .map(|line| {
            if line.starts_with("m=") {
                section = Some(section.map_or(0, |s: usize| s + 1));
            }
            if section == Some(index) && line.starts_with("a=fingerprint:") {
                replaced = true;
                return wrong.clone();
            }
            line.to_owned()
        })
        .collect();
    assert!(replaced, "section {index} has a fingerprint: {sdp}");
    lines.join("\r\n")
}

fn certificate() -> Result<RTCCertificate> {
    let provider = rtc::crypto::default_provider()?;
    Ok(RTCCertificate::generate(
        provider.crypto(),
        rtc::crypto::SignatureScheme::EcdsaP256Sha256,
        CertificateParams::new(vec!["bundle-fingerprints".to_owned()])?,
    )?)
}

/// Peer 0 offers audio, video and data in one BUNDLE group, the audio section tagged.
fn world(answerer_settings: SettingEngineBuilder) -> Result<World> {
    let mut world = World::new(
        Peer::with_configuration(
            "10.0.0.1:5000",
            RTCConfigurationBuilder::new()
                .with_certificates(vec![certificate()?])
                .build(),
            SettingEngineBuilder::new().build(),
        )?,
        Peer::new("10.0.0.2:5000", answerer_settings.build())?,
    );
    for kind in [RtpCodecKind::Audio, RtpCodecKind::Video] {
        world.peers[0]
            .pc
            .add_transceiver_from_kind(kind, Some(RTCRtpTransceiverInit::recvonly()))?;
    }
    world.peers[0].pc.create_data_channel("data", None)?;
    Ok(world)
}

/// RFC 8859 section 4.5: an offer whose second bundled section carries another fingerprint is
/// applied, and the connection is verified with the tagged section's: it connects, with the
/// offerer's certificate.
#[test]
fn the_tagged_sections_fingerprints_are_the_groups_and_the_others_are_not_used() -> Result<()> {
    let mut world = world(SettingEngineBuilder::new())?;
    let (offer, _) = world.exchange_with(0, |sdp| other_fingerprint_in_section(sdp, 1), keep)?;
    assert!(
        offer
            .lines()
            .any(|l| l.starts_with("a=group:BUNDLE") && l.split(' ').count() == 4),
        "three sections in one group: {offer}"
    );
    world.trickle()?;
    world.run("connected over the tagged section's fingerprint", |peers| {
        peers.iter().all(|p| p.connected() && p.channel.is_some())
    })?;
    world.ping_pong("data over the bundled transport")?;
    let offered = &world.peers[0].pc.get_configuration().certificates()[0];
    assert_eq!(
        world.peers[1].remote_certificate().as_deref(),
        Some(offered.dtls_certificate.certificate[0].as_ref())
    );
    Ok(())
}

/// The tagged section's fingerprints decide: with the tagged one changed and the others
/// left right, the answerer verifies against the changed one and the association fails.
#[test]
fn a_wrong_fingerprint_in_the_tagged_section_is_not_rescued_by_the_others() -> Result<()> {
    let mut world = world(SettingEngineBuilder::new())?;
    world.exchange_with(0, |sdp| other_fingerprint_in_section(sdp, 0), keep)?;
    world.trickle()?;
    let failed = world.run_for(std::time::Duration::from_secs(30), |peers| {
        peers[1].failed()
    });
    assert!(
        failed,
        "the answerer verified with a section other than the tagged one"
    );
    Ok(())
}

/// `with_bundled_fingerprints_agreeing(true)`: the hardening refuses the same offer, and the
/// answerer stays in `stable`.
#[test]
fn with_the_hardening_bundled_sections_that_disagree_refuse_the_description() -> Result<()> {
    let mut world = world(SettingEngineBuilder::new().with_bundled_fingerprints_agreeing(true))?;
    let now = Instant::now();
    let offer = world.peers[0].pc.create_offer(None)?;
    world.peers[0]
        .pc
        .set_local_description(now, offer.clone())?;
    let munged = RTCSessionDescription::offer(other_fingerprint_in_section(&offer.sdp, 1))?;
    assert_eq!(
        world.peers[1]
            .pc
            .set_remote_description(now, munged)
            .unwrap_err(),
        Error::ErrSessionDescriptionConflictingFingerprints
    );
    // The same offer unchanged is applied.
    world.peers[1]
        .pc
        .set_remote_description(now, RTCSessionDescription::offer(offer.sdp)?)?;
    Ok(())
}
