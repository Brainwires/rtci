//! W3C webrtc-extensions 10 (`rtpHeaderEncryptionPolicy`, Cryptex) and 13
//! (`alwaysNegotiateDataChannels`): the defaults, what each value negotiates, and that
//! neither changes after construction. Signalling only.

mod jsep_common;

use std::time::Instant;

use jsep_common::{TestResult, exchange, media_sections, mid_of, video_track};
use rtc::peer_connection::configuration::RTCConfigurationBuilder;
use rtc::peer_connection::configuration::media_engine::MediaEngine;
use rtc::peer_connection::cryptex::RTCRtpHeaderEncryptionPolicy;
use rtc::peer_connection::event::RTCPeerConnectionEvent;
use rtc::peer_connection::{RTCPeerConnection, RTCPeerConnectionBuilder};
use rtc::sansio::Protocol;
use rtc::shared::error::Error;

fn peer(
    configuration: RTCConfigurationBuilder,
) -> Result<RTCPeerConnection, Box<dyn std::error::Error>> {
    let mut media_engine = MediaEngine::default();
    media_engine.register_default_codecs()?;
    Ok(RTCPeerConnectionBuilder::new()
        .with_configuration(configuration.build())
        .with_media_engine(media_engine)
        .build(Instant::now())?)
}

fn with_policy(
    policy: RTCRtpHeaderEncryptionPolicy,
) -> Result<RTCPeerConnection, Box<dyn std::error::Error>> {
    peer(RTCConfigurationBuilder::new().with_rtp_header_encryption_policy(policy))
}

fn negotiation_needed(pc: &mut RTCPeerConnection) -> usize {
    let mut n = 0;
    while let Some(event) = pc.poll_event() {
        if matches!(event, RTCPeerConnectionEvent::OnNegotiationNeededEvent) {
            n += 1;
        }
    }
    n
}

/// webrtc-extensions 10.2: the policy defaults to "negotiate", and an offer then carries
/// `a=cryptex`; 10.1 "negotiate": answered with it when offered, used once both said it,
/// headers in the clear when the peer does not.
#[test]
fn the_header_encryption_policy_defaults_to_negotiate() -> TestResult {
    let mut offerer = peer(RTCConfigurationBuilder::new())?;
    assert_eq!(
        offerer.get_configuration().rtp_header_encryption_policy(),
        RTCRtpHeaderEncryptionPolicy::Negotiate
    );
    let mut answerer = peer(RTCConfigurationBuilder::new())?;
    offerer.add_track(video_track("v", 0x0a01_0101))?;
    let (offer, answer) = exchange(&mut offerer, &mut answerer)?;
    assert!(offer.contains("a=cryptex"), "{offer}");
    assert!(answer.contains("a=cryptex"), "{answer}");
    assert!(offerer.cryptex_negotiated() && answerer.cryptex_negotiated());

    let mut offerer = peer(RTCConfigurationBuilder::new())?;
    let mut disabled = with_policy(RTCRtpHeaderEncryptionPolicy::Disable)?;
    offerer.add_track(video_track("v", 0x0a01_0102))?;
    exchange(&mut offerer, &mut disabled)?;
    assert!(
        !offerer.cryptex_negotiated(),
        "the peer did not say it: headers in the clear"
    );
    Ok(())
}

/// webrtc-extensions 10.1 "disable": no `a=cryptex` in offers or answers, and a remote one is
/// not acted on.
#[test]
fn a_disabled_policy_neither_offers_nor_answers_cryptex() -> TestResult {
    let mut disabled = with_policy(RTCRtpHeaderEncryptionPolicy::Disable)?;
    let mut negotiating = peer(RTCConfigurationBuilder::new())?;
    disabled.add_track(video_track("v", 0x0a02_0101))?;
    let (offer, _) = exchange(&mut disabled, &mut negotiating)?;
    assert!(!offer.contains("a=cryptex"), "{offer}");

    let mut negotiating = peer(RTCConfigurationBuilder::new())?;
    let mut disabled = with_policy(RTCRtpHeaderEncryptionPolicy::Disable)?;
    negotiating.add_track(video_track("v", 0x0a02_0102))?;
    let (offer, answer) = exchange(&mut negotiating, &mut disabled)?;
    assert!(offer.contains("a=cryptex"));
    assert!(!answer.contains("a=cryptex"), "{answer}");
    assert!(!disabled.cryptex_negotiated());
    Ok(())
}

/// webrtc-extensions 10.2 and 13.2: neither policy changes after construction:
/// setConfiguration with another value is an InvalidModificationError; the engine setters
/// are refused once a description has been set.
#[test]
fn the_policies_cannot_change_after_construction() -> TestResult {
    let mut pc = peer(RTCConfigurationBuilder::new())?;
    for changed in [
        RTCConfigurationBuilder::new()
            .with_rtp_header_encryption_policy(RTCRtpHeaderEncryptionPolicy::Require),
        RTCConfigurationBuilder::new().with_always_negotiate_data_channels(true),
    ] {
        assert_eq!(
            pc.set_configuration(changed.build()),
            Err(Error::InvalidModificationError)
        );
    }
    pc.set_configuration(RTCConfigurationBuilder::new().build())?;

    pc.add_track(video_track("v", 0x0a03_0101))?;
    let offer = pc.create_offer(None)?;
    pc.set_local_description(Instant::now(), offer)?;
    assert_eq!(
        pc.set_rtp_header_encryption_policy(RTCRtpHeaderEncryptionPolicy::Disable),
        Err(Error::InvalidModificationError)
    );
    assert_eq!(
        pc.set_always_negotiate_data_channels(true),
        Err(Error::InvalidModificationError)
    );
    assert_eq!(
        pc.rtp_header_encryption_policy(),
        RTCRtpHeaderEncryptionPolicy::Negotiate
    );
    Ok(())
}

/// webrtc-extensions 13.2 and 13.3: with `alwaysNegotiateDataChannels` the first offer has a
/// data section without any channel, as the BUNDLE group's offerer-tagged (first) section;
/// the first data channel created after that needs no negotiation, and an offer made then
/// has one data section, not a second.
#[test]
fn always_negotiated_data_channels_need_no_negotiation_for_the_first_channel() -> TestResult {
    let configuration = || RTCConfigurationBuilder::new().with_always_negotiate_data_channels(true);
    let mut offerer = peer(configuration())?;
    let mut answerer = peer(RTCConfigurationBuilder::new())?;
    assert!(offerer.get_configuration().always_negotiate_data_channels());
    offerer.add_track(video_track("v", 0x0a04_0101))?;
    let (offer, _) = exchange(&mut offerer, &mut answerer)?;
    let sections = media_sections(&offer);
    assert!(sections[0][0].starts_with("m=application"), "{offer}");
    let data_mid = mid_of(&sections[0]).expect("a mid").to_owned();
    let group = offer
        .lines()
        .find_map(|l| l.strip_prefix("a=group:BUNDLE "))
        .expect("a BUNDLE group");
    assert_eq!(
        group.split_whitespace().next(),
        Some(data_mid.as_str()),
        "{offer}"
    );
    negotiation_needed(&mut offerer);

    offerer.create_data_channel("first", None)?;
    assert_eq!(
        negotiation_needed(&mut offerer),
        0,
        "the data section exists"
    );
    let offer = offerer.create_offer(None)?;
    assert_eq!(
        media_sections(&offer.sdp)
            .iter()
            .filter(|s| s[0].starts_with("m=application"))
            .count(),
        1,
        "{}",
        offer.sdp
    );
    Ok(())
}
