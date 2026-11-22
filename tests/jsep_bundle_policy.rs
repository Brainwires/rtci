//! The bundle policy (RFC 9429 section 4.1.1) decides which m= sections of an initial offer
//! carry transport parameters and which are bundle-only (RFC 9143 sections 6, 7.1.3 and
//! 7.2.1), and which sections of an offer without a BUNDLE group an answer accepts. The
//! default is `balanced`.

mod jsep_common;

use std::time::Instant;

use jsep_common::{
    SESSION, TRANSPORT, TestResult, crlf, exchange, media_sections, port_of, video_track,
};
use rtc::peer_connection::configuration::media_engine::MediaEngine;
use rtc::peer_connection::configuration::setting_engine::SettingEngineBuilder;
use rtc::peer_connection::configuration::{RTCBundlePolicy, RTCConfigurationBuilder};
use rtc::peer_connection::sdp::RTCSessionDescription;
use rtc::peer_connection::{RTCPeerConnection, RTCPeerConnectionBuilder};
use rtc::rtp_transceiver::rtp_sender::RtpCodecKind;

fn peer(policy: Option<RTCBundlePolicy>) -> Result<RTCPeerConnection, Box<dyn std::error::Error>> {
    peer_with(policy, false)
}

/// `max_bundle_alias`: `SettingEngineBuilder::with_max_bundle_as_must_bundle`.
fn peer_with(
    policy: Option<RTCBundlePolicy>,
    max_bundle_alias: bool,
) -> Result<RTCPeerConnection, Box<dyn std::error::Error>> {
    let mut media_engine = MediaEngine::default();
    media_engine.register_default_codecs()?;
    let mut builder = RTCPeerConnectionBuilder::new()
        .with_media_engine(media_engine)
        .with_setting_engine(
            SettingEngineBuilder::new()
                .with_max_bundle_as_must_bundle(max_bundle_alias)
                .build(),
        );
    if let Some(policy) = policy {
        builder = builder.with_configuration(
            RTCConfigurationBuilder::new()
                .with_bundle_policy(policy)
                .build(),
        );
    }
    Ok(builder.build(Instant::now())?)
}

/// An offerer of audio, video, video and a data channel, in that order.
fn offerer(
    policy: Option<RTCBundlePolicy>,
) -> Result<RTCPeerConnection, Box<dyn std::error::Error>> {
    offerer_with(policy, false)
}

fn offerer_with(
    policy: Option<RTCBundlePolicy>,
    max_bundle_alias: bool,
) -> Result<RTCPeerConnection, Box<dyn std::error::Error>> {
    let mut pc = peer_with(policy, max_bundle_alias)?;
    pc.add_transceiver_from_kind(RtpCodecKind::Audio, None)?;
    pc.add_track(video_track("first", 0x0101_0101))?;
    pc.add_track(video_track("second", 0x0202_0202))?;
    pc.create_data_channel("data", None)?;
    Ok(pc)
}

fn has(section: &[String], prefix: &str) -> bool {
    section.iter().any(|l| l.starts_with(prefix))
}

/// For each section: (media type, whether it is bundle-only).
fn shape(sdp: &str) -> Vec<(String, bool)> {
    media_sections(sdp)
        .iter()
        .map(|section| {
            let media = section[0][2..]
                .split(' ')
                .next()
                .unwrap_or_default()
                .to_owned();
            let bundle_only = has(section, "a=bundle-only");
            // A bundle-only section has port zero and none of the BUNDLE attributes; any
            // other has a port and its transport parameters.
            assert_eq!(port_of(section) == 0, bundle_only, "{sdp}");
            for attribute in ["a=ice-ufrag:", "a=ice-pwd:", "a=setup:"] {
                assert_eq!(has(section, attribute), !bundle_only, "{attribute}\n{sdp}");
            }
            if media != "application" {
                assert_eq!(has(section, "a=rtcp-mux"), !bundle_only, "{sdp}");
            }
            assert!(has(section, "a=mid:"), "{sdp}");
            (media, bundle_only)
        })
        .collect()
}

fn group(sdp: &str) -> Vec<&str> {
    sdp.lines().filter(|l| l.starts_with("a=group:")).collect()
}

#[test]
fn balanced_is_the_default_and_bundles_later_sections_of_a_type() -> TestResult {
    for policy in [None, Some(RTCBundlePolicy::Balanced)] {
        let mut pc = offerer(policy)?;
        let offer = pc.create_offer(None)?;
        assert_eq!(
            shape(&offer.sdp),
            vec![
                ("audio".to_owned(), false),
                ("video".to_owned(), false),
                ("video".to_owned(), true),
                ("application".to_owned(), false),
            ],
            "{}",
            offer.sdp
        );
        // Every section is in the group, bundle-only or not, the first one tagged.
        assert_eq!(
            group(&offer.sdp),
            vec!["a=group:BUNDLE 0 1 2 3"],
            "{}",
            offer.sdp
        );
    }
    Ok(())
}

#[test]
fn must_bundle_gives_only_the_first_section_a_transport() -> TestResult {
    let mut pc = offerer(Some(RTCBundlePolicy::MustBundle))?;
    let offer = pc.create_offer(None)?;
    assert_eq!(
        shape(&offer.sdp)
            .into_iter()
            .map(|(_, bundle_only)| bundle_only)
            .collect::<Vec<_>>(),
        vec![false, true, true, true],
        "{}",
        offer.sdp
    );
    Ok(())
}

/// RFC 9429 section 4.1.1: "'max-bundle' is considered deprecated, and implementations
/// compliant with this specification SHOULD ignore attempts by the application to select this
/// bundle policy": the default, balanced, stays in effect. The setting engine can make it the
/// alias of must-bundle it was defined as.
#[test]
fn max_bundle_is_ignored_unless_made_an_alias_of_must_bundle() -> TestResult {
    let mut pc = offerer(Some(RTCBundlePolicy::MaxBundle))?;
    let offer = pc.create_offer(None)?;
    assert_eq!(
        shape(&offer.sdp)
            .into_iter()
            .map(|(_, bundle_only)| bundle_only)
            .collect::<Vec<_>>(),
        vec![false, false, true, false],
        "balanced:\n{}",
        offer.sdp
    );

    let mut pc = offerer_with(Some(RTCBundlePolicy::MaxBundle), true)?;
    let offer = pc.create_offer(None)?;
    assert_eq!(
        shape(&offer.sdp)
            .into_iter()
            .map(|(_, bundle_only)| bundle_only)
            .collect::<Vec<_>>(),
        vec![false, true, true, true],
        "must-bundle:\n{}",
        offer.sdp
    );
    Ok(())
}

#[test]
fn max_compat_marks_no_section_bundle_only() -> TestResult {
    let mut pc = offerer(Some(RTCBundlePolicy::MaxCompat))?;
    let offer = pc.create_offer(None)?;
    assert!(
        shape(&offer.sdp)
            .iter()
            .all(|(_, bundle_only)| !bundle_only)
    );
    assert!(!offer.sdp.contains("a=bundle-only"), "{}", offer.sdp);
    Ok(())
}

/// The answer accepts the bundle-only sections with a port and without the attribute (RFC
/// 9429 section 5.3.1); a later offer does not mark any section bundle-only (section 5.2.2).
#[test]
fn bundle_only_sections_are_answered_and_not_marked_again() -> TestResult {
    for policy in [None, Some(RTCBundlePolicy::MustBundle)] {
        let mut a = offerer(policy)?;
        let mut b = peer(None)?;
        let (offer, answer) = exchange(&mut a, &mut b)?;
        assert!(offer.contains("a=bundle-only"), "{offer}");
        assert!(!answer.contains("a=bundle-only"), "{answer}");
        let sections = media_sections(&answer);
        assert_eq!(sections.len(), 4);
        for section in &sections {
            assert_ne!(port_of(section), 0, "{answer}");
        }
        assert_eq!(group(&answer), vec!["a=group:BUNDLE 0 1 2 3"], "{answer}");

        let offer = a.create_offer(None)?;
        assert!(!offer.sdp.contains("a=bundle-only"), "{}", offer.sdp);
        for section in media_sections(&offer.sdp) {
            assert_ne!(port_of(&section), 0, "{}", offer.sdp);
        }
        // And the other side's first offer of this session does not either.
        let offer = b.create_offer(None)?;
        assert!(!offer.sdp.contains("a=bundle-only"), "{}", offer.sdp);
    }
    Ok(())
}

/// RFC 9429 section 4.1.1, answering an offer with no BUNDLE group: balanced rejects "all but
/// the first 'm=' section of each type", must-bundle all but the first section, max-compat
/// none.
#[test]
fn an_offer_without_a_group_is_answered_by_the_policy() -> TestResult {
    let section = |media: &str, mid: &str, format: &str| {
        format!(
            "m={media} 9 UDP/TLS/RTP/SAVPF {}
{TRANSPORT}a=mid:{mid}
a=sendrecv
a=rtpmap:{format}
",
            format.split(' ').next().unwrap_or_default()
        )
    };
    let offer = crlf(&format!(
        "{SESSION}{}{}{}",
        section("audio", "0", "111 opus/48000/2"),
        section("video", "1", "96 VP8/90000"),
        section("video", "2", "96 VP8/90000"),
    ));
    for (policy, alias, accepted) in [
        (None, false, [true, true, false]),
        (Some(RTCBundlePolicy::Balanced), false, [true, true, false]),
        (
            Some(RTCBundlePolicy::MustBundle),
            false,
            [true, false, false],
        ),
        (Some(RTCBundlePolicy::MaxBundle), false, [true, true, false]),
        (Some(RTCBundlePolicy::MaxBundle), true, [true, false, false]),
        (Some(RTCBundlePolicy::MaxCompat), false, [true, true, true]),
    ] {
        let mut pc = peer_with(policy, alias)?;
        pc.set_remote_description(Instant::now(), RTCSessionDescription::offer(offer.clone())?)?;
        let answer = pc.create_answer(None)?;
        let ports: Vec<bool> = media_sections(&answer.sdp)
            .iter()
            .map(|s| port_of(s) != 0)
            .collect();
        assert_eq!(ports, accepted, "{policy:?}:\n{}", answer.sdp);
        assert!(group(&answer.sdp).is_empty(), "{}", answer.sdp);
        pc.set_local_description(Instant::now(), answer)?;
    }
    Ok(())
}
