//! The bundle-only sections of an initial offer (RFC 9143 sections 6, 7.1.3, 7.2 and 9.3.1.1)
//! in the RFC form, the default, and in the form browsers accept,
//! `SettingEngineBuilder::with_rtcp_mux_and_session_fingerprint_for_bundle_only_sections(true)`
//! (the `Chrome` profile): `a=rtcp-mux` in each bundle-only RTP section and the fingerprints at
//! session level as well. Chromium, WebKit and Firefox refuse the RFC form (browser matrix,
//! test-env run 45900172027) and take the other (run 45903674595).

mod jsep_common;

use std::time::Instant;

use jsep_common::{TestResult, exchange, media_sections, port_of, video_track};
use rtci::peer_connection::configuration::BehaviourProfile;
use rtci::peer_connection::configuration::media_engine::MediaEngine;
use rtci::peer_connection::configuration::setting_engine::SettingEngineBuilder;
use rtci::peer_connection::configuration::{RTCBundlePolicy, RTCConfigurationBuilder};
use rtci::peer_connection::{RTCPeerConnection, RTCPeerConnectionBuilder};
use rtci::rtp_transceiver::rtp_sender::RtpCodecKind;

/// A peer with the bundle policy and the setting (`None`: no setting engine call at all).
fn peer(
    policy: RTCBundlePolicy,
    browser_form: Option<bool>,
) -> Result<RTCPeerConnection, Box<dyn std::error::Error>> {
    let mut settings = SettingEngineBuilder::new();
    if let Some(on) = browser_form {
        settings = settings.with_rtcp_mux_and_session_fingerprint_for_bundle_only_sections(on);
    }
    build(policy, settings)
}

fn build(
    policy: RTCBundlePolicy,
    settings: SettingEngineBuilder,
) -> Result<RTCPeerConnection, Box<dyn std::error::Error>> {
    let mut media_engine = MediaEngine::default();
    media_engine.register_default_codecs()?;
    Ok(RTCPeerConnectionBuilder::new()
        .with_media_engine(media_engine)
        .with_setting_engine(settings.build())
        .with_configuration(
            RTCConfigurationBuilder::new()
                .with_bundle_policy(policy)
                .build(),
        )
        .build(Instant::now())?)
}

/// Audio, video and a data channel: under max-bundle the video and data sections are
/// bundle-only.
fn audio_video_data(pc: &mut RTCPeerConnection) -> TestResult {
    pc.add_transceiver_from_kind(RtpCodecKind::Audio, None)?;
    pc.add_track(video_track("video", 0x0101_0101))?;
    pc.create_data_channel("data", None)?;
    Ok(())
}

/// The session part of a description: its lines before the first m= line.
fn session(sdp: &str) -> Vec<String> {
    sdp.lines()
        .take_while(|l| !l.starts_with("m="))
        .map(str::to_owned)
        .collect()
}

fn lines<'a>(section: &'a [String], prefix: &str) -> Vec<&'a String> {
    section.iter().filter(|l| l.starts_with(prefix)).collect()
}

fn is_bundle_only(section: &[String]) -> bool {
    section.iter().any(|l| l == "a=bundle-only")
}

fn is_rtp(section: &[String]) -> bool {
    !section[0].starts_with("m=application")
}

/// RFC 9143 section 7.1.3: "In the initial BUNDLE offer, the offerer MUST NOT include
/// IDENTICAL and TRANSPORT multiplexing category SDP attributes (BUNDLE attributes) in
/// bundle-only "m=" sections"; section 9.3.1.1: `a=rtcp-mux` "in each bundled "m=" section
/// (excluding any bundle-only "m=" sections)". The default, and the setting off, write that
/// form, with the fingerprints in the sections that have a transport only.
///
/// With the `chrome-defaults` feature the default is the `Chrome` profile, so the call-free
/// case is the RFC form only in a build with the RFC default.
#[test]
fn by_default_bundle_only_sections_carry_no_bundle_attribute_and_no_session_fingerprint()
-> TestResult {
    let cases: &[Option<bool>] = if BehaviourProfile::compiled_default() == BehaviourProfile::Chrome
    {
        &[Some(false)]
    } else {
        &[None, Some(false)]
    };
    for &browser_form in cases {
        let mut pc = peer(RTCBundlePolicy::MaxBundle, browser_form)?;
        audio_video_data(&mut pc)?;
        let offer = pc.create_offer(None)?.sdp;
        let sections = media_sections(&offer);
        assert_eq!(
            sections
                .iter()
                .map(|s| is_bundle_only(s))
                .collect::<Vec<_>>(),
            vec![false, true, true],
            "{browser_form:?}:\n{offer}"
        );
        for section in sections.iter().filter(|s| is_bundle_only(s)) {
            for attribute in [
                "a=rtcp-mux",
                "a=rtcp-rsize",
                "a=fingerprint:",
                "a=ice-ufrag:",
                "a=setup:",
            ] {
                assert!(
                    lines(section, attribute).is_empty(),
                    "{browser_form:?}: {attribute} in a bundle-only section:\n{offer}"
                );
            }
        }
        assert!(
            lines(&session(&offer), "a=fingerprint:").is_empty(),
            "{browser_form:?}: no session-level fingerprint:\n{offer}"
        );
        assert!(!lines(&sections[0], "a=fingerprint:").is_empty(), "{offer}");
        assert!(!lines(&sections[0], "a=rtcp-mux").is_empty(), "{offer}");
    }
    Ok(())
}

/// The setting: each bundle-only RTP section says `a=rtcp-mux` (and no other BUNDLE
/// attribute), the bundle-only data section none, and the tagged section's fingerprints are
/// at session level as well (RFC 8122 section 5, RFC 9429 section 5.2.1).
#[test]
fn with_the_setting_bundle_only_rtp_sections_say_rtcp_mux_and_the_fingerprints_are_also_at_session_level()
-> TestResult {
    let mut pc = peer(RTCBundlePolicy::MaxBundle, Some(true))?;
    audio_video_data(&mut pc)?;
    let offer = pc.create_offer(None)?.sdp;
    let sections = media_sections(&offer);
    assert_eq!(
        sections
            .iter()
            .map(|s| is_bundle_only(s))
            .collect::<Vec<_>>(),
        vec![false, true, true],
        "{offer}"
    );
    for section in sections.iter().filter(|s| is_bundle_only(s)) {
        let mux = lines(section, "a=rtcp-mux")
            .into_iter()
            .filter(|l| *l == "a=rtcp-mux")
            .count();
        assert_eq!(
            mux,
            usize::from(is_rtp(section)),
            "{}:\n{offer}",
            section[0]
        );
        for attribute in [
            "a=rtcp-mux-only",
            "a=rtcp-rsize",
            "a=fingerprint:",
            "a=ice-ufrag:",
            "a=ice-pwd:",
            "a=setup:",
            "a=candidate:",
        ] {
            assert!(
                lines(section, attribute).is_empty(),
                "{attribute} in a bundle-only section:\n{offer}"
            );
        }
        assert_eq!(port_of(section), 0, "{offer}");
    }
    let tagged = lines(&sections[0], "a=fingerprint:");
    assert!(!tagged.is_empty(), "{offer}");
    assert_eq!(
        lines(&session(&offer), "a=fingerprint:"),
        tagged,
        "the tagged section's fingerprints at session level too:\n{offer}"
    );
    Ok(())
}

/// The `Chrome` behaviour profile turns the setting on; `Rfc` and `StrictRfc` leave it off.
/// `must-bundle`: `StrictRfc` ignores `max-bundle` (RFC 9429 4.1.1 SHOULD,
/// `with_max_bundle_as_must_bundle(false)`), so its offer would have no bundle-only section.
#[test]
fn the_chrome_profile_writes_the_browser_form() -> TestResult {
    for (profile, on) in [
        (BehaviourProfile::Chrome, true),
        (BehaviourProfile::Rfc, false),
        (BehaviourProfile::StrictRfc, false),
    ] {
        let mut pc = build(
            RTCBundlePolicy::MustBundle,
            SettingEngineBuilder::new().with_behaviour_profile(profile),
        )?;
        audio_video_data(&mut pc)?;
        let offer = pc.create_offer(None)?.sdp;
        let video = &media_sections(&offer)[1];
        assert!(is_bundle_only(video), "{profile:?}:\n{offer}");
        assert_eq!(
            !lines(video, "a=rtcp-mux").is_empty(),
            on,
            "{profile:?}:\n{offer}"
        );
        assert_eq!(
            !lines(&session(&offer), "a=fingerprint:").is_empty(),
            on,
            "{profile:?}:\n{offer}"
        );
    }
    Ok(())
}

/// Only an initial offer has bundle-only sections (RFC 9429 section 5.2.2), so the setting
/// changes nothing else: the offerer's later offer and the answers, from an answerer with the
/// setting on, have no session-level fingerprint and their sections are as without it.
#[test]
fn later_offers_and_answers_are_unchanged_by_the_setting() -> TestResult {
    let mut with = peer(RTCBundlePolicy::MaxBundle, Some(true))?;
    let mut without = peer(RTCBundlePolicy::MaxBundle, Some(false))?;
    audio_video_data(&mut with)?;
    audio_video_data(&mut without)?;
    let mut answerer_with = peer(RTCBundlePolicy::MaxBundle, Some(true))?;
    let mut answerer_without = peer(RTCBundlePolicy::MaxBundle, Some(false))?;
    let (_, answer_with) = exchange(&mut with, &mut answerer_with)?;
    let (_, answer_without) = exchange(&mut without, &mut answerer_without)?;
    let later_with = with.create_offer(None)?.sdp;
    let later_without = without.create_offer(None)?.sdp;
    let skeleton = |sdp: &str| -> Vec<Vec<String>> {
        media_sections(sdp)
            .iter()
            .map(|s| {
                s.iter()
                    .map(|l| l.split(':').next().unwrap_or_default().to_owned())
                    .collect()
            })
            .collect()
    };
    for (what, a, b) in [
        ("answer", &answer_with, &answer_without),
        ("later offer", &later_with, &later_without),
    ] {
        assert!(
            lines(&session(a), "a=fingerprint:").is_empty(),
            "{what}: no session-level fingerprint:\n{a}"
        );
        assert!(
            !a.contains("a=bundle-only"),
            "{what} has no bundle-only section:\n{a}"
        );
        assert_eq!(skeleton(a), skeleton(b), "{what}:\n{a}\n---\n{b}");
    }
    Ok(())
}

/// Under `balanced` (the default policy) the second section of a media type is bundle-only
/// (RFC 9429 section 4.1.1): it gets `a=rtcp-mux` too.
#[test]
fn a_balanced_offer_with_two_sections_of_a_type_gets_it_too() -> TestResult {
    let mut pc = peer(RTCBundlePolicy::Balanced, Some(true))?;
    pc.add_track(video_track("first", 0x0101_0101))?;
    pc.add_track(video_track("second", 0x0202_0202))?;
    let offer = pc.create_offer(None)?.sdp;
    let sections = media_sections(&offer);
    assert!(!is_bundle_only(&sections[0]), "{offer}");
    assert!(is_bundle_only(&sections[1]), "{offer}");
    assert!(
        lines(&sections[1], "a=rtcp-mux").contains(&&"a=rtcp-mux".to_owned()),
        "{offer}"
    );
    assert!(
        !lines(&session(&offer), "a=fingerprint:").is_empty(),
        "{offer}"
    );
    Ok(())
}

/// An initial offer without a bundle-only section is the same with the setting on.
#[test]
fn an_offer_without_a_bundle_only_section_is_unchanged() -> TestResult {
    for policy in [RTCBundlePolicy::MaxCompat, RTCBundlePolicy::Balanced] {
        let mut pc = peer(policy, Some(true))?;
        pc.add_transceiver_from_kind(RtpCodecKind::Audio, None)?;
        pc.add_track(video_track("video", 0x0101_0101))?;
        pc.create_data_channel("data", None)?;
        let offer = pc.create_offer(None)?.sdp;
        assert!(!offer.contains("a=bundle-only"), "{policy:?}:\n{offer}");
        assert!(
            lines(&session(&offer), "a=fingerprint:").is_empty(),
            "{policy:?}: no session-level fingerprint:\n{offer}"
        );
    }
    Ok(())
}

/// Between two engines the browser form negotiates as the RFC form does: the answerer accepts
/// every section, the data section with its association.
#[test]
fn an_engine_answers_the_browser_form_as_the_rfc_form() -> TestResult {
    for browser_form in [false, true] {
        let mut offerer = peer(RTCBundlePolicy::MaxBundle, Some(browser_form))?;
        audio_video_data(&mut offerer)?;
        let mut answerer = peer(RTCBundlePolicy::Balanced, None)?;
        let (offer, answer) = exchange(&mut offerer, &mut answerer)?;
        for section in media_sections(&answer) {
            assert_ne!(
                port_of(&section),
                0,
                "{browser_form}:\n{offer}\n---\n{answer}"
            );
        }
        assert!(answerer.sctp().is_some(), "{browser_form}:\n{offer}");
        assert!(offerer.sctp().is_some(), "{browser_form}:\n{offer}");
    }
    Ok(())
}
