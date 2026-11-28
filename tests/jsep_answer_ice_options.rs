//! The `a=ice-options` line of an answer (`docs/conformance/spec-issues.md` row 28).
//!
//! By default every answer says `a=ice-options:trickle ice2`, whatever the offer had: RFC 8840
//! section 4.1.3 ("In any case, the Answerer MUST include the "ice-options:trickle"
//! attribute"), RFC 8445 section 10 ("An agent compliant to this specification MUST inform the
//! peer about the compliance using the 'ice2' option") and RFC 8839 section 4.3.2.
//!
//! `SettingEngineBuilder::with_answer_ice_options_as_offered(true)` (the `StrictRfc` profile)
//! gives the form of RFC 9429 section 5.3.1: the line, with the "trickle" option and the "ice2"
//! option, "is only included if such an option was present in the offer".

mod jsep_common;

use std::time::Instant;

use jsep_common::{SESSION, TRANSPORT, TestResult, crlf};
use rtci::peer_connection::configuration::BehaviourProfile;
use rtci::peer_connection::configuration::media_engine::MediaEngine;
use rtci::peer_connection::configuration::setting_engine::SettingEngineBuilder;
use rtci::peer_connection::sdp::RTCSessionDescription;
use rtci::peer_connection::{RTCPeerConnection, RTCPeerConnectionBuilder};
use rtci::rtp_transceiver::rtp_sender::RtpCodecKind;

fn build(settings: SettingEngineBuilder) -> Result<RTCPeerConnection, Box<dyn std::error::Error>> {
    let mut media_engine = MediaEngine::default();
    media_engine.register_default_codecs()?;
    Ok(RTCPeerConnectionBuilder::new()
        .with_media_engine(media_engine)
        .with_setting_engine(settings.build())
        .build(Instant::now())?)
}

fn peer(as_offered: bool) -> Result<RTCPeerConnection, Box<dyn std::error::Error>> {
    build(SettingEngineBuilder::new().with_answer_ice_options_as_offered(as_offered))
}

/// An audio offer whose session-level `a=ice-options` line is `options` (none for `None`).
fn offer(options: Option<&str>) -> String {
    let line = options.map_or(String::new(), |o| format!("a=ice-options:{o}\n"));
    crlf(&format!(
        "{SESSION}{line}a=group:BUNDLE 0
m=audio 9 UDP/TLS/RTP/SAVPF 111
{TRANSPORT}a=mid:0
a=sendrecv
a=rtpmap:111 opus/48000/2
"
    ))
}

/// The answer `pc` makes to `sdp`, set as its local description.
fn answer_to(
    pc: &mut RTCPeerConnection,
    sdp: String,
) -> Result<String, Box<dyn std::error::Error>> {
    let now = Instant::now();
    pc.set_remote_description(now, RTCSessionDescription::offer(sdp)?)?;
    let answer = pc.create_answer(None)?;
    pc.set_local_description(now, answer.clone())?;
    Ok(answer.sdp)
}

/// Every `a=ice-options` line of `sdp` (session or media level), as its value.
fn ice_options(sdp: &str) -> Vec<String> {
    sdp.lines()
        .filter(|l| l.starts_with("a=ice-options"))
        .map(|l| {
            l.trim_start_matches("a=ice-options")
                .trim_start_matches(':')
                .to_owned()
        })
        .collect()
}

/// The default: `trickle ice2` in the answer to an offer without the line, and to a browser's
/// offer (`trickle` only).
#[test]
fn by_default_every_answer_says_trickle_and_ice2() -> TestResult {
    for offered in [None, Some("trickle"), Some("ice2"), Some("trickle ice2")] {
        let answer = answer_to(&mut peer(false)?, offer(offered))?;
        assert_eq!(
            ice_options(&answer),
            ["trickle ice2"],
            "offer {offered:?}: {answer}"
        );
    }
    Ok(())
}

/// With the setting: each option only when the offer has it, and no line (never an empty one:
/// RFC 8839 section 5.6, "ice-options" is one or more option tags) when it has neither.
#[test]
fn with_the_setting_an_answer_says_only_the_options_the_offer_has() -> TestResult {
    for (offered, answered) in [
        (None, vec![]),
        (Some("trickle"), vec!["trickle"]),
        (Some("ice2"), vec!["ice2"]),
        (Some("trickle ice2"), vec!["trickle ice2"]),
        // Other options are not echoed.
        (Some("trickle renomination"), vec!["trickle"]),
    ] {
        let answer = answer_to(&mut peer(true)?, offer(offered))?;
        assert_eq!(
            ice_options(&answer),
            answered,
            "offer {offered:?}: {answer}"
        );
        assert!(!answer.contains("a=ice-options\r\n"), "{answer}");
        assert!(!answer.contains("a=ice-options:\r\n"), "{answer}");
    }
    Ok(())
}

/// The options are read where the offer has them: at media level too.
#[test]
fn with_the_setting_media_level_options_of_the_offer_count() -> TestResult {
    let sdp = offer(None).replace("a=mid:0\r\n", "a=mid:0\r\na=ice-options:trickle\r\n");
    let answer = answer_to(&mut peer(true)?, sdp)?;
    assert_eq!(ice_options(&answer), ["trickle"], "{answer}");
    Ok(())
}

/// A lite agent (whose descriptions say `trickle ice2`, ice-36) follows the setting too; it
/// still says `a=ice-lite`.
#[test]
fn a_lite_agent_with_the_setting_answers_the_offers_options() -> TestResult {
    let lite = |as_offered| {
        build(
            SettingEngineBuilder::new()
                .with_lite(true)
                .with_answer_ice_options_as_offered(as_offered),
        )
    };
    for (as_offered, offered, answered) in [
        (false, None, vec!["trickle ice2"]),
        (false, Some("trickle"), vec!["trickle ice2"]),
        (true, None, vec![]),
        (true, Some("trickle"), vec!["trickle"]),
        (true, Some("trickle ice2"), vec!["trickle ice2"]),
    ] {
        let answer = answer_to(&mut lite(as_offered)?, offer(offered))?;
        assert!(answer.contains("a=ice-lite\r\n"), "{answer}");
        assert_eq!(
            ice_options(&answer),
            answered,
            "setting {as_offered}, offer {offered:?}: {answer}"
        );
    }
    Ok(())
}

/// Offers are not affected: an initial offer, and the answerer's later offer after it answered
/// a browser's offer with `trickle` alone, say `trickle ice2` (RFC 9429 sections 5.2.1 and
/// 5.2.2). That later offer changes the options its answer stated, which RFC 8839 section
/// 4.4.1.1.1 forbids outside a restart ("The agent MUST NOT modify the SDP "ice-options" ...
/// attributes in a subsequent offer unless the offer is sent in order to request an ICE
/// restart"): one more face of the contradiction (spec-issues row 28).
#[test]
fn with_the_setting_offers_still_say_trickle_and_ice2() -> TestResult {
    let mut offerer = peer(true)?;
    offerer.add_transceiver_from_kind(RtpCodecKind::Audio, None)?;
    let initial = offerer.create_offer(None)?;
    assert_eq!(
        ice_options(&initial.sdp),
        ["trickle ice2"],
        "{}",
        initial.sdp
    );

    let mut answerer = peer(true)?;
    let answer = answer_to(&mut answerer, offer(Some("trickle")))?;
    assert_eq!(ice_options(&answer), ["trickle"], "{answer}");
    let later = answerer.create_offer(None)?;
    assert_eq!(ice_options(&later.sdp), ["trickle ice2"], "{}", later.sdp);
    Ok(())
}

/// Two `rtci` peers with the setting behave as without it: an `rtci` offer always has both
/// options, so the answer has both, and the offerer reads the same from it
/// (`canTrickleIceCandidates`, W3C webrtc-pc 4.4.1.6 / RFC 9429 5.10; the peer's `ice2`,
/// RFC 8839 section 4.3.4).
#[test]
fn two_rtci_peers_with_the_setting_read_both_options_from_the_answer() -> TestResult {
    for as_offered in [false, true] {
        let now = Instant::now();
        let mut offerer = peer(as_offered)?;
        let mut answerer = peer(as_offered)?;
        offerer.add_transceiver_from_kind(RtpCodecKind::Audio, None)?;
        let o = offerer.create_offer(None)?;
        offerer.set_local_description(now, o.clone())?;
        answerer.set_remote_description(now, o)?;
        let a = answerer.create_answer(None)?;
        answerer.set_local_description(now, a.clone())?;
        offerer.set_remote_description(now, a.clone())?;
        assert_eq!(ice_options(&a.sdp), ["trickle ice2"], "{}", a.sdp);
        assert_eq!(offerer.can_trickle_ice_candidates(), Some(true));
        assert_eq!(answerer.can_trickle_ice_candidates(), Some(true));
        let options = offerer.remote_ice_options();
        assert!(
            options.contains(&"trickle".to_owned()) && options.contains(&"ice2".to_owned()),
            "{options:?}"
        );
    }
    Ok(())
}

/// The profiles: only `StrictRfc` answers with the offer's options.
#[test]
fn only_the_strict_rfc_profile_answers_with_the_offers_options() -> TestResult {
    for (profile, answered) in [
        (BehaviourProfile::Rfc, vec!["trickle ice2"]),
        (BehaviourProfile::Chrome, vec!["trickle ice2"]),
        (BehaviourProfile::Performance, vec!["trickle ice2"]),
        (BehaviourProfile::StrictRfc, vec!["trickle"]),
    ] {
        let answer = answer_to(
            &mut build(SettingEngineBuilder::new().with_behaviour_profile(profile))?,
            offer(Some("trickle")),
        )?;
        assert_eq!(ice_options(&answer), answered, "{profile}: {answer}");
    }
    Ok(())
}
