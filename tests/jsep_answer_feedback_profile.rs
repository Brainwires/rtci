//! RFC 9429 section 5.11: "If the 'm=' section references RTCP feedback mechanisms that were
//! not present in the corresponding 'm=' section in the offer, this indicates a negotiation
//! problem and MUST result in an error."
//!
//! This default does not follow RFC 9429 section 5.11 (owner decision, `docs/conformance.md`,
//! "Standing departures from a MUST"): such an answer is applied and the extra feedback is never
//! enabled. `SettingEngineBuilder::with_unoffered_feedback_refused(true)`, which the `StrictRfc`
//! behaviour profile sets, refuses it and leaves the offer pending.

mod jsep_common;

use jsep_common::{TestResult, video_track};
use rtci::peer_connection::configuration::BehaviourProfile;
use rtci::peer_connection::configuration::media_engine::MediaEngine;
use rtci::peer_connection::configuration::setting_engine::SettingEngineBuilder;
use rtci::peer_connection::sdp::RTCSessionDescription;
use rtci::peer_connection::state::RTCSignalingState;
use rtci::peer_connection::{RTCPeerConnection, RTCPeerConnectionBuilder};
use std::time::Instant;

fn peer(profile: BehaviourProfile) -> Result<RTCPeerConnection, Box<dyn std::error::Error>> {
    let mut media_engine = MediaEngine::for_profile(profile);
    media_engine.register_default_codecs()?;
    Ok(RTCPeerConnectionBuilder::new()
        .with_media_engine(media_engine)
        .with_setting_engine(
            SettingEngineBuilder::new()
                .with_behaviour_profile(profile)
                .build(),
        )
        .build(Instant::now())?)
}

/// The offerer's pending video offer and the answer of a peer of the same profile, with one
/// `a=rtcp-fb` line the offer did not have added to the answer's video section.
fn offer_and_answer_with_extra_feedback(
    profile: BehaviourProfile,
) -> Result<(RTCPeerConnection, String), Box<dyn std::error::Error>> {
    let now = Instant::now();
    let mut offerer = peer(profile)?;
    let mut answerer = peer(profile)?;
    offerer.add_track(video_track("v", 0x5e13_0201))?;
    let offer = offerer.create_offer(None)?;
    offerer.set_local_description(now, offer.clone())?;
    answerer.set_remote_description(now, offer.clone())?;
    let answer = answerer.create_answer(None)?;
    answerer.set_local_description(now, answer.clone())?;
    assert!(!offer.sdp.contains("made-up"));
    let payload_type = answer
        .sdp
        .lines()
        .find(|l| l.starts_with("m=video"))
        .and_then(|l| l.split_whitespace().nth(3))
        .expect("the answer accepts a video format")
        .to_owned();
    let mut lines: Vec<String> = answer.sdp.lines().map(str::to_owned).collect();
    let at = lines
        .iter()
        .position(|l| l.starts_with(&format!("a=rtpmap:{payload_type} ")))
        .expect("the format's rtpmap");
    lines.insert(at + 1, format!("a=rtcp-fb:{payload_type} made-up"));
    Ok((offerer, lines.join("\r\n") + "\r\n"))
}

#[test]
fn by_default_an_answer_with_feedback_the_offer_lacked_is_applied() -> TestResult {
    for profile in [
        BehaviourProfile::Rfc,
        BehaviourProfile::Chrome,
        BehaviourProfile::Performance,
    ] {
        let (mut offerer, answer) = offer_and_answer_with_extra_feedback(profile)?;
        offerer.set_remote_description(Instant::now(), RTCSessionDescription::answer(answer)?)?;
        assert_eq!(
            offerer.signaling_state(),
            RTCSignalingState::Stable,
            "{profile:?}"
        );
    }
    Ok(())
}

#[test]
fn the_strict_rfc_profile_refuses_an_answer_with_feedback_the_offer_lacked() -> TestResult {
    let (mut offerer, answer) = offer_and_answer_with_extra_feedback(BehaviourProfile::StrictRfc)?;
    let refused =
        offerer.set_remote_description(Instant::now(), RTCSessionDescription::answer(answer)?);
    assert!(
        matches!(
            refused,
            Err(rtci::shared::error::Error::ErrAnswerDoesNotMatchOffer(ref reason))
                if reason.contains("made-up")
        ),
        "{refused:?}"
    );
    assert_eq!(offerer.signaling_state(), RTCSignalingState::HaveLocalOffer);
    Ok(())
}
