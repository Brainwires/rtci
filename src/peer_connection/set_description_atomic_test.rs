//! A description is checked in full before any of it is applied (RFC 9429 sections 5.9 and
//! 5.10: "the session state MUST be restored to its state before"; W3C webrtc-pc "set a
//! session description"): one that is refused changes neither the signaling state, the pending
//! and current descriptions, the transceivers, the negotiated codecs, the staged ICE restart,
//! nor the queued events.

use std::time::Instant;

use crate::peer_connection::configuration::media_engine::MediaEngine;
use crate::peer_connection::configuration::offer_answer_options::RTCOfferOptions;
use crate::peer_connection::event::RTCPeerConnectionEvent;
use crate::peer_connection::sdp::RTCSessionDescription;
use crate::peer_connection::sdp::sdp_type::RTCSdpType;
use crate::peer_connection::state::RTCSignalingState;
use crate::peer_connection::{RTCPeerConnection, RTCPeerConnectionBuilder};
use crate::rtp_transceiver::rtp_sender::RtpCodecKind;
use crate::rtp_transceiver::{RTCRtpTransceiverDirection, RTCRtpTransceiverInit};
use shared::error::{Error, Result};

const SESSION: &str = "v=0\r\n\
o=- 4215775240449105457 2 IN IP4 127.0.0.1\r\n\
s=-\r\n\
t=0 0\r\n";

const ICE: &str = "a=ice-ufrag:4ZcD\r\n\
a=ice-pwd:2/1muCWoOi3uLifh0NuRHlkwz\r\n";

const FINGERPRINT: &str = "a=fingerprint:sha-256 F2:1C:F2:9E:B4:BE:58:19:C9:48:1A:D9:C4:A7:5D:5A:1F:61:7C:17:6B:07:8E:39:A2:E2:B2:BB:BF:4B:D2:16\r\n";

/// A VP8 video section with the given mid, transport lines and extra lines.
fn video(mid: &str, transport: &str, extra: &str) -> String {
    format!(
        "m=video 9 UDP/TLS/RTP/SAVPF 96\r\n\
c=IN IP4 0.0.0.0\r\n\
{transport}\
a=setup:actpass\r\n\
a=mid:{mid}\r\n\
a=sendrecv\r\n\
a=rtcp-mux\r\n\
a=rtpmap:96 VP8/90000\r\n\
{extra}"
    )
}

fn peer() -> Result<RTCPeerConnection> {
    let mut media_engine = MediaEngine::default();
    media_engine.register_default_codecs()?;
    RTCPeerConnectionBuilder::new()
        .with_media_engine(media_engine)
        .build(Instant::now())
}

fn description(sdp_type: RTCSdpType, sdp: &str) -> RTCSessionDescription {
    RTCSessionDescription {
        sdp_type,
        sdp: sdp.to_owned(),
        parsed: None,
    }
}

fn rollback() -> RTCSessionDescription {
    description(RTCSdpType::Rollback, "")
}

fn signaling_events(pc: &RTCPeerConnection) -> Vec<RTCSignalingState> {
    pc.pipeline_context
        .event_outs
        .iter()
        .filter_map(|event| match event {
            RTCPeerConnectionEvent::OnSignalingStateChangeEvent(state) => Some(*state),
            _ => None,
        })
        .collect()
}

/// The connection is as `RTCPeerConnectionBuilder::build` left it.
fn assert_untouched(pc: &RTCPeerConnection, why: &str) {
    assert_eq!(pc.signaling_state, RTCSignalingState::Stable, "{why}");
    assert!(pc.remote_description().is_none(), "{why}");
    assert!(pc.pending_remote_description().is_none(), "{why}");
    assert!(pc.rtp_transceivers.is_empty(), "{why}: transceivers");
    assert!(pc.pipeline_context.event_outs.is_empty(), "{why}: events");
    assert!(
        !pc.media_engine.negotiated_video && pc.media_engine.negotiated_video_codecs.is_empty(),
        "{why}: negotiated codecs"
    );
    assert_eq!(pc.can_trickle_ice_candidates(), None, "{why}");
}

#[test]
fn a_remote_offer_without_a_fingerprint_changes_nothing() -> Result<()> {
    let mut pc = peer()?;
    let offer = format!("{SESSION}a=group:BUNDLE 0\r\n{}", video("0", ICE, ""));
    let refused = pc.set_remote_description(Instant::now(), description(RTCSdpType::Offer, &offer));
    assert!(
        matches!(refused, Err(Error::ErrSessionDescriptionNoFingerprint)),
        "{refused:?}"
    );
    assert_untouched(&pc, "no fingerprint");

    // The same offer with its fingerprint applies.
    let transport = format!("{ICE}{FINGERPRINT}");
    let offer = format!(
        "{SESSION}a=group:BUNDLE 0\r\n{}",
        video("0", &transport, "")
    );
    pc.set_remote_description(Instant::now(), description(RTCSdpType::Offer, &offer))?;
    assert_eq!(pc.signaling_state, RTCSignalingState::HaveRemoteOffer);
    assert_eq!(pc.rtp_transceivers.len(), 1);
    Ok(())
}

#[test]
fn a_remote_offer_with_conflicting_ice_credentials_changes_nothing() -> Result<()> {
    let mut pc = peer()?;
    // Two sections outside any BUNDLE group, each with its own credentials: two transports,
    // which this engine does not run.
    let first = format!("{ICE}{FINGERPRINT}");
    let second =
        format!("a=ice-ufrag:Zz9x\r\na=ice-pwd:9/9muCWoOi3uLifh0NuRHlkwz\r\n{FINGERPRINT}");
    let offer = format!(
        "{SESSION}{}{}",
        video("0", &first, ""),
        video("1", &second, "")
    );
    let refused = pc.set_remote_description(Instant::now(), description(RTCSdpType::Offer, &offer));
    assert!(
        matches!(
            refused,
            Err(Error::ErrSessionDescriptionConflictingIceUfrag)
        ),
        "{refused:?}"
    );
    assert_untouched(&pc, "conflicting ufrag");
    Ok(())
}

#[test]
fn a_remote_offer_with_a_malformed_candidate_changes_nothing() -> Result<()> {
    let mut pc = peer()?;
    let transport = format!("{ICE}{FINGERPRINT}");
    let offer = format!(
        "{SESSION}a=group:BUNDLE 0\r\n{}",
        video("0", &transport, "a=candidate:not a candidate\r\n")
    );
    let refused = pc.set_remote_description(Instant::now(), description(RTCSdpType::Offer, &offer));
    assert!(refused.is_err(), "a malformed a=candidate is refused");
    assert_untouched(&pc, "malformed candidate");
    Ok(())
}

/// The offerer of an audio (recvonly) and a video (sendrecv) section with its offer applied,
/// and the answer a default peer gives.
fn pending_offer() -> Result<(RTCPeerConnection, String)> {
    let mut offerer = peer()?;
    offerer.add_transceiver_from_kind(
        RtpCodecKind::Audio,
        Some(RTCRtpTransceiverInit {
            direction: RTCRtpTransceiverDirection::Recvonly,
            streams: vec![],
            send_encodings: vec![],
        }),
    )?;
    offerer.add_transceiver_from_kind(RtpCodecKind::Video, None)?;
    let offer = offerer.create_offer(None)?;
    offerer.set_local_description(Instant::now(), offer.clone())?;

    let mut answerer = peer()?;
    answerer.set_remote_description(Instant::now(), offer)?;
    let answer = answerer.create_answer(None)?;
    Ok((offerer, answer.sdp))
}

/// `sdp` with `edit` applied to the lines of media section `index`.
fn edit_section(sdp: &str, index: usize, edit: impl Fn(&mut Vec<String>)) -> String {
    let mut session: Vec<String> = vec![];
    let mut sections: Vec<Vec<String>> = vec![];
    for line in sdp.lines() {
        if line.starts_with("m=") {
            sections.push(vec![line.to_owned()]);
        } else if let Some(section) = sections.last_mut() {
            section.push(line.to_owned());
        } else {
            session.push(line.to_owned());
        }
    }
    edit(&mut sections[index]);
    let mut out = session;
    out.extend(sections.into_iter().flatten());
    out.join("\r\n") + "\r\n"
}

fn is_direction(line: &str) -> bool {
    matches!(
        line,
        "a=sendrecv" | "a=sendonly" | "a=recvonly" | "a=inactive"
    )
}

#[test]
fn a_remote_answer_that_does_not_answer_the_offer_changes_nothing() -> Result<()> {
    let (mut offerer, answer) = pending_offer()?;
    assert!(
        answer.contains("m=audio") && answer.contains("m=video"),
        "{answer}"
    );
    let events = offerer.pipeline_context.event_outs.len();
    let negotiated = (
        offerer.media_engine.negotiated_audio,
        offerer.media_engine.negotiated_video,
    );

    let video_payload_type = answer
        .lines()
        .find(|l| l.starts_with("m=video"))
        .and_then(|l| l.split_whitespace().nth(3))
        .expect("the answer accepts a video format")
        .to_owned();
    let cases: Vec<(&str, String)> = vec![
        (
            "one m= section fewer than the offer (RFC 3264 section 6)",
            answer[..answer.find("m=video").expect("video")].to_owned(),
        ),
        (
            "media types in another order (RFC 3264 section 6)",
            answer
                .replace("m=audio", "m=AUDIO")
                .replace("m=video", "m=audio")
                .replace("m=AUDIO", "m=video"),
        ),
        (
            "another proto (RFC 9429 section 5.8.3)",
            edit_section(&answer, 0, |lines| {
                lines[0] = lines[0].replace("UDP/TLS/RTP/SAVPF", "RTP/SAVPF");
            }),
        ),
        (
            "another mid (RFC 5888 section 9.1)",
            edit_section(&answer, 1, |lines| {
                for line in lines.iter_mut().filter(|l| l.starts_with("a=mid:")) {
                    *line = "a=mid:other".to_owned();
                }
            }),
        ),
        (
            "recvonly answered recvonly (RFC 3264 section 6.1)",
            edit_section(&answer, 0, |lines| {
                lines.retain(|l| !is_direction(l));
                lines.push("a=recvonly".to_owned());
            }),
        ),
        (
            "feedback the offer did not have (RFC 4585 section 4.2)",
            edit_section(&answer, 1, |lines| {
                lines.push(format!("a=rtcp-fb:{video_payload_type} made-up"));
            }),
        ),
        (
            "a BUNDLE group naming a section the offer did not bundle (RFC 9143 section 7.4)",
            answer.replace("a=group:BUNDLE ", "a=group:BUNDLE other "),
        ),
    ];

    for (why, refused_answer) in cases {
        assert_ne!(refused_answer, answer, "{why}: the answer was edited");
        let refused = offerer.set_remote_description(
            Instant::now(),
            description(RTCSdpType::Answer, &refused_answer),
        );
        let error = refused.expect_err(why);
        assert!(
            error
                .to_string()
                .starts_with("the answer does not match the offer"),
            "{why}: {error}"
        );
        assert_eq!(
            offerer.signaling_state,
            RTCSignalingState::HaveLocalOffer,
            "{why}"
        );
        assert!(offerer.pending_local_description.is_some(), "{why}");
        assert!(offerer.current_local_description.is_none(), "{why}");
        assert!(offerer.remote_description().is_none(), "{why}");
        assert_eq!(offerer.pipeline_context.event_outs.len(), events, "{why}");
        assert_eq!(
            (
                offerer.media_engine.negotiated_audio,
                offerer.media_engine.negotiated_video
            ),
            negotiated,
            "{why}"
        );
        assert!(
            offerer.rtp_transceivers.iter().all(|t| !t.stopped()
                && t.current_direction() == RTCRtpTransceiverDirection::Unspecified),
            "{why}: transceivers"
        );
    }

    // The offer is still pending: the answer itself applies.
    offerer.set_remote_description(Instant::now(), description(RTCSdpType::Answer, &answer))?;
    assert_eq!(offerer.signaling_state, RTCSignalingState::Stable);
    Ok(())
}

#[test]
fn a_refused_local_description_applies_no_staged_ice_restart() -> Result<()> {
    let mut pc = peer()?;
    pc.add_transceiver_from_kind(RtpCodecKind::Video, None)?;
    let before = pc.ice_transport().get_local_parameters()?;

    let offer = pc.create_offer(Some(RTCOfferOptions { ice_restart: true }))?;
    assert!(pc.ice_transport().has_pending_restart());

    // Not the offer `create_offer` made (W3C setLocalDescription: InvalidModificationError).
    let refused = pc.set_local_description(
        Instant::now(),
        description(RTCSdpType::Offer, &format!("{}a=other\r\n", offer.sdp)),
    );
    assert!(
        matches!(refused, Err(Error::ErrSDPDoesNotMatchOffer)),
        "{refused:?}"
    );
    assert!(
        pc.ice_transport().has_pending_restart(),
        "the restart stays staged: the refused description applied nothing"
    );
    assert_eq!(pc.signaling_state, RTCSignalingState::Stable);

    // The offer itself applies it.
    pc.set_local_description(Instant::now(), offer)?;
    assert!(!pc.ice_transport().has_pending_restart());
    let after = pc.ice_transport().get_local_parameters()?;
    assert_ne!(before.username_fragment, after.username_fragment);
    Ok(())
}

#[test]
fn a_rollback_applies_no_staged_ice_restart() -> Result<()> {
    let mut pc = peer()?;
    pc.add_transceiver_from_kind(RtpCodecKind::Video, None)?;
    let offer = pc.create_offer(None)?;
    pc.set_local_description(Instant::now(), offer)?;

    // A second offer, with a restart, created while the first is pending and then abandoned.
    pc.create_offer(Some(RTCOfferOptions { ice_restart: true }))?;
    assert!(pc.ice_transport().has_pending_restart());
    pc.set_local_description(Instant::now(), rollback())?;
    assert_eq!(pc.signaling_state, RTCSignalingState::Stable);
    assert!(
        pc.ice_transport().has_pending_restart(),
        "a rollback applies no description, so no restart either"
    );
    Ok(())
}

#[test]
fn create_offer_needs_the_stable_or_have_local_offer_state() -> Result<()> {
    let mut offerer = peer()?;
    offerer.add_transceiver_from_kind(RtpCodecKind::Video, None)?;
    let offer = offerer.create_offer(None)?;
    offerer.set_local_description(Instant::now(), offer.clone())?;
    // have-local-offer: another offer may be created.
    offerer.create_offer(None)?;

    let mut answerer = peer()?;
    answerer.set_remote_description(Instant::now(), offer)?;
    // A transceiver of the application's with no m= section yet.
    answerer.add_transceiver_from_kind(RtpCodecKind::Audio, None)?;
    answerer.restart_ice();

    // have-remote-offer.
    let refused = answerer.create_offer(None);
    assert!(
        matches!(refused, Err(Error::ErrIncorrectSignalingState)),
        "{refused:?}"
    );
    assert!(
        answerer
            .rtp_transceivers
            .iter()
            .any(|t| t.kind() == RtpCodecKind::Audio && t.mid().is_none()),
        "the refused createOffer gave no transceiver a mid"
    );
    assert!(
        answerer.ice_restart_requested.is_some() && !answerer.ice_transport().has_pending_restart(),
        "the refused createOffer kept the restart request and staged nothing"
    );

    // have-local-pranswer.
    let answer = answerer.create_answer(None)?;
    answerer.set_local_description(
        Instant::now(),
        description(RTCSdpType::Pranswer, &answer.sdp),
    )?;
    assert_eq!(
        answerer.signaling_state,
        RTCSignalingState::HaveLocalPranswer
    );
    assert!(matches!(
        answerer.create_offer(None),
        Err(Error::ErrIncorrectSignalingState)
    ));

    // have-remote-pranswer.
    offerer.set_remote_description(
        Instant::now(),
        description(RTCSdpType::Pranswer, &answer.sdp),
    )?;
    assert_eq!(
        offerer.signaling_state,
        RTCSignalingState::HaveRemotePranswer
    );
    assert!(matches!(
        offerer.create_offer(None),
        Err(Error::ErrIncorrectSignalingState)
    ));
    Ok(())
}

#[test]
fn signalingstatechange_fires_only_when_the_state_changes() -> Result<()> {
    let mut offerer = peer()?;
    offerer.add_transceiver_from_kind(RtpCodecKind::Video, None)?;
    let offer = offerer.create_offer(None)?;
    offerer.set_local_description(Instant::now(), offer.clone())?;
    // The same offer applied again: have-local-offer stays have-local-offer.
    offerer.set_local_description(Instant::now(), offer.clone())?;
    assert_eq!(
        signaling_events(&offerer),
        vec![RTCSignalingState::HaveLocalOffer]
    );

    let mut answerer = peer()?;
    answerer.set_remote_description(Instant::now(), offer.clone())?;
    answerer.set_remote_description(Instant::now(), offer)?;
    let answer = answerer.create_answer(None)?;
    let pranswer = description(RTCSdpType::Pranswer, &answer.sdp);
    answerer.set_local_description(Instant::now(), pranswer.clone())?;
    answerer.set_local_description(Instant::now(), pranswer.clone())?;
    assert_eq!(
        signaling_events(&answerer),
        vec![
            RTCSignalingState::HaveRemoteOffer,
            RTCSignalingState::HaveLocalPranswer
        ]
    );

    offerer.set_remote_description(Instant::now(), pranswer.clone())?;
    offerer.set_remote_description(Instant::now(), pranswer)?;
    offerer.set_remote_description(Instant::now(), description(RTCSdpType::Answer, &answer.sdp))?;
    assert_eq!(
        signaling_events(&offerer),
        vec![
            RTCSignalingState::HaveLocalOffer,
            RTCSignalingState::HaveRemotePranswer,
            RTCSignalingState::Stable
        ]
    );
    Ok(())
}

#[test]
fn a_rollback_is_refused_outside_the_offer_states() -> Result<()> {
    // stable
    let mut offerer = peer()?;
    for result in [
        offerer.set_local_description(Instant::now(), rollback()),
        offerer.set_remote_description(Instant::now(), rollback()),
    ] {
        assert!(
            matches!(result, Err(Error::ErrSignalingStateCannotRollback)),
            "{result:?}"
        );
    }
    assert_eq!(offerer.signaling_state, RTCSignalingState::Stable);

    offerer.add_transceiver_from_kind(RtpCodecKind::Video, None)?;
    let offer = offerer.create_offer(None)?;
    offerer.set_local_description(Instant::now(), offer.clone())?;
    let mut answerer = peer()?;
    answerer.set_remote_description(Instant::now(), offer)?;
    let answer = answerer.create_answer(None)?;
    let pranswer = description(RTCSdpType::Pranswer, &answer.sdp);

    // have-local-pranswer
    answerer.set_local_description(Instant::now(), pranswer.clone())?;
    for result in [
        answerer.set_local_description(Instant::now(), rollback()),
        answerer.set_remote_description(Instant::now(), rollback()),
    ] {
        assert!(
            matches!(
                result,
                Err(Error::ErrSignalingStateProposedTransitionInvalid(_))
            ),
            "{result:?}"
        );
    }
    assert_eq!(
        answerer.signaling_state,
        RTCSignalingState::HaveLocalPranswer
    );
    assert_eq!(answerer.rtp_transceivers.len(), 1);

    // have-remote-pranswer
    offerer.set_remote_description(Instant::now(), pranswer)?;
    for result in [
        offerer.set_local_description(Instant::now(), rollback()),
        offerer.set_remote_description(Instant::now(), rollback()),
    ] {
        assert!(
            matches!(
                result,
                Err(Error::ErrSignalingStateProposedTransitionInvalid(_))
            ),
            "{result:?}"
        );
    }
    assert_eq!(
        offerer.signaling_state,
        RTCSignalingState::HaveRemotePranswer
    );
    assert!(offerer.rtp_transceivers[0].mid().is_some());
    Ok(())
}

#[test]
fn an_answer_resets_the_last_created_offer_and_answer() -> Result<()> {
    let mut offerer = peer()?;
    offerer.add_transceiver_from_kind(RtpCodecKind::Video, None)?;
    let offer = offerer.create_offer(None)?;
    offerer.set_local_description(Instant::now(), offer.clone())?;
    let mut answerer = peer()?;
    answerer.set_remote_description(Instant::now(), offer.clone())?;
    let answer = answerer.create_answer(None)?;
    answerer.set_local_description(Instant::now(), answer.clone())?;
    offerer.set_remote_description(Instant::now(), answer)?;

    // W3C "set a session description": an answer sets [[LastCreatedOffer]] and
    // [[LastCreatedAnswer]] to "", so the offer of the finished exchange is not one
    // `create_offer` made for the next: InvalidModificationError.
    assert!(offerer.last_offer.is_empty() && answerer.last_answer.is_empty());
    let refused = offerer.set_local_description(Instant::now(), offer);
    assert!(
        matches!(refused, Err(Error::ErrSDPDoesNotMatchOffer)),
        "{refused:?}"
    );
    assert_eq!(offerer.signaling_state, RTCSignalingState::Stable);
    Ok(())
}
