//! A transceiver created while applying a remote offer has a sender without a track; W3C `addTrack` may
//! reuse it, and the application may make it send with a direction change and
//! `replaceTrack`. Both need a real sender (SSRCs in the answer). Only `addTrack` keeps the
//! transceiver through a rollback of that offer (W3C 4.4.1.6, RFC 9429 section 5.7).

mod jsep_common;

use std::time::Instant;

use jsep_common::{TestResult, default_peer, media_sections, video_track};
use rtci::peer_connection::RTCPeerConnection;
use rtci::peer_connection::sdp::RTCSessionDescription;
use rtci::rtp_transceiver::RTCRtpTransceiverDirection;
use rtci::rtp_transceiver::RTCRtpTransceiverId;

const ANSWER_SSRC: u32 = 0x0a0b_0c0d;

/// An answerer that applied a sendrecv video offer; returns it and the transceiver the offer
/// created.
fn after_remote_offer()
-> Result<(RTCPeerConnection, RTCRtpTransceiverId), Box<dyn std::error::Error>> {
    let mut offerer = default_peer()?;
    offerer.add_track(video_track("offered", 0x0101_0101))?;
    let offer = offerer.create_offer(None)?;

    let mut answerer = default_peer()?;
    answerer.set_remote_description(Instant::now(), offer)?;
    let id = answerer
        .get_transceivers()
        .next()
        .expect("the offer created a transceiver");
    assert!(
        answerer
            .rtp_sender(id.into())
            .expect("every transceiver has a sender")
            .track()
            .is_none(),
        "a transceiver a remote offer creates has a sender without a track"
    );
    Ok((answerer, id))
}

#[test]
fn add_track_to_a_remote_offers_transceiver_sends_in_the_answer() -> TestResult {
    let (mut answerer, id) = after_remote_offer()?;
    answerer.add_track_to_transceiver(id, video_track("answered", ANSWER_SSRC))?;

    let transceiver = answerer.rtp_transceiver(id).expect("transceiver");
    assert!(transceiver.sender().is_some());
    assert_eq!(
        transceiver.direction(),
        RTCRtpTransceiverDirection::Sendrecv
    );

    let answer = answerer.create_answer(None)?;
    let section = &media_sections(&answer.sdp)[0];
    assert!(section.iter().any(|l| l == "a=sendrecv"), "{}", answer.sdp);
    assert!(
        section
            .iter()
            .any(|l| l.starts_with(&format!("a=ssrc:{ANSWER_SSRC} "))),
        "the answer names the new sender's SSRC:\n{}",
        answer.sdp
    );
    Ok(())
}

#[test]
fn a_transceiver_add_track_touched_survives_a_rollback() -> TestResult {
    let (mut answerer, id) = after_remote_offer()?;
    answerer.add_track_to_transceiver(id, video_track("answered", ANSWER_SSRC))?;
    answerer.set_remote_description(Instant::now(), RTCSessionDescription::rollback(None)?)?;
    assert_eq!(answerer.get_transceivers().count(), 1);
    Ok(())
}

#[test]
fn ensure_transceiver_sender_changes_neither_direction_nor_rollback() -> TestResult {
    let (mut answerer, id) = after_remote_offer()?;
    let direction = answerer
        .rtp_transceiver(id)
        .expect("transceiver")
        .direction();
    answerer.ensure_transceiver_sender(id)?;

    let transceiver = answerer.rtp_transceiver(id).expect("transceiver");
    assert!(transceiver.sender().is_some(), "a placeholder sender");
    assert_eq!(transceiver.direction(), direction);

    // Not `addTrack`: rolling the offer back removes the transceiver it created.
    answerer.set_remote_description(Instant::now(), RTCSessionDescription::rollback(None)?)?;
    assert_eq!(answerer.get_transceivers().count(), 0);
    Ok(())
}
