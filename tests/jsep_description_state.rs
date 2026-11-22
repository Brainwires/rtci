//! The state checks of `create_offer`, `create_answer`, `set_local_description` and
//! `set_remote_description` (W3C webrtc-pc 4.4.2; RFC 9429 sections 4.1.9, 5.5 and 5.6): each
//! refusal leaves the connection usable for the call that is valid.

mod jsep_common;

use std::time::Instant;

use jsep_common::{TestResult, default_peer, video_track};
use rtc::peer_connection::sdp::RTCSessionDescription;
use rtc::shared::error::Error;
use sansio::Protocol;

#[test]
fn create_answer_needs_a_remote_offer() -> TestResult {
    let mut offerer = default_peer()?;
    offerer.add_track(video_track("offered", 0x0101_0101))?;
    // No remote description at all (RFC 9429 section 4.1.9).
    assert!(matches!(
        offerer.create_answer(None),
        Err(Error::ErrNoRemoteDescription)
    ));
    let offer = offerer.create_offer(None)?;
    offerer.set_local_description(Instant::now(), offer.clone())?;
    assert!(offerer.create_answer(None).is_err(), "have-local-offer");

    let mut answerer = default_peer()?;
    answerer.set_remote_description(Instant::now(), offer)?;
    let answer = answerer.create_answer(None)?;
    answerer.set_local_description(Instant::now(), answer.clone())?;
    offerer.set_remote_description(Instant::now(), answer)?;

    // Stable, with a remote description: InvalidStateError (W3C createAnswer).
    for pc in [&mut offerer, &mut answerer] {
        assert!(matches!(
            pc.create_answer(None),
            Err(Error::ErrIncorrectSignalingState)
        ));
    }
    Ok(())
}

#[test]
fn a_closed_connection_refuses_offers_answers_and_descriptions() -> TestResult {
    let mut offerer = default_peer()?;
    offerer.add_track(video_track("offered", 0x0202_0202))?;
    let offer = offerer.create_offer(None)?;

    let mut pc = default_peer()?;
    pc.add_track(video_track("local", 0x0303_0303))?;
    let own_offer = pc.create_offer(None)?;
    pc.close()?;

    assert!(matches!(
        pc.create_offer(None),
        Err(Error::ErrConnectionClosed)
    ));
    assert!(pc.create_answer(None).is_err());
    assert!(matches!(
        pc.set_local_description(Instant::now(), own_offer),
        Err(Error::ErrConnectionClosed)
    ));
    assert!(matches!(
        pc.set_remote_description(Instant::now(), offer),
        Err(Error::ErrConnectionClosed)
    ));
    assert!(pc.local_description().is_none() && pc.remote_description().is_none());
    Ok(())
}

/// W3C setLocalDescription: an offer that is not `[[LastCreatedOffer]]`, or an answer that is
/// not `[[LastCreatedAnswer]]`, is an InvalidModificationError; an empty SDP stands for the
/// last one created (RFC 9429 section 5.4: a local description is not modified).
#[test]
fn a_local_description_is_the_last_one_created() -> TestResult {
    let mut offerer = default_peer()?;
    offerer.add_track(video_track("offered", 0x0404_0404))?;
    let offer = offerer.create_offer(None)?;

    let edited = offer.sdp.replace("s=-", "s=edited");
    assert_ne!(edited, offer.sdp);
    assert!(matches!(
        offerer.set_local_description(Instant::now(), RTCSessionDescription::offer(edited)?),
        Err(Error::ErrSDPDoesNotMatchOffer)
    ));
    assert!(offerer.local_description().is_none());

    // An offer with no SDP is the offer last created.
    let mut implicit = offer.clone();
    implicit.sdp = String::new();
    offerer.set_local_description(Instant::now(), implicit)?;
    assert_eq!(
        offerer
            .pending_local_description()
            .expect("the offer is pending")
            .sdp
            .lines()
            .find(|l| l.starts_with("o=")),
        offer.sdp.lines().find(|l| l.starts_with("o="))
    );

    let mut answerer = default_peer()?;
    answerer.set_remote_description(Instant::now(), offer)?;
    let answer = answerer.create_answer(None)?;
    let edited = answer.sdp.replace("s=-", "s=edited");
    assert!(matches!(
        answerer.set_local_description(Instant::now(), RTCSessionDescription::answer(edited)?),
        Err(Error::ErrSDPDoesNotMatchAnswer)
    ));
    assert!(answerer.local_description().is_none());

    let mut implicit = answer.clone();
    implicit.sdp = String::new();
    answerer.set_local_description(Instant::now(), implicit)?;
    assert!(answerer.current_local_description().is_some());
    offerer.set_remote_description(Instant::now(), answer)?;
    Ok(())
}
