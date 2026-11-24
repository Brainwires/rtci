//! webrtc-encoded-transform 2.1 / 2.2 `[[useSFrame]]` and the SDP of
//! draft-ietf-avtcore-rtp-sframe-03 section 6 (`a=sframe`): what a transform sets, what a
//! description sets, what offers and answers carry, and the offerer's refusal when the
//! answer leaves SFrame out. Signalling only.

mod jsep_common;

use std::time::Instant;

use jsep_common::{TestResult, default_peer, media_sections, video_track};
use rtci::peer_connection::RTCPeerConnection;
use rtci::peer_connection::sdp::RTCSessionDescription;
use rtci::rtp_transceiver::RTCRtpTransceiverId;
use rtci::shared::error::Error;

fn has_sframe(sdp: &str) -> bool {
    media_sections(sdp)[0].iter().any(|l| l == "a=sframe")
}

fn transceiver_of(pc: &mut RTCPeerConnection) -> RTCRtpTransceiverId {
    pc.get_transceivers().next().expect("a transceiver")
}

/// webrtc-encoded-transform 2.1 / 2.2: `[[useSFrame]]` is undefined until set; an SFrame
/// transform makes it true and the offer carries `a=sframe`, also in a re-offer; the
/// answerer's transceiver takes it from the offer and answers with it; the other kind of
/// transform is then an InvalidModificationError.
#[test]
fn an_sframe_transform_offers_and_answers_sframe() -> TestResult {
    let mut offerer = default_peer()?;
    let mut answerer = default_peer()?;
    let sender = offerer.add_track(video_track("v", 0x0e01_0101))?;
    let id = RTCRtpTransceiverId::from(sender);
    assert_eq!(offerer.rtp_transceiver(id).expect("t").use_sframe(), None);
    offerer
        .rtp_transceiver(id)
        .expect("t")
        .set_transform_use_sframe(true)?;
    assert_eq!(
        offerer.rtp_transceiver(id).expect("t").use_sframe(),
        Some(true)
    );
    assert_eq!(
        offerer
            .rtp_transceiver(id)
            .expect("t")
            .set_transform_use_sframe(false),
        Err(Error::InvalidModificationError)
    );

    let offer = offerer.create_offer(None)?;
    assert!(has_sframe(&offer.sdp), "{}", offer.sdp);
    offerer.set_local_description(Instant::now(), offer.clone())?;
    answerer.set_remote_description(Instant::now(), offer)?;
    let answered = transceiver_of(&mut answerer);
    assert_eq!(
        answerer.rtp_transceiver(answered).expect("t").use_sframe(),
        Some(true),
        "from the media description"
    );
    assert_eq!(
        answerer
            .rtp_transceiver(answered)
            .expect("t")
            .set_transform_use_sframe(false),
        Err(Error::InvalidModificationError)
    );
    let answer = answerer.create_answer(None)?;
    assert!(has_sframe(&answer.sdp), "{}", answer.sdp);
    answerer.set_local_description(Instant::now(), answer.clone())?;
    offerer.set_remote_description(Instant::now(), answer)?;
    assert!(!offerer.rtp_transceiver(id).expect("t").sframe_refused());

    let reoffer = offerer.create_offer(None)?;
    assert!(
        has_sframe(&reoffer.sdp),
        "a re-offer keeps it: {}",
        reoffer.sdp
    );
    Ok(())
}

/// webrtc-encoded-transform 2.1: a transceiver described without a transform has
/// `[[useSFrame]]` false (no `a=sframe`), and an SFrame transform is then refused; an
/// answerer whose transceiver does not use SFrame answers without it.
#[test]
fn without_a_transform_the_transceiver_does_not_use_sframe() -> TestResult {
    let mut offerer = default_peer()?;
    let sender = offerer.add_track(video_track("v", 0x0e02_0101))?;
    let id = RTCRtpTransceiverId::from(sender);
    let offer = offerer.create_offer(None)?;
    assert!(!has_sframe(&offer.sdp));
    assert_eq!(
        offerer.rtp_transceiver(id).expect("t").use_sframe(),
        Some(false)
    );
    assert_eq!(
        offerer
            .rtp_transceiver(id)
            .expect("t")
            .set_transform_use_sframe(true),
        Err(Error::InvalidModificationError)
    );
    offerer
        .rtp_transceiver(id)
        .expect("t")
        .set_transform_use_sframe(false)?;
    Ok(())
}

/// draft-ietf-avtcore-rtp-sframe-03 section 6: SFrame offered and answered without
/// `a=sframe`: the offerer sends no media (no unencrypted fallback).
#[test]
fn an_answer_without_sframe_stops_the_offerers_media() -> TestResult {
    let mut offerer = default_peer()?;
    let mut answerer = default_peer()?;
    let sender = offerer.add_track(video_track("v", 0x0e03_0101))?;
    let id = RTCRtpTransceiverId::from(sender);
    offerer
        .rtp_transceiver(id)
        .expect("t")
        .set_transform_use_sframe(true)?;
    let offer = offerer.create_offer(None)?;
    offerer.set_local_description(Instant::now(), offer.clone())?;
    answerer.set_remote_description(Instant::now(), offer)?;
    let answer = answerer.create_answer(None)?;
    answerer.set_local_description(Instant::now(), answer.clone())?;
    let stripped = answer.sdp.replace("a=sframe\r\n", "");
    assert_ne!(stripped, answer.sdp);
    offerer.set_remote_description(Instant::now(), RTCSessionDescription::answer(stripped)?)?;
    assert!(offerer.rtp_transceiver(id).expect("t").sframe_refused());
    let refused = offerer.rtp_sender(sender).expect("sender").write_rtp(
        Instant::now(),
        rtci::rtp::Packet {
            header: rtci::rtp::header::Header {
                version: 2,
                ssrc: 0x0e03_0101,
                ..Default::default()
            },
            payload: bytes::Bytes::from_static(&[0x80, 1, 2, 3]),
        },
    );
    assert_eq!(refused, Err(Error::ErrSFrameRefused));
    Ok(())
}

/// draft-ietf-avtcore-rtp-sframe-03 section 6: "An answerer that requires SFrame MUST reject
/// m-sections that do not have the "a=sframe" SDP attribute": a transceiver whose SFrame
/// transform is set answers an offer without `a=sframe` with its section rejected (port 0).
#[test]
fn an_answerer_that_requires_sframe_rejects_a_section_without_it() -> TestResult {
    let mut offerer = default_peer()?;
    let mut answerer = default_peer()?;
    offerer.add_track(video_track("v", 0x0e04_0101))?;
    let sender = answerer.add_track(video_track("w", 0x0e04_0201))?;
    answerer
        .rtp_transceiver(RTCRtpTransceiverId::from(sender))
        .expect("t")
        .set_transform_use_sframe(true)?;
    let offer = offerer.create_offer(None)?;
    assert!(!has_sframe(&offer.sdp));
    offerer.set_local_description(Instant::now(), offer.clone())?;
    answerer.set_remote_description(Instant::now(), offer)?;
    let answer = answerer.create_answer(None)?.sdp;
    let section = &media_sections(&answer)[0];
    assert!(section[0].starts_with("m=video 0 "), "rejected: {answer}");
    assert!(!has_sframe(&answer));
    Ok(())
}

/// draft-ietf-avtcore-rtp-sframe-03 section 6: an offerer whose `a=sframe` the answer left
/// out "SHOULD close it in subsequent offers": the next offer rejects the section.
#[test]
fn a_refused_sframe_section_is_closed_in_the_next_offer() -> TestResult {
    let mut offerer = default_peer()?;
    let mut answerer = default_peer()?;
    let sender = offerer.add_track(video_track("v", 0x0e05_0101))?;
    let id = RTCRtpTransceiverId::from(sender);
    offerer
        .rtp_transceiver(id)
        .expect("t")
        .set_transform_use_sframe(true)?;
    let offer = offerer.create_offer(None)?;
    offerer.set_local_description(Instant::now(), offer.clone())?;
    answerer.set_remote_description(Instant::now(), offer)?;
    let answer = answerer.create_answer(None)?;
    answerer.set_local_description(Instant::now(), answer.clone())?;
    let stripped = answer.sdp.replace("a=sframe\r\n", "");
    offerer.set_remote_description(Instant::now(), RTCSessionDescription::answer(stripped)?)?;
    assert!(offerer.rtp_transceiver(id).expect("t").sframe_refused());
    let reoffer = offerer.create_offer(None)?.sdp;
    let section = &media_sections(&reoffer)[0];
    assert!(section[0].starts_with("m=video 0 "), "closed: {reoffer}");
    Ok(())
}
