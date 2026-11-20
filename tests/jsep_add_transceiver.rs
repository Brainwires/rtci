//! W3C webrtc 5.1 `addTransceiver` takes any direction, and a sending direction needs no
//! `sendEncodings` (the sender then has one encoding); a remote track's label is
//! `"remote " + kind` (4.4.1.6, create an RTCRtpReceiver). The engine used to refuse
//! `inactive` and a send direction without encodings, and to label remote tracks
//! `remote-<kind>-<random>`.

mod jsep_common;

use jsep_common::{TestResult, default_peer, exchange, media_sections, video_track};
use rtc::rtp_transceiver::rtp_sender::RtpCodecKind;
use rtc::rtp_transceiver::{RTCRtpReceiverId, RTCRtpTransceiverDirection, RTCRtpTransceiverInit};

#[test]
fn add_transceiver_takes_inactive() -> TestResult {
    let mut pc = default_peer()?;
    let id = pc.add_transceiver_from_kind(
        RtpCodecKind::Video,
        Some(RTCRtpTransceiverInit {
            direction: RTCRtpTransceiverDirection::Inactive,
            streams: vec![],
            send_encodings: vec![],
        }),
    )?;
    assert_eq!(
        pc.rtp_transceiver(id).expect("transceiver").direction(),
        RTCRtpTransceiverDirection::Inactive
    );
    let offer = pc.create_offer(None)?;
    let section = &media_sections(&offer.sdp)[0];
    assert!(section.iter().any(|l| l == "a=inactive"), "{}", offer.sdp);
    Ok(())
}

#[test]
fn a_send_direction_without_send_encodings_gets_one_encoding() -> TestResult {
    let mut pc = default_peer()?;
    let id = pc.add_transceiver_from_kind(
        RtpCodecKind::Video,
        Some(RTCRtpTransceiverInit {
            direction: RTCRtpTransceiverDirection::Sendonly,
            streams: vec![],
            send_encodings: vec![],
        }),
    )?;
    let transceiver = pc.rtp_transceiver(id).expect("transceiver");
    assert_eq!(
        transceiver.direction(),
        RTCRtpTransceiverDirection::Sendonly
    );
    let sender = transceiver
        .sender()
        .expect("a sending transceiver has a sender");
    assert_eq!(
        pc.rtp_sender(sender)
            .expect("sender")
            .get_parameters()
            .encodings
            .len(),
        1
    );

    let offer = pc.create_offer(None)?;
    let section = &media_sections(&offer.sdp)[0];
    assert!(section.iter().any(|l| l == "a=sendonly"), "{}", offer.sdp);
    assert!(
        section.iter().any(|l| l.starts_with("a=ssrc:")),
        "the engine gave the encoding an SSRC:\n{}",
        offer.sdp
    );
    Ok(())
}

#[test]
fn a_remote_track_is_labelled_remote_and_its_kind() -> TestResult {
    let mut offerer = default_peer()?;
    let mut answerer = default_peer()?;
    offerer.add_track(video_track("video", 0x0707_0707))?;
    exchange(&mut offerer, &mut answerer)?;

    let id = answerer
        .get_transceivers()
        .next()
        .expect("the offer created a transceiver");
    let label = answerer
        .rtp_receiver(RTCRtpReceiverId::from(id))
        .expect("receiver")
        .track()
        .label()
        .clone();
    assert_eq!(label, "remote video");
    Ok(())
}
