//! W3C webrtc 5.1 `addTransceiver` takes any direction, and a sending direction needs no
//! `sendEncodings` (the sender then has one encoding); a remote track's label is
//! `"remote " + kind` (4.4.1.6, create an RTCRtpReceiver). The engine used to refuse
//! `inactive` and a send direction without encodings, and to label remote tracks
//! `remote-<kind>-<random>`.

mod jsep_common;

use jsep_common::{TestResult, default_peer, exchange, media_sections, video_track};
use rtci::rtp_transceiver::rtp_sender::{RTCRtpEncodingParameters, RtpCodecKind};
use rtci::rtp_transceiver::{RTCRtpReceiverId, RTCRtpTransceiverDirection, RTCRtpTransceiverInit};

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

/// RTX is the implementation's choice (W3C `sendEncodings` has no `rtx` member): encodings the
/// application gave get a repair flow like the ones derived from a track, and the offer groups
/// it with its media SSRC (`a=ssrc-group:FID`, RFC 4588 / RFC 5576).
#[test]
fn explicit_send_encodings_get_an_rtx_flow() -> TestResult {
    let mut pc = default_peer()?;
    let id = pc.add_transceiver_from_track(
        video_track("explicit", 0x0e0f_1001),
        Some(RTCRtpTransceiverInit {
            direction: RTCRtpTransceiverDirection::Sendonly,
            streams: vec![],
            send_encodings: vec![RTCRtpEncodingParameters {
                active: true,
                ..Default::default()
            }],
        }),
    )?;
    let sender = pc
        .rtp_transceiver(id)
        .expect("transceiver")
        .sender()
        .expect("a sending transceiver has a sender");
    let (ssrc, rtx_ssrc) = {
        let mut sender = pc.rtp_sender(sender).expect("sender");
        let coding = &sender.get_parameters().encodings[0].rtp_coding_parameters;
        (
            coding.ssrc.expect("an SSRC"),
            coding.rtx.as_ref().map(|rtx| rtx.ssrc),
        )
    };
    let rtx_ssrc = rtx_ssrc.expect("the default video codecs carry RTX");

    let offer = pc.create_offer(None)?;
    let section = &media_sections(&offer.sdp)[0];
    assert!(
        section
            .iter()
            .any(|l| l == &format!("a=ssrc-group:FID {ssrc} {rtx_ssrc}")),
        "{}",
        offer.sdp
    );
    Ok(())
}

/// Without an RTX codec for the kind (the default audio codecs have none) there is no repair
/// flow to give an explicit encoding.
#[test]
fn explicit_send_encodings_get_no_rtx_flow_without_an_rtx_codec() -> TestResult {
    let mut pc = default_peer()?;
    let id = pc.add_transceiver_from_kind(
        RtpCodecKind::Audio,
        Some(RTCRtpTransceiverInit {
            direction: RTCRtpTransceiverDirection::Sendonly,
            streams: vec![],
            send_encodings: vec![RTCRtpEncodingParameters {
                active: true,
                ..Default::default()
            }],
        }),
    )?;
    let sender = pc
        .rtp_transceiver(id)
        .expect("transceiver")
        .sender()
        .expect("a sending transceiver has a sender");
    let mut sender = pc.rtp_sender(sender).expect("sender");
    assert!(
        sender.get_parameters().encodings[0]
            .rtp_coding_parameters
            .rtx
            .is_none()
    );
    Ok(())
}
