//! `RTCRtpSender.setParameters` runs the W3C webrtc 5.2 validation steps, and an encoding's
//! `active` reaches the SDP as a paused rid (RFC 8853, Section 5.3). It used to check only the
//! encoding count, the rids and `scaleResolutionDownBy`.

mod jsep_common;

use jsep_common::{TestResult, default_peer, video_track, vp8};
use rtc::media_stream::MediaStreamTrack;
use rtc::rtp_transceiver::RTCRtpTransceiverId;
use rtc::rtp_transceiver::rtp_sender::{
    RTCRtpCodingParameters, RTCRtpEncodingParameters, RtpCodecKind,
};
use rtc::shared::error::Error;

#[test]
fn set_parameters_needs_the_last_returned_parameters() -> TestResult {
    let mut pc = default_peer()?;
    let sender = pc.add_track(video_track("video", 0x0303_0001))?;
    let mut s = pc.rtp_sender(sender).expect("sender");

    let params = s.get_parameters().clone();
    s.set_parameters(params.clone(), None)?;
    // The parameters a set_parameters consumed are not the last returned any more.
    assert_eq!(
        s.set_parameters(params, None).unwrap_err(),
        Error::InvalidStateError
    );
    Ok(())
}

#[test]
fn set_parameters_checks_the_transaction_id() -> TestResult {
    let mut pc = default_peer()?;
    let sender = pc.add_track(video_track("video", 0x0303_0002))?;
    let mut s = pc.rtp_sender(sender).expect("sender");

    let mut params = s.get_parameters().clone();
    params.transaction_id.push('x');
    assert_eq!(
        s.set_parameters(params, None).unwrap_err(),
        Error::InvalidModificationError
    );
    Ok(())
}

#[test]
fn set_parameters_refuses_a_changed_read_only_member() -> TestResult {
    let mut pc = default_peer()?;
    let sender = pc.add_track(video_track("video", 0x0303_0003))?;
    let mut s = pc.rtp_sender(sender).expect("sender");

    let mut params = s.get_parameters().clone();
    params.rtp_parameters.rtcp.reduced_size = !params.rtp_parameters.rtcp.reduced_size;
    assert_eq!(
        s.set_parameters(params, None).unwrap_err(),
        Error::InvalidModificationError
    );
    Ok(())
}

#[test]
fn set_parameters_refuses_a_negative_max_framerate() -> TestResult {
    let mut pc = default_peer()?;
    let sender = pc.add_track(video_track("video", 0x0303_0004))?;
    let mut s = pc.rtp_sender(sender).expect("sender");

    let mut params = s.get_parameters().clone();
    params.encodings[0].max_framerate = Some(-1.0);
    assert!(matches!(
        s.set_parameters(params, None),
        Err(Error::RangeError(_))
    ));
    Ok(())
}

#[test]
fn a_stopped_transceivers_sender_takes_no_parameters() -> TestResult {
    let mut pc = default_peer()?;
    let sender = pc.add_track(video_track("video", 0x0303_0005))?;
    assert!(pc.rtp_sender(sender).is_some());
    pc.rtp_transceiver(RTCRtpTransceiverId::from(sender))
        .expect("transceiver")
        .stop()?;
    // Stopping makes the transceiver inactive, and `rtp_sender` hands out a sender only while
    // its transceiver sends, so no handle reaches set_parameters (which would also refuse a
    // stopped transceiver with InvalidStateError, W3C webrtc 5.2 setParameters step 4).
    assert!(pc.rtp_sender(sender).is_none());
    Ok(())
}

#[test]
fn an_inactive_encoding_is_a_paused_rid() -> TestResult {
    let mut pc = default_peer()?;
    let encodings = ["f", "h"]
        .into_iter()
        .enumerate()
        .map(|(i, rid)| RTCRtpEncodingParameters {
            rtp_coding_parameters: RTCRtpCodingParameters {
                rid: rid.to_owned(),
                ssrc: Some(0x0303_0100 + i as u32),
                ..Default::default()
            },
            codec: vp8(),
            ..Default::default()
        })
        .collect();
    let sender = pc.add_track(MediaStreamTrack::new(
        "stream".to_owned(),
        "simulcast".to_owned(),
        "simulcast".to_owned(),
        RtpCodecKind::Video,
        encodings,
    ))?;

    let offer = pc.create_offer(None)?;
    assert!(offer.sdp.contains("a=simulcast:send f;h"), "{}", offer.sdp);

    let mut s = pc.rtp_sender(sender).expect("sender");
    let mut params = s.get_parameters().clone();
    assert!(
        params.encodings.iter().all(|e| e.active),
        "encodings are active by default"
    );
    params.encodings[1].active = false;
    s.set_parameters(params, None)?;

    let offer = pc.create_offer(None)?;
    assert!(
        offer.sdp.contains("a=simulcast:send f;~h"),
        "the inactive encoding's rid is paused:\n{}",
        offer.sdp
    );
    Ok(())
}
