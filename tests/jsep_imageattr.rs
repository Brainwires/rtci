//! Video size negotiation with `a=imageattr` (RFC 9429 sections 3.6, 5.2.1, 5.3.1, 5.8.2 and
//! 5.10; RFC 6236): the receiver states its limits, the sender follows them.

mod jsep_common;

use std::time::Instant;

use jsep_common::{TestResult, exchange, media_sections, video_track};
use rtc::peer_connection::configuration::media_engine::MediaEngine;
use rtc::peer_connection::configuration::setting_engine::SettingEngineBuilder;
use rtc::peer_connection::sdp::{RTCSessionDescription, RTCVideoResolutionRange};
use rtc::peer_connection::{RTCPeerConnection, RTCPeerConnectionBuilder};
use rtc::rtp_transceiver::rtp_sender::RtpCodecKind;
use rtc::rtp_transceiver::{RTCRtpTransceiverDirection, RTCRtpTransceiverInit};

fn peer(settings: SettingEngineBuilder) -> Result<RTCPeerConnection, Box<dyn std::error::Error>> {
    let mut media_engine = MediaEngine::default();
    media_engine.register_default_codecs()?;
    Ok(RTCPeerConnectionBuilder::new()
        .with_media_engine(media_engine)
        .with_setting_engine(settings.build())
        .build(Instant::now())?)
}

fn range(min: (u32, u32), max: (u32, u32)) -> RTCVideoResolutionRange {
    RTCVideoResolutionRange {
        min_width: min.0,
        min_height: min.1,
        max_width: max.0,
        max_height: max.1,
    }
}

/// The `a=imageattr` values and the direction of the video section of `sdp`.
fn video_section(sdp: &str) -> (Vec<String>, String) {
    let section = media_sections(sdp)
        .into_iter()
        .find(|s| s[0].starts_with("m=video"))
        .unwrap_or_else(|| panic!("a video section in:\n{sdp}"));
    let imageattrs = section
        .iter()
        .filter_map(|l| l.strip_prefix("a=imageattr:"))
        .map(str::to_owned)
        .collect();
    let direction = section
        .iter()
        .find_map(|l| {
            ["a=sendrecv", "a=sendonly", "a=recvonly", "a=inactive"]
                .into_iter()
                .find(|d| l == d)
        })
        .expect("a direction")
        .to_owned();
    (imageattrs, direction)
}

/// Section 3.6.1: without limits there is no attribute; with limits every codec shares, one
/// wildcard line, in an offer and in an answer (sections 5.2.1, 5.3.1); the offerer's sender
/// then keeps within what the answer permits (sections 3.6.2, 5.10): 1280x720 under a 640x480
/// maximum is sent as 640x360, and below the minimum it is not sent.
#[test]
fn the_receiver_states_its_limits_and_the_sender_keeps_within_them() -> TestResult {
    let mut plain = peer(SettingEngineBuilder::new())?;
    plain.add_transceiver_from_kind(RtpCodecKind::Video, None)?;
    let offer = plain.create_offer(None)?;
    assert!(video_section(&offer.sdp).0.is_empty(), "{}", offer.sdp);

    let mut sender = peer(SettingEngineBuilder::new())?;
    let id = sender.add_track(video_track("camera", 0x0303_0303))?;
    let mut receiver =
        peer(SettingEngineBuilder::new().with_video_receive_limits(range((48, 48), (640, 480))))?;
    receiver
        .add_transceiver_from_kind(RtpCodecKind::Video, Some(RTCRtpTransceiverInit::recvonly()))?;
    let offer = receiver.create_offer(None)?;
    assert_eq!(
        video_section(&offer.sdp).0,
        vec!["* recv [x=[48:640],y=[48:480],q=1.0]".to_owned()],
        "{}",
        offer.sdp
    );

    let (_, answer) = exchange(&mut sender, &mut receiver)?;
    assert_eq!(
        video_section(&answer).0,
        vec!["* recv [x=[48:640],y=[48:480],q=1.0]".to_owned()],
        "{answer}"
    );
    let mut rtp_sender = sender.rtp_sender(id).expect("the sender");
    assert_eq!(rtp_sender.send_resolution(1280, 720)?, (640, 360));
    assert_eq!(rtp_sender.send_resolution(320, 240)?, (320, 240));
    assert!(rtp_sender.send_resolution(32, 24).is_err());
    Ok(())
}

/// Section 3.6.1: codecs with different limits get one line per payload type; limits that
/// permit no size leave the attribute out and the section does not receive.
#[test]
fn per_codec_limits_and_limits_that_permit_nothing() -> TestResult {
    let mut receiver = peer(
        SettingEngineBuilder::new()
            .with_video_receive_limits(range((48, 48), (1920, 1080)))
            .with_codec_video_receive_limits("video/VP9", range((48, 48), (640, 360))),
    )?;
    receiver.add_transceiver_from_kind(RtpCodecKind::Video, None)?;
    let offer = receiver.create_offer(None)?;
    let (lines, _) = video_section(&offer.sdp);
    assert!(lines.len() > 1, "{}", offer.sdp);
    assert!(lines.iter().all(|l| !l.starts_with('*')), "{lines:?}");
    assert!(
        lines
            .iter()
            .any(|l| l.ends_with("recv [x=[48:640],y=[48:360],q=1.0]")),
        "{lines:?}"
    );
    assert!(
        lines
            .iter()
            .any(|l| l.ends_with("recv [x=[48:1920],y=[48:1080],q=1.0]")),
        "{lines:?}"
    );

    let mut nothing =
        peer(SettingEngineBuilder::new().with_video_receive_limits(range((640, 480), (320, 240))))?;
    nothing.add_transceiver_from_kind(
        RtpCodecKind::Video,
        Some(RTCRtpTransceiverInit {
            direction: RTCRtpTransceiverDirection::Sendrecv,
            streams: vec![],
            send_encodings: vec![],
        }),
    )?;
    let offer = nothing.create_offer(None)?;
    assert_eq!(
        video_section(&offer.sdp),
        (vec![], "a=sendonly".to_owned()),
        "{}",
        offer.sdp
    );
    Ok(())
}

/// Section 5.8.2: "Any 'a=imageattr' attributes MUST be parsed as specified in [RFC6236]":
/// a description whose line does not parse is refused.
#[test]
fn a_malformed_imageattr_line_refuses_the_description() -> TestResult {
    let mut offerer = peer(SettingEngineBuilder::new())?;
    offerer.add_transceiver_from_kind(RtpCodecKind::Video, None)?;
    let offer = offerer.create_offer(None)?;
    for (line, accepted) in [
        ("a=imageattr:* recv [x=[48:640],y=[48:480],q=1.0]", true),
        ("a=imageattr:* recv [x=48:640]", false),
        ("a=imageattr:* both *", false),
    ] {
        let sdp = offer
            .sdp
            .replacen("a=mid:0\r\n", &format!("a=mid:0\r\n{line}\r\n"), 1);
        assert_ne!(sdp, offer.sdp);
        let result = peer(SettingEngineBuilder::new())?
            .set_remote_description(Instant::now(), RTCSessionDescription::offer(sdp)?);
        assert_eq!(result.is_ok(), accepted, "{line}: {result:?}");
    }
    Ok(())
}

/// RFC 8859 section 4.7 and appendix A (section 5.17): `a=imageattr` is IDENTICAL-PER-PT, so a
/// payload type has the same lines in every bundled section. An offer of two bundled video
/// sections, with limits per codec, gives each payload type the same `a=imageattr` in both,
/// and its peer applies it.
#[test]
fn two_bundled_video_sections_give_a_payload_type_the_same_image_attributes() -> TestResult {
    let mut offerer = peer(
        SettingEngineBuilder::new()
            .with_video_receive_limits(range((48, 48), (1920, 1080)))
            .with_codec_video_receive_limits("video/VP9", range((48, 48), (640, 360))),
    )?;
    offerer.add_transceiver_from_kind(RtpCodecKind::Video, None)?;
    offerer.add_transceiver_from_kind(RtpCodecKind::Video, None)?;
    let offer = offerer.create_offer(None)?;
    let sections: Vec<Vec<String>> = media_sections(&offer.sdp)
        .into_iter()
        .filter(|s| s[0].starts_with("m=video"))
        .collect();
    assert_eq!(sections.len(), 2, "{}", offer.sdp);
    assert!(
        offer.sdp.contains("a=group:BUNDLE 0 1"),
        "the two sections are bundled:\n{}",
        offer.sdp
    );
    // Payload type -> its a=imageattr values, per section.
    let per_pt = |section: &[String]| {
        let mut out: std::collections::BTreeMap<String, Vec<String>> = Default::default();
        for line in section
            .iter()
            .filter_map(|l| l.strip_prefix("a=imageattr:"))
        {
            let (pt, value) = line.split_once(' ').expect("a format and a value");
            out.entry(pt.to_owned()).or_default().push(value.to_owned());
        }
        out
    };
    let (first, second) = (per_pt(&sections[0]), per_pt(&sections[1]));
    assert!(first.len() > 1, "a line per payload type: {first:?}");
    assert_eq!(first, second, "{}", offer.sdp);

    let mut answerer = peer(SettingEngineBuilder::new())?;
    answerer.set_remote_description(Instant::now(), offer)?;
    Ok(())
}
