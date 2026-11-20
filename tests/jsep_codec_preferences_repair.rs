//! `setCodecPreferences` keeps only the repair formats it lists (W3C webrtc 5.4,
//! setCodecPreferences): leaving RTX out removes it, and with it the sender's
//! `a=ssrc-group:FID`; an RTX entry without `apt`, as `getCapabilities()` lists it, stands for
//! RTX of every primary that survives. Repair formats used to come back into any preference
//! list, so RTX or FEC could not be removed.

mod jsep_common;

use std::time::Instant;

use jsep_common::{TestResult, media_sections, video_track};
use rtc::peer_connection::configuration::media_engine::{
    MIME_TYPE_RTX, MIME_TYPE_VP8, MIME_TYPE_VP9, MediaEngine,
};
use rtc::peer_connection::{RTCPeerConnection, RTCPeerConnectionBuilder};
use rtc::rtp_transceiver::RTCRtpTransceiverId;
use rtc::rtp_transceiver::rtp_sender::{RTCRtpCodec, RTCRtpCodecParameters, RtpCodecKind};

fn video(mime_type: &str, payload_type: u8, fmtp: &str) -> RTCRtpCodecParameters {
    RTCRtpCodecParameters {
        rtp_codec: RTCRtpCodec {
            mime_type: mime_type.to_owned(),
            clock_rate: 90000,
            channels: 0,
            sdp_fmtp_line: fmtp.to_owned(),
            rtcp_feedback: vec![],
        },
        payload_type,
    }
}

/// A peer with VP8 and VP9, each with RTX, and one VP8 track; returns it and the track's
/// transceiver.
fn peer_with_track() -> Result<(RTCPeerConnection, RTCRtpTransceiverId), Box<dyn std::error::Error>>
{
    let mut media_engine = MediaEngine::default();
    for codec in [
        video(MIME_TYPE_VP8, 96, ""),
        video(MIME_TYPE_RTX, 97, "apt=96"),
        video(MIME_TYPE_VP9, 98, "profile-id=0"),
        video(MIME_TYPE_RTX, 99, "apt=98"),
    ] {
        media_engine.register_codec(codec, RtpCodecKind::Video)?;
    }
    let mut pc = RTCPeerConnectionBuilder::new()
        .with_media_engine(media_engine)
        .build(Instant::now())?;
    let sender = pc.add_track(video_track("video", 0x0505_0505))?;
    Ok((pc, RTCRtpTransceiverId::from(sender)))
}

/// The payload types of the first media section's `m=` line.
fn formats(sdp: &str) -> Vec<u8> {
    media_sections(sdp)[0][0]
        .split_whitespace()
        .skip(3)
        .map(|pt| pt.parse().expect("numeric payload type"))
        .collect()
}

#[test]
fn leaving_rtx_out_of_the_preferences_removes_it() -> TestResult {
    let (mut pc, id) = peer_with_track()?;
    pc.rtp_transceiver(id)
        .expect("transceiver")
        .set_codec_preferences(vec![video(MIME_TYPE_VP8, 96, "")])?;

    let offer = pc.create_offer(None)?;
    assert_eq!(formats(&offer.sdp), vec![96], "{}", offer.sdp);
    assert!(!offer.sdp.contains("rtx/90000"), "{}", offer.sdp);
    assert!(
        !offer.sdp.contains("a=ssrc-group:FID"),
        "no RTX format, so no dangling FID group:\n{}",
        offer.sdp
    );
    Ok(())
}

#[test]
fn an_rtx_entry_without_apt_keeps_rtx_for_the_preferred_primaries() -> TestResult {
    let (mut pc, id) = peer_with_track()?;
    pc.rtp_transceiver(id)
        .expect("transceiver")
        .set_codec_preferences(vec![
            video(MIME_TYPE_VP8, 96, ""),
            video(MIME_TYPE_RTX, 97, ""),
        ])?;

    let offer = pc.create_offer(None)?;
    assert_eq!(formats(&offer.sdp), vec![96, 97], "{}", offer.sdp);
    assert!(offer.sdp.contains("a=fmtp:97 apt=96"), "{}", offer.sdp);
    assert!(
        !offer.sdp.contains("apt=98"),
        "VP9 is not preferred, so neither is its RTX:\n{}",
        offer.sdp
    );
    assert!(offer.sdp.contains("a=ssrc-group:FID"), "{}", offer.sdp);
    Ok(())
}
