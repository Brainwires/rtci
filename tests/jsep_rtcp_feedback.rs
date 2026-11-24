//! `a=rtcp-fb` in descriptions (RFC 4585 section 4.2, RFC 8888 section 6, RFC 9429 section
//! 5.3.1): the wildcard payload type is read, an answer keeps the subset of the offered
//! feedback this endpoint has, and RFC 8888 feedback is signalled with the wildcard.

mod jsep_common;

use std::time::Instant;

use jsep_common::{SESSION, TRANSPORT, TestResult, crlf};
use rtci::peer_connection::configuration::media_engine::{MIME_TYPE_VP8, MediaEngine};
use rtci::peer_connection::sdp::RTCSessionDescription;
use rtci::peer_connection::{RTCPeerConnection, RTCPeerConnectionBuilder};
use rtci::rtp_transceiver::rtp_sender::{
    RTCPFeedback, RTCRtpCodec, RTCRtpCodecParameters, RtpCodecKind,
};

fn feedback(typ: &str, parameter: &str) -> RTCPFeedback {
    RTCPFeedback {
        typ: typ.to_owned(),
        parameter: parameter.to_owned(),
    }
}

/// A peer whose only codec is VP8 (payload type 96) with the given feedback.
fn peer(rtcp_feedback: Vec<RTCPFeedback>) -> Result<RTCPeerConnection, Box<dyn std::error::Error>> {
    let mut media_engine = MediaEngine::default();
    media_engine.register_codec(
        RTCRtpCodecParameters {
            rtp_codec: RTCRtpCodec {
                mime_type: MIME_TYPE_VP8.to_owned(),
                clock_rate: 90000,
                channels: 0,
                sdp_fmtp_line: String::new(),
                rtcp_feedback,
            },
            payload_type: 96,
        },
        RtpCodecKind::Video,
    )?;
    Ok(RTCPeerConnectionBuilder::new()
        .with_media_engine(media_engine)
        .build(Instant::now())?)
}

fn feedback_lines(sdp: &str) -> Vec<&str> {
    sdp.lines()
        .filter_map(|l| l.strip_prefix("a=rtcp-fb:"))
        .collect()
}

fn offer(feedback: &str) -> Result<RTCSessionDescription, Box<dyn std::error::Error>> {
    Ok(RTCSessionDescription::offer(crlf(&format!(
        "{SESSION}a=group:BUNDLE 0
m=video 9 UDP/TLS/RTP/SAVPF 96
{TRANSPORT}a=mid:0
a=sendrecv
a=rtpmap:96 VP8/90000
{feedback}"
    )))?)
}

#[test]
fn rfc_8888_feedback_is_offered_with_the_wildcard_payload_type() -> TestResult {
    let mut pc = peer(vec![feedback("nack", ""), feedback("ack", "ccfb")])?;
    pc.add_transceiver_from_kind(
        RtpCodecKind::Video,
        Some(rtci::rtp_transceiver::RTCRtpTransceiverInit::recvonly()),
    )?;
    let offer = pc.create_offer(None)?;
    assert_eq!(
        feedback_lines(&offer.sdp),
        vec!["96 nack", "* ack ccfb"],
        "{}",
        offer.sdp
    );
    Ok(())
}

#[test]
fn wildcard_feedback_of_an_offer_is_answered_as_the_subset_this_endpoint_has() -> TestResult {
    let mut pc = peer(vec![
        feedback("nack", ""),
        feedback("nack", "pli"),
        feedback("ack", "ccfb"),
    ])?;
    // The offer: RFC 8888 feedback and plain NACK for every payload type, FIR for 96; no PLI.
    pc.set_remote_description(
        Instant::now(),
        offer("a=rtcp-fb:* ack ccfb\na=rtcp-fb:* nack\na=rtcp-fb:96 ccm fir\n")?,
    )?;
    let answer = pc.create_answer(None)?;
    let mut lines = feedback_lines(&answer.sdp);
    lines.sort_unstable();
    assert_eq!(lines, vec!["* ack ccfb", "96 nack"], "{}", answer.sdp);
    pc.set_local_description(Instant::now(), answer)?;
    Ok(())
}

#[test]
fn feedback_that_was_not_offered_is_not_answered() -> TestResult {
    let mut pc = peer(vec![feedback("nack", ""), feedback("ack", "ccfb")])?;
    pc.set_remote_description(Instant::now(), offer("a=rtcp-fb:96 nack\n")?)?;
    let answer = pc.create_answer(None)?;
    assert_eq!(
        feedback_lines(&answer.sdp),
        vec!["96 nack"],
        "{}",
        answer.sdp
    );
    Ok(())
}

/// A section offered with a profile without feedback (`UDP/TLS/RTP/SAVP`) is answered in that
/// profile with no `a=rtcp-fb` (RFC 4585 section 4.1: "the feedback mechanisms MUST NOT be
/// used" outside AVPF) and no `a=rtcp-rsize` (RFC 5506 section 4.1: reduced-size RTCP is not
/// used with RTP/SAVP), even when the offer carries them; under SAVPF they are answered.
#[test]
fn a_section_without_the_feedback_profile_is_answered_without_feedback() -> TestResult {
    for (profile, kept) in [("UDP/TLS/RTP/SAVPF", true), ("UDP/TLS/RTP/SAVP", false)] {
        let mut pc = peer(vec![feedback("nack", ""), feedback("nack", "pli")])?;
        let sdp = offer("a=rtcp-fb:96 nack\na=rtcp-fb:96 nack pli\na=rtcp-rsize\n")?
            .sdp
            .replace("UDP/TLS/RTP/SAVPF 96", &format!("{profile} 96"));
        pc.set_remote_description(Instant::now(), RTCSessionDescription::offer(sdp)?)?;
        let answer = pc.create_answer(None)?.sdp;
        assert!(answer.contains(&format!(" {profile} 96\r\n")), "{answer}");
        assert_eq!(
            !feedback_lines(&answer).is_empty(),
            kept,
            "{profile}:\n{answer}"
        );
        assert_eq!(
            answer.contains("a=rtcp-rsize"),
            kept,
            "{profile}:\n{answer}"
        );
    }
    Ok(())
}

/// The default AV1 format offers the Layer Refresh Request (`a=rtcp-fb:<pt> ccm lrr`, AV1 RTP
/// payload format section 8.2); the other default video formats do not.
#[test]
fn the_default_av1_format_offers_layer_refresh_requests() -> TestResult {
    let mut pc = jsep_common::default_peer()?;
    pc.add_transceiver_from_kind(RtpCodecKind::Video, None)?;
    let offer = pc.create_offer(None)?.sdp;
    let av1 = offer
        .lines()
        .find_map(|l| {
            l.strip_prefix("a=rtpmap:")
                .filter(|v| v.contains(" AV1/90000"))
                .and_then(|v| v.split(' ').next())
        })
        .expect("an AV1 format");
    let lrr: Vec<&str> = feedback_lines(&offer)
        .into_iter()
        .filter(|l| l.ends_with(" ccm lrr"))
        .collect();
    assert_eq!(lrr, [format!("{av1} ccm lrr")], "{offer}");
    Ok(())
}
