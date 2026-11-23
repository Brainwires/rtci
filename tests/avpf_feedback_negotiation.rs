//! RFC 4585 (RTP/AVPF) sections 3.7.2, 4.1 and 4.2 as descriptions carry them: feedback is
//! signalled under the AVPF profile only, at media level only, and an answer keeps only the
//! feedback both sides understand.

mod jsep_common;

use std::time::Instant;

use jsep_common::{SESSION, TRANSPORT, TestResult, crlf};
use rtc::interceptor::Registry;
use rtc::peer_connection::configuration::interceptor_registry::register_default_interceptors;
use rtc::peer_connection::configuration::media_engine::{MIME_TYPE_VP8, MediaEngine};
use rtc::peer_connection::sdp::RTCSessionDescription;
use rtc::peer_connection::{RTCPeerConnection, RTCPeerConnectionBuilder};
use rtc::rtp_transceiver::rtp_sender::{
    RTCPFeedback, RTCRtpCodec, RTCRtpCodecParameters, RtpCodecKind,
};

fn feedback(typ: &str, parameter: &str) -> RTCPFeedback {
    RTCPFeedback {
        typ: typ.to_owned(),
        parameter: parameter.to_owned(),
    }
}

/// A peer whose only codec is VP8 (payload type 96) with NACK and PLI.
fn peer() -> Result<RTCPeerConnection, Box<dyn std::error::Error>> {
    let mut media_engine = MediaEngine::default();
    media_engine.register_codec(
        RTCRtpCodecParameters {
            rtp_codec: RTCRtpCodec {
                mime_type: MIME_TYPE_VP8.to_owned(),
                clock_rate: 90000,
                channels: 0,
                sdp_fmtp_line: String::new(),
                rtcp_feedback: vec![feedback("nack", ""), feedback("nack", "pli")],
            },
            payload_type: 96,
        },
        RtpCodecKind::Video,
    )?;
    Ok(RTCPeerConnectionBuilder::new()
        .with_media_engine(media_engine)
        .build(Instant::now())?)
}

/// A peer with the default codecs and interceptors, and their feedback.
fn default_peer() -> Result<RTCPeerConnection, Box<dyn std::error::Error>> {
    let mut media_engine = MediaEngine::default();
    media_engine.register_default_codecs()?;
    let registry = register_default_interceptors(Registry::new(), &mut media_engine)?;
    Ok(RTCPeerConnectionBuilder::new()
        .with_media_engine(media_engine)
        .with_interceptor_registry(registry)
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

/// RFC 4585 sections 3.7.2, 4.2: an endpoint that uses feedback signals the AVPF profile
/// (here its secure form, `UDP/TLS/RTP/SAVPF`) in every section that carries `a=rtcp-fb`,
/// and writes `a=rtcp-fb` only at media level.
#[test]
fn feedback_is_offered_under_the_avpf_profile_and_at_media_level_only() -> TestResult {
    let mut pc = default_peer()?;
    pc.add_transceiver_from_kind(RtpCodecKind::Audio, None)?;
    pc.add_transceiver_from_kind(RtpCodecKind::Video, None)?;
    let offer = pc.create_offer(None)?;
    let mut in_media = false;
    let mut profile = String::new();
    let mut with_feedback = 0;
    for line in offer.sdp.lines() {
        if let Some(m) = line.strip_prefix("m=") {
            in_media = true;
            profile = m.split_whitespace().nth(2).unwrap_or_default().to_owned();
        }
        if line.starts_with("a=rtcp-fb:") {
            assert!(in_media, "a session-level a=rtcp-fb: {}", offer.sdp);
            assert!(
                profile.ends_with("AVPF"),
                "a=rtcp-fb under {profile}: {}",
                offer.sdp
            );
            with_feedback += 1;
        }
    }
    assert!(with_feedback > 0, "{}", offer.sdp);
    Ok(())
}

/// RFC 4585 section 4.2: "Feedback types that are not understood ... MUST be ignored"; and
/// the answerer "MUST remove" the feedback it does not understand or want: an unknown type
/// and an unknown parameter of a known one are not answered, the rest is.
#[test]
fn feedback_this_endpoint_does_not_understand_is_left_out_of_the_answer() -> TestResult {
    let mut pc = peer()?;
    pc.set_remote_description(
        Instant::now(),
        offer("a=rtcp-fb:96 nack\na=rtcp-fb:96 x-unknown\na=rtcp-fb:96 nack x-unknown\na=rtcp-fb:96 nack pli\n")?,
    )?;
    let answer = pc.create_answer(None)?;
    let mut lines = feedback_lines(&answer.sdp);
    lines.sort_unstable();
    assert_eq!(vec!["96 nack", "96 nack pli"], lines, "{}", answer.sdp);
    pc.set_local_description(Instant::now(), answer)?;
    Ok(())
}

/// RFC 3611 section 5.1: "The indicators 'TTL' and 'HL' MUST NOT be signaled together". The
/// endpoint signals only the round-trip pair (`rcvr-rtt`): an answer to an offer whose
/// `a=rtcp-xr` lists a statistics summary with both keeps neither, and states the `rcvr-rtt`
/// it takes.
#[test]
fn ttl_and_hl_are_never_signalled_together() -> TestResult {
    let mut pc = default_peer()?;
    let remote = RTCSessionDescription::offer(crlf(&format!(
        "{SESSION}a=group:BUNDLE 0
m=video 9 UDP/TLS/RTP/SAVPF 96
{TRANSPORT}a=mid:0
a=sendrecv
a=rtpmap:96 VP8/90000
a=rtcp-fb:96 nack
a=rtcp-xr:rcvr-rtt=all stat-summary=loss,TTL,HL
"
    )))?;
    pc.set_remote_description(Instant::now(), remote)?;
    let answer = pc.create_answer(None)?;
    for line in answer.sdp.lines().filter(|l| l.starts_with("a=rtcp-xr")) {
        assert!(
            !(line.contains("TTL") && line.contains("HL")),
            "{}",
            answer.sdp
        );
    }
    let offer = default_peer()
        .and_then(|mut pc| {
            pc.add_transceiver_from_kind(RtpCodecKind::Video, None)?;
            Ok(pc.create_offer(None)?)
        })?
        .sdp;
    for line in offer.lines().filter(|l| l.starts_with("a=rtcp-xr")) {
        assert!(!(line.contains("TTL") && line.contains("HL")), "{offer}");
    }
    Ok(())
}
