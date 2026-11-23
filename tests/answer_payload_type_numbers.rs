//! An answer reuses the payload type number the offer gave a format (RFC 3264 section 6.1),
//! for the formats whose RFCs repeat it as a SHOULD: H.264 (RFC 6184 section 8.2.2), VP9
//! (RFC 9628 section 6.1.2) and H.265 (RFC 7798 section 7.2.2).

mod jsep_common;

use std::time::Instant;

use jsep_common::{SESSION, TRANSPORT, TestResult, crlf};
use rtc::peer_connection::RTCPeerConnectionBuilder;
use rtc::peer_connection::configuration::media_engine::MediaEngine;
use rtc::peer_connection::sdp::RTCSessionDescription;

/// The answer to a one-format video offer of `rtpmap` / `fmtp` under payload type 120, a
/// number the default codecs give none of them.
fn answer_to(rtpmap: &str, fmtp: &str) -> Result<String, Box<dyn std::error::Error>> {
    let mut media_engine = MediaEngine::default();
    media_engine.register_default_codecs()?;
    let mut pc = RTCPeerConnectionBuilder::new()
        .with_media_engine(media_engine)
        .build(Instant::now())?;
    let offer = RTCSessionDescription::offer(crlf(&format!(
        "{SESSION}a=group:BUNDLE 0
m=video 9 UDP/TLS/RTP/SAVPF 120
{TRANSPORT}a=mid:0
a=sendrecv
a=rtpmap:120 {rtpmap}
a=fmtp:120 {fmtp}
"
    )))?;
    pc.set_remote_description(Instant::now(), offer)?;
    Ok(pc.create_answer(None)?.sdp)
}

fn answers_under_120(rtpmap: &str, fmtp: &str) -> TestResult {
    let answer = answer_to(rtpmap, fmtp)?;
    let media = answer
        .lines()
        .find(|l| l.starts_with("m=video"))
        .expect("a video section");
    // The offered format first, under the offer's number; the answerer's other formats follow
    // it (RFC 9429 section 5.3.1: formats absent from the offer "MUST be added after all
    // existing formats").
    assert_eq!(media.split(' ').nth(3), Some("120"), "{media}\n{answer}");
    assert!(
        answer.contains(&format!("a=rtpmap:120 {rtpmap}")),
        "{answer}"
    );
    Ok(())
}

#[test]
fn an_h264_answer_uses_the_offered_payload_type_number() -> TestResult {
    answers_under_120(
        "H264/90000",
        "level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=42e01f",
    )
}

#[test]
fn a_vp9_answer_uses_the_offered_payload_type_number() -> TestResult {
    answers_under_120("VP9/90000", "profile-id=0")
}

#[test]
fn an_h265_answer_uses_the_offered_payload_type_number() -> TestResult {
    answers_under_120(
        "H265/90000",
        "level-id=93;profile-id=1;tier-flag=0;tx-mode=SRST",
    )
}
