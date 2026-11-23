//! What a remote description must have to be applied, and what is ignored in it (RFC 9429
//! section 5.10, RFC 8839 section 5.1).

mod jsep_common;

use jsep_common::{SESSION, TRANSPORT, TestResult, crlf, default_peer};
use rtc::peer_connection::sdp::RTCSessionDescription;
use std::time::Instant;

/// A remote offer with one video section whose formats are `formats` and whose format
/// lines are `lines`.
fn video_offer(
    formats: &str,
    lines: &str,
) -> Result<RTCSessionDescription, rtc::shared::error::Error> {
    RTCSessionDescription::offer(crlf(&format!(
        "{SESSION}a=group:BUNDLE 0\n\
         m=video 9 UDP/TLS/RTP/SAVPF {formats}\n{TRANSPORT}a=mid:0\na=sendrecv\n{lines}"
    )))
}

/// RFC 9429 section 5.10: "If any RTX or FEC format ... is present, but the primary format it
/// is associated with is not present, an error MUST be returned". An RTX format whose primary
/// is on the m= line but not supported is not an error: it is ignored with its primary.
#[test]
fn an_rtx_format_without_its_primary_on_the_m_line_refuses_the_description() -> TestResult {
    let mut pc = default_peer()?;
    let orphan = video_offer(
        "96 97",
        "a=rtpmap:96 VP8/90000\na=rtpmap:97 rtx/90000\na=fmtp:97 apt=100\n",
    )?;
    let refused = pc.set_remote_description(Instant::now(), orphan);
    assert!(refused.is_err(), "{refused:?}");

    let mut pc = default_peer()?;
    let unsupported = video_offer(
        "96 100 101",
        "a=rtpmap:96 VP8/90000\na=rtpmap:100 XYZ/90000\na=rtpmap:101 rtx/90000\n\
         a=fmtp:101 apt=100\n",
    )?;
    pc.set_remote_description(Instant::now(), unsupported)?;
    let answer = pc.create_answer(None)?;
    assert!(
        answer.sdp.contains("a=rtpmap:96 VP8/90000"),
        "{}",
        answer.sdp
    );
    assert!(!answer.sdp.contains("a=rtpmap:101"), "{}", answer.sdp);
    Ok(())
}

/// RFC 8839 section 5.1: "An agent processing remote candidates MUST ignore "candidate" lines
/// that include candidates with FQDNs"; a transport or candidate type this agent does not
/// know is an extension of the grammar and is ignored too. The description is applied and
/// answered. A line that does not follow the grammar still refuses it.
#[test]
fn candidate_lines_with_a_domain_name_or_unknown_tokens_are_ignored() -> TestResult {
    let lines = "a=rtpmap:96 VP8/90000\n\
                 a=candidate:1 1 udp 2130706431 media.example.org 5000 typ host\n\
                 a=candidate:2 1 sctp 2130706431 10.0.0.1 5001 typ host\n\
                 a=candidate:3 1 udp 2130706431 10.0.0.1 5002 typ future\n\
                 a=candidate:4 1 udp 2130706431 10.0.0.1 5003 typ host\n";
    let mut pc = default_peer()?;
    pc.set_remote_description(Instant::now(), video_offer("96", lines)?)?;
    let answer = pc.create_answer(None)?;
    pc.set_local_description(Instant::now(), answer)?;

    let mut pc = default_peer()?;
    let malformed = video_offer(
        "96",
        "a=rtpmap:96 VP8/90000\na=candidate:5 1 udp high 10.0.0.1 5004 typ host\n",
    )?;
    let refused = pc.set_remote_description(Instant::now(), malformed);
    assert!(refused.is_err(), "{refused:?}");
    Ok(())
}

/// RFC 9143 section 5: "an "m=" section MUST NOT be associated with more than one BUNDLE
/// group". A description that lists a mid in two groups is refused; the same sections in one
/// group are not.
#[test]
fn a_mid_in_two_bundle_groups_refuses_the_description() -> TestResult {
    let offer = |groups: &str| -> Result<RTCSessionDescription, rtc::shared::error::Error> {
        RTCSessionDescription::offer(crlf(&format!(
            "{SESSION}{groups}\
             m=video 9 UDP/TLS/RTP/SAVPF 96\n{TRANSPORT}a=mid:0\na=sendrecv\na=rtpmap:96 VP8/90000\n\
             m=video 9 UDP/TLS/RTP/SAVPF 96\n{TRANSPORT}a=mid:1\na=sendrecv\na=rtpmap:96 VP8/90000\n"
        )))
    };
    let mut pc = default_peer()?;
    let refused = pc.set_remote_description(
        Instant::now(),
        offer("a=group:BUNDLE 0 1\na=group:BUNDLE 1\n")?,
    );
    assert!(refused.is_err(), "{refused:?}");

    let mut pc = default_peer()?;
    pc.set_remote_description(Instant::now(), offer("a=group:BUNDLE 0 1\n")?)?;
    Ok(())
}
