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

/// RFC 8839 section 4.4.2.1: "If any of the SDP attributes [ice-options, ice-pacing,
/// ice-lite] have been modified in a subsequent offer that is not used to request an ICE
/// restart, the answerer MUST reject the offer." With new credentials (a restart) the same
/// change is taken.
#[test]
fn a_subsequent_offer_without_a_restart_keeps_the_ice_attributes() -> TestResult {
    let offer = |session: &str, transport: &str| {
        RTCSessionDescription::offer(crlf(&format!(
            "{SESSION}{session}a=group:BUNDLE 0\n\
             m=video 9 UDP/TLS/RTP/SAVPF 96\n{transport}a=mid:0\na=sendrecv\na=rtpmap:96 VP8/90000\n"
        )))
    };
    let mut pc = default_peer()?;
    pc.set_remote_description(Instant::now(), offer("a=ice-options:trickle\n", TRANSPORT)?)?;
    let answer = pc.create_answer(None)?;
    pc.set_local_description(Instant::now(), answer)?;

    for changed in [
        "a=ice-lite\na=ice-options:trickle\n",
        "a=ice-options:trickle ice2\n",
    ] {
        let refused = pc.set_remote_description(Instant::now(), offer(changed, TRANSPORT)?);
        assert!(refused.is_err(), "{changed:?}: {refused:?}");
    }
    let restarted = TRANSPORT
        .replace("a=ice-ufrag:4ZcD", "a=ice-ufrag:R3st")
        .replace(
            "a=ice-pwd:2/1muCWoOi3uLifh0NuRHlkwz",
            "a=ice-pwd:anotherpasswordof22chars",
        );
    pc.set_remote_description(
        Instant::now(),
        offer("a=ice-options:trickle ice2\n", &restarted)?,
    )?;
    Ok(())
}

/// A remote offer of two bundled video sections whose formats are `first` and `second`
/// (each an `m=` format list and its lines).
fn two_bundled_video_sections(
    first: (&str, &str),
    second: (&str, &str),
) -> Result<RTCSessionDescription, rtc::shared::error::Error> {
    RTCSessionDescription::offer(crlf(&format!(
        "{SESSION}a=group:BUNDLE 0 1\n\
         m=video 9 UDP/TLS/RTP/SAVPF {}\n{TRANSPORT}a=mid:0\na=sendrecv\n{}\
         m=video 9 UDP/TLS/RTP/SAVPF {}\n{TRANSPORT}a=mid:1\na=sendrecv\n{}",
        first.0, first.1, second.0, second.1
    )))
}

/// RFC 9143 section 9.1.1: a payload type used in more than one bundled section "MUST share an
/// identical codec configuration"; RFC 8834 section 4.3: one payload type "MUST NOT be assigned
/// to different RTP payload formats, or different configurations of the same RTP payload
/// format, within a single RTP session". A remote offer whose bundled sections give 96 to VP8
/// and to VP9, or to H.264 of two packetization modes, is refused; the same VP8 under 96 in
/// both is applied.
#[test]
fn a_payload_type_with_two_configurations_in_one_bundle_group_refuses_the_description() -> TestResult
{
    let vp8 = ("96", "a=rtpmap:96 VP8/90000\n");
    for other in [
        ("96", "a=rtpmap:96 VP9/90000\n"),
        ("96", "a=rtpmap:96 VP8/48000\n"),
    ] {
        let mut pc = default_peer()?;
        let refused =
            pc.set_remote_description(Instant::now(), two_bundled_video_sections(vp8, other)?);
        assert!(refused.is_err(), "{other:?}: {refused:?}");
    }
    let h264 = |mode: u8| {
        format!(
            "a=rtpmap:102 H264/90000\na=fmtp:102 level-asymmetry-allowed=1;\
             packetization-mode={mode};profile-level-id=42e01f\n"
        )
    };
    let (mode0, mode1) = (h264(0), h264(1));
    let mut pc = default_peer()?;
    let refused = pc.set_remote_description(
        Instant::now(),
        two_bundled_video_sections(("102", &mode1), ("102", &mode0))?,
    );
    assert!(refused.is_err(), "{refused:?}");

    let mut pc = default_peer()?;
    pc.set_remote_description(Instant::now(), two_bundled_video_sections(vp8, vp8)?)?;
    let mut pc = default_peer()?;
    pc.set_remote_description(
        Instant::now(),
        two_bundled_video_sections(("102", &mode1), ("102", &mode1))?,
    )?;
    Ok(())
}
