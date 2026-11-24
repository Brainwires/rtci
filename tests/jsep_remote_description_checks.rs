//! What a remote description must have to be applied, and what is ignored in it (RFC 9429
//! section 5.10, RFC 8839 section 5.1).

mod jsep_common;

use jsep_common::{SESSION, TRANSPORT, TestResult, crlf, default_peer};
use rtci::peer_connection::sdp::RTCSessionDescription;
use std::time::Instant;

/// A remote offer with one video section whose formats are `formats` and whose format
/// lines are `lines`.
fn video_offer(
    formats: &str,
    lines: &str,
) -> Result<RTCSessionDescription, rtci::shared::error::Error> {
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
    let offer = |groups: &str| -> Result<RTCSessionDescription, rtci::shared::error::Error> {
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
) -> Result<RTCSessionDescription, rtci::shared::error::Error> {
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

    // RFC 8859 appendix A: `a=rtcp-fb` is IDENTICAL-PER-PT as well: 96 with NACK in one
    // section and without it in the other is refused; the same feedback in another order is
    // the same.
    let with_feedback = |lines: &str| format!("a=rtpmap:96 VP8/90000\n{lines}");
    let (nack_pli, pli_nack, none) = (
        with_feedback("a=rtcp-fb:96 nack\na=rtcp-fb:96 nack pli\n"),
        with_feedback("a=rtcp-fb:96 nack pli\na=rtcp-fb:96 nack\n"),
        with_feedback(""),
    );
    let mut pc = default_peer()?;
    let refused = pc.set_remote_description(
        Instant::now(),
        two_bundled_video_sections(("96", &nack_pli), ("96", &none))?,
    );
    assert!(refused.is_err(), "{refused:?}");
    let mut pc = default_peer()?;
    pc.set_remote_description(
        Instant::now(),
        two_bundled_video_sections(("96", &nack_pli), ("96", &pli_nack))?,
    )?;

    let mut pc = default_peer()?;
    pc.set_remote_description(Instant::now(), two_bundled_video_sections(vp8, vp8)?)?;
    let mut pc = default_peer()?;
    pc.set_remote_description(
        Instant::now(),
        two_bundled_video_sections(("102", &mode1), ("102", &mode1))?,
    )?;
    Ok(())
}

/// RFC 8859 section 4.7: an IDENTICAL-PER-PT attribute "MUST" have the same value for a
/// payload type in every multiplexed section, and appendix A puts `a=imageattr` in that
/// category (section 5.17). A remote offer whose bundled sections give 96 two different
/// `a=imageattr` sets is refused; the same set, written for 96 in one section and as the `*`
/// wildcard in the other, is applied, and so is a payload type that only one section limits
/// when the other section does not use it.
#[test]
fn a_payload_type_with_two_image_attributes_in_one_bundle_group_refuses_the_description()
-> TestResult {
    let vp8 = |imageattr: &str| format!("a=rtpmap:96 VP8/90000\n{imageattr}");
    let small = vp8("a=imageattr:96 recv [x=[48:640],y=[48:480]]\n");
    let large = vp8("a=imageattr:96 recv [x=[48:1280],y=[48:720]]\n");
    let wildcard_small = vp8("a=imageattr:* recv [x=[48:640],y=[48:480]]\n");

    let mut pc = default_peer()?;
    let refused = pc.set_remote_description(
        Instant::now(),
        two_bundled_video_sections(("96", &small), ("96", &large))?,
    );
    assert!(refused.is_err(), "{refused:?}");
    let mut pc = default_peer()?;
    let refused = pc.set_remote_description(
        Instant::now(),
        two_bundled_video_sections(("96", &small), ("96", &vp8("")))?,
    );
    assert!(refused.is_err(), "{refused:?}");

    let mut pc = default_peer()?;
    pc.set_remote_description(
        Instant::now(),
        two_bundled_video_sections(("96", &small), ("96", &wildcard_small))?,
    )?;
    let vp9 = "a=rtpmap:98 VP9/90000\na=imageattr:98 recv [x=[48:1280],y=[48:720]]\n";
    let mut pc = default_peer()?;
    pc.set_remote_description(
        Instant::now(),
        two_bundled_video_sections(("96", &small), ("98", vp9))?,
    )?;
    Ok(())
}

/// RFC 9143 section 12: "the identifier used for a given extension MUST identify the same
/// extension across all the bundled media descriptions" (RFC 8859 appendix A: `extmap` is
/// SPECIAL, as RFC 8285 defines it). A remote offer whose bundled sections give id 3 to two
/// different extensions is refused; the same mapping in both, or different ids for different
/// extensions, is applied, and so is id 3 reused by a section outside the group.
#[test]
fn an_extension_id_naming_two_extensions_in_one_bundle_group_refuses_the_description() -> TestResult
{
    const MID: &str = "urn:ietf:params:rtp-hdrext:sdes:mid";
    const TOFFSET: &str = "urn:ietf:params:rtp-hdrext:toffset";
    const ABS_SEND_TIME: &str = "http://www.webrtc.org/experiments/rtp-hdrext/abs-send-time";
    let vp8 = |extmap: &str| format!("a=rtpmap:96 VP8/90000\n{extmap}");
    let conflicting = two_bundled_video_sections(
        ("96", &vp8(&format!("a=extmap:3 {TOFFSET}\n"))),
        (
            "96",
            &vp8(&format!("a=extmap:3/recvonly {ABS_SEND_TIME}\n")),
        ),
    )?;
    let refused = default_peer()?.set_remote_description(Instant::now(), conflicting);
    assert!(refused.is_err(), "{refused:?}");

    let same = format!("a=extmap:1 {MID}\na=extmap:3 {TOFFSET}\n");
    default_peer()?.set_remote_description(
        Instant::now(),
        two_bundled_video_sections(("96", &vp8(&same)), ("96", &vp8(&same)))?,
    )?;
    default_peer()?.set_remote_description(
        Instant::now(),
        two_bundled_video_sections(
            ("96", &vp8(&format!("a=extmap:3 {TOFFSET}\n"))),
            ("96", &vp8(&format!("a=extmap:4 {ABS_SEND_TIME}\n"))),
        )?,
    )?;

    // Two groups of one section each: an id means one extension within a group only.
    let ungrouped = RTCSessionDescription::offer(crlf(&format!(
        "{SESSION}a=group:BUNDLE 0\na=group:BUNDLE 1\n\
         m=video 9 UDP/TLS/RTP/SAVPF 96\n{TRANSPORT}a=mid:0\na=sendrecv\n{}\
         m=video 9 UDP/TLS/RTP/SAVPF 96\n{TRANSPORT}a=mid:1\na=sendrecv\n{}",
        vp8(&format!("a=extmap:3 {TOFFSET}\n")),
        vp8(&format!("a=extmap:3 {ABS_SEND_TIME}\n")),
    )))?;
    default_peer()?.set_remote_description(Instant::now(), ungrouped)?;
    Ok(())
}

/// RFC 7728 section 9: "There MUST NOT be more than one 'a=rtcp-fb' line with 'pause'
/// applicable to a single payload type in the SDP, unless the additional line uses '*'". A
/// remote offer with two `ccm pause` lines for 96, or two for `*`, is refused; one for 96 and
/// one for `*` (which then applies to the other formats) is applied.
#[test]
fn two_pause_lines_for_one_payload_type_refuse_the_description() -> TestResult {
    let vp8 = "a=rtpmap:96 VP8/90000\n";
    for lines in [
        "a=rtcp-fb:96 ccm pause\na=rtcp-fb:96 ccm pause nowait\n",
        "a=rtcp-fb:* ccm pause\na=rtcp-fb:* ccm pause config=2\n",
    ] {
        let refused = default_peer()?
            .set_remote_description(Instant::now(), video_offer("96", &format!("{vp8}{lines}"))?);
        assert!(refused.is_err(), "{lines}: {refused:?}");
    }
    default_peer()?.set_remote_description(
        Instant::now(),
        video_offer(
            "96",
            &format!("{vp8}a=rtcp-fb:96 ccm pause\na=rtcp-fb:* ccm pause config=2\n"),
        )?,
    )?;
    Ok(())
}

/// RFC 8866 section 5.7: "A session description MUST contain either at least one 'c=' line in
/// each media description or a single 'c=' line at the session level." A remote offer whose
/// section has no `c=`, with none at the session level, is refused; the same offer with the
/// `c=` at the session level is applied.
#[test]
fn a_section_without_connection_data_anywhere_refuses_the_description() -> TestResult {
    let transport = TRANSPORT.replace("c=IN IP4 0.0.0.0\n", "");
    let section = format!(
        "m=video 9 UDP/TLS/RTP/SAVPF 96\n{transport}a=mid:0\na=sendrecv\na=rtpmap:96 VP8/90000\n"
    );
    let refused = default_peer()?.set_remote_description(
        Instant::now(),
        RTCSessionDescription::offer(crlf(&format!("{SESSION}{section}")))?,
    );
    assert!(refused.is_err(), "{refused:?}");
    let session = SESSION.replace("t=0 0\n", "c=IN IP4 0.0.0.0\nt=0 0\n");
    default_peer()?.set_remote_description(
        Instant::now(),
        RTCSessionDescription::offer(crlf(&format!("{session}{section}")))?,
    )?;
    Ok(())
}
