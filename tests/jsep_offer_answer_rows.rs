//! RFC 3264, RFC 9143 and RFC 8858 clauses on the shape of generated offers and answers that
//! held by construction without a test: origin and timing lines, held streams, bundled
//! sections, rejected sections and identification tags.

mod jsep_common;

use std::time::Instant;

use jsep_common::{
    SESSION, TRANSPORT, TestResult, crlf, default_peer, exchange, media_sections, mid_of, port_of,
    video_track,
};
use rtci::peer_connection::RTCPeerConnection;
use rtci::peer_connection::configuration::media_engine::{MIME_TYPE_VP8, MIME_TYPE_VP9};
use rtci::peer_connection::sdp::RTCSessionDescription;
use rtci::rtp_transceiver::rtp_sender::{RTCRtpCodecParameters, RtpCodecKind};
use rtci::rtp_transceiver::{RTCRtpTransceiverDirection, RTCRtpTransceiverId};

fn line<'a>(sdp: &'a str, prefix: &str) -> &'a str {
    sdp.lines()
        .find_map(|l| l.strip_prefix(prefix))
        .unwrap_or_else(|| panic!("a {prefix} line in {sdp}"))
}

/// RFC 3264 section 5: the initial `<version>` is "less than (2**62)-1", `s=` "SHOULD" be a
/// dash (or a space) and `t=` "SHOULD" be `0 0`; section 6: the answer's origin differs from
/// the offer's ("MUST be different") and its `t=` equals the offer's.
#[test]
fn origin_session_name_and_time_lines() -> TestResult {
    let mut offerer = default_peer()?;
    let mut answerer = default_peer()?;
    offerer.add_track(video_track("v", 0x0e0d_0101))?;
    let (offer, answer) = exchange(&mut offerer, &mut answerer)?;
    let version: u64 = line(&offer, "o=")
        .split_whitespace()
        .nth(2)
        .expect("a version")
        .parse()?;
    assert!(version < (1 << 62) - 1);
    assert_eq!(line(&offer, "s="), "-");
    assert_eq!(line(&offer, "t="), "0 0");
    assert_ne!(line(&offer, "o="), line(&answer, "o="));
    assert_eq!(line(&answer, "t="), line(&offer, "t="));
    Ok(())
}

/// RFC 3264 section 8.4: a stream put on hold (sendonly, inactive) keeps a non-zero port.
#[test]
fn a_held_stream_keeps_its_port() -> TestResult {
    let mut offerer = default_peer()?;
    let mut answerer = default_peer()?;
    let sender = offerer.add_track(video_track("v", 0x0e0d_0201))?;
    exchange(&mut offerer, &mut answerer)?;
    for direction in [
        RTCRtpTransceiverDirection::Sendonly,
        RTCRtpTransceiverDirection::Inactive,
    ] {
        offerer
            .rtp_transceiver(sender.into())
            .expect("t")
            .set_direction(direction)?;
        let (offer, answer) = exchange(&mut offerer, &mut answerer)?;
        for sdp in [&offer, &answer] {
            assert_ne!(port_of(&media_sections(sdp)[0]), 0, "{direction}: {sdp}");
        }
    }
    Ok(())
}

/// RFC 3264 section 8: an offer whose version did not change is no change, and "a valid
/// answer" is generated to it: the same remote offer applied twice is answered both times.
#[test]
fn a_repeated_offer_is_taken_and_answered() -> TestResult {
    let offer = crlf(&format!(
        "{SESSION}m=video 9 UDP/TLS/RTP/SAVPF 96\n{TRANSPORT}a=mid:0\na=sendrecv\n\
         a=rtpmap:96 VP8/90000\n"
    ));
    let mut pc = default_peer()?;
    for _ in 0..2 {
        pc.set_remote_description(Instant::now(), RTCSessionDescription::offer(offer.clone())?)?;
        let answer = pc.create_answer(None)?;
        assert_eq!(media_sections(&answer.sdp).len(), 1, "{}", answer.sdp);
        pc.set_local_description(Instant::now(), answer)?;
    }
    Ok(())
}

/// RFC 9143 section 9.1: the `<proto>` of every bundled RTP section is the same; section
/// 9.3.1.2: no bundled section of an answer has `a=rtcp`; RFC 8858 section 3: `rtcp-mux-only`
/// is never a source attribute.
#[test]
fn bundled_sections_share_a_proto_and_answers_have_no_rtcp_line() -> TestResult {
    let mut offerer = default_peer()?;
    let mut answerer = default_peer()?;
    offerer.add_track(video_track("v", 0x0e0d_0301))?;
    offerer.add_transceiver_from_kind(RtpCodecKind::Audio, None)?;
    answerer.add_track(video_track("w", 0x0e0d_0302))?;
    let (offer, answer) = exchange(&mut offerer, &mut answerer)?;
    for sdp in [&offer, &answer] {
        let protos: Vec<String> = media_sections(sdp)
            .iter()
            .map(|s| s[0].split_whitespace().nth(2).expect("a proto").to_owned())
            .collect();
        assert!(protos.windows(2).all(|w| w[0] == w[1]), "{protos:?}");
        assert!(
            sdp.lines()
                .filter(|l| l.starts_with("a=ssrc:"))
                .all(|l| !l.contains("rtcp-mux-only")),
            "{sdp}"
        );
    }
    assert!(
        !answer.lines().any(|l| l.starts_with("a=rtcp:")),
        "{answer}"
    );
    Ok(())
}

/// RFC 9143 section 7.3.3: a section the answer rejects has no `a=bundle-only`; section 7.3:
/// a subsequent answer keeps the offerer-tagged section the tag (the first mid of the
/// group); section 7.2.1: the suggested offerer tag is a section unlikely to be rejected,
/// the first live one; section 17: identification tags are short (3 bytes or fewer).
#[test]
fn rejected_sections_tags_and_identification_tags() -> TestResult {
    let mut pc = default_peer()?;
    let offer = crlf(&format!(
        "{SESSION}a=group:BUNDLE 0 1\n\
         m=video 9 UDP/TLS/RTP/SAVPF 96\n{TRANSPORT}a=mid:0\na=sendrecv\na=rtpmap:96 VP8/90000\n\
         m=video 0 UDP/TLS/RTP/SAVPF 100\nc=IN IP4 0.0.0.0\na=bundle-only\na=mid:1\na=sendrecv\n\
         a=rtpmap:100 foo/90000\n"
    ));
    pc.set_remote_description(Instant::now(), RTCSessionDescription::offer(offer)?)?;
    let answer = pc.create_answer(None)?.sdp;
    let sections = media_sections(&answer);
    assert_eq!(port_of(&sections[1]), 0, "{answer}");
    assert!(
        !sections[1].iter().any(|l| l == "a=bundle-only"),
        "{answer}"
    );
    assert_eq!(line(&answer, "a=group:BUNDLE "), "0", "{answer}");

    let mut offerer = default_peer()?;
    let mut answerer = default_peer()?;
    offerer.add_track(video_track("v", 0x0e0d_0401))?;
    offerer.add_transceiver_from_kind(RtpCodecKind::Audio, None)?;
    let (offer, answer) = exchange(&mut offerer, &mut answerer)?;
    let first_live = mid_of(&media_sections(&offer)[0])
        .expect("a mid")
        .to_owned();
    assert!(line(&offer, "a=group:BUNDLE ").starts_with(&first_live));
    assert!(line(&answer, "a=group:BUNDLE ").starts_with(&first_live));
    offerer.add_transceiver_from_kind(RtpCodecKind::Video, None)?;
    let (reoffer, reanswer) = exchange(&mut offerer, &mut answerer)?;
    assert!(line(&reoffer, "a=group:BUNDLE ").starts_with(&first_live));
    assert!(line(&reanswer, "a=group:BUNDLE ").starts_with(&first_live));
    for section in media_sections(&reoffer) {
        assert!(mid_of(&section).expect("a mid").len() <= 3);
    }
    Ok(())
}

/// The registered video formats of `mimes`, in that order, with the engine's default payload
/// types (VP8 96, VP9 profile 0 98), as `setCodecPreferences` takes them.
fn video_preferences(
    mimes: &[&str],
) -> Result<Vec<RTCRtpCodecParameters>, Box<dyn std::error::Error>> {
    let mut fresh = default_peer()?;
    let sender = fresh.add_track(video_track("c", 0x0e0d_0601))?;
    let capabilities = fresh
        .rtp_sender(sender)
        .expect("sender")
        .get_capabilities(RtpCodecKind::Video)
        .expect("video capabilities")
        .codecs;
    Ok(mimes
        .iter()
        .map(|mime| RTCRtpCodecParameters {
            rtp_codec: capabilities
                .iter()
                .find(|c| c.mime_type.eq_ignore_ascii_case(mime))
                .expect("a capability")
                .clone(),
            payload_type: if *mime == MIME_TYPE_VP8 { 96 } else { 98 },
        })
        .collect())
}

/// The encoding names of a media section's formats, in order.
fn format_names(section: &[String]) -> Vec<String> {
    section[0]
        .split_whitespace()
        .skip(3)
        .filter_map(|pt| {
            let prefix = format!("a=rtpmap:{pt} ");
            section
                .iter()
                .find_map(|l| l.strip_prefix(prefix.as_str()))
                .map(|rtpmap| rtpmap.split('/').next().unwrap_or("").to_owned())
        })
        .collect()
}

/// RFC 9429 section 5.3.1: an offered section is answered rejected (port zero) when "There
/// is no offered media format that is both supported and, if applicable, allowed by codec
/// preferences". The offer has VP8 only; the answerer supports VP8 and VP9, and its
/// transceiver for the section prefers VP9 only: no offered format is allowed, so the section
/// is rejected, whether the transceiver only receives or the application attached a track to
/// it. Preferences that allow VP8 too accept the section.
#[test]
fn a_section_whose_offered_formats_the_codec_preferences_exclude_is_rejected() -> TestResult {
    for (preferred, with_track, rejected) in [
        (vec![MIME_TYPE_VP9], false, true),
        (vec![MIME_TYPE_VP9], true, true),
        (vec![MIME_TYPE_VP9, MIME_TYPE_VP8], false, false),
    ] {
        let case = format!("preferences {preferred:?}, a track attached: {with_track}");
        let mut offerer = default_peer()?;
        let sender = offerer.add_track(video_track("v", 0x0e0d_0501))?;
        offerer
            .rtp_transceiver(RTCRtpTransceiverId::from(sender))
            .expect("transceiver")
            .set_codec_preferences(video_preferences(&[MIME_TYPE_VP8])?)?;
        let offer = offerer.create_offer(None)?;
        offerer.set_local_description(Instant::now(), offer.clone())?;
        assert_eq!(
            format_names(&media_sections(&offer.sdp)[0]),
            vec!["VP8".to_owned()],
            "{case}: the offer has VP8 only: {}",
            offer.sdp
        );

        let mut answerer: RTCPeerConnection = default_peer()?;
        answerer.set_remote_description(Instant::now(), offer)?;
        if with_track {
            answerer.add_track(video_track("w", 0x0e0d_0502))?;
        }
        let id = answerer.get_transceivers().next().expect("a transceiver");
        answerer
            .rtp_transceiver(id)
            .expect("transceiver")
            .set_codec_preferences(video_preferences(&preferred)?)?;
        let answer = answerer.create_answer(None)?.sdp;
        let section = &media_sections(&answer)[0];
        if rejected {
            assert_eq!(port_of(section), 0, "{case}: rejected: {answer}");
        } else {
            assert_ne!(port_of(section), 0, "{case}: accepted: {answer}");
            assert!(
                format_names(section).contains(&"VP8".to_owned()),
                "{case}: with the offered VP8: {answer}"
            );
        }
    }
    Ok(())
}

/// RFC 9143 section 9.3.1.2: in an initial BUNDLE offer whose suggested offerer-tagged
/// section has `a=rtcp-mux-only`, "If the answerer rejects the "m=" section (Section 7.3.3),
/// the answerer MUST NOT include the attribute". That section (the first mid of the group) is
/// rejected for a format this endpoint does not support, for a media type it does not know
/// (`m=text` over RTP), and with its transceiver stopped before the answer: the answer's
/// rejected section has port zero and no `a=rtcp-mux-only`.
#[test]
fn a_rejected_suggested_offerer_tagged_section_has_no_rtcp_mux_only() -> TestResult {
    for (case, first, stop) in [
        (
            "an unsupported format",
            "video 9 UDP/TLS/RTP/SAVPF 100",
            false,
        ),
        (
            "an unknown media type",
            "text 9 UDP/TLS/RTP/SAVPF 100",
            false,
        ),
        (
            "its transceiver stopped",
            "video 9 UDP/TLS/RTP/SAVPF 96",
            true,
        ),
    ] {
        let rtpmap = if first.ends_with(" 96") {
            "96 VP8/90000"
        } else {
            "100 foo/90000"
        };
        let offer = crlf(&format!(
            "{SESSION}a=group:BUNDLE 0 1\n\
             m={first}\n{TRANSPORT}a=mid:0\na=sendrecv\na=rtcp-mux-only\na=rtpmap:{rtpmap}\n\
             m=video 9 UDP/TLS/RTP/SAVPF 96\n{TRANSPORT}a=mid:1\na=sendrecv\na=rtcp-mux-only\n\
             a=rtpmap:96 VP8/90000\n"
        ));
        let mut pc = default_peer()?;
        pc.set_remote_description(Instant::now(), RTCSessionDescription::offer(offer)?)?;
        if stop {
            let id = pc.get_transceivers().next().expect("a transceiver");
            pc.rtp_transceiver(id).expect("transceiver").stop()?;
        }
        let answer = pc.create_answer(None)?.sdp;
        let sections = media_sections(&answer);
        assert_eq!(mid_of(&sections[0]), Some("0"), "{case}: {answer}");
        assert_eq!(port_of(&sections[0]), 0, "{case}: rejected: {answer}");
        assert!(
            !sections[0].iter().any(|l| l == "a=rtcp-mux-only"),
            "{case}: the rejected section says rtcp-mux-only: {answer}"
        );
    }
    Ok(())
}
