//! RFC 3264, RFC 9143 and RFC 8858 clauses on the shape of generated offers and answers that
//! held by construction without a test: origin and timing lines, held streams, bundled
//! sections, rejected sections and identification tags.

mod jsep_common;

use std::time::Instant;

use jsep_common::{
    SESSION, TRANSPORT, TestResult, crlf, default_peer, exchange, media_sections, mid_of, port_of,
    video_track,
};
use rtc::peer_connection::sdp::RTCSessionDescription;
use rtc::rtp_transceiver::RTCRtpTransceiverDirection;
use rtc::rtp_transceiver::rtp_sender::RtpCodecKind;

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
