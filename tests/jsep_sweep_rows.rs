//! RFC 9429 rows the audit left `untested` though the behaviour was in place: a description
//! that does not parse or does not apply is refused and changes nothing (sections 5.5, 5.9),
//! `a=ice-options` is read and kept (5.8.1), `a=rtcp-mux` stays in later answers (5.3.2), and
//! a later offer lists the formats in the order of the most recent answer (5.2.2).

mod jsep_common;

use std::time::Instant;

use jsep_common::{TestResult, default_peer, exchange, media_sections, video_track};
use rtc::peer_connection::sdp::RTCSessionDescription;
use rtc::peer_connection::state::RTCSignalingState;

/// Section 5.5 (local) and 5.8: a description that does not parse is refused with an error
/// and the session is as it was (no pending description, still stable); section 5.9: one that
/// parses but is not the one this endpoint created (here with its media section removed) is
/// refused too.
#[test]
fn a_local_description_that_does_not_parse_or_apply_is_refused_and_changes_nothing() -> TestResult {
    let mut pc = default_peer()?;
    pc.add_track(video_track("v", 0x5e01_0101))?;
    let garbage = RTCSessionDescription::offer("v=0\r\nthis is not sdp\r\n".to_owned());
    if let Ok(garbage) = garbage {
        assert!(pc.set_local_description(Instant::now(), garbage).is_err());
    }
    assert_eq!(pc.signaling_state(), RTCSignalingState::Stable);
    assert!(pc.pending_local_description().is_none());

    let offer = pc.create_offer(None)?;
    let truncated = offer.sdp[..offer.sdp.find("\r\nm=").expect("a media section") + 2].to_owned();
    let edited = RTCSessionDescription::offer(truncated)?;
    assert!(pc.set_local_description(Instant::now(), edited).is_err());
    assert_eq!(pc.signaling_state(), RTCSignalingState::Stable);
    assert!(pc.pending_local_description().is_none());
    pc.set_local_description(Instant::now(), offer)?;
    assert_eq!(pc.signaling_state(), RTCSignalingState::HaveLocalOffer);
    Ok(())
}

/// Section 5.8.1: "Any 'a=ice-options' attributes MUST be parsed ... and the options stored":
/// every option of the remote description, the ones the engine does not act on included
/// (`ice-option-tag = 1*ice-char`, RFC 8839 section 5.6: letters, digits, `+` and `/`).
#[test]
fn remote_ice_options_are_parsed_and_stored() -> TestResult {
    let mut offerer = default_peer()?;
    let mut answerer = default_peer()?;
    offerer.add_track(video_track("v", 0x5e02_0101))?;
    let offer = offerer.create_offer(None)?;
    let sdp = offer.sdp.replace(
        "a=ice-options:trickle",
        "a=ice-options:trickle xfutureoption",
    );
    assert_ne!(sdp, offer.sdp, "the offer states ice-options");
    answerer.set_remote_description(Instant::now(), RTCSessionDescription::offer(sdp)?)?;
    let options = answerer.remote_ice_options();
    assert!(options.iter().any(|o| o == "trickle"), "{options:?}");
    assert!(options.iter().any(|o| o == "xfutureoption"), "{options:?}");
    Ok(())
}

/// Section 5.3.2: in an answer to a later offer, `a=rtcp-mux` is written for a section that
/// used RTP/RTCP multiplexing before.
#[test]
fn a_later_answer_keeps_rtcp_mux() -> TestResult {
    let mut offerer = default_peer()?;
    let mut answerer = default_peer()?;
    offerer.add_track(video_track("v", 0x5e03_0101))?;
    let (_, first) = exchange(&mut offerer, &mut answerer)?;
    let (_, second) = exchange(&mut offerer, &mut answerer)?;
    for answer in [first, second] {
        for section in media_sections(&answer) {
            assert!(section.iter().any(|l| l == "a=rtcp-mux"), "{answer}");
        }
    }
    Ok(())
}

/// Section 5.2.2: without codec preferences, "the media formats ... MUST be in the same order
/// as in the most recent answer": an answer that puts H.264 before VP8 makes the next offer
/// list them so.
#[test]
fn a_later_offer_lists_the_formats_in_the_order_of_the_last_answer() -> TestResult {
    let mut offerer = default_peer()?;
    let mut answerer = default_peer()?;
    let sender = offerer
        .add_transceiver_from_kind(rtc::rtp_transceiver::rtp_sender::RtpCodecKind::Video, None)?;
    let _ = sender;
    let now = Instant::now();
    let offer = offerer.create_offer(None)?;
    offerer.set_local_description(now, offer.clone())?;
    answerer.set_remote_description(now, offer)?;
    let answer = answerer.create_answer(None)?;
    answerer.set_local_description(now, answer.clone())?;
    // The answer, its m= line reordered: the last format first.
    let mut lines: Vec<String> = answer.sdp.split("\r\n").map(str::to_owned).collect();
    let m = lines
        .iter()
        .position(|l| l.starts_with("m=video"))
        .expect("a video section");
    let mut fields: Vec<String> = lines[m].split(' ').map(str::to_owned).collect();
    let first_media: Vec<String> = fields[3..].to_vec();
    let h264 = media_sections(&answer.sdp)[0]
        .iter()
        .find_map(|l| {
            l.strip_prefix("a=rtpmap:")
                .filter(|rest| rest.contains("H264/"))
                .and_then(|rest| rest.split(' ').next())
                .map(str::to_owned)
        })
        .expect("an H.264 format");
    let mut reordered = vec![h264.clone()];
    reordered.extend(first_media.into_iter().filter(|pt| *pt != h264));
    fields.truncate(3);
    fields.extend(reordered.iter().cloned());
    lines[m] = fields.join(" ");
    offerer.set_remote_description(now, RTCSessionDescription::answer(lines.join("\r\n"))?)?;

    let reoffer = offerer.create_offer(None)?;
    let formats: Vec<String> = media_sections(&reoffer.sdp)[0][0]
        .split(' ')
        .skip(3)
        .map(str::to_owned)
        .collect();
    assert_eq!(formats.first(), Some(&h264), "{}", reoffer.sdp);
    Ok(())
}
