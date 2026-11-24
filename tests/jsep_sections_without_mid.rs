//! A remote description whose m= sections have no `a=mid` (an endpoint that predates mids) is
//! applied, not refused: in an offer each section takes its index, in an answer the mid of our
//! m= section at the same position (RFC 9429 sections 5.10 and 5.11). The SDP text is kept as
//! given; only the parsed description gets the mids.

mod jsep_common;

use std::time::Instant;

use jsep_common::{
    SESSION, TRANSPORT, TestResult, crlf, default_peer, media_sections, mid_of, video_track,
};
use rtci::peer_connection::sdp::RTCSessionDescription;

#[test]
fn an_offer_without_mids_numbers_its_sections_by_index() -> TestResult {
    let mut answerer = default_peer()?;
    let offer = crlf(&format!(
        "{SESSION}m=video 9 UDP/TLS/RTP/SAVPF 96
{TRANSPORT}a=sendrecv
a=rtpmap:96 VP8/90000
"
    ));
    answerer.set_remote_description(Instant::now(), RTCSessionDescription::offer(offer)?)?;

    let transceivers: Vec<_> = answerer.get_transceivers().collect();
    assert_eq!(transceivers.len(), 1, "the section made a transceiver");
    let mid = answerer
        .rtp_transceiver(transceivers[0])
        .expect("transceiver")
        .mid()
        .clone();
    assert_eq!(mid.as_deref(), Some("0"));

    let answer = answerer.create_answer(None)?;
    let sections = media_sections(&answer.sdp);
    assert_eq!(sections.len(), 1, "{}", answer.sdp);
    assert_eq!(mid_of(&sections[0]), Some("0"), "{}", answer.sdp);
    Ok(())
}

#[test]
fn an_answer_without_mids_takes_ours_by_position() -> TestResult {
    let mut offerer = default_peer()?;
    let mut answerer = default_peer()?;
    offerer.add_track(video_track("video", 0x0d0e_0001))?;

    let now = Instant::now();
    let offer = offerer.create_offer(None)?;
    offerer.set_local_description(now, offer.clone())?;
    let offered_mid = mid_of(&media_sections(&offer.sdp)[0])
        .expect("our offer names a mid")
        .to_owned();
    answerer.set_remote_description(now, offer)?;
    let answer = answerer.create_answer(None)?;

    // The answer as an endpoint without mids writes it.
    let stripped: String = answer
        .sdp
        .lines()
        .filter(|line| !line.starts_with("a=mid:"))
        .map(|line| format!("{line}\r\n"))
        .collect();
    assert!(!stripped.contains("a=mid:"), "{stripped}");
    offerer.set_remote_description(now, RTCSessionDescription::answer(stripped.clone())?)?;

    let transceiver = offerer.get_transceivers().next().expect("our transceiver");
    let mid = offerer
        .rtp_transceiver(transceiver)
        .expect("transceiver")
        .mid()
        .clone();
    assert_eq!(mid, Some(offered_mid), "{stripped}");
    assert_eq!(
        offerer.remote_description().map(|d| d.sdp.clone()),
        Some(stripped),
        "the SDP text stays as given"
    );
    Ok(())
}

/// RFC 5888 section 6: "If the identification-tag attribute is not present in each "m" line
/// of the session description, grouping of media lines MUST NOT be performed." An offer with
/// one section lacking `a=mid` has its `a=group` lines ignored, though the numbers the engine
/// gives its sections would match them: the answer groups nothing.
#[test]
fn a_description_with_a_section_without_mid_is_not_grouped() -> TestResult {
    let mut answerer = default_peer()?;
    let offer = crlf(&format!(
        "{SESSION}a=group:BUNDLE 0 1
m=video 9 UDP/TLS/RTP/SAVPF 96
{TRANSPORT}a=mid:0
a=sendrecv
a=rtpmap:96 VP8/90000
m=video 9 UDP/TLS/RTP/SAVPF 96
{TRANSPORT}a=sendrecv
a=rtpmap:96 VP8/90000
"
    ));
    answerer.set_remote_description(Instant::now(), RTCSessionDescription::offer(offer)?)?;
    let answer = answerer.create_answer(None)?;
    assert!(!answer.sdp.contains("a=group:"), "{}", answer.sdp);
    let sections = media_sections(&answer.sdp);
    assert_eq!(sections.len(), 2, "{}", answer.sdp);
    assert_eq!(mid_of(&sections[1]), Some("1"), "{}", answer.sdp);
    Ok(())
}
