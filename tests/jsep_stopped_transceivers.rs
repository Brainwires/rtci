//! Stopped transceivers in offers and answers, and m-line recycling (W3C `stop()`,
//! RFC 9429 section 5.2.2).

mod jsep_common;

use std::time::Instant;

use jsep_common::{
    SESSION, TRANSPORT, TestResult, crlf, default_peer, exchange, media_sections, mid_of, port_of,
    video_track,
};
use rtc::peer_connection::sdp::RTCSessionDescription;
use rtc::rtp_transceiver::rtp_sender::RtpCodecKind;

/// A transceiver stopped before it ever had an m= section gets no mid and no m= section.
#[test]
fn a_stopped_transceiver_without_a_mid_gets_no_section() -> TestResult {
    let mut pc = default_peer()?;
    let kept = pc.add_transceiver_from_kind(RtpCodecKind::Video, None)?;
    let stopped = pc.add_transceiver_from_kind(RtpCodecKind::Video, None)?;
    pc.rtp_transceiver(stopped).expect("transceiver").stop()?;

    let offer = pc.create_offer(None)?;
    assert_eq!(media_sections(&offer.sdp).len(), 1, "{}", offer.sdp);
    assert!(
        pc.rtp_transceiver(kept)
            .expect("transceiver")
            .mid()
            .is_some()
    );
    assert!(
        pc.rtp_transceiver(stopped)
            .expect("transceiver")
            .mid()
            .is_none(),
        "a mid would make the stopped transceiver look associated"
    );
    Ok(())
}

/// An offer rejects a stopped transceiver's m= section (port 0, `a=inactive`, out of
/// BUNDLE); the next offer reuses that m= line for a new transceiver, with the new
/// transceiver's own mid.
#[test]
fn a_rejected_section_is_recycled_for_a_new_transceiver() -> TestResult {
    let mut offerer = default_peer()?;
    let mut answerer = default_peer()?;
    let first = offerer.add_track(video_track("first", 0x0e0f_0001))?;
    exchange(&mut offerer, &mut answerer)?;
    let first_id = rtc::rtp_transceiver::RTCRtpTransceiverId::from(first);
    let old_mid = offerer
        .rtp_transceiver(first_id)
        .expect("transceiver")
        .mid()
        .clone()
        .expect("negotiated, so it has a mid");

    offerer
        .rtp_transceiver(first_id)
        .expect("transceiver")
        .stop()?;
    let (offer, answer) = exchange(&mut offerer, &mut answerer)?;
    let offered = media_sections(&offer);
    assert_eq!(offered.len(), 1, "{offer}");
    assert_eq!(
        port_of(&offered[0]),
        0,
        "the stopped section is rejected:\n{offer}"
    );
    assert!(offered[0].iter().any(|l| l == "a=inactive"), "{offer}");
    assert!(
        !offer.lines().any(|l| l.starts_with("a=group:BUNDLE")
            && l.split_whitespace().skip(1).any(|m| m == old_mid)),
        "a rejected section is out of BUNDLE:\n{offer}"
    );
    assert_eq!(port_of(&media_sections(&answer)[0]), 0, "{answer}");

    let second = offerer.add_track(video_track("second", 0x0e0f_0002))?;
    let offer = offerer.create_offer(None)?;
    let sections = media_sections(&offer.sdp);
    assert_eq!(
        sections.len(),
        1,
        "the rejected m= line is reused, not a new one appended:\n{}",
        offer.sdp
    );
    assert_ne!(port_of(&sections[0]), 0, "{}", offer.sdp);
    let new_mid = offerer
        .rtp_transceiver(rtc::rtp_transceiver::RTCRtpTransceiverId::from(second))
        .expect("transceiver")
        .mid()
        .clone()
        .expect("the offer gave it a mid");
    assert_ne!(
        new_mid, old_mid,
        "the recycled m= line has the new transceiver's mid"
    );
    assert_eq!(
        mid_of(&sections[0]),
        Some(new_mid.as_str()),
        "{}",
        offer.sdp
    );
    Ok(())
}

/// A rejected m= section in a remote offer neither creates nor changes a transceiver, and is
/// answered rejected.
#[test]
fn a_rejected_remote_section_creates_no_transceiver() -> TestResult {
    let mut answerer = default_peer()?;
    let offer = crlf(&format!(
        "{SESSION}a=group:BUNDLE 1
m=video 0 UDP/TLS/RTP/SAVPF 96
{TRANSPORT}a=mid:0
a=inactive
a=rtpmap:96 VP8/90000
m=video 9 UDP/TLS/RTP/SAVPF 96
{TRANSPORT}a=mid:1
a=sendrecv
a=rtpmap:96 VP8/90000
"
    ));
    answerer.set_remote_description(Instant::now(), RTCSessionDescription::offer(offer)?)?;

    let mids: Vec<Option<String>> = answerer
        .get_transceivers()
        .collect::<Vec<_>>()
        .into_iter()
        .map(|id| {
            answerer
                .rtp_transceiver(id)
                .expect("transceiver")
                .mid()
                .clone()
        })
        .collect();
    assert_eq!(
        mids,
        vec![Some("1".to_owned())],
        "only the live section has a transceiver"
    );

    let answer = answerer.create_answer(None)?;
    let sections = media_sections(&answer.sdp);
    assert_eq!(sections.len(), 2, "{}", answer.sdp);
    assert_eq!(port_of(&sections[0]), 0, "{}", answer.sdp);
    assert_ne!(port_of(&sections[1]), 0, "{}", answer.sdp);
    Ok(())
}
