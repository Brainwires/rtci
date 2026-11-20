//! Stopped transceivers in offers and answers, and m-line recycling (W3C `stop()`,
//! RFC 9429 section 5.2.2).

mod jsep_common;

use std::time::Instant;

use jsep_common::{
    SESSION, TRANSPORT, TestResult, crlf, default_peer, exchange, media_sections, mid_of, port_of,
    video_track,
};
use rtc::peer_connection::sdp::RTCSessionDescription;
use rtc::rtp_transceiver::RTCRtpTransceiverDirection;
use rtc::sansio::Protocol;
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

/// A rejected m= section in a remote offer gets a transceiver like every m= section (RFC 9429
/// section 5.10, W3C 4.4.1.6), created stopped and inactive, and is answered rejected.
#[test]
fn a_rejected_remote_section_creates_a_stopped_transceiver() -> TestResult {
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

    let transceivers: Vec<(Option<String>, bool, RTCRtpTransceiverDirection)> = answerer
        .get_transceivers()
        .collect::<Vec<_>>()
        .into_iter()
        .map(|id| {
            let t = answerer.rtp_transceiver(id).expect("transceiver");
            (t.mid().clone(), t.stopped(), t.direction())
        })
        .collect();
    assert_eq!(
        transceivers,
        vec![
            (
                Some("0".to_owned()),
                true,
                RTCRtpTransceiverDirection::Inactive
            ),
            (
                Some("1".to_owned()),
                false,
                RTCRtpTransceiverDirection::Recvonly
            ),
        ],
        "the rejected section's transceiver is stopped"
    );

    let answer = answerer.create_answer(None)?;
    let sections = media_sections(&answer.sdp);
    assert_eq!(sections.len(), 2, "{}", answer.sdp);
    assert_eq!(port_of(&sections[0]), 0, "{}", answer.sdp);
    assert_ne!(port_of(&sections[1]), 0, "{}", answer.sdp);
    Ok(())
}

/// The stopped transceiver a rejected remote section created goes with the offer when that offer
/// is rolled back (RFC 9429, Section 5.7), like the other transceivers it created.
#[test]
fn a_rejected_remote_sections_transceiver_goes_on_rollback() -> TestResult {
    let mut answerer = default_peer()?;
    let offer = crlf(&format!(
        "{SESSION}m=audio 0 UDP/TLS/RTP/SAVPF 111
{TRANSPORT}a=mid:0
a=inactive
a=rtpmap:111 opus/48000/2
"
    ));
    let now = Instant::now();
    answerer.set_remote_description(now, RTCSessionDescription::offer(offer)?)?;
    assert_eq!(answerer.get_transceivers().count(), 1);
    answerer.set_remote_description(now, RTCSessionDescription::rollback(None)?)?;
    assert_eq!(answerer.get_transceivers().count(), 0);
    Ok(())
}

/// After answering a remote offer whose section was rejected, the answerer's own next offer keeps
/// that section rejected in its place: the stopped transceiver neither revives it nor adds one.
#[test]
fn a_rejected_remote_section_stays_rejected_in_the_next_local_offer() -> TestResult {
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
    let now = Instant::now();
    answerer.set_remote_description(now, RTCSessionDescription::offer(offer)?)?;
    let answer = answerer.create_answer(None)?;
    answerer.set_local_description(now, answer)?;

    let next = answerer.create_offer(None)?;
    let sections = media_sections(&next.sdp);
    assert_eq!(sections.len(), 2, "{}", next.sdp);
    assert_eq!(mid_of(&sections[0]), Some("0"), "{}", next.sdp);
    assert_eq!(port_of(&sections[0]), 0, "{}", next.sdp);
    assert_eq!(mid_of(&sections[1]), Some("1"), "{}", next.sdp);
    assert_ne!(port_of(&sections[1]), 0, "{}", next.sdp);
    Ok(())
}

/// The `a=ice-ufrag` of a description.
fn ice_ufrag(sdp: &str) -> Option<String> {
    sdp.lines()
        .find_map(|line| line.strip_prefix("a=ice-ufrag:"))
        .map(str::to_owned)
}

/// After an exchange rejected every m= section (closing the transport), a remote offer with a
/// new m= section sets up a new transport. A peer that keeps one ICE ufrag/pwd per session
/// (Firefox) offers it with the old credentials; the answerer still starts a new ICE session,
/// so its answer carries new credentials instead of resuming the closed transport's.
#[test]
fn a_new_section_after_every_section_was_rejected_is_a_new_ice_session() -> TestResult {
    let mut answerer = default_peer()?;
    let now = Instant::now();
    let mut answer_to = |offer: String| -> Result<String, Box<dyn std::error::Error>> {
        answerer.set_remote_description(now, RTCSessionDescription::offer(crlf(&offer))?)?;
        let answer = answerer.create_answer(None)?;
        answerer.set_local_description(now, answer.clone())?;
        Ok(answer.sdp)
    };

    let first = answer_to(format!(
        "{SESSION}a=group:BUNDLE 0
m=video 9 UDP/TLS/RTP/SAVPF 96
{TRANSPORT}a=mid:0
a=sendrecv
a=rtpmap:96 VP8/90000
"
    ))?;
    let stopped = answer_to(format!(
        "{SESSION}m=video 0 UDP/TLS/RTP/SAVPF 96
{TRANSPORT}a=mid:0
a=inactive
a=rtpmap:96 VP8/90000
"
    ))?;
    assert_eq!(port_of(&media_sections(&stopped)[0]), 0, "{stopped}");
    let reopened = answer_to(format!(
        "{SESSION}a=group:BUNDLE 1
m=video 0 UDP/TLS/RTP/SAVPF 96
{TRANSPORT}a=mid:0
a=inactive
a=rtpmap:96 VP8/90000
m=audio 9 UDP/TLS/RTP/SAVPF 111
{TRANSPORT}a=mid:1
a=sendrecv
a=rtpmap:111 opus/48000/2
"
    ))?;

    let (first_ufrag, reopened_ufrag) = (ice_ufrag(&first), ice_ufrag(&reopened));
    assert!(first_ufrag.is_some(), "{first}");
    assert!(reopened_ufrag.is_some(), "{reopened}");
    assert_ne!(
        first_ufrag, reopened_ufrag,
        "the new transport is a new ICE session: {first}\n---\n{reopened}"
    );
    Ok(())
}

/// A remote offer with one live video section, mid 0.
fn live_video_offer() -> String {
    crlf(&format!(
        "{SESSION}a=group:BUNDLE 0
m=video 9 UDP/TLS/RTP/SAVPF 96
{TRANSPORT}a=mid:0
a=sendrecv
a=msid:remote-stream remote-track
a=ssrc:1111 cname:remote
a=rtpmap:96 VP8/90000
"
    ))
}

/// The same section, rejected (port 0).
fn rejected_video_offer() -> String {
    crlf(&format!(
        "{SESSION}m=video 0 UDP/TLS/RTP/SAVPF 96
{TRANSPORT}a=mid:0
a=inactive
a=rtpmap:96 VP8/90000
"
    ))
}

/// Whether `pc` has an `OnTrack` event waiting; drains its events.
fn fired_track(pc: &mut rtc::peer_connection::RTCPeerConnection) -> bool {
    let mut fired = false;
    while let Some(event) = pc.poll_event() {
        if matches!(
            event,
            rtc::peer_connection::event::RTCPeerConnectionEvent::OnTrack(_)
        ) {
            fired = true;
        }
    }
    fired
}

/// Answers `offer` on `pc` and applies the answer; returns the answer's SDP.
fn answer_offer(
    pc: &mut rtc::peer_connection::RTCPeerConnection,
    offer: String,
) -> Result<String, Box<dyn std::error::Error>> {
    let now = Instant::now();
    pc.set_remote_description(now, RTCSessionDescription::offer(offer)?)?;
    let answer = pc.create_answer(None)?;
    pc.set_local_description(now, answer.clone())?;
    Ok(answer.sdp)
}

/// A remote offer that rejects the m= section of an existing transceiver stops that
/// transceiver (W3C 4.4.1.6), without a track event, and the section is answered rejected.
#[test]
fn a_rejected_section_in_a_remote_offer_stops_its_transceiver() -> TestResult {
    let mut answerer = default_peer()?;
    answer_offer(&mut answerer, live_video_offer())?;
    let id = answerer.get_transceivers().next().expect("a transceiver");
    assert!(!answerer.rtp_transceiver(id).expect("transceiver").stopped());
    fired_track(&mut answerer);

    let now = Instant::now();
    answerer.set_remote_description(now, RTCSessionDescription::offer(rejected_video_offer())?)?;
    assert!(
        answerer.rtp_transceiver(id).expect("transceiver").stopped(),
        "the rejected section's transceiver is stopped"
    );
    assert!(!fired_track(&mut answerer), "no track event for a rejected section");
    let answer = answerer.create_answer(None)?;
    assert_eq!(port_of(&media_sections(&answer.sdp)[0]), 0, "{}", answer.sdp);
    Ok(())
}

/// A remote answer that rejects the m= section of one of our transceivers stops it (W3C
/// 4.4.1.6).
#[test]
fn a_rejected_section_in_a_remote_answer_stops_its_transceiver() -> TestResult {
    let mut offerer = default_peer()?;
    offerer.add_track(video_track("video", 0x0e0f_0011))?;
    let now = Instant::now();
    let offer = offerer.create_offer(None)?;
    offerer.set_local_description(now, offer.clone())?;
    let mid = mid_of(&media_sections(&offer.sdp)[0])
        .expect("a mid")
        .to_owned();

    let answer = crlf(&format!(
        "{SESSION}m=video 0 UDP/TLS/RTP/SAVPF 96
{}a=mid:{mid}
a=inactive
a=rtpmap:96 VP8/90000
",
        TRANSPORT.replace("a=setup:actpass", "a=setup:active")
    ));
    let id = offerer.get_transceivers().next().expect("a transceiver");
    offerer.set_remote_description(now, RTCSessionDescription::answer(answer)?)?;
    assert!(!fired_track(&mut offerer), "no track event for a rejected section");
    assert!(
        offerer.rtp_transceiver(id).expect("transceiver").stopped(),
        "stopped by the answer"
    );
    Ok(())
}

/// A rollback of a remote offer that stopped an existing transceiver leaves it stopped (the
/// stop algorithm is not undone) and does not remove it: the transceiver was not created by the
/// offer.
#[test]
fn a_rollback_leaves_a_transceiver_the_offer_stopped_stopped() -> TestResult {
    let mut answerer = default_peer()?;
    answer_offer(&mut answerer, live_video_offer())?;
    let now = Instant::now();
    answerer.set_remote_description(now, RTCSessionDescription::offer(rejected_video_offer())?)?;
    answerer.set_remote_description(now, RTCSessionDescription::rollback(None)?)?;
    let ids: Vec<_> = answerer.get_transceivers().collect();
    assert_eq!(ids.len(), 1);
    let t = answerer.rtp_transceiver(ids[0]).expect("transceiver");
    assert!(t.stopped());
    assert_eq!(t.mid().as_deref(), Some("0"), "still associated");
    Ok(())
}
