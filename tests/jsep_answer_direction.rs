//! An answer states the transceiver's [[Direction]] intersected with the reverse of the offered
//! direction (RFC 9429 section 5.3.1, RFC 3264 section 6.1), and applying an offer leaves
//! [[Direction]] alone (W3C 4.4.1.6): a remote peer that walks its transceiver through
//! sendonly, recvonly, inactive and back to sendrecv is answered recvonly, sendonly, inactive
//! and sendrecv, as a browser expects.

mod jsep_common;

use jsep_common::{TestResult, default_peer, exchange, media_sections, video_track};
use rtci::peer_connection::event::RTCPeerConnectionEvent;
use rtci::rtp_transceiver::{RTCRtpTransceiverDirection, RTCRtpTransceiverId};
use sansio::Protocol;

fn direction_line(sdp: &str) -> String {
    media_sections(sdp)[0]
        .iter()
        .find(|l| {
            matches!(
                l.as_str(),
                "a=sendrecv" | "a=sendonly" | "a=recvonly" | "a=inactive"
            )
        })
        .cloned()
        .unwrap_or_else(|| panic!("a direction attribute in:\n{sdp}"))
}

#[test]
fn every_offered_direction_is_answered_with_its_complement() -> TestResult {
    let mut offerer = default_peer()?;
    let mut answerer = default_peer()?;
    let offered = offerer.add_track(video_track("offered", 0x0101_0101))?;
    let answering = answerer.add_track(video_track("answered", 0x0202_0202))?;

    let (_, answer) = exchange(&mut offerer, &mut answerer)?;
    assert_eq!(direction_line(&answer), "a=sendrecv", "{answer}");

    for (offer_dir, answer_dir) in [
        (RTCRtpTransceiverDirection::Sendonly, "a=recvonly"),
        (RTCRtpTransceiverDirection::Recvonly, "a=sendonly"),
        (RTCRtpTransceiverDirection::Inactive, "a=inactive"),
        (RTCRtpTransceiverDirection::Sendrecv, "a=sendrecv"),
    ] {
        offerer
            .rtp_transceiver(RTCRtpTransceiverId::from(offered))
            .expect("transceiver")
            .set_direction(offer_dir)
            .expect("the change is accepted");
        let (offer, answer) = exchange(&mut offerer, &mut answerer)?;
        assert_eq!(
            direction_line(&answer),
            answer_dir,
            "offer:\n{offer}\nanswer:\n{answer}"
        );
        // The answerer's own [[Direction]] is what its application set.
        assert_eq!(
            answerer
                .rtp_transceiver(RTCRtpTransceiverId::from(answering))
                .expect("transceiver")
                .direction(),
            RTCRtpTransceiverDirection::Sendrecv
        );
        // The offerer's [[CurrentDirection]] is the direction it offered.
        assert_eq!(
            offerer
                .rtp_transceiver(RTCRtpTransceiverId::from(offered))
                .expect("transceiver")
                .current_direction(),
            Some(offer_dir)
        );
    }
    Ok(())
}

/// An answer that states [[Direction]] intersected with the offered direction is what an answer
/// made now would state, so it needs no renegotiation (W3C "update the negotiation-needed flag",
/// step 5.3.3).
#[test]
fn a_one_way_answer_does_not_ask_for_renegotiation() -> TestResult {
    let mut offerer = default_peer()?;
    let mut answerer = default_peer()?;
    let offered = offerer.add_track(video_track("offered", 0x0101_0101))?;
    let _ = answerer.add_track(video_track("answered", 0x0202_0202))?;
    exchange(&mut offerer, &mut answerer)?;
    count_negotiation_needed(&mut answerer);

    offerer
        .rtp_transceiver(RTCRtpTransceiverId::from(offered))
        .expect("transceiver")
        .set_direction(RTCRtpTransceiverDirection::Sendonly)
        .expect("the change is accepted");
    let (_, answer) = exchange(&mut offerer, &mut answerer)?;
    assert_eq!(direction_line(&answer), "a=recvonly", "{answer}");
    assert_eq!(
        count_negotiation_needed(&mut answerer),
        0,
        "a recvonly answer to a sendonly offer is settled"
    );
    Ok(())
}

fn count_negotiation_needed(pc: &mut rtci::peer_connection::RTCPeerConnection) -> usize {
    let mut count = 0;
    while let Some(event) = pc.poll_event() {
        if matches!(event, RTCPeerConnectionEvent::OnNegotiationNeededEvent) {
            count += 1;
        }
    }
    count
}

/// W3C webrtc-pc 4.4.1.6: "If description is of type "answer" or "pranswer" ... Set
/// transceiver.[[CurrentDirection]] to direction": a provisional answer sets it too, on the
/// side that applies it locally and on the side that receives it.
#[test]
fn a_provisional_answer_sets_the_current_direction() -> TestResult {
    let now = std::time::Instant::now();
    let mut offerer = default_peer()?;
    let mut answerer = default_peer()?;
    let offered = offerer.add_track(video_track("offered", 0x0101_0301))?;
    let offer = offerer.create_offer(None)?;
    offerer.set_local_description(now, offer.clone())?;
    answerer.set_remote_description(now, offer)?;
    let answer = answerer.create_answer(None)?;
    let pranswer = rtci::peer_connection::sdp::RTCSessionDescription::pranswer(answer.sdp)?;
    answerer.set_local_description(now, pranswer.clone())?;
    let answering = answerer.get_transceivers().next().expect("a transceiver");
    assert_eq!(
        answerer
            .rtp_transceiver(answering)
            .expect("transceiver")
            .current_direction(),
        Some(RTCRtpTransceiverDirection::Recvonly),
        "the local pranswer's direction"
    );
    offerer.set_remote_description(now, pranswer)?;
    assert_eq!(
        offerer
            .rtp_transceiver(RTCRtpTransceiverId::from(offered))
            .expect("transceiver")
            .current_direction(),
        Some(RTCRtpTransceiverDirection::Sendonly),
        "the remote pranswer's direction, reversed"
    );
    Ok(())
}

/// RFC 8866 section 5.13: a session-level attribute applies "to all media descriptions
/// unless overridden"; section 6.7: with no direction attribute at either level, "sendrecv
/// SHOULD be assumed". A remote offer whose video section states no direction, with
/// `a=sendonly` at session level, gets a transceiver and is answered `a=recvonly`; without a
/// direction anywhere it is answered `a=sendrecv` (the answerer has a track to send); a
/// section's own direction wins over the session's.
#[test]
fn a_section_without_a_direction_takes_the_sessions_or_sendrecv() -> TestResult {
    use jsep_common::{SESSION, TRANSPORT, crlf};
    use rtci::peer_connection::sdp::RTCSessionDescription;
    use std::time::Instant;
    for (session_line, section_line, answered) in [
        ("a=sendonly\n", "", "a=recvonly"),
        ("", "", "a=sendrecv"),
        ("a=sendonly\n", "a=inactive\n", "a=inactive"),
    ] {
        let offer = crlf(&format!(
            "{SESSION}{session_line}m=video 9 UDP/TLS/RTP/SAVPF 96\n{TRANSPORT}a=mid:0\n\
             {section_line}a=rtpmap:96 VP8/90000\n"
        ));
        // A sending track, so that the answer shows the offered direction it reverses.
        let mut pc = default_peer()?;
        pc.add_track(video_track("local", 0x0909_0909))?;
        pc.set_remote_description(Instant::now(), RTCSessionDescription::offer(offer)?)?;
        // A transceiver serves the section (the track's, or a new one for a sendonly offer).
        let ids: Vec<RTCRtpTransceiverId> = pc.get_transceivers().collect();
        assert!(
            ids.into_iter().any(|id| pc
                .rtp_transceiver(id)
                .is_some_and(|t| t.mid().as_deref() == Some("0"))),
            "{session_line:?}"
        );
        let answer = pc.create_answer(None)?;
        assert_eq!(
            direction_line(&answer.sdp),
            answered,
            "{session_line:?} / {section_line:?}:\n{}",
            answer.sdp
        );
    }
    // A peer with no track of its own: the section without a direction gets a transceiver
    // (it used to be skipped, and the answer failed for want of one), answered recvonly.
    let offer = crlf(&format!(
        "{SESSION}m=video 9 UDP/TLS/RTP/SAVPF 96\n{TRANSPORT}a=mid:0\na=rtpmap:96 VP8/90000\n"
    ));
    let mut pc = default_peer()?;
    pc.set_remote_description(Instant::now(), RTCSessionDescription::offer(offer)?)?;
    assert_eq!(pc.get_transceivers().count(), 1);
    let answer = pc.create_answer(None)?;
    assert_eq!(direction_line(&answer.sdp), "a=recvonly", "{}", answer.sdp);
    Ok(())
}
