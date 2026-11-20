//! An answer states the transceiver's [[Direction]] intersected with the reverse of the offered
//! direction (RFC 9429 section 5.3.1, RFC 3264 section 6.1), and applying an offer leaves
//! [[Direction]] alone (W3C 4.4.1.6): a remote peer that walks its transceiver through
//! sendonly, recvonly, inactive and back to sendrecv is answered recvonly, sendonly, inactive
//! and sendrecv, as a browser expects.

mod jsep_common;

use jsep_common::{TestResult, default_peer, exchange, media_sections, video_track};
use rtc::peer_connection::event::RTCPeerConnectionEvent;
use rtc::rtp_transceiver::{RTCRtpTransceiverDirection, RTCRtpTransceiverId};
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
            .set_direction(offer_dir);
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
            offer_dir
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
        .set_direction(RTCRtpTransceiverDirection::Sendonly);
    let (_, answer) = exchange(&mut offerer, &mut answerer)?;
    assert_eq!(direction_line(&answer), "a=recvonly", "{answer}");
    assert_eq!(
        count_negotiation_needed(&mut answerer),
        0,
        "a recvonly answer to a sendonly offer is settled"
    );
    Ok(())
}

fn count_negotiation_needed(pc: &mut rtc::peer_connection::RTCPeerConnection) -> usize {
    let mut count = 0;
    while let Some(event) = pc.poll_event() {
        if matches!(event, RTCPeerConnectionEvent::OnNegotiationNeededEvent) {
            count += 1;
        }
    }
    count
}
