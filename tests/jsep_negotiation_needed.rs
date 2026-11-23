//! `RTCRtpTransceiver.stop()` and `RTCRtpSender.setStreams()` update the negotiation-needed
//! flag (W3C webrtc 5.4, 5.2), and a stopped transceiver stops asking once its m= section is
//! rejected, or if it never had one (W3C "check if negotiation is needed", steps 5.1, 5.2 and
//! 5.4). The msid check compares the sender's associated streams, not the track's stream id.

mod jsep_common;

use jsep_common::{TestResult, default_peer, exchange, media_sections, video_track};
use rtc::peer_connection::RTCPeerConnection;
use rtc::peer_connection::event::RTCPeerConnectionEvent;
use rtc::rtp_transceiver::rtp_sender::RtpCodecKind;
use rtc::rtp_transceiver::{RTCRtpSenderId, RTCRtpTransceiverId};
use rtc::sansio::Protocol;

/// Drains every queued event, returning how many were negotiation-needed.
fn negotiation_needed(pc: &mut RTCPeerConnection) -> usize {
    let mut count = 0;
    while let Some(event) = pc.poll_event() {
        if matches!(event, RTCPeerConnectionEvent::OnNegotiationNeededEvent) {
            count += 1;
        }
    }
    count
}

/// Two peers negotiated over one video track from the first; returns them and its sender.
fn negotiated()
-> Result<(RTCPeerConnection, RTCPeerConnection, RTCRtpSenderId), Box<dyn std::error::Error>> {
    let mut offerer = default_peer()?;
    let mut answerer = default_peer()?;
    let sender = offerer.add_track(video_track("video", 0x0909_0909))?;
    exchange(&mut offerer, &mut answerer)?;
    negotiation_needed(&mut offerer);
    negotiation_needed(&mut answerer);
    Ok((offerer, answerer, sender))
}

#[test]
fn stop_raises_negotiation_needed_and_settles_once_rejected() -> TestResult {
    let (mut offerer, mut answerer, sender) = negotiated()?;
    let id = RTCRtpTransceiverId::from(sender);

    offerer.rtp_transceiver(id).expect("transceiver").stop()?;
    assert_eq!(
        negotiation_needed(&mut offerer),
        1,
        "stop() updates the flag"
    );

    // Stopping again changes nothing.
    offerer.rtp_transceiver(id).expect("transceiver").stop()?;
    assert_eq!(negotiation_needed(&mut offerer), 0);

    let (offer, _) = exchange(&mut offerer, &mut answerer)?;
    assert!(
        media_sections(&offer)[0][0].starts_with("m=video 0 "),
        "{offer}"
    );
    assert_eq!(
        negotiation_needed(&mut offerer),
        0,
        "the stopped transceiver's section is rejected in both descriptions: nothing to do"
    );
    Ok(())
}

#[test]
fn a_stopped_transceiver_that_never_had_a_section_needs_none() -> TestResult {
    let (mut offerer, mut answerer, _) = negotiated()?;
    let unused = offerer.add_transceiver_from_kind(
        RtpCodecKind::Video,
        Some(rtc::rtp_transceiver::RTCRtpTransceiverInit::recvonly()),
    )?;
    offerer
        .rtp_transceiver(unused)
        .expect("transceiver")
        .stop()?;
    negotiation_needed(&mut offerer);

    for round in 1..=3 {
        exchange(&mut offerer, &mut answerer)?;
        assert_eq!(
            negotiation_needed(&mut offerer),
            0,
            "round {round}: a stopped transceiver without a mid has no m= section to negotiate"
        );
    }
    Ok(())
}

#[test]
fn set_streams_raises_negotiation_needed_until_the_msid_follows() -> TestResult {
    let (mut offerer, mut answerer, sender) = negotiated()?;

    offerer
        .rtp_sender(sender)
        .expect("sender")
        .set_streams(vec!["another-stream".to_owned()])
        .expect("the change is accepted");
    assert_eq!(
        negotiation_needed(&mut offerer),
        1,
        "setStreams updates the flag"
    );

    let (offer, _) = exchange(&mut offerer, &mut answerer)?;
    assert!(
        offer
            .lines()
            .any(|l| l.split(' ').next() == Some("a=msid:another-stream")),
        "{offer}"
    );
    assert_eq!(negotiation_needed(&mut offerer), 0);

    // The same streams again: the check finds nothing to negotiate.
    offerer
        .rtp_sender(sender)
        .expect("sender")
        .set_streams(vec!["another-stream".to_owned()])
        .expect("the change is accepted");
    assert_eq!(negotiation_needed(&mut offerer), 0);
    Ok(())
}
