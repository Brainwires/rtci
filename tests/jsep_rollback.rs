//! A rollback undoes the pending offer whichever method carries it, and restores what the last
//! completed exchange negotiated (RFC 9429 section 5.7: "the same effect", "the state of the
//! session is restored"; W3C webrtc-pc "set a session description", the rollback steps): the
//! negotiated codecs, the transceivers' codecs and the repair flows of their encodings.

mod jsep_common;

use std::time::Instant;

use jsep_common::{
    SESSION, TRANSPORT, TestResult, crlf, default_peer, exchange, media_sections, video_track,
};
use rtc::peer_connection::RTCPeerConnection;
use rtc::peer_connection::event::RTCPeerConnectionEvent;
use rtc::peer_connection::sdp::RTCSessionDescription;
use rtc::peer_connection::state::RTCSignalingState;
use rtc::rtp_transceiver::rtp_sender::RtpCodecKind;
use rtc::rtp_transceiver::{
    RTCRtpTransceiverDirection, RTCRtpTransceiverId, RTCRtpTransceiverInit, SSRC,
};
use sansio::Protocol;

fn rollback() -> RTCSessionDescription {
    RTCSessionDescription::rollback(None).expect("a rollback description")
}

fn signaling_states(pc: &mut RTCPeerConnection) -> Vec<RTCSignalingState> {
    let mut states = vec![];
    while let Some(event) = pc.poll_event() {
        if let RTCPeerConnectionEvent::OnSignalingStateChangeEvent(state) = event {
            states.push(state);
        }
    }
    states
}

/// The formats of the first video m= line of `sdp`.
fn video_formats(sdp: &str) -> Vec<String> {
    media_sections(sdp)
        .iter()
        .find(|section| section[0].starts_with("m=video"))
        .map(|section| {
            section[0]
                .split_whitespace()
                .skip(3)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_else(|| panic!("a video section in:\n{sdp}"))
}

/// The RTX SSRC of the first encoding of the transceiver's sender.
fn rtx_ssrc(pc: &mut RTCPeerConnection, id: RTCRtpTransceiverId) -> Option<SSRC> {
    let sender = pc
        .rtp_transceiver(id)
        .expect("transceiver")
        .sender()
        .expect("sender");
    let mut sender = pc.rtp_sender(sender).expect("sender");
    sender.get_parameters().encodings[0]
        .rtp_coding_parameters
        .rtx
        .as_ref()
        .map(|rtx| rtx.ssrc)
}

#[test]
fn a_local_offer_is_rolled_back_through_set_remote_description() -> TestResult {
    let mut pc = default_peer()?;
    let sender = pc.add_track(video_track("local", 0x0101_0101))?;
    let id = RTCRtpTransceiverId::from(sender);
    let offer = pc.create_offer(None)?;
    pc.set_local_description(Instant::now(), offer)?;
    assert!(pc.rtp_transceiver(id).expect("transceiver").mid().is_some());

    pc.set_remote_description(Instant::now(), rollback())?;
    assert_eq!(
        signaling_states(&mut pc),
        vec![RTCSignalingState::HaveLocalOffer, RTCSignalingState::Stable]
    );
    assert!(pc.pending_local_description().is_none());
    assert!(
        pc.rtp_transceiver(id).expect("transceiver").mid().is_none(),
        "the transceiver the offer associated is disassociated"
    );

    // Stable again: a new offer can be made and applied.
    let offer = pc.create_offer(None)?;
    pc.set_local_description(Instant::now(), offer)?;
    Ok(())
}

#[test]
fn a_remote_offer_is_rolled_back_through_set_local_description() -> TestResult {
    let mut offerer = default_peer()?;
    offerer.add_track(video_track("offered", 0x0202_0202))?;
    let offer = offerer.create_offer(None)?;

    let mut pc = default_peer()?;
    pc.set_remote_description(Instant::now(), offer)?;
    assert_eq!(pc.get_transceivers().count(), 1);

    pc.set_local_description(Instant::now(), rollback())?;
    assert_eq!(
        signaling_states(&mut pc),
        vec![
            RTCSignalingState::HaveRemoteOffer,
            RTCSignalingState::Stable
        ]
    );
    assert!(pc.remote_description().is_none());
    assert_eq!(
        pc.get_transceivers().count(),
        0,
        "the transceiver the offer created is removed"
    );
    assert_eq!(pc.take_removed_transceivers(), vec![0]);
    Ok(())
}

/// A remote offer with fewer formats than this endpoint has (VP8 only, no RTX) narrows the
/// negotiated codecs and takes the RTX flow from the sender's encoding; rolling it back gives
/// both back, so the next local offer is the one the endpoint would have made before.
#[test]
fn a_rollback_restores_the_codecs_and_repair_flows_a_remote_offer_took() -> TestResult {
    let mut pc = default_peer()?;
    // A sending transceiver with no codec preferences: it offers every video codec.
    let id = pc.add_transceiver_from_kind(
        RtpCodecKind::Video,
        Some(RTCRtpTransceiverInit {
            direction: RTCRtpTransceiverDirection::Sendrecv,
            streams: vec![],
            send_encodings: vec![],
        }),
    )?;
    let rtx_before = rtx_ssrc(&mut pc, id).expect("the default video codecs carry RTX");
    let formats_before = video_formats(&pc.create_offer(None)?.sdp);
    assert!(formats_before.len() > 2, "{formats_before:?}");

    let offer = crlf(&format!(
        "{SESSION}a=group:BUNDLE 0
m=video 9 UDP/TLS/RTP/SAVPF 96
{TRANSPORT}a=mid:0
a=sendrecv
a=rtpmap:96 VP8/90000
"
    ));
    pc.set_remote_description(Instant::now(), RTCSessionDescription::offer(offer)?)?;
    assert_eq!(
        rtx_ssrc(&mut pc, id),
        None,
        "an offer without RTX leaves the encoding no repair flow"
    );

    pc.set_remote_description(Instant::now(), rollback())?;
    assert_eq!(rtx_ssrc(&mut pc, id), Some(rtx_before));
    let offer = pc.create_offer(None)?;
    assert_eq!(video_formats(&offer.sdp), formats_before, "{}", offer.sdp);
    assert!(
        offer.sdp.contains(&format!(" {rtx_before}\r\n"))
            && offer.sdp.contains("a=ssrc-group:FID "),
        "{}",
        offer.sdp
    );
    Ok(())
}

/// W3C `[[LastStableStateSctpTransport]]`: an offer does not create or change the SCTP
/// transport here (an answer does), so a rollback leaves `sctp()` as the last completed
/// exchange had it: absent before the first, present after one that negotiated data.
#[test]
fn a_rollback_leaves_the_sctp_transport_of_the_last_stable_state() -> TestResult {
    let mut a = default_peer()?;
    let mut b = default_peer()?;
    a.create_data_channel("data", None)?;
    let offer = a.create_offer(None)?;
    assert!(offer.sdp.contains("m=application"), "{}", offer.sdp);

    // The first offer, abandoned: no SCTP transport before, during or after.
    assert!(b.sctp().is_none());
    b.set_remote_description(Instant::now(), offer)?;
    assert!(b.sctp().is_none());
    b.set_remote_description(Instant::now(), rollback())?;
    assert!(b.sctp().is_none());

    exchange(&mut a, &mut b)?;
    let transport = b.sctp().expect("the exchange negotiated data").id();

    // A renegotiation, abandoned: the transport of the completed exchange stays.
    a.add_track(video_track("later", 0x0505_0505))?;
    let offer = a.create_offer(None)?;
    b.set_remote_description(Instant::now(), offer)?;
    b.set_local_description(Instant::now(), rollback())?;
    assert_eq!(b.sctp().expect("still negotiated").id(), transport);
    assert_eq!(b.get_transceivers().count(), 0);
    Ok(())
}

/// W3C `[[LastStableStateAssociatedRemoteMediaStreams]]`: a remote track is set up when an
/// answer is applied, so an abandoned re-offer that renames the stream changes nothing the
/// receiver reports.
#[test]
fn a_rollback_leaves_the_remote_track_of_the_last_stable_state() -> TestResult {
    let mut a = default_peer()?;
    let mut b = default_peer()?;
    a.add_track(video_track("first", 0x0606_0606))?;
    exchange(&mut a, &mut b)?;
    let id = b.get_transceivers().next().expect("transceiver");
    let receiver = b
        .rtp_transceiver(id)
        .expect("transceiver")
        .receiver()
        .expect("receiver");
    let track = |pc: &mut RTCPeerConnection| {
        let receiver = pc.rtp_receiver(receiver).expect("receiver");
        (
            receiver.track().stream_id().clone(),
            receiver.track().track_id().clone(),
        )
    };
    let before = track(&mut b);
    assert_eq!(before.0, "first-stream");

    let offer = a.create_offer(None)?;
    let renamed = offer.sdp.replace("first-stream", "second-stream");
    assert_ne!(renamed, offer.sdp);
    b.set_remote_description(Instant::now(), RTCSessionDescription::offer(renamed)?)?;
    b.set_remote_description(Instant::now(), rollback())?;
    assert_eq!(track(&mut b), before);
    assert!(
        b.rtp_transceiver(id).expect("transceiver").mid().is_some(),
        "a transceiver the last exchange associated keeps its mid"
    );
    Ok(())
}
