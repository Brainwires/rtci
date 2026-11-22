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
///
/// The transport part holds by construction, not by a restore step: nothing an offer does
/// touches the transport. Before the rollback work this test failed for the method alone (a
/// remote offer could not be rolled back through `set_local_description`); what it keeps
/// true since is that applying an offer (one with a data section, or one that renumbers it)
/// never starts or replaces the transport without the rollback undoing it.
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
    let a_transport = a.sctp().expect("the exchange negotiated data").id();

    // A renegotiation, abandoned: the transport of the completed exchange stays.
    a.add_track(video_track("later", 0x0505_0505))?;
    let offer = a.create_offer(None)?;
    b.set_remote_description(Instant::now(), offer)?;
    b.set_local_description(Instant::now(), rollback())?;
    assert_eq!(b.sctp().expect("still negotiated").id(), transport);
    assert_eq!(b.get_transceivers().count(), 0);

    // An abandoned re-offer with another `a=sctp-port`, which an answer would replace the
    // association for (RFC 8841 section 10.5): rolled back, it replaces nothing.
    let offer = a.create_offer(None)?;
    let port: u16 = offer
        .sdp
        .lines()
        .find_map(|l| l.strip_prefix("a=sctp-port:"))
        .expect("an sctp-port")
        .parse()?;
    let replacing = offer.sdp.replace(
        &format!("a=sctp-port:{port}\r\n"),
        &format!("a=sctp-port:{}\r\n", port + 1),
    );
    assert_ne!(replacing, offer.sdp);
    b.set_remote_description(Instant::now(), RTCSessionDescription::offer(replacing)?)?;
    assert_eq!(b.sctp().expect("an offer replaces nothing").id(), transport);
    b.set_remote_description(Instant::now(), rollback())?;
    assert_eq!(b.sctp().expect("still negotiated").id(), transport);

    // And the exchange that follows keeps the transport of the last stable state.
    exchange(&mut a, &mut b)?;
    assert_eq!(b.sctp().expect("renegotiated").id(), transport);
    assert_eq!(a.sctp().expect("negotiated").id(), a_transport);

    // The offerer's side: its own offer, applied and rolled back, creates no transport.
    let mut c = default_peer()?;
    c.create_data_channel("data", None)?;
    let offer = c.create_offer(None)?;
    c.set_local_description(Instant::now(), offer)?;
    assert!(c.sctp().is_none());
    c.set_local_description(Instant::now(), rollback())?;
    assert!(c.sctp().is_none());
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

/// The signaling state, as the pending descriptions show it.
fn pending(pc: &RTCPeerConnection) -> RTCSignalingState {
    match (
        pc.pending_local_description().is_some(),
        pc.pending_remote_description().is_some(),
    ) {
        (false, false) => RTCSignalingState::Stable,
        (true, false) => RTCSignalingState::HaveLocalOffer,
        (false, true) => RTCSignalingState::HaveRemoteOffer,
        (true, true) => panic!("two pending descriptions"),
    }
}

fn peer_with_explicit_rollback_only() -> Result<RTCPeerConnection, Box<dyn std::error::Error>> {
    use rtc::peer_connection::RTCPeerConnectionBuilder;
    use rtc::peer_connection::configuration::media_engine::MediaEngine;
    use rtc::peer_connection::configuration::setting_engine::SettingEngineBuilder;
    let mut media_engine = MediaEngine::default();
    media_engine.register_default_codecs()?;
    Ok(RTCPeerConnectionBuilder::new()
        .with_media_engine(media_engine)
        .with_setting_engine(
            SettingEngineBuilder::new()
                .with_implicit_rollback(false)
                .build(),
        )
        .build(Instant::now())?)
}

/// W3C webrtc-pc section 4.4.2 (`setRemoteDescription`): a remote offer that arrives while a
/// local offer is pending
/// rolls the local offer back and is applied, in one call; that is the default. RFC 9429
/// sections 5.6 and 5.7 leave the rollback to the application, which is
/// `SettingEngineBuilder::with_implicit_rollback(false)`: the offer is then refused until
/// the application has rolled its own back.
#[test]
fn a_remote_offer_over_a_local_offer_rolls_it_back_unless_rollback_is_left_to_the_application()
-> TestResult {
    let glare =
        |pc: &mut RTCPeerConnection| -> Result<RTCSessionDescription, Box<dyn std::error::Error>> {
            let mut other = default_peer()?;
            other.add_track(video_track("theirs", 0x0909_0909))?;
            let theirs = other.create_offer(None)?;
            pc.add_track(video_track("ours", 0x0808_0808))?;
            let ours = pc.create_offer(None)?;
            pc.set_local_description(Instant::now(), ours)?;
            signaling_states(pc);
            Ok(theirs)
        };

    // Rollback left to the application: RFC 9429's state machine with nothing added.
    let mut pc = peer_with_explicit_rollback_only()?;
    let theirs = glare(&mut pc)?;
    assert!(
        pc.set_remote_description(Instant::now(), theirs.clone())
            .is_err()
    );
    assert_eq!(pending(&pc), RTCSignalingState::HaveLocalOffer);
    assert!(pc.pending_local_description().is_some());
    // Rolled back by the application, the offer is taken.
    pc.set_local_description(Instant::now(), rollback())?;
    pc.set_remote_description(Instant::now(), theirs)?;
    assert_eq!(pending(&pc), RTCSignalingState::HaveRemoteOffer);

    // The implicit rollback, the default.
    let mut pc = default_peer()?;
    let theirs = glare(&mut pc)?;
    pc.set_remote_description(Instant::now(), theirs)?;
    assert_eq!(pending(&pc), RTCSignalingState::HaveRemoteOffer);
    assert!(pc.pending_local_description().is_none());
    assert!(pc.pending_remote_description().is_some());
    assert_eq!(
        signaling_states(&mut pc),
        vec![
            RTCSignalingState::Stable,
            RTCSignalingState::HaveRemoteOffer
        ]
    );
    let answer = pc.create_answer(None)?;
    pc.set_local_description(Instant::now(), answer)?;
    assert_eq!(pending(&pc), RTCSignalingState::Stable);

    // A remote offer that is refused rolls nothing back.
    let mut pc = default_peer()?;
    let theirs = glare(&mut pc)?;
    let without_fingerprint: String = theirs
        .sdp
        .split_inclusive("\r\n")
        .filter(|line| !line.starts_with("a=fingerprint:"))
        .collect();
    assert_ne!(without_fingerprint, theirs.sdp);
    assert!(
        pc.set_remote_description(
            Instant::now(),
            RTCSessionDescription::offer(without_fingerprint)?
        )
        .is_err()
    );
    assert_eq!(pending(&pc), RTCSignalingState::HaveLocalOffer);
    assert!(pc.pending_local_description().is_some());
    assert!(signaling_states(&mut pc).is_empty());
    Ok(())
}
