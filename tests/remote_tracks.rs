//! Remote tracks by description, not by media (W3C webrtc-pc 4.4.1.6, 5.1.1 "process remote
//! tracks", 5.3 "create an RTCRtpReceiver", 5.4 "stop the RTCRtpTransceiver", 5.7, 9.1, 9.2):
//! the track event fires when a remote description makes a transceiver receive, with the
//! streams its `a=msid` lines name, whether or not media ever arrives; the receiver's track
//! has an id of the engine's own and starts muted; streams added later fire it again; a
//! description that stops the receiving removes the track from its streams; negotiation
//! (a rejected section, a rollback) ends the track. Signalling only: no transport is started.

mod jsep_common;

use std::time::Instant;

use jsep_common::{
    SESSION, TRANSPORT, TestResult, crlf, default_peer, exchange, media_sections, video_track,
};
use rtc::peer_connection::RTCPeerConnection;
use rtc::peer_connection::event::{
    RTCPeerConnectionEvent, RTCRemoteStreamsChange, RTCRemoteTrackEventInit, RTCTrackEvent,
};
use rtc::peer_connection::sdp::RTCSessionDescription;
use rtc::rtp_transceiver::rtp_sender::RtpCodecKind;
use rtc::rtp_transceiver::{
    RTCRtpReceiverId, RTCRtpSenderId, RTCRtpTransceiverDirection, RTCRtpTransceiverId,
    RTCRtpTransceiverInit,
};
use rtc::sansio::Protocol;

/// The track events `pc` has queued, other events dropped.
fn track_events(pc: &mut RTCPeerConnection) -> Vec<RTCTrackEvent> {
    let mut events = vec![];
    while let Some(event) = pc.poll_event() {
        if let RTCPeerConnectionEvent::OnTrack(event) = event {
            events.push(event);
        }
    }
    events
}

fn remote_tracks(events: &[RTCTrackEvent]) -> Vec<RTCRemoteTrackEventInit> {
    events
        .iter()
        .filter_map(|event| match event {
            RTCTrackEvent::OnRemoteTrack(init) => Some(init.clone()),
            _ => None,
        })
        .collect()
}

fn stream_changes(events: &[RTCTrackEvent]) -> Vec<RTCRemoteStreamsChange> {
    events
        .iter()
        .filter_map(|event| match event {
            RTCTrackEvent::OnStreamsChanged(change) => Some(change.clone()),
            _ => None,
        })
        .collect()
}

fn closed(events: &[RTCTrackEvent]) -> Vec<String> {
    events
        .iter()
        .filter_map(|event| match event {
            RTCTrackEvent::OnClose(track_id) => Some(track_id.clone()),
            _ => None,
        })
        .collect()
}

fn receiver_track(pc: &mut RTCPeerConnection, id: RTCRtpTransceiverId) -> (String, bool) {
    let receiver = pc.rtp_receiver(id.into()).expect("receiver");
    let track = receiver.track();
    (track.track_id().clone(), track.muted())
}

/// Two peers negotiated over one video track from the first, in streams `streams`.
fn negotiated(
    streams: &[&str],
) -> Result<(RTCPeerConnection, RTCPeerConnection, RTCRtpSenderId), Box<dyn std::error::Error>> {
    let mut offerer = default_peer()?;
    let mut answerer = default_peer()?;
    let sender = offerer.add_track(video_track("offered", 0x0f01_0101))?;
    offerer
        .rtp_sender(sender)
        .expect("sender")
        .set_streams(streams.iter().map(|s| (*s).to_owned()).collect())?;
    exchange(&mut offerer, &mut answerer)?;
    Ok((offerer, answerer, sender))
}

#[test]
fn the_track_event_fires_when_a_remote_offer_makes_the_transceiver_receive() -> TestResult {
    let mut offerer = default_peer()?;
    let sender = offerer.add_track(video_track("offered", 0x0f02_0202))?;
    offerer
        .rtp_sender(sender)
        .expect("sender")
        .set_streams(vec!["first".to_owned(), "second".to_owned()])?;
    let offer = offerer.create_offer(None)?;

    let mut answerer = default_peer()?;
    answerer.set_remote_description(Instant::now(), offer)?;
    let id = answerer.get_transceivers().next().expect("a transceiver");
    let (track_id, muted) = receiver_track(&mut answerer, id);
    let events = track_events(&mut answerer);
    assert_eq!(
        remote_tracks(&events),
        vec![RTCRemoteTrackEventInit {
            receiver_id: RTCRtpReceiverId::from(id),
            transceiver_id: id,
            track_id: track_id.clone(),
            stream_ids: vec!["first".to_owned(), "second".to_owned()],
        }],
        "one track event, at setRemoteDescription, with both msid streams"
    );
    assert_ne!(
        track_id, "offered",
        "the engine's own track id, not the msid's"
    );
    assert!(!track_id.is_empty());
    assert!(muted, "a receiver's track starts muted");
    assert_eq!(
        stream_changes(&events),
        vec![RTCRemoteStreamsChange {
            track_id,
            removed: vec![],
            added: vec!["first".to_owned(), "second".to_owned()],
        }]
    );
    // W3C 4.4.1.6: stream changes are reported before the track event.
    let position = |wanted: fn(&RTCTrackEvent) -> bool| events.iter().position(wanted);
    assert!(
        position(|e| matches!(e, RTCTrackEvent::OnStreamsChanged(_)))
            < position(|e| matches!(e, RTCTrackEvent::OnRemoteTrack(_)))
    );
    Ok(())
}

/// W3C 4.4.1.6, local answer: a section the answer no longer receives on takes the track
/// out of its streams, and receiving again later fires the track event again
/// ([[FiredDirection]] follows the answer).
#[test]
fn a_local_answer_that_stops_receiving_takes_the_track_out_of_its_streams() -> TestResult {
    let (mut offerer, mut answerer, _) = negotiated(&["a"])?;
    let id = answerer.get_transceivers().next().expect("a transceiver");
    let (track_id, _) = receiver_track(&mut answerer, id);
    track_events(&mut answerer);

    answerer
        .rtp_transceiver(id)
        .expect("transceiver")
        .set_direction(RTCRtpTransceiverDirection::Inactive)?;
    let (_, answer) = exchange(&mut offerer, &mut answerer)?;
    assert!(answer.contains("a=inactive"), "{answer}");
    let events = track_events(&mut answerer);
    assert_eq!(
        stream_changes(&events),
        vec![RTCRemoteStreamsChange {
            track_id: track_id.clone(),
            removed: vec!["a".to_owned()],
            added: vec![],
        }]
    );
    assert!(remote_tracks(&events).is_empty());

    answerer
        .rtp_transceiver(id)
        .expect("transceiver")
        .set_direction(RTCRtpTransceiverDirection::Recvonly)?;
    exchange(&mut offerer, &mut answerer)?;
    let events = remote_tracks(&track_events(&mut answerer));
    assert_eq!(events.len(), 1, "receiving again: {events:?}");
    assert_eq!(events[0].track_id, track_id);
    Ok(())
}

#[test]
fn no_track_event_for_a_section_the_remote_does_not_send() -> TestResult {
    let mut offerer = default_peer()?;
    offerer
        .add_transceiver_from_kind(RtpCodecKind::Video, Some(RTCRtpTransceiverInit::recvonly()))?;
    let offer = offerer.create_offer(None)?;
    let mut answerer = default_peer()?;
    answerer.set_remote_description(Instant::now(), offer)?;
    assert!(remote_tracks(&track_events(&mut answerer)).is_empty());
    Ok(())
}

/// The offerer, which applies the answer, fires the track event for the answerer's track.
#[test]
fn the_offerer_fires_the_track_event_when_the_answer_sends() -> TestResult {
    let mut offerer = default_peer()?;
    let mut answerer = default_peer()?;
    offerer.add_track(video_track("offered", 0x0f03_0303))?;
    answerer.add_track(video_track("answered", 0x0f04_0404))?;
    exchange(&mut offerer, &mut answerer)?;
    let events = remote_tracks(&track_events(&mut offerer));
    assert_eq!(events.len(), 1, "{events:?}");
    assert_eq!(events[0].stream_ids, vec!["answered-stream".to_owned()]);
    Ok(())
}

/// [[FiredDirection]]: the same description again fires nothing; a stream added fires the
/// track event again; a stream removed is reported; a direction that stops the receiving
/// leaves the streams, and receiving again fires the track event again.
#[test]
fn the_track_event_follows_fired_direction_and_added_streams() -> TestResult {
    let (mut offerer, mut answerer, sender) = negotiated(&["a"])?;
    let id = RTCRtpTransceiverId::from(sender);
    let answerer_id = answerer.get_transceivers().next().expect("a transceiver");
    let (track_id, _) = receiver_track(&mut answerer, answerer_id);
    track_events(&mut answerer);

    exchange(&mut offerer, &mut answerer)?;
    assert!(
        track_events(&mut answerer).is_empty(),
        "nothing changed, nothing fires"
    );

    let set_streams = |offerer: &mut RTCPeerConnection, streams: &[&str]| {
        offerer
            .rtp_sender(sender)
            .expect("sender")
            .set_streams(streams.iter().map(|s| (*s).to_owned()).collect())
            .expect("set_streams");
    };
    set_streams(&mut offerer, &["a", "b"]);
    exchange(&mut offerer, &mut answerer)?;
    let events = track_events(&mut answerer);
    assert_eq!(
        stream_changes(&events),
        vec![RTCRemoteStreamsChange {
            track_id: track_id.clone(),
            removed: vec![],
            added: vec!["b".to_owned()],
        }]
    );
    assert_eq!(remote_tracks(&events).len(), 1, "a stream was added");

    set_streams(&mut offerer, &["b"]);
    exchange(&mut offerer, &mut answerer)?;
    let events = track_events(&mut answerer);
    assert_eq!(
        stream_changes(&events),
        vec![RTCRemoteStreamsChange {
            track_id: track_id.clone(),
            removed: vec!["a".to_owned()],
            added: vec![],
        }]
    );
    assert!(remote_tracks(&events).is_empty(), "only a removal");

    offerer
        .rtp_transceiver(id)
        .expect("transceiver")
        .set_direction(RTCRtpTransceiverDirection::Recvonly)?;
    exchange(&mut offerer, &mut answerer)?;
    let events = track_events(&mut answerer);
    assert_eq!(
        stream_changes(&events),
        vec![RTCRemoteStreamsChange {
            track_id: track_id.clone(),
            removed: vec!["b".to_owned()],
            added: vec![],
        }],
        "a section the remote no longer sends takes the track out of its streams"
    );
    assert!(remote_tracks(&events).is_empty());

    offerer
        .rtp_transceiver(id)
        .expect("transceiver")
        .set_direction(RTCRtpTransceiverDirection::Sendrecv)?;
    exchange(&mut offerer, &mut answerer)?;
    let events = remote_tracks(&track_events(&mut answerer));
    assert_eq!(events.len(), 1, "receiving again fires the track event");
    assert_eq!(events[0].track_id, track_id, "the same track");
    assert_eq!(events[0].stream_ids, vec!["b".to_owned()]);
    Ok(())
}

#[test]
fn the_receivers_track_keeps_its_id_across_renegotiation() -> TestResult {
    let (mut offerer, mut answerer, sender) = negotiated(&["a"])?;
    let id = answerer.get_transceivers().next().expect("a transceiver");
    let (before, _) = receiver_track(&mut answerer, id);
    offerer
        .rtp_sender(sender)
        .expect("sender")
        .replace_track(Some(video_track("replacement", 0x0f05_0505)))?;
    offerer
        .rtp_sender(sender)
        .expect("sender")
        .set_streams(vec!["c".to_owned()])?;
    exchange(&mut offerer, &mut answerer)?;
    assert_eq!(receiver_track(&mut answerer, id).0, before);
    Ok(())
}

/// RFC 9429 5.8: a section without `a=msid` is in the session's "default" stream, one id
/// for every such section; `a=msid:-` is no stream.
#[test]
fn a_section_without_msid_is_in_the_sessions_default_stream() -> TestResult {
    let section = |mid: &str, msid: &str| {
        format!(
            "m=video 9 UDP/TLS/RTP/SAVPF 96
{TRANSPORT}a=mid:{mid}
a=sendonly
{msid}a=rtpmap:96 VP8/90000
"
        )
    };
    let offer = crlf(&format!(
        "{SESSION}a=group:BUNDLE 0 1 2\n{}{}{}",
        section("0", ""),
        section("1", ""),
        section("2", "a=msid:- track\n"),
    ));
    let mut pc = default_peer()?;
    pc.set_remote_description(Instant::now(), RTCSessionDescription::offer(offer)?)?;
    let events = remote_tracks(&track_events(&mut pc));
    assert_eq!(events.len(), 3, "{events:?}");
    assert_eq!(events[0].stream_ids.len(), 1);
    assert!(!events[0].stream_ids[0].is_empty());
    assert_eq!(
        events[1].stream_ids, events[0].stream_ids,
        "one default stream"
    );
    assert!(events[2].stream_ids.is_empty(), "`-` is no stream");
    Ok(())
}

/// A remote offer that rejects a section stops its transceiver, and that ends the receiver's
/// track (W3C 5.4 "stop sending and receiving").
#[test]
fn a_rejected_section_ends_the_receivers_track() -> TestResult {
    let (mut offerer, mut answerer, sender) = negotiated(&["a"])?;
    let id = answerer.get_transceivers().next().expect("a transceiver");
    let (track_id, _) = receiver_track(&mut answerer, id);
    track_events(&mut answerer);

    offerer
        .rtp_transceiver(sender.into())
        .expect("transceiver")
        .stop()?;
    let offer = offerer.create_offer(None)?;
    offerer.set_local_description(Instant::now(), offer.clone())?;
    assert_eq!(
        media_sections(&offer.sdp)[0][0].split_whitespace().nth(1),
        Some("0")
    );
    answerer.set_remote_description(Instant::now(), offer)?;
    let events = track_events(&mut answerer);
    assert_eq!(closed(&events), vec![track_id.clone()], "{events:?}");
    assert_eq!(
        stream_changes(&events),
        vec![RTCRemoteStreamsChange {
            track_id,
            removed: vec!["a".to_owned()],
            added: vec![],
        }]
    );
    Ok(())
}

/// Rolling back the remote offer that created a transceiver removes it, and its track ends;
/// a transceiver that was there before goes back to the streams it had.
#[test]
fn a_rollback_ends_the_track_of_a_transceiver_it_removes_and_restores_streams() -> TestResult {
    let (mut offerer, mut answerer, sender) = negotiated(&["a"])?;
    let kept = answerer.get_transceivers().next().expect("a transceiver");
    let (kept_track, _) = receiver_track(&mut answerer, kept);
    track_events(&mut answerer);

    offerer
        .rtp_sender(sender)
        .expect("sender")
        .set_streams(vec!["z".to_owned()])?;
    offerer.add_track(video_track("second", 0x0f06_0606))?;
    let offer = offerer.create_offer(None)?;
    answerer.set_remote_description(Instant::now(), offer)?;
    let added = answerer
        .get_transceivers()
        .nth(1)
        .expect("a new transceiver");
    let (added_track, _) = receiver_track(&mut answerer, added);
    let events = track_events(&mut answerer);
    assert_eq!(
        remote_tracks(&events).len(),
        2,
        "z was added, and a new track"
    );

    answerer.set_remote_description(Instant::now(), RTCSessionDescription::rollback(None)?)?;
    let events = track_events(&mut answerer);
    assert_eq!(closed(&events), vec![added_track], "{events:?}");
    assert!(
        stream_changes(&events).contains(&RTCRemoteStreamsChange {
            track_id: kept_track,
            removed: vec!["z".to_owned()],
            added: vec!["a".to_owned()],
        }),
        "{events:?}"
    );
    assert_eq!(answerer.get_transceivers().count(), 1);
    Ok(())
}
