//! W3C mediacapture-main sections 4.2 and 4.3 as the engine provides them to an API layer:
//! generated stream and track ids, `clone()` of a stream and of a track, and the track's
//! attributes and methods (`enabled`, `muted`, `stop()`, the capability, constraint and
//! settings getters). A receiver's track is the remote case (webrtc-pc 9.3).

use rtc::media_stream::{MediaStream, MediaStreamTrack, MediaStreamTrackState, generate_id};
use rtc::rtp_transceiver::rtp_sender::RtpCodecKind;

fn is_uuid_v4(id: &str) -> bool {
    let parts: Vec<&str> = id.split('-').collect();
    id.len() == 36
        && parts.iter().map(|p| p.len()).collect::<Vec<_>>() == [8, 4, 4, 4, 12]
        && id.chars().all(|c| c == '-' || c.is_ascii_hexdigit())
        && parts[2].starts_with('4')
        && matches!(parts[3].chars().next(), Some('8' | '9' | 'a' | 'b'))
}

/// mediacapture-main 4.2 and 4.3: a stream and a track created without an id get a
/// generated one (a UUID), each different; a new track is live, enabled and unmuted.
#[test]
fn streams_and_tracks_get_generated_ids() {
    let ids: Vec<String> = (0..64).map(|_| generate_id()).collect();
    assert!(ids.iter().all(|id| is_uuid_v4(id)), "{ids:?}");
    let mut unique = ids.clone();
    unique.sort();
    unique.dedup();
    assert_eq!(unique.len(), ids.len());

    let track = MediaStreamTrack::with_generated_id(
        "s".to_owned(),
        "camera".to_owned(),
        RtpCodecKind::Video,
        vec![],
    );
    assert!(is_uuid_v4(track.track_id()));
    assert_eq!(track.ready_state(), MediaStreamTrackState::Live);
    assert!(track.enabled());
    assert!(!track.muted());
    assert_eq!(track.label(), "camera");

    let stream = MediaStream::with_generated_id(vec![track.clone()]);
    assert!(is_uuid_v4(stream.stream_id()));
    assert_eq!(stream.get_tracks().count(), 1);
}

/// mediacapture-main 4.2 `clone()` and 4.3.3 `clone()`: a cloned stream has a new id and a
/// clone of each track; a cloned track has a new id and the same kind, label, ready state,
/// enabled flag and constraints as the original, which is left as it was.
#[test]
fn a_clone_has_a_new_id_and_the_same_state() {
    let mut audio = MediaStreamTrack::with_generated_id(
        "s".to_owned(),
        "mic".to_owned(),
        RtpCodecKind::Audio,
        vec![],
    );
    audio.set_enabled(false);
    let video = MediaStreamTrack::with_generated_id(
        "s".to_owned(),
        "cam".to_owned(),
        RtpCodecKind::Video,
        vec![],
    );
    let mut ended = video.clone_track();
    ended.stop();

    let clone = audio.clone_track();
    assert_ne!(clone.track_id(), audio.track_id());
    assert_eq!(clone.kind(), RtpCodecKind::Audio);
    assert_eq!(clone.label(), "mic");
    assert!(!clone.enabled(), "the enabled flag is cloned");
    assert_eq!(
        ended.clone_track().ready_state(),
        MediaStreamTrackState::Ended
    );

    let stream = MediaStream::new("original".to_owned(), vec![audio.clone(), video.clone()]);
    let cloned = stream.clone_stream();
    assert_ne!(cloned.stream_id(), stream.stream_id());
    let original_ids: Vec<&String> = stream.get_tracks().map(|t| t.track_id()).collect();
    let clone_ids: Vec<&String> = cloned.get_tracks().map(|t| t.track_id()).collect();
    assert_eq!(clone_ids.len(), 2);
    assert!(clone_ids.iter().all(|id| !original_ids.contains(id)));
    assert_eq!(
        cloned.get_tracks().map(|t| t.kind()).collect::<Vec<_>>(),
        vec![RtpCodecKind::Audio, RtpCodecKind::Video]
    );
    assert!(
        cloned
            .get_tracks()
            .all(|t| t.stream_id() == cloned.stream_id())
    );
    assert_eq!(
        stream.get_tracks().count(),
        2,
        "the original keeps its tracks"
    );
}

/// mediacapture-main 4.3.3: `enabled` reads what was set; `stop()` ends a live track and
/// leaves an ended one alone; the stopped track's stream is no longer active; the getters
/// return the stored values (a new local track has neither constraints nor settings).
#[test]
fn a_tracks_attributes_and_stop() {
    let mut track = MediaStreamTrack::with_generated_id(
        "s".to_owned(),
        "cam".to_owned(),
        RtpCodecKind::Video,
        vec![],
    );
    track.set_enabled(false);
    assert!(!track.enabled());
    track.set_enabled(true);
    assert!(track.enabled());
    assert!(!track.muted());
    track.set_muted(true);
    assert!(track.muted());

    assert!(track.get_settings().width().is_none());
    assert!(track.get_constraints().basic().width().is_none());
    assert!(track.get_constraints().advanced().is_empty());
    let _ = track.get_capabilities();

    let mut stream = MediaStream::new("s".to_owned(), vec![track.clone()]);
    assert!(stream.active());
    for track in stream.get_tracks_mut() {
        track.stop();
        assert_eq!(track.ready_state(), MediaStreamTrackState::Ended);
        track.stop();
        assert_eq!(track.ready_state(), MediaStreamTrackState::Ended);
    }
    assert!(!stream.active());
}
