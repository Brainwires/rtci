# W3C Media Capture and Streams (mediacapture-main): the parts webrtc-pc depends on

Spec: Media Capture and Streams, W3C Editor's Draft at https://w3c.github.io/mediacapture-main/ (served copy last modified 19 November 2026). Engine: fork master 8916bc3.

Scope: only section 4, the MediaStream and MediaStreamTrack model that webrtc-pc uses for track and stream identity (ids, kind, label, enabled, muted, readyState, the track set of a stream). Capture devices, getUserMedia, permissions, device enumeration, media elements and the constrainable pattern's selection algorithm are outside an engine with no capture and are not enumerated. Sections: 4.2 MediaStream, 4.3 MediaStreamTrack (4.3.1 media flow and life-cycle, 4.3.3 interface), 4.4 MediaStreamTrackEvent. What webrtc-pc itself adds for remote tracks is audited in `w3c-webrtc-pc.md` section 9.

`src/media_stream/mod.rs` has unit tests for the track set and `active`; other `tested` rows cite tests elsewhere that depend on the behaviour.

Totals:

- MUST: tested 25 / untested 1 / partial 1 / missing 0 / violated 0 / n-a 1
- SHOULD: tested 0 / untested 0 / partial 0 / missing 0 / violated 0 / n-a 0
- MAY: tested 0 / untested 0 / partial 0 / missing 0 / violated 0 / n-a 0

| ID | § | Level | Clause (short paraphrase) | Verdict | Code | Test | Note |
|---|---|---|---|---|---|---|---|
| MEDIACAP-4.2-1 | 4.2 | MUST | A stream's track set holds the tracks of the stream | tested | `src/media_stream/mod.rs:248` | `a_streams_tracks_of_one_stream_id_are_all_kept` | Audit finding confirmed by reading; keyed by track id now |
| MEDIACAP-4.2-2 | 4.2 | MUST | MediaStream.id returns the value the stream was created with | tested | `src/media_stream/mod.rs:271` | `a_streams_tracks_of_one_stream_id_are_all_kept` | - |
| MEDIACAP-4.2-3 | 4.2 | MUST | A new stream gets a generated id unless a special-purpose algorithm (remote streams) sets it | tested | `src/media_stream/mod.rs` (generate_id, MediaStream::with_generated_id) | `streams_and_tracks_get_generated_ids` | a UUID (version 4); `new` still takes the caller's id (remote streams) |
| MEDIACAP-4.2-4 | 4.2 | MUST | MediaStream.active is true while at least one track is not ended | tested | `src/media_stream/mod.rs:282` | `a_stream_is_active_while_a_track_has_not_ended` | - |
| MEDIACAP-4.2-5 | 4.2 | MUST | getAudioTracks returns the audio tracks of the set | tested | `src/media_stream/mod.rs:306` | `a_streams_tracks_of_one_stream_id_are_all_kept` | - |
| MEDIACAP-4.2-6 | 4.2 | MUST | getVideoTracks returns the video tracks of the set | tested | `src/media_stream/mod.rs:341` | `a_streams_tracks_of_one_stream_id_are_all_kept` | - |
| MEDIACAP-4.2-7 | 4.2 | MUST | getTracks returns every track of the set | tested | `src/media_stream/mod.rs:374` | `a_streams_tracks_of_one_stream_id_are_all_kept` | - |
| MEDIACAP-4.2-8 | 4.2 | MUST | getTrackById returns the track with that id, or null | tested | `src/media_stream/mod.rs:416` | `a_streams_tracks_of_one_stream_id_are_all_kept` | - |
| MEDIACAP-4.2-9 | 4.2 | MUST | addTrack: a track already in the set is not added again; otherwise it is added | tested | `src/media_stream/mod.rs:487` | `a_streams_tracks_of_one_stream_id_are_all_kept` | - |
| MEDIACAP-4.2-10 | 4.2 | MUST | removeTrack: removes the track if it is in the set | tested | `src/media_stream/mod.rs:534` | `a_streams_tracks_of_one_stream_id_are_all_kept` | - |
| MEDIACAP-4.2-11 | 4.2 | MUST | Adding or removing a track on the user agent's initiative fires addtrack / removetrack | tested | `src/peer_connection/remote_tracks.rs:198` | `the_track_event_follows_fired_direction_and_added_streams`, `a_rollback_ends_the_track_of_a_transceiver_it_removes_and_restores_streams` | For remote streams: RTCTrackEvent::OnStreamsChanged (the engine keeps no MediaStream objects of its own) |
| MEDIACAP-4.2-12 | 4.2 | MUST | clone(): a new stream with a new id and clones of the tracks | tested | `src/media_stream/mod.rs` (clone_stream) | `a_clone_has_a_new_id_and_the_same_state` |  |
| MEDIACAP-4.3-1 | 4.3 | MUST | A track is created with a generated [[Id]], its [[Kind]], [[Label]], [[ReadyState]] "live", [[Enabled]] true and its source's [[Muted]] | tested | `src/media_stream/track.rs` (with_generated_id) | `streams_and_tracks_get_generated_ids` | live, enabled, unmuted; the label is the caller's |
| MEDIACAP-4.3-2 | 4.3 | MUST | Cloning a track gives a new id, the same source, kind, label, state, enabled flag and constraints | tested | `src/media_stream/track.rs` (clone_track) | `a_clone_has_a_new_id_and_the_same_state` | same codings (the source) |
| MEDIACAP-4.3.1-1 | 4.3.1 | MUST | No live samples are made available while a track is muted | n/a | - | - | Samples are the application's |
| MEDIACAP-4.3.1-2 | 4.3.1 | MUST | Setting the muted state updates [[Muted]] and fires mute or unmute | tested | `src/peer_connection/handler/interceptor.rs:1094`, `src/peer_connection/remote_tracks.rs:198` | `rtp_unmutes_the_remote_track_and_a_bye_mutes_it_without_ending_it`, `a_remote_description_that_stops_the_sending_mutes_the_track` | OnMute / OnUnmute for remote tracks |
| MEDIACAP-4.3.1-3 | 4.3.1 | MUST | A disabled track renders silence or black frames; enabling and disabling takes effect on live tracks | untested | `src/media_stream/track.rs:496` | - | The flag is stored; what a sender does with a disabled track is webrtc-pc 5.2 |
| MEDIACAP-4.3.1-4 | 4.3.1 | MUST | A track that ends other than by stop() sets [[ReadyState]] to "ended" and fires ended | tested | `src/peer_connection/remote_tracks.rs:265` | `a_rejected_section_ends_the_receivers_track`, `a_rollback_ends_the_track_of_a_transceiver_it_removes_and_restores_streams` | A remote track ends by negotiation, with OnClose |
| MEDIACAP-4.3.3-1 | 4.3.3 | MUST | kind returns [[Kind]] | tested | `src/media_stream/track.rs:254` | `tests/jsep_add_transceiver.rs` | - |
| MEDIACAP-4.3.3-2 | 4.3.3 | MUST | id returns [[Id]] | tested | `src/media_stream/track.rs:206` | `a_media_source_names_its_track_as_track_identifier` | - |
| MEDIACAP-4.3.3-3 | 4.3.3 | MUST | label returns [[Label]] | tested | `src/media_stream/track.rs:228` | `tests/jsep_add_transceiver.rs` | Remote tracks are labelled "remote " + kind |
| MEDIACAP-4.3.3-4 | 4.3.3 | MUST | enabled getter and setter | tested | `src/media_stream/track.rs` (enabled, set_enabled) | `a_tracks_attributes_and_stop` |  |
| MEDIACAP-4.3.3-5 | 4.3.3 | MUST | muted returns [[Muted]] | tested | `src/media_stream/track.rs` (muted) | `a_tracks_attributes_and_stop`, `rtp_unmutes_the_remote_track_and_a_bye_mutes_it_without_ending_it` |  |
| MEDIACAP-4.3.3-6 | 4.3.3 | MUST | readyState returns [[ReadyState]]: "live" or "ended" | tested | `src/media_stream/track.rs:531`, `src/media_stream/track_state.rs:35` | `src/peer_connection/handler/interceptor_goodbye_test.rs` | - |
| MEDIACAP-4.3.3-7 | 4.3.3 | MUST | stop(): an ended track is left alone; otherwise the source is notified and [[ReadyState]] becomes "ended" | tested | `src/media_stream/track.rs` (stop) | `a_tracks_attributes_and_stop`, `stopping_the_receivers_track_keeps_the_receiver_reporting` | a receiver's stopped track leaves the receiver running (webrtc-pc 5.3) |
| MEDIACAP-4.3.3-8 | 4.3.3 | MUST | getCapabilities / getConstraints / getSettings return the track's capabilities, constraints and settings | tested | `src/media_stream/track.rs` (get_capabilities, get_constraints, get_settings) | `a_tracks_attributes_and_stop`, `a_remote_video_tracks_settings_follow_the_frames_received`, `a_remote_track_has_no_capabilities` | settings filled for a remote video track by the frame feed |
| MEDIACAP-4.3.3-9 | 4.3.3 | MUST | applyConstraints runs the constraint algorithm and fails with OverconstrainedError when unsatisfiable | partial | `src/media_stream/track.rs` (apply_constraints) | `a_remote_track_refuses_constraints_on_its_video_properties` | fails for a remote track (webrtc-pc 9.3.1); a local track's constraints are stored, not evaluated: the engine has no source to select settings from |
| MEDIACAP-4.4-1 | 4.4 | MUST | MediaStreamTrackEvent carries the track for addtrack / removetrack | tested | `src/media_stream/mod.rs` (MediaStreamTrackEvent), `src/peer_connection/event/track_event.rs` (media_stream_track_events) | `a_stream_change_gives_the_media_stream_track_events` | removetrack then addtrack per stream, with the track |

## Gaps, in order of importance

1. **Fix the stream's track set (S).** `MEDIACAP-4.2-1`, `MEDIACAP-4.2-8`, `MEDIACAP-4.2-4`: key by track id in `MediaStream::new`; compute `active` from the tracks' states.
2. **Track life-cycle signals (M).** `MEDIACAP-4.3.1-2`, `MEDIACAP-4.3.1-4`, `MEDIACAP-4.2-11`, `MEDIACAP-4.4-1`: mute / unmute / ended and stream membership events for remote tracks (with the webrtc-pc 5.1.1 work).
3. **Clone and id generation (S).** `MEDIACAP-4.2-3`, `MEDIACAP-4.2-12`, `MEDIACAP-4.3-1`, `MEDIACAP-4.3-2`.
4. **Constraints (M, or declare out of scope).** `MEDIACAP-4.3.3-9`: either evaluate constraints against capabilities or remove the method from the engine and leave it to the application.
5. **Tests (S).** A unit test module for `src/media_stream/` covering every `untested` row.

## Bugs found

1. **`MediaStream::new` loses tracks.** `src/media_stream/mod.rs:254` builds the map with `track.stream_id()` as the key. Reproduce: `MediaStream::new("s", vec![audio, video])` where both tracks have stream id "s": `get_tracks().count()` is 1 and `get_track_by_id(audio_id)` is `None`.
2. **`active` never changes.** `src/media_stream/mod.rs:256`. Reproduce: build a stream of one track, `stop()` the track (through `get_tracks_mut`), read `active()`: still true.
