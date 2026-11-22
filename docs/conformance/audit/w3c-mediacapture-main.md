# W3C Media Capture and Streams (mediacapture-main): the parts webrtc-pc depends on

Spec: Media Capture and Streams, W3C Editor's Draft at https://w3c.github.io/mediacapture-main/ (served copy last modified 19 November 2026). Engine: fork master 8916bc3.

Scope: only section 4, the MediaStream and MediaStreamTrack model that webrtc-pc uses for track and stream identity (ids, kind, label, enabled, muted, readyState, the track set of a stream). Capture devices, getUserMedia, permissions, device enumeration, media elements and the constrainable pattern's selection algorithm are outside an engine with no capture and are not enumerated. Sections: 4.2 MediaStream, 4.3 MediaStreamTrack (4.3.1 media flow and life-cycle, 4.3.3 interface), 4.4 MediaStreamTrackEvent. What webrtc-pc itself adds for remote tracks is audited in `w3c-webrtc-pc.md` section 9.

`src/media_stream/` has no unit test of its own; `tested` rows cite tests elsewhere that depend on the behaviour.

Totals:

- MUST: tested 4 / untested 11 / partial 7 / missing 4 / violated 1 / n-a 1
- SHOULD: tested 0 / untested 0 / partial 0 / missing 0 / violated 0 / n-a 0
- MAY: tested 0 / untested 0 / partial 0 / missing 0 / violated 0 / n-a 0

| ID | § | Level | Clause (short paraphrase) | Verdict | Code | Test | Note |
|---|---|---|---|---|---|---|---|
| MEDIACAP-4.2-1 | 4.2 | MUST | A stream's track set holds the tracks of the stream | partial | `src/media_stream/mod.rs:249` | - | `MediaStream::new` keys each track by its stream id, not its track id, so tracks of one stream overwrite each other |
| MEDIACAP-4.2-2 | 4.2 | MUST | MediaStream.id returns the value the stream was created with | untested | `src/media_stream/mod.rs:268` | - | - |
| MEDIACAP-4.2-3 | 4.2 | MUST | A new stream gets a generated id unless a special-purpose algorithm (remote streams) sets it | partial | `src/media_stream/mod.rs:249` | - | The caller always supplies the id; no generator |
| MEDIACAP-4.2-4 | 4.2 | MUST | MediaStream.active is true while at least one track is not ended | violated | `src/media_stream/mod.rs:256`, `src/media_stream/mod.rs:279` | - | `active` is set to true at construction and never recomputed |
| MEDIACAP-4.2-5 | 4.2 | MUST | getAudioTracks returns the audio tracks of the set | untested | `src/media_stream/mod.rs:301` | - | - |
| MEDIACAP-4.2-6 | 4.2 | MUST | getVideoTracks returns the video tracks of the set | untested | `src/media_stream/mod.rs:336` | - | - |
| MEDIACAP-4.2-7 | 4.2 | MUST | getTracks returns every track of the set | untested | `src/media_stream/mod.rs:369` | - | - |
| MEDIACAP-4.2-8 | 4.2 | MUST | getTrackById returns the track with that id, or null | partial | `src/media_stream/mod.rs:411`, `src/media_stream/mod.rs:254` | - | Fails for tracks passed to `new` (keyed by stream id) |
| MEDIACAP-4.2-9 | 4.2 | MUST | addTrack: a track already in the set is not added again; otherwise it is added | untested | `src/media_stream/mod.rs:478` | - | - |
| MEDIACAP-4.2-10 | 4.2 | MUST | removeTrack: removes the track if it is in the set | untested | `src/media_stream/mod.rs:522` | - | - |
| MEDIACAP-4.2-11 | 4.2 | MUST | Adding or removing a track on the user agent's initiative fires addtrack / removetrack | missing | `src/media_stream/mod.rs:478` | - | Remote stream membership changes raise no event; streams are not objects the peer connection maintains |
| MEDIACAP-4.2-12 | 4.2 | MUST | clone(): a new stream with a new id and clones of the tracks | missing | `src/media_stream/mod.rs:203` | - | No clone |
| MEDIACAP-4.3-1 | 4.3 | MUST | A track is created with a generated [[Id]], its [[Kind]], [[Label]], [[ReadyState]] "live", [[Enabled]] true and its source's [[Muted]] | partial | `src/media_stream/track.rs:165` | - | Id and label are supplied by the caller; state starts live, enabled, unmuted |
| MEDIACAP-4.3-2 | 4.3 | MUST | Cloning a track gives a new id, the same source, kind, label, state, enabled flag and constraints | missing | `src/media_stream/track.rs:91` | - | No track clone with a new id |
| MEDIACAP-4.3.1-1 | 4.3.1 | MUST | No live samples are made available while a track is muted | n/a | - | - | Samples are the application's |
| MEDIACAP-4.3.1-2 | 4.3.1 | MUST | Setting the muted state updates [[Muted]] and fires mute or unmute | partial | `src/media_stream/track.rs:526` | - | A setter exists; the engine never calls it and no event is raised (remote tracks: see w3c-webrtc-pc.md 9.3) |
| MEDIACAP-4.3.1-3 | 4.3.1 | MUST | A disabled track renders silence or black frames; enabling and disabling takes effect on live tracks | untested | `src/media_stream/track.rs:496` | - | The flag is stored; what a sender does with a disabled track is webrtc-pc 5.2 |
| MEDIACAP-4.3.1-4 | 4.3.1 | MUST | A track that ends other than by stop() sets [[ReadyState]] to "ended" and fires ended | partial | `src/peer_connection/handler/interceptor.rs:195`, `src/media_stream/track.rs:557` | `src/peer_connection/handler/interceptor_goodbye_test.rs` | An RTCP BYE ends the remote track; no ended event is raised |
| MEDIACAP-4.3.3-1 | 4.3.3 | MUST | kind returns [[Kind]] | tested | `src/media_stream/track.rs:254` | `tests/jsep_add_transceiver.rs` | - |
| MEDIACAP-4.3.3-2 | 4.3.3 | MUST | id returns [[Id]] | tested | `src/media_stream/track.rs:206` | `a_media_source_names_its_track_as_track_identifier` | - |
| MEDIACAP-4.3.3-3 | 4.3.3 | MUST | label returns [[Label]] | tested | `src/media_stream/track.rs:228` | `tests/jsep_add_transceiver.rs` | Remote tracks are labelled "remote " + kind |
| MEDIACAP-4.3.3-4 | 4.3.3 | MUST | enabled getter and setter | untested | `src/media_stream/track.rs:466`, `src/media_stream/track.rs:496` | - | - |
| MEDIACAP-4.3.3-5 | 4.3.3 | MUST | muted returns [[Muted]] | untested | `src/media_stream/track.rs:521` | - | - |
| MEDIACAP-4.3.3-6 | 4.3.3 | MUST | readyState returns [[ReadyState]]: "live" or "ended" | tested | `src/media_stream/track.rs:531`, `src/media_stream/track_state.rs:35` | `src/peer_connection/handler/interceptor_goodbye_test.rs` | - |
| MEDIACAP-4.3.3-7 | 4.3.3 | MUST | stop(): an ended track is left alone; otherwise the source is notified and [[ReadyState]] becomes "ended" | untested | `src/media_stream/track.rs:557` | - | Sets ended; nothing tells the sender or receiver that uses the track |
| MEDIACAP-4.3.3-8 | 4.3.3 | MUST | getCapabilities / getConstraints / getSettings return the track's capabilities, constraints and settings | untested | `src/media_stream/track.rs:581`, `src/media_stream/track.rs:604`, `src/media_stream/track.rs:628` | - | Stored values; nothing fills settings for a remote track |
| MEDIACAP-4.3.3-9 | 4.3.3 | MUST | applyConstraints runs the constraint algorithm and fails with OverconstrainedError when unsatisfiable | partial | `src/media_stream/track.rs:664` | - | Stores the constraints without evaluating them (TODO in the code), cannot fail |
| MEDIACAP-4.4-1 | 4.4 | MUST | MediaStreamTrackEvent carries the track for addtrack / removetrack | missing | - | - | No such event |

## Gaps, in order of importance

1. **Fix the stream's track set (S).** `MEDIACAP-4.2-1`, `MEDIACAP-4.2-8`, `MEDIACAP-4.2-4`: key by track id in `MediaStream::new`; compute `active` from the tracks' states.
2. **Track life-cycle signals (M).** `MEDIACAP-4.3.1-2`, `MEDIACAP-4.3.1-4`, `MEDIACAP-4.2-11`, `MEDIACAP-4.4-1`: mute / unmute / ended and stream membership events for remote tracks (with the webrtc-pc 5.1.1 work).
3. **Clone and id generation (S).** `MEDIACAP-4.2-3`, `MEDIACAP-4.2-12`, `MEDIACAP-4.3-1`, `MEDIACAP-4.3-2`.
4. **Constraints (M, or declare out of scope).** `MEDIACAP-4.3.3-9`: either evaluate constraints against capabilities or remove the method from the engine and leave it to the application.
5. **Tests (S).** A unit test module for `src/media_stream/` covering every `untested` row.

## Bugs found

1. **`MediaStream::new` loses tracks.** `src/media_stream/mod.rs:254` builds the map with `track.stream_id()` as the key. Reproduce: `MediaStream::new("s", vec![audio, video])` where both tracks have stream id "s": `get_tracks().count()` is 1 and `get_track_by_id(audio_id)` is `None`.
2. **`active` never changes.** `src/media_stream/mod.rs:256`. Reproduce: build a stream of one track, `stop()` the track (through `get_tracks_mut`), read `active()`: still true.
