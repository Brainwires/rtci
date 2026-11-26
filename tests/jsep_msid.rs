//! `a=msid` in a remote description (RFC 8830 sections 2 and 3, RFC 9429 sections 5.2.1 and
//! 5.8.2): the form without appdata that RFC 9429 has senders write, several lines for a
//! track in several MediaStreams, `-` for none, and lines that are not well formed. The
//! receiver's track id is the engine's own, never the msid appdata (W3C webrtc-pc 5.3 "create
//! an RTCRtpReceiver": a new track whose id is not mapped to the remote's).

mod jsep_common;

use std::time::Instant;

use jsep_common::{SESSION, TRANSPORT, TestResult, crlf, default_peer};
use rtci::peer_connection::RTCPeerConnection;
use rtci::peer_connection::sdp::RTCSessionDescription;

fn offer(msid_lines: &str, source_lines: &str) -> String {
    crlf(&format!(
        "{SESSION}a=group:BUNDLE 0
m=video 9 UDP/TLS/RTP/SAVPF 96
{TRANSPORT}a=mid:0
a=sendonly
a=rtpmap:96 VP8/90000
{msid_lines}{source_lines}"
    ))
}

/// Applies `offer` and the answer to it; returns the remote track's stream ids, its first
/// stream id and its track id.
fn remote_track(
    pc: &mut RTCPeerConnection,
    offer: String,
) -> Result<(Vec<String>, String, String), Box<dyn std::error::Error>> {
    pc.set_remote_description(Instant::now(), RTCSessionDescription::offer(offer)?)?;
    let answer = pc.create_answer(None)?;
    pc.set_local_description(Instant::now(), answer)?;
    let id = pc.get_transceivers().next().expect("transceiver");
    let receiver = pc
        .rtp_transceiver(id)
        .expect("transceiver")
        .receiver()
        .expect("receiver");
    let receiver = pc.rtp_receiver(receiver).expect("receiver");
    Ok((
        receiver.streams().to_vec(),
        receiver.track().stream_id().clone(),
        receiver.track().track_id().clone(),
    ))
}

#[test]
fn an_msid_without_appdata_names_the_stream_and_the_recipient_names_the_track() -> TestResult {
    for sources in ["", "a=ssrc:1234 cname:c\n"] {
        let mut pc = default_peer()?;
        let (streams, stream, track) = remote_track(&mut pc, offer("a=msid:stream\n", sources))?;
        assert_eq!(streams, vec!["stream"], "sources {sources:?}");
        assert_eq!(stream, "stream");
        assert!(!track.is_empty(), "the recipient gave the track an id");

        // The same description again (a renegotiation that changes nothing): the same track.
        let again = remote_track(&mut pc, offer("a=msid:stream\n", sources))?;
        assert_eq!(again.2, track, "sources {sources:?}");
    }
    Ok(())
}

#[test]
fn several_msid_lines_put_one_track_in_several_streams() -> TestResult {
    let mut pc = default_peer()?;
    let (streams, stream, track) = remote_track(
        &mut pc,
        offer(
            "a=msid:first track\na=msid:second track\na=msid:first track\n",
            "a=ssrc:1234 cname:c\na=ssrc:1234 msid:legacy other\n",
        ),
    )?;
    assert_eq!(streams, vec!["first", "second"]);
    assert_eq!(stream, "first", "the a=msid lines win over a=ssrc msid");
    assert_ne!(track, "track", "W3C 5.3: not the msid appdata");
    Ok(())
}

#[test]
fn a_dash_is_no_stream() -> TestResult {
    let mut pc = default_peer()?;
    let (streams, stream, track) = remote_track(&mut pc, offer("a=msid:- track\n", ""))?;
    assert!(streams.is_empty(), "{streams:?}");
    assert_eq!(stream, "-");
    assert_ne!(track, "track", "W3C 5.3: not the msid appdata");
    Ok(())
}

/// RFC 8830 section 3: a value that is not `msid-id [SP msid-appdata]` is ignored; the
/// well-formed lines of the section still count.
#[test]
fn a_malformed_msid_line_is_ignored() -> TestResult {
    let mut pc = default_peer()?;
    let (streams, _, track) = remote_track(
        &mut pc,
        offer("a=msid:one two three\na=msid:good track\n", ""),
    )?;
    assert_eq!(streams, vec!["good"]);
    assert!(!track.is_empty());
    Ok(())
}

/// Without `a=msid` lines the source-level msid (RFC 8830 appendix A) still names the track.
#[test]
fn a_source_level_msid_is_used_when_there_is_no_msid_line() -> TestResult {
    let mut pc = default_peer()?;
    let (streams, stream, track) = remote_track(
        &mut pc,
        offer("", "a=ssrc:1234 cname:c\na=ssrc:1234 msid:legacy other\n"),
    )?;
    assert_eq!(streams, vec!["legacy"]);
    assert_eq!(stream, "legacy");
    assert_ne!(track, "other", "W3C 5.3: not the msid appdata");
    Ok(())
}

/// RFC 9429 section 5.2.1: a sending transceiver's section has "an "a=msid" line ... but
/// omitting the "appdata" field" per MediaStream: `with_msid_appdata(false)`. By default the
/// track id follows the stream id, as browsers write it, since webrtc-rs 0.17 drops a
/// simulcast section without it.
#[test]
fn local_msid_lines_carry_the_track_id_unless_it_is_left_out() -> TestResult {
    use rtci::peer_connection::RTCPeerConnectionBuilder;
    use rtci::peer_connection::configuration::RTCConfigurationBuilder;
    use rtci::peer_connection::configuration::media_engine::MediaEngine;
    use rtci::peer_connection::configuration::setting_engine::SettingEngineBuilder;
    let msid_lines = |appdata: Option<bool>| -> Result<Vec<String>, Box<dyn std::error::Error>> {
        let mut pc = match appdata {
            None => default_peer()?,
            Some(appdata) => {
                let mut media_engine = MediaEngine::default();
                media_engine.register_default_codecs()?;
                RTCPeerConnectionBuilder::new()
                    .with_configuration(RTCConfigurationBuilder::new().build())
                    .with_media_engine(media_engine)
                    .with_setting_engine(
                        SettingEngineBuilder::new()
                            .with_msid_appdata(appdata)
                            .build(),
                    )
                    .build(Instant::now())?
            }
        };
        pc.add_track(jsep_common::video_track("the-track", 0x0707_0707))?;
        let offer = pc.create_offer(None)?;
        Ok(offer
            .sdp
            .lines()
            .filter(|l| l.starts_with("a=msid:"))
            .map(str::to_owned)
            .collect())
    };
    let default = msid_lines(None)?;
    assert!(!default.is_empty());
    for line in &default {
        assert!(line.ends_with(" the-track"), "{line}");
    }
    assert_eq!(msid_lines(Some(true))?, default);
    let rfc = msid_lines(Some(false))?;
    assert!(!rfc.is_empty());
    for line in rfc {
        assert_eq!(line.split(' ').count(), 1, "no appdata: {line}");
    }
    Ok(())
}

/// The track's ready state after `pc` applied `offer` and answered it.
fn track_state(
    pc: &mut RTCPeerConnection,
    offer: String,
) -> Result<rtci::media_stream::MediaStreamTrackState, Box<dyn std::error::Error>> {
    remote_track(pc, offer)?;
    let id = pc.get_transceivers().next().expect("transceiver");
    let receiver = pc
        .rtp_transceiver(id)
        .expect("transceiver")
        .receiver()
        .expect("receiver");
    Ok(pc
        .rtp_receiver(receiver)
        .expect("receiver")
        .track()
        .ready_state())
}

/// RFC 8830 section 3: "When a session description is updated to no longer list any 'msid'
/// attribute on a specific media description, the recipient can signal to its application
/// that the corresponding MediaStreamTrack has ended." By default the W3C model governs: the
/// section still sends, so the track stays live, in the session's default stream. With
/// `with_msid_removal_ends_track(true)` it ends; a section that stops sending (recvonly
/// here, msid gone with it) only changes direction, which "will not end the
/// MediaStreamTrack" either way.
#[test]
fn a_section_that_drops_its_msid_ends_the_track_only_when_asked() -> TestResult {
    use rtci::media_stream::MediaStreamTrackState::{Ended, Live};
    use rtci::peer_connection::RTCPeerConnectionBuilder;
    use rtci::peer_connection::configuration::media_engine::MediaEngine;
    use rtci::peer_connection::configuration::setting_engine::SettingEngineBuilder;
    let peer = |ends: bool| -> Result<RTCPeerConnection, Box<dyn std::error::Error>> {
        let mut media_engine = MediaEngine::default();
        media_engine.register_default_codecs()?;
        Ok(RTCPeerConnectionBuilder::new()
            .with_media_engine(media_engine)
            .with_setting_engine(
                SettingEngineBuilder::new()
                    .with_msid_removal_ends_track(ends)
                    .build(),
            )
            .build(Instant::now())?)
    };
    let with_msid = || offer("a=msid:stream\n", "");
    for ends in [false, true] {
        let mut pc = peer(ends)?;
        assert_eq!(track_state(&mut pc, with_msid())?, Live);
        let after = track_state(&mut pc, offer("", ""))?;
        assert_eq!(after, if ends { Ended } else { Live }, "ends {ends}");

        let mut pc = peer(ends)?;
        assert_eq!(track_state(&mut pc, with_msid())?, Live);
        let recvonly = with_msid()
            .replace("a=sendonly\r\n", "a=recvonly\r\n")
            .replace("a=msid:stream\r\n", "");
        assert_eq!(
            track_state(&mut pc, recvonly)?,
            Live,
            "ends {ends}: recvonly"
        );
    }
    Ok(())
}

/// RFC 8830 section 3.2.5: "If no such attribute is found, stop the MediaStreamTrack." The
/// `StrictRfc` behaviour profile turns `with_msid_removal_ends_track` on; the default profile
/// keeps the W3C form (the track stays live).
#[test]
fn the_strict_rfc_profile_ends_a_track_whose_section_drops_its_msid() -> TestResult {
    use rtci::media_stream::MediaStreamTrackState::{Ended, Live};
    use rtci::peer_connection::RTCPeerConnectionBuilder;
    use rtci::peer_connection::configuration::BehaviourProfile;
    use rtci::peer_connection::configuration::media_engine::MediaEngine;
    use rtci::peer_connection::configuration::setting_engine::SettingEngineBuilder;
    for (profile, expected) in [
        (BehaviourProfile::Rfc, Live),
        (BehaviourProfile::Chrome, Live),
        (BehaviourProfile::StrictRfc, Ended),
    ] {
        let mut media_engine = MediaEngine::for_profile(profile);
        media_engine.register_default_codecs()?;
        let mut pc = RTCPeerConnectionBuilder::new()
            .with_media_engine(media_engine)
            .with_setting_engine(
                SettingEngineBuilder::new()
                    .with_behaviour_profile(profile)
                    .build(),
            )
            .build(Instant::now())?;
        assert_eq!(track_state(&mut pc, offer("a=msid:stream\n", ""))?, Live);
        assert_eq!(
            track_state(&mut pc, offer("", ""))?,
            expected,
            "{profile:?}"
        );
    }
    Ok(())
}

/// RFC 9429 sections 5.2.2 and 5.3.2: for a transceiver that is not stopped "the 'a=msid'
/// lines MUST stay the same regardless of changes to the transceiver's direction or track".
/// After `remove_track` (no track, the direction no longer sends) the next offer and the
/// answer to the peer's next offer keep the section's `a=msid` lines.
#[test]
fn msid_lines_stay_when_the_track_is_removed() -> TestResult {
    use jsep_common::{exchange, media_sections, video_track};
    let msid = |sdp: &str| -> Vec<String> {
        media_sections(sdp)[0]
            .iter()
            .filter(|l| l.starts_with("a=msid:"))
            .cloned()
            .collect()
    };
    let mut local = default_peer()?;
    let mut peer = default_peer()?;
    let sender = local.add_track(video_track("v", 0x5e13_0101))?;
    let (offer, _) = exchange(&mut local, &mut peer)?;
    let before = msid(&offer);
    assert!(!before.is_empty(), "{offer}");

    local.remove_track(sender)?;
    let (offer, _) = exchange(&mut local, &mut peer)?;
    assert!(
        !media_sections(&offer)[0]
            .iter()
            .any(|l| l == "a=sendrecv" || l == "a=sendonly"),
        "no longer sending: {offer}"
    );
    assert_eq!(msid(&offer), before, "{offer}");
    let (_, answer) = exchange(&mut peer, &mut local)?;
    assert_eq!(msid(&answer), before, "{answer}");
    Ok(())
}

/// RFC 9429 section 5.2.1: a sending transceiver "not associated with any MediaStream" is
/// written `a=msid:- <id>` (RFC 8830 section 3: `-` is "no MediaStream"). A track that names
/// no stream (an empty stream id, or `-`) is added in none, as W3C `addTrack(track)` with no
/// streams; `add_track_with_streams(track, [])` takes a sender out of its track's stream. The
/// source-level `msid` (RFC 8830 appendix A) says the same stream; a track in a stream keeps
/// it.
#[test]
fn a_sender_in_no_stream_is_written_with_a_dash() -> TestResult {
    use rtci::media_stream::MediaStreamTrack;
    let renamed = |stream: &str| {
        let track = jsep_common::video_track("the-track", 0x0707_0708);
        MediaStreamTrack::new(
            stream.to_owned(),
            track.track_id().clone(),
            track.label().clone(),
            track.kind(),
            track.codings().to_vec(),
        )
    };
    let lines = |sdp: &str, prefix: &str| -> Vec<String> {
        sdp.lines()
            .filter_map(|l| l.strip_prefix(prefix))
            .map(str::to_owned)
            .collect()
    };
    for (stream, without_streams, expected) in [
        ("-", false, "-"),
        ("", false, "-"),
        ("s", true, "-"),
        ("s", false, "s"),
    ] {
        let mut pc = default_peer()?;
        let sender = if without_streams {
            pc.add_track_with_streams(renamed(stream), vec![])?
        } else {
            pc.add_track(renamed(stream))?
        };
        let offer = pc.create_offer(None)?.sdp;
        let case = format!("stream {stream:?}, without streams {without_streams}:\n{offer}");
        // W3C [[AssociatedMediaStreamIds]]: none, or the one stream.
        let associated: Vec<String> = pc
            .rtp_sender(sender)
            .expect("the sender")
            .streams()
            .to_vec();
        let expected_streams: Vec<String> = if expected == "-" {
            vec![]
        } else {
            vec![expected.to_owned()]
        };
        assert_eq!(associated, expected_streams, "{case}");
        assert_eq!(
            lines(&offer, "a=msid:"),
            vec![format!("{expected} the-track")],
            "{case}"
        );
        let source: Vec<String> = lines(&offer, "a=ssrc:")
            .into_iter()
            .filter_map(|l| l.split_once(" msid:").map(|(_, v)| v.to_owned()))
            .collect();
        assert!(!source.is_empty(), "{case}");
        for value in source {
            assert_eq!(value, format!("{expected} the-track"), "{case}");
        }
    }
    Ok(())
}

/// RFC 8830 section 2: `msid-id = 1*64token-char` and `msid-appdata = 1*64token-char`. A
/// received line whose id or appdata is longer than 64 characters is not well formed and is
/// ignored (section 2: such a line "SHOULD be ignored"; the track then takes the next line's
/// stream). An id or track id of this side's that cannot be written (a space, more than 64
/// characters) makes `create_offer` fail instead of writing a line that does not parse; 64
/// characters are written.
#[test]
fn msid_ids_and_appdata_are_one_to_sixty_four_token_characters() -> TestResult {
    let long = "s".repeat(65);
    let mut pc = default_peer()?;
    let (streams, _, _) = remote_track(
        &mut pc,
        offer(
            &format!("a=msid:{long} track\na=msid:short {long}\na=msid:good track\n"),
            "",
        ),
    )?;
    assert_eq!(streams, vec!["good"]);

    let offered = |stream: &str, track: &str| {
        let mut pc = default_peer()?;
        pc.add_track(rtci::media_stream::MediaStreamTrack::new(
            stream.to_owned(),
            track.to_owned(),
            "label".to_owned(),
            rtci::rtp_transceiver::rtp_sender::RtpCodecKind::Video,
            vec![
                rtci::rtp_transceiver::rtp_sender::RTCRtpEncodingParameters {
                    rtp_coding_parameters:
                        rtci::rtp_transceiver::rtp_sender::RTCRtpCodingParameters {
                            ssrc: Some(0x0808_0808),
                            ..Default::default()
                        },
                    codec: jsep_common::vp8(),
                    ..Default::default()
                },
            ],
        ))?;
        pc.create_offer(None)
            .map(|offer| offer.sdp)
            .map_err(Box::<dyn std::error::Error>::from)
    };
    for (stream, track) in [
        ("my stream", "track"),
        ("stream", "my track"),
        (long.as_str(), "track"),
        ("stream", long.as_str()),
    ] {
        assert!(offered(stream, track).is_err(), "{stream:?} / {track:?}");
    }
    let sixty_four = "s".repeat(64);
    let sdp = offered(&sixty_four, &sixty_four)?;
    assert!(
        sdp.contains(&format!("a=msid:{sixty_four} {sixty_four}\r\n")),
        "{sdp}"
    );
    Ok(())
}

/// RFC 8830 section 2: "Multiple media descriptions with the same value for 'msid-id' and
/// 'msid-appdata' are not permitted". W3C webrtc-pc lets one track be sent by two
/// transceivers in one stream (`addTransceiver(track)` twice); the second section's appdata
/// is made unique (`<track id>-1`, its source-level msid too), and a later offer keeps the
/// lines. Without appdata (`with_msid_appdata(false)`, the RFC 9429 form) the two sections
/// carry the stream alone, as RFC 9429's examples do.
#[test]
fn two_sections_never_carry_the_same_msid_pair() -> TestResult {
    use jsep_common::{media_sections, video_track};
    use rtci::peer_connection::RTCPeerConnectionBuilder;
    use rtci::peer_connection::configuration::media_engine::MediaEngine;
    use rtci::peer_connection::configuration::setting_engine::SettingEngineBuilder;
    use rtci::rtp_transceiver::{RTCRtpTransceiverDirection, RTCRtpTransceiverInit};
    let init = || RTCRtpTransceiverInit {
        direction: RTCRtpTransceiverDirection::Sendonly,
        streams: vec!["shared".to_owned()],
        send_encodings: vec![],
    };
    let msid_lines = |sdp: &str| -> Vec<Vec<String>> {
        media_sections(sdp)
            .iter()
            .map(|section| {
                section
                    .iter()
                    .filter(|l| l.starts_with("a=msid:") || l.contains(" msid:"))
                    .cloned()
                    .collect()
            })
            .collect()
    };
    let mut pc = jsep_common::default_peer()?;
    pc.add_transceiver_from_track(video_track("same", 0x0101_0101), Some(init()))?;
    pc.add_transceiver_from_track(video_track("same", 0x0202_0202), Some(init()))?;
    let offer = pc.create_offer(None)?;
    let lines = msid_lines(&offer.sdp);
    assert_eq!(lines.len(), 2, "{}", offer.sdp);
    assert!(
        lines[0].contains(&"a=msid:shared same".to_owned()),
        "{}",
        offer.sdp
    );
    assert!(
        lines[1].contains(&"a=msid:shared same-1".to_owned()),
        "{}",
        offer.sdp
    );
    assert!(
        lines[1]
            .iter()
            .filter(|l| l.contains(" msid:"))
            .all(|l| l.ends_with("msid:shared same-1")),
        "{}",
        offer.sdp
    );
    pc.set_local_description(Instant::now(), offer.clone())?;
    let later = pc.create_offer(None)?;
    assert_eq!(
        msid_lines(&later.sdp),
        lines,
        "a later offer keeps the lines"
    );

    let mut pc = RTCPeerConnectionBuilder::new()
        .with_media_engine({
            let mut media_engine = MediaEngine::default();
            media_engine.register_default_codecs()?;
            media_engine
        })
        .with_setting_engine(SettingEngineBuilder::new().with_msid_appdata(false).build())
        .build(Instant::now())?;
    pc.add_transceiver_from_track(video_track("same", 0x0101_0101), Some(init()))?;
    pc.add_transceiver_from_track(video_track("same", 0x0202_0202), Some(init()))?;
    let offer = pc.create_offer(None)?;
    for section in msid_lines(&offer.sdp) {
        assert!(
            section.contains(&"a=msid:shared".to_owned()),
            "{}",
            offer.sdp
        );
    }
    Ok(())
}

/// RFC 8830 section 3: a new msid-appdata in a section names a new track: "the recipient
/// ... MUST" learn that a new track was added. By default the W3C object model governs (a
/// receiver has one track for its lifetime, webrtc-pc 5.3, with an id the engine generates;
/// RFC 9429 section 5.2.1 has senders leave the appdata out): a changed appdata changes no
/// track and fires no event. With `with_msid_appdata_change_renews_track(true)` the
/// receiver's track ends (`OnClose`) and a new track with a new id takes its place,
/// announced with the `track` event; the same appdata again changes nothing.
#[test]
fn a_new_msid_appdata_is_a_new_track_only_when_asked() -> TestResult {
    use rtci::media_stream::MediaStreamTrackState::Live;
    use rtci::peer_connection::RTCPeerConnectionBuilder;
    use rtci::peer_connection::configuration::media_engine::MediaEngine;
    use rtci::peer_connection::configuration::setting_engine::SettingEngineBuilder;
    use rtci::peer_connection::event::{RTCPeerConnectionEvent, RTCTrackEvent};
    use rtci::sansio::Protocol;
    let peer = |renews: bool| -> Result<RTCPeerConnection, Box<dyn std::error::Error>> {
        let mut media_engine = MediaEngine::default();
        media_engine.register_default_codecs()?;
        Ok(RTCPeerConnectionBuilder::new()
            .with_media_engine(media_engine)
            .with_setting_engine(
                SettingEngineBuilder::new()
                    .with_msid_appdata_change_renews_track(renews)
                    .build(),
            )
            .build(Instant::now())?)
    };
    // (tracks closed, tracks announced by the `track` event) since the last call.
    let events = |pc: &mut RTCPeerConnection| {
        let (mut closed, mut announced) = (vec![], vec![]);
        while let Some(event) = pc.poll_event() {
            match event {
                RTCPeerConnectionEvent::OnTrack(RTCTrackEvent::OnClose(id)) => closed.push(id),
                RTCPeerConnectionEvent::OnTrack(RTCTrackEvent::OnRemoteTrack(init)) => {
                    announced.push(init.track_id)
                }
                _ => {}
            }
        }
        (closed, announced)
    };
    for renews in [false, true] {
        let mut pc = peer(renews)?;
        let (_, _, first) = remote_track(&mut pc, offer("a=msid:stream one\n", ""))?;
        assert_eq!(events(&mut pc).1, vec![first.clone()], "renews {renews}");

        let (_, _, second) = remote_track(&mut pc, offer("a=msid:stream two\n", ""))?;
        let (closed, announced) = events(&mut pc);
        if renews {
            assert_ne!(second, first, "a new track");
            assert_eq!(closed, vec![first.clone()], "the old one ended");
            assert_eq!(announced, vec![second.clone()], "the new one announced");
            assert_eq!(
                track_state(&mut pc, offer("a=msid:stream two\n", ""))?,
                Live
            );
        } else {
            assert_eq!(second, first, "the receiver's one track");
            assert!(
                closed.is_empty() && announced.is_empty(),
                "{closed:?} {announced:?}"
            );
        }
        let (_, _, third) = remote_track(&mut pc, offer("a=msid:stream two\n", ""))?;
        assert_eq!(third, second, "renews {renews}: the same appdata again");
        assert_eq!(events(&mut pc), (vec![], vec![]), "renews {renews}");
    }
    Ok(())
}

/// The appdata of each media-level `a=msid` line of each section of `sdp` (`None` for a
/// line without one), and the section's lines.
fn msid_appdata_per_section(sdp: &str) -> Vec<Vec<Option<String>>> {
    jsep_common::media_sections(sdp)
        .iter()
        .map(|section| {
            section
                .iter()
                .filter_map(|line| line.strip_prefix("a=msid:"))
                .map(|value| value.split_once(' ').map(|(_, appdata)| appdata.to_owned()))
                .collect()
        })
        .collect()
}

/// Asserts that every section of `sdp` whose msid lines carry appdata carries one: RFC 8830
/// section 2, "the value of "msid-appdata" MUST be identical for all occurrences".
fn assert_one_appdata_per_section(what: &str, sdp: &str) {
    for (index, appdata) in msid_appdata_per_section(sdp).iter().enumerate() {
        let mut distinct = appdata.clone();
        distinct.dedup();
        assert!(
            distinct.len() <= 1,
            "{what} section {index}: msid lines with different appdata {appdata:?}\n{sdp}"
        );
    }
}

/// RFC 8830 section 2: "There may be multiple "msid" attributes in a single media
/// description. This represents the case where a single MediaStreamTrack is present in
/// multiple MediaStreams; the value of "msid-appdata" MUST be identical for all
/// occurrences." A track in three streams; one track sent by two transceivers, the second in
/// a stream of the first's and one more, whose pair with the first stream repeats the first
/// section's and is made unique (RFC8830-2-4, `-1`): both of its lines take the new appdata,
/// not only the repeated one; an answerer's track in two streams; a later offer. Each
/// section's `a=msid` lines carry one appdata.
#[test]
fn every_msid_line_of_a_section_carries_the_same_appdata() -> TestResult {
    use jsep_common::video_track;
    use rtci::rtp_transceiver::{RTCRtpTransceiverDirection, RTCRtpTransceiverInit};
    let init = |streams: &[&str]| RTCRtpTransceiverInit {
        direction: RTCRtpTransceiverDirection::Sendrecv,
        streams: streams.iter().map(|s| (*s).to_owned()).collect(),
        send_encodings: vec![],
    };
    let mut offerer = default_peer()?;
    offerer.add_transceiver_from_track(
        video_track("solo", 0x0101_0101),
        Some(init(&["x", "y", "z"])),
    )?;
    offerer
        .add_transceiver_from_track(video_track("same", 0x0202_0202), Some(init(&["shared"])))?;
    offerer.add_transceiver_from_track(
        video_track("same", 0x0303_0303),
        Some(init(&["shared", "other"])),
    )?;
    let now = Instant::now();
    let offer = offerer.create_offer(None)?;
    let appdata = msid_appdata_per_section(&offer.sdp);
    assert_eq!(3, appdata.len(), "{}", offer.sdp);
    assert_eq!(3, appdata[0].len(), "three msid lines: {}", offer.sdp);
    assert_eq!(2, appdata[2].len(), "two msid lines: {}", offer.sdp);
    assert_eq!(Some("same"), appdata[1][0].as_deref(), "{}", offer.sdp);
    assert_ne!(
        Some("same"),
        appdata[2][0].as_deref(),
        "the repeated pair is made unique: {}",
        offer.sdp
    );
    assert_one_appdata_per_section("offer", &offer.sdp);
    offerer.set_local_description(now, offer.clone())?;

    let mut answerer = default_peer()?;
    answerer.set_remote_description(now, RTCSessionDescription::offer(offer.sdp.clone())?)?;
    answerer.add_track_with_streams(
        video_track("back", 0x0404_0404),
        vec!["p".to_owned(), "q".to_owned()],
    )?;
    let answer = answerer.create_answer(None)?;
    let answered = msid_appdata_per_section(&answer.sdp);
    assert!(
        answered.iter().any(|lines| lines.len() == 2),
        "the answerer's track in two streams: {}",
        answer.sdp
    );
    assert_one_appdata_per_section("answer", &answer.sdp);
    answerer.set_local_description(now, answer.clone())?;
    offerer.set_remote_description(now, answer)?;

    let later = offerer.create_offer(None)?;
    assert_one_appdata_per_section("later offer", &later.sdp);
    Ok(())
}
