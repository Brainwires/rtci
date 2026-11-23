//! `a=msid` in a remote description (RFC 8830 sections 2 and 3, RFC 9429 sections 5.2.1 and
//! 5.8.2): the form without appdata that RFC 9429 has senders write, several lines for a
//! track in several MediaStreams, `-` for none, and lines that are not well formed. The
//! receiver's track id is the engine's own, never the msid appdata (W3C webrtc-pc 5.3 "create
//! an RTCRtpReceiver": a new track whose id is not mapped to the remote's).

mod jsep_common;

use std::time::Instant;

use jsep_common::{SESSION, TRANSPORT, TestResult, crlf, default_peer};
use rtc::peer_connection::RTCPeerConnection;
use rtc::peer_connection::sdp::RTCSessionDescription;

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
    use rtc::peer_connection::RTCPeerConnectionBuilder;
    use rtc::peer_connection::configuration::RTCConfigurationBuilder;
    use rtc::peer_connection::configuration::media_engine::MediaEngine;
    use rtc::peer_connection::configuration::setting_engine::SettingEngineBuilder;
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
) -> Result<rtc::media_stream::MediaStreamTrackState, Box<dyn std::error::Error>> {
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
    use rtc::media_stream::MediaStreamTrackState::{Ended, Live};
    use rtc::peer_connection::RTCPeerConnectionBuilder;
    use rtc::peer_connection::configuration::media_engine::MediaEngine;
    use rtc::peer_connection::configuration::setting_engine::SettingEngineBuilder;
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
