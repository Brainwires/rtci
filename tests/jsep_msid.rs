//! `a=msid` in a remote description (RFC 8830 sections 2 and 3, RFC 9429 sections 5.2.1 and
//! 5.8.2): the form without appdata that RFC 9429 has senders write, several lines for a
//! track in several MediaStreams, `-` for none, and lines that are not well formed.

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
    assert_eq!(stream, "first");
    assert_eq!(track, "track", "the a=msid lines win over a=ssrc msid");
    Ok(())
}

#[test]
fn a_dash_is_no_stream() -> TestResult {
    let mut pc = default_peer()?;
    let (streams, stream, track) = remote_track(&mut pc, offer("a=msid:- track\n", ""))?;
    assert!(streams.is_empty(), "{streams:?}");
    assert_eq!((stream.as_str(), track.as_str()), ("-", "track"));
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
    assert_eq!(track, "track");
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
    assert_eq!((stream.as_str(), track.as_str()), ("legacy", "other"));
    Ok(())
}
