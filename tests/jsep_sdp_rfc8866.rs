//! RFC 8866 attributes in a remote description. The informational ones (`tool`, `type`,
//! `orient`, `quality`): well formed, they are accepted and change nothing; malformed, the
//! description is refused (RFC 9429 section 5.8: "If any line is not well formed or cannot be
//! parsed as described, the parser MUST stop with an error and reject the session
//! description, even if the value is to be discarded"). The direction attributes: at most one
//! per level (section 6.7).

mod jsep_common;

use std::time::Instant;

use jsep_common::{SESSION, TRANSPORT, TestResult, crlf, default_peer};
use rtci::peer_connection::sdp::RTCSessionDescription;

fn offer(session: &str, media: &str) -> String {
    crlf(&format!(
        "{SESSION}{session}m=video 9 UDP/TLS/RTP/SAVPF 96\n{TRANSPORT}a=mid:0\na=sendrecv\n\
         {media}a=rtpmap:96 VP8/90000\n"
    ))
}

#[test]
fn informational_attributes_are_accepted_when_well_formed_and_refused_when_not() -> TestResult {
    let mut pc = default_peer()?;
    pc.set_remote_description(
        Instant::now(),
        RTCSessionDescription::offer(offer(
            "a=tool:foobar V3.2\na=type:moderated\n",
            "a=orient:landscape\na=quality:5\n",
        ))?,
    )?;
    let answer = pc.create_answer(None)?;
    assert!(answer.sdp.contains("m=video 9 "), "{}", answer.sdp);
    // The engine writes none of them.
    for name in ["a=tool", "a=type", "a=orient", "a=quality"] {
        assert!(!answer.sdp.contains(name), "{name}:\n{}", answer.sdp);
    }

    for (session, media) in [
        ("a=type:Moderated\n", ""),
        ("", "a=orient:sideways\n"),
        ("", "a=quality:05\n"),
    ] {
        let mut pc = default_peer()?;
        let refused = RTCSessionDescription::offer(offer(session, media))
            .map_err(Box::<dyn std::error::Error>::from)
            .and_then(|offer| Ok(pc.set_remote_description(Instant::now(), offer)?));
        assert!(refused.is_err(), "{session}{media}");
    }
    Ok(())
}

/// RFC 8866 section 6.7: "At most one occurrence of "a=recvonly", "a=sendrecv", "a=sendonly",
/// or "a=inactive" MAY appear at session level, and at most one MAY appear in each media
/// description." A description with two at one level is refused; one at each level is taken,
/// the media level's applying to its section.
#[test]
fn a_level_with_two_direction_attributes_is_refused() -> TestResult {
    for (session, media) in [("a=sendonly\na=recvonly\n", ""), ("", "a=sendonly\n")] {
        let mut pc = default_peer()?;
        let text = offer(session, media);
        assert!(
            pc.set_remote_description(Instant::now(), RTCSessionDescription::offer(text)?)
                .is_err(),
            "{session}{media}"
        );
    }

    // One at session level and one in the section: the section's applies.
    let mut pc = default_peer()?;
    let text = offer("a=inactive\n", "").replace("a=sendrecv\r\n", "a=sendonly\r\n");
    pc.set_remote_description(Instant::now(), RTCSessionDescription::offer(text)?)?;
    let answer = pc.create_answer(None)?;
    assert!(answer.sdp.contains("a=recvonly\r\n"), "{}", answer.sdp);
    Ok(())
}
