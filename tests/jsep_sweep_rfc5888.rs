//! RFC 5888 rows of the sweep (jsep12).

mod jsep_common;

use std::time::Instant;

use jsep_common::{SESSION, TRANSPORT, TestResult, crlf, default_peer};
use rtci::peer_connection::sdp::RTCSessionDescription;

fn offer(ls_group: &str) -> String {
    crlf(&format!(
        "{SESSION}a=group:BUNDLE 0 1\n{ls_group}\
         m=audio 9 UDP/TLS/RTP/SAVPF 111\n{TRANSPORT}a=mid:0\na=sendrecv\na=msid:s\n\
         a=rtpmap:111 opus/48000/2\n\
         m=video 9 UDP/TLS/RTP/SAVPF 96\n{TRANSPORT}a=mid:1\na=sendrecv\na=msid:s\n\
         a=rtpmap:96 VP8/90000\n"
    ))
}

/// Section 6: "'a=group' lines that contain identification-tags that do not correspond to any
/// 'm' line ... MUST be ignored. The application acts as if the 'a=group' line did not
/// exist." An offered LS group of both sections is answered (RFC 9429 section 5.3.1: an
/// answerer without tracks keeps it); the same group naming a third, absent mid is not.
#[test]
fn a_group_naming_an_unknown_mid_is_ignored() -> TestResult {
    for (ls, answered) in [("a=group:LS 0 1\n", true), ("a=group:LS 0 1 2\n", false)] {
        let mut pc = default_peer()?;
        pc.set_remote_description(Instant::now(), RTCSessionDescription::offer(offer(ls))?)?;
        let answer = pc.create_answer(None)?;
        assert_eq!(
            answer.sdp.contains("a=group:LS 0 1"),
            answered,
            "{ls}{}",
            answer.sdp
        );
        assert!(answer.sdp.contains("a=group:BUNDLE 0 1"), "{}", answer.sdp);
    }
    Ok(())
}
