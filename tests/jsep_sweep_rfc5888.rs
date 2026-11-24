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

/// Section 9.3: "If a server receives an offer that contains empty "a=group" lines, it SHOULD
/// add its capabilities also in the form of empty "a=group" lines to its answer." This
/// endpoint understands BUNDLE, LS and DDP: each that the answer does not use is answered as
/// an empty line, beside the groups the answer uses; a semantics it does not understand (FID
/// as a group of m= lines) is not. An offer without empty lines gets none, and an answer with
/// them is applied.
#[test]
fn empty_group_lines_of_an_offer_are_answered_with_this_endpoints_capabilities() -> TestResult {
    let empty_lines = |sdp: &str| -> Vec<String> {
        sdp.lines()
            .filter(|l| l.starts_with("a=group:") && !l.trim_end().contains(' '))
            .map(|l| l.trim_end().to_owned())
            .collect()
    };

    // BUNDLE used, LS and FID offered empty.
    let mut pc = default_peer()?;
    pc.set_remote_description(
        Instant::now(),
        RTCSessionDescription::offer(offer("a=group:LS\na=group:FID\n"))?,
    )?;
    let answer = pc.create_answer(None)?;
    assert!(
        answer.sdp.contains("a=group:BUNDLE 0 1\r\n"),
        "{}",
        answer.sdp
    );
    assert_eq!(
        empty_lines(&answer.sdp),
        ["a=group:LS", "a=group:DDP"],
        "{}",
        answer.sdp
    );
    pc.set_local_description(Instant::now(), answer)?;

    // No group used: an empty BUNDLE line only.
    let unbundled = offer("").replace("a=group:BUNDLE 0 1\r\n", "a=group:BUNDLE\r\n");
    let mut pc = default_peer()?;
    pc.set_remote_description(Instant::now(), RTCSessionDescription::offer(unbundled)?)?;
    let answer = pc.create_answer(None)?;
    assert_eq!(
        empty_lines(&answer.sdp),
        ["a=group:BUNDLE", "a=group:LS", "a=group:DDP"],
        "{}",
        answer.sdp
    );
    assert!(!answer.sdp.contains("a=group:BUNDLE 0"), "{}", answer.sdp);
    assert!(
        answer
            .sdp
            .lines()
            .filter(|l| l.starts_with("m="))
            .all(|l| !l.contains(" 0 UDP")),
        "{}",
        answer.sdp
    );
    pc.set_local_description(Instant::now(), answer)?;

    // No empty line offered: none answered.
    let mut pc = default_peer()?;
    pc.set_remote_description(Instant::now(), RTCSessionDescription::offer(offer(""))?)?;
    let answer = pc.create_answer(None)?;
    assert!(empty_lines(&answer.sdp).is_empty(), "{}", answer.sdp);
    Ok(())
}
