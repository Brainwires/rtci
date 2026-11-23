//! RFC 5583 decoding dependencies (`a=group:DDP`, `a=depend`), as RFC 7798 section 7.2.5 uses
//! them for layered H.265 over several sessions: a remote description's dependencies are
//! read, and an answer keeps the offered relations for what it accepts (section 6.1). The
//! formats here are VP8: the signalling is the same for any codec.

mod jsep_common;

use std::time::Instant;

use jsep_common::{TestResult, crlf, default_peer, media_sections};
use rtc::peer_connection::sdp::RTCSessionDescription;
use rtc::sdp::attribute::{Dependency, DependencyType};

const SESSION: &str = "v=0
o=- 1 2 IN IP4 127.0.0.1
s=-
t=0 0
a=group:BUNDLE L1 L2
a=fingerprint:sha-256 4A:AD:B9:B1:3F:82:18:3B:54:02:12:DF:3E:5D:49:6B:19:E5:7C:AB:4A:AD:B9:B1:3F:82:18:3B:54:02:12:DF
a=ice-ufrag:Ab1c
a=ice-pwd:9/9muCWoOi3uLifh0NuRHlkwz
";

fn section(mid: &str, formats: &str, extra: &str) -> String {
    let mut s = format!(
        "m=video 9 UDP/TLS/RTP/SAVPF {formats}\nc=IN IP4 0.0.0.0\na=setup:actpass\na=mid:{mid}\na=sendrecv\na=rtcp-mux\n"
    );
    for pt in formats.split_whitespace() {
        s.push_str(&format!("a=rtpmap:{pt} VP8/90000\n"));
    }
    s.push_str(extra);
    s
}

fn offer(group: &str, l2_depend: &str) -> String {
    crlf(&format!(
        "{SESSION}{group}{}{}",
        section("L1", "96", ""),
        section("L2", "97", l2_depend)
    ))
}

/// The dependencies of a remote offer are read (`remote_decoding_dependencies`), and the
/// answer has the DDP group and the enhancement section's `a=depend` as offered.
#[test]
fn an_answer_keeps_the_offered_layered_dependency() -> TestResult {
    let mut pc = default_peer()?;
    let sdp = offer("a=group:DDP L1 L2\n", "a=depend:97 lay L1:96\n");
    pc.set_remote_description(Instant::now(), RTCSessionDescription::offer(sdp)?)?;
    let dependencies = pc.remote_decoding_dependencies();
    assert_eq!(dependencies.len(), 1, "{dependencies:?}");
    assert_eq!(dependencies[0].0, "L2");
    assert_eq!(
        dependencies[0].1.dependencies,
        vec![Dependency {
            fmt: "97".to_owned(),
            typ: DependencyType::Lay,
            on: Some(("L1".to_owned(), vec!["96".to_owned()])),
        }]
    );
    let answer = pc.create_answer(None)?;
    assert!(
        answer.sdp.lines().any(|l| l == "a=group:DDP L1 L2"),
        "{}",
        answer.sdp
    );
    let sections = media_sections(&answer.sdp);
    assert!(
        sections[1].iter().any(|l| l == "a=depend:97 lay L1:96"),
        "{}",
        answer.sdp
    );
    assert!(!sections[0].iter().any(|l| l.starts_with("a=depend")));
    pc.set_local_description(Instant::now(), answer)?;
    Ok(())
}

/// Without a DDP group the `a=depend` lines mean nothing (section 5.2.1: the group "informs a
/// receiver about the requirement for handling the media streams of the group"), and a group
/// whose sections state different dependency types is not one RFC 5583 allows: neither is
/// read nor answered.
#[test]
fn dependencies_outside_a_valid_ddp_group_are_not_taken() -> TestResult {
    for (group, depend) in [
        ("", "a=depend:97 lay L1:96\n"),
        ("a=group:DDP L1 L2\n", "a=depend:97 lay L1:96\n"),
    ] {
        let mut pc = default_peer()?;
        let l1 = if group.is_empty() {
            ""
        } else {
            "a=depend:96 mdc\n"
        };
        let sdp = crlf(&format!(
            "{SESSION}{group}{}{}",
            section("L1", "96", l1),
            section("L2", "97", depend)
        ));
        pc.set_remote_description(Instant::now(), RTCSessionDescription::offer(sdp)?)?;
        assert!(pc.remote_decoding_dependencies().is_empty());
        let answer = pc.create_answer(None)?;
        assert!(!answer.sdp.contains("a=group:DDP"), "{}", answer.sdp);
        assert!(!answer.sdp.contains("a=depend"), "{}", answer.sdp);
    }
    Ok(())
}

/// Section 6.1: the answerer "MAY remove media Operation Points", but "cannot change the
/// dependency relations": a dependency on a format the answer does not keep is removed with
/// its line; the group stays for the sections that remain.
#[test]
fn a_dependency_on_a_format_the_answer_drops_is_removed() -> TestResult {
    let mut pc = default_peer()?;
    let l1 = "m=video 9 UDP/TLS/RTP/SAVPF 96 120\nc=IN IP4 0.0.0.0\na=setup:actpass\na=mid:L1\na=sendrecv\na=rtcp-mux\na=rtpmap:96 VP8/90000\na=rtpmap:120 X-UNKNOWN/90000\n";
    let sdp = crlf(&format!(
        "{SESSION}a=group:DDP L1 L2\n{l1}{}",
        section("L2", "97 98", "a=depend:97 lay L1:96; 98 lay L1:120\n")
    ));
    pc.set_remote_description(Instant::now(), RTCSessionDescription::offer(sdp)?)?;
    let answer = pc.create_answer(None)?;
    let sections = media_sections(&answer.sdp);
    let depend: Vec<&str> = sections[1]
        .iter()
        .filter(|l| l.starts_with("a=depend"))
        .map(String::as_str)
        .collect();
    assert_eq!(depend, vec!["a=depend:97 lay L1:96"], "{}", answer.sdp);
    assert!(answer.sdp.lines().any(|l| l == "a=group:DDP L1 L2"));
    Ok(())
}
