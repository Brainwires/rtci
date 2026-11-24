//! Each video section of a remote offer is answered from its own formats (RFC 9429, Section
//! 5.10), not from the codecs the first video section happened to negotiate.
//!
//! `SettingEngineBuilder::with_disable_media_engine_multiple_codecs` documents `false`, every
//! section negotiating its codecs, as the default; until it was wired the media engine latched
//! on the first video section and a second one that offered only VP9 had nothing to answer
//! with.

use std::time::Instant;

use rtci::peer_connection::RTCPeerConnectionBuilder;
use rtci::peer_connection::configuration::media_engine::MediaEngine;
use rtci::peer_connection::sdp::RTCSessionDescription;

fn section(mid: &str, pt: u8, rtpmap: &str, fmtp: &str) -> String {
    let fmtp = if fmtp.is_empty() {
        String::new()
    } else {
        format!("a=fmtp:{pt} {fmtp}\n")
    };
    format!(
        "m=video 9 UDP/TLS/RTP/SAVPF {pt}
c=IN IP4 0.0.0.0
a=ice-ufrag:4ZcD
a=ice-pwd:2/1muCWoOi3uLifh0NuRHlkwz
a=fingerprint:sha-256 F2:1C:F2:9E:B4:BE:58:19:C9:48:1A:D9:C4:A7:5D:5A:1F:61:7C:17:6B:07:8E:39:A2:E2:B2:BB:BF:4B:D2:16
a=setup:actpass
a=mid:{mid}
a=sendonly
a=rtcp-mux
a=rtpmap:{pt} {rtpmap}
{fmtp}"
    )
}

fn offer() -> String {
    let sdp = format!(
        "v=0
o=- 781500112831855234 6 IN IP4 127.0.0.1
s=-
t=0 0
a=group:BUNDLE 0 1
{}{}",
        section("0", 96, "VP8/90000", ""),
        section("1", 98, "VP9/90000", "profile-id=0"),
    );
    sdp.replace("\r\n", "\n").replace('\n', "\r\n")
}

/// The lines of the answer's media section whose `a=mid` is `mid`.
fn answer_section<'a>(sdp: &'a str, mid: &str) -> Vec<&'a str> {
    let mut sections: Vec<Vec<&str>> = vec![];
    for line in sdp.lines() {
        if line.starts_with("m=") {
            sections.push(vec![line]);
        } else if let Some(current) = sections.last_mut() {
            current.push(line);
        }
    }
    let wanted = format!("a=mid:{mid}");
    sections
        .into_iter()
        .find(|lines| lines.contains(&wanted.as_str()))
        .unwrap_or_else(|| panic!("no section with {wanted} in\n{sdp}"))
}

#[test]
fn a_second_video_section_is_answered_with_its_own_codec() -> Result<(), Box<dyn std::error::Error>>
{
    let mut media_engine = MediaEngine::default();
    media_engine.register_default_codecs()?;
    let mut answerer = RTCPeerConnectionBuilder::new()
        .with_media_engine(media_engine)
        .build(Instant::now())?;

    answerer.set_remote_description(Instant::now(), RTCSessionDescription::offer(offer())?)?;
    let answer = answerer.create_answer(None)?;

    let first = answer_section(&answer.sdp, "0");
    assert!(
        first.iter().any(|l| l.starts_with("m=video 9 ")),
        "the VP8 section is accepted:\n{}",
        answer.sdp
    );
    assert!(first.contains(&"a=rtpmap:96 VP8/90000"), "{}", answer.sdp);

    let second = answer_section(&answer.sdp, "1");
    assert!(
        second.iter().any(|l| l.starts_with("m=video 9 ")),
        "the VP9 section is accepted:\n{}",
        answer.sdp
    );
    assert!(
        second.contains(&"a=rtpmap:98 VP9/90000"),
        "the second section answers VP9, the one format it offered:\n{}",
        answer.sdp
    );
    // RFC 9429 section 5.3.1: the offered format first; the formats the offer lacked (VP8,
    // and the other registered ones) may follow it, but never ahead of it.
    let m_line = second
        .iter()
        .find(|l| l.starts_with("m=video "))
        .expect("an m= line");
    assert_eq!(
        m_line.split_whitespace().nth(3),
        Some("98"),
        "the offered VP9 comes first:\n{}",
        answer.sdp
    );
    Ok(())
}
