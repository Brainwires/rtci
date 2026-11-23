//! RED for audio (RFC 2198) in the default formats, against the browsers' descriptions
//! (`tests/fixtures/browser-sdp/`): RFC 8854 section 4.2 has a WebRTC endpoint support it, and
//! Chromium and WebKit offer `red/48000/2` with Opus as primary and redundancy, after Opus.

mod jsep_common;

use std::time::Instant;

use jsep_common::{TestResult, default_peer, media_sections};
use rtc::peer_connection::sdp::RTCSessionDescription;
use rtc::rtp_transceiver::rtp_sender::RtpCodecKind;

const CHROMIUM: &str =
    include_str!("fixtures/browser-sdp/chromium--reflect-audio-opus--1-offer.sdp");
const WEBKIT: &str = include_str!("fixtures/browser-sdp/webkit--reflect-audio-opus--1-offer.sdp");
const FIREFOX: &str = include_str!("fixtures/browser-sdp/firefox--reflect-audio-opus--1-offer.sdp");

/// The first audio section's formats in m= line order, and its `red` rtpmap and fmtp lines.
fn red_of(sdp: &str) -> (Vec<String>, Vec<String>) {
    let section = media_sections(sdp)
        .into_iter()
        .find(|s| s[0].starts_with("m=audio"))
        .expect("an audio section");
    let formats: Vec<String> = section[0].split(' ').skip(3).map(str::to_owned).collect();
    let red: Vec<&str> = section
        .iter()
        .filter_map(|l| l.strip_prefix("a=rtpmap:"))
        .filter(|rest| rest.to_ascii_lowercase().contains(" red/"))
        .filter_map(|rest| rest.split(' ').next())
        .collect();
    let lines = section
        .iter()
        .filter(|l| {
            red.iter().any(|pt| {
                l.starts_with(&format!("a=rtpmap:{pt} ")) || l.starts_with(&format!("a=fmtp:{pt} "))
            })
        })
        .cloned()
        .collect();
    (formats, lines)
}

/// The default offer lists RED as Chromium and WebKit do: `a=rtpmap:63 red/48000/2` and
/// `a=fmtp:63 111/111`, right after Opus on the m= line.
#[test]
fn the_default_offer_has_red_as_chromium_and_webkit_offer_it() -> TestResult {
    let mut pc = default_peer()?;
    pc.add_transceiver_from_kind(RtpCodecKind::Audio, None)?;
    let offer = pc.create_offer(None)?;
    let (formats, lines) = red_of(&offer.sdp);
    for browser in [CHROMIUM, WEBKIT] {
        let (browser_formats, browser_lines) = red_of(browser);
        assert_eq!(lines, browser_lines, "{}", offer.sdp);
        assert_eq!(formats[..2], browser_formats[..2], "{}", offer.sdp);
    }
    assert_eq!(
        lines,
        vec!["a=rtpmap:63 red/48000/2", "a=fmtp:63 111/111"],
        "{}",
        offer.sdp
    );
    Ok(())
}

/// An answer to a browser offer with RED accepts it, in the offer's numbering; an answer to
/// Firefox's offer, which has none, has none either.
#[test]
fn a_browser_offer_with_red_is_answered_with_red() -> TestResult {
    for (browser, sdp) in [
        ("chromium", CHROMIUM),
        ("webkit", WEBKIT),
        ("firefox", FIREFOX),
    ] {
        let mut pc = default_peer()?;
        pc.set_remote_description(
            Instant::now(),
            RTCSessionDescription::offer(sdp.to_owned())?,
        )?;
        let answer = pc.create_answer(None)?;
        let (formats, lines) = red_of(&answer.sdp);
        if browser == "firefox" {
            assert!(lines.is_empty(), "{browser}: {}", answer.sdp);
        } else {
            assert_eq!(
                lines,
                vec!["a=rtpmap:63 red/48000/2", "a=fmtp:63 111/111"],
                "{browser}: {}",
                answer.sdp
            );
            assert!(
                formats.iter().any(|f| f == "63"),
                "{browser}: {}",
                answer.sdp
            );
        }
    }
    Ok(())
}
