//! RED for audio (RFC 2198) in the default formats, against the browsers' descriptions
//! (`tests/fixtures/browser-sdp/`): RFC 8854 section 4.2 has a WebRTC endpoint support it, and
//! Chromium and WebKit offer `red/48000/2` with Opus as primary and redundancy, after Opus, and
//! answer it after Opus. Which format the engine sends them follows that order (RFC 3264
//! sections 5.1 and 6.1) unless the application decides (`AudioRedundancy`).

mod jsep_common;

use std::time::Instant;

use bytes::Bytes;
use jsep_common::{TestResult, default_peer, media_sections};
use rtc::interceptor::{
    AttributedPacket, AudioRedundancy, Interceptor, Packet, RedAudioBuilder, StreamInfo,
    TaggedPacket,
};
use rtc::peer_connection::sdp::RTCSessionDescription;
use rtc::rtp_transceiver::rtp_sender::RtpCodecKind;
use rtc::sansio::Protocol;
use rtc::shared::TransportContext;

const CHROMIUM: &str =
    include_str!("fixtures/browser-sdp/chromium--reflect-audio-opus--1-offer.sdp");
const WEBKIT: &str = include_str!("fixtures/browser-sdp/webkit--reflect-audio-opus--1-offer.sdp");
const FIREFOX: &str = include_str!("fixtures/browser-sdp/firefox--reflect-audio-opus--1-offer.sdp");
/// The browsers' answers to the engine's offer (with RED after Opus) in the same matrix run.
const CHROMIUM_ANSWER: &str = include_str!(
    "fixtures/browser-sdp/chromium--rust-offers-media-the-browser-answers-and-decodes-it--2-answer.sdp"
);
const WEBKIT_ANSWER: &str = include_str!(
    "fixtures/browser-sdp/webkit--rust-offers-media-the-browser-answers-and-decodes-it--2-answer.sdp"
);
const FIREFOX_ANSWER: &str = include_str!(
    "fixtures/browser-sdp/firefox--rust-offers-media-the-browser-answers-and-decodes-it--2-answer.sdp"
);

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

/// The engine's local Opus stream as the peer connection binds it after applying `sdp` as the
/// remote description: Opus with the description's payload type, and the section's formats
/// in its m= line order (the remote side's order of preference).
fn opus_stream_of(sdp: &str) -> StreamInfo {
    let section = media_sections(sdp)
        .into_iter()
        .find(|s| s[0].starts_with("m=audio"))
        .expect("an audio section");
    let formats: Vec<u8> = section[0]
        .split(' ')
        .skip(3)
        .filter_map(|f| f.parse().ok())
        .collect();
    let rtpmap = |pt: u8| {
        section.iter().find_map(|l| {
            l.strip_prefix(&format!("a=rtpmap:{pt} "))
                .and_then(|rest| rest.split('/').next())
                .map(|name| format!("audio/{name}"))
        })
    };
    let fmtp = |pt: u8| {
        section
            .iter()
            .find_map(|l| l.strip_prefix(&format!("a=fmtp:{pt} ")).map(str::to_owned))
            .unwrap_or_default()
    };
    let opus = formats
        .iter()
        .copied()
        .find(|pt| rtpmap(*pt).is_some_and(|m| m.eq_ignore_ascii_case("audio/opus")))
        .expect("Opus");
    StreamInfo {
        ssrc: 1,
        payload_type: opus,
        mime_type: "audio/opus".to_owned(),
        clock_rate: 48_000,
        channels: 2,
        section_mime_types: formats
            .iter()
            .filter_map(|pt| rtpmap(*pt).map(|m| (*pt, m)))
            .collect(),
        section_fmtp_lines: formats.iter().map(|pt| (*pt, fmtp(*pt))).collect(),
        ..Default::default()
    }
}

/// The payload type the engine's `RedAudioInterceptor` puts on an Opus packet of `info`.
fn sent_with(info: &StreamInfo, policy: AudioRedundancy) -> u8 {
    let mut red = RedAudioBuilder::new().with_audio_redundancy(policy).build();
    red.bind_local_stream(info);
    red.handle_write(TaggedPacket {
        now: Instant::now(),
        transport: TransportContext::default(),
        message: AttributedPacket::new(Packet::Rtp(rtc::rtp::Packet {
            header: rtc::rtp::header::Header {
                version: 2,
                ssrc: info.ssrc,
                payload_type: info.payload_type,
                sequence_number: 1,
                ..Default::default()
            },
            payload: Bytes::from_static(&[0x10; 60]),
        })),
    })
    .expect("written");
    match red.poll_write().expect("a packet").message.packet {
        Packet::Rtp(packet) => packet.header.payload_type,
        _ => panic!("RTP expected"),
    }
}

/// What the engine sends each recorded browser description, pinned: Chromium and WebKit list
/// RED after Opus in their offers and in their answers to the engine, so by default
/// (`WhenPreferred`, RFC 3264 sections 5.1 and 6.1, libwebrtc's own rule) the engine sends
/// them Opus (111), as they send it Opus; `Always` sends them RED (63); `Never` Opus. Firefox
/// negotiates no RED: Opus (its offer's 109, its answer's 111) in every mode.
#[test]
fn the_format_the_engine_sends_each_browser_description_is_pinned() {
    use AudioRedundancy::{Always, Never, WhenPreferred};
    let cases: [(&str, &str, [u8; 3]); 6] = [
        ("chromium offer", CHROMIUM, [111, 63, 111]),
        ("webkit offer", WEBKIT, [111, 63, 111]),
        ("firefox offer", FIREFOX, [109, 109, 109]),
        ("chromium answer", CHROMIUM_ANSWER, [111, 63, 111]),
        ("webkit answer", WEBKIT_ANSWER, [111, 63, 111]),
        ("firefox answer", FIREFOX_ANSWER, [111, 111, 111]),
    ];
    for (name, sdp, expected) in cases {
        let info = opus_stream_of(sdp);
        let got = [WhenPreferred, Always, Never].map(|policy| sent_with(&info, policy));
        assert_eq!(
            got, expected,
            "{name}: [WhenPreferred, Always, Never] (formats {:?})",
            info.section_mime_types
        );
    }
}
