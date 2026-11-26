//! Each payload type of a generated description carries the `a=fmtp` parameters of its own
//! registered format, not those of the first registered format of its configuration.
//!
//! RFC 6184 section 8.2.2 makes `profile-level-id` (but its level) and `packetization-mode`
//! the configuration of an H.264 format, and lets the level differ in offer/answer, so the
//! engine's match of a format by its configuration ignores the level. Several registered
//! formats that differ only in level (the default High profile at levels 4.0, 4.1, 4.2, 5.0
//! and 5.1) all match that way, and the description used the first one's line for every
//! payload type (RFC 3264 section 5.1: each payload type of an offer is its own format, with
//! its own parameters; RFC 9429 section 5.2.1 / 5.3.1: the formats are the available ones).
//! The same holds for VP9 (`profile-id`), AV1 (`profile`) and H.265 (profile and tier), whose
//! levels or other parameters may differ between formats of one configuration. RTX names its
//! primary by payload type (`apt`, RFC 4588 section 8.6).

mod jsep_common;

use std::collections::{BTreeMap, BTreeSet};
use std::time::Instant;

use jsep_common::{TestResult, exchange, media_sections};
use rtci::peer_connection::configuration::media_engine::{
    MIME_TYPE_AV1, MIME_TYPE_H264, MIME_TYPE_HEVC, MIME_TYPE_VP9, MediaEngine,
};
use rtci::peer_connection::{RTCPeerConnection, RTCPeerConnectionBuilder};
use rtci::rtp_transceiver::RTCRtpTransceiverInit;
use rtci::rtp_transceiver::rtp_sender::{RTCRtpCodec, RTCRtpCodecParameters, RtpCodecKind};

/// A section's formats: payload type -> (encoding name in upper case, fmtp parameters).
type Formats = BTreeMap<u8, (String, BTreeSet<String>)>;

fn parameters(line: &str) -> BTreeSet<String> {
    line.split(';')
        .map(|p| p.trim().to_ascii_lowercase())
        .filter(|p| !p.is_empty())
        .collect()
}

fn formats(section: &[String]) -> Formats {
    let mut formats = Formats::new();
    for line in section {
        if let Some((pt, encoding)) = line
            .strip_prefix("a=rtpmap:")
            .and_then(|rest| rest.split_once(' '))
        {
            let name = encoding
                .split('/')
                .next()
                .unwrap_or("")
                .to_ascii_uppercase();
            formats
                .entry(pt.parse().expect("payload type"))
                .or_default()
                .0 = name;
        }
        if let Some((pt, line)) = line
            .strip_prefix("a=fmtp:")
            .and_then(|rest| rest.split_once(' '))
        {
            formats
                .entry(pt.parse().expect("payload type"))
                .or_default()
                .1 = parameters(line);
        }
    }
    formats
}

fn video_formats(sdp: &str) -> Formats {
    let sections = media_sections(sdp);
    let section = sections
        .iter()
        .find(|s| s[0].starts_with("m=video"))
        .unwrap_or_else(|| panic!("a video section:\n{sdp}"));
    formats(section)
}

/// No two payload types of one encoding (RTX aside: its `apt` tells them apart) have the
/// same parameters, unless `registered` has them so.
fn assert_distinct(formats: &Formats, what: &str, sdp: &str) {
    let mut seen: BTreeMap<(String, BTreeSet<String>), u8> = BTreeMap::new();
    for (pt, (name, fmtp)) in formats {
        if let Some(other) = seen.insert((name.clone(), fmtp.clone()), *pt) {
            panic!(
                "{what}: payload types {other} and {pt} ({name}) carry the same fmtp {fmtp:?}:\n{sdp}"
            );
        }
    }
}

/// Each payload type of `registered` that `formats` has carries its registered parameters,
/// `apt` included, and nothing in place of them.
fn assert_own_lines(formats: &Formats, registered: &[(u8, &str, &str)], what: &str, sdp: &str) {
    for (pt, name, line) in registered {
        let Some((got_name, got)) = formats.get(pt) else {
            panic!("{what}: payload type {pt} ({name} {line}) is missing:\n{sdp}");
        };
        assert_eq!(got_name, &name.to_ascii_uppercase(), "{what}: {pt}:\n{sdp}");
        let want = parameters(line);
        assert!(
            want.is_subset(got),
            "{what}: payload type {pt} ({name}) carries {got:?}, not its own {want:?}:\n{sdp}"
        );
        // A parameter of the same name with another value (the level of another format).
        for parameter in got.difference(&want) {
            let key = parameter.split('=').next().unwrap_or("");
            assert!(
                !want.iter().any(|w| w.split('=').next() == Some(key)),
                "{what}: payload type {pt} ({name}): {parameter} is not its own {want:?}:\n{sdp}"
            );
        }
    }
}

/// The default H.264 formats and their RTX (RFC 4588 `apt`): media_engine.rs
/// `register_default_codecs`.
const DEFAULT_H264: &[(u8, &str, &str)] = &[
    (
        102,
        "H264",
        "level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=42001f",
    ),
    (
        127,
        "H264",
        "level-asymmetry-allowed=1;packetization-mode=0;profile-level-id=42001f",
    ),
    (
        125,
        "H264",
        "level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=42e01f",
    ),
    (
        108,
        "H264",
        "level-asymmetry-allowed=1;packetization-mode=0;profile-level-id=42e01f",
    ),
    (
        123,
        "H264",
        "level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=640032",
    ),
    (
        118,
        "H264",
        "level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=640028",
    ),
    (
        119,
        "H264",
        "level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=640029",
    ),
    (
        120,
        "H264",
        "level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=64002a",
    ),
    (
        121,
        "H264",
        "level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=640033",
    ),
    (103, "RTX", "apt=102"),
    (104, "RTX", "apt=127"),
    (105, "RTX", "apt=125"),
    (109, "RTX", "apt=108"),
    (124, "RTX", "apt=123"),
    (110, "RTX", "apt=118"),
    (113, "RTX", "apt=119"),
    (114, "RTX", "apt=120"),
    (122, "RTX", "apt=121"),
];

fn default_peer() -> Result<RTCPeerConnection, Box<dyn std::error::Error>> {
    jsep_common::default_peer()
}

/// Offer, answer, and each side's next offer: every description gives each registered
/// payload type its own line (`registered`), and no two payload types one line.
fn check_round_trip(
    mut offerer: RTCPeerConnection,
    mut answerer: RTCPeerConnection,
    registered: &[(u8, &str, &str)],
) -> TestResult {
    offerer.add_transceiver_from_kind(RtpCodecKind::Video, None)?;
    let (offer, answer) = exchange(&mut offerer, &mut answerer)?;
    for (what, sdp) in [("offer", &offer), ("answer", &answer)] {
        let formats = video_formats(sdp);
        assert_own_lines(&formats, registered, what, sdp);
        assert_distinct(&formats, what, sdp);
    }
    let now = Instant::now();
    for (what, pc) in [
        ("the offerer's next offer", &mut offerer),
        ("the answerer's next offer", &mut answerer),
    ] {
        let offer = pc.create_offer(None)?;
        pc.set_local_description(now, offer.clone())?;
        let formats = video_formats(&offer.sdp);
        assert_own_lines(&formats, registered, what, &offer.sdp);
        assert_distinct(&formats, what, &offer.sdp);
        pc.set_local_description(
            now,
            rtci::peer_connection::sdp::RTCSessionDescription::rollback(None)?,
        )?;
    }
    Ok(())
}

#[test]
fn each_default_h264_payload_type_carries_its_own_fmtp() -> TestResult {
    check_round_trip(default_peer()?, default_peer()?, DEFAULT_H264)
}

fn codec(mime_type: &str, payload_type: u8, fmtp: &str) -> RTCRtpCodecParameters {
    RTCRtpCodecParameters {
        rtp_codec: RTCRtpCodec {
            mime_type: mime_type.to_owned(),
            clock_rate: 90000,
            channels: 0,
            sdp_fmtp_line: fmtp.to_owned(),
            rtcp_feedback: vec![],
        },
        payload_type,
    }
}

/// Formats of one configuration that differ in level (H.264, AV1, H.265), tier (AV1) or a
/// receiver limit (VP9), each with its RTX.
const CUSTOM: &[(u8, &str, &str)] = &[
    (
        96,
        "H264",
        "level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=42e01f",
    ),
    (
        97,
        "H264",
        "level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=42e028",
    ),
    (
        98,
        "H264",
        "level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=42e033",
    ),
    (99, "RTX", "apt=96"),
    (100, "RTX", "apt=97"),
    (101, "RTX", "apt=98"),
    (102, "AV1", "profile=0;level-idx=5;tier=0"),
    (103, "AV1", "profile=0;level-idx=8;tier=0"),
    (104, "AV1", "profile=0;level-idx=8;tier=1"),
    (105, "VP9", "profile-id=0"),
    (106, "VP9", "profile-id=0;max-fr=30;max-fs=3600"),
    (
        107,
        "H265",
        "level-id=93;profile-id=1;tier-flag=0;tx-mode=SRST",
    ),
    (
        108,
        "H265",
        "level-id=120;profile-id=1;tier-flag=0;tx-mode=SRST",
    ),
    (109, "RTX", "apt=102"),
    (110, "RTX", "apt=103"),
    (111, "RTX", "apt=104"),
    (112, "RTX", "apt=105"),
    (113, "RTX", "apt=106"),
    (114, "RTX", "apt=107"),
    (115, "RTX", "apt=108"),
];

fn custom_peer() -> Result<RTCPeerConnection, Box<dyn std::error::Error>> {
    let mut media_engine = MediaEngine::default();
    for (pt, name, fmtp) in CUSTOM {
        let mime_type = match *name {
            "H264" => MIME_TYPE_H264,
            "AV1" => MIME_TYPE_AV1,
            "VP9" => MIME_TYPE_VP9,
            "H265" => MIME_TYPE_HEVC,
            _ => "video/rtx",
        };
        media_engine.register_codec(codec(mime_type, *pt, fmtp), RtpCodecKind::Video)?;
    }
    Ok(RTCPeerConnectionBuilder::new()
        .with_media_engine(media_engine)
        .build(Instant::now())?)
}

#[test]
fn formats_of_one_configuration_each_carry_their_own_fmtp() -> TestResult {
    check_round_trip(custom_peer()?, custom_peer()?, CUSTOM)
}

/// W3C webrtc 5.2 / 5.3 getCapabilities list each registered format once, with its own
/// parameters; setCodecPreferences with them offers each of those formats, with its own
/// payload type and line (W3C webrtc 5.4: a preference is matched by the codec dictionary
/// match, which compares every parameter).
#[test]
fn capabilities_list_each_level_and_preferences_offer_each() -> TestResult {
    let mut pc = default_peer()?;
    let transceiver =
        pc.add_transceiver_from_kind(RtpCodecKind::Video, Some(RTCRtpTransceiverInit::recvonly()))?;
    let high: Vec<&(u8, &str, &str)> = DEFAULT_H264
        .iter()
        .filter(|(_, _, line)| line.contains("profile-level-id=64"))
        .collect();
    let receiver_codecs = pc
        .rtp_receiver(transceiver.into())
        .expect("receiver")
        .get_capabilities(RtpCodecKind::Video)
        .expect("video capabilities")
        .codecs;
    let sender_codecs = pc
        .rtp_sender(transceiver.into())
        .expect("sender")
        .get_capabilities(RtpCodecKind::Video)
        .expect("video capabilities")
        .codecs;
    for (what, codecs) in [("receiver", &receiver_codecs), ("sender", &sender_codecs)] {
        for (pt, _, line) in &high {
            let listed = codecs
                .iter()
                .filter(|c| {
                    c.mime_type.eq_ignore_ascii_case(MIME_TYPE_H264)
                        && parameters(&c.sdp_fmtp_line) == parameters(line)
                })
                .count();
            assert_eq!(
                listed, 1,
                "{what} capabilities list {pt}'s {line} once: {codecs:#?}"
            );
        }
    }
    let preferences: Vec<RTCRtpCodecParameters> = receiver_codecs
        .into_iter()
        .filter(|c| {
            c.mime_type.eq_ignore_ascii_case(MIME_TYPE_H264)
                && c.sdp_fmtp_line.contains("profile-level-id=64")
        })
        .map(|rtp_codec| RTCRtpCodecParameters {
            rtp_codec,
            payload_type: 0,
        })
        .collect();
    pc.rtp_transceiver(transceiver)
        .expect("transceiver")
        .set_codec_preferences(preferences)?;
    let offer = pc.create_offer(None)?;
    let formats = video_formats(&offer.sdp);
    let registered: Vec<(u8, &str, &str)> = high.iter().map(|r| **r).collect();
    assert_own_lines(&formats, &registered, "offer with preferences", &offer.sdp);
    assert_distinct(&formats, "offer with preferences", &offer.sdp);
    let offered_h264 = formats.values().filter(|(name, _)| name == "H264").count();
    assert_eq!(offered_h264, high.len(), "{}", offer.sdp);
    Ok(())
}
