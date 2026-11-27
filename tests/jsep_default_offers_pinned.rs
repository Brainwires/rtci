//! The engine's initial offers under its default settings, pinned line by line in
//! `tests/fixtures/engine-offers/`: the bundle policies with audio, video and a data channel,
//! where bundle-only sections are written (RFC 9429 sections 4.1.1 and 5.2.1, RFC 9143 sections
//! 6 and 7.1.3). A change to any line of a default offer is to be seen in review: the pinned file
//! changes with the code that changes it. What differs from one run to the next is replaced by a
//! placeholder before the comparison (the `o=` line's numbers, the ICE credentials, the
//! certificate fingerprint, the `tls-id`, CNAMEs and stream ids).
//!
//! The pinned files were written by this test on `conf/bundle-3-max-bundle-browser-cells` (8a10cfb2,
//! agent-test run 45911540683), before
//! `SettingEngineBuilder::with_bundle_only_sections_in_browser_form` existed, so the comparison
//! shows the default form is the one before that setting. To write them again after a change
//! meant to alter a default offer, run the test with `RTC_UPDATE_OFFER_FIXTURES=1` (it prints
//! each file too) and review the difference.

mod jsep_common;

use std::path::PathBuf;
use std::time::Instant;

use jsep_common::video_track;
use rtci::interceptor::Registry;
use rtci::peer_connection::RTCPeerConnectionBuilder;
use rtci::peer_connection::configuration::interceptor_registry::register_default_interceptors;
use rtci::peer_connection::configuration::media_engine::MediaEngine;
use rtci::peer_connection::configuration::{RTCBundlePolicy, RTCConfigurationBuilder};
use rtci::rtp_transceiver::rtp_sender::RtpCodecKind;

fn fixtures() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/engine-offers")
}

/// An SSRC as `<ssrc-N>`, N its order of first appearance in the offer: the RTX SSRCs are
/// random, the media ones the tracks' own; the order and the pairing of each FID group stay.
fn ssrc(value: &str, seen: &mut Vec<String>) -> String {
    let at = seen.iter().position(|s| s == value).unwrap_or_else(|| {
        seen.push(value.to_owned());
        seen.len() - 1
    });
    format!("<ssrc-{}>", at + 1)
}

/// One line of an offer with what a run chooses at random replaced by a placeholder.
fn normalized(line: &str, seen: &mut Vec<String>) -> String {
    let line = line.trim_end();
    if line.starts_with("o=") {
        let mut fields: Vec<&str> = line.split(' ').collect();
        if fields.len() >= 3 {
            fields[1] = "<session-id>";
            fields[2] = "<session-version>";
        }
        return fields.join(" ");
    }
    for key in ["a=ice-ufrag:", "a=ice-pwd:", "a=tls-id:", "a=msid:"] {
        if line.starts_with(key) {
            return format!("{key}<random>");
        }
    }
    if let Some(value) = line.strip_prefix("a=fingerprint:") {
        let algorithm = value.split(' ').next().unwrap_or_default();
        return format!("a=fingerprint:{algorithm} <certificate>");
    }
    if let Some(value) = line.strip_prefix("a=ssrc:") {
        // `<ssrc> <attribute>:<value>`: the CNAME and stream ids are random.
        let (number, rest) = value.split_once(' ').unwrap_or((value, ""));
        let attribute = rest.split(':').next().unwrap_or_default();
        return format!("a=ssrc:{} {attribute}:<random>", ssrc(number, seen));
    }
    if let Some(value) = line.strip_prefix("a=ssrc-group:") {
        let mut fields = value.split(' ');
        let semantics = fields.next().unwrap_or_default();
        let ssrcs: Vec<String> = fields.map(|n| ssrc(n, seen)).collect();
        return format!("a=ssrc-group:{semantics} {}", ssrcs.join(" "));
    }
    line.to_owned()
}

/// The shapes pinned: (file stem, bundle policy). Each offers a receive-only audio
/// transceiver, two video tracks and a data channel, in that order.
const SHAPES: [(&str, Option<RTCBundlePolicy>); 4] = [
    ("default-policy", None),
    ("max-bundle", Some(RTCBundlePolicy::MaxBundle)),
    ("must-bundle", Some(RTCBundlePolicy::MustBundle)),
    ("max-compat", Some(RTCBundlePolicy::MaxCompat)),
];

/// The engine's initial offer for a shape, normalized, one line each.
fn offer(policy: Option<RTCBundlePolicy>) -> String {
    let now = Instant::now();
    let mut media_engine = MediaEngine::default();
    media_engine
        .register_default_codecs()
        .expect("default codecs");
    let registry = register_default_interceptors(Registry::new(), &mut media_engine)
        .expect("default interceptors");
    let mut builder = RTCPeerConnectionBuilder::new()
        .with_media_engine(media_engine)
        .with_interceptor_registry(registry);
    if let Some(policy) = policy {
        builder = builder.with_configuration(
            RTCConfigurationBuilder::new()
                .with_bundle_policy(policy)
                .build(),
        );
    }
    let mut pc = builder.build(now).expect("a peer connection");
    pc.add_transceiver_from_kind(
        RtpCodecKind::Audio,
        Some(rtci::rtp_transceiver::RTCRtpTransceiverInit::recvonly()),
    )
    .expect("an audio transceiver");
    pc.add_track(video_track("first", 0x0101_0101))
        .expect("a video track");
    pc.add_track(video_track("second", 0x0202_0202))
        .expect("a video track");
    pc.create_data_channel("data", None).expect("a channel");
    let offer = pc.create_offer(None).expect("an offer");
    let mut seen = vec![];
    let mut text: String = offer
        .sdp
        .lines()
        .map(|line| normalized(line, &mut seen))
        .collect::<Vec<_>>()
        .join("\n");
    text.push('\n');
    text
}

#[test]
fn the_default_initial_offers_are_the_pinned_ones() {
    let update = std::env::var_os("RTC_UPDATE_OFFER_FIXTURES").is_some();
    let directory = fixtures();
    if update {
        std::fs::create_dir_all(&directory).expect("the fixture directory");
    }
    let mut differing = vec![];
    for (stem, policy) in SHAPES {
        let text = offer(policy);
        // The same shape offered again gives the same lines: nothing left in them is random.
        assert_eq!(
            text,
            offer(policy),
            "{stem}: two offers differ after normalization"
        );
        let path = directory.join(format!("{stem}-offer.sdp"));
        if update {
            std::fs::write(&path, &text).expect("a written fixture");
            println!("==== {}\n{text}==== end", path.display());
            continue;
        }
        let pinned = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("{}: {e}", path.display()))
            .replace("\r\n", "\n");
        if pinned != text {
            let gone: Vec<String> = pinned
                .lines()
                .filter(|l| !text.lines().any(|n| n == *l))
                .map(|l| format!("- {l}"))
                .collect();
            let new: Vec<String> = text
                .lines()
                .filter(|l| !pinned.lines().any(|p| p == *l))
                .map(|l| format!("+ {l}"))
                .collect();
            differing.push(format!(
                "{stem}:\n{}\n{}\n(whole offer:)\n{text}",
                gone.join("\n"),
                new.join("\n")
            ));
        }
    }
    assert!(
        differing.is_empty(),
        "the default offers changed (RTC_UPDATE_OFFER_FIXTURES=1 rewrites the pinned files):\n{}",
        differing.join("\n\n")
    );
}
