//! The engine's answer to every offer real writers made (`tests/fixtures/browser-sdp/`:
//! Chromium, Firefox, WebKit, webrtc-rs 0.17), pinned line by line in
//! `tests/fixtures/browser-sdp-answers/`.
//!
//! An answer is what a browser has to accept, so a change to any line of it is to be seen in
//! review: the pinned file changes with the code that changes the answer. What differs from
//! one run to the next is replaced by a placeholder before the comparison (the `o=` line's
//! numbers, the ICE credentials, the certificate fingerprint, the `tls-id`, SSRCs, CNAMEs and
//! stream ids): everything else is compared as written, the payload type numbers above all.
//! RFC 3264 section 6.1: "if a particular codec was referenced with a specific payload type
//! number in the offer, that same payload type number SHOULD be used for that codec in the
//! answer"; the default answers here do, and only
//! `SettingEngineBuilder::with_own_payload_types_in_answers` numbers them otherwise
//! (`tests/payload_type_numbering_rtc2rtc.rs`).
//!
//! The answering peer has the default codecs and the default interceptors, and nothing to
//! send.
//!
//! To write the files again after a change that is meant to alter the answers, run the test
//! with `RTC_UPDATE_ANSWER_FIXTURES=1` and review the difference.

use std::path::PathBuf;
use std::time::Instant;

use rtci::interceptor::Registry;
use rtci::peer_connection::RTCPeerConnectionBuilder;
use rtci::peer_connection::configuration::interceptor_registry::register_default_interceptors;
use rtci::peer_connection::configuration::media_engine::MediaEngine;
use rtci::peer_connection::sdp::RTCSessionDescription;

fn fixtures(directory: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(directory)
}

/// The recorded offers: (file name, SDP).
fn offers() -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = std::fs::read_dir(fixtures("browser-sdp"))
        .expect("tests/fixtures/browser-sdp exists")
        .filter_map(|entry| entry.ok().map(|e| e.path()))
        .filter(|path| {
            path.file_name()
                .is_some_and(|name| name.to_string_lossy().ends_with("-offer.sdp"))
        })
        .map(|path| {
            (
                path.file_name().unwrap().to_string_lossy().into_owned(),
                std::fs::read_to_string(&path).expect("a readable fixture"),
            )
        })
        .collect();
    out.sort();
    out
}

/// One line of an answer with what a run chooses at random replaced by a placeholder.
fn normalized(line: &str) -> String {
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
        // `<ssrc> <attribute>:<value>`: the attribute's name stays.
        let attribute = value
            .split_once(' ')
            .map_or("", |(_, rest)| rest.split(':').next().unwrap_or_default());
        return format!("a=ssrc:<ssrc> {attribute}:<random>");
    }
    if let Some(value) = line.strip_prefix("a=ssrc-group:") {
        let semantics = value.split(' ').next().unwrap_or_default();
        let count = value.split(' ').count().saturating_sub(1);
        return format!("a=ssrc-group:{semantics} <{count} ssrcs>");
    }
    line.to_owned()
}

/// The engine's answer to `offer`, normalized, one line each.
fn answer_to(name: &str, offer: &str) -> String {
    let now = Instant::now();
    let mut media_engine = MediaEngine::default();
    media_engine
        .register_default_codecs()
        .expect("default codecs");
    let registry = register_default_interceptors(Registry::new(), &mut media_engine)
        .expect("default interceptors");
    let mut pc = RTCPeerConnectionBuilder::new()
        .with_media_engine(media_engine)
        .with_interceptor_registry(registry)
        .build(now)
        .expect("a peer connection");
    pc.set_remote_description(
        now,
        RTCSessionDescription::offer(offer.to_owned()).expect("an offer"),
    )
    .unwrap_or_else(|e| panic!("{name}: the offer is refused: {e}"));
    let answer = pc
        .create_answer(None)
        .unwrap_or_else(|e| panic!("{name}: no answer: {e}"));
    pc.set_local_description(now, answer.clone())
        .unwrap_or_else(|e| panic!("{name}: the answer is refused: {e}"));
    let mut text: String = answer
        .sdp
        .lines()
        .map(normalized)
        .collect::<Vec<_>>()
        .join("\n");
    text.push('\n');
    text
}

#[test]
fn the_answers_to_the_recorded_offers_are_the_pinned_ones() {
    let update = std::env::var_os("RTC_UPDATE_ANSWER_FIXTURES").is_some();
    let directory = fixtures("browser-sdp-answers");
    if update {
        std::fs::create_dir_all(&directory).expect("the fixture directory");
    }
    let offers = offers();
    assert!(offers.len() >= 20, "the recorded offers: {}", offers.len());
    let mut differing = vec![];
    for (name, offer) in &offers {
        let answer = answer_to(name, offer);
        // The same offer answered again gives the same lines: nothing left in them is
        // random, so a difference from the pinned file is a change of the engine's.
        let again = answer_to(name, offer);
        assert!(
            answer == again,
            "{name}: two answers to one offer differ after normalization:\n{}",
            diff_lines(&answer, &again).join("\n")
        );
        let path = directory.join(name.replace("-offer.sdp", "-answer.sdp"));
        if update {
            std::fs::write(&path, &answer).expect("a written fixture");
            continue;
        }
        let pinned = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("{}: {e}", path.display()))
            .replace("\r\n", "\n");
        if pinned != answer {
            let changed: Vec<String> = diff_lines(&pinned, &answer);
            differing.push(format!("{name}:\n{}", changed.join("\n")));
        }
    }
    assert!(
        differing.is_empty(),
        "the answers changed (RTC_UPDATE_ANSWER_FIXTURES=1 rewrites the pinned files):\n{}",
        differing.join("\n\n")
    );
    if !update {
        // No pinned answer without its offer.
        let pinned = std::fs::read_dir(&directory)
            .expect("tests/fixtures/browser-sdp-answers exists")
            .count();
        assert_eq!(pinned, offers.len(), "one pinned answer per recorded offer");
    }
}

/// The lines only one of the two texts has, `-` for the pinned one and `+` for the new.
fn diff_lines(pinned: &str, new: &str) -> Vec<String> {
    let (old_lines, new_lines): (Vec<&str>, Vec<&str>) =
        (pinned.lines().collect(), new.lines().collect());
    let mut out = vec![];
    for line in &old_lines {
        if !new_lines.contains(line) {
            out.push(format!("  - {line}"));
        }
    }
    for line in &new_lines {
        if !old_lines.contains(line) {
            out.push(format!("  + {line}"));
        }
    }
    if out.is_empty() {
        // The same lines in another order: the first place where the two part.
        for (index, (old, new)) in old_lines.iter().zip(&new_lines).enumerate() {
            if old != new {
                out.push(format!("  line {}: - {old}", index + 1));
                out.push(format!("  line {}: + {new}", index + 1));
                break;
            }
        }
        if out.is_empty() {
            out.push(format!(
                "  {} lines pinned, {} now",
                old_lines.len(),
                new_lines.len()
            ));
        }
    }
    out
}
