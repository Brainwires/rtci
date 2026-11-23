//! The answers to the offers real writers made (`tests/fixtures/browser-sdp/`: Chromium,
//! Firefox, WebKit, webrtc-rs 0.17) number every format as the offer does, and both
//! directions of each section then carry those numbers.
//!
//! RFC 3264 section 6.1: "if a particular codec was referenced with a specific payload type
//! number in the offer, that same payload type number SHOULD be used for that codec in the
//! answer", and the answerer "MUST use the payload type numbers from the offer" to send. The
//! engine keeps the payload types of the two directions of a section apart (the sender has
//! the remote description's, the receiver the local description's); with a peer that offers,
//! and with the default settings, they are the same numbers, and the answers to the recorded
//! offers are what they were before the two were kept apart.
//!
//! With `RTC_DUMP_ANSWER_CODECS=<directory>` the format lines of each answer are also written
//! to `<directory>/<fixture>.txt`, to compare two builds.

mod jsep_common;

use std::path::PathBuf;
use std::time::Instant;

use jsep_common::{default_peer, media_sections};
use rtc::peer_connection::sdp::RTCSessionDescription;
use rtc::rtp_transceiver::rtp_sender::RTCRtpCodecParameters;

/// The recorded offers: (file name, SDP).
fn offers() -> Vec<(String, String)> {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/browser-sdp");
    let mut out: Vec<(String, String)> = std::fs::read_dir(&dir)
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

/// A media section's formats: (payload type, `a=rtpmap` encoding in lower case, `a=fmtp`
/// parameters), in m= line order. A format without `a=rtpmap` (a static one) has an empty
/// encoding.
fn formats(section: &[String]) -> Vec<(u8, String, String)> {
    section[0]
        .split_whitespace()
        .skip(3)
        .filter_map(|pt| pt.parse::<u8>().ok())
        .map(|pt| {
            let value = |key: &str| {
                section
                    .iter()
                    .find_map(|l| l.strip_prefix(&format!("a={key}:{pt} ")))
                    .unwrap_or_default()
                    .trim()
                    .to_owned()
            };
            (pt, value("rtpmap").to_ascii_lowercase(), value("fmtp"))
        })
        .collect()
}

fn is_rtp(section: &[String]) -> bool {
    section[0].starts_with("m=audio") || section[0].starts_with("m=video")
}

fn rejected(section: &[String]) -> bool {
    section[0].split_whitespace().nth(1) == Some("0")
}

/// Whether a format's `a=fmtp` names other formats by payload type: RTX (`apt`, RFC 4588)
/// and RED (RFC 2198).
fn names_payload_types(encoding: &str) -> bool {
    encoding.starts_with("rtx/") || encoding.starts_with("red/")
}

/// The `<type>/<subtype>` of a codec as the description's `a=rtpmap` spells its subtype.
fn subtype(codec: &RTCRtpCodecParameters) -> String {
    codec
        .rtp_codec
        .mime_type
        .split_once('/')
        .map_or("", |(_, subtype)| subtype)
        .to_ascii_lowercase()
}

#[test]
fn answers_to_the_recorded_offers_use_the_offers_numbers_in_both_directions() {
    let dump = std::env::var_os("RTC_DUMP_ANSWER_CODECS").map(PathBuf::from);
    if let Some(dir) = &dump {
        std::fs::create_dir_all(dir).expect("the dump directory");
    }
    let offers = offers();
    assert!(offers.len() >= 20, "the recorded offers: {}", offers.len());
    let mut answered_formats = 0;
    for (name, sdp) in offers {
        let now = Instant::now();
        let mut pc = default_peer().expect("a peer");
        pc.set_remote_description(
            now,
            RTCSessionDescription::offer(sdp.clone()).expect("an offer"),
        )
        .unwrap_or_else(|e| panic!("{name}: the offer is refused: {e}"));
        let answer = pc
            .create_answer(None)
            .unwrap_or_else(|e| panic!("{name}: no answer: {e}"));
        pc.set_local_description(now, answer.clone())
            .unwrap_or_else(|e| panic!("{name}: the answer is refused: {e}"));

        let offered = media_sections(&sdp);
        let answered = media_sections(&answer.sdp);
        assert_eq!(offered.len(), answered.len(), "{name}");
        if let Some(dir) = &dump {
            let lines: Vec<&str> = answer
                .sdp
                .lines()
                .filter(|l| {
                    ["m=", "a=rtpmap:", "a=fmtp:", "a=rtcp-fb:", "a=mid:"]
                        .iter()
                        .any(|prefix| l.starts_with(prefix))
                })
                // The port is the default candidate's.
                .map(|l| l.trim_end())
                .collect();
            std::fs::write(dir.join(format!("{name}.txt")), lines.join("\n") + "\n")
                .expect("a written dump");
        }

        for (offer, answer) in offered.iter().zip(&answered) {
            if !is_rtp(answer) || rejected(answer) {
                continue;
            }
            let offer_formats = formats(offer);
            let answer_formats = formats(answer);
            for (pt, encoding, fmtp) in &answer_formats {
                match offer_formats.iter().find(|(offered, _, _)| offered == pt) {
                    Some((_, offered_encoding, offered_fmtp)) => {
                        assert_eq!(
                            encoding, offered_encoding,
                            "{name}: payload type {pt} names another format than in the offer"
                        );
                        if names_payload_types(encoding) {
                            assert_eq!(
                                fmtp, offered_fmtp,
                                "{name}: payload type {pt} ({encoding}) names other formats \
                                 than in the offer"
                            );
                        }
                        answered_formats += 1;
                    }
                    // A format the answer adds (RFC 9429 section 5.3.1): one the offer does
                    // not have under another number, but for a codec whose parameters make
                    // each configuration a format of its own.
                    None => {
                        let configured = ["h264/", "h265/", "vp9/", "av1/"]
                            .iter()
                            .any(|codec| encoding.starts_with(codec));
                        assert!(
                            configured
                                || !offer_formats
                                    .iter()
                                    .any(|(_, offered, _)| offered == encoding),
                            "{name}: {encoding} is answered as {pt}, not with the offer's number"
                        );
                    }
                }
            }
        }

        // Each transceiver: the sender's codecs carry the offer's numbers (RFC 3264 section
        // 6.1), the receiver's the answer's, which are the same.
        let transceivers: Vec<_> = pc.get_transceivers().collect();
        for id in transceivers {
            let (mid, sender, receiver) = {
                let transceiver = pc.rtp_transceiver(id).expect("transceiver");
                (
                    transceiver.mid().clone(),
                    transceiver.sender(),
                    transceiver.receiver(),
                )
            };
            let Some(mid) = mid else {
                continue;
            };
            let section = |sections: &[Vec<String>]| -> Option<Vec<(u8, String, String)>> {
                sections
                    .iter()
                    .find(|s| jsep_common::mid_of(s) == Some(mid.as_str()))
                    .filter(|s| !rejected(s))
                    .map(|s| formats(s))
            };
            let (Some(offer_formats), Some(answer_formats)) =
                (section(&offered), section(&answered))
            else {
                continue;
            };
            let listed = |formats: &[(u8, String, String)], codec: &RTCRtpCodecParameters| {
                formats.iter().any(|(pt, encoding, fmtp)| {
                    *pt == codec.payload_type
                        // A static payload type has no `a=rtpmap` to compare.
                        && (encoding.is_empty() || encoding.starts_with(&subtype(codec)))
                        && (!names_payload_types(encoding)
                            || *fmtp == codec.rtp_codec.sdp_fmtp_line)
                })
            };
            if let Some(sender) = sender {
                let codecs = pc
                    .rtp_sender(sender)
                    .expect("sender")
                    .get_parameters()
                    .rtp_parameters
                    .codecs
                    .clone();
                for codec in &codecs {
                    assert!(
                        listed(&offer_formats, codec),
                        "{name}, mid {mid}: the sender has {codec:?}, which the offer does \
                         not list so: {offer_formats:?}"
                    );
                }
            }
            if let Some(receiver) = receiver {
                let codecs = pc
                    .rtp_receiver(receiver)
                    .expect("receiver")
                    .get_parameters()
                    .rtp_parameters
                    .codecs
                    .clone();
                for codec in &codecs {
                    assert!(
                        listed(&answer_formats, codec),
                        "{name}, mid {mid}: the receiver has {codec:?}, which the answer \
                         does not list so: {answer_formats:?}"
                    );
                }
            }
        }
    }
    assert!(
        answered_formats > 100,
        "formats answered with the offer's number: {answered_formats}"
    );
}
