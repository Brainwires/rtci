//! A format an answer adds after the offered ones (RFC 9429 section 5.3.1: "Any currently
//! available media formats that are not present in the current remote description MUST be
//! added after all existing formats") whose registered payload type the offer uses for another
//! format takes a free dynamic number, and with the default codecs one is found: the search
//! continues below 96 (RFC 3551 section 3: applications "which need to define more than 32
//! dynamic payload types MAY bind codes below 96"; RFC 5761 section 4: "Values below 64 MAY be
//! used if that is insufficient"), and the numbers the SFrame numbering would use are not held
//! back when no section uses SFrame.
//!
//! Before (jsep-91 follow-up): with the default codecs every number of 96-127 was registered or
//! reserved for the SFrame numbering, and such a format was left out of the answer.

mod jsep_common;

use std::time::Instant;

use jsep_common::{SESSION, TRANSPORT, TestResult, crlf, default_peer, media_sections};
use rtci::peer_connection::sdp::RTCSessionDescription;

/// The answer to a video offer of VP8 on 96 and H.264 on 98, the number the engine registers
/// VP9 profile 0 under.
fn answer() -> Result<String, Box<dyn std::error::Error>> {
    let mut pc = default_peer()?;
    let offer = crlf(&format!(
        "{SESSION}a=group:BUNDLE 0
m=video 9 UDP/TLS/RTP/SAVPF 96 98
{TRANSPORT}a=mid:0
a=sendrecv
a=rtpmap:96 VP8/90000
a=rtpmap:98 H264/90000
a=fmtp:98 level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=42e01f
"
    ));
    pc.set_remote_description(Instant::now(), RTCSessionDescription::offer(offer)?)?;
    let answer = pc.create_answer(None)?;
    pc.set_local_description(Instant::now(), answer.clone())?;
    Ok(answer.sdp)
}

/// (payload type, rtpmap, fmtp) of each format of the answer's video section.
fn formats(sdp: &str) -> Vec<(u8, String, String)> {
    let section = &media_sections(sdp)[0];
    section[0]
        .split_whitespace()
        .skip(3)
        .map(|pt| {
            let find = |key: &str| {
                section
                    .iter()
                    .find_map(|l| l.strip_prefix(&format!("a={key}:{pt} ")))
                    .unwrap_or_default()
                    .to_owned()
            };
            (
                pt.parse().expect("a payload type"),
                find("rtpmap"),
                find("fmtp"),
            )
        })
        .collect()
}

#[test]
fn a_format_whose_number_the_offer_uses_otherwise_is_added_on_a_free_number() -> TestResult {
    let answer = answer()?;
    let formats = formats(&answer);
    let vp9_profile_0 = formats.iter().find(|(_, rtpmap, fmtp)| {
        rtpmap.starts_with("VP9/") && fmtp.split(';').any(|p| p.trim() == "profile-id=0")
    });
    let (pt, _, _) = vp9_profile_0.unwrap_or_else(|| {
        panic!("VP9 profile 0 (registered on 98, which the offer gives H.264) is added: {answer}")
    });
    assert_ne!(*pt, 98, "{answer}");
    assert!(
        (96..=127).contains(pt) || (35..=63).contains(pt),
        "a dynamic number, never 64-95 (RFC 5761 section 4): {pt}\n{answer}"
    );
    // Each number names one format.
    let mut numbers: Vec<u8> = formats.iter().map(|(pt, _, _)| *pt).collect();
    numbers.sort_unstable();
    numbers.dedup();
    assert_eq!(numbers.len(), formats.len(), "{answer}");
    // The offered formats keep the offer's numbers, first.
    assert_eq!(formats[0].0, 96, "{answer}");
    assert_eq!(formats[1].0, 98, "{answer}");
    assert!(formats[1].1.starts_with("H264/"), "{answer}");
    Ok(())
}
