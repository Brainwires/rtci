//! Attribute placement rules of RFC 8839, RFC 8859, RFC 8866 and RFC 4585 that held without a
//! test: what is never written, what is written at which level, and what an answer drops.

mod jsep_common;

use std::time::Instant;

use jsep_common::{
    SESSION, TRANSPORT, TestResult, crlf, default_peer, exchange, media_sections, video_track,
};
use rtc::peer_connection::sdp::RTCSessionDescription;
use rtc::rtp_transceiver::rtp_sender::RtpCodecKind;
use rtc::rtp_transceiver::{RTCRtpTransceiverDirection, RTCRtpTransceiverInit};

/// The session part of `sdp`: the lines before the first `m=`.
fn session_part(sdp: &str) -> Vec<&str> {
    sdp.lines().take_while(|l| !l.starts_with("m=")).collect()
}

/// RFC 8866 sections 6.1, 6.2, 7 and RFC 8859 sections 4.2, 4.9: no `a=cat`, `a=keywds`,
/// keying material (`a=crypto`, `k=`), CAUTION attributes (`a=label`, `a=zrtp-hash`) are
/// written. RFC 4585 section 4.2 and 3.7.2: `a=rtcp-fb` only at media level and only in
/// sections whose profile is AVPF; RFC 8859 A-14 / A-25: `a=extmap-allow-mixed` and
/// `a=msid-semantic` only at session level.
#[test]
fn attributes_that_are_never_written_or_only_at_one_level() -> TestResult {
    let mut offerer = default_peer()?;
    let mut answerer = default_peer()?;
    offerer.add_track(video_track("v", 0x0e10_0101))?;
    offerer.add_transceiver_from_kind(RtpCodecKind::Audio, None)?;
    let (offer, answer) = exchange(&mut offerer, &mut answerer)?;
    for sdp in [&offer, &answer] {
        for absent in [
            "a=cat:",
            "a=keywds:",
            "a=crypto:",
            "\r\nk=",
            "a=label:",
            "a=zrtp-hash:",
        ] {
            assert!(!sdp.contains(absent), "{absent} in {sdp}");
        }
        assert!(
            !session_part(sdp).iter().any(|l| l.starts_with("a=rtcp-fb")),
            "{sdp}"
        );
        for section in media_sections(sdp) {
            assert!(
                !section
                    .iter()
                    .any(|l| *l == "a=extmap-allow-mixed" || l.starts_with("a=msid-semantic")),
                "{sdp}"
            );
            if section.iter().any(|l| l.starts_with("a=rtcp-fb")) {
                assert!(section[0].contains("AVPF "), "{}", section[0]);
            }
        }
    }
    assert!(
        session_part(&answer).contains(&"a=msid-semantic:WMS *"),
        "{answer}"
    );
    Ok(())
}

/// RFC 4585 section 4.2: "the answerer MUST remove all rtcp-fb attributes" it does not
/// understand, and receivers ignore those not fully understood: an unknown feedback type in
/// the offer is not in the answer.
#[test]
fn an_unknown_feedback_type_is_not_answered() -> TestResult {
    let mut pc = default_peer()?;
    let offer = crlf(&format!(
        "{SESSION}m=video 9 UDP/TLS/RTP/SAVPF 96\n{TRANSPORT}a=mid:0\na=sendrecv\n\
         a=rtpmap:96 VP8/90000\na=rtcp-fb:96 nack\na=rtcp-fb:96 x-unknown-feedback\n"
    ));
    pc.set_remote_description(Instant::now(), RTCSessionDescription::offer(offer)?)?;
    let answer = pc.create_answer(None)?.sdp;
    assert!(answer.contains("a=rtcp-fb:96 nack\r\n"), "{answer}");
    assert!(!answer.contains("x-unknown-feedback"), "{answer}");
    Ok(())
}

/// RFC 8839 section 4.2.1.6: an inactive section still carries the ICE attributes; sections
/// 4.4.1.1.1, 4.4.2.1 and 4.4.1.2.1: an offer or answer that is not a restart keeps the
/// credentials, `ice-options`, `ice-pacing` and `ice-lite` of the last one.
#[test]
fn ice_attributes_stay_in_inactive_sections_and_across_renegotiation() -> TestResult {
    let mut offerer = default_peer()?;
    let mut answerer = default_peer()?;
    offerer.add_transceiver_from_kind(
        RtpCodecKind::Video,
        Some(RTCRtpTransceiverInit {
            direction: RTCRtpTransceiverDirection::Inactive,
            streams: vec![],
            send_encodings: vec![],
        }),
    )?;
    let (offer, answer) = exchange(&mut offerer, &mut answerer)?;
    let ice = |sdp: &str| -> Vec<String> {
        sdp.lines()
            .filter(|l| {
                [
                    "a=ice-ufrag:",
                    "a=ice-pwd:",
                    "a=ice-options:",
                    "a=ice-pacing:",
                    "a=ice-lite",
                ]
                .iter()
                .any(|p| l.starts_with(p))
            })
            .map(str::to_owned)
            .collect()
    };
    let section = &media_sections(&offer)[0];
    assert!(section.iter().any(|l| l == "a=inactive"), "{offer}");
    assert!(
        section.iter().any(|l| l.starts_with("a=ice-ufrag:")),
        "{offer}"
    );
    assert!(offer.contains("a=ice-pacing:50\r\n"), "{offer}");
    assert!(answer.contains("a=ice-pacing:50\r\n"), "{answer}");
    offerer.add_transceiver_from_kind(RtpCodecKind::Audio, None)?;
    let (reoffer, reanswer) = exchange(&mut offerer, &mut answerer)?;
    let first = |v: Vec<String>| -> Vec<String> {
        let mut v = v;
        v.sort();
        v.dedup();
        v
    };
    assert_eq!(first(ice(&offer)), first(ice(&reoffer)));
    assert_eq!(first(ice(&answer)), first(ice(&reanswer)));
    Ok(())
}
