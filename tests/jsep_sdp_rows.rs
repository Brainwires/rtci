//! RFC 8866 rows about what the engine writes into its own descriptions (sdp branch, jsep-77).

mod jsep_common;

use std::time::Instant;

use jsep_common::{SESSION, TRANSPORT, TestResult, crlf, default_peer, media_sections};
use rtci::peer_connection::sdp::RTCSessionDescription;
use rtci::rtp_transceiver::RTCRtpTransceiverInit;
use rtci::rtp_transceiver::rtp_sender::RtpCodecKind;

/// The `<bwtype>` of every `b=` line of `sdp`.
fn bandwidth_types(sdp: &str) -> Vec<String> {
    sdp.lines()
        .filter_map(|l| l.strip_prefix("b="))
        .map(|l| l.split(':').next().unwrap_or_default().to_owned())
        .collect()
}

/// RFC 8866 section 5.8: "Use of the "X-" prefix is NOT RECOMMENDED. Instead new (non "X-"
/// prefix) <bwtype> names SHOULD be defined". The receive bandwidth a section states is
/// written with the registered modifiers TIAS (RFC 3890) and AS, in an offer and in an
/// answer, also when the remote offer carried an experimental `b=X-` line.
#[test]
fn bandwidth_lines_use_registered_modifiers_only() -> TestResult {
    let mut pc = default_peer()?;
    let id =
        pc.add_transceiver_from_kind(RtpCodecKind::Video, Some(RTCRtpTransceiverInit::recvonly()))?;
    pc.rtp_transceiver(id)
        .expect("the transceiver")
        .set_receive_bandwidth(Some(500_000));
    let offer = pc.create_offer(None)?;
    assert_eq!(bandwidth_types(&offer.sdp), ["TIAS", "AS"], "{}", offer.sdp);

    // Section 5: b= lines come after c=, at session level before t=.
    let session = SESSION.replace("t=0 0", "b=X-YZ:128\nt=0 0");
    let transport = TRANSPORT.replacen("c=IN IP4 0.0.0.0\n", "c=IN IP4 0.0.0.0\nb=X-YZ:64\n", 1);
    let remote = crlf(&format!(
        "{session}m=video 9 UDP/TLS/RTP/SAVPF 96\n{transport}a=mid:0\na=sendonly\na=msid:s t\n\
         a=rtpmap:96 VP8/90000\n"
    ));
    assert!(remote.contains("b=X-YZ:64\r\na=ice-ufrag"), "{remote}");
    let mut pc = default_peer()?;
    pc.set_remote_description(Instant::now(), RTCSessionDescription::offer(remote)?)?;
    let id = pc
        .get_transceivers()
        .next()
        .expect("the offered transceiver");
    pc.rtp_transceiver(id)
        .expect("the transceiver")
        .set_receive_bandwidth(Some(500_000));
    let answer = pc.create_answer(None)?;
    let sections = media_sections(&answer.sdp);
    assert_eq!(sections.len(), 1, "{}", answer.sdp);
    assert_eq!(
        bandwidth_types(&answer.sdp),
        ["TIAS", "AS"],
        "{}",
        answer.sdp
    );
    assert!(!answer.sdp.contains("b=X-"), "{}", answer.sdp);
    Ok(())
}
