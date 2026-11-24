//! ULPFEC as a separate stream (RFC 5109 section 14.1): its own m= line in a second RTP
//! session, grouped with the media's by `a=group:FEC` (RFC 4756) or `a=group:FEC-FR` (RFC 5956
//! section 4.1). This endpoint runs one RTP session on one transport, so it answers such an
//! offer as RFC 5109 section 14.3 lets an answerer refuse the FEC session: the FEC m= line
//! rejected (port 0) and the group left out of the answer.

mod jsep_common;

use std::time::Instant;

use jsep_common::{
    SESSION, TRANSPORT, TestResult, crlf, default_peer, media_sections, mid_of, port_of,
};
use rtci::peer_connection::sdp::RTCSessionDescription;

#[test]
fn a_separate_fec_session_is_refused_with_its_group() -> TestResult {
    for semantics in ["FEC", "FEC-FR"] {
        let offer = crlf(&format!(
            "{SESSION}a=group:BUNDLE 0\na=group:{semantics} 0 1\n\
             m=video 9 UDP/TLS/RTP/SAVPF 96\n{TRANSPORT}a=mid:0\na=sendrecv\n\
             a=rtpmap:96 VP8/90000\n\
             m=video 9 UDP/TLS/RTP/SAVPF 100\n{TRANSPORT}a=mid:1\na=recvonly\n\
             a=rtpmap:100 ulpfec/90000\n"
        ));
        let mut pc = default_peer()?;
        pc.set_remote_description(Instant::now(), RTCSessionDescription::offer(offer)?)?;
        let answer = pc.create_answer(None)?.sdp;
        let sections = media_sections(&answer);
        assert_eq!(sections.len(), 2, "{answer}");
        assert_eq!(mid_of(&sections[0]), Some("0"));
        assert_ne!(port_of(&sections[0]), 0, "the media is accepted: {answer}");
        assert_eq!(mid_of(&sections[1]), Some("1"));
        assert_eq!(
            port_of(&sections[1]),
            0,
            "the FEC session is refused: {answer}"
        );
        assert!(
            !answer.contains(&format!("a=group:{semantics} ")),
            "the group is left out: {answer}"
        );
        assert!(answer.contains("a=group:BUNDLE 0\r\n"), "{answer}");
    }
    Ok(())
}

/// A FEC session's section listed ahead of the media section it protects (the group names the
/// sections, their order in the description is free): the FEC session is refused as by
/// default, and the media section is answered with its codec.
#[test]
fn a_fec_section_ahead_of_its_media_section_leaves_the_video_formats_alone() -> TestResult {
    let offer = crlf(&format!(
        "{SESSION}a=group:BUNDLE 0\na=group:FEC-FR 0 1\n\
         m=video 9 UDP/TLS/RTP/SAVPF 100\n{TRANSPORT}a=mid:1\na=recvonly\n\
         a=rtpmap:100 ulpfec/90000\n\
         m=video 9 UDP/TLS/RTP/SAVPF 96\n{TRANSPORT}a=mid:0\na=sendrecv\n\
         a=rtpmap:96 VP8/90000\n"
    ));
    let mut pc = default_peer()?;
    pc.set_remote_description(Instant::now(), RTCSessionDescription::offer(offer)?)?;
    let answer = pc.create_answer(None)?.sdp;
    let sections = media_sections(&answer);
    assert_eq!(sections.len(), 2, "{answer}");
    assert_eq!(mid_of(&sections[0]), Some("1"));
    assert_eq!(
        port_of(&sections[0]),
        0,
        "the FEC session is refused: {answer}"
    );
    assert_eq!(mid_of(&sections[1]), Some("0"));
    assert_ne!(port_of(&sections[1]), 0, "the media is accepted: {answer}");
    assert!(
        sections[1]
            .iter()
            .any(|line| line == "a=rtpmap:96 VP8/90000"),
        "{answer}"
    );
    Ok(())
}
