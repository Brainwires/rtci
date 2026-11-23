//! An answerer that does not want FEC leaves it out of its answer: RFC 5109 section 14.3 (the
//! answerer rejects FEC by removing its payload type, and RED with it when FEC was RED's only
//! secondary codec), RFC 8627 section 5.2.1 and draft-ietf-payload-flexible-fec-scheme-03
//! section 5.2.1 ("delete" FlexFEC from the answer). The default codecs register neither.

mod jsep_common;

use std::time::Instant;

use jsep_common::{SESSION, TRANSPORT, TestResult, crlf, default_peer};
use rtc::peer_connection::sdp::RTCSessionDescription;

/// A remote offer of VP8 with RED, ULPFEC, FlexFEC-03 and RFC 8627 FlexFEC. The default
/// answer keeps VP8 (beside formats of its own) and drops the rest: the FEC formats, and RED, whose only secondary codec
/// was ULPFEC.
#[test]
fn an_answer_without_fec_drops_the_fec_formats_and_their_red() -> TestResult {
    let mut pc = default_peer()?;
    let offer = crlf(&format!(
        "{SESSION}m=video 9 UDP/TLS/RTP/SAVPF 96 116 117 118 119\n{TRANSPORT}a=mid:0\na=sendrecv\n\
         a=rtpmap:96 VP8/90000\na=rtpmap:116 red/90000\na=rtpmap:117 ulpfec/90000\n\
         a=rtpmap:118 flexfec-03/90000\na=fmtp:118 repair-window=10000000\n\
         a=rtpmap:119 flexfec/90000\na=fmtp:119 repair-window=200000\n"
    ));
    let now = Instant::now();
    pc.set_remote_description(now, RTCSessionDescription::offer(offer)?)?;
    let answer = pc.create_answer(None)?;
    let m_line = answer
        .sdp
        .lines()
        .find(|line| line.starts_with("m=video"))
        .ok_or("an m=video line")?;
    let formats: Vec<&str> = m_line.split(' ').skip(3).collect();
    assert!(formats.contains(&"96"), "{}", answer.sdp);
    for fec in ["116", "117", "118", "119"] {
        assert!(!formats.contains(&fec), "{fec} answered:\n{}", answer.sdp);
    }
    let lower = answer.sdp.to_lowercase();
    for name in ["red/", "ulpfec", "flexfec"] {
        assert!(!lower.contains(name), "{name} answered:\n{}", answer.sdp);
    }
    Ok(())
}
