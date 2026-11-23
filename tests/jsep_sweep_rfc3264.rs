//! RFC 3264 rows of the sweep (jsep12).

mod jsep_common;

use std::time::Instant;

use jsep_common::{SESSION, TRANSPORT, TestResult, crlf, default_peer};
use rtc::peer_connection::sdp::RTCSessionDescription;

/// Section 6: "The 't=' line in the answer MUST be equal to the ones in the offer". An offer
/// with a bounded session time gets an answer with the same `t=` line, which also applies.
#[test]
fn the_answer_has_the_offers_time() -> TestResult {
    let session = SESSION.replace("t=0 0", "t=3034423619 3042462419");
    let offer = crlf(&format!(
        "{session}a=group:BUNDLE 0\nm=video 9 UDP/TLS/RTP/SAVPF 96\n{TRANSPORT}a=mid:0\n\
         a=sendrecv\na=rtpmap:96 VP8/90000\n"
    ));
    let mut pc = default_peer()?;
    pc.set_remote_description(Instant::now(), RTCSessionDescription::offer(offer)?)?;
    let answer = pc.create_answer(None)?;
    let times: Vec<&str> = answer.sdp.lines().filter(|l| l.starts_with("t=")).collect();
    assert_eq!(times, ["t=3034423619 3042462419"], "{}", answer.sdp);
    pc.set_local_description(Instant::now(), answer)?;
    Ok(())
}
