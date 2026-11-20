//! An m= section of a media type this end doesn't know (RFC 8866 section 5.14: media types are
//! extensible) is parsed, and answered rejected, port 0, with its media type, protocol and
//! formats, in its place (RFC 9429 sections 5.3.1 and 5.2.2). The parser used to refuse the
//! whole description, and the answer generator dropped the section, shifting the m-lines.

mod jsep_common;

use std::time::Instant;

use jsep_common::{SESSION, TRANSPORT, TestResult, crlf, default_peer, media_sections, port_of};
use rtc::peer_connection::sdp::RTCSessionDescription;

#[test]
fn an_unknown_media_type_is_answered_rejected_in_its_place() -> TestResult {
    let mut answerer = default_peer()?;
    let offer = crlf(&format!(
        "{SESSION}a=group:BUNDLE 0 1 2
m=video 9 UDP/TLS/RTP/SAVPF 96
{TRANSPORT}a=mid:0
a=sendrecv
a=rtpmap:96 VP8/90000
m=unicorns 9 UDP/TLS/RTP/SAVPF 120
{TRANSPORT}a=mid:1
a=sendrecv
a=rtpmap:120 horn/90000
m=video 9 UDP/TLS/RTP/SAVPF 96
{TRANSPORT}a=mid:2
a=sendrecv
a=rtpmap:96 VP8/90000
"
    ));
    answerer.set_remote_description(Instant::now(), RTCSessionDescription::offer(offer)?)?;
    let answer = answerer.create_answer(None)?;

    let sections = media_sections(&answer.sdp);
    assert_eq!(
        sections.len(),
        3,
        "every offered section is answered:\n{}",
        answer.sdp
    );
    assert!(sections[0][0].starts_with("m=video "), "{}", answer.sdp);
    assert_ne!(port_of(&sections[0]), 0, "{}", answer.sdp);
    assert!(
        sections[1][0].starts_with("m=unicorns 0 UDP/TLS/RTP/SAVPF 120"),
        "the unknown section is rejected with its own m= line:\n{}",
        answer.sdp
    );
    assert!(sections[2][0].starts_with("m=video "), "{}", answer.sdp);
    assert_ne!(port_of(&sections[2]), 0, "{}", answer.sdp);

    // Only the video sections got transceivers.
    assert_eq!(answerer.get_transceivers().count(), 2);
    Ok(())
}
