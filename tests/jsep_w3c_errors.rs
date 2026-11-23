//! W3C webrtc-pc section 4.4.1.5 ("set the session description"): which error a JavaScript
//! API over this engine raises when a description is refused. One that does not parse (RFC
//! 9429 sections 5.8.1 and 5.8.2) is an `RTCError` (`OperationError`) with `errorDetail`
//! `"sdp-syntax-error"`; one that fails the semantic checks of RFC 9429 section 5.8.3 is an
//! `InvalidAccessError`; one the signaling state does not take is an `InvalidStateError`.
//! `Error::dom_exception_name` and `Error::rtc_error_detail` give those names.

mod jsep_common;

use std::time::Instant;

use jsep_common::{SESSION, TRANSPORT, TestResult, crlf, default_peer};
use rtc::peer_connection::sdp::RTCSessionDescription;

fn video(mid: &str, transport: &str) -> String {
    format!(
        "m=video 9 UDP/TLS/RTP/SAVPF 96\n{transport}a=mid:{mid}\na=recvonly\na=rtpmap:96 VP8/90000\n"
    )
}

/// RFC 9429 section 5.8.3 refusals: each is an `InvalidAccessError`.
#[test]
fn a_description_that_fails_the_semantic_checks_is_an_invalid_access_error() -> TestResult {
    let without_ufrag = TRANSPORT.replace("a=ice-ufrag:4ZcD\n", "");
    let without_fingerprint = TRANSPORT
        .lines()
        .filter(|l| !l.starts_with("a=fingerprint:"))
        .map(|l| format!("{l}\n"))
        .collect::<String>();
    let without_mux = TRANSPORT.replace("a=rtcp-mux\n", "");
    for (what, sdp) in [
        ("no a=ice-ufrag", video("0", &without_ufrag)),
        ("no a=fingerprint", video("0", &without_fingerprint)),
        (
            "no a=rtcp-mux under the require policy",
            video("0", &without_mux),
        ),
    ] {
        let mut offerer = default_peer()?;
        offerer.add_transceiver_from_kind(
            rtc::rtp_transceiver::rtp_sender::RtpCodecKind::Video,
            None,
        )?;
        let offer = offerer.create_offer(None)?;
        offerer.set_local_description(Instant::now(), offer)?;
        let answer = RTCSessionDescription::answer(crlf(&format!(
            "{SESSION}{}",
            sdp.replace("a=recvonly", "a=sendrecv")
        )))?;
        let refused = offerer
            .set_remote_description(Instant::now(), answer)
            .expect_err(what);
        assert_eq!(
            refused.dom_exception_name(),
            Some("InvalidAccessError"),
            "{what}: {refused}"
        );
        assert_eq!(refused.rtc_error_detail(), None, "{what}");
    }
    Ok(())
}

/// A description that does not parse is an `RTCError` with `errorDetail` `sdp-syntax-error`.
#[test]
fn a_description_that_does_not_parse_is_an_sdp_syntax_error() -> TestResult {
    let refused = RTCSessionDescription::offer(crlf(&format!(
        "{SESSION}m=video nine UDP/TLS/RTP/SAVPF 96\n{TRANSPORT}a=mid:0\n"
    )))
    .expect_err("a port that is not a number");
    assert_eq!(
        refused.dom_exception_name(),
        Some("OperationError"),
        "{refused}"
    );
    assert_eq!(refused.rtc_error_detail(), Some("sdp-syntax-error"));
    Ok(())
}

/// An answer in the `stable` state is an `InvalidStateError`.
#[test]
fn an_answer_without_an_offer_is_an_invalid_state_error() -> TestResult {
    let mut pc = default_peer()?;
    let answer =
        RTCSessionDescription::answer(crlf(&format!("{SESSION}{}", video("0", TRANSPORT))))?;
    let refused = pc
        .set_remote_description(Instant::now(), answer)
        .expect_err("no offer");
    assert_eq!(
        refused.dom_exception_name(),
        Some("InvalidStateError"),
        "{refused}"
    );
    Ok(())
}
