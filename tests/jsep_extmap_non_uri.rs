//! A remote `a=extmap` whose extension name isn't a URI is an extension this end doesn't
//! support: it is left out of the answer (RFC 8285 section 5, RFC 9429 section 5.3.1), and
//! the description is applied. It used to fail `set_remote_description` with a URL parse
//! error.

mod jsep_common;

use std::time::Instant;

use jsep_common::{SESSION, TRANSPORT, TestResult, crlf};
use rtc::peer_connection::RTCPeerConnectionBuilder;
use rtc::peer_connection::configuration::media_engine::MediaEngine;
use rtc::peer_connection::sdp::RTCSessionDescription;
use rtc::rtp_transceiver::rtp_sender::{RTCRtpHeaderExtensionCapability, RtpCodecKind};

const MID_URI: &str = "urn:ietf:params:rtp-hdrext:sdes:mid";

#[test]
fn an_extmap_that_is_not_a_uri_is_left_out_of_the_answer() -> TestResult {
    let mut media_engine = MediaEngine::default();
    media_engine.register_default_codecs()?;
    media_engine.register_header_extension(
        RTCRtpHeaderExtensionCapability {
            uri: MID_URI.to_owned(),
        },
        RtpCodecKind::Video,
        None,
    )?;
    let mut answerer = RTCPeerConnectionBuilder::new()
        .with_media_engine(media_engine)
        .build(Instant::now())?;

    let offer = crlf(&format!(
        "{SESSION}a=group:BUNDLE 0
m=video 9 UDP/TLS/RTP/SAVPF 96
{TRANSPORT}a=mid:0
a=sendrecv
a=extmap:2 bogus
a=extmap:3 {MID_URI}
a=rtpmap:96 VP8/90000
"
    ));
    answerer.set_remote_description(Instant::now(), RTCSessionDescription::offer(offer)?)?;
    let answer = answerer.create_answer(None)?;

    assert!(!answer.sdp.contains("bogus"), "{}", answer.sdp);
    assert!(
        answer.sdp.contains(&format!("a=extmap:3 {MID_URI}")),
        "the supported extension is answered with its offered id:\n{}",
        answer.sdp
    );
    Ok(())
}
