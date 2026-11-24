//! A remote `a=extmap` whose extension name is not a URI is not well formed (RFC 8285 section
//! 8: `extensionname = URI`), and RFC 9429 section 5.8 has such a line reject the
//! description "even if the value is to be discarded"; it used to be left out of the answer
//! (before that, it failed `set_remote_description` with a URL parse error). An extension
//! named by a URI this end does not support is left out of the answer (RFC 8285 section 5,
//! RFC 9429 section 5.3.1), and the description is applied.

mod jsep_common;

use std::time::Instant;

use jsep_common::{SESSION, TRANSPORT, TestResult, crlf};
use rtci::peer_connection::RTCPeerConnectionBuilder;
use rtci::peer_connection::configuration::media_engine::MediaEngine;
use rtci::peer_connection::sdp::RTCSessionDescription;
use rtci::rtp_transceiver::rtp_sender::{RTCRtpHeaderExtensionCapability, RtpCodecKind};

const MID_URI: &str = "urn:ietf:params:rtp-hdrext:sdes:mid";

#[test]
fn an_extmap_that_is_not_a_uri_refuses_the_description_and_an_unknown_uri_is_left_out() -> TestResult
{
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

    let offer = |name: &str| {
        crlf(&format!(
            "{SESSION}a=group:BUNDLE 0
m=video 9 UDP/TLS/RTP/SAVPF 96
{TRANSPORT}a=mid:0
a=sendrecv
a=extmap:2 {name}
a=extmap:3 {MID_URI}
a=rtpmap:96 VP8/90000
"
        ))
    };
    let refused = answerer.set_remote_description(
        Instant::now(),
        RTCSessionDescription::offer(offer("bogus"))?,
    );
    assert!(refused.is_err(), "{refused:?}");
    assert!(answerer.remote_description().is_none());

    answerer.set_remote_description(
        Instant::now(),
        RTCSessionDescription::offer(offer("urn:example:bogus"))?,
    )?;
    let answer = answerer.create_answer(None)?;

    assert!(!answer.sdp.contains("bogus"), "{}", answer.sdp);
    assert!(
        answer.sdp.contains(&format!("a=extmap:3 {MID_URI}")),
        "the supported extension is answered with its offered id:\n{}",
        answer.sdp
    );
    Ok(())
}
