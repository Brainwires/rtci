//! The standard interceptor set registers abs-send-time on video: offered beside
//! transport-wide congestion control and `ack ccfb`, and answered to a peer that runs REMB
//! with abs-send-time (draft-ietf-rmcat-gcc-02 section 3, the receive-side variant).

mod jsep_common;

use std::time::Instant;

use jsep_common::{SESSION, TRANSPORT, TestResult, crlf, media_sections};
use rtci::interceptor::Registry;
use rtci::peer_connection::configuration::interceptor_registry::register_default_interceptors;
use rtci::peer_connection::configuration::media_engine::MediaEngine;
use rtci::peer_connection::sdp::RTCSessionDescription;
use rtci::peer_connection::{RTCPeerConnection, RTCPeerConnectionBuilder};
use rtci::rtp_transceiver::rtp_sender::RtpCodecKind;

const ABS: &str = "http://www.webrtc.org/experiments/rtp-hdrext/abs-send-time";
const TWCC: &str = "http://www.ietf.org/id/draft-holmer-rmcat-transport-wide-cc-extensions-01";

fn standard_peer() -> Result<RTCPeerConnection, Box<dyn std::error::Error>> {
    let mut media_engine = MediaEngine::default();
    media_engine.register_default_codecs()?;
    let registry = register_default_interceptors(Registry::new(), &mut media_engine)?;
    Ok(RTCPeerConnectionBuilder::new()
        .with_media_engine(media_engine)
        .with_interceptor_registry(registry)
        .build(Instant::now())?)
}

/// Whether the section of `sdp` whose `m=` line starts with `media` has an `a=extmap` for
/// `uri`.
fn has_extmap(sdp: &str, media: &str, uri: &str) -> bool {
    media_sections(sdp)
        .iter()
        .find(|section| section[0].starts_with(media))
        .unwrap_or_else(|| panic!("{media} in:\n{sdp}"))
        .iter()
        .any(|line| line.starts_with("a=extmap:") && line.ends_with(&format!(" {uri}")))
}

#[test]
fn video_offers_abs_send_time_beside_transport_cc_and_audio_does_not() -> TestResult {
    let mut pc = standard_peer()?;
    pc.add_transceiver_from_kind(RtpCodecKind::Video, None)?;
    pc.add_transceiver_from_kind(RtpCodecKind::Audio, None)?;
    let offer = pc.create_offer(None)?;
    assert!(has_extmap(&offer.sdp, "m=video", ABS), "{}", offer.sdp);
    assert!(has_extmap(&offer.sdp, "m=video", TWCC), "{}", offer.sdp);
    assert!(!has_extmap(&offer.sdp, "m=audio", ABS), "{}", offer.sdp);
    Ok(())
}

/// A peer that offers REMB with abs-send-time and no transport-wide congestion control is
/// answered with abs-send-time.
#[test]
fn a_remb_peers_abs_send_time_is_answered() -> TestResult {
    let mut pc = standard_peer()?;
    let offer = RTCSessionDescription::offer(crlf(&format!(
        "{SESSION}a=group:BUNDLE 0
m=video 9 UDP/TLS/RTP/SAVPF 96
{TRANSPORT}a=mid:0
a=sendrecv
a=extmap:3 {ABS}
a=rtpmap:96 VP8/90000
a=rtcp-fb:96 goog-remb
"
    )))?;
    pc.set_remote_description(Instant::now(), offer)?;
    let answer = pc.create_answer(None)?;
    assert!(has_extmap(&answer.sdp, "m=video", ABS), "{}", answer.sdp);
    assert!(!has_extmap(&answer.sdp, "m=video", TWCC), "{}", answer.sdp);
    Ok(())
}
