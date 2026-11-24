//! The default offer carries no ULPFEC (RFC 5109): the engine neither encodes nor decodes it, so
//! offering it would invite repair packets that are dropped (upstream #837 made the same change,
//! see FORK.md). End-to-end: the generated SDP has video codecs and no ULPFEC rtpmap.
use rtci::peer_connection::RTCPeerConnectionBuilder;
use rtci::peer_connection::configuration::RTCConfigurationBuilder;
use rtci::peer_connection::configuration::media_engine::MediaEngine;
use rtci::rtp_transceiver::rtp_sender::RtpCodecKind;
use rtci::rtp_transceiver::{RTCRtpTransceiverDirection, RTCRtpTransceiverInit};
use std::time::Instant;

#[test]
fn default_offer_sdp_has_no_ulpfec() {
    let mut me = MediaEngine::default();
    me.register_default_codecs()
        .expect("register default codecs");

    let mut pc = RTCPeerConnectionBuilder::new()
        .with_configuration(RTCConfigurationBuilder::new().build())
        .with_media_engine(me)
        .build(Instant::now())
        .expect("build peer connection");
    pc.add_transceiver_from_kind(
        RtpCodecKind::Video,
        Some(RTCRtpTransceiverInit {
            direction: RTCRtpTransceiverDirection::Recvonly,
            ..Default::default()
        }),
    )
    .expect("add video transceiver");

    let offer = pc.create_offer(None).expect("create offer");
    let lower = offer.sdp.to_lowercase();
    assert!(
        !lower.contains("ulpfec"),
        "the default offer must not advertise ULPFEC:\n{}",
        offer.sdp
    );
    // sanity: the offer really does carry video codecs
    assert!(
        lower.contains("vp8"),
        "expected a video offer, got:\n{}",
        offer.sdp
    );
}
