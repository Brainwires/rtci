//! Video `red` + `ulpfec` by behaviour profile. RFC 8854 section 7: "Implementations MAY
//! support additional FEC mechanisms if desired, e.g., [RFC5109]", so the default (`Rfc`)
//! offers neither for video; Chromium offers both in every video section (libwebrtc
//! `GetDefaultSupportedFormats`), and so does the `Chrome` profile, with RTX for RED, and
//! installs ULPFEC in RED in the chain.

use rtci::interceptor::Registry;
use rtci::peer_connection::RTCPeerConnectionBuilder;
use rtci::peer_connection::configuration::RTCConfigurationBuilder;
use rtci::peer_connection::configuration::behaviour_profile::BehaviourProfile;
use rtci::peer_connection::configuration::interceptor_registry::{
    DefaultInterceptorOptions, VIDEO_RED_PAYLOAD_TYPE, VIDEO_RED_RTX_PAYLOAD_TYPE,
    VIDEO_ULPFEC_PAYLOAD_TYPE, register_default_interceptors,
};
use rtci::peer_connection::configuration::media_engine::MediaEngine;
use rtci::rtp_transceiver::rtp_sender::RtpCodecKind;
use rtci::rtp_transceiver::{RTCRtpTransceiverDirection, RTCRtpTransceiverInit};
use std::time::Instant;

/// The video section of an offer made under `profile` with the default codecs and
/// interceptors, and the names of the chain's slots.
fn video_offer(profile: BehaviourProfile) -> (Vec<String>, Vec<String>) {
    let mut media_engine = MediaEngine::for_profile(profile);
    media_engine.register_default_codecs().unwrap();
    let registry = register_default_interceptors(Registry::new(), &mut media_engine).unwrap();
    let slots: Vec<String> = registry.slots().into_iter().map(|(_, name)| name).collect();
    let mut pc = RTCPeerConnectionBuilder::new()
        .with_configuration(RTCConfigurationBuilder::new().build())
        .with_media_engine(media_engine)
        .with_interceptor_registry(registry)
        .build(Instant::now())
        .unwrap();
    pc.add_transceiver_from_kind(
        RtpCodecKind::Video,
        Some(RTCRtpTransceiverInit {
            direction: RTCRtpTransceiverDirection::Sendrecv,
            ..Default::default()
        }),
    )
    .unwrap();
    let offer = pc.create_offer(None).unwrap();
    let video = offer
        .sdp
        .split("\r\nm=")
        .find(|section| section.starts_with("video"))
        .expect("a video section")
        .split("\r\n")
        .map(str::to_owned)
        .collect();
    (video, slots)
}

#[test]
fn by_default_video_offers_neither_red_nor_ulpfec_and_the_chain_has_no_ulpfec() {
    let (video, slots) = video_offer(BehaviourProfile::Rfc);
    assert!(
        !video
            .iter()
            .any(|line| line.contains(" red/90000") || line.contains("ulpfec")),
        "{video:#?}"
    );
    assert!(
        !slots.iter().any(|name| name.starts_with("Ulpfec")),
        "{slots:?}"
    );
    assert!(!DefaultInterceptorOptions::for_profile(BehaviourProfile::Rfc).video_red_ulpfec);
}

#[test]
fn the_chrome_profile_offers_red_with_its_rtx_and_ulpfec_and_runs_ulpfec_in_red() {
    let (video, slots) = video_offer(BehaviourProfile::Chrome);
    for expected in [
        format!("a=rtpmap:{VIDEO_RED_PAYLOAD_TYPE} red/90000"),
        format!("a=rtpmap:{VIDEO_RED_RTX_PAYLOAD_TYPE} rtx/90000"),
        format!("a=fmtp:{VIDEO_RED_RTX_PAYLOAD_TYPE} apt={VIDEO_RED_PAYLOAD_TYPE}"),
        format!("a=rtpmap:{VIDEO_ULPFEC_PAYLOAD_TYPE} ulpfec/90000"),
    ] {
        assert!(video.contains(&expected), "{expected} in {video:#?}");
    }
    // After the media codecs, as Chromium lists them.
    let m_line = &video[0];
    let formats: Vec<&str> = m_line.split(' ').skip(3).collect();
    assert_eq!(
        formats[formats.len() - 3..],
        [
            VIDEO_RED_PAYLOAD_TYPE.to_string().as_str(),
            VIDEO_RED_RTX_PAYLOAD_TYPE.to_string().as_str(),
            VIDEO_ULPFEC_PAYLOAD_TYPE.to_string().as_str()
        ],
        "{m_line}"
    );
    for interceptor in [
        "UlpfecSendInterceptor",
        "WireImageTap",
        "UlpfecReceiveInterceptor",
    ] {
        assert!(
            slots.iter().any(|name| name == interceptor),
            "{interceptor} in {slots:?}"
        );
    }
}

/// RFC 8854 section 5.2: "Use of FEC-only "m=" lines, and grouping using the SDP group
/// mechanism as described in [RFC5956], Section 4.1, is not currently defined for WebRTC, and
/// SHOULD NOT be offered." No profile offers one unless the application asks
/// (`RTCPeerConnection::add_fec_session`).
#[test]
fn no_profile_offers_a_fec_only_section() {
    for profile in [
        BehaviourProfile::Rfc,
        BehaviourProfile::Chrome,
        BehaviourProfile::StrictRfc,
    ] {
        let mut media_engine = MediaEngine::for_profile(profile);
        media_engine.register_default_codecs().unwrap();
        let registry = register_default_interceptors(Registry::new(), &mut media_engine).unwrap();
        let mut pc = RTCPeerConnectionBuilder::new()
            .with_configuration(RTCConfigurationBuilder::new().build())
            .with_media_engine(media_engine)
            .with_interceptor_registry(registry)
            .build(Instant::now())
            .unwrap();
        pc.add_transceiver_from_kind(RtpCodecKind::Video, None)
            .unwrap();
        let offer = pc.create_offer(None).unwrap().sdp;
        assert_eq!(offer.matches("\r\nm=").count(), 1, "{profile}: {offer}");
        assert!(!offer.contains("a=group:FEC"), "{profile}: {offer}");
    }
}
