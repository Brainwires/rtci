//! W3C webrtc-svc `scalabilityMode` on encodings, with its `addTransceiver` and
//! `setParameters` checks; the Dependency Descriptor among the default header extensions; and
//! for encoded transforms (W3C webrtc-encoded-transform, RFC 9605), `rtc::sframe` and a
//! payload the RTP layer does not parse.

use anyhow::Result;
use rtc::interceptor::Registry;
use rtc::peer_connection::RTCPeerConnectionBuilder;
use rtc::peer_connection::configuration::interceptor_registry::register_default_interceptors;
use rtc::peer_connection::configuration::media_engine::MediaEngine;
use rtc::rtp_transceiver::rtp_sender::{
    RTCRtpCodec, RTCRtpCodingParameters, RTCRtpEncodingParameters, RtpCodecKind,
};
use rtc::rtp_transceiver::{RTCRtpSenderId, RTCRtpTransceiverDirection, RTCRtpTransceiverInit};
use rtc::shared::error::Error;
use std::time::Instant;

fn peer() -> Result<rtc::peer_connection::RTCPeerConnection> {
    let mut media_engine = MediaEngine::default();
    media_engine.register_default_codecs()?;
    let registry = register_default_interceptors(Registry::new(), &mut media_engine)?;
    Ok(RTCPeerConnectionBuilder::new()
        .with_media_engine(media_engine)
        .with_interceptor_registry(registry)
        .build(Instant::now())?)
}

fn encoding(rid: &str, mode: Option<&str>, mime: &str) -> RTCRtpEncodingParameters {
    RTCRtpEncodingParameters {
        rtp_coding_parameters: RTCRtpCodingParameters {
            rid: rid.to_owned(),
            ..Default::default()
        },
        codec: RTCRtpCodec {
            mime_type: mime.to_owned(),
            clock_rate: if mime.is_empty() { 0 } else { 90000 },
            ..Default::default()
        },
        scalability_mode: mode.map(str::to_owned),
        ..Default::default()
    }
}

fn add(
    pc: &mut rtc::peer_connection::RTCPeerConnection,
    kind: RtpCodecKind,
    encodings: Vec<RTCRtpEncodingParameters>,
) -> rtc::shared::error::Result<RTCRtpSenderId> {
    pc.add_transceiver_from_kind(
        kind,
        Some(RTCRtpTransceiverInit {
            direction: RTCRtpTransceiverDirection::Sendonly,
            streams: vec![],
            send_encodings: encodings,
        }),
    )
    .map(RTCRtpSenderId::from)
}

/// webrtc-svc 3.1 / 3.2.1 / 3.2.3: a valid mode is kept and returned by getParameters; a mode
/// outside the table, one the encoding's codec cannot carry (VP8 has no spatial layers), one
/// no send codec can carry, and an active "S" mode beside another active encoding are an
/// OperationError; an audio encoding's mode is removed.
#[test]
fn add_transceiver_checks_the_scalability_mode() -> Result<()> {
    let mut pc = peer()?;
    let sender = add(
        &mut pc,
        RtpCodecKind::Video,
        vec![encoding("", Some("L3T3"), "")],
    )?;
    let mut handle = pc.rtp_sender(sender).expect("sender");
    assert_eq!(
        handle.get_parameters().encodings[0]
            .scalability_mode
            .as_deref(),
        Some("L3T3")
    );

    for (encodings, why) in [
        (vec![encoding("", Some("l1t3"), "")], "case sensitive"),
        (vec![encoding("", Some("L9T9"), "")], "not in the table"),
        (
            vec![encoding("", Some("L2T1"), "video/VP8")],
            "VP8 has no spatial layers",
        ),
        (
            vec![encoding("a", Some("S2T1"), ""), encoding("b", None, "")],
            "an active S mode beside another active encoding",
        ),
    ] {
        assert!(
            matches!(
                add(&mut pc, RtpCodecKind::Video, encodings),
                Err(Error::ErrOperationError(_))
            ),
            "{why}"
        );
    }

    let audio = add(
        &mut pc,
        RtpCodecKind::Audio,
        vec![encoding("", Some("L1T3"), "")],
    )?;
    let mut handle = pc.rtp_sender(audio).expect("audio");
    assert_eq!(handle.get_parameters().encodings[0].scalability_mode, None);
    Ok(())
}

/// webrtc-svc 3.2.2: setParameters refuses an invalid mode with InvalidModificationError and
/// takes "L1T1", which getParameters then returns.
#[test]
fn set_parameters_checks_the_scalability_mode() -> Result<()> {
    let mut pc = peer()?;
    let sender = add(&mut pc, RtpCodecKind::Video, vec![encoding("", None, "")])?;
    let mut handle = pc.rtp_sender(sender).expect("sender");
    let mut parameters = handle.get_parameters().clone();
    parameters.encodings[0].scalability_mode = Some("bogus".to_owned());
    assert!(matches!(
        handle.set_parameters(parameters, None),
        Err(Error::InvalidModificationError)
    ));
    let mut parameters = handle.get_parameters().clone();
    parameters.encodings[0].scalability_mode = Some("L1T1".to_owned());
    handle.set_parameters(parameters, None)?;
    assert_eq!(
        handle.get_parameters().encodings[0]
            .scalability_mode
            .as_deref(),
        Some("L1T1")
    );
    Ok(())
}

/// The default header extensions offer the Dependency Descriptor for video (what a forwarder
/// routes SVC layers by when it cannot read the payload, webrtc-svc section 4).
#[test]
fn the_dependency_descriptor_is_offered_for_video() -> Result<()> {
    let mut pc = peer()?;
    add(&mut pc, RtpCodecKind::Video, vec![encoding("", None, "")])?;
    let offer = pc.create_offer(None)?;
    assert!(
        offer
            .sdp
            .contains(rtc::rtp::codec::dependency_descriptor::DEPENDENCY_DESCRIPTOR_URI),
        "{}",
        offer.sdp
    );
    Ok(())
}

/// Encoded transforms: a frame encrypted with `rtc::sframe` (RFC 9605, one ciphertext for the
/// whole frame) goes through the format-agnostic payloader in several packets and comes back
/// decryptable: nothing parses it on the way.
#[test]
fn an_sframe_ciphertext_crosses_the_opaque_payloader() -> Result<()> {
    use rtc::rtp::codec::opaque::{OpaqueDepacketizer, OpaquePayloader};
    use rtc::rtp::packetizer::{Depacketizer, Payloader};
    use rtc::sframe::{CipherSuite, SFrameContext};
    let key = [7u8; 16];
    let mut sender = SFrameContext::with_default_provider(CipherSuite::Aes128GcmSha256_128)?;
    sender.add_send_key(1, &key)?;
    let mut receiver = SFrameContext::with_default_provider(CipherSuite::Aes128GcmSha256_128)?;
    receiver.add_recv_key(1, &key)?;
    let frame: Vec<u8> = (0..3000u32).map(|n| (n % 251) as u8).collect();
    let ciphertext: bytes::Bytes = sender.encrypt(1, b"", &frame)?.into();
    let mut payloads = OpaquePayloader.payload(1100, &ciphertext)?;
    assert!(payloads.len() >= 3);
    let mut depacketizer = OpaqueDepacketizer::default();
    let mut out = bytes::Bytes::new();
    for payload in payloads.drain(..) {
        out = depacketizer.depacketize(&payload)?;
    }
    assert_eq!(out, ciphertext);
    assert_eq!(receiver.decrypt(b"", &out)?, frame);
    Ok(())
}
