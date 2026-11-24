//! W3C webrtc-svc `scalabilityMode` on encodings, with its `addTransceiver` and
//! `setParameters` checks; the Dependency Descriptor among the default header extensions; and
//! for encoded transforms (W3C webrtc-encoded-transform, RFC 9605), `rtci::sframe` and a
//! payload the RTP layer does not parse.

use anyhow::Result;
use rtci::interceptor::Registry;
use rtci::peer_connection::RTCPeerConnectionBuilder;
use rtci::peer_connection::configuration::interceptor_registry::register_default_interceptors;
use rtci::peer_connection::configuration::media_engine::MediaEngine;
use rtci::rtp_transceiver::rtp_sender::{
    RTCRtpCodec, RTCRtpCodingParameters, RTCRtpEncodingParameters, RtpCodecKind,
};
use rtci::rtp_transceiver::{RTCRtpSenderId, RTCRtpTransceiverDirection, RTCRtpTransceiverInit};
use rtci::shared::error::Error;
use std::time::Instant;

fn peer() -> Result<rtci::peer_connection::RTCPeerConnection> {
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
    pc: &mut rtci::peer_connection::RTCPeerConnection,
    kind: RtpCodecKind,
    encodings: Vec<RTCRtpEncodingParameters>,
) -> rtci::shared::error::Result<RTCRtpSenderId> {
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
            .contains(rtci::rtp::codec::dependency_descriptor::DEPENDENCY_DESCRIPTOR_URI),
        "{}",
        offer.sdp
    );
    Ok(())
}

/// Encoded transforms: a frame encrypted with `rtci::sframe` (RFC 9605, one ciphertext for the
/// whole frame) goes through the format-agnostic payloader in several packets and comes back
/// decryptable: nothing parses it on the way.
#[test]
fn an_sframe_ciphertext_crosses_the_opaque_payloader() -> Result<()> {
    use rtci::rtp::codec::opaque::{OpaqueDepacketizer, OpaquePayloader};
    use rtci::rtp::packetizer::{Depacketizer, Payloader};
    use rtci::sframe::{CipherSuite, SFrameContext};
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

/// A peer whose only video codec is VP8 (temporal layers only: L1T1 to L1T3).
fn vp8_only_peer() -> Result<rtci::peer_connection::RTCPeerConnection> {
    use rtci::peer_connection::configuration::media_engine::MIME_TYPE_VP8;
    use rtci::rtp_transceiver::rtp_sender::RTCRtpCodecParameters;
    let mut media_engine = MediaEngine::default();
    media_engine.register_codec(
        RTCRtpCodecParameters {
            rtp_codec: RTCRtpCodec {
                mime_type: MIME_TYPE_VP8.to_owned(),
                clock_rate: 90000,
                ..Default::default()
            },
            payload_type: 96,
        },
        RtpCodecKind::Video,
    )?;
    Ok(RTCPeerConnectionBuilder::new()
        .with_media_engine(media_engine)
        .build(Instant::now())?)
}

fn set_mode(
    pc: &mut rtci::peer_connection::RTCPeerConnection,
    sender: RTCRtpSenderId,
    modes: &[Option<&str>],
) -> rtci::shared::error::Result<()> {
    let mut handle = pc.rtp_sender(sender).expect("sender");
    let mut parameters = handle.get_parameters().clone();
    for (encoding, mode) in parameters.encodings.iter_mut().zip(modes) {
        encoding.scalability_mode = mode.map(str::to_owned);
    }
    handle.set_parameters(parameters, None)
}

/// webrtc-svc 3.2.1 / 3.2.2: a mode no implemented send codec supports is refused by
/// addTransceiver (OperationError) and, before negotiation, by setParameters
/// (InvalidModificationError), as is one the encoding's own codec cannot carry; after
/// negotiation a mode the negotiated codecs cannot carry is refused, and several active
/// encodings with an active "S" mode are refused.
#[test]
fn set_parameters_refuses_modes_the_codecs_cannot_carry() -> Result<()> {
    let mut pc = vp8_only_peer()?;
    assert!(matches!(
        add(
            &mut pc,
            RtpCodecKind::Video,
            vec![encoding("", Some("L2T1"), "")]
        ),
        Err(Error::ErrOperationError(_))
    ));
    let sender = add(&mut pc, RtpCodecKind::Video, vec![encoding("", None, "")])?;
    assert!(matches!(
        set_mode(&mut pc, sender, &[Some("L2T1")]),
        Err(Error::InvalidModificationError)
    ));
    set_mode(&mut pc, sender, &[Some("L1T3")])?;

    let mut pc = peer()?;
    let vp8 = add(
        &mut pc,
        RtpCodecKind::Video,
        vec![encoding("", None, "video/VP8")],
    )?;
    assert!(matches!(
        set_mode(&mut pc, vp8, &[Some("L3T3")]),
        Err(Error::InvalidModificationError)
    ));

    let simulcast = add(
        &mut pc,
        RtpCodecKind::Video,
        vec![encoding("a", None, ""), encoding("b", None, "")],
    )?;
    assert!(matches!(
        set_mode(&mut pc, simulcast, &[Some("S2T1"), None]),
        Err(Error::InvalidModificationError)
    ));

    // Negotiated with a VP8-only peer: the send codecs carry no spatial layers.
    let mut offerer = peer()?;
    let mut answerer = vp8_only_peer()?;
    let sender = add(
        &mut offerer,
        RtpCodecKind::Video,
        vec![encoding("", None, "")],
    )?;
    let now = Instant::now();
    let offer = offerer.create_offer(None)?;
    offerer.set_local_description(now, offer.clone())?;
    answerer.set_remote_description(now, offer)?;
    let answer = answerer.create_answer(None)?;
    answerer.set_local_description(now, answer.clone())?;
    offerer.set_remote_description(now, answer)?;
    assert!(matches!(
        set_mode(&mut offerer, sender, &[Some("L2T2")]),
        Err(Error::InvalidModificationError)
    ));
    set_mode(&mut offerer, sender, &[Some("L1T2")])?;
    Ok(())
}

/// webrtc-svc 3.2.3: after negotiation getParameters returns the mode an encoding was given,
/// and none for an encoding that was given none.
#[test]
fn get_parameters_after_negotiation_returns_the_configured_mode() -> Result<()> {
    let mut offerer = peer()?;
    let mut answerer = peer()?;
    let with = add(
        &mut offerer,
        RtpCodecKind::Video,
        vec![encoding("", Some("L1T3"), "")],
    )?;
    let without = add(
        &mut offerer,
        RtpCodecKind::Video,
        vec![encoding("", None, "")],
    )?;
    let now = Instant::now();
    let offer = offerer.create_offer(None)?;
    offerer.set_local_description(now, offer.clone())?;
    answerer.set_remote_description(now, offer)?;
    let answer = answerer.create_answer(None)?;
    answerer.set_local_description(now, answer.clone())?;
    offerer.set_remote_description(now, answer)?;
    let mode = |pc: &mut rtci::peer_connection::RTCPeerConnection, s: RTCRtpSenderId| {
        pc.rtp_sender(s).expect("sender").get_parameters().encodings[0]
            .scalability_mode
            .clone()
    };
    assert_eq!(mode(&mut offerer, with).as_deref(), Some("L1T3"));
    assert_eq!(mode(&mut offerer, without), None);
    Ok(())
}

/// webrtc-svc 3.2.3: "the user agent MAY configure a different scalability mode" than the one
/// requested when the codec cannot carry it, and getParameters returns the configured one. The
/// application's encoder reports the mode it configured; getParameters returns it from then
/// on. A mode outside the table is a TypeError, an encoding the sender does not have a
/// RangeError.
#[test]
fn get_parameters_returns_the_mode_the_encoder_configured() -> Result<()> {
    let mut offerer = peer()?;
    let mut answerer = peer()?;
    let sender = add(
        &mut offerer,
        RtpCodecKind::Video,
        vec![encoding("", Some("L3T3"), "")],
    )?;
    let now = Instant::now();
    let offer = offerer.create_offer(None)?;
    offerer.set_local_description(now, offer.clone())?;
    answerer.set_remote_description(now, offer)?;
    let answer = answerer.create_answer(None)?;
    answerer.set_local_description(now, answer.clone())?;
    offerer.set_remote_description(now, answer)?;
    let mode = |pc: &mut rtci::peer_connection::RTCPeerConnection| {
        pc.rtp_sender(sender)
            .expect("sender")
            .get_parameters()
            .encodings[0]
            .scalability_mode
            .clone()
    };
    assert_eq!(mode(&mut offerer).as_deref(), Some("L3T3"), "as requested");
    offerer
        .rtp_sender(sender)
        .expect("sender")
        .set_configured_scalability_mode(0, Some("L1T3"))?;
    assert_eq!(mode(&mut offerer).as_deref(), Some("L1T3"), "as configured");
    let mut handle = offerer.rtp_sender(sender).expect("sender");
    assert!(matches!(
        handle.set_configured_scalability_mode(0, Some("L9T9")),
        Err(Error::TypeError(_))
    ));
    assert!(matches!(
        handle.set_configured_scalability_mode(3, Some("L1T1")),
        Err(Error::RangeError(_))
    ));
    Ok(())
}
