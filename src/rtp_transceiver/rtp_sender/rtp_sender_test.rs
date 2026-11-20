//! Ported from the async `webrtc` crate's `rtp_sender_test.rs` to the sans-IO API.
//!
//! The old tests connected two peers over a virtual network (`create_vnet_pair`) and wrote
//! samples through `TrackLocalStaticSample`; here two peer connections are driven against each
//! other in memory by [`crate::peer_connection::util_test::Pair`], and media is RTP written with
//! [`RTCRtpSender::write_rtp`].

use super::*;
use crate::media_stream::MediaStreamTrack;
use crate::peer_connection::configuration::media_engine::{
    MIME_TYPE_H264, MIME_TYPE_OPUS, MIME_TYPE_RTX, MIME_TYPE_VP8, MIME_TYPE_VP9, MediaEngine,
};
use crate::peer_connection::configuration::setting_engine::SettingEngineBuilder;
use crate::peer_connection::event::{RTCPeerConnectionEvent, RTCTrackEvent};
use crate::peer_connection::transport::RTCDtlsRole;
use crate::peer_connection::util_test::{
    Pair, RecordingInterceptor, default_media_engine, new_pair, new_pair_with, new_peer,
    send_until_seen, signal_pair,
};
use crate::rtp_transceiver::{RTCRtpTransceiverDirection, RTCRtpTransceiverInit, SSRC};

fn codec(mime_type: &str) -> RTCRtpCodec {
    let (clock_rate, channels, sdp_fmtp_line) = match mime_type {
        MIME_TYPE_OPUS => (48000, 2, "minptime=10;useinbandfec=1"),
        MIME_TYPE_H264 => (
            90000,
            0,
            "level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=42001f",
        ),
        MIME_TYPE_VP9 => (90000, 0, "profile-id=0"),
        _ => (90000, 0, ""),
    };
    RTCRtpCodec {
        mime_type: mime_type.to_owned(),
        clock_rate,
        channels,
        sdp_fmtp_line: sdp_fmtp_line.to_owned(),
        rtcp_feedback: vec![],
    }
}

fn kind_of(mime_type: &str) -> RtpCodecKind {
    if mime_type.starts_with("audio/") {
        RtpCodecKind::Audio
    } else {
        RtpCodecKind::Video
    }
}

fn encoding(mime_type: &str, rid: &str, ssrc: Option<SSRC>) -> RTCRtpEncodingParameters {
    RTCRtpEncodingParameters {
        rtp_coding_parameters: RTCRtpCodingParameters {
            rid: rid.to_owned(),
            ssrc,
            ..Default::default()
        },
        codec: codec(mime_type),
        ..Default::default()
    }
}

/// A track with one encoding.
fn track(mime_type: &str, rid: &str, ssrc: Option<SSRC>) -> MediaStreamTrack {
    track_with(
        "webrtc-rs",
        "video",
        kind_of(mime_type),
        vec![encoding(mime_type, rid, ssrc)],
    )
}

fn track_with(
    stream_id: &str,
    track_id: &str,
    kind: RtpCodecKind,
    encodings: Vec<RTCRtpEncodingParameters>,
) -> MediaStreamTrack {
    MediaStreamTrack::new(
        stream_id.to_owned(),
        track_id.to_owned(),
        track_id.to_owned(),
        kind,
        encodings,
    )
}

/// The payload type the sender negotiated for `mime_type`.
fn negotiated_payload_type(sender: &mut RTCRtpSender<'_>, mime_type: &str) -> u8 {
    sender
        .get_parameters()
        .rtp_parameters
        .codecs
        .iter()
        .find(|c| c.rtp_codec.mime_type.eq_ignore_ascii_case(mime_type))
        .unwrap_or_else(|| panic!("{mime_type} was not negotiated"))
        .payload_type
}

fn on_track_opens(pair: &Pair) -> usize {
    pair.answerer_seen
        .events
        .iter()
        .filter(|e| matches!(e, RTCPeerConnectionEvent::OnTrack(RTCTrackEvent::OnOpen(_))))
        .count()
}

#[test]
fn test_rtp_sender_replace_track() -> Result<()> {
    let (mut sender, mut receiver) = new_pair()?;

    let ssrc = 0x1111_1111;
    // The first track names no codec: a track's codec becomes its transceiver's codec
    // preference, and a sender pinned to VP8 would never negotiate the H264 it is replaced with.
    // The old `TrackLocalStaticSample` carried a codec without constraining negotiation.
    let first = track_with(
        "webrtc-rs",
        "video",
        RtpCodecKind::Video,
        vec![RTCRtpEncodingParameters {
            rtp_coding_parameters: RTCRtpCodingParameters {
                ssrc: Some(ssrc),
                ..Default::default()
            },
            ..Default::default()
        }],
    );
    let sender_id = sender.add_track(first)?;

    signal_pair(&mut sender, &mut receiver)?;
    let mut pair = Pair::new(sender, receiver);
    pair.connect()?;

    let (vp8_pt, h264_pt) = {
        let mut rtp_sender = pair.offerer.rtp_sender(sender_id).expect("sender");
        (
            negotiated_payload_type(&mut rtp_sender, MIME_TYPE_VP8),
            negotiated_payload_type(&mut rtp_sender, MIME_TYPE_H264),
        )
    };

    // Block until a packet with 0xAA has been seen, and it is VP8 on the receiving side.
    let mut sequence_number = 0;
    let packet = send_until_seen(
        &mut pair,
        sender_id,
        ssrc,
        vp8_pt,
        0xAA,
        &mut sequence_number,
    );
    let (codec, _) = pair
        .answerer
        .media_engine
        .get_codec_by_payload(packet.header.payload_type)?;
    assert_eq!(codec.rtp_codec.mime_type, MIME_TYPE_VP8);

    // The replacement keeps the sender's SSRC (a sender's encodings outlive its track, W3C
    // `replaceTrack`) and carries H264.
    pair.offerer
        .rtp_sender(sender_id)
        .expect("sender")
        .replace_track(track(MIME_TYPE_H264, "", Some(ssrc)))?;
    assert_eq!(
        pair.offerer
            .rtp_sender(sender_id)
            .expect("sender")
            .track()
            .codings()[0]
            .codec
            .mime_type,
        MIME_TYPE_H264
    );

    // Block until a packet with 0xBB has been seen, and it is H264 on the receiving side.
    let packet = send_until_seen(
        &mut pair,
        sender_id,
        ssrc,
        h264_pt,
        0xBB,
        &mut sequence_number,
    );
    let (codec, _) = pair
        .answerer
        .media_engine
        .get_codec_by_payload(packet.header.payload_type)?;
    assert_eq!(codec.rtp_codec.mime_type, MIME_TYPE_H264);

    // One remote track throughout: replacing the local track is not a new stream.
    assert_eq!(on_track_opens(&pair), 1);

    pair.close()
}

#[test]
fn test_rtp_sender_get_parameters() -> Result<()> {
    let (mut offerer, mut answerer) = new_pair()?;

    // The old `add_transceiver_from_kind(Video, None)` made a sendrecv transceiver with a track;
    // the sans-IO default is recvonly, so the sending form is asked for explicitly.
    let transceiver_id = offerer.add_transceiver_from_kind(
        RtpCodecKind::Video,
        Some(RTCRtpTransceiverInit {
            direction: RTCRtpTransceiverDirection::Sendrecv,
            streams: vec![],
            send_encodings: vec![encoding(MIME_TYPE_VP8, "", None)],
        }),
    )?;

    signal_pair(&mut offerer, &mut answerer)?;

    let sender_id = offerer
        .rtp_transceiver(transceiver_id)
        .expect("transceiver")
        .sender()
        .expect("a sending transceiver has a sender");
    let mut sender = offerer.rtp_sender(sender_id).expect("sender");
    let track_ssrc = sender.track().ssrcs().next();
    assert!(track_ssrc.is_some());
    let parameters = sender.get_parameters();
    assert_ne!(0, parameters.rtp_parameters.codecs.len());
    assert_eq!(1, parameters.encodings.len());
    assert_eq!(
        track_ssrc,
        parameters.encodings[0].rtp_coding_parameters.ssrc
    );
    assert!(parameters.encodings[0].rtp_coding_parameters.rid.is_empty());

    offerer.close()?;
    answerer.close()
}

#[test]
fn test_rtp_sender_get_parameters_with_rid() -> Result<()> {
    let (mut offerer, mut answerer) = new_pair()?;

    // The old test swapped a rid-carrying track onto the sender after negotiation
    // (`set_sending_track`); a sender's track is now given when the sender is made.
    let rid = "moo";
    let sender_id = offerer.add_track(track(MIME_TYPE_VP8, rid, None))?;

    signal_pair(&mut offerer, &mut answerer)?;

    let mut sender = offerer.rtp_sender(sender_id).expect("sender");
    let track_ssrc = sender.track().ssrcs().next();
    assert!(track_ssrc.is_some());
    let parameters = sender.get_parameters();
    assert_ne!(0, parameters.rtp_parameters.codecs.len());
    assert_eq!(1, parameters.encodings.len());
    assert_eq!(
        track_ssrc,
        parameters.encodings[0].rtp_coding_parameters.ssrc
    );
    assert_eq!(rid, parameters.encodings[0].rtp_coding_parameters.rid);

    offerer.close()?;
    answerer.close()
}

// Not ported: test_rtp_sender_set_read_deadline. It asserted that `RTCRtpSender::read_rtcp`
// on an idle sender times out under `tokio::time::timeout`. The sans-IO sender has no reader to
// block on: inbound RTCP is surfaced through `RTCPeerConnection::poll_read`, which never waits,
// so there is no read deadline to test.

#[test]
fn test_rtp_sender_replace_track_invalid_track_kind_change() -> Result<()> {
    let (mut sender, mut receiver) = new_pair()?;

    let sender_id = sender.add_track(track(MIME_TYPE_VP8, "", None))?;

    signal_pair(&mut sender, &mut receiver)?;

    let audio_track = track_with(
        "webrtc-rs",
        "audio",
        RtpCodecKind::Audio,
        vec![encoding(MIME_TYPE_OPUS, "", None)],
    );
    assert_eq!(
        sender
            .rtp_sender(sender_id)
            .expect("sender")
            .replace_track(audio_track)
            .unwrap_err(),
        Error::ErrRTPSenderNewTrackHasIncorrectKind
    );

    sender.close()?;
    receiver.close()
}

/// Replaced: the old test expected `replace_track` to refuse a track whose codec (VP9) was not
/// negotiated (`ErrUnsupportedCodec`). W3C `replaceTrack` checks only the kind, and so does the
/// sans-IO sender; what keeps an unnegotiated codec off the wire is the sender's negotiated
/// parameters. This checks that: after the replacement the sender still offers only the
/// preferred codec, and media written with VP9's payload type leaves as VP8.
#[test]
fn test_rtp_sender_replace_track_invalid_codec_change() -> Result<()> {
    let (mut sender, mut receiver) = new_pair()?;

    let ssrc = 0x2222_2222;
    let sender_id = sender.add_track(track(MIME_TYPE_VP8, "", Some(ssrc)))?;

    sender
        .rtp_transceiver(sender_id.0)
        .expect("transceiver")
        .set_codec_preferences(vec![RTCRtpCodecParameters {
            rtp_codec: codec(MIME_TYPE_VP8),
            payload_type: 96,
        }])?;

    signal_pair(&mut sender, &mut receiver)?;
    let mut pair = Pair::new(sender, receiver);
    pair.connect()?;

    pair.offerer
        .rtp_sender(sender_id)
        .expect("sender")
        .replace_track(track(MIME_TYPE_VP9, "", Some(ssrc)))?;

    let codecs = pair
        .offerer
        .rtp_sender(sender_id)
        .expect("sender")
        .get_parameters()
        .rtp_parameters
        .codecs
        .clone();
    assert!(
        !codecs
            .iter()
            .any(|c| c.rtp_codec.mime_type == MIME_TYPE_VP9),
        "VP9 was never negotiated: {codecs:?}"
    );

    // 98 is VP9 in the default codecs, and not negotiated on this sender.
    let mut sequence_number = 0;
    let packet = send_until_seen(&mut pair, sender_id, ssrc, 98, 0xAA, &mut sequence_number);
    let (codec, _) = pair
        .answerer
        .media_engine
        .get_codec_by_payload(packet.header.payload_type)?;
    assert_eq!(codec.rtp_codec.mime_type, MIME_TYPE_VP8);

    pair.close()
}

/// Replaced: the old test cleared the sender's track (`replace_track(None)`) and expected no
/// encodings. A sans-IO `replace_track` takes a track, not an `Option`; a sender stops having a
/// track when it is removed. After that the transceiver no longer sends and the sender is gone,
/// so it reports no parameters at all.
#[test]
fn test_rtp_sender_get_parameters_replaced() -> Result<()> {
    let (mut sender, mut receiver) = new_pair()?;
    let sender_id = sender.add_track(track(MIME_TYPE_VP8, "", None))?;
    {
        let mut rtp_sender = sender.rtp_sender(sender_id).expect("sender");
        assert_eq!(1, rtp_sender.get_parameters().encodings.len());
    }

    sender.remove_track(sender_id)?;
    assert!(sender.rtp_sender(sender_id).is_none());
    assert!(sender.get_senders().all(|id| id != sender_id));
    assert_eq!(
        sender
            .rtp_transceiver(sender_id.0)
            .expect("the transceiver outlives its sender")
            .direction(),
        RTCRtpTransceiverDirection::Recvonly
    );

    sender.close()?;
    receiver.close()
}

/// Replaced: the old test called `send` twice and expected `ErrRTPSenderSendAlreadyCalled` on
/// the second. The sans-IO sender has no `send`: negotiation starts it, binding its streams to
/// the interceptor chain. What the error protected against is a sender started twice, which
/// here would bind its streams twice; a second negotiation must not.
#[test]
fn test_rtp_sender_send() -> Result<()> {
    let (registry, log) = RecordingInterceptor::registry();
    let mut sender = new_peer(
        default_media_engine(),
        SettingEngineBuilder::new()
            .with_answering_dtls_role(RTCDtlsRole::Server)
            .build(),
        Some(registry),
        crate::peer_connection::util_test::OFFERER_ADDR,
    )?;
    let (_, mut receiver) = new_pair()?;

    let ssrc = 0x3333_3333;
    let sender_id = sender.add_track(track(MIME_TYPE_VP8, "", Some(ssrc)))?;
    {
        let mut rtp_sender = sender.rtp_sender(sender_id).expect("sender");
        assert_eq!(1, rtp_sender.get_parameters().encodings.len());
    }
    assert!(log.bound_local.lock().unwrap().is_empty());

    signal_pair(&mut sender, &mut receiver)?;
    let bound = |log: &crate::peer_connection::util_test::StreamLog| {
        log.bound_local
            .lock()
            .unwrap()
            .iter()
            .filter(|info| info.ssrc == ssrc)
            .count()
    };
    assert_eq!(bound(&log), 1, "negotiation starts the sender");
    assert!(
        sender.rtp_transceivers[sender_id.0]
            .sender()
            .as_ref()
            .unwrap()
            .has_sent()
    );

    signal_pair(&mut sender, &mut receiver)?;
    assert_eq!(bound(&log), 1, "a started sender is not started again");

    sender.close()?;
    receiver.close()
}

/// Replaced: the old test expected `send` on a removed sender to fail with
/// `ErrRTPSenderTrackRemoved`. Without `send`, the sans-IO equivalents are that removing the
/// track unbinds the sender's streams from the interceptor chain and leaves no sender to write
/// through.
#[test]
fn test_rtp_sender_send_track_removed() -> Result<()> {
    let (registry, log) = RecordingInterceptor::registry();
    let mut sender = new_peer(
        default_media_engine(),
        SettingEngineBuilder::new()
            .with_answering_dtls_role(RTCDtlsRole::Server)
            .build(),
        Some(registry),
        crate::peer_connection::util_test::OFFERER_ADDR,
    )?;
    let (_, mut receiver) = new_pair()?;

    let ssrc = 0x4444_4444;
    let sender_id = sender.add_track(track(MIME_TYPE_VP8, "", Some(ssrc)))?;
    signal_pair(&mut sender, &mut receiver)?;
    {
        let mut rtp_sender = sender.rtp_sender(sender_id).expect("sender");
        assert_eq!(1, rtp_sender.get_parameters().encodings.len());
    }

    sender.remove_track(sender_id)?;
    assert!(
        log.unbound_local
            .lock()
            .unwrap()
            .iter()
            .any(|info| info.ssrc == ssrc),
        "removing the track unbinds its stream"
    );
    assert!(sender.rtp_sender(sender_id).is_none());

    sender.close()?;
    receiver.close()
}

/// Replaced, in part: the old test built a simulcast sender layer by layer with `add_encoding`
/// and checked each refusal. The sans-IO sender takes its layers as encodings when it is made,
/// so the same rules are checked there:
///
/// - `ErrRTPSenderRidNil`: a layer without a rid among several.
/// - `ErrRTPSenderRIDCollision`: two layers with the same rid.
/// - `ErrRTPSenderStopped` (adding to a stopped sender): adding to a closed connection.
/// - a valid set of layers gives one encoding per layer, each with its own SSRC.
///
/// Not ported: `ErrRTPSenderNoBaseEncoding` (layers are not added to an existing encoding),
/// `ErrRTPSenderBaseEncodingMismatch` for a different stream or track id (every layer belongs
/// to the one `MediaStreamTrack` that carries them, so they cannot differ), and
/// `ErrRTPSenderSendAlreadyCalled` (there is no `send`, and no way to add a layer afterwards).
#[test]
fn test_rtp_sender_add_encoding() -> Result<()> {
    let (mut sender, mut receiver) = new_pair()?;

    let simulcast = |rids: &[&str]| {
        track_with(
            "webrtc-rs",
            "video",
            RtpCodecKind::Video,
            rids.iter()
                .map(|rid| encoding(MIME_TYPE_VP8, rid, None))
                .collect(),
        )
    };

    assert_eq!(
        sender.add_track(simulcast(&["f", ""])).unwrap_err(),
        Error::ErrRTPSenderRidNil
    );

    assert_eq!(
        sender.add_track(simulcast(&["f", "f"])).unwrap_err(),
        Error::ErrRTPSenderRIDCollision
    );

    // A layer whose codec is not the track's kind is refused too (the old
    // `ErrRTPSenderBaseEncodingMismatch` for an Opus layer on a video sender).
    let mixed = track_with(
        "webrtc-rs",
        "video",
        RtpCodecKind::Video,
        vec![
            encoding(MIME_TYPE_VP8, "f", None),
            encoding(MIME_TYPE_OPUS, "h", None),
        ],
    );
    assert!(sender.add_track(mixed).is_err());

    let sender_id = sender.add_track(simulcast(&["f", "h"]))?;
    {
        let mut rtp_sender = sender.rtp_sender(sender_id).expect("sender");
        let encodings = rtp_sender.get_parameters().encodings.clone();
        assert_eq!(
            encodings
                .iter()
                .map(|e| e.rtp_coding_parameters.rid.as_str())
                .collect::<Vec<_>>(),
            ["f", "h"]
        );
        let ssrcs: Vec<_> = encodings
            .iter()
            .map(|e| {
                e.rtp_coding_parameters
                    .ssrc
                    .expect("each layer has an SSRC")
            })
            .collect();
        assert_ne!(ssrcs[0], ssrcs[1]);
    }

    sender.close()?;
    assert_eq!(
        sender.add_track(simulcast(&["f", "h"])).unwrap_err(),
        Error::ErrConnectionClosed
    );

    receiver.close()
}

/// Every way of giving a sender its encodings refuses a repeated rid, and nothing is added.
#[test]
fn test_rtp_sender_duplicate_rid_is_refused() -> Result<()> {
    let (mut pc, _) = new_pair()?;
    let layers = || {
        ["f", "h", "f"]
            .iter()
            .map(|rid| encoding(MIME_TYPE_VP8, rid, None))
            .collect::<Vec<_>>()
    };

    let track = track_with("webrtc-rs", "video", RtpCodecKind::Video, layers());
    assert_eq!(
        pc.add_track(track.clone()).unwrap_err(),
        Error::ErrRTPSenderRIDCollision
    );
    assert_eq!(
        pc.add_transceiver_from_track(track, None).unwrap_err(),
        Error::ErrRTPSenderRIDCollision
    );
    assert_eq!(
        pc.add_transceiver_from_kind(
            RtpCodecKind::Video,
            Some(RTCRtpTransceiverInit {
                direction: RTCRtpTransceiverDirection::Sendonly,
                streams: vec![],
                send_encodings: layers(),
            }),
        )
        .unwrap_err(),
        Error::ErrRTPSenderRIDCollision
    );
    assert_eq!(pc.get_transceivers().count(), 0);

    pc.close()
}

fn rtx_media_engine() -> Result<MediaEngine> {
    let mut m = MediaEngine::default();
    m.register_codec(
        RTCRtpCodecParameters {
            rtp_codec: codec(MIME_TYPE_VP8),
            payload_type: 96,
        },
        RtpCodecKind::Video,
    )?;
    m.register_codec(
        RTCRtpCodecParameters {
            rtp_codec: codec(MIME_TYPE_H264),
            payload_type: 102,
        },
        RtpCodecKind::Video,
    )?;
    // only register rtx for VP8
    m.register_codec(
        RTCRtpCodecParameters {
            rtp_codec: RTCRtpCodec {
                mime_type: MIME_TYPE_RTX.to_owned(),
                clock_rate: 90000,
                channels: 0,
                sdp_fmtp_line: "apt=96".to_string(),
                rtcp_feedback: vec![],
            },
            payload_type: 97,
        },
        RtpCodecKind::Video,
    )?;
    Ok(m)
}

#[test]
fn test_rtp_sender_rtx() -> Result<()> {
    let (registry, log) = RecordingInterceptor::registry();
    let mut offerer = new_peer(
        rtx_media_engine()?,
        SettingEngineBuilder::new()
            .with_answering_dtls_role(RTCDtlsRole::Server)
            .build(),
        Some(registry),
        crate::peer_connection::util_test::OFFERER_ADDR,
    )?;
    let (_, mut answerer) = new_pair_with(rtx_media_engine()?, rtx_media_engine()?)?;

    let sender_a = offerer.add_track(track_with(
        "webrtc-rs",
        "video-a",
        RtpCodecKind::Video,
        vec![encoding(MIME_TYPE_VP8, "", None)],
    ))?;
    let sender_b = offerer.add_track(track_with(
        "webrtc-rs",
        "video-b",
        RtpCodecKind::Video,
        vec![encoding(MIME_TYPE_H264, "", None)],
    ))?;

    signal_pair(&mut offerer, &mut answerer)?;

    let rtx_ssrc = |pc: &mut crate::peer_connection::RTCPeerConnection, id| {
        pc.rtp_sender(id)
            .expect("sender")
            .get_parameters()
            .encodings[0]
            .rtp_coding_parameters
            .rtx
            .as_ref()
            .map(|rtx| rtx.ssrc)
    };
    // rtx enabled for vp8
    let vp8_rtx = rtx_ssrc(&mut offerer, sender_a);
    assert!(vp8_rtx.is_some());
    // An RTX SSRC is reserved per encoding whenever the engine has an RTX codec; whether it is
    // used is decided by the codec the encoding sends, below.
    assert!(rtx_ssrc(&mut offerer, sender_b).is_some());

    let vp8_ssrc = offerer
        .rtp_sender(sender_a)
        .expect("sender")
        .track()
        .ssrcs()
        .next();

    offerer.close()?;
    answerer.close()?;

    let mut vp8_ssrcs = Vec::new();
    let mut h264_ssrcs = Vec::new();
    let mut rtx_associated_ssrcs = Vec::new();

    for info in log.bound_local.lock().unwrap().iter() {
        match info.mime_type.as_str() {
            MIME_TYPE_VP8 => vp8_ssrcs.push(info.ssrc),
            MIME_TYPE_H264 => h264_ssrcs.push(info.ssrc),
            mime => panic!("unexpected mime: {mime}"),
        }
        // The sans-IO chain is told about a repair flow on its media stream's `StreamInfo`
        // (`ssrc_rtx` / `payload_type_rtx`), not with a stream of its own.
        if info.payload_type_rtx.is_some() {
            assert_eq!(info.payload_type_rtx, Some(97));
            assert_eq!(info.ssrc_rtx, vp8_rtx);
            rtx_associated_ssrcs.push(info.ssrc);
        }
    }

    assert_eq!(vp8_ssrcs.len(), 1);
    assert_eq!(h264_ssrcs.len(), 1);
    assert_eq!(vp8_ssrcs, vp8_ssrc.into_iter().collect::<Vec<_>>());
    assert_eq!(rtx_associated_ssrcs, vp8_ssrcs);

    Ok(())
}
