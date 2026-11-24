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
        .replace_track(Some(track(MIME_TYPE_H264, "", Some(ssrc))))?;
    assert_eq!(
        pair.offerer
            .rtp_sender(sender_id)
            .expect("sender")
            .track()
            .expect("the sender has a track")
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
    let track_ssrc = sender.ssrcs().next();
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
    let track_ssrc = sender.ssrcs().next();
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
            .replace_track(Some(audio_track))
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
        .replace_track(Some(track(MIME_TYPE_VP9, "", Some(ssrc))))?;

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

/// W3C webrtc 5.1 `removeTrack` / 5.2 `replaceTrack(null)`: the sender's track becomes null,
/// and the sender stays: it is still in `getSenders`, keeps its encodings and parameters, and
/// its transceiver stops offering to send.
#[test]
fn test_rtp_sender_get_parameters_replaced() -> Result<()> {
    let (mut sender, mut receiver) = new_pair()?;
    let sender_id = sender.add_track(track(MIME_TYPE_VP8, "", None))?;
    let ssrc = {
        let mut rtp_sender = sender.rtp_sender(sender_id).expect("sender");
        assert_eq!(1, rtp_sender.get_parameters().encodings.len());
        rtp_sender.get_parameters().encodings[0]
            .rtp_coding_parameters
            .ssrc
    };

    sender.remove_track(sender_id)?;
    {
        let mut rtp_sender = sender
            .rtp_sender(sender_id)
            .expect("the sender outlives its track");
        assert!(rtp_sender.track().is_none());
        let parameters = rtp_sender.get_parameters().clone();
        assert_eq!(1, parameters.encodings.len());
        assert_eq!(ssrc, parameters.encodings[0].rtp_coding_parameters.ssrc);
        rtp_sender.set_parameters(parameters, None)?;
    }
    assert!(sender.get_senders().any(|id| id == sender_id));
    assert_eq!(
        sender
            .rtp_transceiver(sender_id.0)
            .expect("transceiver")
            .direction(),
        RTCRtpTransceiverDirection::Recvonly
    );

    sender.close()?;
    receiver.close()
}

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

/// Removing the track unbinds the sender's streams from the interceptor chain (which has the
/// sender report interceptor say BYE), and RTP written to the sender is then refused with
/// `ErrRTPSenderTrackRemoved` until `replace_track` gives it a track again.
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
    let packet = rtp::Packet {
        header: rtp::Header {
            version: 2,
            ssrc,
            ..Default::default()
        },
        ..Default::default()
    };
    let mut rtp_sender = sender.rtp_sender(sender_id).expect("sender");
    assert_eq!(
        rtp_sender.write_rtp(Instant::now(), packet.clone()),
        Err(Error::ErrRTPSenderTrackRemoved)
    );
    // With a track again the sender sends, on the SSRC it had, without negotiation.
    rtp_sender.replace_track(Some(track(MIME_TYPE_VP8, "", None)))?;
    assert_eq!(rtp_sender.ssrcs().collect::<Vec<_>>(), vec![ssrc]);
    assert_eq!(
        rtp_sender
            .track()
            .expect("track")
            .ssrcs()
            .collect::<Vec<_>>(),
        vec![ssrc]
    );
    assert_ne!(
        rtp_sender.write_rtp(Instant::now(), packet),
        Err(Error::ErrRTPSenderTrackRemoved)
    );

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

    let vp8_ssrc = offerer.rtp_sender(sender_a).expect("sender").ssrcs().next();

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

/// A recording offerer (sendonly video, one encoding that names no codec, W3C `sendEncodings`
/// leaving the codec to negotiation) and a default answerer.
fn empty_codec_sender() -> Result<(
    RTCPeerConnection,
    RTCPeerConnection,
    crate::peer_connection::util_test::StreamLog,
    crate::rtp_transceiver::RTCRtpTransceiverId,
)> {
    let (registry, log) = RecordingInterceptor::registry();
    let mut sender = new_peer(
        default_media_engine(),
        SettingEngineBuilder::new()
            .with_answering_dtls_role(RTCDtlsRole::Server)
            .build(),
        Some(registry),
        crate::peer_connection::util_test::OFFERER_ADDR,
    )?;
    let (_, receiver) = new_pair()?;
    let transceiver = sender.add_transceiver_from_kind(
        RtpCodecKind::Video,
        Some(RTCRtpTransceiverInit {
            direction: RTCRtpTransceiverDirection::Sendonly,
            streams: vec![],
            send_encodings: vec![RTCRtpEncodingParameters {
                active: true,
                ..Default::default()
            }],
        }),
    )?;
    Ok((sender, receiver, log, transceiver))
}

/// The engine's H.264 codecs (its first fmtp only) and the RTX that goes with it.
fn h264_preferences(pc: &RTCPeerConnection) -> Vec<RTCRtpCodecParameters> {
    let codecs = pc.media_engine.get_codecs_by_kind(RtpCodecKind::Video);
    let h264 = codecs
        .iter()
        .find(|c| c.rtp_codec.mime_type == MIME_TYPE_H264)
        .expect("the default engine has H.264")
        .clone();
    let rtx = codecs
        .iter()
        .find(|c| {
            c.rtp_codec.mime_type == MIME_TYPE_RTX
                && c.rtp_codec.sdp_fmtp_line == format!("apt={}", h264.payload_type)
        })
        .expect("the default engine has RTX for H.264")
        .clone();
    vec![h264, rtx]
}

/// A renegotiation that changes the codec an encoding without a codec of its own is sent with
/// (here: the sender's codec preferences now list H.264 only) re-binds its stream with the new
/// payload type, clock rate and RTX payload type, keeping its SSRCs; one that changes nothing
/// leaves the binding alone.
#[test]
fn a_renegotiated_codec_rebinds_the_senders_stream() -> Result<()> {
    let (mut sender, mut receiver, log, transceiver) = empty_codec_sender()?;
    signal_pair(&mut sender, &mut receiver)?;

    let bound: Vec<interceptor::StreamInfo> = log.bound_local.lock().unwrap().clone();
    assert_eq!(bound.len(), 1, "{bound:?}");
    let first = bound[0].clone();
    assert_eq!(first.mime_type, MIME_TYPE_VP8, "{first:?}");
    assert!(first.ssrc_rtx.is_some() && first.payload_type_rtx.is_some());

    let preferences = h264_preferences(&sender);
    let (h264_pt, rtx_pt) = (preferences[0].payload_type, preferences[1].payload_type);
    sender
        .rtp_transceiver(transceiver)
        .expect("transceiver")
        .set_codec_preferences(preferences)?;
    signal_pair(&mut sender, &mut receiver)?;

    let unbound: Vec<interceptor::StreamInfo> = log.unbound_local.lock().unwrap().clone();
    assert_eq!(
        unbound,
        vec![first.clone()],
        "the stream is unbound as it was bound"
    );
    let bound: Vec<interceptor::StreamInfo> = log.bound_local.lock().unwrap().clone();
    assert_eq!(bound.len(), 2, "{bound:?}");
    let second = &bound[1];
    assert_eq!(second.ssrc, first.ssrc, "the SSRC stays");
    assert_eq!(second.ssrc_rtx, first.ssrc_rtx, "the RTX SSRC stays");
    assert_eq!(second.mime_type, MIME_TYPE_H264, "{second:?}");
    assert_eq!(second.payload_type, h264_pt);
    assert_eq!(second.payload_type_rtx, Some(rtx_pt));
    assert_eq!(second.clock_rate, 90000);

    signal_pair(&mut sender, &mut receiver)?;
    assert_eq!(
        log.bound_local.lock().unwrap().len(),
        2,
        "a renegotiation that changes nothing does not re-bind"
    );
    assert_eq!(log.unbound_local.lock().unwrap().len(), 1);

    // The stats reference the codec the stream is now sent with.
    let ssrc = first.ssrc;
    let report = sender.get_stats(Instant::now(), crate::statistics::StatsSelector::None);
    let codec_id = report
        .outbound_rtp_streams()
        .find(|s| s.sent_rtp_stream_stats.rtp_stream_stats.ssrc == ssrc)
        .map(|s| s.sent_rtp_stream_stats.rtp_stream_stats.codec_id.clone())
        .expect("an outbound-rtp for the stream");
    let codec = report
        .iter()
        .find_map(|entry| match entry {
            crate::statistics::report::RTCStatsReportEntry::Codec(c) if c.stats.id == codec_id => {
                Some(c)
            }
            _ => None,
        })
        .expect("the codec the stream references");
    assert_eq!(codec.payload_type, h264_pt, "{codec:?}");

    sender.close()?;
    receiver.close()
}

/// When the answer leaves RTX out, the stream is bound without the RTX SSRC (there is no RTX
/// payload type to send it with), and the track's codings, which the binding reads, no longer
/// carry it either.
#[test]
fn a_negotiation_without_rtx_binds_no_rtx_ssrc() -> Result<()> {
    let (registry, log) = RecordingInterceptor::registry();
    let mut sender = new_peer(
        default_media_engine(),
        SettingEngineBuilder::new()
            .with_answering_dtls_role(RTCDtlsRole::Server)
            .build(),
        Some(registry),
        crate::peer_connection::util_test::OFFERER_ADDR,
    )?;
    let mut no_rtx = MediaEngine::default();
    no_rtx.register_codec(
        RTCRtpCodecParameters {
            rtp_codec: codec(MIME_TYPE_VP8),
            payload_type: 96,
        },
        RtpCodecKind::Video,
    )?;
    let (_, mut receiver) = new_pair_with(default_media_engine(), no_rtx)?;

    let ssrc = 0x5555_5555;
    let sender_id = sender.add_track(track(MIME_TYPE_VP8, "", Some(ssrc)))?;
    assert!(
        sender.rtp_transceivers[sender_id.0]
            .sender()
            .as_ref()
            .unwrap()
            .track()
            .codings()[0]
            .rtp_coding_parameters
            .rtx
            .is_some(),
        "the engine carries RTX, so the encoding starts with a repair flow"
    );
    signal_pair(&mut sender, &mut receiver)?;

    let bound: Vec<interceptor::StreamInfo> = log.bound_local.lock().unwrap().clone();
    let info = bound
        .iter()
        .find(|info| info.ssrc == ssrc)
        .expect("the stream is bound");
    assert_eq!(info.payload_type_rtx, None, "{info:?}");
    assert_eq!(
        info.ssrc_rtx, None,
        "no RTX SSRC without an RTX payload type: {info:?}"
    );
    let rtp_sender = sender.rtp_transceivers[sender_id.0]
        .sender()
        .as_ref()
        .unwrap();
    assert!(
        rtp_sender.track().codings()[0]
            .rtp_coding_parameters
            .rtx
            .is_none(),
        "the track's codings drop the RTX SSRC too"
    );

    sender.close()?;
    receiver.close()
}

/// A media engine with the default codecs and the MID, RtpStreamId and RepairedRtpStreamId
/// header extensions for audio and video.
fn media_engine_with_stream_ids() -> Result<MediaEngine> {
    let mut media_engine = default_media_engine();
    crate::peer_connection::configuration::interceptor_registry::configure_simulcast_extension_headers(
        &mut media_engine,
    )?;
    crate::peer_connection::configuration::interceptor_registry::configure_default_header_extensions(
        &mut media_engine,
    )?;
    Ok(media_engine)
}

fn negotiated_extension_id(sender: &mut RTCRtpSender<'_>, uri: &str) -> u8 {
    sender
        .get_parameters()
        .rtp_parameters
        .header_extensions
        .iter()
        .find(|extension| extension.uri == uri)
        .unwrap_or_else(|| panic!("{uri} was not negotiated"))
        .id as u8
}

/// RFC 9143 section 15: the MID header extension is sent so that the receiver can associate
/// the RTP stream with its m= section. The sender writes it; the application's packet has no
/// header extension at all.
#[test]
fn the_sender_stamps_the_mid_of_its_transceiver() -> Result<()> {
    let (mut offerer, mut answerer) = new_pair_with(
        media_engine_with_stream_ids()?,
        media_engine_with_stream_ids()?,
    )?;
    let audio_ssrc = 0x0a0a_0001;
    let video_ssrc = 0x0a0a_0002;
    let audio = offerer.add_track(track_with(
        "webrtc-rs",
        "audio",
        RtpCodecKind::Audio,
        vec![encoding(MIME_TYPE_OPUS, "", Some(audio_ssrc))],
    ))?;
    let video = offerer.add_track(track(MIME_TYPE_VP8, "", Some(video_ssrc)))?;

    signal_pair(&mut offerer, &mut answerer)?;
    let mut pair = Pair::new(offerer, answerer);
    pair.connect()?;

    let mut sequence_number = 100;
    for (sender_id, ssrc, mime_type, marker) in [
        (audio, audio_ssrc, MIME_TYPE_OPUS, 0xa1u8),
        (video, video_ssrc, MIME_TYPE_VP8, 0xb2u8),
    ] {
        let (payload_type, mid_id, mid) = {
            let mid = pair.offerer.rtp_transceivers[sender_id.0]
                .mid()
                .clone()
                .expect("a mid");
            let mut sender = pair.offerer.rtp_sender(sender_id).expect("sender");
            (
                negotiated_payload_type(&mut sender, mime_type),
                negotiated_extension_id(&mut sender, ::sdp::extmap::SDES_MID_URI),
                mid,
            )
        };
        let received = send_until_seen(
            &mut pair,
            sender_id,
            ssrc,
            payload_type,
            marker,
            &mut sequence_number,
        );
        assert_eq!(
            received.header.get_extension(mid_id).as_deref(),
            Some(mid.as_bytes()),
            "{mime_type}: the packet carries mid {mid}"
        );
    }
    pair.close()
}

/// RFC 7941 section 4.2.3: "only send header extensions when needed", with "the normal RTCP
/// report blocks" as "an indicator of successful delivery" (section 4.2.4.1: a new SSRC sends
/// them until delivered). The first packets of a stream carry the MID; once the receiver's
/// reception report covers them, the packets the sender writes carry it no more.
#[test]
fn the_mid_is_stamped_until_a_reception_report_shows_it_delivered() -> Result<()> {
    let (mut offerer, mut answerer) = new_pair_with(
        media_engine_with_stream_ids()?,
        media_engine_with_stream_ids()?,
    )?;
    let ssrc = 0x0d0d_0001;
    let sender_id = offerer.add_track(track(MIME_TYPE_VP8, "", Some(ssrc)))?;
    signal_pair(&mut offerer, &mut answerer)?;
    let mut pair = Pair::new(offerer, answerer);
    pair.connect()?;
    let (payload_type, mid_id) = {
        let mut sender = pair.offerer.rtp_sender(sender_id).expect("sender");
        (
            negotiated_payload_type(&mut sender, MIME_TYPE_VP8),
            negotiated_extension_id(&mut sender, ::sdp::extmap::SDES_MID_URI),
        )
    };
    let mut sequence_number = 700;
    let first = send_until_seen(
        &mut pair,
        sender_id,
        ssrc,
        payload_type,
        0xd1,
        &mut sequence_number,
    );
    assert!(
        first.header.get_extension(mid_id).is_some(),
        "the first packet"
    );
    // A few report intervals: the receiver reports on the stream.
    pair.run_until(std::time::Duration::from_secs(4), |_| false)?;
    let later = send_until_seen(
        &mut pair,
        sender_id,
        ssrc,
        payload_type,
        0xd2,
        &mut sequence_number,
    );
    assert!(
        later.header.get_extension(mid_id).is_none(),
        "delivered: the MID is not sent again"
    );
    pair.close()
}

/// RFC 7941 sections 4.2.4.1 and 4.2.4.3: a report block shows delivery only from the first
/// packet that carried the values on; a changed value, or an SSRC that has sent none, is not
/// delivered.
#[test]
fn header_extension_delivery_follows_the_report_blocks() {
    let mut sender = internal::RTCRtpSenderInternal::default();
    let delivered = |sender: &internal::RTCRtpSenderInternal, ssrc: SSRC, values: &str| {
        sender
            .sdes_delivery(ssrc)
            .is_some_and(|delivery| delivery.delivered(values))
    };
    assert!(!delivered(&sender, 1, "0\0"));
    sender.sdes_sent(1, "0\0", 65_530);
    sender.on_report_block(1, 65_529);
    assert!(
        !delivered(&sender, 1, "0\0"),
        "a report from before the first stamped packet"
    );
    // The extended highest sequence number wrapped past it.
    sender.on_report_block(1, 65_536 + 2);
    assert!(delivered(&sender, 1, "0\0"));
    assert!(!delivered(&sender, 1, "1\0"), "a changed value");
    assert!(!delivered(&sender, 2, "0\0"), "another SSRC");
    sender.sdes_sent(1, "1\0", 10);
    assert!(!delivered(&sender, 1, "1\0"));
    sender.on_report_block(1, 65_536 * 2 + 10);
    assert!(delivered(&sender, 1, "1\0"));
}

/// RFC 8852 section 3.3 and RFC 8853 section 5.5: each simulcast stream carries the rid of its
/// encoding in the RtpStreamId header extension (and the MID). The description names no SSRC
/// for a simulcast stream, so the receiver can only place the packet by what the sender
/// stamped: that it arrives, on the layer's rid, is the stamping.
#[test]
fn the_sender_stamps_the_rid_of_each_simulcast_encoding() -> Result<()> {
    let (mut offerer, mut answerer) = new_pair_with(
        media_engine_with_stream_ids()?,
        media_engine_with_stream_ids()?,
    )?;
    let layers = [("q", 0x0b0b_0001u32, 0xc1u8), ("f", 0x0b0b_0002, 0xc2)];
    let sender_id = offerer.add_track(track_with(
        "webrtc-rs",
        "video",
        RtpCodecKind::Video,
        layers
            .iter()
            .map(|(rid, ssrc, _)| encoding(MIME_TYPE_VP8, rid, Some(*ssrc)))
            .collect(),
    ))?;

    signal_pair(&mut offerer, &mut answerer)?;
    let mut pair = Pair::new(offerer, answerer);
    pair.connect()?;

    let (payload_type, mid_id, rid_id) = {
        let mut sender = pair.offerer.rtp_sender(sender_id).expect("sender");
        (
            negotiated_payload_type(&mut sender, MIME_TYPE_VP8),
            negotiated_extension_id(&mut sender, ::sdp::extmap::SDES_MID_URI),
            negotiated_extension_id(&mut sender, ::sdp::extmap::SDES_RTP_STREAM_ID_URI),
        )
    };
    let mid = pair.offerer.rtp_transceivers[sender_id.0]
        .mid()
        .clone()
        .expect("a mid");
    let mut sequence_number = 500;
    for (rid, ssrc, marker) in layers {
        let received = send_until_seen(
            &mut pair,
            sender_id,
            ssrc,
            payload_type,
            marker,
            &mut sequence_number,
        );
        assert_eq!(
            received.header.get_extension(rid_id).as_deref(),
            Some(rid.as_bytes()),
            "the packet of layer {rid} carries its rid"
        );
        assert_eq!(
            received.header.get_extension(mid_id).as_deref(),
            Some(mid.as_bytes())
        );
    }
    // Each layer opened as a track of its own rid on the receiving side.
    let mut rids: Vec<String> = pair
        .answerer_seen
        .events
        .iter()
        .filter_map(|event| match event {
            RTCPeerConnectionEvent::OnTrack(RTCTrackEvent::OnOpen(init)) => init.rid.clone(),
            _ => None,
        })
        .collect();
    rids.sort();
    assert_eq!(rids, vec!["f".to_owned(), "q".to_owned()]);
    pair.close()
}

/// A packet the application gave the extension itself is sent as it is: one MID element.
#[test]
fn a_packet_that_carries_its_mid_is_not_stamped_again() -> Result<()> {
    let (mut offerer, mut answerer) = new_pair_with(
        media_engine_with_stream_ids()?,
        media_engine_with_stream_ids()?,
    )?;
    let ssrc = 0x0c0c_0001;
    let sender_id = offerer.add_track(track(MIME_TYPE_VP8, "", Some(ssrc)))?;
    signal_pair(&mut offerer, &mut answerer)?;
    let mut pair = Pair::new(offerer, answerer);
    pair.connect()?;

    let (payload_type, mid_id) = {
        let mut sender = pair.offerer.rtp_sender(sender_id).expect("sender");
        (
            negotiated_payload_type(&mut sender, MIME_TYPE_VP8),
            negotiated_extension_id(&mut sender, ::sdp::extmap::SDES_MID_URI),
        )
    };
    let mid = pair.offerer.rtp_transceivers[sender_id.0]
        .mid()
        .clone()
        .expect("a mid");
    let mut header = rtp::header::Header {
        version: 2,
        payload_type,
        sequence_number: 9,
        timestamp: 9000,
        ssrc,
        ..Default::default()
    };
    header.set_extension(mid_id, bytes::Bytes::copy_from_slice(mid.as_bytes()))?;
    let before = header.clone();
    let now = pair.now;
    pair.offerer
        .rtp_sender(sender_id)
        .expect("sender")
        .write_rtp(
            now,
            rtp::Packet {
                header,
                payload: bytes::Bytes::from_static(&[0xd1]),
            },
        )?;
    let seen = |pair: &mut Pair| {
        pair.answerer_seen
            .reads
            .iter()
            .any(|m| matches!(m, RTCMessage::RtpPacket(_, p) if p.payload.last() == Some(&0xd1)))
    };
    assert!(pair.run_until(std::time::Duration::from_secs(2), seen)?);
    let received = pair
        .answerer_seen
        .reads
        .iter()
        .find_map(|m| match m {
            RTCMessage::RtpPacket(_, p) if p.payload.last() == Some(&0xd1) => Some(p.clone()),
            _ => None,
        })
        .expect("seen");
    assert_eq!(received.header.extensions.len(), before.extensions.len());
    assert_eq!(
        received.header.get_extension(mid_id).as_deref(),
        Some(mid.as_bytes())
    );
    pair.close()
}
