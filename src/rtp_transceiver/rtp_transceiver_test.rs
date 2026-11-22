//! Ported from the async `webrtc` crate's `rtp_transceiver_test.rs` to the sans-IO API.
//!
//! The old tests made transceivers with `APIBuilder` and awaited every peer connection method;
//! here a transceiver is reached through [`RTCPeerConnection::rtp_transceiver`] and negotiation
//! is synchronous. Negotiation-needed is an [`RTCPeerConnectionEvent`] to poll rather than a
//! callback.

use crate::media_stream::MediaStreamTrack;
use crate::peer_connection::RTCPeerConnection;
use crate::peer_connection::configuration::media_engine::{
    MIME_TYPE_OPUS, MIME_TYPE_VP8, MIME_TYPE_VP9,
};
use crate::peer_connection::event::RTCPeerConnectionEvent;
use crate::peer_connection::util_test::{default_media_engine, new_pair, new_pair_with};
use crate::rtp_transceiver::RTCRtpTransceiverDirection;
use crate::rtp_transceiver::rtp_sender::{
    RTCRtpCodec, RTCRtpCodecParameters, RTCRtpCodingParameters, RTCRtpEncodingParameters,
    RtpCodecKind,
};
use sansio::Protocol;
use shared::error::{Error, Result};
use std::time::Instant;

fn codec(mime_type: &str, clock_rate: u32, channels: u16, fmtp: &str) -> RTCRtpCodec {
    RTCRtpCodec {
        mime_type: mime_type.to_owned(),
        clock_rate,
        channels,
        sdp_fmtp_line: fmtp.to_owned(),
        rtcp_feedback: vec![],
    }
}

fn opus() -> RTCRtpCodecParameters {
    RTCRtpCodecParameters {
        rtp_codec: codec(MIME_TYPE_OPUS, 48000, 2, "minptime=10;useinbandfec=1"),
        payload_type: 111,
    }
}

fn vp8(payload_type: u8) -> RTCRtpCodecParameters {
    RTCRtpCodecParameters {
        rtp_codec: codec(MIME_TYPE_VP8, 90000, 0, ""),
        payload_type,
    }
}

fn video_track() -> MediaStreamTrack {
    MediaStreamTrack::new(
        "webrtc-rs".to_owned(),
        "video".to_owned(),
        "video".to_owned(),
        RtpCodecKind::Video,
        vec![RTCRtpEncodingParameters {
            rtp_coding_parameters: RTCRtpCodingParameters::default(),
            codec: codec(MIME_TYPE_VP8, 90000, 0, ""),
            ..Default::default()
        }],
    )
}

fn drain_negotiation_needed(pc: &mut RTCPeerConnection) -> usize {
    let mut count = 0;
    while let Some(event) = pc.poll_event() {
        if matches!(event, RTCPeerConnectionEvent::OnNegotiationNeededEvent) {
            count += 1;
        }
    }
    count
}

#[test]
fn test_rtp_transceiver_set_codec_preferences() -> Result<()> {
    let m = default_media_engine();
    let media_video_codecs = m.get_codecs_by_kind(RtpCodecKind::Video);

    let mut pc = crate::peer_connection::RTCPeerConnectionBuilder::new()
        .with_media_engine(m)
        .build(Instant::now())?;
    let id = pc.add_transceiver_from_kind(
        RtpCodecKind::Video,
        Some(crate::rtp_transceiver::RTCRtpTransceiverInit::recvonly()),
    )?;
    let get_codecs = |pc: &RTCPeerConnection| pc.rtp_transceivers[id].get_codecs(&pc.media_engine);

    assert_eq!(get_codecs(&pc), media_video_codecs);

    let fail_test_cases = vec![vec![opus()], vec![vp8(96), opus()]];

    for test_case in fail_test_cases {
        assert_eq!(
            pc.rtp_transceiver(id)
                .expect("transceiver")
                .set_codec_preferences(test_case)
                .unwrap_err(),
            Error::InvalidModificationError
        );
    }

    let success_test_cases = vec![
        vec![vp8(96)],
        vec![
            vp8(96),
            RTCRtpCodecParameters {
                rtp_codec: codec(MIME_TYPE_VP9, 90000, 0, "profile-id=0"),
                payload_type: 98,
            },
        ],
    ];

    for test_case in success_test_cases {
        pc.rtp_transceiver(id)
            .expect("transceiver")
            .set_codec_preferences(test_case)?;
    }

    pc.rtp_transceiver(id)
        .expect("transceiver")
        .set_codec_preferences(vec![])?;
    assert_ne!(0, get_codecs(&pc).len());
    assert_eq!(get_codecs(&pc), media_video_codecs);

    pc.close()
}

// Assert that SetCodecPreferences properly filters codecs and PayloadTypes are respected
#[test]
fn test_rtp_transceiver_set_codec_preferences_payload_type() -> Result<()> {
    let test_codec = RTCRtpCodecParameters {
        rtp_codec: codec("video/test_codec", 90000, 0, ""),
        payload_type: 50,
    };

    let mut answerer_media_engine = default_media_engine();
    answerer_media_engine.register_codec(test_codec.clone(), RtpCodecKind::Video)?;
    let (mut offer_pc, mut answer_pc) =
        new_pair_with(default_media_engine(), answerer_media_engine)?;

    let _ = offer_pc.add_transceiver_from_kind(
        RtpCodecKind::Video,
        Some(crate::rtp_transceiver::RTCRtpTransceiverInit::recvonly()),
    )?;

    // The old transceivers were sendrecv by default; the sans-IO default is recvonly, and a
    // recvonly answerer transceiver cannot take a recvonly offer's m-section. A sending one can.
    let answer_sender = answer_pc.add_track(video_track())?;

    answer_pc
        .rtp_transceiver(answer_sender.0)
        .expect("transceiver")
        .set_codec_preferences(vec![test_codec, vp8(51)])?;

    let offer = offer_pc.create_offer(None)?;

    offer_pc.set_local_description(Instant::now(), offer.clone())?;
    answer_pc.set_remote_description(Instant::now(), offer)?;

    let answer = answer_pc.create_answer(None)?;

    // VP8 with proper PayloadType. The old crate answered with the preference's payload type
    // (51); this one answers with the offer's (96, VP8 in the default codecs), which is what
    // RFC 3264 §6.1 asks of an answer ("that same payload type number SHOULD be used for that
    // codec in the answer"). The preference still selects the codec.
    assert!(
        answer.sdp.contains("a=rtpmap:96 VP8/90000"),
        "{}",
        answer.sdp
    );
    assert!(!answer.sdp.contains("a=rtpmap:51 "), "{}", answer.sdp);

    // The preferences filter the answer: codecs the offerer has but the preferences omit are
    // left out.
    assert!(!answer.sdp.contains("VP9"), "{}", answer.sdp);

    // test_codec is ignored since offerer doesn't support
    assert!(!answer.sdp.contains("test_codec"));

    offer_pc.close()?;
    answer_pc.close()
}

#[test]
fn test_rtp_transceiver_direction_change() -> Result<()> {
    let (mut offer_pc, mut answer_pc) = new_pair()?;

    // Sendrecv on both sides, as the old default transceivers were.
    let offer_sender = offer_pc.add_track(video_track())?;
    let _ = answer_pc.add_track(video_track())?;

    let offer = offer_pc.create_offer(None)?;

    offer_pc.set_local_description(Instant::now(), offer.clone())?;
    answer_pc.set_remote_description(Instant::now(), offer)?;

    let answer = answer_pc.create_answer(None)?;
    assert!(answer.sdp.contains("a=sendrecv"), "{}", answer.sdp);
    answer_pc.set_local_description(Instant::now(), answer.clone())?;
    offer_pc.set_remote_description(Instant::now(), answer)?;

    offer_pc
        .rtp_transceiver(offer_sender.0)
        .expect("transceiver")
        .set_direction(RTCRtpTransceiverDirection::Inactive)
        .expect("the change is accepted");

    let offer = offer_pc.create_offer(None)?;
    assert!(offer.sdp.contains("a=inactive"), "{}", offer.sdp);

    offer_pc.set_local_description(Instant::now(), offer.clone())?;
    answer_pc.set_remote_description(Instant::now(), offer)?;

    let answer = answer_pc.create_answer(None)?;
    assert!(answer.sdp.contains("a=inactive"), "{}", answer.sdp);
    offer_pc.set_remote_description(Instant::now(), answer)?;

    offer_pc.close()?;
    answer_pc.close()
}

#[test]
fn test_rtp_transceiver_set_direction_causing_negotiation() -> Result<()> {
    let (mut offer_pc, mut answer_pc) = new_pair()?;

    let offer_sender = offer_pc.add_track(video_track())?;
    let _ = answer_pc.add_track(video_track())?;

    let renegotiate =
        |offer_pc: &mut RTCPeerConnection, answer_pc: &mut RTCPeerConnection| -> Result<()> {
            let offer = offer_pc.create_offer(None)?;
            offer_pc.set_local_description(Instant::now(), offer.clone())?;
            answer_pc.set_remote_description(Instant::now(), offer)?;

            let answer = answer_pc.create_answer(None)?;
            answer_pc.set_local_description(Instant::now(), answer.clone())?;
            offer_pc.set_remote_description(Instant::now(), answer)
        };

    renegotiate(&mut offer_pc, &mut answer_pc)?;
    // The old callback was registered after the first transceiver existed; adding it here fired
    // negotiation-needed before the exchange, which is what that exchange answered.
    drain_negotiation_needed(&mut offer_pc);

    renegotiate(&mut offer_pc, &mut answer_pc)?;
    assert_eq!(drain_negotiation_needed(&mut offer_pc), 0);

    offer_pc
        .rtp_transceiver(offer_sender.0)
        .expect("transceiver")
        .set_direction(RTCRtpTransceiverDirection::Inactive)
        .expect("the change is accepted");

    assert_eq!(drain_negotiation_needed(&mut offer_pc), 1);

    offer_pc.close()?;
    answer_pc.close()
}

/// RFC 9429 Section 5.2.2: an offer rejects (port 0) a stopped transceiver's m= section.
#[test]
fn test_rtp_transceiver_stopping() -> Result<()> {
    let (mut offer_pc, mut answer_pc) = new_pair()?;

    let offer_sender = offer_pc.add_track(video_track())?;
    let _ = answer_pc.add_track(video_track())?;

    let offer = offer_pc.create_offer(None)?;

    offer_pc.set_local_description(Instant::now(), offer.clone())?;
    answer_pc.set_remote_description(Instant::now(), offer)?;

    let answer = answer_pc.create_answer(None)?;
    assert!(answer.sdp.contains("a=sendrecv"), "{}", answer.sdp);
    answer_pc.set_local_description(Instant::now(), answer.clone())?;
    offer_pc.set_remote_description(Instant::now(), answer)?;

    assert!(
        offer_pc
            .rtp_transceiver(offer_sender.0)
            .expect("transceiver")
            .mid()
            .is_some(),
        "A mid should have been associated with the transceiver when applying the answer"
    );
    // Stop the transceiver
    offer_pc
        .rtp_transceiver(offer_sender.0)
        .expect("transceiver")
        .stop()?;

    let offer = offer_pc.create_offer(None)?;
    let parsed = offer.parsed.as_ref().expect("a parsed offer");
    let m = &parsed.media_descriptions[0];
    assert_eq!(
        m.media_name.port.value, 0,
        "After stopping a transceiver it should be rejected in offers: {}",
        offer.sdp
    );

    offer_pc.close()?;
    answer_pc.close()
}

/// Preferences that share no codec with the offer leave the section answered from the whole
/// engine, as without preferences, rather than with no codec.
#[test]
fn test_rtp_transceiver_codec_preferences_without_overlap_fall_back() -> Result<()> {
    let mut offerer_media_engine =
        crate::peer_connection::configuration::media_engine::MediaEngine::default();
    offerer_media_engine.register_codec(vp8(96), RtpCodecKind::Video)?;
    let (mut offer_pc, mut answer_pc) =
        new_pair_with(offerer_media_engine, default_media_engine())?;

    let _ = offer_pc.add_transceiver_from_kind(
        RtpCodecKind::Video,
        Some(crate::rtp_transceiver::RTCRtpTransceiverInit::recvonly()),
    )?;
    let answer_sender = answer_pc.add_track(video_track())?;
    answer_pc
        .rtp_transceiver(answer_sender.0)
        .expect("transceiver")
        .set_codec_preferences(vec![RTCRtpCodecParameters {
            rtp_codec: codec(MIME_TYPE_VP9, 90000, 0, "profile-id=0"),
            payload_type: 98,
        }])?;

    let offer = offer_pc.create_offer(None)?;
    offer_pc.set_local_description(Instant::now(), offer.clone())?;
    answer_pc.set_remote_description(Instant::now(), offer)?;
    let answer = answer_pc.create_answer(None)?;

    assert!(
        answer.sdp.contains("a=rtpmap:96 VP8/90000"),
        "{}",
        answer.sdp
    );
    assert!(!answer.sdp.contains("m=video 0 "), "{}", answer.sdp);

    offer_pc.close()?;
    answer_pc.close()
}
