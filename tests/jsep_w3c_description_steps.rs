//! Steps of W3C webrtc-pc "set a session description" (4.4.1.6) and of `createOffer` /
//! `createAnswer` (4.4.2) that concern the SDP: when a transceiver's mid becomes its own, what
//! a stable state does to the encodings' codecs.

mod jsep_common;

use std::time::Instant;

use jsep_common::{SESSION, TRANSPORT, TestResult, crlf, default_peer};
use rtc::media_stream::MediaStreamTrack;
use rtc::peer_connection::RTCPeerConnection;
use rtc::peer_connection::configuration::media_engine::{
    MIME_TYPE_H264, MIME_TYPE_OPUS, MIME_TYPE_TELEPHONE_EVENT, MIME_TYPE_VP9,
};
use rtc::peer_connection::configuration::{RTCAnswerOptions, RTCOfferOptions};
use rtc::peer_connection::event::RTCPeerConnectionEvent;
use rtc::peer_connection::sdp::RTCSessionDescription;
use rtc::rtp_transceiver::RTCRtpTransceiverDirection;
use rtc::rtp_transceiver::rtp_sender::{
    RTCRtpCodec, RTCRtpCodecParameters, RTCRtpCodingParameters, RTCRtpEncodingParameters,
    RtpCodecKind,
};
use rtc::shared::error::Error;
use sansio::Protocol;

/// W3C 4.4.1.6: applying a local description "set[s] the transceiver's [[Mid]] slot to
/// transceiver.[[JsepMid]]"; `createOffer` chose that mid, but `mid` stays null until the
/// offer is applied, and a rollback disassociates it again.
#[test]
fn a_transceivers_mid_is_set_when_the_offer_is_applied() -> TestResult {
    let mut pc = default_peer()?;
    let id = pc.add_transceiver_from_kind(RtpCodecKind::Video, None)?;
    let offer = pc.create_offer(None)?;
    assert!(offer.sdp.contains("a=mid:0\r\n"), "{}", offer.sdp);
    assert_eq!(
        pc.rtp_transceiver(id).expect("t").mid().as_deref(),
        None,
        "createOffer alone does not set it"
    );
    pc.set_local_description(Instant::now(), offer)?;
    assert_eq!(
        pc.rtp_transceiver(id).expect("t").mid().as_deref(),
        Some("0")
    );
    pc.set_local_description(Instant::now(), RTCSessionDescription::rollback(None)?)?;
    assert_eq!(pc.rtp_transceiver(id).expect("t").mid().as_deref(), None);
    Ok(())
}

/// W3C 4.4.1.6: once the signaling state is stable, "if encoding.codec does not match any
/// entry in [[SendCodecs]] ... remove encoding.codec": an encoding that asked for H.264
/// answered with VP8 only is sent with the negotiated codec.
#[test]
fn an_encoding_codec_the_answer_did_not_negotiate_is_removed() -> TestResult {
    let h264 = RTCRtpCodec {
        mime_type: MIME_TYPE_H264.to_owned(),
        clock_rate: 90000,
        channels: 0,
        sdp_fmtp_line: String::new(),
        rtcp_feedback: vec![],
    };
    let track = MediaStreamTrack::new(
        "s".to_owned(),
        "v".to_owned(),
        "v".to_owned(),
        RtpCodecKind::Video,
        vec![RTCRtpEncodingParameters {
            rtp_coding_parameters: RTCRtpCodingParameters {
                ssrc: Some(0x0e0a_0101),
                ..Default::default()
            },
            codec: h264,
            ..Default::default()
        }],
    );
    let mut pc = default_peer()?;
    let sender = pc.add_track(track)?;
    let offer = crlf(&format!(
        "{SESSION}m=video 9 UDP/TLS/RTP/SAVPF 96\n{TRANSPORT}a=mid:0\na=sendrecv\n\
         a=rtpmap:96 VP8/90000\n"
    ));
    let now = Instant::now();
    pc.set_remote_description(now, RTCSessionDescription::offer(offer)?)?;
    let codec_of = |pc: &mut rtc::peer_connection::RTCPeerConnection| {
        pc.rtp_sender(sender)
            .expect("sender")
            .get_parameters()
            .encodings[0]
            .codec
            .mime_type
            .clone()
    };
    assert_eq!(codec_of(&mut pc), MIME_TYPE_H264, "kept until stable");
    let answer = pc.create_answer(None)?;
    pc.set_local_description(now, answer)?;
    assert_eq!(codec_of(&mut pc), "", "removed once stable");
    Ok(())
}

fn negotiation_needed_events(pc: &mut RTCPeerConnection) -> usize {
    let mut count = 0;
    while let Some(event) = pc.poll_event() {
        if matches!(event, RTCPeerConnectionEvent::OnNegotiationNeededEvent) {
            count += 1;
        }
    }
    count
}

/// W3C webrtc-pc 4.4.3, the legacy `offerToReceive<Kind>` options: `false` turns sendrecv
/// into sendonly and recvonly into inactive; `true` adds a recvonly transceiver of the kind
/// when none receives, an add that "MUST NOT update the negotiation-needed flag".
#[test]
fn legacy_offer_to_receive_options_set_directions_and_add_a_silent_transceiver() -> TestResult {
    let mut pc = default_peer()?;
    let sendrecv = pc.add_transceiver_from_kind(RtpCodecKind::Audio, None)?;
    let recvonly = pc.add_transceiver_from_kind(
        RtpCodecKind::Audio,
        Some(rtc::rtp_transceiver::RTCRtpTransceiverInit::recvonly()),
    )?;
    negotiation_needed_events(&mut pc);
    let offer = pc.create_offer(Some(RTCOfferOptions {
        offer_to_receive_audio: Some(false),
        offer_to_receive_video: Some(true),
        ..Default::default()
    }))?;
    assert_eq!(
        pc.rtp_transceiver(sendrecv).expect("t").direction(),
        RTCRtpTransceiverDirection::Sendonly
    );
    assert_eq!(
        pc.rtp_transceiver(recvonly).expect("t").direction(),
        RTCRtpTransceiverDirection::Inactive
    );
    let ids: Vec<_> = pc.get_transceivers().collect();
    assert_eq!(ids.len(), 3, "a video transceiver was added");
    let video = pc.rtp_transceiver(ids[2]).expect("t");
    assert_eq!(video.direction(), RTCRtpTransceiverDirection::Recvonly);
    assert!(offer.sdp.contains("m=video "), "{}", offer.sdp);
    assert_eq!(
        negotiation_needed_events(&mut pc),
        0,
        "the legacy add does not update the negotiation-needed flag"
    );

    // A kind that already receives gets no other transceiver.
    pc.create_offer(Some(RTCOfferOptions {
        offer_to_receive_video: Some(true),
        ..Default::default()
    }))?;
    assert_eq!(pc.get_transceivers().count(), 3);
    Ok(())
}

/// W3C webrtc-pc 4.2.6: `RTCAnswerOptions` has no members. The fork's one member, RFC 9429
/// section 5.3.3.1 VoiceActivityDetection, is not applied unless asked for: an answer made
/// with the default options is the answer made with none.
#[test]
fn default_answer_options_answer_as_no_options_do() -> TestResult {
    let offer = crlf(&format!(
        "{SESSION}m=audio 9 UDP/TLS/RTP/SAVPF 111 13\n{TRANSPORT}a=mid:0\na=sendrecv\n\
         a=rtpmap:111 opus/48000/2\na=fmtp:111 usedtx=1\na=rtpmap:13 CN/8000\n"
    ));
    let mut pc = default_peer()?;
    pc.set_remote_description(Instant::now(), RTCSessionDescription::offer(offer)?)?;
    let without = pc.create_answer(None)?.sdp;
    let with_default = pc.create_answer(Some(RTCAnswerOptions::default()))?.sdp;
    let body = |sdp: &str| -> Vec<String> {
        sdp.lines()
            .filter(|l| !l.starts_with("o="))
            .map(str::to_owned)
            .collect()
    };
    assert_eq!(body(&without), body(&with_default));
    Ok(())
}

/// W3C webrtc-pc 4.4.2 `createOffer` (RFC 9429 section 5.2: "calling createOffer has no
/// side effects"): an offer made and not applied changes nothing that can be seen: no local
/// description, still stable, no mid, the gathering state as it was, and an ICE restart asked
/// for is not used up (the next offer restarts too).
#[test]
fn create_offer_has_no_visible_side_effects() -> TestResult {
    let mut pc = default_peer()?;
    let mut answerer = default_peer()?;
    let id = pc.add_transceiver_from_kind(RtpCodecKind::Video, None)?;
    let (first, _) = jsep_common::exchange(&mut pc, &mut answerer)?;
    let ufrag = |sdp: &str| -> String {
        sdp.lines()
            .find_map(|l| l.strip_prefix("a=ice-ufrag:"))
            .expect("an ice-ufrag")
            .to_owned()
    };
    pc.restart_ice();
    let gathering = pc.ice_gathering_state();
    let signaling = pc.signaling_state();
    let current = pc.current_local_description().map(|d| d.sdp);
    let restarting = pc.create_offer(None)?;
    assert_ne!(ufrag(&restarting.sdp), ufrag(&first), "an ICE restart");
    assert!(pc.pending_local_description().is_none());
    assert_eq!(pc.current_local_description().map(|d| d.sdp), current);
    assert_eq!(pc.signaling_state(), signaling);
    assert_eq!(pc.ice_gathering_state(), gathering);
    let again = pc.create_offer(None)?;
    assert_ne!(ufrag(&again.sdp), ufrag(&first), "still an ICE restart");

    // A transceiver added after the exchange has no mid until an offer with it is applied.
    let added = pc.add_transceiver_from_kind(RtpCodecKind::Audio, None)?;
    pc.create_offer(None)?;
    assert_eq!(pc.rtp_transceiver(added).expect("t").mid().as_deref(), None);
    assert!(pc.rtp_transceiver(id).expect("t").mid().is_some());
    Ok(())
}

fn codec(mime_type: &str, clock_rate: u32, channels: u16, fmtp: &str) -> RTCRtpCodecParameters {
    RTCRtpCodecParameters {
        rtp_codec: RTCRtpCodec {
            mime_type: mime_type.to_owned(),
            clock_rate,
            channels,
            sdp_fmtp_line: fmtp.to_owned(),
            rtcp_feedback: vec![],
        },
        payload_type: 0,
    }
}

/// W3C webrtc-pc 5.4 `setCodecPreferences` with the codec dictionary match: "If either (but
/// not both) of first.sdpFmtpLine and second.sdpFmtpLine are missing, return false", and a
/// line that is not key-value is compared by equality. VP9 without its `profile-id`, or
/// telephone-event with other events than the capability's `0-15`, matches no capability and
/// is an InvalidModificationError; the capability itself is taken.
#[test]
fn codec_preferences_match_capabilities_by_their_format_parameters() -> TestResult {
    let mut pc = default_peer()?;
    let video = pc.add_transceiver_from_kind(RtpCodecKind::Video, None)?;
    let audio = pc.add_transceiver_from_kind(RtpCodecKind::Audio, None)?;
    let mut set = |id, codecs: Vec<RTCRtpCodecParameters>| {
        pc.rtp_transceiver(id)
            .expect("t")
            .set_codec_preferences(codecs)
    };
    assert_eq!(
        set(video, vec![codec(MIME_TYPE_VP9, 90000, 0, "")]),
        Err(Error::InvalidModificationError),
        "an sdpFmtpLine on one side only"
    );
    set(video, vec![codec(MIME_TYPE_VP9, 90000, 0, "profile-id=0")])?;
    let opus = codec(MIME_TYPE_OPUS, 48000, 2, "minptime=10;useinbandfec=1");
    assert_eq!(
        set(
            audio,
            vec![
                opus.clone(),
                codec(MIME_TYPE_TELEPHONE_EVENT, 48000, 0, "0-16")
            ]
        ),
        Err(Error::InvalidModificationError),
        "a line that is not key-value is compared by equality"
    );
    set(
        audio,
        vec![opus, codec(MIME_TYPE_TELEPHONE_EVENT, 48000, 0, "0-15")],
    )?;
    Ok(())
}
