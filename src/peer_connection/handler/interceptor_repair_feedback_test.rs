//! RFC 4588 6.3: "the receiver MUST NOT send NACKs for the retransmission stream". A repair
//! flow (RTX, FEC) is bound to the interceptors as a stream of its own, without the feedback
//! that asks its primary for retransmissions or key frames.

use super::*;
use crate::media_stream::track::MediaStreamTrack;
use crate::peer_connection::configuration::media_engine::MIME_TYPE_RTX;
use crate::rtp_transceiver::rtp_sender::{
    RTCPFeedback, RTCRtpCodec, RTCRtpCodecParameters, RTCRtpEncodingParameters, RtpCodecKind,
};
use crate::rtp_transceiver::{RTCRtpTransceiverDirection, RTCRtpTransceiverInit};
use bytes::Bytes;
use interceptor::{NackGeneratorBuilder, Registry, Slot};
use rtcp::transport_feedbacks::transport_layer_nack::TransportLayerNack;
use sansio::Protocol as _;
use shared::TransportContext;

const SSRC: u32 = 1000;
const RTX_SSRC: u32 = 2000;
const PT: u8 = 96;
const RTX_PT: u8 = 97;

fn feedback(typ: &str, parameter: &str) -> RTCPFeedback {
    RTCPFeedback {
        typ: typ.to_owned(),
        parameter: parameter.to_owned(),
    }
}

fn vp8() -> RTCRtpCodecParameters {
    RTCRtpCodecParameters {
        rtp_codec: RTCRtpCodec {
            mime_type: "video/VP8".to_owned(),
            clock_rate: 90_000,
            channels: 0,
            sdp_fmtp_line: String::new(),
            rtcp_feedback: vec![
                feedback("nack", ""),
                feedback("nack", "pli"),
                feedback("ccm", "fir"),
                feedback("transport-cc", ""),
            ],
        },
        payload_type: PT,
    }
}

fn rtx() -> RTCRtpCodecParameters {
    RTCRtpCodecParameters {
        rtp_codec: RTCRtpCodec {
            mime_type: MIME_TYPE_RTX.to_owned(),
            clock_rate: 90_000,
            channels: 0,
            sdp_fmtp_line: format!("apt={PT}"),
            rtcp_feedback: vec![],
        },
        payload_type: RTX_PT,
    }
}

fn coding() -> RTCRtpCodingParameters {
    RTCRtpCodingParameters {
        rid: String::new(),
        ssrc: Some(SSRC),
        rtx: Some(RTCRtpRtxParameters { ssrc: RTX_SSRC }),
        fec: None,
    }
}

fn transceiver() -> RTCRtpTransceiverInternal {
    let mut transceiver = RTCRtpTransceiverInternal::new(
        RtpCodecKind::Video,
        None,
        RTCRtpTransceiverInit {
            direction: RTCRtpTransceiverDirection::Recvonly,
            streams: vec![],
            send_encodings: vec![],
        },
    );
    let receiver = transceiver.receiver_mut().as_mut().unwrap();
    receiver.set_coding_parameters(vec![coding()]);
    receiver.set_codec_preferences(vec![vp8(), rtx()]);
    receiver.set_track(MediaStreamTrack::new(
        "stream".to_string(),
        "track".to_string(),
        "label".to_string(),
        RtpCodecKind::Video,
        vec![RTCRtpEncodingParameters {
            rtp_coding_parameters: coding(),
            active: true,
            // Not known until a packet arrives, as `start_rtp` leaves a declared SSRC.
            codec: RTCRtpCodec::default(),
            max_bitrate: 0,
            max_framerate: None,
            scale_resolution_down_by: None,
        }],
    ));
    transceiver
}

fn media_engine() -> MediaEngine {
    let mut media_engine = MediaEngine::default();
    media_engine
        .register_codec(vp8(), RtpCodecKind::Video)
        .expect("vp8");
    media_engine
        .register_codec(rtx(), RtpCodecKind::Video)
        .expect("rtx");
    media_engine
}

fn rtp(
    now: Instant,
    ssrc: u32,
    payload_type: u8,
    sequence_number: u16,
    payload: &'static [u8],
) -> TaggedRTCMessageInternal {
    TaggedRTCMessageInternal {
        now,
        transport: TransportContext::default(),
        message: RTCMessageInternal::Rtp(RTPMessage::Packet(Packet::Rtp(rtp::Packet {
            header: rtp::Header {
                version: 2,
                payload_type,
                sequence_number,
                timestamp: 1,
                ssrc,
                ..Default::default()
            },
            payload: Bytes::from_static(payload),
        }))),
    }
}

/// The media SSRCs the chain NACKs over two seconds after `packets` arrived.
fn nacked_ssrcs(packets: &[(u32, u8, u16, &'static [u8])]) -> Vec<u32> {
    let media_engine = media_engine();
    let mut transceivers = vec![transceiver()];
    let mut stats = RTCStatsAccumulator::new();
    let mut ctx = InterceptorHandlerContext {
        is_dtls_handshake_complete: true,
        ..Default::default()
    };
    let mut chain = Registry::new()
        .with(Slot::NackGenerator, NackGeneratorBuilder::new().build())
        .build();
    let mut handler = InterceptorHandler::new(
        &mut ctx,
        &mut transceivers,
        &media_engine,
        &mut chain,
        &mut stats,
    );

    let now = Instant::now();
    for &(ssrc, payload_type, sequence_number, payload) in packets {
        handler
            .handle_read(rtp(now, ssrc, payload_type, sequence_number, payload))
            .expect("handle_read");
        while handler.poll_read().is_some() {}
    }

    let mut media_ssrcs = vec![];
    for tick in 1..=20u32 {
        handler
            .handle_timeout(now + Duration::from_millis(100) * tick)
            .expect("handle_timeout");
        while let Some(message) = handler.poll_write() {
            if let RTCMessageInternal::Rtp(RTPMessage::Packet(Packet::Rtcp(packets))) =
                message.message
            {
                for packet in packets {
                    if let Some(nack) = packet.as_any().downcast_ref::<TransportLayerNack>() {
                        media_ssrcs.push(nack.media_ssrc);
                    }
                }
            }
        }
    }
    media_ssrcs
}

/// Padding-only RTX packets (bandwidth probes, no original inside) are not de-encapsulated, so
/// they reach the chain on the RTX SSRC with the gaps the retransmissions in between left.
#[test]
fn gaps_between_rtx_padding_probes_are_not_nacked() {
    let nacked = nacked_ssrcs(&[
        (SSRC, PT, 1, &[0xDE, 0xAD]),
        (RTX_SSRC, RTX_PT, 10, &[]),
        (RTX_SSRC, RTX_PT, 20, &[]),
    ]);
    assert!(
        !nacked.contains(&RTX_SSRC),
        "NACKs were sent for the retransmission stream: {nacked:?}"
    );
}

/// The primary stream of the same pair is still repaired by NACK.
#[test]
fn gaps_in_the_primary_stream_are_still_nacked() {
    let nacked = nacked_ssrcs(&[(SSRC, PT, 1, &[0xDE, 0xAD]), (SSRC, PT, 3, &[0xDE, 0xAD])]);
    assert!(nacked.contains(&SSRC), "{nacked:?}");
    assert!(!nacked.contains(&RTX_SSRC), "{nacked:?}");
}

/// What the repair flow is bound with: the transport-wide feedback of its primary, none of
/// the feedback addressed to a media stream.
#[test]
fn a_repair_flow_keeps_only_transport_wide_feedback() {
    let codec = repair_flow_codec(&vp8().rtp_codec);
    assert_eq!(vec![feedback("transport-cc", "")], codec.rtcp_feedback);
    assert_eq!("video/VP8", codec.mime_type);
}
