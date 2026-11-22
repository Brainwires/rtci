//! W3C webrtc 5.3 / RFC 3550 5.1: the SSRC of a received packet is a synchronization source of
//! its receiver and each CSRC a contributing source, for ten seconds after the last packet.

use super::*;
use crate::media_stream::track::MediaStreamTrack;
use crate::rtp_transceiver::rtp_receiver::internal::linear_audio_level;
use crate::rtp_transceiver::rtp_sender::{
    RTCRtpCodec, RTCRtpCodecParameters, RTCRtpEncodingParameters, RtpCodecKind,
};
use crate::rtp_transceiver::{RTCRtpTransceiverDirection, RTCRtpTransceiverInit};
use bytes::Bytes;
use interceptor::Registry;
use sansio::Protocol as _;
use shared::TransportContext;

const SSRC: u32 = 1000;
const PT: u8 = 111;
const AUDIO_LEVEL_ID: u8 = 3;

fn opus() -> RTCRtpCodecParameters {
    RTCRtpCodecParameters {
        rtp_codec: RTCRtpCodec {
            mime_type: "audio/opus".to_owned(),
            clock_rate: 48_000,
            channels: 2,
            sdp_fmtp_line: String::new(),
            rtcp_feedback: vec![],
        },
        payload_type: PT,
    }
}

fn coding() -> RTCRtpCodingParameters {
    RTCRtpCodingParameters {
        rid: String::new(),
        ssrc: Some(SSRC),
        rtx: None,
        fec: None,
    }
}

fn transceiver() -> RTCRtpTransceiverInternal {
    let mut transceiver = RTCRtpTransceiverInternal::new(
        RtpCodecKind::Audio,
        None,
        RTCRtpTransceiverInit {
            direction: RTCRtpTransceiverDirection::Recvonly,
            streams: vec![],
            send_encodings: vec![],
        },
    );
    let receiver = transceiver.receiver_mut().as_mut().unwrap();
    receiver.set_coding_parameters(vec![coding()]);
    receiver.set_codec_preferences(vec![opus()]);
    receiver.set_track(MediaStreamTrack::new(
        "stream".to_string(),
        "track".to_string(),
        "label".to_string(),
        RtpCodecKind::Audio,
        vec![RTCRtpEncodingParameters {
            rtp_coding_parameters: coding(),
            active: true,
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
        .register_codec(opus(), RtpCodecKind::Audio)
        .expect("opus");
    media_engine
        .register_header_extension(
            RTCRtpHeaderExtensionCapability {
                uri: ::sdp::extmap::AUDIO_LEVEL_URI.to_owned(),
            },
            RtpCodecKind::Audio,
            None,
        )
        .expect("extension");
    media_engine
        .update_header_extension(
            u16::from(AUDIO_LEVEL_ID),
            ::sdp::extmap::AUDIO_LEVEL_URI,
            RtpCodecKind::Audio,
        )
        .expect("negotiate audio level");
    media_engine
}

struct Arrival {
    after: Duration,
    sequence_number: u16,
    timestamp: u32,
    csrc: Vec<u32>,
    /// RFC 6464: the level in -dBov.
    audio_level: Option<u8>,
}

/// The receiver after `arrivals` passed the handler and were read by the application.
fn receiver_after(arrivals: Vec<Arrival>) -> RTCRtpTransceiverInternal {
    receiver_after_goodbye(arrivals, vec![])
}

/// The same, with a BYE for `goodbye` arriving last.
fn receiver_after_goodbye(arrivals: Vec<Arrival>, goodbye: Vec<u32>) -> RTCRtpTransceiverInternal {
    let media_engine = media_engine();
    let mut transceivers = vec![transceiver()];
    let mut stats = RTCStatsAccumulator::new();
    let mut ctx = InterceptorHandlerContext {
        is_dtls_handshake_complete: true,
        ..Default::default()
    };
    let mut chain = Registry::new().build();
    let mut handler = InterceptorHandler::new(
        &mut ctx,
        &mut transceivers,
        &media_engine,
        &mut chain,
        &mut stats,
    );

    let base = Instant::now();
    for arrival in arrivals {
        let mut header = rtp::Header {
            version: 2,
            payload_type: PT,
            sequence_number: arrival.sequence_number,
            timestamp: arrival.timestamp,
            ssrc: SSRC,
            csrc: arrival.csrc,
            ..Default::default()
        };
        if let Some(level) = arrival.audio_level {
            header
                .set_extension(AUDIO_LEVEL_ID, Bytes::from(vec![0x80 | level]))
                .expect("extension");
        }
        handler
            .handle_read(TaggedRTCMessageInternal {
                now: base + arrival.after,
                transport: TransportContext::default(),
                message: RTCMessageInternal::Rtp(RTPMessage::Packet(Packet::Rtp(rtp::Packet {
                    header,
                    payload: Bytes::from_static(&[1, 2, 3]),
                }))),
            })
            .expect("handle_read");
        while handler.poll_read().is_some() {}
    }
    if !goodbye.is_empty() {
        handler
            .handle_read(TaggedRTCMessageInternal {
                now: base + Duration::from_secs(1),
                transport: TransportContext::default(),
                message: RTCMessageInternal::Rtp(RTPMessage::Packet(Packet::Rtcp(vec![Box::new(
                    Goodbye {
                        sources: goodbye,
                        reason: Default::default(),
                    },
                )]))),
            })
            .expect("handle_read");
    }
    transceivers.remove(0)
}

fn arrival(after_ms: u64, sequence_number: u16, timestamp: u32, csrc: &[u32]) -> Arrival {
    Arrival {
        after: Duration::from_millis(after_ms),
        sequence_number,
        timestamp,
        csrc: csrc.to_vec(),
        audio_level: None,
    }
}

#[test]
fn the_ssrc_of_a_received_packet_is_a_synchronization_source() {
    let transceiver = receiver_after(vec![Arrival {
        audio_level: Some(30),
        ..arrival(0, 1, 4800, &[])
    }]);
    let receiver = transceiver.receiver().as_ref().unwrap();

    let sources: Vec<_> = receiver.get_synchronization_sources().collect();
    assert_eq!(1, sources.len());
    assert_eq!(SSRC, sources[0].source);
    assert_eq!(4800, sources[0].rtp_timestamp);
    assert!(sources[0].timestamp > Duration::ZERO);
    // RFC 6464 level 30 (-30 dBov) as a linear level.
    assert!((sources[0].audio_level - linear_audio_level(30)).abs() < 1e-9);
    assert!((sources[0].audio_level - 0.0316).abs() < 1e-3);
    assert_eq!(0, receiver.get_contributing_sources().count());
}

#[test]
fn the_csrcs_of_a_received_packet_are_contributing_sources() {
    let transceiver = receiver_after(vec![
        arrival(0, 1, 960, &[7, 8]),
        arrival(20, 2, 1920, &[8, 9]),
    ]);
    let receiver = transceiver.receiver().as_ref().unwrap();

    let mut sources: Vec<(u32, u32)> = receiver
        .get_contributing_sources()
        .map(|source| (source.source, source.rtp_timestamp))
        .collect();
    sources.sort_unstable();
    // One entry per CSRC, with the timestamp of the last packet that named it.
    assert_eq!(vec![(7, 960), (8, 1920), (9, 1920)], sources);

    // The SSRC is listed once, with the latest packet.
    let sync: Vec<_> = receiver.get_synchronization_sources().collect();
    assert_eq!(1, sync.len());
    assert_eq!(1920, sync[0].rtp_timestamp);
}

#[test]
fn a_source_is_forgotten_ten_seconds_after_its_last_packet() {
    let transceiver = receiver_after(vec![
        arrival(0, 1, 960, &[7]),
        arrival(9_000, 2, 1920, &[8]),
        arrival(10_500, 3, 2880, &[]),
    ]);
    let receiver = transceiver.receiver().as_ref().unwrap();

    let sources: Vec<u32> = receiver
        .get_contributing_sources()
        .map(|source| source.source)
        .collect();
    assert_eq!(
        vec![8],
        sources,
        "7 was last heard 10.5 s ago, 8 only 1.5 s"
    );
}

/// RFC 3550 6.6 (RFC 8834 4.1: RTCP relating to CSRCs is handled): a BYE naming a
/// contributing source removes it.
#[test]
fn a_bye_for_a_contributing_source_removes_it() {
    let transceiver = receiver_after_goodbye(vec![arrival(0, 1, 960, &[7, 8])], vec![7]);
    let receiver = transceiver.receiver().as_ref().unwrap();

    let sources: Vec<u32> = receiver
        .get_contributing_sources()
        .map(|source| source.source)
        .collect();
    assert_eq!(vec![8], sources);
    assert_eq!(1, receiver.get_synchronization_sources().count());
}

#[test]
fn silence_has_an_audio_level_of_zero() {
    assert_eq!(0.0, linear_audio_level(127));
    assert_eq!(1.0, linear_audio_level(0));
}
