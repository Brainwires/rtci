//! Which m= section a received RTP stream belongs to (RFC 9143 section 9.2), for an SSRC the
//! remote description does not declare: by the MID header extension, and, for a packet without
//! one, by the payload type when exactly one m= section receives it.

use super::*;
use crate::peer_connection::event::RTCTrackEvent;
use crate::rtp_transceiver::rtp_sender::{RTCRtpCodec, RTCRtpCodecParameters, RtpCodecKind};
use crate::rtp_transceiver::{RTCRtpTransceiverDirection, RTCRtpTransceiverInit};
use bytes::Bytes;
use interceptor::Registry;
use sansio::Protocol as _;
use shared::TransportContext;

const OPUS: u8 = 111;
const VP8: u8 = 96;
const VP9: u8 = 98;
const MID_ID: u8 = 4;

fn codec(mime_type: &str, payload_type: u8) -> RTCRtpCodecParameters {
    let audio = mime_type.starts_with("audio/");
    RTCRtpCodecParameters {
        rtp_codec: RTCRtpCodec {
            mime_type: mime_type.to_owned(),
            clock_rate: if audio { 48_000 } else { 90_000 },
            channels: if audio { 2 } else { 0 },
            sdp_fmtp_line: String::new(),
            rtcp_feedback: vec![],
        },
        payload_type,
    }
}

/// A receive-only transceiver with `mid` whose section negotiated `codecs`, and for which the
/// remote description declared no SSRC.
fn transceiver(
    kind: RtpCodecKind,
    mid: &str,
    codecs: Vec<RTCRtpCodecParameters>,
) -> RTCRtpTransceiverInternal {
    let mut transceiver = RTCRtpTransceiverInternal::new(
        kind,
        None,
        RTCRtpTransceiverInit {
            direction: RTCRtpTransceiverDirection::Recvonly,
            streams: vec![],
            send_encodings: vec![],
        },
    );
    transceiver.set_mid(mid.to_owned()).expect("mid");
    transceiver
        .receiver_mut()
        .as_mut()
        .unwrap()
        .set_codec_preferences(codecs);
    transceiver
}

fn media_engine() -> MediaEngine {
    let mut media_engine = MediaEngine::default();
    media_engine
        .register_codec(codec("audio/opus", OPUS), RtpCodecKind::Audio)
        .expect("opus");
    for (mime_type, payload_type) in [("video/VP8", VP8), ("video/VP9", VP9)] {
        media_engine
            .register_codec(codec(mime_type, payload_type), RtpCodecKind::Video)
            .expect("video codec");
    }
    for uri in [
        ::sdp::extmap::SDES_MID_URI,
        ::sdp::extmap::SDES_RTP_STREAM_ID_URI,
    ] {
        for kind in [RtpCodecKind::Audio, RtpCodecKind::Video] {
            media_engine
                .register_header_extension(
                    RTCRtpHeaderExtensionCapability {
                        uri: uri.to_owned(),
                    },
                    kind,
                    None,
                )
                .expect("extension");
        }
    }
    for kind in [RtpCodecKind::Audio, RtpCodecKind::Video] {
        media_engine
            .update_header_extension(u16::from(MID_ID), ::sdp::extmap::SDES_MID_URI, kind)
            .expect("negotiate the MID extension");
    }
    media_engine
}

struct Arrival {
    ssrc: u32,
    payload_type: u8,
    mid: Option<&'static str>,
}

/// Feeds `arrivals` to the handler and returns, for each track that opened, the index of its
/// transceiver and its SSRC, with the transceivers as the handler left them.
fn opened(
    transceivers: Vec<RTCRtpTransceiverInternal>,
    arrivals: &[Arrival],
) -> (Vec<(usize, u32)>, Vec<RTCRtpTransceiverInternal>) {
    opened_after_sdes(transceivers, &[], arrivals)
}

/// [`opened`], after an RTCP SDES packet with a MID item for each of `sdes_mids` arrived.
fn opened_after_sdes(
    mut transceivers: Vec<RTCRtpTransceiverInternal>,
    sdes_mids: &[(u32, &str)],
    arrivals: &[Arrival],
) -> (Vec<(usize, u32)>, Vec<RTCRtpTransceiverInternal>) {
    let media_engine = media_engine();
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
    let now = Instant::now();
    if !sdes_mids.is_empty() {
        let chunks = sdes_mids
            .iter()
            .map(|(source, mid)| SourceDescriptionChunk {
                source: *source,
                items: vec![
                    SourceDescriptionItem {
                        sdes_type: SdesType::SdesCname,
                        text: Bytes::from_static(b"cname"),
                    },
                    SourceDescriptionItem {
                        sdes_type: SdesType::SdesMid,
                        text: Bytes::copy_from_slice(mid.as_bytes()),
                    },
                ],
            })
            .collect();
        handler
            .handle_read(TaggedRTCMessageInternal {
                now,
                transport: TransportContext::default(),
                message: RTCMessageInternal::Rtp(RTPMessage::Packet(Packet::Rtcp(vec![Box::new(
                    SourceDescription { chunks },
                )]))),
            })
            .expect("handle_read");
        while handler.poll_read().is_some() {}
    }
    for (sequence_number, arrival) in arrivals.iter().enumerate() {
        let mut header = rtp::Header {
            version: 2,
            payload_type: arrival.payload_type,
            sequence_number: sequence_number as u16,
            timestamp: 1000,
            ssrc: arrival.ssrc,
            ..Default::default()
        };
        if let Some(mid) = arrival.mid {
            header
                .set_extension(MID_ID, Bytes::from_static(mid.as_bytes()))
                .expect("extension");
        }
        handler
            .handle_read(TaggedRTCMessageInternal {
                now,
                transport: TransportContext::default(),
                message: RTCMessageInternal::Rtp(RTPMessage::Packet(Packet::Rtp(rtp::Packet {
                    header,
                    payload: Bytes::from_static(&[1, 2, 3]),
                }))),
            })
            .expect("handle_read");
        while handler.poll_read().is_some() {}
    }
    let mut opened = vec![];
    while let Some(event) = handler.poll_event() {
        if let RTCEventInternal::RTCPeerConnectionEvent(RTCPeerConnectionEvent::OnTrack(
            RTCTrackEvent::OnOpen(init),
        )) = event.event
        {
            opened.push((init.receiver_id.0, init.ssrc));
        }
    }
    (opened, transceivers)
}

fn audio_and_two_video() -> Vec<RTCRtpTransceiverInternal> {
    vec![
        transceiver(RtpCodecKind::Audio, "0", vec![codec("audio/opus", OPUS)]),
        transceiver(RtpCodecKind::Video, "1", vec![codec("video/VP8", VP8)]),
        transceiver(RtpCodecKind::Video, "2", vec![codec("video/VP9", VP9)]),
    ]
}

/// RFC 9143 section 9.2: "If the packet's payload type is in the payload type table, update
/// the ... SSRC mapping table to include an entry that maps the packet's SSRC to the 'm='
/// section for that payload type."
#[test]
fn a_stream_without_a_mid_goes_to_the_one_section_that_receives_its_payload_type() {
    let (opened, transceivers) = opened(
        audio_and_two_video(),
        &[
            Arrival {
                ssrc: 0xaaaa,
                payload_type: VP9,
                mid: None,
            },
            Arrival {
                ssrc: 0xbbbb,
                payload_type: OPUS,
                mid: None,
            },
            // Later packets of a stream change nothing.
            Arrival {
                ssrc: 0xaaaa,
                payload_type: VP9,
                mid: None,
            },
        ],
    );
    assert_eq!(opened, vec![(2, 0xaaaa), (0, 0xbbbb)]);
    let ssrc_of = |index: usize| {
        transceivers[index]
            .receiver()
            .as_ref()
            .unwrap()
            .get_coding_parameters()
            .first()
            .and_then(|coding| coding.ssrc)
    };
    assert_eq!(ssrc_of(2), Some(0xaaaa));
    assert_eq!(ssrc_of(0), Some(0xbbbb));
    assert_eq!(ssrc_of(1), None, "nothing arrived for the VP8 section");
}

/// The payload type table holds only payload types that identify one m= section: "Otherwise,
/// drop the packet."
#[test]
fn a_payload_type_two_sections_receive_identifies_neither() {
    let transceivers = vec![
        transceiver(RtpCodecKind::Audio, "0", vec![codec("audio/opus", OPUS)]),
        transceiver(RtpCodecKind::Video, "1", vec![codec("video/VP8", VP8)]),
        transceiver(
            RtpCodecKind::Video,
            "2",
            vec![codec("video/VP8", VP8), codec("video/VP9", VP9)],
        ),
    ];
    let (opened, _) = opened(
        transceivers,
        &[
            Arrival {
                ssrc: 0xaaaa,
                payload_type: VP8,
                mid: None,
            },
            // VP9 is the third section's alone.
            Arrival {
                ssrc: 0xbbbb,
                payload_type: VP9,
                mid: None,
            },
        ],
    );
    assert_eq!(opened, vec![(2, 0xbbbb)]);
}

#[test]
fn a_payload_type_no_section_receives_opens_nothing() {
    let (opened, _) = opened(
        audio_and_two_video(),
        &[Arrival {
            ssrc: 0xaaaa,
            payload_type: 100,
            mid: None,
        }],
    );
    assert!(opened.is_empty(), "{opened:?}");
}

/// A stopped transceiver receives nothing, so its payload types are not in the table: the
/// other section that has the payload type is then the only one.
#[test]
fn a_stopped_transceiver_does_not_count() {
    let mut transceivers = vec![
        transceiver(RtpCodecKind::Audio, "0", vec![codec("audio/opus", OPUS)]),
        transceiver(RtpCodecKind::Video, "1", vec![codec("video/VP8", VP8)]),
        transceiver(RtpCodecKind::Video, "2", vec![codec("video/VP8", VP8)]),
    ];
    let media_engine = media_engine();
    let mut chain = Registry::new().build();
    transceivers[1]
        .stop(&media_engine, &mut chain)
        .expect("stop");
    let (opened, _) = opened(
        transceivers,
        &[Arrival {
            ssrc: 0xaaaa,
            payload_type: VP8,
            mid: None,
        }],
    );
    assert_eq!(opened, vec![(2, 0xaaaa)]);
}

/// RFC 9143 section 9.2 looks at the MID first: a packet that names its m= section goes
/// there, whatever other section has the payload type.
#[test]
fn a_mid_decides_before_the_payload_type() {
    let transceivers = vec![
        transceiver(RtpCodecKind::Audio, "0", vec![codec("audio/opus", OPUS)]),
        transceiver(RtpCodecKind::Video, "1", vec![codec("video/VP8", VP8)]),
        transceiver(RtpCodecKind::Video, "2", vec![codec("video/VP8", VP8)]),
    ];
    let (opened, _) = opened(
        transceivers,
        &[Arrival {
            ssrc: 0xaaaa,
            payload_type: VP8,
            mid: Some("2"),
        }],
    );
    assert_eq!(opened, vec![(2, 0xaaaa)]);
}

/// RFC 9143 section 9.2: an RTCP SDES packet with a MID item maps the chunk's SSRC to the m=
/// section the MID names. A stream of that SSRC whose packets carry no MID, and whose payload
/// type two sections receive, then has its section. A MID that names no section maps nothing.
#[test]
fn an_sdes_mid_item_places_a_stream_whose_packets_carry_no_mid() {
    let two_vp8 = || {
        vec![
            transceiver(RtpCodecKind::Audio, "0", vec![codec("audio/opus", OPUS)]),
            transceiver(RtpCodecKind::Video, "1", vec![codec("video/VP8", VP8)]),
            transceiver(RtpCodecKind::Video, "2", vec![codec("video/VP8", VP8)]),
        ]
    };
    let arrival = [Arrival {
        ssrc: 0xaaaa,
        payload_type: VP8,
        mid: None,
    }];
    let (opened, _) = opened_after_sdes(two_vp8(), &[(0xaaaa, "1")], &arrival);
    assert_eq!(opened, vec![(1, 0xaaaa)]);

    // Another SSRC's MID, or a MID no section has, places nothing.
    let (opened, _) = opened_after_sdes(two_vp8(), &[(0xbbbb, "1"), (0xaaaa, "9")], &arrival);
    assert!(opened.is_empty(), "{opened:?}");
}
