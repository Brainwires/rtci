//! Which m= section a received RTP stream belongs to (RFC 9143 section 9.2), for an SSRC the
//! remote description does not declare: by the MID header extension, and, for a packet without
//! one, by the payload type when exactly one m= section receives it.

use super::*;
use crate::media_stream::MediaStreamTrack;
use crate::peer_connection::event::RTCTrackEvent;
use crate::rtp_transceiver::rtp_sender::{
    RTCRtpCodec, RTCRtpCodecParameters, RTCRtpEncodingParameters, RtpCodecKind,
};
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
    transceivers: Vec<RTCRtpTransceiverInternal>,
    sdes_mids: &[(u32, &str)],
    arrivals: &[Arrival],
) -> (Vec<(usize, u32)>, Vec<RTCRtpTransceiverInternal>) {
    let items: Vec<(u32, Vec<(SdesType, &str)>)> = sdes_mids
        .iter()
        .map(|(source, mid)| (*source, vec![(SdesType::SdesMid, *mid)]))
        .collect();
    opened_after_sdes_items(transceivers, &items, arrivals)
}

/// [`opened`], after an RTCP SDES packet with a chunk of `items` (after a CNAME) for each
/// source arrived.
fn opened_after_sdes_items(
    mut transceivers: Vec<RTCRtpTransceiverInternal>,
    sdes_items: &[(u32, Vec<(SdesType, &str)>)],
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
        None,
    );
    let now = Instant::now();
    if !sdes_items.is_empty() {
        let chunks = sdes_items
            .iter()
            .map(|(source, items)| SourceDescriptionChunk {
                source: *source,
                items: std::iter::once(SourceDescriptionItem {
                    sdes_type: SdesType::SdesCname,
                    text: Bytes::from_static(b"cname"),
                })
                .chain(items.iter().map(|(sdes_type, text)| SourceDescriptionItem {
                    sdes_type: *sdes_type,
                    text: Bytes::copy_from_slice(text.as_bytes()),
                }))
                .collect(),
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

/// RFC 9143 section 9.2: the MID extension of a later packet re-associates an SSRC already
/// bound: a stream placed in section 1 whose packets then name section 2 moves there, and
/// section 1's receiver no longer has it.
#[test]
fn a_later_mid_moves_an_ssrc_to_its_section() {
    let transceivers = vec![
        transceiver(RtpCodecKind::Video, "1", vec![codec("video/VP8", VP8)]),
        transceiver(RtpCodecKind::Video, "2", vec![codec("video/VP8", VP8)]),
    ];
    let (opened, transceivers) = opened(
        transceivers,
        &[
            Arrival {
                ssrc: 0xbbbb,
                payload_type: VP8,
                mid: Some("1"),
            },
            Arrival {
                ssrc: 0xbbbb,
                payload_type: VP8,
                mid: Some("2"),
            },
        ],
    );
    assert_eq!(opened, vec![(0, 0xbbbb), (1, 0xbbbb)]);
    let ssrcs = |t: &RTCRtpTransceiverInternal| -> Vec<Option<u32>> {
        t.receiver()
            .as_ref()
            .map(|r| {
                r.track()
                    .codings()
                    .iter()
                    .map(|c| c.rtp_coding_parameters.ssrc)
                    .collect()
            })
            .unwrap_or_default()
    };
    assert_eq!(ssrcs(&transceivers[0]), vec![]);
    assert_eq!(ssrcs(&transceivers[1]), vec![Some(0xbbbb)]);
}

/// RFC 9143 section 9.2 and RFC 7941 section 4.2.6: a stream the remote description
/// declares for section 1 moves to section 2 when its packets name mid 2; a reordered packet
/// still naming mid 1, older than the one that moved it, does not move it back; a newer one
/// naming mid 1 again does.
#[test]
fn a_declared_ssrc_follows_its_newest_mid() {
    let mut transceivers = vec![
        transceiver(RtpCodecKind::Video, "1", vec![codec("video/VP8", VP8)]),
        transceiver(RtpCodecKind::Video, "2", vec![codec("video/VP8", VP8)]),
    ];
    declare(&mut transceivers[0], 0xcccc);
    let arrival = |mid: &'static str| Arrival {
        ssrc: 0xcccc,
        payload_type: VP8,
        mid: Some(mid),
    };
    let holder = |transceivers: &[RTCRtpTransceiverInternal]| -> Vec<usize> {
        (0..transceivers.len())
            .filter(|&i| receive_codings(transceivers, i).contains(&(Some(0xcccc), None)))
            .collect()
    };
    let (_, after) = opened_in_order(
        transceivers,
        &[(arrival("1"), 10), (arrival("2"), 12), (arrival("1"), 11)],
    );
    assert_eq!(
        holder(&after),
        vec![1],
        "moved to mid 2; the older packet did not move it back"
    );

    let mut transceivers = vec![
        transceiver(RtpCodecKind::Video, "1", vec![codec("video/VP8", VP8)]),
        transceiver(RtpCodecKind::Video, "2", vec![codec("video/VP8", VP8)]),
    ];
    declare(&mut transceivers[0], 0xcccc);
    let (_, after) = opened_in_order(
        transceivers,
        &[(arrival("1"), 10), (arrival("2"), 12), (arrival("1"), 13)],
    );
    assert_eq!(
        holder(&after),
        vec![0],
        "a newer packet naming mid 1 moves it back"
    );
}

/// What a remote description declaring `ssrc` for the section leaves on its receiver: the
/// coding and the track's encoding, the codec still unknown.
fn declare(transceiver: &mut RTCRtpTransceiverInternal, ssrc: u32) {
    let coding = RTCRtpCodingParameters {
        ssrc: Some(ssrc),
        ..Default::default()
    };
    let receiver = transceiver.receiver_mut().as_mut().unwrap();
    receiver.set_coding_parameters(vec![coding.clone()]);
    receiver.set_track(MediaStreamTrack::new(
        "stream".to_string(),
        "declared".to_string(),
        "label".to_string(),
        RtpCodecKind::Video,
        vec![RTCRtpEncodingParameters {
            rtp_coding_parameters: coding,
            active: true,
            ..Default::default()
        }],
    ));
}

/// [`opened`] with the sequence number of each arrival given.
fn opened_in_order(
    mut transceivers: Vec<RTCRtpTransceiverInternal>,
    arrivals: &[(Arrival, u16)],
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
        None,
    );
    let now = Instant::now();
    for (arrival, sequence_number) in arrivals {
        let mut header = rtp::Header {
            version: 2,
            payload_type: arrival.payload_type,
            sequence_number: *sequence_number,
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

/// A receive-only video transceiver with `mid` that expects the simulcast layer `rid`, whose
/// SSRC the first packet of the layer gives.
fn simulcast_layer(mid: &str, rid: &str) -> RTCRtpTransceiverInternal {
    let mut transceiver = transceiver(RtpCodecKind::Video, mid, vec![codec("video/VP8", VP8)]);
    let receiver = transceiver.receiver_mut().as_mut().unwrap();
    let coding = RTCRtpCodingParameters {
        rid: rid.to_owned(),
        ..Default::default()
    };
    receiver.set_coding_parameters(vec![coding.clone()]);
    receiver.set_track(MediaStreamTrack::new(
        "stream".to_owned(),
        "track".to_owned(),
        "remote video".to_owned(),
        RtpCodecKind::Video,
        vec![RTCRtpEncodingParameters {
            rtp_coding_parameters: coding,
            ..Default::default()
        }],
    ));
    transceiver
}

/// RFC 8852 section 3.1: the RtpStreamId SDES item names a stream's rid as the header
/// extension does. A layer whose packets carry the MID but no RID opens once an SDES chunk of
/// its SSRC names the rid, and not without it.
#[test]
fn an_sdes_rtp_stream_id_item_places_a_layer_whose_packets_carry_no_rid() {
    let transceivers = || vec![simulcast_layer("0", "h"), simulcast_layer("1", "h")];
    let arrival = || Arrival {
        ssrc: 7000,
        payload_type: VP8,
        mid: Some("1"),
    };

    let (opened, _) = opened(transceivers(), &[arrival()]);
    assert!(opened.is_empty(), "no rid, no layer: {opened:?}");

    let (opened, _) = opened_after_sdes_items(
        transceivers(),
        &[(7000, vec![(SdesType::SdesRtpStreamId, "h")])],
        &[arrival()],
    );
    assert_eq!(opened, vec![(1, 7000)]);

    // A value that is not an RtpStreamId (RFC 8852 section 3: alphanumerics) is not taken.
    let (opened, _) = opened_after_sdes_items(
        transceivers(),
        &[(7000, vec![(SdesType::SdesRtpStreamId, "h-1")])],
        &[arrival()],
    );
    assert!(opened.is_empty(), "{opened:?}");
}

/// A DTMF event (RFC 4733 section 2.1: on the audio stream's SSRC) that arrives before any
/// audio does not make `telephone-event` the stream's codec: the track opens on the first
/// audio packet, with the audio codec.
#[test]
fn a_dtmf_packet_that_comes_first_does_not_set_the_tracks_codec() {
    const DTMF: u8 = 101;
    let transceivers = vec![
        transceiver(
            RtpCodecKind::Audio,
            "0",
            vec![
                codec("audio/opus", OPUS),
                codec("audio/telephone-event", DTMF),
            ],
        ),
        transceiver(RtpCodecKind::Video, "1", vec![codec("video/VP8", VP8)]),
    ];
    let (opened, transceivers) = opened(
        transceivers,
        &[
            Arrival {
                ssrc: 5000,
                payload_type: DTMF,
                mid: Some("0"),
            },
            Arrival {
                ssrc: 5000,
                payload_type: OPUS,
                mid: Some("0"),
            },
        ],
    );
    assert_eq!(opened, vec![(0, 5000)]);
    let receiver = transceivers[0].receiver().as_ref().expect("a receiver");
    assert_eq!(
        receiver
            .track()
            .get_codec_by_ssrc(5000)
            .map(|codec| codec.mime_type.as_str()),
        Some("audio/opus")
    );
}

/// The receive codings (SSRC, RTX SSRC) of transceiver `index`'s receiver.
fn receive_codings(
    transceivers: &[RTCRtpTransceiverInternal],
    index: usize,
) -> Vec<(Option<u32>, Option<u32>)> {
    transceivers[index]
        .receiver()
        .as_ref()
        .map(|receiver| {
            receiver
                .get_coding_parameters()
                .iter()
                .map(|coding| (coding.ssrc, coding.rtx.as_ref().map(|rtx| rtx.ssrc)))
                .collect()
        })
        .unwrap_or_default()
}

/// RFC 7160 section 4.1 (an SSRC per clock rate) and RFC 8834 section 4.3 (every negotiated
/// format accepted at any time): the source of a single-stream section moves to a new SSRC,
/// and the receiver's track follows it there. It is the same track: no second announcement.
#[test]
fn a_new_ssrc_takes_over_the_stream_of_a_single_stream_receiver() {
    let transceivers = vec![
        transceiver(RtpCodecKind::Audio, "0", vec![codec("audio/opus", OPUS)]),
        transceiver(RtpCodecKind::Video, "1", vec![codec("video/VP8", VP8)]),
    ];
    let (opened, transceivers) = opened(
        transceivers,
        &[
            Arrival {
                ssrc: 0xaaaa,
                payload_type: VP8,
                mid: Some("1"),
            },
            Arrival {
                ssrc: 0xbbbb,
                payload_type: VP8,
                mid: Some("1"),
            },
        ],
    );
    assert_eq!(opened, vec![(1, 0xaaaa)], "one track, announced once");
    assert_eq!(
        receive_codings(&transceivers, 1),
        vec![(Some(0xbbbb), None)]
    );
}

/// RFC 4588 section 5.3: "Upon reception of original RTP packets with a new SSRC, the
/// receiver MUST perform the SSRC association again". An RTX stream from an SSRC nothing
/// declared is associated, by its payload type (its `apt`) and its section, with the one
/// original stream of the section; after the original moved to a new SSRC, the RTX stream
/// from another new SSRC is associated with the new original. An RTX packet before any
/// original is not a stream of its own.
#[test]
fn a_retransmission_stream_is_associated_again_after_the_original_moved() {
    let rtx = RTCRtpCodecParameters {
        rtp_codec: RTCRtpCodec {
            mime_type: "video/rtx".to_owned(),
            clock_rate: 90_000,
            channels: 0,
            sdp_fmtp_line: format!("apt={VP8}"),
            rtcp_feedback: vec![],
        },
        payload_type: 97,
    };
    let video = || {
        vec![
            transceiver(RtpCodecKind::Audio, "0", vec![codec("audio/opus", OPUS)]),
            transceiver(
                RtpCodecKind::Video,
                "1",
                vec![codec("video/VP8", VP8), rtx.clone()],
            ),
        ]
    };
    let (announced, transceivers) = opened(
        video(),
        &[Arrival {
            ssrc: 0xcccc,
            payload_type: 97,
            mid: Some("1"),
        }],
    );
    assert!(announced.is_empty(), "{announced:?}");
    assert_eq!(receive_codings(&transceivers, 1), vec![]);

    let (announced, transceivers) = opened(
        video(),
        &[
            Arrival {
                ssrc: 0xaaaa,
                payload_type: VP8,
                mid: Some("1"),
            },
            Arrival {
                ssrc: 0xa0a0,
                payload_type: 97,
                mid: Some("1"),
            },
        ],
    );
    assert_eq!(announced, vec![(1, 0xaaaa)]);
    assert_eq!(
        receive_codings(&transceivers, 1),
        vec![(Some(0xaaaa), Some(0xa0a0))]
    );

    let (_, transceivers) = opened(
        video(),
        &[
            Arrival {
                ssrc: 0xaaaa,
                payload_type: VP8,
                mid: Some("1"),
            },
            Arrival {
                ssrc: 0xa0a0,
                payload_type: 97,
                mid: Some("1"),
            },
            Arrival {
                ssrc: 0xbbbb,
                payload_type: VP8,
                mid: Some("1"),
            },
            Arrival {
                ssrc: 0xb0b0,
                payload_type: 97,
                mid: Some("1"),
            },
        ],
    );
    assert_eq!(
        receive_codings(&transceivers, 1),
        vec![(Some(0xbbbb), Some(0xb0b0))],
        "the new RTX stream repairs the new original"
    );
}

/// The receiver of a track whose remote description declared the simulcast streams `ssrcs`
/// (RFC 5576 `a=ssrc-group:SIM`): one coding per stream.
fn declare_layers(transceiver: &mut RTCRtpTransceiverInternal, ssrcs: &[u32]) {
    let codings: Vec<RTCRtpCodingParameters> = ssrcs
        .iter()
        .map(|ssrc| RTCRtpCodingParameters {
            ssrc: Some(*ssrc),
            ..Default::default()
        })
        .collect();
    let receiver = transceiver.receiver_mut().as_mut().unwrap();
    receiver.set_coding_parameters(codings.clone());
    receiver.set_track(MediaStreamTrack::new(
        "stream".to_string(),
        "declared".to_string(),
        "label".to_string(),
        RtpCodecKind::Video,
        codings
            .into_iter()
            .map(|rtp_coding_parameters| RTCRtpEncodingParameters {
                rtp_coding_parameters,
                active: true,
                ..Default::default()
            })
            .collect(),
    ));
}

/// RFC 5576 section 4.2 (`a=ssrc-group:SIM`): the declared simulcast streams of a track are
/// received as its layers. Each stream's packets, without a MID, stay with the track's
/// receiver, and none takes over another's coding (RFC 7160 4.1's single-stream rule is for a
/// receiver of one stream).
#[test]
fn the_declared_streams_of_a_sim_group_are_layers_of_one_receiver() {
    let mut transceivers = vec![
        transceiver(RtpCodecKind::Video, "1", vec![codec("video/VP8", VP8)]),
        transceiver(RtpCodecKind::Video, "2", vec![codec("video/VP8", VP8)]),
    ];
    declare_layers(&mut transceivers[0], &[0x5101, 0x5102, 0x5103]);
    let arrival = |ssrc: u32| Arrival {
        ssrc,
        payload_type: VP8,
        mid: None,
    };
    let (_, after) = opened(
        transceivers,
        &[
            arrival(0x5101),
            arrival(0x5102),
            arrival(0x5103),
            arrival(0x5102),
        ],
    );
    assert_eq!(
        receive_codings(&after, 0),
        vec![
            (Some(0x5101), None),
            (Some(0x5102), None),
            (Some(0x5103), None)
        ]
    );
    assert_eq!(receive_codings(&after, 1), vec![]);
}
