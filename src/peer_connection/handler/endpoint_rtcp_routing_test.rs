//! RFC 3550 6.1: a compound RTCP packet is several packets in one datagram. Each one reaches
//! the application with the track it is about, wherever it stands in the compound packet.

use super::*;
use crate::media_stream::track::MediaStreamTrack;
use crate::rtp_transceiver::rtp_sender::{RTCRtpEncodingParameters, RtpCodecKind};
use crate::rtp_transceiver::{RTCRtpTransceiverDirection, RTCRtpTransceiverInit};
use rtcp::payload_feedbacks::full_intra_request::{FirEntry, FullIntraRequest};
use rtcp::payload_feedbacks::picture_loss_indication::PictureLossIndication;
use rtcp::receiver_report::ReceiverReport;
use rtcp::reception_report::ReceptionReport;
use rtcp::sender_report::SenderReport;
use rtcp::source_description::{
    SdesType, SourceDescription, SourceDescriptionChunk, SourceDescriptionItem,
};
use sansio::Protocol;

const LOCAL_AUDIO: u32 = 1111;
const LOCAL_VIDEO: u32 = 2222;
const REMOTE_AUDIO: u32 = 3333;
const REMOTE: u32 = 9999;

fn codec(kind: RtpCodecKind) -> RTCRtpCodec {
    RTCRtpCodec {
        mime_type: match kind {
            RtpCodecKind::Audio => "audio/opus".to_owned(),
            _ => "video/VP8".to_owned(),
        },
        clock_rate: 90000,
        channels: 0,
        sdp_fmtp_line: String::new(),
        rtcp_feedback: vec![],
    }
}

fn track(kind: RtpCodecKind, id: &str, ssrc: u32) -> MediaStreamTrack {
    MediaStreamTrack::new(
        "stream".to_string(),
        id.to_string(),
        "label".to_string(),
        kind,
        vec![RTCRtpEncodingParameters {
            rtp_coding_parameters: RTCRtpCodingParameters {
                rid: String::new(),
                ssrc: Some(ssrc),
                rtx: None,
                fec: None,
                ..Default::default()
            },
            active: true,
            codec: codec(kind),
            max_bitrate: 0,
            max_framerate: None,
            scale_resolution_down_by: None,
            priority: Default::default(),
            network_priority: None,
            scalability_mode: None,
            scale_resolution_down_to: None,
            ptime: None,
            adaptive_ptime: false,
        }],
    )
}

/// A transceiver that sends `id` from `ssrc`.
fn sender(kind: RtpCodecKind, id: &str, ssrc: u32) -> RTCRtpTransceiverInternal {
    RTCRtpTransceiverInternal::new(
        kind,
        Some(track(kind, id, ssrc)),
        RTCRtpTransceiverInit {
            direction: RTCRtpTransceiverDirection::Sendonly,
            streams: vec![],
            send_encodings: vec![],
        },
    )
}

/// A transceiver that receives `id` from `ssrc`.
fn receiver(kind: RtpCodecKind, id: &str, ssrc: u32) -> RTCRtpTransceiverInternal {
    let mut transceiver = RTCRtpTransceiverInternal::new(
        kind,
        None,
        RTCRtpTransceiverInit {
            direction: RTCRtpTransceiverDirection::Recvonly,
            streams: vec![],
            send_encodings: vec![],
        },
    );
    transceiver
        .receiver_mut()
        .as_mut()
        .unwrap()
        .set_track(track(kind, id, ssrc));
    transceiver
}

fn transceivers() -> Vec<RTCRtpTransceiverInternal> {
    vec![
        sender(RtpCodecKind::Audio, "local-audio", LOCAL_AUDIO),
        sender(RtpCodecKind::Video, "local-video", LOCAL_VIDEO),
        receiver(RtpCodecKind::Audio, "remote-audio", REMOTE_AUDIO),
    ]
}

fn sdes(source: u32) -> Box<dyn rtcp::Packet> {
    Box::new(SourceDescription {
        chunks: vec![SourceDescriptionChunk {
            source,
            items: vec![SourceDescriptionItem {
                sdes_type: SdesType::SdesCname,
                text: "peer".into(),
            }],
        }],
    })
}

fn pli(media_ssrc: u32) -> Box<dyn rtcp::Packet> {
    Box::new(PictureLossIndication {
        sender_ssrc: REMOTE,
        media_ssrc,
    })
}

/// What the application reads when `compound` arrives: each track id with the kinds of the
/// packets delivered for it.
fn delivered(compound: Vec<Box<dyn rtcp::Packet>>) -> Vec<(String, Vec<Box<dyn rtcp::Packet>>)> {
    let mut transceivers = transceivers();
    let mut stats = RTCStatsAccumulator::new();
    let mut ctx = EndpointHandlerContext::default();
    let mut handler = EndpointHandler::new(&mut ctx, &mut transceivers, &mut stats);
    handler
        .handle_read(TaggedRTCMessageInternal {
            now: Instant::now(),
            transport: TransportContext::default(),
            message: RTCMessageInternal::Rtp(RTPMessage::Packet(Packet::Rtcp(compound))),
        })
        .unwrap();
    std::iter::from_fn(|| handler.poll_read())
        .map(|message| match message.message {
            RTCMessageInternal::Rtp(RTPMessage::TrackPacket(TrackPacket {
                track_id,
                packet: Packet::Rtcp(packets),
            })) => (track_id.to_string(), packets),
            other => panic!("expected RTCP for a track, got {other:?}"),
        })
        .collect()
}

fn is<T: 'static>(packet: &dyn rtcp::Packet) -> bool {
    packet.as_any().is::<T>()
}

/// The compound packet a receive-only peer sends: an empty receiver report, its SDES, then
/// the feedback. The first packet names no stream at all.
#[test]
fn a_pli_behind_an_empty_receiver_report_reaches_its_sender() {
    let out = delivered(vec![
        Box::new(ReceiverReport {
            ssrc: REMOTE,
            ..Default::default()
        }),
        sdes(REMOTE),
        pli(LOCAL_VIDEO),
    ]);

    assert_eq!(1, out.len(), "one track is concerned: {out:?}");
    assert_eq!("local-video", out[0].0);
    assert_eq!(1, out[0].1.len());
    assert!(is::<PictureLossIndication>(out[0].1[0].as_ref()));
}

/// A report about the audio sender followed by a PLI for the video sender: each goes to its
/// own track, not both to the track of the first packet.
#[test]
fn a_pli_behind_a_report_about_another_stream_reaches_its_own_sender() {
    let out = delivered(vec![
        Box::new(ReceiverReport {
            ssrc: REMOTE,
            reports: vec![ReceptionReport {
                ssrc: LOCAL_AUDIO,
                ..Default::default()
            }],
            ..Default::default()
        }),
        sdes(REMOTE),
        pli(LOCAL_VIDEO),
    ]);

    assert_eq!(2, out.len(), "{out:?}");
    let audio = out.iter().find(|(id, _)| id == "local-audio").unwrap();
    assert_eq!(1, audio.1.len());
    assert!(is::<ReceiverReport>(audio.1[0].as_ref()));
    let video = out.iter().find(|(id, _)| id == "local-video").unwrap();
    assert_eq!(1, video.1.len());
    assert!(is::<PictureLossIndication>(video.1[0].as_ref()));
}

/// A sender report with a report block: the report is about the remote stream (the receiver's
/// track) and about the local stream its block names; the SDES goes with the remote stream.
#[test]
fn a_sender_report_goes_to_the_receiver_and_to_the_sender_it_reports_on() {
    let out = delivered(vec![
        Box::new(SenderReport {
            ssrc: REMOTE_AUDIO,
            reports: vec![ReceptionReport {
                ssrc: LOCAL_VIDEO,
                ..Default::default()
            }],
            ..Default::default()
        }),
        sdes(REMOTE_AUDIO),
    ]);

    assert_eq!(2, out.len(), "{out:?}");
    let remote = out.iter().find(|(id, _)| id == "remote-audio").unwrap();
    assert_eq!(2, remote.1.len());
    assert!(is::<SenderReport>(remote.1[0].as_ref()));
    assert!(is::<SourceDescription>(remote.1[1].as_ref()));
    let video = out.iter().find(|(id, _)| id == "local-video").unwrap();
    assert_eq!(1, video.1.len());
    assert!(is::<SenderReport>(video.1[0].as_ref()));
}

/// RFC 5104 4.3.1: one FIR can name several senders in its FCI; each is told.
#[test]
fn a_fir_for_two_senders_reaches_both() {
    let out = delivered(vec![Box::new(FullIntraRequest {
        sender_ssrc: REMOTE,
        media_ssrc: 0,
        fir: vec![
            FirEntry {
                ssrc: LOCAL_VIDEO,
                sequence_number: 1,
            },
            FirEntry {
                ssrc: LOCAL_AUDIO,
                sequence_number: 1,
            },
        ],
    })]);

    let mut tracks: Vec<&str> = out.iter().map(|(id, _)| id.as_str()).collect();
    tracks.sort_unstable();
    assert_eq!(vec!["local-audio", "local-video"], tracks);
}

/// RFC 5104 4.3.1 and the AV1 RTP specification 8.1: a FIR asks each sender its FCI names
/// for a decoder refresh. It reaches the encoder of the local video sender it names and of no
/// other: not the audio sender, not a sender for an SSRC this side does not have.
#[test]
fn a_fir_reaches_only_the_senders_its_fci_names() {
    let out = delivered(vec![Box::new(FullIntraRequest {
        sender_ssrc: REMOTE,
        media_ssrc: 0,
        fir: vec![
            FirEntry {
                ssrc: 424242,
                sequence_number: 3,
            },
            FirEntry {
                ssrc: LOCAL_VIDEO,
                sequence_number: 3,
            },
        ],
    })]);

    let tracks: Vec<&str> = out.iter().map(|(id, _)| id.as_str()).collect();
    assert_eq!(vec!["local-video"], tracks, "{out:?}");
    assert!(is::<FullIntraRequest>(out[0].1[0].as_ref()));
}

#[test]
fn a_compound_packet_about_no_known_stream_is_not_delivered() {
    let out = delivered(vec![
        Box::new(ReceiverReport {
            ssrc: REMOTE,
            ..Default::default()
        }),
        sdes(REMOTE),
        pli(424242),
    ]);
    assert!(out.is_empty(), "{out:?}");
}

/// RFC 7587 section 4.1: a receiver "MUST be prepared to receive duplicate RTP packets" and
/// hands at most one copy on. A packet that arrives a second time (here the original after
/// its retransmission had already been taken out of its RTX packet, both reaching the
/// endpoint as the primary stream's sequence number) reaches the application once; packets
/// after it, and one far behind the window, still go through.
#[test]
fn a_packet_arriving_twice_reaches_the_application_once() {
    let mut transceivers = transceivers();
    let mut stats = RTCStatsAccumulator::new();
    let mut ctx = EndpointHandlerContext::default();
    let mut handler = EndpointHandler::new(&mut ctx, &mut transceivers, &mut stats);
    let mut send = |sequence_number: u16| {
        handler
            .handle_read(TaggedRTCMessageInternal {
                now: Instant::now(),
                transport: TransportContext::default(),
                message: RTCMessageInternal::Rtp(RTPMessage::Packet(Packet::Rtp(rtp::Packet {
                    header: rtp::header::Header {
                        version: 2,
                        ssrc: REMOTE_AUDIO,
                        sequence_number,
                        payload_type: 111,
                        ..Default::default()
                    },
                    payload: vec![1u8; 10].into(),
                }))),
            })
            .unwrap();
        std::iter::from_fn(|| handler.poll_read())
            .filter(|m| {
                matches!(
                    m.message,
                    RTCMessageInternal::Rtp(RTPMessage::TrackPacket(TrackPacket {
                        packet: Packet::Rtp(_),
                        ..
                    }))
                )
            })
            .count()
    };
    assert_eq!(send(10), 1);
    assert_eq!(send(12), 1);
    assert_eq!(send(11), 1, "a late packet is not a duplicate");
    assert_eq!(send(11), 0, "the second copy is dropped");
    assert_eq!(send(10), 0);
    assert_eq!(send(13), 1);
    assert_eq!(send(13u16.wrapping_add(5000)), 1);
    assert_eq!(send(13), 1, "older than the window: let through");
}
