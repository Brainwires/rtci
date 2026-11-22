//! The peer connection's side of the RTCP session: it starts when DTLS is up under the
//! connection's CNAME, wraps what the application writes, says BYE on close, and is told what
//! a retransmission was on the wire.

use super::*;
use crate::media_stream::track::MediaStreamTrack;
use crate::peer_connection::configuration::interceptor_registry::register_default_interceptors;
use crate::peer_connection::configuration::media_engine::MIME_TYPE_RTX;
use crate::rtp_transceiver::rtp_sender::{
    RTCPFeedback, RTCRtpCodec, RTCRtpCodecParameters, RTCRtpEncodingParameters, RtpCodecKind,
};
use crate::rtp_transceiver::{RTCRtpTransceiverDirection, RTCRtpTransceiverInit};
use bytes::Bytes;
use interceptor::{Registry, StreamInfo};
use rtcp::payload_feedbacks::picture_loss_indication::PictureLossIndication;
use rtcp::reception_report::ReceptionReport;
use sansio::Protocol as _;
use shared::TransportContext;

const SSRC: u32 = 1000;
const RTX_SSRC: u32 = 2000;
const LOCAL_SSRC: u32 = 3000;
const PT: u8 = 96;
const RTX_PT: u8 = 97;

fn vp8() -> RTCRtpCodecParameters {
    RTCRtpCodecParameters {
        rtp_codec: RTCRtpCodec {
            mime_type: "video/VP8".to_owned(),
            clock_rate: 90_000,
            channels: 0,
            sdp_fmtp_line: String::new(),
            rtcp_feedback: vec![RTCPFeedback {
                typ: "nack".to_owned(),
                parameter: String::new(),
            }],
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

fn coding(ssrc: u32, rtx: Option<u32>) -> RTCRtpCodingParameters {
    RTCRtpCodingParameters {
        rid: String::new(),
        ssrc: Some(ssrc),
        rtx: rtx.map(|ssrc| RTCRtpRtxParameters { ssrc }),
        fec: None,
        ..Default::default()
    }
}

fn track(id: &str, coding: RTCRtpCodingParameters, codec: RTCRtpCodec) -> MediaStreamTrack {
    MediaStreamTrack::new(
        "stream".to_string(),
        id.to_string(),
        "label".to_string(),
        RtpCodecKind::Video,
        vec![RTCRtpEncodingParameters {
            rtp_coding_parameters: coding,
            active: true,
            codec,
            max_bitrate: 0,
            max_framerate: None,
            scale_resolution_down_by: None,
            priority: Default::default(),
            network_priority: None,
        }],
    )
}

/// A receiver for a remote stream declared with an RTX flow (`a=ssrc-group:FID`).
fn receiver() -> RTCRtpTransceiverInternal {
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
    receiver.set_coding_parameters(vec![coding(SSRC, Some(RTX_SSRC))]);
    receiver.set_codec_preferences(vec![vp8(), rtx()]);
    receiver.set_track(track(
        "remote",
        coding(SSRC, Some(RTX_SSRC)),
        RTCRtpCodec::default(),
    ));
    transceiver
}

/// A transceiver that sends from `LOCAL_SSRC`.
fn sender() -> RTCRtpTransceiverInternal {
    RTCRtpTransceiverInternal::new(
        RtpCodecKind::Video,
        Some(track("local", coding(LOCAL_SSRC, None), vp8().rtp_codec)),
        RTCRtpTransceiverInit {
            direction: RTCRtpTransceiverDirection::Sendonly,
            streams: vec![],
            send_encodings: vec![],
        },
    )
}

/// The default interceptors and the media engine they were registered on.
fn defaults() -> (MediaEngine, Registry) {
    let mut media_engine = MediaEngine::default();
    media_engine
        .register_codec(vp8(), RtpCodecKind::Video)
        .expect("vp8");
    media_engine
        .register_codec(rtx(), RtpCodecKind::Video)
        .expect("rtx");
    let registry =
        register_default_interceptors(Registry::new(), &mut media_engine).expect("interceptors");
    (media_engine, registry)
}

fn handshake_complete(now: Instant) -> TaggedRTCEventInternal {
    TaggedRTCEventInternal {
        now,
        event: RTCEventInternal::DTLSHandshakeComplete(None, None),
    }
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

fn rtcp(now: Instant, packets: Vec<Box<dyn rtcp::Packet>>) -> TaggedRTCMessageInternal {
    TaggedRTCMessageInternal {
        now,
        transport: TransportContext::default(),
        message: RTCMessageInternal::Rtp(RTPMessage::Packet(Packet::Rtcp(packets))),
    }
}

/// The RTCP datagrams the handler writes while its timers run up to `until`.
fn run(handler: &mut InterceptorHandler<'_>, until: Instant) -> Vec<Vec<Box<dyn rtcp::Packet>>> {
    let mut out = vec![];
    let mut drain = |handler: &mut InterceptorHandler<'_>| {
        while let Some(message) = handler.poll_write() {
            if let RTCMessageInternal::Rtp(RTPMessage::Packet(Packet::Rtcp(packets))) =
                message.message
            {
                assert!(!packets.is_empty(), "an empty RTCP packet left the handler");
                out.push(packets);
            }
        }
    };
    drain(handler);
    for _ in 0..10_000 {
        match handler.poll_timeout() {
            Some(at) if at <= until => {
                handler.handle_timeout(at).expect("handle_timeout");
                drain(handler);
            }
            _ => break,
        }
    }
    handler.handle_timeout(until).expect("handle_timeout");
    drain(handler);
    out
}

fn cname_of(packets: &[Box<dyn rtcp::Packet>]) -> Vec<(u32, String)> {
    packets
        .iter()
        .filter_map(|packet| packet.as_any().downcast_ref::<SourceDescription>())
        .flat_map(|sdes| &sdes.chunks)
        .map(|chunk| {
            (
                chunk.source,
                String::from_utf8(chunk.items[0].text.to_vec()).unwrap(),
            )
        })
        .collect()
}

fn reporter_of(packets: &[Box<dyn rtcp::Packet>]) -> Option<u32> {
    let first = packets.first()?.as_any();
    first
        .downcast_ref::<SenderReport>()
        .map(|sr| sr.ssrc)
        .or_else(|| first.downcast_ref::<ReceiverReport>().map(|rr| rr.ssrc))
}

/// RFC 3550 6.2, RFC 5506 4, RFC 8834 4.9: a connection that receives nothing still sends
/// compound RTCP once DTLS is up, under the connection's CNAME, from an SSRC that is not zero.
#[test]
fn the_session_starts_with_dtls_under_the_connections_cname() {
    let (media_engine, registry) = defaults();
    let mut chain = registry.build();
    let mut transceivers = vec![receiver()];
    let mut stats = RTCStatsAccumulator::new();
    let mut ctx = InterceptorHandlerContext::default();
    let cname = ctx.cname.clone();
    assert_eq!(16, cname.len(), "RFC 7022: 96 bits in Base64");
    let mut handler = InterceptorHandler::new(
        &mut ctx,
        &mut transceivers,
        &media_engine,
        &mut chain,
        &mut stats,
    );

    let base = Instant::now();
    assert!(handler.poll_timeout().is_none());
    handler.handle_event(handshake_complete(base)).unwrap();

    let sent = run(&mut handler, base + Duration::from_secs(3));
    assert!(sent.len() >= 2, "{} RTCP packets", sent.len());
    let reporter = reporter_of(&sent[0]).expect("a compound packet");
    assert_ne!(0, reporter);
    for packets in &sent {
        assert_eq!(Some(reporter), reporter_of(packets));
        assert_eq!(vec![(reporter, cname.clone())], cname_of(packets));
    }
}

/// Two connections do not share a CNAME (RFC 7022 section 5: random).
#[test]
fn every_connection_has_its_own_cname() {
    assert_ne!(
        InterceptorHandlerContext::default().cname,
        InterceptorHandlerContext::default().cname
    );
}

/// RFC 4585 3.1 / RFC 8834 4.6: feedback the application writes leaves compound (reduced-size
/// RTCP is not assumed), from the connection's reporting SSRC whatever the application put.
#[test]
fn feedback_the_application_writes_leaves_in_a_compound_packet() {
    let (media_engine, registry) = defaults();
    let mut chain = registry.build();
    let mut transceivers = vec![receiver()];
    let mut stats = RTCStatsAccumulator::new();
    let mut ctx = InterceptorHandlerContext::default();
    let mut handler = InterceptorHandler::new(
        &mut ctx,
        &mut transceivers,
        &media_engine,
        &mut chain,
        &mut stats,
    );
    let base = Instant::now();
    handler.handle_event(handshake_complete(base)).unwrap();

    handler
        .handle_write(rtcp(
            base + Duration::from_millis(10),
            vec![Box::new(PictureLossIndication {
                sender_ssrc: 0,
                media_ssrc: SSRC,
            })],
        ))
        .unwrap();
    let sent = run(&mut handler, base + Duration::from_millis(10));
    assert_eq!(1, sent.len());
    let packets = &sent[0];
    assert_eq!(3, packets.len());
    let reporter = reporter_of(packets).expect("a report first");
    assert!(packets[1].as_any().is::<SourceDescription>());
    let pli = packets[2]
        .as_any()
        .downcast_ref::<PictureLossIndication>()
        .expect("the PLI last");
    assert_eq!(reporter, pli.sender_ssrc);
    assert_eq!(SSRC, pli.media_ssrc);
}

/// RFC 3550 6.6: closing the connection says BYE for the SSRCs it used.
#[test]
fn closing_says_bye() {
    let (media_engine, registry) = defaults();
    let mut chain = registry.build();
    let mut transceivers = vec![receiver()];
    let mut stats = RTCStatsAccumulator::new();
    let mut ctx = InterceptorHandlerContext::default();
    let mut handler = InterceptorHandler::new(
        &mut ctx,
        &mut transceivers,
        &media_engine,
        &mut chain,
        &mut stats,
    );
    let base = Instant::now();
    handler.handle_event(handshake_complete(base)).unwrap();
    let sent = run(&mut handler, base + Duration::from_secs(1));
    let reporter = reporter_of(&sent[0]).unwrap();

    handler.request_goodbye(base + Duration::from_secs(1));
    let mut farewell = vec![];
    while let Some(message) = handler.poll_write() {
        if let RTCMessageInternal::Rtp(RTPMessage::Packet(Packet::Rtcp(packets))) = message.message
        {
            farewell.push(packets);
        }
    }
    assert_eq!(1, farewell.len());
    let goodbye = farewell[0]
        .last()
        .unwrap()
        .as_any()
        .downcast_ref::<Goodbye>()
        .expect("a BYE, last in its compound packet");
    assert_eq!(vec![reporter], goodbye.sources);
    assert_eq!(Some(reporter), reporter_of(&farewell[0]));

    // Nothing is said after it.
    assert!(run(&mut handler, base + Duration::from_secs(10)).is_empty());
}

/// RFC 4588 6.2 / section 3: a retransmission is de-encapsulated for the chain and the
/// application, and counted on the RTX stream it arrived on: the receiver report on the
/// original stream keeps the loss the path had.
#[test]
fn a_retransmission_is_reported_on_the_rtx_stream() {
    let (media_engine, registry) = defaults();
    let mut chain = registry.build();
    let mut transceivers = vec![receiver()];
    let mut stats = RTCStatsAccumulator::new();
    let mut ctx = InterceptorHandlerContext::default();
    let mut handler = InterceptorHandler::new(
        &mut ctx,
        &mut transceivers,
        &media_engine,
        &mut chain,
        &mut stats,
    );
    let base = Instant::now();
    handler.handle_event(handshake_complete(base)).unwrap();

    for sequence_number in [1u16, 2, 4] {
        handler
            .handle_read(rtp(base, SSRC, PT, sequence_number, &[0xDE, 0xAD]))
            .unwrap();
    }
    // Sequence number 3 again, on the RTX stream: OSN 3, then the payload.
    handler
        .handle_read(rtp(base, RTX_SSRC, RTX_PT, 500, &[0x00, 0x03, 0xDE, 0xAD]))
        .unwrap();
    let mut delivered = vec![];
    while let Some(message) = handler.poll_read() {
        if let RTCMessageInternal::Rtp(RTPMessage::Packet(Packet::Rtp(packet))) = message.message {
            delivered.push((packet.header.ssrc, packet.header.sequence_number));
        }
    }
    assert_eq!(
        vec![(SSRC, 1), (SSRC, 2), (SSRC, 4), (SSRC, 3)],
        delivered,
        "the application gets the repaired packet as the original"
    );

    let sent = run(&mut handler, base + Duration::from_secs(1));
    let blocks: Vec<ReceptionReport> = sent
        .iter()
        .flat_map(|packets| packets.iter())
        .filter_map(|packet| packet.as_any().downcast_ref::<ReceiverReport>())
        .flat_map(|rr| rr.reports.clone())
        .collect();
    let primary = blocks.iter().find(|block| block.ssrc == SSRC).unwrap();
    assert_eq!(4, primary.last_sequence_number);
    assert_eq!(1, primary.cumulative_lost());
    let repair = blocks.iter().find(|block| block.ssrc == RTX_SSRC).unwrap();
    assert_eq!(500, repair.last_sequence_number);
    assert_eq!(0, repair.cumulative_lost());
}

/// RFC 3550 6.5.1: the CNAME a remote source names is kept for the connection.
#[test]
fn a_remote_cname_is_recorded() {
    let (media_engine, registry) = defaults();
    let mut chain = registry.build();
    let mut transceivers = vec![receiver()];
    let mut stats = RTCStatsAccumulator::new();
    let mut ctx = InterceptorHandlerContext::default();
    {
        let mut handler = InterceptorHandler::new(
            &mut ctx,
            &mut transceivers,
            &media_engine,
            &mut chain,
            &mut stats,
        );
        let base = Instant::now();
        handler.handle_event(handshake_complete(base)).unwrap();
        handler
            .handle_read(rtcp(
                base,
                vec![Box::new(SourceDescription {
                    chunks: vec![SourceDescriptionChunk {
                        source: SSRC,
                        items: vec![SourceDescriptionItem {
                            sdes_type: SdesType::SdesCname,
                            text: "the-peer".into(),
                        }],
                    }],
                })],
            ))
            .unwrap();
        while handler.poll_read().is_some() {}
    }
    assert_eq!(
        Some("the-peer"),
        ctx.remote_cnames.get(&SSRC).map(String::as_str)
    );
}

/// RFC 3550 8.2: a remote source using a sender's SSRC is reported to the application once,
/// and its packets are not delivered.
#[test]
fn a_collision_with_a_sender_ssrc_reaches_the_application() {
    let (media_engine, registry) = defaults();
    let mut chain = registry.build();
    chain.bind_local_stream(&StreamInfo {
        ssrc: LOCAL_SSRC,
        clock_rate: 90_000,
        mime_type: "video/VP8".to_owned(),
        payload_type: PT,
        ..Default::default()
    });
    let mut transceivers = vec![sender()];
    let mut stats = RTCStatsAccumulator::new();
    let mut ctx = InterceptorHandlerContext::default();
    let mut handler = InterceptorHandler::new(
        &mut ctx,
        &mut transceivers,
        &media_engine,
        &mut chain,
        &mut stats,
    );
    let base = Instant::now();
    handler.handle_event(handshake_complete(base)).unwrap();

    for sequence_number in 1..=3u16 {
        handler
            .handle_read(rtp(base, LOCAL_SSRC, PT, sequence_number, &[1, 2]))
            .unwrap();
    }
    assert!(handler.poll_read().is_none(), "the packets are dropped");

    let collisions: Vec<SSRC> = std::iter::from_fn(|| handler.poll_event())
        .filter_map(|event| match event.event {
            RTCEventInternal::RTCPeerConnectionEvent(RTCPeerConnectionEvent::OnSsrcCollision(
                ssrc,
            )) => Some(ssrc),
            _ => None,
        })
        .collect();
    assert_eq!(vec![LOCAL_SSRC], collisions);
}
