//! RFC 9143 section 9.2 in an m= section with `a=rid`: the section also declares its streams by
//! SSRC (`a=ssrc`, `a=ssrc-group:FID`), as Firefox and Pion write it. A packet that carries a
//! RID is bound by its rid, as without the declaration; a packet of a declared SSRC that
//! carries no RID is a stream of the section without a rid, with its declared RTX.
//!
//! The receiver is the one `start_rtp` builds from Firefox 152's simulcast offer
//! (`tests/fixtures/browser-sdp`), answered by this engine.

use super::*;
use crate::peer_connection::event::RTCTrackEvent;
use crate::peer_connection::sdp::RTCSessionDescription;
use crate::peer_connection::{RTCPeerConnection, RTCPeerConnectionBuilder};
use crate::rtp_transceiver::rtp_sender::RtpCodecKind;
use bytes::Bytes;
use sansio::Protocol as _;
use shared::TransportContext;

const FIREFOX_OFFER: &str = include_str!(
    "../../../tests/fixtures/browser-sdp/firefox-152--simulcast-three-rids-send--1-offer.sdp"
);

/// The offer's `a=ssrc-group:FID` lines (media, RTX) and its VP8 and VP8-RTX payload types.
const FID: [(u32, u32); 3] = [
    (1730948, 819241208),
    (3146512205, 3191782974),
    (1708365952, 4160432598),
];
const VP8: u8 = 120;
const VP8_RTX: u8 = 124;

/// An engine that answered Firefox's offer: `start_rtp` has set up the video receiver.
fn answered_firefox() -> RTCPeerConnection {
    let mut media_engine = MediaEngine::default();
    media_engine.register_default_codecs().expect("codecs");
    for uri in [
        ::sdp::extmap::SDES_MID_URI,
        ::sdp::extmap::SDES_RTP_STREAM_ID_URI,
        ::sdp::extmap::SDES_REPAIR_RTP_STREAM_ID_URI,
    ] {
        media_engine
            .register_header_extension(
                RTCRtpHeaderExtensionCapability {
                    uri: uri.to_owned(),
                },
                RtpCodecKind::Video,
                None,
            )
            .expect("extension");
    }
    let now = Instant::now();
    let mut pc = RTCPeerConnectionBuilder::new()
        .with_media_engine(media_engine)
        .build(now)
        .expect("peer connection");
    let offer = FIREFOX_OFFER.replace("\r\n", "\n").replace('\n', "\r\n");
    pc.set_remote_description(now, RTCSessionDescription::offer(offer).expect("offer"))
        .expect("set_remote_description");
    let answer = pc.create_answer(None).expect("answer");
    pc.set_local_description(now, answer)
        .expect("set_local_description");
    pc
}

struct Arrival {
    ssrc: u32,
    payload_type: u8,
    mid: Option<&'static str>,
    rid: Option<&'static str>,
}

/// Feeds `arrivals` through the interceptor handler; returns the SSRC and rid of each stream
/// that opened.
fn opened(pc: &mut RTCPeerConnection, arrivals: &[Arrival]) -> Vec<(u32, Option<String>)> {
    let id = |pc: &RTCPeerConnection, uri: &str| {
        let (id, _, video) =
            pc.media_engine
                .get_header_extension_id(RTCRtpHeaderExtensionCapability {
                    uri: uri.to_owned(),
                });
        assert!(video && id != 0, "{uri} is negotiated");
        id as u8
    };
    let mid_id = id(pc, ::sdp::extmap::SDES_MID_URI);
    let rid_id = id(pc, ::sdp::extmap::SDES_RTP_STREAM_ID_URI);
    pc.pipeline_context
        .interceptor_handler_context
        .is_dtls_handshake_complete = true;
    let mut handler = pc.get_interceptor_handler();
    let now = Instant::now();
    for (n, arrival) in arrivals.iter().enumerate() {
        let mut header = rtp::Header {
            version: 2,
            payload_type: arrival.payload_type,
            sequence_number: 100 + n as u16,
            timestamp: 1000,
            ssrc: arrival.ssrc,
            ..Default::default()
        };
        // A retransmission's payload starts with the original sequence number (RFC 4588 4).
        let payload = if arrival.payload_type == VP8_RTX {
            Bytes::from_static(&[0, 100, 1, 2, 3])
        } else {
            Bytes::from_static(&[1, 2, 3])
        };
        for (extension, value) in [(mid_id, arrival.mid), (rid_id, arrival.rid)] {
            if let Some(value) = value {
                header
                    .set_extension(extension, Bytes::from_static(value.as_bytes()))
                    .expect("extension");
            }
        }
        handler
            .handle_read(TaggedRTCMessageInternal {
                now,
                transport: TransportContext::default(),
                message: RTCMessageInternal::Rtp(RTPMessage::Packet(Packet::Rtp(rtp::Packet {
                    header,
                    payload,
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
            opened.push((init.ssrc, init.rid));
        }
    }
    opened
}

/// The video receiver's codings: (rid, SSRC, RTX SSRC).
fn video_codings(pc: &RTCPeerConnection) -> Vec<(String, Option<u32>, Option<u32>)> {
    let transceiver = pc
        .rtp_transceivers
        .iter()
        .find(|t| t.kind() == RtpCodecKind::Video)
        .expect("video transceiver");
    transceiver
        .receiver()
        .as_ref()
        .expect("receiver")
        .get_coding_parameters()
        .iter()
        .map(|c| (c.rid.clone(), c.ssrc, c.rtx.as_ref().map(|r| r.ssrc)))
        .collect()
}

/// The receiver keeps the SSRCs Firefox's offer declares beside its rids, with their FID
/// pairs; they are not codings: the rid codings stay as they were, waiting for their SSRC.
#[test]
fn a_firefox_rid_section_keeps_its_declared_ssrcs_beside_the_rid_codings() {
    let pc = answered_firefox();
    let transceiver = pc
        .rtp_transceivers
        .iter()
        .find(|t| t.kind() == RtpCodecKind::Video)
        .expect("video transceiver");
    let receiver = transceiver.receiver().as_ref().expect("receiver");
    let declared: Vec<(Option<u32>, Option<u32>)> = receiver
        .declared_codings()
        .iter()
        .map(|c| (c.ssrc, c.rtx.as_ref().map(|r| r.ssrc)))
        .collect();
    assert_eq!(
        FID.iter()
            .map(|(media, rtx)| (Some(*media), Some(*rtx)))
            .collect::<Vec<_>>(),
        declared
    );
    assert_eq!(
        vec![
            ("h".to_owned(), None, None),
            ("m".to_owned(), None, None),
            ("l".to_owned(), None, None),
        ],
        video_codings(&pc)
    );
}

/// Firefox writes MID and RID on its layers: each declared SSRC is bound by the rid its packet
/// carries, never as a stream without a rid.
#[test]
fn a_firefox_layer_that_carries_its_rid_is_bound_by_rid_not_by_its_declared_ssrc() {
    let mut pc = answered_firefox();
    let arrivals: Vec<Arrival> = FID
        .iter()
        .zip(["h", "m", "l"])
        .map(|((media, _), rid)| Arrival {
            ssrc: *media,
            payload_type: VP8,
            mid: Some("0"),
            rid: Some(rid),
        })
        .collect();
    let opened = opened(&mut pc, &arrivals);
    assert_eq!(
        vec![
            (FID[0].0, Some("h".to_owned())),
            (FID[1].0, Some("m".to_owned())),
            (FID[2].0, Some("l".to_owned())),
        ],
        opened
    );
    assert_eq!(
        vec![
            ("h".to_owned(), Some(FID[0].0), None),
            ("m".to_owned(), Some(FID[1].0), None),
            ("l".to_owned(), Some(FID[2].0), None),
        ],
        video_codings(&pc),
        "no coding without a rid"
    );
}

/// RFC 9143 section 9.2: a packet of a declared SSRC with no MID or RID is the section's
/// stream, without a rid (none is guessed from the order of the `a=ssrc` lines), with its
/// declared RTX; a later packet with a RID for another layer still binds by rid.
#[test]
fn a_declared_ssrc_without_mid_or_rid_is_a_stream_of_its_section_without_a_rid() {
    let mut pc = answered_firefox();
    let opened = opened(
        &mut pc,
        &[
            Arrival {
                ssrc: FID[2].0,
                payload_type: VP8,
                mid: None,
                rid: None,
            },
            Arrival {
                ssrc: FID[0].0,
                payload_type: VP8,
                mid: Some("0"),
                rid: Some("h"),
            },
        ],
    );
    assert_eq!(
        vec![(FID[2].0, None), (FID[0].0, Some("h".to_owned()))],
        opened
    );
    assert_eq!(
        vec![
            ("h".to_owned(), Some(FID[0].0), None),
            ("m".to_owned(), None, None),
            ("l".to_owned(), None, None),
            (String::new(), Some(FID[2].0), Some(FID[2].1)),
        ],
        video_codings(&pc)
    );
}

/// A retransmission from a declared RTX SSRC that arrives before its stream establishes the
/// stream it repairs (its FID primary), and is not discarded as unassociated.
#[test]
fn a_declared_rtx_ssrc_without_a_rid_resolves_to_its_primary() {
    let mut pc = answered_firefox();
    let opened = opened(
        &mut pc,
        &[Arrival {
            ssrc: FID[1].1,
            payload_type: VP8_RTX,
            mid: None,
            rid: None,
        }],
    );
    assert_eq!(vec![(FID[1].0, None)], opened);
    assert!(
        video_codings(&pc).contains(&(String::new(), Some(FID[1].0), Some(FID[1].1))),
        "{:?}",
        video_codings(&pc)
    );
}
