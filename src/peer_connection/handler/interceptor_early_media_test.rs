//! Streams that arrive while this endpoint's offer is pending (RFC 3264 section 5.1, RFC 9429
//! sections 4.1.11 and 5.9): what they are bound to the interceptors with before the answer,
//! what the answer and a rollback do to those bindings, and what a flood of unknown SSRCs can
//! make the receiver keep.

use super::*;
use crate::rtp_transceiver::rtp_sender::{
    RTCPFeedback, RTCRtpCodec, RTCRtpCodecParameters, RtpCodecKind,
};
use crate::rtp_transceiver::{RTCRtpTransceiverDirection, RTCRtpTransceiverInit};
use bytes::Bytes;
use interceptor::StreamInfo;
use sansio::Protocol as _;
use shared::TransportContext;
use std::sync::{Arc, Mutex};

const VP8: u8 = 96;
const VP8_RTX: u8 = 97;
const VP9: u8 = 98;
const MID_ID: u16 = 4;

fn nack() -> RTCPFeedback {
    RTCPFeedback {
        typ: "nack".to_owned(),
        parameter: String::new(),
    }
}

fn codec(
    mime_type: &str,
    payload_type: u8,
    fmtp: &str,
    feedback: &[RTCPFeedback],
) -> RTCRtpCodecParameters {
    RTCRtpCodecParameters {
        rtp_codec: RTCRtpCodec {
            mime_type: mime_type.to_owned(),
            clock_rate: 90_000,
            channels: 0,
            sdp_fmtp_line: fmtp.to_owned(),
            rtcp_feedback: feedback.to_vec(),
        },
        payload_type,
    }
}

/// The formats an offer lists for a video section: VP8 with NACK, its RTX, and VP9.
fn offered_formats() -> Vec<RTCRtpCodecParameters> {
    vec![
        codec("video/VP8", VP8, "", &[nack()]),
        codec("video/rtx", VP8_RTX, "apt=96", &[]),
        codec("video/VP9", VP9, "", &[nack()]),
    ]
}

/// A media engine with those formats registered (NACK on the media formats), nothing
/// negotiated.
fn media_engine() -> MediaEngine {
    let mut media_engine = MediaEngine::default();
    for format in offered_formats() {
        media_engine
            .register_codec(format, RtpCodecKind::Video)
            .expect("codec");
    }
    media_engine
}

/// What the interceptors were told, in order: (`true` for a bind, the stream).
#[derive(Clone, Default)]
struct Recorder {
    calls: Arc<Mutex<Vec<(bool, StreamInfo)>>>,
}

impl Recorder {
    fn calls(&self) -> Vec<(bool, StreamInfo)> {
        self.calls.lock().unwrap().clone()
    }

    /// The streams bound and not unbound since, by SSRC.
    fn bound(&self) -> Vec<StreamInfo> {
        let mut bound: Vec<StreamInfo> = vec![];
        for (bind, info) in self.calls() {
            bound.retain(|b| b.ssrc != info.ssrc);
            if bind {
                bound.push(info);
            }
        }
        bound
    }
}

impl sansio::Protocol<TaggedPacket, TaggedPacket, ()> for Recorder {
    type Rout = TaggedPacket;
    type Wout = TaggedPacket;
    type Eout = ();
    type Error = Error;
    type Time = Instant;

    fn handle_read(&mut self, _msg: TaggedPacket) -> Result<()> {
        Ok(())
    }
    fn poll_read(&mut self) -> Option<Self::Rout> {
        None
    }
    fn handle_write(&mut self, _msg: TaggedPacket) -> Result<()> {
        Ok(())
    }
    fn poll_write(&mut self) -> Option<Self::Wout> {
        None
    }
    fn handle_timeout(&mut self, _now: Instant) -> Result<()> {
        Ok(())
    }
    fn poll_timeout(&mut self) -> Option<Instant> {
        None
    }
}

impl Interceptor for Recorder {
    fn bind_local_stream(&mut self, _info: &StreamInfo) {}
    fn unbind_local_stream(&mut self, _info: &StreamInfo) {}
    fn bind_remote_stream(&mut self, info: &StreamInfo) {
        self.calls.lock().unwrap().push((true, info.clone()));
    }
    fn unbind_remote_stream(&mut self, info: &StreamInfo) {
        self.calls.lock().unwrap().push((false, info.clone()));
    }
}

/// One video transceiver with mid "1", a handler context that keeps its state between
/// packets, and the recording interceptor.
struct Rig {
    transceivers: Vec<RTCRtpTransceiverInternal>,
    media_engine: MediaEngine,
    ctx: InterceptorHandlerContext,
    stats: RTCStatsAccumulator,
    recorder: Recorder,
}

impl Rig {
    fn new() -> Self {
        let mut transceiver = RTCRtpTransceiverInternal::new(
            RtpCodecKind::Video,
            None,
            RTCRtpTransceiverInit {
                direction: RTCRtpTransceiverDirection::Recvonly,
                streams: vec![],
                send_encodings: vec![],
            },
        );
        transceiver.set_mid("1".to_owned()).expect("mid");
        Self {
            transceivers: vec![transceiver],
            media_engine: media_engine(),
            ctx: InterceptorHandlerContext {
                is_dtls_handshake_complete: true,
                ..Default::default()
            },
            stats: RTCStatsAccumulator::new(),
            recorder: Recorder::default(),
        }
    }

    fn receiver(&mut self) -> &mut RTCRtpReceiverInternal {
        self.transceivers[0].receiver_mut().as_mut().unwrap()
    }

    /// The local offer is applied: the section's formats, for a section never answered.
    fn offer(&mut self) {
        self.receiver().set_offered(offered_formats(), false);
    }

    /// One packet arrives, with the MID header extension under `mid_id` when given.
    fn arrive(&mut self, ssrc: u32, payload_type: u8, sequence_number: u16, mid_id: Option<u16>) {
        let mut header = rtp::Header {
            version: 2,
            payload_type,
            sequence_number,
            timestamp: 3000 * u32::from(sequence_number),
            ssrc,
            ..Default::default()
        };
        if let Some(id) = mid_id {
            header
                .set_extension(id as u8, Bytes::from_static(b"1"))
                .expect("mid extension");
        }
        let mut handler = InterceptorHandler::new(
            &mut self.ctx,
            &mut self.transceivers,
            &self.media_engine,
            &mut self.recorder,
            &mut self.stats,
            None,
        );
        handler
            .handle_read(TaggedRTCMessageInternal {
                now: Instant::now(),
                transport: TransportContext::default(),
                message: RTCMessageInternal::Rtp(RTPMessage::Packet(Packet::Rtp(rtp::Packet {
                    header,
                    // An RTX payload: the original sequence number, then the media.
                    payload: Bytes::from_static(&[0x00, 0x07, 0xDE, 0xAD]),
                }))),
            })
            .expect("handle_read");
    }

    /// The final answer is applied: it negotiates `formats` for the section.
    fn answer(&mut self, formats: Vec<RTCRtpCodecParameters>) {
        self.media_engine
            .push_codecs(formats.clone(), RtpCodecKind::Video);
        self.media_engine.negotiated_video = true;
        self.transceivers[0]
            .receiver_mut()
            .as_mut()
            .unwrap()
            .set_codec_preferences(formats);
        let receiver = self.transceivers[0].receiver_mut().as_mut().unwrap();
        receiver.settle_offered(&self.media_engine, &mut self.recorder);
    }
}

/// RFC 4585 section 4.2: "The offerer and answerer MUST only use feedback mechanisms
/// negotiated in this way"; RFC 9429 section 5.11 enables them when an answer is applied. A
/// stream that arrives while the offer is pending is bound in the offered format without the
/// feedback the offer proposes; the answer that keeps the feedback binds it again with it.
#[test]
fn an_early_stream_is_bound_without_feedback_until_the_answer_has_it() {
    let mut rig = Rig::new();
    rig.offer();
    rig.arrive(1000, VP8, 1, None);
    rig.arrive(1000, VP8, 2, None);

    let bound = rig.recorder.bound();
    assert_eq!(bound.len(), 1, "{bound:?}");
    assert_eq!((bound[0].ssrc, bound[0].payload_type), (1000, VP8));
    assert_eq!(bound[0].mime_type, "video/VP8");
    assert!(bound[0].rtcp_feedback.is_empty(), "{:?}", bound[0]);
    assert_eq!(rig.recorder.calls().len(), 1, "bound once");

    rig.answer(offered_formats());
    let calls = rig.recorder.calls();
    assert_eq!(
        calls.iter().map(|(bind, _)| *bind).collect::<Vec<_>>(),
        vec![true, false, true],
        "unbound with what it was bound with, bound with what the answer negotiated"
    );
    assert_eq!(calls[1].1, calls[0].1);
    let bound = rig.recorder.bound();
    assert_eq!(bound.len(), 1);
    assert_eq!(bound[0].ssrc, 1000);
    assert_eq!(
        bound[0]
            .rtcp_feedback
            .iter()
            .map(|f| f.typ.as_str())
            .collect::<Vec<_>>(),
        vec!["nack"]
    );
    assert!(!rig.receiver().has_offered());
}

/// A stream that arrives early on a section that was answered before, in a format that
/// answer negotiated, is bound with what was negotiated; an answer that changes nothing for
/// it leaves the binding, and so what the interceptors keep for the stream, alone.
#[test]
fn an_early_stream_in_a_negotiated_format_keeps_its_binding_across_the_answer() {
    let mut rig = Rig::new();
    // The section as an earlier exchange left it.
    rig.media_engine
        .push_codecs(offered_formats(), RtpCodecKind::Video);
    rig.media_engine.negotiated_video = true;
    rig.receiver().set_codec_preferences(offered_formats());
    rig.receiver().set_offered(offered_formats(), true);

    rig.arrive(1000, VP8, 1, None);
    let bound = rig.recorder.bound();
    assert_eq!(bound.len(), 1);
    assert_eq!(bound[0].rtcp_feedback.len(), 1, "{:?}", bound[0]);

    rig.answer(offered_formats());
    assert_eq!(rig.recorder.calls().len(), 1, "{:?}", rig.recorder.calls());
}

/// RFC 3264 section 8.3.2: the offerer "can cease being prepared to receive using any new
/// formats" the answer does not take. A stream that arrived early in VP9 is unbound by an
/// answer without VP9, and its next packet in VP8 establishes it again.
#[test]
fn an_answer_without_the_early_streams_format_unbinds_it() {
    let mut rig = Rig::new();
    rig.offer();
    rig.arrive(1000, VP9, 1, None);
    assert_eq!(rig.recorder.bound()[0].payload_type, VP9);

    rig.answer(offered_formats()[..2].to_vec());
    assert!(
        rig.recorder.bound().is_empty(),
        "{:?}",
        rig.recorder.bound()
    );
    let track_codec = rig.receiver().track().codings()[0].codec.clone();
    assert!(track_codec.mime_type.is_empty(), "{track_codec:?}");

    rig.arrive(1000, VP8, 2, None);
    let bound = rig.recorder.bound();
    assert_eq!(bound.len(), 1);
    assert_eq!((bound[0].ssrc, bound[0].payload_type), (1000, VP8));
}

/// RFC 9429 section 5.7: a rollback restores the state before the offer. The early stream
/// is unbound and the receiver has no coding left; without the offer its format is not
/// receivable, so the stream does not come back.
#[test]
fn a_rollback_unbinds_the_early_stream_and_forgets_it() {
    let mut rig = Rig::new();
    rig.offer();
    rig.arrive(1000, VP8, 1, None);
    assert_eq!(rig.recorder.bound().len(), 1);

    let (gone, _) = rig.transceivers[0]
        .receiver_mut()
        .as_mut()
        .unwrap()
        .roll_back_offered(&mut rig.recorder);
    assert_eq!(gone, vec![1000]);
    assert!(rig.recorder.bound().is_empty());
    assert!(rig.receiver().get_coding_parameters().is_empty());
    assert!(rig.receiver().track().codings().is_empty());
    rig.ctx.ssrc_owners.clear();

    rig.arrive(1000, VP8, 2, None);
    assert!(rig.recorder.bound().is_empty());
    assert!(rig.receiver().get_coding_parameters().is_empty());
}

/// RFC 9429 section 5.9: "For each specified RTP header extension, establish a mapping
/// between the extension ID and URI ... If the MID header extension is supported, prepare
/// to demux RTP streams intended for this 'm=' section based on the MID header extension".
/// With two sections that list the same formats, an early packet is placed by its MID, read
/// with the id of the offer: nothing is negotiated yet. Without the offer's mapping the
/// packet belongs to neither section.
#[test]
fn the_offers_header_extension_ids_place_an_early_stream_by_its_mid() {
    for offered_mapping in [false, true] {
        let mut rig = Rig::new();
        let mut other = RTCRtpTransceiverInternal::new(
            RtpCodecKind::Video,
            None,
            RTCRtpTransceiverInit {
                direction: RTCRtpTransceiverDirection::Recvonly,
                streams: vec![],
                send_encodings: vec![],
            },
        );
        other.set_mid("0".to_owned()).expect("mid");
        rig.transceivers.insert(0, other);
        for transceiver in &mut rig.transceivers {
            transceiver
                .receiver_mut()
                .as_mut()
                .unwrap()
                .set_offered(offered_formats(), false);
        }
        if offered_mapping {
            rig.media_engine.offered_header_extensions =
                vec![(MID_ID, ::sdp::extmap::SDES_MID_URI.to_owned())];
        }

        rig.arrive(1000, VP8, 1, Some(MID_ID));
        let owners: Vec<usize> = rig
            .transceivers
            .iter()
            .enumerate()
            .filter(|(_, t)| {
                !t.receiver()
                    .as_ref()
                    .unwrap()
                    .get_coding_parameters()
                    .is_empty()
            })
            .map(|(index, _)| index)
            .collect();
        if offered_mapping {
            assert_eq!(owners, vec![1], "the section with mid 1");
        } else {
            assert!(owners.is_empty());
        }
    }
}

/// RFC 4588 section 5.3: a receiver with one original stream associates a retransmission
/// stream with it. While the offer is pending, the `a=ssrc-group:FID` that would name the RTX
/// SSRC is still in the answer; an RTX packet on an unknown SSRC of the section becomes the
/// early stream's repair flow, bound as a stream of its own. Without a pending offer it is
/// left alone, and it is never taken for a media stream.
#[test]
fn an_early_retransmission_stream_is_associated_with_the_sections_one_stream() {
    let mut rig = Rig::new();
    rig.offer();
    // The retransmission arrives first: it does not establish a stream of its own.
    rig.arrive(2000, VP8_RTX, 1, None);
    assert!(rig.recorder.bound().is_empty());
    assert!(rig.receiver().get_coding_parameters().is_empty());

    rig.arrive(1000, VP8, 1, None);
    rig.arrive(2000, VP8_RTX, 2, None);
    let coding = rig.receiver().get_coding_parameters()[0].clone();
    assert_eq!(coding.ssrc, Some(1000));
    assert_eq!(coding.rtx.map(|rtx| rtx.ssrc), Some(2000));
    let bound = rig.recorder.bound();
    let primary = bound.iter().find(|b| b.ssrc == 1000).expect("the stream");
    assert_eq!(primary.ssrc_rtx, Some(2000));
    assert_eq!(primary.payload_type_rtx, Some(VP8_RTX));
    let repair = bound.iter().find(|b| b.ssrc == 2000).expect("its RTX flow");
    assert_eq!(repair.payload_type, VP8_RTX);
    // A third SSRC with the RTX payload type repairs nothing known: the stream has its flow.
    rig.arrive(3000, VP8_RTX, 3, None);
    assert_eq!(rig.recorder.bound().len(), 2);

    // No offer pending: an RTX packet on an unknown SSRC is associated with nothing.
    let mut rig = Rig::new();
    rig.receiver().set_codec_preferences(offered_formats());
    rig.arrive(1000, VP8, 1, None);
    rig.arrive(2000, VP8_RTX, 2, None);
    assert!(rig.receiver().get_coding_parameters()[0].rtx.is_none());
    assert_eq!(rig.recorder.bound().len(), 1);
}

/// What early media can make an endpoint keep is bounded by what its offer lists: ten
/// thousand packets from as many SSRCs for one offered section bind one stream. The others
/// match nothing the offer describes and leave nothing behind.
#[test]
fn a_flood_of_early_ssrcs_binds_one_stream_per_offered_section() {
    let mut rig = Rig::new();
    rig.offer();
    for n in 0..10_000u32 {
        rig.arrive(5000 + n, VP8, n as u16, None);
    }
    assert_eq!(rig.recorder.calls().len(), 1);
    assert_eq!(rig.recorder.bound()[0].ssrc, 5000);
    assert_eq!(rig.receiver().get_coding_parameters().len(), 1);
    assert_eq!(rig.receiver().track().codings().len(), 1);
    assert_eq!(rig.ctx.placed_ssrcs.len(), 1);
    assert!(rig.ctx.ssrc_owners.len() <= 1);
    assert_eq!(rig.stats.inbound_rtp_streams.len(), 1);
}

/// An implicit rollback whose remote offer is then refused leaves the local offer pending
/// (the description state is restored), but the rollback had unbound the early streams: they
/// are established anew by their next packets, not left known to the receiver and unknown
/// to the interceptors.
#[test]
fn early_streams_are_established_again_after_a_rollback_that_was_undone() {
    let mut rig = Rig::new();
    rig.offer();
    rig.arrive(1000, VP8, 1, None);
    let pending = rig.transceivers.clone();

    rig.transceivers[0]
        .receiver_mut()
        .as_mut()
        .unwrap()
        .roll_back_offered(&mut rig.recorder);
    assert!(rig.recorder.bound().is_empty());

    // The refused offer: the transceivers are put back as they were with the offer pending.
    rig.transceivers = pending;
    rig.ctx.ssrc_owners.clear();
    rig.receiver().reestablish_early_streams();
    assert!(rig.receiver().has_offered());

    rig.arrive(1000, VP8, 2, None);
    let bound = rig.recorder.bound();
    assert_eq!(bound.len(), 1, "{:?}", rig.recorder.calls());
    assert_eq!(bound[0].ssrc, 1000);
    // And the answer settles it like any early stream.
    rig.answer(offered_formats());
    assert_eq!(rig.recorder.bound().len(), 1);
    assert_eq!(rig.recorder.bound()[0].rtcp_feedback.len(), 1);
}
