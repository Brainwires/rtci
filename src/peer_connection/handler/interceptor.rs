use crate::media_stream::track::MediaStreamTrackId;
use crate::media_stream::track_state::MediaStreamTrackState;
use crate::peer_connection::configuration::media_engine::MediaEngine;
use crate::peer_connection::event::RTCPeerConnectionEvent;
use crate::peer_connection::event::track_event::{RTCTrackEvent, RTCTrackEventInit};
use crate::peer_connection::event::{RTCEventInternal, TaggedRTCEventInternal};
use crate::peer_connection::handler::endpoint::{
    SsrcOwners, deencapsulate_rtx, is_auxiliary_mime_type, is_repair_mime_type, repair_flow_codec,
    resolve_rtx_primary,
};
use crate::peer_connection::message::internal::{
    RTCMessageInternal, RTPMessage, TaggedRTCMessageInternal,
};
use crate::rtp_transceiver::rtp_receiver::internal::RTCRtpReceiverInternal;
use crate::rtp_transceiver::rtp_sender::negotiates_ccfb;
use crate::rtp_transceiver::rtp_sender::rtp_codec::{find_fec_format, find_rtx_payload_type};
use crate::rtp_transceiver::rtp_sender::rtp_coding_parameters::{
    RTCRtpCodingParameters, RTCRtpRtxParameters,
};
use crate::rtp_transceiver::rtp_sender::rtp_header_extension_capability::RTCRtpHeaderExtensionCapability;
use crate::rtp_transceiver::{
    PayloadType, RTCRtpReceiverId, SSRC, internal::RTCRtpTransceiverInternal,
};
use crate::statistics::accumulator::RTCStatsAccumulator;
use interceptor::{
    Attribute, AttributedPacket, Interceptor, Packet, RtcpSessionControl, RtcpSessionEvent,
    TaggedPacket,
};
use log::{debug, trace};
use rtcp::goodbye::Goodbye;
use rtcp::receiver_report::ReceiverReport;
use rtcp::sender_report::SenderReport;
use rtcp::source_description::{
    SdesType, SourceDescription, SourceDescriptionChunk, SourceDescriptionItem,
};
use shared::error::{Error, Result};
use shared::marshal::MarshalSize;
use shared::time::SystemInstant;
use std::collections::{HashMap, HashSet, VecDeque};
use std::time::{Duration, Instant};

/// How soon after a simulcast layer (a `mid`/`rid`) was bound to an SSRC it may move to another.
/// Packets under another SSRC for that layer in between are not attributed to it.
pub(crate) const MIN_RID_SSRC_REBIND_INTERVAL: Duration = Duration::from_secs(1);

/// The most remote SSRCs whose CNAME is remembered.
pub(crate) const MAX_REMOTE_CNAMES: usize = 1024;

pub(crate) struct InterceptorHandlerContext {
    is_dtls_handshake_complete: bool,
    pub(crate) ssrc_owners: SsrcOwners,
    /// When each (`mid`, `rid`) layer was last bound to an SSRC (first bind or move), for the
    /// binds of the last [`MIN_RID_SSRC_REBIND_INTERVAL`] only.
    rid_rebinds: HashMap<(String, String), Instant>,

    pub(crate) read_outs: VecDeque<TaggedRTCMessageInternal>,
    pub(crate) write_outs: VecDeque<TaggedRTCMessageInternal>,
    pub(crate) event_outs: VecDeque<TaggedRTCEventInternal>,
    /// The RTCP CNAME of this connection (RFC 7022 4.2, RFC 8834 4.9): one for every SSRC it
    /// sends from, senders, repair flows and receiver reports alike, generated with the
    /// connection and kept for its life.
    pub(crate) cname: String,
    /// The CNAME each remote SSRC named in its SDES (RFC 3550 6.5.1), which is what binds the
    /// streams of one remote endpoint together for synchronisation.
    pub(crate) remote_cnames: HashMap<SSRC, String>,
    /// The MID each remote SSRC named in an RTCP SDES MID item (RFC 9143 sections 9.2 and
    /// 15.1): the m= section of a stream whose packets carry no MID header extension and whose
    /// SSRC no description declares.
    pub(crate) sdes_mids: HashMap<SSRC, String>,
    /// A sender moved to another SSRC after a collision, and the negotiation-needed flag is
    /// still to be updated for the description that signals it.
    pub(crate) ssrcs_replaced: bool,
    /// The RtpStreamId and RepairedRtpStreamId each remote SSRC named in RTCP SDES items (RFC
    /// 8852 sections 3.1, 3.2): the rid of a stream whose packets carry no RID / RRID header
    /// extension.
    pub(crate) sdes_rids: HashMap<SSRC, (String, String)>,
    /// Local SSRCs another source was heard using (RFC 3550 8.2), until their stream is
    /// replaced.
    pub(crate) ssrc_collisions: HashSet<SSRC>,
    /// The wall clock paired with the engine's clock, taken once, for the timestamps of the
    /// receivers' synchronization and contributing sources.
    pub(crate) wall_clock: Option<SystemInstant>,
}

fn receiver_declares_ssrc(transceiver: &RTCRtpTransceiverInternal, ssrc: SSRC) -> bool {
    transceiver.receiver().as_ref().is_some_and(|receiver| {
        receiver
            .get_coding_parameters()
            .iter()
            .any(|coding| coding.ssrc == Some(ssrc))
    })
}

impl Default for InterceptorHandlerContext {
    fn default() -> Self {
        Self {
            is_dtls_handshake_complete: false,
            ssrc_owners: Default::default(),
            rid_rebinds: Default::default(),
            read_outs: Default::default(),
            write_outs: Default::default(),
            event_outs: Default::default(),
            cname: interceptor::generate_rtcp_cname(),
            remote_cnames: Default::default(),
            sdes_mids: Default::default(),
            ssrcs_replaced: false,
            sdes_rids: Default::default(),
            ssrc_collisions: Default::default(),
            wall_clock: None,
        }
    }
}

/// InterceptorHandler implements RTCP feedback handling
pub(crate) struct InterceptorHandler<'a> {
    ctx: &'a mut InterceptorHandlerContext,
    rtp_transceivers: &'a mut Vec<RTCRtpTransceiverInternal>,
    media_engine: &'a MediaEngine,
    interceptor: &'a mut dyn Interceptor,
    stats: &'a mut RTCStatsAccumulator,
}

impl<'a> InterceptorHandler<'a> {
    pub(crate) fn new(
        ctx: &'a mut InterceptorHandlerContext,
        rtp_transceivers: &'a mut Vec<RTCRtpTransceiverInternal>,
        media_engine: &'a MediaEngine,
        interceptor: &'a mut dyn Interceptor,
        stats: &'a mut RTCStatsAccumulator,
    ) -> Self {
        InterceptorHandler {
            ctx,
            rtp_transceivers,
            media_engine,
            interceptor,
            stats,
        }
    }

    pub(crate) fn name(&self) -> &'static str {
        "InterceptorHandler"
    }

    /// Process incoming RTCP packets and update stats (see `RTCStatsAccumulator::on_rtcp_received`).
    fn process_read_rtcp_for_stats(
        &mut self,
        rtcp_packets: &[Box<dyn rtcp::Packet>],
        now: Instant,
    ) {
        self.stats.on_rtcp_received(rtcp_packets, now);
    }

    /// Process outgoing RTCP packets and update stats (see `RTCStatsAccumulator::on_rtcp_sent`).
    fn process_write_rtcp_for_stats(
        &mut self,
        rtcp_packets: &[Box<dyn rtcp::Packet>],
        now: Instant,
    ) {
        self.stats.on_rtcp_sent(rtcp_packets, now);
    }

    // Establishing an inbound stream, before the interceptor chain sees its first packet.
    //
    // # Why this is not in the endpoint handler
    //
    // A remote stream cannot be bound to the interceptors at negotiation time: a declared-SSRC track
    // is created with an empty codec (see `RTCPeerConnection::start_rtp`), and which codec the peer
    // actually sends is only known from the payload type of an arriving packet.
    //
    // That resolution used to live in the endpoint handler, which sits *application-ward* of the
    // interceptor chain on the read walk. So the packet that resolved the codec had already traversed
    // every interceptor by the time the bind happened, and each one missed it:
    //
    // - the FlexFEC decoder never saw packet one, then rebuilt it from the first repair packet —
    //   handing the application a duplicate of a packet that had arrived perfectly well;
    // - the NACK generator's receive log started at packet two, so its notion of "first seen" was off
    //   by one;
    // - the TWCC and RFC 8888 arrival recorders under-reported by one arrival;
    // - `on_rtx_packet_received_if_rtx` / `on_fec_packet_received_if_fec` in the interceptor handler
    //   silently dropped the first packet's bytes, because the accumulator they look up is created
    //   here.
    //
    // Running establishment from the interceptor handler, immediately before the chain is handed the
    // packet, removes the whole class: every interceptor sees every packet of a stream it is bound to,
    // starting with the first.
    //
    // # How upstream avoids the same problem
    //
    // pion's chain is pull-based — an interceptor *wraps* the SRTP read stream, so "bind, then read"
    // is the only expressible order. For a declared SSRC it binds at negotiation time with
    // `Codecs[0]`, a guess it never revisits: `checkAndUpdateTrack` corrects the application-facing
    // `TrackRemote` when the real payload type shows up, but not the `StreamInfo` the interceptors
    // were given, which keeps a possibly-wrong clock rate and feedback list for the life of the
    // stream. For an undeclared SSRC it peeks the payload type without consuming the packet, so the
    // packet is still queued when the bind happens.
    //
    // This module takes pion's ordering and not its guess: the codec is still resolved from the
    // payload type actually on the wire, and the packet still reaches the chain, because the bind
    // simply happens first.

    /// Bind this packet's stream to the interceptors, unless it is already bound.
    ///
    /// A no-op for every packet after the first of a stream, which is the overwhelming majority:
    /// the declared-SSRC path finds a codec already set and returns immediately.
    fn ensure_remote_stream_bound(&mut self, now: Instant, rtp_header: &rtp::Header) {
        // An RTX packet identifies the stream it repairs, not one of its own. It is resolved back
        // to that stream here, so a stream whose first arrival happens to be a retransmission
        // establishes anyway; `handle_read` de-encapsulates it right after, before the chain.
        let known = self.ctx.ssrc_owners.cached(
            rtp_header.ssrc,
            self.rtp_transceivers,
            receiver_declares_ssrc,
        );
        let (ssrc, payload_type) = if known.is_some() {
            (rtp_header.ssrc, rtp_header.payload_type)
        } else {
            self.rtx_primary_for(rtp_header.ssrc, rtp_header.payload_type)
                .unwrap_or((rtp_header.ssrc, rtp_header.payload_type))
        };
        let owner = known.or_else(|| {
            self.ctx
                .ssrc_owners
                .find(ssrc, self.rtp_transceivers, receiver_declares_ssrc)
        });

        // Same order the endpoint's `find_track_id` used: a declared SSRC settles it, otherwise
        // the single-media-section shortcut, otherwise mid/rid.
        if let Some(id) = owner
            && self.bind_declared_ssrc(now, id, ssrc, payload_type)
        {
            return;
        }
        if self.bind_undeclared_ssrc(now, ssrc, payload_type, rtp_header) {
            return;
        }
        self.bind_by_rid(now, ssrc, payload_type, rtp_header);
    }

    /// RFC 9143 section 9.2: "If the RTCP packet is an SDES packet containing a MID item,
    /// update the ... SSRC mapping table" with the SSRC of the chunk and the m= section the
    /// MID names; RFC 8852 sections 3.1 and 3.2: the RtpStreamId and RepairedRtpStreamId SDES
    /// items name the rid of a stream as the header extensions do. Each is used when a stream
    /// of that SSRC arrives without the header extension ([`Self::stream_ids`]). A MID that
    /// names no m= section is not kept, nor a rid that is not 1 to 255 alphanumerics (RFC 8852
    /// section 3).
    fn process_sdes_mids(&mut self, rtcp_packets: &[Box<dyn rtcp::Packet>]) {
        let is_rid = |rid: &str| {
            !rid.is_empty() && rid.len() <= 255 && rid.bytes().all(|b| b.is_ascii_alphanumeric())
        };
        for packet in rtcp_packets {
            let Some(sdes) = packet.as_any().downcast_ref::<SourceDescription>() else {
                continue;
            };
            for chunk in &sdes.chunks {
                for item in &chunk.items {
                    let Ok(text) = std::str::from_utf8(&item.text) else {
                        continue;
                    };
                    match item.sdes_type {
                        SdesType::SdesMid => {
                            let known = self
                                .rtp_transceivers
                                .iter()
                                .any(|t| t.mid().as_deref() == Some(text));
                            if known
                                && (self.ctx.sdes_mids.len() < MAX_REMOTE_CNAMES
                                    || self.ctx.sdes_mids.contains_key(&chunk.source))
                            {
                                self.ctx.sdes_mids.insert(chunk.source, text.to_owned());
                            }
                        }
                        SdesType::SdesRtpStreamId | SdesType::SdesRepairedRtpStreamId
                            if is_rid(text) =>
                        {
                            if self.ctx.sdes_rids.len() >= MAX_REMOTE_CNAMES
                                && !self.ctx.sdes_rids.contains_key(&chunk.source)
                            {
                                continue;
                            }
                            let ids = self.ctx.sdes_rids.entry(chunk.source).or_default();
                            if item.sdes_type == SdesType::SdesRtpStreamId {
                                text.clone_into(&mut ids.0);
                            } else {
                                text.clone_into(&mut ids.1);
                            }
                        }
                        _ => {}
                    }
                }
            }
        }
    }

    /// The MID, RID and RRID of a received packet: its header extensions', each one it does
    /// not carry taken from what an RTCP SDES item said for its SSRC
    /// ([`Self::process_sdes_mids`]). Empty when neither says.
    fn stream_ids(&self, rtp_header: &rtp::Header) -> (String, String, String) {
        let (mut mid, mut rid, mut rrid) = self
            .get_rtp_header_extension_ids(rtp_header)
            .unwrap_or_default();
        if mid.is_empty()
            && let Some(learned) = self.ctx.sdes_mids.get(&rtp_header.ssrc)
        {
            mid.clone_from(learned);
        }
        if rid.is_empty()
            && rrid.is_empty()
            && let Some((learned_rid, learned_rrid)) = self.ctx.sdes_rids.get(&rtp_header.ssrc)
        {
            rid.clone_from(learned_rid);
            rrid.clone_from(learned_rrid);
        }
        (mid, rid, rrid)
    }

    /// RFC 3550 6.6: a BYE says a source has left. W3C webrtc 9.3: when one of the SSRCs a
    /// receiver receives is removed by a BYE, its track is muted (`OnMute`); it is not
    /// ended (only negotiation ends a remote track), and its next RTP packet unmutes it.
    fn process_goodbyes(&mut self, now: Instant, rtcp_packets: &[Box<dyn rtcp::Packet>]) {
        for packet in rtcp_packets {
            let Some(goodbye) = packet.as_any().downcast_ref::<Goodbye>() else {
                continue;
            };
            for &source in &goodbye.sources {
                // The source left, whether it was a stream of its own or a contributor to a
                // mixer's (a CSRC): no receiver lists it any more.
                for transceiver in self.rtp_transceivers.iter_mut() {
                    if let Some(receiver) = transceiver.receiver_mut() {
                        receiver.forget_source(source);
                    }
                }
                let Some(index) = self.rtp_transceivers.iter().position(|transceiver| {
                    transceiver
                        .receiver()
                        .as_ref()
                        .is_some_and(|receiver| receiver.track().ssrcs().any(|ssrc| ssrc == source))
                }) else {
                    continue;
                };
                let Some(receiver) = self.rtp_transceivers[index].receiver_mut() else {
                    continue;
                };
                let track = receiver.track_mut();
                if track.muted() || track.ready_state() == MediaStreamTrackState::Ended {
                    continue;
                }
                track.set_muted(true);
                let track_id = track.track_id().clone();
                self.ctx.event_outs.push_back(TaggedRTCEventInternal {
                    now,
                    event: RTCEventInternal::RTCPeerConnectionEvent(
                        RTCPeerConnectionEvent::OnTrack(RTCTrackEvent::OnMute(track_id)),
                    ),
                });
            }
        }
    }

    /// RFC 3550 6.1: every compound RTCP packet carries an SDES CNAME after its leading SR or
    /// RR. The RTCP session writes it; this covers a chain built without one, whose report
    /// interceptors emit bare reports. The CNAME is the connection's, whichever SSRC reports
    /// (RFC 8834 4.9: one CNAME per connection).
    fn add_sdes_cname(&mut self, packet: &mut TaggedPacket) {
        let Packet::Rtcp(rtcp_packets) = &mut packet.message.packet else {
            return;
        };
        let Some(first) = rtcp_packets.first() else {
            return;
        };
        let reporter = if let Some(sr) = first.as_any().downcast_ref::<SenderReport>() {
            sr.ssrc
        } else if let Some(rr) = first.as_any().downcast_ref::<ReceiverReport>() {
            rr.ssrc
        } else {
            return;
        };
        if rtcp_packets
            .iter()
            .any(|packet| packet.as_any().is::<SourceDescription>())
        {
            return;
        }

        rtcp_packets.insert(
            1,
            Box::new(SourceDescription {
                chunks: vec![SourceDescriptionChunk {
                    source: reporter,
                    items: vec![SourceDescriptionItem {
                        sdes_type: SdesType::SdesCname,
                        text: self.ctx.cname.clone().into(),
                    }],
                }],
            }),
        );
    }

    /// What the RTCP session reports about the session, recorded for the connection.
    fn process_session_event(&mut self, now: Instant, event: &RtcpSessionEvent) {
        match event {
            RtcpSessionEvent::RemoteCname { ssrc, cname } => {
                if self.ctx.remote_cnames.len() < MAX_REMOTE_CNAMES
                    || self.ctx.remote_cnames.contains_key(ssrc)
                {
                    self.ctx.remote_cnames.insert(*ssrc, cname.clone());
                }
            }
            RtcpSessionEvent::SsrcCollision { ssrc, replacement } => {
                // RFC 3550 8.2, RFC 5576 section 5, RFC 8834 section 4.8. The session's own
                // reporting SSRC has already moved. A sender's moves to `replacement`: its
                // streams are bound again (the RTCP session says BYE for the old SSRC when its
                // stream is unbound), its statistics start over under the new one, and the
                // next description signals it with `previous-ssrc` (negotiation-needed). The
                // application is told, once per SSRC.
                let is_sender = self.rtp_transceivers.iter().any(|transceiver| {
                    transceiver.sender().as_ref().is_some_and(|sender| {
                        sender.track().codings().iter().any(|coding| {
                            let coding = &coding.rtp_coding_parameters;
                            coding.ssrc == Some(*ssrc)
                                || coding.rtx.as_ref().is_some_and(|rtx| rtx.ssrc == *ssrc)
                                || coding.fec.as_ref().is_some_and(|fec| fec.ssrc == *ssrc)
                        })
                    })
                });
                log::warn!("ssrc collision: a remote source uses the local ssrc {ssrc}");
                if is_sender && self.ctx.ssrc_collisions.insert(*ssrc) {
                    for transceiver in self.rtp_transceivers.iter_mut() {
                        let Some(sender) = transceiver.sender_mut() else {
                            continue;
                        };
                        let Some(primary) = sender.replace_ssrc(*ssrc, *replacement) else {
                            continue;
                        };
                        sender.rebind_local_streams(self.media_engine, self.interceptor);
                        if primary == *ssrc {
                            self.stats.replace_outbound_rtp_stream(*ssrc, *replacement);
                        }
                        self.ctx.ssrcs_replaced = true;
                    }
                    self.ctx.event_outs.push_back(TaggedRTCEventInternal {
                        now,
                        event: RTCEventInternal::RTCPeerConnectionEvent(
                            RTCPeerConnectionEvent::OnSsrcCollision(*ssrc),
                        ),
                    });
                }
            }
            _ => {}
        }
    }

    /// RFC 3550 6.6: the connection is closing, so every local SSRC says BYE. Called before
    /// the transports are torn down, while the BYE can still be routed.
    pub(crate) fn request_goodbye(&mut self, now: Instant) {
        if self.ctx.is_dtls_handshake_complete {
            let _ = self
                .interceptor
                .handle_write(RtcpSessionControl::Leave.into_packet(now));
        }
    }

    /// Rewrite an RTX packet into the original packet it carries (RFC 4588 4), when it is one.
    /// Returns the SSRC and sequence number it had on the wire when it was rewritten.
    fn deencapsulate_if_rtx(&mut self, rtp_packet: &mut rtp::Packet) -> Option<(SSRC, u16)> {
        let is_primary = self
            .ctx
            .ssrc_owners
            .cached(
                rtp_packet.header.ssrc,
                self.rtp_transceivers,
                receiver_declares_ssrc,
            )
            .is_some();
        if is_primary {
            return None;
        }
        let (primary_ssrc, primary_payload_type) =
            self.rtx_primary_for(rtp_packet.header.ssrc, rtp_packet.header.payload_type)?;
        let arrived_as = (rtp_packet.header.ssrc, rtp_packet.header.sequence_number);
        deencapsulate_rtx(rtp_packet, primary_ssrc, primary_payload_type).then_some(arrived_as)
    }

    /// RTX SSRC of one of this endpoint's receive codings (declared via
    /// `a=ssrc-group:FID <primary> <rtx>` in the remote SDP, RFC 5576). The original payload type
    /// is resolved from the negotiated RTX codec's `apt=` parameter, looked up by the packet's RTX
    /// `payload_type`. Returns `None` when the SSRC is not a known RTX SSRC or the `apt` mapping
    /// cannot be resolved.
    fn rtx_primary_for(
        &self,
        rtx_ssrc: SSRC,
        rtx_payload_type: PayloadType,
    ) -> Option<(SSRC, PayloadType)> {
        self.rtp_transceivers.iter().find_map(|transceiver| {
            let receiver = transceiver.receiver().as_ref()?;
            resolve_rtx_primary(
                receiver.get_coding_parameters(),
                receiver.get_codec_preferences(),
                rtx_ssrc,
                rtx_payload_type,
            )
        })
    }

    /// Returns whether a receiver owns `ssrc`, establishing it if this is its first packet.
    ///
    /// The return value is "this SSRC is accounted for", not "work was done": an already-bound
    /// stream must still stop the caller from trying the rid and undeclared paths, exactly as the
    /// endpoint's `find_track_id_by_ssrc` returning `Some` used to.
    fn bind_declared_ssrc(
        &mut self,
        now: Instant,
        id: usize,
        ssrc: SSRC,
        payload_type: PayloadType,
    ) -> bool {
        let Some(receiver) = self.rtp_transceivers[id].receiver().as_ref() else {
            return false;
        };
        if !receiver
            .track()
            .ssrcs()
            .any(|track_ssrc| track_ssrc == ssrc)
        {
            return false;
        }

        let is_track_codec_empty = receiver
            .track()
            .get_codec_by_ssrc(ssrc)
            .is_some_and(|codec| codec.mime_type.is_empty());

        // `payload_type` is the *primary* codec's: an RTX packet was resolved back to the stream it
        // repairs before we got here. FEC de-encapsulation is still TODO (see #12). A DTMF or
        // comfort-noise packet that comes first leaves the stream unestablished: the next media
        // packet says what the track's codec is.
        let track_codec = if is_track_codec_empty
            && let Some(codec) = receiver.get_codec_preferences().iter().find(|codec| {
                codec.payload_type == payload_type
                    && !is_auxiliary_mime_type(&codec.rtp_codec.mime_type)
            }) {
            Some((codec.rtp_codec.clone(), codec.payload_type))
        } else {
            None
        };

        let Some((codec, payload_type)) = track_codec else {
            // Already established — the common case, once per packet after the first.
            return true;
        };

        // Get kind and mid before borrowing receiver mutably
        let transceiver = &mut self.rtp_transceivers[id];
        let kind = transceiver.kind();
        let mid = transceiver.mid().clone().unwrap_or_default();
        let Some(receiver) = transceiver.receiver_mut() else {
            return false;
        };

        // Get RTX and FEC SSRCs from coding parameters
        let (rtx_ssrc, fec_ssrc) = receiver
            .get_coding_parameters()
            .iter()
            .find(|c| c.ssrc == Some(ssrc))
            .map(|c| {
                (
                    c.rtx.as_ref().map(|r| r.ssrc),
                    c.fec.as_ref().map(|f| f.ssrc),
                )
            })
            .unwrap_or((None, None));

        let parameters = receiver.get_parameters(self.media_engine);
        // Both halves or neither, per repair flow — see `interceptor_remote_streams_op`. RTX and
        // FEC are handled identically: both repair this stream from a separate SSRC.
        let rtx = rtx_ssrc.zip(find_rtx_payload_type(
            payload_type,
            &parameters.rtp_parameters.codecs,
        ));
        let fec = fec_ssrc.zip(find_fec_format(&parameters.rtp_parameters.codecs));

        RTCRtpReceiverInternal::interceptor_remote_stream_op(
            self.interceptor,
            true,
            ssrc,
            rtx.map(|(ssrc_rtx, _)| ssrc_rtx),
            fec.as_ref().map(|(ssrc_fec, _)| *ssrc_fec),
            payload_type,
            rtx.map(|(_, payload_type_rtx)| payload_type_rtx),
            fec.as_ref().map(|(_, fec_format)| fec_format),
            &codec,
            &parameters.rtp_parameters.header_extensions,
        );

        // Each repair flow is also bound in its own right, exactly as
        // `interceptor_remote_streams_op` does it: a real RTP stream with its own SSRC and
        // sequence-number space, which an interceptor tracking arrivals has to know about. Binding
        // only the primary here would also leave the pair unbalanced — `stop` unbinds all three, so
        // the repair flows would be unbound having never been bound.
        if let Some((ssrc_rtx, payload_type_rtx)) = rtx {
            RTCRtpReceiverInternal::interceptor_remote_stream_op(
                self.interceptor,
                true,
                ssrc_rtx,
                None,
                None,
                payload_type_rtx,
                None,
                None,
                &repair_flow_codec(&codec),
                &parameters.rtp_parameters.header_extensions,
            );
        }

        if let Some((ssrc_fec, fec_format)) = fec {
            RTCRtpReceiverInternal::interceptor_remote_stream_op(
                self.interceptor,
                true,
                ssrc_fec,
                None,
                None,
                fec_format.payload_type,
                None,
                None,
                &repair_flow_codec(&codec),
                &parameters.rtp_parameters.header_extensions,
            );
        }

        // Set valid Codec for track when received the first RTP packet for such ssrc stream
        // assert not inserting new entry
        let track_id = receiver.track().track_id().clone();
        let stream_id = receiver.track().stream_id().to_owned();
        let ccfb = negotiates_ccfb(
            codec
                .rtcp_feedback
                .iter()
                .map(|f| (f.typ.as_str(), f.parameter.as_str())),
        );
        let new_entry = receiver.track_mut().set_codec_by_ssrc(codec, ssrc);
        assert!(!new_entry);

        // Create inbound stream accumulator before firing OnOpen event
        self.stats
            .get_or_create_inbound_rtp_streams(ssrc, kind, &track_id, &mid, rtx_ssrc, fec_ssrc, id);
        self.stats.set_inbound_ccfb(ssrc, ccfb);

        self.emit_on_open(now, id, track_id, stream_id, ssrc, None);
        true
    }

    /// The single-media-section shortcut: an SSRC absent from the SDP, resolved by there being
    /// only one place it could belong to.
    /// An SSRC the remote description doesn't declare, for a receiver that expects one: the
    /// only transceiver's, or — with several media sections — the one the packet's MID header
    /// extension names without a RID (RFC 9143 section 9.2: a=ssrc lines are optional, the MID
    /// identifies the m-section), or, for a packet with no MID, the one transceiver that
    /// receives the packet's payload type.
    fn bind_undeclared_ssrc(
        &mut self,
        now: Instant,
        ssrc: SSRC,
        payload_type: PayloadType,
        rtp_header: &rtp::Header,
    ) -> bool {
        let index = if self.rtp_transceivers.len() == 1 {
            0
        } else {
            // No MID (RID, RRID) in the packet: the one an RTCP SDES item gave its SSRC.
            let (mid, rid, rrid) = self.stream_ids(rtp_header);
            // A RID (or RRID) means simulcast: that is the rid path's.
            if !rid.is_empty() || !rrid.is_empty() {
                return false;
            }
            if mid.is_empty() {
                // RFC 9143 section 9.2, the last step of associating an RTP stream with an m=
                // section: "If the packet's payload type is in the payload type table, update
                // the outgoing SSRC mapping table to include an entry that maps the packet's
                // SSRC to the 'm=' section for that payload type", the table holding the
                // payload types that "uniquely identify an 'm=' section". So: the one
                // transceiver that is not stopped and receives this payload type. None, or
                // more than one, and the packet belongs nowhere ("Otherwise, drop the
                // packet").
                let mut receiving = self.rtp_transceivers.iter().enumerate().filter(|(_, t)| {
                    !t.stopped()
                        && t.receiver().as_ref().is_some_and(|receiver| {
                            receiver
                                .get_codec_preferences()
                                .iter()
                                .any(|codec| codec.payload_type == payload_type)
                        })
                });
                match (receiving.next(), receiving.next()) {
                    (Some((index, _)), None) => index,
                    _ => return false,
                }
            } else {
                let Some(index) = self
                    .rtp_transceivers
                    .iter()
                    .position(|t| t.mid().as_deref() == Some(mid.as_str()))
                else {
                    return false;
                };
                index
            }
        };

        if let Some(transceiver) = self.rtp_transceivers.get(index)
            && let Some(receiver) = transceiver.receiver()
            && !receiver.track().codings().is_empty()
        {
            // it is rid-based (or already bound), let's use the rid path
            return false;
        }

        let Some(transceiver) = self.rtp_transceivers.get_mut(index) else {
            return false;
        };
        // Get kind and mid before borrowing receiver mutably
        let kind = transceiver.kind();
        let mid = transceiver.mid().clone().unwrap_or_default();

        let Some(receiver) = transceiver.receiver_mut() else {
            return false;
        };
        // A DTMF or comfort-noise packet does not say what the stream is sent with: the stream
        // is placed by its first media packet.
        let Some(codec) = receiver
            .get_codec_preferences()
            .iter()
            .find(|codec| {
                codec.payload_type == payload_type
                    && !is_auxiliary_mime_type(&codec.rtp_codec.mime_type)
            })
            .cloned()
        else {
            return false;
        };

        let receive_codings = vec![RTCRtpCodingParameters {
            rid: "".to_string(),
            ssrc: Some(ssrc),
            rtx: None,
            fec: None,
            ..Default::default()
        }];
        receiver.set_coding_parameters(receive_codings);

        let parameters = receiver.get_parameters(self.media_engine);
        // An undeclared SSRC arrived without any `a=ssrc-group` to associate it with, so there is
        // no repair flow to report — the codings above are built with `fec: None`.
        RTCRtpReceiverInternal::interceptor_remote_stream_op(
            self.interceptor,
            true,
            ssrc,
            None,
            None,
            codec.payload_type,
            None,
            None,
            &codec.rtp_codec,
            &parameters.rtp_parameters.header_extensions,
        );

        let track_id = receiver.track().track_id().to_owned();
        let stream_id = receiver.track().stream_id().to_owned();
        let ccfb = negotiates_ccfb(
            codec
                .rtp_codec
                .rtcp_feedback
                .iter()
                .map(|f| (f.typ.as_str(), f.parameter.as_str())),
        );
        // assert it inserts a new entry
        let new_entry = receiver
            .track_mut()
            .set_codec_by_ssrc(codec.rtp_codec, ssrc);
        assert!(new_entry);

        // Create inbound stream accumulator before firing OnOpen event
        // Note: undeclared SSRC case doesn't have RTX/FEC info
        self.stats
            .get_or_create_inbound_rtp_streams(ssrc, kind, &track_id, &mid, None, None, index);
        self.stats.set_inbound_ccfb(ssrc, ccfb);

        self.emit_on_open(now, index, track_id, stream_id, ssrc, None);
        true
    }

    /// A repair (RTX) stream announced only by the `repaired-rtp-stream-id` header extension
    /// (RFC 8852 `rrid`): associate its SSRC with the base layer's RTX parameters, so later
    /// packets resolve through [`rtx_primary_for`](Self::rtx_primary_for) and are
    /// de-encapsulated onto the primary, and bind it to the interceptors as a stream of its own.
    ///
    /// Brainwires fork (upstream still has this as TODO #12); see FORK.md.
    fn bind_repair_by_rrid(
        &mut self,
        ssrc: SSRC,
        payload_type: PayloadType,
        mid: &str,
        rrid: &str,
    ) -> bool {
        let Some(transceiver) = self
            .rtp_transceivers
            .iter_mut()
            .find(|transceiver| transceiver.mid().as_deref() == Some(mid))
        else {
            return false;
        };
        let Some(receiver) = transceiver.receiver_mut() else {
            return false;
        };
        // In this branch the packet is the repair flow, so its payload type is the RTX one.
        let Some(codec) = receiver
            .get_codec_preferences()
            .iter()
            .find(|codec| codec.payload_type == payload_type)
            .cloned()
        else {
            return false;
        };

        let (primary_ssrc, replaced_ssrc) = match receiver.get_coding_parameter_mut_by_rid(rrid) {
            Some(coding) => {
                if coding.rtx.as_ref().is_some_and(|rtx| rtx.ssrc == ssrc) {
                    // Already associated and bound.
                    return true;
                }
                let replaced = coding.rtx.as_ref().map(|rtx| rtx.ssrc);
                match coding.rtx.as_mut() {
                    Some(rtx) => rtx.ssrc = ssrc,
                    None => coding.rtx = Some(RTCRtpRtxParameters { ssrc }),
                }
                (coding.ssrc, replaced)
            }
            None => {
                log::warn!(
                    "dropping repair/RTX SSRC association: no base coding parameters found for \
                     rrid='{rrid}' (repair_ssrc={ssrc}, mid='{mid}')"
                );
                return false;
            }
        };

        let parameters = receiver.get_parameters(self.media_engine);
        // A repair SSRC this one replaces (the sender restarted its RTX stream) is unbound, so
        // interceptors do not keep state for a stream that no longer exists.
        if let Some(replaced) = replaced_ssrc
            && replaced != 0
        {
            RTCRtpReceiverInternal::interceptor_remote_stream_op(
                self.interceptor,
                false,
                replaced,
                None,
                None,
                codec.payload_type,
                None,
                None,
                &repair_flow_codec(&codec.rtp_codec),
                &parameters.rtp_parameters.header_extensions,
            );
        }
        RTCRtpReceiverInternal::interceptor_remote_stream_op(
            self.interceptor,
            true,
            ssrc,
            None,
            None,
            codec.payload_type,
            None,
            None,
            &repair_flow_codec(&codec.rtp_codec),
            &parameters.rtp_parameters.header_extensions,
        );

        // Attribute RTX packets to the primary stream's stats.
        if let Some(primary_ssrc) = primary_ssrc {
            self.stats.update_inbound_rtx_ssrc(primary_ssrc, ssrc);
        }
        true
    }

    /// Simulcast: the layer is identified by the `mid`/`rid` header extensions rather than by an
    /// SSRC the SDP declared.
    fn bind_by_rid(
        &mut self,
        now: Instant,
        ssrc: SSRC,
        payload_type: PayloadType,
        rtp_header: &rtp::Header,
    ) -> bool {
        let (mid, rid, rrid) = self.stream_ids(rtp_header);
        if mid.is_empty() || (rid.is_empty() && rrid.is_empty()) {
            return false;
        }
        if !rrid.is_empty() {
            return self.bind_repair_by_rrid(ssrc, payload_type, &mid, &rrid);
        }

        // If rtp header extension has valid mid, find receiver based on mid, instead of rid,
        // since rid is not unique across m= lines
        let Some((id, transceiver)) =
            self.rtp_transceivers
                .iter_mut()
                .enumerate()
                .find(|(_, transceiver)| {
                    transceiver
                        .mid()
                        .as_deref()
                        .is_some_and(|t_mid| t_mid == mid)
                })
        else {
            return false;
        };

        // Get kind before borrowing receiver mutably
        let kind = transceiver.kind();

        let Some(receiver) = transceiver.receiver_mut() else {
            return false;
        };
        let Some(codec) = receiver
            .get_codec_preferences()
            .iter()
            // A layer is established by its primary codec; repair flows are associated through
            // the coding's rtx/fec SSRCs (or rrid), not by binding the layer to a repair codec.
            .find(|codec| {
                codec.payload_type == payload_type
                    && !is_repair_mime_type(&codec.rtp_codec.mime_type)
                    && !is_auxiliary_mime_type(&codec.rtp_codec.mime_type)
            })
            .cloned()
        else {
            return false;
        };

        // Validate rid against SDP. If invalid then drop it.
        let previous_ssrc = match receiver.get_coding_parameter_mut_by_rid(rid.as_str()) {
            None => return false,
            Some(coding) if coding.ssrc == Some(ssrc) => return true,
            Some(coding) => coding.ssrc,
        };

        // A layer moves to a new SSRC at most once per interval, counted from its first bind as
        // well as from each move, and the stream it leaves is unbound: a layer holds one bound
        // stream however often its SSRC changes.
        let key = (mid.clone(), rid.clone());
        if let Some(previous_ssrc) = previous_ssrc
            && self.ctx.rid_rebinds.get(&key).is_some_and(|last| {
                now.saturating_duration_since(*last) < MIN_RID_SSRC_REBIND_INTERVAL
            })
        {
            debug!(
                "ignoring ssrc {ssrc} for mid={mid} rid={rid}: the layer was bound to ssrc \
                 {previous_ssrc} too recently"
            );
            return false;
        }
        self.ctx
            .rid_rebinds
            .retain(|_, last| now.saturating_duration_since(*last) < MIN_RID_SSRC_REBIND_INTERVAL);
        self.ctx.rid_rebinds.insert(key, now);

        if let Some(previous_ssrc) = previous_ssrc {
            let parameters = receiver.get_parameters(self.media_engine);
            RTCRtpReceiverInternal::interceptor_remote_stream_op(
                self.interceptor,
                false,
                previous_ssrc,
                None,
                None,
                codec.payload_type,
                None,
                None,
                &codec.rtp_codec,
                &parameters.rtp_parameters.header_extensions,
            );
            self.stats.remove_inbound_rtp_stream(previous_ssrc);
            self.ctx.ssrc_owners.remove(previous_ssrc);
        }

        match receiver.get_coding_parameter_mut_by_rid(rid.as_str()) {
            Some(coding) => coding.ssrc = Some(ssrc),
            None => return false,
        }

        // Get RTX and FEC SSRCs from coding parameters.
        //
        // Resolved before the bind rather than after it: each simulcast layer has its own repair
        // flow, so the association has to be the one belonging to *this* coding, and it is what the
        // bind below hands to the interceptors.
        let (rtx_ssrc, fec_ssrc) = receiver
            .get_coding_parameters()
            .iter()
            .find(|c| c.ssrc == Some(ssrc))
            .map(|c| {
                (
                    c.rtx.as_ref().map(|r| r.ssrc),
                    c.fec.as_ref().map(|f| f.ssrc),
                )
            })
            .unwrap_or((None, None));

        let parameters = receiver.get_parameters(self.media_engine);
        // Both halves or neither, per repair flow — see `interceptor_remote_streams_op`. RTX and
        // FEC are handled identically: both repair this stream from a separate SSRC.
        let rtx = rtx_ssrc.zip(find_rtx_payload_type(
            codec.payload_type,
            &parameters.rtp_parameters.codecs,
        ));
        let fec = fec_ssrc.zip(find_fec_format(&parameters.rtp_parameters.codecs));

        RTCRtpReceiverInternal::interceptor_remote_stream_op(
            self.interceptor,
            true,
            ssrc,
            rtx.map(|(ssrc_rtx, _)| ssrc_rtx),
            fec.as_ref().map(|(ssrc_fec, _)| *ssrc_fec),
            codec.payload_type,
            rtx.map(|(_, payload_type_rtx)| payload_type_rtx),
            fec.as_ref().map(|(_, fec_format)| fec_format),
            &codec.rtp_codec,
            &parameters.rtp_parameters.header_extensions,
        );

        // And each repair flow in its own right, as `interceptor_remote_streams_op` does: naming it
        // as an association on the primary tells an interceptor which flow repairs which, not that
        // a stream with its own SSRC and sequence-number space is arriving. Simulcast is where this
        // matters most — every layer has its own retransmission flow, and NACK-driven repair is
        // what keeps the upper layers usable.
        if let Some((ssrc_rtx, payload_type_rtx)) = rtx {
            RTCRtpReceiverInternal::interceptor_remote_stream_op(
                self.interceptor,
                true,
                ssrc_rtx,
                None,
                None,
                payload_type_rtx,
                None,
                None,
                &repair_flow_codec(&codec.rtp_codec),
                &parameters.rtp_parameters.header_extensions,
            );
        }

        if let Some((ssrc_fec, fec_format)) = fec {
            RTCRtpReceiverInternal::interceptor_remote_stream_op(
                self.interceptor,
                true,
                ssrc_fec,
                None,
                None,
                fec_format.payload_type,
                None,
                None,
                &repair_flow_codec(&codec.rtp_codec),
                &parameters.rtp_parameters.header_extensions,
            );
        }

        let track_id = receiver.track().track_id().to_owned();
        let stream_id = receiver.track().stream_id().to_owned();
        let ccfb = negotiates_ccfb(
            codec
                .rtp_codec
                .rtcp_feedback
                .iter()
                .map(|f| (f.typ.as_str(), f.parameter.as_str())),
        );
        let new_entry = receiver
            .track_mut()
            .set_codec_ssrc_by_rid(codec.rtp_codec, ssrc, &rid);
        assert!(!new_entry);

        // Create inbound stream accumulator before firing OnOpen event
        self.stats
            .get_or_create_inbound_rtp_streams(ssrc, kind, &track_id, &mid, rtx_ssrc, fec_ssrc, id);
        self.stats.set_inbound_ccfb(ssrc, ccfb);

        self.emit_on_open(now, id, track_id, stream_id, ssrc, Some(rid));
        true
    }

    /// Fire `RTCTrackEvent::OnOpen` for the first RTP packet of a stream.
    ///
    /// Queued to the interceptor handler's events rather than the endpoint's, which is where
    /// establishment now happens. Events and media travel in separate queues to the application, so
    /// their relative order was never guaranteed; what is guaranteed either way is that the
    /// accumulator above exists before this fires.
    fn emit_on_open(
        &mut self,
        now: Instant,
        receiver_id: usize,
        track_id: MediaStreamTrackId,
        stream_id: String,
        ssrc: SSRC,
        rid: Option<String>,
    ) {
        self.ctx.event_outs.push_back(TaggedRTCEventInternal {
            now,
            event: RTCEventInternal::RTCPeerConnectionEvent(RTCPeerConnectionEvent::OnTrack(
                RTCTrackEvent::OnOpen(RTCTrackEventInit {
                    receiver_id: RTCRtpReceiverId(receiver_id),
                    track_id,
                    stream_ids: vec![stream_id],
                    ssrc,
                    rid,
                }),
            )),
        });
    }

    /// Records the SSRC and CSRCs of a packet the chain released, on the receiver that owns
    /// the SSRC (`RTCRtpReceiver::get_synchronization_sources`, `get_contributing_sources`).
    fn record_sources(&mut self, now: Instant, header: &rtp::Header) {
        let Some(id) =
            self.ctx
                .ssrc_owners
                .find(header.ssrc, self.rtp_transceivers, receiver_declares_ssrc)
        else {
            return;
        };
        let extension = |uri: &str| {
            if !header.extension {
                return None;
            }
            let (extension_id, audio, _) =
                self.media_engine
                    .get_header_extension_id(RTCRtpHeaderExtensionCapability {
                        uri: uri.to_owned(),
                    });
            (audio && extension_id != 0)
                .then(|| header.get_extension(extension_id as u8))
                .flatten()
        };
        // RFC 6464: one octet, the voice activity flag and the level in -dBov.
        let audio_level =
            extension(::sdp::extmap::AUDIO_LEVEL_URI).and_then(|payload| payload.first().copied());
        // RFC 6465: one level per CSRC.
        let csrc_levels =
            extension(crate::rtp_transceiver::rtp_receiver::internal::CSRC_AUDIO_LEVEL_URI)
                .and_then(|payload| {
                    use shared::marshal::Unmarshal;
                    rtp::extension::csrc_audio_level_extension::CsrcAudioLevelExtension::unmarshal(
                        &mut payload.as_ref(),
                    )
                    .ok()
                });
        let wall_clock = *self
            .ctx
            .wall_clock
            .get_or_insert_with(|| SystemInstant::now(now));
        // RFC 6464 section 4: the V bit is in use unless the extension was negotiated with
        // `vad=off` (no attribute is `vad=on`).
        let vad = self
            .media_engine
            .negotiated_header_extensions
            .values()
            .find(|e| e.is_audio && e.uri == ::sdp::extmap::AUDIO_LEVEL_URI)
            .is_none_or(|e| {
                rtp::extension::audio_level_extension::parse_vad_attribute(e.attributes.as_deref())
                    .unwrap_or(true)
            });
        let receptive = self.rtp_transceivers[id].receptive();
        if let Some(receiver) = self.rtp_transceivers[id].receiver_mut() {
            receiver.record_sources(
                now,
                wall_clock,
                header,
                audio_level,
                csrc_levels.as_ref().map(|ext| ext.levels.as_slice()),
                vad,
            );
            // W3C webrtc 9.3: data for a muted, not ended track of a receptive transceiver
            // unmutes it.
            let track = receiver.track_mut();
            if receptive && track.muted() && track.ready_state() != MediaStreamTrackState::Ended {
                track.set_muted(false);
                let track_id = track.track_id().clone();
                self.ctx.event_outs.push_back(TaggedRTCEventInternal {
                    now,
                    event: RTCEventInternal::RTCPeerConnectionEvent(
                        RTCPeerConnectionEvent::OnTrack(RTCTrackEvent::OnUnmute(track_id)),
                    ),
                });
            }
        }
    }

    fn get_rtp_header_extension_ids(
        &self,
        rtp_header: &rtp::Header,
    ) -> Option<(String, String, String)> {
        if !rtp_header.extension {
            return None;
        }

        // Each of the three extensions is read when it is negotiated, on its own: a session
        // that negotiated MID without RtpStreamId (no simulcast) still associates by MID.
        let negotiated_id = |uri: &str| -> u16 {
            let (id, audio_supported, video_supported) =
                self.media_engine
                    .get_header_extension_id(RTCRtpHeaderExtensionCapability {
                        uri: uri.to_owned(),
                    });
            if audio_supported || video_supported {
                id
            } else {
                0
            }
        };
        let mid_extension_id = negotiated_id(::sdp::extmap::SDES_MID_URI);
        let rid_extension_id = negotiated_id(::sdp::extmap::SDES_RTP_STREAM_ID_URI);
        let rrid_extension_id = negotiated_id(::sdp::extmap::SDES_REPAIR_RTP_STREAM_ID_URI);
        if mid_extension_id == 0 && rid_extension_id == 0 && rrid_extension_id == 0 {
            return None;
        }

        let mid = if mid_extension_id != 0
            && let Some(payload) = rtp_header.get_extension(mid_extension_id as u8)
        {
            String::from_utf8(payload.to_vec()).unwrap_or_default()
        } else {
            String::new()
        };

        let rid = if rid_extension_id != 0
            && let Some(payload) = rtp_header.get_extension(rid_extension_id as u8)
        {
            String::from_utf8(payload.to_vec()).unwrap_or_default()
        } else {
            String::new()
        };

        let rrid = if rrid_extension_id != 0
            && let Some(payload) = rtp_header.get_extension(rrid_extension_id as u8)
        {
            String::from_utf8(payload.to_vec()).unwrap_or_default()
        } else {
            String::new()
        };

        Some((mid, rid, rrid))
    }
}

impl<'a>
    sansio::Protocol<TaggedRTCMessageInternal, TaggedRTCMessageInternal, TaggedRTCEventInternal>
    for InterceptorHandler<'a>
{
    type Rout = TaggedRTCMessageInternal;
    type Wout = TaggedRTCMessageInternal;
    type Eout = TaggedRTCEventInternal;
    type Error = Error;
    type Time = Instant;

    fn handle_read(&mut self, msg: TaggedRTCMessageInternal) -> Result<()> {
        if self.ctx.is_dtls_handshake_complete
            && let RTCMessageInternal::Rtp(RTPMessage::Packet(mut packet)) = msg.message
        {
            let mut retransmitted = None;
            match &mut packet {
                Packet::Rtp(rtp_packet) => {
                    // Establish the stream *before* the chain is handed the packet. The codec can only
                    // be resolved from an arriving payload type, so this is the first moment it can be
                    // done — and doing it here rather than in the endpoint handler, which sits
                    // application-ward of the chain, is what stops the first packet of every stream
                    // from traversing interceptors that have not yet been told the stream exists.
                    // See "Stream establishment" below.
                    self.ensure_remote_stream_bound(msg.now, &rtp_packet.header);

                    // What arrived, before anything rewrites it: the SSRC it came on, its
                    // payload, and the rest of it (header and padding, RFC 3550 section 5.1).
                    let ssrc = rtp_packet.header.ssrc;
                    let payload_bytes = rtp_packet.payload.len();
                    let overhead_bytes = rtp_packet.header.marshal_size()
                        + if rtp_packet.header.padding {
                            usize::from(rtp_packet.header.padding_size)
                        } else {
                            0
                        };

                    // RFC 4588 5: a retransmission is the original packet again, and the
                    // receiver's own machinery has to see it as that. De-encapsulated here, before
                    // the chain, the NACK generator stops asking for a packet RTX repaired, the
                    // receiver report counts it as received, and a jitter buffer can slot it in.
                    // De-encapsulated after the chain (in the endpoint handler, as it was), all
                    // three only ever saw a packet on the RTX SSRC.
                    //
                    // A padding-only RTX packet (a bandwidth probe, no OSN) carries nothing to
                    // recover and goes on unchanged: its transport-wide sequence number still has
                    // to reach the TWCC recorder, or the probe reads as lost.
                    //
                    // What the retransmission was on the wire travels with it
                    // (`Attribute::Retransmitted`): reception statistics count it on the RTX
                    // stream it arrived on, so the primary stream's receiver report keeps
                    // showing the loss the path had (RFC 4588 3).
                    retransmitted = self.deencapsulate_if_rtx(rtp_packet);

                    // The arrival is counted here, before the chain and on what the wire
                    // carried: webrtc-stats counts the packets received for the SSRC (RFC 3550
                    // section 6.4.1), which is every arrival, whatever an interceptor later
                    // does with it, and no packet a FEC decoder rebuilds. Reached only now that
                    // the accumulator exists: `ensure_remote_stream_bound` creates it.
                    if retransmitted.is_some() {
                        self.stats.on_retransmission_received(
                            rtp_packet.header.ssrc,
                            overhead_bytes,
                            payload_bytes,
                            msg.now,
                        );
                    } else {
                        self.stats
                            .on_rtp_received(ssrc, overhead_bytes, payload_bytes, msg.now);
                    }

                    // The ECN codepoint the datagram arrived with (from the application's socket
                    // layer), counted on the stream the packet belongs to, a repaired one
                    // included.
                    self.stats
                        .on_rtp_ecn_received(rtp_packet.header.ssrc, msg.transport.ecn);
                }
                Packet::Rtcp(rtcp_packets) => {
                    // Counted here, before the chain, for the same reason as the RTP accounting
                    // above: the chain's terminus consumes RTCP that no interceptor marks, so
                    // `poll_read` never sees most incoming SR/RR/NACK/PLI/FIR/CCFB. This is the
                    // read-side counterpart of `process_write_rtcp_for_stats` in `poll_write`.
                    self.process_read_rtcp_for_stats(rtcp_packets, msg.now);
                    self.process_sdes_mids(rtcp_packets);
                    self.process_goodbyes(msg.now, rtcp_packets);
                }
                _ => {}
            }

            let mut message: AttributedPacket = packet.into();
            if let Some((ssrc, sequence_number)) = retransmitted {
                message.add(Attribute::Retransmitted {
                    ssrc,
                    sequence_number,
                });
            }
            self.interceptor.handle_read(TaggedPacket {
                now: msg.now,
                transport: msg.transport,
                message,
            })?;
        } else {
            debug!("interceptor read bypass {:?}", msg.transport.peer_addr);
            self.ctx.read_outs.push_back(msg);
        }
        Ok(())
    }

    fn poll_read(&mut self) -> Option<Self::Rout> {
        if self.ctx.is_dtls_handshake_complete {
            while let Some(packet) = self.interceptor.poll_read() {
                // Attributes are how information crosses interceptors, and this is where the ones
                // that mean something beyond the chain are recorded. The estimate reaches the
                // application through `get_stats` rather than through an event of its own: it is
                // one more number about the send side, and it belongs with the rest of them.
                for attribute in &packet.message.attributes {
                    match attribute {
                        Attribute::TargetBitrateChanged { bits_per_second } => {
                            // The outbound streams' `targetBitrate` and the selected pair's
                            // `availableOutgoingBitrate` (see
                            // `RTCStatsAccumulator::on_target_bitrate`).
                            self.stats.on_target_bitrate(*bits_per_second);
                        }
                        Attribute::Custom(value) => {
                            if let Some(event) = value.downcast_ref::<RtcpSessionEvent>() {
                                let event = event.clone();
                                self.process_session_event(packet.now, &event);
                            }
                        }
                        _ => {}
                    }
                }

                // An empty RTCP packet is an attribute carrier, not a message: the terminus strips
                // an annotated report down to this so its attributes can reach here. Its work is
                // done, and surfacing it would hand the application a packet with nothing in it.
                if matches!(&packet.message.packet, Packet::Rtcp(packets) if packets.is_empty()) {
                    continue;
                }

                // A RED packet that held only ULPFEC travels the read leg emptied, so the
                // interceptors that count sequence numbers see its number. It is not media, and
                // an application has no use for a packet with nothing in it.
                if packet
                    .message
                    .custom::<interceptor::UlpfecRepair>()
                    .is_some()
                {
                    continue;
                }

                match &packet.message.packet {
                    Packet::Rtcp(rtcp_packet) => {
                        trace!("Interceptor forwarded a RTCP packet {:?}", rtcp_packet);
                    }
                    // Media on its way to the application: its sources are the receiver's
                    // synchronization and contributing sources from now on.
                    Packet::Rtp(rtp_packet) => {
                        self.record_sources(packet.now, &rtp_packet.header);
                    }
                    _ => {}
                }

                self.ctx.read_outs.push_back(TaggedRTCMessageInternal {
                    now: packet.now,
                    transport: packet.transport,
                    message: RTCMessageInternal::Rtp(RTPMessage::Packet(packet.message.packet)),
                });
            }
        }

        self.ctx.read_outs.pop_front()
    }

    fn handle_write(&mut self, msg: TaggedRTCMessageInternal) -> Result<()> {
        if self.ctx.is_dtls_handshake_complete
            && let RTCMessageInternal::Rtp(RTPMessage::Packet(packet)) = msg.message
        {
            // When the application wrote the packet: what the time an interceptor holds it
            // (a pacer) is measured from (`totalPacketSendDelay`).
            if let Packet::Rtp(rtp_packet) = &packet {
                self.stats.on_rtp_written(
                    rtp_packet.header.ssrc,
                    rtp_packet.header.sequence_number,
                    msg.now,
                );
            }
            self.interceptor.handle_write(TaggedPacket {
                now: msg.now,
                transport: msg.transport,
                message: packet.into(),
            })?;
        } else {
            debug!("interceptor bypass {:?}", msg.transport.peer_addr);
            self.ctx.write_outs.push_back(msg);
        }
        Ok(())
    }

    fn poll_write(&mut self) -> Option<Self::Wout> {
        if self.ctx.is_dtls_handshake_complete {
            while let Some(mut packet) = self.interceptor.poll_write() {
                // An empty RTCP packet is an attribute carrier (a control message no
                // interceptor took): nothing to send.
                if matches!(&packet.message.packet, Packet::Rtcp(packets) if packets.is_empty()) {
                    continue;
                }
                self.add_sdes_cname(&mut packet);
                // Process outgoing packets for stats
                match &packet.message.packet {
                    Packet::Rtcp(rtcp_packets) => {
                        self.process_write_rtcp_for_stats(rtcp_packets, packet.now);
                    }
                    Packet::Rtp(rtp_packet) => {
                        // Counted on the stream the packet belongs to: its own SSRC or its
                        // RTX SSRC. The NACK responder tags what it sends again, which is how
                        // a retransmission on the stream's own SSRC (no RTX negotiated) is
                        // told from a first transmission.
                        let payload_bytes = rtp_packet.payload.len();
                        let retransmission = packet
                            .message
                            .attributes
                            .iter()
                            .any(|attribute| matches!(attribute, Attribute::Retransmission));
                        self.stats.on_rtp_sent(
                            rtp_packet.header.ssrc,
                            rtp_packet.header.sequence_number,
                            rtp_packet.marshal_size() - payload_bytes,
                            payload_bytes,
                            retransmission,
                            packet.now,
                        );
                    }
                    _ => {}
                }

                // The ECN codepoint the application's socket layer sets on the datagram: ECT(1)
                // for the RTP packets of a stream that sends it, Not-ECT for everything else,
                // whatever context an interceptor copied onto the packet.
                packet.transport.ecn = match &packet.message.packet {
                    Packet::Rtp(rtp_packet) => self.stats.ecn_for_rtp_sent(
                        rtp_packet.header.ssrc,
                        rtp_packet.header.sequence_number,
                        packet.now,
                    ),
                    _ => None,
                };

                self.ctx.write_outs.push_back(TaggedRTCMessageInternal {
                    now: packet.now,
                    transport: packet.transport,
                    message: RTCMessageInternal::Rtp(RTPMessage::Packet(packet.message.packet)),
                });
                trace!("interceptor write {:?}", packet.transport.peer_addr);
            }
        }

        self.ctx.write_outs.pop_front()
    }

    fn handle_event(&mut self, evt: TaggedRTCEventInternal) -> Result<()> {
        if let RTCEventInternal::DTLSHandshakeComplete(_, _) = &evt.event {
            debug!("interceptor recv dtls handshake complete");
            let first = !self.ctx.is_dtls_handshake_complete;
            self.ctx.is_dtls_handshake_complete = true;
            if first {
                // The RTCP session joins when the transport is up, under the connection's
                // CNAME: an endpoint that only receives reports from then on, not from its
                // first inbound packet (RFC 3550 6.2).
                for control in [
                    RtcpSessionControl::Cname(self.ctx.cname.clone()),
                    RtcpSessionControl::Start,
                ] {
                    self.interceptor
                        .handle_write(control.into_packet(evt.now))?;
                }
            }
        }

        self.ctx.event_outs.push_back(evt);
        Ok(())
    }

    fn poll_event(&mut self) -> Option<Self::Eout> {
        // self.interceptor.poll_event(());

        self.ctx.event_outs.pop_front()
    }

    fn handle_timeout(&mut self, now: Instant) -> Result<()> {
        if self.ctx.is_dtls_handshake_complete {
            self.interceptor.handle_timeout(now)
        } else {
            Ok(())
        }
    }

    fn poll_timeout(&mut self) -> Option<Instant> {
        if self.ctx.is_dtls_handshake_complete {
            self.interceptor.poll_timeout()
        } else {
            None
        }
    }

    fn close(&mut self) -> Result<()> {
        self.interceptor.close()
    }
}

#[cfg(test)]
#[path = "interceptor_rtx_test.rs"]
mod interceptor_rtx_test;

#[cfg(test)]
#[path = "interceptor_sdes_test.rs"]
mod interceptor_sdes_test;

#[cfg(test)]
#[path = "interceptor_goodbye_test.rs"]
mod interceptor_goodbye_test;

#[cfg(test)]
#[path = "interceptor_repair_feedback_test.rs"]
mod interceptor_repair_feedback_test;

#[cfg(test)]
#[path = "interceptor_sources_test.rs"]
mod interceptor_sources_test;

#[cfg(test)]
#[path = "interceptor_association_test.rs"]
mod interceptor_association_test;

#[cfg(test)]
#[path = "interceptor_session_test.rs"]
mod interceptor_session_test;

#[cfg(test)]
mod boundary_tests {
    //! The last hop inbound: an attribute becomes a statistic.
    //!
    //! `Ein`/`Eout` on the interceptor trait are `()`, so an attribute riding on a packet is the
    //! only channel between interceptors. It carries information as far as the end of the chain and
    //! no further — these tests are about what happens at that end, where the congestion
    //! controller's estimate stops being chain business and becomes something `get_stats` reports.

    use super::*;
    use crate::statistics::accumulator::{
        InboundRtpStreamAccumulator, OutboundRtpStreamAccumulator,
    };
    use interceptor::{AttributedPacket, StreamInfo};
    use rtcp::payload_feedbacks::full_intra_request::{FirEntry, FullIntraRequest};
    use rtcp::payload_feedbacks::picture_loss_indication::PictureLossIndication;
    use rtcp::receiver_report::ReceiverReport;
    use rtcp::reception_report::ReceptionReport;
    use rtcp::sender_report::SenderReport;
    use rtcp::transport_feedbacks::transport_layer_nack::TransportLayerNack;
    use sansio::Protocol;
    use shared::TransportContext;

    /// A stand-in for a chain, so a test can put an arbitrary attribute on the read leg. A real
    /// chain cannot be made to emit one from outside, which is what needs checking here.
    #[derive(Default)]
    struct FakeChain {
        reads: VecDeque<TaggedPacket>,
        writes: VecDeque<TaggedPacket>,
    }

    impl Protocol<TaggedPacket, TaggedPacket, ()> for FakeChain {
        type Rout = TaggedPacket;
        type Wout = TaggedPacket;
        type Eout = ();
        type Error = Error;
        type Time = Instant;

        fn handle_read(&mut self, msg: TaggedPacket) -> Result<()> {
            self.reads.push_back(msg);
            Ok(())
        }
        fn poll_read(&mut self) -> Option<TaggedPacket> {
            self.reads.pop_front()
        }
        fn handle_write(&mut self, msg: TaggedPacket) -> Result<()> {
            self.writes.push_back(msg);
            Ok(())
        }
        fn poll_write(&mut self) -> Option<TaggedPacket> {
            self.writes.pop_front()
        }
        fn handle_event(&mut self, _: ()) -> Result<()> {
            Ok(())
        }
        fn poll_event(&mut self) -> Option<()> {
            None
        }
        fn handle_timeout(&mut self, _: Instant) -> Result<()> {
            Ok(())
        }
        fn poll_timeout(&mut self) -> Option<Instant> {
            None
        }
        fn close(&mut self) -> Result<()> {
            Ok(())
        }
    }

    impl Interceptor for FakeChain {
        fn bind_local_stream(&mut self, _: &StreamInfo) {}
        fn unbind_local_stream(&mut self, _: &StreamInfo) {}
        fn bind_remote_stream(&mut self, _: &StreamInfo) {}
        fn unbind_remote_stream(&mut self, _: &StreamInfo) {}
    }

    fn carrier(attribute: Attribute) -> TaggedPacket {
        TaggedPacket {
            now: Instant::now(),
            transport: TransportContext::default(),
            message: AttributedPacket::new(Packet::Rtcp(Vec::new())).with(attribute),
        }
    }

    /// A context past the handshake — before it, the handler bypasses the chain entirely.
    fn connected() -> InterceptorHandlerContext {
        InterceptorHandlerContext {
            is_dtls_handshake_complete: true,
            ..Default::default()
        }
    }

    /// The estimate lands in the stats, which is the whole of how it reaches an application.
    #[test]
    fn an_estimate_becomes_a_stat() {
        let mut ctx = connected();
        let mut chain = FakeChain::default();
        let mut stats = RTCStatsAccumulator::default();
        stats.outbound_rtp_streams.insert(
            7,
            OutboundRtpStreamAccumulator {
                ssrc: 7,
                ..Default::default()
            },
        );

        chain
            .handle_read(carrier(Attribute::TargetBitrateChanged {
                bits_per_second: 750_000.0,
            }))
            .expect("seed");

        let mut transceivers = vec![];
        let media_engine = MediaEngine::default();
        let mut handler = InterceptorHandler::new(
            &mut ctx,
            &mut transceivers,
            &media_engine,
            &mut chain,
            &mut stats,
        );
        let message = handler.poll_read();

        assert!(
            message.is_none(),
            "the carrier is not a message — an empty RTCP packet means nothing to an application"
        );
        assert_eq!(
            750_000.0, stats.outbound_rtp_streams[&7].target_bitrate,
            "the estimate must reach the stats, or nothing outside the chain ever learns it"
        );
    }

    /// A FEC-only RED packet reaches the end of the chain as an emptied RTP packet marked
    /// `UlpfecRepair`; media, marked or not, is delivered.
    #[test]
    fn a_fec_only_packet_does_not_reach_the_application() {
        let mut ctx = connected();
        let mut chain = FakeChain::default();
        let mut stats = RTCStatsAccumulator::default();
        let rtp_message = |sequence_number: u16| {
            AttributedPacket::new(Packet::Rtp(rtp::Packet {
                header: rtp::header::Header {
                    version: 2,
                    sequence_number,
                    ssrc: 7,
                    ..Default::default()
                },
                ..Default::default()
            }))
        };
        for message in [
            rtp_message(1),
            rtp_message(2).with(Attribute::Custom(std::sync::Arc::new(
                interceptor::UlpfecRepair,
            ))),
            rtp_message(3).with(Attribute::RecoveredByFec),
        ] {
            chain
                .handle_read(TaggedPacket {
                    now: Instant::now(),
                    transport: TransportContext::default(),
                    message,
                })
                .expect("seed");
        }

        let mut transceivers = vec![];
        let media_engine = MediaEngine::default();
        let mut handler = InterceptorHandler::new(
            &mut ctx,
            &mut transceivers,
            &media_engine,
            &mut chain,
            &mut stats,
        );
        let mut delivered = Vec::new();
        while let Some(message) = handler.poll_read() {
            if let RTCMessageInternal::Rtp(RTPMessage::Packet(Packet::Rtp(packet))) =
                message.message
            {
                delivered.push(packet.header.sequence_number);
            }
        }
        assert_eq!(vec![1, 3], delivered);
    }

    /// A per-packet attribute is chain business. `RecoveredByFec` tells the NACK generator not to
    /// ask for a packet again; an application has nothing to do with it, so it stops here.
    #[test]
    fn a_per_packet_attribute_changes_no_stats() {
        let mut ctx = connected();
        let mut chain = FakeChain::default();
        let mut stats = RTCStatsAccumulator::default();
        stats.outbound_rtp_streams.insert(
            7,
            OutboundRtpStreamAccumulator {
                ssrc: 7,
                ..Default::default()
            },
        );

        chain
            .handle_read(carrier(Attribute::RecoveredByFec))
            .expect("seed");

        let mut transceivers = vec![];
        let media_engine = MediaEngine::default();
        let mut handler = InterceptorHandler::new(
            &mut ctx,
            &mut transceivers,
            &media_engine,
            &mut chain,
            &mut stats,
        );
        while handler.poll_read().is_some() {}

        assert_eq!(
            0.0, stats.outbound_rtp_streams[&7].target_bitrate,
            "only the estimate writes this field"
        );
    }

    /// A real RTCP packet still reaches the application when it asked for one — the carrier drop
    /// keys on emptiness, not on RTCP.
    #[test]
    fn a_real_report_still_reaches_the_application() {
        let mut ctx = connected();
        let mut chain = FakeChain::default();
        let mut stats = RTCStatsAccumulator::default();

        chain
            .handle_read(TaggedPacket {
                now: Instant::now(),
                transport: TransportContext::default(),
                message: AttributedPacket::new(Packet::Rtcp(vec![Box::new(
                    ReceiverReport::default(),
                )])),
            })
            .expect("seed");

        let mut transceivers = vec![];
        let media_engine = MediaEngine::default();
        let mut handler = InterceptorHandler::new(
            &mut ctx,
            &mut transceivers,
            &media_engine,
            &mut chain,
            &mut stats,
        );

        assert!(
            handler.poll_read().is_some(),
            "dropping the carrier must not drop RTCP the application asked for"
        );
    }

    /// Feeds one incoming RTCP compound packet through `handle_read` and returns what the chain was
    /// handed, so a test can check both the stats and that the packet still went on into the chain.
    fn read_rtcp(
        stats: &mut RTCStatsAccumulator,
        now: Instant,
        packets: Vec<Box<dyn rtcp::Packet>>,
    ) -> VecDeque<TaggedPacket> {
        let mut ctx = connected();
        let mut chain = FakeChain::default();
        let mut transceivers = vec![];
        let media_engine = MediaEngine::default();
        let mut handler = InterceptorHandler::new(
            &mut ctx,
            &mut transceivers,
            &media_engine,
            &mut chain,
            stats,
        );
        handler
            .handle_read(TaggedRTCMessageInternal {
                now,
                transport: TransportContext::default(),
                message: RTCMessageInternal::Rtp(RTPMessage::Packet(Packet::Rtcp(packets))),
            })
            .expect("handle_read");
        chain.reads
    }

    fn outbound(ssrc: u32) -> OutboundRtpStreamAccumulator {
        OutboundRtpStreamAccumulator {
            ssrc,
            ..Default::default()
        }
    }

    /// A receiver report about one of our streams is counted before the chain gets it: the
    /// chain's terminus consumes it, so `poll_read` never would (#310).
    #[test]
    fn incoming_receiver_report_reaches_the_stats() {
        let now = Instant::now();
        let mut stats = RTCStatsAccumulator::default();
        stats.outbound_rtp_streams.insert(7, outbound(7));

        let reads = read_rtcp(
            &mut stats,
            now,
            vec![Box::new(ReceiverReport {
                reports: vec![ReceptionReport {
                    ssrc: 7,
                    fraction_lost: 64,
                    total_lost: 3,
                    last_sequence_number: 100,
                    jitter: 9,
                    ..Default::default()
                }],
                ..Default::default()
            })],
        );

        assert_eq!(1, reads.len(), "the report must still go into the chain");
        let stream = &stats.outbound_rtp_streams[&7];
        assert_eq!(3, stream.remote_packets_lost);
        assert_eq!(Some(9), stream.remote_jitter);
        assert_eq!(0.25, stream.remote_fraction_lost);
        assert_eq!(1, stream.remote_reports_received);
        // The report echoes no sender report (LSR 0), so it measures no round trip.
        assert_eq!(0, stream.rtt_measurements);

        let remote = stream.snapshot_remote(now);
        assert_eq!(3, remote.received_rtp_stream_stats.packets_lost);
        // No codec registered on the bare accumulator: the clock rate is unknown, so is the
        // jitter in seconds.
        assert_eq!(None, remote.received_rtp_stream_stats.jitter);
        assert_eq!(0.25, remote.fraction_lost);
    }

    /// NACK, PLI and FIR are feedback about our outbound stream and land in its counters.
    #[test]
    fn incoming_feedback_reaches_the_outbound_stats() {
        let mut stats = RTCStatsAccumulator::default();
        stats.outbound_rtp_streams.insert(7, outbound(7));

        let reads = read_rtcp(
            &mut stats,
            Instant::now(),
            vec![
                Box::new(PictureLossIndication {
                    media_ssrc: 7,
                    ..Default::default()
                }),
                Box::new(TransportLayerNack {
                    media_ssrc: 7,
                    ..Default::default()
                }),
                Box::new(FullIntraRequest {
                    fir: vec![FirEntry {
                        ssrc: 7,
                        sequence_number: 1,
                    }],
                    ..Default::default()
                }),
            ],
        );

        assert_eq!(1, reads.len(), "the feedback must still go into the chain");
        let stream = &stats.outbound_rtp_streams[&7];
        assert_eq!(1, stream.pli_count);
        assert_eq!(1, stream.nack_count);
        assert_eq!(1, stream.fir_count);
    }

    /// A sender report describes the remote sender of one of our inbound streams.
    #[test]
    fn incoming_sender_report_reaches_the_inbound_stats() {
        let now = Instant::now();
        let mut stats = RTCStatsAccumulator::default();
        stats.inbound_rtp_streams.insert(
            9,
            InboundRtpStreamAccumulator {
                ssrc: 9,
                ..Default::default()
            },
        );

        let reads = read_rtcp(
            &mut stats,
            now,
            vec![Box::new(SenderReport {
                ssrc: 9,
                packet_count: 10,
                octet_count: 1000,
                ..Default::default()
            })],
        );

        assert_eq!(1, reads.len(), "the report must still go into the chain");
        let stream = &stats.inbound_rtp_streams[&9];
        assert_eq!(10, stream.remote_packets_sent);
        assert_eq!(1000, stream.remote_bytes_sent);
        assert_eq!(Some(now), stream.remote_report_received_at);
        assert_eq!(1, stream.reports_received);
    }
}

#[cfg(test)]
mod stream_binding_tests {
    //! Binding an inbound stream to the interceptors, on the first packet that identifies it.
    //!
    //! These drive `InterceptorHandler::handle_read` rather than the chain directly, because the
    //! property under test is an *ordering*: the stream must be bound before the chain is handed
    //! the packet that resolved it. A test that called the chain itself could not tell the
    //! difference.

    use super::*;
    use crate::media_stream::track::MediaStreamTrack;
    use crate::peer_connection::configuration::media_engine::MIME_TYPE_RTX;
    use crate::rtp_transceiver::rtp_sender::{
        RTCRtpCodec, RTCRtpCodecParameters, RTCRtpEncodingParameters,
        RTCRtpHeaderExtensionCapability, RTCRtpRtxParameters, RtpCodecKind,
    };
    use crate::rtp_transceiver::{RTCRtpTransceiverDirection, RTCRtpTransceiverInit};
    use bytes::Bytes;
    use interceptor::StreamInfo;
    use sansio::Protocol as _;
    use shared::TransportContext;
    use std::sync::{Arc, Mutex};

    fn coding(primary_ssrc: u32, rtx_ssrc: Option<u32>) -> RTCRtpCodingParameters {
        RTCRtpCodingParameters {
            rid: String::new(),
            ssrc: Some(primary_ssrc),
            rtx: rtx_ssrc.map(|ssrc| RTCRtpRtxParameters { ssrc }),
            fec: None,
            ..Default::default()
        }
    }

    fn codec(payload_type: u8, mime_type: &str, fmtp: &str) -> RTCRtpCodecParameters {
        RTCRtpCodecParameters {
            rtp_codec: RTCRtpCodec {
                mime_type: mime_type.to_owned(),
                clock_rate: 90_000,
                channels: 0,
                sdp_fmtp_line: fmtp.to_owned(),
                rtcp_feedback: vec![],
            },
            payload_type,
        }
    }

    #[derive(Clone, Default)]
    struct Recorder {
        bound: Arc<Mutex<Vec<StreamInfo>>>,
        unbound: Arc<Mutex<Vec<StreamInfo>>>,
    }

    impl Recorder {
        fn bound_ssrcs(&self) -> Vec<u32> {
            self.bound
                .lock()
                .unwrap()
                .iter()
                .map(|info| info.ssrc)
                .collect()
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
            self.bound.lock().unwrap().push(info.clone());
        }
        fn unbind_remote_stream(&mut self, info: &StreamInfo) {
            self.unbound.lock().unwrap().push(info.clone());
        }
    }

    /// A receiver for a remote track whose SSRC was declared in the SDP but whose codec is not yet
    /// known — the state `RTCPeerConnection::start_rtp` leaves a declared-SSRC track in, with the
    /// codec deferred until the first RTP packet names a payload type.
    fn declared_ssrc_transceiver(
        ssrc: u32,
        payload_type: u8,
        rtx: Option<(u32, u8)>,
    ) -> RTCRtpTransceiverInternal {
        let mut transceiver = RTCRtpTransceiverInternal::new(
            RtpCodecKind::Video,
            None,
            RTCRtpTransceiverInit {
                direction: RTCRtpTransceiverDirection::Recvonly,
                streams: vec![],
                send_encodings: vec![],
            },
        );

        let mut preferences = vec![codec(payload_type, "video/VP8", "")];
        if let Some((_, rtx_payload_type)) = rtx {
            preferences.push(codec(
                rtx_payload_type,
                "video/rtx",
                &format!("apt={payload_type}"),
            ));
        }

        let receiver = transceiver.receiver_mut().as_mut().unwrap();
        receiver.set_coding_parameters(vec![coding(ssrc, rtx.map(|(rtx_ssrc, _)| rtx_ssrc))]);
        receiver.set_codec_preferences(preferences);
        receiver.set_track(MediaStreamTrack::new(
            "stream".to_string(),
            "track".to_string(),
            "label".to_string(),
            RtpCodecKind::Video,
            vec![RTCRtpEncodingParameters {
                rtp_coding_parameters: coding(ssrc, rtx.map(|(rtx_ssrc, _)| rtx_ssrc)),
                active: true,
                // Empty: not known until a packet arrives. This is the whole point.
                codec: RTCRtpCodec::default(),
                max_bitrate: 0,
                max_framerate: None,
                scale_resolution_down_by: None,
                priority: Default::default(),
                network_priority: None,
                scalability_mode: None,
            }],
        ));
        transceiver
    }

    /// A media engine that has negotiated VP8 and its RTX pairing.
    ///
    /// `MediaEngine::default()` registers nothing, and the repair payload type is resolved against
    /// the *negotiated* codecs — so with an empty engine `find_rtx_payload_type` returns `None`,
    /// no repair flow is ever recognised, and a test asserting one would fail for a reason that has
    /// nothing to do with binding.
    fn media_engine_with_rtx() -> MediaEngine {
        let mut media_engine = MediaEngine::default();
        media_engine
            .register_codec(codec(96, "video/VP8", ""), RtpCodecKind::Video)
            .expect("vp8");
        media_engine
            .register_codec(codec(97, MIME_TYPE_RTX, "apt=96"), RtpCodecKind::Video)
            .expect("rtx");
        media_engine
    }

    /// Drive `packets` RTP packets through `InterceptorHandler::handle_read`.
    ///
    /// The handler, not the chain directly: the property under test is that the stream is bound
    /// *before* the chain is handed the packet, and only the handler can get that wrong.
    fn feed(
        transceivers: &mut Vec<RTCRtpTransceiverInternal>,
        interceptor: &mut Recorder,
        ssrc: u32,
        payload_type: u8,
        packets: u16,
    ) {
        let media_engine = media_engine_with_rtx();
        let mut stats = RTCStatsAccumulator::new();
        let mut ctx = InterceptorHandlerContext {
            // Media is bypassed entirely until the handshake finishes, so without this the handler
            // would forward every packet untouched and each test would pass vacuously.
            is_dtls_handshake_complete: true,
            ..Default::default()
        };
        let mut handler = InterceptorHandler::new(
            &mut ctx,
            transceivers,
            &media_engine,
            interceptor,
            &mut stats,
        );

        for sequence_number in 1..=packets {
            let packet = rtp::Packet {
                header: rtp::Header {
                    payload_type,
                    sequence_number,
                    timestamp: 12_345,
                    ssrc,
                    ..Default::default()
                },
                payload: Bytes::from_static(&[0xDE, 0xAD]),
            };
            handler
                .handle_read(TaggedRTCMessageInternal {
                    now: Instant::now(),
                    transport: TransportContext::default(),
                    message: RTCMessageInternal::Rtp(RTPMessage::Packet(Packet::Rtp(packet))),
                })
                .expect("handle_read");
        }
    }

    /// A declared-SSRC remote stream reaches the interceptors once its codec resolves.
    ///
    /// The track is built from the remote SDP before any packet arrives, so its codec is empty then
    /// and the bind attempted at that point resolves nothing — see `RTCPeerConnection::start_rtp`.
    /// The first RTP packet is the first moment the stream can be described, and if it is not bound
    /// there it never is.
    ///
    /// The failure this guards against is silent: media flows perfectly and only the *feedback* is
    /// missing, because the interceptors that generate receiver reports, TWCC, NACK and PLI sit in
    /// the chain having never been told the stream exists. A publisher then sees its
    /// `remote-inbound-rtp` stats stay empty and quietly lowers its bitrate.
    #[test]
    fn a_declared_ssrc_stream_is_bound_when_its_codec_resolves() {
        let (ssrc, payload_type) = (1000u32, 96u8);
        let mut transceivers = vec![declared_ssrc_transceiver(ssrc, payload_type, None)];
        let recorder = Recorder::default();
        let mut interceptor = recorder.clone();

        feed(&mut transceivers, &mut interceptor, ssrc, payload_type, 1);

        assert_eq!(
            vec![ssrc],
            recorder.bound_ssrcs(),
            "the stream must be bound once its codec is known"
        );
    }

    /// Bound exactly once, however many packets arrive.
    ///
    /// The bind rides the same branch that resolves the codec, and that branch is guarded on the
    /// codec still being empty. Binding per packet would re-register the stream on every one,
    /// resetting whatever the interceptors keep per stream — sequence tracking, loss counters,
    /// jitter — so the feedback would be wrong rather than absent.
    #[test]
    fn a_declared_ssrc_stream_is_bound_only_once() {
        let (ssrc, payload_type) = (1000u32, 96u8);
        let mut transceivers = vec![declared_ssrc_transceiver(ssrc, payload_type, None)];
        let recorder = Recorder::default();
        let mut interceptor = recorder.clone();

        feed(&mut transceivers, &mut interceptor, ssrc, payload_type, 5);

        assert_eq!(
            vec![ssrc],
            recorder.bound_ssrcs(),
            "five packets, one bind: the codec is only unresolved once"
        );
    }

    /// The repair flow is bound in its own right, not merely named as an association on the primary.
    ///
    /// `interceptor_remote_streams_op` binds all three — primary, RTX, FEC — and `stop` unbinds all
    /// three. Binding only the primary here would leave the RTX stream unbound while still being
    /// unbound at teardown, and an interceptor tracking arrivals would never learn that the
    /// retransmission SSRC exists.
    #[test]
    fn a_declared_ssrc_stream_binds_its_repair_flow_too() {
        let (ssrc, payload_type) = (1000u32, 96u8);
        let (rtx_ssrc, rtx_payload_type) = (2000u32, 97u8);
        let mut transceivers = vec![declared_ssrc_transceiver(
            ssrc,
            payload_type,
            Some((rtx_ssrc, rtx_payload_type)),
        )];
        let recorder = Recorder::default();
        let mut interceptor = recorder.clone();

        feed(&mut transceivers, &mut interceptor, ssrc, payload_type, 1);

        assert_eq!(
            vec![ssrc, rtx_ssrc],
            recorder.bound_ssrcs(),
            "the primary and its retransmission stream are both real streams"
        );
    }

    /// A simulcast layer binds its repair flow in its own right, as the declared-SSRC path does.
    ///
    /// The RID path already bound the primary, naming the RTX SSRC as an *association* on it —
    /// which tells an interceptor which flow repairs which, not that a stream with its own SSRC and
    /// sequence-number space is arriving. Simulcast is where that matters most: every layer has its
    /// own retransmission flow, and NACK-driven repair is what keeps the upper layers usable.
    ///
    /// It also kept the pair unbalanced — `stop` unbinds all three per coding, so the repair flow
    /// was unbound having never been bound.
    #[test]
    fn a_simulcast_layer_binds_its_repair_flow_too() {
        let (ssrc, payload_type) = (1000u32, 96u8);
        let (rtx_ssrc, rtx_payload_type) = (2000u32, 97u8);

        let mut media_engine = media_engine_with_rtx();
        media_engine
            .register_header_extension(
                RTCRtpHeaderExtensionCapability {
                    uri: ::sdp::extmap::SDES_MID_URI.to_owned(),
                },
                RtpCodecKind::Video,
                None,
            )
            .expect("mid extension");
        media_engine
            .register_header_extension(
                RTCRtpHeaderExtensionCapability {
                    uri: ::sdp::extmap::SDES_RTP_STREAM_ID_URI.to_owned(),
                },
                RtpCodecKind::Video,
                None,
            )
            .expect("rid extension");

        // Registering makes an extension *offerable*; the handler resolves mid/rid through the
        // *negotiated* set, which SDP fills in. Negotiate them here, as an answer would.
        media_engine
            .update_header_extension(1, ::sdp::extmap::SDES_MID_URI, RtpCodecKind::Video)
            .expect("negotiate mid");
        media_engine
            .update_header_extension(
                2,
                ::sdp::extmap::SDES_RTP_STREAM_ID_URI,
                RtpCodecKind::Video,
            )
            .expect("negotiate rid");

        // Ask the engine which ids it assigned rather than assuming: the handler resolves mid/rid
        // through the same lookup, so a guess that disagreed would make this test fail for a
        // reason unrelated to binding.
        let (mid_extension_id, _, _) =
            media_engine.get_header_extension_id(RTCRtpHeaderExtensionCapability {
                uri: ::sdp::extmap::SDES_MID_URI.to_owned(),
            });
        let (rid_extension_id, _, _) =
            media_engine.get_header_extension_id(RTCRtpHeaderExtensionCapability {
                uri: ::sdp::extmap::SDES_RTP_STREAM_ID_URI.to_owned(),
            });

        // A layer whose SSRC is not yet known: the RID path is what learns it from the first packet.
        let mut transceiver = RTCRtpTransceiverInternal::new(
            RtpCodecKind::Video,
            None,
            RTCRtpTransceiverInit {
                direction: RTCRtpTransceiverDirection::Recvonly,
                streams: vec![],
                send_encodings: vec![],
            },
        );
        transceiver.set_mid("0".to_owned()).expect("mid");
        {
            let receiver = transceiver.receiver_mut().as_mut().unwrap();
            receiver.set_coding_parameters(vec![RTCRtpCodingParameters {
                rid: "h".to_owned(),
                ssrc: None,
                rtx: Some(RTCRtpRtxParameters { ssrc: rtx_ssrc }),
                fec: None,
                ..Default::default()
            }]);
            receiver.set_codec_preferences(vec![
                codec(payload_type, "video/VP8", ""),
                codec(
                    rtx_payload_type,
                    MIME_TYPE_RTX,
                    &format!("apt={payload_type}"),
                ),
            ]);
            receiver.set_track(MediaStreamTrack::new(
                "stream".to_string(),
                "track".to_string(),
                "label".to_string(),
                RtpCodecKind::Video,
                vec![RTCRtpEncodingParameters {
                    rtp_coding_parameters: RTCRtpCodingParameters {
                        rid: "h".to_owned(),
                        ssrc: None,
                        rtx: Some(RTCRtpRtxParameters { ssrc: rtx_ssrc }),
                        fec: None,
                        ..Default::default()
                    },
                    active: true,
                    codec: RTCRtpCodec::default(),
                    max_bitrate: 0,
                    max_framerate: None,
                    scale_resolution_down_by: None,
                    priority: Default::default(),
                    network_priority: None,
                    scalability_mode: None,
                }],
            ));
        }
        let mut transceivers = vec![transceiver];

        let recorder = Recorder::default();
        let mut interceptor = recorder.clone();
        let mut stats = RTCStatsAccumulator::new();
        let mut ctx = InterceptorHandlerContext {
            is_dtls_handshake_complete: true,
            ..Default::default()
        };

        let mut header = rtp::Header {
            extension: true,
            // One-byte extension form (RFC 8285). Without it the header is read as RFC 3550 and
            // rejects these ids outright.
            extension_profile: 0xBEDE,
            payload_type,
            sequence_number: 1,
            timestamp: 12_345,
            ssrc,
            ..Default::default()
        };
        header
            .set_extension(mid_extension_id as u8, Bytes::from_static(b"0"))
            .expect("mid extension");
        header
            .set_extension(rid_extension_id as u8, Bytes::from_static(b"h"))
            .expect("rid extension");

        {
            let mut handler = InterceptorHandler::new(
                &mut ctx,
                &mut transceivers,
                &media_engine,
                &mut interceptor,
                &mut stats,
            );
            handler
                .handle_read(TaggedRTCMessageInternal {
                    now: Instant::now(),
                    transport: TransportContext::default(),
                    message: RTCMessageInternal::Rtp(RTPMessage::Packet(Packet::Rtp(
                        rtp::Packet {
                            header,
                            payload: Bytes::from_static(&[0xDE, 0xAD]),
                        },
                    ))),
                })
                .expect("handle_read");
        }

        assert_eq!(
            vec![ssrc, rtx_ssrc],
            recorder.bound_ssrcs(),
            "the layer and its retransmission stream are both real streams"
        );
    }

    /// A media engine with VP8 + RTX and the mid / rid header extensions negotiated, and a
    /// receiving transceiver (mid "0") with one simulcast layer "h" whose SSRC is not yet known.
    /// Returns the engine, the transceiver and the mid / rid extension ids.
    fn simulcast_receiver(rtx_ssrc: u32) -> (MediaEngine, RTCRtpTransceiverInternal, u8, u8) {
        let (payload_type, rtx_payload_type) = (96u8, 97u8);
        let mut media_engine = media_engine_with_rtx();
        for uri in [
            ::sdp::extmap::SDES_MID_URI,
            ::sdp::extmap::SDES_RTP_STREAM_ID_URI,
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
        media_engine
            .update_header_extension(1, ::sdp::extmap::SDES_MID_URI, RtpCodecKind::Video)
            .expect("negotiate mid");
        media_engine
            .update_header_extension(
                2,
                ::sdp::extmap::SDES_RTP_STREAM_ID_URI,
                RtpCodecKind::Video,
            )
            .expect("negotiate rid");
        let (mid_extension_id, _, _) =
            media_engine.get_header_extension_id(RTCRtpHeaderExtensionCapability {
                uri: ::sdp::extmap::SDES_MID_URI.to_owned(),
            });
        let (rid_extension_id, _, _) =
            media_engine.get_header_extension_id(RTCRtpHeaderExtensionCapability {
                uri: ::sdp::extmap::SDES_RTP_STREAM_ID_URI.to_owned(),
            });

        let layer = RTCRtpCodingParameters {
            rid: "h".to_owned(),
            ssrc: None,
            rtx: Some(RTCRtpRtxParameters { ssrc: rtx_ssrc }),
            fec: None,
            ..Default::default()
        };
        let mut transceiver = RTCRtpTransceiverInternal::new(
            RtpCodecKind::Video,
            None,
            RTCRtpTransceiverInit {
                direction: RTCRtpTransceiverDirection::Recvonly,
                streams: vec![],
                send_encodings: vec![],
            },
        );
        transceiver.set_mid("0".to_owned()).expect("mid");
        {
            let receiver = transceiver.receiver_mut().as_mut().unwrap();
            receiver.set_coding_parameters(vec![layer.clone()]);
            receiver.set_codec_preferences(vec![
                codec(payload_type, "video/VP8", ""),
                codec(
                    rtx_payload_type,
                    MIME_TYPE_RTX,
                    &format!("apt={payload_type}"),
                ),
            ]);
            receiver.set_track(MediaStreamTrack::new(
                "stream".to_string(),
                "track".to_string(),
                "label".to_string(),
                RtpCodecKind::Video,
                vec![RTCRtpEncodingParameters {
                    rtp_coding_parameters: layer,
                    active: true,
                    codec: RTCRtpCodec::default(),
                    max_bitrate: 0,
                    max_framerate: None,
                    scale_resolution_down_by: None,
                    priority: Default::default(),
                    network_priority: None,
                    scalability_mode: None,
                }],
            ));
        }
        (
            media_engine,
            transceiver,
            mid_extension_id as u8,
            rid_extension_id as u8,
        )
    }

    /// A simulcast layer that keeps arriving under new SSRCs holds one bound stream: the stream
    /// it leaves is unbound and its stats dropped, and it moves at most once per
    /// `MIN_RID_SSRC_REBIND_INTERVAL`, so the bindings, stats entries and `OnTrack` events stay
    /// bounded.
    #[test]
    fn a_simulcast_layer_moving_to_new_ssrcs_holds_one_stream() {
        let rtx_ssrc = 2000u32;
        let (media_engine, transceiver, mid_id, rid_id) = simulcast_receiver(rtx_ssrc);
        let mut transceivers = vec![transceiver];
        let recorder = Recorder::default();
        let mut interceptor = recorder.clone();
        let mut stats = RTCStatsAccumulator::new();
        let mut ctx = InterceptorHandlerContext {
            is_dtls_handshake_complete: true,
            ..Default::default()
        };

        let start = Instant::now();
        let mut feed_one = |ctx: &mut InterceptorHandlerContext,
                            stats: &mut RTCStatsAccumulator,
                            now: Instant,
                            ssrc: u32| {
            let mut header = rtp::Header {
                extension: true,
                extension_profile: 0xBEDE,
                payload_type: 96,
                sequence_number: 1,
                timestamp: 12_345,
                ssrc,
                ..Default::default()
            };
            header
                .set_extension(mid_id, Bytes::from_static(b"0"))
                .expect("mid extension");
            header
                .set_extension(rid_id, Bytes::from_static(b"h"))
                .expect("rid extension");
            let mut handler = InterceptorHandler::new(
                ctx,
                &mut transceivers,
                &media_engine,
                &mut interceptor,
                stats,
            );
            handler
                .handle_read(TaggedRTCMessageInternal {
                    now,
                    transport: TransportContext::default(),
                    message: RTCMessageInternal::Rtp(RTPMessage::Packet(Packet::Rtp(
                        rtp::Packet {
                            header,
                            payload: Bytes::from_static(&[0xDE, 0xAD]),
                        },
                    ))),
                })
                .expect("handle_read");
        };

        // The first SSRC establishes the layer; a flood of others right after it does not move it.
        for ssrc in 10_000u32..12_000 {
            feed_one(&mut ctx, &mut stats, start, ssrc);
        }
        assert_eq!(vec![10_000, rtx_ssrc], recorder.bound_ssrcs());
        assert!(recorder.unbound.lock().unwrap().is_empty());
        assert_eq!(stats.inbound_rtp_streams.len(), 1);
        assert!(stats.inbound_rtp_streams.contains_key(&10_000));
        assert_eq!(ctx.event_outs.len(), 1, "one OnTrack for one layer");
        assert!(ctx.ssrc_owners.len() <= 1);

        // Once the interval has passed the layer may move, and the stream it leaves is unbound.
        let later = start + MIN_RID_SSRC_REBIND_INTERVAL;
        feed_one(&mut ctx, &mut stats, later, 20_000);
        for ssrc in 20_001u32..21_000 {
            feed_one(&mut ctx, &mut stats, later, ssrc);
        }
        assert_eq!(
            vec![10_000, rtx_ssrc, 20_000, rtx_ssrc],
            recorder.bound_ssrcs()
        );
        let unbound: Vec<u32> = recorder
            .unbound
            .lock()
            .unwrap()
            .iter()
            .map(|info| info.ssrc)
            .collect();
        assert_eq!(vec![10_000], unbound);
        assert_eq!(stats.inbound_rtp_streams.len(), 1);
        assert!(stats.inbound_rtp_streams.contains_key(&20_000));
        assert_eq!(ctx.event_outs.len(), 2);
        assert!(ctx.ssrc_owners.len() <= 1);
        assert!(ctx.rid_rebinds.len() <= 1);
    }
}
