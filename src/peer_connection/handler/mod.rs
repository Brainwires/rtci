pub(crate) mod datachannel;
pub(crate) mod demuxer;
pub(crate) mod dtls;
pub(crate) mod endpoint;
pub(crate) mod ice;
pub(crate) mod interceptor;
pub(crate) mod sctp;
pub(crate) mod srtp;
pub(crate) mod transport_set;

use crate::peer_connection::RTCPeerConnection;
use crate::peer_connection::event::{RTCEventInternal, TaggedRTCEvent};
use crate::peer_connection::event::{
    RTCPeerConnectionEvent, RTCPeerConnectionIceEvent, RTCTransportEventKind,
};
use crate::peer_connection::handler::datachannel::{DataChannelHandler, DataChannelHandlerContext};
use crate::peer_connection::handler::demuxer::{DemuxerHandler, DemuxerHandlerContext};
use crate::peer_connection::handler::dtls::DtlsHandler;
use crate::peer_connection::handler::endpoint::{EndpointHandler, EndpointHandlerContext};
use crate::peer_connection::handler::ice::IceHandler;
use crate::peer_connection::handler::interceptor::{InterceptorHandler, InterceptorHandlerContext};
use crate::peer_connection::handler::sctp::{SctpHandler, SctpHandlerContext};
use crate::peer_connection::handler::srtp::SrtpHandler;
use crate::peer_connection::handler::transport_set::{TransportId, TransportSet};
use crate::peer_connection::message::{
    RTCMessage, TaggedRTCMessage,
    internal::{
        ApplicationMessage, DTLSMessage, DataChannelEvent, RTCMessageInternal, RTPMessage,
        TaggedRTCMessageInternal,
    },
};
use crate::peer_connection::state::peer_connection_state::RTCPeerConnectionState;
use crate::peer_connection::state::signaling_state::RTCSignalingState;
use crate::peer_connection::transport::sctp::SctpPath;
use crate::statistics::accumulator::RTCStatsAccumulator;
use ::interceptor::Packet;
use log::warn;
use shared::TaggedBytesMut;
use shared::error::{Error, flatten_errs};
use std::collections::VecDeque;
use std::time::Instant;

/// Forward handler list - invokes callback with handler list
macro_rules! forward_handlers {
    ($callback:ident!($($args:tt)*)) => {
        $callback!(
            $($args)*,
            [
                get_demuxer_handler,
                get_ice_handler,
                get_dtls_handler,
                get_sctp_handler,
                get_datachannel_handler,
                get_srtp_handler,
                get_interceptor_handler,
                get_endpoint_handler
            ]
        )
    };
}

/// Helper macro that processes a list of handlers with code blocks
macro_rules! process_handler_list {
    (call_macro: process_handler!($self:expr, $handler:ident, $code:block), [$($getter:ident),+]) => {{
        $(
            {
                let mut $handler = $self.$getter();
                $code
            }
        )+
    }};
}

/// Unified macro to iterate over handlers with code blocks
macro_rules! for_each_handler {
    // Forward order: execute code block for each handler
    (forward: $macro:ident!($($args:tt)*)) => {
        forward_handlers!(process_handler_list!(call_macro: $macro!($($args)*)))
    };
}

pub(crate) struct PipelineContext {
    // Handler contexts
    pub(crate) demuxer_handler_context: DemuxerHandlerContext,
    /// The ICE, DTLS and SRTP contexts, one set per transport.
    pub(crate) transports: TransportSet,
    pub(crate) sctp_handler_context: SctpHandlerContext,
    pub(crate) datachannel_handler_context: DataChannelHandlerContext,
    pub(crate) interceptor_handler_context: InterceptorHandlerContext,
    pub(crate) endpoint_handler_context: EndpointHandlerContext,

    // Pipeline
    /// Media (RTP/RTCP) ready for the application.
    ///
    /// Split from data-channel output deliberately. Back-pressure is applied by *not draining
    /// a queue* — that is what grows [`Self::data_read_outs`], bounds the SCTP drain,
    /// lowers `a_rwnd` and throttles the peer. While both kinds shared one queue, a caller
    /// applying that back-pressure necessarily stopped draining media too, so a slow
    /// data-channel consumer froze video on the same connection for as long as it stalled —
    /// video that arrives over SRTP and is subject to none of SCTP's flow control.
    pub(crate) media_read_outs: VecDeque<TaggedRTCMessage>,
    /// Data-channel messages ready for the application.
    ///
    /// Its length *is* the back-pressure signal the SCTP handler bounds against, so a caller
    /// that declines to drain it throttles the peer — and nothing else. No counter to keep in
    /// step with it: the queue is the count.
    pub(crate) data_read_outs: VecDeque<TaggedRTCMessage>,
    pub(crate) write_outs: VecDeque<TaggedBytesMut>,
    pub(crate) event_outs: VecDeque<RTCPeerConnectionEvent>,

    // Statistics accumulator
    pub(crate) stats: RTCStatsAccumulator,

    /// The `iceConnectionState` last announced: the aggregate over the transports (W3C
    /// 4.3.4), told when it changes.
    pub(crate) announced_ice_connection_state:
        crate::peer_connection::state::ice_connection_state::RTCIceConnectionState,

    /// The newest instant the pipeline has been given, through a datagram, a write or a timeout.
    ///
    /// `close()` takes no time of its own, and this crate reads no clock, so the `close_notify`
    /// it sends is stamped with this.
    pub(crate) now: Instant,
}

impl PipelineContext {
    pub(crate) fn observe(&mut self, now: Instant) {
        self.now = self.now.max(now);
    }
}

impl RTCPeerConnection {
    /*
     Pipeline Flow (Read Path):
     Raw Bytes -> Demuxer -> ICE -> DTLS -> SCTP -> DataChannel -> SRTP -> Interceptor -> Endpoint -> Application

     Pipeline Flow (Write Path):
     Application -> Endpoint -> Interceptor -> SRTP -> DataChannel -> SCTP -> DTLS -> ICE -> Demuxer -> Raw Bytes
    */

    /// An event leaves for the application. A local candidate's `OnIceCandidateEvent` is the
    /// application's to trickle: from here on the candidate counts as conveyed and the agent
    /// pairs it (RFC 8838 section 10).
    fn hand_out_event(&mut self, evt: RTCPeerConnectionEvent) -> RTCPeerConnectionEvent {
        if let RTCPeerConnectionEvent::OnIceCandidateEvent(RTCPeerConnectionIceEvent {
            candidate: Some(candidate),
            ..
        }) = &evt
        {
            // The candidate is of the transport whose ufrag it carries (each transport has
            // its own agent, RFC 9429 section 5.2.1).
            let ufrag = candidate.username_fragment.clone();
            for bundle in self.pipeline_context.transports.iter_mut() {
                let agent = &mut bundle.ice_handler_context.ice_transport.agent;
                if ufrag
                    .as_ref()
                    .is_none_or(|u| *u == agent.get_local_credentials().ufrag)
                {
                    agent.local_candidate_conveyed(&candidate.id);
                }
            }
        }
        evt
    }

    pub(crate) fn get_demuxer_handler(&mut self) -> DemuxerHandler<'_> {
        DemuxerHandler::new(
            &mut self.pipeline_context.demuxer_handler_context,
            &mut self.pipeline_context.stats,
        )
    }

    pub(crate) fn get_ice_handler(&mut self) -> IceHandler<'_> {
        IceHandler::new(
            &mut self
                .pipeline_context
                .transports
                .active_mut()
                .ice_handler_context,
            &mut self.pipeline_context.stats,
        )
    }

    pub(crate) fn get_dtls_handler(&mut self) -> DtlsHandler<'_> {
        DtlsHandler::new(
            &mut self
                .pipeline_context
                .transports
                .active_mut()
                .dtls_handler_context,
            &mut self.pipeline_context.stats,
        )
    }

    /// Next media (RTP/RTCP) message for the application, if any.
    ///
    /// Never affected by data-channel back-pressure. Media arrives over SRTP and is subject to
    /// none of SCTP's flow control, so a caller throttling a slow data-channel consumer must
    /// still be able to deliver video — draining this is how.
    ///
    /// Most callers should use [`poll_read`](sansio::Protocol::poll_read), which interleaves
    /// media and data-channel messages by the instant each was observed. Reach for this split
    /// pair only to drain one kind without the other.
    #[doc(hidden)]
    pub fn poll_media_read(&mut self) -> Option<TaggedRTCMessage> {
        self.pipeline_context.media_read_outs.pop_front()
    }

    /// Next data-channel message for the application, if any.
    ///
    /// **Declining to call this is how back-pressure is applied.** Undrained messages leave
    /// bytes in SCTP's reassembly queue, which lowers the receiver-window credit advertised in
    /// every SACK, which tells the peer to slow down. Stop calling it while the application is
    /// behind, resume when it catches up.
    ///
    /// Most callers should use [`poll_read`](sansio::Protocol::poll_read), which interleaves
    /// media and data-channel messages by the instant each was observed; declining to call
    /// *that* applies the same back-pressure. Reach for this split pair only to drain one kind
    /// without the other.
    #[doc(hidden)]
    pub fn poll_data_read(&mut self) -> Option<TaggedRTCMessage> {
        self.pipeline_context.data_read_outs.pop_front()
    }

    pub(crate) fn get_sctp_handler(&mut self) -> SctpHandler<'_> {
        // The SCTP handler bounds how much it pulls out of the reassembly queues against what
        // the application has not yet consumed. That backlog lives here, not in the handler's
        // own `read_outs` — the pipeline empties that within a single `handle_read` — and it
        // is data-channel output only, so unrelated media cannot throttle SCTP.
        let downstream_backlog = self.pipeline_context.data_read_outs.len();
        // The path under SCTP is looked at again only when ICE selected a pair or a DTLS
        // handshake completed since it was last looked at: a comparison, not work, per call.
        let selected_pair_changes = self
            .pipeline_context
            .transports
            .data_transport()
            .ice_handler_context
            .selected_pair_changes;
        let path = self
            .pipeline_context
            .sctp_handler_context
            .take_path_refresh(selected_pair_changes)
            .then(|| self.sctp_path());
        let mut handler = SctpHandler::new(
            &mut self.pipeline_context.sctp_handler_context,
            downstream_backlog,
        );
        if let Some(path) = path {
            handler.apply_path(path);
        }
        handler
    }

    /// What lies under the SCTP association: the selected candidate pair (its address
    /// family, its transport, whether this side's candidate is relayed) and what the DTLS
    /// version and cipher suite add to a record. `None` while no pair is selected.
    fn sctp_path(&self) -> Option<SctpPath> {
        let data = self.pipeline_context.transports.data_transport();
        let (local, remote) = data
            .ice_handler_context
            .ice_transport
            .agent
            .get_selected_candidate_pair()?;
        // The record overhead of the version and suite negotiated (a DTLS 1.3 record is
        // smaller than a DTLS 1.2 one).
        let dtls_record_overhead = data
            .dtls_handler_context
            .dtls_transport
            .dtls_endpoint
            .as_ref()
            .and_then(|endpoint| {
                endpoint.record_overhead(shared::TransportContext::default().peer_addr)
            })
            .unwrap_or(SctpPath::DEFAULT_DTLS_RECORD_OVERHEAD);
        Some(SctpPath {
            ipv6: remote.addr().is_ipv6(),
            tcp: local.network_type().is_tcp(),
            relayed: local.candidate_type() == ::ice::candidate::CandidateType::Relay,
            dtls_record_overhead,
        })
    }

    pub(crate) fn get_datachannel_handler(&mut self) -> DataChannelHandler<'_> {
        // Read the Copy values before `&mut self.data_channels` borrows self mutably. The
        // handler needs the DTLS role to give stream ids the parity RFC 8832 §6 requires, and
        // the negotiated stream count to bound them.
        let dtls_role = self
            .pipeline_context
            .transports
            .data_transport()
            .dtls_handler_context
            .dtls_transport
            .role();
        let max_channels = self.sctp_transport().max_channels();
        DataChannelHandler::new(
            &mut self.pipeline_context.datachannel_handler_context,
            &mut self.data_channels,
            &mut self.pipeline_context.stats,
            self.setting_engine.data_channel.dcep_handshake_timeout,
            dtls_role,
            max_channels,
        )
    }

    pub(crate) fn get_srtp_handler(&mut self) -> SrtpHandler<'_> {
        SrtpHandler::new(
            &mut self
                .pipeline_context
                .transports
                .active_mut()
                .srtp_handler_context,
        )
    }

    pub(crate) fn get_interceptor_handler(&mut self) -> InterceptorHandler<'_> {
        let transports = &self.pipeline_context.transports;
        let rtp_session = (transports.len() > 1).then(|| transports.active_id().0);
        InterceptorHandler::new(
            &mut self.pipeline_context.interceptor_handler_context,
            &mut self.rtp_transceivers,
            &self.media_engine,
            &mut self.interceptor,
            &mut self.pipeline_context.stats,
            rtp_session,
        )
    }

    pub(crate) fn get_endpoint_handler(&mut self) -> EndpointHandler<'_> {
        EndpointHandler::new(
            &mut self.pipeline_context.endpoint_handler_context,
            &mut self.rtp_transceivers,
            &mut self.pipeline_context.stats,
        )
    }

    /// Runs every handler's pending writes down the pipeline into `write_outs`, where
    /// [`poll_write`](sansio::Protocol::poll_write) hands them out.
    /// Queues a data channel's close behind the messages the application has already sent on
    /// it: they enter the pipeline at the endpoint too, and a close that went straight to the
    /// channel reset its SCTP stream ahead of them (RFC 8831 section 6.7: the reset follows the
    /// data), so the peer received none of it.
    pub(crate) fn write_data_channel_close(
        &mut self,
        data_channel_id: crate::data_channel::RTCDataChannelId,
    ) -> Result<(), Error> {
        use sansio::Protocol;

        let now = self.pipeline_context.now;
        let mut endpoint_handler = self.get_endpoint_handler();
        endpoint_handler.handle_write(TaggedRTCMessageInternal {
            now,
            transport: Default::default(),
            message: RTCMessageInternal::Dtls(DTLSMessage::DataChannel(ApplicationMessage {
                data_channel_id,
                data_channel_event: DataChannelEvent::Close,
            })),
        })
    }

    pub(crate) fn flush_writes(&mut self) {
        use sansio::Protocol;

        // The stages above SRTP are the connection's: they run once.
        let mut intermediate_wouts = VecDeque::new();
        process_handler_list!(call_macro: process_handler!(self, handler, {
            while let Some(msg) = intermediate_wouts.pop_front() {
                if let Err(err) = handler.handle_write(msg) {
                    warn!("{}.handle_write got error: {}", handler.name(), err);
                }
            }
            while let Some(msg) = handler.poll_write() {
                intermediate_wouts.push_back(msg);
            }
        }), [get_endpoint_handler, get_interceptor_handler]);

        // SRTP and below are each transport's: a packet goes down the transport of the m=
        // section its SSRC belongs to, data channel messages down the one SCTP runs over
        // (RFC 9143 section 9; RFC 9429 section 5.2.1: a transport per unbundled section).
        let ids = self.pipeline_context.transports.ids();
        let data = self.pipeline_context.transports.data_transport_id();
        let mut per_transport: Vec<VecDeque<TaggedRTCMessageInternal>> =
            ids.iter().map(|_| VecDeque::new()).collect();
        while let Some(msg) = intermediate_wouts.pop_front() {
            let id = if ids.len() == 1 {
                ids[0]
            } else {
                self.transport_of_write(&msg).unwrap_or(data)
            };
            let index = ids.iter().position(|t| *t == id).unwrap_or(0);
            per_transport[index].push_back(msg);
        }

        for (id, mut wouts) in ids.into_iter().zip(per_transport) {
            let previous = self.pipeline_context.transports.active_id();
            self.pipeline_context.activate_transport(id);
            process_handler_list!(call_macro: process_handler!(self, handler, {
                while let Some(msg) = wouts.pop_front() {
                    if let Err(err) = handler.handle_write(msg) {
                        warn!("{}.handle_write got error: {}", handler.name(), err);
                    }
                }
                while let Some(msg) = handler.poll_write() {
                    wouts.push_back(msg);
                }
            }), [get_srtp_handler]);
            if id == data {
                process_handler_list!(call_macro: process_handler!(self, handler, {
                    while let Some(msg) = wouts.pop_front() {
                        if let Err(err) = handler.handle_write(msg) {
                            warn!("{}.handle_write got error: {}", handler.name(), err);
                        }
                    }
                    while let Some(msg) = handler.poll_write() {
                        wouts.push_back(msg);
                    }
                }), [get_datachannel_handler, get_sctp_handler]);
            }
            process_handler_list!(call_macro: process_handler!(self, handler, {
                while let Some(msg) = wouts.pop_front() {
                    if let Err(err) = handler.handle_write(msg) {
                        warn!("{}.handle_write got error: {}", handler.name(), err);
                    }
                }
                while let Some(msg) = handler.poll_write() {
                    wouts.push_back(msg);
                }
            }), [get_dtls_handler, get_ice_handler, get_demuxer_handler]);
            self.pipeline_context.activate_transport(previous);

            // Final poll write out to pipeline's write out; what leaves from one of the
            // engine's ICE-TCP candidates goes onto that transport's connection instead.
            while let Some(msg) = wouts.pop_front() {
                if let RTCMessageInternal::Raw(message) = msg.message
                    && let Some(out) = self.take_tcp_write(
                        id,
                        TaggedBytesMut {
                            now: msg.now,
                            transport: msg.transport,
                            message,
                        },
                    )
                {
                    self.pipeline_context.write_outs.push_back(out);
                }
            }
        }
    }

    /// The transport an RTP or RTCP packet on its way to SRTP goes down: that of the m=
    /// section of its SSRC (the sender's or receiver's whose stream it is, or that an RTCP
    /// packet reports on). `None` for anything else, and for an SSRC no section has.
    fn transport_of_write(&self, msg: &TaggedRTCMessageInternal) -> Option<TransportId> {
        let ssrcs: Vec<u32> = match &msg.message {
            RTCMessageInternal::Rtp(RTPMessage::Packet(Packet::Rtp(packet))) => {
                vec![packet.header.ssrc]
            }
            RTCMessageInternal::Rtp(RTPMessage::Packet(Packet::Rtcp(packets))) => packets
                .iter()
                .flat_map(|packet| packet.destination_ssrc())
                .collect(),
            _ => return None,
        };
        ssrcs
            .into_iter()
            .find_map(|ssrc| self.transport_of_ssrc(ssrc))
    }

    /// The transport of the m= section whose sender or receiver has `ssrc` (its media, RTX or
    /// FEC stream).
    pub(crate) fn transport_of_ssrc(&self, ssrc: u32) -> Option<TransportId> {
        let has = |coding: &crate::rtp_transceiver::rtp_sender::RTCRtpCodingParameters| {
            coding.ssrc == Some(ssrc)
                || coding.rtx.as_ref().is_some_and(|rtx| rtx.ssrc == ssrc)
                || coding.fec.as_ref().is_some_and(|fec| fec.ssrc == ssrc)
        };
        self.rtp_transceivers.iter().find_map(|transceiver| {
            let mid = transceiver.mid().as_ref()?;
            let sends = transceiver.sender().as_ref().is_some_and(|sender| {
                sender
                    .send_encodings()
                    .iter()
                    .any(|encoding| has(&encoding.rtp_coding_parameters))
            });
            let receives = transceiver
                .receiver()
                .as_ref()
                .is_some_and(|receiver| receiver.get_coding_parameters().iter().any(&has));
            (sends || receives).then(|| self.pipeline_context.transports.transport_id_for(mid))
        })
    }

    /// Runs the pipeline's reads: `msg` up the active transport, or, without one, what every
    /// transport's handlers have queued.
    fn pump_reads(&mut self, msg: Option<TaggedRTCMessageInternal>) {
        if msg.is_some() || self.pipeline_context.transports.len() == 1 {
            self.pump_reads_on_active(msg);
            return;
        }
        for id in self.pipeline_context.transports.ids() {
            self.with_transport(id, |pc| pc.pump_reads_on_active(None));
        }
    }

    fn pump_reads_on_active(&mut self, msg: Option<TaggedRTCMessageInternal>) {
        // RFC 9143 section 9.2: an unknown SSRC is looked up in the tables of the transport
        // (the BUNDLE group, or the section) it arrived on.
        self.pipeline_context
            .interceptor_handler_context
            .arrival_mids = self.active_transport_mids();
        let mut intermediate_routs = VecDeque::<TaggedRTCMessageInternal>::new();

        if let Some(msg) = msg {
            intermediate_routs.push_back(msg);
        }

        use sansio::Protocol;
        // SCTP and the data channels are on the data transport only: another transport's
        // DTLS carries none of their packets, and its events are not theirs.
        let carries_data = self.active_carries_data();
        process_handler_list!(call_macro: process_handler!(self, handler, {
            while let Some(msg) = intermediate_routs.pop_front() {
                if let Err(err) = handler.handle_read(msg) {
                    warn!("{}.handle_read got error: {}", handler.name(), err);
                }
            }
            while let Some(msg) = handler.poll_read() {
                intermediate_routs.push_back(msg);
            }
        }), [get_demuxer_handler, get_ice_handler, get_dtls_handler]);
        if carries_data {
            process_handler_list!(call_macro: process_handler!(self, handler, {
            while let Some(msg) = intermediate_routs.pop_front() {
                if let Err(err) = handler.handle_read(msg) {
                    warn!("{}.handle_read got error: {}", handler.name(), err);
                }
            }
            while let Some(msg) = handler.poll_read() {
                intermediate_routs.push_back(msg);
            }
        }), [get_sctp_handler, get_datachannel_handler]);
        }
        process_handler_list!(call_macro: process_handler!(self, handler, {
            while let Some(msg) = intermediate_routs.pop_front() {
                if let Err(err) = handler.handle_read(msg) {
                    warn!("{}.handle_read got error: {}", handler.name(), err);
                }
            }
            while let Some(msg) = handler.poll_read() {
                intermediate_routs.push_back(msg);
            }
        }), [get_srtp_handler, get_interceptor_handler, get_endpoint_handler]);

        // Finally, put intermediate_routs into RTCPeerConnection's routs
        while let Some(msg) = intermediate_routs.pop_front() {
            let rtc_message = match msg.message {
                RTCMessageInternal::Dtls(DTLSMessage::DataChannel(application_message)) => {
                    if let DataChannelEvent::Message(data_channel_message) =
                        application_message.data_channel_event
                    {
                        Some(RTCMessage::DataChannelMessage(
                            application_message.data_channel_id,
                            data_channel_message,
                        ))
                    } else {
                        None
                    }
                }
                RTCMessageInternal::Rtp(RTPMessage::TrackPacket(track_packet)) => {
                    match track_packet.packet {
                        Packet::Rtp(packet) => {
                            Some(RTCMessage::RtpPacket(track_packet.track_id, packet))
                        }
                        Packet::Rtcp(packet) => {
                            Some(RTCMessage::RtcpPacket(track_packet.track_id, packet))
                        }
                        _ => None,
                    }
                }
                _ => None,
            };

            if let Some(rtc_message) = rtc_message {
                // The instant travels with the message: the application learns when the packet
                // was observed at the socket, not when it happened to drain it.
                let tagged = TaggedRTCMessage {
                    now: msg.now,
                    message: rtc_message,
                };
                // Routed by kind, so a caller can decline data-channel output — the only way
                // to apply SCTP back-pressure — without also declining media.
                match &tagged.message {
                    RTCMessage::DataChannelMessage(..) => {
                        self.pipeline_context.data_read_outs.push_back(tagged)
                    }
                    _ => self.pipeline_context.media_read_outs.push_back(tagged),
                }
            }
        }
    }

    /// Whether the active transport is the one the SCTP association runs over.
    fn active_carries_data(&self) -> bool {
        let transports = &self.pipeline_context.transports;
        transports.active_id() == transports.data_transport_id()
    }

    /// Returns whether any handler raised an event during the sweep, of any transport.
    fn pump_events(&mut self) -> bool {
        let mut raised = false;
        for id in self.pipeline_context.transports.ids() {
            raised |= self.with_transport(id, |pc| pc.pump_events_on_active());
        }
        // The SCTP transport's state follows its association, which any event may have moved;
        // the selected pair is the agent's, whose change event the DTLS handler consumes.
        self.announce_transport_states();
        if !self.is_closed() {
            self.announce_selected_candidate_pair();
        }

        raised
    }

    fn pump_events_on_active(&mut self) -> bool {
        let mut intermediate_eouts = VecDeque::new();
        let mut raised = false;

        use sansio::Protocol;

        let carries_data = self.active_carries_data();
        process_handler_list!(call_macro: process_handler!(self, handler, {
            while let Some(evt) = intermediate_eouts.pop_front() {
                if let Err(err) = handler.handle_event(evt) {
                    warn!("{}.handle_event got error: {}", handler.name(), err);
                }
            }
            while let Some(msg) = handler.poll_event() {
                raised = true;
                intermediate_eouts.push_back(msg);
            }
        }), [get_demuxer_handler, get_ice_handler, get_dtls_handler]);
        if carries_data {
            process_handler_list!(call_macro: process_handler!(self, handler, {
            while let Some(evt) = intermediate_eouts.pop_front() {
                if let Err(err) = handler.handle_event(evt) {
                    warn!("{}.handle_event got error: {}", handler.name(), err);
                }
            }
            while let Some(msg) = handler.poll_event() {
                raised = true;
                intermediate_eouts.push_back(msg);
            }
        }), [get_sctp_handler, get_datachannel_handler]);
        }
        process_handler_list!(call_macro: process_handler!(self, handler, {
            while let Some(evt) = intermediate_eouts.pop_front() {
                if let Err(err) = handler.handle_event(evt) {
                    warn!("{}.handle_event got error: {}", handler.name(), err);
                }
            }
            while let Some(msg) = handler.poll_event() {
                raised = true;
                intermediate_eouts.push_back(msg);
            }
        }), [get_srtp_handler, get_interceptor_handler, get_endpoint_handler]);

        // Finally, put intermediate_eouts into RTCPeerConnection's eouts, with the transport
        // and connection state events each causes, in the spec's order: the transport's own
        // event, then the connection's (W3C webrtc-pc 4.4.1.3, 5.5, 5.6).
        while let Some(evt_internal) = intermediate_eouts.pop_front() {
            match evt_internal.event {
                RTCEventInternal::RTCPeerConnectionEvent(
                    RTCPeerConnectionEvent::OnIceConnectionStateChangeEvent(state),
                ) => {
                    // `close()` sets the ICE connection state without an event; what the
                    // agent reports once it is closed is not told either.
                    if self.is_closed() {
                        continue;
                    }
                    // The transport's own event (`OnTransportEvent`, and the variant naming
                    // no transport for the default one); the connection's is the aggregate
                    // of every transport's state (W3C 4.3.4).
                    self.announce_ice_transport_state(state);
                    let aggregate = self.ice_connection_state();
                    if aggregate != self.pipeline_context.announced_ice_connection_state {
                        self.pipeline_context.announced_ice_connection_state = aggregate;
                        self.pipeline_context.event_outs.push_back(
                            RTCPeerConnectionEvent::OnIceConnectionStateChangeEvent(aggregate),
                        );
                    }
                    self.update_connection_state(false);
                }
                RTCEventInternal::DTLSHandshakeComplete(_, _) | RTCEventInternal::DTLSClosed => {
                    self.announce_transport_states();
                    self.update_connection_state(false);
                }
                RTCEventInternal::SRTPKeyExhausted => {
                    // RFC 3711 section 9.2: re-key or end the session. A new DTLS association
                    // is not something a browser peer takes on a transport that has one, so
                    // the session ends: the transport fails with the reason.
                    use crate::peer_connection::rtc_error::{RTCError, RTCErrorDetailType};
                    let now = evt_internal.now;
                    self.get_dtls_handler().fail_with(
                        now,
                        RTCError::new(
                            RTCErrorDetailType::DtlsFailure,
                            "the SRTP master key reached its lifetime (RFC 3711 section 9.2)",
                        ),
                    );
                    self.announce_transport_states();
                }
                // webrtc-extensions 7: the candidate pair events are the active transport's.
                RTCEventInternal::RTCPeerConnectionEvent(
                    RTCPeerConnectionEvent::OnIceCandidatePairAdd(pair),
                ) => self.fire_transport_event(
                    RTCPeerConnectionEvent::OnIceCandidatePairAdd(pair.clone()),
                    RTCTransportEventKind::CandidatePairAdd(pair),
                ),
                RTCEventInternal::RTCPeerConnectionEvent(
                    RTCPeerConnectionEvent::OnIceCandidatePairNominate(pair),
                ) => self.fire_transport_event(
                    RTCPeerConnectionEvent::OnIceCandidatePairNominate(pair.clone()),
                    RTCTransportEventKind::CandidatePairNominate(pair),
                ),
                RTCEventInternal::RTCPeerConnectionEvent(
                    RTCPeerConnectionEvent::OnIceCandidatePairRemove(pair),
                ) => self.fire_transport_event(
                    RTCPeerConnectionEvent::OnIceCandidatePairRemove(pair.clone()),
                    RTCTransportEventKind::CandidatePairRemove(pair),
                ),
                RTCEventInternal::RTCPeerConnectionEvent(evt) => {
                    self.pipeline_context.event_outs.push_back(evt);
                }
                _ => {}
            }
        }

        raised
    }
}

impl RTCPeerConnection {
    /// Reads a datagram on the transport `id`, which the caller has already chosen (a stream
    /// the engine knows the transport of, a relayed candidate's link).
    pub(crate) fn read_on_transport(&mut self, id: TransportId, msg: TaggedBytesMut) {
        let msg = TaggedRTCMessageInternal {
            now: msg.now,
            transport: msg.transport,
            message: RTCMessageInternal::Raw(msg.message),
        };
        self.with_transport(id, |pc| pc.pump_reads(Some(msg)));
    }
}

impl sansio::Protocol<TaggedBytesMut, TaggedRTCMessage, TaggedRTCEvent> for RTCPeerConnection {
    type Rout = TaggedRTCMessage;
    type Wout = TaggedBytesMut;
    type Eout = RTCPeerConnectionEvent;
    type Error = Error;
    type Time = Instant;

    fn handle_read(&mut self, msg: TaggedBytesMut) -> Result<(), Self::Error> {
        self.pipeline_context.observe(msg.now);
        // The transport the datagram belongs to, by where it arrived (RFC 9143 section 9: a
        // transport per BUNDLE group or unbundled section) reads it.
        let transport = self
            .pipeline_context
            .transports
            .route(&msg.transport, &msg.message);
        self.read_on_transport(transport, msg);
        Ok(())
    }

    fn poll_read(&mut self) -> Option<Self::Rout> {
        self.pump_reads(None);

        if let (Some(data), Some(media)) = (
            self.pipeline_context.data_read_outs.front(),
            self.pipeline_context.media_read_outs.front(),
        ) {
            if data.now <= media.now {
                self.pipeline_context.data_read_outs.pop_front()
            } else {
                self.pipeline_context.media_read_outs.pop_front()
            }
        } else if self.pipeline_context.data_read_outs.front().is_some() {
            self.pipeline_context.data_read_outs.pop_front()
        } else {
            self.pipeline_context.media_read_outs.pop_front()
        }
    }

    fn handle_write(&mut self, msg: TaggedRTCMessage) -> Result<(), Self::Error> {
        let now = msg.now;
        self.pipeline_context.observe(now);
        let rtc_message_internal = match msg.message {
            RTCMessage::DataChannelMessage(data_channel_id, data_channel_message) => {
                RTCMessageInternal::Dtls(DTLSMessage::DataChannel(ApplicationMessage {
                    data_channel_id,
                    data_channel_event: DataChannelEvent::Message(data_channel_message),
                }))
            }
            RTCMessage::RtpPacket(_track_id, rtp_packet) => {
                RTCMessageInternal::Rtp(RTPMessage::Packet(Packet::Rtp(rtp_packet)))
            }
            RTCMessage::RtcpPacket(_track_id, rtcp_packet) => {
                RTCMessageInternal::Rtp(RTPMessage::Packet(Packet::Rtcp(rtcp_packet)))
            }
        };

        // Only endpoint can handle user write message
        let mut endpoint_handler = self.get_endpoint_handler();
        endpoint_handler.handle_write(TaggedRTCMessageInternal {
            now,
            transport: Default::default(),
            message: rtc_message_internal,
        })
    }

    fn poll_write(&mut self) -> Option<Self::Wout> {
        self.flush_writes();
        // A datagram for one of the engine's own TCP candidates goes on its connection
        // (`poll_stream_transmit`), not to the application.
        while let Some(msg) = self.pipeline_context.write_outs.pop_front() {
            if let Some(msg) = self.route_stream_write(msg) {
                return Some(msg);
            }
        }
        None
    }

    fn handle_event(&mut self, evt: TaggedRTCEvent) -> Result<(), Self::Error> {
        // `RTCEvent` is `pub enum RTCEvent {}` — uninhabited, reserved for future use — so no
        // caller can construct one and this arm is unreachable. Diverging on the empty match
        // keeps that fact in the type system, and avoids inventing an instant to wrap the
        // event with when there is none to be had. C3-03 replaces this with `evt.now` once
        // the public channel carries a timestamp.
        match evt.event {}
    }

    fn poll_event(&mut self) -> Option<Self::Eout> {
        // A description or a timeout may have moved a transport's state (DTLS to "connecting"
        // when its handshake starts, say): announce it behind what is queued.
        self.announce_transport_states();
        self.announce_lite_candidate_update();
        // Drain the backlog before sweeping the pipeline again: anything a sweep adds lands
        // behind it anyway, and the sweep runs once the backlog is empty.
        if let Some(evt) = self.pipeline_context.event_outs.pop_front() {
            return Some(self.hand_out_event(evt));
        }

        // Handling an event can queue read messages, like the open of a negotiated data channel
        // on `SCTPHandshakeComplete`. Deliver them, and the events they raise, now rather than
        // on the next incoming packet.
        if self.pump_events() {
            self.pump_reads(None);
            self.pump_events();
        }

        let evt = self.pipeline_context.event_outs.pop_front()?;
        Some(self.hand_out_event(evt))
    }

    fn handle_timeout(&mut self, now: Instant) -> Result<(), Self::Error> {
        self.pipeline_context.observe(now);
        // RFC 8837 section 5: the association's congestion control starts over when its
        // codepoint changed (a channel of another priority came or went).
        self.restart_sctp_congestion_control_on_dscp_change(now);
        // The connection's handlers once, each transport's for every transport.
        process_handler_list!(call_macro: process_handler!(self, handler, {
            handler.handle_timeout(now)?;
        }), [get_demuxer_handler]);
        for id in self.pipeline_context.transports.ids() {
            self.with_transport(id, |pc| -> Result<(), Error> {
                process_handler_list!(call_macro: process_handler!(pc, handler, {
                    handler.handle_timeout(now)?;
                }), [get_ice_handler, get_dtls_handler]);
                Ok(())
            })?;
        }
        process_handler_list!(call_macro: process_handler!(self, handler, {
            handler.handle_timeout(now)?;
        }), [get_sctp_handler, get_datachannel_handler]);
        for id in self.pipeline_context.transports.ids() {
            self.with_transport(id, |pc| -> Result<(), Error> {
                process_handler_list!(call_macro: process_handler!(pc, handler, {
                    handler.handle_timeout(now)?;
                }), [get_srtp_handler]);
                Ok(())
            })?;
        }
        process_handler_list!(call_macro: process_handler!(self, handler, {
            handler.handle_timeout(now)?;
        }), [get_interceptor_handler, get_endpoint_handler]);
        // The DTMF senders' playout (W3C webrtc-pc section 7).
        self.run_dtmf(now)?;
        // The engine's TURN-over-stream clients and connection races.
        self.turn_handle_timeout(now);
        Ok(())
    }

    fn poll_timeout(&mut self) -> Option<Instant> {
        let mut eto: Option<Instant> = None;
        for_each_handler!(forward: process_handler!(self, handler, {
            if let Some(next) = handler.poll_timeout() {
                eto = Some(eto.map_or(next, |curr| std::cmp::min(curr, next)));
            }
        }));
        // The other transports' ICE, DTLS and SRTP timers.
        let default = self.pipeline_context.transports.default_id();
        for id in self.pipeline_context.transports.ids() {
            if id == default {
                continue;
            }
            let next = self.with_transport(id, |pc| {
                let mut eto: Option<Instant> = None;
                process_handler_list!(call_macro: process_handler!(pc, handler, {
                    if let Some(next) = handler.poll_timeout() {
                        eto = Some(eto.map_or(next, |curr| std::cmp::min(curr, next)));
                    }
                }), [get_ice_handler, get_dtls_handler, get_srtp_handler]);
                eto
            });
            if let Some(next) = next {
                eto = Some(eto.map_or(next, |curr| curr.min(next)));
            }
        }
        if let Some(dtmf) = self.dtmf_timeout() {
            eto = Some(eto.map_or(dtmf, |curr| curr.min(dtmf)));
        }
        if let Some(turn) = self.turn_poll_timeout() {
            eto = Some(eto.map_or(turn, |curr| curr.min(turn)));
        }
        eto
    }

    fn close(&mut self) -> Result<(), Self::Error> {
        // https://www.w3.org/TR/webrtc/#dom-rtcpeerconnection-close (step #1)
        if self.peer_connection_state == RTCPeerConnectionState::Closed {
            return Ok(());
        }

        // https://www.w3.org/TR/webrtc/#dom-rtcpeerconnection-close (step #3)
        self.signaling_state = RTCSignalingState::Closed;

        // Tell the peer before tearing anything down, so it can close at once instead of waiting
        // for its ICE consent checks to time out (rtc#255). During this flush the SCTP handler
        // sends the data it still holds and then an ABORT for each association (W3C close():
        // "tear down the underlying SCTP association by sending an SCTP ABORT chunk"), and the
        // DTLS handler queues a close_notify behind them, so nothing pending is dropped or sent
        // after it. They are routed now because closing the ICE handler below forgets the
        // selected candidate pair every outbound packet is addressed with; the packets wait in
        // `write_outs` for the caller's next `poll_write`.
        let now = self.pipeline_context.now;
        // RFC 3550 6.6: the SSRCs of a participant that leaves say BYE.
        self.get_interceptor_handler().request_goodbye(now);
        self.get_sctp_handler().request_abort();
        // Every transport's DTLS association says close_notify.
        for id in self.pipeline_context.transports.ids() {
            self.with_transport(id, |pc| pc.get_dtls_handler().request_close(now));
        }
        self.flush_writes();
        // The engine's TCP connections carry what was just queued, then close.
        self.close_streams();

        // Close handlers in reverse order (Endpoint→Interceptor→SRTP→DataChannel→SCTP→
        // DTLS→ICE→Demuxer) so that higher-level protocols (DataChannels, SCTP) shut down
        // before the transports they depend on (DTLS, ICE).
        // Collect all errors instead of short-circuiting so every handler gets a chance
        // to clean up even if an earlier one fails. (Brainwires fork; see FORK.md.)
        let mut close_errs: Vec<Error> = vec![];
        process_handler_list!(call_macro: process_handler!(self, handler, {
            if let Err(e) = handler.close() {
                close_errs.push(e);
            }
        }), [get_endpoint_handler, get_interceptor_handler]);
        // Each transport's SRTP, DTLS and ICE, the SCTP association's between them.
        for id in self.pipeline_context.transports.ids() {
            let carries_data = id == self.pipeline_context.transports.data_transport_id();
            let errs = self.with_transport(id, |pc| {
                let mut errs: Vec<Error> = vec![];
                process_handler_list!(call_macro: process_handler!(pc, handler, {
                    if let Err(e) = handler.close() {
                        errs.push(e);
                    }
                }), [get_srtp_handler]);
                if carries_data {
                    process_handler_list!(call_macro: process_handler!(pc, handler, {
                        if let Err(e) = handler.close() {
                            errs.push(e);
                        }
                    }), [get_datachannel_handler, get_sctp_handler]);
                }
                process_handler_list!(call_macro: process_handler!(pc, handler, {
                    if let Err(e) = handler.close() {
                        errs.push(e);
                    }
                }), [get_dtls_handler, get_ice_handler]);
                errs
            });
            close_errs.extend(errs);
        }
        process_handler_list!(call_macro: process_handler!(self, handler, {
            if let Err(e) = handler.close() {
                close_errs.push(e);
            }
        }), [get_demuxer_handler]);

        // W3C WebRTC §close shutdown work is implemented in individual handler close() methods:
        //   InterceptorHandler::close() → interceptor.close()
        //   DataChannelHandler::close() → closes all RTCDataChannelInternal instances
        //   SctpHandler::close()        → closes all SCTP associations + endpoint
        //   DtlsHandler::close()        → dtls_transport.stop()
        //   IceHandler::close()         → ice_transport.agent.close()

        // https://www.w3.org/TR/webrtc/#dom-rtcpeerconnection-close (steps #6 to #11): every
        // transceiver is stopped, and the transports' and the connection's states become
        // "closed", all without an event.
        for transceiver in &mut self.rtp_transceivers {
            if !transceiver.is_stopped()
                && let Err(err) = transceiver.stop(&self.media_engine, &mut *self.interceptor)
            {
                close_errs.push(err);
            }
        }
        // Step 7: every data channel's [[ReadyState]] becomes "closed", without the closing
        // procedure and without an event.
        for channel in self.data_channels.values_mut() {
            channel.ready_state = crate::data_channel::RTCDataChannelState::Closed;
        }
        for id in self.pipeline_context.transports.ids() {
            self.with_transport(id, |pc| {
                pc.ice_transport_mut().ice_connection_state =
                    crate::peer_connection::state::ice_connection_state::RTCIceConnectionState::Closed;
            });
        }
        self.peer_connection_state = RTCPeerConnectionState::Closed;
        self.close_announced_states();

        flatten_errs(close_errs)
    }
}

#[cfg(test)]
mod handler_test {
    use super::*;
    use crate::data_channel::message::RTCDataChannelMessage;
    use crate::peer_connection::RTCPeerConnectionBuilder;
    use crate::peer_connection::event::RTCDataChannelEvent;
    use bytes::BytesMut;
    use sansio::Protocol;
    use shared::{TransportContext, TransportProtocol};
    use std::net::Ipv4Addr;
    use std::time::Duration;

    /// Media must be drainable while data-channel output is held back.
    ///
    /// That is the whole point of the split: back-pressure is applied by declining to drain
    /// the data-channel queue, and while both kinds shared one queue that also stopped media.
    /// A slow signalling channel froze video on the same connection for as long as it stalled.
    #[test]
    fn media_drains_while_data_channel_output_is_held_back() {
        let base = Instant::now();
        let mut pc = RTCPeerConnectionBuilder::new()
            .build(base)
            .expect("build peer connection");

        // Media outnumbering data, the shape of a real SFU connection.
        for i in 0..10 {
            let message = if i % 5 == 0 {
                RTCMessage::DataChannelMessage(0, RTCDataChannelMessage::default())
            } else {
                RTCMessage::RtpPacket(Default::default(), ::rtp::packet::Packet::default())
            };
            let tagged = TaggedRTCMessage { now: base, message };
            match tagged.message {
                RTCMessage::DataChannelMessage(..) => {
                    pc.pipeline_context.data_read_outs.push_back(tagged)
                }
                _ => pc.pipeline_context.media_read_outs.push_back(tagged),
            }
        }

        // Drain media only — as a caller applying data-channel back-pressure would.
        let mut media = 0;
        while let Some(msg) = pc.poll_media_read() {
            assert!(
                !matches!(msg.message, RTCMessage::DataChannelMessage(..)),
                "poll_media_read must never yield data-channel output"
            );
            media += 1;
        }

        assert_eq!(
            media, 8,
            "all media must be deliverable while data is held back"
        );
        assert_eq!(
            pc.pipeline_context.data_read_outs.len(),
            2,
            "held-back data-channel output must stay queued — its length is the signal the \
             SCTP drain is bounded against, so losing it would drop the back-pressure"
        );

        // And releasing it hands over exactly what was held.
        let mut data = 0;
        while let Some(msg) = pc.poll_data_read() {
            assert!(matches!(msg.message, RTCMessage::DataChannelMessage(..)));
            data += 1;
        }
        assert_eq!(data, 2);
    }

    /// `poll_read` still yields both kinds, so the callers that predate the split — 58 files
    /// across tests and examples — behave exactly as before.
    #[test]
    fn poll_read_still_yields_both_kinds() {
        let base = Instant::now();
        let mut pc = RTCPeerConnectionBuilder::new()
            .build(base)
            .expect("build peer connection");

        pc.pipeline_context
            .data_read_outs
            .push_back(TaggedRTCMessage {
                now: base,
                message: RTCMessage::DataChannelMessage(0, RTCDataChannelMessage::default()),
            });
        pc.pipeline_context
            .media_read_outs
            .push_back(TaggedRTCMessage {
                now: base,
                message: RTCMessage::RtpPacket(
                    Default::default(),
                    ::rtp::packet::Packet::default(),
                ),
            });

        let mut kinds = vec![];
        while let Some(msg) = pc.poll_read() {
            kinds.push(matches!(msg.message, RTCMessage::DataChannelMessage(..)));
        }
        assert_eq!(kinds.len(), 2, "poll_read must still drain everything");
        assert!(kinds.contains(&true) && kinds.contains(&false));
    }

    /// The instant the application supplies on `handle_write` is the one the core stamps the
    /// resulting internal message with — not a reading the core took for itself. Before C3-03
    /// the public `Win` was a bare `RTCMessage`, so this entry point had no time source and
    /// stamped `Instant::now()`.
    #[test]
    fn handle_write_stamps_from_the_caller_not_the_clock() {
        let base = Instant::now();
        let t = |secs| base + Duration::from_secs(secs);

        let mut pc = RTCPeerConnectionBuilder::new()
            .build(t(0))
            .expect("a default peer connection builds");

        pc.handle_write(TaggedRTCMessage {
            now: t(5),
            message: RTCMessage::DataChannelMessage(
                1,
                RTCDataChannelMessage {
                    is_string: true,
                    data: BytesMut::from(&b"hello"[..]),
                },
            ),
        })
        .expect("handle_write queues the message");

        let queued = pc
            .pipeline_context
            .endpoint_handler_context
            .write_outs
            .front()
            .expect("the message reaches the endpoint handler");

        assert_eq!(
            queued.now,
            t(5),
            "the internal message carries the caller's instant, not an ambient reading"
        );
        assert_ne!(queued.now, t(0), "and not the construction instant either");
    }

    /// The open of a negotiated data channel is queued as a read message while
    /// `SCTPHandshakeComplete` is being handled, i.e. inside `poll_event`. That same `poll_event`
    /// call must return the `OnOpen`: the async `webrtc` driver drains events until `poll_event`
    /// returns `None` and then waits for the next packet or timer.
    #[test]
    fn negotiated_channel_opens_within_the_same_poll_event() {
        use crate::data_channel::RTCDataChannelInit;
        use crate::peer_connection::event::TaggedRTCEventInternal;
        use crate::peer_connection::transport::RTCDtlsRole;

        let base = Instant::now();
        let mut pc = RTCPeerConnectionBuilder::new()
            .build(base)
            .expect("a default peer connection builds");
        let id = pc
            .create_data_channel(
                "negotiated",
                Some(RTCDataChannelInit {
                    negotiated: Some(1),
                    ..Default::default()
                }),
            )
            .expect("a negotiated data channel is created")
            .id();

        // Drain what creating the channel raised (`OnNegotiationNeeded`): an unrelated event
        // returned alongside would keep the loop below polling and hide a stuck open.
        while pc.poll_event().is_some() {}

        // Resolved by the DTLS handshake, which precedes the association.
        pc.dtls_transport_mut().dtls_role = RTCDtlsRole::Client;

        // What the SCTP handler emits once the association is up.
        pc.pipeline_context
            .sctp_handler_context
            .event_outs
            .push_back(TaggedRTCEventInternal {
                now: base,
                event: RTCEventInternal::SCTPHandshakeComplete(0),
            });

        let mut opened = false;
        while let Some(event) = pc.poll_event() {
            if matches!(
                event,
                RTCPeerConnectionEvent::OnDataChannel(RTCDataChannelEvent::OnOpen(opened_id)) if opened_id == id
            ) {
                opened = true;
            }
        }
        assert!(
            opened,
            "the open must not wait for the next incoming packet"
        );
    }

    /// Check that messages in the `read_out` queues don't get stuck until the next incoming packet triggers `handle_read`.
    #[test]
    fn pump_read_outs() {
        let base = Instant::now();
        let t = |secs| base + Duration::from_secs(secs);

        let mut pc = RTCPeerConnectionBuilder::new()
            .build(t(0))
            .expect("a default peer connection builds");

        // drop a message into the data channel handler read outs, like DataChannel::emit_data_channel_opened() does
        pc.pipeline_context
            .datachannel_handler_context
            .read_outs
            .push_back(TaggedRTCMessageInternal {
                now: t(5),
                transport: TransportContext {
                    local_addr: (Ipv4Addr::LOCALHOST, 0).into(),
                    peer_addr: (Ipv4Addr::LOCALHOST, 0).into(),
                    transport_protocol: TransportProtocol::UDP,
                    ecn: None,
                },
                message: RTCMessageInternal::Dtls(DTLSMessage::DataChannel(ApplicationMessage {
                    data_channel_id: 42,
                    data_channel_event: DataChannelEvent::Open,
                })),
            });

        // call `poll_read` to pump the read outs
        let msg = pc.poll_read();
        assert!(
            msg.is_none(),
            "The message should be consumed by the enpoint handler"
        );

        // we should get a channel opened event
        let event = pc.poll_event().expect("should have an event");
        assert!(matches!(
            event,
            RTCPeerConnectionEvent::OnDataChannel(RTCDataChannelEvent::OnOpen(42))
        ));
    }
}

#[cfg(test)]
mod close_tests {
    use super::*;
    use crate::peer_connection::RTCPeerConnectionBuilder;
    use sansio::Protocol;

    #[test]
    fn close_transitions_to_closed_state() {
        let mut pc = RTCPeerConnectionBuilder::new()
            .build(std::time::Instant::now())
            .unwrap();
        assert_ne!(pc.peer_connection_state, RTCPeerConnectionState::Closed);
        assert_ne!(pc.signaling_state, RTCSignalingState::Closed);

        pc.close().unwrap();

        assert_eq!(pc.peer_connection_state, RTCPeerConnectionState::Closed);
        assert_eq!(pc.signaling_state, RTCSignalingState::Closed);
    }

    #[test]
    fn close_is_idempotent() {
        let mut pc = RTCPeerConnectionBuilder::new()
            .build(std::time::Instant::now())
            .unwrap();
        pc.close().unwrap();
        // Second close should be a no-op (early return for already-closed)
        pc.close().unwrap();
        assert_eq!(pc.peer_connection_state, RTCPeerConnectionState::Closed);
    }

    #[test]
    fn close_preserves_data_channels_in_map() {
        let mut pc = RTCPeerConnectionBuilder::new()
            .build(std::time::Instant::now())
            .unwrap();
        // Create a data channel before closing
        let dc = pc.create_data_channel("test", None).unwrap();
        let dc_id = dc.id();
        assert!(pc.data_channels.contains(&dc_id));

        pc.close().unwrap();

        // Data channels must remain in the map so that public RTCDataChannel
        // methods (label(), ready_state(), etc.) which use unwrap() don't panic.
        assert!(
            pc.data_channels.contains(&dc_id),
            "data_channels map must not be cleared on close"
        );
    }

    #[test]
    fn close_with_data_channel_does_not_panic() {
        let mut pc = RTCPeerConnectionBuilder::new()
            .build(std::time::Instant::now())
            .unwrap();
        let dc = pc.create_data_channel("my-dc", None).unwrap();
        let dc_id = dc.id();
        pc.close().unwrap();

        // After close, public accessors on the data channel must still work
        // (they unwrap() the map entry).
        let dc = pc.data_channel(dc_id).unwrap();
        assert_eq!(dc.label(), "my-dc");
        let _ = dc.ready_state();
    }
}
