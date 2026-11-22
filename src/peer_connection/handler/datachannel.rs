use crate::data_channel::RTCDataChannelId;
use crate::data_channel::internal::RTCDataChannelInternal;
use crate::data_channel::message::RTCDataChannelMessage;
use crate::data_channel::registry::DataChannelRegistry;
use crate::data_channel::state::RTCDataChannelState;
use crate::peer_connection::event::data_channel_event::RTCDataChannelEvent;
use crate::peer_connection::event::{
    RTCEventInternal, RTCPeerConnectionEvent, TaggedRTCEventInternal,
};
use crate::peer_connection::message::internal::{
    ApplicationMessage, DTLSMessage, DataChannelEvent, RTCMessageInternal, TaggedRTCMessageInternal,
};
use crate::peer_connection::rtc_error::{RTCError, RTCErrorDetailType};
use crate::peer_connection::transport::dtls::role::RTCDtlsRole;
use crate::statistics::accumulator::RTCStatsAccumulator;
use bytes::BytesMut;
use datachannel::data_channel::DataChannelMessage;
use datachannel::message::Message as DcepMessage;
use datachannel::message::message_channel_close::DataChannelClose;
use log::{debug, warn};
use sctp::{PayloadProtocolIdentifier, StreamId};
use shared::TransportContext;
use shared::error::{Error, Result};
use shared::marshal::Marshal;
use std::collections::VecDeque;
use std::time::{Duration, Instant};

pub(crate) struct DataChannelHandlerContext {
    pub(crate) read_outs: VecDeque<TaggedRTCMessageInternal>,
    pub(crate) write_outs: VecDeque<TaggedRTCMessageInternal>,
    pub(crate) event_outs: VecDeque<TaggedRTCEventInternal>,

    /// The newest instant a caller has supplied, seeded at construction.
    ///
    /// `poll_write` drains each channel's outbound queue, and a message can still be sitting
    /// there from an earlier `handle_*` — the datachannel layer buffers when SCTP back-pressures
    /// it. Stamping those with the instant of the input that caused them is the right answer;
    /// this field is what a `poll_*` has instead of a parameter.
    now: Instant,
}

impl DataChannelHandlerContext {
    pub(crate) fn new(now: Instant) -> Self {
        Self {
            read_outs: VecDeque::new(),
            write_outs: VecDeque::new(),
            event_outs: VecDeque::new(),
            now,
        }
    }

    /// Records the newest instant a caller has supplied. See the design's §9.3 for why there is
    /// no monotonicity assert alongside the `max`.
    fn observe(&mut self, now: Instant) {
        self.now = now.max(self.now);
    }
}

/// DataChannelHandler implements DataChannel Protocol handling
pub(crate) struct DataChannelHandler<'a> {
    ctx: &'a mut DataChannelHandlerContext,
    data_channels: &'a mut DataChannelRegistry,
    stats: &'a mut RTCStatsAccumulator,
    /// Configured DCEP handshake timeout for in-band channels. `None` disables it.
    dcep_handshake_timeout: Option<Duration>,
    /// The DTLS role this endpoint negotiated, which RFC 8832 §6 turns into the parity of the
    /// stream ids assigned at `SCTPHandshakeComplete`. Resolved by the time an association
    /// exists, so the handler never has to guess it.
    dtls_role: RTCDtlsRole,
    /// Negotiated stream limit, bounding stream-id assignment. `None` until the association
    /// reports one.
    max_channels: Option<u16>,
}

impl<'a> DataChannelHandler<'a> {
    pub(crate) fn new(
        ctx: &'a mut DataChannelHandlerContext,
        data_channels: &'a mut DataChannelRegistry,
        stats: &'a mut RTCStatsAccumulator,
        dcep_handshake_timeout: Option<Duration>,
        dtls_role: RTCDtlsRole,
        max_channels: Option<u16>,
    ) -> Self {
        DataChannelHandler {
            ctx,
            data_channels,
            stats,
            dcep_handshake_timeout,
            dtls_role,
            max_channels,
        }
    }

    pub(crate) fn name(&self) -> &'static str {
        "DataChannelHandler"
    }

    /// Fires `OnClose` for a channel that has been removed, and counts it as closed.
    ///
    /// The event names the channel by handle, as every application-facing event does; the
    /// stream id was only how SCTP referred to it. A channel already closed by handshake timeout
    /// has already fired `OnClose` and been counted, so it is not announced twice.
    fn announce_closed(&mut self, now: Instant, dc: RTCDataChannelInternal) {
        if dc.close_emitted {
            return;
        }
        let channel_id = dc.id;
        // The channel is gone from the registry: drop its statistics with it, and count it as
        // closed if it had been open.
        self.stats.on_data_channel_gone(channel_id);
        self.ctx.event_outs.push_back(TaggedRTCEventInternal {
            now,
            event: RTCEventInternal::RTCPeerConnectionEvent(RTCPeerConnectionEvent::OnDataChannel(
                RTCDataChannelEvent::OnClose(channel_id),
            )),
        });
    }

    /// Whether the peer may open an in-band channel on `stream_id`.
    ///
    /// RFC 8832 §6: the DTLS client opens channels on even stream ids and the DTLS server on
    /// odd ones, so the peer's ids have the parity this side's do not. An id of this side's
    /// parity is one `assign_stream_ids` may hand to a local channel; accepting the peer's
    /// OPEN on it would let the peer take that stream first. With the role unresolved there
    /// is no parity to judge by, and no stream is accepted.
    fn is_peer_stream_id(&self, stream_id: StreamId) -> bool {
        let local_parity = match self.dtls_role {
            RTCDtlsRole::Client => 0,
            RTCDtlsRole::Server => 1,
            _ => return false,
        };
        stream_id % 2 != local_parity
    }

    /// Asks SCTP to reset `stream_id`, through the same DCEP close a local `close()` sends, so
    /// a stream the peer was not allowed to open does not linger half-open in the
    /// association.
    fn reset_stream(
        &mut self,
        now: Instant,
        association_handle: usize,
        stream_id: StreamId,
    ) -> Result<()> {
        let payload = DcepMessage::DataChannelClose(DataChannelClose).marshal()?;
        self.ctx.write_outs.push_back(TaggedRTCMessageInternal {
            now,
            transport: TransportContext::default(),
            message: RTCMessageInternal::Dtls(DTLSMessage::Sctp(DataChannelMessage {
                association_handle,
                stream_id,
                ppi: PayloadProtocolIdentifier::Dcep,
                payload: BytesMut::from(&payload[..]),
                negotiated: false,
            })),
        });
        Ok(())
    }

    /// `OnError` for channel `id`, with the `RTCError` it reports recorded for
    /// `RTCPeerConnection::data_channel_error` (W3C `RTCErrorEvent.error`).
    fn push_channel_error(
        ctx_events: &mut std::collections::VecDeque<TaggedRTCEventInternal>,
        data_channels: &mut DataChannelRegistry,
        now: Instant,
        id: RTCDataChannelId,
        error: RTCError,
    ) {
        data_channels.record_error(id, error);
        ctx_events.push_back(TaggedRTCEventInternal {
            now,
            event: RTCEventInternal::RTCPeerConnectionEvent(RTCPeerConnectionEvent::OnDataChannel(
                RTCDataChannelEvent::OnError(id),
            )),
        });
    }

    /// The `RTCError` of a channel the SCTP association's failure fails: `sctp-failure`, with
    /// the cause code when the association was aborted with one.
    fn sctp_failure(&self) -> RTCError {
        RTCError {
            sctp_cause_code: self.data_channels.sctp_failure_cause,
            ..RTCError::new(
                RTCErrorDetailType::SctpFailure,
                "the SCTP association failed",
            )
        }
    }

    /// Closes channel `id` for an error the peer made on its stream: `OnError` now, the
    /// stream reset as a local `close()` resets it, and `OnClose` when that reset completes.
    /// What the peer still sends on the stream until then is ignored, as for any closed
    /// channel.
    fn fail_channel(&mut self, now: Instant, id: RTCDataChannelId) -> Result<()> {
        let Some(dc) = self.data_channels.get_mut(&id) else {
            return Ok(());
        };
        let report = !dc.close_emitted && !dc.failed;
        if report {
            dc.failed = true;
        }
        dc.close()?;
        if report {
            Self::push_channel_error(
                &mut self.ctx.event_outs,
                self.data_channels,
                now,
                id,
                RTCError::new(
                    RTCErrorDetailType::DataChannelFailure,
                    "the peer broke the data channel protocol on the channel's stream",
                ),
            );
        }
        let Some(dc) = self.data_channels.get_mut(&id) else {
            return Ok(());
        };
        if let Some(data_channel) = dc.data_channel.as_mut() {
            while let Some(data_channel_message) = sansio::Protocol::poll_write(data_channel) {
                self.ctx.write_outs.push_back(TaggedRTCMessageInternal {
                    now,
                    transport: TransportContext::default(),
                    message: RTCMessageInternal::Dtls(DTLSMessage::Sctp(data_channel_message)),
                });
            }
        }
        Ok(())
    }

    /// Creates the statistics entry of channel `id` if it has none, copying its label and
    /// protocol once rather than for every message. A closed channel's entry is not recreated.
    fn ensure_data_channel_stats(&mut self, id: RTCDataChannelId) {
        if self.stats.data_channels.contains_key(&id) {
            return;
        }
        if let Some(dc) = self.data_channels.get(&id)
            && dc.ready_state != RTCDataChannelState::Closed
        {
            self.stats
                .get_or_create_data_channel(id, dc.label(), dc.protocol());
        }
    }

    /// Emit the `DataChannelEvent::Open` application message and record the
    /// corresponding peer-connection and per-channel statistics.
    ///
    /// The caller must have already ensured the channel's `ready_state` is `Open`.
    fn emit_data_channel_opened(
        &mut self,
        now: Instant,
        transport: TransportContext,
        id: RTCDataChannelId,
    ) -> Result<()> {
        let dc = self
            .data_channels
            .get(&id)
            .ok_or(Error::ErrDataChannelNotExisted)?;

        self.ctx.read_outs.push_back(TaggedRTCMessageInternal {
            now,
            transport,
            message: RTCMessageInternal::Dtls(DTLSMessage::DataChannel(ApplicationMessage {
                data_channel_id: id,
                data_channel_event: DataChannelEvent::Open,
            })),
        });

        // The channel is open, so it necessarily has a stream id by now; record it as the
        // W3C `dataChannelIdentifier`, which is the wire value rather than the handle the
        // accumulator is keyed by.
        let stream_id = dc.stream_id;

        self.stats.peer_connection.on_data_channel_opened();
        self.stats
            .get_or_create_data_channel(id, dc.label(), dc.protocol())
            .on_opened();
        if let Some(stream_id) = stream_id {
            self.stats.set_data_channel_stream_id(id, stream_id);
        }
        Ok(())
    }
}

impl<'a>
    sansio::Protocol<TaggedRTCMessageInternal, TaggedRTCMessageInternal, TaggedRTCEventInternal>
    for DataChannelHandler<'a>
{
    type Rout = TaggedRTCMessageInternal;
    type Wout = TaggedRTCMessageInternal;
    type Eout = TaggedRTCEventInternal;
    type Error = Error;
    type Time = Instant;

    fn handle_read(&mut self, msg: TaggedRTCMessageInternal) -> Result<()> {
        let now = msg.now;
        self.ctx.observe(now);

        if let RTCMessageInternal::Dtls(DTLSMessage::Sctp(message)) = msg.message {
            debug!(
                "recv SCTP DataChannelMessage from {:?}",
                msg.transport.peer_addr
            );

            let stream_id = message.stream_id;
            let transport = msg.transport;

            // SCTP addresses channels by stream id; everything leaving this handler towards
            // the application is keyed by handle instead.
            let opened = if let Some(data_channel_internal) =
                self.data_channels.get_by_stream_mut(&stream_id)
            {
                // A closed channel is terminal: ignore any late DCEP or user data.
                if data_channel_internal.ready_state == RTCDataChannelState::Closed {
                    return Ok(());
                }

                // Process the inbound message, then check whether a still-connecting
                // in-band channel just completed its DCEP handshake (initiator side).
                // If so, promote it to Open and emit the open event.
                let mut opened = false;
                let data_channel = data_channel_internal
                    .data_channel
                    .as_mut()
                    .ok_or(Error::ErrDataChannelNotExisted)?;
                if let Err(err) = data_channel.handle_read(message) {
                    // RFC 8832 section 6 (a DATA_CHANNEL_OPEN on a stream in use, a DCEP
                    // message that is not well formed) and RFC 8831 section 6.6 (an
                    // unsupported PPID): the channel is closed. Returning the error left it
                    // open, and before that an OPEN was acknowledged a second time and a
                    // message of unknown interpretation delivered as binary data.
                    warn!("closing the data channel on stream {stream_id}: the peer sent {err}");
                    let channel_id = data_channel_internal.id;
                    return self.fail_channel(now, channel_id);
                }
                if data_channel.is_handshake_complete()
                    && data_channel_internal.ready_state == RTCDataChannelState::Connecting
                {
                    data_channel_internal.ready_state = RTCDataChannelState::Open;
                    data_channel_internal.handshake_deadline = None;
                    opened = true;
                }
                opened
            } else {
                // A stream no channel is registered for is one the peer is opening in-band.
                // Out-of-band negotiated channels are registered under their id on both
                // sides, so they are found above and never get here, whatever their parity.
                if !self.is_peer_stream_id(stream_id) {
                    warn!(
                        "rejecting stream {stream_id} the peer opened: RFC 8832 §6 gives ids of \
                         that parity to this side (DTLS {})",
                        self.dtls_role
                    );
                    self.reset_stream(now, message.association_handle, stream_id)?;
                    return Ok(());
                }
                let data_channel_internal = match RTCDataChannelInternal::accept(
                    message.association_handle,
                    message.stream_id,
                    message.ppi,
                    &message.payload,
                ) {
                    Ok(data_channel_internal) => data_channel_internal,
                    Err(err) => {
                        // RFC 8832 section 6: a DATA_CHANNEL_OPEN that is not well formed or
                        // has invalid parameters, and any other message on an unused stream
                        // (user data, a stray ACK), close the channel the peer meant, which
                        // here is only its stream. Returning the error instead left that
                        // stream open for good, each later message failing the same way.
                        warn!("resetting stream {stream_id}, which the peer did not open: {err}");
                        self.reset_stream(now, message.association_handle, stream_id)?;
                        return Ok(());
                    }
                };

                self.data_channels.insert(data_channel_internal);
                true
            };

            // From here on the channel is addressed by handle, which is what the application
            // and every event it receives use.
            let channel_id = self
                .data_channels
                .handle_of_stream(&stream_id)
                .ok_or(Error::ErrDataChannelNotExisted)?;

            if opened {
                self.emit_data_channel_opened(now, transport, channel_id)?;
            }

            // Only deliver application messages once the channel is Open. Messages that
            // arrive while it is still Connecting stay buffered in the underlying
            // DataChannel's read queue; they drain once the channel opens, or are
            // discarded on close/timeout.
            let is_open = self
                .data_channels
                .get(&channel_id)
                .is_some_and(|dc| dc.ready_state == RTCDataChannelState::Open);
            if is_open {
                self.ensure_data_channel_stats(channel_id);
            }

            let data_channel = self
                .data_channels
                .get_mut(&channel_id)
                .ok_or(Error::ErrDataChannelNotExisted)?
                .data_channel
                .as_mut()
                .ok_or(Error::ErrDataChannelNotExisted)?;

            if is_open {
                while let Some(data_channel_message) = data_channel.poll_read() {
                    // https://datatracker.ietf.org/doc/html/rfc8831#section-6.6
                    // An empty message travels as one padding byte under an
                    // Empty PPID; it counts as 0 bytes received, as the sender
                    // counts it as 0 bytes sent (webrtc-stats bytesReceived).
                    let is_empty = matches!(
                        data_channel_message.ppi,
                        PayloadProtocolIdentifier::StringEmpty
                            | PayloadProtocolIdentifier::BinaryEmpty
                    );
                    let payload_len = if is_empty {
                        0
                    } else {
                        data_channel_message.payload.len()
                    };
                    debug!("recv application message {:?}", msg.transport.peer_addr);

                    // Track received message stats
                    if let Some(dc_stats) = self.stats.data_channels.get_mut(&channel_id) {
                        dc_stats.on_message_received(payload_len);
                    }

                    // https://datatracker.ietf.org/doc/html/rfc8831#section-6.6
                    // When receiving an SCTP user message with one of these [Empty]
                    // PPIDs, the receiver MUST ignore the SCTP user message and
                    // process it as an empty message.
                    let message_data = if is_empty {
                        Default::default()
                    } else {
                        data_channel_message.payload
                    };

                    self.ctx.read_outs.push_back(TaggedRTCMessageInternal {
                        now: msg.now,
                        transport: msg.transport,
                        message: RTCMessageInternal::Dtls(DTLSMessage::DataChannel(
                            ApplicationMessage {
                                data_channel_id: channel_id,
                                data_channel_event: DataChannelEvent::Message(
                                    RTCDataChannelMessage {
                                        is_string: matches!(
                                            data_channel_message.ppi,
                                            PayloadProtocolIdentifier::String
                                                | PayloadProtocolIdentifier::StringEmpty
                                        ),
                                        data: message_data,
                                    },
                                ),
                            },
                        )),
                    });
                }
            }

            while let Some(data_channel_message) = data_channel.poll_write() {
                debug!("send data channel message from handle_read");
                self.ctx.write_outs.push_back(TaggedRTCMessageInternal {
                    now,
                    transport: TransportContext::default(),
                    message: RTCMessageInternal::Dtls(DTLSMessage::Sctp(data_channel_message)),
                });
            }
        } else {
            // Bypass
            debug!("bypass DataChannel read {:?}", msg.transport.peer_addr);
            self.ctx.read_outs.push_back(msg);
        }
        Ok(())
    }

    fn poll_read(&mut self) -> Option<Self::Rout> {
        self.ctx.read_outs.pop_front()
    }

    fn handle_write(&mut self, msg: TaggedRTCMessageInternal) -> Result<()> {
        let now = msg.now;
        self.ctx.observe(now);

        if let RTCMessageInternal::Dtls(DTLSMessage::DataChannel(message)) = msg.message {
            debug!("send application message {:?}", msg.transport.peer_addr);

            if let DataChannelEvent::Message(RTCDataChannelMessage { is_string, data }) =
                message.data_channel_event
            {
                let data_len = data.len();
                let channel_id = message.data_channel_id;

                if self.data_channels.get(&channel_id).is_none() {
                    return Err(Error::ErrDataChannelNotExisted);
                }
                self.ensure_data_channel_stats(channel_id);

                let data_channel = self
                    .data_channels
                    .get_mut(&channel_id)
                    .ok_or(Error::ErrDataChannelNotExisted)?
                    .data_channel
                    .as_mut()
                    .ok_or(Error::ErrDataChannelNotExisted)?;

                let data_channel_message =
                    ::datachannel::data_channel::DataChannel::get_data_channel_message(
                        is_string, data,
                    );
                data_channel.handle_write(data_channel_message)?;

                // Track sent message stats
                if let Some(dc_stats) = self.stats.data_channels.get_mut(&channel_id) {
                    dc_stats.on_message_sent(data_len);
                }

                while let Some(data_channel_message) = data_channel.poll_write() {
                    debug!("send data channel message from handle_write");
                    self.ctx.write_outs.push_back(TaggedRTCMessageInternal {
                        now,
                        transport: TransportContext::default(),
                        message: RTCMessageInternal::Dtls(DTLSMessage::Sctp(data_channel_message)),
                    });
                }
            } else if let DataChannelEvent::Close = message.data_channel_event {
                // The application's close, in order behind its sends: reset the stream now.
                let Some(dc) = self.data_channels.get_mut(&message.data_channel_id) else {
                    return Ok(());
                };
                if dc.ready_state != RTCDataChannelState::Closed {
                    dc.close()?;
                }
                if let Some(data_channel) = dc.data_channel.as_mut() {
                    while let Some(data_channel_message) = data_channel.poll_write() {
                        self.ctx.write_outs.push_back(TaggedRTCMessageInternal {
                            now,
                            transport: TransportContext::default(),
                            message: RTCMessageInternal::Dtls(DTLSMessage::Sctp(
                                data_channel_message,
                            )),
                        });
                    }
                }
            } else {
                warn!(
                    "drop unsupported DATACHANNEL message to {}",
                    msg.transport.peer_addr
                );
            }
        } else {
            // Bypass
            debug!("bypass DataChannel write {:?}", msg.transport.peer_addr);
            self.ctx.write_outs.push_back(msg);
        }
        Ok(())
    }

    fn poll_write(&mut self) -> Option<Self::Wout> {
        for data_channel_internal in self.data_channels.values_mut() {
            if let Some(data_channel) = data_channel_internal.data_channel.as_mut() {
                while let Some(data_channel_message) = data_channel.poll_write() {
                    debug!("send data channel message from poll_write");
                    self.ctx.write_outs.push_back(TaggedRTCMessageInternal {
                        now: self.ctx.now,
                        transport: TransportContext::default(),
                        message: RTCMessageInternal::Dtls(DTLSMessage::Sctp(data_channel_message)),
                    });
                }
            }
        }

        self.ctx.write_outs.pop_front()
    }

    fn handle_event(&mut self, evt: TaggedRTCEventInternal) -> Result<()> {
        let now = evt.now;
        match evt.event {
            RTCEventInternal::SCTPHandshakeComplete(association_handle) => {
                // The W3C "RTCSctpTransport connected procedure": the association is up, so
                // the DTLS role is resolved and the negotiated stream count is known. This is
                // the first moment a stream id can be chosen correctly, and therefore the
                // moment it is chosen at all (RFC 8832 §6).
                //
                // W3C 6.1.1.3: a channel that could be given no id, or whose id is not below
                // [[MaxChannels]], is closed with a failure; the others go on. Running out of
                // ids used to fail the whole event, which dialed no channel at all.
                if let Err(err) = self
                    .data_channels
                    .assign_stream_ids(self.dtls_role, self.max_channels)
                {
                    debug!("data channel ids not assigned: {err}");
                }
                let max_channels = self.max_channels.unwrap_or(u16::MAX);
                let mut unusable: Vec<RTCDataChannelId> = self
                    .data_channels
                    .values()
                    .filter(|dc| {
                        dc.ready_state == RTCDataChannelState::Connecting
                            && dc.data_channel.is_none()
                            && dc.stream_id.is_none_or(|id| id >= max_channels)
                    })
                    .map(|dc| dc.id)
                    .collect();
                unusable.sort_unstable();
                for id in unusable {
                    if let Some(dc) = self.data_channels.remove(&id) {
                        Self::push_channel_error(
                            &mut self.ctx.event_outs,
                            self.data_channels,
                            now,
                            id,
                            RTCError::new(
                                RTCErrorDetailType::DataChannelFailure,
                                "no stream id below the SCTP transport's maxChannels",
                            ),
                        );
                        self.announce_closed(now, dc);
                    }
                }

                // Out-of-band negotiated channels have no DCEP handshake, so they are
                // open immediately and fire the open event here. In-band channels stay
                // connecting until their `DATA_CHANNEL_ACK` arrives in `handle_read`.
                let mut opened = Vec::new();
                for data_channel_internal in self.data_channels.values_mut() {
                    // Only dial channels that have not been dialed yet. An in-band channel stays
                    // Connecting after dialing, so the ready_state guard alone does not
                    // exclude it from a second SCTPHandshakeComplete.
                    if data_channel_internal.ready_state == RTCDataChannelState::Connecting
                        && data_channel_internal.data_channel.is_none()
                    {
                        data_channel_internal.dial(association_handle)?;

                        if data_channel_internal.negotiated {
                            opened.push(data_channel_internal.id);
                        } else {
                            // In-band channels have a DCEP handshake to complete; arm a
                            // deadline so a lost ACK cannot leave them Connecting forever.
                            data_channel_internal.handshake_deadline =
                                self.dcep_handshake_timeout.map(|timeout| now + timeout);
                        }

                        let data_channel = data_channel_internal
                            .data_channel
                            .as_mut()
                            .ok_or(Error::ErrDataChannelNotExisted)?;

                        while let Some(data_channel_message) = data_channel.poll_write() {
                            debug!("send data channel message from handle_event");
                            self.ctx.write_outs.push_back(TaggedRTCMessageInternal {
                                now,
                                transport: TransportContext::default(),
                                message: RTCMessageInternal::Dtls(DTLSMessage::Sctp(
                                    data_channel_message,
                                )),
                            });
                        }
                    }
                }

                for id in opened {
                    self.emit_data_channel_opened(now, TransportContext::default(), id)?;
                }
            }

            RTCEventInternal::SCTPFailureCause(cause) => {
                self.data_channels.sctp_failure_cause = Some(cause);
            }

            RTCEventInternal::SCTPAssociationFailed(_association_handle) => {
                // One association per connection: every channel over it fails with it and is
                // closed, its underlying data transport being gone (W3C webrtc 6.2, "announce
                // the data channel as closed" with an error). Channels with a stream were
                // closed by their own `SCTPStreamClosed` already; this reaches the rest: a
                // pre-negotiated channel that never carried data, and every channel of an
                // association that failed in its handshake, which never opened a stream and
                // so stayed `connecting` for good.
                let error = self.sctp_failure();
                for dc in self.data_channels.drain() {
                    if !dc.close_emitted && !dc.failed {
                        Self::push_channel_error(
                            &mut self.ctx.event_outs,
                            self.data_channels,
                            now,
                            dc.id,
                            error.clone(),
                        );
                    }
                    self.announce_closed(now, dc);
                }
            }

            RTCEventInternal::SCTPStreamFailed(_association_handle, stream_id) => {
                let error = self.sctp_failure();
                if let Some(dc) = self.data_channels.get_by_stream_mut(&stream_id)
                    && !dc.close_emitted
                    && !dc.failed
                {
                    dc.failed = true;
                    let channel_id = dc.id;
                    Self::push_channel_error(
                        &mut self.ctx.event_outs,
                        self.data_channels,
                        now,
                        channel_id,
                        error,
                    );
                }
            }

            RTCEventInternal::SCTPStreamClosed(_association_handle, stream_id) => {
                if let Some(mut dc) = self.data_channels.remove_by_stream(&stream_id) {
                    // RFC 8832 section 6: "receiving an SCTP stream-reset request for a
                    // stream on which no DATA_CHANNEL_ACK message has been received indicates
                    // to the sender of the corresponding DATA_CHANNEL_OPEN message the
                    // failure of the data channel setup procedure". That is an error, not
                    // the closing procedure of a channel that was open.
                    let awaits_ack = !dc.negotiated
                        && dc.ready_state == RTCDataChannelState::Connecting
                        && dc.data_channel.is_some();
                    if awaits_ack && !dc.close_emitted && !dc.failed {
                        dc.failed = true;
                        Self::push_channel_error(
                            &mut self.ctx.event_outs,
                            self.data_channels,
                            now,
                            dc.id,
                            RTCError::new(
                                RTCErrorDetailType::DataChannelFailure,
                                "the peer reset the stream before acknowledging the channel",
                            ),
                        );
                    }
                    // W3C closing procedure: a close the remote started (its stream reset, or
                    // its DCEP close) takes an open or connecting channel to `closing` first.
                    // A channel this side is closing is already there, and one whose
                    // association failed is closed with an error instead.
                    if !dc.close_emitted
                        && !dc.failed
                        && matches!(
                            dc.ready_state,
                            RTCDataChannelState::Open | RTCDataChannelState::Connecting
                        )
                    {
                        self.ctx.event_outs.push_back(TaggedRTCEventInternal {
                            now,
                            event: RTCEventInternal::RTCPeerConnectionEvent(
                                RTCPeerConnectionEvent::OnDataChannel(
                                    RTCDataChannelEvent::OnClosing(dc.id),
                                ),
                            ),
                        });
                    }
                    self.announce_closed(now, dc);
                }
            }

            // RFC 8841 section 10: signalling closed the association (a rejected data
            // section, `a=sctp-port:0`, a new `a=sctp-port`), and RFC 8831 section 6.2: its
            // data channels are closed with it. A channel that never opened did not get
            // what it was created for, which is an error; one not dialed yet belongs to no
            // association, and waits for the new one if there is to be one.
            RTCEventInternal::SCTPClosedBySignalling(replaced) => {
                let mut handles: Vec<RTCDataChannelId> =
                    self.data_channels.values().map(|dc| dc.id).collect();
                handles.sort_unstable();
                for handle in handles {
                    let waits_for_the_new_association = replaced
                        && self.data_channels.get(&handle).is_some_and(|dc| {
                            dc.data_channel.is_none()
                                && dc.ready_state == RTCDataChannelState::Connecting
                        });
                    if waits_for_the_new_association {
                        continue;
                    }
                    let Some(dc) = self.data_channels.remove(&handle) else {
                        continue;
                    };
                    if dc.ready_state == RTCDataChannelState::Connecting
                        && !dc.close_emitted
                        && !dc.failed
                    {
                        Self::push_channel_error(
                            &mut self.ctx.event_outs,
                            self.data_channels,
                            now,
                            dc.id,
                            RTCError::new(
                                RTCErrorDetailType::DataChannelFailure,
                                "signalling closed the SCTP association before the channel opened",
                            ),
                        );
                    }
                    self.announce_closed(now, dc);
                }
            }

            // The peer closed the DTLS transport, and with it the SCTP transport every channel
            // runs over: every channel is closed now (rtc#255).
            RTCEventInternal::DTLSClosed => {
                for dc in self.data_channels.drain() {
                    self.announce_closed(now, dc);
                }
                self.ctx.event_outs.push_back(TaggedRTCEventInternal {
                    now,
                    event: RTCEventInternal::DTLSClosed,
                });
            }

            RTCEventInternal::SCTPBufferReleased(_association_handle, stream_id, n_bytes) => {
                // Pure accounting: SCTP released (acked or abandoned) `n_bytes` of
                // this channel's outgoing buffer. Decrement the synchronous send
                // back-pressure counter; do NOT forward the event further.
                if let Some(dc) = self.data_channels.get_by_stream_mut(&stream_id) {
                    dc.outstanding_bytes = dc.outstanding_bytes.saturating_sub(n_bytes);
                }
            }
            // The SCTP layer knows only stream ids; the application-facing events name the
            // channel by handle, like every other event it receives. This is the layer that
            // owns the mapping, so the translation happens here.
            RTCEventInternal::SCTPBufferedAmountLow(_association_handle, stream_id) => {
                if let Some(channel_id) = self.data_channels.handle_of_stream(&stream_id) {
                    self.ctx.event_outs.push_back(TaggedRTCEventInternal {
                        now,
                        event: RTCEventInternal::RTCPeerConnectionEvent(
                            RTCPeerConnectionEvent::OnDataChannel(
                                RTCDataChannelEvent::OnBufferedAmountLow(channel_id),
                            ),
                        ),
                    });
                }
            }

            RTCEventInternal::SCTPBufferedAmountHigh(_association_handle, stream_id) => {
                if let Some(channel_id) = self.data_channels.handle_of_stream(&stream_id) {
                    self.ctx.event_outs.push_back(TaggedRTCEventInternal {
                        now,
                        event: RTCEventInternal::RTCPeerConnectionEvent(
                            RTCPeerConnectionEvent::OnDataChannel(
                                RTCDataChannelEvent::OnBufferedAmountHigh(channel_id),
                            ),
                        ),
                    });
                }
            }

            // Events propagate rather than being re-stamped: the forwarded event keeps the
            // instant at which its condition was observed, not the instant this hop ran.
            event => {
                self.ctx
                    .event_outs
                    .push_back(TaggedRTCEventInternal { now, event });
            }
        }
        Ok(())
    }

    fn poll_event(&mut self) -> Option<Self::Eout> {
        self.ctx.event_outs.pop_front()
    }

    fn handle_timeout(&mut self, now: Instant) -> Result<()> {
        self.ctx.observe(now);

        // Close in-band channels whose DCEP handshake did not complete in time.
        let mut timed_out = Vec::new();
        for dc in self.data_channels.values() {
            if let Some(deadline) = dc.handshake_deadline
                && dc.ready_state == RTCDataChannelState::Connecting
                && deadline <= now
            {
                timed_out.push(dc.id);
            }
        }

        for id in timed_out {
            if let Some(dc) = self.data_channels.get_mut(&id) {
                dc.handshake_deadline = None;
                dc.ready_state = RTCDataChannelState::Closed;
                if let Some(data_channel) = dc.data_channel.as_mut() {
                    data_channel.close()?;
                }

                // Closed for good. It never opened, so it is not one of `dataChannelsClosed`.
                self.stats.on_data_channel_gone(id);

                dc.close_emitted = true;
                // W3C 6.2.7 "unable to create the underlying data transport": the channel is
                // closed with an error (`data-channel-failure`), then the close event.
                Self::push_channel_error(
                    &mut self.ctx.event_outs,
                    self.data_channels,
                    now,
                    id,
                    RTCError::new(
                        RTCErrorDetailType::DataChannelFailure,
                        "the DCEP handshake did not complete in time",
                    ),
                );
                self.ctx.event_outs.push_back(TaggedRTCEventInternal {
                    now,
                    event: RTCEventInternal::RTCPeerConnectionEvent(
                        RTCPeerConnectionEvent::OnDataChannel(RTCDataChannelEvent::OnClose(id)),
                    ),
                });
            }
        }

        Ok(())
    }

    fn poll_timeout(&mut self) -> Option<Instant> {
        self.data_channels
            .values()
            .filter_map(|dc| {
                if dc.ready_state == RTCDataChannelState::Connecting {
                    dc.handshake_deadline
                } else {
                    None
                }
            })
            .min()
    }

    fn close(&mut self) -> Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    //! Timing contract for the DCEP handshake-complete signal.
    //!
    //! These drive `DataChannelHandler` directly and pin
    //! *when* the open event fires and `ready_state` flips, which the integration
    //! tests cannot see: they only require the open event to fire *eventually*, so
    //! they pass whether the channel is promoted at dial time or on the ACK.

    use super::*;
    use crate::data_channel::parameters::DataChannelParameters;
    use crate::statistics::accumulator::RTCStatsAccumulator;
    use bytes::BytesMut;
    use datachannel::data_channel::DataChannelMessage;
    use datachannel::message::Message;
    use datachannel::message::message_channel_ack::DataChannelAck;
    use sansio::Protocol;
    use sctp::StreamId;
    use shared::marshal::Marshal;

    /// An in-band channel that already has its stream id, i.e. one past the point where
    /// `assign_stream_ids` would have run. These tests are about DCEP open/ack timing, not
    /// about stream-id assignment.
    fn in_band_channel(stream_id: StreamId) -> RTCDataChannelInternal {
        let mut dc = RTCDataChannelInternal::new(DataChannelParameters {
            label: "timing-test".to_string(),
            protocol: String::new(),
            ordered: true,
            max_packet_life_time: None,
            max_retransmits: None,
            negotiated: None,
        });
        dc.stream_id = Some(stream_id);
        dc
    }

    fn negotiated_channel(stream_id: StreamId) -> RTCDataChannelInternal {
        RTCDataChannelInternal::new(DataChannelParameters {
            label: "timing-test".to_string(),
            protocol: String::new(),
            ordered: true,
            max_packet_life_time: None,
            max_retransmits: None,
            negotiated: Some(stream_id),
        })
    }

    /// A registry seeded with `channels`, returning it alongside their handles in the order
    /// given.
    fn registry(
        channels: Vec<RTCDataChannelInternal>,
    ) -> (DataChannelRegistry, Vec<RTCDataChannelId>) {
        let mut reg = DataChannelRegistry::new();
        let handles = channels.into_iter().map(|dc| reg.insert(dc)).collect();
        (reg, handles)
    }

    fn ack(association_handle: usize, stream_id: u16) -> DataChannelMessage {
        let ack = Message::DataChannelAck(DataChannelAck {})
            .marshal()
            .unwrap();
        DataChannelMessage {
            association_handle,
            stream_id,
            ppi: PayloadProtocolIdentifier::Dcep,
            payload: BytesMut::from(&ack[..]),
            negotiated: false,
        }
    }

    fn data_message(association_handle: usize, stream_id: u16, data: &[u8]) -> DataChannelMessage {
        DataChannelMessage {
            association_handle,
            stream_id,
            ppi: PayloadProtocolIdentifier::String,
            payload: BytesMut::from(data),
            negotiated: false,
        }
    }

    fn message_events(ctx: &DataChannelHandlerContext) -> Vec<DataChannelEvent> {
        ctx.read_outs
            .iter()
            .filter_map(|m| match &m.message {
                RTCMessageInternal::Dtls(DTLSMessage::DataChannel(app)) => {
                    Some(app.data_channel_event.clone())
                }
                _ => None,
            })
            .collect()
    }

    /// An in-band channel is dialed at `SCTPHandshakeComplete` but stays
    /// `Connecting` with no open event; the open event fires exactly once, and
    /// `ready_state` flips to `Open`, only when the peer's `DATA_CHANNEL_ACK`
    /// is processed.
    #[test]
    fn in_band_channel_fires_open_only_when_ack_is_processed() {
        let now = Instant::now();
        let mut ctx = DataChannelHandlerContext::new(now);
        let (mut data_channels, handles) = registry(vec![in_band_channel(1)]);
        let handle = handles[0];
        let mut stats = RTCStatsAccumulator::new();

        {
            let mut handler = DataChannelHandler::new(
                &mut ctx,
                &mut data_channels,
                &mut stats,
                None,
                RTCDtlsRole::Server,
                None,
            );
            handler
                .handle_event(TaggedRTCEventInternal {
                    now,
                    event: RTCEventInternal::SCTPHandshakeComplete(0),
                })
                .unwrap();
        }

        let dc = data_channels.get(&handle).unwrap();
        assert!(
            dc.data_channel.is_some(),
            "SCTPHandshakeComplete must dial the in-band channel"
        );
        assert_eq!(
            dc.ready_state,
            RTCDataChannelState::Connecting,
            "an in-band channel must stay Connecting after the SCTP handshake"
        );
        assert!(
            ctx.read_outs.iter().all(|m| !matches!(
                &m.message,
                RTCMessageInternal::Dtls(DTLSMessage::DataChannel(app))
                    if matches!(app.data_channel_event, DataChannelEvent::Open)
            )),
            "no open event may fire at SCTPHandshakeComplete time"
        );

        {
            let mut handler = DataChannelHandler::new(
                &mut ctx,
                &mut data_channels,
                &mut stats,
                None,
                RTCDtlsRole::Server,
                None,
            );
            handler
                .handle_read(TaggedRTCMessageInternal {
                    now,
                    transport: TransportContext::default(),
                    message: RTCMessageInternal::Dtls(DTLSMessage::Sctp(ack(0, 1))),
                })
                .unwrap();
        }

        assert_eq!(
            data_channels.get(&handle).unwrap().ready_state,
            RTCDataChannelState::Open,
            "ready_state flips to Open exactly when the ACK is processed"
        );

        let open_events: Vec<RTCDataChannelId> = ctx
            .read_outs
            .iter()
            .filter_map(|m| match &m.message {
                RTCMessageInternal::Dtls(DTLSMessage::DataChannel(app))
                    if matches!(app.data_channel_event, DataChannelEvent::Open) =>
                {
                    Some(app.data_channel_id)
                }
                _ => None,
            })
            .collect();
        assert_eq!(
            open_events,
            vec![handle],
            "exactly one open event, fired on the ACK"
        );
        assert_eq!(
            stats.peer_connection.data_channels_opened, 1,
            "open stats recorded exactly once"
        );
    }

    /// W3C 6.1.1.3, the connected procedure: a channel whose id is not below [[MaxChannels]],
    /// or that could be given none, is closed with a failure (`error` with
    /// `data-channel-failure`, then `close`); the others are dialed as usual. Running out of
    /// ids used to fail the whole event, so no channel was dialed at all.
    #[test]
    fn channels_without_a_usable_id_are_closed_with_a_failure_at_connect() {
        let now = Instant::now();
        let mut ctx = DataChannelHandlerContext::new(now);
        // Two streams: ids 0 and 1. The negotiated id 5 is above them; the DTLS server's
        // in-band channels take odd ids, so the second one finds none.
        let (mut data_channels, handles) = registry(vec![
            negotiated_channel(5),
            negotiated_channel(0),
            in_band_channel(0),
            in_band_channel(0),
        ]);
        for handle in &handles[2..] {
            data_channels.get_mut(handle).unwrap().stream_id = None;
        }
        let mut stats = RTCStatsAccumulator::new();
        let mut handler = DataChannelHandler::new(
            &mut ctx,
            &mut data_channels,
            &mut stats,
            None,
            RTCDtlsRole::Server,
            Some(2),
        );
        handler
            .handle_event(TaggedRTCEventInternal {
                now,
                event: RTCEventInternal::SCTPHandshakeComplete(0),
            })
            .unwrap();
        let events: Vec<RTCDataChannelEvent> = std::iter::from_fn(|| handler.poll_event())
            .filter_map(|e| match e.event {
                RTCEventInternal::RTCPeerConnectionEvent(
                    RTCPeerConnectionEvent::OnDataChannel(e),
                ) => Some(e),
                _ => None,
            })
            .collect();
        for failed in [handles[0], handles[3]] {
            let error = events
                .iter()
                .position(|e| *e == RTCDataChannelEvent::OnError(failed))
                .unwrap_or_else(|| panic!("an error for {failed}: {events:?}"));
            let close = events
                .iter()
                .position(|e| *e == RTCDataChannelEvent::OnClose(failed))
                .unwrap_or_else(|| panic!("a close for {failed}: {events:?}"));
            assert!(error < close, "{events:?}");
            assert_eq!(
                data_channels.error(failed).map(|e| e.error_detail),
                Some(RTCErrorDetailType::DataChannelFailure)
            );
        }
        assert_eq!(
            data_channels.get(&handles[1]).map(|dc| dc.ready_state),
            Some(RTCDataChannelState::Open),
            "the negotiated channel on stream 0 opened"
        );
        assert!(
            data_channels
                .get(&handles[2])
                .is_some_and(|dc| dc.data_channel.is_some() && dc.stream_id == Some(1)),
            "the first in-band channel was dialed on stream 1"
        );
    }

    /// A negotiated (out-of-band) channel has no DCEP handshake: it dials open
    /// immediately and fires the open event at `SCTPHandshakeComplete`.
    #[test]
    fn negotiated_channel_fires_open_at_handshake_complete() {
        let now = Instant::now();
        let mut ctx = DataChannelHandlerContext::new(now);
        let (mut data_channels, handles) = registry(vec![negotiated_channel(1)]);
        let handle = handles[0];
        let mut stats = RTCStatsAccumulator::new();

        let mut handler = DataChannelHandler::new(
            &mut ctx,
            &mut data_channels,
            &mut stats,
            None,
            RTCDtlsRole::Server,
            None,
        );
        handler
            .handle_event(TaggedRTCEventInternal {
                now,
                event: RTCEventInternal::SCTPHandshakeComplete(0),
            })
            .unwrap();

        let dc = data_channels.get(&handle).unwrap();
        assert_eq!(
            dc.ready_state,
            RTCDataChannelState::Open,
            "a negotiated channel is open immediately at SCTPHandshakeComplete"
        );
        assert!(
            dc.handshake_deadline.is_none(),
            "a negotiated channel has no DCEP handshake deadline"
        );

        let open_events: Vec<RTCDataChannelId> = ctx
            .read_outs
            .iter()
            .filter_map(|m| match &m.message {
                RTCMessageInternal::Dtls(DTLSMessage::DataChannel(app))
                    if matches!(app.data_channel_event, DataChannelEvent::Open) =>
                {
                    Some(app.data_channel_id)
                }
                _ => None,
            })
            .collect();
        assert_eq!(
            open_events,
            vec![handle],
            "exactly one open event at SCTPHandshakeComplete for a negotiated channel"
        );
        assert_eq!(
            stats.peer_connection.data_channels_opened, 1,
            "open stats recorded for the negotiated channel"
        );
    }

    /// `emit_data_channel_opened` returns an error when the channel does not exist.
    #[test]
    fn emit_data_channel_opened_missing_channel_returns_error() {
        let now = Instant::now();
        let mut ctx = DataChannelHandlerContext::new(now);
        let mut data_channels = DataChannelRegistry::new();
        let mut stats = RTCStatsAccumulator::new();

        let mut handler = DataChannelHandler::new(
            &mut ctx,
            &mut data_channels,
            &mut stats,
            None,
            RTCDtlsRole::Server,
            None,
        );
        let err = handler
            .emit_data_channel_opened(now, TransportContext::default(), 99)
            .unwrap_err();
        assert_eq!(err, Error::ErrDataChannelNotExisted);
    }

    /// A second `SCTPHandshakeComplete` must not re-dial an already-dialed
    /// in-band channel: it stays Connecting after dialing, so the
    /// `data_channel.is_none()` guard is what excludes it.
    #[test]
    fn sctp_handshake_complete_does_not_redial() {
        let now = Instant::now();
        let mut ctx = DataChannelHandlerContext::new(now);
        let (mut data_channels, handles) = registry(vec![in_band_channel(1)]);
        let _handle = handles[0];
        let mut stats = RTCStatsAccumulator::new();

        // Fire SCTPHandshakeComplete once; this dials the channel and queues its OPEN.
        {
            let mut handler = DataChannelHandler::new(
                &mut ctx,
                &mut data_channels,
                &mut stats,
                None,
                RTCDtlsRole::Server,
                None,
            );
            handler
                .handle_event(TaggedRTCEventInternal {
                    now,
                    event: RTCEventInternal::SCTPHandshakeComplete(0),
                })
                .unwrap();
        }
        let first_writes = ctx.write_outs.len();
        assert!(
            first_writes >= 1,
            "dialing must queue the DATA_CHANNEL_OPEN"
        );
        ctx.write_outs.clear();

        // Fire it again: no new dial, so nothing new is queued.
        {
            let mut handler = DataChannelHandler::new(
                &mut ctx,
                &mut data_channels,
                &mut stats,
                None,
                RTCDtlsRole::Server,
                None,
            );
            handler
                .handle_event(TaggedRTCEventInternal {
                    now,
                    event: RTCEventInternal::SCTPHandshakeComplete(0),
                })
                .unwrap();
        }
        assert_eq!(
            ctx.write_outs.len(),
            0,
            "a second SCTPHandshakeComplete must not re-dial the channel"
        );
    }

    /// A straggler `DATA_CHANNEL_ACK` on a channel that has already been closed
    /// must be ignored: it must not flip state or emit an open event.
    #[test]
    fn ack_on_closed_channel_is_ignored() {
        let now = Instant::now();
        let mut ctx = DataChannelHandlerContext::new(now);
        let mut dc = in_band_channel(1);
        dc.ready_state = RTCDataChannelState::Closed;
        let (mut data_channels, handles) = registry(vec![dc]);
        let handle = handles[0];
        let mut stats = RTCStatsAccumulator::new();

        let mut handler = DataChannelHandler::new(
            &mut ctx,
            &mut data_channels,
            &mut stats,
            None,
            RTCDtlsRole::Server,
            None,
        );
        handler
            .handle_read(TaggedRTCMessageInternal {
                now,
                transport: TransportContext::default(),
                message: RTCMessageInternal::Dtls(DTLSMessage::Sctp(ack(0, 1))),
            })
            .unwrap();

        assert_eq!(
            data_channels.get(&handle).unwrap().ready_state,
            RTCDataChannelState::Closed,
            "a closed channel must ignore a late ACK"
        );
        assert!(
            !message_events(&ctx)
                .iter()
                .any(|e| matches!(e, DataChannelEvent::Open)),
            "no open event may fire for a closed channel"
        );
    }

    fn channel_events(ctx: &DataChannelHandlerContext) -> Vec<RTCDataChannelEvent> {
        ctx.event_outs
            .iter()
            .filter_map(|e| match &e.event {
                RTCEventInternal::RTCPeerConnectionEvent(
                    RTCPeerConnectionEvent::OnDataChannel(dc),
                ) => Some(dc.clone()),
                _ => None,
            })
            .collect()
    }

    fn feed(
        ctx: &mut DataChannelHandlerContext,
        data_channels: &mut DataChannelRegistry,
        events: Vec<RTCEventInternal>,
    ) {
        let mut stats = RTCStatsAccumulator::new();
        let mut handler = DataChannelHandler::new(
            ctx,
            data_channels,
            &mut stats,
            None,
            RTCDtlsRole::Server,
            None,
        );
        for event in events {
            handler
                .handle_event(TaggedRTCEventInternal {
                    now: Instant::now(),
                    event,
                })
                .unwrap();
        }
    }

    /// W3C closing procedure: a close the remote side starts takes an open channel through
    /// `closing` to `closed`.
    #[test]
    fn remote_close_fires_closing_then_close() {
        let mut ctx = DataChannelHandlerContext::new(Instant::now());
        let mut dc = in_band_channel(1);
        dc.ready_state = RTCDataChannelState::Open;
        let (mut data_channels, handles) = registry(vec![dc]);
        feed(
            &mut ctx,
            &mut data_channels,
            vec![RTCEventInternal::SCTPStreamClosed(0, 1)],
        );
        assert_eq!(
            channel_events(&ctx),
            vec![
                RTCDataChannelEvent::OnClosing(handles[0]),
                RTCDataChannelEvent::OnClose(handles[0]),
            ]
        );
    }

    /// A channel this side is closing is already `closing`: its close completes with `close`
    /// alone.
    #[test]
    fn local_close_completes_with_close_only() {
        let mut ctx = DataChannelHandlerContext::new(Instant::now());
        let mut dc = in_band_channel(1);
        dc.ready_state = RTCDataChannelState::Closing;
        let (mut data_channels, handles) = registry(vec![dc]);
        feed(
            &mut ctx,
            &mut data_channels,
            vec![RTCEventInternal::SCTPStreamClosed(0, 1)],
        );
        assert_eq!(
            channel_events(&ctx),
            vec![RTCDataChannelEvent::OnClose(handles[0])]
        );
    }

    /// The association lost under an open channel (the peer's ABORT): `error`, then `close`,
    /// and no `closing` (W3C "announce the data channel as closed" with an error).
    #[test]
    fn association_failure_fires_error_then_close() {
        let mut ctx = DataChannelHandlerContext::new(Instant::now());
        let mut dc = negotiated_channel(3);
        dc.ready_state = RTCDataChannelState::Open;
        let (mut data_channels, handles) = registry(vec![dc]);
        feed(
            &mut ctx,
            &mut data_channels,
            vec![
                RTCEventInternal::SCTPStreamFailed(0, 3),
                RTCEventInternal::SCTPStreamClosed(0, 3),
            ],
        );
        assert_eq!(
            channel_events(&ctx),
            vec![
                RTCDataChannelEvent::OnError(handles[0]),
                RTCDataChannelEvent::OnClose(handles[0]),
            ]
        );
    }

    /// An association lost to an error fails every channel over it, a pre-negotiated one that
    /// never carried data (and so has no SCTP stream to report) included, once each, and
    /// closes it: its underlying data transport is gone.
    #[test]
    fn association_failure_fails_idle_negotiated_channels() {
        let mut ctx = DataChannelHandlerContext::new(Instant::now());
        let mut dc = negotiated_channel(0);
        dc.ready_state = RTCDataChannelState::Open;
        let (mut data_channels, handles) = registry(vec![dc]);
        feed(
            &mut ctx,
            &mut data_channels,
            vec![
                RTCEventInternal::SCTPAssociationFailed(0),
                RTCEventInternal::SCTPStreamFailed(0, 0),
            ],
        );
        assert_eq!(
            channel_events(&ctx),
            vec![
                RTCDataChannelEvent::OnError(handles[0]),
                RTCDataChannelEvent::OnClose(handles[0]),
            ]
        );
        assert!(data_channels.is_empty());
    }

    /// An association that fails in its handshake opened no stream, so no stream event closes
    /// its channels: the association's own failure must (B5). They were left `connecting`.
    #[test]
    fn handshake_failure_closes_connecting_channels() {
        let mut ctx = DataChannelHandlerContext::new(Instant::now());
        let (mut data_channels, handles) =
            registry(vec![in_band_channel(1), negotiated_channel(2)]);
        feed(
            &mut ctx,
            &mut data_channels,
            vec![RTCEventInternal::SCTPAssociationFailed(0)],
        );
        assert_eq!(
            channel_events(&ctx),
            vec![
                RTCDataChannelEvent::OnError(handles[0]),
                RTCDataChannelEvent::OnClose(handles[0]),
                RTCDataChannelEvent::OnError(handles[1]),
                RTCDataChannelEvent::OnClose(handles[1]),
            ]
        );
        assert!(data_channels.is_empty());
    }

    /// A channel the stream path already closed is not closed (or failed) twice.
    #[test]
    fn association_failure_after_stream_failure_closes_once() {
        let mut ctx = DataChannelHandlerContext::new(Instant::now());
        let mut dc = negotiated_channel(3);
        dc.ready_state = RTCDataChannelState::Open;
        let (mut data_channels, handles) = registry(vec![dc]);
        feed(
            &mut ctx,
            &mut data_channels,
            vec![
                RTCEventInternal::SCTPStreamFailed(0, 3),
                RTCEventInternal::SCTPStreamClosed(0, 3),
                RTCEventInternal::SCTPAssociationFailed(0),
            ],
        );
        assert_eq!(
            channel_events(&ctx),
            vec![
                RTCDataChannelEvent::OnError(handles[0]),
                RTCDataChannelEvent::OnClose(handles[0]),
            ]
        );
    }

    /// An in-band channel whose ACK never arrives must time out: it transitions
    /// to Closed and fires OnClose once. It never opened, so it is not counted as closed.
    #[test]
    fn in_band_channel_times_out_without_ack() {
        let now = Instant::now();
        let timeout = Duration::from_millis(100);
        let mut ctx = DataChannelHandlerContext::new(now);
        let (mut data_channels, handles) = registry(vec![in_band_channel(1)]);
        let handle = handles[0];
        let mut stats = RTCStatsAccumulator::new();

        // Dial the in-band channel and arm a deadline.
        {
            let mut handler = DataChannelHandler::new(
                &mut ctx,
                &mut data_channels,
                &mut stats,
                Some(timeout),
                RTCDtlsRole::Server,
                None,
            );
            handler
                .handle_event(TaggedRTCEventInternal {
                    now,
                    event: RTCEventInternal::SCTPHandshakeComplete(0),
                })
                .unwrap();
        }

        // A deadline must be reported.
        {
            let mut handler = DataChannelHandler::new(
                &mut ctx,
                &mut data_channels,
                &mut stats,
                Some(timeout),
                RTCDtlsRole::Server,
                None,
            );
            let deadline = handler
                .poll_timeout()
                .expect("a dialed in-band channel must have a deadline");
            assert!(deadline <= now + timeout);
        }

        // Advance past the deadline and let handle_timeout fire.
        let later = now + timeout + Duration::from_secs(1);
        {
            let mut handler = DataChannelHandler::new(
                &mut ctx,
                &mut data_channels,
                &mut stats,
                Some(timeout),
                RTCDtlsRole::Server,
                None,
            );
            handler.handle_timeout(later).unwrap();
        }

        let dc = data_channels.get(&handle).unwrap();
        assert_eq!(
            dc.ready_state,
            RTCDataChannelState::Closed,
            "a timed-out channel must be Closed"
        );
        assert!(
            dc.handshake_deadline.is_none(),
            "timeout must clear the deadline"
        );
        assert!(
            !message_events(&ctx)
                .iter()
                .any(|e| matches!(e, DataChannelEvent::Open)),
            "no open event for a timed-out channel"
        );

        let closes = ctx
            .event_outs
            .iter()
            .filter(|e| {
                matches!(
                    &e.event,
                    RTCEventInternal::RTCPeerConnectionEvent(
                        RTCPeerConnectionEvent::OnDataChannel(RTCDataChannelEvent::OnClose(id))
                    ) if *id == handle
                )
            })
            .count();
        assert_eq!(closes, 1, "exactly one OnClose for the timed-out channel");

        // webrtc-stats `dataChannelsClosed` counts the channels that left the `open` state:
        // this one never was in it, and opened minus closed (the channels open now) stays 0.
        assert_eq!(stats.peer_connection.data_channels_opened, 0);
        assert_eq!(stats.peer_connection.data_channels_closed, 0);
        assert!(
            stats
                .data_channels
                .values()
                .all(|c| c.state == RTCDataChannelState::Closed),
            "its statistics stay, closed (webrtc-stats lifetime)"
        );

        // No further deadlines remain.
        {
            let mut handler = DataChannelHandler::new(
                &mut ctx,
                &mut data_channels,
                &mut stats,
                Some(timeout),
                RTCDtlsRole::Server,
                None,
            );
            assert!(
                handler.poll_timeout().is_none(),
                "no deadline after the timeout fired"
            );
        }
    }

    /// A user message arriving before the ACK is buffered and delivered only
    /// after the channel opens, with the open event first.
    #[test]
    fn pre_open_data_is_buffered_until_open() {
        let now = Instant::now();
        let mut ctx = DataChannelHandlerContext::new(now);
        let (mut data_channels, handles) = registry(vec![in_band_channel(1)]);
        let _handle = handles[0];
        let mut stats = RTCStatsAccumulator::new();

        // Dial first.
        {
            let mut handler = DataChannelHandler::new(
                &mut ctx,
                &mut data_channels,
                &mut stats,
                None,
                RTCDtlsRole::Server,
                None,
            );
            handler
                .handle_event(TaggedRTCEventInternal {
                    now,
                    event: RTCEventInternal::SCTPHandshakeComplete(0),
                })
                .unwrap();
        }

        // A user data message arrives while the channel is still Connecting.
        {
            let mut handler = DataChannelHandler::new(
                &mut ctx,
                &mut data_channels,
                &mut stats,
                None,
                RTCDtlsRole::Server,
                None,
            );
            handler
                .handle_read(TaggedRTCMessageInternal {
                    now,
                    transport: TransportContext::default(),
                    message: RTCMessageInternal::Dtls(DTLSMessage::Sctp(data_message(
                        0, 1, b"hello",
                    ))),
                })
                .unwrap();
        }

        // No message event yet.
        assert!(
            !message_events(&ctx)
                .iter()
                .any(|e| matches!(e, DataChannelEvent::Message(_))),
            "no message may be delivered before the channel is open"
        );

        // The ACK arrives: the channel opens and the buffered message is delivered,
        // with the open event first.
        {
            let mut handler = DataChannelHandler::new(
                &mut ctx,
                &mut data_channels,
                &mut stats,
                None,
                RTCDtlsRole::Server,
                None,
            );
            handler
                .handle_read(TaggedRTCMessageInternal {
                    now,
                    transport: TransportContext::default(),
                    message: RTCMessageInternal::Dtls(DTLSMessage::Sctp(ack(0, 1))),
                })
                .unwrap();
        }

        let events = message_events(&ctx);
        assert!(
            matches!(events.first(), Some(DataChannelEvent::Open)),
            "open event must fire first"
        );
        assert!(
            matches!(events.get(1), Some(DataChannelEvent::Message(_))),
            "the buffered message must be delivered after the open event"
        );
    }

    /// A user message buffered before the ACK is discarded if the channel times
    /// out: it must never be delivered to the application.
    #[test]
    fn pre_open_data_is_dropped_on_timeout() {
        let now = Instant::now();
        let timeout = Duration::from_millis(100);
        let mut ctx = DataChannelHandlerContext::new(now);
        let (mut data_channels, handles) = registry(vec![in_band_channel(1)]);
        let _handle = handles[0];
        let mut stats = RTCStatsAccumulator::new();

        {
            let mut handler = DataChannelHandler::new(
                &mut ctx,
                &mut data_channels,
                &mut stats,
                Some(timeout),
                RTCDtlsRole::Server,
                None,
            );
            handler
                .handle_event(TaggedRTCEventInternal {
                    now,
                    event: RTCEventInternal::SCTPHandshakeComplete(0),
                })
                .unwrap();
        }

        // Buffer a user message while Connecting.
        {
            let mut handler = DataChannelHandler::new(
                &mut ctx,
                &mut data_channels,
                &mut stats,
                Some(timeout),
                RTCDtlsRole::Server,
                None,
            );
            handler
                .handle_read(TaggedRTCMessageInternal {
                    now,
                    transport: TransportContext::default(),
                    message: RTCMessageInternal::Dtls(DTLSMessage::Sctp(data_message(
                        0, 1, b"bye",
                    ))),
                })
                .unwrap();
        }

        // Time out; the channel closes and the buffered message must not be delivered.
        let later = now + timeout + Duration::from_secs(1);
        {
            let mut handler = DataChannelHandler::new(
                &mut ctx,
                &mut data_channels,
                &mut stats,
                Some(timeout),
                RTCDtlsRole::Server,
                None,
            );
            handler.handle_timeout(later).unwrap();
        }

        assert!(
            !message_events(&ctx)
                .iter()
                .any(|e| matches!(e, DataChannelEvent::Message(_))),
            "a buffered message must never be delivered after the timeout"
        );
    }

    /// A DCEP OPEN from the peer, on `stream_id`.
    fn open_message(association_handle: usize, stream_id: u16) -> DataChannelMessage {
        use datachannel::message::message_channel_open::{
            CHANNEL_PRIORITY_NORMAL, ChannelType, DataChannelOpen,
        };
        let open = Message::DataChannelOpen(DataChannelOpen {
            channel_type: ChannelType::Reliable,
            priority: CHANNEL_PRIORITY_NORMAL,
            reliability_parameter: 0,
            label: b"peer".to_vec(),
            protocol: Vec::new(),
        })
        .marshal()
        .unwrap();
        DataChannelMessage {
            association_handle,
            stream_id,
            ppi: PayloadProtocolIdentifier::Dcep,
            payload: BytesMut::from(&open[..]),
            negotiated: false,
        }
    }

    /// RFC 8832 §6: the DTLS client opens channels on even stream ids and the server on odd
    /// ones. An OPEN from the peer on an id of this side's parity is refused, and the stream
    /// reset, so the peer cannot take an id `assign_stream_ids` may give a local channel.
    /// Negotiated channels are registered on both sides and keep working on either parity.
    #[test]
    fn peer_open_with_this_sides_stream_parity_is_rejected() {
        // (this side's role, an id of the peer's parity, an id of this side's parity)
        for (role, peer_id, own_id) in [(RTCDtlsRole::Client, 3, 2), (RTCDtlsRole::Server, 2, 3)] {
            let now = Instant::now();
            let mut ctx = DataChannelHandlerContext::new(now);
            let (mut data_channels, handles) =
                registry(vec![negotiated_channel(4), negotiated_channel(5)]);
            let mut stats = RTCStatsAccumulator::new();
            let mut handler =
                DataChannelHandler::new(&mut ctx, &mut data_channels, &mut stats, None, role, None);
            handler
                .handle_event(TaggedRTCEventInternal {
                    now,
                    event: RTCEventInternal::SCTPHandshakeComplete(0),
                })
                .unwrap();
            while handler.poll_write().is_some() {}
            while handler.poll_read().is_some() {}

            let read = |handler: &mut DataChannelHandler<'_>, message: DataChannelMessage| {
                handler
                    .handle_read(TaggedRTCMessageInternal {
                        now,
                        transport: TransportContext::default(),
                        message: RTCMessageInternal::Dtls(DTLSMessage::Sctp(message)),
                    })
                    .unwrap()
            };

            read(&mut handler, open_message(0, own_id));
            assert!(
                handler.poll_read().is_none(),
                "{role}: the peer opened a channel on stream {own_id}, of this side's parity"
            );
            let reset = handler.poll_write().expect("the refused stream is reset");
            match reset.message {
                RTCMessageInternal::Dtls(DTLSMessage::Sctp(m)) => {
                    use shared::marshal::Unmarshal;
                    assert_eq!(m.stream_id, own_id);
                    assert!(matches!(
                        Message::unmarshal(&mut &m.payload[..]),
                        Ok(Message::DataChannelClose(_))
                    ));
                }
                _ => panic!("{role}: expected a DCEP close for the refused stream"),
            }

            read(&mut handler, open_message(0, peer_id));
            assert!(
                matches!(
                    handler.poll_read().map(|m| m.message),
                    Some(RTCMessageInternal::Dtls(DTLSMessage::DataChannel(
                        ApplicationMessage {
                            data_channel_event: DataChannelEvent::Open,
                            ..
                        }
                    )))
                ),
                "{role}: the peer's OPEN on stream {peer_id} opens a channel"
            );
            while handler.poll_read().is_some() {}

            // Negotiated channels, whichever parity they were given, still carry data.
            for (handle, stream_id) in [(handles[0], 4), (handles[1], 5)] {
                read(&mut handler, data_message(0, stream_id, b"hi"));
                assert!(
                    matches!(
                        handler.poll_read().map(|m| m.message),
                        Some(RTCMessageInternal::Dtls(DTLSMessage::DataChannel(
                            ApplicationMessage {
                                data_channel_id,
                                data_channel_event: DataChannelEvent::Message(_),
                            }
                        ))) if data_channel_id == handle
                    ),
                    "{role}: negotiated stream {stream_id} lost its data"
                );
            }
            drop(handler);
            assert_eq!(data_channels.len(), 3);
        }
    }

    /// A peer that opens, uses and resets channels in a loop leaves no statistics behind: a
    /// channel's entry goes when it closes. Its label is held by the DCEP channel alone, and
    /// messages are counted against the existing entry.
    #[test]
    fn peer_channel_statistics_are_freed_on_close() {
        use datachannel::message::message_channel_open::{
            CHANNEL_PRIORITY_NORMAL, ChannelType, DataChannelOpen,
        };
        const PEER_STREAM: u16 = 3; // odd: the peer's parity when this side is the DTLS client
        let label = vec![b'l'; 32 * 1024];
        let protocol = vec![b'p'; 1024];
        let open = Message::DataChannelOpen(DataChannelOpen {
            channel_type: ChannelType::Reliable,
            priority: CHANNEL_PRIORITY_NORMAL,
            reliability_parameter: 0,
            label: label.clone(),
            protocol: protocol.clone(),
        })
        .marshal()
        .unwrap();

        let now = Instant::now();
        let mut ctx = DataChannelHandlerContext::new(now);
        let mut data_channels = DataChannelRegistry::new();
        let mut stats = RTCStatsAccumulator::new();
        let mut handler = DataChannelHandler::new(
            &mut ctx,
            &mut data_channels,
            &mut stats,
            None,
            RTCDtlsRole::Client,
            None,
        );
        let read = |handler: &mut DataChannelHandler<'_>, message: DataChannelMessage| {
            handler
                .handle_read(TaggedRTCMessageInternal {
                    now,
                    transport: TransportContext::default(),
                    message: RTCMessageInternal::Dtls(DTLSMessage::Sctp(message)),
                })
                .unwrap()
        };

        for _ in 0..200 {
            read(
                &mut handler,
                DataChannelMessage {
                    association_handle: 0,
                    stream_id: PEER_STREAM,
                    ppi: PayloadProtocolIdentifier::Dcep,
                    payload: BytesMut::from(&open[..]),
                    negotiated: false,
                },
            );
            for _ in 0..3 {
                read(&mut handler, data_message(0, PEER_STREAM, b"x"));
            }

            let handle = handler
                .data_channels
                .handle_of_stream(&PEER_STREAM)
                .expect("the peer's channel is open");
            let dc = handler.data_channels.get(&handle).unwrap();
            assert_eq!(dc.label().as_bytes(), &label[..]);
            assert_eq!(dc.protocol().as_bytes(), &protocol[..]);
            assert!(dc.label.is_empty() && dc.protocol.is_empty(), "held twice");
            let live = |stats: &RTCStatsAccumulator| {
                stats
                    .data_channels
                    .values()
                    .filter(|c| c.state != RTCDataChannelState::Closed)
                    .count()
            };
            assert_eq!(live(handler.stats), 1);
            let dc_stats = &handler.stats.data_channels[&handle];
            assert_eq!(dc_stats.messages_received, 3);
            assert_eq!(dc_stats.label.as_bytes(), &label[..]);

            handler
                .handle_event(TaggedRTCEventInternal {
                    now,
                    event: RTCEventInternal::SCTPStreamClosed(0, PEER_STREAM),
                })
                .unwrap();
            // webrtc-stats lifetime: the closed channel's object stays, "closed", among the
            // last MAX_CLOSED_DATA_CHANNEL_STATS channels closed; older ones go.
            assert_eq!(live(handler.stats), 0);
            assert_eq!(
                handler.stats.data_channels[&handle].state,
                RTCDataChannelState::Closed,
                "a closed channel's statistics are kept, closed"
            );
            assert!(
                handler.stats.data_channels.len()
                    <= crate::statistics::accumulator::MAX_CLOSED_DATA_CHANNEL_STATS,
                "the closed channels kept are bounded"
            );
            while handler.poll_read().is_some() {}
            while handler.poll_write().is_some() {}
            while handler.poll_event().is_some() {}
        }
        drop(handler);
        assert_eq!(data_channels.len(), 0);
        assert_eq!(stats.peer_connection.data_channels_opened, 200);
        assert_eq!(stats.peer_connection.data_channels_closed, 200);
    }

    /// Commit eb4c4f61, RFC 8831 6.6: an empty message travels as one padding byte under an
    /// Empty PPID, and counts as one message of 0 bytes received (webrtc-stats
    /// `bytesReceived`), as the sender counts it as 0 bytes sent. The application gets it empty.
    #[test]
    fn an_empty_message_counts_as_zero_bytes_received() {
        let now = Instant::now();
        let mut ctx = DataChannelHandlerContext::new(now);
        let (mut data_channels, handles) = registry(vec![negotiated_channel(4)]);
        let mut stats = RTCStatsAccumulator::new();
        {
            let mut handler = DataChannelHandler::new(
                &mut ctx,
                &mut data_channels,
                &mut stats,
                None,
                RTCDtlsRole::Client,
                None,
            );
            handler
                .handle_event(TaggedRTCEventInternal {
                    now,
                    event: RTCEventInternal::SCTPHandshakeComplete(0),
                })
                .unwrap();
            while handler.poll_write().is_some() {}
            while handler.poll_read().is_some() {}
            for (ppi, payload) in [
                (PayloadProtocolIdentifier::StringEmpty, &[0u8][..]),
                (PayloadProtocolIdentifier::BinaryEmpty, &[0u8][..]),
                (PayloadProtocolIdentifier::String, &b"hello"[..]),
            ] {
                handler
                    .handle_read(TaggedRTCMessageInternal {
                        now,
                        transport: TransportContext::default(),
                        message: RTCMessageInternal::Dtls(DTLSMessage::Sctp(DataChannelMessage {
                            association_handle: 0,
                            stream_id: 4,
                            ppi,
                            payload: BytesMut::from(payload),
                            negotiated: false,
                        })),
                    })
                    .unwrap();
            }
        }
        let dc_stats = &stats.data_channels[&handles[0]];
        assert_eq!(3, dc_stats.messages_received);
        assert_eq!(
            5, dc_stats.bytes_received,
            "the two empty messages add nothing"
        );
    }

    /// A handler whose association is up: the channels it was given are dialed, and nothing
    /// is left queued.
    struct Connected {
        now: Instant,
        ctx: DataChannelHandlerContext,
        data_channels: DataChannelRegistry,
        stats: RTCStatsAccumulator,
        role: RTCDtlsRole,
        handles: Vec<RTCDataChannelId>,
    }

    impl Connected {
        fn new(role: RTCDtlsRole, channels: Vec<RTCDataChannelInternal>) -> Self {
            let now = Instant::now();
            let (data_channels, handles) = registry(channels);
            let mut connected = Connected {
                now,
                ctx: DataChannelHandlerContext::new(now),
                data_channels,
                stats: RTCStatsAccumulator::new(),
                role,
                handles,
            };
            connected.event(RTCEventInternal::SCTPHandshakeComplete(0));
            connected.written();
            connected.delivered();
            connected
        }

        fn handler(&mut self) -> DataChannelHandler<'_> {
            DataChannelHandler::new(
                &mut self.ctx,
                &mut self.data_channels,
                &mut self.stats,
                None,
                self.role,
                None,
            )
        }

        fn event(&mut self, event: RTCEventInternal) {
            let now = self.now;
            self.handler()
                .handle_event(TaggedRTCEventInternal { now, event })
                .unwrap();
        }

        /// What the SCTP handler delivers for one message from the peer.
        fn read(&mut self, message: DataChannelMessage) -> Result<()> {
            let now = self.now;
            self.handler().handle_read(TaggedRTCMessageInternal {
                now,
                transport: TransportContext::default(),
                message: RTCMessageInternal::Dtls(DTLSMessage::Sctp(message)),
            })
        }

        /// Everything queued towards SCTP since the last call.
        fn written(&mut self) -> Vec<DataChannelMessage> {
            let mut handler = self.handler();
            let mut out = vec![];
            while let Some(msg) = handler.poll_write() {
                if let RTCMessageInternal::Dtls(DTLSMessage::Sctp(message)) = msg.message {
                    out.push(message);
                }
            }
            out
        }

        /// Everything handed towards the application since the last call.
        fn delivered(&mut self) -> Vec<(RTCDataChannelId, DataChannelEvent)> {
            let mut handler = self.handler();
            let mut out = vec![];
            while let Some(msg) = handler.poll_read() {
                if let RTCMessageInternal::Dtls(DTLSMessage::DataChannel(app)) = msg.message {
                    out.push((app.data_channel_id, app.data_channel_event));
                }
            }
            out
        }

        /// The data channel events raised since the last call.
        fn events(&mut self) -> Vec<RTCDataChannelEvent> {
            let events = channel_events(&self.ctx);
            self.ctx.event_outs.clear();
            events
        }
    }

    fn dcep(stream_id: u16, payload: &[u8]) -> DataChannelMessage {
        peer_message(stream_id, PayloadProtocolIdentifier::Dcep, payload)
    }

    fn peer_message(
        stream_id: u16,
        ppi: PayloadProtocolIdentifier,
        payload: &[u8],
    ) -> DataChannelMessage {
        DataChannelMessage {
            association_handle: 0,
            stream_id,
            ppi,
            payload: BytesMut::from(payload),
            negotiated: false,
        }
    }

    /// The DCEP message types among `written`, per stream: what the handler asks SCTP to do.
    fn dcep_types(written: &[DataChannelMessage]) -> Vec<(u16, u8)> {
        written
            .iter()
            .filter(|m| m.ppi == PayloadProtocolIdentifier::Dcep)
            .map(|m| (m.stream_id, m.payload[0]))
            .collect()
    }

    /// The internal message that makes the SCTP handler reset a stream (never on the wire).
    const RESET: u8 = 0x01;
    /// RFC 8832 5.2.
    const ACK: u8 = 0x02;

    /// RFC 8832 section 6: a DATA_CHANNEL_OPEN "received on an already used stream" closes the
    /// data channel, and no DATA_CHANNEL_ACK is sent in response. The stream is one the peer
    /// opened in band, or one both sides negotiated.
    #[test]
    fn an_open_on_a_stream_in_use_closes_the_channel_without_an_ack() {
        // The peer (DTLS server) opens stream 1, and both sides negotiated stream 4.
        let mut c = Connected::new(RTCDtlsRole::Client, vec![negotiated_channel(4)]);
        c.read(open_message(0, 1)).unwrap();
        assert_eq!(dcep_types(&c.written()), vec![(1, ACK)], "the first OPEN");
        let peer_opened = c.data_channels.handle_of_stream(&1).unwrap();
        c.delivered();
        c.events();

        for (stream_id, handle) in [(1, peer_opened), (4, c.handles[0])] {
            c.read(open_message(0, stream_id))
                .expect("a second OPEN is the peer's error, not a read failure");
            assert_eq!(
                dcep_types(&c.written()),
                vec![(stream_id, RESET)],
                "stream {stream_id}: its stream is reset and the OPEN is not acknowledged"
            );
            assert_eq!(
                c.data_channels.get(&handle).unwrap().ready_state,
                RTCDataChannelState::Closed
            );
            assert_eq!(c.events(), vec![RTCDataChannelEvent::OnError(handle)]);
            assert!(c.delivered().is_empty(), "no second open event");

            // The reset completes: the channel is announced closed, as one that failed.
            c.event(RTCEventInternal::SCTPStreamClosed(0, stream_id));
            assert_eq!(c.events(), vec![RTCDataChannelEvent::OnClose(handle)]);
            assert!(c.data_channels.get(&handle).is_none());
        }
    }

    /// RFC 8832 section 6: an OPEN with "invalid parameters" or "inconsistencies of lengths"
    /// closes the channel: the stream the peer used is reset, where it used to stay half open
    /// with the error dropped on the floor. Nothing is acknowledged and no channel exists.
    #[test]
    fn a_malformed_open_resets_its_stream() {
        let mut well_formed = open_message(0, 1).payload.to_vec();
        let truncated = well_formed[..well_formed.len() - 2].to_vec();
        // Label "peer" replaced by bytes that are not UTF-8.
        let label_at = well_formed.len() - 4;
        well_formed[label_at..].copy_from_slice(&[0xff, 0xfe, 0xfd, 0xfc]);
        let bad_utf8 = well_formed;

        let cases: [(&str, Vec<u8>); 7] = [
            (
                "reserved channel type",
                vec![0x03, 0x7f, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            ),
            ("lengths past the end of the message", truncated),
            ("a label that is not UTF-8", bad_utf8),
            ("a header cut short", vec![0x03, 0x00, 0x01]),
            ("an ACK where the OPEN belongs", vec![ACK]),
            ("an unassigned message type", vec![0x7e]),
            ("no message at all", vec![]),
        ];
        for (what, payload) in cases {
            let mut c = Connected::new(RTCDtlsRole::Client, vec![]);
            c.read(dcep(1, &payload))
                .unwrap_or_else(|err| panic!("{what}: returned {err} and reset nothing"));
            assert_eq!(dcep_types(&c.written()), vec![(1, RESET)], "{what}");
            assert!(c.data_channels.is_empty(), "{what}: no channel is created");
            assert!(c.delivered().is_empty(), "{what}: nothing is announced");
        }
    }

    /// RFC 8832 section 6: "If a message other than a DATA_CHANNEL_OPEN is received on an
    /// unused stream, the receiver MUST close the corresponding data channel": user data on a
    /// stream of the peer's parity that no OPEN opened resets it.
    #[test]
    fn user_data_on_a_stream_that_was_never_opened_resets_it() {
        for ppi in [
            PayloadProtocolIdentifier::String,
            PayloadProtocolIdentifier::Binary,
            PayloadProtocolIdentifier::StringEmpty,
            PayloadProtocolIdentifier::BinaryEmpty,
            PayloadProtocolIdentifier::Unknown,
        ] {
            let mut c = Connected::new(RTCDtlsRole::Client, vec![]);
            c.read(peer_message(1, ppi, b"x"))
                .unwrap_or_else(|err| panic!("{ppi}: returned {err} and reset nothing"));
            assert_eq!(dcep_types(&c.written()), vec![(1, RESET)], "{ppi}");
            assert!(c.data_channels.is_empty(), "{ppi}");
            assert!(c.delivered().is_empty(), "{ppi}");
        }
    }

    /// RFC 8831 section 6.6: "The SCTP Payload Protocol Identifiers (PPIDs) are used to signal
    /// the interpretation of the 'payload data'", and a message with an unsupported one closes
    /// the channel. It used to reach the application as a binary message, so each fragment a
    /// peer sent under the deprecated partial PPIDs (52, 54) became a message of its own.
    #[test]
    fn a_message_with_an_unsupported_ppid_closes_the_channel() {
        let mut c = Connected::new(RTCDtlsRole::Client, vec![negotiated_channel(4)]);
        let handle = c.handles[0];
        c.events();

        // 52, 54 and every unassigned value decode to `Unknown`.
        c.read(peer_message(4, PayloadProtocolIdentifier::Unknown, b"??"))
            .expect("the peer's error is not a read failure");
        assert!(
            c.delivered().is_empty(),
            "a message of unknown interpretation is not delivered as binary"
        );
        assert_eq!(dcep_types(&c.written()), vec![(4, RESET)]);
        assert_eq!(c.events(), vec![RTCDataChannelEvent::OnError(handle)]);
        assert_eq!(
            c.data_channels.get(&handle).unwrap().ready_state,
            RTCDataChannelState::Closed
        );

        // What still arrives before the reset completes is not delivered either.
        c.read(data_message(0, 4, b"late")).unwrap();
        assert!(c.delivered().is_empty());
        assert!(c.written().is_empty(), "the stream is reset once");
        assert!(c.events().is_empty(), "the error is reported once");
    }

    /// RFC 8831 section 6.6 (closing on a receive error) for DCEP itself: a control message
    /// that cannot be parsed, or one only this crate uses internally, closes an open channel.
    #[test]
    fn a_malformed_dcep_message_on_an_open_channel_closes_it() {
        for payload in [&[0x7e][..], &[][..], &[0x00, 0, 0, 0, 1][..], &[0x01][..]] {
            let mut c = Connected::new(RTCDtlsRole::Client, vec![negotiated_channel(4)]);
            let handle = c.handles[0];
            c.events();
            c.read(dcep(4, payload))
                .unwrap_or_else(|err| panic!("{payload:?}: returned {err}"));
            assert_eq!(dcep_types(&c.written()), vec![(4, RESET)], "{payload:?}");
            assert_eq!(
                c.events(),
                vec![RTCDataChannelEvent::OnError(handle)],
                "{payload:?}"
            );
        }
    }

    /// A DATA_CHANNEL_ACK on a channel whose handshake is already complete carries nothing
    /// new: it is ignored, the channel stays open (a retransmitted or duplicated ACK must not
    /// cost the channel).
    #[test]
    fn a_repeated_ack_leaves_the_channel_open() {
        let mut c = Connected::new(RTCDtlsRole::Client, vec![in_band_channel(0)]);
        let handle = c.handles[0];
        c.read(ack(0, 0)).unwrap();
        c.read(ack(0, 0)).unwrap();
        assert!(c.written().is_empty());
        assert_eq!(
            c.data_channels.get(&handle).unwrap().ready_state,
            RTCDataChannelState::Open
        );
        assert_eq!(c.delivered().len(), 1, "one open event");
        assert!(c.events().is_empty());
    }

    /// RFC 8831 section 6.6: "When receiving an SCTP user message with one of these PPIDs
    /// [String Empty, Binary Empty], the receiver MUST ignore the SCTP user message and
    /// process it as an empty message": the application gets no byte of it, as a string or as
    /// binary data by its PPID.
    #[test]
    fn an_empty_message_reaches_the_application_empty() {
        let mut c = Connected::new(RTCDtlsRole::Client, vec![negotiated_channel(4)]);
        c.read(peer_message(
            4,
            PayloadProtocolIdentifier::StringEmpty,
            &[0],
        ))
        .unwrap();
        c.read(peer_message(
            4,
            PayloadProtocolIdentifier::BinaryEmpty,
            &[0x55],
        ))
        .unwrap();
        let got: Vec<(bool, Vec<u8>)> = c
            .delivered()
            .into_iter()
            .filter_map(|(_, event)| match event {
                DataChannelEvent::Message(m) => Some((m.is_string, m.data.to_vec())),
                _ => None,
            })
            .collect();
        assert_eq!(got, vec![(true, vec![]), (false, vec![])]);
    }

    /// RFC 8832 section 6: a stream reset that arrives where the DATA_CHANNEL_ACK was expected
    /// means the peer refused the channel. Its setup failed: `error`, then `close`, and no
    /// `closing`, which is the closing procedure of a channel that was open.
    #[test]
    fn a_reset_before_the_ack_fails_the_channel_setup() {
        let mut c = Connected::new(RTCDtlsRole::Client, vec![in_band_channel(0)]);
        let handle = c.handles[0];
        assert_eq!(
            c.data_channels.get(&handle).unwrap().ready_state,
            RTCDataChannelState::Connecting
        );
        c.event(RTCEventInternal::SCTPStreamClosed(0, 0));
        assert_eq!(
            c.events(),
            vec![
                RTCDataChannelEvent::OnError(handle),
                RTCDataChannelEvent::OnClose(handle),
            ]
        );
        assert!(c.data_channels.is_empty());
    }

    /// RFC 8832 section 7: the peer may open as many channels as the association has streams,
    /// and every one of them is accepted; each costs one registry entry, which goes when the
    /// channel closes.
    #[test]
    fn the_peer_may_open_every_stream_of_its_parity() {
        let mut c = Connected::new(RTCDtlsRole::Client, vec![]);
        let streams: Vec<u16> = (1..u16::MAX).step_by(2).collect();
        for stream_id in &streams {
            c.read(open_message(0, *stream_id)).unwrap();
        }
        assert_eq!(c.data_channels.len(), streams.len());
        // Counted where `handle_read` queues them: `poll_write` walks every channel.
        assert_eq!(c.ctx.write_outs.len(), streams.len(), "one ACK each");
        c.ctx.write_outs.clear();
        for stream_id in &streams {
            c.event(RTCEventInternal::SCTPStreamClosed(0, *stream_id));
        }
        assert!(c.data_channels.is_empty());
        // The closed channels' stats objects stay, for the last few only.
        assert!(
            c.stats.data_channels.len()
                <= crate::statistics::accumulator::MAX_CLOSED_DATA_CHANNEL_STATS
        );
        assert!(
            c.stats
                .data_channels
                .values()
                .all(|s| s.state == RTCDataChannelState::Closed)
        );
    }

    /// RFC 8841 section 10 with RFC 8831 section 6.2: an association closed by signalling
    /// (a rejected data section, `a=sctp-port:0`) takes its data channels with it. An open
    /// channel is closed; one that never opened failed, and says so first.
    #[test]
    fn an_association_closed_by_signalling_closes_its_channels() {
        let mut waiting = in_band_channel(2);
        waiting.stream_id = None;
        let mut c = Connected::new(
            RTCDtlsRole::Client,
            vec![negotiated_channel(4), in_band_channel(0)],
        );
        let (open, connecting) = (c.handles[0], c.handles[1]);
        // Created after the association came up, and never dialed.
        let undialed = c.data_channels.insert(waiting);
        c.events();

        c.event(RTCEventInternal::SCTPClosedBySignalling(false));
        assert_eq!(
            c.events(),
            vec![
                RTCDataChannelEvent::OnClose(open),
                RTCDataChannelEvent::OnError(connecting),
                RTCDataChannelEvent::OnClose(connecting),
                RTCDataChannelEvent::OnError(undialed),
                RTCDataChannelEvent::OnClose(undialed),
            ]
        );
        assert!(c.data_channels.is_empty());
        assert!(
            c.stats
                .data_channels
                .values()
                .all(|s| s.state == RTCDataChannelState::Closed),
            "closed channels keep a closed stats object"
        );
    }

    /// RFC 8841 section 9.3: a new `a=sctp-port` closes the association and establishes a
    /// new one. The channels that ran over the old one are closed; a channel that was not
    /// dialed yet belongs to neither, keeps its handle, and is opened on the new one.
    #[test]
    fn a_replaced_association_keeps_the_channels_not_yet_dialed() {
        let mut c = Connected::new(
            RTCDtlsRole::Client,
            vec![negotiated_channel(4), in_band_channel(0)],
        );
        let (open, connecting) = (c.handles[0], c.handles[1]);
        let mut waiting = in_band_channel(2);
        waiting.stream_id = None;
        let undialed = c.data_channels.insert(waiting);
        c.events();
        c.written();

        c.event(RTCEventInternal::SCTPClosedBySignalling(true));
        assert_eq!(
            c.events(),
            vec![
                RTCDataChannelEvent::OnClose(open),
                RTCDataChannelEvent::OnError(connecting),
                RTCDataChannelEvent::OnClose(connecting),
            ]
        );
        assert_eq!(c.data_channels.len(), 1);
        assert!(c.data_channels.get(&undialed).is_some());

        // The new association comes up: the waiting channel takes the first free stream of
        // this side's parity, which the closed channel no longer holds, and is dialed.
        c.event(RTCEventInternal::SCTPHandshakeComplete(1));
        let dc = c.data_channels.get(&undialed).expect("the waiting channel");
        assert_eq!(dc.stream_id, Some(0));
        assert!(dc.data_channel.is_some());
        let written = c.written();
        assert_eq!(dcep_types(&written)[0], (0, 0x03), "its OPEN");
        assert_eq!(written[0].association_handle, 1, "on the new association");
    }
}
