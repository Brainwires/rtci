//! Stream re-configuration (RFC 6525): the RE-CONFIG chunk, this side's requests and the
//! peer's.
//!
//! This side has one request in flight (5.1.1); the others wait in a queue. A received
//! request is identified by its Re-configuration Request Sequence Number: one seen before is
//! answered again as it was, one too old to tell is answered "Error - Bad Sequence Number".

use super::*;
use crate::param::{
    param_add_streams_request::ParamAddStreamsRequest,
    param_incoming_reset_request::ParamIncomingResetRequest,
    param_ssn_tsn_reset_request::ParamSsnTsnResetRequest,
};
use crate::queue::payload_queue::PayloadQueue;

/// RFC 6525 5.1.4: "Only one SSN/TSN Reset Request SHOULD be sent within 30 seconds".
pub(crate) const MIN_TSN_RESET_INTERVAL: Duration = Duration::from_secs(30);

/// How far around the request sequence numbers already seen a peer's request is taken as
/// new. A peer that follows RFC 6525 5.1.1 sends each number once the one before it is
/// answered; one that keeps several requests in flight has them reordered by the network at
/// most this far apart.
const PEER_RSN_WINDOW: u32 = 64;

/// The outcome of a stream re-configuration (RFC 6525 section 6.1 describes these as socket
/// events).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ReconfigEvent {
    /// The peer performed the reset of these outgoing streams this side asked for: each sends
    /// from Stream Sequence Number 0 again. No stream listed means all of them.
    OutgoingStreamsReset {
        /// The streams that were reset.
        streams: Vec<StreamId>,
    },
    /// The peer did not perform a reset of outgoing streams this side asked for; the streams
    /// go on with the sequence numbers they had.
    OutgoingStreamsResetFailed {
        /// The streams named by the request.
        streams: Vec<StreamId>,
        /// The peer denied the request, as opposed to reporting an error.
        denied: bool,
    },
    /// The peer answered a request to reset its outgoing streams
    /// ([`Association::request_incoming_stream_reset`]) without resetting them: it refused,
    /// or it had nothing to do.
    IncomingStreamsResetNotPerformed {
        /// The streams named by the request.
        streams: Vec<StreamId>,
        /// The peer denied the request.
        denied: bool,
    },
    /// The peer asked this side to reset these outgoing streams (all when none is listed),
    /// and this side is doing so.
    OutgoingResetRequestedByPeer {
        /// The streams named by the peer.
        streams: Vec<StreamId>,
    },
    /// The TSNs of both directions and the Stream Sequence Numbers of every stream started
    /// over, at this side's request or at the peer's.
    AssociationReset {
        /// The TSN of the next DATA chunk this side sends.
        local_next_tsn: u32,
        /// The TSN of the next DATA chunk the peer sends.
        remote_next_tsn: u32,
    },
    /// The peer did not perform the SSN/TSN reset this side asked for.
    AssociationResetFailed {
        /// The peer denied the request.
        denied: bool,
    },
    /// The number of streams changed: the counts the association has now.
    StreamsAdded {
        /// Streams the peer may send on.
        inbound_streams: u16,
        /// Streams this side may send on.
        outbound_streams: u16,
    },
    /// The peer did not add the streams this side asked for.
    AddStreamsFailed {
        /// The peer denied the request.
        denied: bool,
    },
}

/// A re-configuration request of this side's own (RFC 6525 5.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum OwnRequest {
    /// Outgoing SSN Reset Request (5.1.2). Each stream comes with the generation of the
    /// stream that asked, `None` for a stream this side holds no state for. No stream at all
    /// is a reset of every stream.
    OutgoingReset {
        streams: Vec<(u16, Option<u64>)>,
        /// The peer's Incoming SSN Reset Request this answers (5.1.2 A4).
        response_to: Option<u32>,
    },
    /// Incoming SSN Reset Request (5.1.3).
    IncomingReset { streams: Vec<u16> },
    /// SSN/TSN Reset Request (5.1.4).
    SsnTsnReset,
    /// Add Outgoing Streams Request (5.1.5).
    AddOutgoingStreams(u16),
    /// Add Incoming Streams Request (5.1.6).
    AddIncomingStreams(u16),
}

/// An Incoming SSN Reset Request of the peer that this side performs: the reset of each of
/// its streams waits in the send queue behind the data written before it.
#[derive(Debug, Clone)]
pub(crate) struct IncomingResetWaiting {
    /// The stream numbers as the peer listed them, copied into the answer (5.1.2 A4).
    streams: Vec<u16>,
    /// The streams whose turn in the send queue has not come yet.
    markers_left: usize,
    /// The streams this side holds, with their generations.
    generations: Vec<(u16, Option<u64>)>,
}

/// What a received RE-CONFIG chunk is answered with.
#[derive(Default)]
pub(crate) struct ReconfigAnswer {
    responses: Vec<ParamReconfigResponse>,
    /// Streams whose outgoing direction this side resets in turn (RFC 8831 6.7).
    echo: Vec<u16>,
    /// Answers given before, sent again as they were (RFC 6525 5.2.1).
    repeats: Vec<ChunkReconfig>,
}

impl ReconfigAnswer {
    fn respond(&mut self, rsn: u32, result: ReconfigResult) {
        self.responses.push(ParamReconfigResponse {
            reconfig_response_sequence_number: rsn,
            result,
            next_tsns: None,
        });
    }
}

/// How a request of the peer's stands, by its sequence number.
enum PeerRequest {
    New,
    /// Accepted and not performed yet.
    Deferred,
    /// Answered for good, with this chunk.
    Answered(ChunkReconfig),
    /// Not a number the peer can be using now.
    Bad,
}

/// Puts DATA chunks in TSN order (serial number arithmetic, RFC 9260 1.6: they lie within
/// one receive window of each other).
fn sort_by_tsn(chunks: &mut [ChunkPayloadData]) {
    let Some(base) = chunks
        .iter()
        .map(|c| c.tsn)
        .reduce(|a, b| if sna32lt(b, a) { b } else { a })
    else {
        return;
    };
    chunks.sort_by_key(|c| c.tsn.wrapping_sub(base));
}

/// RFC 6525 3.1: the ten combinations of parameters a RE-CONFIG chunk may hold.
fn allowed_combination(a: u16, b: Option<u16>) -> bool {
    match b {
        None => matches!(a, 13..=18),
        Some(b) => matches!(
            (a.min(b), a.max(b)),
            (13, 14) | (17, 18) | (13, 16) | (16, 16)
        ),
    }
}

impl Association {
    /// Whether the peer announced the stream re-configuration extension (RFC 6525 5.1.1).
    /// Without it no stream can be reset, which closing a WebRTC data channel needs.
    pub fn peer_supports_reconfig(&self) -> bool {
        self.peer_supports_reconfig
    }

    /// Asks the peer to reset some of its outgoing streams, this side's incoming ones (RFC
    /// 6525 5.1.3); no stream listed asks for all of them. The peer answers by resetting
    /// them, which arrives as a reset of each stream, or by refusing
    /// ([`ReconfigEvent::IncomingStreamsResetNotPerformed`]).
    pub fn request_incoming_stream_reset(&mut self, streams: &[StreamId]) -> Result<()> {
        self.check_reconfig_allowed()?;
        self.queue_own_request(OwnRequest::IncomingReset {
            streams: streams.to_vec(),
        })
    }

    /// Asks for the TSNs of both directions and the Stream Sequence Numbers of every stream
    /// to start over (RFC 6525 5.1.4). Nothing new is sent from now until the peer has
    /// answered ([`ReconfigEvent::AssociationReset`] or
    /// [`ReconfigEvent::AssociationResetFailed`]); what is written meanwhile is queued. The
    /// request goes out once everything sent so far is acknowledged.
    ///
    /// Refused within 30 seconds of the last such request.
    pub fn request_ssn_tsn_reset(&mut self, now: Instant) -> Result<()> {
        self.check_reconfig_allowed()?;
        if self.tsn_reset_requested {
            return Err(Error::OtherSctpErr(
                "an SSN/TSN reset is already under way".into(),
            ));
        }
        if self
            .last_tsn_reset_request
            .is_some_and(|last| now.saturating_duration_since(last) < MIN_TSN_RESET_INTERVAL)
        {
            return Err(Error::OtherSctpErr(
                "one SSN/TSN reset per 30 seconds (RFC 6525 5.1.4)".into(),
            ));
        }
        self.queue_own_request(OwnRequest::SsnTsnReset)?;
        self.tsn_reset_requested = true;
        self.last_tsn_reset_request = Some(now);
        Ok(())
    }

    /// Asks for `count` more outgoing streams (RFC 6525 5.1.5). They may be used once the
    /// peer has accepted ([`ReconfigEvent::StreamsAdded`]), and not before.
    pub fn add_outgoing_streams(&mut self, count: u16) -> Result<()> {
        self.check_reconfig_allowed()?;
        if count == 0
            || self
                .my_max_num_outbound_streams
                .checked_add(count)
                .is_none()
        {
            return Err(Error::ErrStreamCreateFailed);
        }
        self.queue_own_request(OwnRequest::AddOutgoingStreams(count))
    }

    /// Asks the peer to add `count` outgoing streams of its own, this side's incoming ones
    /// (RFC 6525 5.1.6). A peer that agrees adds them with a request of its own; asking
    /// raises this side's inbound limit ([`set_stream_limits`](Self::set_stream_limits)) to
    /// make room for them.
    pub fn add_incoming_streams(&mut self, count: u16) -> Result<()> {
        self.check_reconfig_allowed()?;
        let Some(total) = self
            .my_max_num_inbound_streams
            .checked_add(count)
            .filter(|_| count != 0)
        else {
            return Err(Error::ErrStreamCreateFailed);
        };
        self.queue_own_request(OwnRequest::AddIncomingStreams(count))?;
        self.configured_inbound_streams = self.configured_inbound_streams.max(total);
        Ok(())
    }

    /// Sets how many streams this association may grow to when the peer asks for more (RFC
    /// 6525 5.2.5, 5.2.6: "a limit that should be configurable by the application"): a
    /// request that would take the inbound or the outbound count past its limit is denied.
    /// The limits start as the counts the association was configured with
    /// ([`TransportConfig::with_max_num_inbound_streams`],
    /// [`TransportConfig::with_max_num_outbound_streams`]). Streams the association already
    /// has are not taken away.
    pub fn set_stream_limits(&mut self, max_inbound: u16, max_outbound: u16) {
        self.configured_inbound_streams = max_inbound;
        self.configured_outbound_streams = max_outbound;
    }

    /// RFC 6525 5.1.1: no re-configuration request is sent to a peer that did not announce
    /// the extension, and the application is told so.
    fn check_reconfig_allowed(&self) -> Result<()> {
        if self.state() != AssociationState::Established {
            return Err(Error::ErrResetPacketInStateNotExist);
        }
        if !self.peer_supports_reconfig {
            return Err(Error::OtherSctpErr(
                "the peer does not support stream re-configuration (RFC 6525 5.1.1)".into(),
            ));
        }
        Ok(())
    }

    /// Whether new DATA is held back for an SSN/TSN reset (RFC 6525 5.1.4 C2), this side's
    /// own or the peer's.
    pub(crate) fn sending_suspended(&self) -> bool {
        self.tsn_reset_requested || self.deferred_tsn_reset.is_some()
    }

    /// Queues the reset of an outgoing stream (RFC 6525 5.1.2). It waits in the send queue
    /// behind the data written before it, so the request's "Sender's Last Assigned TSN"
    /// covers that data; its retransmission timer starts when the request is sent.
    pub(crate) fn send_reset_request(
        &mut self,
        _now: Instant,
        stream_identifier: StreamId,
    ) -> Result<()> {
        self.check_reconfig_allowed()?;
        let mut generation = 0;
        if let Some(s) = self.streams.get_mut(&stream_identifier) {
            // 5.1.2 A1: from now on new data of this stream gets no sequence number.
            s.outgoing_reset_pending = true;
            generation = s.generation;
        }
        self.pending_queue.push_reset(ResetMarker {
            stream_identifier,
            generation,
            response_to: None,
        });
        self.awake_write_loop();

        Ok(())
    }

    /// Puts a request in the queue behind the one in flight. A reset of outgoing streams
    /// joins the one waiting at the end of the queue.
    fn queue_own_request(&mut self, request: OwnRequest) -> Result<()> {
        self.queue_own_request_bounded(request, true)
    }

    fn queue_own_request_bounded(&mut self, request: OwnRequest, bounded: bool) -> Result<()> {
        if let OwnRequest::OutgoingReset {
            streams,
            response_to: None,
        } = &request
            && let Some(OwnRequest::OutgoingReset {
                streams: waiting,
                response_to: None,
            }) = self.reconfig_queue.back_mut()
            && !waiting.is_empty()
            && !streams.is_empty()
        {
            for stream in streams {
                if !waiting.contains(stream) {
                    waiting.push(*stream);
                }
            }
            return Ok(());
        }
        if bounded && self.reconfig_queue.len() >= MAX_OUTSTANDING_RECONFIGS {
            return Err(Error::OtherSctpErr(
                "too many re-configuration requests are waiting".into(),
            ));
        }
        self.reconfig_queue.push_back(request);
        self.awake_write_loop();
        Ok(())
    }

    /// A stream reset reached the head of the send queue: the data written before it has
    /// been sent, and the reset can be asked for.
    pub(crate) fn on_reset_marker_ready(&mut self, marker: ResetMarker) {
        let Some(rsn) = marker.response_to else {
            // Asked for by `Stream::stop`, which has changed the stream already: not refused
            // for a full queue.
            let _ = self.queue_own_request_bounded(
                OwnRequest::OutgoingReset {
                    streams: vec![(marker.stream_identifier, Some(marker.generation))],
                    response_to: None,
                },
                false,
            );
            return;
        };
        // One stream of an Incoming SSN Reset Request the peer sent.
        let done = self
            .incoming_resets_waiting
            .get_mut(&rsn)
            .is_some_and(|waiting| {
                waiting.markers_left = waiting.markers_left.saturating_sub(1);
                waiting.markers_left == 0
            });
        // The request stays on record, as one being worked on, until its answer leaves.
        if done && let Some(waiting) = self.incoming_resets_waiting.get(&rsn).cloned() {
            self.answer_incoming_reset(rsn, waiting);
        }
    }

    /// RFC 6525 5.2.3 F1: the Outgoing SSN Reset Request that answers the peer's Incoming
    /// SSN Reset Request `rsn`. It is the answer, so it is not refused for a full queue.
    fn answer_incoming_reset(&mut self, rsn: u32, waiting: IncomingResetWaiting) {
        // 5.1.2 A4: the stream numbers are copied from the peer's request. `generations`
        // says which of them this side holds.
        let streams = waiting
            .streams
            .iter()
            .map(|id| {
                let generation = waiting
                    .generations
                    .iter()
                    .find(|(held, _)| held == id)
                    .and_then(|(_, generation)| *generation);
                (*id, generation)
            })
            .collect();
        self.reconfig_queue.push_back(OwnRequest::OutgoingReset {
            streams,
            response_to: Some(rsn),
        });
    }

    /// The most stream numbers one Outgoing or Incoming SSN Reset Request holds: what fits a
    /// packet.
    fn max_streams_per_request(&self) -> usize {
        if self.mtu == 0 {
            return usize::MAX;
        }
        // Common header, chunk header, the largest request parameter header.
        ((self.mtu as usize).saturating_sub(COMMON_HEADER_SIZE as usize + CHUNK_HEADER_SIZE + 16)
            / 2)
        .max(1)
    }

    /// The next request, if none is in flight and one waits (RFC 6525 5.1.1).
    pub(crate) fn next_reconfig_request(&mut self, now: Instant) -> Option<Packet> {
        if !self.reconfigs.is_empty() {
            return None;
        }
        if matches!(self.reconfig_queue.front()?, OwnRequest::SsnTsnReset)
            && !(self.inflight_queue.is_empty() && !self.pending_queue.is_mid_message())
        {
            // 5.1.4 C2: the sender has no outstanding TSNs.
            return None;
        }
        let mut request = self.reconfig_queue.pop_front()?;
        let limit = self.max_streams_per_request();
        match &mut request {
            OwnRequest::OutgoingReset {
                streams,
                response_to: None,
            } if streams.len() > limit => {
                let rest = streams.split_off(limit);
                self.reconfig_queue.push_front(OwnRequest::OutgoingReset {
                    streams: rest,
                    response_to: None,
                });
            }
            OwnRequest::IncomingReset { streams } if streams.len() > limit => {
                let rest = streams.split_off(limit);
                self.reconfig_queue
                    .push_front(OwnRequest::IncomingReset { streams: rest });
            }
            _ => {}
        }
        if request == OwnRequest::SsnTsnReset {
            self.last_tsn_reset_request = Some(now);
        }
        let (rsn, param) = self.own_request_param(&request);
        debug!(
            "[{}] sending RECONFIG: rsn={} {:?}",
            self.side, rsn, request
        );
        let chunk = ChunkReconfig {
            param_a: Some(param),
            param_b: None,
        };
        if let OwnRequest::OutgoingReset {
            response_to: Some(answered),
            ..
        } = &request
        {
            // This request is the answer to the peer's Incoming SSN Reset Request: a
            // retransmission of that one gets it again (5.2.1).
            self.incoming_resets_waiting.remove(answered);
            self.remember_answer(*answered, chunk.clone());
        }
        self.reconfigs.insert(rsn, chunk.clone());
        self.reconfig_in_flight = Some(request);
        self.reconfig_in_progress = false;
        // 5.1.1: the timer starts when the request is sent.
        self.timers.stop(Timer::Reconfig);
        self.timers
            .start(Timer::Reconfig, now, self.rto_mgr.get_rto());
        Some(self.create_packet(vec![Box::new(chunk)]))
    }

    /// Builds the parameter of `request`, with the next request sequence number (RFC 6525
    /// 5.1.2 A2, 5.1.3 B1, 5.1.4 C1).
    fn own_request_param(&mut self, request: &OwnRequest) -> (u32, Box<dyn Param>) {
        let rsn = self.generate_next_rsn();
        let param: Box<dyn Param> = match request {
            OwnRequest::OutgoingReset {
                streams,
                response_to,
            } => Box::new(ParamOutgoingResetRequest {
                reconfig_request_sequence_number: rsn,
                // 5.1.2 A4: the peer's request this answers, or else the peer's next
                // expected request sequence number minus 1.
                reconfig_response_sequence_number: response_to.unwrap_or_else(|| {
                    self.peer_rsn_window
                        .map_or(0, |(_, next)| next.wrapping_sub(1))
                }),
                // 5.1.2 A3.
                sender_last_tsn: self.my_next_tsn.wrapping_sub(1),
                stream_identifiers: streams.iter().map(|(id, _)| *id).collect(),
            }),
            OwnRequest::IncomingReset { streams } => Box::new(ParamIncomingResetRequest {
                reconfig_request_sequence_number: rsn,
                stream_identifiers: streams.clone(),
            }),
            OwnRequest::SsnTsnReset => Box::new(ParamSsnTsnResetRequest {
                reconfig_request_sequence_number: rsn,
            }),
            OwnRequest::AddOutgoingStreams(count) => Box::new(ParamAddStreamsRequest {
                incoming: false,
                reconfig_request_sequence_number: rsn,
                number_of_new_streams: *count,
            }),
            OwnRequest::AddIncomingStreams(count) => Box::new(ParamAddStreamsRequest {
                incoming: true,
                reconfig_request_sequence_number: rsn,
                number_of_new_streams: *count,
            }),
        };
        (rsn, param)
    }

    /// RFC 6525 5.2.1: a RE-CONFIG chunk. Each parameter is processed, and what is returned
    /// goes back in one chunk.
    pub(crate) fn handle_reconfig(&mut self, c: &ChunkReconfig) -> Result<Vec<Packet>> {
        trace!("[{}] handle_reconfig", self.side);

        let params: Vec<&Box<dyn Param>> = [&c.param_a, &c.param_b].into_iter().flatten().collect();
        let types: Vec<u16> = params.iter().map(|p| u16::from(p.header().typ)).collect();
        let known = |t: &u16| matches!(*t, 13..=18);
        if types.iter().all(known)
            && let Some(first) = types.first()
            && !allowed_combination(*first, types.get(1).copied())
        {
            // 3.1: a combination that is not allowed is answered with an ERROR chunk,
            // "Protocol Violation", and none of it is performed.
            warn!(
                "[{}] RE-CONFIG with parameters {:?}: not an allowed combination",
                self.side, types
            );
            self.report_error(Self::protocol_violation(
                "RE-CONFIG: parameter combination not allowed (RFC 6525 3.1)",
            ));
            return Ok(vec![]);
        }

        let mut answer = ReconfigAnswer::default();
        let mut held_request = false;
        for param in params {
            // RFC 6525 4, RFC 9260 3.2.1: a parameter that is not recognized ends the
            // processing of this chunk (its type's upper bits are 00), and of nothing else.
            if !self.handle_reconfig_param(param, &mut answer)? {
                break;
            }
            held_request |= u16::from(param.header().typ) != 16;
        }
        if held_request
            && matches!(
                self.state(),
                AssociationState::Established
                    | AssociationState::ShutdownPending
                    | AssociationState::ShutdownReceived
            )
        {
            // 5.2.1: a chunk with a request is acknowledged with a SACK as well, which
            // hurries along whatever the request waits for.
            self.immediate_ack_triggered = true;
        }
        Ok(self.reconfig_answer_packets(answer))
    }

    /// Handles one parameter of a RE-CONFIG chunk. `Ok(false)`: the parameter is not one
    /// this side knows, and the rest of the chunk is not processed.
    #[allow(clippy::borrowed_box)]
    fn handle_reconfig_param(
        &mut self,
        raw: &Box<dyn Param>,
        answer: &mut ReconfigAnswer,
    ) -> Result<bool> {
        let any = raw.as_any();
        if let Some(p) = any.downcast_ref::<ParamReconfigResponse>() {
            self.handle_reconfig_response(p);
            return Ok(true);
        }
        let rsn = if let Some(p) = any.downcast_ref::<ParamOutgoingResetRequest>() {
            // 5.2.2 E1: the request can be the answer to an Incoming SSN Reset Request of
            // this side's.
            self.acknowledge_incoming_reset_request(p.reconfig_response_sequence_number);
            p.reconfig_request_sequence_number
        } else if let Some(p) = any.downcast_ref::<ParamIncomingResetRequest>() {
            p.reconfig_request_sequence_number
        } else if let Some(p) = any.downcast_ref::<ParamSsnTsnResetRequest>() {
            p.reconfig_request_sequence_number
        } else if let Some(p) = any.downcast_ref::<ParamAddStreamsRequest>() {
            p.reconfig_request_sequence_number
        } else {
            debug!("[{}] ignoring RE-CONFIG parameter {}", self.side, raw);
            return Ok(false);
        };

        // 5.2.1: the request sequence number says whether this is a request seen before.
        match self.classify_peer_request(rsn) {
            PeerRequest::Deferred => {
                if self.deferred_tsn_reset == Some(rsn) {
                    // The retransmission of an SSN/TSN Reset Request that waited for this
                    // side's outstanding DATA: perhaps it can be performed now.
                    let performed = self.perform_deferred_tsn_reset();
                    if performed.is_empty() {
                        answer.respond(rsn, ReconfigResult::InProgress);
                    } else if let Some((_, chunk)) = self
                        .completed_reconfig_requests
                        .iter()
                        .find(|(done, _)| *done == rsn)
                    {
                        answer.repeats.push(chunk.clone());
                    }
                } else {
                    answer.respond(rsn, ReconfigResult::InProgress);
                }
                return Ok(true);
            }
            PeerRequest::Answered(chunk) => {
                answer.repeats.push(chunk);
                return Ok(true);
            }
            PeerRequest::Bad => {
                debug!(
                    "[{}] RE-CONFIG request {} is not a sequence number the peer can be using",
                    self.side, rsn
                );
                answer.respond(rsn, ReconfigResult::ErrorBadSequenceNumber);
                return Ok(true);
            }
            PeerRequest::New => self.note_peer_request(rsn),
        }

        if let Some(p) = any.downcast_ref::<ParamOutgoingResetRequest>() {
            if self.reconfig_requests.len() >= MAX_PENDING_RECONFIG_REQUESTS {
                debug!(
                    "[{}] deny reset request rsn={}: {} requests already pending",
                    self.side,
                    rsn,
                    self.reconfig_requests.len()
                );
                answer.respond(rsn, ReconfigResult::Denied);
                return Ok(true);
            }
            self.reconfig_requests.insert(rsn, p.clone());
            let (result, mut echo) = self.perform_peer_outgoing_reset(p);
            answer.respond(rsn, result);
            answer.echo.append(&mut echo);
        } else if let Some(p) = any.downcast_ref::<ParamIncomingResetRequest>() {
            self.handle_incoming_reset_request(p, answer);
        } else if any.downcast_ref::<ParamSsnTsnResetRequest>().is_some() {
            self.handle_tsn_reset_request(rsn, answer);
        } else if let Some(p) = any.downcast_ref::<ParamAddStreamsRequest>() {
            self.handle_add_streams_request(p, answer);
        }
        Ok(true)
    }

    fn classify_peer_request(&self, rsn: u32) -> PeerRequest {
        if self.reconfig_requests.contains_key(&rsn)
            || self.incoming_resets_waiting.contains_key(&rsn)
            || self.deferred_tsn_reset == Some(rsn)
        {
            return PeerRequest::Deferred;
        }
        if let Some((_, chunk)) = self
            .completed_reconfig_requests
            .iter()
            .find(|(done, _)| *done == rsn)
        {
            return PeerRequest::Answered(chunk.clone());
        }
        match self.peer_rsn_window {
            // No handshake told the peer's first number: the first request tells it.
            None => PeerRequest::New,
            Some((lowest, next)) => {
                if sna32gte(rsn, lowest) && sna32lt(rsn, next.wrapping_add(PEER_RSN_WINDOW)) {
                    PeerRequest::New
                } else {
                    PeerRequest::Bad
                }
            }
        }
    }

    /// Takes `rsn` as a request sequence number the peer has used.
    fn note_peer_request(&mut self, rsn: u32) {
        let (mut lowest, mut next) = self.peer_rsn_window.unwrap_or((rsn, rsn));
        if sna32gte(rsn, next) {
            next = rsn.wrapping_add(1);
        }
        if next.wrapping_sub(lowest) > PEER_RSN_WINDOW {
            lowest = next.wrapping_sub(PEER_RSN_WINDOW);
        }
        self.peer_rsn_window = Some((lowest, next));
    }

    /// Remembers the chunk a request was answered with for good.
    fn remember_answer(&mut self, rsn: u32, chunk: ChunkReconfig) {
        self.completed_reconfig_requests
            .retain(|(done, _)| *done != rsn);
        if self.completed_reconfig_requests.len() >= MAX_COMPLETED_RECONFIG_REQUESTS {
            self.completed_reconfig_requests.pop_front();
        }
        self.completed_reconfig_requests.push_back((rsn, chunk));
    }

    /// Turns what a RE-CONFIG chunk is answered with into packets: the responses in one
    /// chunk (RFC 6525 5.2.1), with this side's own reset of the same streams when it can go
    /// along (3.1, combination 9).
    pub(crate) fn reconfig_answer_packets(&mut self, answer: ReconfigAnswer) -> Vec<Packet> {
        let mut packets: Vec<Packet> = answer
            .repeats
            .into_iter()
            .map(|chunk| self.create_packet(vec![Box::new(chunk)]))
            .collect();

        let mut bundled: Option<(u32, OwnRequest, Box<dyn Param>)> = None;
        if !answer.echo.is_empty() {
            let own = OwnRequest::OutgoingReset {
                streams: answer.echo.iter().map(|id| (*id, None)).collect(),
                response_to: None,
            };
            if answer.responses.len() == 1
                && self.reconfigs.is_empty()
                && self.reconfig_queue.is_empty()
                && self.peer_supports_reconfig
                && answer.echo.len() <= self.max_streams_per_request()
            {
                let (rsn, param) = self.own_request_param(&own);
                bundled = Some((rsn, own, param));
            } else if self.queue_own_request(own).is_err() {
                debug!(
                    "[{}] resetStream(): not echoing reset of {:?}, {} requests waiting",
                    self.side,
                    answer.echo,
                    self.reconfig_queue.len()
                );
            }
        }

        if answer.responses.is_empty() {
            return packets;
        }
        let finals: Vec<u32> = answer
            .responses
            .iter()
            .filter(|r| r.result != ReconfigResult::InProgress)
            .map(|r| r.reconfig_response_sequence_number)
            .collect();
        let mut params: Vec<Box<dyn Param>> = answer
            .responses
            .into_iter()
            .map(|r| Box::new(r) as Box<dyn Param>)
            .collect();
        let mut in_flight = None;
        if let Some((rsn, own, param)) = bundled {
            params.push(param);
            in_flight = Some((rsn, own));
        }
        let mut params = params.into_iter();
        let chunk = ChunkReconfig {
            param_a: params.next(),
            param_b: params.next(),
        };
        debug!("[{}] RESET RESPONSE: {}", self.side, chunk);
        for rsn in finals {
            self.remember_answer(rsn, chunk.clone());
        }
        if let Some((rsn, own)) = in_flight {
            // The request is retransmitted with the response it left with.
            self.reconfigs.insert(rsn, chunk.clone());
            self.reconfig_in_flight = Some(own);
            self.reconfig_in_progress = false;
        }
        packets.push(self.create_packet(vec![Box::new(chunk)]));
        packets
    }

    /// Streams named by `p` that still hold a complete message the application
    /// has not collected, so a reset naming them cannot be performed yet.
    ///
    /// Only *readable* data counts: an incomplete fragment set can never be
    /// completed once the peer has reset, so it is discardable and must not
    /// hold the reset open forever.
    ///
    /// Nor does data on a stream the application has stopped reading (`Stream::stop`, or
    /// `Stream::close`: the close of a data channel): reads of it fail, so nothing would ever
    /// drain it, and the reset that completes the close (RFC 8831 6.7) would wait for good,
    /// with the stream id never freed and the bytes never given back to the window. That data
    /// is abandoned with the stream ("[RFC6525] also guarantees that all the messages are
    /// delivered (or abandoned) before the stream is reset"): its channel is closed.
    fn streams_awaiting_drain(&self, p: &ParamOutgoingResetRequest) -> Vec<StreamId> {
        p.stream_identifiers
            .iter()
            .copied()
            .filter(|id| {
                self.streams.get(id).is_some_and(|s| {
                    let still_read = matches!(
                        s.state,
                        RecvSendState::Readable | RecvSendState::ReadWritable
                    );
                    still_read && s.reassembly_queue.is_readable()
                })
            })
            .collect()
    }

    /// RFC 6525 5.2.2: performs the peer's Outgoing SSN Reset Request `p` as far as it can
    /// be performed now. Returns the result to answer with and the streams whose outgoing
    /// direction this side resets in turn.
    fn perform_peer_outgoing_reset(
        &mut self,
        p: &ParamOutgoingResetRequest,
    ) -> (ReconfigResult, Vec<u16>) {
        // RFC 6525 5.2.2: a request without stream numbers is for every stream.
        let every_stream = p.stream_identifiers.is_empty();
        let all_streams;
        let p = if every_stream {
            let mut stream_identifiers: Vec<u16> = self.streams.keys().copied().collect();
            stream_identifiers.sort_unstable();
            all_streams = ParamOutgoingResetRequest {
                stream_identifiers,
                ..p.clone()
            };
            &all_streams
        } else {
            p
        };
        let mut result = ReconfigResult::SuccessPerformed;
        let mut sis_to_reset = vec![];

        if sna32lte(p.sender_last_tsn, self.peer_last_tsn) {
            debug!(
                "[{}] resetStream(): senderLastTSN={} <= peer_last_tsn={}",
                self.side, p.sender_last_tsn, self.peer_last_tsn
            );

            let draining = self.streams_awaiting_drain(p);
            let mut seen = FxHashSet::default();

            for id in &p.stream_identifiers {
                if draining.contains(id) || !seen.insert(*id) {
                    continue;
                }
                if let Some(stream) = self.streams.get(id) {
                    // RFC 8831 section 6.7: the receiver of a reset resets its own outgoing
                    // stream too, unless it already has (the peer's request is then the
                    // second half of a close this side started). Echoing it again would
                    // send a reset after the stream id is free, and reset the next channel
                    // that takes the id.
                    let outgoing_open = !stream.outgoing_reset_started;
                    if outgoing_open {
                        if self.pending_queue.holds_stream(*id) {
                            // What the application wrote to the stream before now is still
                            // to be sent, all or part of it without a TSN. RFC 6525 5.1.2 A3
                            // makes the request's Sender's Last Assigned TSN "the next TSN
                            // the sender assigns minus 1", and RFC 8831 6.7 relies on it:
                            // "[RFC6525] also guarantees that all the messages are delivered
                            // (or abandoned) before the stream is reset". Sent at once, the
                            // reset would leave that data after the Sender's Last Assigned
                            // TSN, where the peer takes it for data of the stream after the
                            // reset (5.2.2 E2, E4): the rest of a message half sent there
                            // waits in front of the next channel on the stream for good. So
                            // the reset waits behind it in the send queue, as a reset this
                            // side asks for itself does (`send_reset_request`).
                            let generation = stream.generation;
                            self.pending_queue.push_reset(ResetMarker {
                                stream_identifier: *id,
                                generation,
                                response_to: None,
                            });
                            self.awake_write_loop();
                        } else {
                            sis_to_reset.push(*id);
                        }
                    }
                    self.unregister_stream(*id, AssociationError::Reset);
                } else if self.my_max_num_inbound_streams == 0
                    || *id < self.my_max_num_inbound_streams
                {
                    // A stream this side never sent or received on (a pre-negotiated data
                    // channel left idle) has no state here, but the application still
                    // holds it: report the reset, and reset the outgoing direction too.
                    // An id past the negotiated stream count names no such channel.
                    sis_to_reset.push(*id);
                    self.events.push_back(Event::AssociationLost {
                        reason: AssociationError::Reset,
                        id: *id,
                    });
                }
            }

            if draining.is_empty() {
                self.reconfig_requests
                    .remove(&p.reconfig_request_sequence_number);
            } else {
                debug!(
                    "[{}] resetStream(): deferring reset of {:?}, application has not drained",
                    self.side, draining
                );
                result = ReconfigResult::InProgress;
                // Keep only the streams still waiting, so a retry performs each reset once.
                self.reconfig_requests.insert(
                    p.reconfig_request_sequence_number,
                    ParamOutgoingResetRequest {
                        stream_identifiers: draining,
                        ..p.clone()
                    },
                );
            }
            // 5.2.2 E4: the DATA that was held for the streams now reset is processed.
            self.release_held_reset_data();
        } else {
            debug!(
                "[{}] resetStream(): senderLastTSN={} > peer_last_tsn={}",
                self.side, p.sender_last_tsn, self.peer_last_tsn
            );
            result = ReconfigResult::InProgress;
        }

        (result, sis_to_reset)
    }

    /// Whether DATA chunk `d` waits for a reset that is not performed yet: the peer sent it
    /// after the request (RFC 6525 5.2.2 E2), so it belongs to the stream as it is after the
    /// reset. Also everything received while this side's own SSN/TSN reset is in flight,
    /// which is sorted out when the answer says where the peer's new TSNs start.
    pub(crate) fn holds_for_reset(&self, d: &ChunkPayloadData) -> bool {
        if matches!(self.reconfig_in_flight, Some(OwnRequest::SsnTsnReset)) {
            return true;
        }
        self.reconfig_requests.values().any(|p| {
            sna32gt(d.tsn, p.sender_last_tsn)
                && (p.stream_identifiers.is_empty()
                    || p.stream_identifiers.contains(&d.stream_identifier))
        })
    }

    /// Delivers the held DATA that no deferred reset holds any more.
    fn release_held_reset_data(&mut self) {
        if self.held_reset_data.is_empty() {
            return;
        }
        let mut held = std::mem::take(&mut self.held_reset_data);
        // In TSN order, as they would have been processed had they not waited: a fragment
        // goes to its stream after the one before it in its message.
        sort_by_tsn(&mut held);
        for d in held {
            if self.holds_for_reset(&d) {
                self.held_reset_data.push(d);
            } else {
                self.reassembly_bytes = self.reassembly_bytes.saturating_sub(d.user_data.len());
                self.deliver_to_stream(&d);
            }
        }
    }

    /// Performs the stored reset requests whose sender's last TSN the cumulative TSN reached
    /// since it stood at `prev_peer_last_tsn`.
    pub(crate) fn reset_streams_reached_since(
        &mut self,
        prev_peer_last_tsn: u32,
        reply: &mut Vec<Packet>,
    ) -> Result<()> {
        if self.peer_last_tsn == prev_peer_last_tsn || self.reconfig_requests.is_empty() {
            return Ok(());
        }
        let peer_last_tsn = self.peer_last_tsn;
        let mut reached: Vec<ParamOutgoingResetRequest> = self
            .reconfig_requests
            .values()
            .filter(|p| {
                sna32gt(p.sender_last_tsn, prev_peer_last_tsn)
                    && sna32lte(p.sender_last_tsn, peer_last_tsn)
            })
            .cloned()
            .collect();
        reached.sort_by_key(|p| p.reconfig_request_sequence_number);
        for request in reached {
            // Performed late, the reset is answered as one performed at once is: with this
            // side's own reset of the streams (RFC 8831 6.7). Each stream is performed (and
            // unregistered) once, so none is answered twice; a stream still to drain is
            // answered by `retry_deferred_resets`.
            let mut answer = ReconfigAnswer::default();
            let (result, mut echo) = self.perform_peer_outgoing_reset(&request);
            answer.respond(request.reconfig_request_sequence_number, result);
            answer.echo.append(&mut echo);
            reply.append(&mut self.reconfig_answer_packets(answer));
        }
        Ok(())
    }

    /// Re-run any reset request that was answered In Progress because
    /// `stream_identifier` still had data the application had not collected
    /// Called when that stream drains.
    ///
    /// The reply is queued like any other control packet; a request naming
    /// several streams is retried as a whole and simply defers again if another
    /// of its streams is still readable.
    pub(crate) fn retry_deferred_resets(&mut self, stream_identifier: StreamId) {
        let mut pending: Vec<ParamOutgoingResetRequest> = self
            .reconfig_requests
            .values()
            .filter(|p| p.stream_identifiers.contains(&stream_identifier))
            .cloned()
            .collect();
        if pending.is_empty() {
            return;
        }
        pending.sort_by_key(|p| p.reconfig_request_sequence_number);

        for p in pending {
            let mut answer = ReconfigAnswer::default();
            let (result, mut echo) = self.perform_peer_outgoing_reset(&p);
            answer.respond(p.reconfig_request_sequence_number, result);
            answer.echo.append(&mut echo);
            for packet in self.reconfig_answer_packets(answer) {
                self.control_queue.push_back(packet);
            }
        }
        self.awake_write_loop();
    }

    /// RFC 6525 5.2.3: the peer asks this side to reset outgoing streams.
    fn handle_incoming_reset_request(
        &mut self,
        p: &ParamIncomingResetRequest,
        answer: &mut ReconfigAnswer,
    ) {
        let rsn = p.reconfig_request_sequence_number;
        let wanted = &p.stream_identifiers;

        // "If the Outgoing SSN Reset Request Parameter that was just sent completely
        // overlaps the received Incoming SSN Reset Request Parameter, respond ... Nothing to
        // do".
        if let Some(OwnRequest::OutgoingReset { streams, .. }) = &self.reconfig_in_flight {
            let covered = streams.is_empty()
                || (!wanted.is_empty()
                    && wanted
                        .iter()
                        .all(|id| streams.iter().any(|(sent, _)| sent == id)));
            if covered {
                answer.respond(rsn, ReconfigResult::SuccessNop);
                return;
            }
        }

        // The streams of the request this side holds and sends on.
        let mut held: Vec<u16> = if wanted.is_empty() {
            self.streams.keys().copied().collect()
        } else {
            let mut seen = FxHashSet::default();
            wanted
                .iter()
                .copied()
                .filter(|id| seen.insert(*id) && self.streams.contains_key(id))
                .collect()
        };
        held.sort_unstable();

        // "the Incoming request will arrive after the Outgoing SSN Reset Request just
        // completed. In such a case, all of the streams being requested will be already set
        // to 0": nothing to do. A stream this side holds no state for has sent nothing.
        let untouched = held.iter().all(|id| {
            self.streams
                .get(id)
                .is_some_and(|s| s.sequence_number == 0 && !s.outgoing_reset_pending)
        });
        if untouched {
            answer.respond(rsn, ReconfigResult::SuccessNop);
            return;
        }
        if self.incoming_resets_waiting.len() >= MAX_PENDING_RECONFIG_REQUESTS
            || self.reconfig_queue.len() >= MAX_OUTSTANDING_RECONFIGS
        {
            answer.respond(rsn, ReconfigResult::Denied);
            return;
        }

        // F1: the answer is an Outgoing SSN Reset Request for the same streams. Each stream
        // is reset when the data written before now has been sent (5.1.2 A3), and takes no
        // new sequence numbers until the peer has answered (A1).
        let mut waiting = IncomingResetWaiting {
            streams: wanted.clone(),
            markers_left: 0,
            generations: vec![],
        };
        for id in held {
            let Some(s) = self.streams.get_mut(&id) else {
                continue;
            };
            waiting.generations.push((id, Some(s.generation)));
            s.outgoing_reset_pending = true;
            // As after `Stream::stop`: this side has reset its direction of the stream, so
            // the peer's own reset of it (RFC 8831 6.7) is not answered with another. The
            // peer's direction is not touched (5.2.3): it stays readable, and what it holds is
            // delivered before the peer's reset is performed (5.2.2).
            s.outgoing_reset_started = true;
            let generation = s.generation;
            waiting.markers_left += 1;
            self.pending_queue.push_reset(ResetMarker {
                stream_identifier: id,
                generation,
                response_to: Some(rsn),
            });
        }
        self.events.push_back(Event::Reconfig(
            ReconfigEvent::OutgoingResetRequestedByPeer {
                streams: wanted.clone(),
            },
        ));
        let ready = waiting.markers_left == 0;
        self.incoming_resets_waiting.insert(rsn, waiting.clone());
        if ready {
            self.answer_incoming_reset(rsn, waiting);
        }
        self.awake_write_loop();
    }

    /// RFC 6525 5.2.2 E1: an Outgoing SSN Reset Request whose Response Sequence Number is
    /// that of this side's Incoming SSN Reset Request in flight is the answer to it.
    fn acknowledge_incoming_reset_request(&mut self, rsn: u32) {
        if matches!(
            self.reconfig_in_flight,
            Some(OwnRequest::IncomingReset { .. })
        ) && self.reconfigs.remove(&rsn).is_some()
        {
            self.reconfig_in_flight = None;
            self.reconfig_in_progress = false;
            self.timers.stop(Timer::Reconfig);
        }
    }

    /// RFC 6525 5.2.4: the peer asks for an SSN/TSN reset.
    fn handle_tsn_reset_request(&mut self, rsn: u32, answer: &mut ReconfigAnswer) {
        // Both sides asked at once: each would stop sending and wait for the other.
        if self.tsn_reset_requested {
            answer.respond(rsn, ReconfigResult::ErrorRequestAlreadyInProgress);
            return;
        }
        if let Some(earlier) = self.deferred_tsn_reset
            && earlier != rsn
        {
            answer.respond(rsn, ReconfigResult::ErrorRequestAlreadyInProgress);
            return;
        }
        self.deferred_tsn_reset = Some(rsn);
        let performed = self.perform_deferred_tsn_reset();
        if performed.is_empty() {
            // G3 takes everything this side sent as acknowledged. Rather than give up DATA
            // the peer may not have, the reset waits until it is acknowledged; no new DATA
            // is sent meanwhile.
            answer.respond(rsn, ReconfigResult::InProgress);
        } else if let Some((_, chunk)) = self
            .completed_reconfig_requests
            .iter()
            .find(|(done, _)| *done == rsn)
        {
            answer.repeats.push(chunk.clone());
        }
    }

    /// Performs the peer's SSN/TSN reset that waited for this side's outstanding DATA, if
    /// there is one and nothing is outstanding now. Returns the packet with the response.
    pub(crate) fn perform_deferred_tsn_reset(&mut self) -> Vec<Packet> {
        let Some(rsn) = self.deferred_tsn_reset else {
            return vec![];
        };
        if !self.inflight_queue.is_empty() || self.pending_queue.is_mid_message() {
            return vec![];
        }
        self.deferred_tsn_reset = None;

        // G1: the TSN the peer sends next: the smallest TSN this side has not acknowledged,
        // plus 2^31, so that anything of the old numbering still on its way is behind it.
        let receiver_next_tsn = self.peer_last_tsn.wrapping_add(1).wrapping_add(1 << 31);
        // G2: this side goes on from the highest TSN it sent, plus 1.
        let sender_next_tsn = self.my_next_tsn;
        // G3: a SACK for everything sent. Nothing is outstanding.
        // G4: a FORWARD TSN, all streams, up to the Receiver's Next TSN minus 1.
        let prev_peer_last_tsn = self.peer_last_tsn;
        self.payload_queue = PayloadQueue::new();
        self.peer_last_tsn = receiver_next_tsn.wrapping_sub(1);
        let mut packets = vec![];
        let _ = self.reset_streams_reached_since(prev_peer_last_tsn, &mut packets);
        // G5.
        self.reset_all_sequence_numbers();
        self.release_held_reset_data();

        let chunk = ChunkReconfig {
            param_a: Some(Box::new(ParamReconfigResponse {
                reconfig_response_sequence_number: rsn,
                result: ReconfigResult::SuccessPerformed,
                next_tsns: Some((sender_next_tsn, receiver_next_tsn)),
            })),
            param_b: None,
        };
        self.remember_answer(rsn, chunk.clone());
        self.events
            .push_back(Event::Reconfig(ReconfigEvent::AssociationReset {
                local_next_tsn: sender_next_tsn,
                remote_next_tsn: receiver_next_tsn,
            }));
        packets.push(self.create_packet(vec![Box::new(chunk)]));
        self.awake_write_loop();
        packets
    }

    /// RFC 6525 5.2.4 G5, 5.2.7 H5: the next expected and the outgoing Stream Sequence
    /// Numbers of every stream are 0. The ordered messages still queued are numbered again.
    fn reset_all_sequence_numbers(&mut self) {
        let ids: Vec<StreamId> = self.streams.keys().copied().collect();
        for id in &ids {
            if let Some(s) = self.streams.get_mut(id) {
                let bytes_before = s.get_num_bytes_in_reassembly_queue();
                s.reassembly_queue.reset_sequence_numbers();
                s.reset_outgoing_numbers();
                if s.reassembly_queue.is_readable() {
                    self.events
                        .push_back(Event::Stream(StreamEvent::Readable { id: *id }));
                }
                self.reindex_stream(*id, bytes_before);
            }
        }
        // The messages still queued take the first numbers of their streams, and the streams
        // go on from there.
        let mut next: FxHashMap<u16, (u16, u32, u32)> = FxHashMap::default();
        self.pending_queue.renumber(|stream, unordered| {
            let (ssn, ordered_mid, unordered_mid) = next.entry(stream).or_insert((0, 0, 0));
            if unordered {
                let mid = *unordered_mid;
                *unordered_mid = unordered_mid.wrapping_add(1);
                (*ssn, mid)
            } else {
                let assigned = (*ssn, *ordered_mid);
                *ssn = ssn.wrapping_add(1);
                *ordered_mid = ordered_mid.wrapping_add(1);
                assigned
            }
        });
        for (id, (ssn, ordered_mid, unordered_mid)) in next {
            if let Some(s) = self.streams.get_mut(&id) {
                s.sequence_number = ssn;
                s.ordered_mid = ordered_mid;
                s.unordered_mid = unordered_mid;
            }
        }
    }

    /// RFC 6525 5.2.5, 5.2.6: the peer adds outgoing streams, or asks this side to.
    fn handle_add_streams_request(
        &mut self,
        p: &ParamAddStreamsRequest,
        answer: &mut ReconfigAnswer,
    ) {
        let rsn = p.reconfig_request_sequence_number;
        let count = p.number_of_new_streams;
        if !p.incoming {
            // 5.2.6: the peer's Add Outgoing Streams Request is how it performs an Add
            // Incoming Streams Request of this side's, which is thereby answered.
            if matches!(
                self.reconfig_in_flight,
                Some(OwnRequest::AddIncomingStreams(_))
            ) {
                self.reconfigs.clear();
                self.reconfig_in_flight = None;
                self.reconfig_in_progress = false;
                self.timers.stop(Timer::Reconfig);
            }
            // 5.2.5: the new inbound streams are added, each expecting SSN 0, unless that
            // passes the limit the application configured.
            let total = self.my_max_num_inbound_streams.checked_add(count);
            match total {
                Some(total) if total <= self.configured_inbound_streams => {
                    if count == 0 {
                        answer.respond(rsn, ReconfigResult::SuccessNop);
                        return;
                    }
                    self.my_max_num_inbound_streams = total;
                    self.events
                        .push_back(Event::Reconfig(ReconfigEvent::StreamsAdded {
                            inbound_streams: self.my_max_num_inbound_streams,
                            outbound_streams: self.my_max_num_outbound_streams,
                        }));
                    answer.respond(rsn, ReconfigResult::SuccessPerformed);
                }
                _ => answer.respond(rsn, ReconfigResult::Denied),
            }
            return;
        }

        // 5.2.6: the peer wants more streams from this side: denied, or done with an Add
        // Outgoing Streams Request of this side's own.
        let total = self.my_max_num_outbound_streams.checked_add(count);
        let allowed = total.is_some_and(|total| total <= self.configured_outbound_streams);
        if !allowed || !self.peer_supports_reconfig {
            answer.respond(rsn, ReconfigResult::Denied);
        } else if count == 0 {
            answer.respond(rsn, ReconfigResult::SuccessNop);
        } else if self
            .queue_own_request(OwnRequest::AddOutgoingStreams(count))
            .is_ok()
        {
            answer.respond(rsn, ReconfigResult::SuccessPerformed);
        } else {
            answer.respond(rsn, ReconfigResult::Denied);
        }
    }

    /// RFC 6525 5.2.7: a Re-configuration Response.
    fn handle_reconfig_response(&mut self, p: &ParamReconfigResponse) {
        let rsn = p.reconfig_response_sequence_number;
        // H1: a response for no request in flight is done with.
        if !self.reconfigs.contains_key(&rsn) {
            return;
        }
        if p.result == ReconfigResult::InProgress {
            // H2: the timer starts again, and its next expiry is not counted as an error.
            self.restart_reconfig_timer = true;
            self.reconfig_in_progress = true;
            return;
        }
        self.reconfigs.remove(&rsn);
        self.timers.stop(Timer::Reconfig);
        self.reconfig_in_progress = false;
        let Some(request) = self.reconfig_in_flight.take() else {
            return;
        };
        let success = matches!(
            p.result,
            ReconfigResult::SuccessPerformed | ReconfigResult::SuccessNop
        );
        let denied = p.result == ReconfigResult::Denied;
        match request {
            OwnRequest::OutgoingReset { streams, .. } => {
                // H3, H4: on success the streams send from SSN 0; either way sequence
                // numbers are assigned again and the data that was queued goes out.
                self.finish_outgoing_reset(&streams, success);
                let streams = streams.into_iter().map(|(id, _)| id).collect();
                self.events.push_back(Event::Reconfig(if success {
                    ReconfigEvent::OutgoingStreamsReset { streams }
                } else {
                    ReconfigEvent::OutgoingStreamsResetFailed { streams, denied }
                }));
            }
            OwnRequest::IncomingReset { streams } => {
                // A peer that performs the request answers with an Outgoing SSN Reset
                // Request (5.2.2 E1); a response says it did not.
                self.events.push_back(Event::Reconfig(
                    ReconfigEvent::IncomingStreamsResetNotPerformed { streams, denied },
                ));
            }
            OwnRequest::SsnTsnReset => {
                self.finish_tsn_reset(success.then_some(p.next_tsns).flatten(), denied)
            }
            OwnRequest::AddOutgoingStreams(count) => {
                if success {
                    // H6: the streams exist from the positive response on.
                    self.my_max_num_outbound_streams =
                        self.my_max_num_outbound_streams.saturating_add(count);
                    self.events
                        .push_back(Event::Reconfig(ReconfigEvent::StreamsAdded {
                            inbound_streams: self.my_max_num_inbound_streams,
                            outbound_streams: self.my_max_num_outbound_streams,
                        }));
                } else {
                    self.events
                        .push_back(Event::Reconfig(ReconfigEvent::AddStreamsFailed { denied }));
                }
            }
            OwnRequest::AddIncomingStreams(_) => {
                if !success {
                    self.events
                        .push_back(Event::Reconfig(ReconfigEvent::AddStreamsFailed { denied }));
                }
            }
        }
        self.awake_write_loop();
    }

    /// RFC 6525 5.2.7 H3, H4: the peer answered the reset of these outgoing streams.
    fn finish_outgoing_reset(&mut self, streams: &[(u16, Option<u64>)], success: bool) {
        let ids: Vec<(u16, Option<u64>)> = if streams.is_empty() {
            // Every stream.
            self.streams
                .iter()
                .map(|(id, s)| (*id, Some(s.generation)))
                .collect()
        } else {
            streams.to_vec()
        };
        for (id, generation) in ids {
            let Some(s) = self.streams.get_mut(&id) else {
                continue;
            };
            if generation != Some(s.generation) {
                // The stream that asked is gone; this one is another use of its number.
                continue;
            }
            if success {
                s.reset_outgoing_numbers();
            }
            s.outgoing_reset_pending = false;
            let held = std::mem::take(&mut s.held_writes);
            // They are numbered as they leave the queue, from the numbers just reset (or
            // kept, when the peer did not perform the reset).
            for chunks in held {
                self.held_write_count = self.held_write_count.saturating_sub(1);
                self.pending_queue.push_message(chunks);
            }
        }
    }

    /// RFC 6525 5.2.7 H5: the peer answered this side's SSN/TSN Reset Request. `next_tsns`
    /// is the Sender's Next TSN and the Receiver's Next TSN of a successful response.
    fn finish_tsn_reset(&mut self, next_tsns: Option<(u32, u32)>, denied: bool) {
        self.tsn_reset_requested = false;
        let mut held = std::mem::take(&mut self.held_reset_data);
        sort_by_tsn(&mut held);
        let release = |this: &mut Self, chunks: Vec<ChunkPayloadData>| {
            for d in chunks {
                this.reassembly_bytes = this.reassembly_bytes.saturating_sub(d.user_data.len());
                this.deliver_to_stream(&d);
            }
        };
        let Some((sender_next_tsn, receiver_next_tsn)) = next_tsns else {
            release(self, held);
            self.events
                .push_back(Event::Reconfig(ReconfigEvent::AssociationResetFailed {
                    denied,
                }));
            return;
        };

        // What arrived while the request was in flight: the peer's DATA from before its
        // reset is delivered first, what it sent after belongs to the streams as reset.
        let (after, before): (Vec<_>, Vec<_>) = held
            .into_iter()
            .partition(|d| sna32gte(d.tsn, sender_next_tsn));
        release(self, before);

        // "new data MUST be sent from the Receiver's Next TSN, beginning with SSN 0 for all
        // outgoing streams".
        self.inflight_queue = PayloadQueue::new();
        self.my_next_tsn = receiver_next_tsn;
        self.cumulative_tsn_ack_point = receiver_next_tsn.wrapping_sub(1);
        self.advanced_peer_tsn_ack_point = self.cumulative_tsn_ack_point;
        self.min_tsn2measure_rtt = receiver_next_tsn;
        self.fwd_tsn_stream_map.clear();
        self.i_fwd_tsn_stream_map.clear();
        self.will_send_forward_tsn = false;
        self.timers.stop(Timer::T3RTX);
        // "All incoming streams MUST be reset to 0 as the next expected SSN. The peer will
        // send DATA chunks starting with the Sender's Next TSN."
        let last_before = sender_next_tsn.wrapping_sub(1);
        if sna32lt(self.peer_last_tsn, last_before) {
            while let Some(&front) = self.payload_queue.sorted.front() {
                if !sna32lte(front, last_before) || self.payload_queue.pop(front).is_none() {
                    break;
                }
            }
            self.peer_last_tsn = last_before;
        }
        self.reset_all_sequence_numbers();
        release(self, after);

        self.events
            .push_back(Event::Reconfig(ReconfigEvent::AssociationReset {
                local_next_tsn: receiver_next_tsn,
                remote_next_tsn: sender_next_tsn,
            }));
    }
}
