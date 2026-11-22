use crate::peer_connection::event::RTCPeerConnectionEvent;
use crate::peer_connection::event::{RTCEventInternal, TaggedRTCEventInternal};
use crate::peer_connection::message::internal::{
    RTCMessageInternal, STUNMessage, TaggedRTCMessageInternal,
};
use crate::peer_connection::transport::ice::IceTransport;
use crate::statistics::accumulator::{
    IceCandidatePairAccumulator, RTCStatsAccumulator, candidate_pair_stats_id,
};
use crate::statistics::stats::ice_candidate_pair::RTCStatsIceCandidatePairState;
use log::{debug, trace};
use shared::error::{Error, Result};
use shared::{TransportContext, TransportMessage};
use std::collections::VecDeque;
use std::time::Instant;

pub(crate) struct IceHandlerContext {
    pub(crate) ice_transport: IceTransport,

    pub(crate) read_outs: VecDeque<TaggedRTCMessageInternal>,
    pub(crate) write_outs: VecDeque<TaggedRTCMessageInternal>,
    pub(crate) event_outs: VecDeque<TaggedRTCEventInternal>,

    /// Cached stats key of the currently selected ICE candidate pair
    /// (`RTCIceCandidatePair_<local>_<remote>`), refreshed only when the selected
    /// pair changes. The per-packet read/write path looks the pair's stats
    /// accumulator up with this key instead of re-`format!`ing it on every packet
    /// — that formatting was a heap allocation on the hot path in both directions.
    pub(crate) selected_pair_key: Option<String>,

    /// How many times the agent has reported another selected candidate pair. The SCTP
    /// transport, which runs on a placeholder address and so cannot see the path change under
    /// it, is told through this (RFC 8831 section 5: "SCTP SHOULD be notified when an address
    /// change has happened"): the event itself ends at the DTLS handler.
    pub(crate) selected_pair_changes: u64,

    /// Two lite agents, this one controlling: the pair it chose among several, which the
    /// next offer conveys (RFC 8445 section 8.2, RFC 8839 section 4.4.1.3: the local candidate
    /// alone and `a=remote-candidates`) until an answer to such an offer is applied.
    pub(crate) lite_candidate_update: Option<(
        Box<::ice::candidate::Candidate>,
        Box<::ice::candidate::Candidate>,
    )>,
    /// `lite_candidate_update` was set and the negotiation-needed flag is still to be updated.
    pub(crate) lite_candidate_update_raised: bool,
}

impl IceHandlerContext {
    pub(crate) fn new(ice_transport: IceTransport) -> Self {
        Self {
            ice_transport,

            read_outs: VecDeque::new(),
            write_outs: VecDeque::new(),
            event_outs: VecDeque::new(),

            selected_pair_key: None,
            selected_pair_changes: 0,
            lite_candidate_update: None,
            lite_candidate_update_raised: false,
        }
    }
}

/// IceHandler implements ICE Protocol handling
pub(crate) struct IceHandler<'a> {
    ctx: &'a mut IceHandlerContext,
    stats: &'a mut RTCStatsAccumulator,
}

impl<'a> IceHandler<'a> {
    pub(crate) fn new(ctx: &'a mut IceHandlerContext, stats: &'a mut RTCStatsAccumulator) -> Self {
        IceHandler { ctx, stats }
    }

    pub(crate) fn name(&self) -> &'static str {
        "IceHandler"
    }

    /// Counts a datagram on the candidate pair it travels on (webrtc-stats
    /// `RTCIceCandidatePairStats.packetsSent` / `packetsReceived`: the packets "on this candidate
    /// pair", every one of them).
    ///
    /// The pair's statistics are found through the key cached at the last
    /// `SelectedCandidatePairChange`, so the per-packet path formats nothing. The agent can
    /// have a selected pair before that event has been polled, though, and a datagram that
    /// crosses in between travels on that pair all the same: when the cache does not name a
    /// pair with statistics, it is filled from the agent's selected pair. (During an ICE
    /// restart the agent has none and the path is the previous pair's, which the cache still
    /// names.)
    fn count_on_pair_in_use(&mut self, count: impl FnOnce(&mut IceCandidatePairAccumulator)) {
        let cached = self
            .ctx
            .selected_pair_key
            .as_ref()
            .is_some_and(|key| self.stats.ice_candidate_pairs.contains_key(key));
        if !cached
            && let Some((local, remote)) =
                self.ctx.ice_transport.agent.get_selected_candidate_pair()
        {
            let (local_id, remote_id) = (local.id().to_owned(), remote.id().to_owned());
            self.stats
                .get_or_create_candidate_pair(&local_id, &remote_id);
            self.ctx.selected_pair_key = Some(candidate_pair_stats_id(&local_id, &remote_id));
        }
        if let Some(key) = &self.ctx.selected_pair_key
            && let Some(pair) = self.stats.ice_candidate_pairs.get_mut(key)
        {
            count(pair);
        }
    }
}

impl<'a>
    sansio::Protocol<TaggedRTCMessageInternal, TaggedRTCMessageInternal, TaggedRTCEventInternal>
    for IceHandler<'a>
{
    type Rout = TaggedRTCMessageInternal;
    type Wout = TaggedRTCMessageInternal;
    type Eout = TaggedRTCEventInternal;
    type Error = Error;
    type Time = Instant;

    fn handle_read(&mut self, mut msg: TaggedRTCMessageInternal) -> Result<()> {
        if let RTCMessageInternal::Stun(STUNMessage::Raw(message)) = msg.message {
            self.ctx.ice_transport.agent.handle_read(TransportMessage {
                now: msg.now,
                transport: msg.transport,
                message,
            })?;
        } else if self.ctx.ice_transport.agent.media_path().is_some() {
            // Data is taken from the path it is sent on (the selected pair's; during an ICE
            // restart the pair the session had before it, RFC 8445 Section 9) and from the
            // remote candidate of any other valid pair (Section 12.2: an agent is "prepared to
            // receive data on any of the candidates" it provided, and knows the data is the
            // peer's "as a consequence of the STUN exchange"). A datagram from an address no
            // check of ours was answered from is not part of this connection: it is dropped
            // rather than handed to DTLS, where it would cost a decrypt attempt or reach
            // handshake processing. With `with_ice_data_from_selected_pair_only` only the
            // selected pair's remote address is accepted.
            let other_pair = match self.ctx.ice_transport.agent.data_path(msg.transport) {
                None => {
                    trace!(
                        "drop non-STUN message from {:?}: not from a valid pair",
                        msg.transport.peer_addr
                    );
                    // RFC 6544 Section 7.1: on a TCP connection this agent opened, a first
                    // answer that is not STUN fails the pairs of that remote candidate (the
                    // application closes the connection).
                    if self
                        .ctx
                        .ice_transport
                        .agent
                        .handle_non_stun_before_validation(msg.now, msg.transport)
                    {
                        debug!(
                            "the first answer on the TCP connection to {:?} is not STUN: its pairs failed",
                            msg.transport.peer_addr
                        );
                    }
                    return Ok(());
                }
                Some(::ice::DataPath::InUse) => None,
                Some(::ice::DataPath::Valid(local, remote)) => {
                    Some((local.id().to_owned(), remote.id().to_owned()))
                }
            };

            // only ICE connection is ready and bypass it
            debug!("bypass ice read {:?}", msg.transport.peer_addr);

            // Track packets/bytes received on the selected candidate pair. Look
            // the accumulator up via the cached key (set on the last
            // SelectedCandidatePairChange) to avoid allocating the key per packet.
            let bytes = msg.message.len();
            let now = msg.now;
            match other_pair {
                None => self.count_on_pair_in_use(|pair| pair.on_packet_received(bytes, now)),
                // (Off the path in use: rare, so the key is made per packet.)
                Some((local_id, remote_id)) => self
                    .stats
                    .get_or_create_candidate_pair(&local_id, &remote_id)
                    .on_packet_received(bytes, now),
            }

            // When ICE restarts and the selected candidate pair changes,
            // WebRTC treats this as a path migration, and DTLS continues unchanged, bound to the ICE transport, not to a fixed 5-tuple.
            // Use default for transport to make DTLS tunneled
            //
            // The ECN codepoint the datagram arrived with stays on SRTP / SRTCP: the RTP
            // receive side counts it and RFC 8888 feedback reports it. DTLS does not use it.
            let ecn = if matches!(msg.message, RTCMessageInternal::Rtp(_)) {
                msg.transport.ecn
            } else {
                None
            };
            msg.transport = TransportContext {
                ecn,
                ..TransportContext::default()
            };
            self.ctx.read_outs.push_back(msg);
        } else {
            trace!(
                "drop message from {:?} to {:?} before ICE connection is connected",
                msg.transport.peer_addr, msg.transport.local_addr
            );
            // RFC 6544 Section 7.1, as above.
            self.ctx
                .ice_transport
                .agent
                .handle_non_stun_before_validation(msg.now, msg.transport);
        }

        Ok(())
    }

    fn poll_read(&mut self) -> Option<Self::Rout> {
        self.ctx.read_outs.pop_front()
    }

    fn handle_write(&mut self, mut msg: TaggedRTCMessageInternal) -> Result<()> {
        if let Some(path) = self.ctx.ice_transport.agent.media_path() {
            // use ICE selected candidate pair to replace local/peer addr and
            // transport protocol: DTLS/SCTP endpoints run on placeholder
            // transport contexts, so without the protocol rewrite their
            // transmits stay stamped UDP even when the selected pair is TCP,
            // and consumers routing poll_write() output by transport_protocol
            // send every non-STUN packet down the wrong transport.
            // Use the local candidate's base address: for (server/peer-)
            // reflexive candidates the candidate address is the NAT mapping,
            // not a bound local socket (RFC 8445 §5.1.1).
            // During an ICE restart this is the previous pair's path, until the restart
            // selects one (RFC 8445 Section 9).
            msg.transport.local_addr = path.local_addr;
            msg.transport.peer_addr = path.peer_addr;
            msg.transport.transport_protocol = path.transport_protocol;
            // Only RTP media is ever ECN-marked (the interceptor handler decides which);
            // DTLS and SCTP go out Not-ECT whatever context their endpoints carried.
            if !matches!(msg.message, RTCMessageInternal::Rtp(_)) {
                msg.transport.ecn = None;
            }
            debug!("Bypass ice write {:?}", msg.transport.peer_addr);

            // Track packets/bytes sent on the selected candidate pair. Look the
            // accumulator up via the cached key to avoid allocating it per packet.
            let bytes = msg.message.len();
            let now = msg.now;
            self.count_on_pair_in_use(|pair| pair.on_packet_sent(bytes, now));

            self.ctx.write_outs.push_back(msg);
        } else {
            trace!(
                "drop message from {:?} to {:?} before ICE connection is connected",
                msg.transport.local_addr, msg.transport.peer_addr,
            );
        }

        Ok(())
    }

    fn poll_write(&mut self) -> Option<Self::Wout> {
        while let Some(transmit) = self.ctx.ice_transport.agent.poll_write() {
            self.ctx.write_outs.push_back(TaggedRTCMessageInternal {
                now: transmit.now,
                transport: transmit.transport,
                message: RTCMessageInternal::Stun(STUNMessage::Raw(transmit.message)),
            });
        }

        self.ctx.write_outs.pop_front()
    }

    fn handle_event(&mut self, evt: TaggedRTCEventInternal) -> Result<()> {
        self.ctx.event_outs.push_back(evt);
        Ok(())
    }

    fn poll_event(&mut self) -> Option<Self::Eout> {
        if let Some(evt) = self.ctx.ice_transport.agent.poll_event() {
            // The agent stamps its own events, so this drain *propagates* that instant rather
            // than retaining one: the condition was observed when the agent saw it, not when
            // the pipeline got round to polling for it.
            let now = evt.now;
            match evt.event {
                ::ice::Event::ConnectionStateChange(state) => {
                    let ice_connection_state = state.into();
                    self.ctx.ice_transport.ice_connection_state = ice_connection_state;

                    // Update transport stats for ICE state change
                    // Use the original ice state which converts to RTCIceTransportState
                    self.stats.transport.on_ice_state_changed(state.into());
                    // A transport that failed or closed has no selected pair any more.
                    if matches!(
                        state,
                        ::ice::state::ConnectionState::Failed
                            | ::ice::state::ConnectionState::Closed
                    ) {
                        self.stats.on_selected_candidate_pair(None);
                    }

                    self.ctx.event_outs.push_back(TaggedRTCEventInternal {
                        now,
                        event: RTCEventInternal::RTCPeerConnectionEvent(
                            RTCPeerConnectionEvent::OnIceConnectionStateChangeEvent(
                                ice_connection_state,
                            ),
                        ),
                    });
                }
                ::ice::Event::SelectedCandidatePairChange(local, remote) => {
                    debug!(
                        "ice selected candidate pair {:?} <-> {:?}",
                        local.addr(),
                        remote.addr()
                    );

                    // Create/update the candidate pair accumulator
                    let pair = self
                        .stats
                        .get_or_create_candidate_pair(local.id(), remote.id());
                    pair.nominated = true;
                    pair.state = RTCStatsIceCandidatePairState::Succeeded;

                    // Cache the pair's stats key so the per-packet path can look
                    // the accumulator up by borrow instead of re-formatting (and
                    // allocating) the key on every read/write.
                    let key = candidate_pair_stats_id(local.id(), remote.id());
                    self.ctx.selected_pair_key = Some(key.clone());
                    self.ctx.selected_pair_changes += 1;
                    // Update transport stats for selected candidate pair change
                    self.stats.on_selected_candidate_pair(Some(key));

                    self.ctx.event_outs.push_back(TaggedRTCEventInternal {
                        now,
                        event: RTCEventInternal::ICESelectedCandidatePairChange,
                    });
                }
                ::ice::Event::RoleChange(is_controlling) => {
                    self.stats.transport.on_ice_role_changed(is_controlling);
                }
                ::ice::Event::LocalCandidateRenamed(candidate) => {
                    // The candidate's mDNS name was lost to another host and replaced (RFC
                    // 6762 section 9): it is announced again, for the application to convey,
                    // and its statistics show the new name.
                    let mut rtc_candidate =
                        crate::peer_connection::transport::RTCIceCandidate::from(&*candidate);
                    self.ctx
                        .ice_transport
                        .describe_local_candidate(&mut rtc_candidate);
                    if let Some(known) = self.stats.local_candidates.get_mut(
                        &crate::statistics::accumulator::local_candidate_stats_id(candidate.id()),
                    ) {
                        known.address = Some(rtc_candidate.address.clone());
                    }
                    self.ctx.event_outs.push_back(TaggedRTCEventInternal {
                        now,
                        event: RTCEventInternal::RTCPeerConnectionEvent(
                            RTCPeerConnectionEvent::OnIceCandidateEvent(
                                crate::peer_connection::event::RTCPeerConnectionIceEvent {
                                    candidate: Some(rtc_candidate),
                                    url: None,
                                },
                            ),
                        ),
                    });
                }
                ::ice::Event::LiteCandidateUpdate(local, remote) => {
                    // The peer connection makes the updated offer (`check_negotiation_needed`).
                    self.ctx.lite_candidate_update = Some((local, remote));
                    self.ctx.lite_candidate_update_raised = true;
                }
                _ => {}
            }
        }

        self.ctx.event_outs.pop_front()
    }

    fn handle_timeout(&mut self, now: Instant) -> Result<()> {
        self.ctx.ice_transport.agent.handle_timeout(now)
    }

    fn poll_timeout(&mut self) -> Option<Instant> {
        self.ctx.ice_transport.agent.poll_timeout()
    }

    fn close(&mut self) -> Result<()> {
        self.ctx.ice_transport.agent.close()
    }
}
