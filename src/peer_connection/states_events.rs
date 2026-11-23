//! The states an API layer reads and the events that announce their changes (W3C webrtc-pc
//! sections 4.3, 4.4.1.3, 5.5, 5.6, 6.1.4 and 12): the connection's aggregate state getters,
//! the transport objects' `statechange`, `gatheringstatechange`, `selectedcandidatepairchange`
//! and `error` events, the end-of-candidates indications, and `icecandidateerror`.
//!
//! The transports change state deep in the pipeline handlers. What the application has been
//! told is kept here ([`AnnouncedStates`]), and a change is announced when the connection
//! learns of it, in the order the spec sets: a transport's own event, then the connection's
//! aggregate ones.

use super::RTCPeerConnection;
use crate::peer_connection::event::{
    RTCPeerConnectionEvent, RTCPeerConnectionIceErrorEvent, RTCPeerConnectionIceEvent,
    RTCTransportEvent, RTCTransportEventKind,
};
use crate::peer_connection::handler::transport_set::{
    TransportAnnounced, aggregate_gathering_state,
};
use crate::peer_connection::state::ice_connection_state::RTCIceConnectionState;
use crate::peer_connection::state::ice_gathering_state::RTCIceGatheringState;
use crate::peer_connection::state::peer_connection_state::RTCPeerConnectionState;
use crate::peer_connection::state::signaling_state::RTCSignalingState;
use crate::peer_connection::transport::dtls::state::RTCDtlsTransportState;
use crate::peer_connection::transport::ice::candidate::RTCIceCandidate;
use crate::peer_connection::transport::ice::state::RTCIceTransportState;
use crate::peer_connection::transport::sctp::state::RTCSctpTransportState;
use shared::error::{Error, Result};
use std::collections::HashSet;

/// The STUN error code W3C webrtc-pc section 4.8.3 reserves for a server that could not be
/// reached: "If no host candidate can reach the server, errorCode will be set to the value
/// 701 which is outside the STUN error code range."
pub const ICE_SERVER_UNREACHABLE: u16 = 701;

/// What the application has been told about the connection's states. What it has been told
/// about each transport is the transport's (`TransportAnnounced`).
#[derive(Debug, Default)]
pub(crate) struct AnnouncedStates {
    /// `None` while there is no SCTP transport (W3C `sctp` is null).
    pub(crate) sctp: Option<RTCSctpTransportState>,
    /// The server URLs an `icecandidateerror` with code 701 was fired for in the current
    /// gathering (W3C 4.8.3: once per URL while gathering).
    unreachable_servers: HashSet<String>,
    /// The connection's `iceGatheringState` last announced: the aggregate of the transports'
    /// gatherer states (W3C 4.3.2).
    gathering: RTCIceGatheringState,
}

impl AnnouncedStates {
    pub(crate) fn new() -> Self {
        Self {
            gathering: RTCIceGatheringState::New,
            ..Default::default()
        }
    }
}

fn ice_transport_state_of(state: RTCIceConnectionState) -> RTCIceTransportState {
    match state {
        RTCIceConnectionState::New => RTCIceTransportState::New,
        RTCIceConnectionState::Checking => RTCIceTransportState::Checking,
        RTCIceConnectionState::Connected => RTCIceTransportState::Connected,
        RTCIceConnectionState::Completed => RTCIceTransportState::Completed,
        RTCIceConnectionState::Disconnected => RTCIceTransportState::Disconnected,
        RTCIceConnectionState::Failed => RTCIceTransportState::Failed,
        RTCIceConnectionState::Closed => RTCIceTransportState::Closed,
        _ => RTCIceTransportState::Unspecified,
    }
}

impl RTCPeerConnection {
    /// W3C `signalingState`: where the connection is in the offer/answer exchange.
    pub fn signaling_state(&self) -> RTCSignalingState {
        self.signaling_state
    }

    /// W3C `iceGatheringState`: the aggregate of the ICE transports' gathering states (W3C
    /// 4.3.2): "gathering" while any transport gathers, "complete" once all have, else "new".
    pub fn ice_gathering_state(&self) -> RTCIceGatheringState {
        self.announced.gathering
    }

    /// W3C `iceConnectionState`: the aggregate of the ICE transports' states (W3C 4.3.4), and
    /// `Closed` once the connection is closed.
    pub fn ice_connection_state(&self) -> RTCIceConnectionState {
        if self.is_closed() {
            return RTCIceConnectionState::Closed;
        }
        crate::peer_connection::handler::transport_set::aggregate_ice_connection_state(
            self.pipeline_context.transports.ice_connection_states(),
        )
    }

    /// W3C `connectionState`: the aggregate of the ICE and DTLS transports' states (W3C 4.3.3).
    pub fn connection_state(&self) -> RTCPeerConnectionState {
        self.peer_connection_state
    }

    /// W3C `RTCErrorEvent.error` of a data channel's `error` event: the `RTCError` that
    /// [`RTCDataChannelEvent::OnError`] for channel `id` reported (`data-channel-failure`, or
    /// `sctp-failure` with the SCTP cause code). Kept after the channel closed, for the last
    /// 64 channels that failed; `None` for a channel that did not fail.
    ///
    /// [`RTCDataChannelEvent::OnError`]: crate::peer_connection::event::RTCDataChannelEvent::OnError
    pub fn data_channel_error(
        &self,
        id: crate::data_channel::RTCDataChannelId,
    ) -> Option<&crate::peer_connection::rtc_error::RTCError> {
        self.data_channels.error(id)
    }

    /// What the application has been told about the active transport.
    pub(crate) fn active_announced(&self) -> &TransportAnnounced {
        &self.pipeline_context.transports.active().announced
    }

    /// What the application has been told about the active transport, mutably.
    pub(crate) fn active_announced_mut(&mut self) -> &mut TransportAnnounced {
        &mut self.pipeline_context.transports.active_mut().announced
    }

    /// Fires `event` at the active transport (`OnTransportEvent`, with its ids), after
    /// `legacy`, the variant that names no transport, when the active transport is the
    /// default one.
    pub(crate) fn fire_transport_event(
        &mut self,
        legacy: RTCPeerConnectionEvent,
        event: RTCTransportEventKind,
    ) {
        let transports = &self.pipeline_context.transports;
        let is_default = transports.active_id() == transports.default_id();
        let active = transports.active();
        let event = RTCTransportEvent {
            ice_transport: active.ice_handler_context.ice_transport.id,
            dtls_transport: active.dtls_handler_context.dtls_transport.id,
            event,
        };
        if is_default {
            self.pipeline_context.event_outs.push_back(legacy);
        }
        self.pipeline_context
            .event_outs
            .push_back(RTCPeerConnectionEvent::OnTransportEvent(event));
    }

    /// W3C "update the ICE transport state" for a change the active transport's ICE agent
    /// reported: the transport's `statechange`, when its state changed. The caller then
    /// delivers the connection's `iceconnectionstatechange` and updates the connection state,
    /// in that order (webrtc-pc section 5.6).
    pub(crate) fn announce_ice_transport_state(&mut self, state: RTCIceConnectionState) {
        let state = ice_transport_state_of(state);
        if state == self.active_announced().ice || state == RTCIceTransportState::Unspecified {
            return;
        }
        self.active_announced_mut().ice = state;
        self.fire_transport_event(
            RTCPeerConnectionEvent::OnIceTransportStateChange(state),
            RTCTransportEventKind::IceStateChange(state),
        );
    }

    /// W3C 5.6 "selected candidate pair changed": `selectedcandidatepairchange` of each
    /// transport whose agent has a pair other than the one last announced.
    pub(crate) fn announce_selected_candidate_pair(&mut self) {
        for id in self.pipeline_context.transports.ids() {
            self.with_transport(id, |pc| pc.announce_selected_candidate_pair_on_active());
        }
    }

    fn announce_selected_candidate_pair_on_active(&mut self) {
        let pair = self.ice_transport().get_selected_candidate_pair();
        if pair == self.active_announced().selected_pair {
            return;
        }
        self.active_announced_mut().selected_pair = pair.clone();
        if let Some(pair) = pair {
            self.fire_transport_event(
                RTCPeerConnectionEvent::OnSelectedCandidatePairChange(pair.clone()),
                RTCTransportEventKind::SelectedCandidatePairChange(pair),
            );
        }
    }

    /// Announces the DTLS and SCTP transports' state changes the application has not been told
    /// of yet: each DTLS transport's `error` (for a failure) and `statechange`, then the
    /// connection's `connectionstatechange` the DTLS change causes (W3C 4.4.1.3, 5.5); the SCTP
    /// transport's `statechange` (W3C 6.1.4). Nothing once the connection is closed: `close()`
    /// changes the states without events.
    pub(crate) fn announce_transport_states(&mut self) {
        if self.is_closed() {
            return;
        }
        for id in self.pipeline_context.transports.ids() {
            self.with_transport(id, |pc| pc.announce_dtls_state_on_active());
        }

        let sctp = self.sctp().map(|sctp| sctp.state());
        if sctp != self.announced.sctp {
            let previous = std::mem::replace(&mut self.announced.sctp, sctp);
            // The transport is created in the "connecting" state without an event; only a
            // change of an existing transport's state is one.
            if let (Some(_), Some(state)) = (previous, sctp) {
                self.pipeline_context
                    .event_outs
                    .push_back(RTCPeerConnectionEvent::OnSctpTransportStateChange(state));
            }
        }
    }

    fn announce_dtls_state_on_active(&mut self) {
        let dtls = self.dtls_transport().state();
        if dtls == self.active_announced().dtls {
            return;
        }
        self.active_announced_mut().dtls = dtls;
        if dtls == RTCDtlsTransportState::Failed
            && let Some(error) = self.dtls_transport_mut().failure.take()
        {
            self.fire_transport_event(
                RTCPeerConnectionEvent::OnDtlsTransportError(error.clone()),
                RTCTransportEventKind::DtlsError(error),
            );
        }
        self.fire_transport_event(
            RTCPeerConnectionEvent::OnDtlsTransportStateChange(dtls),
            RTCTransportEventKind::DtlsStateChange(dtls),
        );
        self.update_connection_state(false);
    }

    /// W3C 4.4.1.6 (set the session description, stable): a transport no non-stopped
    /// transceiver uses any more is closed, "the RTCDtlsTransports and their associated
    /// RTCIceTransports", and "this results in events firing on these objects": the active
    /// transport's DTLS and then ICE `statechange` to "closed", when it had not announced that
    /// already.
    pub(crate) fn announce_transport_closed(&mut self) {
        if self.active_announced().dtls != RTCDtlsTransportState::Closed {
            self.active_announced_mut().dtls = RTCDtlsTransportState::Closed;
            self.fire_transport_event(
                RTCPeerConnectionEvent::OnDtlsTransportStateChange(RTCDtlsTransportState::Closed),
                RTCTransportEventKind::DtlsStateChange(RTCDtlsTransportState::Closed),
            );
        }
        if self.active_announced().ice != RTCIceTransportState::Closed {
            self.active_announced_mut().ice = RTCIceTransportState::Closed;
            self.active_announced_mut().selected_pair = None;
            self.fire_transport_event(
                RTCPeerConnectionEvent::OnIceTransportStateChange(RTCIceTransportState::Closed),
                RTCTransportEventKind::IceStateChange(RTCIceTransportState::Closed),
            );
        }
    }

    /// What `close()` changes without telling (W3C `close()`: the states are set "without
    /// firing any event"): the announced states become the closed ones.
    pub(crate) fn close_announced_states(&mut self) {
        for bundle in self.pipeline_context.transports.iter_mut() {
            bundle.announced.ice = RTCIceTransportState::Closed;
            bundle.announced.dtls = bundle.dtls_handler_context.dtls_transport.state();
            bundle.announced.selected_pair = None;
        }
        self.announced.sctp = self.sctp().map(|sctp| sctp.state());
    }

    /// Moves the active transport's gatherer to `state`, with its `gatheringstatechange` when
    /// it changed, then the connection's gathering state (W3C 5.6: "fire an event named
    /// gatheringstatechange at transport", then update the connection's gathering state).
    pub(crate) fn set_gathering_state(&mut self, state: RTCIceGatheringState) {
        self.ice_transport_mut().ice_gathering_state = state;
        if self.active_announced().gathering == state {
            return;
        }
        self.active_announced_mut().gathering = state;
        self.fire_transport_event(
            RTCPeerConnectionEvent::OnIceGathererStateChange(state),
            RTCTransportEventKind::GatheringStateChange(state),
        );
        self.update_gathering_state();
    }

    /// W3C 4.3.2 for the connection: its `iceGatheringState` is the aggregate of the
    /// transports' gatherer states; a change is announced with `icegatheringstatechange`, and
    /// the move to "complete" also with the legacy `icecandidate` whose candidate is null (W3C
    /// 4.8.2: "All RTCIceTransports have finished gathering candidates").
    pub(crate) fn update_gathering_state(&mut self) {
        let aggregate =
            aggregate_gathering_state(self.pipeline_context.transports.gathering_states());
        if aggregate == self.announced.gathering {
            return;
        }
        self.announced.gathering = aggregate;
        if aggregate == RTCIceGatheringState::Gathering {
            // A new gathering: errors are reported once per server again.
            self.announced.unreachable_servers.clear();
        }
        self.pipeline_context.event_outs.push_back(
            RTCPeerConnectionEvent::OnIceGatheringStateChangeEvent(aggregate),
        );
        if aggregate == RTCIceGatheringState::Complete {
            self.pipeline_context.event_outs.push_back(
                RTCPeerConnectionEvent::OnIceCandidateEvent(RTCPeerConnectionIceEvent {
                    candidate: None,
                    url: None,
                    ice_transport: None,
                }),
            );
        }
    }

    /// The gatherer state last announced and the username fragment of the generation it
    /// belongs to.
    pub(crate) fn announced_gathering(&self) -> (RTCIceGatheringState, Option<String>) {
        let announced = self.active_announced();
        (announced.gathering, announced.gathering_ufrag.clone())
    }

    /// Announces again the gathering [`Self::announced_gathering`] returned: a rolled-back
    /// local offer's ICE restart was taken back.
    pub(crate) fn restore_announced_gathering(
        &mut self,
        (state, ufrag): (RTCIceGatheringState, Option<String>),
    ) {
        self.active_announced_mut().gathering_ufrag = ufrag;
        self.set_gathering_state(state);
    }

    /// W3C 5.6 "gathering begins", at `set_local_description`: when the description's ICE
    /// generation (its username fragment) has not gathered yet, the first time or after an ICE
    /// restart, the gatherer goes to "gathering" with its events. A later description of the
    /// same generation changes nothing: a generation that finished stays "complete" (W3C
    /// 5.6.3: "will not gather again until an ICE restart").
    ///
    /// Also records the media section the transport's candidates name: the first section of
    /// the BUNDLE group, or else the first section with a mid.
    pub(crate) fn begin_local_gathering(
        &mut self,
        local_description: &sdp::description::session::SessionDescription,
    ) {
        let bundle_mid = local_description
            .attribute(sdp::description::session::ATTR_KEY_GROUP)
            .and_then(|group| {
                let mut tokens = group.split_whitespace();
                (tokens.next() == Some("BUNDLE"))
                    .then(|| tokens.next().map(str::to_owned))
                    .flatten()
            });
        let section = local_description
            .media_descriptions
            .iter()
            .enumerate()
            .find_map(|(index, media)| {
                let mid = media.attribute(sdp::description::session::ATTR_KEY_MID)??;
                let wanted = bundle_mid.as_deref().is_none_or(|bundle| bundle == mid);
                wanted.then(|| (mid.to_owned(), u16::try_from(index).unwrap_or(u16::MAX)))
            });
        if section.is_some() {
            self.ice_transport_mut().local_media_section = section;
        }
        self.begin_gathering_generation();
    }

    /// The active transport starts gathering its ICE generation, unless it has already: the
    /// gatherer goes to "gathering", with its events.
    pub(crate) fn begin_gathering_generation(&mut self) {
        let ufrag = self
            .ice_transport()
            .agent
            .get_local_credentials()
            .ufrag
            .clone();
        if self.active_announced().gathering_ufrag.as_deref() == Some(ufrag.as_str()) {
            // The field may have been moved by a restart offer that was not applied.
            let announced = self.active_announced().gathering;
            self.ice_transport_mut().ice_gathering_state = announced;
            return;
        }
        self.active_announced_mut().gathering_ufrag = Some(ufrag);
        self.set_gathering_state(RTCIceGatheringState::Gathering);
    }

    /// W3C 5.6 "the ICE agent has finished gathering" for the active transport's current
    /// generation, which the application signals with an empty local candidate: an
    /// `icecandidate` with the end-of-candidates candidate of the generation,
    /// `a=end-of-candidates` in the local descriptions, the transport's gathering state
    /// "complete" with its events, and, once every transport has finished, the connection's
    /// (with the legacy `icecandidate` whose candidate is null).
    ///
    /// Nothing happens when the generation has already finished: the end is announced once,
    /// until an ICE restart starts a new one.
    pub(crate) fn finish_local_gathering(&mut self) {
        if self.active_announced().gathering == RTCIceGatheringState::Complete {
            return;
        }
        // The generation has gathered: a local description of it set later (the application
        // may finish gathering before it sets one) does not start it again.
        let ufrag = self
            .ice_transport()
            .agent
            .get_local_credentials()
            .ufrag
            .clone();
        self.active_announced_mut().gathering_ufrag = Some(ufrag);
        let mut end = RTCIceCandidate::end_of_candidates_for(None, None, None);
        self.ice_transport().describe_local_candidate(&mut end);
        let ice_transport = Some(self.ice_transport().id);
        self.pipeline_context
            .event_outs
            .push_back(RTCPeerConnectionEvent::OnIceCandidateEvent(
                RTCPeerConnectionIceEvent {
                    candidate: Some(end),
                    url: None,
                    ice_transport,
                },
            ));
        // RFC 8838 section 13: no candidate follows the end-of-candidates indication of its
        // generation; the agent refuses one from here on, until an ICE restart.
        self.ice_transport_mut()
            .agent
            .set_local_gathering_complete();
        // The local descriptions list the candidates, and `a=end-of-candidates` once the state
        // is "complete", whenever they are read (`populate_local_candidates`).
        self.set_gathering_state(RTCIceGatheringState::Complete);
    }

    /// The ICE username fragments of the current and pending local descriptions.
    pub(crate) fn local_ice_ufrags(&self) -> Vec<String> {
        let mut ufrags: Vec<String> = [
            self.current_local_description(),
            self.pending_local_description(),
        ]
        .into_iter()
        .flatten()
        .filter_map(|description| description.parsed)
        .flat_map(|parsed| description_ufrags(&parsed))
        .collect();
        ufrags.sort();
        ufrags.dedup();
        ufrags
    }

    /// Whether an ICE restart `restart_ice` asked for is still to be done: it recorded
    /// credentials, and no answer has yet made a current local description without them (W3C:
    /// `[[LocalIceCredentialsToReplace]]` is emptied when an answer does).
    pub(crate) fn ice_restart_pending(&self) -> bool {
        if self.ice_credentials_to_replace.is_empty() {
            return false;
        }
        // The set is emptied when an answer leaves the current local description with none of
        // its credentials; until a first answer there is no current description to look at.
        let Some(current) = self
            .current_local_description()
            .and_then(|description| description.parsed)
        else {
            return true;
        };
        description_ufrags(&current)
            .iter()
            .any(|ufrag| self.ice_credentials_to_replace.contains(ufrag))
    }

    /// Reports that gathering from a STUN or TURN server failed (W3C webrtc-pc section 4.8.3,
    /// `icecandidateerror`). The application gathers (it owns the sockets), so it is the one
    /// that sees a server answer with an error or not at all; this raises
    /// [`RTCPeerConnectionEvent::OnIceCandidateErrorEvent`] for it as the spec has the user
    /// agent do.
    ///
    /// `error.address` and `error.port` are the local socket's, or empty and `None`-like (an
    /// empty address, port 0) when that address is not already exposed in a local candidate
    /// (4.8.3: "null if the local address has not yet been exposed"); they are cleared here when
    /// no local candidate has that address. An `error_code` of [`ICE_SERVER_UNREACHABLE`]
    /// (701) is reported once per server URL in a gathering (4.8.3: "fired once per server
    /// URL while in the gathering state"); later ones are dropped. Other codes must be STUN
    /// error codes (300 to 699).
    ///
    /// # Errors
    ///
    /// `InvalidStateError` once the connection is closed; `RangeError` for an `error_code`
    /// that is neither a STUN error code nor 701.
    pub fn report_ice_candidate_error(
        &mut self,
        mut error: RTCPeerConnectionIceErrorEvent,
    ) -> Result<()> {
        if self.is_closed() {
            return Err(Error::InvalidStateError);
        }
        if error.error_code != ICE_SERVER_UNREACHABLE && !(300..=699).contains(&error.error_code) {
            return Err(Error::RangeError(format!(
                "ICE candidate error code {} is neither a STUN error code nor 701",
                error.error_code
            )));
        }
        if error.error_code == ICE_SERVER_UNREACHABLE
            && !self.announced.unreachable_servers.insert(error.url.clone())
        {
            return Ok(());
        }
        // The transport whose gathering failed: the one the application named, else the one
        // that exposed the local address, else the default one.
        let transports = &self.pipeline_context.transports;
        let exposed_on = (!error.address.is_empty())
            .then(|| {
                transports.ids().into_iter().find(|id| {
                    transports.transport(*id).is_some_and(|bundle| {
                        bundle
                            .ice_handler_context
                            .ice_transport
                            .agent
                            .get_local_candidates()
                            .iter()
                            .any(|candidate| candidate.address() == error.address)
                    })
                })
            })
            .flatten();
        let named = error.ice_transport.and_then(|named| {
            transports.ids().into_iter().find(|id| {
                transports
                    .transport(*id)
                    .is_some_and(|bundle| bundle.ice_handler_context.ice_transport.id == named)
            })
        });
        let on = named.or(exposed_on).unwrap_or(transports.default_id());
        let exposed = exposed_on == Some(on);
        error.ice_transport = Some(self.ice_transport_of(on).id);
        if !exposed {
            error.address.clear();
            error.port = 0;
        }
        self.pipeline_context
            .event_outs
            .push_back(RTCPeerConnectionEvent::OnIceCandidateErrorEvent(error));
        Ok(())
    }
}

/// The ICE username fragments a description carries, at session level or in its sections.
fn description_ufrags(description: &sdp::description::session::SessionDescription) -> Vec<String> {
    description
        .media_descriptions
        .iter()
        .filter_map(|media| {
            crate::peer_connection::sdp::media_ice_credentials(description, media)
                .0
                .map(str::to_owned)
        })
        .chain(description.attribute("ice-ufrag").cloned())
        .collect()
}
