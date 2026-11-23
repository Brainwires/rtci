//! The transports of one peer connection.
//!
//! RFC 9429 gives every m= section that is not bundled into another one a transport of its
//! own: ICE credentials and candidates, a DTLS association and the SRTP keys it exports
//! (sections 4.1.1, 5.2.1, 5.3.1; RFC 9143 section 7). A [`TransportSet`] holds those
//! transports, each a [`TransportBundle`] keyed by a [`TransportId`], and says which one an
//! m= section, a datagram or the SCTP association uses.
//!
//! The first transport is created with the peer connection and is the default one: every
//! m= section without a transport of its own is on it, and the single-transport accessors
//! (`ice_transport()`, `dtls_transport()`) return it. Descriptions add transports for the
//! sections outside a BUNDLE group (`RTCPeerConnection::update_transport_layout`) and
//! remove those a BUNDLE group made unused.
//!
//! The pipeline's ICE, DTLS and SRTP handlers act on the *active* transport. It is the
//! default one except while the connection works on another: a datagram routed to it, a
//! sweep of the pipeline per transport, or [`RTCPeerConnection::with_transport`].
//!
//! [`RTCPeerConnection::with_transport`]: crate::peer_connection::RTCPeerConnection

use crate::peer_connection::handler::dtls::DtlsHandlerContext;
use crate::peer_connection::handler::ice::IceHandlerContext;
use crate::peer_connection::handler::srtp::SrtpHandlerContext;
use crate::peer_connection::state::ice_connection_state::RTCIceConnectionState;
use crate::peer_connection::state::ice_gathering_state::RTCIceGatheringState;
use crate::peer_connection::state::peer_connection_state::RTCPeerConnectionState;
use crate::peer_connection::transport::dtls::state::RTCDtlsTransportState;
use crate::peer_connection::transport::ice::candidate_pair::RTCIceCandidatePair;
use crate::peer_connection::transport::ice::state::RTCIceTransportState;
use shared::TransportContext;
use std::collections::HashMap;

/// Names one transport of a [`TransportSet`]. Internal: the W3C objects carry
/// [`RTCTransportId`](crate::peer_connection::transport::RTCTransportId)s, which stay what
/// they were.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub(crate) struct TransportId(pub(crate) usize);

/// One transport: an ICE agent, the DTLS endpoint over it and the SRTP contexts that
/// endpoint keys. The SCTP association is not part of it: there is one per peer connection,
/// over the transport [`TransportSet::data_transport_id`] names.
pub(crate) struct TransportBundle {
    pub(crate) id: TransportId,
    pub(crate) ice_handler_context: IceHandlerContext,
    pub(crate) dtls_handler_context: DtlsHandlerContext,
    pub(crate) srtp_handler_context: SrtpHandlerContext,
    /// What the application has been told about this transport.
    pub(crate) announced: TransportAnnounced,
}

/// What the application has been told about one transport's states (W3C webrtc-pc 5.5, 5.6:
/// each `RTCIceTransport` and `RTCDtlsTransport` fires its own events).
#[derive(Debug)]
pub(crate) struct TransportAnnounced {
    pub(crate) ice: RTCIceTransportState,
    pub(crate) selected_pair: Option<RTCIceCandidatePair>,
    pub(crate) dtls: RTCDtlsTransportState,
    /// The gatherer state last announced. The field on the ICE transport can run ahead of it:
    /// `create_offer` with an ICE restart moves it to "gathering" for the description it
    /// generates, before the restart is applied.
    pub(crate) gathering: RTCIceGatheringState,
    /// The username fragment of the ICE generation whose gathering was started last.
    pub(crate) gathering_ufrag: Option<String>,
    /// The local candidates announced in an `icecandidate` event, with the username fragment
    /// of the generation they were announced for (W3C 5.6: candidates are surfaced per
    /// generation; RFC 8838 section 9 ties a trickled candidate to its generation).
    pub(crate) announced_candidates: Vec<(String, String)>,
}

impl Default for TransportAnnounced {
    fn default() -> Self {
        Self {
            ice: RTCIceTransportState::New,
            selected_pair: None,
            dtls: RTCDtlsTransportState::New,
            gathering: RTCIceGatheringState::New,
            gathering_ufrag: None,
            announced_candidates: vec![],
        }
    }
}

#[derive(Clone, Copy)]
enum Direction {
    Inbound,
    Outbound,
}

/// The `(receiver, sender)` ufrags of a STUN Binding request's USERNAME (RFC 8445 section
/// 7.2.2: `<receiver's ufrag>:<sender's ufrag>`); `None` for anything else.
pub(crate) fn binding_request_ufrags(datagram: &[u8]) -> Option<(&str, &str)> {
    const BINDING_REQUEST: u16 = 0x0001;
    const MAGIC_COOKIE: [u8; 4] = [0x21, 0x12, 0xa4, 0x42];
    const USERNAME: u16 = 0x0006;
    if datagram.len() < 20 || datagram[4..8] != MAGIC_COOKIE {
        return None;
    }
    if u16::from_be_bytes([datagram[0], datagram[1]]) != BINDING_REQUEST {
        return None;
    }
    let length = usize::from(u16::from_be_bytes([datagram[2], datagram[3]]));
    let attributes = datagram.get(20..20 + length)?;
    let mut at = 0;
    while at + 4 <= attributes.len() {
        let kind = u16::from_be_bytes([attributes[at], attributes[at + 1]]);
        let len = usize::from(u16::from_be_bytes([attributes[at + 2], attributes[at + 3]]));
        let value = attributes.get(at + 4..at + 4 + len)?;
        if kind == USERNAME {
            return std::str::from_utf8(value).ok()?.split_once(':');
        }
        at += 4 + len.next_multiple_of(4);
    }
    None
}

/// The transports of a peer connection; never empty.
pub(crate) struct TransportSet {
    bundles: Vec<TransportBundle>,
    /// The id the next transport gets: ids are never reused.
    next: usize,
    /// The transport of each m= section that has been given one; a mid that is not here is
    /// on the default transport.
    by_mid: HashMap<String, TransportId>,
    /// The first transport: the BUNDLE transport while every section is bundled, and what
    /// the single-transport accessors (`ice_transport()`, `dtls_transport()`) return.
    default: TransportId,
    /// The transport the SCTP association runs over.
    data: TransportId,
    /// The transport the pipeline's ICE, DTLS and SRTP handlers act on: the default one,
    /// except while a datagram routed to another is read.
    active: TransportId,
}

fn agent_of(bundle: &TransportBundle) -> &ice::Agent {
    &bundle.ice_handler_context.ice_transport.agent
}

impl TransportSet {
    /// A set holding `first` as its only, default transport.
    pub(crate) fn new(
        ice_handler_context: IceHandlerContext,
        dtls_handler_context: DtlsHandlerContext,
        srtp_handler_context: SrtpHandlerContext,
    ) -> Self {
        let id = TransportId(0);
        Self {
            bundles: vec![TransportBundle {
                id,
                ice_handler_context,
                dtls_handler_context,
                srtp_handler_context,
                announced: TransportAnnounced::default(),
            }],
            next: 1,
            by_mid: HashMap::new(),
            default: id,
            data: id,
            active: id,
        }
    }

    fn index(&self, id: TransportId) -> Option<usize> {
        self.bundles.iter().position(|bundle| bundle.id == id)
    }

    /// The default transport.
    pub(crate) fn default(&self) -> &TransportBundle {
        self.transport(self.default)
            .expect("the default transport is in the set")
    }

    /// The default transport, mutably.
    pub(crate) fn default_mut(&mut self) -> &mut TransportBundle {
        let id = self.default;
        self.transport_mut(id)
            .expect("the default transport is in the set")
    }

    /// The transport `id` names, if it is in the set.
    pub(crate) fn transport(&self, id: TransportId) -> Option<&TransportBundle> {
        self.index(id).map(|index| &self.bundles[index])
    }

    /// The transport `id` names, mutably, if it is in the set.
    pub(crate) fn transport_mut(&mut self, id: TransportId) -> Option<&mut TransportBundle> {
        self.index(id).map(move |index| &mut self.bundles[index])
    }

    /// The id of the transport the m= section `mid` uses.
    pub(crate) fn transport_id_for(&self, mid: &str) -> TransportId {
        self.by_mid
            .get(mid)
            .copied()
            .filter(|id| self.index(*id).is_some())
            .unwrap_or(self.default)
    }

    /// The transport the m= section `mid` uses.
    pub(crate) fn transport_for(&self, mid: &str) -> &TransportBundle {
        let id = self.transport_id_for(mid);
        self.transport(id).unwrap_or_else(|| self.default())
    }

    /// The transport the m= section `mid` uses, mutably.
    pub(crate) fn transport_for_mut(&mut self, mid: &str) -> &mut TransportBundle {
        let id = self.transport_id_for(mid);
        let id = if self.index(id).is_some() {
            id
        } else {
            self.default
        };
        self.transport_mut(id)
            .expect("the default transport is in the set")
    }

    /// Puts the m= section `mid` on the transport `id`.
    pub(crate) fn assign(&mut self, mid: &str, id: TransportId) {
        self.by_mid.insert(mid.to_owned(), id);
    }

    /// Takes the m= section `mid` off its transport: it is on the default one again.
    pub(crate) fn unassign(&mut self, mid: &str) {
        self.by_mid.remove(mid);
    }

    /// The id of the transport the SCTP association runs over.
    pub(crate) fn data_transport_id(&self) -> TransportId {
        self.data
    }

    /// The transport the SCTP association runs over.
    pub(crate) fn data_transport(&self) -> &TransportBundle {
        self.transport(self.data).unwrap_or_else(|| self.default())
    }

    /// The transport the pipeline's ICE, DTLS and SRTP handlers act on.
    pub(crate) fn active_mut(&mut self) -> &mut TransportBundle {
        let id = if self.index(self.active).is_some() {
            self.active
        } else {
            self.default
        };
        self.transport_mut(id)
            .expect("the default transport is in the set")
    }

    /// Has the pipeline's handlers act on `id` (the default transport when `id` is not in the
    /// set) until [`Self::reset_active`].
    pub(crate) fn set_active(&mut self, id: TransportId) {
        self.active = if self.index(id).is_some() {
            id
        } else {
            self.default
        };
    }

    /// Has the pipeline's handlers act on the default transport again.
    pub(crate) fn reset_active(&mut self) {
        self.active = self.default;
    }

    /// The transport a datagram belongs to, by the local address the driver reports it with:
    /// the transport one of whose local candidates has that address (or that base). With one
    /// transport, or for an address no transport gathered on, the default transport.
    ///
    /// Each transport normally has a local address of its own (RFC 9429 section 5.2.1 gives
    /// every transport its own candidates). A driver that shares one port between transports
    /// (`rtc-stream-driver`'s shared UDP or ICE-TCP port) gives several transports the same
    /// address: then a Binding request names its transport by the receiver's ufrag of its
    /// USERNAME (RFC 8445 section 7.2.2), and anything else goes to the transport that knows
    /// the sender as a remote candidate (a check from it has made it a peer-reflexive one if
    /// it was not signalled). Two transports on one 5-tuple cannot be told apart once DTLS
    /// runs on both: the default transport takes what is left.
    pub(crate) fn route(&self, transport: &TransportContext, datagram: &[u8]) -> TransportId {
        self.route_datagram(transport, datagram, Direction::Inbound)
    }

    /// The transport a datagram the connection is about to send from `transport.local_addr`
    /// belongs to: as [`Self::route`], with the sender's ufrag of a Binding request's
    /// USERNAME (this side's) naming it.
    pub(crate) fn route_outbound(
        &self,
        transport: &TransportContext,
        datagram: &[u8],
    ) -> TransportId {
        self.route_datagram(transport, datagram, Direction::Outbound)
    }

    /// The transport a datagram on a connection that names none yet belongs to, only when
    /// that is certain: one transport, an address only one transport gathered on, or a
    /// Binding request whose USERNAME names one (RFC 8445 section 7.2.2). `None` where
    /// [`Self::route`] would guess from the peer's address, which two transports may both
    /// know (two of this side's active ICE-TCP candidates to one remote candidate).
    pub(crate) fn route_named(
        &self,
        transport: &TransportContext,
        datagram: &[u8],
    ) -> Option<TransportId> {
        match self.route_with_certainty(transport, datagram, Direction::Inbound) {
            (id, true) => Some(id),
            (_, false) => None,
        }
    }

    fn route_datagram(
        &self,
        transport: &TransportContext,
        datagram: &[u8],
        direction: Direction,
    ) -> TransportId {
        self.route_with_certainty(transport, datagram, direction).0
    }

    /// The transport, and whether the datagram's address or USERNAME named it (`false`: it
    /// was chosen by the peer's address or as the default).
    fn route_with_certainty(
        &self,
        transport: &TransportContext,
        datagram: &[u8],
        direction: Direction,
    ) -> (TransportId, bool) {
        if self.bundles.len() == 1 {
            return (self.default, true);
        }
        let local = transport.local_addr;
        let on: Vec<&TransportBundle> = self
            .bundles
            .iter()
            .filter(|bundle| {
                agent_of(bundle)
                    .get_local_candidates()
                    .iter()
                    .any(|candidate| candidate.addr() == local || candidate.base_addr() == local)
            })
            .collect();
        match on.as_slice() {
            [] => return (self.default, false),
            [only] => return (only.id, true),
            _ => {}
        }
        if let Some((receiver, sender)) = binding_request_ufrags(datagram) {
            let ours = match direction {
                Direction::Inbound => receiver,
                Direction::Outbound => sender,
            };
            if let Some(bundle) = on
                .iter()
                .find(|bundle| agent_of(bundle).get_local_credentials().ufrag == ours)
            {
                return (bundle.id, true);
            }
        }
        let peer = transport.peer_addr;
        if let Some(bundle) = on.iter().find(|bundle| {
            agent_of(bundle)
                .get_remote_candidates()
                .iter()
                .any(|candidate| candidate.addr() == peer)
        }) {
            return (bundle.id, false);
        }
        // The default transport first: an address several transports gathered on is its.
        let id = on
            .iter()
            .find(|bundle| bundle.id == self.default)
            .unwrap_or(&on[0])
            .id;
        (id, false)
    }

    /// Every transport, in the order they were created.
    pub(crate) fn iter_mut(&mut self) -> impl Iterator<Item = &mut TransportBundle> {
        self.bundles.iter_mut()
    }

    /// How many transports the set holds: at least one.
    pub(crate) fn len(&self) -> usize {
        self.bundles.len()
    }

    /// Adds a transport; it carries no m= section until one is assigned to it.
    pub(crate) fn insert(
        &mut self,
        ice_handler_context: IceHandlerContext,
        dtls_handler_context: DtlsHandlerContext,
        srtp_handler_context: SrtpHandlerContext,
    ) -> TransportId {
        let id = TransportId(self.next);
        self.next += 1;
        self.bundles.push(TransportBundle {
            id,
            ice_handler_context,
            dtls_handler_context,
            srtp_handler_context,
            announced: TransportAnnounced::default(),
        });
        id
    }

    /// Takes the transport `id` out of the set, with the m= sections assigned to it, and
    /// returns it. The last transport is never removed; when the default or the data
    /// transport goes, the first remaining one takes its place.
    pub(crate) fn remove(&mut self, id: TransportId) -> Option<TransportBundle> {
        if self.bundles.len() == 1 {
            return None;
        }
        let index = self.index(id)?;
        let bundle = self.bundles.remove(index);
        self.by_mid.retain(|_, on| *on != id);
        let first = self.bundles[0].id;
        if self.default == id {
            self.default = first;
        }
        if self.data == id {
            self.data = first;
        }
        if self.active == id {
            self.active = self.default;
        }
        Some(bundle)
    }

    /// The ids of every transport, in the order they were created.
    pub(crate) fn ids(&self) -> Vec<TransportId> {
        self.bundles.iter().map(|bundle| bundle.id).collect()
    }

    /// The id of the default transport.
    pub(crate) fn default_id(&self) -> TransportId {
        self.default
    }

    /// Makes `id` the default transport, when it is in the set.
    pub(crate) fn set_default(&mut self, id: TransportId) {
        if self.index(id).is_some() {
            self.default = id;
        }
    }

    /// Makes `id` the transport the SCTP association runs over, when it is in the set.
    pub(crate) fn set_data(&mut self, id: TransportId) {
        if self.index(id).is_some() {
            self.data = id;
        }
    }

    /// The transport the m= section `mid` was assigned to, if any.
    pub(crate) fn assignment(&self, mid: &str) -> Option<TransportId> {
        self.by_mid
            .get(mid)
            .copied()
            .filter(|id| self.index(*id).is_some())
    }

    /// The m= sections assigned to `id`.
    pub(crate) fn mids_on(&self, id: TransportId) -> Vec<String> {
        let mut mids: Vec<String> = self
            .by_mid
            .iter()
            .filter(|(_, on)| **on == id)
            .map(|(mid, _)| mid.clone())
            .collect();
        mids.sort();
        mids
    }

    /// The id of the active transport.
    pub(crate) fn active_id(&self) -> TransportId {
        if self.index(self.active).is_some() {
            self.active
        } else {
            self.default
        }
    }

    /// The active transport.
    pub(crate) fn active(&self) -> &TransportBundle {
        self.transport(self.active_id())
            .expect("the active transport is in the set")
    }
}

impl super::PipelineContext {
    /// Has the pipeline's handlers act on transport `id` (the default one when `id` is not in
    /// the set), its statistics included.
    pub(crate) fn activate_transport(&mut self, id: TransportId) {
        self.transports.set_active(id);
        self.sync_transport_stats();
    }

    /// Has the statistics the handlers update be the active transport's.
    pub(crate) fn sync_transport_stats(&mut self) {
        let active = self.transports.active_id();
        self.stats.activate_transport(active.0);
    }

    /// Takes transport `id` out of the set, with its statistics, and returns it.
    pub(crate) fn remove_transport(&mut self, id: TransportId) -> Option<TransportBundle> {
        let bundle = self.transports.remove(id)?;
        self.sync_transport_stats();
        self.stats.retire_transport(id.0);
        Some(bundle)
    }

    /// Tells the statistics which transport each m= section is on.
    pub(crate) fn describe_section_transports(&mut self) {
        let sections: Vec<(String, usize)> = self
            .transports
            .by_mid
            .iter()
            .filter(|(_, id)| self.transports.index(**id).is_some())
            .map(|(mid, id)| (mid.clone(), id.0))
            .collect();
        let default = self.transports.default_id().0;
        self.stats.set_section_transports(&sections, default);
    }
}

/// W3C webrtc-pc 4.3.4 `RTCIceConnectionState`: the aggregate of the ICE transports' states,
/// for a connection that is not closed.
pub(crate) fn aggregate_ice_connection_state(
    states: impl IntoIterator<Item = RTCIceConnectionState> + Clone,
) -> RTCIceConnectionState {
    use RTCIceConnectionState::*;
    let all = |f: &dyn Fn(RTCIceConnectionState) -> bool| states.clone().into_iter().all(f);
    let any = |f: &dyn Fn(RTCIceConnectionState) -> bool| states.clone().into_iter().any(f);
    if any(&|s| s == Failed) {
        // "None of the previous states apply and any RTCIceTransports are in the failed state."
        Failed
    } else if any(&|s| s == Disconnected) {
        // "... any RTCIceTransports are in the disconnected state."
        Disconnected
    } else if all(&|s| matches!(s, New | Closed)) {
        // "... all RTCIceTransports are in the new or closed state, or there are no transports."
        New
    } else if any(&|s| matches!(s, New | Checking)) {
        // "... any RTCIceTransports are in the new or checking state."
        Checking
    } else if all(&|s| matches!(s, Completed | Closed)) {
        // "... all RTCIceTransports are in the completed or closed state."
        Completed
    } else if all(&|s| matches!(s, Connected | Completed | Closed)) {
        // "... all RTCIceTransports are in the connected, completed or closed state."
        Connected
    } else {
        // An `Unspecified` state, which no transport reports.
        states.into_iter().next().unwrap_or(New)
    }
}

/// W3C webrtc-pc 4.3.2 `RTCIceGatheringState`: the aggregate of the ICE transports' gatherer
/// states.
pub(crate) fn aggregate_gathering_state(
    states: impl IntoIterator<Item = RTCIceGatheringState>,
) -> RTCIceGatheringState {
    use RTCIceGatheringState::*;
    let mut states = states.into_iter().peekable();
    if states.peek().is_none() {
        // "... or there are no transports."
        return New;
    }
    let states: Vec<RTCIceGatheringState> = states.collect();
    if states.contains(&Gathering) {
        // "Any of the RTCIceTransports are in the gathering state."
        Gathering
    } else if states.iter().all(|s| *s == Complete) {
        // "At least one RTCIceTransport exists, and all RTCIceTransports are in the complete
        // gathering state."
        Complete
    } else {
        // "Any of the RTCIceTransports are in the new gathering state and none of the
        // transports are in the gathering state."
        New
    }
}

/// W3C webrtc-pc 4.3.3 `RTCPeerConnectionState`: the aggregate of the ICE and DTLS
/// transports' states, for a connection that is not closed. The table reads the
/// connection's `[[IceConnectionState]]` (the 4.3.4 aggregate of the ICE transports) and the
/// DTLS transports' states:
///
/// - "failed": the ICE connection state is "failed", or any DTLS transport is "failed";
/// - "disconnected": the ICE connection state is "disconnected" (whatever the others are);
/// - "new": the ICE connection state is "new" and every DTLS transport "new" or "closed", or
///   there are no transports;
/// - "connected": the ICE connection state is "connected" and every DTLS transport
///   "connected" or "closed";
/// - "connecting" otherwise.
///
/// An ICE connection state of "completed" counts as "connected" here: read literally the
/// table then gives "connecting" for a connection all of whose ICE transports completed,
/// which no browser reports (they say "connected").
pub(crate) fn aggregate_connection_state(
    ice: &[RTCIceConnectionState],
    dtls: &[RTCDtlsTransportState],
) -> RTCPeerConnectionState {
    use RTCDtlsTransportState as Dtls;
    use RTCIceConnectionState as Ice;
    if ice.is_empty() && dtls.is_empty() {
        return RTCPeerConnectionState::New;
    }
    let ice_state = aggregate_ice_connection_state(ice.iter().copied());
    let dtls_all = |f: &dyn Fn(Dtls) -> bool| dtls.iter().all(|s| f(*s));
    if ice_state == Ice::Failed || dtls.contains(&Dtls::Failed) {
        RTCPeerConnectionState::Failed
    } else if ice_state == Ice::Disconnected {
        RTCPeerConnectionState::Disconnected
    } else if ice_state == Ice::New && dtls_all(&|s| matches!(s, Dtls::New | Dtls::Closed)) {
        RTCPeerConnectionState::New
    } else if matches!(ice_state, Ice::Connected | Ice::Completed)
        && dtls_all(&|s| matches!(s, Dtls::Connected | Dtls::Closed))
    {
        RTCPeerConnectionState::Connected
    } else {
        RTCPeerConnectionState::Connecting
    }
}

impl TransportSet {
    /// Every transport's ICE connection state.
    pub(crate) fn ice_connection_states(&self) -> Vec<RTCIceConnectionState> {
        self.bundles
            .iter()
            .map(|bundle| {
                bundle
                    .ice_handler_context
                    .ice_transport
                    .ice_connection_state
            })
            .collect()
    }

    /// Every transport's gatherer state, as announced.
    pub(crate) fn gathering_states(&self) -> Vec<RTCIceGatheringState> {
        self.bundles
            .iter()
            .map(|bundle| bundle.announced.gathering)
            .collect()
    }

    /// Every transport's DTLS state.
    pub(crate) fn dtls_states(&self) -> Vec<RTCDtlsTransportState> {
        self.bundles
            .iter()
            .map(|bundle| bundle.dtls_handler_context.dtls_transport.state())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::peer_connection::RTCPeerConnectionBuilder;
    use std::time::Instant;

    /// What a peer connection is built with: one transport, the default, the data one and the
    /// one every section and datagram goes to.
    #[test]
    fn a_new_connection_has_one_transport_for_everything() {
        let pc = RTCPeerConnectionBuilder::new()
            .build(Instant::now())
            .expect("a default peer connection builds");
        let transports = &pc.pipeline_context.transports;
        assert_eq!(transports.len(), 1);
        let default = transports.default().id;
        assert_eq!(transports.data_transport_id(), default);
        assert_eq!(transports.transport_id_for("0"), default);
        assert_eq!(transports.transport_for("audio").id, default);
        assert_eq!(transports.route(&TransportContext::default(), &[]), default);
        // The single-transport accessors are the default transport's.
        assert_eq!(
            pc.ice_transport().id,
            transports.default().ice_handler_context.ice_transport.id
        );
        assert_eq!(
            pc.dtls_transport().id,
            transports.default().dtls_handler_context.dtls_transport.id
        );
    }

    /// W3C webrtc-pc 5.4: "Creating an RTCRtpTransceiver does not create" DTLS or ICE
    /// transports; descriptions do. Transceivers of every kind leave the connection with its
    /// one transport, under `max-compat` too, until an offer is made.
    #[test]
    fn adding_transceivers_creates_no_transport() {
        use crate::peer_connection::configuration::{RTCBundlePolicy, RTCConfigurationBuilder};
        use crate::rtp_transceiver::rtp_sender::RtpCodecKind;
        let mut media_engine =
            crate::peer_connection::configuration::media_engine::MediaEngine::default();
        media_engine
            .register_default_codecs()
            .expect("the default codecs register");
        let mut pc = RTCPeerConnectionBuilder::new()
            .with_media_engine(media_engine)
            .with_configuration(
                RTCConfigurationBuilder::new()
                    .with_bundle_policy(RTCBundlePolicy::MaxCompat)
                    .build(),
            )
            .build(Instant::now())
            .expect("a peer connection builds");
        for kind in [
            RtpCodecKind::Audio,
            RtpCodecKind::Video,
            RtpCodecKind::Video,
        ] {
            pc.add_transceiver_from_kind(kind, None)
                .expect("a transceiver is added");
        }
        pc.create_data_channel("data", None)
            .expect("a data channel is created");
        assert_eq!(pc.pipeline_context.transports.len(), 1);
        assert_eq!(pc.dtls_transports().len(), 1);
        let offer = pc.create_offer(None).expect("an offer");
        pc.set_local_description(Instant::now(), offer)
            .expect("the offer is applied");
        assert_eq!(
            pc.pipeline_context.transports.len(),
            4,
            "the max-compat offer gives each section a transport"
        );
    }

    /// A mid or id that names no transport of the set falls back to the default transport,
    /// never to nothing.
    #[test]
    fn lookups_of_a_transport_not_in_the_set_give_the_default_one() {
        let mut pc = RTCPeerConnectionBuilder::new()
            .build(Instant::now())
            .expect("a default peer connection builds");
        let transports = &mut pc.pipeline_context.transports;
        let default = transports.default().id;
        let gone = TransportId(7);
        assert!(transports.transport(gone).is_none());
        transports.assign("1", gone);
        assert_eq!(transports.transport_id_for("1"), default);
        assert_eq!(transports.transport_for_mut("1").id, default);
        transports.set_active(gone);
        assert_eq!(transports.active_mut().id, default);
        transports.assign("1", default);
        assert_eq!(transports.transport_id_for("1"), default);
        transports.reset_active();
        assert_eq!(transports.active_mut().id, default);
    }

    /// A transport added beside the first shares its ICE credentials by default (the
    /// browsers' form, which Pion and webrtc-rs 0.17 require) and has its own with
    /// `with_unique_transport_credentials(true)` (RFC 9429 section 5.2.1).
    #[test]
    fn added_transports_share_the_first_ones_credentials_unless_unique() {
        use crate::peer_connection::configuration::setting_engine::SettingEngineBuilder;
        for unique in [false, true] {
            let mut pc = RTCPeerConnectionBuilder::new()
                .with_setting_engine(
                    SettingEngineBuilder::new()
                        .with_unique_transport_credentials(unique)
                        .build(),
                )
                .build(Instant::now())
                .expect("a peer connection builds");
            let default = pc.pipeline_context.transports.default_id();
            let other = pc.add_transport().expect("a second transport");
            let credentials = |id| {
                let c = pc.ice_transport_of(id).agent.get_local_credentials();
                (c.ufrag.clone(), c.pwd.clone())
            };
            let (first, second) = (credentials(default), credentials(other));
            if unique {
                assert_ne!(first.0, second.0);
                assert_ne!(first.1, second.1);
            } else {
                assert_eq!(first, second);
            }
        }
    }

    /// W3C 4.3.4: the connection's ICE state is the aggregate of every transport's, not the
    /// first one's.
    #[test]
    fn the_ice_connection_state_aggregates_every_transport() {
        use RTCIceConnectionState::*;
        let aggregate = |states: &[RTCIceConnectionState]| {
            aggregate_ice_connection_state(states.iter().copied())
        };
        assert_eq!(aggregate(&[Connected, Checking]), Checking);
        assert_eq!(aggregate(&[Connected, Failed]), Failed);
        assert_eq!(aggregate(&[Connected, Disconnected]), Disconnected);
        assert_eq!(aggregate(&[Connected, Completed]), Connected);
        assert_eq!(aggregate(&[Completed, Closed]), Completed);
        assert_eq!(aggregate(&[New, Closed]), New);
        assert_eq!(aggregate(&[Connected, New]), Checking);
        assert_eq!(aggregate(&[]), New);
    }

    const ICE_STATES: [RTCIceConnectionState; 7] = [
        RTCIceConnectionState::New,
        RTCIceConnectionState::Checking,
        RTCIceConnectionState::Connected,
        RTCIceConnectionState::Completed,
        RTCIceConnectionState::Disconnected,
        RTCIceConnectionState::Failed,
        RTCIceConnectionState::Closed,
    ];
    const DTLS_STATES: [RTCDtlsTransportState; 5] = [
        RTCDtlsTransportState::New,
        RTCDtlsTransportState::Connecting,
        RTCDtlsTransportState::Connected,
        RTCDtlsTransportState::Closed,
        RTCDtlsTransportState::Failed,
    ];

    /// The W3C 4.3.4 table row by row, first match wins, as the specification words it.
    fn ice_table(states: &[RTCIceConnectionState]) -> RTCIceConnectionState {
        use RTCIceConnectionState::*;
        let any = |s: &[RTCIceConnectionState]| states.iter().any(|x| s.contains(x));
        let all = |s: &[RTCIceConnectionState]| states.iter().all(|x| s.contains(x));
        if any(&[Failed]) {
            Failed
        } else if any(&[Disconnected]) {
            Disconnected
        } else if all(&[New, Closed]) {
            New
        } else if any(&[New, Checking]) {
            Checking
        } else if all(&[Completed, Closed]) {
            Completed
        } else {
            // "all ... connected, completed or closed": what is left.
            assert!(all(&[Connected, Completed, Closed]));
            Connected
        }
    }

    /// W3C 4.3.4 for every combination of the states of one, two and three ICE transports.
    #[test]
    fn the_ice_connection_state_follows_the_w3c_table_for_every_combination() {
        let mut combinations = 0;
        for a in ICE_STATES {
            assert_eq!(aggregate_ice_connection_state([a]), ice_table(&[a]));
            for b in ICE_STATES {
                assert_eq!(aggregate_ice_connection_state([a, b]), ice_table(&[a, b]));
                for c in ICE_STATES {
                    let states = [a, b, c];
                    assert_eq!(
                        aggregate_ice_connection_state(states),
                        ice_table(&states),
                        "{states:?}"
                    );
                    combinations += 1;
                }
            }
        }
        assert_eq!(combinations, 343);
    }

    /// W3C 4.3.3 for every combination of two transports' ICE and DTLS states: the table read
    /// from the ICE connection state (`ice_table`) and the DTLS states, "completed" counting
    /// as "connected".
    #[test]
    fn the_connection_state_follows_the_w3c_table_for_every_combination() {
        use RTCDtlsTransportState as Dtls;
        use RTCIceConnectionState as Ice;
        use RTCPeerConnectionState as Pc;
        let table = |ice: &[Ice], dtls: &[Dtls]| {
            let ice_state = ice_table(ice);
            let dtls_all = |s: &[Dtls]| dtls.iter().all(|x| s.contains(x));
            if ice_state == Ice::Failed || dtls.contains(&Dtls::Failed) {
                Pc::Failed
            } else if ice_state == Ice::Disconnected {
                Pc::Disconnected
            } else if ice_state == Ice::New && dtls_all(&[Dtls::New, Dtls::Closed]) {
                Pc::New
            } else if matches!(ice_state, Ice::Connected | Ice::Completed)
                && dtls_all(&[Dtls::Connected, Dtls::Closed])
            {
                Pc::Connected
            } else {
                Pc::Connecting
            }
        };
        let mut combinations = 0;
        for ia in ICE_STATES {
            for ib in ICE_STATES {
                for da in DTLS_STATES {
                    for db in DTLS_STATES {
                        let (ice, dtls) = ([ia, ib], [da, db]);
                        assert_eq!(
                            aggregate_connection_state(&ice, &dtls),
                            table(&ice, &dtls),
                            "{ice:?} {dtls:?}"
                        );
                        combinations += 1;
                    }
                }
            }
        }
        assert_eq!(combinations, 1225);
        assert_eq!(aggregate_connection_state(&[], &[]), Pc::New);
    }

    /// The W3C 4.3.3 cases with one transport failing or closing beside a connected one, and
    /// the "disconnected" row, which looks at the ICE connection state only: a transport that
    /// is still checking beside a disconnected one leaves the connection "disconnected".
    #[test]
    fn one_transport_failing_or_closing_beside_a_connected_one() {
        use RTCDtlsTransportState as Dtls;
        use RTCIceConnectionState as Ice;
        use RTCPeerConnectionState as Pc;
        let up = (Ice::Connected, Dtls::Connected);
        let state =
            |other: (Ice, Dtls)| aggregate_connection_state(&[up.0, other.0], &[up.1, other.1]);
        assert_eq!(state((Ice::Failed, Dtls::Connected)), Pc::Failed);
        assert_eq!(state((Ice::Connected, Dtls::Failed)), Pc::Failed);
        assert_eq!(state((Ice::Closed, Dtls::Closed)), Pc::Connected);
        assert_eq!(
            state((Ice::Disconnected, Dtls::Connected)),
            Pc::Disconnected
        );
        assert_eq!(state((Ice::Completed, Dtls::Connected)), Pc::Connected);
        assert_eq!(state((Ice::Checking, Dtls::New)), Pc::Connecting);
        assert_eq!(
            aggregate_connection_state(
                &[Ice::Disconnected, Ice::Checking],
                &[Dtls::Connected, Dtls::New]
            ),
            Pc::Disconnected
        );
    }

    /// W3C 4.3.2: the connection's gathering state is the aggregate of every transport's.
    #[test]
    fn the_gathering_state_aggregates_every_transport() {
        use RTCIceGatheringState::*;
        let aggregate =
            |states: &[RTCIceGatheringState]| aggregate_gathering_state(states.iter().copied());
        assert_eq!(aggregate(&[]), New);
        assert_eq!(aggregate(&[Complete, Gathering]), Gathering);
        assert_eq!(aggregate(&[New, Gathering]), Gathering);
        assert_eq!(aggregate(&[Complete, Complete]), Complete);
        assert_eq!(aggregate(&[Complete, New]), New);
        assert_eq!(aggregate(&[New]), New);
    }

    /// W3C 4.3.3: the connection state is the aggregate of every ICE and DTLS transport's.
    #[test]
    fn the_connection_state_aggregates_every_transport() {
        use RTCDtlsTransportState as Dtls;
        use RTCIceConnectionState as Ice;
        use RTCPeerConnectionState as Pc;
        let connected = [Ice::Connected, Ice::Connected];
        assert_eq!(
            aggregate_connection_state(&connected, &[Dtls::Connected, Dtls::Connecting]),
            Pc::Connecting
        );
        assert_eq!(
            aggregate_connection_state(&connected, &[Dtls::Connected, Dtls::Connected]),
            Pc::Connected
        );
        assert_eq!(
            aggregate_connection_state(&connected, &[Dtls::Connected, Dtls::Failed]),
            Pc::Failed
        );
        assert_eq!(
            aggregate_connection_state(
                &[Ice::Connected, Ice::Checking],
                &[Dtls::Connected, Dtls::New]
            ),
            Pc::Connecting
        );
        assert_eq!(
            aggregate_connection_state(&[Ice::New, Ice::Closed], &[Dtls::New, Dtls::Closed]),
            Pc::New
        );
        assert_eq!(
            aggregate_connection_state(
                &[Ice::Disconnected, Ice::Connected],
                &[Dtls::Connected, Dtls::Connected]
            ),
            Pc::Disconnected
        );
    }

    /// A STUN Binding request with `username` as its USERNAME, and nothing else.
    fn binding_request(username: &str) -> Vec<u8> {
        let mut attribute = vec![0x00, 0x06];
        attribute.extend_from_slice(&(username.len() as u16).to_be_bytes());
        attribute.extend_from_slice(username.as_bytes());
        while attribute.len() % 4 != 0 {
            attribute.push(0);
        }
        let mut message = vec![0x00, 0x01];
        message.extend_from_slice(&(attribute.len() as u16).to_be_bytes());
        message.extend_from_slice(&[0x21, 0x12, 0xa4, 0x42]);
        message.extend_from_slice(&[7; 12]);
        message.extend_from_slice(&attribute);
        message
    }

    /// A driver that shares one port between transports gives them the same local address
    /// (`rtc-stream-driver`'s shared UDP or ICE-TCP port). A Binding request then goes to the
    /// transport whose ufrag it names (RFC 8445 section 7.2.2), on the way in by the
    /// receiver's part and on the way out by the sender's; what follows from a peer goes to
    /// the transport that knows it as a remote candidate; the rest to the default one.
    #[test]
    fn a_port_shared_by_two_transports_is_routed_by_ufrag_then_by_peer() {
        // Routing by ufrag needs credentials per transport; by default they are shared.
        let mut pc = RTCPeerConnectionBuilder::new()
            .with_setting_engine(
                crate::peer_connection::configuration::setting_engine::SettingEngineBuilder::new()
                    .with_unique_transport_credentials(true)
                    .build(),
            )
            .build(Instant::now())
            .expect("a default peer connection builds");
        let default = pc.pipeline_context.transports.default_id();
        let other = pc.add_transport().expect("a second transport");
        let shared = "candidate:1 1 udp 2130706431 10.0.0.1 4000 typ host";
        for id in [default, other] {
            pc.with_transport(id, |pc| {
                let candidate = ice::candidate::unmarshal_candidate(shared).unwrap();
                pc.ice_transport_mut()
                    .add_local_candidate(candidate)
                    .expect("the shared candidate is added")
            });
        }
        let ufrag = |pc: &crate::peer_connection::RTCPeerConnection, id| {
            pc.ice_transport_of(id)
                .agent
                .get_local_credentials()
                .ufrag
                .clone()
        };
        let (ours, theirs) = (ufrag(&pc, other), "peer");
        let peer: std::net::SocketAddr = "10.0.0.2:5000".parse().unwrap();
        let context = TransportContext {
            local_addr: "10.0.0.1:4000".parse().unwrap(),
            peer_addr: peer,
            ..Default::default()
        };
        let transports = &pc.pipeline_context.transports;
        assert_eq!(
            transports.route(&context, &binding_request(&format!("{ours}:{theirs}"))),
            other,
            "a check names the second transport's ufrag"
        );
        assert_eq!(
            transports.route_outbound(&context, &binding_request(&format!("{theirs}:{ours}"))),
            other,
            "a check the second transport sends names it as the sender"
        );
        assert_eq!(
            transports.route(&context, &binding_request(&format!("{theirs}:{ours}"))),
            default,
            "an inbound request is routed by its receiver part only"
        );
        assert_eq!(transports.route(&context, &[0x16, 0xfe, 0xfd]), default);
        // Once the second transport knows the peer, the peer's DTLS goes to it.
        pc.with_transport(other, |pc| {
            let candidate = ice::candidate::unmarshal_candidate(
                "candidate:2 1 udp 2130706431 10.0.0.2 5000 typ host",
            )
            .unwrap();
            pc.ice_transport_mut()
                .add_remote_candidate(candidate)
                .expect("the remote candidate is added")
        });
        assert_eq!(
            pc.pipeline_context
                .transports
                .route(&context, &[0x16, 0xfe, 0xfd]),
            other
        );
        // An address only one transport has is that transport's, whatever it carries.
        let own = TransportContext {
            local_addr: "10.0.0.1:4001".parse().unwrap(),
            ..context
        };
        pc.with_transport(other, |pc| {
            let candidate = ice::candidate::unmarshal_candidate(
                "candidate:3 1 udp 2130706431 10.0.0.1 4001 typ host",
            )
            .unwrap();
            pc.ice_transport_mut()
                .add_local_candidate(candidate)
                .unwrap()
        });
        assert_eq!(
            pc.pipeline_context.transports.route(
                &own,
                &binding_request(&format!("{}:x", ufrag(&pc, default)))
            ),
            other
        );
    }

    /// `route_named` answers only where the address or a check's USERNAME names the
    /// transport: DTLS on an address two transports share, which `route` gives to the
    /// transport that knows the peer, is no one's until a check names it.
    #[test]
    fn only_an_address_or_a_checks_username_names_the_transport_for_certain() {
        let mut pc = RTCPeerConnectionBuilder::new()
            .build(Instant::now())
            .expect("a default peer connection builds");
        let context = TransportContext {
            local_addr: "10.0.0.1:4000".parse().unwrap(),
            peer_addr: "10.0.0.2:5000".parse().unwrap(),
            ..Default::default()
        };
        let dtls = [0x16, 0xfe, 0xfd];
        assert_eq!(
            pc.pipeline_context.transports.route_named(&context, &dtls),
            Some(pc.pipeline_context.transports.default_id()),
            "one transport: everything is its"
        );
        let default = pc.pipeline_context.transports.default_id();
        let other = pc.add_transport().expect("a second transport");
        for id in [default, other] {
            pc.with_transport(id, |pc| {
                let local = ice::candidate::unmarshal_candidate(
                    "candidate:1 1 udp 2130706431 10.0.0.1 4000 typ host",
                )
                .unwrap();
                pc.ice_transport_mut().add_local_candidate(local).unwrap();
                // Both know the peer.
                let remote = ice::candidate::unmarshal_candidate(
                    "candidate:2 1 udp 2130706431 10.0.0.2 5000 typ host",
                )
                .unwrap();
                pc.ice_transport_mut().add_remote_candidate(remote).unwrap()
            });
        }
        let transports = &pc.pipeline_context.transports;
        assert_eq!(transports.route_named(&context, &dtls), None);
        assert_eq!(
            transports.route(&context, &dtls),
            default,
            "route still guesses for the datagram path"
        );
        let ours = pc
            .ice_transport_of(other)
            .agent
            .get_local_credentials()
            .ufrag
            .clone();
        assert_eq!(
            pc.pipeline_context
                .transports
                .route_named(&context, &binding_request(&format!("{ours}:peer"))),
            Some(other)
        );
    }
}
