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
use crate::peer_connection::state::peer_connection_state::RTCPeerConnectionState;
use crate::peer_connection::transport::dtls::state::RTCDtlsTransportState;
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
    /// Each transport needs a local address of its own: RFC 9429 section 5.2.1 gives every
    /// transport its own candidates, and two transports on one 5-tuple cannot be told apart
    /// once DTLS runs on both.
    pub(crate) fn route(&self, transport: &TransportContext) -> TransportId {
        if self.bundles.len() == 1 {
            return self.default;
        }
        let local = transport.local_addr;
        let on = |bundle: &TransportBundle| {
            bundle
                .ice_handler_context
                .ice_transport
                .agent
                .get_local_candidates()
                .iter()
                .any(|candidate| candidate.addr() == local || candidate.base_addr() == local)
        };
        // The default transport first: an address several transports gathered on is its.
        if let Some(default) = self.transport(self.default)
            && on(default)
        {
            return self.default;
        }
        self.bundles
            .iter()
            .find(|bundle| on(bundle))
            .map_or(self.default, |bundle| bundle.id)
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

/// W3C webrtc-pc 4.3.3 `RTCPeerConnectionState`: the aggregate of the ICE and DTLS
/// transports' states, for a connection that is not closed.
pub(crate) fn aggregate_connection_state(
    ice: &[RTCIceConnectionState],
    dtls: &[RTCDtlsTransportState],
) -> RTCPeerConnectionState {
    use RTCDtlsTransportState as Dtls;
    use RTCIceConnectionState as Ice;
    let ice_any = |f: &dyn Fn(Ice) -> bool| ice.iter().any(|s| f(*s));
    let ice_all = |f: &dyn Fn(Ice) -> bool| ice.iter().all(|s| f(*s));
    let dtls_any = |f: &dyn Fn(Dtls) -> bool| dtls.iter().any(|s| f(*s));
    let dtls_all = |f: &dyn Fn(Dtls) -> bool| dtls.iter().all(|s| f(*s));
    if ice_any(&|s| s == Ice::Failed) || dtls_any(&|s| s == Dtls::Failed) {
        // "Any of the RTCIceTransports or RTCDtlsTransports are in a failed state."
        RTCPeerConnectionState::Failed
    } else if ice_any(&|s| s == Ice::Disconnected) && !ice_any(&|s| s == Ice::Checking) {
        // "Any of the RTCIceTransports or RTCDtlsTransports are in the disconnected state and
        // none of them are in the failed or connecting or checking state."
        RTCPeerConnectionState::Disconnected
    } else if ice_all(&|s| matches!(s, Ice::New | Ice::Closed))
        && dtls_all(&|s| matches!(s, Dtls::New | Dtls::Closed))
    {
        // "... all RTCIceTransports are in the new or closed state, and all RTCDtlsTransports
        // are in the new or closed state, or there are no transports."
        RTCPeerConnectionState::New
    } else if ice_any(&|s| matches!(s, Ice::New | Ice::Checking))
        || dtls_any(&|s| matches!(s, Dtls::New | Dtls::Connecting))
    {
        // "... any RTCIceTransport is in the new or checking state or any RTCDtlsTransport is
        // in the new or connecting state."
        RTCPeerConnectionState::Connecting
    } else if ice_all(&|s| matches!(s, Ice::Connected | Ice::Completed | Ice::Closed))
        && dtls_all(&|s| matches!(s, Dtls::Connected | Dtls::Closed))
    {
        // "... all RTCIceTransports are in the connected, completed or closed state and all
        // RTCDtlsTransports are in the connected or closed state."
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
        assert_eq!(transports.route(&TransportContext::default()), default);
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
}
