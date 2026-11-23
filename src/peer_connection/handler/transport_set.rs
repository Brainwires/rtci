//! The transports of one peer connection.
//!
//! RFC 9429 gives every m= section that is not bundled into another one a transport of its
//! own: ICE credentials and candidates, a DTLS association and the SRTP keys it exports
//! (sections 4.1.1, 5.2.1, 5.3.1; RFC 9143 section 7). A [`TransportSet`] holds those
//! transports, each a [`TransportBundle`] keyed by a [`TransportId`], and says which one an
//! m= section, a datagram or the SCTP association uses.
//!
//! Today the set holds exactly one transport, created with the peer connection: every
//! section is bundled onto it, every datagram is routed to it and the SCTP association runs
//! over it, which is what the engine did before the set existed. The lookups are written
//! for several entries so that the handlers and `RTCPeerConnection` reach a transport only
//! through them.

use crate::peer_connection::handler::dtls::DtlsHandlerContext;
use crate::peer_connection::handler::ice::IceHandlerContext;
use crate::peer_connection::handler::srtp::SrtpHandlerContext;
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
    #[allow(dead_code)] // The handlers ask by mid once sections can have transports of their own.
    pub(crate) fn transport_for(&self, mid: &str) -> &TransportBundle {
        let id = self.transport_id_for(mid);
        self.transport(id).unwrap_or_else(|| self.default())
    }

    /// The transport the m= section `mid` uses, mutably.
    #[allow(dead_code)] // The handlers ask by mid once sections can have transports of their own.
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
    #[allow(dead_code)] // Sections get transports of their own from descriptions, next.
    pub(crate) fn assign(&mut self, mid: &str, id: TransportId) {
        self.by_mid.insert(mid.to_owned(), id);
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

    /// The transport a datagram belongs to, by the local address and 5-tuple the driver
    /// reports it with. With one transport that is the one; with several the local candidate
    /// it arrived on decides, and for a socket shared by transports the ICE username of the
    /// binding request that validated the 5-tuple.
    pub(crate) fn route(&self, _transport: &TransportContext) -> TransportId {
        self.default
    }

    /// Every transport, in the order they were created.
    pub(crate) fn iter_mut(&mut self) -> impl Iterator<Item = &mut TransportBundle> {
        self.bundles.iter_mut()
    }

    /// How many transports the set holds: at least one.
    #[allow(dead_code)] // Read once sections can have transports of their own.
    pub(crate) fn len(&self) -> usize {
        self.bundles.len()
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
}
