#[cfg(test)]
mod association_flow_test;
#[cfg(test)]
mod endpoint_test;
#[cfg(test)]
mod handshake_failure_test;
#[cfg(test)]
mod handshake_loss_test;
#[cfg(test)]
pub(crate) mod link_test;
#[cfg(test)]
mod loss_recovery_test;
#[cfg(test)]
mod sctp_port_test;

use std::{
    collections::HashMap,
    fmt, iter,
    net::SocketAddr,
    ops::{Index, IndexMut},
    sync::Arc,
    sync::atomic::{AtomicBool, Ordering},
    time::Instant,
};

use rustc_hash::FxHashMap;

use crate::Payload;
use crate::association::Association;
use crate::chunk::chunk_type::CT_INIT;
use crate::config::{ClientConfig, EndpointConfig, ServerConfig, TransportConfig};
use crate::packet::PartialDecode;
use crate::shared::{
    AssociationEvent, AssociationEventInner, AssociationId, EndpointEvent, EndpointEventInner,
};
use crate::util::{AssociationIdGenerator, RandomAssociationIdGenerator};
use shared::{EcnCodepoint, TransportContext, TransportMessage, TransportProtocol};

use bytes::Bytes;
use log::{debug, trace, warn};
use slab::Slab;
use thiserror::Error;

/// The main entry point to the library
///
/// This object performs no I/O whatsoever. Instead, it generates a stream of packets to send via
/// `poll_transmit`, and consumes incoming packets and association-generated events via `handle` and
/// `handle_event`.
pub struct Endpoint {
    local_addr: SocketAddr,
    transport_protocol: TransportProtocol,
    /// Identifies associations based on the INIT Dst AID the peer utilized
    ///
    /// Uses a standard `HashMap` to protect against hash collision attacks:
    /// keys are remote-chosen initiate-tags.
    association_ids_init: HashMap<AssociationId, AssociationHandle>,
    /// Identifies associations based on locally created CIDs
    ///
    /// Uses a cheaper hash function since keys are locally created
    association_ids: FxHashMap<AssociationId, AssociationHandle>,
    /// Identifies associations by the peer's address and the two SCTP ports, which is what an
    /// association is between (RFC 9260 1.3). An INIT with an Initiate Tag not seen before
    /// finds the association it is for here.
    ///
    /// A standard `HashMap`: the keys are the peer's.
    association_peers: HashMap<PeerKey, AssociationHandle>,

    associations: Slab<AssociationMeta>,
    /// Associations that have not ended: what `concurrent_associations` bounds. An ended
    /// association may keep its entry in `associations` until its owner reports it drained.
    live: usize,
    local_cid_generator: Box<dyn AssociationIdGenerator>,
    endpoint_config: Arc<EndpointConfig>,
    server_config: Option<Arc<ServerConfig>>,
    /// Whether incoming associations should be unconditionally rejected by a server
    ///
    /// Equivalent to a `ServerConfig.accept_buffer` of `0`, but can be changed after the endpoint is constructed.
    reject_new_associations: bool,
}

impl fmt::Debug for Endpoint {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt.debug_struct("Endpoint<T>")
            .field("association_ids_initial", &self.association_ids_init)
            .field("association_ids", &self.association_ids)
            .field("associations", &self.associations)
            .field("config", &self.endpoint_config)
            .field("server_config", &self.server_config)
            .field("reject_new_associations", &self.reject_new_associations)
            .finish()
    }
}

impl Endpoint {
    /// Create a new endpoint
    ///
    /// Returns `Err` if the configuration is invalid.
    pub fn new(
        local_addr: SocketAddr,
        transport_protocol: TransportProtocol,
        endpoint_config: Arc<EndpointConfig>,
        server_config: Option<Arc<ServerConfig>>,
    ) -> Self {
        Self {
            local_addr,
            transport_protocol,
            association_ids_init: HashMap::default(),
            association_ids: FxHashMap::default(),
            association_peers: HashMap::default(),
            associations: Slab::new(),
            live: 0,
            local_cid_generator: (endpoint_config.aid_generator_factory.as_ref())(),
            reject_new_associations: false,
            endpoint_config,
            server_config,
        }
    }

    /// Replace the server configuration, affecting new incoming associations only
    pub fn set_server_config(&mut self, server_config: Option<Arc<ServerConfig>>) {
        self.server_config = server_config;
    }

    /// Process `EndpointEvent`s emitted from related `Association`s
    pub fn handle_event(&mut self, ch: AssociationHandle, event: EndpointEvent) {
        match event.0 {
            EndpointEventInner::Drained => {
                // A handle the endpoint does not hold (reported twice, or never its own) is
                // ignored: removing a vacant entry panics.
                self.release(ch);
                self.associations.try_remove(ch.0);
            }
        }
    }

    /// Stops routing to an association and frees its place under `concurrent_associations`.
    /// Its entry stays, so the handle is not given to another association while the owner
    /// may still report this one drained.
    fn release(&mut self, ch: AssociationHandle) {
        let Some(meta) = self.associations.get_mut(ch.0) else {
            return;
        };
        if meta.released {
            return;
        }
        meta.released = true;
        self.live = self.live.saturating_sub(1);
        // Only the accepting side registers its peer's Initiate Tag, and another
        // association may have registered the same tag since: remove only our own.
        if self.association_ids_init.get(&meta.init_cid) == Some(&ch) {
            self.association_ids_init.remove(&meta.init_cid);
        }
        if self.association_peers.get(&meta.peer) == Some(&ch) {
            self.association_peers.remove(&meta.peer);
        }
        for cid in meta.loc_cids.values() {
            self.association_ids.remove(cid);
        }
    }

    /// Whether the association behind `ch` has ended (RFC 9260 9.1: it is then removed from
    /// the record). Releases it if so.
    fn release_if_ended(&mut self, ch: AssociationHandle) -> bool {
        let ended = self
            .associations
            .get(ch.0)
            .is_none_or(|meta| meta.ended.load(Ordering::Relaxed));
        if ended {
            self.release(ch);
        }
        ended
    }

    /// Releases every association that has ended. Linear in the associations held, so it runs
    /// only when the endpoint would otherwise refuse a new one.
    fn release_ended(&mut self) {
        let ended: Vec<AssociationHandle> = self
            .associations
            .iter()
            .filter(|(_, meta)| !meta.released && meta.ended.load(Ordering::Relaxed))
            .map(|(id, _)| AssociationHandle(id))
            .collect();
        for ch in ended {
            self.release(ch);
        }
    }

    /// The association an INIT without a known Initiate Tag is for: the one between the same
    /// peer address and ports. An endpoint that holds a single association and can take no
    /// other (SCTP over one DTLS transport, RFC 8261) takes any INIT between the same ports as
    /// its peer's: the address is the DTLS transport's affair and may have changed under it.
    fn association_for_init(
        &self,
        remote: SocketAddr,
        ports: (u16, u16),
    ) -> Option<AssociationHandle> {
        if let Some(ch) = self.association_peers.get(&(remote, ports.0, ports.1)) {
            return Some(*ch);
        }
        let single = self
            .server_config
            .as_ref()
            .is_some_and(|config| config.concurrent_associations == 1);
        if single && self.live == 1 {
            return self
                .associations
                .iter()
                .find(|(_, meta)| !meta.released && (meta.peer.1, meta.peer.2) == ports)
                .map(|(id, _)| AssociationHandle(id));
        }
        None
    }

    /// Process an incoming UDP datagram
    pub fn handle(
        &mut self,
        now: Instant,
        remote: SocketAddr,
        ecn: Option<EcnCodepoint>,
        data: Bytes,
    ) -> Option<(AssociationHandle, DatagramEvent)> {
        let partial_decode = match PartialDecode::unmarshal(&data) {
            Ok(x) => x,
            Err(err) => {
                trace!("malformed header: {}", err);
                return None;
            }
        };

        //
        // Handle packet on existing association, if any
        //
        let dst_cid = partial_decode.common_header.verification_tag;
        let known_ch = if dst_cid > 0 {
            self.association_ids.get(&dst_cid).cloned()
        } else {
            // INIT packets arrive with verification_tag=0 (per RFC 4960 §8.5.1).
            // Full DoS hardening would require per-source-address rate limiting or
            // stateless cookie exchange (RFC 4960 §5.1.3); the global
            // server_config.concurrent_associations limit enforced during
            // first-packet handling provides coarse-grained protection in the
            // meantime.
            //
            // An INIT the peer sends again (its INIT ACK was lost, RFC 9260 5.1 C) carries the
            // Initiate Tag of the first one, and belongs to the association that INIT started:
            // that association answers it with the same INIT ACK. Treated as the first packet
            // of another association instead, it is refused by an endpoint that holds one
            // association at a time, and the handshake can never complete.
            //
            // An INIT with another Initiate Tag from a peer this endpoint has an association
            // with belongs to that association too (RFC 9260 5.2.1, 5.2.2: the association
            // answers an unexpected INIT). A peer that starts over before its COOKIE ECHO
            // would otherwise be refused for as long as the half-open association lasts.
            if partial_decode.first_chunk_type == CT_INIT {
                let ports = (
                    partial_decode.common_header.source_port,
                    partial_decode.common_header.destination_port,
                );
                partial_decode
                    .initiate_tag
                    .and_then(|initiate_tag| self.association_ids_init.get(&initiate_tag))
                    .copied()
                    .or_else(|| self.association_for_init(remote, ports))
            } else {
                None
            }
        };
        // An association that has ended takes no more packets (RFC 9260 9.1).
        let known_ch = known_ch.filter(|ch| !self.release_if_ended(*ch));

        if let Some(ch) = known_ch {
            return Some((
                ch,
                DatagramEvent::AssociationEvent(AssociationEvent(AssociationEventInner::Datagram(
                    TransportMessage {
                        now,
                        transport: TransportContext {
                            local_addr: self.local_addr,
                            peer_addr: remote,
                            ecn,
                            transport_protocol: self.transport_protocol,
                        },
                        message: Payload::PartialDecode(partial_decode),
                    },
                ))),
            ));
        }

        //
        // Potentially create a new association
        //
        self.handle_first_packet(now, remote, ecn, partial_decode)
            .map(|(ch, a)| (ch, DatagramEvent::NewAssociation(a)))
    }

    /// Initiate an Association
    pub fn connect(
        &mut self,
        now: Instant,
        config: ClientConfig,
        remote: SocketAddr,
    ) -> Result<(AssociationHandle, Association), ConnectError> {
        if self.is_full() {
            return Err(ConnectError::TooManyAssociations);
        }
        if remote.port() == 0 {
            return Err(ConnectError::InvalidRemoteAddress(remote));
        }

        let remote_aid = RandomAssociationIdGenerator::new().generate_aid();
        let local_aid = self.new_aid();

        let ports = (
            config.transport.remote_sctp_port(),
            config.transport.sctp_port(),
        );
        let (ch, conn) = self.add_association(
            remote_aid,
            local_aid,
            remote,
            ports,
            now,
            None,
            config.transport,
        );
        Ok((ch, conn))
    }

    fn new_aid(&mut self) -> AssociationId {
        loop {
            let aid = self.local_cid_generator.generate_aid();
            if !self.association_ids.contains_key(&aid) {
                break aid;
            }
        }
    }

    fn handle_first_packet(
        &mut self,
        now: Instant,
        remote: SocketAddr,
        ecn: Option<EcnCodepoint>,
        partial_decode: PartialDecode,
    ) -> Option<(AssociationHandle, Association)> {
        if partial_decode.first_chunk_type != CT_INIT
            || (partial_decode.first_chunk_type == CT_INIT && partial_decode.initiate_tag.is_none())
        {
            debug!("refusing first packet with Non-INIT or empty initial_tag INIT");
            return None;
        }

        let server_config = if let Some(server_config) = self.server_config.as_ref() {
            server_config
        } else {
            warn!("refusing first packet due to empty server_config");
            return None;
        };

        let limit = server_config.concurrent_associations as usize;
        if self.live >= limit {
            // An association that ended has given its place back.
            self.release_ended();
        }
        let server_config = self.server_config.as_ref()?;
        if self.live >= limit || self.reject_new_associations || self.is_full() {
            debug!("refusing association");
            //TODO: self.initial_close();
            return None;
        }

        let server_config = server_config.clone();
        let transport_config = server_config.transport.clone();

        // The guard above (line ~214) already rejects packets with initiate_tag==None,
        // but use `?`-style early return here so the safety invariant is compiler-verified.
        let Some(initiate_tag) = partial_decode.initiate_tag.as_ref() else {
            debug!("refusing INIT with empty initiate_tag (should have been caught above)");
            return None;
        };
        let remote_aid = *initiate_tag;
        let local_aid = self.new_aid();

        let ports = (
            partial_decode.common_header.source_port,
            partial_decode.common_header.destination_port,
        );
        let (ch, mut conn) = self.add_association(
            remote_aid,
            local_aid,
            remote,
            ports,
            now,
            Some(server_config),
            transport_config,
        );
        // Where a retransmission of this INIT is routed (see `handle`).
        self.association_ids_init.insert(remote_aid, ch);

        conn.handle_event(AssociationEvent(AssociationEventInner::Datagram(
            TransportMessage {
                now,
                transport: TransportContext {
                    local_addr: self.local_addr,
                    peer_addr: remote,
                    ecn,
                    transport_protocol: self.transport_protocol,
                },
                message: Payload::PartialDecode(partial_decode),
            },
        )));

        Some((ch, conn))
    }

    #[allow(clippy::too_many_arguments)]
    fn add_association(
        &mut self,
        remote_aid: AssociationId,
        local_aid: AssociationId,
        remote_addr: SocketAddr,
        ports: (u16, u16),
        now: Instant,
        server_config: Option<Arc<ServerConfig>>,
        transport_config: Arc<TransportConfig>,
    ) -> (AssociationHandle, Association) {
        let conn = Association::new(
            server_config,
            transport_config,
            self.endpoint_config.get_max_payload_size(),
            local_aid,
            remote_addr,
            self.local_addr,
            self.transport_protocol,
            now,
        );

        let peer = (remote_addr, ports.0, ports.1);
        let id = self.associations.insert(AssociationMeta {
            init_cid: remote_aid,
            cids_issued: 0,
            loc_cids: iter::once((0, local_aid)).collect(),
            initial_remote: remote_addr,
            peer,
            ended: conn.ended_flag(),
            released: false,
        });
        self.live += 1;

        let ch = AssociationHandle(id);
        self.association_ids.insert(local_aid, ch);
        self.association_peers.insert(peer, ch);

        (ch, conn)
    }

    /// Unconditionally reject future incoming associations
    pub fn reject_new_associations(&mut self) {
        self.reject_new_associations = true;
    }

    /// Access the configuration used by this endpoint
    pub fn endpoint_config(&self) -> &EndpointConfig {
        &self.endpoint_config
    }

    /// Whether we've used up 3/4 of the available AID space
    fn is_full(&self) -> bool {
        (((u32::MAX >> 1) + (u32::MAX >> 2)) as usize) < self.association_ids.len()
    }

    /// How many associations the endpoint routes to: the ones that have not ended.
    #[cfg(test)]
    pub(crate) fn live_associations(&self) -> usize {
        self.live
    }
}

#[derive(Debug)]
pub(crate) struct AssociationMeta {
    init_cid: AssociationId,
    /// Number of local association IDs.
    cids_issued: u64,
    loc_cids: HashMap<u64, AssociationId>,
    /// Remote address the association began with
    ///
    /// Only needed to support associations with zero-length AIDs, which cannot migrate, so we don't
    /// bother keeping it up to date.
    initial_remote: SocketAddr,
    /// The peer's address, its SCTP port and this side's.
    peer: PeerKey,
    /// Set by the association when it ends.
    ended: Arc<AtomicBool>,
    /// No longer routed to nor counted; the entry only keeps the handle from being reused.
    released: bool,
}

/// The peer's address, the peer's SCTP port, this side's SCTP port.
type PeerKey = (SocketAddr, u16, u16);

/// Internal identifier for an `Association` currently associated with an endpoint
#[derive(Default, Debug, Copy, Clone, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub struct AssociationHandle(pub usize);

impl From<AssociationHandle> for usize {
    fn from(x: AssociationHandle) -> usize {
        x.0
    }
}

impl Index<AssociationHandle> for Slab<AssociationMeta> {
    type Output = AssociationMeta;
    fn index(&self, ch: AssociationHandle) -> &AssociationMeta {
        &self[ch.0]
    }
}

impl IndexMut<AssociationHandle> for Slab<AssociationMeta> {
    fn index_mut(&mut self, ch: AssociationHandle) -> &mut AssociationMeta {
        &mut self[ch.0]
    }
}

/// Event resulting from processing a single datagram
#[allow(clippy::large_enum_variant)] // Not passed around extensively
#[non_exhaustive]
pub enum DatagramEvent {
    /// The datagram is redirected to its `Association`
    AssociationEvent(AssociationEvent),
    /// The datagram has resulted in starting a new `Association`
    NewAssociation(Association),
}

/// Errors in the parameters being used to create a new association
///
/// These arise before any I/O has been performed.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ConnectError {
    /// The endpoint can no longer create new associations
    ///
    /// Indicates that a necessary component of the endpoint has been dropped or otherwise disabled.
    #[error("endpoint stopping")]
    EndpointStopping,
    /// The number of active associations on the local endpoint is at the limit
    ///
    /// Try using longer association IDs.
    #[error("too many associations")]
    TooManyAssociations,
    /// The domain name supplied was malformed
    #[error("invalid DNS name: {0}")]
    InvalidDnsName(String),
    /// The remote [`SocketAddr`] supplied was malformed
    ///
    /// Examples include attempting to connect to port 0, or using an inappropriate address family.
    #[error("invalid remote address: {0}")]
    InvalidRemoteAddress(SocketAddr),
    /// No default client configuration was set up
    ///
    /// Use `Endpoint::connect_with` to specify a client configuration.
    #[error("no default client config")]
    NoDefaultClientConfig,
}
