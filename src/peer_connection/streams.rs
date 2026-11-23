//! The peer connection's stream transports: the ICE-TCP candidates the engine gathers itself
//! and the TCP connections they use (RFC 6544), carried through `rtc_shared::stream`.
//!
//! The application (the *driver*) owns the sockets and nothing else: it listens, connects,
//! accepts, closes, reads and writes when the engine says so ([`RTCPeerConnection::poll_stream_command`],
//! [`RTCPeerConnection::poll_stream_transmit`]) and reports back
//! ([`RTCPeerConnection::handle_stream_event`], [`RTCPeerConnection::handle_stream_accepted`],
//! [`RTCPeerConnection::handle_stream_read`]). The engine gathers the TCP host candidates (a
//! passive and a simultaneous-open one on a listener each, and an active one) for every
//! address of a UDP host candidate the application adds, opens the connections its active and
//! simultaneous-open candidates need, frames every packet with RFC 4571, closes what ICE no
//! longer needs and reports failed connections to the ICE agent.
//!
//! A TCP candidate the application adds itself, and the connections it opens for one, stay the
//! application's (`handle_read` / `poll_write` with `TransportProtocol::TCP`, framed by the
//! application), as before.

use super::RTCPeerConnection;
use crate::peer_connection::state::RTCIceGatheringState;
use bytes::BytesMut;
use ice::TransportError;
use ice::candidate::{CandidateConfig, CandidateType, candidate_host::CandidateHostConfig};
use ice::network_type::NetworkType;
use ice::tcp_type::TcpType;
use log::{debug, trace};
use shared::error::{Error, Result};
use shared::stream::{
    Framing, ListenerId, StreamCommand, StreamConfig, StreamEvent, StreamId, StreamNotice,
    StreamOrigin, StreamState, StreamTable, StreamTransmit,
};
use shared::{TaggedBytesMut, TransportContext, TransportProtocol};
use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};
use std::time::Instant;

/// The stream-table tag of ICE-TCP connections and listeners.
pub(crate) const ICE_TCP: u32 = 1;

/// The port an active TCP candidate is signalled with (RFC 6544 section 4.5).
const ACTIVE_PORT: u16 = 9;

/// What the engine does with TCP by itself. See the `SettingEngineBuilder` methods
/// `with_tcp_candidate_gathering`, `with_tcp_simultaneous_open`,
/// `with_tcp_close_unused_connections` and `with_stream_limits`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StreamSettings {
    /// Gather TCP host candidates for each address of a UDP host candidate (RFC 6544 section
    /// 4.1, browsers' default). On by default.
    pub tcp_candidates: bool,
    /// With them, a simultaneous-open candidate on its own port (RFC 6544 section 5.1). On by
    /// default.
    pub simultaneous_open: bool,
    /// Close every ICE-TCP connection but the selected pair's once ICE has completed (RFC 6544
    /// section 8). On by default.
    pub close_unused_connections: bool,
    /// The stream table's window, queue and connection limits.
    pub limits: StreamConfig,
}

impl Default for StreamSettings {
    fn default() -> Self {
        Self {
            tcp_candidates: true,
            simultaneous_open: true,
            close_unused_connections: true,
            limits: StreamConfig::default(),
        }
    }
}

struct GatherListener {
    id: ListenerId,
    tcp_type: TcpType,
    bound: Option<SocketAddr>,
    failed: bool,
}

/// The TCP candidates of one local address.
struct TcpGather {
    ip: IpAddr,
    listeners: Vec<GatherListener>,
    active_added: bool,
}

impl TcpGather {
    fn pending(&self) -> bool {
        self.listeners
            .iter()
            .any(|l| l.bound.is_none() && !l.failed)
    }
}

/// The peer connection's stream state.
pub(crate) struct EngineStreams {
    pub(crate) settings: StreamSettings,
    pub(crate) table: StreamTable,
    /// The application has used the stream interface: it drives streams.
    driver_seen: bool,
    gathers: Vec<TcpGather>,
    /// Addresses of the active candidates the engine added (port 9).
    active: HashSet<IpAddr>,
    /// Bases of the passive and simultaneous-open candidates the engine added.
    bound: HashSet<SocketAddr>,
    /// Connections an active candidate opened (its ephemeral port is not a candidate's).
    active_connections: HashSet<StreamId>,
    /// Connections that have delivered a message.
    answered: HashSet<StreamId>,
    /// End of gathering was signalled while listeners were still being bound.
    end_of_gathering_deferred: bool,
    /// Writes for an engine candidate that no connection could take.
    pub(crate) unroutable: u64,
}

impl EngineStreams {
    pub(crate) fn new(settings: StreamSettings) -> Self {
        Self {
            settings,
            table: StreamTable::new(settings.limits),
            driver_seen: false,
            gathers: Vec::new(),
            active: HashSet::new(),
            bound: HashSet::new(),
            active_connections: HashSet::new(),
            answered: HashSet::new(),
            end_of_gathering_deferred: false,
            unroutable: 0,
        }
    }

    /// Whether `local` is the base of a TCP candidate the engine gathered.
    fn manages(&self, local: SocketAddr) -> bool {
        (local.port() == ACTIVE_PORT && self.active.contains(&local.ip()))
            || self.bound.contains(&local)
    }

    fn pending_listeners(&self) -> bool {
        self.gathers.iter().any(TcpGather::pending)
    }

    /// The local address the agent knows a connection by: an active candidate's (port 9) for
    /// one it opened, the bound address otherwise.
    fn agent_local(&self, id: StreamId, local: SocketAddr) -> SocketAddr {
        if self.active_connections.contains(&id) {
            SocketAddr::new(local.ip(), ACTIVE_PORT)
        } else {
            local
        }
    }

    /// The connection for a datagram the agent sends from `local` to `remote`.
    fn connection_for(&self, local: SocketAddr, remote: SocketAddr) -> Option<StreamId> {
        let active = local.port() == ACTIVE_PORT && self.active.contains(&local.ip());
        let mut connecting = None;
        for c in self.table.connections() {
            if c.tag != ICE_TCP || c.remote != remote || c.state == StreamState::Closing {
                continue;
            }
            let fits = if active {
                self.active_connections.contains(&c.id) && c.local.ip() == local.ip()
            } else {
                !self.active_connections.contains(&c.id)
                    && (c.local == local || c.requested_local == local)
            };
            if fits {
                if c.state == StreamState::Open {
                    return Some(c.id);
                }
                connecting.get_or_insert(c.id);
            }
        }
        connecting
    }
}

/// RFC 7983's first-byte ranges for what may travel on an ICE-TCP connection: STUN, DTLS,
/// RTP / RTCP. Anything else means the RFC 4571 framing is lost (RFC 4571 section 2).
fn demultiplexable(first: u8) -> bool {
    matches!(first, 0..=3 | 20..=63 | 128..=191)
}

fn tcp_context(local: SocketAddr, peer: SocketAddr) -> TransportContext {
    TransportContext {
        local_addr: local,
        peer_addr: peer,
        transport_protocol: TransportProtocol::TCP,
        ecn: None,
    }
}

impl RTCPeerConnection {
    /// The next thing the driver is to do with a socket: listen for, open, close or reset a
    /// TCP connection. Poll it, as `poll_write`, after each input. See
    /// [`rtc::shared::stream`](shared::stream) for the commands and the module documentation
    /// of `streams` for who owns what.
    pub fn poll_stream_command(&mut self) -> Option<StreamCommand> {
        self.streams.driver_seen = true;
        self.route_stream_writes();
        self.close_unused_tcp_connections();
        self.streams.table.poll_command()
    }

    /// The next bytes to write on one of the engine's connections, after every earlier
    /// transmit of that connection. Report what reached the socket with
    /// [`StreamEvent::Written`]: it is the back-pressure signal.
    pub fn poll_stream_transmit(&mut self) -> Option<StreamTransmit> {
        self.streams.driver_seen = true;
        self.route_stream_writes();
        self.streams.table.poll_transmit()
    }

    /// What the driver did: a listener bound or failed, a connection established or failed,
    /// bytes written, a connection closed or reset.
    ///
    /// # Errors
    ///
    /// An error of a connection's security layer.
    pub fn handle_stream_event(&mut self, now: Instant, event: StreamEvent) -> Result<()> {
        self.streams.driver_seen = true;
        self.pipeline_context.observe(now);
        let result = self.streams.table.handle_event(event);
        self.process_stream_notices(now);
        result
    }

    /// The driver accepted a connection from `remote` on `listener`, arriving on `local`.
    /// Returns the connection's id, or `None` when the engine does not take it: the driver
    /// closes the socket then.
    pub fn handle_stream_accepted(
        &mut self,
        now: Instant,
        listener: ListenerId,
        local: SocketAddr,
        remote: SocketAddr,
    ) -> Option<StreamId> {
        self.streams.driver_seen = true;
        self.pipeline_context.observe(now);
        if self.is_closed() {
            return None;
        }
        let id = self.streams.table.accept(listener, local, remote);
        trace!("accepted {id:?} on {listener} from {remote}");
        id
    }

    /// Bytes the driver read from a connection, in whatever piece the socket gave them.
    ///
    /// # Errors
    ///
    /// [`Error::ErrUnknownStream`]; the connection's stream is not of its framing or its
    /// layer failed (the connection is then reset).
    pub fn handle_stream_read(&mut self, now: Instant, id: StreamId, data: &[u8]) -> Result<()> {
        use sansio::Protocol;
        self.streams.driver_seen = true;
        self.pipeline_context.observe(now);
        let info = self.streams.table.info(id).ok_or(Error::ErrUnknownStream)?;
        let messages = match self.streams.table.read(id, data) {
            Ok(messages) => messages,
            Err(err) => {
                self.process_stream_notices(now);
                return Err(err);
            }
        };
        if info.tag != ICE_TCP {
            return Ok(());
        }
        let local = self.streams.agent_local(id, info.local);
        for message in messages {
            // A null packet (RFC 4571 section 2) carries nothing.
            let Some(&first) = message.first() else {
                continue;
            };
            let transport = tcp_context(local, info.remote);
            if !demultiplexable(first) {
                debug!("{id}: a frame that is neither STUN, DTLS nor RTP: framing lost, reset");
                self.streams.table.reset(id);
                self.ice_transport_mut().agent.handle_transport_error(
                    now,
                    transport,
                    TransportError::NotStun,
                );
                break;
            }
            let first_answer =
                self.streams.answered.insert(id) && info.origin == StreamOrigin::Connected;
            self.handle_read(TaggedBytesMut {
                now,
                transport,
                message: BytesMut::from(&message[..]),
            })?;
            // RFC 6544 section 7.1: on a connection this agent opened, a first answer that is
            // not STUN closes it (the agent has failed the pairs of that remote candidate).
            if first_answer && first > 3 {
                debug!("{id}: the first answer is not STUN, the connection is closed");
                self.streams.table.reset(id);
                break;
            }
        }
        self.process_stream_notices(now);
        Ok(())
    }

    /// The ICE username fragment the peer's checks address this connection by (RFC 8445
    /// section 7.2.2: a Binding request's USERNAME is `<this ufrag>:<the peer's>`). A driver
    /// that shares one UDP port or one ICE-TCP listening port between peer connections routes
    /// by it (`rtc-stream-driver`'s `UfragMux`); read it again after each local description,
    /// since an ICE restart changes it. During a restart the previous one stays in use until
    /// the restart completes.
    pub fn ice_username_fragment(&self) -> String {
        self.ice_transport()
            .agent
            .get_local_credentials()
            .ufrag
            .clone()
    }

    /// Requests the TCP candidates of the address of a UDP host candidate the application just
    /// added (`candidate_value`), or adds them again when they are bound already (a new ICE
    /// generation re-gathering the same addresses).
    pub(crate) fn gather_tcp_candidates(&mut self, candidate_value: &str) {
        if !self.streams.settings.tcp_candidates || self.is_closed() {
            return;
        }
        let Ok(candidate) = ice::candidate::unmarshal_candidate(candidate_value) else {
            return;
        };
        if candidate.candidate_type() != CandidateType::Host || candidate.network_type().is_tcp() {
            return;
        }
        let Ok(ip) = candidate.address().parse::<IpAddr>() else {
            return;
        };
        let accepted = self
            .ice_transport()
            .agent
            .get_local_candidates()
            .iter()
            .any(|c| c.addr() == candidate.addr() && !c.network_type().is_tcp());
        let network = if ip.is_ipv4() {
            NetworkType::Tcp4
        } else {
            NetworkType::Tcp6
        };
        let types = &self.setting_engine.candidates.ice_network_types;
        if !accepted || (!types.is_empty() && !types.contains(&network)) {
            return;
        }
        if let Some(gather) = self.streams.gathers.iter().find(|g| g.ip == ip) {
            let bound: Vec<(SocketAddr, TcpType)> = gather
                .listeners
                .iter()
                .filter_map(|l| l.bound.map(|a| (a, l.tcp_type)))
                .collect();
            let active = gather.active_added;
            for (addr, tcp_type) in bound {
                self.add_engine_tcp_candidate(addr, tcp_type);
            }
            if active {
                self.add_engine_tcp_candidate(SocketAddr::new(ip, ACTIVE_PORT), TcpType::Active);
            }
            return;
        }
        let any = SocketAddr::new(ip, 0);
        let mut listeners = vec![GatherListener {
            id: self
                .streams
                .table
                .listen(any, Framing::Rfc4571, ICE_TCP, false),
            tcp_type: TcpType::Passive,
            bound: None,
            failed: false,
        }];
        if self.streams.settings.simultaneous_open {
            listeners.push(GatherListener {
                id: self
                    .streams
                    .table
                    .listen(any, Framing::Rfc4571, ICE_TCP, true),
                tcp_type: TcpType::SimultaneousOpen,
                bound: None,
                failed: false,
            });
        }
        self.streams.gathers.push(TcpGather {
            ip,
            listeners,
            active_added: false,
        });
    }

    /// The end-of-gathering sentinel: held back while the engine's listeners are being bound
    /// for a driver that serves them, so their candidates are not refused (RFC 8838 section
    /// 13); given at once otherwise.
    pub(crate) fn finish_local_gathering_after_streams(&mut self) {
        if self.streams.driver_seen && self.streams.pending_listeners() {
            self.streams.end_of_gathering_deferred = true;
        } else {
            self.finish_local_gathering();
        }
    }

    fn add_engine_tcp_candidate(&mut self, addr: SocketAddr, tcp_type: TcpType) {
        let candidate = CandidateHostConfig {
            base_config: CandidateConfig {
                network: "tcp".to_owned(),
                address: addr.ip().to_string(),
                port: addr.port(),
                component: 1,
                ..Default::default()
            },
            tcp_type,
        }
        .new_candidate_host();
        let value = candidate
            .and_then(|c| crate::peer_connection::transport::RTCIceCandidate::from(&c).to_json())
            .map(|init| {
                init.candidate
                    .strip_prefix("candidate:")
                    .unwrap_or(&init.candidate)
                    .to_owned()
            });
        let value = match value {
            Ok(value) => value,
            Err(err) => {
                debug!("TCP candidate {addr} not made: {err}");
                return;
            }
        };
        match tcp_type {
            TcpType::Active => {
                self.streams.active.insert(addr.ip());
            }
            _ => {
                self.streams.bound.insert(addr);
            }
        }
        if let Err(err) = self.add_ice_local_candidate(&value, None, None) {
            debug!("TCP candidate {addr} not added: {err}");
        }
    }

    fn process_stream_notices(&mut self, now: Instant) {
        while let Some(notice) = self.streams.table.poll_notice() {
            match notice {
                StreamNotice::Listening {
                    listener,
                    tag: ICE_TCP,
                    local,
                } => {
                    let mut add = vec![];
                    if let Some(gather) = self
                        .streams
                        .gathers
                        .iter_mut()
                        .find(|g| g.listeners.iter().any(|l| l.id == listener))
                    {
                        if let Some(l) = gather.listeners.iter_mut().find(|l| l.id == listener) {
                            l.bound = Some(local);
                            add.push((local, l.tcp_type));
                        }
                        if !gather.active_added {
                            gather.active_added = true;
                            add.push((SocketAddr::new(gather.ip, ACTIVE_PORT), TcpType::Active));
                        }
                    }
                    for (addr, tcp_type) in add {
                        self.add_engine_tcp_candidate(addr, tcp_type);
                    }
                }
                StreamNotice::ListenFailed {
                    listener,
                    tag: ICE_TCP,
                    ..
                } => {
                    let mut active = None;
                    if let Some(gather) = self
                        .streams
                        .gathers
                        .iter_mut()
                        .find(|g| g.listeners.iter().any(|l| l.id == listener))
                    {
                        if let Some(l) = gather.listeners.iter_mut().find(|l| l.id == listener) {
                            l.failed = true;
                        }
                        // The active candidate needs no listener.
                        if !gather.active_added {
                            gather.active_added = true;
                            active = Some(SocketAddr::new(gather.ip, ACTIVE_PORT));
                        }
                    }
                    if let Some(addr) = active {
                        self.add_engine_tcp_candidate(addr, TcpType::Active);
                    }
                }
                StreamNotice::ConnectFailed {
                    id,
                    tag: ICE_TCP,
                    local,
                    remote,
                } => {
                    // RFC 6544 section 7.1: the pair's check has failed.
                    let local = self.streams.agent_local(id, local);
                    self.streams.active_connections.remove(&id);
                    debug!("{id} from {local} to {remote} could not be established");
                    self.ice_transport_mut().agent.handle_transport_error(
                        now,
                        tcp_context(local, remote),
                        TransportError::ConnectionFailed,
                    );
                }
                StreamNotice::Closed {
                    id,
                    tag: ICE_TCP,
                    local,
                    remote,
                    reset,
                } => {
                    let local = self.streams.agent_local(id, local);
                    self.streams.active_connections.remove(&id);
                    self.streams.answered.remove(&id);
                    debug!("{id} from {local} to {remote} ended (reset: {reset})");
                    // A check still waiting on it will not be answered there. A valid pair is
                    // left to consent: an active or simultaneous-open side reopens its
                    // connection with the next write (RFC 6544 section 11.1).
                    self.ice_transport_mut().agent.handle_transport_error(
                        now,
                        tcp_context(local, remote),
                        TransportError::ConnectionFailed,
                    );
                }
                _ => {}
            }
        }
        if self.streams.end_of_gathering_deferred && !self.streams.pending_listeners() {
            self.streams.end_of_gathering_deferred = false;
            if self.ice_gathering_state() != RTCIceGatheringState::Complete {
                self.finish_local_gathering();
            }
        }
    }

    /// Moves the queued datagrams for the engine's TCP candidates onto their connections.
    pub(crate) fn route_stream_writes(&mut self) {
        if self.streams.active.is_empty() && self.streams.bound.is_empty() {
            return;
        }
        self.flush_writes();
        let mut kept = std::collections::VecDeque::new();
        while let Some(msg) = self.pipeline_context.write_outs.pop_front() {
            if let Some(msg) = self.route_stream_write(msg) {
                kept.push_back(msg);
            }
        }
        self.pipeline_context.write_outs = kept;
    }

    /// Takes `msg` when it leaves from an engine TCP candidate (and returns `None`), else
    /// returns it for `poll_write`.
    pub(crate) fn route_stream_write(&mut self, msg: TaggedBytesMut) -> Option<TaggedBytesMut> {
        let local = msg.transport.local_addr;
        if msg.transport.transport_protocol != TransportProtocol::TCP
            || !self.streams.manages(local)
        {
            return Some(msg);
        }
        let remote = msg.transport.peer_addr;
        let id = match self.streams.connection_for(local, remote) {
            Some(id) => Some(id),
            None if local.port() == ACTIVE_PORT && self.streams.active.contains(&local.ip()) => {
                // RFC 6544 section 7.1: an active candidate opens its connection from that
                // interface, on an ephemeral port, when its check is sent.
                let id = self.streams.table.connect(
                    SocketAddr::new(local.ip(), 0),
                    remote,
                    Framing::Rfc4571,
                    ICE_TCP,
                    false,
                    None,
                );
                if let Ok(id) = id {
                    self.streams.active_connections.insert(id);
                }
                id.ok()
            }
            None if self
                .streams
                .gathers
                .iter()
                .flat_map(|g| g.listeners.iter())
                .any(|l| l.tcp_type == TcpType::SimultaneousOpen && l.bound == Some(local)) =>
            {
                // A simultaneous-open candidate connects from its own port (RFC 6544
                // section 7.1), beside its listener.
                self.streams
                    .table
                    .connect(local, remote, Framing::Rfc4571, ICE_TCP, true, None)
                    .ok()
            }
            // A passive candidate only answers on connections it accepted.
            None => None,
        };
        let sent =
            id.is_some_and(|id| matches!(self.streams.table.send(id, &msg.message), Ok(true)));
        if !sent {
            self.streams.unroutable += 1;
            trace!("no TCP connection takes a datagram from {local} to {remote}");
        }
        None
    }

    /// RFC 6544 section 8: once ICE has completed, the connections that do not carry the
    /// selected pair are closed.
    fn close_unused_tcp_connections(&mut self) {
        if !self.streams.settings.close_unused_connections || self.is_closed() {
            return;
        }
        let agent = &self.ice_transport().agent;
        // Completed: a pair is selected (RFC 8445 section 6.1.2.1), and the agent has not failed.
        if agent.get_selected_candidate_pair().is_none()
            || agent.state() == ice::state::ConnectionState::Failed
        {
            return;
        }
        let Some(path) = agent.media_path() else {
            return;
        };
        let keep = if path.transport_protocol == TransportProtocol::TCP {
            // The selected pair's connection is gone: the peer may be reopening it (RFC 6544
            // section 11.1), on a connection this side has not tied to the pair yet. Nothing
            // is closed until the pair has one again.
            match self.streams.connection_for(path.local_addr, path.peer_addr) {
                Some(id) => Some(id),
                None => return,
            }
        } else {
            None
        };
        let unused: Vec<StreamId> = self
            .streams
            .table
            .connections()
            .filter(|c| c.tag == ICE_TCP && c.state != StreamState::Closing && Some(c.id) != keep)
            .map(|c| c.id)
            .collect();
        for id in unused {
            debug!("{id} carries no selected pair: closed");
            self.streams.table.close(id);
        }
    }

    /// `close()`: what is queued goes out, then every connection closes and every listener
    /// stops.
    pub(crate) fn close_streams(&mut self) {
        self.route_stream_writes();
        let ids: Vec<StreamId> = self.streams.table.connections().map(|c| c.id).collect();
        for id in ids {
            self.streams.table.close(id);
        }
        let listeners: Vec<ListenerId> = self.streams.table.listeners().map(|l| l.0).collect();
        for listener in listeners {
            self.streams.table.stop_listening(listener);
        }
    }
}
