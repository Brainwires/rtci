//! Relayed TCP candidates (RFC 6544 section 5.5 over TURN-TCP, RFC 6062), run by the engine
//! for its `turn:...?transport=tcp` and `turns:` servers.
//!
//! A link with `relay_tcp` asks for a TCP allocation (REQUESTED-TRANSPORT TCP) on a control
//! connection of its own and announces its relayed address twice: as a passive TCP candidate,
//! and on port 9 as an active one (RFC 6544 section 4.5). Each peer connection through the
//! allocation is a data connection to the server: the engine opens it for a ConnectionAttempt
//! the server indicates (a peer reached the passive candidate; RFC 6062 section 4.4), or after
//! a Connect for a check the agent sends from the active candidate (section 4.3), binds it with
//! ConnectionBind and then carries the peer's byte stream over it, framed with RFC 4571 as on
//! any ICE-TCP connection. Permissions for the peers' addresses are created as the agent learns
//! remote candidates, since the server refuses a connection from an address without one
//! (RFC 6062 section 5.3).

use super::*;
use crate::peer_connection::streams::TURN_DATA;
use shared::tcp_framing::TcpFrameDecoder;
use turn::client::data_connection::{DataConnection, DataConnectionEvent};
use turn::client::{AllocateOptions, RelayTransport};
use turn::proto::connid::ConnectionId;

/// Datagrams the agent sends from the active relayed candidate while its data connection is
/// being made.
const MAX_QUEUED: usize = 32;

/// The port of an active TCP candidate (RFC 6544 section 4.5).
const ACTIVE_PORT: u16 = 9;

/// One peer's TCP connection through a TCP allocation.
pub(super) struct DataConn {
    /// The data connection to the server, once asked for.
    stream: Option<StreamId>,
    peer: SocketAddr,
    /// Made for a check from the active candidate (Connect), not for a ConnectionAttempt.
    active: bool,
    connection_id: Option<ConnectionId>,
    conn: Option<DataConnection>,
    decoder: TcpFrameDecoder,
    /// ICE datagrams waiting for the bind.
    queued: Vec<Vec<u8>>,
}

impl DataConn {
    fn new(peer: SocketAddr, active: bool, connection_id: Option<ConnectionId>) -> Self {
        Self {
            stream: None,
            peer,
            active,
            connection_id,
            conn: None,
            decoder: TcpFrameDecoder::new(),
            queued: vec![],
        }
    }

    /// Its data connection to the server, once asked for.
    pub(super) fn stream(&self) -> Option<StreamId> {
        self.stream
    }
}

/// The allocation options of a TCP allocation.
pub(super) fn tcp_allocation() -> AllocateOptions {
    AllocateOptions {
        transport: RelayTransport::Tcp,
        ..Default::default()
    }
}

impl TurnLink {
    /// The address the agent knows its side of `conn` by: the passive candidate's (the
    /// relayed address) or the active one's (its address on port 9).
    fn agent_local(&self, conn: &DataConn) -> Option<SocketAddr> {
        let relay = self.relay?;
        Some(if conn.active {
            SocketAddr::new(relay.ip(), ACTIVE_PORT)
        } else {
            relay
        })
    }
}

impl RTCPeerConnection {
    /// The TCP-allocation link whose relayed candidate `local` is: `(index, active)`.
    fn tcp_relay_of(&self, local: SocketAddr) -> Option<(usize, bool)> {
        self.streams
            .turn
            .links
            .iter()
            .position(|l| {
                l.relay_tcp
                    && l.relay.is_some_and(|r| {
                        r == local || (local.port() == ACTIVE_PORT && r.ip() == local.ip())
                    })
            })
            .map(|i| {
                let relay = self.streams.turn.links[i].relay;
                (i, relay != Some(local))
            })
    }

    /// Takes a TCP datagram the agent sends from a relayed TCP candidate (and returns
    /// `None`), onto the data connection to its peer; returns anything else.
    pub(crate) fn turn_tcp_write(&mut self, msg: TaggedBytesMut) -> Option<TaggedBytesMut> {
        if msg.transport.transport_protocol != TransportProtocol::TCP {
            return Some(msg);
        }
        let Some((index, active)) = self.tcp_relay_of(msg.transport.local_addr) else {
            return Some(msg);
        };
        let now = msg.now.max(self.pipeline_context.now);
        let peer = msg.transport.peer_addr;
        let framed = match Framing::Rfc4571.encode(&msg.message) {
            Ok(framed) => framed,
            Err(err) => {
                debug!("relayed TCP write to {peer}: {err}");
                return None;
            }
        };
        let link = &mut self.streams.turn.links[index];
        if let Some(conn) = link
            .data
            .iter_mut()
            .find(|c| c.peer == peer && c.active == active)
        {
            match conn.conn.as_mut() {
                Some(c) if c.is_bound() => {
                    if let Err(err) = c.send(now, &framed) {
                        debug!("relayed TCP write to {peer}: {err}");
                    }
                }
                _ if conn.queued.len() < MAX_QUEUED => conn.queued.push(framed),
                _ => {}
            }
        } else if active {
            // RFC 6062 section 4.3: Connect, after the permission the server checks.
            if let (Some(relay), Some(client)) = (link.relay, link.client.as_mut())
                && let Ok(mut r) = client.relay(relay)
            {
                if link.permitted.insert(peer.ip()) {
                    let _ = r.create_permission(now, peer);
                }
                match r.connect(now, peer) {
                    Ok(_) => {
                        let mut conn = DataConn::new(peer, true, None);
                        conn.queued.push(framed);
                        link.data.push(conn);
                    }
                    Err(err) => debug!("TURN Connect to {peer}: {err}"),
                }
            }
        }
        // A passive candidate only answers on connections the server announced.
        self.pump_turn_data(now, index);
        self.pump_turn(now);
        None
    }

    /// RFC 6062 section 4.3 / 4.4: the server has a peer connection for `peer` (a Connect
    /// succeeded, or a peer connected to the relayed address): a data connection is opened to
    /// the server for it.
    pub(super) fn turn_tcp_peer_ready(
        &mut self,
        index: usize,
        peer: SocketAddr,
        connection_id: ConnectionId,
        attempt: bool,
    ) {
        let link = &self.streams.turn.links[index];
        let Some(server) = link.server else {
            return;
        };
        let layer: Option<Box<dyn StreamLayer>> = if link.tls() {
            match self
                .streams
                .turn
                .tls_config
                .clone()
                .map(|config| TlsLayer::new(config, &link.url.host))
            {
                Some(Ok(layer)) => Some(Box::new(layer)),
                _ => return,
            }
        } else {
            None
        };
        let link = &mut self.streams.turn.links[index];
        let conn = if attempt {
            link.data
                .push(DataConn::new(peer, false, Some(connection_id)));
            link.data.last_mut()
        } else {
            let found = link
                .data
                .iter_mut()
                .find(|c| c.active && c.peer == peer && c.connection_id.is_none());
            if let Some(c) = found {
                c.connection_id = Some(connection_id);
                Some(c)
            } else {
                None
            }
        };
        let Some(conn) = conn else {
            return;
        };
        match self.streams.table.connect(
            any_of_family(server),
            server,
            Framing::Raw,
            TURN_DATA,
            false,
            layer,
        ) {
            Ok(id) => conn.stream = Some(id),
            Err(err) => debug!("TURN data connection for {peer}: {err}"),
        }
    }

    fn data_conn_of_stream(&self, id: StreamId) -> Option<(usize, usize)> {
        self.streams
            .turn
            .links
            .iter()
            .enumerate()
            .find_map(|(i, l)| {
                l.data
                    .iter()
                    .position(|c| c.stream == Some(id))
                    .map(|j| (i, j))
            })
    }

    /// A data connection to the server is up: the ConnectionBind goes out on it.
    pub(crate) fn turn_data_connected(&mut self, now: Instant, id: StreamId, local: SocketAddr) {
        let Some((index, j)) = self.data_conn_of_stream(id) else {
            return;
        };
        let link = &mut self.streams.turn.links[index];
        let (Some(relay), Some(client)) = (link.relay, link.client.as_mut()) else {
            return;
        };
        let Some(connection_id) = link.data[j].connection_id else {
            return;
        };
        match client
            .relay(relay)
            .and_then(|mut r| r.data_connection(now, connection_id, local))
        {
            Ok(conn) => link.data[j].conn = Some(conn),
            Err(err) => {
                debug!("TURN data connection: {err}");
                self.streams.table.close(id);
                self.streams.turn.links[index].data.remove(j);
                return;
            }
        }
        self.pump_turn_data(now, index);
    }

    /// Bytes read on a data connection: the ConnectionBind response, then the peer's stream.
    pub(crate) fn turn_data_messages(&mut self, now: Instant, id: StreamId, chunks: Vec<Vec<u8>>) {
        let Some((index, j)) = self.data_conn_of_stream(id) else {
            return;
        };
        let Some(info) = self.streams.table.info(id) else {
            return;
        };
        let transport = self.streams.turn.links[index].transport;
        let mut packets = vec![];
        let mut failed = false;
        {
            let link = &mut self.streams.turn.links[index];
            let agent_local = link.agent_local(&link.data[j]);
            let conn = &mut link.data[j];
            if let Some(c) = conn.conn.as_mut() {
                for chunk in chunks {
                    if let Err(err) = c.handle_read(TaggedBytesMut {
                        now,
                        transport: tcp_context(info.local, info.remote),
                        message: BytesMut::from(&chunk[..]),
                    }) {
                        debug!("TURN data connection: {err}");
                    }
                }
                while let Some(event) = c.poll_event() {
                    match event {
                        DataConnectionEvent::Bound => {
                            for framed in std::mem::take(&mut conn.queued) {
                                let _ = c.send(now, &framed);
                            }
                        }
                        DataConnectionEvent::BindError(err) => {
                            debug!("ConnectionBind for {}: {err:?}", conn.peer);
                            failed = true;
                        }
                        _ => {}
                    }
                }
                while let Some(bytes) = c.poll_read() {
                    if conn.decoder.push(&bytes).is_err() {
                        failed = true;
                        break;
                    }
                    while let Some(packet) = conn.decoder.next_packet() {
                        packets.push(packet);
                    }
                }
            }
            if let Some(local) = agent_local {
                for packet in packets {
                    self.pipeline_context.observe(now);
                    let peer = self.streams.turn.links[index].data[j].peer;
                    self.read_on_transport(
                        transport,
                        TaggedBytesMut {
                            now,
                            transport: tcp_context(local, peer),
                            message: BytesMut::from(&packet[..]),
                        },
                    );
                }
            }
        }
        if failed {
            self.streams.table.reset(id);
            self.turn_data_ended(now, id);
            return;
        }
        self.pump_turn_data(now, index);
    }

    /// A data connection could not be made or has ended: the peer's connection is gone, and
    /// the checks waiting on it fail (RFC 6544 section 7.1).
    pub(crate) fn turn_data_ended(&mut self, now: Instant, id: StreamId) {
        let Some((index, j)) = self.data_conn_of_stream(id) else {
            return;
        };
        let link = &mut self.streams.turn.links[index];
        let conn = link.data.remove(j);
        let (transport, local) = (link.transport, link.agent_local(&conn));
        if let Some(local) = local {
            self.with_transport(transport, |pc| {
                pc.ice_transport_mut().agent.handle_transport_error(
                    now,
                    tcp_context(local, conn.peer),
                    ice::TransportError::ConnectionFailed,
                )
            });
        }
    }

    /// Moves what the data connections of link `index` have to send onto their streams.
    pub(super) fn pump_turn_data(&mut self, _now: Instant, index: usize) {
        let link = &mut self.streams.turn.links[index];
        for conn in link.data.iter_mut() {
            let (Some(id), Some(c)) = (conn.stream, conn.conn.as_mut()) else {
                continue;
            };
            while let Some(t) = c.poll_write() {
                let _ = self.streams.table.send(id, &t.message);
            }
        }
    }

    /// A Connect for `peer` failed: its queued checks fail with it (RFC 6544 section 7.1).
    pub(super) fn turn_tcp_connect_failed(&mut self, now: Instant, index: usize, peer: SocketAddr) {
        let link = &mut self.streams.turn.links[index];
        let Some(j) = link
            .data
            .iter()
            .position(|c| c.active && c.peer == peer && c.stream.is_none())
        else {
            return;
        };
        let conn = link.data.remove(j);
        if let Some(local) = link.agent_local(&conn) {
            let transport = link.transport;
            self.with_transport(transport, |pc| {
                pc.ice_transport_mut().agent.handle_transport_error(
                    now,
                    tcp_context(local, conn.peer),
                    ice::TransportError::ConnectionFailed,
                )
            });
        }
    }

    /// RFC 6062 section 5.3: a peer reaches the passive relayed candidate only with a
    /// permission for its address, so one is created for each remote TCP candidate address of
    /// the transport (of the relayed address's family) as the agent learns it.
    pub(crate) fn turn_tcp_permissions(&mut self, now: Instant) {
        for index in 0..self.streams.turn.links.len() {
            let link = &self.streams.turn.links[index];
            let (true, Some(relay), LinkState::Open(_)) = (link.relay_tcp, link.relay, link.state)
            else {
                continue;
            };
            let transport = link.transport;
            // The remote TCP candidates the agent holds, and those it does not keep (active
            // ones, RFC 6544 section 4.5) but that were signalled.
            let remote_description: Vec<IpAddr> = self
                .remote_description()
                .map(|d| d.sdp.clone())
                .unwrap_or_default()
                .lines()
                .filter_map(|l| l.strip_prefix("a=candidate:"))
                .filter_map(|v| ice::candidate::unmarshal_candidate(v).ok())
                .filter(|c| c.network_type().is_tcp())
                .filter_map(|c| c.address().parse::<IpAddr>().ok())
                .collect();
            let ips: Vec<IpAddr> = self
                .ice_transport_of(transport)
                .agent
                .get_remote_candidates()
                .iter()
                .filter(|c| c.network_type().is_tcp())
                .map(|c| c.addr().ip())
                .chain(
                    self.streams
                        .turn
                        .remote_tcp_ips
                        .iter()
                        .filter(|(t, _)| *t == transport)
                        .map(|(_, ip)| *ip),
                )
                .chain(remote_description)
                .filter(|ip| ip.is_ipv4() == relay.is_ipv4())
                .collect();
            let link = &mut self.streams.turn.links[index];
            let Some(client) = link.client.as_mut() else {
                continue;
            };
            for ip in ips {
                if link.permitted.insert(ip)
                    && let Ok(mut r) = client.relay(relay)
                {
                    let _ = r.create_permission(now, SocketAddr::new(ip, 0));
                }
            }
        }
    }

    /// Notes the address of a remote TCP candidate (`candidate_value`) of the active
    /// transport for the permissions of its TCP allocations.
    pub(crate) fn note_remote_tcp_candidate(&mut self, candidate_value: &str) {
        if !self.streams.turn.tcp_relay {
            return;
        }
        let Ok(c) = ice::candidate::unmarshal_candidate(candidate_value) else {
            return;
        };
        if !c.network_type().is_tcp() {
            return;
        }
        let Ok(ip) = c.address().parse::<IpAddr>() else {
            return;
        };
        let on = self.pipeline_context.transports.active_id();
        if !self.streams.turn.remote_tcp_ips.contains(&(on, ip)) {
            self.streams.turn.remote_tcp_ips.push((on, ip));
        }
    }

    /// The data connections' timers (the ConnectionBind's 30 s, RFC 6062 section 4.4).
    pub(super) fn turn_data_poll_timeout(&mut self) -> Option<Instant> {
        self.streams
            .turn
            .links
            .iter_mut()
            .flat_map(|l| l.data.iter_mut())
            .filter_map(|c| c.conn.as_mut().and_then(|c| c.poll_timeout()))
            .min()
    }

    /// Fires the data connections' timers.
    pub(super) fn turn_data_handle_timeout(&mut self, now: Instant) {
        let mut failed = vec![];
        for link in self.streams.turn.links.iter_mut() {
            for conn in link.data.iter_mut() {
                let (Some(id), Some(c)) = (conn.stream, conn.conn.as_mut()) else {
                    continue;
                };
                if c.poll_timeout().is_some_and(|t| t <= now) {
                    let _ = c.handle_timeout(now);
                }
                while let Some(event) = c.poll_event() {
                    if let DataConnectionEvent::BindError(err) = event {
                        debug!("ConnectionBind for {}: {err:?}", conn.peer);
                        failed.push(id);
                    }
                }
            }
        }
        for id in failed {
            self.streams.table.reset(id);
            self.turn_data_ended(now, id);
        }
    }
}
