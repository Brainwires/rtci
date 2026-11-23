//! TURN over TCP and over TLS built into the engine (RFC 8656 section 3.1; `turns:` and
//! `turn:...?transport=tcp` servers of the configuration), through the stream interface.
//!
//! For each such server the engine asks its driver to resolve the name
//! ([`StreamCommand::Resolve`](shared::stream::StreamCommand::Resolve)) unless it is an
//! address, orders the addresses by Happy Eyeballs (RFC 8305) and connects to them staggered
//! by the Connection Attempt Delay, keeping the first that connects. Over TLS (rustls,
//! sans-I/O, ALPN `stun.turn`) it verifies the server with the roots or verifier the
//! application gave. It then runs the TURN client over the connection (TURN's own framing,
//! RFC 8656 section 12.5), allocates, announces the relayed candidate with its
//! `relayProtocol` (`tcp` or `tls`), creates permissions as the agent sends, and relays the
//! agent's datagrams both ways. The relayed transport itself is UDP (RFC 8656).

use super::RTCPeerConnection;
use super::streams::{TURN, tcp_context};
use super::turn_tls::{TlsLayer, TurnTlsConfig};
use crate::peer_connection::handler::transport_set::TransportId;
use crate::peer_connection::transport::ice::candidate::RTCIceServerTransportProtocol;
use bytes::BytesMut;
use ice::url::{ProtoType, SchemeType, Url};
use log::debug;
use sansio::Protocol;
use shared::stream::happy_eyeballs::{CONNECTION_ATTEMPT_DELAY, HappyEyeballs, sort_addresses};
use shared::stream::{Framing, StreamId, StreamLayer};
use shared::{TaggedBytesMut, TransportContext, TransportProtocol};
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Instant;

/// Datagrams held per peer address while their permission is being created.
const MAX_HELD_PER_PEER: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LinkState {
    /// Not started.
    Pending,
    /// The driver is resolving the host name.
    Resolving(u64),
    /// Connection attempts are racing.
    Connecting,
    /// Connected; the TURN client runs on it.
    Open(StreamId),
    /// Given up: no address connected, TLS failed, the allocation failed or the connection
    /// ended.
    Failed,
}

pub(crate) struct TurnLink {
    /// The transport the relayed candidate is gathered for: each transport allocates on its
    /// own (RFC 9429 section 5.2.1).
    transport: TransportId,
    url: Url,
    tls: bool,
    state: LinkState,
    race: Option<HappyEyeballs>,
    attempts: Vec<StreamId>,
    client: Option<turn::client::Client>,
    server: Option<SocketAddr>,
    link_local: Option<SocketAddr>,
    relay: Option<SocketAddr>,
    /// The ICE generation (local ufrag) the relayed candidate was last announced for.
    announced_ufrag: Option<String>,
    held: HashMap<IpAddr, Vec<(SocketAddr, Vec<u8>)>>,
}

impl TurnLink {
    fn settled(&self) -> bool {
        self.state == LinkState::Failed || self.relay.is_some()
    }

    fn url_string(&self) -> String {
        if self.tls {
            format!(
                "turns:{}:{}?transport=tcp",
                host_for_url(&self.url.host),
                self.url.port
            )
        } else {
            format!(
                "turn:{}:{}?transport=tcp",
                host_for_url(&self.url.host),
                self.url.port
            )
        }
    }

    fn protocol(&self) -> RTCIceServerTransportProtocol {
        if self.tls {
            RTCIceServerTransportProtocol::Tls
        } else {
            RTCIceServerTransportProtocol::Tcp
        }
    }
}

fn host_for_url(host: &str) -> String {
    if host.contains(':') {
        format!("[{host}]")
    } else {
        host.to_owned()
    }
}

/// The engine's TURN-over-stream links.
pub(crate) struct EngineTurn {
    /// The servers each transport allocates on: `turn:...?transport=tcp` and `turns:` URLs.
    servers: Vec<Url>,
    /// The transports whose links were made (once each, failed ones are not made again).
    made_for: HashSet<TransportId>,
    links: Vec<TurnLink>,
    pub(crate) enabled: bool,
    tls: TurnTlsConfig,
    tls_config: Option<std::sync::Arc<rustls::ClientConfig>>,
}

impl EngineTurn {
    /// The links of the `turn:...?transport=tcp` and `turns:` URLs among `urls`.
    pub(crate) fn new(urls: &[Url], enabled: bool, tls: TurnTlsConfig) -> Self {
        let servers = urls
            .iter()
            // `turns:` over UDP is DTLS (RFC 7350 section 4), which this does not run: such a
            // server is left alone (its resolution "MUST stop with an error").
            .filter(|u| {
                matches!(u.scheme, SchemeType::Turn | SchemeType::Turns)
                    && u.proto == ProtoType::Tcp
            })
            .cloned()
            .collect();
        let tls_config = tls.client_config().ok().flatten();
        Self {
            servers,
            made_for: HashSet::new(),
            links: vec![],
            enabled,
            tls,
            tls_config,
        }
    }

    /// The links of `transport`, one per server, unless it has had them.
    fn make_links(&mut self, transport: TransportId) {
        if !self.made_for.insert(transport) {
            return;
        }
        for url in &self.servers {
            self.links.push(TurnLink {
                transport,
                url: url.clone(),
                tls: url.scheme == SchemeType::Turns,
                state: LinkState::Pending,
                race: None,
                attempts: vec![],
                client: None,
                server: None,
                link_local: None,
                relay: None,
                announced_ufrag: None,
                held: HashMap::new(),
            });
        }
    }

    /// Whether a link of `transport` is still on its way to a relayed candidate.
    pub(crate) fn pending(&self, transport: TransportId) -> bool {
        self.enabled
            && self
                .links
                .iter()
                .any(|l| l.transport == transport && l.state != LinkState::Pending && !l.settled())
    }

    fn link_of_stream(&self, id: StreamId) -> Option<usize> {
        self.links
            .iter()
            .position(|l| l.state == LinkState::Open(id) || l.attempts.contains(&id))
    }

    /// The link whose relayed address is `addr`.
    pub(crate) fn link_of_relay(&self, addr: SocketAddr) -> Option<usize> {
        self.links.iter().position(|l| l.relay == Some(addr))
    }

    /// The links and their relayed addresses, for diagnostics.
    pub(crate) fn relays(&self) -> Vec<SocketAddr> {
        self.links.iter().filter_map(|l| l.relay).collect()
    }

    pub(crate) fn tls_config(&self) -> &TurnTlsConfig {
        &self.tls
    }
}

fn any_of_family(addr: SocketAddr) -> SocketAddr {
    if addr.is_ipv4() {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
    } else {
        SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0)
    }
}

impl RTCPeerConnection {
    /// Starts the links not started yet, once there is a local description, and announces
    /// the relayed candidates again for a new ICE generation.
    pub(crate) fn start_turn_links(&mut self) {
        if !self.streams.turn.enabled || self.is_closed() || self.local_description().is_none() {
            return;
        }
        for transport in self.pipeline_context.transports.ids() {
            self.streams.turn.make_links(transport);
        }
        let now = self.pipeline_context.now;
        for index in 0..self.streams.turn.links.len() {
            let link = &mut self.streams.turn.links[index];
            if link.state != LinkState::Pending {
                continue;
            }
            match link.url.host.parse::<IpAddr>() {
                Ok(ip) => {
                    let addr = SocketAddr::new(ip, link.url.port);
                    link.race = Some(HappyEyeballs::new(vec![addr], CONNECTION_ATTEMPT_DELAY));
                    link.state = LinkState::Connecting;
                }
                Err(_) => {
                    let query = self
                        .streams
                        .table
                        .resolve(link.url.host.clone(), link.url.port);
                    self.streams.turn.links[index].state = LinkState::Resolving(query);
                }
            }
        }
        self.drive_turn_races(now);
        let again: Vec<usize> = self
            .streams
            .turn
            .links
            .iter()
            .enumerate()
            .filter(|(_, l)| {
                let ufrag = &self
                    .ice_transport_of(l.transport)
                    .agent
                    .get_local_credentials()
                    .ufrag;
                l.relay.is_some() && l.announced_ufrag.as_ref() != Some(ufrag)
            })
            .map(|(i, _)| i)
            .collect();
        for index in again {
            self.announce_relay_candidate(index);
        }
    }

    /// Starts the connection attempts that are due.
    pub(crate) fn drive_turn_races(&mut self, now: Instant) {
        for index in 0..self.streams.turn.links.len() {
            if self.streams.turn.links[index].state != LinkState::Connecting {
                continue;
            }
            while let Some(addr) = self.streams.turn.links[index]
                .race
                .as_mut()
                .and_then(|r| r.next_attempt(now))
            {
                let tls = self.streams.turn.links[index].tls;
                let layer: Option<Box<dyn StreamLayer>> = if tls {
                    let Some(config) = self.streams.turn.tls_config.clone() else {
                        debug!("turns: server without roots or a verifier to check it: not used");
                        self.streams.turn.links[index].state = LinkState::Failed;
                        break;
                    };
                    match TlsLayer::new(config, &self.streams.turn.links[index].url.host) {
                        Ok(layer) => Some(Box::new(layer)),
                        Err(err) => {
                            debug!("TURN TLS: {err}");
                            self.streams.turn.links[index].state = LinkState::Failed;
                            break;
                        }
                    }
                } else {
                    None
                };
                match self.streams.table.connect(
                    any_of_family(addr),
                    addr,
                    Framing::Turn,
                    TURN,
                    false,
                    layer,
                ) {
                    Ok(id) => self.streams.turn.links[index].attempts.push(id),
                    Err(_) => {
                        if let Some(r) = self.streams.turn.links[index].race.as_mut() {
                            r.failed();
                        }
                    }
                }
            }
            if self.streams.turn.links[index]
                .race
                .as_ref()
                .is_some_and(HappyEyeballs::exhausted)
            {
                debug!(
                    "TURN server {}: no address connected",
                    self.streams.turn.links[index].url
                );
                self.streams.turn.links[index].state = LinkState::Failed;
            }
        }
    }

    /// A name the driver resolved.
    pub(crate) fn turn_resolved(&mut self, query: u64, addresses: Vec<SocketAddr>) {
        let now = self.pipeline_context.now;
        if let Some(link) = self
            .streams
            .turn
            .links
            .iter_mut()
            .find(|l| l.state == LinkState::Resolving(query))
        {
            let sorted = sort_addresses(&addresses, true);
            if sorted.is_empty() {
                link.state = LinkState::Failed;
            } else {
                link.race = Some(HappyEyeballs::new(sorted, CONNECTION_ATTEMPT_DELAY));
                link.state = LinkState::Connecting;
            }
        }
        self.drive_turn_races(now);
    }

    /// A TURN connection attempt connected: the race is won, the client starts.
    pub(crate) fn turn_connected(
        &mut self,
        now: Instant,
        id: StreamId,
        local: SocketAddr,
        remote: SocketAddr,
    ) {
        let Some(index) = self.streams.turn.link_of_stream(id) else {
            return;
        };
        if self.streams.turn.links[index].state != LinkState::Connecting {
            return;
        }
        let losers: Vec<StreamId> = self.streams.turn.links[index]
            .attempts
            .iter()
            .copied()
            .filter(|a| *a != id)
            .collect();
        for loser in losers {
            self.streams.table.reset(loser);
        }
        let Some(provider) = self.setting_engine.crypto_provider.clone() else {
            self.streams.turn.links[index].state = LinkState::Failed;
            return;
        };
        let link = &mut self.streams.turn.links[index];
        if let Some(race) = link.race.as_mut() {
            race.succeeded();
        }
        link.attempts = vec![id];
        link.state = LinkState::Open(id);
        link.server = Some(remote);
        link.link_local = Some(local);
        let config = turn::client::ClientConfig {
            stun_serv_addr: remote.to_string(),
            turn_serv_addr: remote.to_string(),
            local_addr: local,
            transport_protocol: TransportProtocol::TCP,
            username: link.url.username.clone(),
            password: link.url.password.clone(),
            realm: String::new(),
            rto_in_ms: 0,
            allocation_refresh_interval_cap: self
                .setting_engine
                .turn_allocation_refresh_interval_cap,
            ..Default::default()
        };
        match turn::client::Client::new(config, provider).and_then(|mut client| {
            client.allocate(now)?;
            Ok(client)
        }) {
            Ok(client) => link.client = Some(client),
            Err(err) => {
                debug!("TURN client for {}: {err}", link.url);
                link.state = LinkState::Failed;
            }
        }
        self.pump_turn(now);
    }

    /// A TURN connection attempt failed, or a TURN connection ended.
    pub(crate) fn turn_connection_ended(&mut self, now: Instant, id: StreamId) {
        let Some(index) = self.streams.turn.link_of_stream(id) else {
            return;
        };
        let link = &mut self.streams.turn.links[index];
        link.attempts.retain(|a| *a != id);
        match link.state {
            LinkState::Connecting => {
                if let Some(race) = link.race.as_mut() {
                    race.failed();
                }
                self.drive_turn_races(now);
            }
            LinkState::Open(open) if open == id => {
                // RFC 8656 section 3.1: the allocation lives as long as its connection.
                debug!(
                    "TURN connection to {} ended: its allocation is gone",
                    link.url
                );
                link.state = LinkState::Failed;
                link.client = None;
                link.relay = None;
            }
            _ => {}
        }
    }

    /// TURN messages read from a link.
    pub(crate) fn turn_messages(&mut self, now: Instant, id: StreamId, messages: Vec<Vec<u8>>) {
        let Some(index) = self.streams.turn.link_of_stream(id) else {
            return;
        };
        let link = &mut self.streams.turn.links[index];
        let (Some(server), Some(local)) = (link.server, link.link_local) else {
            return;
        };
        if let Some(client) = link.client.as_mut() {
            for message in messages {
                if let Err(err) = client.handle_read(TaggedBytesMut {
                    now,
                    transport: tcp_context(local, server),
                    message: BytesMut::from(&message[..]),
                }) {
                    debug!("TURN message from {server}: {err}");
                }
            }
        }
        self.pump_turn(now);
    }

    /// Moves what the TURN clients have to send onto their connections and acts on their
    /// events.
    pub(crate) fn pump_turn(&mut self, now: Instant) {
        let mut inbound = vec![];
        let mut announce = vec![];
        for index in 0..self.streams.turn.links.len() {
            let link = &mut self.streams.turn.links[index];
            let LinkState::Open(id) = link.state else {
                continue;
            };
            let Some(client) = link.client.as_mut() else {
                continue;
            };
            let mut granted = vec![];
            while let Some(event) = client.poll_event() {
                match event {
                    turn::client::Event::AllocateResponse(_, relayed) => {
                        link.relay = Some(relayed);
                        announce.push(index);
                    }
                    turn::client::Event::AllocateError(_, err) => {
                        debug!("TURN allocation on {} refused: {err:?}", link.url);
                        link.state = LinkState::Failed;
                    }
                    turn::client::Event::AllocationLost(_, err) => {
                        debug!("TURN allocation on {} lost: {err:?}", link.url);
                        link.state = LinkState::Failed;
                        link.relay = None;
                    }
                    turn::client::Event::CreatePermissionResponse(_, peer) => {
                        granted.push(peer.ip());
                    }
                    turn::client::Event::CreatePermissionError(_, err) => {
                        debug!("TURN permission refused: {err:?}");
                    }
                    turn::client::Event::DataIndicationOrChannelData(_, peer, data) => {
                        if let Some(relay) = link.relay {
                            inbound.push((link.transport, relay, peer, data));
                        }
                    }
                    _ => {}
                }
            }
            if let (Some(relay), Some(client)) = (link.relay, link.client.as_mut()) {
                for ip in granted {
                    for (peer, data) in link.held.remove(&ip).unwrap_or_default() {
                        if let Ok(mut r) = client.relay(relay) {
                            let _ = r.send_to(now, &data, peer);
                        }
                    }
                }
            }
            if let Some(client) = link.client.as_mut() {
                while let Some(transmit) = client.poll_write() {
                    let _ = self.streams.table.send(id, &transmit.message);
                }
            }
        }
        for index in announce {
            self.announce_relay_candidate(index);
        }
        for (transport, relay, peer, data) in inbound {
            // On the transport the relayed candidate is of.
            self.pipeline_context.observe(now);
            self.read_on_transport(
                transport,
                TaggedBytesMut {
                    now,
                    transport: TransportContext {
                        local_addr: relay,
                        peer_addr: peer,
                        transport_protocol: TransportProtocol::UDP,
                        ecn: None,
                    },
                    message: data,
                },
            );
        }
        self.finish_deferred_gathering();
    }

    fn announce_relay_candidate(&mut self, index: usize) {
        let link = &self.streams.turn.links[index];
        let (Some(relay), Some(local)) = (link.relay, link.link_local) else {
            return;
        };
        let (url, protocol, transport) = (link.url_string(), link.protocol(), link.transport);
        let candidate = ice::candidate::candidate_relay::CandidateRelayConfig {
            base_config: ice::candidate::CandidateConfig {
                network: "udp".to_owned(),
                address: relay.ip().to_string(),
                port: relay.port(),
                component: 1,
                ..Default::default()
            },
            rel_addr: local.ip().to_string(),
            rel_port: local.port(),
            ..Default::default()
        }
        .new_candidate_relay()
        .and_then(|c| crate::peer_connection::transport::RTCIceCandidate::from(&c).to_json());
        match candidate {
            Ok(init) => {
                let value = init
                    .candidate
                    .strip_prefix("candidate:")
                    .unwrap_or(&init.candidate)
                    .to_owned();
                if let Err(err) =
                    self.add_engine_local_candidate(transport, &value, Some(&url), Some(protocol))
                {
                    debug!("relayed candidate {relay} not added: {err}");
                }
                let ufrag = self
                    .ice_transport_of(transport)
                    .agent
                    .get_local_credentials()
                    .ufrag
                    .clone();
                self.streams.turn.links[index].announced_ufrag = Some(ufrag);
            }
            Err(err) => debug!("relayed candidate {relay} not made: {err}"),
        }
    }

    /// Sends a datagram the agent wrote from a relayed candidate through its TURN link: at
    /// once with a permission for the peer, else after one is created (RFC 8656 section 9).
    pub(crate) fn send_via_turn(&mut self, index: usize, msg: TaggedBytesMut) {
        let now = msg.now.max(self.pipeline_context.now);
        let peer = msg.transport.peer_addr;
        let link = &mut self.streams.turn.links[index];
        let (Some(relay), Some(client)) = (link.relay, link.client.as_mut()) else {
            return;
        };
        let Ok(mut r) = client.relay(relay) else {
            return;
        };
        match r.send_to(now, &msg.message, peer) {
            Ok(()) => {}
            Err(shared::error::Error::ErrNoPermission) => {
                let first = !link.held.contains_key(&peer.ip());
                let held = link.held.entry(peer.ip()).or_default();
                if held.len() < MAX_HELD_PER_PEER {
                    held.push((peer, msg.message.to_vec()));
                }
                if first && let Ok(mut r) = client.relay(relay) {
                    let _ = r.create_permission(now, peer);
                }
            }
            Err(err) => debug!("TURN send to {peer}: {err}"),
        }
        self.pump_turn(now);
    }

    /// Drops the links of transports a description removed, and their connections.
    pub(crate) fn release_removed_turn_links(&mut self) {
        let ids = self.pipeline_context.transports.ids();
        let mut ended = vec![];
        self.streams.turn.links.retain(|l| {
            let kept = ids.contains(&l.transport);
            if !kept {
                ended.extend(l.attempts.iter().copied());
            }
            kept
        });
        self.streams.turn.made_for.retain(|t| ids.contains(t));
        for id in ended {
            self.streams.table.close(id);
        }
    }

    /// The TURN clients' and races' next timer.
    pub(crate) fn turn_poll_timeout(&mut self) -> Option<Instant> {
        let mut next: Option<Instant> = None;
        for link in self.streams.turn.links.iter_mut() {
            let t = match link.state {
                LinkState::Connecting => link.race.as_ref().and_then(HappyEyeballs::poll_timeout),
                LinkState::Open(_) => link.client.as_mut().and_then(|c| c.poll_timeout()),
                _ => None,
            };
            if let Some(t) = t {
                next = Some(next.map_or(t, |n| n.min(t)));
            }
        }
        next
    }

    /// Fires the TURN clients' and races' timers.
    pub(crate) fn turn_handle_timeout(&mut self, now: Instant) {
        if self.streams.turn.links.is_empty() {
            return;
        }
        for link in self.streams.turn.links.iter_mut() {
            if let (LinkState::Open(_), Some(client)) = (link.state, link.client.as_mut())
                && let Err(err) = client.handle_timeout(now)
            {
                debug!("TURN client timer: {err}");
            }
        }
        self.drive_turn_races(now);
        self.pump_turn(now);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_turn_over_tcp_and_turns_over_tcp_servers_get_a_link() {
        let urls: Vec<Url> = [
            "turn:192.0.2.1:3478?transport=tcp",
            "turns:turn.example:5349",
            "turns:192.0.2.1:5349?transport=tcp",
            "turn:192.0.2.1:3478",
            "turns:192.0.2.1:5349?transport=udp",
            "stun:192.0.2.1:3478",
        ]
        .iter()
        .map(|u| Url::parse_url(u).unwrap())
        .collect();
        let mut turn = EngineTurn::new(&urls, true, TurnTlsConfig::default());
        assert!(
            turn.links.is_empty(),
            "no link before a transport needs one"
        );
        let first = TransportId::default();
        turn.make_links(first);
        turn.make_links(first);
        let links: Vec<(String, bool)> =
            turn.links.iter().map(|l| (l.url_string(), l.tls)).collect();
        assert_eq!(
            links,
            vec![
                ("turn:192.0.2.1:3478?transport=tcp".to_owned(), false),
                ("turns:turn.example:5349?transport=tcp".to_owned(), true),
                ("turns:192.0.2.1:5349?transport=tcp".to_owned(), true),
            ]
        );
        assert_eq!(turn.links[0].protocol(), RTCIceServerTransportProtocol::Tcp);
        assert_eq!(turn.links[1].protocol(), RTCIceServerTransportProtocol::Tls);
        // Nothing started: nothing pending for the end of gathering.
        assert!(!turn.pending(first));
        // Another transport gets links of its own, once.
        turn.make_links(TransportId(1));
        assert_eq!(turn.links.len(), 6);
        assert!(
            turn.links[3..]
                .iter()
                .all(|l| l.transport == TransportId(1))
        );
    }
}
