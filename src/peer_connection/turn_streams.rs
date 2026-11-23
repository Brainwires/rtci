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
//!
//! A `turns:...?transport=udp` server is reached over DTLS (RFC 7350): a client-role
//! `rtc-dtls` association from a UDP host candidate's base, on the application's socket. Its
//! records leave through `poll_write` and are taken out of `handle_read` before ICE sees them
//! (by the server's address on that base); the server's certificate is checked against the
//! URI's host with the same roots or verifier as TLS. The TURN client runs over it with UDP's
//! retransmissions (RFC 7350 section 4), and the relayed candidate's `relayProtocol` is
//! `dtls`.

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
use std::sync::Arc;
use std::time::Instant;

mod tcp_relay;

/// Datagrams held per peer address while their permission is being created.
const MAX_HELD_PER_PEER: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LinkState {
    /// Not started.
    Pending,
    /// The driver is looking up the server's NAPTR or SRV records (RFC 5928 section 3).
    Discovering(u64),
    /// The driver is resolving the host name.
    Resolving(u64),
    /// Connection attempts are racing.
    Connecting,
    /// Connected; the TURN client runs on it.
    Open(StreamId),
    /// The DTLS association is up (`TurnLink::dtls`); the TURN client runs on it.
    OpenDtls,
    /// Given up: no address connected, TLS failed, the allocation failed or the connection
    /// ended.
    Failed,
    /// Closed once ICE had completed without its relayed candidate (RFC 6544 section 11.2);
    /// a new ICE generation allocates again.
    Released,
}

/// What carries a link's TURN messages.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Carrier {
    /// TCP (`turn:...?transport=tcp`).
    Tcp,
    /// TLS over TCP (`turns:`).
    Tls,
    /// DTLS over the application's UDP socket (`turns:...?transport=udp`, RFC 7350).
    Dtls,
}

/// A DTLS association to one address of a `turns:...?transport=udp` server, from a UDP base.
pub(crate) struct DtlsAttempt {
    remote: SocketAddr,
    base: SocketAddr,
    endpoint: dtls::endpoint::Endpoint,
}

impl DtlsAttempt {
    /// Moves the association's records onto the application's socket (`poll_write`).
    fn flush(&mut self, out: &mut std::collections::VecDeque<TaggedBytesMut>) {
        while let Some(t) = self.endpoint.poll_transmit() {
            out.push_back(t);
        }
    }
}

pub(crate) struct TurnLink {
    /// The transport the relayed candidate is gathered for: each transport allocates on its
    /// own (RFC 9429 section 5.2.1).
    transport: TransportId,
    url: Url,
    carrier: Carrier,
    /// Over DTLS: the handshakes racing, one per server address.
    dtls_attempts: Vec<DtlsAttempt>,
    /// Over DTLS: the association that won.
    dtls: Option<DtlsAttempt>,
    /// A TCP allocation (RFC 6062): relayed TCP candidates, peers on data connections.
    relay_tcp: bool,
    /// Its peers' data connections.
    data: Vec<tcp_relay::DataConn>,
    /// The peer addresses it has created a permission for.
    permitted: HashSet<IpAddr>,
    state: LinkState,
    race: Option<HappyEyeballs>,
    attempts: Vec<StreamId>,
    client: Option<turn::client::Client>,
    server: Option<SocketAddr>,
    link_local: Option<SocketAddr>,
    relay: Option<SocketAddr>,
    /// The ICE generation (local ufrag) the relayed candidate was last announced for.
    announced_ufrag: Option<String>,
    /// The name's query, while its per-family answers may still come.
    query: Option<u64>,
    /// The NAPTR / SRV discovery of a server whose URI gives no port.
    discovery: Option<crate::peer_connection::dns_discovery::Discovery>,
    held: HashMap<IpAddr, Vec<(SocketAddr, Vec<u8>)>>,
}

impl TurnLink {
    fn settled(&self) -> bool {
        matches!(self.state, LinkState::Failed | LinkState::Released) || self.relay.is_some()
    }

    fn url_string(&self) -> String {
        let (scheme, transport) = match self.carrier {
            Carrier::Tcp => ("turn", "tcp"),
            Carrier::Tls => ("turns", "tcp"),
            Carrier::Dtls => ("turns", "udp"),
        };
        format!(
            "{scheme}:{}:{}?transport={transport}",
            host_for_url(&self.url.host),
            self.url.port
        )
    }

    fn protocol(&self) -> RTCIceServerTransportProtocol {
        match self.carrier {
            Carrier::Tcp => RTCIceServerTransportProtocol::Tcp,
            Carrier::Tls => RTCIceServerTransportProtocol::Tls,
            Carrier::Dtls => RTCIceServerTransportProtocol::Dtls,
        }
    }

    fn tls(&self) -> bool {
        self.carrier == Carrier::Tls
    }

    /// The DTLS association (racing or won) to `remote` from `base`.
    fn dtls_to(&mut self, base: SocketAddr, remote: SocketAddr) -> Option<&mut DtlsAttempt> {
        self.dtls
            .iter_mut()
            .chain(self.dtls_attempts.iter_mut())
            .find(|a| a.base == base && a.remote == remote)
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
    /// The servers each transport allocates on: `turn:...?transport=tcp` and `turns:` URLs
    /// (`turns:...?transport=udp` over DTLS).
    servers: Vec<Url>,
    /// The bases of the UDP host candidates of each transport: where a DTLS link starts.
    udp_bases: Vec<(TransportId, SocketAddr)>,
    /// The transports whose links were made (once each, failed ones are not made again).
    made_for: HashSet<TransportId>,
    links: Vec<TurnLink>,
    pub(crate) enabled: bool,
    tls: TurnTlsConfig,
    tls_config: Option<std::sync::Arc<rustls::ClientConfig>>,
    /// Relayed TCP candidates from a TCP allocation beside the UDP one, for each server over
    /// TCP or TLS (RFC 6544 section 5.5).
    pub(crate) tcp_relay: bool,
    /// The addresses of the remote TCP candidates signalled per transport (for the
    /// permissions of the TCP allocations).
    remote_tcp_ips: Vec<(TransportId, IpAddr)>,
}

impl EngineTurn {
    /// The links of the `turn:...?transport=tcp` and `turns:` URLs among `urls`.
    pub(crate) fn new(urls: &[Url], enabled: bool, tls: TurnTlsConfig) -> Self {
        let servers = urls
            .iter()
            // `turn:` over UDP stays the application's; `turns:` over UDP is DTLS (RFC 7350
            // section 4).
            .filter(|u| {
                (matches!(u.scheme, SchemeType::Turn | SchemeType::Turns)
                    && u.proto == ProtoType::Tcp)
                    || (u.scheme == SchemeType::Turns && u.proto == ProtoType::Udp)
            })
            .cloned()
            .collect();
        let tls_config = tls.client_config().ok().flatten();
        Self {
            servers,
            udp_bases: vec![],
            made_for: HashSet::new(),
            links: vec![],
            enabled,
            tls,
            tls_config,
            tcp_relay: true,
            remote_tcp_ips: vec![],
        }
    }

    /// The links of `transport`, one per server, unless it has had them.
    fn make_links(&mut self, transport: TransportId) {
        if !self.made_for.insert(transport) {
            return;
        }
        for url in &self.servers {
            let carrier = match (url.scheme, url.proto) {
                (SchemeType::Turns, ProtoType::Udp) => Carrier::Dtls,
                (SchemeType::Turns, _) => Carrier::Tls,
                _ => Carrier::Tcp,
            };
            // Over TCP and TLS also a TCP allocation, on a control connection of its own (an
            // allocation is its 5-tuple's, RFC 8656 section 2.2), for relayed TCP candidates.
            let kinds: &[bool] = if self.tcp_relay && carrier != Carrier::Dtls {
                &[false, true]
            } else {
                &[false]
            };
            for &relay_tcp in kinds {
                self.links.push(TurnLink {
                    transport,
                    url: url.clone(),
                    carrier,
                    dtls_attempts: vec![],
                    dtls: None,
                    relay_tcp,
                    data: vec![],
                    permitted: HashSet::new(),
                    state: LinkState::Pending,
                    race: None,
                    attempts: vec![],
                    client: None,
                    server: None,
                    link_local: None,
                    relay: None,
                    announced_ufrag: None,
                    query: None,
                    discovery: None,
                    held: HashMap::new(),
                });
            }
        }
    }

    /// Whether a link of `transport` is still on its way to a relayed candidate. A link over
    /// a stream waits for the driver (`driver`: one serves the stream interface); a DTLS link
    /// needs it only to resolve a name.
    pub(crate) fn pending(&self, transport: TransportId, driver: bool) -> bool {
        self.enabled
            && self.links.iter().any(|l| {
                l.transport == transport
                    && l.state != LinkState::Pending
                    && !l.settled()
                    && (driver
                        || (l.carrier == Carrier::Dtls
                            && !matches!(
                                l.state,
                                LinkState::Resolving(_) | LinkState::Discovering(_)
                            )))
            })
    }

    /// A UDP host candidate's base of `transport`: DTLS links of the transport can start.
    pub(crate) fn note_udp_base(&mut self, transport: TransportId, base: SocketAddr) {
        if !self.udp_bases.contains(&(transport, base)) {
            self.udp_bases.push((transport, base));
        }
    }

    /// The first UDP base of `transport` of the family of `server`.
    fn udp_base(&self, transport: TransportId, server: SocketAddr) -> Option<SocketAddr> {
        self.udp_bases
            .iter()
            .find(|(t, b)| *t == transport && b.is_ipv4() == server.is_ipv4())
            .map(|(_, b)| *b)
    }

    /// The DTLS link (and whether its association has won) that `(base, remote)` is one of.
    fn link_of_dtls(&self, base: SocketAddr, remote: SocketAddr) -> Option<usize> {
        self.links.iter().position(|l| {
            l.dtls
                .iter()
                .chain(l.dtls_attempts.iter())
                .any(|a| a.base == base && a.remote == remote)
        })
    }

    fn link_of_stream(&self, id: StreamId) -> Option<usize> {
        self.links
            .iter()
            .position(|l| l.state == LinkState::Open(id) || l.attempts.contains(&id))
    }

    /// Whether a TCP allocation has its relayed address.
    pub(crate) fn has_tcp_relay(&self) -> bool {
        self.links.iter().any(|l| l.relay_tcp && l.relay.is_some())
    }

    /// The link whose relayed UDP address is `addr`.
    pub(crate) fn link_of_relay(&self, addr: SocketAddr) -> Option<usize> {
        self.links
            .iter()
            .position(|l| !l.relay_tcp && l.relay == Some(addr))
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
        let driver = self.streams.driver_seen;
        for index in 0..self.streams.turn.links.len() {
            let link = &self.streams.turn.links[index];
            // A link over a stream starts for a driver that serves the stream interface; a
            // DTLS link from a UDP host candidate's base, once the transport has one.
            if link.state != LinkState::Pending
                || (link.carrier != Carrier::Dtls && !driver)
                || (link.carrier == Carrier::Dtls
                    && !self
                        .streams
                        .turn
                        .udp_bases
                        .iter()
                        .any(|(t, _)| *t == link.transport))
            {
                continue;
            }
            let link = &mut self.streams.turn.links[index];
            match link.url.host.parse::<IpAddr>() {
                Ok(ip) => {
                    let addr = SocketAddr::new(ip, link.url.port);
                    link.race = Some(HappyEyeballs::new(vec![addr], CONNECTION_ATTEMPT_DELAY));
                    link.state = LinkState::Connecting;
                }
                // RFC 5928 section 3: without a port, S-NAPTR and SRV find the server.
                Err(_) if !link.url.explicit_port => {
                    // RFC 5928 section 3 and RFC 7350 section 4.2: the S-NAPTR tag and SRV
                    // service of the transport.
                    let (tag, srv) = match link.carrier {
                        Carrier::Tcp => ("turn.tcp", "_turn._tcp"),
                        Carrier::Tls => ("turn.tls", "_turns._tcp"),
                        Carrier::Dtls => ("turn.dtls", "_turns._udp"),
                    };
                    let discovery = crate::peer_connection::dns_discovery::Discovery::new(
                        &link.url.host,
                        link.url.port,
                        Some(tag),
                        srv,
                    );
                    let first = discovery.start();
                    link.discovery = Some(discovery);
                    self.turn_discovery_next(index, first, now);
                }
                Err(_) => {
                    let query = self
                        .streams
                        .table
                        .resolve(link.url.host.clone(), link.url.port);
                    let link = &mut self.streams.turn.links[index];
                    link.state = LinkState::Resolving(query);
                    link.query = Some(query);
                }
            }
        }
        // A link released once ICE had completed allocates again for a new ICE generation.
        for i in 0..self.streams.turn.links.len() {
            let l = &self.streams.turn.links[i];
            if l.state != LinkState::Released {
                continue;
            }
            let ufrag = self
                .ice_transport_of(l.transport)
                .agent
                .get_local_credentials()
                .ufrag
                .clone();
            if l.announced_ufrag.as_ref() != Some(&ufrag) {
                let l = &mut self.streams.turn.links[i];
                l.state = LinkState::Pending;
                l.race = None;
                l.query = None;
                l.discovery = None;
                l.announced_ufrag = None;
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
                if self.streams.turn.links[index].carrier == Carrier::Dtls {
                    if !self.start_dtls_attempt(now, index, addr)
                        && let Some(r) = self.streams.turn.links[index].race.as_mut()
                    {
                        r.failed();
                    }
                    if self.streams.turn.links[index].state == LinkState::Failed {
                        break;
                    }
                    continue;
                }
                let tls = self.streams.turn.links[index].tls();
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
                // RFC 5928 section 3: the next SRV target, when there is one.
                if let Some(next) = self.streams.turn.links[index]
                    .discovery
                    .as_mut()
                    .map(|d| d.next_target())
                {
                    self.turn_discovery_next(index, next, now);
                } else {
                    debug!(
                        "TURN server {}: no address connected",
                        self.streams.turn.links[index].url
                    );
                    self.streams.turn.links[index].state = LinkState::Failed;
                }
            }
        }
    }

    /// Acts on the next step of a link's discovery.
    fn turn_discovery_next(
        &mut self,
        index: usize,
        next: crate::peer_connection::dns_discovery::Next,
        now: Instant,
    ) {
        use crate::peer_connection::dns_discovery::Next;
        match next {
            Next::Records { name, kind } => {
                let query = self.streams.table.resolve_records(name, kind);
                let link = &mut self.streams.turn.links[index];
                link.state = LinkState::Discovering(query);
                if let Some(d) = link.discovery.as_mut() {
                    d.asked(query, now);
                }
            }
            Next::Address { host, port } => match host.parse::<IpAddr>() {
                Ok(ip) => {
                    let link = &mut self.streams.turn.links[index];
                    link.race = Some(HappyEyeballs::new(
                        vec![SocketAddr::new(ip, port)],
                        CONNECTION_ATTEMPT_DELAY,
                    ));
                    link.state = LinkState::Connecting;
                }
                Err(_) => {
                    let query = self.streams.table.resolve(host, port);
                    let link = &mut self.streams.turn.links[index];
                    link.state = LinkState::Resolving(query);
                    link.query = Some(query);
                    link.race = None;
                }
            },
            Next::Exhausted => {
                debug!(
                    "TURN server {}: no target connected",
                    self.streams.turn.links[index].url
                );
                self.streams.turn.links[index].state = LinkState::Failed;
            }
        }
    }

    /// The NAPTR or SRV records the driver looked up for a link (`None`: the query timed out).
    /// Returns whether the query was a link's.
    pub(crate) fn turn_records(
        &mut self,
        query: u64,
        records: &[shared::stream::DnsRecord],
    ) -> bool {
        let now = self.pipeline_context.now;
        let Some(index) = self
            .streams
            .turn
            .links
            .iter()
            .position(|l| l.state == LinkState::Discovering(query))
        else {
            return false;
        };
        let Some(next) = self.streams.turn.links[index]
            .discovery
            .as_mut()
            .map(|d| d.on_records(records))
        else {
            return false;
        };
        self.turn_discovery_next(index, next, now);
        self.drive_turn_races(now);
        true
    }

    /// A name the driver resolved: every address at once (`ipv6` `None`), or one family's
    /// as it arrived (RFC 8305 section 3: the race starts on the first answer, and a late one
    /// joins it).
    pub(crate) fn turn_resolved(
        &mut self,
        query: u64,
        ipv6: Option<bool>,
        addresses: &[SocketAddr],
    ) {
        let now = self.pipeline_context.now;
        if let Some(link) = self.streams.turn.links.iter_mut().find(|l| {
            l.query == Some(query)
                && (l.state == LinkState::Resolving(query)
                    || (l.state == LinkState::Connecting
                        && l.race.as_ref().is_some_and(HappyEyeballs::awaiting)))
        }) {
            match ipv6 {
                None => {
                    link.query = None;
                    // No address: an exhausted race, which moves on to the next SRV target
                    // or fails the link (`drive_turn_races`).
                    let sorted = sort_addresses(addresses, true);
                    link.race = Some(HappyEyeballs::new(sorted, CONNECTION_ATTEMPT_DELAY));
                    link.state = LinkState::Connecting;
                }
                Some(ipv6) => {
                    link.race
                        .get_or_insert_with(|| {
                            HappyEyeballs::awaiting_answers(CONNECTION_ATTEMPT_DELAY)
                        })
                        .answer(now, ipv6, addresses, true);
                    link.state = LinkState::Connecting;
                }
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
        let tcp = link.relay_tcp;
        match turn::client::Client::new(config, provider).and_then(|mut client| {
            if tcp {
                // RFC 6062 section 4.1: REQUESTED-TRANSPORT TCP.
                client.allocate_with(now, tcp_relay::tcp_allocation())?;
            } else {
                client.allocate(now)?;
            }
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
                self.turn_allocation_lost(now, index);
            }
            _ => {}
        }
    }

    /// A link's allocation is gone with its connection (or DTLS association). RFC 6544 section
    /// 11.2: when the session uses an address that server allocated, the client "SHOULD
    /// reconnect to the TURN server, obtain a new allocation, and restart ICE": the link starts
    /// over and ICE is restarted (`restart_ice`: the next offer has new credentials, and the
    /// new generation announces the new relayed candidate). A link whose candidate is not in
    /// use has failed.
    pub(crate) fn turn_allocation_lost(&mut self, now: Instant, index: usize) {
        let in_use = self.relay_in_use(index);
        let link = &mut self.streams.turn.links[index];
        for conn in std::mem::take(&mut link.data) {
            if let Some(id) = conn.stream() {
                self.streams.table.close(id);
            }
        }
        let link = &mut self.streams.turn.links[index];
        link.client = None;
        link.relay = None;
        link.dtls = None;
        link.permitted.clear();
        link.attempts.clear();
        if in_use {
            debug!(
                "{}: reconnecting for a new allocation; ICE restarts",
                link.url
            );
            link.state = LinkState::Pending;
            link.race = None;
            link.query = None;
            link.discovery = None;
            link.announced_ufrag = None;
            self.restart_ice();
            self.start_turn_links();
        } else {
            link.state = LinkState::Failed;
        }
        let _ = now;
    }

    /// Whether the selected pair of the link's transport has its relayed candidate as the
    /// local one.
    fn relay_in_use(&self, index: usize) -> bool {
        let link = &self.streams.turn.links[index];
        let Some(relay) = link.relay else {
            return false;
        };
        self.ice_transport_of(link.transport)
            .agent
            .get_selected_candidate_pair()
            .is_some_and(|(local, _)| {
                let addr = local.addr();
                addr == relay || (link.relay_tcp && addr.ip() == relay.ip() && addr.port() == 9)
            })
    }

    /// RFC 6544 section 11.2: once ICE of a transport has completed, the connection to a TURN
    /// server whose relayed candidate the selected pair does not use is closed (it "MUST be
    /// kept open ... if a relayed candidate from the TURN server was selected"). Its
    /// allocation goes with it; a later ICE generation allocates again.
    pub(crate) fn close_settled_turn_links(&mut self) {
        for index in 0..self.streams.turn.links.len() {
            let link = &self.streams.turn.links[index];
            let LinkState::Open(id) = link.state else {
                continue;
            };
            let completed = self
                .ice_transport_of(link.transport)
                .agent
                .get_selected_candidate_pair()
                .is_some();
            if !completed || link.relay.is_none() || self.relay_in_use(index) {
                continue;
            }
            debug!(
                "{}: ICE completed without its relayed candidate: closed",
                link.url
            );
            let link = &mut self.streams.turn.links[index];
            for conn in std::mem::take(&mut link.data) {
                if let Some(id) = conn.stream() {
                    self.streams.table.close(id);
                }
            }
            let link = &mut self.streams.turn.links[index];
            link.state = LinkState::Released;
            link.client = None;
            link.relay = None;
            link.attempts.clear();
            link.permitted.clear();
            self.streams.table.close(id);
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
        let mut peers_ready = vec![];
        let mut failed_peers = vec![];
        for index in 0..self.streams.turn.links.len() {
            let link = &mut self.streams.turn.links[index];
            let id = match link.state {
                LinkState::Open(id) => Some(id),
                LinkState::OpenDtls => None,
                _ => continue,
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
                    turn::client::Event::ConnectResponse(_, peer, connection_id) => {
                        peers_ready.push((index, peer, connection_id, false));
                    }
                    turn::client::Event::ConnectionAttempt(_, peer, connection_id) => {
                        peers_ready.push((index, peer, connection_id, true));
                    }
                    turn::client::Event::ConnectError(_, peer, err) => {
                        debug!("TURN Connect to {peer}: {err:?}");
                        failed_peers.push((index, peer));
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
                    match (id, link.dtls.as_mut()) {
                        (Some(id), _) => {
                            let _ = self.streams.table.send(id, &transmit.message);
                        }
                        (None, Some(dtls)) => {
                            let remote = dtls.remote;
                            if let Err(err) = dtls.endpoint.write(now, remote, &transmit.message) {
                                debug!("TURN over DTLS to {remote}: {err}");
                            }
                            dtls.flush(&mut self.pipeline_context.write_outs);
                        }
                        (None, None) => {}
                    }
                }
            }
        }
        for index in announce {
            self.announce_relay_candidate(index);
        }
        for (index, peer, connection_id, attempt) in peers_ready {
            self.turn_tcp_peer_ready(index, peer, connection_id, attempt);
        }
        for (index, peer) in failed_peers {
            self.turn_tcp_connect_failed(now, index, peer);
        }
        for index in 0..self.streams.turn.links.len() {
            self.pump_turn_data(now, index);
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
        // A TCP allocation: a passive relayed candidate, and on port 9 an active one (RFC
        // 6544 sections 4.5 and 5.5).
        let kinds: Vec<(&str, u16, Option<ice::tcp_type::TcpType>)> = if link.relay_tcp {
            vec![
                ("tcp", relay.port(), Some(ice::tcp_type::TcpType::Passive)),
                ("tcp", 9, Some(ice::tcp_type::TcpType::Active)),
            ]
        } else {
            vec![("udp", relay.port(), None)]
        };
        for (network, port, tcp_type) in kinds {
            let candidate = ice::candidate::candidate_relay::CandidateRelayConfig {
                base_config: ice::candidate::CandidateConfig {
                    network: network.to_owned(),
                    address: relay.ip().to_string(),
                    port,
                    component: 1,
                    ..Default::default()
                },
                rel_addr: local.ip().to_string(),
                rel_port: local.port(),
                ..Default::default()
            }
            .new_candidate_relay()
            .and_then(|mut c| {
                if let Some(tcp_type) = tcp_type {
                    c.set_tcp_type(tcp_type);
                }
                crate::peer_connection::transport::RTCIceCandidate::from(&c).to_json()
            });
            match candidate {
                Ok(init) => {
                    let value = init
                        .candidate
                        .strip_prefix("candidate:")
                        .unwrap_or(&init.candidate)
                        .to_owned();
                    if let Err(err) = self.add_engine_local_candidate(
                        transport,
                        &value,
                        Some(&url),
                        Some(protocol),
                    ) {
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
        let now = self.pipeline_context.now;
        let out = &mut self.pipeline_context.write_outs;
        self.streams.turn.links.retain_mut(|l| {
            let kept = ids.contains(&l.transport);
            if !kept {
                ended.extend(l.attempts.iter().copied());
                ended.extend(l.data.iter().filter_map(|c| c.stream()));
                // A DTLS association says close_notify.
                for a in l.dtls.iter_mut().chain(l.dtls_attempts.iter_mut()) {
                    let _ = a.endpoint.close(now);
                    a.flush(out);
                }
            }
            kept
        });
        self.streams.turn.made_for.retain(|t| ids.contains(t));
        self.streams.turn.udp_bases.retain(|(t, _)| ids.contains(t));
        for id in ended {
            self.streams.table.close(id);
        }
    }

    /// The TURN clients' and races' next timer.
    pub(crate) fn turn_poll_timeout(&mut self) -> Option<Instant> {
        let mut next: Option<Instant> = None;
        for link in self.streams.turn.links.iter_mut() {
            let t = match link.state {
                LinkState::Discovering(_) => link.discovery.as_ref().and_then(|d| d.poll_timeout()),
                LinkState::Connecting => link
                    .race
                    .as_ref()
                    .and_then(HappyEyeballs::poll_timeout)
                    .into_iter()
                    .chain(
                        link.dtls_attempts
                            .iter()
                            .filter_map(|a| a.endpoint.poll_timeout(&a.remote)),
                    )
                    .min(),
                LinkState::Open(_) => link.client.as_mut().and_then(|c| c.poll_timeout()),
                LinkState::OpenDtls => link
                    .client
                    .as_mut()
                    .and_then(|c| c.poll_timeout())
                    .into_iter()
                    .chain(
                        link.dtls
                            .as_ref()
                            .and_then(|a| a.endpoint.poll_timeout(&a.remote)),
                    )
                    .min(),
                _ => None,
            };
            if let Some(t) = t {
                next = Some(next.map_or(t, |n| n.min(t)));
            }
        }
        if let Some(t) = self.turn_data_poll_timeout() {
            next = Some(next.map_or(t, |n| n.min(t)));
        }
        next
    }

    /// Fires the TURN clients' and races' timers.
    pub(crate) fn turn_handle_timeout(&mut self, now: Instant) {
        // A DTLS link whose base was added before the local description starts now.
        self.start_turn_links();
        if self.streams.turn.links.is_empty() {
            return;
        }
        for link in self.streams.turn.links.iter_mut() {
            if let (LinkState::Open(_) | LinkState::OpenDtls, Some(client)) =
                (link.state, link.client.as_mut())
                && let Err(err) = client.handle_timeout(now)
            {
                debug!("TURN client timer: {err}");
            }
        }
        self.turn_dtls_timeouts(now);
        self.turn_data_handle_timeout(now);
        // A records query the driver did not answer counts as empty.
        let unanswered: Vec<u64> = self
            .streams
            .turn
            .links
            .iter()
            .filter_map(|l| match l.state {
                LinkState::Discovering(q)
                    if l.discovery.as_ref().is_some_and(|d| d.timed_out(now)) =>
                {
                    Some(q)
                }
                _ => None,
            })
            .collect();
        for query in unanswered {
            self.turn_records(query, &[]);
        }
        self.drive_turn_races(now);
        self.pump_turn(now);
    }
}

impl RTCPeerConnection {
    /// A UDP host candidate the application added (`candidate_value`), on the active
    /// transport: its base is where that transport's DTLS links start (RFC 7350). Whether ICE
    /// took the candidate does not matter (with the `relay` policy it does not): the socket is
    /// the application's either way.
    pub(crate) fn note_udp_base_for_turn(&mut self, candidate_value: &str) {
        if !self.streams.turn.enabled || self.is_closed() {
            return;
        }
        let Ok(candidate) = ice::candidate::unmarshal_candidate(candidate_value) else {
            return;
        };
        if candidate.candidate_type() != ice::candidate::CandidateType::Host
            || candidate.network_type().is_tcp()
        {
            return;
        }
        let Ok(ip) = candidate.address().parse::<IpAddr>() else {
            return;
        };
        let on = self.pipeline_context.transports.active_id();
        self.streams
            .turn
            .note_udp_base(on, SocketAddr::new(ip, candidate.port()));
        self.start_turn_links();
    }

    /// The DTLS client configuration of a link to `host` (RFC 7350 section 4, RFC 8656
    /// section 3.1): the server's certificate is checked against the URI's host with the roots
    /// or the verifier of `with_turn_tls`; only forward-secret AEAD suites (BCP 195, RFC 7350
    /// 4-2: TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 among them). `None` when nothing could
    /// verify a server.
    fn turn_dtls_config(&self, host: &str) -> Option<Arc<dtls::config::HandshakeConfig>> {
        use dtls::cipher_suite::CipherSuiteId;
        let provider = self.setting_engine.crypto_provider.clone()?;
        let tls = self.streams.turn.tls_config();
        let mut builder = dtls::config::ConfigBuilder::default()
            .with_crypto_provider(provider)
            .with_server_name(host.to_owned())
            .with_cipher_suites(vec![
                CipherSuiteId::Tls_Ecdhe_Ecdsa_With_Aes_128_Gcm_Sha256,
                CipherSuiteId::Tls_Ecdhe_Rsa_With_Aes_128_Gcm_Sha256,
                CipherSuiteId::Tls_Ecdhe_Ecdsa_With_ChaCha20_Poly1305_Sha256,
                CipherSuiteId::Tls_Ecdhe_Rsa_With_ChaCha20_Poly1305_Sha256,
                CipherSuiteId::Tls_Aes_128_Gcm_Sha256,
                CipherSuiteId::Tls_Aes_256_Gcm_Sha384,
                CipherSuiteId::Tls_ChaCha20_Poly1305_Sha256,
            ])
            .with_extended_master_secret(dtls::config::ExtendedMasterSecretType::Request);
        if let Some(verifier) = &tls.verifier {
            builder = builder.with_server_cert_verifier(verifier.clone());
        } else if let Some(roots) = &tls.roots {
            builder = builder.with_roots_cas((**roots).clone());
        } else if tls.webpki_roots {
            #[cfg(feature = "turn-tls-webpki-roots")]
            {
                builder = builder.with_roots_cas(rustls::RootCertStore {
                    roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
                });
            }
            #[cfg(not(feature = "turn-tls-webpki-roots"))]
            {
                return None;
            }
        } else {
            return None;
        }
        if tls.disable_tls12 {
            builder = builder.with_protocol_versions(
                dtls::config::DtlsVersion::Dtls1_3,
                dtls::config::DtlsVersion::Dtls1_3,
            );
        }
        match builder.build(true, None) {
            Ok(config) => Some(Arc::new(config)),
            Err(err) => {
                debug!("TURN DTLS configuration: {err}");
                None
            }
        }
    }

    /// Starts a DTLS handshake to `addr` for link `index`, from the transport's UDP base of
    /// that family. Returns whether it started; a link nothing can verify has failed.
    fn start_dtls_attempt(&mut self, now: Instant, index: usize, addr: SocketAddr) -> bool {
        let (transport, host) = {
            let l = &self.streams.turn.links[index];
            (l.transport, l.url.host.clone())
        };
        let Some(base) = self.streams.turn.udp_base(transport, addr) else {
            debug!("TURN over DTLS to {addr}: no UDP base of that family");
            return false;
        };
        let Some(config) = self.turn_dtls_config(&host) else {
            debug!("turns: DTLS server without roots or a verifier to check it: not used");
            self.streams.turn.links[index].state = LinkState::Failed;
            return false;
        };
        let mut endpoint = dtls::endpoint::Endpoint::new(base, TransportProtocol::UDP, None);
        if let Err(err) = endpoint.connect(now, addr, config, None) {
            debug!("TURN over DTLS to {addr}: {err}");
            return false;
        }
        let mut attempt = DtlsAttempt {
            remote: addr,
            base,
            endpoint,
        };
        attempt.flush(&mut self.pipeline_context.write_outs);
        self.streams.turn.links[index].dtls_attempts.push(attempt);
        true
    }

    /// Takes a datagram of a DTLS link (from a server's address to the base an association
    /// runs on) before ICE sees it; returns anything else.
    pub(crate) fn take_turn_dtls(&mut self, msg: TaggedBytesMut) -> Option<TaggedBytesMut> {
        if msg.transport.transport_protocol != TransportProtocol::UDP
            || !msg.message.first().is_some_and(|b| (20..=63).contains(b))
        {
            return Some(msg);
        }
        let (base, remote) = (msg.transport.local_addr, msg.transport.peer_addr);
        let Some(index) = self.streams.turn.link_of_dtls(base, remote) else {
            return Some(msg);
        };
        let now = msg.now;
        let won = self.streams.turn.links[index]
            .dtls
            .as_ref()
            .is_some_and(|a| a.base == base && a.remote == remote);
        let link = &mut self.streams.turn.links[index];
        let Some(attempt) = link.dtls_to(base, remote) else {
            return Some(msg);
        };
        let result = attempt
            .endpoint
            .read(now, remote, msg.transport.ecn, msg.message);
        attempt.flush(&mut self.pipeline_context.write_outs);
        match result {
            Err(err) => {
                debug!("TURN over DTLS from {remote}: {err}");
                let failed = attempt.endpoint.is_connection_failed(&remote)
                    || attempt.endpoint.get_connection_state(remote).is_none();
                if failed {
                    self.turn_dtls_ended(now, index, base, remote, won);
                }
            }
            Ok(events) => {
                for event in events {
                    match event {
                        dtls::endpoint::EndpointEvent::HandshakeComplete if !won => {
                            self.turn_dtls_won(now, index, base, remote);
                        }
                        dtls::endpoint::EndpointEvent::ApplicationData(data) => {
                            let link = &mut self.streams.turn.links[index];
                            if let Some(client) = link.client.as_mut()
                                && let Err(err) = client.handle_read(TaggedBytesMut {
                                    now,
                                    transport: TransportContext {
                                        local_addr: base,
                                        peer_addr: remote,
                                        transport_protocol: TransportProtocol::UDP,
                                        ecn: None,
                                    },
                                    message: data,
                                })
                            {
                                debug!("TURN message from {remote}: {err}");
                            }
                        }
                        dtls::endpoint::EndpointEvent::PeerClosed => {
                            self.turn_dtls_ended(now, index, base, remote, won);
                        }
                        _ => {}
                    }
                }
            }
        }
        self.pump_turn(now);
        None
    }

    /// A DTLS handshake of link `index` completed: the race is won, the TURN client starts
    /// over the association, with UDP's retransmissions (RFC 7350 section 4).
    fn turn_dtls_won(&mut self, now: Instant, index: usize, base: SocketAddr, remote: SocketAddr) {
        let link = &mut self.streams.turn.links[index];
        if link.state != LinkState::Connecting {
            return;
        }
        let Some(position) = link
            .dtls_attempts
            .iter()
            .position(|a| a.base == base && a.remote == remote)
        else {
            return;
        };
        let winner = link.dtls_attempts.remove(position);
        for mut loser in std::mem::take(&mut link.dtls_attempts) {
            let r = loser.remote;
            let _ = loser.endpoint.stop(now, r);
            loser.flush(&mut self.pipeline_context.write_outs);
        }
        if let Some(race) = link.race.as_mut() {
            race.succeeded();
        }
        link.dtls = Some(winner);
        link.state = LinkState::OpenDtls;
        link.server = Some(remote);
        link.link_local = Some(base);
        let Some(provider) = self.setting_engine.crypto_provider.clone() else {
            link.state = LinkState::Failed;
            return;
        };
        let config = turn::client::ClientConfig {
            stun_serv_addr: remote.to_string(),
            turn_serv_addr: remote.to_string(),
            local_addr: base,
            transport_protocol: TransportProtocol::UDP,
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
    }

    /// A DTLS association of link `index` failed or was closed: a racing one fails its
    /// address; the one that won takes the allocation with it.
    fn turn_dtls_ended(
        &mut self,
        now: Instant,
        index: usize,
        base: SocketAddr,
        remote: SocketAddr,
        won: bool,
    ) {
        if won {
            debug!("TURN over DTLS to {remote} ended: its allocation is gone");
            // RFC 6544 section 11.2: "Similar measures SHOULD apply also to other types of
            // relaying servers".
            self.turn_allocation_lost(now, index);
            return;
        }
        let link = &mut self.streams.turn.links[index];
        link.dtls_attempts
            .retain(|a| !(a.base == base && a.remote == remote));
        if link.state == LinkState::Connecting {
            if let Some(race) = link.race.as_mut() {
                race.failed();
            }
            self.drive_turn_races(now);
        }
    }

    /// The DTLS associations' timers: handshake retransmissions and give-up.
    fn turn_dtls_timeouts(&mut self, now: Instant) {
        let mut ended = vec![];
        for (index, link) in self.streams.turn.links.iter_mut().enumerate() {
            let won = link.dtls.as_mut().map(|a| (a, true));
            let racing = link.dtls_attempts.iter_mut().map(|a| (a, false));
            for (a, won) in won.into_iter().chain(racing) {
                let remote = a.remote;
                if !a.endpoint.poll_timeout(&remote).is_some_and(|t| t <= now) {
                    continue;
                }
                let result = a.endpoint.handle_timeout(remote, now);
                a.flush(&mut self.pipeline_context.write_outs);
                if let Err(err) = result {
                    debug!("TURN over DTLS to {remote}: {err}");
                    ended.push((index, a.base, remote, won));
                }
            }
        }
        for (index, base, remote, won) in ended {
            self.turn_dtls_ended(now, index, base, remote, won);
        }
    }

    /// `close()`: every DTLS association says close_notify.
    pub(crate) fn close_turn_dtls(&mut self) {
        let now = self.pipeline_context.now;
        for link in self.streams.turn.links.iter_mut() {
            for a in link.dtls.iter_mut().chain(link.dtls_attempts.iter_mut()) {
                let _ = a.endpoint.close(now);
                a.flush(&mut self.pipeline_context.write_outs);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 8656 section 3.1, RFC 7350 section 4.1: `turn:...?transport=tcp` (TCP), `turns:`
    /// (TLS over TCP) and `turns:...?transport=udp` (DTLS) servers get a link per transport;
    /// a `turn:` server over UDP stays the application's.
    #[test]
    fn turn_servers_over_tcp_tls_and_dtls_get_a_link_and_over_udp_none() {
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
        // The TCP allocations beside: `a_tcp_or_tls_server_gets_a_tcp_allocation_link_too`.
        turn.tcp_relay = false;
        assert!(
            turn.links.is_empty(),
            "no link before a transport needs one"
        );
        let first = TransportId::default();
        turn.make_links(first);
        turn.make_links(first);
        let links: Vec<(String, RTCIceServerTransportProtocol)> = turn
            .links
            .iter()
            .map(|l| (l.url_string(), l.protocol()))
            .collect();
        assert_eq!(
            links,
            vec![
                (
                    "turn:192.0.2.1:3478?transport=tcp".to_owned(),
                    RTCIceServerTransportProtocol::Tcp
                ),
                (
                    "turns:turn.example:5349?transport=tcp".to_owned(),
                    RTCIceServerTransportProtocol::Tls
                ),
                (
                    "turns:192.0.2.1:5349?transport=tcp".to_owned(),
                    RTCIceServerTransportProtocol::Tls
                ),
                (
                    "turns:192.0.2.1:5349?transport=udp".to_owned(),
                    RTCIceServerTransportProtocol::Dtls
                ),
            ]
        );
        // Nothing started: nothing pending for the end of gathering.
        assert!(!turn.pending(first, true));
        // Another transport gets links of its own, once.
        turn.make_links(TransportId(1));
        assert_eq!(turn.links.len(), 8);
        assert!(
            turn.links[4..]
                .iter()
                .all(|l| l.transport == TransportId(1))
        );
    }

    /// RFC 6062 section 4.1 with RFC 6544 section 5.5: a server over TCP or TLS gets a second
    /// link for a TCP allocation (its own control connection: an allocation is its 5-tuple's);
    /// one over DTLS none (a TCP allocation needs TCP or TLS to the server).
    #[test]
    fn a_tcp_or_tls_server_gets_a_tcp_allocation_link_too() {
        let urls: Vec<Url> = [
            "turn:192.0.2.1:3478?transport=tcp",
            "turns:192.0.2.1:5349?transport=tcp",
            "turns:192.0.2.1:5349?transport=udp",
        ]
        .iter()
        .map(|u| Url::parse_url(u).unwrap())
        .collect();
        let mut turn = EngineTurn::new(&urls, true, TurnTlsConfig::default());
        turn.make_links(TransportId::default());
        let links: Vec<(RTCIceServerTransportProtocol, bool)> = turn
            .links
            .iter()
            .map(|l| (l.protocol(), l.relay_tcp))
            .collect();
        assert_eq!(
            links,
            vec![
                (RTCIceServerTransportProtocol::Tcp, false),
                (RTCIceServerTransportProtocol::Tcp, true),
                (RTCIceServerTransportProtocol::Tls, false),
                (RTCIceServerTransportProtocol::Tls, true),
                (RTCIceServerTransportProtocol::Dtls, false),
            ]
        );
    }
}
