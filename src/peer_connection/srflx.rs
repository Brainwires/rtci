//! Server-reflexive candidates gathered by the engine (RFC 8445 section 5.1.1.2): a STUN
//! Binding request to each `stun:` / `stuns:` server of the configuration, from each host
//! candidate's base, on each transport (RFC 9429 section 5.2.1).
//!
//! - Over UDP, from every UDP host candidate the application adds: the request leaves through
//!   `poll_write` from the candidate's address and the response is taken out of `handle_read`
//!   before ICE sees it (by its transaction id). Retransmissions follow RFC 8489 section
//!   6.2.1 (`rtc_stun::client`).
//! - Over TCP and TLS (`stun:` and `stuns:`, RFC 7064), from the engine's passive and
//!   simultaneous-open ICE-TCP candidates: a connection from the listener's own port
//!   (`reuse_address`, RFC 6544 Appendix B) carries one Binding request, sent once and
//!   failed after Ti (RFC 8489 section 6.2.2); over TLS the server's certificate is checked
//!   as for TURN (RFC 8489 section 6.2.3, ALPN `stun.nat-discovery`, RFC 7443). The mapped
//!   address is a server-reflexive passive or simultaneous-open candidate, and its address
//!   on port 9 a server-reflexive active one (RFC 6544 section 5.2).
//!
//! A server's name is resolved through the driver ([`StreamCommand::Resolve`]); the
//! addresses race with Happy Eyeballs (RFC 8305, RFC 8656 section 3.9), a Binding
//! transaction per address started every Connection Attempt Delay, the first answer winning.
//! New transactions start no faster than one every Ta (RFC 8445 section 5.1.1.2). The end of
//! gathering waits for every probe to be answered or to fail.
//!
//! [`StreamCommand::Resolve`]: shared::stream::StreamCommand::Resolve

use super::RTCPeerConnection;
use super::streams::{SRFLX, tcp_context};
use super::turn_tls::TlsLayer;
use crate::peer_connection::handler::transport_set::TransportId;
use bytes::BytesMut;
use ice::candidate::CandidateConfig;
use ice::candidate::candidate_server_reflexive::CandidateServerReflexiveConfig;
use ice::tcp_type::TcpType;
use ice::url::{SchemeType, Url};
use log::debug;
use sansio::Protocol;
use shared::stream::happy_eyeballs::{CONNECTION_ATTEMPT_DELAY, HappyEyeballs, sort_addresses};
use shared::stream::{Framing, StreamId, StreamLayer};
use shared::{TaggedBytesMut, TransportProtocol};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};
use stun::agent::StunEvent;
use stun::client::{Client, ClientBuilder, TaggedMessage};
use stun::message::{BINDING_REQUEST, CLASS_SUCCESS_RESPONSE, Getter, Message, Setter};
use stun::xoraddr::XorMappedAddress;

/// The ALPN protocol id of STUN NAT discovery over TLS (RFC 7443 section 3).
pub const ALPN_STUN_NAT_DISCOVERY: &[u8] = b"stun.nat-discovery";

/// RFC 8445 section 14.2: the default pacing of gathering transactions.
const TA: Duration = Duration::from_millis(50);

/// The port an active TCP candidate is signalled with (RFC 6544 section 4.5).
const ACTIVE_PORT: u16 = 9;

/// Who gathers server-reflexive candidates. See
/// `SettingEngineBuilder::with_server_reflexive_gathering`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum ReflexiveGathering {
    /// The engine, from the configuration's `stun:` / `stuns:` servers (RFC 8445 section
    /// 5.1.1.2: gathering is implemented and on unless configured off). A base for which the
    /// application adds a server-reflexive candidate itself is left to it.
    #[default]
    Engine,
    /// The application: the engine sends no Binding request to a server.
    Application,
}

/// What a probe's mapped address becomes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Base {
    /// A UDP host candidate's address.
    Udp,
    /// A passive or simultaneous-open ICE-TCP listener's address.
    Tcp(TcpType),
}

/// One Binding transaction to one address of the server.
struct Attempt {
    server: SocketAddr,
    client: Client,
    /// The request's transaction id.
    transaction: [u8; 12],
    /// The connection, over TCP / TLS.
    stream: Option<StreamId>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProbeState {
    Pending,
    /// NAPTR / SRV records are being looked up (a URI without a port, RFC 8489 section 8).
    Discovering(u64),
    Resolving(u64),
    Racing,
    Done,
}

/// One server-reflexive candidate on its way: a base, a server, a transport.
struct Probe {
    transport: TransportId,
    base: SocketAddr,
    kind: Base,
    url: Url,
    tls: bool,
    state: ProbeState,
    race: Option<HappyEyeballs>,
    attempts: Vec<Attempt>,
    /// The name's query, while its answers may still come.
    query: Option<u64>,
    /// The address the server reported.
    mapped: Option<SocketAddr>,
    /// The SRV discovery of a server whose URI gives no port.
    discovery: Option<crate::peer_connection::dns_discovery::Discovery>,
}

impl Probe {
    fn url_string(&self) -> String {
        let host = if self.url.host.contains(':') {
            format!("[{}]", self.url.host)
        } else {
            self.url.host.clone()
        };
        let scheme = if self.tls { "stuns" } else { "stun" };
        format!("{scheme}:{host}:{}", self.url.port)
    }
}

/// The engine's server-reflexive gathering.
pub(crate) struct EngineSrflx {
    servers: Vec<Url>,
    pub(crate) mode: ReflexiveGathering,
    probes: Vec<Probe>,
    tls_config: Option<Arc<rustls::ClientConfig>>,
    /// Bases the application gathers server-reflexive candidates for itself.
    application_bases: Vec<SocketAddr>,
    /// When the last transaction started (Ta pacing).
    last_start: Option<Instant>,
    /// Mapped addresses announced: transport, address, base kind, ICE ufrag.
    announced: Vec<(TransportId, SocketAddr, Base, String)>,
}

impl EngineSrflx {
    pub(crate) fn new(
        urls: &[Url],
        mode: ReflexiveGathering,
        tls: Option<Arc<rustls::ClientConfig>>,
    ) -> Self {
        let servers = urls
            .iter()
            .filter(|u| matches!(u.scheme, SchemeType::Stun | SchemeType::Stuns))
            .cloned()
            .collect();
        let tls_config = tls.map(|config| {
            let mut config = (*config).clone();
            config.alpn_protocols = vec![ALPN_STUN_NAT_DISCOVERY.to_vec()];
            Arc::new(config)
        });
        Self {
            servers,
            mode,
            probes: vec![],
            tls_config,
            application_bases: vec![],
            last_start: None,
            announced: vec![],
        }
    }

    /// Whether a probe of `transport` is still on its way. A name waits for the driver only
    /// when one serves the stream interface (`resolving_counts`).
    pub(crate) fn pending(&self, transport: TransportId, resolving_counts: bool) -> bool {
        self.probes.iter().any(|p| {
            p.transport == transport
                && match p.state {
                    ProbeState::Pending | ProbeState::Racing => true,
                    ProbeState::Resolving(_) | ProbeState::Discovering(_) => resolving_counts,
                    ProbeState::Done => false,
                }
        })
    }

    /// Probes from `base` on `transport`, one per server; returns what earlier probes from it
    /// found (a new ICE generation announces them again).
    fn add(
        &mut self,
        transport: TransportId,
        base: SocketAddr,
        kind: Base,
    ) -> Vec<(SocketAddr, String)> {
        let mut found = vec![];
        if self.mode != ReflexiveGathering::Engine || self.application_bases.contains(&base) {
            return found;
        }
        for url in &self.servers {
            let tls = url.scheme == SchemeType::Stuns;
            // `stuns:` is TLS over TCP (RFC 7064); STUN over DTLS is not run here.
            if tls && kind == Base::Udp {
                continue;
            }
            if let Some(p) = self.probes.iter().find(|p| {
                p.transport == transport && p.base == base && p.url.to_string() == url.to_string()
            }) {
                if let Some(mapped) = p.mapped {
                    found.push((mapped, p.url_string()));
                }
                continue;
            }
            self.probes.push(Probe {
                transport,
                base,
                kind,
                url: url.clone(),
                tls,
                state: ProbeState::Pending,
                race: None,
                attempts: vec![],
                query: None,
                mapped: None,
                discovery: None,
            });
        }
        found
    }

    /// The application gathers for `base` itself: the engine's probes from it stop.
    pub(crate) fn application_gathers(&mut self, base: SocketAddr) {
        if !self.application_bases.contains(&base) {
            self.application_bases.push(base);
        }
        for p in self.probes.iter_mut().filter(|p| p.base == base) {
            p.state = ProbeState::Done;
            p.attempts.clear();
        }
    }

    fn probe_of_stream(&self, id: StreamId) -> Option<(usize, usize)> {
        self.probes.iter().enumerate().find_map(|(i, p)| {
            p.attempts
                .iter()
                .position(|a| a.stream == Some(id))
                .map(|j| (i, j))
        })
    }
}

/// A Binding request (RFC 8489 section 6; no attribute an RFC 5389 server would not know).
fn binding_request() -> shared::error::Result<Message> {
    let mut message = Message::new();
    let setters: Vec<Box<dyn Setter>> = vec![
        Box::new(stun::message::TransactionId::new()),
        Box::new(BINDING_REQUEST),
    ];
    message.build(&setters)?;
    Ok(message)
}

/// The reflexive address a success response carries: XOR-MAPPED-ADDRESS, or MAPPED-ADDRESS
/// from a server of RFC 3489 (RFC 8489 section 5, backwards compatibility).
fn mapped_address(response: &Message) -> Option<SocketAddr> {
    if response.typ.class != CLASS_SUCCESS_RESPONSE {
        return None;
    }
    let mut xor = XorMappedAddress::default();
    if xor.get_from(response).is_ok() {
        return Some(SocketAddr::new(xor.ip, xor.port));
    }
    let mut plain = stun::addr::MappedAddress::default();
    plain
        .get_from(response)
        .ok()
        .map(|()| SocketAddr::new(plain.ip, plain.port))
}

impl RTCPeerConnection {
    /// Whether the engine gathers server-reflexive candidates at all: servers are configured,
    /// it is asked to, and the policy allows them.
    fn srflx_wanted(&self) -> bool {
        !self.streams.srflx.servers.is_empty()
            && self.streams.srflx.mode == ReflexiveGathering::Engine
            && !self.setting_engine.candidates.ice_lite
            && self.configuration.ice_transport_policy
                != crate::peer_connection::configuration::RTCIceTransportPolicy::Relay
            && !self.is_closed()
    }

    /// Probes for a UDP host candidate the application just added (`candidate_value`) on the
    /// active transport; a server-reflexive candidate the application adds marks its base as
    /// the application's.
    pub(crate) fn gather_srflx_for(&mut self, candidate_value: &str) {
        let Ok(candidate) = ice::candidate::unmarshal_candidate(candidate_value) else {
            return;
        };
        match candidate.candidate_type() {
            ice::candidate::CandidateType::ServerReflexive => {
                // The engine's own, coming back through a transport's path.
                let own = self
                    .streams
                    .srflx
                    .announced
                    .iter()
                    .any(|(_, mapped, _, _)| *mapped == candidate.addr());
                if !own
                    && let Some(related) = candidate.related_address()
                    && let Ok(ip) = related.address.parse::<IpAddr>()
                {
                    self.streams
                        .srflx
                        .application_gathers(SocketAddr::new(ip, related.port));
                }
                return;
            }
            ice::candidate::CandidateType::Host if !candidate.network_type().is_tcp() => {}
            _ => return,
        }
        if !self.srflx_wanted() {
            return;
        }
        let on = self.pipeline_context.transports.active_id();
        let base = candidate.addr();
        let accepted = self
            .ice_transport()
            .agent
            .get_local_candidates()
            .iter()
            .any(|c| c.addr() == base && !c.network_type().is_tcp());
        if accepted {
            for (mapped, url) in self.streams.srflx.add(on, base, Base::Udp) {
                self.announce_srflx(on, base, Base::Udp, mapped, &url);
            }
            self.drive_srflx(self.pipeline_context.now);
        }
    }

    /// Probes over TCP / TLS from an engine ICE-TCP listener that is now bound.
    pub(crate) fn gather_srflx_tcp(
        &mut self,
        transport: TransportId,
        base: SocketAddr,
        tcp_type: TcpType,
    ) {
        if !self.srflx_wanted() || tcp_type == TcpType::Active {
            return;
        }
        for (mapped, url) in self.streams.srflx.add(transport, base, Base::Tcp(tcp_type)) {
            self.announce_tcp_srflx(transport, base, tcp_type, mapped, &url);
        }
        self.drive_srflx(self.pipeline_context.now);
    }

    /// Starts what is due: names to resolve, races to start, transactions at most one per Ta.
    pub(crate) fn drive_srflx(&mut self, now: Instant) {
        let ids = self.pipeline_context.transports.ids();
        self.streams
            .srflx
            .probes
            .retain(|p| ids.contains(&p.transport));
        for index in 0..self.streams.srflx.probes.len() {
            let probe = &mut self.streams.srflx.probes[index];
            if probe.state != ProbeState::Pending {
                continue;
            }
            match probe.url.host.parse::<IpAddr>() {
                Ok(ip) => {
                    probe.race = Some(HappyEyeballs::new(
                        vec![SocketAddr::new(ip, probe.url.port)],
                        CONNECTION_ATTEMPT_DELAY,
                    ));
                    probe.state = ProbeState::Racing;
                }
                // RFC 8489 section 8 / RFC 7064 section 3.2: without a port, SRV finds it.
                Err(_) if !probe.url.explicit_port => {
                    let srv = match (probe.kind, probe.tls) {
                        (Base::Udp, _) => "_stun._udp",
                        (_, false) => "_stun._tcp",
                        (_, true) => "_stuns._tcp",
                    };
                    let discovery = crate::peer_connection::dns_discovery::Discovery::new(
                        &probe.url.host,
                        probe.url.port,
                        None,
                        srv,
                    );
                    let first = discovery.start();
                    probe.discovery = Some(discovery);
                    self.srflx_discovery_next(index, first, now);
                }
                Err(_) => {
                    let (host, port) = (probe.url.host.clone(), probe.url.port);
                    let query = self.streams.table.resolve(host, port);
                    let probe = &mut self.streams.srflx.probes[index];
                    probe.state = ProbeState::Resolving(query);
                    probe.query = Some(query);
                }
            }
        }
        for index in 0..self.streams.srflx.probes.len() {
            if self.streams.srflx.probes[index].state != ProbeState::Racing {
                continue;
            }
            loop {
                if self
                    .streams
                    .srflx
                    .last_start
                    .is_some_and(|last| now < last + TA)
                {
                    break;
                }
                let base_ip = self.streams.srflx.probes[index].base.ip();
                let Some(server) = self.streams.srflx.probes[index]
                    .race
                    .as_mut()
                    .and_then(|r| r.next_attempt(now))
                else {
                    break;
                };
                // A server of the other family cannot be reached from this base.
                if server.is_ipv4() != base_ip.is_ipv4() {
                    if let Some(r) = self.streams.srflx.probes[index].race.as_mut() {
                        r.failed();
                    }
                    continue;
                }
                self.streams.srflx.last_start = Some(now);
                self.start_srflx_attempt(now, index, server);
            }
            let probe = &mut self.streams.srflx.probes[index];
            if probe.race.as_ref().is_some_and(HappyEyeballs::exhausted) {
                // The next SRV target, when there is one (RFC 2782).
                if let Some(next) = probe.discovery.as_mut().map(|d| d.next_target()) {
                    self.srflx_discovery_next(index, next, now);
                } else {
                    debug!(
                        "{}: no server-reflexive address from {}",
                        probe.url, probe.base
                    );
                    probe.state = ProbeState::Done;
                }
            }
        }
        self.finish_deferred_gathering();
    }

    fn start_srflx_attempt(&mut self, now: Instant, index: usize, server: SocketAddr) {
        let (base, kind, tls, host) = {
            let p = &self.streams.srflx.probes[index];
            (p.base, p.kind, p.tls, p.url.host.clone())
        };
        let protocol = if kind == Base::Udp {
            TransportProtocol::UDP
        } else {
            TransportProtocol::TCP
        };
        let started = (|| -> shared::error::Result<Attempt> {
            let mut client = ClientBuilder::new().build(now, base, server, protocol)?;
            let request = binding_request()?;
            let transaction = request.transaction_id.0;
            client.handle_write(TaggedMessage {
                now,
                message: request,
            })?;
            let stream = if kind == Base::Udp {
                None
            } else {
                let layer: Option<Box<dyn StreamLayer>> = if tls {
                    let config = self.streams.srflx.tls_config.clone().ok_or_else(|| {
                        shared::error::Error::Other(
                            "stuns: server without roots or a verifier to check it".to_owned(),
                        )
                    })?;
                    Some(Box::new(TlsLayer::new(config, &host)?))
                } else {
                    None
                };
                // RFC 6544 Appendix B: from the candidate's own port, beside its listener.
                Some(
                    self.streams
                        .table
                        .connect(base, server, Framing::Turn, SRFLX, true, layer)?,
                )
            };
            Ok(Attempt {
                server,
                client,
                transaction,
                stream,
            })
        })();
        match started {
            Ok(attempt) => {
                self.streams.srflx.probes[index].attempts.push(attempt);
                self.pump_srflx_attempt(
                    now,
                    index,
                    self.streams.srflx.probes[index].attempts.len() - 1,
                );
            }
            Err(err) => {
                debug!("Binding request to {server} from {base}: {err}");
                if let Some(r) = self.streams.srflx.probes[index].race.as_mut() {
                    r.failed();
                }
            }
        }
    }

    /// Sends what an attempt's client has to send and acts on its events.
    fn pump_srflx_attempt(&mut self, now: Instant, index: usize, attempt: usize) {
        let mut outcome: Option<Option<SocketAddr>> = None;
        {
            let probe = &mut self.streams.srflx.probes[index];
            let a = &mut probe.attempts[attempt];
            while let Some(transmit) = a.client.poll_write() {
                match a.stream {
                    None => self.pipeline_context.write_outs.push_back(transmit),
                    Some(id) => {
                        let _ = self.streams.table.send(id, &transmit.message);
                    }
                }
            }
            while let Some(event) = a.client.poll_event() {
                outcome = Some(match event {
                    StunEvent::Message(response) => {
                        let mapped = mapped_address(&response);
                        if mapped.is_none() {
                            debug!("{}: Binding error or no mapped address", a.server);
                        }
                        mapped
                    }
                    other => {
                        debug!("{}: Binding transaction ended: {other:?}", a.server);
                        None
                    }
                });
            }
        }
        match outcome {
            None => {}
            Some(Some(mapped)) => self.srflx_won(now, index, attempt, mapped),
            Some(None) => self.srflx_attempt_failed(now, index, attempt),
        }
    }

    fn srflx_attempt_failed(&mut self, now: Instant, index: usize, attempt: usize) {
        let a = self.streams.srflx.probes[index].attempts.remove(attempt);
        if let Some(id) = a.stream {
            self.streams.table.close(id);
        }
        if let Some(r) = self.streams.srflx.probes[index].race.as_mut() {
            r.failed();
        }
        self.drive_srflx(now);
    }

    /// The first answer: the race is over, the candidate is announced.
    fn srflx_won(&mut self, now: Instant, index: usize, attempt: usize, mapped: SocketAddr) {
        let probe = &mut self.streams.srflx.probes[index];
        if let Some(r) = probe.race.as_mut() {
            r.succeeded();
        }
        probe.state = ProbeState::Done;
        probe.mapped = Some(mapped);
        let winner = probe.attempts.remove(attempt);
        let losers: Vec<Attempt> = std::mem::take(&mut probe.attempts);
        let (transport, base, kind, url) =
            (probe.transport, probe.base, probe.kind, probe.url_string());
        for a in losers.iter().chain(std::iter::once(&winner)) {
            // RFC 8489 section 6.2.2: the client closes the connection once it is done.
            if let Some(id) = a.stream {
                self.streams.table.close(id);
            }
        }
        match kind {
            Base::Udp => self.announce_srflx(transport, base, kind, mapped, &url),
            Base::Tcp(tcp_type) => self.announce_tcp_srflx(transport, base, tcp_type, mapped, &url),
        }
        self.drive_srflx(now);
    }

    /// A passive or simultaneous-open server-reflexive candidate, and (RFC 6544 section 5.2)
    /// an active one on the same address, its base the host active candidate.
    fn announce_tcp_srflx(
        &mut self,
        transport: TransportId,
        base: SocketAddr,
        tcp_type: TcpType,
        mapped: SocketAddr,
        url: &str,
    ) {
        self.announce_srflx(transport, base, Base::Tcp(tcp_type), mapped, url);
        self.announce_srflx(
            transport,
            SocketAddr::new(base.ip(), ACTIVE_PORT),
            Base::Tcp(TcpType::Active),
            SocketAddr::new(mapped.ip(), ACTIVE_PORT),
            url,
        );
    }

    fn announce_srflx(
        &mut self,
        transport: TransportId,
        base: SocketAddr,
        kind: Base,
        mapped: SocketAddr,
        url: &str,
    ) {
        let ufrag = self
            .ice_transport_of(transport)
            .agent
            .get_local_credentials()
            .ufrag
            .clone();
        let key = (transport, mapped, kind, ufrag);
        // RFC 8445 section 5.1.3: one equal to its base (no NAT) is redundant.
        if mapped == base || self.streams.srflx.announced.contains(&key) {
            return;
        }
        self.streams.srflx.announced.push(key);
        let network = if kind == Base::Udp { "udp" } else { "tcp" };
        let candidate = CandidateServerReflexiveConfig {
            base_config: CandidateConfig {
                network: network.to_owned(),
                address: mapped.ip().to_string(),
                port: mapped.port(),
                component: 1,
                ..Default::default()
            },
            rel_addr: base.ip().to_string(),
            rel_port: base.port(),
            url: Some(url.to_owned()),
        }
        .new_candidate_server_reflexive()
        .and_then(|mut c| {
            if let Base::Tcp(tcp_type) = kind {
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
                if let Err(err) =
                    self.add_engine_local_candidate(transport, &value, Some(url), None)
                {
                    debug!("server-reflexive candidate {mapped} not added: {err}");
                }
            }
            Err(err) => debug!("server-reflexive candidate {mapped} not made: {err}"),
        }
    }

    /// Takes a datagram that answers one of the engine's Binding requests over UDP; returns
    /// it otherwise, for ICE.
    pub(crate) fn take_srflx_response(&mut self, msg: TaggedBytesMut) -> Option<TaggedBytesMut> {
        if msg.transport.transport_protocol != TransportProtocol::UDP
            || msg.message.len() < 20
            || msg.message[0] & 0xc0 != 0
            || self.streams.srflx.probes.is_empty()
        {
            return Some(msg);
        }
        let (local, peer) = (msg.transport.local_addr, msg.transport.peer_addr);
        let found = self
            .streams
            .srflx
            .probes
            .iter()
            .enumerate()
            .find_map(|(i, p)| {
                if p.base != local {
                    return None;
                }
                p.attempts
                    .iter()
                    .position(|a| {
                        a.stream.is_none()
                            && a.server == peer
                            && msg.message[8..20] == a.transaction
                    })
                    .map(|j| (i, j))
            });
        let Some((index, attempt)) = found else {
            return Some(msg);
        };
        let now = msg.now;
        let a = &mut self.streams.srflx.probes[index].attempts[attempt];
        if let Err(err) = a.client.handle_read(msg) {
            debug!("Binding response from {peer}: {err}");
        }
        self.pump_srflx_attempt(now, index, attempt);
        None
    }

    /// Messages read on a Binding connection.
    pub(crate) fn srflx_messages(&mut self, now: Instant, id: StreamId, messages: Vec<Vec<u8>>) {
        let Some((index, attempt)) = self.streams.srflx.probe_of_stream(id) else {
            return;
        };
        {
            let a = &mut self.streams.srflx.probes[index].attempts[attempt];
            let context = tcp_context(a.client.local_addr(), a.server);
            for message in messages {
                if let Err(err) = a.client.handle_read(TaggedBytesMut {
                    now,
                    transport: context,
                    message: BytesMut::from(&message[..]),
                }) {
                    debug!("Binding response from {}: {err}", a.server);
                }
            }
        }
        self.pump_srflx_attempt(now, index, attempt);
    }

    /// A Binding connection could not be made or ended before its answer.
    pub(crate) fn srflx_connection_ended(&mut self, now: Instant, id: StreamId) {
        if let Some((index, attempt)) = self.streams.srflx.probe_of_stream(id) {
            self.streams.srflx.probes[index].attempts[attempt].stream = None;
            self.srflx_attempt_failed(now, index, attempt);
        }
    }

    /// A name resolved for a probe: all its addresses at once (`ipv6` `None`) or one family.
    /// Returns whether the query was a probe's.
    pub(crate) fn srflx_resolved(
        &mut self,
        query: u64,
        ipv6: Option<bool>,
        addresses: &[SocketAddr],
    ) -> bool {
        let now = self.pipeline_context.now;
        let mut ours = false;
        for probe in self.streams.srflx.probes.iter_mut() {
            let waiting = probe.query == Some(query)
                && (probe.state == ProbeState::Resolving(query)
                    || (probe.state == ProbeState::Racing
                        && probe.race.as_ref().is_some_and(HappyEyeballs::awaiting)));
            if !waiting {
                continue;
            }
            ours = true;
            match ipv6 {
                None => {
                    probe.query = None;
                    let sorted = sort_addresses(addresses, true);
                    probe.race = Some(HappyEyeballs::new(sorted, CONNECTION_ATTEMPT_DELAY));
                }
                Some(ipv6) => {
                    let race = probe.race.get_or_insert_with(|| {
                        HappyEyeballs::awaiting_answers(CONNECTION_ATTEMPT_DELAY)
                    });
                    race.answer(now, ipv6, addresses, true);
                }
            }
            probe.state = ProbeState::Racing;
        }
        if ours {
            self.drive_srflx(now);
        }
        ours
    }

    /// Acts on the next step of a probe's discovery.
    fn srflx_discovery_next(
        &mut self,
        index: usize,
        next: crate::peer_connection::dns_discovery::Next,
        now: Instant,
    ) {
        use crate::peer_connection::dns_discovery::Next;
        match next {
            Next::Records { name, kind } => {
                let query = self.streams.table.resolve_records(name, kind);
                let probe = &mut self.streams.srflx.probes[index];
                probe.state = ProbeState::Discovering(query);
                if let Some(d) = probe.discovery.as_mut() {
                    d.asked(query, now);
                }
            }
            Next::Address { host, port } => match host.parse::<IpAddr>() {
                Ok(ip) => {
                    let probe = &mut self.streams.srflx.probes[index];
                    probe.race = Some(HappyEyeballs::new(
                        vec![SocketAddr::new(ip, port)],
                        CONNECTION_ATTEMPT_DELAY,
                    ));
                    probe.state = ProbeState::Racing;
                }
                Err(_) => {
                    let query = self.streams.table.resolve(host, port);
                    let probe = &mut self.streams.srflx.probes[index];
                    probe.state = ProbeState::Resolving(query);
                    probe.query = Some(query);
                    probe.race = None;
                }
            },
            Next::Exhausted => self.streams.srflx.probes[index].state = ProbeState::Done,
        }
    }

    /// SRV records the driver looked up for a probe. Returns whether the query was a probe's.
    pub(crate) fn srflx_records(
        &mut self,
        query: u64,
        records: &[shared::stream::DnsRecord],
    ) -> bool {
        let now = self.pipeline_context.now;
        let Some(index) = self
            .streams
            .srflx
            .probes
            .iter()
            .position(|p| p.state == ProbeState::Discovering(query))
        else {
            return false;
        };
        let Some(next) = self.streams.srflx.probes[index]
            .discovery
            .as_mut()
            .map(|d| d.on_records(records))
        else {
            return false;
        };
        self.srflx_discovery_next(index, next, now);
        self.drive_srflx(now);
        true
    }

    /// The probes' next timer: a retransmission, Ti, the next attempt or the Ta gate.
    pub(crate) fn srflx_poll_timeout(&mut self) -> Option<Instant> {
        let mut next: Option<Instant> = None;
        let gate = self.streams.srflx.last_start.map(|last| last + TA);
        for probe in self.streams.srflx.probes.iter_mut() {
            if let ProbeState::Discovering(_) = probe.state
                && let Some(t) = probe.discovery.as_ref().and_then(|d| d.poll_timeout())
            {
                next = Some(next.map_or(t, |n| n.min(t)));
            }
            for a in probe.attempts.iter_mut() {
                if let Some(t) = a.client.poll_timeout() {
                    next = Some(next.map_or(t, |n| n.min(t)));
                }
            }
            if probe.state == ProbeState::Racing
                && let Some(race) = probe.race.as_ref()
            {
                // A first attempt held only by the Ta gate is due when the gate opens.
                let held = probe.attempts.is_empty() && !race.exhausted() && !race.awaiting();
                let due = race.poll_timeout().or(if held { gate } else { None });
                if let Some(t) = due {
                    let t = gate.map_or(t, |g| t.max(g));
                    next = Some(next.map_or(t, |n| n.min(t)));
                }
            }
        }
        next
    }

    /// Fires the probes' timers.
    pub(crate) fn srflx_handle_timeout(&mut self, now: Instant) {
        if self.streams.srflx.probes.is_empty() {
            return;
        }
        for index in 0..self.streams.srflx.probes.len() {
            for attempt in (0..self.streams.srflx.probes[index].attempts.len()).rev() {
                if index >= self.streams.srflx.probes.len()
                    || attempt >= self.streams.srflx.probes[index].attempts.len()
                {
                    continue;
                }
                let a = &mut self.streams.srflx.probes[index].attempts[attempt];
                if a.client.poll_timeout().is_some_and(|t| t <= now)
                    && let Err(err) = a.client.handle_timeout(now)
                {
                    debug!("Binding transaction timer: {err}");
                }
                self.pump_srflx_attempt(now, index, attempt);
            }
        }
        // A records query the driver did not answer counts as empty.
        let unanswered: Vec<u64> = self
            .streams
            .srflx
            .probes
            .iter()
            .filter_map(|p| match p.state {
                ProbeState::Discovering(q)
                    if p.discovery.as_ref().is_some_and(|d| d.timed_out(now)) =>
                {
                    Some(q)
                }
                _ => None,
            })
            .collect();
        for query in unanswered {
            self.srflx_records(query, &[]);
        }
        self.drive_srflx(now);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::peer_connection::RTCPeerConnectionBuilder;
    use crate::peer_connection::configuration::setting_engine::SettingEngineBuilder;
    use crate::peer_connection::configuration::{RTCConfigurationBuilder, RTCIceServer};
    use crate::peer_connection::event::RTCPeerConnectionEvent;
    use crate::peer_connection::transport::RTCIceCandidateInit;
    use crate::peer_connection::turn_tls::{TurnTlsConfig, rustls_provider};
    use shared::stream::{StreamCommand, StreamEvent};
    use std::io::{Read, Write};

    fn tls_server(name: &str) -> (Arc<rustls::ServerConfig>, Arc<rustls::RootCertStore>) {
        let key = rcgen::KeyPair::generate().unwrap();
        let cert = rcgen::CertificateParams::new(vec![name.to_owned()])
            .unwrap()
            .self_signed(&key)
            .unwrap();
        let der = cert.der().clone();
        let mut roots = rustls::RootCertStore::empty();
        roots.add(der.clone()).unwrap();
        let mut config = rustls::ServerConfig::builder_with_provider(rustls_provider().unwrap())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                vec![der],
                rustls::pki_types::PrivateKeyDer::Pkcs8(key.serialize_der().into()),
            )
            .unwrap();
        config.alpn_protocols = vec![ALPN_STUN_NAT_DISCOVERY.to_vec()];
        (Arc::new(config), Arc::new(roots))
    }

    /// RFC 7064 / RFC 8489 section 6.2.3: a `stuns:` server is asked over TLS from the
    /// passive listener's port, its certificate checked against the URI's host with the
    /// configured roots, ALPN `stun.nat-discovery` (RFC 7443); the mapped address is a
    /// server-reflexive TCP candidate carrying the `stuns:` URL. No UDP request goes to it.
    #[test]
    fn a_stuns_server_is_asked_over_tls_and_its_answer_is_a_tcp_candidate() {
        let now = Instant::now();
        let (server_config, roots) = tls_server("stun.rtc.test");
        let mut pc = RTCPeerConnectionBuilder::new()
            .with_configuration(
                RTCConfigurationBuilder::new()
                    .with_ice_servers(vec![RTCIceServer {
                        urls: vec!["stuns:stun.rtc.test:5349".to_owned()],
                        ..Default::default()
                    }])
                    .build(),
            )
            .with_setting_engine(
                SettingEngineBuilder::new()
                    .with_tcp_simultaneous_open(false)
                    .with_turn_tls(TurnTlsConfig {
                        roots: Some(roots),
                        ..Default::default()
                    })
                    .build(),
            )
            .build(now)
            .unwrap();
        pc.create_data_channel("stuns", None).unwrap();
        let offer = pc.create_offer(None).unwrap();
        pc.set_local_description(now, offer).unwrap();
        pc.add_local_candidate(RTCIceCandidateInit {
            candidate: "candidate:1 1 udp 2130706431 10.0.0.1 4000 typ host".to_owned(),
            ..Default::default()
        })
        .unwrap();
        let mut commands = vec![];
        let drain = |pc: &mut RTCPeerConnection, commands: &mut Vec<StreamCommand>| {
            while let Some(c) = pc.poll_stream_command() {
                commands.push(c);
            }
        };
        drain(&mut pc, &mut commands);
        assert!(
            pc.poll_write().is_none(),
            "no STUN over UDP to a stuns: server"
        );
        let listener = commands
            .iter()
            .find_map(|c| match c {
                StreamCommand::Listen { listener, .. } => Some(*listener),
                _ => None,
            })
            .unwrap();
        let bound: SocketAddr = "10.0.0.1:7000".parse().unwrap();
        pc.handle_stream_event(
            now,
            StreamEvent::Listening {
                listener,
                local: bound,
            },
        )
        .unwrap();
        drain(&mut pc, &mut commands);
        let query = commands
            .iter()
            .find_map(|c| match c {
                StreamCommand::Resolve { query, .. } => Some(*query),
                _ => None,
            })
            .expect("the server's name goes to the driver");
        let server: SocketAddr = "192.0.2.10:5349".parse().unwrap();
        pc.handle_stream_event(
            now,
            StreamEvent::Resolved {
                query,
                addresses: vec![server],
            },
        )
        .unwrap();
        drain(&mut pc, &mut commands);
        let id = commands
            .iter()
            .find_map(|c| match c {
                StreamCommand::Connect {
                    id,
                    local,
                    remote,
                    reuse_address: true,
                } if *local == bound && *remote == server => Some(*id),
                _ => None,
            })
            .expect("a connection from the listener's port");
        pc.handle_stream_event(now, StreamEvent::Connected { id, local: bound })
            .unwrap();

        let mut tls = rustls::ServerConnection::new(server_config).unwrap();
        let mut request = None;
        for _ in 0..20 {
            while let Some(t) = pc.poll_stream_transmit() {
                assert_eq!(t.id, id);
                tls.read_tls(&mut &t.data[..]).unwrap();
                tls.process_new_packets().unwrap();
            }
            let mut plain = vec![];
            let _ = tls.reader().read_to_end(&mut plain);
            if !plain.is_empty() {
                let mut m = Message::new();
                m.unmarshal_binary(&plain).unwrap();
                request = Some(m);
            }
            let mut out = vec![];
            while tls.wants_write() {
                tls.write_tls(&mut out).unwrap();
            }
            if !out.is_empty() {
                pc.handle_stream_read(now, id, &out).unwrap();
            }
            if request.is_some() {
                break;
            }
        }
        let request = request.expect("the Binding request over TLS");
        assert_eq!(request.typ, BINDING_REQUEST);
        assert_eq!(tls.alpn_protocol(), Some(ALPN_STUN_NAT_DISCOVERY));
        let mut response = Message::new();
        let setters: Vec<Box<dyn Setter>> = vec![
            Box::new(request.transaction_id),
            Box::new(stun::message::BINDING_SUCCESS),
            Box::new(XorMappedAddress {
                ip: "203.0.113.5".parse().unwrap(),
                port: 62000,
            }),
        ];
        response.build(&setters).unwrap();
        tls.writer().write_all(&response.raw).unwrap();
        let mut out = vec![];
        while tls.wants_write() {
            tls.write_tls(&mut out).unwrap();
        }
        pc.handle_stream_read(now, id, &out).unwrap();

        let mut found = None;
        while let Some(e) = pc.poll_event() {
            if let RTCPeerConnectionEvent::OnIceCandidateEvent(ev) = e
                && let Some(init) = ev.candidate.as_ref().and_then(|c| c.to_json().ok())
                && init.candidate.contains("typ srflx")
                && init.candidate.contains("tcptype passive")
            {
                found = Some((init.candidate, ev.url));
            }
        }
        let (candidate, url) = found.expect("a server-reflexive passive TCP candidate");
        assert!(
            candidate.contains("203.0.113.5 62000 typ srflx raddr 10.0.0.1 rport 7000"),
            "{candidate}"
        );
        assert_eq!(url.as_deref(), Some("stuns:stun.rtc.test:5349"));
    }
}
