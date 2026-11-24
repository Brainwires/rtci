//! A whole peer connection driven over sockets the driver owns (feature `peer`, on by
//! default): its UDP sockets for the ICE host candidates, and the TCP sockets of the engine's
//! stream interface through a [`StreamDriver`].
//!
//! [`PeerDriver`] gathers for the application and keeps the gathering right across what makes
//! a transport lose its candidates. The engine has no sockets, so it tells the application
//! with `RTCPeerConnectionEvent::OnLocalCandidatesNeeded` when a transport needs a new set of
//! local candidates: a new DTLS association over UDP runs on a new 3-tuple (RFC 8842 section
//! 5.1), so after an ICE restart for a new association (automatic SRTP re-keying included) or
//! on the transport that replaced one an answer closed, the transport's previous UDP addresses
//! are refused. The driver reacts by itself: it binds new UDP ports (inside
//! [`PeerDriverConfig::udp_port_range`], skipping ports the host refuses), adds their host
//! candidates for the event's section, ends the generation, and closes the previous sockets
//! only once a candidate pair on a new one is selected for that transport (and then after
//! [`PeerDriverConfig::retired_socket_linger`], for what the peer still sends there before its
//! own selection switches), or the transport is closed: until then the previous path keeps
//! carrying the transport's packets. The engine's
//! ICE-TCP listener is kept (RFC 8842 asks a new 3-tuple of unordered transports only), and
//! its server-reflexive and TURN gathering follow the new host candidates by themselves.
//!
//! With `SettingEngineBuilder::with_dtls_new_association_on_previous_addresses(true)` the
//! engine keeps the candidates and fires no event: the driver keeps its sockets and gives their
//! candidates to each new ICE generation again.
//!
//! # mDNS
//!
//! A connection with mDNS on (`SettingEngineBuilder::with_multicast_dns_mode`) publishes its
//! host addresses behind `.local` names and resolves the peer's: its ICE agents write their
//! mDNS datagrams from local port 5353. At the first one the driver binds the host's mDNS
//! sockets, port 5353 joined to 224.0.0.251 and, where the host has IPv6, to ff02::fb (shared
//! with other mDNS responders of the host through address reuse); it sends the connection's
//! queries, probes and answers there and hands what arrives back to the connection. A
//! connection without mDNS writes none, and the driver binds nothing.
//!
//! Every mDNS datagram takes one message from a budget shared by every driver of the process
//! ([`process_mdns_rate_limit`], unless [`PeerDriverConfig::mdns_rate_limit`] names another):
//! draft-ietf-mmusic-mdns-ice-candidates section 7.1 requires "an implementation-wide rate
//! limit" over the mDNS queries and responses of all connections. A datagram the budget refuses
//! waits in the driver and leaves, in order, when the budget has room.
//!
//! # The loop
//!
//! ```text
//! let mut driver = PeerDriver::new(pc, PeerDriverConfig::on(vec![ip]));
//! // offer / answer through the application's signalling, on driver.pc_mut();
//! // after the first local description, the driver gathers by itself;
//! loop {
//!     driver.step(Duration::from_millis(20)).await?;
//!     while let Some(event) = driver.poll_event() {
//!         // signal OnIceCandidateEvent candidates to the peer, answer negotiation-needed, ...
//!     }
//!     while let Some(read) = driver.pc_mut().poll_read() { /* media, data channels */ }
//! }
//! ```

use crate::mdns_io::{MDNS_MAX_DATAGRAM, MdnsEgress, mdns_v4, mdns_v6};
pub use crate::mdns_io::{MDNS_MULTICAST_IPV6, process_mdns_rate_limit};
use crate::runtime::{self, AsyncUdpSocket, JoinHandle, Runtime, Transmit};
use crate::sockets::{self, PortRange};
use crate::{DriverConfig, DriverInput, StreamDriver};
use bytes::BytesMut;
use rtci::mdns::{MDNS_PORT, MdnsRateLimit};
use rtci::peer_connection::RTCPeerConnection;
use rtci::peer_connection::event::{
    RTCLocalCandidatesNeededEvent, RTCLocalCandidatesNeededReason, RTCPeerConnectionEvent,
    RTCTransportEventKind,
};
use rtci::peer_connection::state::{RTCIceGatheringState, RTCSignalingState};
use rtci::peer_connection::transport::{
    CandidateConfig, CandidateHostConfig, RTCIceCandidate, RTCIceCandidateInit, RTCIceProtocol,
    RTCIceTransportState, RTCTransportId,
};
use rtci::sansio::Protocol;
use rtci::shared::error::{Error, IoError, Result};
use rtci::shared::{TaggedBytesMut, TransportContext, TransportProtocol};
use std::collections::{HashSet, VecDeque};
use std::future::Future;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::task::Poll;
use std::time::{Duration, Instant};

/// A datagram a socket of the driver received: its local address, the sender, the bytes.
type Received = (SocketAddr, SocketAddr, Vec<u8>);

/// What a [`PeerDriver`] binds.
#[derive(Debug, Clone)]
pub struct PeerDriverConfig {
    /// The local addresses that get a host candidate: one UDP socket per address for each
    /// transport.
    pub addresses: Vec<IpAddr>,
    /// The UDP sockets take a port of this range (any free port without one). A port the
    /// host refuses to applications is skipped like a port in use
    /// ([`sockets::bind_udp_in_range`]).
    pub udp_port_range: Option<PortRange>,
    /// The engine's TCP sockets (ICE-TCP, TURN over TCP and TLS), with their port range.
    pub streams: DriverConfig,
    /// How long a previous socket stays open after its transport selected a pair on a new one:
    /// the peer may still send to the previous address until its own selection switches
    /// (each side selects on its own), and those packets must not be lost. 5 seconds by
    /// default.
    pub retired_socket_linger: Duration,
    /// The budget the connection's mDNS datagrams take from
    /// (draft-ietf-mmusic-mdns-ice-candidates section 7.1). `None`, the default: the one of
    /// the process, [`process_mdns_rate_limit`], shared by every driver that has none named.
    /// A limit given here is shared by the drivers given clones of it.
    pub mdns_rate_limit: Option<MdnsRateLimit>,
}

impl PeerDriverConfig {
    /// Host candidates on `addresses`, any free port.
    pub fn on(addresses: Vec<IpAddr>) -> Self {
        Self {
            addresses,
            udp_port_range: None,
            streams: DriverConfig::default(),
            retired_socket_linger: Duration::from_secs(5),
            mdns_rate_limit: None,
        }
    }

    /// The budget this configuration's mDNS takes from: the one named, or the process's.
    pub fn mdns_rate_limit(&self) -> MdnsRateLimit {
        self.mdns_rate_limit
            .clone()
            .unwrap_or_else(process_mdns_rate_limit)
    }
}

/// The host's mDNS sockets of a driver, bound at the connection's first mDNS datagram.
struct MdnsSockets {
    v4: Option<(Arc<dyn AsyncUdpSocket>, SocketAddr)>,
    v6: Option<(Arc<dyn AsyncUdpSocket>, SocketAddr)>,
    readers: Vec<Box<dyn JoinHandle>>,
}

impl Drop for MdnsSockets {
    fn drop(&mut self) {
        for reader in &self.readers {
            reader.abort();
        }
    }
}

/// One UDP socket of the connection, with the reader that hands its datagrams to the driver.
struct HostSocket {
    socket: Arc<dyn AsyncUdpSocket>,
    local: SocketAddr,
    /// The section its candidate was added for.
    mid: String,
    /// Set when the engine refused its address for `transport` (`OnLocalCandidatesNeeded`):
    /// it is closed once that transport has selected a pair on another socket, or closed.
    retired_for: Option<RTCTransportId>,
    /// Once its transport selected a pair on another socket: when it is closed.
    close_at: Option<Instant>,
    /// Counted in [`PeerDriver::unmarked_sockets`] (the platform refused to mark it: its
    /// datagrams leave unmarked).
    counted_unmarked: bool,
    reader: Box<dyn JoinHandle>,
}

impl Drop for HostSocket {
    fn drop(&mut self) {
        self.reader.abort();
    }
}

/// Drives an `RTCPeerConnection` over sockets of its own (see the [module documentation](self)).
pub struct PeerDriver {
    runtime: Arc<dyn Runtime>,
    pc: RTCPeerConnection,
    streams: StreamDriver,
    config: PeerDriverConfig,
    sockets: Vec<HostSocket>,
    datagrams_tx: async_channel::Sender<Received>,
    datagrams: async_channel::Receiver<Received>,
    /// The engine's events, for the application, after the driver had its look.
    events: VecDeque<RTCPeerConnectionEvent>,
    /// The transports whose generation the driver gathered for on an
    /// `OnLocalCandidatesNeeded`: their `gatheringstatechange` that follows needs nothing.
    gathered: HashSet<RTCTransportId>,
    /// Datagrams the engine wrote that no socket sent ([`Self::unsent_datagrams`]).
    unsent: u64,
    /// The connection's mDNS datagrams, held to the budget.
    mdns_egress: MdnsEgress,
    /// `None` until the connection writes its first mDNS datagram.
    mdns_sockets: Option<MdnsSockets>,
    /// mDNS datagrams sent ([`Self::mdns_datagrams_sent`]).
    mdns_sent: u64,
    /// mDNS datagrams received ([`Self::mdns_datagrams_received`]).
    mdns_received: u64,
    /// Sockets on which the platform refused a TOS / Traffic Class ([`Self::unmarked_sockets`]).
    unmarked_sockets: u64,
    /// Datagrams sent, by the TOS / Traffic Class their socket had ([`Self::sent_by_traffic_class`]).
    sent_by_traffic_class: std::collections::BTreeMap<u8, u64>,
}

impl PeerDriver {
    /// A driver for `pc` on tokio ([`runtime::TokioRuntime::new`]: it must be used inside a
    /// tokio runtime), with no socket yet: it binds when the connection's first local
    /// description begins gathering. Feature `runtime-tokio` (on by default).
    #[cfg(feature = "runtime-tokio")]
    pub fn new(pc: RTCPeerConnection, config: PeerDriverConfig) -> Self {
        Self::with_runtime(Arc::new(runtime::TokioRuntime::new()), pc, config)
    }

    /// A driver for `pc` on `runtime`, with no socket yet: it binds when the connection's first
    /// local description begins gathering. Every time it gives the connection is the
    /// runtime's ([`Runtime::now`]).
    pub fn with_runtime(
        runtime: Arc<dyn Runtime>,
        pc: RTCPeerConnection,
        config: PeerDriverConfig,
    ) -> Self {
        let (datagrams_tx, datagrams) = async_channel::unbounded();
        Self {
            streams: StreamDriver::with_runtime(runtime.clone(), config.streams),
            runtime,
            pc,
            sockets: Vec::new(),
            datagrams_tx,
            datagrams,
            events: VecDeque::new(),
            gathered: HashSet::new(),
            unsent: 0,
            mdns_egress: MdnsEgress::new(config.mdns_rate_limit()),
            mdns_sockets: None,
            mdns_sent: 0,
            mdns_received: 0,
            config,
            unmarked_sockets: 0,
            sent_by_traffic_class: std::collections::BTreeMap::new(),
        }
    }

    /// The runtime the driver runs on.
    pub fn runtime(&self) -> &Arc<dyn Runtime> {
        &self.runtime
    }

    /// The peer connection.
    pub fn pc(&self) -> &RTCPeerConnection {
        &self.pc
    }

    /// The peer connection, for signalling, media and data channels. Call
    /// [`flush`](Self::flush) (or [`step`](Self::step)) after changing it, so that what it
    /// wants to send leaves and the driver sees its events.
    pub fn pc_mut(&mut self) -> &mut RTCPeerConnection {
        &mut self.pc
    }

    /// The local addresses of the UDP sockets open, the previous ones still waiting for a new
    /// pair included.
    pub fn local_addresses(&self) -> Vec<SocketAddr> {
        self.sockets.iter().map(|s| s.local).collect()
    }

    /// How many datagrams the connection wrote that were not sent: from a local address with
    /// no open socket (one closed already), or refused by the socket (its send buffer full:
    /// UDP drops them, as the wire would). Counted so that none is lost unseen.
    pub fn unsent_datagrams(&self) -> u64 {
        self.unsent
    }

    /// How many mDNS datagrams the driver sent for the connection (queries, probes,
    /// announcements, answers, goodbyes), after the budget let them go.
    pub fn mdns_datagrams_sent(&self) -> u64 {
        self.mdns_sent
    }

    /// How many datagrams the driver's mDNS sockets received and handed to the connection
    /// (its own looped back by the host included).
    pub fn mdns_datagrams_received(&self) -> u64 {
        self.mdns_received
    }

    /// How many sockets the platform refused a TOS / Traffic Class on: their datagrams leave
    /// without the DSCP the engine asked for (Windows without qWAVE, an IPv6 socket where the
    /// platform has no `IPV6_TCLASS`; see [`sockets::set_traffic_class`]).
    pub fn unmarked_sockets(&self) -> u64 {
        self.unmarked_sockets
    }

    /// How many datagrams were sent with each TOS / Traffic Class byte set on their socket
    /// (a socket the platform refused counts under 0).
    pub fn sent_by_traffic_class(&self) -> &std::collections::BTreeMap<u8, u64> {
        &self.sent_by_traffic_class
    }

    /// The TOS / Traffic Class byte the operating system reports for the UDP socket bound to
    /// `local` (`getsockopt` of `IP_TOS` / `IPV6_TCLASS`): what its next datagram carries.
    /// `None` without such a socket.
    pub fn socket_traffic_class(&self, local: SocketAddr) -> Option<io::Result<u32>> {
        let host = self.sockets.iter().find(|s| s.local == local)?;
        Some(host.socket.traffic_class())
    }

    /// The next event of the connection. The driver has already done what is its to do
    /// (gathering on `OnLocalCandidatesNeeded` and when a transport begins gathering, closing
    /// the previous sockets on a new selected pair); the application signals the candidates
    /// of `OnIceCandidateEvent` to the peer and handles the rest.
    pub fn poll_event(&mut self) -> Option<RTCPeerConnectionEvent> {
        self.events.pop_front()
    }

    /// Hands what the connection wants to send to the sockets and the stream driver, and
    /// reacts to its events, until nothing is left.
    ///
    /// # Errors
    ///
    /// A socket that cannot be bound for a transport that needs one, or a candidate the
    /// connection refuses.
    pub fn flush(&mut self) -> Result<()> {
        loop {
            let mut progress = false;
            while let Some(command) = self.pc.poll_stream_command() {
                self.streams.execute(command);
                progress = true;
            }
            while let Some(transmit) = self.pc.poll_stream_transmit() {
                self.streams.write(transmit);
                progress = true;
            }
            while let Some(datagram) = self.pc.poll_write() {
                self.send(datagram);
                progress = true;
            }
            while let Some(event) = self.pc.poll_event() {
                self.on_event(&event)?;
                self.events.push_back(event);
                progress = true;
            }
            if !progress {
                self.send_mdns(self.runtime.now());
                return Ok(());
            }
        }
    }

    /// One round: flushes, then waits up to `wait` (less when a timer of the connection is due
    /// first) for a datagram, a stream input or the timer, hands it over, and flushes again.
    ///
    /// # Errors
    ///
    /// As [`flush`](Self::flush).
    pub async fn step(&mut self, wait: Duration) -> Result<()> {
        self.flush()?;
        let now = self.runtime.now();
        let deadline = self
            .pc
            .poll_timeout()
            .into_iter()
            .chain(self.mdns_egress.next_ready(now))
            .fold(now + wait, Instant::min)
            .max(now);
        let woke = {
            let mut datagram = std::pin::pin!(self.datagrams.recv());
            let mut input = std::pin::pin!(self.streams.next());
            let mut timer = self.runtime.sleep_until(deadline);
            std::future::poll_fn(|cx| {
                if let Poll::Ready(Ok(received)) = datagram.as_mut().poll(cx) {
                    return Poll::Ready(Woke::Datagram(received));
                }
                if let Poll::Ready(input) = input.as_mut().poll(cx) {
                    return Poll::Ready(Woke::Stream(input));
                }
                timer.as_mut().poll(cx).map(|()| Woke::Timer)
            })
            .await
        };
        match woke {
            Woke::Datagram((local, peer, data)) => {
                self.feed(local, peer, data);
                while let Ok((local, peer, data)) = self.datagrams.try_recv() {
                    self.feed(local, peer, data);
                }
            }
            Woke::Stream(input) => self.feed_stream(input),
            Woke::Timer => {}
        }
        // The engine's timers; one that fails is the connection's to report (its states).
        let now = self.runtime.now();
        let _ = self.pc.handle_timeout(now);
        self.sockets
            .retain(|s| s.close_at.is_none_or(|close_at| close_at > now));
        self.flush()
    }

    fn feed(&mut self, local: SocketAddr, peer: SocketAddr, data: Vec<u8>) {
        if self.mdns_sockets.as_ref().is_some_and(|m| {
            [&m.v4, &m.v6]
                .iter()
                .any(|s| s.as_ref().is_some_and(|(_, at)| *at == local))
        }) {
            self.mdns_received += 1;
        }
        // A datagram the engine cannot take (a stray, a late one) is its business, not the
        // driver's: it goes on.
        let _ = self.pc.handle_read(TaggedBytesMut {
            now: self.runtime.now(),
            transport: TransportContext {
                local_addr: local,
                peer_addr: peer,
                ecn: None,
                transport_protocol: TransportProtocol::UDP,
            },
            message: BytesMut::from(&data[..]),
        });
    }

    fn feed_stream(&mut self, input: DriverInput) {
        let now = self.runtime.now();
        match input {
            DriverInput::Event(event) => {
                let _ = self.pc.handle_stream_event(now, event);
            }
            DriverInput::Read { id, data } => {
                let _ = self.pc.handle_stream_read(now, id, &data);
            }
            DriverInput::Accepted(accepted) => {
                if let Some(id) = self.pc.handle_stream_accepted(
                    now,
                    accepted.listener,
                    accepted.local,
                    accepted.remote,
                ) {
                    self.streams.adopt(id, accepted);
                }
            }
        }
    }

    /// Sends a datagram of the engine on the socket of its local address, marked with the
    /// DSCP and ECN codepoint the engine gives it (`RTCPeerConnection::traffic_class`: RFC 8837
    /// Table 1 by flow and priority, RFC 8835 section 4.2): the socket's `IP_TOS` /
    /// `IPV6_TCLASS` is set before the datagram when it differs from the last one set.
    fn send(&mut self, datagram: TaggedBytesMut) {
        if datagram.transport.transport_protocol != TransportProtocol::UDP {
            return;
        }
        let local = datagram.transport.local_addr;
        if local.port() == MDNS_PORT && !self.sockets.iter().any(|s| s.local == local) {
            if !self.mdns_egress.push(datagram) {
                self.unsent += 1;
            }
            return;
        }
        let traffic_class = self.pc.traffic_class(&datagram);
        let Some(host) = self.sockets.iter_mut().find(|s| s.local == local) else {
            self.unsent += 1;
            return;
        };
        // UDP: a datagram the socket cannot take now is lost, as on the wire.
        let sent = host.socket.try_send(&Transmit {
            destination: datagram.transport.peer_addr,
            contents: &datagram.message,
            traffic_class,
            segment_size: None,
        });
        // The platform does not mark (RFC 8835 4.2: "appropriate to depart ... on platforms
        // where QoS marking is not implemented"): counted once per socket.
        let unmarked = host.socket.unmarked();
        if unmarked && !host.counted_unmarked {
            host.counted_unmarked = true;
            self.unmarked_sockets += 1;
        }
        if sent {
            let applied = if unmarked { 0 } else { traffic_class };
            *self.sent_by_traffic_class.entry(applied).or_default() += 1;
        } else {
            self.unsent += 1;
        }
    }

    /// Sends the held mDNS datagrams the budget lets go at `now`, binding the mDNS sockets at
    /// the first. A datagram for a family the host has no mDNS socket for is unsent.
    fn send_mdns(&mut self, now: Instant) {
        while let Some(datagram) = self.mdns_egress.pop_ready(now) {
            let sockets = self.mdns_sockets.get_or_insert_with(|| {
                let mut readers = Vec::new();
                let mut open = |config: runtime::MulticastConfig| {
                    let socket = self.runtime.bind_udp_multicast(&config).ok()?;
                    let local = socket.local_addr().ok()?;
                    readers.push(self.runtime.spawn(Box::pin(read_loop(
                        socket.clone(),
                        local,
                        self.datagrams_tx.clone(),
                        MDNS_MAX_DATAGRAM,
                    ))));
                    Some((socket, local))
                };
                let v4 = open(mdns_v4());
                let v6 = open(mdns_v6());
                MdnsSockets { v4, v6, readers }
            });
            let socket = match datagram.transport.peer_addr {
                SocketAddr::V4(_) => &sockets.v4,
                SocketAddr::V6(_) => &sockets.v6,
            };
            let sent = socket.as_ref().is_some_and(|(socket, _)| {
                socket.try_send(&Transmit {
                    destination: datagram.transport.peer_addr,
                    contents: &datagram.message,
                    traffic_class: 0,
                    segment_size: None,
                })
            });
            if sent {
                self.mdns_sent += 1;
            } else {
                self.unsent += 1;
            }
        }
    }

    fn on_event(&mut self, event: &RTCPeerConnectionEvent) -> Result<()> {
        match event {
            RTCPeerConnectionEvent::OnLocalCandidatesNeeded(needed) => {
                self.on_candidates_needed(needed)
            }
            RTCPeerConnectionEvent::OnSignalingStateChangeEvent(RTCSignalingState::Stable) => {
                self.match_sockets_to_candidates();
                Ok(())
            }
            RTCPeerConnectionEvent::OnTransportEvent(event) => match &event.event {
                RTCTransportEventKind::GatheringStateChange(RTCIceGatheringState::Gathering) => {
                    self.on_gathering_begins(event.ice_transport, event.dtls_transport)
                }
                RTCTransportEventKind::SelectedCandidatePairChange(pair) => {
                    let local = pair.local();
                    let on_retired = self.sockets.iter().any(|s| {
                        s.retired_for.is_some() && names_socket(&local.address, local.port, s.local)
                    });
                    if !on_retired {
                        self.release_after_linger(event.ice_transport);
                    }
                    Ok(())
                }
                RTCTransportEventKind::IceStateChange(RTCIceTransportState::Closed) => {
                    self.release(event.ice_transport);
                    Ok(())
                }
                _ => Ok(()),
            },
            _ => Ok(()),
        }
    }

    /// `OnLocalCandidatesNeeded`: new sockets for the transport, or (`DiscardedBySetting`,
    /// no address refused) the same sockets' candidates again.
    fn on_candidates_needed(&mut self, needed: &RTCLocalCandidatesNeededEvent) -> Result<()> {
        let Some(mid) = needed.mids.first().cloned() else {
            return Ok(());
        };
        let index = needed.sdp_mline_index;
        self.gathered.insert(needed.ice_transport);
        if !needed.reason.needs_new_addresses() {
            let on: Vec<SocketAddr> = self
                .sockets
                .iter()
                .filter(|s| s.retired_for.is_none() && needed.mids.contains(&s.mid))
                .map(|s| s.local)
                .collect();
            if !on.is_empty() {
                for local in on {
                    self.pc
                        .add_local_candidate(host_candidate(local, &mid, index)?)?;
                }
                return self.end_of_candidates(&mid, index);
            }
            return self.gather_section(&mid, index);
        }
        for host in self
            .sockets
            .iter_mut()
            .filter(|s| needed.refused_addresses.contains(&s.local))
        {
            host.retired_for = Some(needed.ice_transport);
        }
        if needed.reason == RTCLocalCandidatesNeededReason::TransportReplaced {
            // The transport they served is closed: nothing travels over them any more.
            self.release(needed.ice_transport);
        }
        self.gather_section(&mid, index)
    }

    /// Back in the stable state, the sockets are matched against the candidates the
    /// transports hold. A local offer that is rolled back takes its ICE restart back (RFC
    /// 9429 section 5.7: "any resources or candidates that were allocated by the abandoned
    /// local description are discarded"), the `OnLocalCandidatesNeeded` it fired included: a
    /// socket retired for it whose candidate the transport holds again carries the
    /// transport's packets as before (it is no longer retired), and a socket bound for the
    /// abandoned generation, whose candidate the transport dropped, is closed. The answer to
    /// the peer's colliding offer, if it sets up a new association, fires its own event.
    fn match_sockets_to_candidates(&mut self) {
        let held: Vec<(String, u16)> = self
            .pc
            .dtls_transports()
            .iter()
            .flat_map(|t| t.ice_transport().get_local_candidates())
            .filter(|c| c.protocol == RTCIceProtocol::Udp)
            .map(|c| (c.address, c.port))
            .collect();
        let holds = |local: &SocketAddr| {
            held.iter()
                .any(|(address, port)| names_socket(address, *port, *local))
        };
        for host in self.sockets.iter_mut() {
            if host.retired_for.is_some() && holds(&host.local) {
                host.retired_for = None;
                host.close_at = None;
            }
        }
        self.sockets
            .retain(|s| s.retired_for.is_some() || holds(&s.local));
    }

    /// A transport begins gathering an ICE generation the driver was not told about: the
    /// first one (no socket of the transport yet: every section without one gets them), or a
    /// restart that kept the candidates (each is given to the new generation again).
    fn on_gathering_begins(
        &mut self,
        ice_transport: RTCTransportId,
        dtls_transport: RTCTransportId,
    ) -> Result<()> {
        if self.gathered.remove(&ice_transport) {
            return Ok(());
        }
        let Some(held) = self.pc.dtls_transport_by_id(dtls_transport).and_then(|t| {
            let ice = t.ice_transport();
            (ice.gathering_state() == RTCIceGatheringState::Gathering)
                .then(|| ice.get_local_candidates())
        }) else {
            return Ok(());
        };
        let kept: Vec<(SocketAddr, String)> = self
            .sockets
            .iter()
            .filter(|s| s.retired_for.is_none())
            .filter(|s| {
                held.iter()
                    .any(|c| names_socket(&c.address, c.port, s.local))
            })
            .map(|s| (s.local, s.mid.clone()))
            .collect();
        if kept.is_empty() {
            return self.gather();
        }
        let mid = kept[0].1.clone();
        for (local, _) in &kept {
            self.pc
                .add_local_candidate(host_candidate(*local, &mid, None)?)?;
        }
        self.end_of_candidates(&mid, None)
    }

    /// Host candidates for every transport section (`ice_transport_sections`) that has no
    /// socket of its own yet, each ended with the end of its generation.
    ///
    /// # Errors
    ///
    /// As [`flush`](Self::flush).
    pub fn gather(&mut self) -> Result<()> {
        for (mid, index) in self.pc.ice_transport_sections() {
            if self
                .sockets
                .iter()
                .any(|s| s.retired_for.is_none() && s.mid == mid)
            {
                continue;
            }
            self.gather_section(&mid, Some(index))?;
        }
        Ok(())
    }

    /// New sockets, one per configured address, for the transport of section `mid`: their
    /// host candidates, then the end of the generation.
    fn gather_section(&mut self, mid: &str, index: Option<u16>) -> Result<()> {
        for ip in self.config.addresses.clone() {
            let socket = match self.config.udp_port_range {
                Some(range) => sockets::bind_runtime_udp_in_range(self.runtime.as_ref(), ip, range),
                None => self.runtime.bind_udp(SocketAddr::new(ip, 0)),
            }
            .map_err(io_error)?;
            let local = socket.local_addr().map_err(io_error)?;
            let reader = self.runtime.spawn(Box::pin(read_loop(
                socket.clone(),
                local,
                self.datagrams_tx.clone(),
                2048,
            )));
            self.sockets.push(HostSocket {
                socket,
                local,
                mid: mid.to_owned(),
                retired_for: None,
                close_at: None,
                counted_unmarked: false,
                reader,
            });
            self.pc
                .add_local_candidate(host_candidate(local, mid, index)?)?;
        }
        self.end_of_candidates(mid, index)
    }

    fn end_of_candidates(&mut self, mid: &str, index: Option<u16>) -> Result<()> {
        self.pc.add_local_candidate(RTCIceCandidateInit {
            sdp_mid: Some(mid.to_owned()),
            sdp_mline_index: index,
            ..Default::default()
        })
    }

    /// Closes the sockets retired for `transport` (it is closed: nothing travels over them).
    fn release(&mut self, transport: RTCTransportId) {
        self.sockets.retain(|s| s.retired_for != Some(transport));
    }

    /// `transport` selected a pair on a new socket: its retired sockets are closed after
    /// [`PeerDriverConfig::retired_socket_linger`], for what the peer still sends to them.
    fn release_after_linger(&mut self, transport: RTCTransportId) {
        let close_at = self.runtime.now() + self.config.retired_socket_linger;
        for host in self
            .sockets
            .iter_mut()
            .filter(|s| s.retired_for == Some(transport) && s.close_at.is_none())
        {
            host.close_at = Some(close_at);
        }
    }
}

/// Whether a local candidate of `address` and `port` is the one of the socket at `local`. With
/// mDNS (`QueryAndGather`) the engine has replaced the candidate's address with a `.local` name
/// (draft-ietf-mmusic-mdns-ice-candidates section 3.1.1): the port tells the socket then (two
/// sockets of the driver on different addresses with one port number would both match).
fn names_socket(address: &str, port: u16, local: SocketAddr) -> bool {
    port == local.port()
        && (address == local.ip().to_string() || address.to_ascii_lowercase().ends_with(".local"))
}

fn io_error(e: io::Error) -> Error {
    Error::Io(IoError(e))
}

/// The host candidate of `local` for section `mid`.
fn host_candidate(local: SocketAddr, mid: &str, index: Option<u16>) -> Result<RTCIceCandidateInit> {
    let candidate = CandidateHostConfig {
        base_config: CandidateConfig {
            network: "udp".to_owned(),
            address: local.ip().to_string(),
            port: local.port(),
            component: 1,
            ..Default::default()
        },
        ..Default::default()
    }
    .new_candidate_host()?;
    let mut init = RTCIceCandidate::from(&candidate).to_json()?;
    init.sdp_mid = Some(mid.to_owned());
    init.sdp_mline_index = index;
    Ok(init)
}

/// What woke a [`PeerDriver::step`].
enum Woke {
    Datagram(Received),
    Stream(DriverInput),
    Timer,
}

async fn read_loop(
    socket: Arc<dyn AsyncUdpSocket>,
    local: SocketAddr,
    tx: async_channel::Sender<Received>,
    max_datagram: usize,
) {
    let mut buf = vec![0u8; max_datagram];
    loop {
        match socket.recv_from(&mut buf).await {
            Ok((n, peer)) => {
                if tx.try_send((local, peer, buf[..n].to_vec())).is_err() {
                    return;
                }
            }
            // An ICMP error reported on the socket (Windows: a port unreachable) is not the
            // end of it.
            Err(_) => runtime::yield_now().await,
        }
    }
}
