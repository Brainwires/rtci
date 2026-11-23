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

use crate::sockets::{self, PortRange};
use crate::{DriverConfig, DriverInput, StreamDriver};
use bytes::BytesMut;
use rtc::peer_connection::RTCPeerConnection;
use rtc::peer_connection::event::{
    RTCLocalCandidatesNeededEvent, RTCLocalCandidatesNeededReason, RTCPeerConnectionEvent,
    RTCTransportEventKind,
};
use rtc::peer_connection::state::RTCIceGatheringState;
use rtc::peer_connection::transport::{
    CandidateConfig, CandidateHostConfig, RTCIceCandidate, RTCIceCandidateInit,
    RTCIceTransportState, RTCTransportId,
};
use rtc::sansio::Protocol;
use rtc::shared::error::{Error, IoError, Result};
use rtc::shared::{TaggedBytesMut, TransportContext, TransportProtocol};
use std::collections::{HashSet, VecDeque};
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

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
}

impl PeerDriverConfig {
    /// Host candidates on `addresses`, any free port.
    pub fn on(addresses: Vec<IpAddr>) -> Self {
        Self {
            addresses,
            udp_port_range: None,
            streams: DriverConfig::default(),
            retired_socket_linger: Duration::from_secs(5),
        }
    }
}

/// One UDP socket of the connection, with the reader that hands its datagrams to the driver.
struct HostSocket {
    socket: Arc<UdpSocket>,
    local: SocketAddr,
    /// The section its candidate was added for.
    mid: String,
    /// Set when the engine refused its address for `transport` (`OnLocalCandidatesNeeded`):
    /// it is closed once that transport has selected a pair on another socket, or closed.
    retired_for: Option<RTCTransportId>,
    /// Once its transport selected a pair on another socket: when it is closed.
    close_at: Option<Instant>,
    reader: JoinHandle<()>,
}

impl Drop for HostSocket {
    fn drop(&mut self) {
        self.reader.abort();
    }
}

/// Drives an `RTCPeerConnection` over sockets of its own (see the [module documentation](self)).
pub struct PeerDriver {
    pc: RTCPeerConnection,
    streams: StreamDriver,
    config: PeerDriverConfig,
    sockets: Vec<HostSocket>,
    datagrams_tx: mpsc::UnboundedSender<(SocketAddr, SocketAddr, Vec<u8>)>,
    datagrams: mpsc::UnboundedReceiver<(SocketAddr, SocketAddr, Vec<u8>)>,
    /// The engine's events, for the application, after the driver had its look.
    events: VecDeque<RTCPeerConnectionEvent>,
    /// The transports whose generation the driver gathered for on an
    /// `OnLocalCandidatesNeeded`: their `gatheringstatechange` that follows needs nothing.
    gathered: HashSet<RTCTransportId>,
}

impl PeerDriver {
    /// A driver for `pc`, with no socket yet: it binds when the connection's first local
    /// description begins gathering. Must be used inside a tokio runtime.
    pub fn new(pc: RTCPeerConnection, config: PeerDriverConfig) -> Self {
        let (datagrams_tx, datagrams) = mpsc::unbounded_channel();
        Self {
            pc,
            streams: StreamDriver::new(config.streams),
            config,
            sockets: Vec::new(),
            datagrams_tx,
            datagrams,
            events: VecDeque::new(),
            gathered: HashSet::new(),
        }
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
        let now = Instant::now();
        let deadline = self
            .pc
            .poll_timeout()
            .map_or(now + wait, |due| due.min(now + wait))
            .max(now);
        tokio::select! {
            Some((local, peer, data)) = self.datagrams.recv() => {
                self.feed(local, peer, data);
                while let Ok((local, peer, data)) = self.datagrams.try_recv() {
                    self.feed(local, peer, data);
                }
            }
            input = self.streams.next() => self.feed_stream(input),
            _ = tokio::time::sleep_until(deadline.into()) => {}
        }
        // The engine's timers; one that fails is the connection's to report (its states).
        let now = Instant::now();
        let _ = self.pc.handle_timeout(now);
        self.sockets
            .retain(|s| s.close_at.is_none_or(|close_at| close_at > now));
        self.flush()
    }

    fn feed(&mut self, local: SocketAddr, peer: SocketAddr, data: Vec<u8>) {
        // A datagram the engine cannot take (a stray, a late one) is its business, not the
        // driver's: it goes on.
        let _ = self.pc.handle_read(TaggedBytesMut {
            now: Instant::now(),
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
        let now = Instant::now();
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

    fn send(&mut self, datagram: TaggedBytesMut) {
        if datagram.transport.transport_protocol != TransportProtocol::UDP {
            return;
        }
        if let Some(host) = self
            .sockets
            .iter()
            .find(|s| s.local == datagram.transport.local_addr)
        {
            // UDP: a datagram the socket cannot take now is lost, as on the wire.
            let _ = host
                .socket
                .try_send_to(&datagram.message, datagram.transport.peer_addr);
        }
    }

    fn on_event(&mut self, event: &RTCPeerConnectionEvent) -> Result<()> {
        match event {
            RTCPeerConnectionEvent::OnLocalCandidatesNeeded(needed) => {
                self.on_candidates_needed(needed)
            }
            RTCPeerConnectionEvent::OnTransportEvent(event) => match &event.event {
                RTCTransportEventKind::GatheringStateChange(RTCIceGatheringState::Gathering) => {
                    self.on_gathering_begins(event.ice_transport, event.dtls_transport)
                }
                RTCTransportEventKind::SelectedCandidatePairChange(pair) => {
                    let local = pair.local();
                    let on_retired = self.sockets.iter().any(|s| {
                        s.retired_for.is_some()
                            && s.local.port() == local.port
                            && s.local.ip().to_string() == local.address
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
                    .any(|c| c.port == s.local.port() && c.address == s.local.ip().to_string())
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
                Some(range) => sockets::bind_udp_in_range(ip, range),
                None => std::net::UdpSocket::bind(SocketAddr::new(ip, 0)),
            }
            .and_then(|socket| {
                socket.set_nonblocking(true)?;
                UdpSocket::from_std(socket)
            })
            .map_err(io_error)?;
            let local = socket.local_addr().map_err(io_error)?;
            let socket = Arc::new(socket);
            let reader = tokio::spawn(read_loop(socket.clone(), local, self.datagrams_tx.clone()));
            self.sockets.push(HostSocket {
                socket,
                local,
                mid: mid.to_owned(),
                retired_for: None,
                close_at: None,
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
        let close_at = Instant::now() + self.config.retired_socket_linger;
        for host in self
            .sockets
            .iter_mut()
            .filter(|s| s.retired_for == Some(transport) && s.close_at.is_none())
        {
            host.close_at = Some(close_at);
        }
    }
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

async fn read_loop(
    socket: Arc<UdpSocket>,
    local: SocketAddr,
    tx: mpsc::UnboundedSender<(SocketAddr, SocketAddr, Vec<u8>)>,
) {
    let mut buf = vec![0u8; 2048];
    loop {
        match socket.recv_from(&mut buf).await {
            Ok((n, peer)) => {
                if tx.send((local, peer, buf[..n].to_vec())).is_err() {
                    return;
                }
            }
            // An ICMP error reported on the socket (Windows: a port unreachable) is not the
            // end of it.
            Err(_) => tokio::task::yield_now().await,
        }
    }
}
