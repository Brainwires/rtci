//! The reference driver for the stream half of WebRTC.rs's sans-I/O engine
//! (`rtci_shared::stream`): it owns the TCP sockets, on tokio, and does what the engine asks.
//!
//! # Engine and driver
//!
//! The engine (`rtci::peer_connection::RTCPeerConnection`) performs no I/O. For its datagrams
//! the application reads and writes its own UDP sockets (`handle_read` / `poll_write`). For
//! TCP it is the engine that **decides** — which ICE-TCP candidates to gather (RFC 6544), which
//! connections to open and close, the RFC 4571 framing, TURN over TCP, TLS and DTLS, relayed
//! TCP candidates (RFC 6062), server-reflexive gathering over TCP, the Happy Eyeballs race
//! (RFC 8305) — and names every listener and connection by id. This driver only **carries
//! out** what it is told:
//!
//! | The engine says ([`StreamCommand`]) | The driver |
//! | --- | --- |
//! | `Listen { local, reuse_address }` | binds a listener (port 0: any, or one of [`DriverConfig::tcp_port_range`]), reports `Listening` or `ListenFailed`, then `Accepted` for each connection |
//! | `Connect { local, remote, reuse_address }` | connects (within [`DriverConfig::connect_timeout`]), reports `Connected` or `ConnectFailed` |
//! | `Close` / `Reset` | ends the connection with FIN (waiting [`DriverConfig::close_linger`]) or RST |
//! | `Resolve { host, port }` | looks the name up (both families at once, or AAAA and A apart with the `dns-records` feature) |
//! | `ResolveRecords { name, kind }` | SRV / NAPTR records with `dns-records`, none without |
//!
//! Bytes go both ways untouched: what the engine transmits ([`StreamDriver::write`]) is
//! already framed and encrypted, and what the socket reads goes back in whatever pieces it
//! came ([`DriverInput::Read`]); each write is reported with `StreamEvent::Written`, the
//! engine's back-pressure signal.
//!
//! # The loop
//!
//! ```text
//! while let Some(command) = pc.poll_stream_command() { driver.execute(command) }
//! while let Some(transmit) = pc.poll_stream_transmit() { driver.write(transmit) }
//! match driver.next().await {                      // or try_next() in a polling loop
//!     DriverInput::Event(event) => pc.handle_stream_event(now, event)?,
//!     DriverInput::Read { id, data } => pc.handle_stream_read(now, id, &data)?,
//!     DriverInput::Accepted(accepted) => match pc.handle_stream_accepted(
//!         now, accepted.listener, accepted.local, accepted.remote) {
//!         Some(id) => driver.adopt(id, accepted),
//!         None => drop(accepted),                  // refused: the socket closes
//!     },
//! }
//! ```
//!
//! A complete program, two peer connections over loopback TCP with a data channel, is the
//! `stream-driver-loopback` example of the `rtci` crate (`cargo run --example
//! stream-driver-loopback`); the test environment runs it.
//!
//! # Server choices
//!
//! [`sockets`] has what a server decides and the engine does not: port ranges
//! ([`sockets::PortRange`]), which local addresses get candidates ([`sockets::AddressFilter`]),
//! one UDP port for many peer connections ([`sockets::UfragMux`]) and one passive ICE-TCP port
//! for many ([`DriverConfig::shared_passive`], [`sockets::accept_by_ufrag`]).
//!
//! # NAT-assisted candidates
//!
//! [`nat_mapping`] (opt-in, no dependency) asks the gateway for a port mapping with PCP (RFC
//! 6887), falling back to NAT-PMP (RFC 6886); the application adds the mapped address as a
//! server-reflexive candidate ([`nat_mapping::candidate_line`], RFC 6544 section 5.3).
//!
//! # A whole peer connection
//!
//! [`peer::PeerDriver`] (feature `peer`, on by default) drives an `rtci` peer connection over
//! sockets it owns, its UDP host sockets included, and gathers for it: at the first local
//! description, and again on its own when a transport needs a new set of local candidates
//! (`OnLocalCandidatesNeeded`: a new DTLS association runs on a new 3-tuple, RFC 8842 section
//! 5.1), closing the previous sockets once a pair on the new ones is selected.
//!
//! # Features
//!
//! - `peer` (default): [`peer`], with a dependency on `rtci`.
//! - `dns-records`: SRV and NAPTR lookups (RFC 5928, RFC 8489 section 8) and AAAA / A answered
//!   apart (RFC 8305 section 3), with hickory-resolver (MIT OR Apache-2.0). Without it, names go
//!   to the system resolver and record queries are answered with none (the engine then uses
//!   the host and the scheme's default port).
//!
//! Each connection has a reader task and a writer task. Sockets are created on the thread that
//! calls [`StreamDriver::execute`] inside a tokio runtime, so a current-thread runtime on a
//! thread that entered a network namespace keeps them there.

#![warn(missing_docs)]

#[cfg(feature = "peer")]
mod mdns_io;
pub mod nat_mapping;
#[cfg(feature = "peer")]
pub mod peer;
pub mod sockets;

use shared::stream::{ListenerId, StreamCommand, StreamEvent, StreamId, StreamTransmit};
use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpSocket, TcpStream};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

/// What the driver has for the engine.
#[derive(Debug)]
pub enum DriverInput {
    /// Pass to the engine's `handle_stream_event`.
    Event(StreamEvent),
    /// Bytes read from a connection: pass to the engine's `handle_stream_read`.
    Read {
        /// The connection.
        id: StreamId,
        /// What was read.
        data: Vec<u8>,
    },
    /// A connection accepted on a listener: ask the engine for its id
    /// (`handle_stream_accepted`) and [`adopt`](StreamDriver::adopt) it, or drop it.
    Accepted(Accepted),
}

/// A connection accepted on a listener, waiting for its id.
#[derive(Debug)]
pub struct Accepted {
    /// The listener it arrived on.
    pub listener: ListenerId,
    /// Its local address.
    pub local: SocketAddr,
    /// The peer's address.
    pub remote: SocketAddr,
    stream: TcpStream,
}

/// The driver's settings.
#[derive(Debug, Clone, Copy)]
pub struct DriverConfig {
    /// How long a connection attempt may take before it is reported failed.
    pub connect_timeout: Duration,
    /// How long a close waits for the peer's end of stream before giving up.
    pub close_linger: Duration,
    /// Listeners asked for on port 0 take a port of this range.
    pub tcp_port_range: Option<sockets::PortRange>,
    /// A passive ICE-TCP listening port shared with other peer connections: a `Listen` without
    /// `reuse_address` is answered with this address and binds nothing; the application
    /// accepts on the shared listener ([`sockets::accept_by_ufrag`]) and hands each connection
    /// to the driver of the peer connection its first check names
    /// ([`StreamDriver::adopt_shared`]). Every transport of the connection is answered with the
    /// same address; the engine gives each connection to the transport its first check names.
    pub shared_passive: Option<SocketAddr>,
}

impl Default for DriverConfig {
    fn default() -> Self {
        Self {
            connect_timeout: Duration::from_secs(10),
            close_linger: Duration::from_secs(2),
            tcp_port_range: None,
            shared_passive: None,
        }
    }
}

enum WriterMessage {
    Data(Vec<u8>),
    Close,
    Reset,
}

struct Connection {
    writer: mpsc::UnboundedSender<WriterMessage>,
    task: JoinHandle<()>,
    established: Arc<AtomicBool>,
}

/// Owns the sockets of one engine (see the [crate documentation](crate)).
pub struct StreamDriver {
    config: DriverConfig,
    inputs_tx: mpsc::UnboundedSender<DriverInput>,
    inputs: mpsc::UnboundedReceiver<DriverInput>,
    listeners: HashMap<ListenerId, JoinHandle<()>>,
    connections: HashMap<StreamId, Connection>,
    /// The engine's listener answered with the shared passive address.
    shared_listener: Option<ListenerId>,
}

impl Default for StreamDriver {
    fn default() -> Self {
        Self::new(DriverConfig::default())
    }
}

impl Drop for StreamDriver {
    fn drop(&mut self) {
        for (_, task) in self.listeners.drain() {
            task.abort();
        }
        for (_, connection) in self.connections.drain() {
            connection.task.abort();
        }
    }
}

impl StreamDriver {
    /// A driver with no sockets.
    pub fn new(config: DriverConfig) -> Self {
        let (inputs_tx, inputs) = mpsc::unbounded_channel();
        Self {
            config,
            inputs_tx,
            inputs,
            listeners: HashMap::new(),
            connections: HashMap::new(),
            shared_listener: None,
        }
    }

    /// Carries out a command of the engine. Must be called inside a tokio runtime.
    pub fn execute(&mut self, command: StreamCommand) {
        match command {
            StreamCommand::Listen {
                listener,
                local,
                reuse_address,
            } if !reuse_address
                && self.config.shared_passive.is_some_and(|shared| {
                    shared.ip() == local.ip() || local.ip().is_unspecified()
                }) =>
            {
                self.shared_listener = Some(listener);
                let shared = self.config.shared_passive.unwrap_or(local);
                self.send(DriverInput::Event(StreamEvent::Listening {
                    listener,
                    local: shared,
                }));
            }
            StreamCommand::Listen {
                listener,
                local,
                reuse_address,
            } => match match self.config.tcp_port_range {
                Some(range) if local.port() == 0 => {
                    sockets::bind_tcp_listener_in_range(local.ip(), range, reuse_address)
                }
                _ => bind_listener(local, reuse_address),
            } {
                Ok(socket) => {
                    let bound = socket.local_addr().unwrap_or(local);
                    self.send(DriverInput::Event(StreamEvent::Listening {
                        listener,
                        local: bound,
                    }));
                    let tx = self.inputs_tx.clone();
                    let task = tokio::spawn(accept_loop(listener, socket, tx));
                    if let Some(old) = self.listeners.insert(listener, task) {
                        old.abort();
                    }
                }
                Err(_) => self.send(DriverInput::Event(StreamEvent::ListenFailed { listener })),
            },
            StreamCommand::StopListening { listener } => {
                if let Some(task) = self.listeners.remove(&listener) {
                    task.abort();
                }
            }
            StreamCommand::Connect {
                id,
                local,
                remote,
                reuse_address,
            } => {
                let (writer, rx) = mpsc::unbounded_channel();
                let established = Arc::new(AtomicBool::new(false));
                let tx = self.inputs_tx.clone();
                let config = self.config;
                let flag = established.clone();
                let task = tokio::spawn(async move {
                    let connected = tokio::time::timeout(
                        config.connect_timeout,
                        connect(local, remote, reuse_address),
                    )
                    .await;
                    match connected {
                        Ok(Ok(stream)) => {
                            let local = stream.local_addr().unwrap_or(local);
                            flag.store(true, Ordering::SeqCst);
                            let _ =
                                tx.send(DriverInput::Event(StreamEvent::Connected { id, local }));
                            run_connection(id, stream, rx, tx, config).await;
                        }
                        _ => {
                            let _ = tx.send(DriverInput::Event(StreamEvent::ConnectFailed { id }));
                        }
                    }
                });
                self.connections.insert(
                    id,
                    Connection {
                        writer,
                        task,
                        established,
                    },
                );
            }
            StreamCommand::Close { id } => {
                if let Some(connection) = self.connections.remove(&id) {
                    if connection.established.load(Ordering::SeqCst) {
                        let _ = connection.writer.send(WriterMessage::Close);
                    } else {
                        connection.task.abort();
                    }
                }
            }
            StreamCommand::Reset { id } => {
                if let Some(connection) = self.connections.remove(&id) {
                    if connection.established.load(Ordering::SeqCst) {
                        let _ = connection.writer.send(WriterMessage::Reset);
                    } else {
                        connection.task.abort();
                    }
                }
            }
            #[cfg(not(feature = "dns-records"))]
            StreamCommand::Resolve { query, host, port } => {
                let tx = self.inputs_tx.clone();
                tokio::spawn(async move {
                    // Both families at once (RFC 8305 section 3): the system resolver asks for
                    // AAAA and A together.
                    let addresses = match tokio::net::lookup_host((host.as_str(), port)).await {
                        Ok(found) => found.collect(),
                        Err(_) => vec![],
                    };
                    let _ = tx.send(DriverInput::Event(StreamEvent::Resolved {
                        query,
                        addresses,
                    }));
                });
            }
            #[cfg(feature = "dns-records")]
            StreamCommand::Resolve { query, host, port } => {
                // AAAA and A asked together, each answered as it arrives (RFC 8305 section 3):
                // the engine starts on the first.
                for ipv6 in [true, false] {
                    let tx = self.inputs_tx.clone();
                    let host = host.clone();
                    tokio::spawn(async move {
                        let addresses = dns::addresses(&host, port, ipv6).await;
                        let _ = tx.send(DriverInput::Event(StreamEvent::ResolvedFamily {
                            query,
                            ipv6,
                            addresses,
                        }));
                    });
                }
            }
            StreamCommand::ResolveRecords { query, name, kind } => {
                let tx = self.inputs_tx.clone();
                tokio::spawn(async move {
                    #[cfg(feature = "dns-records")]
                    let records = dns::records(&name, kind).await;
                    // Without the feature there is no record lookup: none, and the engine
                    // takes the host's addresses (RFC 5928 section 3).
                    #[cfg(not(feature = "dns-records"))]
                    let records = {
                        let _ = (&name, kind);
                        vec![]
                    };
                    let _ = tx.send(DriverInput::Event(StreamEvent::ResolvedRecords {
                        query,
                        records,
                    }));
                });
            }
            _ => {}
        }
    }

    /// Takes the engine's id for an accepted connection and starts serving it.
    pub fn adopt(&mut self, id: StreamId, accepted: Accepted) {
        let (writer, rx) = mpsc::unbounded_channel();
        let tx = self.inputs_tx.clone();
        let config = self.config;
        let task = tokio::spawn(run_connection(id, accepted.stream, rx, tx, config));
        self.connections.insert(
            id,
            Connection {
                writer,
                task,
                established: Arc::new(AtomicBool::new(true)),
            },
        );
    }

    /// The engine's listener that stands for the shared passive port
    /// ([`DriverConfig::shared_passive`]), once the engine asked for it.
    pub fn shared_listener(&self) -> Option<ListenerId> {
        self.shared_listener
    }

    /// Serves a connection accepted on the shared passive port, which the engine gave `id`
    /// (`handle_stream_accepted` with [`shared_listener`](Self::shared_listener)); the bytes
    /// already read from it to route it are handed to the engine first.
    pub fn adopt_shared(&mut self, id: StreamId, accepted: sockets::SharedAccept) {
        if !accepted.read.is_empty() {
            self.send(DriverInput::Read {
                id,
                data: accepted.read,
            });
        }
        self.adopt(
            id,
            Accepted {
                listener: self.shared_listener.unwrap_or(ListenerId(0)),
                local: accepted.local,
                remote: accepted.remote,
                stream: accepted.stream,
            },
        );
    }

    /// Writes a transmit of the engine, after the earlier ones of its connection.
    pub fn write(&mut self, transmit: StreamTransmit) {
        if let Some(connection) = self.connections.get(&transmit.id) {
            let _ = connection.writer.send(WriterMessage::Data(transmit.data));
        }
    }

    /// The next input for the engine.
    pub async fn next(&mut self) -> DriverInput {
        // The driver holds a sender itself, so the channel never closes.
        self.inputs
            .recv()
            .await
            .expect("the driver keeps its own sender")
    }

    /// The next input for the engine, if one is ready.
    pub fn try_next(&mut self) -> Option<DriverInput> {
        self.inputs.try_recv().ok()
    }

    /// Connections and listeners open.
    pub fn sockets(&self) -> (usize, usize) {
        (self.connections.len(), self.listeners.len())
    }

    fn send(&self, input: DriverInput) {
        let _ = self.inputs_tx.send(input);
    }
}

fn new_socket(addr: SocketAddr, reuse_address: bool) -> io::Result<TcpSocket> {
    let socket = if addr.is_ipv4() {
        TcpSocket::new_v4()?
    } else {
        TcpSocket::new_v6()?
    };
    if reuse_address {
        socket.set_reuseaddr(true)?;
        #[cfg(all(unix, not(any(target_os = "solaris", target_os = "illumos"))))]
        socket.set_reuseport(true)?;
    }
    Ok(socket)
}

pub(crate) fn bind_listener(local: SocketAddr, reuse_address: bool) -> io::Result<TcpListener> {
    let socket = new_socket(local, reuse_address)?;
    socket.bind(local)?;
    socket.listen(128)
}

async fn connect(
    local: SocketAddr,
    remote: SocketAddr,
    reuse_address: bool,
) -> io::Result<TcpStream> {
    let socket = new_socket(local, reuse_address)?;
    socket.bind(local)?;
    let stream = socket.connect(remote).await?;
    // A connection whose two ends are the same address is the socket connected to itself, not
    // to a peer: connecting from an ephemeral port to a loopback port nothing listens on, the
    // system can pick that very port as the source, and TCP's simultaneous open (RFC 9293
    // section 3.5) then "connects" the socket to itself. It is a failed connection (an ICE-TCP
    // check toward a dead loopback candidate would otherwise succeed against its own echo).
    if is_self_connection(stream.local_addr()?, stream.peer_addr()?) {
        return Err(io::Error::new(
            io::ErrorKind::ConnectionRefused,
            format!("{remote}: the socket connected to itself"),
        ));
    }
    stream.set_nodelay(true)?;
    Ok(stream)
}

/// Whether a connection runs from an address to that same address.
fn is_self_connection(local: SocketAddr, peer: SocketAddr) -> bool {
    local == peer
}

async fn accept_loop(
    listener: ListenerId,
    socket: TcpListener,
    tx: mpsc::UnboundedSender<DriverInput>,
) {
    loop {
        match socket.accept().await {
            Ok((stream, remote)) => {
                let _ = stream.set_nodelay(true);
                let local = match stream.local_addr() {
                    Ok(local) => local,
                    Err(_) => continue,
                };
                if tx
                    .send(DriverInput::Accepted(Accepted {
                        listener,
                        local,
                        remote,
                        stream,
                    }))
                    .is_err()
                {
                    return;
                }
            }
            // Out of descriptors, say: try again shortly rather than spin.
            Err(_) => tokio::time::sleep(Duration::from_millis(50)).await,
        }
    }
}

async fn run_connection(
    id: StreamId,
    stream: TcpStream,
    mut rx: mpsc::UnboundedReceiver<WriterMessage>,
    tx: mpsc::UnboundedSender<DriverInput>,
    config: DriverConfig,
) {
    let (mut read_half, mut write_half) = stream.into_split();
    let reader_tx = tx.clone();
    let mut reader = tokio::spawn(async move {
        let mut buf = vec![0u8; 64 * 1024];
        loop {
            match read_half.read(&mut buf).await {
                Ok(0) => {
                    let _ = reader_tx.send(DriverInput::Event(StreamEvent::Closed { id }));
                    return;
                }
                Ok(n) => {
                    if reader_tx
                        .send(DriverInput::Read {
                            id,
                            data: buf[..n].to_vec(),
                        })
                        .is_err()
                    {
                        return;
                    }
                }
                Err(_) => {
                    let _ = reader_tx.send(DriverInput::Event(StreamEvent::Reset { id }));
                    return;
                }
            }
        }
    });
    loop {
        tokio::select! {
            message = rx.recv() => match message {
                Some(WriterMessage::Data(data)) => {
                    if write_half.write_all(&data).await.is_err() {
                        let _ = tx.send(DriverInput::Event(StreamEvent::Reset { id }));
                        reader.abort();
                        return;
                    }
                    let _ = tx.send(DriverInput::Event(StreamEvent::Written {
                        id,
                        bytes: data.len(),
                    }));
                }
                Some(WriterMessage::Close) => {
                    let _ = write_half.shutdown().await;
                    // The reader reports Closed at the peer's end of stream; one that never
                    // comes is given up on.
                    if tokio::time::timeout(config.close_linger, &mut reader).await.is_err() {
                        reader.abort();
                        let _ = tx.send(DriverInput::Event(StreamEvent::Closed { id }));
                    }
                    return;
                }
                Some(WriterMessage::Reset) | None => {
                    // SO_LINGER 0: closing sends RST instead of FIN.
                    let _ = socket2::SockRef::from(write_half.as_ref())
                        .set_linger(Some(Duration::ZERO));
                    write_half.forget();
                    reader.abort();
                    return;
                }
            },
            // The peer closed or the connection broke: the reader has reported it.
            _ = &mut reader => return,
        }
    }
}

/// DNS lookups with hickory-resolver (feature `dns-records`).
#[cfg(feature = "dns-records")]
mod dns {
    use hickory_resolver::TokioResolver;
    use hickory_resolver::proto::rr::{RData, RecordType};
    use shared::stream::{DnsRecord, RecordKind};
    use std::net::{IpAddr, SocketAddr};

    /// The system's resolver (its name servers and search list).
    fn resolver() -> Option<TokioResolver> {
        TokioResolver::builder_tokio().ok()?.build().ok()
    }

    /// The addresses of one family of `host`, with `port`.
    pub(crate) async fn addresses(host: &str, port: u16, ipv6: bool) -> Vec<SocketAddr> {
        match resolver() {
            Some(resolver) => addresses_with(&resolver, host, port, ipv6).await,
            None => vec![],
        }
    }

    async fn addresses_with(
        resolver: &TokioResolver,
        host: &str,
        port: u16,
        ipv6: bool,
    ) -> Vec<SocketAddr> {
        let kind = if ipv6 {
            RecordType::AAAA
        } else {
            RecordType::A
        };
        let Ok(found) = resolver.lookup(host, kind).await else {
            return vec![];
        };
        found
            .answers()
            .iter()
            .filter_map(|r| match &r.data {
                RData::A(a) => Some(IpAddr::V4(a.0)),
                RData::AAAA(a) => Some(IpAddr::V6(a.0)),
                _ => None,
            })
            .map(|ip| SocketAddr::new(ip, port))
            .collect()
    }

    /// The SRV or NAPTR records of `name` (none on any error).
    pub(crate) async fn records(name: &str, kind: RecordKind) -> Vec<DnsRecord> {
        match resolver() {
            Some(resolver) => records_with(&resolver, name, kind).await,
            None => vec![],
        }
    }

    async fn records_with(
        resolver: &TokioResolver,
        name: &str,
        kind: RecordKind,
    ) -> Vec<DnsRecord> {
        let record_type = match kind {
            RecordKind::Srv => RecordType::SRV,
            RecordKind::Naptr => RecordType::NAPTR,
            _ => return vec![],
        };
        let Ok(found) = resolver.lookup(name, record_type).await else {
            return vec![];
        };
        let text = |b: &[u8]| String::from_utf8_lossy(b).into_owned();
        found
            .answers()
            .iter()
            .filter_map(|r| match &r.data {
                RData::SRV(srv) => Some(DnsRecord::Srv {
                    priority: srv.priority,
                    weight: srv.weight,
                    port: srv.port,
                    target: srv.target.to_utf8(),
                }),
                RData::NAPTR(n) => Some(DnsRecord::Naptr {
                    order: n.order,
                    preference: n.preference,
                    flags: text(&n.flags),
                    services: text(&n.services),
                    regexp: text(&n.regexp),
                    replacement: n.replacement.to_utf8(),
                }),
                _ => None,
            })
            .collect()
    }

    /// The lookups against a name server on loopback that answers from a fixed zone, through
    /// the resolver's own UDP client: what the engine's SRV / NAPTR discovery of STUN and TURN
    /// servers (RFC 5928, RFC 8489 section 8) and its per-family answers (RFC 8305 section 3)
    /// receive.
    #[cfg(test)]
    mod tests {
        use super::*;
        use hickory_resolver::config::{NameServerConfig, ResolverConfig};
        use hickory_resolver::net::runtime::TokioRuntimeProvider;
        use hickory_resolver::proto::op::{Message, OpCode};
        use hickory_resolver::proto::rr::rdata::{A, AAAA, NAPTR, SRV};
        use hickory_resolver::proto::rr::{Name, Record};
        use std::net::{Ipv4Addr, Ipv6Addr};

        /// A name server on 127.0.0.1 answering `turn.example.`; its port.
        async fn name_server() -> u16 {
            let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let port = socket.local_addr().unwrap().port();
            tokio::spawn(async move {
                let mut buf = [0u8; 1500];
                loop {
                    let Ok((n, from)) = socket.recv_from(&mut buf).await else {
                        return;
                    };
                    let Ok(query) = Message::from_vec(&buf[..n]) else {
                        continue;
                    };
                    let mut response = Message::response(query.metadata.id, OpCode::Query);
                    response.metadata.recursion_desired = query.metadata.recursion_desired;
                    response.metadata.recursion_available = true;
                    response.metadata.authoritative = true;
                    for q in &query.queries {
                        response.add_query(q.clone());
                        let name = q.name().clone();
                        let rdata = |r| Record::from_rdata(name.clone(), 60, r);
                        let host = |s: &str| Name::from_ascii(s).unwrap();
                        let answers: Vec<Record> = match q.query_type() {
                            RecordType::A => vec![rdata(RData::A(A(Ipv4Addr::new(192, 0, 2, 7))))],
                            RecordType::AAAA => vec![rdata(RData::AAAA(AAAA(Ipv6Addr::new(
                                0x2001, 0xdb8, 0, 0, 0, 0, 0, 7,
                            ))))],
                            RecordType::SRV => vec![
                                rdata(RData::SRV(SRV::new(1, 5, 3478, host("turn1.example.")))),
                                rdata(RData::SRV(SRV::new(2, 0, 3479, host("turn2.example.")))),
                            ],
                            RecordType::NAPTR => vec![rdata(RData::NAPTR(NAPTR::new(
                                10,
                                20,
                                b"s".to_vec().into_boxed_slice(),
                                b"RELAY:turn.udp".to_vec().into_boxed_slice(),
                                Vec::new().into_boxed_slice(),
                                host("_turn._udp.example."),
                            )))],
                            _ => vec![],
                        };
                        for a in answers {
                            response.add_answer(a);
                        }
                    }
                    if let Ok(bytes) = response.to_vec() {
                        let _ = socket.send_to(&bytes, from).await;
                    }
                }
            });
            port
        }

        fn resolver_at(port: u16) -> TokioResolver {
            let mut server = NameServerConfig::udp(IpAddr::V4(Ipv4Addr::LOCALHOST));
            for connection in &mut server.connections {
                connection.port = port;
            }
            let config = ResolverConfig::from_parts(None, vec![], vec![server]);
            TokioResolver::builder_with_config(config, TokioRuntimeProvider::default())
                .build()
                .unwrap()
        }

        #[tokio::test]
        async fn srv_and_naptr_records_and_each_address_family_come_back_whole() {
            let resolver = resolver_at(name_server().await);
            let mut srv = records_with(&resolver, "turn.example.", RecordKind::Srv).await;
            srv.sort_by_key(|r| match r {
                DnsRecord::Srv { priority, .. } => *priority,
                _ => u16::MAX,
            });
            assert_eq!(
                srv,
                vec![
                    DnsRecord::Srv {
                        priority: 1,
                        weight: 5,
                        port: 3478,
                        target: "turn1.example.".into(),
                    },
                    DnsRecord::Srv {
                        priority: 2,
                        weight: 0,
                        port: 3479,
                        target: "turn2.example.".into(),
                    },
                ]
            );
            assert_eq!(
                records_with(&resolver, "turn.example.", RecordKind::Naptr).await,
                vec![DnsRecord::Naptr {
                    order: 10,
                    preference: 20,
                    flags: "s".into(),
                    services: "RELAY:turn.udp".into(),
                    regexp: String::new(),
                    replacement: "_turn._udp.example.".into(),
                }]
            );
            assert_eq!(
                addresses_with(&resolver, "turn.example.", 3478, false).await,
                vec![SocketAddr::new(Ipv4Addr::new(192, 0, 2, 7).into(), 3478)]
            );
            assert_eq!(
                addresses_with(&resolver, "turn.example.", 3478, true).await,
                vec![SocketAddr::new(
                    Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 7).into(),
                    3478
                )]
            );
        }
    }
}

#[cfg(test)]
mod self_connection_tests {
    use super::*;

    #[test]
    fn a_connection_is_to_itself_only_when_both_ends_are_the_same_address() {
        let a: SocketAddr = "127.0.0.1:45149".parse().unwrap();
        assert!(is_self_connection(a, a));
        assert!(!is_self_connection(a, "127.0.0.1:45150".parse().unwrap()));
        assert!(!is_self_connection(a, "127.0.0.2:45149".parse().unwrap()));
        let v6: SocketAddr = "[::1]:45149".parse().unwrap();
        assert!(is_self_connection(v6, v6));
        assert!(!is_self_connection(v6, "[::1]:9".parse().unwrap()));
    }
}
