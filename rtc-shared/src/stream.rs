//! Stream transports (TCP, and TLS over TCP) for a sans-I/O engine.
//!
//! A datagram engine is driven with one call per received datagram and one per datagram to
//! send. A stream has more to it: it is opened (connect, or accept on a listener), it carries
//! bytes in whatever pieces the network delivers, it can only take so much at a time, and it
//! ends, cleanly or not. This module puts all of that behind ids, so the engine keeps every
//! decision and the application (the *driver*) keeps only the sockets:
//!
//! | Direction | What | Type |
//! |---|---|---|
//! | engine → driver | listen on / stop listening on an address; connect to an address from a local one; close; reset | [`StreamCommand`] |
//! | driver → engine | listening (with the bound address); connected (with the local address); failed; written; closed by the peer; reset | [`StreamEvent`] |
//! | driver → engine | a connection accepted on a listener: the engine gives it an id | [`StreamTable::accept`] |
//! | driver → engine | bytes read from a connection, in any segmentation | [`StreamTable::read`] |
//! | engine → driver | bytes to write on a connection, in order | [`StreamTransmit`] |
//!
//! [`StreamTable`] is the engine's half: it allocates the ids, frames outgoing messages
//! ([`Framing::Rfc4571`] for ICE-TCP, RFC 4571 / RFC 6544; [`Framing::Turn`] for TURN over TCP,
//! RFC 8656 §12.5, whose messages delimit themselves), splits incoming bytes back into
//! messages whatever the read sizes, optionally runs a [`StreamLayer`] (TLS) between the two,
//! and applies back-pressure.
//!
//! # Back-pressure
//!
//! The driver reports with [`StreamEvent::Written`] how many bytes of a connection have left
//! for the socket. The table hands out at most [`StreamConfig::window`] bytes a connection
//! that are not yet reported written (one transmit is always allowed, so progress never
//! stops), and keeps what does not fit queued, up to [`StreamConfig::max_queued`] bytes.
//! Beyond that a message is dropped whole, before framing or encryption, exactly as a
//! congested datagram path would lose it: a byte stream is never cut inside a frame or a TLS
//! record. [`StreamTable::send`] says which happened.
//!
//! # Order of commands and transmits
//!
//! A [`StreamCommand::Close`] is issued only after the last [`StreamTransmit`] of its
//! connection has been handed out, so a driver that writes each transmit as it takes it closes
//! after the last byte. [`StreamCommand::Reset`] discards whatever the driver still holds.
//!
//! # Example: one framed message each way over a connection the engine asked for
//!
//! ```
//! use rtc_shared::stream::*;
//!
//! let mut engine = StreamTable::new(StreamConfig::default());
//! let local = "10.0.0.1:0".parse().unwrap();
//! let remote = "10.0.0.2:5000".parse().unwrap();
//! let id = engine.connect(local, remote, Framing::Rfc4571, 0, false, None).unwrap();
//! assert_eq!(
//!     engine.poll_command(),
//!     Some(StreamCommand::Connect { id, local, remote, reuse_address: false })
//! );
//! // The engine may queue data before the connection is up.
//! assert!(engine.send(id, b"hello").unwrap());
//! assert!(engine.poll_transmit().is_none());
//!
//! // The driver connected from an ephemeral port.
//! let bound = "10.0.0.1:40001".parse().unwrap();
//! engine.handle_event(StreamEvent::Connected { id, local: bound }).unwrap();
//! let transmit = engine.poll_transmit().unwrap();
//! assert_eq!(transmit.data, b"\x00\x05hello");
//! engine.handle_event(StreamEvent::Written { id, bytes: transmit.data.len() }).unwrap();
//!
//! // The answer arrives one byte at a time.
//! let mut messages = vec![];
//! for byte in b"\x00\x03bye" {
//!     messages.extend(engine.read(id, &[*byte]).unwrap());
//! }
//! assert_eq!(messages, vec![b"bye".to_vec()]);
//! ```

use crate::error::{Error, Result};
use crate::tcp_framing::{FRAMING_HEADER_LEN, MAX_FRAMED_PACKET_SIZE, TcpFrameDecoder};
use crate::turn_framing::TurnStreamDecoder;
use std::collections::{BTreeMap, VecDeque};
use std::fmt;
use std::net::SocketAddr;
use std::ops::Bound;

/// A connection, as the engine names it. Every id is allocated by the engine: for a connection
/// it asks for in [`StreamCommand::Connect`], and for one the driver accepted, by
/// [`StreamTable::accept`]. Ids are never reused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct StreamId(pub u64);

impl fmt::Display for StreamId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "stream#{}", self.0)
    }
}

/// A listening socket, as the engine names it in [`StreamCommand::Listen`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ListenerId(pub u64);

impl fmt::Display for ListenerId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "listener#{}", self.0)
    }
}

/// What the engine asks the driver to do with its sockets.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum StreamCommand {
    /// Listen for TCP connections on `local` (port 0: any free port) and accept them, each
    /// reported with [`StreamTable::accept`]. Answer with [`StreamEvent::Listening`], naming
    /// the bound address, or [`StreamEvent::ListenFailed`].
    Listen {
        /// The listener's id.
        listener: ListenerId,
        /// The address to bind.
        local: SocketAddr,
        /// Bind with `SO_REUSEADDR` (and `SO_REUSEPORT` where it exists): the engine will also
        /// connect from this address (an RFC 6544 simultaneous-open candidate).
        reuse_address: bool,
    },
    /// Close the listener. Connections it accepted stay open.
    StopListening {
        /// The listener's id.
        listener: ListenerId,
    },
    /// Open a TCP connection from `local` (port 0: an ephemeral port on that address) to
    /// `remote`. Answer with [`StreamEvent::Connected`], naming the local address the
    /// connection got, or [`StreamEvent::ConnectFailed`].
    Connect {
        /// The connection's id.
        id: StreamId,
        /// The address to bind before connecting.
        local: SocketAddr,
        /// Where to connect.
        remote: SocketAddr,
        /// Bind with `SO_REUSEADDR` (and `SO_REUSEPORT` where it exists): a listener is on
        /// `local` too (RFC 6544 simultaneous open).
        reuse_address: bool,
    },
    /// Write what was handed out for the connection, then close it (FIN). Report
    /// [`StreamEvent::Closed`] when it is closed.
    Close {
        /// The connection's id.
        id: StreamId,
    },
    /// Abort the connection now (RST), discarding what was not written. The engine has
    /// forgotten the id: nothing needs to be reported.
    Reset {
        /// The connection's id.
        id: StreamId,
    },
    /// Resolve `host` (a server's name, both IPv6 and IPv4 at once, RFC 8305 section 3) and
    /// answer with [`StreamEvent::Resolved`], `port` on every address.
    Resolve {
        /// The query's id.
        query: u64,
        /// The name.
        host: String,
        /// The port the addresses get.
        port: u16,
    },
    /// Look up the `kind` records of `name` (SRV, RFC 2782; NAPTR, RFC 3403) and answer with
    /// [`StreamEvent::ResolvedRecords`], an empty list when there are none or the driver
    /// cannot look them up. Used to find a STUN or TURN server whose URI gives no port (RFC
    /// 5928 section 3, RFC 8489 section 8); an answer that does not come within
    /// [`RECORDS_TIMEOUT`] counts as empty.
    ResolveRecords {
        /// The query's id.
        query: u64,
        /// The name (for SRV, the whole `_service._proto.name`).
        name: String,
        /// The record type.
        kind: RecordKind,
    },
}

/// How long the engine waits for a [`StreamCommand::ResolveRecords`] answer before it takes
/// the name's addresses instead (a driver that does not look records up).
pub const RECORDS_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(2);

/// A DNS record type the engine asks for ([`StreamCommand::ResolveRecords`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum RecordKind {
    /// SRV (RFC 2782).
    Srv,
    /// NAPTR (RFC 3403), for S-NAPTR (RFC 3958).
    Naptr,
}

/// A DNS record, as the driver reports it ([`StreamEvent::ResolvedRecords`]).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum DnsRecord {
    /// An SRV record (RFC 2782).
    Srv {
        /// Lower is tried first.
        priority: u16,
        /// Among equal priorities, the share of selections.
        weight: u16,
        /// The server's port.
        port: u16,
        /// The server's name ("." for "no service here").
        target: String,
    },
    /// A NAPTR record (RFC 3403).
    Naptr {
        /// Lower is used first.
        order: u16,
        /// Among equal orders, lower is used first.
        preference: u16,
        /// `S` (the replacement is an SRV name), `A` (an address name), ...
        flags: String,
        /// The service field, `RELAY:turn.tcp` and the like for TURN (RFC 5928 section 4).
        services: String,
        /// The regular expression (unused by S-NAPTR).
        regexp: String,
        /// The next name to look up.
        replacement: String,
    },
}

/// What the driver tells the engine about its sockets.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum StreamEvent {
    /// The listener is bound to `local`.
    Listening {
        /// The listener's id.
        listener: ListenerId,
        /// The address it is bound to (the port chosen when the command asked for port 0).
        local: SocketAddr,
    },
    /// The listener could not be bound.
    ListenFailed {
        /// The listener's id.
        listener: ListenerId,
    },
    /// The connection is established from `local`.
    Connected {
        /// The connection's id.
        id: StreamId,
        /// Its local address (with the ephemeral port it got).
        local: SocketAddr,
    },
    /// The connection could not be established (refused, unreachable, timed out).
    ConnectFailed {
        /// The connection's id.
        id: StreamId,
    },
    /// `bytes` more of the connection's transmits have been written to the socket.
    Written {
        /// The connection's id.
        id: StreamId,
        /// How many bytes.
        bytes: usize,
    },
    /// The connection is closed: the peer finished it (end of stream), or a close the engine
    /// asked for is done.
    Closed {
        /// The connection's id.
        id: StreamId,
    },
    /// The connection broke (reset by the peer, or an I/O error).
    Reset {
        /// The connection's id.
        id: StreamId,
    },
    /// A [`StreamCommand::Resolve`] is answered: the addresses, empty when the name did not
    /// resolve.
    Resolved {
        /// The query's id.
        query: u64,
        /// The addresses, with the query's port.
        addresses: Vec<SocketAddr>,
    },
    /// A [`StreamCommand::ResolveRecords`] is answered (an empty list: none).
    ResolvedRecords {
        /// The query's id.
        query: u64,
        /// The records.
        records: Vec<DnsRecord>,
    },
    /// One family of a [`StreamCommand::Resolve`] is answered (AAAA with `ipv6`, A without),
    /// as it arrives: the engine starts on the first answer (RFC 8305 section 3). A driver
    /// answers each family once, an empty list when it has none; or answers the whole query
    /// once with [`StreamEvent::Resolved`].
    ResolvedFamily {
        /// The query's id.
        query: u64,
        /// Whether these are the IPv6 (AAAA) addresses.
        ipv6: bool,
        /// The addresses of that family, with the query's port.
        addresses: Vec<SocketAddr>,
    },
}

/// Bytes to write on a connection, after every earlier transmit of the same connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamTransmit {
    /// The connection.
    pub id: StreamId,
    /// The bytes, framed (and encrypted, over TLS).
    pub data: Vec<u8>,
}

/// How messages are delimited on a connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Framing {
    /// RFC 4571: a two-byte length before each message (ICE-TCP, RFC 6544 section 3).
    Rfc4571,
    /// TURN over TCP / TLS (RFC 8656 section 12.5): STUN and ChannelData messages back to
    /// back, each delimited by its own header.
    Turn,
}

impl Framing {
    /// `message` as it goes on the wire.
    ///
    /// # Errors
    ///
    /// [`Error::ErrStreamMessageTooLong`] for an RFC 4571 message over 65535 bytes.
    pub fn encode(self, message: &[u8]) -> Result<Vec<u8>> {
        match self {
            Framing::Rfc4571 => {
                if message.len() > MAX_FRAMED_PACKET_SIZE {
                    return Err(Error::ErrStreamMessageTooLong);
                }
                let mut framed = Vec::with_capacity(FRAMING_HEADER_LEN + message.len());
                framed.extend_from_slice(&(message.len() as u16).to_be_bytes());
                framed.extend_from_slice(message);
                Ok(framed)
            }
            Framing::Turn => Ok(message.to_vec()),
        }
    }

    /// The most bytes one message takes on the wire, framing included.
    fn max_wire_len(self) -> usize {
        match self {
            Framing::Rfc4571 => FRAMING_HEADER_LEN + MAX_FRAMED_PACKET_SIZE,
            // A STUN header (20) or a padded ChannelData message (4 + 65535 + 1).
            Framing::Turn => 20 + MAX_FRAMED_PACKET_SIZE,
        }
    }
}

/// Splits a byte stream of one [`Framing`] back into its messages. Bytes can be fed in any
/// segmentation; memory stays bounded by two messages whatever the read size, because input is
/// taken a message's worth at a time and drained in between.
#[derive(Debug)]
pub struct StreamDecoder {
    framing: Framing,
    rfc4571: TcpFrameDecoder,
    turn: TurnStreamDecoder,
}

impl StreamDecoder {
    /// A decoder for `framing`.
    pub fn new(framing: Framing) -> Self {
        Self {
            framing,
            rfc4571: TcpFrameDecoder::new(),
            turn: TurnStreamDecoder::new(),
        }
    }

    /// Takes `data` and returns every message it completes, in order.
    ///
    /// # Errors
    ///
    /// For [`Framing::Turn`], bytes that start neither a STUN nor a ChannelData message
    /// ([`Error::OtherTurnErr`]): the stream cannot be resynchronised and must be closed.
    pub fn decode(&mut self, data: &[u8]) -> Result<Vec<Vec<u8>>> {
        let mut out = Vec::new();
        for chunk in data.chunks(self.framing.max_wire_len()) {
            match self.framing {
                Framing::Rfc4571 => {
                    // Never refused: at most one partial frame is held before the chunk.
                    self.rfc4571.push(chunk)?;
                    while let Some(message) = self.rfc4571.next_packet() {
                        out.push(message);
                    }
                }
                Framing::Turn => {
                    self.turn.extend_from_slice(chunk);
                    while let Some(message) = self.turn.next_message()? {
                        out.push(message);
                    }
                }
            }
        }
        Ok(out)
    }

    /// Bytes held that do not make a whole message yet.
    pub fn buffered_len(&self) -> usize {
        match self.framing {
            Framing::Rfc4571 => self.rfc4571.buffered_len(),
            Framing::Turn => self.turn.buffered_len(),
        }
    }
}

/// A security layer between the framing and the socket: TLS for TURN over TLS, in its
/// sans-I/O form. Ciphertext comes in with [`receive`](Self::receive), plaintext goes out
/// with [`send`](Self::send) once the handshake [is done](Self::is_established), and the
/// table collects what the layer has to write after every call.
pub trait StreamLayer: Send {
    /// Takes bytes received from the peer and processes them.
    ///
    /// # Errors
    ///
    /// A protocol error (bad record, failed certificate verification): the connection is
    /// reset.
    fn receive(&mut self, data: &[u8]) -> Result<()>;
    /// Appends the plaintext received so far to `out`.
    fn read_plaintext(&mut self, out: &mut Vec<u8>) -> Result<()>;
    /// Whether plaintext can be sent: the handshake is complete.
    fn is_established(&self) -> bool;
    /// Takes plaintext to send.
    fn send(&mut self, plaintext: &[u8]) -> Result<()>;
    /// Appends the bytes the layer has to write to `out`.
    fn write_wire(&mut self, out: &mut Vec<u8>) -> Result<()>;
    /// Starts an orderly close (TLS `close_notify`).
    fn close(&mut self);
    /// Whether the peer closed the layer (TLS `close_notify` received).
    fn peer_closed(&self) -> bool;
}

/// Limits of a [`StreamTable`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StreamConfig {
    /// Bytes of a connection handed to the driver and not yet reported written, beyond which
    /// no more is handed out (one transmit is always allowed).
    pub window: usize,
    /// Bytes of a connection queued in the engine, beyond which a message is dropped whole.
    pub max_queued: usize,
    /// Connections at most, accepted ones included; an accept beyond it is refused.
    pub max_connections: usize,
}

impl Default for StreamConfig {
    fn default() -> Self {
        Self {
            window: 64 * 1024,
            max_queued: 512 * 1024,
            max_connections: 256,
        }
    }
}

/// How a connection came to be.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum StreamOrigin {
    /// The engine asked for it ([`StreamCommand::Connect`]).
    Connected,
    /// The driver accepted it on a listener.
    Accepted(ListenerId),
}

/// Where a connection is in its life.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum StreamState {
    /// Asked for, not yet established.
    Connecting,
    /// Established.
    Open,
    /// The engine closed it; the driver writes what it holds, then closes.
    Closing,
}

/// A connection, as [`StreamTable::info`] describes it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StreamInfo {
    /// Its id.
    pub id: StreamId,
    /// The owner's tag, given when it was opened or when its listener was.
    pub tag: u32,
    /// How it came to be.
    pub origin: StreamOrigin,
    /// Its state.
    pub state: StreamState,
    /// Its local address: the requested one until it is established, then the bound one.
    pub local: SocketAddr,
    /// The local address it was asked for (port 0: any).
    pub requested_local: SocketAddr,
    /// The peer's address.
    pub remote: SocketAddr,
    /// Its framing.
    pub framing: Framing,
    /// Messages sent and received, and messages dropped by back-pressure.
    pub messages_sent: u64,
    /// Messages received.
    pub messages_received: u64,
    /// Messages dropped because the queue was full.
    pub messages_dropped: u64,
    /// Bytes handed to the driver and not yet reported written.
    pub in_flight: usize,
    /// Bytes queued in the engine.
    pub queued: usize,
}

/// What a [`StreamTable`] reports to its owner, in the order it happened.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum StreamNotice {
    /// A listener is bound.
    Listening {
        /// The listener.
        listener: ListenerId,
        /// Its tag.
        tag: u32,
        /// The bound address.
        local: SocketAddr,
    },
    /// A listener could not be bound.
    ListenFailed {
        /// The listener.
        listener: ListenerId,
        /// Its tag.
        tag: u32,
        /// The address it was asked for.
        requested: SocketAddr,
    },
    /// A connection the engine asked for is established.
    Connected {
        /// The connection.
        id: StreamId,
        /// Its tag.
        tag: u32,
        /// Its local address.
        local: SocketAddr,
        /// The peer.
        remote: SocketAddr,
    },
    /// A connection the engine asked for could not be established; its queued messages are
    /// gone.
    ConnectFailed {
        /// The connection.
        id: StreamId,
        /// Its tag.
        tag: u32,
        /// The local address it was asked for.
        local: SocketAddr,
        /// The peer.
        remote: SocketAddr,
    },
    /// A connection is gone: closed (`reset` false) or broken (`reset` true). Not reported
    /// for a connection the engine reset itself.
    Closed {
        /// The connection.
        id: StreamId,
        /// Its tag.
        tag: u32,
        /// Its local address.
        local: SocketAddr,
        /// The peer.
        remote: SocketAddr,
        /// Whether it broke rather than closed.
        reset: bool,
    },
    /// A name the engine asked for was resolved.
    Resolved {
        /// The query.
        query: u64,
        /// The addresses (empty: the name did not resolve).
        addresses: Vec<SocketAddr>,
    },
    /// Records the engine asked for were looked up.
    ResolvedRecords {
        /// The query.
        query: u64,
        /// The records (possibly none).
        records: Vec<DnsRecord>,
    },
    /// One family of a name the engine asked for was resolved.
    ResolvedFamily {
        /// The query.
        query: u64,
        /// Whether these are the IPv6 addresses.
        ipv6: bool,
        /// The addresses of that family (possibly none).
        addresses: Vec<SocketAddr>,
    },
}

struct Listener {
    tag: u32,
    framing: Framing,
    requested: SocketAddr,
    bound: Option<SocketAddr>,
}

struct Connection {
    tag: u32,
    origin: StreamOrigin,
    state: StreamState,
    requested_local: SocketAddr,
    local: SocketAddr,
    remote: SocketAddr,
    framing: Framing,
    decoder: StreamDecoder,
    layer: Option<Box<dyn StreamLayer>>,
    /// Framed messages waiting for the layer's handshake.
    pending_plaintext: VecDeque<Vec<u8>>,
    /// Wire bytes not yet handed to the driver.
    queue: VecDeque<Vec<u8>>,
    queued: usize,
    in_flight: usize,
    close_sent: bool,
    messages_sent: u64,
    messages_received: u64,
    messages_dropped: u64,
}

impl Connection {
    fn info(&self, id: StreamId) -> StreamInfo {
        StreamInfo {
            id,
            tag: self.tag,
            origin: self.origin,
            state: self.state,
            local: self.local,
            requested_local: self.requested_local,
            remote: self.remote,
            framing: self.framing,
            messages_sent: self.messages_sent,
            messages_received: self.messages_received,
            messages_dropped: self.messages_dropped,
            in_flight: self.in_flight,
            queued: self.queued,
        }
    }

    fn enqueue_wire(&mut self, bytes: Vec<u8>) {
        if !bytes.is_empty() {
            self.queued += bytes.len();
            self.queue.push_back(bytes);
        }
    }

    /// Moves what the layer has to write into the queue.
    fn collect_layer_output(&mut self) -> Result<()> {
        if let Some(layer) = self.layer.as_mut() {
            let mut out = Vec::new();
            layer.write_wire(&mut out)?;
            self.enqueue_wire(out);
        }
        Ok(())
    }

    /// Hands messages that waited for the handshake to the layer once it is established.
    fn flush_pending_plaintext(&mut self) -> Result<()> {
        let Some(layer) = self.layer.as_mut() else {
            return Ok(());
        };
        if !layer.is_established() {
            return Ok(());
        }
        while let Some(frame) = self.pending_plaintext.pop_front() {
            self.queued -= frame.len();
            layer.send(&frame)?;
        }
        self.collect_layer_output()
    }
}

/// The engine's side of its stream transports: listeners, connections, framing, the optional
/// security layer and back-pressure. See the [module documentation](self).
///
/// The *tag* given to [`listen`](Self::listen) and [`connect`](Self::connect) is the owner's:
/// one table can serve several users (ICE-TCP and a TURN client, say), each finding its
/// connections by tag.
pub struct StreamTable {
    config: StreamConfig,
    next_id: u64,
    next_listener: u64,
    connections: BTreeMap<StreamId, Connection>,
    listeners: BTreeMap<ListenerId, Listener>,
    commands: VecDeque<StreamCommand>,
    notices: VecDeque<StreamNotice>,
    last_transmit: Option<StreamId>,
    next_query: u64,
}

impl fmt::Debug for StreamTable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StreamTable")
            .field("connections", &self.connections.len())
            .field("listeners", &self.listeners.len())
            .field("commands", &self.commands.len())
            .finish()
    }
}

impl Default for StreamTable {
    fn default() -> Self {
        Self::new(StreamConfig::default())
    }
}

impl StreamTable {
    /// An empty table.
    pub fn new(config: StreamConfig) -> Self {
        Self {
            config,
            next_id: 1,
            next_listener: 1,
            connections: BTreeMap::new(),
            listeners: BTreeMap::new(),
            commands: VecDeque::new(),
            notices: VecDeque::new(),
            last_transmit: None,
            next_query: 1,
        }
    }

    /// Its limits.
    pub fn config(&self) -> StreamConfig {
        self.config
    }

    /// Asks the driver to listen on `local`; connections it accepts get `framing` and `tag`.
    pub fn listen(
        &mut self,
        local: SocketAddr,
        framing: Framing,
        tag: u32,
        reuse_address: bool,
    ) -> ListenerId {
        let listener = ListenerId(self.next_listener);
        self.next_listener += 1;
        self.listeners.insert(
            listener,
            Listener {
                tag,
                framing,
                requested: local,
                bound: None,
            },
        );
        self.commands.push_back(StreamCommand::Listen {
            listener,
            local,
            reuse_address,
        });
        listener
    }

    /// Asks the driver to resolve `host`; the answer comes as [`StreamNotice::Resolved`] with
    /// the returned query id.
    pub fn resolve(&mut self, host: String, port: u16) -> u64 {
        let query = self.next_query;
        self.next_query += 1;
        self.commands
            .push_back(StreamCommand::Resolve { query, host, port });
        query
    }

    /// Asks the driver for the `kind` records of `name`; the answer comes as
    /// [`StreamNotice::ResolvedRecords`] with the returned query id (ids are shared with
    /// [`resolve`](Self::resolve)).
    pub fn resolve_records(&mut self, name: String, kind: RecordKind) -> u64 {
        let query = self.next_query;
        self.next_query += 1;
        self.commands
            .push_back(StreamCommand::ResolveRecords { query, name, kind });
        query
    }

    /// Asks the driver to close the listener. Unknown listeners are ignored.
    pub fn stop_listening(&mut self, listener: ListenerId) {
        if self.listeners.remove(&listener).is_some() {
            self.commands
                .push_back(StreamCommand::StopListening { listener });
        }
    }

    /// The address a listener is bound to, once the driver said so.
    pub fn listener_address(&self, listener: ListenerId) -> Option<SocketAddr> {
        self.listeners.get(&listener).and_then(|l| l.bound)
    }

    /// The listeners: id, tag, requested and bound address.
    pub fn listeners(
        &self,
    ) -> impl Iterator<Item = (ListenerId, u32, SocketAddr, Option<SocketAddr>)> + '_ {
        self.listeners
            .iter()
            .map(|(id, l)| (*id, l.tag, l.requested, l.bound))
    }

    /// Asks the driver for a connection from `local` (port 0: ephemeral) to `remote`. Messages
    /// can be sent at once; they wait for the connection. With a `layer`, what it writes first
    /// (a TLS ClientHello) is sent first, and messages wait for its handshake.
    ///
    /// # Errors
    ///
    /// [`Error::ErrBufferFull`] when the table holds [`StreamConfig::max_connections`]; an
    /// error of the layer.
    pub fn connect(
        &mut self,
        local: SocketAddr,
        remote: SocketAddr,
        framing: Framing,
        tag: u32,
        reuse_address: bool,
        layer: Option<Box<dyn StreamLayer>>,
    ) -> Result<StreamId> {
        if self.connections.len() >= self.config.max_connections {
            return Err(Error::ErrBufferFull);
        }
        let id = StreamId(self.next_id);
        self.next_id += 1;
        let mut connection = Connection {
            tag,
            origin: StreamOrigin::Connected,
            state: StreamState::Connecting,
            requested_local: local,
            local,
            remote,
            framing,
            decoder: StreamDecoder::new(framing),
            layer,
            pending_plaintext: VecDeque::new(),
            queue: VecDeque::new(),
            queued: 0,
            in_flight: 0,
            close_sent: false,
            messages_sent: 0,
            messages_received: 0,
            messages_dropped: 0,
        };
        connection.collect_layer_output()?;
        self.connections.insert(id, connection);
        self.commands.push_back(StreamCommand::Connect {
            id,
            local,
            remote,
            reuse_address,
        });
        Ok(id)
    }

    /// The driver accepted a connection from `remote` on `listener`, arriving on `local`.
    /// Returns its id, or `None` when the listener is unknown or the table is full: the driver
    /// closes the socket then.
    pub fn accept(
        &mut self,
        listener: ListenerId,
        local: SocketAddr,
        remote: SocketAddr,
    ) -> Option<StreamId> {
        let (tag, framing) = {
            let l = self.listeners.get(&listener)?;
            (l.tag, l.framing)
        };
        if self.connections.len() >= self.config.max_connections {
            return None;
        }
        let id = StreamId(self.next_id);
        self.next_id += 1;
        self.connections.insert(
            id,
            Connection {
                tag,
                origin: StreamOrigin::Accepted(listener),
                state: StreamState::Open,
                requested_local: local,
                local,
                remote,
                framing,
                decoder: StreamDecoder::new(framing),
                layer: None,
                pending_plaintext: VecDeque::new(),
                queue: VecDeque::new(),
                queued: 0,
                in_flight: 0,
                close_sent: false,
                messages_sent: 0,
                messages_received: 0,
                messages_dropped: 0,
            },
        );
        Some(id)
    }

    /// Queues `message` on the connection, framed (and encrypted with its layer). Returns
    /// `false` when back-pressure dropped it: the connection already holds
    /// [`StreamConfig::max_queued`] bytes.
    ///
    /// # Errors
    ///
    /// [`Error::ErrUnknownStream`], [`Error::ErrStreamConnectionClosed`] (closing),
    /// [`Error::ErrStreamMessageTooLong`], or an error of the layer.
    pub fn send(&mut self, id: StreamId, message: &[u8]) -> Result<bool> {
        let max_queued = self.config.max_queued;
        let connection = self
            .connections
            .get_mut(&id)
            .ok_or(Error::ErrUnknownStream)?;
        if connection.state == StreamState::Closing {
            return Err(Error::ErrStreamConnectionClosed);
        }
        let frame = connection.framing.encode(message)?;
        if connection.queued > 0 && connection.queued + frame.len() > max_queued {
            connection.messages_dropped += 1;
            return Ok(false);
        }
        connection.messages_sent += 1;
        match connection.layer.as_mut() {
            Some(layer) if layer.is_established() && connection.pending_plaintext.is_empty() => {
                layer.send(&frame)?;
                connection.collect_layer_output()?;
            }
            Some(_) => {
                connection.queued += frame.len();
                connection.pending_plaintext.push_back(frame);
            }
            None => connection.enqueue_wire(frame),
        }
        Ok(true)
    }

    /// Bytes the driver read from the connection, in whatever piece: returns the messages
    /// they complete, in order.
    ///
    /// # Errors
    ///
    /// [`Error::ErrUnknownStream`]; a stream that is not of its framing (TURN) or a layer
    /// error: the connection is then reset ([`StreamCommand::Reset`] is issued) and reported
    /// [`StreamNotice::Closed`].
    pub fn read(&mut self, id: StreamId, data: &[u8]) -> Result<Vec<Vec<u8>>> {
        let connection = self
            .connections
            .get_mut(&id)
            .ok_or(Error::ErrUnknownStream)?;
        let result = (|| {
            let plaintext = match connection.layer.as_mut() {
                Some(layer) => {
                    layer.receive(data)?;
                    let mut plaintext = Vec::new();
                    layer.read_plaintext(&mut plaintext)?;
                    connection.collect_layer_output()?;
                    connection.flush_pending_plaintext()?;
                    plaintext
                }
                None => data.to_vec(),
            };
            connection.decoder.decode(&plaintext)
        })();
        match result {
            Ok(messages) => {
                connection.messages_received += messages.len() as u64;
                let peer_closed = connection
                    .layer
                    .as_ref()
                    .is_some_and(|layer| layer.peer_closed());
                if peer_closed && connection.state != StreamState::Closing {
                    self.close(id);
                }
                Ok(messages)
            }
            Err(err) => {
                self.fail(id, true);
                Err(err)
            }
        }
    }

    /// Closes the connection in order: what is queued is still handed out, then
    /// [`StreamCommand::Close`] is issued. A connection still connecting is reset instead.
    /// Unknown ids are ignored.
    pub fn close(&mut self, id: StreamId) {
        let Some(connection) = self.connections.get_mut(&id) else {
            return;
        };
        match connection.state {
            StreamState::Connecting => self.reset(id),
            StreamState::Closing => {}
            StreamState::Open => {
                connection.state = StreamState::Closing;
                // Messages still waiting for a handshake will never be sent.
                for frame in connection.pending_plaintext.drain(..) {
                    connection.queued -= frame.len();
                }
                if let Some(layer) = connection.layer.as_mut() {
                    layer.close();
                }
                let _ = connection.collect_layer_output();
                self.issue_closes();
            }
        }
    }

    /// Aborts the connection: [`StreamCommand::Reset`] is issued and the id forgotten. Unknown
    /// ids are ignored.
    pub fn reset(&mut self, id: StreamId) {
        if self.connections.remove(&id).is_some() {
            self.commands.push_back(StreamCommand::Reset { id });
        }
    }

    /// Takes an event from the driver. Events for ids the table no longer knows (a connection
    /// it reset, a listener it stopped) are ignored: they cross on the way.
    ///
    /// # Errors
    ///
    /// An error of a connection's layer once it is established.
    pub fn handle_event(&mut self, event: StreamEvent) -> Result<()> {
        match event {
            StreamEvent::Listening { listener, local } => {
                if let Some(l) = self.listeners.get_mut(&listener) {
                    l.bound = Some(local);
                    self.notices.push_back(StreamNotice::Listening {
                        listener,
                        tag: l.tag,
                        local,
                    });
                }
            }
            StreamEvent::ListenFailed { listener } => {
                if let Some(l) = self.listeners.remove(&listener) {
                    self.notices.push_back(StreamNotice::ListenFailed {
                        listener,
                        tag: l.tag,
                        requested: l.requested,
                    });
                }
            }
            StreamEvent::Connected { id, local } => {
                if let Some(connection) = self.connections.get_mut(&id)
                    && connection.state == StreamState::Connecting
                {
                    connection.state = StreamState::Open;
                    connection.local = local;
                    self.notices.push_back(StreamNotice::Connected {
                        id,
                        tag: connection.tag,
                        local,
                        remote: connection.remote,
                    });
                }
            }
            StreamEvent::ConnectFailed { id } => {
                if let Some(connection) = self.connections.remove(&id) {
                    self.notices.push_back(StreamNotice::ConnectFailed {
                        id,
                        tag: connection.tag,
                        local: connection.requested_local,
                        remote: connection.remote,
                    });
                }
            }
            StreamEvent::Written { id, bytes } => {
                if let Some(connection) = self.connections.get_mut(&id) {
                    connection.in_flight = connection.in_flight.saturating_sub(bytes);
                }
            }
            StreamEvent::Closed { id } => self.fail(id, false),
            StreamEvent::Reset { id } => self.fail(id, true),
            StreamEvent::Resolved { query, addresses } => self
                .notices
                .push_back(StreamNotice::Resolved { query, addresses }),
            StreamEvent::ResolvedRecords { query, records } => self
                .notices
                .push_back(StreamNotice::ResolvedRecords { query, records }),
            StreamEvent::ResolvedFamily {
                query,
                ipv6,
                addresses,
            } => self.notices.push_back(StreamNotice::ResolvedFamily {
                query,
                ipv6,
                addresses,
            }),
        }
        Ok(())
    }

    /// Forgets a connection that ended and reports it; with `issue_reset`, also tells the
    /// driver to abort it (an engine-side error).
    fn fail(&mut self, id: StreamId, reset: bool) {
        if let Some(connection) = self.connections.remove(&id) {
            self.notices.push_back(StreamNotice::Closed {
                id,
                tag: connection.tag,
                local: connection.local,
                remote: connection.remote,
                reset,
            });
            if reset {
                self.commands.push_back(StreamCommand::Reset { id });
            }
        }
    }

    /// Issues [`StreamCommand::Close`] for closing connections with nothing left to hand out.
    fn issue_closes(&mut self) {
        for (id, connection) in self.connections.iter_mut() {
            if connection.state == StreamState::Closing
                && !connection.close_sent
                && connection.queue.is_empty()
            {
                connection.close_sent = true;
                self.commands.push_back(StreamCommand::Close { id: *id });
            }
        }
    }

    /// The next command for the driver.
    pub fn poll_command(&mut self) -> Option<StreamCommand> {
        self.issue_closes();
        self.commands.pop_front()
    }

    /// The next notice for the owner.
    pub fn poll_notice(&mut self) -> Option<StreamNotice> {
        self.notices.pop_front()
    }

    /// The next bytes to write, connections taking turns. Only established connections
    /// transmit, each within its [window](StreamConfig::window).
    pub fn poll_transmit(&mut self) -> Option<StreamTransmit> {
        let window = self.config.window;
        let start = self.last_transmit.map_or(Bound::Unbounded, Bound::Excluded);
        let candidates: Vec<StreamId> = self
            .connections
            .range((start, Bound::Unbounded))
            .chain(self.connections.range(..))
            .filter(|(_, c)| {
                c.state != StreamState::Connecting
                    && c.queue.front().is_some_and(|front| {
                        c.in_flight == 0 || c.in_flight + front.len() <= window
                    })
            })
            .map(|(id, _)| *id)
            .take(1)
            .collect();
        let id = *candidates.first()?;
        let connection = self.connections.get_mut(&id)?;
        let mut data = connection.queue.pop_front()?;
        // Coalesce what else fits in the window.
        while let Some(next) = connection.queue.front() {
            if connection.in_flight + data.len() + next.len() > window {
                break;
            }
            let next = connection.queue.pop_front()?;
            data.extend_from_slice(&next);
        }
        connection.queued -= data.len();
        connection.in_flight += data.len();
        self.last_transmit = Some(id);
        if connection.state == StreamState::Closing && connection.queue.is_empty() {
            self.issue_closes();
        }
        Some(StreamTransmit { id, data })
    }

    /// A connection's description, while the table knows it.
    pub fn info(&self, id: StreamId) -> Option<StreamInfo> {
        self.connections.get(&id).map(|c| c.info(id))
    }

    /// Every connection.
    pub fn connections(&self) -> impl Iterator<Item = StreamInfo> + '_ {
        self.connections.iter().map(|(id, c)| c.info(*id))
    }

    /// A connection of `tag` to `remote` from `local` that can still carry data (not closing),
    /// an established one before one still connecting. With `local_ip_only`, any local port
    /// on `local`'s address matches (an RFC 6544 active candidate, whose connections each get
    /// an ephemeral port).
    pub fn find(
        &self,
        tag: u32,
        local: SocketAddr,
        remote: SocketAddr,
        local_ip_only: bool,
    ) -> Option<StreamId> {
        let matches = |c: &Connection| {
            c.tag == tag
                && c.remote == remote
                && c.state != StreamState::Closing
                && (if local_ip_only {
                    c.local.ip() == local.ip()
                } else {
                    c.local == local
                        || (c.state == StreamState::Connecting && c.requested_local == local)
                })
        };
        let mut connecting = None;
        for (id, c) in &self.connections {
            if matches(c) {
                if c.state == StreamState::Open {
                    return Some(*id);
                }
                connecting.get_or_insert(*id);
            }
        }
        connecting
    }

    /// Whether anything is waiting for the driver: a command or a transmit it may take.
    pub fn has_output(&self) -> bool {
        !self.commands.is_empty()
            || self.connections.values().any(|c| {
                (c.state != StreamState::Connecting && !c.queue.is_empty())
                    || (c.state == StreamState::Closing && !c.close_sent && c.queue.is_empty())
            })
    }
}

/// Happy Eyeballs (RFC 8305): address order and staggered connection attempts.
pub mod happy_eyeballs;

#[cfg(test)]
mod stream_test;
