//! A tokio driver for the stream transports of the sans-I/O engine (`rtc_shared::stream`).
//!
//! The engine decides everything about its TCP connections (ICE-TCP candidates, TURN over TCP
//! or TLS) and names them by id; this driver only owns the sockets. The loop that runs a peer
//! connection does four things with it:
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
//! Each connection has a reader task, which reports what it reads in whatever pieces the socket
//! gives (the engine reassembles frames), and a writer task, which writes transmits in order and
//! reports each with `StreamEvent::Written`, the engine's back-pressure signal. Sockets are
//! created on the thread that calls [`StreamDriver::execute`] inside a tokio runtime, so a
//! current-thread runtime on a thread that entered a network namespace keeps them there.

#![warn(missing_docs)]

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
    /// ([`StreamDriver::adopt_shared`]).
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
    stream.set_nodelay(true)?;
    Ok(stream)
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
