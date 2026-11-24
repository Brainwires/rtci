//! Bring your own async runtime: `rtci-stream-driver` built with `default-features = false`
//! (no tokio, no smol) and driven on a runtime this program implements over `async-executor`
//! (tasks) and `async-io` (reactor and timers). Two `PeerDriver`s on it connect over loopback
//! and exchange a data-channel message each way.
//!
//! `cargo run -p rtci-custom-runtime-example`. The program exits 0 when both messages
//! arrived.
//!
//! What a runtime gives the driver is exactly `rtci_stream_driver::runtime::Runtime`: spawn,
//! a clock and timers, UDP (and multicast) sockets, TCP listen / connect, name resolution and
//! `block_on`. Channels, locks and wake-ups are not the runtime's: the driver brings its own,
//! executor-agnostic ones.

use async_executor::Executor;
use async_io::{Async, Timer};
use bytes::BytesMut;
use rtci::peer_connection::RTCPeerConnectionBuilder;
use rtci::peer_connection::configuration::RTCConfigurationBuilder;
use rtci::peer_connection::event::{RTCDataChannelEvent, RTCPeerConnectionEvent};
use rtci::peer_connection::message::RTCMessage;
use rtci::peer_connection::transport::RTCIceCandidateInit;
use rtci::sansio::Protocol;
use rtci_stream_driver::peer::{PeerDriver, PeerDriverConfig};
use rtci_stream_driver::runtime::{
    self, AsyncTcpListener, AsyncTcpStream, AsyncUdpSocket, BoxFuture, JoinHandle, MulticastConfig,
    RecvMeta, Runtime, TrafficClassMarker, Transmit,
};
use std::future::Future;
use std::io::{self, IoSliceMut, Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream, ToSocketAddrs, UdpSocket};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, ready};
use std::time::{Duration, Instant};

/// The application's runtime: one executor, run by one worker thread and by `block_on`.
#[derive(Debug, Clone)]
struct CustomRuntime {
    executor: Arc<Executor<'static>>,
}

impl CustomRuntime {
    fn new() -> Self {
        let executor = Arc::new(Executor::new());
        let worker = executor.clone();
        std::thread::Builder::new()
            .name("custom-runtime".into())
            .spawn(move || async_io::block_on(worker.run(std::future::pending::<()>())))
            .expect("a worker thread");
        Self { executor }
    }
}

/// A task of the executor; dropping the handle detaches it.
#[derive(Debug)]
struct Task(Mutex<Option<async_executor::Task<()>>>);

impl JoinHandle for Task {
    fn abort(&self) {
        drop(self.0.lock().unwrap().take());
    }

    fn is_finished(&self) -> bool {
        self.0
            .lock()
            .unwrap()
            .as_ref()
            .is_none_or(|t| t.is_finished())
    }

    fn poll_join(&mut self, cx: &mut Context<'_>) -> Poll<()> {
        let slot = self.0.get_mut().unwrap();
        let Some(task) = slot.as_mut() else {
            return Poll::Ready(());
        };
        ready!(Pin::new(task).poll(cx));
        *slot = None;
        Poll::Ready(())
    }
}

impl Drop for Task {
    fn drop(&mut self) {
        if let Some(task) = self.0.get_mut().unwrap().take() {
            task.detach();
        }
    }
}

impl Runtime for CustomRuntime {
    fn spawn(&self, future: BoxFuture<'static, ()>) -> Box<dyn JoinHandle> {
        Box::new(Task(Mutex::new(Some(self.executor.spawn(future)))))
    }

    fn now(&self) -> Instant {
        Instant::now()
    }

    fn sleep_until(&self, deadline: Instant) -> BoxFuture<'static, ()> {
        Box::pin(async move {
            Timer::at(deadline).await;
        })
    }

    fn bind_udp(&self, local: SocketAddr) -> io::Result<Arc<dyn AsyncUdpSocket>> {
        Udp::wrap(runtime::std_udp(local)?)
    }

    fn bind_udp_multicast(&self, config: &MulticastConfig) -> io::Result<Arc<dyn AsyncUdpSocket>> {
        Udp::wrap(runtime::std_multicast(config)?)
    }

    fn listen_tcp(
        &self,
        local: SocketAddr,
        reuse_address: bool,
    ) -> io::Result<Arc<dyn AsyncTcpListener>> {
        Ok(Arc::new(Listener(Async::new(runtime::std_tcp_listener(
            local,
            reuse_address,
        )?)?)))
    }

    fn connect_tcp(
        &self,
        local: SocketAddr,
        remote: SocketAddr,
        reuse_address: bool,
    ) -> BoxFuture<'static, io::Result<Arc<dyn AsyncTcpStream>>> {
        let started = runtime::std_tcp_connect_start(local, remote, reuse_address);
        Box::pin(async move {
            let stream = Async::new(started?)?;
            stream.writable().await?;
            if let Some(e) = stream.get_ref().take_error()? {
                return Err(e);
            }
            stream.get_ref().peer_addr()?;
            stream.get_ref().set_nodelay(true)?;
            Ok(Arc::new(Tcp(stream)) as Arc<dyn AsyncTcpStream>)
        })
    }

    fn resolve_host(
        &self,
        host: &str,
        port: u16,
    ) -> BoxFuture<'static, io::Result<Vec<SocketAddr>>> {
        // The system resolver blocks: it runs on a thread of its own.
        let (tx, rx) = async_channel::bounded(1);
        let host = host.to_owned();
        std::thread::spawn(move || {
            let found = (host.as_str(), port)
                .to_socket_addrs()
                .map(|addresses| addresses.collect());
            let _ = tx.send_blocking(found);
        });
        Box::pin(async move {
            rx.recv()
                .await
                .unwrap_or_else(|_| Err(io::Error::other("the resolver thread ended")))
        })
    }

    fn block_on(&self, future: Pin<Box<dyn Future<Output = ()> + '_>>) {
        async_io::block_on(self.executor.run(future));
    }
}

#[derive(Debug)]
struct Udp {
    socket: Async<UdpSocket>,
    ipv6: bool,
    marker: TrafficClassMarker,
}

impl Udp {
    fn wrap(socket: UdpSocket) -> io::Result<Arc<dyn AsyncUdpSocket>> {
        let ipv6 = socket.local_addr()?.is_ipv6();
        Ok(Arc::new(Self {
            socket: Async::new(socket)?,
            ipv6,
            marker: TrafficClassMarker::default(),
        }))
    }
}

impl AsyncUdpSocket for Udp {
    fn poll_send(&self, cx: &mut Context<'_>, transmit: &Transmit<'_>) -> Poll<io::Result<usize>> {
        let socket = self.socket.get_ref();
        self.marker
            .apply(socket.into(), self.ipv6, transmit.traffic_class);
        loop {
            match socket.send_to(transmit.contents, transmit.destination) {
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    ready!(self.socket.poll_writable(cx))?;
                }
                other => return Poll::Ready(other),
            }
        }
    }

    fn poll_recv(
        &self,
        cx: &mut Context<'_>,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        loop {
            match self.socket.get_ref().recv_from(&mut bufs[0]) {
                Ok((len, addr)) => {
                    meta[0] = RecvMeta {
                        addr,
                        len,
                        stride: len,
                        ..RecvMeta::default()
                    };
                    return Poll::Ready(Ok(1));
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    ready!(self.socket.poll_readable(cx))?;
                }
                Err(e) => return Poll::Ready(Err(e)),
            }
        }
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.get_ref().local_addr()
    }

    fn traffic_class(&self) -> io::Result<u32> {
        rtci_stream_driver::sockets::traffic_class(self.socket.get_ref().into(), self.ipv6)
    }

    fn unmarked(&self) -> bool {
        self.marker.refused()
    }
}

#[derive(Debug)]
struct Tcp(Async<TcpStream>);

impl AsyncTcpStream for Tcp {
    fn poll_read(&self, cx: &mut Context<'_>, buf: &mut [u8]) -> Poll<io::Result<usize>> {
        loop {
            match self.0.get_ref().read(buf) {
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    ready!(self.0.poll_readable(cx))?;
                }
                other => return Poll::Ready(other),
            }
        }
    }

    fn poll_write(&self, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        loop {
            match self.0.get_ref().write(buf) {
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    ready!(self.0.poll_writable(cx))?;
                }
                other => return Poll::Ready(other),
            }
        }
    }

    fn shutdown_write(&self) -> io::Result<()> {
        self.0.get_ref().shutdown(std::net::Shutdown::Write)
    }

    fn reset_on_close(&self) -> io::Result<()> {
        runtime::reset_on_close(self.0.get_ref().into())
    }

    fn set_traffic_class(&self, value: u8) -> io::Result<u32> {
        let ipv6 = self.0.get_ref().local_addr()?.is_ipv6();
        runtime::set_and_read_traffic_class(self.0.get_ref().into(), ipv6, value)
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.0.get_ref().local_addr()
    }

    fn peer_addr(&self) -> io::Result<SocketAddr> {
        self.0.get_ref().peer_addr()
    }
}

#[derive(Debug)]
struct Listener(Async<TcpListener>);

impl AsyncTcpListener for Listener {
    fn poll_accept(
        &self,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<(Arc<dyn AsyncTcpStream>, SocketAddr)>> {
        loop {
            match self.0.get_ref().accept() {
                Ok((stream, remote)) => {
                    let _ = stream.set_nodelay(true);
                    return Poll::Ready(Ok((Arc::new(Tcp(Async::new(stream)?)), remote)));
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    ready!(self.0.poll_readable(cx))?;
                }
                Err(e) => return Poll::Ready(Err(e)),
            }
        }
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.0.get_ref().local_addr()
    }
}

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

/// A peer: the driver and what the application saw.
struct Peer {
    driver: PeerDriver,
    outgoing: Vec<RTCIceCandidateInit>,
    open: bool,
    received: Vec<Vec<u8>>,
}

impl Peer {
    fn new(runtime: Arc<dyn Runtime>) -> Result<Self> {
        let pc = RTCPeerConnectionBuilder::new()
            .with_configuration(RTCConfigurationBuilder::new().build())
            .build(runtime.now())?;
        let loopback = IpAddr::V4(Ipv4Addr::LOCALHOST);
        Ok(Self {
            driver: PeerDriver::with_runtime(runtime, pc, PeerDriverConfig::on(vec![loopback])),
            outgoing: vec![],
            open: false,
            received: vec![],
        })
    }

    fn collect(&mut self) {
        while let Some(event) = self.driver.poll_event() {
            match event {
                RTCPeerConnectionEvent::OnIceCandidateEvent(event) => {
                    if let Some(candidate) = event.candidate.filter(|c| !c.end_of_candidates)
                        && let Ok(init) = candidate.to_json()
                    {
                        self.outgoing.push(init);
                    }
                }
                RTCPeerConnectionEvent::OnDataChannel(RTCDataChannelEvent::OnOpen(_)) => {
                    self.open = true;
                }
                _ => {}
            }
        }
        while let Some(read) = self.driver.pc_mut().poll_read() {
            if let RTCMessage::DataChannelMessage(_, message) = read.message {
                self.received.push(message.data.to_vec());
            }
        }
    }
}

async fn run(runtime: Arc<dyn Runtime>) -> Result<()> {
    let mut a = Peer::new(runtime.clone())?;
    let mut b = Peer::new(runtime.clone())?;
    let channel = a.driver.pc_mut().create_data_channel("custom", None)?.id();
    let offer = a.driver.pc_mut().create_offer(None)?;
    let now = runtime.now();
    a.driver
        .pc_mut()
        .set_local_description(now, offer.clone())?;
    b.driver.pc_mut().set_remote_description(now, offer)?;
    let answer = b.driver.pc_mut().create_answer(None)?;
    b.driver
        .pc_mut()
        .set_local_description(now, answer.clone())?;
    a.driver.pc_mut().set_remote_description(now, answer)?;
    let mut sent = false;
    let mut replied = false;
    let deadline = runtime.now() + Duration::from_secs(30);
    while runtime.now() < deadline {
        a.driver.step(Duration::from_millis(2)).await?;
        b.driver.step(Duration::from_millis(2)).await?;
        a.collect();
        b.collect();
        for c in std::mem::take(&mut a.outgoing) {
            b.driver.pc_mut().add_remote_candidate(c)?;
        }
        for c in std::mem::take(&mut b.outgoing) {
            a.driver.pc_mut().add_remote_candidate(c)?;
        }
        if !sent && a.open && b.open {
            let now = runtime.now();
            let mut dc = a
                .driver
                .pc_mut()
                .data_channel(channel)
                .ok_or("a's channel")?;
            dc.send(now, BytesMut::from(&b"from a"[..]))?;
            a.driver.flush()?;
            sent = true;
        }
        if !replied && !b.received.is_empty() {
            // b answers on the channel it was given (the same id on both sides).
            let now = runtime.now();
            let mut dc = b
                .driver
                .pc_mut()
                .data_channel(channel)
                .ok_or("b's channel")?;
            dc.send(now, BytesMut::from(&b"from b"[..]))?;
            b.driver.flush()?;
            replied = true;
        }
        if !a.received.is_empty() {
            assert_eq!(b.received, vec![b"from a".to_vec()]);
            assert_eq!(a.received, vec![b"from b".to_vec()]);
            return Ok(());
        }
    }
    Err(format!(
        "timed out: a {:?} open {} received {}, b {:?} open {} received {}",
        a.driver.pc().connection_state(),
        a.open,
        a.received.len(),
        b.driver.pc().connection_state(),
        b.open,
        b.received.len()
    )
    .into())
}

fn main() {
    let runtime: Arc<dyn Runtime> = Arc::new(CustomRuntime::new());
    let mut outcome = None;
    runtime.block_on(Box::pin(async {
        outcome = Some(run(runtime.clone()).await);
    }));
    match outcome {
        Some(Ok(())) => println!("custom runtime: connected, one data-channel message each way"),
        Some(Err(e)) => {
            eprintln!("custom runtime: {e}");
            std::process::exit(1);
        }
        None => {
            eprintln!("custom runtime: block_on returned without running the future");
            std::process::exit(1);
        }
    }
}
