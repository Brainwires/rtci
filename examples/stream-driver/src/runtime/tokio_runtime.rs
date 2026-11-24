//! [`TokioRuntime`] (feature `runtime-tokio`, on by default).

use super::{
    AsyncTcpListener, AsyncTcpStream, AsyncUdpSocket, BoxFuture, JoinHandle, MulticastConfig,
    MulticastInterfaceSelector, RecvMeta, Runtime, TrafficClassMarker, Transmit,
};
use shared::stream::{DnsRecord, RecordKind};
use socket2::SockRef;
use std::future::Future;
use std::io::{self, IoSliceMut};
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, ready};
use std::time::Instant;
use tokio::io::ReadBuf;
use tokio::runtime::Handle;

/// The tokio runtime.
///
/// [`TokioRuntime::new`] uses the tokio runtime of the thread at each call, as `tokio::spawn`
/// does: the driver must then be used inside one (a current-thread runtime on a thread that
/// entered a network namespace keeps the sockets there). [`TokioRuntime::with_handle`] uses the
/// runtime of `handle` from anywhere.
#[derive(Debug, Clone, Default)]
pub struct TokioRuntime {
    handle: Option<Handle>,
}

impl TokioRuntime {
    /// The tokio runtime the calling code runs in, at each call.
    pub fn new() -> Self {
        Self { handle: None }
    }

    /// The tokio runtime of `handle`.
    pub fn with_handle(handle: Handle) -> Self {
        Self {
            handle: Some(handle),
        }
    }

    fn enter(&self) -> Option<tokio::runtime::EnterGuard<'_>> {
        self.handle.as_ref().map(Handle::enter)
    }
}

#[derive(Debug)]
struct TokioJoinHandle(tokio::task::JoinHandle<()>);

impl JoinHandle for TokioJoinHandle {
    fn abort(&self) {
        self.0.abort();
    }

    fn is_finished(&self) -> bool {
        self.0.is_finished()
    }

    fn poll_join(&mut self, cx: &mut Context<'_>) -> Poll<()> {
        Pin::new(&mut self.0).poll(cx).map(|_| ())
    }
}

impl Runtime for TokioRuntime {
    fn spawn(&self, future: BoxFuture<'static, ()>) -> Box<dyn JoinHandle> {
        Box::new(TokioJoinHandle(match &self.handle {
            Some(handle) => handle.spawn(future),
            None => tokio::spawn(future),
        }))
    }

    fn now(&self) -> Instant {
        Instant::now()
    }

    fn sleep_until(&self, deadline: Instant) -> BoxFuture<'static, ()> {
        let _guard = self.enter();
        Box::pin(tokio::time::sleep_until(deadline.into()))
    }

    fn bind_udp(&self, local: SocketAddr) -> io::Result<Arc<dyn AsyncUdpSocket>> {
        let _guard = self.enter();
        TokioUdp::wrap(super::std_udp(local)?)
    }

    fn bind_udp_multicast(&self, config: &MulticastConfig) -> io::Result<Arc<dyn AsyncUdpSocket>> {
        let _guard = self.enter();
        TokioUdp::wrap(super::std_multicast(config)?)
    }

    fn listen_tcp(
        &self,
        local: SocketAddr,
        reuse_address: bool,
    ) -> io::Result<Arc<dyn AsyncTcpListener>> {
        let _guard = self.enter();
        let listener =
            tokio::net::TcpListener::from_std(super::std_tcp_listener(local, reuse_address)?)?;
        Ok(Arc::new(TokioListener(listener)))
    }

    fn connect_tcp(
        &self,
        local: SocketAddr,
        remote: SocketAddr,
        reuse_address: bool,
    ) -> BoxFuture<'static, io::Result<Arc<dyn AsyncTcpStream>>> {
        let _guard = self.enter();
        let socket = super::std_tcp_bound(local, reuse_address)
            .map(|socket| tokio::net::TcpSocket::from_std_stream(socket.into()));
        Box::pin(async move {
            let stream = socket?.connect(remote).await?;
            stream.set_nodelay(true)?;
            Ok(Arc::new(TokioTcp(stream)) as Arc<dyn AsyncTcpStream>)
        })
    }

    fn resolve_host(
        &self,
        host: &str,
        port: u16,
    ) -> BoxFuture<'static, io::Result<Vec<SocketAddr>>> {
        let host = host.to_owned();
        Box::pin(async move {
            Ok(tokio::net::lookup_host((host.as_str(), port))
                .await?
                .collect())
        })
    }

    #[cfg(feature = "dns-records")]
    fn resolve_family(
        &self,
        host: &str,
        port: u16,
        ipv6: bool,
    ) -> Option<BoxFuture<'static, Vec<SocketAddr>>> {
        let host = host.to_owned();
        Some(Box::pin(async move {
            crate::dns::addresses(&host, port, ipv6).await
        }))
    }

    #[cfg(feature = "dns-records")]
    fn resolve_records(&self, name: &str, kind: RecordKind) -> BoxFuture<'static, Vec<DnsRecord>> {
        let name = name.to_owned();
        Box::pin(async move { crate::dns::records(&name, kind).await })
    }

    #[cfg(not(feature = "dns-records"))]
    fn resolve_records(&self, name: &str, kind: RecordKind) -> BoxFuture<'static, Vec<DnsRecord>> {
        // No record lookup without `dns-records`: none, and the engine takes the host's
        // addresses (RFC 5928 section 3).
        let _ = (name, kind);
        Box::pin(std::future::ready(Vec::new()))
    }

    fn block_on(&self, future: Pin<Box<dyn Future<Output = ()> + '_>>) {
        match &self.handle {
            Some(handle) => handle.block_on(future),
            None => Handle::current().block_on(future),
        }
    }
}

#[derive(Debug)]
struct TokioUdp {
    socket: tokio::net::UdpSocket,
    ipv6: bool,
    marker: TrafficClassMarker,
    interface: MulticastInterfaceSelector,
}

impl TokioUdp {
    fn wrap(socket: std::net::UdpSocket) -> io::Result<Arc<dyn AsyncUdpSocket>> {
        let ipv6 = socket.local_addr()?.is_ipv6();
        Ok(Arc::new(Self {
            socket: tokio::net::UdpSocket::from_std(socket)?,
            ipv6,
            marker: TrafficClassMarker::default(),
            interface: MulticastInterfaceSelector::default(),
        }))
    }
}

impl AsyncUdpSocket for TokioUdp {
    fn poll_send(&self, cx: &mut Context<'_>, transmit: &Transmit<'_>) -> Poll<io::Result<usize>> {
        // A multicast datagram leaves by the interface of its source (RFC 6762 section 14).
        if let Err(e) = self.interface.apply(SockRef::from(&self.socket), transmit) {
            return Poll::Ready(Err(e));
        }
        self.marker.apply(
            SockRef::from(&self.socket),
            self.ipv6,
            transmit.traffic_class,
        );
        self.socket
            .poll_send_to(cx, transmit.contents, transmit.destination)
    }

    fn poll_recv(
        &self,
        cx: &mut Context<'_>,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        let Some(buf) = bufs.first_mut() else {
            return Poll::Ready(Ok(0));
        };
        let mut read = ReadBuf::new(buf);
        let addr = ready!(self.socket.poll_recv_from(cx, &mut read))?;
        let len = read.filled().len();
        meta[0] = RecvMeta {
            addr,
            len,
            stride: len,
            ecn: None,
            dst_ip: None,
        };
        Poll::Ready(Ok(1))
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    fn traffic_class(&self) -> io::Result<u32> {
        crate::sockets::traffic_class(SockRef::from(&self.socket), self.ipv6)
    }

    fn unmarked(&self) -> bool {
        self.marker.refused()
    }
}

#[derive(Debug)]
struct TokioTcp(tokio::net::TcpStream);

impl AsyncTcpStream for TokioTcp {
    fn poll_read(&self, cx: &mut Context<'_>, buf: &mut [u8]) -> Poll<io::Result<usize>> {
        loop {
            ready!(self.0.poll_read_ready(cx))?;
            match self.0.try_read(buf) {
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => continue,
                other => return Poll::Ready(other),
            }
        }
    }

    fn poll_write(&self, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        loop {
            ready!(self.0.poll_write_ready(cx))?;
            match self.0.try_write(buf) {
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => continue,
                other => return Poll::Ready(other),
            }
        }
    }

    fn shutdown_write(&self) -> io::Result<()> {
        SockRef::from(&self.0).shutdown(std::net::Shutdown::Write)
    }

    fn reset_on_close(&self) -> io::Result<()> {
        super::reset_on_close(SockRef::from(&self.0))
    }

    fn set_traffic_class(&self, value: u8) -> io::Result<u32> {
        let ipv6 = self.0.local_addr()?.is_ipv6();
        super::set_and_read_traffic_class(SockRef::from(&self.0), ipv6, value)
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.0.local_addr()
    }

    fn peer_addr(&self) -> io::Result<SocketAddr> {
        self.0.peer_addr()
    }
}

#[derive(Debug)]
struct TokioListener(tokio::net::TcpListener);

impl AsyncTcpListener for TokioListener {
    fn poll_accept(
        &self,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<(Arc<dyn AsyncTcpStream>, SocketAddr)>> {
        let (stream, remote) = ready!(self.0.poll_accept(cx))?;
        let _ = stream.set_nodelay(true);
        Poll::Ready(Ok((Arc::new(TokioTcp(stream)), remote)))
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.0.local_addr()
    }
}
