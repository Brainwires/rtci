//! [`SmolRuntime`] (feature `runtime-smol`).

use super::{
    AsyncTcpListener, AsyncTcpStream, AsyncUdpSocket, BoxFuture, JoinHandle, MulticastConfig,
    RecvMeta, Runtime, TrafficClassMarker, Transmit,
};
use smol::Async;
use socket2::SockRef;
use std::future::Future;
use std::io::{self, IoSliceMut, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, ready};
use std::time::Instant;

/// The smol runtime: tasks on smol's global executor, timers and sockets on `async-io`'s
/// reactor, name lookups on smol's thread pool. It needs no setup and can be used from any
/// thread, inside or outside `smol::block_on`.
#[derive(Debug, Clone, Copy, Default)]
pub struct SmolRuntime;

impl SmolRuntime {
    /// The smol runtime.
    pub fn new() -> Self {
        Self
    }
}

/// A smol task; dropping the handle detaches it.
#[derive(Debug)]
struct SmolJoinHandle(Mutex<Option<smol::Task<()>>>);

impl JoinHandle for SmolJoinHandle {
    fn abort(&self) {
        // Dropping a smol task cancels it.
        drop(self.0.lock().unwrap_or_else(|e| e.into_inner()).take());
    }

    fn is_finished(&self) -> bool {
        self.0
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .as_ref()
            .is_none_or(smol::Task::is_finished)
    }

    fn poll_join(&mut self, cx: &mut Context<'_>) -> Poll<()> {
        let slot = self.0.get_mut().unwrap_or_else(|e| e.into_inner());
        let Some(task) = slot.as_mut() else {
            return Poll::Ready(());
        };
        ready!(Pin::new(task).poll(cx));
        *slot = None;
        Poll::Ready(())
    }
}

impl Drop for SmolJoinHandle {
    fn drop(&mut self) {
        if let Some(task) = self.0.get_mut().unwrap_or_else(|e| e.into_inner()).take() {
            task.detach();
        }
    }
}

impl Runtime for SmolRuntime {
    fn spawn(&self, future: BoxFuture<'static, ()>) -> Box<dyn JoinHandle> {
        Box::new(SmolJoinHandle(Mutex::new(Some(smol::spawn(future)))))
    }

    fn now(&self) -> Instant {
        Instant::now()
    }

    fn sleep_until(&self, deadline: Instant) -> BoxFuture<'static, ()> {
        Box::pin(async move {
            smol::Timer::at(deadline).await;
        })
    }

    fn bind_udp(&self, local: SocketAddr) -> io::Result<Arc<dyn AsyncUdpSocket>> {
        SmolUdp::wrap(super::std_udp(local)?)
    }

    fn bind_udp_multicast(&self, config: &MulticastConfig) -> io::Result<Arc<dyn AsyncUdpSocket>> {
        SmolUdp::wrap(super::std_multicast(config)?)
    }

    fn listen_tcp(
        &self,
        local: SocketAddr,
        reuse_address: bool,
    ) -> io::Result<Arc<dyn AsyncTcpListener>> {
        let listener = Async::new(super::std_tcp_listener(local, reuse_address)?)?;
        Ok(Arc::new(SmolListener(listener)))
    }

    fn connect_tcp(
        &self,
        local: SocketAddr,
        remote: SocketAddr,
        reuse_address: bool,
    ) -> BoxFuture<'static, io::Result<Arc<dyn AsyncTcpStream>>> {
        let started = super::std_tcp_connect_start(local, remote, reuse_address);
        Box::pin(async move {
            let stream = Async::new(started?)?;
            // As async-io's own connect: writable once the handshake ended, then the outcome.
            stream.writable().await?;
            if let Some(e) = stream.get_ref().take_error()? {
                return Err(e);
            }
            stream.get_ref().peer_addr()?;
            stream.get_ref().set_nodelay(true)?;
            Ok(Arc::new(SmolTcp(stream)) as Arc<dyn AsyncTcpStream>)
        })
    }

    fn resolve_host(
        &self,
        host: &str,
        port: u16,
    ) -> BoxFuture<'static, io::Result<Vec<SocketAddr>>> {
        let host = host.to_owned();
        Box::pin(async move { smol::net::resolve((host.as_str(), port)).await })
    }

    fn block_on(&self, future: Pin<Box<dyn Future<Output = ()> + '_>>) {
        smol::block_on(future);
    }
}

#[derive(Debug)]
struct SmolUdp {
    socket: Async<UdpSocket>,
    ipv6: bool,
    marker: TrafficClassMarker,
}

impl SmolUdp {
    fn wrap(socket: UdpSocket) -> io::Result<Arc<dyn AsyncUdpSocket>> {
        let ipv6 = socket.local_addr()?.is_ipv6();
        Ok(Arc::new(Self {
            socket: Async::new(socket)?,
            ipv6,
            marker: TrafficClassMarker::default(),
        }))
    }
}

impl AsyncUdpSocket for SmolUdp {
    fn poll_send(&self, cx: &mut Context<'_>, transmit: &Transmit<'_>) -> Poll<io::Result<usize>> {
        self.marker.apply(
            SockRef::from(self.socket.get_ref()),
            self.ipv6,
            transmit.traffic_class,
        );
        loop {
            match self
                .socket
                .get_ref()
                .send_to(transmit.contents, transmit.destination)
            {
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
        let Some(buf) = bufs.first_mut() else {
            return Poll::Ready(Ok(0));
        };
        loop {
            match self.socket.get_ref().recv_from(buf) {
                Ok((len, addr)) => {
                    meta[0] = RecvMeta {
                        addr,
                        len,
                        stride: len,
                        ecn: None,
                        dst_ip: None,
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
        crate::sockets::traffic_class(SockRef::from(self.socket.get_ref()), self.ipv6)
    }

    fn unmarked(&self) -> bool {
        self.marker.refused()
    }
}

#[derive(Debug)]
struct SmolTcp(Async<TcpStream>);

impl AsyncTcpStream for SmolTcp {
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
        super::reset_on_close(SockRef::from(self.0.get_ref()))
    }

    fn set_traffic_class(&self, value: u8) -> io::Result<u32> {
        let ipv6 = self.0.get_ref().local_addr()?.is_ipv6();
        super::set_and_read_traffic_class(SockRef::from(self.0.get_ref()), ipv6, value)
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.0.get_ref().local_addr()
    }

    fn peer_addr(&self) -> io::Result<SocketAddr> {
        self.0.get_ref().peer_addr()
    }
}

#[derive(Debug)]
struct SmolListener(Async<TcpListener>);

impl AsyncTcpListener for SmolListener {
    fn poll_accept(
        &self,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<(Arc<dyn AsyncTcpStream>, SocketAddr)>> {
        loop {
            match self.0.get_ref().accept() {
                Ok((stream, remote)) => {
                    let _ = stream.set_nodelay(true);
                    let stream = Async::new(stream)?;
                    return Poll::Ready(Ok((Arc::new(SmolTcp(stream)), remote)));
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
