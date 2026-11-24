//! [`MockRuntime`] (feature `runtime-mock`): virtual time and an in-memory network, so that
//! driven connections run deterministically and a 30-second timeout takes no wall time.
//!
//! - **Clock.** [`MockRuntime::now`] starts at the moment the runtime was made and moves only
//!   when told: [`MockClock::advance`] by hand, or, inside [`MockRuntime::run`] (and
//!   `block_on`), to the next timer whenever nothing can run (as tokio's paused clock does).
//!   A timer whose time is reached is woken; what waits on nothing with no timer pending is a
//!   deadlock, and `run` panics saying so instead of hanging.
//! - **Executor.** Tasks run on the thread that calls `run`, in the order they were woken.
//! - **Network** ([`MockNet`]). UDP sockets (multicast included) and TCP listeners and
//!   connections between mock sockets, by address: no file descriptor, nothing leaves the
//!   process. Each direction between two IP addresses is a link with a delay, a loss rate and a
//!   block switch ([`LinkConfig`]); loss draws from a seeded generator, so a run is the same
//!   every time. A filter can drop chosen datagrams ([`MockNet::set_filter`]), and every
//!   datagram is logged with its traffic class and fate ([`MockNet::log`]). Names resolve from
//!   a table ([`MockNet::add_host`]). TCP is reliable: its bytes take the link's delay, never
//!   its loss, and a blocked link holds a connection attempt forever.

use super::{
    AsyncTcpListener, AsyncTcpStream, AsyncUdpSocket, BoxFuture, JoinHandle, MulticastConfig,
    RecvMeta, Runtime, Transmit,
};
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::fmt;
use std::future::Future;
use std::io::{self, IoSliceMut};
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, Weak};
use std::task::{Context, Poll, Wake, Waker};
use std::time::{Duration, Instant};

/// A runtime on virtual time with an in-memory network (see the [module documentation](self)).
#[derive(Clone)]
pub struct MockRuntime {
    shared: Arc<Shared>,
}

impl fmt::Debug for MockRuntime {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MockRuntime")
            .field("elapsed", &self.clock().elapsed())
            .finish()
    }
}

struct Shared {
    base: Instant,
    state: Mutex<State>,
    ready: Mutex<VecDeque<async_task::Runnable>>,
    running: AtomicBool,
}

struct State {
    elapsed: Duration,
    seq: u64,
    timers: BTreeMap<(Instant, u64), Timer>,
    auto_advance: bool,
    net: Net,
}

enum Timer {
    Wake(Waker),
    Datagram {
        to: Arc<UdpEndpoint>,
        from: SocketAddr,
        data: Vec<u8>,
    },
    Bytes {
        to: Arc<Pipe>,
        data: Vec<u8>,
    },
    End {
        to: Arc<Pipe>,
        reset: bool,
    },
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|e| e.into_inner())
}

impl Default for MockRuntime {
    fn default() -> Self {
        Self::new()
    }
}

impl MockRuntime {
    /// A runtime whose clock reads the present moment, then moves only when told; loss drawn
    /// from seed 1.
    pub fn new() -> Self {
        Self::with_seed(1)
    }

    /// As [`new`](Self::new), loss drawn from `seed`.
    pub fn with_seed(seed: u64) -> Self {
        Self {
            shared: Arc::new(Shared {
                base: Instant::now(),
                state: Mutex::new(State {
                    elapsed: Duration::ZERO,
                    seq: 0,
                    timers: BTreeMap::new(),
                    auto_advance: true,
                    net: Net::new(seed),
                }),
                ready: Mutex::new(VecDeque::new()),
                running: AtomicBool::new(false),
            }),
        }
    }

    /// The virtual clock.
    pub fn clock(&self) -> MockClock {
        MockClock {
            shared: self.shared.clone(),
        }
    }

    /// The in-memory network.
    pub fn net(&self) -> MockNet {
        MockNet {
            shared: self.shared.clone(),
        }
    }

    /// Whether [`run`](Self::run) moves the clock to the next timer when nothing can run
    /// (on by default). Off, the clock moves only by [`MockClock::advance`], and `run` panics
    /// when it would have to wait.
    pub fn set_auto_advance(&self, on: bool) {
        lock(&self.shared.state).auto_advance = on;
    }

    /// Runs the tasks that can run now, without moving the clock.
    pub fn run_until_idle(&self) {
        loop {
            // The queue's lock is not held while a task runs: it may wake others.
            let next = lock(&self.shared.ready).pop_front();
            let Some(runnable) = next else {
                return;
            };
            runnable.run();
        }
    }

    /// Runs `future` to completion on this thread, with the runtime's tasks, moving the clock
    /// to the next timer whenever nothing can run.
    ///
    /// # Panics
    ///
    /// When nothing can run and no timer is pending (the future would wait forever), when
    /// the clock may not advance by itself and something must wait, and when called from
    /// inside another `run` of the same runtime.
    pub fn run<F: Future>(&self, future: F) -> F::Output {
        assert!(
            !self.shared.running.swap(true, Ordering::SeqCst),
            "MockRuntime::run inside MockRuntime::run"
        );
        struct Running<'a>(&'a AtomicBool);
        impl Drop for Running<'_> {
            fn drop(&mut self) {
                self.0.store(false, Ordering::SeqCst);
            }
        }
        let _running = Running(&self.shared.running);
        let woken = Arc::new(Flag(AtomicBool::new(true)));
        let waker = Waker::from(woken.clone());
        let mut cx = Context::from_waker(&waker);
        let mut future = std::pin::pin!(future);
        loop {
            if woken.0.swap(false, Ordering::SeqCst)
                && let Poll::Ready(output) = future.as_mut().poll(&mut cx)
            {
                return output;
            }
            self.run_until_idle();
            if woken.0.load(Ordering::SeqCst) || !lock(&self.shared.ready).is_empty() {
                continue;
            }
            let (next, auto) = {
                let state = lock(&self.shared.state);
                (
                    state.timers.keys().next().map(|(at, _)| *at),
                    state.auto_advance,
                )
            };
            match next {
                Some(at) if auto => self.clock().advance_to(at),
                Some(at) => panic!(
                    "MockRuntime: nothing can run and the next timer ({:?} ahead) waits for MockClock::advance",
                    at.saturating_duration_since(self.now())
                ),
                None => panic!(
                    "MockRuntime: stalled at {:?}: nothing can run and no timer is pending",
                    self.clock().elapsed()
                ),
            }
        }
    }

    fn schedule_timer(&self, at: Instant, timer: Timer) -> (Instant, u64) {
        let mut state = lock(&self.shared.state);
        state.seq += 1;
        let key = (at, state.seq);
        state.timers.insert(key, timer);
        key
    }
}

struct Flag(AtomicBool);

impl Wake for Flag {
    fn wake(self: Arc<Self>) {
        self.0.store(true, Ordering::SeqCst);
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.0.store(true, Ordering::SeqCst);
    }
}

/// The virtual clock of a [`MockRuntime`].
#[derive(Clone)]
pub struct MockClock {
    shared: Arc<Shared>,
}

impl fmt::Debug for MockClock {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MockClock")
            .field("elapsed", &self.elapsed())
            .finish()
    }
}

impl MockClock {
    /// The time on the clock.
    pub fn now(&self) -> Instant {
        self.shared.base + lock(&self.shared.state).elapsed
    }

    /// How far the clock moved since the runtime was made.
    pub fn elapsed(&self) -> Duration {
        lock(&self.shared.state).elapsed
    }

    /// Moves the clock forward by `by`, waking every timer reached on the way, in order, and
    /// delivering what the network held until then.
    pub fn advance(&self, by: Duration) {
        let to = self.now() + by;
        self.advance_to(to);
    }

    /// Moves the clock to `to` (never back), as [`advance`](Self::advance).
    pub fn advance_to(&self, to: Instant) {
        loop {
            let due = {
                let mut state = lock(&self.shared.state);
                let Some(&key) = state.timers.keys().next().filter(|(at, _)| *at <= to) else {
                    let target = to.saturating_duration_since(self.shared.base);
                    state.elapsed = state.elapsed.max(target);
                    return;
                };
                let timer = state.timers.remove(&key).expect("the first timer");
                let at = key.0.saturating_duration_since(self.shared.base);
                state.elapsed = state.elapsed.max(at);
                timer
            };
            // Outside the lock: a wake may schedule a task, a delivery takes its socket's.
            fire(due);
        }
    }
}

fn fire(timer: Timer) {
    match timer {
        Timer::Wake(waker) => waker.wake(),
        Timer::Datagram { to, from, data } => to.deliver(from, data),
        Timer::Bytes { to, data } => to.push(&data),
        Timer::End { to, reset } => to.end(reset),
    }
}

/// A task of a [`MockRuntime`]; dropping the handle detaches it.
#[derive(Debug)]
struct MockTask(Mutex<Option<async_task::Task<()>>>);

impl JoinHandle for MockTask {
    fn abort(&self) {
        drop(lock(&self.0).take());
    }

    fn is_finished(&self) -> bool {
        lock(&self.0)
            .as_ref()
            .is_none_or(async_task::Task::is_finished)
    }

    fn poll_join(&mut self, cx: &mut Context<'_>) -> Poll<()> {
        let slot = self.0.get_mut().unwrap_or_else(|e| e.into_inner());
        let Some(task) = slot.as_mut() else {
            return Poll::Ready(());
        };
        if Pin::new(task).poll(cx).is_pending() {
            return Poll::Pending;
        }
        *slot = None;
        Poll::Ready(())
    }
}

impl Drop for MockTask {
    fn drop(&mut self) {
        if let Some(task) = self.0.get_mut().unwrap_or_else(|e| e.into_inner()).take() {
            task.detach();
        }
    }
}

/// A [`MockRuntime`] timer.
struct Sleep {
    runtime: MockRuntime,
    deadline: Instant,
    key: Option<(Instant, u64)>,
}

impl Future for Sleep {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        if self.runtime.now() >= self.deadline {
            if let Some(key) = self.key.take() {
                lock(&self.runtime.shared.state).timers.remove(&key);
            }
            return Poll::Ready(());
        }
        if let Some(key) = self.key {
            let mut state = lock(&self.runtime.shared.state);
            match state.timers.get_mut(&key) {
                Some(Timer::Wake(waker)) => {
                    waker.clone_from(cx.waker());
                    return Poll::Pending;
                }
                // Fired (woken) before its deadline was seen: armed again.
                _ => drop(state),
            }
        }
        let key = self
            .runtime
            .schedule_timer(self.deadline, Timer::Wake(cx.waker().clone()));
        self.key = Some(key);
        Poll::Pending
    }
}

impl Drop for Sleep {
    fn drop(&mut self) {
        if let Some(key) = self.key.take() {
            lock(&self.runtime.shared.state).timers.remove(&key);
        }
    }
}

impl Runtime for MockRuntime {
    fn spawn(&self, future: BoxFuture<'static, ()>) -> Box<dyn JoinHandle> {
        let shared = Arc::downgrade(&self.shared);
        let schedule = move |runnable| {
            if let Some(shared) = shared.upgrade() {
                lock(&shared.ready).push_back(runnable);
            }
        };
        let (runnable, task) = async_task::spawn(future, schedule);
        runnable.schedule();
        Box::new(MockTask(Mutex::new(Some(task))))
    }

    fn now(&self) -> Instant {
        self.clock().now()
    }

    fn sleep_until(&self, deadline: Instant) -> BoxFuture<'static, ()> {
        Box::pin(Sleep {
            runtime: self.clone(),
            deadline,
            key: None,
        })
    }

    fn bind_udp(&self, local: SocketAddr) -> io::Result<Arc<dyn AsyncUdpSocket>> {
        let mut state = lock(&self.shared.state);
        let local = state.net.bind_udp(local)?;
        let endpoint = Arc::new(UdpEndpoint::new(local));
        state.net.udp.insert(local, Arc::downgrade(&endpoint));
        Ok(Arc::new(MockUdp {
            runtime: self.clone(),
            endpoint,
        }))
    }

    fn bind_udp_multicast(&self, config: &MulticastConfig) -> io::Result<Arc<dyn AsyncUdpSocket>> {
        let group = SocketAddr::new(config.group, config.port);
        let mut state = lock(&self.shared.state);
        let local = SocketAddr::new(unspecified(config.group), config.port);
        let endpoint = Arc::new(UdpEndpoint::new(local));
        state.net.multicast.push((group, Arc::downgrade(&endpoint)));
        Ok(Arc::new(MockUdp {
            runtime: self.clone(),
            endpoint,
        }))
    }

    fn listen_tcp(
        &self,
        local: SocketAddr,
        _reuse_address: bool,
    ) -> io::Result<Arc<dyn AsyncTcpListener>> {
        let mut state = lock(&self.shared.state);
        let local = state.net.bind_tcp(local)?;
        let listener = Arc::new(ListenerEndpoint {
            local,
            queue: Mutex::new((VecDeque::new(), None)),
        });
        state.net.listeners.insert(local, Arc::downgrade(&listener));
        Ok(Arc::new(MockListener {
            runtime: self.clone(),
            endpoint: listener,
        }))
    }

    fn connect_tcp(
        &self,
        local: SocketAddr,
        remote: SocketAddr,
        _reuse_address: bool,
    ) -> BoxFuture<'static, io::Result<Arc<dyn AsyncTcpStream>>> {
        let runtime = self.clone();
        Box::pin(async move {
            let (local, link, listener) = {
                let mut state = lock(&runtime.shared.state);
                let local = state.net.bind_tcp(local)?;
                let link = state.net.link(local.ip(), remote.ip());
                let listener = state.net.listener(remote);
                (local, link, listener)
            };
            if link.blocked {
                // Nothing answers: the driver's connect timeout ends it.
                std::future::pending::<()>().await;
            }
            // The handshake: one round trip.
            super::sleep(&runtime, link.delay * 2).await;
            let Some(listener) = listener else {
                return Err(io::Error::from(io::ErrorKind::ConnectionRefused));
            };
            let to_client = Arc::new(Pipe::default());
            let to_server = Arc::new(Pipe::default());
            let client = Arc::new(MockTcp {
                runtime: runtime.clone(),
                local,
                peer: remote,
                incoming: to_client.clone(),
                outgoing: to_server.clone(),
                state: Mutex::new(TcpEnd::default()),
            });
            let server: Arc<dyn AsyncTcpStream> = Arc::new(MockTcp {
                runtime: runtime.clone(),
                local: listener.local_for(remote),
                peer: local,
                incoming: to_server,
                outgoing: to_client,
                state: Mutex::new(TcpEnd::default()),
            });
            listener.push(server, local);
            Ok(client as Arc<dyn AsyncTcpStream>)
        })
    }

    fn resolve_host(
        &self,
        host: &str,
        port: u16,
    ) -> BoxFuture<'static, io::Result<Vec<SocketAddr>>> {
        let found = match host.parse::<IpAddr>() {
            Ok(ip) => Ok(vec![SocketAddr::new(ip, port)]),
            Err(_) => lock(&self.shared.state)
                .net
                .hosts
                .get(host)
                .map(|ips| ips.iter().map(|ip| SocketAddr::new(*ip, port)).collect())
                .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, host.to_owned())),
        };
        Box::pin(std::future::ready(found))
    }

    fn block_on(&self, future: Pin<Box<dyn Future<Output = ()> + '_>>) {
        self.run(future);
    }
}

fn unspecified(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V4(_) => IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
        IpAddr::V6(_) => IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED),
    }
}

/// One direction between two IP addresses of the [`MockNet`].
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct LinkConfig {
    /// One-way delay (TCP's handshake takes two).
    pub delay: Duration,
    /// The share of datagrams lost, 0.0 to 1.0, drawn from the runtime's seed.
    pub loss: f64,
    /// Nothing passes: datagrams are lost, connection attempts never complete.
    pub blocked: bool,
}

impl Default for LinkConfig {
    fn default() -> Self {
        Self {
            delay: Duration::ZERO,
            loss: 0.0,
            blocked: false,
        }
    }
}

/// A datagram as the [`MockNet`] sees it, for a filter.
#[derive(Debug, Clone, Copy)]
pub struct MockDatagram<'a> {
    /// When it was sent.
    pub at: Instant,
    /// The sender's address.
    pub from: SocketAddr,
    /// Where to (a multicast group for a multicast datagram).
    pub to: SocketAddr,
    /// The bytes.
    pub data: &'a [u8],
}

/// What became of a datagram.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fate {
    /// Delivered (or on its way) to this many sockets.
    Delivered(usize),
    /// Nobody was bound there.
    Unbound,
    /// The link was blocked.
    Blocked,
    /// Lost to the link's loss rate.
    Lost,
    /// Dropped by the filter.
    Filtered,
}

/// One datagram of the [`MockNet::log`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DatagramRecord {
    /// When it was sent.
    pub at: Instant,
    /// The sender.
    pub from: SocketAddr,
    /// Where to.
    pub to: SocketAddr,
    /// Its size.
    pub len: usize,
    /// The TOS / Traffic Class byte it was sent with.
    pub traffic_class: u8,
    /// What became of it.
    pub fate: Fate,
}

/// A filter of the [`MockNet`]: `false` drops the datagram.
pub type DatagramFilter = Box<dyn FnMut(&MockDatagram<'_>) -> bool + Send>;

/// The in-memory network of a [`MockRuntime`].
#[derive(Clone)]
pub struct MockNet {
    shared: Arc<Shared>,
}

impl fmt::Debug for MockNet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MockNet").finish_non_exhaustive()
    }
}

impl MockNet {
    /// Every link not set otherwise.
    pub fn set_default_link(&self, link: LinkConfig) {
        lock(&self.shared.state).net.default_link = link;
    }

    /// The link from `from` to `to` (one direction).
    pub fn set_link(&self, from: IpAddr, to: IpAddr, link: LinkConfig) {
        lock(&self.shared.state).net.links.insert((from, to), link);
    }

    /// Both directions between `a` and `b`.
    pub fn set_links(&self, a: IpAddr, b: IpAddr, link: LinkConfig) {
        self.set_link(a, b, link);
        self.set_link(b, a, link);
    }

    /// Drops every datagram `filter` returns `false` for (after the link's own fate).
    pub fn set_filter(&self, filter: DatagramFilter) {
        lock(&self.shared.state).net.filter = Some(filter);
    }

    /// No filter.
    pub fn clear_filter(&self) {
        lock(&self.shared.state).net.filter = None;
    }

    /// `name` resolves to `ips`.
    pub fn add_host(&self, name: &str, ips: Vec<IpAddr>) {
        lock(&self.shared.state)
            .net
            .hosts
            .insert(name.to_owned(), ips);
    }

    /// Every datagram sent so far, in order.
    pub fn log(&self) -> Vec<DatagramRecord> {
        lock(&self.shared.state).net.log.clone()
    }
}

struct Net {
    udp: HashMap<SocketAddr, Weak<UdpEndpoint>>,
    multicast: Vec<(SocketAddr, Weak<UdpEndpoint>)>,
    listeners: HashMap<SocketAddr, Weak<ListenerEndpoint>>,
    tcp_ports: HashMap<SocketAddr, usize>,
    next_port: u16,
    default_link: LinkConfig,
    links: HashMap<(IpAddr, IpAddr), LinkConfig>,
    filter: Option<DatagramFilter>,
    hosts: HashMap<String, Vec<IpAddr>>,
    log: Vec<DatagramRecord>,
    rng: u64,
}

impl Net {
    fn new(seed: u64) -> Self {
        Self {
            udp: HashMap::new(),
            multicast: Vec::new(),
            listeners: HashMap::new(),
            tcp_ports: HashMap::new(),
            next_port: 49152,
            default_link: LinkConfig::default(),
            links: HashMap::new(),
            filter: None,
            hosts: HashMap::new(),
            log: Vec::new(),
            // xorshift64 needs a state other than 0.
            rng: seed.max(1),
        }
    }

    fn link(&self, from: IpAddr, to: IpAddr) -> LinkConfig {
        self.links
            .get(&(from, to))
            .copied()
            .unwrap_or(self.default_link)
    }

    /// A uniform draw in [0, 1) (xorshift64).
    fn draw(&mut self) -> f64 {
        let mut x = self.rng;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.rng = x;
        (x >> 11) as f64 / (1u64 << 53) as f64
    }

    fn bind_udp(&mut self, local: SocketAddr) -> io::Result<SocketAddr> {
        self.udp.retain(|_, e| e.strong_count() > 0);
        let ip = local.ip();
        let port = match local.port() {
            0 => {
                let udp = &self.udp;
                free_port(&mut self.next_port, |p| {
                    udp.contains_key(&SocketAddr::new(ip, p))
                })?
            }
            port => port,
        };
        let local = SocketAddr::new(ip, port);
        if self.udp.contains_key(&local) {
            return Err(io::Error::from(io::ErrorKind::AddrInUse));
        }
        Ok(local)
    }

    fn bind_tcp(&mut self, local: SocketAddr) -> io::Result<SocketAddr> {
        self.listeners.retain(|_, l| l.strong_count() > 0);
        let ip = local.ip();
        let port = match local.port() {
            0 => {
                let listeners = &self.listeners;
                let ports = &self.tcp_ports;
                free_port(&mut self.next_port, |p| {
                    let addr = SocketAddr::new(ip, p);
                    listeners.contains_key(&addr) || ports.contains_key(&addr)
                })?
            }
            port => port,
        };
        let local = SocketAddr::new(ip, port);
        if self.listeners.contains_key(&local) {
            return Err(io::Error::from(io::ErrorKind::AddrInUse));
        }
        *self.tcp_ports.entry(local).or_default() += 1;
        Ok(local)
    }

    fn listener(&self, remote: SocketAddr) -> Option<Arc<ListenerEndpoint>> {
        self.listeners
            .get(&remote)
            .or_else(|| {
                self.listeners
                    .get(&SocketAddr::new(unspecified(remote.ip()), remote.port()))
            })
            .and_then(Weak::upgrade)
    }

    /// The sockets a datagram to `to` reaches.
    fn receivers(&self, to: SocketAddr) -> Vec<Arc<UdpEndpoint>> {
        if to.ip().is_multicast() {
            return self
                .multicast
                .iter()
                .filter(|(group, _)| *group == to)
                .filter_map(|(_, e)| e.upgrade())
                .collect();
        }
        self.udp
            .get(&to)
            .or_else(|| {
                self.udp
                    .get(&SocketAddr::new(unspecified(to.ip()), to.port()))
            })
            .and_then(Weak::upgrade)
            .into_iter()
            .collect()
    }
}

/// The next ephemeral port (49152 and up) that `taken` does not hold.
fn free_port(next: &mut u16, taken: impl Fn(u16) -> bool) -> io::Result<u16> {
    for _ in 0..16384 {
        let port = *next;
        *next = if *next == u16::MAX { 49152 } else { *next + 1 };
        if !taken(port) {
            return Ok(port);
        }
    }
    Err(io::Error::from(io::ErrorKind::AddrInUse))
}

/// A datagram waiting in a mock socket: its sender and bytes.
type Received = (SocketAddr, Vec<u8>);

struct UdpEndpoint {
    local: SocketAddr,
    inbox: Mutex<(VecDeque<Received>, Option<Waker>)>,
    traffic_class: AtomicU8,
}

impl UdpEndpoint {
    fn new(local: SocketAddr) -> Self {
        Self {
            local,
            inbox: Mutex::new((VecDeque::new(), None)),
            traffic_class: AtomicU8::new(0),
        }
    }

    fn deliver(&self, from: SocketAddr, data: Vec<u8>) {
        let waker = {
            let mut inbox = lock(&self.inbox);
            inbox.0.push_back((from, data));
            inbox.1.take()
        };
        if let Some(waker) = waker {
            waker.wake();
        }
    }
}

/// A UDP socket of a [`MockRuntime`].
struct MockUdp {
    runtime: MockRuntime,
    endpoint: Arc<UdpEndpoint>,
}

impl fmt::Debug for MockUdp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MockUdp")
            .field("local", &self.endpoint.local)
            .finish()
    }
}

impl AsyncUdpSocket for MockUdp {
    fn poll_send(&self, _: &mut Context<'_>, transmit: &Transmit<'_>) -> Poll<io::Result<usize>> {
        self.endpoint
            .traffic_class
            .store(transmit.traffic_class, Ordering::Relaxed);
        let now = self.runtime.now();
        // A socket bound to the unspecified address (the mDNS sockets) sends from the address
        // the transmit names, as a real one does from its interface's address.
        let from = match transmit.source {
            Some(ip) if self.endpoint.local.ip().is_unspecified() => {
                SocketAddr::new(ip, self.endpoint.local.port())
            }
            _ => self.endpoint.local,
        };
        let to = transmit.destination;
        let mut deliveries = Vec::new();
        let delay;
        {
            let mut state = lock(&self.runtime.shared.state);
            let net = &mut state.net;
            let link = net.link(from.ip(), to.ip());
            delay = link.delay;
            let receivers = net.receivers(to);
            let fate = if link.blocked {
                Fate::Blocked
            } else if link.loss > 0.0 && net.draw() < link.loss {
                Fate::Lost
            } else if !net.filter.as_mut().is_none_or(|keep| {
                keep(&MockDatagram {
                    at: now,
                    from,
                    to,
                    data: transmit.contents,
                })
            }) {
                Fate::Filtered
            } else if receivers.is_empty() {
                Fate::Unbound
            } else {
                Fate::Delivered(receivers.len())
            };
            net.log.push(DatagramRecord {
                at: now,
                from,
                to,
                len: transmit.contents.len(),
                traffic_class: transmit.traffic_class,
                fate,
            });
            if let Fate::Delivered(_) = fate {
                deliveries = receivers;
            }
        }
        for receiver in deliveries {
            let data = transmit.contents.to_vec();
            if delay.is_zero() {
                receiver.deliver(from, data);
            } else {
                self.runtime.schedule_timer(
                    now + delay,
                    Timer::Datagram {
                        to: receiver,
                        from,
                        data,
                    },
                );
            }
        }
        Poll::Ready(Ok(transmit.contents.len()))
    }

    fn poll_recv(
        &self,
        cx: &mut Context<'_>,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        let mut inbox = lock(&self.endpoint.inbox);
        let mut filled = 0;
        while filled < bufs.len().min(meta.len()) {
            let Some((from, data)) = inbox.0.pop_front() else {
                break;
            };
            let len = data.len().min(bufs[filled].len());
            bufs[filled][..len].copy_from_slice(&data[..len]);
            meta[filled] = RecvMeta {
                addr: from,
                len,
                stride: len,
                ecn: None,
                dst_ip: Some(self.endpoint.local.ip()),
            };
            filled += 1;
        }
        if filled == 0 {
            inbox.1 = Some(cx.waker().clone());
            return Poll::Pending;
        }
        Poll::Ready(Ok(filled))
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.endpoint.local)
    }

    fn max_receive_batch(&self) -> usize {
        64
    }

    fn traffic_class(&self) -> io::Result<u32> {
        Ok(u32::from(
            self.endpoint.traffic_class.load(Ordering::Relaxed),
        ))
    }
}

/// One direction of a mock TCP connection.
#[derive(Default)]
struct Pipe(Mutex<PipeState>);

#[derive(Default)]
struct PipeState {
    bytes: VecDeque<u8>,
    eof: bool,
    reset: bool,
    reader: Option<Waker>,
}

impl Pipe {
    fn push(&self, data: &[u8]) {
        let waker = {
            let mut pipe = lock(&self.0);
            pipe.bytes.extend(data);
            pipe.reader.take()
        };
        if let Some(waker) = waker {
            waker.wake();
        }
    }

    fn end(&self, reset: bool) {
        let waker = {
            let mut pipe = lock(&self.0);
            if reset {
                pipe.reset = true;
                pipe.bytes.clear();
            } else {
                pipe.eof = true;
            }
            pipe.reader.take()
        };
        if let Some(waker) = waker {
            waker.wake();
        }
    }
}

#[derive(Default)]
struct TcpEnd {
    shut: bool,
    reset_on_close: bool,
    traffic_class: u8,
}

/// A TCP connection end of a [`MockRuntime`].
struct MockTcp {
    runtime: MockRuntime,
    local: SocketAddr,
    peer: SocketAddr,
    incoming: Arc<Pipe>,
    outgoing: Arc<Pipe>,
    state: Mutex<TcpEnd>,
}

impl fmt::Debug for MockTcp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MockTcp")
            .field("local", &self.local)
            .field("peer", &self.peer)
            .finish()
    }
}

impl MockTcp {
    /// Sends `timer` toward the peer after the link's delay.
    fn toward_peer(&self, timer: Timer) {
        let delay = lock(&self.runtime.shared.state)
            .net
            .link(self.local.ip(), self.peer.ip())
            .delay;
        if delay.is_zero() {
            fire(timer);
        } else {
            let at = self.runtime.now() + delay;
            self.runtime.schedule_timer(at, timer);
        }
    }
}

impl AsyncTcpStream for MockTcp {
    fn poll_read(&self, cx: &mut Context<'_>, buf: &mut [u8]) -> Poll<io::Result<usize>> {
        let mut pipe = lock(&self.incoming.0);
        if pipe.reset {
            return Poll::Ready(Err(io::Error::from(io::ErrorKind::ConnectionReset)));
        }
        if pipe.bytes.is_empty() {
            if pipe.eof {
                return Poll::Ready(Ok(0));
            }
            pipe.reader = Some(cx.waker().clone());
            return Poll::Pending;
        }
        let n = buf.len().min(pipe.bytes.len());
        for (slot, byte) in buf.iter_mut().zip(pipe.bytes.drain(..n)) {
            *slot = byte;
        }
        Poll::Ready(Ok(n))
    }

    fn poll_write(&self, _: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        if lock(&self.state).shut {
            return Poll::Ready(Err(io::Error::from(io::ErrorKind::BrokenPipe)));
        }
        if lock(&self.outgoing.0).reset {
            return Poll::Ready(Err(io::Error::from(io::ErrorKind::ConnectionReset)));
        }
        self.toward_peer(Timer::Bytes {
            to: self.outgoing.clone(),
            data: buf.to_vec(),
        });
        Poll::Ready(Ok(buf.len()))
    }

    fn shutdown_write(&self) -> io::Result<()> {
        let first = !std::mem::replace(&mut lock(&self.state).shut, true);
        if first {
            self.toward_peer(Timer::End {
                to: self.outgoing.clone(),
                reset: false,
            });
        }
        Ok(())
    }

    fn reset_on_close(&self) -> io::Result<()> {
        lock(&self.state).reset_on_close = true;
        Ok(())
    }

    fn set_traffic_class(&self, value: u8) -> io::Result<u32> {
        lock(&self.state).traffic_class = value;
        Ok(u32::from(value))
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.local)
    }

    fn peer_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.peer)
    }
}

impl Drop for MockTcp {
    fn drop(&mut self) {
        let (shut, reset) = {
            let state = lock(&self.state);
            (state.shut, state.reset_on_close)
        };
        if reset {
            self.toward_peer(Timer::End {
                to: self.outgoing.clone(),
                reset: true,
            });
        } else if !shut {
            self.toward_peer(Timer::End {
                to: self.outgoing.clone(),
                reset: false,
            });
        }
        if let Some(count) = lock(&self.runtime.shared.state)
            .net
            .tcp_ports
            .get_mut(&self.local)
        {
            *count = count.saturating_sub(1);
        }
    }
}

type Pending = (Arc<dyn AsyncTcpStream>, SocketAddr);

struct ListenerEndpoint {
    local: SocketAddr,
    queue: Mutex<(VecDeque<Pending>, Option<Waker>)>,
}

impl ListenerEndpoint {
    fn push(&self, stream: Arc<dyn AsyncTcpStream>, remote: SocketAddr) {
        let waker = {
            let mut queue = lock(&self.queue);
            queue.0.push_back((stream, remote));
            queue.1.take()
        };
        if let Some(waker) = waker {
            waker.wake();
        }
    }

    /// The local address a connection from `remote` has on this listener.
    fn local_for(&self, remote: SocketAddr) -> SocketAddr {
        if self.local.ip().is_unspecified() {
            SocketAddr::new(remote.ip(), self.local.port())
        } else {
            self.local
        }
    }
}

/// A TCP listener of a [`MockRuntime`].
struct MockListener {
    runtime: MockRuntime,
    endpoint: Arc<ListenerEndpoint>,
}

impl fmt::Debug for MockListener {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MockListener")
            .field("local", &self.endpoint.local)
            .finish()
    }
}

impl AsyncTcpListener for MockListener {
    fn poll_accept(&self, cx: &mut Context<'_>) -> Poll<io::Result<Pending>> {
        let mut queue = lock(&self.endpoint.queue);
        match queue.0.pop_front() {
            Some(accepted) => Poll::Ready(Ok(accepted)),
            None => {
                queue.1 = Some(cx.waker().clone());
                Poll::Pending
            }
        }
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.endpoint.local)
    }
}

impl Drop for MockListener {
    fn drop(&mut self) {
        let mut state = lock(&self.runtime.shared.state);
        if let Some(count) = state.net.tcp_ports.get_mut(&self.endpoint.local) {
            *count = count.saturating_sub(1);
        }
    }
}
