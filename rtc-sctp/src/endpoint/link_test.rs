//! Two associations over an in-memory link: virtual time, a fixed one-way latency, and a seeded
//! decision per datagram whether it is lost. No sockets and no wall clock, so a test of loss
//! recovery is deterministic and takes virtual seconds, not real ones.

use super::*;
use crate::association::Event;
use crate::association::stream::{StreamEvent, StreamId};
use std::collections::VecDeque;
use std::time::Duration;

/// xorshift64*: a reproducible loss pattern without a dependency.
pub(crate) struct Rng(u64);

impl Rng {
    pub(crate) fn new(seed: u64) -> Self {
        Rng(seed.max(1))
    }

    pub(crate) fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    /// True with probability `percent` / 100.
    pub(crate) fn chance(&mut self, percent: u64) -> bool {
        percent > 0 && self.next_u64() % 100 < percent
    }
}

/// One side of the link: an endpoint and the (single) association it carries.
pub(crate) struct Peer {
    endpoint: Endpoint,
    pub(crate) addr: SocketAddr,
    pub(crate) association: Option<(AssociationHandle, Association)>,
    inbound: VecDeque<(Instant, Bytes)>,
    /// Application events other than stream readability, in order.
    pub(crate) events: Vec<Event>,
    /// Every message, read as soon as its stream became readable.
    pub(crate) received: Vec<(StreamId, Bytes)>,
    /// When false, readable streams are left alone (an application that stopped reading).
    pub(crate) auto_read: bool,
}

impl Peer {
    fn new(addr: SocketAddr, server: Option<TransportConfig>) -> Self {
        Peer {
            endpoint: Endpoint::new(
                addr,
                TransportProtocol::UDP,
                Arc::new(EndpointConfig::default()),
                server.map(|transport| Arc::new(ServerConfig::new(transport))),
            ),
            addr,
            association: None,
            inbound: VecDeque::new(),
            events: vec![],
            received: vec![],
            auto_read: true,
        }
    }

    /// The association; panics if the handshake has not created it.
    pub(crate) fn conn(&mut self) -> &mut Association {
        &mut self.association.as_mut().expect("no association").1
    }

    /// Whether `Event::Connected` has been seen.
    pub(crate) fn connected(&self) -> bool {
        self.events.iter().any(|e| matches!(e, Event::Connected))
    }

    fn deliver(&mut self, now: Instant, remote: SocketAddr) {
        while self.inbound.front().is_some_and(|(at, _)| *at <= now) {
            let Some((at, data)) = self.inbound.pop_front() else {
                break;
            };
            match self.endpoint.handle(at, remote, None, data) {
                Some((ch, DatagramEvent::NewAssociation(conn))) => {
                    if self.association.is_none() {
                        self.association = Some((ch, conn));
                    }
                }
                Some((ch, DatagramEvent::AssociationEvent(event))) => {
                    if let Some((own, conn)) = self.association.as_mut()
                        && *own == ch
                    {
                        conn.handle_event(event);
                    }
                }
                None => {}
            }
        }
    }

    /// Runs due timers, collects events and messages, and returns the datagrams to send.
    fn service(&mut self, now: Instant) -> Vec<Bytes> {
        let mut out = vec![];
        let Some((_, conn)) = self.association.as_mut() else {
            return out;
        };
        if conn.poll_timeout().is_some_and(|at| at <= now) {
            conn.handle_timeout(now);
        }
        while let Some(event) = conn.poll() {
            match event {
                Event::Stream(StreamEvent::Readable { id }) if self.auto_read => {
                    if let Ok(mut stream) = conn.stream(id) {
                        while let Ok(Some(chunks)) = stream.read_sctp() {
                            let mut buf = vec![0u8; chunks.len()];
                            let n = chunks.read(&mut buf).unwrap_or(0);
                            buf.truncate(n);
                            self.received.push((id, Bytes::from(buf)));
                        }
                    }
                }
                other => self.events.push(other),
            }
        }
        // A drain notice only matters to a real endpoint's bookkeeping; this link keeps routing.
        while conn.poll_endpoint_event().is_some() {}
        while let Some(transmit) = conn.poll_transmit(now) {
            if let Payload::RawEncode(contents) = transmit.message {
                out.extend(contents);
            }
        }
        out
    }

    fn next_wakeup(&self) -> Option<Instant> {
        let timer = self
            .association
            .as_ref()
            .and_then(|(_, conn)| conn.poll_timeout());
        let inbound = self.inbound.front().map(|(at, _)| *at);
        match (timer, inbound) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        }
    }
}

/// Decides, per datagram, whether it is lost. `true` from the client.
pub(crate) type DropFilter = Box<dyn FnMut(bool, &Bytes) -> bool>;

/// The link between a client and a server association.
pub(crate) struct Link {
    pub(crate) client: Peer,
    pub(crate) server: Peer,
    client_transport: TransportConfig,
    pub(crate) now: Instant,
    pub(crate) latency: Duration,
    /// Percent of datagrams lost, in each direction.
    pub(crate) loss_percent: u64,
    /// Drops chosen datagrams, before the random loss is applied.
    pub(crate) filter: Option<DropFilter>,
    rng: Rng,
    pub(crate) dropped: usize,
}

impl Link {
    pub(crate) fn new(client: TransportConfig, server: TransportConfig, seed: u64) -> Self {
        Link {
            client: Peer::new(SocketAddr::from(([10, 0, 0, 1], 5000)), None),
            server: Peer::new(SocketAddr::from(([10, 0, 0, 2], 5000)), Some(server)),
            client_transport: client,
            now: Instant::now(),
            latency: Duration::from_millis(10),
            loss_percent: 0,
            filter: None,
            rng: Rng::new(seed),
            dropped: 0,
        }
    }

    /// Starts the client's handshake and runs until both sides are connected.
    pub(crate) fn connect(&mut self) {
        let (ch, conn) = self
            .client
            .endpoint
            .connect(
                self.now,
                ClientConfig::new(self.client_transport.clone()),
                self.server.addr,
            )
            .expect("connect");
        self.client.association = Some((ch, conn));
        let deadline = self.now + Duration::from_secs(60);
        assert!(
            self.run_until(deadline, |l| l.client.connected() && l.server.connected()),
            "the handshake did not complete"
        );
    }

    /// Moves datagrams and virtual time forward until `done` holds, or until nothing is left
    /// to happen before `deadline`. Returns `done`'s last answer.
    pub(crate) fn run_until(
        &mut self,
        deadline: Instant,
        mut done: impl FnMut(&mut Link) -> bool,
    ) -> bool {
        for _ in 0..10_000_000u32 {
            self.pump();
            if done(self) {
                return true;
            }
            let next = match (self.client.next_wakeup(), self.server.next_wakeup()) {
                (Some(a), Some(b)) => Some(a.min(b)),
                (a, b) => a.or(b),
            };
            match next {
                Some(at) if at <= deadline => self.now = self.now.max(at),
                _ => return done(self),
            }
        }
        panic!("the link never settled");
    }

    /// Runs until `deadline` whatever happens.
    pub(crate) fn run_for(&mut self, duration: Duration) {
        let deadline = self.now + duration;
        self.run_until(deadline, |_| false);
        self.now = self.now.max(deadline);
    }

    /// Processes everything due at `now`, until neither side has anything more to send.
    fn pump(&mut self) {
        for _ in 0..1_000_000u32 {
            let (now, client_addr, server_addr) = (self.now, self.client.addr, self.server.addr);
            self.client.deliver(now, server_addr);
            self.server.deliver(now, client_addr);
            let from_client = self.client.service(now);
            let from_server = self.server.service(now);
            if from_client.is_empty() && from_server.is_empty() {
                return;
            }
            for datagram in from_client {
                self.send(true, datagram);
            }
            for datagram in from_server {
                self.send(false, datagram);
            }
        }
        panic!("the link kept sending at one instant");
    }

    fn send(&mut self, from_client: bool, datagram: Bytes) {
        let filtered = self
            .filter
            .as_mut()
            .is_some_and(|filter| filter(from_client, &datagram));
        if filtered || self.rng.chance(self.loss_percent) {
            self.dropped += 1;
            return;
        }
        let at = self.now + self.latency;
        let to = if from_client {
            &mut self.server
        } else {
            &mut self.client
        };
        to.inbound.push_back((at, datagram));
    }
}

/// The type of a datagram's first chunk (RFC 9260 3.1: the common header is 12 bytes).
pub(crate) fn first_chunk_type(datagram: &Bytes) -> Option<u8> {
    datagram.get(12).copied()
}
