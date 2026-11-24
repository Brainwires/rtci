//! Two associations over an in-memory link: virtual time, a one-way latency (with optional
//! jitter), and seeded decisions per datagram whether it is lost or overtakes the ones before it.
//! No sockets and no wall clock, so a test of loss recovery is deterministic and takes virtual
//! seconds, not real ones.

use super::*;
use crate::association::Event;
use crate::association::stream::{StreamEvent, StreamId};
use std::collections::{HashMap, VecDeque};
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
    /// How messages are read: in parts with `Stream::read_part`, put together here as the
    /// data channel layer does (the default), or whole with `Stream::read_sctp`.
    pub(crate) read_parts: bool,
    /// The parts read of each stream's message that is not complete yet.
    partial: HashMap<StreamId, Vec<u8>>,
    /// How many parts were read that did not end their message.
    pub(crate) parts_before_end: usize,
    /// When true, what the endpoint itself has to send (`Endpoint::poll_transmit`: the INIT
    /// ACK of a stateless handshake, answers to out-of-the-blue packets) goes on the link.
    pub(crate) endpoint_answers: bool,
}

impl Peer {
    pub(crate) fn new(addr: SocketAddr, server: Option<ServerConfig>) -> Self {
        Peer {
            endpoint: Endpoint::new(
                addr,
                TransportProtocol::UDP,
                Arc::new(EndpointConfig::default()),
                server.map(Arc::new),
            ),
            addr,
            association: None,
            inbound: VecDeque::new(),
            events: vec![],
            received: vec![],
            auto_read: true,
            read_parts: true,
            partial: HashMap::new(),
            parts_before_end: 0,
            endpoint_answers: false,
        }
    }

    /// The association; panics if the handshake has not created it.
    pub(crate) fn conn(&mut self) -> &mut Association {
        &mut self.association.as_mut().expect("no association").1
    }

    /// How many associations the endpoint holds, the ones this link does not route to included.
    pub(crate) fn endpoint_associations(&self) -> usize {
        self.endpoint.associations.len()
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
        while self.endpoint_answers
            && let Some(transmit) = self.endpoint.poll_transmit()
        {
            if let Payload::RawEncode(contents) = transmit.message {
                out.extend(contents);
            }
        }
        let Some((ch, conn)) = self.association.as_mut() else {
            return out;
        };
        let ch = *ch;
        if conn.poll_timeout().is_some_and(|at| at <= now) {
            conn.handle_timeout(now);
        }
        while let Some(event) = conn.poll() {
            match event {
                Event::Stream(StreamEvent::Readable { id }) if self.auto_read => {
                    if let Ok(mut stream) = conn.stream(id) {
                        if self.read_parts {
                            while let Ok(Some(part)) = stream.read_part() {
                                let buf = self.partial.entry(id).or_default();
                                for c in &part.chunks.chunks {
                                    buf.extend_from_slice(&c.user_data);
                                }
                                if part.end_of_record {
                                    let whole = self.partial.remove(&id).unwrap_or_default();
                                    self.received.push((id, Bytes::from(whole)));
                                } else {
                                    self.parts_before_end += 1;
                                }
                            }
                        } else {
                            while let Ok(Some(chunks)) = stream.read_sctp() {
                                let mut buf = vec![0u8; chunks.len()];
                                let n = chunks.read(&mut buf).unwrap_or(0);
                                buf.truncate(n);
                                self.received.push((id, Bytes::from(buf)));
                            }
                        }
                    }
                }
                Event::Stream(StreamEvent::PartialDeliveryAborted { id, .. }) => {
                    self.partial.remove(&id);
                    self.events.push(event);
                }
                other => self.events.push(other),
            }
        }
        // A drain notice only matters to a real endpoint's bookkeeping; this link keeps routing.
        // New tags after a restart (RFC 9260 5.2.4) are given to the endpoint, as a real
        // driver does.
        while let Some(event) = conn.poll_endpoint_event() {
            if matches!(event.0, crate::shared::EndpointEventInner::Retagged { .. }) {
                self.endpoint.handle_event(ch, event);
            }
        }
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
    /// Up to this much extra one-way delay, drawn per datagram, so datagrams also overtake
    /// each other the way netem's `delay <latency> <jitter>` makes them.
    pub(crate) jitter: Duration,
    /// Percent of datagrams sent without any delay, overtaking the ones still in flight
    /// (netem's `reorder`).
    pub(crate) reorder_percent: u64,
    /// Drops chosen datagrams, before the random loss is applied.
    pub(crate) filter: Option<DropFilter>,
    rng: Rng,
    pub(crate) dropped: usize,
    /// Bytes each side put on the link, lost ones included: `[client, server]`.
    pub(crate) bytes_sent: [usize; 2],
}

impl Link {
    pub(crate) fn new(client: TransportConfig, server: TransportConfig, seed: u64) -> Self {
        Self::with_server_config(client, ServerConfig::new(server), seed)
    }

    /// As `new`, with the accepting endpoint's whole configuration (its association limit, say).
    pub(crate) fn with_server_config(
        client: TransportConfig,
        server: ServerConfig,
        seed: u64,
    ) -> Self {
        Link {
            client: Peer::new(SocketAddr::from(([10, 0, 0, 1], 5000)), None),
            server: Peer::new(SocketAddr::from(([10, 0, 0, 2], 5000)), Some(server)),
            client_transport: client,
            now: Instant::now(),
            latency: Duration::from_millis(10),
            loss_percent: 0,
            jitter: Duration::ZERO,
            reorder_percent: 0,
            filter: None,
            rng: Rng::new(seed),
            dropped: 0,
            bytes_sent: [0, 0],
        }
    }

    /// Starts the client's handshake without waiting for it.
    pub(crate) fn begin_connect(&mut self) {
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
    }

    /// Starts the client's handshake and runs until both sides are connected.
    pub(crate) fn connect(&mut self) {
        self.begin_connect();
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
        self.bytes_sent[usize::from(!from_client)] += datagram.len();
        let filtered = self
            .filter
            .as_mut()
            .is_some_and(|filter| filter(from_client, &datagram));
        if filtered || self.rng.chance(self.loss_percent) {
            self.dropped += 1;
            return;
        }
        // Neither draws from the generator while it is off, so a link without them loses the
        // same datagrams for a given seed as it did before they existed.
        let at = if self.rng.chance(self.reorder_percent) {
            self.now
        } else if self.jitter.is_zero() {
            self.now + self.latency
        } else {
            let jitter_us = self.jitter.as_micros() as u64;
            self.now + self.latency + Duration::from_micros(self.rng.next_u64() % (jitter_us + 1))
        };
        let to = if from_client {
            &mut self.server
        } else {
            &mut self.client
        };
        // Kept in arrival order: `deliver` takes datagrams from the front while they are due.
        let index = to.inbound.partition_point(|(due, _)| *due <= at);
        to.inbound.insert(index, (at, datagram));
    }
}

/// The type of a datagram's first chunk (RFC 9260 3.1: the common header is 12 bytes).
pub(crate) fn first_chunk_type(datagram: &Bytes) -> Option<u8> {
    datagram.get(12).copied()
}
