//! Helpers for the tests of `Mdns`: hand-built messages (so that a test does not check the
//! writer with the writer), delivery, and a virtual clock.

use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

use bytes::BytesMut;
use sansio::Protocol;
use shared::{TaggedBytesMut, TransportContext, TransportProtocol};

use super::wire::{self, CLASS_IN, CLASS_TOP_BIT, Inbound, TYPE_A, TYPE_AAAA};
use super::{MDNS_DEST_ADDR, Mdns, MdnsEvent, QueryId};
use crate::config::MdnsConfig;

/// Names as an ICE agent makes them (`<uuid>.local`): not probed for.
pub(super) const UUID_1: &str = "aaaaaaaa-0000-4000-8000-000000000001.local";
pub(super) const UUID_2: &str = "aaaaaaaa-0000-4000-8000-000000000002.local";

pub(super) const TYPE_TXT: u16 = 16;
pub(super) const CLASS_CHAOS: u16 = 3;

/// Header flags of a response (QR, AA) and of a query.
pub(super) const RESPONSE: u16 = 0x8400;
pub(super) const QUERY: u16 = 0;
pub(super) const TC: u16 = 0x0200;

pub(super) fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

pub(super) fn ms(millis: u64) -> Duration {
    Duration::from_millis(millis)
}

/// The default configuration with a fixed jitter seed (a test that fails, fails every time),
/// for a caller that says where each datagram was addressed to.
pub(super) fn config() -> MdnsConfig {
    MdnsConfig::default()
        .with_jitter_seed(1)
        .with_destination_reported(true)
}

/// A record to put into a hand-built message.
#[derive(Debug, Clone)]
pub(super) struct Rec {
    pub(super) name: String,
    pub(super) typ: u16,
    /// The class field as on the wire, top bit included.
    pub(super) class: u16,
    pub(super) ttl: u32,
    pub(super) rdata: Vec<u8>,
}

/// An address record for `name` with TTL 120 and the cache-flush bit, as its owner sends it.
pub(super) fn addr(name: &str, address: &str) -> Rec {
    let (typ, rdata) = match ip(address) {
        IpAddr::V4(v4) => (TYPE_A, v4.octets().to_vec()),
        IpAddr::V6(v6) => (TYPE_AAAA, v6.octets().to_vec()),
    };
    Rec {
        name: name.to_owned(),
        typ,
        class: CLASS_IN | CLASS_TOP_BIT,
        ttl: 120,
        rdata,
    }
}

impl Rec {
    pub(super) fn ttl(mut self, ttl: u32) -> Self {
        self.ttl = ttl;
        self
    }

    pub(super) fn class(mut self, class: u16) -> Self {
        self.class = class;
        self
    }
}

/// A record of another type, with the data given.
pub(super) fn other(name: &str, typ: u16, rdata: &[u8]) -> Rec {
    Rec {
        name: name.to_owned(),
        typ,
        class: CLASS_IN | CLASS_TOP_BIT,
        ttl: 120,
        rdata: rdata.to_vec(),
    }
}

/// `name` in wire form, uncompressed.
pub(super) fn wire_name(name: &str) -> Vec<u8> {
    let mut out = Vec::new();
    for label in name
        .trim_end_matches('.')
        .split('.')
        .filter(|l| !l.is_empty())
    {
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
    out
}

/// A DNS message built by hand: no compression, the counts as given by the slices.
pub(super) fn message(
    id: u16,
    flags: u16,
    questions: &[(&str, u16, u16)],
    answers: &[Rec],
    authorities: &[Rec],
    additionals: &[Rec],
) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&id.to_be_bytes());
    out.extend_from_slice(&flags.to_be_bytes());
    for count in [
        questions.len(),
        answers.len(),
        authorities.len(),
        additionals.len(),
    ] {
        out.extend_from_slice(&(count as u16).to_be_bytes());
    }
    for (name, typ, class) in questions {
        out.extend_from_slice(&wire_name(name));
        out.extend_from_slice(&typ.to_be_bytes());
        out.extend_from_slice(&class.to_be_bytes());
    }
    for rec in answers.iter().chain(authorities).chain(additionals) {
        out.extend_from_slice(&wire_name(&rec.name));
        out.extend_from_slice(&rec.typ.to_be_bytes());
        out.extend_from_slice(&rec.class.to_be_bytes());
        out.extend_from_slice(&rec.ttl.to_be_bytes());
        out.extend_from_slice(&(rec.rdata.len() as u16).to_be_bytes());
        out.extend_from_slice(&rec.rdata);
    }
    out
}

/// A query for `name`'s A and AAAA records, as this crate's resolver and browsers send it.
pub(super) fn query_for(name: &str) -> Vec<u8> {
    message(
        0,
        QUERY,
        &[(name, TYPE_A, CLASS_IN), (name, TYPE_AAAA, CLASS_IN)],
        &[],
        &[],
        &[],
    )
}

/// A response answering with `answers`.
pub(super) fn response(answers: &[Rec]) -> Vec<u8> {
    message(0, RESPONSE, &[], answers, &[], &[])
}

/// Gives `conn` a datagram from `from` (`ip:port`) that arrived on the multicast group.
pub(super) fn deliver(conn: &mut Mdns, now: Instant, from: &str, bytes: &[u8]) {
    deliver_to(conn, now, from, MDNS_DEST_ADDR, bytes);
}

/// Gives `conn` a datagram from `from` that was addressed to `to`.
pub(super) fn deliver_to(conn: &mut Mdns, now: Instant, from: &str, to: SocketAddr, bytes: &[u8]) {
    conn.handle_read(TaggedBytesMut {
        now,
        transport: TransportContext {
            local_addr: to,
            peer_addr: from.parse().unwrap(),
            transport_protocol: TransportProtocol::UDP,
            ecn: None,
        },
        message: BytesMut::from(bytes),
    })
    .unwrap();
}

/// A packet `Mdns` wrote.
pub(super) struct Sent {
    /// When it was queued, since the test's base instant.
    pub(super) at: Duration,
    pub(super) from: SocketAddr,
    pub(super) to: SocketAddr,
    pub(super) raw: Vec<u8>,
    pub(super) msg: Inbound,
}

impl Sent {
    pub(super) fn is_response(&self) -> bool {
        self.msg.header.response
    }

    /// The header's flags word.
    pub(super) fn flags(&self) -> u16 {
        u16::from_be_bytes([self.raw[2], self.raw[3]])
    }

    /// Whether it goes to the mDNS group.
    pub(super) fn multicast(&self) -> bool {
        self.to == MDNS_DEST_ADDR
    }
}

/// Everything `conn` has queued, taken off its write queue.
pub(super) fn sent(conn: &mut Mdns, base: Instant) -> Vec<Sent> {
    std::iter::from_fn(|| conn.poll_write())
        .map(|packet| Sent {
            at: packet.now.duration_since(base),
            from: packet.transport.local_addr,
            to: packet.transport.peer_addr,
            msg: wire::parse(&packet.message).expect("Mdns writes messages it can read"),
            raw: packet.message.to_vec(),
        })
        .collect()
}

/// Runs `conn`'s timers in order from `base + from` to `base + until` (both included),
/// returning what it wrote on the way.
pub(super) fn run(conn: &mut Mdns, base: Instant, from: Duration, until: Duration) -> Vec<Sent> {
    let mut out = Vec::new();
    let mut now = base + from;
    let end = base + until;
    conn.handle_timeout(now).unwrap();
    out.extend(sent(conn, base));
    for _ in 0..10_000 {
        let Some(next) = conn.poll_timeout() else {
            break;
        };
        if next > end {
            break;
        }
        now = next.max(now);
        conn.handle_timeout(now).unwrap();
        out.extend(sent(conn, base));
    }
    conn.handle_timeout(end).unwrap();
    out.extend(sent(conn, base));
    out
}

pub(super) fn events(conn: &mut Mdns) -> Vec<MdnsEvent> {
    std::iter::from_fn(|| conn.poll_event()).collect()
}

/// The queries answered, of the events queued.
pub(super) fn answered(conn: &mut Mdns) -> Vec<(QueryId, IpAddr)> {
    events(conn)
        .into_iter()
        .filter_map(|event| match event {
            MdnsEvent::QueryAnswered(id, addr) => Some((id, addr)),
            _ => None,
        })
        .collect()
}

/// The queries that ended without an address, of the events queued.
pub(super) fn ended(conn: &mut Mdns) -> Vec<QueryId> {
    events(conn)
        .into_iter()
        .filter_map(|event| match event {
            MdnsEvent::QueryTimeout(id) => Some(id),
            _ => None,
        })
        .collect()
}

/// A responder that owns `name` at `address`, started and past its announcements: ten
/// seconds into the test, with nothing left to send.
pub(super) fn established(base: Instant, name: &str, address: &str) -> Mdns {
    let mut conn = Mdns::new(base, config());
    assert!(conn.add_local_name(name, ip(address)));
    run(&mut conn, base, ms(0), ms(10_000));
    assert!(conn.poll_timeout().is_none(), "nothing is left to do");
    conn
}
