#![no_main]
//! Stateful target: the mDNS responder and resolver (`Mdns`) fed fuzzed multicast datagrams.
//!
//! Every datagram goes through the DNS message parser (header, questions, every resource record
//! type, name compression) and then through the responder (questions for our names) and the
//! resolver (answers for pending queries). Besides raw datagrams the input can build a question
//! for one of our names or an answer for one of our pending queries around fuzzed bytes, so the
//! matching paths are reached without the fuzzer having to guess a name. Queries are started,
//! cancelled and retried on a clock the input advances. No randomness: an input replays
//! identically.

use bytes::BytesMut;
use libfuzzer_sys::fuzz_target;
use rtc_mdns::{MDNS_DEST_ADDR, Mdns, MdnsConfig, QueryId};
use rtc_shared::{TaggedBytesMut, TransportContext, TransportProtocol};
use sansio::Protocol;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

// One base instant for the whole process: the harness only ever adds input-chosen offsets to it.
static START: OnceLock<Instant> = OnceLock::new();

/// The names the resolver asks for and the responder owns, uuid-shaped like a browser's.
const NAMES: [&str; 4] = [
    "f81d4fae-7dec-11d0-a765-00a0c91e6bf6.local",
    "0d1b5b8e-3c1a-4c55-9e0a-6c1f0a7c2b11.local",
    "a.local",
    "device.local",
];

fn byte(arg: &[u8], i: usize) -> u8 {
    arg.get(i).copied().unwrap_or(0)
}

/// Splits the next op argument off `data`: a one-byte length, then that many bytes.
fn take_arg<'a>(data: &mut &'a [u8]) -> &'a [u8] {
    let Some((&len, rest)) = data.split_first() else {
        return &[];
    };
    let len = usize::from(len).min(rest.len());
    let (arg, rest) = rest.split_at(len);
    *data = rest;
    arg
}

/// A name in DNS wire form: length-prefixed labels and the root label.
fn encode_name(name: &str) -> Vec<u8> {
    let mut out = Vec::new();
    for label in name.trim_end_matches('.').split('.') {
        let label = &label.as_bytes()[..label.len().min(63)];
        out.push(label.len() as u8);
        out.extend_from_slice(label);
    }
    out.push(0);
    out
}

/// A DNS header: id 0, the flags, then the four section counts.
fn header(flags: u16, questions: u16, answers: u16) -> Vec<u8> {
    let mut out = vec![0, 0];
    out.extend_from_slice(&flags.to_be_bytes());
    out.extend_from_slice(&questions.to_be_bytes());
    out.extend_from_slice(&answers.to_be_bytes());
    out.extend_from_slice(&[0, 0, 0, 0]);
    out
}

/// A source address: on the local link, off it, or IPv6, as the flags byte says.
fn source(flags: u8, host: u8) -> SocketAddr {
    let ip = match flags % 3 {
        0 => IpAddr::V4(Ipv4Addr::new(192, 168, 1, host)),
        1 => IpAddr::V4(Ipv4Addr::new(203, 0, 113, host)),
        _ => IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, u16::from(host))),
    };
    let port = if flags & 0x80 == 0 { 5353 } else { 40000 };
    SocketAddr::new(ip, port)
}

struct Harness {
    mdns: Mdns,
    now: Instant,
    queries: Vec<QueryId>,
}

impl Harness {
    fn drain(&mut self) {
        let mut budget = 4096;
        while self.mdns.poll_write().is_some() && budget > 0 {
            budget -= 1;
        }
        while self.mdns.poll_event().is_some() && budget > 0 {
            budget -= 1;
        }
    }

    fn datagram(&mut self, from: SocketAddr, message: &[u8]) {
        let _ = self.mdns.handle_read(TaggedBytesMut {
            now: self.now,
            transport: TransportContext {
                local_addr: MDNS_DEST_ADDR,
                peer_addr: from,
                transport_protocol: TransportProtocol::UDP,
                ecn: None,
            },
            message: BytesMut::from(message),
        });
        self.drain();
    }

    fn advance(&mut self, millis: u16) {
        self.now += Duration::from_millis(u64::from(millis));
        let _ = self.mdns.handle_timeout(self.now);
        // A timer the responder asks for at or before now fires too.
        if let Some(deadline) = self.mdns.poll_timeout()
            && deadline <= self.now
        {
            let _ = self.mdns.handle_timeout(self.now);
        }
        self.drain();
    }
}

fuzz_target!(|data: &[u8]| {
    let start = *START.get_or_init(Instant::now);
    let mut data = data;
    let Some((&config, rest)) = data.split_first() else {
        return;
    };
    data = rest;

    let mut mdns_config = MdnsConfig::default()
        .with_query_interval(Duration::from_millis(u64::from(config & 0x0f) * 100));
    if config & 0x10 != 0 {
        mdns_config =
            mdns_config.with_query_timeout(Duration::from_secs(u64::from(config >> 5) + 1));
    }
    if config & 0x20 != 0 {
        mdns_config = mdns_config
            .with_local_names(vec![NAMES[0].to_owned()])
            .with_local_ip(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2)));
    }

    let mut h = Harness {
        mdns: Mdns::new(start, mdns_config),
        now: start,
        queries: Vec::new(),
    };
    h.mdns
        .add_local_name(NAMES[1], IpAddr::V4(Ipv4Addr::new(192, 168, 1, 3)));

    let mut ops = 0;
    while let Some((&op, rest)) = data.split_first() {
        data = rest;
        ops += 1;
        if ops > 256 {
            break;
        }
        let arg = take_arg(&mut data);
        match op % 8 {
            // A raw datagram.
            0 => h.datagram(
                source(byte(arg, 0), byte(arg, 1)),
                arg.get(2..).unwrap_or(&[]),
            ),
            // A response answering one of the names: the record type, class, TTL and RDATA
            // come from the input.
            1 => {
                let name = NAMES[usize::from(byte(arg, 0)) % NAMES.len()];
                let mut message = header(0x8400, 0, 1 + u16::from(byte(arg, 1) & 0x01));
                for _ in 0..1 + (byte(arg, 1) & 0x01) {
                    message.extend_from_slice(&encode_name(name));
                    let typ = if byte(arg, 2) & 0x01 == 0 { 1u16 } else { 28 };
                    message.extend_from_slice(&typ.to_be_bytes());
                    message.extend_from_slice(&[byte(arg, 3) & 0x80, 0x01]);
                    message.extend_from_slice(&[0, 0, 0, byte(arg, 4)]);
                    let rdata = arg.get(6..).unwrap_or(&[]);
                    let rdlen = if byte(arg, 5) & 0x80 == 0 {
                        rdata.len() as u16
                    } else {
                        u16::from(byte(arg, 5) & 0x7f)
                    };
                    message.extend_from_slice(&rdlen.to_be_bytes());
                    message.extend_from_slice(rdata);
                }
                h.datagram(source(byte(arg, 3), byte(arg, 4)), &message);
            }
            // A question for one of the names, with fuzzed type and class.
            2 => {
                let name = NAMES[usize::from(byte(arg, 0)) % NAMES.len()];
                let mut message = header(u16::from(byte(arg, 1)) << 8, 1, 0);
                message.extend_from_slice(&encode_name(name));
                message.extend_from_slice(&[0, byte(arg, 2), byte(arg, 3) & 0x80, 0x01]);
                message.extend_from_slice(arg.get(4..).unwrap_or(&[]));
                h.datagram(source(byte(arg, 1), byte(arg, 2)), &message);
            }
            3 => {
                let name = NAMES[usize::from(byte(arg, 0)) % NAMES.len()];
                let id = h.mdns.query_now(h.now, name);
                h.queries.push(id);
                h.drain();
            }
            4 => {
                let name = NAMES[usize::from(byte(arg, 0)) % NAMES.len()];
                let id = h.mdns.schedule_query(name);
                h.queries.push(id);
                h.drain();
            }
            5 => {
                if !h.queries.is_empty() {
                    let id = h.queries[usize::from(byte(arg, 0)) % h.queries.len()];
                    h.mdns.cancel_query(id);
                    let _ = h.mdns.is_query_pending(id);
                    let _ = h.mdns.pending_query_count();
                }
            }
            6 => h.advance(u16::from_be_bytes([byte(arg, 0), byte(arg, 1)])),
            _ => {
                let name = String::from_utf8_lossy(arg.get(1..).unwrap_or(&[])).into_owned();
                let ip = if byte(arg, 0) & 0x01 == 0 {
                    IpAddr::V4(Ipv4Addr::new(10, 0, 0, byte(arg, 0)))
                } else {
                    IpAddr::V6(Ipv6Addr::new(
                        0xfe80,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        u16::from(byte(arg, 0)),
                    ))
                };
                let _ = h.mdns.add_local_name(&name, ip);
            }
        }
    }
});
