//! Entry points for stateful fuzz targets.
//!
//! [`client_handle_inbound`] drives a TURN client through allocation, permissions, channel
//! binding and refreshes, answering its requests with fuzzer-shaped server responses and
//! injecting Data indications and ChannelData. Responses carry the transaction id of a request
//! the client actually sent (picked by position) and come from the configured server, so they
//! get past the transaction and source checks to the response handlers.
//!
//! The clock is `start` plus offsets the input chooses, and there are no sockets. STUN
//! transaction ids are drawn by `rand` inside `rtci-stun`; the harness never depends on their
//! value. Gated behind `cfg(fuzzing)`; not part of the supported API.
use std::collections::VecDeque;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};

use bytes::BytesMut;
use sansio::Protocol;
use shared::{TaggedBytesMut, TransportContext, TransportProtocol};
use stun::attributes::{
    ATTR_ALTERNATE_SERVER, ATTR_CONNECTION_ID, ATTR_LIFETIME, ATTR_NONCE, ATTR_REALM,
    ATTR_RESERVATION_TOKEN, ATTR_UNKNOWN_ATTRIBUTES, ATTR_XOR_RELAYED_ADDRESS,
    ATTR_XORMAPPED_ADDRESS, AttrType,
};
use stun::error_code::{CODE_STALE_NONCE, CODE_UNAUTHORIZED, ErrorCode, ErrorCodeAttribute};
use stun::fingerprint::FINGERPRINT;
use stun::integrity::MessageIntegrity;
use stun::message::{
    CLASS_ERROR_RESPONSE, CLASS_INDICATION, CLASS_REQUEST, CLASS_SUCCESS_RESPONSE, METHOD_ALLOCATE,
    METHOD_CHANNEL_BIND, METHOD_CONNECTION_ATTEMPT, METHOD_CONNECTION_BIND, METHOD_DATA, Message,
    MessageType, Method, Setter, TransactionId, is_stun_message,
};
use stun::textattrs::TextAttribute;
use stun::xoraddr::XorMappedAddress;

use crate::client::credential::{Credential, Login};
use crate::client::data_connection::{DataConnection, DataConnectionConfig};
use crate::client::{AllocateOptions, Client, ClientConfig, Event, RelayTransport};
use crate::proto::addfamily::ATTR_ADDITIONAL_ADDRESS_FAMILY;
use crate::proto::addrerror::ATTR_ADDRESS_ERROR_CODE;
use crate::proto::chandata::ChannelData;
use crate::proto::channum::ChannelNumber;
use crate::proto::connid::ConnectionId;
use crate::proto::data::Data;
use crate::proto::evenport::EvenPort;
use crate::proto::icmp::ATTR_ICMP;
use crate::proto::lifetime::Lifetime;
use crate::proto::peeraddr::PeerAddress;
use crate::proto::relayaddr::RelayedAddress;
use crate::proto::reqfamily::RequestedAddressFamily;
use crate::proto::rsrvtoken::ReservationToken;

const USERNAME: &str = "fuzz-user";
const PASSWORD: &str = "fuzz-password";

/// Attributes the client reads from a server's responses beside the ones the harness builds:
/// RESERVATION-TOKEN, ADDITIONAL-ADDRESS-FAMILY, ADDRESS-ERROR-CODE, ICMP, UNKNOWN-ATTRIBUTES,
/// ALTERNATE-SERVER, XOR-RELAYED-ADDRESS (a second one), XOR-MAPPED-ADDRESS, LIFETIME, and
/// CONNECTION-ID (RFC 6062).
const RESPONSE_ATTRS: [AttrType; 10] = [
    ATTR_CONNECTION_ID,
    ATTR_RESERVATION_TOKEN,
    ATTR_ADDITIONAL_ADDRESS_FAMILY,
    ATTR_ADDRESS_ERROR_CODE,
    ATTR_ICMP,
    ATTR_UNKNOWN_ATTRIBUTES,
    ATTR_ALTERNATE_SERVER,
    ATTR_XOR_RELAYED_ADDRESS,
    ATTR_XORMAPPED_ADDRESS,
    ATTR_LIFETIME,
];

/// How many of the client's outgoing requests the harness remembers.
const REQUESTS: usize = 16;

fn turn_server() -> SocketAddr {
    SocketAddr::from(([10, 0, 0, 9], 3478))
}

fn stun_server() -> SocketAddr {
    SocketAddr::from(([10, 0, 0, 8], 3478))
}

/// One of a handful of peers, so permissions and channel bindings collide.
fn peer(selector: u8) -> SocketAddr {
    SocketAddr::from((
        [192, 0, 2, 1 + (selector & 0x03)],
        4000 + u16::from(selector >> 2 & 0x03),
    ))
}

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

struct Harness {
    client: Client,
    now: Instant,
    /// The client's recent requests: transaction id, method and destination.
    requests: VecDeque<(TransactionId, Method, SocketAddr)>,
    /// Relayed addresses the client reported as allocated.
    relays: Vec<SocketAddr>,
    /// Channel numbers seen in the client's ChannelBind requests.
    channels: Vec<u16>,
}

impl Harness {
    fn drain(&mut self) {
        while let Some(msg) = self.client.poll_write() {
            if !is_stun_message(&msg.message) {
                continue;
            }
            let mut m = Message {
                raw: msg.message.to_vec(),
                ..Message::default()
            };
            if m.decode().is_err() || m.typ.class != CLASS_REQUEST {
                continue;
            }
            if m.typ.method == METHOD_CHANNEL_BIND {
                let mut number = ChannelNumber::default();
                use stun::message::Getter;
                if number.get_from(&m).is_ok() && !self.channels.contains(&number.0) {
                    self.channels.push(number.0);
                }
            }
            if self.requests.len() == REQUESTS {
                self.requests.pop_front();
            }
            self.requests
                .push_back((m.transaction_id, m.typ.method, msg.transport.peer_addr));
        }
        while let Some(event) = self.client.poll_event() {
            if let Event::AllocateResponse(_, relayed) = event
                && !self.relays.contains(&relayed)
            {
                self.relays.push(relayed);
            }
        }
    }

    fn inbound(&mut self, from: SocketAddr, message: Vec<u8>) {
        let _ = self.client.handle_read(TaggedBytesMut {
            now: self.now,
            transport: TransportContext {
                local_addr: self.client.local_addr(),
                peer_addr: from,
                ecn: None,
                transport_protocol: TransportProtocol::UDP,
            },
            message: BytesMut::from(&message[..]),
        });
        self.drain();
    }

    fn source(&self, selector: u8, request_to: SocketAddr) -> SocketAddr {
        match selector & 0x03 {
            0 => request_to,
            1 => turn_server(),
            2 => stun_server(),
            _ => peer(selector >> 2),
        }
    }

    /// A server response to one of the client's requests, with fuzzer-chosen class and
    /// attributes. With no request outstanding, a response under a made-up id.
    fn response(&mut self, arg: &[u8]) {
        let flags = byte(arg, 0);
        let (transaction_id, method, to) = if self.requests.is_empty() {
            (
                TransactionId([byte(arg, 1); 12]),
                METHOD_ALLOCATE,
                turn_server(),
            )
        } else {
            self.requests[usize::from(byte(arg, 1)) % self.requests.len()]
        };
        let class = if flags & 0x01 != 0 {
            CLASS_ERROR_RESPONSE
        } else {
            CLASS_SUCCESS_RESPONSE
        };
        let address = SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(
                byte(arg, 2),
                byte(arg, 3),
                byte(arg, 4),
                byte(arg, 5),
            )),
            u16::from_be_bytes([byte(arg, 6), byte(arg, 7)]),
        );
        let lifetime = u32::from_be_bytes([0, byte(arg, 8), byte(arg, 9), byte(arg, 10)]);
        let text = String::from_utf8_lossy(arg.get(12..).unwrap_or(&[])).into_owned();

        let realm = "fuzz-realm".to_owned();
        let provider = crypto::default_provider().ok();
        let mut setters: Vec<Box<dyn Setter>> = vec![
            Box::new(transaction_id),
            Box::new(MessageType::new(method, class)),
        ];
        if class == CLASS_ERROR_RESPONSE {
            let code = match byte(arg, 11) & 0x03 {
                0 => CODE_UNAUTHORIZED,
                1 => CODE_STALE_NONCE,
                _ => ErrorCode(u16::from(byte(arg, 11)) * 4),
            };
            setters.push(Box::new(ErrorCodeAttribute {
                code,
                reason: b"fuzz".to_vec(),
            }));
        } else {
            if flags & 0x02 != 0 {
                setters.push(Box::new(RelayedAddress {
                    ip: address.ip(),
                    port: address.port(),
                }));
            }
            if flags & 0x04 != 0 {
                setters.push(Box::new(Lifetime(Duration::from_secs(u64::from(lifetime)))));
            }
            setters.push(Box::new(XorMappedAddress {
                ip: address.ip(),
                port: address.port(),
            }));
        }
        if flags & 0x08 != 0 {
            setters.push(Box::new(TextAttribute::new(ATTR_NONCE, text.clone())));
        }
        if flags & 0x10 != 0 {
            setters.push(Box::new(TextAttribute::new(ATTR_REALM, realm.clone())));
        }
        if flags & 0x20 != 0
            && let Some(provider) = provider.as_ref()
            && let Ok(integrity) = MessageIntegrity::new_long_term_integrity_with_provider(
                USERNAME.to_owned(),
                realm,
                PASSWORD.to_owned(),
                provider.crypto(),
            )
        {
            setters.push(Box::new(integrity));
        }
        if flags & 0x40 != 0 {
            setters.push(Box::new(FINGERPRINT));
        }
        let mut m = Message::new();
        if m.build(&setters).is_ok() {
            if flags & 0x80 != 0 {
                // One more attribute, raw: the value from the input, the type one the
                // client reads from a response or any other.
                let typ = if byte(arg, 11) & 0x04 != 0 {
                    RESPONSE_ATTRS[usize::from(byte(arg, 9)) % RESPONSE_ATTRS.len()]
                } else {
                    AttrType(u16::from(byte(arg, 11)) << 8 | 0x22)
                };
                m.add(typ, text.as_bytes());
                m.write_length();
            }
            let from = self.source(byte(arg, 11) >> 4, to);
            self.inbound(from, m.raw);
        }
    }

    /// A Data indication from the server (or elsewhere), carrying a fuzzed peer and payload.
    fn data_indication(&mut self, arg: &[u8]) {
        let flags = byte(arg, 0);
        // A Data indication, or the ConnectionAttempt indication of a TCP allocation.
        let method = if flags & 0x08 != 0 {
            METHOD_CONNECTION_ATTEMPT
        } else {
            METHOD_DATA
        };
        let mut setters: Vec<Box<dyn Setter>> = vec![
            Box::new(TransactionId([flags; 12])),
            Box::new(MessageType::new(method, CLASS_INDICATION)),
        ];
        if flags & 0x08 != 0 && flags & 0x02 == 0 {
            setters.push(Box::new(ConnectionId(u32::from(byte(arg, 2)))));
        }
        if flags & 0x01 == 0 {
            let p = peer(byte(arg, 1));
            setters.push(Box::new(PeerAddress {
                ip: p.ip(),
                port: p.port(),
            }));
        }
        if flags & 0x02 == 0 {
            setters.push(Box::new(Data(arg.get(2..).unwrap_or(&[]).to_vec())));
        }
        let mut m = Message::new();
        if m.build(&setters).is_ok() {
            if flags & 0x04 != 0 {
                // An ICMP attribute (RFC 8656 §18.13), of whatever length the input has.
                m.add(ATTR_ICMP, arg.get(2..).unwrap_or(&[]));
                m.write_length();
            }
            let from = self.source(flags >> 4, turn_server());
            self.inbound(from, m.raw);
        }
    }

    /// ChannelData from the server, on a channel the client bound (or any other number).
    fn channel_data(&mut self, arg: &[u8]) {
        let flags = byte(arg, 0);
        let number = if flags & 0x01 == 0 && !self.channels.is_empty() {
            self.channels[usize::from(byte(arg, 1)) % self.channels.len()]
        } else {
            u16::from_be_bytes([byte(arg, 1), byte(arg, 2)])
        };
        let mut channel_data = ChannelData {
            data: arg.get(3..).unwrap_or(&[]).to_vec(),
            number: ChannelNumber(number),
            raw: vec![],
        };
        let _ = channel_data.encode();
        if flags & 0x02 != 0 && channel_data.raw.len() >= 4 {
            // A length field that disagrees with the payload.
            channel_data.raw[2] = byte(arg, 2);
            channel_data.raw[3] = byte(arg, 1);
        }
        let from = self.source(flags >> 4, turn_server());
        self.inbound(from, channel_data.raw);
    }

    fn with_relay(
        &mut self,
        selector: u8,
        f: impl FnOnce(&mut crate::client::relay::Relay<'_>, Instant),
    ) {
        if self.relays.is_empty() {
            return;
        }
        let relayed = self.relays[usize::from(selector) % self.relays.len()];
        let now = self.now;
        if let Ok(mut relay) = self.client.relay(relayed) {
            f(&mut relay, now);
        }
        self.drain();
    }
}

/// Stateful target: a TURN client fed fuzzed server responses, Data indications and ChannelData.
///
/// The first byte sets the client's options (a STUN server, the refresh cap, UDP or TCP to the
/// server). The rest is a
/// sequence of ops, each an op byte followed by a length-prefixed argument:
///
/// - client actions: Allocate with any options (a TCP allocation among them, when the client
///   reaches the server over TCP), Connect and data connections, Binding requests, CreatePermission, send (which
///   binds a channel), send with DONT-FRAGMENT, closing a relay or one of its address
///   families, refreshing allocations, new credentials;
/// - a response to one of the client's requests, with fuzzed class, error code, relayed and
///   mapped address, lifetime, NONCE / REALM, MESSAGE-INTEGRITY, FINGERPRINT, an extra raw
///   attribute (of a type the client reads, or any), and source address;
/// - a Data indication (with DATA, ICMP or neither), a ConnectionAttempt indication or
///   ChannelData, from the server or elsewhere;
/// - a raw datagram; advancing the clock, which drives retransmissions and refreshes.
pub fn client_handle_inbound(mut data: &[u8], start: Instant) {
    let Some((&config, rest)) = data.split_first() else {
        return;
    };
    data = rest;
    let Ok(provider) = crypto::fuzzing::deterministic_provider(31, false) else {
        return;
    };
    let Ok(client) = Client::new(
        ClientConfig {
            stun_serv_addr: if config & 0x01 != 0 {
                stun_server().to_string()
            } else {
                String::new()
            },
            turn_serv_addr: turn_server().to_string(),
            local_addr: SocketAddr::from(([10, 0, 0, 1], 5000)),
            // Over TCP the client can hold a TCP allocation (RFC 6062).
            transport_protocol: if config & 0x08 != 0 {
                TransportProtocol::TCP
            } else {
                TransportProtocol::UDP
            },
            username: USERNAME.to_owned(),
            password: PASSWORD.to_owned(),
            realm: String::new(),
            software: if config & 0x02 != 0 {
                "fuzz".to_owned()
            } else {
                String::new()
            },
            rto_in_ms: 100,
            allocation_refresh_interval_cap: (config & 0x04 != 0)
                .then(|| Duration::from_millis(u64::from(config) * 40)),
            ..Default::default()
        },
        provider,
    ) else {
        return;
    };
    let mut h = Harness {
        client,
        now: start,
        requests: VecDeque::new(),
        relays: Vec::new(),
        channels: Vec::new(),
    };

    let mut ops = 0;
    while let Some((&op, rest)) = data.split_first() {
        data = rest;
        ops += 1;
        if ops > 256 {
            break;
        }
        let arg = take_arg(&mut data);
        let now = h.now;
        match op % 17 {
            0 => {
                // An Allocate with the options the argument picks; every combination the
                // RFC forbids must be refused, not sent.
                let flags = byte(arg, 0);
                let options = AllocateOptions {
                    transport: if byte(arg, 2) & 0x01 != 0 {
                        RelayTransport::Tcp
                    } else {
                        RelayTransport::Udp
                    },
                    address_family: (flags & 0x01 != 0)
                        .then(|| RequestedAddressFamily(1 + (flags >> 1 & 0x01))),
                    additional_ipv6: flags & 0x04 != 0,
                    lifetime: (flags & 0x08 != 0)
                        .then(|| Duration::from_secs(u64::from(byte(arg, 1)) * 60)),
                    dont_fragment: flags & 0x10 != 0,
                    even_port: (flags & 0x20 != 0).then_some(EvenPort {
                        reserve_port: flags & 0x40 != 0,
                    }),
                    reservation_token: (flags & 0x80 != 0)
                        .then(|| ReservationToken(vec![byte(arg, 1); 8])),
                };
                let _ = h.client.allocate_with(now, options);
                h.drain();
            }
            1 => {
                let _ = h.client.send_binding_request(now);
                h.drain();
            }
            2 => {
                let to = h.source(byte(arg, 0), turn_server());
                let _ = h.client.send_binding_request_to(now, to);
                h.drain();
            }
            3 => h.response(arg),
            4 => h.data_indication(arg),
            5 => h.channel_data(arg),
            6 => {
                let from = h.source(byte(arg, 0), turn_server());
                h.inbound(from, arg.to_vec());
            }
            7 => {
                h.now += Duration::from_millis(u64::from(byte(arg, 0)) * 250 + 1);
                let _ = h.client.handle_timeout(h.now);
                let _ = h.client.poll_timeout();
                h.drain();
            }
            8 => {
                let p = peer(byte(arg, 1));
                h.with_relay(byte(arg, 0), |relay, now| {
                    let _ = relay.create_permission(now, p);
                });
            }
            9 => {
                let p = peer(byte(arg, 1));
                let payload = arg.get(2..).unwrap_or(&[]).to_vec();
                h.with_relay(byte(arg, 0), |relay, now| {
                    let _ = relay.send_to(now, &payload, p);
                });
            }
            10 => h.with_relay(byte(arg, 0), |relay, now| {
                let _ = relay.close(now);
            }),
            11 => {
                let _ = h.client.refresh_allocations(now);
                h.drain();
            }
            12 => {
                let _ = h.client.update_credentials(
                    String::from_utf8_lossy(arg).into_owned(),
                    PASSWORD.to_owned(),
                );
            }
            13 => {
                let p = peer(byte(arg, 1));
                let payload = arg.get(2..).unwrap_or(&[]).to_vec();
                h.with_relay(byte(arg, 0), |relay, now| {
                    let _ = relay.send_to_dont_fragment(now, &payload, p);
                });
            }
            14 => {
                let family = RequestedAddressFamily(byte(arg, 1) & 0x03);
                h.with_relay(byte(arg, 0), |relay, now| {
                    let _ = relay.release_family(now, family);
                });
                h.client.clear_allocate_restrictions();
            }
            15 => {
                // A Connect through a TCP allocation, and a data connection for whatever
                // CONNECTION-ID the argument names.
                let p = peer(byte(arg, 1));
                let connection_id = ConnectionId(u32::from(byte(arg, 2)));
                h.with_relay(byte(arg, 0), |relay, now| {
                    let _ = relay.connect(now, p);
                    let _ = relay.data_connection(
                        now,
                        connection_id,
                        SocketAddr::from(([10, 0, 0, 1], 5001)),
                    );
                });
            }
            _ => {
                let _ = h.client.close();
                h.drain();
            }
        }
    }
}

/// Stateful target: the data connection of a TCP allocation (RFC 6062 §4.3 to §4.5) fed a
/// fuzzed stream.
///
/// The first byte says whether the connection has a credential. The rest is a sequence of
/// ops, each an op byte followed by a length-prefixed argument: a raw chunk of the stream (any
/// boundaries); a response to the ConnectionBind that is out, with fuzzed class, error code,
/// NONCE / REALM and MESSAGE-INTEGRITY, split in two reads at a fuzzed point and followed by
/// fuzzed bytes; advancing the clock; writing to the peer; closing.
///
/// Whatever the stream holds, nothing is delivered as the peer's data before the bind
/// succeeded, and after it every chunk comes out as it went in.
pub fn data_connection_handle_read(mut data: &[u8], start: Instant) {
    let Some((&config, rest)) = data.split_first() else {
        return;
    };
    data = rest;
    let Ok(provider) = crypto::fuzzing::deterministic_provider(37, false) else {
        return;
    };
    let realm = "fuzz-realm".to_owned();
    let key = if config & 0x01 != 0 {
        MessageIntegrity::long_term_integrity_key(
            USERNAME.to_owned(),
            realm.clone(),
            PASSWORD.to_owned(),
            provider.crypto(),
        )
        .unwrap_or_default()
    } else {
        vec![]
    };
    let local = SocketAddr::from(([10, 0, 0, 1], 5001));
    // The credential of the control connection: none, or the one a 401 with this realm and
    // nonce asked for.
    let mut credential = Credential::new(std::sync::Arc::new(Login {
        username: USERNAME.to_owned(),
        password: PASSWORD.to_owned(),
        password_algorithms: vec![],
    }));
    if !key.is_empty() {
        let mut challenge = Message::new();
        let built = challenge.build(&[
            Box::new(TransactionId::new()),
            Box::new(MessageType::new(
                METHOD_CONNECTION_BIND,
                CLASS_ERROR_RESPONSE,
            )),
            Box::new(ErrorCodeAttribute {
                code: stun::error_code::CODE_UNAUTHORIZED,
                reason: vec![],
            }),
            Box::new(TextAttribute::new(ATTR_NONCE, "fuzz-nonce".to_owned())),
            Box::new(TextAttribute::new(ATTR_REALM, realm.clone())),
        ]);
        let Ok(challenged) = built.map_err(|_| ()).and_then(|()| {
            credential
                .challenged(&Message::new(), &challenge, provider.crypto())
                .map_err(|_| ())
        }) else {
            return;
        };
        credential = challenged;
    }
    let Ok(mut connection) = DataConnection::new(
        start,
        DataConnectionConfig {
            crypto_provider: provider.clone(),
            server_addr: turn_server(),
            local_addr: local,
            connection_id: ConnectionId(u32::from(config)),
            software: TextAttribute::new(stun::attributes::ATTR_SOFTWARE, String::new()),
            credential: std::sync::Arc::new(credential),
        },
    ) else {
        return;
    };

    let mut now = start;
    // The id of the ConnectionBind that is out, read off what the connection sends.
    let mut bind_id = None;
    let mut ops = 0;
    loop {
        while let Some(out) = connection.poll_write() {
            assert_eq!(out.transport.peer_addr, turn_server());
            assert_eq!(out.transport.local_addr, local);
            if !connection.is_bound() && is_stun_message(&out.message) {
                let mut m = Message::new();
                m.raw = out.message.to_vec();
                if m.decode().is_ok() && m.typ.method == METHOD_CONNECTION_BIND {
                    bind_id = Some(m.transaction_id);
                }
            }
        }
        while connection.poll_event().is_some() {}
        let bound = connection.is_bound();
        while let Some(read) = connection.poll_read() {
            assert!(
                bound,
                "the peer's data was delivered before the bind succeeded"
            );
            assert!(!read.is_empty());
        }

        let Some((&op, rest)) = data.split_first() else {
            break;
        };
        data = rest;
        ops += 1;
        if ops > 256 {
            break;
        }
        let arg = take_arg(&mut data);
        let read = |connection: &mut DataConnection, now: Instant, bytes: &[u8]| {
            let _ = connection.handle_read(TaggedBytesMut {
                now,
                transport: TransportContext {
                    local_addr: local,
                    peer_addr: turn_server(),
                    transport_protocol: TransportProtocol::TCP,
                    ecn: None,
                },
                message: BytesMut::from(bytes),
            });
        };
        match op % 5 {
            0 => {
                let was_bound = connection.is_bound();
                read(&mut connection, now, arg);
                if was_bound && !arg.is_empty() {
                    // After the bind the stream is the peer's, byte for byte.
                    let got = connection.poll_read().expect("the chunk is delivered");
                    assert_eq!(&got[..], arg);
                }
            }
            1 => {
                let flags = byte(arg, 0);
                let class = if flags & 0x01 != 0 {
                    CLASS_ERROR_RESPONSE
                } else {
                    CLASS_SUCCESS_RESPONSE
                };
                let id = match bind_id {
                    Some(id) if flags & 0x02 == 0 => id,
                    _ => TransactionId([byte(arg, 1); 12]),
                };
                let mut setters: Vec<Box<dyn Setter>> = vec![
                    Box::new(id),
                    Box::new(MessageType::new(METHOD_CONNECTION_BIND, class)),
                ];
                if class == CLASS_ERROR_RESPONSE {
                    let code = match byte(arg, 1) & 0x03 {
                        0 => CODE_UNAUTHORIZED,
                        1 => CODE_STALE_NONCE,
                        _ => ErrorCode(u16::from(byte(arg, 1)) * 4),
                    };
                    setters.push(Box::new(ErrorCodeAttribute {
                        code,
                        reason: b"fuzz".to_vec(),
                    }));
                }
                if flags & 0x04 != 0 {
                    setters.push(Box::new(TextAttribute::new(
                        ATTR_NONCE,
                        String::from_utf8_lossy(arg.get(3..).unwrap_or(&[])).into_owned(),
                    )));
                }
                if flags & 0x08 != 0 {
                    setters.push(Box::new(TextAttribute::new(ATTR_REALM, realm.clone())));
                }
                if flags & 0x10 != 0 && !key.is_empty() {
                    setters.push(Box::new(MessageIntegrity::new_raw_integrity_with_provider(
                        key.clone(),
                        provider.crypto(),
                    )));
                }
                let mut m = Message::new();
                if m.build(&setters).is_ok() {
                    let mut stream = m.raw.clone();
                    if flags & 0x20 != 0 {
                        stream.extend_from_slice(arg.get(3..).unwrap_or(&[]));
                    }
                    let cut = usize::from(byte(arg, 2)) % (stream.len() + 1);
                    read(&mut connection, now, &stream[..cut]);
                    read(&mut connection, now, &stream[cut..]);
                }
            }
            2 => {
                now += Duration::from_millis(u64::from(byte(arg, 0)) * 250 + 1);
                let _ = connection.handle_timeout(now);
                let _ = connection.poll_timeout();
            }
            3 => {
                let was_bound = connection.is_bound();
                let sent = connection.send(now, arg);
                assert_eq!(sent.is_ok(), was_bound);
                if was_bound {
                    let out = connection.poll_write().expect("the bytes go out");
                    assert_eq!(&out.message[..], arg);
                }
            }
            _ => {
                let _ = connection.close();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The ops can drive an authenticated allocation to completion, so the relay paths are
    /// reachable.
    #[test]
    fn allocation_completes() {
        let start = Instant::now();
        let provider = crypto::fuzzing::deterministic_provider(31, false).unwrap();
        let client = Client::new(
            ClientConfig {
                stun_serv_addr: String::new(),
                turn_serv_addr: turn_server().to_string(),
                local_addr: SocketAddr::from(([10, 0, 0, 1], 5000)),
                transport_protocol: TransportProtocol::UDP,
                username: USERNAME.to_owned(),
                password: PASSWORD.to_owned(),
                realm: String::new(),
                software: String::new(),
                rto_in_ms: 100,
                allocation_refresh_interval_cap: None,
                ..Default::default()
            },
            provider,
        )
        .unwrap();
        let mut h = Harness {
            client,
            now: start,
            requests: VecDeque::new(),
            relays: Vec::new(),
            channels: Vec::new(),
        };
        h.client.allocate(start).unwrap();
        h.drain();
        // 401 with NONCE and REALM, then a signed success with a relayed address and a
        // lifetime.
        h.response(&[0x01 | 0x08 | 0x10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, b'n']);
        h.response(&[
            0x02 | 0x04 | 0x20,
            1,
            192,
            0,
            2,
            99,
            0x13,
            0x88,
            0,
            2,
            0x58,
            0,
        ]);
        assert_eq!(h.relays.len(), 1, "allocation did not complete");
    }
}
