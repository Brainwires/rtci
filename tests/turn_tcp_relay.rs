//! Relayed TCP candidates run by the engine (RFC 6544 section 5.5 over TURN-TCP, RFC 6062):
//! for a `turn:...?transport=tcp` server the engine asks for a TCP allocation on a control
//! connection of its own, announces the relayed address as a passive and an active TCP
//! candidate, accepts a peer's connection from the server's ConnectionAttempt and opens one
//! with Connect for a check from the active candidate, each over a data connection bound with
//! ConnectionBind that then carries the peer's RFC 4571 stream to ICE. The TURN server is
//! scripted by the test, behind the stream interface.

use anyhow::Result;
use rtc::ice::attributes::control::AttrControlled;
use rtc::ice::attributes::priority::PriorityAttr;
use rtc::peer_connection::configuration::setting_engine::SettingEngineBuilder;
use rtc::peer_connection::configuration::{RTCConfigurationBuilder, RTCIceServer};
use rtc::peer_connection::event::RTCPeerConnectionEvent;
use rtc::peer_connection::transport::RTCIceCandidateInit;
use rtc::peer_connection::{RTCPeerConnection, RTCPeerConnectionBuilder};
use rtc::sansio::Protocol;
use rtc::shared::stream::{Framing, StreamCommand, StreamEvent, StreamId};
use rtc::stun::attributes::{ATTR_MESSAGE_INTEGRITY, ATTR_NONCE, ATTR_REALM, ATTR_USERNAME};
use rtc::stun::error_code::{CODE_UNAUTHORIZED, ErrorCodeAttribute};
use rtc::stun::fingerprint::FINGERPRINT;
use rtc::stun::integrity::MessageIntegrity;
use rtc::stun::message::{
    BINDING_REQUEST, BINDING_SUCCESS, CLASS_ERROR_RESPONSE, CLASS_INDICATION, CLASS_REQUEST,
    CLASS_SUCCESS_RESPONSE, Getter, METHOD_ALLOCATE, METHOD_CONNECT, METHOD_CONNECTION_ATTEMPT,
    METHOD_CONNECTION_BIND, Message, MessageType, Setter, TransactionId,
};
use rtc::stun::textattrs::{Nonce, Realm, Username};
use rtc::stun::xoraddr::XorMappedAddress;
use rtc::turn::proto::connid::ConnectionId;
use rtc::turn::proto::lifetime::Lifetime;
use rtc::turn::proto::peeraddr::PeerAddress;
use rtc::turn::proto::relayaddr::RelayedAddress;
use rtc::turn::proto::reqtrans::RequestedTransport;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

mod common;

const SERVER: &str = "192.0.2.40:3478";
const UDP_RELAY: &str = "192.0.2.40:50000";
const TCP_RELAY: &str = "192.0.2.40:50001";
const USER: &str = "user";
const PASS: &str = "pass";
const REALM: &str = "rtc.test";

fn a(s: &str) -> SocketAddr {
    s.parse().unwrap()
}

/// What a connection to the scripted server is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Role {
    /// A control connection; `Some(true)` once it asked for a TCP allocation.
    Control(Option<bool>),
    /// A data connection, bound or not.
    Data { bound: bool },
}

struct Harness {
    pc: RTCPeerConnection,
    now: Instant,
    key: Vec<u8>,
    next_port: u16,
    roles: HashMap<StreamId, Role>,
    /// Requests the server read, with the connection they came on.
    requests: Vec<(StreamId, Message)>,
    /// What a bound data connection carried from the engine (the peer's side of the stream).
    to_peer: HashMap<StreamId, Vec<u8>>,
    events: Vec<RTCPeerConnectionEvent>,
    /// The CONNECTION-ID the next Connect success names.
    next_connection_id: u32,
    local_ufrag: String,
    local_pwd: String,
    remote_ufrag: String,
    remote_pwd: String,
    /// Connections the engine closed or reset.
    closed: Vec<StreamId>,
}

fn sdp_attribute(sdp: &str, name: &str) -> String {
    let prefix = format!("a={name}:");
    sdp.lines()
        .find_map(|l| l.strip_prefix(prefix.as_str()))
        .unwrap_or_else(|| panic!("no {name}"))
        .trim()
        .to_owned()
}

impl Harness {
    /// The engine with the TURN-over-TCP server, its offer answered by a second peer
    /// connection (so remote candidates can be added).
    fn new() -> Result<Self> {
        Self::with(SettingEngineBuilder::new())
    }

    /// The same, with `settings` (TCP candidates not gathered).
    fn with(settings: SettingEngineBuilder) -> Result<Self> {
        common::install_crypto_provider();
        let now = Instant::now();
        let mut pc = RTCPeerConnectionBuilder::new()
            .with_configuration(
                RTCConfigurationBuilder::new()
                    .with_ice_servers(vec![RTCIceServer {
                        urls: vec![format!("turn:{SERVER}?transport=tcp")],
                        username: USER.to_owned(),
                        credential: PASS.to_owned(),
                    }])
                    .build(),
            )
            .with_setting_engine(settings.with_tcp_candidate_gathering(false).build())
            .build(now)?;
        pc.create_data_channel("tcp-relay", None)?;
        let offer = pc.create_offer(None)?;
        pc.set_local_description(now, offer.clone())?;
        let mut answerer = RTCPeerConnectionBuilder::new().build(now)?;
        answerer.set_remote_description(now, offer.clone())?;
        let answer = answerer.create_answer(None)?;
        answerer.set_local_description(now, answer.clone())?;
        pc.set_remote_description(now, answer.clone())?;
        let provider = rtc::crypto::default_provider()?;
        let key = MessageIntegrity::long_term_integrity_key(
            USER.to_owned(),
            REALM.to_owned(),
            PASS.to_owned(),
            provider.crypto(),
        )?;
        let mut h = Self {
            pc,
            now,
            key,
            next_port: 60000,
            roles: HashMap::new(),
            requests: vec![],
            to_peer: HashMap::new(),
            events: vec![],
            next_connection_id: 7,
            local_ufrag: sdp_attribute(&offer.sdp, "ice-ufrag"),
            local_pwd: sdp_attribute(&offer.sdp, "ice-pwd"),
            remote_ufrag: sdp_attribute(&answer.sdp, "ice-ufrag"),
            remote_pwd: sdp_attribute(&answer.sdp, "ice-pwd"),
            closed: vec![],
        };
        h.pump()?;
        Ok(h)
    }

    fn reply(
        &self,
        request: &Message,
        class: rtc::stun::message::MessageClass,
        attrs: Vec<Box<dyn Setter>>,
        sign: bool,
    ) -> Result<Vec<u8>> {
        let provider = rtc::crypto::default_provider()?;
        let mut setters: Vec<Box<dyn Setter>> = vec![
            Box::new(request.transaction_id),
            Box::new(MessageType::new(request.typ.method, class)),
        ];
        setters.extend(attrs);
        if sign {
            setters.push(Box::new(MessageIntegrity::new_raw_integrity_with_provider(
                self.key.clone(),
                provider.crypto(),
            )));
        }
        setters.push(Box::new(FINGERPRINT));
        let mut m = Message::new();
        m.build(&setters)?;
        Ok(m.raw)
    }

    /// The scripted server's answer to a request on `id`.
    fn answer(&mut self, id: StreamId, request: &Message) -> Result<Option<Vec<u8>>> {
        if request.typ.class != CLASS_REQUEST {
            return Ok(None);
        }
        if !request.contains(ATTR_MESSAGE_INTEGRITY) {
            return self
                .reply(
                    request,
                    CLASS_ERROR_RESPONSE,
                    vec![
                        Box::new(ErrorCodeAttribute {
                            code: CODE_UNAUTHORIZED,
                            reason: b"Unauthorized".to_vec(),
                        }),
                        Box::new(Nonce::new(ATTR_NONCE, "nonce".to_owned())),
                        Box::new(Realm::new(ATTR_REALM, REALM.to_owned())),
                    ],
                    false,
                )
                .map(Some);
        }
        let attrs: Vec<Box<dyn Setter>> = match request.typ.method {
            METHOD_ALLOCATE => {
                let mut transport = RequestedTransport::default();
                transport.get_from(request)?;
                let tcp = transport.protocol == rtc::turn::proto::PROTO_TCP;
                self.roles.insert(id, Role::Control(Some(tcp)));
                let relay = a(if tcp { TCP_RELAY } else { UDP_RELAY });
                vec![
                    Box::new(RelayedAddress {
                        ip: relay.ip(),
                        port: relay.port(),
                    }),
                    Box::new(XorMappedAddress {
                        ip: a("203.0.113.9:40000").ip(),
                        port: 40000,
                    }),
                    Box::new(Lifetime(Duration::from_secs(600))),
                ]
            }
            METHOD_CONNECT => {
                let connection_id = self.next_connection_id;
                self.next_connection_id += 1;
                vec![Box::new(ConnectionId(connection_id))]
            }
            METHOD_CONNECTION_BIND => {
                self.roles.insert(id, Role::Data { bound: true });
                vec![]
            }
            _ => vec![],
        };
        self.reply(request, CLASS_SUCCESS_RESPONSE, attrs, true)
            .map(Some)
    }

    /// Serves the stream interface and the scripted server until nothing moves.
    fn pump(&mut self) -> Result<()> {
        loop {
            let mut moved = false;
            while let Some(e) = self.pc.poll_event() {
                self.events.push(e);
                moved = true;
            }
            while self.pc.poll_write().is_some() {
                moved = true;
            }
            let mut commands = vec![];
            while let Some(c) = self.pc.poll_stream_command() {
                commands.push(c);
            }
            for c in commands {
                moved = true;
                if let StreamCommand::Close { id } | StreamCommand::Reset { id } = c {
                    self.closed.push(id);
                }
                if let StreamCommand::Connect { id, remote, .. } = c {
                    assert_eq!(remote, a(SERVER), "only the TURN server is connected to");
                    let role = if self.roles.values().any(|r| matches!(r, Role::Control(_)))
                        && self.roles.len() >= 2
                    {
                        Role::Data { bound: false }
                    } else {
                        Role::Control(None)
                    };
                    self.roles.insert(id, role);
                    let local = SocketAddr::new(a("10.0.0.1:0").ip(), self.next_port);
                    self.next_port += 1;
                    self.pc
                        .handle_stream_event(self.now, StreamEvent::Connected { id, local })?;
                }
            }
            let mut transmits = vec![];
            while let Some(t) = self.pc.poll_stream_transmit() {
                transmits.push(t);
            }
            for t in transmits {
                moved = true;
                self.pc.handle_stream_event(
                    self.now,
                    StreamEvent::Written {
                        id: t.id,
                        bytes: t.data.len(),
                    },
                )?;
                match self.roles.get(&t.id).copied() {
                    Some(Role::Data { bound: true }) => {
                        self.to_peer.entry(t.id).or_default().extend(t.data);
                    }
                    Some(_) => {
                        let mut at = 0;
                        while at + 20 <= t.data.len() {
                            let len = u16::from_be_bytes([t.data[at + 2], t.data[at + 3]]) as usize;
                            let mut m = Message::new();
                            m.unmarshal_binary(&t.data[at..at + 20 + len])?;
                            at += 20 + len;
                            self.requests.push((t.id, m.clone()));
                            if let Some(reply) = self.answer(t.id, &m)? {
                                self.pc.handle_stream_read(self.now, t.id, &reply)?;
                            }
                        }
                    }
                    None => panic!("a transmit on an unknown connection"),
                }
            }
            if !moved {
                return Ok(());
            }
        }
    }

    fn control(&self, tcp: bool) -> StreamId {
        *self
            .roles
            .iter()
            .find(|(_, r)| **r == Role::Control(Some(tcp)))
            .expect("the control connection")
            .0
    }

    fn data_connections(&self) -> Vec<StreamId> {
        let mut ids: Vec<StreamId> = self
            .roles
            .iter()
            .filter(|(_, r)| matches!(r, Role::Data { .. }))
            .map(|(id, _)| *id)
            .collect();
        ids.sort_by_key(|id| id.0);
        ids
    }

    fn candidates(&self) -> Vec<String> {
        self.events
            .iter()
            .filter_map(|e| match e {
                RTCPeerConnectionEvent::OnIceCandidateEvent(ev) => ev
                    .candidate
                    .as_ref()
                    .and_then(|c| c.to_json().ok())
                    .map(|i| i.candidate),
                _ => None,
            })
            .collect()
    }

    fn requests_of(&self, method: rtc::stun::message::Method) -> Vec<(StreamId, Message)> {
        self.requests
            .iter()
            .filter(|(_, m)| m.typ.method == method && m.typ.class == CLASS_REQUEST)
            .cloned()
            .collect()
    }

    /// A check from the peer at the engine's candidate, as the controlled agent sends it.
    fn check(&self) -> Result<Vec<u8>> {
        let provider = rtc::crypto::default_provider()?;
        let mut m = Message::new();
        m.build(&[
            Box::new(BINDING_REQUEST),
            Box::new(TransactionId::new()),
            Box::new(Username::new(
                ATTR_USERNAME,
                format!("{}:{}", self.local_ufrag, self.remote_ufrag),
            )),
            Box::new(AttrControlled(1)),
            Box::new(PriorityAttr(1_845_501_695)),
            Box::new(MessageIntegrity::new_short_term_integrity_with_provider(
                self.local_pwd.clone(),
                provider.crypto(),
            )),
            Box::new(FINGERPRINT),
        ])?;
        Ok(m.raw)
    }
}

fn no_peer() -> PeerAddress {
    PeerAddress {
        ip: std::net::Ipv4Addr::UNSPECIFIED.into(),
        port: 0,
    }
}

/// The STUN messages an RFC 4571 stream carries.
fn framed_stun(bytes: &[u8]) -> Vec<Message> {
    let mut decoder = rtc::shared::stream::StreamDecoder::new(Framing::Rfc4571);
    decoder
        .decode(bytes)
        .unwrap()
        .into_iter()
        .filter_map(|frame| {
            let mut m = Message::new();
            m.unmarshal_binary(&frame).ok().map(|_| m)
        })
        .collect()
}

/// RFC 6062 section 4.1 with RFC 6544 section 5.5: beside the UDP allocation the engine asks
/// for a TCP allocation (REQUESTED-TRANSPORT TCP), on a control connection of its own, and
/// announces its relayed address as a passive TCP candidate and on port 9 as an active one,
/// related to the control connection's local address.
#[test]
fn a_tcp_allocation_gives_a_passive_and_an_active_relayed_tcp_candidate() -> Result<()> {
    let h = Harness::new()?;
    let allocates = h.requests_of(METHOD_ALLOCATE);
    let tcp = h.control(true);
    let udp = h.control(false);
    assert_ne!(tcp, udp, "two control connections");
    for (id, m) in &allocates {
        let mut transport = RequestedTransport::default();
        transport.get_from(m)?;
        let expected = if *id == tcp {
            rtc::turn::proto::PROTO_TCP
        } else {
            rtc::turn::proto::PROTO_UDP
        };
        assert_eq!(transport.protocol, expected);
    }
    let candidates = h.candidates();
    let relayed: Vec<&String> = candidates
        .iter()
        .filter(|c| c.contains("typ relay"))
        .collect();
    assert!(
        relayed.iter().any(|c| c.contains(" tcp ")
            && c.contains("192.0.2.40 50001 typ relay")
            && c.contains("tcptype passive")),
        "{relayed:?}"
    );
    assert!(
        relayed.iter().any(|c| c.contains(" tcp ")
            && c.contains("192.0.2.40 9 typ relay")
            && c.contains("tcptype active")),
        "{relayed:?}"
    );
    assert!(
        relayed
            .iter()
            .any(|c| c.contains(" udp ") && c.contains("192.0.2.40 50000 typ relay")),
        "the UDP allocation's too: {relayed:?}"
    );
    Ok(())
}

/// RFC 6062 sections 4.4 and 4.5 with RFC 6544 section 5.5: the engine creates a permission
/// for a remote TCP candidate's address (the server accepts a peer only with one); a peer's
/// connection to the relayed address, announced by ConnectionAttempt, gets a data connection
/// bound with its CONNECTION-ID; the peer's RFC 4571 frames reach ICE on the passive relayed
/// candidate and the agent's answer goes back over the data connection.
#[test]
fn a_peer_connecting_to_the_relayed_address_reaches_ice_over_a_data_connection() -> Result<()> {
    let mut h = Harness::new()?;
    let peer = a("198.51.100.7:45000");
    h.pc.add_remote_candidate(RTCIceCandidateInit {
        candidate: format!(
            "candidate:1 1 tcp 1518280447 {} 9 typ host tcptype active",
            peer.ip()
        ),
        sdp_mid: Some("0".to_owned()),
        ..Default::default()
    })?;
    h.pump()?;
    let tcp = h.control(true);
    let permission: Vec<Message> = h
        .requests_of(rtc::stun::message::METHOD_CREATE_PERMISSION)
        .into_iter()
        .filter(|(id, _)| *id == tcp)
        .map(|(_, m)| m)
        .collect();
    assert!(
        permission.iter().any(|m| {
            let mut p = no_peer();
            p.get_from(m).is_ok() && p.ip == peer.ip()
        }),
        "a permission for the remote candidate's address on the TCP allocation"
    );

    let mut indication = Message::new();
    indication.build(&[
        Box::new(MessageType::new(
            METHOD_CONNECTION_ATTEMPT,
            CLASS_INDICATION,
        )),
        Box::new(TransactionId::new()),
        Box::new(ConnectionId(42)),
        Box::new(PeerAddress {
            ip: peer.ip(),
            port: peer.port(),
        }),
    ])?;
    h.pc.handle_stream_read(h.now, tcp, &indication.raw)?;
    h.pump()?;
    let data = h.data_connections();
    assert_eq!(data.len(), 1, "a data connection to the server");
    let bind = h.requests_of(METHOD_CONNECTION_BIND);
    assert_eq!(bind.len(), 1);
    let mut cid = ConnectionId::default();
    cid.get_from(&bind[0].1)?;
    assert_eq!(cid.0, 42, "bound with the attempt's CONNECTION-ID");

    // The peer's check, framed as on any ICE-TCP connection, after the bind response.
    let check = h.check()?;
    let framed = Framing::Rfc4571.encode(&check)?;
    h.pc.handle_stream_read(h.now, data[0], &framed)?;
    h.pump()?;
    let answers = framed_stun(h.to_peer.get(&data[0]).map_or(&[][..], |v| &v[..]));
    assert!(
        answers.iter().any(|m| m.typ == BINDING_SUCCESS),
        "the agent answers over the data connection: {answers:?}"
    );
    Ok(())
}

/// RFC 6062 section 4.3 with RFC 6544 section 5.5: a check from the active relayed candidate
/// to a remote passive candidate makes the engine create a permission and send Connect on the
/// TCP allocation's control connection; the CONNECTION-ID of its success binds a new data
/// connection, which then carries the check, framed with RFC 4571.
/// The SOFTWARE of the engine's TURN client over TCP (RFC 8656 section 5, RFC 8489 section
/// 16.1.2: "Implementers SHOULD make usage of the SOFTWARE attribute a configurable option"),
/// in the Allocate requests of both control connections, the CreatePermission and the
/// ConnectionBind of a data connection (RFC 6062 section 4.3): `rtc-turn` and its version by
/// default, the text `with_ice_software` names, none with `with_ice_software(None)`.
#[test]
fn the_engine_tcp_turn_client_sends_the_software_with_ice_software_names() -> Result<()> {
    use rtc::stun::attributes::ATTR_SOFTWARE;
    use rtc::stun::textattrs::Software;
    for (setting, expected) in [
        (None, Some(rtc::turn::client::DEFAULT_SOFTWARE.to_owned())),
        (Some(None), None),
        (Some(Some("app 1.0".to_owned())), Some("app 1.0".to_owned())),
    ] {
        let mut settings = SettingEngineBuilder::new();
        if let Some(software) = setting.clone() {
            settings = settings.with_ice_software(software);
        }
        let mut h = Harness::with(settings)?;
        let peer = a("198.51.100.7:45000");
        h.pc.add_remote_candidate(RTCIceCandidateInit {
            candidate: format!(
                "candidate:1 1 tcp 1518280447 {} 9 typ host tcptype active",
                peer.ip()
            ),
            sdp_mid: Some("0".to_owned()),
            ..Default::default()
        })?;
        h.pump()?;
        let tcp = h.control(true);
        let mut indication = Message::new();
        indication.build(&[
            Box::new(MessageType::new(
                METHOD_CONNECTION_ATTEMPT,
                CLASS_INDICATION,
            )),
            Box::new(TransactionId::new()),
            Box::new(ConnectionId(42)),
            Box::new(PeerAddress {
                ip: peer.ip(),
                port: peer.port(),
            }),
        ])?;
        h.pc.handle_stream_read(h.now, tcp, &indication.raw)?;
        h.pump()?;
        for method in [
            METHOD_ALLOCATE,
            rtc::stun::message::METHOD_CREATE_PERMISSION,
            METHOD_CONNECTION_BIND,
        ] {
            assert!(!h.requests_of(method).is_empty(), "{setting:?}: a {method}");
        }
        for (_, m) in &h.requests {
            let software = Software::get_from_as(m, ATTR_SOFTWARE)
                .ok()
                .map(|software| software.text);
            assert_eq!(software, expected, "{setting:?}: {}", m.typ);
        }
    }
    Ok(())
}

#[test]
fn a_check_from_the_active_relayed_candidate_connects_through_the_server() -> Result<()> {
    let mut h = Harness::new()?;
    let peer = a("198.51.100.8:5000");
    h.pc.add_remote_candidate(RTCIceCandidateInit {
        candidate: format!(
            "candidate:1 1 tcp 1518280447 {} {} typ host tcptype passive",
            peer.ip(),
            peer.port()
        ),
        sdp_mid: Some("0".to_owned()),
        ..Default::default()
    })?;
    let until = h.now + Duration::from_secs(5);
    while h.requests_of(METHOD_CONNECT).is_empty() && h.now < until {
        h.now += Duration::from_millis(20);
        h.pc.handle_timeout(h.now)?;
        h.pump()?;
    }
    let connects = h.requests_of(METHOD_CONNECT);
    assert_eq!(connects.len(), 1, "one Connect for the peer");
    assert_eq!(connects[0].0, h.control(true), "on the TCP allocation");
    let mut p = no_peer();
    p.get_from(&connects[0].1)?;
    assert_eq!(SocketAddr::new(p.ip, p.port), peer);
    let data = h.data_connections();
    assert_eq!(data.len(), 1, "a data connection for the CONNECTION-ID");
    let carried = framed_stun(h.to_peer.get(&data[0]).map_or(&[][..], |v| &v[..]));
    assert!(
        carried.iter().any(|m| m.typ == BINDING_REQUEST),
        "the check goes out on it once bound: {carried:?}"
    );
    Ok(())
}

/// The peer answers every check the engine sent on data connection `id` that it has not
/// answered yet, as the remote agent would (signed with its password).
fn answer_checks(
    h: &mut Harness,
    id: StreamId,
    peer: SocketAddr,
    answered: &mut Vec<TransactionId>,
) -> Result<()> {
    let provider = rtc::crypto::default_provider()?;
    let requests = framed_stun(h.to_peer.get(&id).map_or(&[][..], |v| &v[..]));
    for request in requests.into_iter().filter(|m| m.typ == BINDING_REQUEST) {
        if answered.contains(&request.transaction_id) {
            continue;
        }
        answered.push(request.transaction_id);
        let mut m = Message::new();
        m.build(&[
            Box::new(request.transaction_id),
            Box::new(BINDING_SUCCESS),
            Box::new(XorMappedAddress {
                ip: a(TCP_RELAY).ip(),
                port: a(TCP_RELAY).port(),
            }),
            Box::new(MessageIntegrity::new_short_term_integrity_with_provider(
                h.remote_pwd.clone(),
                provider.crypto(),
            )),
            Box::new(FINGERPRINT),
        ])?;
        let _ = peer;
        let framed = Framing::Rfc4571.encode(&m.raw)?;
        h.pc.handle_stream_read(h.now, id, &framed)?;
    }
    Ok(())
}

/// RFC 6544 section 11.2: once ICE has completed on the passive relayed TCP candidate, the
/// connection to the TURN server whose relayed candidate was selected "MUST be kept open"
/// (the TCP allocation's control and data connections), and the other one (the UDP
/// allocation's, not selected) "SHOULD be closed". When the kept control connection is then
/// lost during the session, the engine reconnects for a new allocation and restarts ICE
/// ("SHOULD reconnect to the TURN server, obtain a new allocation, and restart ICE").
#[test]
fn turn_connections_follow_the_selected_pair_and_a_lost_one_is_reallocated() -> Result<()> {
    let mut h = Harness::new()?;
    let peer = a("198.51.100.7:45000");
    h.pc.add_remote_candidate(RTCIceCandidateInit {
        candidate: format!(
            "candidate:1 1 tcp 1518280447 {} 9 typ host tcptype active",
            peer.ip()
        ),
        sdp_mid: Some("0".to_owned()),
        ..Default::default()
    })?;
    h.pump()?;
    let tcp = h.control(true);
    let udp = h.control(false);
    let mut indication = Message::new();
    indication.build(&[
        Box::new(MessageType::new(
            METHOD_CONNECTION_ATTEMPT,
            CLASS_INDICATION,
        )),
        Box::new(TransactionId::new()),
        Box::new(ConnectionId(42)),
        Box::new(PeerAddress {
            ip: peer.ip(),
            port: peer.port(),
        }),
    ])?;
    h.pc.handle_stream_read(h.now, tcp, &indication.raw)?;
    h.pump()?;
    let data = h.data_connections()[0];
    let check = h.check()?;
    h.pc.handle_stream_read(h.now, data, &Framing::Rfc4571.encode(&check)?)?;
    h.pump()?;
    let mut answered = vec![];
    let until = h.now + Duration::from_secs(10);
    let selected = |h: &Harness| {
        h.events.iter().any(|e| {
            matches!(
                e,
                RTCPeerConnectionEvent::OnIceConnectionStateChangeEvent(
                    rtc::peer_connection::state::RTCIceConnectionState::Connected
                        | rtc::peer_connection::state::RTCIceConnectionState::Completed
                )
            )
        })
    };
    while !selected(&h) && h.now < until {
        answer_checks(&mut h, data, peer, &mut answered)?;
        h.now += Duration::from_millis(20);
        h.pc.handle_timeout(h.now)?;
        h.pump()?;
    }
    assert!(selected(&h), "ICE connected on the relayed TCP candidate");
    h.pump()?;
    assert!(
        h.closed.contains(&udp),
        "the UDP allocation's connection is closed once ICE has completed"
    );
    assert!(
        !h.closed.contains(&tcp) && !h.closed.contains(&data),
        "the selected candidate's connections stay open"
    );

    // The control connection is lost: a new one, a new allocation, and ICE restarts.
    let connects_before = h.roles.len();
    h.pc.handle_stream_event(h.now, StreamEvent::Closed { id: tcp })?;
    h.pump()?;
    assert!(
        h.roles.len() > connects_before,
        "a new connection to the TURN server"
    );
    assert!(
        h.events
            .iter()
            .any(|e| matches!(e, RTCPeerConnectionEvent::OnNegotiationNeededEvent)),
        "ICE is restarted (restartIce: negotiation needed)"
    );
    Ok(())
}
