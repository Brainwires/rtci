//! RFC 5928 section 3 and RFC 8656 section 7.4 for the engine's TURN servers: a refused
//! Allocate ends that server's part of the resolution; a 300 (Try Alternate) is followed to the
//! ALTERNATE-SERVER; a server answering 486 or 508 is not used for a minute, even by a later
//! resolution; and once every allocation failed, a new ICE generation runs the resolution again
//! from the beginning. The TURN server is scripted by the test, behind the stream interface.

use anyhow::Result;
use rtci::peer_connection::configuration::setting_engine::SettingEngineBuilder;
use rtci::peer_connection::configuration::{RTCConfigurationBuilder, RTCIceServer};
use rtci::peer_connection::event::RTCPeerConnectionEvent;
use rtci::peer_connection::{RTCPeerConnection, RTCPeerConnectionBuilder};
use rtci::sansio::Protocol;
use rtci::shared::stream::{StreamCommand, StreamEvent, StreamId};
use rtci::stun::addr::MappedAddress;
use rtci::stun::attributes::{
    ATTR_ALTERNATE_SERVER, ATTR_MESSAGE_INTEGRITY, ATTR_NONCE, ATTR_REALM,
};
use rtci::stun::error_code::{CODE_UNAUTHORIZED, ErrorCode, ErrorCodeAttribute};
use rtci::stun::fingerprint::FINGERPRINT;
use rtci::stun::integrity::MessageIntegrity;
use rtci::stun::message::{
    CLASS_ERROR_RESPONSE, CLASS_REQUEST, CLASS_SUCCESS_RESPONSE, METHOD_ALLOCATE, Message,
    MessageType, Setter,
};
use rtci::stun::textattrs::{Nonce, Realm};
use rtci::stun::xoraddr::XorMappedAddress;
use rtci::turn::proto::lifetime::Lifetime;
use rtci::turn::proto::relayaddr::RelayedAddress;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

mod common;

const SERVER: &str = "192.0.2.40:3478";
const ALTERNATE: &str = "192.0.2.41:3478";
const USER: &str = "user";
const PASS: &str = "pass";
const REALM: &str = "rtc.test";

fn a(s: &str) -> SocketAddr {
    s.parse().unwrap()
}

struct Harness {
    pc: RTCPeerConnection,
    answerer: RTCPeerConnection,
    now: Instant,
    key: Vec<u8>,
    next_port: u16,
    /// The server each connection went to.
    remotes: HashMap<StreamId, SocketAddr>,
    /// Every Connect, in order.
    connects: Vec<SocketAddr>,
    /// How a server answers a signed Allocate: an error code and an ALTERNATE-SERVER.
    refuse: HashMap<SocketAddr, (u16, Option<SocketAddr>)>,
    events: Vec<RTCPeerConnectionEvent>,
}

impl Harness {
    fn new(refuse: &[(SocketAddr, u16, Option<SocketAddr>)]) -> Result<Self> {
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
            .with_setting_engine(
                SettingEngineBuilder::new()
                    .with_tcp_candidate_gathering(false)
                    .with_turn_tcp_relay(false)
                    .build(),
            )
            .build(now)?;
        pc.create_data_channel("resolution", None)?;
        let answerer = RTCPeerConnectionBuilder::new().build(now)?;
        let provider = rtci::crypto::default_provider()?;
        let key = MessageIntegrity::long_term_integrity_key(
            USER.to_owned(),
            REALM.to_owned(),
            PASS.to_owned(),
            provider.crypto(),
        )?;
        let mut h = Self {
            pc,
            answerer,
            now,
            key,
            next_port: 60000,
            remotes: HashMap::new(),
            connects: vec![],
            refuse: refuse.iter().map(|(s, c, alt)| (*s, (*c, *alt))).collect(),
            events: vec![],
        };
        h.negotiate()?;
        Ok(h)
    }

    /// One offer / answer exchange; with `restart_ice` first, a new ICE generation.
    fn negotiate(&mut self) -> Result<()> {
        let offer = self.pc.create_offer(None)?;
        self.pc.set_local_description(self.now, offer.clone())?;
        self.answerer.set_remote_description(self.now, offer)?;
        let answer = self.answerer.create_answer(None)?;
        self.answerer
            .set_local_description(self.now, answer.clone())?;
        self.pc.set_remote_description(self.now, answer)?;
        self.pump()
    }

    fn restart(&mut self) -> Result<()> {
        self.pc.restart_ice();
        self.negotiate()
    }

    fn reply(
        &self,
        request: &Message,
        class: rtci::stun::message::MessageClass,
        attrs: Vec<Box<dyn Setter>>,
        sign: bool,
    ) -> Result<Vec<u8>> {
        let provider = rtci::crypto::default_provider()?;
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

    fn answer(&self, server: SocketAddr, request: &Message) -> Result<Option<Vec<u8>>> {
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
        if request.typ.method == METHOD_ALLOCATE
            && let Some((code, alternate)) = self.refuse.get(&server)
        {
            let mut attrs: Vec<Box<dyn Setter>> = vec![Box::new(ErrorCodeAttribute {
                code: ErrorCode(*code),
                reason: b"refused".to_vec(),
            })];
            if let Some(alt) = alternate {
                attrs.push(Box::new(AlternateServer(MappedAddress {
                    ip: alt.ip(),
                    port: alt.port(),
                })));
            }
            return self
                .reply(request, CLASS_ERROR_RESPONSE, attrs, true)
                .map(Some);
        }
        let attrs: Vec<Box<dyn Setter>> = if request.typ.method == METHOD_ALLOCATE {
            vec![
                Box::new(RelayedAddress {
                    ip: server.ip(),
                    port: 50000,
                }),
                Box::new(XorMappedAddress {
                    ip: a("203.0.113.9:40000").ip(),
                    port: 40000,
                }),
                Box::new(Lifetime(Duration::from_secs(600))),
            ]
        } else {
            vec![]
        };
        self.reply(request, CLASS_SUCCESS_RESPONSE, attrs, true)
            .map(Some)
    }

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
                if let StreamCommand::Connect { id, remote, .. } = c {
                    self.remotes.insert(id, remote);
                    self.connects.push(remote);
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
                let server = self.remotes[&t.id];
                let mut at = 0;
                while at + 20 <= t.data.len() {
                    let len = u16::from_be_bytes([t.data[at + 2], t.data[at + 3]]) as usize;
                    let mut m = Message::new();
                    m.unmarshal_binary(&t.data[at..at + 20 + len])?;
                    at += 20 + len;
                    if let Some(reply) = self.answer(server, &m)? {
                        let _ = self.pc.handle_stream_read(self.now, t.id, &reply);
                    }
                }
            }
            if !moved {
                return Ok(());
            }
        }
    }

    fn advance(&mut self, by: Duration) -> Result<()> {
        let until = self.now + by;
        while self.now < until {
            self.now = (self.now + Duration::from_millis(500)).min(until);
            self.pc.handle_timeout(self.now)?;
            self.pump()?;
        }
        Ok(())
    }

    fn relayed(&self) -> Vec<String> {
        self.events
            .iter()
            .filter_map(|e| match e {
                RTCPeerConnectionEvent::OnIceCandidateEvent(ev) => ev
                    .candidate
                    .as_ref()
                    .and_then(|c| c.to_json().ok())
                    .map(|i| i.candidate)
                    .filter(|c| c.contains("typ relay")),
                _ => None,
            })
            .collect()
    }

    fn connects_to(&self, server: &str) -> usize {
        self.connects.iter().filter(|c| **c == a(server)).count()
    }
}

/// ALTERNATE-SERVER, written as a MAPPED-ADDRESS of its own type.
struct AlternateServer(MappedAddress);

impl Setter for AlternateServer {
    fn add_to(&self, m: &mut Message) -> rtci::shared::error::Result<()> {
        self.0.add_to_as(m, ATTR_ALTERNATE_SERVER)
    }
}

/// RFC 8656 section 7.4 (300, Try Alternate): the client "SHOULD try the Allocate request
/// with the alternate server before trying any other servers"; the engine connects to the
/// ALTERNATE-SERVER and allocates there (the RFC 8155 anycast procedure relies on it).
#[test]
fn a_300_is_followed_to_the_alternate_server() -> Result<()> {
    let h = Harness::new(&[(a(SERVER), 300, Some(a(ALTERNATE)))])?;
    assert_eq!(h.connects_to(SERVER), 1);
    assert_eq!(h.connects_to(ALTERNATE), 1, "{:?}", h.connects);
    assert!(
        h.relayed()
            .iter()
            .any(|c| c.contains("192.0.2.41 50000 typ relay")),
        "allocated on the alternate: {:?}",
        h.relayed()
    );
    Ok(())
}

/// RFC 5928 section 3: "After an allocation succeeds or all the allocations fail, the
/// resolution context MUST be discarded, and the resolution algorithm MUST be restarted from
/// the beginning for any subsequent allocation." A server refusing with 403 fails the link;
/// the next ICE generation runs it again from the start.
#[test]
fn after_every_allocation_failed_a_new_ice_generation_resolves_again() -> Result<()> {
    let mut h = Harness::new(&[(a(SERVER), 403, None)])?;
    assert_eq!(h.connects_to(SERVER), 1);
    assert!(h.relayed().is_empty());
    h.advance(Duration::from_secs(1))?;
    assert_eq!(h.connects_to(SERVER), 1, "not again within the generation");
    h.restart()?;
    assert_eq!(h.connects_to(SERVER), 2, "the new generation starts over");
    Ok(())
}

/// RFC 5928 section 3 with RFC 8656 section 7.4: a server that answered 508 (Insufficient
/// Capacity) "MUST NOT be used for the specified duration, even if returned by a subsequent
/// resolution": a minute (486 alike, 437 two minutes).
#[test]
fn a_server_answering_508_is_not_used_for_a_minute_even_by_a_new_resolution() -> Result<()> {
    let mut h = Harness::new(&[(a(SERVER), 508, None)])?;
    assert_eq!(h.connects_to(SERVER), 1);
    h.advance(Duration::from_secs(10))?;
    h.restart()?;
    assert_eq!(h.connects_to(SERVER), 1, "held back for a minute");
    h.advance(Duration::from_secs(55))?;
    h.restart()?;
    assert_eq!(h.connects_to(SERVER), 2, "used again after the minute");
    Ok(())
}
