//! TURN over DTLS in the engine (RFC 7350, RFC 8656 section 3.1): a `turns:...?transport=udp`
//! server is reached with a client-role DTLS association from the application's UDP host
//! candidate, demultiplexed before ICE. The server here is an `rtc-dtls` server endpoint with
//! a TURN server scripted by the test behind it.

use anyhow::Result;
use bytes::BytesMut;
use rtc::dtls::config::ConfigBuilder;
use rtc::dtls::crypto::Certificate;
use rtc::dtls::endpoint::{Endpoint, EndpointEvent};
use rtc::peer_connection::configuration::setting_engine::SettingEngineBuilder;
use rtc::peer_connection::configuration::{RTCConfigurationBuilder, RTCIceServer};
use rtc::peer_connection::event::RTCPeerConnectionEvent;
use rtc::peer_connection::state::RTCIceGatheringState;
use rtc::peer_connection::transport::{RTCIceCandidateInit, RTCIceServerTransportProtocol};
use rtc::peer_connection::turn_tls::TurnTlsConfig;
use rtc::peer_connection::{RTCPeerConnection, RTCPeerConnectionBuilder};
use rtc::sansio::Protocol;
use rtc::shared::{TaggedBytesMut, TransportContext, TransportProtocol};
use rtc::stun::attributes::{ATTR_MESSAGE_INTEGRITY, ATTR_NONCE, ATTR_REALM};
use rtc::stun::error_code::{CODE_UNAUTHORIZED, ErrorCodeAttribute};
use rtc::stun::fingerprint::FINGERPRINT;
use rtc::stun::integrity::MessageIntegrity;
use rtc::stun::message::{
    CLASS_ERROR_RESPONSE, CLASS_REQUEST, CLASS_SUCCESS_RESPONSE, Getter, METHOD_ALLOCATE, Message,
    MessageType, Setter,
};
use rtc::stun::textattrs::{Nonce, Realm};
use rtc::stun::xoraddr::XorMappedAddress;
use rtc::turn::proto::lifetime::Lifetime;
use rtc::turn::proto::relayaddr::RelayedAddress;
use rtc::turn::proto::reqtrans::RequestedTransport;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

mod common;

const HOST: &str = "10.0.0.1:4000";
const SERVER: &str = "192.0.2.20:5349";
const RELAYED: &str = "192.0.2.20:50000";
const USER: &str = "user";
const PASS: &str = "pass";
const REALM: &str = "rtc.test";

fn a(s: &str) -> SocketAddr {
    s.parse().unwrap()
}

/// A self-signed certificate for `name` and the roots that vouch for it.
fn certificate(name: &str) -> Result<(Certificate, rustls::RootCertStore)> {
    let provider = rtc::crypto::default_provider()?;
    let cert = Certificate::generate_self_signed(vec![name.to_owned()], provider.crypto())?;
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert.certificate[0].clone())?;
    Ok((cert, roots))
}

/// The DTLS server at [`SERVER`] with a TURN server scripted behind it.
struct Server {
    endpoint: Endpoint,
    key: Vec<u8>,
    /// The TURN requests it read, in order, with when.
    requests: Vec<Message>,
    request_times: Vec<Instant>,
    handshakes: usize,
    /// Leave the first Allocate unanswered (a lost response).
    drop_first: bool,
}

impl Server {
    fn new(cert: Certificate) -> Result<Self> {
        let provider = rtc::crypto::default_provider()?;
        let config = ConfigBuilder::default()
            .with_crypto_provider(provider.clone())
            .with_certificates(vec![cert])
            .build(false, None)?;
        let key = MessageIntegrity::long_term_integrity_key(
            USER.to_owned(),
            REALM.to_owned(),
            PASS.to_owned(),
            provider.crypto(),
        )?;
        Ok(Self {
            endpoint: Endpoint::new(a(SERVER), TransportProtocol::UDP, Some(Arc::new(config))),
            key,
            requests: vec![],
            request_times: vec![],
            handshakes: 0,
            drop_first: false,
        })
    }

    /// The TURN server's answer to `request`: a 401 to an unsigned Allocate, a success with
    /// the relayed address to a signed one.
    fn answer(&self, request: &Message, client: SocketAddr) -> Result<Vec<u8>> {
        let signed = request.contains(ATTR_MESSAGE_INTEGRITY);
        let provider = rtc::crypto::default_provider()?;
        let mut setters: Vec<Box<dyn Setter>> = vec![Box::new(request.transaction_id)];
        if !signed {
            setters.push(Box::new(MessageType::new(
                METHOD_ALLOCATE,
                CLASS_ERROR_RESPONSE,
            )));
            setters.push(Box::new(ErrorCodeAttribute {
                code: CODE_UNAUTHORIZED,
                reason: b"Unauthorized".to_vec(),
            }));
            setters.push(Box::new(Nonce::new(ATTR_NONCE, "nonce".to_owned())));
            setters.push(Box::new(Realm::new(ATTR_REALM, REALM.to_owned())));
        } else {
            setters.push(Box::new(MessageType::new(
                METHOD_ALLOCATE,
                CLASS_SUCCESS_RESPONSE,
            )));
            setters.push(Box::new(RelayedAddress {
                ip: a(RELAYED).ip(),
                port: a(RELAYED).port(),
            }));
            setters.push(Box::new(XorMappedAddress {
                ip: client.ip(),
                port: client.port(),
            }));
            setters.push(Box::new(Lifetime(Duration::from_secs(600))));
            setters.push(Box::new(MessageIntegrity::new_raw_integrity_with_provider(
                self.key.clone(),
                provider.crypto(),
            )));
        }
        setters.push(Box::new(FINGERPRINT));
        let mut reply = Message::new();
        reply.build(&setters)?;
        Ok(reply.raw)
    }

    /// Reads a datagram of the client; answers TURN requests over the association.
    fn read(&mut self, now: Instant, from: SocketAddr, data: BytesMut) -> Result<()> {
        let events = match self.endpoint.read(now, from, None, data) {
            Ok(events) => events,
            // A handshake the server gave up on (the client refused its certificate, say).
            Err(_) => return Ok(()),
        };
        for event in events {
            match event {
                EndpointEvent::HandshakeComplete => self.handshakes += 1,
                EndpointEvent::ApplicationData(data) => {
                    let mut request = Message::new();
                    request.unmarshal_binary(&data)?;
                    let lost = self.drop_first && self.requests.is_empty();
                    if !lost
                        && request.typ.class == CLASS_REQUEST
                        && request.typ.method == METHOD_ALLOCATE
                    {
                        let reply = self.answer(&request, from)?;
                        self.endpoint.write(now, from, &reply)?;
                    }
                    self.requests.push(request);
                    self.request_times.push(now);
                }
                _ => {}
            }
        }
        Ok(())
    }
}

struct Harness {
    pc: RTCPeerConnection,
    server: Server,
    now: Instant,
    events: Vec<RTCPeerConnectionEvent>,
    /// The first datagram the engine sent to the server (the ClientHello).
    first: Option<Vec<u8>>,
}

impl Harness {
    fn new(server_cert: Certificate, roots: rustls::RootCertStore) -> Result<Self> {
        Self::with(
            &format!("turns:{SERVER}?transport=udp"),
            server_cert,
            TurnTlsConfig {
                roots: Some(Arc::new(roots)),
                ..Default::default()
            },
        )
    }

    fn with(url: &str, server_cert: Certificate, tls: TurnTlsConfig) -> Result<Self> {
        Self::with_settings(
            url,
            server_cert,
            SettingEngineBuilder::new().with_turn_tls(tls),
        )
    }

    fn with_settings(
        url: &str,
        server_cert: Certificate,
        settings: SettingEngineBuilder,
    ) -> Result<Self> {
        common::install_crypto_provider();
        let now = Instant::now();
        let mut pc = RTCPeerConnectionBuilder::new()
            .with_configuration(
                RTCConfigurationBuilder::new()
                    .with_ice_servers(vec![RTCIceServer {
                        urls: vec![url.to_owned()],
                        username: USER.to_owned(),
                        credential: PASS.to_owned(),
                    }])
                    .build(),
            )
            .with_setting_engine(settings.build())
            .build(now)?;
        pc.create_data_channel("turn-dtls", None)?;
        let offer = pc.create_offer(None)?;
        pc.set_local_description(now, offer)?;
        Ok(Self {
            pc,
            server: Server::new(server_cert)?,
            now,
            events: vec![],
            first: None,
        })
    }

    /// Moves datagrams both ways (the network between the base and the server) and the
    /// timers on, until nothing moves or `until`.
    fn run(&mut self, until: Instant) -> Result<()> {
        loop {
            let mut moved = false;
            while let Some(w) = self.pc.poll_write() {
                if w.transport.peer_addr == a(SERVER) {
                    assert_eq!(w.transport.local_addr, a(HOST), "from the host candidate");
                    assert_eq!(w.transport.transport_protocol, TransportProtocol::UDP);
                    if self.first.is_none() {
                        self.first = Some(w.message.to_vec());
                    }
                    self.server.read(self.now, a(HOST), w.message)?;
                    moved = true;
                }
            }
            while let Some(t) = self.server.endpoint.poll_transmit() {
                self.pc.handle_read(TaggedBytesMut {
                    now: self.now,
                    transport: TransportContext {
                        local_addr: a(HOST),
                        peer_addr: a(SERVER),
                        transport_protocol: TransportProtocol::UDP,
                        ecn: None,
                    },
                    message: t.message,
                })?;
                moved = true;
            }
            while let Some(e) = self.pc.poll_event() {
                self.events.push(e);
                moved = true;
            }
            if moved {
                continue;
            }
            let next = [
                self.pc.poll_timeout(),
                self.server.endpoint.poll_timeout(&a(HOST)),
            ]
            .into_iter()
            .flatten()
            .min();
            match next {
                Some(t) if t <= until => {
                    self.now = t.max(self.now + Duration::from_micros(1));
                    self.pc.handle_timeout(self.now)?;
                    let _ = self.server.endpoint.handle_timeout(a(HOST), self.now);
                }
                _ => return Ok(()),
            }
        }
    }

    fn add_host(&mut self) -> Result<()> {
        let host = a(HOST);
        self.pc.add_local_candidate(RTCIceCandidateInit {
            candidate: format!(
                "candidate:1 1 udp 2130706431 {} {} typ host",
                host.ip(),
                host.port()
            ),
            ..Default::default()
        })?;
        Ok(())
    }

    /// The relayed candidates announced, with their URL and relay protocol.
    fn relayed(&self) -> Vec<(String, Option<String>, RTCIceServerTransportProtocol)> {
        self.events
            .iter()
            .filter_map(|e| match e {
                RTCPeerConnectionEvent::OnIceCandidateEvent(ev) => {
                    let c = ev.candidate.as_ref()?;
                    let init = c.to_json().ok()?;
                    init.candidate
                        .contains("typ relay")
                        .then(|| (init.candidate, ev.url.clone(), c.relay_protocol))
                }
                _ => None,
            })
            .collect()
    }
}

/// RFC 7350 section 4 and RFC 8656 section 3.1: the engine runs a DTLS client from the host
/// candidate's base to the `turns:...?transport=udp` server, checks its certificate against
/// the URI's host with the configured roots, allocates over the association (REQUESTED-
/// TRANSPORT UDP: no TCP allocation over DTLS, RFC 7350 section 4.2) and announces the relayed
/// address with `relayProtocol` "dtls"; the end of gathering waits for it.
#[test]
fn a_turns_udp_server_is_reached_over_dtls_and_its_relayed_candidate_announced() -> Result<()> {
    let (cert, roots) = certificate("192.0.2.20")?;
    let mut h = Harness::new(cert, roots)?;
    h.add_host()?;
    h.pc.add_local_candidate(RTCIceCandidateInit::default())?;
    assert_ne!(
        h.pc.ice_gathering_state(),
        RTCIceGatheringState::Complete,
        "the end of gathering waits for the allocation"
    );
    h.run(h.now + Duration::from_secs(10))?;
    assert_eq!(h.server.handshakes, 1, "one DTLS association");
    let allocates: Vec<&Message> = h
        .server
        .requests
        .iter()
        .filter(|m| m.typ.method == METHOD_ALLOCATE)
        .collect();
    assert_eq!(
        allocates.len(),
        2,
        "the 401 exchange, then the signed request"
    );
    for allocate in allocates {
        let mut transport = RequestedTransport::default();
        transport.get_from(allocate)?;
        assert_eq!(
            transport.protocol,
            rtc::turn::proto::PROTO_UDP,
            "no TCP allocation over DTLS"
        );
    }
    let relayed = h.relayed();
    assert_eq!(relayed.len(), 1, "{relayed:?}");
    let (candidate, url, protocol) = &relayed[0];
    assert!(
        candidate.contains("192.0.2.20 50000 typ relay raddr 10.0.0.1 rport 4000"),
        "{candidate}"
    );
    assert_eq!(url.as_deref(), Some("turns:192.0.2.20:5349?transport=udp"));
    assert_eq!(*protocol, RTCIceServerTransportProtocol::Dtls);
    assert_eq!(h.pc.ice_gathering_state(), RTCIceGatheringState::Complete);
    Ok(())
}

/// RFC 7350 section 4 (the TLS certificate rules) and RFC 8656 section 3.1: a server whose
/// certificate the roots do not vouch for is not used; gathering ends without a relayed
/// candidate.
/// The SOFTWARE of the engine's TURN client over DTLS (RFC 8656 section 5, RFC 8489 section
/// 16.1.2: "Implementers SHOULD make usage of the SOFTWARE attribute a configurable option"):
/// `rtc-turn` and its version by default, the text `with_ice_software` names, and with
/// `with_ice_software(None)` none in any request over the association.
#[test]
fn the_engine_dtls_turn_client_sends_the_software_with_ice_software_names() -> Result<()> {
    use rtc::stun::attributes::ATTR_SOFTWARE;
    use rtc::stun::textattrs::Software;
    for (setting, expected) in [
        (None, Some(rtc::turn::client::DEFAULT_SOFTWARE.to_owned())),
        (Some(None), None),
        (Some(Some("app 1.0".to_owned())), Some("app 1.0".to_owned())),
    ] {
        let (cert, roots) = certificate("192.0.2.20")?;
        let mut settings = SettingEngineBuilder::new().with_turn_tls(TurnTlsConfig {
            roots: Some(Arc::new(roots)),
            ..Default::default()
        });
        if let Some(software) = setting.clone() {
            settings = settings.with_ice_software(software);
        }
        let mut h =
            Harness::with_settings(&format!("turns:{SERVER}?transport=udp"), cert, settings)?;
        h.add_host()?;
        h.run(h.now + Duration::from_secs(10))?;
        assert!(
            h.server
                .requests
                .iter()
                .filter(|m| m.typ.method == METHOD_ALLOCATE)
                .count()
                >= 2,
            "{setting:?}: the 401 exchange, then the signed Allocate"
        );
        for m in &h.server.requests {
            let software = Software::get_from_as(m, ATTR_SOFTWARE)
                .ok()
                .map(|software| software.text);
            assert_eq!(software, expected, "{setting:?}: {}", m.typ);
        }
    }
    Ok(())
}

#[test]
fn a_dtls_server_the_roots_do_not_vouch_for_is_not_used() -> Result<()> {
    let (cert, _) = certificate("192.0.2.20")?;
    let (_, other_roots) = certificate("192.0.2.20")?;
    let mut h = Harness::new(cert, other_roots)?;
    h.add_host()?;
    h.pc.add_local_candidate(RTCIceCandidateInit::default())?;
    h.run(h.now + Duration::from_secs(70))?;
    assert!(h.server.requests.is_empty(), "no TURN request crossed");
    assert!(h.relayed().is_empty());
    assert_eq!(h.pc.ice_gathering_state(), RTCIceGatheringState::Complete);
    Ok(())
}

/// RFC 7350 section 4 with BCP 195 (RFC 8656 section 3.1): the ClientHello offers only
/// forward-secret AEAD suites, TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 among them, nothing
/// with CBC, DES or RC4, and null compression only.
#[test]
fn the_turn_dtls_client_hello_offers_forward_secret_aead_suites_only() -> Result<()> {
    let (cert, roots) = certificate("192.0.2.20")?;
    let mut h = Harness::new(cert, roots)?;
    h.add_host()?;
    h.run(h.now)?;
    let hello = h.first.clone().expect("a ClientHello");
    // DTLS record header (13), handshake header (12), client_version (2), random (32).
    assert_eq!(hello[0], 22, "a handshake record");
    assert_eq!(hello[13], 1, "a ClientHello");
    let mut at = 13 + 12 + 2 + 32;
    let session = hello[at] as usize;
    at += 1 + session;
    let cookie = hello[at] as usize;
    at += 1 + cookie;
    let len = u16::from_be_bytes([hello[at], hello[at + 1]]) as usize;
    at += 2;
    let suites: Vec<u16> = hello[at..at + len]
        .chunks(2)
        .map(|c| u16::from_be_bytes([c[0], c[1]]))
        .collect();
    at += len;
    assert!(
        suites.contains(&0xc02f),
        "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256: {suites:x?}"
    );
    let allowed = [
        0xc02b, 0xc02f, 0xcca8, 0xcca9, 0x1301, 0x1302, 0x1303, // AEAD, forward secret
        0x00ff, // TLS_EMPTY_RENEGOTIATION_INFO_SCSV (RFC 5746), not a suite
    ];
    assert!(
        suites.iter().all(|s| allowed.contains(s)),
        "only forward-secret AEAD suites: {suites:x?}"
    );
    assert_eq!(&hello[at..at + 2], &[1, 0], "null compression only");
    Ok(())
}

/// RFC 7350 section 4: STUN over DTLS takes UDP's retransmission rules. The server's answer
/// to the first Allocate is lost; the client sends the same request again (same transaction)
/// after RTO, 500 ms (RFC 8489 section 6.2.1), over the association.
#[test]
fn a_lost_answer_over_dtls_is_retransmitted_as_over_udp() -> Result<()> {
    let (cert, roots) = certificate("192.0.2.20")?;
    let mut h = Harness::new(cert, roots)?;
    h.server.drop_first = true;
    h.add_host()?;
    h.run(h.now + Duration::from_secs(10))?;
    assert!(h.server.requests.len() >= 2, "{}", h.server.requests.len());
    assert_eq!(
        h.server.requests[0].transaction_id, h.server.requests[1].transaction_id,
        "the same request again"
    );
    let gap = h.server.request_times[1].duration_since(h.server.request_times[0]);
    assert!(
        gap >= Duration::from_millis(500) && gap < Duration::from_millis(600),
        "after RTO: {gap:?}"
    );
    assert_eq!(h.relayed().len(), 1, "allocated after the retransmission");
    Ok(())
}

/// RFC 7350 section 4: the default port of `turns:` over DTLS is 5349. A URI without a port,
/// its host an address (nothing to look up), reaches the server on 5349.
#[test]
fn a_turns_udp_uri_without_a_port_uses_5349() -> Result<()> {
    let (cert, roots) = certificate("192.0.2.20")?;
    let mut h = Harness::with(
        "turns:192.0.2.20?transport=udp",
        cert,
        TurnTlsConfig {
            roots: Some(Arc::new(roots)),
            ..Default::default()
        },
    )?;
    h.add_host()?;
    h.run(h.now + Duration::from_secs(10))?;
    assert!(h.first.is_some(), "the ClientHello went to 192.0.2.20:5349");
    let relayed = h.relayed();
    assert_eq!(relayed.len(), 1, "{relayed:?}");
    assert_eq!(
        relayed[0].1.as_deref(),
        Some("turns:192.0.2.20:5349?transport=udp")
    );
    Ok(())
}

/// RFC 7350 section 4.2 with RFC 8656 section 3.1: without roots or a verifier nothing can
/// check the server, so it is not contacted at all (its resolution stops with an error) and
/// gathering ends without it.
#[test]
fn a_dtls_server_without_roots_or_a_verifier_is_not_contacted() -> Result<()> {
    let (cert, _) = certificate("192.0.2.20")?;
    let mut h = Harness::with(
        &format!("turns:{SERVER}?transport=udp"),
        cert,
        TurnTlsConfig::default(),
    )?;
    h.add_host()?;
    h.pc.add_local_candidate(RTCIceCandidateInit::default())?;
    h.run(h.now + Duration::from_secs(10))?;
    assert!(h.first.is_none(), "no ClientHello");
    assert!(h.relayed().is_empty());
    assert_eq!(h.pc.ice_gathering_state(), RTCIceGatheringState::Complete);
    Ok(())
}
