//! TURN over TCP and over TLS built into the engine (RFC 8656 section 3.1), against the test
//! environment's coturn (`scripts/test-env/run.sh`); ignored elsewhere.
//!
//! Both peers sit behind symmetric NATs with the relay policy: only relayed candidates exist.
//! The applications add no candidate at all; they give the configuration a `turn:...?transport=tcp`
//! or `turns:` server and serve the stream interface with the tokio reference driver
//! (`examples/stream-driver`), whose sockets live in each peer's namespace. The engine connects,
//! runs TLS (verified against the environment's CA, ALPN `stun.turn`), allocates, announces the
//! relayed candidate with its `relayProtocol` and relays every packet.
//!
//! Over DTLS (`turns:...?transport=udp`, RFC 7350) each application binds one UDP socket and
//! adds its host candidate (which the relay policy keeps from the peer): the engine runs its
//! DTLS association to coturn from that socket, and every datagram on it is to or from coturn.
//! Over plain UDP (`turn:...?transport=udp`) the same, without DTLS.
//!
//! TLS 1.3 and TLS 1.2 each have a case of their own: the engine offering TLS 1.3 alone to the
//! environment's main coturn (which speaks both), and the engine's default offer (1.3 and 1.2)
//! to a second coturn that stops at TLS 1.2 (`coturn/turnserver-tls12.conf`), as servers
//! without TLS 1.3 do. Each first checks, with a plain rustls client, that the server
//! negotiates exactly what the case says.

mod common;
mod testenv;

use bytes::BytesMut;
use rtci::peer_connection::RTCPeerConnectionBuilder;
use rtci::peer_connection::configuration::setting_engine::SettingEngineBuilder;
use rtci::peer_connection::configuration::{RTCConfigurationBuilder, RTCIceTransportPolicy};
use rtci::peer_connection::event::{RTCDataChannelEvent, RTCPeerConnectionEvent};
use rtci::peer_connection::message::RTCMessage;
use rtci::peer_connection::sdp::RTCSessionDescription;
use rtci::peer_connection::state::RTCPeerConnectionState;
use rtci::peer_connection::transport::{
    RTCIceCandidateInit, RTCIceCandidateType, RTCIceServer, RTCIceServerTransportProtocol,
};
use rtci::peer_connection::turn_tls::TurnTlsConfig;
use rtci::sansio::Protocol;
use std::io;
use std::sync::Arc;
use std::sync::mpsc::{Receiver, Sender};
use std::time::{Duration, Instant};
use stream_driver::{DriverInput, StreamDriver};
use testenv::{Env, in_netns};

enum Signal {
    Description(String),
    Candidate(String),
    Done,
}

/// What a peer of a case is.
#[derive(Clone, Copy, PartialEq, Eq)]
enum PeerKind {
    /// The relay policy, the engine's TURN client.
    Relay,
    /// As `Relay`, TURN over TLS offering TLS 1.3 alone (`TurnTlsConfig::disable_tls12`).
    RelayTls13Only,
    /// As `Relay`, TCP candidates only: the relayed TCP candidates of the TCP allocation.
    RelayTcpOnly,
    /// No TURN server: the engine's own ICE-TCP candidates (the application adds the host
    /// candidate of its UDP socket).
    IceTcp,
}

struct Outcome {
    connected: bool,
    received: Vec<Vec<u8>>,
    relay_protocols: Vec<RTCIceServerTransportProtocol>,
    only_relay: bool,
}

fn roots(env: &Env) -> Arc<rustls::RootCertStore> {
    use rustls::pki_types::CertificateDer;
    use rustls::pki_types::pem::PemObject;
    let mut roots = rustls::RootCertStore::empty();
    for cert in CertificateDer::pem_slice_iter(env.ca_pem.as_bytes()) {
        roots.add(cert.unwrap()).unwrap();
    }
    Arc::new(roots)
}

#[allow(clippy::too_many_arguments)]
fn peer(
    offerer: bool,
    url: String,
    env: Env,
    tx: Sender<Signal>,
    rx: Receiver<Signal>,
    messages: Vec<Vec<u8>>,
    udp: Option<std::net::IpAddr>,
    kind: PeerKind,
) -> io::Result<Outcome> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async move {
        // Over DTLS: the application's UDP socket, the engine's DTLS association on it.
        let socket = match udp {
            Some(ip) => Some(tokio::net::UdpSocket::bind((ip, 0)).await?),
            None => None,
        };
        let turn_server: std::net::SocketAddr = url
            .trim_start_matches("turns:")
            .trim_start_matches("turn:")
            .trim_end_matches("?transport=udp")
            .parse()
            .unwrap_or(env.turn_tls);
        let mut buf = vec![0u8; 2048];
        let configuration = if kind == PeerKind::IceTcp {
            RTCConfigurationBuilder::new().build()
        } else {
            RTCConfigurationBuilder::new()
                .with_ice_servers(vec![RTCIceServer {
                    urls: vec![url.clone()],
                    username: env.user.clone(),
                    credential: env.pass.clone(),
                }])
                .with_ice_transport_policy(RTCIceTransportPolicy::Relay)
                .build()
        };
        let mut settings = SettingEngineBuilder::new().with_turn_tls(TurnTlsConfig {
            roots: Some(roots(&env)),
            disable_tls12: kind == PeerKind::RelayTls13Only,
            ..Default::default()
        });
        if kind == PeerKind::RelayTcpOnly {
            settings =
                settings.with_network_types(vec![rtci::ice::network_type::NetworkType::Tcp4]);
        }
        let mut pc = RTCPeerConnectionBuilder::new()
            .with_configuration(configuration)
            .with_setting_engine(settings.build())
            .build(Instant::now())
            .unwrap();
        let mut driver = StreamDriver::default();
        let mut channel = None;
        if offerer {
            channel = Some(pc.create_data_channel("turn-streams", None).unwrap().id());
            let offer = pc.create_offer(None).unwrap();
            pc.set_local_description(Instant::now(), offer.clone())
                .unwrap();
            let _ = tx.send(Signal::Description(serde_json::to_string(&offer).unwrap()));
        }
        let add_host = |pc: &mut rtci::peer_connection::RTCPeerConnection| {
            if let Some(local) = socket.as_ref().and_then(|s| s.local_addr().ok()) {
                pc.add_local_candidate(RTCIceCandidateInit {
                    candidate: format!(
                        "candidate:1 1 udp 2130706431 {} {} typ host",
                        local.ip(),
                        local.port()
                    ),
                    ..Default::default()
                })
                .unwrap();
            }
        };
        if offerer {
            add_host(&mut pc);
        }
        let mut out = Outcome {
            connected: false,
            received: vec![],
            relay_protocols: vec![],
            only_relay: true,
        };
        let mut sent = false;
        let deadline = Instant::now() + Duration::from_secs(40);
        while Instant::now() < deadline {
            while let Ok(signal) = rx.try_recv() {
                match signal {
                    Signal::Description(json) => {
                        let d: RTCSessionDescription = serde_json::from_str(&json).unwrap();
                        pc.set_remote_description(Instant::now(), d).unwrap();
                        if !offerer {
                            let answer = pc.create_answer(None).unwrap();
                            pc.set_local_description(Instant::now(), answer.clone())
                                .unwrap();
                            add_host(&mut pc);
                            let _ = tx
                                .send(Signal::Description(serde_json::to_string(&answer).unwrap()));
                        }
                    }
                    Signal::Candidate(json) => {
                        let c: RTCIceCandidateInit = serde_json::from_str(&json).unwrap();
                        let _ = pc.add_remote_candidate(c);
                    }
                    Signal::Done => return Ok(out),
                }
            }
            while let Some(command) = pc.poll_stream_command() {
                driver.execute(command);
            }
            while let Some(transmit) = pc.poll_stream_transmit() {
                driver.write(transmit);
            }
            // Everything goes through the relay: nothing is left for the application's sockets
            // but, over DTLS, the association to the TURN server.
            while let Some(w) = pc.poll_write() {
                match socket.as_ref() {
                    Some(s) if w.transport.peer_addr == turn_server => {
                        let _ = s.send_to(&w.message, w.transport.peer_addr).await;
                    }
                    _ => out.only_relay = false,
                }
            }
            if let Some(s) = socket.as_ref() {
                while let Ok((n, from)) = s.try_recv_from(&mut buf) {
                    if from != turn_server {
                        out.only_relay = false;
                    }
                    let local = s.local_addr()?;
                    let _ = pc.handle_read(rtci::shared::TaggedBytesMut {
                        now: Instant::now(),
                        transport: rtci::shared::TransportContext {
                            local_addr: local,
                            peer_addr: from,
                            transport_protocol: rtci::shared::TransportProtocol::UDP,
                            ecn: None,
                        },
                        message: BytesMut::from(&buf[..n]),
                    });
                }
            }
            while let Some(e) = pc.poll_event() {
                match e {
                    RTCPeerConnectionEvent::OnIceCandidateEvent(ev) => {
                        if let Some(c) = ev.candidate.filter(|c| !c.end_of_candidates) {
                            if c.typ == RTCIceCandidateType::Relay {
                                out.relay_protocols.push(c.relay_protocol);
                            }
                            if let Ok(init) = c.to_json() {
                                let _ = tx
                                    .send(Signal::Candidate(serde_json::to_string(&init).unwrap()));
                            }
                        }
                    }
                    RTCPeerConnectionEvent::OnConnectionStateChangeEvent(
                        RTCPeerConnectionState::Connected,
                    ) => out.connected = true,
                    RTCPeerConnectionEvent::OnDataChannel(RTCDataChannelEvent::OnOpen(id))
                        if offerer && Some(id) == channel && !sent =>
                    {
                        let mut dc = pc.data_channel(id).unwrap();
                        for m in &messages {
                            dc.send(Instant::now(), BytesMut::from(&m[..])).unwrap();
                        }
                        sent = true;
                    }
                    _ => {}
                }
            }
            while let Some(m) = pc.poll_read() {
                if let RTCMessage::DataChannelMessage(_, msg) = m.message {
                    out.received.push(msg.data.to_vec());
                }
            }
            if !offerer && out.received.len() >= messages.len() {
                let _ = tx.send(Signal::Done);
                break;
            }
            let wake = pc
                .poll_timeout()
                .unwrap_or_else(|| Instant::now() + Duration::from_millis(10))
                .min(Instant::now() + Duration::from_millis(10));
            let wait = wake.saturating_duration_since(Instant::now());
            if let Ok(input) = tokio::time::timeout(wait, driver.next()).await {
                let mut inputs = vec![input];
                while let Some(more) = driver.try_next() {
                    inputs.push(more);
                }
                for input in inputs {
                    let now = Instant::now();
                    match input {
                        DriverInput::Event(event) => {
                            let _ = pc.handle_stream_event(now, event);
                        }
                        DriverInput::Read { id, data } => {
                            let _ = pc.handle_stream_read(now, id, &data);
                        }
                        DriverInput::Accepted(accepted) => {
                            if let Some(id) = pc.handle_stream_accepted(
                                now,
                                accepted.listener,
                                accepted.local,
                                accepted.remote,
                            ) {
                                driver.adopt(id, accepted);
                            }
                        }
                    }
                }
            }
            let now = Instant::now();
            if pc.poll_timeout().is_some_and(|t| t <= now) {
                let _ = pc.handle_timeout(now);
            }
        }
        Ok(out)
    })
}

/// The TLS version `server` settles on with a client (plain rustls, the environment's CA, the
/// server named by its address as the engine names it) that offers `versions`, from `open-a`;
/// the handshake's error when it refuses them all.
fn negotiated_tls_version(
    env: &Env,
    server: std::net::SocketAddr,
    versions: &[&'static rustls::SupportedProtocolVersion],
) -> io::Result<rustls::ProtocolVersion> {
    let provider = rustls::crypto::CryptoProvider::get_default()
        .cloned()
        .expect("install_crypto_provider() first");
    let config = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(versions)
        .map_err(io::Error::other)?
        .with_root_certificates(roots(env))
        .with_no_client_auth();
    let mut conn = rustls::ClientConnection::new(
        Arc::new(config),
        rustls::pki_types::ServerName::from(server.ip()),
    )
    .map_err(io::Error::other)?;
    let mut stream = in_netns("open-a", move || {
        std::net::TcpStream::connect_timeout(&server, Duration::from_secs(5))
    })?;
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    while conn.is_handshaking() {
        conn.complete_io(&mut stream)?;
    }
    conn.protocol_version()
        .ok_or_else(|| io::Error::other("no protocol version after the handshake"))
}

fn relay_through_engine_turn(url: &str, expected: RTCIceServerTransportProtocol) {
    relay_through_engine_turn_as(url, expected, PeerKind::Relay);
}

fn relay_through_engine_turn_as(
    url: &str,
    expected: RTCIceServerTransportProtocol,
    kind: PeerKind,
) {
    common::install_crypto_provider();
    let env = Env::get();
    // Over DTLS and over plain UDP the engine runs on the application's UDP socket.
    let datagrams = match expected {
        RTCIceServerTransportProtocol::Dtls => Some(env.turn_tls),
        RTCIceServerTransportProtocol::Udp => Some(env.turn_udp),
        _ => None,
    };
    let (ip_a, ip_b) = if let Some(server) = datagrams {
        (
            Some(testenv::source_ip("h-symmetric-a", server).unwrap()),
            Some(testenv::source_ip("h-symmetric-b", server).unwrap()),
        )
    } else {
        (None, None)
    };
    let mut messages = vec![b"relayed by the engine".to_vec(), vec![9u8; 30_000]];
    messages.extend((0..30u8).map(|i| vec![i; 200]));
    let (a_tx, b_rx) = std::sync::mpsc::channel();
    let (b_tx, a_rx) = std::sync::mpsc::channel();
    let (u, e, m) = (url.to_owned(), env.clone(), messages.clone());
    let offerer = std::thread::spawn(move || {
        in_netns("h-symmetric-a", move || {
            peer(true, u, e, a_tx, a_rx, m, ip_a, kind)
        })
    });
    let (u, e, m) = (url.to_owned(), env.clone(), messages.clone());
    let answerer = std::thread::spawn(move || {
        in_netns("h-symmetric-b", move || {
            peer(false, u, e, b_tx, b_rx, m, ip_b, kind)
        })
    });
    let b = answerer.join().unwrap().unwrap();
    let a = offerer.join().unwrap().unwrap();
    eprintln!(
        "TURN client in the engine over {url}: received {} of {}; relay protocols {:?} / {:?}",
        b.received.len(),
        messages.len(),
        a.relay_protocols,
        b.relay_protocols
    );
    assert!(
        a.connected && b.connected,
        "not connected through the engine's TURN"
    );
    assert_eq!(b.received, messages, "every message, in order");
    for o in [&a, &b] {
        assert!(!o.relay_protocols.is_empty(), "a relayed candidate");
        assert!(
            o.relay_protocols.iter().all(|p| *p == expected),
            "{:?}",
            o.relay_protocols
        );
        assert!(o.only_relay, "the application's sockets carried something");
    }
}

#[test]
#[ignore = "needs the real-network test environment (coturn, NAT namespaces): scripts/test-env/run.sh"]
fn the_engine_relays_through_turn_over_tcp() {
    let env = Env::get();
    relay_through_engine_turn(
        &format!("turn:{}?transport=tcp", env.turn_tcp),
        RTCIceServerTransportProtocol::Tcp,
    );
}

#[test]
#[ignore = "needs the real-network test environment (coturn, NAT namespaces): scripts/test-env/run.sh"]
fn the_engine_relays_through_turn_over_tls() {
    let env = Env::get();
    // The server certificate names 203.0.113.10 as well as turn.rtc.test.
    relay_through_engine_turn(
        &format!("turns:{}?transport=tcp", env.turn_tls),
        RTCIceServerTransportProtocol::Tls,
    );
}

/// RFC 8656 section 3.1 over TLS 1.3 (RFC 8446): the engine offers TLS 1.3 alone
/// (`TurnTlsConfig::disable_tls12`) to coturn, which speaks TLS 1.3 and 1.2 and settles on 1.3.
#[test]
#[ignore = "needs the real-network test environment (coturn, NAT namespaces): scripts/test-env/run.sh"]
fn the_engine_relays_through_turn_over_tls_1_3() {
    common::install_crypto_provider();
    let env = Env::get();
    use rustls::version::{TLS12, TLS13};
    assert_eq!(
        negotiated_tls_version(&env, env.turn_tls, &[&TLS13, &TLS12]).unwrap(),
        rustls::ProtocolVersion::TLSv1_3,
        "the environment's coturn must take TLS 1.3 when it is offered"
    );
    relay_through_engine_turn_as(
        &format!("turns:{}?transport=tcp", env.turn_tls),
        RTCIceServerTransportProtocol::Tls,
        PeerKind::RelayTls13Only,
    );
}

/// RFC 8656 section 3.1 over TLS 1.2 (RFC 5246): the engine's default offer (TLS 1.3 and 1.2)
/// to a coturn that stops at TLS 1.2 settles on 1.2, as with the servers deployed without TLS
/// 1.3. The server is checked first: a client offering TLS 1.3 alone is refused, one offering
/// both gets 1.2.
#[test]
#[ignore = "needs the real-network test environment (coturn, NAT namespaces): scripts/test-env/run.sh"]
fn the_engine_relays_through_turn_over_tls_1_2_to_a_server_without_tls_1_3() {
    common::install_crypto_provider();
    let env = Env::get();
    let server = env.turn_tls12.expect(
        "RTC_TESTENV_TURN_TLS12 is not set: scripts/test-env/coturn/start.sh starts that server",
    );
    use rustls::version::{TLS12, TLS13};
    assert!(
        negotiated_tls_version(&env, server, &[&TLS13]).is_err(),
        "the TLS 1.2 server took a TLS 1.3-only ClientHello"
    );
    assert_eq!(
        negotiated_tls_version(&env, server, &[&TLS13, &TLS12]).unwrap(),
        rustls::ProtocolVersion::TLSv1_2
    );
    relay_through_engine_turn(
        &format!("turns:{server}?transport=tcp"),
        RTCIceServerTransportProtocol::Tls,
    );
}

/// RFC 7350 and RFC 8656 section 3.1: TURN over DTLS, the engine's DTLS client on each
/// application's UDP socket, coturn's certificate checked against the environment's CA for the
/// URI's host (its certificate names 203.0.113.10); `relayProtocol` "dtls".
#[test]
#[ignore = "needs the real-network test environment (coturn, NAT namespaces): scripts/test-env/run.sh"]
fn the_engine_relays_through_turn_over_dtls() {
    let env = Env::get();
    relay_through_engine_turn(
        &format!("turns:{}?transport=udp", env.turn_tls),
        RTCIceServerTransportProtocol::Dtls,
    );
}

/// RFC 8656 over plain UDP, run by the engine (`RelayGathering::Engine`, the default): each
/// application binds one UDP socket and adds its host candidate; the engine allocates on coturn
/// from it (the 401 exchange, permissions, channel bindings, refreshes) and relays every
/// packet; `relayProtocol` "udp".
#[test]
#[ignore = "needs the real-network test environment (coturn, NAT namespaces): scripts/test-env/run.sh"]
fn the_engine_relays_through_turn_over_udp() {
    let env = Env::get();
    relay_through_engine_turn(
        &format!("turn:{}?transport=udp", env.turn_udp),
        RTCIceServerTransportProtocol::Udp,
    );
}

/// RFC 6544 section 5.5 over TURN-TCP (RFC 6062), run by the engine: the offerer behind a
/// symmetric NAT has only relayed TCP candidates (the relay policy, TCP candidates only), the
/// answerer on the WAN only its engine ICE-TCP candidates. The connection runs through
/// coturn's TCP allocation: a Connect from the active relayed candidate to the passive one, or
/// the answerer's active candidate connecting to the relayed address (a ConnectionAttempt);
/// either way a data connection bound with ConnectionBind carries the RFC 4571 stream.
#[test]
#[ignore = "needs the real-network test environment (coturn, NAT namespaces): scripts/test-env/run.sh"]
fn the_engine_connects_over_a_relayed_tcp_candidate() {
    common::install_crypto_provider();
    let env = Env::get();
    let url = format!("turn:{}?transport=tcp", env.turn_tcp);
    let mut messages = vec![b"over a relayed TCP candidate".to_vec(), vec![5u8; 20_000]];
    messages.extend((0..20u8).map(|i| vec![i; 300]));
    let ip_b = testenv::source_ip("open-b", env.turn_tcp).unwrap();
    let (a_tx, b_rx) = std::sync::mpsc::channel();
    let (b_tx, a_rx) = std::sync::mpsc::channel();
    let (u, e, m) = (url.clone(), env.clone(), messages.clone());
    let offerer = std::thread::spawn(move || {
        in_netns("h-symmetric-a", move || {
            peer(true, u, e, a_tx, a_rx, m, None, PeerKind::RelayTcpOnly)
        })
    });
    let (u, e, m) = (url.clone(), env.clone(), messages.clone());
    let answerer = std::thread::spawn(move || {
        in_netns("open-b", move || {
            peer(false, u, e, b_tx, b_rx, m, Some(ip_b), PeerKind::IceTcp)
        })
    });
    let b = answerer.join().unwrap().unwrap();
    let a = offerer.join().unwrap().unwrap();
    eprintln!(
        "TURN-TCP relayed candidate: received {} of {}; offerer relay protocols {:?}",
        b.received.len(),
        messages.len(),
        a.relay_protocols
    );
    assert!(
        a.connected && b.connected,
        "not connected over the relayed TCP candidate"
    );
    assert_eq!(b.received, messages, "every message, in order");
    assert!(
        !a.relay_protocols.is_empty()
            && a.relay_protocols
                .iter()
                .all(|p| *p == RTCIceServerTransportProtocol::Tcp),
        "only relayed TCP candidates: {:?}",
        a.relay_protocols
    );
    assert!(
        a.only_relay,
        "the offerer's application sockets carried nothing"
    );
}
