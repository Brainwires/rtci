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

mod common;
mod testenv;

use bytes::BytesMut;
use rtc::peer_connection::RTCPeerConnectionBuilder;
use rtc::peer_connection::configuration::setting_engine::SettingEngineBuilder;
use rtc::peer_connection::configuration::{RTCConfigurationBuilder, RTCIceTransportPolicy};
use rtc::peer_connection::event::{RTCDataChannelEvent, RTCPeerConnectionEvent};
use rtc::peer_connection::message::RTCMessage;
use rtc::peer_connection::sdp::RTCSessionDescription;
use rtc::peer_connection::state::RTCPeerConnectionState;
use rtc::peer_connection::transport::{
    RTCIceCandidateInit, RTCIceCandidateType, RTCIceServer, RTCIceServerTransportProtocol,
};
use rtc::peer_connection::turn_tls::TurnTlsConfig;
use rtc::sansio::Protocol;
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
            .trim_end_matches("?transport=udp")
            .parse()
            .unwrap_or(env.turn_tls);
        let mut buf = vec![0u8; 2048];
        let mut pc = RTCPeerConnectionBuilder::new()
            .with_configuration(
                RTCConfigurationBuilder::new()
                    .with_ice_servers(vec![RTCIceServer {
                        urls: vec![url],
                        username: env.user.clone(),
                        credential: env.pass.clone(),
                    }])
                    .with_ice_transport_policy(RTCIceTransportPolicy::Relay)
                    .build(),
            )
            .with_setting_engine(
                SettingEngineBuilder::new()
                    .with_turn_tls(TurnTlsConfig {
                        roots: Some(roots(&env)),
                        ..Default::default()
                    })
                    .build(),
            )
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
        let add_host = |pc: &mut rtc::peer_connection::RTCPeerConnection| {
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
                    let _ = pc.handle_read(rtc::shared::TaggedBytesMut {
                        now: Instant::now(),
                        transport: rtc::shared::TransportContext {
                            local_addr: local,
                            peer_addr: from,
                            transport_protocol: rtc::shared::TransportProtocol::UDP,
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

fn relay_through_engine_turn(url: &str, expected: RTCIceServerTransportProtocol) {
    common::install_crypto_provider();
    let env = Env::get();
    let dtls = expected == RTCIceServerTransportProtocol::Dtls;
    let (ip_a, ip_b) = if dtls {
        (
            Some(testenv::source_ip("h-symmetric-a", env.turn_tls).unwrap()),
            Some(testenv::source_ip("h-symmetric-b", env.turn_tls).unwrap()),
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
            peer(true, u, e, a_tx, a_rx, m, ip_a)
        })
    });
    let (u, e, m) = (url.to_owned(), env.clone(), messages.clone());
    let answerer = std::thread::spawn(move || {
        in_netns("h-symmetric-b", move || {
            peer(false, u, e, b_tx, b_rx, m, ip_b)
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
