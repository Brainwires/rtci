//! ICE over TCP (RFC 6544) through a NAT, on real sockets in the test environment
//! (`scripts/test-env/run.sh`); ignored elsewhere.
//!
//! One peer sits behind a symmetric NAT (`h-symmetric-a`) with an active TCP candidate: its
//! LAN address and port 9 (RFC 6544 4.5). The other is a public host (`open-b`) with a passive
//! candidate, a real listener. The active side's connection reaches the passive side from the
//! NAT's public address and a port the NAT chose, which the passive agent learns as a
//! peer-reflexive candidate (RFC 6544 7.2.2, RFC 8445 7.3.1.3). Both agents are TCP-only, so
//! nothing can fall back to UDP. Every packet on a connection is framed with RFC 4571's 16-bit
//! length (`rtc::shared::tcp_framing`).

mod common;
mod testenv;

use bytes::BytesMut;
use rtc::data_channel::RTCDataChannelId;
use rtc::ice::network_type::NetworkType;
use rtc::ice::tcp_type::TcpType;
use rtc::peer_connection::configuration::setting_engine::SettingEngineBuilder;
use rtc::peer_connection::event::{RTCDataChannelEvent, RTCPeerConnectionEvent};
use rtc::peer_connection::message::RTCMessage;
use rtc::peer_connection::state::RTCPeerConnectionState;
use rtc::peer_connection::transport::{CandidateConfig, CandidateHostConfig, RTCIceCandidate};
use rtc::peer_connection::{RTCPeerConnection, RTCPeerConnectionBuilder};
use rtc::sansio::Protocol;
use rtc::shared::tcp_framing::{TcpFrameDecoder, frame_packet};
use rtc::shared::{TaggedBytesMut, TransportContext, TransportProtocol};
use std::io::{self, ErrorKind, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::time::{Duration, Instant};
use testenv::{Env, in_netns, source_ip};

/// The port signalled for an active candidate (RFC 6544 4.5).
const ACTIVE_PORT: u16 = 9;

struct Conn {
    stream: TcpStream,
    /// This end's address, as the peer connection is told it.
    local: SocketAddr,
    /// The other end's address as this host sees it (after the NAT, on the passive side).
    remote: SocketAddr,
    decoder: TcpFrameDecoder,
}

struct TcpPeer {
    name: &'static str,
    netns: &'static str,
    pc: RTCPeerConnection,
    tcp_type: TcpType,
    /// The candidate's address: the LAN address (port 9) for active, the listener for passive.
    addr: SocketAddr,
    listener: Option<TcpListener>,
    conns: Vec<Conn>,
    events: Vec<RTCPeerConnectionEvent>,
    received: Vec<Vec<u8>>,
    /// Writes the agent made over UDP (must stay 0) or that had no connection to go on.
    udp_writes: u64,
    unroutable: u64,
}

impl TcpPeer {
    fn new(name: &'static str, netns: &'static str, tcp_type: TcpType, env: &Env) -> TcpPeer {
        let pc = RTCPeerConnectionBuilder::new()
            .with_setting_engine(
                SettingEngineBuilder::new()
                    .with_network_types(vec![NetworkType::Tcp4])
                    .build(),
            )
            .build(Instant::now())
            .unwrap();
        // The host's own address toward the WAN (the TURN server's host is on it).
        let ip = source_ip(netns, env.turn_udp).expect("source address");
        let (addr, listener) = if tcp_type == TcpType::Passive {
            let l = in_netns(netns, move || TcpListener::bind(SocketAddr::new(ip, 0)))
                .expect("listener");
            l.set_nonblocking(true).unwrap();
            (l.local_addr().unwrap(), Some(l))
        } else {
            (SocketAddr::new(ip, ACTIVE_PORT), None)
        };
        TcpPeer {
            name,
            netns,
            pc,
            tcp_type,
            addr,
            listener,
            conns: vec![],
            events: vec![],
            received: vec![],
            udp_writes: 0,
            unroutable: 0,
        }
    }

    fn candidate(&self) -> rtc::peer_connection::transport::RTCIceCandidateInit {
        let c = CandidateHostConfig {
            base_config: CandidateConfig {
                network: "tcp".to_owned(),
                address: self.addr.ip().to_string(),
                port: self.addr.port(),
                component: 1,
                ..Default::default()
            },
            tcp_type: self.tcp_type,
        }
        .new_candidate_host()
        .unwrap();
        RTCIceCandidate::from(&c).to_json().unwrap()
    }

    fn connected(&self) -> bool {
        self.events.iter().rev().find_map(|e| match e {
            RTCPeerConnectionEvent::OnConnectionStateChangeEvent(s) => Some(*s),
            _ => None,
        }) == Some(RTCPeerConnectionState::Connected)
    }

    fn channel_open(&self) -> Option<RTCDataChannelId> {
        self.events.iter().find_map(|e| match e {
            RTCPeerConnectionEvent::OnDataChannel(RTCDataChannelEvent::OnOpen(id)) => Some(*id),
            _ => None,
        })
    }

    fn step(&mut self) -> io::Result<()> {
        while let Some(m) = self.pc.poll_write() {
            if m.transport.transport_protocol != TransportProtocol::TCP {
                self.udp_writes += 1;
                continue;
            }
            let to = m.transport.peer_addr;
            let index = match self.conns.iter().position(|c| c.remote == to) {
                Some(i) => Some(i),
                // Only the active side opens connections (RFC 6544 4.1), to the address of a
                // passive candidate it was given.
                None if self.tcp_type == TcpType::Active => {
                    match in_netns(self.netns, move || {
                        TcpStream::connect_timeout(&to, Duration::from_secs(5))
                    }) {
                        Ok(stream) => {
                            stream.set_nodelay(true)?;
                            stream.set_nonblocking(true)?;
                            let local = stream.local_addr()?;
                            self.conns.push(Conn {
                                stream,
                                local,
                                remote: to,
                                decoder: TcpFrameDecoder::new(),
                            });
                            Some(self.conns.len() - 1)
                        }
                        Err(_) => None,
                    }
                }
                None => None,
            };
            match index {
                Some(i) => write_all(&mut self.conns[i].stream, &frame_packet(&m.message))?,
                None => self.unroutable += 1,
            }
        }
        if let Some(l) = &self.listener {
            loop {
                match l.accept() {
                    Ok((stream, from)) => {
                        stream.set_nodelay(true)?;
                        stream.set_nonblocking(true)?;
                        self.conns.push(Conn {
                            stream,
                            local: self.addr,
                            remote: from,
                            decoder: TcpFrameDecoder::new(),
                        });
                    }
                    Err(e) if e.kind() == ErrorKind::WouldBlock => break,
                    Err(e) => return Err(e),
                }
            }
        }
        let mut buf = [0u8; 16384];
        for c in self.conns.iter_mut() {
            loop {
                match c.stream.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => c.decoder.extend_from_slice(&buf[..n]),
                    Err(e) if e.kind() == ErrorKind::WouldBlock => break,
                    Err(e) if e.kind() == ErrorKind::ConnectionReset => break,
                    Err(e) => return Err(e),
                }
            }
            while let Some(p) = c.decoder.next_packet() {
                let _ = self.pc.handle_read(TaggedBytesMut {
                    now: Instant::now(),
                    transport: TransportContext {
                        local_addr: c.local,
                        peer_addr: c.remote,
                        ecn: None,
                        transport_protocol: TransportProtocol::TCP,
                    },
                    message: BytesMut::from(&p[..]),
                });
            }
        }
        let now = Instant::now();
        if self.pc.poll_timeout().is_some_and(|t| t <= now) {
            let _ = self.pc.handle_timeout(now);
        }
        while let Some(e) = self.pc.poll_event() {
            self.events.push(e);
        }
        while let Some(m) = self.pc.poll_read() {
            if let RTCMessage::DataChannelMessage(_, msg) = m.message {
                self.received.push(msg.data.to_vec());
            }
        }
        Ok(())
    }
}

fn write_all(stream: &mut TcpStream, mut data: &[u8]) -> io::Result<()> {
    let deadline = Instant::now() + Duration::from_secs(5);
    while !data.is_empty() {
        match stream.write(data) {
            Ok(n) => data = &data[n..],
            Err(e) if e.kind() == ErrorKind::WouldBlock && Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(1))
            }
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

fn messages() -> Vec<Vec<u8>> {
    // A small message, one larger than a datagram could carry, and a run of ordered ones.
    let mut out = vec![b"over tcp through a nat".to_vec(), vec![7u8; 60_000]];
    out.extend((0..50u8).map(|i| vec![i; 100]));
    out
}

/// `active_offers`: the peer behind the NAT (active) makes the offer; otherwise the public
/// passive peer does, and is then the controlling agent.
fn ice_tcp_through_nat(active_offers: bool) {
    common::install_crypto_provider();
    let env = Env::get();
    let active = TcpPeer::new("active", "h-symmetric-a", TcpType::Active, &env);
    let passive = TcpPeer::new("passive", "open-b", TcpType::Passive, &env);
    let (mut offerer, mut answerer) = if active_offers {
        (active, passive)
    } else {
        (passive, active)
    };
    let channel = offerer
        .pc
        .create_data_channel("ice-tcp", None)
        .unwrap()
        .id();
    let offer = offerer.pc.create_offer(None).unwrap();
    offerer
        .pc
        .set_local_description(Instant::now(), offer.clone())
        .unwrap();
    answerer
        .pc
        .set_remote_description(Instant::now(), offer)
        .unwrap();
    let answer = answerer.pc.create_answer(None).unwrap();
    answerer
        .pc
        .set_local_description(Instant::now(), answer.clone())
        .unwrap();
    offerer
        .pc
        .set_remote_description(Instant::now(), answer)
        .unwrap();
    let (co, ca) = (offerer.candidate(), answerer.candidate());
    offerer.pc.add_local_candidate(co.clone()).unwrap();
    answerer.pc.add_local_candidate(ca.clone()).unwrap();
    offerer.pc.add_remote_candidate(ca).unwrap();
    answerer.pc.add_remote_candidate(co).unwrap();

    let expected = messages();
    let mut sent = false;
    let deadline = Instant::now() + Duration::from_secs(30);
    while Instant::now() < deadline {
        offerer.step().unwrap();
        answerer.step().unwrap();
        if !sent && offerer.channel_open() == Some(channel) {
            let mut dc = offerer.pc.data_channel(channel).unwrap();
            for m in &expected {
                dc.send(Instant::now(), BytesMut::from(&m[..])).unwrap();
            }
            sent = true;
        }
        if sent && answerer.received.len() >= expected.len() {
            break;
        }
        std::thread::sleep(Duration::from_micros(500));
    }
    let (active, passive) = if active_offers {
        (&offerer, &answerer)
    } else {
        (&answerer, &offerer)
    };
    eprintln!(
        "ICE-TCP through a symmetric NAT (active offers: {active_offers}): active {} connections \
         {:?}, passive saw {:?}; received {} of {}; unroutable writes {} / {}",
        active.name,
        active
            .conns
            .iter()
            .map(|c| (c.local, c.remote))
            .collect::<Vec<_>>(),
        passive.conns.iter().map(|c| c.remote).collect::<Vec<_>>(),
        answerer.received.len(),
        expected.len(),
        active.unroutable,
        passive.unroutable,
    );
    assert!(
        offerer.connected() && answerer.connected(),
        "not connected over TCP"
    );
    assert_eq!(answerer.received, expected, "every message, in order");
    assert_eq!(
        active.udp_writes + passive.udp_writes,
        0,
        "a TCP-only agent wrote UDP"
    );
    // The connection really crossed the NAT: the passive side sees a public address that is
    // not the active candidate's LAN address.
    assert!(
        !passive.conns.is_empty(),
        "the passive side accepted nothing"
    );
    for c in &passive.conns {
        assert_ne!(
            c.remote.ip(),
            active.addr.ip(),
            "the connection did not go through the NAT"
        );
        assert!(
            c.remote.ip().to_string().starts_with("203.0.113."),
            "the passive side saw {}, not the NAT's public address",
            c.remote
        );
    }
}

#[test]
#[ignore = "needs the real-network test environment (NAT namespaces): scripts/test-env/run.sh"]
fn ice_tcp_active_behind_a_nat_offers_to_a_public_passive_peer() {
    ice_tcp_through_nat(true);
}

#[test]
#[ignore = "needs the real-network test environment (NAT namespaces): scripts/test-env/run.sh"]
fn ice_tcp_public_passive_peer_offers_to_an_active_peer_behind_a_nat() {
    ice_tcp_through_nat(false);
}

/// Signalling between the two peer threads of the built-in case, as JSON.
enum Signal {
    Description(String),
    Candidate(String),
    /// The answerer has every message.
    Done,
}

/// One peer of the built-in case: the application adds a UDP host candidate and sends no UDP
/// at all (UDP is "blocked"); the engine gathers its TCP candidates and drives its connections
/// through the tokio reference driver, whose sockets live in the peer's namespace.
fn engine_tcp_peer(
    offerer: bool,
    ip: std::net::IpAddr,
    tx: std::sync::mpsc::Sender<Signal>,
    rx: std::sync::mpsc::Receiver<Signal>,
    messages: Vec<Vec<u8>>,
) -> io::Result<(bool, Vec<Vec<u8>>, String)> {
    use rtc::peer_connection::sdp::RTCSessionDescription;
    use rtc::peer_connection::transport::RTCIceCandidateInit;
    use stream_driver::{DriverInput, StreamDriver};
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async move {
        let mut pc = RTCPeerConnectionBuilder::new()
            .build(Instant::now())
            .unwrap();
        let mut driver = StreamDriver::default();
        let host = RTCIceCandidateInit {
            candidate: format!("candidate:1 1 udp 2130706431 {ip} 4000 typ host"),
            ..Default::default()
        };
        let mut channel = None;
        if offerer {
            channel = Some(pc.create_data_channel("engine-tcp", None).unwrap().id());
            let offer = pc.create_offer(None).unwrap();
            pc.set_local_description(Instant::now(), offer.clone())
                .unwrap();
            let _ = tx.send(Signal::Description(serde_json::to_string(&offer).unwrap()));
            pc.add_local_candidate(host.clone()).unwrap();
        }
        let mut received = vec![];
        let mut sent = false;
        let mut connected = false;
        let mut selected = String::new();
        let deadline = Instant::now() + Duration::from_secs(30);
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
                            let _ = tx
                                .send(Signal::Description(serde_json::to_string(&answer).unwrap()));
                            pc.add_local_candidate(host.clone()).unwrap();
                        }
                    }
                    Signal::Candidate(json) => {
                        let c: RTCIceCandidateInit = serde_json::from_str(&json).unwrap();
                        let _ = pc.add_remote_candidate(c);
                    }
                    Signal::Done => return Ok((connected, received, selected)),
                }
            }
            while let Some(command) = pc.poll_stream_command() {
                driver.execute(command);
            }
            while let Some(transmit) = pc.poll_stream_transmit() {
                driver.write(transmit);
            }
            // UDP is blocked: nothing written for it leaves.
            while pc.poll_write().is_some() {}
            while let Some(e) = pc.poll_event() {
                match e {
                    RTCPeerConnectionEvent::OnIceCandidateEvent(ev) => {
                        if let Some(c) = ev.candidate.filter(|c| !c.end_of_candidates)
                            && let Ok(init) = c.to_json()
                        {
                            let _ =
                                tx.send(Signal::Candidate(serde_json::to_string(&init).unwrap()));
                        }
                    }
                    RTCPeerConnectionEvent::OnConnectionStateChangeEvent(
                        RTCPeerConnectionState::Connected,
                    ) => connected = true,
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
                    received.push(msg.data.to_vec());
                }
            }
            if connected && selected.is_empty() {
                let report = pc.get_stats(Instant::now(), rtc::statistics::StatsSelector::None);
                if let Some(pair) = report.candidate_pairs().find(|p| p.nominated) {
                    selected = format!(
                        "{} -> {}",
                        pair.local_candidate_id, pair.remote_candidate_id
                    );
                }
            }
            if !offerer && received.len() >= messages.len() {
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
        Ok((connected, received, selected))
    })
}

/// ICE-TCP built into the engine through a NAT, with UDP blocked: each application adds only a
/// UDP host candidate (and never sends UDP); the engine gathers passive, simultaneous-open and
/// active TCP candidates and the tokio reference driver (`examples/stream-driver`) owns the
/// sockets. The peer behind the symmetric NAT can only reach the public one through its
/// active candidate.
fn engine_tcp_through_nat(nat_side_offers: bool) {
    common::install_crypto_provider();
    let env = Env::get();
    let messages = messages();
    let (nat_ns, public_ns) = ("h-symmetric-a", "open-b");
    let nat_ip = source_ip(nat_ns, env.turn_udp).expect("source address");
    let public_ip = source_ip(public_ns, env.turn_udp).expect("source address");
    let (a_tx, b_rx) = std::sync::mpsc::channel();
    let (b_tx, a_rx) = std::sync::mpsc::channel();
    let (offer_ns, offer_ip, answer_ns, answer_ip) = if nat_side_offers {
        (nat_ns, nat_ip, public_ns, public_ip)
    } else {
        (public_ns, public_ip, nat_ns, nat_ip)
    };
    let m = messages.clone();
    let offerer = std::thread::spawn(move || {
        in_netns(offer_ns, move || {
            engine_tcp_peer(true, offer_ip, a_tx, a_rx, m)
        })
    });
    let m = messages.clone();
    let answerer = std::thread::spawn(move || {
        in_netns(answer_ns, move || {
            engine_tcp_peer(false, answer_ip, b_tx, b_rx, m)
        })
    });
    let (answer_connected, received, answer_pair) = answerer.join().unwrap().unwrap();
    let (offer_connected, _, offer_pair) = offerer.join().unwrap().unwrap();
    eprintln!(
        "ICE-TCP built in (NAT side offers: {nat_side_offers}): received {} of {}; pairs {offer_pair} / {answer_pair}",
        received.len(),
        messages.len()
    );
    assert!(
        offer_connected && answer_connected,
        "not connected over the engine's TCP"
    );
    assert_eq!(received, messages, "every message, in order");
}

#[test]
#[ignore = "needs the real-network test environment (NAT namespaces): scripts/test-env/run.sh"]
fn engine_gathered_tcp_connects_through_a_nat_with_udp_blocked_nat_side_offering() {
    engine_tcp_through_nat(true);
}

#[test]
#[ignore = "needs the real-network test environment (NAT namespaces): scripts/test-env/run.sh"]
fn engine_gathered_tcp_connects_through_a_nat_with_udp_blocked_public_side_offering() {
    engine_tcp_through_nat(false);
}
