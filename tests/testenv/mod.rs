//! Support for the tests that need the real-network test environment (`tests/testenv_*.rs`).
//!
//! `scripts/test-env/run.sh` builds a container with Linux network namespaces (NAT routers of
//! every RFC 4787 type, a public "WAN", an mDNS LAN), a coturn STUN/TURN server and netem, and
//! runs these tests inside it with `--ignored`. Outside it they are `#[ignore]`d with the reason
//! spelled out, so a plain `cargo test` lists them as ignored rather than passing them silently.
//!
//! The tests drive sans-I/O peers over real sockets. A socket is created inside a network
//! namespace (`setns(2)` on a short-lived thread) and stays there, so one test process can hold a
//! peer behind a full-cone NAT and another behind a symmetric NAT. Gathering is the
//! application's job in a sans-I/O stack, so `EnvPeer` does it the way an application does: a
//! host candidate from its socket, a server-reflexive one from a STUN Binding, a relayed one from
//! a TURN allocation over UDP, TCP or TLS (`rtc::turn::client`), and it routes the peer
//! connection's writes through the relay when they leave from the relayed address.

#![allow(dead_code)]

use bytes::BytesMut;
use rtc::peer_connection::RTCPeerConnection;
use rtc::peer_connection::event::RTCPeerConnectionEvent;
use rtc::peer_connection::message::TaggedRTCMessage;
use rtc::peer_connection::state::RTCPeerConnectionState;
use rtc::peer_connection::transport::{
    CandidateConfig, CandidateHostConfig, RTCIceCandidate, RTCIceCandidateInit,
};
use rtc::sansio::Protocol;
use rtc::shared::turn_framing::TurnStreamDecoder;
use rtc::shared::{TaggedBytesMut, TransportContext, TransportProtocol};
use rtc::statistics::StatsSelector;
use rtc::statistics::report::RTCStatsReportEntry;
use rtc::turn::client::{Client, ClientConfig, Event as TurnEvent};
use std::collections::{HashMap, HashSet};
use std::io::{self, ErrorKind, Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream, UdpSocket};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// The environment's addresses and credentials, from the variables `run.sh` exports.
#[derive(Clone, Debug)]
pub struct Env {
    pub turn_udp: SocketAddr,
    pub turn_tcp: SocketAddr,
    pub turn_tls: SocketAddr,
    pub turn_tls_name: String,
    pub user: String,
    pub pass: String,
    pub realm: String,
    pub ca_pem: String,
}

impl Env {
    /// The environment, or a panic that says how to get one. Only `--ignored` runs reach this,
    /// and those are meant to run inside the environment.
    pub fn get() -> Env {
        let var = |k: &str| {
            std::env::var(k).unwrap_or_else(|_| {
                panic!(
                    "{k} is not set: this test needs the real-network test environment. \
                     Run it with scripts/test-env/run.sh (see scripts/test-env/README.md)."
                )
            })
        };
        let _ = var("RTC_TESTENV");
        Env {
            turn_udp: var("RTC_TESTENV_TURN_UDP").parse().unwrap(),
            turn_tcp: var("RTC_TESTENV_TURN_TCP").parse().unwrap(),
            turn_tls: var("RTC_TESTENV_TURN_TLS").parse().unwrap(),
            turn_tls_name: var("RTC_TESTENV_TURN_TLS_NAME"),
            user: var("RTC_TESTENV_TURN_USER"),
            pass: var("RTC_TESTENV_TURN_PASS"),
            realm: var("RTC_TESTENV_TURN_REALM"),
            ca_pem: std::fs::read_to_string(var("RTC_TESTENV_TURN_CA")).unwrap(),
        }
    }
}

/// Runs `f` with the calling thread inside network namespace `ns` (`/run/netns/<ns>`); a
/// socket it creates belongs to that namespace for the rest of its life.
pub fn in_netns<T: Send + 'static>(
    ns: &str,
    f: impl FnOnce() -> io::Result<T> + Send + 'static,
) -> io::Result<T> {
    let path = format!("/run/netns/{ns}");
    std::thread::spawn(move || {
        #[cfg(target_os = "linux")]
        {
            use std::os::fd::AsRawFd;
            let file = std::fs::File::open(&path)?;
            // SAFETY: setns on a valid namespace fd; it only affects this short-lived thread.
            if unsafe { libc::setns(file.as_raw_fd(), libc::CLONE_NEWNET) } != 0 {
                return Err(io::Error::last_os_error());
            }
            f()
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = f;
            Err(io::Error::new(
                ErrorKind::Unsupported,
                format!("network namespaces ({path}) need Linux: run scripts/test-env/run.sh"),
            ))
        }
    })
    .join()
    .expect("netns thread panicked")
}

/// The address a namespace's host uses to reach `dst` (its own interface address).
pub fn source_ip(ns: &str, dst: SocketAddr) -> io::Result<IpAddr> {
    in_netns(ns, move || {
        let s = UdpSocket::bind("0.0.0.0:0")?;
        // A LAN without a route to the WAN (the mDNS LAN) still routes multicast.
        if s.connect(dst).is_err() {
            s.connect("224.0.0.251:5353")?;
        }
        Ok(s.local_addr()?.ip())
    })
}

/// How a TURN client reaches the server (the relay itself is always UDP, RFC 8656).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TurnTransport {
    Udp,
    Tcp,
    Tls,
}

/// Which local candidates a peer gathers.
#[derive(Clone, Copy, Debug)]
pub struct Gather {
    pub host: bool,
    pub srflx: bool,
    pub relay: Option<TurnTransport>,
}

impl Gather {
    pub const ALL: Gather = Gather {
        host: true,
        srflx: true,
        relay: Some(TurnTransport::Udp),
    };
    pub const DIRECT: Gather = Gather {
        host: true,
        srflx: true,
        relay: None,
    };
    pub const HOST: Gather = Gather {
        host: true,
        srflx: false,
        relay: None,
    };
    pub const SRFLX_ONLY: Gather = Gather {
        host: false,
        srflx: true,
        relay: None,
    };
    pub fn relay_only(t: TurnTransport) -> Gather {
        Gather {
            host: false,
            srflx: false,
            relay: Some(t),
        }
    }
}

enum Link {
    /// The client shares the peer's UDP socket.
    Udp,
    Tcp {
        stream: TcpStream,
        decoder: TurnStreamDecoder,
    },
    Tls {
        stream: TcpStream,
        conn: Box<rustls::ClientConnection>,
        decoder: TurnStreamDecoder,
    },
}

struct TurnSide {
    client: Client,
    link: Link,
    server: SocketAddr,
    /// The client's own address on the link to the server (the relayed candidate's raddr).
    link_local: SocketAddr,
}

/// A sans-I/O peer connection on real sockets in a network namespace.
pub struct EnvPeer {
    pub name: String,
    pub netns: String,
    pub pc: RTCPeerConnection,
    sock: UdpSocket,
    pub local: SocketAddr,
    /// The mDNS socket (port 5353, joined to 224.0.0.251), when `enable_mdns` was called.
    mdns: Option<UdpSocket>,
    /// STUN (srflx) and TURN clients; one client does both when TURN runs over UDP.
    stun: Option<TurnSide>,
    turn: Option<TurnSide>,
    pub srflx: Option<SocketAddr>,
    pub relay: Option<SocketAddr>,
    perm_pending: HashMap<rtc::stun::message::TransactionId, SocketAddr>,
    perm_requested: HashSet<SocketAddr>,
    perm_granted: HashSet<SocketAddr>,
    pub local_candidates: Vec<RTCIceCandidateInit>,
    pub events: Vec<RTCPeerConnectionEvent>,
    pub reads: Vec<TaggedRTCMessage>,
    pub sent_direct: u64,
    /// Datagrams the socket refused (other than a full buffer, which is waited out).
    pub send_errors: u64,
    pub sent_relayed: u64,
    pub recv_direct: u64,
    pub recv_relayed: u64,
    /// STUN/TURN failures and refused remote candidates, for diagnostics.
    pub errors: Vec<String>,
}

fn turn_config(
    env: &Env,
    server: SocketAddr,
    local: SocketAddr,
    proto: TransportProtocol,
) -> ClientConfig {
    ClientConfig {
        stun_serv_addr: server.to_string(),
        turn_serv_addr: server.to_string(),
        local_addr: local,
        transport_protocol: proto,
        username: env.user.clone(),
        password: env.pass.clone(),
        realm: env.realm.clone(),
        software: String::new(),
        rto_in_ms: 0,
        allocation_refresh_interval_cap: None,
    }
}

fn tls_client_config(env: &Env) -> Arc<rustls::ClientConfig> {
    use rustls::pki_types::CertificateDer;
    use rustls::pki_types::pem::PemObject;
    let mut roots = rustls::RootCertStore::empty();
    for cert in CertificateDer::pem_slice_iter(env.ca_pem.as_bytes()) {
        roots.add(cert.unwrap()).unwrap();
    }
    let provider = rustls::crypto::CryptoProvider::get_default()
        .cloned()
        .expect("install_crypto_provider() first");
    Arc::new(
        // TLS 1.2 only: the environment's coturn (4.6, OpenSSL 3) answers every TLS 1.3
        // ClientHello with a handshake_failure alert, `openssl s_client -tls1_3` included,
        // instead of negotiating down. Its TLS 1.2 (ECDHE-ECDSA-AES-GCM) works.
        rustls::ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS12])
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    )
}

impl EnvPeer {
    /// Binds a UDP socket in `netns`, gathers the candidates `gather` asks for (blocking up to
    /// ten seconds for STUN/TURN), and adds them to `pc`.
    pub fn new(
        name: &str,
        netns: &str,
        gather: Gather,
        env: &Env,
        pc: RTCPeerConnection,
    ) -> io::Result<EnvPeer> {
        let ip = source_ip(netns, env.turn_udp)?;
        let sock = in_netns(netns, move || UdpSocket::bind(SocketAddr::new(ip, 0)))?;
        sock.set_nonblocking(true)?;
        let local = sock.local_addr()?;
        let mut peer = EnvPeer {
            name: name.to_owned(),
            netns: netns.to_owned(),
            pc,
            sock,
            local,
            mdns: None,
            stun: None,
            turn: None,
            srflx: None,
            relay: None,
            perm_pending: HashMap::new(),
            perm_requested: HashSet::new(),
            perm_granted: HashSet::new(),
            local_candidates: vec![],
            events: vec![],
            reads: vec![],
            sent_direct: 0,
            send_errors: 0,
            sent_relayed: 0,
            recv_direct: 0,
            recv_relayed: 0,
            errors: vec![],
        };
        let provider = rtc::crypto::default_provider().map_err(io::Error::other)?;
        let now = Instant::now();

        if let Some(t) = gather.relay {
            let side = match t {
                TurnTransport::Udp => TurnSide {
                    client: Client::new(
                        turn_config(env, env.turn_udp, local, TransportProtocol::UDP),
                        provider.clone(),
                    )
                    .map_err(io::Error::other)?,
                    link: Link::Udp,
                    server: env.turn_udp,
                    link_local: local,
                },
                TurnTransport::Tcp | TurnTransport::Tls => {
                    let server = if t == TurnTransport::Tcp {
                        env.turn_tcp
                    } else {
                        env.turn_tls
                    };
                    let stream = in_netns(netns, move || {
                        TcpStream::connect_timeout(&server, Duration::from_secs(5))
                    })?;
                    stream.set_nodelay(true)?;
                    let link_local = stream.local_addr()?;
                    let link = if t == TurnTransport::Tcp {
                        stream.set_nonblocking(true)?;
                        Link::Tcp {
                            stream,
                            decoder: TurnStreamDecoder::new(),
                        }
                    } else {
                        let name =
                            rustls::pki_types::ServerName::try_from(env.turn_tls_name.clone())
                                .map_err(io::Error::other)?;
                        let mut conn = rustls::ClientConnection::new(tls_client_config(env), name)
                            .map_err(io::Error::other)?;
                        let mut s = stream;
                        s.set_read_timeout(Some(Duration::from_secs(5)))?;
                        while conn.is_handshaking() {
                            conn.complete_io(&mut s)?;
                        }
                        s.set_nonblocking(true)?;
                        Link::Tls {
                            stream: s,
                            conn: Box::new(conn),
                            decoder: TurnStreamDecoder::new(),
                        }
                    };
                    TurnSide {
                        client: Client::new(
                            turn_config(env, server, link_local, TransportProtocol::TCP),
                            provider.clone(),
                        )
                        .map_err(io::Error::other)?,
                        link,
                        server,
                        link_local,
                    }
                }
            };
            peer.turn = Some(side);
            peer.turn
                .as_mut()
                .unwrap()
                .client
                .allocate(now)
                .map_err(io::Error::other)?;
        }
        if gather.srflx {
            let use_turn_udp = matches!(gather.relay, Some(TurnTransport::Udp));
            if !use_turn_udp {
                peer.stun = Some(TurnSide {
                    client: Client::new(
                        turn_config(env, env.turn_udp, local, TransportProtocol::UDP),
                        provider,
                    )
                    .map_err(io::Error::other)?,
                    link: Link::Udp,
                    server: env.turn_udp,
                    link_local: local,
                });
            }
            let side = if use_turn_udp {
                peer.turn.as_mut()
            } else {
                peer.stun.as_mut()
            };
            side.unwrap()
                .client
                .send_binding_request(now)
                .map_err(io::Error::other)?;
        }

        let deadline = Instant::now() + Duration::from_secs(10);
        while (gather.srflx && peer.srflx.is_none())
            || (gather.relay.is_some() && peer.relay.is_none())
        {
            if Instant::now() > deadline {
                return Err(io::Error::new(
                    ErrorKind::TimedOut,
                    format!(
                        "{name}: gathering timed out (srflx {:?}, relay {:?}, errors {:?})",
                        peer.srflx, peer.relay, peer.errors
                    ),
                ));
            }
            peer.step()?;
            std::thread::sleep(Duration::from_millis(2));
        }

        if gather.host {
            peer.add_candidate(
                CandidateHostConfig {
                    base_config: CandidateConfig {
                        network: "udp".to_owned(),
                        address: local.ip().to_string(),
                        port: local.port(),
                        component: 1,
                        ..Default::default()
                    },
                    ..Default::default()
                }
                .new_candidate_host()
                .map_err(io::Error::other)?,
                None,
            )?;
        }
        if let Some(srflx) = peer.srflx {
            peer.add_candidate(
                rtc::ice::candidate::candidate_server_reflexive::CandidateServerReflexiveConfig {
                    base_config: CandidateConfig {
                        network: "udp".to_owned(),
                        address: srflx.ip().to_string(),
                        port: srflx.port(),
                        component: 1,
                        ..Default::default()
                    },
                    rel_addr: local.ip().to_string(),
                    rel_port: local.port(),
                    ..Default::default()
                }
                .new_candidate_server_reflexive()
                .map_err(io::Error::other)?,
                Some(format!("stun:{}", env.turn_udp)),
            )?;
        }
        if let Some(relay) = peer.relay {
            let (link_local, url) = {
                let t = peer.turn.as_ref().unwrap();
                let url = match gather.relay.unwrap() {
                    TurnTransport::Udp => format!("turn:{}?transport=udp", t.server),
                    TurnTransport::Tcp => format!("turn:{}?transport=tcp", t.server),
                    TurnTransport::Tls => format!("turns:{}?transport=tcp", env.turn_tls_name),
                };
                (t.link_local, url)
            };
            peer.add_candidate(
                rtc::ice::candidate::candidate_relay::CandidateRelayConfig {
                    base_config: CandidateConfig {
                        network: "udp".to_owned(),
                        address: relay.ip().to_string(),
                        port: relay.port(),
                        component: 1,
                        ..Default::default()
                    },
                    rel_addr: link_local.ip().to_string(),
                    rel_port: link_local.port(),
                    ..Default::default()
                }
                .new_candidate_relay()
                .map_err(io::Error::other)?,
                Some(url),
            )?;
        }
        Ok(peer)
    }

    /// Opens the peer's mDNS socket (port 5353 on its LAN interface, joined to 224.0.0.251), so
    /// the peer connection's mDNS queries and answers reach the LAN.
    pub fn enable_mdns(&mut self) -> io::Result<()> {
        let IpAddr::V4(ip) = self.local.ip() else {
            return Err(io::Error::other("mDNS needs an IPv4 host address"));
        };
        let sock = in_netns(&self.netns, move || {
            rtc::mdns::MulticastSocket::new()
                .with_interface(ip)
                .into_std()
        })?;
        sock.set_nonblocking(true)?;
        self.mdns = Some(sock);
        Ok(())
    }

    fn add_candidate(
        &mut self,
        c: rtc::ice::candidate::Candidate,
        url: Option<String>,
    ) -> io::Result<()> {
        let mut init = RTCIceCandidate::from(&c)
            .to_json()
            .map_err(io::Error::other)?;
        init.url = url;
        self.pc
            .add_local_candidate(init.clone())
            .map_err(io::Error::other)?;
        self.local_candidates.push(init);
        Ok(())
    }

    /// Adds the other peer's candidates and asks the relay to let their addresses in.
    pub fn add_remote_candidates(&mut self, cands: &[RTCIceCandidateInit]) -> io::Result<()> {
        for c in cands {
            let mut c = c.clone();
            c.url = None;
            if let Some(addr) = candidate_addr(&c.candidate) {
                self.request_permission(addr);
            }
            // The descriptions already carry the candidates gathered before the offer, so a
            // trickled copy may be refused as a duplicate; that is not a failure.
            if let Err(e) = self.pc.add_remote_candidate(c) {
                self.errors.push(format!("add_remote_candidate: {e}"));
            }
        }
        Ok(())
    }

    fn request_permission(&mut self, addr: SocketAddr) {
        let (Some(relay), Some(turn)) = (self.relay, self.turn.as_mut()) else {
            return;
        };
        if !self.perm_requested.insert(addr) {
            return;
        }
        match turn
            .client
            .relay(relay)
            .and_then(|mut r| r.create_permission(Instant::now(), addr))
        {
            Ok(Some(tid)) => {
                self.perm_pending.insert(tid, addr);
            }
            Ok(None) => {
                self.perm_granted.insert(addr);
            }
            Err(e) => self.errors.push(format!("create_permission {addr}: {e}")),
        }
    }

    fn turn_write(side: &mut TurnSide, sock: &UdpSocket) -> io::Result<()> {
        while let Some(t) = side.client.poll_write() {
            match &mut side.link {
                Link::Udp => {
                    let _ = send_nb(sock, &t.message, t.transport.peer_addr);
                }
                Link::Tcp { stream, .. } => write_all_nb(stream, &t.message)?,
                Link::Tls { stream, conn, .. } => {
                    conn.writer().write_all(&t.message)?;
                    while conn.wants_write() {
                        match conn.write_tls(stream) {
                            Ok(_) => {}
                            Err(e) if e.kind() == ErrorKind::WouldBlock => {
                                std::thread::sleep(Duration::from_millis(1))
                            }
                            Err(e) => return Err(e),
                        }
                    }
                }
            }
        }
        Ok(())
    }

    /// Reads whatever a TCP/TLS link has and feeds whole TURN messages to the client.
    fn turn_read_stream(side: &mut TurnSide) -> io::Result<()> {
        let mut buf = [0u8; 8192];
        let (server, local) = (side.server, side.link_local);
        let mut frames = vec![];
        match &mut side.link {
            Link::Udp => return Ok(()),
            Link::Tcp { stream, decoder } => loop {
                match stream.read(&mut buf) {
                    Ok(0) => {
                        return Err(io::Error::new(
                            ErrorKind::ConnectionReset,
                            "TURN TCP closed",
                        ));
                    }
                    Ok(n) => decoder.extend_from_slice(&buf[..n]),
                    Err(e) if e.kind() == ErrorKind::WouldBlock => break,
                    Err(e) => return Err(e),
                }
            },
            Link::Tls {
                stream,
                conn,
                decoder,
            } => loop {
                match conn.read_tls(stream) {
                    Ok(0) => {
                        return Err(io::Error::new(
                            ErrorKind::ConnectionReset,
                            "TURN TLS closed",
                        ));
                    }
                    Ok(_) => {
                        conn.process_new_packets().map_err(io::Error::other)?;
                        loop {
                            match conn.reader().read(&mut buf) {
                                Ok(0) => break,
                                Ok(n) => decoder.extend_from_slice(&buf[..n]),
                                Err(e) if e.kind() == ErrorKind::WouldBlock => break,
                                Err(e) => return Err(e),
                            }
                        }
                    }
                    Err(e) if e.kind() == ErrorKind::WouldBlock => break,
                    Err(e) => return Err(e),
                }
            },
        }
        if let Link::Tcp { decoder, .. } | Link::Tls { decoder, .. } = &mut side.link {
            while let Some(f) = decoder.next_message().map_err(io::Error::other)? {
                frames.push(f);
            }
        }
        for f in frames {
            side.client
                .handle_read(TaggedBytesMut {
                    now: Instant::now(),
                    transport: TransportContext {
                        local_addr: local,
                        peer_addr: server,
                        ecn: None,
                        transport_protocol: TransportProtocol::TCP,
                    },
                    message: BytesMut::from(&f[..]),
                })
                .map_err(io::Error::other)?;
        }
        Ok(())
    }

    /// One turn of the event loop: writes, socket reads, STUN/TURN events, timers, and the peer
    /// connection's events and reads (collected in `events` / `reads`).
    pub fn step(&mut self) -> io::Result<()> {
        let now = Instant::now();
        while let Some(m) = self.pc.poll_write() {
            let peer = m.transport.peer_addr;
            if peer.port() == rtc::mdns::MDNS_PORT
                && let Some(mdns) = &self.mdns
            {
                let _ = mdns.send_to(&m.message, peer);
            } else if self.relay.is_some() && Some(m.transport.local_addr) == self.relay {
                self.request_permission(peer);
                if self.perm_granted.contains(&peer) {
                    let relay = self.relay.unwrap();
                    let t = self.turn.as_mut().unwrap();
                    match t
                        .client
                        .relay(relay)
                        .and_then(|mut r| r.send_to(now, &m.message, peer))
                    {
                        Ok(()) => self.sent_relayed += 1,
                        Err(e) => self.errors.push(format!("relay send {peer}: {e}")),
                    }
                }
            } else {
                // A full socket buffer (EAGAIN on this non-blocking socket) is waited out, not
                // dropped: a burst would otherwise lose datagrams the protocol under test never
                // lost. Other failures (unreachable) are a lost datagram, which ICE retransmits.
                match send_nb(&self.sock, &m.message, peer) {
                    Ok(()) => self.sent_direct += 1,
                    Err(_) => self.send_errors += 1,
                }
            }
        }
        for side in [self.turn.as_mut(), self.stun.as_mut()]
            .into_iter()
            .flatten()
        {
            Self::turn_write(side, &self.sock)?;
        }

        let mut buf = [0u8; 2048];
        loop {
            match self.sock.recv_from(&mut buf) {
                Ok((n, from)) => {
                    let msg = TaggedBytesMut {
                        now: Instant::now(),
                        transport: TransportContext {
                            local_addr: self.local,
                            peer_addr: from,
                            ecn: None,
                            transport_protocol: TransportProtocol::UDP,
                        },
                        message: BytesMut::from(&buf[..n]),
                    };
                    let udp_turn = self
                        .turn
                        .as_mut()
                        .filter(|t| matches!(t.link, Link::Udp) && t.server == from);
                    if let Some(t) = udp_turn {
                        let _ = t.client.handle_read(msg);
                    } else if let Some(s) = self.stun.as_mut().filter(|s| s.server == from) {
                        let _ = s.client.handle_read(msg);
                    } else {
                        self.recv_direct += 1;
                        let _ = self.pc.handle_read(msg);
                    }
                }
                Err(e) if e.kind() == ErrorKind::WouldBlock => break,
                Err(e) if e.kind() == ErrorKind::ConnectionRefused => continue,
                Err(e) => return Err(e),
            }
        }
        if let Some(t) = self.turn.as_mut() {
            Self::turn_read_stream(t)?;
        }
        if let Some(mdns) = &self.mdns {
            let local_addr = mdns.local_addr()?;
            loop {
                match mdns.recv_from(&mut buf) {
                    Ok((n, from)) => {
                        let _ = self.pc.handle_read(TaggedBytesMut {
                            now: Instant::now(),
                            transport: TransportContext {
                                local_addr,
                                peer_addr: from,
                                ecn: None,
                                transport_protocol: TransportProtocol::UDP,
                            },
                            message: BytesMut::from(&buf[..n]),
                        });
                    }
                    Err(e) if e.kind() == ErrorKind::WouldBlock => break,
                    Err(e) => return Err(e),
                }
            }
        }

        for which in 0..2 {
            let side = if which == 0 {
                self.turn.as_mut()
            } else {
                self.stun.as_mut()
            };
            let Some(side) = side else { continue };
            let mut relayed_in = vec![];
            while let Some(ev) = side.client.poll_event() {
                match ev {
                    TurnEvent::BindingResponse(_, addr) => self.srflx = Some(addr),
                    TurnEvent::AllocateResponse(_, addr) => self.relay = Some(addr),
                    TurnEvent::CreatePermissionResponse(tid, addr) => {
                        let a = self.perm_pending.remove(&tid).unwrap_or(addr);
                        self.perm_granted.insert(a);
                    }
                    TurnEvent::DataIndicationOrChannelData(_, from, data) => {
                        relayed_in.push((from, data))
                    }
                    TurnEvent::TransactionTimeout(tid) => {
                        self.errors.push(format!("transaction timeout {tid:?}"))
                    }
                    TurnEvent::BindingError(_, e)
                    | TurnEvent::AllocateError(_, e)
                    | TurnEvent::CreatePermissionError(_, e) => self.errors.push(e.to_string()),
                    _ => {}
                }
            }
            if let Some(relay) = self.relay {
                for (from, data) in relayed_in {
                    self.recv_relayed += 1;
                    let _ = self.pc.handle_read(TaggedBytesMut {
                        now: Instant::now(),
                        transport: TransportContext {
                            local_addr: relay,
                            peer_addr: from,
                            ecn: None,
                            transport_protocol: TransportProtocol::UDP,
                        },
                        message: BytesMut::from(&data[..]),
                    });
                }
            }
        }

        let now = Instant::now();
        if self.pc.poll_timeout().is_some_and(|t| t <= now) {
            let _ = self.pc.handle_timeout(now);
        }
        for side in [self.turn.as_mut(), self.stun.as_mut()]
            .into_iter()
            .flatten()
        {
            if side.client.poll_timeout().is_some_and(|t| t <= now) {
                let _ = side.client.handle_timeout(now);
            }
        }
        while let Some(e) = self.pc.poll_event() {
            self.events.push(e);
        }
        while let Some(m) = self.pc.poll_read() {
            self.reads.push(m);
        }
        Ok(())
    }

    pub fn connection_state(&self) -> Option<RTCPeerConnectionState> {
        self.events.iter().rev().find_map(|e| match e {
            RTCPeerConnectionEvent::OnConnectionStateChangeEvent(s) => Some(*s),
            _ => None,
        })
    }

    pub fn connected(&self) -> bool {
        self.connection_state() == Some(RTCPeerConnectionState::Connected)
    }

    pub fn failed(&self) -> bool {
        self.connection_state() == Some(RTCPeerConnectionState::Failed)
    }

    /// The selected pair's local and remote candidate types ("host", "srflx", "prflx",
    /// "relay"), from the W3C stats.
    pub fn selected_pair_types(&mut self) -> Option<(String, String)> {
        let report = self.pc.get_stats(Instant::now(), StatsSelector::None);
        let pair_id = report.transport()?.selected_candidate_pair_id.clone();
        let pair = report.candidate_pairs().find(|p| p.stats.id == pair_id)?;
        let ty = |id: &str| match report.get(id) {
            Some(RTCStatsReportEntry::LocalCandidate(c))
            | Some(RTCStatsReportEntry::RemoteCandidate(c)) => Some(c.candidate_type.to_string()),
            _ => None,
        };
        Some((
            ty(&pair.local_candidate_id)?,
            ty(&pair.remote_candidate_id)?,
        ))
    }
}

fn send_nb(sock: &UdpSocket, data: &[u8], to: SocketAddr) -> io::Result<()> {
    let deadline = Instant::now() + Duration::from_secs(1);
    loop {
        match sock.send_to(data, to) {
            Ok(_) => return Ok(()),
            Err(e) if e.kind() == ErrorKind::WouldBlock && Instant::now() < deadline => {
                std::thread::sleep(Duration::from_micros(200))
            }
            Err(e) => return Err(e),
        }
    }
}

fn write_all_nb(stream: &mut TcpStream, mut data: &[u8]) -> io::Result<()> {
    while !data.is_empty() {
        match stream.write(data) {
            Ok(n) => data = &data[n..],
            Err(e) if e.kind() == ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(1))
            }
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

/// `<ip> <port>` of an ICE candidate line.
pub fn candidate_addr(line: &str) -> Option<SocketAddr> {
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() < 6 {
        return None;
    }
    Some(SocketAddr::new(
        parts[4].parse().ok()?,
        parts[5].parse().ok()?,
    ))
}

/// Offer from `a`, answer from `b`, then trickle each side's candidates to the other.
pub fn negotiate(a: &mut EnvPeer, b: &mut EnvPeer) -> io::Result<()> {
    let e = io::Error::other;
    let offer = a.pc.create_offer(None).map_err(e)?;
    a.pc.set_local_description(Instant::now(), offer.clone())
        .map_err(e)?;
    b.pc.set_remote_description(Instant::now(), offer)
        .map_err(e)?;
    let answer = b.pc.create_answer(None).map_err(e)?;
    b.pc.set_local_description(Instant::now(), answer.clone())
        .map_err(e)?;
    a.pc.set_remote_description(Instant::now(), answer)
        .map_err(e)?;
    let (ca, cb) = (a.local_candidates.clone(), b.local_candidates.clone());
    a.add_remote_candidates(&cb)?;
    b.add_remote_candidates(&ca)?;
    Ok(())
}

/// Offer from `a`, answer from `b`, with no trickling: each side learns the other's candidates
/// only from the descriptions (where an mDNS-hiding peer writes `.local` names). Returns the
/// offer's and the answer's SDP.
pub fn negotiate_in_sdp(a: &mut EnvPeer, b: &mut EnvPeer) -> io::Result<(String, String)> {
    let e = io::Error::other;
    let offer = a.pc.create_offer(None).map_err(e)?;
    a.pc.set_local_description(Instant::now(), offer.clone())
        .map_err(e)?;
    let offer_sdp = offer.sdp.clone();
    b.pc.set_remote_description(Instant::now(), offer)
        .map_err(e)?;
    let answer = b.pc.create_answer(None).map_err(e)?;
    b.pc.set_local_description(Instant::now(), answer.clone())
        .map_err(e)?;
    let answer_sdp = answer.sdp.clone();
    a.pc.set_remote_description(Instant::now(), answer)
        .map_err(e)?;
    Ok((offer_sdp, answer_sdp))
}

/// Steps every peer until `done` holds or `timeout` passes; returns whether `done` held.
pub fn pump(
    peers: &mut [&mut EnvPeer],
    timeout: Duration,
    mut done: impl FnMut(&mut [&mut EnvPeer]) -> bool,
) -> io::Result<bool> {
    let deadline = Instant::now() + timeout;
    loop {
        for p in peers.iter_mut() {
            p.step()?;
        }
        if done(peers) {
            return Ok(true);
        }
        if Instant::now() > deadline {
            return Ok(false);
        }
        std::thread::sleep(Duration::from_micros(500));
    }
}
