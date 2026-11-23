//! The TURN client (`rtc::turn::client`) against a real TURN server, in the real-network test
//! environment (`scripts/test-env/run.sh`); ignored elsewhere.
//!
//! The unit tests in `rtc-turn` script the server's answers. These prove the claims that need
//! a server to agree: that coturn takes the Allocate options the client sends (RFC 8656 7.1),
//! gives the relayed addresses asked for, relays a Send indication carrying DONT-FRAGMENT, and
//! refuses what the RFC says a server refuses; and that a TCP allocation (RFC 6062) connects
//! to a peer and accepts one, each over a data connection that carries the bytes as they are.
//! The environment's third coturn (`scripts/test-env/coturn/turnserver-client.conf`, port 3480)
//! relays on an IPv4 and an IPv6 address and knows two users.

mod common;
mod testenv;

use bytes::BytesMut;
use rtc::ice::agent::agent_config::AgentConfig;
use rtc::ice::agent::{Agent, Event as IceEvent};
use rtc::ice::candidate::candidate_host::CandidateHostConfig;
use rtc::ice::candidate::candidate_relay::CandidateRelayConfig;
use rtc::ice::candidate::candidate_server_reflexive::CandidateServerReflexiveConfig;
use rtc::ice::candidate::{CandidateConfig, CandidateType};
use rtc::ice::mdns::MulticastDnsMode;
use rtc::ice::network_type::NetworkType;
use rtc::ice::state::ConnectionState;
use rtc::ice::tcp_type::TcpType;
use rtc::sansio::Protocol;
use rtc::shared::tcp_framing::{TcpFrameDecoder, frame_packet};
use rtc::shared::turn_framing::TurnStreamDecoder;
use rtc::shared::{TaggedBytesMut, TransportContext, TransportProtocol};
use rtc::stun::error_code::{CODE_ADDR_FAMILY_NOT_SUPPORTED, CODE_UNAUTHORIZED};
use rtc::turn::client::data_connection::{DataConnection, DataConnectionEvent};
use rtc::turn::client::{
    AllocateOptions, Client, ClientConfig, Event, RelayTransport, RetransmissionConfig,
};
use rtc::turn::proto::connid::ConnectionId;
use rtc::turn::proto::evenport::EvenPort;
use rtc::turn::proto::reqfamily::{REQUESTED_FAMILY_IPV4, REQUESTED_FAMILY_IPV6};
use std::io::{self, ErrorKind, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::sync::Arc;
use std::time::{Duration, Instant};
use testenv::{Env, in_netns, source_ip};

/// How long any one answer from the server may take.
const ANSWER: Duration = Duration::from_secs(10);

fn client_server() -> SocketAddr {
    std::env::var("RTC_TESTENV_TURN_CLIENT")
        .expect(
            "RTC_TESTENV_TURN_CLIENT is not set: this test needs the real-network test \
             environment (scripts/test-env/run.sh), whose coturn/start.sh starts that server",
        )
        .parse()
        .unwrap()
}

/// A UDP socket in namespace `ns`, on the address that namespace reaches `server` from.
fn socket_in(ns: &'static str, server: SocketAddr) -> io::Result<UdpSocket> {
    let ip = source_ip(ns, server)?;
    let sock = in_netns(ns, move || UdpSocket::bind((ip, 0)))?;
    sock.set_nonblocking(true)?;
    Ok(sock)
}

/// A TCP connection from namespace `ns` to `to`, non-blocking.
fn connect_in(ns: &'static str, to: SocketAddr) -> io::Result<TcpStream> {
    let stream = in_netns(ns, move || {
        TcpStream::connect_timeout(&to, Duration::from_secs(5))
    })?;
    stream.set_nodelay(true)?;
    stream.set_nonblocking(true)?;
    Ok(stream)
}

fn write_all(stream: &mut TcpStream, mut data: &[u8]) -> io::Result<()> {
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

/// How the client reaches the server: a UDP socket, or a TCP connection whose stream is cut
/// into TURN messages (RFC 8656 3.1).
enum Link {
    Udp(UdpSocket),
    Tcp(TcpStream, TurnStreamDecoder),
}

/// A sans-I/O TURN client on a real socket.
struct TurnPeer {
    client: Client,
    link: Link,
    server: SocketAddr,
    local: SocketAddr,
    events: Vec<Event>,
}

impl TurnPeer {
    fn new(ns: &'static str, server: SocketAddr, user: &str, pass: &str) -> io::Result<Self> {
        let sock = socket_in(ns, server)?;
        let local = sock.local_addr()?;
        Self::on(Link::Udp(sock), server, local, user, pass)
    }

    /// A client over TCP: the control connection a TCP allocation needs (RFC 6062 4.1).
    fn over_tcp(ns: &'static str, server: SocketAddr, user: &str, pass: &str) -> io::Result<Self> {
        let stream = connect_in(ns, server)?;
        let local = stream.local_addr()?;
        Self::on(
            Link::Tcp(stream, TurnStreamDecoder::new()),
            server,
            local,
            user,
            pass,
        )
    }

    /// A client over UDP whose requests give up after 700 ms (sent at 0, 100 and 300 ms), for
    /// a test that waits for a request to fail.
    fn impatient(ns: &'static str, server: SocketAddr, user: &str, pass: &str) -> io::Result<Self> {
        let mut peer = Self::new(ns, server, user, pass)?;
        let retransmission = RetransmissionConfig {
            rc: 3,
            rm: 4,
            ..Default::default()
        };
        peer.client = Client::new(
            ClientConfig {
                turn_serv_addr: server.to_string(),
                local_addr: peer.local,
                transport_protocol: TransportProtocol::UDP,
                username: user.to_owned(),
                password: pass.to_owned(),
                software: "rtc test-env".to_owned(),
                rto_in_ms: 100,
                retransmission,
                ..Default::default()
            },
            rtc::crypto::default_provider().map_err(io::Error::other)?,
        )
        .map_err(io::Error::other)?;
        Ok(peer)
    }

    fn on(
        link: Link,
        server: SocketAddr,
        local: SocketAddr,
        user: &str,
        pass: &str,
    ) -> io::Result<Self> {
        let transport_protocol = match link {
            Link::Udp(_) => TransportProtocol::UDP,
            Link::Tcp(..) => TransportProtocol::TCP,
        };
        let client = Client::new(
            ClientConfig {
                turn_serv_addr: server.to_string(),
                local_addr: local,
                transport_protocol,
                username: user.to_owned(),
                password: pass.to_owned(),
                software: "rtc test-env".to_owned(),
                ..Default::default()
            },
            rtc::crypto::default_provider().map_err(io::Error::other)?,
        )
        .map_err(io::Error::other)?;
        Ok(TurnPeer {
            client,
            link,
            server,
            local,
            events: vec![],
        })
    }

    /// One turn of the loop: what the client queued goes out, what the socket holds comes in,
    /// a due timer runs, events are collected.
    fn step(&mut self) -> io::Result<()> {
        while let Some(out) = self.client.poll_write() {
            match &mut self.link {
                Link::Udp(sock) => match sock.send_to(&out.message, out.transport.peer_addr) {
                    Ok(_) => {}
                    Err(e) if e.kind() == ErrorKind::WouldBlock => {}
                    Err(e) => return Err(e),
                },
                Link::Tcp(stream, _) => write_all(stream, &out.message)?,
            }
        }
        let mut buf = [0u8; 4096];
        let mut inbound = vec![];
        match &mut self.link {
            Link::Udp(sock) => loop {
                match sock.recv_from(&mut buf) {
                    Ok((n, from)) => inbound.push((buf[..n].to_vec(), from)),
                    Err(e) if e.kind() == ErrorKind::WouldBlock => break,
                    Err(e) => return Err(e),
                }
            },
            Link::Tcp(stream, decoder) => {
                loop {
                    match stream.read(&mut buf) {
                        Ok(0) => {
                            return Err(io::Error::new(
                                ErrorKind::ConnectionReset,
                                "the server closed the control connection",
                            ));
                        }
                        Ok(n) => decoder.extend_from_slice(&buf[..n]),
                        Err(e) if e.kind() == ErrorKind::WouldBlock => break,
                        Err(e) => return Err(e),
                    }
                }
                while let Some(message) = decoder.next_message().map_err(io::Error::other)? {
                    inbound.push((message, self.server));
                }
            }
        }
        let transport_protocol = match self.link {
            Link::Udp(_) => TransportProtocol::UDP,
            Link::Tcp(..) => TransportProtocol::TCP,
        };
        for (message, from) in inbound {
            let _ = self.client.handle_read(TaggedBytesMut {
                now: Instant::now(),
                transport: TransportContext {
                    local_addr: self.local,
                    peer_addr: from,
                    transport_protocol,
                    ecn: None,
                },
                message: BytesMut::from(&message[..]),
            });
        }
        let now = Instant::now();
        if self.client.poll_timeout().is_some_and(|at| at <= now) {
            self.client.handle_timeout(now).map_err(io::Error::other)?;
        }
        while let Some(event) = self.client.poll_event() {
            self.events.push(event);
        }
        Ok(())
    }

    /// Runs until an event `pick` takes turns up, and returns what it made of it. Panics with
    /// `what` and the events seen if none does in time.
    fn wait_for<T>(&mut self, what: &str, mut pick: impl FnMut(&Event) -> Option<T>) -> T {
        let deadline = Instant::now() + ANSWER;
        loop {
            self.step().expect("socket I/O");
            for i in 0..self.events.len() {
                if let Some(found) = pick(&self.events[i]) {
                    self.events.remove(i);
                    return found;
                }
            }
            assert!(
                Instant::now() < deadline,
                "no {what} within {ANSWER:?}; events: {:?}",
                self.events
            );
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    /// Runs for `time` and returns the events raised meanwhile.
    fn run_for(&mut self, time: Duration) -> Vec<Event> {
        let until = Instant::now() + time;
        while Instant::now() < until {
            self.step().expect("socket I/O");
            std::thread::sleep(Duration::from_millis(5));
        }
        std::mem::take(&mut self.events)
    }

    fn allocate(&mut self, options: AllocateOptions) -> SocketAddr {
        let tid = self
            .client
            .allocate_with(Instant::now(), options)
            .expect("the Allocate is sent");
        self.wait_for("AllocateResponse", |e| match e {
            Event::AllocateResponse(id, addr) if *id == tid => Some(*addr),
            Event::AllocateError(id, err) if *id == tid => panic!("the Allocate failed: {err}"),
            _ => None,
        })
    }

    fn permit(&mut self, relayed: SocketAddr, peer: SocketAddr) {
        let tid = self
            .client
            .relay(relayed)
            .expect("the allocation")
            .create_permission(Instant::now(), peer)
            .expect("the CreatePermission is sent")
            .expect("a new permission is asked for");
        self.wait_for("CreatePermissionResponse", |e| match e {
            Event::CreatePermissionResponse(id, _) if *id == tid => Some(()),
            Event::CreatePermissionError(id, err) if *id == tid => {
                panic!("the CreatePermission failed: {err}")
            }
            _ => None,
        });
    }

    fn release(&mut self, relayed: SocketAddr) {
        self.client
            .relay(relayed)
            .expect("the allocation")
            .close(Instant::now())
            .expect("the release is sent");
        self.wait_for("AllocationReleased", |e| match e {
            Event::AllocationReleased(addr) if *addr == relayed => Some(()),
            _ => None,
        });
    }
}

/// Waits for one datagram on a plain socket.
fn recv(sock: &UdpSocket) -> (Vec<u8>, SocketAddr) {
    let deadline = Instant::now() + ANSWER;
    let mut buf = [0u8; 2048];
    loop {
        match sock.recv_from(&mut buf) {
            Ok((n, from)) => return (buf[..n].to_vec(), from),
            Err(e) if e.kind() == ErrorKind::WouldBlock => {
                assert!(Instant::now() < deadline, "nothing arrived in {ANSWER:?}");
                std::thread::sleep(Duration::from_millis(5));
            }
            Err(e) => panic!("recv: {e}"),
        }
    }
}

/// RFC 8656 7.1, 7.3, 11.1: a server takes LIFETIME, DONT-FRAGMENT and EVEN-PORT with the R bit
/// in an Allocate; its answer carries the client's reflexive address and the token of the
/// reserved port, which a second allocation is given; and it relays a Send indication with
/// DONT-FRAGMENT.
#[test]
#[ignore = "needs the real-network test environment (the TURN client's coturn, namespaces): scripts/test-env/run.sh"]
fn allocate_options_are_honoured_by_coturn() {
    common::install_crypto_provider();
    let env = Env::get();
    let server = client_server();
    let mut a = TurnPeer::new("open-a", server, &env.user, &env.pass).expect("client a");

    let relayed = a.allocate(AllocateOptions {
        lifetime: Some(Duration::from_secs(1200)),
        dont_fragment: true,
        even_port: Some(EvenPort { reserve_port: true }),
        ..Default::default()
    });
    let (mapped, lifetime, token, dont_fragment) = {
        let relay = a.client.relay(relayed).unwrap();
        (
            relay.mapped_addr(),
            relay.lifetime(),
            relay.reservation_token(),
            relay.dont_fragment(),
        )
    };
    eprintln!(
        "TURN client: relayed {relayed}, mapped {mapped:?}, lifetime {lifetime:?}, \
         token {}, DONT-FRAGMENT {dont_fragment}",
        token.is_some()
    );
    assert!(relayed.is_ipv4());
    assert_eq!(relayed.port() % 2, 0, "EVEN-PORT: the relayed port is even");
    assert_eq!(
        mapped,
        Some(a.local),
        "no NAT in between: the reflexive address is the socket's"
    );
    assert_eq!(
        lifetime,
        Some(Duration::from_secs(1200)),
        "the server grants the lifetime asked for (its maximum is an hour)"
    );
    assert!(dont_fragment, "coturn on Linux knows DONT-FRAGMENT");
    let token = token.expect("EVEN-PORT with R = 1: the response has a RESERVATION-TOKEN");

    // The reserved port is the next one, and the token gets it.
    let mut second = TurnPeer::new("open-a", server, &env.user, &env.pass).expect("client a2");
    let reserved = second.allocate(AllocateOptions {
        reservation_token: Some(token),
        ..Default::default()
    });
    assert_eq!(
        (reserved.ip(), reserved.port()),
        (relayed.ip(), relayed.port() + 1),
        "RESERVATION-TOKEN: the port after the even one"
    );
    second.release(reserved);

    // A Send indication with DONT-FRAGMENT reaches the peer from the relayed address, and the
    // peer's answer comes back as a Data indication.
    let b = socket_in("open-b", server).expect("peer b");
    let b_addr = b.local_addr().unwrap();
    a.permit(relayed, b_addr);
    a.client
        .relay(relayed)
        .unwrap()
        .send_to_dont_fragment(Instant::now(), b"do not fragment", b_addr)
        .expect("the Send indication goes out");
    a.step().unwrap();
    let (data, from) = recv(&b);
    assert_eq!(data, b"do not fragment");
    assert_eq!(from, relayed);

    b.send_to(b"back", relayed).unwrap();
    let (peer, back) = a.wait_for("the peer's data", |e| match e {
        Event::DataIndicationOrChannelData(_, peer, data) => Some((*peer, data.to_vec())),
        _ => None,
    });
    assert_eq!((peer, back.as_slice()), (b_addr, &b"back"[..]));

    a.release(relayed);
    assert!(a.client.relay(relayed).is_err());
}

/// RFC 8656 7.1, 8.1: REQUESTED-ADDRESS-FAMILY gets an IPv6 relayed address,
/// ADDITIONAL-ADDRESS-FAMILY an IPv4 and an IPv6 one, and a Refresh with LIFETIME 0 and a
/// family deletes that one address and leaves the other usable.
#[test]
#[ignore = "needs the real-network test environment (the TURN client's coturn, namespaces): scripts/test-env/run.sh"]
fn ipv6_and_dual_allocations_on_coturn() {
    common::install_crypto_provider();
    let env = Env::get();
    let server = client_server();

    let mut six = TurnPeer::new("open-a", server, &env.user, &env.pass).expect("client");
    let relayed = six.allocate(AllocateOptions {
        address_family: Some(REQUESTED_FAMILY_IPV6),
        ..Default::default()
    });
    eprintln!("TURN client: IPv6 relayed address {relayed}");
    assert!(
        relayed.is_ipv6(),
        "REQUESTED-ADDRESS-FAMILY IPv6: {relayed}"
    );
    assert_eq!(
        six.client.relay(relayed).unwrap().relayed_addrs(),
        vec![relayed]
    );
    six.release(relayed);

    let mut dual = TurnPeer::new("open-a", server, &env.user, &env.pass).expect("client");
    let first = dual.allocate(AllocateOptions {
        additional_ipv6: true,
        ..Default::default()
    });
    let addrs = dual.client.relay(first).unwrap().relayed_addrs();
    eprintln!("TURN client: dual allocation {addrs:?}");
    if addrs.len() == 1 {
        // ADDITIONAL-ADDRESS-FAMILY is comprehension-optional (0x8000, RFC 8656 18.11): a
        // server that does not implement it ignores it and allocates as if it were absent.
        // coturn 4.6.1 does: the allocation is the IPv4 address alone, and it works.
        eprintln!("TURN client: the server ignored ADDITIONAL-ADDRESS-FAMILY; one address");
        assert!(addrs[0].is_ipv4(), "{addrs:?}");
        assert_eq!(addrs[0], first);
        dual.client.refresh_allocations(Instant::now()).unwrap();
        let events = dual.run_for(Duration::from_secs(1));
        assert!(events.is_empty(), "the Refresh is accepted: {events:?}");
        assert!(
            dual.client
                .relay(first)
                .unwrap()
                .release_family(Instant::now(), REQUESTED_FAMILY_IPV6)
                .is_err(),
            "a family the allocation does not hold is never named"
        );
        dual.release(first);
        return;
    }
    assert_eq!(addrs.len(), 2, "an IPv4 and an IPv6 relayed address");
    assert!(addrs[0].is_ipv4() && addrs[1].is_ipv6(), "{addrs:?}");
    assert!(dual.client.relay(first).unwrap().address_error().is_none());
    let (v4, v6) = (addrs[0], addrs[1]);

    // Both are refreshed by one Refresh.
    dual.client.refresh_allocations(Instant::now()).unwrap();
    let events = dual.run_for(Duration::from_secs(1));
    assert!(events.is_empty(), "the Refresh is accepted: {events:?}");

    // The IPv6 address goes; the IPv4 one stays and works.
    dual.client
        .relay(v6)
        .unwrap()
        .release_family(Instant::now(), REQUESTED_FAMILY_IPV6)
        .unwrap();
    dual.wait_for("the IPv6 address to be released", |e| match e {
        Event::AllocationReleased(addr) if *addr == v6 => Some(()),
        _ => None,
    });
    assert_eq!(dual.client.relay(v4).unwrap().relayed_addrs(), vec![v4]);
    assert!(dual.client.relay(v6).is_err());
    assert!(
        dual.client
            .relay(v4)
            .unwrap()
            .release_family(Instant::now(), REQUESTED_FAMILY_IPV6)
            .is_err(),
        "a family the allocation does not hold is never named"
    );

    let b = socket_in("open-b", server).expect("peer b");
    let b_addr = b.local_addr().unwrap();
    dual.permit(v4, b_addr);
    dual.client
        .relay(v4)
        .unwrap()
        .send_to(Instant::now(), b"still here", b_addr)
        .unwrap();
    dual.step().unwrap();
    let (data, from) = recv(&b);
    assert_eq!((data.as_slice(), from), (&b"still here"[..], v4));
    dual.client.refresh_allocations(Instant::now()).unwrap();
    let events = dual.run_for(Duration::from_secs(1));
    assert!(events.is_empty(), "the Refresh is accepted: {events:?}");

    dual.client
        .relay(v4)
        .unwrap()
        .release_family(Instant::now(), REQUESTED_FAMILY_IPV4)
        .unwrap();
    dual.wait_for("the allocation to be released", |e| match e {
        Event::AllocationReleased(addr) if *addr == v4 => Some(()),
        _ => None,
    });
}

/// RFC 8656 7.4: a server with no IPv6 relay address answers 440 (Address Family not
/// Supported), and the client does not make that request again. The environment's first coturn
/// relays on IPv4 only.
#[test]
#[ignore = "needs the real-network test environment (coturn, namespaces): scripts/test-env/run.sh"]
fn an_ipv6_relay_is_refused_by_a_server_without_one() {
    common::install_crypto_provider();
    let env = Env::get();
    let mut a = TurnPeer::new("open-a", env.turn_udp, &env.user, &env.pass).expect("client");
    let ipv6 = AllocateOptions {
        address_family: Some(REQUESTED_FAMILY_IPV6),
        ..Default::default()
    };

    let tid = a
        .client
        .allocate_with(Instant::now(), ipv6.clone())
        .unwrap();
    let code = a.wait_for("AllocateError", |e| match e {
        Event::AllocateError(id, err) if *id == tid => Some(err.code().map(|c| c.0)),
        Event::AllocateResponse(id, addr) if *id == tid => {
            panic!("a server without an IPv6 relay address allocated {addr}")
        }
        _ => None,
    });
    eprintln!("TURN client: IPv6 on an IPv4-only server: {code:?}");
    assert_eq!(code, Some(CODE_ADDR_FAMILY_NOT_SUPPORTED.0));

    assert!(
        a.client.allocate_with(Instant::now(), ipv6).is_err(),
        "440: the request is not made again"
    );
    // An IPv4 address was never refused.
    let relayed = a.allocate(AllocateOptions {
        address_family: Some(REQUESTED_FAMILY_IPV4),
        ..Default::default()
    });
    assert!(relayed.is_ipv4());
    a.release(relayed);
}

/// RFC 8656 5: an allocation belongs to the username that made it ("the client MUST use the
/// same username" for its later requests), and a server answers a request for it under
/// another username with 441 (Wrong Credentials). The client keeps each allocation under its
/// own username: after `update_credentials` with another one, the Refresh of the live
/// allocation is still signed as its owner and coturn accepts it; the new username is for the
/// next allocation only.
#[test]
#[ignore = "needs the real-network test environment (the TURN client's coturn, namespaces): scripts/test-env/run.sh"]
fn a_live_allocation_keeps_its_username_after_a_credential_change() {
    common::install_crypto_provider();
    let env = Env::get();
    let server = client_server();
    let mut a = TurnPeer::impatient("open-a", server, &env.user, &env.pass).expect("client");
    let relayed = a.allocate(AllocateOptions::default());

    a.client
        .update_credentials("other".to_owned(), "other".to_owned())
        .unwrap();
    a.client.refresh_allocations(Instant::now()).unwrap();
    let events = a.run_for(Duration::from_secs(2));
    assert!(
        events.is_empty(),
        "the Refresh goes out under the allocation's own username and is accepted: {events:?}"
    );
    assert!(a.client.relay(relayed).is_ok(), "the allocation is kept");
    a.release(relayed);
}

/// RFC 8489 9.2.5: a 401 (Unauthenticated) to a request that carried the credential is the
/// answer, not a challenge: the client reports it and does not send the same credential
/// again. coturn answers a wrong password that way.
#[test]
#[ignore = "needs the real-network test environment (the TURN client's coturn, namespaces): scripts/test-env/run.sh"]
fn a_wrong_password_is_refused_with_401_and_not_sent_again() {
    common::install_crypto_provider();
    let env = Env::get();
    let server = client_server();
    let mut a = TurnPeer::new("open-a", server, &env.user, "not the password").expect("client");

    let tid = a
        .client
        .allocate_with(Instant::now(), AllocateOptions::default())
        .unwrap();
    let code = a.wait_for("AllocateError", |e| match e {
        Event::AllocateError(id, err) if *id == tid => Some(err.code().map(|c| c.0)),
        Event::AllocateResponse(id, addr) if *id == tid => {
            panic!("a wrong password allocated {addr}")
        }
        _ => None,
    });
    eprintln!("TURN client: Allocate with a wrong password: {code:?}");
    assert_eq!(code, Some(CODE_UNAUTHORIZED.0));

    let events = a.run_for(Duration::from_secs(1));
    assert!(events.is_empty(), "nothing follows the 401: {events:?}");
    assert!(
        !a.client.has_transaction(&tid),
        "the refused request is not outstanding again"
    );

    // The same client with the right password is served: nothing was remembered against it.
    a.client
        .update_credentials(env.user.clone(), env.pass.clone())
        .unwrap();
    let relayed = a.allocate(AllocateOptions::default());
    a.release(relayed);
}

/// RFC 8489 6.2.1: the RTO follows the server's round-trip time (RFC 6298), never below the
/// initial 500 ms. On the test network a round trip takes a few milliseconds, so after the
/// answered Allocate exchange a request is still retransmitted 500 ms after it was sent, not
/// sooner: a Refresh that is held back from the socket is queued once in its first 400 ms.
#[test]
#[ignore = "needs the real-network test environment (the TURN client's coturn, namespaces): scripts/test-env/run.sh"]
fn requests_to_a_real_server_keep_the_500_ms_initial_rto() {
    common::install_crypto_provider();
    let env = Env::get();
    let server = client_server();
    let mut a = TurnPeer::new("open-a", server, &env.user, &env.pass).expect("client");
    let relayed = a.allocate(AllocateOptions::default());

    // Nothing answers a Refresh that never leaves: count what the client queues for it.
    a.client.refresh_allocations(Instant::now()).unwrap();
    let sent_at = Instant::now();
    let mut copies = 0;
    while Instant::now() < sent_at + Duration::from_millis(400) {
        while a.client.poll_write().is_some() {
            copies += 1;
        }
        let now = Instant::now();
        if a.client.poll_timeout().is_some_and(|at| at <= now) {
            a.client.handle_timeout(now).unwrap();
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    eprintln!("TURN client: {copies} copy of an unanswered Refresh in 400 ms");
    assert_eq!(copies, 1, "retransmitted before the initial RTO");

    // The allocation is still the server's: a Refresh that is delivered is answered.
    a.client.refresh_allocations(Instant::now()).unwrap();
    let events = a.run_for(Duration::from_secs(1));
    assert!(
        !events
            .iter()
            .any(|e| matches!(e, Event::RefreshError(..) | Event::AllocationLost(..))),
        "{events:?}"
    );
    a.release(relayed);
}

/// One client data connection of a TCP allocation on a real TCP connection.
struct DataLink {
    connection: DataConnection,
    stream: TcpStream,
    local: SocketAddr,
    /// What the peer sent, as the data connection delivered it.
    received: Vec<u8>,
    events: Vec<DataConnectionEvent>,
}

impl DataLink {
    /// Opens a new TCP connection to the server from `ns` and starts binding it to
    /// `connection_id` (RFC 6062 4.3, 4.4).
    fn open(
        ns: &'static str,
        control: &mut TurnPeer,
        relayed: SocketAddr,
        connection_id: ConnectionId,
    ) -> io::Result<Self> {
        let stream = connect_in(ns, control.server)?;
        let local = stream.local_addr()?;
        assert_ne!(local, control.local, "another local transport address");
        let connection = control
            .client
            .relay(relayed)
            .map_err(io::Error::other)?
            .data_connection(Instant::now(), connection_id, local)
            .map_err(io::Error::other)?;
        assert_eq!(connection.server_addr(), control.server);
        Ok(DataLink {
            connection,
            stream,
            local,
            received: vec![],
            events: vec![],
        })
    }

    fn step(&mut self) -> io::Result<()> {
        while let Some(out) = self.connection.poll_write() {
            write_all(&mut self.stream, &out.message)?;
        }
        let mut buf = [0u8; 4096];
        loop {
            match self.stream.read(&mut buf) {
                Ok(0) => {
                    return Err(io::Error::new(
                        ErrorKind::ConnectionReset,
                        "the server closed the data connection",
                    ));
                }
                Ok(n) => {
                    let _ = self.connection.handle_read(TaggedBytesMut {
                        now: Instant::now(),
                        transport: TransportContext {
                            local_addr: self.local,
                            peer_addr: self.connection.server_addr(),
                            transport_protocol: TransportProtocol::TCP,
                            ecn: None,
                        },
                        message: BytesMut::from(&buf[..n]),
                    });
                }
                Err(e) if e.kind() == ErrorKind::WouldBlock => break,
                Err(e) => return Err(e),
            }
        }
        let now = Instant::now();
        if self.connection.poll_timeout().is_some_and(|at| at <= now) {
            self.connection
                .handle_timeout(now)
                .map_err(io::Error::other)?;
        }
        while let Some(event) = self.connection.poll_event() {
            self.events.push(event);
        }
        while let Some(data) = self.connection.poll_read() {
            self.received.extend_from_slice(&data);
        }
        Ok(())
    }

    /// Runs until the server accepted the ConnectionBind.
    fn wait_bound(&mut self) {
        let deadline = Instant::now() + ANSWER;
        while !self.connection.is_bound() {
            self.step().expect("data connection I/O");
            assert!(
                !self
                    .events
                    .iter()
                    .any(|e| matches!(e, DataConnectionEvent::BindError(_))),
                "the ConnectionBind failed: {:?}",
                self.events
            );
            assert!(
                Instant::now() < deadline,
                "the ConnectionBind was not answered in {ANSWER:?}"
            );
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    /// Runs until the peer's bytes so far are `expected`.
    fn wait_received(&mut self, expected: &[u8]) {
        let deadline = Instant::now() + ANSWER;
        while self.received.len() < expected.len() {
            self.step().expect("data connection I/O");
            assert!(
                Instant::now() < deadline,
                "only {:?} of {expected:?} arrived",
                self.received
            );
            std::thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(self.received, expected, "relayed as it is");
    }

    fn send(&mut self, data: &[u8]) {
        self.connection
            .send(Instant::now(), data)
            .expect("the data connection is bound");
        self.step().expect("data connection I/O");
    }
}

/// Reads exactly `n` bytes from a plain peer socket.
fn read_exact(stream: &mut TcpStream, n: usize) -> Vec<u8> {
    stream.set_nonblocking(false).unwrap();
    stream.set_read_timeout(Some(ANSWER)).unwrap();
    let mut buf = vec![0u8; n];
    stream
        .read_exact(&mut buf)
        .expect("the bytes arrive in time");
    buf
}

/// RFC 6062 4.1 to 4.6: over TCP to the server, an Allocate with REQUESTED-TRANSPORT TCP gets a
/// TCP relayed address. A Connect makes the server connect to a peer, and a peer connecting to
/// the relayed address is announced with a ConnectionAttempt; each becomes a data connection
/// with a ConnectionBind on a new TCP connection, and then carries the bytes as they are, both
/// ways. The allocation is refreshed on the control connection meanwhile, and closing a data
/// connection closes the peer's.
#[test]
#[ignore = "needs the real-network test environment (the TURN client's coturn, namespaces): scripts/test-env/run.sh"]
fn a_tcp_allocation_connects_and_accepts_through_coturn() {
    common::install_crypto_provider();
    let env = Env::get();
    let server = client_server();

    // Over UDP there is no TCP allocation, and nothing is sent to find out.
    let mut over_udp = TurnPeer::new("open-a", server, &env.user, &env.pass).expect("client");
    let tcp = AllocateOptions {
        transport: RelayTransport::Tcp,
        ..Default::default()
    };
    assert!(
        over_udp
            .client
            .allocate_with(Instant::now(), tcp.clone())
            .is_err()
    );

    let mut a = TurnPeer::over_tcp("open-a", server, &env.user, &env.pass).expect("client a");
    let relayed = a.allocate(tcp);
    eprintln!("TURN client: TCP relayed address {relayed}");
    assert_eq!(
        a.client.relay(relayed).unwrap().transport(),
        RelayTransport::Tcp
    );

    // The client connects out: the server dials a listener in open-b from the relayed address.
    let b_ip = source_ip("open-b", server).unwrap();
    let listener = in_netns("open-b", move || TcpListener::bind((b_ip, 0))).expect("listener");
    let listening = listener.local_addr().unwrap();
    a.permit(relayed, listening);
    let tid = a
        .client
        .relay(relayed)
        .unwrap()
        .connect(Instant::now(), listening)
        .expect("the Connect is sent");
    assert!(
        a.client
            .relay(relayed)
            .unwrap()
            .connect(Instant::now(), listening)
            .is_err(),
        "never two Connect requests for one peer address"
    );
    let connection_id = a.wait_for("ConnectResponse", |e| match e {
        Event::ConnectResponse(id, peer, connection_id) if *id == tid => {
            assert_eq!(*peer, listening);
            Some(*connection_id)
        }
        Event::ConnectError(id, _, err) if *id == tid => panic!("the Connect failed: {err}"),
        _ => None,
    });
    listener.set_nonblocking(false).unwrap();
    let (mut dialled, from) = listener.accept().expect("the server's connection");
    eprintln!("TURN client: Connect made connection {connection_id}; the peer sees {from}");
    assert_eq!(from.ip(), relayed.ip(), "the peer sees the relayed address");

    let mut out = DataLink::open("open-a", &mut a, relayed, connection_id).expect("data link");
    out.wait_bound();
    out.send(b"through the relay, as it is");
    assert_eq!(read_exact(&mut dialled, 27), b"through the relay, as it is");
    dialled.write_all(b"and back").unwrap();
    out.wait_received(b"and back");

    // A peer connects in: the server announces it, and the client accepts it.
    let mut knocking = in_netns("open-b", move || {
        TcpStream::connect_timeout(&relayed, Duration::from_secs(5))
    })
    .expect("the peer reaches the relayed address");
    let knocking_from = knocking.local_addr().unwrap();
    let attempt = a.wait_for("ConnectionAttempt", |e| match e {
        Event::ConnectionAttempt(to, peer, connection_id) => {
            assert_eq!(*to, relayed);
            Some((*peer, *connection_id))
        }
        _ => None,
    });
    eprintln!(
        "TURN client: ConnectionAttempt {} from {} (the peer's socket is {knocking_from})",
        attempt.1, attempt.0
    );
    assert_eq!(attempt.0, knocking_from);
    assert_ne!(attempt.1, connection_id);
    let mut accepted = DataLink::open("open-a", &mut a, relayed, attempt.1).expect("data link");
    accepted.wait_bound();
    knocking.write_all(b"knock").unwrap();
    accepted.wait_received(b"knock");
    accepted.send(b"come in");
    assert_eq!(read_exact(&mut knocking, 7), b"come in");

    // The allocation is refreshed on the control connection while the data connections live.
    a.client.refresh_allocations(Instant::now()).unwrap();
    let events = a.run_for(Duration::from_secs(1));
    assert!(events.is_empty(), "the Refresh is accepted: {events:?}");
    out.send(b"still open");
    assert_eq!(read_exact(&mut dialled, 10), b"still open");

    // Closing the data connection ends the peer's connection.
    drop(out);
    dialled.set_read_timeout(Some(ANSWER)).unwrap();
    let mut rest = [0u8; 16];
    let closed = dialled.read(&mut rest);
    let ended = match &closed {
        Ok(0) => true,
        Err(e) => matches!(
            e.kind(),
            ErrorKind::ConnectionReset | ErrorKind::ConnectionAborted | ErrorKind::BrokenPipe
        ),
        Ok(_) => false,
    };
    assert!(
        ended,
        "the peer's connection stays open after its data connection closed: {closed:?}"
    );

    a.release(relayed);
}

/// An ICE agent of this test: TCP only, no mDNS.
fn tcp_agent(controlling: bool) -> Agent {
    Agent::new(
        Instant::now(),
        Arc::new(AgentConfig {
            is_controlling: controlling,
            network_types: vec![NetworkType::Tcp4],
            multicast_dns_mode: MulticastDnsMode::Disabled,
            ..Default::default()
        }),
        rtc::crypto::default_provider().expect("a crypto provider"),
    )
    .expect("an agent")
}

/// Runs an agent's due timer and collects its connection states.
fn agent_step(agent: &mut Agent, states: &mut Vec<ConnectionState>) {
    let now = Instant::now();
    if agent.poll_timeout().is_some_and(|at| at <= now) {
        agent.handle_timeout(now).expect("the agent's timer");
    }
    while let Some(event) = agent.poll_event() {
        if let IceEvent::ConnectionStateChange(state) = event.event {
            states.push(state);
        }
    }
}

/// One of the passive peer's accepted connections.
struct PassiveConn {
    stream: TcpStream,
    from: SocketAddr,
    decoder: TcpFrameDecoder,
}

/// RFC 6544 Sections 4.1, 4.5 and 5 over a real TURN server (RFC 6062): ICE connects on a
/// relayed TCP candidate. Peer A holds a TCP allocation and has two TCP candidates from it, both
/// active (port 9, Section 4.5): the relayed address, and the server-reflexive one its
/// XOR-MAPPED-ADDRESS gives (`Relay::mapped_addr`, the address-discovery technique of
/// Section 5). Peer B has a passive host candidate, a real listener. A's checks on the relayed
/// pair go out from the relayed address: the application turns the first into a Connect, binds
/// a data connection to it, and from then carries the pair's RFC 4571 frames on it as they
/// are. B sees the server's connection come from the relayed address and answers on it. A,
/// controlling, nominates the relayed pair, and both agents are connected on it.
#[test]
#[ignore = "needs the real-network test environment (the TURN client's coturn, namespaces): scripts/test-env/run.sh"]
fn ice_connects_on_a_relayed_tcp_candidate_through_coturn() {
    common::install_crypto_provider();
    let env = Env::get();
    let server = client_server();

    let mut turn = TurnPeer::over_tcp("open-a", server, &env.user, &env.pass).expect("client a");
    let relayed = turn.allocate(AllocateOptions {
        transport: RelayTransport::Tcp,
        ..Default::default()
    });
    let mapped = turn
        .client
        .relay(relayed)
        .unwrap()
        .mapped_addr()
        .expect("the Allocate response's XOR-MAPPED-ADDRESS");
    eprintln!("ICE over TURN TCP: relayed {relayed}, server-reflexive {mapped}");

    // B: a passive host candidate on a listener in open-b.
    let b_ip = source_ip("open-b", server).unwrap();
    let listener = in_netns("open-b", move || TcpListener::bind((b_ip, 0))).expect("listener");
    listener.set_nonblocking(true).unwrap();
    let b_addr = listener.local_addr().unwrap();
    let passive = || {
        CandidateHostConfig {
            base_config: CandidateConfig {
                network: "tcp".to_owned(),
                address: b_addr.ip().to_string(),
                port: b_addr.port(),
                component: 1,
                ..Default::default()
            },
            tcp_type: TcpType::Passive,
        }
        .new_candidate_host()
        .unwrap()
    };
    // A: the relayed and the server-reflexive candidate of the allocation, both active.
    let relay_active = || {
        let mut c = CandidateRelayConfig {
            base_config: CandidateConfig {
                network: "tcp".to_owned(),
                address: relayed.ip().to_string(),
                port: 9,
                component: 1,
                ..Default::default()
            },
            rel_addr: turn.local.ip().to_string(),
            rel_port: turn.local.port(),
            url: None,
        }
        .new_candidate_relay()
        .unwrap();
        c.set_tcp_type(TcpType::Active);
        c
    };
    let srflx_active = || {
        let mut c = CandidateServerReflexiveConfig {
            base_config: CandidateConfig {
                network: "tcp".to_owned(),
                address: mapped.ip().to_string(),
                port: 9,
                component: 1,
                ..Default::default()
            },
            rel_addr: turn.local.ip().to_string(),
            rel_port: 9,
            url: None,
        }
        .new_candidate_server_reflexive()
        .unwrap();
        c.set_tcp_type(TcpType::Active);
        c
    };

    let mut a = tcp_agent(true);
    let mut b = tcp_agent(false);
    a.add_local_candidate(relay_active()).unwrap();
    a.add_local_candidate(srflx_active()).unwrap();
    b.add_local_candidate(passive()).unwrap();
    a.add_remote_candidate(passive()).unwrap();
    // A's active candidates are signalled too; B reaches them as the peer-reflexive candidates
    // their connections make.
    b.add_remote_candidate(relay_active()).unwrap();
    b.add_remote_candidate(srflx_active()).unwrap();
    let (a_cred, b_cred) = (
        a.get_local_credentials().clone(),
        b.get_local_credentials().clone(),
    );
    a.start_connectivity_checks(Instant::now(), true, b_cred.ufrag, b_cred.pwd)
        .unwrap();
    b.start_connectivity_checks(Instant::now(), false, a_cred.ufrag, a_cred.pwd)
        .unwrap();

    let (mut a_events, mut b_events) = (vec![], vec![]);
    let mut link: Option<DataLink> = None;
    // The local address A's agent sent the relayed pair's checks from.
    let mut a_relayed_local = None;
    let mut a_decoder = TcpFrameDecoder::new();
    let mut b_conns: Vec<PassiveConn> = vec![];
    // Checks from the server-reflexive candidate's base to B's passive candidate.
    let mut srflx_checks = 0u32;
    let deadline = Instant::now() + Duration::from_secs(30);
    let connected = |states: &[ConnectionState]| states.last() == Some(&ConnectionState::Connected);
    while !(connected(&a_events) && connected(&b_events)) {
        assert!(
            Instant::now() < deadline,
            "ICE did not connect over the relayed TCP candidate in 30 s: A {a_events:?}, B \
             {b_events:?} ({srflx_checks} server-reflexive checks)"
        );
        turn.step().expect("control connection I/O");

        // A's writes: the relayed pair's go over the data connection.
        while let Some(out) = a.poll_write() {
            assert_eq!(out.transport.transport_protocol, TransportProtocol::TCP);
            if out.transport.peer_addr != b_addr {
                continue;
            }
            if out.transport.local_addr.ip() != relayed.ip() {
                srflx_checks += 1;
                continue;
            }
            a_relayed_local = Some(out.transport.local_addr);
            if link.is_none() {
                turn.permit(relayed, b_addr);
                let tid = turn
                    .client
                    .relay(relayed)
                    .unwrap()
                    .connect(Instant::now(), b_addr)
                    .expect("the Connect is sent");
                let connection_id = turn.wait_for("ConnectResponse", |e| match e {
                    Event::ConnectResponse(id, _, connection_id) if *id == tid => {
                        Some(*connection_id)
                    }
                    Event::ConnectError(id, _, err) if *id == tid => {
                        panic!("the Connect failed: {err}")
                    }
                    _ => None,
                });
                let mut opened =
                    DataLink::open("open-a", &mut turn, relayed, connection_id).expect("data link");
                opened.wait_bound();
                link = Some(opened);
            }
            link.as_mut().unwrap().send(&frame_packet(&out.message));
        }
        // What came back on the data connection, to A's relayed candidate.
        if let Some(l) = link.as_mut() {
            l.step().expect("data connection I/O");
            a_decoder.extend_from_slice(&std::mem::take(&mut l.received));
            while let Some(packet) = a_decoder.next_packet() {
                let _ = a.handle_read(TaggedBytesMut {
                    now: Instant::now(),
                    transport: TransportContext {
                        local_addr: a_relayed_local.expect("A sent first"),
                        peer_addr: b_addr,
                        transport_protocol: TransportProtocol::TCP,
                        ecn: None,
                    },
                    message: BytesMut::from(&packet[..]),
                });
            }
        }

        // B: the server's connections from the relayed address, and the frames on them.
        while let Ok((stream, from)) = listener.accept() {
            stream.set_nonblocking(true).unwrap();
            assert_eq!(
                from.ip(),
                relayed.ip(),
                "the server connects from the relayed address"
            );
            b_conns.push(PassiveConn {
                stream,
                from,
                decoder: TcpFrameDecoder::new(),
            });
        }
        let mut buf = [0u8; 4096];
        for conn in b_conns.iter_mut() {
            loop {
                match conn.stream.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => conn.decoder.extend_from_slice(&buf[..n]),
                    Err(e) if e.kind() == ErrorKind::WouldBlock => break,
                    Err(e) => panic!("B's connection: {e}"),
                }
            }
            while let Some(packet) = conn.decoder.next_packet() {
                let _ = b.handle_read(TaggedBytesMut {
                    now: Instant::now(),
                    transport: TransportContext {
                        local_addr: b_addr,
                        peer_addr: conn.from,
                        transport_protocol: TransportProtocol::TCP,
                        ecn: None,
                    },
                    message: BytesMut::from(&packet[..]),
                });
            }
        }
        while let Some(out) = b.poll_write() {
            if let Some(conn) = b_conns
                .iter_mut()
                .find(|c| c.from == out.transport.peer_addr)
            {
                write_all(&mut conn.stream, &frame_packet(&out.message)).expect("B writes");
            }
        }

        agent_step(&mut a, &mut a_events);
        agent_step(&mut b, &mut b_events);
        std::thread::sleep(Duration::from_millis(5));
    }

    let (local, remote) = a.get_selected_candidate_pair().expect("A selected a pair");
    assert_eq!(
        local.candidate_type(),
        CandidateType::Relay,
        "on the relayed candidate"
    );
    assert_eq!(local.addr().ip(), relayed.ip());
    assert_eq!(remote.addr(), b_addr);
    let (b_local, _) = b.get_selected_candidate_pair().expect("B selected a pair");
    assert_eq!(b_local.addr(), b_addr);
    // Section 5: the server-reflexive candidate the allocation gave was paired and checked
    // too, from its base (this test does not open that direct connection).
    assert!(
        srflx_checks > 0,
        "the server-reflexive TCP candidate was not checked"
    );
    drop(link);
    turn.release(relayed);
}
