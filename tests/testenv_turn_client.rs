//! The TURN client (`rtc::turn::client`) against a real TURN server, in the real-network test
//! environment (`scripts/test-env/run.sh`); ignored elsewhere.
//!
//! The unit tests in `rtc-turn` script the server's answers. These prove the claims that need
//! a server to agree: that coturn takes the Allocate options the client sends (RFC 8656 7.1),
//! gives the relayed addresses asked for, relays a Send indication carrying DONT-FRAGMENT, and
//! refuses what the RFC says a server refuses. The environment's third coturn
//! (`scripts/test-env/coturn/turnserver-client.conf`, port 3480) relays on an IPv4 and an IPv6
//! address and knows two users.

mod common;
mod testenv;

use bytes::BytesMut;
use rtc::sansio::Protocol;
use rtc::shared::{TaggedBytesMut, TransportContext, TransportProtocol};
use rtc::stun::error_code::{CODE_ADDR_FAMILY_NOT_SUPPORTED, CODE_WRONG_CREDENTIALS};
use rtc::turn::client::{AllocateOptions, Client, ClientConfig, Event};
use rtc::turn::proto::evenport::EvenPort;
use rtc::turn::proto::reqfamily::{REQUESTED_FAMILY_IPV4, REQUESTED_FAMILY_IPV6};
use std::io::{self, ErrorKind};
use std::net::{SocketAddr, UdpSocket};
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

/// A sans-I/O TURN client on a real UDP socket.
struct TurnPeer {
    client: Client,
    sock: UdpSocket,
    local: SocketAddr,
    events: Vec<Event>,
}

impl TurnPeer {
    fn new(ns: &'static str, server: SocketAddr, user: &str, pass: &str) -> io::Result<Self> {
        let sock = socket_in(ns, server)?;
        let local = sock.local_addr()?;
        let client = Client::new(
            ClientConfig {
                turn_serv_addr: server.to_string(),
                local_addr: local,
                transport_protocol: TransportProtocol::UDP,
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
            sock,
            local,
            events: vec![],
        })
    }

    /// One turn of the loop: what the client queued goes out, what the socket holds comes in,
    /// a due timer runs, events are collected.
    fn step(&mut self) -> io::Result<()> {
        while let Some(out) = self.client.poll_write() {
            match self.sock.send_to(&out.message, out.transport.peer_addr) {
                Ok(_) => {}
                Err(e) if e.kind() == ErrorKind::WouldBlock => {}
                Err(e) => return Err(e),
            }
        }
        let mut buf = [0u8; 2048];
        loop {
            match self.sock.recv_from(&mut buf) {
                Ok((n, from)) => {
                    let _ = self.client.handle_read(TaggedBytesMut {
                        now: Instant::now(),
                        transport: TransportContext {
                            local_addr: self.local,
                            peer_addr: from,
                            transport_protocol: TransportProtocol::UDP,
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

/// RFC 8656 5: an allocation belongs to the username that made it. A Refresh under another
/// username is answered 441 (Wrong Credentials), which the client reports; the allocation is
/// kept, and the old credential still refreshes it.
#[test]
#[ignore = "needs the real-network test environment (the TURN client's coturn, namespaces): scripts/test-env/run.sh"]
fn a_refresh_under_another_username_is_refused_with_441() {
    common::install_crypto_provider();
    let env = Env::get();
    let server = client_server();
    let mut a = TurnPeer::new("open-a", server, &env.user, &env.pass).expect("client");
    let relayed = a.allocate(AllocateOptions::default());

    a.client
        .update_credentials("other".to_owned(), "other".to_owned())
        .unwrap();
    a.client.refresh_allocations(Instant::now()).unwrap();
    let code = a.wait_for("RefreshError", |e| match e {
        Event::RefreshError(addr, err) if *addr == relayed => Some(err.code().map(|c| c.0)),
        _ => None,
    });
    eprintln!("TURN client: Refresh under another username: {code:?}");
    assert_eq!(code, Some(CODE_WRONG_CREDENTIALS.0));
    assert!(a.client.relay(relayed).is_ok(), "the allocation is kept");

    a.client
        .update_credentials(env.user.clone(), env.pass.clone())
        .unwrap();
    a.client.refresh_allocations(Instant::now()).unwrap();
    let events = a.run_for(Duration::from_secs(1));
    assert!(
        events.is_empty(),
        "the owner's Refresh is accepted: {events:?}"
    );
    a.release(relayed);
}
