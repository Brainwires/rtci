//! `close()` lets the engine's TURN allocations over UDP go reliably (RFC 8656 section 8: a
//! client deletes an allocation it no longer needs with a Refresh of LIFETIME 0; over UDP that
//! request is retransmitted like any STUN transaction, RFC 8489 section 6.2.1, and a 438 is
//! answered with the new nonce, RFC 8489 section 9.2.5). A closed peer connection keeps serving
//! `poll_write`, `handle_read`, `poll_timeout` and `handle_timeout` for those transactions only,
//! until they are done (`poll_timeout` is then `None`, and `OnTurnAllocationReleased` names the
//! local address that is free). An Allocate still under way at `close()` is followed to its
//! answer, and an allocation it made is deleted.
//!
//! One application socket, one peer connection after another (a host serving viewer sessions):
//! the next peer connection allocates on the same 5-tuple, which the server refuses with 437
//! while the previous allocation lives (RFC 8656 section 7.2). With another UDP base the engine
//! tries that one (section 7.4: "pick another client transport address and retry").
//!
//! The server is the in-memory coturn-like one of `common/turn_server.rs`; time is virtual.

use anyhow::Result;
use rtci::peer_connection::configuration::setting_engine::SettingEngineBuilder;
use rtci::peer_connection::configuration::{RTCConfigurationBuilder, RTCIceServer};
use rtci::peer_connection::event::RTCPeerConnectionEvent;
use rtci::peer_connection::transport::{
    CandidateConfig, CandidateHostConfig, RTCIceCandidate, RTCIceCandidateInit,
};
use rtci::peer_connection::{RTCPeerConnection, RTCPeerConnectionBuilder};
use rtci::sansio::Protocol;
use rtci::shared::{TaggedBytesMut, TransportContext, TransportProtocol};
use rtci::stun::message::{METHOD_ALLOCATE, METHOD_REFRESH};
use std::net::SocketAddr;
use std::time::{Duration, Instant};

mod common;
#[path = "common/turn_server.rs"]
mod turn_server;
use turn_server::{Auth, TurnServer};

const HOST: &str = "10.0.0.1:4000";
const HOST_2: &str = "10.0.0.1:4001";
const SERVER: &str = "192.0.2.20:3478";

fn a(s: &str) -> SocketAddr {
    s.parse().unwrap()
}

fn server(now: Instant) -> TurnServer {
    TurnServer::new(
        Auth::Static(vec![("u1".to_owned(), "p1".to_owned())]),
        vec![a(SERVER)],
        a(SERVER).ip(),
        now,
    )
}

/// A peer connection with the `turn:` server and the host candidates `hosts`, its offer
/// answered by a second one (so it has its descriptions; nothing reaches the answerer).
fn peer(now: Instant, hosts: &[&str]) -> Result<RTCPeerConnection> {
    common::install_crypto_provider();
    let mut pc = RTCPeerConnectionBuilder::new()
        .with_configuration(
            RTCConfigurationBuilder::new()
                .with_ice_servers(vec![RTCIceServer {
                    urls: vec![format!("turn:{SERVER}")],
                    username: "u1".to_owned(),
                    credential: "p1".to_owned(),
                }])
                .build(),
        )
        .with_setting_engine(
            SettingEngineBuilder::new()
                .with_tcp_candidate_gathering(false)
                .build(),
        )
        .build(now)?;
    pc.create_data_channel("release", None)?;
    let offer = pc.create_offer(None)?;
    pc.set_local_description(now, offer.clone())?;
    let mut answerer = RTCPeerConnectionBuilder::new().build(now)?;
    answerer.set_remote_description(now, offer)?;
    let answer = answerer.create_answer(None)?;
    answerer.set_local_description(now, answer.clone())?;
    pc.set_remote_description(now, answer)?;
    for host in hosts {
        let host = a(host);
        let candidate = CandidateHostConfig {
            base_config: CandidateConfig {
                network: "udp".to_owned(),
                address: host.ip().to_string(),
                port: host.port(),
                component: 1,
                ..Default::default()
            },
            ..Default::default()
        }
        .new_candidate_host()?;
        let init: RTCIceCandidateInit = RTCIceCandidate::from(&candidate).to_json()?;
        pc.add_local_candidate(init)?;
    }
    Ok(pc)
}

struct Run {
    now: Instant,
    events: Vec<RTCPeerConnectionEvent>,
}

impl Run {
    /// Moves datagrams between `pc` and the server, and the timers on, until nothing moves
    /// or `until`. Datagrams to anyone else are dropped.
    fn run(
        &mut self,
        pc: &mut RTCPeerConnection,
        s: &mut TurnServer,
        until: Instant,
    ) -> Result<()> {
        loop {
            let mut moved = false;
            while let Some(w) = pc.poll_write() {
                moved = true;
                if s.addresses.contains(&w.transport.peer_addr) {
                    s.client_sent(
                        self.now,
                        w.transport.local_addr,
                        w.transport.peer_addr,
                        &w.message,
                    )?;
                }
            }
            for (from, to, data) in std::mem::take(&mut s.out) {
                moved = true;
                let _ = pc.handle_read(TaggedBytesMut {
                    now: self.now,
                    transport: TransportContext {
                        local_addr: to,
                        peer_addr: from,
                        transport_protocol: TransportProtocol::UDP,
                        ecn: None,
                    },
                    message: data[..].into(),
                });
            }
            while let Some(e) = pc.poll_event() {
                moved = true;
                self.events.push(e);
            }
            if moved {
                continue;
            }
            match pc.poll_timeout() {
                Some(t) if t <= until => {
                    self.now = t.max(self.now + Duration::from_micros(1));
                    pc.handle_timeout(self.now)?;
                }
                _ => return Ok(()),
            }
        }
    }

    fn relayed(&self) -> Vec<String> {
        self.events
            .iter()
            .filter_map(|e| match e {
                RTCPeerConnectionEvent::OnIceCandidateEvent(ev) => {
                    let init = ev.candidate.as_ref()?.to_json().ok()?;
                    init.candidate
                        .contains("typ relay")
                        .then_some(init.candidate)
                }
                _ => None,
            })
            .collect()
    }

    fn released(&self) -> Vec<(SocketAddr, Option<SocketAddr>)> {
        self.events
            .iter()
            .filter_map(|e| match e {
                RTCPeerConnectionEvent::OnTurnAllocationReleased {
                    local_address,
                    relayed_address,
                    ..
                } => Some((*local_address, *relayed_address)),
                _ => None,
            })
            .collect()
    }
}

/// RFC 8656 section 8 with RFC 8489 section 6.2.1: the first Refresh of LIFETIME 0 that
/// `close()` sends is lost; the closed peer connection sends it again on its timer, the server
/// deletes the allocation, the release is announced with the local address, and the
/// connection has no timer left.
#[test]
fn close_retransmits_the_release_until_it_is_answered() -> Result<()> {
    let mut run = Run {
        now: Instant::now(),
        events: vec![],
    };
    let mut s = server(run.now);
    let mut pc = peer(run.now, &[HOST])?;
    let until = run.now + Duration::from_secs(5);
    run.run(&mut pc, &mut s, until)?;
    assert_eq!(s.allocations.len(), 1, "allocated");
    let relayed = s.allocations.values().next().map(|al| al.relayed);

    s.lose_releases = 1;
    pc.close()?;
    let until = run.now + Duration::from_secs(60);
    run.run(&mut pc, &mut s, until)?;
    assert!(
        s.allocations.is_empty(),
        "the allocation is deleted after close"
    );
    assert_eq!(s.deleted.len(), 1);
    assert_eq!(run.released(), vec![(a(HOST), relayed)]);
    assert_eq!(pc.poll_timeout(), None, "nothing left to do");
    Ok(())
}

/// RFC 8489 section 9.2.5: the release answered 438 (Stale Nonce) is sent again with the new
/// nonce, after close.
#[test]
fn close_answers_a_stale_nonce_to_the_release() -> Result<()> {
    let mut run = Run {
        now: Instant::now(),
        events: vec![],
    };
    let mut s = server(run.now);
    let mut pc = peer(run.now, &[HOST])?;
    let until = run.now + Duration::from_secs(5);
    run.run(&mut pc, &mut s, until)?;
    s.stale_nonce_next = true;
    pc.close()?;
    let until = run.now + Duration::from_secs(60);
    run.run(&mut pc, &mut s, until)?;
    assert!(
        s.rejections
            .iter()
            .any(|r| r.0 == METHOD_REFRESH && r.1 == 438)
    );
    assert!(s.allocations.is_empty(), "deleted on the second request");
    assert_eq!(run.released().len(), 1);
    assert_eq!(pc.poll_timeout(), None);
    Ok(())
}

/// The Allocate with the credential is under way when `close()` runs: its success arrives
/// after, and the allocation it made is deleted at once.
#[test]
fn close_during_an_allocate_deletes_the_allocation_it_makes() -> Result<()> {
    let mut run = Run {
        now: Instant::now(),
        events: vec![],
    };
    let mut s = server(run.now);
    let mut pc = peer(run.now, &[HOST])?;
    // The 401 exchange, then the signed Allocate: the server allocates, its answer waits.
    s.hold = true;
    let until = run.now + Duration::from_millis(10);
    run.run(&mut pc, &mut s, until)?;
    assert_eq!(s.count(METHOD_ALLOCATE), 1);
    s.release_held();
    s.hold = true;
    let until = run.now + Duration::from_millis(10);
    run.run(&mut pc, &mut s, until)?;
    assert_eq!(s.count(METHOD_ALLOCATE), 2);
    assert_eq!(
        s.allocations.len(),
        1,
        "the signed Allocate reached the server"
    );
    assert!(run.relayed().is_empty(), "its answer has not");
    pc.close()?;
    s.release_held();
    let until = run.now + Duration::from_secs(60);
    run.run(&mut pc, &mut s, until)?;
    assert!(s.allocations.is_empty(), "the late allocation is deleted");
    assert_eq!(run.released().len(), 1);
    assert_eq!(pc.poll_timeout(), None);
    Ok(())
}

/// One socket, one peer connection after another: the first closes (its release lost once),
/// the second, on the same 5-tuple, allocates once the first has finished.
#[test]
fn the_next_peer_connection_on_the_same_socket_allocates_after_close() -> Result<()> {
    let mut run = Run {
        now: Instant::now(),
        events: vec![],
    };
    let mut s = server(run.now);
    let mut first = peer(run.now, &[HOST])?;
    let until = run.now + Duration::from_secs(5);
    run.run(&mut first, &mut s, until)?;
    s.lose_releases = 1;
    first.close()?;
    let until = run.now + Duration::from_secs(60);
    run.run(&mut first, &mut s, until)?;
    assert_eq!(
        run.released().len(),
        1,
        "the first connection says it is done"
    );

    let mut next = Run {
        now: run.now,
        events: vec![],
    };
    let mut second = peer(next.now, &[HOST])?;
    let until = next.now + Duration::from_secs(5);
    next.run(&mut second, &mut s, until)?;
    assert!(
        !s.rejections.iter().any(|r| r.1 == 437),
        "no Allocation Mismatch: {:?}",
        s.rejections
    );
    assert_eq!(
        next.relayed().len(),
        1,
        "the second connection has its relayed candidate"
    );
    Ok(())
}

/// RFC 8656 section 7.4: an allocation left on the 5-tuple (a peer connection dropped without
/// `close()`) makes the next Allocate from it 437. The engine says so
/// (`OnTurnRequestRejected`) and allocates from the transport's other UDP base.
#[test]
fn a_437_moves_the_allocate_to_another_base() -> Result<()> {
    let mut run = Run {
        now: Instant::now(),
        events: vec![],
    };
    let mut s = server(run.now);
    let mut dropped = peer(run.now, &[HOST])?;
    let until = run.now + Duration::from_secs(5);
    run.run(&mut dropped, &mut s, until)?;
    drop(dropped);
    assert_eq!(s.allocations.len(), 1, "left behind");

    let mut next = Run {
        now: run.now,
        events: vec![],
    };
    let mut pc = peer(next.now, &[HOST, HOST_2])?;
    let until = next.now + Duration::from_secs(10);
    next.run(&mut pc, &mut s, until)?;
    assert!(
        s.rejections
            .iter()
            .any(|r| r.0 == METHOD_ALLOCATE && r.1 == 437)
    );
    assert!(next.events.iter().any(|e| matches!(
        e,
        RTCPeerConnectionEvent::OnTurnRequestRejected {
            method: "Allocate",
            error_code: 437,
            ..
        }
    )));
    let relayed = next.relayed();
    assert_eq!(relayed.len(), 1, "{relayed:?}");
    assert!(relayed[0].contains("rport 4001"), "{}", relayed[0]);
    Ok(())
}
