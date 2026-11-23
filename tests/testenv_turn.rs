//! A relayed call that outlives its TURN server's nonce, in the real-network test environment
//! (`scripts/test-env/run.sh`); ignored elsewhere.
//!
//! The environment runs a second coturn (`scripts/test-env/coturn/turnserver-stale.conf`, on
//! port 3479) whose nonces go stale after 10 s and whose allocations last at most 30 s. A client
//! that refreshes its allocation at half its lifetime sends that Refresh with a stale nonce, and
//! the server answers 438 (Stale Nonce). RFC 8656 4.4 / RFC 8489 9.2.4: the client takes the new
//! NONCE from the 438 and repeats the request. A client that gives up instead loses its
//! allocation when the 30 s run out, and the relayed call with it: on a stock server (a nonce
//! of an hour) that is the call that drops after about an hour.

mod common;
mod testenv;

use rtc::data_channel::RTCDataChannelId;
use rtc::peer_connection::RTCPeerConnectionBuilder;
use rtc::peer_connection::event::{RTCDataChannelEvent, RTCPeerConnectionEvent};
use rtc::peer_connection::message::RTCMessage;
use std::time::{Duration, Instant};
use testenv::{Env, EnvPeer, Gather, TurnTransport, negotiate, pump};

/// How long the call must keep carrying messages: past the 10 s nonce, the first Refresh at
/// 15 s, and the 30 s at which an unrefreshed allocation ends, with margin.
const CALL: Duration = Duration::from_secs(50);

fn dc_open(p: &EnvPeer) -> Option<RTCDataChannelId> {
    p.events.iter().find_map(|e| match e {
        RTCPeerConnectionEvent::OnDataChannel(RTCDataChannelEvent::OnOpen(id)) => Some(*id),
        _ => None,
    })
}

fn received_numbers(p: &EnvPeer) -> Vec<u32> {
    p.reads
        .iter()
        .filter_map(|m| match &m.message {
            RTCMessage::DataChannelMessage(_, msg) if msg.data.len() == 4 => {
                Some(u32::from_be_bytes(msg.data[..4].try_into().unwrap()))
            }
            _ => None,
        })
        .collect()
}

#[test]
#[ignore = "needs the real-network test environment (the short-nonce coturn, NAT namespaces): scripts/test-env/run.sh"]
fn relayed_call_outlives_a_stale_nonce() {
    common::install_crypto_provider();
    let env = Env::get().with_stale_nonce_turn();
    let new_pc = || {
        RTCPeerConnectionBuilder::new()
            .build(Instant::now())
            .unwrap()
    };
    // Behind symmetric NATs, relay candidates only: the relay is the only path.
    let gather = Gather::relay_only(TurnTransport::Udp);
    let mut a = EnvPeer::new("a", "h-symmetric-a", gather, &env, new_pc()).expect("peer a");
    let mut b = EnvPeer::new("b", "h-symmetric-b", gather, &env, new_pc()).expect("peer b");
    a.pc.create_data_channel("nonce", None).unwrap();
    negotiate(&mut a, &mut b).unwrap();

    // One numbered message every 250 ms for CALL, then a few seconds for the last to land.
    let mut next = 0u32;
    let mut last_send = Instant::now();
    let mut started: Option<Instant> = None;
    pump(&mut [&mut a, &mut b], CALL + Duration::from_secs(40), |p| {
        let Some(id) = dc_open(p[0]) else {
            return false;
        };
        let t0 = *started.get_or_insert_with(Instant::now);
        if t0.elapsed() < CALL
            && last_send.elapsed() >= Duration::from_millis(250)
            && let Some(mut dc) = p[0].pc.data_channel(id)
            && dc
                .send(
                    Instant::now(),
                    bytes::BytesMut::from(&next.to_be_bytes()[..]),
                )
                .is_ok()
        {
            next += 1;
            last_send = Instant::now();
        }
        (t0.elapsed() >= CALL && received_numbers(p[1]).len() as u32 >= next)
            || t0.elapsed() >= CALL + Duration::from_secs(10)
    })
    .unwrap();

    let got = received_numbers(&b);
    eprintln!(
        "TURN stale nonce: sent {next} messages over {CALL:?}, received {}; a relayed {} / errors {:?}, b relayed {} / errors {:?}",
        got.len(),
        a.sent_relayed,
        a.errors,
        b.sent_relayed,
        b.errors
    );
    assert!(
        started.is_some(),
        "the data channel never opened through the relay"
    );
    assert!(
        next as u64 >= CALL.as_millis() as u64 / 250 * 9 / 10,
        "a could only send {next} messages"
    );
    // A reliable, ordered channel: every message, in order, including those sent long after the
    // allocation would have expired without a Refresh.
    assert_eq!(
        got,
        (0..next).collect::<Vec<_>>(),
        "the relayed call stopped carrying messages (last received {:?} of {next})",
        got.last()
    );
    assert_eq!(
        a.sent_direct + b.sent_direct,
        0,
        "relay-only peers sent directly"
    );

    // The test proves nothing unless the server really refused a stale nonce.
    if let Some(log) = &env.turn_stale_log {
        let text = std::fs::read_to_string(log).unwrap_or_default();
        assert!(
            text.contains("438"),
            "the short-nonce coturn never answered 438 Stale Nonce ({log}); its nonce or allocation \
             lifetime did not apply, so the call never needed the retry"
        );
    }
}

/// `RelayGathering::Engine` (the default) with an application that runs its own TURN client
/// on the same socket and adds its relayed candidate itself, as the test environment's peers
/// do: the configuration names the same `turn:` server, and the engine leaves it to the
/// application. Each peer announces one relayed candidate (its own), the engine sends nothing
/// to coturn from the application's socket, and the call connects through the application's
/// allocations.
#[test]
#[ignore = "needs the real-network test environment (coturn, NAT namespaces): scripts/test-env/run.sh"]
fn an_application_gathering_its_own_relay_gets_no_engine_allocation_beside() {
    use rtc::peer_connection::configuration::{RTCConfigurationBuilder, RTCIceTransportPolicy};
    use rtc::peer_connection::transport::{RTCIceCandidateType, RTCIceServer};
    common::install_crypto_provider();
    let env = Env::get();
    let new_pc = || {
        RTCPeerConnectionBuilder::new()
            .with_configuration(
                RTCConfigurationBuilder::new()
                    .with_ice_servers(vec![RTCIceServer {
                        urls: vec![format!("turn:{}?transport=udp", env.turn_udp)],
                        username: env.user.clone(),
                        credential: env.pass.clone(),
                    }])
                    .with_ice_transport_policy(RTCIceTransportPolicy::Relay)
                    .build(),
            )
            .build(Instant::now())
            .unwrap()
    };
    // The host candidate gives the engine a base to allocate from, were it to.
    let gather = Gather {
        host: true,
        srflx: false,
        relay: Some(TurnTransport::Udp),
    };
    let mut a = EnvPeer::new("a", "h-symmetric-a", gather, &env, new_pc()).expect("peer a");
    let mut b = EnvPeer::new("b", "h-symmetric-b", gather, &env, new_pc()).expect("peer b");
    a.pc.create_data_channel("own-relay", None).unwrap();
    negotiate(&mut a, &mut b).unwrap();
    pump(&mut [&mut a, &mut b], Duration::from_secs(20), |p| {
        dc_open(p[0]).is_some() && dc_open(p[1]).is_some()
    })
    .unwrap();
    let relayed = |p: &EnvPeer| {
        p.events
            .iter()
            .filter(|e| {
                matches!(e, RTCPeerConnectionEvent::OnIceCandidateEvent(ev)
                    if ev.candidate.as_ref().is_some_and(|c| c.typ == RTCIceCandidateType::Relay))
            })
            .count()
    };
    eprintln!(
        "own relay: a {} relayed candidates, sent direct {}; b {} / {}",
        relayed(&a),
        a.sent_direct,
        relayed(&b),
        b.sent_direct
    );
    assert!(dc_open(&a).is_some(), "not connected through the relay");
    for p in [&a, &b] {
        assert_eq!(
            relayed(p),
            1,
            "{}: the application's relayed candidate only",
            p.name
        );
        assert_eq!(
            p.sent_direct, 0,
            "{}: the engine sent from the application's socket",
            p.name
        );
    }
}
