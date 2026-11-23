//! ICE-TCP built into the engine (RFC 6544, RFC 4571): two `rtc` peers whose application adds
//! only a UDP host candidate and serves the stream interface; the engine gathers the TCP
//! candidates, opens, frames, reuses and closes the connections. On `tests/stream_net`, an
//! in-memory network on a virtual clock that cuts every write into random pieces, delays,
//! refuses and breaks connections, and can drop UDP.

mod stream_net;

use anyhow::{Result, bail};
use bytes::BytesMut;
use rtc::peer_connection::configuration::RTCConfigurationBuilder;
use rtc::peer_connection::configuration::setting_engine::{SettingEngine, SettingEngineBuilder};
use rtc::peer_connection::event::RTCPeerConnectionEvent;
use rtc::peer_connection::state::RTCIceGatheringState;
use rtc::peer_connection::transport::RTCIceCandidateInit;
use rtc::peer_connection::{RTCPeerConnection, RTCPeerConnectionBuilder};
use rtc::sansio::Protocol;
use rtc::shared::stream::{StreamCommand, StreamEvent};
use rtc::statistics::StatsSelector;
use rtc::statistics::report::RTCStatsReportEntry;
use std::time::{Duration, Instant};
use stream_net::{Net, Peer, udp_host};

fn pc(settings: SettingEngine) -> RTCPeerConnection {
    RTCPeerConnectionBuilder::new()
        .with_configuration(RTCConfigurationBuilder::new().build())
        .with_setting_engine(settings)
        .build(Instant::now())
        .unwrap()
}

fn peers(settings: impl Fn() -> SettingEngine) -> Vec<Peer> {
    vec![Peer::new(pc(settings()), 0), Peer::new(pc(settings()), 1)]
}

/// Offer from peer 0, answer from peer 1, each adds its UDP host candidate.
fn negotiate(peers: &mut [Peer], net: &Net) -> Result<rtc::data_channel::RTCDataChannelId> {
    let now = net.now;
    let channel = peers[0].pc.create_data_channel("tcp", None)?.id();
    let offer = peers[0].pc.create_offer(None)?;
    peers[0].pc.set_local_description(now, offer.clone())?;
    peers[1].pc.set_remote_description(now, offer)?;
    let answer = peers[1].pc.create_answer(None)?;
    peers[1].pc.set_local_description(now, answer.clone())?;
    peers[0].pc.set_remote_description(now, answer)?;
    for p in peers.iter_mut() {
        let c = udp_host(p);
        p.pc.add_local_candidate(c)?;
    }
    Ok(channel)
}

/// Runs until every message of `messages` reached peer 1, or fails at `deadline` of virtual
/// time. `each` runs every pass (to break things on the way).
fn exchange(
    peers: &mut [Peer],
    net: &mut Net,
    channel: rtc::data_channel::RTCDataChannelId,
    messages: &[Vec<u8>],
    deadline: Duration,
    mut each: impl FnMut(&mut Net, &mut [Peer]),
) -> Result<()> {
    let mut sent = 0;
    while net.elapsed() < deadline {
        net.step(peers);
        each(net, peers);
        if peers[0].channel_open == Some(channel) && sent < messages.len() {
            let mut dc = peers[0].pc.data_channel(channel).expect("open channel");
            while sent < messages.len() {
                dc.send(net.now, BytesMut::from(&messages[sent][..]))?;
                sent += 1;
            }
        }
        if sent == messages.len() && peers[1].received.len() >= messages.len() {
            return Ok(());
        }
        net.advance(peers);
    }
    bail!(
        "not done after {deadline:?}: connected {}/{}, {} of {} messages, connections {:?}",
        peers[0].connected(),
        peers[1].connected(),
        peers[1].received.len(),
        messages.len(),
        net.conns,
    )
}

fn messages() -> Vec<Vec<u8>> {
    let mut out = vec![b"over engine tcp".to_vec(), vec![7u8; 60_000]];
    out.extend((0..40u8).map(|i| vec![i; 300]));
    out
}

/// The protocol of each peer's nominated pair's local candidate.
fn nominated_protocol(pc: &mut RTCPeerConnection, now: Instant) -> Option<String> {
    let report = pc.get_stats(now, StatsSelector::None);
    let pair = report.candidate_pairs().find(|p| p.nominated)?;
    report.iter().find_map(|e| match e {
        RTCStatsReportEntry::LocalCandidate(c) if c.stats.id == pair.local_candidate_id => {
            Some(c.protocol.clone())
        }
        _ => None,
    })
}

#[test]
fn with_udp_blocked_the_engine_gathers_tcp_candidates_and_connects_over_them() -> Result<()> {
    let mut net = Net::new();
    let mut peers = peers(SettingEngine::default);
    let channel = negotiate(&mut peers, &net)?;
    let expected = messages();
    exchange(
        &mut peers,
        &mut net,
        channel,
        &expected,
        Duration::from_secs(30),
        |_, _| {},
    )?;
    assert_eq!(peers[1].received, expected, "every message, in order");
    let now = net.now;
    for (i, p) in peers.iter_mut().enumerate() {
        let announced = p.announced();
        for tcptype in ["passive", "active", "so"] {
            assert!(
                announced
                    .iter()
                    .any(|c| c.contains(" tcp ") && c.contains(&format!("tcptype {tcptype}"))),
                "peer {i} announced a {tcptype} TCP candidate: {announced:?}"
            );
        }
        assert!(
            announced
                .iter()
                .any(|c| c.contains(" 9 typ host tcptype active")),
            "an active candidate is signalled with port 9 (RFC 6544 4.5): {announced:?}"
        );
        assert_eq!(nominated_protocol(&mut p.pc, now).as_deref(), Some("tcp"));
    }
    assert_eq!(
        net.tcp_writes_via_poll_write, 0,
        "the engine's TCP never reaches poll_write"
    );
    // RFC 6544 section 7.1: an active candidate's connections leave from an ephemeral port of
    // its interface (port 0 asked for), not from port 9 or a listener's port.
    let active_connects: Vec<_> = peers
        .iter()
        .flat_map(|p| p.commands.iter())
        .filter_map(|c| match c {
            StreamCommand::Connect {
                local,
                reuse_address: false,
                ..
            } => Some(*local),
            _ => None,
        })
        .collect();
    assert!(!active_connects.is_empty());
    assert!(
        active_connects.iter().all(|l| l.port() == 0),
        "{active_connects:?}"
    );
    Ok(())
}

#[test]
fn reads_cut_into_single_bytes_and_slow_writes_change_nothing() -> Result<()> {
    let mut net = Net::new();
    net.max_segment = 1;
    net.written_delay = Duration::from_millis(30);
    net.latency = Duration::from_millis(40);
    let mut peers = peers(|| {
        SettingEngineBuilder::new()
            .with_stream_limits(rtc::shared::stream::StreamConfig {
                window: 4096,
                ..Default::default()
            })
            .build()
    });
    let channel = negotiate(&mut peers, &net)?;
    let expected = messages();
    exchange(
        &mut peers,
        &mut net,
        channel,
        &expected,
        Duration::from_secs(60),
        |_, _| {},
    )?;
    assert_eq!(peers[1].received, expected);
    Ok(())
}

#[test]
fn with_udp_open_the_udp_pair_wins_and_the_unused_tcp_connections_are_closed() -> Result<()> {
    let mut net = Net::new();
    net.udp = true;
    let mut peers = peers(SettingEngine::default);
    let channel = negotiate(&mut peers, &net)?;
    exchange(
        &mut peers,
        &mut net,
        channel,
        &[b"x".to_vec()],
        Duration::from_secs(30),
        |_, _| {},
    )?;
    // Let the checks that were under way finish, then everything settles.
    let until = net.elapsed() + Duration::from_secs(3);
    while net.elapsed() < until {
        net.step(&mut peers);
        net.advance(&mut peers);
    }
    let now = net.now;
    for p in peers.iter_mut() {
        assert_eq!(nominated_protocol(&mut p.pc, now).as_deref(), Some("udp"));
    }
    assert!(!net.conns.is_empty(), "TCP pairs were checked too");
    assert_eq!(
        net.open_connections(),
        0,
        "RFC 6544 section 8: no TCP connection outlives ICE completion: {:?}",
        net.conns
    );
    Ok(())
}

#[test]
fn with_the_close_of_unused_connections_off_they_stay_open() -> Result<()> {
    let mut net = Net::new();
    net.udp = true;
    let mut peers = peers(|| {
        SettingEngineBuilder::new()
            .with_tcp_close_unused_connections(false)
            .build()
    });
    let channel = negotiate(&mut peers, &net)?;
    exchange(
        &mut peers,
        &mut net,
        channel,
        &[b"x".to_vec()],
        Duration::from_secs(30),
        |_, _| {},
    )?;
    let until = net.elapsed() + Duration::from_secs(3);
    while net.elapsed() < until {
        net.step(&mut peers);
        net.advance(&mut peers);
    }
    assert!(net.open_connections() > 0);
    assert!(net.closes_seen.is_empty(), "{:?}", net.closes_seen);
    Ok(())
}

#[test]
fn a_broken_selected_connection_is_reopened_by_the_active_side_and_data_resumes() -> Result<()> {
    let mut net = Net::new();
    let mut peers = peers(SettingEngine::default);
    let channel = negotiate(&mut peers, &net)?;
    exchange(
        &mut peers,
        &mut net,
        channel,
        &[b"before".to_vec()],
        Duration::from_secs(30),
        |_, _| {},
    )?;
    let used = net
        .conns
        .iter()
        .position(|c| c.open)
        .expect("an open connection");
    net.break_connection(used);
    let mut expected = vec![b"before".to_vec()];
    expected.extend((0..20u8).map(|i| vec![i; 500]));
    // Send the rest after the break.
    let mut dc_sent = false;
    let deadline = net.elapsed() + Duration::from_secs(40);
    while net.elapsed() < deadline {
        net.step(&mut peers);
        if !dc_sent {
            let mut dc = peers[0].pc.data_channel(channel).expect("channel");
            for m in &expected[1..] {
                dc.send(net.now, BytesMut::from(&m[..]))?;
            }
            dc_sent = true;
        }
        if peers[1].received.len() >= expected.len() {
            break;
        }
        net.advance(&mut peers);
    }
    if peers[1].received.len() != expected.len() {
        let now = net.now;
        for (i, p) in peers.iter_mut().enumerate() {
            let report = p.pc.get_stats(now, StatsSelector::None);
            for pair in report.candidate_pairs() {
                eprintln!(
                    "peer {i}: {} -> {} {:?} nominated {}",
                    pair.local_candidate_id, pair.remote_candidate_id, pair.state, pair.nominated
                );
            }
            eprintln!("peer {i} announced {:?}", p.announced());
            eprintln!(
                "peer {i} events {:?}",
                p.events
                    .iter()
                    .map(|e| format!("{e:?}").chars().take(90).collect::<String>())
                    .collect::<Vec<_>>()
            );
        }
        eprintln!("broke {used}; connections {:?}", net.conns);
    }
    assert_eq!(
        peers[1].received.len(),
        expected.len(),
        "data resumed on a new connection"
    );
    assert_eq!(peers[1].received, expected);
    assert!(
        net.conns.iter().skip(used + 1).any(|c| c.open),
        "a new connection carries it: {:?}",
        net.conns
    );
    Ok(())
}

#[test]
fn simultaneous_open_candidates_connect_when_passive_ones_cannot() -> Result<()> {
    let mut net = Net::new();
    net.refuse_plain_listeners = true;
    let mut peers = peers(SettingEngine::default);
    let channel = negotiate(&mut peers, &net)?;
    exchange(
        &mut peers,
        &mut net,
        channel,
        &[b"s-o".to_vec()],
        Duration::from_secs(60),
        |_, _| {},
    )?;
    let now = net.now;
    for p in peers.iter_mut() {
        let report = p.pc.get_stats(now, StatsSelector::None);
        let pair = report.candidate_pairs().find(|p| p.nominated).unwrap();
        let local = report
            .iter()
            .find_map(|e| match e {
                RTCStatsReportEntry::LocalCandidate(c) if c.stats.id == pair.local_candidate_id => {
                    Some(c)
                }
                _ => None,
            })
            .unwrap();
        assert_eq!(local.protocol, "tcp");
        assert_eq!(
            local.tcp_type,
            rtc::peer_connection::transport::RTCIceTcpCandidateType::SimultaneousOpen,
            "the S-O / S-O pair (RFC 6544 6.2)"
        );
    }
    Ok(())
}

#[test]
fn a_refused_connection_fails_its_pair_at_once() -> Result<()> {
    let mut net = Net::new();
    net.refuse_plain_listeners = true;
    let mut peers = peers(|| {
        SettingEngineBuilder::new()
            .with_tcp_simultaneous_open(false)
            .build()
    });
    negotiate(&mut peers, &net)?;
    // Long enough for the checks and refusals, far below Ti (39.5 s).
    let until = net.elapsed() + Duration::from_secs(2);
    while net.elapsed() < until {
        net.step(&mut peers);
        net.advance(&mut peers);
    }
    let now = net.now;
    let report = peers[0].pc.get_stats(now, StatsSelector::None);
    let failed = report
        .candidate_pairs()
        .filter(|p| {
            p.state
                == rtc::statistics::stats::ice_candidate_pair::RTCStatsIceCandidatePairState::Failed
        })
        .count();
    assert!(
        failed > 0,
        "a refused TCP connection failed its pair (RFC 6544 7.1)"
    );
    Ok(())
}

#[test]
fn a_frame_that_is_neither_stun_dtls_nor_rtp_resets_its_connection() -> Result<()> {
    let mut net = Net::new();
    let mut peers = peers(SettingEngine::default);
    let channel = negotiate(&mut peers, &net)?;
    exchange(
        &mut peers,
        &mut net,
        channel,
        &[b"x".to_vec()],
        Duration::from_secs(30),
        |_, _| {},
    )?;
    let conn = net.conns.iter().find(|c| c.open).expect("open");
    let end = conn.b.unwrap();
    // A frame whose first byte (0x50) RFC 7983 gives to nobody: the framing is lost.
    peers[end.peer]
        .pc
        .handle_stream_read(net.now, end.id, &[0x00, 0x02, 0x50, 0x00])?;
    let mut reset = false;
    while let Some(cmd) = peers[end.peer].pc.poll_stream_command() {
        reset |= cmd == StreamCommand::Reset { id: end.id };
    }
    assert!(reset, "RFC 4571 section 2: the connection is reset");
    Ok(())
}

#[test]
fn no_stream_command_when_tcp_gathering_is_off_or_the_policy_is_relay() -> Result<()> {
    use rtc::peer_connection::configuration::RTCIceTransportPolicy;
    let off = SettingEngineBuilder::new()
        .with_tcp_candidate_gathering(false)
        .build();
    let mut a = Peer::new(pc(off), 0);
    let relay = RTCPeerConnectionBuilder::new()
        .with_configuration(
            RTCConfigurationBuilder::new()
                .with_ice_transport_policy(RTCIceTransportPolicy::Relay)
                .build(),
        )
        .build(Instant::now())?;
    let mut b = Peer::new(relay, 1);
    for p in [&mut a, &mut b] {
        let c = udp_host(p);
        let _ = p.pc.add_local_candidate(c);
        assert_eq!(p.pc.poll_stream_command(), None);
    }
    Ok(())
}

#[test]
fn end_of_gathering_waits_for_the_listeners_of_a_driver_that_serves_them() -> Result<()> {
    let mut p = Peer::new(pc(SettingEngine::default()), 0);
    let c = udp_host(&p);
    p.pc.add_local_candidate(c)?;
    let mut listens = vec![];
    while let Some(cmd) = p.pc.poll_stream_command() {
        if let StreamCommand::Listen {
            listener, local, ..
        } = cmd
        {
            listens.push((listener, local));
        }
    }
    assert_eq!(
        listens.len(),
        2,
        "a passive and a simultaneous-open listener"
    );
    p.pc.add_local_candidate(RTCIceCandidateInit::default())?;
    assert_ne!(p.pc.ice_gathering_state(), RTCIceGatheringState::Complete);
    let now = Instant::now();
    for (i, (listener, local)) in listens.into_iter().enumerate() {
        let bound = std::net::SocketAddr::new(local.ip(), 6000 + i as u16);
        p.pc.handle_stream_event(
            now,
            StreamEvent::Listening {
                listener,
                local: bound,
            },
        )?;
    }
    assert_eq!(p.pc.ice_gathering_state(), RTCIceGatheringState::Complete);
    let mut candidates = vec![];
    let mut complete_after = false;
    while let Some(e) = p.pc.poll_event() {
        if let RTCPeerConnectionEvent::OnIceCandidateEvent(ev) = e {
            match ev.candidate {
                Some(c) if !c.end_of_candidates => {
                    assert!(!complete_after, "a candidate after end-of-candidates");
                    candidates.push(c.to_json()?.candidate);
                }
                _ => complete_after = true,
            }
        }
    }
    assert_eq!(
        candidates.len(),
        4,
        "UDP, passive, S-O, active: {candidates:?}"
    );
    Ok(())
}

#[test]
fn an_application_that_never_serves_streams_gets_no_tcp_candidate_and_ends_gathering_at_once()
-> Result<()> {
    let mut p = Peer::new(pc(SettingEngine::default()), 0);
    let c = udp_host(&p);
    p.pc.add_local_candidate(c)?;
    p.pc.add_local_candidate(RTCIceCandidateInit::default())?;
    assert_eq!(p.pc.ice_gathering_state(), RTCIceGatheringState::Complete);
    let mut tcp = 0;
    while let Some(e) = p.pc.poll_event() {
        if let RTCPeerConnectionEvent::OnIceCandidateEvent(ev) = e
            && ev
                .candidate
                .is_some_and(|c| c.to_string().contains(" tcp "))
        {
            tcp += 1;
        }
    }
    assert_eq!(tcp, 0);
    Ok(())
}
