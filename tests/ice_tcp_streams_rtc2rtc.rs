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

fn pc(settings: SettingEngine, now: Instant) -> RTCPeerConnection {
    RTCPeerConnectionBuilder::new()
        .with_configuration(RTCConfigurationBuilder::new().build())
        .with_setting_engine(settings)
        .build(now)
        .unwrap()
}

/// Both peers, built at the network's virtual start: a peer's ICE agent paces its checks (Ta)
/// from the instant it is built, so a peer built at `Instant::now()` would start its checks as
/// much later on the virtual clock as building took in real time, and the course of a run (which
/// checks happen before the nomination ends them) would depend on the machine's load.
fn peers(net: &Net, settings: impl Fn() -> SettingEngine) -> Vec<Peer> {
    vec![
        Peer::new(pc(settings(), net.start), 0),
        Peer::new(pc(settings(), net.start), 1),
    ]
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
    let mut peers = peers(&net, SettingEngine::default);
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
    let mut peers = peers(&net, || {
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

/// RFC 6544 section 9.2: "If an ICE restart occurs for a media stream with TCP candidate
/// pairs that have been selected by ICE, the agents MUST NOT close the connections after the
/// restart." Two peers connected over TCP (UDP blocked) restart ICE: no connection open when
/// the restart starts is closed before each peer's new generation has selected a pair, and
/// the messages sent across the restart arrive.
#[test]
fn an_ice_restart_does_not_close_the_selected_tcp_connection() -> Result<()> {
    let mut net = Net::new();
    let mut peers = peers(&net, SettingEngine::default);
    let channel = negotiate(&mut peers, &net)?;
    exchange(
        &mut peers,
        &mut net,
        channel,
        &[b"before the restart".to_vec()],
        Duration::from_secs(30),
        |_, _| {},
    )?;
    // The connections of pairs that were not selected close once ICE has completed (RFC
    // 6544 section 8); what stays open carries the selected pair.
    let until = net.elapsed() + Duration::from_secs(3);
    while net.elapsed() < until {
        net.step(&mut peers);
        net.advance(&mut peers);
    }
    let now = net.now;
    for p in peers.iter_mut() {
        assert_eq!(nominated_protocol(&mut p.pc, now).as_deref(), Some("tcp"));
    }
    let selected: Vec<(usize, rtc::shared::stream::StreamId)> = net
        .conns
        .iter()
        .filter(|c| c.open)
        .flat_map(|c| {
            [
                Some((c.a.peer, c.a.id)),
                c.b.as_ref().map(|b| (b.peer, b.id)),
            ]
        })
        .flatten()
        .collect();
    assert!(
        !selected.is_empty(),
        "a TCP connection carries the selected pair"
    );
    let ufrags: Vec<String> = peers
        .iter()
        .map(|p| p.pc.local_description().map(|d| d.sdp).unwrap_or_default())
        .collect();

    let closes = net.closes_seen.len();
    let marks: Vec<usize> = peers.iter().map(|p| p.events.len()).collect();
    peers[0].pc.restart_ice();
    let offer = peers[0].pc.create_offer(None)?;
    peers[0].pc.set_local_description(now, offer.clone())?;
    peers[1].pc.set_remote_description(now, offer)?;
    let answer = peers[1].pc.create_answer(None)?;
    peers[1].pc.set_local_description(now, answer.clone())?;
    peers[0].pc.set_remote_description(now, answer)?;
    for (i, p) in peers.iter().enumerate() {
        let sdp = p.pc.local_description().map(|d| d.sdp).unwrap_or_default();
        let ufrag = |sdp: &str| {
            sdp.lines()
                .find_map(|l| l.strip_prefix("a=ice-ufrag:").map(str::to_owned))
        };
        assert_ne!(ufrag(&sdp), ufrag(&ufrags[i]), "peer {i}: an ICE restart");
    }

    let mut closed_early = vec![];
    let mut seen = closes;
    let expected = messages();
    exchange(
        &mut peers,
        &mut net,
        channel,
        &expected,
        Duration::from_secs(30),
        |net, peers| {
            for &(peer, id) in &net.closes_seen[seen..] {
                let reselected = peers.iter().zip(&marks).all(|(p, mark)| {
                    p.events[*mark..].iter().any(|e| {
                        matches!(e, RTCPeerConnectionEvent::OnSelectedCandidatePairChange(_))
                    })
                });
                if selected.contains(&(peer, id)) && !reselected {
                    closed_early.push((peer, id));
                }
            }
            seen = net.closes_seen.len();
        },
    )?;
    assert_eq!(
        closed_early,
        vec![],
        "the selected pair's connection was closed during the restart"
    );
    assert_eq!(
        peers[1].received[1..],
        expected[..],
        "every message sent across the restart, in order"
    );
    Ok(())
}

/// UDP open: the peers connect over the UDP pair and close every TCP connection their checks
/// opened (RFC 6544 section 8).
///
/// The TCP connection whose close this proves exists because the controlled peer (the
/// answerer, peer 1) starts its check on the active-to-passive TCP pair in its second Ta slot,
/// 50 ms after its first, before the controlling peer's nomination of the UDP pair reaches it:
/// RFC 8445 section 8.1.2 then removes every other pair from the checklist, and nothing obliges
/// an agent to check a lower-priority pair first ("The criteria for stopping the connectivity
/// checks ... are a matter of local optimization", section 8.1.1). On the virtual clock that
/// order is fixed, but only because both peers are built at its start (`peers`).
fn udp_wins_and_the_unused_tcp_connections_close(mut net: Net, mut peers: Vec<Peer>) -> Result<()> {
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
    assert!(
        !net.conns.is_empty(),
        "the controlled peer checked the TCP pair before the nomination reached it"
    );
    assert_eq!(
        net.open_connections(),
        0,
        "RFC 6544 section 8: no TCP connection outlives ICE completion: {:?}",
        net.conns
    );
    Ok(())
}

#[test]
fn with_udp_open_the_udp_pair_wins_and_the_unused_tcp_connections_are_closed() -> Result<()> {
    let mut net = Net::new();
    net.udp = true;
    let peers = peers(&net, SettingEngine::default);
    udp_wins_and_the_unused_tcp_connections_close(net, peers)
}

/// The run above does not depend on how long the peers took to build in real time. Built at
/// `Instant::now()`, a second peer built 11 to 40 ms after the first (a preempted thread on a
/// loaded Windows runner, whose scheduler quantum is about 15.6 ms) had its Ta slots that much
/// later on the virtual clock: its second slot came after the nomination, it never checked the
/// TCP pair, and no connection was opened (seen once on GitHub's windows-latest).
#[test]
fn the_course_of_a_run_does_not_depend_on_the_real_time_building_the_peers_took() -> Result<()> {
    let mut net = Net::new();
    net.udp = true;
    let built = std::cell::Cell::new(0);
    let peers = peers(&net, || {
        if built.get() == 1 {
            std::thread::sleep(Duration::from_millis(20));
        }
        built.set(built.get() + 1);
        SettingEngine::default()
    });
    udp_wins_and_the_unused_tcp_connections_close(net, peers)
}

#[test]
fn with_the_close_of_unused_connections_off_they_stay_open() -> Result<()> {
    let mut net = Net::new();
    net.udp = true;
    let mut peers = peers(&net, || {
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
    let mut peers = peers(&net, SettingEngine::default);
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
    let mut peers = peers(&net, SettingEngine::default);
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
    let mut peers = peers(&net, || {
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
    let mut peers = peers(&net, SettingEngine::default);
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
    let mut a = Peer::new(pc(off, Instant::now()), 0);
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
    let mut p = Peer::new(pc(SettingEngine::default(), Instant::now()), 0);
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
    let mut p = Peer::new(pc(SettingEngine::default(), Instant::now()), 0);
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

/// `with_nat_1to1_ips` (a server behind a 1:1 NAT, rtc-ice's external IP mapper) reaches the
/// engine's own TCP candidates: with the `Host` type they are announced on the external
/// address, with `Srflx` a server-reflexive candidate is added beside each.
#[test]
fn nat_1to1_addresses_apply_to_the_engines_tcp_candidates() -> Result<()> {
    use rtc::peer_connection::transport::RTCIceCandidateType;
    for (kind, expect_host, expect_srflx) in [
        (RTCIceCandidateType::Host, true, false),
        (RTCIceCandidateType::Srflx, false, true),
    ] {
        let settings = SettingEngineBuilder::new()
            .with_nat_1to1_ips(vec!["203.0.113.7".to_owned()], kind)
            .build();
        let mut p = Peer::new(pc(settings, Instant::now()), 0);
        let c = udp_host(&p);
        p.pc.add_local_candidate(c)?;
        let now = Instant::now();
        let mut port = 7000;
        while let Some(cmd) = p.pc.poll_stream_command() {
            if let StreamCommand::Listen {
                listener, local, ..
            } = cmd
            {
                port += 1;
                p.pc.handle_stream_event(
                    now,
                    StreamEvent::Listening {
                        listener,
                        local: std::net::SocketAddr::new(local.ip(), port),
                    },
                )?;
            }
        }
        let mut lines = vec![];
        while let Some(e) = p.pc.poll_event() {
            if let RTCPeerConnectionEvent::OnIceCandidateEvent(ev) = e
                && let Some(c) = ev.candidate.filter(|c| !c.end_of_candidates)
            {
                lines.push(c.to_json()?.candidate);
            }
        }
        let tcp: Vec<&String> = lines.iter().filter(|l| l.contains(" tcp ")).collect();
        assert!(
            tcp.iter()
                .any(|l| l.contains("203.0.113.7 7001 typ host tcptype passive"))
                == expect_host,
            "{kind:?}: {tcp:?}"
        );
        assert!(
            tcp.iter()
                .any(|l| l.contains("203.0.113.7 7001 typ srflx") && l.contains("tcptype passive"))
                == expect_srflx,
            "{kind:?}: {tcp:?}"
        );
    }
    Ok(())
}

/// The offerer under `max-compat` with an audio section and a data section, answered by a peer
/// that does not bundle (the BUNDLE group is taken out of the offer): two transports on each
/// side (RFC 9429 section 5.2.1). Each transport's UDP host candidate is added with its
/// section, on a port of its own; UDP is blocked.
fn negotiate_two_transports(
    peers: &mut [Peer],
    net: &Net,
) -> Result<rtc::data_channel::RTCDataChannelId> {
    use rtc::rtp_transceiver::RTCRtpTransceiverDirection;
    use rtc::rtp_transceiver::RTCRtpTransceiverInit;
    use rtc::rtp_transceiver::rtp_sender::RtpCodecKind;
    let now = net.now;
    peers[0].pc.add_transceiver_from_kind(
        RtpCodecKind::Audio,
        Some(RTCRtpTransceiverInit {
            direction: RTCRtpTransceiverDirection::Sendonly,
            streams: vec![],
            send_encodings: vec![],
        }),
    )?;
    let channel = peers[0].pc.create_data_channel("tcp", None)?.id();
    let offer = peers[0].pc.create_offer(None)?;
    peers[0].pc.set_local_description(now, offer.clone())?;
    let unbundled: String = offer
        .sdp
        .lines()
        .filter(|l| !l.starts_with("a=group:BUNDLE"))
        .map(|l| format!("{l}\r\n"))
        .collect();
    peers[1].pc.set_remote_description(
        now,
        rtc::peer_connection::sdp::RTCSessionDescription::offer(unbundled)?,
    )?;
    let answer = peers[1].pc.create_answer(None)?;
    peers[1].pc.set_local_description(now, answer.clone())?;
    peers[0].pc.set_remote_description(now, answer)?;
    for p in peers.iter_mut() {
        let sections = p.pc.ice_transport_sections();
        assert_eq!(sections.len(), 2, "two transports: {sections:?}");
        for (k, (mid, index)) in sections.into_iter().enumerate() {
            p.pc.add_local_candidate(RTCIceCandidateInit {
                candidate: format!(
                    "candidate:{} 1 udp 2130706431 {} {} typ host",
                    k + 1,
                    p.ip,
                    4000 + k
                ),
                sdp_mid: Some(mid),
                sdp_mline_index: Some(index),
                ..Default::default()
            })?;
        }
    }
    Ok(channel)
}

fn max_compat_peers(net: &Net, settings: impl Fn() -> SettingEngine) -> Result<Vec<Peer>> {
    use rtc::peer_connection::configuration::RTCBundlePolicy;
    use rtc::peer_connection::configuration::media_engine::MediaEngine;
    let mut peers = vec![];
    for (i, policy) in [RTCBundlePolicy::MaxCompat, RTCBundlePolicy::Balanced]
        .into_iter()
        .enumerate()
    {
        let mut media_engine = MediaEngine::default();
        media_engine.register_default_codecs()?;
        let pc = RTCPeerConnectionBuilder::new()
            .with_configuration(
                RTCConfigurationBuilder::new()
                    .with_bundle_policy(policy)
                    .build(),
            )
            .with_media_engine(media_engine)
            .with_setting_engine(settings())
            .build(net.start)?;
        peers.push(Peer::new(pc, i));
    }
    Ok(peers)
}

/// The sdpMids the TCP candidates a peer announced name.
fn tcp_candidate_mids(p: &Peer) -> std::collections::BTreeSet<String> {
    p.events
        .iter()
        .filter_map(|e| match e {
            RTCPeerConnectionEvent::OnIceCandidateEvent(ev) => ev.candidate.as_ref(),
            _ => None,
        })
        .filter(|c| !c.end_of_candidates)
        .filter_map(|c| c.to_json().ok())
        .filter(|init| init.candidate.contains(" tcp "))
        .filter_map(|init| init.sdp_mid)
        .collect()
}

/// RFC 6544 with RFC 9429 section 5.2.1: each transport of a connection gathers TCP
/// candidates of its own (its own listeners, announced with its section) and its checks run
/// on connections of its own; with UDP blocked both transports connect over TCP, so the
/// connection (the aggregate of both) connects and the data channel on the second transport
/// carries every message.
#[test]
fn every_transport_of_an_unbundled_connection_gathers_and_connects_over_tcp() -> Result<()> {
    let mut net = Net::new();
    let mut peers = max_compat_peers(&net, SettingEngine::default)?;
    let channel = negotiate_two_transports(&mut peers, &net)?;
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
    for (i, p) in peers.iter().enumerate() {
        assert!(p.connected(), "peer {i}: both transports connected");
        assert_eq!(
            tcp_candidate_mids(p).len(),
            2,
            "peer {i} announced TCP candidates for both sections"
        );
        let listens = p
            .commands
            .iter()
            .filter(|c| matches!(c, StreamCommand::Listen { .. }))
            .count();
        assert_eq!(
            listens, 4,
            "peer {i}: a passive and a simultaneous-open listener per transport"
        );
        assert_eq!(p.pc.ice_username_fragments().len(), 2);
    }
    assert_eq!(net.tcp_writes_via_poll_write, 0);
    Ok(())
}

/// A driver that shares one passive ICE-TCP port (`rtc-stream-driver`'s `shared_passive`)
/// gives both transports' passive candidates the same address and reports every accept on
/// one listener. The engine gives each accepted connection to the transport its first check
/// names (RFC 8445 section 7.2.2) and answers on it; with simultaneous open off, every pair is
/// active to passive, so both transports connect through the shared port. The transports need
/// credentials of their own for it (`with_unique_transport_credentials`): by default they
/// share the first transport's, and the ufrag of a check then names none of them.
#[test]
fn a_shared_passive_port_serves_every_transport_by_the_ufrag_of_its_first_check() -> Result<()> {
    let mut net = Net::new();
    net.shared_passive_port = Some(7000);
    let mut peers = max_compat_peers(&net, || {
        SettingEngineBuilder::new()
            .with_tcp_simultaneous_open(false)
            // Both sides sharing their credentials leave nothing in a first check on the
            // shared passive port that names a transport (docs/conformance.md, several
            // transports, mt-9).
            .with_unique_transport_credentials(true)
            .build()
    })?;
    let channel = negotiate_two_transports(&mut peers, &net)?;
    let expected = messages();
    exchange(
        &mut peers,
        &mut net,
        channel,
        &expected,
        Duration::from_secs(30),
        |_, _| {},
    )?;
    assert_eq!(peers[1].received, expected);
    for (i, p) in peers.iter().enumerate() {
        assert!(p.connected(), "peer {i}: both transports connected");
        let passive: Vec<String> = p
            .announced()
            .into_iter()
            .filter(|c| c.contains("tcptype passive"))
            .collect();
        assert_eq!(passive.len(), 2, "one per transport: {passive:?}");
        assert!(
            passive.iter().all(|c| c.contains(" 7000 typ host")),
            "both on the shared port: {passive:?}"
        );
    }
    Ok(())
}

/// RFC 4571 section 3: one direction of a framed TCP connection carries RTP of several SSRCs,
/// and RTCP about several. Two senders (audio and video, bundled) on one ICE-TCP pair, UDP
/// blocked: the receiver reads RTP of both SSRCs and has the sender reports of both (its
/// remote-outbound-rtp statistics exist only once an SR for the SSRC arrived).
#[test]
fn rtp_and_rtcp_of_two_ssrcs_share_one_tcp_connection() -> Result<()> {
    use bytes::Bytes;
    use rtc::interceptor::Registry;
    use rtc::peer_connection::configuration::interceptor_registry::register_default_interceptors;
    use rtc::peer_connection::configuration::media_engine::MediaEngine;
    use rtc::rtp_transceiver::rtp_sender::{RTCRtpEncodingParameters, RtpCodecKind};
    use rtc::rtp_transceiver::{RTCRtpTransceiverDirection, RTCRtpTransceiverInit};

    let mut net = Net::new();
    let mut peers = vec![];
    for i in 0..2 {
        let mut media_engine = MediaEngine::default();
        media_engine.register_default_codecs()?;
        let registry = register_default_interceptors(Registry::new(), &mut media_engine)?;
        let pc = RTCPeerConnectionBuilder::new()
            .with_configuration(RTCConfigurationBuilder::new().build())
            .with_media_engine(media_engine)
            .with_interceptor_registry(registry)
            .build(net.start)?;
        peers.push(Peer::new(pc, i));
    }
    let mut senders = vec![];
    for kind in [RtpCodecKind::Audio, RtpCodecKind::Video] {
        let transceiver = peers[0].pc.add_transceiver_from_kind(
            kind,
            Some(RTCRtpTransceiverInit {
                direction: RTCRtpTransceiverDirection::Sendonly,
                streams: vec![],
                send_encodings: vec![RTCRtpEncodingParameters {
                    active: true,
                    ..Default::default()
                }],
            }),
        )?;
        senders.push(
            peers[0]
                .pc
                .rtp_transceiver(transceiver)
                .and_then(|t| t.sender())
                .expect("a sendonly transceiver has a sender"),
        );
    }
    let now = net.now;
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
    let mut ssrcs = vec![];
    let mut seq = 0u16;
    let mut next_send = net.now;
    while net.elapsed() < Duration::from_secs(30) {
        net.step(&mut peers);
        if peers[0].connected() && net.now >= next_send {
            seq = seq.wrapping_add(1);
            for sender in &senders {
                let (ssrc, payload_type) = {
                    let mut sender = peers[0].pc.rtp_sender(*sender).expect("sender");
                    let parameters = sender.get_parameters();
                    (
                        parameters.encodings[0]
                            .rtp_coding_parameters
                            .ssrc
                            .expect("an SSRC"),
                        parameters.rtp_parameters.codecs[0].payload_type,
                    )
                };
                if !ssrcs.contains(&ssrc) {
                    ssrcs.push(ssrc);
                }
                let header = rtc::rtp::header::Header {
                    version: 2,
                    payload_type,
                    sequence_number: seq,
                    timestamp: u32::from(seq) * 960,
                    ssrc,
                    marker: true,
                    ..Default::default()
                };
                peers[0].pc.rtp_sender(*sender).expect("sender").write_rtp(
                    net.now,
                    rtc::rtp::Packet {
                        header,
                        payload: Bytes::from(vec![0x10u8; 100]),
                    },
                )?;
            }
            next_send = net.now + Duration::from_millis(20);
        }
        if ssrcs.len() == 2 && ssrcs.iter().all(|s| peers[1].rtp_ssrcs.contains(s)) {
            let report = peers[1].pc.get_stats(net.now, StatsSelector::None);
            let reported: Vec<u32> = report
                .iter()
                .filter_map(|e| match e {
                    RTCStatsReportEntry::RemoteOutboundRtp(s) => {
                        Some(s.sent_rtp_stream_stats.rtp_stream_stats.ssrc)
                    }
                    _ => None,
                })
                .collect();
            if ssrcs.iter().all(|s| reported.contains(s)) {
                let now = net.now;
                for p in peers.iter_mut() {
                    assert_eq!(nominated_protocol(&mut p.pc, now).as_deref(), Some("tcp"));
                }
                assert_eq!(
                    net.open_connections(),
                    1,
                    "everything on one TCP connection"
                );
                return Ok(());
            }
        }
        net.advance(&mut peers);
    }
    bail!(
        "not done: connected {}, RTP SSRCs read {:?} of {ssrcs:?}",
        peers[0].connected(),
        peers[1]
            .rtp_ssrcs
            .iter()
            .collect::<std::collections::BTreeSet<_>>()
    )
}

/// Two transports behind one shared passive port (`rtc-stream-driver`'s `shared_passive`),
/// their selected connections broken: each active side reopens its transport's connection
/// (RFC 6544 section 11.1) with the next write, which can be DTLS rather than a check. On the
/// shared port nothing but a check names which transport such a connection carries (RFC 8445
/// section 7.2.2): a frame before one is not given to a transport guessed from the peer's
/// address, and the connection is tied to the transport the next check names. Data resumes
/// on both transports' connections.
#[test]
fn a_reopened_connection_on_a_shared_port_waits_for_a_check_to_name_its_transport() -> Result<()> {
    let mut net = Net::new();
    net.shared_passive_port = Some(7000);
    let mut peers = max_compat_peers(&net, || {
        SettingEngineBuilder::new()
            .with_tcp_simultaneous_open(false)
            .with_unique_transport_credentials(true)
            .build()
    })?;
    let channel = negotiate_two_transports(&mut peers, &net)?;
    exchange(
        &mut peers,
        &mut net,
        channel,
        &[b"before".to_vec()],
        Duration::from_secs(30),
        |_, _| {},
    )?;
    let broken: Vec<usize> = (0..net.conns.len())
        .filter(|i| net.conns[*i].open)
        .collect();
    assert!(!broken.is_empty(), "open connections to break");
    for i in &broken {
        net.break_connection(*i);
    }
    let mut expected = vec![b"before".to_vec()];
    expected.extend((0..20u8).map(|i| vec![i; 500]));
    let mut sent = false;
    let deadline = net.elapsed() + Duration::from_secs(60);
    while net.elapsed() < deadline {
        net.step(&mut peers);
        if !sent {
            let mut dc = peers[0].pc.data_channel(channel).expect("channel");
            for m in &expected[1..] {
                dc.send(net.now, BytesMut::from(&m[..]))?;
            }
            sent = true;
        }
        if peers[1].received.len() >= expected.len() {
            break;
        }
        net.advance(&mut peers);
    }
    assert_eq!(
        peers[1].received, expected,
        "data resumed on reopened connections: {:?}",
        net.conns
    );
    for (i, p) in peers.iter().enumerate() {
        assert!(!p.failed(), "peer {i} did not fail");
    }
    Ok(())
}

/// An ICE restart that moves the call from an ICE-TCP pair to a UDP pair: each peer selects
/// the new pair on its own (the controlled one when the nomination reaches it, the
/// controlling one when its response comes back), and until the other has, it still sends on
/// the TCP pair. The TCP connection of the replaced pair stays open while the agents take data
/// on it (`Agent::retired_media_path`, RFC 8445 section 12.2: "prepared to receive data on any
/// of the candidates provided in the most recent candidate exchange"): it is not closed before
/// both peers have selected the new pair. Closed by the first to select (RFC 6544 section 8
/// applied at once), whatever the other side sent on it meanwhile was lost: one RTP packet per
/// SRTP re-keying over ICE-TCP in `rtc-stream-driver`'s re-keying test.
#[test]
fn moving_from_tcp_to_udp_keeps_the_tcp_connection_until_both_peers_switched() -> Result<()> {
    let mut net = Net::new();
    let mut peers = peers(&net, SettingEngine::default);
    let channel = negotiate(&mut peers, &net)?;
    exchange(
        &mut peers,
        &mut net,
        channel,
        &[b"over tcp".to_vec()],
        Duration::from_secs(30),
        |_, _| {},
    )?;
    let until = net.elapsed() + Duration::from_secs(3);
    while net.elapsed() < until {
        net.step(&mut peers);
        net.advance(&mut peers);
    }
    let now = net.now;
    for p in peers.iter_mut() {
        assert_eq!(nominated_protocol(&mut p.pc, now).as_deref(), Some("tcp"));
    }
    let selected: Vec<(usize, rtc::shared::stream::StreamId)> = net
        .conns
        .iter()
        .filter(|c| c.open)
        .flat_map(|c| {
            [
                Some((c.a.peer, c.a.id)),
                c.b.as_ref().map(|b| (b.peer, b.id)),
            ]
        })
        .flatten()
        .collect();
    assert!(!selected.is_empty(), "a TCP connection carries the pair");

    // UDP opens; an ICE restart finds the UDP pair, of higher priority.
    net.udp = true;
    let marks: Vec<usize> = peers.iter().map(|p| p.events.len()).collect();
    let closes = net.closes_seen.len();
    peers[0].pc.restart_ice();
    let offer = peers[0].pc.create_offer(None)?;
    peers[0].pc.set_local_description(now, offer.clone())?;
    peers[1].pc.set_remote_description(now, offer)?;
    let answer = peers[1].pc.create_answer(None)?;
    peers[1].pc.set_local_description(now, answer.clone())?;
    peers[0].pc.set_remote_description(now, answer)?;

    let mut closed_early = vec![];
    let mut seen = closes;
    exchange(
        &mut peers,
        &mut net,
        channel,
        &messages(),
        Duration::from_secs(30),
        |net, peers| {
            for &(peer, id) in &net.closes_seen[seen..] {
                let both_switched = peers.iter().zip(&marks).all(|(p, mark)| {
                    p.events[*mark..].iter().any(|e| {
                        matches!(e, RTCPeerConnectionEvent::OnSelectedCandidatePairChange(_))
                    })
                });
                if selected.contains(&(peer, id)) && !both_switched {
                    closed_early.push((peer, id));
                }
            }
            seen = net.closes_seen.len();
        },
    )?;
    let until = net.elapsed() + Duration::from_secs(10);
    while net.elapsed() < until {
        net.step(&mut peers);
        net.advance(&mut peers);
    }
    let now = net.now;
    for p in peers.iter_mut() {
        assert_eq!(nominated_protocol(&mut p.pc, now).as_deref(), Some("udp"));
    }
    assert_eq!(
        closed_early,
        vec![],
        "the replaced pair's TCP connection closed before both peers selected the UDP pair"
    );
    assert_eq!(
        net.open_connections(),
        0,
        "once the agents no longer take data on it, it is closed (RFC 6544 section 8): {:?}",
        net.conns
    );
    Ok(())
}
