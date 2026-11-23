//! Server-reflexive candidates gathered by the engine (RFC 8445 section 5.1.1.2; RFC 8489
//! sections 6.2.1 and 6.2.2; RFC 6544 section 5.2; RFC 8305 section 3): the application adds a
//! host candidate, the engine asks the configured STUN server for the address a NAT gave it,
//! over UDP through `poll_write` / `handle_read`, over TCP through the stream interface, and
//! announces what the server reports. The server here is the test, answering by hand.

use anyhow::Result;
use bytes::BytesMut;
use rtc::peer_connection::configuration::setting_engine::{SettingEngine, SettingEngineBuilder};
use rtc::peer_connection::configuration::{RTCConfigurationBuilder, RTCIceServer};
use rtc::peer_connection::event::RTCPeerConnectionEvent;
use rtc::peer_connection::srflx::ReflexiveGathering;
use rtc::peer_connection::state::RTCIceGatheringState;
use rtc::peer_connection::transport::RTCIceCandidateInit;
use rtc::peer_connection::{RTCPeerConnection, RTCPeerConnectionBuilder};
use rtc::sansio::Protocol;
use rtc::shared::stream::{StreamCommand, StreamEvent};
use rtc::shared::{TaggedBytesMut, TransportContext, TransportProtocol};
use rtc::stun::message::{BINDING_REQUEST, BINDING_SUCCESS, Message, Setter};
use rtc::stun::xoraddr::XorMappedAddress;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

const HOST: &str = "10.0.0.1:4000";
const MAPPED: &str = "203.0.113.5:61000";

fn a(s: &str) -> SocketAddr {
    s.parse().unwrap()
}

struct Harness {
    pc: RTCPeerConnection,
    now: Instant,
    sent: Vec<(Instant, TaggedBytesMut)>,
    events: Vec<RTCPeerConnectionEvent>,
    commands: Vec<StreamCommand>,
    transmits: Vec<rtc::shared::stream::StreamTransmit>,
    /// Whether the harness serves the stream interface (the engine's TCP).
    serve_streams: bool,
}

impl Harness {
    fn new(urls: &[&str], settings: SettingEngine) -> Result<Self> {
        let now = Instant::now();
        let mut pc = RTCPeerConnectionBuilder::new()
            .with_configuration(
                RTCConfigurationBuilder::new()
                    .with_ice_servers(vec![RTCIceServer {
                        urls: urls.iter().map(|u| u.to_string()).collect(),
                        ..Default::default()
                    }])
                    .build(),
            )
            .with_setting_engine(settings)
            .build(now)?;
        pc.create_data_channel("srflx", None)?;
        let offer = pc.create_offer(None)?;
        pc.set_local_description(now, offer)?;
        Ok(Self {
            pc,
            now,
            sent: vec![],
            events: vec![],
            commands: vec![],
            transmits: vec![],
            serve_streams: false,
        })
    }

    fn add_host(&mut self, host: &str) -> Result<()> {
        let host = a(host);
        self.pc.add_local_candidate(RTCIceCandidateInit {
            candidate: format!(
                "candidate:1 1 udp 2130706431 {} {} typ host",
                host.ip(),
                host.port()
            ),
            ..Default::default()
        })?;
        self.pump();
        Ok(())
    }

    fn end_of_candidates(&mut self) -> Result<()> {
        self.pc
            .add_local_candidate(RTCIceCandidateInit::default())?;
        self.pump();
        Ok(())
    }

    fn pump(&mut self) {
        loop {
            let mut any = false;
            while let Some(w) = self.pc.poll_write() {
                self.sent.push((self.now, w));
                any = true;
            }
            while self.serve_streams
                && let Some(c) = self.pc.poll_stream_command()
            {
                self.commands.push(c);
                any = true;
            }
            while self.serve_streams
                && let Some(t) = self.pc.poll_stream_transmit()
            {
                self.transmits.push(t);
                any = true;
            }
            while let Some(e) = self.pc.poll_event() {
                self.events.push(e);
                any = true;
            }
            if !any {
                break;
            }
        }
    }

    /// Runs the timers up to `until`.
    fn advance_to(&mut self, until: Instant) {
        loop {
            self.pump();
            match self.pc.poll_timeout() {
                Some(t) if t <= until => {
                    self.now = t.max(self.now);
                    self.pc.handle_timeout(self.now).unwrap();
                }
                _ => break,
            }
        }
        self.now = until;
        self.pc.handle_timeout(self.now).unwrap();
        self.pump();
    }

    /// Binding requests sent to `server`, with when they left and from where.
    fn requests_to(&self, server: SocketAddr) -> Vec<(Instant, SocketAddr, Message)> {
        self.sent
            .iter()
            .filter(|(_, w)| w.transport.peer_addr == server)
            .filter_map(|(t, w)| {
                let mut m = Message::new();
                m.unmarshal_binary(&w.message).ok()?;
                (m.typ == BINDING_REQUEST).then_some((*t, w.transport.local_addr, m))
            })
            .collect()
    }

    fn candidates(&self) -> Vec<RTCIceCandidateInit> {
        self.events
            .iter()
            .filter_map(|e| match e {
                RTCPeerConnectionEvent::OnIceCandidateEvent(ev) => ev.candidate.as_ref(),
                _ => None,
            })
            .filter(|c| !c.end_of_candidates)
            .filter_map(|c| c.to_json().ok())
            .collect()
    }

    fn srflx(&self) -> Vec<RTCIceCandidateInit> {
        self.candidates()
            .into_iter()
            .filter(|c| c.candidate.contains("typ srflx"))
            .collect()
    }

    fn gathering_complete(&self) -> bool {
        self.pc.ice_gathering_state() == RTCIceGatheringState::Complete
    }

    /// The server answers `request` from `server` to `local`, reporting `mapped`.
    fn answer(&mut self, request: &Message, server: SocketAddr, local: SocketAddr, mapped: &str) {
        let response = success(request, a(mapped));
        self.pc
            .handle_read(TaggedBytesMut {
                now: self.now,
                transport: TransportContext {
                    local_addr: local,
                    peer_addr: server,
                    transport_protocol: TransportProtocol::UDP,
                    ecn: None,
                },
                message: BytesMut::from(&response[..]),
            })
            .unwrap();
        self.pump();
    }
}

fn success(request: &Message, mapped: SocketAddr) -> Vec<u8> {
    let mut response = Message::new();
    let setters: Vec<Box<dyn Setter>> = vec![
        Box::new(request.transaction_id),
        Box::new(BINDING_SUCCESS),
        Box::new(XorMappedAddress {
            ip: mapped.ip(),
            port: mapped.port(),
        }),
    ];
    response.build(&setters).unwrap();
    response.raw
}

/// RFC 8445 section 5.1.1.2: the engine sends a Binding request from the host candidate's
/// address to the server and announces the mapped address it reports as a server-reflexive
/// candidate whose related address is the host candidate (RFC 8839 section 5.1), with the
/// server's URL; the end of gathering waits for it.
#[test]
fn a_binding_request_from_the_host_candidate_yields_a_server_reflexive_candidate() -> Result<()> {
    let server = a("192.0.2.10:3478");
    let mut h = Harness::new(&["stun:192.0.2.10:3478"], SettingEngine::default())?;
    h.add_host(HOST)?;
    h.end_of_candidates()?;
    let requests = h.requests_to(server);
    assert_eq!(requests.len(), 1, "one Binding request at once");
    assert_eq!(requests[0].1, a(HOST), "from the host candidate's address");
    assert!(
        !h.gathering_complete(),
        "the end of gathering waits for the server's answer"
    );
    let request = requests[0].2.clone();
    h.answer(&request, server, a(HOST), MAPPED);
    let srflx = h.srflx();
    assert_eq!(srflx.len(), 1, "{srflx:?}");
    assert!(
        srflx[0].candidate.contains(" udp ")
            && srflx[0]
                .candidate
                .contains("203.0.113.5 61000 typ srflx raddr 10.0.0.1 rport 4000"),
        "{}",
        srflx[0].candidate
    );
    assert!(h.gathering_complete(), "every probe answered");
    let url = h.events.iter().find_map(|e| match e {
        RTCPeerConnectionEvent::OnIceCandidateEvent(ev)
            if ev
                .candidate
                .as_ref()
                .is_some_and(|c| c.to_json().is_ok_and(|i| i.candidate.contains("srflx"))) =>
        {
            ev.url.clone()
        }
        _ => None,
    });
    assert_eq!(url.as_deref(), Some("stun:192.0.2.10:3478"));
    Ok(())
}

/// RFC 8489 section 6.2.1: over UDP an unanswered request is sent again at RTO, 2 RTO, 4
/// RTO ... (RTO 500 ms, Rc 7 sends) and the transaction fails Rm x RTO (16 x 500 ms) after
/// the last: 39.5 s. Gathering then ends without the candidate.
#[test]
fn an_unanswered_request_is_retransmitted_and_gathering_ends_when_it_fails() -> Result<()> {
    let server = a("192.0.2.10:3478");
    let mut h = Harness::new(&["stun:192.0.2.10:3478"], SettingEngine::default())?;
    let t0 = h.now;
    h.add_host(HOST)?;
    h.end_of_candidates()?;
    h.advance_to(t0 + Duration::from_millis(39_400));
    let at: Vec<u128> = h
        .requests_to(server)
        .iter()
        .map(|(t, _, _)| t.duration_since(t0).as_millis())
        .collect();
    assert_eq!(at, vec![0, 500, 1500, 3500, 7500, 15500, 31500]);
    assert!(!h.gathering_complete(), "still waiting before 39.5 s");
    h.advance_to(t0 + Duration::from_millis(39_600));
    assert!(h.gathering_complete(), "the transaction failed at 39.5 s");
    assert!(h.srflx().is_empty());
    Ok(())
}

/// RFC 8445 section 5.1.1.2: gathering transactions start no faster than one per Ta (50 ms):
/// two servers, the second request leaves 50 ms after the first.
#[test]
fn transactions_to_two_servers_start_one_ta_apart() -> Result<()> {
    let mut h = Harness::new(
        &["stun:192.0.2.10:3478", "stun:192.0.2.11:3478"],
        SettingEngine::default(),
    )?;
    let t0 = h.now;
    h.add_host(HOST)?;
    assert_eq!(h.requests_to(a("192.0.2.10:3478")).len(), 1);
    assert!(h.requests_to(a("192.0.2.11:3478")).is_empty(), "held by Ta");
    h.advance_to(t0 + Duration::from_millis(49));
    assert!(h.requests_to(a("192.0.2.11:3478")).is_empty());
    h.advance_to(t0 + Duration::from_millis(50));
    let second = h.requests_to(a("192.0.2.11:3478"));
    assert_eq!(second.len(), 1);
    assert_eq!(second[0].0.duration_since(t0), Duration::from_millis(50));
    Ok(())
}

/// The setting: with `ReflexiveGathering::Application` the engine asks no server; with the
/// default, a base the application adds a server-reflexive candidate for itself is left to
/// it (its own transaction is not repeated).
#[test]
fn an_application_that_gathers_itself_keeps_doing_so() -> Result<()> {
    let server = a("192.0.2.10:3478");
    let mut off = Harness::new(
        &["stun:192.0.2.10:3478"],
        SettingEngineBuilder::new()
            .with_server_reflexive_gathering(ReflexiveGathering::Application)
            .build(),
    )?;
    off.add_host(HOST)?;
    off.end_of_candidates()?;
    assert!(off.requests_to(server).is_empty());
    assert!(off.gathering_complete(), "nothing to wait for");

    let mut h = Harness::new(&["stun:192.0.2.10:3478"], SettingEngine::default())?;
    let t0 = h.now;
    h.add_host(HOST)?;
    assert_eq!(h.requests_to(server).len(), 1);
    h.pc.add_local_candidate(RTCIceCandidateInit {
        candidate:
            "candidate:2 1 udp 1694498815 203.0.113.5 61000 typ srflx raddr 10.0.0.1 rport 4000"
                .to_owned(),
        ..Default::default()
    })?;
    h.end_of_candidates()?;
    assert!(
        h.gathering_complete(),
        "the engine's probe for that base ended"
    );
    h.advance_to(t0 + Duration::from_secs(5));
    assert_eq!(h.requests_to(server).len(), 1, "no retransmission");
    Ok(())
}

/// A server address equal to the base (no NAT between them) is not a candidate (RFC 8445
/// section 5.1.3: redundant), and a response to a request the engine did not send is left to
/// ICE.
#[test]
fn a_mapped_address_equal_to_the_base_is_not_announced() -> Result<()> {
    let server = a("192.0.2.10:3478");
    let mut h = Harness::new(&["stun:192.0.2.10:3478"], SettingEngine::default())?;
    h.add_host(HOST)?;
    h.end_of_candidates()?;
    let request = h.requests_to(server)[0].2.clone();
    h.answer(&request, server, a(HOST), HOST);
    assert!(h.srflx().is_empty());
    assert!(h.gathering_complete());
    Ok(())
}

/// RFC 6544 section 5.2 with RFC 8489 section 6.2.2: from the engine's passive ICE-TCP
/// candidate the engine connects to the server from the listener's own port (Appendix B,
/// `reuse_address`), sends one Binding request over the stream (STUN's own framing), announces
/// the mapped address as a server-reflexive passive candidate and its address on port 9 as a
/// server-reflexive active one, and closes the connection.
#[test]
fn a_binding_request_over_tcp_from_the_passive_listener_yields_tcp_candidates() -> Result<()> {
    let server = a("192.0.2.10:3478");
    let mut h = Harness::new(
        &["stun:192.0.2.10:3478"],
        SettingEngineBuilder::new()
            .with_tcp_simultaneous_open(false)
            .build(),
    )?;
    h.serve_streams = true;
    h.add_host(HOST)?;
    let listener = h
        .commands
        .iter()
        .find_map(|c| match c {
            StreamCommand::Listen { listener, .. } => Some(*listener),
            _ => None,
        })
        .expect("the passive listener");
    let bound = a("10.0.0.1:7000");
    h.pc.handle_stream_event(
        h.now,
        StreamEvent::Listening {
            listener,
            local: bound,
        },
    )?;
    h.pump();
    // The UDP probe went first; the TCP one is one Ta later.
    h.advance_to(h.now + Duration::from_millis(50));
    let (id, reuse) = h
        .commands
        .iter()
        .find_map(|c| match c {
            StreamCommand::Connect {
                id,
                local,
                remote,
                reuse_address,
            } if *local == bound && *remote == server => Some((*id, *reuse_address)),
            _ => None,
        })
        .expect("a connection from the listener's port to the server");
    assert!(reuse, "beside the listener: SO_REUSEADDR");
    h.pc.handle_stream_event(h.now, StreamEvent::Connected { id, local: bound })?;
    h.pump();
    let wire: Vec<u8> = h
        .transmits
        .iter()
        .filter(|t| t.id == id)
        .flat_map(|t| t.data.clone())
        .collect();
    let mut request = Message::new();
    request.unmarshal_binary(&wire)?;
    assert_eq!(request.typ, BINDING_REQUEST, "unframed STUN over TCP");
    h.pc.handle_stream_read(h.now, id, &success(&request, a("203.0.113.5:62000")))?;
    h.pump();
    let tcp: Vec<String> = h
        .srflx()
        .into_iter()
        .map(|c| c.candidate)
        .filter(|c| c.contains(" tcp "))
        .collect();
    assert!(
        tcp.iter()
            .any(|c| c
                .contains("203.0.113.5 62000 typ srflx raddr 10.0.0.1 rport 7000 tcptype passive")),
        "{tcp:?}"
    );
    assert!(
        tcp.iter()
            .any(|c| c.contains("203.0.113.5 9 typ srflx raddr 10.0.0.1 rport 9 tcptype active")),
        "{tcp:?}"
    );
    assert!(
        h.commands
            .iter()
            .any(|c| matches!(c, StreamCommand::Close { id: closed } if *closed == id)),
        "RFC 8489 section 6.2.2: the client closes the connection once done"
    );
    Ok(())
}

/// RFC 8305 section 3 for a server's name (RFC 8656 3.9-1): resolved through the driver; an
/// AAAA answer starts the race at once, without waiting for the A answer.
#[test]
fn a_names_aaaa_answer_starts_the_binding_request_at_once() -> Result<()> {
    let mut h = Harness::new(&["stun:stun.example.org:3478"], SettingEngine::default())?;
    h.serve_streams = true;
    h.add_host("[2001:db8::1]:4000")?;
    let query = h
        .commands
        .iter()
        .find_map(|c| match c {
            StreamCommand::Resolve { query, host, port } => {
                assert_eq!((host.as_str(), *port), ("stun.example.org", 3478));
                Some(*query)
            }
            _ => None,
        })
        .expect("the name goes to the driver");
    let v6 = a("[2001:db8::10]:3478");
    h.pc.handle_stream_event(
        h.now,
        StreamEvent::ResolvedFamily {
            query,
            ipv6: true,
            addresses: vec![v6],
        },
    )?;
    h.pump();
    assert_eq!(h.requests_to(v6).len(), 1, "no wait for the A answer");
    Ok(())
}

/// RFC 8305 section 3: an A answer that comes first waits the Resolution Delay (50 ms) for
/// the AAAA answer before the race starts on it.
#[test]
fn a_names_a_answer_first_waits_the_resolution_delay() -> Result<()> {
    let mut h = Harness::new(&["stun:stun.example.org:3478"], SettingEngine::default())?;
    h.serve_streams = true;
    let t0 = h.now;
    h.add_host(HOST)?;
    let query = h
        .commands
        .iter()
        .find_map(|c| match c {
            StreamCommand::Resolve { query, .. } => Some(*query),
            _ => None,
        })
        .expect("the name goes to the driver");
    let v4 = a("192.0.2.10:3478");
    h.pc.handle_stream_event(
        h.now,
        StreamEvent::ResolvedFamily {
            query,
            ipv6: false,
            addresses: vec![v4],
        },
    )?;
    h.pump();
    assert!(h.requests_to(v4).is_empty(), "held for the AAAA answer");
    h.advance_to(t0 + Duration::from_millis(49));
    assert!(h.requests_to(v4).is_empty());
    h.advance_to(t0 + Duration::from_millis(50));
    assert_eq!(h.requests_to(v4).len(), 1, "the Resolution Delay is over");
    Ok(())
}

/// RFC 8445 section 5.1.1.2 (backwards compatibility with RFC 5389 servers) and RFC 8489
/// section 5: a server of RFC 3489 answers with MAPPED-ADDRESS, not XOR-MAPPED-ADDRESS; the
/// engine takes that address.
#[test]
fn a_mapped_address_answer_of_an_old_server_is_taken() -> Result<()> {
    use rtc::stun::addr::MappedAddress;
    let server = a("192.0.2.10:3478");
    let mut h = Harness::new(&["stun:192.0.2.10:3478"], SettingEngine::default())?;
    h.add_host(HOST)?;
    let request = h.requests_to(server)[0].2.clone();
    let mut response = Message::new();
    let setters: Vec<Box<dyn Setter>> = vec![
        Box::new(request.transaction_id),
        Box::new(BINDING_SUCCESS),
        Box::new(MappedAddress {
            ip: a(MAPPED).ip(),
            port: a(MAPPED).port(),
        }),
    ];
    response.build(&setters)?;
    h.pc.handle_read(TaggedBytesMut {
        now: h.now,
        transport: TransportContext {
            local_addr: a(HOST),
            peer_addr: server,
            transport_protocol: TransportProtocol::UDP,
            ecn: None,
        },
        message: BytesMut::from(&response.raw[..]),
    })?;
    h.pump();
    let srflx = h.srflx();
    assert_eq!(srflx.len(), 1);
    assert!(srflx[0].candidate.contains("203.0.113.5 61000 typ srflx"));
    Ok(())
}
