//! ECN for RTP is for UDP (RFC 6679): between two `rtci` peers with ECN on that connect over
//! ICE-TCP (RFC 6544), on a simulated network, no RTP packet is ECN-marked and no description
//! made after nomination says `a=ecn-capable-rtp`.
//!
//! The network is the one of `ice_tcp_rtc2rtc.rs`: one passive TCP host candidate (a
//! listener), one active one; every packet is framed with RFC 4571's two-byte length and
//! reassembled on the other end. Time is virtual.

use anyhow::{Result, bail};
use bytes::{Bytes, BytesMut};
use rtci::ice::network_type::NetworkType;
use rtci::ice::tcp_type::TcpType;
use rtci::interceptor::{EcnInitiation, Registry};
use rtci::peer_connection::configuration::RTCConfigurationBuilder;
use rtci::peer_connection::configuration::interceptor_registry::{
    configure_congestion_control_feedback, configure_rtcp_reports,
};
use rtci::peer_connection::configuration::media_engine::{MIME_TYPE_VP8, MediaEngine};
use rtci::peer_connection::configuration::setting_engine::SettingEngineBuilder;
use rtci::peer_connection::event::RTCPeerConnectionEvent;
use rtci::peer_connection::state::RTCPeerConnectionState;
use rtci::peer_connection::transport::{CandidateConfig, CandidateHostConfig, RTCIceCandidate};
use rtci::peer_connection::{RTCPeerConnection, RTCPeerConnectionBuilder};
use rtci::rtp_transceiver::rtp_sender::{
    RTCRtpCodec, RTCRtpCodecParameters, RTCRtpEncodingParameters, RtpCodecKind,
};
use rtci::rtp_transceiver::{RTCRtpSenderId, RTCRtpTransceiverDirection, RTCRtpTransceiverInit};
use rtci::sansio::Protocol;
use rtci::shared::tcp_framing::{TcpFrameDecoder, frame_packet};
use rtci::shared::{TaggedBytesMut, TransportContext, TransportProtocol};
use std::net::SocketAddr;
use std::time::{Duration, Instant};

const DEADLINE: Duration = Duration::from_secs(30);
/// The port signalled for active candidates (RFC 6544 section 4.5).
const ACTIVE_PORT: u16 = 9;
const VP8_PT: u8 = 96;
const ECN_CAPABLE_RTP: &str = "a=ecn-capable-rtp:";

struct Peer {
    pc: RTCPeerConnection,
    ip: &'static str,
    tcp_type: TcpType,
    connected: bool,
}

impl Peer {
    /// VP8, RTCP reports and RFC 8888 feedback (`ack ccfb`), ECN on, marking every packet from
    /// the first (RFC 6679 section 7.2.3): over UDP every RTP packet of the stream would leave
    /// ECT. Only TCP candidates are gathered.
    fn new(ip: &'static str, tcp_type: TcpType) -> Result<Self> {
        let mut media_engine = MediaEngine::default();
        media_engine.register_codec(
            RTCRtpCodecParameters {
                rtp_codec: RTCRtpCodec {
                    mime_type: MIME_TYPE_VP8.to_owned(),
                    clock_rate: 90000,
                    ..Default::default()
                },
                payload_type: VP8_PT,
            },
            RtpCodecKind::Video,
        )?;
        let registry = configure_congestion_control_feedback(
            configure_rtcp_reports(Registry::new()),
            &mut media_engine,
        );
        let pc = RTCPeerConnectionBuilder::new()
            .with_configuration(RTCConfigurationBuilder::new().build())
            .with_setting_engine(
                SettingEngineBuilder::new()
                    .with_network_types(vec![NetworkType::Tcp4])
                    .with_ecn(true)
                    .with_ecn_initiation(EcnInitiation::LeapOfFaith)
                    .build(),
            )
            .with_media_engine(media_engine)
            .with_interceptor_registry(registry)
            .build(Instant::now())?;
        Ok(Self {
            pc,
            ip,
            tcp_type,
            connected: false,
        })
    }

    fn port(&self) -> u16 {
        if self.tcp_type == TcpType::Active {
            ACTIVE_PORT
        } else {
            5000
        }
    }

    fn listener(&self) -> Option<SocketAddr> {
        (self.tcp_type == TcpType::Passive).then(|| format!("{}:5000", self.ip).parse().unwrap())
    }

    fn candidate(&self) -> Result<rtci::peer_connection::transport::RTCIceCandidateInit> {
        let candidate = CandidateHostConfig {
            base_config: CandidateConfig {
                network: "tcp".to_owned(),
                address: self.ip.to_owned(),
                port: self.port(),
                component: 1,
                ..Default::default()
            },
            tcp_type: self.tcp_type,
        }
        .new_candidate_host()?;
        Ok(RTCIceCandidate::from(&candidate).to_json()?)
    }
}

/// One simulated TCP connection: the active peer's ephemeral address and the passive peer's
/// listener, with a decoder per direction.
struct Connection {
    dialer: usize,
    dialer_addr: SocketAddr,
    listener: usize,
    listener_addr: SocketAddr,
    to_listener: TcpFrameDecoder,
    to_dialer: TcpFrameDecoder,
}

#[derive(Default)]
struct Network {
    connections: Vec<Connection>,
    next_port: u16,
    /// Packets in flight: (receiving peer, local address, peer address, payload).
    in_flight: Vec<(usize, SocketAddr, SocketAddr, BytesMut)>,
}

impl Network {
    /// Carries one packet a peer wrote: on its connection, or, from the active peer to a
    /// listener, on a connection opened for it.
    fn send(
        &mut self,
        peers: &[Peer],
        from: usize,
        local: SocketAddr,
        to: SocketAddr,
        data: &[u8],
    ) {
        let framed = frame_packet(data);
        if let Some(c) = self
            .connections
            .iter_mut()
            .find(|c| c.listener == from && c.dialer_addr == to)
        {
            c.to_dialer.push(&framed).unwrap();
            while let Some(p) = c.to_dialer.next_packet() {
                self.in_flight.push((
                    c.dialer,
                    c.dialer_addr,
                    c.listener_addr,
                    BytesMut::from(&p[..]),
                ));
            }
            return;
        }
        if peers[from].tcp_type != TcpType::Active || local.port() != ACTIVE_PORT {
            return;
        }
        let Some(listener) = peers.iter().position(|p| p.listener() == Some(to)) else {
            return;
        };
        let index = match self
            .connections
            .iter()
            .position(|c| c.dialer == from && c.listener_addr == to)
        {
            Some(i) => i,
            None => {
                self.next_port += 1;
                self.connections.push(Connection {
                    dialer: from,
                    dialer_addr: SocketAddr::new(local.ip(), 40000 + self.next_port),
                    listener,
                    listener_addr: to,
                    to_listener: TcpFrameDecoder::new(),
                    to_dialer: TcpFrameDecoder::new(),
                });
                self.connections.len() - 1
            }
        };
        let c = &mut self.connections[index];
        c.to_listener.push(&framed).unwrap();
        while let Some(p) = c.to_listener.next_packet() {
            self.in_flight.push((
                c.listener,
                c.listener_addr,
                c.dialer_addr,
                BytesMut::from(&p[..]),
            ));
        }
    }
}

struct World {
    peers: Vec<Peer>,
    net: Network,
    now: Instant,
    /// The RTP packets the sender wrote to the network (SRTP: the header is in the clear),
    /// by SSRC, with the ECN codepoint it asked for.
    rtp_written: Vec<(u32, Option<rtci::shared::EcnCodepoint>)>,
}

impl World {
    /// Moves every packet written and delivers it, handles events, until nothing is in
    /// flight; then advances to the next timer, 50 ms at most.
    fn step(&mut self) -> Result<()> {
        loop {
            for i in 0..2 {
                while let Some(msg) = self.peers[i].pc.poll_write() {
                    assert_eq!(msg.transport.transport_protocol, TransportProtocol::TCP);
                    let data = &msg.message;
                    if i == 0
                        && data.len() >= 12
                        && data[0] >> 6 == 2
                        && !(192..=223).contains(&data[1])
                    {
                        let ssrc = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);
                        self.rtp_written.push((ssrc, msg.transport.ecn));
                    }
                    let (local, to) = (msg.transport.local_addr, msg.transport.peer_addr);
                    self.net.send(&self.peers, i, local, to, data);
                }
            }
            if self.net.in_flight.is_empty() {
                break;
            }
            for (i, local, from, data) in std::mem::take(&mut self.net.in_flight) {
                let _ = self.peers[i].pc.handle_read(TaggedBytesMut {
                    now: self.now,
                    transport: TransportContext {
                        local_addr: local,
                        peer_addr: from,
                        ecn: None,
                        transport_protocol: TransportProtocol::TCP,
                    },
                    message: data,
                });
            }
        }
        for peer in self.peers.iter_mut() {
            while let Some(event) = peer.pc.poll_event() {
                match event {
                    RTCPeerConnectionEvent::OnConnectionStateChangeEvent(
                        RTCPeerConnectionState::Connected,
                    ) => peer.connected = true,
                    RTCPeerConnectionEvent::OnConnectionStateChangeEvent(
                        RTCPeerConnectionState::Failed,
                    ) => bail!("a peer's connection failed"),
                    _ => {}
                }
            }
            while peer.pc.poll_read().is_some() {}
        }
        let now = self.now;
        let next = self
            .peers
            .iter_mut()
            .filter_map(|p| p.pc.poll_timeout())
            .min()
            .unwrap_or(now + Duration::from_millis(50))
            .min(now + Duration::from_millis(50));
        self.now = next.max(now + Duration::from_millis(1));
        for peer in self.peers.iter_mut() {
            let _ = peer.pc.handle_timeout(self.now);
        }
        Ok(())
    }

    fn run_for(&mut self, span: Duration) -> Result<()> {
        let until = self.now + span;
        while self.now < until {
            self.step()?;
        }
        Ok(())
    }

    /// The passive peer offers a sendonly VP8 stream, the active one answers; both connect
    /// over one TCP connection.
    fn connected() -> Result<(Self, RTCRtpSenderId)> {
        let mut world = World {
            peers: vec![
                Peer::new("10.0.0.1", TcpType::Passive)?,
                Peer::new("10.0.0.2", TcpType::Active)?,
            ],
            net: Network::default(),
            now: Instant::now(),
            rtp_written: Vec::new(),
        };
        let transceiver = world.peers[0].pc.add_transceiver_from_kind(
            RtpCodecKind::Video,
            Some(RTCRtpTransceiverInit {
                direction: RTCRtpTransceiverDirection::Sendonly,
                streams: vec![],
                send_encodings: vec![RTCRtpEncodingParameters {
                    active: true,
                    ..Default::default()
                }],
            }),
        )?;
        let sender = world.peers[0]
            .pc
            .rtp_transceiver(transceiver)
            .and_then(|t| t.sender())
            .expect("a sendonly transceiver has a sender");
        let now = world.now;
        let offer = world.peers[0].pc.create_offer(None)?;
        world.peers[0]
            .pc
            .set_local_description(now, offer.clone())?;
        world.peers[1].pc.set_remote_description(now, offer)?;
        let answer = world.peers[1].pc.create_answer(None)?;
        world.peers[1]
            .pc
            .set_local_description(now, answer.clone())?;
        world.peers[0].pc.set_remote_description(now, answer)?;
        for i in 0..2 {
            let candidate = world.peers[i].candidate()?;
            world.peers[i].pc.add_local_candidate(candidate.clone())?;
            world.peers[1 - i].pc.add_remote_candidate(candidate)?;
        }
        let start = world.now;
        while !world.peers.iter().all(|p| p.connected) {
            if world.now.duration_since(start) >= DEADLINE {
                bail!("not connected over TCP within {DEADLINE:?}");
            }
            world.step()?;
        }
        Ok((world, sender))
    }
}

/// RFC 6679 section 6.1.3: "It MUST NOT be used for RTP sessions using TCP". The first offer,
/// made before any candidate was gathered, negotiates ECN for the video section (it says
/// `UDP/TLS/RTP/SAVPF`); the peers then connect over an ICE-TCP pair. None of the stream's RTP
/// packets leaves ECN-marked, though over UDP every one would (ECN on, marking from the first
/// packet), and a later offer and its answer, which say `TCP/DTLS/RTP/SAVPF`, carry no
/// `a=ecn-capable-rtp`.
#[test]
fn rtp_over_an_ice_tcp_pair_is_not_ecn_marked_nor_offered_ecn() -> Result<()> {
    let (mut world, sender) = World::connected()?;
    let first_offer = world.peers[0]
        .pc
        .local_description()
        .expect("the offer")
        .sdp;
    assert!(
        first_offer.contains(ECN_CAPABLE_RTP),
        "ECN negotiated before the transport was known:\n{first_offer}"
    );
    let ssrc = {
        let mut sender = world.peers[0].pc.rtp_sender(sender).expect("sender");
        sender.get_parameters().encodings[0]
            .rtp_coding_parameters
            .ssrc
            .expect("an SSRC")
    };
    for n in 0..50u16 {
        let now = world.now;
        world.peers[0]
            .pc
            .rtp_sender(sender)
            .expect("sender")
            .write_rtp(
                now,
                rtci::rtp::Packet {
                    header: rtci::rtp::header::Header {
                        version: 2,
                        payload_type: VP8_PT,
                        sequence_number: 1000 + n,
                        timestamp: u32::from(n) * 3000,
                        ssrc,
                        marker: true,
                        ..Default::default()
                    },
                    payload: Bytes::from(vec![0x10u8; 200]),
                },
            )?;
        world.run_for(Duration::from_millis(20))?;
    }
    world.run_for(Duration::from_secs(2))?;
    let media: Vec<_> = world
        .rtp_written
        .iter()
        .filter(|(s, _)| *s == ssrc)
        .collect();
    assert!(media.len() >= 50, "the stream was sent: {}", media.len());
    assert!(
        media.iter().all(|(_, ecn)| ecn.is_none()),
        "no RTP packet ECN-marked over TCP: {media:?}"
    );

    let now = world.now;
    let offer = world.peers[0].pc.create_offer(None)?;
    let video = offer
        .sdp
        .lines()
        .find(|l| l.starts_with("m=video"))
        .expect("a video section");
    assert!(video.contains("TCP/DTLS/RTP/SAVPF"), "{video}");
    assert!(!offer.sdp.contains(ECN_CAPABLE_RTP), "{}", offer.sdp);
    world.peers[0]
        .pc
        .set_local_description(now, offer.clone())?;
    world.peers[1].pc.set_remote_description(now, offer)?;
    let answer = world.peers[1].pc.create_answer(None)?;
    assert!(!answer.sdp.contains(ECN_CAPABLE_RTP), "{}", answer.sdp);
    Ok(())
}
