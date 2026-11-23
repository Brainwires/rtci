//! A two-peer `rtc` world on a simulated link in virtual time, shared by the pipeline tests
//! and the headless example: ICE, DTLS and SCTP pass untouched until the connection is up,
//! then SRTP / SRTCP datagrams are dropped and delayed (so reordered) as [`Link`] says, from a
//! fixed seed.
#![allow(dead_code)]

use std::collections::VecDeque;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use anyhow::{Result, bail};
use rtc::interceptor::Registry;
use rtc::peer_connection::configuration::RTCConfigurationBuilder;
use rtc::peer_connection::configuration::interceptor_registry::{
    DefaultInterceptorHandles, register_default_interceptors_with_handles,
};
use rtc::peer_connection::configuration::media_engine::MediaEngine;
use rtc::peer_connection::event::{RTCPeerConnectionEvent, RTCTrackEvent};
use rtc::peer_connection::message::RTCMessage;
use rtc::peer_connection::state::RTCPeerConnectionState;
use rtc::peer_connection::transport::{
    CandidateConfig, CandidateHostConfig, RTCIceCandidate, RTCIceCandidateInit,
};
use rtc::peer_connection::{RTCPeerConnection, RTCPeerConnectionBuilder};
use rtc::rtp_transceiver::rtp_sender::{RTCRtpEncodingParameters, RtpCodecKind};
use rtc::rtp_transceiver::{
    RTCRtpReceiverId, RTCRtpSenderId, RTCRtpTransceiverDirection, RTCRtpTransceiverInit,
};
use rtc::sansio::Protocol;
use rtc::shared::{TaggedBytesMut, TransportContext, TransportProtocol};
use rtc_audio::signal::Rng;

pub struct Peer {
    pub pc: RTCPeerConnection,
    pub addr: SocketAddr,
    pub connected: bool,
    /// The default interceptors' handles (congestion controller, circuit breaker).
    pub handles: DefaultInterceptorHandles,
}

impl Peer {
    fn new(addr: &str, now: Instant) -> Result<Self> {
        let mut media_engine = MediaEngine::default();
        media_engine.register_default_codecs()?;
        let (registry, handles) =
            register_default_interceptors_with_handles(Registry::new(), &mut media_engine)?;
        let pc = RTCPeerConnectionBuilder::new()
            .with_configuration(RTCConfigurationBuilder::new().build())
            .with_media_engine(media_engine)
            .with_interceptor_registry(registry)
            .build(now)?;
        Ok(Self {
            pc,
            addr: addr.parse()?,
            connected: false,
            handles,
        })
    }

    fn candidate(&self) -> Result<RTCIceCandidateInit> {
        let candidate = CandidateHostConfig {
            base_config: CandidateConfig {
                network: "udp".to_owned(),
                address: self.addr.ip().to_string(),
                port: self.addr.port(),
                component: 1,
                ..Default::default()
            },
            ..Default::default()
        }
        .new_candidate_host()?;
        Ok(RTCIceCandidate::from(&candidate).to_json()?)
    }
}

/// The link both directions share once the connection is up.
#[derive(Clone, Copy, Debug)]
pub struct Link {
    /// Share of media datagrams dropped.
    pub loss: f64,
    /// One-way delay.
    pub delay: Duration,
    /// Each media datagram is delayed by up to this much more, uniformly.
    pub jitter: Duration,
}

/// Two peers: the first sends audio, the second receives it.
pub struct World {
    pub peers: [Peer; 2],
    pub now: Instant,
    pub link: Link,
    pub impaired: bool,
    rng: Rng,
    in_flight: VecDeque<(Instant, usize, SocketAddr, SocketAddr, bytes::BytesMut)>,
    /// The second peer's receiver, once its track opened.
    pub receiver: Option<RTCRtpReceiverId>,
    /// RTP packets the second peer's `poll_read` delivered.
    pub rtp_in: Vec<rtc::rtp::Packet>,
    /// RTCP packets the first peer's `poll_read` delivered.
    pub rtcp_in: Vec<Box<dyn rtc::rtcp::Packet>>,
    pub dropped: u64,
    pub media_datagrams: u64,
}

/// SRTP or SRTCP (RFC 7983: first byte 128 to 191).
fn is_rtp(data: &[u8]) -> bool {
    matches!(data.first(), Some(128..=191))
}

impl World {
    pub fn new(link: Link, seed: u64) -> Result<Self> {
        let now = Instant::now();
        Ok(Self {
            peers: [
                Peer::new("10.0.0.1:5000", now)?,
                Peer::new("10.0.0.2:5000", now)?,
            ],
            now,
            link,
            impaired: false,
            rng: Rng::new(seed),
            in_flight: VecDeque::new(),
            receiver: None,
            rtp_in: Vec::new(),
            rtcp_in: Vec::new(),
            dropped: 0,
            media_datagrams: 0,
        })
    }

    fn pump(&mut self) -> Result<()> {
        for (i, peer) in self.peers.iter_mut().enumerate() {
            while let Some(msg) = peer.pc.poll_write() {
                let media = is_rtp(&msg.message);
                let mut at = self.now + self.link.delay;
                if self.impaired && media {
                    self.media_datagrams += 1;
                    if self.rng.unit() < self.link.loss {
                        self.dropped += 1;
                        continue;
                    }
                    at += Duration::from_secs_f64(self.link.jitter.as_secs_f64() * self.rng.unit());
                }
                self.in_flight.push_back((
                    at,
                    i,
                    msg.transport.local_addr,
                    msg.transport.peer_addr,
                    msg.message,
                ));
            }
        }
        // Deliver what is due, in arrival order.
        let mut due: Vec<_> = Vec::new();
        let mut keep = VecDeque::new();
        while let Some(d) = self.in_flight.pop_front() {
            if d.0 <= self.now {
                due.push(d);
            } else {
                keep.push_back(d);
            }
        }
        self.in_flight = keep;
        due.sort_by_key(|d| d.0);
        for (_, _, from, to, data) in due {
            let Some(peer) = self.peers.iter_mut().find(|p| p.addr == to) else {
                continue;
            };
            let _ = peer.pc.handle_read(TaggedBytesMut {
                now: self.now,
                transport: TransportContext {
                    local_addr: to,
                    peer_addr: from,
                    ecn: None,
                    transport_protocol: TransportProtocol::UDP,
                },
                message: data,
            });
        }
        for (i, peer) in self.peers.iter_mut().enumerate() {
            while let Some(event) = peer.pc.poll_event() {
                match event {
                    RTCPeerConnectionEvent::OnConnectionStateChangeEvent(state) => {
                        if state == RTCPeerConnectionState::Failed {
                            bail!("peer {i} failed");
                        }
                        peer.connected = state == RTCPeerConnectionState::Connected;
                    }
                    RTCPeerConnectionEvent::OnTrack(RTCTrackEvent::OnOpen(init)) if i == 1 => {
                        self.receiver = Some(init.receiver_id);
                    }
                    _ => {}
                }
            }
            while let Some(message) = peer.pc.poll_read() {
                match message.message {
                    RTCMessage::RtpPacket(_, packet) if i == 1 => self.rtp_in.push(packet),
                    RTCMessage::RtcpPacket(_, packets) if i == 0 => self.rtcp_in.extend(packets),
                    _ => {}
                }
            }
        }
        Ok(())
    }

    pub fn advance(&mut self, to: Instant) -> Result<()> {
        while self.now < to {
            let mut next = to;
            for peer in self.peers.iter_mut() {
                if let Some(deadline) = peer.pc.poll_timeout() {
                    next = next.min(deadline);
                }
            }
            if let Some(d) = self.in_flight.iter().map(|d| d.0).min() {
                next = next.min(d);
            }
            self.now = next.max(self.now + Duration::from_micros(100)).min(to);
            for peer in self.peers.iter_mut() {
                peer.pc.handle_timeout(self.now)?;
            }
            self.pump()?;
        }
        Ok(())
    }

    /// Two peers connected over host candidates, the first with a sendonly audio
    /// transceiver; impairment starts once both are connected.
    pub fn connected_audio(link: Link, seed: u64) -> Result<(Self, RTCRtpSenderId)> {
        let mut world = World::new(link, seed)?;
        let transceiver = world.peers[0].pc.add_transceiver_from_kind(
            RtpCodecKind::Audio,
            Some(RTCRtpTransceiverInit {
                direction: RTCRtpTransceiverDirection::Sendonly,
                streams: vec![],
                send_encodings: vec![RTCRtpEncodingParameters {
                    active: true,
                    ..Default::default()
                }],
            }),
        )?;
        let sender_id = world.peers[0]
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
            if world.now.duration_since(start) > Duration::from_secs(10) {
                bail!("not connected");
            }
            let t = world.now + Duration::from_millis(10);
            world.advance(t)?;
        }
        world.impaired = true;
        Ok((world, sender_id))
    }
}
