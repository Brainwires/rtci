//! An idle endpoint yields nothing and still makes progress.
//!
//! These replace upstream `webrtc` v0.17.1's `test_rtp_sender_set_read_deadline` and
//! `test_rtp_receiver_set_read_deadline`, which assert that a blocking `read_rtcp` /
//! `read_rtp` on an idle sender or receiver returns at its deadline. This engine has no
//! blocking read and no deadline setter: `poll_read` returns at once, and time only moves
//! when the application calls `handle_timeout`. What those tests protect is that a sender
//! with nothing to send and a receiver with nothing to receive neither invent messages nor
//! stall: after connecting with no media, `poll_read()` is `None`, `poll_timeout()` still
//! gives a deadline, and after `handle_timeout` at each deadline `poll_read()` is still
//! `None` and the connection is still connected.
//!
//! Two `rtc` peers on a simulated network, virtual time, no sockets, no interceptors beyond
//! the RTCP session every connection runs (RFC 8834 4.1): the reports it exchanges are its own
//! and never reach `poll_read`, so any RTCP a sender read would be invented.

use anyhow::{Result, bail};
use rtc::media_stream::MediaStreamTrack;
use rtc::peer_connection::configuration::RTCConfigurationBuilder;
use rtc::peer_connection::configuration::media_engine::{MIME_TYPE_VP8, MediaEngine};
use rtc::peer_connection::event::RTCPeerConnectionEvent;
use rtc::peer_connection::message::RTCMessage;
use rtc::peer_connection::state::RTCPeerConnectionState;
use rtc::peer_connection::transport::{
    CandidateConfig, CandidateHostConfig, RTCIceCandidate, RTCIceCandidateInit,
};
use rtc::peer_connection::{RTCPeerConnection, RTCPeerConnectionBuilder};
use rtc::rtp_transceiver::rtp_sender::{
    RTCRtpCodec, RTCRtpCodecParameters, RTCRtpCodingParameters, RTCRtpEncodingParameters,
    RtpCodecKind,
};
use rtc::sansio::Protocol;
use rtc::shared::{TaggedBytesMut, TransportContext, TransportProtocol};
use std::net::SocketAddr;
use std::time::{Duration, Instant};

/// Virtual time allowed to connect.
const CONNECT_WITHIN: Duration = Duration::from_secs(10);
/// Virtual time the idle phase lasts: several ICE keepalive intervals, well inside the
/// disconnected timeout an endpoint that stopped making progress would hit.
const IDLE_FOR: Duration = Duration::from_secs(20);

fn vp8() -> RTCRtpCodec {
    RTCRtpCodec {
        mime_type: MIME_TYPE_VP8.to_owned(),
        clock_rate: 90000,
        channels: 0,
        sdp_fmtp_line: String::new(),
        rtcp_feedback: vec![],
    }
}

struct Peer {
    pc: RTCPeerConnection,
    addr: SocketAddr,
    connected: bool,
    states: Vec<RTCPeerConnectionState>,
    /// What `poll_read` yielded, by kind.
    read: Vec<&'static str>,
}

impl Peer {
    fn new(addr: &str) -> Result<Self> {
        let mut media_engine = MediaEngine::default();
        media_engine.register_codec(
            RTCRtpCodecParameters {
                rtp_codec: vp8(),
                payload_type: 96,
            },
            RtpCodecKind::Video,
        )?;
        let pc = RTCPeerConnectionBuilder::new()
            .with_configuration(RTCConfigurationBuilder::new().build())
            .with_media_engine(media_engine)
            .build(Instant::now())?;
        Ok(Self {
            pc,
            addr: addr.parse()?,
            connected: false,
            states: Vec::new(),
            read: Vec::new(),
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

struct World {
    peers: [Peer; 2],
    now: Instant,
}

impl World {
    /// Delivers every datagram in flight, repeatedly, until both peers are quiet; then takes
    /// their events and drains `poll_read`.
    fn pump(&mut self) -> Result<()> {
        loop {
            let mut in_flight = Vec::new();
            for peer in self.peers.iter_mut() {
                while let Some(msg) = peer.pc.poll_write() {
                    in_flight.push((
                        msg.transport.local_addr,
                        msg.transport.peer_addr,
                        msg.message,
                    ));
                }
            }
            if in_flight.is_empty() {
                break;
            }
            for (from, to, data) in in_flight {
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
        }
        for peer in self.peers.iter_mut() {
            while let Some(event) = peer.pc.poll_event() {
                if let RTCPeerConnectionEvent::OnConnectionStateChangeEvent(state) = event {
                    if state == RTCPeerConnectionState::Failed {
                        bail!("a peer's connection failed: {:?}", peer.states);
                    }
                    peer.connected = state == RTCPeerConnectionState::Connected;
                    peer.states.push(state);
                }
            }
            while let Some(message) = peer.pc.poll_read() {
                peer.read.push(match message.message {
                    RTCMessage::RtpPacket(..) => "rtp",
                    RTCMessage::RtcpPacket(..) => "rtcp",
                    RTCMessage::DataChannelMessage(..) => "data channel message",
                    _ => "another message",
                });
            }
        }
        Ok(())
    }

    /// Moves virtual time to the earliest deadline either peer reports and fires it on both.
    /// Every peer must report one: an endpoint with nothing to do still keeps ICE alive.
    fn advance(&mut self) -> Result<()> {
        let mut next = None;
        for (i, peer) in self.peers.iter_mut().enumerate() {
            let Some(deadline) = peer.pc.poll_timeout() else {
                bail!("peer {i} reports no deadline, so it would never make progress");
            };
            next = Some(next.map_or(deadline, |n: Instant| n.min(deadline)));
        }
        let next = next.expect("two peers");
        self.now = next.max(self.now + Duration::from_millis(1));
        for peer in self.peers.iter_mut() {
            peer.pc.handle_timeout(self.now)?;
        }
        Ok(())
    }

    /// Two peers, the offerer sending a video track it never writes to (sendonly) and the
    /// answerer receiving it, connected over host candidates.
    fn connected() -> Result<Self> {
        let mut world = World {
            peers: [Peer::new("10.0.0.1:5000")?, Peer::new("10.0.0.2:5000")?],
            now: Instant::now(),
        };
        let track = MediaStreamTrack::new(
            "idle-stream".to_owned(),
            "idle-video".to_owned(),
            "idle-video".to_owned(),
            RtpCodecKind::Video,
            vec![RTCRtpEncodingParameters {
                rtp_coding_parameters: RTCRtpCodingParameters {
                    ssrc: Some(0x1d1e_0001),
                    ..Default::default()
                },
                codec: vp8(),
                ..Default::default()
            }],
        );
        world.peers[0].pc.add_track(track)?;

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
        loop {
            world.pump()?;
            if world.peers.iter().all(|p| p.connected) {
                break;
            }
            if world.now.duration_since(start) >= CONNECT_WITHIN {
                bail!(
                    "not connected after {CONNECT_WITHIN:?}: {:?} / {:?}",
                    world.peers[0].states,
                    world.peers[1].states
                );
            }
            world.advance()?;
        }
        Ok(world)
    }

    /// Runs the idle phase, checking `who` after each deadline.
    fn stay_idle(&mut self, who: usize, what: &str) -> Result<()> {
        assert!(
            self.peers[who].read.is_empty(),
            "{what} yielded {:?} while connecting with no media",
            self.peers[who].read
        );
        let start = self.now;
        let mut deadlines = 0;
        while self.now.duration_since(start) < IDLE_FOR {
            self.advance()?;
            self.pump()?;
            deadlines += 1;
            assert!(
                self.peers[who].read.is_empty(),
                "{what} yielded {:?} after {:?} of idle time",
                self.peers[who].read,
                self.now.duration_since(start)
            );
            assert!(
                self.peers[who].connected,
                "{what} left `connected` while idle: {:?}",
                self.peers[who].states
            );
        }
        assert!(
            deadlines > 1,
            "{what}'s timers fired only {deadlines} time(s) in {IDLE_FOR:?}"
        );
        Ok(())
    }
}

/// Replaces `test_rtp_sender_set_read_deadline`: the RTCP side of an idle sender.
#[test]
fn idle_sender_yields_no_rtcp_and_its_timers_advance() -> Result<()> {
    let mut world = World::connected()?;
    world.stay_idle(0, "an idle sender")
}

/// Replaces `test_rtp_receiver_set_read_deadline`: the media side of an idle receiver.
#[test]
fn idle_receiver_yields_no_media_and_its_timers_advance() -> Result<()> {
    let mut world = World::connected()?;
    world.stay_idle(1, "an idle receiver")
}
