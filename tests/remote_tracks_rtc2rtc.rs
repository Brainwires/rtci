//! A remote track's muted state between two `rtc` peer connections, in virtual time (W3C
//! webrtc-pc 9.3, 5.1.1, 5.3): the track starts muted, its first RTP packet unmutes it, an RTCP
//! BYE mutes it without ending it, RTP unmutes it again, and a remote description that stops
//! the sending mutes it.

use anyhow::{Result, bail};
use bytes::Bytes;
use rtc::interceptor::Registry;
use rtc::peer_connection::configuration::RTCConfigurationBuilder;
use rtc::peer_connection::configuration::interceptor_registry::register_default_interceptors;
use rtc::peer_connection::configuration::media_engine::MediaEngine;
use rtc::peer_connection::event::{RTCPeerConnectionEvent, RTCTrackEvent};
use rtc::peer_connection::state::RTCPeerConnectionState;
use rtc::peer_connection::transport::{
    CandidateConfig, CandidateHostConfig, RTCIceCandidate, RTCIceCandidateInit,
};
use rtc::peer_connection::{RTCPeerConnection, RTCPeerConnectionBuilder};
use rtc::rtp_transceiver::rtp_sender::{RTCRtpEncodingParameters, RtpCodecKind};
use rtc::rtp_transceiver::{
    RTCRtpSenderId, RTCRtpTransceiverDirection, RTCRtpTransceiverId, RTCRtpTransceiverInit,
};
use rtc::sansio::Protocol;
use rtc::shared::{TaggedBytesMut, TransportContext, TransportProtocol};
use std::net::SocketAddr;
use std::time::{Duration, Instant};

const CONNECT_WITHIN: Duration = Duration::from_secs(10);

struct Peer {
    pc: RTCPeerConnection,
    addr: SocketAddr,
    connected: bool,
    states: Vec<RTCPeerConnectionState>,
    /// The track events, in order.
    track_events: Vec<RTCTrackEvent>,
}

impl Peer {
    fn new(addr: &str) -> Result<Self> {
        let mut media_engine = MediaEngine::default();
        media_engine.register_default_codecs()?;
        let registry = register_default_interceptors(Registry::new(), &mut media_engine)?;
        let pc = RTCPeerConnectionBuilder::new()
            .with_configuration(RTCConfigurationBuilder::new().build())
            .with_media_engine(media_engine)
            .with_interceptor_registry(registry)
            .build(Instant::now())?;
        Ok(Self {
            pc,
            addr: addr.parse()?,
            connected: false,
            states: Vec::new(),
            track_events: Vec::new(),
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

    /// The mute, unmute and close events since the last call, as text.
    fn take_mute_events(&mut self) -> Vec<String> {
        std::mem::take(&mut self.track_events)
            .into_iter()
            .filter_map(|event| match event {
                RTCTrackEvent::OnMute(_) => Some("mute".to_owned()),
                RTCTrackEvent::OnUnmute(_) => Some("unmute".to_owned()),
                RTCTrackEvent::OnClose(_) => Some("close".to_owned()),
                _ => None,
            })
            .collect()
    }
}

struct World {
    peers: [Peer; 2],
    now: Instant,
}

impl World {
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
                match event {
                    RTCPeerConnectionEvent::OnConnectionStateChangeEvent(state) => {
                        if state == RTCPeerConnectionState::Failed {
                            bail!("a peer's connection failed: {:?}", peer.states);
                        }
                        peer.connected = state == RTCPeerConnectionState::Connected;
                        peer.states.push(state);
                    }
                    RTCPeerConnectionEvent::OnTrack(event) => peer.track_events.push(event),
                    _ => {}
                }
            }
            while peer.pc.poll_read().is_some() {}
        }
        Ok(())
    }

    fn run_until(&mut self, until: Instant) -> Result<()> {
        while self.now < until {
            let mut next = until;
            for peer in self.peers.iter_mut() {
                if let Some(deadline) = peer.pc.poll_timeout() {
                    next = next.min(deadline);
                }
            }
            self.now = next.max(self.now + Duration::from_millis(1)).min(until);
            for peer in self.peers.iter_mut() {
                peer.pc.handle_timeout(self.now)?;
            }
            self.pump()?;
        }
        Ok(())
    }

    fn negotiate(&mut self) -> Result<()> {
        let now = self.now;
        let offer = self.peers[0].pc.create_offer(None)?;
        self.peers[0].pc.set_local_description(now, offer.clone())?;
        self.peers[1].pc.set_remote_description(now, offer)?;
        let answer = self.peers[1].pc.create_answer(None)?;
        self.peers[1]
            .pc
            .set_local_description(now, answer.clone())?;
        self.peers[0].pc.set_remote_description(now, answer)?;
        self.pump()
    }

    /// The offerer sends video from a sendonly transceiver; connected over host candidates.
    fn connected() -> Result<(Self, RTCRtpSenderId)> {
        let mut world = World {
            peers: [Peer::new("10.0.0.1:5000")?, Peer::new("10.0.0.2:5000")?],
            now: Instant::now(),
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
        world.negotiate()?;
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
                    "not connected: {:?} / {:?}",
                    world.peers[0].states,
                    world.peers[1].states
                );
            }
            let next = world
                .peers
                .iter_mut()
                .filter_map(|p| p.pc.poll_timeout())
                .min()
                .unwrap_or(world.now);
            world.run_until(next.max(world.now + Duration::from_millis(1)))?;
        }
        Ok((world, RTCRtpSenderId::from(transceiver)))
    }

    fn send_media(&mut self, sender: RTCRtpSenderId, first: u16, packets: u16) -> Result<()> {
        let (ssrc, pt) = {
            let mut sender = self.peers[0].pc.rtp_sender(sender).expect("sender");
            let parameters = sender.get_parameters();
            (
                parameters.encodings[0]
                    .rtp_coding_parameters
                    .ssrc
                    .expect("an SSRC"),
                parameters.rtp_parameters.codecs[0].payload_type,
            )
        };
        for n in 0..packets {
            let now = self.now;
            let sequence_number = first.wrapping_add(n);
            self.peers[0]
                .pc
                .rtp_sender(sender)
                .expect("sender")
                .write_rtp(
                    now,
                    rtc::rtp::Packet {
                        header: rtc::rtp::header::Header {
                            version: 2,
                            payload_type: pt,
                            sequence_number,
                            timestamp: u32::from(sequence_number) * 3000,
                            ssrc,
                            marker: true,
                            ..Default::default()
                        },
                        payload: Bytes::from(vec![0x10u8; 100]),
                    },
                )?;
            self.pump()?;
            self.run_until(now + Duration::from_millis(20))?;
        }
        Ok(())
    }

    fn receiver_track(&mut self) -> (bool, rtc::media_stream::MediaStreamTrackState) {
        let id: RTCRtpTransceiverId = self.peers[1]
            .pc
            .get_transceivers()
            .next()
            .expect("a transceiver");
        let receiver = self.peers[1].pc.rtp_receiver(id.into()).expect("receiver");
        (receiver.track().muted(), receiver.track().ready_state())
    }
}

/// W3C 9.3: RTP unmutes the receiver's muted track; a BYE for its SSRC mutes it and does not
/// end it (only negotiation does).
#[test]
fn rtp_unmutes_the_remote_track_and_a_bye_mutes_it_without_ending_it() -> Result<()> {
    let (mut world, sender) = World::connected()?;
    assert!(
        world.peers[1]
            .track_events
            .iter()
            .any(|event| matches!(event, RTCTrackEvent::OnRemoteTrack(_))),
        "the track event came with the offer, before any media"
    );
    assert!(world.receiver_track().0, "muted until media arrives");
    world.peers[1].take_mute_events();

    world.send_media(sender, 100, 10)?;
    assert_eq!(world.peers[1].take_mute_events(), vec!["unmute"]);
    assert!(!world.receiver_track().0);

    // The sender's connection closes: its streams say BYE (RFC 3550 6.6).
    world.peers[0].pc.close()?;
    world.pump()?;
    assert_eq!(world.peers[1].take_mute_events(), vec!["mute"]);
    assert_eq!(
        world.receiver_track(),
        (true, rtc::media_stream::MediaStreamTrackState::Live),
        "muted, not ended"
    );
    Ok(())
}

/// W3C 5.1.1 / 9.3: a remote description that stops the sending mutes the receiving track.
#[test]
fn a_remote_description_that_stops_the_sending_mutes_the_track() -> Result<()> {
    let (mut world, sender) = World::connected()?;
    world.send_media(sender, 200, 10)?;
    assert!(!world.receiver_track().0);
    world.peers[1].take_mute_events();

    world.peers[0]
        .pc
        .rtp_transceiver(sender.into())
        .expect("transceiver")
        .set_direction(RTCRtpTransceiverDirection::Inactive)?;
    world.negotiate()?;
    assert_eq!(world.peers[1].take_mute_events(), vec!["mute"]);
    assert_eq!(
        world.receiver_track(),
        (true, rtc::media_stream::MediaStreamTrackState::Live)
    );
    Ok(())
}
