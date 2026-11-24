//! A sender sends once negotiated, between two `rtci` peer connections in virtual time, for
//! each way the W3C object model makes one (webrtc-pc 5.1 addTrack, 4.4.1.6 a remote offer's
//! transceiver, RFC 9429 5.7 rollback): the transceiver `add_track` created, one a remote
//! offer created and `add_track` then took, and one whose offer was rolled back (glare)
//! before the other side's offer was answered and the first offer was made again. Media and
//! a data channel both flow afterwards.

use anyhow::{Result, bail};
use bytes::Bytes;
use rtci::interceptor::Registry;
use rtci::media_stream::MediaStreamTrack;
use rtci::peer_connection::configuration::RTCConfigurationBuilder;
use rtci::peer_connection::configuration::interceptor_registry::register_default_interceptors;
use rtci::peer_connection::configuration::media_engine::{MIME_TYPE_VP8, MediaEngine};
use rtci::peer_connection::event::{RTCDataChannelEvent, RTCPeerConnectionEvent};
use rtci::peer_connection::message::RTCMessage;
use rtci::peer_connection::sdp::RTCSessionDescription;
use rtci::peer_connection::state::RTCPeerConnectionState;
use rtci::peer_connection::transport::{
    CandidateConfig, CandidateHostConfig, RTCIceCandidate, RTCIceCandidateInit,
};
use rtci::peer_connection::{RTCPeerConnection, RTCPeerConnectionBuilder};
use rtci::rtp_transceiver::RTCRtpSenderId;
use rtci::rtp_transceiver::rtp_sender::{
    RTCRtpCodec, RTCRtpCodingParameters, RTCRtpEncodingParameters, RtpCodecKind,
};
use rtci::sansio::Protocol;
use rtci::shared::{TaggedBytesMut, TransportContext, TransportProtocol};
use std::net::SocketAddr;
use std::time::{Duration, Instant};

const CONNECT_WITHIN: Duration = Duration::from_secs(10);

struct Peer {
    pc: RTCPeerConnection,
    addr: SocketAddr,
    connected: bool,
    states: Vec<RTCPeerConnectionState>,
    rtp_received: usize,
    messages: Vec<String>,
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
            rtp_received: 0,
            messages: Vec::new(),
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

    /// A VP8 track with one coding on `ssrc`, as an application that chooses its SSRCs
    /// makes it.
    fn add_video_track(&mut self, name: &str, ssrc: u32) -> Result<RTCRtpSenderId> {
        Ok(self.pc.add_track(MediaStreamTrack::new(
            format!("{name}-stream"),
            name.to_owned(),
            name.to_owned(),
            RtpCodecKind::Video,
            vec![RTCRtpEncodingParameters {
                rtp_coding_parameters: RTCRtpCodingParameters {
                    ssrc: Some(ssrc),
                    ..Default::default()
                },
                codec: RTCRtpCodec {
                    mime_type: MIME_TYPE_VP8.to_owned(),
                    clock_rate: 90000,
                    ..Default::default()
                },
                ..Default::default()
            }],
        ))?)
    }
}

struct World {
    peers: [Peer; 2],
    now: Instant,
}

impl World {
    fn new() -> Result<Self> {
        Ok(World {
            peers: [Peer::new("10.0.0.1:5000")?, Peer::new("10.0.0.2:5000")?],
            now: Instant::now(),
        })
    }

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
        let now = self.now;
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
                    RTCPeerConnectionEvent::OnDataChannel(RTCDataChannelEvent::OnOpen(id)) => {
                        if let Some(mut dc) = peer.pc.data_channel(id) {
                            dc.send_text(now, "hello")?;
                        }
                    }
                    _ => {}
                }
            }
            while let Some(message) = peer.pc.poll_read() {
                match message.message {
                    RTCMessage::RtpPacket(..) => peer.rtp_received += 1,
                    RTCMessage::DataChannelMessage(_, message) => {
                        peer.messages
                            .push(String::from_utf8_lossy(&message.data).into_owned());
                    }
                    _ => {}
                }
            }
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

    /// One exchange, `offerer` offering.
    fn negotiate(&mut self, offerer: usize) -> Result<()> {
        let now = self.now;
        let answerer = 1 - offerer;
        let offer = self.peers[offerer].pc.create_offer(None)?;
        self.peers[offerer]
            .pc
            .set_local_description(now, offer.clone())?;
        self.peers[answerer].pc.set_remote_description(now, offer)?;
        let answer = self.peers[answerer].pc.create_answer(None)?;
        self.peers[answerer]
            .pc
            .set_local_description(now, answer.clone())?;
        self.peers[offerer].pc.set_remote_description(now, answer)?;
        self.pump()
    }

    fn connect(&mut self) -> Result<()> {
        for i in 0..2 {
            let candidate = self.peers[i].candidate()?;
            self.peers[i].pc.add_local_candidate(candidate.clone())?;
            self.peers[1 - i].pc.add_remote_candidate(candidate)?;
        }
        let start = self.now;
        while !self.peers.iter().all(|p| p.connected) {
            if self.now.duration_since(start) >= CONNECT_WITHIN {
                bail!(
                    "not connected: {:?} / {:?}",
                    self.peers[0].states,
                    self.peers[1].states
                );
            }
            let next = self.now + Duration::from_millis(5);
            self.run_until(next)?;
        }
        Ok(())
    }

    /// Writes `packets` VP8 packets from `from`'s `sender`, as an application does: the
    /// payload type is the negotiated one, the SSRC the track's.
    fn send_media(
        &mut self,
        from: usize,
        sender: RTCRtpSenderId,
        ssrc: u32,
        packets: u16,
    ) -> Result<()> {
        let pt = {
            let mut sender = self.peers[from].pc.rtp_sender(sender).expect("sender");
            sender
                .get_parameters()
                .rtp_parameters
                .codecs
                .iter()
                .find(|c| c.rtp_codec.mime_type.eq_ignore_ascii_case(MIME_TYPE_VP8))
                .map(|c| c.payload_type)
                .expect("VP8 is negotiated")
        };
        for n in 0..packets {
            let now = self.now;
            self.peers[from]
                .pc
                .rtp_sender(sender)
                .expect("sender")
                .write_rtp(
                    now,
                    rtci::rtp::Packet {
                        header: rtci::rtp::header::Header {
                            version: 2,
                            payload_type: pt,
                            sequence_number: 1000 + n,
                            timestamp: u32::from(n) * 3000,
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
}

#[test]
fn the_transceiver_add_track_created_sends_once_negotiated() -> Result<()> {
    let mut world = World::new()?;
    let sender = world.peers[0].add_video_track("offered", 0x1111_0001)?;
    world.peers[0].pc.create_data_channel("chat", None)?;
    world.negotiate(0)?;
    world.connect()?;
    world.send_media(0, sender, 0x1111_0001, 20)?;
    assert!(
        world.peers[1].rtp_received >= 15,
        "received {}",
        world.peers[1].rtp_received
    );
    world.run_until(world.now + Duration::from_millis(500))?;
    assert!(world.peers[1].messages.iter().any(|m| m == "hello"));
    Ok(())
}

/// The answerer gives the transceiver the offer created a track (`add_track` reuses it):
/// its media reaches the offerer.
#[test]
fn a_remote_offers_transceiver_sends_once_add_track_took_it() -> Result<()> {
    let mut world = World::new()?;
    world.peers[0].add_video_track("offered", 0x2222_0001)?;
    let now = world.now;
    let offer = world.peers[0].pc.create_offer(None)?;
    world.peers[0]
        .pc
        .set_local_description(now, offer.clone())?;
    world.peers[1].pc.set_remote_description(now, offer)?;
    let answering = world.peers[1].add_video_track("answered", 0x2222_0002)?;
    assert_eq!(world.peers[1].pc.get_transceivers().count(), 1, "reused");
    let answer = world.peers[1].pc.create_answer(None)?;
    world.peers[1]
        .pc
        .set_local_description(now, answer.clone())?;
    world.peers[0].pc.set_remote_description(now, answer)?;
    world.connect()?;
    world.send_media(1, answering, 0x2222_0002, 20)?;
    assert!(
        world.peers[0].rtp_received >= 15,
        "received {}",
        world.peers[0].rtp_received
    );
    Ok(())
}

/// Glare (RFC 9429 4.1.8.2, 5.7): the first peer's offer is rolled back by the second's
/// (implicitly), answered, and then the first offers again; its sender sends, and the data
/// channel works.
#[test]
fn a_sender_whose_offer_was_rolled_back_sends_after_the_next_exchange() -> Result<()> {
    let mut world = World::new()?;
    let sender = world.peers[0].add_video_track("first", 0x3333_0001)?;
    world.peers[0].pc.create_data_channel("chat", None)?;
    let now = world.now;
    let abandoned = world.peers[0].pc.create_offer(None)?;
    world.peers[0].pc.set_local_description(now, abandoned)?;

    world.peers[1].pc.create_data_channel("other", None)?;
    let offer = world.peers[1].pc.create_offer(None)?;
    world.peers[1]
        .pc
        .set_local_description(now, offer.clone())?;
    // A remote offer over a pending local offer rolls it back (W3C 4.4.2 implicit rollback).
    world.peers[0].pc.set_remote_description(now, offer)?;
    let answer = world.peers[0].pc.create_answer(None)?;
    world.peers[0]
        .pc
        .set_local_description(now, answer.clone())?;
    world.peers[1].pc.set_remote_description(now, answer)?;

    world.negotiate(0)?;
    world.connect()?;
    world.send_media(0, sender, 0x3333_0001, 20)?;
    assert!(
        world.peers[1].rtp_received >= 15,
        "received {}",
        world.peers[1].rtp_received
    );
    world.run_until(world.now + Duration::from_millis(500))?;
    assert!(
        world.peers[1].messages.iter().any(|m| m == "hello"),
        "{:?}",
        world.peers[1].messages
    );
    Ok(())
}

/// An explicit rollback of a local offer leaves the session usable (RFC 9429 5.7).
#[test]
fn an_explicitly_rolled_back_offer_leaves_the_sender_usable() -> Result<()> {
    let mut world = World::new()?;
    let sender = world.peers[0].add_video_track("first", 0x4444_0001)?;
    let now = world.now;
    let offer = world.peers[0].pc.create_offer(None)?;
    world.peers[0].pc.set_local_description(now, offer)?;
    world.peers[0]
        .pc
        .set_local_description(now, RTCSessionDescription::rollback(None)?)?;
    world.negotiate(0)?;
    world.connect()?;
    world.send_media(0, sender, 0x4444_0001, 20)?;
    assert!(
        world.peers[1].rtp_received >= 15,
        "received {}",
        world.peers[1].rtp_received
    );
    Ok(())
}
