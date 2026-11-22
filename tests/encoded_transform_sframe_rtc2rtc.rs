//! W3C webrtc-encoded-transform with SFrame (RFC 9605) between two `rtc` peer connections, as
//! an application does it today: it encrypts each encoded frame with `rtc::sframe` before
//! packetization, splits the ciphertext with the format-agnostic payloader
//! (`rtp::codec::opaque`), writes the packets on a video sender, and on the other side
//! reassembles them and decrypts. The link loses packets; NACK and RTX (the default
//! interceptors) bring them back, and every frame is decrypted.
//!
//! The SFrame RTP payload format of draft-ietf-avtcore-rtp-sframe and its SDP signalling are
//! not implemented: the payload type here is the negotiated VP8 one, and both applications
//! know the payload is opaque.
//!
//! The peers exchange datagrams in memory, on a virtual clock.

use anyhow::{Result, bail};
use bytes::Bytes;
use rtc::interceptor::Registry;
use rtc::peer_connection::configuration::RTCConfigurationBuilder;
use rtc::peer_connection::configuration::interceptor_registry::register_default_interceptors;
use rtc::peer_connection::configuration::media_engine::MediaEngine;
use rtc::peer_connection::event::RTCPeerConnectionEvent;
use rtc::peer_connection::message::RTCMessage;
use rtc::peer_connection::state::RTCPeerConnectionState;
use rtc::peer_connection::transport::{
    CandidateConfig, CandidateHostConfig, RTCIceCandidate, RTCIceCandidateInit,
};
use rtc::peer_connection::{RTCPeerConnection, RTCPeerConnectionBuilder};
use rtc::rtp::codec::opaque::{OpaqueDepacketizer, OpaquePayloader};
use rtc::rtp::header::Header;
use rtc::rtp::packetizer::{Depacketizer, Payloader};
use rtc::rtp_transceiver::rtp_sender::{RTCRtpEncodingParameters, RtpCodecKind};
use rtc::rtp_transceiver::{RTCRtpSenderId, RTCRtpTransceiverDirection, RTCRtpTransceiverInit};
use rtc::sansio::Protocol;
use rtc::sframe::{CipherSuite, SFrameContext};
use rtc::shared::marshal::Unmarshal;
use rtc::shared::{TaggedBytesMut, TransportContext, TransportProtocol};
use std::net::SocketAddr;
use std::time::{Duration, Instant};

struct Peer {
    pc: RTCPeerConnection,
    addr: SocketAddr,
    /// The RTP packets `poll_read` yielded.
    read: Vec<rtc::rtp::Packet>,
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
            read: vec![],
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
    /// (SSRC, sequence number) of media packets the link loses the first time they cross it.
    lose: Vec<(u32, u16)>,
    lost: Vec<(u32, u16)>,
}

/// The RTP header of an SRTP packet (the header is in the clear), `None` for anything else.
fn rtp_header(datagram: &[u8]) -> Option<Header> {
    if datagram.len() < 12 || datagram[0] >> 6 != 2 || (192..=223).contains(&datagram[1]) {
        return None;
    }
    Header::unmarshal(&mut &datagram[..]).ok()
}

impl World {
    fn pump(&mut self) -> Result<()> {
        loop {
            let mut in_flight = vec![];
            for (i, peer) in self.peers.iter_mut().enumerate() {
                while let Some(msg) = peer.pc.poll_write() {
                    in_flight.push((
                        i,
                        msg.transport.local_addr,
                        msg.transport.peer_addr,
                        msg.message,
                    ));
                }
            }
            if in_flight.is_empty() {
                break;
            }
            for (i, from, to, data) in in_flight {
                if i == 0
                    && let Some(header) = rtp_header(&data)
                {
                    let key = (header.ssrc, header.sequence_number);
                    if let Some(at) = self.lose.iter().position(|k| *k == key) {
                        self.lose.remove(at);
                        self.lost.push(key);
                        continue;
                    }
                }
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
                if let RTCPeerConnectionEvent::OnConnectionStateChangeEvent(
                    RTCPeerConnectionState::Failed,
                ) = event
                {
                    bail!("a peer's connection failed");
                }
            }
            while let Some(message) = peer.pc.poll_read() {
                if let RTCMessage::RtpPacket(_, packet) = message.message {
                    peer.read.push(packet);
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

    fn connected() -> Result<(Self, RTCRtpSenderId)> {
        let mut world = World {
            peers: [Peer::new("10.0.0.1:5000")?, Peer::new("10.0.0.2:5000")?],
            now: Instant::now(),
            lose: vec![],
            lost: vec![],
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
        let sender = RTCRtpSenderId::from(transceiver);
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
        let deadline = now + Duration::from_secs(10);
        while !world
            .peers
            .iter()
            .all(|p| p.pc.connection_state() == RTCPeerConnectionState::Connected)
        {
            if world.now >= deadline {
                bail!("not connected");
            }
            let next = world.now + Duration::from_millis(10);
            world.run_until(next)?;
        }
        Ok((world, sender))
    }
}

/// webrtc-encoded-transform section 3 / RFC 9605: frames SFrame-encrypted by the
/// application before packetization cross the link in the opaque payload, survive packet loss
/// through NACK and RTX, and are decrypted after reassembly; the RTP layer never parses them.
#[test]
fn sframe_encrypted_frames_survive_loss_through_nack_and_rtx() -> Result<()> {
    const FRAMES: u32 = 12;
    let (mut world, sender) = World::connected()?;
    let key = [9u8; 16];
    let mut encryptor = SFrameContext::with_default_provider(CipherSuite::Aes128GcmSha256_128)?;
    encryptor.add_send_key(1, &key)?;
    let mut decryptor = SFrameContext::with_default_provider(CipherSuite::Aes128GcmSha256_128)?;
    decryptor.add_recv_key(1, &key)?;

    let (ssrc, pt) = {
        let mut sender = world.peers[0].pc.rtp_sender(sender).expect("sender");
        let parameters = sender.get_parameters();
        (
            parameters.encodings[0]
                .rtp_coding_parameters
                .ssrc
                .expect("an SSRC"),
            parameters.rtp_parameters.codecs[0].payload_type,
        )
    };
    // The second packet of frames 2, 5 and 9 is lost the first time.
    world.lose = vec![(ssrc, 1007), (ssrc, 1016), (ssrc, 1028)];

    let frame = |n: u32| -> Vec<u8> { (0..2500u32).map(|i| ((i + 7 * n) % 251) as u8).collect() };
    let mut seq: u16 = 1000;
    for n in 0..FRAMES {
        let ciphertext: Bytes = encryptor.encrypt(1, b"", &frame(n))?.into();
        let payloads = OpaquePayloader.payload(1100, &ciphertext)?;
        let count = payloads.len();
        for (i, payload) in payloads.into_iter().enumerate() {
            let now = world.now;
            world.peers[0]
                .pc
                .rtp_sender(sender)
                .expect("sender")
                .write_rtp(
                    now,
                    rtc::rtp::Packet {
                        header: Header {
                            version: 2,
                            payload_type: pt,
                            sequence_number: seq,
                            timestamp: 3000 * n,
                            ssrc,
                            marker: i + 1 == count,
                            ..Default::default()
                        },
                        payload,
                    },
                )?;
            seq = seq.wrapping_add(1);
        }
        world.pump()?;
        let next = world.now + Duration::from_millis(33);
        world.run_until(next)?;
    }
    let next = world.now + Duration::from_secs(2);
    world.run_until(next)?;
    assert_eq!(world.lost.len(), 3, "the link lost the three packets");

    // Reassemble in sequence order, each packet once (a retransmission may arrive after the
    // packets that followed it).
    let mut received: Vec<rtc::rtp::Packet> = world.peers[1]
        .read
        .iter()
        .filter(|p| p.header.ssrc == ssrc)
        .cloned()
        .collect();
    received.sort_by_key(|p| p.header.sequence_number);
    received.dedup_by_key(|p| p.header.sequence_number);
    assert_eq!(
        received.len(),
        usize::from(seq - 1000),
        "every packet arrived, the lost ones retransmitted"
    );
    let mut depacketizer = OpaqueDepacketizer::default();
    let mut frames = vec![];
    for packet in &received {
        let unit = depacketizer.depacketize(&packet.payload)?;
        if !unit.is_empty() {
            frames.push(decryptor.decrypt(b"", &unit)?);
        }
    }
    assert_eq!(frames.len(), FRAMES as usize);
    for (n, decrypted) in frames.iter().enumerate() {
        assert_eq!(*decrypted, frame(n as u32), "frame {n}");
    }
    Ok(())
}
