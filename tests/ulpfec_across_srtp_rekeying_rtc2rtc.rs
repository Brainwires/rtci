//! RFC 5109 section 11: "the new key SHOULD be used to encrypt the FEC packets that are
//! generated from a combination of payload packets encrypted by the old and new keys" (row
//! RFC5109-11-3).
//!
//! Two `rtci` peers in virtual time, VP8 in RED with ULPFEC in RED packets of its own (the
//! `Chrome` profile's form), one FEC packet for each two media packets, no NACK. The first
//! media packet of a block leaves under the first DTLS association's SRTP keys; the sender
//! then asks for a new association (`renew_dtls_association`, RFC 5764 section 4.1.2: new
//! keys) and once its handshake is done the block's second media packet and its FEC packet
//! leave under the new keys, after the receiver stopped holding the old ones (RFC 5764
//! section 4.3 lets it keep them a while). The network loses one of the two media packets, and the receiver
//! rebuilds it from the other and the FEC packet, so the FEC was protected under keys the
//! receiver holds, and computed over the packets whichever keys they left under (the encoder
//! reads them before SRTP: `Slot::FecWireImage`).

use anyhow::{Context, Result, bail};
use bytes::Bytes;
use rtci::interceptor::{RedPlacement, Registry, Slot, UlpfecReceiveBuilder, UlpfecSendBuilder};
use rtci::peer_connection::configuration::RTCConfigurationBuilder;
use rtci::peer_connection::configuration::interceptor_registry::register_default_interceptors;
use rtci::peer_connection::configuration::media_engine::{MIME_TYPE_VP8, MediaEngine};
use rtci::peer_connection::configuration::setting_engine::SettingEngineBuilder;
use rtci::peer_connection::event::RTCPeerConnectionEvent;
use rtci::peer_connection::message::RTCMessage;
use rtci::peer_connection::state::RTCPeerConnectionState;
use rtci::peer_connection::transport::{
    CandidateConfig, CandidateHostConfig, RTCIceCandidate, RTCIceCandidateInit,
};
use rtci::peer_connection::{RTCPeerConnection, RTCPeerConnectionBuilder};
use rtci::rtp::header::Header;
use rtci::rtp_transceiver::RTCRtpSenderId;
use rtci::rtp_transceiver::rtp_sender::{
    RTCRtpCodec, RTCRtpCodecParameters, RTCRtpEncodingParameters, RtpCodecKind,
};
use rtci::rtp_transceiver::{RTCRtpTransceiverDirection, RTCRtpTransceiverInit};
use rtci::sansio::Protocol;
use rtci::shared::marshal::Unmarshal;
use rtci::shared::{TaggedBytesMut, TransportContext, TransportProtocol};
use std::net::SocketAddr;
use std::time::{Duration, Instant};

const CONNECT_WITHIN: Duration = Duration::from_secs(10);
const VP8_PT: u8 = 96;
const RED_PT: u8 = 116;
const ULPFEC_PT: u8 = 117;

struct Peer {
    pc: RTCPeerConnection,
    addr: SocketAddr,
    connected: bool,
    states: Vec<RTCPeerConnectionState>,
    /// The media packets the application was given.
    rtp: Vec<rtci::rtp::Packet>,
}

impl Peer {
    /// VP8 without NACK, RED and ULPFEC; a ULPFEC encoder that sends one FEC packet for every
    /// two media packets whatever the loss, reading them as they leave (its wire tap), and the
    /// decoder. A new DTLS association stays on the peer's address.
    fn new(addr: &str) -> Result<Self> {
        let mut media_engine = MediaEngine::default();
        for (mime_type, payload_type) in [
            (MIME_TYPE_VP8, VP8_PT),
            ("video/red", RED_PT),
            ("video/ulpfec", ULPFEC_PT),
        ] {
            media_engine.register_codec(
                RTCRtpCodecParameters {
                    rtp_codec: RTCRtpCodec {
                        mime_type: mime_type.to_owned(),
                        clock_rate: 90000,
                        channels: 0,
                        sdp_fmtp_line: String::new(),
                        rtcp_feedback: vec![],
                    },
                    payload_type,
                },
                RtpCodecKind::Video,
            )?;
        }
        let registry = register_default_interceptors(Registry::new(), &mut media_engine)?;
        let mut encoder = UlpfecSendBuilder::red(RED_PT, ULPFEC_PT)
            .with_red_placement(RedPlacement::OwnPacket)
            .with_num_media_packets(2)
            .with_num_fec_packets(1)
            .with_adaptive_rate(false)
            .build();
        let tap = encoder.wire_tap();
        let registry = registry
            .with(Slot::FecEncoder, encoder)
            .with(Slot::FecWireImage, tap)
            .with(
                Slot::FecDecoder,
                UlpfecReceiveBuilder::red(RED_PT, ULPFEC_PT).build(),
            );
        let pc = RTCPeerConnectionBuilder::new()
            .with_configuration(RTCConfigurationBuilder::new().build())
            .with_setting_engine(
                SettingEngineBuilder::new()
                    .with_dtls_new_association_on_previous_addresses(true)
                    .build(),
            )
            .with_media_engine(media_engine)
            .with_interceptor_registry(registry)
            .build(Instant::now())?;
        Ok(Self {
            pc,
            addr: addr.parse()?,
            connected: false,
            states: Vec::new(),
            rtp: Vec::new(),
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

    /// The `a=tls-id` of the peer's current local description.
    fn tls_id(&self) -> Option<String> {
        let sdp = self.pc.current_local_description()?.sdp;
        sdp.lines()
            .find_map(|line| line.strip_prefix("a=tls-id:"))
            .map(str::to_owned)
    }
}

/// The RTP header of an SRTP packet on the wire (SRTP leaves it in the clear).
fn wire_rtp_header(datagram: &[u8]) -> Option<Header> {
    if datagram.len() < 12 || datagram[0] >> 6 != 2 || (192..=223).contains(&datagram[1]) {
        return None;
    }
    Header::unmarshal(&mut &datagram[..]).ok()
}

/// What crossed the network, in order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Crossed {
    /// A DTLS handshake record (RFC 9147 / RFC 6347 content type 22) of either peer.
    DtlsHandshake,
    /// The first peer's RTP packet in RED (media or FEC: the block header is encrypted): its
    /// sequence number on the wire, and whether the network lost it.
    Red { sequence_number: u16, lost: bool },
}

struct World {
    peers: [Peer; 2],
    now: Instant,
    /// The first peer's media sequence number the network loses.
    lose: Option<u16>,
    crossed: Vec<Crossed>,
}

impl World {
    fn pump(&mut self) -> Result<()> {
        loop {
            let mut in_flight = Vec::new();
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
                if data.first() == Some(&22) {
                    self.crossed.push(Crossed::DtlsHandshake);
                }
                if i == 0
                    && let Some(header) = wire_rtp_header(&data)
                    && header.payload_type == RED_PT
                {
                    let lost = self.lose == Some(header.sequence_number);
                    self.crossed.push(Crossed::Red {
                        sequence_number: header.sequence_number,
                        lost,
                    });
                    if lost {
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
                if let RTCPeerConnectionEvent::OnConnectionStateChangeEvent(state) = event {
                    if state == RTCPeerConnectionState::Failed {
                        bail!("a peer's connection failed: {:?}", peer.states);
                    }
                    peer.connected = state == RTCPeerConnectionState::Connected;
                    peer.states.push(state);
                }
            }
            while let Some(message) = peer.pc.poll_read() {
                if let RTCMessage::RtpPacket(_, packet) = message.message {
                    peer.rtp.push(packet);
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

    /// Offer from the first peer, answer from the second, both host candidates, run until
    /// both are connected.
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
        for i in 0..2 {
            let candidate = self.peers[i].candidate()?;
            self.peers[i].pc.add_local_candidate(candidate.clone())?;
            self.peers[1 - i].pc.add_remote_candidate(candidate)?;
        }
        let start = self.now;
        while !self.peers.iter().all(|p| p.connected) {
            if self.now.duration_since(start) >= CONNECT_WITHIN {
                bail!("not connected: {:?}", self.peers[0].states);
            }
            let next = self.now + Duration::from_millis(10);
            self.run_until(next)?;
        }
        Ok(())
    }

    fn connected(lose: u16) -> Result<(Self, RTCRtpSenderId)> {
        let mut world = World {
            peers: [Peer::new("10.0.0.1:5000")?, Peer::new("10.0.0.2:5000")?],
            now: Instant::now(),
            lose: Some(lose),
            crossed: Vec::new(),
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
        world.negotiate()?;
        Ok((world, sender))
    }

    /// Writes a one-packet VP8 frame with sequence number `seq`, then lets 33 ms pass.
    fn send(&mut self, sender: RTCRtpSenderId, seq: u16) -> Result<()> {
        let now = self.now;
        let mut rtp_sender = self.peers[0].pc.rtp_sender(sender).expect("sender");
        let ssrc = rtp_sender.get_parameters().encodings[0]
            .rtp_coding_parameters
            .ssrc
            .expect("an SSRC");
        rtp_sender.write_rtp(
            now,
            rtci::rtp::Packet {
                header: Header {
                    version: 2,
                    payload_type: VP8_PT,
                    sequence_number: seq,
                    timestamp: u32::from(seq) * 3000,
                    ssrc,
                    marker: true,
                    ..Default::default()
                },
                payload: payload(seq),
            },
        )?;
        self.pump()?;
        self.run_until(now + Duration::from_millis(33))
    }
}

fn payload(seq: u16) -> Bytes {
    let mut payload = vec![0x10u8];
    payload.extend((0..200u16).map(|i| (i as u8) ^ (seq as u8)));
    Bytes::from(payload)
}

/// The application's packets 1000 and 1001 make a first block (wire 1000, 1001, FEC 1002);
/// the next block is the application's 1002 (wire 1003, sent under the first association's
/// keys) and 1003 (wire 1004), whose FEC packet (wire 1005) follows it, both sent after a new
/// DTLS association took over. The network loses wire sequence number `lose`.
fn block_across_a_key_change(lose: u16) -> Result<World> {
    let (mut world, sender) = World::connected(lose)?;
    world.send(sender, 1000)?;
    world.send(sender, 1001)?;
    world.send(sender, 1002)?;
    let tls_ids = [world.peers[0].tls_id(), world.peers[1].tls_id()];
    let handshakes_before = world
        .crossed
        .iter()
        .filter(|c| **c == Crossed::DtlsHandshake)
        .count();

    // New keys: a new DTLS association on the same addresses (RFC 5764 section 4.1.2).
    world.peers[0].pc.renew_dtls_association();
    world.negotiate()?;
    // Past the time the receiver keeps the previous association's keys for packets still on
    // their way (RFC 5764 section 4.3; 10 s in the engine): from here on only packets under
    // the new keys can be read.
    let until = world.now + Duration::from_secs(11);
    world.run_until(until)?;
    for (i, before) in tls_ids.iter().enumerate() {
        assert!(before.is_some());
        assert_ne!(
            &world.peers[i].tls_id(),
            before,
            "peer {i}: a new DTLS association"
        );
    }
    let handshake_at = world
        .crossed
        .iter()
        .enumerate()
        .filter(|(_, c)| **c == Crossed::DtlsHandshake)
        .nth(handshakes_before)
        .map(|(at, _)| at)
        .context("the new association's handshake crossed the network")?;

    world.send(sender, 1003)?;
    let until = world.now + Duration::from_millis(500);
    world.run_until(until)?;

    // The block's two media packets and its FEC packet, in the order they crossed: the first
    // before the new handshake, the others after it.
    let position = |seq: u16| {
        world.crossed.iter().position(
            |c| matches!(c, Crossed::Red { sequence_number, .. } if *sequence_number == seq),
        )
    };
    let (a, b, fec) = (
        position(1003).context("first media packet of the block")?,
        position(1004).context("second media packet of the block")?,
        position(1005).context("the block's FEC packet")?,
    );
    assert!(
        a < handshake_at && handshake_at < b && b < fec,
        "old keys, new handshake, new keys: {a} {handshake_at} {b} {fec}"
    );
    assert!(
        world
            .crossed
            .iter()
            .any(|c| matches!(c, Crossed::Red { sequence_number, lost: true } if *sequence_number == lose)),
        "the network lost {lose}"
    );
    Ok(world)
}

/// The packet sent under the old keys is lost: the second media packet and the FEC packet,
/// both under the new keys, bring it back.
#[test]
fn fec_under_the_new_keys_rebuilds_a_packet_sent_under_the_old_ones() -> Result<()> {
    let world = block_across_a_key_change(1003)?;
    let rebuilt = world.peers[1]
        .rtp
        .iter()
        .find(|packet| packet.payload == payload(1002))
        .context("the packet sent under the old keys was rebuilt")?;
    assert_eq!(VP8_PT, rebuilt.header.payload_type);
    let received = world.peers[1].pc.fec_stats().received;
    assert_eq!(1, received[0].packets_recovered, "{received:?}");
    Ok(())
}

/// The packet sent under the new keys is lost: the first media packet (old keys) and the FEC
/// packet (new keys) bring it back.
#[test]
fn fec_under_the_new_keys_rebuilds_a_packet_sent_under_them_from_one_under_the_old() -> Result<()> {
    let world = block_across_a_key_change(1004)?;
    world.peers[1]
        .rtp
        .iter()
        .find(|packet| packet.payload == payload(1003))
        .context("the packet sent under the new keys was rebuilt")?;
    let received = world.peers[1].pc.fec_stats().received;
    assert_eq!(1, received[0].packets_recovered, "{received:?}");
    Ok(())
}
