//! Loss repair when no retransmission format is negotiated, between two `rtci` peer
//! connections in virtual time: VP8 with NACK and no `rtx` format, the default interceptors,
//! and a network that loses packets.
//!
//! RFC 4585 section 6.2.1 defines the generic NACK and leaves the form of the retransmission
//! to the sender; RFC 4588 is the retransmission format, and without it negotiated the sender
//! answers a NACK with the packet again, as it was sent: the media SSRC, the same sequence
//! number. Under SRTP that is the same packet index a second time, and "each packet index is
//! protected at most once" (RFC 3711 section 3.3.1; RFC 7714 section 8.1 for the AEAD
//! nonce): the engine's SRTP sender protects the SAME packet again, which yields the same
//! bytes, and refuses a different one. So everything wire-ward of the NACK responder has to
//! leave such a retransmission as its first transmission left: the header extensions an
//! interceptor writes per transmission (the transport-wide sequence number, the
//! abs-send-time stamp) keep the values the first transmission had.

use anyhow::{Result, bail};
use bytes::Bytes;
use rtci::interceptor::Registry;
use rtci::media_stream::MediaStreamTrack;
use rtci::peer_connection::configuration::RTCConfigurationBuilder;
use rtci::peer_connection::configuration::interceptor_registry::register_default_interceptors;
use rtci::peer_connection::configuration::media_engine::{MIME_TYPE_VP8, MediaEngine};
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
    RTCRtpCodec, RTCRtpCodecParameters, RTCRtpCodingParameters, RTCRtpEncodingParameters,
    RtpCodecKind,
};
use rtci::sansio::Protocol;
use rtci::shared::marshal::Unmarshal;
use rtci::shared::{TaggedBytesMut, TransportContext, TransportProtocol};
use std::collections::{BTreeMap, BTreeSet};
use std::net::SocketAddr;
use std::time::{Duration, Instant};

const CONNECT_WITHIN: Duration = Duration::from_secs(10);
const VP8_PT: u8 = 96;
const MEDIA_SSRC: u32 = 0x4e4f_5258;

struct Peer {
    pc: RTCPeerConnection,
    addr: SocketAddr,
    connected: bool,
    states: Vec<RTCPeerConnectionState>,
    /// The RTP packets handed to the application: sequence number and payload.
    read: Vec<(u16, Bytes)>,
}

impl Peer {
    /// VP8 and nothing else for video (no `rtx` format), and the default interceptors: NACK,
    /// congestion control feedback, the abs-send-time stamp, the pacer.
    fn new(addr: &str) -> Result<Self> {
        let mut media_engine = MediaEngine::default();
        media_engine.register_codec(
            RTCRtpCodecParameters {
                rtp_codec: RTCRtpCodec {
                    mime_type: MIME_TYPE_VP8.to_owned(),
                    clock_rate: 90000,
                    channels: 0,
                    sdp_fmtp_line: String::new(),
                    rtcp_feedback: vec![],
                },
                payload_type: VP8_PT,
            },
            RtpCodecKind::Video,
        )?;
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

/// The RTP header of an SRTP packet on the wire (SRTP leaves the header in the clear), or
/// `None` for anything else.
fn wire_rtp_header(datagram: &[u8]) -> Option<Header> {
    if datagram.len() < 12 || datagram[0] >> 6 != 2 || (192..=223).contains(&datagram[1]) {
        return None;
    }
    Header::unmarshal(&mut &datagram[..]).ok()
}

struct World {
    peers: [Peer; 2],
    now: Instant,
    /// The sequence numbers of the first peer's media packets the network lost (each the
    /// first time it crossed; a packet sent again arrives).
    lost: BTreeSet<u16>,
    /// Every datagram of the first peer's media stream that crossed the wire, by sequence
    /// number, in the order sent: the protected bytes.
    wire: BTreeMap<u16, Vec<Vec<u8>>>,
    /// The payload types and SSRCs of the first peer's RTP on the wire.
    flows: BTreeSet<(u32, u8)>,
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
                if i == 0
                    && let Some(header) = wire_rtp_header(&data)
                {
                    self.flows.insert((header.ssrc, header.payload_type));
                    if header.ssrc == MEDIA_SSRC {
                        let copies = self.wire.entry(header.sequence_number).or_default();
                        copies.push(data.to_vec());
                        // The network loses one media packet in five, the first time it is
                        // sent.
                        if copies.len() == 1 && header.sequence_number % 5 == 2 {
                            self.lost.insert(header.sequence_number);
                            continue;
                        }
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
                    peer.read
                        .push((packet.header.sequence_number, packet.payload));
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

    /// Two connected peers; the first sends one VP8 stream without a retransmission stream.
    fn connected() -> Result<(Self, RTCRtpSenderId)> {
        let mut world = World {
            peers: [Peer::new("10.0.0.1:5000")?, Peer::new("10.0.0.2:5000")?],
            now: Instant::now(),
            lost: BTreeSet::new(),
            wire: BTreeMap::new(),
            flows: BTreeSet::new(),
        };
        let sender = world.peers[0].pc.add_track(MediaStreamTrack::new(
            "call".to_owned(),
            "video".to_owned(),
            "video".to_owned(),
            RtpCodecKind::Video,
            vec![RTCRtpEncodingParameters {
                rtp_coding_parameters: RTCRtpCodingParameters {
                    ssrc: Some(MEDIA_SSRC),
                    ..Default::default()
                },
                codec: RTCRtpCodec {
                    mime_type: MIME_TYPE_VP8.to_owned(),
                    clock_rate: 90000,
                    channels: 0,
                    sdp_fmtp_line: String::new(),
                    rtcp_feedback: vec![],
                },
                ..Default::default()
            }],
        ))?;
        let now = world.now;
        let offer = world.peers[0].pc.create_offer(None)?;
        assert!(
            !offer.sdp.contains(" rtx/"),
            "no retransmission format is offered:\n{}",
            offer.sdp
        );
        assert!(
            offer.sdp.contains("abs-send-time"),
            "the default interceptors offer the abs-send-time extension on video:\n{}",
            offer.sdp
        );
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
            if world.now.duration_since(start) >= CONNECT_WITHIN {
                bail!("not connected: {:?}", world.peers[0].states);
            }
            let next = world.now + Duration::from_millis(10);
            world.run_until(next)?;
        }
        Ok((world, sender))
    }

    /// The payload of the one-packet VP8 frame with sequence number `seq`.
    fn payload(seq: u16) -> Bytes {
        let mut payload = vec![0x10u8];
        payload.extend((0..200u16).map(|i| (i as u8) ^ (seq as u8)));
        Bytes::from(payload)
    }

    /// Writes a one-packet VP8 frame with sequence number `seq`, then runs 33 ms.
    fn send(&mut self, sender: RTCRtpSenderId, seq: u16) -> Result<()> {
        let now = self.now;
        let mut rtp_sender = self.peers[0].pc.rtp_sender(sender).expect("sender");
        rtp_sender.write_rtp(
            now,
            rtci::rtp::Packet {
                header: Header {
                    version: 2,
                    payload_type: VP8_PT,
                    sequence_number: seq,
                    timestamp: u32::from(seq) * 3000,
                    ssrc: MEDIA_SSRC,
                    marker: true,
                    ..Default::default()
                },
                payload: Self::payload(seq),
            },
        )?;
        self.pump()?;
        self.run_until(now + Duration::from_millis(33))
    }
}

/// Without a retransmission format the sender answers a NACK with the packet again as it was
/// sent, and that packet reaches the wire and the receiving application.
///
/// The default interceptors stamp the abs-send-time extension wire-ward of the NACK responder.
/// A new stamp on the packet sent again made it a different packet under the SRTP index of
/// the first transmission, which the SRTP sender refuses (RFC 3711 section 3.3.1): every such
/// retransmission was dropped below the interceptors, after the NACK responder had lowered
/// the media target to make room for it and the congestion controller had recorded it as
/// sent, and no lost packet was ever repaired. The packet sent again keeps the stamp of its
/// first transmission: it is the same packet, byte for byte, on the wire.
#[test]
fn a_lost_packet_is_sent_again_as_it_was_and_arrives_when_no_rtx_is_negotiated() -> Result<()> {
    let (mut world, sender) = World::connected()?;
    for seq in 1000..1100 {
        world.send(sender, seq)?;
    }
    let until = world.now + Duration::from_secs(2);
    world.run_until(until)?;

    assert_eq!(
        BTreeSet::from([(MEDIA_SSRC, VP8_PT)]),
        world.flows,
        "one flow: no retransmission stream"
    );
    assert_eq!(
        (1000..1100u16)
            .filter(|seq| seq % 5 == 2)
            .collect::<BTreeSet<_>>(),
        world.lost,
        "the network lost one packet in five"
    );

    // Each lost packet crossed the wire again, the same bytes as the first time.
    for seq in &world.lost {
        let copies = &world.wire[seq];
        assert!(
            copies.len() >= 2,
            "the lost packet {seq} was sent again ({} on the wire)",
            copies.len()
        );
        for copy in &copies[1..] {
            assert_eq!(
                &copies[0], copy,
                "the retransmission of {seq} is the packet as it was first sent"
            );
        }
    }

    // And every packet written reached the receiving application.
    let read: BTreeMap<u16, &Bytes> = world.peers[1]
        .read
        .iter()
        .map(|(seq, payload)| (*seq, payload))
        .collect();
    for seq in 1000..1100u16 {
        assert_eq!(
            Some(&&World::payload(seq)),
            read.get(&seq),
            "the packet {seq} reached the application"
        );
    }
    Ok(())
}
