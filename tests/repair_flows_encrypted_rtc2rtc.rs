//! Repair flows are protected as the media they repair, between two `rtci` peer connections in
//! virtual time: VP8 with RTX (RFC 4588) and RED-carried ULPFEC (RFC 2198, RFC 5109), one
//! packet lost and retransmitted. No datagram on the wire carries the application's payload in
//! the clear: not the media, not its retransmission, not the FEC built from it, not the RED
//! packets that carry either.

use anyhow::{Result, bail};
use bytes::Bytes;
use rtci::interceptor::Registry;
use rtci::peer_connection::configuration::RTCConfigurationBuilder;
use rtci::peer_connection::configuration::interceptor_registry::{
    configure_ulpfec, register_default_interceptors,
};
use rtci::peer_connection::configuration::media_engine::{
    MIME_TYPE_RTX, MIME_TYPE_VP8, MediaEngine,
};
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
    RTCPFeedback, RTCRtpCodec, RTCRtpCodecParameters, RTCRtpEncodingParameters, RtpCodecKind,
};
use rtci::rtp_transceiver::{RTCRtpTransceiverDirection, RTCRtpTransceiverInit};
use rtci::sansio::Protocol;
use rtci::shared::marshal::Unmarshal;
use rtci::shared::{TaggedBytesMut, TransportContext, TransportProtocol};
use std::collections::HashSet;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

const CONNECT_WITHIN: Duration = Duration::from_secs(10);
const VP8_PT: u8 = 96;
const RTX_PT: u8 = 97;
const RED_PT: u8 = 116;
const ULPFEC_PT: u8 = 117;
/// What the application writes in every payload, after a VP8 payload descriptor.
const MARKER: &[u8] = b"PLAINTEXT-MARKER-0123456789abcdef";

fn codec(mime_type: &str, sdp_fmtp_line: &str, rtcp_feedback: Vec<RTCPFeedback>) -> RTCRtpCodec {
    RTCRtpCodec {
        mime_type: mime_type.to_owned(),
        clock_rate: 90000,
        channels: 0,
        sdp_fmtp_line: sdp_fmtp_line.to_owned(),
        rtcp_feedback,
    }
}

struct Peer {
    pc: RTCPeerConnection,
    addr: SocketAddr,
    connected: bool,
    states: Vec<RTCPeerConnectionState>,
    read_rtp: usize,
}

impl Peer {
    /// VP8 with NACK and RTX, RED and ULPFEC, and the default interceptors with the ULPFEC
    /// encoder.
    fn new(addr: &str) -> Result<Self> {
        let mut media_engine = MediaEngine::default();
        let nack = vec![RTCPFeedback {
            typ: "nack".to_owned(),
            parameter: "".to_owned(),
        }];
        for (mime_type, fmtp, feedback, payload_type) in [
            (MIME_TYPE_VP8, String::new(), nack, VP8_PT),
            (MIME_TYPE_RTX, format!("apt={VP8_PT}"), vec![], RTX_PT),
            ("video/red", String::new(), vec![], RED_PT),
            ("video/ulpfec", String::new(), vec![], ULPFEC_PT),
        ] {
            media_engine.register_codec(
                RTCRtpCodecParameters {
                    rtp_codec: codec(mime_type, &fmtp, feedback),
                    payload_type,
                },
                RtpCodecKind::Video,
            )?;
        }
        let registry = register_default_interceptors(Registry::new(), &mut media_engine)?;
        let registry = configure_ulpfec(registry, RED_PT, ULPFEC_PT);
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
            read_rtp: 0,
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
    /// Every datagram the first peer sent, once connected.
    wire: Vec<Vec<u8>>,
    /// The sender's media sequence number lost once on the way.
    drop_once: Option<u16>,
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
                if i == 0 {
                    if self.peers.iter().all(|p| p.connected) {
                        self.wire.push(data.to_vec());
                    }
                    if let Some(header) = wire_rtp_header(&data)
                        && (header.payload_type == VP8_PT || header.payload_type == RED_PT)
                        && self.drop_once == Some(header.sequence_number)
                    {
                        self.drop_once = None;
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
                if let RTCMessage::RtpPacket(_, _) = message.message {
                    peer.read_rtp += 1;
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
            wire: Vec::new(),
            drop_once: None,
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
            if world.now.duration_since(start) >= CONNECT_WITHIN {
                bail!("not connected: {:?}", world.peers[0].states);
            }
            let next = world.now + Duration::from_millis(10);
            world.run_until(next)?;
        }
        Ok((world, sender))
    }

    /// Writes a one-packet VP8 frame with sequence number `seq` carrying [`MARKER`].
    fn send(&mut self, sender: RTCRtpSenderId, seq: u16) -> Result<()> {
        let now = self.now;
        let mut rtp_sender = self.peers[0].pc.rtp_sender(sender).expect("sender");
        let ssrc = rtp_sender.get_parameters().encodings[0]
            .rtp_coding_parameters
            .ssrc
            .expect("an SSRC");
        let mut payload = vec![0x10u8];
        payload.extend_from_slice(MARKER);
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
                payload: Bytes::from(payload),
            },
        )?;
        self.pump()?;
        self.run_until(now + Duration::from_millis(33))
    }
}

/// RFC 2198 section 6, RFC 5109 section 11, RFC 4588 section 12: RED packets, the FEC stream
/// and the retransmission stream are protected as the media stream is ("the same security
/// considerations apply"; FEC "SHOULD" be encrypted with the media; RTX cryptography "as
/// strong as" the original's). They leave through the same SRTP context: on the wire, RTX,
/// RED (which carries the FEC) and media packets are all there, and not one datagram holds
/// the application's payload in the clear.
#[test]
fn retransmissions_fec_and_red_are_encrypted_like_the_media() -> Result<()> {
    let (mut world, sender) = World::connected()?;
    world.drop_once = Some(1010);
    for seq in 1000..1030 {
        world.send(sender, seq)?;
    }
    let until = world.now + Duration::from_secs(1);
    world.run_until(until)?;

    let payload_types: HashSet<u8> = world
        .wire
        .iter()
        .filter_map(|datagram| wire_rtp_header(datagram))
        .map(|header| header.payload_type)
        .collect();
    assert!(
        payload_types.contains(&RTX_PT),
        "the lost packet was resent over RTX: {payload_types:?}"
    );
    assert!(
        payload_types.contains(&RED_PT),
        "FEC went out in RED: {payload_types:?}"
    );
    assert!(world.drop_once.is_none(), "the loss happened");
    let clear = world
        .wire
        .iter()
        .filter(|datagram| datagram.windows(MARKER.len()).any(|w| w == MARKER))
        .count();
    assert_eq!(clear, 0, "datagrams with the payload in the clear");
    assert!(world.peers[1].read_rtp >= 29, "{}", world.peers[1].read_rtp);
    Ok(())
}
