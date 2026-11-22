//! The RTCP session between two `rtc` peer connections, in virtual time: one CNAME per
//! connection for every SSRC it sends from (RFC 7022, RFC 8834 4.9, RFC 4588 5.2), feedback
//! from the connection's own SSRC in a compound packet (RFC 4585 3.1, RFC 8108 5.4.1), RTCP
//! kept to a few packets a second (RFC 3550 6.2), and BYE on close (RFC 3550 6.6).

use anyhow::{Result, bail};
use bytes::Bytes;
use rtc::interceptor::Registry;
use rtc::peer_connection::configuration::RTCConfigurationBuilder;
use rtc::peer_connection::configuration::interceptor_registry::register_default_interceptors;
use rtc::peer_connection::configuration::media_engine::{
    MIME_TYPE_RTX, MIME_TYPE_VP8, MediaEngine,
};
use rtc::peer_connection::event::RTCPeerConnectionEvent;
use rtc::peer_connection::event::RTCTrackEvent;
use rtc::peer_connection::message::RTCMessage;
use rtc::peer_connection::state::RTCPeerConnectionState;
use rtc::peer_connection::transport::{
    CandidateConfig, CandidateHostConfig, RTCIceCandidate, RTCIceCandidateInit,
};
use rtc::peer_connection::{RTCPeerConnection, RTCPeerConnectionBuilder};
use rtc::rtcp::payload_feedbacks::picture_loss_indication::PictureLossIndication;
use rtc::rtp_transceiver::rtp_sender::{
    RTCRtpCodec, RTCRtpCodecParameters, RTCRtpEncodingParameters, RtpCodecKind,
};
use rtc::rtp_transceiver::{
    RTCRtpReceiverId, RTCRtpSenderId, RTCRtpTransceiverDirection, RTCRtpTransceiverInit,
};
use rtc::sansio::Protocol;
use rtc::shared::{TaggedBytesMut, TransportContext, TransportProtocol};
use std::net::SocketAddr;
use std::time::{Duration, Instant};

const CONNECT_WITHIN: Duration = Duration::from_secs(10);
const VP8_PT: u8 = 96;
const RTX_PT: u8 = 97;
const FIRST_SEQ: u16 = 4000;

fn codec(mime_type: &str, sdp_fmtp_line: &str) -> RTCRtpCodec {
    RTCRtpCodec {
        mime_type: mime_type.to_owned(),
        clock_rate: 90000,
        channels: 0,
        sdp_fmtp_line: sdp_fmtp_line.to_owned(),
        rtcp_feedback: vec![],
    }
}

struct Peer {
    pc: RTCPeerConnection,
    addr: SocketAddr,
    connected: bool,
    states: Vec<RTCPeerConnectionState>,
    /// The receivers of the tracks that opened.
    opened: Vec<RTCRtpReceiverId>,
    /// How many tracks closed.
    closed: usize,
    /// The RTCP packets `poll_read` yielded.
    read_rtcp: Vec<Box<dyn rtc::rtcp::Packet>>,
    /// The RTCP datagrams this peer put on the wire.
    rtcp_datagrams: usize,
}

impl Peer {
    fn new(addr: &str) -> Result<Self> {
        let mut media_engine = MediaEngine::default();
        media_engine.register_codec(
            RTCRtpCodecParameters {
                rtp_codec: codec(MIME_TYPE_VP8, ""),
                payload_type: VP8_PT,
            },
            RtpCodecKind::Video,
        )?;
        media_engine.register_codec(
            RTCRtpCodecParameters {
                rtp_codec: codec(MIME_TYPE_RTX, &format!("apt={VP8_PT}")),
                payload_type: RTX_PT,
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
            opened: Vec::new(),
            closed: 0,
            read_rtcp: Vec::new(),
            rtcp_datagrams: 0,
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

/// The SSRC and sequence number of an SRTP packet on the wire, or `None` for anything else.
fn wire_rtp(datagram: &[u8]) -> Option<(u32, u16)> {
    if datagram.len() < 12 || datagram[0] >> 6 != 2 || (192..=223).contains(&datagram[1]) {
        return None;
    }
    let seq = u16::from_be_bytes([datagram[2], datagram[3]]);
    let ssrc = u32::from_be_bytes([datagram[8], datagram[9], datagram[10], datagram[11]]);
    Some((ssrc, seq))
}

/// Whether a datagram is SRTCP (RFC 5761: version 2 and a packet type of 192 to 223).
fn wire_rtcp(datagram: &[u8]) -> bool {
    datagram.len() >= 8 && datagram[0] >> 6 == 2 && (192..=223).contains(&datagram[1])
}

struct World {
    peers: [Peer; 2],
    now: Instant,
    /// Drop the sender's RTP packet with this SSRC and sequence number, once.
    drop_once: Option<(u32, u16)>,
}

impl World {
    fn pump(&mut self) -> Result<()> {
        loop {
            let mut in_flight = Vec::new();
            for (i, peer) in self.peers.iter_mut().enumerate() {
                while let Some(msg) = peer.pc.poll_write() {
                    if wire_rtcp(&msg.message) {
                        peer.rtcp_datagrams += 1;
                    }
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
                    && let Some(rtp) = wire_rtp(&data)
                    && self.drop_once == Some(rtp)
                {
                    self.drop_once = None;
                    continue;
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
                match event {
                    RTCPeerConnectionEvent::OnConnectionStateChangeEvent(state) => {
                        if state == RTCPeerConnectionState::Failed {
                            bail!("a peer's connection failed: {:?}", peer.states);
                        }
                        peer.connected = state == RTCPeerConnectionState::Connected;
                        peer.states.push(state);
                    }
                    RTCPeerConnectionEvent::OnTrack(RTCTrackEvent::OnOpen(init)) => {
                        peer.opened.push(init.receiver_id);
                    }
                    RTCPeerConnectionEvent::OnTrack(RTCTrackEvent::OnClose(_)) => {
                        peer.closed += 1;
                    }
                    _ => {}
                }
            }
            while let Some(message) = peer.pc.poll_read() {
                if let RTCMessage::RtcpPacket(_, packets) = message.message {
                    peer.read_rtcp.extend(packets);
                }
            }
        }
        Ok(())
    }

    /// Moves virtual time to `until`, firing every deadline on the way.
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

    /// The offerer sends video; the answerer receives it. Connected over host candidates.
    fn connected() -> Result<(Self, RTCRtpSenderId)> {
        let mut world = World {
            peers: [Peer::new("10.0.0.1:5000")?, Peer::new("10.0.0.2:5000")?],
            now: Instant::now(),
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
            let next = world
                .peers
                .iter_mut()
                .filter_map(|p| p.pc.poll_timeout())
                .min()
                .unwrap_or(world.now);
            world.run_until(next.max(world.now + Duration::from_millis(1)))?;
        }
        Ok((world, sender))
    }

    /// The sender's (media SSRC, RTX SSRC, negotiated payload type).
    fn sender_stream(&mut self, sender: RTCRtpSenderId) -> (u32, Option<u32>, u8) {
        let mut sender = self.peers[0].pc.rtp_sender(sender).expect("sender");
        let parameters = sender.get_parameters();
        let encoding = &parameters.encodings[0];
        let pt = parameters
            .rtp_parameters
            .codecs
            .first()
            .expect("a negotiated codec")
            .payload_type;
        (
            encoding.rtp_coding_parameters.ssrc.expect("an SSRC"),
            encoding
                .rtp_coding_parameters
                .rtx
                .as_ref()
                .map(|rtx| rtx.ssrc),
            pt,
        )
    }

    /// Writes `packets` RTP packets from sequence number `first`, 20 ms apart.
    fn send_media(&mut self, sender: RTCRtpSenderId, first: u16, packets: u16) -> Result<()> {
        let (ssrc, _, pt) = self.sender_stream(sender);
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
                            timestamp: u32::from(sequence_number) * 1800,
                            ssrc,
                            marker: true,
                            ..Default::default()
                        },
                        payload: Bytes::from(vec![0x10u8; 200]),
                    },
                )?;
            self.pump()?;
            self.run_until(now + Duration::from_millis(20))?;
        }
        Ok(())
    }
}

/// RFC 7022 4.2 / RFC 8834 4.9: each connection has one CNAME of 96 random bits; the receiver
/// learns it for the sender's media SSRC from its SDES, and, once a retransmission has been
/// sent, for the RTX SSRC too (RFC 4588 5.2: the same CNAME, and section 6.1: the RTX stream
/// sends its own sender reports).
#[test]
fn the_receiver_learns_one_cname_for_the_media_and_the_rtx_ssrc() -> Result<()> {
    let (mut world, sender) = World::connected()?;
    let (ssrc, rtx_ssrc, _) = world.sender_stream(sender);
    let rtx_ssrc = rtx_ssrc.expect("RTX is negotiated");
    let cname = world.peers[0].pc.rtcp_cname().to_owned();
    assert_eq!(16, cname.len());
    assert_ne!(cname, world.peers[1].pc.rtcp_cname());

    // One packet is lost on the way: the receiver asks for it, the sender answers over RTX.
    world.drop_once = Some((ssrc, FIRST_SEQ + 20));
    world.send_media(sender, FIRST_SEQ, 150)?;
    let until = world.now + Duration::from_secs(2);
    world.run_until(until)?;

    assert_eq!(
        Some(cname.as_str()),
        world.peers[1].pc.remote_rtcp_cname(ssrc)
    );
    assert_eq!(
        Some(cname.as_str()),
        world.peers[1].pc.remote_rtcp_cname(rtx_ssrc),
        "the RTX SSRC is described with the same CNAME"
    );
    Ok(())
}

/// RFC 4585 3.1, RFC 8108 5.4.1: a PLI the receiving application writes with no packet sender
/// reaches the sending application from the receiver's own SSRC, which is not zero.
#[test]
fn a_pli_arrives_from_the_receivers_own_ssrc() -> Result<()> {
    let (mut world, sender) = World::connected()?;
    let (ssrc, _, _) = world.sender_stream(sender);
    world.send_media(sender, FIRST_SEQ, 25)?;
    let receiver = *world.peers[1].opened.first().expect("the track opened");

    let now = world.now;
    world.peers[1]
        .pc
        .rtp_receiver(receiver)
        .expect("receiver")
        .write_rtcp(
            now,
            vec![Box::new(PictureLossIndication {
                sender_ssrc: 0,
                media_ssrc: ssrc,
            })],
        )?;
    world.pump()?;
    // RFC 4585 section 3.5.2: the PLI leaves as an Early packet, or, when an Early packet
    // (a NACK, say) already went out since the last Regular one (`allow_early` is false until
    // then, and that Regular packet is put off to `tp + 2 * T_rr`), with the next Regular
    // packet, a randomised interval away. Either way it arrives, once.
    let is_pli =
        |packet: &Box<dyn rtc::rtcp::Packet>| packet.as_any().is::<PictureLossIndication>();
    let deadline = now + Duration::from_secs(20);
    while world.now < deadline && !world.peers[0].read_rtcp.iter().any(is_pli) {
        let next = world.now + Duration::from_millis(100);
        world.run_until(next)?;
    }
    let settle = world.now + Duration::from_millis(500);
    world.run_until(settle)?;

    let plis: Vec<&PictureLossIndication> = world.peers[0]
        .read_rtcp
        .iter()
        .filter_map(|packet| packet.as_any().downcast_ref::<PictureLossIndication>())
        .collect();
    assert_eq!(1, plis.len(), "{:?}", world.peers[0].read_rtcp);
    assert_eq!(ssrc, plis[0].media_ssrc);
    assert_ne!(0, plis[0].sender_ssrc);
    assert_ne!(ssrc, plis[0].sender_ssrc);
    Ok(())
}

/// RFC 3550 6.2: RTCP stays a small share of the session: a few compound packets a second
/// from each side while media and feedback flow, not one per stream per interceptor.
#[test]
fn rtcp_is_a_few_packets_a_second() -> Result<()> {
    let (mut world, sender) = World::connected()?;
    for peer in world.peers.iter_mut() {
        peer.rtcp_datagrams = 0;
    }
    // Five seconds of media.
    world.send_media(sender, FIRST_SEQ, 250)?;

    for (name, peer) in ["sender", "receiver"].iter().zip(&world.peers) {
        println!(
            "the {name} sent {} RTCP datagrams in five seconds",
            peer.rtcp_datagrams
        );
        assert!(
            (3..=80).contains(&peer.rtcp_datagrams),
            "the {name} sent {} RTCP datagrams in five seconds",
            peer.rtcp_datagrams
        );
    }
    Ok(())
}

/// RFC 3550 6.6: closing a connection says BYE for its SSRCs, and the peer's track ends.
#[test]
fn closing_the_sender_ends_the_receivers_track() -> Result<()> {
    let (mut world, sender) = World::connected()?;
    world.send_media(sender, FIRST_SEQ, 50)?;
    assert_eq!(1, world.peers[1].opened.len());
    assert_eq!(0, world.peers[1].closed);

    world.peers[0].pc.close()?;
    world.pump()?;

    assert_eq!(1, world.peers[1].closed, "the BYE ended the remote track");
    Ok(())
}

/// RFC 9143 section 15: "The RTCP MID SDES item SHOULD be sent in the first few RTCP packets
/// after joining the session and SHOULD be sent regularly thereafter": the receiver reads the
/// sender's media SSRC described with the mid of its m= section, in each SDES of the sender.
#[test]
fn the_sender_describes_its_ssrc_with_the_mid_of_its_section() -> Result<()> {
    use rtc::rtcp::source_description::{SdesType, SourceDescription};

    let (mut world, sender) = World::connected()?;
    let (ssrc, _, _) = world.sender_stream(sender);
    let sdp = world.peers[0]
        .pc
        .local_description()
        .expect("a local description")
        .sdp
        .clone();
    let mid = sdp
        .lines()
        .find_map(|line| line.strip_prefix("a=mid:"))
        .expect("a mid")
        .trim()
        .to_owned();

    world.send_media(sender, FIRST_SEQ, 100)?;
    let until = world.now + Duration::from_secs(3);
    world.run_until(until)?;

    let described: Vec<Option<String>> = world.peers[1]
        .read_rtcp
        .iter()
        .filter_map(|packet| packet.as_any().downcast_ref::<SourceDescription>())
        .flat_map(|sdes| &sdes.chunks)
        .filter(|chunk| chunk.source == ssrc)
        .map(|chunk| {
            chunk
                .items
                .iter()
                .find(|item| item.sdes_type == SdesType::SdesMid)
                .map(|item| String::from_utf8_lossy(&item.text).into_owned())
        })
        .collect();
    assert!(!described.is_empty(), "the sender's SSRC is described");
    assert!(
        described
            .iter()
            .all(|item| item.as_deref() == Some(mid.as_str())),
        "every SDES chunk of the SSRC names mid {mid}: {described:?}"
    );
    Ok(())
}
