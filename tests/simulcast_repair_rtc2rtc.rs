//! Simulcast with RTX between two `rtc` peer connections, in virtual time: the sender offers
//! three layers (`a=rid` / `a=simulcast`, RFC 8851 / RFC 8853) with RTX (RFC 4588) and the
//! MID / RtpStreamId / RepairedRtpStreamId header extensions (RFC 9143 section 15, RFC 8852
//! sections 3.1 and 3.2); the receiver answers. One packet of every layer is lost on the way,
//! and each layer is repaired: the receiver binds every layer and its RTX stream, asks for the
//! lost packet (RFC 4585 section 6.2.1) and gets it back on the layer's own stream. This is
//! what the browser matrix's "simulcast with RTX: every layer is repaired under netem" checks
//! with a browser as the sender.

use anyhow::{Result, bail};
use bytes::Bytes;
use rtc::interceptor::Registry;
use rtc::media_stream::MediaStreamTrack;
use rtc::peer_connection::configuration::RTCConfigurationBuilder;
use rtc::peer_connection::configuration::interceptor_registry::{
    configure_simulcast_extension_headers, register_default_interceptors,
};
use rtc::peer_connection::configuration::media_engine::{
    MIME_TYPE_RTX, MIME_TYPE_VP8, MediaEngine,
};
use rtc::peer_connection::event::RTCPeerConnectionEvent;
use rtc::peer_connection::message::RTCMessage;
use rtc::peer_connection::state::RTCPeerConnectionState;
use rtc::peer_connection::transport::{
    CandidateConfig, CandidateHostConfig, RTCIceCandidate, RTCIceCandidateInit,
};
use rtc::peer_connection::{RTCPeerConnection, RTCPeerConnectionBuilder};
use rtc::rtp_transceiver::RTCRtpSenderId;
use rtc::rtp_transceiver::rtp_sender::{
    RTCPFeedback, RTCRtpCodec, RTCRtpCodecParameters, RTCRtpCodingParameters,
    RTCRtpEncodingParameters, RtpCodecKind,
};
use rtc::sansio::Protocol;
use rtc::shared::{TaggedBytesMut, TransportContext, TransportProtocol};
use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::time::{Duration, Instant};

const CONNECT_WITHIN: Duration = Duration::from_secs(10);
const VP8_PT: u8 = 96;
const RTX_PT: u8 = 97;
const FIRST_SEQ: u16 = 4000;
const RIDS: [&str; 3] = ["q", "h", "f"];

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
    /// The (SSRC, sequence number) of every RTP packet `poll_read` yielded.
    read_rtp: HashSet<(u32, u16)>,
    /// The RTCP packets `poll_read` yielded.
    read_rtcp: Vec<Box<dyn rtc::rtcp::Packet>>,
}

impl Peer {
    /// A peer as the interop peer configures it: VP8 with RTX and NACK, the default
    /// interceptors, and the simulcast header extensions.
    fn new(addr: &str) -> Result<Self> {
        let mut media_engine = MediaEngine::default();
        media_engine.register_codec(
            RTCRtpCodecParameters {
                rtp_codec: codec(
                    MIME_TYPE_VP8,
                    "",
                    vec![RTCPFeedback {
                        typ: "nack".to_owned(),
                        parameter: "".to_owned(),
                    }],
                ),
                payload_type: VP8_PT,
            },
            RtpCodecKind::Video,
        )?;
        media_engine.register_codec(
            RTCRtpCodecParameters {
                rtp_codec: codec(MIME_TYPE_RTX, &format!("apt={VP8_PT}"), vec![]),
                payload_type: RTX_PT,
            },
            RtpCodecKind::Video,
        )?;
        configure_simulcast_extension_headers(&mut media_engine)?;
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
            read_rtp: HashSet::new(),
            read_rtcp: Vec::new(),
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

struct World {
    peers: [Peer; 2],
    now: Instant,
    /// The sender's RTP packets (SSRC, sequence number) dropped once each.
    drop_once: HashSet<(u32, u16)>,
    /// The sender's RTP packets put on the wire, per SSRC.
    sent_by_ssrc: HashMap<u32, usize>,
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
                    && let Some(rtp) = wire_rtp(&data)
                {
                    *self.sent_by_ssrc.entry(rtp.0).or_default() += 1;
                    if self.drop_once.remove(&rtp) {
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
                match message.message {
                    RTCMessage::RtpPacket(_, packet) => {
                        peer.read_rtp
                            .insert((packet.header.ssrc, packet.header.sequence_number));
                    }
                    RTCMessage::RtcpPacket(_, packets) => peer.read_rtcp.extend(packets),
                    _ => {}
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

    /// The offerer sends three simulcast layers; the answerer receives them.
    fn connected() -> Result<(Self, RTCRtpSenderId)> {
        Self::connected_edited(|offer, _| offer.to_owned())
    }

    /// [`Self::connected`], the offer passed through `edit` (with each layer's rid, media SSRC
    /// and RTX SSRC) on its way to the answerer.
    fn connected_edited(
        edit: impl Fn(&str, &[(String, u32, Option<u32>)]) -> String,
    ) -> Result<(Self, RTCRtpSenderId)> {
        let mut world = World {
            peers: [Peer::new("10.0.0.1:5000")?, Peer::new("10.0.0.2:5000")?],
            now: Instant::now(),
            drop_once: HashSet::new(),
            sent_by_ssrc: HashMap::new(),
        };
        let encodings = RIDS
            .iter()
            .enumerate()
            .map(|(i, rid)| RTCRtpEncodingParameters {
                rtp_coding_parameters: RTCRtpCodingParameters {
                    rid: (*rid).to_owned(),
                    ssrc: Some(0x0515_0000 + i as u32),
                    ..Default::default()
                },
                active: true,
                ..Default::default()
            })
            .collect();
        let track = MediaStreamTrack::new(
            "simulcast-stream".to_owned(),
            "simulcast".to_owned(),
            "simulcast".to_owned(),
            RtpCodecKind::Video,
            encodings,
        );
        let sender = world.peers[0].pc.add_track(track)?;

        let now = world.now;
        let offer = world.peers[0].pc.create_offer(None)?;
        world.peers[0]
            .pc
            .set_local_description(now, offer.clone())?;
        // Each layer's rid, media SSRC (the encodings above) and an RTX SSRC for the edit to
        // declare (the engine's simulcast offer names none; Pion's offer names its own).
        let layers: Vec<(String, u32, Option<u32>)> = RIDS
            .iter()
            .enumerate()
            .map(|(i, rid)| {
                (
                    (*rid).to_owned(),
                    0x0515_0000 + i as u32,
                    Some(0x0515_0100 + i as u32),
                )
            })
            .collect();
        let offer =
            rtc::peer_connection::sdp::RTCSessionDescription::offer(edit(&offer.sdp, &layers))?;
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

    /// Each layer's (rid, media SSRC, RTX SSRC), and the negotiated payload type.
    fn layers(&mut self, sender: RTCRtpSenderId) -> (Vec<(String, u32, Option<u32>)>, u8) {
        let mut sender = self.peers[0].pc.rtp_sender(sender).expect("sender");
        let parameters = sender.get_parameters();
        let pt = parameters
            .rtp_parameters
            .codecs
            .iter()
            .find(|c| c.rtp_codec.mime_type.eq_ignore_ascii_case(MIME_TYPE_VP8))
            .expect("VP8 is negotiated")
            .payload_type;
        let layers = parameters
            .encodings
            .iter()
            .map(|e| {
                let coding = &e.rtp_coding_parameters;
                (
                    coding.rid.clone(),
                    coding.ssrc.expect("an SSRC"),
                    coding.rtx.as_ref().map(|rtx| rtx.ssrc),
                )
            })
            .collect();
        (layers, pt)
    }

    /// Writes `packets` RTP packets on every layer from sequence number `first`, 20 ms apart.
    fn send_media(&mut self, sender: RTCRtpSenderId, first: u16, packets: u16) -> Result<()> {
        let (layers, pt) = self.layers(sender);
        for n in 0..packets {
            let now = self.now;
            let sequence_number = first.wrapping_add(n);
            for (_, ssrc, _) in &layers {
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
                                ssrc: *ssrc,
                                marker: true,
                                ..Default::default()
                            },
                            payload: Bytes::from(vec![0x10u8; 200]),
                        },
                    )?;
            }
            self.pump()?;
            self.run_until(now + Duration::from_millis(20))?;
        }
        Ok(())
    }
}

/// RFC 4588 with RFC 8852 section 3.2 and RFC 8853: a packet lost on any simulcast layer is
/// asked for and retransmitted on that layer's RTX stream, and the receiver gets it back on
/// the layer's own stream (the NACK itself is answered inside the sender's interceptors).
#[test]
fn every_simulcast_layer_is_repaired_over_its_rtx_stream() -> Result<()> {
    let (mut world, sender) = World::connected()?;
    let (layers, _) = world.layers(sender);
    assert_eq!(
        RIDS.to_vec(),
        layers
            .iter()
            .map(|(rid, _, _)| rid.as_str())
            .collect::<Vec<_>>(),
        "the answer keeps the three layers"
    );
    for (rid, _, rtx) in &layers {
        assert!(rtx.is_some(), "layer {rid} has an RTX SSRC");
    }
    let lost: Vec<(u32, u16)> = layers
        .iter()
        .enumerate()
        .map(|(i, (_, ssrc, _))| (*ssrc, FIRST_SEQ + 30 + 7 * i as u16))
        .collect();
    world.drop_once = lost.iter().copied().collect();

    world.send_media(sender, FIRST_SEQ, 100)?;
    let until = world.now + Duration::from_secs(2);
    world.run_until(until)?;

    assert!(world.drop_once.is_empty(), "every loss happened");
    for ((rid, ssrc, rtx), (_, seq)) in layers.iter().zip(&lost) {
        let rtx = rtx.expect("checked above");
        assert!(
            world.peers[1].read_rtp.contains(&(*ssrc, FIRST_SEQ + 50)),
            "layer {rid} (ssrc {ssrc}) is received"
        );
        assert!(
            world.sent_by_ssrc.get(&rtx).copied().unwrap_or(0) > 0,
            "layer {rid}'s loss is retransmitted on its RTX ssrc {rtx}: {:?}",
            world.sent_by_ssrc
        );
        assert!(
            world.peers[1].read_rtp.contains(&(*ssrc, *seq)),
            "layer {rid}'s lost packet {seq} comes back on ssrc {ssrc}"
        );
    }
    Ok(())
}

/// Pion (pion/webrtc v4.2.29, train 10's interop matrix) offers simulcast by RID and declares
/// every layer's SSRCs too, libwebrtc's older way: per layer an `a=ssrc-group:FID <media>
/// <rtx>` and `a=ssrc` lines with `cname`, `msid`, `mslabel` and `label`, and an `a=msid` line
/// per layer, before the `a=rid` / `a=simulcast` lines (RFC 8853 section 5.3 lets SSRCs be
/// signalled beside RIDs; RFC 5576 section 4.2 the FID group). The answerer still binds each
/// layer by its RID and receives every layer.
#[test]
fn a_simulcast_offer_that_also_declares_its_layer_ssrcs_like_pion_is_received() -> Result<()> {
    let (mut world, sender) = World::connected_edited(|offer, layers| {
        let mut pion = String::new();
        for (_, media, rtx) in layers {
            let rtx = rtx.expect("each layer has an RTX SSRC");
            pion += &format!("a=ssrc-group:FID {media} {rtx}\r\n");
            for ssrc in [*media, rtx] {
                pion += &format!(
                    "a=ssrc:{ssrc} cname:pion\r\na=ssrc:{ssrc} msid:pion video\r\n\
                     a=ssrc:{ssrc} mslabel:pion\r\na=ssrc:{ssrc} label:video\r\n"
                );
            }
            pion += "a=msid:pion video\r\n";
        }
        let at = offer.find("a=rid:").expect("the offer has rids");
        format!("{}{pion}{}", &offer[..at], &offer[at..])
    })?;
    let (layers, _) = world.layers(sender);
    world.send_media(sender, FIRST_SEQ, 30)?;
    for (rid, ssrc, _) in &layers {
        assert!(
            world.peers[1].read_rtp.contains(&(*ssrc, FIRST_SEQ + 20)),
            "layer {rid} (ssrc {ssrc}) is received: {:?}",
            world.peers[1]
                .read_rtp
                .iter()
                .map(|(s, _)| *s)
                .collect::<HashSet<_>>()
        );
    }
    Ok(())
}
