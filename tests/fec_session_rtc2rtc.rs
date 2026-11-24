//! ULPFEC as a separate stream (RFC 5109 sections 7.2, 14.1 and 14.3), between two `rtci`
//! peers on a simulated UDP network in virtual time.
//!
//! The offerer asks for a FEC session of its own for its video (`add_fec_session`): a second
//! m= section that lists only `ulpfec`, outside the BUNDLE group and so on a transport of its
//! own, grouped with the video section. The answerer takes it
//! (`with_separate_fec_sessions(true)`) or refuses it (the default, RFC 8854 section 5.2).
//! Accepted, the FEC travels between the second pair of addresses, each FEC packet with the
//! SSRC of the media stream it protects, and repairs what the media path lost.

use anyhow::{Context, Result, bail};
use bytes::Bytes;
use rtci::interceptor::{Registry, Slot, UlpfecReceiveBuilder, UlpfecSendBuilder};
use rtci::peer_connection::configuration::RTCConfigurationBuilder;
use rtci::peer_connection::configuration::interceptor_registry::{
    configure_ulpfec_sessions, register_default_interceptors,
};
use rtci::peer_connection::configuration::media_engine::MediaEngine;
use rtci::peer_connection::configuration::setting_engine::SettingEngineBuilder;
use rtci::peer_connection::event::{RTCPeerConnectionEvent, RTCTrackEvent};
use rtci::peer_connection::message::RTCMessage;
use rtci::peer_connection::sdp::RTCSessionDescription;
use rtci::peer_connection::state::RTCPeerConnectionState;
use rtci::peer_connection::transport::{
    CandidateConfig, CandidateHostConfig, RTCIceCandidate, RTCIceCandidateInit,
};
use rtci::peer_connection::{RTCPeerConnection, RTCPeerConnectionBuilder};
use rtci::rtp::header::Header;
use rtci::rtp_transceiver::rtp_sender::{RTCRtpEncodingParameters, RtpCodecKind};
use rtci::rtp_transceiver::{
    RTCFecGroupSemantics, RTCRtpSenderId, RTCRtpTransceiverDirection, RTCRtpTransceiverId,
    RTCRtpTransceiverInit,
};
use rtci::sansio::Protocol;
use rtci::shared::{TaggedBytesMut, TransportContext, TransportProtocol};
use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

const CONNECT_WITHIN: Duration = Duration::from_secs(10);

/// An SRTP packet as it travelled: the RTP header is in the clear (RFC 3711 section 3.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct OnTheWire {
    from: SocketAddr,
    to: SocketAddr,
    ssrc: u32,
    payload_type: u8,
    sequence_number: u16,
    marker: bool,
    lost: bool,
}

struct Peer {
    pc: RTCPeerConnection,
    ip: IpAddr,
    /// The local addresses this peer gathered on, one per transport, in the order of
    /// `ice_transport_sections`.
    addrs: Vec<SocketAddr>,
    /// The mid of the section each address was gathered for.
    mids: Vec<String>,
    connected: bool,
    /// The RTP packets the application was given.
    rtp: Vec<rtci::rtp::Packet>,
    tracks: usize,
}

impl Peer {
    /// A peer with the default interceptors and ULPFEC for FEC sessions; `accept`: whether it
    /// takes an offered FEC session. `fixed_amount`: one FEC packet for each frame whatever
    /// loss is reported, instead of the amount `configure_ulpfec_sessions` has follow the
    /// reported loss (none while no loss is reported: RFC 8854 section 8).
    fn new(ip: &str, accept: bool, fixed_amount: bool) -> Result<Self> {
        let mut media_engine = MediaEngine::default();
        media_engine.register_default_codecs()?;
        let registry = register_default_interceptors(Registry::new(), &mut media_engine)?;
        let registry = if fixed_amount {
            let mut encoder = UlpfecSendBuilder::stream()
                .with_flush_on_marker(true)
                .with_adaptive_rate(false)
                .build();
            let tap = encoder.wire_tap();
            registry
                .with(Slot::FecEncoder, encoder)
                .with(Slot::FecWireImage, tap)
                .with(Slot::FecDecoder, UlpfecReceiveBuilder::sessions().build())
        } else {
            configure_ulpfec_sessions(registry)
        };
        let pc = RTCPeerConnectionBuilder::new()
            .with_configuration(RTCConfigurationBuilder::new().build())
            .with_setting_engine(
                SettingEngineBuilder::new()
                    .with_unique_transport_credentials(true)
                    .with_separate_fec_sessions(accept)
                    .build(),
            )
            .with_media_engine(media_engine)
            .with_interceptor_registry(registry)
            .build(Instant::now())?;
        Ok(Self {
            pc,
            ip: ip.parse()?,
            addrs: vec![],
            mids: vec![],
            connected: false,
            rtp: vec![],
            tracks: 0,
        })
    }

    fn host_candidate(addr: SocketAddr, mid: &str, index: u16) -> Result<RTCIceCandidateInit> {
        let candidate = CandidateHostConfig {
            base_config: CandidateConfig {
                network: "udp".to_owned(),
                address: addr.ip().to_string(),
                port: addr.port(),
                component: 1,
                ..Default::default()
            },
            ..Default::default()
        }
        .new_candidate_host()?;
        let mut init = RTCIceCandidate::from(&candidate).to_json()?;
        init.sdp_mid = Some(mid.to_owned());
        init.sdp_mline_index = Some(index);
        Ok(init)
    }

    /// The address this peer gathered for the transport of the section `mid`.
    fn addr_of(&self, mid: &str) -> Result<SocketAddr> {
        let index = self
            .mids
            .iter()
            .position(|m| m == mid)
            .with_context(|| format!("no transport was gathered for the section {mid}"))?;
        Ok(self.addrs[index])
    }
}

struct World {
    peers: [Peer; 2],
    now: Instant,
    /// Every SRTP packet written, delivered or lost.
    srtp: Vec<OnTheWire>,
    /// The (from, to, SSRC of the first packet's sender) of every SRTCP datagram: the first
    /// eight octets of an SRTCP packet are in the clear (RFC 3711 section 3.4).
    rtcp: Vec<(SocketAddr, SocketAddr, u32)>,
    /// The (from address, sequence number) of RTP packets the network loses.
    lose: HashSet<(SocketAddr, u16)>,
    /// From this address only the first transmission of each packet of this payload type
    /// gets through: retransmissions (RFC 4588, on the RTX payload type or as a repeat) are
    /// lost, so that whatever repairs a loss is FEC.
    only_first_transmissions: Option<(SocketAddr, u8)>,
}

impl World {
    /// The offerer and an answerer that takes an offered FEC session, or not.
    fn new(answerer_accepts: bool) -> Result<Self> {
        Self::with_fec_amount(answerer_accepts, false)
    }

    /// `new`, with a fixed amount of FEC (`Peer::new`) or the amount that follows the loss.
    fn with_fec_amount(answerer_accepts: bool, fixed_amount: bool) -> Result<Self> {
        Ok(Self {
            peers: [
                Peer::new("10.0.0.1", false, fixed_amount)?,
                Peer::new("10.0.0.2", answerer_accepts, fixed_amount)?,
            ],
            now: Instant::now(),
            srtp: vec![],
            rtcp: vec![],
            lose: HashSet::new(),
            only_first_transmissions: None,
        })
    }

    /// Every transport of each peer gathers a host candidate on a port of its own and
    /// trickles it, with its section, to the other peer.
    fn gather(&mut self) -> Result<()> {
        for i in 0..2 {
            let sections = self.peers[i].pc.ice_transport_sections();
            for (k, (mid, index)) in sections.into_iter().enumerate() {
                let addr = SocketAddr::new(self.peers[i].ip, 5000 + k as u16);
                self.peers[i].addrs.push(addr);
                self.peers[i].mids.push(mid.clone());
                let candidate = Peer::host_candidate(addr, &mid, index)?;
                self.peers[i].pc.add_local_candidate(candidate.clone())?;
                self.peers[1 - i].pc.add_remote_candidate(candidate)?;
            }
        }
        Ok(())
    }

    fn step(&mut self) -> Result<bool> {
        let mut in_flight = vec![];
        for peer in self.peers.iter_mut() {
            while let Some(msg) = peer.pc.poll_write() {
                in_flight.push((
                    msg.transport.local_addr,
                    msg.transport.peer_addr,
                    msg.message,
                ));
            }
        }
        let delivered = !in_flight.is_empty();
        for (from, to, data) in in_flight {
            // RFC 7983: a first octet of 128..=191 is RTP or RTCP; RTCP has a packet type of
            // 192..=223 (RFC 5761 section 4).
            let rtp_or_rtcp = data.len() >= 12 && (128..=191).contains(&data[0]);
            if rtp_or_rtcp && (192..=223).contains(&data[1]) {
                let ssrc = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
                self.rtcp.push((from, to, ssrc));
            } else if rtp_or_rtcp {
                let sequence_number = u16::from_be_bytes([data[2], data[3]]);
                let payload_type = data[1] & 0x7F;
                let repair = self
                    .only_first_transmissions
                    .is_some_and(|(media, media_type)| {
                        from == media
                            && (payload_type != media_type
                                || self.srtp.iter().any(|sent| {
                                    sent.from == from
                                        && sent.payload_type == payload_type
                                        && sent.sequence_number == sequence_number
                                }))
                    });
                let lost = repair || self.lose.contains(&(from, sequence_number));
                self.srtp.push(OnTheWire {
                    from,
                    to,
                    ssrc: u32::from_be_bytes([data[8], data[9], data[10], data[11]]),
                    payload_type,
                    sequence_number,
                    marker: data[1] & 0x80 != 0,
                    lost,
                });
                if lost {
                    continue;
                }
            }
            let Some(peer) = self.peers.iter_mut().find(|p| p.addrs.contains(&to)) else {
                continue;
            };
            peer.pc.handle_read(TaggedBytesMut {
                now: self.now,
                transport: TransportContext {
                    local_addr: to,
                    peer_addr: from,
                    ecn: None,
                    transport_protocol: TransportProtocol::UDP,
                },
                message: data,
            })?;
        }
        for peer in self.peers.iter_mut() {
            while let Some(event) = peer.pc.poll_event() {
                match event {
                    RTCPeerConnectionEvent::OnConnectionStateChangeEvent(state) => {
                        if state == RTCPeerConnectionState::Failed {
                            bail!("a peer's connection failed");
                        }
                        peer.connected = state == RTCPeerConnectionState::Connected;
                    }
                    RTCPeerConnectionEvent::OnTrack(RTCTrackEvent::OnOpen(_)) => peer.tracks += 1,
                    _ => {}
                }
            }
            while let Some(message) = peer.pc.poll_read() {
                if let RTCMessage::RtpPacket(_, packet) = message.message {
                    peer.rtp.push(packet);
                }
            }
        }
        Ok(delivered)
    }

    fn run(&mut self, what: &str, done: impl Fn(&[Peer; 2]) -> bool) -> Result<()> {
        let start = self.now;
        loop {
            let delivered = self.step()?;
            if done(&self.peers) {
                return Ok(());
            }
            if delivered {
                continue;
            }
            if self.now.duration_since(start) >= CONNECT_WITHIN {
                bail!("{what}: not done within {CONNECT_WITHIN:?}");
            }
            self.tick(None)?;
        }
    }

    /// Runs for `by` of virtual time, whatever happens.
    fn advance(&mut self, by: Duration) -> Result<()> {
        let until = self.now + by;
        while self.now < until {
            if self.step()? {
                continue;
            }
            self.tick(Some(until))?;
        }
        Ok(())
    }

    fn tick(&mut self, until: Option<Instant>) -> Result<()> {
        let next = self
            .peers
            .iter_mut()
            .filter_map(|p| p.pc.poll_timeout())
            .min()
            .unwrap_or(self.now + Duration::from_millis(50));
        let next = until.map_or(next, |until| next.min(until));
        self.now = next.max(self.now + Duration::from_millis(1));
        for peer in self.peers.iter_mut() {
            peer.pc.handle_timeout(self.now)?;
        }
        Ok(())
    }

    /// The offerer adds a video sender and a FEC session for it, grouped with `semantics`.
    fn add_video_with_fec_session(
        &mut self,
        semantics: RTCFecGroupSemantics,
    ) -> Result<(RTCRtpSenderId, RTCRtpTransceiverId, RTCRtpTransceiverId)> {
        let pc = &mut self.peers[0].pc;
        let video = pc.add_transceiver_from_kind(
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
        let sender = pc
            .rtp_transceiver(video)
            .and_then(|t| t.sender())
            .context("a sendonly transceiver has a sender")?;
        let session = pc.add_fec_session(video, semantics)?;
        Ok((sender, video, session))
    }

    /// One offer from peer 0 and its answer; returns both.
    fn negotiate(&mut self) -> Result<(String, String)> {
        let now = self.now;
        let offer = self.peers[0].pc.create_offer(None)?;
        self.peers[0].pc.set_local_description(now, offer.clone())?;
        self.peers[1]
            .pc
            .set_remote_description(now, RTCSessionDescription::offer(offer.sdp.clone())?)?;
        let answer = self.peers[1].pc.create_answer(None)?;
        self.peers[1]
            .pc
            .set_local_description(now, answer.clone())?;
        self.peers[0]
            .pc
            .set_remote_description(now, answer.clone())?;
        Ok((offer.sdp, answer.sdp))
    }

    fn sender_ssrc(&mut self, sender: RTCRtpSenderId) -> u32 {
        self.peers[0]
            .pc
            .rtp_sender(sender)
            .expect("sender")
            .get_parameters()
            .encodings[0]
            .rtp_coding_parameters
            .ssrc
            .expect("an SSRC")
    }

    fn media_payload_type(&mut self, sender: RTCRtpSenderId) -> u8 {
        self.peers[0]
            .pc
            .rtp_sender(sender)
            .expect("sender")
            .get_parameters()
            .rtp_parameters
            .codecs[0]
            .payload_type
    }

    /// The offerer writes one video packet: `frame` is its timestamp's frame, `last` whether
    /// it ends the frame.
    fn send_video(
        &mut self,
        sender: RTCRtpSenderId,
        sequence_number: u16,
        frame: u32,
        last: bool,
    ) -> Result<()> {
        let now = self.now;
        let header = Header {
            version: 2,
            payload_type: self.media_payload_type(sender),
            sequence_number,
            timestamp: frame * 3000,
            ssrc: self.sender_ssrc(sender),
            marker: last,
            ..Default::default()
        };
        self.peers[0]
            .pc
            .rtp_sender(sender)
            .expect("sender")
            .write_rtp(
                now,
                rtci::rtp::Packet {
                    header,
                    payload: video_payload(sequence_number),
                },
            )?;
        Ok(())
    }
}

/// A payload that differs from packet to packet and in length, so that a rebuilt packet is
/// only right when the FEC really covered it.
fn video_payload(sequence_number: u16) -> Bytes {
    let length = 200 + usize::from(sequence_number % 7) * 31;
    Bytes::from(
        (0..length)
            .map(|index| (index as u8).wrapping_mul(17) ^ (sequence_number as u8).wrapping_mul(3))
            .collect::<Vec<u8>>(),
    )
}

/// The m= sections of a description, each with its lines.
fn sections(sdp: &str) -> Vec<Vec<&str>> {
    let mut sections: Vec<Vec<&str>> = vec![];
    for line in sdp.lines() {
        if line.starts_with("m=") {
            sections.push(vec![]);
        }
        if let Some(section) = sections.last_mut() {
            section.push(line);
        }
    }
    sections
}

fn session_lines(sdp: &str) -> Vec<&str> {
    sdp.lines()
        .take_while(|line| !line.starts_with("m="))
        .collect()
}

fn value<'a>(section: &[&'a str], attribute: &str) -> Option<&'a str> {
    section
        .iter()
        .find_map(|line| line.strip_prefix(&format!("a={attribute}:")))
}

/// RFC 5109 section 14.1: the FEC stream has "their m line", a dynamic payload type bound by
/// an rtpmap to "ulpfec", and is grouped with the media section; it is not multiplexed with
/// the media in one RTP session, so it is outside the BUNDLE group, with transport parameters
/// of its own. Section 14.3: the answerer accepts "by including the same grouping in the
/// answer". Both group semantics (RFC 5956 `FEC-FR`, the default; RFC 4756 `FEC`).
#[test]
fn a_fec_session_is_offered_as_a_section_of_its_own_and_accepted_with_the_same_grouping()
-> Result<()> {
    for (semantics, token) in [
        (RTCFecGroupSemantics::FecFr, "FEC-FR"),
        (RTCFecGroupSemantics::Fec, "FEC"),
    ] {
        let mut world = World::new(true)?;
        let (_, video, session) = world.add_video_with_fec_session(semantics)?;
        assert_eq!(world.peers[0].pc.fec_session_of(video), Some(session));
        assert_eq!(world.peers[0].pc.fec_session_protects(session), Some(video));
        let (offer, answer) = world.negotiate()?;

        for (what, sdp, direction) in [
            ("offer", &offer, "a=sendonly"),
            ("answer", &answer, "a=recvonly"),
        ] {
            let media = sections(sdp);
            assert_eq!(media.len(), 2, "{what}: {sdp}");
            let (video, fec) = (&media[0], &media[1]);
            let (video_mid, fec_mid) = (
                value(video, "mid").context("mid")?,
                value(fec, "mid").context("mid")?,
            );
            let session = session_lines(sdp);
            // Grouped, the media section first.
            assert!(
                session.contains(&format!("a=group:{token} {video_mid} {fec_mid}").as_str()),
                "{what}: {sdp}"
            );
            // A second RTP session: not in the BUNDLE group, and never bundle-only.
            assert!(
                session.contains(&format!("a=group:BUNDLE {video_mid}").as_str()),
                "{what}: {sdp}"
            );
            assert!(!fec.contains(&"a=bundle-only"), "{what}: {sdp}");
            // Its own m= line: one dynamic payload type, bound to ulpfec at the media's rate.
            assert_eq!(fec[0], "m=video 9 UDP/TLS/RTP/SAVPF 127", "{what}: {sdp}");
            assert_eq!(
                value(fec, "rtpmap"),
                Some("127 ulpfec/90000"),
                "{what}: {sdp}"
            );
            assert_eq!(
                fec.iter().filter(|l| l.starts_with("a=rtpmap:")).count(),
                1,
                "{what}: {sdp}"
            );
            assert!(fec.contains(&direction), "{what}: {sdp}");
            assert!(fec.contains(&"a=rtcp-mux"), "{what}: {sdp}");
            // Transport parameters of its own.
            let ufrag = value(fec, "ice-ufrag").context("the FEC section has ICE credentials")?;
            assert_ne!(Some(ufrag), value(video, "ice-ufrag"), "{what}: {sdp}");
            assert!(value(fec, "fingerprint").is_some(), "{what}: {sdp}");
            assert!(value(fec, "setup").is_some(), "{what}: {sdp}");
            // It describes no source: the FEC stream has the media stream's SSRC.
            assert!(
                !fec.iter()
                    .any(|l| l.starts_with("a=ssrc") || l.starts_with("a=msid")),
                "{what}: {sdp}"
            );
            // The media section is an ordinary one, with no ulpfec format of its own.
            assert!(!video.iter().any(|l| l.contains("ulpfec")), "{what}: {sdp}");
        }

        // The answerer has the session as a transceiver that protects the video's.
        let answerer = &world.peers[1].pc;
        assert_eq!(answerer.fec_session_of(0), Some(1));
        assert_eq!(answerer.fec_session_protects(1), Some(0));
        // Two transports on each side.
        assert_eq!(world.peers[0].pc.ice_transport_sections().len(), 2);
        assert_eq!(world.peers[1].pc.ice_transport_sections().len(), 2);
        // Nothing left to negotiate, and a second offer keeps the shape.
        let (again, answered_again) = world.negotiate()?;
        for sdp in [&again, &answered_again] {
            assert!(
                session_lines(sdp)
                    .iter()
                    .any(|l| l.starts_with(&format!("a=group:{token} "))),
                "{sdp}"
            );
            assert_eq!(
                sections(sdp)[1][0],
                "m=video 9 UDP/TLS/RTP/SAVPF 127",
                "{sdp}"
            );
        }
    }
    Ok(())
}

/// RFC 8854 section 5.2: "Answerers SHOULD reject any FEC-only "m=" lines, unless they
/// specifically know how to handle such a thing"; RFC 5109 section 14.3: "the answerer MAY
/// refuse the separate FEC session by setting the port to 0, and remove the "a=group"
/// attribute", which "does not prevent the media sessions from being accepted and used
/// without FEC". The default answerer does that to this engine's own offer, and the offerer
/// goes on without FEC.
#[test]
fn by_default_an_offered_fec_session_is_refused_and_the_media_goes_on_without_fec() -> Result<()> {
    let mut world = World::new(false)?;
    let (sender, video, _) = world.add_video_with_fec_session(RTCFecGroupSemantics::FecFr)?;
    let (offer, answer) = world.negotiate()?;
    assert!(offer.contains("a=group:FEC-FR "), "{offer}");
    let media = sections(&answer);
    assert_eq!(media.len(), 2, "{answer}");
    assert!(media[0][0].starts_with("m=video 9 "), "{answer}");
    assert!(
        media[1][0].starts_with("m=video 0 "),
        "the FEC section is refused: {answer}"
    );
    assert!(!answer.contains("a=group:FEC"), "{answer}");
    assert_eq!(
        world.peers[0].pc.fec_session_of(video),
        None,
        "the refused session's transceiver is stopped"
    );

    world.gather()?;
    world.run("connect", |p| p[0].connected && p[1].connected)?;
    let ssrc = world.sender_ssrc(sender);
    let media_payload_type = world.media_payload_type(sender);
    for sequence_number in 0..10u16 {
        world.send_video(
            sender,
            sequence_number,
            u32::from(sequence_number / 5),
            sequence_number % 5 == 4,
        )?;
    }
    world.advance(Duration::from_millis(500))?;
    assert_eq!(world.peers[1].rtp.len(), 10);
    // Everything travels between the one pair of addresses, and none of it is FEC. (The
    // stream's RTX flow may carry padding there: bandwidth probes.)
    let media_from = world.peers[0].addrs[0];
    assert_eq!(world.peers[0].addrs.len(), 1, "one transport is left");
    assert!(
        world
            .srtp
            .iter()
            .all(|packet| packet.from == media_from && packet.payload_type != 127),
        "no FEC leaves: {:?}",
        world.srtp
    );
    assert_eq!(
        world
            .srtp
            .iter()
            .filter(|packet| packet.ssrc == ssrc && packet.payload_type == media_payload_type)
            .count(),
        10
    );
    Ok(())
}

/// RFC 5109 section 7.2 on the wire: the FEC packets travel between the FEC section's pair of
/// addresses with "the same [SSRC] as the SSRC value of the media stream" they protect, the
/// FEC section's payload type, the marker 0 and sequence numbers of their own that count up
/// by one; the media stream keeps its transport and its sequence numbers. Section 9: a media
/// packet the media path lost is rebuilt from the FEC of the other transport and delivered.
/// The FEC session is an RTP session with RTCP of its own, under the same SSRC.
#[test]
fn the_fec_travels_in_its_own_session_under_the_media_ssrc_and_repairs_a_loss() -> Result<()> {
    let mut world = World::with_fec_amount(true, true)?;
    let (sender, _, _) = world.add_video_with_fec_session(RTCFecGroupSemantics::FecFr)?;
    let (offer, _) = world.negotiate()?;
    let mids: Vec<String> = sections(&offer)
        .iter()
        .filter_map(|section| value(section, "mid").map(str::to_owned))
        .collect();
    world.gather()?;
    world.run("connect", |p| p[0].connected && p[1].connected)?;
    let media_from = world.peers[0].addr_of(&mids[0])?;
    let fec_from = world.peers[0].addr_of(&mids[1])?;
    let fec_to = world.peers[1].addr_of(&mids[1])?;
    assert_ne!(media_from, fec_from);

    let ssrc = world.sender_ssrc(sender);
    let media_payload_type = world.media_payload_type(sender);
    // Four frames of five packets; the network loses one packet of each of the first three,
    // and every retransmission, so that only FEC can bring them back.
    let lost = [1u16, 8, 14];
    for sequence_number in lost {
        world.lose.insert((media_from, sequence_number));
    }
    world.only_first_transmissions = Some((media_from, media_payload_type));
    for sequence_number in 0..20u16 {
        world.send_video(
            sender,
            sequence_number,
            u32::from(sequence_number / 5),
            sequence_number % 5 == 4,
        )?;
        world.advance(Duration::from_millis(2))?;
    }
    world.advance(Duration::from_millis(300))?;

    // The media: on its own transport, every sequence number once, three of them lost.
    let media: Vec<&OnTheWire> = world
        .srtp
        .iter()
        .filter(|packet| packet.from == media_from && packet.payload_type == media_payload_type)
        .collect();
    let first_pass: Vec<u16> = media.iter().map(|p| p.sequence_number).take(20).collect();
    assert_eq!(
        first_pass,
        (0..20).collect::<Vec<u16>>(),
        "{:?}",
        world.srtp
    );
    assert!(media.iter().all(|packet| packet.ssrc == ssrc));
    assert_eq!(
        media.iter().filter(|p| !p.lost).count(),
        17,
        "seventeen media packets arrived: {:?}",
        world.srtp
    );

    // The FEC: on the FEC section's transport and nowhere else.
    let fec: Vec<&OnTheWire> = world
        .srtp
        .iter()
        .filter(|packet| packet.from == fec_from)
        .collect();
    assert_eq!(
        fec.len(),
        4,
        "one FEC packet for each frame: {:?}",
        world.srtp
    );
    for packet in &fec {
        assert_eq!(packet.to, fec_to);
        assert_eq!(
            packet.ssrc, ssrc,
            "the SSRC of the media stream it protects"
        );
        assert_eq!(packet.payload_type, 127, "the FEC section's payload type");
        assert!(!packet.marker, "the marker is 0");
    }
    for pair in fec.windows(2) {
        assert_eq!(
            pair[1].sequence_number,
            pair[0].sequence_number.wrapping_add(1),
            "one higher than the FEC packet before"
        );
    }
    assert!(
        world
            .srtp
            .iter()
            .filter(|packet| packet.from == media_from)
            .all(|packet| packet.payload_type != 127),
        "no FEC in the media's session: {:?}",
        world.srtp
    );

    // What the receiving application got: every packet of the three frames that lost one,
    // the lost ones rebuilt, octet for octet.
    let received = &world.peers[1].rtp;
    for sequence_number in 0..15u16 {
        let packet = received
            .iter()
            .find(|packet| packet.header.sequence_number == sequence_number)
            .with_context(|| format!("packet {sequence_number} was not delivered"))?;
        assert_eq!(packet.header.ssrc, ssrc);
        assert_eq!(packet.header.payload_type, media_payload_type);
        assert_eq!(packet.payload, video_payload(sequence_number));
    }
    assert!(
        received
            .iter()
            .all(|packet| packet.header.payload_type != 127),
        "FEC is not delivered to the application"
    );
    assert!(
        received.iter().all(|packet| packet.header.ssrc == ssrc),
        "nor anything under another SSRC"
    );
    assert_eq!(
        world.peers[1].tracks, 1,
        "one track: the FEC session has none"
    );

    // The FEC session's RTCP: its sender reports are the media SSRC's, on the FEC transport.
    world.advance(Duration::from_secs(3))?;
    assert!(
        world
            .rtcp
            .iter()
            .any(|(from, to, sender)| *from == fec_from && *to == fec_to && *sender == ssrc),
        "RTCP of the FEC session under the media SSRC: {:?}",
        world.rtcp
    );
    Ok(())
}

/// The chain `configure_ulpfec_sessions` builds, between two peers: the amount of FEC follows
/// the loss the receiver reports (RFC 8854 section 8: "SHOULD only transmit the amount of FEC
/// needed to protect against the observed packet loss"; RFC 5109 section 12). While the
/// receiver reports no loss, no FEC leaves; once its reports show loss, FEC travels in the FEC
/// session and repairs what is lost from then on.
#[test]
fn with_the_default_helper_the_amount_of_fec_follows_the_reported_loss() -> Result<()> {
    let mut world = World::new(true)?;
    let (sender, _, _) = world.add_video_with_fec_session(RTCFecGroupSemantics::FecFr)?;
    let (offer, _) = world.negotiate()?;
    let mids: Vec<String> = sections(&offer)
        .iter()
        .filter_map(|section| value(section, "mid").map(str::to_owned))
        .collect();
    world.gather()?;
    world.run("connect", |p| p[0].connected && p[1].connected)?;
    let media_from = world.peers[0].addr_of(&mids[0])?;
    let fec_from = world.peers[0].addr_of(&mids[1])?;
    let ssrc = world.sender_ssrc(sender);
    let media_payload_type = world.media_payload_type(sender);
    world.only_first_transmissions = Some((media_from, media_payload_type));

    // Thirty frames a second of five packets. Five seconds without loss, then ten seconds in
    // which the network loses the third packet of every other frame (a tenth of the packets)
    // and every retransmission.
    const QUIET: u16 = 150;
    const FRAMES: u16 = 450;
    let mut fec_by_frame = vec![0usize; usize::from(FRAMES)];
    for frame in 0..FRAMES {
        if frame >= QUIET && frame % 2 == 0 {
            world.lose.insert((media_from, frame * 5 + 2));
        }
        let before = world.srtp.iter().filter(|p| p.from == fec_from).count();
        for index in 0..5u16 {
            world.send_video(sender, frame * 5 + index, u32::from(frame), index == 4)?;
        }
        world.advance(Duration::from_millis(33))?;
        fec_by_frame[usize::from(frame)] =
            world.srtp.iter().filter(|p| p.from == fec_from).count() - before;
    }
    world.advance(Duration::from_millis(500))?;

    // No loss reported: no FEC, in the last second before the loss began.
    assert_eq!(
        fec_by_frame[usize::from(QUIET) - 30..usize::from(QUIET)]
            .iter()
            .sum::<usize>(),
        0,
        "FEC that helps nothing is not sent: {fec_by_frame:?}"
    );
    // Loss reported: FEC, for every frame of the last second.
    assert!(
        fec_by_frame[usize::from(FRAMES) - 30..]
            .iter()
            .all(|sent| *sent >= 1),
        "FEC for each frame once the loss is known: {fec_by_frame:?}"
    );
    let fec: Vec<&OnTheWire> = world
        .srtp
        .iter()
        .filter(|packet| packet.from == fec_from)
        .collect();
    assert!(
        fec.iter()
            .all(|packet| packet.ssrc == ssrc && packet.payload_type == 127),
        "{fec:?}"
    );
    assert!(
        world
            .srtp
            .iter()
            .filter(|packet| packet.from == media_from)
            .all(|packet| packet.payload_type != 127),
        "no FEC in the media's session"
    );
    // The last second: every frame complete, the lost packets rebuilt octet for octet.
    let received = &world.peers[1].rtp;
    for frame in FRAMES - 30..FRAMES {
        for index in 0..5u16 {
            let sequence_number = frame * 5 + index;
            let packet = received
                .iter()
                .find(|packet| packet.header.sequence_number == sequence_number)
                .with_context(|| format!("packet {sequence_number} was not delivered"))?;
            assert_eq!(packet.payload, video_payload(sequence_number));
        }
    }
    Ok(())
}
