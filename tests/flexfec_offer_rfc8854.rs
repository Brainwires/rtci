//! RFC 8854 section 5.2 against RFC 8627 section 1.1.7 (audit row RFC8854-5.2-1, `conflict`).
//!
//! RFC 8854 section 5.2: support for an SSRC-multiplexed FlexFEC stream "SHOULD be indicated by
//! including video/flexfec (described in [RFC8627], Section 5.1.2) as an additional supported
//! media type for the associated "m=" section in the SDP offer". RFC 8627 section 1.1.7: "If a
//! peer supporting both FLEX FEC and other RTP retransmission methods (see [RFC4588]) receives
//! an Offer including both FLEX FEC and another RTP retransmission method, it MUST respond with
//! an Answer containing only FLEX FEC." With `video/flexfec` in every offer, two default peers
//! would answer each other without RTX. So the default does not offer it and keeps RTX; RFC
//! 8854's form is `DefaultInterceptorOptions::video_flexfec` (`configure_video_flexfec`), on in
//! the `StrictRfc` profile. Both forms are tested here, the setting end to end.

use anyhow::{Context, Result, bail};
use bytes::Bytes;
use rtci::interceptor::Registry;
use rtci::peer_connection::configuration::RTCConfigurationBuilder;
use rtci::peer_connection::configuration::behaviour_profile::BehaviourProfile;
use rtci::peer_connection::configuration::interceptor_registry::{
    DefaultInterceptorOptions, FLEXFEC_DECODER_SLOT, FLEXFEC_ENCODER_SLOT, FLEXFEC_WIRE_IMAGE_SLOT,
    VIDEO_FLEXFEC_PAYLOAD_TYPE, register_default_interceptors,
    register_default_interceptors_with_options,
};
use rtci::peer_connection::configuration::media_engine::MediaEngine;
use rtci::peer_connection::event::RTCPeerConnectionEvent;
use rtci::peer_connection::message::RTCMessage;
use rtci::peer_connection::state::RTCPeerConnectionState;
use rtci::peer_connection::transport::{
    CandidateConfig, CandidateHostConfig, RTCIceCandidate, RTCIceCandidateInit,
};
use rtci::peer_connection::{RTCPeerConnection, RTCPeerConnectionBuilder};
use rtci::rtp::header::Header;
use rtci::rtp_transceiver::RTCRtpSenderId;
use rtci::rtp_transceiver::rtp_sender::{RTCRtpEncodingParameters, RtpCodecKind};
use rtci::rtp_transceiver::{RTCRtpTransceiverDirection, RTCRtpTransceiverInit};
use rtci::sansio::Protocol;
use rtci::shared::marshal::Unmarshal;
use rtci::shared::{TaggedBytesMut, TransportContext, TransportProtocol};
use std::collections::HashSet;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

const CONNECT_WITHIN: Duration = Duration::from_secs(10);

/// The lines of the video section of `sdp`.
fn video_section(sdp: &str) -> Vec<String> {
    sdp.split("\r\nm=")
        .find(|section| section.starts_with("video"))
        .expect("a video section")
        .split("\r\n")
        .map(str::to_owned)
        .collect()
}

/// The encoding names the section's `a=rtpmap` lines bind (`flexfec/90000`, `rtx/90000`, ...).
fn encodings(section: &[String]) -> Vec<String> {
    section
        .iter()
        .filter_map(|line| line.strip_prefix("a=rtpmap:"))
        .filter_map(|value| {
            value
                .split_once(' ')
                .map(|(_, encoding)| encoding.to_owned())
        })
        .collect()
}

/// A peer with the default codecs and the default interceptors as `options` sets them, and
/// whether its answers keep RTX next to FlexFEC.
fn peer(
    options: &DefaultInterceptorOptions,
    flexfec_with_retransmission: bool,
) -> Result<RTCPeerConnection> {
    let mut media_engine = MediaEngine::default();
    media_engine.register_default_codecs()?;
    media_engine.set_flexfec_with_retransmission(flexfec_with_retransmission);
    let (registry, _) =
        register_default_interceptors_with_options(Registry::new(), &mut media_engine, options)?;
    Ok(RTCPeerConnectionBuilder::new()
        .with_configuration(RTCConfigurationBuilder::new().build())
        .with_media_engine(media_engine)
        .with_interceptor_registry(registry)
        .build(Instant::now())?)
}

fn flexfec_options() -> DefaultInterceptorOptions {
    let mut options = DefaultInterceptorOptions::default();
    options.video_flexfec = true;
    options
}

fn offer_video(pc: &mut RTCPeerConnection) -> Result<String> {
    pc.add_transceiver_from_kind(
        RtpCodecKind::Video,
        Some(RTCRtpTransceiverInit {
            direction: RTCRtpTransceiverDirection::Sendrecv,
            ..Default::default()
        }),
    )?;
    Ok(pc.create_offer(None)?.sdp)
}

/// The default (the `Rfc` profile): the video offer has RTX and no FlexFEC, and the chain no
/// FlexFEC coder, so two default peers keep RFC 4588 retransmission (RFC 8627 section 1.1.7
/// never applies).
#[test]
fn by_default_video_offers_rtx_and_no_flexfec() -> Result<()> {
    let mut media_engine = MediaEngine::default();
    media_engine.register_default_codecs()?;
    let registry = register_default_interceptors(Registry::new(), &mut media_engine)?;
    let slots: Vec<usize> = registry
        .slots()
        .into_iter()
        .map(|(slot, _)| slot.into())
        .collect();
    for slot in [
        FLEXFEC_ENCODER_SLOT,
        FLEXFEC_WIRE_IMAGE_SLOT,
        FLEXFEC_DECODER_SLOT,
    ] {
        assert!(!slots.contains(&slot), "{slots:?}");
    }
    let mut pc = RTCPeerConnectionBuilder::new()
        .with_configuration(RTCConfigurationBuilder::new().build())
        .with_media_engine(media_engine)
        .with_interceptor_registry(registry)
        .build(Instant::now())?;
    let video = video_section(&offer_video(&mut pc)?);
    let encodings = encodings(&video);
    assert!(encodings.iter().any(|e| e == "rtx/90000"), "{video:#?}");
    assert!(
        !encodings.iter().any(|e| e.starts_with("flexfec")),
        "{video:#?}"
    );
    assert!(
        !video
            .iter()
            .any(|line| line.starts_with("a=ssrc-group:FEC-FR")),
        "{video:#?}"
    );
    assert!(!DefaultInterceptorOptions::default().video_flexfec);
    assert!(!DefaultInterceptorOptions::for_profile(BehaviourProfile::Chrome).video_flexfec);
    Ok(())
}

/// RFC 8854 section 5.2 with the setting (and in the `StrictRfc` profile): the video offer
/// includes `video/flexfec` with its required `repair-window` (RFC 8627 section 5.1) as an
/// additional media type, the sender has a FEC SSRC grouped with its media SSRC by
/// `a=ssrc-group:FEC-FR` (RFC 5956 section 4.3), and the chain has the RFC 8627 coder beside
/// the ULPFEC slots.
#[test]
fn with_the_setting_the_video_offer_indicates_flexfec() -> Result<()> {
    assert!(DefaultInterceptorOptions::for_profile(BehaviourProfile::StrictRfc).video_flexfec);
    let mut media_engine = MediaEngine::default();
    media_engine.register_default_codecs()?;
    let (registry, _) = register_default_interceptors_with_options(
        Registry::new(),
        &mut media_engine,
        &flexfec_options(),
    )?;
    let slots: Vec<usize> = registry
        .slots()
        .into_iter()
        .map(|(slot, _)| slot.into())
        .collect();
    for slot in [
        FLEXFEC_ENCODER_SLOT,
        FLEXFEC_WIRE_IMAGE_SLOT,
        FLEXFEC_DECODER_SLOT,
    ] {
        assert!(slots.contains(&slot), "{slots:?}");
    }
    let mut pc = RTCPeerConnectionBuilder::new()
        .with_configuration(RTCConfigurationBuilder::new().build())
        .with_media_engine(media_engine)
        .with_interceptor_registry(registry)
        .build(Instant::now())?;
    let video = video_section(&offer_video(&mut pc)?);
    let pt = VIDEO_FLEXFEC_PAYLOAD_TYPE;
    assert!(
        video.contains(&format!("a=rtpmap:{pt} flexfec/90000")),
        "{video:#?}"
    );
    assert!(
        video.contains(&format!("a=fmtp:{pt} repair-window=10000000")),
        "{video:#?}"
    );
    assert!(
        video[0]
            .split_whitespace()
            .skip(3)
            .any(|f| f == pt.to_string()),
        "listed on the m= line: {video:#?}"
    );
    assert!(
        encodings(&video).iter().any(|e| e == "rtx/90000"),
        "an offer may carry both: {video:#?}"
    );
    let group = video
        .iter()
        .find_map(|line| line.strip_prefix("a=ssrc-group:FEC-FR "))
        .with_context(|| format!("{video:#?}"))?;
    assert_eq!(group.split_whitespace().count(), 2, "{group}");
    Ok(())
}

/// RFC 8627 section 1.1.7, the answerer's rule both ways. Offered `flexfec` and `rtx`, an
/// answerer that supports both answers "only FLEX FEC" (the default,
/// `MediaEngine::set_flexfec_with_retransmission(false)`); with the lenient setting it keeps
/// both. An offer without `flexfec` (the default) is answered with RTX either way.
#[test]
fn the_answerer_keeps_only_flexfec_unless_told_to_keep_rtx_too() -> Result<()> {
    for (offerer_flexfec, lenient, flexfec, rtx) in [
        (true, false, true, false),
        (true, true, true, true),
        (false, false, false, true),
    ] {
        let offerer_options = if offerer_flexfec {
            flexfec_options()
        } else {
            DefaultInterceptorOptions::default()
        };
        let mut offerer = peer(&offerer_options, false)?;
        let mut answerer = peer(&flexfec_options(), lenient)?;
        let now = Instant::now();
        offer_video(&mut offerer)?;
        let offer = offerer.create_offer(None)?;
        offerer.set_local_description(now, offer.clone())?;
        answerer.set_remote_description(now, offer)?;
        let answer = answerer.create_answer(None)?;
        let video = video_section(&answer.sdp);
        let encodings = encodings(&video);
        let case = format!("offerer flexfec {offerer_flexfec}, lenient {lenient}: {video:#?}");
        assert_eq!(
            encodings.iter().any(|e| e == "flexfec/90000"),
            flexfec,
            "{case}"
        );
        assert_eq!(encodings.iter().any(|e| e == "rtx/90000"), rtx, "{case}");
        offerer.set_remote_description(now, answer)?;
    }
    Ok(())
}

struct Peer {
    pc: RTCPeerConnection,
    addr: SocketAddr,
    connected: bool,
    states: Vec<RTCPeerConnectionState>,
    /// The (SSRC, sequence number) of each RTP packet the application was given.
    read: Vec<(u32, u16)>,
}

impl Peer {
    fn new(addr: &str) -> Result<Self> {
        Ok(Self {
            pc: peer(&flexfec_options(), false)?,
            addr: addr.parse()?,
            connected: false,
            states: vec![],
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

/// The RTP header of an SRTP packet on the wire (SRTP leaves the header in the clear).
fn wire_rtp_header(datagram: &[u8]) -> Option<Header> {
    if datagram.len() < 12 || datagram[0] >> 6 != 2 || (192..=223).contains(&datagram[1]) {
        return None;
    }
    Header::unmarshal(&mut &datagram[..]).ok()
}

struct World {
    peers: [Peer; 2],
    now: Instant,
    /// The media payload type and SSRC of the first peer's video.
    media: Option<(u8, u32)>,
    /// Media sequence numbers that crossed the wire once: a second transmission (a
    /// retransmission on the media SSRC, RTX not being negotiated) is lost, so whatever brings
    /// a lost packet back is FlexFEC.
    seen: HashSet<u16>,
    /// The media sequence numbers the network lost.
    lost: Vec<u16>,
    /// The FlexFEC repair packets of the first peer that crossed the wire: (SSRC, payload type).
    repair: Vec<(u32, u8)>,
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
                    if header.payload_type == VIDEO_FLEXFEC_PAYLOAD_TYPE {
                        self.repair.push((header.ssrc, header.payload_type));
                    }
                    if let Some((media_pt, media_ssrc)) = self.media
                        && header.ssrc == media_ssrc
                        && header.payload_type == media_pt
                    {
                        // One media packet in twenty is lost, and every second transmission.
                        let first = self.seen.insert(header.sequence_number);
                        if !first {
                            continue;
                        }
                        if header.sequence_number % 20 == 7 {
                            self.lost.push(header.sequence_number);
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
                        .push((packet.header.ssrc, packet.header.sequence_number));
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
}

/// Two peers with the setting on: the offer carries `flexfec` and `rtx`, the answer only
/// `flexfec` (RFC 8627 section 1.1.7); the sender's FlexFEC repair packets go on its FEC SSRC
/// under the FlexFEC payload type once the receiver reports loss (RFC 8854 section 8), and
/// media packets the network lost come back to the receiving application, rebuilt: no
/// second transmission of a media packet gets through.
#[test]
fn with_the_setting_at_both_ends_flexfec_is_negotiated_and_rebuilds_lost_media() -> Result<()> {
    let mut world = World {
        peers: [Peer::new("10.0.0.1:5000")?, Peer::new("10.0.0.2:5000")?],
        now: Instant::now(),
        media: None,
        seen: HashSet::new(),
        lost: vec![],
        repair: vec![],
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
    let sender: RTCRtpSenderId = world.peers[0]
        .pc
        .rtp_transceiver(transceiver)
        .and_then(|t| t.sender())
        .context("a sendonly transceiver has a sender")?;
    let now = world.now;
    let offer = world.peers[0].pc.create_offer(None)?;
    world.peers[0]
        .pc
        .set_local_description(now, offer.clone())?;
    world.peers[1]
        .pc
        .set_remote_description(now, offer.clone())?;
    let answer = world.peers[1].pc.create_answer(None)?;
    world.peers[1]
        .pc
        .set_local_description(now, answer.clone())?;
    world.peers[0]
        .pc
        .set_remote_description(now, answer.clone())?;
    let offered = encodings(&video_section(&offer.sdp));
    assert!(offered.iter().any(|e| e == "flexfec/90000"), "{offered:?}");
    assert!(offered.iter().any(|e| e == "rtx/90000"), "{offered:?}");
    let answered = encodings(&video_section(&answer.sdp));
    assert!(
        answered.iter().any(|e| e == "flexfec/90000"),
        "{answered:?}"
    );
    assert!(
        !answered.iter().any(|e| e == "rtx/90000"),
        "RFC 8627 section 1.1.7: only FlexFEC: {answered:?}"
    );

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

    let (ssrc, fec_ssrc, media_pt) = {
        let mut rtp_sender = world.peers[0].pc.rtp_sender(sender).context("sender")?;
        let parameters = rtp_sender.get_parameters();
        let coding = &parameters.encodings[0].rtp_coding_parameters;
        (
            coding.ssrc.context("an SSRC")?,
            coding
                .fec
                .as_ref()
                .map(|fec| fec.ssrc)
                .context("a FEC SSRC")?,
            parameters.rtp_parameters.codecs[0].payload_type,
        )
    };
    world.media = Some((media_pt, ssrc));

    // Ten seconds of one-packet frames at 30 per second.
    for seq in 0..300u16 {
        let now = world.now;
        let mut payload = vec![0x10u8];
        payload.extend((0..300u16).map(|i| (i as u8) ^ (seq as u8)));
        world.peers[0]
            .pc
            .rtp_sender(sender)
            .context("sender")?
            .write_rtp(
                now,
                rtci::rtp::Packet {
                    header: Header {
                        version: 2,
                        payload_type: media_pt,
                        sequence_number: seq,
                        timestamp: u32::from(seq) * 3000,
                        ssrc,
                        marker: true,
                        ..Default::default()
                    },
                    payload: Bytes::from(payload),
                },
            )?;
        world.pump()?;
        world.run_until(now + Duration::from_millis(33))?;
    }
    let until = world.now + Duration::from_secs(1);
    world.run_until(until)?;

    assert!(!world.lost.is_empty());
    assert!(!world.repair.is_empty(), "FlexFEC repair packets were sent");
    assert!(
        world.repair.iter().all(|(s, _)| *s == fec_ssrc),
        "on the FEC SSRC: {:?}",
        world.repair
    );
    let sent = world.peers[0].pc.fec_stats().sent;
    assert_eq!(sent.len(), 1, "{sent:?}");
    assert_eq!(sent[0].ssrc, ssrc);
    assert!(sent[0].fec_packets_sent > 0, "{sent:?}");

    let delivered: HashSet<u16> = world.peers[1]
        .read
        .iter()
        .filter(|(s, _)| *s == ssrc)
        .map(|(_, seq)| *seq)
        .collect();
    let rebuilt: Vec<u16> = world
        .lost
        .iter()
        .copied()
        .filter(|seq| delivered.contains(seq))
        .collect();
    assert!(
        !rebuilt.is_empty(),
        "FlexFEC rebuilt lost media packets: lost {:?}, delivered {}",
        world.lost,
        delivered.len()
    );
    // Once the receiver's reports showed the loss, FEC follows it: the losses of the second
    // half of the call are rebuilt.
    assert_eq!(
        world.seen.len(),
        300,
        "every media packet crossed the wire: {:?}",
        world.seen.iter().max()
    );
    let late: Vec<u16> = world
        .lost
        .iter()
        .copied()
        .filter(|seq| *seq >= 150)
        .collect();
    assert!(
        late.iter().all(|seq| delivered.contains(seq)),
        "lost after FEC started {late:?}, rebuilt {rebuilt:?}, delivered {}, FEC sent {sent:?}",
        delivered.len()
    );
    Ok(())
}
