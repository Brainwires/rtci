//! ECN (RFC 3168) and L4S (RFC 9331) on RTP media, with RFC 8888 congestion control feedback.
//!
//! The engine is sans-I/O, so the application's socket layer carries the IP header's ECN
//! codepoint in `TransportContext::ecn`: it names the codepoint each received datagram arrived
//! with, and the engine names the codepoint each datagram to send is to carry. With ECN on
//! (`SettingEngineBuilder::with_ecn`) and `ack ccfb` negotiated, RTP media goes out ECT(1)
//! and nothing else is marked; the receiver counts ECT(1) / CE receptions, reports each packet's
//! marking back in RFC 8888 feedback, and the sender turns the reports into remote-inbound
//! statistics (marks, losses, recoveries, bleached ECT(1)).
//!
//! Two `rtc` peers on a simulated network that can mark CE, bleach ECT(1), delay and drop
//! packets; virtual time, no sockets.

use anyhow::{Result, bail};
use bytes::{Bytes, BytesMut};
use rtc::interceptor::Registry;
use rtc::peer_connection::configuration::RTCConfigurationBuilder;
use rtc::peer_connection::configuration::interceptor_registry::{
    configure_congestion_control_feedback, configure_nack, configure_rtcp_reports,
};
use rtc::peer_connection::configuration::media_engine::{
    MIME_TYPE_RTX, MIME_TYPE_VP8, MediaEngine,
};
use rtc::peer_connection::configuration::setting_engine::SettingEngineBuilder;
use rtc::peer_connection::event::RTCPeerConnectionEvent;
use rtc::peer_connection::state::RTCPeerConnectionState;
use rtc::peer_connection::transport::{
    CandidateConfig, CandidateHostConfig, RTCIceCandidate, RTCIceCandidateInit,
};
use rtc::peer_connection::{RTCPeerConnection, RTCPeerConnectionBuilder};
use rtc::rtp_transceiver::rtp_sender::{
    RTCRtpCodec, RTCRtpCodecParameters, RTCRtpEncodingParameters, RtpCodecKind,
};
use rtc::rtp_transceiver::{RTCRtpSenderId, RTCRtpTransceiverDirection, RTCRtpTransceiverInit};
use rtc::sansio::Protocol;
use rtc::shared::{EcnCodepoint, TaggedBytesMut, TransportContext, TransportProtocol};
use rtc::statistics::StatsSelector;
use rtc::statistics::report::{RTCStatsReport, RTCStatsReportEntry};
use serde_json::Value;
use std::collections::HashSet;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

const CONNECT_WITHIN: Duration = Duration::from_secs(10);
const VP8_PT: u8 = 96;
const RTX_PT: u8 = 97;
/// RTP packets the sender writes, one per 20 ms of virtual time.
const PACKETS: u16 = 100;
const FIRST_SEQ: u16 = 7000;

fn codec(mime_type: &str, sdp_fmtp_line: &str) -> RTCRtpCodec {
    RTCRtpCodec {
        mime_type: mime_type.to_owned(),
        clock_rate: 90000,
        channels: 0,
        sdp_fmtp_line: sdp_fmtp_line.to_owned(),
        rtcp_feedback: vec![],
    }
}

/// How a peer is configured.
#[derive(Clone, Copy)]
struct Setup {
    /// `SettingEngineBuilder::with_ecn`.
    ecn: bool,
    /// `configure_congestion_control_feedback` (`ack ccfb` and the RFC 8888 recorder).
    ccfb: bool,
    /// `configure_nack` (NACK + RTX repair).
    nack: bool,
}

struct Peer {
    pc: RTCPeerConnection,
    addr: SocketAddr,
    connected: bool,
    states: Vec<RTCPeerConnectionState>,
}

impl Peer {
    fn new(addr: &str, setup: Setup) -> Result<Self> {
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
        let mut registry = configure_rtcp_reports(Registry::new());
        if setup.nack {
            registry = configure_nack(registry, &mut media_engine);
        }
        if setup.ccfb {
            registry = configure_congestion_control_feedback(registry, &mut media_engine);
        }
        let pc = RTCPeerConnectionBuilder::new()
            .with_configuration(RTCConfigurationBuilder::new().build())
            .with_setting_engine(SettingEngineBuilder::new().with_ecn(setup.ecn).build())
            .with_media_engine(media_engine)
            .with_interceptor_registry(registry)
            .build(Instant::now())?;
        Ok(Self {
            pc,
            addr: addr.parse()?,
            connected: false,
            states: Vec::new(),
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

/// The SSRC and sequence number of an SRTP packet on the wire (its RTP header is in the clear),
/// or `None` for anything else (RTCP, DTLS, STUN).
fn wire_rtp(datagram: &[u8]) -> Option<(u32, u16)> {
    if datagram.len() < 12 || datagram[0] >> 6 != 2 || (192..=223).contains(&datagram[1]) {
        return None;
    }
    let seq = u16::from_be_bytes([datagram[2], datagram[3]]);
    let ssrc = u32::from_be_bytes([datagram[8], datagram[9], datagram[10], datagram[11]]);
    Some((ssrc, seq))
}

/// A datagram the network holds back, delivered at `at`.
struct Held {
    at: Instant,
    to: SocketAddr,
    from: SocketAddr,
    ecn: Option<EcnCodepoint>,
    data: BytesMut,
}

/// What the network did to the sender's media stream, by sequence number.
#[derive(Default)]
struct Path {
    /// Marked CE on the way (a congested L4S queue).
    mark_ce: HashSet<u16>,
    /// ECN bits cleared on the way (a router that bleaches).
    bleach: HashSet<u16>,
    /// Delivered this long after it was sent, behind the packets after it.
    delay: Option<(u16, Duration)>,
    /// Never delivered.
    drop: HashSet<u16>,
    /// Dropped once; a retransmission goes through.
    drop_once: Option<u16>,
}

/// A datagram on the wire: whether the sender sent it, its SSRC and sequence number if it is
/// RTP, and the ECN codepoint it was sent with.
type Sent = (bool, Option<(u32, u16)>, Option<EcnCodepoint>);

struct World {
    peers: [Peer; 2],
    now: Instant,
    /// The SSRC of the sender's media stream, once known.
    media_ssrc: Option<u32>,
    path: Path,
    held: Vec<Held>,
    /// (from the sender, SSRC and sequence number if RTP, the ECN codepoint it was sent with)
    /// for every datagram either peer sent.
    sent: Vec<Sent>,
}

impl World {
    fn deliver(
        &mut self,
        to: SocketAddr,
        from: SocketAddr,
        ecn: Option<EcnCodepoint>,
        data: BytesMut,
    ) {
        let Some(peer) = self.peers.iter_mut().find(|p| p.addr == to) else {
            return;
        };
        let _ = peer.pc.handle_read(TaggedBytesMut {
            now: self.now,
            transport: TransportContext {
                local_addr: to,
                peer_addr: from,
                ecn,
                transport_protocol: TransportProtocol::UDP,
            },
            message: data,
        });
    }

    fn pump(&mut self) -> Result<()> {
        loop {
            let mut in_flight = Vec::new();
            let now = self.now;
            let (due, held): (Vec<Held>, Vec<Held>) = std::mem::take(&mut self.held)
                .into_iter()
                .partition(|h| h.at <= now);
            self.held = held;
            for h in due {
                self.deliver(h.to, h.from, h.ecn, h.data);
            }
            for (i, peer) in self.peers.iter_mut().enumerate() {
                while let Some(msg) = peer.pc.poll_write() {
                    in_flight.push((i, msg.transport, msg.message));
                }
            }
            if in_flight.is_empty() {
                break;
            }
            for (i, transport, data) in in_flight {
                let rtp = wire_rtp(&data);
                self.sent.push((i == 0, rtp, transport.ecn));
                let mut ecn = transport.ecn;
                if i == 0
                    && let Some((ssrc, seq)) = rtp
                    && Some(ssrc) == self.media_ssrc
                {
                    if self.path.drop.contains(&seq) {
                        continue;
                    }
                    if self.path.drop_once == Some(seq) {
                        self.path.drop_once = None;
                        continue;
                    }
                    if self.path.mark_ce.contains(&seq) {
                        ecn = Some(EcnCodepoint::Ce);
                    }
                    if self.path.bleach.contains(&seq) {
                        ecn = None;
                    }
                    if let Some((delayed, by)) = self.path.delay
                        && delayed == seq
                    {
                        self.path.delay = None;
                        self.held.push(Held {
                            at: self.now + by,
                            to: transport.peer_addr,
                            from: transport.local_addr,
                            ecn,
                            data,
                        });
                        continue;
                    }
                }
                self.deliver(transport.peer_addr, transport.local_addr, ecn, data);
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
            while peer.pc.poll_read().is_some() {}
        }
        Ok(())
    }

    /// Moves virtual time to `until`, firing every deadline (and held datagram) on the way.
    fn run_until(&mut self, until: Instant) -> Result<()> {
        while self.now < until {
            let mut next = until;
            for peer in self.peers.iter_mut() {
                if let Some(deadline) = peer.pc.poll_timeout() {
                    next = next.min(deadline);
                }
            }
            for h in &self.held {
                next = next.min(h.at);
            }
            self.now = next.max(self.now + Duration::from_millis(1)).min(until);
            for peer in self.peers.iter_mut() {
                peer.pc.handle_timeout(self.now)?;
            }
            self.pump()?;
        }
        Ok(())
    }

    /// The offerer (`sender`) sends video to the answerer (`receiver`), connected over host
    /// candidates. Returns the world, the sender and the offer's SDP.
    fn connected(sender: Setup, receiver: Setup) -> Result<(Self, RTCRtpSenderId, String)> {
        let mut world = World {
            peers: [
                Peer::new("10.0.0.1:5000", sender)?,
                Peer::new("10.0.0.2:5000", receiver)?,
            ],
            now: Instant::now(),
            media_ssrc: None,
            path: Path::default(),
            held: Vec::new(),
            sent: Vec::new(),
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
        let sender_id = world.peers[0]
            .pc
            .rtp_transceiver(transceiver)
            .and_then(|t| t.sender())
            .expect("a sendonly transceiver has a sender");

        let now = world.now;
        let offer = world.peers[0].pc.create_offer(None)?;
        let offer_sdp = offer.sdp.clone();
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
        let ssrc = world.sender_stream(sender_id).0;
        world.media_ssrc = Some(ssrc);
        Ok((world, sender_id, offer_sdp))
    }

    /// The sender's (media SSRC, RTX SSRC).
    fn sender_stream(&mut self, sender: RTCRtpSenderId) -> (u32, Option<u32>) {
        let mut sender = self.peers[0].pc.rtp_sender(sender).expect("sender");
        let parameters = sender.get_parameters();
        let encoding = &parameters.encodings[0];
        (
            encoding.rtp_coding_parameters.ssrc.expect("an SSRC"),
            encoding
                .rtp_coding_parameters
                .rtx
                .as_ref()
                .map(|rtx| rtx.ssrc),
        )
    }

    /// Writes `PACKETS` RTP packets, 20 ms apart, then lets RTCP run for `settle`.
    fn send_media(&mut self, sender: RTCRtpSenderId, settle: Duration) -> Result<()> {
        let (ssrc, _) = self.sender_stream(sender);
        for n in 0..PACKETS {
            let now = self.now;
            self.peers[0]
                .pc
                .rtp_sender(sender)
                .expect("sender")
                .write_rtp(
                    now,
                    rtc::rtp::Packet {
                        header: rtc::rtp::header::Header {
                            version: 2,
                            payload_type: VP8_PT,
                            sequence_number: FIRST_SEQ.wrapping_add(n),
                            timestamp: u32::from(n) * 1800,
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
        let until = self.now + settle;
        self.run_until(until)
    }

    fn stats(&mut self, peer: usize) -> RTCStatsReport {
        let now = self.now;
        self.peers[peer].pc.get_stats(now, StatsSelector::None)
    }
}

/// The `outbound-rtp`, `inbound-rtp` or `remote-inbound-rtp` object for `ssrc`, as the JSON
/// webrtc-stats defines (a member left out reads as `null`).
fn stats_json(report: &RTCStatsReport, typ: &str, ssrc: u32) -> Option<Value> {
    report.iter().find_map(|entry| {
        let json = match entry {
            RTCStatsReportEntry::OutboundRtp(s) => serde_json::to_value(s),
            RTCStatsReportEntry::InboundRtp(s) => serde_json::to_value(s),
            RTCStatsReportEntry::RemoteInboundRtp(s) => serde_json::to_value(s),
            _ => return None,
        }
        .ok()?;
        (json["type"] == typ && json["ssrc"] == ssrc).then_some(json)
    })
}

const ECN_CCFB: Setup = Setup {
    ecn: true,
    ccfb: true,
    nack: false,
};

/// The whole path: ECT(1) on the wire for media only, CE marks and bleaching counted by the
/// receiver from what its socket layer reports, and reported back over RFC 8888 so the sender's
/// remote-inbound object has the same marks, the bleached packets, the losses and the recovery.
#[test]
fn media_is_sent_ect1_and_both_sides_count_what_the_path_did() -> Result<()> {
    let (mut world, sender, offer) = World::connected(ECN_CCFB, ECN_CCFB)?;
    assert!(
        offer.contains(&format!("a=rtcp-fb:{VP8_PT} ack ccfb")),
        "the offer negotiates RFC 8888 feedback:\n{offer}"
    );
    let (ssrc, _) = world.sender_stream(sender);

    world.path.mark_ce = (10..15).map(|n| FIRST_SEQ + n).collect();
    world.path.bleach = (20..23).map(|n| FIRST_SEQ + n).collect();
    world.path.delay = Some((FIRST_SEQ + 40, Duration::from_millis(400)));
    world.path.drop = HashSet::from([FIRST_SEQ + 60]);
    world.send_media(sender, Duration::from_secs(1))?;

    // On the wire: every RTP packet of the stream ECT(1); nothing else marked, in either
    // direction (STUN, DTLS, SRTCP).
    let media: Vec<_> = world
        .sent
        .iter()
        .filter(|(from_sender, rtp, _)| *from_sender && rtp.is_some_and(|(s, _)| s == ssrc))
        .collect();
    assert_eq!(media.len(), usize::from(PACKETS));
    assert!(
        media
            .iter()
            .all(|(_, _, ecn)| *ecn == Some(EcnCodepoint::Ect1)),
        "media is sent ECT(1)"
    );
    let others: Vec<_> = world
        .sent
        .iter()
        .filter(|(_, rtp, _)| rtp.is_none())
        .collect();
    assert!(!others.is_empty());
    assert!(
        others.iter().all(|(_, _, ecn)| ecn.is_none()),
        "STUN, DTLS and RTCP are not marked"
    );

    // Delivered: 100 sent, 1 lost; of the 99, 5 CE, 3 bleached, 91 ECT(1).
    let sender_stats = world.stats(0);
    let outbound = stats_json(&sender_stats, "outbound-rtp", ssrc).expect("outbound-rtp");
    assert_eq!(outbound["packetsSentWithEct1"], PACKETS, "{outbound}");

    let inbound = stats_json(&world.stats(1), "inbound-rtp", ssrc).expect("inbound-rtp");
    assert_eq!(inbound["packetsReceivedWithCe"], 5, "{inbound}");
    assert_eq!(inbound["packetsReceivedWithEct1"], 91, "{inbound}");
    assert_eq!(
        inbound["packetsReportedAsLost"], 2,
        "the delayed packet and the dropped one were reported lost: {inbound}"
    );
    assert_eq!(
        inbound["packetsReportedAsLostButRecovered"], 1,
        "the delayed packet was reported received later: {inbound}"
    );

    let remote = stats_json(&sender_stats, "remote-inbound-rtp", ssrc).expect("remote-inbound-rtp");
    assert_eq!(remote["packetsReceivedWithCe"], 5, "{remote}");
    assert_eq!(remote["packetsReceivedWithEct1"], 91, "{remote}");
    assert_eq!(remote["packetsReportedAsLost"], 2, "{remote}");
    assert_eq!(remote["packetsReportedAsLostButRecovered"], 1, "{remote}");
    assert_eq!(remote["packetsWithBleachedEct1Marking"], 3, "{remote}");
    Ok(())
}

/// A retransmission is RTP media too: the RTX packet that repairs a loss goes out ECT(1).
#[test]
fn a_retransmission_is_sent_ect1() -> Result<()> {
    let setup = Setup {
        nack: true,
        ..ECN_CCFB
    };
    let (mut world, sender, _) = World::connected(setup, setup)?;
    let (_, rtx_ssrc) = world.sender_stream(sender);
    let rtx_ssrc = rtx_ssrc.expect("RTX is negotiated");
    world.path.drop_once = Some(FIRST_SEQ + 30);
    world.send_media(sender, Duration::from_millis(500))?;

    let rtx: Vec<_> = world
        .sent
        .iter()
        .filter(|(from_sender, rtp, _)| *from_sender && rtp.is_some_and(|(s, _)| s == rtx_ssrc))
        .collect();
    assert!(!rtx.is_empty(), "the lost packet was resent over RTX");
    assert!(
        rtx.iter()
            .all(|(_, _, ecn)| *ecn == Some(EcnCodepoint::Ect1))
    );
    Ok(())
}

/// ECN is off by default: nothing is marked and the ECN members are left out (the engine
/// cannot see the IP header itself), while the RFC 8888 members, which come from the feedback,
/// are there as soon as `ack ccfb` is negotiated.
#[test]
fn without_ecn_nothing_is_marked_and_the_ecn_counts_are_left_out() -> Result<()> {
    let setup = Setup {
        ecn: false,
        ..ECN_CCFB
    };
    let (mut world, sender, _) = World::connected(setup, setup)?;
    let (ssrc, _) = world.sender_stream(sender);
    world.path.drop = HashSet::from([FIRST_SEQ + 50]);
    world.send_media(sender, Duration::from_millis(500))?;

    assert!(world.sent.iter().all(|(_, _, ecn)| ecn.is_none()));

    let sender_stats = world.stats(0);
    let outbound = stats_json(&sender_stats, "outbound-rtp", ssrc).expect("outbound-rtp");
    assert_eq!(outbound["packetsSentWithEct1"], Value::Null, "{outbound}");
    let inbound = stats_json(&world.stats(1), "inbound-rtp", ssrc).expect("inbound-rtp");
    assert_eq!(inbound["packetsReceivedWithEct1"], Value::Null, "{inbound}");
    assert_eq!(inbound["packetsReceivedWithCe"], Value::Null, "{inbound}");
    assert_eq!(inbound["packetsReportedAsLost"], 1, "{inbound}");
    assert_eq!(inbound["packetsReportedAsLostButRecovered"], 0, "{inbound}");

    let remote = stats_json(&sender_stats, "remote-inbound-rtp", ssrc).expect("remote-inbound-rtp");
    assert_eq!(remote["packetsReportedAsLost"], 1, "{remote}");
    assert_eq!(remote["packetsReceivedWithEct1"], 0, "{remote}");
    assert_eq!(remote["packetsWithBleachedEct1Marking"], 0, "{remote}");
    Ok(())
}

/// ECN without RFC 8888 feedback marks nothing: an L4S sender needs the receiver to report CE
/// back. The offer carries no `ack ccfb`, and the RFC 8888 members are left out.
#[test]
fn without_ccfb_media_is_not_marked() -> Result<()> {
    let setup = Setup {
        ccfb: false,
        ..ECN_CCFB
    };
    let (mut world, sender, offer) = World::connected(setup, setup)?;
    assert!(!offer.contains("ack ccfb"), "{offer}");
    let (ssrc, _) = world.sender_stream(sender);
    world.send_media(sender, Duration::from_secs(2))?;

    assert!(world.sent.iter().all(|(_, _, ecn)| ecn.is_none()));
    let sender_stats = world.stats(0);
    let outbound = stats_json(&sender_stats, "outbound-rtp", ssrc).expect("outbound-rtp");
    assert_eq!(outbound["packetsSentWithEct1"], 0, "{outbound}");
    let inbound = stats_json(&world.stats(1), "inbound-rtp", ssrc).expect("inbound-rtp");
    assert_eq!(inbound["packetsReceivedWithEct1"], 0, "{inbound}");
    assert_eq!(inbound["packetsReportedAsLost"], Value::Null, "{inbound}");

    let remote = stats_json(&sender_stats, "remote-inbound-rtp", ssrc)
        .expect("remote-inbound-rtp (from receiver reports)");
    assert_eq!(remote["packetsReportedAsLost"], Value::Null, "{remote}");
    assert_eq!(
        remote["packetsWithBleachedEct1Marking"],
        Value::Null,
        "{remote}"
    );
    Ok(())
}

/// Only one side configured for RFC 8888: `ack ccfb` is not negotiated, so the sender marks
/// nothing even with ECN on.
#[test]
fn ccfb_offered_but_not_answered_marks_nothing() -> Result<()> {
    let answerer = Setup {
        ccfb: false,
        ..ECN_CCFB
    };
    let (mut world, sender, offer) = World::connected(ECN_CCFB, answerer)?;
    assert!(offer.contains("ack ccfb"));
    world.send_media(sender, Duration::from_millis(200))?;
    assert!(world.sent.iter().all(|(_, _, ecn)| ecn.is_none()));
    Ok(())
}
