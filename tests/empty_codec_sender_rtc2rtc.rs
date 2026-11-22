//! A sender whose encodings name no codec (W3C `addTransceiver` with `sendEncodings` that leave
//! `codec` unset, so negotiation picks it) is a sender like any other: its stream is bound to
//! the interceptors (sender reports, the NACK responder), it gets an RTX repair flow when RTX is
//! negotiated, and its outbound stream references the codec it is sent with (so the
//! remote-inbound `jitter`, which needs that codec's clock rate, is reported). With receiver
//! reference times negotiated (`a=rtcp-fb:<pt> rrtr`), the receiver's remote-outbound stats
//! carry a round trip time measured over RTCP XR (RFC 3611 sections 4.4, 4.5).
//!
//! Two `rtc` peers on a simulated network, virtual time, no sockets.

use anyhow::{Result, bail};
use bytes::Bytes;
use rtc::interceptor::Registry;
use rtc::peer_connection::configuration::RTCConfigurationBuilder;
use rtc::peer_connection::configuration::interceptor_registry::{
    configure_nack, configure_receiver_reference_time, configure_rtcp_reports,
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
use rtc::rtp_transceiver::rtp_sender::{
    RTCRtpCodec, RTCRtpCodecParameters, RTCRtpEncodingParameters, RtpCodecKind,
};
use rtc::rtp_transceiver::{RTCRtpSenderId, RTCRtpTransceiverDirection, RTCRtpTransceiverInit};
use rtc::sansio::Protocol;
use rtc::shared::{TaggedBytesMut, TransportContext, TransportProtocol};
use rtc::statistics::StatsSelector;
use rtc::statistics::report::RTCStatsReportEntry;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

const CONNECT_WITHIN: Duration = Duration::from_secs(10);
const VP8_PT: u8 = 96;
const RTX_PT: u8 = 97;
/// RTP packets the sender writes, one per 20 ms of virtual time.
const PACKETS: u16 = 100;
const FIRST_SEQ: u16 = 4000;
/// The packet the network drops once, which only a NACK can bring back.
const DROPPED_SEQ: u16 = FIRST_SEQ + 40;

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
    /// The sequence numbers of the RTP packets `poll_read` yielded, by SSRC.
    read_rtp: Vec<(u32, u16)>,
}

impl Peer {
    /// A peer that, with `rrtr`, negotiates receiver reference times.
    fn with_rrtr(addr: &str, rrtr: bool) -> Result<Self> {
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
        if rrtr {
            configure_receiver_reference_time(&mut media_engine);
        }
        let registry = configure_rtcp_reports(configure_nack(Registry::new(), &mut media_engine));
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
            read_rtp: Vec::new(),
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

struct World {
    peers: [Peer; 2],
    now: Instant,
    /// Drop the sender's RTP packet with this SSRC and sequence number, once.
    drop_once: Option<(u32, u16)>,
    /// The (SSRC, sequence number) of every RTP packet the sender put on the wire.
    sent_on_wire: Vec<(u32, u16)>,
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
                    self.sent_on_wire.push(rtp);
                    if self.drop_once == Some(rtp) {
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
                if let RTCMessage::RtpPacket(_, packet) = message.message {
                    peer.read_rtp
                        .push((packet.header.ssrc, packet.header.sequence_number));
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

    /// The offerer sends video from a transceiver whose one encoding names no codec; the
    /// answerer receives it. Connected over host candidates.
    fn connected() -> Result<(Self, RTCRtpSenderId)> {
        Self::connected_with_rrtr(false)
    }

    /// `connected`, both peers negotiating receiver reference times with `rrtr`.
    fn connected_with_rrtr(rrtr: bool) -> Result<(Self, RTCRtpSenderId)> {
        let mut world = World {
            peers: [
                Peer::with_rrtr("10.0.0.1:5000", rrtr)?,
                Peer::with_rrtr("10.0.0.2:5000", rrtr)?,
            ],
            now: Instant::now(),
            drop_once: None,
            sent_on_wire: Vec::new(),
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
        assert!(
            encoding.codec.mime_type.is_empty(),
            "the encoding names no codec: {:?}",
            encoding.codec
        );
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

    /// Writes `PACKETS` RTP packets, 20 ms apart, then lets RTCP run for `settle`.
    fn send_media(&mut self, sender: RTCRtpSenderId, settle: Duration) -> Result<()> {
        let (_, _, pt) = self.sender_stream(sender);
        self.send_media_with_pt(sender, pt, settle)
    }

    /// `send_media`, every packet written with payload type `pt`.
    fn send_media_with_pt(
        &mut self,
        sender: RTCRtpSenderId,
        pt: u8,
        settle: Duration,
    ) -> Result<()> {
        let (ssrc, _, _) = self.sender_stream(sender);
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
                            payload_type: pt,
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
}

/// The sender's stream is bound: sender reports reach the receiver (its remote-outbound stats),
/// and the receiver's reports come back to a stream that knows its codec (remote-inbound
/// `jitter` and a round-trip time from the report's LSR / DLSR).
#[test]
fn an_encoding_without_a_codec_sends_reports_and_has_stats() -> Result<()> {
    let (mut world, sender) = World::connected()?;
    let (ssrc, _, _) = world.sender_stream(sender);
    world.send_media(sender, Duration::from_secs(3))?;

    let now = world.now;
    let receiver_report = world.peers[1].pc.get_stats(now, StatsSelector::None);
    let remote_outbound = receiver_report.iter().find_map(|entry| match entry {
        RTCStatsReportEntry::RemoteOutboundRtp(s)
            if s.sent_rtp_stream_stats.rtp_stream_stats.ssrc == ssrc =>
        {
            Some(s)
        }
        _ => None,
    });
    let remote_outbound =
        remote_outbound.expect("the receiver got sender reports for the stream (remote-outbound)");
    assert!(remote_outbound.reports_sent > 0, "{remote_outbound:?}");

    let sender_report = world.peers[0].pc.get_stats(now, StatsSelector::None);
    let remote_inbound = sender_report
        .iter()
        .find_map(|entry| match entry {
            RTCStatsReportEntry::RemoteInboundRtp(s)
                if s.received_rtp_stream_stats.rtp_stream_stats.ssrc == ssrc =>
            {
                Some(s)
            }
            _ => None,
        })
        .expect("the sender got receiver reports for the stream (remote-inbound)");
    assert!(
        remote_inbound.received_rtp_stream_stats.jitter.is_some(),
        "the outbound stream knows its codec's clock rate, so jitter is reported: {remote_inbound:?}"
    );
    assert!(
        remote_inbound.round_trip_time_measurements > 0,
        "the receiver reports answered sender reports (LSR / DLSR), so the RTT is measured: \
         {remote_inbound:?}"
    );

    let outbound = sender_report
        .outbound_rtp_streams()
        .find(|s| s.sent_rtp_stream_stats.rtp_stream_stats.ssrc == ssrc)
        .expect("an outbound-rtp for the stream");
    assert!(
        !outbound
            .sent_rtp_stream_stats
            .rtp_stream_stats
            .codec_id
            .is_empty(),
        "the outbound stream references the codec it is sent with: {outbound:?}"
    );
    Ok(())
}

/// The encoding gets an RTX repair flow (RTX is negotiated), and a packet the network loses is
/// NACKed by the receiver and resent over RTX by the sender's NACK responder.
#[test]
fn an_encoding_without_a_codec_is_repaired_over_rtx() -> Result<()> {
    let (mut world, sender) = World::connected()?;
    let (ssrc, rtx_ssrc, _) = world.sender_stream(sender);
    let rtx_ssrc = rtx_ssrc.expect("RTX is negotiated, so the encoding has a repair flow");

    let now = world.now;
    let outbound_rtx = world.peers[0]
        .pc
        .get_stats(now, StatsSelector::None)
        .outbound_rtp_streams()
        .find(|s| s.sent_rtp_stream_stats.rtp_stream_stats.ssrc == ssrc)
        .and_then(|s| s.rtx_ssrc);
    assert_eq!(
        outbound_rtx,
        Some(rtx_ssrc),
        "outbound-rtp names its rtxSsrc"
    );

    world.drop_once = Some((ssrc, DROPPED_SEQ));
    world.send_media(sender, Duration::from_secs(2))?;

    assert!(world.drop_once.is_none(), "the packet to drop was sent");
    assert!(
        world.sent_on_wire.iter().any(|&(s, _)| s == rtx_ssrc),
        "the lost packet was resent on the RTX SSRC"
    );
    assert!(
        world.peers[1].read_rtp.contains(&(ssrc, DROPPED_SEQ)),
        "the receiver got the lost packet back"
    );
    Ok(())
}

/// A packet whose payload type is not negotiated is rewritten to the payload type of the codec
/// its encoding is sent with. For an encoding that names no codec that is the codec negotiation
/// picked (the one its stream is bound with), not a refusal.
#[test]
fn an_encoding_without_a_codec_rewrites_an_unnegotiated_payload_type() -> Result<()> {
    let (mut world, sender) = World::connected()?;
    let (ssrc, _, pt) = world.sender_stream(sender);
    assert_eq!(pt, VP8_PT);
    const UNNEGOTIATED_PT: u8 = 120;
    world.send_media_with_pt(sender, UNNEGOTIATED_PT, Duration::from_millis(200))?;

    let received: Vec<u16> = world.peers[1]
        .read_rtp
        .iter()
        .filter(|&&(s, _)| s == ssrc)
        .map(|&(_, seq)| seq)
        .collect();
    assert_eq!(
        received.len(),
        usize::from(PACKETS),
        "every packet went out with the negotiated payload type and was received"
    );
    Ok(())
}

/// The receiver's remote-outbound round trip time for `ssrc`: (`roundTripTime`,
/// `totalRoundTripTime`, `roundTripTimeMeasurements`), or `None` without remote-outbound stats.
fn remote_outbound_rtt(world: &mut World, ssrc: u32) -> Option<(Option<f64>, f64, u64)> {
    let now = world.now;
    world.peers[1]
        .pc
        .get_stats(now, StatsSelector::None)
        .iter()
        .find_map(|entry| match entry {
            RTCStatsReportEntry::RemoteOutboundRtp(s)
                if s.sent_rtp_stream_stats.rtp_stream_stats.ssrc == ssrc =>
            {
                Some((
                    s.round_trip_time,
                    s.total_round_trip_time,
                    s.round_trip_time_measurements,
                ))
            }
            _ => None,
        })
}

/// With receiver reference times negotiated, the receiver sends RTCP XR receiver reference time
/// blocks, the sender answers with DLRR blocks, and the receiver's remote-outbound stats carry
/// the round trip time (`roundTripTime`, `totalRoundTripTime`, `roundTripTimeMeasurements`).
#[test]
fn the_receiver_measures_a_round_trip_time_over_rtcp_xr() -> Result<()> {
    let (mut world, sender) = World::connected_with_rrtr(true)?;
    let (ssrc, _, _) = world.sender_stream(sender);
    world.send_media(sender, Duration::from_secs(3))?;

    // webrtc-stats: `roundTripTime` exists while the latest sender report came with a DLRR
    // block that measures one. When reports go out is the RTCP schedule's business, so the
    // clock is driven until the latest report is such a one, not for a fixed time.
    let started = world.now;
    let give_up = started + Duration::from_secs(30);
    // What the report said each time it changed: (ms, roundTripTime, measurements).
    let mut seen: Vec<(u128, Option<f64>, u64)> = Vec::new();
    loop {
        let (rtt, _, measurements) =
            remote_outbound_rtt(&mut world, ssrc).expect("remote-outbound stats");
        if seen.last().map(|(_, rtt, n)| (*rtt, *n)) != Some((rtt, measurements)) {
            seen.push(((world.now - started).as_millis(), rtt, measurements));
        }
        if rtt.is_some() || world.now >= give_up {
            break;
        }
        let until = world.now + Duration::from_millis(5);
        world.run_until(until)?;
    }
    let (rtt, total, measurements) =
        remote_outbound_rtt(&mut world, ssrc).expect("remote-outbound stats");
    assert!(
        measurements > 0,
        "the DLRR blocks gave round trip times: {rtt:?} {total} {measurements}; {seen:?}"
    );
    let rtt = rtt.unwrap_or_else(|| panic!("a round trip time; the report over time: {seen:?}"));
    assert!(
        (0.0..1.0).contains(&rtt),
        "a plausible round trip time on a virtual network: {rtt}"
    );
    assert!(total >= rtt);
    Ok(())
}

/// Without it negotiated, no reference times are sent and the round trip time stays unmeasured.
#[test]
fn without_rrtr_the_remote_outbound_round_trip_time_is_unmeasured() -> Result<()> {
    let (mut world, sender) = World::connected()?;
    let (ssrc, _, _) = world.sender_stream(sender);
    world.send_media(sender, Duration::from_secs(3))?;

    let (rtt, _, measurements) =
        remote_outbound_rtt(&mut world, ssrc).expect("remote-outbound stats");
    assert_eq!(rtt, None);
    assert_eq!(measurements, 0);
    Ok(())
}
