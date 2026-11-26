//! FEC statistics between two `rtci` peer connections in virtual time: VP8 in RED with ULPFEC
//! in RED packets of its own (RFC 2198, RFC 5109 section 14.2, the form libwebrtc sends), a
//! fixed amount of FEC, and a network that loses packets (NACK is on, the default interceptors
//! negotiate it for video; the first test's stream has no RTX, so its repairs are the packets
//! again, which the network loses as it lost the first). What the receiver's
//! webrtc-stats say (`fecPacketsReceived`, `fecBytesReceived`, `fecPacketsDiscarded`, 8.5)
//! and what the engine's own FEC counts say (`RTCPeerConnection::fec_stats`) are checked
//! against what crossed the wire.

use anyhow::{Context, Result, bail};
use bytes::Bytes;
use rtci::interceptor::{RedPlacement, Registry, Slot, UlpfecReceiveBuilder, UlpfecSendBuilder};
use rtci::peer_connection::configuration::RTCConfigurationBuilder;
use rtci::peer_connection::configuration::behaviour_profile::BehaviourProfile;
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
use rtci::statistics::StatsSelector;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

const CONNECT_WITHIN: Duration = Duration::from_secs(10);
const VP8_PT: u8 = 96;
const RED_PT: u8 = 116;
const ULPFEC_PT: u8 = 117;

fn codec(mime_type: &str) -> RTCRtpCodec {
    RTCRtpCodec {
        mime_type: mime_type.to_owned(),
        clock_rate: 90000,
        channels: 0,
        sdp_fmtp_line: String::new(),
        rtcp_feedback: vec![],
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
    /// VP8, RED and ULPFEC, no RTX format; the default interceptors (NACK among them: a repair
    /// is the packet again, RFC 4585 section 6.2.1) with a ULPFEC encoder that
    /// sends one FEC packet for every two media packets whatever the loss, reading the packets
    /// as they leave (its wire tap), and the decoder.
    fn new(addr: &str) -> Result<Self> {
        let mut media_engine = MediaEngine::default();
        for (mime_type, payload_type) in [
            (MIME_TYPE_VP8, VP8_PT),
            ("video/red", RED_PT),
            ("video/ulpfec", ULPFEC_PT),
        ] {
            media_engine.register_codec(
                RTCRtpCodecParameters {
                    rtp_codec: codec(mime_type),
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
    /// The `Chrome` behaviour profile's codecs and interceptors, nothing added by hand.
    fn chrome(addr: &str) -> Result<Self> {
        let mut media_engine = MediaEngine::for_profile(BehaviourProfile::Chrome);
        media_engine.register_default_codecs()?;
        let registry = register_default_interceptors(Registry::new(), &mut media_engine)?;
        let pc = RTCPeerConnectionBuilder::new()
            .with_configuration(RTCConfigurationBuilder::new().build())
            .with_setting_engine(
                SettingEngineBuilder::new()
                    .with_behaviour_profile(BehaviourProfile::Chrome)
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
    /// The RTP packets of the first peer the network lost.
    lost: u64,
    /// RTP packets of the first peer that crossed the wire, lost ones included: each
    /// sequence number once. The default interceptors negotiate NACK for video, and without an
    /// RTX stream a repair is the packet again (RFC 4585 section 6.2.1), which this network
    /// loses as it lost the first.
    sent_rtp: u64,
    /// The sequence numbers counted in `sent_rtp`.
    seen: std::collections::HashSet<u16>,
    /// Packets sent again under a sequence number already seen.
    sent_again: u64,
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
                // The network loses one RTP packet of the first peer in five: media and FEC
                // alike, as they share the RED payload type and sequence space.
                if i == 0
                    && let Some(header) = wire_rtp_header(&data)
                    && header.payload_type == RED_PT
                {
                    let first = self.seen.insert(header.sequence_number);
                    if first {
                        self.sent_rtp += 1;
                    } else {
                        self.sent_again += 1;
                    }
                    if header.sequence_number % 5 == 2 {
                        if first {
                            self.lost += 1;
                        }
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
        Self::connected_with(Peer::new)
    }

    fn connected_with(make: fn(&str) -> Result<Peer>) -> Result<(Self, RTCRtpSenderId)> {
        let mut world = World {
            peers: [make("10.0.0.1:5000")?, make("10.0.0.2:5000")?],
            now: Instant::now(),
            lost: 0,
            sent_rtp: 0,
            seen: std::collections::HashSet::new(),
            sent_again: 0,
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

    /// Writes a one-packet VP8 frame with sequence number `seq`.
    fn send(&mut self, sender: RTCRtpSenderId, seq: u16) -> Result<()> {
        let now = self.now;
        let mut rtp_sender = self.peers[0].pc.rtp_sender(sender).expect("sender");
        let ssrc = rtp_sender.get_parameters().encodings[0]
            .rtp_coding_parameters
            .ssrc
            .expect("an SSRC");
        let mut payload = vec![0x10u8];
        payload.extend((0..200u16).map(|i| (i as u8) ^ (seq as u8)));
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

    fn ssrc(&mut self, sender: RTCRtpSenderId) -> u32 {
        let mut rtp_sender = self.peers[0].pc.rtp_sender(sender).expect("sender");
        rtp_sender.get_parameters().encodings[0]
            .rtp_coding_parameters
            .ssrc
            .expect("an SSRC")
    }
}

/// webrtc-stats 8.5: `fecPacketsReceived` is "Total number of RTP FEC packets received for
/// this SSRC" and `fecBytesReceived` their payload bytes, "a subset of bytesReceived"; FEC in
/// RED packets of the media stream is FEC received for that SSRC. `fecPacketsDiscarded` counts
/// those "where the error correction payload was discarded", a subset of
/// `fecPacketsReceived`. The engine's counts add what the sender sent and what FEC rebuilt.
#[test]
fn fec_in_red_is_counted_by_both_ends_and_what_it_rebuilt_is_reported() -> Result<()> {
    let (mut world, sender) = World::connected()?;
    for seq in 1000..1060 {
        world.send(sender, seq)?;
    }
    let until = world.now + Duration::from_secs(2);
    world.run_until(until)?;
    let ssrc = world.ssrc(sender);
    assert!(world.lost > 0, "the network lost packets");

    let sent = world.peers[0].pc.fec_stats().sent;
    assert_eq!(sent.len(), 1, "{sent:?}");
    assert_eq!(sent[0].ssrc, ssrc);
    // One FEC packet per two media packets.
    assert_eq!(sent[0].fec_packets_sent, 30, "{sent:?}");
    assert!(sent[0].fec_bytes_sent > 30 * 200, "{sent:?}");
    assert_eq!(world.sent_rtp, 60 + 30, "every media and FEC packet left");
    // A lost packet asked for again is sent again, as it was (no RTX stream here): it
    // reaches the wire, where it used to be refused by the SRTP sender.
    assert!(
        world.sent_again > 0,
        "the repairs the receiver asked for left too"
    );

    let now = world.now;
    let report = world.peers[1].pc.get_stats(now, StatsSelector::None);
    let inbound = report
        .inbound_rtp_streams()
        .find(|stream| stream.received_rtp_stream_stats.rtp_stream_stats.ssrc == ssrc)
        .context("an inbound-rtp for the stream")?;
    let received = world.peers[1].pc.fec_stats().received;
    assert_eq!(received.len(), 1, "{received:?}");
    let fec = received[0];
    assert_eq!(fec.ssrc, ssrc);

    // What arrived: everything that left but what the network lost.
    assert_eq!(
        inbound.received_rtp_stream_stats.packets_received,
        world.sent_rtp - world.lost
    );
    assert!(fec.fec_packets_received > 0, "{fec:?}");
    assert!(
        fec.fec_packets_received < sent[0].fec_packets_sent,
        "some FEC was lost"
    );
    assert_eq!(fec.fec_packets_in_red, fec.fec_packets_received);
    assert_eq!(inbound.fec_packets_received, fec.fec_packets_received);
    assert_eq!(inbound.fec_bytes_received, fec.fec_bytes_received);
    assert!(inbound.fec_bytes_received > 0);
    assert!(inbound.fec_bytes_received < inbound.bytes_received);

    // What FEC did: rebuilt lost media, handed to the application.
    assert!(fec.packets_recovered > 0, "{fec:?}");
    let delivered = world.peers[1].read_rtp as u64;
    assert!(
        delivered >= 60 - world.lost + fec.packets_recovered,
        "{delivered} {fec:?}"
    );
    // Every FEC packet that rebuilt nothing was discarded, for a reason.
    assert_eq!(
        inbound.fec_packets_discarded,
        Some(fec.fec_packets_discarded)
    );
    assert_eq!(
        fec.fec_packets_discarded,
        fec.discarded_unneeded + fec.discarded_expired + fec.discarded_rejected
    );
    assert!(
        fec.discarded_unneeded > 0,
        "FEC for pairs that lost nothing: {fec:?}"
    );
    assert!(fec.fec_packets_discarded + fec.packets_recovered <= fec.fec_packets_received);
    Ok(())
}

/// The `Chrome` behaviour profile offers video `red` and `ulpfec` as Chromium does
/// (`DefaultInterceptorOptions::video_red_ulpfec`): between two such peers the video goes in
/// RED, and once the receiver reports loss FEC follows and rebuilds packets the network lost
/// before a retransmission could (NACK is negotiated too).
#[test]
fn in_the_chrome_profile_fec_in_red_rebuilds_what_the_network_lost() -> Result<()> {
    let (mut world, sender) = World::connected_with(Peer::chrome)?;
    for seq in 1000..1150 {
        world.send(sender, seq)?;
    }
    let until = world.now + Duration::from_secs(2);
    world.run_until(until)?;
    assert!(world.lost > 0, "the network lost packets");
    let sent = world.peers[0].pc.fec_stats().sent;
    assert_eq!(sent.len(), 1, "FEC was sent: {sent:?}");
    let received = world.peers[1].pc.fec_stats().received;
    assert_eq!(received.len(), 1, "{received:?}");
    assert!(received[0].fec_packets_in_red > 0, "{received:?}");
    assert!(received[0].packets_recovered > 0, "{received:?}");
    Ok(())
}
