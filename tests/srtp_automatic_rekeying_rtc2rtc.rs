//! RFC 5764 section 4.4: "Once the key lifetime has been reached, a new DTLS session SHOULD be
//! established" (the SRTP keys come from the association, section 4.1.2). The connection asks
//! for one by itself when a master key has a sixteenth of its lifetime left: it raises
//! negotiation-needed, and the next offer carries a new `a=tls-id` with new ICE credentials
//! (RFC 9429 section 5.8.3). The application only answers `negotiationneeded`; media goes on
//! under the old keys until the new handshake hands over the new ones, and the data channel
//! goes on over the new association (RFC 8841 section 10.5).
//!
//! Two `rtci` peers exchange datagrams in memory, on a virtual clock, with a key lifetime of
//! 320 SRTP packets and an audio stream of 900 packets, one every 20 ms.

use anyhow::{Result, bail};
use bytes::{Bytes, BytesMut};
use rtci::data_channel::RTCDataChannelId;
use rtci::media_stream::MediaStreamTrack;
use rtci::peer_connection::configuration::RTCConfigurationBuilder;
use rtci::peer_connection::configuration::media_engine::{MIME_TYPE_OPUS, MediaEngine};
use rtci::peer_connection::configuration::setting_engine::SettingEngineBuilder;
use rtci::peer_connection::event::{RTCDataChannelEvent, RTCPeerConnectionEvent};
use rtci::peer_connection::message::RTCMessage;
use rtci::peer_connection::state::{RTCPeerConnectionState, RTCSignalingState};
use rtci::peer_connection::transport::{
    CandidateConfig, CandidateHostConfig, RTCDtlsRole, RTCDtlsTransportState, RTCIceCandidate,
    RTCIceCandidateInit,
};
use rtci::peer_connection::{RTCPeerConnection, RTCPeerConnectionBuilder};
use rtci::rtp_transceiver::RTCRtpSenderId;
use rtci::rtp_transceiver::rtp_sender::{
    RTCRtpCodec, RTCRtpCodingParameters, RTCRtpEncodingParameters, RtpCodecKind,
};
use rtci::sansio::Protocol;
use rtci::shared::{TaggedBytesMut, TransportContext, TransportProtocol};
use rtci::srtp::keying::KeyLifetime;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

const AUDIO_SSRC: u32 = 4343;
/// SRTP packets per master key: the renewal starts with 20 left.
const LIFETIME: u64 = 320;
/// Packets sent in all: well past two lifetimes.
const PACKETS: u16 = 900;
const PACKET_INTERVAL: Duration = Duration::from_millis(20);

fn host(addr: SocketAddr) -> Result<RTCIceCandidateInit> {
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
    Ok(RTCIceCandidate::from(&candidate).to_json()?)
}

struct Peer {
    pc: RTCPeerConnection,
    addr: SocketAddr,
    inbox: Vec<TaggedBytesMut>,
    events: Vec<RTCPeerConnectionEvent>,
    /// Events not looked at by the signalling step yet.
    unseen: usize,
    rtp: usize,
    channel: Option<RTCDataChannelId>,
    messages: Vec<Vec<u8>>,
}

impl Peer {
    fn new(addr: &str, setting_engine: SettingEngineBuilder, now: Instant) -> Result<Self> {
        let mut media_engine = MediaEngine::default();
        media_engine.register_default_codecs()?;
        let pc = RTCPeerConnectionBuilder::new()
            .with_configuration(RTCConfigurationBuilder::new().build())
            .with_media_engine(media_engine)
            .with_setting_engine(setting_engine.build())
            .build(now)?;
        Ok(Self {
            pc,
            addr: addr.parse()?,
            inbox: Vec::new(),
            events: Vec::new(),
            unseen: 0,
            rtp: 0,
            channel: None,
            messages: Vec::new(),
        })
    }

    fn turn(&mut self) -> Result<Vec<TaggedBytesMut>> {
        for datagram in self.inbox.drain(..) {
            self.pc.handle_read(datagram)?;
        }
        while let Some(event) = self.pc.poll_event() {
            if let RTCPeerConnectionEvent::OnDataChannel(RTCDataChannelEvent::OnOpen(id)) = &event {
                self.channel = Some(*id);
            }
            self.events.push(event);
        }
        while let Some(message) = self.pc.poll_read() {
            match message.message {
                RTCMessage::RtpPacket(_, packet) if packet.header.ssrc == AUDIO_SSRC => {
                    self.rtp += 1
                }
                RTCMessage::DataChannelMessage(_, m) => self.messages.push(m.data.to_vec()),
                _ => {}
            }
        }
        let mut written = Vec::new();
        while let Some(datagram) = self.pc.poll_write() {
            written.push(datagram);
        }
        Ok(written)
    }

    /// The other peer's `datagrams`, on the 5-tuple each was sent on: after a new DTLS
    /// association moved the peers to new ports, what still leaves on the previous path
    /// arrives on it.
    fn deliver(&mut self, datagrams: Vec<TaggedBytesMut>, now: Instant) {
        for datagram in datagrams {
            self.inbox.push(TaggedBytesMut {
                now,
                transport: TransportContext {
                    local_addr: datagram.transport.peer_addr,
                    peer_addr: datagram.transport.local_addr,
                    ecn: None,
                    transport_protocol: TransportProtocol::UDP,
                },
                message: datagram.message,
            });
        }
    }

    fn attribute(&self, key: &str) -> String {
        let sdp = self
            .pc
            .local_description()
            .expect("a local description")
            .sdp;
        let prefix = format!("a={key}:");
        sdp.lines()
            .find_map(|line| line.trim_end().strip_prefix(prefix.as_str()))
            .unwrap_or_else(|| panic!("a={key}"))
            .to_owned()
    }

    fn dtls_state(&mut self, now: Instant) -> Option<RTCDtlsTransportState> {
        self.pc
            .get_stats(now, rtci::statistics::StatsSelector::None)
            .transport()
            .map(|t| t.dtls_state)
    }

    fn channel_closed(&self) -> bool {
        self.events.iter().any(|e| {
            matches!(
                e,
                RTCPeerConnectionEvent::OnDataChannel(
                    RTCDataChannelEvent::OnClose(_) | RTCDataChannelEvent::OnClosing(_)
                )
            )
        })
    }
}

fn audio_track() -> MediaStreamTrack {
    MediaStreamTrack::new(
        "stream".to_owned(),
        "audio".to_owned(),
        "audio".to_owned(),
        RtpCodecKind::Audio,
        vec![RTCRtpEncodingParameters {
            rtp_coding_parameters: RTCRtpCodingParameters {
                ssrc: Some(AUDIO_SSRC),
                ..Default::default()
            },
            codec: RTCRtpCodec {
                mime_type: MIME_TYPE_OPUS.to_owned(),
                clock_rate: 48000,
                channels: 2,
                ..Default::default()
            },
            ..Default::default()
        }],
    )
}

/// What an application does on `negotiationneeded`: an offer, the peer's answer, and the
/// candidates of the (possibly new) ICE generation trickled both ways.
fn negotiate(peers: &mut [Peer; 2], offerer: usize, now: Instant) -> Result<()> {
    let answerer = 1 - offerer;
    let offer = peers[offerer].pc.create_offer(None)?;
    peers[offerer]
        .pc
        .set_local_description(now, offer.clone())?;
    peers[answerer].pc.set_remote_description(now, offer)?;
    let answer = peers[answerer].pc.create_answer(None)?;
    peers[answerer]
        .pc
        .set_local_description(now, answer.clone())?;
    peers[offerer].pc.set_remote_description(now, answer)?;
    for i in 0..2 {
        // A new DTLS association runs on new 3-tuples (RFC 8842 section 5.1): a peer whose
        // ICE transport dropped its candidates for it gathers on the next port.
        let holds_none = peers[i]
            .pc
            .dtls_transports()
            .iter()
            .all(|t| t.ice_transport().get_local_candidates().is_empty());
        if holds_none {
            let port = peers[i].addr.port();
            peers[i].addr.set_port(port + 1);
        }
        let candidate = host(peers[i].addr)?;
        peers[i].pc.add_local_candidate(candidate.clone())?;
        peers[1 - i].pc.add_remote_candidate(candidate)?;
    }
    Ok(())
}

struct Outcome {
    peers: [Peer; 2],
    /// `(tls-id, ice-ufrag)` of each peer's local description once connected.
    first: [(String, String); 2],
    /// Exchanges the application made because of `negotiationneeded` after the connection.
    renegotiations: usize,
    sent: u16,
    now: Instant,
}

/// Connects peer 0 (offerer, audio sender, data channel) to peer 1, then sends `PACKETS`
/// audio packets and answers every `negotiationneeded` from then on as an application does.
/// `settings[i]` builds peer `i`. Stops early when a connection fails.
fn run(settings: [SettingEngineBuilder; 2]) -> Result<Outcome> {
    let start = Instant::now();
    let [s0, s1] = settings;
    let mut peers = [
        Peer::new("10.0.1.1:5000", s0, start)?,
        Peer::new("10.0.1.2:5000", s1, start)?,
    ];
    let sender: RTCRtpSenderId = peers[0].pc.add_track(audio_track())?;
    peers[0].pc.create_data_channel("survives", None)?;
    negotiate(&mut peers, 0, start)?;

    let mut now = start;
    let mut next_packet = start;
    let mut sent = 0u16;
    let mut first = None;
    let mut renegotiations = 0;
    for _ in 0..1_000_000 {
        let out = peers[0].turn()?;
        peers[1].deliver(out, now);
        let out = peers[1].turn()?;
        peers[0].deliver(out, now);
        if peers
            .iter()
            .any(|p| p.pc.connection_state() == RTCPeerConnectionState::Failed)
        {
            break;
        }
        let connected = peers
            .iter()
            .all(|p| p.pc.connection_state() == RTCPeerConnectionState::Connected)
            && peers[1].channel.is_some();
        if connected && first.is_none() {
            first = Some([0, 1].map(|i| {
                (
                    peers[i].attribute("tls-id"),
                    peers[i].attribute("ice-ufrag"),
                )
            }));
            for p in peers.iter_mut() {
                p.unseen = p.events.len();
            }
        }
        if first.is_some() {
            // The application answers negotiation-needed, peer 0 first.
            for i in 0..2 {
                let raised = peers[i].events[peers[i].unseen..]
                    .iter()
                    .any(|e| matches!(e, RTCPeerConnectionEvent::OnNegotiationNeededEvent));
                peers[i].unseen = peers[i].events.len();
                if raised
                    && peers
                        .iter()
                        .all(|p| p.pc.signaling_state() == RTCSignalingState::Stable)
                {
                    negotiate(&mut peers, i, now)?;
                    renegotiations += 1;
                }
            }
        }
        if !peers[0].inbox.is_empty() || !peers[1].inbox.is_empty() {
            continue;
        }
        if first.is_some() && now >= next_packet {
            if sent == PACKETS {
                break;
            }
            sent += 1;
            next_packet = now + PACKET_INTERVAL;
            // Refused once a key is exhausted: the error is the pipeline's.
            let _ = peers[0].pc.rtp_sender(sender).expect("sender").write_rtp(
                now,
                rtci::rtp::Packet {
                    header: rtci::rtp::header::Header {
                        version: 2,
                        payload_type: 111,
                        sequence_number: sent,
                        timestamp: u32::from(sent) * 960,
                        ssrc: AUDIO_SSRC,
                        ..Default::default()
                    },
                    payload: Bytes::from_static(&[0xF8, 0xFF, 0xFE]),
                },
            );
            continue;
        }
        let mut next = [peers[0].pc.poll_timeout(), peers[1].pc.poll_timeout()]
            .into_iter()
            .flatten()
            .min()
            .unwrap_or(now + PACKET_INTERVAL);
        if first.is_some() {
            next = next.min(next_packet);
        }
        now = next.max(now);
        for p in peers.iter_mut() {
            p.pc.handle_timeout(now)?;
        }
    }
    let Some(first) = first else {
        bail!("the peers never connected")
    };
    Ok(Outcome {
        peers,
        first,
        renegotiations,
        sent,
        now,
    })
}

fn lifetime() -> Option<KeyLifetime> {
    Some(KeyLifetime {
        srtp_packets: LIFETIME,
        srtcp_packets: 1 << 31,
    })
}

/// Peer 0's media, keyed by an association whose renewal peer `renewer` asks for when its key
/// (outbound for peer 0, inbound for peer 1) nears the end: every packet arrives, the
/// connection never fails, the association and the ICE credentials are new, and a message on
/// the data channel opened before arrives after, on the channel that never closed.
fn renewal(renewer: usize, answering_role: RTCDtlsRole) -> Result<()> {
    let setting = |i: usize| {
        let s = SettingEngineBuilder::new();
        let s = if i == renewer {
            s.with_srtp_key_lifetime(lifetime())
        } else {
            s
        };
        if i == 1 {
            s.with_answering_dtls_role(answering_role)
        } else {
            s
        }
    };
    let mut outcome = run([setting(0), setting(1)])?;
    let Outcome { peers, sent, .. } = &mut outcome;
    for p in peers.iter() {
        assert_ne!(
            p.pc.connection_state(),
            RTCPeerConnectionState::Failed,
            "the connection failed: {:?}",
            p.events
        );
    }
    assert_eq!(*sent, PACKETS);
    let expiring = peers[renewer]
        .events
        .iter()
        .position(|e| matches!(e, RTCPeerConnectionEvent::OnSrtpKeyLifetimeExpiring { .. }))
        .expect("the key lifetime event");
    assert!(
        peers[renewer].events[expiring..]
            .iter()
            .any(|e| matches!(e, RTCPeerConnectionEvent::OnNegotiationNeededEvent)),
        "negotiation-needed follows the key lifetime event"
    );
    assert!(outcome.renegotiations >= 1);
    let (peers, first) = (&mut outcome.peers, &outcome.first);
    for i in 0..2 {
        assert_ne!(
            peers[i].attribute("tls-id"),
            first[i].0,
            "peer {i}: a new DTLS association"
        );
        assert_ne!(
            peers[i].attribute("ice-ufrag"),
            first[i].1,
            "peer {i}: with an ICE restart"
        );
    }
    // Two lifetimes' worth crossed one key each: every packet arrived.
    assert_eq!(
        peers[1].rtp,
        usize::from(PACKETS),
        "packets lost across the re-key"
    );

    let mut now = outcome.now;
    assert_eq!(
        peers[0].dtls_state(now),
        Some(RTCDtlsTransportState::Connected)
    );
    let channel = peers[0].channel.expect("the channel");
    peers[0]
        .pc
        .data_channel(channel)
        .expect("the channel")
        .send(now, BytesMut::from(&b"after the re-key"[..]))?;
    for _ in 0..50 {
        now += Duration::from_millis(10);
        for p in peers.iter_mut() {
            p.pc.handle_timeout(now)?;
        }
        let out = peers[0].turn()?;
        peers[1].deliver(out, now);
        let out = peers[1].turn()?;
        peers[0].deliver(out, now);
    }
    assert_eq!(
        peers[1].messages.last().map(Vec::as_slice),
        Some(&b"after the re-key"[..])
    );
    assert!(!peers[0].channel_closed() && !peers[1].channel_closed());
    Ok(())
}

/// The sender's outbound key nears its end; the sender, DTLS client, renews.
#[test]
fn the_sender_renews_the_association_before_its_key_runs_out_as_dtls_client() -> Result<()> {
    renewal(0, RTCDtlsRole::Server)
}

/// The sender's outbound key nears its end; the sender, DTLS server, renews.
#[test]
fn the_sender_renews_the_association_before_its_key_runs_out_as_dtls_server() -> Result<()> {
    renewal(0, RTCDtlsRole::Client)
}

/// The receiver's inbound key nears its end (only it has the short lifetime); the receiver,
/// the answerer of the first exchange, renews with an offer of its own.
#[test]
fn the_receiver_renews_the_association_before_its_inbound_key_runs_out() -> Result<()> {
    renewal(1, RTCDtlsRole::Client)
}

/// `with_srtp_automatic_rekeying(false)`: the application gets the key lifetime event and no
/// negotiation-needed; when it does nothing, the transport fails at the limit.
#[test]
fn without_automatic_rekeying_the_transport_fails_at_the_limit() -> Result<()> {
    let outcome = run([
        SettingEngineBuilder::new()
            .with_srtp_key_lifetime(lifetime())
            .with_srtp_automatic_rekeying(false),
        SettingEngineBuilder::new(),
    ])?;
    let events = &outcome.peers[0].events;
    let expiring = events
        .iter()
        .position(|e| matches!(e, RTCPeerConnectionEvent::OnSrtpKeyLifetimeExpiring { .. }))
        .expect("the key lifetime event");
    assert!(
        !events[expiring..]
            .iter()
            .any(|e| matches!(e, RTCPeerConnectionEvent::OnNegotiationNeededEvent)),
        "no negotiation-needed: {events:?}"
    );
    assert_eq!(outcome.renegotiations, 0);
    assert_eq!(
        outcome.peers[0].pc.connection_state(),
        RTCPeerConnectionState::Failed
    );
    assert!(outcome.peers[1].rtp <= LIFETIME as usize);
    Ok(())
}
