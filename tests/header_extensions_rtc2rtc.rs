//! Header extensions on the wire between two `rtc` peer connections, in virtual time: the
//! one-byte / two-byte form of a stream as `a=extmap-allow-mixed` was negotiated (RFC 8285
//! sections 4.1.2 and 6), and RFC 6904 header extension encryption once an extension is
//! negotiated in its encrypted form.

use anyhow::{Result, bail};
use bytes::Bytes;
use rtc::interceptor::Registry;
use rtc::peer_connection::configuration::RTCConfigurationBuilder;
use rtc::peer_connection::configuration::interceptor_registry::register_default_interceptors;
use rtc::peer_connection::configuration::media_engine::MediaEngine;
use rtc::peer_connection::event::RTCPeerConnectionEvent;
use rtc::peer_connection::message::RTCMessage;
use rtc::peer_connection::sdp::RTCSessionDescription;
use rtc::peer_connection::state::RTCPeerConnectionState;
use rtc::peer_connection::transport::{
    CandidateConfig, CandidateHostConfig, RTCIceCandidate, RTCIceCandidateInit,
};
use rtc::peer_connection::{RTCPeerConnection, RTCPeerConnectionBuilder};
use rtc::rtp::header::{ExtensionForm, Header};
use rtc::rtp_transceiver::rtp_sender::{RTCRtpEncodingParameters, RtpCodecKind};
use rtc::rtp_transceiver::{RTCRtpSenderId, RTCRtpTransceiverDirection, RTCRtpTransceiverInit};
use rtc::sansio::Protocol;
use rtc::shared::marshal::Unmarshal;
use rtc::shared::{TaggedBytesMut, TransportContext, TransportProtocol};
use std::net::SocketAddr;
use std::time::{Duration, Instant};

const CONNECT_WITHIN: Duration = Duration::from_secs(10);
const AUDIO_LEVEL: &str = "urn:ietf:params:rtp-hdrext:ssrc-audio-level";

struct Peer {
    pc: RTCPeerConnection,
    addr: SocketAddr,
    connected: bool,
    states: Vec<RTCPeerConnectionState>,
    /// The headers of the RTP packets `poll_read` yielded.
    read_rtp: Vec<Header>,
}

impl Peer {
    fn new(addr: &str) -> Result<Self> {
        let mut media_engine = MediaEngine::default();
        media_engine.register_default_codecs()?;
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

/// The RTP header of an SRTP packet on the wire (SRTP leaves the header in the clear, RFC
/// 3711 section 3.1, apart from RFC 6904 elements), or `None` for anything else.
fn wire_rtp_header(datagram: &[u8]) -> Option<Header> {
    if datagram.len() < 12 || datagram[0] >> 6 != 2 || (192..=223).contains(&datagram[1]) {
        return None;
    }
    Header::unmarshal(&mut &datagram[..]).ok()
}

struct World {
    peers: [Peer; 2],
    now: Instant,
    /// The headers of the RTP packets the first peer put on the wire.
    wire: Vec<Header>,
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
                    self.wire.push(header);
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
                    peer.read_rtp.push(packet.header);
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

    /// The first peer sends `kind`; the second answers, its answer passed through `edit`
    /// before the first applies it. Connected over host candidates.
    fn connected(
        kind: RtpCodecKind,
        edit: impl Fn(String) -> String,
    ) -> Result<(Self, RTCRtpSenderId)> {
        let mut world = World {
            peers: [Peer::new("10.0.0.1:5000")?, Peer::new("10.0.0.2:5000")?],
            now: Instant::now(),
            wire: Vec::new(),
        };
        let transceiver = world.peers[0].pc.add_transceiver_from_kind(
            kind,
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
        world.peers[0]
            .pc
            .set_remote_description(now, RTCSessionDescription::answer(edit(answer.sdp))?)?;
        for i in 0..2 {
            let candidate = world.peers[i].candidate()?;
            world.peers[i].pc.add_local_candidate(candidate.clone())?;
            world.peers[1 - i].pc.add_remote_candidate(candidate)?;
        }
        let start = world.now;
        while !world.peers.iter().all(|p| p.connected) {
            if world.now.duration_since(start) >= CONNECT_WITHIN {
                bail!(
                    "not connected: {:?} / {:?}",
                    world.peers[0].states,
                    world.peers[1].states
                );
            }
            let next = world.now + Duration::from_millis(10);
            world.run_until(next)?;
        }
        Ok((world, sender))
    }

    /// Writes a packet on the sender's stream with the given header extension elements.
    fn send(&mut self, sender: RTCRtpSenderId, seq: u16, elements: &[(u8, &[u8])]) -> Result<()> {
        let now = self.now;
        let (ssrc, pt) = {
            let mut sender = self.peers[0].pc.rtp_sender(sender).expect("sender");
            let parameters = sender.get_parameters();
            (
                parameters.encodings[0]
                    .rtp_coding_parameters
                    .ssrc
                    .expect("an SSRC"),
                parameters.rtp_parameters.codecs[0].payload_type,
            )
        };
        let mut header = Header {
            version: 2,
            payload_type: pt,
            sequence_number: seq,
            timestamp: u32::from(seq) * 960,
            ssrc,
            marker: true,
            ..Default::default()
        };
        for (id, value) in elements {
            header.set_extension_upgrading(*id, Bytes::copy_from_slice(value))?;
        }
        self.peers[0]
            .pc
            .rtp_sender(sender)
            .expect("sender")
            .write_rtp(
                now,
                rtc::rtp::Packet {
                    header,
                    payload: Bytes::from(vec![0x10u8; 100]),
                },
            )?;
        self.pump()?;
        self.run_until(now + Duration::from_millis(20))
    }
}

/// The forms of the headers on the wire after the first, which carried a 20-byte element.
fn forms_after_a_long_element(
    edit: impl Fn(String) -> String,
) -> Result<Vec<Option<ExtensionForm>>> {
    let (mut world, sender) = World::connected(RtpCodecKind::Video, edit)?;
    // An element of 20 bytes fits the two-byte form only (RFC 8285 section 4.2: 1 to 16).
    world.send(sender, 100, &[(13, &[0xAB; 20])])?;
    for seq in 101..106 {
        world.send(sender, seq, &[])?;
    }
    assert_eq!(6, world.wire.len(), "every packet went out");
    assert_eq!(Some(ExtensionForm::TwoByte), world.wire[0].extension_form());
    Ok(world.wire[1..].iter().map(|h| h.extension_form()).collect())
}

/// RFC 8285 section 4.1.2: "A stream MUST contain only one-byte headers or only two-byte
/// headers unless it is known that all recipients support mixing", by `a=extmap-allow-mixed`
/// in the offer and the answer (section 6: "In the cases where the attribute has been
/// excluded, both clients SHALL NOT use mixed one-byte and two-byte extensions in the same
/// RTP stream"). With it, each packet takes the smallest form; without it, a stream that sent
/// the two-byte form keeps it.
#[test]
fn a_stream_mixes_header_forms_only_when_extmap_allow_mixed_was_negotiated() -> Result<()> {
    let mixed = forms_after_a_long_element(|sdp| sdp)?;
    assert!(
        mixed.iter().all(|f| *f == Some(ExtensionForm::OneByte)),
        "with mixing, later packets are one-byte: {mixed:?}"
    );
    let unmixed = forms_after_a_long_element(|sdp| sdp.replace("a=extmap-allow-mixed\r\n", ""))?;
    assert!(
        unmixed.iter().all(|f| *f == Some(ExtensionForm::TwoByte)),
        "without mixing, the stream stays two-byte: {unmixed:?}"
    );
    Ok(())
}

/// RFC 6904 sections 3 and 4: once the client-to-mixer audio level is negotiated encrypted
/// (both peers offer it best effort and answer the encrypted form), its element is encrypted
/// on the wire and decrypted for the receiving application; the other elements stay in the
/// clear.
#[test]
fn an_extension_negotiated_encrypted_is_encrypted_on_the_wire() -> Result<()> {
    let (mut world, sender) = World::connected(RtpCodecKind::Audio, |sdp| sdp)?;
    let level = world.peers[0]
        .pc
        .rtp_sender(sender)
        .expect("sender")
        .get_parameters()
        .rtp_parameters
        .header_extensions
        .iter()
        .find(|e| e.uri == AUDIO_LEVEL)
        .cloned()
        .expect("the audio level is negotiated");
    assert!(
        level.encrypted,
        "negotiated in its encrypted form: {level:?}"
    );
    let id = u8::try_from(level.id)?;

    for seq in 0..8u16 {
        world.send(sender, 200 + seq, &[(id, &[0x2A])])?;
    }
    assert_eq!(8, world.wire.len());
    let on_wire: Vec<Option<u8>> = world
        .wire
        .iter()
        .map(|h| h.get_extension(id).and_then(|v| v.first().copied()))
        .collect();
    assert!(
        on_wire.iter().all(|v| v.is_some()) && on_wire.iter().any(|v| *v != Some(0x2A)),
        "the element is encrypted on the wire: {on_wire:?}"
    );
    let received: Vec<Option<u8>> = world.peers[1]
        .read_rtp
        .iter()
        .map(|h| h.get_extension(id).and_then(|v| v.first().copied()))
        .collect();
    assert_eq!(
        vec![Some(0x2A); 8],
        received,
        "and decrypted for the receiver"
    );
    Ok(())
}
