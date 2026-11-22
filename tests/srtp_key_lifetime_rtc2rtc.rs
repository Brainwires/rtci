//! SRTP in the peer connection (RFC 3711 sections 3.3.2 and 9.2, RFC 5764 section 4.1.2): the
//! replay window bound, and a master key that reaches its lifetime: the connection is told
//! ahead, and at the limit the DTLS transport fails with the reason.
//!
//! The peers exchange datagrams in memory, on a virtual clock.

use anyhow::Result;
use bytes::Bytes;
use rtc::media_stream::MediaStreamTrack;
use rtc::peer_connection::configuration::RTCConfigurationBuilder;
use rtc::peer_connection::configuration::media_engine::{MIME_TYPE_OPUS, MediaEngine};
use rtc::peer_connection::configuration::setting_engine::SettingEngineBuilder;
use rtc::peer_connection::event::RTCPeerConnectionEvent;
use rtc::peer_connection::message::RTCMessage;
use rtc::peer_connection::rtc_error::RTCErrorDetailType;
use rtc::peer_connection::state::RTCPeerConnectionState;
use rtc::peer_connection::transport::{
    CandidateConfig, CandidateHostConfig, RTCDtlsRole, RTCIceCandidate, RTCIceCandidateInit,
};
use rtc::peer_connection::{RTCPeerConnection, RTCPeerConnectionBuilder};
use rtc::rtp_transceiver::rtp_sender::{
    RTCRtpCodec, RTCRtpCodingParameters, RTCRtpEncodingParameters, RtpCodecKind,
};
use rtc::sansio::Protocol;
use rtc::shared::error::Error;
use rtc::shared::{TaggedBytesMut, TransportContext, TransportProtocol};
use rtc::srtp::keying::KeyLifetime;
use std::net::SocketAddr;
use std::time::Instant;

const AUDIO_SSRC: u32 = 4242;

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
    events: Vec<(Instant, RTCPeerConnectionEvent)>,
    rtp: Vec<(Instant, rtc::rtp::Packet)>,
}

impl Peer {
    fn new(addr: SocketAddr, role: RTCDtlsRole, now: Instant) -> Result<Self> {
        Self::with(
            addr,
            SettingEngineBuilder::new().with_answering_dtls_role(role),
            now,
        )
    }

    fn with(addr: SocketAddr, setting_engine: SettingEngineBuilder, now: Instant) -> Result<Self> {
        let mut media_engine = MediaEngine::default();
        media_engine.register_default_codecs()?;
        let pc = RTCPeerConnectionBuilder::new()
            .with_configuration(RTCConfigurationBuilder::new().build())
            .with_media_engine(media_engine)
            .with_setting_engine(setting_engine.build())
            .build(now)?;
        Ok(Self {
            pc,
            addr,
            inbox: Vec::new(),
            events: Vec::new(),
            rtp: Vec::new(),
        })
    }

    fn turn(&mut self, now: Instant) -> Result<Vec<TaggedBytesMut>> {
        for datagram in self.inbox.drain(..) {
            self.pc.handle_read(datagram)?;
        }
        while let Some(event) = self.pc.poll_event() {
            self.events.push((now, event));
        }
        while let Some(message) = self.pc.poll_read() {
            if let RTCMessage::RtpPacket(_, packet) = message.message {
                self.rtp.push((now, packet));
            }
        }
        let mut written = Vec::new();
        while let Some(datagram) = self.pc.poll_write() {
            written.push(datagram);
        }
        Ok(written)
    }

    fn deliver(&mut self, from: SocketAddr, datagrams: Vec<TaggedBytesMut>, now: Instant) {
        for datagram in datagrams {
            self.inbox.push(TaggedBytesMut {
                now,
                transport: TransportContext {
                    local_addr: self.addr,
                    peer_addr: from,
                    ecn: None,
                    transport_protocol: TransportProtocol::UDP,
                },
                message: datagram.message,
            });
        }
    }
}

/// RFC 3711 section 3.3.2: "the window size MUST be at least 64"; 0 (no replay protection,
/// as documented) and 64 are taken, 1 to 63 make building the connection fail.
#[test]
fn a_replay_window_below_64_is_refused() -> Result<()> {
    let build = |engine: SettingEngineBuilder| {
        RTCPeerConnectionBuilder::new()
            .with_setting_engine(engine.build())
            .build(Instant::now())
            .err()
    };
    for window in [1, 32, 63] {
        assert!(matches!(
            build(SettingEngineBuilder::new().with_srtp_replay_protection_window(window)),
            Some(Error::ErrSrtpReplayWindowTooSmall("SRTP", _))
        ));
        assert!(matches!(
            build(SettingEngineBuilder::new().with_srtcp_replay_protection_window(window)),
            Some(Error::ErrSrtpReplayWindowTooSmall("SRTCP", _))
        ));
    }
    for window in [0, 64, 1024] {
        assert!(
            build(SettingEngineBuilder::new().with_srtp_replay_protection_window(window)).is_none()
        );
    }
    assert!(
        build(
            SettingEngineBuilder::new().with_srtp_key_lifetime(Some(KeyLifetime {
                srtp_packets: 0,
                srtcp_packets: 1,
            }))
        )
        .is_some(),
        "a lifetime of zero packets"
    );
    Ok(())
}

/// RFC 3711 section 9.2 with a lifetime of 40 packets: the connection says the outbound key
/// is near its end, and at the limit the DTLS transport fails with dtls-failure (re-keying
/// with a new DTLS association is not something a browser peer takes on a transport that has
/// one), and the connection with it.
#[test]
fn an_exhausted_srtp_key_fails_the_transport_with_its_reason() -> Result<()> {
    let now = Instant::now();
    let lifetime = KeyLifetime {
        srtp_packets: 40,
        srtcp_packets: 1 << 31,
    };
    let mut caller = Peer::with(
        "127.0.0.1:55010".parse()?,
        SettingEngineBuilder::new()
            .with_answering_dtls_role(RTCDtlsRole::Client)
            .with_srtp_key_lifetime(Some(lifetime)),
        now,
    )?;
    let mut callee = Peer::new("127.0.0.1:55011".parse()?, RTCDtlsRole::Server, now)?;
    let track = MediaStreamTrack::new(
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
    );
    let sender = caller.pc.add_track(track)?;
    let offer = caller.pc.create_offer(None)?;
    caller.pc.set_local_description(now, offer.clone())?;
    callee.pc.set_remote_description(now, offer)?;
    let answer = callee.pc.create_answer(None)?;
    callee.pc.set_local_description(now, answer.clone())?;
    caller.pc.set_remote_description(now, answer)?;
    let (a, b) = (caller.addr, callee.addr);
    caller.pc.add_local_candidate(host(a)?)?;
    callee.pc.add_local_candidate(host(b)?)?;
    caller.pc.add_remote_candidate(host(b)?)?;
    callee.pc.add_remote_candidate(host(a)?)?;

    let mut now = now;
    let mut written = 0u16;
    for _ in 0..50_000 {
        let out = caller.turn(now)?;
        callee.deliver(caller.addr, out, now);
        let out = callee.turn(now)?;
        caller.deliver(callee.addr, out, now);
        if caller.pc.connection_state() == RTCPeerConnectionState::Failed {
            break;
        }
        if caller.pc.connection_state() == RTCPeerConnectionState::Connected && written < 60 {
            written += 1;
            // Refused once the key is exhausted: the error is the pipeline's, not the caller's.
            let _ = caller.pc.rtp_sender(sender).expect("sender").write_rtp(
                now,
                rtc::rtp::Packet {
                    header: rtc::rtp::header::Header {
                        version: 2,
                        payload_type: 111,
                        sequence_number: written,
                        timestamp: u32::from(written) * 960,
                        ssrc: AUDIO_SSRC,
                        ..Default::default()
                    },
                    payload: Bytes::from_static(&[0xF8, 0xFF, 0xFE]),
                },
            );
            continue;
        }
        if caller.inbox.is_empty() && callee.inbox.is_empty() {
            let next = [caller.pc.poll_timeout(), callee.pc.poll_timeout()]
                .into_iter()
                .flatten()
                .min();
            let Some(next) = next else { break };
            now = now.max(next);
            caller.pc.handle_timeout(now)?;
            callee.pc.handle_timeout(now)?;
        }
    }
    let position = |pred: &dyn Fn(&RTCPeerConnectionEvent) -> bool| {
        caller.events.iter().position(|(_, e)| pred(e))
    };
    let expiring = position(&|e| {
        matches!(
            e,
            RTCPeerConnectionEvent::OnSrtpKeyLifetimeExpiring {
                outbound: true,
                rtcp: false,
                ..
            }
        )
    })
    .expect("told the key is near its end");
    let error = position(&|e| {
        matches!(
            e,
            RTCPeerConnectionEvent::OnDtlsTransportError(error)
                if error.error_detail == RTCErrorDetailType::DtlsFailure
        )
    })
    .expect("the DTLS transport's error");
    let failed = position(&|e| {
        matches!(
            e,
            RTCPeerConnectionEvent::OnConnectionStateChangeEvent(RTCPeerConnectionState::Failed)
        )
    })
    .expect("the connection failed");
    assert!(expiring < error && error < failed);
    let received = callee
        .rtp
        .iter()
        .filter(|(_, p)| p.header.ssrc == AUDIO_SSRC)
        .count();
    assert!(
        received <= 40,
        "nothing beyond the key's lifetime: {received}"
    );
    Ok(())
}
