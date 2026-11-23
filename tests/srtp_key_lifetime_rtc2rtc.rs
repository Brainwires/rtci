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

/// An Opus track the caller sends with `AUDIO_SSRC`.
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

fn exchange(offerer: &mut Peer, answerer: &mut Peer, now: Instant) -> Result<()> {
    let offer = offerer.pc.create_offer(None)?;
    offerer.pc.set_local_description(now, offer.clone())?;
    answerer.pc.set_remote_description(now, offer)?;
    let answer = answerer.pc.create_answer(None)?;
    answerer.pc.set_local_description(now, answer.clone())?;
    offerer.pc.set_remote_description(now, answer)?;
    Ok(())
}

/// Whether the peer's DTLS transport is connected (`RTCTransportStats.dtlsState`).
fn dtls_connected(peer: &mut Peer, now: Instant) -> bool {
    peer.pc
        .get_stats(now, rtc::statistics::StatsSelector::None)
        .transport()
        .is_some_and(|t| {
            t.dtls_state == rtc::peer_connection::transport::RTCDtlsTransportState::Connected
        })
}

/// How many RTP packets of the caller's track the callee received.
fn received(callee: &Peer) -> usize {
    callee
        .rtp
        .iter()
        .filter(|(_, p)| p.header.ssrc == AUDIO_SSRC)
        .count()
}

/// Whether a datagram is SRTP (RFC 7983: first byte 128 to 191) and not SRTCP (RFC 5761:
/// payload types 72 to 76 with the marker bit, i.e. RTCP packet types 200 to 204).
fn is_srtp(datagram: &[u8]) -> bool {
    datagram.len() > 1 && (128..=191).contains(&datagram[0]) && !(200..=204).contains(&datagram[1])
}

/// Re-keying by a new DTLS association (RFC 3711 sections 9.2 and 11.3, RFC 7714 sections
/// 8.4 and 9.4, RFC 5764 section 4.1.2): with a key lifetime of 40 packets, the caller sends
/// 30, asks for a new association (`renew_dtls_association`) and negotiates; the new DTLS
/// handshake exports new SRTP keys, and the caller sends 35 more, past the lifetime the old
/// key had (65 in all), without the transport failing: the packet count started over with the
/// new key, whose own 40 are not used up.
/// A packet protected with the old key, held back on the wire and delivered after the
/// re-key, is not accepted: the keys changed.
#[test]
fn a_new_dtls_association_re_keys_srtp_and_starts_the_key_lifetime_over() -> Result<()> {
    let start = Instant::now();
    let lifetime = KeyLifetime {
        srtp_packets: 40,
        srtcp_packets: 1 << 31,
    };
    let mut caller = Peer::with(
        "127.0.0.1:55020".parse()?,
        SettingEngineBuilder::new()
            .with_answering_dtls_role(RTCDtlsRole::Client)
            .with_srtp_key_lifetime(Some(lifetime)),
        start,
    )?;
    let mut callee = Peer::new("127.0.0.1:55021".parse()?, RTCDtlsRole::Server, start)?;
    let sender = caller.pc.add_track(audio_track())?;
    exchange(&mut caller, &mut callee, start)?;
    let (a, b) = (caller.addr, callee.addr);
    caller.pc.add_local_candidate(host(a)?)?;
    callee.pc.add_local_candidate(host(b)?)?;
    caller.pc.add_remote_candidate(host(b)?)?;
    callee.pc.add_remote_candidate(host(a)?)?;

    let mut now = start;
    let mut seq = 0u16;
    let mut held: Option<TaggedBytesMut> = None;
    let mut renewed = false;
    let mut received_at_renewal = 0;
    for _ in 0..100_000 {
        let mut out = caller.turn(now)?;
        if seq == 31 && held.is_none() && !renewed {
            // Packet 31, protected with the first key, is held back.
            if let Some(i) = out.iter().position(|d| is_srtp(&d.message)) {
                held = Some(out.remove(i));
            }
        }
        callee.deliver(caller.addr, out, now);
        let out = callee.turn(now)?;
        caller.deliver(callee.addr, out, now);
        assert_ne!(
            caller.pc.connection_state(),
            RTCPeerConnectionState::Failed,
            "the caller failed after {seq} packets"
        );
        let connected = caller.pc.connection_state() == RTCPeerConnectionState::Connected
            && callee.pc.connection_state() == RTCPeerConnectionState::Connected;
        if held.is_some() && !renewed {
            renewed = true;
            received_at_renewal = received(&callee);
            caller.pc.renew_dtls_association();
            exchange(&mut caller, &mut callee, now)?;
            // RFC 8842 section 5.1: the new association runs on new 3-tuples.
            caller.addr.set_port(55030);
            callee.addr.set_port(55031);
            let (a, b) = (caller.addr, callee.addr);
            caller.pc.add_local_candidate(host(a)?)?;
            callee.pc.add_local_candidate(host(b)?)?;
            caller.pc.add_remote_candidate(host(b)?)?;
            callee.pc.add_remote_candidate(host(a)?)?;
            continue;
        }
        if renewed && received(&callee) >= received_at_renewal + 35 {
            break;
        }
        let may_send = if renewed {
            // After the renewal, once the new association has keyed SRTP on both sides.
            connected && dtls_connected(&mut caller, now) && dtls_connected(&mut callee, now)
        } else {
            connected && seq < 31
        };
        if may_send {
            seq += 1;
            let _ = caller.pc.rtp_sender(sender).expect("sender").write_rtp(
                now,
                rtc::rtp::Packet {
                    header: rtc::rtp::header::Header {
                        version: 2,
                        payload_type: 111,
                        sequence_number: seq,
                        timestamp: u32::from(seq) * 960,
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
    assert!(renewed, "the first key carried packets");
    let after = received(&callee) - received_at_renewal;
    assert!(
        after >= 35,
        "{after} packets after the renewal, {} written in all",
        seq
    );

    // The held packet: protected with the first association's key.
    let before = received(&callee);
    callee.deliver(caller.addr, vec![held.expect("held")], now);
    let _ = callee.turn(now);
    assert_eq!(
        received(&callee),
        before,
        "a packet under the old key was accepted"
    );
    Ok(())
}
