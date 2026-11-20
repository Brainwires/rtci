//! Helpers shared by the peer-connection fuzz targets: certificates made once per process,
//! peers built the way an application builds them, and the in-memory network between two peers.
//! Not a target itself (it has no `[[bin]]` entry); targets include it with `#[path]`.
#![allow(dead_code)]

use bytes::BytesMut;
use rtc::crypto::SignatureScheme;
use rtc::interceptor::Registry;
use rtc::peer_connection::certificate::{CertificateParams, RTCCertificate};
use rtc::peer_connection::configuration::RTCConfigurationBuilder;
use rtc::peer_connection::configuration::interceptor_registry::register_default_interceptors;
use rtc::peer_connection::configuration::media_engine::MediaEngine;
use rtc::peer_connection::configuration::setting_engine::SettingEngineBuilder;
use rtc::peer_connection::transport::{
    CandidateConfig, CandidateHostConfig, RTCDtlsRole, RTCIceCandidate,
};
use rtc::peer_connection::{RTCPeerConnection, RTCPeerConnectionBuilder};
use rtc::sansio::Protocol;
use rtc::shared::{TaggedBytesMut, TransportContext, TransportProtocol};
use std::net::SocketAddr;
use std::sync::OnceLock;
use std::time::Instant;

/// One base instant for the whole process: the harnesses only ever add input-chosen offsets.
static START: OnceLock<Instant> = OnceLock::new();

pub fn start() -> Instant {
    *START.get_or_init(Instant::now)
}

/// Two certificates, generated once: key generation per input would dominate the run time.
static CERTIFICATES: OnceLock<Option<[RTCCertificate; 2]>> = OnceLock::new();

pub fn certificate(which: usize) -> Option<RTCCertificate> {
    let certificates = CERTIFICATES.get_or_init(|| {
        let provider = rtc::crypto::default_provider().ok()?;
        let make = || {
            RTCCertificate::generate(
                provider.crypto(),
                SignatureScheme::EcdsaP256Sha256,
                CertificateParams::new(vec!["localhost".to_owned()]).ok()?,
            )
            .ok()
        };
        Some([make()?, make()?])
    });
    certificates.as_ref().map(|c| c[which % 2].clone())
}

/// A peer connection as an application builds one: default codecs and default interceptors,
/// one of the fixed certificates, and randomness seeded from `seed` (the engine also draws some
/// of its own, so an input replays closely but not always byte for byte).
pub fn peer(which: usize, seed: u64, answering_role: RTCDtlsRole) -> Option<RTCPeerConnection> {
    let mut media_engine = MediaEngine::default();
    media_engine.register_default_codecs().ok()?;
    let registry = register_default_interceptors(Registry::new(), &mut media_engine).ok()?;
    let provider = rtc::crypto::fuzzing::deterministic_provider(seed, false).ok()?;
    RTCPeerConnectionBuilder::new()
        .with_configuration(
            RTCConfigurationBuilder::new()
                .with_certificates(vec![certificate(which)?])
                .build(),
        )
        .with_media_engine(media_engine)
        .with_interceptor_registry(registry)
        .with_setting_engine(
            SettingEngineBuilder::new()
                .with_answering_dtls_role(answering_role)
                .with_crypto_provider(provider)
                .build(),
        )
        .build(start())
        .ok()
}

/// Registers a host candidate at `addr`, so the description carries it.
pub fn add_host_candidate(pc: &mut RTCPeerConnection, addr: SocketAddr) -> Option<()> {
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
    .new_candidate_host()
    .ok()?;
    pc.add_local_candidate(RTCIceCandidate::from(&candidate).to_json().ok()?)
        .ok()
}

/// Hands `message` to `pc` as a UDP datagram from `from` to `to`.
pub fn deliver(
    pc: &mut RTCPeerConnection,
    now: Instant,
    from: SocketAddr,
    to: SocketAddr,
    message: &[u8],
) {
    let _ = pc.handle_read(TaggedBytesMut {
        now,
        transport: TransportContext {
            local_addr: to,
            peer_addr: from,
            transport_protocol: TransportProtocol::UDP,
            ecn: None,
        },
        message: BytesMut::from(message),
    });
}

/// Drains everything `pc` has for the application and its events, with a budget so a peer that
/// keeps producing cannot hang the target. Calls `on_event` for each event.
pub fn drain(
    pc: &mut RTCPeerConnection,
    mut on_event: impl FnMut(&rtc::peer_connection::event::RTCPeerConnectionEvent),
) {
    let mut budget = 4096;
    while budget > 0 {
        let Some(event) = pc.poll_event() else {
            break;
        };
        on_event(&event);
        budget -= 1;
    }
    while budget > 0 && pc.poll_read().is_some() {
        budget -= 1;
    }
}
