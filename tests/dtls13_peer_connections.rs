//! Two peer connections of this engine negotiate DTLS 1.3 (RFC 9147) by default, and DTLS 1.2
//! when either side is configured without the TLS 1.3 cipher suites.
//!
//! - Data-channel-only and media sessions both complete under DTLS 1.3, in either DTLS role:
//!   `tlsVersion` is `FEFC`, the cipher is a TLS 1.3 suite, each side holds the certificate
//!   whose fingerprint the other signalled, and the data channel carries messages (SCTP over
//!   the DTLS 1.3 record layer).
//! - A media session keys SRTP from the DTLS 1.3 exporter: `use_srtp` is answered in
//!   EncryptedExtensions and the SRTP cipher is reported. (Media through those keys is
//!   counted in `stats_conformance_rtc2rtc.rs`.)
//! - A peer whose cipher suite list has no TLS 1.3 suite negotiates DTLS 1.2 with one that
//!   offers both, whichever of them is the DTLS client.

mod dtls_sdp_common;

use anyhow::Result;
use dtls::cipher_suite::CipherSuiteId;
use dtls_sdp_common::{Peer, World};
use rtc::peer_connection::configuration::setting_engine::SettingEngineBuilder;
use rtc::peer_connection::transport::{RTCDtlsRole, RTCDtlsTransportState};
use rtc::rtp_transceiver::rtp_sender::RtpCodecKind;
use rtc::statistics::StatsSelector;
use std::time::Instant;

fn peer(
    addr: &str,
    suites: Option<Vec<CipherSuiteId>>,
    answering_role: Option<RTCDtlsRole>,
) -> Result<Peer> {
    let mut setting_engine = SettingEngineBuilder::new();
    if let Some(suites) = suites {
        setting_engine = setting_engine.with_dtls_cipher_suites(suites);
    }
    if let Some(role) = answering_role {
        setting_engine = setting_engine.with_answering_dtls_role(role);
    }
    Peer::new(addr, setting_engine.build())
}

/// (tlsVersion, dtlsCipher) of a peer's transport.
fn version_and_cipher(peer: &mut Peer, now: Instant) -> (String, String) {
    peer.pc
        .get_stats(now, StatsSelector::None)
        .transport()
        .map(|transport| (transport.tls_version.clone(), transport.dtls_cipher.clone()))
        .unwrap_or_default()
}

fn dtls_1_2_only() -> Vec<CipherSuiteId> {
    vec![CipherSuiteId::Tls_Ecdhe_Ecdsa_With_Aes_128_Gcm_Sha256]
}

#[test]
fn a_data_channel_session_negotiates_dtls_1_3() -> Result<()> {
    for answering_role in [None, Some(RTCDtlsRole::Server)] {
        let what = format!("the answerer answers as {answering_role:?}");
        let mut world = World::new(
            peer("10.0.0.1:5000", None, None)?,
            peer("10.0.0.2:5000", None, answering_role)?,
        );
        world.connect()?;
        world.ping_pong(&what)?;
        let now = world.now;
        for i in 0..2 {
            assert_eq!(
                world.peers[i].dtls_state(now),
                RTCDtlsTransportState::Connected,
                "{what}: peer {i}"
            );
            let (version, cipher) = version_and_cipher(&mut world.peers[i], now);
            assert_eq!(version, "FEFC", "{what}: peer {i}");
            assert_eq!(cipher, "TLS_AES_128_GCM_SHA256", "{what}: peer {i}");
            // The fingerprint check ran on the certificate of the DTLS 1.3 handshake.
            assert!(
                world.peers[i].remote_certificate().is_some(),
                "{what}: peer {i}"
            );
            assert!(!world.peers[i].failed(), "{what}: peer {i}");
        }
    }
    Ok(())
}

#[test]
fn a_media_session_keys_srtp_from_dtls_1_3() -> Result<()> {
    for answering_role in [None, Some(RTCDtlsRole::Server)] {
        let mut world = World::new(
            peer("10.0.0.1:5000", None, None)?,
            peer("10.0.0.2:5000", None, answering_role)?,
        );
        world.peers[0]
            .pc
            .add_transceiver_from_kind(RtpCodecKind::Audio, None)?;
        world.connect()?;
        world.ping_pong("a media session under DTLS 1.3")?;
        let now = world.now;
        for i in 0..2 {
            let (version, _) = version_and_cipher(&mut world.peers[i], now);
            assert_eq!(version, "FEFC", "peer {i}");
            assert_eq!(
                world.peers[i].srtp_cipher(now),
                "SRTP_AEAD_AES_256_GCM",
                "peer {i}: use_srtp was answered in EncryptedExtensions"
            );
        }
    }
    Ok(())
}

#[test]
fn a_peer_without_tls_1_3_suites_gets_dtls_1_2() -> Result<()> {
    // Which peer is restricted, and which is the DTLS client (the answerer by default).
    for restricted in [0usize, 1] {
        for answering_role in [None, Some(RTCDtlsRole::Server)] {
            let what =
                format!("peer {restricted} has DTLS 1.2 suites only, answerer {answering_role:?}");
            let suites = |i: usize| (i == restricted).then(dtls_1_2_only);
            let mut world = World::new(
                peer("10.0.0.1:5000", suites(0), None)?,
                peer("10.0.0.2:5000", suites(1), answering_role)?,
            );
            world.peers[0]
                .pc
                .add_transceiver_from_kind(RtpCodecKind::Audio, None)?;
            world.connect()?;
            world.ping_pong(&what)?;
            let now = world.now;
            for i in 0..2 {
                let (version, cipher) = version_and_cipher(&mut world.peers[i], now);
                assert_eq!(version, "FEFD", "{what}: peer {i}");
                assert_eq!(
                    cipher, "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
                    "{what}: peer {i}"
                );
                assert_eq!(
                    world.peers[i].srtp_cipher(now),
                    "SRTP_AEAD_AES_256_GCM",
                    "{what}"
                );
            }
        }
    }
    Ok(())
}
