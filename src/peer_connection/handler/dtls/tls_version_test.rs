//! webrtc-stats `RTCTransportStats.tlsVersion`: the uppercase hex of the two ServerHello version
//! bytes, "FEFD" for DTLS 1.2 (RFC 6347 section 4.1), not "DTLS 1.2" (commit 0833d736).

use super::*;
use crate::peer_connection::transport::{RTCTransportId, TransportKind};

#[test]
fn handshake_completion_reports_the_tls_version_as_server_hello_hex() -> Result<()> {
    let provider =
        crypto::default_provider().expect("a built-in crypto provider is enabled for tests");
    let transport = DtlsTransport::new(
        crate::peer_connection::transport::dtls::RTCDtlsTransportConfig {
            id: RTCTransportId::new(0x0123_4567_89ab_cdef, TransportKind::Dtls),
            ice_transport_id: RTCTransportId::new(0x0123_4567_89ab_cdef, TransportKind::Ice),
            certificates: vec![],
            answering_dtls_role: Default::default(),
            srtp_protection_profiles: vec![],
            use_srtp: true,
            dtls_cipher_suites: vec![],
            allow_insecure_verification_algorithm: false,
            disable_certificate_fingerprint_verification: false,
            replay_protection: Default::default(),
            crypto_provider: provider,
        },
    )
    .expect("transport");
    let mut context = DtlsHandlerContext::new(transport);
    let mut stats = RTCStatsAccumulator::default();

    DtlsHandler::new(&mut context, &mut stats).update_dtls_stats_from_profile(
        SrtpProtectionProfile::Srtp_Aead_Aes_128_Gcm,
        &[vec![0x30u8, 0x82, 0x01, 0x0a]],
        Some("TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256".to_owned()),
    )?;

    assert_eq!(stats.transport.tls_version, "FEFD");
    assert_ne!(stats.transport.tls_version, "DTLS 1.2");
    Ok(())
}
