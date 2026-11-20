use super::flight0::*;
use super::flight4::*;
use super::*;
use crate::content::*;
use crate::handshake::handshake_message_hello_verify_request::*;
use crate::handshake::*;
use crate::record_layer::record_layer_header::*;
use shared::error::Error;

use crate::config::HandshakeConfig;
use std::fmt;

#[derive(Debug, PartialEq)]
pub(crate) struct Flight2;

impl fmt::Display for Flight2 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Flight 2")
    }
}

impl Flight for Flight2 {
    fn has_retransmit(&self) -> bool {
        false
    }

    fn parse(
        &self,
        //tx: &mut mpsc::Sender<mpsc::Sender<()>>,
        state: &mut State,
        cache: &HandshakeCache,
        cfg: &HandshakeConfig,
    ) -> Result<Box<dyn Flight>, (Option<Alert>, Option<Error>)> {
        let (seq, msgs) = match cache.full_pull_map(
            state.handshake_recv_sequence,
            &[HandshakeCachePullRule {
                typ: HandshakeType::ClientHello,
                epoch: cfg.initial_epoch,
                is_client: true,
                optional: false,
            }],
        ) {
            // No valid message received. Keep reading
            Ok((seq, msgs)) => (seq, msgs),

            // Client may retransmit the first ClientHello when HelloVerifyRequest is dropped.
            // Parse as flight 0 in this case.
            Err(_) => return Flight0 {}.parse(/*tx,*/ state, cache, cfg),
        };

        state.handshake_recv_sequence = seq;

        if let Some(message) = msgs.get(&HandshakeType::ClientHello) {
            // Validate type
            let client_hello = match message {
                HandshakeMessage::ClientHello(client_hello) => client_hello,
                _ => {
                    return Err((
                        Some(Alert {
                            alert_level: AlertLevel::Fatal,
                            alert_description: AlertDescription::InternalError,
                        }),
                        None,
                    ));
                }
            };

            if client_hello.version != PROTOCOL_VERSION1_2 {
                return Err((
                    Some(Alert {
                        alert_level: AlertLevel::Fatal,
                        alert_description: AlertDescription::ProtocolVersion,
                    }),
                    Some(Error::ErrUnsupportedProtocolVersion),
                ));
            }

            if client_hello.cookie.is_empty() {
                return Err((None, None));
            }

            if state.cookie != client_hello.cookie {
                return Err((
                    Some(Alert {
                        alert_level: AlertLevel::Fatal,
                        alert_description: AlertDescription::AccessDenied,
                    }),
                    Some(Error::ErrCookieMismatch),
                ));
            }

            // Negotiate from the cookie-verified ClientHello, which the handshake transcript
            // covers, not from the first one, which anyone on the path could have sent.
            negotiate_client_hello(state, client_hello, cfg)?;

            Ok(Box::new(Flight4 {}))
        } else {
            Err((
                Some(Alert {
                    alert_level: AlertLevel::Fatal,
                    alert_description: AlertDescription::InternalError,
                }),
                None,
            ))
        }
    }

    fn generate(
        &self,
        state: &mut State,
        _cache: &HandshakeCache,
        _cfg: &HandshakeConfig,
    ) -> Result<Vec<Packet>, (Option<Alert>, Option<Error>)> {
        state.handshake_send_sequence = 0;
        Ok(vec![Packet {
            record: RecordLayer::new(
                PROTOCOL_VERSION1_2,
                0,
                Content::Handshake(Handshake::new(HandshakeMessage::HelloVerifyRequest(
                    HandshakeMessageHelloVerifyRequest {
                        version: PROTOCOL_VERSION1_2,
                        cookie: state.cookie.clone(),
                    },
                ))),
            ),
            should_encrypt: false,
            reset_local_sequence_number: false,
        }])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cipher_suite::CipherSuiteId;
    use crate::compression_methods::default_compression_methods;
    use crate::curve::named_curve::NamedCurve;
    use crate::extension::Extension;
    use crate::extension::extension_supported_elliptic_curves::ExtensionSupportedEllipticCurves;
    use crate::extension::extension_use_srtp::{ExtensionUseSrtp, SrtpProtectionProfile};
    use crate::handshake::handshake_message_client_hello::HandshakeMessageClientHello;
    use crate::handshake::handshake_random::HandshakeRandom;
    use std::sync::Arc;

    fn push_client_hello(
        cache: &mut HandshakeCache,
        message_sequence: u16,
        cookie: Vec<u8>,
        random_byte: u8,
        curves: Vec<NamedCurve>,
        profiles: Vec<SrtpProtectionProfile>,
    ) {
        let mut random = HandshakeRandom::default();
        random.random_bytes = [random_byte; 28];
        let mut handshake =
            Handshake::new(HandshakeMessage::ClientHello(HandshakeMessageClientHello {
                version: PROTOCOL_VERSION1_2,
                random,
                cookie,
                cipher_suites: vec![CipherSuiteId::Tls_Ecdhe_Ecdsa_With_Aes_128_Gcm_Sha256],
                compression_methods: default_compression_methods(),
                extensions: vec![
                    Extension::SupportedEllipticCurves(ExtensionSupportedEllipticCurves {
                        elliptic_curves: curves,
                    }),
                    Extension::UseSrtp(ExtensionUseSrtp {
                        protection_profiles: profiles,
                    }),
                ],
            }));
        handshake.handshake_header.message_sequence = message_sequence;
        let mut data = vec![];
        handshake.marshal(&mut data).unwrap();
        assert!(cache.push(data, 0, message_sequence, HandshakeType::ClientHello, true));
    }

    /// The first ClientHello carries no cookie, so anyone on the path can send it in place of the
    /// genuine one. The parameters must come from the cookie-verified ClientHello.
    #[test]
    fn test_parameters_come_from_the_cookie_verified_client_hello() {
        let provider = ::crypto::default_provider().unwrap();
        let mut cfg = HandshakeConfig::new(provider.clone());
        cfg.local_cipher_suites = vec![CipherSuiteId::Tls_Ecdhe_Ecdsa_With_Aes_128_Gcm_Sha256];
        cfg.local_named_curves = vec![NamedCurve::X25519, NamedCurve::P256];
        cfg.local_srtp_protection_profiles = vec![
            SrtpProtectionProfile::Srtp_Aead_Aes_128_Gcm,
            SrtpProtectionProfile::Srtp_Aes128_Cm_Hmac_Sha1_80,
            SrtpProtectionProfile::Srtp_Aes128_Cm_Hmac_Sha1_32,
        ];
        let cfg = Arc::new(cfg);
        let mut state = State::new(provider, false);
        let mut cache = HandshakeCache::new();

        Flight0 {}.generate(&mut state, &cache, &cfg).unwrap();

        // A forged first ClientHello offering only the weakest options.
        push_client_hello(
            &mut cache,
            0,
            vec![],
            1,
            vec![NamedCurve::P256],
            vec![SrtpProtectionProfile::Srtp_Aes128_Cm_Hmac_Sha1_32],
        );
        let next = Flight0 {}.parse(&mut state, &cache, &cfg).unwrap();
        assert_eq!(next.to_string(), Flight2 {}.to_string());
        assert_eq!(
            state.srtp_protection_profile,
            SrtpProtectionProfile::Srtp_Aes128_Cm_Hmac_Sha1_32
        );

        // The genuine client's ClientHello, answering our HelloVerifyRequest.
        let cookie = state.cookie.clone();
        push_client_hello(
            &mut cache,
            1,
            cookie,
            2,
            vec![NamedCurve::X25519, NamedCurve::P256],
            vec![
                SrtpProtectionProfile::Srtp_Aead_Aes_128_Gcm,
                SrtpProtectionProfile::Srtp_Aes128_Cm_Hmac_Sha1_80,
                SrtpProtectionProfile::Srtp_Aes128_Cm_Hmac_Sha1_32,
            ],
        );
        let next = Flight2 {}.parse(&mut state, &cache, &cfg).unwrap();
        assert_eq!(next.to_string(), "Flight 4");

        assert_eq!(
            state.srtp_protection_profile,
            SrtpProtectionProfile::Srtp_Aead_Aes_128_Gcm
        );
        assert_eq!(state.named_curve, NamedCurve::X25519);
        assert_eq!(
            state.local_keypair.as_ref().map(|keypair| keypair.curve),
            Some(NamedCurve::X25519)
        );
        assert_eq!(state.remote_random.random_bytes, [2u8; 28]);
    }
}
