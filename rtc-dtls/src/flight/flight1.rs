use super::flight3::*;
use super::*;
use crate::cipher_suite::CipherSuiteId;
use crate::compression_methods::*;
use crate::config::*;
use crate::conn::*;
use crate::content::*;
use crate::extension::extension_server_name::*;
use crate::extension::extension_supported_elliptic_curves::*;
use crate::extension::extension_supported_point_formats::*;
use crate::extension::extension_supported_signature_algorithms::*;
use crate::extension::extension_use_extended_master_secret::*;
use crate::extension::extension_use_srtp::*;
use crate::extension::*;
use crate::handshake::handshake_message_client_hello::*;
use crate::handshake::*;
use crate::record_layer::record_layer_header::*;
use crate::record_layer::*;
use shared::error::Error;

use crate::extension::renegotiation_info::ExtensionRenegotiationInfo;
use std::fmt;

#[derive(Debug, PartialEq)]
pub(crate) struct Flight1;

impl fmt::Display for Flight1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Flight 1")
    }
}

impl Flight for Flight1 {
    fn parse(
        &self,
        //tx: &mut mpsc::Sender<mpsc::Sender<()>>,
        state: &mut State,
        cache: &HandshakeCache,
        cfg: &HandshakeConfig,
    ) -> Result<Box<dyn Flight>, (Option<Alert>, Option<Error>)> {
        // HelloVerifyRequest can be skipped by the server,
        // so allow ServerHello during flight1 also
        let (seq, msgs) = match cache.full_pull_map(
            state.handshake_recv_sequence,
            &[
                HandshakeCachePullRule {
                    typ: HandshakeType::HelloVerifyRequest,
                    epoch: cfg.initial_epoch,
                    is_client: false,
                    optional: true,
                },
                HandshakeCachePullRule {
                    typ: HandshakeType::ServerHello,
                    epoch: cfg.initial_epoch,
                    is_client: false,
                    optional: true,
                },
            ],
        ) {
            // No valid message received. Keep reading
            Ok((seq, msgs)) => (seq, msgs),
            Err(_) => return Err((None, None)),
        };

        if msgs.contains_key(&HandshakeType::ServerHello) {
            // Flight1 and flight2 were skipped.
            // Parse as flight3.
            let flight3 = Flight3 {};
            return flight3.parse(/*tx,*/ state, cache, cfg);
        }

        if let Some(message) = msgs.get(&HandshakeType::HelloVerifyRequest) {
            // DTLS 1.2 clients must not assume that the server will use the protocol version
            // specified in HelloVerifyRequest message. RFC 6347 Section 4.2.1
            let h = match message {
                HandshakeMessage::HelloVerifyRequest(h) => h,
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

            if h.version != PROTOCOL_VERSION1_0 && h.version != PROTOCOL_VERSION1_2 {
                return Err((
                    Some(Alert {
                        alert_level: AlertLevel::Fatal,
                        alert_description: AlertDescription::ProtocolVersion,
                    }),
                    Some(Error::ErrUnsupportedProtocolVersion),
                ));
            }

            state.cookie.clone_from(&h.cookie);
            state.handshake_recv_sequence = seq;
            Ok(Box::new(Flight3 {}))
        } else {
            // Neither a HelloVerifyRequest nor a ServerHello has arrived yet: a handshake
            // record that delivered nothing (a fragment, or one that was discarded) is no
            // reason for an alert. This used to answer any such record, which anyone can send
            // from the server's address, with a fatal internal_error that ended the handshake.
            Err((None, None))
        }
    }

    fn generate(
        &self,
        state: &mut State,
        _cache: &HandshakeCache,
        cfg: &HandshakeConfig,
    ) -> Result<Vec<Packet>, (Option<Alert>, Option<Error>)> {
        state.local_epoch = 0;
        state.remote_epoch = 0;

        state.named_curve = DEFAULT_NAMED_CURVE;
        state.cookie = vec![];
        if let Err(error) = state.local_random.populate(cfg.provider().random()) {
            return Err((None, Some(error)));
        }

        // DTLS 1.3 is offered in the same ClientHello (RFC 9147 section 5.3): its suites
        // ahead of the DTLS 1.2 ones, and supported_versions and key_share among the
        // extensions. The key shares are kept until the server has answered.
        state.tls13_offer = None;
        if cfg.supports_dtls13() {
            match crate::dtls13::hello::ClientOffer::new(cfg) {
                Ok(offer) => state.tls13_offer = Some(offer),
                Err(error) => return Err((None, Some(error))),
            }
        }
        let extensions = client_hello_extensions(cfg, state.tls13_offer.as_ref());

        Ok(vec![Packet {
            record: RecordLayer::new(
                PROTOCOL_VERSION1_2,
                0,
                Content::Handshake(Handshake::new(HandshakeMessage::ClientHello(
                    HandshakeMessageClientHello {
                        version: PROTOCOL_VERSION1_2,
                        random: state.local_random.clone(),
                        cookie: state.cookie.clone(),

                        cipher_suites: client_hello_cipher_suites(cfg),
                        compression_methods: default_compression_methods(),
                        extensions,
                    },
                ))),
            ),
            should_encrypt: false,
            reset_local_sequence_number: false,
        }])
    }
}

/// The extensions of this client's ClientHello: the same in the first one and in the one that
/// answers HelloVerifyRequest (RFC 6347 4.2.1), and the set a ServerHello's extensions are
/// checked against (RFC 5246 7.4.1.4).
pub(crate) fn client_hello_extensions(
    cfg: &HandshakeConfig,
    tls13_offer: Option<&crate::dtls13::hello::ClientOffer>,
) -> Vec<Extension> {
    let mut extensions = vec![
        Extension::SupportedSignatureAlgorithms(ExtensionSupportedSignatureAlgorithms {
            signature_hash_algorithms: cfg.local_signature_schemes.clone(),
        }),
        // RFC 5746 3.4: empty in an initial handshake. The signalling suite is not sent as
        // well.
        Extension::RenegotiationInfo(ExtensionRenegotiationInfo::default()),
    ];

    if cfg.local_psk_callback.is_none() {
        extensions.extend_from_slice(&[
            Extension::SupportedEllipticCurves(ExtensionSupportedEllipticCurves {
                elliptic_curves: cfg.local_named_curves.clone(),
            }),
            Extension::SupportedPointFormats(ExtensionSupportedPointFormats {
                point_formats: vec![ELLIPTIC_CURVE_POINT_FORMAT_UNCOMPRESSED],
            }),
        ]);
    }

    if !cfg.local_srtp_protection_profiles.is_empty() {
        extensions.push(Extension::UseSrtp(ExtensionUseSrtp {
            protection_profiles: cfg.local_srtp_protection_profiles.clone(),
            mki: vec![],
        }));
    }

    if cfg.extended_master_secret == ExtendedMasterSecretType::Request
        || cfg.extended_master_secret == ExtendedMasterSecretType::Require
    {
        extensions.push(Extension::UseExtendedMasterSecret(
            ExtensionUseExtendedMasterSecret { supported: true },
        ));
    }

    if let Some(host_name) = sni_host_name(&cfg.server_name) {
        extensions.push(Extension::ServerName(ExtensionServerName {
            server_name: host_name.to_owned(),
        }));
    }

    if let Some(offer) = tls13_offer {
        extensions.extend(offer.extensions(cfg));
    }

    extensions
}

/// The cipher suites of this client's ClientHello: the TLS 1.3 ones when DTLS 1.3 is offered,
/// then the DTLS 1.2 ones unless DTLS 1.3 is the least it accepts.
pub(crate) fn client_hello_cipher_suites(cfg: &HandshakeConfig) -> Vec<CipherSuiteId> {
    let mut suites = cfg.local_tls13_cipher_suites.clone();
    if cfg.supports_dtls12() || suites.is_empty() {
        suites.extend_from_slice(&cfg.local_cipher_suites);
    }
    suites
}

/// The HostName a client puts in its server_name extension for `server_name`, if it may send
/// one: RFC 6066 section 3 permits DNS host names only, not literal IPv4 or IPv6 addresses,
/// and writes them without a trailing dot. The configured name still names the certificate
/// that is expected; an address is simply not announced.
pub(crate) fn sni_host_name(server_name: &str) -> Option<&str> {
    let host_name = server_name.strip_suffix('.').unwrap_or(server_name);
    let is_address = host_name.parse::<std::net::IpAddr>().is_ok()
        || host_name
            .strip_prefix('[')
            .and_then(|rest| rest.strip_suffix(']'))
            .is_some_and(|inner| inner.parse::<std::net::Ipv6Addr>().is_ok());
    (!host_name.is_empty() && !is_address).then_some(host_name)
}
