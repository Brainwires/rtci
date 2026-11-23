use super::flight1::client_hello_extensions;
use super::flight5::*;
use super::*;
use crate::compression_methods::*;
use crate::config::*;
use crate::content::*;
use crate::extension::extension_use_srtp::*;
use crate::extension::*;
use crate::handshake::handshake_message_client_hello::*;
use crate::handshake::handshake_message_server_hello::HandshakeMessageServerHello;
use crate::handshake::handshake_message_server_key_exchange::*;
use crate::handshake::*;
use crate::record_layer::record_layer_header::*;
use crate::record_layer::*;
use shared::error::Error;

use crate::cipher_suite::cipher_suite_for_id;
use crate::prf::{prf_pre_master_secret, prf_psk_pre_master_secret};
use crate::{find_matching_cipher_suite, find_matching_srtp_profile};

use log::*;
use std::fmt;

#[derive(Debug, PartialEq)]
pub(crate) struct Flight3;

impl fmt::Display for Flight3 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Flight 3")
    }
}

impl Flight for Flight3 {
    fn parse(
        &self,
        //_tx: &mut mpsc::Sender<mpsc::Sender<()>>,
        state: &mut State,
        cache: &HandshakeCache,
        cfg: &HandshakeConfig,
    ) -> Result<Box<dyn Flight>, (Option<Alert>, Option<Error>)> {
        // Clients may receive multiple HelloVerifyRequest messages with different cookies.
        // Clients SHOULD handle this by sending a new ClientHello with a cookie in response
        // to the new HelloVerifyRequest. RFC 6347 Section 4.2.1
        if let Ok((seq, msgs)) = cache.full_pull_map(
            state.handshake_recv_sequence,
            &[HandshakeCachePullRule {
                typ: HandshakeType::HelloVerifyRequest,
                epoch: cfg.initial_epoch,
                is_client: false,
                optional: true,
            }],
        ) && let Some(message) = msgs.get(&HandshakeType::HelloVerifyRequest)
        {
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

            // DTLS 1.2 clients must not assume that the server will use the protocol version
            // specified in HelloVerifyRequest message. RFC 6347 Section 4.2.1
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
            return Ok(Box::new(Flight3 {}) as Box<dyn Flight>);
        }

        // RFC 5246 7.3: a ServerHello that echoes the session id this client offered resumes
        // the session: the abbreviated handshake. One with another id begins a full handshake,
        // and the session is not offered again.
        if state.dtls12_offer.is_some()
            && let Ok((_, msgs)) = cache.full_pull_map(
                state.handshake_recv_sequence,
                &[HandshakeCachePullRule {
                    typ: HandshakeType::ServerHello,
                    epoch: cfg.initial_epoch,
                    is_client: false,
                    optional: false,
                }],
            )
            && let Some(HandshakeMessage::ServerHello(h)) = msgs.get(&HandshakeType::ServerHello)
        {
            if !h.session_id.is_empty() && h.session_id == state.session_id {
                return parse_abbreviated(state, cache, cfg, h);
            }
            state.dtls12_offer = None;
        }

        let result = if cfg.local_psk_callback.is_some() {
            cache.full_pull_map(
                state.handshake_recv_sequence,
                &[
                    HandshakeCachePullRule {
                        typ: HandshakeType::ServerHello,
                        epoch: cfg.initial_epoch,
                        is_client: false,
                        optional: false,
                    },
                    HandshakeCachePullRule {
                        typ: HandshakeType::ServerKeyExchange,
                        epoch: cfg.initial_epoch,
                        is_client: false,
                        optional: true,
                    },
                    HandshakeCachePullRule {
                        typ: HandshakeType::ServerHelloDone,
                        epoch: cfg.initial_epoch,
                        is_client: false,
                        optional: false,
                    },
                ],
            )
        } else {
            cache.full_pull_map(
                state.handshake_recv_sequence,
                &[
                    HandshakeCachePullRule {
                        typ: HandshakeType::ServerHello,
                        epoch: cfg.initial_epoch,
                        is_client: false,
                        optional: false,
                    },
                    HandshakeCachePullRule {
                        typ: HandshakeType::Certificate,
                        epoch: cfg.initial_epoch,
                        is_client: false,
                        optional: true,
                    },
                    HandshakeCachePullRule {
                        typ: HandshakeType::ServerKeyExchange,
                        epoch: cfg.initial_epoch,
                        is_client: false,
                        optional: false,
                    },
                    HandshakeCachePullRule {
                        typ: HandshakeType::CertificateRequest,
                        epoch: cfg.initial_epoch,
                        is_client: false,
                        optional: true,
                    },
                    HandshakeCachePullRule {
                        typ: HandshakeType::ServerHelloDone,
                        epoch: cfg.initial_epoch,
                        is_client: false,
                        optional: false,
                    },
                ],
            )
        };

        let (seq, msgs) = match result {
            Ok((seq, msgs)) => (seq, msgs),
            Err(_) => return Err((None, None)),
        };

        state.handshake_recv_sequence = seq;

        if let Some(message) = msgs.get(&HandshakeType::ServerHello) {
            let h = match message {
                HandshakeMessage::ServerHello(h) => h,
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
            process_server_hello(state, cfg, h)?;
            // RFC 5246 7.4.1.3: the session this full handshake makes, if the server keeps
            // it. RFC 5077 section 3.3: a NewSessionTicket comes if the ServerHello said so.
            state.session_id.clone_from(&h.session_id);
            state.new_session_ticket = server_announces_ticket(h)?;
        }

        if let Some(message) = msgs.get(&HandshakeType::Certificate) {
            let h = match message {
                HandshakeMessage::Certificate(h) => h,
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
            state.peer_certificates.clone_from(&h.certificate);
        }

        if let Some(message) = msgs.get(&HandshakeType::ServerKeyExchange) {
            let h = match message {
                HandshakeMessage::ServerKeyExchange(h) => h,
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

            if let Err((alert, err)) = handle_server_key_exchange(state, cfg, h) {
                return Err((alert, err));
            }
        }

        if let Some(message) = msgs.get(&HandshakeType::CertificateRequest) {
            let h = match message {
                HandshakeMessage::CertificateRequest(h) => h,
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
            state.remote_requested_certificate = true;
            // RFC 5246 7.4.4: what the client's certificate and CertificateVerify must fit.
            state
                .remote_certificate_types
                .clone_from(&h.certificate_types);
            state
                .remote_signature_schemes
                .clone_from(&h.signature_hash_algorithms);
        }

        Ok(Box::new(Flight5 {}) as Box<dyn Flight>)
    }

    fn generate(
        &self,
        state: &mut State,
        _cache: &HandshakeCache,
        cfg: &HandshakeConfig,
    ) -> Result<Vec<Packet>, (Option<Alert>, Option<Error>)> {
        // RFC 6347 4.2.1: the same parameters as the first ClientHello, plus the cookie.
        let extensions = client_hello_extensions(
            cfg,
            state.tls13_offer.as_ref(),
            state.connection_id_offer.as_deref(),
            state.session_ticket_offer.as_deref(),
        );

        let mut client_hello = HandshakeMessageClientHello {
            session_id: state.session_id.clone(),
            version: PROTOCOL_VERSION1_2,
            random: state.local_random.clone(),
            cookie: state.cookie.clone(),

            cipher_suites: super::flight1::client_hello_cipher_suites(cfg),
            compression_methods: default_compression_methods(),
            extensions,
        };
        // The PSK binders cover the cookie too.
        if let Err(error) =
            super::flight1::bind_client_hello(cfg, state.tls13_offer.as_ref(), &mut client_hello)
        {
            return Err((None, Some(error)));
        }

        Ok(vec![Packet {
            record: RecordLayer::new(
                PROTOCOL_VERSION1_2,
                0,
                Content::Handshake(Handshake::new(HandshakeMessage::ClientHello(client_hello))),
            ),
            should_encrypt: false,
            reset_local_sequence_number: false,
        }])
    }
}

/// The checks and settings of a DTLS 1.2 ServerHello, in a full or an abbreviated handshake:
/// version, compression, extensions (only ones the ClientHello carried), SRTP profile,
/// extended master secret, secure renegotiation, connection ids, the cipher suite.
fn process_server_hello(
    state: &mut State,
    cfg: &HandshakeConfig,
    h: &HandshakeMessageServerHello,
) -> Result<(), (Option<Alert>, Option<Error>)> {
    if h.version != PROTOCOL_VERSION1_2 {
        return Err((
            Some(Alert {
                alert_level: AlertLevel::Fatal,
                alert_description: AlertDescription::ProtocolVersion,
            }),
            Some(Error::ErrUnsupportedProtocolVersion),
        ));
    }

    // RFC 5246 7.4.1.3: null is the only compression method this client offers.
    if h.compression_method != CompressionMethodId::Null {
        return Err((
            Some(Alert {
                alert_level: AlertLevel::Fatal,
                alert_description: AlertDescription::IllegalParameter,
            }),
            Some(Error::ErrCompressionMethodNotOffered),
        ));
    }

    // RFC 5246 7.4.1.4: an extension type the ClientHello did not carry is answered
    // with unsupported_extension.
    let offered: Vec<u16> = client_hello_extensions(
        cfg,
        state.tls13_offer.as_ref(),
        state.connection_id_offer.as_deref(),
        state.session_ticket_offer.as_deref(),
    )
    .iter()
    .map(|extension| extension.extension_type())
    .collect();
    if h.extensions
        .iter()
        .any(|extension| !offered.contains(&extension.extension_type()))
    {
        return Err((
            Some(Alert {
                alert_level: AlertLevel::Fatal,
                alert_description: AlertDescription::UnsupportedExtension,
            }),
            Some(Error::ErrUnsolicitedExtension),
        ));
    }

    state.srtp_protection_profile = SrtpProtectionProfile::Unsupported;
    state.extended_master_secret = false;
    state.secure_renegotiation = false;
    // RFC 9146 section 3: with the extension in both hellos, connection ids are
    // negotiated. The server's is what this client puts in its records; the one
    // this client offered is what the server puts in its own. (An extension the
    // ClientHello did not carry was refused above.)
    state.local_connection_id = None;
    state.remote_connection_id = None;
    // RFC 7301 section 3.1: the ServerHello names exactly one protocol, one this client
    // offered (an ALPN extension the ClientHello did not carry was refused above).
    state.application_protocol = None;
    for extension in &h.extensions {
        match extension.as_alpn() {
            Some(Ok(protocols)) => match protocols.as_slice() {
                [protocol] if cfg.alpn_protocols.contains(protocol) => {
                    state.application_protocol = Some(protocol.clone());
                }
                _ => {
                    return Err((
                        Some(Alert {
                            alert_level: AlertLevel::Fatal,
                            alert_description: AlertDescription::IllegalParameter,
                        }),
                        Some(Error::Other(
                            "the server selected an application protocol not offered".to_owned(),
                        )),
                    ));
                }
            },
            Some(Err(error)) => {
                return Err((
                    Some(Alert {
                        alert_level: AlertLevel::Fatal,
                        alert_description: AlertDescription::DecodeError,
                    }),
                    Some(error),
                ));
            }
            None => {}
        }
    }
    for extension in &h.extensions {
        match extension.as_connection_id() {
            Some(Ok(connection_id)) => {
                state.remote_connection_id = Some(connection_id.to_vec());
                state
                    .local_connection_id
                    .clone_from(&state.connection_id_offer);
            }
            Some(Err(error)) => {
                return Err((
                    Some(Alert {
                        alert_level: AlertLevel::Fatal,
                        alert_description: AlertDescription::DecodeError,
                    }),
                    Some(error),
                ));
            }
            None => {}
        }
    }
    for extension in &h.extensions {
        match extension {
            Extension::UseSrtp(e) => {
                // RFC 5764 4.1.1: exactly one profile. 4.1.3: this client offers no
                // MKI, so a server that returns one has changed the offer.
                if e.protection_profiles.len() != 1 || !e.mki.is_empty() {
                    return Err((
                        Some(Alert {
                            alert_level: AlertLevel::Fatal,
                            alert_description: AlertDescription::IllegalParameter,
                        }),
                        Some(Error::ErrInvalidUseSrtpAnswer),
                    ));
                }
                let profile = match find_matching_srtp_profile(
                    &e.protection_profiles,
                    &cfg.local_srtp_protection_profiles,
                ) {
                    Ok(profile) => profile,
                    Err(_) => {
                        return Err((
                            Some(Alert {
                                alert_level: AlertLevel::Fatal,
                                alert_description: AlertDescription::IllegalParameter,
                            }),
                            Some(Error::ErrClientNoMatchingSrtpProfile),
                        ));
                    }
                };
                state.srtp_protection_profile = profile;
            }
            Extension::UseExtendedMasterSecret(_) => {
                state.extended_master_secret = true;
            }
            Extension::RenegotiationInfo(e) => {
                // RFC 5746 3.4: this is an initial handshake, so the field is empty.
                if !e.renegotiated_connection.is_empty() {
                    return Err((
                        Some(Alert {
                            alert_level: AlertLevel::Fatal,
                            alert_description: AlertDescription::HandshakeFailure,
                        }),
                        Some(Error::ErrRenegotiationInfoNotEmpty),
                    ));
                }
                state.secure_renegotiation = true;
            }
            _ => {}
        };
    }

    // RFC 7627 5.2: handshake_failure.
    if cfg.extended_master_secret == ExtendedMasterSecretType::Require
        && !state.extended_master_secret
    {
        return Err((
            Some(Alert {
                alert_level: AlertLevel::Fatal,
                alert_description: AlertDescription::HandshakeFailure,
            }),
            Some(Error::ErrClientRequiredButNoServerEms),
        ));
    }
    if !cfg.local_srtp_protection_profiles.is_empty()
        && !cfg.use_srtp_optional
        && state.srtp_protection_profile == SrtpProtectionProfile::Unsupported
    {
        return Err((
            Some(Alert {
                alert_level: AlertLevel::Fatal,
                alert_description: AlertDescription::InsufficientSecurity,
            }),
            Some(Error::ErrRequestedButNoSrtpExtension),
        ));
    }
    // RFC 5246 7.4.1.3: the suite is one of the ClientHello's.
    if find_matching_cipher_suite(&[h.cipher_suite], &cfg.local_cipher_suites).is_err() {
        debug!(
            "[handshake:{}] use cipher suite: {}",
            srv_cli_str(state.is_client),
            h.cipher_suite
        );

        return Err((
            Some(Alert {
                alert_level: AlertLevel::Fatal,
                alert_description: AlertDescription::IllegalParameter,
            }),
            Some(Error::ErrCipherSuiteNoIntersection),
        ));
    }

    let cipher_suite = match cipher_suite_for_id(h.cipher_suite) {
        Ok(cipher_suite) => cipher_suite,
        Err(_) => {
            debug!(
                "[handshake:{}] use cipher suite: {}",
                srv_cli_str(state.is_client),
                h.cipher_suite
            );

            return Err((
                Some(Alert {
                    alert_level: AlertLevel::Fatal,
                    alert_description: AlertDescription::InsufficientSecurity,
                }),
                Some(Error::ErrInvalidCipherSuite),
            ));
        }
    };

    debug!(
        "[handshake:{}] use cipher suite: {}",
        srv_cli_str(state.is_client),
        cipher_suite.to_string()
    );

    // The same suite again (the flight is parsed once more when the rest of it comes) keeps
    // the one there, whose keys a resumption may have made already.
    if state
        .cipher_suite
        .as_ref()
        .is_none_or(|current| current.id() != cipher_suite.id())
    {
        state.cipher_suite = Some(cipher_suite);
    }
    state.remote_random = h.random.clone();
    Ok(())
}

/// RFC 5077 section 3.2: whether the ServerHello carries the SessionTicket extension, which
/// says a NewSessionTicket follows. The server's is empty.
fn server_announces_ticket(
    h: &HandshakeMessageServerHello,
) -> Result<bool, (Option<Alert>, Option<Error>)> {
    match crate::resumption::session_ticket_of(&h.extensions) {
        Some(data) if !data.is_empty() => Err(crate::resumption::fatal(
            AlertDescription::DecodeError,
            Error::ErrInvalidExtensionType,
        )),
        Some(_) => Ok(true),
        None => Ok(false),
    }
}

/// The client's side of the abbreviated handshake (RFC 5246 7.3): the server resumes the
/// session offered. Its flight is ServerHello, NewSessionTicket if announced, ChangeCipherSpec
/// and Finished; the keys come from the session's master secret, and the server's Finished is
/// checked over ClientHello, ServerHello and NewSessionTicket before this client sends its
/// own.
fn parse_abbreviated(
    state: &mut State,
    cache: &HandshakeCache,
    cfg: &HandshakeConfig,
    h: &HandshakeMessageServerHello,
) -> Result<Box<dyn Flight>, (Option<Alert>, Option<Error>)> {
    process_server_hello(state, cfg, h)?;
    state.session_id.clone_from(&h.session_id);
    state.new_session_ticket = server_announces_ticket(h)?;
    crate::resumption::client_resume(state, cfg)?;

    let rule = |typ, epoch, optional| HandshakeCachePullRule {
        typ,
        epoch,
        is_client: false,
        optional,
    };
    let Ok((seq, msgs)) = cache.full_pull_map(
        state.handshake_recv_sequence,
        &[
            rule(HandshakeType::ServerHello, cfg.initial_epoch, false),
            rule(HandshakeType::NewSessionTicket, cfg.initial_epoch, true),
            rule(HandshakeType::Finished, cfg.initial_epoch + 1, false),
        ],
    ) else {
        // The ChangeCipherSpec and Finished are still to come, or were held until the keys
        // were made.
        return Err((None, None));
    };
    take_new_session_ticket(state, &msgs)?;
    let Some(HandshakeMessage::Finished(finished)) = msgs.get(&HandshakeType::Finished) else {
        return Err(crate::resumption::fatal(
            AlertDescription::InternalError,
            Error::ErrInvalidContentType,
        ));
    };
    let Some(cipher_suite) = &state.cipher_suite else {
        return Err(crate::resumption::fatal(
            AlertDescription::InternalError,
            Error::ErrCipherSuiteUnset,
        ));
    };
    let expected = crate::prf::prf_verify_data_server(
        cfg.provider().crypto(),
        &state.master_secret,
        &crate::resumption::abbreviated_transcript(cache, cfg, false),
        cipher_suite.hash_func(),
    )
    .map_err(|err| crate::resumption::fatal(AlertDescription::InternalError, err))?;
    // RFC 5246 7.4.9, 7.2.2: decrypt_error for a Finished that does not verify.
    if !crypto::constant_time_eq(&expected, &finished.verify_data) {
        return Err(crate::resumption::fatal(
            AlertDescription::DecryptError,
            Error::ErrVerifyDataMismatch,
        ));
    }
    state.handshake_recv_sequence = seq;
    Ok(Box::new(super::flight5b::Flight5b {}))
}

/// RFC 5077 section 3.3: a NewSessionTicket comes only after a ServerHello that announced it
/// (unexpected_message otherwise); a ticket that is not empty is kept, to store the session
/// with once the handshake completes.
pub(crate) fn take_new_session_ticket(
    state: &mut State,
    msgs: &std::collections::HashMap<HandshakeType, HandshakeMessage>,
) -> Result<(), (Option<Alert>, Option<Error>)> {
    match msgs.get(&HandshakeType::NewSessionTicket) {
        Some(_) if !state.new_session_ticket => Err(crate::resumption::fatal(
            AlertDescription::UnexpectedMessage,
            Error::ErrInvalidContentType,
        )),
        Some(HandshakeMessage::NewSessionTicket(ticket)) => {
            state.received_ticket = (!ticket.ticket.is_empty())
                .then(|| (ticket.ticket.clone(), ticket.ticket_lifetime_hint));
            Ok(())
        }
        _ => Ok(()),
    }
}

pub(crate) fn handle_server_key_exchange(
    state: &mut State,
    cfg: &HandshakeConfig,
    h: &HandshakeMessageServerKeyExchange,
) -> Result<(), (Option<Alert>, Option<Error>)> {
    if let Some(local_psk_callback) = &cfg.local_psk_callback {
        let psk = match local_psk_callback(&h.identity_hint) {
            Ok(psk) => psk,
            Err(err) => {
                return Err((
                    Some(Alert {
                        alert_level: AlertLevel::Fatal,
                        alert_description: AlertDescription::InternalError,
                    }),
                    Some(err),
                ));
            }
        };

        state.identity_hint.clone_from(&h.identity_hint);
        state.pre_master_secret = prf_psk_pre_master_secret(&psk);
    } else {
        let mut local_keypair = match h
            .named_curve
            .generate_keypair_with_crypto(cfg.provider().crypto())
        {
            Ok(local_keypair) => local_keypair,
            Err(err) => {
                return Err((
                    Some(Alert {
                        alert_level: AlertLevel::Fatal,
                        alert_description: AlertDescription::InternalError,
                    }),
                    Some(err),
                ));
            }
        };

        let curve = local_keypair.curve;
        state.pre_master_secret =
            match prf_pre_master_secret(&h.public_key, &mut local_keypair, curve) {
                Ok(pre_master_secret) => pre_master_secret,
                Err(err) => {
                    // RFC 8422 5.10: a peer's point that is not on the curve (or otherwise
                    // unusable) is refused: illegal_parameter.
                    return Err((
                        Some(Alert {
                            alert_level: AlertLevel::Fatal,
                            alert_description: AlertDescription::IllegalParameter,
                        }),
                        Some(err),
                    ));
                }
            };

        state.local_keypair = Some(local_keypair);
    }

    Ok(())
}
