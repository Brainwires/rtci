use super::flight2::*;
use super::*;
use crate::compression_methods::CompressionMethodId;
use crate::config::*;
use crate::conn::*;
use crate::crypto::certificates_signed_within;
use crate::extension::*;
use crate::handshake::handshake_message_client_hello::HandshakeMessageClientHello;
use crate::handshake::*;
use crate::signature_hash_algorithm::{
    default_remote_signature_schemes, select_common_signature_scheme,
};
use crate::*;
use shared::error::Error;

use log::debug;
use std::fmt;

#[derive(Debug, PartialEq)]
pub(crate) struct Flight0;

impl fmt::Display for Flight0 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Flight 0")
    }
}

impl Flight for Flight0 {
    fn parse(
        &self,
        //_tx: &mut mpsc::Sender<mpsc::Sender<()>>,
        state: &mut State,
        cache: &HandshakeCache,
        cfg: &HandshakeConfig,
    ) -> Result<Box<dyn Flight>, (Option<Alert>, Option<Error>)> {
        let (seq, msgs) = match cache.full_pull_map(
            0,
            &[HandshakeCachePullRule {
                typ: HandshakeType::ClientHello,
                epoch: cfg.initial_epoch,
                is_client: true,
                optional: false,
            }],
        ) {
            Ok((seq, msgs)) => (seq, msgs),
            Err(_) => return Err((None, None)),
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

            // RFC 5246 E.1: a client offering a later version than 1.2 is answered with 1.2
            // (the ServerHello's version); one offering only an earlier version is refused.
            if !client_hello.version.is_dtls1_2_or_later() {
                return Err((
                    Some(Alert {
                        alert_level: AlertLevel::Fatal,
                        alert_description: AlertDescription::ProtocolVersion,
                    }),
                    Some(Error::ErrUnsupportedProtocolVersion),
                ));
            }

            // Nothing is negotiated from this ClientHello: it carries no cookie, so anyone can
            // have sent it from this address, and it is not part of the handshake transcript.
            // The parameters (and any alert about them) come from the ClientHello that echoes
            // the cookie (`Flight2::parse`), and so does the ECDHE key pair (see
            // `DTLSConn::on_peer_address_verified` and `ensure_local_keypair`).
            Ok(Box::new(Flight2 {}))
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
        cfg: &HandshakeConfig,
    ) -> Result<Vec<Packet>, (Option<Alert>, Option<Error>)> {
        // Initialize
        state.cookie = vec![0; COOKIE_LENGTH];
        if let Err(error) = cfg.provider().random().fill(state.cookie.as_mut_slice()) {
            return Err((None, Some(Error::Crypto(error.to_string()))));
        }

        state.local_epoch = 0;
        state.remote_epoch = 0;

        state.named_curve = DEFAULT_NAMED_CURVE;
        if cfg.local_psk_callback.is_none() {
            state.named_curve = cfg.local_named_curves[0];
        }
        if let Err(error) = state.local_random.populate(cfg.provider().random()) {
            return Err((None, Some(error)));
        }

        Ok(vec![])
    }
}

fn fatal(description: AlertDescription, err: Error) -> (Option<Alert>, Option<Error>) {
    (
        Some(Alert {
            alert_level: AlertLevel::Fatal,
            alert_description: description,
        }),
        Some(err),
    )
}

/// Selects the connection parameters (random, cipher suite, curve, signature algorithm, SRTP
/// profile, extended master secret, renegotiation indication, server name) from a ClientHello.
/// The server runs it on the ClientHello that echoes its cookie: the first one is
/// unauthenticated and not part of the handshake transcript.
pub(crate) fn negotiate_client_hello(
    state: &mut State,
    client_hello: &HandshakeMessageClientHello,
    cfg: &HandshakeConfig,
) -> Result<(), (Option<Alert>, Option<Error>)> {
    // Start from the defaults `Flight0::generate` sets, so that nothing chosen from an earlier
    // ClientHello survives a later one.
    state.named_curve = DEFAULT_NAMED_CURVE;
    if cfg.local_psk_callback.is_none()
        && let Some(curve) = cfg.local_named_curves.first()
    {
        state.named_curve = *curve;
    }
    state.cipher_suite = None;
    state.srtp_protection_profile = SrtpProtectionProfile::Unsupported;
    state.application_protocol = None;
    state.extended_master_secret = false;
    state.secure_renegotiation = false;
    state.remote_offered_point_formats = false;
    state.local_signature_scheme = None;
    state.server_name.clear();
    // RFC 9146 section 3: what this ClientHello says, not an earlier one's. (The server's
    // own id, once chosen in flight 4, is kept: a repeated ClientHello gets the same.)
    state.remote_connection_id = None;

    state.remote_random = client_hello.random.clone();

    // RFC 5246 7.4.1.2: the list always holds the null method, the only one this crate has.
    if !client_hello
        .compression_methods
        .ids
        .contains(&CompressionMethodId::Null)
    {
        return Err(fatal(
            AlertDescription::IllegalParameter,
            Error::ErrNoNullCompressionMethod,
        ));
    }

    let mut client_curves = None;
    let mut client_signature_schemes = None;
    let mut client_use_srtp = None;
    for extension in &client_hello.extensions {
        match extension {
            Extension::SupportedEllipticCurves(e) => client_curves = Some(&e.elliptic_curves),
            Extension::SupportedPointFormats(_) => state.remote_offered_point_formats = true,
            Extension::SupportedSignatureAlgorithms(e) => {
                client_signature_schemes = Some(e.signature_hash_algorithms.clone())
            }
            Extension::UseSrtp(e) => client_use_srtp = Some(e),
            Extension::UseExtendedMasterSecret(_)
                if cfg.extended_master_secret != ExtendedMasterSecretType::Disable =>
            {
                state.extended_master_secret = true;
            }
            Extension::ServerName(e) => {
                state.server_name.clone_from(&e.server_name); // remote server name
            }
            // RFC 9146 section 3: the connection id the client wants in the records it
            // receives. A server configured for connection ids answers with its own
            // (flight 4); one that is not ignores the extension.
            extension if extension.as_connection_id().is_some() => {
                match extension.as_connection_id() {
                    Some(Ok(connection_id)) if cfg.connection_id.is_some() => {
                        state.remote_connection_id = Some(connection_id.to_vec());
                    }
                    Some(Err(error)) => {
                        return Err(fatal(AlertDescription::DecodeError, error));
                    }
                    _ => {}
                }
            }
            // RFC 7301 section 3.2: the first of this server's protocols the client offered;
            // none in common is a no_application_protocol alert. A server without ALPN
            // ignores the extension.
            extension if extension.as_alpn().is_some() => match extension.as_alpn() {
                Some(Ok(offered)) => match cfg.select_alpn(&offered) {
                    Some(Ok(protocol)) => state.application_protocol = Some(protocol),
                    Some(Err(error)) => {
                        return Err(fatal(AlertDescription::NoApplicationProtocol, error));
                    }
                    None => {}
                },
                Some(Err(error)) => return Err(fatal(AlertDescription::DecodeError, error)),
                None => {}
            },
            Extension::RenegotiationInfo(e) => {
                // RFC 5746 3.6: this is an initial handshake, so the field is empty.
                if !e.renegotiated_connection.is_empty() {
                    return Err(fatal(
                        AlertDescription::HandshakeFailure,
                        Error::ErrRenegotiationInfoNotEmpty,
                    ));
                }
                state.secure_renegotiation = true;
            }
            _ => {}
        }
    }
    // RFC 5746 3.6: the signalling suite says the same as an empty renegotiation_info.
    if client_hello
        .cipher_suites
        .contains(&CipherSuiteId::Tls_Empty_Renegotiation_Info_Scsv)
    {
        state.secure_renegotiation = true;
    }

    // RFC 5246 7.4.1.4.1: without the extension the client accepts the SHA-1 defaults only.
    state.remote_signature_schemes =
        client_signature_schemes.unwrap_or_else(default_remote_signature_schemes);

    // What a certificate (ECDHE) suite needs besides the suite itself. RFC 8422 5.1: a curve
    // the client listed (any of ours when it sent no list). RFC 5246 7.4.2, 7.4.3: a
    // certificate signed with, and a key able to sign the ServerKeyExchange with, a pair the
    // client listed.
    let curve = match client_curves {
        None => cfg.local_named_curves.first().copied(),
        Some(curves) => curves
            .iter()
            .find(|curve| cfg.local_named_curves.contains(curve))
            .copied(),
    };
    let signature_scheme = cfg
        .get_certificate(&cfg.server_name)
        .ok()
        .filter(|certificate| {
            certificates_signed_within(&certificate.certificate, &state.remote_signature_schemes)
        })
        .and_then(|certificate| {
            select_common_signature_scheme(
                &cfg.local_signature_schemes,
                &state.remote_signature_schemes,
                &certificate.private_key,
            )
            .ok()
        });

    // RFC 5246 7.4.1.3, 7.4.3: the first suite of the client's list that this server has and
    // whose requirements the ClientHello meets. Suites it does not know are skipped.
    let mut common_suite = false;
    for id in &client_hello.cipher_suites {
        if !cfg.local_cipher_suites.contains(id) {
            continue;
        }
        let Ok(cipher_suite) = cipher_suite_for_id(*id) else {
            continue;
        };
        common_suite = true;
        if !cipher_suite.is_psk() {
            let (Some(curve), Some(signature_scheme)) = (curve, signature_scheme) else {
                continue;
            };
            state.named_curve = curve;
            state.local_signature_scheme = Some(signature_scheme);
        }
        debug!(
            "[handshake:{}] use cipher suite: {}",
            srv_cli_str(state.is_client),
            cipher_suite.to_string()
        );
        state.cipher_suite = Some(cipher_suite);
        break;
    }
    if state.cipher_suite.is_none() {
        // RFC 5246 7.2.2: handshake_failure, no acceptable set of parameters.
        let err = if !common_suite {
            Error::ErrCipherSuiteNoIntersection
        } else if curve.is_none() {
            Error::ErrNoSupportedEllipticCurves
        } else {
            Error::ErrNoAvailableSignatureSchemes
        };
        return Err(fatal(AlertDescription::HandshakeFailure, err));
    }

    // RFC 5764 4.1.1: a server that does not do DTLS-SRTP ignores use_srtp. One that does and
    // shares no profile with the client leaves the extension out too, and the association
    // falls back to DTLS without SRTP; it refuses only when told that is not acceptable.
    if let Some(use_srtp) = client_use_srtp
        && !cfg.local_srtp_protection_profiles.is_empty()
    {
        match find_matching_srtp_profile(
            &use_srtp.protection_profiles,
            &cfg.local_srtp_protection_profiles,
        ) {
            Ok(profile) => state.srtp_protection_profile = profile,
            Err(_) if cfg.use_srtp_required => {
                return Err(fatal(
                    AlertDescription::InsufficientSecurity,
                    Error::ErrServerNoMatchingSrtpProfile,
                ));
            }
            Err(_) => {}
        }
    }

    // RFC 7627 5.2: handshake_failure.
    if cfg.extended_master_secret == ExtendedMasterSecretType::Require
        && !state.extended_master_secret
    {
        return Err(fatal(
            AlertDescription::HandshakeFailure,
            Error::ErrServerRequiredButNoClientEms,
        ));
    }
    Ok(())
}

/// Makes the server's ECDHE key pair one for the negotiated curve, generating it if there is
/// none yet or the curve changed. Run on the cookie-verified ClientHello only: a cookieless one
/// must cost no key generation (RFC 6347 4.2.1).
pub(crate) fn ensure_local_keypair(
    state: &mut State,
    cfg: &HandshakeConfig,
) -> Result<(), (Option<Alert>, Option<Error>)> {
    let keypair_matches_curve = state
        .local_keypair
        .as_ref()
        .is_some_and(|keypair| keypair.curve == state.named_curve);
    if !keypair_matches_curve {
        state.local_keypair = match state
            .named_curve
            .generate_keypair_with_crypto(cfg.provider().crypto())
        {
            Ok(local_keypar) => Some(local_keypar),
            Err(err) => {
                return Err((
                    Some(Alert {
                        alert_level: AlertLevel::Fatal,
                        alert_description: AlertDescription::IllegalParameter,
                    }),
                    Some(err),
                ));
            }
        };
    }
    Ok(())
}
