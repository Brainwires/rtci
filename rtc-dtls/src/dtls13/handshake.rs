//! The DTLS 1.3 handshake (RFC 8446 section 4 as RFC 9147 section 5 carries it): what each
//! side does with each message, and the flights it answers with.
//!
//! ```text
//!  Client                                          Server
//!  ClientHello               -------->
//!                            <--------  HelloRetryRequest (cookie, and a group if needed)
//!  ClientHello + cookie      -------->
//!                                                 ServerHello
//!                                       {EncryptedExtensions}
//!                                       {CertificateRequest*}
//!                                               {Certificate}
//!                                         {CertificateVerify}
//!                            <--------             {Finished}
//!  {Certificate*}
//!  {CertificateVerify*}
//!  {Finished}                -------->
//!                            <--------                  [ACK]
//! ```

use super::codec::*;
use super::conn::*;
use super::hello::*;
use super::key_schedule::{DTLS13_LABEL_PREFIX, KeySchedule, certificate_verify_input};
use super::messages::*;
use super::suite::Suite13;
use super::{DTLS1_2_WIRE_VERSION, DTLS1_3_WIRE_VERSION};
use crate::cipher_suite::CipherSuiteId;
use crate::config::{ClientAuthType, HandshakeConfig};
use crate::crypto::{verify_client_cert, verify_server_cert};
use crate::curve::named_curve::NamedCurve;
use crate::extension::extension_use_srtp::SrtpProtectionProfile;
use crate::signature_hash_algorithm::{SignatureAlgorithm, SignatureHashAlgorithm};
use crypto::{PublicKey, PublicKeyEncoding, SecretVec};
use log::debug;
use shared::error::{Error, Result};
use std::net::SocketAddr;
use std::sync::Arc;

fn internal(error: Error) -> Refusal {
    refuse(alert::INTERNAL_ERROR, error)
}

fn illegal(error: Error) -> Refusal {
    refuse(alert::ILLEGAL_PARAMETER, error)
}

fn unexpected() -> Refusal {
    refuse(alert::UNEXPECTED_MESSAGE, Error::ErrUnhandledContextType)
}

/// What a server was told about a ClientHello before the association saw it.
pub(crate) struct ServerStart {
    /// The message_seq of the ClientHello.
    pub(crate) message_seq: u16,
    /// The sequence number of the record it came in, which the server's first plaintext
    /// record takes.
    pub(crate) record_sequence: u64,
    /// The client's address is known to be its own (a cookie exchange, or the application
    /// says so by switching the exchange off).
    pub(crate) address_verified: bool,
    /// The cookie of this ClientHello, already verified by the endpoint, with what it holds.
    pub(crate) verified_retry: Option<(Vec<u8>, RetryCookie)>,
}

impl Conn13 {
    // ------------------------------------------------------------------------------------
    // Construction.
    // ------------------------------------------------------------------------------------

    /// The association of a client whose ClientHello, `client_hello` (the body), was
    /// answered with a ServerHello or HelloRetryRequest that selects DTLS 1.3.
    pub(crate) fn client(
        cfg: Arc<HandshakeConfig>,
        offer: ClientOffer,
        client_hello: Vec<u8>,
        client_hello_message_seq: u16,
        next_plaintext_sequence: u64,
    ) -> Self {
        let mut conn = Self::new(cfg, true, HandshakeState::ClientWaitServerHello);
        conn.transcript.add(CLIENT_HELLO, &client_hello);
        conn.offered_extensions = ClientHello::parse(&client_hello)
            .map(|hello| hello.extensions.iter().map(|(t, _)| *t).collect())
            .unwrap_or_default();
        conn.client_hello = client_hello;
        conn.offer = Some(offer);
        conn.next_send_seq = client_hello_message_seq.wrapping_add(1);
        conn.set_plaintext_send_sequence(next_plaintext_sequence);
        conn.address_verified = true;
        conn
    }

    /// The association of a server for a ClientHello that offers DTLS 1.3. The ClientHello
    /// is processed: the server's first flight, a HelloRetryRequest or an alert is queued.
    pub(crate) fn server(
        cfg: Arc<HandshakeConfig>,
        client_hello: &[u8],
        start: ServerStart,
    ) -> Self {
        let mut conn = Self::new(cfg, false, HandshakeState::ServerWaitClientHello);
        conn.set_next_receive_seq(start.message_seq.wrapping_add(1));
        conn.set_plaintext_send_sequence(start.record_sequence);
        conn.address_verified = start.address_verified;
        if start.verified_retry.is_some() {
            // The HelloRetryRequest was message 0 of this server.
            conn.next_send_seq = 1;
        }
        conn.verified_retry = start.verified_retry;
        if let Err(refusal) = conn.on_client_hello(client_hello) {
            conn.refuse(refusal);
        }
        conn
    }

    // ------------------------------------------------------------------------------------
    // Dispatch.
    // ------------------------------------------------------------------------------------

    /// One whole handshake message, next in order, from a record of `epoch`.
    pub(crate) fn on_handshake_message(
        &mut self,
        handshake_type: u8,
        body: &[u8],
        epoch: u64,
    ) -> std::result::Result<(), Refusal> {
        // RFC 8446 section 5: the hellos are unprotected, the rest of the handshake is under
        // the handshake keys, and what follows it under the application keys.
        let expected_epoch = match (self.state, handshake_type) {
            (HandshakeState::Established, _) => {
                if epoch < EPOCH_APPLICATION {
                    return Err(unexpected());
                }
                return self.on_post_handshake_message(handshake_type, body);
            }
            (_, CLIENT_HELLO | SERVER_HELLO) => 0,
            _ => EPOCH_HANDSHAKE,
        };
        if epoch != expected_epoch {
            return Err(unexpected());
        }
        match (self.state, handshake_type) {
            (HandshakeState::ClientWaitServerHello, SERVER_HELLO) => self.on_server_hello(body),
            (HandshakeState::ClientWaitEncryptedExtensions, ENCRYPTED_EXTENSIONS) => {
                self.on_encrypted_extensions(body)
            }
            (HandshakeState::ClientWaitCertificateOrRequest, CERTIFICATE_REQUEST) => {
                self.on_certificate_request(body)
            }
            (
                HandshakeState::ClientWaitCertificateOrRequest
                | HandshakeState::ClientWaitCertificate
                | HandshakeState::ServerWaitCertificate,
                CERTIFICATE,
            ) => self.on_certificate(body),
            (
                HandshakeState::ClientWaitCertificateVerify
                | HandshakeState::ServerWaitCertificateVerify,
                CERTIFICATE_VERIFY,
            ) => self.on_certificate_verify(body),
            (HandshakeState::ClientWaitFinished, FINISHED) => self.on_server_finished(body),
            (HandshakeState::ServerWaitFinished, FINISHED) => self.on_client_finished(body),
            (HandshakeState::ServerWaitClientHello, CLIENT_HELLO) => self.on_client_hello(body),
            // RFC 8446 section 4: any other message, or a message out of its order, is an
            // unexpected_message.
            _ => Err(unexpected()),
        }
    }

    fn crypto(&self) -> &dyn crypto::RTCCrypto {
        self.provider.crypto()
    }

    fn transcript_hash(&self) -> std::result::Result<Vec<u8>, Refusal> {
        let suite = self.suite().map_err(internal)?;
        self.transcript.hash(self.crypto(), suite).map_err(internal)
    }

    /// Installs the handshake traffic keys of both directions (epoch 2), from the shared
    /// secret and the transcript through the ServerHello.
    fn enter_handshake_keys(&mut self, shared_secret: &[u8]) -> std::result::Result<(), Refusal> {
        let suite = self.suite().map_err(internal)?;
        let hash = self.transcript_hash()?;
        let mut schedule =
            KeySchedule::new(self.crypto(), suite, DTLS13_LABEL_PREFIX).map_err(internal)?;
        schedule
            .enter_handshake(self.crypto(), shared_secret, &hash)
            .map_err(internal)?;
        let client = schedule.client_handshake_traffic.clone();
        let server = schedule.server_handshake_traffic.clone();
        self.schedule = Some(schedule);
        let (Some(client), Some(server)) = (client, server) else {
            return Err(internal(Error::ErrCipherSuiteUnset));
        };
        let (local, remote) = if self.is_client {
            (client, server)
        } else {
            (server, client)
        };
        self.install_write_epoch(EPOCH_HANDSHAKE, local.as_ref())
            .map_err(internal)?;
        self.install_read_epoch(EPOCH_HANDSHAKE, remote.as_ref())
            .map_err(internal)?;
        Ok(())
    }

    /// Derives the application traffic secrets and the exporter secret from the transcript
    /// through the server's Finished. Returns (this side's secret, the peer's).
    fn enter_application_secrets(
        &mut self,
    ) -> std::result::Result<(SecretVec, SecretVec), Refusal> {
        let hash = self.transcript_hash()?;
        let provider = self.provider.clone();
        let schedule = self
            .schedule
            .as_mut()
            .ok_or_else(|| internal(Error::ErrCipherSuiteUnset))?;
        schedule
            .enter_application(provider.crypto(), &hash)
            .map_err(internal)?;
        let client = schedule.client_application_traffic.clone();
        let server = schedule.server_application_traffic.clone();
        self.exporter_secret = schedule.exporter.clone();
        let (Some(client), Some(server)) = (client, server) else {
            return Err(internal(Error::ErrCipherSuiteUnset));
        };
        Ok(if self.is_client {
            (client, server)
        } else {
            (server, client)
        })
    }

    fn finished_verify_data(&self, of_client: bool) -> std::result::Result<Vec<u8>, Refusal> {
        let hash = self.transcript_hash()?;
        let schedule = self
            .schedule
            .as_ref()
            .ok_or_else(|| internal(Error::ErrCipherSuiteUnset))?;
        let base_key = if of_client {
            &schedule.client_handshake_traffic
        } else {
            &schedule.server_handshake_traffic
        };
        let base_key = base_key
            .as_ref()
            .ok_or_else(|| internal(Error::ErrCipherSuiteUnset))?;
        schedule
            .finished_verify_data(self.crypto(), base_key.as_ref(), &hash)
            .map_err(internal)
    }

    /// Adds a message of this side to the transcript and to `flight`.
    fn add_to_flight(
        &mut self,
        flight: &mut Flight,
        epoch: u64,
        handshake_type: u8,
        body: Vec<u8>,
    ) {
        self.transcript.add(handshake_type, &body);
        flight.push(self.next_send_seq, epoch, handshake_type, body);
        self.next_send_seq = self.next_send_seq.wrapping_add(1);
    }

    /// The signature schemes this side lists, as code points.
    fn local_scheme_codes(&self) -> Vec<u16> {
        self.cfg
            .local_signature_schemes
            .iter()
            .map(SignatureHashAlgorithm::scheme_code)
            .collect()
    }

    /// Checks a CertificateVerify signature against the end-entity certificate of the
    /// peer's chain (RFC 8446 section 4.4.3).
    fn verify_certificate_signature(
        &self,
        scheme: SignatureHashAlgorithm,
        signature: &[u8],
        from_server: bool,
    ) -> std::result::Result<(), Refusal> {
        let bad_certificate = |error| refuse(alert::BAD_CERTIFICATE, error);
        let end_entity = self
            .peer_certificates
            .first()
            .ok_or_else(|| bad_certificate(Error::ErrLengthMismatch))?;
        let (_, certificate) = x509_parser::parse_x509_certificate(end_entity)
            .map_err(|err| bad_certificate(Error::Other(err.to_string())))?;
        let encoding = match scheme.signature {
            SignatureAlgorithm::Ed25519 => PublicKeyEncoding::Ed25519Raw,
            SignatureAlgorithm::Ecdsa => PublicKeyEncoding::EcUncompressedPoint,
            _ => PublicKeyEncoding::RsaPkcs1Der,
        };
        let crypto_scheme = scheme.crypto_scheme().map_err(illegal)?;
        let input = certificate_verify_input(from_server, &self.transcript_hash()?);
        // RFC 8446 section 6.2: a signature that does not verify is a decrypt_error.
        self.crypto()
            .verify_signature(
                crypto_scheme,
                PublicKey {
                    encoding,
                    bytes: &certificate
                        .tbs_certificate
                        .subject_pki
                        .subject_public_key
                        .data,
                },
                &input,
                signature,
            )
            .map_err(|_| refuse(alert::DECRYPT_ERROR, Error::ErrKeySignatureMismatch))
    }

    // ------------------------------------------------------------------------------------
    // Client.
    // ------------------------------------------------------------------------------------

    fn on_server_hello(&mut self, body: &[u8]) -> std::result::Result<(), Refusal> {
        let hello = ServerHello::parse(body).map_err(decode_error)?;
        // RFC 8446 section 4.1.3, RFC 9147 sections 5 and 5.4.
        if hello.selected_version() != Some(DTLS1_3_WIRE_VERSION)
            || hello.legacy_version != DTLS1_2_WIRE_VERSION
        {
            return Err(illegal(Error::ErrUnsupportedProtocolVersion));
        }
        if !hello.legacy_session_id_echo.is_empty() || hello.legacy_compression_method != 0 {
            return Err(illegal(Error::ErrInvalidCompressionMethod));
        }
        let suite = Some(CipherSuiteId::from(hello.cipher_suite))
            .filter(|suite| self.cfg.local_tls13_cipher_suites.contains(suite))
            .and_then(Suite13::for_id)
            .ok_or_else(|| illegal(Error::ErrInvalidCipherSuite))?;
        // After a HelloRetryRequest the ServerHello keeps its cipher suite (4.1.4).
        if self.suite.is_some_and(|earlier| earlier != suite) {
            return Err(illegal(Error::ErrInvalidCipherSuite));
        }

        if hello.is_hello_retry_request() {
            return self.on_hello_retry_request(&hello, suite, body);
        }

        // RFC 8446 section 4.2: an extension that does not belong in a ServerHello is an
        // illegal_parameter, one that was not offered an unsupported_extension.
        let mut key_share = None;
        for (extension_type, data) in &hello.extensions {
            match *extension_type {
                EXT_SUPPORTED_VERSIONS => {}
                EXT_KEY_SHARE => key_share = Some(*data),
                EXT_CONNECTION_ID if self.offered_extensions.contains(&EXT_CONNECTION_ID) => {
                    let connection_id = parse_connection_id(data).map_err(decode_error)?;
                    self.remote_connection_id = connection_id.to_vec();
                    self.connection_ids_negotiated = true;
                }
                // No PSK was offered.
                EXT_PRE_SHARED_KEY => return Err(illegal(Error::ErrInvalidExtensionType)),
                other if self.offered_extensions.contains(&other) => {
                    return Err(illegal(Error::ErrInvalidExtensionType));
                }
                _ => {
                    return Err(refuse(
                        alert::UNSUPPORTED_EXTENSION,
                        Error::ErrInvalidExtensionType,
                    ));
                }
            }
        }
        let offer = self
            .offer
            .take()
            .ok_or_else(|| internal(Error::ErrNamedCurveAndPrivateKeyMismatch))?;
        if self.connection_ids_negotiated {
            self.local_connection_id = offer.connection_id.clone().unwrap_or_default();
        }
        // RFC 8446 section 4.2.8: the server's share is for a group this client sent a
        // share for; anything else is an illegal_parameter. Without one there is no key
        // exchange this client can do.
        let key_share = key_share.ok_or_else(|| {
            refuse(
                alert::MISSING_EXTENSION,
                Error::ErrNoSupportedEllipticCurves,
            )
        })?;
        let mut reader = Reader::new(key_share);
        let group = reader.u16().map_err(decode_error)?;
        let key_exchange = reader.vec16().map_err(decode_error)?;
        reader.finish().map_err(decode_error)?;
        let mut keypair = offer
            .key_shares
            .into_iter()
            .find(|keypair| keypair.curve as u16 == group)
            .ok_or_else(|| illegal(Error::ErrInvalidNamedCurve))?;
        let shared_secret = SecretVec::new(keypair.complete(key_exchange).map_err(illegal)?);

        self.suite = Some(suite);
        self.transcript.add(SERVER_HELLO, body);
        self.flight_answered();
        self.enter_handshake_keys(shared_secret.as_ref())?;
        self.state = HandshakeState::ClientWaitEncryptedExtensions;
        // What arrived of the server's flight ahead of its ServerHello can be read now.
        self.replay_early_records()
    }

    fn on_hello_retry_request(
        &mut self,
        hello: &ServerHello<'_>,
        suite: Suite13,
        body: &[u8],
    ) -> std::result::Result<(), Refusal> {
        // RFC 8446 section 4.1.4, RFC 9147 section 5.1: a second HelloRetryRequest is an
        // unexpected_message.
        if self.hello_retry_seen {
            return Err(unexpected());
        }
        let mut cookie = None;
        let mut group = None;
        for (extension_type, data) in &hello.extensions {
            match *extension_type {
                EXT_SUPPORTED_VERSIONS => {}
                EXT_COOKIE => cookie = Some(parse_cookie(data).map_err(decode_error)?),
                EXT_KEY_SHARE => match data {
                    [high, low] => group = Some(u16::from_be_bytes([*high, *low])),
                    _ => return Err(decode_error(Error::ErrLengthMismatch)),
                },
                _ => {
                    return Err(refuse(
                        alert::UNSUPPORTED_EXTENSION,
                        Error::ErrInvalidExtensionType,
                    ));
                }
            }
        }
        // RFC 8446 section 4.1.4: a HelloRetryRequest that would change nothing in the
        // ClientHello is an illegal_parameter.
        if cookie.is_none() && group.is_none() {
            return Err(illegal(Error::ErrCookieMismatch));
        }
        let offer = self
            .offer
            .as_mut()
            .ok_or_else(|| internal(Error::ErrNamedCurveAndPrivateKeyMismatch))?;
        let mut new_share = None;
        if let Some(group) = group {
            // Section 4.2.8: the group is one this client supports and sent no share for.
            let curve = NamedCurve::from(group);
            if !self.cfg.local_named_curves.contains(&curve)
                || offer
                    .key_shares
                    .iter()
                    .any(|keypair| keypair.curve == curve)
            {
                return Err(illegal(Error::ErrInvalidNamedCurve));
            }
            let keypair = curve
                .generate_keypair_with_crypto(self.provider.crypto())
                .map_err(internal)?;
            offer.key_shares = vec![keypair];
            new_share = Some(group);
        }

        let first = ClientHello::parse(&self.client_hello).map_err(internal)?;
        let share = new_share.map(|group| (group, offer.key_shares[0].public_key.as_slice()));
        let second = second_client_hello(&first, share, cookie);

        self.suite = Some(suite);
        self.hello_retry_seen = true;
        // Section 4.4.1: the first ClientHello becomes a message_hash in the transcript.
        self.transcript
            .replace_with_message_hash(self.provider.crypto(), suite)
            .map_err(internal)?;
        self.transcript.add(SERVER_HELLO, body);
        self.offered_extensions.push(EXT_COOKIE);

        let mut flight = Flight::new(FlightKind::Handshake);
        self.client_hello.clone_from(&second);
        self.add_to_flight(&mut flight, 0, CLIENT_HELLO, second);
        self.send_flight(flight).map_err(internal)
    }

    fn on_encrypted_extensions(&mut self, body: &[u8]) -> std::result::Result<(), Refusal> {
        let mut reader = Reader::new(body);
        let block = reader.vec16().map_err(decode_error)?;
        reader.finish().map_err(decode_error)?;
        let extensions = read_extensions(block).map_err(decode_error)?;
        for (extension_type, data) in &extensions {
            // RFC 8446 section 4.2: only answers to what the ClientHello offered, and only
            // what belongs in EncryptedExtensions.
            if !self.offered_extensions.contains(extension_type) {
                return Err(refuse(
                    alert::UNSUPPORTED_EXTENSION,
                    Error::ErrInvalidExtensionType,
                ));
            }
            match *extension_type {
                EXT_SERVER_NAME | EXT_SUPPORTED_GROUPS => {}
                EXT_USE_SRTP => {
                    // RFC 5764 section 4.1.1: exactly one profile, one of those offered.
                    let (profiles, _mki) = parse_use_srtp(data).map_err(decode_error)?;
                    let profile = match profiles.as_slice() {
                        [profile] => SrtpProtectionProfile::from(*profile),
                        _ => return Err(illegal(Error::ErrInvalidUseSrtpAnswer)),
                    };
                    if !self.cfg.local_srtp_protection_profiles.contains(&profile) {
                        return Err(illegal(Error::ErrClientNoMatchingSrtpProfile));
                    }
                    self.srtp_profile = profile;
                }
                _ => return Err(illegal(Error::ErrInvalidExtensionType)),
            }
        }
        // As with DTLS 1.2: a client that asked for DTLS-SRTP does not go on without it.
        if !self.cfg.local_srtp_protection_profiles.is_empty()
            && self.srtp_profile == SrtpProtectionProfile::Unsupported
        {
            return Err(refuse(
                alert::INSUFFICIENT_SECURITY,
                Error::ErrRequestedButNoSrtpExtension,
            ));
        }
        self.transcript.add(ENCRYPTED_EXTENSIONS, body);
        self.state = HandshakeState::ClientWaitCertificateOrRequest;
        Ok(())
    }

    fn on_certificate_request(&mut self, body: &[u8]) -> std::result::Result<(), Refusal> {
        let (context, schemes) = parse_certificate_request(body)?;
        // RFC 8446 section 4.3.2: the context is empty in the handshake.
        if !context.is_empty() {
            return Err(illegal(Error::ErrLengthMismatch));
        }
        self.certificate_requested = Some(schemes);
        self.transcript.add(CERTIFICATE_REQUEST, body);
        self.state = HandshakeState::ClientWaitCertificate;
        Ok(())
    }

    fn on_certificate(&mut self, body: &[u8]) -> std::result::Result<(), Refusal> {
        let (context, chain) = parse_certificate(body)?;
        if !context.is_empty() {
            return Err(illegal(Error::ErrLengthMismatch));
        }
        if self.is_client {
            // RFC 8446 section 4.4.2.4: a server's Certificate is never empty.
            if chain.is_empty() {
                return Err(decode_error(Error::ErrServerMustHaveCertificate));
            }
            self.peer_certificates = chain;
            self.transcript.add(CERTIFICATE, body);
            self.state = HandshakeState::ClientWaitCertificateVerify;
            return Ok(());
        }

        // The client's flight has begun: the server's is acknowledged by it.
        self.flight_answered();
        self.transcript.add(CERTIFICATE, body);
        if chain.is_empty() {
            // Section 4.4.2.4: no certificate, where one is required, is a
            // certificate_required.
            if matches!(
                self.cfg.client_auth,
                ClientAuthType::RequireAnyClientCert | ClientAuthType::RequireAndVerifyClientCert
            ) {
                return Err(refuse(
                    alert::CERTIFICATE_REQUIRED,
                    Error::ErrClientCertificateRequired,
                ));
            }
            self.state = HandshakeState::ServerWaitFinished;
        } else {
            self.peer_certificates = chain;
            self.state = HandshakeState::ServerWaitCertificateVerify;
        }
        Ok(())
    }

    fn on_certificate_verify(&mut self, body: &[u8]) -> std::result::Result<(), Refusal> {
        let (code, signature) = parse_certificate_verify(body).map_err(decode_error)?;
        let scheme = SignatureHashAlgorithm::from_scheme_code(code);
        // RFC 8446 section 4.4.3: one of the schemes this side listed, and one TLS 1.3
        // signs with (never RSA PKCS#1 v1.5 or SHA-1).
        if !scheme.is_tls13_signature() || !self.cfg.local_signature_schemes.contains(&scheme) {
            return Err(illegal(Error::ErrNoAvailableSignatureSchemes));
        }
        let from_server = self.is_client;
        let bad_certificate = |error| refuse(alert::BAD_CERTIFICATE, error);

        if from_server {
            self.verify_certificate_signature(scheme, signature, true)?;
            let mut chains = vec![];
            if !self.cfg.insecure_skip_verify {
                let verifier = self.cfg.server_cert_verifier.as_ref().ok_or_else(|| {
                    bad_certificate(Error::Crypto(
                        "CA-chain verification has no configured verifier adapter".to_owned(),
                    ))
                })?;
                chains =
                    verify_server_cert(&self.peer_certificates, verifier, &self.cfg.server_name)
                        .map_err(bad_certificate)?;
            }
            if let Some(verify_peer_certificate) = &self.cfg.verify_peer_certificate {
                verify_peer_certificate(&self.peer_certificates, &chains)
                    .map_err(bad_certificate)?;
            }
            self.state = HandshakeState::ClientWaitFinished;
        } else {
            // As in the DTLS 1.2 handshake: without chain verification the peer-certificate
            // callback (the WebRTC fingerprint check) does not depend on the signature and,
            // being far cheaper, runs first.
            let verifies_chain =
                self.cfg.client_auth as u8 >= ClientAuthType::VerifyClientCertIfGiven as u8;
            if !verifies_chain
                && let Some(verify_peer_certificate) = &self.cfg.verify_peer_certificate
            {
                verify_peer_certificate(&self.peer_certificates, &[]).map_err(bad_certificate)?;
            }
            self.verify_certificate_signature(scheme, signature, false)?;
            if verifies_chain {
                let verifier = self
                    .cfg
                    .client_cert_verifier
                    .as_ref()
                    .ok_or_else(|| bad_certificate(Error::ErrInvalidCertificate))?;
                let chains = verify_client_cert(&self.peer_certificates, verifier)
                    .map_err(bad_certificate)?;
                if let Some(verify_peer_certificate) = &self.cfg.verify_peer_certificate {
                    verify_peer_certificate(&self.peer_certificates, &chains)
                        .map_err(bad_certificate)?;
                }
            }
            self.state = HandshakeState::ServerWaitFinished;
        }
        self.peer_signature_scheme = Some(scheme);
        self.transcript.add(CERTIFICATE_VERIFY, body);
        Ok(())
    }

    fn on_server_finished(&mut self, body: &[u8]) -> std::result::Result<(), Refusal> {
        // RFC 8446 section 4.4.4: a Finished that does not verify is a decrypt_error.
        let expected = self.finished_verify_data(false)?;
        if !crypto::constant_time_eq(&expected, body) {
            return Err(refuse(alert::DECRYPT_ERROR, Error::ErrVerifyDataMismatch));
        }
        self.transcript.add(FINISHED, body);
        let (local, remote) = self.enter_application_secrets()?;
        self.install_read_epoch(EPOCH_APPLICATION, remote.as_ref())
            .map_err(internal)?;

        // The client's flight, under the handshake keys: its certificate if one was asked
        // for, and its Finished.
        let mut flight = Flight::new(FlightKind::ClientFinal);
        if let Some(schemes) = self.certificate_requested.take() {
            let credentials = self
                .cfg
                .get_certificate(&self.cfg.server_name)
                .ok()
                .and_then(|certificate| {
                    self.cfg
                        .local_signature_schemes
                        .iter()
                        .find(|scheme| {
                            scheme.is_tls13_signature()
                                && schemes.contains(&scheme.scheme_code())
                                && scheme.is_compatible(&certificate.private_key)
                        })
                        .copied()
                        .map(|scheme| (certificate, scheme))
                });
            match credentials {
                Some((certificate, scheme)) => {
                    let chain: Vec<&[u8]> = certificate
                        .certificate
                        .iter()
                        .map(|der| der.as_ref())
                        .collect();
                    self.add_to_flight(
                        &mut flight,
                        EPOCH_HANDSHAKE,
                        CERTIFICATE,
                        super::messages::certificate(&[], &chain),
                    );
                    let input = certificate_verify_input(false, &self.transcript_hash()?);
                    let signature = certificate
                        .private_key
                        .signing_key
                        .sign(scheme.crypto_scheme().map_err(internal)?, &input)
                        .map_err(|err| internal(Error::Crypto(err.to_string())))?;
                    self.add_to_flight(
                        &mut flight,
                        EPOCH_HANDSHAKE,
                        CERTIFICATE_VERIFY,
                        certificate_verify(scheme.scheme_code(), &signature),
                    );
                }
                // RFC 8446 section 4.4.2.3: without a suitable certificate, an empty one.
                None => self.add_to_flight(
                    &mut flight,
                    EPOCH_HANDSHAKE,
                    CERTIFICATE,
                    super::messages::certificate(&[], &[]),
                ),
            }
        }
        let verify_data = self.finished_verify_data(true)?;
        self.add_to_flight(&mut flight, EPOCH_HANDSHAKE, FINISHED, verify_data);
        self.send_flight(flight).map_err(internal)?;

        self.install_write_epoch(EPOCH_APPLICATION, local.as_ref())
            .map_err(internal)?;
        self.set_application_secrets(local, remote);
        debug!("client: handshake complete");
        self.establish().map_err(internal)
    }

    // ------------------------------------------------------------------------------------
    // Server.
    // ------------------------------------------------------------------------------------

    fn on_client_hello(&mut self, body: &[u8]) -> std::result::Result<(), Refusal> {
        let hello = ClientHello::parse(body).map_err(decode_error)?;
        if !hello.offers_dtls13() {
            return Err(refuse(
                alert::PROTOCOL_VERSION,
                Error::ErrUnsupportedProtocolVersion,
            ));
        }
        let cfg = self.cfg.clone();
        let negotiated = negotiate(&cfg, &hello)?;
        let suite = negotiated.suite;

        // The cookie exchange (RFC 9147 section 5.1). A cookie that is not this server's is
        // an illegal_parameter.
        let retry = match hello.extension(EXT_COOKIE) {
            Some(data) => {
                let cookie = parse_cookie(data).map_err(decode_error)?;
                let opened = match self.verified_retry.take() {
                    Some((verified, opened)) if verified == cookie => Some(opened),
                    Some(_) => None,
                    None => match &self.cookie_secret {
                        Some(secret) => RetryCookie::open(
                            self.provider.as_ref(),
                            &[secret.as_ref()],
                            None,
                            cookie,
                        )
                        .map_err(internal)?,
                        None => None,
                    },
                };
                let opened = opened.ok_or_else(|| illegal(Error::ErrCookieMismatch))?;
                Some((cookie.to_vec(), opened))
            }
            None => None,
        };

        match &retry {
            Some((cookie, retry)) => {
                // RFC 8446 section 4.1.2: the second ClientHello keeps the suite, and has
                // a share for the group it was asked for.
                if retry.suite != suite.id as u16
                    || (retry.group != 0
                        && (retry.group != negotiated.group as u16
                            || negotiated.client_share.is_none()))
                    || negotiated.client_share.is_none()
                {
                    return Err(illegal(Error::ErrCookieMismatch));
                }
                self.transcript.set_message_hash(&retry.client_hello_hash);
                self.transcript
                    .add(SERVER_HELLO, &retry.hello_retry_request(cookie));
                self.address_verified = true;
                self.next_send_seq = self.next_send_seq.max(1);
            }
            None => {
                let needs_cookie = cfg.cookie_exchange && !self.address_verified;
                if needs_cookie || negotiated.client_share.is_none() {
                    if self.state != HandshakeState::ServerWaitClientHello || self.next_send_seq > 0
                    {
                        // The answer to a HelloRetryRequest carries its cookie.
                        return Err(illegal(Error::ErrCookieMismatch));
                    }
                    return self.send_hello_retry_request(body, &negotiated);
                }
            }
        }

        self.suite = Some(suite);
        self.transcript.add(CLIENT_HELLO, body);
        self.client_random = hello.random.to_vec();
        self.srtp_profile = negotiated.srtp_profile;
        self.server_name.clone_from(&negotiated.server_name);
        self.offered_extensions
            .clone_from(&negotiated.offered_extensions);

        // The key exchange: this server's share for the group, and the shared secret.
        let Some(client_share) = &negotiated.client_share else {
            return Err(internal(Error::ErrNoSupportedEllipticCurves));
        };
        let mut keypair = negotiated
            .group
            .generate_keypair_with_crypto(self.provider.crypto())
            .map_err(internal)?;
        let server_share = keypair.public_key.clone();
        // RFC 8446 section 4.2.8.2: a share that is not a valid point is an
        // illegal_parameter.
        let shared_secret = SecretVec::new(keypair.complete(client_share).map_err(illegal)?);

        // Connection ids (RFC 9146 section 3, RFC 9147 section 9): only if both sides use
        // the extension.
        let mut connection_id = None;
        if let (Some(client_connection_id), Some(local)) =
            (&negotiated.client_connection_id, cfg.connection_id_offer())
        {
            self.connection_ids_negotiated = true;
            self.remote_connection_id.clone_from(client_connection_id);
            connection_id = Some(local);
        }

        let mut random = [0u8; 32];
        self.provider
            .random()
            .fill(&mut random)
            .map_err(|err| internal(Error::Crypto(err.to_string())))?;
        let server_hello = server_hello(&random, suite.id as u16, |extensions| {
            put_extension(extensions, EXT_KEY_SHARE, |data| {
                put_u16(data, negotiated.group as u16);
                put_vec16(data, |out| out.extend_from_slice(&server_share));
            });
            if let Some(connection_id) = &connection_id {
                put_extension(extensions, EXT_CONNECTION_ID, |data| {
                    put_vec8(data, |out| out.extend_from_slice(connection_id))
                });
            }
        });

        let mut flight = Flight::new(FlightKind::Handshake);
        self.add_to_flight(&mut flight, 0, SERVER_HELLO, server_hello);
        self.enter_handshake_keys(shared_secret.as_ref())?;
        // The client's records carry this server's connection id once they are protected.
        if let Some(connection_id) = connection_id {
            self.local_connection_id = connection_id;
        }

        // EncryptedExtensions: answers to what the client offered (RFC 8446 section 4.3.1).
        let mut encrypted_extensions = vec![];
        put_vec16(&mut encrypted_extensions, |extensions| {
            if self.srtp_profile != SrtpProtectionProfile::Unsupported {
                put_extension(extensions, EXT_USE_SRTP, |data| {
                    put_vec16(data, |out| put_u16(out, self.srtp_profile as u16));
                    data.push(0);
                });
            }
            if !negotiated.server_name.is_empty() {
                // RFC 6066 section 3: an empty server_name says the name was used.
                put_extension(extensions, EXT_SERVER_NAME, |_| {});
            }
        });
        self.add_to_flight(
            &mut flight,
            EPOCH_HANDSHAKE,
            ENCRYPTED_EXTENSIONS,
            encrypted_extensions,
        );

        if cfg.client_auth as u8 > ClientAuthType::NoClientCert as u8 {
            let request = certificate_request(&[], &self.local_scheme_codes());
            self.add_to_flight(&mut flight, EPOCH_HANDSHAKE, CERTIFICATE_REQUEST, request);
            self.client_certificate_expected = true;
        }

        let chain: Vec<&[u8]> = negotiated
            .certificate
            .certificate
            .iter()
            .map(|der| der.as_ref())
            .collect();
        self.add_to_flight(
            &mut flight,
            EPOCH_HANDSHAKE,
            CERTIFICATE,
            super::messages::certificate(&[], &chain),
        );
        let input = certificate_verify_input(true, &self.transcript_hash()?);
        let signature = negotiated
            .certificate
            .private_key
            .signing_key
            .sign(
                negotiated
                    .signature_scheme
                    .crypto_scheme()
                    .map_err(internal)?,
                &input,
            )
            .map_err(|err| internal(Error::Crypto(err.to_string())))?;
        self.add_to_flight(
            &mut flight,
            EPOCH_HANDSHAKE,
            CERTIFICATE_VERIFY,
            certificate_verify(negotiated.signature_scheme.scheme_code(), &signature),
        );
        let verify_data = self.finished_verify_data(false)?;
        self.add_to_flight(&mut flight, EPOCH_HANDSHAKE, FINISHED, verify_data);

        // The application keys follow from the transcript through this Finished. The
        // client's are needed to read what it sends after its own Finished; what arrives
        // under them before that is held (RFC 9147 section 5.8.1).
        let (local, remote) = self.enter_application_secrets()?;
        self.install_read_epoch(EPOCH_APPLICATION, remote.as_ref())
            .map_err(internal)?;
        self.send_flight(flight).map_err(internal)?;
        self.install_write_epoch(EPOCH_APPLICATION, local.as_ref())
            .map_err(internal)?;
        self.set_application_secrets(local, remote);
        self.state = if self.client_certificate_expected {
            HandshakeState::ServerWaitCertificate
        } else {
            HandshakeState::ServerWaitFinished
        };
        Ok(())
    }

    /// Answers a first ClientHello with a HelloRetryRequest, from an association that runs
    /// the cookie exchange itself. Until the cookie comes back nothing is computed for the
    /// client: no key pair, no signature.
    fn send_hello_retry_request(
        &mut self,
        client_hello: &[u8],
        negotiated: &Negotiated,
    ) -> std::result::Result<(), Refusal> {
        let mut secret = vec![0u8; 32];
        self.provider
            .random()
            .fill(&mut secret)
            .map_err(|err| internal(Error::Crypto(err.to_string())))?;
        let secret = SecretVec::new(secret);
        let (hello_retry_request, _) = hello_retry_request(
            self.provider.as_ref(),
            secret.as_ref(),
            None,
            client_hello,
            negotiated,
        )
        .map_err(internal)?;
        self.cookie_secret = Some(secret);
        let mut flight = Flight::new(FlightKind::Handshake);
        flight.push(self.next_send_seq, 0, SERVER_HELLO, hello_retry_request);
        self.next_send_seq = self.next_send_seq.wrapping_add(1);
        self.state = HandshakeState::ServerWaitClientHello;
        // A HelloRetryRequest is not retransmitted: the client's ClientHello is, and draws
        // a new one. The server keeps nothing to time.
        self.send_flight(flight).map_err(internal)?;
        self.flight = None;
        Ok(())
    }

    fn on_client_finished(&mut self, body: &[u8]) -> std::result::Result<(), Refusal> {
        // The Finished follows the server's flight directly when no certificate was sent.
        self.flight_answered();
        let expected = self.finished_verify_data(true)?;
        if !crypto::constant_time_eq(&expected, body) {
            return Err(refuse(alert::DECRYPT_ERROR, Error::ErrVerifyDataMismatch));
        }
        self.transcript.add(FINISHED, body);
        debug!("server: handshake complete");
        self.establish().map_err(internal)?;
        // RFC 9147 section 7.1: the client's last flight is answered by nothing else, so it
        // is acknowledged, at once.
        self.acknowledge_now();
        Ok(())
    }
}

/// The HelloRetryRequest that answers `client_hello` (its body), and the cookie in it:
/// stateless, in that the second ClientHello and the cookie are all a server needs to go on
/// (RFC 9147 section 5.1). `remote` binds the cookie to the client's address.
pub(crate) fn hello_retry_request(
    provider: &dyn crypto::RTCCryptoProvider,
    secret: &[u8],
    remote: Option<SocketAddr>,
    client_hello: &[u8],
    negotiated: &Negotiated,
) -> Result<(Vec<u8>, Vec<u8>)> {
    let mut message = vec![CLIENT_HELLO];
    put_u24(&mut message, client_hello.len());
    message.extend_from_slice(client_hello);
    let client_hello_hash = provider
        .crypto()
        .hash(negotiated.suite.hash(), &message)
        .map_err(|err| Error::Crypto(err.to_string()))?;
    let retry = RetryCookie {
        suite: negotiated.suite.id as u16,
        group: if negotiated.client_share.is_none() {
            negotiated.group as u16
        } else {
            0
        },
        client_hello_hash,
    };
    let cookie = retry.seal(provider, secret, remote)?;
    Ok((retry.hello_retry_request(&cookie), cookie))
}
