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
use super::psk::{
    PSK_DHE_KE, PSK_KE, TicketIssuer, binder, hash_of, new_session_ticket,
    parse_client_pre_shared_key, parse_psk_key_exchange_modes, placeholder_binders,
    pre_shared_key_data,
};
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
use std::time::{Duration, Instant};

/// RFC 8446 section 4.4.2.4: a certificate signed with MD5 is a bad_certificate, whether or
/// not the chain is verified (with fingerprint authentication it is not, and MD5 is still
/// refused).
fn refuse_md5(chain: &[Vec<u8>]) -> std::result::Result<(), Refusal> {
    if chain
        .iter()
        .any(|der| super::certificate_checks::signed_with_md5(der))
    {
        return Err(refuse(
            alert::BAD_CERTIFICATE,
            Error::Other("a certificate signed with MD5".to_owned()),
        ));
    }
    Ok(())
}

/// RFC 8446 section 4.4.2.4: "it is RECOMMENDED that any endpoint receiving any certificate
/// which it would need to validate using any signature algorithm using a SHA-1 hash abort the
/// handshake with a bad_certificate alert". Called where the chain is validated only: under
/// fingerprint authentication (WebRTC, RFC 8122) no certificate signature is validated, and a
/// SHA-1-signed self-signed certificate is taken.
fn refuse_sha1(chain: &[Vec<u8>]) -> std::result::Result<(), Refusal> {
    if chain
        .iter()
        .any(|der| super::certificate_checks::signed_with_sha1(der))
    {
        return Err(refuse(
            alert::BAD_CERTIFICATE,
            Error::Other("a certificate signed with SHA-1 in a chain to validate".to_owned()),
        ));
    }
    Ok(())
}

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
    /// The endpoint's cookie secrets, when it left the cookie exchange to the association.
    pub(crate) retry_keys: Option<RetryKeys>,
    /// The time the ClientHello arrived at, which a ticket it offers is checked against.
    pub(crate) now: Option<Instant>,
}

/// The PSK a server accepts from a ClientHello's pre_shared_key.
struct SelectedPsk {
    index: u16,
    secret: SecretVec,
    without_key_exchange: bool,
    peer_certificates: Vec<Vec<u8>>,
    /// The 0-RTT data the server takes with it, if it takes any.
    early_data_limit: Option<u32>,
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
        if offer.early_data.is_some() {
            conn.early_data_accepted = Some(false);
        }
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
        conn.clock = start.now;
        if start.verified_retry.is_some() {
            // The HelloRetryRequest was message 0 of this server.
            conn.next_send_seq = 1;
        }
        conn.verified_retry = start.verified_retry;
        conn.retry_keys = start.retry_keys;
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
                self.message_epoch = epoch;
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
        let mut schedule = match &self.psk {
            Some(psk) => {
                KeySchedule::with_psk(self.crypto(), suite, DTLS13_LABEL_PREFIX, psk.as_ref())
            }
            None => KeySchedule::new(self.crypto(), suite, DTLS13_LABEL_PREFIX),
        }
        .map_err(internal)?;
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
        // Handed over, not copied: the association keeps them for its key updates (section
        // 7.2), and one copy is all there is to erase (section 7.1).
        let client = schedule.client_application_traffic.take();
        let server = schedule.server_application_traffic.take();
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

    /// Derives `resumption_master_secret` from the transcript through the client's Finished,
    /// which ends the Main Secret; it is kept where tickets are made (a server that issues
    /// them) or taken (a client with a session store).
    fn derive_resumption_secret(&mut self) -> std::result::Result<(), Refusal> {
        let hash = self.transcript_hash()?;
        let provider = self.provider.clone();
        let keeps = if self.is_client {
            self.cfg.session_store.is_some()
        } else {
            self.cfg.ticket_issuer.is_some()
        };
        if let Some(schedule) = self.schedule.as_mut() {
            let secret = schedule
                .take_resumption_master_secret(provider.crypto(), &hash)
                .map_err(internal)?;
            if keeps {
                self.resumption_secret = Some(secret);
            }
        }
        Ok(())
    }

    /// Runs the configured peer-certificate check again on the certificates a PSK carries
    /// from the handshake that made it: a resumed association is the same peer only if the
    /// application still accepts that one.
    fn verify_resumed_peer(&self) -> std::result::Result<(), Refusal> {
        if self.peer_certificates.is_empty() {
            return Ok(());
        }
        if let Some(verify_peer_certificate) = &self.cfg.verify_peer_certificate {
            verify_peer_certificate(&self.peer_certificates, &[])
                .map_err(|error| refuse(alert::BAD_CERTIFICATE, error))?;
        }
        Ok(())
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
        let transcript_hash = self.transcript_hash()?;
        self.verify_signature_over(
            &self.peer_certificates,
            scheme,
            signature,
            from_server,
            &transcript_hash,
        )
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
        let mut selected_psk = None;
        for (extension_type, data) in &hello.extensions {
            match *extension_type {
                EXT_SUPPORTED_VERSIONS => {}
                EXT_KEY_SHARE => key_share = Some(*data),
                EXT_PRE_SHARED_KEY if self.offered_extensions.contains(&EXT_PRE_SHARED_KEY) => {
                    let mut reader = Reader::new(data);
                    selected_psk = Some(reader.u16().map_err(decode_error)?);
                    reader.finish().map_err(decode_error)?;
                }
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
        // RFC 8446 section 4.2.11: a PSK the server selects is one this client offered, of
        // the hash of the suite selected, and comes with a key_share unless this client
        // offered psk_ke; anything else is an illegal_parameter.
        let mut offer = offer;
        let psk = match selected_psk {
            Some(index) => {
                let psk = offer
                    .psks
                    .drain(..)
                    .nth(usize::from(index))
                    .ok_or_else(|| illegal(Error::ErrInvalidExtensionType))?;
                if psk.suite.hash() != suite.hash()
                    || (key_share.is_none() && !self.cfg.psk_without_key_exchange)
                {
                    return Err(illegal(Error::ErrInvalidCipherSuite));
                }
                Some(psk)
            }
            None => None,
        };
        let shared_secret = match key_share {
            Some(key_share) => {
                // RFC 8446 section 4.2.8: the server's share is for a group this client sent
                // a share for; anything else is an illegal_parameter.
                let mut reader = Reader::new(key_share);
                let group = reader.u16().map_err(decode_error)?;
                let key_exchange = reader.vec16().map_err(decode_error)?;
                reader.finish().map_err(decode_error)?;
                let mut keypair = offer
                    .key_shares
                    .into_iter()
                    .find(|keypair| keypair.curve as u16 == group)
                    .ok_or_else(|| illegal(Error::ErrInvalidNamedCurve))?;
                SecretVec::new(keypair.complete(key_exchange).map_err(illegal)?)
            }
            // psk_ke: the (EC)DHE input of the key schedule is zeros (RFC 8446 section 7.1).
            None if psk.is_some() => {
                self.psk_without_key_exchange = true;
                SecretVec::new(vec![0u8; suite.hash_len()])
            }
            // Without a share and without a PSK there is no key exchange this client can do.
            None => {
                return Err(refuse(
                    alert::MISSING_EXTENSION,
                    Error::ErrNoSupportedEllipticCurves,
                ));
            }
        };
        self.psk_index = selected_psk;
        if let Some(psk) = psk {
            // The server is the one that made the ticket (or holds the external PSK): its
            // certificates are those of the handshake the ticket came from.
            self.psk = Some(psk.secret);
            self.resumed = true;
            self.peer_certificates = psk.peer_certificates;
        }

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
            if !self.cfg.local_tls13_groups.contains(&curve)
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

        // RFC 8446 section 4.2.11: the PSKs of another hash than the suite's are not offered
        // again.
        offer.psks.retain(|psk| psk.suite.hash() == suite.hash());
        let psks = offer.psks.clone();

        let first = ClientHello::parse(&self.client_hello).map_err(internal)?;
        let share = new_share.map(|group| (group, offer.key_shares[0].public_key.as_slice()));
        let psk_data =
            (!psks.is_empty()).then(|| pre_shared_key_data(&psks, &placeholder_binders(&psks)));
        let mut second = second_client_hello(&first, share, cookie, psk_data.as_deref());

        self.suite = Some(suite);
        self.hello_retry_seen = true;
        // Section 4.4.1: the first ClientHello becomes a message_hash in the transcript.
        self.transcript
            .replace_with_message_hash(self.provider.crypto(), suite)
            .map_err(internal)?;
        self.transcript.add(SERVER_HELLO, body);
        self.offered_extensions.push(EXT_COOKIE);
        // RFC 8446 section 4.2.10: no early_data in the ClientHello after a
        // HelloRetryRequest; the 0-RTT data sent is not accepted.
        self.offered_extensions
            .retain(|extension| *extension != EXT_EARLY_DATA);
        if psks.is_empty() {
            self.offered_extensions
                .retain(|extension| *extension != EXT_PRE_SHARED_KEY);
        } else {
            // Section 4.2.11.2: the binders of the second ClientHello cover the transcript
            // from the message_hash on.
            super::psk::bind(self.provider.crypto(), &psks, &self.transcript, &mut second)
                .map_err(internal)?;
        }

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
                // RFC 8446 sections 4.2.10 and 4.2.11: the server took the 0-RTT data, which
                // went with the first PSK; a selected_identity other than 0 is an
                // illegal_parameter.
                EXT_EARLY_DATA => {
                    if !data.is_empty() {
                        return Err(decode_error(Error::ErrLengthMismatch));
                    }
                    if self.psk_index != Some(0) {
                        return Err(illegal(Error::ErrInvalidExtensionType));
                    }
                    self.early_data_accepted = Some(true);
                }
                EXT_USE_SRTP => {
                    // RFC 5764 sections 4.1.1 and 4.1.3: exactly one profile, one of those
                    // offered, and no MKI (this client offers none; RFC 8827 section 6.5).
                    let (profiles, mki) = parse_use_srtp(data).map_err(decode_error)?;
                    if !mki.is_empty() {
                        return Err(illegal(Error::ErrInvalidUseSrtpAnswer));
                    }
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
        // As with DTLS 1.2: a client that asked for DTLS-SRTP does not go on without it,
        // unless its configuration says the association may do without.
        if !self.cfg.local_srtp_protection_profiles.is_empty()
            && !self.cfg.use_srtp_optional
            && self.srtp_profile == SrtpProtectionProfile::Unsupported
        {
            return Err(refuse(
                alert::INSUFFICIENT_SECURITY,
                Error::ErrRequestedButNoSrtpExtension,
            ));
        }
        self.transcript.add(ENCRYPTED_EXTENSIONS, body);
        // RFC 8446 section 2.2: a server that authenticates with a PSK sends no certificate,
        // and asks for none (section 4.3.2).
        self.state = if self.resumed {
            HandshakeState::ClientWaitFinished
        } else {
            HandshakeState::ClientWaitCertificateOrRequest
        };
        Ok(())
    }

    fn on_certificate_request(&mut self, body: &[u8]) -> std::result::Result<(), Refusal> {
        let (context, schemes, oid_filters) = parse_certificate_request(body)?;
        // RFC 8446 section 4.3.2: the context is empty in the handshake.
        if !context.is_empty() {
            return Err(illegal(Error::ErrLengthMismatch));
        }
        self.certificate_requested = Some((schemes, oid_filters));
        self.transcript.add(CERTIFICATE_REQUEST, body);
        self.state = HandshakeState::ClientWaitCertificate;
        Ok(())
    }

    fn on_certificate(&mut self, body: &[u8]) -> std::result::Result<(), Refusal> {
        let (context, chain) = parse_certificate(body)?;
        if !context.is_empty() {
            return Err(illegal(Error::ErrLengthMismatch));
        }
        refuse_md5(&chain)?;
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
                refuse_sha1(&self.peer_certificates)?;
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
                refuse_sha1(&self.peer_certificates)?;
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
        if self.resumed {
            self.verify_resumed_peer()?;
        }
        self.transcript.add(FINISHED, body);
        let (local, remote) = self.enter_application_secrets()?;
        self.install_read_epoch(EPOCH_APPLICATION, remote.as_ref())
            .map_err(internal)?;

        // The client's flight, under the handshake keys: its certificate if one was asked
        // for, and its Finished.
        let mut flight = Flight::new(FlightKind::ClientFinal);
        let authenticates = self.certificate_requested.is_some();
        if let Some((schemes, oid_filters)) = self.certificate_requested.take() {
            match self.client_credentials(&schemes, &oid_filters) {
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
        // Both Finished are done: the handshake traffic secrets have given all they give
        // (RFC 8446 section 7.1); the epoch's record keys stay for the retransmissions.
        if let Some(schedule) = self.schedule.as_mut() {
            schedule.forget_handshake_secrets();
        }
        self.derive_resumption_secret()?;
        self.send_flight(flight).map_err(internal)?;

        self.install_write_epoch(EPOCH_APPLICATION, local.as_ref())
            .map_err(internal)?;
        self.set_application_secrets(local, remote);
        if authenticates {
            // The server has yet to accept this client's certificate: the handshake is
            // complete when it has said so (its ACK, or anything under its application
            // keys).
            self.state = HandshakeState::ClientWaitConfirmation;
            return Ok(());
        }
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
                    None => match (&self.retry_keys, &self.cookie_secret) {
                        // The endpoint's cookie, made by this association, another or the
                        // endpoint itself.
                        (Some(keys), _) => {
                            let secrets: Vec<&[u8]> =
                                keys.secrets.iter().map(|secret| secret.as_ref()).collect();
                            RetryCookie::open(
                                self.provider.as_ref(),
                                &secrets,
                                Some(keys.remote),
                                cookie,
                            )
                            .map_err(internal)?
                        }
                        (None, Some(secret)) => RetryCookie::open(
                            self.provider.as_ref(),
                            &[secret.as_ref()],
                            None,
                            cookie,
                        )
                        .map_err(internal)?,
                        (None, None) => None,
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
        // A PSK, if the client offers one this server takes (RFC 8446 section 4.2.11): its
        // binder covers the transcript up to here and the ClientHello.
        let selected = self.select_psk(&hello, body, suite, &negotiated)?;
        self.transcript.add(CLIENT_HELLO, body);
        self.client_random = hello.random.to_vec();
        self.srtp_profile = negotiated.srtp_profile;
        self.server_name.clone_from(&negotiated.server_name);
        self.offered_extensions
            .clone_from(&negotiated.offered_extensions);
        if let Some(modes) = hello.extension(EXT_PSK_KEY_EXCHANGE_MODES) {
            self.client_psk_modes = parse_psk_key_exchange_modes(modes)
                .map_err(decode_error)?
                .to_vec();
        }
        let selected_index = selected.as_ref().map(|selected| selected.index);
        // RFC 8446 section 4.2.10: 0-RTT data taken where the PSK allows it, keyed from
        // client_early_traffic_secret over the ClientHello.
        let mut early_secret = None;
        if let Some(limit) = selected
            .as_ref()
            .and_then(|selected| selected.early_data_limit)
        {
            let hash = self.transcript_hash()?;
            let secret = selected
                .as_ref()
                .map(|selected| selected.secret.clone())
                .ok_or_else(|| internal(Error::ErrCipherSuiteUnset))?;
            let schedule =
                KeySchedule::with_psk(self.crypto(), suite, DTLS13_LABEL_PREFIX, secret.as_ref())
                    .map_err(internal)?;
            early_secret = Some(
                schedule
                    .client_early_traffic_secret(self.crypto(), &hash)
                    .map_err(internal)?,
            );
            self.early_data_limit = limit as usize;
        }
        if hello.extension(EXT_EARLY_DATA).is_some() {
            self.early_data_accepted = Some(early_secret.is_some());
        }
        if let Some(selected) = selected {
            self.psk = Some(selected.secret);
            self.psk_without_key_exchange = selected.without_key_exchange;
            self.resumed = true;
            self.peer_certificates = selected.peer_certificates;
        }

        // The key exchange: this server's share for the group, and the shared secret; with
        // psk_ke, none, and zeros in its place (RFC 8446 section 7.1).
        let (server_share, shared_secret) = if self.psk_without_key_exchange {
            (None, SecretVec::new(vec![0u8; suite.hash_len()]))
        } else {
            let Some(client_share) = &negotiated.client_share else {
                return Err(internal(Error::ErrNoSupportedEllipticCurves));
            };
            // RFC 8446 section 4.2.8.2: a share that is not a valid point (or, for the
            // hybrid group, not a key of the right form) is an illegal_parameter.
            let (share, secret) = negotiated
                .group
                .respond_with_crypto(self.provider.crypto(), client_share)
                .map_err(illegal)?;
            (Some(share), secret)
        };

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
            if let Some(server_share) = &server_share {
                put_extension(extensions, EXT_KEY_SHARE, |data| {
                    put_u16(data, negotiated.group as u16);
                    put_vec16(data, |out| out.extend_from_slice(server_share));
                });
            }
            if let Some(index) = selected_index {
                put_extension(extensions, EXT_PRE_SHARED_KEY, |data| put_u16(data, index));
            }
            if let Some(connection_id) = &connection_id {
                put_extension(extensions, EXT_CONNECTION_ID, |data| {
                    put_vec8(data, |out| out.extend_from_slice(connection_id))
                });
            }
        });

        let mut flight = Flight::new(FlightKind::Handshake);
        self.add_to_flight(&mut flight, 0, SERVER_HELLO, server_hello);
        self.enter_handshake_keys(shared_secret.as_ref())?;
        if let Some(secret) = &early_secret {
            self.install_read_epoch(EPOCH_EARLY, secret.as_ref())
                .map_err(internal)?;
        }
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
            if early_secret.is_some() {
                put_extension(extensions, EXT_EARLY_DATA, |_| {});
            }
        });
        self.add_to_flight(
            &mut flight,
            EPOCH_HANDSHAKE,
            ENCRYPTED_EXTENSIONS,
            encrypted_extensions,
        );

        // RFC 8446 section 2.2: with a PSK the server sends no certificate, and section
        // 4.3.2 asks for none.
        if !self.resumed {
            self.add_certificate_messages(&mut flight, &negotiated)?;
        }
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

    /// The CertificateRequest (if the configuration authenticates clients), Certificate and
    /// CertificateVerify of a server's flight.
    fn add_certificate_messages(
        &mut self,
        flight: &mut Flight,
        negotiated: &Negotiated,
    ) -> std::result::Result<(), Refusal> {
        if self.cfg.client_auth as u8 > ClientAuthType::NoClientCert as u8 {
            let request = certificate_request(&[], &self.local_scheme_codes());
            self.add_to_flight(flight, EPOCH_HANDSHAKE, CERTIFICATE_REQUEST, request);
            self.client_certificate_expected = true;
        }

        let chain: Vec<&[u8]> = negotiated
            .certificate
            .certificate
            .iter()
            .map(|der| der.as_ref())
            .collect();
        self.add_to_flight(
            flight,
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
            flight,
            EPOCH_HANDSHAKE,
            CERTIFICATE_VERIFY,
            certificate_verify(negotiated.signature_scheme.scheme_code(), &signature),
        );
        Ok(())
    }

    /// The PSK of a ClientHello this server accepts, if any (RFC 8446 section 4.2.11): the
    /// first identity that is an external PSK of this server or one of its tickets, still
    /// valid, unused, for the hash of the suite negotiated and the same server name, in a key
    /// exchange mode both sides take. Its binder must verify, or the handshake ends with a
    /// decrypt_error. Any other offer is ignored: the handshake is a full one.
    fn select_psk(
        &mut self,
        hello: &ClientHello<'_>,
        body: &[u8],
        suite: Suite13,
        negotiated: &Negotiated,
    ) -> std::result::Result<Option<SelectedPsk>, Refusal> {
        let Some(data) = hello.extension(EXT_PRE_SHARED_KEY) else {
            return Ok(None);
        };
        // `negotiate` has seen that the extension is the last and comes with the modes.
        let modes = hello
            .extension(EXT_PSK_KEY_EXCHANGE_MODES)
            .ok_or_else(|| refuse(alert::MISSING_EXTENSION, Error::ErrInvalidExtensionType))?;
        let modes = parse_psk_key_exchange_modes(modes).map_err(decode_error)?;
        let offered = parse_client_pre_shared_key(data).map_err(decode_error)?;
        // psk_dhe_ke where the client sent a share for the group; psk_ke only if this server
        // allows it and the client offers it (RFC 8446 section 4.2.9).
        let without_key_exchange =
            if modes.contains(&PSK_DHE_KE) && negotiated.client_share.is_some() {
                false
            } else if modes.contains(&PSK_KE) && self.cfg.psk_without_key_exchange {
                true
            } else {
                return Ok(None);
            };
        let cfg = self.cfg.clone();
        let provider = self.provider.clone();
        let requires_certificate = matches!(
            cfg.client_auth,
            ClientAuthType::RequireAnyClientCert | ClientAuthType::RequireAndVerifyClientCert
        );
        let offers_early_data = hello.extension(EXT_EARLY_DATA).is_some();
        // No HelloRetryRequest came before this ClientHello (its transcript starts with it).
        let first_client_hello = self.transcript.is_empty();
        for (index, (identity, obfuscated_age)) in offered.identities.iter().enumerate() {
            let mut early_data_limit = None;
            // An external PSK of this identity, or a ticket of this server (RFC 8446 section
            // 4.6.1: of the same hash, within its lifetime; the name it was made for).
            let mut claim = None;
            let candidate = if let Some(external) = cfg
                .external_psks
                .iter()
                .find(|external| external.identity == *identity)
            {
                (hash_of(external.hash) == suite.hash())
                    .then(|| (external.secret.clone(), true, vec![]))
            } else if let (Some(issuer), Some(now)) = (&cfg.ticket_issuer, self.clock) {
                issuer.open(provider.as_ref(), identity).and_then(|ticket| {
                    let now_ms = issuer.ms(now);
                    let expires = ticket
                        .issued_ms
                        .saturating_add(u64::from(ticket.lifetime) * 1000);
                    let usable = Suite13::for_id(ticket.suite)
                        .is_some_and(|issued| issued.hash() == suite.hash())
                        && ticket.issued_ms <= now_ms
                        && now_ms < expires
                        && ticket.server_name == negotiated.server_name
                        && (!requires_certificate || !ticket.peer_certificates.is_empty());
                    claim = Some((ticket.id, now_ms, expires));
                    // RFC 8446 sections 4.2.10 and 8.3: 0-RTT with the first PSK, a ticket
                    // that allows it, of the same suite, in a first ClientHello, whose age as
                    // the client counts it agrees with this server's within the window.
                    let client_age = u64::from(obfuscated_age.wrapping_sub(ticket.age_add));
                    let server_age = now_ms.saturating_sub(ticket.issued_ms);
                    if offers_early_data
                        && index == 0
                        && first_client_hello
                        && ticket.max_early_data > 0
                        && cfg.max_early_data > 0
                        && ticket.suite == suite.id
                        && client_age.abs_diff(server_age) <= super::psk::EARLY_DATA_AGE_WINDOW_MS
                    {
                        early_data_limit = Some(ticket.max_early_data.min(cfg.max_early_data));
                    }
                    usable.then_some((ticket.secret, false, ticket.peer_certificates))
                })
            } else {
                None
            };
            let Some((secret, external, peer_certificates)) = candidate else {
                continue;
            };
            // RFC 8446 section 4.2.11: the binder of the PSK selected is verified before it
            // is accepted, and one that does not verify ends the handshake.
            let expected = binder(
                provider.crypto(),
                suite,
                secret.as_ref(),
                external,
                &self.transcript,
                body,
                offered.binders_len,
            )
            .map_err(internal)?;
            if !crypto::constant_time_eq(&expected, offered.binders[index]) {
                return Err(refuse(alert::DECRYPT_ERROR, Error::ErrVerifyDataMismatch));
            }
            // A ticket is accepted once (RFC 8446 section 8.1): one seen before gets a full
            // handshake.
            if let (Some(issuer), Some((id, now_ms, expires))) = (&cfg.ticket_issuer, claim)
                && !issuer.claim(id, now_ms, expires)
            {
                debug!("server: a ticket offered again; full handshake");
                return Ok(None);
            }
            let selected = SelectedPsk {
                index: index as u16,
                secret,
                without_key_exchange,
                peer_certificates,
                early_data_limit,
            };
            // The client is the peer of the handshake the ticket came from: the
            // application's check of it runs again.
            let earlier = std::mem::replace(
                &mut self.peer_certificates,
                selected.peer_certificates.clone(),
            );
            let checked = self.verify_resumed_peer();
            self.peer_certificates = earlier;
            checked?;
            return Ok(Some(selected));
        }
        Ok(None)
    }

    /// Sends the configured number of NewSessionTicket messages (RFC 8446 section 4.6.1),
    /// after the client's Finished: to a client that offered a PSK key exchange mode this
    /// server takes (section 4.2.9), each with its own nonce and ticket_age_add.
    fn send_session_tickets(&mut self) -> std::result::Result<(), Refusal> {
        let cfg = self.cfg.clone();
        let (Some(issuer), Some(now), Some(secret)) = (
            cfg.ticket_issuer.as_ref(),
            self.clock,
            self.resumption_secret.take(),
        ) else {
            return Ok(());
        };
        let takes_a_mode = self.client_psk_modes.contains(&PSK_DHE_KE)
            || (cfg.psk_without_key_exchange && self.client_psk_modes.contains(&PSK_KE));
        if !takes_a_mode || !TicketIssuer::carries(&self.peer_certificates) {
            return Ok(());
        }
        let suite = self.suite().map_err(internal)?;
        let provider = self.provider.clone();
        for _ in 0..issuer.count {
            let nonce = [self.tickets_issued];
            self.tickets_issued = self.tickets_issued.wrapping_add(1);
            let psk = self
                .schedule
                .as_ref()
                .ok_or_else(|| internal(Error::ErrCipherSuiteUnset))?
                .resumption_psk(provider.crypto(), secret.as_ref(), &nonce)
                .map_err(internal)?;
            let mut age_add = [0u8; 4];
            provider
                .random()
                .fill(&mut age_add)
                .map_err(|err| internal(Error::Crypto(err.to_string())))?;
            let age_add = u32::from_be_bytes(age_add);
            let ticket = issuer
                .seal(
                    provider.as_ref(),
                    suite.id,
                    now,
                    age_add,
                    psk.as_ref(),
                    &self.server_name,
                    &self.peer_certificates,
                    cfg.max_early_data,
                )
                .map_err(internal)?;
            let body = new_session_ticket(
                issuer.lifetime.as_secs() as u32,
                age_add,
                &nonce,
                &ticket,
                (cfg.max_early_data > 0).then_some(cfg.max_early_data),
            );
            self.send_post_handshake(FlightKind::NewSessionTicket, NEW_SESSION_TICKET, body)
                .map_err(internal)?;
        }
        Ok(())
    }

    /// A client's NewSessionTicket (RFC 8446 section 4.6.1): with a session store, the
    /// ticket is kept with its PSK, `HKDF-Expand-Label(resumption_master_secret,
    /// "resumption", ticket_nonce)`, for the next handshake with this server name. A lifetime
    /// of zero says to keep it not at all; one beyond seven days is cut to seven days.
    pub(crate) fn on_new_session_ticket(
        &mut self,
        body: &[u8],
    ) -> std::result::Result<(), Refusal> {
        let ticket = super::psk::parse_new_session_ticket(body).map_err(decode_error)?;
        let cfg = self.cfg.clone();
        let (Some(store), Some(secret), Some(now)) = (
            cfg.session_store.as_ref(),
            self.resumption_secret.as_ref(),
            self.clock,
        ) else {
            return Ok(());
        };
        if ticket.lifetime == 0 {
            return Ok(());
        }
        let suite = self.suite().map_err(internal)?;
        let psk = self
            .schedule
            .as_ref()
            .ok_or_else(|| internal(Error::ErrCipherSuiteUnset))?
            .resumption_psk(self.provider.crypto(), secret.as_ref(), ticket.nonce)
            .map_err(internal)?;
        store.put(
            &cfg.server_name,
            crate::session::Tls13Session {
                ticket: ticket.ticket.to_vec(),
                secret: psk,
                suite: suite.id,
                received: now,
                lifetime: Duration::from_secs(u64::from(ticket.lifetime))
                    .min(crate::session::MAX_TICKET_LIFETIME),
                age_add: ticket.age_add,
                max_early_data: ticket.max_early_data.unwrap_or(0),
                peer_certificates: self.peer_certificates.clone(),
            },
        );
        Ok(())
    }

    /// Answers a first ClientHello with a HelloRetryRequest, from an association that runs
    /// the cookie exchange itself. Until the cookie comes back nothing is computed for the
    /// client: no key pair, no signature.
    ///
    /// The cookie is made with the endpoint's secret and bound to the client's address when
    /// the endpoint handed them over (`retry_keys`), else with a secret of this association.
    /// The HelloRetryRequest is kept, and sent again each time the ClientHello is repeated
    /// (RFC 9147 sections 5.1 and 5.8.1): if it was lost, the client's retransmission is all
    /// that can bring it. It is never sent on a timer.
    fn send_hello_retry_request(
        &mut self,
        client_hello: &[u8],
        negotiated: &Negotiated,
    ) -> std::result::Result<(), Refusal> {
        let hello_retry_request = match &self.retry_keys {
            Some(keys) => {
                let secret = keys
                    .secrets
                    .first()
                    .ok_or_else(|| internal(Error::Crypto("no cookie secret".to_owned())))?;
                hello_retry_request(
                    self.provider.as_ref(),
                    secret.as_ref(),
                    Some(keys.remote),
                    client_hello,
                    negotiated,
                )
                .map_err(internal)?
                .0
            }
            None => {
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
                hello_retry_request
            }
        };
        let mut flight = Flight::new(FlightKind::HelloRetryRequest);
        flight.push(self.next_send_seq, 0, SERVER_HELLO, hello_retry_request);
        self.next_send_seq = self.next_send_seq.wrapping_add(1);
        self.state = HandshakeState::ServerWaitClientHello;
        self.send_flight(flight).map_err(internal)?;
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
        // RFC 8446 section 7.1, as on the client.
        if let Some(schedule) = self.schedule.as_mut() {
            schedule.forget_handshake_secrets();
        }
        self.derive_resumption_secret()?;
        debug!("server: handshake complete");
        self.establish().map_err(internal)?;
        // RFC 9147 section 7.1: the client's last flight is answered by nothing else, so it
        // is acknowledged, at once.
        self.acknowledge_now();
        self.send_session_tickets()
    }
}

impl Conn13 {
    // ------------------------------------------------------------------------------------
    // Post-handshake authentication (RFC 8446 sections 4.2.6 and 4.6.2).
    // ------------------------------------------------------------------------------------

    /// The certificate a client answers a CertificateRequest listing `schemes` and
    /// `oid_filters` with, and the scheme it signs with: one TLS 1.3 signs with, that the
    /// request lists and its key can make (RFC 8446 section 4.4.2.3). `None` when it has
    /// none: no certificate, or one whose chain is signed with algorithms the request does
    /// not list (a self-signed certificate excepted) or that does not meet the filters.
    fn client_credentials(
        &self,
        schemes: &[u16],
        oid_filters: &[super::certificate_checks::OidFilter],
    ) -> Option<(crate::crypto::Certificate, SignatureHashAlgorithm)> {
        use super::certificate_checks::{client_chain_acceptable, matches_oid_filters};

        let certificate = self.cfg.get_certificate(&self.cfg.server_name).ok()?;
        let pairs: Vec<SignatureHashAlgorithm> = schemes
            .iter()
            .map(|code| SignatureHashAlgorithm::from_scheme_code(*code))
            .collect();
        if !client_chain_acceptable(&certificate.certificate, &pairs)
            || !certificate
                .certificate
                .first()
                .is_some_and(|leaf| matches_oid_filters(leaf.as_ref(), oid_filters))
        {
            return None;
        }
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
    }

    /// Whether this client would answer a CertificateRequest of `schemes` and `oid_filters`
    /// with a certificate.
    #[cfg(test)]
    pub(crate) fn client_credentials_for_test(
        &self,
        schemes: &[u16],
        oid_filters: &[super::certificate_checks::OidFilter],
    ) -> bool {
        self.client_credentials(schemes, oid_filters).is_some()
    }

    /// Whether the client sent post_handshake_auth (RFC 8446 section 4.2.6).
    pub(crate) fn post_handshake_auth_offered(&self) -> bool {
        self.offered_extensions.contains(&EXT_POST_HANDSHAKE_AUTH)
    }

    /// Server: asks the client to authenticate, after the handshake (RFC 8446 section 4.6.2):
    /// a CertificateRequest with a fresh, non-empty certificate_request_context, under the
    /// application keys, acknowledged like any post-handshake message. The client's answer
    /// is checked as its Certificate and CertificateVerify would be in the handshake, and its
    /// Finished with the key of its current application traffic secret.
    ///
    /// # Errors
    ///
    /// For a client, before the handshake is complete, when the client did not send
    /// post_handshake_auth (RFC 8446 section 4.2.6 forbids the request then), and with
    /// [`MAX_PENDING_CERTIFICATE_REQUESTS`] unanswered.
    pub(crate) fn request_client_certificate(&mut self) -> Result<()> {
        if !self.established || self.closed {
            return Err(Error::ErrConnClosed);
        }
        if self.is_client || !self.post_handshake_auth_offered() {
            return Err(Error::Other(
                "the client did not offer post-handshake authentication".to_owned(),
            ));
        }
        if self.pending_certificate_requests.len() >= MAX_PENDING_CERTIFICATE_REQUESTS {
            return Err(Error::Other(
                "too many unanswered CertificateRequests".to_owned(),
            ));
        }
        let mut context = vec![0u8; 16];
        self.provider
            .random()
            .fill(&mut context)
            .map_err(|err| Error::Crypto(err.to_string()))?;
        let body = certificate_request(&context, &self.local_scheme_codes());
        // RFC 8446 section 4.4: the context of the answer is the handshake through the
        // client's Finished, and this CertificateRequest.
        let mut transcript = self.transcript.clone();
        transcript.add(CERTIFICATE_REQUEST, &body);
        self.pending_certificate_requests
            .push((context, transcript));
        self.send_post_handshake(FlightKind::CertificateRequest, CERTIFICATE_REQUEST, body)
    }

    /// Client: answers a post-handshake CertificateRequest at once (RFC 8446 section 4.6.2):
    /// Certificate, CertificateVerify and Finished, one flight, or an empty Certificate and
    /// Finished when this client has no certificate the request allows.
    pub(crate) fn on_post_handshake_certificate_request(
        &mut self,
        body: &[u8],
    ) -> std::result::Result<(), Refusal> {
        let (context, schemes, oid_filters) = parse_certificate_request(body)?;
        // RFC 8446 section 4.3.2: after the handshake the context is not empty.
        if context.is_empty() {
            return Err(illegal(Error::ErrLengthMismatch));
        }
        let suite = self.suite().map_err(internal)?;
        let crypto = self.provider.clone();
        let crypto = crypto.crypto();
        let mut transcript = self.transcript.clone();
        transcript.add(CERTIFICATE_REQUEST, body);
        let mut messages = vec![];
        match self.client_credentials(&schemes, &oid_filters) {
            Some((certificate, scheme)) => {
                let chain: Vec<&[u8]> = certificate
                    .certificate
                    .iter()
                    .map(|der| der.as_ref())
                    .collect();
                let certificate_message = super::messages::certificate(context, &chain);
                transcript.add(CERTIFICATE, &certificate_message);
                messages.push((CERTIFICATE, certificate_message));
                let input = certificate_verify_input(
                    false,
                    &transcript.hash(crypto, suite).map_err(internal)?,
                );
                let signature = certificate
                    .private_key
                    .signing_key
                    .sign(scheme.crypto_scheme().map_err(internal)?, &input)
                    .map_err(|err| internal(Error::Crypto(err.to_string())))?;
                let verify = certificate_verify(scheme.scheme_code(), &signature);
                transcript.add(CERTIFICATE_VERIFY, &verify);
                messages.push((CERTIFICATE_VERIFY, verify));
            }
            None => {
                // RFC 8446 section 4.6.2: one that declines sends a Certificate with no
                // certificates, and its Finished.
                let certificate_message = super::messages::certificate(context, &[]);
                transcript.add(CERTIFICATE, &certificate_message);
                messages.push((CERTIFICATE, certificate_message));
            }
        }
        // RFC 8446 section 4.4: the Finished of a post-handshake answer is keyed from
        // client_application_traffic_secret_N: the secret this side sends under, which is
        // the one the answer is protected with (a KeyUpdate of this side's takes effect only
        // when it is acknowledged, RFC 9147 section 8), and which the server reads it with.
        let base_key = self
            .local_application_secret()
            .ok_or_else(|| internal(Error::ErrCipherSuiteUnset))?;
        let schedule = self
            .schedule
            .as_ref()
            .ok_or_else(|| internal(Error::ErrCipherSuiteUnset))?;
        let finished = schedule
            .finished_verify_data(
                crypto,
                base_key.as_ref(),
                &transcript.hash(crypto, suite).map_err(internal)?,
            )
            .map_err(internal)?;
        messages.push((FINISHED, finished));
        self.send_post_handshake_messages(FlightKind::Authentication, messages)
            .map_err(internal)
    }

    /// Server: one message of a client's answer to a post-handshake CertificateRequest (RFC
    /// 8446 section 4.6.2). They come in order and together: a Certificate with the context of
    /// a request outstanding, its CertificateVerify when it holds a certificate, and the
    /// Finished. Anything else in between is an unexpected_message.
    pub(crate) fn on_post_handshake_authentication(
        &mut self,
        handshake_type: u8,
        body: &[u8],
    ) -> std::result::Result<(), Refusal> {
        let suite = self.suite().map_err(internal)?;
        let provider = self.provider.clone();
        let crypto = provider.crypto();
        let bad_certificate = |error| refuse(alert::BAD_CERTIFICATE, error);
        match (handshake_type, self.client_authentication.take()) {
            (CERTIFICATE, None) => {
                let (context, chain) = parse_certificate(body)?;
                refuse_md5(&chain)?;
                let Some(index) = self
                    .pending_certificate_requests
                    .iter()
                    .position(|(pending, _)| pending.as_slice() == context)
                else {
                    // A context of no request this server made.
                    return Err(illegal(Error::ErrLengthMismatch));
                };
                let (_, mut transcript) = self.pending_certificate_requests.remove(index);
                transcript.add(CERTIFICATE, body);
                if chain.is_empty()
                    && matches!(
                        self.cfg.client_auth,
                        ClientAuthType::RequireAnyClientCert
                            | ClientAuthType::RequireAndVerifyClientCert
                    )
                {
                    return Err(refuse(
                        alert::CERTIFICATE_REQUIRED,
                        Error::ErrClientCertificateRequired,
                    ));
                }
                self.client_authentication = Some(ClientAuthentication {
                    verified: chain.is_empty(),
                    chain,
                    transcript,
                });
                Ok(())
            }
            (CERTIFICATE_VERIFY, Some(mut answer)) if !answer.verified => {
                let (code, signature) = parse_certificate_verify(body).map_err(decode_error)?;
                let scheme = SignatureHashAlgorithm::from_scheme_code(code);
                if !scheme.is_tls13_signature()
                    || !self.cfg.local_signature_schemes.contains(&scheme)
                {
                    return Err(illegal(Error::ErrNoAvailableSignatureSchemes));
                }
                let hash = answer.transcript.hash(crypto, suite).map_err(internal)?;
                self.verify_signature_over(&answer.chain, scheme, signature, false, &hash)?;
                // As in the handshake: the CA chain if the configuration verifies one, and
                // the application's check.
                let mut chains = vec![];
                if self.cfg.client_auth as u8 >= ClientAuthType::VerifyClientCertIfGiven as u8 {
                    let verifier = self
                        .cfg
                        .client_cert_verifier
                        .as_ref()
                        .ok_or_else(|| bad_certificate(Error::ErrInvalidCertificate))?;
                    chains =
                        verify_client_cert(&answer.chain, verifier).map_err(bad_certificate)?;
                }
                if let Some(verify_peer_certificate) = &self.cfg.verify_peer_certificate {
                    verify_peer_certificate(&answer.chain, &chains).map_err(bad_certificate)?;
                }
                answer.transcript.add(CERTIFICATE_VERIFY, body);
                answer.verified = true;
                self.client_authentication = Some(answer);
                Ok(())
            }
            (FINISHED, Some(answer)) if answer.verified => {
                // RFC 8446 section 4.4: keyed from client_application_traffic_secret_N, the
                // client's current one, which is the one its Finished is protected under. In
                // DTLS the two directions move to new keys apart (RFC 9147 section 8): a
                // client that sent a KeyUpdate keeps its old keys until it is acknowledged,
                // while this side reads its next ones from the KeyUpdate on. So the base
                // key is the secret of the epoch the Finished arrived in, which is the one
                // the client keyed it from, not this side's newest secret of the client's.
                let base_key = self
                    .read_epoch_secret(self.message_epoch)
                    .or(self.remote_application_secret())
                    .ok_or_else(|| internal(Error::ErrCipherSuiteUnset))?;
                let schedule = self
                    .schedule
                    .as_ref()
                    .ok_or_else(|| internal(Error::ErrCipherSuiteUnset))?;
                let expected = schedule
                    .finished_verify_data(
                        crypto,
                        base_key.as_ref(),
                        &answer.transcript.hash(crypto, suite).map_err(internal)?,
                    )
                    .map_err(internal)?;
                if !crypto::constant_time_eq(&expected, body) {
                    return Err(refuse(alert::DECRYPT_ERROR, Error::ErrVerifyDataMismatch));
                }
                debug!(
                    "server: post-handshake authentication with {} certificates",
                    answer.chain.len()
                );
                self.post_handshake_peer_certificates = Some(answer.chain);
                self.post_handshake_authentications += 1;
                Ok(())
            }
            _ => Err(unexpected()),
        }
    }

    /// Checks a CertificateVerify signature by the end-entity certificate of `chain` over
    /// the transcript hash given (RFC 8446 section 4.4.3).
    fn verify_signature_over(
        &self,
        chain: &[Vec<u8>],
        scheme: SignatureHashAlgorithm,
        signature: &[u8],
        from_server: bool,
        transcript_hash: &[u8],
    ) -> std::result::Result<(), Refusal> {
        let bad_certificate = |error| refuse(alert::BAD_CERTIFICATE, error);
        let end_entity = chain
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
        let input = certificate_verify_input(from_server, transcript_hash);
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
}

/// A client's answer to a post-handshake CertificateRequest, while it comes in.
pub(crate) struct ClientAuthentication {
    chain: Vec<Vec<u8>>,
    /// The transcript of the answer so far: the handshake, the request, and what came.
    transcript: super::key_schedule::Transcript,
    /// Its CertificateVerify has been checked, or it has no certificate to check one for.
    verified: bool,
}

/// How many post-handshake CertificateRequests a server leaves unanswered at once.
pub(crate) const MAX_PENDING_CERTIFICATE_REQUESTS: usize = 4;

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
