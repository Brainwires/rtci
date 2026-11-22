use super::cipher_suite::*;
use super::client_certificate_type::ClientCertificateType;
use super::conn::*;
use super::curve::named_curve::*;
use super::extension::extension_use_srtp::SrtpProtectionProfile;
use super::handshake::handshake_random::*;
use super::prf::*;
use super::signature_hash_algorithm::SignatureHashAlgorithm;
use crypto::RTCCryptoProvider;
use crypto::SecretVec;
use rkyv::{Archive, Deserialize, Serialize};
use shared::error::*;
use std::io::{BufWriter, Cursor};
use std::sync::Arc;

// State holds the dtls connection state and implements both encoding.BinaryMarshaler and encoding.BinaryUnmarshaler
/// The negotiated connection state: keys, sequence numbers, peer identity and the active
/// cipher suite.
pub struct State {
    pub(crate) crypto_provider: Arc<dyn RTCCryptoProvider>,
    pub(crate) local_epoch: u16,
    pub(crate) remote_epoch: u16,
    pub(crate) local_sequence_number: Vec<u64>, // uint48
    pub(crate) local_random: HandshakeRandom,
    pub(crate) remote_random: HandshakeRandom,
    pub(crate) master_secret: Vec<u8>,
    pub(crate) cipher_suite: Option<Box<dyn CipherSuite>>, // nil if a cipher_suite hasn't been chosen

    pub(crate) srtp_protection_profile: SrtpProtectionProfile, // Negotiated srtp_protection_profile
    /// The peer's certificate chain, DER-encoded.
    ///
    /// WebRTC checks its fingerprint against the one signalled in SDP.
    pub peer_certificates: Vec<Vec<u8>>,
    /// The PSK identity hint, for pre-shared-key handshakes.
    pub identity_hint: Vec<u8>,

    pub(crate) is_client: bool,

    pub(crate) pre_master_secret: Vec<u8>,
    pub(crate) extended_master_secret: bool,

    pub(crate) named_curve: NamedCurve,
    pub(crate) local_keypair: Option<NamedCurveKeypair>,
    pub(crate) cookie: Vec<u8>,
    pub(crate) handshake_send_sequence: isize,
    pub(crate) handshake_recv_sequence: isize,
    pub(crate) server_name: String,
    pub(crate) remote_requested_certificate: bool, // Did we get a CertificateRequest
    pub(crate) local_certificates_verify: Vec<u8>, // cache CertificateVerify
    pub(crate) local_verify_data: Vec<u8>,         // cached VerifyData
    pub(crate) local_key_signature: Vec<u8>,       // cached keySignature
    pub(crate) peer_certificates_verified: bool,
    /// The transcript and CertificateVerify signature whose check last passed, so that
    /// re-parsing the same flight does not verify the same signature again.
    pub(crate) verified_certificate_verify: Option<Vec<u8>>,
    /// Both ends signalled secure renegotiation in this handshake (RFC 5746 3.4, 3.6): the
    /// ClientHello carried an empty renegotiation_info or the signalling suite, and, for a
    /// client, the ServerHello answered with an empty renegotiation_info.
    pub(crate) secure_renegotiation: bool,
    /// The hash and signature pairs the peer accepts signatures under. For a server: the
    /// ClientHello's signature_algorithms, or the RFC 5246 7.4.1.4.1 defaults when it sent
    /// none. For a client: the CertificateRequest's supported_signature_algorithms.
    pub(crate) remote_signature_schemes: Vec<SignatureHashAlgorithm>,
    /// Client: the certificate types the CertificateRequest listed (RFC 5246 7.4.4).
    pub(crate) remote_certificate_types: Vec<ClientCertificateType>,
    /// Server: the ClientHello carried ec_point_formats, so the ServerHello may (RFC 8422 5.2).
    pub(crate) remote_offered_point_formats: bool,
    /// Server: the pair chosen for the ServerKeyExchange signature, one the client listed and
    /// the certificate's key can produce (RFC 5246 7.4.3).
    pub(crate) local_signature_scheme: Option<SignatureHashAlgorithm>,
    /// The association failed and its secrets have been overwritten (RFC 5246 7.2.2).
    pub(crate) secrets_forgotten: bool,
    //pub(crate) replay_detector: Vec<Box<dyn ReplayDetector>>,
}

#[derive(Archive, Serialize, Deserialize, PartialEq, Debug)]
struct SerializedState {
    local_epoch: u16,
    remote_epoch: u16,
    local_random: [u8; HANDSHAKE_RANDOM_LENGTH],
    remote_random: [u8; HANDSHAKE_RANDOM_LENGTH],
    cipher_suite_id: u16,
    master_secret: Vec<u8>,
    sequence_number: u64,
    srtp_protection_profile: u16,
    peer_certificates: Vec<Vec<u8>>,
    identity_hint: Vec<u8>,
    is_client: bool,
    extended_master_secret: bool,
}

impl State {
    /// Creates the initial handshake state for a connection.
    ///
    /// The crypto provider comes from the caller — `rtc-dtls` never resolves a default. This
    /// replaces the former `Default` impl, which resolved one implicitly only for `DTLSConn::new`
    /// to overwrite it a few lines later.
    pub fn new(crypto_provider: Arc<dyn RTCCryptoProvider>, is_client: bool) -> Self {
        State {
            crypto_provider,
            local_epoch: 0,
            remote_epoch: 0,
            local_sequence_number: vec![],
            local_random: HandshakeRandom::default(),
            remote_random: HandshakeRandom::default(),
            master_secret: vec![],
            cipher_suite: None,

            srtp_protection_profile: SrtpProtectionProfile::Unsupported,
            peer_certificates: vec![],
            identity_hint: vec![],

            is_client,

            pre_master_secret: vec![],
            extended_master_secret: false,

            named_curve: NamedCurve::Unsupported,
            local_keypair: None,
            cookie: vec![],
            handshake_send_sequence: 0,
            handshake_recv_sequence: 0,
            server_name: "".to_string(),
            remote_requested_certificate: false,
            local_certificates_verify: vec![],
            local_verify_data: vec![],
            local_key_signature: vec![],
            peer_certificates_verified: false,
            verified_certificate_verify: None,
            secure_renegotiation: false,
            remote_signature_schemes: vec![],
            remote_certificate_types: vec![],
            remote_offered_point_formats: false,
            local_signature_scheme: None,
            secrets_forgotten: false,
        }
    }
}

impl State {
    fn serialize(&self) -> Result<SerializedState> {
        let mut local_rand = vec![];
        {
            let mut writer = BufWriter::<&mut Vec<u8>>::new(local_rand.as_mut());
            self.local_random.marshal(&mut writer)?;
        }
        let mut remote_rand = vec![];
        {
            let mut writer = BufWriter::<&mut Vec<u8>>::new(remote_rand.as_mut());
            self.remote_random.marshal(&mut writer)?;
        }

        let mut local_random = [0u8; HANDSHAKE_RANDOM_LENGTH];
        let mut remote_random = [0u8; HANDSHAKE_RANDOM_LENGTH];

        local_random.copy_from_slice(&local_rand);
        remote_random.copy_from_slice(&remote_rand);

        let local_epoch = self.local_epoch;
        let remote_epoch = self.remote_epoch;
        let sequence_number = self.local_sequence_number[local_epoch as usize];
        let cipher_suite_id = {
            match &self.cipher_suite {
                Some(cipher_suite) => cipher_suite.id() as u16,
                None => return Err(Error::ErrCipherSuiteUnset),
            }
        };

        Ok(SerializedState {
            local_epoch,
            remote_epoch,
            local_random,
            remote_random,
            cipher_suite_id,
            master_secret: self.master_secret.clone(),
            sequence_number,
            srtp_protection_profile: self.srtp_protection_profile as u16,
            peer_certificates: self.peer_certificates.clone(),
            identity_hint: self.identity_hint.clone(),
            is_client: self.is_client,
            extended_master_secret: self.extended_master_secret,
        })
    }

    fn deserialize(&mut self, serialized: &SerializedState) -> Result<()> {
        // Set epoch values
        self.local_epoch = serialized.local_epoch;
        self.remote_epoch = serialized.remote_epoch;
        {
            while self.local_sequence_number.len() <= serialized.local_epoch as usize {
                self.local_sequence_number.push(0);
            }
            self.local_sequence_number[serialized.local_epoch as usize] =
                serialized.sequence_number;
        }

        // Set random values
        let mut reader = Cursor::new(&serialized.local_random);
        self.local_random = HandshakeRandom::unmarshal(&mut reader)?;

        let mut reader = Cursor::new(&serialized.remote_random);
        self.remote_random = HandshakeRandom::unmarshal(&mut reader)?;

        self.is_client = serialized.is_client;
        self.extended_master_secret = serialized.extended_master_secret;

        // Set master secret
        self.master_secret.clone_from(&serialized.master_secret);

        // Set cipher suite
        self.cipher_suite = Some(cipher_suite_for_id(serialized.cipher_suite_id.into())?);

        self.srtp_protection_profile = serialized.srtp_protection_profile.into();

        // Set remote certificate
        self.peer_certificates
            .clone_from(&serialized.peer_certificates);
        self.identity_hint.clone_from(&serialized.identity_hint);

        Ok(())
    }

    /// Installs the negotiated keys into the cipher suite.
    ///
    /// # Errors
    ///
    /// Fails if the master secret or randoms are not yet available.
    pub fn init_cipher_suite(&mut self) -> Result<()> {
        if let Some(cipher_suite) = &mut self.cipher_suite {
            if cipher_suite.is_initialized() {
                return Ok(());
            }

            let mut local_random = vec![];
            {
                let mut writer = BufWriter::<&mut Vec<u8>>::new(local_random.as_mut());
                self.local_random.marshal(&mut writer)?;
            }
            let mut remote_random = vec![];
            {
                let mut writer = BufWriter::<&mut Vec<u8>>::new(remote_random.as_mut());
                self.remote_random.marshal(&mut writer)?;
            }

            if self.is_client {
                cipher_suite.init(
                    self.crypto_provider.clone(),
                    &self.master_secret,
                    &local_random,
                    &remote_random,
                    true,
                )
            } else {
                cipher_suite.init(
                    self.crypto_provider.clone(),
                    &self.master_secret,
                    &remote_random,
                    &local_random,
                    false,
                )
            }
        } else {
            Err(Error::ErrCipherSuiteUnset)
        }
    }

    // marshal_binary is a binary.BinaryMarshaler.marshal_binary implementation
    /// Serializes the state, so a connection can be resumed or migrated.
    ///
    /// # Errors
    ///
    /// Fails if the state is incomplete.
    pub fn marshal_binary(&self) -> Result<Vec<u8>> {
        let serialized = self.serialize()?;

        match rkyv::to_bytes::<rkyv::rancor::Error>(&serialized).map(Vec::from) {
            Ok(enc) => Ok(enc),
            Err(err) => Err(Error::Other(err.to_string())),
        }
    }

    // unmarshal_binary is a binary.BinaryUnmarshaler.unmarshal_binary implementation
    /// Restores state previously produced by [`Self::marshal_binary`].
    ///
    /// # Errors
    ///
    /// Fails if `data` is truncated or malformed.
    pub fn unmarshal_binary(&mut self, data: &[u8]) -> Result<()> {
        let serialized: SerializedState =
            match rkyv::access::<ArchivedSerializedState, rkyv::rancor::Error>(data)
                .and_then(rkyv::deserialize)
            {
                Ok(dec) => dec,
                Err(err) => return Err(Error::Other(err.to_string())),
            };
        self.deserialize(&serialized)?;
        self.init_cipher_suite()?;

        Ok(())
    }

    /// Forgets the session's secrets: the master secret and the premaster secret are
    /// overwritten and dropped (RFC 5246 7.2.2 for a failed connection, 8.1 for the premaster
    /// secret once the master secret exists). Nothing can be exported or resumed afterwards.
    pub(crate) fn forget_secrets(&mut self) {
        self.secrets_forgotten = true;
        self.forget_pre_master_secret();
        drop(SecretVec::new(std::mem::take(&mut self.master_secret)));
    }

    /// Overwrites and drops the premaster secret.
    pub(crate) fn forget_pre_master_secret(&mut self) {
        drop(SecretVec::new(std::mem::take(&mut self.pre_master_secret)));
    }

    /// The SRTP protection profile negotiated through `use_srtp`.
    pub fn srtp_protection_profile(&self) -> SrtpProtectionProfile {
        self.srtp_protection_profile
    }

    /// Whether this endpoint took the client role.
    pub fn is_client(&self) -> bool {
        self.is_client
    }

    /// The active cipher suite, once one has been negotiated.
    pub fn cipher_suite(&self) -> Option<&dyn CipherSuite> {
        self.cipher_suite.as_deref()
    }

    /// Whether the negotiated cipher suite authenticates with a pre-shared key.
    pub fn is_cipher_suite_psk(&self) -> bool {
        self.cipher_suite
            .as_ref()
            .is_some_and(|cipher_suite| cipher_suite.is_psk())
    }

    /// Exports `length` bytes of keying material from an established session, as defined in
    /// RFC 5705.
    ///
    /// # Errors
    ///
    /// Returns an error before the handshake completes, when `context` is non-empty, when the
    /// label is reserved by TLS, when the negotiated cipher suite is unavailable, or when the
    /// session was established without the extended master secret: such a master secret is not
    /// bound to the handshake, and RFC 7627 5.4 forbids exporting from it.
    pub fn export_keying_material(
        &self,
        label: &str,
        context: &[u8],
        length: usize,
    ) -> Result<SecretVec> {
        if self.local_epoch == 0 {
            return Err(Error::HandshakeInProgress);
        } else if !context.is_empty() {
            return Err(Error::ContextUnsupported);
        } else if INVALID_KEYING_LABELS.contains(&label) {
            return Err(Error::ReservedExportKeyingMaterial);
        } else if !self.extended_master_secret {
            return Err(Error::ErrExportWithoutExtendedMasterSecret);
        } else if self.secrets_forgotten {
            // The association failed and its secrets were forgotten (RFC 5246 7.2.2).
            return Err(Error::ErrConnClosed);
        }

        let mut local_random = vec![];
        {
            let mut writer = BufWriter::<&mut Vec<u8>>::new(local_random.as_mut());
            self.local_random.marshal(&mut writer)?;
        }
        let mut remote_random = vec![];
        {
            let mut writer = BufWriter::<&mut Vec<u8>>::new(remote_random.as_mut());
            self.remote_random.marshal(&mut writer)?;
        }

        let mut seed = label.as_bytes().to_vec();
        if self.is_client {
            seed.extend_from_slice(&local_random);
            seed.extend_from_slice(&remote_random);
        } else {
            seed.extend_from_slice(&remote_random);
            seed.extend_from_slice(&local_random);
        }

        if let Some(cipher_suite) = &self.cipher_suite {
            let provider = self.crypto_provider.as_ref();
            match prf_p_hash(
                provider.crypto(),
                &self.master_secret,
                &seed,
                length,
                cipher_suite.hash_func(),
            ) {
                Ok(v) => Ok(SecretVec::new(v)),
                Err(err) => Err(Error::Hash(err.to_string())),
            }
        } else {
            Err(Error::CipherSuiteUnset)
        }
    }
}
