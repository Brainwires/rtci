//! The TLS 1.3 key schedule (RFC 8446 section 7) with the DTLS 1.3 label prefix (RFC 9147
//! section 5.9), and the handshake transcript it is keyed to.

use super::suite::Suite13;
use crypto::{RTCCrypto, SecretVec, hkdf_expand_label, hkdf_extract};
use shared::error::{Error, Result};

/// The label prefix of DTLS 1.3 (RFC 9147 section 5.9): no trailing space, unlike TLS 1.3's.
pub(crate) const DTLS13_LABEL_PREFIX: &str = "dtls13";
/// The label prefix of TLS 1.3 (RFC 8446 section 7.1), which the RFC 8448 traces use.
#[cfg(test)]
pub(crate) const TLS13_LABEL_PREFIX: &str = "tls13 ";

/// The handshake type of the synthetic message that stands for the first ClientHello after a
/// HelloRetryRequest (RFC 8446 section 4.4.1).
pub(crate) const HANDSHAKE_TYPE_MESSAGE_HASH: u8 = 254;

fn crypto_error(error: crypto::CryptoError) -> Error {
    Error::Crypto(error.to_string())
}

/// The handshake transcript: the TLS 1.3 form of every handshake message so far, that is,
/// type, 24-bit length and body, without the DTLS message_seq and fragment fields (RFC 9147
/// section 5.2).
#[derive(Clone, Default)]
pub(crate) struct Transcript {
    bytes: Vec<u8>,
}

impl Transcript {
    /// Appends one whole handshake message.
    pub(crate) fn add(&mut self, handshake_type: u8, body: &[u8]) {
        self.bytes.push(handshake_type);
        self.bytes
            .extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
        self.bytes.extend_from_slice(body);
    }

    /// Replaces what has been recorded, which is the first ClientHello, with the synthetic
    /// message_hash message that carries its hash: what a HelloRetryRequest does to the
    /// transcript (RFC 8446 section 4.4.1).
    pub(crate) fn replace_with_message_hash(
        &mut self,
        crypto: &dyn RTCCrypto,
        suite: Suite13,
    ) -> Result<()> {
        let hash = self.hash(crypto, suite)?;
        self.set_message_hash(&hash);
        Ok(())
    }

    /// Starts the transcript from the hash of a first ClientHello this side no longer has:
    /// a server that kept no state for it reads the hash back from its cookie (RFC 9147
    /// section 5.1).
    pub(crate) fn set_message_hash(&mut self, client_hello_hash: &[u8]) {
        self.bytes.clear();
        self.add(HANDSHAKE_TYPE_MESSAGE_HASH, client_hello_hash);
    }

    /// `Transcript-Hash` of everything recorded.
    pub(crate) fn hash(&self, crypto: &dyn RTCCrypto, suite: Suite13) -> Result<Vec<u8>> {
        crypto.hash(suite.hash(), &self.bytes).map_err(crypto_error)
    }

    /// `Transcript-Hash` of everything recorded followed by `more`.
    pub(crate) fn hash_with(
        &self,
        crypto: &dyn RTCCrypto,
        suite: Suite13,
        more: &[u8],
    ) -> Result<Vec<u8>> {
        let mut bytes = self.bytes.clone();
        bytes.extend_from_slice(more);
        crypto.hash(suite.hash(), &bytes).map_err(crypto_error)
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}

/// The secrets of one handshake, derived stage by stage as RFC 8446 section 7.1 draws them.
pub(crate) struct KeySchedule {
    suite: Suite13,
    prefix: &'static str,
    /// The Early Secret, then the Handshake Secret, then the Main Secret.
    current: SecretVec,
    pub(crate) client_handshake_traffic: Option<SecretVec>,
    pub(crate) server_handshake_traffic: Option<SecretVec>,
    pub(crate) client_application_traffic: Option<SecretVec>,
    pub(crate) server_application_traffic: Option<SecretVec>,
    pub(crate) exporter: Option<SecretVec>,
}

impl KeySchedule {
    /// Starts the schedule with no PSK: the Early Secret is extracted from a string of zeros.
    pub(crate) fn new(
        crypto: &dyn RTCCrypto,
        suite: Suite13,
        prefix: &'static str,
    ) -> Result<Self> {
        let zeros = vec![0u8; suite.hash_len()];
        let early = hkdf_extract(crypto, suite.hmac(), &[], &zeros).map_err(crypto_error)?;
        Ok(Self {
            suite,
            prefix,
            current: early,
            client_handshake_traffic: None,
            server_handshake_traffic: None,
            client_application_traffic: None,
            server_application_traffic: None,
            exporter: None,
        })
    }

    pub(crate) fn suite(&self) -> Suite13 {
        self.suite
    }

    fn expand_label(
        &self,
        crypto: &dyn RTCCrypto,
        secret: &[u8],
        label: &str,
        context: &[u8],
        length: usize,
    ) -> Result<SecretVec> {
        hkdf_expand_label(
            crypto,
            self.suite.hmac(),
            secret,
            self.prefix,
            label,
            context,
            length,
        )
        .map_err(crypto_error)
    }

    /// `Derive-Secret(Secret, Label, Messages)`, given the transcript hash of the messages.
    fn derive_secret(
        &self,
        crypto: &dyn RTCCrypto,
        secret: &[u8],
        label: &str,
        transcript_hash: &[u8],
    ) -> Result<SecretVec> {
        self.expand_label(
            crypto,
            secret,
            label,
            transcript_hash,
            self.suite.hash_len(),
        )
    }

    /// Moves from the current secret to the next one in the chain:
    /// `HKDF-Extract(Derive-Secret(current, "derived", ""), input)`.
    fn advance(&mut self, crypto: &dyn RTCCrypto, input: &[u8]) -> Result<()> {
        let empty_hash = crypto.hash(self.suite.hash(), &[]).map_err(crypto_error)?;
        let salt = self.derive_secret(crypto, self.current.as_ref(), "derived", &empty_hash)?;
        self.current =
            hkdf_extract(crypto, self.suite.hmac(), salt.as_ref(), input).map_err(crypto_error)?;
        Ok(())
    }

    /// Derives the Handshake Secret from the (EC)DHE shared secret, and from it the two
    /// handshake traffic secrets, over the transcript up to and including the ServerHello.
    pub(crate) fn enter_handshake(
        &mut self,
        crypto: &dyn RTCCrypto,
        shared_secret: &[u8],
        transcript_hash: &[u8],
    ) -> Result<()> {
        self.advance(crypto, shared_secret)?;
        self.client_handshake_traffic = Some(self.derive_secret(
            crypto,
            self.current.as_ref(),
            "c hs traffic",
            transcript_hash,
        )?);
        self.server_handshake_traffic = Some(self.derive_secret(
            crypto,
            self.current.as_ref(),
            "s hs traffic",
            transcript_hash,
        )?);
        Ok(())
    }

    /// Derives the Main Secret, and from it the first application traffic secrets and the
    /// exporter secret, over the transcript up to and including the server's Finished.
    pub(crate) fn enter_application(
        &mut self,
        crypto: &dyn RTCCrypto,
        transcript_hash: &[u8],
    ) -> Result<()> {
        let zeros = vec![0u8; self.suite.hash_len()];
        self.advance(crypto, &zeros)?;
        self.client_application_traffic = Some(self.derive_secret(
            crypto,
            self.current.as_ref(),
            "c ap traffic",
            transcript_hash,
        )?);
        self.server_application_traffic = Some(self.derive_secret(
            crypto,
            self.current.as_ref(),
            "s ap traffic",
            transcript_hash,
        )?);
        self.exporter = Some(self.derive_secret(
            crypto,
            self.current.as_ref(),
            "exp master",
            transcript_hash,
        )?);
        // Nothing else is derived from the Main Secret here (no resumption), so it goes.
        self.current = SecretVec::new(vec![]);
        Ok(())
    }

    /// The verify_data of a Finished: `HMAC(finished_key, Transcript-Hash)`, the key expanded
    /// from the sender's handshake traffic secret (RFC 8446 section 4.4.4).
    pub(crate) fn finished_verify_data(
        &self,
        crypto: &dyn RTCCrypto,
        base_key: &[u8],
        transcript_hash: &[u8],
    ) -> Result<Vec<u8>> {
        let finished_key =
            self.expand_label(crypto, base_key, "finished", &[], self.suite.hash_len())?;
        let mut mac = crypto
            .new_hmac(self.suite.hmac(), finished_key.as_ref())
            .map_err(crypto_error)?;
        let mut verify_data = vec![0u8; mac.output_len()];
        mac.sign(&[transcript_hash], &mut verify_data)
            .map_err(crypto_error)?;
        Ok(verify_data)
    }

    /// `application_traffic_secret_N+1` from `application_traffic_secret_N` (RFC 8446
    /// section 7.2): what a KeyUpdate moves a direction to.
    pub(crate) fn next_application_traffic_secret(
        &self,
        crypto: &dyn RTCCrypto,
        secret: &[u8],
    ) -> Result<SecretVec> {
        self.expand_label(crypto, secret, "traffic upd", &[], self.suite.hash_len())
    }

    /// The key, IV and record-number key of a traffic secret (RFC 8446 section 7.3, RFC 9147
    /// section 4.2.3).
    pub(crate) fn traffic_keys(
        &self,
        crypto: &dyn RTCCrypto,
        secret: &[u8],
    ) -> Result<TrafficKeys> {
        Ok(TrafficKeys {
            key: self.expand_label(crypto, secret, "key", &[], self.suite.key_len())?,
            iv: self.expand_label(crypto, secret, "iv", &[], 12)?,
            sequence_number_key: self.expand_label(
                crypto,
                secret,
                "sn",
                &[],
                self.suite.header_mask().key_len(),
            )?,
        })
    }

    /// `TLS-Exporter(label, context_value, key_length)` (RFC 8446 section 7.5).
    pub(crate) fn export(
        &self,
        crypto: &dyn RTCCrypto,
        exporter_secret: &[u8],
        label: &str,
        context: &[u8],
        length: usize,
    ) -> Result<SecretVec> {
        let empty_hash = crypto.hash(self.suite.hash(), &[]).map_err(crypto_error)?;
        let secret = self.derive_secret(crypto, exporter_secret, label, &empty_hash)?;
        let context_hash = crypto
            .hash(self.suite.hash(), context)
            .map_err(crypto_error)?;
        self.expand_label(crypto, secret.as_ref(), "exporter", &context_hash, length)
    }

    /// Overwrites and drops every secret (RFC 8446 section 6.2: a failed connection's
    /// secrets are forgotten).
    pub(crate) fn forget(&mut self) {
        self.current = SecretVec::new(vec![]);
        self.client_handshake_traffic = None;
        self.server_handshake_traffic = None;
        self.client_application_traffic = None;
        self.server_application_traffic = None;
        self.exporter = None;
    }
}

/// The keys of one direction in one epoch.
pub(crate) struct TrafficKeys {
    pub(crate) key: SecretVec,
    pub(crate) iv: SecretVec,
    pub(crate) sequence_number_key: SecretVec,
}

/// What a CertificateVerify signs (RFC 8446 section 4.4.3): 64 spaces, the context string, a
/// zero byte and the transcript hash.
pub(crate) fn certificate_verify_input(from_server: bool, transcript_hash: &[u8]) -> Vec<u8> {
    let context: &[u8] = if from_server {
        b"TLS 1.3, server CertificateVerify"
    } else {
        b"TLS 1.3, client CertificateVerify"
    };
    let mut input = vec![0x20u8; 64];
    input.extend_from_slice(context);
    input.push(0);
    input.extend_from_slice(transcript_hash);
    input
}

/// `TLS-Exporter` for a completed DTLS 1.3 handshake, from its exporter secret.
pub(crate) fn export_keying_material(
    crypto: &dyn RTCCrypto,
    suite: Suite13,
    exporter_secret: &[u8],
    label: &str,
    context: &[u8],
    length: usize,
) -> Result<SecretVec> {
    let empty_hash = crypto.hash(suite.hash(), &[]).map_err(crypto_error)?;
    let expand = |secret: &[u8], label: &str, context: &[u8], length: usize| {
        hkdf_expand_label(
            crypto,
            suite.hmac(),
            secret,
            DTLS13_LABEL_PREFIX,
            label,
            context,
            length,
        )
        .map_err(crypto_error)
    };
    let secret = expand(exporter_secret, label, &empty_hash, suite.hash_len())?;
    let context_hash = crypto.hash(suite.hash(), context).map_err(crypto_error)?;
    expand(secret.as_ref(), "exporter", &context_hash, length)
}
