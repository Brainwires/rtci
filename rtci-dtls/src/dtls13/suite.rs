//! The TLS 1.3 cipher suites DTLS 1.3 negotiates (RFC 8446 appendix B.4): an AEAD for the
//! records and a hash for the key schedule. Key exchange and authentication are negotiated
//! apart from the suite.

use crate::cipher_suite::{CipherSuite, CipherSuiteHash, CipherSuiteId};
use crate::client_certificate_type::ClientCertificateType;
use crate::record_layer::record_layer_header::RecordLayerHeader;
use crypto::{
    AeadAlgorithm, CryptoAlgorithm, HashAlgorithm, HeaderMaskAlgorithm, HmacAlgorithm, RTCCrypto,
    RTCCryptoProvider,
};
use shared::error::{Error, Result};
use std::sync::Arc;

/// A TLS 1.3 cipher suite.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Suite13 {
    pub(crate) id: CipherSuiteId,
}

/// The suites offered and accepted when a configuration names none, in order of preference:
/// the one RFC 8446 section 9.1 makes mandatory and the two it recommends. The CCM suites are
/// for constrained peers and have to be asked for.
pub(crate) const DEFAULT_SUITES: [CipherSuiteId; 3] = [
    CipherSuiteId::Tls_Aes_128_Gcm_Sha256,
    CipherSuiteId::Tls_ChaCha20_Poly1305_Sha256,
    CipherSuiteId::Tls_Aes_256_Gcm_Sha384,
];

impl Suite13 {
    pub(crate) fn for_id(id: CipherSuiteId) -> Option<Self> {
        matches!(
            id,
            CipherSuiteId::Tls_Aes_128_Gcm_Sha256
                | CipherSuiteId::Tls_Aes_256_Gcm_Sha384
                | CipherSuiteId::Tls_ChaCha20_Poly1305_Sha256
                | CipherSuiteId::Tls_Aes_128_Ccm_Sha256
                | CipherSuiteId::Tls_Aes_128_Ccm_8_Sha256
        )
        .then_some(Self { id })
    }

    pub(crate) fn hash(&self) -> HashAlgorithm {
        match self.id {
            CipherSuiteId::Tls_Aes_256_Gcm_Sha384 => HashAlgorithm::Sha384,
            _ => HashAlgorithm::Sha256,
        }
    }

    pub(crate) fn hmac(&self) -> HmacAlgorithm {
        match self.id {
            CipherSuiteId::Tls_Aes_256_Gcm_Sha384 => HmacAlgorithm::Sha384,
            _ => HmacAlgorithm::Sha256,
        }
    }

    pub(crate) fn hash_len(&self) -> usize {
        self.hash().output_len()
    }

    pub(crate) fn aead(&self) -> AeadAlgorithm {
        match self.id {
            CipherSuiteId::Tls_Aes_256_Gcm_Sha384 => AeadAlgorithm::Aes256Gcm,
            CipherSuiteId::Tls_ChaCha20_Poly1305_Sha256 => AeadAlgorithm::ChaCha20Poly1305,
            CipherSuiteId::Tls_Aes_128_Ccm_Sha256 => AeadAlgorithm::Aes128Ccm,
            CipherSuiteId::Tls_Aes_128_Ccm_8_Sha256 => AeadAlgorithm::Aes128Ccm8,
            _ => AeadAlgorithm::Aes128Gcm,
        }
    }

    pub(crate) fn key_len(&self) -> usize {
        match self.id {
            CipherSuiteId::Tls_Aes_256_Gcm_Sha384 | CipherSuiteId::Tls_ChaCha20_Poly1305_Sha256 => {
                32
            }
            _ => 16,
        }
    }

    pub(crate) fn tag_len(&self) -> usize {
        match self.id {
            CipherSuiteId::Tls_Aes_128_Ccm_8_Sha256 => 8,
            _ => 16,
        }
    }

    /// What the record sequence number is encrypted with: the cipher underneath the AEAD
    /// (RFC 9147 section 4.2.3).
    pub(crate) fn header_mask(&self) -> HeaderMaskAlgorithm {
        match self.id {
            CipherSuiteId::Tls_Aes_256_Gcm_Sha384 => HeaderMaskAlgorithm::Aes256,
            CipherSuiteId::Tls_ChaCha20_Poly1305_Sha256 => HeaderMaskAlgorithm::ChaCha20,
            _ => HeaderMaskAlgorithm::Aes128,
        }
    }

    /// How many records one key may protect (RFC 9147 section 4.5.3, RFC 8446 section 5.5):
    /// 2^24.5 for AES-GCM, 2^23 for AES-CCM. ChaCha20-Poly1305 has no limit short of the
    /// sequence number, of which 2^47 leaves room to rekey.
    pub(crate) fn confidentiality_limit(&self) -> u64 {
        match self.aead() {
            AeadAlgorithm::Aes128Gcm | AeadAlgorithm::Aes256Gcm => 23_726_566,
            AeadAlgorithm::Aes128Ccm | AeadAlgorithm::Aes128Ccm8 => 1 << 23,
            _ => 1 << 47,
        }
    }

    /// How many records may fail authentication under one key before the association is
    /// closed (RFC 9147 section 4.5.3): 2^36 for AES-GCM and ChaCha20-Poly1305, 2^23.5 for
    /// AES-CCM. For AES-CCM-8 the RFC gives no figure and requires one "based on an
    /// understanding of any additional forgery protections"; there are none here, so the
    /// limit is the 2^7 forgeries that keep the chance of one success, with a 64-bit tag, at
    /// the 2^-57 the other limits aim for.
    pub(crate) fn integrity_limit(&self) -> u64 {
        match self.aead() {
            AeadAlgorithm::Aes128Ccm => 11_863_283,
            AeadAlgorithm::Aes128Ccm8 => 1 << 7,
            _ => 1 << 36,
        }
    }

    /// Whether `crypto` has what the suite needs. The record-number mask is also created
    /// once: it is the one operation only DTLS 1.3 uses, and a provider that wraps another
    /// and passes `supports` through while leaving `new_header_mask` at its default would
    /// otherwise negotiate DTLS 1.3 and then fail every record. Such a provider gets DTLS
    /// 1.2 instead.
    pub(crate) fn supported_by(&self, crypto: &dyn RTCCrypto) -> bool {
        crypto.supports(CryptoAlgorithm::Hash(self.hash()))
            && crypto.supports(CryptoAlgorithm::Hmac(self.hmac()))
            && crypto.supports(CryptoAlgorithm::Aead(self.aead()))
            && crypto.supports(CryptoAlgorithm::HeaderMask(self.header_mask()))
            && crypto
                .new_header_mask(self.header_mask(), &vec![0u8; self.key_len()])
                .is_ok_and(|mut mask| mask.mask(&[0u8; crypto::HEADER_MASK_SAMPLE_LEN]).is_ok())
    }
}

/// A TLS 1.3 suite as the [`CipherSuite`] an association reports
/// ([`State::cipher_suite`](crate::state::State::cipher_suite)). Its record protection is the
/// DTLS 1.3 record layer's, with keys per epoch, so the DTLS 1.2 entry points of the trait
/// refuse.
impl CipherSuite for Suite13 {
    fn to_string(&self) -> String {
        format!("{}", self.id)
    }

    fn id(&self) -> CipherSuiteId {
        self.id
    }

    fn certificate_type(&self) -> ClientCertificateType {
        // A TLS 1.3 suite does not name the authentication; the certificate decides.
        ClientCertificateType::Unsupported
    }

    fn hash_func(&self) -> CipherSuiteHash {
        match self.hash() {
            HashAlgorithm::Sha384 => CipherSuiteHash::Sha384,
            _ => CipherSuiteHash::Sha256,
        }
    }

    fn is_psk(&self) -> bool {
        false
    }

    fn is_initialized(&self) -> bool {
        false
    }

    fn record_expansion(&self) -> usize {
        // The inner content type and the tag; the unified header is at most five bytes plus
        // the connection id, against the 13 of a DTLS 1.2 record header.
        1 + self.tag_len()
    }

    fn init(
        &mut self,
        _provider: Arc<dyn RTCCryptoProvider>,
        _master_secret: &[u8],
        _client_random: &[u8],
        _server_random: &[u8],
        _is_client: bool,
    ) -> Result<()> {
        Err(Error::ErrInvalidCipherSuite)
    }

    fn encrypt(&mut self, _pkt_rlh: &RecordLayerHeader, _raw: &[u8]) -> Result<Vec<u8>> {
        Err(Error::ErrInvalidCipherSuite)
    }

    fn decrypt(&mut self, _input: &[u8]) -> Result<Vec<u8>> {
        Err(Error::ErrInvalidCipherSuite)
    }
}
