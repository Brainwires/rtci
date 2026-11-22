/// Shared implementation for the AES-128-CCM suites.
pub mod cipher_suite_aes_128_ccm;
/// Shared implementation for the AES-128-GCM-SHA256 suites.
pub mod cipher_suite_aes_128_gcm_sha256;
/// Shared implementation for the AES-256-CBC-SHA suites.
pub mod cipher_suite_aes_256_cbc_sha;
/// Shared implementation for the ChaCha20-Poly1305-SHA256 suites.
pub mod cipher_suite_chacha20_poly1305_sha256;
/// An ECDHE-ECDSA suite with AES-128, the pairing WebRTC normally negotiates.
/// An ECDHE-ECDSA suite with AES-128-CCM and a truncated 8-byte tag.
pub mod cipher_suite_tls_ecdhe_ecdsa_with_aes_128_ccm;
/// An ECDHE-ECDSA suite with AES-128-CCM and a full 16-byte tag.
pub mod cipher_suite_tls_ecdhe_ecdsa_with_aes_128_ccm8;
/// `TLS_PSK_WITH_AES_128_CCM`, for pre-shared-key handshakes.
pub mod cipher_suite_tls_psk_with_aes_128_ccm;
/// `TLS_PSK_WITH_AES_128_CCM_8`, with a truncated 8-byte tag.
pub mod cipher_suite_tls_psk_with_aes_128_ccm8;
/// `TLS_PSK_WITH_AES_128_GCM_SHA256`, for pre-shared-key handshakes.
pub mod cipher_suite_tls_psk_with_aes_128_gcm_sha256;

use crypto::RTCCryptoProvider;
use crypto::{
    AeadAlgorithm, CbcAlgorithm, CryptoAlgorithm, HashAlgorithm, HmacAlgorithm, RTCCrypto,
};
use std::fmt;
use std::sync::Arc;

use super::client_certificate_type::*;
use super::record_layer::record_layer_header::*;
use shared::error::*;

use cipher_suite_aes_128_gcm_sha256::*;
use cipher_suite_aes_256_cbc_sha::*;
use cipher_suite_chacha20_poly1305_sha256::*;
use cipher_suite_tls_ecdhe_ecdsa_with_aes_128_ccm::*;
use cipher_suite_tls_ecdhe_ecdsa_with_aes_128_ccm8::*;
use cipher_suite_tls_psk_with_aes_128_ccm::*;
use cipher_suite_tls_psk_with_aes_128_ccm8::*;
use cipher_suite_tls_psk_with_aes_128_gcm_sha256::*;

// CipherSuiteID is an ID for our supported CipherSuites
// Supported Cipher Suites
#[allow(non_camel_case_types)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
/// The cipher suites this crate can negotiate, by their IANA code points.
#[non_exhaustive]
pub enum CipherSuiteId {
    // AES-128-CCM
    /// `TLS_ECDHE_ECDSA_WITH_AES_128_CCM` (`0xc0ac`).
    Tls_Ecdhe_Ecdsa_With_Aes_128_Ccm = 0xc0ac,
    /// `TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8` (`0xc0ae`).
    Tls_Ecdhe_Ecdsa_With_Aes_128_Ccm_8 = 0xc0ae,

    // AES-128-GCM-SHA256
    /// `TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256` (`0xc02b`).
    Tls_Ecdhe_Ecdsa_With_Aes_128_Gcm_Sha256 = 0xc02b,
    /// `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256` (`0xc02f`).
    Tls_Ecdhe_Rsa_With_Aes_128_Gcm_Sha256 = 0xc02f,

    // AES-256-CBC-SHA
    /// `TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA` (`0xc00a`).
    Tls_Ecdhe_Ecdsa_With_Aes_256_Cbc_Sha = 0xc00a,
    /// `TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA` (`0xc014`).
    Tls_Ecdhe_Rsa_With_Aes_256_Cbc_Sha = 0xc014,

    /// `TLS_PSK_WITH_AES_128_CCM` (`0xc0a4`).
    Tls_Psk_With_Aes_128_Ccm = 0xc0a4,
    /// `TLS_PSK_WITH_AES_128_CCM_8` (`0xc0a8`).
    Tls_Psk_With_Aes_128_Ccm_8 = 0xc0a8,
    /// `TLS_PSK_WITH_AES_128_GCM_SHA256` (`0x00a8`).
    Tls_Psk_With_Aes_128_Gcm_Sha256 = 0x00a8,

    // CHACHA20_POLY1305_SHA256
    /// `TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256` (`0xcca8`).
    Tls_Ecdhe_Rsa_With_ChaCha20_Poly1305_Sha256 = 0xcca8,
    /// `TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256` (`0xcca9`).
    Tls_Ecdhe_Ecdsa_With_ChaCha20_Poly1305_Sha256 = 0xcca9,

    // TLS 1.3 suites (RFC 8446 appendix B.4), negotiated with DTLS 1.3 only.
    /// `TLS_AES_128_GCM_SHA256` (`0x1301`), DTLS 1.3.
    Tls_Aes_128_Gcm_Sha256 = 0x1301,
    /// `TLS_AES_256_GCM_SHA384` (`0x1302`), DTLS 1.3.
    Tls_Aes_256_Gcm_Sha384 = 0x1302,
    /// `TLS_CHACHA20_POLY1305_SHA256` (`0x1303`), DTLS 1.3.
    Tls_ChaCha20_Poly1305_Sha256 = 0x1303,
    /// `TLS_AES_128_CCM_SHA256` (`0x1304`), DTLS 1.3. Not in the default list.
    Tls_Aes_128_Ccm_Sha256 = 0x1304,
    /// `TLS_AES_128_CCM_8_SHA256` (`0x1305`), DTLS 1.3. Never in the default list: RFC 9147
    /// section 4.5.3 forbids it in DTLS without further protection against forgery, so it is
    /// negotiated only when a configuration names it, and then under a small limit of
    /// records that may fail authentication.
    Tls_Aes_128_Ccm_8_Sha256 = 0x1305,

    /// `TLS_EMPTY_RENEGOTIATION_INFO_SCSV` (`0x00ff`): not a cipher suite. A client lists it
    /// to signal secure renegotiation without the renegotiation_info extension (RFC 5746 3.3).
    /// It is recognised in a ClientHello and never negotiated or offered.
    Tls_Empty_Renegotiation_Info_Scsv = 0x00ff,

    /// A code point this crate does not implement.
    Unsupported,
}

impl fmt::Display for CipherSuiteId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            CipherSuiteId::Tls_Ecdhe_Ecdsa_With_Aes_128_Ccm => {
                write!(f, "TLS_ECDHE_ECDSA_WITH_AES_128_CCM")
            }
            CipherSuiteId::Tls_Ecdhe_Ecdsa_With_Aes_128_Ccm_8 => {
                write!(f, "TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8")
            }
            CipherSuiteId::Tls_Ecdhe_Ecdsa_With_Aes_128_Gcm_Sha256 => {
                write!(f, "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256")
            }
            CipherSuiteId::Tls_Ecdhe_Rsa_With_Aes_128_Gcm_Sha256 => {
                write!(f, "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256")
            }
            CipherSuiteId::Tls_Ecdhe_Ecdsa_With_Aes_256_Cbc_Sha => {
                write!(f, "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA")
            }
            CipherSuiteId::Tls_Ecdhe_Rsa_With_Aes_256_Cbc_Sha => {
                write!(f, "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA")
            }
            CipherSuiteId::Tls_Psk_With_Aes_128_Ccm => write!(f, "TLS_PSK_WITH_AES_128_CCM"),
            CipherSuiteId::Tls_Psk_With_Aes_128_Ccm_8 => write!(f, "TLS_PSK_WITH_AES_128_CCM_8"),
            CipherSuiteId::Tls_Psk_With_Aes_128_Gcm_Sha256 => {
                write!(f, "TLS_PSK_WITH_AES_128_GCM_SHA256")
            }
            CipherSuiteId::Tls_Ecdhe_Rsa_With_ChaCha20_Poly1305_Sha256 => {
                write!(f, "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256")
            }
            CipherSuiteId::Tls_Ecdhe_Ecdsa_With_ChaCha20_Poly1305_Sha256 => {
                write!(f, "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256")
            }

            CipherSuiteId::Tls_Aes_128_Gcm_Sha256 => write!(f, "TLS_AES_128_GCM_SHA256"),
            CipherSuiteId::Tls_Aes_256_Gcm_Sha384 => write!(f, "TLS_AES_256_GCM_SHA384"),
            CipherSuiteId::Tls_ChaCha20_Poly1305_Sha256 => {
                write!(f, "TLS_CHACHA20_POLY1305_SHA256")
            }
            CipherSuiteId::Tls_Aes_128_Ccm_Sha256 => write!(f, "TLS_AES_128_CCM_SHA256"),
            CipherSuiteId::Tls_Aes_128_Ccm_8_Sha256 => write!(f, "TLS_AES_128_CCM_8_SHA256"),

            CipherSuiteId::Tls_Empty_Renegotiation_Info_Scsv => {
                write!(f, "TLS_EMPTY_RENEGOTIATION_INFO_SCSV")
            }

            _ => write!(f, "Unsupported CipherSuiteID"),
        }
    }
}

impl From<u16> for CipherSuiteId {
    fn from(val: u16) -> Self {
        match val {
            // AES-128-CCM
            0xc0ac => CipherSuiteId::Tls_Ecdhe_Ecdsa_With_Aes_128_Ccm,
            0xc0ae => CipherSuiteId::Tls_Ecdhe_Ecdsa_With_Aes_128_Ccm_8,

            // AES-128-GCM-SHA256
            0xc02b => CipherSuiteId::Tls_Ecdhe_Ecdsa_With_Aes_128_Gcm_Sha256,
            0xc02f => CipherSuiteId::Tls_Ecdhe_Rsa_With_Aes_128_Gcm_Sha256,

            // AES-256-CBC-SHA
            0xc00a => CipherSuiteId::Tls_Ecdhe_Ecdsa_With_Aes_256_Cbc_Sha,
            0xc014 => CipherSuiteId::Tls_Ecdhe_Rsa_With_Aes_256_Cbc_Sha,

            0xc0a4 => CipherSuiteId::Tls_Psk_With_Aes_128_Ccm,
            0xc0a8 => CipherSuiteId::Tls_Psk_With_Aes_128_Ccm_8,
            0x00a8 => CipherSuiteId::Tls_Psk_With_Aes_128_Gcm_Sha256,

            // CHACHA20_POLY1305_SHA256
            0xcca8 => CipherSuiteId::Tls_Ecdhe_Rsa_With_ChaCha20_Poly1305_Sha256,
            0xcca9 => CipherSuiteId::Tls_Ecdhe_Ecdsa_With_ChaCha20_Poly1305_Sha256,

            0x1301 => CipherSuiteId::Tls_Aes_128_Gcm_Sha256,
            0x1302 => CipherSuiteId::Tls_Aes_256_Gcm_Sha384,
            0x1303 => CipherSuiteId::Tls_ChaCha20_Poly1305_Sha256,
            0x1304 => CipherSuiteId::Tls_Aes_128_Ccm_Sha256,
            0x1305 => CipherSuiteId::Tls_Aes_128_Ccm_8_Sha256,

            0x00ff => CipherSuiteId::Tls_Empty_Renegotiation_Info_Scsv,

            _ => CipherSuiteId::Unsupported,
        }
    }
}

impl From<&str> for CipherSuiteId {
    fn from(val: &str) -> Self {
        match val {
            "TLS_ECDHE_ECDSA_WITH_AES_128_CCM" => CipherSuiteId::Tls_Ecdhe_Ecdsa_With_Aes_128_Ccm,
            "TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8" => {
                CipherSuiteId::Tls_Ecdhe_Ecdsa_With_Aes_128_Ccm_8
            }
            "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256" => {
                CipherSuiteId::Tls_Ecdhe_Ecdsa_With_Aes_128_Gcm_Sha256
            }
            "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256" => {
                CipherSuiteId::Tls_Ecdhe_Rsa_With_Aes_128_Gcm_Sha256
            }
            "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA" => {
                CipherSuiteId::Tls_Ecdhe_Ecdsa_With_Aes_256_Cbc_Sha
            }
            "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA" => {
                CipherSuiteId::Tls_Ecdhe_Rsa_With_Aes_256_Cbc_Sha
            }
            "TLS_PSK_WITH_AES_128_CCM" => CipherSuiteId::Tls_Psk_With_Aes_128_Ccm,
            "TLS_PSK_WITH_AES_128_CCM_8" => CipherSuiteId::Tls_Psk_With_Aes_128_Ccm_8,
            "TLS_PSK_WITH_AES_128_GCM_SHA256" => CipherSuiteId::Tls_Psk_With_Aes_128_Gcm_Sha256,
            "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256" => {
                CipherSuiteId::Tls_Ecdhe_Rsa_With_ChaCha20_Poly1305_Sha256
            }
            "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256" => {
                CipherSuiteId::Tls_Ecdhe_Ecdsa_With_ChaCha20_Poly1305_Sha256
            }
            "TLS_AES_128_GCM_SHA256" => CipherSuiteId::Tls_Aes_128_Gcm_Sha256,
            "TLS_AES_256_GCM_SHA384" => CipherSuiteId::Tls_Aes_256_Gcm_Sha384,
            "TLS_CHACHA20_POLY1305_SHA256" => CipherSuiteId::Tls_ChaCha20_Poly1305_Sha256,
            "TLS_AES_128_CCM_SHA256" => CipherSuiteId::Tls_Aes_128_Ccm_Sha256,
            "TLS_AES_128_CCM_8_SHA256" => CipherSuiteId::Tls_Aes_128_Ccm_8_Sha256,
            _ => CipherSuiteId::Unsupported,
        }
    }
}

impl CipherSuiteId {
    /// Whether this is a TLS 1.3 suite, which DTLS 1.3 negotiates and DTLS 1.2 cannot.
    pub fn is_tls13(self) -> bool {
        crate::dtls13::suite::Suite13::for_id(self).is_some()
    }

    pub(crate) fn supported_by(self, crypto: &dyn RTCCrypto) -> bool {
        if let Some(suite) = crate::dtls13::suite::Suite13::for_id(self) {
            return suite.supported_by(crypto);
        }
        let record_algorithm = match self {
            Self::Tls_Ecdhe_Ecdsa_With_Aes_128_Ccm | Self::Tls_Psk_With_Aes_128_Ccm => {
                CryptoAlgorithm::Aead(AeadAlgorithm::Aes128Ccm)
            }
            Self::Tls_Ecdhe_Ecdsa_With_Aes_128_Ccm_8 | Self::Tls_Psk_With_Aes_128_Ccm_8 => {
                CryptoAlgorithm::Aead(AeadAlgorithm::Aes128Ccm8)
            }
            Self::Tls_Ecdhe_Ecdsa_With_Aes_128_Gcm_Sha256
            | Self::Tls_Ecdhe_Rsa_With_Aes_128_Gcm_Sha256
            | Self::Tls_Psk_With_Aes_128_Gcm_Sha256 => {
                CryptoAlgorithm::Aead(AeadAlgorithm::Aes128Gcm)
            }
            Self::Tls_Ecdhe_Ecdsa_With_Aes_256_Cbc_Sha
            | Self::Tls_Ecdhe_Rsa_With_Aes_256_Cbc_Sha => {
                CryptoAlgorithm::Cbc(CbcAlgorithm::Aes256Cbc)
            }
            Self::Tls_Ecdhe_Ecdsa_With_ChaCha20_Poly1305_Sha256
            | Self::Tls_Ecdhe_Rsa_With_ChaCha20_Poly1305_Sha256 => {
                CryptoAlgorithm::Aead(AeadAlgorithm::ChaCha20Poly1305)
            }
            Self::Tls_Aes_128_Gcm_Sha256
            | Self::Tls_Aes_256_Gcm_Sha384
            | Self::Tls_ChaCha20_Poly1305_Sha256
            | Self::Tls_Aes_128_Ccm_Sha256
            | Self::Tls_Aes_128_Ccm_8_Sha256
            | Self::Tls_Empty_Renegotiation_Info_Scsv
            | Self::Unsupported => return false,
        };
        crypto.supports(CryptoAlgorithm::Hash(HashAlgorithm::Sha256))
            && crypto.supports(CryptoAlgorithm::Hmac(HmacAlgorithm::Sha256))
            && crypto.supports(record_algorithm)
            && (!matches!(record_algorithm, CryptoAlgorithm::Cbc(_))
                || crypto.supports(CryptoAlgorithm::Hmac(HmacAlgorithm::Sha1)))
    }
}

#[derive(Copy, Clone, Debug)]
/// The hash a suite uses in its PRF and `Finished` computation.
#[non_exhaustive]
pub enum CipherSuiteHash {
    /// SHA-256.
    Sha256,
    /// SHA-384 (TLS 1.3 `_SHA384` suites).
    Sha384,
}

impl CipherSuiteHash {
    pub(crate) fn size(&self) -> usize {
        match *self {
            CipherSuiteHash::Sha256 => 32,
            CipherSuiteHash::Sha384 => 48,
        }
    }

    pub(crate) fn hmac_algorithm(&self) -> HmacAlgorithm {
        match *self {
            CipherSuiteHash::Sha256 => HmacAlgorithm::Sha256,
            CipherSuiteHash::Sha384 => HmacAlgorithm::Sha384,
        }
    }

    pub(crate) fn hash_algorithm(&self) -> HashAlgorithm {
        match *self {
            CipherSuiteHash::Sha256 => HashAlgorithm::Sha256,
            CipherSuiteHash::Sha384 => HashAlgorithm::Sha384,
        }
    }
}

/// A negotiated cipher suite: its identity, and the record encryption it performs once keys
/// are installed.
pub trait CipherSuite: Send {
    /// The suite's IANA name.
    fn to_string(&self) -> String;
    /// The suite's code point.
    fn id(&self) -> CipherSuiteId;
    /// The certificate type this suite requires of a peer.
    fn certificate_type(&self) -> ClientCertificateType;
    /// The hash used for the PRF and `Finished`.
    fn hash_func(&self) -> CipherSuiteHash;
    /// Whether this suite authenticates with a pre-shared key rather than certificates.
    fn is_psk(&self) -> bool;
    /// Whether keys have been installed, so records can be protected.
    fn is_initialized(&self) -> bool;
    /// The most bytes this suite's record protection adds to a record's payload (explicit
    /// nonce or IV, authentication tag or MAC, padding), on top of the 13-byte record header.
    /// An application sizing its datagrams for a path MTU subtracts both (RFC 6347 4.1.1.1).
    fn record_expansion(&self) -> usize;

    // Generate the internal encryption state
    /// Installs the keying material derived from the handshake.
    ///
    /// # Errors
    ///
    /// Fails if the key or salt lengths do not match what this suite expects.
    fn init(
        &mut self,
        provider: Arc<dyn RTCCryptoProvider>,
        master_secret: &[u8],
        client_random: &[u8],
        server_random: &[u8],
        is_client: bool,
    ) -> Result<()>;

    /// Protects one record, returning the encrypted record including its header.
    ///
    /// # Errors
    ///
    /// Fails if keys are not installed, or the cipher rejects the input.
    fn encrypt(&mut self, pkt_rlh: &RecordLayerHeader, raw: &[u8]) -> Result<Vec<u8>>;
    /// Unprotects one record.
    ///
    /// # Errors
    ///
    /// Fails if authentication fails, or the record is malformed.
    fn decrypt(&mut self, input: &[u8]) -> Result<Vec<u8>>;

    /// [`Self::encrypt`] for a `tls12_cid` record (RFC 9146): `pkt_rlh` and `raw` have the
    /// content type `tls12_cid` and the DTLSInnerPlaintext, without the connection id,
    /// which the additional data (or MAC) covers. The result has the 13-byte header too;
    /// the caller puts the connection id into it.
    ///
    /// # Errors
    ///
    /// Fails as [`Self::encrypt`] does, and for a suite without `tls12_cid` records.
    fn encrypt_with_connection_id(
        &mut self,
        _pkt_rlh: &RecordLayerHeader,
        _raw: &[u8],
        _connection_id: &[u8],
    ) -> Result<Vec<u8>> {
        Err(Error::Other(
            "the cipher suite has no tls12_cid records".to_owned(),
        ))
    }

    /// [`Self::decrypt`] for a `tls12_cid` record (RFC 9146), given without its connection
    /// id; the result is the header and the DTLSInnerPlaintext.
    ///
    /// # Errors
    ///
    /// Fails as [`Self::decrypt`] does, and for a suite without `tls12_cid` records.
    fn decrypt_with_connection_id(
        &mut self,
        _input: &[u8],
        _connection_id: &[u8],
    ) -> Result<Vec<u8>> {
        Err(Error::Other(
            "the cipher suite has no tls12_cid records".to_owned(),
        ))
    }
}

// Taken from https://www.iana.org/assignments/tls-parameters/tls-parameters.xml
// A cipher_suite is a specific combination of key agreement, cipher and MAC
// function.
/// Builds the [`CipherSuite`] implementation for `id`.
///
/// # Errors
///
/// Fails if the id is not one this crate implements.
pub fn cipher_suite_for_id(id: CipherSuiteId) -> Result<Box<dyn CipherSuite>> {
    match id {
        CipherSuiteId::Tls_Ecdhe_Ecdsa_With_Aes_128_Ccm => {
            Ok(Box::new(new_cipher_suite_tls_ecdhe_ecdsa_with_aes_128_ccm()))
        }
        CipherSuiteId::Tls_Ecdhe_Ecdsa_With_Aes_128_Ccm_8 => Ok(Box::new(
            new_cipher_suite_tls_ecdhe_ecdsa_with_aes_128_ccm8(),
        )),
        CipherSuiteId::Tls_Ecdhe_Ecdsa_With_Aes_128_Gcm_Sha256 => {
            Ok(Box::new(CipherSuiteAes128GcmSha256::new(false)))
        }
        CipherSuiteId::Tls_Ecdhe_Rsa_With_Aes_128_Gcm_Sha256 => {
            Ok(Box::new(CipherSuiteAes128GcmSha256::new(true)))
        }
        CipherSuiteId::Tls_Ecdhe_Rsa_With_Aes_256_Cbc_Sha => {
            Ok(Box::new(CipherSuiteAes256CbcSha::new(true)))
        }
        CipherSuiteId::Tls_Ecdhe_Ecdsa_With_Aes_256_Cbc_Sha => {
            Ok(Box::new(CipherSuiteAes256CbcSha::new(false)))
        }
        CipherSuiteId::Tls_Psk_With_Aes_128_Ccm => {
            Ok(Box::new(new_cipher_suite_tls_psk_with_aes_128_ccm()))
        }
        CipherSuiteId::Tls_Psk_With_Aes_128_Ccm_8 => {
            Ok(Box::new(new_cipher_suite_tls_psk_with_aes_128_ccm8()))
        }
        CipherSuiteId::Tls_Psk_With_Aes_128_Gcm_Sha256 => {
            Ok(Box::<CipherSuiteTlsPskWithAes128GcmSha256>::default())
        }
        CipherSuiteId::Tls_Ecdhe_Rsa_With_ChaCha20_Poly1305_Sha256 => {
            Ok(Box::new(CipherSuiteChaCha20Poly1305Sha256::new(true)))
        }
        CipherSuiteId::Tls_Ecdhe_Ecdsa_With_ChaCha20_Poly1305_Sha256 => {
            Ok(Box::new(CipherSuiteChaCha20Poly1305Sha256::new(false)))
        }

        id => crate::dtls13::suite::Suite13::for_id(id)
            .map(|suite| Box::new(suite) as Box<dyn CipherSuite>)
            .ok_or(Error::ErrInvalidCipherSuite),
    }
}

// CipherSuites we support in order of preference
pub(crate) fn default_cipher_suites() -> Vec<Box<dyn CipherSuite>> {
    vec![
        Box::new(CipherSuiteAes128GcmSha256::new(false)),
        Box::new(CipherSuiteAes256CbcSha::new(false)),
        Box::new(CipherSuiteAes128GcmSha256::new(true)),
        Box::new(CipherSuiteAes256CbcSha::new(true)),
        Box::new(CipherSuiteChaCha20Poly1305Sha256::new(false)),
    ]
}

fn all_cipher_suites() -> Vec<Box<dyn CipherSuite>> {
    vec![
        Box::new(new_cipher_suite_tls_ecdhe_ecdsa_with_aes_128_ccm()),
        Box::new(new_cipher_suite_tls_ecdhe_ecdsa_with_aes_128_ccm8()),
        Box::new(CipherSuiteAes128GcmSha256::new(false)),
        Box::new(CipherSuiteAes128GcmSha256::new(true)),
        Box::new(CipherSuiteAes256CbcSha::new(false)),
        Box::new(CipherSuiteAes256CbcSha::new(true)),
        Box::new(new_cipher_suite_tls_psk_with_aes_128_ccm()),
        Box::new(new_cipher_suite_tls_psk_with_aes_128_ccm8()),
        Box::<CipherSuiteTlsPskWithAes128GcmSha256>::default(),
        Box::new(CipherSuiteChaCha20Poly1305Sha256::new(false)),
        Box::new(CipherSuiteChaCha20Poly1305Sha256::new(true)),
    ]
}

fn cipher_suites_for_ids(ids: &[CipherSuiteId]) -> Result<Vec<Box<dyn CipherSuite>>> {
    let mut cipher_suites = vec![];
    for id in ids {
        cipher_suites.push(cipher_suite_for_id(*id)?);
    }
    Ok(cipher_suites)
}

pub(crate) fn parse_cipher_suites(
    user_selected_suites: &[CipherSuiteId],
    exclude_psk: bool,
    exclude_non_psk: bool,
) -> Result<Vec<Box<dyn CipherSuite>>> {
    let cipher_suites = if !user_selected_suites.is_empty() {
        cipher_suites_for_ids(user_selected_suites)?
    } else {
        default_cipher_suites()
    };

    let filtered_cipher_suites: Vec<Box<dyn CipherSuite>> = cipher_suites
        .into_iter()
        .filter(|c| !((exclude_psk && c.is_psk()) || (exclude_non_psk && !c.is_psk())))
        .collect();

    if filtered_cipher_suites.is_empty() {
        Err(Error::ErrNoAvailableCipherSuites)
    } else {
        Ok(filtered_cipher_suites)
    }
}
