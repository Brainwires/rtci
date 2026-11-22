/// Algorithms accepted by [`crate::RTCCrypto::hash`].
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HashAlgorithm {
    /// MD5, retained only for STUN long-term credential derivation.
    Md5,
    /// SHA-256.
    Sha256,
    /// SHA-1, only to verify a certificate fingerprint a peer gives with no stronger hash
    /// (RFC 8122 section 5).
    Sha1,
    /// SHA-224 (certificate fingerprints, RFC 8122 section 5).
    Sha224,
    /// SHA-384 (certificate fingerprints, RFC 8122 section 5).
    Sha384,
    /// SHA-512 (certificate fingerprints, RFC 8122 section 5).
    Sha512,
}

impl HashAlgorithm {
    /// Returns the digest length in bytes.
    #[must_use]
    pub const fn output_len(self) -> usize {
        match self {
            Self::Md5 => 16,
            Self::Sha256 => 32,
            Self::Sha1 => 20,
            Self::Sha224 => 28,
            Self::Sha384 => 48,
            Self::Sha512 => 64,
        }
    }
}

/// Algorithms accepted by the HMAC operations.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HmacAlgorithm {
    /// HMAC-SHA1.
    Sha1,
    /// HMAC-SHA256.
    Sha256,
    /// HMAC-SHA512, for the SFrame cipher suites keyed with SHA-512 (RFC 9605 section 4.5).
    Sha512,
    /// HMAC-SHA384, for HKDF with the TLS 1.3 `_SHA384` cipher suites.
    Sha384,
}

impl HmacAlgorithm {
    /// Returns the native tag length in bytes.
    #[must_use]
    pub const fn output_len(self) -> usize {
        match self {
            Self::Sha1 => 20,
            Self::Sha256 => 32,
            Self::Sha512 => 64,
            Self::Sha384 => 48,
        }
    }
}

/// Authenticated-encryption algorithms.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AeadAlgorithm {
    /// AES-128-GCM.
    Aes128Gcm,
    /// AES-256-GCM.
    Aes256Gcm,
    /// AES-128-CCM with a 16-byte tag.
    Aes128Ccm,
    /// AES-128-CCM with an 8-byte tag.
    Aes128Ccm8,
    /// ChaCha20-Poly1305.
    ChaCha20Poly1305,
}

/// Stream-cipher algorithms.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StreamCipherAlgorithm {
    /// AES-128 in counter mode.
    Aes128Ctr,
    /// AES-256 in counter mode.
    Aes256Ctr,
    /// AES-192 in counter mode (RFC 6188 `AES_192_CM`).
    Aes192Ctr,
}

/// Single-block encryption algorithms.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BlockCipherAlgorithm {
    /// AES-128.
    Aes128,
    /// AES-256.
    Aes256,
    /// AES-192 (RFC 6188 `AES_192_CM_PRF`).
    Aes192,
}

/// The ciphers a record-number (header-protection) mask is made with: the block cipher or
/// stream cipher underneath an AEAD, keyed separately (RFC 9147 section 4.2.3; the same
/// construction as QUIC header protection, RFC 9001 section 5.4).
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HeaderMaskAlgorithm {
    /// AES-128 in ECB mode over the 16-byte sample.
    Aes128,
    /// AES-256 in ECB mode over the 16-byte sample.
    Aes256,
    /// The ChaCha20 block function, the sample giving the block counter and the nonce.
    ChaCha20,
}

impl HeaderMaskAlgorithm {
    /// Returns the key length in bytes.
    #[must_use]
    pub const fn key_len(self) -> usize {
        match self {
            Self::Aes128 => 16,
            Self::Aes256 | Self::ChaCha20 => 32,
        }
    }
}

/// CBC algorithms.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CbcAlgorithm {
    /// AES-256-CBC.
    Aes256Cbc,
}

/// Ephemeral key-agreement algorithms.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KeyExchangeAlgorithm {
    /// ECDH over NIST P-256.
    P256,
    /// ECDH over NIST P-384.
    P384,
    /// X25519.
    X25519,
    /// X25519MLKEM768 (draft-ietf-tls-ecdhe-mlkem, code point 0x11EC): ML-KEM-768 and
    /// X25519 side by side. Not a Diffie-Hellman exchange: the initiator's share is an
    /// ML-KEM encapsulation key followed by an X25519 public key (1216 bytes), the
    /// responder's an ML-KEM ciphertext followed by an X25519 public key (1120 bytes), and
    /// the shared secret the ML-KEM secret followed by the X25519 one (64 bytes). A
    /// responder goes through [`RTCCrypto::key_exchange_respond`](crate::RTCCrypto::key_exchange_respond).
    X25519MlKem768,
}

/// Signature schemes currently used by DTLS.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SignatureScheme {
    /// Ed25519.
    Ed25519,
    /// ECDSA P-256 with SHA-256 and ASN.1 DER signatures.
    EcdsaP256Sha256,
    /// ECDSA P-384 with SHA-384 and ASN.1 DER signatures.
    EcdsaP384Sha384,
    /// RSA PKCS#1 v1.5 with SHA-1, for legacy verification only.
    RsaPkcs1Sha1,
    /// RSA PKCS#1 v1.5 with SHA-256.
    RsaPkcs1Sha256,
    /// RSA PKCS#1 v1.5 with SHA-384.
    RsaPkcs1Sha384,
    /// RSA PKCS#1 v1.5 with SHA-512.
    RsaPkcs1Sha512,
    /// ECDSA P-384 with SHA-256 and ASN.1 DER signatures.
    EcdsaP384Sha256,
    /// RSASSA-PSS with SHA-256, MGF1 with SHA-256 and a salt as long as the digest, over a
    /// key with the rsaEncryption OID (TLS 1.3 `rsa_pss_rsae_sha256`, RFC 8446 section 4.2.3).
    RsaPssSha256,
    /// RSASSA-PSS with SHA-384 (TLS 1.3 `rsa_pss_rsae_sha384`).
    RsaPssSha384,
    /// RSASSA-PSS with SHA-512 (TLS 1.3 `rsa_pss_rsae_sha512`).
    RsaPssSha512,
}

/// The encoding of public-key bytes.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PublicKeyEncoding {
    /// Complete DER-encoded SubjectPublicKeyInfo.
    SubjectPublicKeyInfoDer,
    /// SEC1 uncompressed elliptic-curve point.
    EcUncompressedPoint,
    /// Raw 32-byte Ed25519 public key.
    Ed25519Raw,
    /// PKCS#1 DER `RSAPublicKey`.
    RsaPkcs1Der,
}

/// Borrowed public-key bytes with an explicit encoding.
#[derive(Debug, Clone, Copy)]
pub struct PublicKey<'a> {
    /// Encoding of `bytes`.
    pub encoding: PublicKeyEncoding,
    /// Encoded public key.
    pub bytes: &'a [u8],
}

/// A provider capability identifier.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CryptoAlgorithm {
    /// Stateless hash operation.
    Hash(HashAlgorithm),
    /// HMAC generation and verification.
    Hmac(HmacAlgorithm),
    /// Authenticated encryption.
    Aead(AeadAlgorithm),
    /// Stream encryption.
    StreamCipher(StreamCipherAlgorithm),
    /// Single-block encryption.
    BlockCipher(BlockCipherAlgorithm),
    /// Record-number (header-protection) masks.
    HeaderMask(HeaderMaskAlgorithm),
    /// CBC encryption and decryption.
    Cbc(CbcAlgorithm),
    /// Ephemeral key agreement.
    KeyExchange(KeyExchangeAlgorithm),
    /// Signature verification.
    Signature(SignatureScheme),
    /// Signing-key generation.
    SigningKeyGeneration(SignatureScheme),
    /// PKCS#8 signing-key import.
    SigningKeyImport(SignatureScheme),
}
