use std::sync::Arc;

use crate::{
    AeadAlgorithm, BlockCipherAlgorithm, CbcAlgorithm, CryptoAlgorithm, CryptoError, HashAlgorithm,
    HeaderMaskAlgorithm, HmacAlgorithm, KeyExchangeAlgorithm, PublicKey, SecretVec,
    SignatureScheme, StreamCipherAlgorithm,
};

/// A bundle of cryptographic operations and cryptographically secure randomness.
pub trait RTCCryptoProvider: Send + Sync {
    /// Returns a non-secret diagnostic name.
    fn name(&self) -> &'static str;

    /// Returns the cryptographic operations implementation.
    fn crypto(&self) -> &dyn RTCCrypto;

    /// Returns the cryptographically secure random source.
    fn random(&self) -> &dyn RTCRandom;
}

/// A cryptographically secure random byte generator.
pub trait RTCRandom: Send + Sync {
    /// Fills all of `output` with random bytes.
    fn fill(&self, output: &mut [u8]) -> Result<(), CryptoError>;

    /// Fills all of `output` with random bytes that become a secret key (a cookie secret, a
    /// ticket key), from a source that keeps no copy of them.
    ///
    /// A generator that buffers its output (as the built-in providers' [`fill`](Self::fill)
    /// does, for speed) keeps the bytes it handed out in its buffer until it makes the next
    /// block: whatever key was drawn from it stays in memory after the key itself is erased.
    /// The default calls `fill`; the built-in providers draw from the operating system, which
    /// writes into `output` only.
    fn fill_secret(&self, output: &mut [u8]) -> Result<(), CryptoError> {
        self.fill(output)
    }
}

/// Provider-neutral cryptographic operations.
pub trait RTCCrypto: Send + Sync {
    /// Reports whether an operation is implemented.
    fn supports(&self, algorithm: CryptoAlgorithm) -> bool;

    /// Hashes `data`.
    fn hash(&self, algorithm: HashAlgorithm, _data: &[u8]) -> Result<Vec<u8>, CryptoError> {
        Err(CryptoError::UnsupportedAlgorithm(CryptoAlgorithm::Hash(
            algorithm,
        )))
    }

    /// Encrypts exactly one block in place.
    fn block_encrypt(
        &self,
        algorithm: BlockCipherAlgorithm,
        _key: &[u8],
        _block: &mut [u8],
    ) -> Result<(), CryptoError> {
        Err(CryptoError::UnsupportedAlgorithm(
            CryptoAlgorithm::BlockCipher(algorithm),
        ))
    }

    /// Creates a keyed MAC.
    ///
    /// This is the only HMAC entry point. Deriving the key schedule is the expensive part, so it
    /// happens here rather than per message; a caller that authenticates many messages with one
    /// key holds the returned [`Mac`]. One-shot callers simply drop it after a single `sign` or
    /// `verify`.
    fn new_hmac(&self, algorithm: HmacAlgorithm, _key: &[u8]) -> Result<Box<dyn Mac>, CryptoError> {
        Err(CryptoError::UnsupportedAlgorithm(CryptoAlgorithm::Hmac(
            algorithm,
        )))
    }

    /// Creates a keyed stream cipher.
    fn new_stream_cipher(
        &self,
        algorithm: StreamCipherAlgorithm,
        _key: &[u8],
    ) -> Result<Box<dyn StreamCipher>, CryptoError> {
        Err(CryptoError::UnsupportedAlgorithm(
            CryptoAlgorithm::StreamCipher(algorithm),
        ))
    }

    /// Creates a keyed AEAD cipher.
    fn new_aead(
        &self,
        algorithm: AeadAlgorithm,
        _key: &[u8],
    ) -> Result<Box<dyn AeadCipher>, CryptoError> {
        Err(CryptoError::UnsupportedAlgorithm(CryptoAlgorithm::Aead(
            algorithm,
        )))
    }

    /// Creates a keyed record-number mask generator (RFC 9147 section 4.2.3).
    fn new_header_mask(
        &self,
        algorithm: HeaderMaskAlgorithm,
        _key: &[u8],
    ) -> Result<Box<dyn HeaderMask>, CryptoError> {
        Err(CryptoError::UnsupportedAlgorithm(
            CryptoAlgorithm::HeaderMask(algorithm),
        ))
    }

    /// Creates a keyed CBC cipher.
    fn new_cbc(
        &self,
        algorithm: CbcAlgorithm,
        _key: &[u8],
    ) -> Result<Box<dyn CbcCipher>, CryptoError> {
        Err(CryptoError::UnsupportedAlgorithm(CryptoAlgorithm::Cbc(
            algorithm,
        )))
    }

    /// Starts a one-shot ephemeral key exchange.
    fn start_key_exchange(
        &self,
        algorithm: KeyExchangeAlgorithm,
    ) -> Result<Box<dyn ActiveKeyExchange>, CryptoError> {
        Err(CryptoError::UnsupportedAlgorithm(
            CryptoAlgorithm::KeyExchange(algorithm),
        ))
    }

    /// Answers a key exchange the peer started: makes this side's share for `peer_share`
    /// and the shared secret. For the Diffie-Hellman groups that is a key pair and an
    /// agreement, which is what the default does; a KEM-based group (X25519MLKEM768)
    /// encapsulates to the peer's key instead, and its provider overrides this.
    fn key_exchange_respond(
        &self,
        algorithm: KeyExchangeAlgorithm,
        peer_share: &[u8],
    ) -> Result<(Vec<u8>, SecretVec), CryptoError> {
        let exchange = self.start_key_exchange(algorithm)?;
        let share = exchange.public_key().to_vec();
        let secret = exchange.complete(peer_share)?;
        Ok((share, secret))
    }

    /// Generates an exportable signing key.
    fn generate_signing_key(
        &self,
        scheme: SignatureScheme,
    ) -> Result<Arc<dyn SigningKey>, CryptoError> {
        Err(CryptoError::UnsupportedAlgorithm(
            CryptoAlgorithm::SigningKeyGeneration(scheme),
        ))
    }

    /// Imports an exportable PKCS#8 signing key.
    fn import_signing_key(
        &self,
        scheme: SignatureScheme,
        _pkcs8_der: &[u8],
    ) -> Result<Arc<dyn SigningKey>, CryptoError> {
        Err(CryptoError::UnsupportedAlgorithm(
            CryptoAlgorithm::SigningKeyImport(scheme),
        ))
    }

    /// Verifies a signature.
    fn verify_signature(
        &self,
        scheme: SignatureScheme,
        _public_key: PublicKey<'_>,
        _message: &[u8],
        _signature: &[u8],
    ) -> Result<(), CryptoError> {
        Err(CryptoError::UnsupportedAlgorithm(
            CryptoAlgorithm::Signature(scheme),
        ))
    }
}

/// A keyed message authentication code with a reusable key schedule.
///
/// Created once per key by [`RTCCrypto::new_hmac`] and used for every message authenticated with
/// that key, so the ipad/opad derivation is paid once rather than per packet.
///
/// `Send` and mutable, like the keyed cipher traits, and for the same reason: `&mut self` lets an
/// implementation carry per-message state — a reused streaming context, a hardware session
/// handle — without interior mutability, and does not impose `Sync` on implementors that cannot
/// offer it. A caller whose own signature is fixed to `&self`, such as STUN's `Setter::add_to`,
/// can still create a local `Mac` per message and use it mutably.
pub trait Mac: Send {
    /// Returns the untruncated tag length in bytes.
    fn output_len(&self) -> usize;

    /// Writes the tag over the concatenation of `input` into `output`.
    ///
    /// `output` must be exactly [`output_len`](Self::output_len) bytes. Protocols that transmit a
    /// truncated tag — SRTP sends 80 or 32 bits of an SHA-1 tag — truncate the result themselves.
    fn sign(&mut self, input: &[&[u8]], output: &mut [u8]) -> Result<(), CryptoError>;

    /// Verifies a complete untruncated tag in constant time.
    fn verify(&mut self, input: &[&[u8]], expected: &[u8]) -> Result<(), CryptoError>;
}

/// A keyed stream cipher with a reusable expanded key.
pub trait StreamCipher: Send {
    /// Applies the keystream in place with a fresh IV.
    fn apply_keystream(&mut self, iv: &[u8], data: &mut [u8]) -> Result<(), CryptoError>;
}

/// A keyed authenticated cipher with detached tags.
pub trait AeadCipher: Send {
    /// Returns the detached tag length in bytes.
    fn tag_len(&self) -> usize;

    /// Encrypts and authenticates a caller-owned buffer.
    fn seal_in_place(
        &mut self,
        nonce: &[u8],
        aad: &[u8],
        plaintext_and_ciphertext: &mut [u8],
        tag_out: &mut [u8],
    ) -> Result<(), CryptoError>;

    /// Authenticates and decrypts a caller-owned buffer.
    fn open_in_place(
        &mut self,
        nonce: &[u8],
        aad: &[u8],
        ciphertext_and_plaintext: &mut [u8],
        tag: &[u8],
    ) -> Result<(), CryptoError>;
}

/// The length of the ciphertext sample a [`HeaderMask`] is computed from.
pub const HEADER_MASK_SAMPLE_LEN: usize = 16;
/// The length of the mask a [`HeaderMask`] returns.
pub const HEADER_MASK_LEN: usize = 5;

/// A keyed generator of record-number masks.
///
/// DTLS 1.3 encrypts the sequence number of a protected record by XORing it with the leading
/// bytes of a mask computed from the first 16 bytes of the record's ciphertext (RFC 9147
/// section 4.2.3): AES-ECB of the sample for the AES suites, and for ChaCha20 the keystream
/// the block function gives with the sample's first four bytes as the block counter and the
/// other twelve as the nonce. QUIC header protection (RFC 9001 section 5.4) is the same
/// computation, which is why five bytes come back; DTLS uses one or two of them.
pub trait HeaderMask: Send {
    /// Computes the mask for `sample`.
    fn mask(
        &mut self,
        sample: &[u8; HEADER_MASK_SAMPLE_LEN],
    ) -> Result<[u8; HEADER_MASK_LEN], CryptoError>;
}

/// A keyed CBC block cipher with a reusable expanded key.
pub trait CbcCipher: Send {
    /// Returns the block and IV length in bytes.
    fn block_len(&self) -> usize;

    /// Encrypts whole blocks in place without applying padding.
    fn encrypt_blocks(&mut self, iv: &[u8], blocks: &mut [u8]) -> Result<(), CryptoError>;

    /// Decrypts whole blocks in place without removing padding.
    fn decrypt_blocks(&mut self, iv: &[u8], blocks: &mut [u8]) -> Result<(), CryptoError>;
}

/// Provider-owned one-shot ephemeral key exchange.
pub trait ActiveKeyExchange: Send {
    /// Returns the key-exchange algorithm.
    fn algorithm(&self) -> KeyExchangeAlgorithm;

    /// Returns the encoded wire public key.
    fn public_key(&self) -> &[u8];

    /// Consumes the private key and derives the shared secret.
    fn complete(self: Box<Self>, peer_public_key: &[u8]) -> Result<SecretVec, CryptoError>;
}

/// A provider-owned signing key, including external or non-exportable keys.
pub trait SigningKey: Send + Sync {
    /// Reports whether this key can sign with `scheme`.
    fn supports(&self, scheme: SignatureScheme) -> bool;

    /// Returns the public key with explicit encoding.
    fn public_key(&self) -> PublicKey<'_>;

    /// Signs `message`.
    fn sign(&self, scheme: SignatureScheme, message: &[u8]) -> Result<Vec<u8>, CryptoError>;

    /// Exports PKCS#8 when supported. `Ok(None)` means the key is non-exportable.
    fn to_pkcs8_der(&self) -> Result<Option<SecretVec>, CryptoError> {
        Ok(None)
    }
}
