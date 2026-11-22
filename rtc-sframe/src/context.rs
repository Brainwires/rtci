//! The SFrame context: a key store with a role per key, and the encryption and decryption of
//! RFC 9605 sections 4.4.3 and 4.4.4.

use std::collections::HashMap;
use std::sync::Arc;

use crypto::{RTCCrypto, RTCCryptoProvider, constant_time_eq};
use zeroize::{Zeroize, Zeroizing};

use crate::aead::SuiteAead;
use crate::cipher_suite::{CipherSuite, NONCE_LEN};
use crate::error::{Error, Result};
use crate::header::{Header, MAX_HEADER_LEN};
use crate::kdf::derive_key_salt;
use crate::replay::{DEFAULT_REPLAY_WINDOW, ReplayWindow};

/// What a stored key may be used for. A key has one role for as long as it is stored
/// (RFC 9605 section 4.4.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KeyUsage {
    /// The key encrypts; this endpoint is its one sender.
    Encrypt,
    /// The key decrypts what another sender encrypted.
    Decrypt,
}

/// Options of an [`SFrameContext`].
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SFrameConfig {
    /// The anti-replay window of each decryption key, in counter values, or `None` for no
    /// replay protection (RFC 9605 section 9.3 leaves it to the receiver). With a window, an
    /// authentic ciphertext is accepted once per counter, and refused when its counter is older
    /// than the window. Rounded up to a multiple of 64, at most
    /// [`MAX_REPLAY_WINDOW`](crate::MAX_REPLAY_WINDOW). It applies to keys added afterwards.
    ///
    /// Default: [`DEFAULT_REPLAY_WINDOW`].
    pub replay_window: Option<usize>,
    /// Accept a header whose KID or CTR is longer than it needs to be. RFC 9605 section 4.3
    /// requires the shortest form of a sender; this admits senders that do not follow it.
    ///
    /// Default: `false`.
    pub allow_non_minimal_headers: bool,
}

impl Default for SFrameConfig {
    fn default() -> Self {
        Self {
            replay_window: Some(DEFAULT_REPLAY_WINDOW),
            allow_non_minimal_headers: false,
        }
    }
}

/// Counts of what a context has done, for an application that watches for the brute-force
/// signal of RFC 9605 section 7.5 (an elevated rate of failures against a short tag).
#[non_exhaustive]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SFrameStats {
    /// Plaintexts encrypted.
    pub encrypted: u64,
    /// Ciphertexts decrypted and released.
    pub decrypted: u64,
    /// Ciphertexts refused because the header or the length is malformed.
    pub syntax_errors: u64,
    /// Ciphertexts refused because no decryption key is stored for their KID.
    pub unknown_key_ids: u64,
    /// Ciphertexts refused because the authentication tag did not validate.
    pub authentication_failures: u64,
    /// Authentic ciphertexts refused as replays.
    pub replays: u64,
}

/// The base key of the decoy: any fixed bytes do, nothing is ever encrypted with it.
const DECOY_BASE_KEY: &[u8] = b"rtc-sframe decoy";

enum Role {
    /// The next CTR to encrypt with; `None` once the last one (2^64 - 1) has been used.
    Send {
        next_ctr: Option<u64>,
    },
    Recv {
        replay: Option<ReplayWindow>,
    },
}

/// A parsed SFrame ciphertext and the metadata it is to be decrypted with.
pub(crate) struct Frame<'a> {
    header: Header,
    /// The header as it was received: it is authenticated byte for byte.
    encoded_header: &'a [u8],
    /// What follows the header: the encrypted data, then the tag.
    body: &'a [u8],
    metadata: &'a [u8],
}

impl<'a> Frame<'a> {
    /// `ciphertext` divided after its `header_len`-byte header.
    fn new(header: Header, header_len: usize, ciphertext: &'a [u8], metadata: &'a [u8]) -> Self {
        let (encoded_header, body) = ciphertext.split_at(header_len);
        Self {
            header,
            encoded_header,
            body,
            metadata,
        }
    }
}

/// One stored key: the keyed AEAD, the salt, and what the role needs.
pub(crate) struct KeyContext {
    aead: SuiteAead,
    salt: Zeroizing<[u8; NONCE_LEN]>,
    role: Role,
}

impl KeyContext {
    fn derive(
        crypto: &dyn RTCCrypto,
        suite: CipherSuite,
        kid: u64,
        base_key: &[u8],
        role: Role,
    ) -> Result<Self> {
        let derived = derive_key_salt(crypto, suite, kid, base_key)?;
        Ok(Self {
            aead: SuiteAead::new(crypto, suite, &derived.key)?,
            salt: derived.salt,
            role,
        })
    }

    /// A decryption key for `kid`, not stored anywhere yet.
    pub(crate) fn derive_recv(
        crypto: &dyn RTCCrypto,
        suite: CipherSuite,
        kid: u64,
        base_key: &[u8],
        replay_window: Option<usize>,
    ) -> Result<Self> {
        let replay = replay_window.map(ReplayWindow::new);
        Self::derive(crypto, suite, kid, base_key, Role::Recv { replay })
    }

    /// The nonce of RFC 9605 section 4.4.3: the salt XOR the CTR as an `Nn`-byte big-endian
    /// integer.
    fn nonce(&self, ctr: u64) -> Zeroizing<[u8; NONCE_LEN]> {
        let mut nonce = Zeroizing::new(*self.salt);
        for (byte, ctr_byte) in nonce[NONCE_LEN - 8..].iter_mut().zip(ctr.to_be_bytes()) {
            *byte ^= ctr_byte;
        }
        nonce
    }

    fn usage(&self) -> KeyUsage {
        match self.role {
            Role::Send { .. } => KeyUsage::Encrypt,
            Role::Recv { .. } => KeyUsage::Decrypt,
        }
    }

    /// Decrypts one ciphertext with this key, appending the plaintext to `out`.
    ///
    /// On any error `out` is as it was, and the bytes written meanwhile are erased.
    pub(crate) fn open(
        &mut self,
        suite: CipherSuite,
        frame: Frame<'_>,
        scratch: &mut Vec<u8>,
        out: &mut Vec<u8>,
    ) -> Result<()> {
        let Frame {
            header,
            encoded_header,
            body,
            metadata,
        } = frame;
        let nonce = self.nonce(header.ctr);
        let Role::Recv { replay } = &mut self.role else {
            return Err(Error::KeyRoleConflict(header.kid));
        };
        let Some(data_len) = body.len().checked_sub(suite.tag_len()) else {
            return Err(Error::TruncatedCiphertext);
        };
        let (data, tag) = body.split_at(data_len);

        let start = out.len();
        out.extend_from_slice(data);
        let mut result = self.aead.open(
            &nonce,
            encoded_header,
            metadata,
            scratch,
            &mut out[start..],
            tag,
        );
        // The replay check comes after authentication: only an authentic ciphertext can be a
        // replay, and a replayed one costs what a fresh one does.
        if result.is_ok()
            && let Some(window) = replay
        {
            if window.is_fresh(header.ctr) {
                window.accept(header.ctr);
            } else {
                result = Err(Error::Replayed {
                    kid: header.kid,
                    ctr: header.ctr,
                });
            }
        }
        if result.is_err() {
            out[start..].zeroize();
            out.truncate(start);
        }
        result
    }
}

/// An SFrame context (RFC 9605 Appendix A): one cipher suite, and the keys known for each KID.
///
/// A key is added for sending or for receiving and keeps that role. Encryption takes the KID to
/// use and draws the CTR from the key's own counter, so a (key, nonce) pair is never used
/// twice; decryption finds the key by the KID in the SFrame header.
///
/// ```
/// use rtc_sframe::{CipherSuite, SFrameContext};
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let suite = CipherSuite::Aes128GcmSha256_128;
/// let base_key = [0x2a; 16]; // from the application's key management
///
/// let mut sender = SFrameContext::with_default_provider(suite)?;
/// sender.add_send_key(7, &base_key)?;
/// let mut receiver = SFrameContext::with_default_provider(suite)?;
/// receiver.add_recv_key(7, &base_key)?;
///
/// let metadata = b"what the application authenticates but sends elsewhere";
/// let ciphertext = sender.encrypt(7, metadata, b"an encoded frame")?;
/// assert_eq!(receiver.decrypt(metadata, &ciphertext)?, b"an encoded frame");
/// # Ok(())
/// # }
/// ```
pub struct SFrameContext {
    suite: CipherSuite,
    provider: Arc<dyn RTCCryptoProvider>,
    config: SFrameConfig,
    keys: HashMap<u64, KeyContext>,
    /// A decryption key that belongs to no sender, for ciphertexts that have none: see
    /// [`decrypt_uncounted`](Self::decrypt_uncounted). Made with the first decryption key.
    decoy: Option<KeyContext>,
    /// Reused to join header and metadata for a native AEAD.
    scratch: Vec<u8>,
    stats: SFrameStats,
}

impl SFrameContext {
    /// A context for `suite` with no keys and the default [`SFrameConfig`].
    #[must_use]
    pub fn new(suite: CipherSuite, provider: Arc<dyn RTCCryptoProvider>) -> Self {
        Self::with_config(suite, provider, SFrameConfig::default())
    }

    /// A context for `suite` with no keys.
    #[must_use]
    pub fn with_config(
        suite: CipherSuite,
        provider: Arc<dyn RTCCryptoProvider>,
        config: SFrameConfig,
    ) -> Self {
        Self {
            suite,
            provider,
            config,
            keys: HashMap::new(),
            decoy: None,
            scratch: Vec::new(),
            stats: SFrameStats::default(),
        }
    }

    /// A context for `suite` on the built-in crypto provider. Fails when the crate was built
    /// without one.
    pub fn with_default_provider(suite: CipherSuite) -> Result<Self> {
        Ok(Self::new(
            suite,
            crypto::default_provider().map_err(Error::Crypto)?,
        ))
    }

    /// The context's cipher suite.
    #[must_use]
    pub fn cipher_suite(&self) -> CipherSuite {
        self.suite
    }

    /// The context's options.
    #[must_use]
    pub fn config(&self) -> &SFrameConfig {
        &self.config
    }

    /// The crypto provider the context was built with.
    #[must_use]
    pub fn provider(&self) -> &Arc<dyn RTCCryptoProvider> {
        &self.provider
    }

    /// What the context has done so far.
    #[must_use]
    pub fn stats(&self) -> SFrameStats {
        self.stats
    }

    /// The most bytes encryption adds to a plaintext: the longest header and the suite's tag.
    #[must_use]
    pub fn max_overhead(&self) -> usize {
        MAX_HEADER_LEN + self.suite.tag_len()
    }

    /// Adds `base_key` under `kid` for encryption, with its counter at 0.
    ///
    /// The caller is the key's one sender (RFC 9605 section 4.4.1). Fails with
    /// [`Error::KeyRoleConflict`] when `kid` holds a decryption key, and with
    /// [`Error::KeyReuse`] when `kid` already sends with this very key, since starting its
    /// counter again would repeat nonces. Another key under the same KID replaces the old one.
    pub fn add_send_key(&mut self, kid: u64, base_key: &[u8]) -> Result<()> {
        self.add_send_key_at(kid, base_key, 0)
    }

    /// Adds `base_key` under `kid` for encryption, with its counter at `next_ctr`.
    ///
    /// For a context restored from storage (RFC 9605 section 9.1): store
    /// [`next_counter`](Self::next_counter) before using it, and resume from the stored value,
    /// so that a failure never leads to a counter being used twice.
    pub fn add_send_key_at(&mut self, kid: u64, base_key: &[u8], next_ctr: u64) -> Result<()> {
        let role = Role::Send {
            next_ctr: Some(next_ctr),
        };
        let key = KeyContext::derive(self.provider.crypto(), self.suite, kid, base_key, role)?;
        match self.keys.get(&kid) {
            Some(existing) if existing.usage() != KeyUsage::Encrypt => {
                Err(Error::KeyRoleConflict(kid))
            }
            Some(existing) if constant_time_eq(&existing.salt[..], &key.salt[..]) => {
                Err(Error::KeyReuse(kid))
            }
            _ => {
                self.keys.insert(kid, key);
                Ok(())
            }
        }
    }

    /// Adds `base_key` under `kid` for decryption.
    ///
    /// Fails with [`Error::KeyRoleConflict`] when `kid` holds an encryption key. Adding the key
    /// `kid` already decrypts with changes nothing (its replay window is kept); another key
    /// under the same KID replaces the old one.
    pub fn add_recv_key(&mut self, kid: u64, base_key: &[u8]) -> Result<()> {
        let key = KeyContext::derive_recv(
            self.provider.crypto(),
            self.suite,
            kid,
            base_key,
            self.config.replay_window,
        )?;
        match self.keys.get(&kid) {
            Some(existing) if existing.usage() != KeyUsage::Decrypt => {
                return Err(Error::KeyRoleConflict(kid));
            }
            Some(existing) if constant_time_eq(&existing.salt[..], &key.salt[..]) => {
                return Ok(());
            }
            _ => {}
        }
        if self.decoy.is_none() {
            self.decoy = Some(KeyContext::derive_recv(
                self.provider.crypto(),
                self.suite,
                0,
                DECOY_BASE_KEY,
                None,
            )?);
        }
        self.keys.insert(kid, key);
        Ok(())
    }

    /// Stores a decryption key derived elsewhere in this crate, replacing what `kid` held.
    pub(crate) fn insert_key(&mut self, kid: u64, key: KeyContext) {
        self.keys.insert(kid, key);
    }

    /// Removes the key stored under `kid`. Returns whether there was one.
    ///
    /// A removed encryption key takes its counter with it: adding the same `base_key` under the
    /// same KID again would repeat nonces, and it is the application that must not do so
    /// (RFC 9605 section 9.1).
    pub fn remove_key(&mut self, kid: u64) -> bool {
        self.keys.remove(&kid).is_some()
    }

    /// Removes every key whose KID `keep` returns `false` for.
    pub fn retain_keys(&mut self, mut keep: impl FnMut(u64) -> bool) {
        self.keys.retain(|kid, _| keep(*kid));
    }

    /// What the key stored under `kid` is for, if there is one.
    #[must_use]
    pub fn key_usage(&self, kid: u64) -> Option<KeyUsage> {
        self.keys.get(&kid).map(KeyContext::usage)
    }

    /// The number of keys stored.
    #[must_use]
    pub fn key_count(&self) -> usize {
        self.keys.len()
    }

    /// The CTR the next encryption under `kid` will use. `None` when `kid` holds no encryption
    /// key, or one that has used every counter.
    #[must_use]
    pub fn next_counter(&self, kid: u64) -> Option<u64> {
        match self.keys.get(&kid)?.role {
            Role::Send { next_ctr } => next_ctr,
            Role::Recv { .. } => None,
        }
    }

    /// Encrypts `plaintext` with the key stored under `kid` and returns the SFrame ciphertext:
    /// header, encrypted data, authentication tag (RFC 9605 section 4.4.3).
    ///
    /// `metadata` is authenticated with the header but is not part of the output; the receiver
    /// must supply the same bytes.
    pub fn encrypt(&mut self, kid: u64, metadata: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
        let mut out = Vec::with_capacity(plaintext.len() + self.max_overhead());
        self.encrypt_into(kid, metadata, plaintext, &mut out)?;
        Ok(out)
    }

    /// [`encrypt`](Self::encrypt), appending the ciphertext to `out` so that a caller can reuse
    /// one buffer. Returns the header that was written. On an error `out` is as it was.
    ///
    /// The key's counter advances before the cipher runs, so a counter is never used twice,
    /// whatever happens. After 2^64 encryptions the key is exhausted
    /// ([`Error::CounterExhausted`]).
    pub fn encrypt_into(
        &mut self,
        kid: u64,
        metadata: &[u8],
        plaintext: &[u8],
        out: &mut Vec<u8>,
    ) -> Result<Header> {
        let Some(key) = self.keys.get_mut(&kid) else {
            return Err(Error::UnknownKeyId(kid));
        };
        let Role::Send { next_ctr } = &mut key.role else {
            return Err(Error::KeyRoleConflict(kid));
        };
        let Some(ctr) = *next_ctr else {
            return Err(Error::CounterExhausted(kid));
        };
        *next_ctr = ctr.checked_add(1);

        let header = Header::new(kid, ctr);
        let mut encoded_header = [0u8; MAX_HEADER_LEN];
        let header_len = header.encode(&mut encoded_header);
        let nonce = key.nonce(ctr);

        let start = out.len();
        out.reserve(header_len + plaintext.len() + self.suite.tag_len());
        out.extend_from_slice(&encoded_header[..header_len]);
        out.extend_from_slice(plaintext);
        out.resize(out.len() + self.suite.tag_len(), 0);
        let (data, tag) = out[start + header_len..].split_at_mut(plaintext.len());
        let sealed = key.aead.seal(
            &nonce,
            &encoded_header[..header_len],
            metadata,
            &mut self.scratch,
            data,
            tag,
        );
        if let Err(error) = sealed {
            out[start..].zeroize();
            out.truncate(start);
            return Err(error);
        }
        self.stats.encrypted = self.stats.encrypted.saturating_add(1);
        Ok(header)
    }

    /// Decrypts an SFrame ciphertext and returns the plaintext (RFC 9605 section 4.4.4).
    ///
    /// `metadata` must be the bytes the sender authenticated. Nothing of an unauthenticated
    /// ciphertext is returned. A ciphertext that fails authentication, is a replay or names a
    /// KID without a decryption key costs the cipher and MAC work of a valid one of its length,
    /// so that the outcome does not show in the time taken; only a malformed one, which has
    /// nothing to process, returns at once.
    ///
    /// The ciphertext is not consumed: when the failure is
    /// [`Error::UnknownKeyId`], the application may keep it (see
    /// [`PendingCiphertexts`](crate::PendingCiphertexts)) and decrypt again once the key has
    /// arrived. Any other failure means the ciphertext is to be discarded.
    pub fn decrypt(&mut self, metadata: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
        let mut out = Vec::with_capacity(ciphertext.len());
        self.decrypt_into(metadata, ciphertext, &mut out)?;
        Ok(out)
    }

    /// [`decrypt`](Self::decrypt), appending the plaintext to `out` so that a caller can reuse
    /// one buffer. Returns the header of the ciphertext. On an error `out` is as it was.
    pub fn decrypt_into(
        &mut self,
        metadata: &[u8],
        ciphertext: &[u8],
        out: &mut Vec<u8>,
    ) -> Result<Header> {
        let result = self.decrypt_uncounted(metadata, ciphertext, out);
        self.count(&result);
        result
    }

    /// [`decrypt_into`](Self::decrypt_into) without the statistics, for the key-management
    /// helpers that may try a second key before the outcome is known.
    pub(crate) fn decrypt_uncounted(
        &mut self,
        metadata: &[u8],
        ciphertext: &[u8],
        out: &mut Vec<u8>,
    ) -> Result<Header> {
        let (header, header_len) = self.decode_header(ciphertext)?;
        let frame = Frame::new(header, header_len, ciphertext, metadata);
        let refusal = match self.keys.get_mut(&header.kid) {
            Some(key) if key.usage() == KeyUsage::Decrypt => {
                key.open(self.suite, frame, &mut self.scratch, out)?;
                return Ok(header);
            }
            Some(_) => Error::KeyRoleConflict(header.kid),
            None => Error::UnknownKeyId(header.kid),
        };
        // No key to decrypt with. The decoy does the work a key would have done, so that this
        // ciphertext is discarded like one that fails authentication (RFC 9605 section 4.4.4).
        if let Some(decoy) = &mut self.decoy {
            let start = out.len();
            let _ = decoy.open(self.suite, frame, &mut self.scratch, out);
            out[start..].zeroize();
            out.truncate(start);
        }
        Err(refusal)
    }

    /// Parses the header of `ciphertext` as this context's configuration admits it.
    pub(crate) fn decode_header(&self, ciphertext: &[u8]) -> Result<(Header, usize)> {
        if self.config.allow_non_minimal_headers {
            Header::decode_lenient(ciphertext)
        } else {
            Header::decode(ciphertext)
        }
    }

    /// Decrypts with a key that is not in the store (yet), for the key-management helpers that
    /// derive a key on demand and keep it only once a ciphertext has authenticated with it.
    pub(crate) fn decrypt_with(
        &mut self,
        key: &mut KeyContext,
        header: Header,
        header_len: usize,
        metadata: &[u8],
        ciphertext: &[u8],
        out: &mut Vec<u8>,
    ) -> Result<()> {
        key.open(
            self.suite,
            Frame::new(header, header_len, ciphertext, metadata),
            &mut self.scratch,
            out,
        )
    }

    /// Adds the outcome of one decryption to the statistics.
    pub(crate) fn count<T>(&mut self, result: &Result<T>) {
        let counter = match result {
            Ok(_) => &mut self.stats.decrypted,
            Err(Error::TruncatedHeader | Error::NonMinimalHeader | Error::TruncatedCiphertext) => {
                &mut self.stats.syntax_errors
            }
            Err(Error::UnknownKeyId(_) | Error::KeyRoleConflict(_)) => {
                &mut self.stats.unknown_key_ids
            }
            Err(Error::AuthenticationFailed) => &mut self.stats.authentication_failures,
            Err(Error::Replayed { .. }) => &mut self.stats.replays,
            Err(_) => return,
        };
        *counter = counter.saturating_add(1);
    }
}

impl std::fmt::Debug for SFrameContext {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SFrameContext")
            .field("suite", &self.suite)
            .field("config", &self.config)
            .field("keys", &self.keys.len())
            .field("stats", &self.stats)
            .finish_non_exhaustive()
    }
}
