//! The sender-keys scheme of RFC 9605 section 5.1: each sender distributes its own `base_key`
//! over an end-to-end secure channel, and ratchets it forward for forward secrecy.

use std::collections::VecDeque;
use std::sync::Arc;

use crypto::{RTCCryptoProvider, SecretVec};

use crate::cipher_suite::CipherSuite;
use crate::context::{KeyContext, SFrameConfig, SFrameContext};
use crate::error::{Error, Result};
use crate::header::Header;
use crate::kdf::ratchet_base_key;
use crate::key_id::SenderKeyIdLayout;

/// How many ratchet steps a [`SenderKeyReceiver`] follows for one ciphertext unless told
/// otherwise.
pub const DEFAULT_MAX_RATCHET_STEPS: u64 = 8;

/// How many keys older than the current one a [`SenderKeyReceiver`] keeps unless told
/// otherwise.
pub const DEFAULT_RETAINED_OLD_KEYS: usize = 2;

/// One sender's key at a point of its ratchet: the key generation, the ratchet step and the
/// `base_key` there.
///
/// The sender holds one and [`advance`](Self::advance)s it, installing each new `base_key`
/// under the new KID as its encryption key and removing the previous one. A receiver gets the
/// sender's current `base_key` and KID over the secure channel and follows with a
/// [`SenderKeyReceiver`].
pub struct SenderKeyRatchet {
    suite: CipherSuite,
    provider: Arc<dyn RTCCryptoProvider>,
    layout: SenderKeyIdLayout,
    key_generation: u64,
    ratchet_step: u64,
    base_key: SecretVec,
}

impl SenderKeyRatchet {
    /// A freshly distributed key: generation `key_generation`, ratchet step 0.
    pub fn new(
        suite: CipherSuite,
        provider: Arc<dyn RTCCryptoProvider>,
        layout: SenderKeyIdLayout,
        key_generation: u64,
        base_key: &[u8],
    ) -> Result<Self> {
        let kid = layout.key_id(key_generation, 0)?;
        Self::at_key_id(suite, provider, layout, kid, base_key)
    }

    /// The key a sender is at when it uses `kid`, as a participant joining mid-session learns
    /// it: the sender's current `base_key` together with its current KID.
    ///
    /// The KID carries only the low bits of the ratchet step; they are all a receiver needs to
    /// follow.
    pub fn at_key_id(
        suite: CipherSuite,
        provider: Arc<dyn RTCCryptoProvider>,
        layout: SenderKeyIdLayout,
        kid: u64,
        base_key: &[u8],
    ) -> Result<Self> {
        if base_key.is_empty() {
            return Err(Error::EmptyBaseKey);
        }
        let parts = layout.split(kid);
        Ok(Self {
            suite,
            provider,
            layout,
            key_generation: parts.key_generation,
            ratchet_step: parts.ratchet_step,
            base_key: SecretVec::new(base_key.to_vec()),
        })
    }

    /// The KID layout.
    #[must_use]
    pub fn layout(&self) -> SenderKeyIdLayout {
        self.layout
    }

    /// The key generation.
    #[must_use]
    pub fn key_generation(&self) -> u64 {
        self.key_generation
    }

    /// The ratchet step. After [`at_key_id`](Self::at_key_id) it counts from the low bits the
    /// KID carried.
    #[must_use]
    pub fn ratchet_step(&self) -> u64 {
        self.ratchet_step
    }

    /// The KID of the current key.
    #[must_use]
    pub fn key_id(&self) -> u64 {
        // The generation came out of a KID of this layout, so it fits its field.
        self.layout.compose(self.key_generation, self.ratchet_step)
    }

    /// The current `base_key`: what goes into the SFrame context under
    /// [`key_id`](Self::key_id), and what a new participant is sent.
    #[must_use]
    pub fn base_key(&self) -> &[u8] {
        self.base_key.as_ref()
    }

    /// Ratchets one step forward and returns the new KID. The previous `base_key` is erased.
    pub fn advance(&mut self) -> Result<u64> {
        let Some(next_step) = self.ratchet_step.checked_add(1) else {
            return Err(Error::RatchetExhausted);
        };
        self.base_key =
            ratchet_base_key(self.provider.crypto(), self.suite, self.base_key.as_ref())?;
        self.ratchet_step = next_step;
        Ok(self.key_id())
    }

    /// How many steps forward `kid` is from the current key, or `None` when it belongs to
    /// another key generation (the sender distributed, or will distribute, a new key).
    ///
    /// The count is modulo `1 << R`: a KID from before the current step reads as far ahead. A
    /// receiver therefore keeps its recent keys installed and bounds how far it follows.
    #[must_use]
    pub fn steps_to(&self, kid: u64) -> Option<u64> {
        let parts = self.layout.split(kid);
        (parts.key_generation == self.key_generation).then(|| {
            self.layout
                .steps_between(self.ratchet_step, parts.ratchet_step)
        })
    }
}

impl std::fmt::Debug for SenderKeyRatchet {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SenderKeyRatchet")
            .field("suite", &self.suite)
            .field("layout", &self.layout)
            .field("key_generation", &self.key_generation)
            .field("ratchet_step", &self.ratchet_step)
            .finish_non_exhaustive()
    }
}

/// The receiving side of one sender in the sender-keys scheme.
///
/// It decrypts with the keys it holds, and when the sender signals a ratchet step by a KID with
/// a higher step, derives the keys up to it. The KID is not authenticated until a key has been
/// derived from it, so the ratchet moves only once a ciphertext has authenticated under the new
/// key: a forged KID costs a bounded number of derivations and changes nothing.
///
/// Old keys stay for out-of-order delivery, a bounded number of them; an application that
/// wants them gone sooner calls [`forget_old_keys`](Self::forget_old_keys).
pub struct SenderKeyReceiver {
    context: SFrameContext,
    layout: SenderKeyIdLayout,
    ratchet: Option<SenderKeyRatchet>,
    /// The KIDs installed, oldest first; the last one is the current key's.
    installed: VecDeque<u64>,
    max_ratchet_steps: u64,
    retained_old_keys: usize,
}

impl SenderKeyReceiver {
    /// A receiver for one sender whose KIDs follow `layout`, with no key yet.
    #[must_use]
    pub fn new(
        suite: CipherSuite,
        provider: Arc<dyn RTCCryptoProvider>,
        layout: SenderKeyIdLayout,
    ) -> Self {
        Self::with_config(suite, provider, layout, SFrameConfig::default())
    }

    /// [`new`](Self::new) with explicit options for the underlying [`SFrameContext`].
    #[must_use]
    pub fn with_config(
        suite: CipherSuite,
        provider: Arc<dyn RTCCryptoProvider>,
        layout: SenderKeyIdLayout,
        config: SFrameConfig,
    ) -> Self {
        Self {
            context: SFrameContext::with_config(suite, provider, config),
            layout,
            ratchet: None,
            installed: VecDeque::new(),
            max_ratchet_steps: DEFAULT_MAX_RATCHET_STEPS,
            retained_old_keys: DEFAULT_RETAINED_OLD_KEYS,
        }
    }

    /// Sets how many ratchet steps one ciphertext may make the receiver follow. A KID further
    /// ahead is treated as unknown.
    pub fn set_max_ratchet_steps(&mut self, steps: u64) {
        self.max_ratchet_steps = steps;
    }

    /// Sets how many keys older than the current one are kept for late ciphertexts.
    pub fn set_retained_old_keys(&mut self, keys: usize) {
        self.retained_old_keys = keys;
        self.prune();
    }

    /// The underlying context: its cipher suite, statistics and stored keys.
    #[must_use]
    pub fn context(&self) -> &SFrameContext {
        &self.context
    }

    /// The KID of the newest key held, if any.
    #[must_use]
    pub fn current_key_id(&self) -> Option<u64> {
        self.ratchet.as_ref().map(SenderKeyRatchet::key_id)
    }

    /// Installs the `base_key` the sender distributed, for the KID it is used under: the first
    /// key, a new key generation, or the current key of a session joined midway.
    pub fn set_key(&mut self, kid: u64, base_key: &[u8]) -> Result<()> {
        let ratchet = SenderKeyRatchet::at_key_id(
            self.context.cipher_suite(),
            self.context.provider().clone(),
            self.layout,
            kid,
            base_key,
        )?;
        self.context.add_recv_key(kid, base_key)?;
        self.ratchet = Some(ratchet);
        self.note_installed(kid);
        Ok(())
    }

    /// Removes every key but the current one.
    pub fn forget_old_keys(&mut self) {
        while self.installed.len() > 1 {
            if let Some(kid) = self.installed.pop_front() {
                self.context.remove_key(kid);
            }
        }
    }

    fn note_installed(&mut self, kid: u64) {
        self.installed.retain(|installed| *installed != kid);
        self.installed.push_back(kid);
        self.prune();
    }

    fn prune(&mut self) {
        while self.installed.len() > self.retained_old_keys.saturating_add(1) {
            if let Some(kid) = self.installed.pop_front() {
                self.context.remove_key(kid);
            }
        }
    }

    /// Decrypts an SFrame ciphertext from this sender and returns the plaintext.
    pub fn decrypt(&mut self, metadata: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
        let mut out = Vec::with_capacity(ciphertext.len());
        self.decrypt_into(metadata, ciphertext, &mut out)?;
        Ok(out)
    }

    /// [`decrypt`](Self::decrypt), appending the plaintext to `out`. On an error `out` is as it
    /// was.
    pub fn decrypt_into(
        &mut self,
        metadata: &[u8],
        ciphertext: &[u8],
        out: &mut Vec<u8>,
    ) -> Result<Header> {
        let result = self.decrypt_uncounted(metadata, ciphertext, out);
        self.context.count(&result);
        result
    }

    fn decrypt_uncounted(
        &mut self,
        metadata: &[u8],
        ciphertext: &[u8],
        out: &mut Vec<u8>,
    ) -> Result<Header> {
        let (header, _) = self.context.decode_header(ciphertext)?;
        if self.context.key_usage(header.kid).is_some() {
            let result = self.context.decrypt_uncounted(metadata, ciphertext, out);
            // KIDs repeat every `1 << R` steps: a key that fails to authenticate may be an old
            // one whose KID the sender has come round to again.
            if result != Err(Error::AuthenticationFailed) || !self.is_ahead(header.kid) {
                return result;
            }
        }
        self.decrypt_ratcheting(metadata, ciphertext, out)
    }

    /// Whether `kid` is a step the receiver would follow the ratchet to.
    fn is_ahead(&self, kid: u64) -> bool {
        self.ratchet
            .as_ref()
            .and_then(|ratchet| ratchet.steps_to(kid))
            .is_some_and(|steps| (1..=self.max_ratchet_steps).contains(&steps))
    }

    /// Decrypts a ciphertext whose KID is ahead of the current key, and moves the ratchet there
    /// if it authenticated.
    fn decrypt_ratcheting(
        &mut self,
        metadata: &[u8],
        ciphertext: &[u8],
        out: &mut Vec<u8>,
    ) -> Result<Header> {
        let (header, header_len) = self.context.decode_header(ciphertext)?;
        let unknown = Error::UnknownKeyId(header.kid);
        if !self.is_ahead(header.kid) {
            return Err(unknown);
        }
        let Some(ratchet) = &self.ratchet else {
            return Err(unknown);
        };
        let Some(steps) = ratchet.steps_to(header.kid) else {
            return Err(unknown);
        };

        // Derive ahead on a copy: the ratchet itself moves only on success.
        let mut ahead = SenderKeyRatchet::at_key_id(
            ratchet.suite,
            ratchet.provider.clone(),
            ratchet.layout,
            ratchet.key_id(),
            ratchet.base_key(),
        )?;
        let mut passed: Vec<(u64, SecretVec)> = Vec::new();
        for step in 1..=steps {
            let kid = ahead.advance()?;
            if step < steps {
                passed.push((kid, SecretVec::new(ahead.base_key().to_vec())));
            }
        }
        if ahead.key_id() != header.kid {
            return Err(unknown);
        }

        let mut key = KeyContext::derive_recv(
            self.context.provider().crypto(),
            self.context.cipher_suite(),
            header.kid,
            ahead.base_key(),
            self.context.config().replay_window,
        )?;
        self.context
            .decrypt_with(&mut key, header, header_len, metadata, ciphertext, out)?;

        // Authentic: the sender is at this step. Keep the keys of the steps passed over too,
        // for ciphertexts of theirs still on the way. The plaintext is already in `out`, so a
        // key that cannot be installed is left out rather than reported.
        for (kid, base_key) in passed {
            if self.context.add_recv_key(kid, base_key.as_ref()).is_ok() {
                self.note_installed(kid);
            }
        }
        self.context.insert_key(header.kid, key);
        self.note_installed(header.kid);
        self.ratchet = Some(ahead);
        Ok(header)
    }
}

impl std::fmt::Debug for SenderKeyReceiver {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SenderKeyReceiver")
            .field("context", &self.context)
            .field("layout", &self.layout)
            .field("ratchet", &self.ratchet)
            .finish_non_exhaustive()
    }
}
