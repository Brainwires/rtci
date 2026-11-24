//! SFrame keyed from MLS (RFC 9605 section 5.2). No MLS here: the application runs MLS and
//! hands over each epoch's exported secret.

use std::collections::HashMap;
use std::sync::Arc;

use crypto::{RTCCryptoProvider, SecretVec, constant_time_eq};

use crate::cipher_suite::CipherSuite;
use crate::context::{KeyContext, SFrameConfig, SFrameContext};
use crate::error::{Error, Result};
use crate::header::Header;
use crate::key_id::MlsKeyIdLayout;

/// The label of the MLS exporter call that yields an epoch's SFrame `base_key`:
/// `base_key = MLS-Exporter("SFrame 1.0 Base Key", "", AEAD.Nk)`, with `AEAD.Nk` being
/// [`CipherSuite::key_len`].
pub const MLS_EXPORTER_LABEL: &str = "SFrame 1.0 Base Key";

/// The number of derived keys an [`MlsContext`] holds unless told otherwise.
pub const DEFAULT_MAX_MLS_KEYS: usize = 4096;

/// What a KID's low epoch bits currently stand for.
struct EpochSlot {
    /// The newest epoch introduced with these low bits.
    epoch: u64,
    /// Its exported secret; `None` once the epoch has been removed.
    base_key: Option<SecretVec>,
}

/// An SFrame context keyed by MLS epochs.
///
/// Every member derives its keys from the epoch's exported secret and its own KIDs
/// ([`MlsKeyIdLayout`]): the KIDs with this member's index encrypt, all the others decrypt.
/// Keys are derived on demand. A decryption key is kept only once a ciphertext has
/// authenticated with it, so forged KIDs do not fill the store.
///
/// A new epoch whose low `E` bits equal an older one's replaces it, with every key derived
/// from the older one (RFC 9605 section 5.2). An epoch at or below one already introduced with
/// the same low bits is refused, so a removed epoch cannot come back with its counters at 0.
pub struct MlsContext {
    context: SFrameContext,
    layout: MlsKeyIdLayout,
    sender_index: u64,
    slots: HashMap<u64, EpochSlot>,
    max_keys: usize,
}

impl MlsContext {
    /// A context for the member at `sender_index` of the MLS group, with no epoch yet.
    ///
    /// Fails with [`Error::KeyIdLayout`] when the index does not fit the layout's `S` bits.
    pub fn new(
        suite: CipherSuite,
        provider: Arc<dyn RTCCryptoProvider>,
        layout: MlsKeyIdLayout,
        sender_index: u64,
    ) -> Result<Self> {
        Self::with_config(
            suite,
            provider,
            layout,
            sender_index,
            SFrameConfig::default(),
        )
    }

    /// [`new`](Self::new) with explicit options for the underlying [`SFrameContext`].
    pub fn with_config(
        suite: CipherSuite,
        provider: Arc<dyn RTCCryptoProvider>,
        layout: MlsKeyIdLayout,
        sender_index: u64,
        config: SFrameConfig,
    ) -> Result<Self> {
        // Validates the index against the layout.
        layout.key_id(0, sender_index, 0)?;
        Ok(Self {
            context: SFrameContext::with_config(suite, provider, config),
            layout,
            sender_index,
            slots: HashMap::new(),
            max_keys: DEFAULT_MAX_MLS_KEYS,
        })
    }

    /// Sets how many derived keys the context holds at most. Beyond it, a KID that needs a new
    /// key fails with [`Error::TooManyKeys`] until an epoch is replaced or removed.
    pub fn set_max_keys(&mut self, max_keys: usize) {
        self.max_keys = max_keys;
    }

    /// The KID layout.
    #[must_use]
    pub fn layout(&self) -> MlsKeyIdLayout {
        self.layout
    }

    /// This member's index in the MLS group.
    #[must_use]
    pub fn sender_index(&self) -> u64 {
        self.sender_index
    }

    /// The underlying context: its cipher suite, statistics and stored keys.
    #[must_use]
    pub fn context(&self) -> &SFrameContext {
        &self.context
    }

    /// Whether `epoch` has been introduced and not removed or replaced.
    #[must_use]
    pub fn has_epoch(&self, epoch: u64) -> bool {
        self.secret(epoch).is_some()
    }

    fn secret(&self, epoch: u64) -> Option<&SecretVec> {
        let slot = self.slots.get(&self.layout.epoch_slot(epoch))?;
        if slot.epoch == epoch {
            slot.base_key.as_ref()
        } else {
            None
        }
    }

    /// Removes every key derived for the epoch that `slot` stood for.
    fn purge(&mut self, slot: u64) {
        let layout = self.layout;
        self.context
            .retain_keys(|kid| layout.epoch_slot(kid) != slot);
    }

    /// Introduces `epoch` with its exported secret (see [`MLS_EXPORTER_LABEL`]).
    ///
    /// An older epoch with the same low `E` bits is removed, with all its keys. Introducing an
    /// epoch again with the same secret changes nothing. Fails with [`Error::StaleEpoch`] when
    /// `epoch` is older than the one its low bits already stand for, was removed, or comes with
    /// another secret than before.
    pub fn add_epoch(&mut self, epoch: u64, base_key: &[u8]) -> Result<()> {
        if base_key.is_empty() {
            return Err(Error::EmptyBaseKey);
        }
        let slot = self.layout.epoch_slot(epoch);
        if let Some(current) = self.slots.get(&slot) {
            if current.epoch > epoch {
                return Err(Error::StaleEpoch(epoch));
            }
            if current.epoch == epoch {
                return match &current.base_key {
                    Some(known) if constant_time_eq(known.as_ref(), base_key) => Ok(()),
                    _ => Err(Error::StaleEpoch(epoch)),
                };
            }
            self.purge(slot);
        }
        self.slots.insert(
            slot,
            EpochSlot {
                epoch,
                base_key: Some(SecretVec::new(base_key.to_vec())),
            },
        );
        Ok(())
    }

    /// Removes `epoch`, its secret and every key derived from it. Returns whether it was
    /// there. The epoch cannot be introduced again.
    pub fn remove_epoch(&mut self, epoch: u64) -> bool {
        let slot = self.layout.epoch_slot(epoch);
        match self.slots.get_mut(&slot) {
            Some(current) if current.epoch == epoch && current.base_key.is_some() => {
                current.base_key = None;
                self.purge(slot);
                true
            }
            _ => false,
        }
    }

    /// The KID this member sends with in `epoch` for its `context` value.
    pub fn key_id(&self, epoch: u64, context: u64) -> Result<u64> {
        self.layout.key_id(epoch, self.sender_index, context)
    }

    /// Encrypts `plaintext` as this member in `epoch`, under the KID of `context`, and returns
    /// the SFrame ciphertext. Fails with [`Error::UnknownEpoch`] when the epoch is not held.
    pub fn encrypt(
        &mut self,
        epoch: u64,
        context: u64,
        metadata: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>> {
        let mut out = Vec::with_capacity(plaintext.len() + self.context.max_overhead());
        self.encrypt_into(epoch, context, metadata, plaintext, &mut out)?;
        Ok(out)
    }

    /// [`encrypt`](Self::encrypt), appending the ciphertext to `out`.
    pub fn encrypt_into(
        &mut self,
        epoch: u64,
        context: u64,
        metadata: &[u8],
        plaintext: &[u8],
        out: &mut Vec<u8>,
    ) -> Result<Header> {
        let kid = self.key_id(epoch, context)?;
        if self.context.key_usage(kid).is_none() {
            let slot = self.slots.get(&self.layout.epoch_slot(epoch));
            let Some(base_key) = slot
                .filter(|slot| slot.epoch == epoch)
                .and_then(|slot| slot.base_key.as_ref())
            else {
                return Err(Error::UnknownEpoch(epoch));
            };
            if self.context.key_count() >= self.max_keys {
                return Err(Error::TooManyKeys);
            }
            self.context.add_send_key(kid, base_key.as_ref())?;
        } else if !self.has_epoch(epoch) {
            // The KID's low bits now stand for another epoch.
            return Err(Error::UnknownEpoch(epoch));
        }
        self.context.encrypt_into(kid, metadata, plaintext, out)
    }

    /// Decrypts an SFrame ciphertext from another member and returns the plaintext.
    ///
    /// The key is found by the KID in the header: the epoch by its low `E` bits, the sender by
    /// its index. A KID with this member's own index is refused
    /// ([`Error::KeyRoleConflict`]): its keys encrypt only.
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
        if let Ok((header, _)) = self.context.decode_header(ciphertext)
            && self.context.key_usage(header.kid).is_some()
        {
            return self.context.decrypt_into(metadata, ciphertext, out);
        }
        let result = self.decrypt_on_demand(metadata, ciphertext, out);
        self.context.count(&result);
        result
    }

    /// Decrypts with a key derived for the occasion, and stores the key if the ciphertext
    /// authenticated.
    fn decrypt_on_demand(
        &mut self,
        metadata: &[u8],
        ciphertext: &[u8],
        out: &mut Vec<u8>,
    ) -> Result<Header> {
        let (header, header_len) = self.context.decode_header(ciphertext)?;
        let parts = self.layout.split(header.kid);
        if parts.sender_index == self.sender_index {
            return Err(Error::KeyRoleConflict(header.kid));
        }
        let Some(base_key) = self
            .slots
            .get(&parts.epoch)
            .and_then(|slot| slot.base_key.as_ref())
        else {
            return Err(Error::UnknownKeyId(header.kid));
        };
        if self.context.key_count() >= self.max_keys {
            return Err(Error::TooManyKeys);
        }
        let mut key = KeyContext::derive_recv(
            self.context.provider().crypto(),
            self.context.cipher_suite(),
            header.kid,
            base_key.as_ref(),
            self.context.config().replay_window,
        )?;
        self.context
            .decrypt_with(&mut key, header, header_len, metadata, ciphertext, out)?;
        self.context.insert_key(header.kid, key);
        Ok(header)
    }
}

impl std::fmt::Debug for MlsContext {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("MlsContext")
            .field("context", &self.context)
            .field("layout", &self.layout)
            .field("sender_index", &self.sender_index)
            .field("epochs", &self.slots.len())
            .finish_non_exhaustive()
    }
}
