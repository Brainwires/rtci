#[cfg(test)]
mod context_test;
#[cfg(test)]
mod cryptex_test;
#[cfg(test)]
mod srtcp_test;
#[cfg(test)]
mod srtp_test;

use std::collections::HashMap;
use std::hash::{BuildHasher, RandomState};

use crypto::RTCCrypto;
use shared::replay_detector::*;

use crate::cipher::cipher_aead_aes_gcm::*;
use crate::cipher::cipher_aes_cm_hmac_sha1::*;
use crate::cipher::*;
use crate::cryptex::Cryptex;
use crate::option::*;
use crate::protection_profile::*;
use shared::error::{Error, Result};

/// SRTCP protection and unprotection.
pub mod srtcp;
/// SRTP protection and unprotection.
pub mod srtp;

const MAX_ROC: u32 = u32::MAX;
const SEQ_NUM_MEDIAN: u16 = 1 << 15;
const SEQ_NUM_MAX: u16 = u16::MAX;
/// How many packet indexes behind the highest one sent the sender still tracks individually
/// (the NACK responder's default buffer). An index protects one packet only (RFC 3711 Section
/// 3.3.1, RFC 7714 Section 8.1): the same packet again is protected again (the output is the
/// same), a different one is refused, and so is any index older than this window.
pub(crate) const SRTP_SEND_INDEX_WINDOW: usize = 1024;
/// How many SSRCs one context keeps SRTP state for, and separately SRTCP state for. Packets for
/// a further SSRC are refused (existing state is never evicted).
pub(crate) const MAX_SSRC_STATES: usize = 1024;

/// Encrypt/Decrypt state for a single SRTP SSRC
#[derive(Default)]
pub(crate) struct SrtpSsrcState {
    ssrc: u32,
    index: u64,
    rollover_has_processed: bool,
    replay_detector: Option<Box<dyn ReplayDetector>>,
    /// The packet indexes this (sending) context has encrypted, created on first encryption.
    sent_indexes: Option<SentIndexes>,
}

/// What an SRTP index may protect, as decided by [`SentIndexes::check`].
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum SendIndexUse {
    /// Not used yet: protect the packet and record it.
    New,
    /// Already used for this very packet: protecting it again yields the same bytes.
    SamePacket,
    /// Used for a different packet, or too old to tell: refuse.
    Refused,
}

/// The packet indexes a sending context protected within [`SRTP_SEND_INDEX_WINDOW`] of the
/// highest one, each with a digest of the packet it protected.
pub(crate) struct SentIndexes {
    highest: Option<u64>,
    /// `(index, digest)` by `index % SRTP_SEND_INDEX_WINDOW`; `None` when never written.
    slots: Vec<Option<(u64, u64)>>,
}

impl SentIndexes {
    pub(crate) fn new() -> Self {
        SentIndexes {
            highest: None,
            slots: vec![None; SRTP_SEND_INDEX_WINDOW],
        }
    }

    fn slot(index: u64) -> usize {
        (index % SRTP_SEND_INDEX_WINDOW as u64) as usize
    }

    /// Whether `index` may protect the packet whose digest is `digest`.
    pub(crate) fn check(&self, index: u64, digest: u64) -> SendIndexUse {
        // Within the window every index has a slot of its own, so a slot holding another index
        // holds an older one, and `index` is unused.
        if let Some((used, used_digest)) = self.slots[Self::slot(index)]
            && used == index
        {
            return if used_digest == digest {
                SendIndexUse::SamePacket
            } else {
                SendIndexUse::Refused
            };
        }
        match self.highest {
            Some(highest) if index + SRTP_SEND_INDEX_WINDOW as u64 <= highest => {
                SendIndexUse::Refused
            }
            _ => SendIndexUse::New,
        }
    }

    /// Records that `index` protected the packet whose digest is `digest`.
    pub(crate) fn record(&mut self, index: u64, digest: u64) {
        self.slots[Self::slot(index)] = Some((index, digest));
        if self.highest.is_none_or(|highest| index > highest) {
            self.highest = Some(index);
        }
    }
}

/// Encrypt/Decrypt state for a single SRTCP SSRC
#[derive(Default)]
pub(crate) struct SrtcpSsrcState {
    srtcp_index: usize,
    ssrc: u32,
    replay_detector: Option<Box<dyn ReplayDetector>>,
}

impl SrtpSsrcState {
    pub fn next_rollover_count(&self, sequence_number: u16) -> (u32, i32, bool) {
        let local_roc = (self.index >> 16) as u32;
        let local_seq = self.index as u16;

        let mut guess_roc = local_roc;

        let diff = if self.rollover_has_processed {
            let seq = (sequence_number as i32).wrapping_sub(local_seq as i32);
            // When local_roc is equal to 0, and entering seq-local_seq > SEQ_NUM_MEDIAN
            // judgment, it will cause guess_roc calculation error
            if self.index > SEQ_NUM_MEDIAN as _ {
                if local_seq < SEQ_NUM_MEDIAN {
                    if seq > SEQ_NUM_MEDIAN as i32 {
                        guess_roc = local_roc.wrapping_sub(1);
                        seq.wrapping_sub(SEQ_NUM_MAX as i32 + 1)
                    } else {
                        seq
                    }
                } else if local_seq - SEQ_NUM_MEDIAN > sequence_number {
                    guess_roc = local_roc.wrapping_add(1);
                    seq.wrapping_add(SEQ_NUM_MAX as i32 + 1)
                } else {
                    seq
                }
            } else {
                // local_roc is equal to 0
                seq
            }
        } else {
            0i32
        };

        (guess_roc, diff, (guess_roc == 0 && local_roc == MAX_ROC))
    }

    /// https://tools.ietf.org/html/rfc3550#appendix-A.1
    ///
    /// The highest index only moves forward: RFC 3711 Section 3.3.1 and Appendix A update `s_l`
    /// and the ROC only for a packet ahead of them.
    pub fn update_rollover_count(&mut self, sequence_number: u16, diff: i32) {
        if !self.rollover_has_processed {
            self.index |= sequence_number as u64;
            self.rollover_has_processed = true;
        } else if diff > 0 {
            self.index = self.index.wrapping_add(diff as _);
        }
    }
}

/// Context represents a SRTP cryptographic context
/// Context can only be used for one-way operations
/// it must either used ONLY for encryption or ONLY for decryption
pub struct Context {
    cipher: Box<dyn Cipher>,

    srtp_ssrc_states: HashMap<u32, SrtpSsrcState>,
    srtcp_ssrc_states: HashMap<u32, SrtcpSsrcState>,

    new_srtp_replay_detector: ContextOption,
    new_srtcp_replay_detector: ContextOption,

    cryptex: Cryptex,
    /// Keys the digests of protected packets kept per sending SSRC (see [`SentIndexes`]).
    sent_digest_hasher: RandomState,
}

impl Context {
    /// Creates an SRTP context.
    ///
    /// The crypto implementation is supplied by the caller; this crate never resolves a default.
    /// Borrowed, not owned: it is only needed to build the keyed cipher/MAC objects below, which
    /// are what the context retains.
    pub fn new(
        master_key: &[u8],
        master_salt: &[u8],
        profile: ProtectionProfile,
        srtp_ctx_opt: Option<ContextOption>,
        srtcp_ctx_opt: Option<ContextOption>,
        crypto: &dyn RTCCrypto,
    ) -> Result<Context> {
        let key_len = profile.key_len();
        let salt_len = profile.salt_len();

        if master_key.len() != key_len {
            return Err(Error::SrtpMasterKeyLength(key_len, master_key.len()));
        } else if master_salt.len() != salt_len {
            return Err(Error::SrtpSaltLength(salt_len, master_salt.len()));
        }
        profile.ensure_crypto_supported(crypto)?;

        let cipher: Box<dyn Cipher> = match profile {
            ProtectionProfile::Aes128CmHmacSha1_32
            | ProtectionProfile::Aes128CmHmacSha1_80
            | ProtectionProfile::Aes256CmHmacSha1_80
            | ProtectionProfile::Aes256CmHmacSha1_32 => Box::new(CipherAesCmHmacSha1::new(
                profile,
                master_key,
                master_salt,
                crypto,
            )?),

            ProtectionProfile::AeadAes128Gcm | ProtectionProfile::AeadAes256Gcm => {
                // `CipherAeadAesGcm::new` selects AES-128 vs AES-256 from the
                // profile itself, so both GCM profiles share one arm.
                Box::new(CipherAeadAesGcm::new(
                    profile,
                    master_key,
                    master_salt,
                    crypto,
                )?)
            }
        };

        let srtp_ctx_opt = if let Some(ctx_opt) = srtp_ctx_opt {
            ctx_opt
        } else {
            srtp_no_replay_protection()
        };

        let srtcp_ctx_opt = if let Some(ctx_opt) = srtcp_ctx_opt {
            ctx_opt
        } else {
            srtcp_no_replay_protection()
        };

        Ok(Context {
            cipher,
            srtp_ssrc_states: HashMap::new(),
            srtcp_ssrc_states: HashMap::new(),
            new_srtp_replay_detector: srtp_ctx_opt,
            new_srtcp_replay_detector: srtcp_ctx_opt,
            cryptex: Cryptex::default(),
            sent_digest_hasher: RandomState::new(),
        })
    }

    /// How this context uses Cryptex (RFC 9335); see [`Cryptex`].
    pub fn cryptex(&self) -> Cryptex {
        self.cryptex
    }

    /// Sets how this context uses Cryptex (RFC 9335). It applies from the next packet.
    pub fn set_cryptex(&mut self, cryptex: Cryptex) {
        self.cryptex = cryptex;
    }

    /// Fails with [`Error::SrtpTooManySsrcs`] if `ssrc` has no SRTP state yet and the context
    /// already holds [`MAX_SSRC_STATES`] of them.
    fn check_srtp_ssrc_capacity(&self, ssrc: u32) -> Result<()> {
        if self.srtp_ssrc_states.len() >= MAX_SSRC_STATES
            && !self.srtp_ssrc_states.contains_key(&ssrc)
        {
            return Err(Error::SrtpTooManySsrcs(ssrc, MAX_SSRC_STATES));
        }
        Ok(())
    }

    /// Fails with [`Error::SrtpTooManySsrcs`] if `ssrc` has no SRTCP state yet and the context
    /// already holds [`MAX_SSRC_STATES`] of them.
    fn check_srtcp_ssrc_capacity(&self, ssrc: u32) -> Result<()> {
        if self.srtcp_ssrc_states.len() >= MAX_SSRC_STATES
            && !self.srtcp_ssrc_states.contains_key(&ssrc)
        {
            return Err(Error::SrtpTooManySsrcs(ssrc, MAX_SSRC_STATES));
        }
        Ok(())
    }

    fn get_srtp_ssrc_state(&mut self, ssrc: u32) -> Result<&mut SrtpSsrcState> {
        self.check_srtp_ssrc_capacity(ssrc)?;
        // `or_insert_with` so the replay detector (a boxed sliding-window
        // detector backed by a heap-allocated bit buffer) is only constructed on
        // the first packet for a given SSRC. `or_insert` would build — and then
        // immediately drop — a fresh detector on every decrypted packet.
        let new_srtp_replay_detector = &self.new_srtp_replay_detector;
        Ok(self
            .srtp_ssrc_states
            .entry(ssrc)
            .or_insert_with(|| SrtpSsrcState {
                ssrc,
                replay_detector: Some(new_srtp_replay_detector()),
                ..Default::default()
            }))
    }

    fn get_srtcp_ssrc_state(&mut self, ssrc: u32) -> Result<&mut SrtcpSsrcState> {
        self.check_srtcp_ssrc_capacity(ssrc)?;
        let new_srtcp_replay_detector = &self.new_srtcp_replay_detector;
        Ok(self
            .srtcp_ssrc_states
            .entry(ssrc)
            .or_insert_with(|| SrtcpSsrcState {
                ssrc,
                replay_detector: Some(new_srtcp_replay_detector()),
                ..Default::default()
            }))
    }

    /// roc returns SRTP rollover counter value of specified SSRC.
    fn get_roc(&self, ssrc: u32) -> Option<u32> {
        self.srtp_ssrc_states
            .get(&ssrc)
            .map(|s| (s.index >> 16) as _)
    }

    /// set_roc sets SRTP rollover counter value of specified SSRC.
    fn set_roc(&mut self, ssrc: u32, roc: u32) {
        if let Ok(state) = self.get_srtp_ssrc_state(ssrc) {
            state.index = (roc as u64) << 16;
            state.rollover_has_processed = false;
        }
    }

    /// index returns SRTCP index value of specified SSRC.
    fn get_index(&self, ssrc: u32) -> Option<usize> {
        self.srtcp_ssrc_states.get(&ssrc).map(|s| s.srtcp_index)
    }

    /// set_index sets SRTCP index value of specified SSRC.
    fn set_index(&mut self, ssrc: u32, index: usize) {
        if let Ok(state) = self.get_srtcp_ssrc_state(ssrc) {
            state.srtcp_index = index % (MAX_SRTCP_INDEX + 1);
        }
    }
}
