//! A bounded store for ciphertexts whose key has not arrived yet (RFC 9605 section 4.4.4).

use std::collections::VecDeque;

use crate::error::Result;
use crate::header::Header;

/// A ciphertext waiting for its key, with the metadata it has to be decrypted with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingCiphertext {
    /// The KID in the ciphertext's header.
    pub kid: u64,
    /// The metadata the application supplies to decryption.
    pub metadata: Vec<u8>,
    /// The SFrame ciphertext, whole.
    pub ciphertext: Vec<u8>,
}

/// Ciphertexts that failed with [`Error::UnknownKeyId`](crate::Error::UnknownKeyId), kept to
/// be decrypted once the key is there.
///
/// A client MAY do this (RFC 9605 section 4.4.4): a new key can reach a receiver after the
/// first frames encrypted with it. The store is bounded in frames and in bytes and drops the
/// oldest entry to make room, so a peer naming keys that never come cannot grow it. Nothing
/// held here is authenticated: it is only ever handed back for decryption. It has no clock;
/// an application that wants entries to expire calls [`discard_oldest`](Self::discard_oldest)
/// or [`clear`](Self::clear) on its own timer.
#[derive(Debug)]
pub struct PendingCiphertexts {
    max_frames: usize,
    max_bytes: usize,
    bytes: usize,
    frames: VecDeque<PendingCiphertext>,
}

impl PendingCiphertexts {
    /// A store of at most `max_frames` ciphertexts and `max_bytes` bytes (ciphertext plus
    /// metadata).
    #[must_use]
    pub fn new(max_frames: usize, max_bytes: usize) -> Self {
        Self {
            max_frames,
            max_bytes,
            bytes: 0,
            frames: VecDeque::new(),
        }
    }

    /// The number of ciphertexts held.
    #[must_use]
    pub fn len(&self) -> usize {
        self.frames.len()
    }

    /// Whether nothing is held.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.frames.is_empty()
    }

    /// The bytes held: ciphertexts and their metadata.
    #[must_use]
    pub fn bytes(&self) -> usize {
        self.bytes
    }

    /// Keeps `ciphertext` and its `metadata` under the KID of its header, dropping the oldest
    /// entries if the bounds require it. Returns the KID, or `None` when the ciphertext alone
    /// exceeds the bounds and was not kept.
    ///
    /// Fails when the header does not parse: such a ciphertext can never be decrypted.
    pub fn push(&mut self, metadata: &[u8], ciphertext: &[u8]) -> Result<Option<u64>> {
        let (header, _) = Header::decode_lenient(ciphertext)?;
        let size = metadata.len() + ciphertext.len();
        if self.max_frames == 0 || size > self.max_bytes {
            return Ok(None);
        }
        while self.frames.len() >= self.max_frames || self.bytes + size > self.max_bytes {
            self.discard_oldest(1);
        }
        self.bytes += size;
        self.frames.push_back(PendingCiphertext {
            kid: header.kid,
            metadata: metadata.to_vec(),
            ciphertext: ciphertext.to_vec(),
        });
        Ok(Some(header.kid))
    }

    /// Removes and returns the ciphertexts waiting for `kid`, oldest first: call it when the
    /// key for `kid` has been added, and decrypt each.
    pub fn take(&mut self, kid: u64) -> Vec<PendingCiphertext> {
        let (taken, kept): (VecDeque<_>, VecDeque<_>) = std::mem::take(&mut self.frames)
            .into_iter()
            .partition(|pending| pending.kid == kid);
        self.frames = kept;
        self.bytes = self.frames.iter().map(size_of_entry).sum();
        taken.into()
    }

    /// Drops the `count` oldest ciphertexts.
    pub fn discard_oldest(&mut self, count: usize) {
        for _ in 0..count {
            let Some(dropped) = self.frames.pop_front() else {
                break;
            };
            self.bytes -= size_of_entry(&dropped);
        }
    }

    /// Drops everything.
    pub fn clear(&mut self) {
        self.frames.clear();
        self.bytes = 0;
    }
}

fn size_of_entry(pending: &PendingCiphertext) -> usize {
    pending.metadata.len() + pending.ciphertext.len()
}
