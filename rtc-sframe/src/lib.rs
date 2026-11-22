#![warn(rust_2018_idioms)]
#![warn(missing_docs)]

//! SFrame for the Sans-I/O WebRTC stack.
//!
//! Secure Frame ([RFC 9605]) is authenticated encryption for media that stays end-to-end when
//! the transport is not: a selective forwarding unit terminates SRTP and still cannot read or
//! alter what SFrame protects. An SFrame ciphertext is a short header (a key id and a counter),
//! the encrypted data and an authentication tag; it is produced from a whole encoded frame or
//! from one packet's payload, and travels as the payload of whatever carries the media.
//!
//! The crate does no I/O, reads no clock and runs no key exchange. The application brings the
//! keys (`base_key` values labelled with a KID) from its key management, and decides what a
//! ciphertext covers and how it is packetized.
//!
//! # Structure
//!
//! * [`SFrameContext`]: the key store and the two operations, [`encrypt`](SFrameContext::encrypt)
//!   and [`decrypt`](SFrameContext::decrypt). A key is added for sending or for receiving and
//!   keeps that role; a sending key owns its counter, so a (key, nonce) pair is never used
//!   twice; a receiving key has an anti-replay window.
//! * [`CipherSuite`]: the five suites of RFC 9605 and the three AES-256-CTR suites of the IANA
//!   registry.
//! * [`Header`]: the SFrame header codec.
//! * [`SenderKeyIdLayout`], [`SenderKeyRatchet`], [`SenderKeyReceiver`], [`ratchet_base_key`]:
//!   the sender-keys scheme of section 5.1.
//! * [`MlsKeyIdLayout`], [`MlsContext`]: SFrame keyed from MLS epochs, section 5.2. The
//!   application runs MLS and supplies each epoch's exported secret.
//! * [`PendingCiphertexts`]: a bounded store for ciphertexts whose key has not arrived yet.
//!
//! # Example
//!
//! ```
//! use rtc_sframe::{CipherSuite, Error, SFrameContext};
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let suite = CipherSuite::Aes128CtrHmacSha256_80;
//! let base_key = b"sixteen byte key"; // from the application's key management
//!
//! let mut alice = SFrameContext::with_default_provider(suite)?;
//! alice.add_send_key(1, base_key)?;
//! let mut bob = SFrameContext::with_default_provider(suite)?;
//! bob.add_recv_key(1, base_key)?;
//!
//! // The metadata is authenticated but not sent in the ciphertext.
//! let ciphertext = alice.encrypt(1, b"metadata", b"an encoded frame")?;
//! assert_eq!(ciphertext.len(), 1 + b"an encoded frame".len() + suite.tag_len());
//! assert_eq!(bob.decrypt(b"metadata", &ciphertext)?, b"an encoded frame");
//!
//! // A ciphertext is accepted once.
//! assert!(matches!(
//!     bob.decrypt(b"metadata", &ciphertext),
//!     Err(Error::Replayed { kid: 1, ctr: 0 })
//! ));
//! # Ok(())
//! # }
//! ```
//!
//! # What stays with the application
//!
//! RFC 9605 leaves these to the application, and so does this crate: that a `base_key` has one
//! sender, and that a (`base_key`, KID) pair is never installed for sending twice (section
//! 9.1); the key exchange and when keys change (sections 5, 7.3 and 9.2); what goes into the
//! metadata, and that nothing uses it before decryption has authenticated it (section 9.4);
//! and reassembling a ciphertext that was sent in several packets (section 4.4.4).
//!
//! [RFC 9605]: https://www.rfc-editor.org/rfc/rfc9605

mod aead;
mod cipher_suite;
mod context;
mod error;
mod header;
mod kdf;
mod key_id;
mod mls;
mod pending;
mod replay;
mod sender_key;

/// Entry points for the fuzz targets. Gated behind `cfg(fuzzing)`; not part of the supported
/// API.
#[cfg(any(fuzzing, test))]
pub mod fuzzing;

/// The crypto provider API.
///
/// Re-exported because this crate's public constructors take an
/// [`Arc<dyn RTCCryptoProvider>`](crypto::RTCCryptoProvider), which a caller must be able to name
/// without adding, and version-matching, a direct `rtc-crypto` dependency.
pub use crypto;

pub use cipher_suite::{CipherSuite, NONCE_LEN, UnknownCipherSuite};
pub use context::{KeyUsage, SFrameConfig, SFrameContext, SFrameStats};
pub use error::{Error, ErrorKind, Result};
pub use header::{Header, MAX_HEADER_LEN};
pub use kdf::{derive_ssrc_key, ratchet_base_key};
pub use key_id::{MlsKeyId, MlsKeyIdLayout, SenderKeyId, SenderKeyIdLayout};
pub use mls::{DEFAULT_MAX_MLS_KEYS, MLS_EXPORTER_LABEL, MlsContext};
pub use pending::{PendingCiphertext, PendingCiphertexts};
pub use replay::{DEFAULT_REPLAY_WINDOW, MAX_REPLAY_WINDOW};
pub use sender_key::{
    DEFAULT_MAX_RATCHET_STEPS, DEFAULT_RETAINED_OLD_KEYS, SenderKeyRatchet, SenderKeyReceiver,
};

#[cfg(test)]
mod aead_test;
#[cfg(test)]
mod context_test;
#[cfg(test)]
mod fuzzing_test;
#[cfg(test)]
mod header_test;
#[cfg(test)]
mod header_vectors;
#[cfg(test)]
mod kdf_test;
#[cfg(test)]
mod key_management_test;
#[cfg(test)]
mod test_util;
#[cfg(test)]
mod test_vectors;
