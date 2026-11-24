#![warn(rust_2018_idioms)]
#![warn(missing_docs)]
#![allow(dead_code)]

//! SRTP and SRTCP for the Sans-I/O WebRTC stack.
//!
//! The Secure Real-time Transport Protocol ([RFC 3711]) as WebRTC keys it: protection
//! profiles negotiated through DTLS-SRTP ([RFC 5764]), with keying material exported from
//! the DTLS handshake rather than signalled.
//!
//! # Structure
//!
//! * [`context`] — [`Context`](context::Context), the encrypt/decrypt state for one
//!   direction: `encrypt_rtp`/`decrypt_rtp` and the RTCP equivalents, plus the replay
//!   protection and rollover-counter tracking the RFC requires.
//! * [`protection_profile`] — the negotiable profiles (AES-128-CM-SHA1-80,
//!   AEAD-AES-128-GCM, and friends) and their key/salt lengths.
//! * [`config`], [`option`] — how a context is built, including replay-window sizing.
//! * [`keying`] — master keys over time: the key derivation rate, the MKI and the master-key
//!   table, key lifetimes, and the events that tell the application to re-key.
//! * [`cryptex`] ([RFC 9335]) and [`header_extension`] ([RFC 6904]) — the two ways to encrypt
//!   RTP header extensions.
//!
//! # Transforms
//!
//! AES-128 counter mode with HMAC-SHA1 (the default of [RFC 3711]), AES-192 and AES-256
//! counter mode ([RFC 6188]), the NULL cipher with HMAC-SHA1 (mandatory to implement in RFC
//! 3711, never used by WebRTC), and AEAD_AES_128_GCM / AEAD_AES_256_GCM ([RFC 7714]). AES-f8
//! (RFC 3711 section 4.1.2, optional) is not implemented.
//!
//! # Example
//!
//! A profile is negotiated through DTLS-SRTP, and it fixes the key, salt and tag sizes the
//! context will use:
//!
//! ```
//! use rtci_srtp::protection_profile::ProtectionProfile;
//!
//! let profile = ProtectionProfile::Aes128CmHmacSha1_80;
//! assert_eq!(profile.key_len(), 16); // AES-128
//! assert_eq!(profile.salt_len(), 14);
//! assert_eq!(profile.rtp_auth_tag_len(), 10); // 80-bit tag
//!
//! // The AEAD profiles authenticate inside the cipher, so they carry no HMAC key.
//! assert_eq!(ProtectionProfile::AeadAes128Gcm.auth_key_len(), 0);
//! ```
//!
//! Most applications do not depend on this crate directly — the
//! [`rtci`](https://docs.rs/rtc) crate creates the contexts from the DTLS handshake and
//! applies them to media as one layer of the peer-connection pipeline.
//! Applications constructing contexts directly can select cryptography explicitly with
//! [`context::Context::new`]; [`context::Context::new`] retains default-provider
//! compatibility.
//!
//! [RFC 3711]: https://datatracker.ietf.org/doc/html/rfc3711
//! [RFC 5764]: https://datatracker.ietf.org/doc/html/rfc5764
//! [RFC 6188]: https://datatracker.ietf.org/doc/html/rfc6188
//! [RFC 6904]: https://datatracker.ietf.org/doc/html/rfc6904
//! [RFC 7714]: https://datatracker.ietf.org/doc/html/rfc7714
//! [RFC 9335]: https://datatracker.ietf.org/doc/html/rfc9335

mod cipher;

/// The crypto provider API.
///
/// Re-exported because this crate's public constructors take an
/// [`Arc<dyn RTCCryptoProvider>`](crypto::RTCCryptoProvider), which a caller must be able to name
/// without adding — and version-matching — a direct `rtci-crypto` dependency.
pub use crypto;

/// Session configuration: keys, protection profile, and replay-protection options.
pub mod config;
/// The encrypt/decrypt state for one SRTP/SRTCP session.
pub mod context;
pub mod cryptex;
/// Entry points for stateful fuzz targets. Gated behind `cfg(fuzzing)`; not part of the
/// supported API.
#[cfg(fuzzing)]
pub mod fuzzing;
pub mod header_extension;
mod key_derivation;
pub mod keying;
/// Per-context options, currently the replay-detector factory.
pub mod option;
/// The DTLS-SRTP protection profiles and their key, salt and tag lengths.
pub mod protection_profile;

#[cfg(test)]
mod rfc_vectors_test;

/// Helpers shared by the unit tests.
#[cfg(test)]
pub(crate) mod test_util {
    /// The bytes a hexadecimal string spells; white space is ignored.
    pub(crate) fn hex(s: &str) -> Vec<u8> {
        let s: String = s.split_whitespace().collect();
        assert!(s.len().is_multiple_of(2), "odd number of hex digits");
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex digit"))
            .collect()
    }

    /// The built-in provider, for tests only. Library code never resolves a default.
    pub(crate) fn provider() -> std::sync::Arc<dyn crypto::RTCCryptoProvider> {
        crypto::default_provider().expect("a built-in crypto provider must be enabled for tests")
    }
}
