use crypto::{
    AeadAlgorithm, BlockCipherAlgorithm, CryptoAlgorithm, HmacAlgorithm, RTCCrypto,
    StreamCipherAlgorithm,
};
use shared::error::{Error, Result};

use crate::key_derivation::Prf;
use crate::keying::KeyLifetime;

const AES_128_CM_REQUIREMENTS: &[CryptoAlgorithm] = &[
    CryptoAlgorithm::BlockCipher(BlockCipherAlgorithm::Aes128),
    CryptoAlgorithm::StreamCipher(StreamCipherAlgorithm::Aes128Ctr),
    CryptoAlgorithm::Hmac(HmacAlgorithm::Sha1),
];
const AES_256_CM_REQUIREMENTS: &[CryptoAlgorithm] = &[
    CryptoAlgorithm::BlockCipher(BlockCipherAlgorithm::Aes256),
    CryptoAlgorithm::StreamCipher(StreamCipherAlgorithm::Aes256Ctr),
    CryptoAlgorithm::Hmac(HmacAlgorithm::Sha1),
];
const AES_192_CM_REQUIREMENTS: &[CryptoAlgorithm] = &[
    CryptoAlgorithm::BlockCipher(BlockCipherAlgorithm::Aes192),
    CryptoAlgorithm::StreamCipher(StreamCipherAlgorithm::Aes192Ctr),
    CryptoAlgorithm::Hmac(HmacAlgorithm::Sha1),
];
// The NULL cipher still derives its keys with the AES-CM PRF (RFC 5764 section 4.1.2).
const NULL_REQUIREMENTS: &[CryptoAlgorithm] = &[
    CryptoAlgorithm::BlockCipher(BlockCipherAlgorithm::Aes128),
    CryptoAlgorithm::Hmac(HmacAlgorithm::Sha1),
];
// The AES-CM stream cipher is for RFC 6904 header extension encryption (RFC 7714 section 8.3).
const AEAD_AES_128_GCM_REQUIREMENTS: &[CryptoAlgorithm] = &[
    CryptoAlgorithm::BlockCipher(BlockCipherAlgorithm::Aes128),
    CryptoAlgorithm::StreamCipher(StreamCipherAlgorithm::Aes128Ctr),
    CryptoAlgorithm::Aead(AeadAlgorithm::Aes128Gcm),
];
const AEAD_AES_256_GCM_REQUIREMENTS: &[CryptoAlgorithm] = &[
    CryptoAlgorithm::BlockCipher(BlockCipherAlgorithm::Aes256),
    CryptoAlgorithm::StreamCipher(StreamCipherAlgorithm::Aes256Ctr),
    CryptoAlgorithm::Aead(AeadAlgorithm::Aes256Gcm),
];

/// ProtectionProfile specifies Cipher and AuthTag details, similar to TLS cipher suite
///
/// The discriminants are not wire values. The DTLS-SRTP code point of a profile, for the ones
/// the IANA "DTLS-SRTP Protection Profiles" registry assigns one to, is
/// [`dtls_srtp_id`](Self::dtls_srtp_id). The registry has none for the AES-192 and AES-256
/// counter-mode suites of RFC 6188 (0x0003 and 0x0004 are unassigned, and other stacks use them
/// for AES-f8), so `use_srtp` cannot negotiate those: they are for key management that names
/// the suite itself.
#[derive(Default, Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
#[non_exhaustive]
pub enum ProtectionProfile {
    #[default]
    /// `SRTP_AES128_CM_HMAC_SHA1_80`: AES-128 counter mode with an 80-bit HMAC-SHA1 tag.
    ///
    /// The profile every WebRTC implementation supports.
    Aes128CmHmacSha1_80 = 0x0001,
    /// `SRTP_AES128_CM_HMAC_SHA1_32`: as above with a truncated 32-bit tag, trading
    /// authentication strength for 6 bytes per packet.
    Aes128CmHmacSha1_32 = 0x0002,
    /// `AES_256_CM_HMAC_SHA1_80` (RFC 6188): AES-256 counter mode with an 80-bit HMAC-SHA1 tag.
    /// No DTLS-SRTP code point.
    Aes256CmHmacSha1_80 = 0x0003,
    /// `AES_256_CM_HMAC_SHA1_32` (RFC 6188): AES-256 counter mode with a 32-bit HMAC-SHA1 tag
    /// on SRTP (80 bits on SRTCP). No DTLS-SRTP code point.
    Aes256CmHmacSha1_32 = 0x0004,
    /// `SRTP_NULL_HMAC_SHA1_80` (RFC 3711 section 4.1.3, RFC 5764): no encryption, an 80-bit
    /// HMAC-SHA1 tag. RFC 3711 section 5.1 makes the NULL cipher mandatory to implement; it is
    /// never mandatory to use, and WebRTC forbids it (RFC 8827 section 6.5): a peer connection
    /// must not offer this profile.
    NullHmacSha1_80 = 0x0005,
    /// `SRTP_NULL_HMAC_SHA1_32`: no encryption, a 32-bit HMAC-SHA1 tag on SRTP (80 bits on
    /// SRTCP). See [`NullHmacSha1_80`](Self::NullHmacSha1_80).
    NullHmacSha1_32 = 0x0006,
    /// `SRTP_AEAD_AES_128_GCM`: AES-128 in GCM, which authenticates as part of encryption
    /// rather than with a separate HMAC.
    AeadAes128Gcm = 0x0007,
    /// `SRTP_AEAD_AES_256_GCM`: AES-256 in GCM.
    AeadAes256Gcm = 0x0008,
    /// `AES_192_CM_HMAC_SHA1_80` (RFC 6188): AES-192 counter mode with an 80-bit HMAC-SHA1 tag.
    /// No DTLS-SRTP code point.
    Aes192CmHmacSha1_80 = 0x00F1,
    /// `AES_192_CM_HMAC_SHA1_32` (RFC 6188): AES-192 counter mode with a 32-bit HMAC-SHA1 tag
    /// on SRTP (80 bits on SRTCP). No DTLS-SRTP code point.
    Aes192CmHmacSha1_32 = 0x00F2,
}

impl ProtectionProfile {
    /// Returns the provider operations required to construct this protection profile.
    #[must_use]
    pub const fn required_crypto_algorithms(self) -> &'static [CryptoAlgorithm] {
        match self {
            Self::Aes128CmHmacSha1_32 | Self::Aes128CmHmacSha1_80 => AES_128_CM_REQUIREMENTS,
            Self::Aes256CmHmacSha1_32 | Self::Aes256CmHmacSha1_80 => AES_256_CM_REQUIREMENTS,
            Self::Aes192CmHmacSha1_32 | Self::Aes192CmHmacSha1_80 => AES_192_CM_REQUIREMENTS,
            Self::NullHmacSha1_32 | Self::NullHmacSha1_80 => NULL_REQUIREMENTS,
            Self::AeadAes128Gcm => AEAD_AES_128_GCM_REQUIREMENTS,
            Self::AeadAes256Gcm => AEAD_AES_256_GCM_REQUIREMENTS,
        }
    }

    /// Validates that `crypto` implements every operation required by this profile.
    pub fn ensure_crypto_supported(self, crypto: &dyn RTCCrypto) -> Result<()> {
        for algorithm in self.required_crypto_algorithms() {
            if !crypto.supports(*algorithm) {
                return Err(Error::Crypto(format!(
                    "SRTP protection profile {self:?} requires unsupported algorithm {algorithm:?}"
                )));
            }
        }
        Ok(())
    }

    /// Every profile this crate implements.
    pub const ALL: [ProtectionProfile; 10] = [
        Self::Aes128CmHmacSha1_80,
        Self::Aes128CmHmacSha1_32,
        Self::Aes192CmHmacSha1_80,
        Self::Aes192CmHmacSha1_32,
        Self::Aes256CmHmacSha1_80,
        Self::Aes256CmHmacSha1_32,
        Self::NullHmacSha1_80,
        Self::NullHmacSha1_32,
        Self::AeadAes128Gcm,
        Self::AeadAes256Gcm,
    ];

    /// The profile's value in the IANA "DTLS-SRTP Protection Profiles" registry, which is what
    /// the DTLS `use_srtp` extension carries (RFC 5764 section 4.1.2, RFC 7714 section 14.2).
    /// `None` for the RFC 6188 counter-mode suites, which have no assignment.
    #[must_use]
    pub const fn dtls_srtp_id(self) -> Option<u16> {
        match self {
            Self::Aes128CmHmacSha1_80 => Some(0x0001),
            Self::Aes128CmHmacSha1_32 => Some(0x0002),
            Self::NullHmacSha1_80 => Some(0x0005),
            Self::NullHmacSha1_32 => Some(0x0006),
            Self::AeadAes128Gcm => Some(0x0007),
            Self::AeadAes256Gcm => Some(0x0008),
            Self::Aes192CmHmacSha1_80
            | Self::Aes192CmHmacSha1_32
            | Self::Aes256CmHmacSha1_80
            | Self::Aes256CmHmacSha1_32 => None,
        }
    }

    /// The profile a DTLS-SRTP code point names, among the ones this crate implements.
    #[must_use]
    pub const fn from_dtls_srtp_id(id: u16) -> Option<Self> {
        match id {
            0x0001 => Some(Self::Aes128CmHmacSha1_80),
            0x0002 => Some(Self::Aes128CmHmacSha1_32),
            0x0005 => Some(Self::NullHmacSha1_80),
            0x0006 => Some(Self::NullHmacSha1_32),
            0x0007 => Some(Self::AeadAes128Gcm),
            0x0008 => Some(Self::AeadAes256Gcm),
            _ => None,
        }
    }

    /// Whether the profile uses the NULL cipher: packets are authenticated and not encrypted.
    #[must_use]
    pub const fn is_null_cipher(self) -> bool {
        matches!(self, Self::NullHmacSha1_80 | Self::NullHmacSha1_32)
    }

    /// Whether the profile is one of the AEAD (AES-GCM) ones.
    #[must_use]
    pub const fn is_aead(self) -> bool {
        matches!(self, Self::AeadAes128Gcm | Self::AeadAes256Gcm)
    }

    pub(crate) const fn is_aes_cm_or_null(self) -> bool {
        !self.is_aead()
    }

    /// The key derivation PRF: AES-CM with the master key's size (RFC 3711 section 4.3.3,
    /// RFC 6188 section 3.1, RFC 7714 section 11).
    pub(crate) const fn prf(self) -> Prf {
        match self {
            Self::Aes128CmHmacSha1_80
            | Self::Aes128CmHmacSha1_32
            | Self::NullHmacSha1_80
            | Self::NullHmacSha1_32
            | Self::AeadAes128Gcm => Prf::Aes128,
            Self::Aes192CmHmacSha1_80 | Self::Aes192CmHmacSha1_32 => Prf::Aes192,
            Self::Aes256CmHmacSha1_80 | Self::Aes256CmHmacSha1_32 | Self::AeadAes256Gcm => {
                Prf::Aes256
            }
        }
    }

    /// How many packets one master key protects unless key management says otherwise: 2^48
    /// SRTP and 2^31 SRTCP packets (RFC 3711 section 9.2, RFC 7714 section 12), and 2^31 of
    /// each for the RFC 6188 suites (section 4, "default key lifetime").
    #[must_use]
    pub const fn default_key_lifetime(self) -> KeyLifetime {
        match self {
            Self::Aes192CmHmacSha1_80
            | Self::Aes192CmHmacSha1_32
            | Self::Aes256CmHmacSha1_80
            | Self::Aes256CmHmacSha1_32 => KeyLifetime {
                srtp_packets: 1 << 31,
                srtcp_packets: 1 << 31,
            },
            _ => KeyLifetime::MAX,
        }
    }

    /// The master key length in bytes for this profile.
    ///
    /// The NULL-cipher profiles take a 128-bit master key like the AES-128 ones: their session
    /// authentication keys come from the AES-CM PRF (RFC 5764 section 4.1.2).
    pub fn key_len(&self) -> usize {
        self.prf().key_len()
    }

    /// The master salt length in bytes for this profile.
    pub fn salt_len(&self) -> usize {
        if self.is_aead() { 12 } else { 14 }
    }

    /// The authentication tag length appended to each SRTP packet, in bytes.
    pub fn rtp_auth_tag_len(&self) -> usize {
        match *self {
            ProtectionProfile::Aes128CmHmacSha1_80
            | ProtectionProfile::Aes192CmHmacSha1_80
            | ProtectionProfile::Aes256CmHmacSha1_80
            | ProtectionProfile::NullHmacSha1_80 => 10,
            ProtectionProfile::Aes128CmHmacSha1_32
            | ProtectionProfile::Aes192CmHmacSha1_32
            | ProtectionProfile::Aes256CmHmacSha1_32
            | ProtectionProfile::NullHmacSha1_32 => 4,
            ProtectionProfile::AeadAes128Gcm | ProtectionProfile::AeadAes256Gcm => 0,
        }
    }

    /// The authentication tag length appended to each SRTCP packet, in bytes. Never below 80
    /// bits for HMAC-SHA1 (RFC 3711 section 5.2), whatever the SRTP tag length.
    pub fn rtcp_auth_tag_len(&self) -> usize {
        if self.is_aead() { 0 } else { 10 }
    }

    /// The AEAD tag length in bytes, for the GCM profiles; `0` for the HMAC-SHA1 ones.
    pub fn aead_auth_tag_len(&self) -> usize {
        if self.is_aead() { 16 } else { 0 }
    }

    /// The HMAC authentication key length in bytes; `0` for the AEAD profiles, which derive
    /// authentication from the cipher itself.
    pub fn auth_key_len(&self) -> usize {
        if self.is_aead() { 0 } else { 20 }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct CapabilityCrypto {
        missing: Option<CryptoAlgorithm>,
    }

    impl RTCCrypto for CapabilityCrypto {
        fn supports(&self, algorithm: CryptoAlgorithm) -> bool {
            self.missing != Some(algorithm)
        }
    }

    const PROFILES: [ProtectionProfile; 10] = ProtectionProfile::ALL;

    #[test]
    fn complete_provider_supports_every_profile() {
        let crypto = CapabilityCrypto { missing: None };
        for profile in PROFILES {
            profile.ensure_crypto_supported(&crypto).unwrap();
        }
    }

    #[test]
    fn every_required_capability_is_enforced() {
        for profile in PROFILES {
            for algorithm in profile.required_crypto_algorithms() {
                let crypto = CapabilityCrypto {
                    missing: Some(*algorithm),
                };
                let error = profile.ensure_crypto_supported(&crypto).unwrap_err();
                let message = error.to_string();
                assert!(message.contains(&format!("{profile:?}")));
                assert!(message.contains(&format!("{algorithm:?}")));
            }
        }
    }
}
