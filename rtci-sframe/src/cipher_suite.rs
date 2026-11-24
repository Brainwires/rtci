use std::fmt;
use std::str::FromStr;

use crypto::{AeadAlgorithm, HmacAlgorithm, StreamCipherAlgorithm};

/// The size in bytes of every SFrame nonce (`AEAD.Nn`): 12 for all registered suites.
pub const NONCE_LEN: usize = 12;

/// An SFrame cipher suite: the hash used for key derivation and the AEAD used for the frames.
///
/// The first five are the suites of RFC 9605 section 4.5. The three `Aes256CtrHmacSha512`
/// suites are the AES-256 counterparts of the AES-CTR construction (IANA "SFrame Cipher Suites"
/// values 0x0006 to 0x0008, from draft-barnes-sframe-iana-256), which the W3C Encoded Transform
/// API lists in `SFrameCipherSuite`.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CipherSuite {
    /// `AES_128_CTR_HMAC_SHA256_80` (0x0001): AES-128-CTR with HMAC-SHA256, 80-bit tag.
    Aes128CtrHmacSha256_80,
    /// `AES_128_CTR_HMAC_SHA256_64` (0x0002): AES-128-CTR with HMAC-SHA256, 64-bit tag.
    Aes128CtrHmacSha256_64,
    /// `AES_128_CTR_HMAC_SHA256_32` (0x0003): AES-128-CTR with HMAC-SHA256, 32-bit tag.
    Aes128CtrHmacSha256_32,
    /// `AES_128_GCM_SHA256_128` (0x0004): AES-128-GCM, keys derived with SHA-256.
    Aes128GcmSha256_128,
    /// `AES_256_GCM_SHA512_128` (0x0005): AES-256-GCM, keys derived with SHA-512.
    Aes256GcmSha512_128,
    /// `AES_256_CTR_HMAC_SHA512_80` (0x0006): AES-256-CTR with HMAC-SHA512, 80-bit tag.
    Aes256CtrHmacSha512_80,
    /// `AES_256_CTR_HMAC_SHA512_64` (0x0007): AES-256-CTR with HMAC-SHA512, 64-bit tag.
    Aes256CtrHmacSha512_64,
    /// `AES_256_CTR_HMAC_SHA512_32` (0x0008): AES-256-CTR with HMAC-SHA512, 32-bit tag.
    Aes256CtrHmacSha512_32,
}

/// How a suite encrypts: a native AEAD, or the AES-CTR with HMAC construction of RFC 9605
/// section 4.5.1.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AeadKind {
    Gcm(AeadAlgorithm),
    CtrHmac(StreamCipherAlgorithm),
}

impl CipherSuite {
    /// Every suite this crate implements, in registry order.
    pub const ALL: [CipherSuite; 8] = [
        Self::Aes128CtrHmacSha256_80,
        Self::Aes128CtrHmacSha256_64,
        Self::Aes128CtrHmacSha256_32,
        Self::Aes128GcmSha256_128,
        Self::Aes256GcmSha512_128,
        Self::Aes256CtrHmacSha512_80,
        Self::Aes256CtrHmacSha512_64,
        Self::Aes256CtrHmacSha512_32,
    ];

    /// The suite's value in the IANA "SFrame Cipher Suites" registry (RFC 9605 section 8.1).
    /// It is part of the key derivation labels.
    #[must_use]
    pub const fn id(self) -> u16 {
        match self {
            Self::Aes128CtrHmacSha256_80 => 0x0001,
            Self::Aes128CtrHmacSha256_64 => 0x0002,
            Self::Aes128CtrHmacSha256_32 => 0x0003,
            Self::Aes128GcmSha256_128 => 0x0004,
            Self::Aes256GcmSha512_128 => 0x0005,
            Self::Aes256CtrHmacSha512_80 => 0x0006,
            Self::Aes256CtrHmacSha512_64 => 0x0007,
            Self::Aes256CtrHmacSha512_32 => 0x0008,
        }
    }

    /// The suite with this registry value, if this crate implements it. 0x0000 is reserved and
    /// 0xF000 to 0xFFFF are for private use: neither names a suite.
    #[must_use]
    pub const fn from_id(id: u16) -> Option<Self> {
        Some(match id {
            0x0001 => Self::Aes128CtrHmacSha256_80,
            0x0002 => Self::Aes128CtrHmacSha256_64,
            0x0003 => Self::Aes128CtrHmacSha256_32,
            0x0004 => Self::Aes128GcmSha256_128,
            0x0005 => Self::Aes256GcmSha512_128,
            0x0006 => Self::Aes256CtrHmacSha512_80,
            0x0007 => Self::Aes256CtrHmacSha512_64,
            0x0008 => Self::Aes256CtrHmacSha512_32,
            _ => return None,
        })
    }

    /// The suite's registered name, which is also its `SFrameCipherSuite` value in the W3C
    /// Encoded Transform API.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Aes128CtrHmacSha256_80 => "AES_128_CTR_HMAC_SHA256_80",
            Self::Aes128CtrHmacSha256_64 => "AES_128_CTR_HMAC_SHA256_64",
            Self::Aes128CtrHmacSha256_32 => "AES_128_CTR_HMAC_SHA256_32",
            Self::Aes128GcmSha256_128 => "AES_128_GCM_SHA256_128",
            Self::Aes256GcmSha512_128 => "AES_256_GCM_SHA512_128",
            Self::Aes256CtrHmacSha512_80 => "AES_256_CTR_HMAC_SHA512_80",
            Self::Aes256CtrHmacSha512_64 => "AES_256_CTR_HMAC_SHA512_64",
            Self::Aes256CtrHmacSha512_32 => "AES_256_CTR_HMAC_SHA512_32",
        }
    }

    /// `Hash.Nh`: the output size in bytes of the suite's hash function.
    #[must_use]
    pub const fn hash_len(self) -> usize {
        match self {
            Self::Aes128CtrHmacSha256_80
            | Self::Aes128CtrHmacSha256_64
            | Self::Aes128CtrHmacSha256_32
            | Self::Aes128GcmSha256_128 => 32,
            Self::Aes256GcmSha512_128
            | Self::Aes256CtrHmacSha512_80
            | Self::Aes256CtrHmacSha512_64
            | Self::Aes256CtrHmacSha512_32 => 64,
        }
    }

    /// `AEAD.Nka`: the AES key size in bytes of a suite built on AES-CTR with HMAC; `None` for
    /// the GCM suites.
    #[must_use]
    pub const fn aes_ctr_key_len(self) -> Option<usize> {
        match self {
            Self::Aes128CtrHmacSha256_80
            | Self::Aes128CtrHmacSha256_64
            | Self::Aes128CtrHmacSha256_32 => Some(16),
            Self::Aes256CtrHmacSha512_80
            | Self::Aes256CtrHmacSha512_64
            | Self::Aes256CtrHmacSha512_32 => Some(32),
            Self::Aes128GcmSha256_128 | Self::Aes256GcmSha512_128 => None,
        }
    }

    /// `AEAD.Nk`: the size in bytes of the derived `sframe_key`. For the AES-CTR suites it is
    /// `Nka + Nh` (an encryption subkey and an authentication subkey). It is also the length an
    /// MLS exporter is asked for (RFC 9605 section 5.2).
    #[must_use]
    pub const fn key_len(self) -> usize {
        match self {
            Self::Aes128GcmSha256_128 => 16,
            Self::Aes256GcmSha512_128 => 32,
            Self::Aes128CtrHmacSha256_80
            | Self::Aes128CtrHmacSha256_64
            | Self::Aes128CtrHmacSha256_32 => 16 + 32,
            Self::Aes256CtrHmacSha512_80
            | Self::Aes256CtrHmacSha512_64
            | Self::Aes256CtrHmacSha512_32 => 32 + 64,
        }
    }

    /// `AEAD.Nn`: the nonce size in bytes.
    #[must_use]
    pub const fn nonce_len(self) -> usize {
        NONCE_LEN
    }

    /// `AEAD.Nt`: the size in bytes of the authentication tag the suite appends.
    #[must_use]
    pub const fn tag_len(self) -> usize {
        match self {
            Self::Aes128CtrHmacSha256_80 | Self::Aes256CtrHmacSha512_80 => 10,
            Self::Aes128CtrHmacSha256_64 | Self::Aes256CtrHmacSha512_64 => 8,
            Self::Aes128CtrHmacSha256_32 | Self::Aes256CtrHmacSha512_32 => 4,
            Self::Aes128GcmSha256_128 | Self::Aes256GcmSha512_128 => 16,
        }
    }

    /// The HMAC that HKDF runs on, and that the AES-CTR suites authenticate with.
    pub(crate) const fn hmac(self) -> HmacAlgorithm {
        match self.hash_len() {
            32 => HmacAlgorithm::Sha256,
            _ => HmacAlgorithm::Sha512,
        }
    }

    pub(crate) const fn aead_kind(self) -> AeadKind {
        match self {
            Self::Aes128GcmSha256_128 => AeadKind::Gcm(AeadAlgorithm::Aes128Gcm),
            Self::Aes256GcmSha512_128 => AeadKind::Gcm(AeadAlgorithm::Aes256Gcm),
            Self::Aes128CtrHmacSha256_80
            | Self::Aes128CtrHmacSha256_64
            | Self::Aes128CtrHmacSha256_32 => AeadKind::CtrHmac(StreamCipherAlgorithm::Aes128Ctr),
            Self::Aes256CtrHmacSha512_80
            | Self::Aes256CtrHmacSha512_64
            | Self::Aes256CtrHmacSha512_32 => AeadKind::CtrHmac(StreamCipherAlgorithm::Aes256Ctr),
        }
    }
}

impl fmt::Display for CipherSuite {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.name())
    }
}

/// The name is not that of a cipher suite this crate implements.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("unknown SFrame cipher suite name")]
pub struct UnknownCipherSuite;

impl FromStr for CipherSuite {
    type Err = UnknownCipherSuite;

    /// Parses a registered name, exactly as registered.
    fn from_str(name: &str) -> Result<Self, Self::Err> {
        Self::ALL
            .into_iter()
            .find(|suite| suite.name() == name)
            .ok_or(UnknownCipherSuite)
    }
}

impl TryFrom<u16> for CipherSuite {
    type Error = UnknownCipherSuite;

    fn try_from(id: u16) -> Result<Self, Self::Error> {
        Self::from_id(id).ok_or(UnknownCipherSuite)
    }
}

impl From<CipherSuite> for u16 {
    fn from(suite: CipherSuite) -> Self {
        suite.id()
    }
}
