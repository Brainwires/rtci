use crypto::{BlockCipherAlgorithm, RTCCrypto, SecretVec, StreamCipherAlgorithm};

use crate::cipher::crypto_error;
use shared::error::{Error, Result};

pub const LABEL_SRTP_ENCRYPTION: u8 = 0x00;
pub const LABEL_SRTP_AUTHENTICATION_TAG: u8 = 0x01;
pub const LABEL_SRTP_SALT: u8 = 0x02;
pub const LABEL_SRTCP_ENCRYPTION: u8 = 0x03;
pub const LABEL_SRTCP_AUTHENTICATION_TAG: u8 = 0x04;
pub const LABEL_SRTCP_SALT: u8 = 0x05;
/// RFC 6904 section 3: k_he, the header extension encryption key.
pub const LABEL_SRTP_HEADER_ENCRYPTION: u8 = 0x06;
/// RFC 6904 section 3: k_hs, the header extension salting key.
pub const LABEL_SRTP_HEADER_SALT: u8 = 0x07;

pub(crate) const SRTCP_INDEX_SIZE: usize = 4;

/// The PRF input `x` is 112 bits (RFC 3711 section 4.3.3); a shorter master salt (the 96-bit
/// one of RFC 7714) is padded with zeros on the right.
const PRF_SALT_LEN: usize = 14;
const AES_BLOCK_LEN: usize = 16;
/// `index DIV kdr` is a 48-bit field of the key id (RFC 3711 section 4.3.1).
const MAX_INDEX_OVER_KDR: u64 = (1 << 48) - 1;
/// PRF_n produces at most 2^16 blocks (RFC 3711 section 4.3.3: n <= 2^23 bits).
const MAX_PRF_BLOCKS: usize = 1 << 16;

/// The SRTP key derivation PRFs: AES in counter mode keyed with the master key (RFC 3711
/// section 4.3.3 for AES-128; RFC 6188 section 3 for AES-192 and AES-256).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Prf {
    /// `AES_CM_PRF`, RFC 3711.
    Aes128,
    /// `AES_192_CM_PRF`, RFC 6188.
    Aes192,
    /// `AES_256_CM_PRF`, RFC 6188.
    Aes256,
}

impl Prf {
    pub(crate) const fn block_cipher(self) -> BlockCipherAlgorithm {
        match self {
            Prf::Aes128 => BlockCipherAlgorithm::Aes128,
            Prf::Aes192 => BlockCipherAlgorithm::Aes192,
            Prf::Aes256 => BlockCipherAlgorithm::Aes256,
        }
    }

    /// The counter-mode transform of the same key size (the payload cipher of the AES-CM
    /// profiles, and the RFC 6904 header extension keystream of every profile).
    pub(crate) const fn stream_cipher(self) -> StreamCipherAlgorithm {
        match self {
            Prf::Aes128 => StreamCipherAlgorithm::Aes128Ctr,
            Prf::Aes192 => StreamCipherAlgorithm::Aes192Ctr,
            Prf::Aes256 => StreamCipherAlgorithm::Aes256Ctr,
        }
    }

    pub(crate) const fn key_len(self) -> usize {
        match self {
            Prf::Aes128 => 16,
            Prf::Aes192 => 24,
            Prf::Aes256 => 32,
        }
    }
}

/// The SRTP key derivation function (RFC 3711 section 4.3.1):
///
/// ```text
/// key_id = label || (index DIV kdr)        8 + 48 bits
/// x      = key_id XOR master_salt          112 bits
/// key    = PRF_n(master_key, x)            AES-CM blocks of (x * 2^16) + i
/// ```
///
/// `index_over_kdr` is `index DIV key_derivation_rate`, zero when the rate is zero. For the
/// SRTCP labels the index is the 31-bit SRTCP index (section 4.3.2).
pub(crate) fn derive(
    crypto: &dyn RTCCrypto,
    prf: Prf,
    label: u8,
    master_key: &[u8],
    master_salt: &[u8],
    index_over_kdr: u64,
    out_len: usize,
) -> Result<SecretVec> {
    if master_key.len() != prf.key_len() {
        return Err(Error::InvalidMasterKeyLength);
    }
    if master_salt.len() > PRF_SALT_LEN {
        return Err(Error::InvalidMasterSaltLength);
    }
    if index_over_kdr > MAX_INDEX_OVER_KDR {
        return Err(Error::UnsupportedIndexOverKdr);
    }
    let blocks = out_len.div_ceil(AES_BLOCK_LEN);
    if blocks > MAX_PRF_BLOCKS {
        return Err(Error::UnsupportedOutLength);
    }

    let mut x = [0u8; AES_BLOCK_LEN];
    x[..master_salt.len()].copy_from_slice(master_salt);
    x[7] ^= label;
    for (dst, src) in x[8..PRF_SALT_LEN]
        .iter_mut()
        .zip(&index_over_kdr.to_be_bytes()[2..])
    {
        *dst ^= src;
    }

    let mut out = SecretVec::new(vec![0u8; blocks * AES_BLOCK_LEN]);
    for i in 0..blocks {
        let block = &mut out.as_mut()[i * AES_BLOCK_LEN..(i + 1) * AES_BLOCK_LEN];
        x[PRF_SALT_LEN..].copy_from_slice(&(i as u16).to_be_bytes());
        block.copy_from_slice(&x);
        crypto
            .block_encrypt(prf.block_cipher(), master_key, block)
            .map_err(crypto_error)?;
    }
    // Truncated into a fresh allocation; the full blocks are zeroized with `out`.
    Ok(SecretVec::new(out.as_ref()[..out_len].to_vec()))
}

/// `AES_CM_PRF` (RFC 3711 section 4.3.3).
pub(crate) fn aes_cm_key_derivation(
    crypto: &dyn RTCCrypto,
    label: u8,
    master_key: &[u8],
    master_salt: &[u8],
    index_over_kdr: u64,
    out_len: usize,
) -> Result<Vec<u8>> {
    derive(
        crypto,
        Prf::Aes128,
        label,
        master_key,
        master_salt,
        index_over_kdr,
        out_len,
    )
    .map(SecretVec::into_bytes)
}

/// `AES_256_CM_PRF` (RFC 6188 section 3).
pub(crate) fn aes_256_cm_key_derivation(
    crypto: &dyn RTCCrypto,
    label: u8,
    master_key: &[u8],
    master_salt: &[u8],
    index_over_kdr: u64,
    out_len: usize,
) -> Result<Vec<u8>> {
    derive(
        crypto,
        Prf::Aes256,
        label,
        master_key,
        master_salt,
        index_over_kdr,
        out_len,
    )
    .map(SecretVec::into_bytes)
}

/// Generate IV https://tools.ietf.org/html/rfc3711#section-4.1.1
/// where the 128-bit integer value IV SHALL be defined by the SSRC, the
/// SRTP packet index i, and the SRTP session salting key k_s, as below.
/// ROC = a 32-bit unsigned rollover counter (roc), which records how many
/// times the 16-bit RTP sequence number has been reset to zero after
/// passing through 65,535
/// ```text
/// i  = 2^16 * roc + SEQ
/// IV = (salt * 2^16) | (ssrc * 2^64) | (i * 2^16)
/// ```
pub(crate) fn generate_counter(
    sequence_number: u16,
    rollover_counter: u32,
    ssrc: u32,
    session_salt: &[u8],
) -> [u8; 16] {
    assert!(session_salt.len() <= 16);

    let mut counter = [0; 16];

    let ssrc_be = ssrc.to_be_bytes();
    let rollover_be = rollover_counter.to_be_bytes();
    let seq_be = ((sequence_number as u32) << 16).to_be_bytes();

    counter[4..8].copy_from_slice(&ssrc_be);
    counter[8..12].copy_from_slice(&rollover_be);
    counter[12..16].copy_from_slice(&seq_be);

    for i in 0..session_salt.len() {
        counter[i] ^= session_salt[i];
    }

    counter
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::protection_profile::*;

    #[test]
    fn test_valid_session_keys() -> Result<()> {
        let provider = crypto::default_provider().map_err(crypto_error)?;
        // Key Derivation Test Vectors from https://tools.ietf.org/html/rfc3711#appendix-B.3
        let master_key = vec![
            0xE1, 0xF9, 0x7A, 0x0D, 0x3E, 0x01, 0x8B, 0xE0, 0xD6, 0x4F, 0xA3, 0x2C, 0x06, 0xDE,
            0x41, 0x39,
        ];
        let master_salt = vec![
            0x0E, 0xC6, 0x75, 0xAD, 0x49, 0x8A, 0xFE, 0xEB, 0xB6, 0x96, 0x0B, 0x3A, 0xAB, 0xE6,
        ];

        let expected_session_key = vec![
            0xC6, 0x1E, 0x7A, 0x93, 0x74, 0x4F, 0x39, 0xEE, 0x10, 0x73, 0x4A, 0xFE, 0x3F, 0xF7,
            0xA0, 0x87,
        ];
        let expected_session_salt = vec![
            0x30, 0xCB, 0xBC, 0x08, 0x86, 0x3D, 0x8C, 0x85, 0xD4, 0x9D, 0xB3, 0x4A, 0x9A, 0xE1,
        ];
        let expected_session_auth_tag = vec![
            0xCE, 0xBE, 0x32, 0x1F, 0x6F, 0xF7, 0x71, 0x6B, 0x6F, 0xD4, 0xAB, 0x49, 0xAF, 0x25,
            0x6A, 0x15, 0x6D, 0x38, 0xBA, 0xA4,
        ];

        let session_key = aes_cm_key_derivation(
            provider.crypto(),
            LABEL_SRTP_ENCRYPTION,
            &master_key,
            &master_salt,
            0,
            master_key.len(),
        )?;
        assert_eq!(
            session_key, expected_session_key,
            "Session Key:\n{session_key:?} \ndoes not match expected:\n{expected_session_key:?}\nMaster Key:\n{master_key:?}\nMaster Salt:\n{master_salt:?}\n",
        );

        let session_salt = aes_cm_key_derivation(
            provider.crypto(),
            LABEL_SRTP_SALT,
            &master_key,
            &master_salt,
            0,
            master_salt.len(),
        )?;
        assert_eq!(
            session_salt, expected_session_salt,
            "Session Salt {session_salt:?} does not match expected {expected_session_salt:?}"
        );

        let auth_key_len = ProtectionProfile::Aes128CmHmacSha1_80.auth_key_len();

        let session_auth_tag = aes_cm_key_derivation(
            provider.crypto(),
            LABEL_SRTP_AUTHENTICATION_TAG,
            &master_key,
            &master_salt,
            0,
            auth_key_len,
        )?;
        assert_eq!(
            session_auth_tag, expected_session_auth_tag,
            "Session Auth Tag {session_auth_tag:?} does not match expected {expected_session_auth_tag:?}",
        );

        Ok(())
    }

    /// RFC 3711 section 4.3.1: `key_id = label || (index DIV kdr)`, the latter a 48-bit field
    /// in the low octets of the 112-bit `x`. Since `x = key_id XOR master_salt`, deriving with
    /// `index DIV kdr = r` is deriving with zero from a salt that has `r` XORed into its last
    /// six octets.
    #[test]
    fn test_index_over_kdr() -> Result<()> {
        let provider = crypto::default_provider().map_err(crypto_error)?;
        let crypto = provider.crypto();
        for (prf, key_len) in [(Prf::Aes128, 16), (Prf::Aes192, 24), (Prf::Aes256, 32)] {
            let master_key: Vec<u8> = (0..key_len as u8).collect();
            let master_salt: Vec<u8> = (0..14).map(|i| 0xC0 ^ i).collect();
            for r in [1u64, 0x0102_0304_0506, (1 << 48) - 1] {
                let mut salt_with_r = master_salt.clone();
                for (dst, src) in salt_with_r[8..].iter_mut().zip(&r.to_be_bytes()[2..]) {
                    *dst ^= src;
                }
                for label in 0..=LABEL_SRTP_HEADER_SALT {
                    let with_index = derive(crypto, prf, label, &master_key, &master_salt, r, 46)?;
                    let with_salt = derive(crypto, prf, label, &master_key, &salt_with_r, 0, 46)?;
                    assert_eq!(
                        with_index.as_ref(),
                        with_salt.as_ref(),
                        "{prf:?} {label} {r}"
                    );
                    let at_zero = derive(crypto, prf, label, &master_key, &master_salt, 0, 46)?;
                    assert_ne!(with_index.as_ref(), at_zero.as_ref(), "{prf:?} {label} {r}");
                }
            }
            // The field is 48 bits wide.
            assert_eq!(
                derive(crypto, prf, 0, &master_key, &master_salt, 1 << 48, 16).unwrap_err(),
                Error::UnsupportedIndexOverKdr
            );
        }
        Ok(())
    }

    /// The PRF is keyed with a master key of its own size and takes a salt of at most 112 bits.
    #[test]
    fn test_derive_refuses_wrong_key_and_salt_lengths() {
        let provider = crypto::default_provider().unwrap();
        let crypto = provider.crypto();
        assert_eq!(
            derive(crypto, Prf::Aes128, 0, &[0; 32], &[0; 14], 0, 16).unwrap_err(),
            Error::InvalidMasterKeyLength
        );
        assert_eq!(
            derive(crypto, Prf::Aes256, 0, &[0; 16], &[0; 14], 0, 16).unwrap_err(),
            Error::InvalidMasterKeyLength
        );
        assert_eq!(
            derive(crypto, Prf::Aes192, 0, &[0; 24], &[0; 15], 0, 16).unwrap_err(),
            Error::InvalidMasterSaltLength
        );
    }

    #[test]
    fn test_aes_256_cm_key_derivation() -> Result<()> {
        let provider = crypto::default_provider().map_err(crypto_error)?;
        // Key Derivation Test Vectors from https://datatracker.ietf.org/doc/html/rfc6188#section-7.2
        let master_key = vec![
            0xF0, 0xF0, 0x49, 0x14, 0xB5, 0x13, 0xF2, 0x76, 0x3A, 0x1B, 0x1F, 0xA1, 0x30, 0xF1,
            0x0E, 0x29, 0x98, 0xF6, 0xF6, 0xE4, 0x3E, 0x43, 0x09, 0xD1, 0xE6, 0x22, 0xA0, 0xE3,
            0x32, 0xB9, 0xF1, 0xB6,
        ];
        let master_salt = vec![
            0x3B, 0x04, 0x80, 0x3D, 0xE5, 0x1E, 0xE7, 0xC9, 0x64, 0x23, 0xAB, 0x5B, 0x78, 0xD2,
        ];

        let expected_session_key = vec![
            0x5B, 0xA1, 0x06, 0x4E, 0x30, 0xEC, 0x51, 0x61, 0x3C, 0xAD, 0x92, 0x6C, 0x5A, 0x28,
            0xEF, 0x73, 0x1E, 0xC7, 0xFB, 0x39, 0x7F, 0x70, 0xA9, 0x60, 0x65, 0x3C, 0xAF, 0x06,
            0x55, 0x4C, 0xD8, 0xC4,
        ];
        let expected_session_salt = vec![
            0xFA, 0x31, 0x79, 0x16, 0x85, 0xCA, 0x44, 0x4A, 0x9E, 0x07, 0xC6, 0xC6, 0x4E, 0x93,
        ];
        let expected_session_auth_tag = vec![
            0xFD, 0x9C, 0x32, 0xD3, 0x9E, 0xD5, 0xFB, 0xB5, 0xA9, 0xDC, 0x96, 0xB3, 0x08, 0x18,
            0x45, 0x4D, 0x13, 0x13, 0xDC, 0x05,
        ];

        let session_key = aes_256_cm_key_derivation(
            provider.crypto(),
            LABEL_SRTP_ENCRYPTION,
            &master_key,
            &master_salt,
            0,
            master_key.len(),
        )?;
        assert_eq!(
            session_key, expected_session_key,
            "Session Key:\n{session_key:?} \ndoes not match expected:\n{expected_session_key:?}\nMaster Key:\n{master_key:?}\nMaster Salt:\n{master_salt:?}\n",
        );

        let session_salt = aes_256_cm_key_derivation(
            provider.crypto(),
            LABEL_SRTP_SALT,
            &master_key,
            &master_salt,
            0,
            master_salt.len(),
        )?;
        assert_eq!(
            session_salt, expected_session_salt,
            "Session Salt {session_salt:?} does not match expected {expected_session_salt:?}"
        );

        let auth_key_len = ProtectionProfile::Aes128CmHmacSha1_80.auth_key_len();

        let session_auth_tag = aes_256_cm_key_derivation(
            provider.crypto(),
            LABEL_SRTP_AUTHENTICATION_TAG,
            &master_key,
            &master_salt,
            0,
            auth_key_len,
        )?;
        assert_eq!(
            session_auth_tag, expected_session_auth_tag,
            "Session Auth Tag {session_auth_tag:?} does not match expected {expected_session_auth_tag:?}",
        );

        Ok(())
    }
}
