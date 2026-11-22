//! The AEAD of a cipher suite: AES-GCM from the provider, or the AES-CTR with HMAC construction
//! of RFC 9605 section 4.5.1.

use crypto::{AeadCipher, Mac, RTCCrypto, StreamCipher, constant_time_eq};
use zeroize::{Zeroize, Zeroizing};

use crate::cipher_suite::{AeadKind, CipherSuite, NONCE_LEN};
use crate::error::{Error, Result, crypto_error};

/// The largest HMAC output of any suite (SHA-512).
const MAX_MAC_LEN: usize = 64;

/// A keyed AEAD for one `sframe_key`.
///
/// The associated data is given in two parts, the SFrame header and the application's metadata
/// (`aad = header + metadata`), so the caller never has to join them. The tag is detached:
/// RFC 9605 appends it to the ciphertext, and the caller owns that layout.
pub(crate) enum SuiteAead {
    /// AES-GCM with a 16-byte tag.
    Gcm(Box<dyn AeadCipher>),
    /// AES-CTR for confidentiality, a truncated HMAC over lengths, nonce, AAD and ciphertext
    /// for authentication (encrypt-then-MAC).
    CtrHmac {
        cipher: Box<dyn StreamCipher>,
        mac: Box<dyn Mac>,
        tag_len: usize,
    },
}

impl SuiteAead {
    /// Keys the suite's AEAD with `sframe_key` (`Nk` bytes).
    ///
    /// For AES-CTR with HMAC the key splits into its subkeys (`derive_subkeys`): the first
    /// `Nka` bytes encrypt, the remaining `Nh` authenticate.
    pub(crate) fn new(crypto: &dyn RTCCrypto, suite: CipherSuite, key: &[u8]) -> Result<Self> {
        if key.len() != suite.key_len() {
            return Err(Error::Crypto(crypto::CryptoError::InvalidKeyLength {
                expected: suite.key_len(),
                actual: key.len(),
            }));
        }
        match suite.aead_kind() {
            AeadKind::Gcm(algorithm) => {
                let aead = crypto.new_aead(algorithm, key).map_err(crypto_error)?;
                if aead.tag_len() != suite.tag_len() {
                    return Err(Error::Crypto(crypto::CryptoError::InvalidTagLength {
                        expected: suite.tag_len(),
                        actual: aead.tag_len(),
                    }));
                }
                Ok(Self::Gcm(aead))
            }
            AeadKind::CtrHmac(algorithm) => {
                let (enc_key, auth_key) = key.split_at(key.len() - suite.hash_len());
                let mac = crypto
                    .new_hmac(suite.hmac(), auth_key)
                    .map_err(crypto_error)?;
                if mac.output_len() != suite.hash_len() || suite.hash_len() > MAX_MAC_LEN {
                    return Err(Error::Crypto(crypto::CryptoError::InvalidTagLength {
                        expected: suite.hash_len(),
                        actual: mac.output_len(),
                    }));
                }
                Ok(Self::CtrHmac {
                    cipher: crypto
                        .new_stream_cipher(algorithm, enc_key)
                        .map_err(crypto_error)?,
                    mac,
                    tag_len: suite.tag_len(),
                })
            }
        }
    }

    /// `AEAD.Encrypt`: encrypts `data` in place and writes the tag (`Nt` bytes) to `tag`.
    ///
    /// `scratch` is reused across calls to join the two AAD parts for a native AEAD.
    pub(crate) fn seal(
        &mut self,
        nonce: &[u8; NONCE_LEN],
        header: &[u8],
        metadata: &[u8],
        scratch: &mut Vec<u8>,
        data: &mut [u8],
        tag: &mut [u8],
    ) -> Result<()> {
        match self {
            Self::Gcm(aead) => aead
                .seal_in_place(nonce, joined(header, metadata, scratch), data, tag)
                .map_err(crypto_error),
            Self::CtrHmac {
                cipher,
                mac,
                tag_len,
            } => {
                check_tag_len(*tag_len, tag.len())?;
                cipher
                    .apply_keystream(&initial_counter(nonce)[..], data)
                    .map_err(crypto_error)?;
                let mut full = [0u8; MAX_MAC_LEN];
                let computed = compute_tag_into(
                    mac.as_mut(),
                    *tag_len,
                    nonce,
                    header,
                    metadata,
                    data,
                    &mut full,
                );
                if computed.is_ok() {
                    tag.copy_from_slice(&full[..*tag_len]);
                }
                full.zeroize();
                computed.map(|_| ())
            }
        }
    }

    /// `AEAD.Decrypt`: checks `tag` and decrypts `data` in place.
    ///
    /// On an error `data` holds no plaintext the caller may use: its content is unspecified and
    /// the caller erases it. The AES-CTR construction runs the cipher whether or not the tag
    /// matched, so that a forged ciphertext costs the same as a valid one (RFC 9605 section
    /// 4.4.4).
    pub(crate) fn open(
        &mut self,
        nonce: &[u8; NONCE_LEN],
        header: &[u8],
        metadata: &[u8],
        scratch: &mut Vec<u8>,
        data: &mut [u8],
        tag: &[u8],
    ) -> Result<()> {
        match self {
            Self::Gcm(aead) => aead
                .open_in_place(nonce, joined(header, metadata, scratch), data, tag)
                .map_err(crypto_error),
            Self::CtrHmac {
                cipher,
                mac,
                tag_len,
            } => {
                check_tag_len(*tag_len, tag.len())?;
                let mut full = [0u8; MAX_MAC_LEN];
                let mac_len = compute_tag_into(
                    mac.as_mut(),
                    *tag_len,
                    nonce,
                    header,
                    metadata,
                    data,
                    &mut full,
                );
                let authentic = match &mac_len {
                    Ok(_) => constant_time_eq(&full[..*tag_len], tag),
                    Err(_) => false,
                };
                full.zeroize();
                let decrypted = cipher
                    .apply_keystream(&initial_counter(nonce)[..], data)
                    .map_err(crypto_error);
                mac_len?;
                decrypted?;
                if authentic {
                    Ok(())
                } else {
                    Err(Error::AuthenticationFailed)
                }
            }
        }
    }
}

fn check_tag_len(expected: usize, actual: usize) -> Result<()> {
    if expected == actual {
        Ok(())
    } else {
        Err(Error::Crypto(crypto::CryptoError::InvalidTagLength {
            expected,
            actual,
        }))
    }
}

/// `header + metadata` as one slice: `header` itself when there is no metadata, else both
/// copied into `scratch` (whose allocation is kept between calls).
fn joined<'a>(header: &'a [u8], metadata: &[u8], scratch: &'a mut Vec<u8>) -> &'a [u8] {
    if metadata.is_empty() {
        return header;
    }
    scratch.clear();
    scratch.extend_from_slice(header);
    scratch.extend_from_slice(metadata);
    scratch
}

/// `nonce + 0x00000000`: the first counter block of AES-CTR.
fn initial_counter(nonce: &[u8; NONCE_LEN]) -> Zeroizing<[u8; 16]> {
    let mut counter = Zeroizing::new([0u8; 16]);
    counter[..NONCE_LEN].copy_from_slice(nonce);
    counter
}

/// `compute_tag` of RFC 9605 section 4.5.1, untruncated, into `full`. Returns the HMAC's
/// output length.
///
/// ```text
/// auth_data = aad_len + ct_len + tag_len + nonce + aad + ct     (lengths as 8 big-endian bytes)
/// tag = HMAC(auth_key, auth_data)
/// ```
fn compute_tag_into(
    mac: &mut dyn Mac,
    tag_len: usize,
    nonce: &[u8; NONCE_LEN],
    header: &[u8],
    metadata: &[u8],
    ciphertext: &[u8],
    full: &mut [u8; MAX_MAC_LEN],
) -> Result<usize> {
    let mut lengths = [0u8; 24];
    lengths[..8].copy_from_slice(&((header.len() + metadata.len()) as u64).to_be_bytes());
    lengths[8..16].copy_from_slice(&(ciphertext.len() as u64).to_be_bytes());
    lengths[16..].copy_from_slice(&(tag_len as u64).to_be_bytes());
    let mac_len = mac.output_len();
    mac.sign(
        &[&lengths, nonce, header, metadata, ciphertext],
        &mut full[..mac_len],
    )
    .map_err(crypto_error)?;
    Ok(mac_len)
}
