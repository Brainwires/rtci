//! Key derivation (RFC 9605 section 4.4.2) and the sender-key ratchet (section 5.1), on HKDF
//! (RFC 5869) built from the provider's HMAC.

use crypto::{HmacAlgorithm, RTCCrypto, SecretVec};
use zeroize::{Zeroize, Zeroizing};

use crate::cipher_suite::{CipherSuite, NONCE_LEN};
use crate::error::{Error, Result, crypto_error};

const KEY_LABEL: &[u8] = b"SFrame 1.0 Secret key ";
const SALT_LABEL: &[u8] = b"SFrame 1.0 Secret salt ";
const RATCHET_LABEL: &[u8] = b"SFrame 1.0 Ratchet";
/// draft-ietf-avtcore-rtp-sframe-03 section 7, the `info` of the per-SSRC key derivation.
const RTP_STREAM_LABEL: &[u8] = b"SFrame 1.0 RTP Stream";

/// The largest hash output of any suite (SHA-512).
const MAX_HASH_LEN: usize = 64;

/// `HKDF-Extract("", ikm)`: the pseudorandom key, `Nh` bytes at the start of the array.
///
/// RFC 5869 section 2.2: a salt that is not provided is `Nh` zero bytes.
pub(crate) fn hkdf_extract(
    crypto: &dyn RTCCrypto,
    algorithm: HmacAlgorithm,
    ikm: &[u8],
) -> Result<Zeroizing<[u8; MAX_HASH_LEN]>> {
    let hash_len = algorithm.output_len();
    let salt = [0u8; MAX_HASH_LEN];
    let mut prk = Zeroizing::new([0u8; MAX_HASH_LEN]);
    crypto
        .new_hmac(algorithm, &salt[..hash_len])
        .map_err(crypto_error)?
        .sign(&[ikm], &mut prk[..hash_len])
        .map_err(crypto_error)?;
    Ok(prk)
}

/// `HKDF-Extract(salt, ikm)` (RFC 5869 section 2.2) with a salt given: the pseudorandom key,
/// `Nh` bytes at the start of the array.
pub(crate) fn hkdf_extract_salted(
    crypto: &dyn RTCCrypto,
    algorithm: HmacAlgorithm,
    salt: &[u8],
    ikm: &[u8],
) -> Result<Zeroizing<[u8; MAX_HASH_LEN]>> {
    let hash_len = algorithm.output_len();
    let mut prk = Zeroizing::new([0u8; MAX_HASH_LEN]);
    crypto
        .new_hmac(algorithm, salt)
        .map_err(crypto_error)?
        .sign(&[ikm], &mut prk[..hash_len])
        .map_err(crypto_error)?;
    Ok(prk)
}

/// `HKDF-Expand(prk, info, out.len())`, with `info` given in parts.
///
/// RFC 5869 section 2.3: `T(n) = HMAC(prk, T(n-1) | info | n)`, and the output is the first
/// bytes of `T(1) | T(2) | ...`. No more than 255 blocks may be asked for; every SFrame output
/// is one or two.
pub(crate) fn hkdf_expand(
    crypto: &dyn RTCCrypto,
    algorithm: HmacAlgorithm,
    prk: &[u8],
    info: &[&[u8]],
    out: &mut [u8],
) -> Result<()> {
    let hash_len = algorithm.output_len();
    debug_assert!(out.len() <= 255 * hash_len);
    let mut mac = crypto.new_hmac(algorithm, prk).map_err(crypto_error)?;
    let mut block = Zeroizing::new([0u8; MAX_HASH_LEN]);
    let mut previous = Zeroizing::new([0u8; MAX_HASH_LEN]);
    let mut previous_len = 0;
    for (index, chunk) in out.chunks_mut(hash_len).enumerate() {
        let counter = [u8::try_from(index + 1).map_err(|_| Error::KeyIdLayout)?];
        let mut input: Vec<&[u8]> = Vec::with_capacity(info.len() + 2);
        input.push(&previous[..previous_len]);
        input.extend_from_slice(info);
        input.push(&counter);
        mac.sign(&input, &mut block[..hash_len])
            .map_err(crypto_error)?;
        chunk.copy_from_slice(&block[..chunk.len()]);
        previous[..hash_len].copy_from_slice(&block[..hash_len]);
        previous_len = hash_len;
    }
    Ok(())
}

/// The key and salt of one KID.
pub(crate) struct KeySalt {
    /// `sframe_key`, `Nk` bytes.
    pub(crate) key: Zeroizing<Vec<u8>>,
    /// `sframe_salt`, `Nn` bytes.
    pub(crate) salt: Zeroizing<[u8; NONCE_LEN]>,
}

/// `derive_key_salt(KID, base_key)` of RFC 9605 section 4.4.2.
///
/// ```text
/// sframe_secret = HKDF-Extract("", base_key)
/// sframe_key  = HKDF-Expand(sframe_secret, "SFrame 1.0 Secret key "  + KID + cipher_suite, Nk)
/// sframe_salt = HKDF-Expand(sframe_secret, "SFrame 1.0 Secret salt " + KID + cipher_suite, Nn)
/// ```
///
/// with the KID as 8 big-endian bytes and the cipher suite as 2.
pub(crate) fn derive_key_salt(
    crypto: &dyn RTCCrypto,
    suite: CipherSuite,
    kid: u64,
    base_key: &[u8],
) -> Result<KeySalt> {
    if base_key.is_empty() {
        return Err(Error::EmptyBaseKey);
    }
    let algorithm = suite.hmac();
    let secret = hkdf_extract(crypto, algorithm, base_key)?;
    let secret = &secret[..suite.hash_len()];
    let kid = kid.to_be_bytes();
    let suite_id = suite.id().to_be_bytes();

    let mut key = Zeroizing::new(vec![0u8; suite.key_len()]);
    hkdf_expand(
        crypto,
        algorithm,
        secret,
        &[KEY_LABEL, &kid, &suite_id],
        &mut key,
    )?;
    let mut salt = Zeroizing::new([0u8; NONCE_LEN]);
    hkdf_expand(
        crypto,
        algorithm,
        secret,
        &[SALT_LABEL, &kid, &suite_id],
        &mut salt[..],
    )?;
    Ok(KeySalt { key, salt })
}

/// One step of the sender-key ratchet of RFC 9605 section 5.1: the next `base_key`, `Nh` bytes.
///
/// ```text
/// base_key[i+1] = HKDF-Expand(HKDF-Extract("", base_key[i]), "SFrame 1.0 Ratchet", Nh)
/// ```
///
/// The step is one-way: a receiver added after it cannot recover `base_key[i]`.
pub fn ratchet_base_key(
    crypto: &dyn RTCCrypto,
    suite: CipherSuite,
    base_key: &[u8],
) -> Result<SecretVec> {
    if base_key.is_empty() {
        return Err(Error::EmptyBaseKey);
    }
    let algorithm = suite.hmac();
    let secret = hkdf_extract(crypto, algorithm, base_key)?;
    let mut next = vec![0u8; suite.hash_len()];
    let expanded = hkdf_expand(
        crypto,
        algorithm,
        &secret[..suite.hash_len()],
        &[RATCHET_LABEL],
        &mut next,
    );
    if let Err(error) = expanded {
        next.zeroize();
        return Err(error);
    }
    Ok(SecretVec::new(next))
}

/// draft-ietf-avtcore-rtp-sframe-03 section 7, the per-SSRC key of an RTP stream (`Nh` bytes),
/// the initial `base_key` of that SSRC's SFrame keys (and of its ratchet, section 8):
///
/// ```text
/// ssrc_key = HKDF-Expand(HKDF-Extract(SSRC, base_key), "SFrame 1.0 RTP Stream", Nh)
/// ```
///
/// The SSRC is the salt, as 4 bytes big-endian; the suite is the one the key is used with.
/// Streams that share a `base_key` then never share a key, so their independent counters
/// cannot reuse a nonce (section 9.5).
pub fn derive_ssrc_key(
    crypto: &dyn RTCCrypto,
    suite: CipherSuite,
    base_key: &[u8],
    ssrc: u32,
) -> Result<SecretVec> {
    if base_key.is_empty() {
        return Err(Error::EmptyBaseKey);
    }
    let algorithm = suite.hmac();
    let prk = hkdf_extract_salted(crypto, algorithm, &ssrc.to_be_bytes(), base_key)?;
    let mut key = vec![0u8; suite.hash_len()];
    let expanded = hkdf_expand(
        crypto,
        algorithm,
        &prk[..suite.hash_len()],
        &[RTP_STREAM_LABEL],
        &mut key,
    );
    if let Err(error) = expanded {
        key.zeroize();
        return Err(error);
    }
    Ok(SecretVec::new(key))
}
