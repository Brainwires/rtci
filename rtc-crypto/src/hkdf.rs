//! HKDF (RFC 5869) and the TLS 1.3 `HKDF-Expand-Label` (RFC 8446 section 7.1), built on the
//! provider's HMAC.
//!
//! HKDF is HMAC and nothing else, so it needs no provider operation of its own: whatever
//! implements [`RTCCrypto::new_hmac`] for a hash has HKDF for it, a downstream provider
//! included. The outputs are key material and come back as [`SecretVec`], which zeroizes.

use crate::{CryptoError, HmacAlgorithm, RTCCrypto, SecretVec};
use zeroize::Zeroizing;

/// `HKDF-Extract(salt, IKM)` (RFC 5869 section 2.2): the pseudorandom key, one digest long.
///
/// An empty `salt` stands for a string of zeros as long as the digest, as the RFC defines;
/// HMAC pads its key with zeros, so the two are the same key.
pub fn hkdf_extract(
    crypto: &dyn RTCCrypto,
    algorithm: HmacAlgorithm,
    salt: &[u8],
    input_key_material: &[u8],
) -> Result<SecretVec, CryptoError> {
    let mut mac = crypto.new_hmac(algorithm, salt)?;
    let mut pseudorandom_key = vec![0u8; mac.output_len()];
    mac.sign(&[input_key_material], &mut pseudorandom_key)?;
    Ok(SecretVec::new(pseudorandom_key))
}

/// `HKDF-Expand(PRK, info, L)` (RFC 5869 section 2.3), `info` given in pieces.
///
/// # Errors
///
/// [`CryptoError::OutputTooSmall`] when `length` is more than 255 digests, the most HKDF
/// defines.
pub fn hkdf_expand(
    crypto: &dyn RTCCrypto,
    algorithm: HmacAlgorithm,
    pseudorandom_key: &[u8],
    info: &[&[u8]],
    length: usize,
) -> Result<SecretVec, CryptoError> {
    let digest_len = algorithm.output_len();
    if length > 255 * digest_len {
        return Err(CryptoError::OutputTooSmall {
            required: length,
            actual: 255 * digest_len,
        });
    }
    let mut mac = crypto.new_hmac(algorithm, pseudorandom_key)?;
    // Sized up front, so that growing never leaves a copy of key material behind.
    let mut output = Zeroizing::new(Vec::with_capacity(
        length.next_multiple_of(digest_len.max(1)),
    ));
    let mut previous = Zeroizing::new(Vec::with_capacity(digest_len));
    let mut counter = 1u8;
    while output.len() < length {
        let counter_byte = [counter];
        let mut input: Vec<&[u8]> = Vec::with_capacity(info.len() + 2);
        input.push(&previous);
        input.extend_from_slice(info);
        input.push(&counter_byte);
        let mut block = Zeroizing::new(vec![0u8; digest_len]);
        mac.sign(&input, &mut block)?;
        output.extend_from_slice(&block);
        previous = block;
        counter = counter.wrapping_add(1);
    }
    output.truncate(length);
    Ok(SecretVec::new(std::mem::take(&mut *output)))
}

/// `HKDF-Expand-Label(Secret, Label, Context, Length)` (RFC 8446 section 7.1): HKDF-Expand
/// with the `HkdfLabel` structure as info. `prefix` is what the label is prefixed with on the
/// wire: `"tls13 "` for TLS 1.3 and `"dtls13"` for DTLS 1.3 (RFC 9147 section 5.9).
///
/// # Errors
///
/// [`CryptoError::Provider`] when the prefixed label or the context is longer than the
/// one-byte length the structure gives each.
pub fn hkdf_expand_label(
    crypto: &dyn RTCCrypto,
    algorithm: HmacAlgorithm,
    secret: &[u8],
    prefix: &str,
    label: &str,
    context: &[u8],
    length: usize,
) -> Result<SecretVec, CryptoError> {
    let label_len = prefix.len() + label.len();
    if label_len > 255 || context.len() > 255 || length > usize::from(u16::MAX) {
        return Err(CryptoError::Provider(
            "HkdfLabel field is too long".to_owned(),
        ));
    }
    let length_bytes = (length as u16).to_be_bytes();
    let label_len_byte = [label_len as u8];
    let context_len_byte = [context.len() as u8];
    hkdf_expand(
        crypto,
        algorithm,
        secret,
        &[
            &length_bytes,
            &label_len_byte,
            prefix.as_bytes(),
            label.as_bytes(),
            &context_len_byte,
            context,
        ],
        length,
    )
}
