//! RSASSA-PKCS1-v1_5 verification of the DigestInfo form without hash parameters.
//!
//! RFC 5246 section 4.7: "For hash algorithms without parameters (which includes SHA-1), the
//! DigestInfo.AlgorithmIdentifier.parameters field MUST be NULL, but implementations MUST
//! accept both without parameters and with NULL parameters." Both built-in providers verify
//! PKCS#1 v1.5 against the NULL-parameter encoding only (ring `rsa/padding/pkcs1.rs`, AWS-LC
//! `kPKCS1SigPrefixes`) and neither gives the raw RSA public operation, so the other form is
//! verified here: `s^e mod n` (RFC 8017 section 5.2.2, RSAVP1; public values only, nothing
//! secret is involved, so it needs no constant-time arithmetic) and a byte-for-byte comparison
//! with the EMSA-PKCS1-v1_5 encoding (RFC 8017 section 9.2) of the digest whose DigestInfo has
//! no parameters. The encoding is built and compared whole, never parsed, so a signature of
//! any other shape fails (no Bleichenbacher-style lax parsing).

use crate::{CryptoError, HashAlgorithm, SignatureScheme};
use num_bigint::BigUint;
use subtle::ConstantTimeEq;

/// The moduli the providers' PKCS#1 v1.5 verifiers take (ring `RSA_PKCS1_1024_8192_*`).
const MIN_MODULUS_BITS: u64 = 1024;
const MAX_MODULUS_BITS: u64 = 8192;

/// The hash of an RSASSA-PKCS1-v1_5 scheme and the DER of its DigestInfo up to the digest,
/// with an AlgorithmIdentifier of the hash OID alone (no parameters field):
/// `SEQUENCE { SEQUENCE { OID }, OCTET STRING <digest> }`.
fn digest_info_without_parameters(
    scheme: SignatureScheme,
) -> Option<(HashAlgorithm, &'static [u8])> {
    Some(match scheme {
        SignatureScheme::RsaPkcs1Sha1 => (
            HashAlgorithm::Sha1,
            &[
                0x30, 0x1f, 0x30, 0x07, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x04, 0x14,
            ],
        ),
        SignatureScheme::RsaPkcs1Sha256 => (
            HashAlgorithm::Sha256,
            &[
                0x30, 0x2f, 0x30, 0x0b, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
                0x01, 0x04, 0x20,
            ],
        ),
        SignatureScheme::RsaPkcs1Sha384 => (
            HashAlgorithm::Sha384,
            &[
                0x30, 0x3f, 0x30, 0x0b, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
                0x02, 0x04, 0x30,
            ],
        ),
        SignatureScheme::RsaPkcs1Sha512 => (
            HashAlgorithm::Sha512,
            &[
                0x30, 0x4f, 0x30, 0x0b, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
                0x03, 0x04, 0x40,
            ],
        ),
        _ => return None,
    })
}

/// The hash an RSASSA-PKCS1-v1_5 scheme signs with; `None` for any other scheme.
pub fn rsa_pkcs1_hash(scheme: SignatureScheme) -> Option<HashAlgorithm> {
    digest_info_without_parameters(scheme).map(|(hash, _)| hash)
}

/// One DER TLV of tag `tag` at the start of `input`, definite length in its shortest form:
/// its contents and the bytes after it.
fn der_tlv(input: &[u8], tag: u8) -> Result<(&[u8], &[u8]), CryptoError> {
    let bad = || CryptoError::InvalidPublicKey;
    let (&t, rest) = input.split_first().ok_or_else(bad)?;
    if t != tag {
        return Err(bad());
    }
    let (&first, mut rest) = rest.split_first().ok_or_else(bad)?;
    let len = match first {
        0..=0x7f => first as usize,
        0x81 => {
            let (&b, r) = rest.split_first().ok_or_else(bad)?;
            rest = r;
            if b < 0x80 {
                return Err(bad());
            }
            b as usize
        }
        0x82 => {
            if rest.len() < 2 || rest[0] == 0 {
                return Err(bad());
            }
            let len = u16::from_be_bytes([rest[0], rest[1]]) as usize;
            rest = &rest[2..];
            if len < 0x100 {
                return Err(bad());
            }
            len
        }
        _ => return Err(bad()),
    };
    if rest.len() < len {
        return Err(bad());
    }
    Ok((&rest[..len], &rest[len..]))
}

/// A positive DER INTEGER's magnitude.
fn der_positive_integer(input: &[u8]) -> Result<(BigUint, &[u8]), CryptoError> {
    let (contents, rest) = der_tlv(input, 0x02)?;
    let magnitude = match contents {
        [] => return Err(CryptoError::InvalidPublicKey),
        [0, next, ..] if *next >= 0x80 => &contents[1..],
        [0, _, ..] => return Err(CryptoError::InvalidPublicKey),
        [first, ..] if *first >= 0x80 => return Err(CryptoError::InvalidPublicKey),
        _ => contents,
    };
    Ok((BigUint::from_bytes_be(magnitude), rest))
}

/// `(n, e)` of a DER `RSAPublicKey` (RFC 8017 appendix A.1.1), the subjectPublicKey of an
/// rsaEncryption certificate.
fn rsa_public_key(der: &[u8]) -> Result<(BigUint, BigUint), CryptoError> {
    let (sequence, trailing) = der_tlv(der, 0x30)?;
    if !trailing.is_empty() {
        return Err(CryptoError::InvalidPublicKey);
    }
    let (n, rest) = der_positive_integer(sequence)?;
    let (e, rest) = der_positive_integer(rest)?;
    if !rest.is_empty() {
        return Err(CryptoError::InvalidPublicKey);
    }
    Ok((n, e))
}

/// Verifies an RSASSA-PKCS1-v1_5 `signature` over the message whose `digest` (made with
/// [`rsa_pkcs1_hash`] of `scheme`) is given, for the DigestInfo encoding WITHOUT the NULL
/// parameters (RFC 5246 section 4.7). `public_key` is the DER `RSAPublicKey`. The form with
/// NULL parameters is the provider's ([`crate::RTCCrypto::verify_signature`]); this one
/// accepts only the other.
pub fn verify_rsa_pkcs1_without_digest_parameters(
    scheme: SignatureScheme,
    public_key: &[u8],
    digest: &[u8],
    signature: &[u8],
) -> Result<(), CryptoError> {
    let (hash, prefix) =
        digest_info_without_parameters(scheme).ok_or(CryptoError::InvalidSignature)?;
    if digest.len() != hash.output_len() {
        return Err(CryptoError::InvalidSignature);
    }
    let (n, e) = rsa_public_key(public_key)?;
    let bits = n.bits();
    if !(MIN_MODULUS_BITS..=MAX_MODULUS_BITS).contains(&bits) || e < BigUint::from(3u8) || !e.bit(0)
    {
        return Err(CryptoError::InvalidPublicKey);
    }
    let k = bits.div_ceil(8) as usize;
    // RFC 8017 section 8.2.2 step 1: the signature is k octets; RSAVP1: 0 <= s < n.
    if signature.len() != k {
        return Err(CryptoError::InvalidSignature);
    }
    let s = BigUint::from_bytes_be(signature);
    if s >= n {
        return Err(CryptoError::InvalidSignature);
    }
    let m = s.modpow(&e, &n).to_bytes_be();
    let mut em = vec![0u8; k - m.len()];
    em.extend_from_slice(&m);
    // EMSA-PKCS1-v1_5: 0x00 || 0x01 || PS (0xff, at least 8) || 0x00 || T.
    let t_len = prefix.len() + digest.len();
    if k < t_len + 11 {
        return Err(CryptoError::InvalidSignature);
    }
    let mut expected = Vec::with_capacity(k);
    expected.extend_from_slice(&[0x00, 0x01]);
    expected.resize(k - t_len - 1, 0xff);
    expected.push(0x00);
    expected.extend_from_slice(prefix);
    expected.extend_from_slice(digest);
    if bool::from(em.ct_eq(&expected)) {
        Ok(())
    } else {
        Err(CryptoError::InvalidSignature)
    }
}
