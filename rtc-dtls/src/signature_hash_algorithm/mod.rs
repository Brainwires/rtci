#[cfg(test)]
mod signature_hash_algorithm_test;

use std::fmt;

use crate::crypto::*;
use shared::error::*;

// HashAlgorithm is used to indicate the hash algorithm used
// https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-18
// Supported hash hash algorithms
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
/// The hash algorithms that may be paired with a signature algorithm.
#[non_exhaustive]
pub enum HashAlgorithm {
    /// `MD2` (`0`).
    Md2 = 0, // Blacklisted
    /// `MD5` (`1`).
    Md5 = 1, // Blacklisted
    /// `SHA1` (`2`).
    Sha1 = 2, // Blacklisted
    /// `SHA224` (`3`).
    Sha224 = 3,
    /// `SHA256` (`4`).
    Sha256 = 4,
    /// `SHA384` (`5`).
    Sha384 = 5,
    /// `SHA512` (`6`).
    Sha512 = 6,
    /// `Intrinsic` (`8`): the hash is part of the signature algorithm. The value of Ed25519
    /// (`0x0807`) and of the RSASSA-PSS schemes (`0x0804` to `0x0806`), whose first byte this is.
    Ed25519 = 8,
    /// An algorithm this crate does not implement.
    Unsupported,
}

impl From<u8> for HashAlgorithm {
    fn from(val: u8) -> Self {
        match val {
            0 => HashAlgorithm::Md2,
            1 => HashAlgorithm::Md5,
            2 => HashAlgorithm::Sha1,
            3 => HashAlgorithm::Sha224,
            4 => HashAlgorithm::Sha256,
            5 => HashAlgorithm::Sha384,
            6 => HashAlgorithm::Sha512,
            8 => HashAlgorithm::Ed25519,
            _ => HashAlgorithm::Unsupported,
        }
    }
}

impl fmt::Display for HashAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            HashAlgorithm::Md2 => write!(f, "md2"),
            HashAlgorithm::Md5 => write!(f, "md5"), // [RFC3279]
            HashAlgorithm::Sha1 => write!(f, "sha-1"), // [RFC3279]
            HashAlgorithm::Sha224 => write!(f, "sha-224"), // [RFC4055]
            HashAlgorithm::Sha256 => write!(f, "sha-256"), // [RFC4055]
            HashAlgorithm::Sha384 => write!(f, "sha-384"), // [RFC4055]
            HashAlgorithm::Sha512 => write!(f, "sha-512"), // [RFC4055]
            HashAlgorithm::Ed25519 => write!(f, "null"), // [RFC4055]
            _ => write!(f, "unknown or unsupported hash algorithm"),
        }
    }
}

impl HashAlgorithm {
    pub(crate) fn insecure(&self) -> bool {
        matches!(
            *self,
            HashAlgorithm::Md2 | HashAlgorithm::Md5 | HashAlgorithm::Sha1
        )
    }

    pub(crate) fn invalid(&self) -> bool {
        matches!(*self, HashAlgorithm::Md2)
    }
}

// https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-16
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
/// The signature algorithms this crate can verify and produce.
#[non_exhaustive]
pub enum SignatureAlgorithm {
    /// `RSA` (`1`).
    Rsa = 1,
    /// `ECDSA` (`3`).
    Ecdsa = 3,
    /// `ED25519` (`7`).
    Ed25519 = 7,
    /// `rsa_pss_rsae_sha256` (`0x0804`, RFC 8446 section 4.2.3): RSASSA-PSS with SHA-256
    /// over a key with the rsaEncryption OID. Paired with the hash value `8` (intrinsic).
    RsaPssRsaeSha256 = 4,
    /// `rsa_pss_rsae_sha384` (`0x0805`).
    RsaPssRsaeSha384 = 5,
    /// `rsa_pss_rsae_sha512` (`0x0806`).
    RsaPssRsaeSha512 = 6,
    /// An algorithm this crate does not implement.
    Unsupported = 0xff,
}

impl SignatureAlgorithm {
    /// Whether the signature is made with an RSA key: PKCS#1 v1.5 or RSASSA-PSS.
    pub fn is_rsa(self) -> bool {
        matches!(
            self,
            Self::Rsa | Self::RsaPssRsaeSha256 | Self::RsaPssRsaeSha384 | Self::RsaPssRsaeSha512
        )
    }
}

impl From<u8> for SignatureAlgorithm {
    fn from(val: u8) -> Self {
        match val {
            1 => SignatureAlgorithm::Rsa,
            3 => SignatureAlgorithm::Ecdsa,
            7 => SignatureAlgorithm::Ed25519,
            4 => SignatureAlgorithm::RsaPssRsaeSha256,
            5 => SignatureAlgorithm::RsaPssRsaeSha384,
            6 => SignatureAlgorithm::RsaPssRsaeSha512,
            _ => SignatureAlgorithm::Unsupported,
        }
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
/// A signature and hash pair, as negotiated for certificate verification.
pub struct SignatureHashAlgorithm {
    /// The hash to digest the signed data with.
    pub hash: HashAlgorithm,
    /// The signature algorithm to apply.
    pub signature: SignatureAlgorithm,
}

impl SignatureHashAlgorithm {
    /// The pair as the 16-bit SignatureScheme of RFC 8446 section 4.2.3: the hash byte, then
    /// the signature byte.
    pub fn scheme_code(&self) -> u16 {
        u16::from_be_bytes([self.hash as u8, self.signature as u8])
    }

    /// The pair for a 16-bit SignatureScheme.
    pub fn from_scheme_code(code: u16) -> Self {
        let [hash, signature] = code.to_be_bytes();
        Self {
            hash: hash.into(),
            signature: signature.into(),
        }
    }

    /// Whether the pair may sign a TLS 1.3 CertificateVerify (RFC 8446 section 4.4.3): ECDSA
    /// with the curve its hash names, Ed25519, or RSASSA-PSS. RSA PKCS#1 v1.5 and SHA-1 may
    /// not.
    pub(crate) fn is_tls13_signature(&self) -> bool {
        matches!(
            (self.signature, self.hash),
            (
                SignatureAlgorithm::Ecdsa,
                HashAlgorithm::Sha256 | HashAlgorithm::Sha384
            ) | (
                SignatureAlgorithm::Ed25519
                    | SignatureAlgorithm::RsaPssRsaeSha256
                    | SignatureAlgorithm::RsaPssRsaeSha384
                    | SignatureAlgorithm::RsaPssRsaeSha512,
                HashAlgorithm::Ed25519
            )
        )
    }

    pub(crate) fn crypto_scheme(&self) -> Result<crypto::SignatureScheme> {
        match (self.signature, self.hash) {
            (SignatureAlgorithm::Ed25519, _) => Ok(crypto::SignatureScheme::Ed25519),
            (SignatureAlgorithm::RsaPssRsaeSha256, HashAlgorithm::Ed25519) => {
                Ok(crypto::SignatureScheme::RsaPssSha256)
            }
            (SignatureAlgorithm::RsaPssRsaeSha384, HashAlgorithm::Ed25519) => {
                Ok(crypto::SignatureScheme::RsaPssSha384)
            }
            (SignatureAlgorithm::RsaPssRsaeSha512, HashAlgorithm::Ed25519) => {
                Ok(crypto::SignatureScheme::RsaPssSha512)
            }
            (SignatureAlgorithm::Ecdsa, HashAlgorithm::Sha256) => {
                Ok(crypto::SignatureScheme::EcdsaP256Sha256)
            }
            (SignatureAlgorithm::Ecdsa, HashAlgorithm::Sha384) => {
                Ok(crypto::SignatureScheme::EcdsaP384Sha384)
            }
            (SignatureAlgorithm::Rsa, HashAlgorithm::Sha1) => {
                Ok(crypto::SignatureScheme::RsaPkcs1Sha1)
            }
            (SignatureAlgorithm::Rsa, HashAlgorithm::Sha256) => {
                Ok(crypto::SignatureScheme::RsaPkcs1Sha256)
            }
            (SignatureAlgorithm::Rsa, HashAlgorithm::Sha384) => {
                Ok(crypto::SignatureScheme::RsaPkcs1Sha384)
            }
            (SignatureAlgorithm::Rsa, HashAlgorithm::Sha512) => {
                Ok(crypto::SignatureScheme::RsaPkcs1Sha512)
            }
            _ => Err(Error::ErrKeySignatureVerifyUnimplemented),
        }
    }

    // is_compatible checks that given private key is compatible with the signature scheme.
    pub(crate) fn is_compatible(&self, private_key: &CryptoPrivateKey) -> bool {
        self.crypto_scheme()
            .is_ok_and(|scheme| private_key.signing_key.supports(scheme))
    }
}

pub(crate) fn default_signature_schemes() -> Vec<SignatureHashAlgorithm> {
    vec![
        SignatureHashAlgorithm {
            hash: HashAlgorithm::Sha256,
            signature: SignatureAlgorithm::Ecdsa,
        },
        SignatureHashAlgorithm {
            hash: HashAlgorithm::Sha384,
            signature: SignatureAlgorithm::Ecdsa,
        },
        SignatureHashAlgorithm {
            hash: HashAlgorithm::Sha512,
            signature: SignatureAlgorithm::Ecdsa,
        },
        SignatureHashAlgorithm {
            hash: HashAlgorithm::Sha256,
            signature: SignatureAlgorithm::Rsa,
        },
        SignatureHashAlgorithm {
            hash: HashAlgorithm::Sha384,
            signature: SignatureAlgorithm::Rsa,
        },
        SignatureHashAlgorithm {
            hash: HashAlgorithm::Sha512,
            signature: SignatureAlgorithm::Rsa,
        },
        SignatureHashAlgorithm {
            hash: HashAlgorithm::Ed25519,
            signature: SignatureAlgorithm::Ed25519,
        },
        // RSASSA-PSS (RFC 8446 section 4.2.3), which TLS 1.3 requires of an RSA key and
        // TLS 1.2 may use. After PKCS#1 v1.5, so that a DTLS 1.2 handshake signs as before
        // with a peer that lists both.
        SignatureHashAlgorithm {
            hash: HashAlgorithm::Ed25519,
            signature: SignatureAlgorithm::RsaPssRsaeSha256,
        },
        SignatureHashAlgorithm {
            hash: HashAlgorithm::Ed25519,
            signature: SignatureAlgorithm::RsaPssRsaeSha384,
        },
        SignatureHashAlgorithm {
            hash: HashAlgorithm::Ed25519,
            signature: SignatureAlgorithm::RsaPssRsaeSha512,
        },
    ]
}

// select Signature Scheme returns most preferred and compatible scheme.
pub(crate) fn select_signature_scheme(
    sigs: &[SignatureHashAlgorithm],
    private_key: &CryptoPrivateKey,
) -> Result<SignatureHashAlgorithm> {
    for ss in sigs {
        if ss.is_compatible(private_key) {
            return Ok(*ss);
        }
    }

    Err(Error::ErrNoAvailableSignatureSchemes)
}

/// The pairs a client that sends no signature_algorithms extension is taken to accept
/// (RFC 5246 7.4.1.4.1): SHA-1 with the signature algorithm of the negotiated key exchange.
pub(crate) fn default_remote_signature_schemes() -> Vec<SignatureHashAlgorithm> {
    vec![
        SignatureHashAlgorithm {
            hash: HashAlgorithm::Sha1,
            signature: SignatureAlgorithm::Rsa,
        },
        SignatureHashAlgorithm {
            hash: HashAlgorithm::Sha1,
            signature: SignatureAlgorithm::Ecdsa,
        },
    ]
}

/// The most preferred of `local` (in its order) that the peer lists in `remote` and
/// `private_key` can sign with: the pair for a ServerKeyExchange (RFC 5246 7.4.3) or a
/// CertificateVerify (7.4.8).
pub(crate) fn select_common_signature_scheme(
    local: &[SignatureHashAlgorithm],
    remote: &[SignatureHashAlgorithm],
    private_key: &CryptoPrivateKey,
) -> Result<SignatureHashAlgorithm> {
    local
        .iter()
        .find(|scheme| remote.contains(scheme) && scheme.is_compatible(private_key))
        .copied()
        .ok_or(Error::ErrNoAvailableSignatureSchemes)
}

/// The certificate type (RFC 5246 7.4.4, RFC 8422 5.5) a certificate with `private_key` is:
/// rsa_sign for an RSA key, ecdsa_sign for an ECDSA or EdDSA one.
pub(crate) fn client_certificate_type(
    private_key: &CryptoPrivateKey,
) -> crate::client_certificate_type::ClientCertificateType {
    use crate::client_certificate_type::ClientCertificateType;

    let is_rsa = [
        HashAlgorithm::Sha1,
        HashAlgorithm::Sha256,
        HashAlgorithm::Sha384,
        HashAlgorithm::Sha512,
    ]
    .into_iter()
    .any(|hash| {
        SignatureHashAlgorithm {
            hash,
            signature: SignatureAlgorithm::Rsa,
        }
        .is_compatible(private_key)
    });
    if is_rsa {
        ClientCertificateType::RsaSign
    } else {
        ClientCertificateType::EcdsaSign
    }
}

// SignatureScheme identifies a signature algorithm supported by TLS. See
// RFC 8446, Section 4.2.3.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
/// A TLS signature scheme, which names a signature and hash together ([RFC 8446] §4.2.3).
#[non_exhaustive]
pub enum SignatureScheme {
    // RSASSA-PKCS1-v1_5 algorithms.
    /// `PKCS1_WITH_SHA256` (`0x0401`).
    Pkcs1WithSha256 = 0x0401,
    /// `PKCS1_WITH_SHA384` (`0x0501`).
    Pkcs1WithSha384 = 0x0501,
    /// `PKCS1_WITH_SHA512` (`0x0601`).
    Pkcs1WithSha512 = 0x0601,

    // RSASSA-PSS algorithms with public key OID rsaEncryption.
    /// `PSS_WITH_SHA256` (`0x0804`).
    PssWithSha256 = 0x0804,
    /// `PSS_WITH_SHA384` (`0x0805`).
    PssWithSha384 = 0x0805,
    /// `PSS_WITH_SHA512` (`0x0806`).
    PssWithSha512 = 0x0806,

    // ECDSA algorithms. Only constrained to a specific curve in TLS 1.3.
    /// `ECDSA_WITH_P256_AND_SHA256` (`0x0403`).
    EcdsaWithP256AndSha256 = 0x0403,
    /// `ECDSA_WITH_P384_AND_SHA384` (`0x0503`).
    EcdsaWithP384AndSha384 = 0x0503,
    /// `ECDSA_WITH_P521_AND_SHA512` (`0x0603`).
    EcdsaWithP521AndSha512 = 0x0603,

    // EdDSA algorithms.
    /// `ED25519` (`0x0807`).
    Ed25519 = 0x0807,

    // Legacy signature and hash algorithms for TLS 1.2.
    /// `PKCS1_WITH_SHA1` (`0x0201`).
    Pkcs1WithSha1 = 0x0201,
    /// `ECDSA_WITH_SHA1` (`0x0203`).
    EcdsaWithSha1 = 0x0203,
}

// parse_signature_schemes translates []tls.SignatureScheme to []signatureHashAlgorithm.
// It returns default signature scheme list if no SignatureScheme is passed.
pub(crate) fn parse_signature_schemes(
    sigs: &[u16],
    insecure_hashes: bool,
) -> Result<Vec<SignatureHashAlgorithm>> {
    if sigs.is_empty() {
        return Ok(default_signature_schemes());
    }

    let mut out = vec![];
    for ss in sigs {
        let sig: SignatureAlgorithm = ((*ss & 0xFF) as u8).into();
        if sig == SignatureAlgorithm::Unsupported {
            return Err(Error::ErrInvalidSignatureAlgorithm);
        }
        let h: HashAlgorithm = (((*ss >> 8) & 0xFF) as u8).into();
        if h == HashAlgorithm::Unsupported || h.invalid() {
            return Err(Error::ErrInvalidHashAlgorithm);
        }
        if h.insecure() && !insecure_hashes {
            continue;
        }
        out.push(SignatureHashAlgorithm {
            hash: h,
            signature: sig,
        })
    }

    if out.is_empty() {
        Err(Error::ErrNoAvailableSignatureSchemes)
    } else {
        Ok(out)
    }
}
