# Crypto provider migration decisions

These decisions freeze the boundaries needed to start G3 implementation. Reopening one requires an explicit design change because provider implementations and protocol migrations depend on them.

## SRTP OpenSSL features

The `openssl` and `vendored-openssl` features were partial SRTP implementation choices, not complete RTC crypto providers, and were removed when SRTP migrated to `rtci-crypto`. A future OpenSSL provider is possible only as a complete downstream implementation of the public provider traits that passes the same conformance suite as the built-in providers; partial protocol-specific backend features will not return.

The removal is recorded in the changelog and the crypto-provider migration guide. This pre-1.0 cleanup is intentional: retaining the feature names would falsely imply that OpenSSL provided the complete algorithm surface now required by SRTP and the rest of the RTC stack.

## Crypto errors and protocol boundaries

`rtci-crypto` owns a backend-neutral, non-exhaustive `CryptoError`. The initial variants are `NoDefaultProvider`, `UnsupportedAlgorithm(CryptoAlgorithm)`, `InvalidKeyLength { expected, actual }`, `InvalidNonceLength { expected, actual }`, `InvalidTagLength { expected, actual }`, `InvalidPublicKey`, `InvalidPrivateKey`, `AuthenticationFailed`, `InvalidSignature`, `RandomnessFailed`, `OutputTooSmall { required, actual }`, and `Provider(String)`. Authentication, tag, and padding failures from decryption converge on `AuthenticationFailed`; signature verification uses `InvalidSignature`. These failures must not expose backend-specific distinctions that could become an oracle.

Protocol crates convert `CryptoError` at their own boundary. `rtci-shared` must not depend on `rtci-crypto`, and G3 will not introduce that dependency merely to obtain an automatic `From` conversion. During migration, each call site maps a provider failure to the protocol's existing semantic error where one exists; otherwise it maps to a backend-neutral shared crypto error without retaining the backend error type. This mapping is explicit rather than a blanket conversion.

The string in `Provider(String)` is sanitized local diagnostic context, is not a stable matching surface, and may be logged at trace level. It must not be serialized into packets, alerts, or peer-visible protocol messages. All other variants use stable provider-neutral wording. Secret material, keys, plaintext, nonces, tags, and complete signatures are never included in `Debug`, `Display`, or error sources.

The existing shared public error type remains available during G3 to avoid mixing a workspace-wide error redesign into provider migration. Backend-specific shared variants are removed in P7-01. Moving protocols to crate-local error types can be considered separately and is not required to finish G3.

## Public keys and certificate adapters

The initial non-exhaustive `PublicKeyEncoding` distinguishes these encodings:

| Variant | Encoding |
|---|---|
| `SubjectPublicKeyInfoDer` | Complete DER-encoded SubjectPublicKeyInfo |
| `EcUncompressedPoint` | SEC1 uncompressed P-256 or P-384 point; the signature scheme determines the curve |
| `Ed25519Raw` | Raw 32-byte Ed25519 public key |
| `RsaPkcs1Der` | PKCS#1 DER `RSAPublicKey` |

The canonical certificate-facing public-key boundary is complete DER-encoded SubjectPublicKeyInfo. Certificate parsing and policy remain outside `RTCCrypto`; adapters parse SPKI and construct the operation-specific `PublicKey` passed to signature verification. This preserves an unambiguous public boundary while matching the encodings accepted by current providers.

A `SigningKey` may be non-exportable. Public-key access and signing are mandatory; `to_pkcs8_der()` returns `Ok(None)` for a non-exportable key. PEM/private-key serialization built on that operation returns an explicit adapter error rather than fabricating bytes. Key equality or certificate identity must use public material or a stable provider-neutral identifier, never private-key export.

The current `rcgen::KeyPair`, `CryptoPrivateKeyKind`, and `CustomSigner` APIs remain only as migration adapters. Provider-neutral key generation/import and signing land first; the old adapters are then deprecated and removed before 1.0 in P7-02. Internal DTLS named-curve private-key types are replaced by provider-owned active key-exchange objects and do not become public compatibility APIs.

rustls/webpki certificate-chain verification remains an explicitly separate adapter and policy layer. `RTCCrypto` performs cryptographic primitives and signing-key operations; it does not own trust stores, certificate path building, hostname validation, revocation policy, or application identity policy.

## Feature and provider selection invariants

`ring` remains the default built-in provider. `ring` and `aws-lc-rs` become additive in P1-09: enabling both compiles both and does not silently select AWS-LC-RS. Construction resolves the chosen provider once and protocol objects store an `Arc<dyn RTCCryptoProvider>`; packet paths do not read a mutable global or repeatedly resolve defaults.

The protocol crates still intentionally reject both built-ins together and cannot yet build the full RTC stack without one while their direct backend calls remain. P1-09 makes these configurations pass for `rtci-crypto`; P2 through P6 migrate the consumers, and P7 adds the corresponding full-workspace matrix. This sequencing keeps the new provider contract independently testable without claiming that unmigrated protocol crates are already additive.

## TLS 1.3 primitives (DTLS 1.3)

DTLS 1.3 reaches its cryptography through the same boundary; nothing in `rtci-dtls` names a
backend. What it added to the provider contract, and why each piece sits where it does:

| Need | Where | Decision |
|---|---|---|
| SHA-384, HMAC-SHA-384 | `HashAlgorithm::Sha384`, `HmacAlgorithm::Sha384` | Provider operations, for `TLS_AES_256_GCM_SHA384`. |
| HKDF-Extract, HKDF-Expand, HKDF-Expand-Label | `rtci_crypto::{hkdf_extract, hkdf_expand, hkdf_expand_label}` | Not provider operations. HKDF (RFC 5869) is HMAC and nothing else, so it is written once on `RTCCrypto::new_hmac`; a provider that has HMAC for a hash has HKDF for it, a downstream one included, and the built-ins cannot disagree. Outputs are `SecretVec`. The label prefix is a parameter: `"dtls13"` (RFC 9147 section 5.9), and `"tls13 "` for the RFC 8448 trace the conformance suite checks. |
| Record AEADs | `AeadAlgorithm` (unchanged) | AES-128-GCM, AES-256-GCM, ChaCha20-Poly1305, AES-128-CCM and AES-128-CCM-8 were all there for DTLS 1.2 and SRTP. |
| Record sequence number encryption (RFC 9147 section 4.2.3) | `RTCCrypto::new_header_mask`, `HeaderMask`, `HeaderMaskAlgorithm::{Aes128, Aes256, ChaCha20}` | A provider operation of its own: the mask is AES-ECB of a 16-byte sample or the ChaCha20 block function keyed by it, which is QUIC header protection (RFC 9001 section 5.4). Both built-ins implement it on their `aead::quic::HeaderProtectionKey`, so the key is expanded once and AES uses the hardware. `block_encrypt` would have re-expanded the key per record and has no ChaCha20. |
| Key shares | `KeyExchangeAlgorithm` (unchanged) | X25519, P-256, P-384. Neither built-in offers a hybrid ML-KEM group through its stable API in the versions pinned here (aws-lc-rs has ML-KEM itself; ring has none), so `X25519MLKEM768` is not offered. Adding it is a new `KeyExchangeAlgorithm` variant whose `ActiveKeyExchange` concatenates the two shares; the handshake code is indifferent to the group. |
| RSASSA-PSS | `SignatureScheme::{RsaPssSha256, RsaPssSha384, RsaPssSha512}` | The `rsa_pss_rsae_*` schemes of RFC 8446 section 4.2.3: MGF1 with the same hash, salt as long as the digest, key with the rsaEncryption OID. Verified from `RsaPkcs1Der` like PKCS#1 v1.5. An imported RSA key signs both paddings: `SigningKey::supports` is true for the PSS schemes on a key imported as `RsaPkcs1Sha256`. `rsa_pss_pss_*` (keys with the RSASSA-PSS OID) is not implemented: neither backend imports such keys. |
| Ed25519, ECDSA P-256 / P-384 | `SignatureScheme` (unchanged) | In TLS 1.3 an ECDSA scheme names its curve; the handshake asks for `EcdsaP256Sha256` or `EcdsaP384Sha384` and never for the P-384 / SHA-256 pairing DTLS 1.2 allows. |

The conformance suite (`rtci_crypto::conformance`) checks each against published values:
FIPS 180-4 and RFC 4231 (SHA-384, HMAC-SHA-384), RFC 5869 appendix A (HKDF), the RFC 8448
section 3 trace (the TLS 1.3 key schedule down to a traffic key and IV), RFC 9001 appendix A
(the AES-128 and ChaCha20 masks) and RSASSA-PSS signatures made with OpenSSL. RFC 9147 itself
publishes no test vectors; what is specific to DTLS 1.3 is checked against handshakes
recorded with OpenSSL in `rtci-dtls`.

## RSA PKCS#1 v1.5 DigestInfo without parameters

RFC 5246 section 4.7 (and RFC 8017 section 9.2, note 1) has a verifier of an RSASSA-PKCS1-v1_5
signature accept the DigestInfo whose AlgorithmIdentifier parameters are NULL and the one
where they are absent. Both providers accept the NULL form only, and neither exposes the raw
public operation. Since audit-6 `rtci-crypto` checks the other form itself
(`verify_rsa_pkcs1_without_digest_parameters`, called by the DTLS 1.2 verifier when the
provider refuses an RSASSA-PKCS1-v1_5 signature): `s^e mod n` with `num-bigint` (public values
only, so no constant-time arithmetic is needed; the crate was already in the graph through
`der-parser`), then a byte-for-byte comparison with the EMSA-PKCS1-v1_5 encoding of the
DigestInfo without parameters. RFC5246-4.7-1 is `tested`. The `rsa` crate stays out
(RUSTSEC-2023-0071, Marvin). The upstream request below would let the provider do it instead
(ring, and aws-lc-rs / AWS-LC):

> RSA PKCS#1 v1.5 verification accepts only the DigestInfo encoding with NULL parameters.
> RFC 8017 section 9.2 note 1 and RFC 5246 section 4.7 ask verifiers to accept the encoding
> with the parameters absent as well (`SEQUENCE { SEQUENCE { OID } , OCTET STRING }`). Could
> the PKCS#1 v1.5 verification algorithms (`RSA_PKCS1_2048_8192_SHA256` and the others) accept
> both encodings, or a separate verification algorithm be offered that does? A raw RSA public
> operation (`s^e mod n`) in the public API would serve as well.
