# Key erasure in rtci-dtls, rtci-srtp and rtci-crypto

The rule: memory a secret was in is overwritten before it is freed. Every struct holding secret
key material derives `Zeroize` and `ZeroizeOnDrop`, or holds each secret in a type that does
(`crypto::SecretVec`, `zeroize::Zeroizing`). Key material is never built in a buffer that
grows: a `Vec` that grows moves to a new allocation and frees the old one as it is. Clauses:
RFC 5246 section 8.1 (the premaster secret is deleted once the master secret exists), RFC 8446
section 7.1 (a secret is erased once what derives from it is computed), RFC 3711 section 9.3
and RFC 7714 section 13.1 (SRTP keys erased when no longer needed).

## What holds what

| Secret | Where it lives | Erased (0.1.0) | Erased now | Test |
|---|---|---|---|---|
| (EC)DHE private scalar | the provider's key-exchange object (`ring::agreement::EphemeralPrivateKey`, AWS-LC) | provider | provider (ring: not erased; AWS-LC: cleansed) | none (not observable: the scalar never crosses the provider boundary) |
| (EC)DHE shared secret / DTLS 1.2 premaster secret | `SecretVec` from the provider; `State.pre_master_secret` | no: `into_bytes` to a plain `Vec`, `State` field plain, flight 4's local plain on error paths | yes: `SecretVec` end to end, forgotten once the master secret exists; the stack scrubbed after the provider computes it | `tests/dtls_secret_erasure.rs` (all DTLS 1.2 tests, process test) |
| PSK from the application's callback, PSK premaster secret | flight 3/4 locals | no (plain `Vec`) | yes (`SecretVec` on receipt; premaster built at its size) | `dtls12_psk_and_its_premaster_secret_are_erased` |
| DTLS 1.2 master secret | `State.master_secret`, sessions, tickets | no: `State` field plain; replaced without erasure | yes (`SecretVec`) | `dtls12_secrets_are_erased_for_every_cipher_suite_family`, ticket and serialization tests |
| PRF output and its `A(i)` values (master secret, key block, exporter output) | `prf_p_hash` | no: plain vectors, growing output buffer, truncated copy | yes: zeroizing buffers sized up front, HMAC keyed once | `tests/dtls_srtp_keying_material_erasure.rs::dtls12_*`, `dtls12_secrets_*` |
| Key block: client/server write keys, MAC keys, write IVs | `EncryptionKeys`; the record ciphers' IVs | no; `EncryptionKeys` printed every key in `Display`/`Debug` | yes: `EncryptionKeys` and `CryptoGcm`/`CryptoCcm`/`CryptoChaCha20` derive `Zeroize`, `ZeroizeOnDrop`; `Debug` prints lengths; `Display` removed | `dtls12_secrets_*` (the 4-byte AES-GCM/CCM implicit nonces are too short to search for; ChaCha20's 12-byte IVs are searched) |
| Record cipher key schedules | AES-CBC, AES-CCM: RustCrypto `aes` in the crate's objects; AES-GCM, ChaCha20: the provider | CBC/CCM no (`aes` without `zeroize`) | CBC/CCM yes (`aes`, `ctr` with `zeroize`); stack scrubbed after each is built | `dtls12_secrets_*`, `dtls13_secrets_*` (CCM) |
| Finished verify data inputs | master secret / finished keys (above) | as above | as above | as above (verify_data itself is sent, not secret) |
| DTLS-SRTP exporter output | `export_keying_material` returns `SecretVec` | DTLS 1.2: no (PRF); DTLS 1.3: yes | yes | `dtls_srtp_keying_material_erasure.rs` |
| DTLS 1.3 key schedule secrets, traffic secrets, exporter/resumption secrets | `KeySchedule`, `ReadEpoch.secret`, sessions | yes (`SecretVec`) | yes | `dtls13_secrets_are_erased_across_key_updates` |
| DTLS 1.3 traffic keys, record-number keys | the provider's AEAD and header-mask objects | provider | provider (ring: not erased, see below) | as above, ring's objects reported apart |
| DTLS 1.3 record IVs | `RecordKeys` | no: inline in epochs kept in vectors that grow (copies freed), plain store in `Drop` | yes: `SecretVec` in the heap | `dtls13_secrets_*` (found in 0.1.0 code by the scan) |
| Resumption PSK (1.3), ticket keys, ticket plaintexts | `TicketIssuer`, `seal`/`open` | keys yes; plaintexts grew while built (copies freed) | yes: plaintexts sized up front; keys drawn with `fill_secret` | `dtls12_ticket_keys_*`, `dtls13_resumption_*` |
| External PSK (1.3) | `ExternalPsk` (`SecretVec`) | yes | yes | `dtls13_resumption_and_external_psk_secrets_are_erased` |
| Cookie secrets (1.2 HelloVerifyRequest, 1.3 HelloRetryRequest) | `CookieSecrets` in the endpoint; the HRR secret | no: `take()` left the bytes in place; the previous secret never erased; drawn from the buffered generator | yes: overwritten in place; drawn with `RTCRandom::fill_secret` | `cookie_secrets_are_erased_with_the_endpoint` |
| Serialized `State` (`marshal_binary`) | the returned bytes; `SerializedState` | intermediate copies freed as they were | intermediate copies erased, output written once at its size | `dtls12_state_serialization_leaves_no_master_secret_behind` |
| Certificate private key (PKCS#8) | provider `SigningKey` (`pkcs8_der: SecretVec`); PEM import copy | provider; import copy plain | import copy `SecretVec` (the `pem`/`rcgen` crates' own buffers are theirs) | none |
| SRTP master keys and salts | `SessionKeys` | yes (manual `Drop`) | yes (`Zeroize`, `ZeroizeOnDrop`) | `rtci-srtp/tests/key_erasure.rs` |
| SRTP session keys, salts, KDF output | `SecretVec`; AES-CM keys in `AesCtr` | yes | yes | `rtci-srtp/tests/key_schedule_erasure.rs` |
| SRTP HMAC-SHA1 states (AES-CM, NULL profiles) | ring provider: RustCrypto `hmac`; AWS-LC: `HMAC_CTX` | ring: no | yes (`Drop for RustCryptoHmacSha1` overwrites the state) | `with_ring_only_its_aes_gcm_key_objects_are_left_in_freed_rust_memory`, process test |
| AES-CM per-packet key schedules | stack (RustCrypto `ctr`/`aes`) | no (never observed) | yes (`aes`, `ctr` with `zeroize`); no test can show it | none |
| SRTP AES-GCM keys | the provider's AEAD object | ring: no; AWS-LC: yes | unchanged: ring's limit | `known_limit_*` (ring), `aws_lc_*` |
| `Debug`/log output | `SecretVec`, sessions, `SessionKeys`, `CryptoPrivateKey`: redacted | `EncryptionKeys`, `SerializedState` printed keys | redacted / no `Debug` | review |

## The ring provider's limit

ring does not erase its own key objects: `ring::aead::LessSafeKey` (AES-GCM, ChaCha20-Poly1305),
`aead::quic::HeaderProtectionKey` (DTLS 1.3 record-number keys), `hmac::Key` (the PRF and HKDF
keyed states) and `agreement::EphemeralPrivateKey` are freed as they are, and its stack
temporaries are not erased. The crate does not reach into ring's memory. With ring, RFC 7714
section 13.1 is therefore not met for the AES-GCM SRTP profiles, nor for the DTLS record keys of
the AES-GCM and ChaCha20 suites; everything the crate itself holds is erased with either
provider. ring's maintainer decided against destructor-based zeroization (ring issue #15,
closed 2025-02-25) and points to an allocator that zeroizes on deallocation: an application that
needs the clause with ring can install such a global allocator. The AWS-LC provider
(`crypto-aws-lc-rs`) meets the clause: its `EVP_AEAD_CTX` and `HMAC_CTX` are cleansed, and the
process-memory tests find nothing after the drop, for every SRTP profile and the DTLS suites
tested.

## What the tests look at

`tests/dtls_secret_erasure.rs` runs associations over a provider wrapper that records every
secret crossing the provider boundary (kept inverted) and derives what the association
computes from them; a test allocator keeps every block freed during the association (and
tracks those still allocated after it) and searches them all. On Linux the whole process is
searched after a worker thread has dropped the association. `rtci-srtp/tests/key_*` do the
same for SRTP contexts with keys they compute themselves.

## Serialized state

`State::marshal_binary` returns the session's master secret in the clear inside its bytes, and
`unmarshal_binary` reads it from bytes the caller holds: protecting and erasing those bytes is
the application's responsibility. The format is unchanged.
