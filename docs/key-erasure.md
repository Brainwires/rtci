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
| (EC)DHE private scalar | the provider's key-exchange object (`ring::agreement::EphemeralPrivateKey`, AWS-LC) | ring: no (the freed key-exchange object kept it: 1 block per exchange, X25519 and P-256, measured with the 0.1.0 code path as mutation m6) | ring: yes (`ErasedOnDrop`; `into_inner` overwrites the slot when `agree_ephemeral` consumes the key; the stack copy is scrubbed after key agreement); AWS-LC: its own, not measured | `ring_ecdhe_private_key_and_shared_secret_are_erased` (scalar drawn from a known seed through the test-support seam) |
| (EC)DHE shared secret / DTLS 1.2 premaster secret | `SecretVec` from the provider; `State.pre_master_secret` | no: `into_bytes` to a plain `Vec`, `State` field plain, flight 4's local plain on error paths | yes: `SecretVec` end to end, forgotten once the master secret exists; the stack scrubbed after the provider computes it | `tests/dtls_secret_erasure.rs` (all DTLS 1.2 tests, process test) |
| PSK from the application's callback, PSK premaster secret | flight 3/4 locals | no (plain `Vec`) | yes (`SecretVec` on receipt; premaster built at its size) | `dtls12_psk_and_its_premaster_secret_are_erased` |
| DTLS 1.2 master secret | `State.master_secret`, sessions, tickets | no: `State` field plain; replaced without erasure | yes (`SecretVec`) | `dtls12_secrets_are_erased_for_every_cipher_suite_family`, ticket and serialization tests |
| PRF output and its `A(i)` values (master secret, key block, exporter output) | `prf_p_hash` | no: plain vectors, growing output buffer, truncated copy | yes: zeroizing buffers sized up front, HMAC keyed once | `tests/dtls_srtp_keying_material_erasure.rs::dtls12_*`, `dtls12_secrets_*` |
| Key block: client/server write keys, MAC keys, write IVs | `EncryptionKeys`; the record ciphers' IVs | no; `EncryptionKeys` printed every key in `Display`/`Debug` | yes: `EncryptionKeys` and `CryptoGcm`/`CryptoCcm`/`CryptoChaCha20` derive `Zeroize`, `ZeroizeOnDrop`; `Debug` prints lengths; `Display` removed | `dtls12_secrets_*` (the 4-byte AES-GCM/CCM implicit nonces are too short to search for; ChaCha20's 12-byte IVs are searched) |
| Record cipher key schedules | AES-CBC, AES-CCM: RustCrypto `aes` in the crate's objects; AES-GCM, ChaCha20: the provider | CBC/CCM no (`aes` without `zeroize`) | CBC/CCM yes (`aes`, `ctr` with `zeroize`); stack scrubbed after each is built | `dtls12_secrets_*`, `dtls13_secrets_*` (CCM) |
| Finished verify data inputs | master secret / finished keys (above) | as above | as above | as above (verify_data itself is sent, not secret) |
| DTLS-SRTP exporter output | `export_keying_material` returns `SecretVec` | DTLS 1.2: no (PRF); DTLS 1.3: yes | yes | `dtls_srtp_keying_material_erasure.rs` |
| DTLS 1.3 key schedule secrets, traffic secrets, exporter/resumption secrets | `KeySchedule`, `ReadEpoch.secret`, sessions | yes (`SecretVec`) | yes | `dtls13_secrets_are_erased_across_key_updates` |
| DTLS 1.3 traffic keys, record-number keys | the provider's AEAD and header-mask objects | ring: no; AWS-LC: yes | yes: ring's objects in an `ErasedOnDrop` allocation, overwritten after the drop | as above (ring's objects no longer left out of the search); `rtci-crypto/tests/ring_key_object_erasure.rs` |
| DTLS record keys of the AES-GCM and ChaCha20-Poly1305 suites; PRF, HKDF and cookie HMAC keys (HMAC-SHA-256/384) | ring provider: `ring::aead::LessSafeKey`, `ring::hmac::Key`; AWS-LC: its own | ring: no | yes (`ErasedOnDrop`) | `dtls12_secrets_*`, `ring_key_objects_are_erased_when_dropped` (the HMAC states are searched for there) |
| DTLS 1.3 record IVs | `RecordKeys` | no: inline in epochs kept in vectors that grow (copies freed), plain store in `Drop` | yes: `SecretVec` in the heap | `dtls13_secrets_*` (found in 0.1.0 code by the scan) |
| Resumption PSK (1.3), ticket keys, ticket plaintexts | `TicketIssuer`, `seal`/`open` | keys yes; plaintexts grew while built (copies freed) | yes: plaintexts sized up front; keys drawn with `fill_secret` | `dtls12_ticket_keys_*`, `dtls13_resumption_*` |
| External PSK (1.3) | `ExternalPsk` (`SecretVec`) | yes | yes | `dtls13_resumption_and_external_psk_secrets_are_erased` |
| Cookie secrets (1.2 HelloVerifyRequest, 1.3 HelloRetryRequest) | `CookieSecrets` in the endpoint; the HRR secret | no: the previous secret (after a rotation) was never erased; drawn from the buffered generator, whose output buffer kept them (the current secret taken out with `take()` was not observed left behind) | yes: both overwritten in place; drawn with `RTCRandom::fill_secret` | `cookie_secrets_are_erased_with_the_endpoint` (rotates, looks for both) |
| Serialized `State` (`marshal_binary`) | the returned bytes; `SerializedState` | intermediate copies freed as they were | intermediate copies erased, output written once at its size | `dtls12_state_serialization_leaves_no_master_secret_behind` |
| Certificate private key (PKCS#8) and the provider's parsed key pair | provider `SigningKey` (`pkcs8_der: SecretVec`; ring's `Ed25519KeyPair` / `EcdsaKeyPair` / `RsaKeyPair`); PEM import copy | ring key pair: no (1 freed block per key, Ed25519 and P-256, measured with the 0.1.0 layout as mutation m7); import copy plain | ring Ed25519/P-256 key pairs: yes (`ErasedOnDrop`); `pkcs8_der` and the import copy `SecretVec`; ring's RSA key pair keeps its private limbs in heap allocations of ring's own, which the crate cannot reach (by reading ring 0.17.14; not measured); the application's own copies (`pem`/`rcgen` buffers, the PKCS#8 it supplies) are its to protect | `ring_signing_key_objects_are_erased_when_dropped` (Ed25519 secret prefix, P-256 scalar in ring's Montgomery form) |
| SRTP master keys and salts | `SessionKeys` | yes (manual `Drop`) | yes (`Zeroize`, `ZeroizeOnDrop`) | `rtci-srtp/tests/key_erasure.rs` |
| SRTP session keys, salts, KDF output | `SecretVec`; AES-CM keys in `AesCtr` | yes | yes | `rtci-srtp/tests/key_schedule_erasure.rs` |
| SRTP HMAC-SHA1 states (AES-CM, NULL profiles) | ring provider: RustCrypto `hmac`; AWS-LC: `HMAC_CTX` | ring: no | yes (`Drop for RustCryptoHmacSha1` overwrites the state) | `with_ring_no_key_is_left_in_freed_rust_memory`, process test |
| AES-CM per-packet key schedules | stack (RustCrypto `ctr`/`aes`) | no (never observed) | yes (`aes`, `ctr` with `zeroize`); no test can show it | none |
| SRTP AES-GCM keys and round keys | the provider's AEAD object | ring: no; AWS-LC: yes | yes: ring's `LessSafeKey` in an `ErasedOnDrop` allocation, overwritten after the drop | `with_ring_no_key_is_left_in_freed_rust_memory`, `with_ring_no_key_outlives_its_contexts_in_process_memory`, `aws_lc_*` |
| `Debug`/log output | `SecretVec`, sessions, `SessionKeys`, `CryptoPrivateKey`: redacted | `EncryptionKeys`, `SerializedState` printed keys | redacted / no `Debug` | review |

## The ring provider's key objects

ring does not erase its own key objects when they are dropped (its maintainer decided against
destructor-based zeroization, ring issue #15, closed 2025-02-25). Since 0.2 the ring provider
keeps each key object it makes in an allocation of its own, `ErasedOnDrop<T>`
(`rtci-crypto/src/providers/ring.rs`): a `Box<MaybeUninit<T>>` lent out only as `&T`; on drop
the value is dropped in place and then the `size_of::<T>()` bytes are overwritten with volatile
writes before the box is freed. After the drop in place the slot holds no value, so the overwrite
is a write to the crate's own memory and does not depend on ring's layout. It covers
`ring::aead::LessSafeKey` (AES-128-GCM, AES-256-GCM, ChaCha20-Poly1305), `aead::quic::HeaderProtectionKey`
(DTLS 1.3 record-number keys) and `hmac::Key` (HMAC-SHA-256/384/512: the PRF, HKDF and cookie
keys). In ring 0.17 these keep their whole key schedule inline (AES round keys, the GHASH table,
the ChaCha20 key, the two SHA-2 states), with no allocation of their own. Measured: every one is
found live and none is left in freed memory after the drop
(`rtci-crypto/tests/ring_key_object_erasure.rs`, Linux x86_64, macOS arm64, Windows x86_64); the
SRTP and DTLS scans find no key of either provider after the drop, in the heap on every platform
and in the whole process on Linux. Mutations caught: the overwrite removed; the value moved to
another heap block before the drop.

What remains with ring:

- The ECDHE private key (`agreement::EphemeralPrivateKey`) and the Ed25519 and ECDSA P-256
  signing key pairs are kept in `ErasedOnDrop` too (since the second zeroize round); the
  private key is consumed by value by `agree_ephemeral`, so `into_inner` reads it out and
  overwrites the slot. Measured: found live, left in no freed block (before: one freed block
  each). The shared secret is in no freed block either. An RSA signing key pair keeps its
  private limbs in heap allocations of ring's own, freed by ring without erasure: out of the
  crate's reach, the provider's limit (from ring 0.17.14's source; not measured).
- Stack copies. Building a key object leaves copies in the dead stack frames of the functions
  that built it, and a value moved out of the wrapper would be a copy it cannot reach (the
  wrapper never moves its value out). The engine calls `crypto::scrub_stack()` after building
  keyed objects. What the tests show: in DTLS, copies carried from dead frames into heap padding
  were found and the scrub removes them (its removal is caught, m13 of the first round). The
  Linux process scan also searches the dead stack frames of the worker thread that built and
  dropped the SRTP contexts, and there it HAS found keys after the drop: in train 34's test
  environment (rustc 1.99.1, run 45714962513, all ten SRTP profiles, ring) the SRTCP encryption
  key and its AES round keys, the SRTCP HMAC-SHA1 inner and outer states and the master key
  (with the AES-GCM profiles also one or two SRTP round keys), 120 key forms, all in that
  thread's stack below its live frame, none in the heap or any other mapping. They are what
  building the contexts left (deriving the SRTCP keys is the last step of building a cipher).
  It depends on the compiler: the same test with the same sources found nothing in 40 runs on
  GitHub's Ubuntu runners, 20 with rustc 1.99.1 and 20 with 1.100.0 (runs 45726148580,
  45726156299). The process-memory tests therefore assert on everything but those dead frames
  and print what they find there (`STACK RESIDUE`); the ignored test
  `known_limit_with_ring_building_an_srtp_context_leaves_keys_in_dead_stack_frames` (and its
  AWS-LC twin) is the limit as a test. A
  copy deliberately moved onto the stack before the drop (mutation m3) was NOT caught, nor was
  a scrub added after the SRTP AES-GCM context is built ever needed (its removal, m5, changed
  nothing any test sees; it cost about 10 µs per context with the per-byte form, so it was taken out): residue that
  stays on the stack is not guaranteed erased, and is reported rather than asserted.
  For an application: the thread that builds SRTP contexts (and DTLS associations) can keep
  copies of their keys in its dead stack frames after they are dropped, until later calls on
  that thread overwrite them, or after the thread ends, until the C library gives its cached
  stack to another thread. Build them on a long-lived thread whose stack is reused (an event
  loop), or call `crypto::scrub_stack()` from the frame that built them: it overwrites the
  32 KiB below its caller's frame, and reaches neither the caller's own frame, the frames above
  it, registers, other threads' stacks nor anything deeper.
  `scrub_stack` is one bulk zero fill of a 32 KiB buffer in a never-inlined frame, made
  observable to the optimiser (`black_box` and a compiler fence) so it is not dropped as a
  dead store; it reaches the stack below its caller only, never registers or the frames above.
  Tested (zeroize3, ubuntu): its body emptied, the DTLS erasure tests fail in debug and release
  builds (runs 45659948616, 45659954724); the fill left unobservable, they fail in a release
  build (45659972471) and pass in a debug build (45659963417: at opt-level 0 nothing is
  removed, so the two cannot be told apart there). Cost: about 0.7 µs per call (DTLS
  record-cipher setup 1.07 µs AES-128-GCM and 1.38 µs AES-256-CBC against 0.39 and 0.47 µs on
  master, run 45660052237; the first form, a volatile write per byte, took 13.8 and 22.5 µs).

The AWS-LC provider (`crypto-aws-lc-rs`) cleanses its `EVP_AEAD_CTX` and `HMAC_CTX` itself; the
process-memory tests find nothing after the drop outside dead stack frames, for every SRTP
profile and the DTLS suites tested.

## What the tests look at

`tests/dtls_secret_erasure.rs` runs associations over a provider wrapper that records every
secret crossing the provider boundary (kept inverted) and derives what the association
computes from them; a test allocator keeps every block freed during the association (and
tracks those still allocated after it) and searches them all. On Linux the whole process is
searched after a worker thread has dropped the association. `rtci-srtp/tests/key_*` do the
same for SRTP contexts with keys they compute themselves; `key_erasure_process_memory.rs`
classifies each hit by its address, fails on any hit outside the worker's dead stack frames
(heap, other mappings, the worker's live frame, its TLS) and prints those inside them. Each of
its tests uses master keys of its own: a test thread computes the keys it looks for on its
stack, and the C library can give that stack to a later thread, so two tests looking for the
same keys found each other's computations (10 of 50 runs with two tests per provider and shared
keys, runs 45726164797, 45726174061, 45726181744, 45726197738; 0 of 40 with one test per
provider, 45726148580, 45726156299).

## Serialized state

`State::marshal_binary` returns the session's master secret in the clear inside its bytes, and
`unmarshal_binary` reads it from bytes the caller holds: protecting and erasing those bytes is
the application's responsibility. The format is unchanged.
