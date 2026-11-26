# Key erasure in rtci-dtls, rtci-srtp and rtci-crypto

The rule: memory a secret was in is overwritten before it is freed. Every struct holding secret
key material derives `Zeroize` and `ZeroizeOnDrop`, or holds each secret in a type that does
(`crypto::SecretVec`, `zeroize::Zeroizing`). Key material is never built in a buffer that
grows: a `Vec` that grows moves to a new allocation and frees the old one as it is. Clauses:
RFC 5246 section 8.1 (the premaster secret is deleted once the master secret exists), RFC 8446
section 7.1 (a secret is erased once what derives from it is computed), RFC 7714
section 13.1 (SRTP keys, and a secret master salt, erased when no longer needed; RFC 3711 itself
has no erasure clause: its section 3.2.1 has the master key "kept secret").

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
| SRTP session keys, salts, KDF output | `SecretVec` | yes | yes | `rtci-srtp/tests/key_schedule_erasure.rs` |
| SRTP AES-CM key schedules (payload cipher of the AES-CM profiles; RFC 6904 header-extension keystream of every profile) | 0.2.0: the key in a `SecretVec`, expanded into both AES schedules on the stack for every packet. Now: the expanded schedule in the boxed cipher object (`AesCtr`), used through a reference | heap: yes; stack: no (never observed in 0.1.0 / 0.2.0; measured for this change: both schedules of the SRTCP and header-extension keys in dead stack frames after every packet) | yes: nothing is expanded per packet; the object is overwritten whole when dropped and built over overwritten stack | `rtci-srtp/tests/key_residue.rs`, `key_schedule_erasure.rs` |
| SRTP HMAC-SHA1 states (AES-CM, NULL profiles) | ring provider: RustCrypto `hmac` / `sha1` in a boxed object; AWS-LC: `HMAC_CTX` | ring: heap no in 0.1.0, yes in 0.2.0; stack no (each MAC was computed on a copy of the keyed object in a stack frame) | ring: yes (`hmac` 0.13, `sha1` 0.11 with `zeroize`; computed in the keyed object, in place). AWS-LC: heap yes, stack NO (its limit, below) | `with_ring_no_key_is_left_in_freed_rust_memory`, `key_residue.rs` |
| SRTP AES-GCM keys and round keys | the provider's AEAD object | ring: no; AWS-LC: yes | yes: ring's `LessSafeKey` in an `ErasedOnDrop` allocation, overwritten after the drop; what building it leaves on the stack is overwritten (`on_erased_stack`) | `with_ring_no_key_is_left_in_freed_rust_memory`, `key_residue.rs`, `aws_lc_*` |
| What building an SRTP context, re-deriving session keys and adding a master key leave on the stack (the master key and both of its AES schedules, session round keys, GHASH key, HMAC states) | dead stack frames of the calling thread | no | yes: run under `crypto::on_erased_stack` | `key_residue.rs` (build, rekey steps) |
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
- Stack copies in DTLS. Building a key object leaves copies in the dead stack frames of the
  functions that built it, and a value moved out of the wrapper would be a copy it cannot
  reach (the wrapper never moves its value out). The DTLS crate calls `crypto::scrub_stack()`
  after building keyed objects and after key agreement. What the tests show for DTLS: copies
  carried from dead frames into heap padding were found and the scrub removes them (its
  removal is caught, m13 of the first round); DTLS has no stack measurement of the kind SRTP
  has (next section), so for a copy that stays on the stack DTLS is "scrubbed, not measured".
  `scrub_stack` is one bulk zero fill of a 32 KiB buffer in a never-inlined frame, made
  observable to the optimiser (`black_box` and a compiler fence) so it is not dropped as a
  dead store; it reaches the stack below its caller only, never registers or the frames above.
  Tested (zeroize3, ubuntu): its body emptied, the DTLS erasure tests fail in debug and release
  builds (runs 45659948616, 45659954724); the fill left unobservable, they fail in a release
  build (45659972471) and pass in a debug build (45659963417: at opt-level 0 nothing is
  removed, so the two cannot be told apart there). Cost: about 0.5 to 0.7 µs per call.

## SRTP keys on the stack: what is guaranteed, and how it is known

RFC 7714 section 13.1: "If the master salt is to be kept secret, it MUST be properly erased when
no longer needed", and "The secret master key and all keys derived from it MUST be kept secret.
All keys MUST be properly erased when no longer needed."

**The measurement** (`rtci-srtp/tests/key_residue.rs`). Each step of a session's life runs on a
worker thread whose stack the test maps itself and fills with a known byte: building the
contexts, protecting and unprotecting RTP and RTCP (with RFC 6904 header-extension encryption),
re-keying (an MKI and a key derivation rate of two packets: session keys derived again on the
packet path, a second master key added and the first removed), tearing down. The contexts go
from one worker to the next as boxes, so what a worker's dead frames hold is what that step
left, and the test reads those bytes while the worker waits. Every key the session derives is
looked for in every form: the keys, the AES round keys of both schedules, the GHASH key (as
`H`, as two host-order words, and as the `H·x` table entry of carry-less-multiplication code),
the HMAC padded keys and both SHA-1 states in both word orders, the header-extension keys, each
key derivation epoch, the master key and the master salt. On Linux the whole process is searched
as well, while the contexts are alive (the search must find the keys where they are kept, and
must not find a master-key schedule in the heap) and after the teardown (nothing may be left
outside the workers' dead frames). A control leaves a key on a stack, in the heap, in a freed
block and in static data and finds each, and does not find an erased one. The inventories are
identical, digest for digest, in the test-environment image (glibc 2.39) and on GitHub's
runners (glibc 2.43) with one compiler.

**What 0.2.0 left** (ring provider, rustc 1.99.1, x86-64 Linux: 1943 key forms over the ten
profiles and both ways of keying, 2137 with rustc 1.100; 1995 on AArch64 macOS, the same
picture; the AWS-LC provider 1817):

| Step | `Context::new` | with an MKI and a key derivation rate |
|---|---|---|
| building | 298: the master key and both of its AES schedules (227), SRTCP HMAC-SHA1 states, SRTCP and SRTP round keys, for AES-GCM the GHASH key and table entry | the same |
| packets | 273: both AES schedules of the SRTCP and header-extension encryption keys, HMAC-SHA1 states | 537: the same and, from deriving again, the master key |
| re-keying | n/a | 537, for the new master key |
| tearing down | 0 | 0 |

Nothing outside dead stack frames, ever: no heap block, no other mapping. What a step leaves
is what the last calls at each depth wrote; later calls overwrite earlier residue, so the SRTP
keys are mostly hidden under the SRTCP ones in this table.

**What is done about it**

- Building a context, deriving session keys again and adding a master key run under
  `crypto::on_erased_stack`: the work runs in a frame of its own and the 32 KiB of stack below
  it are overwritten afterwards (`scrub_stack`). The built-in providers use about 3 KiB there
  in an optimised build.
- AES-CM: the expanded schedule lives in the boxed cipher object and a packet runs the counter
  mode over a reference to it; nothing is expanded per packet. `aes`'s cipher types are unions
  of a hardware and a larger portable schedule and the bytes of the variant not in use are
  never written by it (they are what the stack held where the value was built), so the object
  is overwritten whole when dropped, used bytes or not, and is built over stack that has just
  been overwritten.
- HMAC-SHA1 (ring provider): `hmac` 0.13 and `sha1` 0.11 with their `zeroize` features; the
  keyed object is boxed and a MAC is computed in it (`update`, `finalize_reset`). The one copy
  the crate makes per MAC (the outer state) is overwritten by the crate when dropped. With
  `hmac` 0.12, as in 0.2.0, each MAC was computed on a copy of the whole keyed object in a
  stack frame: with everything else of this change in place that alone left 42 key forms in an
  optimised build on x86-64 Linux and 36 on AArch64 macOS.
- ring's AES-GCM `seal` / `open` were measured to leave no form of the key in a stack frame
  (x86-64 with AES-NI, AArch64 with the ARMv8 extensions): nothing to do there.

**What is guaranteed, by which test**

| Claim | Where it is asserted |
|---|---|
| ring provider (the default), optimised build, every profile, both ways of keying: no key the session derives is found in any form in the dead stack frames of the thread that built the contexts, protected and unprotected packets, re-keyed or tore down | `with_ring_key_handling_leaves_no_key_in_dead_stack_frames`, CI job `key_residue`: x86-64 Linux and AArch64 macOS |
| the same thread, the same build: nothing is left anywhere else in the process after the teardown, and no master-key schedule is in the heap while the contexts live | the same test, Linux (whole-process search) |
| either provider, any build: building and tearing down leave nothing in dead stack frames | the same test and `with_aws_lc_building_and_tearing_down_leave_no_key_in_dead_stack_frames`, in the ordinary test jobs (Linux, macOS) |
| HMAC-SHA1 computed in the keyed object is correct and the object is reusable | `rtci-crypto/tests/hmac_sha1_vectors.rs` (RFC 2202 cases 1 to 7), and the SRTP, DTLS and STUN vectors of their crates |

**What is not guaranteed**

- **The AWS-LC provider's packet path.** AWS-LC computes each HMAC on a copy of the keyed
  context in a stack frame of its own, and its AES-GCM leaves a GHASH table entry in one: every
  protected or unprotected packet leaves the SRTP / SRTCP HMAC-SHA1 states (AES-CM and NULL
  profiles) or a form of the GCM key in dead stack frames, 78 key forms over the profiles in
  unoptimised and optimised builds alike. The engine does not overwrite the stack after every
  packet. `known_limit_with_aws_lc_the_packet_path_leaves_keys_in_dead_stack_frames` (ignored)
  is the limit as a test.
- **Unoptimised builds.** At opt-level 0 the compiler stores every intermediate value of the
  AES and SHA-1 routines in a stack slot, round keys and hash states included, whatever the
  source does, and how much of that survives depends on the compiler (an intermediate state of
  this work left 24 key forms with rustc 1.100 and 96 with rustc 1.99.1 from the same sources).
  The packet path is therefore asserted in optimised builds only; in unoptimised ones the test
  prints what it finds.
- **CPU registers, and whatever stores them on a stack.** A provider's AES leaves round keys in
  vector registers when it returns. A signal delivered next puts them into the signal frame; on
  Apple systems the lazy set-up of a thread-local saves the vector registers on the caller's
  stack (seen once during this work: one AES-GCM round key of the ring provider, when a
  thread-local was first used in a thread right after a packet). The engine's packet path uses
  no thread-local and installs no signal handler; it cannot speak for the application's.
- **Windows; architectures other than x86-64 and AArch64.** The code is the same and the heap
  searches run on Windows, but the stack measurement needs a thread on a stack of the test's
  own (`pthread_attr_setstack`) and has run on x86-64 Linux and AArch64 macOS only. On
  processors without the AES and SHA instructions the portable routines of `aes`, `sha1` and
  ring run instead, which nothing here has measured.
- **Deeper than 32 KiB.** `on_erased_stack` overwrites 32 KiB below its frame. A provider
  supplied by the application that uses more stack than that to build a key object leaves what
  lies deeper.
- **DTLS.** Scrubbed (above), not measured in this way.

For an application: nothing is asked of it for SRTP with the default provider. With the AWS-LC
provider, the thread that protects and unprotects packets keeps HMAC-SHA1 states or a GCM key
form in its dead stack frames until later calls on that thread overwrite them; call
`crypto::scrub_stack()` from that thread when a session ends if that matters.

The AWS-LC provider (`crypto-aws-lc-rs`) cleanses its `EVP_AEAD_CTX` and `HMAC_CTX` itself: no
freed block and no other part of the process holds a key after the drop, for every SRTP profile
and the DTLS suites tested. What its packet path leaves in stack frames is in the next section.

## What the tests look at

`tests/dtls_secret_erasure.rs` runs associations over a provider wrapper that records every
secret crossing the provider boundary (kept inverted) and derives what the association
computes from them; a test allocator keeps every block freed during the association (and
tracks those still allocated after it) and searches them all. On Linux the whole process is
searched after a worker thread has dropped the association. `rtci-srtp/tests/key_*` do the
same for SRTP contexts with keys they compute themselves; `rtci-srtp/tests/key_residue.rs` is
the stack measurement described above, with the whole-process search on Linux. It computes the
keys it looks for on a worker whose stack is overwritten and unmapped before anything is
searched, so no stack of a test thread ever holds one, and leaves nothing out of the search.
(The process search it replaced left out the whole mapping that held the searching thread's
stack, which with glibc 2.42 and later is also the mapping of the worker's stack; and the
stack of a thread that has ended is mostly given back to the kernel by glibc. It therefore saw
part of the residue in one environment and none in another:
`investigate_how_the_c_library_treats_thread_stacks` prints the facts.)

## Serialized state

`State::marshal_binary` returns the session's master secret in the clear inside its bytes, and
`unmarshal_binary` reads it from bytes the caller holds: protecting and erasing those bytes is
the application's responsibility. The format is unchanged.
