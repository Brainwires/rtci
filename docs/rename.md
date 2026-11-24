# The rename from `rtc` to `rtci`

The crates are renamed from the `rtc` family to `rtci` ("an RTC implementation"): the root crate
`rtc` becomes `rtci`, every `rtc-<x>` crate `rtci-<x>` (library paths `rtc_<x>` -> `rtci_<x>`),
the repository becomes `Brainwires/rtci`, and the version line restarts at `0.1.0` (tag `v0.1.0`):
crates.io ignores the `+brainwires.N` build metadata of the `0.22.0+brainwires.N` line, so it
cannot order those releases. The earlier tags stay as they are.

The rename is made by one script, `scripts/rename-to-rtci.py`, as one commit at the end of an
integration train. It works on whatever tree it is run on: the crate names come from
`cargo metadata` at run time, so crates a later branch adds are renamed too.

## Running it

From a clean checkout (no build output inside the crate directories: a directory the rename
moves to must not exist; the script stops before changing anything if one does):

```sh
python3 scripts/rename-to-rtci.py --dry-run     # every planned change, counts per category
python3 scripts/rename-to-rtci.py               # apply; prints the counts, the publication
                                                # order and what it left on purpose
python3 scripts/rename-to-rtci.py --check       # exit 0: nothing left to rename
cargo check --workspace --all-targets && cargo fmt --all --check
git add -A && git commit                        # the one rename commit
```

Other modes: `--residue` prints every old-name occurrence left on purpose, grouped by reason;
`--manifest-report` lists what crates.io needs per publishable crate. Options: `--root DIR`,
`--no-fmt`, `--no-lock`, `--quiet`. It needs Python 3 (standard library only), git and cargo.

It is deterministic and idempotent: a second run changes nothing and exits 0. The one-time steps
(the version reset, the lineage text in README.md and FORK.md, the CHANGELOG entry, FORK.md's
release row, the publication list in release.yml and the workflow and parity-tooling patches)
run only while the tree still has crates under the old names. After the rename, `--check` is a CI
gate (the rename adds it to cargo.yml's `test_inventory` job): it fails, printing each site, when
a later change brings an old name back, and `python3 scripts/rename-to-rtci.py` fixes it.

## What it renames

Crate discovery: the root `Cargo.toml` and every tracked `Cargo.toml` with a `[workspace]` table
(the fuzz crates, the test environment's peers, the benchmark) go through
`cargo metadata --no-deps`; every package named `rtc` or `rtc-*` (or already `rtci`/`rtci-*`) is
one of ours, with its library name and kinds. Nothing else is matched: names are exact, longest
first, with word boundaries for the file type.

| Where | What changes |
|---|---|
| Crate directories | `git mv rtc-<x> rtci-<x>` for every crate whose directory carries its name. The root crate stays at the repository root. |
| `Cargo.toml` | package names, `members`, path dependencies, dependency keys and `package = "..."`, `[dependencies.<crate>]` tables, `[profile.<name>.package.<crate>]` tables, `[patch]` / `[replace]`, feature references (`rtc/x`, `dep:rtc`), `documentation` (docs.rs), `repository` (to `Brainwires/rtci`), the workspace version and every version requirement on our crates (to `0.1.0`). A dependency named `rtc` without `path` or `workspace = true` is upstream's crate on crates.io and stays. |
| Rust | `rtc::`, `::rtc::`, `use rtc;`, `extern crate rtc`, `rtc_<x>` paths (also inside `quote!`, doc links and doc tests), `"rtc"` next to `CARGO_PKG_NAME`. `foo::rtc::`, `webrtc::`, `rtcp`, `RTCPeerConnection` and identifiers such as `rtc_pc` do not match. |
| Workflows, scripts, configuration | `-p` / `--package` / `--features rtc/...`, crate names in job names, paths filters, matrices, artifact names, quoted `"rtc"` / `'rtc'`, shell words (`oss-fuzz/build.sh`), job ids that start with a library name, globs `rtc-*`, `RUST_LOG` targets, the repository name `webrtc-rs-rtc`, cliff.toml's commit link (it pointed at `webrtc-rs/rtc`; now `Brainwires/rtci`). |
| Markdown | crate names and paths, code spans `` `rtc` ``, `rtc::` paths, cargo flags, TOML snippets (`rtc = "0.21"` -> `rtci = "0.1"`), Rust code blocks with the Rust rules, and `sh` / `bash` / `shell` / `console` / `zsh` blocks with the shell rules (a bare `rtc` word there is the crate, as in a `for p in ... rtc; do` publish loop). |
| CHANGELOG.md | only `## [Unreleased]` (created if missing), plus one entry describing the rename. Released sections stay byte for byte. |
| Lock files | committed `Cargo.lock` files that name our crates (today `scripts/test-env/peers/layers/Cargo.lock`) are regenerated with `cargo metadata` (offline when the registry cache has everything); the script checks that no registry package changed version. |
| C interface (when the tree has a `cdylib` / `staticlib` crate) | the library (`librtc_ffi` -> `librtci_ffi`), the header file (`rtc.h` -> `rtci.h`, `git mv`), and every name the header exports, see below. The header's continuation lines are re-aligned to the longer names, so it equals what cbindgen 0.29.2 generates from the renamed sources (cargo.yml's `c_header` job). |
| Formatting | `cargo fmt --all` on each workspace that was rustfmt-clean before the rename (the names get one character longer, which can move a line break). Workspaces that were not clean are left as they were and reported. |

Two workflow patches keep CI meaning the same: cargo.yml's packaging job accepted only cargo's
"failed to select a version for `rtc-crypto`" (the crate existed upstream); `rtci-crypto` does not
exist on crates.io at all, so "no matching package named `rtci-crypto`" is accepted too. And the
`--check` gate step is added after `audit-count.py --check`. If a later tree moved those lines the
patch is skipped with a warning.

`scripts/check-test-parity.py` keys upstream's tests by upstream's crate names
(`docs/upstream-tests/*.txt` are generated from upstream checkouts and the parity table's `Crate`
column follows them). Those stay; the script gets a two-line patch that maps the fork's `rtci-<x>`
directories back to `rtc-<x>` when it collects the fork's tests.

## What it leaves on purpose

After applying, the script prints every remaining occurrence of the old names, grouped by reason.
On the tree the rename commit was made from (master `56b6476b` with `conf/gcc-8-paced-picture-guard`; 6027 occurrences):

| Reason | Count |
|---|---|
| Upstream test lists `docs/upstream-tests/*.txt` (upstream data) | 3481 |
| Identifiers and names that are not crate names (`rtc_pc` 516, `rtc_connected` 108, test names such as `offer_answer_rtc2rtc`, `rtc-env`, `rtc-testenv`, `rtc-interop`, thread names) | 1246 |
| The word `rtc` in prose, local variables, strings and keys (not a crate path) | 409 |
| URLs of other projects: upstream's repository, badges, crates.io and docs.rs pages of upstream's crates, the webrtc.rs logo files | 57 |
| Released CHANGELOG sections | 170 |
| The rename script and its tests (and, once committed, this page) | 412 |
| The parity table's rows (upstream keys) | 105 |
| Byte-string and C-string data literals: hashed, signed, AAD, KDF labels, test vectors (a peer or a fixture must agree) | 17 |
| `docs/crypto-provider-migration.md`, the migration guide of the `rtc` 0.21 line (history) | 51 |
| The test environment's realm `rtc.test` (certificates, coturn) | 27 |
| `scripts/check-test-parity.py` (upstream names) | 23 |
| The layers peer's lock file before regeneration | 19 |
| FORK.md table cells about upstream (`Upstream changes not taken`, `Fork features dropped`) and `upstream's rtc-...` statements | 7 |
| fuzz.yml's runner-plan key `rtc` (a job key like `dtls`; check-fuzz-registry.py checks it) | 3 |

Also unchanged: W3C and IETF names in Rust and C (`RTCPeerConnection`, `RTCRtpSender`,
`RTCIceCandidate`, `RTCConfiguration`, `RTCP`, `rtcp-mux`, `srtcp`, `webrtc`), licence files and
copyright lines (`authors` keeps upstream's author), git history (commit ids, old branch and tag
names), fixture data, the test environment's environment variables (`RTC_TESTENV_*`,
`RTC_INTEROP_*`) and its directories (`/run/rtc-env`), and the crate READMEs' badges, which
point at upstream's crates.io pages. The test files named after the old crates
(`dimpl_rtc_dtls.rs`, `rice_rtc_ice.rs`, `*_rtc2rtc.rs`) keep their names: the test inventory and
the audit tables cite them.

The rules are in the script's tables: `EXCLUDED_PATHS` (files never edited), `SECTION_RULES`
(Markdown sections whose table cells name upstream's crates), `EXCEPTIONS` (places where the bare
word `rtc` is not the crate), `DATA_LITERALS` (string literals the data rule below cannot decide)
and `PATCHES` (the one-time code patches).

### Data literals

A label's text is not a brand; it is data. Bytes that are hashed, signed, used as AEAD associated
data or a key-derivation label, compared with a fixed expected value, or that a peer on the old
name must agree with keep their text. The first application renamed `b"rtc-crypto verification
vector"`, the message of fixed P-384 and RSASSA-PSS signatures, and `rtci-crypto`'s
`ring_provider_conforms` failed. The rule, in Rust source and in Rust code blocks in Markdown:

1. A byte string (`b"…"`, `br"…"`, `br#"…"#`), byte character or C string (`c"…"`) is never
   rewritten.
2. A string literal turned into bytes on the spot (`"…".as_bytes()`, `.into_bytes()`, `.bytes()`,
   `Bytes::from_static("…")`, `Bytes::from("…")`) is not rewritten either.
3. Where neither rule sees it (a `&str` constant used as bytes elsewhere), `DATA_LITERALS` names the
   literal, `keep` or `rename`, with the reason.

Everything else in a string literal is renamed like code. What is kept is printed in the residue
with its reason and does not count for `--check`.

Audit of master `4e6de256`: the script without the rule rewrote 39 literals.

Kept (14 byte strings, rule 1):

| Literal | Where | Why it is data |
|---|---|---|
| `b"rtc-crypto provider conformance"` | `rtc-crypto/src/conformance.rs:616` | message signed and verified across providers |
| `b"rtc-crypto verification vector"` | `rtc-crypto/src/conformance.rs:657` | message of the fixed P-384 signature vectors |
| `b"rtc-crypto RSASSA-PSS verification vector"` | `rtc-crypto/src/conformance.rs:1001` | message of the fixed RSASSA-PSS signature vector |
| `b"rtc-dtls dtls13 ticket"` (`TICKET_AAD`) | `rtc-dtls/src/dtls13/psk.rs:36` | AEAD associated data of session tickets: tickets issued before the rename must still open |
| `b"rtc-dtls dtls12 ticket"` (`DTLS12_TICKET_AAD`) | `rtc-dtls/src/dtls13/psk.rs:40` | the same for DTLS 1.2 tickets |
| `b"rtc-sframe decoy"` (`DECOY_BASE_KEY`) | `rtc-sframe/src/context.rs:75` | key material of the decoy context |
| `b"rtc-dtls-test"` (PSK identity hint), 3 | `rtc-dtls/src/config/config_test.rs:152`, `rtc-dtls/src/endpoint.rs:1148`, `:1941` | protocol data sent in ServerKeyExchange |
| `b"rtc-dtls-fuzz"` (PSK identity hint) | `rtc-dtls/src/fuzzing.rs:116` | protocol data; fuzz seeds made with it keep their meaning |
| `b"hello from the rtc-dtls client\n"`, `…server\n"` | `rtc-dtls/examples/dtls_interop.rs:321`, `:323` | application payload an interop peer receives |
| `b"from rtc-dtls"`, 2 | `scripts/test-env/peers/layers/tests/dimpl_rtc_dtls.rs:309`, `:314` | payload sent and compared with the received bytes |

Renamed (25 `&str` literals, human-facing):

| Literal | Where | Why it is a name |
|---|---|---|
| `"rtc-ice "` in `DEFAULT_SOFTWARE` | `rtc-ice/src/agent/mod.rs:287` | STUN SOFTWARE product name (RFC 8489 14.14, informational, carries the version; no peer compares it). Listed `rename` in `DATA_LITERALS` |
| `"rtc-turn "` in `DEFAULT_SOFTWARE`, and its test | `rtc-turn/src/client/mod.rs:395`, `client_software_mtu_test.rs:29` | the same for TURN; listed `rename` |
| clap `about` texts, 3 | `rtc-mdns/examples/mdns_query.rs:32`, `mdns_server.rs:32`, `mdns_server_query.rs:35` | CLI help text |
| assertion and error messages, 7 | `rtc-sctp/src/endpoint/endpoint_test.rs:3196`, `tests/sctp_rfc_defaults_rtc2rtc.rs:304`, `scripts/test-env/peers/layers/tests/dimpl_rtc_dtls.rs:256`, `:323`, `rice_rtc_ice.rs:234`, `:252`, `:307` | messages for people |
| behaviour-profile texts, 12 sites | `src/peer_connection/configuration/behaviour_profile.rs:156`, `:292`, `:458`, `:460`, `:862`, `:876`, `:1563`, `:1573`, `:1608` | documentation strings; `docs/behaviour-profiles.md` is generated from them and renamed alike |

Also checked, nothing to keep: no `&str` with an old name is used as bytes (`.as_bytes()` and the
like), no `include_bytes!` / `include_str!` path names an old crate, no Markdown or doc-comment
example holds a byte string with one, and no fixture, corpus, `.sdp`, `.pem`, `.bin` or JSON
vector contains one (those paths are excluded anyway). The bare word `rtc` in data (`b"rtc"` as
AEAD associated data in `rtc-crypto/tests/cross_provider.rs`, `b"turn.rtc.test"`) was never
rewritten; the residue now gives it the data reason.

## The C interface

Rule: a name changes when the crate's own prefix made it, never when a specification made it.

| Changes | From | To |
|---|---|---|
| Functions and types the header exports, lower case | `rtc_pc_*`, `rtc_driven_*`, `rtc_mux_*`, `rtc_string_free`, `rtc_last_error`, `rtc_version`, `rtc_abi_version`, `rtc_debug_live_objects`, `rtc_addr`, `rtc_transport`, `rtc_message` | `rtci_...` |
| Constants and macros the header exports | `RTC_OK`, `RTC_EMPTY`, `RTC_ERR_*`, `RTC_PROTOCOL_*`, `RTC_MESSAGE_*`, `RTC_ABI_VERSION` | `RTCI_...` |
| Include guard and configuration macros | `RTC_FFI_H`, `RTC_FFI_DRIVER`, `RTC_FFI_NO_DRIVER` | `RTCI_FFI_...` |
| Names made from the library name | `RTC_FFI_LIB` (the Deno binding's library path), `RTC_FFI_TARGET` (build script) | `RTCI_FFI_...` |
| Library and header files | `librtc_ffi.{so,a,dylib}`, `rtc_ffi.dll`, `include/rtc.h` | `librtci_ffi...`, `rtci_ffi.dll`, `include/rtci.h` |

Unchanged: every W3C-defined name (`RTCConfiguration`, `RTCDataChannelInit`, `RTCIceCandidateInit`,
`RTCOfferOptions`, `RTCAnswerOptions`, `RTCRtpTransceiverInit` ... in comments and JSON), and the
Rust-side type names of the FFI crate (`RtcAddr`, `RtcTransport`, `RtcMessage`,
`RtcDrivenCallback`): cbindgen's `[export.rename]` gives them their C names, which change.

The set of exported names is read from the FFI crate's header at run time (`rtc_` / `RTC_` words in
it) and renamed only in the FFI crate's directory and in files that name the FFI crate, its library
or its header, so a local variable called `rtc_pc` elsewhere stays.

## Publication order

`cargo publish` order for the new names, dependencies first (normal and build dependencies, and
versioned dev-dependencies), generated from `cargo metadata` and written into release.yml's
commented publish step. `docs/releasing.md` ("What is published") is the reference; 0.1.0 is
published in this order:

1. `rtci-crypto`
2. `rtci-interceptor-derive`
3. `rtci-sframe`
4. `rtci-shared`
5. `rtci-dtls`
6. `rtci-mdns`
7. `rtci-rtcp`
8. `rtci-rtp`
9. `rtci-interceptor`
10. `rtci-media`
11. `rtci-sctp`
12. `rtci-datachannel`
13. `rtci-sdp`
14. `rtci-srtp`
15. `rtci-stun`
16. `rtci-ice`
17. `rtci-turn`
18. `rtci`
19. `rtci-stream-driver` (its default feature `peer` depends on `rtci`)

The root crate's dev-dependencies on `rtci-stream-driver` and `rtci-signal` carry no version, so
`cargo publish` drops them from `rtci`'s published manifest. `rtci-signal` (the examples'
signalling helper) is `publish = false`, as are the fuzz crates, the benchmark and the test
environment's peers.

crates.io fields (`--manifest-report`): every publishable crate has a description, a README, the
licence `MIT OR Apache-2.0` and `repository = "https://github.com/Brainwires/rtci"`, all
inherited from `[workspace.package]` where they are shared; none sets `homepage`.

## For dependents

| Before | After |
|---|---|
| `rtc = "0.22"` (or a git dependency on `Brainwires/webrtc-rs-rtc`) | `rtci = "0.1"` from crates.io |
| `rtc-<x> = "..."` | `rtci-<x> = "0.1"` |
| `use rtc::...` | `use rtci::...` |
| `use rtc_<x>::...` | `use rtci_<x>::...` |
| `features = ["rtc/crypto-ring"]` in a dependent's own feature list | `["rtci/crypto-ring"]` |
| Cargo features of the crates (`crypto-ring`, `crypto-aws-lc-rs`, `openssl`, `pem`, ...) | unchanged |
| W3C / IETF type names (`RTCPeerConnection`, `RTCRtpSender`, ...) | unchanged |
| C: `librtc_ffi`, `#include "rtc.h"`, `rtc_*`, `RTC_*` | `librtci_ffi`, `#include "rtci.h"`, `rtci_*`, `RTCI_*` (W3C names unchanged) |
| `RUST_LOG=rtc=debug,rtc_ice=trace` | `RUST_LOG=rtci=debug,rtci_ice=trace` |

A dependent that keeps its code unchanged can rename on its side instead:
`rtc = { package = "rtci", version = "0.1" }`.

A git dependency on the old repository URL keeps resolving through GitHub's redirect (at the old
tags the crates are still `rtc`; from `v0.1.0` on there is no crate `rtc` to find). Move it to the
crates.io release rather than to a git dependency on `Brainwires/rtci`.
