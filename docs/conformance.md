# Conformance

The engine does everything it claims, and claims nothing it doesn't do. A claim is a row of the
README's feature list, a row of `FORK.md`, the documentation of a public option, a codec or
attribute the default SDP offers, or a member the statistics report emits. This document holds
one row per claim: the specification section, where it is implemented, and the test that proves
it. What is deliberately not implemented is listed at the end, so nothing is implied that is not
there.

## How it is checked

Each area's rows live in a fragment under [`conformance/`](conformance/), written with the code
that makes the claim true. In every table with a **Test** column, each backticked name is a test
(`name`, `file.rs::name`) or a test file (`tests/x.rs`); `scripts/check-test-inventory.py` (the
`Test inventory` job in `cargo.yml`) fails when one does not exist, so a claim cannot outlive the
test behind it. Tables whose proof is an environment test or a browser-interop cell say
**Proved by** instead; `scripts/test-env/interop/gate.mjs` checks those (criterion C3).

The rest of the evidence that the claims hold:

- [Test exclusions](test-exclusions.md): every test runs on every platform CI tests, except the
  ones listed there with a reason and a covering test.
- [Upstream test parity](upstream-test-parity.md): every test of upstream `webrtc-rs/rtc` and
  `webrtc-rs/webrtc` v0.17.1 has a fork test, a mapped equivalent, or the reason it cannot exist.
- Fuzzing: every parser a peer, a server or an untrusted file reaches has a fuzz target, run by
  `fuzz.yml` and built by OSS-Fuzz ([fuzzing and gates](conformance/w7.md)).

## Claims, by area

| Area | Fragment |
|---|---|
| Data channels, SCTP | [conformance/w1.md](conformance/w1.md) |
| JSEP negotiation, codecs, transceivers, API state rules; SDP syntax and typed attributes (rtc-sdp) | [conformance/w2.md](conformance/w2.md) |
| ICE, TURN, STUN, DTLS, mDNS, SRTP | [conformance/w3.md](conformance/w3.md) |
| JSEP negotiation, codecs, transceivers, API state rules | [conformance/w2.md](conformance/w2.md) |
| ICE, TURN, STUN, DTLS, mDNS, SRTP, SFrame | [conformance/w3.md](conformance/w3.md) |
| RTP, RTCP, interceptors, payloaders, FEC | [conformance/w4.md](conformance/w4.md) |
| Statistics | [conformance/w5.md](conformance/w5.md) |
| The real-network environment and the browser matrix | [conformance/w6.md](conformance/w6.md) |
| Fuzzing and the repository's gates | [conformance/w7.md](conformance/w7.md) |

## Decisions that change a claim

| # | Claim | What the engine does |
|---|---|---|
| D1 | ULPFEC (RFC 5109) | Not offered by default: nothing encodes or decodes it. `MIME_TYPE_ULP_FEC` stays, and an application with its own coder registers it explicitly. RED is not implemented. |
| D2 | `bundle_policy` | The engine has one transport, so `balanced` and `max-compat` behave as `max-bundle`. A remote offer without BUNDLE gets a defined error, never a half-working session. |
| D3 | `SettingEngine` options with no effect in a sans-I/O engine (`receive_mtu`, `include_loopback_candidate`, `disable_media_engine_copy`) | `#[deprecated]` with the reason; no option is silently a no-op. `nat_1to1_ips` and `disable_media_engine_multiple_codecs` are implemented. |

## Not implemented, on purpose

These are outside what the engine claims. None is offered in the default SDP or implied by the
README.

| Area | Not implemented | Why |
|---|---|---|
| Media | Encoding, decoding, capture, playout | The engine is a transport. Statistics members that need them are left out of the report, not reported as 0. |
| DTLS | DTLS 1.3, RSA-PSS, connection id | Never claimed. Browsers negotiate DTLS 1.2 with it. |
| DTLS | Renegotiation; session resumption (session ids, tickets) | RFC 8827 section 6.5 forbids renegotiation in WebRTC and DTLS 1.3 removed it: a request is refused with the no_renegotiation warning (RFC 5746). WebRTC makes one association per transport, so nothing would be resumed: a ClientHello's session id is read and answered with a full handshake, and none is offered. What implementing resumption would take is written down in [`conformance/audit/rfc5246.md`](conformance/audit/rfc5246.md). |
| SCTP | I-DATA (RFC 8260), Add Streams (RFC 6525 4.5), path MTU discovery, zero checksum (RFC 9653), RACK-TLP | Never claimed; none is needed for a browser data channel. |
| TURN | TCP allocations (RFC 6062), a TURN server | Never claimed. The TURN client is implemented. |
| STUN | NAT behaviour discovery (RFC 5780): the discovery procedures, CHANGE-REQUEST / RESPONSE-PORT / PADDING as typed attributes; backwards compatibility with RFC 3489 (no magic cookie); resending a request after a 5xx; resolving a server name (SRV, A / AAAA) and (D)TLS to a STUN server | RFC 5780 is experimental and outside the WebRTC specification set; RESPONSE-ORIGIN and OTHER-ADDRESS are encoded and decoded, the rest are code points. RFC 3489 compatibility and the 5xx resend are optional in RFC 8489 (§11, §6.3.4). `rtc-stun` performs no I/O: the application resolves names (`Uri::srv_query_name`, `Uri::port_or_default`) and owns the connection. |
| TURN | A TURN server; relay candidates with transport TCP | Never claimed. The TURN client is implemented, TCP allocations (RFC 6062) included, but ICE gathers no relayed TCP candidate from one. |
| SRTP | AEAD double (RFC 8723), MKI, EKT | Never claimed. |
| SRTP | AEAD double (RFC 8723), EKT, the SEED and ARIA transforms | Never claimed. |
| SRTP | AES-f8 (RFC 3711 4.1.2) | Optional in RFC 3711 (section 5 makes AES-CM, the NULL cipher and HMAC-SHA1 mandatory), with no DTLS-SRTP code point in the IANA registry. To add it: `k_e`, `k_s`, `k_a` as for AES-CM; `IV' = E(k_e XOR m, IV)` with `m = k_s \|\| 0x555..5`; `S(j) = E(k_e, IV' XOR j XOR S(j-1))`, `S(-1) = 0`; the SRTP IV is `0x00 \|\| M \|\| PT \|\| SEQ \|\| TS \|\| SSRC \|\| ROC` and the SRTCP IV `0..0 \|\| E \|\| SRTCP index \|\| V \|\| P \|\| RC \|\| PT \|\| length \|\| SSRC` (4.1.2.2, 4.1.2.3); at most 2^32 blocks per IV; test vectors in Appendix B.1. It needs only `RTCCrypto::block_encrypt` and a third `Cipher` implementation beside the two in `rtc-srtp/src/cipher/`. |
| SRTP | `<From, To>` master key lifetimes (RFC 3711 8.1.1) | Optional. Re-keying is by MKI (`Context::add_master_key`) or a new DTLS-SRTP handshake. |
| SRTP | Negotiation of an MKI (`use_srtp` `srtp_mki`), of RFC 6904 (`urn:ietf:params:rtp-hdrext:encrypt`), and of the NULL-cipher and RFC 6188 counter-mode profiles by a peer connection | `rtc-srtp` implements all of them ([SRTP claims](conformance/w3.md)); a peer connection negotiates none. The NULL cipher is forbidden in WebRTC (RFC 8827 6.5), the RFC 6188 suites have no DTLS-SRTP code point, and browsers use Cryptex (RFC 9335), not RFC 6904. |
| SFrame | An SFrame RTP payload format (draft-ietf-avtcore-rtp-sframe), its SDP signalling, a transceiver switch | `rtc-sframe` encrypts and decrypts; the application packetizes the ciphertext and signals its use. |
| FEC | FlexFEC as RFC 8627 | Only draft-ietf-payload-flexible-fec-scheme-03 is implemented, and the codec name is matched exactly so RFC 8627 `flexfec` is never fed to it. |
| RTP | H.264 STAP-B / MTAP / FU-B (interleaved mode, never offered); `scalabilityMode` on an encoding | Simulcast is implemented. The SVC modes, their layer structures and their signalling (VP8 / VP9 payload descriptors, AV1 with the Dependency Descriptor) are in `rtc-rtp` for an application to use ([conformance/w4.md](conformance/w4.md)); the encoding parameter, its validation and offering the Dependency Descriptor by default are not. |
| Identity | `peer_identity`, identity providers | Applications (Deno, for one) implement webrtc-identity above the engine. |
| W3C API | `RTCDTMFSender` | Applications implement DTMF above the engine; the engine sends the telephone-event packets it is given. |
| Test platforms | The real-network environment and browser interop run on Linux only | They need network namespaces. Unit and integration tests run on Linux, macOS and Windows. |
| Web platform tests | WPT | They test a browser API, not this crate; the Deno integration runs them. |

## Known bugs

None open is the bar for calling a release conformant: each bug found is either fixed, with a test
and a row in its area's fragment, or its claim is withdrawn and the feature moves to the table
above. An open bug is listed here, with its spec section and the issue that tracks it, until then.
