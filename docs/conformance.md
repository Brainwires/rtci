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
| D1 | ULPFEC (RFC 5109) | Implemented, opt-in, and not offered by default. `configure_ulpfec` adds the encoder and decoder for ULPFEC carried in RED (RFC 2198), the form browsers negotiate for video; the application registers `video/red` and `MIME_TYPE_ULP_FEC` and passes their payload types. The RED payload format (RFC 2198) is in `rtc-rtp` (`codec::red`); the engine uses it for that carriage only: it neither offers `red` for audio nor wraps or unwraps audio in it. A separate FEC RTP session (RFC 5109 14.1) is not expressible over one transport. |
| D2 | `bundle_policy` | The engine has one transport, so `balanced` and `max-compat` behave as `max-bundle`. A remote offer without BUNDLE gets a defined error, never a half-working session. |
| D1 | ULPFEC (RFC 5109) | Not offered by default: nothing encodes or decodes it. `MIME_TYPE_ULP_FEC` stays, and an application with its own coder registers it explicitly. RED is not implemented. |
| D2 | `bundle_policy` | The engine has one transport. The policy decides what an initial offer marks `a=bundle-only` and which sections of an offer without a BUNDLE group are answered (RFC 9429 4.1.1; `balanced` is the default; `must-bundle` is a policy; `max-bundle`, which W3C webrtc-pc 4.2.5 still defines, is that policy too, unless `with_max_bundle_as_must_bundle(false)` has it ignored as the RFC's SHOULD says), but every section shares the one set of ICE credentials, also under `max-compat`. A remote description whose sections need separate transports (different ICE credentials outside a BUNDLE group) gets a defined error, never a half-working session. |
| D3 | `SettingEngine` options with no effect in a sans-I/O engine (`receive_mtu`, `include_loopback_candidate`, `disable_media_engine_copy`) | `#[deprecated]` with the reason; no option is silently a no-op. `nat_1to1_ips` and `disable_media_engine_multiple_codecs` are implemented. |
| D4 | FlexFEC draft-03 (`video/flexfec-03`) where libwebrtc departs from the draft's letter | The engine follows libwebrtc, the only draft-03 peer: mask bit j names the packet SN base + j (the draft's text says SN base + j + 1; RFC 8627 4.2.2.1 later wrote down what libwebrtc does), and the coder answers to the subtype `flexfec-03` only (the draft registers `flexfec`, which now means RFC 8627 and selects that coder). Both are pinned by tests (`mask_bit_j_names_sn_base_plus_j_as_libwebrtc_sends_it`, `the_mime_type_match_is_exact`). |

## Not implemented, on purpose

These are outside what the engine claims. None is offered in the default SDP or implied by the
README.

| Area | Not implemented | Why |
|---|---|---|
| Media | Encoding, decoding, capture, playout | The engine is a transport. Statistics members that need them are left out of the report, not reported as 0. |
| DTLS | In the peer connection: DTLS 1.3 session resumption, external PSKs, 0-RTT and post-handshake authentication, and DTLS 1.2 session resumption by session id and RFC 5077 ticket (implemented in `rtc-dtls`, off in the engine) | DTLS 1.3 itself, RSASSA-PSS, the hybrid ML-KEM group, connection ids for both versions and DTLS 1.3 pre-shared keys (tickets, resumption, external PSKs) are implemented (`conformance/w3.md`). WebRTC authenticates each association by the fingerprints of its SDP and makes a new one per session, so the engine issues no ticket, keeps no session cache or store and offers no PSK, session id or ticket (`the_engine_neither_offers_nor_accepts_a_dtls12_resumption`); a configuration with a DTLS 1.2 pre-shared key negotiates DTLS 1.2. 0-RTT, off by default in `rtc-dtls` too, needs the cookie exchange off. |
| DTLS | Renegotiation | RFC 8827 section 6.5 forbids renegotiation in WebRTC and DTLS 1.3 removed it: a request is refused with the no_renegotiation warning (RFC 5746). |
| DTLS in SDP | Listening for a ClientHello before the answer (RFC 8842 5.2); a new 3-tuple for a new association (RFC 8842 5.1, 6); the old association kept while a new one forms (RFC 8842 5.5) | Transports start with the remote description, and the answerer's retransmitted ClientHello is what the offerer takes. The engine has no sockets: the application decides which candidates a new association runs on. |
| STUN | NAT behaviour discovery (RFC 5780): the discovery procedures, CHANGE-REQUEST / RESPONSE-PORT / PADDING as typed attributes; backwards compatibility with RFC 3489 (no magic cookie); resending a request after a 5xx; resolving a server name (SRV, A / AAAA) and (D)TLS to a STUN server | RFC 5780 is experimental and outside the WebRTC specification set; RESPONSE-ORIGIN and OTHER-ADDRESS are encoded and decoded, the rest are code points. RFC 3489 compatibility and the 5xx resend are optional in RFC 8489 (§11, §6.3.4). `rtc-stun` performs no I/O: the application resolves names (`Uri::srv_query_name`, `Uri::port_or_default`) and owns the connection. |
| TURN | A TURN server; relay candidates with transport TCP | Never claimed. The TURN client is implemented, TCP allocations (RFC 6062) included, but ICE gathers no relayed TCP candidate from one. |
| SRTP | AEAD double (RFC 8723), EKT, the SEED and ARIA transforms | Never claimed. |
| SRTP | AES-f8 (RFC 3711 4.1.2) | Optional in RFC 3711 (section 5 makes AES-CM, the NULL cipher and HMAC-SHA1 mandatory), with no DTLS-SRTP code point in the IANA registry. To add it: `k_e`, `k_s`, `k_a` as for AES-CM; `IV' = E(k_e XOR m, IV)` with `m = k_s \|\| 0x555..5`; `S(j) = E(k_e, IV' XOR j XOR S(j-1))`, `S(-1) = 0`; the SRTP IV is `0x00 \|\| M \|\| PT \|\| SEQ \|\| TS \|\| SSRC \|\| ROC` and the SRTCP IV `0..0 \|\| E \|\| SRTCP index \|\| V \|\| P \|\| RC \|\| PT \|\| length \|\| SSRC` (4.1.2.2, 4.1.2.3); at most 2^32 blocks per IV; test vectors in Appendix B.1. It needs only `RTCCrypto::block_encrypt` and a third `Cipher` implementation beside the two in `rtc-srtp/src/cipher/`. |
| SRTP | `<From, To>` master key lifetimes (RFC 3711 8.1.1) | Optional. Re-keying is by MKI (`Context::add_master_key`) or a new DTLS-SRTP handshake. |
| SRTP | Negotiation of an MKI (`use_srtp` `srtp_mki`), of RFC 6904 (`urn:ietf:params:rtp-hdrext:encrypt`), and of the NULL-cipher and RFC 6188 counter-mode profiles by a peer connection | `rtc-srtp` implements all of them ([SRTP claims](conformance/w3.md)); a peer connection negotiates none. The NULL cipher is forbidden in WebRTC (RFC 8827 6.5), the RFC 6188 suites have no DTLS-SRTP code point, and browsers use Cryptex (RFC 9335), not RFC 6904. |
| SFrame | An SFrame RTP payload format (draft-ietf-avtcore-rtp-sframe), its SDP signalling, a transceiver switch | `rtc-sframe` encrypts and decrypts; the application packetizes the ciphertext and signals its use. |
| FEC | For RFC 8627 FlexFEC: answering FlexFEC only when offered with RTX (1.1.7), refusing an offer over its `repair-window` (5.2.1), adapting the amount of FEC to loss (8) | The RFC 8627 coder itself is implemented (opt-in, `video/flexfec`; [conformance/w4.md](conformance/w4.md)). libwebrtc answers both FlexFEC and RTX, and the engine does the same. |
| Identity | `peer_identity`, identity providers, making and verifying assertions | Applications (Deno, for one) implement webrtc-identity above the engine, which carries the `a=identity` attribute for them (`set_identity_assertion`, `remote_identity_assertion`). |
| RTP | H.264 interleaved mode in negotiation (`rtc-rtp` packetizes and depacketizes STAP-B / MTAP / FU-B and de-interleaves; no codec the engine registers offers `packetization-mode=2`); `scalabilityMode` on an encoding | Simulcast is implemented. The SVC modes, their layer structures and their signalling (VP8 / VP9 payload descriptors, AV1 with the Dependency Descriptor) are in `rtc-rtp` for an application to use ([conformance/w4.md](conformance/w4.md)); the encoding parameter, its validation and offering the Dependency Descriptor by default are not. |
| W3C API | `RTCDTMFSender` | Applications implement DTMF above the engine, with `rtc-rtp`'s telephone-event packets and sender state machine (`codec::telephone_event`); the engine sends the packets it is given. |
| TURN | A TURN server; relay candidates with transport TCP | Never claimed. The TURN client is implemented, TCP allocations (RFC 6062) included, but ICE gathers no relayed TCP candidate from one. |
| STUN | NAT behaviour discovery (RFC 5780): the discovery procedures, CHANGE-REQUEST / RESPONSE-PORT / PADDING as typed attributes; backwards compatibility with RFC 3489 (no magic cookie); resending a request after a 5xx; resolving a server name (SRV, A / AAAA) and (D)TLS to a STUN server | RFC 5780 is experimental and outside the WebRTC specification set; RESPONSE-ORIGIN and OTHER-ADDRESS are encoded and decoded, the rest are code points. RFC 3489 compatibility and the 5xx resend are optional in RFC 8489 (§11, §6.3.4). `rtc-stun` performs no I/O: the application resolves names (`Uri::srv_query_name`, `Uri::port_or_default`) and owns the connection. |
| SCTP | Path MTU discovery (the association takes the size of its packets from the selected candidate pair and the DTLS cipher suite, 1200 bytes at the IP layer over IPv4 and 1280 over IPv6, and does not probe for more), RACK-TLP, restarting an association (RFC 9260 5.2.4 action A) | Never claimed; none is needed for a browser data channel. |
| TURN | TCP allocations (RFC 6062), a TURN server | Never claimed. The TURN client is implemented. |
| SRTP | AEAD double (RFC 8723), MKI, EKT | Never claimed. |
| FEC | FlexFEC as RFC 8627 | Only draft-ietf-payload-flexible-fec-scheme-03 is implemented, and the codec name is matched exactly so RFC 8627 `flexfec` is never fed to it. |
| RTP | H.264 STAP-B / MTAP / FU-B (interleaved mode, never offered); SVC layer packetization for VP9 and AV1 | Simulcast is implemented; SVC is not claimed. |
| Identity | `peer_identity`, identity providers | Applications (Deno, for one) implement webrtc-identity above the engine. |
| W3C API | `RTCDTMFSender` | Applications implement DTMF above the engine; the engine sends the telephone-event packets it is given. |
| Test platforms | The real-network environment and browser interop run on Linux only | They need network namespaces. Unit and integration tests run on Linux, macOS and Windows. |
| Web platform tests | WPT | They test a browser API, not this crate; the Deno integration runs them. |

## Specified, not started

Two pieces of the BUNDLE / JSEP model are not implemented. Each is written down here as the
work it is, with the audit rows it would close, so that it can be started without a second
analysis. Until then the rows stay as the audit has them and decision D2 stands: one transport,
one BUNDLE group.

### Several BUNDLE groups (size M)

RFC 9143 section 5 lets a description carry more than one `a=group:BUNDLE` line, each m=
section in at most one of them. Today `bundle_groups` (`src/peer_connection/sdp/mod.rs`) reads
every group line, but the answer (`BundleMode::Answer(Some(group))`) and the transport
attributes (`tagged_section`, `extract_ice_details`) use the first group only: sections of a
second group are treated as outside any group and answered with port zero.

A group is a transport, so the whole of this piece depends on the next one. The part that is
its own:

1. Parsing. `bundle_groups` already returns every group. Refuse a description in which a mid
   is in two BUNDLE groups (`check_remote_description`, `SdpInvalidValue`): RFC9143-5-1.
2. Offers. Keep generating one group: nothing in RFC 9429 has a JSEP endpoint offer several
   (sections 5.2.1 and 5.2.2 speak of "the" BUNDLE group). A subsequent offer after a remote
   offer with several groups repeats the groups of the most recent answer
   (`MediaSection` gains the index of its group; `populate_sdp` writes one `a=group:BUNDLE`
   line per index, the tagged section first): RFC9429-5.2.2-28 for the multi-group case.
3. Answers. `BundleMode::Answer` carries `Vec<Vec<String>>`. Each offered group is answered
   on its own: its first accepted tag is the answerer-tagged section, only that section
   carries the BUNDLE attributes (RFC 9143 section 7.1.3), a section is never moved between
   groups (section 7.3): RFC9143-5-2, RFC9143-7.3-1 (multi-group part), RFC9429-5.3.1-31.
4. Receiving an answer. `check_answer_against_offer` already compares the groups of the two
   descriptions as sets per group; add the rule that the answer's group *i* is a subset of
   the offer's group *i* and not of another: RFC9143-7.4-1, RFC9143-7.3.2-2.
5. Transport selection. Every lookup of "the transport of this m= section" (ICE credentials,
   DTLS fingerprint and role, candidates by `sdpMid`, the SRTP context, the RTP stream
   tables of RFC 9143 section 9.2) goes through the section's group, which is the
   multi-transport piece below.
6. Tests: an offer with two groups is answered with two groups, each with its own
   credentials; a mid in two groups is refused; a subsequent offer keeps the two groups; a
   packet is delivered through the transport of its group and an SSRC is looked up in that
   group's table only.

Rows: RFC9143-5-1, RFC9143-5-2, RFC9143-7.3-1, RFC9143-7.3.2-2, RFC9143-9.2-2 (per group),
RFC9429-5.2.2-28, RFC9429-5.3.1-31.

### Several transports (size L)

A peer connection here has one ICE agent, one DTLS endpoint and association, one SRTP context
pair and one SCTP association (`PipelineContext` in `src/peer_connection/handler/mod.rs`).
RFC 9429 has an m= section that is not bundled into another one own a transport: its own ICE
credentials and candidates, DTLS association and SRTP keys. That is what an initial offer
means for each section that is not bundle-only, what an answerer has to give a section
offered outside a BUNDLE group or moved out of one, and what an offerer falls back to when
the answer has no BUNDLE group.

Done (mt-1): the indirection. The ICE, DTLS and SRTP contexts are a `TransportSet`
(`src/peer_connection/handler/transport_set.rs`) of transport bundles keyed by a transport id,
reached through `default()`, `transport(id)`, `transport_for(mid)` and the data transport the
SCTP association runs over; `handle_read` routes a datagram to a transport before the pipeline
reads it; the sender's, receiver's and SCTP transport's `transport()` name their section's
transport. The set holds one transport, so no row changes with it; the items below fill it.

1. The transport as a value. `Transport { id, ice: IceTransport, dtls: DtlsTransport, srtp
   contexts, selected pair, stats }` replaces the single fields of the handler contexts
   (`IceHandlerContext`, `DtlsHandlerContext`, `SrtpHandlerContext`); `PipelineContext` holds
   `Vec<Transport>` and a map from mid to transport index. SCTP stays one association, on
   the transport of the data section. `RTCDtlsTransport` and `RTCIceTransport` handles become
   per transceiver, as W3C webrtc-pc has them (`sender.transport`, `receiver.transport`,
   `sctp.transport`), and several distinct ones can exist.
2. Demultiplexing. The first stage of the read path (`handler/demuxer.rs`, RFC 7983) is per
   transport; which transport a datagram belongs to is decided before it, by the local
   candidate it arrived on, and for a datagram on a shared socket by the ICE username of its
   STUN binding request (`<remote ufrag>:<local ufrag>`), then by the 5-tuple that request
   validated. `handle_read` takes the datagram's local address, as it does today.
3. Gathering. The application adds local candidates per transport: `add_local_candidate`
   takes the mid (or m= line index) the candidate belongs to, and the candidate events name
   it. With the bundle policy the count of transports to gather for is known before the offer
   (RFC 9429 section 4.1.1): `balanced` one per media type, `max-compat` one per m= section,
   `must-bundle` one. Bundle-only sections get none.
4. Offers. An initial offer writes each transport's own ufrag, pwd, fingerprint, setup and
   candidates in the sections that own one (the BUNDLE attributes of RFC 9143 section 7.1.3,
   "each bundled 'm=' line can contain a different set"), and the default candidate of that
   transport in `m=` / `c=`: RFC9143-7.2-1, RFC9429-5.2.1-13, 5.2.1-14, 5.2.1-40, 5.2.2-7.
5. Answers received. When the answer bundles, the transports of the sections bundled into
   the tagged one are closed (their candidates released, an event per closed transport) and
   their transceivers point at the tagged section's transport. When it does not, or moves a
   section out, each keeps its own: RFC9143-7.4-3, RFC9143-7.3.2-1, RFC9429-5.11 (transport
   steps).
6. Answers generated. A section offered outside any BUNDLE group, or with a transport the
   answerer keeps separate, is answered with its own credentials and candidates instead of
   being rejected by the policy (`populate_sdp`, the `BundleMode::Answer(None)` arm):
   RFC9429-5.3.1-8, 5.3.1-9, 5.3.1-19, RFC9143-7.3.2-1.
7. RTCP without multiplexing stays out: every transport multiplexes (`a=rtcp-mux-only`), so
   the component-2 rows (RFC9429-5.2.2-11, 5.3.2-9, RFC9143-9.3.1.1-3) stay `n/a`.
8. Rollback. A transport created by an offer that is rolled back is closed and its
   candidates released (W3C "set a session description", rollback steps; RFC 9429 section
   5.7): RFC9429-5.7-7. With one transport the only state an abandoned offer leaves today is
   an ICE restart that was not applied.
9. Connection state. `RTCPeerConnectionState` and `RTCIceConnectionState` aggregate over the
   transports as W3C webrtc-pc sections 4.3.2 and 4.3.3 define (any failed: failed; all
   connected or completed: connected). Statistics get one `transport` and its candidate
   pairs per transport.
10. Tests, in the simulated network of the rtc2rtc tests: `max-compat` with audio and video
    to an answerer that does not bundle (two transports, both carry media); the same offer to
    one that bundles (the second transport closes, media moves to the first); a section moved
    out in the answer; an answer without a BUNDLE group; rollback of an offer that added a
    transport; a datagram for transport B arriving on A's candidate is dropped; and against
    the webrtc 0.17 test peer with `balanced`.

Rows: RFC9143-7.2-1, RFC9143-7.3.2-1, RFC9143-7.4-3, RFC9143-9.3.1.2-3 (moved-out part),
RFC9429-5.2.1-13, 5.2.1-14, 5.2.1-40, 5.2.2-7, 5.2.2-10, 5.3.1-8, 5.3.1-9, 5.3.1-19, 5.3.2-5,
5.7-7, RFC9429-4.1.1-3 (the "one transport all the same" note), RFC8839 rows on the default
candidate in `m=` / `c=`, and the W3C webrtc-pc rows on `RTCDtlsTransport` per transceiver.
What it does not close: a separate RTCP component (item 7).

## Known bugs

None open is the bar for calling a release conformant: each bug found is either fixed, with a test
and a row in its area's fragment, or its claim is withdrawn and the feature moves to the table
above. An open bug is listed here, with its spec section and the issue that tracks it, until then.
