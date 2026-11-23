# Interoperability

What the engine has been run against, how, and what each peer negotiated. The browser cells and
the non-browser peer cells run in the test environment (`scripts/test-env/run.sh interop`, the
`test-env` workflow); `interop/gate.mjs` fails the run unless every cell is a pass or a cited
n/a. The claims these cells prove are rows of [conformance/w6.md](conformance/w6.md).

## The peers

| Peer | Kind | Version | Licence | Upstream | Where it runs |
|---|---|---|---|---|---|
| Chromium, Firefox, WebKit | browsers | the Playwright 1.64.1 image's builds | - | [playwright](https://github.com/microsoft/playwright) | `interop/*.spec.mjs`, headless |
| webrtc-rs `webrtc` | Rust, the pre-sans-I/O line (its own DTLS, SCTP, ICE) | 0.17.3 | MIT OR Apache-2.0 | [webrtc-rs/webrtc](https://github.com/webrtc-rs/webrtc) | `tests/*_interop.rs`, in-process, every platform CI tests |
| Pion (`pion`) | Go; its own ICE, DTLS, SCTP, SRTP, RTP and interceptors | `github.com/pion/webrtc/v4` v4.2.29 (pion/ice v4.4.9, pion/dtls v3.1.16, pion/sctp v1.12.1, pion/srtp v3.1.3, pion/interceptor v0.1.51; `peers/pion/image/go.sum`), Go 1.27.4 | MIT | [pion/webrtc](https://github.com/pion/webrtc) | `peers/pion`, in the test image, built offline from the image's module cache |
| str0m (`str0m`) | Rust, sans-I/O; its own ICE agent (`is`), DTLS (`dimpl`, 1.2 and 1.3), SCTP (`sctp-proto`), SRTP | str0m 0.26.0, `rust-crypto` backend (dimpl 0.9.0, str0m-rust-crypto 0.7.0, is 0.12.1, sctp-proto 0.10.9; `peers/str0m/Cargo.lock`) | MIT OR Apache-2.0 | [algesten/str0m](https://github.com/algesten/str0m) | `peers/str0m`, a crate outside the workspace, built `--locked` in the test image |
| aiortc (`aiortc`) | Python (asyncio); its own SDP, SCTP and RTP; ICE from aioice; DTLS through pyOpenSSL (OpenSSL); SRTP through pylibsrtp (libsrtp); codecs through PyAV (FFmpeg: VP8, H.264, Opus; no VP9) | aiortc 1.16.0, aioice 0.13.0, pyOpenSSL 26.4.0, cryptography 50.0.2, pylibsrtp 1.0.0, av 19.0.2 (`peers/aiortc/image/requirements.txt`, every wheel by SHA-256) | BSD-3-Clause (PyAV's wheel bundles FFmpeg, LGPL; test image only) | [aiortc/aiortc](https://github.com/aiortc/aiortc) | `peers/aiortc`, a venv in the test image |
| dimpl (layer) | Rust, sans-I/O DTLS 1.2 / 1.3 (str0m's) | 0.9.0, `rust-crypto` | MIT OR Apache-2.0 | [algesten/dimpl](https://github.com/algesten/dimpl) | `peers/layers/tests/dimpl_rtc_dtls.rs`, against rtc-dtls |
| librice (layer) | Rust, sans-I/O ICE agent `rice-proto` | 0.4.3, `std` only | MIT OR Apache-2.0 | [ystreet/librice](https://github.com/ystreet/librice) | `peers/layers/tests/rice_rtc_ice.rs`, against rtc-ice |

The browsers' media stacks largely descend from libwebrtc. The peers below are independent
implementations, each pinned to an exact release, run by the same signalling as the browser page.

## How a peer cell runs

A peer is a small program around its stack (`scripts/test-env/peers/<name>/`, contract in
[its README](../scripts/test-env/peers/README.md)). It connects to `examples/interop-peer` over
the WebSocket signalling the browser page speaks (offer, answer, candidates, the scenario,
`request-offer`, `report`), runs one plan (a list of steps: create a channel, add a track, offer,
ask Rust to offer, echo, wait for RTP, restart ICE, roll back, collide, impair the path with
netem) and reports what happened: the connection state, the data-channel messages echoed, the
RTP packets and bytes received per kind, the RTCP received by type, the selected candidate pair,
the DTLS version, cipher suite and SRTP profile, the SCTP limits, and every description sent and
received. `interop/peers.spec.mjs` holds the scenarios and the checks, the same for every peer;
each peer is a Playwright project, so a cell is `<scenario> [<peer>]`. Most scenarios run in both
directions, "(peer offers)" and "(Rust offers)". The Rust side reports its own view of the same
session (its RTP and RTCP counts, sequence coverage per stream, W3C stats with the transport's
`tlsVersion`, `dtlsCipher`, `srtpCipher` and selected pair, SCTP limits), so a cell checks both.

A scenario a peer's stack cannot express is `na-peer`, with the reason and a citation (the stack's
source or documentation at the pinned version, or what the peer observed at run time), never a
silent skip. A failure is a finding: [Findings](#findings) records which side is off-spec, by the
RFC text.

## Matrix

Train 10 round 1 (PR #47, head f5d9abb2): Pion 41 pass, 3 n/a, 5 failing; str0m 40 / 6 / 3;
aiortc 26 / 12 / 11. Every failing cell has a verdict below; the round-1 "fail" cells marked
harness or n/a are fixed or reclassified on `conf/peers-6-train-fixes`, and the next round's
results replace this table. A cell named "(peer offers)" has the peer make the offer, "(Rust
offers)" has Rust make it.

| Cell | Pion | str0m | aiortc |
|---|---|---|---|
| data channel ordered (peer offers) | pass | pass | pass |
| data channel ordered (Rust offers) | pass | pass | pass |
| data channel unordered (peer offers) | pass | pass | pass |
| data channel unordered (Rust offers) | pass | pass | pass |
| data channel unreliable (maxRetransmits 0) (peer offers) | pass | pass | pass |
| data channel unreliable (maxRetransmits 0) (Rust offers) | pass | pass | pass |
| data channel partial reliability (maxPacketLifeTime 3000 ms) (peer offers) | pass | pass | pass |
| data channel partial reliability (maxPacketLifeTime 3000 ms) (Rust offers) | pass | pass | pass |
| data channel 64 KiB binary messages (peer offers) | pass | pass | pass |
| data channel 64 KiB binary messages (Rust offers) | pass | pass | pass |
| data channel 256 KiB message (peer offers) | pass | pass | pass |
| data channel 256 KiB message (Rust offers) | pass | pass | pass |
| data channel negotiated (id 5) (peer offers) | pass | pass | pass |
| data channel negotiated (id 5) (Rust offers) | pass | pass | pass |
| renegotiation: the peer adds a channel | pass | pass | pass |
| renegotiation: Rust offers a new channel | pass | pass | pass |
| audio Opus both ways (peer offers, Rust reflects) | pass | pass | pass |
| audio Opus both ways (Rust offers and streams its fixture) | pass | pass | fail (aiortc off-spec: extmap attributes; na-peer from round 2) |
| video VP8 both ways (peer offers, Rust reflects) | pass | pass | fail (harness: aiortc getStats) |
| video VP8 both ways (Rust offers and streams its fixture) | pass | pass | pass |
| video VP9 both ways (peer offers, Rust reflects) | pass | pass | n/a: aiortc has no VP9 codec |
| video VP9 both ways (Rust offers and streams its fixture) | pass | pass | n/a: aiortc has no VP9 codec |
| video H264 both ways (peer offers, Rust reflects) | pass | pass | fail (harness: aiortc getStats) |
| video H264 both ways (Rust offers and streams its fixture) | pass | pass | fail (harness: aiortc getStats) |
| RTCP: SR and RR both ways, PLI and FIR from the peer, transport-cc feedback from Rust | fail (harness: SR/RR are the engine's own; round 2 reads the report stats) | fail (harness, as Pion) | fail (harness: aiortc getStats; round 2 counts RTP itself) |
| loss recovery: NACK and RTX repair the peer's video under netem (peer offers) | pass | pass | FAIL: 9 of 373 still missing; open |
| loss recovery: Rust repairs its video to the peer under netem (Rust offers) | pass | pass | pass |
| non-trickle: every candidate in the description (peer offers) | pass | pass | pass |
| non-trickle: every candidate in the description (Rust offers) | pass | pass | pass |
| trickle: candidates sent as they are gathered (peer offers) | pass | pass | n/a: aiortc gathers every candidate while it applies a local description and emits no icecandid |
| ICE restart by the peer keeps the data channel | pass | pass | n/a: aiortc has no ICE restart |
| ICE restart by Rust keeps the data channel | pass | pass | n/a: aiortc has no ICE restart |
| relay only through coturn over UDP (peer offers) | pass | n/a: str0m has no TURN client | pass |
| relay only through coturn over TCP (peer offers) | pass | n/a: str0m has no TURN client | pass |
| relay only through coturn over TLS (peer offers) | pass | n/a: str0m has no TURN client | pass |
| ICE-TCP: the peer's active candidate reaches Rust's passive one | n/a: Pion's ICE agent gathers TCP candidates only through a TCPMux, as passive ones | fail (harness: no selected pair before str0m's first stats event) | n/a: aioice gathers UDP host, server-reflexive and relayed candidates only |
| ICE-TCP: built into the engine with UDP blocked, the peer reaches an engine-gathered TCP candidate | pass | fail (harness: no selected pair before str0m's first stats event) | n/a: aioice gathers UDP host, server-reflexive and relayed candidates only |
| mDNS-hidden peer candidates resolve on the Rust side | pass | n/a: str0m neither registers nor resolves mDNS (.local) candidate names | n/a: aioice resolves a remote .local candidate but never hides its own host candidates behind a |
| DTLS and SRTP: both sides agree on version, cipher suite and SRTP profile (peer offers) | pass | pass | pass |
| DTLS and SRTP: both sides agree on version, cipher suite and SRTP profile (Rust offers) | pass | pass | fail (aiortc off-spec: extmap attributes; na-peer from round 2) |
| DTLS 1.3: a peer that prefers it negotiates DTLS 1.3 with Rust (peer offers) | n/a: Pion's DTLS (pion/dtls v3) speaks DTLS 1.2 only | pass | n/a: aiortc's DTLS is OpenSSL's DTLS_METHOD, DTLS 1.2 at most |
| DTLS 1.3: a peer that prefers it negotiates DTLS 1.3 with Rust (Rust offers) | n/a: Pion's DTLS (pion/dtls v3) speaks DTLS 1.2 only | pass | n/a: aiortc's DTLS is OpenSSL's DTLS_METHOD, DTLS 1.2 at most |
| renegotiation: the peer adds a video track, then removes it, audio keeps flowing | pass | pass | fail (harness: replaceTrack is not awaitable) |
| rollback: an abandoned local offer leaves the session usable | fail (Pion has no local rollback; na-peer from round 2) | pass | n/a: aiortc cannot roll back a description |
| glare: Rust rolls its offer back, answers, and offers again | pass | pass | pass |
| simulcast: three RIDs from the peer reach Rust | FAIL: Rust bound no stream; open | pass | n/a: aiortc sends one encoding per sender |
| balanced: Rust's offer with a transport per media type, the peer bundles it | pass | pass | fail (aiortc off-spec: extmap attributes; na-peer from round 2) |
| balanced, answered without BUNDLE: a transport per media type | fail (Pion limitation: rejects ungrouped sections; na-peer from round 2) | n/a: str0m runs one ICE transport per session | fail (aiortc off-spec: extmap attributes; na-peer from round 2) |
| unbundled: the peer offers a transport per section, without a BUNDLE group | fail (Pion limitation: one transport; na-peer from round 2) | n/a: str0m runs one ICE transport per session | fail (harness: aiortc getStats) |


## What each peer negotiates

From the round's `DTLS and SRTP: *`, `DTLS 1.3: *` and `RTCP: *` cells (both sides' views).

| | Pion | str0m | aiortc |
|---|---|---|---|
| DTLS version | 1.2 (`FEFD`); its DTLS has no 1.3 | 1.2 by default; 1.3 (`FEFC`) when set to prefer it, either role | 1.2 (OpenSSL `DTLS_METHOD`) |
| DTLS suite | TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 | TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 (1.2), TLS_AES_128_GCM_SHA256 (1.3) | TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 |
| SRTP profile | SRTP_AEAD_AES_256_GCM | SRTP_AEAD_AES_256_GCM | SRTP_AEAD_AES_256_GCM |
| SCTP max-message-size | 1073741823 stated, 256 KiB messages both ways | 256 KiB | 256 KiB |
| Congestion feedback | transport-cc both ways (Pion adds transport-wide sequence numbers when configured) | transport-cc | REMB (no transport-cc) |
| RTCP Rust receives | SR, RR, SDES, transport-cc, PLI, FIR | SR, RR, SDES, transport-cc, XR, FIR (its PLI and FIR coalesced) | SR, REMB, NACK, PLI |
| ICE | full; trickle; restart; TURN over UDP, TCP, TLS; passive ICE-TCP only; mDNS | full; trickle; restart; active ICE-TCP (application-driven); no TURN, no mDNS | full (aioice); no trickle, no restart; TURN over UDP, TCP, TLS (TLS 1.2: the environment's coturn); no ICE-TCP |
| Transports | one per PeerConnection (bundles everything) | one per session (bundles everything) | a transport per section with max-compat |

## Findings

Each failing cell of round 1, which side is off and why (the RFC text decides).

| Cell(s) | Verdict | Detail |
|---|---|---|
| `RTCP: *` [pion, str0m] "Rust received no SR" | harness | The engine's RTCP session takes SR and RR in itself; they never reach `poll_read` (`tests/idle_endpoints.rs`), so interop-peer's application-level count could not see them. The cell now reads the remote-outbound-rtp (`reportsSent`) and remote-inbound-rtp stats the reports make (W3C webrtc-stats 7.5, 7.6). |
| `video * both ways`, `RTCP: *`, `unbundled: *` [aiortc] "44 of N video packets" | harness (aiortc's stats) | aiortc's `RTCRtpReceiver.getStats` files every SSRC of a receiver under one id (`"inbound-rtp_" + id(self)`), so its report shows the last stream added: the RTX stream, carrying the engine's 44 bandwidth-probe packets. The peer now counts media packets in the receiver's RTP handler. |
| `balanced, answered without BUNDLE` [pion], `unbundled: *` [pion] | peer limitation (n/a) | Pion answers port 0 (a rejection, RFC 3264 6) for every section outside the offer's BUNDLE group (pion/webrtc v4.2.29 `sdp.go` `populateSDP`) and runs one ICE and DTLS transport per PeerConnection, also under max-compat. The engine's default of one set of ICE credentials across its transports is what lets Pion bundle Rust's balanced offer (`balanced: Rust's offer with a transport per media type, the peer bundles it` passes). |
| `* (Rust offers)` with media, `balanced: *` [aiortc] `ValueError` | peer off-spec (n/a) | aiortc's SDP parser takes `a=extmap:<id> <uri>` only (`sdp.py`: `ext_id, ext_uri = value.split()`). RFC 8285 section 5 allows a direction after the id and extension attributes after the URI, and RFC 6904 section 4 encrypted extensions are written with them (`a=extmap:6 urn:ietf:params:rtp-hdrext:encrypt urn:...`), so aiortc refuses Rust's whole offer. The engine keeps the RFC form; aiortc is not a stack whose deployment would make the owner rule apply without the owner's decision. |
| `rollback: *` [pion] | peer limitation (n/a) | Pion's SetLocalDescription refuses a rollback description. |
| `renegotiation: ... removes it` [aiortc] | harness | `RTCRtpSender.replaceTrack` is a plain method in aiortc 1.16.0; the peer awaited it. |
| `ICE-TCP: *` [str0m] | harness | Both echoes passed; the session ended before str0m's first stats event, so no selected pair was reported. The peer now reports the path its last datagrams came over. |
| ICE-TCP pairing [str0m], observed in the container | peer off-spec (no cell fails) | str0m's ICE agent (is 0.12.1) forms TCP pairs without looking at tcptype: it paired its active candidate with Rust's active one and connected to port 9 (RFC 6544 6.2: active pairs only with passive). The working pair still formed. |
| `simulcast: three RIDs from the peer reach Rust` [pion] | open | Rust bound no stream at all; Pion's offer declares `a=ssrc` / `a=ssrc-group:FID` lines beside `a=rid` / `a=simulcast`. Round 2 reports Pion's outbound-rtp stats and Rust's transport counters to tell whether Pion sent. |
| `loss recovery: NACK and RTX repair the peer's video` [aiortc] | open | 9 of 373 still missing: Rust sent 14 NACKs (nackCount), aiortc's sender handled 7 and retransmitted 8 packets. Round 2 logs aiortc's RTCP and SRTP failures. |
