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
| aiortc (`aiortc`) | Python (asyncio); its own SDP, SCTP and RTP; ICE from aioice; DTLS through pyOpenSSL (OpenSSL); SRTP through pylibsrtp (libsrtp); codecs through PyAV (FFmpeg: VP8, H.264, Opus; no VP9) | aiortc 1.16.0, aioice 0.13.0, pyOpenSSL 26.4.0, cryptography 50.0.2, pylibsrtp 1.0.0, av 19.0.2 (`peers/aiortc/image/requirements.txt`, every wheel by SHA-256), with `sdp.py` from the fork `Brainwires/aiortc` commit 2245f90 and `rtp.py` likewise (the fixes for https://github.com/aiortc/aiortc/issues/1492 and RTCP SDES chunk alignment; to be dropped when upstream releases them) | BSD-3-Clause (PyAV's wheel bundles FFmpeg, LGPL; test image only) | [aiortc/aiortc](https://github.com/aiortc/aiortc) | `peers/aiortc`, a venv in the test image |
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

A known engine gap is an expected failure (`xfail`: Playwright `test.fail` with an `engine-gap: <reason> [<citation>]` annotation), which the gate accepts until the cell starts passing. A scenario a peer's stack cannot express is `na-peer`, with the reason and a citation (the stack's
source or documentation at the pinned version, or what the peer observed at run time), never a
silent skip. A failure is a finding: [Findings](#findings) records which side is off-spec, by the
RFC text.

## Matrix

Train 10 round 5 (PR #47, head 8945a520): Pion 42 pass, 6 n/a, 1 failing; str0m 43 / 6 / 0; aiortc
35 / 13 / 1. The two failing cells have their verdicts in the cells; `conf/peers-6-train-fixes`
6a937864 (round 6) fixes the RTCP cell's count and has the Pion peer write MID / RID, with the
RID-less form kept as an expected failure. A cell named "(peer offers)" has the peer make the offer,
"(Rust offers)" has Rust make it.

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
| audio Opus both ways (Rust offers and streams its fixture) | pass | pass | pass |
| video VP8 both ways (peer offers, Rust reflects) | pass | pass | pass |
| video VP8 both ways (Rust offers and streams its fixture) | pass | pass | pass |
| video VP9 both ways (peer offers, Rust reflects) | pass | pass | n/a: aiortc has no VP9 codec |
| video VP9 both ways (Rust offers and streams its fixture) | pass | pass | n/a: aiortc has no VP9 codec |
| video H264 both ways (peer offers, Rust reflects) | pass | pass | pass |
| video H264 both ways (Rust offers and streams its fixture) | pass | pass | pass |
| RTCP: SR and RR both ways, PLI and FIR from the peer, transport-cc feedback from Rust | pass | pass | FAIL: aiortc counted RR packets only, while Rust (a sender here) reports in its SRs; harness, round 6 counts reception report blocks |
| loss recovery: NACK and RTX repair the peer's video under netem (peer offers) | pass | pass | pass |
| loss recovery: Rust repairs its video to the peer under netem (Rust offers) | pass | pass | pass |
| non-trickle: every candidate in the description (peer offers) | pass | pass | pass |
| non-trickle: every candidate in the description (Rust offers) | pass | pass | pass |
| trickle: candidates sent as they are gathered (peer offers) | pass | pass | na-peer (aiortc gathers every candidate while it applies a local description and emits no icecandidate events: its descriptions carry all its candidates, none i |
| ICE restart by the peer keeps the data channel | pass | pass | n/a: aiortc has no ICE restart |
| ICE restart by Rust keeps the data channel | pass | pass | n/a: aiortc has no ICE restart |
| relay only through coturn over UDP (peer offers) | pass | n/a: str0m has no TURN client: address discovery, STUN and TURN are left to the application | pass |
| relay only through coturn over TCP (peer offers) | pass | n/a: str0m has no TURN client: address discovery, STUN and TURN are left to the application | pass |
| relay only through coturn over TLS (peer offers) | pass | n/a: str0m has no TURN client: address discovery, STUN and TURN are left to the application | pass |
| ICE-TCP: the peer's active candidate reaches Rust's passive one | n/a: Pion's ICE agent gathers TCP candidates only through a TCPMux, as passive ones: it has no active TCP candidate to reach a passive one | pass | n/a: aioice gathers UDP host, server-reflexive and relayed candidates only: TCP is only its way to a TURN server |
| ICE-TCP: built into the engine with UDP blocked, the peer reaches an engine-gathered TCP candidate | pass | pass | n/a: aioice gathers UDP host, server-reflexive and relayed candidates only: TCP is only its way to a TURN server |
| mDNS-hidden peer candidates resolve on the Rust side | pass | n/a: str0m neither registers nor resolves mDNS (.local) candidate names: candidates are addresses the application gives it | n/a: aioice resolves a remote .local candidate but never hides its own host candidates behind an mDNS name |
| DTLS and SRTP: both sides agree on version, cipher suite and SRTP profile (peer offers) | pass | pass | pass |
| DTLS and SRTP: both sides agree on version, cipher suite and SRTP profile (Rust offers) | pass | pass | pass |
| DTLS 1.3: a peer that prefers it negotiates DTLS 1.3 with Rust (peer offers) | n/a: Pion's DTLS (pion/dtls v3) speaks DTLS 1.2 only | pass | n/a: aiortc's DTLS is OpenSSL's DTLS_METHOD, DTLS 1.2 at most |
| DTLS 1.3: a peer that prefers it negotiates DTLS 1.3 with Rust (Rust offers) | n/a: Pion's DTLS (pion/dtls v3) speaks DTLS 1.2 only | pass | n/a: aiortc's DTLS is OpenSSL's DTLS_METHOD, DTLS 1.2 at most |
| renegotiation: the peer adds a video track, then removes it, audio keeps flowing | pass | pass | pass |
| rollback: an abandoned local offer leaves the session usable | n/a: Pion does not take a rollback description | pass | n/a: aiortc cannot roll back a description |
| glare: Rust rolls its offer back, answers, and offers again | pass | pass | pass |
| simulcast: three RIDs from the peer reach Rust | FAIL: Pion's layers carry no MID / RID header extension though Rust's answer negotiates both; peer-side, round 6 has the Pion peer write them | pass | n/a: aiortc sends one encoding per sender: no simulcast |
| balanced: Rust's offer with a transport per media type, the peer bundles it | pass | pass | pass |
| balanced, answered without BUNDLE: a transport per media type | na-peer (Pion runs one ICE and one DTLS transport per PeerConnection: in an answer it rejects (port 0) every section outside the offer's BUNDLE group, and with | n/a: str0m runs one ICE transport per session: every m-line must be bundled | na-peer (aiortc answers an offer without a BUNDLE group with one (a=group:BUNDLE 0 1), then still runs an ICE connection per section; the offerer bundles by tha |
| unbundled: the peer offers a transport per section, without a BUNDLE group | na-peer (Pion runs one ICE and one DTLS transport per PeerConnection: in an answer it rejects (port 0) every section outside the offer's BUNDLE group, and with | n/a: str0m runs one ICE transport per session: every m-line must be bundled | pass |

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
| `* (Rust offers)` with media, `balanced: *` [aiortc] `ValueError` | peer off-spec, fixed in a fork | aiortc 1.16.0's SDP parser reads an `a=extmap` value as exactly two fields (`sdp.py`: `ext_id, ext_uri = value.split()`, the direction then split off the id), so a line with extension attributes (RFC 8285 section 5), as the engine's default RFC 6904 section 4 encrypted audio levels are (`a=extmap:6 urn:ietf:params:rtp-hdrext:encrypt urn:ietf:params:rtp-hdrext:ssrc-audio-level`), makes it refuse the whole description. Reported upstream: https://github.com/aiortc/aiortc/issues/1492. The test image runs the fork's parser (`Brainwires/aiortc` branch `fix/extmap-extension-attributes-1.16.0`, commit 2245f90: 1.16.0 plus `value.split()[:2]` and the SDES fix below; branch `fix/extmap-extension-attributes` has the same fix on upstream `main`), overlaid on the 1.16.0 wheel by SHA-256, to be dropped when upstream releases the fix. The engine keeps offering the RFC form; an application that must talk to an unpatched aiortc offers the audio levels in the clear with `MediaEngine::set_header_extension_encryption(uri, RTCRtpHeaderExtensionEncryption::Clear)` for `ssrc-audio-level` and `csrc-audio-level`. |
| `RTCP: *`, `loss recovery: NACK and RTX repair the peer's video` [aiortc] (round 3) | peer off-spec, fixed in the fork | aiortc 1.16.0's `RtcpSdesPacket.parse` reads a length octet after the END item and does not skip to the 32-bit boundary (`while pos < len(data) - 1: d_type, d_length = unpack_from("!BB", data, pos) ... if d_type == 0: break`), so an SDES with several chunks fails ("RTCP SDES item is truncated", 38 and 58 times in those cells' logs) and the whole compound is dropped: its RR, and the NACKs (aiortc handled 6 of the engine's 14). RFC 3550 6.5: "No length octet follows the null item type octet, but additional null octets MUST be included if needed to pad until the next 32-bit boundary". The engine writes that form (`SourceDescriptionChunk::marshal_to`); Pion and str0m read it. aiortc's writer had the matching fault (two nulls per chunk, padding only at the packet's end). Fixed in the fork: branch `fix/rtcp-sdes-chunk-alignment` on upstream main, and in the 1.16.0 branch the image overlays (`rtp.py`, commit 2245f90). |
| `balanced, answered without BUNDLE` [aiortc] (round 3) | peer off-spec (n/a) | Rust's offer reached aiortc without a group; aiortc answered `a=group:BUNDLE 0 1` and still ran an ICE connection per section (aioice `Connection(1)` never completed). RFC 9143 7.3: "The answerer is only allowed to include a BUNDLE group in an initial BUNDLE answer if the offerer requested the BUNDLE group to be created in the corresponding initial BUNDLE offer". Whether the engine, as offerer, should refuse such an answer is for after the release (RFC 9429 5.10 / 5.11, RFC 9143 7.3.x / 7.5); today it bundles by it. |
| `RTCP: *` [aiortc] (round 4) "the peer received no RR from Rust" | harness | Rust sends media in this cell, so its reception reports ride as blocks in its SRs (RFC 3550 6.4: an RR is for a participant that has not sent), and aiortc's counter sat after aiortc's router, which hands an RR only to the senders its blocks name and an SR to several recipients. The peers now count every RTCP packet once on arrival and the report blocks in SRs and RRs; the cell requires report blocks about the peer's streams. |
| `rollback: *` [pion] | peer limitation (n/a) | Pion's SetLocalDescription refuses a rollback description. |
| `renegotiation: ... removes it` [aiortc] | harness | `RTCRtpSender.replaceTrack` is a plain method in aiortc 1.16.0; the peer awaited it. |
| `ICE-TCP: *` [str0m] | harness | Both echoes passed; the session ended before str0m's first stats event, so no selected pair was reported. The peer now reports the path its last datagrams came over. |
| ICE-TCP pairing [str0m], observed in the container | peer off-spec (no cell fails) | str0m's ICE agent (is 0.12.1) forms TCP pairs without looking at tcptype: it paired its active candidate with Rust's active one and connected to port 9 (RFC 6544 6.2: active pairs only with passive). The working pair still formed. |
| `simulcast: three RIDs from the peer reach Rust` [pion] | harness, then a known engine gap | Round 4: the first header of each Pion layer carried only extension id 4, which Pion's offer maps to transport-wide-cc (`a=extmap:4 http://www.ietf.org/id/draft-holmer-rmcat-transport-wide-cc-extensions-01`), no MID (id 1) or RID (id 2); the engine discarded the three SSRCs as unassociated (`discardedSsrcs: [2103457592, 1113759899, 1994375962]`). Pion v4.2.29 never writes MID or RID: `TrackLocalStaticRTP.writeRTP` sets only SSRC and payload type, and nothing in pion/webrtc outside tests calls `SetExtension`. The Pion peer now writes MID and RID itself, as a Pion application sending simulcast does (an interceptor setting the negotiated sdes:mid / sdes:rtp-stream-id ids on every layer packet), so `simulcast: three RIDs from the peer reach Rust` tests three RID-identified layers from an independent stack. The RID-less form is its own cell, `simulcast without MID or RID on the wire: *`, an expected failure (`xfail`, gate.mjs) with this verdict. Engine gap, scheduled after the release on `conf/demux-1-declared-ssrc-in-rid-section`: those SSRCs were declared by `a=ssrc` / `a=ssrc-group:FID` lines in the section, and RFC 9143 9.2 associates a declared SSRC (and a payload type unique in the BUNDLE group) with its m= section; the engine drops the declared SSRCs of a section that has `a=rid` (`track_details_from_sdp`: "we will need to override tracks, and remove ssrcs") and leaves a RID-less packet of a simulcast receiver to the rid path (`bind_undeclared_ssrc`: "it is rid-based ... use the rid path"), which discards it. |
| `loss recovery: NACK and RTX repair the peer's video` [aiortc] | open | 9 of 373 still missing: Rust sent 14 NACKs (nackCount), aiortc's sender handled 7 and retransmitted 8 packets. Round 2 logs aiortc's RTCP and SRTP failures. |
