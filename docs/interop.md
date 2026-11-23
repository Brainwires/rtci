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

Filled from the train's `test-env` run; rows are the cells of `interop/peers.spec.mjs`.

## What each peer negotiates

## Findings
