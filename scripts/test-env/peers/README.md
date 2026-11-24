# Non-browser interop peers

The interop matrix runs examples/interop-peer against three browsers and against the
independent implementations here. Each peer is a small program around one WebRTC stack that
speaks the same WebSocket signalling as the browser page (`interop/peer.js`) and runs one
**plan** per invocation. The cells live in `interop/peers.spec.mjs` (one Playwright project per
peer, so a cell is `<scenario> [<peer>]` in the matrix); the checks are there, in one place, and
a peer only reports what happened.

| Directory | What it holds |
|---|---|
| `<name>/peer.json` | `name`, the pinned `version`, `licence`, `upstream`, and `lacks`: each capability the stack does not have, with the reason and a citation (the cells that need it are `na-peer`) |
| `<name>/build.sh` | `build.sh <out-dir>` builds the peer offline from what the image holds and leaves an executable `<out-dir>/<name>-peer` |

`interop/run.sh` builds every peer, then runs the peer projects in the `open-a` namespace (as the
browsers), with the mDNS cell in `lan-a` against the second interop-peer.

## Invocation

`<name>-peer <plan.json>`. The peer logs to stderr (kept per cell under
`artifacts/peers/<name>/`) and writes JSON lines to stdout:

- `{"event": "impair", "direction": "to-rust" | "to-peer", "rustPort": N}`: asks the runner to put
  this session's packets on that path through netem (5% loss, 20 ms); the runner answers one line
  on stdin (`{"ok": true}`). `{"event": "unimpair"}` ends it (answer `{"ok": true, "dropped": N}`).
- the last line, `{"result": {...}}`.

## Plan

```json
{
  "ws": "ws://203.0.113.51:8080",
  "scenario": { },
  "config": {
    "iceServers": [{"urls": ["turn:203.0.113.10:3478?transport=udp"], "username": "test", "credential": "test"}],
    "iceTransportPolicy": "all",
    "trickle": true,
    "mdns": false,
    "tcp": false,
    "bundlePolicy": "balanced",
    "dtls13": false,
    "caFile": "/run/rtc-env/ca.crt"
  },
  "media": "/run/rtc-env/media",
  "timeout_ms": 60000,
  "steps": [ {"op": "..."} ]
}
```

`scenario` goes to Rust with the first `offer` or `request-offer` message, as the page sends it.
`dtls13: true` sets the stack to prefer DTLS 1.3 (with 1.2 fallback where it can); without
it the stack keeps its default. `trickle: false` waits for gathering to complete and sends no `candidate` message (every
candidate is in the description); `true` sends each candidate as it is gathered, after the
description it belongs to. `mdns: true` hides host candidates behind mDNS names; `tcp: true`
gathers ICE-TCP candidates. `caFile` is the CA the TURN-over-TLS server's certificate is signed
with.

Steps, run in order; a step that fails ends the run with `ok: false` and the step's error:

| Step | Does |
|---|---|
| `{"op":"dc","label":L,"ordered":B,"maxRetransmits":N,"maxPacketLifeTime":MS,"negotiated":ID}` | creates a data channel (the optional members as in RTCDataChannelInit) |
| `{"op":"track","kind":"audio"\|"video","codec":"opus"\|"vp8"\|"vp9"\|"h264","simulcast":[rids]}` | adds a send track and streams it while connected (a fixture from `media`, looped, or the stack's own encoder); before a `request-offer`, the track is attached to the offered section of its kind |
| `{"op":"transceiver","kind":K,"direction":D}` | adds a transceiver without a track |
| `{"op":"remove-track","kind":K}` | stops sending that kind (removeTrack) |
| `{"op":"offer","iceRestart":B,"munge":"strip-bundle"}` | creates and applies an offer, sends it (munged as asked: what Rust receives), waits for the answer to apply |
| `{"op":"request-offer","tracks":[..],"iceRestart":B,"munge":"strip-bundle"}` | asks Rust to offer (`{"type":"request-offer"}`; `tracks` are what Rust adds, `iceRestart` restarts its ICE); waits for that offer, applies it (munged as asked: as from a peer that wrote it so) and answers it; the queued `track`s go on the offered sections of their kind |
| `{"op":"connected","ms":N}` | waits for the connection state `connected` (fails on `failed`) |
| `{"op":"echo","label":L,"count":N,"size":S,"ms":T}` | sends N messages on channel L (text `msg-<i>`, or S bytes: big-endian i at offset 0, then i mod 251) and waits for N echoes |
| `{"op":"await-channel","label":L,"ms":T}` | waits for a channel Rust opened and its first message |
| `{"op":"await-rtp","kind":K,"packets":N,"more":M,"ms":T}` | waits until N packets of that kind arrived from Rust (or M more than when the step began) |
| `{"op":"await-rust-rtp","kind":K,"packets":N,"ms":T}` | asks Rust for reports until it has N packets of that kind from this peer |
| `{"op":"rtcp","types":["pli","fir"]}` | sends those feedback messages for every received video stream |
| `{"op":"impair","direction":D,"ms":T}` | the `impair` event, T ms of streaming, `unimpair` |
| `{"op":"rollback"}` | creates and applies an offer, then rolls it back |
| `{"op":"glare","ms":T}` | applies an offer of its own, sends `request-offer`, then sends its offer; as the impolite peer it ignores Rust's colliding offer, takes the answer, then answers Rust's next offer |
| `{"op":"wait","ms":T}` | keeps streaming for T ms |
| `{"op":"report"}` | asks Rust for a report (the last one is the result's `rust`) |

A step the stack cannot express ends the run with `na: {"reason": ..., "cite": ...}`.

## Result

```json
{
  "ok": true, "error": null, "na": null, "version": "v4.2.28",
  "connectionState": "connected",
  "steps": [{"op": "offer", "ok": true, "ms": 120, "signalingState": "stable"}],
  "datachannels": {"interop": {"got": ["msg-0"], "sizes": [5]}},
  "remoteChannels": {"from-rust": "hello-from-rust"},
  "rtp": {"audio": {"packets": 0, "bytes": 0, "codec": "audio/opus"}},
  "rtpSent": {"video": {"packets": 0, "bytes": 0}},
  "coverage": [{"kind": "video", "ssrc": 1, "span": 0, "missing": 0, "received": 0}],
  "rtcp": {"sr": 0, "rr": 0, "nack": 0, "pli": 0, "fir": 0, "twcc": 0},
  "rtcpSent": {"pli": 0, "fir": 0},
  "selectedPair": {"local": {"candidateType": "host", "protocol": "udp", "relayProtocol": null}, "remote": {}},
  "dtls": {"version": "DTLS 1.2", "cipher": "...", "srtpProfile": "...", "role": "client"},
  "sctp": {"maxMessageSize": 262144},
  "localCandidates": ["candidate:..."],
  "trickled": 0,
  "descriptions": [["sent", "offer", "v=0..."]],
  "remoteOffers": 0, "ignoredOffers": 0,
  "rust": {"type": "report"},
  "rustErrors": []
}
```

Fields a stack cannot fill are `null`. `rtcp` counts what arrived from Rust, by type;
`descriptions` lists every description sent, received, applied or ignored, in order.

## Layers

`layers/` is a crate of its own (`layer-interop`, outside the workspace, `Cargo.lock` tracked)
whose tests pair one engine layer with an independent implementation of it, in memory and in
virtual time: `tests/dimpl_rtc_dtls.rs` (rtci-dtls against dimpl 0.9.0, DTLS 1.2 and 1.3, each
in both roles: handshake, the DTLS-SRTP exporter, data, close_notify, the cookie exchange,
a lost flight, the 1.3-to-1.2 fallback) and `tests/rice_rtc_ice.rs` (rtci-ice against
rice-proto 0.4.3, librice's sans-I/O agent: full ICE in both roles, trickle, rtci-ice lite,
role conflicts). `entry.sh` runs them in the unit stage; `cargo test --manifest-path
scripts/test-env/peers/layers/Cargo.toml` runs them anywhere.
