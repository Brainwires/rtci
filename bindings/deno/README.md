# Deno binding (reference example)

`mod.ts` maps rtc-ffi's driven layer (`rtc_driven_*`, `rtc_mux_*`; see
[docs/packaging.md](../../docs/packaging.md)) onto the browser's WebRTC classes with
`Deno.dlopen`: `RTCPeerConnection`, `RTCDataChannel`, `RTCRtpTransceiver`, `RTCRtpSender`,
`RTCRtpReceiver`, `RTCSessionDescription`, `RTCIceCandidate`, their events and `getStats`.

**This is a reference, not a package.** The Denext project maintains its own binding of this
engine; this one shows how the C interface maps onto the browser API and is not published
anywhere (no JSR, no npm, no deno.land/x).

## What differs from a browser

- **A second constructor argument** carries the server options of the reference driver:
  `bindAddresses`, `includeLoopback`, `includeLinkLocal`, `portRange` (`{min, max}`), `tcp`
  (the engine's ICE-TCP and TURN over TCP / TLS, on by default), `natIps` and
  `natCandidateType` (1:1 NAT), `iceLite`, `sharedPort` (an `RTCSharedPort`: one UDP port, and
  optionally one ICE-TCP port, shared by many peer connections, routed by ICE ufrag), and
  `settings` (rtc-ffi's engine settings JSON).
- **No capture, no codecs run here.** A local track is `{kind, id, label, ssrc, codec}`; the
  application sends encoded media with `RTCRtpSender.writeFrame(frame, samples)` (the engine
  packetizes with the negotiated codec) or `writeRtp(packet)`, and receives RTP packets with
  the receiver's `rtp` event (`RTCRtpPacketEvent.data`, the decrypted wire form).
- `close()` returns a promise (the driver's thread is joined).

## Loading the library

`RTC_FFI_LIB` names the library file when set; otherwise `librtc_ffi.so` (Linux),
`librtc_ffi.dylib` (macOS) or `rtc_ffi.dll` (Windows) beside `mod.ts`. There is no download
logic: build the library (`cargo build -p rtc-ffi --release`, it lands in `target/release/`)
or take it from a release's artefacts (`docs/packaging.md`). The binding checks
`rtc_abi_version()` at load.

```sh
cargo build -p rtc-ffi --release
RTC_FFI_LIB=target/release/librtc_ffi.so deno run --allow-ffi --allow-env bindings/deno/example.ts
```

## Status

`deno check bindings/deno/mod.ts bindings/deno/example.ts` passes with Deno 2.5.6, and
`example.ts` runs to the end (data channel echo, an RTP packet received, `getStats`, both
closed) against the debug library in the repository's Linux test container. Not run on macOS
or Windows; not covered by CI.
