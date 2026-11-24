# rtci-shared

What every crate of the workspace shares: the `Marshal` / `Unmarshal` / `MarshalSize`
traits, the common error type, `TransportContext` and the tagged message types that carry a
datagram with its addresses, replay detection, network interface listing, and the stream
transport interface (`stream`): connection ids, the commands a driver carries out, RFC 4571
and TURN framing of arbitrarily segmented reads, an optional TLS layer and back-pressure.

## Specifications

- RFC 4571, framing RTP and RTCP over connection-oriented transport
- RFC 8656 section 11.5, ChannelData framing over TCP
- RFC 8305, Happy Eyeballs, as the stream interface's connection race uses it

Clause-by-clause status, with the test that proves each clause: [rfc4571](../docs/conformance/audit/rfc4571.md), [rfc8305](../docs/conformance/audit/rfc8305.md).

## Use

Other crates use it directly; an application meets it as `rtci::shared` (the root crate
re-exports it): `TaggedBytesMut` and `TransportContext` in its event loop, and
`stream::{StreamCommand, StreamEvent}` when it drives the engine's TCP. Features: `marshal`,
`replay`, `ifaces` (all default).

## Sans-I/O

Types and codecs only. `ifaces` lists the host's interfaces when asked; nothing else touches the operating system or reads a clock.

## Licence

Licensed under either of the [MIT licence](LICENSE-MIT) or the
[Apache License, Version 2.0](LICENSE-APACHE), at your option.

This crate is part of the [`rtci`](../README.md) workspace, which descends from
[webrtc-rs/rtc](https://github.com/webrtc-rs/rtc) and is developed independently;
[FORK.md](../FORK.md) lists what it carries over upstream. Upstream's licence and copyright
notices are retained.
