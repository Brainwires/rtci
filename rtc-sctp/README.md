# rtc-sctp

SCTP as WebRTC data channels use it: associations over DTLS, ordered and unordered
streams, partial reliability, stream reconfiguration, stream schedulers, congestion and flow
control, path MTU handling and the association lifecycle.

## Specifications

- RFC 9260, Stream Control Transmission Protocol
- RFC 3758 and RFC 7496, partial reliability and its policies
- RFC 6525, stream reconfiguration
- RFC 8260, stream schedulers (user message interleaving, I-DATA, is not implemented)
- RFC 8261, SCTP over DTLS

Clause-by-clause status, with the test that proves each clause: [rfc9260](../docs/conformance/audit/rfc9260.md), [rfc3758](../docs/conformance/audit/rfc3758.md), [rfc7496](../docs/conformance/audit/rfc7496.md), [rfc6525](../docs/conformance/audit/rfc6525.md), [rfc8260](../docs/conformance/audit/rfc8260.md), [rfc8261](../docs/conformance/audit/rfc8261.md).

## Use

`Endpoint` accepts and opens associations; an `Association` carries the streams. The
root crate (`rtc`) runs one association per peer connection under its data channels
(`rtc-datachannel`).

## Sans-I/O

A deterministic state machine: feed it datagrams and time, poll it for datagrams, timeouts and events. The crate does no I/O and reads no clock: every call that depends on time takes an `Instant` from the caller.

## Licence

Licensed under either of the [MIT licence](LICENSE-MIT) or the
[Apache License, Version 2.0](LICENSE-APACHE), at your option.

This crate is part of the [`rtc`](../README.md) workspace, which descends from
[webrtc-rs/rtc](https://github.com/webrtc-rs/rtc) and is developed independently;
[FORK.md](../FORK.md) lists what it carries over upstream. Upstream's licence and copyright
notices are retained.
