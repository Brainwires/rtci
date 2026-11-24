# rtci-turn

A TURN client: allocations for UDP relayed addresses of either family or both,
permissions, channels, refreshes, the long-term credential mechanism, and TCP allocations
(`Connect`, `ConnectionAttempt`, a data connection per peer). There is no TURN server.

## Specifications

- RFC 8656, Traversal Using Relays around NAT (TURN)
- RFC 6062, TURN extensions for TCP allocations
- RFC 8489, STUN, as TURN uses it

Clause-by-clause status, with the test that proves each clause: [rfc8656](../docs/conformance/audit/rfc8656.md), [rfc6062](../docs/conformance/audit/rfc6062.md).

## Use

`client::Client` runs allocations against a server; the root crate (`rtci`) uses it to
gather relayed candidates over UDP, TCP, TLS and DTLS, so most applications only configure a
`turn:` / `turns:` URL on the peer connection.

## Sans-I/O

Datagrams in, datagrams out, deadlines polled: the transport to the server (UDP socket, TCP or TLS connection) belongs to the caller. The crate does no I/O and reads no clock: every call that depends on time takes an `Instant` from the caller.

## Licence

Licensed under either of the [MIT licence](LICENSE-MIT) or the
[Apache License, Version 2.0](LICENSE-APACHE), at your option.

This crate is part of the [`rtci`](../README.md) workspace, which descends from
[webrtc-rs/rtc](https://github.com/webrtc-rs/rtc) and is developed independently;
[FORK.md](../FORK.md) lists what it carries over upstream. Upstream's licence and copyright
notices are retained.
