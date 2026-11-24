# rtci-stun

STUN messages and attributes, message integrity (HMAC-SHA1 and HMAC-SHA256),
fingerprints, long-term credentials with the password algorithms and USERHASH, a validator
that exposes only the attributes the integrity check covers, and a client transaction layer
with the RFC 8489 retransmission timer.

## Specifications

- RFC 8489, Session Traversal Utilities for NAT (STUN)
- RFC 5780, NAT behaviour discovery attributes
- RFC 8656 and RFC 6062, the attributes TURN adds
- RFC 7983, multiplexing STUN with DTLS, RTP and others

Clause-by-clause status, with the test that proves each clause: [rfc8489](../docs/conformance/audit/rfc8489.md), [rfc5780](../docs/conformance/audit/rfc5780.md), [rfc7983](../docs/conformance/audit/rfc7983.md).

## Use

`message::Message` builds, marshals and parses messages; `validated::Validator` checks
integrity and fingerprint before an attribute is read; `client::Client` runs transactions.
`rtci-ice` and `rtci-turn` are built on it.

## Sans-I/O

The client is a state machine driven by the caller's datagrams and `Instant`s. The crate does no I/O and reads no clock: every call that depends on time takes an `Instant` from the caller. Integrity uses `rtci-crypto`'s provider.

## Licence

Licensed under either of the [MIT licence](LICENSE-MIT) or the
[Apache License, Version 2.0](LICENSE-APACHE), at your option.

This crate is part of the [`rtci`](../README.md) workspace, which descends from
[webrtc-rs/rtc](https://github.com/webrtc-rs/rtc) and is developed independently;
[FORK.md](../FORK.md) lists what it carries over upstream. Upstream's licence and copyright
notices are retained.
