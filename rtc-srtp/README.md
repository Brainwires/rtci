# rtc-srtp

SRTP and SRTCP for WebRTC: encryption and authentication of RTP and RTCP with the
protection profiles DTLS-SRTP negotiates, replay protection, rollover counter tracking, key
lifetimes and rekeying, Cryptex and encrypted header extensions.

## Specifications

- RFC 3711, SRTP and SRTCP
- RFC 7714, AES-GCM for SRTP; RFC 6188, AES-192 and AES-256 counter mode
- RFC 5764, keys from DTLS-SRTP
- RFC 9335, completely encrypting RTP header extensions and contributing sources (Cryptex)
- RFC 6904, encryption of header extensions

Clause-by-clause status, with the test that proves each clause: [rfc3711](../docs/conformance/audit/rfc3711.md), [rfc7714](../docs/conformance/audit/rfc7714.md), [rfc6188](../docs/conformance/audit/rfc6188.md), [rfc9335](../docs/conformance/audit/rfc9335.md), [rfc6904](../docs/conformance/audit/rfc6904.md).

## Use

`context::Context` encrypts or decrypts one direction (`encrypt_rtp` / `decrypt_rtp` and
the RTCP equivalents) for a `protection_profile::ProtectionProfile`. The root crate (`rtc`)
creates the contexts from the keys `rtc-dtls` exports.

## Sans-I/O

Packets in, packets out; the crate holds the per-stream replay and rollover state and nothing else. No I/O, no clock. All cryptography goes through `rtc-crypto`'s provider (`crypto-ring` by default, or `crypto-aws-lc-rs`; `openssl` adds an OpenSSL AES-CTR cipher).

## Licence

Licensed under either of the [MIT licence](LICENSE-MIT) or the
[Apache License, Version 2.0](LICENSE-APACHE), at your option.

This crate is part of the [`rtc`](../README.md) workspace, which descends from
[webrtc-rs/rtc](https://github.com/webrtc-rs/rtc) and is developed independently;
[FORK.md](../FORK.md) lists what it carries over upstream. Upstream's licence and copyright
notices are retained.
