# rtci-interceptor

A composable pipeline of RTP / RTCP processors ("interceptors") between the application
and the wire: the RTCP session (sender and receiver reports, SDES, BYE, compound packets and
their timing), NACK generation and retransmission (with RTX), transport-wide congestion
control feedback, bandwidth estimation (GCC), pacing, FEC encoders and decoders, a jitter
buffer, key-frame requests and RTCP extended reports.

## Specifications

- RFC 3550, RTP and its RTCP timing rules; RFC 4585, RTP/AVPF feedback
- RFC 4588, RTP retransmission; RFC 5104, codec control messages
- RFC 8888, RTCP congestion control feedback; draft-holmer-rmcat-transport-wide-cc-extensions
- draft-ietf-rmcat-gcc, Google congestion control
- RFC 8627 and draft-ietf-payload-flexible-fec-scheme-03, FlexFEC; RFC 5109, ULPFEC
- RFC 3611, RTCP extended reports; RFC 6679, ECN for RTP; RFC 8083, circuit breakers
- RFC 5506, reduced-size RTCP; RFC 7022, CNAMEs; RFC 7728, pause and resume; RFC 8108, multiple streams

Clause-by-clause status, with the test that proves each clause: [rfc3550](../docs/conformance/audit/rfc3550.md), [rfc4585](../docs/conformance/audit/rfc4585.md), [rfc4588](../docs/conformance/audit/rfc4588.md), [rfc8888](../docs/conformance/audit/rfc8888.md), [draft-ietf-rmcat-gcc](../docs/conformance/audit/draft-ietf-rmcat-gcc.md), [rfc8627](../docs/conformance/audit/rfc8627.md), [rfc5109](../docs/conformance/audit/rfc5109.md), [rfc3611](../docs/conformance/audit/rfc3611.md).

## Use

`Registry` assembles a chain from builders (`NackGeneratorBuilder`, `TwccSenderBuilder`,
`RtcpSessionBuilder`, ...); the root crate (`rtci`) builds one per peer connection from its
`interceptor_registry` configuration. A new interceptor implements the traits with the
derive macros of `rtci-interceptor-derive`. The crate documentation describes the chain's
direction rules and has a quick-start example.

**The congestion controller's target in a peer connection.** `rtci`'s default interceptors
run the GCC estimator (`Gcc` in a `CongestionControlInterceptor`, one per transport) with the
pacer. Read the target from the handles `rtci`'s
`register_default_interceptors_with_handles` returns (`DefaultInterceptorHandles::
congestion_control`, `CongestionControlHandle::target_bitrate`), or per encoding from
`RTCRtpSender::target_bitrates`. `GccInterceptorBuilder` and its `GccHandle` are for a chain
assembled by hand: `build()` returns a factory closure for `Interceptor::with`
(`PassThroughInterceptor::new().with(builder.build())`), and a `GccInterceptor` put in a
default registry replaces the per-transport controller (see `GccInterceptorBuilder`).

## Sans-I/O

Each interceptor is a `sansio::Protocol`: packets in, packets out, timeouts polled and handled. The crate does no I/O and reads no clock: every call that depends on time takes an `Instant` from the caller.

## Licence

Licensed under either of the [MIT licence](LICENSE-MIT) or the
[Apache License, Version 2.0](LICENSE-APACHE), at your option.

This crate is part of the [`rtci`](../README.md) workspace, which descends from
[webrtc-rs/rtc](https://github.com/webrtc-rs/rtc) and is developed independently;
[FORK.md](../FORK.md) lists what it carries over upstream. Upstream's licence and copyright
notices are retained.
