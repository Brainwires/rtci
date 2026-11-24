# rtci-stream-driver

The reference driver for the stream half of the `rtci` engine's sans-I/O interface: it owns
the TCP sockets, on the async runtime it is given, and carries out what the engine asks (listen, connect, close, reset,
resolve a name or SRV / NAPTR records), and reports back what happened. The engine decides
everything else: which ICE-TCP candidates exist (RFC 6544), RFC 4571 framing, TURN over TCP
and TLS, the Happy Eyeballs race (RFC 8305).

It also has what a server decides and the engine does not (`sockets`): port ranges, which
local addresses get candidates, one UDP port and one passive ICE-TCP port shared by many peer
connections; and an opt-in PCP / NAT-PMP client for NAT-assisted candidates (`nat_mapping`,
RFC 6887, RFC 6886).

## Use

```text
while let Some(command) = pc.poll_stream_command() { driver.execute(command) }
while let Some(transmit) = pc.poll_stream_transmit() { driver.write(transmit) }
match driver.next().await {
    DriverInput::Event(event) => pc.handle_stream_event(now, event)?,
    DriverInput::Read { id, data } => pc.handle_stream_read(now, id, &data)?,
    DriverInput::Accepted(accepted) => { /* pc.handle_stream_accepted, then driver.adopt */ }
}
```

The crate documentation has the command table and the complete loop; the root crate's
`stream-driver-loopback` example runs two peer connections over loopback TCP through it.
Feature `dns-records` adds SRV / NAPTR lookups and per-family answers to `TokioRuntime`
through hickory-resolver (0.26.2 or later, which has no open RustSec advisory; the lookups are
those of a stub resolver asking the system's name servers, without DNSSEC validation);
without it, records are answered as none and names through the system resolver.

## A whole peer connection

`peer::PeerDriver` (feature `peer`, on by default, which depends on `rtci`) drives an `rtci`
peer connection over sockets it owns, its UDP host sockets included: it gathers when a
transport begins gathering, and again by itself when the engine says a transport needs new
local candidates (`OnLocalCandidatesNeeded`: a new DTLS association runs on a new 3-tuple,
RFC 8842 section 5.1), binding new ports in its range and closing the previous sockets once a
pair on the new ones is selected. The application only signals.

A connection with mDNS on gets its mDNS carried too: at its first mDNS datagram the driver
binds the host's mDNS sockets (port 5353, the IPv4 and, where available, IPv6 groups), and
every driver of the process sends its mDNS within one message budget
(`peer::process_mdns_rate_limit`), the implementation-wide rate limit of
draft-ietf-mmusic-mdns-ice-candidates section 7.1.

## I/O, and bringing your own runtime

Unlike the other crates of the workspace this one does I/O. The engine itself still never
touches a socket or a clock; the driver does, through the async runtime it is given.

Everything that touches a reactor or a clock goes through one object-safe trait,
`runtime::Runtime`, given to each driver as an `Arc<dyn Runtime>`:

| Injected (`Runtime`) | Not injected |
| --- | --- |
| `spawn` (a `JoinHandle` trait object; dropping it detaches) | channels and wake-ups between the driver's tasks (`async-channel`, executor-agnostic) |
| `now`, `sleep_until`: the clock every time given to the engine comes from | `runtime::sleep`, `timeout`, `timeout_at`, `yield_now`: free functions on top |
| `bind_udp`, `bind_udp_multicast` (`AsyncUdpSocket`: poll form, batched receive, per-datagram traffic class) | |
| `listen_tcp`, `connect_tcp` (`AsyncTcpListener`, `AsyncTcpStream`) | |
| `resolve_host`, and the optional `resolve_family` / `resolve_records` | |
| `block_on` (a future that need not be `Send`) | |

There is no global or default runtime, and none can be set: `StreamDriver::with_runtime` and
`PeerDriver::with_runtime` take one. With the default feature `runtime-tokio`,
`StreamDriver::new`, `StreamDriver::default` and `PeerDriver::new` use `TokioRuntime::new()`
(the tokio runtime of the calling code, as `tokio::spawn` does). The one process-wide state
the crate keeps is the mDNS budget above: the mDNS draft requires an implementation-wide rate
limit, and it is a budget, not a runtime.

| Feature | Gives |
| --- | --- |
| `runtime-tokio` (default) | `TokioRuntime`, and `StreamDriver::new` / `default`, `PeerDriver::new` |
| `runtime-smol` | `SmolRuntime` |
| `runtime-mock` | `MockRuntime`: virtual time and an in-memory network |
| `peer` (default) | `peer::PeerDriver` (depends on `rtci`) |
| `dns-records` | hickory lookups in `TokioRuntime` (turns `runtime-tokio` on) |

Features only decide which runtime types exist; several can be on at once, and with
`default-features = false` and none of them the crate builds without any async runtime in its
dependency tree (CI checks it). Your own runtime implements `Runtime`; the workspace's
`examples/custom-runtime` does it over `async-executor` and `async-io` in about 300 lines, with
the helpers `runtime::{std_udp, std_multicast, std_tcp_listener, std_tcp_connect_start,
TrafficClassMarker, ...}` for runtimes whose sockets are real ones.

`MockRuntime` runs drivers on virtual time: its clock moves when told (`MockClock::advance`)
or, inside `MockRuntime::run`, to the next timer whenever nothing can run; its network
(`MockNet`) carries UDP, multicast and TCP between mock sockets with per-link delay, seeded
loss and blocking, a datagram filter and a log. Two `PeerDriver`s connect on it with no
socket, and a 30-second ICE consent expiry takes no wall time (`tests/virtual_time.rs`).

The design follows the upstream project's "Bring Your Own Async Runtime" (webrtc.rs,
2026-07-30, <https://webrtc.rs/blog/2026/07/30/pluggable-async-runtime.html>); where it
differs (the clock is injected, sockets are bound by address, the socket types are the
crate's own), the crate documentation of `runtime` says why.

## Licence

Licensed under either of the [MIT licence](LICENSE-MIT) or the
[Apache License, Version 2.0](LICENSE-APACHE), at your option.

This crate is part of the [`rtci`](../README.md) workspace, which descends from
[webrtc-rs/rtc](https://github.com/webrtc-rs/rtc) and is developed independently;
[FORK.md](../FORK.md) lists what it carries over upstream. Upstream's licence and copyright
notices are retained.
