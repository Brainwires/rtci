# rtci-stream-driver

The reference driver for the stream half of the `rtci` engine's sans-I/O interface: it owns
the TCP sockets on tokio and carries out what the engine asks (listen, connect, close, reset,
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
Feature `dns-records` adds SRV / NAPTR lookups and per-family answers through
hickory-resolver (0.26.2 or later, which has no open RustSec advisory; the lookups are
those of a stub resolver asking the system's name servers, without DNSSEC validation);
without it, records are answered as none and names through the system resolver.

## A whole peer connection

`peer::PeerDriver` (feature `peer`, on by default, which depends on `rtci`) drives an `rtci`
peer connection over sockets it owns, its UDP host sockets included: it gathers when a
transport begins gathering, and again by itself when the engine says a transport needs new
local candidates (`OnLocalCandidatesNeeded`: a new DTLS association runs on a new 3-tuple,
RFC 8842 section 5.1), binding new ports in its range and closing the previous sockets once a
pair on the new ones is selected. The application only signals.

## I/O

Unlike the other crates of the workspace this one does I/O: it is the tokio side of the
engine's stream interface. The engine itself still never touches a socket or a clock.

## Licence

Licensed under either of the [MIT licence](LICENSE-MIT) or the
[Apache License, Version 2.0](LICENSE-APACHE), at your option.

This crate is part of the [`rtci`](../README.md) workspace, which descends from
[webrtc-rs/rtc](https://github.com/webrtc-rs/rtc) and is developed independently;
[FORK.md](../FORK.md) lists what it carries over upstream. Upstream's licence and copyright
notices are retained.
