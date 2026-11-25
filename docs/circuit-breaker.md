# The RTP circuit breaker (RFC 8083)

The default interceptor set has an RTP circuit breaker on every transport (RFC 8834 section 7.1
requires one of a WebRTC endpoint). It reads the receiver reports about each flow this endpoint
sends and ceases a flow whose receiver has gone (RTCP timeout), whose packets do not arrive
(media timeout), that persistently sends more than ten times what TCP would on that path
(congestion), or that is outside the bound the application set (media usability). The clause
audit is `docs/conformance/audit/rfc8083.md`; the code is
`rtci-interceptor/src/circuit_breaker/mod.rs`.

## What the application sees

- A ceased flow's packets are dropped in the engine. `RTCPeerConnectionEvent::OnCircuitBreaker`
  names the sender, the RID, the SSRC, the breaker that tripped and the time before which a
  restart is refused; a restart is announced with `ceased: None`.
- The engine restarts a ceased flow by itself (RFC 8083 section 4.5: "information that the
  congestion has dissipated") on the receiver's reports about another flow that still runs on
  the same transport, never before the hold has passed, and holds a flow that trips again soon
  after a restart twice as long each time (up to 64 times). When every flow of a transport has
  ceased no report can say anything, and the restart is the application's:
  `DefaultInterceptorHandles::circuit_breaker`, `CircuitBreakerHandle::restart`.
- A ceased encoding takes no share of the congestion controller's target.
- Settings: `DefaultInterceptorOptions::circuit_breaker` (`false`: no breaker; the `Chrome`
  behaviour profile, row `cb.enabled`, since libwebrtc has none),
  `circuit_breaker_automatic_restart` (`false`: every restart is the application's),
  `circuit_breaker_packet_size` (`cb.packet-size`).
- `T_rr_interval` is 0 by default (RFC 4585 section 4.2), so beside video the peer reports every
  few tens of milliseconds, and the breaker's counts of reports (five without a new packet for
  the media timeout) pass in a quarter of a second or less. The `Performance` profile's 1 s
  interval makes them a matter of seconds.

## Known limits

This section belongs with the conformance documentation's known limits ("Standing departures
from a SHOULD", added by `conf/dtls-resume-3`); move it there when that is on master. It is not
a departure: ceasing is what RFC 8083 section 4.3 says ("SHOULD cease transmission"). It is
what following it costs a user.

**A deep queue at the bottleneck: the voice of a call is silent for some seconds after a
capacity collapse.** Measured with the capacity instrument (a 2.5 Mbit/s audio and video call
between two peers of this engine, the caller's path capped to 300 kbit/s for 20 s; seeds 1 to 300 a
tree behind the 1000 ms queue; hosted runs 45516841561 / 45516852677 and 45516861432 / 45516870845):

| bottleneck queue | before (0.2 line without the corrected rules) | now |
|---|---|---|
| 300 ms (534 runs) | voice ceased 0.13 to 0.22 s after the drop and never restarted in 63 runs (12 %) | no flow ceased in any run |
| 1000 ms (300 runs) | voice ceased and never restarted in 96 runs (32 %): silent to the end of the call | voice ceased for congestion in 84 runs (28 %), 3.3 to 3.8 s after the drop, and restarted by the engine in every one: silent for 3.7 s (median), 7.3 s (90th percentile), 10.9 s (worst) |
| both directions capped, 300 ms (100 runs) | a flow left ceased in 94 runs (retransmission flows, video) | a flow ceased in 7 runs, each restarted; the voice in none |

Why it still happens behind the 1000 ms queue: the voice is 76 kbit/s whatever the congestion
controller says, the round trip is over a second and packets are lost while the video's
backlog drains, and ten times the TCP throughput for that loss and round trip is under 76
kbit/s over the whole CB_INTERVAL window and over the last round trip. The breaker ceases the
voice as the text has it, holds it for the triggering interval, and restarts it when the
video's reports show the loss gone. An application that would rather keep the voice lowers
what it sends when its target falls (the engine cannot lower an application's audio), sets a
`T_rr_interval`, or takes the restarts into its own hands.

**rtci 0.1.0** has none of this: there the breaker silences a call's voice about 150 ms after
such a collapse in about 8 % of calls through the default chain (83 of 1000 runs; 30 % behind
a 1000 ms queue, 61 of 200), never restarts it, and tells the application nothing (poll
`CircuitBreakerHandle::ceased` and call `restart`, or build the chain without the breaker).
