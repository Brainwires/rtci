# ICE, SCTP and RTCP randomness audit

## Scope

`RTCRandom` is the workspace boundary for cryptographically secure randomness when a component naturally owns an `RTCCryptoProvider`. It is not a replacement for every random-looking value in the workspace. Standalone crates may retain a direct CSPRNG when adding provider ownership would distort their public API, while deterministic protocol fields and test fixtures should remain deterministic.

## ICE

| Value | Security role | Source and decision |
| --- | --- | --- |
| Local username fragment | Short-term ICE credential | `Agent` generates it through `RTCCryptoProvider::random()`. The standalone compatibility helper retains `rand`'s thread-local CSPRNG. An application-supplied value remains unchanged. |
| Local password | Short-term ICE credential | `Agent` generates it through `RTCCryptoProvider::random()`. The standalone compatibility helper retains `rand`'s thread-local CSPRNG. An application-supplied value remains unchanged. |
| Controlling/controlled tie breaker | Unpredictable role-conflict input | Generated through `RTCCryptoProvider::random()` because `Agent` already owns the provider. |
| STUN transaction ID | Request correlation with an unpredictability requirement | `rtci-stun` retains its documented direct CSPRNG path because a `Message` can be constructed without provider ownership. This is separate from STUN integrity and fingerprint operations, which use the configured provider. |
| Candidate ID | Local uniqueness and diagnostics | Retains the direct CSPRNG helper. It is neither a credential nor a cryptographic identity, and passing a provider solely for this field would add unnecessary coupling. |
| Candidate foundation | Candidate grouping and redundancy elimination | Deterministic CRC32C over candidate properties. It is intentionally not random or secret. |
| mDNS host name | Privacy-preserving local alias | Retains UUID v4 generation through the UUID crate's secure random source. The mDNS subsystem does not naturally own the provider. |
| mDNS delays (first query, probe start, delayed responses) | Desynchronising hosts on a link (RFC 6762 sections 5.2, 6, 8.1); nothing secret | `rtci-mdns` draws them from a SplitMix64 generator seeded from the process's hash seed (`std::collections::hash_map::RandomState`), or from `MdnsConfig::with_jitter_seed` for a reproducible run. Not a CSPRNG and not routed through the provider: predictability of a delay gains an attacker nothing. |
| Explicit configuration and test values | Application policy and deterministic fixtures | Preserved exactly as supplied. Tests may use deterministic `RTCRandom` implementations to verify provider routing and error propagation. |

## SCTP

| Value | Security role | Source and decision |
| --- | --- | --- |
| Verification tag / association ID | Unpredictable nonzero SCTP verification tag | From `RTCCryptoProvider::random()` when `EndpointConfig::random_source` names a provider (the peer connection passes its own), else `rand`'s thread-local CSPRNG; rejected if zero. |
| Initial TSN | Unpredictable starting sequence number | The endpoint's random source (as above), nonzero. |
| State-cookie bytes | Unpredictable 256-bit challenge echoed by the peer | Without `ServerConfig::cookie_authentication`: 32 bytes from the endpoint's random source, compared in constant time. With it the cookie carries an HMAC under a key drawn from that provider's `random()`. |
| Initiate Tag of the INIT ACK that answers an INIT for an existing association (RFC 9260 5.2.2) | Unpredictable nonzero tag, never used by the association | The endpoint's random source, nonzero. |
| HEARTBEAT nonce | 64 bits that tie a HEARTBEAT ACK to the HEARTBEAT sent, so a forged acknowledgement cannot clear the error count or feed the RTT estimate | The endpoint's random source; compared in constant time. |
| HEARTBEAT timer jitter (RFC 9260 8.3) | None: it spreads HEARTBEATs within one RTO | The endpoint's random source. Tests assert the range, not the value. |
| Retransmission counters, sequence arithmetic, and timers | Derived protocol state | Deterministic values derived from negotiated state and elapsed time; no random source is appropriate. |
| `ParamRandom` | Peer-provided extension negotiation input | Parsed from the peer rather than generated locally. It is not an application randomness boundary. |
| Unit-test packets and fixtures | Reproducible protocol inputs | Fixed constants remain intentional. Tests for generated values check invariants rather than depending on exact output. |

## RTCP and the interceptors

| Value | Security role | Source and decision |
| --- | --- | --- |
| RTCP report interval variation, early-feedback dither (RFC 3550 6.3.1, RFC 4585 3.5.2) | None; it desynchronises reporters | The RTCP session's `RtcpRandom`. The peer connection's fallback session (`configure_rtcp_reports_from`, installed when the registry has none) and the default set with `DefaultInterceptorOptions::rtcp_random` draw from the crypto provider's `random()`; the default set without it, and `configure_rtcp_reports`, from `rand`. A seeded provider in both the setting engine and `rtcp_random` makes a session's report times, and everything they drive, the same every run (`the_same_seed_gives_the_same_run`). |
| RTCP session SSRC and CNAME (RFC 3550 8.1, RFC 7022) | Unique per session; the CNAME is not to be traceable | The same `RtcpRandom`. |
| Report and feedback sender SSRCs of the interceptors (NACK generator, RFC 8888 sender, TWCC recorder, receiver report stream, REMB) | Identifiers, nothing secret | `rand`. They name packets and do not decide when anything is sent, so they do not change a run's course. |
| XR receipt-time origin, FlexFEC / ULPFEC initial sequence number and timestamp, pause/resume fallback SSRC, NACK responder's RTX sequence start | Starting values (RFC 3550 5.1 asks for random initial values) | `rand`, unless configured. Values only. |

## Provider boundary decision

ICE already owns `Arc<dyn RTCCryptoProvider>` for STUN operations, so routing credential and tie-breaker generation through the same provider is a natural extension of that ownership. SCTP's random values come from the provider named by `EndpointConfig::random_source` (`rtci-sctp` depends on the `rtci-crypto` traits already, for the State Cookie MAC), which the peer connection sets to its own provider: a seeded provider then reproduces a whole session (`tests/lossy_link_rtc2rtc.rs`). A standalone endpoint without one keeps `rand`'s thread-local CSPRNG, and so does any value whose provider call fails.
