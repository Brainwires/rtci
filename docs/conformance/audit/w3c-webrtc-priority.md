# W3C WebRTC Priority Control API (webrtc-priority): clause-level audit

Spec: WebRTC Priority Control API, W3C Editor's Draft of 9 February 2021 (https://w3c.github.io/webrtc-priority/; sections as numbered there). Engine: fork master 8916bc3.

The engine is the layer under the JS API: an `RTCPriorityType` string is the binding's concern, the value and its effect (bandwidth share, DSCP on the datagram, DCEP priority) are the engine's. DSCP itself is set by the application's socket; the engine's part is to say which codepoint each outgoing datagram should carry, as it does for ECN in `TransportContext`.

Totals:

- MUST: tested 2 / untested 2 / partial 4 / missing 6 / violated 0 / n-a 0
- SHOULD: tested 0 / untested 0 / partial 0 / missing 0 / violated 0 / n-a 0
- MAY: tested 0 / untested 0 / partial 0 / missing 0 / violated 0 / n-a 1

| ID | § | Level | Clause (short paraphrase) | Verdict | Code | Test | Note |
|---|---|---|---|---|---|---|---|
| PRIO-3.1-1 | 3.1 | MUST | RTCPriorityType "very-low" (DCEP "below normal", 128) | partial | `rtc-datachannel/src/message/message_channel_open.rs:13` | - | The DCEP constant exists; no priority type for media |
| PRIO-3.1-2 | 3.1 | MUST | RTCPriorityType "low" (DCEP "normal", 256) | partial | `rtc-datachannel/src/message/message_channel_open.rs:15` | - | Same |
| PRIO-3.1-3 | 3.1 | MUST | RTCPriorityType "medium" (DCEP "high", 512) | partial | `rtc-datachannel/src/message/message_channel_open.rs:17` | - | Same |
| PRIO-3.1-4 | 3.1 | MUST | RTCPriorityType "high" (DCEP "extra high", 1024) | partial | `rtc-datachannel/src/message/message_channel_open.rs:19` | - | Same |
| PRIO-3.2-1 | 3.2 | MUST | RTCRtpEncodingParameters.priority member, default "low" | missing | `src/rtp_transceiver/rtp_sender/rtp_encoding_parameters.rs:1` | - | The encoding parameters have no priority |
| PRIO-3.2-2 | 3.2 | MUST | priority influences bandwidth allocation among senders (rtcweb-transports 4.1) | missing | - | - | No allocation among senders exists: one estimate, no per-sender share |
| PRIO-3.2-3 | 3.2 | MUST | RTCRtpEncodingParameters.networkPriority member | missing | `src/rtp_transceiver/rtp_sender/rtp_encoding_parameters.rs:1` | - | - |
| PRIO-3.2-4 | 3.2 | MUST | networkPriority sets the DSCP marking of the encoding's packets (rtcweb-transports 4.2) | missing | `rtc-shared/src/lib.rs:1` | - | `TransportContext` carries ECN but no DSCP for the socket layer to apply |
| PRIO-3.2-5 | 3.2 | MUST | With networkPriority unset, priority controls the DSCP marking | missing | - | - | - |
| PRIO-4.1-1 | 4.1 | MUST | RTCDataChannel.priority returns the channel's [[DataChannelPriority]] | tested | `src/data_channel/mod.rs:168` | `an_accepted_channel_reports_the_peers_priority` | Returned as the DCEP integer |
| PRIO-4.2-1 | 4.2 | MUST | RTCDataChannelInit.priority, default "low" | untested | `src/data_channel/init.rs:89`, `src/data_channel/init.rs:110` | - | Default is 256 ("normal" = "low"); no test reads back a non-default value from the creating side or the wire |
| PRIO-4.3-1 | 4.3 | MUST | Creating a channel initializes [[DataChannelPriority]] from the option | untested | `src/data_channel/internal.rs:231`, `src/data_channel/internal.rs:153` | - | Copied into the channel and its DATA_CHANNEL_OPEN |
| PRIO-4.3-2 | 4.3 | MUST | An incoming channel takes its priority from the DCEP value | tested | `src/data_channel/internal.rs:265` | `an_accepted_channel_reports_the_peers_priority` | - |
| PRIO-4.3-3 | 4.3 | MUST | Mapping of the integer: 0-128 very-low, 129-256 low, 257-512 medium, 513+ high | missing | `src/data_channel/mod.rs:168` | - | The engine hands out the integer; no function maps it to the four classes |
| PRIO-5-1 | 5 | MAY | DSCP bleaching or ignoring markings as a countermeasure | n/a | - | - | Network configuration, not an endpoint rule |

## Gaps, in order of importance

1. **Media priority (M).** `PRIO-3.2-1`, `PRIO-3.2-2`, `PRIO-3.2-3`, `PRIO-3.2-5`, `PRIO-3.1-1` to `PRIO-3.1-4`: a priority type, `priority` and `network_priority` on `RTCRtpEncodingParameters` (validated and returned by get/set parameters), and a weight per sender wherever the estimate is divided.
2. **DSCP hint to the socket layer (S).** `PRIO-3.2-4`: a DSCP field in `TransportContext` beside `ecn`, set from the encoding's (network) priority and the media kind per RFC 8837 table 1; for data channels from the channel priority.
3. **Priority classes for data channels (S).** `PRIO-4.3-3`, `PRIO-4.2-1`, `PRIO-4.3-1`: a `priority_type()` accessor with the 4.3 mapping, and a test that a non-default priority reaches the peer.

## Bugs found

None. (`rtc-sctp` has `Stream::set_priority` and a weighted scheduler, `a_higher_priority_stream_gets_the_larger_share`; whether the peer connection sets it from the channel's priority was not traced.)
