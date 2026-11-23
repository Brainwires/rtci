# W3C WebRTC Priority Control API (webrtc-priority): clause-level audit

Spec: WebRTC Priority Control API, W3C Editor's Draft of 9 February 2021 (https://w3c.github.io/webrtc-priority/; sections as numbered there). Engine: fork master 8916bc3.

The engine is the layer under the JS API: an `RTCPriorityType` string is the binding's concern, the value and its effect (bandwidth share, DSCP on the datagram, DCEP priority) are the engine's. DSCP itself is set by the application's socket; the engine's part is to say which codepoint each outgoing datagram should carry, as it does for ECN in `TransportContext`.

Totals:

- MUST: tested 14 / untested 0 / partial 0 / missing 0 / violated 0 / n-a 0
- SHOULD: tested 0 / untested 0 / partial 0 / missing 0 / violated 0 / n-a 0
- MAY: tested 0 / untested 0 / partial 0 / missing 0 / violated 0 / n-a 1

| ID | § | Level | Clause (short paraphrase) | Verdict | Code | Test | Note |
|---|---|---|---|---|---|---|---|
| PRIO-3.1-1 | 3.1 | MUST | RTCPriorityType "very-low" (DCEP "below normal", 128) | tested | src/peer_connection/priority.rs (RTCPriorityType) | priority_classes_map_to_and_from_dcep_values | very-low, 128 |
| PRIO-3.1-2 | 3.1 | MUST | RTCPriorityType "low" (DCEP "normal", 256) | tested | src/peer_connection/priority.rs (RTCPriorityType) | priority_classes_map_to_and_from_dcep_values | low, 256 |
| PRIO-3.1-3 | 3.1 | MUST | RTCPriorityType "medium" (DCEP "high", 512) | tested | src/peer_connection/priority.rs (RTCPriorityType) | priority_classes_map_to_and_from_dcep_values | medium, 512 |
| PRIO-3.1-4 | 3.1 | MUST | RTCPriorityType "high" (DCEP "extra high", 1024) | tested | src/peer_connection/priority.rs (RTCPriorityType) | priority_classes_map_to_and_from_dcep_values | high, 1024 |
| PRIO-3.2-1 | 3.2 | MUST | RTCRtpEncodingParameters.priority member, default "low" | tested | src/rtp_transceiver/rtp_sender/rtp_encoding_parameters.rs (priority) | datagrams_are_marked_by_their_flows_priority | `RTCRtpEncodingParameters::priority`, `low` by default, set with setParameters |
| PRIO-3.2-2 | 3.2 | MUST | priority influences bandwidth allocation among senders (rtcweb-transports 4.1) | tested | `src/peer_connection/priority.rs` (bandwidth_weight, allocate_bandwidth, allocate_target_bitrate), `src/peer_connection/handler/interceptor.rs` (TargetBitrateChanged), `src/rtp_transceiver/rtp_sender/mod.rs` (target_bitrates) | `each_priority_level_gets_twice_the_share_of_the_level_below`, `the_target_is_divided_among_the_senders_by_priority_and_max_bitrate`, `the_congestion_target_reaches_the_sender_capped_at_max_bitrate` | the congestion controller's target is divided among the sending encodings 1 : 2 : 4 : 8 by priority (RFC 8835 section 4.1), each capped at its maxBitrate with the rest shared out; each sender reads its encodings' shares (`target_bitrates`, the streams' `targetBitrate`); data channels are not in the division (SCTP has its own congestion control) |
| PRIO-3.2-3 | 3.2 | MUST | RTCRtpEncodingParameters.networkPriority member | tested | src/rtp_transceiver/rtp_sender/rtp_encoding_parameters.rs (network_priority) | datagrams_are_marked_by_their_flows_priority |  |
| PRIO-3.2-4 | 3.2 | MUST | networkPriority sets the DSCP marking of the encoding's packets (rtcweb-transports 4.2) | tested | src/peer_connection/priority.rs (RTCPeerConnection::dscp) | datagrams_are_marked_by_their_flows_priority | the engine performs no I/O: `dscp(&datagram)` gives the socket layer the codepoint of each datagram poll_write returned |
| PRIO-3.2-5 | 3.2 | MUST | With networkPriority unset, priority controls the DSCP marking | tested | src/peer_connection/priority.rs (rtp_dscp) | datagrams_are_marked_by_their_flows_priority |  |
| PRIO-4.1-1 | 4.1 | MUST | RTCDataChannel.priority returns the channel's [[DataChannelPriority]] | tested | `src/data_channel/mod.rs:168` | `an_accepted_channel_reports_the_peers_priority` | Returned as the DCEP integer |
| PRIO-4.2-1 | 4.2 | MUST | RTCDataChannelInit.priority, default "low" | tested | `src/data_channel/init.rs:89`, `src/data_channel/init.rs:110` | a_data_channels_priority_defaults_to_low_and_reaches_the_peer | default 256 (low) read back on both sides; 512 (medium) reaches the peer in DATA_CHANNEL_OPEN |
| PRIO-4.3-1 | 4.3 | MUST | Creating a channel initializes [[DataChannelPriority]] from the option | tested | src/data_channel/mod.rs (priority_type) | datagrams_are_marked_by_their_flows_priority |  |
| PRIO-4.3-2 | 4.3 | MUST | An incoming channel takes its priority from the DCEP value | tested | `src/data_channel/internal.rs:265` | `an_accepted_channel_reports_the_peers_priority` | - |
| PRIO-4.3-3 | 4.3 | MUST | Mapping of the integer: 0-128 very-low, 129-256 low, 257-512 medium, 513+ high | tested | src/peer_connection/priority.rs (from_dcep_priority) | priority_classes_map_to_and_from_dcep_values |  |
| PRIO-5-1 | 5 | MAY | DSCP bleaching or ignoring markings as a countermeasure | n/a | - | - | Network configuration, not an endpoint rule |

## Gaps, in order of importance

1. **Media priority (M).** `PRIO-3.2-1`, `PRIO-3.2-2`, `PRIO-3.2-3`, `PRIO-3.2-5`, `PRIO-3.1-1` to `PRIO-3.1-4`: a priority type, `priority` and `network_priority` on `RTCRtpEncodingParameters` (validated and returned by get/set parameters), and a weight per sender wherever the estimate is divided.
2. **DSCP hint to the socket layer (S).** `PRIO-3.2-4`: a DSCP field in `TransportContext` beside `ecn`, set from the encoding's (network) priority and the media kind per RFC 8837 table 1; for data channels from the channel priority.
3. **Priority classes for data channels (S).** `PRIO-4.3-3`, `PRIO-4.2-1`, `PRIO-4.3-1`: a `priority_type()` accessor with the 4.3 mapping, and a test that a non-default priority reaches the peer.

## Bugs found

None. (`rtc-sctp` has `Stream::set_priority` and a weighted scheduler, `a_higher_priority_stream_gets_the_larger_share`; whether the peer connection sets it from the channel's priority was not traced.)
