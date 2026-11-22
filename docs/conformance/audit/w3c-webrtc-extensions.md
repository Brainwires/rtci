# W3C WebRTC Extensions (webrtc-extensions): clause-level audit

Spec: WebRTC Extensions, W3C Editor's Draft at https://w3c.github.io/webrtc-extensions/ (served copy last modified 24 September 2026). Engine: fork master 8916bc3.

The draft's section numbers are generated when it is rendered; this file numbers its extensions in heading order: 3 ICE candidate filtering by CSP, 4 RTP header extension control (4.1 slots and procedures, 4.2 methods), 5 RTCRtpEncodingParameters extensions (5.1 RTCResolutionRestriction), 6 key frame request in setParameters, 7 RTCIceTransport extensions (7.1 RTCIceCandidatePairEvent, 7.2 candidate match), 8 RTCRtpContributingSource extensions, 9 transferable data channels, 10 RTP header encryption (10.1 policy enum, 10.2 RTCConfiguration), 11 RTCRtpReceiver source-change events, 12 disabling hardware acceleration, 13 always negotiating data channels (13.1 configuration, 13.2 procedures, 13.3 JSEP), 14 event summary, 15 timestamp behaviour, 16 target latency, 17 diagnostic logging.

`n/a` rows are browser concerns (CSP, workers, hardware codecs, user-agent logging) or steps an API layer performs wholly above the engine because the encoder is the application's.

Totals:

- MUST: tested 6 / untested 7 / partial 9 / missing 39 / violated 0 / n-a 12
- SHOULD: tested 1 / untested 0 / partial 0 / missing 0 / violated 0 / n-a 1
- MAY: tested 0 / untested 0 / partial 0 / missing 1 / violated 0 / n-a 0

| ID | § | Level | Clause (short paraphrase) | Verdict | Code | Test | Note |
|---|---|---|---|---|---|---|---|
| WEBRTC-EXT-3-1 | 3 | MUST | If CSP blocks RTC connections, all candidates are administratively prohibited | n/a | - | - | Content-Security-Policy is a browser concept |
| WEBRTC-EXT-4.1-1 | 4.1 | MUST | RTCRtpHeaderExtensionCapability gains a required direction | missing | `src/rtp_transceiver/internal.rs:55` | - | The to-negotiate list is URIs only; an extension is either listed or not, with no direction |
| WEBRTC-EXT-4.1-2 | 4.1 | MUST | [[HeaderExtensionsToNegotiate]] of a new transceiver is copied from the first non-stopping transceiver of the same kind | missing | `src/rtp_transceiver/internal.rs:103` | - | A new transceiver starts with `None` (everything the media engine has) |
| WEBRTC-EXT-4.1-3 | 4.1 | MUST | Otherwise it is the implemented extensions; mandatory ones not "stopped", not-offered-by-default ones "stopped" | partial | `src/peer_connection/sdp/mod.rs:1033`, `src/peer_connection/configuration/media_engine.rs:312` | - | `None` offers every registered extension; there is no implemented-but-stopped state |
| WEBRTC-EXT-4.1-4 | 4.1 | MUST | Extensions that must be identical across a bundle copy their direction from another transceiver in the bundle | missing | - | - | - |
| WEBRTC-EXT-4.1-5 | 4.1 | MUST | [[NegotiatedHeaderExtensions]] starts empty | missing | `src/peer_connection/configuration/media_engine.rs:312` | - | Negotiated extensions are kept per media engine, not per transceiver |
| WEBRTC-EXT-4.1-6 | 4.1 | MUST | Applying an answer: each extension's direction becomes the answer's extmap direction, or "stopped" if absent | missing | `src/peer_connection/configuration/media_engine.rs:1002` | - | The media engine records the negotiated ids; no per-transceiver direction list |
| WEBRTC-EXT-4.1-7 | 4.1 | MUST | For a remote answer the direction is reversed to the local point of view | missing | - | - | - |
| WEBRTC-EXT-4.1-8 | 4.1 | MUST | An extension unusable because of other negotiated options becomes "stopped" | missing | - | - | - |
| WEBRTC-EXT-4.1-9 | 4.1 | MUST | After an answer [[NegotiatedHeaderExtensions]] and [[HeaderExtensionsToNegotiate]] are both the negotiated list | missing | `src/rtp_transceiver/internal.rs:119` | - | The to-negotiate list is only what the application last set |
| WEBRTC-EXT-4.1-10 | 4.1 | MUST | Initial offer: an a=extmap for each to-negotiate extension that is not "stopped", with its direction | partial | `src/peer_connection/sdp/mod.rs:1035` | - | Listed URIs are offered, unlisted ones left out; no direction on the extmap line; no test calls the setter |
| WEBRTC-EXT-4.1-11 | 4.1 | MUST | Subsequent offer: extmap lines from [[HeaderExtensionsToNegotiate]], so a stopped extension can be re-offered | partial | `src/peer_connection/sdp/mod.rs:1051` | - | `reoffered_header_extensions` re-offers listed URIs; untested |
| WEBRTC-EXT-4.1-12 | 4.1 | MUST | Answer: only extensions in the offer and in the list with a non-stopped direction, direction not exceeding the offer's | partial | `src/peer_connection/sdp/mod.rs:1037` | - | Filtered by URI; direction not handled |
| WEBRTC-EXT-4.2-1 | 4.2 | MUST | getHeaderExtensionsToNegotiate returns the slot | partial | `src/rtp_transceiver/internal.rs:115` | - | Getter is crate-private; the public transceiver has only the setter |
| WEBRTC-EXT-4.2-2 | 4.2 | MUST | setHeaderExtensionsToNegotiate: a list of a different size is an InvalidModificationError | missing | `src/rtp_transceiver/mod.rs:332` | - | The setter takes any list, infallibly |
| WEBRTC-EXT-4.2-3 | 4.2 | MUST | setHeaderExtensionsToNegotiate: a URI differing from the slot's at the same index is an InvalidModificationError | missing | `src/rtp_transceiver/mod.rs:332` | - | - |
| WEBRTC-EXT-4.2-4 | 4.2 | MUST | setHeaderExtensionsToNegotiate: a mandatory-to-use extension not "sendrecv" is an InvalidModificationError | missing | `src/rtp_transceiver/mod.rs:332` | - | The mid extension can be dropped |
| WEBRTC-EXT-4.2-5 | 4.2 | MUST | setHeaderExtensionsToNegotiate: stopping a mandatory-to-implement extension is an InvalidModificationError | missing | `src/rtp_transceiver/mod.rs:332` | - | - |
| WEBRTC-EXT-4.2-6 | 4.2 | MAY | Directions are restricted to what the implementation can do | missing | - | - | - |
| WEBRTC-EXT-4.2-7 | 4.2 | MUST | setHeaderExtensionsToNegotiate stores the list | untested | `src/rtp_transceiver/internal.rs:119` | - | - |
| WEBRTC-EXT-4.2-8 | 4.2 | MUST | getNegotiatedHeaderExtensions returns the per-transceiver negotiated list | missing | `src/peer_connection/configuration/media_engine.rs:800` | - | Only the media engine's connection-wide map exists |
| WEBRTC-EXT-5-1 | 5 | MUST | scaleResolutionDownTo member; when present scaleResolutionDownBy is ignored and frames are never upscaled | missing | `src/rtp_transceiver/rtp_sender/rtp_encoding_parameters.rs:13` | - | Not in the encoding parameters |
| WEBRTC-EXT-5-2 | 5 | MUST | scaleResolutionDownTo must be on all active encodings, else OperationError (addTransceiver) / InvalidModificationError (setParameters) | missing | `src/rtp_transceiver/rtp_sender/rtp_encoding_parameters.rs:13` | - | - |
| WEBRTC-EXT-5-3 | 5 | MUST | Both dimensions of scaleResolutionDownTo are greater than 0, else the same errors | missing | `src/rtp_transceiver/rtp_sender/rtp_encoding_parameters.rs:13` | - | - |
| WEBRTC-EXT-5-4 | 5 | MUST | ptime member: preferred packet duration in milliseconds | missing | `src/rtp_transceiver/rtp_sender/rtp_encoding_parameters.rs:13` | - | - |
| WEBRTC-EXT-5-5 | 5 | MUST | adaptivePtime member, default false: fixed frame length unless true | missing | `src/rtp_transceiver/rtp_sender/rtp_encoding_parameters.rs:13` | - | - |
| WEBRTC-EXT-5-6 | 5 | MUST | adaptivePtime true together with ptime is an InvalidModificationError | missing | `src/rtp_transceiver/rtp_sender/rtp_encoding_parameters.rs:13` | - | - |
| WEBRTC-EXT-5.1-1 | 5.1 | MUST | RTCResolutionRestriction.maxWidth / maxHeight, orientation agnostic, one scaling factor for both dimensions | missing | `src/rtp_transceiver/rtp_sender/rtp_encoding_parameters.rs:13` | - | The scaling itself is the encoder's; the engine would only carry and validate it |
| WEBRTC-EXT-6-1 | 6 | MUST | RTCSetParameterOptions.encodingOptions, one RTCEncodingOptions { keyFrame } per encoding | n/a | - | - | Encoder is the application's |
| WEBRTC-EXT-6-2 | 6 | MUST | setParameters: encodingOptions is emptied for audio | n/a | - | - | Encoder is the application's |
| WEBRTC-EXT-6-3 | 6 | MUST | setParameters: encodingOptions of a different length than encodings is an InvalidModificationError | n/a | - | - | Encoder is the application's |
| WEBRTC-EXT-6-4 | 6 | MUST | setParameters: keyFrame true asks that encoding's encoder for a key frame, without waiting | n/a | - | - | Encoder is the application's |
| WEBRTC-EXT-7-1 | 7 | MUST | When the ICE agent forms a candidate pair it is appended to [[CandidatePairs]] and icecandidatepairadd fires | missing | `src/peer_connection/transport/ice/mod.rs:1` | - | No event; pairs are visible only through get_stats |
| WEBRTC-EXT-7-2 | 7 | MUST | Before nominating, a cancelable icecandidatepairnominate fires; if cancelled the agent keeps checking | missing | `src/peer_connection/transport/ice/mod.rs:1` | - | Nomination cannot be deferred |
| WEBRTC-EXT-7-3 | 7 | MUST | [[ProposalPending]] is true while a nominate or remove proposal is being decided | missing | - | - | - |
| WEBRTC-EXT-7-4 | 7 | MUST | Before removing a pair, icecandidatepairremove fires, cancelable when freeing an unused candidate | missing | `src/peer_connection/transport/ice/mod.rs:1` | - | - |
| WEBRTC-EXT-7-5 | 7 | MUST | A cancelled removal keeps the pair and its connectivity checks | missing | - | - | - |
| WEBRTC-EXT-7-6 | 7 | MUST | An accepted removal takes the pair out of [[CandidatePairs]] and the agent drops it | missing | - | - | - |
| WEBRTC-EXT-7-7 | 7 | MUST | selectCandidatePair: InvalidStateError if closed, a proposal is pending, or the state is new / failed / closed | missing | `src/peer_connection/transport/ice/mod.rs:1` | - | No such method |
| WEBRTC-EXT-7-8 | 7 | MUST | selectCandidatePair: NotFoundError for a pair not in [[CandidatePairs]] | missing | - | - | - |
| WEBRTC-EXT-7-9 | 7 | MUST | selectCandidatePair: the agent sends data on the given pair, then selected pair and state are updated with their events | missing | - | - | - |
| WEBRTC-EXT-7-10 | 7 | MUST | removeCandidatePair: the same three InvalidStateError checks | missing | `src/peer_connection/transport/ice/mod.rs:1` | - | No such method |
| WEBRTC-EXT-7-11 | 7 | MUST | removeCandidatePair: NotFoundError for an unknown pair | missing | - | - | - |
| WEBRTC-EXT-7-12 | 7 | MUST | removeCandidatePair: the agent stops checks on the pair, then a non-cancelable icecandidatepairremove fires | missing | - | - | - |
| WEBRTC-EXT-7.1-1 | 7.1 | MUST | RTCIceCandidatePairEvent carries the candidatePair | missing | `src/peer_connection/event/mod.rs:1` | - | No candidate-pair event in the event enum |
| WEBRTC-EXT-7.2-1 | 7.2 | MUST | Changing the selected pair picks the [[CandidatePairs]] item whose local and remote candidates match | missing | - | - | There is no [[CandidatePairs]] list to pick from |
| WEBRTC-EXT-7.2-2 | 7.2 | MUST | Candidate match: identical candidate string, sdpMid, sdpMLineIndex and usernameFragment (null matching only null) | missing | - | - | - |
| WEBRTC-EXT-8-1 | 8 | MUST | RTCRtpContributingSource.captureTimestamp: the abs-capture-time of the packet, or interpolated from an earlier one, else undefined | missing | `src/rtp_transceiver/rtp_receiver/rtp_contributing_source.rs:14`, `rtc-rtp/src/extension/mod.rs:1` | - | No abs-capture-time header extension parser |
| WEBRTC-EXT-8-2 | 8 | MUST | RTCRtpContributingSource.senderCaptureTimeOffset: the extension's estimated capture clock offset, or the most recent one, else undefined | missing | `src/rtp_transceiver/rtp_receiver/rtp_contributing_source.rs:14` | - | - |
| WEBRTC-EXT-9-1 | 9 | MUST | RTCDataChannel is exposed to and transferable to any Worker | n/a | - | - | Worker transfer is a binding concern |
| WEBRTC-EXT-10-1 | 10 | SHOULD | Once both endpoints signalled a=cryptex, header extensions and CSRCs are encrypted with RFC 9335 | tested | `src/peer_connection/cryptex.rs:121`, `src/peer_connection/handler/srtp.rs:35` | `cryptex_aes_cm_test_vectors`, `require_accepts_cryptex_both_ways` | - |
| WEBRTC-EXT-10.1-1 | 10.1 | MUST | "disable": no a=cryptex in offers or answers, a remote a=cryptex is not acted on | untested | `src/peer_connection/cryptex.rs:93` | - | - |
| WEBRTC-EXT-10.1-2 | 10.1 | MUST | "negotiate": a=cryptex is offered and answered; without the remote's, headers go in the clear | untested | `src/peer_connection/cryptex.rs:88`, `src/peer_connection/cryptex.rs:121` | `cryptex_at_the_session_or_on_every_rtp_section` | The helper that reads a description is tested; no negotiate-mode exchange is |
| WEBRTC-EXT-10.1-3 | 10.1 | MUST | "require": a remote description without cryptex is rejected (InvalidAccessError) | tested | `src/peer_connection/cryptex.rs:109` | `require_refuses_an_answer_without_cryptex`, `require_refuses_an_offer_without_cryptex` | - |
| WEBRTC-EXT-10.1-4 | 10.1 | MUST | "require": received RTP not encrypted with cryptex is not processed further (RFC 9335 5.2) | tested | `rtc-srtp/src/context/mod.rs:1` | `cryptex_required_refuses_clear_header_extensions` | - |
| WEBRTC-EXT-10.2-1 | 10.2 | MUST | RTCConfiguration.rtpHeaderEncryptionPolicy, default "negotiate" | partial | `src/peer_connection/cryptex.rs:21`, `src/peer_connection/cryptex.rs:63` | - | The policy exists; the engine's default is `Disable`, so an API layer must set it |
| WEBRTC-EXT-10.2-2 | 10.2 | MUST | With BUNDLE, a=cryptex is on every RTP m= section of the group or on none | tested | `src/peer_connection/cryptex.rs:37`, `src/peer_connection/cryptex.rs:88` | `cryptex_at_the_session_or_on_every_rtp_section` | - |
| WEBRTC-EXT-10.2-3 | 10.2 | MUST | The policy cannot change after construction: setConfiguration with a different value fails (InvalidModificationError) | partial | `src/peer_connection/cryptex.rs:63` | - | `set_rtp_header_encryption_policy` can be called at any time and is not refused after negotiation |
| WEBRTC-EXT-11-1 | 11 | MUST | ssrcchange fires on the receiver when the synchronization source of the last frame changes | missing | `src/rtp_transceiver/rtp_receiver/mod.rs:321` | - | Sources can be polled; no change event |
| WEBRTC-EXT-11-2 | 11 | MUST | csrcchange fires when the contributing sources change, after both lists are updated | missing | `src/rtp_transceiver/rtp_receiver/mod.rs:299` | - | - |
| WEBRTC-EXT-12-1 | 12 | MUST | RTCRtpReceiver.disableHardwareDecoding, only before any peer connection exists | n/a | - | - | No decoders in the engine |
| WEBRTC-EXT-12-2 | 12 | MUST | RTCRtpSender.disableHardwareEncoding, only before any peer connection exists | n/a | - | - | No encoders in the engine |
| WEBRTC-EXT-12-3 | 12 | MUST | With hardware disabled, hardware-only codecs are removed from the receive and send codec lists | n/a | - | - | The application registers its codecs |
| WEBRTC-EXT-13.1-1 | 13.1 | MUST | RTCConfiguration.alwaysNegotiateDataChannels, default false | tested | `src/peer_connection/always_negotiate.rs:13`, `src/peer_connection/internal.rs:230` | `the_data_section_is_offered_first_without_a_channel` | - |
| WEBRTC-EXT-13.2-1 | 13.2 | MUST | createDataChannel updates negotiation-needed for the first channel only if [[SctpTransport]] is null | untested | `src/peer_connection/internal.rs:540` | - | No test creates the first channel after an always-negotiated data section and checks the flag |
| WEBRTC-EXT-13.2-2 | 13.2 | MUST | The setting cannot change after construction: setConfiguration with a different value fails | partial | `src/peer_connection/always_negotiate.rs:13` | - | The setter is accepted at any time |
| WEBRTC-EXT-13.3-1 | 13.3 | MUST | Initial offer: with the preference set, a data m= section is generated before the transceivers' sections | tested | `src/peer_connection/internal.rs:308` | `the_data_section_is_offered_first_without_a_channel` | - |
| WEBRTC-EXT-13.3-2 | 13.3 | MUST | A data section is generated for a created channel only if none was generated already | untested | `src/peer_connection/internal.rs:540` | - | - |
| WEBRTC-EXT-13.3-3 | 13.3 | MUST | The always-negotiated data section is the offerer-tagged m= section of the BUNDLE group | untested | `src/peer_connection/internal.rs:308` | - | It is first in the offer; the test does not read a=group |
| WEBRTC-EXT-15-1 | 15 | MUST | A received frame's capture timestamp is the remote capture time translated to the receiver clock, when computable | partial | `src/peer_connection/message/mod.rs:420` | - | The application sees every RTCP SR and RTP timestamp and can compute it; the engine offers no helper and no abs-capture-time |
| WEBRTC-EXT-15-2 | 15 | MUST | A received video frame's RTP timestamp is that of its packets | tested | `src/peer_connection/handler/endpoint.rs:264` | `every_reference_resolves_and_nothing_unmeasured_is_reported` | Packets are delivered with their headers intact; frames are the application's |
| WEBRTC-EXT-15-3 | 15 | MUST | A received frame's receive timestamp is when its last packet arrived | untested | `src/peer_connection/message/mod.rs:420` | - | `poll_read` hands out the packet; whether the arrival instant travels with it was not confirmed by a test |
| WEBRTC-EXT-16-1 | 16 | MUST | RTCConfiguration.targetLatency ("lowest" default, "none") | n/a | - | - | Network link setup is the application's |
| WEBRTC-EXT-16-2 | 16 | SHOULD | "lowest": use techniques such as network slicing when available | n/a | - | - | Network link setup is the application's |
| WEBRTC-EXT-17-1 | 17 | MUST | startDiagnosticLogging / stopDiagnosticLogging / cancelDiagnosticLogging with their state and metadata checks | n/a | - | - | User-agent logging session, user consent |
| WEBRTC-EXT-17-2 | 17 | MUST | Nothing is logged after a session stops; a cancelled session's data is deleted | n/a | - | - | User-agent logging session |

## Gaps, in order of importance

1. **RTP header extension control with directions (M).** `WEBRTC-EXT-4.1-1` to `WEBRTC-EXT-4.1-12`, `WEBRTC-EXT-4.2-1` to `WEBRTC-EXT-4.2-8`: a per-transceiver list of (uri, direction) seeded from the media engine (or the first transceiver of the kind), the four setter checks, extmap directions in offers and answers, the negotiated list written back when an answer is applied, public getters for both lists, and tests (today no test calls the setter).
2. **ICE candidate pair control (L).** `WEBRTC-EXT-7-1` to `WEBRTC-EXT-7-12`, `WEBRTC-EXT-7.1-1`, `WEBRTC-EXT-7.2-1`, `WEBRTC-EXT-7.2-2`: pair-added / pair-removed / nomination-proposed events from `rtc-ice`, a way to veto a nomination or a removal, `select_candidate_pair` and `remove_candidate_pair` on the ICE transport.
3. **Absolute capture time (M).** `WEBRTC-EXT-8-1`, `WEBRTC-EXT-8-2`, `WEBRTC-EXT-15-1`: the abs-capture-time header extension (parse, write, register), the two members on the contributing / synchronization source with interpolation, and an SR-based NTP mapping helper.
4. **Encoding parameters (S).** `WEBRTC-EXT-5-1` to `WEBRTC-EXT-5-6`, `WEBRTC-EXT-5.1-1`: `scale_resolution_down_to`, `ptime`, `adaptive_ptime` carried, validated and returned.
5. **Source-change events (S).** `WEBRTC-EXT-11-1`, `WEBRTC-EXT-11-2`.
6. **Policies fixed at construction, and the default (S).** `WEBRTC-EXT-10.2-1`, `WEBRTC-EXT-10.2-3`, `WEBRTC-EXT-13.2-2`: refuse a change once a description exists; decide whether the engine default becomes `Negotiate`.
7. **Tests (S).** `WEBRTC-EXT-10.1-1`, `WEBRTC-EXT-10.1-2`, `WEBRTC-EXT-13.2-1`, `WEBRTC-EXT-13.3-2`, `WEBRTC-EXT-13.3-3`, `WEBRTC-EXT-15-3`, `WEBRTC-EXT-4.2-7`.

## Bugs found

1. **The mid extension can be removed from the offer.** `set_header_extensions_to_negotiate(Some(vec![]))` (`src/rtp_transceiver/mod.rs:332`) is accepted, and `sdp/mod.rs:1037` then skips every extension, the BUNDLE-mandatory `urn:ietf:params:rtp-hdrext:sdes:mid` included. Reproduce: add a transceiver, set an empty list, create an offer: the m= section has no a=extmap for mid.
2. **Cryptex policy can be switched mid-session.** `set_rtp_header_encryption_policy` (`src/peer_connection/cryptex.rs:63`) has no state check. Reproduce: negotiate with `Negotiate`, then set `Disable` and renegotiate: the engine drops a=cryptex from a live session, which the spec forbids by making the policy immutable.
