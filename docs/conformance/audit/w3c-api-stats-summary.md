# W3C API and statistics: audit summary

Area `w3c-api-stats`. Engine: fork master 8916bc3. Read-only analysis of code and tests; nothing was run.

## Files

| Spec | File | Version audited |
|---|---|---|
| WebRTC (webrtc-pc) | [w3c-webrtc-pc.md](w3c-webrtc-pc.md) | Editor's Draft, served copy of 12 November 2026 |
| WebRTC Statistics (webrtc-stats) | [w3c-webrtc-stats.md](w3c-webrtc-stats.md) | Editor's Draft, served copy of 8 October 2026 |
| WebRTC Extensions | [w3c-webrtc-extensions.md](w3c-webrtc-extensions.md) | Editor's Draft, served copy of 24 September 2026 |
| WebRTC Priority Control | [w3c-webrtc-priority.md](w3c-webrtc-priority.md) | Editor's Draft, 9 February 2021 |
| WebRTC Encoded Transform | [w3c-webrtc-encoded-transform.md](w3c-webrtc-encoded-transform.md) | Editor's Draft, 25 June 2026 |
| RFC 9605 (SFrame) | [rfc9605.md](rfc9605.md) | RFC, August 2024 |
| RTP Payload Format for SFrame | [draft-ietf-avtcore-rtp-sframe.md](draft-ietf-avtcore-rtp-sframe.md) | draft-ietf-avtcore-rtp-sframe-03, 21 October 2026 (pinned) |
| WebRTC SVC extension | [w3c-webrtc-svc.md](w3c-webrtc-svc.md) | Editor's Draft, served copy of 14 September 2026 |
| Media Capture and Streams (section 4 only) | [w3c-mediacapture-main.md](w3c-mediacapture-main.md) | Editor's Draft, served copy of 19 November 2026 |

## Totals per spec

MUST-level rows (algorithm steps, members, attributes and enum values count as MUST unless the text says should or may):

| Spec | Rows | tested | untested | partial | missing | violated | n/a |
|---|---|---|---|---|---|---|---|
| webrtc-pc | 957 | 824 | 2 | 24 | 17 | 0 | 62 |
| webrtc-stats | 263 | 256 | 0 | 1 | 0 | 0 | 1 |
| webrtc-extensions | 76 | 59 | 0 | 0 | 0 | 0 | 14 |
| webrtc-priority | 15 | 14 | 0 | 0 | 0 | 0 | 0 |
| webrtc-encoded-transform | 54 | 41 | 0 | 0 | 0 | 0 | 12 |
| RFC 9605 | 40 | 25 | 1 | 0 | 3 | 0 | 3 |
| webrtc-svc | 56 | 51 | 0 | 0 | 0 | 0 | 1 |
| mediacapture-main (section 4) | 28 | 26 | 0 | 0 | 0 | 0 | 2 |
| draft-ietf-avtcore-rtp-sframe-03 | 36 | 28 | 0 | 0 | 1 | 1 | 0 |
| **All** | **1525** | **1324** | **3** | **25** | **21** | **1** | **95** |

The Rows column counts all levels; the verdict columns count MUST rows. SHOULD rows, all specs: tested 11 / untested 0 / partial 1 / missing 1 / violated 0 / n-a 11. MAY rows: tested 10 / untested 2 / partial 2 / missing 2 / violated 0 / n-a 16. Recounted from the tables on branch `conf/pc-25-open-rows`.

Of the MUST rows that bind the engine (1374 after `n/a`), 1324 (96%) are implemented and tested, 3 (0%) implemented without a test that would catch a regression, 25 (2%) partial, 21 (2%) missing and 1 (0%) violated.

Statistics members (webrtc-stats, 206 member rows): 126 measured by the engine, 69 present only from the application feed, 11 absent.

## Top gaps

1. **Descriptions are not applied atomically and rollback is incomplete** (webrtc-pc 4.4.1.4; L). A remote description that fails late leaves the new signaling state, the pending description and new transceivers in place; rollback is refused from the "other" method and restores neither codecs, SCTP transport, encodings nor remote tracks.
2. **Sender / receiver / transceiver object model** (webrtc-pc 5.1 to 5.4; L). A transceiver without a track has no sender and one without a receive direction has no receiver; `remove_track` drops the sender; `get_senders` / `get_receivers` filter on direction; no stopping / stopped split, no "stopped" direction value.
3. **Remote tracks are announced by media, not by the description** (webrtc-pc 5.1.1, 9.3; L). The track event fires on the first RTP packet; the engine never mutes a track; an RTCP BYE ends it.
4. **State, events and error detail an API layer cannot get** (webrtc-pc 4.3, 5.5, 5.6, 11, 12; M). No getters for signaling / ICE connection / connection state, no icecandidateerror, no end-of-candidates, no DTLS or SCTP state-change or error events, no selected-candidate-pair-change event, and `OnError` carries no errorDetail, SCTP cause code, DTLS alert or SDP line number.
5. **Statistics that report a wrong value** (webrtc-stats; M). `remoteTimestamp` is the local clock, `active` is always true, `dataChannelsClosed` counts channels that never opened, peer-reflexive remote candidate addresses are exposed, `firCount` / `pliCount` appear on audio, `retransmitted*Received` without RTX, `packetsSent` excludes RTX retransmissions, header bytes exclude padding, transport bytes include STUN, a recycled SSRC reuses the deleted object's id.
6. **Data channel creation and send() checks** (webrtc-pc 6.1, 6.2; M). No label length check; id 65535, a duplicate negotiated id and an id at or above maxChannels are accepted; one unassignable id fails every pending channel; `send()` gates on "has a stream", not on readyState.
7. **No SFrame, no SFrame packetization** (RFC 9605, encoded-transform 2.1 and 3; L). Nothing in any crate; the codec payloaders parse payloads, so an application's own encrypted frames have no format-agnostic packetizer either.
8. **No SVC** (webrtc-svc; M for the parameter and validation, L for layered packetization). `scalabilityMode` is not an encoding parameter; VP8 / VP9 payloaders write no layer fields; no AV1 dependency descriptor.
9. **Header extension control, ICE pair control, capture time** (webrtc-extensions 4, 7, 8; M, L, M). The to-negotiate list is URIs without directions and without the four validation errors; no candidate-pair events, `selectCandidatePair` or `removeCandidatePair`; no abs-capture-time.
10. **DTMF and media priority** (webrtc-pc 7; webrtc-priority 3; L, M). `RTCDTMFSender` is absent (25 rows); encodings have no `priority` / `networkPriority`, and `TransportContext` has no DSCP hint for the socket layer.

Smaller packages, each with row ids and a size, are in the per-spec files: remote-driven simulcast, negotiation-needed and ICE restart bookkeeping, `getContributingSources` / `getSynchronizationSources` and `jitterBufferTarget`, capabilities and the codec match, `set_configuration` atomicity, certificates, `MediaStream::new` and `active`.

## Bugs found

Counted per file: webrtc-pc 35 (13 + 13 + 9), webrtc-stats 10, webrtc-extensions 2, mediacapture-main 2, the others none. Each has a reproduction idea in its file. Two contradict a row of the existing claims:

- `docs/conformance/w2.md` says a remote description that fails to apply leaves the signaling state as it was; a remote offer without `a=ice-ufrag` returns an error but leaves have-remote-offer (webrtc-pc, sections 1 to 4, B1).
- `docs/conformance/w5.md` says no member the engine cannot measure is reported; `packetsDiscardedOnSend`, `bytesDiscardedOnSend`, `active`, and `firCount` / `pliCount` on audio are written with nothing measured behind them (webrtc-stats, gaps 1 and 2).

## Not finished, and limits

- Every section of the eight specs in scope has rows. mediacapture-main is audited for section 4 only (the MediaStream / MediaStreamTrack model webrtc-pc depends on); capture, devices and the constraint-selection algorithm are not enumerated.
- webrtc-encoded-transform and RFC 9605 are at feature level, as the scope asked: JS stream and worker steps are one `n/a` row each, not one row per step.
- Nothing was run. In webrtc-pc sections 5 and 6 to 12, some `tested` verdicts rest on a test's name and location rather than a full read of its body; in webrtc-stats, several `Code` cells for members point at the accumulator method or the struct field, with line numbers taken from a listing with comments stripped, so they can be off by a few lines.
- About forty dictionary and enum rows of webrtc-pc section 5, and the `missing` rows of the smaller specs, cite the file where the item would live (`:1`) because there is no statement to cite.
- ICE transport state semantics (webrtc-pc 5.6.4) were judged for their mapping onto the API only; the ICE auditor owns the state machine.
