# W3C WebRTC (webrtc-pc): clause-level audit

Spec: WebRTC: Real-Time Communication in Browsers, W3C Editor's Draft at https://w3c.github.io/webrtc-pc/ (served copy last modified 12 November 2026, candidate amendments included). Engine: fork master 8916bc3.

Section numbers: the draft numbers its sections when rendered; this file uses the numbering of the published Recommendation's structure, which the draft's headings follow: 4.2 Configuration, 4.3 State definitions, 4.4.1 Operation (4.4.1.1 constructor, 4.4.1.2 operations chain, 4.4.1.3 update the connection state, 4.4.1.4 set the session description, 4.4.1.5 set the configuration), 4.4.2 Interface definition, 4.4.3 Legacy extensions, 4.5 Error handling, 4.6 Session description model, 4.7 Session negotiation model, 4.8 ICE interfaces, 4.9 Certificates, 5.1 to 5.7 RTP media API, 6.1 to 6.4 Data API, 7.1 to 7.4 DTMF, 8.1 to 8.6 Statistics model, 9 Media stream extensions, 11 Error handling, 12 Event summary. Under 4.4.2 and other interface sections, a row's paraphrase starts with the method or algorithm it belongs to.

How rows were judged. The engine is sans-I/O Rust under a JS API layer: promises, task queuing, garbage collection, WebIDL conversion and serialization are `n/a`; the behaviour behind them (state checks, ordering, errors, events an API layer has to be told about, data it has to be able to read) is judged. Algorithm steps, members, attributes and enum values are MUST-level unless the text says should or may. The audit was done in three passes (sections 1 to 4, 5, 6 to 12) by reading code and tests; nothing was run. Some `tested` verdicts in sections 5 and 6 to 12 rest on the name and location of a test rather than a full read of its body, and about forty dictionary and enum rows of section 5 cite a declaration line (or `:1`) rather than a statement; the per-pass limits are at the end. Member-by-member statistics are in `w3c-webrtc-stats.md`; section 8.6 here judges presence only.

Totals (rows 957):

- MUST: tested 382 / untested 157 / partial 152 / missing 149 / violated 27 / n-a 62
- SHOULD: tested 2 / untested 0 / partial 2 / missing 1 / violated 0 / n-a 5
- MAY: tested 2 / untested 2 / partial 1 / missing 1 / violated 0 / n-a 12

By pass:

- sections 1 to 4: rows 399; MUST: tested 151 / untested 67 / partial 72 / missing 50 / violated 7 / n-a 35
- section 5: rows 258; MUST: tested 81 / untested 50 / partial 46 / missing 43 / violated 16 / n-a 14
- sections 6 to 12: rows 300; MUST: tested 150 / untested 40 / partial 34 / missing 56 / violated 4 / n-a 13

| ID | § | Level | Clause (short paraphrase) | Verdict | Code | Test | Note |
|---|---|---|---|---|---|---|---|
| WEBRTC-1-1 | 1 | MUST | ECMAScript implementations follow the WebIDL ECMAScript bindings | n/a | | | JS binding concern |
| WEBRTC-3-1 | 3 | MUST | Values shown to the application are consistent within a task (run-to-completion, no data races) | n/a | | | synchronous `&mut self` API |
| WEBRTC-4.2.1-1 | 4.2.1 | MUST | RTCConfiguration.iceServers, default empty list | tested | src/peer_connection/configuration/mod.rs:262 | test_set_get_configuration | |
| WEBRTC-4.2.1-2 | 4.2.1 | MUST | ICE servers above an implementation limit are ignored; the limit is at least 32 | untested | src/peer_connection/configuration/mod.rs:262 | | no cap at all, so the minimum holds; nothing asserts 32+ servers |
| WEBRTC-4.2.1-3 | 4.2.1 | MUST | iceTransportPolicy member, default "all" | partial | src/peer_connection/configuration/mod.rs:266 | test_configuration_json_partial_deserialize | default is `Unspecified` (acts as all); serialises as "Unspecified", not "all" |
| WEBRTC-4.2.1-4 | 4.2.1 | MUST | bundlePolicy member, default "balanced" | partial | src/peer_connection/configuration/mod.rs:270 | test_configuration_json_partial_deserialize | default is `Unspecified`; every value behaves as max-bundle (decision D2) |
| WEBRTC-4.2.1-5 | 4.2.1 | MUST | rtcpMuxPolicy member, default "require" | partial | src/peer_connection/configuration/mod.rs:274 | test_configuration_json_partial_deserialize | default is `Unspecified`; the policy is stored, never enforced |
| WEBRTC-4.2.1-6 | 4.2.1 | MUST | certificates member: certificates the connection authenticates with | tested | src/peer_connection/internal.rs:152 | descriptions_offer_trickle_and_a_fingerprint_per_certificate | |
| WEBRTC-4.2.1-7 | 4.2.1 | MUST | With several certificates the implementation selects the one used for a connection | untested | src/peer_connection/transport/dtls/mod.rs:125 | | every fingerprint is offered; no test shows which certificate the handshake presents |
| WEBRTC-4.2.1-8 | 4.2.1 | MUST | Absent certificates: a default set is generated per connection | tested | src/peer_connection/transport/dtls/mod.rs:133 | test_offer_answer_rtc_to_rtc | |
| WEBRTC-4.2.1-9 | 4.2.1 | MUST | The certificates value cannot change after it is first selected | partial | src/peer_connection/mod.rs:2224 | | see 4.4.1.5-1 and 4.4.1.5-2 |
| WEBRTC-4.2.1-10 | 4.2.1 | MUST | iceCandidatePoolSize member (octet, default 0): size of the prefetched ICE pool | untested | src/peer_connection/configuration/mod.rs:289 | | stored and returned only; pooling itself is the application's gathering |
| WEBRTC-4.2.1-11 | 4.2.1 | MUST | No member outside the dictionary changes behaviour (peerIdentity was removed from the spec) | untested | src/peer_connection/configuration/mod.rs:279 | | extra `peer_identity` member kept; stored, compared in set_configuration, otherwise unused |
| WEBRTC-4.2.2-1 | 4.2.2 | MUST | RTCIceServer.urls: one or more STUN/TURN URIs (RFC 7064/7065) | tested | src/peer_connection/transport/ice/server.rs:17 | test_ice_server_validate_success | |
| WEBRTC-4.2.2-2 | 4.2.2 | MUST | RTCIceServer.username: username for a TURN server | tested | src/peer_connection/transport/ice/server.rs:54 | test_ice_server_validate_failure | |
| WEBRTC-4.2.2-3 | 4.2.2 | MUST | RTCIceServer.credential: long-term password (RFC 5389 10.2) | tested | src/peer_connection/transport/ice/server.rs:55 | test_ice_server_validate_failure | |
| WEBRTC-4.2.3-1 | 4.2.3 | MUST | "relay": the ICE agent uses only relay candidates | tested | src/peer_connection/internal.rs:77 | a_relay_policy_set_later_reaches_the_agent | |
| WEBRTC-4.2.3-2 | 4.2.3 | MUST | "all": the ICE agent may use any candidate type | tested | src/peer_connection/mod.rs:2258 | an_all_policy_set_later_lifts_relay | |
| WEBRTC-4.2.3-3 | 4.2.3 | MUST | Only candidates the policy permits are surfaced and used for connectivity checks | partial | src/peer_connection/mod.rs:2121 | a_relay_policy_set_later_reaches_the_agent | the agent filters; whether a filtered local candidate still raises OnIceCandidateEvent is not tested |
| WEBRTC-4.2.4-1 | 4.2.4 | MUST | "balanced": one transport per media type when the remote is not bundle-aware | missing | src/peer_connection/configuration/mod.rs:270 | | D2: one transport only; behaves as max-bundle |
| WEBRTC-4.2.4-2 | 4.2.4 | MUST | "max-compat": one transport per track when the remote is not bundle-aware | missing | src/peer_connection/configuration/mod.rs:270 | | D2: one transport only |
| WEBRTC-4.2.4-3 | 4.2.4 | MUST | "max-bundle": gather for one track; negotiate one media track if the remote is not bundle-aware | untested | src/peer_connection/internal.rs:531 | | D2 promises a defined error for a remote offer without BUNDLE; no test or error variant found |
| WEBRTC-4.2.4-4 | 4.2.4 | MUST | A bundle-aware remote gets all media and data on one transport | tested | src/peer_connection/sdp/mod.rs:1461 | test_offer_answer_rtc_to_rtc | |
| WEBRTC-4.2.5-1 | 4.2.5 | MUST | "require": gather for RTP only and multiplex RTCP on it | tested | src/peer_connection/configuration/rtcp_mux_policy.rs:66 | test_populate_sdp | every generated section carries a=rtcp-mux |
| WEBRTC-4.2.5-2 | 4.2.5 | MUST | Under "require", negotiation fails when the remote cannot rtcp-mux | missing | src/peer_connection/mod.rs:1417 | | no check for a=rtcp-mux in a remote description; see 4.4.1.4-9 |
| WEBRTC-4.2.5-3 | 4.2.5 | MUST | "require" is the only value of the enum | violated | src/peer_connection/configuration/rtcp_mux_policy.rs:53 | test_new_rtcp_mux_policy | `Negotiate` is accepted and silently behaves as require |
| WEBRTC-4.2.6-1 | 4.2.6 | MUST | iceRestart true, or pending credentials to replace: the offer has new ICE credentials | tested | src/peer_connection/mod.rs:825 | ice_restart_offer_carries_no_previous_candidates | also data_flows_at_every_step_of_an_ice_restart |
| WEBRTC-4.2.6-2 | 4.2.6 | MUST | Applying such an offer restarts ICE | tested | src/peer_connection/mod.rs:1208 | data_flows_at_every_step_of_an_ice_restart | |
| WEBRTC-4.2.6-3 | 4.2.6 | MUST | iceRestart false and nothing pending: the offer keeps the current local description's credentials | untested | src/peer_connection/internal.rs:269 | | no test compares ufrag/pwd of two successive offers |
| WEBRTC-4.2.6-4 | 4.2.6 | MUST | RTCAnswerOptions has no members | untested | src/peer_connection/configuration/offer_answer_options.rs:16 | | extra `voice_activity_detection` member, ignored by create_answer |
| WEBRTC-4.3.1-1 | 4.3.1 | MUST | "stable": no exchange in progress; the initial state | tested | src/peer_connection/internal.rs:214 | sections_without_ssrc_lines_are_answered | |
| WEBRTC-4.3.1-2 | 4.3.1 | MUST | "have-local-offer": a local offer was applied | tested | src/peer_connection/state/signaling_state.rs:325 | polite_peer_glare_recovery_with_local_offer_rollback | |
| WEBRTC-4.3.1-3 | 4.3.1 | MUST | "have-remote-offer": a remote offer was applied | tested | src/peer_connection/state/signaling_state.rs:331 | a_remote_offer_can_be_applied_again_and_rolled_back | |
| WEBRTC-4.3.1-4 | 4.3.1 | MUST | "have-local-pranswer": remote offer then local pranswer applied | tested | src/peer_connection/state/signaling_state.rs:388 | provisional_answers_repeat_and_keep_the_offerer_controlling | |
| WEBRTC-4.3.1-5 | 4.3.1 | MUST | "have-remote-pranswer": local offer then remote pranswer applied | tested | src/peer_connection/state/signaling_state.rs:345 | provisional_answers_repeat_and_keep_the_offerer_controlling | |
| WEBRTC-4.3.1-6 | 4.3.1 | MUST | "closed": the connection is closed | tested | src/peer_connection/handler/mod.rs:538 | close_transitions_to_closed_state | |
| WEBRTC-4.3.2-1 | 4.3.2 | MUST | iceGatheringState "new": no transport gathering, or no transports | tested | src/peer_connection/transport/ice/mod.rs:108 | gathering_state_reports_the_tracked_field | accessor test only; the initial value is the field default |
| WEBRTC-4.3.2-2 | 4.3.2 | MUST | "gathering": any transport is gathering | partial | src/peer_connection/mod.rs:1319 | | set on every successful set_local_description (rollback included, even after "complete"); no event for it |
| WEBRTC-4.3.2-3 | 4.3.2 | MUST | "complete": a transport exists and all have finished gathering | untested | src/peer_connection/mod.rs:2130 | | set when the application adds an empty local candidate; no test drives it |
| WEBRTC-4.3.2-4 | 4.3.2 | MUST | The state aggregates the transports the transceivers and SCTP transport reference | n/a | | | one bundled transport (D2) |
| WEBRTC-4.3.3-1 | 4.3.3 | MUST | connectionState "closed" when the ICE connection state is closed | tested | src/peer_connection/internal.rs:1338 | test_peer_connection_state | |
| WEBRTC-4.3.3-2 | 4.3.3 | MUST | "failed": ICE failed or any DTLS transport failed | tested | src/peer_connection/internal.rs:1340 | a_fingerprint_mismatch_fails_the_dtls_transport_and_the_connection | also test_peer_connection_state |
| WEBRTC-4.3.3-3 | 4.3.3 | MUST | "disconnected": ICE disconnected and no earlier state applies | tested | src/peer_connection/internal.rs:1343 | test_peer_connection_state | |
| WEBRTC-4.3.3-4 | 4.3.3 | MUST | "new": ICE new and all DTLS transports new or closed, or no transports | tested | src/peer_connection/internal.rs:1347 | test_peer_connection_state | initial value asserted only |
| WEBRTC-4.3.3-5 | 4.3.3 | MUST | "connected": ICE connected and all DTLS transports connected or closed | tested | src/peer_connection/internal.rs:1357 | test_peer_connection_state | |
| WEBRTC-4.3.3-6 | 4.3.3 | MUST | "connecting": none of the other states apply | partial | src/peer_connection/internal.rs:1352 | test_peer_connection_state | the final `else` yields `New`, not connecting (e.g. ICE closed with DTLS connecting) |
| WEBRTC-4.3.4-1 | 4.3.4 | MUST | iceConnectionState "closed" once the connection is closed | untested | src/peer_connection/handler/mod.rs:531 | | close() sets signaling and connection state; the ICE connection state field is only updated when an agent event is polled |
| WEBRTC-4.3.4-2 | 4.3.4 | MUST | "failed": any ICE transport failed | untested | src/peer_connection/handler/ice.rs:202 | | mapped from the agent; no engine-level test reaches Failed (tests only abort on it) |
| WEBRTC-4.3.4-3 | 4.3.4 | MUST | "disconnected": any ICE transport disconnected | untested | src/peer_connection/handler/ice.rs:202 | | |
| WEBRTC-4.3.4-4 | 4.3.4 | MUST | "new": all transports new or closed, or none | untested | src/peer_connection/transport/ice/mod.rs:41 | | |
| WEBRTC-4.3.4-5 | 4.3.4 | MUST | "checking": any transport new or checking | untested | src/peer_connection/handler/ice.rs:202 | | |
| WEBRTC-4.3.4-6 | 4.3.4 | MUST | "completed": all transports completed or closed | untested | src/peer_connection/handler/ice.rs:202 | | |
| WEBRTC-4.3.4-7 | 4.3.4 | MUST | "connected": all transports connected, completed or closed | tested | src/peer_connection/handler/ice.rs:202 | test_media_only_negotiation_does_not_start_sctp | |
| WEBRTC-4.3.4-8 | 4.3.4 | MUST | The state may jump when a transport is discarded or created by signaling | n/a | | | one transport |
| WEBRTC-4.4.1-1 | 4.4.1 | MAY | A TURN server may also be used as a STUN server for server-reflexive candidates | n/a | | | application gathers candidates |
| WEBRTC-4.4.1-2 | 4.4.1 | MUST | The five description slots change only in setLocal/setRemoteDescription, addIceCandidate and candidate surfacing | untested | src/peer_connection/internal.rs:671 | | holds by construction; no test |
| WEBRTC-4.4.1-3 | 4.4.1 | MUST | All description-slot changes complete before any event fires | untested | src/peer_connection/internal.rs:836 | | events are queued and polled after the call returns |
| WEBRTC-4.4.1-4 | 4.4.1 | MUST | Document unload closes every connection of the window | n/a | | | browser lifecycle |
| WEBRTC-4.4.1.1-1 | 4.4.1.1 | MUST | A construction step failing for an unspecified reason throws UnknownError | n/a | | | error-class mapping is the binding's; build() returns the engine error |
| WEBRTC-4.4.1.1-2 | 4.4.1.1 | MUST | [[DocumentOrigin]] slot | n/a | | | origins are a browser concept |
| WEBRTC-4.4.1.1-3 | 4.4.1.1 | MUST | A configured certificate whose expires is in the past throws InvalidAccessError | untested | src/peer_connection/configuration/mod.rs:401 | | ErrCertificateExpired is asserted by no test |
| WEBRTC-4.4.1.1-4 | 4.4.1.1 | MUST | A certificate of another origin throws InvalidAccessError | n/a | | | origins are a browser concept |
| WEBRTC-4.4.1.1-5 | 4.4.1.1 | MUST | Configured certificates are stored | tested | src/peer_connection/internal.rs:152 | descriptions_offer_trickle_and_a_fingerprint_per_certificate | moved out of the configuration: get_configuration() then reports none (bug B4) |
| WEBRTC-4.4.1.1-6 | 4.4.1.1 | MUST | Otherwise generate one or more certificates for this connection | tested | src/peer_connection/transport/dtls/mod.rs:133 | test_offer_answer_rtc_to_rtc | |
| WEBRTC-4.4.1.1-7 | 4.4.1.1 | MAY | Default certificate generation may happen asynchronously | n/a | | | generated synchronously in build() |
| WEBRTC-4.4.1.1-8 | 4.4.1.1 | MUST | Initialize the connection's ICE agent | tested | src/peer_connection/internal.rs:148 | test_offer_answer_rtc_to_rtc | |
| WEBRTC-4.4.1.1-9 | 4.4.1.1 | MUST | [[Configuration]] is set through "set the configuration" (all its validation runs) | partial | src/peer_connection/internal.rs:49 | test_configuration_validate_relay_policy | constructor validation differs from set_configuration: stun queries are stripped, see 4.4.1.5 rows |
| WEBRTC-4.4.1.1-10 | 4.4.1.1 | MUST | [[IsClosed]] starts false | tested | src/peer_connection/internal.rs:215 | close_transitions_to_closed_state | represented by the Closed connection state |
| WEBRTC-4.4.1.1-11 | 4.4.1.1 | MUST | [[NegotiationNeeded]] starts false | untested | src/peer_connection/internal.rs:229 | | `is_negotiation_ongoing` |
| WEBRTC-4.4.1.1-12 | 4.4.1.1 | MUST | [[SctpTransport]] starts null | tested | src/peer_connection/mod.rs:2875 | sctp_is_none_until_sctp_is_negotiated | |
| WEBRTC-4.4.1.1-13 | 4.4.1.1 | MUST | [[LastStableStateSctpTransport]] slot, initially null | missing | | | no such state; see 4.4.1.4-16 |
| WEBRTC-4.4.1.1-14 | 4.4.1.1 | MUST | [[DataChannels]] starts as an empty ordered set | untested | src/peer_connection/internal.rs:219 | | |
| WEBRTC-4.4.1.1-15 | 4.4.1.1 | MUST | [[Operations]] chain starts empty | n/a | | | synchronous API, no chain |
| WEBRTC-4.4.1.1-16 | 4.4.1.1 | MUST | [[UpdateNegotiationNeededFlagOnEmptyChain]] starts false | n/a | | | synchronous API, no chain |
| WEBRTC-4.4.1.1-17 | 4.4.1.1 | MUST | [[LastCreatedOffer]] and [[LastCreatedAnswer]] start as "" | untested | src/peer_connection/internal.rs:224 | | |
| WEBRTC-4.4.1.1-18 | 4.4.1.1 | MUST | [[EarlyCandidates]] starts empty | n/a | | | application gathers; no queue |
| WEBRTC-4.4.1.1-19 | 4.4.1.1 | MUST | [[SignalingState]] starts "stable" | tested | src/peer_connection/internal.rs:214 | test_signaling_state_transitions | first transitions only succeed from stable |
| WEBRTC-4.4.1.1-20 | 4.4.1.1 | MUST | [[IceConnectionState]] starts "new" | untested | src/peer_connection/transport/ice/mod.rs:41 | | |
| WEBRTC-4.4.1.1-21 | 4.4.1.1 | MUST | [[IceGatheringState]] starts "new" | tested | src/peer_connection/transport/ice/mod.rs:108 | gathering_state_reports_the_tracked_field | |
| WEBRTC-4.4.1.1-22 | 4.4.1.1 | MUST | [[ConnectionState]] starts "new" | tested | src/peer_connection/internal.rs:215 | test_peer_connection_state | |
| WEBRTC-4.4.1.1-23 | 4.4.1.1 | MUST | Pending and current local and remote descriptions start null | untested | src/peer_connection/internal.rs:208 | | |
| WEBRTC-4.4.1.1-24 | 4.4.1.1 | MUST | [[LocalIceCredentialsToReplace]] starts as an empty set | partial | src/peer_connection/internal.rs:226 | | modelled as one `ice_restart_requested` flag, not a credential set |
| WEBRTC-4.4.1.2-1 | 4.4.1.2 | MUST | Chaining on a closed connection rejects with InvalidStateError | partial | src/peer_connection/mod.rs:818 | | create_offer, create_answer, set_*_description check closed; add_remote_candidate does not; none is tested |
| WEBRTC-4.4.1.2-2 | 4.4.1.2 | MUST | Only one chained operation runs at a time; later ones wait for earlier promises | n/a | | | synchronous `&mut self` calls |
| WEBRTC-4.4.1.2-3 | 4.4.1.2 | MUST | Results of an operation are dropped if the connection closed meanwhile | n/a | | | synchronous API |
| WEBRTC-4.4.1.2-4 | 4.4.1.2 | MUST | When the chain empties and the deferred flag is set, update the negotiation-needed flag | n/a | | | no chain; the check runs at once or on reaching stable |
| WEBRTC-4.4.1.3-1 | 4.4.1.3 | MUST | A DTLS transport state change re-derives the connection state | partial | src/peer_connection/handler/mod.rs:397 | a_fingerprint_mismatch_fails_the_dtls_transport_and_the_connection | re-derived on DTLS handshake complete, closed and ICE changes; the new to connecting DTLS transition has no trigger of its own |
| WEBRTC-4.4.1.3-2 | 4.4.1.3 | MUST | No update once the connection is closed | tested | src/peer_connection/internal.rs:1332 | close_is_idempotent | |
| WEBRTC-4.4.1.3-3 | 4.4.1.3 | MUST | No event when the derived state equals the current one | untested | src/peer_connection/internal.rs:1366 | | |
| WEBRTC-4.4.1.3-4 | 4.4.1.3 | MUST | Otherwise set [[ConnectionState]] and fire connectionstatechange | tested | src/peer_connection/internal.rs:1371 | a_fingerprint_mismatch_fails_the_dtls_transport_and_the_connection | |
| WEBRTC-4.4.1.4-1 | 4.4.1.4 | MUST | rollback in stable, have-local-pranswer or have-remote-pranswer rejects with InvalidStateError | tested | src/peer_connection/state/signaling_state.rs:315 | `pc/set_description_atomic_test.rs::a_rollback_is_refused_outside_the_offer_states` | `ErrSignalingStateCannotRollback` in stable, `ErrSignalingStateProposedTransitionInvalid` in the pranswer states, through either method |
| WEBRTC-4.4.1.4-2 | 4.4.1.4 | MUST | Apply against a snapshot of the transceiver set, using [[JsepMid]] as the mid | n/a | | | no in-parallel section |
| WEBRTC-4.4.1.4-3 | 4.4.1.4 | MUST | Local description: never gather from administratively prohibited sources | n/a | | | application gathers candidates |
| WEBRTC-4.4.1.4-4 | 4.4.1.4 | MUST | Remote description: never check connectivity to administratively prohibited candidates | partial | src/peer_connection/internal.rs:118 | | loopback / link-local / `remote_address_filter` options exist; no bad-port list (see 4.4.2-64) |
| WEBRTC-4.4.1.4-5 | 4.4.1.4 | MUST | Back-to-back remote offers are validated as if answers had been applied in between | tested | src/peer_connection/state/signaling_state.rs:393 | a_remote_offer_can_be_applied_again_and_rolled_back | |
| WEBRTC-4.4.1.4-6 | 4.4.1.4 | MUST | On failure, nothing is reported if the connection closed meanwhile | n/a | | | synchronous API |
| WEBRTC-4.4.1.4-7 | 4.4.1.4 | MUST | A type invalid for the signaling state rejects with InvalidStateError | tested | src/peer_connection/state/signaling_state.rs:308 | test_signaling_state_transitions | |
| WEBRTC-4.4.1.4-8 | 4.4.1.4 | MUST | An SDP parse failure rejects with RTCError sdp-syntax-error carrying sdpLineNumber | partial | src/peer_connection/mod.rs:1433 | | the parse error is returned; no line number is available to the API layer |
| WEBRTC-4.4.1.4-9 | 4.4.1.4 | MUST | Remote description without rtcp-mux under policy "require" rejects with InvalidAccessError | missing | src/peer_connection/mod.rs:1417 | | a=rtcp-mux is never checked |
| WEBRTC-4.4.1.4-10 | 4.4.1.4 | MUST | A description that renegotiates RIDs rejects with InvalidAccessError | missing | src/peer_connection/mod.rs:1417 | | no comparison with previously negotiated rids |
| WEBRTC-4.4.1.4-11 | 4.4.1.4 | MUST | A description failing RFC 9429 5.8.3 semantic validation rejects with InvalidAccessError | partial | src/peer_connection/mod.rs:1709 | extract_ice_details_checks_the_credentials_syntax | ICE credentials, candidates, fingerprints, mids and the answer-against-offer checks run before anything changes (`check_remote_description`); the rtcp-mux, rid and tls-id checks of RFC 9429 5.8.3 do not exist yet |
| WEBRTC-4.4.1.4-12 | 4.4.1.4 | MUST | Any other failure rejects with OperationError | n/a | | | error-class mapping is the binding's |
| WEBRTC-4.4.1.4-13 | 4.4.1.4 | MUST | A failed application leaves the connection as it was | tested | pc/mod.rs `check_remote_description`, `check_local_answer`; pc/internal.rs `description_snapshot` | `pc/set_description_atomic_test.rs`, `pc/set_remote_description_test.rs` | every check precedes the first change; a staged ICE restart is applied after validation; transport failures restore the description state |
| WEBRTC-4.4.1.4-14 | 4.4.1.4 | MUST | On success, nothing happens if the connection closed meanwhile | n/a | | | synchronous API |
| WEBRTC-4.4.1.4-15 | 4.4.1.4 | MUST | Remote offer: restart the process if addTrack succeeded while it was being applied | n/a | | | no interleaving possible |
| WEBRTC-4.4.1.4-16 | 4.4.1.4 | MUST | Restart the process while setParameters promises are unsettled | n/a | | | no interleaving possible |
| WEBRTC-4.4.1.4-17 | 4.4.1.4 | MUST | Offer applied in stable: remember [[SctpTransport]] as the last stable one | tested |  | `tests/jsep_rollback.rs::a_rollback_leaves_the_sctp_transport_of_the_last_stable_state` | an offer never creates or changes the SCTP transport here (an answer does), so the last stable one is the one in place |
| WEBRTC-4.4.1.4-18 | 4.4.1.4 | MUST | Offer in stable: remember each sender's and receiver's transport | untested | src/peer_connection/internal.rs:1005 | | transport presence follows the mid; disassociation on rollback undoes it, untested for the transport accessor |
| WEBRTC-4.4.1.4-19 | 4.4.1.4 | MUST | Offer in stable: remember a lone rid-less encoding as [[LastStableRidlessSendEncodings]] | missing | | | |
| WEBRTC-4.4.1.4-20 | 4.4.1.4 | MUST | Offer in stable: remember each receiver's associated remote streams | partial |  | `tests/jsep_rollback.rs::a_rollback_leaves_the_remote_track_of_the_last_stable_state` | not remembered separately: remote tracks are set up when an answer is applied (see 4.4.1.4-61), so an offer changes none |
| WEBRTC-4.4.1.4-21 | 4.4.1.4 | MUST | Offer in stable: remember each receiver's [[ReceiveCodecs]] | tested | pc/internal.rs `commit_description` (`LastStableState`) | `tests/jsep_rollback.rs::a_rollback_restores_the_codecs_and_repair_flows_a_remote_offer_took` | the negotiated media engine and every transceiver are copied when an offer is applied in stable |
| WEBRTC-4.4.1.4-22 | 4.4.1.4 | MUST | Local offer: set [[PendingLocalDescription]], state have-local-offer | tested | src/peer_connection/internal.rs:700 | polite_peer_glare_recovery_with_local_offer_rollback | |
| WEBRTC-4.4.1.4-23 | 4.4.1.4 | MUST | Local offer, answer or pranswer: release early candidates | n/a | | | application gathers; no early-candidate queue |
| WEBRTC-4.4.1.4-24 | 4.4.1.4 | MUST | Local answer: current local = description, current remote = pending remote, both pending null | tested | src/peer_connection/internal.rs:718 | sections_without_ssrc_lines_are_answered | |
| WEBRTC-4.4.1.4-25 | 4.4.1.4 | MUST | Local answer: reset [[LastCreatedOffer]] and [[LastCreatedAnswer]] to "" | tested | pc/internal.rs `commit_description` | `pc/set_description_atomic_test.rs::an_answer_resets_the_last_created_offer_and_answer` |  |
| WEBRTC-4.4.1.4-26 | 4.4.1.4 | MUST | Local answer: signaling state becomes stable | tested | src/peer_connection/state/signaling_state.rs:381 | sections_without_ssrc_lines_are_answered | |
| WEBRTC-4.4.1.4-27 | 4.4.1.4 | MUST | Local answer: empty [[LocalIceCredentialsToReplace]] when none of them is in the description | partial | src/peer_connection/mod.rs:825 | | the restart request is consumed by create_offer, not when an answer replaces the credentials; a discarded restart offer loses the request |
| WEBRTC-4.4.1.4-28 | 4.4.1.4 | MUST | Local pranswer: set [[PendingLocalDescription]], state have-local-pranswer | tested | src/peer_connection/internal.rs:757 | provisional_answers_repeat_and_keep_the_offerer_controlling | |
| WEBRTC-4.4.1.4-29 | 4.4.1.4 | MUST | Remote offer: set [[PendingRemoteDescription]], state have-remote-offer | tested | src/peer_connection/internal.rs:776 | glare_recovery_with_remote_offer_rollback | |
| WEBRTC-4.4.1.4-30 | 4.4.1.4 | MUST | Remote answer: current remote = description, current local = pending local, both pending null, state stable | tested | src/peer_connection/internal.rs:790 | provisional_answers_repeat_and_keep_the_offerer_controlling | |
| WEBRTC-4.4.1.4-31 | 4.4.1.4 | MUST | Remote answer: reset [[LastCreatedOffer]] and [[LastCreatedAnswer]] to "" | tested | pc/internal.rs `commit_description` | `pc/set_description_atomic_test.rs::an_answer_resets_the_last_created_offer_and_answer` |  |
| WEBRTC-4.4.1.4-32 | 4.4.1.4 | MUST | Remote answer: empty [[LocalIceCredentialsToReplace]] when none is in the new current local description | partial | src/peer_connection/mod.rs:825 | | as 4.4.1.4-27 |
| WEBRTC-4.4.1.4-33 | 4.4.1.4 | MUST | Remote pranswer: set [[PendingRemoteDescription]], state have-remote-pranswer | tested | src/peer_connection/internal.rs:826 | provisional_answers_repeat_and_keep_the_offerer_controlling | |
| WEBRTC-4.4.1.4-34 | 4.4.1.4 | MUST | Offer describing an SCTP association with no [[SctpTransport]]: create one in "connecting" | partial | src/peer_connection/mod.rs:2875 | sctp_is_none_until_sctp_is_negotiated | the transport is exposed once negotiated, not when the offer is applied |
| WEBRTC-4.4.1.4-35 | 4.4.1.4 | MUST | Answer that closes the SCTP association: [[SctpTransport]] becomes null | partial | src/peer_connection/mod.rs:1286 | | no code found resetting the SCTP transport when an answer rejects the data section |
| WEBRTC-4.4.1.4-36 | 4.4.1.4 | MUST | Answer or pranswer: update the data max message size of the SCTP transport | partial | src/peer_connection/mod.rs:1293 | max_message_size_with_no_configured_limit_reports_the_ceiling | done when a final answer starts SCTP; not on pranswer, not re-evaluated on renegotiation |
| WEBRTC-4.4.1.4-37 | 4.4.1.4 | MUST | Answer or pranswer fixing the DTLS role: give every id-less data channel an id (RFC 8832) | tested | src/peer_connection/mod.rs:2151 | answer_assigns_data_channel_ids_by_dtls_role | |
| WEBRTC-4.4.1.4-38 | 4.4.1.4 | MUST | A channel that cannot get an id is closed and reported in errorList | partial | src/peer_connection/mod.rs:2157 | | the failure is logged; no per-channel close or error event here |
| WEBRTC-4.4.1.4-39 | 4.4.1.4 | MUST | Local description, new m= section: set the transceiver's [[Mid]] to [[JsepMid]] | partial | src/peer_connection/mod.rs:880 | set_local_rollback_disassociates_but_keeps_app_created_transceivers | mid() is already set by create_offer, before the description is applied |
| WEBRTC-4.4.1.4-40 | 4.4.1.4 | MUST | Local description: a stopped transceiver gets no transport | untested | src/peer_connection/internal.rs:276 | | |
| WEBRTC-4.4.1.4-41 | 4.4.1.4 | MUST | Local description: sender and receiver get the bundle transport, or a new DTLS/ICE transport | tested | src/peer_connection/mod.rs:2889 | sender_and_receiver_transport_are_none_until_the_transceiver_is_associated | always the one transport |
| WEBRTC-4.4.1.4-42 | 4.4.1.4 | MUST | Local description: [[Receptive]] true for sendrecv/recvonly, false otherwise | partial | src/peer_connection/internal.rs:1215 | | receivers are set up in start_rtp when the answer is applied, not when a local offer is |
| WEBRTC-4.4.1.4-43 | 4.4.1.4 | MUST | Local description: [[ReceiveCodecs]] = codecs negotiated for receiving; empty for sendonly/inactive | untested | src/peer_connection/sdp/mod.rs:1556 | | belongs with getParameters (RTP audit) |
| WEBRTC-4.4.1.4-44 | 4.4.1.4 | MUST | Local answer with several send encodings: all layers missing keeps only the first encoding | missing | src/peer_connection/mod.rs:1234 | | no pruning of send encodings in the set-description path |
| WEBRTC-4.4.1.4-45 | 4.4.1.4 | MUST | Local answer: encodings of layers the description lacks are removed | missing | src/peer_connection/mod.rs:1234 | | |
| WEBRTC-4.4.1.4-46 | 4.4.1.4 | MUST | Local answer: [[SendCodecs]] = codecs negotiated for sending; [[LastReturnedParameters]] null | untested | src/peer_connection/mod.rs:1234 | | not verified here; see the RTP audit |
| WEBRTC-4.4.1.4-47 | 4.4.1.4 | MUST | Local answer no longer receiving: clear the remote streams and process removal of the remote track | partial | src/peer_connection/handler/interceptor.rs:229 | | a track close event exists; not raised from set_local_description on a direction change |
| WEBRTC-4.4.1.4-48 | 4.4.1.4 | MUST | Local answer or pranswer: [[CurrentDirection]] and [[FiredDirection]] = the section's direction | partial | src/peer_connection/mod.rs:1276 | tests/jsep_answer_direction.rs | final answer only; a pranswer sets nothing |
| WEBRTC-4.4.1.4-49 | 4.4.1.4 | MUST | Remote offer asking to receive simulcast: build proposedSendEncodings from the rid order, first alternative only | missing | src/peer_connection/mod.rs:1513 | | a remote offer's a=simulcast recv never becomes send encodings |
| WEBRTC-4.4.1.4-50 | 4.4.1.4 | MUST | proposedSendEncodings: duplicate rids are removed | missing | | | |
| WEBRTC-4.4.1.4-51 | 4.4.1.4 | MUST | proposedSendEncodings truncated to the supported number of encodings | missing | | | |
| WEBRTC-4.4.1.4-52 | 4.4.1.4 | MUST | proposedSendEncodings get scaleResolutionDownBy 2^(n - index - 1) | missing | | | |
| WEBRTC-4.4.1.4-53 | 4.4.1.4 | MUST | Remote description: find an existing transceiver for the m= section as RFC 9429 says | tested | src/peer_connection/mod.rs:1576 | add_track_then_rollback_remote_offer_then_create_offer_includes_track | |
| WEBRTC-4.4.1.4-54 | 4.4.1.4 | MUST | Found transceiver with one rid-less encoding takes proposedSendEncodings | missing | | | |
| WEBRTC-4.4.1.4-55 | 4.4.1.4 | MUST | No transceiver found: create sender, receiver and transceiver and add it to the set | tested | src/peer_connection/mod.rs:1606 | set_remote_rollback_removes_transceivers_created_by_remote_offer | |
| WEBRTC-4.4.1.4-56 | 4.4.1.4 | MUST | The transceiver created for a remote m= section has direction "recvonly" | violated | src/peer_connection/mod.rs:1599 | | created `Sendonly` when the offered section is recvonly |
| WEBRTC-4.4.1.4-57 | 4.4.1.4 | MUST | Remote answer rejecting simulcast or missing all layers: keep only the first send encoding | missing | src/peer_connection/mod.rs:1639 | | |
| WEBRTC-4.4.1.4-58 | 4.4.1.4 | MUST | Remote answer missing some layers: remove those encodings | missing | src/peer_connection/mod.rs:1639 | | |
| WEBRTC-4.4.1.4-59 | 4.4.1.4 | MUST | Remote description: set [[Mid]] to [[JsepMid]] | tested | src/peer_connection/mod.rs:1594 | an_offer_without_mids_numbers_its_sections_by_index | |
| WEBRTC-4.4.1.4-60 | 4.4.1.4 | MUST | Remote description: direction is the section's, reversed; "inactive" if rejected | tested | src/peer_connection/mod.rs:1674 | tests/jsep_answer_direction.rs | |
| WEBRTC-4.4.1.4-61 | 4.4.1.4 | MUST | Remote description: collect the MSIDs for a receiving direction | partial | src/peer_connection/internal.rs:1218 | tests/jsep_add_transceiver.rs | read in start_rtp once an answer is applied, not when a remote offer is |
| WEBRTC-4.4.1.4-62 | 4.4.1.4 | MUST | Remote description: process remote tracks (streams added/removed, track event queued) | partial | src/peer_connection/internal.rs:1224 | tests/jsep_add_transceiver.rs | the remote track is created at the answer and announced on its first RTP packet; no stream add/remove bookkeeping |
| WEBRTC-4.4.1.4-63 | 4.4.1.4 | MUST | Remote description: [[ReceiveCodecs]] = codecs negotiated for receiving | untested | src/peer_connection/mod.rs:1589 | | |
| WEBRTC-4.4.1.4-64 | 4.4.1.4 | MUST | Remote answer or pranswer: [[SendCodecs]] = codecs negotiated for sending | untested | src/peer_connection/mod.rs:1457 | | |
| WEBRTC-4.4.1.4-65 | 4.4.1.4 | MUST | Remote answer or pranswer: [[CurrentDirection]] = direction | partial | src/peer_connection/mod.rs:1682 | tests/jsep_answer_direction.rs | final answer only |
| WEBRTC-4.4.1.4-66 | 4.4.1.4 | MUST | Remote description: sender and receiver transport = the section's DTLS transport | tested | src/peer_connection/mod.rs:2889 | sender_and_receiver_transport_are_none_until_the_transceiver_is_associated | |
| WEBRTC-4.4.1.4-67 | 4.4.1.4 | MUST | [[IceRole]] is not modified once it is not "unknown" | untested | src/peer_connection/mod.rs:1717 | provisional_answers_repeat_and_keep_the_offerer_controlling | the role is recomputed for every remote description that starts or restarts transports |
| WEBRTC-4.4.1.4-68 | 4.4.1.4 | MUST | A local offer sets [[IceRole]] to controlling | partial | src/peer_connection/mod.rs:1717 | provisional_answers_repeat_and_keep_the_offerer_controlling | decided when the remote answer arrives; unknown between the local offer and it |
| WEBRTC-4.4.1.4-69 | 4.4.1.4 | MUST | A remote offer with a=ice-lite sets [[IceRole]] to controlling | untested | src/peer_connection/mod.rs:1719 | | |
| WEBRTC-4.4.1.4-70 | 4.4.1.4 | MUST | A remote offer without a=ice-lite sets [[IceRole]] to controlled | untested | src/peer_connection/mod.rs:1723 | | no test asserts Controlled |
| WEBRTC-4.4.1.4-71 | 4.4.1.4 | MUST | A rejected remote m= section stops its transceiver if not already stopped | tested | src/peer_connection/mod.rs:1532 | a_rejected_section_in_a_remote_offer_stops_its_transceiver | |
| WEBRTC-4.4.1.4-72 | 4.4.1.4 | MUST | Rollback: [[SctpTransport]] returns to the last stable one | tested | src/peer_connection/internal.rs:977 | `tests/jsep_rollback.rs::a_rollback_leaves_the_sctp_transport_of_the_last_stable_state` | as 4.4.1.4-17 |
| WEBRTC-4.4.1.4-73 | 4.4.1.4 | MUST | Rollback: a transceiver the pending description associated is disassociated, mid null | tested | src/peer_connection/internal.rs:999 | set_local_rollback_disassociates_but_keeps_app_created_transceivers | |
| WEBRTC-4.4.1.4-74 | 4.4.1.4 | MUST | Rollback: sender and receiver transports return to the last stable ones | untested | src/peer_connection/internal.rs:1005 | | |
| WEBRTC-4.4.1.4-75 | 4.4.1.4 | MUST | Rollback: restore the rid-less send encodings a remote offer replaced | missing | | | nothing replaces them either (4.4.1.4-54) |
| WEBRTC-4.4.1.4-76 | 4.4.1.4 | MUST | Rollback: [[ReceiveCodecs]] return to the last stable ones | tested | pc/internal.rs `restore_last_stable_state`, src/rtp_transceiver/internal.rs `restore_negotiated_state` | `tests/jsep_rollback.rs::a_rollback_restores_the_codecs_and_repair_flows_a_remote_offer_took`, `tests/jsep_rollback.rs::a_rollback_of_a_renegotiation_restores_the_last_negotiated_codecs` | negotiated codecs and header extensions, each transceiver's codecs, the senders' RTX / FEC flows |
| WEBRTC-4.4.1.4-77 | 4.4.1.4 | MUST | Rollback of a remote offer: process remote tracks with the last stable streams and direction | partial | src/peer_connection/internal.rs:977 | `tests/jsep_rollback.rs::a_rollback_leaves_the_remote_track_of_the_last_stable_state` | nothing to undo: an offer does not process remote tracks here (4.4.1.4-61); the track of the last answer stays |
| WEBRTC-4.4.1.4-78 | 4.4.1.4 | MUST | Rollback: a transceiver the pending description created, never given a track by addTrack, is stopped and removed | tested | src/peer_connection/internal.rs:989 | rollback_keeps_transceiver_with_track_attached_via_add_track | also set_remote_rollback_removes_transceivers_created_by_remote_offer |
| WEBRTC-4.4.1.4-79 | 4.4.1.4 | MUST | Rollback: both pending descriptions null, state stable | tested | src/peer_connection/internal.rs:738 | polite_peer_glare_recovery_with_local_offer_rollback | |
| WEBRTC-4.4.1.4-80 | 4.4.1.4 | MUST | A rollback is valid in have-local-offer and have-remote-offer whichever method carries it | tested | pc/state/signaling_state.rs `check_next_signaling_state` | `tests/jsep_rollback.rs`, `signaling_state.rs::test_signaling_state_transitions` |  |
| WEBRTC-4.4.1.4-81 | 4.4.1.4 | MUST | Answer: remove stopped transceivers whose m= section is rejected in a current description | tested | src/peer_connection/internal.rs:947 | stopped_transceivers_are_removed_once_their_sections_are_rejected | |
| WEBRTC-4.4.1.4-82 | 4.4.1.4 | MUST | Stable: close DTLS and ICE transports no non-stopped transceiver references any more | partial | src/peer_connection/internal.rs:725 | rejects_every_media_section_only_when_all_are_rejected | the single transport is marked closed when every section is rejected; no transport state event |
| WEBRTC-4.4.1.4-83 | 4.4.1.4 | MUST | Stable: remove encoding.codec values that match no entry of [[SendCodecs]] | missing | | | not found in the set-description path |
| WEBRTC-4.4.1.4-84 | 4.4.1.4 | MUST | Stable: clear the negotiation-needed flag and update it | tested | src/peer_connection/internal.rs:841 | stop_raises_negotiation_needed_and_settles_once_rejected | |
| WEBRTC-4.4.1.4-85 | 4.4.1.4 | MUST | signalingstatechange fires only if the signaling state changed | tested | pc/internal.rs `commit_description` | `pc/set_description_atomic_test.rs::signalingstatechange_fires_only_when_the_state_changes` |  |
| WEBRTC-4.4.1.4-86 | 4.4.1.4 | MUST | Fire an error event (data-channel-failure) at each channel in errorList | missing | src/peer_connection/mod.rs:2157 | | |
| WEBRTC-4.4.1.4-87 | 4.4.1.4 | MUST | Mute every track in muteTracks | missing | | | no muted state or event from set-description |
| WEBRTC-4.4.1.4-88 | 4.4.1.4 | MUST | Remove each (stream, track) pair of removeList from its stream | missing | | | no stream membership change is reported |
| WEBRTC-4.4.1.4-89 | 4.4.1.4 | MUST | Add each (stream, track) pair of addList to its stream | partial | src/peer_connection/internal.rs:1261 | tests/jsep_add_transceiver.rs | one stream id on the remote track; several msid streams or later changes are not reported |
| WEBRTC-4.4.1.4-90 | 4.4.1.4 | MUST | Fire a track event (receiver, track, streams, transceiver) for each entry of trackEventInits | partial | src/peer_connection/handler/interceptor.rs:899 | tests/jsep_add_transceiver.rs | fired when the first RTP packet arrives, not when the description is applied |
| WEBRTC-4.4.1.4-91 | 4.4.1.4 | MUST | Events fire in order: signalingstatechange, channel errors, mute, stream changes, track | partial | src/peer_connection/internal.rs:850 | | signalingstatechange and negotiationneeded are queued in order; the others are not raised here |
| WEBRTC-4.4.1.5-1 | 4.4.1.5 | MUST | A certificates list of a different length fails with InvalidModificationError | partial | src/peer_connection/mod.rs:2224 | | only when the new list is non-empty; dropping every certificate is accepted |
| WEBRTC-4.4.1.5-2 | 4.4.1.5 | MUST | A certificate that is not the same object as before fails with InvalidModificationError | violated | src/peer_connection/mod.rs:2229 | | certificates are never compared, and the stored list was emptied at construction, so re-passing the original configuration fails while different certificates are stored silently (bug B4) |
| WEBRTC-4.4.1.5-3 | 4.4.1.5 | MUST | A different bundlePolicy fails with InvalidModificationError | untested | src/peer_connection/mod.rs:2234 | | |
| WEBRTC-4.4.1.5-4 | 4.4.1.5 | MUST | A different rtcpMuxPolicy fails with InvalidModificationError | untested | src/peer_connection/mod.rs:2240 | | |
| WEBRTC-4.4.1.5-5 | 4.4.1.5 | MUST | A different iceCandidatePoolSize after setLocalDescription was called fails | partial | src/peer_connection/mod.rs:2246 | | a new size of 0 is ignored instead of compared; "called" is approximated by a local description being present |
| WEBRTC-4.4.1.5-6 | 4.4.1.5 | MUST | iceServers is truncated to the supported maximum | untested | src/peer_connection/mod.rs:2272 | | no maximum |
| WEBRTC-4.4.1.5-7 | 4.4.1.5 | MUST | A single urls string is treated as a one-element list | n/a | | | `urls` is a Vec; the binding converts |
| WEBRTC-4.4.1.5-8 | 4.4.1.5 | MUST | An empty urls list throws SyntaxError | missing | src/peer_connection/transport/ice/server.rs:42 | | a server with no urls validates |
| WEBRTC-4.4.1.5-9 | 4.4.1.5 | MUST | Every url is validated | tested | src/peer_connection/mod.rs:2274 | test_ice_server_validate_failure | |
| WEBRTC-4.4.1.5-10 | 4.4.1.5 | MUST | The ICE agent's transports setting follows iceTransportPolicy, from the next gathering | tested | src/peer_connection/mod.rs:2258 | a_relay_policy_set_later_reaches_the_agent | |
| WEBRTC-4.4.1.5-11 | 4.4.1.5 | MUST | The ICE agent's candidate pool size follows iceCandidatePoolSize | n/a | | | application gathers; no pool |
| WEBRTC-4.4.1.5-12 | 4.4.1.5 | MUST | The ICE agent's server list becomes iceServers | partial | src/peer_connection/mod.rs:2277 | test_set_get_configuration | stored for the application; an empty list cannot clear the old one; the agent's own url list is not updated |
| WEBRTC-4.4.1.5-13 | 4.4.1.5 | MUST | The configuration is stored only after every check passed | violated | src/peer_connection/mod.rs:2209 | | members are stored one by one; a late failure (an invalid ICE server) leaves the policy already changed (bug B6) |
| WEBRTC-4.4.1.5-14 | 4.4.1.5 | MUST | A url that fails to parse throws SyntaxError | tested | rtc-ice/src/url/mod.rs:139 | test_parse_url_failure | |
| WEBRTC-4.4.1.5-15 | 4.4.1.5 | MUST | A scheme other than stun, stuns, turn, turns throws SyntaxError | untested | rtc-ice/src/url/mod.rs:155 | | only a missing scheme is tested, not an unknown one |
| WEBRTC-4.4.1.5-16 | 4.4.1.5 | MUST | A url without an opaque path, or whose path has "/" or "@", throws SyntaxError | partial | rtc-ice/src/url/mod.rs:141 | | "//" is refused; "@" and a single "/" are not tested |
| WEBRTC-4.4.1.5-17 | 4.4.1.5 | MUST | A url with a fragment throws SyntaxError | untested | rtc-ice/src/url/mod.rs:153 | | no fragment check found |
| WEBRTC-4.4.1.5-18 | 4.4.1.5 | MUST | A stun or stuns url with a query throws SyntaxError | partial | rtc-ice/src/url/mod.rs:177 | test_ice_server_validate_failure_err_stun_query | set_configuration refuses it; the constructor strips the query first and accepts it (src/peer_connection/configuration/mod.rs:349) |
| WEBRTC-4.4.1.5-19 | 4.4.1.5 | MUST | A scheme the user agent does not implement throws NotSupportedError | n/a | | | all four schemes parse; using them is the application's |
| WEBRTC-4.4.1.5-20 | 4.4.1.5 | MUST | Host-and-port part that fails to parse, or has path, username or password, throws SyntaxError | partial | rtc-ice/src/url/mod.rs:157 | test_parse_url_failure | host and port errors tested; userinfo is not refused |
| WEBRTC-4.4.1.5-21 | 4.4.1.5 | MUST | A turn/turns query other than transport=udp or transport=tcp throws SyntaxError | tested | rtc-ice/src/url/mod.rs:189 | test_parse_url_failure | |
| WEBRTC-4.4.1.5-22 | 4.4.1.5 | MUST | A turn/turns server without username or credential throws InvalidAccessError | tested | src/peer_connection/transport/ice/server.rs:50 | test_ice_server_validate_failure | |
| WEBRTC-4.4.1.5-23 | 4.4.1.5 | MUST | TURN username over RFC 8489 14.3 length, or credential failing RFC 8265 4.1, throws InvalidAccessError | missing | src/peer_connection/transport/ice/server.rs:50 | | only emptiness is checked |
| WEBRTC-4.4.2-1 | 4.4.2 | MUST | localDescription returns the pending local description, else the current one | tested | src/peer_connection/mod.rs:1343 | polite_peer_glare_recovery_with_local_offer_rollback | |
| WEBRTC-4.4.2-2 | 4.4.2 | MUST | currentLocalDescription returns [[CurrentLocalDescription]], with local candidates gathered since | untested | src/peer_connection/mod.rs:1361 | | no test calls it; candidates are added to the first m= section only |
| WEBRTC-4.4.2-3 | 4.4.2 | MUST | pendingLocalDescription returns [[PendingLocalDescription]]; null in stable | tested | src/peer_connection/mod.rs:1376 | polite_peer_glare_recovery_with_local_offer_rollback | |
| WEBRTC-4.4.2-4 | 4.4.2 | MUST | remoteDescription returns the pending remote description, else the current one | tested | src/peer_connection/mod.rs:1853 | per_section_ufrags_in_a_bundle_group_use_the_tagged_sections | |
| WEBRTC-4.4.2-5 | 4.4.2 | MUST | currentRemoteDescription returns [[CurrentRemoteDescription]], with remote candidates added since | untested | src/peer_connection/mod.rs:1872 | | never called by a test |
| WEBRTC-4.4.2-6 | 4.4.2 | MUST | pendingRemoteDescription returns [[PendingRemoteDescription]]; null in stable | tested | src/peer_connection/mod.rs:1887 | glare_recovery_with_remote_offer_rollback | |
| WEBRTC-4.4.2-7 | 4.4.2 | MUST | signalingState returns [[SignalingState]] | partial | src/peer_connection/mod.rs:757 | | no public accessor; the application only sees OnSignalingStateChangeEvent, and close() changes the state without one |
| WEBRTC-4.4.2-8 | 4.4.2 | MUST | iceGatheringState returns [[IceGatheringState]] | partial | src/peer_connection/transport/mod.rs:291 | gathering_state_reports_the_tracked_field | readable through the ICE transport handle only |
| WEBRTC-4.4.2-9 | 4.4.2 | MUST | iceConnectionState returns [[IceConnectionState]] | partial | src/peer_connection/handler/ice.rs:204 | | no public accessor; events only |
| WEBRTC-4.4.2-10 | 4.4.2 | MUST | connectionState returns [[ConnectionState]] | partial | src/peer_connection/mod.rs:758 | | no public accessor; events only |
| WEBRTC-4.4.2-11 | 4.4.2 | MUST | canTrickleIceCandidates: null before a remote description, then whether it advertises trickle | tested | src/peer_connection/mod.rs:1475 | per_section_ufrags_in_a_bundle_group_use_the_tagged_sections | the false and null cases are not asserted |
| WEBRTC-4.4.2-12 | 4.4.2 | MUST | negotiationneeded event is delivered to the application | tested | src/peer_connection/internal.rs:1452 | stop_raises_negotiation_needed_and_settles_once_rejected | |
| WEBRTC-4.4.2-13 | 4.4.2 | MUST | icecandidate event is delivered | tested | src/peer_connection/internal.rs:1836 | test_host_candidate_event_emission | |
| WEBRTC-4.4.2-14 | 4.4.2 | MUST | icecandidateerror event is delivered | missing | src/peer_connection/event/mod.rs:310 | | the variant exists; nothing ever emits it |
| WEBRTC-4.4.2-15 | 4.4.2 | MUST | signalingstatechange event is delivered | untested | src/peer_connection/internal.rs:868 | | no test reads OnSignalingStateChangeEvent |
| WEBRTC-4.4.2-16 | 4.4.2 | MUST | iceconnectionstatechange event is delivered | tested | src/peer_connection/handler/ice.rs:213 | test_media_only_negotiation_does_not_start_sctp | |
| WEBRTC-4.4.2-17 | 4.4.2 | MUST | icegatheringstatechange event is delivered | partial | src/peer_connection/mod.rs:2133 | | only for "complete"; the change to "gathering" raises nothing; untested |
| WEBRTC-4.4.2-18 | 4.4.2 | MUST | connectionstatechange event is delivered | tested | src/peer_connection/internal.rs:1374 | a_fingerprint_mismatch_fails_the_dtls_transport_and_the_connection | |
| WEBRTC-4.4.2-19 | 4.4.2 | MUST | createOffer: an offer stays applicable by setLocalDescription until the caller has seen it | tested | src/peer_connection/mod.rs:913 | test_offer_answer_rtc_to_rtc | |
| WEBRTC-4.4.2-20 | 4.4.2 | MUST | createOffer follows RFC 9429 offer generation, treating a stopping transceiver as stopped | tested | src/peer_connection/internal.rs:276 | tests/jsep_stopped_transceivers.rs | clause-level JSEP verdicts are in the RFC 9429 audit |
| WEBRTC-4.4.2-21 | 4.4.2 | MUST | createOffer on a closed connection fails with InvalidStateError | tested | src/peer_connection/mod.rs:818 | `tests/jsep_description_state.rs::a_closed_connection_refuses_offers_answers_and_descriptions` |  |
| WEBRTC-4.4.2-22 | 4.4.2 | MUST | createOffer in a state other than stable or have-local-offer fails with InvalidStateError | tested | pc/mod.rs `create_offer` | `pc/set_description_atomic_test.rs::create_offer_needs_the_stable_or_have_local_offer_state` | `ErrIncorrectSignalingState` |
| WEBRTC-4.4.2-23 | 4.4.2 | MUST | createOffer waits for the default certificate to be generated | n/a | | | certificate exists from build() |
| WEBRTC-4.4.2-24 | 4.4.2 | MUST | createOffer: a failed inspection of system resources rejects with OperationError | n/a | | | no media resources in the engine |
| WEBRTC-4.4.2-25 | 4.4.2 | MUST | createOffer re-inspects when the connection was modified meanwhile | n/a | | | synchronous |
| WEBRTC-4.4.2-26 | 4.4.2 | MUST | createOffer: the offerer-tagged m= section is the first non-stopped transceiver's | untested | src/peer_connection/sdp/mod.rs:1461 | | no test asserts the first mid of a=group:BUNDLE; `alwaysNegotiateDataChannels` puts the data section first by design |
| WEBRTC-4.4.2-27 | 4.4.2 | MUST | createOffer: filtering [[PreferredCodecs]] never changes the order of the preferences | tested | src/peer_connection/internal.rs:2108 | tests/jsep_codec_preferences_repair.rs | |
| WEBRTC-4.4.2-28 | 4.4.2 | MUST | createOffer: a sending direction drops preferred codecs not implemented for sending | partial | src/peer_connection/internal.rs:2108 | | one MediaEngine codec list per kind; send and receive lists are not told apart |
| WEBRTC-4.4.2-29 | 4.4.2 | MUST | createOffer: a receiving direction drops preferred codecs not implemented for receiving | partial | src/peer_connection/internal.rs:2108 | | as above |
| WEBRTC-4.4.2-30 | 4.4.2 | MUST | createOffer: several send encodings give a=rid send lines and a=simulcast:send in encoding order, no restrictions | tested | src/peer_connection/sdp/mod.rs:1383 | tests/one_media_section_rtc_to_rtc_simulcast.rs | |
| WEBRTC-4.4.2-31 | 4.4.2 | MUST | createOffer returns type "offer" with the SDP and stores it as [[LastCreatedOffer]] | tested | src/peer_connection/mod.rs:907 | test_offer_answer_rtc_to_rtc | |
| WEBRTC-4.4.2-32 | 4.4.2 | MUST | createOffer has no side effects on the session (RFC 9429 5.2) | partial | src/peer_connection/mod.rs:880 | set_local_rollback_disassociates_but_keeps_app_created_transceivers | it assigns mids, marks senders negotiated, stages an ICE restart and consumes the restart request |
| WEBRTC-4.4.2-33 | 4.4.2 | SHOULD | createAnswer reflects the current system state | n/a | | | no media resources in the engine |
| WEBRTC-4.4.2-34 | 4.4.2 | MUST | createAnswer follows RFC 9429 answer generation | tested | src/peer_connection/internal.rs:357 | test_offer_answer_rtc_to_rtc | clause-level verdicts in the RFC 9429 audit |
| WEBRTC-4.4.2-35 | 4.4.2 | MUST | createAnswer on a closed connection fails with InvalidStateError | tested | src/peer_connection/mod.rs:1026 | `tests/jsep_description_state.rs::a_closed_connection_refuses_offers_answers_and_descriptions` |  |
| WEBRTC-4.4.2-36 | 4.4.2 | MUST | createAnswer outside have-remote-offer / have-local-pranswer fails with InvalidStateError | tested | src/peer_connection/mod.rs:1030 | `tests/jsep_description_state.rs::create_answer_needs_a_remote_offer` |  |
| WEBRTC-4.4.2-37 | 4.4.2 | MUST | createAnswer filters [[PreferredCodecs]] by direction without reordering | partial | src/peer_connection/internal.rs:2108 | tests/answer_preserves_offer_codec_order.rs | as 4.4.2-28 |
| WEBRTC-4.4.2-38 | 4.4.2 | MUST | createAnswer to a simulcast offer: only the first of comma-separated rid alternatives is kept | untested | src/peer_connection/sdp/mod.rs:592 | | implemented in get_rids; no test with alternatives found |
| WEBRTC-4.4.2-39 | 4.4.2 | MUST | createAnswer: identically named rids are reduced to the first; no restrictions set | untested | src/peer_connection/sdp/mod.rs:630 | | |
| WEBRTC-4.4.2-40 | 4.4.2 | MUST | createAnswer: rids not in the sender's [[SendEncodings]] are left out of the answer | missing | src/peer_connection/internal.rs:519 | | the remote-receives-simulcast case is not implemented (4.4.1.4-49) |
| WEBRTC-4.4.2-41 | 4.4.2 | MUST | createAnswer returns type "answer" and stores the SDP as [[LastCreatedAnswer]] | tested | src/peer_connection/mod.rs:1086 | sections_without_ssrc_lines_are_answered | |
| WEBRTC-4.4.2-42 | 4.4.2 | MUST | A provisional answer is made by setting the type of a created answer to "pranswer" | tested | src/peer_connection/internal.rs:746 | provisional_answers_repeat_and_keep_the_offerer_controlling | |
| WEBRTC-4.4.2-43 | 4.4.2 | MUST | setLocalDescription: current and pending local descriptions stay usable together until the answer or a rollback | partial | src/peer_connection/mod.rs:1457 | | one negotiated media engine; no test of media under a pending incompatible offer |
| WEBRTC-4.4.2-44 | 4.4.2 | MUST | setLocalDescription without a type uses "offer" in stable, have-local-offer, have-remote-pranswer; else "answer" | missing | src/peer_connection/internal.rs:676 | | the type is required; `Unspecified` is an error |
| WEBRTC-4.4.2-45 | 4.4.2 | MUST | setLocalDescription(offer) with SDP different from [[LastCreatedOffer]] fails with InvalidModificationError | tested | src/peer_connection/internal.rs:690 | `tests/jsep_description_state.rs::a_local_description_is_the_last_one_created` |  |
| WEBRTC-4.4.2-46 | 4.4.2 | MUST | setLocalDescription(answer or pranswer) with SDP different from [[LastCreatedAnswer]] fails | tested | src/peer_connection/internal.rs:708 | `tests/jsep_description_state.rs::a_local_description_is_the_last_one_created` |  |
| WEBRTC-4.4.2-47 | 4.4.2 | MUST | setLocalDescription(offer, empty sdp) uses [[LastCreatedOffer]] | tested | src/peer_connection/mod.rs:1219 | `tests/jsep_description_state.rs::a_local_description_is_the_last_one_created` |  |
| WEBRTC-4.4.2-48 | 4.4.2 | MUST | ...and creates a new offer when there is none or it no longer matches the system state | missing | src/peer_connection/mod.rs:1219 | | an empty or stale last offer is parsed as it is; the parse fails or a stale offer is applied |
| WEBRTC-4.4.2-49 | 4.4.2 | MUST | setLocalDescription(answer/pranswer, empty sdp) uses [[LastCreatedAnswer]] | tested | src/peer_connection/mod.rs:1216 | `tests/jsep_description_state.rs::a_local_description_is_the_last_one_created` |  |
| WEBRTC-4.4.2-50 | 4.4.2 | MUST | ...and creates a new answer when there is none or it no longer matches | missing | src/peer_connection/mod.rs:1216 | | |
| WEBRTC-4.4.2-51 | 4.4.2 | MUST | setLocalDescription then sets the local description {type, sdp} | tested | src/peer_connection/mod.rs:1232 | test_offer_answer_rtc_to_rtc | |
| WEBRTC-4.4.2-52 | 4.4.2 | MUST | setRemoteDescription(offer) in a state where an offer is invalid first rolls back the local offer | missing | src/peer_connection/state/signaling_state.rs:337 | glare_recovery_with_remote_offer_rollback | a remote offer in have-local-offer is refused; the application has to roll back itself |
| WEBRTC-4.4.2-53 | 4.4.2 | MUST | setRemoteDescription otherwise sets the remote description | tested | src/peer_connection/mod.rs:1452 | test_offer_answer_rtc_to_rtc | |
| WEBRTC-4.4.2-54 | 4.4.2 | MUST | addIceCandidate: non-empty candidate with sdpMid and sdpMLineIndex both null fails with TypeError | missing | src/peer_connection/mod.rs:2007 | | such a candidate is handed to the ICE transport |
| WEBRTC-4.4.2-55 | 4.4.2 | MUST | addIceCandidate without a remote description fails with InvalidStateError | untested | src/peer_connection/mod.rs:1916 | | |
| WEBRTC-4.4.2-56 | 4.4.2 | MUST | addIceCandidate: sdpMid matching no media description fails with OperationError | tested | src/peer_connection/mod.rs:1944 | per_section_ufrags_in_a_bundle_group_use_the_tagged_sections | |
| WEBRTC-4.4.2-57 | 4.4.2 | MUST | addIceCandidate: sdpMLineIndex beyond the media descriptions fails with OperationError | untested | src/peer_connection/mod.rs:1948 | | |
| WEBRTC-4.4.2-58 | 4.4.2 | MUST | addIceCandidate for a section whose transceiver is stopped resolves without doing anything | missing | src/peer_connection/mod.rs:1938 | | no stopped-transceiver check |
| WEBRTC-4.4.2-59 | 4.4.2 | MUST | addIceCandidate: a usernameFragment not in the section's applied remote description fails with OperationError | tested | src/peer_connection/mod.rs:1958 | per_section_ufrags_in_a_bundle_group_use_the_tagged_sections | |
| WEBRTC-4.4.2-60 | 4.4.2 | MUST | addIceCandidate adds the candidate to the ICE agent, for the generation its usernameFragment names (latest if null) | partial | src/peer_connection/mod.rs:2017 | per_section_ufrags_in_a_bundle_group_use_the_tagged_sections | a candidate of a non-current ufrag is recorded only; an older generation still present in the current description is not served |
| WEBRTC-4.4.2-61 | 4.4.2 | MUST | addIceCandidate: an empty candidate is end-of-candidates for the section and generation, or for all sections | partial | src/peer_connection/mod.rs:1973 | per_section_ufrags_in_a_bundle_group_use_the_tagged_sections | written into the description; the ICE agent is not told gathering ended |
| WEBRTC-4.4.2-62 | 4.4.2 | MUST | addIceCandidate: a candidate that cannot be added fails with OperationError | tested | src/peer_connection/internal.rs:1782 | test_trickled_candidate_component_out_of_range_is_rejected | |
| WEBRTC-4.4.2-63 | 4.4.2 | MUST | addIceCandidate: the candidate is added to the pending and/or current remote description of its generation | tested | src/peer_connection/mod.rs:2048 | per_section_ufrags_in_a_bundle_group_use_the_tagged_sections | |
| WEBRTC-4.4.2-64 | 4.4.2 | MUST | Connections to ports on the Fetch bad-port list are prohibited | missing | | | no port list anywhere |
| WEBRTC-4.4.2-65 | 4.4.2 | MAY | The UA may prohibit connections to other addresses | untested | src/peer_connection/internal.rs:124 | | `remote_address_filter`, loopback and link-local switches reach the agent; no engine-level test |
| WEBRTC-4.4.2-66 | 4.4.2 | MUST | A prohibited candidate behaves as if added (no error, no indication) | untested | src/peer_connection/mod.rs:1997 | | candidates past the cap are ignored silently; filtered addresses not verified |
| WEBRTC-4.4.2-67 | 4.4.2 | MUST | With every candidate prohibited, connect to none and gather from no source | n/a | | | no such global switch; gathering is the application's |
| WEBRTC-4.4.2-68 | 4.4.2 | MUST | Under policy "relay", candidates needing external resolution (mDNS, DNS names) are prohibited | missing | src/peer_connection/mod.rs:1910 | | no policy check on a remote candidate's address kind |
| WEBRTC-4.4.2-69 | 4.4.2 | MUST | restartIce records every ICE credential of the current and pending local descriptions as to-be-replaced | partial | src/peer_connection/mod.rs:2174 | data_flows_at_every_step_of_an_ice_restart | a single flag; the next offer gets new credentials |
| WEBRTC-4.4.2-70 | 4.4.2 | MUST | restartIce updates the negotiation-needed flag | missing | src/peer_connection/mod.rs:2174 | | no trigger, and check_negotiation_needed skips the credentials step (4.7.3-9) |
| WEBRTC-4.4.2-71 | 4.4.2 | MUST | After restartIce, every later createOffer restarts ICE until an answer replaces the credentials | partial | src/peer_connection/mod.rs:825 | | the first create_offer consumes the request, even if that offer is discarded or rolled back |
| WEBRTC-4.4.2-72 | 4.4.2 | MUST | getConfiguration returns the stored [[Configuration]] | partial | src/peer_connection/mod.rs:2186 | test_set_get_configuration | certificates are always reported empty (moved to the DTLS transport) |
| WEBRTC-4.4.2-73 | 4.4.2 | MUST | setConfiguration on a closed connection throws InvalidStateError | untested | src/peer_connection/mod.rs:2211 | | |
| WEBRTC-4.4.2-74 | 4.4.2 | MUST | setConfiguration otherwise sets the configuration | tested | src/peer_connection/mod.rs:2209 | test_set_get_configuration | |
| WEBRTC-4.4.2-75 | 4.4.2 | MUST | close on a closed connection does nothing | tested | src/peer_connection/handler/mod.rs:533 | close_is_idempotent | |
| WEBRTC-4.4.2-76 | 4.4.2 | MUST | close sets [[IsClosed]] | tested | src/peer_connection/handler/mod.rs:572 | close_transitions_to_closed_state | |
| WEBRTC-4.4.2-77 | 4.4.2 | MUST | close sets the signaling state to "closed" without an event | tested | src/peer_connection/handler/mod.rs:538 | close_transitions_to_closed_state | the absence of the event is not asserted |
| WEBRTC-4.4.2-78 | 4.4.2 | MUST | close stops every transceiver that is not stopped | missing | src/peer_connection/handler/mod.rs:531 | | transceivers keep their state after close |
| WEBRTC-4.4.2-79 | 4.4.2 | MUST | close sets every data channel's [[ReadyState]] to "closed", without the closing procedure | partial | src/peer_connection/handler/datachannel.rs:726 | close_with_data_channel_does_not_panic | the handler's close is empty; the test reads ready_state without asserting it |
| WEBRTC-4.4.2-80 | 4.4.2 | MUST | close tears the SCTP association down with an ABORT chunk; SCTP transport state "closed" | partial | src/peer_connection/handler/mod.rs:549 | close_is_noticed_by_the_remote | the ABORT is sent; the local SCTP transport state after close is not asserted |
| WEBRTC-4.4.2-81 | 4.4.2 | MUST | close sets every DTLS transport's state to "closed" | untested | src/peer_connection/transport/dtls/mod.rs:460 | | |
| WEBRTC-4.4.2-82 | 4.4.2 | MUST | close destroys the ICE agent, ending ICE processing and releasing resources | tested | src/peer_connection/handler/ice.rs:264 | close_is_noticed_by_the_remote | TURN allocations belong to the application |
| WEBRTC-4.4.2-83 | 4.4.2 | MUST | close sets every ICE transport's state to "closed" | untested | src/peer_connection/handler/ice.rs:264 | | |
| WEBRTC-4.4.2-84 | 4.4.2 | MUST | close sets the ICE connection state to "closed" without an event | untested | src/peer_connection/handler/mod.rs:531 | | as 4.3.4-1 |
| WEBRTC-4.4.2-85 | 4.4.2 | MUST | close sets the connection state to "closed" without an event | violated | src/peer_connection/handler/mod.rs:572 | test_peer_connection_state | update_connection_state(true) queues OnConnectionStateChangeEvent(Closed) |
| WEBRTC-4.4.2-86 | 4.4.2 | MUST | After close, methods that chain operations fail with InvalidStateError | partial | src/peer_connection/mod.rs:1910 | | add_remote_candidate, add_local_candidate, restart_ice and create_data_channel paths not all checked; none tested |
| WEBRTC-4.4.3-1 | 4.4.3 | MAY | Legacy callback overload of createOffer | n/a | | | JS callback overloads |
| WEBRTC-4.4.3-2 | 4.4.3 | MAY | Legacy callback overload of setLocalDescription | n/a | | | JS callback overloads |
| WEBRTC-4.4.3-3 | 4.4.3 | MAY | Legacy callback overload of createAnswer | n/a | | | JS callback overloads |
| WEBRTC-4.4.3-4 | 4.4.3 | MAY | Legacy callback overload of setRemoteDescription | n/a | | | JS callback overloads |
| WEBRTC-4.4.3-5 | 4.4.3 | MAY | Legacy callback overload of addIceCandidate | n/a | | | JS callback overloads |
| WEBRTC-4.4.3-6 | 4.4.3 | MAY | offerToReceiveAudio / offerToReceiveVideo false: sendrecv becomes sendonly, recvonly becomes inactive | n/a | | | built by the binding from set_direction |
| WEBRTC-4.4.3-7 | 4.4.3 | MAY | offerToReceive true with no receiving transceiver of the kind: add a recvonly transceiver | n/a | | | built by the binding from add_transceiver_from_kind |
| WEBRTC-4.4.3-8 | 4.4.3 | MUST | That added transceiver must not update the negotiation-needed flag | missing | src/peer_connection/internal.rs:904 | | every add_rtp_transceiver triggers the check; the engine offers no silent add |
| WEBRTC-4.4.4-1 | 4.4.4 | MUST | The connection is not garbage collected while an event can still fire on it | n/a | | | ownership is the application's |
| WEBRTC-4.5.1-1 | 4.5.1 | MUST | Failures are reported as rejections or exceptions with the specified error name | partial | rtc-shared/src/error.rs:1740 | | distinct Error variants exist; several W3C cases share a variant or are missing (rows above) |
| WEBRTC-4.6.1-1 | 4.6.1 | MUST | "offer": the description is treated as an SDP offer | tested | src/peer_connection/sdp/sdp_type.rs:110 | test_offer_answer_rtc_to_rtc | |
| WEBRTC-4.6.1-2 | 4.6.1 | MUST | "pranswer": treated as a non-final answer; may follow an offer or a previous pranswer | tested | src/peer_connection/sdp/sdp_type.rs:131 | provisional_answers_repeat_and_keep_the_offerer_controlling | |
| WEBRTC-4.6.1-3 | 4.6.1 | MUST | "answer": treated as the final answer; the exchange is complete | tested | src/peer_connection/sdp/sdp_type.rs:147 | provisional_answers_repeat_and_keep_the_offerer_controlling | |
| WEBRTC-4.6.1-4 | 4.6.1 | MUST | "rollback": cancels the current negotiation and returns to the previous stable state | tested | src/peer_connection/sdp/sdp_type.rs:170 | polite_peer_glare_recovery_with_local_offer_rollback | |
| WEBRTC-4.6.1-5 | 4.6.1 | MUST | An answer or pranswer cannot be rolled back | untested | src/peer_connection/state/signaling_state.rs:361 | | refused by the transition table; not tested |
| WEBRTC-4.6.2-1 | 4.6.2 | MUST | RTCSessionDescription exposes type | tested | src/peer_connection/sdp/session_description.rs:162 | test_session_description_json | |
| WEBRTC-4.6.2-2 | 4.6.2 | MUST | RTCSessionDescription exposes sdp, default "" | tested | src/peer_connection/sdp/session_description.rs:169 | test_session_description_json | |
| WEBRTC-4.6.2-3 | 4.6.2 | MUST | toJSON gives {type, sdp} | tested | src/peer_connection/sdp/session_description.rs:158 | test_session_description_json | |
| WEBRTC-4.6.2-4 | 4.6.2 | MUST | RTCSessionDescriptionInit: type required, sdp optional; sdp unused for rollback | tested | src/peer_connection/mod.rs:1432 | a_remote_offer_can_be_applied_again_and_rolled_back | |
| WEBRTC-4.6.2-5 | 4.6.2 | MUST | RTCLocalSessionDescriptionInit: type optional (inferred) | missing | src/peer_connection/internal.rs:676 | | see 4.4.2-44 |
| WEBRTC-4.7.3-1 | 4.7.3 | MUST | Internal changes that affect negotiation update the negotiation-needed flag | untested | src/peer_connection/internal.rs:1396 | | no internal trigger besides API calls |
| WEBRTC-4.7.3-2 | 4.7.3 | MUST | With operations pending, the update is deferred to the end of the chain | n/a | | | no chain |
| WEBRTC-4.7.3-3 | 4.7.3 | MUST | The update runs in a queued task, so several changes in one task give one event | partial | src/peer_connection/internal.rs:1403 | test_set_direction_updates_negotiation_needed_flag | the check runs inside the call; the single event is kept by `is_negotiation_ongoing` |
| WEBRTC-4.7.3-4 | 4.7.3 | MUST | No update on a closed connection | untested | src/peer_connection/internal.rs:1420 | | |
| WEBRTC-4.7.3-5 | 4.7.3 | MUST | No update outside stable; it runs when the state returns to stable | tested | src/peer_connection/internal.rs:1430 | set_streams_raises_negotiation_needed_until_the_msid_follows | |
| WEBRTC-4.7.3-6 | 4.7.3 | MUST | Check false: clear [[NegotiationNeeded]] | tested | src/peer_connection/internal.rs:1436 | test_recvonly_answer_without_track_settles | |
| WEBRTC-4.7.3-7 | 4.7.3 | MUST | Flag already true: no second event | tested | src/peer_connection/internal.rs:1441 | test_set_direction_updates_negotiation_needed_flag | |
| WEBRTC-4.7.3-8 | 4.7.3 | MUST | Otherwise set the flag and fire negotiationneeded | tested | src/peer_connection/internal.rs:1447 | stop_raises_negotiation_needed_and_settles_once_rejected | |
| WEBRTC-4.7.3-9 | 4.7.3 | MUST | Check: non-empty [[LocalIceCredentialsToReplace]] means negotiation is needed | missing | src/peer_connection/internal.rs:1470 | | step skipped ("Skip 1, 2 steps") |
| WEBRTC-4.7.3-10 | 4.7.3 | MUST | Check: with no current local description and nothing to negotiate the result is false | violated | src/peer_connection/internal.rs:1596 | | returns true whenever there is no current local description, so a rollback to an empty stable state fires negotiationneeded (bug B3) |
| WEBRTC-4.7.3-11 | 4.7.3 | MUST | Check: data channels exist and no data m= section is negotiated: true | untested | src/peer_connection/internal.rs:1478 | | create_data_channel triggers the check (src/peer_connection/mod.rs:2412); no test asserts the event for it |
| WEBRTC-4.7.3-12 | 4.7.3 | MUST | Check: a stopping, not yet stopped transceiver: true | tested | src/peer_connection/internal.rs:1488 | stop_raises_negotiation_needed_and_settles_once_rejected | no separate stopping state |
| WEBRTC-4.7.3-13 | 4.7.3 | MUST | Check: a non-stopped transceiver not associated with an m= section: true | untested | src/peer_connection/internal.rs:1508 | | no test adds a transceiver after a first negotiation and asserts the event |
| WEBRTC-4.7.3-14 | 4.7.3 | MUST | Check: sending direction and the section's a=msid lines differ from the sender's stream ids: true | tested | src/peer_connection/internal.rs:1519 | set_streams_raises_negotiation_needed_until_the_msid_follows | skipped for a sending direction without a sender |
| WEBRTC-4.7.3-15 | 4.7.3 | MUST | Check: local description is an offer and neither current description's direction matches [[Direction]]: true | tested | src/peer_connection/internal.rs:1546 | test_set_direction_updates_negotiation_needed_flag | |
| WEBRTC-4.7.3-16 | 4.7.3 | MUST | Check: local description is an answer and its direction differs from [[Direction]] intersected with the offer: true | tested | src/peer_connection/internal.rs:1565 | test_recvonly_answer_without_track_settles | |
| WEBRTC-4.7.3-17 | 4.7.3 | MUST | Check: a stopped transceiver whose m= section is not yet rejected in the current descriptions: true | tested | src/peer_connection/internal.rs:1488 | stop_raises_negotiation_needed_and_settles_once_rejected | |
| WEBRTC-4.7.3-18 | 4.7.3 | MUST | Check: otherwise false | tested | src/peer_connection/internal.rs:1594 | a_stopped_transceiver_that_never_had_a_section_needs_none | |
| WEBRTC-4.8.1-1 | 4.8.1 | MUST | RTCIceCandidate constructor: sdpMid and sdpMLineIndex both null throws TypeError | n/a | | | no such constructor; candidates enter as RTCIceCandidateInit (see 4.4.2-54) |
| WEBRTC-4.8.1-2 | 4.8.1 | MUST | Creating a candidate parses the candidate-attribute and fills the derived attributes | tested | src/peer_connection/transport/ice/candidate.rs:131 | test_host_candidate_event_emission | |
| WEBRTC-4.8.1-3 | 4.8.1 | MUST | A candidate string that does not parse keeps the raw string and leaves derived attributes null | n/a | | | constructor leniency is the binding's; the engine refuses unparsable candidates |
| WEBRTC-4.8.1-4 | 4.8.1 | MUST | candidate attribute: the candidate-attribute string; empty for end-of-candidates | partial | src/peer_connection/transport/ice/candidate.rs:228 | test_host_candidate_event_emission | to_json rebuilds the string; no end-of-candidates candidate object is ever produced |
| WEBRTC-4.8.1-5 | 4.8.1 | MUST | sdpMid attribute | missing | src/peer_connection/transport/ice/candidate.rs:233 | | RTCIceCandidate has no mid; to_json always gives None |
| WEBRTC-4.8.1-6 | 4.8.1 | MUST | sdpMLineIndex attribute | partial | src/peer_connection/transport/ice/candidate.rs:234 | | to_json always gives 0 |
| WEBRTC-4.8.1-7 | 4.8.1 | MUST | foundation attribute | tested | src/peer_connection/transport/ice/candidate.rs:99 | test_host_candidate_event_emission | |
| WEBRTC-4.8.1-8 | 4.8.1 | MUST | component attribute ("rtp" / "rtcp") | untested | src/peer_connection/transport/ice/candidate.rs:111 | | numeric component id |
| WEBRTC-4.8.1-9 | 4.8.1 | MUST | priority attribute | tested | src/peer_connection/transport/ice/candidate.rs:101 | a_candidate_reports_its_whole_priority_and_only_the_members_it_has | via stats |
| WEBRTC-4.8.1-10 | 4.8.1 | MUST | address attribute (IPv4, IPv6 or FQDN) | tested | src/peer_connection/transport/ice/candidate.rs:103 | test_host_candidate_event_emission | |
| WEBRTC-4.8.1-11 | 4.8.1 | MUST | The address of an exposed remote candidate stays null until the application supplied that address itself | missing | src/peer_connection/transport/mod.rs:304 | | get_remote_candidates returns the agent's candidates as they are; no address withholding |
| WEBRTC-4.8.1-12 | 4.8.1 | MUST | protocol attribute | tested | src/peer_connection/transport/ice/candidate.rs:105 | test_host_candidate_event_emission | |
| WEBRTC-4.8.1-13 | 4.8.1 | MUST | port attribute | tested | src/peer_connection/transport/ice/candidate.rs:107 | test_host_candidate_event_emission | |
| WEBRTC-4.8.1-14 | 4.8.1 | MUST | type attribute | tested | src/peer_connection/transport/ice/candidate.rs:109 | test_srflx_candidate_event_emission | |
| WEBRTC-4.8.1-15 | 4.8.1 | MUST | tcpType attribute; null unless protocol is tcp | untested | src/peer_connection/transport/ice/candidate.rs:117 | | `Unspecified` stands for null |
| WEBRTC-4.8.1-16 | 4.8.1 | MUST | relatedAddress / relatedPort; null for host candidates | untested | src/peer_connection/transport/ice/candidate.rs:113 | | empty string and 0 stand for null |
| WEBRTC-4.8.1-17 | 4.8.1 | MUST | usernameFragment attribute | missing | src/peer_connection/transport/ice/candidate.rs:235 | | not carried by RTCIceCandidate or its to_json |
| WEBRTC-4.8.1-18 | 4.8.1 | MUST | relayProtocol: protocol to the TURN server for local relay candidates | missing | src/peer_connection/transport/ice/candidate.rs:153 | | always `Unspecified`; RTCIceCandidateInit has no member to supply it |
| WEBRTC-4.8.1-19 | 4.8.1 | MUST | url: the ICE server a local srflx or relay candidate came from; null otherwise | tested | src/peer_connection/transport/ice/candidate.rs:154 | test_srflx_candidate_event_emission | |
| WEBRTC-4.8.1-20 | 4.8.1 | MUST | toJSON gives candidate, sdpMid, sdpMLineIndex, usernameFragment | partial | src/peer_connection/transport/ice/candidate.rs:228 | test_ice_candidate_serialization | sdpMid null, index 0, usernameFragment null whatever the candidate |
| WEBRTC-4.8.1-21 | 4.8.1 | MUST | RTCIceCandidateInit members candidate, sdpMid, sdpMLineIndex, usernameFragment with their defaults | tested | src/peer_connection/transport/ice/candidate.rs:254 | test_ice_candidate_serialization | |
| WEBRTC-4.8.1-22 | 4.8.1 | MUST | RTCLocalIceCandidateInit members relayProtocol and url | partial | src/peer_connection/transport/ice/candidate.rs:274 | test_srflx_candidate_event_emission | url only |
| WEBRTC-4.8.1.1-1 | 4.8.1.1 | MUST | The candidate-attribute grammar includes the ICE TCP extension (RFC 6544 4.5) | tested | src/peer_connection/transport/ice/candidate.rs:40 | tests/ice_tcp_rtc2rtc.rs | |
| WEBRTC-4.8.1.1-2 | 4.8.1.1 | MAY | Other grammar extensions | untested | rtc-ice/src/candidate/mod.rs | | see the ICE audits (ufrag, generation, network-cost extensions) |
| WEBRTC-4.8.1.2-1 | 4.8.1.2 | MUST | RTCIceProtocol "udp" | tested | src/peer_connection/transport/ice/protocol.rs | test_host_candidate_event_emission | |
| WEBRTC-4.8.1.2-2 | 4.8.1.2 | MUST | RTCIceProtocol "tcp" | tested | src/peer_connection/transport/ice/protocol.rs | tests/ice_tcp_rtc2rtc.rs | |
| WEBRTC-4.8.1.3-1 | 4.8.1.3 | MUST | RTCIceTcpCandidateType "active" | tested | src/peer_connection/transport/ice/candidate.rs:29 | tests/ice_tcp_active_passive.rs | |
| WEBRTC-4.8.1.3-2 | 4.8.1.3 | MUST | RTCIceTcpCandidateType "passive" | tested | src/peer_connection/transport/ice/candidate.rs:33 | tests/ice_tcp_active_passive.rs | |
| WEBRTC-4.8.1.3-3 | 4.8.1.3 | MUST | RTCIceTcpCandidateType "so" | untested | src/peer_connection/transport/ice/candidate.rs:37 | | |
| WEBRTC-4.8.1.4-1 | 4.8.1.4 | MUST | RTCIceCandidateType "host" | tested | src/peer_connection/transport/ice/candidate_type.rs | test_host_candidate_event_emission | |
| WEBRTC-4.8.1.4-2 | 4.8.1.4 | MUST | RTCIceCandidateType "srflx" | tested | src/peer_connection/transport/ice/candidate_type.rs | test_srflx_candidate_event_emission | |
| WEBRTC-4.8.1.4-3 | 4.8.1.4 | MUST | RTCIceCandidateType "prflx" | untested | src/peer_connection/transport/ice/candidate_type.rs | | |
| WEBRTC-4.8.1.4-4 | 4.8.1.4 | MUST | RTCIceCandidateType "relay" | untested | src/peer_connection/transport/ice/candidate_type.rs | | at this layer; the real-network TURN tests are `testenv_turn.rs` |
| WEBRTC-4.8.1.5-1 | 4.8.1.5 | MUST | RTCIceServerTransportProtocol "udp" | untested | src/peer_connection/transport/ice/candidate.rs:76 | | enum only; never set (4.8.1-18) |
| WEBRTC-4.8.1.5-2 | 4.8.1.5 | MUST | RTCIceServerTransportProtocol "tcp" | untested | src/peer_connection/transport/ice/candidate.rs:79 | | |
| WEBRTC-4.8.1.5-3 | 4.8.1.5 | MUST | RTCIceServerTransportProtocol "tls" | untested | src/peer_connection/transport/ice/candidate.rs:82 | | |
| WEBRTC-4.8.2-1 | 4.8.2 | MUST | An icecandidate event's candidate carries both sdpMid and sdpMLineIndex | violated | src/peer_connection/internal.rs:1836 | | the event's RTCIceCandidate has neither; to_json gives sdpMid null and index 0 |
| WEBRTC-4.8.2-2 | 4.8.2 | MUST | For a srflx or relay candidate the event's url is the ICE server's URL | tested | src/peer_connection/internal.rs:1838 | test_srflx_candidate_event_emission | supplied by the application with the candidate |
| WEBRTC-4.8.2-3 | 4.8.2 | MUST | A gathered candidate fires icecandidate with the candidate | tested | src/peer_connection/internal.rs:1835 | test_multiple_candidates_events | |
| WEBRTC-4.8.2-4 | 4.8.2 | MUST | End of a generation of a transport fires icecandidate with an empty candidate string | missing | src/peer_connection/mod.rs:2129 | | an empty local candidate only sets the gathering state |
| WEBRTC-4.8.2-5 | 4.8.2 | MUST | All transports done: one icecandidate with a null candidate, with gathering state "complete" | partial | src/peer_connection/mod.rs:2130 | | OnIceGatheringStateChangeEvent(Complete) is raised; no null-candidate event |
| WEBRTC-4.8.2-6 | 4.8.2 | MUST | RTCPeerConnectionIceEvent members candidate (nullable) and url (nullable) | partial | src/peer_connection/event/ice_event.rs:75 | test_host_candidate_event_emission | neither is nullable: empty string stands for no url |
| WEBRTC-4.8.3-1 | 4.8.3 | MUST | icecandidateerror: address and port of the local socket, null when not already exposed | missing | src/peer_connection/event/ice_error_event.rs:55 | | struct only; never emitted, and the application has no call to report a gathering failure |
| WEBRTC-4.8.3-2 | 4.8.3 | MUST | icecandidateerror: url of the failing STUN/TURN server | missing | src/peer_connection/event/ice_error_event.rs:69 | | |
| WEBRTC-4.8.3-3 | 4.8.3 | MUST | icecandidateerror: errorCode is the STUN error code, or 701 when the server is unreachable | missing | src/peer_connection/event/ice_error_event.rs:74 | | |
| WEBRTC-4.8.3-4 | 4.8.3 | MUST | Error 701 fires once per server URL while gathering | missing | | | |
| WEBRTC-4.8.3-5 | 4.8.3 | MUST | icecandidateerror: errorText is the STUN reason phrase | missing | src/peer_connection/event/ice_error_event.rs:79 | | |
| WEBRTC-4.9-1 | 4.9 | MUST | Without configured certificates a new set is generated | tested | src/peer_connection/transport/dtls/mod.rs:133 | test_offer_answer_rtc_to_rtc | |
| WEBRTC-4.9-2 | 4.9 | MUST | The default set includes an ECDSA P-256 certificate signed with SHA-256 | untested | src/peer_connection/transport/dtls/mod.rs:137 | | implemented; no test inspects the default certificate's algorithm |
| WEBRTC-4.9-3 | 4.9 | MUST | generateCertificate supports RSASSA-PKCS1-v1_5, 2048 bit, exponent 65537, SHA-256 | partial | src/peer_connection/certificate/mod.rs:768 | test_generate_certificate_rsa | neither built-in provider generates RSA keys; the test returns early. Imported RSA keys work (`tests/dtls_rsa_certificate.rs`) |
| WEBRTC-4.9-4 | 4.9 | MUST | generateCertificate supports ECDSA P-256 | tested | src/peer_connection/certificate/mod.rs:378 | test_generate_certificate_ecdsa | |
| WEBRTC-4.9-5 | 4.9 | SHOULD | The certificate is signed with SHA-256 when a hash is needed | tested | src/peer_connection/certificate/mod.rs:766 | test_generate_certificate_ecdsa | scheme-bound; Ed25519 needs none |
| WEBRTC-4.9-6 | 4.9 | MUST | The certificate holds nothing linkable to a user or user agent | partial | src/peer_connection/transport/dtls/mod.rs:133 | | the default certificate uses a random name; `generate` takes whatever CertificateParams the caller builds (examples use fixed names) |
| WEBRTC-4.9-7 | 4.9 | SHOULD | Randomised distinguished name and serial number | partial | src/peer_connection/transport/dtls/mod.rs:133 | | random subject-alt name for the default certificate only; serial left to rcgen's default, unverified |
| WEBRTC-4.9-8 | 4.9 | MUST | generateCertificate: default expiry is 30 days from generation | missing | src/peer_connection/certificate/mod.rs:449 | | expiry is the params' not_after (rcgen default, far future); on 32-bit arm it is fixed at 2 days |
| WEBRTC-4.9-9 | 4.9 | MUST | generateCertificate: an RTCCertificateExpiration.expires in the algorithm sets the lifetime | partial | src/peer_connection/certificate/mod.rs:449 | test_from_existing_with_custom_expiry | lifetime comes from not_after or `from_existing`, not a duration argument |
| WEBRTC-4.9-10 | 4.9 | MUST | generateCertificate: the lifetime is capped at 365 days | missing | src/peer_connection/certificate/mod.rs:449 | | no cap |
| WEBRTC-4.9-11 | 4.9 | MAY | The user agent may cap the lifetime further | n/a | | | optional |
| WEBRTC-4.9-12 | 4.9 | MUST | generateCertificate: an algorithm that fails normalisation rejects with that error | n/a | | | WebCrypto normalisation is the binding's; the engine takes a SignatureScheme enum |
| WEBRTC-4.9-13 | 4.9 | MUST | generateCertificate: an algorithm unusable for DTLS authentication rejects with NotSupportedError | tested | src/peer_connection/certificate/mod.rs:764 | test_from_key_pair_unsupported_rejects | explicit error from the provider or key import |
| WEBRTC-4.9-14 | 4.9 | MUST | generateCertificate generates the key and a certificate and returns an RTCCertificate holding both | tested | src/peer_connection/certificate/mod.rs:439 | test_generate_certificate_ecdsa | |
| WEBRTC-4.9-15 | 4.9 | MUST | The certificate's [[Expires]] is generation time plus the lifetime | partial | src/peer_connection/certificate/mod.rs:449 | test_generate_certificate_expires | only "expires is in the future" is asserted |
| WEBRTC-4.9-16 | 4.9 | MUST | [[Origin]] is recorded and the certificate is unusable from another origin | n/a | | | origins are a browser concept |
| WEBRTC-4.9.1-1 | 4.9.1 | MAY | RTCCertificateExpiration.expires: maximum validity in milliseconds from creation | partial | src/peer_connection/certificate/mod.rs:359 | test_from_existing_with_custom_expiry | an absolute SystemTime, set by the caller |
| WEBRTC-4.9.2-1 | 4.9.2 | MUST | RTCCertificate.expires: time after which the certificate is invalid | tested | src/peer_connection/certificate/mod.rs:359 | test_generate_certificate_expires | |
| WEBRTC-4.9.2-2 | 4.9.2 | MUST | Constructing a connection with a certificate past expires fails | untested | src/peer_connection/transport/dtls/mod.rs:126 | | as 4.4.1.1-3 |
| WEBRTC-4.9.2-3 | 4.9.2 | MUST | getFingerprints returns the fingerprints, one with the digest of the certificate's signature | partial | src/peer_connection/certificate/mod.rs:724 | test_from_key_pair_ed25519_produces_fingerprints | always sha-256, also for certificates signed with SHA-384 or SHA-512 |
| WEBRTC-4.9.2-4 | 4.9.2 | MUST | Certificates can be stored and retrieved with their keying material | tested | src/peer_connection/certificate/mod.rs:534 | test_certificate_serialize_pem_and_from_pem | PEM, private key in clear |
| WEBRTC-4.9.2-5 | 4.9.2 | SHOULD | Keying material is kept in a module safe from same-process memory attacks | partial | src/peer_connection/certificate/mod.rs:412 | non_exportable_signing_key_returns_an_explicit_pem_error | a SigningKey trait lets an HSM/KMS hold the key; the built-in providers keep it in process memory |
| WEBRTC-4.9.2-6 | 4.9.2 | MUST | Serialization keeps expires, certificate, origin and a handle to the key, not the key itself | partial | src/peer_connection/certificate/mod.rs:658 | test_certificate_serialize_pem_and_from_pem | expires and certificate kept; the key itself is written out; no origin |
| WEBRTC-4.9.2-7 | 4.9.2 | MUST | Deserialization restores expires, certificate, origin and key handle | tested | src/peer_connection/certificate/mod.rs:534 | test_certificate_serialize_pem_and_from_pem | |
| WEBRTC-5-1 | 5 | MUST | Video is not upscaled, not cropped beyond pixel-count limits, aspect ratio unchanged | n/a | - | - | No encoder or scaler |
| WEBRTC-5-2 | 5 | MUST | With scaleResolutionDownBy, never transmit larger than the integer part of the scaled size | n/a | - | - | No encoder or scaler |
| WEBRTC-5-3 | 5 | SHOULD | Track characteristics (size, rate, channels) are reasonably retained at the remote side | n/a | - | - | No encoder or decoder |
| WEBRTC-5-4 | 5 | MUST | Set of transceivers starts empty; sender and receiver are created with their transceiver and stay attached | partial | `src/rtp_transceiver/internal.rs:74` | - | A transceiver without a track has no sender, one without receive direction has no receiver |
| WEBRTC-5-5 | 5 | MUST | A remote offer associates new m= sections only with addTrack-created transceivers, never addTransceiver-created ones | tested | `src/rtp_transceiver/internal.rs:107`, `src/rtp_transceiver/mod.rs:299` | `test_remote_offer_skips_a_transceiver_that_is_not_associable` | The API layer has to set the flag; the engine default is associable for both |
| WEBRTC-5.1-1 | 5.1 | MUST | ontrack: a track event is surfaced to the application | tested | `src/peer_connection/event/mod.rs:518`, `src/peer_connection/handler/interceptor.rs:899` | `a_remote_track_is_labelled_remote_and_its_kind` | Fired on the first RTP packet, see 5.1.1 rows |
| WEBRTC-5.1-2 | 5.1 | MUST | getSenders / CollectSenders: the sender of every non-stopped transceiver, insertion order | violated | `src/peer_connection/mod.rs:2428` | - | Filters on direction having send, so recvonly and inactive transceivers' senders are missing and a stopped one is not excluded by its flag |
| WEBRTC-5.1-3 | 5.1 | MUST | getReceivers: the receiver of every non-stopped transceiver | violated | `src/peer_connection/mod.rs:2444` | - | Filters on direction having recv; sendonly transceivers' receivers are missing |
| WEBRTC-5.1-4 | 5.1 | MUST | getTransceivers / CollectTransceivers: all transceivers in insertion order | untested | `src/peer_connection/mod.rs:2460` | - | Ids are indices; removal of a stopped transceiver renumbers the later ones (take_removed_transceivers) |
| WEBRTC-5.1-5 | 5.1 | MUST | addTrack: InvalidStateError when the connection is closed | untested | `src/peer_connection/mod.rs:2500` | - | - |
| WEBRTC-5.1-6 | 5.1 | MUST | addTrack: InvalidAccessError when a sender for the track already exists | missing | `src/peer_connection/mod.rs:2499` | - | The same track id can be added twice |
| WEBRTC-5.1-7 | 5.1 | MUST | addTrack: reuse a sender only if its track is null, kind matches, transceiver not stopping, and it has never sent | partial | `src/peer_connection/mod.rs:2506` | `add_track_to_a_remote_offers_transceiver_sends_in_the_answer` | Reuses a transceiver with no sender of the same kind that is not stopped; "never used to send" is not tracked |
| WEBRTC-5.1-8 | 5.1 | MUST | addTrack reuse: set the sender track, replace associated stream ids with the given streams | partial | `src/peer_connection/mod.rs:2511` | `add_track_to_a_remote_offers_transceiver_sends_in_the_answer` | Stream ids come from the track's single stream id; no streams argument |
| WEBRTC-5.1-9 | 5.1 | MUST | addTrack reuse: recvonly becomes sendrecv, inactive becomes sendonly | tested | `src/peer_connection/mod.rs:2517` | `add_track_to_a_remote_offers_transceiver_sends_in_the_answer` | - |
| WEBRTC-5.1-10 | 5.1 | MUST | addTrack without a reusable sender: create sender, receiver and a sendrecv transceiver and add it to the set | tested | `src/peer_connection/mod.rs:2528`, `src/peer_connection/internal.rs:899` | `test_offer_has_one_msid_line_per_stream` | - |
| WEBRTC-5.1-11 | 5.1 | MUST | addTrack: content of an inaccessible (cross-origin) track is not transmitted | n/a | - | - | Browser origin concept |
| WEBRTC-5.1-12 | 5.1 | MUST | addTrack: update the negotiation-needed flag and return the sender | tested | `src/peer_connection/mod.rs:2523`, `src/peer_connection/internal.rs:1396` | `tests/negotiation_needed_send_without_sender.rs` | - |
| WEBRTC-5.1-13 | 5.1 | MUST | removeTrack: InvalidStateError when the connection is closed | untested | `src/peer_connection/mod.rs:2675` | - | - |
| WEBRTC-5.1-14 | 5.1 | MUST | removeTrack: InvalidAccessError when the sender was not created by this connection | partial | `src/peer_connection/mod.rs:2678` | - | Senders are indices into one connection; an out-of-range id is refused, a foreign one cannot be told apart |
| WEBRTC-5.1-15 | 5.1 | MUST | removeTrack: abort when the transceiver is stopping, the sender is not in getSenders, or its track is null | violated | `src/peer_connection/mod.rs:2681` | - | No such checks: the direction is rewritten and negotiation-needed raised even for a stopped transceiver or a sender without a track |
| WEBRTC-5.1-16 | 5.1 | MUST | removeTrack: set the sender's track to null; the sender still appears in getSenders | violated | `src/peer_connection/mod.rs:2691` | `test_rtp_sender_send_track_removed` | The sender object is dropped (`sender_mut().take()`), so getParameters, setStreams and stats by sender no longer work |
| WEBRTC-5.1-17 | 5.1 | MUST | removeTrack: sendrecv becomes recvonly, sendonly becomes inactive | untested | `src/peer_connection/mod.rs:2682` | - | - |
| WEBRTC-5.1-18 | 5.1 | MUST | removeTrack: update the negotiation-needed flag | untested | `src/peer_connection/mod.rs:2688` | - | Only raised when the sender existed |
| WEBRTC-5.1-19 | 5.1 | MUST | addTransceiver(kind): TypeError unless kind is audio or video | untested | `src/peer_connection/mod.rs:2787`, `src/peer_connection/internal.rs:1604` | - | Typed enum; `Unspecified` kind is not refused in add_transceiver_from_kind |
| WEBRTC-5.1-20 | 5.1 | MUST | addTransceiver(track): kind is the track's kind; any direction is accepted | violated | `src/peer_connection/mod.rs:2731` | - | A track with recvonly or inactive direction is refused (ErrInvalidDirection); listed in w2.md limits |
| WEBRTC-5.1-21 | 5.1 | MUST | addTransceiver: InvalidStateError when the connection is closed | untested | `src/peer_connection/mod.rs:2728`, `src/peer_connection/mod.rs:2792` | - | - |
| WEBRTC-5.1-22 | 5.1 | MUST | addTransceiver sendEncodings: TypeError for a rid not conforming to RFC 8851 section 10 | missing | `src/peer_connection/internal.rs:2163` | - | rid syntax is never checked |
| WEBRTC-5.1-23 | 5.1 | MUST | addTransceiver sendEncodings: TypeError when some but not all encodings have a rid | tested | `src/peer_connection/internal.rs:2190` | `test_rtp_sender_add_encoding` | - |
| WEBRTC-5.1-24 | 5.1 | MUST | addTransceiver sendEncodings: TypeError for duplicate rids | tested | `src/peer_connection/internal.rs:2197` | `test_rtp_sender_duplicate_rid_is_refused` | - |
| WEBRTC-5.1-25 | 5.1 | MUST | addTransceiver sendEncodings: InvalidAccessError for a read-only parameter other than rid | n/a | - | - | Engine takes ssrc/rtx/fec by design |
| WEBRTC-5.1-26 | 5.1 | MUST | addTransceiver sendEncodings: OperationError for a codec matching none of the send capabilities | untested | `src/peer_connection/internal.rs:2185` | - | `codec_preferences_from_encodings` returns an error for an unknown codec; no test |
| WEBRTC-5.1-27 | 5.1 | MUST | addTransceiver sendEncodings: for audio, remove scaleResolutionDownBy and maxFramerate | missing | `src/peer_connection/internal.rs:2163` | - | Not removed at addTransceiver (setParameters does remove them) |
| WEBRTC-5.1-28 | 5.1 | MUST | addTransceiver sendEncodings: RangeError for scaleResolutionDownBy below 1.0 | missing | `src/peer_connection/internal.rs:2163` | - | Checked only in setParameters |
| WEBRTC-5.1-29 | 5.1 | MUST | addTransceiver sendEncodings: RangeError for maxFramerate not greater than 0 | missing | `src/peer_connection/internal.rs:2163` | - | Checked only in setParameters |
| WEBRTC-5.1-30 | 5.1 | MUST | addTransceiver sendEncodings: trim to the maximum number of simultaneous encodings (at least 1) | missing | `src/peer_connection/internal.rs:2163` | - | No limit on the number of encodings |
| WEBRTC-5.1-31 | 5.1 | MUST | addTransceiver sendEncodings: fill scaleResolutionDownBy (1.0 where others have it; powers of two for video when none has) | missing | `src/peer_connection/internal.rs:2163` | - | Left unset |
| WEBRTC-5.1-32 | 5.1 | MUST | addTransceiver sendEncodings: a single remaining encoding loses its rid | missing | `src/peer_connection/internal.rs:2203` | - | A lone encoding keeps its rid and is offered as a one-layer simulcast |
| WEBRTC-5.1-33 | 5.1 | MUST | addTransceiver: create the sender with track, kind, streams and sendEncodings | tested | `src/peer_connection/internal.rs:1600`, `src/rtp_transceiver/internal.rs:74` | `a_send_direction_without_send_encodings_gets_one_encoding` | Without a track and with a send direction, a placeholder track with random ids is created |
| WEBRTC-5.1-34 | 5.1 | MUST | addTransceiver: create receiver and transceiver with the direction, add to the set | tested | `src/peer_connection/mod.rs:2836`, `src/peer_connection/internal.rs:899` | `add_transceiver_takes_inactive` | - |
| WEBRTC-5.1-35 | 5.1 | MUST | addTransceiver: update the negotiation-needed flag; return the transceiver; mid starts null | untested | `src/peer_connection/internal.rs:899` | - | - |
| WEBRTC-5.1-36 | 5.1 | MUST | RTCRtpTransceiverInit.direction defaults to sendrecv | violated | `src/peer_connection/mod.rs:2795` | - | add_transceiver_from_kind without init defaults to recvonly |
| WEBRTC-5.1-37 | 5.1 | MUST | RTCRtpTransceiverInit.streams: the stream ids signalled for the sender | untested | `src/rtp_transceiver/internal.rs:84`, `src/rtp_transceiver/rtp_sender/internal.rs:71` | - | - |
| WEBRTC-5.1-38 | 5.1 | MUST | RTCRtpTransceiverInit.sendEncodings | tested | `src/rtp_transceiver/internal.rs:84` | `explicit_send_encodings_get_an_rtx_flow` | - |
| WEBRTC-5.1-39 | 5.1 | MUST | RTCRtpTransceiverDirection "sendrecv": offers to send and receive; sends if accepted and an encoding is active | tested | `src/rtp_transceiver/direction.rs:18` | `test_rtp_transceiver_direction_change` | - |
| WEBRTC-5.1-40 | 5.1 | MUST | "sendonly": offers to send only; does not receive | untested | `src/rtp_transceiver/direction.rs:18` | - | - |
| WEBRTC-5.1-41 | 5.1 | MUST | "recvonly": offers to receive only; does not send | untested | `src/rtp_transceiver/direction.rs:18` | - | write_rtp does not check the negotiated direction |
| WEBRTC-5.1-42 | 5.1 | MUST | "inactive": neither sends nor receives | tested | `src/rtp_transceiver/direction.rs:41` | `test_rtp_transceiver_direction_change` | SDP only; write_rtp does not check the direction |
| WEBRTC-5.1-43 | 5.1 | MUST | "stopped": terminal value, zero port in offers | partial | `src/rtp_transceiver/internal.rs:210`, `src/rtp_transceiver/direction.rs:18` | `test_rtp_transceiver_stopping` | No `Stopped` enum value: a stopped transceiver reports inactive and a separate `stopped()` flag |
| WEBRTC-5.1.1-1 | 5.1.1 | MUST | process remote tracks: set the associated remote streams from the msids | partial | `src/peer_connection/internal.rs:1215`, `src/peer_connection/event/track_event.rs:66` | - | One stream id per track (the first msid); add/remove lists for changed msids are not produced |
| WEBRTC-5.1.1-2 | 5.1.1 | MUST | process remote tracks: direction now receiving and not fired before (or streams added): queue a track event | violated | `src/peer_connection/handler/interceptor.rs:899`, `src/peer_connection/internal.rs:1215` | `a_remote_track_is_labelled_remote_and_its_kind` | The track event fires on the first RTP packet of the stream, not when the remote description is applied; none fires for a track that never sends |
| WEBRTC-5.1.1-3 | 5.1.1 | MUST | process remote tracks: direction sendonly or inactive sets [[Receptive]] false | untested | `src/peer_connection/internal.rs:1215` | - | Receiving is gated on the receiver's bound streams |
| WEBRTC-5.1.1-4 | 5.1.1 | MUST | process remote tracks: direction no longer receiving after having fired: mute the track | missing | `src/media_stream/track.rs:526` | - | Nothing in the engine calls `set_muted`; no mute event |
| WEBRTC-5.1.1-5 | 5.1.1 | MUST | process remote tracks: remember [[FiredDirection]] | missing | `src/rtp_transceiver/internal.rs:40` | - | No such slot; a track that resumes gets no second event unless its SSRC is new |
| WEBRTC-5.1.1-6 | 5.1.1 | MUST | process the addition of a remote track: event carries receiver, track, streams, transceiver | partial | `src/peer_connection/event/track_event.rs:51` | - | Receiver id, track id, stream ids, ssrc, rid; the transceiver is the same index as the receiver |
| WEBRTC-5.1.1-7 | 5.1.1 | MUST | set the associated remote streams: one MediaStream per msid id, reused across tracks; removals and additions computed | partial | `src/peer_connection/internal.rs:1244` | - | Stream identity is the id string; removed streams are not reported |
| WEBRTC-5.2-1 | 5.2 | MUST | create an RTCRtpSender: slots SenderTrack, SenderTransport, AssociatedMediaStreamIds, SendEncodings, SendCodecs, LastReturnedParameters | partial | `src/rtp_transceiver/rtp_sender/internal.rs:40`, `src/rtp_transceiver/rtp_sender/internal.rs:65` | `test_rtp_sender_get_parameters` | No LastStableStateSenderTransport or LastStableRidlessSendEncodings; track is never null |
| WEBRTC-5.2-2 | 5.2 | MUST | create an RTCRtpSender: an audio sender gets an RTCDTMFSender | missing | `src/rtp_transceiver/rtp_sender/internal.rs:65` | - | RTCDTMFSender is not implemented (conformance.md, on purpose) |
| WEBRTC-5.2-3 | 5.2 | MUST | create an RTCRtpSender: associated stream ids are the given streams, deduplicated | partial | `src/rtp_transceiver/rtp_sender/internal.rs:71` | `test_offer_has_one_msid_line_per_stream` | Empty streams falls back to the track's stream id instead of the empty set; no deduplication |
| WEBRTC-5.2-4 | 5.2 | MUST | create an RTCRtpSender: without sendEncodings, one default encoding (video: scaleResolutionDownBy 1.0), active true | partial | `src/peer_connection/mod.rs:2800`, `src/rtp_transceiver/rtp_sender/internal.rs:65` | `a_send_direction_without_send_encodings_gets_one_encoding` | One active encoding; scaleResolutionDownBy stays unset until setParameters |
| WEBRTC-5.2-5 | 5.2 | MUST | track attribute returns [[SenderTrack]], which may be null | partial | `src/rtp_transceiver/rtp_sender/mod.rs:272` | - | Never null: removing the track removes the sender; `track()` unwraps and panics on a transceiver without a sender |
| WEBRTC-5.2-6 | 5.2 | MUST | An ended, disabled or muted track: black frames (video), nothing (audio); null track: nothing sent | n/a | - | - | Application supplies the packets |
| WEBRTC-5.2-7 | 5.2 | SHOULD | A disabled video track sends one black frame per second | n/a | - | - | Application supplies the packets |
| WEBRTC-5.2-8 | 5.2 | MUST | transport attribute: null before the DTLS transport exists, else the shared transport | untested | `src/rtp_transceiver/rtp_sender/mod.rs:258` | - | Some once the transceiver has a mid |
| WEBRTC-5.2-9 | 5.2 | MUST | getCapabilities(kind): null for a kind that is neither audio nor video | untested | `src/rtp_transceiver/rtp_sender/internal.rs:127` | - | - |
| WEBRTC-5.2-10 | 5.2 | MUST | getCapabilities(kind): the implemented send codecs and header extensions for the kind, with no state needed | violated | `src/rtp_transceiver/rtp_sender/internal.rs:122` | - | Not static: needs a sender, and lists that sender's negotiated/preferred codecs (empty before negotiation), not the engine's codecs for the kind |
| WEBRTC-5.2-11 | 5.2 | MAY | getCapabilities may report a reduced set in privacy-sensitive contexts | n/a | - | - | Browser privacy mitigation |
| WEBRTC-5.2-12 | 5.2 | MUST | setParameters: InvalidStateError when the transceiver is stopping | tested | `src/rtp_transceiver/rtp_sender/mod.rs:313` | `a_stopped_transceivers_sender_takes_no_parameters` | - |
| WEBRTC-5.2-13 | 5.2 | MUST | setParameters: InvalidStateError when [[LastReturnedParameters]] is null | tested | `src/rtp_transceiver/rtp_sender/internal.rs:178` | `set_parameters_needs_the_last_returned_parameters` | - |
| WEBRTC-5.2-14 | 5.2 | MUST | setParameters: InvalidModificationError when the number of encodings differs | untested | `src/rtp_transceiver/rtp_sender/internal.rs:189` | - | - |
| WEBRTC-5.2-15 | 5.2 | MUST | setParameters: InvalidModificationError when encodings are re-ordered | partial | `src/rtp_transceiver/rtp_sender/internal.rs:192` | - | Detected only through differing rids; rid-less encodings cannot be told apart |
| WEBRTC-5.2-16 | 5.2 | MUST | setParameters: InvalidModificationError when a read-only parameter or the transactionId differs | tested | `src/rtp_transceiver/rtp_sender/internal.rs:181`, `src/rtp_transceiver/rtp_sender/internal.rs:184` | `set_parameters_checks_the_transaction_id`, `set_parameters_refuses_a_changed_read_only_member` | ssrc, rtx and fec of an encoding are not compared |
| WEBRTC-5.2-17 | 5.2 | MUST | setParameters: InvalidModificationError when an encoding's codec is not among the choosable codecs | missing | `src/rtp_transceiver/rtp_sender/internal.rs:172` | - | The codec member is stored unchecked; write_rtp later fails or falls back |
| WEBRTC-5.2-18 | 5.2 | MUST | setParameters: for audio remove scaleResolutionDownBy and maxFramerate | untested | `src/rtp_transceiver/rtp_sender/internal.rs:220` | - | - |
| WEBRTC-5.2-19 | 5.2 | MUST | setParameters: for video default scaleResolutionDownBy to 1.0; RangeError below 1.0 | untested | `src/rtp_transceiver/rtp_sender/internal.rs:197` | - | - |
| WEBRTC-5.2-20 | 5.2 | MUST | setParameters: RangeError for a negative maxFramerate | tested | `src/rtp_transceiver/rtp_sender/internal.rs:210` | `set_parameters_refuses_a_negative_max_framerate` | - |
| WEBRTC-5.2-21 | 5.2 | MUST | setParameters: OperationError if per-encoding or mixed codecs are not supported | n/a | - | - | Engine sends any negotiated codec |
| WEBRTC-5.2-22 | 5.2 | MUST | setParameters: apply to the media stack, then clear [[LastReturnedParameters]] and store the encodings | tested | `src/rtp_transceiver/rtp_sender/internal.rs:226` | `an_inactive_encoding_is_a_paused_rid` | active=false stops write_rtp for that encoding; maxBitrate, maxFramerate, scaleResolutionDownBy are stored for the application |
| WEBRTC-5.2-23 | 5.2 | MUST | setParameters failure: RTCError hardware-encoder-not-available / hardware-encoder-error, else OperationError | n/a | - | - | No encoder in the engine |
| WEBRTC-5.2-24 | 5.2 | MUST | getParameters: return [[LastReturnedParameters]] when set | untested | `src/rtp_transceiver/rtp_sender/internal.rs:249` | - | - |
| WEBRTC-5.2-25 | 5.2 | MUST | getParameters: a new unique transactionId and the current encodings | tested | `src/rtp_transceiver/rtp_sender/internal.rs:256` | `test_rtp_sender_get_parameters` | - |
| WEBRTC-5.2-26 | 5.2 | MUST | getParameters: headerExtensions are those negotiated for sending | partial | `src/rtp_transceiver/rtp_sender/internal.rs:251`, `src/peer_connection/configuration/media_engine.rs:1252` | - | Connection-wide negotiated set for the kind, not this m= section's; before negotiation all registered extensions are listed |
| WEBRTC-5.2-27 | 5.2 | MUST | getParameters: codecs is [[SendCodecs]] | tested | `src/rtp_transceiver/rtp_sender/internal.rs:253` | `a_renegotiated_codec_rebinds_the_senders_stream` | - |
| WEBRTC-5.2-28 | 5.2 | MUST | getParameters: rtcp.cname is the connection's CNAME; rtcp.reducedSize reflects negotiation | missing | `src/peer_connection/configuration/media_engine.rs:1252` | - | Both members are always the default (empty string, false) |
| WEBRTC-5.2-29 | 5.2 | MUST | getParameters: [[LastReturnedParameters]] is cleared at the end of the task | n/a | - | - | No event loop; cached until setParameters or a codec change |
| WEBRTC-5.2-30 | 5.2 | MUST | replaceTrack: TypeError when the new track's kind differs | tested | `src/rtp_transceiver/rtp_sender/internal.rs:282` | `test_rtp_sender_replace_track_invalid_track_kind_change` | - |
| WEBRTC-5.2-31 | 5.2 | MUST | replaceTrack: InvalidStateError when the transceiver is stopping | missing | `src/rtp_transceiver/rtp_sender/mod.rs:358` | - | No check |
| WEBRTC-5.2-32 | 5.2 | MUST | replaceTrack(null): the sender stops sending and its track becomes null | missing | `src/rtp_transceiver/rtp_sender/mod.rs:358` | - | The argument is not optional |
| WEBRTC-5.2-33 | 5.2 | MUST | replaceTrack: InvalidModificationError when the track cannot be sent within the negotiated envelope | untested | `src/rtp_transceiver/rtp_sender/internal.rs:281` | `test_rtp_sender_replace_track_invalid_codec_change` | The test name suggests a codec check; `replace_track` itself checks kind only |
| WEBRTC-5.2-34 | 5.2 | MUST | replaceTrack: switch to the new track without renegotiation; set [[SenderTrack]] | partial | `src/rtp_transceiver/rtp_sender/internal.rs:285` | `test_rtp_sender_replace_track` | Also replaces the associated stream ids with the new track's, which changes the msid and needs negotiation |
| WEBRTC-5.2-35 | 5.2 | MUST | replaceTrack: runs on the operations chain; no-op once the connection is closed | n/a | - | - | Synchronous API |
| WEBRTC-5.2-36 | 5.2 | MUST | setStreams: InvalidStateError when the connection is closed | missing | `src/rtp_transceiver/rtp_sender/mod.rs:373` | - | No check |
| WEBRTC-5.2-37 | 5.2 | MUST | setStreams: associated stream ids become exactly the given ids, deduplicated (possibly empty) | partial | `src/rtp_transceiver/rtp_sender/internal.rs:309` | `set_streams_raises_negotiation_needed_until_the_msid_follows` | An empty list falls back to the track's stream id; duplicates kept |
| WEBRTC-5.2-38 | 5.2 | MUST | setStreams: update the negotiation-needed flag | tested | `src/rtp_transceiver/rtp_sender/mod.rs:380` | `set_streams_raises_negotiation_needed_until_the_msid_follows` | - |
| WEBRTC-5.2-39 | 5.2 | MUST | sender.getStats: the stats selection algorithm with the sender as selector | tested | `src/statistics/accumulator/mod.rs:303` | `test_stats_selector_sender_filters_outbound` | - |
| WEBRTC-5.2.1-1 | 5.2.1 | MUST | RTCRtpParameters.headerExtensions (read-only) | tested | `src/rtp_transceiver/rtp_sender/rtp_parameters.rs:13` | `set_parameters_refuses_a_changed_read_only_member` | - |
| WEBRTC-5.2.1-2 | 5.2.1 | MUST | RTCRtpParameters.rtcp (read-only) | partial | `src/rtp_transceiver/rtp_sender/rtp_parameters.rs:15` | - | Present, never filled |
| WEBRTC-5.2.1-3 | 5.2.1 | MUST | RTCRtpParameters.codecs (read-only): media codecs plus RTX, RED, FEC entries with apt in sdpFmtpLine | tested | `src/rtp_transceiver/rtp_sender/rtp_parameters.rs:17` | `test_rtp_sender_rtx` | - |
| WEBRTC-5.2.2-1 | 5.2.2 | MUST | RTCRtpSendParameters.transactionId | tested | `src/rtp_transceiver/rtp_sender/internal.rs:256` | `set_parameters_checks_the_transaction_id` | - |
| WEBRTC-5.2.2-2 | 5.2.2 | MUST | RTCRtpSendParameters.encodings | tested | `src/rtp_transceiver/rtp_sender/internal.rs:257` | `test_rtp_sender_get_parameters_with_rid` | - |
| WEBRTC-5.2.3-1 | 5.2.3 | MUST | RTCRtpReceiveParameters: headerExtensions, rtcp, codecs | tested | `src/rtp_transceiver/rtp_receiver/internal.rs:105` | `test_set_rtp_parameters` | - |
| WEBRTC-5.2.4-1 | 5.2.4 | MUST | RTCRtpCodingParameters.rid: sent as the RID header extension; read-only after addTransceiver | tested | `src/rtp_transceiver/rtp_sender/rtp_coding_parameters.rs:1`, `src/rtp_transceiver/rtp_sender/internal.rs:192` | `tests/simulcast_rtc_to_rtc_interop.rs` | The application writes the RID extension into its packets |
| WEBRTC-5.2.5-1 | 5.2.5 | MUST | RTCRtpEncodingParameters.active (default true): false stops sending that encoding, no BYE | tested | `src/rtp_transceiver/rtp_sender/mod.rs:432` | `an_inactive_encoding_is_a_paused_rid` | Rust `Default` gives false; the engine's own constructors set true |
| WEBRTC-5.2.5-2 | 5.2.5 | SHOULD | RTCRtpEncodingParameters.codec: send with the first [[SendCodecs]] entry matching it | tested | `src/rtp_transceiver/rtp_sender/mod.rs:440` | `an_encoding_without_a_codec_is_repaired_over_rtx` | Used to rewrite the payload type of a packet whose own type is not negotiated |
| WEBRTC-5.2.5-3 | 5.2.5 | MUST | RTCRtpEncodingParameters.maxBitrate: an upper bound the sender never exceeds | partial | `src/rtp_transceiver/rtp_sender/rtp_encoding_parameters.rs:1` | - | Carried (u32, 0 for unset) but enforced by nothing: neither the pacer nor the congestion controller reads it |
| WEBRTC-5.2.5-4 | 5.2.5 | MUST | RTCRtpEncodingParameters.maxFramerate (video only) | partial | `src/rtp_transceiver/rtp_sender/internal.rs:210` | `set_parameters_refuses_a_negative_max_framerate` | Carried and validated; applying it is the encoder's job |
| WEBRTC-5.2.5-5 | 5.2.5 | MUST | RTCRtpEncodingParameters.scaleResolutionDownBy (video only, at least 1.0) | partial | `src/rtp_transceiver/rtp_sender/internal.rs:197` | - | Carried and validated in setParameters only |
| WEBRTC-5.2.6-1 | 5.2.6 | MUST | RTCRtcpParameters.cname | missing | `src/rtp_transceiver/rtp_sender/rtcp_parameters.rs:9` | - | Field exists, always empty; the CNAME lives in the SDES interceptor path |
| WEBRTC-5.2.6-2 | 5.2.6 | MUST | RTCRtcpParameters.reducedSize | missing | `src/rtp_transceiver/rtp_sender/rtcp_parameters.rs:11` | - | Field exists, always false |
| WEBRTC-5.2.7-1 | 5.2.7 | MUST | RTCRtpHeaderExtensionParameters.uri | tested | `src/peer_connection/configuration/media_engine.rs:1269` | `tests/extmap_renegotiation.rs` | - |
| WEBRTC-5.2.7-2 | 5.2.7 | MUST | RTCRtpHeaderExtensionParameters.id | tested | `src/peer_connection/configuration/media_engine.rs:1269` | `tests/extmap_renegotiation.rs` | - |
| WEBRTC-5.2.7-3 | 5.2.7 | MUST | RTCRtpHeaderExtensionParameters.encrypted | missing | `src/rtp_transceiver/rtp_sender/rtp_header_extension_parameters.rs:16` | - | Always false, also when Cryptex is negotiated |
| WEBRTC-5.2.7-4 | 5.2.7 | MUST | A header extension's direction is observable as presence in sender and/or receiver getParameters | untested | `src/peer_connection/configuration/media_engine.rs:1265` | - | `is_matching_direction` filters; no test reads both sides |
| WEBRTC-5.2.8-1 | 5.2.8 | MUST | RTCRtpCodec.mimeType | tested | `src/rtp_transceiver/rtp_sender/rtp_codec.rs:74` | `test_rtp_transceiver_set_codec_preferences` | - |
| WEBRTC-5.2.8-2 | 5.2.8 | MUST | RTCRtpCodec.clockRate | tested | `src/rtp_transceiver/rtp_sender/rtp_codec.rs:76` | `tests/codec_negotiation.rs` | - |
| WEBRTC-5.2.8-3 | 5.2.8 | MUST | RTCRtpCodec.channels: present only when the codec has channels | tested | `src/rtp_transceiver/rtp_sender/rtp_codec.rs:78` | `tests/codec_negotiation.rs` | 0 stands for absent |
| WEBRTC-5.2.8-4 | 5.2.8 | MUST | RTCRtpCodec.sdpFmtpLine | tested | `src/rtp_transceiver/rtp_sender/rtp_codec.rs:80` | `tests/jsep_av1_fmtp.rs` | Empty string stands for absent |
| WEBRTC-5.2.9-1 | 5.2.9 | MUST | RTCRtpCodecParameters.payloadType; inherited members read-only | tested | `src/rtp_transceiver/rtp_sender/rtp_codec_parameters.rs:17` | `test_rtp_transceiver_set_codec_preferences_payload_type` | - |
| WEBRTC-5.2.9-2 | 5.2.9 | MUST | Sender sdpFmtpLine comes from the current remote description; receiver's from the local description | untested | `src/rtp_transceiver/internal.rs:325` | - | Sender codecs are matched against the remote section; no test reads the fmtp on each side |
| WEBRTC-5.2.10-1 | 5.2.10 | MUST | RTCRtpCapabilities.codecs: one entry per distinct payload type combination, RTX/RED/FEC included | partial | `src/rtp_transceiver/rtp_sender/internal.rs:132` | - | See 5.2-10: per-sender list |
| WEBRTC-5.2.10-2 | 5.2.10 | MUST | RTCRtpCapabilities.codecs has a single RTX entry without sdpFmtpLine | violated | `src/rtp_transceiver/rtp_sender/internal.rs:132` | - | One rtx entry per apt, each with its fmtp |
| WEBRTC-5.2.10-3 | 5.2.10 | MUST | RTCRtpCapabilities.headerExtensions | untested | `src/rtp_transceiver/rtp_sender/internal.rs:142` | - | - |
| WEBRTC-5.2.11-1 | 5.2.11 | MUST | RTCRtpHeaderExtensionCapability.uri | untested | `src/rtp_transceiver/rtp_sender/internal.rs:145` | - | - |
| WEBRTC-5.2.12-1 | 5.2.12 | MUST | RTCSetParameterOptions: an empty, extensible dictionary | tested | `src/rtp_transceiver/rtp_sender/internal.rs:175` | `set_parameters_needs_the_last_returned_parameters` | Accepted and ignored |
| WEBRTC-5.3-1 | 5.3 | MUST | create an RTCRtpReceiver: a new track with a UA-generated id not mapped to the remote's | violated | `src/peer_connection/internal.rs:1249` | `a_remote_track_is_labelled_remote_and_its_kind` | The track and stream ids are taken from the remote msid; before a remote description the track is an empty default |
| WEBRTC-5.3-2 | 5.3 | MUST | create an RTCRtpReceiver: track kind is the kind, label is "remote " + kind, readyState live | tested | `src/peer_connection/internal.rs:1251` | `a_remote_track_is_labelled_remote_and_its_kind` | - |
| WEBRTC-5.3-3 | 5.3 | MUST | create an RTCRtpReceiver: the track starts muted | violated | `src/media_stream/track.rs:179` | - | Tracks are created unmuted and the engine never changes it |
| WEBRTC-5.3-4 | 5.3 | MUST | create an RTCRtpReceiver: slots ReceiverTransport, AssociatedRemoteMediaStreams, ReceiveCodecs and their LastStableState copies, JitterBufferTarget | partial | `src/rtp_transceiver/rtp_receiver/internal.rs:23` | - | ReceiveCodecs and a jitter-buffer field only; no last-stable-state copies (rollback restores from elsewhere) |
| WEBRTC-5.3-5 | 5.3 | MUST | track attribute returns [[ReceiverTrack]] | tested | `src/rtp_transceiver/rtp_receiver/mod.rs:234` | `a_remote_track_is_labelled_remote_and_its_kind` | - |
| WEBRTC-5.3-6 | 5.3 | MUST | transport attribute: null before the DTLS transport exists | untested | `src/rtp_transceiver/rtp_receiver/mod.rs:213` | - | - |
| WEBRTC-5.3-7 | 5.3 | MUST | jitterBufferTarget getter returns [[JitterBufferTarget]] | missing | `src/rtp_transceiver/rtp_receiver/internal.rs:38` | - | Private field, no accessor |
| WEBRTC-5.3-8 | 5.3 | MUST | jitterBufferTarget setter: RangeError when negative or above 4000 ms; store the target | missing | `src/rtp_transceiver/rtp_receiver/internal.rs:38` | - | No setter |
| WEBRTC-5.3-9 | 5.3 | MUST | jitterBufferTarget: the system applies the target, clamped to its minimum and maximum allowed targets | missing | `rtc-interceptor/src/jitterbuffer` | - | The jitter-buffer interceptors take their delay at construction, not from the receiver |
| WEBRTC-5.3-10 | 5.3 | SHOULD | jitterBufferTarget: synchronized receivers use the larger target; changes are applied gradually | n/a | - | - | Playout is the application's |
| WEBRTC-5.3-11 | 5.3 | MUST | getCapabilities(kind): null for other kinds; else implemented receive codecs and header extensions | violated | `src/rtp_transceiver/rtp_receiver/internal.rs:73` | - | Same defect as 5.2-10: per-receiver negotiated list, empty before negotiation |
| WEBRTC-5.3-12 | 5.3 | MUST | getParameters: header extensions the receiver is prepared to receive | partial | `src/rtp_transceiver/rtp_receiver/internal.rs:109` | `test_set_rtp_parameters` | Connection-wide set for the kind |
| WEBRTC-5.3-13 | 5.3 | MUST | getParameters: codecs is [[ReceiveCodecs]], narrowed by the remote answer | tested | `src/rtp_transceiver/rtp_receiver/internal.rs:112` | `test_set_rtp_parameters` | - |
| WEBRTC-5.3-14 | 5.3 | MUST | getParameters: rtcp.reducedSize reflects what is negotiated; cname left out | missing | `src/rtp_transceiver/rtp_receiver/internal.rs:109` | - | Always false |
| WEBRTC-5.3-15 | 5.3 | MUST | getContributingSources: one entry per CSRC received in the last 10 seconds, newest first | missing | `src/rtp_transceiver/rtp_receiver/internal.rs:122` | - | The list is never filled: always empty |
| WEBRTC-5.3-16 | 5.3 | MUST | getSynchronizationSources: one entry per SSRC received in the last 10 seconds, newest first | missing | `src/rtp_transceiver/rtp_receiver/internal.rs:128` | - | The list is never filled: always empty |
| WEBRTC-5.3-17 | 5.3 | MUST | Sources are updated when a frame is delivered to the track, also without a sink | missing | `src/rtp_transceiver/rtp_receiver/internal.rs:26` | - | No update path |
| WEBRTC-5.3-18 | 5.3 | MUST | RTCRtpContributingSource.timestamp: delivery time of the latest frame from the source | missing | `src/rtp_transceiver/rtp_receiver/rtp_contributing_source.rs:1` | - | Field only |
| WEBRTC-5.3-19 | 5.3 | MUST | RTCRtpContributingSource.source: the CSRC or SSRC | missing | `src/rtp_transceiver/rtp_receiver/rtp_contributing_source.rs:1` | - | Field only |
| WEBRTC-5.3-20 | 5.3 | MUST | audioLevel for CSRCs from the RFC 6465 extension, absent without it; converted 10^(-level/20), 127 to 0 | missing | `src/rtp_transceiver/rtp_receiver/rtp_contributing_source.rs:1` | - | Field is a plain f64 (cannot be absent); no conversion code |
| WEBRTC-5.3-21 | 5.3 | MUST | audioLevel for SSRCs from the RFC 6464 extension | missing | `src/rtp_transceiver/rtp_receiver/rtp_contributing_source.rs:1` | - | rtc-rtp parses the extension; nothing connects it |
| WEBRTC-5.3-22 | 5.3 | SHOULD | audioLevel for SSRCs is absent when the RFC 6464 extension is not received | missing | `src/rtp_transceiver/rtp_receiver/rtp_contributing_source.rs:1` | - | Not optional in the struct |
| WEBRTC-5.3-23 | 5.3 | MUST | RTCRtpContributingSource.rtpTimestamp of the media played out | missing | `src/rtp_transceiver/rtp_receiver/rtp_contributing_source.rs:1` | - | Field only |
| WEBRTC-5.3-24 | 5.3 | MUST | RTCRtpSynchronizationSource dictionary | missing | `src/rtp_transceiver/rtp_receiver/rtp_contributing_source.rs:1` | - | Type alias, never produced |
| WEBRTC-5.3-25 | 5.3 | MUST | receiver.getStats: the stats selection algorithm with the receiver as selector | tested | `src/statistics/accumulator/mod.rs:384` | `test_stats_selector_receiver_filters_inbound` | - |
| WEBRTC-5.3-26 | 5.3 | MUST | Stopping the receiver's track does not stop the receiver: receiver reports continue | untested | `src/media_stream/track.rs:557` | - | - |
| WEBRTC-5.4-1 | 5.4 | MUST | create an RTCRtpTransceiver: slots Sender, Receiver, Stopping, Stopped, Direction, Receptive, CurrentDirection, FiredDirection, PreferredCodecs, JsepMid, Mid | partial | `src/rtp_transceiver/internal.rs:27`, `src/rtp_transceiver/internal.rs:74` | - | One `stopped` flag for Stopping and Stopped; no Receptive, FiredDirection or separate JsepMid |
| WEBRTC-5.4-2 | 5.4 | MUST | Creating a transceiver creates no DTLS or ICE transport objects | n/a | - | - | One transport, always present |
| WEBRTC-5.4-3 | 5.4 | MUST | mid attribute returns [[Mid]], null until negotiated | tested | `src/rtp_transceiver/mod.rs:235` | `tests/jsep_sections_without_mid.rs` | - |
| WEBRTC-5.4-4 | 5.4 | MUST | sender attribute returns [[Sender]] | partial | `src/rtp_transceiver/mod.rs:244` | - | None when the transceiver was created without a track |
| WEBRTC-5.4-5 | 5.4 | MUST | receiver attribute returns [[Receiver]] | partial | `src/rtp_transceiver/mod.rs:260` | - | None when the transceiver was created without a receive direction |
| WEBRTC-5.4-6 | 5.4 | MUST | direction getter: "stopped" when stopping, else [[Direction]] | partial | `src/rtp_transceiver/internal.rs:169` | `test_rtp_transceiver_stopping` | Returns inactive for a stopped transceiver; `stopped()` is separate |
| WEBRTC-5.4-7 | 5.4 | MUST | direction setter: InvalidStateError when stopping | missing | `src/rtp_transceiver/mod.rs:343` | - | A stopped transceiver's direction can be set, and negotiation-needed is raised |
| WEBRTC-5.4-8 | 5.4 | MUST | direction setter: no-op when unchanged | tested | `src/rtp_transceiver/mod.rs:347` | `test_set_direction_noop_when_unchanged` | - |
| WEBRTC-5.4-9 | 5.4 | MUST | direction setter: TypeError for "stopped" | n/a | - | - | No such enum value; `Unspecified` is accepted unchecked |
| WEBRTC-5.4-10 | 5.4 | MUST | direction setter: store and update the negotiation-needed flag | tested | `src/rtp_transceiver/mod.rs:343`, `src/peer_connection/internal.rs:1385` | `test_set_direction_triggers_negotiation_on_change`, `test_set_direction_updates_negotiation_needed_flag` | - |
| WEBRTC-5.4-11 | 5.4 | MUST | currentDirection: "stopped" when stopped, else [[CurrentDirection]], null before any negotiation | partial | `src/rtp_transceiver/internal.rs:198`, `src/rtp_transceiver/internal.rs:227` | - | `Unspecified` stands for null; a stopped transceiver reports inactive |
| WEBRTC-5.4-12 | 5.4 | MUST | stop(): InvalidStateError when the connection is closed | missing | `src/rtp_transceiver/mod.rs:391` | - | No check |
| WEBRTC-5.4-13 | 5.4 | MUST | stop(): no-op when already stopping | tested | `src/rtp_transceiver/internal.rs:215`, `src/rtp_transceiver/mod.rs:397` | `stop_raises_negotiation_needed_and_settles_once_rejected` | - |
| WEBRTC-5.4-14 | 5.4 | MUST | stop(): stop sending and receiving, then update the negotiation-needed flag | tested | `src/rtp_transceiver/mod.rs:391` | `stop_raises_negotiation_needed_and_settles_once_rejected` | - |
| WEBRTC-5.4-15 | 5.4 | MUST | stop sending and receiving: stop the sender and send an RTCP BYE for each RTP stream it sent | untested | `src/rtp_transceiver/rtp_sender/internal.rs:338`, `rtc-interceptor/src/report/sender.rs:376` | - | The sender-report interceptor emits a BYE on unbind; no test reads a BYE after stop() |
| WEBRTC-5.4-16 | 5.4 | MUST | stop sending and receiving: stop receiving media | untested | `src/rtp_transceiver/rtp_receiver/internal.rs:232` | - | Remote streams are unbound |
| WEBRTC-5.4-17 | 5.4 | MUST | stop sending and receiving: the receiver's track ends (event) unless disappear | missing | `src/rtp_transceiver/rtp_receiver/internal.rs:232` | - | The track is not ended and no OnClose is emitted on stop(); only a remote BYE ends it |
| WEBRTC-5.4-18 | 5.4 | MUST | stop sending and receiving: [[Direction]] becomes inactive, [[Stopping]] true | tested | `src/rtp_transceiver/internal.rs:226` | `test_rtp_transceiver_stopping` | - |
| WEBRTC-5.4-19 | 5.4 | MUST | A stopping transceiver is offered with a zero port but does not affect createAnswer until stopped | partial | `src/rtp_transceiver/internal.rs:219` | `a_rejected_section_is_recycled_for_a_new_transceiver`, `test_rtp_transceiver_stopping` | No stopping state: stop() is stopped at once, so an answer made right after stop() rejects the section (w2.md limit) |
| WEBRTC-5.4-20 | 5.4 | MUST | stop the RTCRtpTransceiver (rejected m= section): Stopped true, Receptive false, CurrentDirection null, remote streams cleared | partial | `src/rtp_transceiver/internal.rs:210` | `a_rejected_section_in_a_remote_offer_stops_its_transceiver` | CurrentDirection becomes inactive rather than null; no stream lists to clear |
| WEBRTC-5.4-21 | 5.4 | MUST | A stopping transceiver always needs negotiation until stopped | tested | `src/peer_connection/internal.rs:1470` | `stop_raises_negotiation_needed_and_settles_once_rejected`, `a_stopped_transceiver_that_never_had_a_section_needs_none` | - |
| WEBRTC-5.4-22 | 5.4 | MUST | createOffer / createAnswer filter preferred codecs on direction and use them in the given order | partial | `src/rtp_transceiver/rtp_receiver/internal.rs:134`, `src/rtp_transceiver/internal.rs:277` | `test_rtp_transceiver_set_codec_preferences`, `leaving_rtx_out_of_the_preferences_removes_it` | Order and subset are honoured; no filtering by direction (send-only versus receive-only codecs) |
| WEBRTC-5.4-23 | 5.4 | MUST | setCodecPreferences([]) resets to the default preferences | untested | `src/rtp_transceiver/internal.rs:245` | - | - |
| WEBRTC-5.4-24 | 5.4 | MUST | setCodecPreferences: remove duplicate codecs, keeping the first | missing | `src/rtp_transceiver/internal.rs:245` | - | Duplicates are kept |
| WEBRTC-5.4-25 | 5.4 | MUST | setCodecPreferences: InvalidModificationError for a codec matching none of the send or receive capabilities | partial | `src/rtp_transceiver/internal.rs:250` | `test_rtp_transceiver_set_codec_preferences` | A mime-type-only match is accepted, so a wrong clockRate, channels or fmtp passes |
| WEBRTC-5.4-26 | 5.4 | MUST | setCodecPreferences: InvalidModificationError when only RTX, RED, FEC or CN entries are given | missing | `src/rtp_transceiver/internal.rs:245` | - | Accepted; the next offer has a section with only repair formats |
| WEBRTC-5.4-27 | 5.4 | MUST | setCodecPreferences: preferences stay in effect for all later offers and answers | tested | `src/rtp_transceiver/internal.rs:268` | `test_rtp_transceiver_set_codec_preferences_payload_type` | A remote description overwrites them with the negotiated intersection (set_codec_preferences_from_remote_description) |
| WEBRTC-5.4-28 | 5.4 | MUST | codec dictionary match: mimeType compared ASCII case-insensitively | tested | `src/rtp_transceiver/rtp_sender/rtp_codec.rs:182` | `tests/codec_negotiation.rs` | - |
| WEBRTC-5.4-29 | 5.4 | MUST | codec dictionary match: clockRate must be equal | violated | `src/rtp_transceiver/rtp_sender/rtp_codec.rs:165` | - | `codec_parameters_fuzzy_search` never compares clockRate |
| WEBRTC-5.4-30 | 5.4 | MUST | codec dictionary match: channels must both be absent or equal | violated | `src/rtp_transceiver/rtp_sender/rtp_codec.rs:165` | - | channels are never compared |
| WEBRTC-5.4-31 | 5.4 | MUST | codec dictionary match: sdpFmtpLine present on one side only is no match; non key-value lines compared by equality | partial | `src/rtp_transceiver/rtp_sender/rtp_codec.rs:169`, `src/rtp_transceiver/fmtp/generic/mod.rs:1` | `src/rtp_transceiver/fmtp/generic/generic_test.rs` | An exact fmtp match is preferred, but a mime-only "partial" match is then accepted by every caller |
| WEBRTC-5.4-32 | 5.4 | MUST | codec dictionary match: symmetrical parameters must be equal; asymmetrical ones compared unless ignored | partial | `src/rtp_transceiver/fmtp/h264/mod.rs:1` | `src/rtp_transceiver/fmtp/h264/h264_test.rs` | H.264 profile and packetization-mode rules only; no ignoreAsymmetricalParameters switch; other codecs compare all pairs |
| WEBRTC-5.4.1-1 | 5.4.1 | MUST | Simulcast sending is set up by addTransceiver sendEncodings | tested | `src/peer_connection/internal.rs:2196` | `tests/simulcast_rtc_to_rtc_interop.rs` | - |
| WEBRTC-5.4.1-2 | 5.4.1 | MUST | A remote offer to receive simulcast promotes an addTrack sender: encodings and rids taken from the offer | untested | `src/peer_connection/internal.rs:1111` | `tests/simulcast_recv_offer_answer.rs` | Not verified that send encodings are rebuilt from the offer's rids |
| WEBRTC-5.4.1-3 | 5.4.1 | MUST | The simulcast envelope may be narrowed by renegotiation but never re-expanded; setParameters cannot change it | partial | `src/rtp_transceiver/rtp_sender/internal.rs:189` | - | setParameters keeps the count; narrowing by an answer with fewer rids is not applied to the encodings |
| WEBRTC-5.4.1-4 | 5.4.1 | MUST | Offers carry only a "send" a=simulcast description, no alternatives or restrictions | tested | `src/peer_connection/sdp/mod.rs:1` | `tests/simulcast_rtx_rrid.rs` | - |
| WEBRTC-5.4.1-5 | 5.4.1 | MUST | setParameters active=false pauses one simulcast stream without negotiation | tested | `src/rtp_transceiver/rtp_sender/mod.rs:432` | `an_inactive_encoding_is_a_paused_rid` | - |
| WEBRTC-5.4.1-6 | 5.4.1 | SHOULD | Bandwidth is allocated so every simulcast stream is usable on its own | n/a | - | - | Encoder allocation is the application's |
| WEBRTC-5.4.1-7 | 5.4.1 | MAY | A receiver that gets several RTP streams (SFU switching) delivers one track | tested | `src/peer_connection/handler/interceptor.rs:2081` | `tests/simulcast_webrtc_to_rtc_interop.rs` | One track per receiver; each rid's SSRC is bound as it appears |
| WEBRTC-5.4.2-1 | 5.4.2 | MUST | Hold: direction plus replaceTrack give music-on-hold and resume without a new transceiver | partial | `src/rtp_transceiver/mod.rs:343`, `src/rtp_transceiver/rtp_sender/mod.rs:358` | `test_set_direction_change_triggers_renegotiation` | Direction part works; replaceTrack(null) does not exist |
| WEBRTC-5.5-1 | 5.5 | MUST | RTCDtlsTransport: one object per transport, reused by a new DTLS association | tested | `src/peer_connection/transport/mod.rs:340`, `src/peer_connection/transport/dtls/mod.rs:334` | `restart_from_connected_as_client` | - |
| WEBRTC-5.5-2 | 5.5 | MUST | [[DtlsTransportState]] starts "new"; [[RemoteCertificates]] starts empty | tested | `src/peer_connection/transport/dtls/mod.rs:112` | `remote_certificates_are_empty_until_the_handshake_supplies_them` | - |
| WEBRTC-5.5-3 | 5.5 | MUST | DTLS error (certificate validation failure, fatal alert): state becomes "failed", once | tested | `src/peer_connection/handler/dtls.rs:514` | `a_fingerprint_mismatch_fails_the_dtls_transport_and_the_connection` | - |
| WEBRTC-5.5-4 | 5.5 | MUST | DTLS error: an error event with errorDetail dtls-failure or fingerprint-failure and the alert fields | missing | `src/peer_connection/handler/dtls.rs:514` | - | No error event; the application sees only the connection state go to failed |
| WEBRTC-5.5-5 | 5.5 | MUST | DTLS state change: a statechange event at the transport | missing | `src/peer_connection/transport/dtls/mod.rs:164` | - | No DTLS state event; only OnConnectionStateChangeEvent, which hides new/connecting/closed changes |
| WEBRTC-5.5-6 | 5.5 | MUST | On "connected", [[RemoteCertificates]] is the remote chain, DER | tested | `src/peer_connection/handler/dtls.rs:309` | `a_connection_reports_dtls_state_channel_state_and_every_pair` | - |
| WEBRTC-5.5-7 | 5.5 | MUST | iceTransport attribute: the underlying ICE transport | untested | `src/peer_connection/transport/mod.rs:353` | - | - |
| WEBRTC-5.5-8 | 5.5 | MUST | state attribute returns [[DtlsTransportState]] | tested | `src/peer_connection/transport/mod.rs:360` | `state_reports_what_state_change_wrote` | - |
| WEBRTC-5.5-9 | 5.5 | MUST | getRemoteCertificates returns [[RemoteCertificates]] | tested | `src/peer_connection/transport/mod.rs:368` | `remote_certificates_are_empty_until_the_handshake_supplies_them` | - |
| WEBRTC-5.5-10 | 5.5 | MUST | RTCDtlsTransportState "new" | tested | `src/peer_connection/transport/dtls/state.rs:89` | `prepare_transport_stays_new_on_config_failure` | - |
| WEBRTC-5.5-11 | 5.5 | MUST | "connecting" | tested | `src/peer_connection/transport/dtls/mod.rs:313` | `prepare_transport_transitions_to_connecting_after_config` | - |
| WEBRTC-5.5-12 | 5.5 | MUST | "connected": handshake done and remote fingerprint verified | tested | `src/peer_connection/handler/dtls.rs:309` | `a_connection_reports_dtls_state_channel_state_and_every_pair` | - |
| WEBRTC-5.5-13 | 5.5 | MUST | "closed": on a received close_notify or close() | untested | `src/peer_connection/handler/dtls.rs:344`, `src/peer_connection/transport/dtls/mod.rs:461` | - | - |
| WEBRTC-5.5-14 | 5.5 | MUST | "failed": error alert or fingerprint validation failure | tested | `src/peer_connection/handler/dtls.rs:514` | `a_fingerprint_mismatch_fails_the_dtls_transport_and_the_connection` | - |
| WEBRTC-5.5.1-1 | 5.5.1 | MUST | RTCDtlsFingerprint.algorithm: an IANA hash function name | tested | `src/peer_connection/transport/dtls/fingerprint.rs:93` | `tests/dtls_rsa_certificate.rs` | - |
| WEBRTC-5.5.1-2 | 5.5.1 | MUST | RTCDtlsFingerprint.value: lowercase hex in RFC 4572 syntax | untested | `src/peer_connection/transport/dtls/fingerprint.rs:93` | - | Case of the produced value not asserted |
| WEBRTC-5.6-1 | 5.6 | MUST | RTCIceTransport: one object reused across ICE restarts | tested | `src/peer_connection/transport/mod.rs:259` | `tests/ice_restart_keeps_path_rtc2rtc.rs` | - |
| WEBRTC-5.6-2 | 5.6 | MUST | Gathering starts: [[IceGathererState]] "gathering", connection gathering state derived | partial | `src/peer_connection/mod.rs:1319`, `src/peer_connection/internal.rs:1689` | `gathering_state_reports_the_tracked_field` | State is set when a local description is applied (candidates come from the application) |
| WEBRTC-5.6-3 | 5.6 | MUST | Gathering starts: gatheringstatechange and, if changed, icegatheringstatechange events | missing | `src/peer_connection/mod.rs:1319` | - | No event for new to gathering; only "complete" is announced |
| WEBRTC-5.6-4 | 5.6 | MUST | Gathering finished: add a=end-of-candidates to the pending and current local descriptions | untested | `src/peer_connection/mod.rs:2129` | - | An empty local candidate sets the state; a test counts end-of-candidates lines for remote candidates only (not verified for local) |
| WEBRTC-5.6-5 | 5.6 | MUST | Gathering finished: an icecandidate event with an empty candidate string and the generation's ufrag | missing | `src/peer_connection/mod.rs:2129` | - | No end-of-gathering candidate event |
| WEBRTC-5.6-6 | 5.6 | MUST | No generation still gathering: state "complete", gatheringstatechange / icegatheringstatechange events | untested | `src/peer_connection/mod.rs:2130` | - | OnIceGatheringStateChangeEvent(Complete) is pushed, also when the state was already complete; no test asserts it |
| WEBRTC-5.6-7 | 5.6 | MUST | After "complete": an icecandidate event with a null candidate | missing | `src/peer_connection/mod.rs:2129` | - | Legacy null-candidate event not produced |
| WEBRTC-5.6-8 | 5.6 | MUST | New candidate with a local description for its generation: surface it; otherwise hold it in [[EarlyCandidates]] | n/a | - | - | Application gathers and times candidates |
| WEBRTC-5.6-9 | 5.6 | MUST | Role conflict (RFC 8445 7.3.1.1): [[IceRole]] takes the new value | untested | `src/peer_connection/handler/ice.rs:246`, `src/peer_connection/transport/ice/mod.rs:195` | - | `role()` reads the agent, so it follows; the event updates stats only |
| WEBRTC-5.6-10 | 5.6 | MUST | release early candidates: surface each held candidate, then clear the list | n/a | - | - | Application gathers and times candidates |
| WEBRTC-5.6-11 | 5.6 | MUST | surface a candidate: add it to the pending and current local descriptions' SDP | untested | `src/peer_connection/internal.rs:1801` | - | Local candidates reach the agent; not verified that local_description() then lists them |
| WEBRTC-5.6-12 | 5.6 | MUST | surface a candidate: add to the transport's local candidates and fire icecandidate with mid, m-line index and ufrag | partial | `src/peer_connection/internal.rs:1829` | `test_host_candidate_event_emission`, `test_srflx_candidate_event_emission` | Event carries the candidate and url; sdpMid, sdpMLineIndex and usernameFragment are the API layer's to add |
| WEBRTC-5.6-13 | 5.6 | MUST | Selected pair changed: [[SelectedCandidatePair]] is the new pair (or null) | tested | `src/peer_connection/transport/ice/mod.rs:124`, `src/peer_connection/handler/ice.rs:219` | `selected_candidate_pair_names_the_reported_candidates` | - |
| WEBRTC-5.6-14 | 5.6 | MUST | Selected pair changed: a selectedcandidatepairchange event at the transport | missing | `src/peer_connection/event/mod.rs:556` | - | `ICESelectedCandidatePairChange` is an internal event; nothing reaches the application |
| WEBRTC-5.6-15 | 5.6 | MUST | Transport state changed: [[IceTransportState]] updated, connection ICE and connection states derived in the same step | tested | `src/peer_connection/handler/ice.rs:203` | `tests/ice_restart_by_rtc_interop.rs` | - |
| WEBRTC-5.6-16 | 5.6 | MUST | Transport state changed: statechange at the transport, then iceconnectionstatechange, then connectionstatechange | partial | `src/peer_connection/handler/ice.rs:209` | `tests/dtls_failed_state.rs` | Connection-level events only; with one transport the transport state equals the ICE connection state |
| WEBRTC-5.6-17 | 5.6 | MUST | Slots start: state "new", gatherer state "new", selected pair null, role "unknown" | partial | `src/peer_connection/transport/ice/mod.rs:41`, `src/peer_connection/transport/ice/mod.rs:195` | `selected_candidate_pair_and_remote_candidates_are_empty_before_ice_runs` | Role is never unknown: `role()` says controlled until the agent is controlling |
| WEBRTC-5.6-18 | 5.6 | MUST | role attribute | partial | `src/peer_connection/transport/mod.rs:278` | - | See 5.6-17 |
| WEBRTC-5.6-19 | 5.6 | MUST | component attribute: "rtp" when RTCP is multiplexed | tested | `src/peer_connection/transport/ice/mod.rs:117` | `component_is_rtp_under_rtcp_mux` | - |
| WEBRTC-5.6-20 | 5.6 | MUST | state attribute returns [[IceTransportState]] | untested | `src/peer_connection/transport/mod.rs:283` | - | - |
| WEBRTC-5.6-21 | 5.6 | MUST | gatheringState attribute returns [[IceGathererState]] | tested | `src/peer_connection/transport/mod.rs:291` | `gathering_state_reports_the_tracked_field` | - |
| WEBRTC-5.6-22 | 5.6 | MUST | getLocalCandidates: the local candidates in the local description | untested | `src/peer_connection/transport/ice/mod.rs:69` | - | The agent's list, which can include peer-reflexive local candidates |
| WEBRTC-5.6-23 | 5.6 | MUST | getRemoteCandidates: the remote candidates in the remote description, never peer-reflexive ones | violated | `src/peer_connection/transport/ice/mod.rs:130` | - | Returns the agent's remote candidates, which include those learned from checks |
| WEBRTC-5.6-24 | 5.6 | MUST | getSelectedCandidatePair: the slot; null in "new" or "closed" | partial | `src/peer_connection/transport/ice/mod.rs:124` | `selected_candidate_pair_and_remote_candidates_are_empty_before_ice_runs` | Null before ICE runs; after close it returns whatever the agent still holds |
| WEBRTC-5.6-25 | 5.6 | MUST | getLocalParameters: null while there is no local description | violated | `src/peer_connection/transport/ice/mod.rs:58`, `src/peer_connection/transport/mod.rs:316` | - | Always returns the agent's credentials, also before any description |
| WEBRTC-5.6-26 | 5.6 | MUST | getRemoteParameters: null while there is no remote description | tested | `src/peer_connection/transport/ice/mod.rs:90` | `remote_parameters_are_none_until_credentials_arrive` | - |
| WEBRTC-5.6.1-1 | 5.6.1 | MUST | RTCIceParameters.usernameFragment | tested | `src/peer_connection/transport/ice/parameters.rs:14` | `remote_parameters_are_none_until_credentials_arrive` | - |
| WEBRTC-5.6.1-2 | 5.6.1 | MUST | RTCIceParameters.password | tested | `src/peer_connection/transport/ice/parameters.rs:14` | `remote_parameters_are_none_until_credentials_arrive` | - |
| WEBRTC-5.6.2-1 | 5.6.2 | MUST | create an RTCIceCandidatePair with local and remote candidates | untested | `src/peer_connection/transport/ice/candidate_pair.rs:27` | - | - |
| WEBRTC-5.6.2-2 | 5.6.2 | MUST | RTCIceCandidatePair.local | untested | `src/peer_connection/transport/ice/candidate_pair.rs:32` | - | - |
| WEBRTC-5.6.2-3 | 5.6.2 | MUST | RTCIceCandidatePair.remote | untested | `src/peer_connection/transport/ice/candidate_pair.rs:37` | - | - |
| WEBRTC-5.6.3-1 | 5.6.3 | MUST | RTCIceGathererState "new" | tested | `src/peer_connection/state/ice_gathering_state.rs:131` | `gathering_state_reports_the_tracked_field` | The connection-level enum is reused; it also has `Unspecified` |
| WEBRTC-5.6.3-2 | 5.6.3 | MUST | "gathering" | tested | `src/peer_connection/state/ice_gathering_state.rs:142` | `gathering_state_reports_the_tracked_field` | - |
| WEBRTC-5.6.3-3 | 5.6.3 | MUST | "complete": will not gather again until an ICE restart | partial | `src/peer_connection/mod.rs:2130` | `gathering_state_reports_the_tracked_field` | Not verified that a restart moves complete back to gathering with an event |
| WEBRTC-5.6.4-1 | 5.6.4 | MUST | RTCIceTransportState "closed": shut down, no longer answering STUN | untested | `src/peer_connection/transport/ice/state.rs:62` | - | - |
| WEBRTC-5.6.4-2 | 5.6.4 | MUST | "failed": gathering done, no more remote candidates, all pairs failed or lost consent | untested | `src/peer_connection/transport/ice/state.rs:50` | - | Judged in the ICE auditor's area; mapping only here |
| WEBRTC-5.6.4-3 | 5.6.4 | MUST | "disconnected": connectivity currently lost, transient | untested | `src/peer_connection/transport/ice/state.rs:57` | - | - |
| WEBRTC-5.6.4-4 | 5.6.4 | MUST | "new": gathering or waiting for remote candidates, not yet checking | tested | `src/peer_connection/transport/ice/state.rs:24` | `selected_candidate_pair_and_remote_candidates_are_empty_before_ice_runs` | - |
| WEBRTC-5.6.4-5 | 5.6.4 | MUST | "checking": has a remote candidate and is checking pairs | untested | `src/peer_connection/transport/ice/state.rs:30` | - | - |
| WEBRTC-5.6.4-6 | 5.6.4 | MUST | "completed": finished gathering and checking with a connection, and the remote signalled end of candidates | untested | `src/peer_connection/transport/ice/state.rs:44` | - | - |
| WEBRTC-5.6.4-7 | 5.6.4 | MUST | "connected": usable connection found, still checking | tested | `src/peer_connection/transport/ice/state.rs:38` | `tests/offer_answer_rtc2rtc.rs` | - |
| WEBRTC-5.6.4-8 | 5.6.4 | MUST | ICE restart: completed goes to connected, disconnected or failed goes to checking | untested | `src/peer_connection/transport/ice/mod.rs:229` | `tests/ice_restart_keeps_path_rtc2rtc.rs` | The restart keeps the path; the state sequence is not asserted |
| WEBRTC-5.6.4-9 | 5.6.4 | MUST | failed and completed need the end-of-remote-candidates indication | untested | `src/peer_connection/mod.rs:1935` | - | The indication is accepted by add_remote_candidate; its effect on the state is not asserted |
| WEBRTC-5.6.5-1 | 5.6.5 | MUST | RTCIceRole "unknown" | partial | `src/peer_connection/transport/ice/role.rs:19` | `a_fresh_transport_writes_no_value_outside_the_w3c_enums` | Enum value exists (`Unspecified`) and stats use it; the transport's `role()` never returns it |
| WEBRTC-5.6.5-2 | 5.6.5 | MUST | "controlling" | tested | `src/peer_connection/transport/ice/role.rs:26` | `tests/dtls_answer_setup_role.rs` | - |
| WEBRTC-5.6.5-3 | 5.6.5 | MUST | "controlled" | tested | `src/peer_connection/transport/ice/role.rs:31` | `tests/dtls_answer_setup_role.rs` | - |
| WEBRTC-5.6.6-1 | 5.6.6 | MUST | RTCIceComponent "rtp" (component id 1) | tested | `src/peer_connection/transport/ice/component.rs:25` | `component_is_rtp_under_rtcp_mux` | - |
| WEBRTC-5.6.6-2 | 5.6.6 | MUST | RTCIceComponent "rtcp" (component id 2) | untested | `src/peer_connection/transport/ice/component.rs:29` | - | Never used: rtcp-mux only |
| WEBRTC-5.7-1 | 5.7 | MUST | RTCTrackEvent.receiver | tested | `src/peer_connection/event/track_event.rs:55` | `a_remote_track_is_labelled_remote_and_its_kind` | - |
| WEBRTC-5.7-2 | 5.7 | MUST | RTCTrackEvent.track: the receiver's track | tested | `src/peer_connection/event/track_event.rs:60` | `a_remote_track_is_labelled_remote_and_its_kind` | By id |
| WEBRTC-5.7-3 | 5.7 | MUST | RTCTrackEvent.streams: every stream the track is part of | partial | `src/peer_connection/event/track_event.rs:66`, `src/peer_connection/handler/interceptor.rs:903` | - | Always exactly one stream id; a track with several msids or with none ("-") is not represented |
| WEBRTC-5.7-4 | 5.7 | MUST | RTCTrackEvent.transceiver | partial | `src/peer_connection/event/track_event.rs:51` | - | Not in the event; equal to the receiver id by construction |
| WEBRTC-5.7-5 | 5.7 | MUST | RTCTrackEvent constructor and RTCTrackEventInit | n/a | - | - | JS event construction |
| WEBRTC-6.1-1 | 6.1 | MUST | sctp attribute: the SCTP transport, null until SCTP is negotiated | untested | `src/peer_connection/mod.rs:2875` | - | `sctp()` is None until the transport is started; only its members are tested |
| WEBRTC-6.1-2 | 6.1 | MUST | ondatachannel: an event announces a channel the peer opened | tested | `src/peer_connection/handler/datachannel.rs:176`, `src/peer_connection/event/data_channel_event.rs:1` | `tests/data_channels_create_interop.rs` | No separate event type: the peer's channel arrives as `OnOpen` with a new handle |
| WEBRTC-6.1-3 | 6.1 | MUST | createDataChannel: closed connection throws InvalidStateError | untested | `src/peer_connection/mod.rs:2318` | - | `ErrConnectionClosed` |
| WEBRTC-6.1-4 | 6.1 | MUST | createDataChannel: create the channel and set its label | tested | `src/peer_connection/mod.rs:2322` | `test_data_channel_parameters_protocol_exchange` | - |
| WEBRTC-6.1-5 | 6.1 | MUST | createDataChannel: label longer than 65535 UTF-8 bytes throws TypeError | missing | `src/peer_connection/mod.rs:2322` | - | No length check on the label (the protocol is checked) |
| WEBRTC-6.1-6 | 6.1 | MUST | createDataChannel: maxPacketLifeTime from options, else null | tested | `src/peer_connection/mod.rs:2343` | `test_accepted_unreliable_channel_is_not_blocked_by_a_lost_message` | - |
| WEBRTC-6.1-7 | 6.1 | MUST | createDataChannel: maxRetransmits from options, else null | tested | `src/peer_connection/mod.rs:2346` | `an_accepted_channel_reports_the_peers_channel_type_and_reliability` | - |
| WEBRTC-6.1-8 | 6.1 | MUST | createDataChannel: ordered from options | tested | `src/peer_connection/mod.rs:2340` | `channel_created_without_options_is_ordered`, `unordered_can_still_be_requested` | - |
| WEBRTC-6.1-9 | 6.1 | MUST | createDataChannel: protocol from options | tested | `src/peer_connection/mod.rs:2349` | `test_data_channel_parameters_protocol_exchange` | - |
| WEBRTC-6.1-10 | 6.1 | MUST | createDataChannel: protocol longer than 65535 bytes throws TypeError | untested | `src/peer_connection/mod.rs:2352` | - | `ErrProtocolTooLarge`; no test reaches it |
| WEBRTC-6.1-11 | 6.1 | MUST | createDataChannel: negotiated from options | tested | `src/peer_connection/mod.rs:2362` | `test_negotiated_data_channel_rtc_to_rtc` | - |
| WEBRTC-6.1-12 | 6.1 | MUST | createDataChannel: id taken only when negotiated is true, otherwise null | tested | `src/data_channel/init.rs:1`, `src/data_channel/internal.rs:60` | `test_negotiated_data_channel_rtc_to_rtc` | `negotiated: Option<StreamId>` carries both |
| WEBRTC-6.1-13 | 6.1 | MUST | createDataChannel: negotiated without an id throws TypeError | n/a | - | - | Unrepresentable in the Rust type |
| WEBRTC-6.1-14 | 6.1 | MUST | createDataChannel: both maxPacketLifeTime and maxRetransmits set throws TypeError | untested | `src/peer_connection/mod.rs:2333` | - | `ErrRetransmitsOrPacketLifeTime`; no test |
| WEBRTC-6.1-15 | 6.1 | MUST | createDataChannel: an unreliable setting above the supported maximum is clamped | untested | `src/peer_connection/mod.rs:2343` | - | u16 is the wire maximum, so nothing to clamp; unasserted |
| WEBRTC-6.1-16 | 6.1 | MUST | createDataChannel: id 65535 throws TypeError | missing | `src/peer_connection/mod.rs:2362`, `src/data_channel/registry.rs:28` | - | A negotiated id of 65535 is accepted and registered |
| WEBRTC-6.1-17 | 6.1 | MUST | createDataChannel: with the DTLS role known, generate the id per RFC 8832 | tested | `src/peer_connection/mod.rs:2387`, `src/data_channel/registry.rs:92` | `stream_id_parity_matches_negotiated_dtls_role_across_all_role_configurations` | - |
| WEBRTC-6.1-18 | 6.1 | MUST | createDataChannel: no id available, or id already used by another channel, throws OperationError | partial | `src/data_channel/registry.rs:101`, `src/data_channel/registry.rs:28` | - | Exhaustion gives `ErrMaxDataChannelID` (untested, and the channel stays registered); a duplicate negotiated id is accepted and overwrites the stream map entry |
| WEBRTC-6.1-19 | 6.1 | MUST | createDataChannel: id at or above MaxChannels on a connected transport throws OperationError | partial | `src/data_channel/registry.rs:98` | - | Applied to generated ids only; a negotiated id is not compared with `max_channels` |
| WEBRTC-6.1-20 | 6.1 | MUST | createDataChannel: first channel updates the negotiation-needed flag | tested | `src/peer_connection/mod.rs:2412` | `tests/jsep_negotiation_needed.rs` | Triggered for every channel; the check itself decides |
| WEBRTC-6.1-21 | 6.1 | MUST | createDataChannel: append the channel to the connection's channels | tested | `src/peer_connection/mod.rs:2370`, `src/data_channel/registry.rs:28` | `test_data_channel_statistics_collection` | - |
| WEBRTC-6.1-22 | 6.1 | MUST | createDataChannel: create the underlying data transport with the channel's properties | tested | `src/peer_connection/mod.rs:2408`, `src/data_channel/internal.rs:98`, `src/peer_connection/handler/datachannel.rs:501` | `negotiated_channel_fires_open_at_handshake_complete`, `sctp_handshake_complete_does_not_redial` | - |
| WEBRTC-6.1.1.1-1 | 6.1.1.1 | MUST | SctpTransport created with a state, MaxMessageSize null, MaxChannels null | tested | `src/peer_connection/transport/sctp/mod.rs:68` | `max_message_size_is_none_before_start`, `state_and_max_channels_before_any_association` | - |
| WEBRTC-6.1.1.1-2 | 6.1.1.1 | MUST | SctpTransport has a MaxBufferSize slot, initially null | missing | `src/peer_connection/transport/sctp/mod.rs:44` | - | No such value is kept |
| WEBRTC-6.1.1.2-1 | 6.1.1.2 | MUST | Update max message size: remote value from the SDP max-message-size attribute, 65536 if missing | untested | `src/peer_connection/mod.rs:1293`, `src/peer_connection/sdp/mod.rs:1973` | - | `DEFAULT_MESSAGE_SIZE` for a missing attribute; the test passes the capability in directly |
| WEBRTC-6.1.1.2-2 | 6.1.1.2 | MUST | Update max message size: canSendSize is the local limit or 0 for none | tested | `src/peer_connection/transport/sctp/mod.rs:195` | `no_limit_on_either_side_resolves_to_the_implementation_ceiling` | - |
| WEBRTC-6.1.1.2-3 | 6.1.1.2 | MUST | Update max message size: both 0 gives infinity | partial | `src/peer_connection/transport/sctp/mod.rs:98` | `no_limit_on_either_side_resolves_to_the_implementation_ceiling` | Reports a finite ceiling (`u32::MAX`), by design |
| WEBRTC-6.1.1.2-4 | 6.1.1.2 | MUST | Update max message size: one of them 0 gives the larger | untested | `src/peer_connection/transport/sctp/mod.rs:101` | - | Implemented; no test with exactly one side unlimited |
| WEBRTC-6.1.1.2-5 | 6.1.1.2 | MUST | Update max message size: otherwise MaxMessageSize is the smaller | tested | `src/peer_connection/transport/sctp/mod.rs:103` | `max_message_size_takes_the_smaller_of_the_two_limits`, `max_message_size_reports_the_negotiated_value_not_the_configured_one` | - |
| WEBRTC-6.1.1.2-6 | 6.1.1.2 | MUST | Update max message size: MaxBufferSize is set to the larger (or infinity) | missing | `src/peer_connection/transport/sctp/mod.rs:98` | - | No MaxBufferSize |
| WEBRTC-6.1.1.3-1 | 6.1.1.3 | MUST | Connected: MaxChannels is the minimum of negotiated incoming and outgoing streams | untested | `src/peer_connection/transport/sctp/mod.rs:165` | `test_assoc_negotiated_max_streams` | The association value is tested in rtc-sctp; the transport getter after connect is not |
| WEBRTC-6.1.1.3-2 | 6.1.1.3 | MUST | Connected: every channel with a null id gets an id per RFC 8832 | tested | `src/peer_connection/handler/datachannel.rs:489`, `src/data_channel/registry.rs:92` | `stream_id_parity_matches_negotiated_dtls_role_across_all_role_configurations` | - |
| WEBRTC-6.1.1.3-3 | 6.1.1.3 | MUST | Connected: a channel whose id is at or above MaxChannels, or that got no id, is closed with a failure; others announced open | violated | `src/peer_connection/handler/datachannel.rs:489` | - | `assign_stream_ids(..)?` fails the whole event: no channel is dialed, none gets error/close; a negotiated id above the limit is dialed anyway |
| WEBRTC-6.1.1.3-4 | 6.1.1.3 | MUST | Connected: statechange fires on the transport, before the channels' open events | missing | `src/peer_connection/event/mod.rs:229` | - | No SCTP transport state event; `state()` can be polled |
| WEBRTC-6.1.1-1 | 6.1.1 | MUST | RTCSctpTransport.transport: the DTLS transport carrying SCTP | untested | `src/peer_connection/transport/mod.rs:399` | - | - |
| WEBRTC-6.1.1-2 | 6.1.1 | MUST | RTCSctpTransport.state returns the transport state | tested | `src/peer_connection/transport/mod.rs:405`, `src/peer_connection/transport/sctp/mod.rs:134` | `a_handshaking_association_is_connecting`, `state_follows_a_closed_association` | Derived from the association |
| WEBRTC-6.1.1-3 | 6.1.1 | MUST | RTCSctpTransport.maxMessageSize returns the negotiated value | tested | `src/peer_connection/transport/mod.rs:410` | `max_message_size_reports_the_negotiated_value_not_the_configured_one` | - |
| WEBRTC-6.1.1-4 | 6.1.1 | MUST | RTCSctpTransport.maxChannels: null until connected | tested | `src/peer_connection/transport/mod.rs:420` | `state_and_max_channels_before_any_association` | - |
| WEBRTC-6.1.1-5 | 6.1.1 | MUST | RTCSctpTransport.onstatechange | missing | `src/peer_connection/event/mod.rs:229` | - | No event |
| WEBRTC-6.1.2-1 | 6.1.2 | MUST | RTCSctpTransportState "connecting": negotiating; the initial state | tested | `src/peer_connection/transport/sctp/mod.rs:137` | `a_handshaking_association_is_connecting` | - |
| WEBRTC-6.1.2-2 | 6.1.2 | MUST | "connected": association established | untested | `src/peer_connection/transport/sctp/mod.rs:140` | - | No test reads `state()` on an established association |
| WEBRTC-6.1.2-3 | 6.1.2 | MUST | "closed" when a SHUTDOWN or ABORT chunk is received | tested | `src/peer_connection/transport/sctp/mod.rs:138` | `state_follows_a_closed_association`, `an_association_that_ended_in_its_handshake_is_closed` | - |
| WEBRTC-6.1.2-4 | 6.1.2 | MUST | "closed" when the association is closed intentionally (close, description rejecting data or changing the SCTP port) | untested | `src/peer_connection/transport/sctp/mod.rs:138` | - | Follows the association; a description that rejects the data section is not tested for it |
| WEBRTC-6.1.2-5 | 6.1.2 | MUST | "closed" when the DTLS transport goes to "closed" | untested | `src/peer_connection/transport/sctp/mod.rs:134`, `src/peer_connection/handler/datachannel.rs:608` | - | Channels are closed on `DTLSClosed`; the SCTP state is read from the association only |
| WEBRTC-6.2-1 | 6.2 | MUST | A channel is initially "connecting"; announced open when its transport is ready | tested | `src/data_channel/internal.rs:67`, `src/peer_connection/handler/datachannel.rs:255` | `in_band_channel_fires_open_only_when_ack_is_processed` | - |
| WEBRTC-6.2.1-1 | 6.2.1 | MUST | Create: ReadyState "connecting" | tested | `src/data_channel/internal.rs:67` | `in_band_channel_fires_open_only_when_ack_is_processed` | - |
| WEBRTC-6.2.1-2 | 6.2.1 | MUST | Create: BufferedAmount 0 | tested | `src/data_channel/internal.rs:70` | `rejected_send_does_not_charge_outstanding_bytes` | `outstanding_bytes` |
| WEBRTC-6.2.1-3 | 6.2.1 | MUST | Create: slots for label, ordered, maxPacketLifeTime, maxRetransmits, protocol, negotiated, id | tested | `src/data_channel/internal.rs:11` | `test_data_channel_parameters_protocol_exchange` | - |
| WEBRTC-6.2.1-4 | 6.2.1 | MUST | Create: IsTransferable slot, cleared by a queued task | n/a | - | - | Worker transfer is a binding concern |
| WEBRTC-6.2.2-1 | 6.2.2 | MUST | Announce open: abort if the connection is closed | untested | `src/peer_connection/handler/datachannel.rs:176` | - | No explicit check; a closed connection processes no input |
| WEBRTC-6.2.2-2 | 6.2.2 | MUST | Announce open: abort if the channel is closing or closed | tested | `src/peer_connection/handler/datachannel.rs:241`, `src/peer_connection/handler/datachannel.rs:255` | `ack_on_closed_channel_is_ignored` | - |
| WEBRTC-6.2.2-3 | 6.2.2 | MUST | Announce open: set "open" and fire open | tested | `src/peer_connection/handler/datachannel.rs:257`, `src/peer_connection/handler/datachannel.rs:186` | `in_band_channel_fires_open_only_when_ack_is_processed`, `negotiated_channel_fires_open_at_handshake_complete` | - |
| WEBRTC-6.2.3-1 | 6.2.3 | MUST | Announce instance: abort if the connection is closed | untested | `src/peer_connection/handler/datachannel.rs:222` | - | - |
| WEBRTC-6.2.3-2 | 6.2.3 | MUST | Announce instance: create a channel from the peer's DCEP configuration (label, ordered, reliability, protocol, id) | tested | `src/data_channel/internal.rs:118` | `an_accepted_channel_reports_the_peers_channel_type_and_reliability`, `test_data_channel_parameters_protocol_exchange` | - |
| WEBRTC-6.2.3-3 | 6.2.3 | MUST | Announce instance: Negotiated is false | untested | `src/data_channel/internal.rs:118` | - | - |
| WEBRTC-6.2.3-4 | 6.2.3 | MUST | Announce instance: append to the connection's channels | tested | `src/peer_connection/handler/datachannel.rs:282` | `peer_channel_statistics_are_freed_on_close` | - |
| WEBRTC-6.2.3-5 | 6.2.3 | MUST | Announce instance: state is "open" before the datachannel event, so the handler can send | tested | `src/peer_connection/handler/datachannel.rs:282`, `src/peer_connection/handler/datachannel.rs:186` | `tests/data_channels_create_interop.rs` | - |
| WEBRTC-6.2.3-6 | 6.2.3 | MUST | Announce instance: fire datachannel with the channel, then announce it open | partial | `src/peer_connection/handler/datachannel.rs:186` | `tests/data_channels_create_interop.rs` | One `OnOpen` stands for both events |
| WEBRTC-6.2.4-1 | 6.2.4 | MUST | Closing procedure: remove the channel from the connection's channels | tested | `src/peer_connection/handler/datachannel.rs:585` | `remote_close_fires_closing_then_close` | Removed when the stream is closed |
| WEBRTC-6.2.4-2 | 6.2.4 | MUST | Closing procedure: unless started by close(), set "closing" and fire closing | tested | `src/peer_connection/handler/datachannel.rs:586` | `remote_close_fires_closing_then_close`, `local_close_completes_with_close_only` | The state is never observable as "closing" on a remote close: closing and close are emitted together |
| WEBRTC-6.2.4-3 | 6.2.4 | MUST | Closing procedure: finish sending pending messages | untested | `src/data_channel/mod.rs:447`, `src/peer_connection/handler/datachannel.rs:438` | - | The close travels the write pipeline after earlier sends; no test asserts delivery of data sent just before close |
| WEBRTC-6.2.4-4 | 6.2.4 | MUST | Closing procedure: follow RFC 8831 6.7 (stream reset) and close the transport | tested | `src/peer_connection/handler/datachannel.rs:137`, `src/peer_connection/handler/datachannel.rs:442` | `test_data_channel_close_interop`, `local_close_completes_with_close_only` | - |
| WEBRTC-6.2.5-1 | 6.2.5 | MUST | Announce closed: abort if already "closed" | tested | `src/peer_connection/handler/datachannel.rs:103` | `association_failure_after_stream_failure_closes_once` | `close_emitted` |
| WEBRTC-6.2.5-2 | 6.2.5 | MUST | Announce closed: set "closed" and remove the channel | tested | `src/peer_connection/handler/datachannel.rs:585`, `src/peer_connection/handler/datachannel.rs:109` | `peer_channel_statistics_are_freed_on_close` | The channel is dropped from the registry |
| WEBRTC-6.2.5-3 | 6.2.5 | MUST | Announce closed: a transport closed with an error fires error with errorDetail "sctp-failure" | partial | `src/peer_connection/handler/datachannel.rs:551`, `src/peer_connection/handler/datachannel.rs:571` | `association_failure_fires_error_then_close` | `OnError(id)` fires; it carries no error detail |
| WEBRTC-6.2.5-4 | 6.2.5 | MUST | Announce closed: fire close | tested | `src/peer_connection/handler/datachannel.rs:112` | `remote_close_fires_closing_then_close`, `tests/graceful_close.rs` | - |
| WEBRTC-6.2.6-1 | 6.2.6 | MUST | Transfer steps and transfer-receiving steps | n/a | - | - | Worker transfer is a binding concern |
| WEBRTC-6.2.7-1 | 6.2.7 | MUST | Cannot create the transport: set "closed" | partial | `src/peer_connection/handler/datachannel.rs:691`, `src/peer_connection/handler/datachannel.rs:489` | `in_band_channel_times_out_without_ack`, `handshake_failure_closes_connecting_channels` | Done for a DCEP timeout and a failed association; not for an id that cannot be assigned or is out of range |
| WEBRTC-6.2.7-2 | 6.2.7 | MUST | Cannot create the transport: fire error with errorDetail "data-channel-failure" | missing | `src/peer_connection/handler/datachannel.rs:700` | - | The DCEP timeout fires `OnClose` only; no error event, no detail |
| WEBRTC-6.2.7-3 | 6.2.7 | MUST | Cannot create the transport: fire close | tested | `src/peer_connection/handler/datachannel.rs:704` | `in_band_channel_times_out_without_ack` | - |
| WEBRTC-6.2.8-1 | 6.2.8 | MUST | Receive: discard the data if the channel is not "open" | partial | `src/peer_connection/handler/datachannel.rs:302` | `pre_open_data_is_buffered_until_open`, `pre_open_data_is_dropped_on_timeout` | Data before open is held and delivered at open, not discarded |
| WEBRTC-6.2.8-2 | 6.2.8 | MUST | Receive: a string message is delivered as text (UTF-8) | tested | `src/peer_connection/handler/datachannel.rs:345`, `src/data_channel/mod.rs:355` | `test_data_channel_statistics_collection` | `is_string` flag; decoding is the binding's |
| WEBRTC-6.2.8-3 | 6.2.8 | MUST | Receive: a binary message is delivered as bytes (Blob / ArrayBuffer by binaryType) | tested | `src/peer_connection/handler/datachannel.rs:345` | `a_message_within_the_advertised_limit_is_received` | binaryType is the binding's |
| WEBRTC-6.2.8-4 | 6.2.8 | MUST | Receive: fire message at the channel | tested | `src/peer_connection/handler/datachannel.rs:320` | `first_message_sent_on_open_reaches_the_peer_that_comes_up_last` | Delivered through `poll_read` |
| WEBRTC-6.2-2 | 6.2 | MUST | label attribute | tested | `src/data_channel/mod.rs:107` | `test_data_channel_parameters_protocol_exchange` | - |
| WEBRTC-6.2-3 | 6.2 | MUST | ordered attribute | tested | `src/data_channel/mod.rs:120` | `channel_created_without_options_is_ordered` | - |
| WEBRTC-6.2-4 | 6.2 | MUST | maxPacketLifeTime attribute | tested | `src/data_channel/mod.rs:132` | `an_accepted_channel_reports_the_peers_channel_type_and_reliability` | - |
| WEBRTC-6.2-5 | 6.2 | MUST | maxRetransmits attribute | tested | `src/data_channel/mod.rs:144` | `an_accepted_channel_reports_the_peers_channel_type_and_reliability` | - |
| WEBRTC-6.2-6 | 6.2 | MUST | protocol attribute | tested | `src/data_channel/mod.rs:156` | `test_data_channel_parameters_protocol_exchange` | - |
| WEBRTC-6.2-7 | 6.2 | MUST | negotiated attribute | untested | `src/data_channel/mod.rs:180` | - | - |
| WEBRTC-6.2-8 | 6.2 | MUST | id attribute: null until assigned, then fixed | tested | `src/data_channel/mod.rs:219` | `stream_id_parity_matches_negotiated_dtls_role_across_all_role_configurations` | `stream_id()`; `id()` is the engine's handle |
| WEBRTC-6.2-9 | 6.2 | MUST | readyState attribute | tested | `src/data_channel/mod.rs:230` | `in_band_channel_fires_open_only_when_ack_is_processed` | - |
| WEBRTC-6.2-10 | 6.2 | MUST | bufferedAmount: bytes queued by send(), without framing; not decreased within a task; not reset when the channel closes | partial | `src/data_channel/mod.rs:430`, `src/peer_connection/handler/datachannel.rs:627` | `rejected_send_does_not_charge_outstanding_bytes`, `test_slow_consumer_throttles_the_peer_without_losing_data` | `outstanding_bytes` rises at send and falls as SCTP releases; unreadable once the channel is removed at close |
| WEBRTC-6.2-11 | 6.2 | MUST | bufferedAmountLowThreshold: initially 0, settable at any time | untested | `src/data_channel/mod.rs:278`, `src/data_channel/mod.rs:291` | - | - |
| WEBRTC-6.2-12 | 6.2 | MUST | bufferedamountlow fires when bufferedAmount falls from above the threshold to at or below it | untested | `src/peer_connection/handler/datachannel.rs:634` | - | No test in this crate observes `OnBufferedAmountLow` |
| WEBRTC-6.2-13 | 6.2 | MUST | onopen, onerror, onclosing, onclose, onmessage handlers exist as events | tested | `src/peer_connection/event/data_channel_event.rs:1` | `remote_close_fires_closing_then_close` | See section 12 rows per event |
| WEBRTC-6.2-14 | 6.2 | MUST | onerror carries sctp-failure, the SCTP cause code and cause information | missing | `src/peer_connection/event/data_channel_event.rs:1` | - | `OnError(id)` only |
| WEBRTC-6.2-15 | 6.2 | MUST | binaryType: initially "arraybuffer" | n/a | - | - | Binding chooses the container |
| WEBRTC-6.2-16 | 6.2 | MUST | close(): abort if "closing" or "closed" | partial | `src/data_channel/mod.rs:447` | `send_on_a_closed_channel_reports_closed` | A second close() while closing runs the close again |
| WEBRTC-6.2-17 | 6.2 | MUST | close(): set "closing" | tested | `src/data_channel/mod.rs:452` | `local_close_completes_with_close_only` | - |
| WEBRTC-6.2-18 | 6.2 | MUST | close(): start the closing procedure if not started | tested | `src/data_channel/mod.rs:455` | `local_close_completes_with_close_only`, `test_data_channel_close_interop` | - |
| WEBRTC-6.2-19 | 6.2 | MUST | send(): clears IsTransferable | n/a | - | - | Worker transfer is a binding concern |
| WEBRTC-6.2-20 | 6.2 | MUST | send(): not "open" throws InvalidStateError | partial | `src/data_channel/mod.rs:306` | `send_before_the_stream_exists_is_rejected`, `send_on_a_closed_channel_reports_closed` | The check is "has a stream", not the state: an in-band channel awaiting its DCEP ACK, and a closing channel, accept a send |
| WEBRTC-6.2-21 | 6.2 | MUST | send(): string encoded as UTF-8; binary taken as bytes | tested | `src/data_channel/mod.rs:355`, `src/data_channel/mod.rs:382` | `test_data_channel_statistics_collection` | `send` and `send_text` |
| WEBRTC-6.2-22 | 6.2 | MUST | send(): Blob data is queued in call order | n/a | - | - | Blob is a binding type |
| WEBRTC-6.2-23 | 6.2 | MUST | send(): data larger than maxMessageSize throws TypeError | tested | `src/data_channel/mod.rs:329` | `send_larger_than_max_message_size_is_rejected` | - |
| WEBRTC-6.2-24 | 6.2 | MUST | send(): BufferedAmount plus the data above MaxBufferSize throws OperationError | missing | `src/data_channel/mod.rs:306` | - | No buffer ceiling; the application watches `OnBufferedAmountHigh` |
| WEBRTC-6.2-25 | 6.2 | MUST | send(): transmit on the transport; an SCTP-level error fires error with "sctp-failure" | partial | `src/peer_connection/handler/datachannel.rs:416`, `src/peer_connection/handler/datachannel.rs:571` | `association_failure_fires_error_then_close` | Error event without detail |
| WEBRTC-6.2-26 | 6.2 | MUST | send(): increase BufferedAmount by the data size | tested | `src/data_channel/mod.rs:371` | `rejected_send_does_not_charge_outstanding_bytes` | - |
| WEBRTC-6.2-27 | 6.2 | MUST | RTCDataChannelInit.ordered defaults to true | tested | `src/data_channel/init.rs:1` | `default_init_is_ordered` | - |
| WEBRTC-6.2-28 | 6.2 | MUST | RTCDataChannelInit.maxPacketLifeTime | tested | `src/data_channel/init.rs:1` | `test_accepted_unreliable_channel_is_not_blocked_by_a_lost_message` | - |
| WEBRTC-6.2-29 | 6.2 | MUST | RTCDataChannelInit.maxRetransmits | tested | `src/data_channel/init.rs:1` | `an_accepted_channel_reports_the_peers_channel_type_and_reliability` | - |
| WEBRTC-6.2-30 | 6.2 | MUST | RTCDataChannelInit.protocol defaults to "" | tested | `src/data_channel/init.rs:1` | `test_data_channel_parameters_protocol_exchange` | - |
| WEBRTC-6.2-31 | 6.2 | MUST | RTCDataChannelInit.negotiated defaults to false | tested | `src/data_channel/init.rs:1` | `test_negotiated_data_channel_rtc_to_rtc` | - |
| WEBRTC-6.2-32 | 6.2 | MUST | RTCDataChannelInit.id: used when negotiated | tested | `src/data_channel/init.rs:1` | `test_negotiated_data_channel_rtc_to_rtc` | - |
| WEBRTC-6.2-33 | 6.2 | MUST | RTCDataChannelState "connecting" | tested | `src/data_channel/state.rs:1` | `in_band_channel_fires_open_only_when_ack_is_processed` | - |
| WEBRTC-6.2-34 | 6.2 | MUST | RTCDataChannelState "open" | tested | `src/data_channel/state.rs:1` | `negotiated_channel_fires_open_at_handshake_complete` | - |
| WEBRTC-6.2-35 | 6.2 | MUST | RTCDataChannelState "closing" | tested | `src/data_channel/state.rs:1` | `local_close_completes_with_close_only` | - |
| WEBRTC-6.2-36 | 6.2 | MUST | RTCDataChannelState "closed" | tested | `src/data_channel/state.rs:1` | `in_band_channel_times_out_without_ack` | - |
| WEBRTC-6.3-1 | 6.3 | MUST | RTCDataChannelEvent.channel names the announced channel | tested | `src/peer_connection/event/data_channel_event.rs:1` | `tests/data_channels_create_interop.rs` | The event carries the channel handle |
| WEBRTC-6.3-2 | 6.3 | MUST | RTCDataChannelEvent constructor and init dictionary | n/a | - | - | JS event construction |
| WEBRTC-6.4-1 | 6.4 | MUST | A channel with listeners or queued data is not garbage collected | n/a | - | - | Engine owns channels; no GC |
| WEBRTC-7.1-1 | 7.1 | MUST | RTCRtpSender.dtmf: a DTMF sender for an audio sender, else null | missing | `src/rtp_transceiver/rtp_sender/mod.rs:1` | - | No RTCDTMFSender (listed as not implemented on purpose) |
| WEBRTC-7.2-1 | 7.2 | MUST | RTCDTMFSender has Duration, InterToneGap and ToneBuffer slots | missing | - | - | - |
| WEBRTC-7.2-2 | 7.2 | MUST | canInsertDTMF attribute returns the algorithm's result | missing | - | - | - |
| WEBRTC-7.2-3 | 7.2 | MUST | toneBuffer returns the tones remaining to be played | missing | - | - | - |
| WEBRTC-7.2-4 | 7.2 | MUST | insertDTMF: characters 0-9, A-D, #, * generate tones; a-d normalized to upper case | missing | - | - | - |
| WEBRTC-7.2-5 | 7.2 | MUST | insertDTMF: "," is a 2 second delay | missing | - | - | - |
| WEBRTC-7.2-6 | 7.2 | MAY | insertDTMF: duration and gap may be stretched to RTP packet boundaries, by at most one packet | missing | - | - | - |
| WEBRTC-7.2-7 | 7.2 | MUST | insertDTMF: InvalidStateError when DTMF cannot be sent | missing | - | - | - |
| WEBRTC-7.2-8 | 7.2 | MUST | insertDTMF: unrecognized characters throw InvalidCharacterError | missing | - | - | - |
| WEBRTC-7.2-9 | 7.2 | MUST | insertDTMF: replace ToneBuffer, set Duration and InterToneGap | missing | - | - | - |
| WEBRTC-7.2-10 | 7.2 | MUST | insertDTMF: duration clamped to 40..6000 ms | missing | - | - | - |
| WEBRTC-7.2-11 | 7.2 | MUST | insertDTMF: interToneGap clamped to 30..6000 ms | missing | - | - | - |
| WEBRTC-7.2-12 | 7.2 | MUST | insertDTMF: an empty buffer aborts; a playout task already scheduled is kept | missing | - | - | - |
| WEBRTC-7.2-13 | 7.2 | MUST | Playout task: abort when DTMF cannot be sent | missing | - | - | - |
| WEBRTC-7.2-14 | 7.2 | MUST | Playout task: empty buffer fires tonechange with "" and stops | missing | - | - | - |
| WEBRTC-7.2-15 | 7.2 | MUST | Playout task: "," delays 2000 ms then continues | missing | - | - | - |
| WEBRTC-7.2-16 | 7.2 | MUST | Playout task: play the tone for Duration with the telephone-event codec, continue after Duration plus InterToneGap | missing | `src/peer_connection/configuration/media_engine.rs:191` | - | Only the MIME constant exists: no RFC 4733 payload builder, no timer; an application writes the event packets itself |
| WEBRTC-7.2-17 | 7.2 | MUST | Playout task: fire tonechange with the tone | missing | - | - | - |
| WEBRTC-7.3-1 | 7.3 | MUST | canInsertDTMF: false unless the connection is "connected" | missing | - | - | - |
| WEBRTC-7.3-2 | 7.3 | MUST | canInsertDTMF: false if the transceiver is stopping | missing | - | - | - |
| WEBRTC-7.3-3 | 7.3 | MUST | canInsertDTMF: false if the sender has no track | missing | - | - | - |
| WEBRTC-7.3-4 | 7.3 | MUST | canInsertDTMF: false unless currentDirection is sendrecv or sendonly | missing | - | - | - |
| WEBRTC-7.3-5 | 7.3 | MUST | canInsertDTMF: false if the first encoding is inactive | missing | - | - | - |
| WEBRTC-7.3-6 | 7.3 | MUST | canInsertDTMF: false if audio/telephone-event is not negotiated for sending | missing | `src/rtp_transceiver/rtp_sender/rtp_codec.rs:117` | - | telephone-event is recognised as a non-media codec but is not in the default codecs |
| WEBRTC-7.4-1 | 7.4 | MUST | RTCDTMFToneChangeEvent.tone: the tone begun, or "" at the end | missing | - | - | - |
| WEBRTC-8.1-1 | 8.1 | MUST | A track selector must be sent or received by this connection | tested | `src/statistics/mod.rs:81`, `src/statistics/accumulator/mod.rs:303` | `test_stats_selector_no_matching_streams` | Selector is a sender or receiver id of this connection |
| WEBRTC-8.1-2 | 8.1 | MUST | Monitored objects stay available after close() unless their lifetime says otherwise | untested | `src/peer_connection/mod.rs:2992` | - | See STATS-4.3-1 |
| WEBRTC-8.2-1 | 8.2 | MUST | getStats: null selector selects the whole connection | tested | `src/statistics/accumulator/mod.rs:290` | `test_stats_selector_none_returns_all`, `test_get_stats_selector_none_complete` | - |
| WEBRTC-8.2-2 | 8.2 | MUST | getStats: a track selects the sender or receiver whose track it is | n/a | - | - | Track lookup is the binding's |
| WEBRTC-8.2-3 | 8.2 | MUST | getStats: no match, or more than one, rejects with InvalidAccessError | partial | `src/statistics/accumulator/mod.rs:303` | `test_stats_selector_no_matching_streams` | An unknown id returns an empty selection instead of an error |
| WEBRTC-8.2-4 | 8.2 | MUST | getStats: gather per the selection algorithm and deliver the report | tested | `src/peer_connection/mod.rs:2992` | `test_get_stats_selector_subset_property` | Synchronous |
| WEBRTC-8.3-1 | 8.3 | MUST | RTCStatsReport maps each stats id to its dictionary | tested | `src/statistics/report.rs:183` | `test_stats_report_iteration` | - |
| WEBRTC-8.4-1 | 8.4 | MUST | All values in one stats object are synchronized | tested | `src/statistics/accumulator/mod.rs:167` | `test_master_accumulator_snapshot` | One snapshot under one `now` |
| WEBRTC-8.4-2 | 8.4 | MUST | timestamp: collection time; arrival time for remote-sourced stats | partial | `src/statistics/accumulator/mod.rs:167` | `test_master_accumulator_snapshot` | Remote-inbound / remote-outbound objects carry the snapshot time, not the RTCP arrival time |
| WEBRTC-8.4-3 | 8.4 | MUST | type is the most specific type name | tested | `src/statistics/stats/mod.rs:63` | `test_json_format_compliance` | - |
| WEBRTC-8.4-4 | 8.4 | MUST | id: the same for the same object across reports | tested | `src/statistics/accumulator/mod.rs:167` | `every_reference_resolves_and_nothing_unmeasured_is_reported` | - |
| WEBRTC-8.4-5 | 8.4 | MUST | id must not be predictable by an application | violated | `src/statistics/accumulator/rtp_stream/inbound.rs:23`, `src/statistics/accumulator/peer_connection.rs:36` | - | Ids are fixed strings built from kind, SSRC, payload type ("RTCPeerConnection", "RTCTransport", ...); no per-connection salt |
| WEBRTC-8.5-1 | 8.5 | MUST | Selection: null selector returns everything | tested | `src/statistics/accumulator/mod.rs:290` | `test_stats_selector_none_returns_all` | - |
| WEBRTC-8.5-2 | 8.5 | MUST | Selection: sender gives its outbound-rtp objects | tested | `src/statistics/accumulator/mod.rs:303` | `test_stats_selector_sender_filters_outbound`, `test_stats_selector_simulcast_sender` | - |
| WEBRTC-8.5-3 | 8.5 | MUST | Selection: plus everything they reference, directly or indirectly | tested | `src/statistics/accumulator/mod.rs:303` | `test_stats_selector_includes_referenced_codecs`, `test_stats_selector_sender_includes_remote_inbound`, `test_stats_selector_includes_ice_candidates` | - |
| WEBRTC-8.5-4 | 8.5 | MUST | Selection: receiver gives its inbound-rtp objects | tested | `src/statistics/accumulator/mod.rs:384` | `test_stats_selector_receiver_filters_inbound` | - |
| WEBRTC-8.5-5 | 8.5 | MUST | Selection: plus everything they reference | tested | `src/statistics/accumulator/mod.rs:384` | `test_stats_selector_receiver_includes_remote_outbound` | - |
| WEBRTC-8.6-1 | 8.6 | MUST | Mandatory stats: "codec" has payloadType | tested | `src/statistics/accumulator/mod.rs:167` | `test_snapshot_video_codec`, `test_from_codec_audio_with_fmtp` | present |
| WEBRTC-8.6-2 | 8.6 | MUST | Mandatory stats: "codec" has mimeType | tested | `src/statistics/accumulator/mod.rs:167` | `test_snapshot_video_codec`, `test_from_codec_audio_with_fmtp` | present |
| WEBRTC-8.6-3 | 8.6 | MUST | Mandatory stats: "codec" has clockRate | tested | `src/statistics/accumulator/mod.rs:167` | `test_snapshot_video_codec`, `test_from_codec_audio_with_fmtp` | present |
| WEBRTC-8.6-4 | 8.6 | MUST | Mandatory stats: "codec" has channels | tested | `src/statistics/accumulator/mod.rs:167` | `test_snapshot_video_codec`, `test_from_codec_audio_with_fmtp` | present |
| WEBRTC-8.6-5 | 8.6 | MUST | Mandatory stats: "codec" has sdpFmtpLine | tested | `src/statistics/accumulator/mod.rs:167` | `test_snapshot_video_codec`, `test_from_codec_audio_with_fmtp` | present |
| WEBRTC-8.6-6 | 8.6 | MUST | Mandatory stats: "inbound-rtp" has ssrc | tested | `src/statistics/accumulator/mod.rs:167` | `every_reference_resolves_and_nothing_unmeasured_is_reported` | present |
| WEBRTC-8.6-7 | 8.6 | MUST | Mandatory stats: "inbound-rtp" has kind | tested | `src/statistics/accumulator/mod.rs:167` | `every_reference_resolves_and_nothing_unmeasured_is_reported` | present |
| WEBRTC-8.6-8 | 8.6 | MUST | Mandatory stats: "inbound-rtp" has transportId | tested | `src/statistics/accumulator/mod.rs:167` | `every_reference_resolves_and_nothing_unmeasured_is_reported` | present |
| WEBRTC-8.6-9 | 8.6 | MUST | Mandatory stats: "inbound-rtp" has codecId | tested | `src/statistics/accumulator/mod.rs:167` | `every_reference_resolves_and_nothing_unmeasured_is_reported` | present |
| WEBRTC-8.6-10 | 8.6 | MUST | Mandatory stats: "outbound-rtp" has ssrc | tested | `src/statistics/accumulator/mod.rs:167` | `every_reference_resolves_and_nothing_unmeasured_is_reported` | present |
| WEBRTC-8.6-11 | 8.6 | MUST | Mandatory stats: "outbound-rtp" has kind | tested | `src/statistics/accumulator/mod.rs:167` | `every_reference_resolves_and_nothing_unmeasured_is_reported` | present |
| WEBRTC-8.6-12 | 8.6 | MUST | Mandatory stats: "outbound-rtp" has transportId | tested | `src/statistics/accumulator/mod.rs:167` | `every_reference_resolves_and_nothing_unmeasured_is_reported` | present |
| WEBRTC-8.6-13 | 8.6 | MUST | Mandatory stats: "outbound-rtp" has codecId | tested | `src/statistics/accumulator/mod.rs:167` | `every_reference_resolves_and_nothing_unmeasured_is_reported` | present |
| WEBRTC-8.6-14 | 8.6 | MUST | Mandatory stats: "remote-inbound-rtp" has ssrc | tested | `src/statistics/accumulator/mod.rs:167` | `every_reference_resolves_and_nothing_unmeasured_is_reported` | present |
| WEBRTC-8.6-15 | 8.6 | MUST | Mandatory stats: "remote-inbound-rtp" has kind | tested | `src/statistics/accumulator/mod.rs:167` | `every_reference_resolves_and_nothing_unmeasured_is_reported` | present |
| WEBRTC-8.6-16 | 8.6 | MUST | Mandatory stats: "remote-inbound-rtp" has transportId | tested | `src/statistics/accumulator/mod.rs:167` | `every_reference_resolves_and_nothing_unmeasured_is_reported` | present |
| WEBRTC-8.6-17 | 8.6 | MUST | Mandatory stats: "remote-inbound-rtp" has codecId | tested | `src/statistics/accumulator/mod.rs:167` | `every_reference_resolves_and_nothing_unmeasured_is_reported` | present |
| WEBRTC-8.6-18 | 8.6 | MUST | Mandatory stats: "remote-outbound-rtp" has ssrc | tested | `src/statistics/accumulator/mod.rs:167` | `remote_outbound_exists_from_the_first_sender_report` | present |
| WEBRTC-8.6-19 | 8.6 | MUST | Mandatory stats: "remote-outbound-rtp" has kind | tested | `src/statistics/accumulator/mod.rs:167` | `remote_outbound_exists_from_the_first_sender_report` | present |
| WEBRTC-8.6-20 | 8.6 | MUST | Mandatory stats: "remote-outbound-rtp" has transportId | tested | `src/statistics/accumulator/mod.rs:167` | `remote_outbound_exists_from_the_first_sender_report` | present |
| WEBRTC-8.6-21 | 8.6 | MUST | Mandatory stats: "remote-outbound-rtp" has codecId | tested | `src/statistics/accumulator/mod.rs:167` | `remote_outbound_exists_from_the_first_sender_report` | present |
| WEBRTC-8.6-22 | 8.6 | MUST | Mandatory stats: "inbound-rtp" has packetsReceived | tested | `src/statistics/accumulator/mod.rs:167` | `every_reference_resolves_and_nothing_unmeasured_is_reported`, `cumulative_loss_is_signed` | present |
| WEBRTC-8.6-23 | 8.6 | MUST | Mandatory stats: "inbound-rtp" has packetsLost | tested | `src/statistics/accumulator/mod.rs:167` | `every_reference_resolves_and_nothing_unmeasured_is_reported`, `cumulative_loss_is_signed` | present |
| WEBRTC-8.6-24 | 8.6 | MUST | Mandatory stats: "inbound-rtp" has jitter | tested | `src/statistics/accumulator/mod.rs:167` | `every_reference_resolves_and_nothing_unmeasured_is_reported`, `cumulative_loss_is_signed` | present |
| WEBRTC-8.6-25 | 8.6 | MUST | Mandatory stats: "inbound-rtp" has trackIdentifier | untested | `src/statistics/accumulator/mod.rs:167` | - | present; value unasserted |
| WEBRTC-8.6-26 | 8.6 | MUST | Mandatory stats: "inbound-rtp" has bytesReceived | untested | `src/statistics/accumulator/mod.rs:167` | - | present; value unasserted |
| WEBRTC-8.6-27 | 8.6 | MUST | Mandatory stats: "inbound-rtp" has nackCount | untested | `src/statistics/accumulator/mod.rs:167` | - | present; value unasserted |
| WEBRTC-8.6-28 | 8.6 | MUST | Mandatory stats: "inbound-rtp" has remoteId | tested | `src/statistics/accumulator/mod.rs:167` | `test_snapshot_remote` | present once an SR arrived |
| WEBRTC-8.6-29 | 8.6 | MUST | Mandatory stats: "inbound-rtp" has framesDecoded | partial | `src/statistics/accumulator/mod.rs:167` | `an_update_merges_into_what_was_supplied_before` | present only when the application feeds it |
| WEBRTC-8.6-30 | 8.6 | MUST | Mandatory stats: "inbound-rtp" has framesReceived | partial | `src/statistics/accumulator/mod.rs:167` | `an_update_merges_into_what_was_supplied_before` | present only when the application feeds it |
| WEBRTC-8.6-31 | 8.6 | MUST | Mandatory stats: "inbound-rtp" has framesDropped | partial | `src/statistics/accumulator/mod.rs:167` | - | present only when the application feeds it; feed value untested |
| WEBRTC-8.6-32 | 8.6 | MUST | Mandatory stats: "inbound-rtp" has totalAudioEnergy | partial | `src/statistics/accumulator/mod.rs:167` | - | present only when the application feeds it; feed value untested |
| WEBRTC-8.6-33 | 8.6 | MUST | Mandatory stats: "inbound-rtp" has totalSamplesDuration | partial | `src/statistics/accumulator/mod.rs:167` | - | present only when the application feeds it; feed value untested |
| WEBRTC-8.6-34 | 8.6 | MUST | Mandatory stats: "inbound-rtp" has packetsDiscarded | partial | `src/statistics/accumulator/mod.rs:167` | - | present only when the application feeds it; feed value untested |
| WEBRTC-8.6-35 | 8.6 | MUST | Mandatory stats: "outbound-rtp" has packetsSent | tested | `src/statistics/accumulator/mod.rs:167` | `test_on_rtp_sent` | present (RTX-SSRC retransmissions not included, see STATS-8.7) |
| WEBRTC-8.6-36 | 8.6 | MUST | Mandatory stats: "outbound-rtp" has bytesSent | tested | `src/statistics/accumulator/mod.rs:167` | `test_on_rtp_sent` | present (RTX-SSRC retransmissions not included, see STATS-8.7) |
| WEBRTC-8.6-37 | 8.6 | MUST | Mandatory stats: "outbound-rtp" has remoteId | tested | `src/statistics/accumulator/mod.rs:167` | `test_snapshot_remote` | present once a report arrived |
| WEBRTC-8.6-38 | 8.6 | MUST | Mandatory stats: "outbound-rtp" has nackCount | untested | `src/statistics/accumulator/mod.rs:167` | - | present; value unasserted |
| WEBRTC-8.6-39 | 8.6 | MUST | Mandatory stats: "outbound-rtp" has framesEncoded | partial | `src/statistics/accumulator/mod.rs:167` | `supplied_stats_reach_the_report_and_their_references_resolve` | present only when the application feeds it |
| WEBRTC-8.6-40 | 8.6 | MUST | Mandatory stats: "outbound-rtp" has framesSent | partial | `src/statistics/accumulator/mod.rs:167` | - | present only when the application feeds it |
| WEBRTC-8.6-41 | 8.6 | MUST | Mandatory stats: "remote-inbound-rtp" has packetsReceived | tested | `src/statistics/accumulator/mod.rs:167` | `test_on_receiver_report`, `cumulative_loss_is_signed` | present |
| WEBRTC-8.6-42 | 8.6 | MUST | Mandatory stats: "remote-inbound-rtp" has packetsLost | tested | `src/statistics/accumulator/mod.rs:167` | `test_on_receiver_report`, `cumulative_loss_is_signed` | present |
| WEBRTC-8.6-43 | 8.6 | MUST | Mandatory stats: "remote-inbound-rtp" has jitter | tested | `src/statistics/accumulator/mod.rs:167` | `test_on_receiver_report`, `cumulative_loss_is_signed` | present |
| WEBRTC-8.6-44 | 8.6 | MUST | Mandatory stats: "remote-inbound-rtp" has localId | tested | `src/statistics/accumulator/mod.rs:167` | `a_receiver_report_that_echoes_our_sender_report_measures_the_round_trip` | present |
| WEBRTC-8.6-45 | 8.6 | MUST | Mandatory stats: "remote-inbound-rtp" has roundTripTime | tested | `src/statistics/accumulator/mod.rs:167` | `a_receiver_report_that_echoes_our_sender_report_measures_the_round_trip` | present |
| WEBRTC-8.6-46 | 8.6 | MUST | Mandatory stats: "remote-outbound-rtp" has packetsSent | tested | `src/statistics/accumulator/mod.rs:167` | `test_on_rtcp_sr_received`, `test_snapshot_remote` | present |
| WEBRTC-8.6-47 | 8.6 | MUST | Mandatory stats: "remote-outbound-rtp" has bytesSent | tested | `src/statistics/accumulator/mod.rs:167` | `test_on_rtcp_sr_received`, `test_snapshot_remote` | present |
| WEBRTC-8.6-48 | 8.6 | MUST | Mandatory stats: "remote-outbound-rtp" has localId | tested | `src/statistics/accumulator/mod.rs:167` | `test_on_rtcp_sr_received`, `test_snapshot_remote` | present |
| WEBRTC-8.6-49 | 8.6 | MUST | Mandatory stats: "remote-outbound-rtp" has remoteTimestamp | partial | `src/statistics/accumulator/mod.rs:167` | - | present, but it is the local arrival time (STATS-8.10-remoteTimestamp) |
| WEBRTC-8.6-50 | 8.6 | MUST | Mandatory stats: "media-source" has trackIdentifier | partial | `src/statistics/accumulator/mod.rs:167` | `a_media_source_names_its_track_as_track_identifier` | object exists only once the application feeds source stats |
| WEBRTC-8.6-51 | 8.6 | MUST | Mandatory stats: "media-source" has kind | partial | `src/statistics/accumulator/mod.rs:167` | `a_media_source_names_its_track_as_track_identifier` | object exists only once the application feeds source stats |
| WEBRTC-8.6-52 | 8.6 | MUST | Mandatory stats: "media-source" has totalAudioEnergy | partial | `src/statistics/accumulator/mod.rs:167` | - | present only when the application feeds it; untested |
| WEBRTC-8.6-53 | 8.6 | MUST | Mandatory stats: "media-source" has totalSamplesDuration | partial | `src/statistics/accumulator/mod.rs:167` | - | present only when the application feeds it; untested |
| WEBRTC-8.6-54 | 8.6 | MUST | Mandatory stats: "media-source" has framesPerSecond | partial | `src/statistics/accumulator/mod.rs:167` | - | present only when the application feeds it; untested |
| WEBRTC-8.6-55 | 8.6 | MUST | Mandatory stats: "media-source" has height | partial | `src/statistics/accumulator/mod.rs:167` | - | present only when the application feeds it; untested |
| WEBRTC-8.6-56 | 8.6 | MUST | Mandatory stats: "media-source" has width | partial | `src/statistics/accumulator/mod.rs:167` | `supplied_stats_reach_the_report_and_their_references_resolve` | present only when the application feeds it |
| WEBRTC-8.6-57 | 8.6 | MUST | Mandatory stats: "peer-connection" has dataChannelsOpened | tested | `src/statistics/accumulator/mod.rs:167` | `test_data_channel_statistics_collection` | present |
| WEBRTC-8.6-58 | 8.6 | MUST | Mandatory stats: "peer-connection" has dataChannelsClosed | partial | `src/statistics/accumulator/mod.rs:167` | - | present; counts never-opened channels (STATS-8.15) |
| WEBRTC-8.6-59 | 8.6 | MUST | Mandatory stats: "data-channel" has label | tested | `src/statistics/accumulator/mod.rs:167` | `test_data_channel_statistics_collection` | present |
| WEBRTC-8.6-60 | 8.6 | MUST | Mandatory stats: "data-channel" has state | tested | `src/statistics/accumulator/mod.rs:167` | `test_data_channel_statistics_collection` | present |
| WEBRTC-8.6-61 | 8.6 | MUST | Mandatory stats: "data-channel" has messagesSent | tested | `src/statistics/accumulator/mod.rs:167` | `test_data_channel_statistics_collection` | present |
| WEBRTC-8.6-62 | 8.6 | MUST | Mandatory stats: "data-channel" has bytesSent | tested | `src/statistics/accumulator/mod.rs:167` | `test_data_channel_statistics_collection` | present |
| WEBRTC-8.6-63 | 8.6 | MUST | Mandatory stats: "data-channel" has messagesReceived | tested | `src/statistics/accumulator/mod.rs:167` | `test_data_channel_statistics_collection` | present |
| WEBRTC-8.6-64 | 8.6 | MUST | Mandatory stats: "data-channel" has bytesReceived | tested | `src/statistics/accumulator/mod.rs:167` | `test_data_channel_statistics_collection` | present |
| WEBRTC-8.6-65 | 8.6 | MUST | Mandatory stats: "data-channel" has protocol | untested | `src/statistics/accumulator/mod.rs:167` | - | present |
| WEBRTC-8.6-66 | 8.6 | MUST | Mandatory stats: "data-channel" has dataChannelIdentifier | partial | `src/statistics/accumulator/mod.rs:167` | `tests/data_channel_stream_id_parity.rs` | present; 0 while unassigned |
| WEBRTC-8.6-67 | 8.6 | MUST | Mandatory stats: "transport" has bytesSent | tested | `src/statistics/accumulator/mod.rs:167` | `test_transport_statistics_collection` | present (STUN included, see STATS-8.17) |
| WEBRTC-8.6-68 | 8.6 | MUST | Mandatory stats: "transport" has bytesReceived | tested | `src/statistics/accumulator/mod.rs:167` | `test_transport_statistics_collection` | present (STUN included, see STATS-8.17) |
| WEBRTC-8.6-69 | 8.6 | MUST | Mandatory stats: "transport" has selectedCandidatePairId | tested | `src/statistics/accumulator/mod.rs:167` | `a_connection_reports_dtls_state_channel_state_and_every_pair` | present |
| WEBRTC-8.6-70 | 8.6 | MUST | Mandatory stats: "transport" has localCertificateId | tested | `src/statistics/accumulator/mod.rs:167` | `a_connection_reports_dtls_state_channel_state_and_every_pair` | present |
| WEBRTC-8.6-71 | 8.6 | MUST | Mandatory stats: "transport" has remoteCertificateId | tested | `src/statistics/accumulator/mod.rs:167` | `a_connection_reports_dtls_state_channel_state_and_every_pair` | present |
| WEBRTC-8.6-72 | 8.6 | MUST | Mandatory stats: "candidate-pair" has transportId | tested | `src/statistics/accumulator/mod.rs:167` | `every_candidate_pair_is_reported_with_its_state` | present |
| WEBRTC-8.6-73 | 8.6 | MUST | Mandatory stats: "candidate-pair" has localCandidateId | tested | `src/statistics/accumulator/mod.rs:167` | `every_candidate_pair_is_reported_with_its_state` | present |
| WEBRTC-8.6-74 | 8.6 | MUST | Mandatory stats: "candidate-pair" has remoteCandidateId | tested | `src/statistics/accumulator/mod.rs:167` | `every_candidate_pair_is_reported_with_its_state` | present |
| WEBRTC-8.6-75 | 8.6 | MUST | Mandatory stats: "candidate-pair" has state | tested | `src/statistics/accumulator/mod.rs:167` | `every_candidate_pair_is_reported_with_its_state` | present |
| WEBRTC-8.6-76 | 8.6 | MUST | Mandatory stats: "candidate-pair" has nominated | tested | `src/statistics/accumulator/mod.rs:167` | `every_candidate_pair_is_reported_with_its_state` | present |
| WEBRTC-8.6-77 | 8.6 | MUST | Mandatory stats: "candidate-pair" has bytesSent | untested | `src/statistics/accumulator/mod.rs:167` | - | present; value unasserted |
| WEBRTC-8.6-78 | 8.6 | MUST | Mandatory stats: "candidate-pair" has bytesReceived | untested | `src/statistics/accumulator/mod.rs:167` | - | present; value unasserted |
| WEBRTC-8.6-79 | 8.6 | MUST | Mandatory stats: "candidate-pair" has totalRoundTripTime | untested | `src/statistics/accumulator/mod.rs:167` | - | present; value unasserted |
| WEBRTC-8.6-80 | 8.6 | MUST | Mandatory stats: "candidate-pair" has responsesReceived | untested | `src/statistics/accumulator/mod.rs:167` | - | present; value unasserted |
| WEBRTC-8.6-81 | 8.6 | MUST | Mandatory stats: "candidate-pair" has currentRoundTripTime | untested | `src/statistics/accumulator/mod.rs:167` | - | present; value unasserted |
| WEBRTC-8.6-82 | 8.6 | MUST | Mandatory stats: "local-candidate" has address | tested | `src/statistics/accumulator/mod.rs:167` | `a_candidate_reports_its_whole_priority_and_only_the_members_it_has` | present |
| WEBRTC-8.6-83 | 8.6 | MUST | Mandatory stats: "local-candidate" has port | tested | `src/statistics/accumulator/mod.rs:167` | `a_candidate_reports_its_whole_priority_and_only_the_members_it_has` | present |
| WEBRTC-8.6-84 | 8.6 | MUST | Mandatory stats: "local-candidate" has candidateType | tested | `src/statistics/accumulator/mod.rs:167` | `a_candidate_reports_its_whole_priority_and_only_the_members_it_has` | present |
| WEBRTC-8.6-85 | 8.6 | MUST | Mandatory stats: "local-candidate" has protocol | untested | `src/statistics/accumulator/mod.rs:167` | - | present |
| WEBRTC-8.6-86 | 8.6 | MUST | Mandatory stats: "remote-candidate" has address | tested | `src/statistics/accumulator/mod.rs:167` | `a_candidate_reports_its_whole_priority_and_only_the_members_it_has` | present |
| WEBRTC-8.6-87 | 8.6 | MUST | Mandatory stats: "remote-candidate" has port | tested | `src/statistics/accumulator/mod.rs:167` | `a_candidate_reports_its_whole_priority_and_only_the_members_it_has` | present |
| WEBRTC-8.6-88 | 8.6 | MUST | Mandatory stats: "remote-candidate" has candidateType | tested | `src/statistics/accumulator/mod.rs:167` | `a_candidate_reports_its_whole_priority_and_only_the_members_it_has` | present |
| WEBRTC-8.6-89 | 8.6 | MUST | Mandatory stats: "remote-candidate" has protocol | untested | `src/statistics/accumulator/mod.rs:167` | - | present |
| WEBRTC-8.6-90 | 8.6 | MUST | Mandatory stats: "local-candidate" has url | untested | `src/statistics/accumulator/mod.rs:167` | - | present for srflx and relay |
| WEBRTC-8.6-91 | 8.6 | MUST | Mandatory stats: "remote-candidate" has url | tested | `src/statistics/accumulator/mod.rs:167` | `a_candidate_reports_its_whole_priority_and_only_the_members_it_has` | correctly never present for a remote candidate |
| WEBRTC-8.6-92 | 8.6 | MUST | Mandatory stats: "certificate" has fingerprint | tested | `src/statistics/accumulator/mod.rs:167` | `a_connection_reports_dtls_state_channel_state_and_every_pair`, `base64_matches_rfc_4648` | present |
| WEBRTC-8.6-93 | 8.6 | MUST | Mandatory stats: "certificate" has fingerprintAlgorithm | tested | `src/statistics/accumulator/mod.rs:167` | `a_connection_reports_dtls_state_channel_state_and_every_pair`, `base64_matches_rfc_4648` | present |
| WEBRTC-8.6-94 | 8.6 | MUST | Mandatory stats: "certificate" has base64Certificate | tested | `src/statistics/accumulator/mod.rs:167` | `a_connection_reports_dtls_state_channel_state_and_every_pair`, `base64_matches_rfc_4648` | present |
| WEBRTC-8.6-95 | 8.6 | MUST | Mandatory stats: "certificate" has issuerCertificateId | missing | `src/statistics/accumulator/mod.rs:167` | - | never present: only the leaf certificate is reported |
| WEBRTC-8.6-96 | 8.6 | MAY | Any other statistic of webrtc-stats may be generated | tested | `src/statistics/accumulator/mod.rs:167` | `every_reference_resolves_and_nothing_unmeasured_is_reported` | See w3c-webrtc-stats.md |
| WEBRTC-9.1-1 | 9.1 | MUST | A sent track appears as exactly one track to the recipient | tested | `src/peer_connection/handler/interceptor.rs:470`, `src/peer_connection/event/track_event.rs:171` | `tests/one_media_section_rtc_to_rtc_unicast.rs` | One `OnTrack(OnOpen)` per receiver track |
| WEBRTC-9.1-2 | 9.1 | MUST | The sender's stream membership (msid) creates and populates the receiver-side streams | untested | `src/media_stream/track.rs:193`, `src/peer_connection/event/track_event.rs:1` | - | The track carries a stream id from the remote msid; several streams per track are not modelled on the track |
| WEBRTC-9.1-3 | 9.1 | MUST | All channels a codec encodes jointly are in one track | n/a | - | - | Media encoding is the application's |
| WEBRTC-9.2.1-1 | 9.2.1 | MUST | A remote stream's id is initialized from the remote description | untested | `src/media_stream/track.rs:193` | - | No test asserts the stream id of a remote track against the offered msid |
| WEBRTC-9.3-1 | 9.3 | MUST | RTP arriving for a muted, not ended, receptive receiver track sets muted to false | missing | `src/media_stream/track.rs:526` | - | `muted` is only ever set by the application |
| WEBRTC-9.3-2 | 9.3 | MUST | A BYE removing one of the receiver's SSRCs sets the track muted | violated | `src/peer_connection/handler/interceptor.rs:195` | `a_bye_for_the_tracks_ssrc_ends_it` | The track is ended (`stop()`, `OnClose`) once every SSRC said BYE; it should be muted and able to resume |
| WEBRTC-9.3-3 | 9.3 | MUST | setRemoteDescription can set a receiver track muted | missing | `src/media_stream/track.rs:526` | - | No muted transition on a direction change |
| WEBRTC-9.3-4 | 9.3 | MAY | Resources of an ended receiver track may be freed | n/a | - | - | No decoder in the engine |
| WEBRTC-9.3.1-1 | 9.3.1 | MUST | getCapabilities returns the empty set for a remote track | untested | `src/media_stream/track.rs:581` | - | Returns the stored capabilities, empty by default |
| WEBRTC-9.3.1-2 | 9.3.1 | MUST | applyConstraints rejects with OverconstrainedError on a remote track | violated | `src/media_stream/track.rs:664` | - | Stores the constraints and returns nothing, for any track |
| WEBRTC-9.3.1-3 | 9.3.1 | MUST | Remote video track setting width: latest received frame | missing | `src/media_stream/track_settings.rs:1` | - | No frame information reaches the settings; no feed |
| WEBRTC-9.3.1-4 | 9.3.1 | MUST | Remote video track setting height | missing | `src/media_stream/track_settings.rs:1` | - | - |
| WEBRTC-9.3.1-5 | 9.3.1 | MUST | Remote video track setting frameRate | missing | `src/media_stream/track_settings.rs:1` | - | - |
| WEBRTC-9.3.1-6 | 9.3.1 | MUST | Remote video track setting aspectRatio | missing | `src/media_stream/track_settings.rs:1` | - | - |
| WEBRTC-11.1-1 | 11.1 | MUST | RTCError: an OperationError carrying errorDetail | missing | `rtc-shared/src/error.rs:1` | - | Errors are one flat `Error` enum; no detail type an API layer can map |
| WEBRTC-11.1-2 | 11.1 | MUST | RTCError.sdpLineNumber for an SDP syntax error | missing | `rtc-shared/src/error.rs:1` | - | SDP parse errors carry text, not a line number field |
| WEBRTC-11.1-3 | 11.1 | MUST | RTCError.sctpCauseCode for an SCTP failure | missing | `src/peer_connection/event/data_channel_event.rs:1` | - | - |
| WEBRTC-11.1-4 | 11.1 | MUST | RTCError.receivedAlert for a fatal DTLS alert received | missing | `src/peer_connection/event/mod.rs:229` | - | - |
| WEBRTC-11.1-5 | 11.1 | MUST | RTCError.sentAlert for a fatal DTLS alert sent | missing | `src/peer_connection/event/mod.rs:229` | - | - |
| WEBRTC-11.1-6 | 11.1 | MUST | RTCError constructor and RTCErrorInit | n/a | - | - | JS object construction |
| WEBRTC-11.2-1 | 11.2 | MUST | errorDetail "data-channel-failure" | missing | `src/peer_connection/event/data_channel_event.rs:1` | - | `OnError(id)` has no reason |
| WEBRTC-11.2-2 | 11.2 | MUST | errorDetail "dtls-failure", with the alert values | missing | `src/peer_connection/handler/dtls.rs:517` | `a_fingerprint_mismatch_fails_the_dtls_transport_and_the_connection` | The transport goes to failed; no error event or reason |
| WEBRTC-11.2-3 | 11.2 | MUST | errorDetail "fingerprint-failure" | missing | `src/peer_connection/handler/dtls.rs:517` | `a_fingerprint_mismatch_fails_the_dtls_transport_and_the_connection` | State failed is tested; the cause is not surfaced |
| WEBRTC-11.2-4 | 11.2 | MUST | errorDetail "sctp-failure", with the cause code | missing | `src/peer_connection/handler/datachannel.rs:551` | `association_failure_fires_error_then_close` | - |
| WEBRTC-11.2-5 | 11.2 | MUST | errorDetail "sdp-syntax-error", with the line number | missing | `rtc-shared/src/error.rs:1` | - | - |
| WEBRTC-11.2-6 | 11.2 | MUST | errorDetail "hardware-encoder-not-available" | n/a | - | - | No encoder in the engine |
| WEBRTC-11.2-7 | 11.2 | MUST | errorDetail "hardware-encoder-error" | n/a | - | - | No encoder in the engine |
| WEBRTC-11.3-1 | 11.3 | MUST | RTCErrorEvent.error: the RTCError that triggered the event | missing | `src/peer_connection/event/data_channel_event.rs:1` | - | Error events carry only the channel handle |
| WEBRTC-12-1 | 12 | MUST | RTCDataChannel open | tested | `src/peer_connection/handler/datachannel.rs:186` | `in_band_channel_fires_open_only_when_ack_is_processed` | - |
| WEBRTC-12-2 | 12 | MUST | RTCDataChannel message | tested | `src/peer_connection/handler/datachannel.rs:320` | `first_message_sent_on_open_reaches_the_peer_that_comes_up_last` | - |
| WEBRTC-12-3 | 12 | MUST | RTCDataChannel bufferedamountlow | untested | `src/peer_connection/handler/datachannel.rs:634` | - | - |
| WEBRTC-12-4 | 12 | MUST | RTCDataChannel error | tested | `src/peer_connection/handler/datachannel.rs:551` | `association_failure_fires_error_then_close` | Without RTCError content, see 11.x |
| WEBRTC-12-5 | 12 | MUST | RTCDataChannel closing | tested | `src/peer_connection/handler/datachannel.rs:596` | `remote_close_fires_closing_then_close` | - |
| WEBRTC-12-6 | 12 | MUST | RTCDataChannel close | tested | `src/peer_connection/handler/datachannel.rs:112` | `tests/graceful_close.rs` | - |
| WEBRTC-12-7 | 12 | MUST | RTCPeerConnection track | tested | `src/peer_connection/event/mod.rs:335` | `tests/media_only_negotiation_no_sctp.rs` | - |
| WEBRTC-12-8 | 12 | MUST | RTCPeerConnection negotiationneeded | tested | `src/peer_connection/event/mod.rs:257` | `tests/jsep_negotiation_needed.rs` | - |
| WEBRTC-12-9 | 12 | MUST | RTCPeerConnection signalingstatechange | untested | `src/peer_connection/event/mod.rs:341` | - | No test observes `OnSignalingStateChangeEvent` |
| WEBRTC-12-10 | 12 | MUST | RTCPeerConnection iceconnectionstatechange | tested | `src/peer_connection/event/mod.rs:378` | `tests/media_only_negotiation_no_sctp.rs` | - |
| WEBRTC-12-11 | 12 | MUST | RTCPeerConnection icegatheringstatechange | untested | `src/peer_connection/event/mod.rs:411` | - | No test observes `OnIceGatheringStateChangeEvent` |
| WEBRTC-12-12 | 12 | MUST | RTCPeerConnection icecandidate | tested | `src/peer_connection/event/mod.rs:286` | `tests/ice_candidate_events_test.rs` | - |
| WEBRTC-12-13 | 12 | MUST | RTCPeerConnection connectionstatechange | tested | `src/peer_connection/event/mod.rs:458` | `tests/data_channels_negotiated_rtc2rtc.rs` | - |
| WEBRTC-12-14 | 12 | MUST | RTCPeerConnection icecandidateerror | untested | `src/peer_connection/event/mod.rs:310` | - | No test observes `OnIceCandidateErrorEvent` |
| WEBRTC-12-15 | 12 | MUST | RTCPeerConnection datachannel | partial | `src/peer_connection/handler/datachannel.rs:186` | `tests/data_channels_create_interop.rs` | Folded into the channel's `OnOpen` |
| WEBRTC-12-16 | 12 | MUST | RTCDTMFSender tonechange | missing | - | - | No DTMF sender |
| WEBRTC-12-17 | 12 | MUST | RTCIceTransport statechange | partial | `src/peer_connection/event/mod.rs:378` | `tests/media_only_negotiation_no_sctp.rs` | One transport: surfaced only as the connection's ICE connection state event |
| WEBRTC-12-18 | 12 | MUST | RTCIceTransport gatheringstatechange | partial | `src/peer_connection/event/mod.rs:411` | - | Surfaced only as the connection's gathering state event |
| WEBRTC-12-19 | 12 | MUST | RTCIceTransport selectedcandidatepairchange | missing | `src/peer_connection/event/mod.rs:556` | - | `ICESelectedCandidatePairChange` is internal; the application gets no event (the selected pair can be read) |
| WEBRTC-12-20 | 12 | MUST | RTCDtlsTransport statechange | missing | `src/peer_connection/event/mod.rs:229` | - | No DTLS state event; the state is readable and feeds the connection state |
| WEBRTC-12-21 | 12 | MUST | RTCDtlsTransport error | missing | `src/peer_connection/event/mod.rs:229` | - | No DTLS error event |
| WEBRTC-12-22 | 12 | MUST | RTCSctpTransport statechange | missing | `src/peer_connection/event/mod.rs:229` | - | No SCTP state event |

## Gaps, in order of importance

Across the whole specification, the work packages that matter most (details and row ids in the per-section lists below):

1. **A description applies fully or not at all, and rollback works** (sections 1 to 4, packages 1 and 2; L).
2. **The sender / receiver / transceiver object model** (section 5, packages 1 and 3; L): every transceiver has a sender and a receiver, `removeTrack` keeps the sender, stopping versus stopped.
3. **Remote tracks are processed when the description is applied** (section 5, package 2; sections 6 to 12, package 5; L): track events at setRemoteDescription, muted state.
4. **Events, state and error detail an API layer cannot get today** (sections 1 to 4, package 7; section 5, package 5; sections 6 to 12, packages 1 and 4; M).
5. **Data channel creation checks and send() state** (sections 6 to 12, packages 2 and 3; M).
6. **Simulcast negotiated from the remote side** (sections 1 to 4, package 3; L).
7. **Negotiation-needed and ICE restart bookkeeping** (sections 1 to 4, packages 4 and 5; S / M).
8. **Receiver sources, jitter buffer target, capabilities and codec match** (section 5, packages 4 and 6; M).
9. **DTMF** (sections 6 to 12, package 6; L).
10. **Tests for implemented behaviour** (165 MUST rows are `untested`).

### Sections 1 to 4 (peer connection, descriptions, negotiation, ICE candidates, certificates)

1. **Set-description atomicity and error cases** (M) — a description must either apply fully or
   change nothing, and the spec's refusals must exist. Validate everything (ICE credentials,
   fingerprints, mids, rtcp-mux under `require`, rid renegotiation) before the signaling state and
   the pending/current descriptions change; apply a staged ICE restart only after a local
   description is accepted; expose the SDP line number of a parse error.
   Rows: 4.4.1.4-8, -9, -10, -11, -13; 4.2.5-2.
2. **Rollback is incomplete** (L) — rollback must be accepted from either method in
   have-local-offer and have-remote-offer, and restore what the offer changed: negotiated codecs
   / media engine, SCTP transport, rid-less send encodings, remote streams and tracks.
   `setRemoteDescription(offer)` in have-local-offer must roll back implicitly (or the engine must
   offer that as one call).
   Rows: 4.4.1.4-17, -19, -20, -21, -72, -75, -76, -77, -80; 4.4.2-52; 4.4.1.1-13.
3. **Simulcast negotiated from the remote side** (L) — a remote offer asking to receive simulcast
   must produce send encodings (rid order, first alternative, dedupe, truncation,
   scaleResolutionDownBy), answers must prune encodings for missing layers, and createAnswer must
   leave out rids the sender does not have.
   Rows: 4.4.1.4-44, -45, -49, -50, -51, -52, -54, -57, -58, -83; 4.4.2-40.
4. **Negotiation-needed correctness** (S) — the check returns true whenever there is no current
   local description; `restart_ice` does not trigger it and the credentials step is skipped; no way
   to add a transceiver without triggering it.
   Rows: 4.7.3-9, 4.7.3-10, 4.4.2-70, 4.4.3-8; untested 4.7.3-11, -13.
5. **ICE restart bookkeeping** (M) — model `[[LocalIceCredentialsToReplace]]`: the request must
   survive a discarded or rolled-back offer and clear only when an answer no longer carries the old
   credentials; createOffer must not consume it.
   Rows: 4.4.1.4-27, -32; 4.4.2-69, -71; 4.4.1.1-24; 4.4.2-32.
6. **State machine entry checks and implicit descriptions** (M) — createOffer needs the
   signaling-state check; setLocalDescription needs type inference and implicit
   createOffer/createAnswer for an empty or stale SDP; `last_offer`/`last_answer` must be cleared
   on an answer; every method must refuse a closed connection.
   Rows: 4.4.2-22, -44, -48, -50; 4.4.1.4-25, -31; 4.6.2-5; 4.4.1.2-1; 4.4.2-86.
7. **Events and state the API layer cannot get** (M) — signalingstatechange only on a change;
   no connectionstatechange on close; public getters for signaling, ICE connection and connection
   state; the "gathering" transition and its event; end-of-candidates and null-candidate
   icecandidate events; icecandidateerror (needs an application entry point to report a
   STUN/TURN failure); track / mute / stream changes raised when a description is applied.
   Rows: 4.4.1.4-85, -86, -87, -88, -89, -90, -91; 4.4.2-7, -9, -10, -14, -17, -85; 4.3.2-2;
   4.8.2-4, -5; 4.8.3-1..5.
8. **RTCIceCandidate completeness** (S) — carry sdpMid, sdpMLineIndex, usernameFragment and
   relayProtocol on local candidates and in `to_json`; withhold the address of remote candidates
   the application did not supply.
   Rows: 4.8.1-5, -6, -11, -17, -18, -20, -22; 4.8.2-1, -6.
9. **setConfiguration / configuration validation** (S) — compare certificates by identity against
   the list given at construction (keep it readable in `get_configuration`), validate everything
   before storing anything, allow clearing ICE servers and the pool size, pass the new server list
   to whoever gathers, refuse empty `urls`, stun queries at construction, userinfo/fragment in
   URLs and over-long TURN usernames; make the defaults the W3C ones ("all", "balanced",
   "require") and drop `Negotiate`.
   Rows: 4.4.1.5-1, -2, -5, -8, -12, -13, -16, -17, -18, -20, -23; 4.2.1-3, -4, -5, -9;
   4.2.5-3; 4.4.2-72; 4.4.1.1-9.
10. **Remote-offer transceiver direction and pranswer handling** (S) — a transceiver created for
    a remote m= section is `recvonly`; a pranswer sets current direction and updates the max
    message size; ICE role is fixed at the first offer (local offer: controlling) and not
    recomputed.
    Rows: 4.4.1.4-36, -48, -56, -65, -67, -68.
11. **close()** (S) — stop transceivers, set data channel / SCTP / DTLS / ICE transport and ICE
    connection states to closed, with tests for each.
    Rows: 4.4.2-78, -79, -80, -81, -83, -84; 4.3.4-1.
12. **Administrative prohibition** (S) — Fetch bad-port list for remote candidates; under
    `relay`, refuse mDNS / DNS-name candidates.
    Rows: 4.4.2-64, -68; 4.4.1.4-4; 4.4.2-58 (stopped-transceiver candidates), 4.4.2-54.
13. **Certificates** (S) — a `generateCertificate`-shaped entry point with the 30-day default and
    365-day cap, fingerprints with the signature's digest, RSA-2048 generation in a built-in
    provider (or documented as import-only), key-handle serialisation.
    Rows: 4.9-3, -6, -7, -8, -9, -10, -15; 4.9.2-3, -5, -6.
14. **Bundle policies** (XL, deliberate) — `balanced` / `max-compat` need more than one transport
    (decision D2). The promised "defined error" for a remote offer without BUNDLE has no test or
    error variant.
    Rows: 4.2.4-1, -2, -3.
15. **Tests only** (M) — 75 MUST rows are implemented with no test; the cheap ones are the error
    paths: closed-connection errors, ErrSDPDoesNotMatchOffer/Answer, ErrIncorrectSignalingState,
    ErrCertificateExpired, ErrModifying*, rollback in stable / pranswer states, addIceCandidate
    without a remote description or with an out-of-range index, ICE role with ice-lite,
    OnSignalingStateChangeEvent.

### Section 5 (RTP media API, DTLS and ICE transports)

1. **Sender / receiver / transceiver object model (L).** A transceiver always has a sender and a receiver; a sender's track can be null; `removeTrack` keeps the sender; `getSenders` / `getReceivers` list every non-stopped transceiver; `replaceTrack(null)`; `addTransceiver(track, {direction: recvonly|inactive})`; default direction sendrecv. Rows: WEBRTC-5-4, 5.1-2, 5.1-3, 5.1-6, 5.1-7, 5.1-8, 5.1-15, 5.1-16, 5.1-20, 5.1-36, 5.2-1, 5.2-3, 5.2-5, 5.2-31, 5.2-32, 5.2-34, 5.2-36, 5.2-37, 5.4-4, 5.4-5, 5.4.2-1.
2. **Remote track processing at setRemoteDescription (L).** Track event when the description is applied (not on first RTP), FiredDirection, mute on direction change and initial muted state, several msids per track with add/remove lists, engine-generated track ids, track ended on `stop()`. Rows: WEBRTC-5.1.1-1, 5.1.1-2, 5.1.1-4, 5.1.1-5, 5.1.1-6, 5.1.1-7, 5.3-1, 5.3-3, 5.3-4, 5.4-17, 5.7-3, 5.7-4.
3. **Stopping versus stopped, and the "stopped" direction value (M).** Separate Stopping and Stopped slots, `Stopped` enum value for direction / currentDirection, currentDirection null after stop, state checks in the direction setter and `stop()`. Rows: WEBRTC-5.1-43, 5.4-1, 5.4-6, 5.4-7, 5.4-11, 5.4-12, 5.4-19, 5.4-20.
4. **getContributingSources / getSynchronizationSources and jitterBufferTarget (M).** Fill the source lists from received packets (CSRC list, RFC 6464 / 6465 levels, 10-second window, optional audioLevel); accessor, range check and wiring of the jitter-buffer target to the jitter-buffer interceptors. Rows: WEBRTC-5.3-7, 5.3-8, 5.3-9, 5.3-15 to 5.3-24.
5. **Transport events (M).** DTLS statechange and error (with errorDetail and alert), ICE gathering-state change to gathering, end-of-gathering and null candidate events, selectedcandidatepairchange, transport-level statechange; `role()` unknown before it is decided; `getRemoteCandidates` without peer-reflexive ones; `getLocalParameters` null before a local description; selected pair null after close. Rows: WEBRTC-5.5-4, 5.5-5, 5.6-2, 5.6-3, 5.6-5, 5.6-7, 5.6-12, 5.6-14, 5.6-16, 5.6-17, 5.6-18, 5.6-23, 5.6-24, 5.6-25, 5.6.3-3, 5.6.5-1.
6. **Capabilities and the codec dictionary match (M).** Static `getCapabilities(kind)` from the media engine (one RTX entry, no fmtp), a real codec dictionary match (clockRate, channels, fmtp presence, symmetric / asymmetric parameters) used by setCodecPreferences, setParameters and addTransceiver; duplicate removal and the "only repair formats" check; direction filtering of preferences. Rows: WEBRTC-5.2-10, 5.2-17, 5.2.10-1, 5.2.10-2, 5.3-11, 5.4-22, 5.4-24, 5.4-25, 5.4-26, 5.4-29, 5.4-30, 5.4-31, 5.4-32.
7. **addTransceiver sendEncodings validation and defaults (S).** rid grammar, audio member removal, range checks, maximum encodings, scaleResolutionDownBy defaults, rid dropped from a lone encoding. Rows: WEBRTC-5.1-22, 5.1-27 to 5.1-32, 5.2-4.
8. **getParameters contents (S).** rtcp.cname, rtcp.reducedSize, `encrypted`, per-m-section header extensions, re-order detection, simulcast envelope narrowing, maxBitrate enforcement. Rows: WEBRTC-5.2-15, 5.2-26, 5.2-28, 5.2.1-2, 5.2.5-3, 5.2.5-4, 5.2.5-5, 5.2.6-1, 5.2.6-2, 5.2.7-3, 5.3-12, 5.3-14, 5.4.1-3.
9. **DTMF sender on audio senders (M).** Row: WEBRTC-5.2-2 (section 7 has the rest).
10. **Tests for the 50 untested rows (M).** Closed-connection errors, removeTrack direction changes, BYE after stop(), ICE state sequences across restart, candidate lists against the descriptions.

### Sections 6 to 12 (data channels, DTMF, statistics model, media stream extensions, errors, events)

1. **Error detail for an API layer (M).** WEBRTC-11.1-1,WEBRTC-11.1-2,WEBRTC-11.1-3,WEBRTC-11.1-4,WEBRTC-11.1-5,WEBRTC-11.2-1,WEBRTC-11.2-2,WEBRTC-11.2-3,WEBRTC-11.2-4,WEBRTC-11.2-5,WEBRTC-11.3-1, plus the error rows of 6.2 (`OnError(id)` only). Add an error-detail value (data-channel-failure, sctp-failure with cause code, dtls-failure with received / sent alert, fingerprint-failure, sdp-syntax-error with line number) to the data channel error event, a DTLS transport error event and the SDP parse error. Without it a binding cannot build RTCError.
2. **createDataChannel id validation and the connected procedure (M).** WEBRTC-6.1-5, WEBRTC-6.1-16, WEBRTC-6.1-18, WEBRTC-6.1-19, WEBRTC-6.1.1.3-3, WEBRTC-6.2.7-1,WEBRTC-6.2.7-2: check the label length; refuse id 65535, a duplicate negotiated id and an id at or above maxChannels; when an id cannot be assigned at SCTP connect, close that one channel with error + close instead of failing the whole event; do not leave a channel registered when createDataChannel returns an error.
3. **send() state and buffer checks (S).** WEBRTC-6.2-20, WEBRTC-6.2-24, WEBRTC-6.1.1.1-2,WEBRTC-6.1.1.2-6,WEBRTC-6.2-24, WEBRTC-6.2-16, WEBRTC-6.2.8-1: gate send on readyState == open (not on "has a stream"), add MaxBufferSize and the OperationError above it, make a second close() a no-op.
4. **Transport events (S).** WEBRTC-12-15,WEBRTC-12-16,WEBRTC-12-17,WEBRTC-12-18,WEBRTC-12-19,WEBRTC-12-20,WEBRTC-12-21,WEBRTC-12-22, WEBRTC-6.1.1.3-4: events for SCTP state, DTLS state and error, ICE selected candidate pair change; a distinct datachannel event (or a flag on OnOpen saying the peer opened it).
5. **Remote track muted state (M).** WEBRTC-9.3-1,WEBRTC-9.3-2,WEBRTC-9.3-3: mute on BYE instead of ending the track, unmute when RTP arrives again, mute from setRemoteDescription; WEBRTC-9.3.1-2 (reject constraints on a remote track); WEBRTC-9.3.1-3,WEBRTC-9.3.1-4,WEBRTC-9.3.1-5,WEBRTC-9.3.1-6 (a feed for the remote video settings).
6. **DTMF (L).** WEBRTC-7.1-1,WEBRTC-7.4-1 (every row of section 7): RTCDTMFSender tone buffer, clamping, playout timer in the sans-I/O `handle_timeout`, RFC 4733 telephone-event packets, tonechange event, canInsertDTMF; telephone-event in the default codecs.
7. **Stats model (S to M).** WEBRTC-8.4-5 (salt the ids per connection), WEBRTC-8.2-3 (error for an unknown selector), mandatory members that are app-feed only or absent (WEBRTC-8.6-29,WEBRTC-8.6-95 and the rows between; detail in w3c-webrtc-stats.md).
8. **Tests (M).** Every `untested` row: createDataChannel error cases, SCTP state "connected" / closed-by-DTLS, maxChannels after connect, bufferedamountlow, signalingstatechange / icegatheringstatechange / icecandidateerror events, remote msid to stream id.

## Bugs found

### Sections 1 to 4 (peer connection, descriptions, negotiation, ICE candidates, certificates)

- **B1: a remote description that fails late leaves the connection half-changed.**
  `set_remote_description` calls `set_description` (signaling state, pending/current
  descriptions, transceiver creation) before `extract_ice_details`, fingerprint extraction and
  transport start (`src/peer_connection/mod.rs:1452` vs `:1709`). Reproduce: apply a remote offer
  with one audio section and no `a=ice-ufrag`; expect `Err` and then assert the signaling state is
  still stable, `pending_remote_description()` is None and no transceiver was added. Contradicts
  the w2.md row "a remote description that fails to apply leaves the signaling state ... as they
  were". Same shape: a remote answer naming an unknown mid (`ErrPeerConnTransceiverMidNil` at
  `:1671`) after the state already went stable.
- **B2: a refused local description still applies a staged ICE restart.**
  `set_local_description` runs `apply_ice_restart` (`mod.rs:1208`) before any validation.
  Reproduce: connected pair; `restart_ice()`; `create_offer`; then call `set_local_description`
  with a tampered copy of the offer (or a rollback in stable): it returns an error, yet the agent
  has restarted (local credentials changed, candidates discarded per the setting).
- **B3: negotiationneeded fires with nothing to negotiate.** `check_negotiation_needed` returns
  true whenever `current_local_description` is None (`internal.rs:1596`). Reproduce: fresh
  connection, apply a remote audio offer, roll it back with `set_remote_description(rollback)`,
  drain events: an `OnNegotiationNeededEvent` appears although there is no transceiver and no
  data channel.
- **B4: the configured certificates vanish from the configuration, so `set_configuration` with
  the original configuration fails.** `RTCPeerConnection::new` moves them out
  (`internal.rs:152`). Reproduce: build with one certificate; `get_configuration().certificates()`
  is empty; `set_configuration(original_config)` returns `ErrModifyingCertificates` (1 != 0).
  The check compares lengths only and then stores the new list (`mod.rs:2224-2229`), so
  certificate identity is never compared.
- **B5: rolling back a remote offer does not restore the negotiated codecs.**
  `set_remote_description` replaces `self.media_engine` with the copy updated from the offer
  (`mod.rs:1457`) and sets codec preferences on transceivers; `rollback_transceivers` restores
  neither. Reproduce: negotiate VP8+H264; apply a remote re-offer listing only VP8 (or different
  payload types); roll it back; `create_offer` and compare the codec list with the one before the
  re-offer. (Needs confirming against what `update_from_remote_description` narrows.)
- **B6: `set_configuration` is not atomic.** Members are stored as they are checked
  (`mod.rs:2216-2278`). Reproduce: call it with a new `iceTransportPolicy` of relay and an invalid
  ICE server URL: it returns an error, but `get_configuration().ice_transport_policy()` is relay
  and the agent's candidate types changed.
- **B7: `set_local_description(rollback)` is refused in have-remote-offer (and
  `set_remote_description(rollback)` in have-local-offer).** `check_next_signaling_state`
  (`state/signaling_state.rs:350-420`) ties the rollback to the side that made the offer; W3C
  accepts it from either method. The unit test
  `a_remote_offer_can_be_applied_again_and_rolled_back` asserts the refusal.
- **B8: signalingstatechange is emitted when the state did not change.** `set_description` calls
  `do_signaling_state_change` unconditionally (`internal.rs:850`). Reproduce: apply the same
  remote offer twice (have-remote-offer both times) and count `OnSignalingStateChangeEvent`: two.
- **B9: `close()` queues `OnConnectionStateChangeEvent(Closed)`** (`handler/mod.rs:572`); W3C
  close fires no event. Reproduce: close and drain events.
- **B10: `create_offer` works in have-remote-offer** (no state check, `mod.rs:814`), and
  consumes a pending `restart_ice()` request there. Reproduce: apply a remote offer, call
  `create_offer`: expect an invalid-state error, get an offer.
- **B11: set_local_description marks ICE gathering as "gathering" on every success**
  (`mod.rs:1319`), including a rollback and a renegotiation after gathering completed, with no
  event; the description then omits `a=end-of-candidates`. Reproduce: finish gathering (empty
  local candidate), renegotiate, read `ice_transport().gathering_state()`.
- **B12: the transceiver created for a recvonly remote section is `Sendonly`**
  (`mod.rs:1599`), where W3C creates it `recvonly`. Reproduce: apply a remote offer with
  `a=recvonly` audio; read the new transceiver's direction.
- **B13 (inconsistency): a `stun:` URL with a query is accepted by the constructor (the query is
  stripped, `configuration/mod.rs:349`) and refused by `set_configuration`.** Reproduce: build
  with `stun:host?transport=udp`, then `set_configuration` with the same configuration.

### Section 5 (RTP media API, DTLS and ICE transports)

1. **`get_senders` / `get_receivers` filter on direction** (`src/peer_connection/mod.rs:2428`, `:2444`). Reproduce: `add_transceiver_from_kind(Video, recvonly)` then `get_senders().count()` is 0 and, for a sendonly transceiver, `get_receivers().count()` is 0; the spec lists both for every non-stopped transceiver.
2. **`remove_track` ignores the transceiver's state and drops the sender** (`mod.rs:2674`). Reproduce: add a track, `stop()` the transceiver, call `remove_track`: the direction is rewritten, negotiation-needed fires again; afterwards `rtp_sender(id).unwrap().track()` panics on `unwrap()` because the sender is gone.
3. **A stopped transceiver's direction can be changed** (`src/rtp_transceiver/mod.rs:343`). Reproduce: `stop()`, then `set_direction(Sendrecv)`: no error, `direction()` reads sendrecv and OnNegotiationNeeded fires; the next offer still rejects the section.
4. **Sender `get_capabilities` is empty before negotiation and ignores the engine's codecs** (`rtp_sender/internal.rs:122`). Reproduce: add a video track on a default MediaEngine, call `get_capabilities(Video)` before any offer: `codecs` is empty (or only the preferred subset), not VP8/VP9/H264/AV1.
5. **Codec match ignores clockRate and channels** (`rtp_codec.rs:165`). Reproduce: `set_codec_preferences` with `audio/opus` at clockRate 8000, channels 1: accepted, where InvalidModificationError is required.
6. **`set_codec_preferences` accepts a list of only RTX** (`rtp_transceiver/internal.rs:245`). Reproduce: pass only the `video/rtx` entry; the next offer's video section has a repair format and no media codec.
7. **`set_streams(vec![])` does not clear the streams** (`rtp_sender/internal.rs:309`): it restores the track's own stream id, so the msid line never becomes `a=msid:- track`. Reproduce: call it with an empty list and read the next offer.
8. **`replace_track` changes the msid** (`rtp_sender/internal.rs:285`): it overwrites the associated stream ids with the new track's stream id, so a replacement that must not need negotiation raises a different `a=msid` in the next offer. Reproduce: replace with a track of another stream id, create an offer, compare msid lines.
9. **`getRemoteCandidates` exposes peer-reflexive candidates** (`transport/ice/mod.rs:130`). Reproduce: connect with one side signalling no candidates; the other side's `get_remote_candidates()` lists a prflx candidate.
10. **`get_local_parameters` before a local description** (`transport/ice/mod.rs:58`) returns credentials where null is required. Reproduce: build a connection and call it at once.
11. **Gathering "complete" is announced every time** (`mod.rs:2130`): each empty local candidate pushes `OnIceGatheringStateChangeEvent(Complete)`, also when the state did not change, and the change to "gathering" is never announced. Reproduce: call `add_local_candidate` with an empty candidate twice and count events.
12. **The track event depends on media** (`handler/interceptor.rs:899`): a remote sendonly/sendrecv section whose sender never sends RTP produces no track event at all. Reproduce: apply a remote offer with a sending video section and poll events without feeding RTP.
13. **A lone encoding keeps its rid** (`internal.rs:2203`). Reproduce: `add_transceiver_from_kind` with one send encoding that has rid "a": the offer carries `a=rid:a send` / `a=simulcast:send a` for a single layer.

### Sections 6 to 12 (data channels, DTMF, statistics model, media stream extensions, errors, events)

1. **One unassignable channel id fails every pending channel.** `handle_event(SCTPHandshakeComplete)` (`src/peer_connection/handler/datachannel.rs:489`) propagates `assign_stream_ids(..)?`. Reproduce: create enough in-band channels before negotiation that the ids of this side's parity run past the negotiated stream count (or set a small `max_channels`), connect: the handler returns `ErrMaxDataChannelID`, no channel is dialed and none gets an error or close event.
2. **createDataChannel that fails leaves the channel registered.** `src/peer_connection/mod.rs:2370-2391`: the channel is inserted before `assign_stream_ids` can return an error. Reproduce: on a connected peer exhaust the ids, call `create_data_channel` (Err), then `get_stats`: a data-channel object for the failed channel is there, and every later create fails too.
3. **A duplicate negotiated id is accepted.** `DataChannelRegistry::insert` (`src/data_channel/registry.rs:28`) overwrites `by_stream`. Reproduce: two `create_data_channel` calls with `negotiated: Some(5)`: both succeed; inbound data on stream 5 reaches only the second, the first never opens or closes.
4. **Negotiated id 65535 and ids at or above maxChannels are accepted.** Same path, no range check. Reproduce: `negotiated: Some(65535)` returns Ok.
5. **A label over 65535 bytes is accepted.** `create_data_channel` checks the protocol length only. Reproduce: a 70000-byte label returns Ok; the DCEP open then cannot carry it (16-bit length).
6. **send() is allowed while connecting (awaiting the DCEP ACK) and while closing.** `ensure_sendable` (`src/data_channel/mod.rs:306`) tests `dc.data_channel.is_none()`, not the ready state. Reproduce: create an in-band channel on a connected association, call `send` before the ACK arrives (ready_state is Connecting): Ok. Call `close()` then `send`: no state error.
7. **A BYE ends the remote track.** `process_goodbyes` (`src/peer_connection/handler/interceptor.rs:195`) calls `track.stop()` and fires `OnClose`; the spec mutes the track, and media that resumes on that SSRC has no live track. Reproduce: receive RTP, a BYE for the SSRC, RTP again: the track is ended and stays ended.
8. **applyConstraints on a remote track succeeds.** `src/media_stream/track.rs:664` stores the constraints. Reproduce: call it on a receiver's track; no error.
9. **Stats ids are predictable.** Fixed strings ("RTCPeerConnection", "RTCTransport", "RTCInboundRTPStream_video_<ssrc>"). Reproduce: compute the id from the SSRC without reading a report and look it up.

## Not finished, and limits of the pass

### Sections 1 to 4 (peer connection, descriptions, negotiation, ICE candidates, certificates)

Nothing in the slice was skipped: every section from 1 to 4.9.2 has rows. Limits of the pass:
- Sub-transport state after `close()` (rows 4.4.2-79 to -84, 4.3.4-1) and the bundle-tagged
  section choice (4.4.2-26) were read at the peer-connection level only; they are marked
  `untested` / `partial`, not verified in the SCTP / DTLS / ICE crates.
- B5 and row 4.8.1-11 are from reading; neither was confirmed by tracing every callee.

### Section 5 (RTP media API, DTLS and ICE transports)

Nothing left out of §5. Limits of this pass: test bodies were read for names and a sample of assertions only, so some `tested` verdicts rest on the test's name and file matching the behaviour (notably 5.1-12, 5.2.7-1/2, 5.4.1-4, 5.6-1, 5.6.4-7, 5.6.5-2/3); ICE state semantics (5.6.4) are judged for mapping only and belong to the ICE auditor; line numbers for struct-only references (`:1`) point at the file.

### Sections 6 to 12 (data channels, DTMF, statistics model, media stream extensions, errors, events)

Nothing left out of lines 2736-3693. Limits of the pass: section 10 (examples) and the privacy / accessibility sections after 12 are informative and have no rows; section 8.6 rows judge presence only (measurement is in w3c-webrtc-stats.md); the events of section 12 that belong to sections 4 and 5 were judged only for "is the trigger surfaced and is there a test that observes it", not for their state machines.

