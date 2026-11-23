# Congestion control on a path that reorders

Measured on `conf/pacer-1-queue-time` and its follow-up, against libwebrtc at revision
`a222406d49ecffb8e045d113e45f89f62b3819e8`. Two separate findings; the first is fixed, the
second is a proposal.

## 1. Loss-based control: a packet only overtaken was counted lost (fixed)

The feedback history released every packet up to the highest one acknowledged as received, so a
packet a feedback reported "not received" because a later packet had overtaken it was counted as
lost at once and forgotten; the later feedback reporting it received matched nothing.

libwebrtc keeps it: `TransportFeedbackAdapter::RetrievePacketFeedback` (`modules/congestion_controller/rtp/transport_feedback_adapter.cc`):

> Note: Lost packets are not removed from history because they might be reported as received by
> a later feedback.

and marks it `previously_reported_lost`, so a later feedback gives
`reported_recovered_for_the_first_time`; `LossBasedBweV2::PushBackObservation`
(`loss_based_bwe_v2.cc`) erases a packet from its lost set when a later result says it was
received.

Our history now holds a reported loss for one more feedback; a packet reported received by then
is reported received (without its arrival time: the delay model reads reports in send order),
`History::recovered` counts it. Measured, 500 kbit/s video, 60 s, every datagram held back by up
to 40 ms, nothing lost (`tests/circuit_breaker_reordering_rtc2rtc.rs`, the video test with
`RUST_LOG=rtc_interceptor::gcc=debug`):

| | feedback batches | packets counted lost | reported received after a feedback reported them lost | target at the end |
|---|---|---|---|---|
| before | 1241 | 514 of 6261 (8.2 %); loss average up to 12 % | 1148, each matching nothing (already released as lost) | 100 kbit/s (loss target 183 to 194 kbit/s while the delay target was 650 to 730 kbit/s) |
| after | 1198 | 0 of 6385 | 595, reported received (`History::recovered`) | 677 kbit/s |

Feedback by feedback, before (from the middle of the run; each line one feedback): `feedback of 6
packets, 1 lost; loss average 0.090` / `4 packets, 0 lost; 0.072` / `6 packets, 1 lost; 0.091` /
`5 packets, 1 lost; 0.113, loss target 182831` / `5 packets, 0 lost; 0.090`, with the delay target
at 700 to 730 kbit/s throughout. After, the same feedbacks carry no loss.

The reordering sweep (two flows, target at the end, kbit/s, before → after):

| reorder | loss | 500 kbit/s | 2000 kbit/s |
|---|---|---|---|
| 10 ms | 0 % | 743 → 749 | 1756 → 2911 |
| 10 ms | 2 % | 687 → 698 | 100 → 2570 |
| 10 ms | 5 % | 144 → 462 | 1052 → 2032 |
| 40 ms | 0 % | 100 → 703 | 1147 → 2319 |
| 40 ms | 2 % | 100 → 597 | 828 → 2448 |
| 40 ms | 5 % | 293 → 556 | 322 → 1118 |
| 100 ms | 0 % | 100 → 133 | 100 → 150 |
| 0 ms (no reordering) | 0 to 5 % | unchanged within a few % | unchanged within a few % |

At 100 ms of reordering the target stays at the floor: that is the delay-based half (below).

## 2. Delay-based grouping: more packets discarded, more noise (proposal, not changed)

`delay_based_bwe.cc` sorts each feedback's packets by receive time
(`msg.SortedByReceiveTime()`) before `InterArrivalDelta` groups them by send time (5 ms groups,
a packet sent before its group's first is discarded as reordered). Our `ArrivalGroupAccumulator`
reads them in send order and drops a packet that arrived before the current group's latest
arrival. The same 6000 packets (100 a second, 25 ms one way, a share held back) through both
groupings and the same Kalman filter and overuse detector
(`rtc-interceptor/src/gcc/slope.rs`, `reorder_trace_against_libwebrtc_grouping`):

| path | ours: readings, gradient sd | libwebrtc's: readings, gradient sd |
|---|---|---|
| no reordering | 5998, 0.00 ms | 5998, 0.00 ms |
| half held by up to 40 ms | 3079, 15.5 ms | 3915, 7.0 ms (1677 packets discarded) |
| all held by up to 40 ms | 3277, 11.7 ms | 3468, 11.6 ms |
| half held by up to 100 ms | 1696, 30.8 ms | 3389, 6.5 ms |

Neither reached overuse in this replay (mean gradient about 0 in both), but ours keeps fewer
readings and has two to five times the noise on a path where only some packets are held back,
which the adaptive threshold then follows. Proposal: sort each feedback's reports by arrival
before grouping and discard a packet sent before its group's first, as `InterArrivalDelta` does
(keeping the 5 ms send-time groups and the burst rule), measured on the same sweep before it
replaces the present grouping. Not changed here: the loss fix above is measured on its own.
