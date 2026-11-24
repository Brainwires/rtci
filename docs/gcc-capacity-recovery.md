# Congestion control after a capacity cap lifts

Measured on `conf/gcc-1-cap-recovery` (and on the release, v0.22.0+brainwires.6) with the
TWCC-driven GCC (`rtci-interceptor/src/gcc/twcc_gcc`, no pacer: ParolNet's chain), in ParolNet's
simulation `m1::the_estimate_follows_a_cap_that_comes_and_goes` and in its port
`tests/capacity_cap_video_rtc2rtc.rs`. A finding for the congestion-control work; nothing here
is changed yet.

## The scenario

A call at about 1.4 Mbit/s; the caller's uplink drops to 300 kbit/s (30 ms one way, 300 ms
drop-tail queue) for twenty seconds after the estimate went under 400 kbit/s, then opens again
(10 ms, no cap). The test reads the estimate twenty seconds after the cap went.
v0.22.0+brainwires.5 gave 1.18 Mbit/s there; the release and this branch give 0.45 to 1.5
Mbit/s, depending on the seed.

## What decides the figure: where the estimate is when the cap goes

The controller climbs at 8% a second from wherever it is (`rate_controller.rs`,
`1.08f64.powf(dt_s)`), so twenty seconds multiply it by about 4.7. The figure is therefore set by
the estimate at the moment the path opens:

- At 250 kbit/s and climbing (v0.22.0+brainwires.5): 1.18 Mbit/s.
- Cut to the 100 kbit/s floor a second before (the release, half of this branch's seeds): 0.45
  to 0.5 Mbit/s.

The cut happens when the estimate has climbed back to the link's capacity before the cap goes.
ParolNet trace, first bad commit `ee4217b2` (per 100 ms: time, cap, target kbit/s | GCC
over/normal/under, loss % | caller's packets sent video/RTX/audio/RTCP, dropped at the queue the
same, queue ms):

```
 37.0 300   300 |  0/1/0   0.0 | 3/0/5/1   0/0/0/0    8
 38.0 300   324 |  0/1/0   0.0 | 3/0/5/1   0/0/0/0   36
 39.0 300   350 |  0/1/0   0.0 | 3/0/5/1   0/0/0/0  132
 39.5 300   364 |  0/1/0   0.0 | 3/0/5/1   0/0/0/0  215
 40.0 300   378 |  0/1/0   0.0 | 3/0/5/1   0/0/2/0  301
 40.5 300   279 |  0/1/0  37.5 | 3/0/5/1   0/0/3/0  303
 41.0 300   103 |  0/1/0  25.0 | 3/1/5/1   0/0/0/0    0   <- the cap goes at 41.1 s
 61.0   0   462 |  0/1/0   0.0 | 6/0/5/1   0/0/0/0    0   <- 20 s later
```

Two things happen, and neither is new in the release:

1. **The delay-based half does not see the queue growing.** From 37 s the queue grows from 8 to
   300 ms in three seconds and the trendline filter reports "normal" throughout. The filter is
   per packet with a window of 20 packets (`trendline.rs`), about 0.3 s at this rate; a queue
   that grows by 0.1 ms per ms gives a modified trend of about 2, under the threshold's floor
   of 6. Only the overflow is seen, as loss.
2. **The loss-based half cuts on every feedback.** Once the queue overflows, each 100 ms TWCC
   feedback covers about eight packets, two or three of them lost (25 to 40%), and each one
   multiplies the estimate by `1 - 0.5 p` (`rate_controller.rs`). Ten feedbacks a second take
   the estimate from 378 to 103 kbit/s within a second, to the floor, just before the path
   opens.

What changed in the release is only *when* the estimate reaches the capacity: v0.22.0+
brainwires.5 asked for every lost packet every 100 ms without limit, its retransmissions kept the
reported loss over 10% until about 29 s, and the estimate was still climbing (250 kbit/s) when the
cap went. With requests a round trip apart (RFC 4588 6.3, since `ee4217b2`) the loss ends about
six seconds earlier and the estimate reaches the capacity before the cap goes. Removing the round
trip between requests on the release restored 1.03 to 1.06 Mbit/s in ParolNet's simulation,
which confirms the timing; it is not a fix (the RFC asks for that wait).

## The draft

draft-ietf-rmcat-gcc-02 section 6:

> The loss-based controller SHOULD run every time feedback from the receiver is received.
>
> o  If 2-10% of the packets have been lost since the previous report from the receiver, the
>    sender available bandwidth estimate As_hat(i) will be kept unchanged.
>
> o  If more than 10% of the packets have been lost a new estimate is calculated as
>    As_hat(i) = As_hat(i-1)(1-0.5p), where p is the loss ratio.

The draft's feedback was the RTCP receiver report, about once a second; with transport-wide
feedback every 100 ms the same rule applies ten times as often, and the loss ratio of a report is
taken over eight packets instead of a second's worth.

## What libwebrtc does differently

The libwebrtc snapshot in `specs/libwebrtc/` (revision `a222406d`) carries
`goog_cc_network_control.cc` but not `send_side_bandwidth_estimation.cc` or
`loss_based_bwe_v2.cc`, so the following is from libwebrtc's sources outside the snapshot and is
to be checked against them before it is relied on:

- The classic loss-based controller (`SendSideBandwidthEstimation::UpdateEstimate`) decreases
  at most once per `kBweDecreaseInterval` (300 ms) plus the round-trip time, and only on a loss
  fraction taken over at least `kLimitNumPackets` (20) packets.
- `LossBasedBweV2` (what `goog_cc_network_control.cc` includes, line 37, and drives through
  `UpdateLossBasedEstimator`, line 519) fits a loss model over a window of observations instead
  of reacting to each report.

Either keeps a burst of overflow from compounding ten times a second into the floor.

## For the successor

- A decrease rate limit (once per 300 ms plus RTT) and a minimum packet count per loss ratio in
  `twcc_gcc/rate_controller.rs`, each a setting if the draft's per-report form stays the
  default; measured on this scenario (estimate 20 s after the cap, six seeds,
  `RTC_CAP_TRACE=1 cargo test --test capacity_cap_video_rtc2rtc -- --nocapture`).
- A trendline that sees a queue growing slowly (the 300 ms queue fills in three seconds without an
  over-use signal).
