# draft-ietf-rmcat-gcc: A Google Congestion Control Algorithm for Real-Time Communication

Spec: draft-ietf-rmcat-gcc-02, 8 July 2016 (expired working-group draft; the last published version). Audited against
fork master 8916bc3. Sections done: 3, 4, 5.1 to 5.6, 6, 7 (all algorithm text; 1, 2, 8 to 11 hold no requirement).

The draft has few BCP 14 keywords. Each algorithm step, equation and constant is a clause; the level is what the text
implies: an equation or step of the algorithm is MUST, a RECOMMENDED value or "should" is SHOULD, an explicit
alternative is MAY.

The engine has two implementations:

- **A, `Gcc`** (`rtc-interceptor/src/gcc/{estimator,arrival_group,kalman,slope,overuse,threshold,state,rate_calc,rate_control,loss}.rs`):
  the Kalman variant of the draft, driven through `CongestionControlInterceptor` (`cc/interceptor.rs`) by TWCC or
  RFC 8888 feedback, with `PacerInterceptor` (`pacing/`). This is what `configure_congestion_control` installs. **The
  table and the totals are for A.**
- **B, `GccInterceptor`** (`rtc-interceptor/src/gcc/twcc_gcc/{mod,trendline,rate_controller}.rs`): an older,
  self-contained trendline variant with a shared-handle output and no pacer. Its differences are listed after the table.

Totals (MUST includes MUST NOT/SHALL; SHOULD includes SHOULD NOT/RECOMMENDED):

- MUST: tested 20 / untested 3 / partial 6 / missing 5 / violated 1 / n-a 0
- SHOULD: tested 7 / untested 3 / partial 4 / missing 3 / violated 0 / n-a 0
- MAY: tested 0 / untested 0 / partial 0 / missing 1 / violated 0 / n-a 0

| ID | § | Level | Clause (short paraphrase) | Verdict | Code | Test | Note |
|---|---|---|---|---|---|---|---|
| GCC-3-1 | 3 | MUST | Send-side variant: the receiver records arrival time and transport-wide number of each packet and feeds them back periodically | tested | `twcc/receiver.rs`, `twcc/recorder.rs` | `test_twcc_receiver_generates_feedback_on_timeout`, `test_combined_twcc_sender_and_receiver` | |
| GCC-3-2 | 3 | SHOULD | Feedback once per received video frame, or at least every 30 ms when audio-only or multi-stream; up to 100 ms to limit overhead | partial | `twcc/receiver.rs:13` (100 ms), `rfc8888/sender.rs:16` (100 ms) | `test_twcc_receiver_configurable_interval` | Timer only, at the upper bound the draft allows; never per frame |
| GCC-3-3 | 3 | MUST | The sender maps each {sequence number, arrival time} to the packet's send time and feeds the delay-based controller | tested | `rtpfb/history.rs:86-131`, `cc/interceptor.rs:137-190`, `gcc/estimator.rs:127-146` | `reports_carry_the_transport_wide_sequence_numbers`, `every_departing_packet_is_recorded_at_its_release_instant`, `gcc_settles_under_a_rate_limited_link` | |
| GCC-3-4 | 3 | MUST | The sender computes a loss ratio from the sequence numbers in the feedback | tested | `gcc/estimator.rs:152-153` | `gcc_backs_off_on_a_lossy_path_with_no_queueing`, `the_more_pessimistic_half_wins` | The ratio also counts packets the feedback never covered (see bug G2) |
| GCC-3-5 | 3 | MAY | Receive-side variant: delay-based controller at the receiver, estimate returned in REMB | missing | REMB codec only: `rtc-rtcp/src/payload_feedbacks/receiver_estimated_maximum_bitrate/mod.rs` | codec tests only | No interceptor generates REMB, yet `goog-remb` is in the default video feedback (`media_engine.rs:403`, `video_rtcp_feedback`) |
| GCC-3-6 | 3 | SHOULD | With the receive-side variant the sender uses the abs-send-time header extension | partial | `rtc-rtp/src/packetizer/mod.rs:159-168` (`enable_abs_send_time`), `rtc-rtp/src/extension/abs_send_time_extension/mod.rs` | `abs_send_time_extension_test.rs`, `packetizer_test.rs` | Stamped only on the last packet of a frame, only when the application enables it on its packetizer; the engine never registers or stamps it |
| GCC-3-7 | 3 | MUST | Sender feeds received REMB and RR fraction-lost into the loss-based controller | missing | none (`ReceiverEstimatedMaximumBitrate` has no consumer in `src/` or `rtc-interceptor/src/`) | none | A REMB from a browser changes nothing |
| GCC-3-8 | 3 | SHOULD | REMB is sent as soon as congestion is detected, otherwise at least once per second | missing | none | none | |
| GCC-4-1 | 4 | MUST | A pacer actuates the target bitrate: media goes into a pacer queue and leaves at the target rate | tested | `pacing/sender.rs:125-176`, `pacing/pacer.rs`, `cc/interceptor.rs:176-187` | `the_pacer_follows_the_estimate`, `a_burst_is_released_at_the_configured_rate`, `changing_the_rate_changes_the_subsequent_schedule` | Until the estimate first changes the pacer runs at its own 1 Mbit/s default, not the estimator's initial 300 kbit/s (bug G4) |
| GCC-4-2 | 4 | SHOULD | The pacer sends a group every burst_time = 5 ms; group size = target bitrate x burst_time | partial | `pacing/pacer.rs` `burst_for` (`bits_per_second / 10`, floor 12000 bits) | `a_larger_burst_releases_more_at_once`, `a_derived_burst_follows_the_rate` | Token bucket whose burst is 100 ms of the target, 20 times the recommended group; no 5 ms cadence |
| GCC-5.1-1 | 5.1 | MUST | d(i) = t(i) - t(i-1) - (T(i) - T(i-1)) between consecutive groups | tested | `gcc/arrival_group.rs:123-134` | `a_path_that_does_not_queue_has_a_zero_gradient`, `a_growing_queue_has_a_positive_gradient`, `a_draining_queue_has_a_negative_gradient` | |
| GCC-5.1-2 | 5.1 | MUST | T(i) is the departure time of the last packet of the group | tested | `gcc/arrival_group.rs:91` | `packets_sent_together_form_one_group` | |
| GCC-5.1-3 | 5.1 | MUST | t(i) is the arrival time of the last packet of the group | untested | `gcc/arrival_group.rs:92` (latest arrival in the group) | none separates "last packet" from "latest arrival" | |
| GCC-5.1-4 | 5.1 | MUST | Packets received out of order are ignored by the arrival-time model | partial | `gcc/arrival_group.rs:70-109`, `rtpfb/history.rs:136-157` (reports in send order) | none | Send order is guaranteed, so departures never go back. A packet that arrived before its predecessor is still folded into its group instead of being skipped |
| GCC-5.2-1 | 5.2 | MUST | Packets sent within one burst_time (5 ms) form one group | tested | `gcc/arrival_group.rs:9`, `:86-96` | `packets_sent_together_form_one_group` | Measured from the group's first departure |
| GCC-5.2-2 | 5.2 | MUST | A packet with inter-arrival time below burst_time and d(i) < 0 joins the current group | missing | `gcc/arrival_group.rs:86-96` (departure test only) | none | Bursts delivered after an outage are measured as separate groups |
| GCC-5.3-1 | 5.3 | MUST | Kalman update: z = d - m_hat; k = (e + q) / (var_v + e + q); m_hat += z k; e = (1 - k)(e + q) | tested | `gcc/kalman.rs:67-84` | `a_sustained_gradient_is_tracked`, `a_negative_gradient_is_tracked_too`, `a_zero_signal_keeps_a_zero_estimate`, `symmetric_noise_does_not_move_the_estimate` | |
| GCC-5.3-2 | 5.3 | SHOULD | q = 10^-3 | untested | `gcc/kalman.rs:43` | none pins the default | |
| GCC-5.3-3 | 5.6 | SHOULD | e(0) = 0.1 | untested | `gcc/kalman.rs:41` | none | |
| GCC-5.3-4 | 5.3 | MUST | var_v_hat = max(alpha var_v_hat + (1 - alpha) z^2, 1) | untested | `gcc/kalman.rs:73-75` | none asserts the variance or its floor | Starts at 0, so the floor of 1 rules from the first sample |
| GCC-5.3-5 | 5.3 | MUST | alpha = (1 - chi)^(30 / (1000 f_max)), chi in [0.001, 0.1], f_max the highest group rate over the last K groups | partial | `gcc/kalman.rs:44` (fixed `noise_gain: 3e-4`) | none | A constant; f_max is never measured, so the filter does not adapt to the sampling rate |
| GCC-5.3-6 | 5.3 | MUST | Outlier filter: when z > 3 sqrt(var_v_hat), the variance update uses 3 sqrt(var_v_hat) | missing | `gcc/kalman.rs:73-75` | none | |
| GCC-5.4-1 | 5.4 | MUST | m(i) > del_var_th(i) is an over-use indication; m(i) < -del_var_th(i) is under-use; otherwise normal | tested | `gcc/overuse.rs:43-73`, `gcc/estimator.rs:140-145` | `a_sustained_growing_trend_is_overuse`, `a_draining_queue_reads_under`, `a_quiet_path_reads_normal`, `overuse_is_detected_on_a_queueing_path_and_not_on_a_steady_one` | What is compared is m(i) x min(readings, 60), as libwebrtc and pion do; the draft compares m(i) |
| GCC-5.4-2 | 5.4 | MUST | Over-use is signalled only after the condition has held for overuse_time_th | tested | `gcc/overuse.rs:48-57` | `one_spike_is_not_overuse` | Also needs a second consecutive reading (libwebrtc) |
| GCC-5.4-3 | 5.4 | MUST | Over-use is not signalled when m(i) < m(i-1) | untested | `gcc/overuse.rs:51` | `a_high_but_flat_trend_does_not_re_declare_overuse` returns below the threshold, so it does not reach this rule | |
| GCC-5.4-4 | 5.4 | MUST | del_var_th(i) = del_var_th(i-1) + (t(i) - t(i-1)) K(i) (abs(m(i)) - del_var_th(i-1)), K = K_d inside the threshold, K_u outside | partial | `gcc/threshold.rs:28-55` | `a_trend_outside_the_threshold_raises_it`, `a_trend_inside_the_threshold_lowers_it` | The time step is the gap between group departures (`trend.at`), not arrivals, and is capped at 100 ms (libwebrtc) |
| GCC-5.4-5 | 5.4 | SHOULD NOT | The threshold is not updated when abs(m(i)) - del_var_th(i) > 15 | tested | `gcc/threshold.rs:41-43` | `an_outlier_does_not_move_it` | |
| GCC-5.4-6 | 5.4 | SHOULD | del_var_th is clamped to [6, 600] | tested | `gcc/threshold.rs:53` | `it_stays_within_bounds` | |
| GCC-5.4-7 | 5.4 | SHOULD | K_u > K_d; K_u = 0.01, K_d = 0.00018 | tested | `gcc/threshold.rs:15-16` | `it_rises_faster_than_it_falls` | |
| GCC-5.4-8 | 5.4 | SHOULD | del_var_th(0) = 12.5 ms | tested | `gcc/threshold.rs:3` | `it_starts_at_the_drafts_value` | |
| GCC-5.4-9 | 5.4 | SHOULD | overuse_time_th = 10 ms | untested | `gcc/overuse.rs:11` | none pins the value | |
| GCC-5.5-1 | 5.5 | MUST | State table: Over-use leads to Decrease; Normal: Hold to Increase, Decrease to Hold; Under-use: Increase and Decrease to Hold | tested | `gcc/state.rs:11-23` | `overuse_always_decreases`, `recovery_holds_once_before_climbing`, `a_quiet_path_keeps_increasing`, `a_draining_queue_holds`, `every_transition_is_defined` | |
| GCC-5.5-2 | 5.5 | MUST | The subsystem starts in the Increase state | violated | `gcc/state.rs:5-6` (`#[default] Hold`) | none | Costs one update: the first Normal moves Hold to Increase |
| GCC-5.5-3 | 5.5 | MUST | Multiplicative increase: eta = 1.08^min(dt, 1 s); A_hat = eta A_hat | tested | `gcc/rate_control.rs:77-78` | `a_quiet_path_increases`, `gcc_climbs_on_a_healthy_path` | |
| GCC-5.5-4 | 5.5 | MUST | "Near convergence" means R_hat within three standard deviations of the average incoming rate seen in Decrease | partial | `gcc/rate_control.rs:69-71` (`target > last_decrease_rate * 0.85`) | `it_climbs_carefully_near_a_known_ceiling` | Last decrease rate only; no average, no deviation, and the test compares the target, not R_hat |
| GCC-5.5-5 | 5.5 | SHOULD | That average and deviation are exponential moving averages with smoothing 0.95 | missing | none | none | |
| GCC-5.5-6 | 5.5 | MUST | Without valid statistics, stay in multiplicative increase | tested | `gcc/rate_control.rs:69-79` (`last_decrease_rate: None`) | `a_quiet_path_increases` | |
| GCC-5.5-7 | 5.5 | MUST | R_hat rising above three deviations of the average resets the average and returns to multiplicative increase | missing | `gcc/rate_control.rs` (`last_decrease_rate` is never cleared) | none | After the first over-use the controller is additive for as long as the target stays above 85% of that old rate, even after capacity grows |
| GCC-5.5-8 | 5.5 | MUST | R_hat is the incoming rate over a window T | tested | `gcc/rate_calc.rs:24-41`, `gcc/estimator.rs:128-149` | `it_measures_a_steady_stream`, `old_samples_expire`, `it_follows_a_halved_rate` | Measured on the receiver's timeline, with whole-packet sizes |
| GCC-5.5-9 | 5.5 | SHOULD | T is between 0.5 and 1 s | tested | `gcc/rate_calc.rs:4` (500 ms) | `old_samples_expire` | |
| GCC-5.5-10 | 5.5 | MUST | Additive increase: response_time = 100 ms + rtt; alpha = 0.5 min(dt / response_time, 1); A_hat += max(1000, alpha x expected_packet_size_bits) | partial | `gcc/rate_control.rs:72-75` (`+ 12_000.0` per update) | `it_climbs_carefully_near_a_known_ceiling` | A fixed 12 kbit per 200 ms step; no RTT, no dt scaling, no packet-size model. `EstimatorStats::round_trip_time` is always `None` |
| GCC-5.5-11 | 5.5 | MUST | A_hat(i) < 1.5 R_hat(i): the estimate may not run away from the rate actually sent | missing | `gcc/rate_control.rs:65-80` | none | An application-limited sender lets the delay target climb to the configured maximum |
| GCC-5.5-12 | 5.5 | MUST | On over-use: A_hat = beta R_hat | tested | `gcc/rate_control.rs:56-64` | `overuse_backs_off_from_the_received_rate`, `it_holds_when_the_received_rate_is_unknown`, `gcc_backs_off_on_a_queueing_path` | |
| GCC-5.5-13 | 5.5 | SHOULD | beta = 0.85 | tested | `gcc/rate_control.rs:5` | `overuse_backs_off_from_the_received_rate` | |
| GCC-5.5-14 | 5.5 | MUST | On under-use the estimate is held | tested | `gcc/state.rs:17`, `gcc/rate_control.rs:55` | `a_draining_queue_holds` | |
| GCC-5.5-15 | 5.5 | SHOULD | The A_hat update runs at least once every response_time interval | partial | `gcc/estimator.rs:150` (once per feedback), `gcc/rate_control.rs:48-53` | `increases_are_paced_but_a_decrease_is_not` | Runs only when feedback arrives; nothing runs it on a timer |
| GCC-6-1 | 6 | SHOULD | The loss-based controller runs every time feedback is received | tested | `gcc/estimator.rs:152-153` | `heavy_loss_lowers_the_target_on_its_own` | Acts at most once per 200 ms (`loss.rs:48-52`) |
| GCC-6-2 | 6 | MUST | Loss between 2% and 10%: As_hat unchanged | tested | `gcc/loss.rs:53-63` | `moderate_loss_changes_nothing`, `gcc_ignores_loss_inside_the_band` | |
| GCC-6-3 | 6 | MUST | Loss above 10%: As_hat = As_hat (1 - 0.5 p) | tested | `gcc/loss.rs:57-60` | `the_backoff_is_proportional_to_the_loss`, `heavy_loss_lowers_the_target_on_its_own` | p is an 0.8/0.2 smoothed average, and the smaller of average and sample must exceed 10% |
| GCC-6-4 | 6 | MUST | Loss below 2%: As_hat = 1.05 As_hat | tested | `gcc/loss.rs:53-56` | `a_clean_path_raises_the_target` | |
| GCC-6-5 | 6 | MUST | The sending rate is min(As_hat, A_hat) | tested | `gcc/estimator.rs:155` | `the_more_pessimistic_half_wins`, `stats_report_both_halves` | |
| GCC-6-6 | 6 | MUST | The loss-based controller takes the delay-based estimate (and REMB) as its bound | partial | `gcc/loss.rs`, `gcc/estimator.rs:155` | none | The two halves are independent: As_hat grows 5% per 200 ms to the configured maximum whatever A_hat is; only the output is the minimum. REMB is not an input |
| GCC-7-1 | 7 | SHOULD | Against a receiver without TWCC or REMB: use RR fraction-lost and RTT for the loss-based controller, delay-based controller disabled | missing | `cc/interceptor.rs:137-159` (TWCC and CCFB only) | none | With no per-packet feedback the estimate never moves and the pacer holds its rate |

## Implementation B (`gcc/twcc_gcc`), differences from the draft

Not counted in the totals. Verified by reading `gcc/twcc_gcc/{mod,trendline,rate_controller}.rs`.

- 5.2 pre-filtering: none; every acknowledged packet is a sample, so there are no groups (missing).
- 5.3 arrival-time filter: a least-squares trendline over 20 samples of the smoothed, accumulated gradient, not the
  Kalman filter (the draft allows "any adaptive filter"); tested by `test_signal_overuse_increasing_delay`,
  `test_signal_underuse_decreasing_delay`, `test_window_size_capped`.
- 5.4 threshold: per-sample update with constants 0.0087 up and 0.039 down, not time-scaled; the 15 ms rule is
  absent; clamp [6, 600] present (`trendline.rs:48-58`). The up and down gains are the reverse of the draft's
  K_u > K_d recommendation: the threshold falls faster than it rises (violated; `test_threshold_adapts`).
- 5.4 overuse_time_th and the "m(i) < m(i-1)" rule: absent; one reading over the threshold is over-use (missing).
- 5.5 state table: under-use is treated like normal (it may increase); Decrease always falls to Hold for 250 ms
  (`rate_controller.rs:43-63`). Starts in Hold (violated).
- 5.5 decrease: 0.85 x the current estimate, not 0.85 x R_hat; R_hat is not measured at all (violated).
- 5.5 increase: multiplicative only; no additive mode, no 1.5 R_hat bound (missing).
- 6 loss-based control: no separate As_hat. Loss above 10% multiplies the single estimate by (1 - 0.5 p) on every
  feedback; nothing below 2% (partial; `test_loss_reduces_rate`).
- 3 send times are taken in `handle_write` at the slot where the interceptor sits, and only the last 512 are kept.
- 4 pacing: none; the estimate is published through `GccHandle` for the application.
- Not reachable from any `configure_*` helper; the module's own usage example is `ignore`d rustdoc.

## Gaps, in order of importance

1. **Bound the estimate by what is sent (S).** GCC-5.5-11. Clamp the delay target to 1.5 x R_hat; without it an
   application-limited or paused sender inflates A_hat to the maximum and then overshoots.
2. **Convergence statistics and additive increase (M).** GCC-5.5-4, -5, -7, -10. EMA mean and deviation of R_hat at
   decrease, reset above three deviations, RTT-scaled additive step. Needs an RTT input (`History::apply` already
   computes one and drops it).
3. **Pre-filter and Kalman details (M).** GCC-5.2-2, GCC-5.3-5, GCC-5.3-6, GCC-5.1-4.
4. **REMB (L, or withdraw the claim).** GCC-3-5, -3-7, -3-8, GCC-6-6. Either implement receive-side REMB generation
   and consume inbound REMB as a cap, or stop advertising `goog-remb` in the default codecs.
5. **Fallback to receiver reports (M).** GCC-7-1.
6. **Pacer burst (S).** GCC-4-2: 5 ms groups instead of a 100 ms bucket; start the pacer at the estimator's initial
   target (bug G4).
7. **Feedback cadence (M).** GCC-3-2: per-frame feedback with a 30 to 100 ms timer bound.
8. **Start state, timer-driven update (S).** GCC-5.5-2, GCC-5.5-15.
9. **Tests pinning constants and rules (S).** GCC-5.1-3, GCC-5.3-2, -3, -4, GCC-5.4-3, GCC-5.4-9.
10. **Decide the fate of implementation B (S).** Bring it to the draft or remove it; today the crate exports two
    estimators that disagree.

## Bugs found

- **G1. The delay target has no upper bound relative to the received rate.** `gcc/rate_control.rs:65-80`. Reproduce:
  feed `Gcc` clean feedback for packets sent at a constant 100 kbit/s for 60 s; `delay_based_bitrate()` climbs
  8% per second far past 150 kbit/s.
- **G2. Unacknowledged packets from other streams, or from lost feedback, are counted as loss.**
  `cc/interceptor.rs:204-216` records every bound stream, `rtpfb/history.rs:136-157` reports every unacknowledged id
  below the highest acknowledged one as lost, `gcc/estimator.rs:152` counts them. Reproduce: bind two local streams,
  one with the transport-cc extension and one without (or run CCFB where the peer reports only one SSRC), interleave
  their packets, acknowledge all of the first stream: `on_reports` sees 50% loss and the loss half backs off.
- **G3. After the first over-use the controller stays additive.** `gcc/rate_control.rs:69-71`: `last_decrease_rate`
  is never reset. Reproduce: over-use at R_hat = 1 Mbit/s, then a path with 10 Mbit/s capacity: the target climbs
  12 kbit per 200 ms (60 kbit/s per second) for as long as it is above 850 kbit/s, minutes instead of seconds.
- **G4. The pacer does not start at the estimator's target.** `cc/interceptor.rs:52` initialises `last_target` to
  the estimator's value and only emits `TargetBitrateChanged` on a change; `pacing/sender.rs:14` defaults to
  1 Mbit/s. Reproduce: `configure_congestion_control(.., Gcc::default(), ..)`, send before any feedback: packets
  leave at 1 Mbit/s while `target_bitrate()` is 300 kbit/s.
- **G5. `goog-remb` is advertised and never honoured.** `media_engine.rs` `video_rtcp_feedback` lists `goog-remb`
  for every default video codec; no interceptor sends REMB and none reads one. Reproduce: negotiate with defaults,
  receive video for 10 s: no REMB is written; send a REMB to the engine: nothing changes.
- **G6 (implementation B). Decrease is taken from the estimate, not the received rate, and the threshold gains are
  inverted.** `gcc/twcc_gcc/rate_controller.rs:71-73`, `gcc/twcc_gcc/trendline.rs:51-57`. Reproduce: hold the
  over-use signal with a link at a tenth of the estimate: the estimate needs 14 feedbacks (0.85^14) to get there.
