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

**Since the audit** (the table and the totals are current; the gap and bug lists below are the audit's):
bugs G1, G2, G3 and G4 are fixed, each first reproduced by a failing test
(`an_application_limited_sender_does_not_inflate_the_delay_estimate`,
`a_stream_the_feedback_does_not_cover_is_not_counted_as_lost`,
`the_controller_leaves_additive_increase_when_the_path_widens`,
`the_pacer_follows_the_estimators_starting_rate`).

Totals (MUST includes MUST NOT/SHALL; SHOULD includes SHOULD NOT/RECOMMENDED):

- MUST: tested 34 / untested 0 / partial 1 / missing 0 / violated 0 / n-a 0
- SHOULD: tested 15 / untested 0 / partial 2 / missing 0 / violated 0 / n-a 0
- MAY: tested 1 / untested 0 / partial 0 / missing 0 / violated 0 / n-a 0

| ID | § | Level | Clause (short paraphrase) | Verdict | Code | Test | Note |
|---|---|---|---|---|---|---|---|
| GCC-3-1 | 3 | MUST | Send-side variant: the receiver records arrival time and transport-wide number of each packet and feeds them back periodically | tested | `twcc/receiver.rs`, `twcc/recorder.rs` | `test_twcc_receiver_generates_feedback_on_timeout`, `test_combined_twcc_sender_and_receiver` | |
| GCC-3-2 | 3 | SHOULD | Feedback once per received video frame, or at least every 30 ms when audio-only or multi-stream; up to 100 ms to limit overhead | partial | `twcc/receiver.rs:13` (100 ms), `rfc8888/sender.rs:16` (100 ms) | `test_twcc_receiver_configurable_interval` | Timer-driven, not per frame. Since the nominal-bandwidth change on the train the generators report every 100 ms from 64 kbit/s of media up (the draft's upper bound), up to 250 ms only where 5% of the media holds no more (the owner's feedback-cadence decision, `with_adaptive_interval(false)` for a fixed rhythm). Feedback per received frame (draft: or every 30 ms) is not done: at 30 frames a second it is three times the feedback |
| GCC-3-3 | 3 | MUST | The sender maps each {sequence number, arrival time} to the packet's send time and feeds the delay-based controller | tested | `rtpfb/history.rs:86-131`, `cc/interceptor.rs:137-190`, `gcc/estimator.rs:127-146` | `reports_carry_the_transport_wide_sequence_numbers`, `every_departing_packet_is_recorded_at_its_release_instant`, `gcc_settles_under_a_rate_limited_link` | |
| GCC-3-4 | 3 | MUST | The sender computes a loss ratio from the sequence numbers in the feedback | tested | `gcc/estimator.rs:152-153` | `gcc_backs_off_on_a_lossy_path_with_no_queueing`, `the_more_pessimistic_half_wins` | The ratio also counts packets the feedback never covered (see bug G2) |
| GCC-3-5 | 3 | MAY | Receive-side variant: delay-based controller at the receiver, estimate returned in REMB | tested | `rtc-interceptor/src/gcc/remb.rs` (`RembGeneratorInterceptor`), `interceptor_registry.rs` (`configure_remb`, in the default set) | `a_remb_stream_gets_an_estimate_at_least_once_a_second`, `congestion_sends_a_lower_remb_at_once`, `no_remb_without_goog_remb_or_with_per_packet_feedback` | For every remote stream that negotiated `goog-remb` and neither transport-cc nor RFC 8888: the delay-based controller of `Gcc` on the arrivals against abs-send-time (one estimate for all such streams) or the RTP timestamp (one per stream), first estimate the incoming rate after 5 s (libwebrtc), REMB the sum. Retransmissions are left out |
| GCC-3-6 | 3 | SHOULD | With the receive-side variant the sender uses the abs-send-time header extension | tested | `rtc-interceptor/src/gcc/remb.rs` (`AbsSendTimeInterceptor`, `ABS_SEND_TIME_SLOT`, below the pacer); `interceptor_registry.rs` (`configure_remb`); `interceptor_registry.rs` (`configure_abs_send_time`, in the default set) | `abs_send_time_is_stamped_as_the_packet_passes`, `a_remb_stream_gets_an_estimate_at_least_once_a_second`; `tests/default_abs_send_time.rs::video_offers_abs_send_time_beside_transport_cc_and_audio_does_not`, `tests/default_abs_send_time.rs::a_remb_peers_abs_send_time_is_answered` | Every packet of a local stream that negotiated abs-send-time is stamped as it leaves the pacer. The default media engine does not register the extension: a peer's offer of it is answered only when the application registers it (`MediaEngine::register_header_extension`); without it the receiver uses RTP timestamps; The default set now registers the extension on video, so it is offered and answered without the application registering it |
| GCC-3-7 | 3 | MUST | Sender feeds received REMB and RR fraction-lost into the loss-based controller | tested | `cc/interceptor.rs` `ingest` (REMB as an upper bound of the estimator, `REMB_TIMEOUT`; receiver-report fraction lost while there is no per-packet feedback), `gcc/estimator.rs` `set_external_bounds`, `on_receiver_report` | `a_remb_bounds_the_target`, `a_remb_that_is_not_repeated_lapses`, `gcc_backs_off_on_reported_loss_when_there_is_no_per_packet_feedback` | With TWCC or RFC 8888 feedback the loss fraction is counted from the per-packet reports instead of the RR |
| GCC-3-8 | 3 | SHOULD | REMB is sent as soon as congestion is detected, otherwise at least once per second | tested | `rtc-interceptor/src/gcc/remb.rs` (`REMB_MAX_INTERVAL`, `REMB_DECREASE_TRIGGER`) | `a_remb_stream_gets_an_estimate_at_least_once_a_second`, `congestion_sends_a_lower_remb_at_once` | At once when the estimate falls below 97% of the last one sent (congestion), otherwise once a second |
| GCC-4-1 | 4 | MUST | A pacer actuates the target bitrate: media goes into a pacer queue and leaves at the target rate | tested | `pacing/sender.rs:125-176`, `pacing/pacer.rs`, `cc/interceptor.rs:176-187` | `the_pacer_follows_the_estimate`, `a_burst_is_released_at_the_configured_rate`, `changing_the_rate_changes_the_subsequent_schedule` | Until the estimate first changes the pacer runs at its own 1 Mbit/s default, not the estimator's initial 300 kbit/s (bug G4) |
| GCC-4-2 | 4 | SHOULD | The pacer sends a group every burst_time = 5 ms; group size = target bitrate x burst_time | tested | `pacing/pacer.rs` `burst_for`, `BURST_TIME` (5 ms of the target, floored at one 1500-byte packet) | `a_derived_burst_follows_the_rate`, `a_larger_burst_releases_more_at_once`, `a_packet_inside_the_budget_leaves_when_it_is_written` | The budget refills continuously and is capped at one 5 ms group. A packet inside it leaves as it is written (RFC 8836 section 2 requirement 1: no self-inflicted delay); `PacerBuilder::with_immediate_release(false)` holds every packet for the driver's next wake-up |
| GCC-5.1-1 | 5.1 | MUST | d(i) = t(i) - t(i-1) - (T(i) - T(i-1)) between consecutive groups | tested | `gcc/arrival_group.rs:123-134` | `a_path_that_does_not_queue_has_a_zero_gradient`, `a_growing_queue_has_a_positive_gradient`, `a_draining_queue_has_a_negative_gradient` | |
| GCC-5.1-2 | 5.1 | MUST | T(i) is the departure time of the last packet of the group | tested | `gcc/arrival_group.rs:91` | `packets_sent_together_form_one_group` | |
| GCC-5.1-3 | 5.1 | MUST | t(i) is the arrival time of the last packet of the group | tested | `gcc/arrival_group.rs:92` (latest arrival in the group) | `a_packet_received_out_of_order_is_ignored` | The group's latest arrival, which with out-of-order packets left out (GCC-5.1-4) is its last packet's |
| GCC-5.1-4 | 5.1 | MUST | Packets received out of order are ignored by the arrival-time model | tested | `gcc/arrival_group.rs` (`accumulate`) | `a_packet_received_out_of_order_is_ignored` | A packet that arrived before the group it follows is left out of the arrival-time model |
| GCC-5.2-1 | 5.2 | MUST | Packets sent within one burst_time (5 ms) form one group | tested | `gcc/arrival_group.rs:9`, `:86-96` | `packets_sent_together_form_one_group` | Measured from the group's first departure |
| GCC-5.2-2 | 5.2 | MUST | A packet with inter-arrival time below burst_time and d(i) < 0 joins the current group | tested | `gcc/arrival_group.rs` (`accumulate`) | `a_backlog_delivered_at_once_is_one_group` | |
| GCC-5.3-1 | 5.3 | MUST | Kalman update: z = d - m_hat; k = (e + q) / (var_v + e + q); m_hat += z k; e = (1 - k)(e + q) | tested | `gcc/kalman.rs:67-84` | `a_sustained_gradient_is_tracked`, `a_negative_gradient_is_tracked_too`, `a_zero_signal_keeps_a_zero_estimate`, `symmetric_noise_does_not_move_the_estimate` | |
| GCC-5.3-2 | 5.3 | SHOULD | q = 10^-3 | tested | `gcc/kalman.rs:43` | `the_first_step_is_set_by_e0_q_and_the_variance_floor` | |
| GCC-5.3-3 | 5.6 | SHOULD | e(0) = 0.1 | tested | `gcc/kalman.rs:41` | `the_first_step_is_set_by_e0_q_and_the_variance_floor` | |
| GCC-5.3-4 | 5.3 | MUST | var_v_hat = max(alpha var_v_hat + (1 - alpha) z^2, 1) | tested | `gcc/kalman.rs:73-75` | `the_first_step_is_set_by_e0_q_and_the_variance_floor`, `an_outlier_enters_the_variance_as_three_deviations` | Starts at 0, so the floor of 1 rules from the first sample |
| GCC-5.3-5 | 5.3 | MUST | alpha = (1 - chi)^(30 / (1000 f_max)), chi in [0.001, 0.1], f_max the highest group rate over the last K groups | tested | `gcc/kalman.rs` (`update_with_period`, `DEFAULT_CHI` 0.001, `PERIOD_HISTORY` 60), `gcc/slope.rs` (`filter`) | `the_noise_weight_follows_the_group_rate` | f_max from the departure periods of the last 60 groups; chi 0.001, which at 100 groups a second is the constant the filter had |
| GCC-5.3-6 | 5.3 | MUST | Outlier filter: when z > 3 sqrt(var_v_hat), the variance update uses 3 sqrt(var_v_hat) | tested | `gcc/kalman.rs` (`update_with_noise_gain`) | `an_outlier_enters_the_variance_as_three_deviations` | Signed: a residual beyond plus or minus three deviations is clamped to them |
| GCC-5.4-1 | 5.4 | MUST | m(i) > del_var_th(i) is an over-use indication; m(i) < -del_var_th(i) is under-use; otherwise normal | tested | `gcc/overuse.rs:43-73`, `gcc/estimator.rs:140-145` | `a_sustained_growing_trend_is_overuse`, `a_draining_queue_reads_under`, `a_quiet_path_reads_normal`, `overuse_is_detected_on_a_queueing_path_and_not_on_a_steady_one` | What is compared is m(i) x min(readings, 60), as libwebrtc and pion do; the draft compares m(i) |
| GCC-5.4-2 | 5.4 | MUST | Over-use is signalled only after the condition has held for overuse_time_th | tested | `gcc/overuse.rs:48-57` | `one_spike_is_not_overuse` | Also needs a second consecutive reading (libwebrtc) |
| GCC-5.4-3 | 5.4 | MUST | Over-use is not signalled when m(i) < m(i-1) | tested | `gcc/overuse.rs:51` | `a_trend_above_the_threshold_but_falling_is_not_overuse` | |
| GCC-5.4-4 | 5.4 | MUST | del_var_th(i) = del_var_th(i-1) + (t(i) - t(i-1)) K(i) (abs(m(i)) - del_var_th(i-1)), K = K_d inside the threshold, K_u outside | partial | `gcc/threshold.rs:28-55` | `a_trend_outside_the_threshold_raises_it`, `a_trend_inside_the_threshold_lowers_it` | The time step is the gap between group departures (`trend.at`), not arrivals, and is capped at 100 ms (libwebrtc). Checked against the draft for RFC8836-2-2a: the bounds and the gains are the draft's, and the threshold falls back to 6 ms within seconds of a calm path |
| GCC-5.4-5 | 5.4 | SHOULD NOT | The threshold is not updated when abs(m(i)) - del_var_th(i) > 15 | tested | `gcc/threshold.rs:41-43` | `an_outlier_does_not_move_it` | |
| GCC-5.4-6 | 5.4 | SHOULD | del_var_th is clamped to [6, 600] | tested | `gcc/threshold.rs:53` | `it_stays_within_bounds` | |
| GCC-5.4-7 | 5.4 | SHOULD | K_u > K_d; K_u = 0.01, K_d = 0.00018 | tested | `gcc/threshold.rs:15-16` | `it_rises_faster_than_it_falls` | |
| GCC-5.4-8 | 5.4 | SHOULD | del_var_th(0) = 12.5 ms | tested | `gcc/threshold.rs:3` | `it_starts_at_the_drafts_value` | |
| GCC-5.4-9 | 5.4 | SHOULD | overuse_time_th = 10 ms | tested | `gcc/overuse.rs:11` | `overuse_needs_ten_milliseconds_outside_the_threshold` | |
| GCC-5.5-1 | 5.5 | MUST | State table: Over-use leads to Decrease; Normal: Hold to Increase, Decrease to Hold; Under-use: Increase and Decrease to Hold | tested | `gcc/state.rs:11-23` | `overuse_always_decreases`, `recovery_holds_once_before_climbing`, `a_quiet_path_keeps_increasing`, `a_draining_queue_holds`, `every_transition_is_defined` | |
| GCC-5.5-2 | 5.5 | MUST | The subsystem starts in the Increase state | tested | `gcc/state.rs` (`#[default] Increase`) | `the_controller_starts_in_the_increase_state` |  |
| GCC-5.5-3 | 5.5 | MUST | Multiplicative increase: eta = 1.08^min(dt, 1 s); A_hat = eta A_hat | tested | `gcc/rate_control.rs:77-78` | `a_quiet_path_increases`, `gcc_climbs_on_a_healthy_path` | |
| GCC-5.5-4 | 5.5 | MUST | "Near convergence" means R_hat within three standard deviations of the average incoming rate seen in Decrease | tested | `gcc/rate_control.rs` `Convergence` (`band`), `RateController::update` | `the_additive_increase_is_half_a_packet_per_response_time`, `it_climbs_carefully_near_a_known_ceiling`, `a_received_rate_above_the_convergence_band_returns_to_multiplicative_increase` | Average and deviation of R_hat measured at each decrease; "close" is R_hat within three deviations. The variance is normalised by the average and held in [0.4, 2.5] kbit/s as libwebrtc holds it, so the band scales with the rate |
| GCC-5.5-5 | 5.5 | SHOULD | That average and deviation are exponential moving averages with smoothing 0.95 | tested | `gcc/rate_control.rs` `Convergence::on_decrease` (smoothing 0.95) | `a_received_rate_above_the_convergence_band_returns_to_multiplicative_increase` (band of about 60 kbit/s at 1 Mbit/s), `a_decrease_far_below_the_band_restarts_the_average` |  |
| GCC-5.5-6 | 5.5 | MUST | Without valid statistics, stay in multiplicative increase | tested | `gcc/rate_control.rs:69-79` (`last_decrease_rate: None`) | `a_quiet_path_increases` | |
| GCC-5.5-7 | 5.5 | MUST | R_hat rising above three deviations of the average resets the average and returns to multiplicative increase | tested | `gcc/rate_control.rs` `RateController::update` (Increase: `convergence.reset()` above the band) | `a_received_rate_above_the_convergence_band_returns_to_multiplicative_increase`, `the_controller_leaves_additive_increase_when_the_path_widens` | A decrease far below the band also restarts the average |
| GCC-5.5-8 | 5.5 | MUST | R_hat is the incoming rate over a window T | tested | `gcc/rate_calc.rs:24-41`, `gcc/estimator.rs:128-149` | `it_measures_a_steady_stream`, `old_samples_expire`, `it_follows_a_halved_rate` | Measured on the receiver's timeline, with whole-packet sizes |
| GCC-5.5-9 | 5.5 | SHOULD | T is between 0.5 and 1 s | tested | `gcc/rate_calc.rs:4` (500 ms) | `old_samples_expire` | |
| GCC-5.5-10 | 5.5 | MUST | Additive increase: response_time = 100 ms + rtt; alpha = 0.5 min(dt / response_time, 1); A_hat += max(1000, alpha x expected_packet_size_bits) | tested | `gcc/rate_control.rs` `RateController::update`, `expected_packet_size_bits`, `set_round_trip_time`; `cc/interceptor.rs` `note_round_trip_time`; `gcc/estimator.rs` `on_round_trip_time` | `the_additive_increase_is_half_a_packet_per_response_time`, `the_round_trip_time_from_feedback_reaches_the_estimator` | The RTT is measured from feedback (departure of the newest acknowledged packet to the feedback being read, smoothed), 200 ms until the first; `EstimatorStats::round_trip_time` reports it |
| GCC-5.5-11 | 5.5 | MUST | A_hat(i) < 1.5 R_hat(i): the estimate may not run away from the rate actually sent | tested | `gcc/rate_control.rs` `RateController::update` (`MAX_ESTIMATE_TO_RECEIVED_RATIO`) | `the_estimate_stays_within_one_and_a_half_times_the_received_rate`, `an_application_limited_sender_does_not_inflate_the_delay_estimate` | Applied whenever R_hat is known, so an application-limited sender pulls the estimate down to 1.5 times what it sends |
| GCC-5.5-12 | 5.5 | MUST | On over-use: A_hat = beta R_hat | tested | `gcc/rate_control.rs:56-64` | `overuse_backs_off_from_the_received_rate`, `it_holds_when_the_received_rate_is_unknown`, `gcc_backs_off_on_a_queueing_path`, `lasting_over_use_cuts_once_per_round_trip`, `a_collapse_of_the_received_rate_cuts_at_once` | By default a further cut waits a round trip (10 to 200 ms) unless the received rate fell below half the target (libwebrtc's `TimeToReduceFurther`): the draft cuts on every update while over-use lasts, and a flow that filters slowly cut itself several times for one episode (RFC8836-2-2a). `RateController::with_one_decrease_per_round_trip(false)` / `Gcc::with_one_decrease_per_round_trip(false)` is the draft as written |
| GCC-5.5-13 | 5.5 | SHOULD | beta = 0.85 | tested | `gcc/rate_control.rs:5` | `overuse_backs_off_from_the_received_rate` | |
| GCC-5.5-14 | 5.5 | MUST | On under-use the estimate is held | tested | `gcc/state.rs:17`, `gcc/rate_control.rs:55` | `a_draining_queue_holds` | |
| GCC-5.5-15 | 5.5 | SHOULD | The A_hat update runs at least once every response_time interval | partial | `gcc/estimator.rs:150` (once per feedback), `gcc/rate_control.rs:48-53` | `increases_are_paced_but_a_decrease_is_not` | Runs on every feedback report, which since the train's nominal-bandwidth change arrives every 100 ms from 64 kbit/s of media up (inside response_time = 100 ms + RTT); slower only at 5% sizing below that. A timer-driven update was tried and dropped: with feedback missing, an update on the last usage signal raises the estimate on stale data, against the feedback-timeout cut (RFC 8888 section 5, RFC 8836 requirement 10, `gcc_halves_the_target_for_every_feedback_timeout_without_feedback`) |
| GCC-6-1 | 6 | SHOULD | The loss-based controller runs every time feedback is received | tested | `gcc/estimator.rs:152-153` | `heavy_loss_lowers_the_target_on_its_own` | Acts at most once per 200 ms (`loss.rs:48-52`) |
| GCC-6-2 | 6 | MUST | Loss between 2% and 10%: As_hat unchanged | tested | `gcc/loss.rs:53-63` | `moderate_loss_changes_nothing`, `gcc_ignores_loss_inside_the_band`, `a_loss_with_no_queue_is_not_at_the_limit`, `a_loss_on_a_jittery_path_is_not_at_the_limit` | Unchanged in the loss-based controller. A loss out of a queue at its limit (every arrived packet of the batch waited at least 75% of the highest queueing delay of the last 5 s, and at least 10 ms) is over-use for the delay-based one by default (`Gcc::with_loss_at_queue_limit_as_overuse`): at a full tail-drop queue the gradient is zero and the band let `Gcc` starve TCP (RFC8836-2-3). `false` is the draft as written |
| GCC-6-3 | 6 | MUST | Loss above 10%: As_hat = As_hat (1 - 0.5 p) | tested | `gcc/loss.rs:57-60` | `the_backoff_is_proportional_to_the_loss`, `heavy_loss_lowers_the_target_on_its_own` | p is an 0.8/0.2 smoothed average, and the smaller of average and sample must exceed 10% |
| GCC-6-4 | 6 | MUST | Loss below 2%: As_hat = 1.05 As_hat | tested | `gcc/loss.rs:53-56` | `a_clean_path_raises_the_target` | |
| GCC-6-5 | 6 | MUST | The sending rate is min(As_hat, A_hat) | tested | `gcc/estimator.rs:155` | `the_more_pessimistic_half_wins`, `stats_report_both_halves` | |
| GCC-6-6 | 6 | MUST | The loss-based controller takes the delay-based estimate (and REMB) as its bound | tested | `gcc/estimator.rs` `on_reports` (`loss_control.cap(delay_target)`, `with_loss_estimate_capped_by_delay_estimate`), `set_external_bounds` (REMB bounds both); `gcc/loss.rs` `cap` | `the_loss_based_estimate_free_and_capped_on_the_recovery_and_lossy_fixtures`, `gcc_backs_off_on_a_lossy_path_with_no_queueing`, `gcc_climbs_back_after_the_path_widens`, `a_remb_bounds_the_target` | As_hat is held at or below A_hat after every update, so a loss cut is taken from the rate being sent. Left free it grows 5% per interval to several times that rate and absorbs the cuts (measured: 4.06 Mbit/s against a 530 kbit/s target after five quiet seconds, and 39% loss over two seconds then moved the target by 9%). The free form stays available as an option |
| GCC-7-1 | 7 | SHOULD | Against a receiver without TWCC or REMB: use RR fraction-lost and RTT for the loss-based controller, delay-based controller disabled | tested | `cc/interceptor.rs` `ingest` (`per_packet_feedback`), `gcc/estimator.rs` `on_receiver_report`, `gcc/loss.rs` `update_fraction` | `receiver_reports_feed_the_estimator_only_without_per_packet_feedback`, `gcc_backs_off_on_reported_loss_when_there_is_no_per_packet_feedback` | The delay-based controller has no input and does not run; the RTT of the reports is not used (the loss controller of the draft does not take one) |

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
