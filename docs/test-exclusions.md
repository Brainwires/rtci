# Test exclusions

Every test in this repository runs, on every platform CI tests (Linux with four feature sets,
macOS and Windows with default features), except the ones below. Each row says why the test does
not run everywhere and which test covers the same behaviour where it does not.

`scripts/check-test-inventory.py` (the `Test inventory` job in `cargo.yml`) enforces this list
in both directions: a test that is ignored, commented out, compiled by no `mod`, or behind a
platform `cfg` fails the job unless it has a row here, and a row that no longer matches anything
fails it too. The real-network environment's tests (`tests/testenv_*.rs`) are `#[ignore]`d with
their reason in the attribute and need no row: `scripts/test-env/run.sh` runs them.

Kinds: `ignored` (`#[ignore]`), `commented` (a commented-out `#[test]`), `orphan` (a `*_test.rs`
no `mod` compiles), `platform` (a test or test module behind a platform `cfg`).

To remove a row, make the test run where it does not (drop the attribute or the `cfg`, add the
`mod`), then delete the row; the script tells you when a row has gone stale.

Tests left inside block comments since the sans-I/O port (in `rtc-ice`'s agent tests,
`rtc-dtls`'s connection tests, `rtc-datachannel`, `rtc-sctp`, `rtc-stun`, `rtc-turn` and the
session-description tests) are deliberately **not** listed: they are to be restored, and the
check fails, naming each one, until they are. The same tests are `port` rows in
[upstream-test-parity.md](upstream-test-parity.md).

| Kind | File | Test | Reason | Covered by |
|---|---|---|---|---|
| ignored | tests/lossy_link_rtc2rtc.rs | sweep | An investigation tool, not a check: it runs one session per seed of a range set by `LOSSY_LINK_SEEDS` (with `LOSSY_LINK_LOSS`, `LOSSY_LINK_SALT`, `LOSSY_LINK_REPEAT`) and prints each outcome and the fingerprint of its course; thousands of sessions take minutes. | The seeded tests of `tests/lossy_link_rtc2rtc.rs` (5, 10 and 30 % loss, the failing seeds found by sweeps) and `the_same_seed_gives_the_same_run` |
| ignored | tests/circuit_breaker_reordering_rtc2rtc.rs | sweep | An investigation tool, not a check: 80 sessions of 60 s each (reordering 0 to 100 ms, loss 0 to 5 %, five flows) printed as the table of where the RTP circuit breaker fires; about twenty minutes. `RTC_CB_SWEEP_SECONDS` shortens them. | `an_audio_flow_over_a_lossless_reordering_link_is_never_stopped`, `a_talkspurt_flow_over_a_lossless_jittered_link_is_never_stopped`, and the congestion tests of `rtc-interceptor/tests/circuit_breaker.rs` |
| ignored | tests/rtcp_rate_trace_rtc2rtc.rs | trace_rtcp_of_a_call | An investigation tool, not a check: seven 30 s calls under the `Rfc` and `Performance` profiles printed as the RTCP table of the file's documentation and of `docs/behaviour-profiles.md`; about three minutes. | `the_performance_profile_sends_regular_reports_about_once_a_second`, `the_performance_profile_keeps_low_rate_rtcp_inside_five_percent` |
| ignored | tests/circuit_breaker_reordering_rtc2rtc.rs | video_seeds | An investigation tool: the 500 kbit/s video flow over the lossless reordering link for each seed of `RTC_CB_SEEDS` (default 1 to 20), one outcome line each; about fifteen minutes. | `a_video_flow_over_a_lossless_reordering_link_is_not_repaired` |
| ignored | rtc-interceptor/src/gcc/slope.rs | reorder_trace_against_libwebrtc_grouping | An investigation tool, not a check: prints the delay-gradient readings of a reorder-only path as our arrival grouping and as libwebrtc's (arrival-sorted, `InterArrivalDelta`) make them, through the same filter and detector. | `a_packet_received_out_of_order_is_ignored`, `a_steady_path_reads_flat` |
| ignored | rtc-sctp/src/association/zero_window_progress_test.rs | zero_window_sweep_up_to_four_mebibytes | The zero window sweep with 4 MiB messages (up to 24 MiB a run): minutes in a debug build. Run with `--ignored` when the zero window, probing or reassembly code changes. | `zero_window_sweep_delivers_or_fails_never_stalls` (the same sweep, messages up to 1 MiB) and `a_message_larger_than_the_receive_buffer_arrives_at_a_round_trip_per_fragment` |
