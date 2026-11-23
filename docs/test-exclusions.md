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
| ignored | tests/circuit_breaker_reordering_rtc2rtc.rs | video_seeds | An investigation tool: the 500 kbit/s video flow over the lossless reordering link for each seed of `RTC_CB_SEEDS` (default 1 to 20), one outcome line each; about fifteen minutes. | `a_video_flow_over_a_lossless_reordering_link_is_not_repaired` |
| ignored | tests/vp8_nack_jitter_buffer_rtc2rtc.rs | vp8_seeds | An investigation tool: the testenv VP8 stream over the modelled netem link for each seed of `RTC_VP8_SEEDS` (default 1 to 20) at the jitter buffer depth `RTC_VP8_DEPTH_MS` (default 250), one outcome line each with the course of every lost packet not played; 200 seeds take about two minutes. | `on_the_testenv_link_what_is_played_is_whole_in_order_and_everything_in_time`, `a_jitter_buffer_deeper_than_the_feedback_delay_repairs_every_detectable_loss` |
