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
| ignored | `rtc-sctp/src/association/retransmission_review_test.rs` | `benchmark_recovery_flushes` | A timing comparison printed for a person to read (recovery CPU cost at 128, 1,024 and 4,096 outstanding chunks), not an assertion; run by hand with `--ignored`. | `recovery_checks_are_bounded_by_candidates_in_large_windows` asserts the bound the benchmark illustrates |
