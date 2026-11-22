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
| ignored | `rtc-interceptor/tests/rfc8836_multi_flow.rs` | `a_flow_that_joins_late_gets_a_useful_share` | RFC 8836 section 2 (2a) is not met by `Gcc` (draft-ietf-rmcat-gcc-02 as implemented): a flow joining an established one falls to the floor. The test asserts the requirement and fails; it stays until the algorithm changes (`docs/conformance/audit/rfc8836.md`, RFC8836-2-2a) | `two_gcc_flows_share_a_bottleneck` (fairness of flows started together) |
| ignored | `rtc-interceptor/tests/rfc8836_multi_flow.rs` | `gcc_does_not_starve_a_tcp_like_transfer` | RFC 8836 section 2 (3) is not met by `Gcc`: a TCP-like transfer behind a full tail-drop queue gets 3% of the path. The test asserts the requirement and fails (RFC8836-2-3) | `gcc_is_not_starved_by_a_tcp_like_transfer` (the same run, the other direction) |
