# The capacity instrument: what a call's user sees when the path collapses

`tests/capacity_instrument.rs` (the world it runs in: `tests/capacity_common/mod.rs`) measures a
video call between two peer connections, in virtual time, whose path drops from 2.5 Mbit/s to
300 kbit/s for twenty seconds, or disappears for four seconds and returns with an ICE restart.
It replaces the freeze and oldest-picture assertions of `tests/capacity_cap_video_rtc2rtc.rs`,
which counted any frame that came out of the receiver's buffer however old it was, on two to six
seeds, at one phase of the cap, with one direction capped and a receiver that waits without a
bound in time. Over 1100 seeds 8 % of those runs were over the 2 s that test required (six seeds
pass 59 % of the time at that share), and the picture on the screen was 8 s old meanwhile.
Nothing here changes engine behaviour.

The figures, the cells, the statistics and the run modes are defined in the test file's module
documentation; this page says how the instrument is used and what it found.

## What is asserted, and where

| | what | when |
|---|---|---|
| unit tests, determinism | the figures' and the statistics' arithmetic; the same seed twice gives the same figures | every `cargo test`, every platform |
| tripwires | each cell of the pull-request ensemble against the recorded baseline | the `capacity_instrument` job (release build) |
| requirements the engine meets | picture, freeze and audio in ParolNet's chain, 300 runs | the same job |
| a requirement met, too large for the job; requirements at the bound | the outage without the pacer; picture and freeze without the pacer; 300 runs each | on demand: `-- --ignored on_demand_` |
| requirements the engine does not meet | `known_limit_*`: ignored, with the measured share in the attribute | they fail when run: `-- --ignored known_limit_` |
| the audio guard | no run of the default chain's reference cells ends with a flow left ceased by the circuit breaker or its audio silent (`ensemble_requirement_no_flow_is_left_ceased_and_audio_is_alive_at_the_end`) | the same job, on every pull request since the circuit breaker's rules were corrected (breaker-1; before, 8.9 % of runs ended so) |
| the picture guard | at most one of the 100 runs of the default chain's reference cells shows a picture older than 2 s for more than 0.5 s (`ensemble_tripwire_picture_in_the_default_chain`): 0 of 2000 with the backlog flushed (docs/capacity-collapse.md); a tree in which 5 % of calls miss passes with probability 0.037 | the tripwire of `on_demand_requirement_picture_in_the_default_chain`, which needs 300 runs |
| the fine comparison | the merge-point rule below | `capacity-compare.yml`, by hand |

A requirement is a share: "in at most 5 % of calls ...", tested on 300 runs with at most 21
violating (exact binomial: a tree at 5 % passes with probability 0.951, a tree at 10 % fails with
0.954). A requirement the engine misses is not loosened. The requirements:

- **picture**: the screen shows a picture older than 2 s for no more than 0.5 s in all
  (`stale2`);
- **freeze**: never more than 2 s without a new picture of any age (`freeze`; the figure the
  old test asserted, secondary);
- **audio**: never more than 1 s without audio (`audio_gap`; audio that a ceased flow never
  sends again counts);
- **resume** (the outage): a new picture within 2 s of the path's return (`resume`).

### The pull-request job

606 runs: the reference cell (default chain, the receiver with the 300 ms bound) 60, the
receiver without a bound 40, the pacer-less chain 40 and 20, both directions capped 30 and 20,
the queue at 100 and 1000 ms and 5 % loss on the reverse path 12 each, the outage 20 and 20,
ParolNet's chain 20 and, for its three requirement tests, 300. A run costs 1.7 to 7.4 s of one
core (measured on hosted runners). Measured (hosted run 45516163858, the job's steps on master
687ac4a7): the ensemble 5 min 14 s, the whole job 8 min 49 s with the release build; allow
twelve minutes, and twice that on a slow hosted runner (the same 2000-run measurement took
1770 to 4007 s on different runners; the timeout is 45 minutes). Two mutations show it notices
(`expect: fail` runs): with the pacer's pause removed the tripwire `discards` > 0 fails in every
cell of the default chain (60 of 60 runs in the reference cell where the baseline has 0 of 1000)
and the picture tripwires of the receiver without a bound in 40 of 40 (45516199691); with
retransmissions not rate limited the picture and freeze requirements of ParolNet's chain fail
(49 and 95 of 300 runs, at most 21 allowed) and 37 tripwires with them (45516206263). At this size the job notices: a requirement that
ParolNet's chain stops meeting (a share of 10 % fails with 0.95); in every other cell a gross
regression (a threshold that a tenth of the baseline was beyond fails once a quarter to 40 % of
the runs are beyond it; in the reference cell that is a picture about a second older); a flow
ceased by the circuit breaker or a peer that leaves Connected where the baseline had none; a run
that is no longer a function of its seed. It does not notice a picture 0.3 s older, a share that
moves from 8 % to 12 %, or anything in the cells it does not run. That is the comparison's.

### The full ensemble, on demand

`capacity-compare.yml` (workflow_dispatch: `head`, `base` = master) measures both trees with
the dispatching ref's instrument: the two gate cells (default chain, receiver with and without
the bound) on seeds 1 to 1000 and twelve star cells on seeds 1 to 100, about 40 minutes a side
on hosted runners, and applies the merge-point rule. Any cell, seed range or phase:

    RTC_INSTR_CELLS=cap/paced/gap300/up/q300/rl0 RTC_INSTR_SEEDS=1-1000 \
      cargo test --release -p rtci --test capacity_instrument -- --ignored --nocapture --exact measure > rows.log
    python3 scripts/capacity-instrument.py table master=rows.log

## The merge-point rule

For a change to congestion control, pacing, retransmission or RTCP timing (and anything else
that moves these figures). Head and base are measured by the same instrument on the same seeds
in the same session; `scripts/capacity-instrument.py compare --base ... --head ...` exits 1 when
the rule is broken. In every cell both sides hold, NOTHING OF THE FOLLOWING MAY BE WORSE ON THE
HEAD:

1. **Shares** (Fisher's exact test, one-sided: the head has more): runs that did not complete;
   picture (`stale2` > 0.5 s); freeze (`freeze` > 2 s); audio (`audio_gap` > 1 s); never back
   (`tail_gap` > 5 s); slow resume (`resume` > 2 s); slow recovery (`recover` > 20 s); a flow
   ceased by the circuit breaker (`cb` > 0); a peer that left Connected (`disc` > 0).
2. **Means** (the per-seed difference head less base, one-sided, normal approximation; Welch's
   test when the seeds differ): `max_age`, `stale1`, `stale2`, `fresh_gap` worse by more than
   0.1 s; `audio_lost` by more than 5 packets (0.1 s of audio); `under` (the target under the
   cap) lower by more than 10 kbit/s; `window` (the target 15 to 25 s after the cap) lower by
   more than 50 kbit/s.
3. **Requirements**: one the base meets (the instrument's exact test at the sample size) that the
   head misses with more violating runs than chance gives (Fisher, 5 %).

Confidence: 1 and 2 are tested at a family-wise level of 1 % (Bonferroni: each test at 0.01
divided by the number of tests made, about 250 with all fourteen cells), so a head that changes
nothing breaks the rule with probability at most 0.01. With 1000 seeds a picture 0.25 s older in
a gate cell is found with probability above 0.99 when the change leaves seeds comparable (the
per-seed difference of two trains of master is known to +-0.04 s) and above 0.9 when it re-draws
every seed (+-0.12 s). The margins are what a difference must exceed to count: without them a
well-measured 8 ms of audio would break the rule.

A head that is worse in one figure and better in another has broken the rule; whether the trade
is wanted is the owner's decision, made on the table, not the integrator's. A change that
improves a cell re-records the baseline (below).

## Reading the recovery after the cap

Three figures say how the rate comes back once the capacity has. `recover` is the time until the
target is at 0.4 of what it was before the drop: a RELATIVE level, 1000 kbit/s for a call that
met the drop at 2.5 Mbit/s and 565 kbit/s for one that met it at 1.4 Mbit/s, so it compares two
chains or two trees only where `before` is the same (the chains without a pacer read six seconds
"faster" than the default chain for as long as their start-up did not reach the maximum; the
climb was the same). `to1000` is the time until the target is at 1000 kbit/s, whatever it was
before: the ABSOLUTE figure, the one to compare chains and trees with. `window` is the mean
target 15 to 25 s after the capacity's return. From the under-cap rate of about 240 kbit/s the
8 % a second of draft-ietf-rmcat-gcc-02 section 5.5 is at 1000 kbit/s after 18 s; no IETF text
asks for more after a long cap.

`startup` is the time from the start of the call until the target is within 5 % of the 2.5 Mbit/s
maximum (99: not before the drop at 20 s): the start-up probing of RFC 8836 section 2,
requirement 4, as a figure of every run.

The scenario `cap60` holds the cap for 60 s instead of 20 (measurement only): what a sender that
tries for its old rate costs a path that does not come back for a long time is read there, in
`under`, the picture and the audio figures.

## Re-recording the baseline

The tripwires compare with `tests/fixtures/capacity-instrument-baseline.tsv`, recorded from
master. THE BRANCH THAT MOVES A FIGURE RE-RECORDS THE BASELINE, IN ITS OWN ROUND: a change that
is meant to move these figures (the repairs, the estimator, the circuit breaker's restart, the
flush at a collapse, the consent fix: each does) passes the merge-point rule against master
first, then carries the re-recorded file, the known-limit attributes and the table below in the
same branch, measured on that branch merged with the master it will land on. The integrator
merges it only with the new baseline in it; a round that merges two such branches re-records
once, on the round's head. A branch that moves nothing leaves the file alone (the rows are a
function of the seeds: master 687ac4a7 gave the same 4800 rows as 63e1b8b8, to the digit, two
trains later). One measurement and one command:

    # on the merged head, on a hosted runner (agent-test.yml), two runs:
    RTC_INSTR_CELLS=cap/paced/gap300/up/q300/rl0,cap/paced/gap0/up/q300/rl0 RTC_INSTR_SEEDS=1-1000 cargo test --release -p rtci --test capacity_instrument -- --ignored --nocapture --exact measure
    RTC_INSTR_CELLS=<the other cells of PR_CELLS, comma separated> RTC_INSTR_SEEDS=1-200 cargo test --release -p rtci --test capacity_instrument -- --ignored --nocapture --exact measure
    # then, with the two logs:
    python3 scripts/capacity-instrument.py baseline gate.log star.log --source "master <sha>, runs <ids>" > tests/fixtures/capacity-instrument-baseline.tsv

and the known-limit attributes, CHANGELOG "Known limits" and the table below follow the new
figures (a requirement the engine now meets moves from `known_limit_` to
`ensemble_requirement_`). The pull-request seeds (5001 on) are not the baseline's (1 to 1000),
so the job tests a fresh draw against it.

## The reference receiver

`SampleBuilder::new(256, ..).with_max_gap_wait(300 ms)` (the builder's default for video since
`conf/flush-2-receiver-gap-bound`), a PLI when the builder gives a gap up
or the decoder has no reference, at most one a second (docs/receiver-gap-policy.md). 300 ms is
two NACK rounds on the open path (the generator asks every 100 ms, the round trip is 20 ms) and
inside the 200 ms to 1 s of playout delay of interactive video; under the cap a first repair
arrives 140 to 440 ms after the gap is known, so with a full queue the bound ends the wait
first, which is the policy of a receiver that will not show a picture a second old. Measured
against 600 and 1000 ms (master d914b929, 200 seeds): with the pacer the oldest picture is 9.04
/ 8.91 / 9.01 s (the pause decides, not the bound); without it 1.33 / 1.79 / 2.34 s and the
picture requirement is missed in 8 / 10 / 37 % of runs. The receiver without a bound in time
(`gap0`, the old test's) stays a measured cell: it is the one receiver for which discarding a
stale repair is catastrophic, and a policy must be judged on both.

## Determinism, and what is still drawn unseeded

A run is a function of its cell, seed and phase: asserted in every build
(`the_same_seed_gives_the_same_figures`), on the ensemble (`ensemble_runs_are_reproducible`) and
between two processes in the job; the instrument reproduces the independent review's v0.1.0
ensemble to the digit (93 of 1100 runs over 2 s, the same six seeds' freezes). The world seeds
the crypto provider (ICE credentials and tie-breaker, DTLS randoms, SCTP, the RTCP report
intervals) and the link's losses, fixes the wall clock and the RTP sequence numbers, and reads
no clock but the origin of its virtual time. What the engine still draws from an unseeded source
in these scenarios, none of which reaches a figure (values of fixed length, or sizes that only
matter before the call's time zero):

- the DTLS certificate's key, serial and signatures and the ECDHE key (the crypto backend's
  system generator), its validity dates and the hello's `gmt_unix_time` (wall clock): handshake
  bytes, and with them the SRTP keys;
- STUN transaction ids and ICE candidate ids (`rand`);
- the sender SSRCs of the feedback interceptors (NACK generator, TWCC recorder, receiver report
  stream), the RTX stream's first sequence number (`rand`): identifiers;
- the RTP timestamp base of `rtci::rtp::packetizer::new_packetizer` (`rand`): the one to
  watch, since a 32-bit wrap of the video timestamp falls inside about one run in 700;
- media stream ids, transport nonces, the ECN draw of the statistics, the SRTP context's hash
  seed, `HashMap` iteration order (`RandomState`);
- clock reads: the eight of docs/sans-io-deterministic-time-allowlist.txt, none on this
  scenario's wire.

## What it found

Hosted runners, release build. v0.1.0; master d914b929 (before train 26, which brought the
draft's threshold time base as the estimator's default); master 63e1b8b8 (after it: THE
BASELINE the tripwires are recorded from); master 63e1b8b8 with `conf/rtx-2r-smooth-limiter`
387b3a0a as it stood. Gate cells on seeds 1 to 1000, the others on 1 to 200 (runs 45504338825,
45504350938; 45504320760, 45504332564; 45504296525, 45504305195; 45504358600, 45504375646).
Shares are of all runs; "clean" runs are those with no flow ceased by the circuit breaker and no
peer that left Connected; "picture, clean" is the picture requirement's share among them.

| cell | tree | runs | picture | freeze | audio gap>1 s | resume>2 s | never back | cb (audio) | disc (failed) | clean | picture, clean | max_age p50/p90 | fresh_gap p50/p90 | audio_share mean | under p50 | recover p50 |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| cap/paced/gap300/up/q300/rl0 | v0.1.0 | 1000 | 100.0 % | 100.0 % | 8.3 % | 0.0 % | 0.0 % | 84 (83) | 163 (0) | 767 | 100.0 % | 9.02/10.15 | 8.69/9.86 | 0.907 | 208 | 18.3 |
| cap/paced/gap300/up/q300/rl0 | d914b929 | 1000 | 100.0 % | 100.0 % | 8.9 % | 0.0 % | 0.0 % | 91 (89) | 155 (0) | 761 | 100.0 % | 9.04/10.19 | 8.74/9.89 | 0.901 | 207 | 18.3 |
| cap/paced/gap300/up/q300/rl0 | 63e1b8b8 | 1000 | 100.0 % | 100.0 % | 8.9 % | 0.0 % | 0.0 % | 91 (89) | 156 (0) | 761 | 100.0 % | 9.00/10.23 | 8.68/9.94 | 0.900 | 213 | 18.1 |
| cap/paced/gap300/up/q300/rl0 | +rtx-2r | 1000 | 100.0 % | 100.0 % | 8.9 % | 0.0 % | 0.0 % | 93 (89) | 159 (0) | 757 | 100.0 % | 6.34/7.30 | 6.17/7.10 | 0.900 | 224 | 17.7 |
| cap/paced/gap0/up/q300/rl0 | v0.1.0 | 1000 | 100.0 % | 29.6 % | 8.3 % | 0.0 % | 0.0 % | 86 (83) | 164 (0) | 764 | 100.0 % | 8.38/9.46 | 8.56/9.68 | 0.907 | 208 | 18.3 |
| cap/paced/gap0/up/q300/rl0 | d914b929 | 1000 | 100.0 % | 27.7 % | 8.9 % | 0.0 % | 0.0 % | 91 (89) | 156 (0) | 760 | 100.0 % | 8.34/9.44 | 8.50/9.71 | 0.901 | 207 | 18.4 |
| cap/paced/gap0/up/q300/rl0 | 63e1b8b8 | 1000 | 100.0 % | 27.2 % | 8.9 % | 0.0 % | 0.0 % | 91 (89) | 159 (0) | 757 | 100.0 % | 8.32/9.53 | 8.48/9.71 | 0.900 | 214 | 18.1 |
| cap/paced/gap0/up/q300/rl0 | +rtx-2r | 1000 | 100.0 % | 0.0 % | 8.9 % | 0.0 % | 0.0 % | 89 (89) | 160 (0) | 758 | 100.0 % | 5.68/6.66 | 5.98/6.86 | 0.900 | 223 | 17.5 |
| cap/nopacer/gap300/up/q300/rl0 | v0.1.0 | 200 | 5.5 % | 4.5 % | 0.0 % | 0.0 % | 0.0 % | 0 (0) | 39 (0) | 161 | 3.7 % | 1.33/2.13 | 0.98/1.72 | 0.989 | 232 | 10.3 |
| cap/nopacer/gap300/up/q300/rl0 | d914b929 | 200 | 8.0 % | 6.5 % | 0.0 % | 0.0 % | 0.0 % | 0 (0) | 40 (0) | 160 | 8.8 % | 1.33/2.36 | 0.98/1.67 | 0.989 | 233 | 10.3 |
| cap/nopacer/gap300/up/q300/rl0 | 63e1b8b8 | 200 | 7.0 % | 5.5 % | 0.0 % | 0.0 % | 0.0 % | 0 (0) | 40 (0) | 160 | 7.5 % | 1.33/2.35 | 0.98/1.67 | 0.989 | 234 | 10.9 |
| cap/nopacer/gap300/up/q300/rl0 | +rtx-2r | 200 | 1.0 % | 1.0 % | 0.0 % | 0.0 % | 0.0 % | 0 (0) | 37 (0) | 163 | 1.2 % | 1.38/2.04 | 0.95/1.69 | 0.989 | 237 | 10.6 |
| cap/nopacer/gap0/up/q300/rl0 | v0.1.0 | 200 | 100.0 % | 0.0 % | 0.0 % | 0.0 % | 0.0 % | 0 (0) | 35 (0) | 165 | 100.0 % | 5.19/7.30 | 5.36/7.55 | 0.989 | 232 | 10.3 |
| cap/nopacer/gap0/up/q300/rl0 | d914b929 | 200 | 100.0 % | 0.5 % | 0.0 % | 0.0 % | 0.0 % | 0 (0) | 36 (0) | 164 | 100.0 % | 5.22/7.38 | 5.39/7.54 | 0.989 | 233 | 10.3 |
| cap/nopacer/gap0/up/q300/rl0 | 63e1b8b8 | 200 | 100.0 % | 1.0 % | 0.0 % | 0.0 % | 0.0 % | 0 (0) | 36 (0) | 164 | 100.0 % | 5.24/7.37 | 5.40/7.62 | 0.989 | 235 | 10.8 |
| cap/nopacer/gap0/up/q300/rl0 | +rtx-2r | 200 | 100.0 % | 0.0 % | 0.0 % | 0.0 % | 0.0 % | 0 (0) | 37 (0) | 163 | 100.0 % | 3.17/4.35 | 3.42/4.76 | 0.989 | 237 | 10.8 |
| cap/paced/gap300/both/q300/rl0 | v0.1.0 | 200 | 100.0 % | 100.0 % | 4.5 % | 28.0 % | 7.5 % | 193 (3) | 79 (0) | 5 | 100.0 % | 20.77/26.18 | 20.51/25.86 | 0.969 | 0 | 18.3 |
| cap/paced/gap300/both/q300/rl0 | d914b929 | 200 | 100.0 % | 100.0 % | 2.5 % | 32.5 % | 8.5 % | 196 (2) | 69 (0) | 2 | 100.0 % | 20.82/26.34 | 20.57/25.95 | 0.968 | 0 | 18.1 |
| cap/paced/gap300/both/q300/rl0 | 63e1b8b8 | 200 | 100.0 % | 100.0 % | 2.5 % | 31.0 % | 8.5 % | 187 (2) | 70 (0) | 9 | 100.0 % | 20.43/26.34 | 20.18/25.95 | 0.968 | 0 | 18.1 |
| cap/paced/gap300/both/q300/rl0 | +rtx-2r | 200 | 100.0 % | 100.0 % | 2.5 % | 12.0 % | 11.5 % | 183 (2) | 72 (0) | 9 | 100.0 % | 14.07/46.48 | 13.84/46.09 | 0.968 | 139 | 16.8 |
| cap/nopacer/gap300/both/q300/rl0 | v0.1.0 | 200 | 28.5 % | 27.5 % | 0.0 % | 25.0 % | 25.0 % | 91 (0) | 96 (0) | 61 | 8.2 % | 1.90/43.45 | 1.55/43.15 | 0.986 | 234 | 10.0 |
| cap/nopacer/gap300/both/q300/rl0 | d914b929 | 200 | 32.0 % | 32.0 % | 0.0 % | 28.5 % | 28.5 % | 102 (0) | 111 (0) | 46 | 8.7 % | 1.97/43.54 | 1.61/43.16 | 0.986 | 232 | 10.1 |
| cap/nopacer/gap300/both/q300/rl0 | 63e1b8b8 | 200 | 32.0 % | 32.0 % | 0.0 % | 28.5 % | 28.5 % | 102 (0) | 112 (0) | 44 | 9.1 % | 1.97/43.54 | 1.62/43.16 | 0.986 | 227 | 10.2 |
| cap/nopacer/gap300/both/q300/rl0 | +rtx-2r | 200 | 38.5 % | 40.5 % | 0.0 % | 32.5 % | 32.5 % | 111 (0) | 127 (0) | 20 | 15.0 % | 2.31/42.84 | 1.95/42.63 | 0.987 | 272 | 9.8 |
| cap/paced/gap300/up/q100/rl0 | v0.1.0 | 200 | 100.0 % | 100.0 % | 8.0 % | 0.0 % | 0.0 % | 19 (16) | 42 (0) | 142 | 100.0 % | 7.97/8.66 | 7.86/8.60 | 0.902 | 183 | 18.8 |
| cap/paced/gap300/up/q100/rl0 | d914b929 | 200 | 100.0 % | 100.0 % | 13.0 % | 0.0 % | 0.0 % | 30 (26) | 38 (0) | 134 | 100.0 % | 7.85/8.71 | 7.70/8.60 | 0.853 | 190 | 18.5 |
| cap/paced/gap300/up/q100/rl0 | 63e1b8b8 | 200 | 100.0 % | 100.0 % | 13.0 % | 0.0 % | 0.0 % | 29 (26) | 39 (0) | 134 | 100.0 % | 7.81/8.77 | 7.73/8.72 | 0.852 | 191 | 18.6 |
| cap/paced/gap300/up/q100/rl0 | +rtx-2r | 200 | 100.0 % | 100.0 % | 13.0 % | 1.0 % | 1.0 % | 30 (26) | 39 (0) | 135 | 100.0 % | 5.75/6.23 | 5.67/6.25 | 0.851 | 206 | 18.1 |
| cap/paced/gap300/up/q1000/rl0 | v0.1.0 | 200 | 100.0 % | 100.0 % | 30.5 % | 0.0 % | 0.0 % | 61 (61) | 103 (0) | 70 | 100.0 % | 7.99/8.70 | 7.16/7.95 | 0.698 | 219 | 17.4 |
| cap/paced/gap300/up/q1000/rl0 | d914b929 | 200 | 100.0 % | 100.0 % | 33.0 % | 0.0 % | 0.0 % | 66 (66) | 96 (0) | 67 | 100.0 % | 7.95/8.68 | 7.09/7.93 | 0.672 | 220 | 17.4 |
| cap/paced/gap300/up/q1000/rl0 | 63e1b8b8 | 200 | 100.0 % | 100.0 % | 33.0 % | 0.0 % | 0.0 % | 66 (66) | 96 (0) | 67 | 100.0 % | 7.95/8.69 | 7.11/7.94 | 0.672 | 224 | 17.3 |
| cap/paced/gap300/up/q1000/rl0 | +rtx-2r | 200 | 100.0 % | 100.0 % | 30.0 % | 0.0 % | 0.0 % | 60 (60) | 99 (0) | 65 | 100.0 % | 7.37/8.32 | 6.64/7.69 | 0.700 | 222 | 17.5 |
| cap/paced/gap300/up/q300/rl5 | v0.1.0 | 200 | 100.0 % | 100.0 % | 14.0 % | 0.0 % | 0.0 % | 35 (28) | 103 (0) | 80 | 100.0 % | 8.93/10.33 | 8.60/10.03 | 0.851 | 200 | 18.6 |
| cap/paced/gap300/up/q300/rl5 | d914b929 | 200 | 100.0 % | 100.0 % | 12.0 % | 0.0 % | 0.0 % | 35 (24) | 103 (0) | 83 | 100.0 % | 8.81/10.11 | 8.55/9.77 | 0.870 | 200 | 18.0 |
| cap/paced/gap300/up/q300/rl5 | 63e1b8b8 | 200 | 100.0 % | 100.0 % | 12.0 % | 0.0 % | 0.0 % | 49 (24) | 111 (0) | 64 | 100.0 % | 8.83/10.05 | 8.52/9.76 | 0.870 | 206 | 17.7 |
| cap/paced/gap300/up/q300/rl5 | +rtx-2r | 200 | 100.0 % | 100.0 % | 21.0 % | 0.0 % | 0.0 % | 70 (42) | 105 (0) | 60 | 100.0 % | 6.79/8.43 | 6.58/8.25 | 0.781 | 217 | 17.2 |
| cap/nopacer/gap300/up/q100/rl0 | v0.1.0 | 200 | 6.5 % | 6.5 % | 0.0 % | 0.0 % | 0.0 % | 0 (0) | 38 (0) | 162 | 4.9 % | 1.86/2.04 | 1.63/1.94 | 0.983 | 216 | 10.6 |
| cap/nopacer/gap300/up/q100/rl0 | d914b929 | 200 | 9.0 % | 9.0 % | 0.5 % | 0.0 % | 0.0 % | 1 (1) | 57 (0) | 142 | 8.5 % | 1.88/2.11 | 1.66/1.97 | 0.978 | 216 | 10.6 |
| cap/nopacer/gap300/up/q100/rl0 | 63e1b8b8 | 200 | 9.5 % | 9.5 % | 0.5 % | 0.0 % | 0.0 % | 1 (1) | 58 (0) | 141 | 10.6 % | 1.88/2.10 | 1.66/1.97 | 0.976 | 215 | 10.6 |
| cap/nopacer/gap300/up/q100/rl0 | +rtx-2r | 200 | 6.0 % | 6.0 % | 0.5 % | 0.0 % | 0.0 % | 1 (1) | 49 (0) | 150 | 6.7 % | 1.72/2.06 | 1.61/1.95 | 0.980 | 233 | 10.6 |
| cap/nopacer/gap300/up/q1000/rl0 | v0.1.0 | 200 | 100.0 % | 60.0 % | 0.5 % | 0.0 % | 0.5 % | 1 (1) | 199 (1) | 1 | 100.0 % | 3.48/3.82 | 2.63/3.54 | 0.992 | 213 | 10.8 |
| cap/nopacer/gap300/up/q1000/rl0 | d914b929 | 200 | 100.0 % | 61.5 % | 1.0 % | 0.0 % | 1.0 % | 2 (2) | 197 (2) | 3 | 100.0 % | 3.48/3.83 | 2.62/3.60 | 0.989 | 215 | 10.5 |
| cap/nopacer/gap300/up/q1000/rl0 | 63e1b8b8 | 200 | 100.0 % | 61.5 % | 1.5 % | 0.0 % | 1.5 % | 3 (3) | 197 (3) | 3 | 100.0 % | 3.48/3.85 | 2.63/3.63 | 0.987 | 214 | 10.1 |
| cap/nopacer/gap300/up/q1000/rl0 | +rtx-2r | 200 | 99.5 % | 3.5 % | 0.5 % | 0.0 % | 0.0 % | 1 (1) | 191 (0) | 8 | 100.0 % | 2.81/2.88 | 3.43/3.90 | 0.986 | 216 | 10.6 |
| cap/nopacer/gap300/up/q300/rl5 | v0.1.0 | 200 | 7.0 % | 8.5 % | 0.0 % | 0.0 % | 0.0 % | 0 (0) | 119 (0) | 81 | 6.2 % | 1.33/2.39 | 0.99/1.93 | 0.990 | 234 | 11.2 |
| cap/nopacer/gap300/up/q300/rl5 | d914b929 | 200 | 10.0 % | 9.5 % | 0.0 % | 0.0 % | 0.0 % | 1 (0) | 100 (0) | 99 | 14.1 % | 1.35/2.44 | 0.99/2.00 | 0.990 | 234 | 11.1 |
| cap/nopacer/gap300/up/q300/rl5 | 63e1b8b8 | 200 | 10.5 % | 9.5 % | 0.0 % | 0.0 % | 0.0 % | 2 (0) | 113 (0) | 86 | 15.1 % | 1.35/2.56 | 0.99/2.00 | 0.990 | 232 | 10.7 |
| cap/nopacer/gap300/up/q300/rl5 | +rtx-2r | 200 | 2.5 % | 2.5 % | 0.0 % | 0.0 % | 0.0 % | 7 (0) | 109 (0) | 89 | 3.4 % | 1.46/2.16 | 1.10/1.67 | 0.990 | 230 | 11.0 |
| outage/paced/gap300/up/q300/rl0 | v0.1.0 | 200 | 100.0 % | 100.0 % | 100.0 % | 67.0 % | 0.0 % | 0 (0) | 0 (0) | 200 | 100.0 % | 6.09/6.12 | 7.30/14.20 | 0.861 | 0 | 15.0 |
| outage/paced/gap300/up/q300/rl0 | d914b929 | 200 | 100.0 % | 100.0 % | 100.0 % | 67.0 % | 0.0 % | 0 (0) | 0 (0) | 200 | 100.0 % | 6.09/6.12 | 7.30/14.31 | 0.861 | 0 | 15.0 |
| outage/paced/gap300/up/q300/rl0 | 63e1b8b8 | 200 | 100.0 % | 100.0 % | 100.0 % | 67.0 % | 0.0 % | 0 (0) | 0 (0) | 200 | 100.0 % | 6.09/6.12 | 7.30/14.31 | 0.861 | 0 | 15.0 |
| outage/paced/gap300/up/q300/rl0 | +rtx-2r | 200 | 100.0 % | 100.0 % | 100.0 % | 0.0 % | 0.0 % | 0 (0) | 0 (0) | 200 | 100.0 % | 5.26/5.26 | 5.20/5.21 | 0.861 | 0 | 14.9 |
| outage/nopacer/gap300/up/q300/rl0 | v0.1.0 | 200 | 100.0 % | 100.0 % | 100.0 % | 0.0 % | 0.0 % | 0 (0) | 0 (0) | 200 | 100.0 % | 4.35/4.35 | 4.47/4.47 | 0.861 | 0 | 10.2 |
| outage/nopacer/gap300/up/q300/rl0 | d914b929 | 200 | 100.0 % | 100.0 % | 100.0 % | 0.0 % | 0.0 % | 0 (0) | 0 (0) | 200 | 100.0 % | 4.35/4.35 | 4.47/4.47 | 0.861 | 0 | 10.1 |
| outage/nopacer/gap300/up/q300/rl0 | 63e1b8b8 | 200 | 100.0 % | 100.0 % | 100.0 % | 0.0 % | 0.0 % | 0 (0) | 0 (0) | 200 | 100.0 % | 4.35/4.35 | 4.47/4.47 | 0.861 | 0 | 10.1 |
| outage/nopacer/gap300/up/q300/rl0 | +rtx-2r | 200 | 100.0 % | 100.0 % | 100.0 % | 0.0 % | 0.0 % | 0 (0) | 0 (0) | 200 | 100.0 % | 4.58/4.58 | 4.60/4.60 | 0.861 | 0 | 8.2 |
| cap/parolnet/gap300/up/q300/rl0 | v0.1.0 | 200 | 0.0 % | 0.0 % | 0.0 % | 0.0 % | 0.0 % | 0 (0) | 33 (0) | 167 | 0.0 % | 1.33/1.34 | 0.98/0.99 | 0.991 | 242 | 10.6 |
| cap/parolnet/gap300/up/q300/rl0 | d914b929 | 200 | 0.0 % | 0.0 % | 0.0 % | 0.0 % | 0.0 % | 0 (0) | 35 (0) | 165 | 0.0 % | 1.33/1.34 | 0.98/0.99 | 0.991 | 240 | 10.8 |
| cap/parolnet/gap300/up/q300/rl0 | 63e1b8b8 | 200 | 0.0 % | 0.0 % | 0.0 % | 0.0 % | 0.0 % | 0 (0) | 44 (0) | 156 | 0.0 % | 1.33/1.34 | 0.98/0.99 | 0.987 | 248 | 10.4 |
| cap/parolnet/gap300/up/q300/rl0 | +rtx-2r | 200 | 0.0 % | 0.0 % | 0.0 % | 0.0 % | 0.0 % | 0 (0) | 35 (0) | 165 | 0.0 % | 1.43/1.98 | 1.08/1.63 | 0.987 | 244 | 11.0 |
| cap/parolnet/gap0/up/q300/rl0 | v0.1.0 | 200 | 100.0 % | 0.0 % | 0.0 % | 0.0 % | 0.0 % | 0 (0) | 29 (0) | 171 | 100.0 % | 4.58/6.90 | 4.71/7.10 | 0.991 | 244 | 10.7 |
| cap/parolnet/gap0/up/q300/rl0 | d914b929 | 200 | 100.0 % | 0.0 % | 0.0 % | 0.0 % | 0.0 % | 0 (0) | 34 (0) | 166 | 100.0 % | 4.57/7.04 | 4.72/7.26 | 0.991 | 241 | 11.0 |
| cap/parolnet/gap0/up/q300/rl0 | 63e1b8b8 | 200 | 100.0 % | 0.0 % | 0.0 % | 0.0 % | 0.0 % | 0 (0) | 47 (0) | 153 | 100.0 % | 4.57/7.12 | 4.72/7.29 | 0.987 | 251 | 10.6 |
| cap/parolnet/gap0/up/q300/rl0 | +rtx-2r | 200 | 100.0 % | 0.0 % | 0.0 % | 0.0 % | 0.0 % | 0 (0) | 42 (0) | 158 | 100.0 % | 3.07/4.17 | 3.16/4.26 | 0.987 | 245 | 11.1 |

(In the outage cells the picture, freeze and audio columns are the outage itself, four seconds
and the restart: the requirement there is `resume`.)

Requirements on master, by cell:

| cell | picture | freeze | audio | resume |
|---|---|---|---|---|
| default chain, reference receiver | MISSED: 100 % (oldest picture 9.0 s in the median) | MISSED: 100 % (8.7 s) | met since breaker-1: 0 of 1000 (was 8.9 %: audio ceased by the circuit breaker and never restarted) | |
| default chain, receiver without a bound | MISSED: 100 % (8.3 s) | MISSED: 27.2 % (29.1 % with breaker-1: the calls whose audio was dead froze less) | met since breaker-1: 0 of 1000 (was 8.9 %) | |
| pacer-less chain, reference receiver | at the bound: 7.0 % (4.2 to 11.4) | at the bound: 5.5 % (3.1 to 9.6) | met: 0 of 200 | |
| ParolNet's chain, reference receiver | met: 0 of 200 (1.33 s) | met: 0 of 200 | met: 0 of 200 | |
| both directions capped, default chain | MISSED: 100 % (20.4 s; 8.5 % never back) | MISSED: 100 % | 2.5 % | |
| both directions capped, pacer-less | MISSED: 32 % (28.5 % never back) | MISSED: 32 % | met | |
| outage, default chain | | | | MISSED: 67 % |
| outage, pacer-less | | | | met: 0 of 200 |

Master against v0.1.0: nothing moved in the default chain (oldest picture 9.00 against 9.02 s,
the share of the old freeze over 2 s 27.2 against 29.6 %). Train 26 against the master before
it, per seed: picture -0.03 +-0.04 s, the target under the cap +7.1 +-1.6 kbit/s, 15 to 25 s
after it +27 +-13 kbit/s, audio and circuit breaker unchanged in the default chain; in
ParolNet's chain 8.8 +-1.1 more audio packets lost at the drop (20.3 to 29.1, 0.18 s of audio),
which breaks the merge-point rule's audio margin, and in the pacer-less chain the target 15 to
25 s after the cap is 46 +-16 kbit/s lower.

Since then (master 0ca11557, train 30, against 2299c39e; the baseline file is recorded from
0ca11557, runs 45531256372 and 45531266403): the consent fix removed the peers that failed and
most of those that left Connected behind a 1000 ms queue (197 to 32 of 200 without the pacer),
and left the standard cells as they were (156 of 1000). Not repeating a repair the feedback
reported received (`conf/rtx-1r2-duplicate-repairs`) made the picture 1.2 s younger in the
default chain (oldest picture 7.9 s in the median, per seed -1.22 +-0.05 s), took the old
freeze over 2 s with the receiver without a bound from 272 to 15 of 1000 runs (that requirement
is now met there; the picture on the screen is still 7.2 s old), and did not slow the
recovery after the cap: the target 15 to 25 s after it moved by -0.1 +-17 kbit/s in the default
chain, +14 +-20 without the pacer and -30 +-23 in ParolNet's chain, the time to recover the rate
by +0.03 +-0.31, -0.17 +-0.22 and +0.31 +-0.24 s. The merge-point rule holds. The picture
requirement is still missed in every run of the default chain, and the audio is still left dead
in 8.9 %.
