//! What the user of a video call sees when the path's capacity collapses, measured as
//! distributions over an ensemble of runs. Virtual time ([`capacity_common`]).
//!
//! The call: audio and video each way, open for 20 s, then the caller's uplink drops from
//! whatever the estimate had reached (2.5 Mbit/s with the pacer) to 300 kbit/s, stays there for
//! 20 s after the sender reacted (60 s in the scenario `cap60`), and opens again for 25 s. A
//! second scenario takes the whole path away for 4 s and brings it back with an ICE restart.
//!
//! # Figures
//!
//! Every figure is computed from what the callee's screen and loudspeaker had, not from what
//! came out of a buffer. The picture ON THE SCREEN at an instant is the last usable frame the
//! decoder gave; its AGE is that instant less the frame's capture (captures are stamped to
//! 10 ms). One line per run (`IROW cell=.. seed=.. phase=.. name=value ..`), seconds unless
//! said:
//!
//! | figure | what it is |
//! |---|---|
//! | `max_age` | the oldest picture on the screen, from the drop to the end of the run |
//! | `age_p50`, `age_p95` | the age not exceeded for half / 95 % of the time under the cap |
//! | `stale1`, `stale2` | time the screen showed a picture older than 1 s / 2 s, from the drop on |
//! | `fresh_gap` | the longest time without a new picture less than 1 s old, from the drop on |
//! | `freeze` | the longest time without a new picture of any age (2 s into the call to the end): the figure `capacity_cap_video_rtc2rtc.rs` asserted until this instrument; secondary |
//! | `tail_gap` | at the end of the run, how long since the last picture less than 1 s old (a call that never recovers: 25 s and more) |
//! | `resume` | from the capacity's return (the cap lifted, the new pair selected) to the next picture less than 1 s old; 99 when none came |
//! | `settle` | from the capacity's return to the last instant the screen was more than 0.5 s old |
//! | `audio_gap` | the longest time without an Opus packet arriving, from the drop on (audio that never comes back: the rest of the run) |
//! | `audio_share`, `audio_back` | the share of the audio of the time from the drop on that arrived: the caller's at the callee, the callee's at the caller |
//! | `audio_tail` | at the end of the run, how long since the last Opus packet arrived (audio silent to the end: the rest of the call) |
//! | `audio_lost` | the caller's Opus packets of that time that did not arrive (20 ms each) |
//! | `audio_delay` | the most an Opus packet was delayed beyond the call's best |
//! | `cb`, `cb_audio` | flows (of either peer) the RTP circuit breaker (RFC 8083) had ceased at the end, and how many of them are audio: the engine drops what is written on a ceased flow |
//! | `disc`, `pc_failed` | how often a peer connection left Connected, and whether one reached Failed |
//! | `disc_time`, `disc_max`, `disc_open` | the episodes in which a peer was not Connected (after it first was): their total length over both peers, the longest, and how many were still open at the end of the run (a peer that never came back, or failed) |
//! | `stun_lost` | STUN datagrams (ICE consent checks and their responses, RFC 7675) that did not arrive: dropped at a link's queue or lost on the reverse path. One lost check makes its sender `disconnected` when the next check's answer comes later than 5 s after it |
//! | `low`, `mean10` | kbit/s: the caller's lowest target in the 5 s after the drop (a pause left out), and its mean over the 10 s after |
//! | `back_low`, `back_mean` | the same of the callee's target: the direction whose capacity did not change unless the cell is `both` (its feedback crosses the capped link) |
//! | `recover` | from the capacity's return until the encoder's target is back to 0.4 of what it was before the drop; 99 when not within the 25 s observed. RELATIVE: two chains or trees whose `before` differs wait for different rates (0.4 of 2.5 Mbit/s is 1000 kbit/s, of 1.4 Mbit/s 565), so it compares them only where `before` is the same |
//! | `to1000` | from the capacity's return until the encoder's target is at 1000 kbit/s; 99 when not within the 25 s observed. ABSOLUTE: the same rate in every chain and on every tree |
//! | `startup` | from the start of the call (the peers connected) until the encoder's target is within 5 % of the 2.5 Mbit/s maximum (2375 kbit/s); 99 when not before the drop |
//! | `before`, `under`, `window` | kbit/s: the target before the drop, its median under the cap, its mean 15 to 25 s after the cap |
//! | `reacted` | from the drop until the target is under 400 kbit/s (99: not within 5 s); in the outage, from the restart to the new pair |
//! | `paused` | time the target was zero (the pacer's pause), from the drop on |
//! | `rtx`, `rtx_dropped`, `qdrops` | retransmissions sent and dropped at the link's queue, all queue drops (caller's uplink, whole call) |
//! | `pli`, `keyframes`, `unusable`, `gaps` | key-frame requests the callee sent, key frames the caller made, frames without a reference, gaps the builder gave up for its time bound |
//! | `discards` | the caller's `OnPacerDiscard` events |
//! | `end` | the length of the call |
//!
//! A run is CLEAN when no flow was ceased and no peer left Connected (`cb` = 0, `disc` = 0).
//! A short freeze with dead audio is not a good run: the tables give the shares over all runs
//! and over the clean ones apart, and the audio requirement counts dead audio.
//!
//! # Cells
//!
//! A cell names everything but the seed: `scenario/chain/gapN/direction/qN/rlN`.
//!
//! - scenario: `cap`, `cap60` (the cap stays 60 s instead of 20: what a sender does to a path
//!   that does not come back for a long time, and whether trying for the old rate meanwhile
//!   costs anything; measurement only), `outage`, or `fbgap` (the capacity does not change;
//!   none of the callee's RTCP arrives for 300 ms: what a gap in the feedback alone costs the
//!   caller's target, read in `low` and `mean10`);
//! - chain: `paced` (the engine's default interceptors), `nopacer` (the same without the pacer),
//!   `parolnet` (ParolNet's chain; measurement only);
//! - `gapN`: the receiver. `gap300` is the REFERENCE receiver: `SampleBuilder::new(256, ..)
//!   .with_max_gap_wait(300 ms)` and a PLI when the builder gives a gap up
//!   (docs/receiver-gap-policy.md). `gap0` is the receiver without a bound in time
//!   (`with_max_gap_wait(None)`), which holds a gap for 256 packets or until a complete key
//!   frame releases it (the builder's rule for every receiver): the second, documented cell,
//!   because it is the one configuration in which discarding a stale repair is costly, and a
//!   policy must be measured on both.
//!   Why 300 ms: the NACK generator asks every 100 ms and a repair comes back a round trip
//!   later, so on the open path (20 ms round trip) 300 ms is two whole request rounds with
//!   margin, and it is inside the 200 ms to 1 s of playout delay that page gives for
//!   interactive video. Under the cap the forward path is 30 ms and up to the queue's 300 ms,
//!   so a first repair arrives 140 to 440 ms after the gap is known: with a full queue the
//!   bound ends the wait before the repair can arrive. That is the policy, not an accident: a
//!   receiver that will not show a picture a second old cannot wait for one. `gap600` and
//!   `gap1000` are measured for comparison (docs/capacity-instrument.md);
//! - direction: `up` (the caller's uplink capped, feedback path open) or `both`;
//! - `qN`: the capped link's drop-tail queue in ms at the link's rate (100, 300, 1000);
//! - `rlN`: per cent of the callee's datagrams (its media and all its feedback) lost.
//!
//! The cap arrives 20 s into the call plus a PHASE of 0, 11 or 23 ms ([`PHASES_MS`], a third of
//! the seeds each): the frame clock is 33.3 ms and the phase at which the cap meets it moves
//! the figures (0 ms, the only phase the old test ran, is the favourable one).
//!
//! # How a claim is asserted
//!
//! Never as a maximum over a handful of runs: a seed is a draw, and the dynamics are chaotic
//! (one more seeded byte moves every figure). Two kinds of claim:
//!
//! **A REQUIREMENT** is what the call's user is owed, as a share: "in at most 5 % of calls
//! does ..." ([`REQUIRED_SHARE`]). It is tested on [`REQUIREMENT_RUNS`] = 300 runs and passes
//! when at most 21 of them violate it (the exact binomial critical value at 5 %, computed by
//! [`critical`]). The power calculation, exact binomial, n = 300, c = 21:
//!
//! | true share of violating calls | the test passes with probability |
//! |---|---|
//! | 2.5 % | 0.99999 |
//! | 5 % (at the bound) | 0.951 |
//! | 10 % (twice the bound) | 0.046 (fails with 0.954) |
//! | 15 % | 0.0000 (fails with 1.0000) |
//!
//! (240 runs would give 0.966 and 0.885; 300 is the smallest round number with both at 0.95.
//! `the_requirement_test_has_the_power_it_claims` holds these figures.) A run that fails to
//! complete counts as a violation. A requirement the engine does not meet is NOT loosened: its
//! test is `#[ignore]`d with the measured share in the attribute, listed in CHANGELOG "Known
//! limits", and a tripwire holds today's level.
//!
//! **A TRIPWIRE** notices a regression against a recorded baseline. The baseline
//! (`tests/fixtures/capacity-instrument-baseline.tsv`, written by
//! `scripts/capacity-instrument.py baseline` from a large measurement of master) records, per
//! cell and figure, a threshold (the baseline's median and 90th percentile and a tenth of slack,
//! or a fixed limit)
//! and how many of the baseline's runs were beyond it. The tripwire counts this tree's runs
//! beyond the same threshold and fails when that count is improbable under the baseline: more
//! than the binomial critical value at [`TRIPWIRE_ALPHA`] = 0.002 for a share equal to the
//! upper end of the baseline share's 95 % Wilson interval (the stated tolerance: the baseline
//! is itself a sample). With 60 runs a threshold that a tenth of the baseline's runs were
//! beyond (12 % allowed for) fails above 15 runs: a change that puts 25 % of runs beyond it is
//! caught with probability 0.43, 40 % with 0.99; one that half were beyond fails above 43: 75 %
//! beyond is caught with 0.68, 85 % with 0.99. (With the tenth of slack a median's threshold
//! has fewer than half of the baseline beyond it: 16 % in the reference cell, whose oldest
//! picture is 9.0 s with a spread of 0.9 s, so a picture one second older, which puts over half
//! of the runs beyond it, is caught.) Tripwires are for gross regressions on every pull
//! request; the fine comparison is the dispatched one (`capacity-compare.yml`,
//! docs/capacity-instrument.md).
//!
//! # Run modes
//!
//! - `cargo test --test capacity_instrument`: the figures' and the statistics' unit tests and
//!   the determinism check (debug build, every platform).
//! - `cargo test --release --test capacity_instrument -- --ignored ensemble_`: the pull-request
//!   ensemble ([`PR_CELLS`], 606 runs): the tripwires of every cell and the requirements the
//!   engine meets in ParolNet's chain. Release build: a run takes 1.7 to 7.4 s of one core
//!   (3.1 s on average over the ensemble), about eight minutes on a four-core hosted runner.
//! - `cargo test --release --test capacity_instrument -- --ignored on_demand_`: a requirement
//!   the engine meets whose 300 runs do not fit the pull-request job, and two that are at
//!   the bound (they pass on one draw and fail on the next).
//! - `cargo test --release --test capacity_instrument -- --ignored known_limit_`: the
//!   requirements the engine does not meet today (they fail, with the figures).
//! - `cargo test --release --test capacity_instrument -- --ignored --nocapture --exact
//!   measure`: one `IROW` line per run of the cells and seeds the environment names
//!   (`RTC_INSTR_CELLS`, `RTC_INSTR_SEEDS`, `RTC_INSTR_PHASE`, `RTC_INSTR_THREADS`), for
//!   `scripts/capacity-instrument.py`.

mod capacity_common;

use anyhow::{Result, anyhow, bail};
use capacity_common::*;
use rtci::peer_connection::state::RTCPeerConnectionState;
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

// ---------------------------------------------------------------------------------------------
// The screen
// ---------------------------------------------------------------------------------------------

/// A usable frame: when it came out of the decoder (from then on it is the picture on the
/// screen) and when it was captured.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Shown {
    at: Duration,
    captured: Duration,
}

/// The callee's screen: every usable frame, in the order shown.
fn screen(peer: &Peer) -> Vec<Shown> {
    peer.usable_at
        .iter()
        .zip(&peer.usable_lag)
        .map(|(at, lag)| Shown {
            at: *at,
            captured: at.saturating_sub(*lag),
        })
        .collect()
}

/// The part of `from..to` each picture was on the screen: (its capture, from, until), never
/// empty. Before the first picture the screen is blank, which is as old as the call.
fn spans(frames: &[Shown], from: Duration, to: Duration) -> Vec<(Duration, Duration, Duration)> {
    let mut spans = Vec::new();
    let first = frames.first().map_or(to, |frame| frame.at).min(to);
    if first > from {
        spans.push((Duration::ZERO, from, first));
    }
    for (i, frame) in frames.iter().enumerate() {
        let until = frames.get(i + 1).map_or(to, |next| next.at);
        let (lo, hi) = (frame.at.max(from), until.min(to));
        if hi > lo {
            spans.push((frame.captured, lo, hi));
        }
    }
    spans
}

/// The oldest the picture on the screen was in `from..to`.
fn max_age(frames: &[Shown], from: Duration, to: Duration) -> Duration {
    spans(frames, from, to)
        .into_iter()
        .map(|(captured, _, until)| until.saturating_sub(captured))
        .max()
        .unwrap_or_default()
}

/// For how much of `from..to` the picture on the screen was older than `limit`.
fn stale(frames: &[Shown], limit: Duration, from: Duration, to: Duration) -> Duration {
    spans(frames, from, to)
        .into_iter()
        .map(|(captured, lo, hi)| hi.saturating_sub(lo.max(captured + limit)))
        .sum()
}

/// The age the picture on the screen did not exceed for the share `q` of `from..to`.
fn age_quantile(frames: &[Shown], q: f64, from: Duration, to: Duration) -> Duration {
    let allowed = to.saturating_sub(from).mul_f64(1.0 - q);
    let (mut lo, mut hi) = (Duration::ZERO, max_age(frames, from, to));
    // `stale` falls as the limit rises: bisect to a microsecond.
    while hi.saturating_sub(lo) > Duration::from_micros(1) {
        let mid = (lo + hi) / 2;
        if stale(frames, mid, from, to) > allowed {
            lo = mid;
        } else {
            hi = mid;
        }
    }
    hi
}

/// The last instant in `from..to` at which the picture on the screen was older than `limit`.
fn last_older_than(
    frames: &[Shown],
    limit: Duration,
    from: Duration,
    to: Duration,
) -> Option<Duration> {
    spans(frames, from, to)
        .into_iter()
        .filter(|(captured, _, until)| *until > *captured + limit)
        .map(|(_, _, until)| until)
        .max()
}

/// When each picture younger than `fresh` at its showing was shown.
fn fresh_times(frames: &[Shown], fresh: Duration) -> Vec<Duration> {
    frames
        .iter()
        .filter(|frame| frame.at.saturating_sub(frame.captured) < fresh)
        .map(|frame| frame.at)
        .collect()
}

/// What the loudspeaker had in `from..to`.
#[derive(Debug, PartialEq)]
struct Audio {
    /// Packets of that time that did not arrive in it (one is sent every 20 ms).
    lost: u64,
    /// The share of that time's packets that arrived in it.
    share: f64,
    /// The longest time without an arrival.
    gap: Duration,
    /// How long before `to` the last packet arrived: audio silent to the end is the whole
    /// rest of the call.
    tail: Duration,
    /// The most a packet was delayed beyond the least delayed packet of the call (a packet
    /// leaves every 20 ms, one sequence number each).
    delay: Duration,
}

fn audio(arrivals: &[(Duration, u16)], from: Duration, to: Duration) -> Audio {
    let times: Vec<Duration> = arrivals.iter().map(|arrival| arrival.0).collect();
    let (gap, _) = longest_gap(&times, from, to);
    let sent = (to.saturating_sub(from).as_millis() / 20) as u64;
    let arrived = arrivals
        .iter()
        .filter(|(at, _)| *at >= from && *at <= to)
        .count() as u64;
    // How late against a clock that ticks 20 ms a sequence number, in microseconds.
    let first = arrivals.first().map_or(0, |arrival| arrival.1);
    let offset = |(at, seq): &(Duration, u16)| {
        at.as_micros() as i128 - 20_000 * i128::from(seq.wrapping_sub(first))
    };
    let best = arrivals.iter().map(offset).min().unwrap_or(0);
    let delay = arrivals
        .iter()
        .filter(|(at, _)| *at >= from && *at <= to)
        .map(offset)
        .max()
        .map_or(0, |worst| worst - best);
    Audio {
        lost: sent.saturating_sub(arrived),
        share: if sent == 0 {
            1.0
        } else {
            (arrived as f64 / sent as f64).min(1.0)
        },
        gap,
        tail: to.saturating_sub(
            times
                .iter()
                .rev()
                .find(|at| **at <= to)
                .copied()
                .unwrap_or_default(),
        ),
        delay: Duration::from_micros(delay.max(0) as u64),
    }
}

/// How long after `from` the target is first at `level` or more; `None` when not by `to`.
fn recovered_after(
    targets: &[(Duration, u32)],
    level: u32,
    from: Duration,
    to: Duration,
) -> Option<Duration> {
    if target_at(targets, from) >= level {
        return Some(Duration::ZERO);
    }
    targets
        .iter()
        .find(|(at, bps)| *at >= from && *at <= to && *bps >= level)
        .map(|(at, _)| *at - from)
}

/// When the target was first at `level` or more, counted from the start of the call; `None`
/// when not by `by`.
fn reached_by(targets: &[(Duration, u32)], level: u32, by: Duration) -> Option<Duration> {
    targets
        .iter()
        .find(|(at, bps)| *at <= by && *bps >= level)
        .map(|(at, _)| *at)
}

/// The lowest target in `from..to`, a pause (zero) left out: the estimate's own low point.
fn lowest(targets: &[(Duration, u32)], from: Duration, to: Duration) -> u32 {
    let mut low = target_at(targets, from);
    for (at, bps) in targets {
        if *at >= from && *at < to && *bps > 0 && (*bps < low || low == 0) {
            low = *bps;
        }
    }
    low
}

/// The mean target over `from..to`, sampled every 100 ms.
fn mean_target(targets: &[(Duration, u32)], from: Duration, to: Duration) -> u32 {
    let mut sum = 0u64;
    let mut n = 0u64;
    let mut at = from;
    while at < to {
        sum += u64::from(target_at(targets, at));
        n += 1;
        at += Duration::from_millis(100);
    }
    (sum / n.max(1)) as u32
}

/// The episodes in which a peer was not Connected after it first was: their total length,
/// the longest, and how many are still open at `end`.
fn disconnects(
    states: &[(Duration, RTCPeerConnectionState)],
    end: Duration,
) -> (Duration, Duration, u32) {
    let mut total = Duration::ZERO;
    let mut longest = Duration::ZERO;
    let mut was_connected = false;
    let mut since: Option<Duration> = None;
    for (at, state) in states {
        if *state == RTCPeerConnectionState::Connected {
            was_connected = true;
            if let Some(from) = since.take() {
                total += *at - from;
                longest = longest.max(*at - from);
            }
        } else if was_connected && since.is_none() {
            since = Some(*at);
        }
    }
    let Some(from) = since else {
        return (total, longest, 0);
    };
    (total + (end - from), longest.max(end - from), 1)
}

/// For how much of `from..to` the target was zero.
fn paused(targets: &[(Duration, u32)], from: Duration, to: Duration) -> Duration {
    let mut total = Duration::ZERO;
    for (i, (at, bps)) in targets.iter().enumerate() {
        if *bps == 0 {
            let until = targets.get(i + 1).map_or(to, |next| next.0);
            total += until.min(to).saturating_sub((*at).max(from));
        }
    }
    total
}

// ---------------------------------------------------------------------------------------------
// A run and its figures
// ---------------------------------------------------------------------------------------------

/// The figures of a run, in the order they are printed (the module's table).
const NAMES: [&str; 45] = [
    "max_age",
    "age_p50",
    "age_p95",
    "stale1",
    "stale2",
    "fresh_gap",
    "freeze",
    "tail_gap",
    "resume",
    "settle",
    "audio_gap",
    "audio_lost",
    "audio_delay",
    "recover",
    "before",
    "reacted",
    "under",
    "window",
    "paused",
    "rtx",
    "rtx_dropped",
    "qdrops",
    "pli",
    "keyframes",
    "unusable",
    "gaps",
    "discards",
    "cb",
    "cb_audio",
    "disc",
    "pc_failed",
    "audio_share",
    "audio_back",
    "audio_tail",
    "end",
    "disc_time",
    "disc_max",
    "disc_open",
    "stun_lost",
    "low",
    "mean10",
    "back_low",
    "back_mean",
    "to1000",
    "startup",
];

/// What stands for "it never happened" in a figure that is a time until something.
const NEVER: f64 = 99.0;

/// A picture this young is a new picture to the viewer.
const FRESH: Duration = Duration::from_secs(1);

/// The share of the target before the drop that [`NAMES`]' `recover` waits for.
const RECOVERED_SHARE: f64 = 0.4;

/// The rate [`NAMES`]' `to1000` waits for after the capacity's return, bit/s.
const RECOVERED_RATE: u32 = 1_000_000;

/// The rate [`NAMES`]' `startup` waits for from the start of the call: within 5 % of the
/// maximum the chains are given (a target that follows the estimate less a reserve for
/// retransmissions still counts as there).
const STARTED_RATE: u32 = MAX_BPS / 100 * 95;

#[derive(Clone, Debug, PartialEq)]
struct Figures([f64; NAMES.len()]);

impl Figures {
    fn get(&self, name: &str) -> f64 {
        match NAMES.iter().position(|known| *known == name) {
            Some(i) => self.0[i],
            None => panic!("no figure is called {name}"),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum Scenario {
    /// The capacity drops to 300 kbit/s and comes back.
    Cap,
    /// The same, and the capacity stays down for 60 s ([`LONG_CAP_HELD`]).
    LongCap,
    /// The path is gone for 4 s and comes back with an ICE restart.
    Outage,
    /// The capacity does not change: none of the callee's RTCP (the feedback about the
    /// caller's media) arrives for 300 ms.
    FeedbackGap,
}

/// Everything of a run but its seed (the module's "Cells").
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
struct Cell {
    scenario: Scenario,
    chain: Chain,
    /// The receiver's bound on a gap in ms; 0 for none.
    gap_ms: u64,
    /// Both directions capped, or the caller's uplink alone.
    both: bool,
    queue_ms: u64,
    reverse_loss: u32,
}

impl Cell {
    fn parse(name: &str) -> Result<Self> {
        let parts: Vec<&str> = name.split('/').collect();
        let [scenario, chain, gap, direction, queue, loss] = parts[..] else {
            bail!("a cell is scenario/chain/gapN/direction/qN/rlN, not {name}");
        };
        let number = |text: &str, prefix: &str| -> Result<u64> {
            text.strip_prefix(prefix)
                .and_then(|digits| digits.parse().ok())
                .ok_or_else(|| anyhow!("{text} in {name} is not {prefix}N"))
        };
        Ok(Self {
            scenario: match scenario {
                "cap" => Scenario::Cap,
                "cap60" => Scenario::LongCap,
                "outage" => Scenario::Outage,
                "fbgap" => Scenario::FeedbackGap,
                other => bail!("unknown scenario {other} in {name}"),
            },
            chain: match chain {
                "paced" => Chain::Default,
                "nopacer" => Chain::DefaultWithoutPacer,
                "parolnet" => Chain::ParolNet,
                other => bail!("unknown chain {other} in {name}"),
            },
            gap_ms: number(gap, "gap")?,
            both: match direction {
                "up" => false,
                "both" => true,
                other => bail!("unknown direction {other} in {name}"),
            },
            queue_ms: number(queue, "q")?,
            reverse_loss: number(loss, "rl")? as u32,
        })
    }

    fn name(&self) -> String {
        format!(
            "{}/{}/gap{}/{}/q{}/rl{}",
            match self.scenario {
                Scenario::Cap => "cap",
                Scenario::LongCap => "cap60",
                Scenario::Outage => "outage",
                Scenario::FeedbackGap => "fbgap",
            },
            match self.chain {
                Chain::Default => "paced",
                Chain::DefaultWithoutPacer => "nopacer",
                Chain::ParolNet => "parolnet",
            },
            self.gap_ms,
            if self.both { "both" } else { "up" },
            self.queue_ms,
            self.reverse_loss,
        )
    }

    fn setup(&self, seed: u64) -> Setup {
        let setup = Setup::new(seed, None)
            .chain(self.chain)
            .anchor(ANCHORS[0])
            .reverse_loss(self.reverse_loss);
        match self.gap_ms {
            0 => setup,
            ms => setup.gap_wait(Duration::from_millis(ms)),
        }
    }
}

/// The phases of the cap against the 33.3 ms frame clock, in ms after the call's 20th second.
const PHASES_MS: [u64; 3] = [0, 11, 23];

/// The phase a seed is run at: a third of the seeds each.
fn phase_of(seed: u64) -> u64 {
    PHASES_MS[(seed % 3) as usize]
}

/// How long the call is open before the drop, the cap stays after the sender reacted, and
/// the call goes on after the capacity is back.
const OPEN_BEFORE: Duration = Duration::from_secs(20);
const CAP_HELD: Duration = Duration::from_secs(20);
const LONG_CAP_HELD: Duration = Duration::from_secs(60);
const OPEN_AFTER: Duration = Duration::from_secs(25);
const OUTAGE: Duration = Duration::from_secs(4);
const FEEDBACK_GAP: Duration = Duration::from_millis(300);

/// One run of `cell`: its figures.
fn run_cell(cell: Cell, seed: u64, phase_ms: u64) -> Result<Figures> {
    let mut world = World::connected(&cell.setup(seed))?;
    // A peer connection that fails is a figure of the run (`pc_failed`), not its end.
    world.tolerate_failure = true;
    let t = world.now + OPEN_BEFORE + Duration::from_millis(phase_ms);
    world.advance(t)?;
    let before = target_at(&world.peers[0].targets, world.elapsed());
    let dropped_at = world.elapsed();
    let (reacted, under, back_at) = match cell.scenario {
        Scenario::Cap | Scenario::LongCap => {
            let held = match cell.scenario {
                Scenario::LongCap => LONG_CAP_HELD,
                _ => CAP_HELD,
            };
            let capped = LinkProfile {
                delay: Duration::from_millis(30),
                rate_bps: Some(300_000),
                queue: Duration::from_millis(cell.queue_ms),
            };
            world.uplinks[0].set_profile(capped);
            if cell.both {
                world.uplinks[1].set_profile(capped);
            }
            let mut reacted = None;
            while world.elapsed() < dropped_at + Duration::from_secs(5) {
                if target_at(&world.peers[0].targets, world.elapsed()) < 400_000 {
                    reacted = Some(world.elapsed() - dropped_at);
                    break;
                }
                let t = world.now + Duration::from_millis(10);
                world.advance(t)?;
            }
            let t = world.now + held;
            world.advance(t)?;
            let mut samples = Vec::new();
            let mut at = dropped_at + Duration::from_secs(8);
            while at <= world.elapsed() {
                samples.push(target_at(&world.peers[0].targets, at));
                at += Duration::from_millis(100);
            }
            samples.sort_unstable();
            let under = samples[samples.len() / 2];
            world.uplinks[0].set_profile(LinkProfile::open());
            if cell.both {
                world.uplinks[1].set_profile(LinkProfile::open());
            }
            (reacted, under, world.elapsed())
        }
        Scenario::FeedbackGap => {
            world.feedback_outage_until = Some(world.now + FEEDBACK_GAP);
            let t = world.now + CAP_HELD;
            world.advance(t)?;
            let under = target_at(&world.peers[0].targets, world.elapsed());
            (None, under, world.elapsed())
        }
        Scenario::Outage => {
            // As `path_change_run` of capacity_cap_video_rtc2rtc.rs: nothing arrives either
            // way, then an ICE restart whose checks arrive while the media path still does
            // not, until the caller has selected the new pair.
            for peer in world.peers.iter_mut() {
                peer.pair_changes.clear();
            }
            world.blackhole = true;
            let t = world.now + OUTAGE;
            world.advance(t)?;
            world.blackhole = false;
            world.stun_only = true;
            world.restart_ice()?;
            let restarted_at = world.elapsed();
            while world.peers[0].pair_changes.is_empty() {
                if world.elapsed() > restarted_at + Duration::from_secs(10) {
                    bail!("the restart selected no pair");
                }
                let t = world.now + Duration::from_millis(10);
                world.advance(t)?;
            }
            world.stun_only = false;
            let switched_at = world.peers[0].pair_changes[0].0;
            (Some(switched_at - restarted_at), 0, world.elapsed())
        }
    };
    let t = world.now + OPEN_AFTER;
    world.advance(t)?;
    let end = world.elapsed();
    if std::env::var_os("RTC_INSTR_TRACE").is_some() {
        for line in &world.trace {
            println!("ITRACE {} seed {seed} {line}", cell.name());
        }
    }
    let caller = &world.peers[0];
    let callee = &world.peers[1];
    let (caller_out, caller_longest, caller_open) = disconnects(&caller.states, end);
    let (callee_out, callee_longest, callee_open) = disconnects(&callee.states, end);
    let after = dropped_at + Duration::from_secs(5);
    let ten = dropped_at + Duration::from_secs(10);
    let frames = screen(callee);
    let fresh = fresh_times(&frames, FRESH);
    let seconds = |d: Duration| d.as_secs_f64();
    let or_never = |d: Option<Duration>| d.map_or(NEVER, seconds);
    let window: Vec<u64> = (150..=250u64)
        .map(|tenths| {
            u64::from(target_at(
                &caller.targets,
                back_at + Duration::from_millis(tenths * 100),
            ))
        })
        .collect();
    let sound = audio(&callee.audio_arrivals, dropped_at, end);
    // Every flow of either peer the circuit breaker ceased. A peer's audio SSRC is its base
    // (0x1000_0000, 0x2000_0000), its video the next and the retransmissions the one after.
    let ceased: Vec<u32> = world
        .peers
        .iter()
        .flat_map(|peer| peer.breaker_ceased())
        .collect();
    let link = &world.uplinks[0];
    let level = (f64::from(before) * RECOVERED_SHARE) as u32;
    let figures = [
        seconds(max_age(&frames, dropped_at, end)),
        seconds(age_quantile(&frames, 0.5, dropped_at, back_at)),
        seconds(age_quantile(&frames, 0.95, dropped_at, back_at)),
        seconds(stale(&frames, Duration::from_secs(1), dropped_at, end)),
        seconds(stale(&frames, Duration::from_secs(2), dropped_at, end)),
        seconds(longest_gap(&fresh, dropped_at, end).0),
        seconds(longest_gap(&callee.usable_at, Duration::from_secs(2), end).0),
        seconds(end.saturating_sub(fresh.last().copied().unwrap_or_default())),
        or_never(
            fresh
                .iter()
                .find(|at| **at >= back_at)
                .map(|at| *at - back_at),
        ),
        last_older_than(&frames, Duration::from_millis(500), back_at, end)
            .map_or(0.0, |at| seconds(at - back_at)),
        seconds(sound.gap),
        sound.lost as f64,
        seconds(sound.delay),
        or_never(recovered_after(&caller.targets, level, back_at, end)),
        f64::from(before / 1000),
        or_never(reacted),
        f64::from(under / 1000),
        (window.iter().sum::<u64>() / window.len() as u64 / 1000) as f64,
        seconds(paused(&caller.targets, dropped_at, end)),
        link.rtx_sent as f64,
        link.rtx_dropped as f64,
        link.queue_drops as f64,
        callee.keyframe_requests.len() as f64,
        caller.keyframes_sent.len() as f64,
        callee.unusable as f64,
        callee.builder.skipped_gaps() as f64,
        caller.pacer_discards.len() as f64,
        ceased.len() as f64,
        ceased.iter().filter(|ssrc| *ssrc & 0xf == 0).count() as f64,
        f64::from(caller.left_connected + callee.left_connected),
        f64::from(u8::from(caller.failed || callee.failed)),
        sound.share,
        audio(&caller.audio_arrivals, dropped_at, end).share,
        seconds(sound.tail),
        seconds(end),
        seconds(caller_out + callee_out),
        seconds(caller_longest.max(callee_longest)),
        f64::from(caller_open + callee_open),
        f64::from(world.stun_lost),
        f64::from(lowest(&caller.targets, dropped_at, after) / 1000),
        f64::from(mean_target(&caller.targets, dropped_at, ten) / 1000),
        f64::from(lowest(&callee.targets, dropped_at, after) / 1000),
        f64::from(mean_target(&callee.targets, dropped_at, ten) / 1000),
        or_never(recovered_after(
            &caller.targets,
            RECOVERED_RATE,
            back_at,
            end,
        )),
        or_never(reached_by(&caller.targets, STARTED_RATE, dropped_at)),
    ];
    Ok(Figures(figures))
}

/// A run of the ensemble: its figures, or why it did not complete.
#[derive(Clone, Debug)]
struct Row {
    cell: Cell,
    seed: u64,
    phase_ms: u64,
    figures: Result<Figures, String>,
    /// How long the run took on this machine (never printed in the row: not a figure).
    took: Duration,
}

impl Row {
    /// The figure `name`; `None` for a run that did not complete.
    fn value(&self, name: &str) -> Option<f64> {
        self.figures.as_ref().ok().map(|figures| figures.get(name))
    }

    /// The line `scripts/capacity-instrument.py` reads.
    fn line(&self) -> String {
        let mut line = format!(
            "IROW cell={} seed={} phase={}",
            self.cell.name(),
            self.seed,
            self.phase_ms
        );
        match &self.figures {
            Ok(figures) => {
                for (name, value) in NAMES.iter().zip(figures.0) {
                    line.push_str(&format!(" {name}={value:.3}"));
                }
            }
            Err(error) => line.push_str(&format!(" failed={}", error.replace(' ', "_"))),
        }
        line
    }
}

/// How many runs go side by side: `RTC_INSTR_THREADS`, or the machine's parallelism.
fn threads() -> usize {
    std::env::var("RTC_INSTR_THREADS")
        .ok()
        .and_then(|threads| threads.parse().ok())
        .unwrap_or_else(|| std::thread::available_parallelism().map_or(1, |n| n.get()))
        .max(1)
}

/// Every job's row, in the jobs' order; each printed as it ends when `print`.
fn run_rows(jobs: &[(Cell, u64, u64)], print: bool) -> Vec<Row> {
    let next = AtomicUsize::new(0);
    let rows: Mutex<Vec<Option<Row>>> = Mutex::new(vec![None; jobs.len()]);
    std::thread::scope(|scope| {
        for _ in 0..threads().min(jobs.len().max(1)) {
            scope.spawn(|| {
                loop {
                    let i = next.fetch_add(1, Ordering::Relaxed);
                    let Some(&(cell, seed, phase_ms)) = jobs.get(i) else {
                        break;
                    };
                    let started = std::time::Instant::now();
                    let figures = run_cell(cell, seed, phase_ms).map_err(|error| error.to_string());
                    let row = Row {
                        cell,
                        seed,
                        phase_ms,
                        figures,
                        took: started.elapsed(),
                    };
                    if print {
                        println!("{}", row.line());
                    }
                    if let Ok(mut rows) = rows.lock() {
                        rows[i] = Some(row);
                    }
                }
            });
        }
    });
    let rows = rows
        .into_inner()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    rows.into_iter().flatten().collect()
}

/// `runs` runs of `cell` on the seeds after `seed_base`, each at its seed's phase.
fn rows_of(cell: &str, seed_base: u64, runs: usize) -> Result<Vec<Row>> {
    let cell = Cell::parse(cell)?;
    let jobs: Vec<_> = (1..=runs as u64)
        .map(|i| (cell, seed_base + i, phase_of(seed_base + i)))
        .collect();
    Ok(run_rows(&jobs, false))
}

// ---------------------------------------------------------------------------------------------
// Statistics
// ---------------------------------------------------------------------------------------------

/// The probability that a binomial(`n`, `p`) variable is at most `k`.
fn binomial_cdf(n: usize, k: usize, p: f64) -> f64 {
    if p <= 0.0 || k >= n {
        return 1.0;
    }
    if p >= 1.0 {
        return 0.0;
    }
    let ln_factorial: Vec<f64> = std::iter::once(0.0)
        .chain((1..=n).scan(0.0, |sum, i| {
            *sum += (i as f64).ln();
            Some(*sum)
        }))
        .collect();
    (0..=k)
        .map(|i| {
            (ln_factorial[n] - ln_factorial[i] - ln_factorial[n - i]
                + i as f64 * p.ln()
                + (n - i) as f64 * (1.0 - p).ln())
            .exp()
        })
        .sum::<f64>()
        .min(1.0)
}

/// The critical value: the least count `c` such that `n` runs of which each is beyond with
/// probability `p` have at most `c` beyond with probability at least `1 - alpha`. A count above
/// it rejects "the share is `p` or less" at level `alpha`.
fn critical(n: usize, p: f64, alpha: f64) -> usize {
    (0..=n)
        .find(|c| binomial_cdf(n, *c, p) >= 1.0 - alpha)
        .unwrap_or(n)
}

/// The upper end of the Wilson score interval of `k` of `n` at `z` standard deviations.
fn wilson_upper(k: u64, n: u64, z: f64) -> f64 {
    if n == 0 {
        return 1.0;
    }
    let (k, n) = (k as f64, n as f64);
    let p = k / n;
    let denominator = 1.0 + z * z / n;
    let centre = (p + z * z / (2.0 * n)) / denominator;
    let half = z * (p * (1.0 - p) / n + z * z / (4.0 * n * n)).sqrt() / denominator;
    (centre + half).min(1.0)
}

/// The value at the share `q` of `values` (linear between ranks), for the tables.
fn quantile(values: &[f64], q: f64) -> f64 {
    let mut sorted = values.to_vec();
    sorted.sort_by(f64::total_cmp);
    if sorted.is_empty() {
        return f64::NAN;
    }
    let rank = (sorted.len() - 1) as f64 * q;
    let (low, high) = (rank.floor() as usize, rank.ceil() as usize);
    sorted[low] + (sorted[high] - sorted[low]) * (rank - low as f64)
}

/// The figures a table shows.
const TABLE: [&str; 15] = [
    "max_age",
    "stale1",
    "stale2",
    "fresh_gap",
    "freeze",
    "tail_gap",
    "resume",
    "audio_gap",
    "audio_share",
    "audio_lost",
    "recover",
    "to1000",
    "startup",
    "under",
    "rtx",
];

/// A cell's rows as a table: each figure's 10th, 50th and 90th percentile and maximum.
fn table(cell: &str, rows: &[Row]) -> String {
    let completed = rows.iter().filter(|row| row.figures.is_ok()).count();
    let count = |name: &str| {
        rows.iter()
            .filter(|row| row.value(name).is_some_and(|value| value > 0.0))
            .count()
    };
    let took: Duration = rows.iter().map(|row| row.took).sum();
    let mut text = format!(
        "{cell}: {} runs, {} did not complete; the circuit breaker ceased a flow in {} (audio \
         in {}), a peer left Connected in {} (failed in {}); {:.2} s of one core a run\n  \
         figure        p10     p50     p90     max\n",
        rows.len(),
        rows.len() - completed,
        count("cb"),
        count("cb_audio"),
        count("disc"),
        count("pc_failed"),
        took.as_secs_f64() / rows.len().max(1) as f64,
    );
    for name in TABLE {
        let values: Vec<f64> = rows.iter().filter_map(|row| row.value(name)).collect();
        text.push_str(&format!(
            "  {name:10} {:7.2} {:7.2} {:7.2} {:7.2}\n",
            quantile(&values, 0.1),
            quantile(&values, 0.5),
            quantile(&values, 0.9),
            quantile(&values, 1.0),
        ));
    }
    for row in rows {
        if let Err(error) = &row.figures {
            text.push_str(&format!("  seed {} did not complete: {error}\n", row.seed));
        }
    }
    text
}

// ---------------------------------------------------------------------------------------------
// Requirements
// ---------------------------------------------------------------------------------------------

/// What the call's user is owed: in at most [`REQUIRED_SHARE`] of calls is `figure` over
/// `limit`.
struct Requirement {
    claim: &'static str,
    figure: &'static str,
    limit: f64,
}

/// The share of calls a requirement may be violated in.
const REQUIRED_SHARE: f64 = 0.05;
/// The level of a requirement's test: a tree whose true share is exactly [`REQUIRED_SHARE`]
/// fails with at most this probability.
const REQUIREMENT_ALPHA: f64 = 0.05;
/// The runs a requirement is tested on (the module's power calculation).
const REQUIREMENT_RUNS: usize = 300;

/// THE requirement, restated on what is on the screen ("no freeze over 2 s" counted any frame
/// that came out of the decoder, however old).
const PICTURE: Requirement = Requirement {
    claim: "the screen shows a picture older than 2 s for no more than 0.5 s in all",
    figure: "stale2",
    limit: 0.5,
};

/// The requirement as it was stated until this instrument, kept as the secondary figure.
const FREEZE: Requirement = Requirement {
    claim: "never more than 2 s without a new picture of any age",
    figure: "freeze",
    limit: 2.0,
};

const AUDIO: Requirement = Requirement {
    claim: "never more than 1 s without audio",
    figure: "audio_gap",
    limit: 1.0,
};

/// After an outage: once the path is back (the new pair selected), a new picture within 2 s.
const RESUME: Requirement = Requirement {
    claim: "a new picture within 2 s of the path's return",
    figure: "resume",
    limit: 2.0,
};

impl Requirement {
    /// How many of `rows` violate it (a run that did not complete does).
    fn violators(&self, rows: &[Row]) -> usize {
        rows.iter()
            .filter(|row| {
                row.value(self.figure)
                    .is_none_or(|value| value > self.limit)
            })
            .count()
    }

    /// Fails the test unless `rows` are consistent with the requirement being met.
    fn assert_met(&self, cell: &str, rows: &[Row]) {
        let violators = self.violators(rows);
        let allowed = critical(rows.len(), REQUIRED_SHARE, REQUIREMENT_ALPHA);
        println!("{}", table(cell, rows));
        assert!(
            violators <= allowed,
            "REQUIREMENT not met in {cell}: {} ({} > {}) in {violators} of {} runs ({:.1} %); \
             at most {allowed} are consistent with the required {:.0} % of calls\n{}",
            self.claim,
            self.figure,
            self.limit,
            rows.len(),
            violators as f64 * 100.0 / rows.len() as f64,
            REQUIRED_SHARE * 100.0,
            table(cell, rows),
        );
    }

    /// Runs `cell` on [`REQUIREMENT_RUNS`] seeds and asserts the requirement.
    fn test(&self, cell: &str) -> Result<()> {
        self.assert_met(cell, &rows_of(cell, PR_SEED_BASE, REQUIREMENT_RUNS)?);
        Ok(())
    }
}

// ---------------------------------------------------------------------------------------------
// Tripwires
// ---------------------------------------------------------------------------------------------

/// The level of one tripwire: an unchanged tree's fresh draw fails it with at most this
/// probability.
const TRIPWIRE_ALPHA: f64 = 0.002;

/// One line of the baseline: of `runs` runs of `cell` on the baseline tree, `beyond` had
/// `figure` over (`high`) or under `threshold` or did not complete.
#[derive(Debug)]
struct Tripwire {
    cell: String,
    figure: String,
    high: bool,
    threshold: f64,
    beyond: u64,
    runs: u64,
    /// What the threshold is: `p50`, `p90`, `p10` of the baseline, or `limit`.
    level: String,
}

/// The recorded baseline (the module's "A TRIPWIRE").
fn baseline() -> Result<Vec<Tripwire>> {
    let mut tripwires = Vec::new();
    for line in include_str!("fixtures/capacity-instrument-baseline.tsv").lines() {
        if line.starts_with('#') || line.trim().is_empty() || line.starts_with("cell\t") {
            continue;
        }
        let fields: Vec<&str> = line.split('\t').collect();
        let [cell, figure, direction, threshold, beyond, runs, level] = fields[..] else {
            bail!("a baseline line has seven fields: {line}");
        };
        tripwires.push(Tripwire {
            cell: cell.to_owned(),
            figure: figure.to_owned(),
            high: match direction {
                "hi" => true,
                "lo" => false,
                other => bail!("direction {other} in: {line}"),
            },
            threshold: threshold.parse()?,
            beyond: beyond.parse()?,
            runs: runs.parse()?,
            level: level.to_owned(),
        });
    }
    Ok(tripwires)
}

impl Tripwire {
    /// How many of `rows` are beyond the threshold.
    fn beyond(&self, rows: &[Row]) -> usize {
        rows.iter()
            .filter(|row| {
                row.value(&self.figure).is_none_or(|value| {
                    if self.high {
                        value > self.threshold
                    } else {
                        value < self.threshold
                    }
                })
            })
            .count()
    }

    /// The most of `n` runs that may be beyond it: the critical value at [`TRIPWIRE_ALPHA`]
    /// for the upper end of the baseline share's 95 % Wilson interval.
    fn allowed(&self, n: usize) -> usize {
        critical(
            n,
            wilson_upper(self.beyond, self.runs, 1.96),
            TRIPWIRE_ALPHA,
        )
    }
}

// ---------------------------------------------------------------------------------------------
// The pull-request ensemble
// ---------------------------------------------------------------------------------------------

/// The seeds of the pull-request ensemble and of the requirement tests start after this one;
/// the baseline is measured on seeds 1 to 1000, so these are a fresh draw.
const PR_SEED_BASE: u64 = 5000;

/// The cells every pull request runs, and how many runs of each: the reference cell and the
/// receiver without a bound in both chains, then one dimension at a time from the reference
/// (both directions, the queue's depth, loss on the reverse path) and the outage. The whole
/// cross is `measure`'s and the dispatched comparison's.
const PR_CELLS: [(&str, usize); 13] = [
    ("cap/paced/gap300/up/q300/rl0", 60),
    ("cap/paced/gap0/up/q300/rl0", 40),
    ("cap/nopacer/gap300/up/q300/rl0", 40),
    ("cap/nopacer/gap0/up/q300/rl0", 20),
    ("cap/paced/gap300/both/q300/rl0", 30),
    ("cap/nopacer/gap300/both/q300/rl0", 20),
    ("cap/paced/gap300/up/q100/rl0", 12),
    ("cap/paced/gap300/up/q1000/rl0", 12),
    ("cap/paced/gap300/up/q300/rl5", 12),
    ("outage/paced/gap300/up/q300/rl0", 20),
    (MET_OUTAGE, 20),
    ("cap/parolnet/gap0/up/q300/rl0", 20),
    // The cell the requirements are met in: the runs their tests need.
    (MET_CAP, REQUIREMENT_RUNS),
];

/// The cells in which the engine meets requirements today: the capacity drop in ParolNet's
/// chain (no pacer, the TWCC-driven estimator) with the reference receiver, asserted on every
/// pull request, and the outage in the default chain without the pacer, asserted on demand
/// (300 more runs would not fit the pull-request job; its tripwires hold it meanwhile).
const MET_CAP: &str = "cap/parolnet/gap300/up/q300/rl0";
const MET_OUTAGE: &str = "outage/nopacer/gap300/up/q300/rl0";

/// The default chain's cells, where the requirements are known limits.
const DEFAULT_CHAIN: &str = "cap/paced/gap300/up/q300/rl0";
const DEFAULT_CHAIN_NO_BOUND: &str = "cap/paced/gap0/up/q300/rl0";
const WITHOUT_PACER: &str = "cap/nopacer/gap300/up/q300/rl0";
const BOTH_DIRECTIONS: &str = "cap/paced/gap300/both/q300/rl0";
const OUTAGE_DEFAULT_CHAIN: &str = "outage/paced/gap300/up/q300/rl0";

/// The rows of `cell` in the pull-request ensemble.
fn pr_rows(cell: &str) -> Result<&'static [Row]> {
    pr_ensemble()
        .get(cell)
        .map(Vec::as_slice)
        .ok_or_else(|| anyhow!("{cell} is not in the pull-request ensemble"))
}

// Requirements the engine meets: asserted on every pull request, 300 runs each cell.

#[test]
#[ignore = "release ensemble: the capacity-instrument job runs it (cargo test --release -- --ignored ensemble_)"]
fn ensemble_requirement_picture_in_parolnets_chain() -> Result<()> {
    PICTURE.assert_met(MET_CAP, pr_rows(MET_CAP)?);
    Ok(())
}

#[test]
#[ignore = "release ensemble: the capacity-instrument job runs it (cargo test --release -- --ignored ensemble_)"]
fn ensemble_requirement_freeze_in_parolnets_chain() -> Result<()> {
    FREEZE.assert_met(MET_CAP, pr_rows(MET_CAP)?);
    Ok(())
}

#[test]
#[ignore = "release ensemble: the capacity-instrument job runs it (cargo test --release -- --ignored ensemble_)"]
fn ensemble_requirement_audio_in_parolnets_chain() -> Result<()> {
    AUDIO.assert_met(MET_CAP, pr_rows(MET_CAP)?);
    Ok(())
}

/// THE AUDIO GUARD: in the default chain's two reference cells of the pull-request ensemble
/// (100 runs), no run ends with a flow left ceased by the circuit breaker (`cb`) or with the
/// audio silent (`audio_tail` over 1 s). Not a share: one such run fails it (with 100 runs, a
/// tree in which 3 % of calls end so fails with probability 0.95). `cb` is read at the end of
/// the run: a flow the breaker ceased and restarted reads 0. A requirement since the breaker's
/// rules were corrected (breaker-1): until then it ceased the audio at the drop in 8.9 % of
/// runs and nothing restarted it (this test was `known_limit_…` and failed when run, hosted
/// run 45516189525's kind); with the corrected rules no flow is ceased at any time in these
/// cells (0 of 2000 runs, hosted run 45525698919).
#[test]
#[ignore = "release ensemble: the capacity-instrument job runs it (cargo test --release -- --ignored ensemble_)"]
fn ensemble_requirement_no_flow_is_left_ceased_and_audio_is_alive_at_the_end() -> Result<()> {
    let mut dead = Vec::new();
    for cell in [DEFAULT_CHAIN, DEFAULT_CHAIN_NO_BOUND] {
        for row in pr_rows(cell)? {
            let ceased = row.value("cb").is_none_or(|flows| flows > 0.0);
            let silent = row.value("audio_tail").is_none_or(|tail| tail > 1.0);
            if ceased || silent {
                dead.push(format!(
                    "{cell} seed {}: {} flow(s) ceased, {} of them audio; audio silent for the \
                     last {} s",
                    row.seed,
                    row.value("cb").unwrap_or(f64::NAN),
                    row.value("cb_audio").unwrap_or(f64::NAN),
                    row.value("audio_tail").unwrap_or(f64::NAN),
                ));
            }
        }
    }
    assert!(
        dead.is_empty(),
        "REQUIREMENT not met: no call ends with a flow left ceased or its audio dead; {} \
         run(s) did:\n{}",
        dead.len(),
        dead.join("\n")
    );
    Ok(())
}

/// THE PICTURE GUARD: in the default chain's two reference cells of the pull-request ensemble
/// (100 runs) at most ONE run shows a picture older than 2 s for more than 0.5 s. With the
/// backlog flushed at a collapse (docs/capacity-collapse.md) none does (0 of 2000 runs of
/// these two cells; 2000 of 2000 with the pause). The requirement itself, at most 5 % of
/// calls on 300 runs, is `on_demand_requirement_picture_in_the_default_chain`, which does not
/// fit the job; this is its tripwire: a tree in which 5 % of calls miss passes it with
/// probability 0.037 (0.95^100 + 100 x 0.05 x 0.95^99), one in which none does never fails.
#[test]
#[ignore = "release ensemble: the capacity-instrument job runs it (cargo test --release -- --ignored ensemble_)"]
fn ensemble_tripwire_picture_in_the_default_chain() -> Result<()> {
    const ALLOWED: usize = 1;
    let mut missed = Vec::new();
    for cell in [DEFAULT_CHAIN, DEFAULT_CHAIN_NO_BOUND] {
        for row in pr_rows(cell)? {
            if row
                .value(PICTURE.figure)
                .is_none_or(|stale| stale > PICTURE.limit)
            {
                missed.push(format!(
                    "{cell} seed {}: a picture older than 2 s for {} s",
                    row.seed,
                    row.value(PICTURE.figure).unwrap_or(f64::NAN),
                ));
            }
        }
    }
    assert!(
        missed.len() <= ALLOWED,
        "TRIPWIRE: {} of the default chain's runs miss the picture requirement ({}), at most \
         {ALLOWED} allowed:\n{}",
        missed.len(),
        PICTURE.claim,
        missed.join("\n")
    );
    Ok(())
}

/// The 1 s audio requirement in the default chain: met since breaker-1 (0 of 1000 runs with
/// more than 1 s without audio, hosted run 45525698919; 89 of 1000 before). On 300 runs, on
/// demand: the reference cell has 60 runs in the pull-request ensemble, where
/// `ensemble_requirement_no_flow_is_left_ceased_and_audio_is_alive_at_the_end` guards it.
#[test]
#[ignore = "release ensemble on demand, 300 runs: cargo test --release -- --ignored on_demand_"]
fn on_demand_requirement_audio_in_the_default_chain() -> Result<()> {
    AUDIO.test(DEFAULT_CHAIN)
}

#[test]
#[ignore = "release ensemble on demand, 300 runs: cargo test --release -- --ignored on_demand_"]
fn on_demand_requirement_resume_after_an_outage_without_the_pacer() -> Result<()> {
    RESUME.test(MET_OUTAGE)
}

// At the bound: without the pacer the picture and freeze requirements are violated in 7.0 %
// and 5.5 % of 200 runs on master (intervals 4.2 to 11.4 % and 3.1 to 9.6 %), and their tests
// passed on the 300 runs of seeds 5001 on (hosted run 45516189525). A share at the bound passes
// on one draw and fails on the next, so neither "met" nor "known limit" can be claimed and
// neither is asserted on pull requests; the cell's tripwires hold its level.

#[test]
#[ignore = "AT THE BOUND, on demand: 4 of 200 runs on master 0ca11557 (14 before the repairs stopped repeating), required at most 5 %; passes or fails by the draw"]
fn on_demand_requirement_picture_without_the_pacer() -> Result<()> {
    PICTURE.test(WITHOUT_PACER)
}

#[test]
#[ignore = "AT THE BOUND, on demand: 2 of 200 runs on master 0ca11557 (11 before the repairs stopped repeating), required at most 5 %; passes or fails by the draw"]
fn on_demand_requirement_freeze_without_the_pacer() -> Result<()> {
    FREEZE.test(WITHOUT_PACER)
}

// Requirements the engine does NOT meet today. Not loosened: each test states the requirement
// and fails when run (`-- --ignored known_limit_`), the attribute carries the share measured
// on master, CHANGELOG "Known limits" tracks it, and the tripwires of the cell hold today's
// level. When the engine meets one, its test moves up among the `ensemble_requirement_` ones.

/// The picture requirement in the default chain: met since the pacer flushes its backlog at a
/// collapse (docs/capacity-collapse.md): 0 of 200 runs, oldest picture 1.33 s in the median
/// (200 of 200 and 7.9 s with the pause). On 300 runs, on demand; the reference cell's
/// tripwires hold it on every pull request.
#[test]
#[ignore = "release ensemble on demand, 300 runs: cargo test --release -- --ignored on_demand_"]
fn on_demand_requirement_picture_in_the_default_chain() -> Result<()> {
    PICTURE.test(DEFAULT_CHAIN)
}

/// Met with the flush as well: 0 of 200 runs with more than 2 s without a picture.
#[test]
#[ignore = "release ensemble on demand, 300 runs: cargo test --release -- --ignored on_demand_"]
fn on_demand_requirement_freeze_in_the_default_chain() -> Result<()> {
    FREEZE.test(DEFAULT_CHAIN)
}

/// Met with the flush and the builder's key-frame release: 0 of 200 runs, 1.33 s in the median.
#[test]
#[ignore = "release ensemble on demand, 300 runs: cargo test --release -- --ignored on_demand_"]
fn on_demand_requirement_picture_in_the_default_chain_with_a_receiver_without_a_bound() -> Result<()>
{
    PICTURE.test(DEFAULT_CHAIN_NO_BOUND)
}

/// The requirement as `capacity_cap_video_rtc2rtc.rs` stated it, on that test's receiver:
/// met since the repairs stopped repeating (`conf/rtx-1r2-duplicate-repairs`: 272 of 1000 runs
/// over 2 s before it, 15 after). The picture on the screen is 7.2 s old all the same.
#[test]
#[ignore = "release ensemble on demand, 300 runs: cargo test --release -- --ignored on_demand_"]
fn on_demand_requirement_freeze_in_the_default_chain_with_a_receiver_without_a_bound() -> Result<()>
{
    FREEZE.test(DEFAULT_CHAIN_NO_BOUND)
}

#[test]
#[ignore = "KNOWN LIMIT: a picture older than 2 s is on the screen for more than 0.5 s in 119 of 200 runs with the backlog flushed (200 of 200 before; required: at most 5 %); 2.6 s in the median: the estimate falls only by the missing-feedback rule (docs/capacity-collapse.md)"]
fn known_limit_picture_with_both_directions_capped() -> Result<()> {
    PICTURE.test(BOTH_DIRECTIONS)
}

/// Met with the flush for the bounded receiver: 0 of 200 runs (134 with the pause).
#[test]
#[ignore = "release ensemble on demand, 300 runs: cargo test --release -- --ignored on_demand_"]
fn on_demand_requirement_resume_after_an_outage_in_the_default_chain() -> Result<()> {
    RESUME.test(OUTAGE_DEFAULT_CHAIN)
}

/// The pull-request ensemble's rows by cell, run once for all the tests that read it.
fn pr_ensemble() -> &'static BTreeMap<&'static str, Vec<Row>> {
    static ENSEMBLE: OnceLock<BTreeMap<&'static str, Vec<Row>>> = OnceLock::new();
    ENSEMBLE.get_or_init(|| {
        let mut jobs = Vec::new();
        let mut cells = Vec::new();
        for (name, runs) in PR_CELLS {
            let cell = match Cell::parse(name) {
                Ok(cell) => cell,
                Err(error) => panic!("{error}"),
            };
            cells.push((name, cell));
            for i in 1..=runs as u64 {
                jobs.push((cell, PR_SEED_BASE + i, phase_of(PR_SEED_BASE + i)));
            }
        }
        let rows = run_rows(&jobs, false);
        cells
            .into_iter()
            .map(|(name, cell)| {
                let of_cell = rows
                    .iter()
                    .filter(|row| row.cell == cell)
                    .cloned()
                    .collect();
                (name, of_cell)
            })
            .collect()
    })
}

/// Every tripwire of every cell of the pull-request ensemble, all reported before the test
/// fails. The figures of each cell are printed (`--nocapture`, or on failure).
#[test]
#[ignore = "release ensemble: the capacity-instrument job runs it (cargo test --release -- --ignored ensemble_)"]
fn ensemble_tripwires_hold_in_every_cell() -> Result<()> {
    let tripwires = baseline()?;
    let mut failed = Vec::new();
    for (cell, rows) in pr_ensemble() {
        println!("{}", table(cell, rows));
        let of_cell: Vec<&Tripwire> = tripwires.iter().filter(|t| t.cell == *cell).collect();
        if of_cell.is_empty() {
            failed.push(format!("{cell}: no baseline recorded"));
        }
        for tripwire in of_cell {
            let (beyond, allowed) = (tripwire.beyond(rows), tripwire.allowed(rows.len()));
            let line = format!(
                "{cell}: {} {} {} ({}) in {beyond} of {} runs; baseline {} of {}, at most \
                 {allowed} allowed",
                tripwire.figure,
                if tripwire.high { ">" } else { "<" },
                tripwire.threshold,
                tripwire.level,
                rows.len(),
                tripwire.beyond,
                tripwire.runs,
            );
            println!("  {line}");
            if beyond > allowed {
                failed.push(line);
            }
        }
    }
    assert!(
        failed.is_empty(),
        "TRIPWIRES (a regression against the recorded baseline, see the module's doc):\n{}",
        failed.join("\n")
    );
    Ok(())
}

/// The runs of the ensemble are a function of their seed: the first two of each cell, run
/// again on other threads, give the same figures to the last digit. (The reviewer's ensembles
/// were identical between a release run and a debug run on another machine; this holds the
/// instrument to it within a process, and the job repeats a measurement in a second process.)
#[test]
#[ignore = "release ensemble: the capacity-instrument job runs it (cargo test --release -- --ignored ensemble_)"]
fn ensemble_runs_are_reproducible() -> Result<()> {
    let mut jobs = Vec::new();
    let mut first = Vec::new();
    for rows in pr_ensemble().values() {
        for row in rows.iter().take(2) {
            jobs.push((row.cell, row.seed, row.phase_ms));
            first.push(row.clone());
        }
    }
    let again = run_rows(&jobs, false);
    for (first, again) in first.iter().zip(&again) {
        assert_eq!(first.line(), again.line(), "the same seed gave another run");
    }
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// Measurement
// ---------------------------------------------------------------------------------------------

/// One `IROW` line per run of what the environment names; asserts nothing.
/// `RTC_INSTR_CELLS`: cell names, comma separated (`pr` stands for the cells of [`PR_CELLS`];
/// the reference cell by default). `RTC_INSTR_SEEDS`: `first-last` (1-40). `RTC_INSTR_PHASE`:
/// one phase in ms for every seed, instead of each seed's own. `RTC_INSTR_THREADS`.
/// `RTC_INSTR_TRACE`: the world's 100 ms trace of every run as well.
#[test]
#[ignore = "measurement: run with --ignored --nocapture"]
fn measure() -> Result<()> {
    let names = std::env::var("RTC_INSTR_CELLS").unwrap_or_else(|_| PR_CELLS[0].0.to_owned());
    let mut cells = Vec::new();
    for name in names.split(',').map(str::trim).filter(|n| !n.is_empty()) {
        if name == "pr" {
            for (name, _) in PR_CELLS {
                cells.push(Cell::parse(name)?);
            }
        } else {
            cells.push(Cell::parse(name)?);
        }
    }
    let seeds = std::env::var("RTC_INSTR_SEEDS").unwrap_or_else(|_| "1-40".to_owned());
    let Some((first, last)) = seeds
        .split_once('-')
        .and_then(|(first, last)| Some((first.parse::<u64>().ok()?, last.parse::<u64>().ok()?)))
    else {
        bail!("RTC_INSTR_SEEDS is first-last, not {seeds}");
    };
    let phase: Option<u64> = match std::env::var("RTC_INSTR_PHASE") {
        Ok(phase) => Some(phase.parse()?),
        Err(_) => None,
    };
    let jobs: Vec<_> = cells
        .iter()
        .flat_map(|cell| {
            (first..=last).map(move |seed| (*cell, seed, phase.unwrap_or_else(|| phase_of(seed))))
        })
        .collect();
    let rows = run_rows(&jobs, true);
    for cell in cells {
        let of_cell: Vec<Row> = rows
            .iter()
            .filter(|row| row.cell == cell)
            .cloned()
            .collect();
        println!("{}", table(&cell.name(), &of_cell));
    }
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// The instrument's own tests (debug build, every platform)
// ---------------------------------------------------------------------------------------------

fn ms(ms: u64) -> Duration {
    Duration::from_millis(ms)
}

fn shown(at: u64, captured: u64) -> Shown {
    Shown {
        at: ms(at),
        captured: ms(captured),
    }
}

/// Thirty frames a second, each shown 50 ms after its capture, from `from` to `to` ms.
fn smooth(from: u64, to: u64) -> Vec<Shown> {
    (from..to)
        .step_by(33)
        .map(|at| shown(at, at - 50))
        .collect()
}

#[test]
fn the_age_of_the_picture_is_measured_until_the_next_one_replaces_it() {
    // A smooth picture, then nothing from 10.000 to 13.000 s, then smooth again.
    let mut frames = smooth(50, 10_000);
    let last = *frames.last().unwrap();
    frames.extend(smooth(13_000, 20_000));
    let (from, to) = (ms(5_000), ms(20_000));
    // The frame on the screen through the hole was captured 50 ms before it was shown.
    let oldest = ms(13_000) - last.captured;
    assert_eq!(oldest, max_age(&frames, from, to));
    assert!(oldest > ms(3_050) && oldest < ms(3_090), "{oldest:?}");
    // Older than 1 s from 1 s after that frame's capture until the next picture; never
    // otherwise (a smooth picture is at most 83 ms old).
    assert_eq!(oldest - ms(1_000), stale(&frames, ms(1_000), from, to));
    assert_eq!(oldest - ms(2_000), stale(&frames, ms(2_000), from, to));
    assert_eq!(Duration::ZERO, stale(&frames, ms(4_000), from, to));
    assert_eq!(
        Some(ms(13_000)),
        last_older_than(&frames, ms(500), from, to)
    );
    assert_eq!(None, last_older_than(&frames, ms(4_000), from, to));
    // Outside the window the hole does not count.
    assert!(max_age(&frames, ms(14_000), to) < ms(90));
    assert_eq!(Duration::ZERO, stale(&frames, ms(1_000), ms(14_000), to));
}

#[test]
fn old_frames_coming_out_of_the_buffer_do_not_make_the_picture_new() {
    // What the old "freeze" could not see: after 10 s a frame comes out every 0.6 s, each
    // captured in the second after 10 s (a backlog draining), until 18 s; then live again.
    let mut frames = smooth(50, 10_000);
    for i in 0..13u64 {
        frames.push(shown(10_600 + i * 600, 10_000 + i * 33));
    }
    frames.extend(smooth(18_400, 25_000));
    let (from, to) = (ms(10_000), ms(25_000));
    let times: Vec<Duration> = frames.iter().map(|frame| frame.at).collect();
    // The old figure: never more than 0.6 s (and a bit) without a frame.
    let (freeze, _) = longest_gap(&times, ms(2_000), to);
    assert!(freeze <= ms(650), "{freeze:?}");
    // The screen: the last backlog frame, captured at 10.396 s, is shown until 18.4 s.
    assert_eq!(ms(18_400 - 10_396), max_age(&frames, from, to));
    // No new picture under 1 s old from the last smooth frame (9.983 s) until the first
    // backlog frame, which is 0.6 s old, at 10.6 s; then none until 18.4 s.
    let fresh = fresh_times(&frames, FRESH);
    assert_eq!(ms(18_400 - 10_600), longest_gap(&fresh, from, to).0);
    // Older than 2 s from 12.0 s (the first backlog frame's successors are older still)...
    let stale2 = stale(&frames, ms(2_000), from, to);
    assert!(stale2 > ms(6_000) && stale2 < ms(6_500), "{stale2:?}");
    // ... which is most of the 8.4 s: the median age of that stretch is over 4 s.
    let median = age_quantile(&frames, 0.5, from, ms(18_400));
    assert!(median > ms(4_000) && median < ms(5_000), "{median:?}");
}

#[test]
fn the_age_quantile_is_the_age_not_exceeded_for_that_share_of_the_time() {
    // One picture captured at 0 and shown from 0 to 10 s: its age rises from 0 to 10 s, so
    // the age not exceeded for a share q of the time is q times 10 s.
    let frames = [shown(0, 0)];
    for (q, expected) in [(0.5, 5_000u64), (0.9, 9_000), (0.95, 9_500)] {
        let age = age_quantile(&frames, q, Duration::ZERO, ms(10_000));
        assert!(
            age >= ms(expected) && age <= ms(expected + 1),
            "{q}: {age:?}"
        );
    }
}

#[test]
fn a_screen_that_never_had_a_picture_is_as_old_as_the_call() {
    assert_eq!(ms(7_000), max_age(&[], ms(3_000), ms(7_000)));
    assert_eq!(ms(4_000), stale(&[], ms(1_000), ms(3_000), ms(7_000)));
    let late = [shown(6_000, 5_900)];
    assert_eq!(ms(6_000), max_age(&late, ms(3_000), ms(7_000)));
    assert_eq!(ms(3_000), stale(&late, ms(2_000), ms(3_000), ms(7_000)));
}

#[test]
fn audio_is_measured_by_what_arrived() {
    // A packet every 20 ms arriving 10 ms after it left; 25 packets (0.5 s) lost from
    // number 500 on, and the ten after them held up to 200 ms more by a queue.
    let mut arrivals = Vec::new();
    for seq in 0..1_000u16 {
        let left = u64::from(seq) * 20;
        match seq {
            500..525 => {}
            525..535 => arrivals.push((ms(left + 10 + 200 - u64::from(seq - 525) * 20), seq)),
            _ => arrivals.push((ms(left + 10), seq)),
        }
    }
    let sound = audio(&arrivals, ms(9_000), ms(20_000));
    // 550 packets belong to those 11 s; 525 arrived in them.
    assert_eq!(25, sound.lost);
    assert!((sound.share - 525.0 / 550.0).abs() < 1e-9, "{sound:?}");
    assert_eq!(ms(200), sound.delay);
    // From number 499 (9.990 s) to number 525 (10.500 + 0.010 + 0.200 s).
    assert_eq!(ms(10_710 - 9_990), sound.gap);
    // Before the loss nothing is missing and nothing late.
    let quiet = audio(&arrivals, ms(2_000), ms(9_000));
    assert_eq!(
        (0, 1.0, ms(20), Duration::ZERO),
        (quiet.lost, quiet.share, quiet.gap, quiet.delay)
    );
    // Audio that stops for good (a ceased flow) is lost to the end, and the gap is the rest.
    let dead: Vec<_> = arrivals
        .iter()
        .copied()
        .filter(|(at, _)| *at < ms(10_000))
        .collect();
    let sound = audio(&dead, ms(9_000), ms(20_000));
    assert_eq!((500, ms(20_000 - 9_990)), (sound.lost, sound.gap));
    assert_eq!(ms(20_000 - 9_990), sound.tail);
    assert_eq!(ms(10), audio(&arrivals, ms(9_000), ms(20_000)).tail);
    assert!((sound.share - 50.0 / 550.0).abs() < 1e-9, "{sound:?}");
    // Nothing at all.
    let none = audio(&[], ms(1_000), ms(6_000));
    assert_eq!((250, 0.0, ms(5_000)), (none.lost, none.share, none.gap));
    assert_eq!(ms(6_000), none.tail);
}

#[test]
fn recovery_and_pause_are_read_from_the_target() {
    let targets = [
        (ms(0), 300_000),
        (ms(15_000), 2_500_000),
        (ms(20_500), 150_000),
        (ms(21_000), 0),
        (ms(29_000), 120_000),
        (ms(47_000), 800_000),
        (ms(52_000), 1_100_000),
    ];
    let (lifted, end) = (ms(40_500), ms(65_500));
    assert_eq!(
        Some(ms(11_500)),
        recovered_after(&targets, 1_000_000, lifted, end)
    );
    assert_eq!(None, recovered_after(&targets, 2_000_000, lifted, end));
    assert_eq!(
        Some(Duration::ZERO),
        recovered_after(&targets, 100_000, lifted, end)
    );
    assert_eq!(ms(8_000), paused(&targets, ms(20_000), end));
    assert_eq!(ms(4_000), paused(&targets, ms(25_000), end));
    // The start-up: the first time at the level, from the start of the call, and only when
    // it came before the drop.
    assert_eq!(
        Some(ms(15_000)),
        reached_by(&targets, STARTED_RATE, ms(20_000))
    );
    assert_eq!(None, reached_by(&targets, STARTED_RATE, ms(14_900)));
    assert_eq!(Some(ms(0)), reached_by(&targets, 300_000, ms(20_000)));
    assert_eq!(2_375_000, STARTED_RATE);
}

#[test]
fn a_cell_has_one_name() -> Result<()> {
    for (name, _) in PR_CELLS {
        assert_eq!(name, Cell::parse(name)?.name());
    }
    let cell = Cell::parse("cap/nopacer/gap0/both/q1000/rl5")?;
    assert_eq!(
        (Chain::DefaultWithoutPacer, 0, true, 1000, 5),
        (
            cell.chain,
            cell.gap_ms,
            cell.both,
            cell.queue_ms,
            cell.reverse_loss
        )
    );
    let gap = "fbgap/paced/gap300/up/q300/rl0";
    assert_eq!(gap, Cell::parse(gap)?.name());
    assert_eq!(Scenario::FeedbackGap, Cell::parse(gap)?.scenario);
    let long = "cap60/parolnet/gap300/up/q300/rl0";
    assert_eq!(long, Cell::parse(long)?.name());
    assert_eq!(Scenario::LongCap, Cell::parse(long)?.scenario);
    assert!(Cell::parse("cap/paced/gap300/up/q300").is_err());
    assert!(Cell::parse("cap/paced/wait300/up/q300/rl0").is_err());
    // A third of the seeds at each phase.
    for phase in PHASES_MS {
        assert_eq!(
            100,
            (1..=300).filter(|seed| phase_of(*seed) == phase).count()
        );
    }
    Ok(())
}

/// The power calculation of the module's doc, held: with [`REQUIREMENT_RUNS`] runs, a tree
/// exactly at the required share passes with at least 0.95, and a tree at twice that share
/// fails with at least 0.95.
#[test]
fn the_requirement_test_has_the_power_it_claims() {
    let allowed = critical(REQUIREMENT_RUNS, REQUIRED_SHARE, REQUIREMENT_ALPHA);
    assert_eq!(21, allowed);
    let passes_at_the_bound = binomial_cdf(REQUIREMENT_RUNS, allowed, REQUIRED_SHARE);
    let passes_at_twice = binomial_cdf(REQUIREMENT_RUNS, allowed, 2.0 * REQUIRED_SHARE);
    assert!(
        (0.951..0.952).contains(&passes_at_the_bound),
        "{passes_at_the_bound}"
    );
    assert!(
        (0.045..0.047).contains(&passes_at_twice),
        "{passes_at_twice}"
    );
    assert!(binomial_cdf(REQUIREMENT_RUNS, allowed, 0.025) > 0.9999);
    assert!(binomial_cdf(REQUIREMENT_RUNS, allowed, 0.15) < 0.0001);
    // The 240 runs first suggested: short of 0.95 at twice the bound.
    let allowed = critical(240, REQUIRED_SHARE, REQUIREMENT_ALPHA);
    assert_eq!(18, allowed);
    assert!(1.0 - binomial_cdf(240, allowed, 2.0 * REQUIRED_SHARE) < 0.89);
}

/// A tripwire's tolerance and power, as the module's doc gives them for 60 runs.
#[test]
fn a_tripwire_allows_for_the_baseline_being_a_sample() {
    let tripwire = |beyond, runs| Tripwire {
        cell: String::new(),
        figure: "max_age".to_owned(),
        high: true,
        threshold: 1.0,
        beyond,
        runs,
        level: String::new(),
    };
    // A 90th percentile of 1000 baseline runs: 10 % beyond, allowed for as 12 %.
    let p90 = tripwire(100, 1000);
    let share = wilson_upper(100, 1000, 1.96);
    assert!((0.119..0.121).contains(&share), "{share}");
    assert_eq!(15, p90.allowed(60));
    assert!(binomial_cdf(60, 15, share) >= 1.0 - TRIPWIRE_ALPHA);
    assert!((0.42..0.44).contains(&(1.0 - binomial_cdf(60, 15, 0.25))));
    assert!(1.0 - binomial_cdf(60, 15, 0.4) > 0.98);
    // A median: 50 % beyond, allowed for as 53 %.
    let p50 = tripwire(500, 1000);
    assert_eq!(43, p50.allowed(60));
    assert!((0.67..0.69).contains(&(1.0 - binomial_cdf(60, 43, 0.75))));
    assert!(1.0 - binomial_cdf(60, 43, 0.85) > 0.99);
    // Nothing beyond in the baseline is not "never": 0 of 1000 allows for 0.4 %.
    assert_eq!(2, tripwire(0, 1000).allowed(60));
    // A threshold every baseline run was beyond holds nothing.
    assert_eq!(60, tripwire(1000, 1000).allowed(60));
    // Counting: over the threshold, or not completed.
    let cell = Cell::parse(PR_CELLS[0].0).unwrap();
    let row = |figures| Row {
        cell,
        seed: 1,
        phase_ms: 0,
        figures,
        took: Duration::ZERO,
    };
    let mut over = Figures([0.0; NAMES.len()]);
    over.0[0] = 1.5;
    let rows = [
        row(Ok(Figures([0.0; NAMES.len()]))),
        row(Ok(over)),
        row(Err("peer 0 failed".to_owned())),
    ];
    assert_eq!(2, p90.beyond(&rows));
    assert_eq!(1, PICTURE.violators(&rows));
    assert_eq!(
        "IROW cell=cap/paced/gap300/up/q300/rl0 seed=1 phase=0 failed=peer_0_failed",
        rows[2].line()
    );
}

#[test]
fn a_disconnect_lasts_from_leaving_connected_to_coming_back() {
    use RTCPeerConnectionState::{Connected, Connecting, Disconnected, Failed};
    let ms = Duration::from_millis;
    let end = ms(60_000);
    // Connecting before the first Connected is not a disconnect.
    let once = [(ms(0), Connecting), (ms(100), Connected)];
    assert_eq!((ms(0), ms(0), 0), disconnects(&once, end));
    // Two episodes: 700 ms and 300 ms; a state between (Disconnected then Failed, say) does
    // not start a new one.
    let twice = [
        (ms(0), Connecting),
        (ms(100), Connected),
        (ms(25_000), Disconnected),
        (ms(25_700), Connected),
        (ms(31_000), Disconnected),
        (ms(31_300), Connected),
    ];
    assert_eq!((ms(1_000), ms(700), 0), disconnects(&twice, end));
    // One that never comes back lasts to the end of the run and is still open.
    let open = [
        (ms(100), Connected),
        (ms(25_000), Disconnected),
        (ms(50_000), Failed),
    ];
    assert_eq!((ms(35_000), ms(35_000), 1), disconnects(&open, end));
}

#[test]
fn the_lowest_and_the_mean_target_are_read_from_the_target() {
    let ms = Duration::from_millis;
    let targets = [
        (ms(0), 2_500_000),
        (ms(20_500), 1_250_000),
        (ms(21_000), 0),
        (ms(22_000), 300_000),
        (ms(26_000), 100_000),
    ];
    // The pause is not a target; what follows the window is not in it.
    assert_eq!(300_000, lowest(&targets, ms(20_000), ms(25_000)));
    assert_eq!(2_500_000, lowest(&targets, ms(10_000), ms(20_000)));
    // 20.0 to 21.0 s: five samples at 2.5 M, five at 1.25 M.
    assert_eq!(1_875_000, mean_target(&targets, ms(20_000), ms(21_000)));
}

/// RFC 8888 section 5: "If only a single congestion control feedback packet is lost, an
/// appropriate response is to assume that the level of congestion has remained roughly the
/// same". On a path whose capacity does not change, 300 ms without any of the receiver's
/// RTCP (several feedback packets, less than the controller's missing-feedback timeout)
/// leaves the sender's target where it was, and no peer leaves Connected.
#[test]
fn a_feedback_gap_shorter_than_the_timeout_does_not_lower_the_target() -> Result<()> {
    let cell = Cell::parse("fbgap/paced/gap300/up/q300/rl0")?;
    let figures = run_cell(cell, 7, phase_of(7))?;
    let value = |name: &str| figures.0[NAMES.iter().position(|n| *n == name).unwrap()];
    assert!(value("before") >= 1000.0, "the call had not ramped up");
    assert_eq!(value("before"), value("low"), "the target fell in the gap");
    assert_eq!(value("before"), value("mean10"));
    assert_eq!(0.0, value("disc"));
    assert_eq!(0.0, value("stun_lost"));
    Ok(())
}

/// The outage of the `fbgap` scenario takes RTCP, and only the callee's, for its 300 ms.
#[test]
fn the_feedback_outage_takes_the_callees_rtcp_for_300_ms() -> Result<()> {
    let cell = Cell::parse("fbgap/paced/gap300/up/q300/rl0")?;
    let mut world = World::connected(&cell.setup(7))?;
    let t = world.now + Duration::from_secs(5);
    world.advance(t)?;
    assert_eq!(0, world.feedback_outage_lost);
    world.feedback_outage_until = Some(world.now + FEEDBACK_GAP);
    let t = world.now + Duration::from_secs(2);
    world.advance(t)?;
    // The callee sends some 60 RTCP datagrams a second: 300 ms hold between 6 and 40.
    assert!(
        (6..=40).contains(&world.feedback_outage_lost),
        "{} RTCP datagrams lost",
        world.feedback_outage_lost
    );
    assert_eq!(0, world.stun_lost);
    let audio = world.peers[0].audio_arrivals.len();
    assert!(audio > 300, "the callee's audio went on arriving: {audio}");
    Ok(())
}

/// The baseline file parses, and names only cells and figures there are.
#[test]
fn the_recorded_baseline_is_well_formed() -> Result<()> {
    for tripwire in baseline()? {
        Cell::parse(&tripwire.cell)?;
        assert!(NAMES.contains(&tripwire.figure.as_str()), "{tripwire:?}");
        assert!(
            tripwire.beyond <= tripwire.runs && tripwire.runs > 0,
            "{tripwire:?}"
        );
    }
    Ok(())
}

/// A run is a function of its cell, seed and phase: the same run twice, the second time on
/// another thread, gives the same figures to the last digit, with the reference receiver and
/// with loss drawn on the reverse path. Nothing in it reads a clock or draws from an unseeded
/// source in a way that reaches a figure (docs/capacity-instrument.md lists what the engine
/// still draws unseeded, and why it does not).
#[test]
fn the_same_seed_gives_the_same_figures() -> Result<()> {
    for name in [PR_CELLS[0].0, "cap/nopacer/gap300/up/q300/rl5"] {
        let cell = Cell::parse(name)?;
        let here = run_cell(cell, 1, 11)?;
        let there = std::thread::spawn(move || run_cell(cell, 1, 11).map_err(|e| e.to_string()))
            .join()
            .map_err(|_| anyhow!("the second run panicked"))?
            .map_err(|error| anyhow!(error))?;
        assert_eq!(here, there, "{name}");
        // And it is the scenario: a call that had climbed, met the drop and reacted.
        assert!(here.get("before") >= 1_000.0, "{name}: {here:?}");
        assert!(here.get("reacted") < 5.0, "{name}: {here:?}");
        assert!(here.get("max_age") > 0.3, "{name}: {here:?}");
        assert!(
            here.get("end") > 65.0 && here.get("end") < 71.0,
            "{name}: {here:?}"
        );
        // The absolute recovery figure waits for 1000 kbit/s, which is never less than the
        // relative one's 0.4 of a target that cannot be above the 2.5 Mbit/s maximum, and
        // the rate was not there when the capacity came back.
        assert!(
            here.get("to1000") >= here.get("recover"),
            "{name}: {here:?}"
        );
        assert!(here.get("to1000") > 1.0, "{name}: {here:?}");
    }
    // The default chain probes at the start: the maximum is found long before the drop.
    let paced = run_cell(Cell::parse(PR_CELLS[0].0)?, 1, 11)?;
    assert!(paced.get("startup") < 5.0, "{paced:?}");
    assert_eq!(2_500.0, paced.get("before"), "{paced:?}");
    assert_eq!(paced.get("recover"), paced.get("to1000"), "{paced:?}");
    Ok(())
}

/// The scenario `cap60` is the cap held for a minute: the call is 40 s longer than the
/// reference scenario's, the target is under the capped link's rate through it, and it is
/// not back at 1000 kbit/s the moment the capacity returns.
#[test]
fn the_long_cap_holds_the_capacity_down_for_a_minute() -> Result<()> {
    let cell = Cell::parse("cap60/parolnet/gap300/up/q300/rl0")?;
    let figures = run_cell(cell, 1, 11)?;
    assert!(
        figures.get("end") > 105.0 && figures.get("end") < 111.0,
        "{figures:?}"
    );
    assert!(figures.get("under") < 300.0, "{figures:?}");
    assert!(figures.get("to1000") > 1.0, "{figures:?}");
    Ok(())
}
