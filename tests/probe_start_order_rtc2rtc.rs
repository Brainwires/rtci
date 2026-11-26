//! The start-up probing of a call between two peer connections (virtual time,
//! [`capacity_common`]) whose sources do not start in the same instant.
//!
//! RFC 8836 section 2, requirement 4: the algorithm "SHOULD adapt as quickly as possible to
//! initial network conditions at the start of a flow". The engine does it by probing: its
//! first start-up cluster is asked for with the first packet that leaves, and in a chain
//! without a pacer the NACK responder fills it with padding on the RTX stream of a stream that
//! has sent. A real application's microphone delivers its first frame some milliseconds before
//! its camera, so the first packet of a call is audio, whose stream has no RTX stream, and the
//! video comes after it. Every other two-peer test writes the first audio and video frames in
//! the same instant ([`StartOrder::Together`]), which hid that a cluster asked for then went
//! unanswered and stopped the probing for the whole call
//! (`conf/probe-1-start-up-probe-before-the-video`: the peer climbed at the 8 % a second of
//! draft-ietf-rmcat-gcc-02 section 5.5, 1 Mbit/s after 15.6 s).
//!
//! Each call here is a few seconds on an open link (10 ms one way, no cap, no loss), audio and
//! video with RTX each way, the video following the estimate. Both peers are held to what
//! `an_open_link_is_found_within_a_second_without_a_pacer` (capacity_cap_video_rtc2rtc.rs)
//! holds a call whose sources start together to (1 Mbit/s within a second, the 2.5 Mbit/s
//! maximum within two), except where a test says why its first bound is later.

mod capacity_common;

use anyhow::Result;
use capacity_common::*;
use rtci::interceptor::PacerBacklog;
use std::time::Duration;

/// What a call's start-up gave each peer (caller, callee).
#[derive(Debug)]
#[allow(dead_code)] // Read through `Debug`.
struct StartUp {
    /// When the estimate reached 1 Mbit/s and the maximum, from the start of the measured
    /// stretch (the call's start, or the video's in [`video_added_run`]).
    reached_1m: [Option<Duration>; 2],
    reached_max: [Option<Duration>; 2],
    /// The estimate at the end.
    last: [Option<u32>; 2],
    /// Probe padding each peer's uplink carried (padding-only RTX packets), in the measured
    /// stretch.
    padding: [u64; 2],
}

fn start_up(world: &World, from: Duration, padding_before: [u64; 2]) -> StartUp {
    let reached = |i: usize, level: u32| {
        world.peers[i]
            .estimates
            .iter()
            .find(|(at, bps)| *at >= from && *bps >= level)
            .map(|(at, _)| *at - from)
    };
    StartUp {
        reached_1m: [0, 1].map(|i| reached(i, 1_000_000)),
        reached_max: [0, 1].map(|i| reached(i, MAX_BPS)),
        last: [0, 1].map(|i| world.peers[i].estimates.last().map(|(_, bps)| *bps)),
        padding: [0, 1].map(|i| world.uplinks[i].padding_sent - padding_before[i]),
    }
}

/// A call of five seconds whose sources start in `order`.
fn open_link_run(setup: &Setup) -> Result<StartUp> {
    // As capacity_cap_video_rtc2rtc.rs: this world's receiver was tuned for the pacer that
    // keeps its backlog. Nothing here is capped, so nothing is ever flushed either way.
    let setup = &setup.pacer_backlog(PacerBacklog::Keep);
    let mut world = World::connected(setup)?;
    world.sampling = true;
    let t = world.now + Duration::from_secs(5);
    world.advance(t)?;
    world.print_trace("start order", setup);
    Ok(start_up(&world, Duration::ZERO, [0, 0]))
}

/// Whether a peer found the open link: 1 Mbit/s within `to_1m`, the maximum within
/// `to_max`, the maximum at the end, and (without a pacer, where the responder's padding is
/// the probe) padding on its uplink. Every failure, for every peer.
fn misses(setup: &Setup, outcome: &StartUp, to_1m: Duration, to_max: Duration) -> Vec<String> {
    let mut misses = Vec::new();
    for (i, who) in ["caller", "callee"].into_iter().enumerate() {
        let mut miss = |what: String| misses.push(format!("{setup:?} {who}: {what}: {outcome:?}"));
        if !outcome.reached_1m[i].is_some_and(|at| at <= to_1m) {
            miss(format!(
                "1 Mbit/s at {:?}, not within {to_1m:?}",
                outcome.reached_1m[i]
            ));
        }
        if !outcome.reached_max[i].is_some_and(|at| at <= to_max) {
            miss(format!(
                "the maximum at {:?}, not within {to_max:?}",
                outcome.reached_max[i]
            ));
        }
        if outcome.last[i] != Some(MAX_BPS) {
            miss(format!("{:?} at the end, not the maximum", outcome.last[i]));
        }
        if setup.chain != Chain::Default && outcome.padding[i] == 0 {
            miss("no probe padding left".to_owned());
        }
    }
    misses
}

/// Every run of `runs` (what it is, its setup) through `run`, each printed, then every
/// miss at once: one CI run gives the figures of all of them.
fn check(
    runs: Vec<(String, Setup)>,
    run: fn(&Setup) -> Result<StartUp>,
    to_1m: Duration,
    to_max: Duration,
) -> Result<()> {
    let mut all = Vec::new();
    for (what, setup) in runs {
        let outcome = run(&setup)?;
        println!("{what}, {:?} seed {}: {outcome:?}", setup.chain, setup.seed);
        all.extend(misses(&setup, &outcome, to_1m, to_max));
    }
    assert!(all.is_empty(), "{}", all.join("\n"));
    Ok(())
}

/// The audio leads by these: under a frame of video, and over one audio frame.
const AUDIO_LEADS_MS: [u64; 2] = [10, 25];

fn audio_first(chain: Chain) -> Vec<(String, Setup)> {
    let mut runs = Vec::new();
    for lead in AUDIO_LEADS_MS {
        for seed in 1..=2 {
            let setup = Setup::new(seed, None)
                .chain(chain)
                .anchor(ANCHORS[0])
                .start_order(StartOrder::AudioFirst(Duration::from_millis(lead)));
            runs.push((format!("audio first by {lead} ms"), setup));
        }
    }
    runs
}

/// How long a call whose audio starts first takes to 1 Mbit/s without a pacer. The first
/// start-up cluster, asked for by the first audio packet, cannot be carried: the NACK
/// responder says so and the cluster is counted as never asked for
/// (`conf/probe-3-start-up-sequence-waits-for-a-carrier`), so the video's first packet asks
/// for it again and the start-up goes as for a call whose video starts first (0.27-0.37 s to
/// 1 Mbit/s, 0.47 s to the maximum). Was 1.07 s with probe-1 alone (its result was waited for,
/// `PROBE_RESULT_TIMEOUT`, 1 s: hosted run 45859028514) and never within the 5 s on 0.2.0
/// (45859034615: one cluster, no padding, 447 kbit/s at the end).
const AUDIO_FIRST_1M_BY: Duration = Duration::from_millis(500);
/// And to the maximum.
const AUDIO_FIRST_MAX_BY: Duration = Duration::from_secs(1);

/// The default interceptors with the pacer's slot passed through: the first audio packet
/// asks for the first start-up cluster before the video has sent, and nothing can be padded
/// for it. It is asked for again with the video's first packet and leaves as padding on the
/// video's RTX stream ([`AUDIO_FIRST_1M_BY`]).
#[test]
fn audio_before_video_still_probes_without_a_pacer() -> Result<()> {
    check(
        audio_first(Chain::DefaultWithoutPacer),
        open_link_run,
        AUDIO_FIRST_1M_BY,
        AUDIO_FIRST_MAX_BY,
    )
}

/// The same in ParolNet's chain (the TWCC-driven GCC, no pacer): the chain of the consumer's
/// report (`the_estimate_climbs_on_an_open_link`: the caller at 1 Mbit/s after 15.61 s).
#[test]
fn audio_before_video_still_probes_in_parolnets_chain() -> Result<()> {
    check(
        audio_first(Chain::ParolNet),
        open_link_run,
        AUDIO_FIRST_1M_BY,
        AUDIO_FIRST_MAX_BY,
    )
}

/// The engine's default interceptors: the pacer sends its clusters itself, from what it holds
/// and padding, so the order the sources start in does not matter (0.37 s to 1 Mbit/s and
/// 0.47 s to the maximum, as a call whose sources start together); held here so that it
/// stays so.
#[test]
fn audio_before_video_still_probes_with_the_pacer() -> Result<()> {
    check(
        audio_first(Chain::Default),
        open_link_run,
        Duration::from_secs(1),
        Duration::from_secs(2),
    )
}

/// The other order: the video's first frame 10 ms before the audio's. The first packet that
/// leaves is the video's, so the first cluster is asked for with a stream that can carry it
/// (0.27 to 0.37 s to 1 Mbit/s, 0.47 s to the maximum, in every chain, with the fix and
/// without).
#[test]
fn video_before_audio_probes_in_every_chain() -> Result<()> {
    let mut runs = Vec::new();
    for chain in [Chain::DefaultWithoutPacer, Chain::ParolNet, Chain::Default] {
        for seed in 1..=2 {
            let setup = Setup::new(seed, None)
                .chain(chain)
                .anchor(ANCHORS[0])
                .start_order(StartOrder::VideoFirst(Duration::from_millis(10)));
            runs.push(("video first by 10 ms".to_owned(), setup));
        }
    }
    check(
        runs,
        open_link_run,
        Duration::from_secs(1),
        Duration::from_secs(2),
    )
}

/// Three seconds of audio alone, then both cameras on by renegotiation (the caller's, then the
/// callee's, in one instant), and six seconds more: the start-up of the video, measured from
/// the renegotiation.
fn video_added_run(setup: &Setup) -> Result<StartUp> {
    let setup = &setup.pacer_backlog(PacerBacklog::Keep);
    let mut world = World::connected(&setup.audio_only())?;
    world.sampling = true;
    let t = world.now + Duration::from_secs(3);
    world.advance(t)?;
    let padding_before = [0, 1].map(|i| world.uplinks[i].padding_sent);
    let on = world.elapsed();
    world.set_video(0, true)?;
    world.set_video(1, true)?;
    let t = world.now + Duration::from_secs(6);
    world.advance(t)?;
    world.print_trace("video added", setup);
    Ok(start_up(&world, on, padding_before))
}

/// A call that starts with audio alone and gains video by renegotiation, on seeds 1 and 2 of
/// `chain`. RFC 8836 section 2, requirement 4, at the start of the video's flow: the
/// estimate should find the open link soon after the video starts. Held to 1 Mbit/s within
/// three seconds of the renegotiation (a cluster nothing carries is waited for for one second)
/// and the maximum within four.
fn video_added(chain: Chain) -> Result<()> {
    let runs = (1..=2)
        .map(|seed| {
            let setup = Setup::new(seed, None).chain(chain).anchor(ANCHORS[0]);
            ("video added after 3 s of audio".to_owned(), setup)
        })
        .collect();
    check(
        runs,
        video_added_run,
        Duration::from_secs(3),
        Duration::from_secs(4),
    )
}

/// [`video_added`] in the default interceptors without the pacer.
#[test]
fn video_added_to_an_audio_call_is_probed_for_without_a_pacer() -> Result<()> {
    video_added(Chain::DefaultWithoutPacer)
}

/// [`video_added`] in ParolNet's chain.
#[test]
fn video_added_to_an_audio_call_is_probed_for_in_parolnets_chain() -> Result<()> {
    video_added(Chain::ParolNet)
}

/// [`video_added`] in the engine's default interceptors.
#[test]
fn video_added_to_an_audio_call_is_probed_for_with_the_pacer() -> Result<()> {
    video_added(Chain::Default)
}
