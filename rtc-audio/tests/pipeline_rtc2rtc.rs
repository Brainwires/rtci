//! Audio through the whole pipeline between two `rtc` peer connections in virtual time:
//! speech-like capture → processing → Opus (in-band FEC on reported loss) → the engine
//! (SRTP, RTCP) → a simulated link with loss, jitter and reordering → the engine → the
//! jitter buffer → playout, with the receive statistics fed into `getStats()`.
//!
//! The link carries ICE, DTLS and SCTP untouched until the connection is up, then drops a
//! fixed share of the SRTP / SRTCP datagrams in each direction and delays each by a random
//! amount (so they overtake each other), from a fixed seed. Numbers are printed with
//! `MEASURE` for `docs/media-pipeline.md`.

mod common;

use std::time::Duration;

use anyhow::Result;
use common::{Link, World};
use rtc::statistics::StatsSelector;
use rtc_audio::AudioFrame;
use rtc_audio::engine::{AudioReceiver, AudioSender, AudioSenderOptions, OpusBackend};
use rtc_audio::jitter::{JitterBufferConfig, ReceiveStats};
use rtc_audio::processing::ProcessingConfig;
use rtc_audio::signal::SpeechLike;

/// What a run measured.
struct Outcome {
    stats: ReceiveStats,
    played: Vec<f32>,
    loss: f64,
    report_concealed: Option<u64>,
    packets_sent: u64,
    fec_on: bool,
}

fn lateness_base(base: &mut Option<u32>, ts: u32) -> u32 {
    *base.get_or_insert(ts)
}

fn run(link: Link, seconds: u64, seed: u64) -> Result<Outcome> {
    let (mut world, sender_id) = World::connected_audio(link, seed)?;
    let t0 = world.now;
    let mut sender = AudioSender::new(
        &mut world.peers[0].pc,
        sender_id,
        t0,
        AudioSenderOptions {
            processing: ProcessingConfig::OFF,
            ..Default::default()
        },
    )?;
    let mut source = SpeechLike::new(48_000, seed);
    let mut receiver: Option<AudioReceiver> = None;
    let mut played = Vec::new();
    // Each packet's arrival against its media time, for the delay diagnostics.
    let mut lateness: Vec<f64> = Vec::new();
    let mut ts0: Option<u32> = None;
    let mut frame = vec![0.0f32; 480];
    for tick in 0..seconds * 100 {
        let t = t0 + Duration::from_millis(tick * 10);
        world.advance(t)?;
        source.fill(&mut frame);
        sender.push_capture(
            &mut world.peers[0].pc,
            t,
            &AudioFrame {
                samples: frame.clone(),
                sample_rate: 48_000,
                channels: 1,
            },
        )?;
        if tick % 50 == 0 {
            sender.update_network(&mut world.peers[0].pc, t);
        }
        let rtcp = std::mem::take(&mut world.rtcp_in);
        sender.handle_rtcp(&rtcp);
        if receiver.is_none()
            && let Some(id) = world.receiver
        {
            receiver = Some(AudioReceiver::new(
                &mut world.peers[1].pc,
                id,
                JitterBufferConfig::default(),
                1,
                OpusBackend::Rust,
            )?);
        }
        if let Some(r) = receiver.as_mut() {
            for p in std::mem::take(&mut world.rtp_in) {
                lateness.push(
                    world.now.duration_since(t0).as_secs_f64()
                        - f64::from(
                            p.header
                                .timestamp
                                .wrapping_sub(lateness_base(&mut ts0, p.header.timestamp)),
                        ) / 48_000.0,
                );
                r.handle_rtp(world.now, &p);
            }
            played.extend(r.pull(t).samples);
        }
    }
    let mut receiver = receiver.expect("the track opened");
    receiver.update_stats(&mut world.peers[1].pc);
    let report = world.peers[1].pc.get_stats(world.now, StatsSelector::None);
    let report_concealed = report
        .inbound_rtp_streams()
        .find_map(|s| s.concealed_samples);
    let inbound = report
        .inbound_rtp_streams()
        .map(|s| s.received_rtp_stream_stats.packets_received)
        .sum::<u64>();
    let sent_report = world.peers[0].pc.get_stats(world.now, StatsSelector::None);
    let outbound = sent_report
        .outbound_rtp_streams()
        .map(|s| s.sent_rtp_stream_stats.packets_sent)
        .sum::<u64>();
    let min = lateness.iter().copied().fold(f64::INFINITY, f64::min);
    let mut rel: Vec<f64> = lateness.iter().map(|d| d - min).collect();
    rel.sort_by(f64::total_cmp);
    let pct = |q: f64| {
        rel.get(((rel.len() as f64 - 1.0) * q) as usize)
            .copied()
            .unwrap_or(0.0)
            * 1000.0
    };
    println!(
        "rtc2rtc arrival lateness: p50 {:.1} ms, p95 {:.1} ms, max {:.1} ms; target at the end {:?}",
        pct(0.5),
        pct(0.95),
        pct(1.0),
        receiver.buffer().target_delay(),
    );
    println!(
        "rtc2rtc diagnostics: written {}, engine sent {outbound}, engine received {inbound}, \
         circuit breaker ceased {:?}, media datagrams {} (dropped {})",
        sender.packets_sent(),
        world.peers[0]
            .handles
            .as_ref()
            .map(|h| h.circuit_breaker.ceased()),
        world.media_datagrams,
        world.dropped,
    );
    Ok(Outcome {
        stats: receiver.stats().clone(),
        played,
        loss: world.dropped as f64 / world.media_datagrams.max(1) as f64,
        report_concealed,
        packets_sent: sender.packets_sent(),
        fec_on: sender.pipeline().stats().fec,
    })
}

#[test]
fn audio_plays_through_the_pipeline_at_every_loss_rate() -> Result<()> {
    let jitter = Duration::from_millis(40);
    let mut failures = Vec::new();
    for (loss, max_concealed) in [
        (0.0, 0.002),
        (0.02, 0.02),
        (0.05, 0.055),
        (0.10, 0.09),
        (0.20, 0.20),
    ] {
        let link = Link {
            loss,
            delay: Duration::from_millis(25),
            jitter,
        };
        let o = run(link, 30, 11)?;
        let s = &o.stats;
        let mean = s.mean_delay().unwrap_or_default();
        println!(
            "MEASURE rtc2rtc Opus {:>4.1} % loss (measured {:.1} %), 40 ms jitter: concealed {:.2} %, \
             FEC frames {}, mean delay {:.0} ms, underruns {}, late {}, accelerate {} / expand {} samples, FEC on {}",
            loss * 100.0,
            o.loss * 100.0,
            100.0 * s.concealment_ratio(),
            s.fec_frames_recovered,
            mean.as_secs_f64() * 1000.0,
            s.underruns,
            s.packets_late,
            s.removed_samples_for_acceleration,
            s.inserted_samples_for_deceleration,
            o.fec_on,
        );
        // Every rate is run and reported before any assertion fails.
        let mut check = |ok: bool, what: String| {
            if !ok {
                failures.push(format!("{:.0} % loss: {what}", loss * 100.0));
            }
        };
        check(
            o.packets_sent >= 1490,
            format!("{} packets sent", o.packets_sent),
        );
        check(
            s.concealment_ratio() <= max_concealed,
            format!("concealed {:.3}", s.concealment_ratio()),
        );
        check(
            mean <= Duration::from_millis(160),
            format!("mean delay {mean:?}"),
        );
        // Playout never stopped: 30 s at 48 kHz less the start-up.
        check(
            o.played.len() >= 48_000 * 29,
            format!("{} samples played", o.played.len()),
        );
        check(s.total_samples_received >= 48_000 * 29, format!("{s:?}"));
        // The engine's report carries the buffer's counters.
        check(
            o.report_concealed == Some(s.concealed_samples),
            format!("report {:?}", o.report_concealed),
        );
        if loss >= 0.05 {
            check(o.fec_on, "FEC stayed off".into());
        }
        // At 5 % libopus (and opus-rs) spends no LBRR at 32 kbit/s full band
        // (`decide_fec`); above 5 % it narrows the band until it can.
        if loss >= 0.10 {
            check(s.fec_frames_recovered > 0, "no FEC frame recovered".into());
            check(
                s.concealment_ratio() < loss * 0.8,
                "FEC did not reduce concealment".into(),
            );
        }
    }
    assert!(failures.is_empty(), "{failures:#?}");
    Ok(())
}

/// The congestion controller's target is an upper bound for audio, never a target: in a call
/// with an audio and a video sender, the audio encoding's share stops at what its encoder can
/// use (its ceiling, here the application's 16 kbit/s, and its packets' overhead), and the
/// video encoding gets the rest of the target (libwebrtc clamps an audio stream's allocation
/// to its encoder's range the same way). The congestion controller stays at its starting
/// 100 kbit/s in this call (nothing sends more than audio), so a ceiling under half of it is
/// what shows the split; RFC 7587's default ceilings are the `fmtp` tests'.
#[test]
fn audio_takes_its_ceiling_of_the_target_and_video_the_rest() -> Result<()> {
    let link = Link {
        loss: 0.0,
        delay: Duration::from_millis(25),
        jitter: Duration::ZERO,
    };
    let (mut world, audio_id, video_id) = World::connected_audio_video(link, 5)?;
    let t0 = world.now;
    let mut sender = AudioSender::new(
        &mut world.peers[0].pc,
        audio_id,
        t0,
        AudioSenderOptions {
            processing: ProcessingConfig::OFF,
            max_bitrate: Some(16_000),
            ..Default::default()
        },
    )?;
    // 16 kbit/s of Opus and 58 bytes of overhead on each of 50 packets a second.
    let cap = sender.pipeline().max_allocation_bps();
    assert_eq!(cap, 16_000.0 + 58.0 * 8.0 * 50.0);
    let mut tone = rtc_audio::signal::Tone::new(48_000, 440.0, 0.25);
    let mut frame = vec![0.0f32; 480];
    for tick in 0..300u64 {
        let t = t0 + Duration::from_millis(tick * 10);
        world.advance(t)?;
        tone.fill(&mut frame);
        sender.push_capture(
            &mut world.peers[0].pc,
            t,
            &AudioFrame {
                samples: frame.clone(),
                sample_rate: 48_000,
                channels: 1,
            },
        )?;
        if tick % 50 == 0 {
            sender.update_network(&mut world.peers[0].pc, t);
        }
        world.rtcp_in.clear();
        world.rtp_in.clear();
    }
    let share = |world: &mut World, id| -> f64 {
        world.peers[0]
            .pc
            .rtp_sender(id)
            .map(|s| s.target_bitrates().iter().map(|&(_, bps)| bps).sum())
            .unwrap_or_default()
    };
    let (audio, video) = (share(&mut world, audio_id), share(&mut world, video_id));
    let total = world.peers[0]
        .pc
        .get_stats(world.now, StatsSelector::None)
        .candidate_pairs()
        .find_map(|p| p.available_outgoing_bitrate)
        .expect("the congestion controller set a target");
    println!("MEASURE two-stream allocation: total {total:.0}, audio {audio:.0}, video {video:.0}");
    assert!(
        total > 2.0 * cap,
        "a target audio cannot use half of: {total}"
    );
    assert_eq!(audio, cap, "audio stops at its ceiling");
    assert!(
        (audio + video - total).abs() < 1.0,
        "video gets the rest: {video} of {total}"
    );
    // The encoder runs at its ceiling, not at its share.
    assert_eq!(sender.pipeline().stats().target_bitrate, Some(16_000));
    Ok(())
}
