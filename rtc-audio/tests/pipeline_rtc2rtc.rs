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
            sender.update_bitrate(&mut world.peers[0].pc);
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
    println!(
        "rtc2rtc diagnostics: written {}, engine sent {outbound}, engine received {inbound}, \
         circuit breaker ceased {:?} (dropped {}), media datagrams {} (dropped {})",
        sender.packets_sent(),
        world.peers[0].handles.circuit_breaker.ceased(),
        world.peers[0].handles.circuit_breaker.dropped(),
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
    for (loss, max_concealed) in [
        (0.0, 0.002),
        (0.02, 0.02),
        (0.05, 0.04),
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
        assert!(o.packets_sent >= 1490, "{} packets", o.packets_sent);
        assert!(s.concealment_ratio() <= max_concealed, "{loss}: {s:?}");
        assert!(mean <= Duration::from_millis(160), "{loss}: {mean:?}");
        // Playout never stopped: 30 s at 48 kHz less the start-up.
        assert!(o.played.len() >= 48_000 * 29);
        assert!(s.total_samples_received >= 48_000 * 29);
        // The engine's report carries the buffer's counters.
        assert_eq!(o.report_concealed, Some(s.concealed_samples));
        if loss >= 0.05 {
            assert!(o.fec_on, "{loss}: FEC stayed off");
            assert!(s.fec_frames_recovered > 0, "{loss}: {s:?}");
        }
    }
    Ok(())
}
