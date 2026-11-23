//! Headless audio through the whole stack: a WAV file (or a synthetic speech-like signal) is
//! processed, encoded with Opus and sent by one `rtc` peer connection to another over a
//! simulated lossy, jittery link in virtual time; the receiver's jitter buffer decodes and
//! conceals it, and the result is written as a WAV file. The Opus packets that arrived are
//! also written as an Ogg file, so an independent decoder (GStreamer's `opusdec`, in the test
//! environment's env stage) can check them.
//!
//! ```text
//! cargo run -p rtc-audio --example audio-loopback -- \
//!     [--input in.wav] [--seconds 10] [--loss 0.05] [--jitter-ms 40] \
//!     [--output out.wav] [--ogg received.ogg]
//! ```
//!
//! It prints the receive statistics and exits non-zero when the audio did not arrive (the
//! output is silent, or more than twice the link's loss was concealed).

#[path = "../tests/common/mod.rs"]
mod common;

use std::fs::File;
use std::io::{BufReader, BufWriter, Read, Write};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use common::{Link, World};
use rtc::media::io::Writer as _;
use rtc::media::io::ogg_writer::OggWriter;
use rtc_audio::AudioFrame;
use rtc_audio::dsp::resample::MultiResampler;
use rtc_audio::engine::{AudioReceiver, AudioSender, AudioSenderOptions, OpusBackend};
use rtc_audio::jitter::JitterBufferConfig;
use rtc_audio::processing::ProcessingConfig;
use rtc_audio::signal::SpeechLike;

struct Args {
    input: Option<String>,
    output: String,
    ogg: Option<String>,
    seconds: f64,
    loss: f64,
    jitter_ms: u64,
}

fn args() -> Result<Args> {
    let mut a = Args {
        input: None,
        output: "audio-loopback.wav".into(),
        ogg: None,
        seconds: 10.0,
        loss: 0.05,
        jitter_ms: 40,
    };
    let mut it = std::env::args().skip(1);
    while let Some(flag) = it.next() {
        let mut value = || it.next().with_context(|| format!("{flag} needs a value"));
        match flag.as_str() {
            "--input" => a.input = Some(value()?),
            "--output" => a.output = value()?,
            "--ogg" => a.ogg = Some(value()?),
            "--seconds" => a.seconds = value()?.parse()?,
            "--loss" => a.loss = value()?.parse()?,
            "--jitter-ms" => a.jitter_ms = value()?.parse()?,
            other => bail!("unknown argument {other}"),
        }
    }
    Ok(a)
}

/// Reads a 16-bit PCM WAV file: its samples mixed to mono, and its rate.
fn read_wav(path: &str) -> Result<(Vec<f32>, u32)> {
    let mut bytes = Vec::new();
    BufReader::new(File::open(path)?).read_to_end(&mut bytes)?;
    if bytes.len() < 12 || &bytes[..4] != b"RIFF" || &bytes[8..12] != b"WAVE" {
        bail!("{path} is not a WAV file");
    }
    let (mut rate, mut channels, mut bits) = (0u32, 0u16, 0u16);
    let mut pos = 12;
    while pos + 8 <= bytes.len() {
        let id = &bytes[pos..pos + 4];
        let len = u32::from_le_bytes(bytes[pos + 4..pos + 8].try_into()?) as usize;
        let body = &bytes[pos + 8..(pos + 8 + len).min(bytes.len())];
        if id == b"fmt " && body.len() >= 16 {
            channels = u16::from_le_bytes([body[2], body[3]]);
            rate = u32::from_le_bytes(body[4..8].try_into()?);
            bits = u16::from_le_bytes([body[14], body[15]]);
        } else if id == b"data" {
            if bits != 16 || channels == 0 {
                bail!("{path}: only 16-bit PCM is read");
            }
            let ch = usize::from(channels);
            let samples = body
                .chunks_exact(2 * ch)
                .map(|f| {
                    f.as_chunks::<2>()
                        .0
                        .iter()
                        .map(|s| f32::from(i16::from_le_bytes([s[0], s[1]])) / 32768.0)
                        .sum::<f32>()
                        / ch as f32
                })
                .collect();
            return Ok((samples, rate));
        }
        pos += 8 + len + len % 2;
    }
    bail!("{path} has no data")
}

/// Writes 48 kHz mono 16-bit PCM.
fn write_wav(path: &str, samples: &[f32]) -> Result<()> {
    let mut w = BufWriter::new(File::create(path)?);
    let data = (samples.len() * 2) as u32;
    w.write_all(b"RIFF")?;
    w.write_all(&(36 + data).to_le_bytes())?;
    w.write_all(b"WAVEfmt ")?;
    w.write_all(&16u32.to_le_bytes())?;
    w.write_all(&1u16.to_le_bytes())?;
    w.write_all(&1u16.to_le_bytes())?;
    w.write_all(&48_000u32.to_le_bytes())?;
    w.write_all(&96_000u32.to_le_bytes())?;
    w.write_all(&2u16.to_le_bytes())?;
    w.write_all(&16u16.to_le_bytes())?;
    w.write_all(b"data")?;
    w.write_all(&data.to_le_bytes())?;
    for s in samples {
        w.write_all(&rtc_audio::frame::f32_to_i16(*s).to_le_bytes())?;
    }
    Ok(())
}

fn main() -> Result<()> {
    let a = args()?;
    let input = match &a.input {
        Some(path) => {
            let (x, rate) = read_wav(path)?;
            if rate == 48_000 {
                x
            } else {
                let mut r = MultiResampler::new(rate, 48_000, 1);
                let mut y = Vec::new();
                r.process(&x, &mut y);
                y
            }
        }
        None => {
            let mut x = vec![0.0f32; (a.seconds * 48_000.0) as usize];
            SpeechLike::new(48_000, 1).fill(&mut x);
            x
        }
    };
    let link = Link {
        loss: a.loss,
        delay: Duration::from_millis(25),
        jitter: Duration::from_millis(a.jitter_ms),
    };
    let (mut world, sender_id) = World::connected_audio(link, 7)?;
    let t0 = world.now;
    let mut sender = AudioSender::new(
        &mut world.peers[0].pc,
        sender_id,
        t0,
        AudioSenderOptions {
            processing: ProcessingConfig::CALL,
            ..Default::default()
        },
    )?;
    let mut ogg = match &a.ogg {
        Some(path) => Some(OggWriter::new(
            BufWriter::new(File::create(path)?),
            48_000,
            1,
        )?),
        None => None,
    };
    let mut receiver: Option<AudioReceiver> = None;
    let mut output = Vec::with_capacity(input.len());
    // Half a second more than the input, for what is still in flight.
    let ticks = input.len() / 480 + 50;
    for tick in 0..ticks {
        let t = t0 + Duration::from_millis(tick as u64 * 10);
        world.advance(t)?;
        let frame = input
            .get(tick * 480..(tick + 1) * 480)
            .map(<[f32]>::to_vec)
            .unwrap_or_else(|| vec![0.0; 480]);
        sender.push_capture(
            &mut world.peers[0].pc,
            t,
            &AudioFrame {
                samples: frame,
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
                if let Some(w) = ogg.as_mut() {
                    w.write_rtp(&p)?;
                }
                r.handle_rtp(world.now, &p);
            }
            let played = r.pull(t);
            // The far end's playout is this end's echo reference in a real call; here the
            // receiver is the other peer, so nothing is fed back.
            output.extend(played.samples);
        }
    }
    if let Some(mut w) = ogg.take() {
        w.close()?;
    }
    let receiver = receiver.context("the track never opened")?;
    let s = receiver.stats();
    let loss = world.dropped as f64 / world.media_datagrams.max(1) as f64;
    println!(
        "AUDIO-LOOPBACK: {:.1} s in, link loss {:.1} %, concealed {:.2} %, FEC frames {}, mean delay {:.0} ms, \
         underruns {}, packets sent {}, encoder {}",
        input.len() as f64 / 48_000.0,
        loss * 100.0,
        100.0 * s.concealment_ratio(),
        s.fec_frames_recovered,
        s.mean_delay().unwrap_or_default().as_secs_f64() * 1000.0,
        s.underruns,
        sender.packets_sent(),
        sender.pipeline().encoder_name(),
    );
    write_wav(&a.output, &output)?;
    let rms = (output.iter().map(|v| f64::from(*v).powi(2)).sum::<f64>()
        / output.len().max(1) as f64)
        .sqrt();
    if rms < 1e-3 {
        bail!("the output is silent (RMS {rms})");
    }
    if s.concealment_ratio() > (2.0 * loss).max(0.01) {
        bail!(
            "{:.2} % concealed on a {:.1} % link",
            100.0 * s.concealment_ratio(),
            100.0 * loss
        );
    }
    Ok(())
}
