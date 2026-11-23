//! The processing chain against a simulated room: far-end speech played through an echo path
//! (bulk delay, direct path, a decaying reverberant tail), near-end speech and noise added at
//! the microphone. Echo return loss enhancement is measured where only the far end talks.

use super::*;
use crate::signal::{Noise, Rng, SpeechLike, best_lag, snr_db};

/// An echo path: `delay_ms` of bulk delay, then a direct path and a reverberant tail of
/// `tail_ms` decaying by 60 dB, `gain` overall.
fn room(delay_ms: usize, tail_ms: usize, gain: f32, seed: u64) -> Vec<f32> {
    let mut rng = Rng::new(seed);
    let d = delay_ms * 48;
    let tail = tail_ms * 48;
    let mut h = vec![0.0f32; d + tail];
    h[d] = 1.0;
    for i in 1..tail {
        let decay = 10f32.powf(-3.0 * i as f32 / tail as f32);
        h[d + i] = 0.3 * decay * rng.gaussian() as f32;
    }
    let norm = h.iter().map(|v| v * v).sum::<f32>().sqrt();
    h.iter_mut().for_each(|v| *v *= gain / norm);
    h
}

fn convolve(x: &[f32], h: &[f32]) -> Vec<f32> {
    // Overlap-add with the crate's FFT: a direct convolution of a long tail is too slow.
    use crate::dsp::fft::{Complex, Fft};
    let n = (2 * h.len()).next_power_of_two().max(1024);
    let block = n - h.len() + 1;
    let mut fft = Fft::new(n);
    let mut hp = vec![0.0f32; n];
    hp[..h.len()].copy_from_slice(h);
    let mut hs = vec![Complex::default(); n / 2 + 1];
    fft.real_forward(&hp, &mut hs);
    let mut y = vec![0.0f32; x.len() + n];
    let mut buf = vec![0.0f32; n];
    let mut spec = vec![Complex::default(); n / 2 + 1];
    for (b, chunk) in x.chunks(block).enumerate() {
        buf.iter_mut().for_each(|v| *v = 0.0);
        buf[..chunk.len()].copy_from_slice(chunk);
        fft.real_forward(&buf, &mut spec);
        for (s, k) in spec.iter_mut().zip(&hs) {
            *s = *s * *k;
        }
        fft.real_inverse(&spec, &mut buf);
        for (i, v) in buf.iter().enumerate() {
            y[b * block + i] += v;
        }
    }
    y.truncate(x.len());
    y
}

struct Run {
    output: Vec<f32>,
    capture: Vec<f32>,
    stats: ProcessingStats,
}

fn run(config: ProcessingConfig, far: &[f32], capture: &[f32]) -> Run {
    let mut apm = AudioProcessing::new(config);
    let mut output = Vec::with_capacity(capture.len());
    for (r, c) in far
        .as_chunks::<FRAME>()
        .0
        .iter()
        .zip(capture.as_chunks::<FRAME>().0)
    {
        apm.process_render(r);
        let mut f = c.to_vec();
        apm.process_capture(&mut f);
        output.extend(f);
    }
    Run {
        output,
        capture: capture.to_vec(),
        stats: apm.stats(),
    }
}

fn power(x: &[f32]) -> f64 {
    x.iter().map(|v| f64::from(*v).powi(2)).sum::<f64>() / x.len().max(1) as f64
}

const ECHO_ONLY: ProcessingConfig = ProcessingConfig {
    high_pass: false,
    echo_cancellation: true,
    noise_suppression: None,
    gain_control: false,
    voice_detection: true,
};

#[test]
fn far_end_echo_is_cancelled_through_an_unknown_delayed_path() {
    let secs = 20;
    let mut far = vec![0.0f32; 48_000 * secs];
    SpeechLike::new(48_000, 31).fill(&mut far);
    for delay_ms in [20usize, 120] {
        let h = room(delay_ms, 60, 0.5, delay_ms as u64);
        let echo = convolve(&far, &h);
        let mut noise = vec![0.0f32; far.len()];
        Noise::new(2, 0.0003).fill(&mut noise);
        let capture: Vec<f32> = echo.iter().zip(&noise).map(|(e, n)| e + n).collect();
        let r = run(ECHO_ONLY, &far, &capture);
        // ERLE over the last 10 s (the suppressor delays the output by 10 ms).
        let from = 48_000 * 10;
        let erle = 10.0
            * (power(&r.capture[from..far.len() - FRAME]) / power(&r.output[from + FRAME..]))
                .log10();
        let found = r.stats.delay.map(|d| d.as_secs_f64() * 1000.0);
        println!(
            "MEASURE AEC: {delay_ms} ms bulk delay + 60 ms tail, ERL {:.1} dB: ERLE {erle:.1} dB \
             (linear filter {:.1} dB), delay found {found:?} ms",
            r.stats.echo_return_loss.unwrap_or_default(),
            r.stats.echo_return_loss_enhancement.unwrap_or_default(),
        );
        assert!(erle > 30.0, "{delay_ms} ms: ERLE {erle:.1} dB");
        let found = found.expect("a delay estimate");
        assert!((found - delay_ms as f64).abs() < 3.0, "{found} ms");
    }
}

#[test]
fn near_end_speech_survives_double_talk() {
    let secs = 16;
    let mut far = vec![0.0f32; 48_000 * secs];
    SpeechLike::new(48_000, 41).fill(&mut far);
    let mut near = vec![0.0f32; 48_000 * secs];
    SpeechLike::new(48_000, 42).fill(&mut near);
    // The near end talks only in the second half.
    near[..48_000 * 8].iter_mut().for_each(|v| *v = 0.0);
    let h = room(40, 50, 0.5, 9);
    let echo = convolve(&far, &h);
    let capture: Vec<f32> = echo.iter().zip(&near).map(|(e, n)| e + n).collect();
    let r = run(ECHO_ONLY, &far, &capture);
    // In the double-talk half, the output is close to the near-end speech alone (10 ms
    // later): much closer than the capture was.
    let from = 48_000 * 9;
    let to = far.len() - FRAME;
    let before = snr_db(&near[from..to], &capture[from..to]);
    let after = snr_db(&near[from..to], &r.output[from + FRAME..to + FRAME]);
    println!(
        "MEASURE AEC double talk: near-end SNR {before:.1} dB in the capture, {after:.1} dB out"
    );
    assert!(after > before + 6.0, "{before:.1} -> {after:.1} dB");
    assert!(after > 8.0, "{after:.1} dB");
}

#[test]
fn with_every_stage_off_the_capture_is_unchanged() {
    let mut x = vec![0.0f32; 48_000];
    SpeechLike::new(48_000, 1).fill(&mut x);
    let r = run(ProcessingConfig::OFF, &x, &x);
    assert_eq!(r.output, x);
}

#[test]
fn the_whole_chain_cancels_echo_and_levels_speech() {
    let secs = 20;
    let mut far = vec![0.0f32; 48_000 * secs];
    SpeechLike::new(48_000, 51).fill(&mut far);
    let mut near = vec![0.0f32; 48_000 * secs];
    SpeechLike::new(48_000, 52).fill(&mut near);
    near.iter_mut().for_each(|v| *v *= 0.1); // a quiet talker, about -40 dBFS
    near[..48_000 * 10].iter_mut().for_each(|v| *v = 0.0);
    let h = room(60, 60, 0.5, 5);
    let echo = convolve(&far, &h);
    let mut noise = vec![0.0f32; far.len()];
    Noise::new(3, 0.001).fill(&mut noise);
    let capture: Vec<f32> = echo
        .iter()
        .zip(&near)
        .zip(&noise)
        .map(|((e, n), z)| e + n + z)
        .collect();
    let r = run(ProcessingConfig::CALL, &far, &capture);
    let echo_out = power(&r.output[48_000 * 6..48_000 * 10]);
    let echo_in = power(&capture[48_000 * 6..48_000 * 10]);
    let erle = 10.0 * (echo_in / echo_out).log10();
    println!(
        "MEASURE full chain: echo and noise down {erle:.1} dB where only the far end talks, gain {:?} dB",
        r.stats.gain_db
    );
    assert!(erle > 30.0, "{erle:.1} dB");
    // The quiet near end is raised towards the target.
    assert!(r.stats.gain_db.unwrap() > 6.0, "{:?}", r.stats.gain_db);
    let lag = best_lag(
        &near[48_000 * 12..48_000 * 13],
        &r.output[48_000 * 12..48_000 * 13],
        2000,
    );
    assert!((FRAME..=FRAME + 100).contains(&lag), "{lag}");
}
