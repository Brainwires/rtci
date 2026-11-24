//! Time-stretching by whole pitch periods (the method of libwebrtc NetEq's accelerate and
//! preemptive expand, a WSOLA variant): find the lag at which the signal best repeats
//! itself, then remove one period by cross-fading two consecutive periods into one, or
//! insert one by cross-fading a period into a copy of itself. Voiced speech keeps its pitch
//! and formants; quiet or unvoiced audio is stretched wherever it is, since there nothing
//! audible depends on the lag.

/// The shortest lag searched: 2.5 ms (a 400 Hz pitch).
pub const MIN_LAG_SECS: f64 = 0.0025;
/// The longest lag searched: 15 ms (a 67 Hz pitch). A stretch needs `2 * MAX_LAG` of input.
pub const MAX_LAG_SECS: f64 = 0.015;
/// The normalised correlation above which voiced audio is stretched (NetEq's 0.9).
pub const CORRELATION_THRESHOLD: f64 = 0.9;
/// Below this mean square (about -45 dBFS) audio counts as quiet: stretched at any
/// correlation.
pub const QUIET_POWER: f64 = 3e-5;

/// What a stretch did.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Stretch {
    /// The lag in samples per channel: the number removed or inserted.
    pub lag: usize,
    /// The normalised correlation at that lag.
    pub correlation: f64,
}

fn mono_mix(input: &[f32], channels: usize, len: usize) -> Vec<f32> {
    (0..len)
        .map(|i| {
            let mut s = 0.0;
            for c in 0..channels {
                s += input[i * channels + c];
            }
            s / channels as f32
        })
        .collect()
}

fn normalised_correlation(x: &[f32], lag: usize) -> f64 {
    let (mut xy, mut xx, mut yy) = (0.0f64, 0.0f64, 0.0f64);
    for i in 0..lag {
        let a = f64::from(x[i]);
        let b = f64::from(x[i + lag]);
        xy += a * b;
        xx += a * a;
        yy += b * b;
    }
    if xx <= 1e-12 || yy <= 1e-12 {
        return 0.0;
    }
    xy / (xx * yy).sqrt()
}

/// The best lag of `mono` (at least `2 * max_lag` samples): a coarse search on a 4x
/// decimated copy, refined at full rate.
fn best_lag(mono: &[f32], min_lag: usize, max_lag: usize) -> (usize, f64) {
    let decimation = 4;
    let coarse: Vec<f32> = mono
        .chunks_exact(decimation)
        .map(|c| c.iter().sum::<f32>() / decimation as f32)
        .collect();
    let (lo, hi) = (
        (min_lag / decimation).max(1),
        (max_lag / decimation).min(coarse.len() / 2),
    );
    let mut best = (lo, f64::MIN);
    for lag in lo..=hi.max(lo) {
        if 2 * lag > coarse.len() {
            break;
        }
        let c = normalised_correlation(&coarse, lag);
        if c > best.1 {
            best = (lag, c);
        }
    }
    let centre = best.0 * decimation;
    let mut fine = (centre.clamp(min_lag, max_lag), f64::MIN);
    for lag in centre.saturating_sub(decimation)..=centre + decimation {
        if lag < min_lag || lag > max_lag || 2 * lag > mono.len() {
            continue;
        }
        let c = normalised_correlation(mono, lag);
        if c > fine.1 {
            fine = (lag, c);
        }
    }
    fine
}

fn lags(sample_rate: u32) -> (usize, usize) {
    let rate = f64::from(sample_rate.max(1));
    (
        (MIN_LAG_SECS * rate).round() as usize,
        (MAX_LAG_SECS * rate).round() as usize,
    )
}

/// The lag (2.5 to 15 ms) at which mono audio `mono` best repeats itself, and the normalised
/// correlation there. `mono` needs `2 * MAX_LAG` samples for the whole range.
pub fn find_lag(mono: &[f32], sample_rate: u32) -> (usize, f64) {
    let (min_lag, max_lag) = lags(sample_rate);
    let max_lag = max_lag
        .min(mono.len() / 2)
        .max(min_lag.min(mono.len() / 2))
        .max(1);
    best_lag(mono, min_lag.min(max_lag), max_lag)
}

/// The input a stretch needs, in samples per channel (`2 * MAX_LAG`).
pub fn required_input(sample_rate: u32) -> usize {
    2 * lags(sample_rate).1
}

/// Whether the stretch may go ahead at this lag and correlation.
fn acceptable(mono: &[f32], lag: usize, correlation: f64) -> bool {
    let power = mono[..2 * lag]
        .iter()
        .map(|s| f64::from(*s).powi(2))
        .sum::<f64>()
        / (2 * lag) as f64;
    correlation >= CORRELATION_THRESHOLD || power < QUIET_POWER
}

/// Removes one pitch period from the start of `input` (interleaved, `channels`), writing the
/// result to `out`. `None`, with `input` copied to `out`, when the audio is voiced but does
/// not repeat well enough, or is too short ([`required_input`]).
pub fn accelerate(
    input: &[f32],
    channels: u16,
    sample_rate: u32,
    out: &mut Vec<f32>,
) -> Option<Stretch> {
    let ch = usize::from(channels.max(1));
    let n = input.len() / ch;
    let (min_lag, max_lag) = lags(sample_rate);
    if n < 2 * max_lag {
        out.extend_from_slice(input);
        return None;
    }
    let mono = mono_mix(input, ch, 2 * max_lag);
    let (lag, correlation) = best_lag(&mono, min_lag, max_lag);
    if !acceptable(&mono, lag, correlation) {
        out.extend_from_slice(input);
        return None;
    }
    // y[0..L] = x[0..L] fading out + x[L..2L] fading in; then x[2L..].
    for i in 0..lag {
        let w = (i as f32 + 0.5) / lag as f32;
        for c in 0..ch {
            out.push(input[i * ch + c] * (1.0 - w) + input[(i + lag) * ch + c] * w);
        }
    }
    out.extend_from_slice(&input[2 * lag * ch..]);
    Some(Stretch { lag, correlation })
}

/// Inserts one pitch period near the start of `input` (interleaved, `channels`), writing the
/// result to `out`. `None`, with `input` copied to `out`, as for [`accelerate`].
pub fn preemptive_expand(
    input: &[f32],
    channels: u16,
    sample_rate: u32,
    out: &mut Vec<f32>,
) -> Option<Stretch> {
    let ch = usize::from(channels.max(1));
    let n = input.len() / ch;
    let (min_lag, max_lag) = lags(sample_rate);
    if n < 2 * max_lag {
        out.extend_from_slice(input);
        return None;
    }
    let mono = mono_mix(input, ch, 2 * max_lag);
    let (lag, correlation) = best_lag(&mono, min_lag, max_lag);
    if !acceptable(&mono, lag, correlation) {
        out.extend_from_slice(input);
        return None;
    }
    // y = x[0..L], then x[L..2L] fading out + x[0..L] fading in, then x[L..].
    out.extend_from_slice(&input[..lag * ch]);
    for i in 0..lag {
        let w = (i as f32 + 0.5) / lag as f32;
        for c in 0..ch {
            out.push(input[(i + lag) * ch + c] * (1.0 - w) + input[i * ch + c] * w);
        }
    }
    out.extend_from_slice(&input[lag * ch..]);
    Some(Stretch { lag, correlation })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signal::Tone;

    fn tone(hz: f64, n: usize) -> Vec<f32> {
        let mut t = Tone::new(48_000, hz, 0.5);
        let mut v = vec![0.0f32; n];
        t.fill(&mut v);
        v
    }

    /// The largest jump between neighbouring samples, against the largest a clean sine of
    /// this frequency has.
    fn max_step(x: &[f32]) -> f32 {
        x.windows(2)
            .map(|w| (w[1] - w[0]).abs())
            .fold(0.0, f32::max)
    }

    #[test]
    fn a_periodic_signal_loses_or_gains_whole_periods_without_a_click() {
        // 200 Hz: a 240-sample period at 48 kHz.
        let x = tone(200.0, 1440);
        let clean = max_step(&x);
        let mut out = Vec::new();
        let s = accelerate(&x, 1, 48_000, &mut out).expect("a sine repeats");
        assert_eq!(s.lag % 240, 0, "{s:?}");
        assert_eq!(out.len(), 1440 - s.lag);
        assert!(max_step(&out) <= clean * 1.05);
        out.clear();
        let s = preemptive_expand(&x, 1, 48_000, &mut out).expect("a sine repeats");
        assert_eq!(s.lag % 240, 0, "{s:?}");
        assert_eq!(out.len(), 1440 + s.lag);
        assert!(max_step(&out) <= clean * 1.05);
    }

    #[test]
    fn loud_noise_is_left_alone_and_quiet_noise_is_stretched() {
        let mut noise = crate::signal::Noise::new(4, 0.2);
        let mut x = vec![0.0f32; 1440];
        noise.fill(&mut x);
        let mut out = Vec::new();
        assert!(accelerate(&x, 1, 48_000, &mut out).is_none());
        assert_eq!(out, x);
        let mut quiet = crate::signal::Noise::new(4, 0.001);
        quiet.fill(&mut x);
        out.clear();
        assert!(accelerate(&x, 1, 48_000, &mut out).is_some());
        assert!(out.len() < x.len());
    }

    #[test]
    fn stereo_is_stretched_on_both_channels_alike() {
        let m = tone(150.0, 1440);
        let x: Vec<f32> = m.iter().flat_map(|&s| [s, -s]).collect();
        let mut out = Vec::new();
        let s = accelerate(&x, 2, 48_000, &mut out);
        // The mono mix of (s, -s) is silence: quiet, so it is stretched anywhere.
        assert!(s.is_some());
        for p in out.as_chunks::<2>().0 {
            assert!((p[0] + p[1]).abs() < 1e-6);
        }
    }
}
