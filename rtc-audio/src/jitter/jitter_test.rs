//! The receive pipeline on a virtual clock: a sender encodes a speech-like signal, a
//! simulated network delays, reorders, duplicates and drops its packets, and playout pulls
//! 10 ms every 10 ms. Numbers are printed with `MEASURE` for `docs/media-pipeline.md`.

use super::*;
use crate::codec::AudioEncoder;
use crate::codec::g711::{G711Decoder, G711Encoder, Law};
use crate::signal::{Rng, SpeechLike};
use rtp::header::Header;

/// One encoded packet on its way.
#[derive(Clone)]
struct Sent {
    header: Header,
    payload: Bytes,
    arrival: Duration,
}

/// The network between the encoder and the buffer.
#[derive(Clone, Copy, Debug)]
struct Net {
    loss: f64,
    base: Duration,
    /// Each packet is delayed by `base` plus up to this much, uniformly (so packets reorder).
    jitter: Duration,
    /// Share of packets sent twice.
    duplicate: f64,
    /// The sender's clock against the receiver's, in parts per million.
    drift_ppm: f64,
    seed: u64,
}

impl Default for Net {
    fn default() -> Self {
        Self {
            loss: 0.0,
            base: Duration::from_millis(30),
            jitter: Duration::ZERO,
            duplicate: 0.0,
            drift_ppm: 0.0,
            seed: 1,
        }
    }
}

/// Encodes `secs` of speech-like audio with `enc` and sends it over `net`.
fn send(
    enc: &mut dyn AudioEncoder,
    pt: u8,
    secs: f64,
    net: Net,
    keep: impl Fn(usize) -> bool,
) -> Vec<Sent> {
    let rate = enc.sample_rate();
    let frame = enc.frame_samples();
    let mut source = SpeechLike::new(rate, net.seed ^ 0xabc);
    let mut rng = Rng::new(net.seed);
    let mut out = Vec::new();
    let frames = (secs * f64::from(rate) / frame as f64) as usize;
    let mut pcm = vec![0.0f32; frame];
    let ptime = frame as f64 / f64::from(rate);
    for k in 0..frames {
        source.fill(&mut pcm);
        let mut payload = Vec::new();
        enc.encode(&pcm, &mut payload).unwrap();
        // The sender's clock runs (1 + drift) times as fast as the receiver's.
        let sent_at = k as f64 * ptime / (1.0 + net.drift_ppm * 1e-6);
        let header = Header {
            version: 2,
            payload_type: pt,
            sequence_number: k as u16,
            timestamp: (k as u64 * u64::from(enc.frame_rtp_duration())) as u32,
            ssrc: 1,
            marker: k == 0,
            ..Default::default()
        };
        let lost = rng.unit() < net.loss || !keep(k);
        let copies = if rng.unit() < net.duplicate { 2 } else { 1 };
        for _ in 0..copies {
            let delay = net.base.as_secs_f64() + net.jitter.as_secs_f64() * rng.unit();
            if !lost {
                out.push(Sent {
                    header: header.clone(),
                    payload: Bytes::from(payload.clone()),
                    arrival: Duration::from_secs_f64(sent_at + delay),
                });
            }
        }
    }
    out.sort_by_key(|s| s.arrival);
    out
}

/// Runs the buffer over `packets` for `secs`, pulling every 10 ms.
fn play(jb: &mut JitterBuffer, packets: &[Sent], secs: f64) -> Vec<f32> {
    let t0 = Instant::now();
    let mut out = Vec::new();
    let mut next = 0;
    let ticks = (secs * 100.0) as u64;
    for tick in 0..ticks {
        let now = Duration::from_millis(tick * 10);
        while next < packets.len() && packets[next].arrival <= now {
            let p = &packets[next];
            jb.insert(t0 + p.arrival, &p.header, &p.payload).unwrap();
            next += 1;
        }
        out.extend(jb.pull(t0 + now).samples);
    }
    out
}

fn g711_buffer(config: JitterBufferConfig) -> JitterBuffer {
    let mut jb = JitterBuffer::new(config);
    jb.register_decoder(0, Box::new(G711Decoder::new(Law::Mu)));
    jb.register_comfort_noise(13, 8000);
    jb.register_telephone_event(101);
    jb
}

fn report(name: &str, s: &ReceiveStats) {
    println!(
        "MEASURE jitter {name}: concealed {:.2} %, mean delay {:.1} ms, target {:.1} ms, \
         accelerate {} / expand {} samples, FEC frames {}, late {}, dup {}, underruns {}",
        100.0 * s.concealment_ratio(),
        s.mean_delay().unwrap_or_default().as_secs_f64() * 1000.0,
        if s.jitter_buffer_emitted_count > 0 {
            1000.0 * s.jitter_buffer_target_delay / s.jitter_buffer_emitted_count as f64
        } else {
            0.0
        },
        s.removed_samples_for_acceleration,
        s.inserted_samples_for_deceleration,
        s.fec_frames_recovered,
        s.packets_late,
        s.packets_duplicated,
        s.underruns,
    );
}

#[test]
fn a_clean_stream_plays_without_concealment_at_one_packet_of_delay() {
    let mut enc = G711Encoder::new(Law::Mu, 20).unwrap();
    let packets = send(&mut enc, 0, 10.0, Net::default(), |_| true);
    let mut jb = g711_buffer(JitterBufferConfig::default());
    let out = play(&mut jb, &packets, 10.0);
    let s = jb.stats().clone();
    report("clean G.711", &s);
    assert_eq!(s.concealed_samples, 0);
    assert_eq!(s.concealment_events, 0);
    // At most one pitch period, while the level settles after the start.
    assert!(
        s.removed_samples_for_acceleration + s.inserted_samples_for_deceleration <= 120,
        "{s:?}"
    );
    // Played from 30 ms (the network) plus the first packet: everything from then on.
    assert!(
        s.total_samples_received >= 8000 * 9,
        "{}",
        s.total_samples_received
    );
    let mean = s.mean_delay().unwrap().as_secs_f64();
    assert!((0.0..=0.030).contains(&mean), "{mean}");
    assert_eq!(out.len(), 48_000 * 10);
    // Every emitted sample is counted once.
    assert!(s.jitter_buffer_emitted_count <= s.total_samples_received);
}

#[test]
fn reordered_and_duplicated_packets_play_in_order_once() {
    let mut enc = G711Encoder::new(Law::Mu, 20).unwrap();
    let net = Net {
        jitter: Duration::from_millis(60),
        duplicate: 0.1,
        ..Default::default()
    };
    let packets = send(&mut enc, 0, 20.0, net, |_| true);
    let mut jb = g711_buffer(JitterBufferConfig::default());
    play(&mut jb, &packets, 20.0);
    let s = jb.stats().clone();
    report("60 ms jitter + 10 % duplicates, G.711", &s);
    assert!(s.packets_duplicated > 50, "{}", s.packets_duplicated);
    // Once the estimate has learnt the jitter, nothing is concealed: under 2 % overall.
    assert!(s.concealment_ratio() < 0.02, "{}", s.concealment_ratio());
    let target = s.jitter_buffer_target_delay / s.jitter_buffer_emitted_count as f64;
    assert!((0.06..=0.11).contains(&target), "target {target}");
}

#[test]
fn the_application_target_sets_the_delay() {
    let mut enc = G711Encoder::new(Law::Mu, 20).unwrap();
    let packets = send(&mut enc, 0, 10.0, Net::default(), |_| true);
    let mut jb = g711_buffer(JitterBufferConfig {
        target_delay: Some(Duration::from_millis(200)),
        ..Default::default()
    });
    play(&mut jb, &packets, 10.0);
    let s = jb.stats().clone();
    report("jitterBufferTarget 200 ms, G.711", &s);
    assert_eq!(s.concealed_samples, 0);
    let mean = s.mean_delay().unwrap().as_secs_f64();
    assert!((0.16..=0.23).contains(&mean), "{mean}");
    // The network alone needs one packet and one pull.
    let minimum = s.jitter_buffer_minimum_delay / s.jitter_buffer_emitted_count as f64;
    assert!((0.029..=0.034).contains(&minimum), "{minimum}");
}

#[test]
fn a_lowered_target_is_reached_by_acceleration() {
    let mut enc = G711Encoder::new(Law::Mu, 20).unwrap();
    let packets = send(&mut enc, 0, 30.0, Net::default(), |_| true);
    let mut jb = g711_buffer(JitterBufferConfig {
        target_delay: Some(Duration::from_millis(300)),
        ..Default::default()
    });
    let t0 = Instant::now();
    let mut next = 0;
    for tick in 0..3000u64 {
        if tick == 1000 {
            jb.set_target_delay(Some(Duration::from_millis(60)));
        }
        let now = Duration::from_millis(tick * 10);
        while next < packets.len() && packets[next].arrival <= now {
            let p = &packets[next];
            jb.insert(t0 + p.arrival, &p.header, &p.payload).unwrap();
            next += 1;
        }
        jb.pull(t0 + now);
    }
    let s = jb.stats().clone();
    report("target 300 -> 60 ms, G.711", &s);
    assert!(
        s.removed_samples_for_acceleration > 8 * 200,
        "{}",
        s.removed_samples_for_acceleration
    );
    let level = jb.buffered_delay().as_secs_f64();
    assert!(level < 0.12, "{level}");
    assert_eq!(s.concealed_samples, 0);
}

#[test]
fn generic_concealment_fills_losses_and_counts_them() {
    let mut enc = G711Encoder::new(Law::Mu, 20).unwrap();
    // Every 10th packet lost.
    let packets = send(&mut enc, 0, 10.0, Net::default(), |k| k % 10 != 5);
    let mut jb = g711_buffer(JitterBufferConfig::default());
    play(&mut jb, &packets, 10.0);
    let s = jb.stats().clone();
    report("10 % periodic loss, G.711", &s);
    // 49 of 500 packets lost, 160 samples each.
    let lost = 49 * 160;
    assert!(
        (lost as u64 - 320..=lost as u64 + 320).contains(&s.concealed_samples),
        "{}",
        s.concealed_samples
    );
    assert!(
        (45..=50).contains(&s.concealment_events),
        "{}",
        s.concealment_events
    );
}

#[test]
fn telephone_events_are_reported_and_never_decoded() {
    let mut jb = g711_buffer(JitterBufferConfig::default());
    let t0 = Instant::now();
    let header = Header {
        payload_type: 101,
        timestamp: 1000,
        marker: true,
        ..Default::default()
    };
    // Event 5, volume 10, duration 400.
    jb.insert(t0, &header, &Bytes::from_static(&[5, 10, 0x01, 0x90]))
        .unwrap();
    assert!(matches!(
        jb.poll_event(),
        Some(ReceiveEvent::TelephoneEvent(
            TelephoneEventReport::Started { event: 5, .. }
        ))
    ));
    assert_eq!(jb.buffered_delay(), Duration::ZERO);
    assert!(
        jb.insert(
            t0,
            &Header {
                payload_type: 77,
                ..Default::default()
            },
            &Bytes::from_static(&[1])
        )
        .is_err()
    );
}

#[test]
fn rfc3389_comfort_noise_plays_the_sid_level_and_is_not_concealment() {
    let mut jb = g711_buffer(JitterBufferConfig::default());
    let mut enc = G711Encoder::new(Law::Mu, 20).unwrap();
    let t0 = Instant::now();
    let mut pcm = vec![0.0f32; 160];
    let mut src = SpeechLike::new(8000, 3);
    // 1 s of speech, a SID at -40 dBov, 2 s of silence, speech again.
    let mut ts = 0u32;
    let mut seq = 0u16;
    let mut out = Vec::new();
    for tick in 0..400u64 {
        let now = t0 + Duration::from_millis(tick * 10);
        if tick % 2 == 0 && !(100..300).contains(&tick) {
            src.fill(&mut pcm);
            let mut payload = Vec::new();
            enc.encode(&pcm, &mut payload).unwrap();
            let h = Header {
                payload_type: 0,
                sequence_number: seq,
                timestamp: ts,
                marker: tick == 300,
                ..Default::default()
            };
            jb.insert(now, &h, &Bytes::from(payload)).unwrap();
            seq = seq.wrapping_add(1);
        }
        if tick == 100 {
            let h = Header {
                payload_type: 13,
                sequence_number: seq,
                timestamp: ts,
                ..Default::default()
            };
            jb.insert(now, &h, &Bytes::from_static(&[40, 127, 127]))
                .unwrap();
            seq = seq.wrapping_add(1);
        }
        if tick % 2 == 0 {
            ts = ts.wrapping_add(160);
        }
        out.push(jb.pull(now));
    }
    let s = jb.stats().clone();
    report("RFC 3389 comfort noise, G.711", &s);
    assert_eq!(s.concealed_samples, 0, "{s:?}");
    // The silence is noise at about -40 dBov (0.01 RMS).
    let noise: Vec<f32> = out[150..280]
        .iter()
        .flat_map(|f| f.samples.clone())
        .collect();
    let rms =
        (noise.iter().map(|v| f64::from(*v).powi(2)).sum::<f64>() / noise.len() as f64).sqrt();
    assert!((0.005..0.02).contains(&rms), "{rms}");
    // Speech resumes after the silence.
    let tail: Vec<f32> = out[330..].iter().flat_map(|f| f.samples.clone()).collect();
    assert!(tail.iter().any(|v| v.abs() > 0.05));
}

#[test]
fn a_flood_of_packets_is_flushed_not_kept() {
    let mut jb = g711_buffer(JitterBufferConfig {
        max_packets: 20,
        ..Default::default()
    });
    let t0 = Instant::now();
    for k in 0..50u32 {
        let h = Header {
            payload_type: 0,
            sequence_number: k as u16,
            timestamp: k * 160,
            ..Default::default()
        };
        jb.insert(t0, &h, &Bytes::from(vec![0xffu8; 160])).unwrap();
    }
    assert!(jb.stats().flushes >= 1);
    assert!(jb.buffered_delay() <= Duration::from_millis(400));
}

#[cfg(feature = "opus")]
mod opus {
    use super::*;
    use crate::codec::fmtp::OpusEncoderConfig;
    use crate::codec::opus::{OpusDecoder, OpusEncoder};

    fn opus_buffer(config: JitterBufferConfig) -> JitterBuffer {
        let mut jb = JitterBuffer::new(config);
        jb.register_decoder(111, Box::new(OpusDecoder::new(1).unwrap()));
        jb.register_red(63);
        jb
    }

    fn encoder(fec: bool, loss: u8) -> OpusEncoder {
        OpusEncoder::new(OpusEncoderConfig {
            fec,
            packet_loss_percent: loss,
            ..Default::default()
        })
        .unwrap()
    }

    #[test]
    fn in_band_fec_recovers_isolated_losses() {
        let net = Net {
            loss: 0.05,
            jitter: Duration::from_millis(20),
            seed: 7,
            ..Default::default()
        };
        let run = |fec: bool| {
            let mut enc = encoder(fec, 10);
            let packets = send(&mut enc, 111, 20.0, net, |_| true);
            let mut jb = opus_buffer(JitterBufferConfig::default());
            play(&mut jb, &packets, 20.0);
            jb.stats().clone()
        };
        let with = run(true);
        let without = run(false);
        report("5 % loss, Opus with FEC", &with);
        report("5 % loss, Opus without FEC", &without);
        assert!(
            with.fec_frames_recovered > 20,
            "{}",
            with.fec_frames_recovered
        );
        assert!(
            with.concealed_samples * 2 < without.concealed_samples,
            "{} vs {}",
            with.concealed_samples,
            without.concealed_samples
        );
    }

    #[test]
    fn clock_drift_of_200_ppm_either_way_is_absorbed() {
        for drift in [200.0, -200.0] {
            let net = Net {
                drift_ppm: drift,
                jitter: Duration::from_millis(10),
                ..Default::default()
            };
            let mut enc = encoder(true, 0);
            let packets = send(&mut enc, 111, 120.0, net, |_| true);
            let mut jb = opus_buffer(JitterBufferConfig::default());
            play(&mut jb, &packets, 120.0);
            let s = jb.stats().clone();
            report(&format!("{drift:+} ppm drift, Opus, 120 s"), &s);
            // 200 ppm of 120 s is 24 ms (1152 samples at 48 kHz). Part of it moves the level
            // within the band the target allows; the rest is removed or inserted.
            if drift > 0.0 {
                assert!(
                    s.removed_samples_for_acceleration > s.inserted_samples_for_deceleration,
                    "{s:?}"
                );
            } else {
                assert!(s.inserted_samples_for_deceleration > 0, "{s:?}");
            }
            assert!(s.concealment_ratio() < 0.005, "{s:?}");
            // The delay stayed bounded: the drift did not accumulate.
            let level = jb.buffered_delay().as_secs_f64();
            assert!(level < 0.08, "{level}");
        }
    }

    #[test]
    fn dtx_silence_is_comfort_noise_and_not_concealment() {
        let mut enc = OpusEncoder::new(OpusEncoderConfig {
            dtx: true,
            ..Default::default()
        })
        .unwrap();
        // Speech, 3 s of digital silence (DTX), speech; the sender skips what DTX left out.
        let mut jb = opus_buffer(JitterBufferConfig::default());
        let t0 = Instant::now();
        let mut src = SpeechLike::new(48_000, 4);
        let mut pcm = vec![0.0f32; 960];
        let mut in_dtx = false;
        let mut seq = 0u16;
        let mut sent = 0usize;
        for tick in 0..800u64 {
            let now = t0 + Duration::from_millis(tick * 10);
            if tick % 2 == 0 {
                let k = tick / 2;
                if (100..250).contains(&k) {
                    pcm.iter_mut().for_each(|v| *v = 0.0);
                } else {
                    src.fill(&mut pcm);
                }
                let mut payload = Vec::new();
                enc.encode(&pcm, &mut payload).unwrap();
                let dtx = payload.len() <= 2;
                // libwebrtc's rule: send the first DTX packet, skip the rest.
                if !(dtx && in_dtx) {
                    let h = Header {
                        payload_type: 111,
                        sequence_number: seq,
                        timestamp: (k * 960) as u32,
                        marker: in_dtx && !dtx,
                        ..Default::default()
                    };
                    jb.insert(now + Duration::from_millis(30), &h, &Bytes::from(payload))
                        .unwrap();
                    seq = seq.wrapping_add(1);
                    sent += 1;
                }
                in_dtx = dtx;
            }
            jb.pull(now + Duration::from_millis(30));
        }
        let s = jb.stats().clone();
        report("Opus DTX", &s);
        assert!(sent < 300, "{sent} packets sent");
        assert_eq!(s.concealed_samples, 0, "{s:?}");
        assert!(s.total_samples_received >= 48_000 * 7);
    }

    #[test]
    fn red_recovers_lost_primaries_from_the_next_packet() {
        let mut enc = encoder(false, 0);
        let mut red = rtp::codec::red::RedEncoder::new(1, 1200);
        let net = Net {
            loss: 0.1,
            seed: 3,
            ..Default::default()
        };
        let plain = send(&mut enc, 111, 10.0, Net { loss: 0.0, ..net }, |_| true);
        // Wrap every packet in RED (one redundant copy), then lose 10 %.
        let mut rng = Rng::new(99);
        let mut packets = Vec::new();
        for p in &plain {
            let payload = red
                .encode(111, p.header.timestamp, p.payload.clone())
                .unwrap();
            if rng.unit() >= net.loss {
                let mut h = p.header.clone();
                h.payload_type = 63;
                packets.push(Sent {
                    header: h,
                    payload,
                    arrival: p.arrival,
                });
            }
        }
        let mut jb = opus_buffer(JitterBufferConfig {
            target_delay: Some(Duration::from_millis(60)),
            ..Default::default()
        });
        play(&mut jb, &packets, 10.0);
        let s = jb.stats().clone();
        report("10 % loss, Opus in RED", &s);
        assert!(s.red_packets_recovered > 20, "{s:?}");
        assert!(s.concealment_ratio() < 0.02, "{s:?}");
    }
}
