//! Real encoded streams the repository has (`examples/test-data`: libvpx VP8 and VP9 IVF,
//! H.264 and H.265 Annex B), packetized with the engine's payloaders, sent through a seeded
//! network that loses, delays and reorders packets and retransmits lost ones a round trip
//! later (as NACK and RTX would), and received by the pipeline. Every picture released must be
//! byte for byte what was sent (NAL units for H.264 / H.265) and decodable in the order
//! released.

use std::collections::HashMap;
use std::path::Path;
use std::time::{Duration, Instant};

use bytes::Bytes;
use rtci::rtp::codec::h264::H264Payloader;
use rtci::rtp::codec::h265::HevcPayloader;
use rtci::rtp::codec::vp8::Vp8Payloader;
use rtci::rtp::codec::vp9::Vp9Payloader;
use rtci::rtp::packetizer::Payloader;
use rtci_video::decoder::{ReferenceCheckingDecoder, VideoDecoder};
use rtci_video::frame::VideoPacket;
use rtci_video::picture::I420Buffer;
use rtci_video::{Codec, DecodeOutcome, ReceiveConfig, ReceivePipeline};

struct Rng(u64);

impl Rng {
    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    fn unit(&mut self) -> f64 {
        (self.next_u64() >> 11) as f64 / (1u64 << 53) as f64
    }
}

fn test_data(name: &str) -> Vec<u8> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../examples/test-data")
        .join(name);
    std::fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

/// The frames of an IVF file.
fn ivf_frames(data: &[u8]) -> Vec<Bytes> {
    let header = u16::from_le_bytes([data[6], data[7]]) as usize;
    let mut off = header;
    let mut out = Vec::new();
    while off + 12 <= data.len() {
        let size = u32::from_le_bytes(data[off..off + 4].try_into().unwrap()) as usize;
        out.push(Bytes::copy_from_slice(&data[off + 12..off + 12 + size]));
        off += 12 + size;
    }
    out
}

/// The NAL units of an Annex B stream, without start codes.
fn nal_units(data: &[u8]) -> Vec<&[u8]> {
    let mut starts = Vec::new();
    let mut i = 0;
    while i + 3 <= data.len() {
        if data[i] == 0 && data[i + 1] == 0 && data[i + 2] == 1 {
            starts.push(i + 3);
            i += 3;
        } else {
            i += 1;
        }
    }
    let mut out = Vec::new();
    for (k, &s) in starts.iter().enumerate() {
        let mut end = starts.get(k + 1).map_or(data.len(), |n| n - 3);
        while end > s && data[end - 1] == 0 {
            end -= 1;
        }
        out.push(&data[s..end]);
    }
    out
}

/// Access units of an Annex B stream: a slice whose first slice flag is set (the first bit
/// of the slice header: first_mb_in_slice == 0 for H.264, first_slice_segment_in_pic_flag
/// for H.265) starts one, with the parameter sets and SEI before it.
fn access_units(data: &[u8], hevc: bool) -> Vec<Vec<Vec<u8>>> {
    let mut units: Vec<Vec<Vec<u8>>> = Vec::new();
    let mut pending: Vec<Vec<u8>> = Vec::new();
    let mut seen_slice = false;
    for nal in nal_units(data) {
        if nal.is_empty() {
            continue;
        }
        let (is_slice, first) = if hevc {
            let t = (nal[0] >> 1) & 0x3f;
            (t < 32, nal.get(2).is_some_and(|b| b & 0x80 != 0))
        } else {
            let t = nal[0] & 0x1f;
            (
                (1..=5).contains(&t),
                nal.get(1).is_some_and(|b| b & 0x80 != 0),
            )
        };
        if is_slice {
            if first || !seen_slice {
                let mut unit = std::mem::take(&mut pending);
                unit.push(nal.to_vec());
                units.push(unit);
            } else if let Some(last) = units.last_mut() {
                last.extend(std::mem::take(&mut pending));
                last.push(nal.to_vec());
            }
            seen_slice = true;
        } else {
            pending.push(nal.to_vec());
        }
    }
    units
}

fn annexb(nals: &[Vec<u8>]) -> Bytes {
    let mut v = Vec::new();
    for n in nals {
        v.extend_from_slice(&[0, 0, 0, 1]);
        v.extend_from_slice(n);
    }
    Bytes::from(v)
}

struct Network {
    loss: f64,
    delay: Duration,
    jitter: Duration,
    rtt: Duration,
    seed: u64,
}

struct Outcome {
    released: usize,
    decoded: usize,
    mismatched: usize,
    decoder_errors: u64,
    key_frame_requests: u32,
    lost_for_good: usize,
    freezes: u32,
    longest_ms: f64,
    broken_chain: usize,
    /// Decoded pictures that differ from decoding the source stream directly, in order.
    pictures_differ: usize,
}

fn run(codec: Codec, frames: &[Bytes], payloader: Box<dyn Payloader>, net: Network) -> Outcome {
    run_with(
        codec,
        frames,
        payloader,
        net,
        &mut ReferenceCheckingDecoder::new((0, 0)),
        None,
    )
}

/// `reference`: the picture of each frame of the source decoded in order, when `decoder` is a
/// real decoder; every picture it decodes from the pipeline's output must be that one.
fn run_with(
    codec: Codec,
    frames: &[Bytes],
    mut payloader: Box<dyn Payloader>,
    net: Network,
    decoder: &mut dyn VideoDecoder,
    reference: Option<&[I420Buffer]>,
) -> Outcome {
    let t0 = Instant::now();
    let mut rng = Rng(net.seed);
    let interval = Duration::from_micros(33_367);
    let mut arrivals: Vec<(Instant, VideoPacket)> = Vec::new();
    let mut seq: u16 = 65_000;
    let mut lost_for_good = 0;
    let mut sent: HashMap<u32, Bytes> = HashMap::new();
    let mut index_of: HashMap<u32, usize> = HashMap::new();
    for (i, frame) in frames.iter().enumerate() {
        let send = t0 + interval * i as u32;
        let ts = (i as u32).wrapping_mul(3003).wrapping_add(0xffff_0000);
        sent.insert(ts, frame.clone());
        index_of.insert(ts, i);
        let payloads = payloader.payload(1200, frame).expect("payloads");
        let n = payloads.len();
        for (k, payload) in payloads.into_iter().enumerate() {
            let packet = VideoPacket {
                arrival: send,
                sequence_number: seq,
                timestamp: ts,
                marker: k + 1 == n,
                payload_type: 96,
                ssrc: 7,
                payload,
                dependency_descriptor: None,
                playout_delay_ms: None,
                retransmitted: false,
            };
            seq = seq.wrapping_add(1);
            // First transmission, then a retransmission a round trip after each loss.
            let mut at = send;
            let mut delivered = false;
            for attempt in 0..10 {
                let arrival =
                    at + net.delay + Duration::from_secs_f64(net.jitter.as_secs_f64() * rng.unit());
                if rng.unit() >= net.loss {
                    let mut p = packet.clone();
                    p.arrival = arrival;
                    arrivals.push((arrival, p));
                    delivered = true;
                    break;
                }
                at += net.rtt + net.jitter + Duration::from_millis(5 * attempt);
            }
            if !delivered {
                lost_for_good += 1;
            }
        }
    }
    arrivals.sort_by_key(|a| a.0);
    let mut pipeline = ReceivePipeline::new(codec, t0, ReceiveConfig::default());
    pipeline.set_rtt(net.rtt);
    let mut decoder_errors = 0;
    let mut out = Outcome {
        released: 0,
        decoded: 0,
        mismatched: 0,
        decoder_errors: 0,
        key_frame_requests: 0,
        lost_for_good,
        freezes: 0,
        longest_ms: 0.0,
        broken_chain: 0,
        pictures_differ: 0,
    };
    let end = t0 + interval * frames.len() as u32 + Duration::from_secs(3);
    let mut next = 0;
    let mut last_released: Option<usize> = None;
    let mut now = t0;
    while now < end {
        while next < arrivals.len() && arrivals[next].0 <= now {
            pipeline.insert_packet(arrivals[next].1.clone());
            next += 1;
        }
        pipeline.handle_timeout(now);
        while pipeline.poll_key_frame_request().is_some() {
            out.key_frame_requests += 1;
        }
        while let Some(request) = pipeline.poll_frame(now) {
            out.released += 1;
            let ts = request.frame.frame.rtp_timestamp;
            // The fixtures are I-P-P-...: a delta picture needs the picture before it, which
            // the stream itself says, whatever the pipeline's reference finder concluded.
            let index = index_of[&ts];
            if !request.frame.is_keyframe() && last_released != Some(index.wrapping_sub(1)) {
                out.broken_chain += 1;
            }
            last_released = Some(index);
            let expected = &sent[&ts];
            let same = match codec {
                Codec::H264 | Codec::H265 => nal_units(expected) == nal_units(request.frame.data()),
                _ => expected == request.frame.data(),
            };
            if !same {
                out.mismatched += 1;
            }
            let outcome = match decoder.decode(&request.frame) {
                Ok(_) => {
                    out.decoded += 1;
                    if let Some(reference) = reference {
                        let same = decoder
                            .picture()
                            .is_some_and(|p| p.to_buffer() == reference[index]);
                        if !same {
                            out.pictures_differ += 1;
                        }
                    }
                    DecodeOutcome::Decoded {
                        width: 176,
                        height: 144,
                        qp: None,
                        decode_time: Duration::from_millis(1),
                        request_key_frame: false,
                    }
                }
                Err(_) => {
                    decoder_errors += 1;
                    DecodeOutcome::Failed
                }
            };
            pipeline.on_decoded(now, request.token, outcome);
            pipeline.on_rendered(request.render_time.unwrap_or(now).max(now));
        }
        now += Duration::from_millis(1);
    }
    out.decoder_errors = decoder_errors;
    let s = pipeline.stats(now);
    out.freezes = s.freeze_count;
    out.longest_ms = s.longest_render_interval * 1000.0;
    println!(
        "MEASURE {codec:?} loss {:.0}%: frames {} released {} decoded {} mismatched {} errors {} \
         lost for good {} key frame requests {} dropped {} freezes {} longest {:.0} ms \
         decoder {} pictures differing {}",
        net.loss * 100.0,
        frames.len(),
        out.released,
        out.decoded,
        out.mismatched,
        out.decoder_errors,
        out.lost_for_good,
        out.key_frame_requests,
        s.frames_dropped,
        s.freeze_count,
        s.longest_render_interval * 1000.0,
        decoder.implementation_name(),
        out.pictures_differ,
    );
    out
}

fn lossy(seed: u64) -> Network {
    Network {
        loss: 0.05,
        delay: Duration::from_millis(25),
        jitter: Duration::from_millis(40),
        rtt: Duration::from_millis(60),
        seed,
    }
}

fn check(codec: Codec, frames: &[Bytes], payloader: impl Fn() -> Box<dyn Payloader>) {
    let clean = run(
        codec,
        frames,
        payloader(),
        Network {
            loss: 0.0,
            jitter: Duration::ZERO,
            ..lossy(1)
        },
    );
    assert_eq!(
        clean.released,
        frames.len(),
        "every frame released on a clean link"
    );
    assert_eq!(
        (clean.mismatched, clean.decoder_errors, clean.broken_chain),
        (0, 0, 0)
    );
    let o = run(codec, frames, payloader(), lossy(2));
    assert_eq!(o.mismatched, 0, "every released picture is what was sent");
    assert_eq!(
        o.broken_chain, 0,
        "no delta picture before the one it predicts from"
    );
    assert_eq!(
        o.decoder_errors, 0,
        "released in an order its references allow"
    );
    assert_eq!(o.lost_for_good, 0, "the seed loses nothing for good");
    // Repairs a round trip after each loss (60 ms) and 0..40 ms of jitter: no W3C freeze.
    assert_eq!(
        o.freezes, 0,
        "freezes (longest interval {:.0} ms)",
        o.longest_ms
    );
    assert!(
        o.decoded * 100 >= frames.len() * 99,
        "decoded {} of {}",
        o.decoded,
        frames.len()
    );
}

#[test]
fn vp8_ivf_survives_loss_and_reordering_intact() {
    let frames = ivf_frames(&test_data("output_vp8.ivf"));
    assert_eq!(frames.len(), 300);
    check(Codec::Vp8, &frames, || {
        let mut p = Vp8Payloader::default();
        p.enable_picture_id = true;
        Box::new(p)
    });
}

#[test]
fn vp9_ivf_survives_loss_and_reordering_intact() {
    let frames = ivf_frames(&test_data("output_vp9.ivf"));
    assert_eq!(frames.len(), 300);
    check(Codec::Vp9, &frames, || {
        let mut p = Vp9Payloader::default();
        p.initial_picture_id_fn = Some(std::sync::Arc::new(|| 1000));
        Box::new(p)
    });
}

#[test]
fn h264_annexb_survives_loss_and_reordering_intact() {
    let units = access_units(&test_data("output.264"), false);
    let frames: Vec<Bytes> = units.iter().map(|u| annexb(u)).collect();
    assert!(frames.len() > 100, "{} access units", frames.len());
    check(Codec::H264, &frames, || Box::<H264Payloader>::default());
}

#[test]
fn h265_annexb_survives_loss_and_reordering_intact() {
    let units = access_units(&test_data("output.265"), true);
    let frames: Vec<Bytes> = units.iter().map(|u| annexb(u)).collect();
    assert!(frames.len() > 100, "{} access units", frames.len());
    check(Codec::H265, &frames, || Box::<HevcPayloader>::default());
}

/// The VP8 fixture through the lossy, reordering network into the real VP8 decoder (feature
/// `vp8`): every picture the pipeline lets it decode is bit for bit the picture of that frame
/// when the source file is decoded in order, and none fails.
#[cfg(feature = "vp8")]
#[test]
fn vp8_ivf_through_loss_decodes_bit_exactly_with_the_vp8_decoder() {
    use rtci_video::codec::vp8::Vp8Decoder;
    let frames = ivf_frames(&test_data("output_vp8.ivf"));
    let mut direct = Vp8Decoder::new();
    let reference: Vec<I420Buffer> = frames
        .iter()
        .map(|f| {
            direct.decode_bytes(f).expect("the fixture decodes");
            direct.picture().expect("shown").to_buffer()
        })
        .collect();
    let payloader = || {
        let mut p = Vp8Payloader::default();
        p.enable_picture_id = true;
        Box::new(p) as Box<dyn Payloader>
    };
    for net in [
        Network {
            loss: 0.0,
            jitter: Duration::ZERO,
            ..lossy(1)
        },
        lossy(2),
    ] {
        let loss = net.loss;
        let o = run_with(
            Codec::Vp8,
            &frames,
            payloader(),
            net,
            &mut Vp8Decoder::new(),
            Some(&reference),
        );
        assert_eq!(o.decoder_errors, 0, "loss {loss}: decode errors");
        assert_eq!(o.pictures_differ, 0, "loss {loss}: pictures differ");
        assert!(
            o.decoded * 100 >= frames.len() * 99,
            "loss {loss}: decoded {}",
            o.decoded
        );
        assert_eq!(o.freezes, 0, "loss {loss}: freezes");
    }
}

/// An AV1 stream from rav1e (feature `av1`; the synthetic source at 160x96, 60 pictures,
/// key frame first) through the lossy, reordering network into rav1d: every picture decoded
/// from the pipeline's output is bit for bit the picture of decoding the stream in order.
#[cfg(feature = "av1")]
#[test]
fn av1_from_rav1e_through_loss_decodes_bit_exactly_with_rav1d() {
    use rtci::rtp::codec::av1::Av1Payloader;
    use rtci_video::codec::av1::{Av1Decoder, Av1Encoder};
    use rtci_video::encoder::VideoEncoder;
    use rtci_video::picture::TestSource;
    let mut source = TestSource::new(160, 96);
    let mut enc = Av1Encoder::new(160, 96, 30, 200_000, 10).expect("encoder");
    let mut tus = Vec::new();
    for i in 0..60 {
        tus.extend(
            enc.encode(&source.next_picture().view(), i == 0)
                .expect("encode"),
        );
    }
    tus.extend(enc.flush().expect("flush"));
    assert_eq!(tus.len(), 60);
    let frames: Vec<Bytes> = tus.iter().map(|t| Bytes::from(t.data.clone())).collect();
    let mut direct = Av1Decoder::new().expect("decoder");
    let reference: Vec<I420Buffer> = tus
        .iter()
        .map(|t| {
            direct
                .decode_bytes(&t.data, t.keyframe)
                .expect("decodes")
                .expect("a picture");
            direct.picture().expect("picture").to_buffer()
        })
        .collect();
    for net in [
        Network {
            loss: 0.0,
            jitter: Duration::ZERO,
            ..lossy(1)
        },
        lossy(3),
    ] {
        let loss = net.loss;
        let o = run_with(
            Codec::Av1,
            &frames,
            Box::<Av1Payloader>::default(),
            net,
            &mut Av1Decoder::new().expect("decoder"),
            Some(&reference),
        );
        // The payload format rewrites the OBUs (temporal delimiters dropped, size fields
        // removed and restored), so the bytes differ from rav1e's; the pictures may not.
        assert_eq!(o.decoder_errors, 0, "loss {loss}: decode errors");
        assert_eq!(o.pictures_differ, 0, "loss {loss}: pictures differ");
        assert!(
            o.decoded * 100 >= frames.len() * 95,
            "loss {loss}: decoded {}",
            o.decoded
        );
    }
}
