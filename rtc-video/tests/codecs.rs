//! The pure-Rust codec backends (features `vp8` and `av1`): quality at the design's operating
//! point, and robustness against hostile input (docs/video-pipeline.md 4.6 and phase 2).
//!
//! Conformance (the WebM VP8 test vectors, libaom's AV1 vectors against dav1d) and speed are
//! measured by `scripts/video-codec-check.sh` on a hosted runner, with data fetched there.

use std::panic::{AssertUnwindSafe, catch_unwind};

mod common {
    pub mod md5;
}

use rtc_video::codec::av1::{Av1Decoder, Av1Encoder};
use rtc_video::codec::vp8::{Vp8Decoder, Vp8Encoder};
use rtc_video::decoder::VideoDecoder;
use rtc_video::encoder::VideoEncoder;
use rtc_video::picture::{TestSource, psnr};

fn test_data(name: &str) -> Vec<u8> {
    let path = format!(
        "{}/../examples/test-data/{name}",
        env!("CARGO_MANIFEST_DIR")
    );
    std::fs::read(&path).unwrap_or_else(|e| panic!("{path}: {e}"))
}

fn ivf_frames(data: &[u8]) -> Vec<Vec<u8>> {
    let header = u16::from_le_bytes([data[6], data[7]]) as usize;
    let mut out = Vec::new();
    let mut at = header;
    while at + 12 <= data.len() {
        let size =
            u32::from_le_bytes([data[at], data[at + 1], data[at + 2], data[at + 3]]) as usize;
        at += 12;
        out.push(data[at..at + size].to_vec());
        at += size;
    }
    out
}

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next() % n.max(1) as u64) as usize
    }
}

/// One hostile variant of `frame`: bytes flipped, the frame cut short or lengthened with
/// garbage, or a run of random bytes written over it.
fn mutate(rng: &mut Rng, frame: &[u8]) -> Vec<u8> {
    let mut f = frame.to_vec();
    match rng.below(4) {
        0 => {
            for _ in 0..1 + rng.below(8) {
                let i = rng.below(f.len());
                f[i] ^= 1 << rng.below(8);
            }
        }
        1 => f.truncate(rng.below(f.len())),
        2 => {
            for _ in 0..rng.below(64) {
                f.push(rng.next() as u8);
            }
        }
        _ => {
            let start = rng.below(f.len());
            for b in f.iter_mut().skip(start).take(1 + rng.below(32)) {
                *b = rng.next() as u8;
            }
        }
    }
    f
}

/// The design's operating point (docs/video-pipeline.md phase 2): VP8 at 640x360 and
/// 600 kbit/s on the synthetic source decodes at 32 dB PSNR or better, at about the rate.
#[test]
fn vp8_at_640x360_and_600_kbits_reaches_32_db() {
    let (w, h, fps, rate) = (640, 360, 30, 600_000);
    let mut source = TestSource::new(w, h);
    let mut enc = Vp8Encoder::new(w, h, fps, rate).expect("encoder");
    let mut dec = Vp8Decoder::new();
    let (mut sum, mut n, mut bytes) = (0.0, 0, 0usize);
    let frames = 90;
    for i in 0..frames {
        let pic = source.next_picture();
        if let Some(f) = enc.encode(&pic.view(), i == 0).expect("encode") {
            bytes += f.data.len();
            dec.decode_bytes(&f.data).expect("decode").expect("shown");
            sum += psnr(&pic.view(), &dec.picture().expect("picture")).expect("size");
            n += 1;
        }
    }
    let mean = sum / f64::from(n);
    let kbps = bytes as f64 * 8.0 / (f64::from(frames) / f64::from(fps)) / 1000.0;
    println!(
        "MEASURE vp8 640x360 600 kbit/s synthetic: {n} frames, PSNR {mean:.2} dB, {kbps:.0} kbit/s"
    );
    assert!(mean >= 32.0, "PSNR {mean:.2} dB");
    assert!(
        kbps <= 600.0 * 1.25,
        "{kbps:.0} kbit/s for a 600 kbit/s target"
    );
}

/// The same operating point for AV1 at rav1e's fastest preset: reported, with a floor that
/// says the stream is usable.
#[test]
fn av1_at_640x360_and_600_kbits_is_reported() {
    let (w, h, fps, rate) = (640, 360, 30, 600_000);
    let mut source = TestSource::new(w, h);
    let mut enc = Av1Encoder::new(w, h, fps, rate, 10).expect("encoder");
    let mut dec = Av1Decoder::new().expect("decoder");
    let (mut sum, mut n, mut bytes) = (0.0, 0, 0usize);
    let frames = 30;
    for i in 0..frames {
        let pic = source.next_picture();
        if let Some(tu) = enc.encode(&pic.view(), i == 0).expect("encode") {
            bytes += tu.data.len();
            dec.decode_bytes(&tu.data, tu.keyframe)
                .expect("decode")
                .expect("a picture");
            sum += psnr(&pic.view(), &dec.picture().expect("picture")).expect("size");
            n += 1;
        }
    }
    let mean = sum / f64::from(n);
    let kbps = bytes as f64 * 8.0 / (f64::from(frames) / f64::from(fps)) / 1000.0;
    println!(
        "MEASURE av1 640x360 600 kbit/s synthetic speed 10: {n} frames, PSNR {mean:.2} dB, {kbps:.0} kbit/s"
    );
    assert_eq!(n, frames, "one picture per picture in (low latency)");
    assert!(mean >= 30.0, "PSNR {mean:.2} dB");
}

/// A decoder that panics on a hostile frame cannot be a default: it would take down the
/// application on a malicious peer's stream. Seeded mutations of a real stream (the libvpx
/// fixture for VP8, a rav1e stream for AV1), each fed to a decoder that has decoded the
/// stream so far: every outcome is an `Ok` or an `Err`, never a panic; and after the hostile
/// frame, the decoder still decodes the stream's key frame.
#[test]
fn hostile_frames_never_panic_the_decoders() {
    let vp8 = ivf_frames(&test_data("output_vp8.ivf"));
    let mut av1_enc = Av1Encoder::new(96, 64, 30, 150_000, 10).expect("encoder");
    let mut source = TestSource::new(96, 64);
    let av1: Vec<Vec<u8>> = (0..12)
        .map(|i| {
            av1_enc
                .encode(&source.next_picture().view(), i == 0)
                .expect("encode")
                .expect("low latency")
                .data
        })
        .collect();
    let mut rng = Rng(0x5eed_f00d);
    let (mut panics, mut errors, mut cases) = (0, 0, 0);
    for case in 0..1500 {
        let use_vp8 = case % 2 == 0;
        let stream = if use_vp8 { &vp8 } else { &av1 };
        let at = rng.below(stream.len().min(40));
        let hostile = mutate(&mut rng, &stream[at]);
        let outcome = catch_unwind(AssertUnwindSafe(|| {
            if use_vp8 {
                let mut d = Vp8Decoder::new();
                for f in &stream[..at] {
                    d.decode_bytes(f).expect("the stream decodes");
                }
                let hostile_failed = d.decode_bytes(&hostile).is_err();
                // Recovery: the key frame decodes again.
                d.decode_bytes(&stream[0])
                    .expect("a key frame after a hostile one");
                hostile_failed
            } else {
                let mut d = Av1Decoder::new().expect("decoder");
                for (i, f) in stream[..at].iter().enumerate() {
                    d.decode_bytes(f, i == 0).expect("the stream decodes");
                }
                let hostile_failed = d.decode_bytes(&hostile, at == 0).is_err();
                d.decode_bytes(&stream[0], true)
                    .expect("a key frame after a hostile one");
                hostile_failed
            }
        }));
        cases += 1;
        match outcome {
            Ok(true) => errors += 1,
            Ok(false) => {}
            Err(_) => panics += 1,
        }
    }
    println!("MEASURE hostile frames: {cases} cases, {errors} refused, {panics} panics");
    assert_eq!(panics, 0, "panics on hostile input");
    assert!(errors > 0, "the mutations are hostile enough to be refused");
}

/// The repository's libvpx VP8 fixture decodes to exactly what libvpx decodes it to: the MD5
/// of every picture's I420, one after the other, is the MD5 of libvpx's output (ffmpeg with
/// `-c:v libvpx`, hosted run 45314695095).
#[test]
fn the_vp8_decoder_decodes_the_libvpx_fixture_as_libvpx_does() {
    const LIBVPX_I420_MD5: &str = "4b669885d06924a93256b85aa90383db";
    let mut dec = Vp8Decoder::new();
    let mut all = Vec::new();
    for f in ivf_frames(&test_data("output_vp8.ivf")) {
        dec.decode_bytes(&f).expect("decode").expect("shown");
        for row in dec.picture().expect("picture").rows() {
            all.extend_from_slice(row);
        }
    }
    assert_eq!(all.len(), 300 * 176 * 144 * 3 / 2);
    assert_eq!(
        common::md5::md5(&mut std::iter::once(&all[..])),
        LIBVPX_I420_MD5
    );
}
