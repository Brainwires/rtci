//! The libdav1d backend (feature `dav1d`, loaded at run time): needs libdav1d 1.x installed
//! (Debian / Ubuntu: `libdav1d7`); without it these tests fail at the first decoder, saying so.
//! Compared with rav1d (feature `av1`), on the same inputs, including the hostile ones that abort
//! rav1d 1.1.0 (docs/video-pipeline.md 4.8, 4.9).

use std::time::Instant;

use rtci_video::codec::av1::{Av1Decoder, Av1Encoder};
use rtci_video::codec::dav1d::Dav1dDecoder;
use rtci_video::decoder::VideoDecoder;
use rtci_video::encoder::VideoEncoder;
use rtci_video::picture::TestSource;

fn data(name: &str) -> Vec<u8> {
    let path = format!("{}/tests/data/{name}", env!("CARGO_MANIFEST_DIR"));
    std::fs::read(&path).unwrap_or_else(|e| panic!("{path}: {e}"))
}

fn ivf_units(d: &[u8]) -> Vec<Vec<u8>> {
    let mut at = u16::from_le_bytes([d[6], d[7]]) as usize;
    let mut out = Vec::new();
    while at + 12 <= d.len() {
        let n = u32::from_le_bytes([d[at], d[at + 1], d[at + 2], d[at + 3]]) as usize;
        at += 12;
        out.push(d[at..at + n].to_vec());
        at += n;
    }
    out
}

fn dav1d() -> Dav1dDecoder {
    Dav1dDecoder::new().unwrap_or_else(|e| panic!("libdav1d 1.x is not installed: {e}"))
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

/// libdav1d and rav1d decode the rav1e stream to the same pictures, byte for byte.
#[test]
fn dav1d_decodes_as_rav1d_does() {
    let units = ivf_units(&data("clean-stream.ivf"));
    let mut a = dav1d();
    let mut b = Av1Decoder::new().expect("rav1d");
    println!("MEASURE dav1d: {}", a.implementation_name());
    for (i, u) in units.iter().enumerate() {
        let pa = a.decode_bytes(u, i == 0).expect("dav1d").expect("picture");
        let pb = b.decode_bytes(u, i == 0).expect("rav1d").expect("picture");
        assert_eq!(pa, pb, "unit {i}");
        assert!(
            a.picture()
                .expect("dav1d")
                .rows()
                .eq(b.picture().expect("rav1d").rows()),
            "unit {i}: pixels differ"
        );
    }
}

/// The frame that aborts rav1d 1.1.0 is an error for libdav1d, and the next key frame decodes.
#[test]
fn the_rav1d_reproducer_is_an_error_for_dav1d() {
    let clean = ivf_units(&data("clean-stream.ivf"));
    let hostile = ivf_units(&data("rav1d-abort.ivf")).remove(0);
    let mut d = dav1d();
    let r = d.decode_bytes(&hostile, true);
    println!("MEASURE dav1d: the rav1d reproducer gives {r:?}");
    d.decode_bytes(&clean[0], true)
        .expect("key frame after")
        .expect("picture");
}

/// Every single-bit flip of the key frame (19,352 cases; 711 abort rav1d 1.1.0) and phase 2's
/// 1500 seeded mutations of the stream, each in a fresh libdav1d after the stream before it:
/// the process survives (a crash in C would end this test binary), and the key frame decodes
/// after each.
#[test]
fn hostile_av1_frames_do_not_crash_dav1d() {
    let units = ivf_units(&data("clean-stream.ivf"));
    let key = &units[0];
    let (mut flips, mut refused, mut pictures) = (0, 0, 0);
    let mut d = dav1d();
    for i in 0..key.len() {
        for bit in 0..8 {
            let mut k = key.clone();
            k[i] ^= 1 << bit;
            flips += 1;
            match d.decode_bytes(&k, true) {
                Err(_) => refused += 1,
                Ok(Some(_)) => pictures += 1,
                Ok(None) => {}
            }
            d.decode_bytes(key, true)
                .expect("the key frame after a flipped one");
        }
    }
    println!(
        "MEASURE dav1d single-bit flips of the key frame: {flips} cases, {refused} refused, {pictures} decoded to a picture, 0 crashes"
    );
    assert_eq!(flips, key.len() * 8);
    assert!(refused > 0);

    let mut rng = Rng(0x5eed_f00d);
    let (mut cases, mut errors) = (0, 0);
    let mut not_recovered = Vec::new();
    for _ in 0..1500 {
        let at = rng.below(units.len());
        let mut f = units[at].clone();
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
        let mut d = dav1d();
        for (i, u) in units[..at].iter().enumerate() {
            d.decode_bytes(u, i == 0).expect("the stream decodes");
        }
        cases += 1;
        errors += usize::from(d.decode_bytes(&f, at == 0).is_err());
        if let Err(e) = d.decode_bytes(&units[0], true) {
            not_recovered.push(format!("case {cases} (unit {at}): {e}"));
        }
    }
    println!(
        "MEASURE dav1d seeded mutations: {cases} cases, {errors} refused, 0 crashes, {} key frames not decoded after a hostile frame {:?}",
        not_recovered.len(),
        not_recovered.iter().take(3).collect::<Vec<_>>()
    );
    assert!(not_recovered.is_empty(), "{not_recovered:?}");
}

/// A decoder as a closure: temporal unit and key-frame flag in.
type DecodeFn = Box<dyn FnMut(&[u8], bool)>;

/// One-thread decode speed of libdav1d against rav1d without assembly, on 60 pictures of rav1e
/// at 640x360, reported.
#[test]
fn dav1d_speed_is_reported() {
    let (w, h) = (640, 360);
    let mut source = TestSource::new(w, h);
    let mut enc = Av1Encoder::new(w, h, 30, 800_000, 10).expect("rav1e");
    let mut units = Vec::new();
    for i in 0..60 {
        units.extend(
            enc.encode(&source.next_picture().view(), i == 0)
                .expect("encode"),
        );
    }
    units.extend(enc.flush().expect("flush"));
    let mut speeds = Vec::new();
    for which in ["libdav1d", "rav1d"] {
        let mut d: DecodeFn = if which == "libdav1d" {
            let mut x = dav1d();
            Box::new(move |u, k| {
                x.decode_bytes(u, k).expect("decode").expect("picture");
            })
        } else {
            let mut x = Av1Decoder::new().expect("rav1d");
            Box::new(move |u, k| {
                x.decode_bytes(u, k).expect("decode").expect("picture");
            })
        };
        let t = Instant::now();
        for u in &units {
            d(&u.data, u.keyframe);
        }
        speeds.push(units.len() as f64 / t.elapsed().as_secs_f64());
    }
    println!(
        "MEASURE av1 640x360 decode, one thread: libdav1d {:.0} fps, rav1d (no assembly) {:.0} fps",
        speeds[0], speeds[1]
    );
    assert!(speeds[0] >= 30.0);
}
