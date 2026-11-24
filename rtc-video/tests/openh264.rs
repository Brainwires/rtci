//! The OpenH264 backend (feature `openh264`): needs Cisco's binary, its path in
//! `OPENH264_LIBRARY` (`libopenh264-2.6.0-linux64.8.so` or 2.7.0, downloaded from
//! `http://ciscobinary.openh264.org/`). Without it these tests fail, saying so: the feature is
//! opt-in and whoever turns it on supplies the binary. docs/video-pipeline.md 4.9.

use std::time::Instant;

use rtc_video::codec::openh264::{H264Decoder, H264Encoder};
use rtc_video::decoder::VideoDecoder;
use rtc_video::encoder::VideoEncoder;
use rtc_video::picture::{TestSource, psnr};

fn library() -> String {
    std::env::var("OPENH264_LIBRARY")
        .expect("OPENH264_LIBRARY: the path of Cisco's OpenH264 binary (2.6.0 or 2.7.0)")
}

fn nal_units(d: &[u8]) -> Vec<&[u8]> {
    let mut starts = Vec::new();
    let mut i = 0;
    while i + 3 <= d.len() {
        if d[i] == 0 && d[i + 1] == 0 && d[i + 2] == 1 {
            starts.push(i + 3);
            i += 3;
        } else {
            i += 1;
        }
    }
    let mut out = Vec::new();
    for (k, &s) in starts.iter().enumerate() {
        let mut e = starts.get(k + 1).map_or(d.len(), |&n| n - 3);
        while e > s && d[e - 1] == 0 {
            e -= 1;
        }
        out.push(&d[s..e]);
    }
    out
}

/// Annex B access units: parameter sets and SEI join the next picture; a slice with
/// first_mb_in_slice 0 starts a picture.
fn access_units(d: &[u8]) -> Vec<Vec<u8>> {
    let mut units: Vec<Vec<u8>> = Vec::new();
    let mut pending = Vec::new();
    for nal in nal_units(d) {
        let Some(&h) = nal.first() else { continue };
        let t = h & 0x1f;
        let first = (1..=5).contains(&t) && nal.get(1).is_some_and(|b| b & 0x80 != 0);
        let mut bytes = vec![0, 0, 0, 1];
        bytes.extend_from_slice(nal);
        if (1..=5).contains(&t)
            && !first
            && let Some(u) = units.last_mut()
        {
            u.extend_from_slice(&bytes);
            continue;
        }
        pending.extend_from_slice(&bytes);
        if (1..=5).contains(&t) {
            units.push(std::mem::take(&mut pending));
        }
    }
    units
}

/// The repository's H.264 fixture decodes.
#[test]
fn openh264_decodes_the_h264_fixture() {
    let path = format!(
        "{}/../examples/test-data/output.264",
        env!("CARGO_MANIFEST_DIR")
    );
    let units = access_units(&std::fs::read(path).expect("fixture"));
    let mut d = H264Decoder::with_library(library()).expect("Cisco's binary");
    let (mut shown, mut size) = (0, None);
    for u in &units {
        if let Some(p) = d.decode_bytes(u).expect("decode") {
            shown += 1;
            size = Some((p.width, p.height));
        }
    }
    println!(
        "MEASURE openh264 fixture: {} access units, {shown} pictures, size {size:?}",
        units.len()
    );
    assert!(
        shown * 100 >= units.len() * 99,
        "{shown} of {}",
        units.len()
    );
}

/// A file that is not one of Cisco's published binaries is refused before it is loaded.
#[test]
fn openh264_refuses_a_library_that_is_not_ciscos() {
    let path = std::env::temp_dir().join("rtc-video-not-openh264.so");
    std::fs::write(&path, b"not a library").expect("write");
    let r = H264Decoder::with_library(&path);
    println!(
        "MEASURE openh264: a foreign file gives {:?}",
        r.as_ref().err()
    );
    assert!(r.is_err());
}

/// The design's operating point (640x360, 600 kbit/s, synthetic source): PSNR and rate, decoded
/// with OpenH264; key frames on request only.
#[test]
fn openh264_at_640x360_and_600_kbits_reaches_32_db() {
    let (w, h, fps, rate) = (640, 360, 30, 600_000);
    let mut source = TestSource::new(w, h);
    let mut enc = H264Encoder::with_library(library(), w, h, fps, rate).expect("encoder");
    let mut dec = H264Decoder::with_library(library()).expect("decoder");
    let (mut sum, mut n, mut bytes, mut keys) = (0.0, 0, 0usize, 0);
    let frames = 90;
    let t = Instant::now();
    for i in 0..frames {
        let pic = source.next_picture();
        let key = i == 0 || i == 45;
        let Some(f) = enc.encode(&pic.view(), key).expect("encode") else {
            continue;
        };
        keys += usize::from(f.keyframe);
        bytes += f.data.len();
        dec.decode_bytes(&f.data).expect("decode").expect("picture");
        sum += psnr(&pic.view(), &dec.picture().expect("picture")).expect("size");
        n += 1;
    }
    let fps_done = f64::from(frames) / t.elapsed().as_secs_f64();
    let mean = sum / f64::from(n);
    let kbps = bytes as f64 * 8.0 / (f64::from(frames) / f64::from(fps)) / 1000.0;
    println!(
        "MEASURE openh264 640x360 600 kbit/s synthetic: {n} frames, PSNR {mean:.2} dB, {kbps:.0} kbit/s, {keys} key frames, encode+decode {fps_done:.0} fps"
    );
    assert_eq!(n, frames, "a frame per picture (no skipping)");
    assert_eq!(keys, 2, "key frames at 0 and 45 only");
    assert!(mean >= 32.0, "PSNR {mean:.2} dB");
    assert!(kbps <= 750.0, "{kbps:.0} kbit/s for 600");
}
