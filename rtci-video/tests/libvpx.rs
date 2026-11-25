//! The libvpx backend (feature `libvpx`, loaded at run time): needs libvpx installed (Debian /
//! Ubuntu: `libvpx12`); without it these tests fail at the first decoder, saying so.
//! docs/video-pipeline.md 4.9.

mod common {
    pub mod md5;
}

use std::time::Instant;

use rtci_video::codec::libvpx::{VpxCodec, VpxDecoder, VpxEncoder};
use rtci_video::codec::vp8::Vp8Decoder;
use rtci_video::decoder::VideoDecoder;
use rtci_video::encoder::VideoEncoder;
use rtci_video::picture::{TestSource, psnr};

fn test_data(name: &str) -> Vec<u8> {
    let path = format!(
        "{}/../examples/test-data/{name}",
        env!("CARGO_MANIFEST_DIR")
    );
    std::fs::read(&path).unwrap_or_else(|e| panic!("{path}: {e}"))
}

fn ivf_frames(d: &[u8]) -> Vec<Vec<u8>> {
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

fn decoder(codec: VpxCodec) -> VpxDecoder {
    VpxDecoder::new(codec).unwrap_or_else(|e| panic!("libvpx is not installed or differs: {e}"))
}

/// The repository's VP8 fixture through this binding gives exactly the I420 that libvpx gives
/// through ffmpeg (`-c:v libvpx`, the MD5 `tests/codecs.rs` checks the pure-Rust decoder
/// against).
#[test]
fn libvpx_decodes_the_vp8_fixture_to_libvpx_reference_output() {
    const LIBVPX_I420_MD5: &str = "4b669885d06924a93256b85aa90383db";
    let mut dec = decoder(VpxCodec::Vp8);
    println!("MEASURE libvpx: {}", dec.implementation_name());
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

/// The VP9 fixture (libvpx, 176x144, 300 frames) decodes completely.
#[test]
fn libvpx_decodes_the_vp9_fixture() {
    let mut dec = decoder(VpxCodec::Vp9);
    let frames = ivf_frames(&test_data("output_vp9.ivf"));
    let mut shown = 0;
    let mut all = Vec::new();
    for f in &frames {
        if let Some(p) = dec.decode_bytes(f).expect("decode") {
            assert_eq!((p.width, p.height), (176, 144));
            shown += 1;
            for row in dec.picture().expect("picture").rows() {
                all.extend_from_slice(row);
            }
        }
    }
    println!(
        "MEASURE libvpx vp9 fixture: {} frames, {shown} shown, I420 MD5 {}",
        frames.len(),
        common::md5::md5(&mut std::iter::once(&all[..]))
    );
    assert_eq!(shown, 300);
}

/// Encode at the design's operating point (640x360, 600 kbit/s, synthetic source), decode with
/// libvpx: PSNR, rate; for VP8 the pure-Rust decoder must decode libvpx's stream to the same
/// bytes as libvpx.
fn operating_point(codec: VpxCodec) -> (f64, f64) {
    let (w, h, fps, rate) = (640, 360, 30, 600_000);
    let mut source = TestSource::new(w, h);
    let mut enc = VpxEncoder::new(codec, w, h, fps, rate).expect("encoder");
    let mut dec = decoder(codec);
    let mut rust = Vp8Decoder::new();
    let (mut sum, mut n, mut bytes) = (0.0, 0, 0usize);
    let frames = 90;
    for i in 0..frames {
        let pic = source.next_picture();
        let f = enc
            .encode(&pic.view(), i == 0)
            .expect("encode")
            .expect("a frame per picture (real time, no look-ahead)");
        assert_eq!(f.source_index, i as u64);
        assert_eq!(f.keyframe, i == 0, "frame {i}");
        bytes += f.data.len();
        dec.decode_bytes(&f.data).expect("decode").expect("shown");
        let got = dec.picture().expect("picture");
        sum += psnr(&pic.view(), &got).expect("size");
        n += 1;
        if codec == VpxCodec::Vp8 {
            rust.decode_bytes(&f.data)
                .expect("vp8-decoder")
                .expect("shown");
            assert!(
                rust.picture().expect("picture").rows().eq(got.rows()),
                "frame {i}: vp8-decoder and libvpx differ"
            );
        }
    }
    let mean = sum / f64::from(n);
    let kbps = bytes as f64 * 8.0 / (f64::from(frames) / f64::from(fps)) / 1000.0;
    println!(
        "MEASURE libvpx {codec:?} 640x360 600 kbit/s synthetic: PSNR {mean:.2} dB, {kbps:.0} kbit/s"
    );
    (mean, kbps)
}

#[test]
fn libvpx_vp8_at_640x360_and_600_kbits_reaches_32_db_and_vp8_decoder_agrees() {
    let (q, kbps) = operating_point(VpxCodec::Vp8);
    assert!(q >= 32.0, "PSNR {q:.2} dB");
    // CBR may undershoot on a simple source (libwebrtc's undershoot 100 %); never overshoot.
    assert!(kbps <= 750.0, "{kbps:.0} kbit/s for 600");
}

#[test]
fn libvpx_vp9_at_640x360_and_600_kbits_reaches_32_db() {
    let (q, kbps) = operating_point(VpxCodec::Vp9);
    assert!(q >= 32.0, "PSNR {q:.2} dB");
    // CBR may undershoot on a simple source (libwebrtc's undershoot 100 %); never overshoot.
    assert!(kbps <= 750.0, "{kbps:.0} kbit/s for 600");
}

/// `set_bitrate` takes effect without a new encoder (`vpx_codec_enc_config_set`): two seconds
/// at 1 Mbit/s, then two at 300 kbit/s; the second half's rate is at most 25 % over 300 and
/// below the first's.
#[test]
fn libvpx_follows_a_new_target_without_a_key_frame() {
    let (w, h, fps) = (640, 360, 30);
    let mut source = TestSource::new(w, h);
    let mut enc = VpxEncoder::new(VpxCodec::Vp8, w, h, fps, 1_000_000).expect("encoder");
    let (mut first, mut second, mut keys) = (0usize, 0usize, 0);
    for i in 0..120 {
        if i == 60 {
            enc.set_bitrate(300_000);
        }
        let f = enc
            .encode(&source.next_picture().view(), i == 0)
            .expect("encode")
            .expect("frame");
        keys += usize::from(f.keyframe);
        // Skip the first second after each target (the rate controller's buffer).
        if (30..60).contains(&i) {
            first += f.data.len();
        } else if i >= 90 {
            second += f.data.len();
        }
    }
    let (a, b) = (first as f64 * 8.0 / 1000.0, second as f64 * 8.0 / 1000.0);
    println!(
        "MEASURE libvpx rate change: {a:.0} kbit/s at 1000, then {b:.0} kbit/s at 300, {keys} key frames"
    );
    assert_eq!(keys, 1, "no key frame for a rate change");
    assert!(b <= 375.0, "{b:.0} kbit/s for 300");
    assert!(a > b, "{a:.0} then {b:.0} kbit/s");
}

/// 720p speed on one thread, reported; decode must be real time (30 fps) with margin.
#[test]
fn libvpx_speed_at_720p_is_reported() {
    for codec in [VpxCodec::Vp8, VpxCodec::Vp9] {
        let (w, h, fps) = (1280, 720, 30);
        let mut source = TestSource::new(w, h);
        let pictures: Vec<_> = (0..60).map(|_| source.next_picture()).collect();
        let mut enc = VpxEncoder::new(codec, w, h, fps, 2_000_000).expect("encoder");
        let t = Instant::now();
        let frames: Vec<_> = pictures
            .iter()
            .enumerate()
            .map(|(i, p)| {
                enc.encode(&p.view(), i == 0)
                    .expect("encode")
                    .expect("frame")
                    .data
            })
            .collect();
        let enc_fps = 60.0 / t.elapsed().as_secs_f64();
        let mut dec = decoder(codec);
        let t = Instant::now();
        for f in &frames {
            dec.decode_bytes(f).expect("decode").expect("shown");
        }
        let dec_fps = 60.0 / t.elapsed().as_secs_f64();
        println!(
            "MEASURE libvpx {codec:?} 1280x720 2 Mbit/s synthetic, one thread: encode {enc_fps:.0} fps, decode {dec_fps:.0} fps"
        );
        assert!(dec_fps >= 30.0, "{codec:?} decode {dec_fps:.0} fps");
    }
}
