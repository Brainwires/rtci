//! Checks and measures the pure-Rust codec backends (features `vp8` and `av1`), for the
//! evidence in docs/video-pipeline.md 4.6. Run on a GitHub-hosted runner by
//! `scripts/video-codec-check.sh`, which fetches the test data (nothing here is committed).
//!
//! ```text
//! codec_check vp8-vectors DIR
//!     Decodes every DIR/*.ivf and compares each shown frame's I420 MD5 with DIR/<name>.ivf.md5
//!     (the WebM project's VP8 test vectors). Exit status 1 on any mismatch.
//! codec_check decode vp8|av1 IN.ivf OUT.yuv
//!     Decodes IN.ivf to raw I420 (every shown frame), for comparison with libvpx or dav1d.
//! codec_check encode vp8|av1 IN.y4m|synthetic:WxH FRAMES FPS BITRATE SPEED OUT.ivf
//!     Encodes, writes IVF and the encoder's own reconstruction check: prints encode speed,
//!     bitrate reached, PSNR of our decode against the source, and decode speed.
//! ```

use std::fs;
use std::io::Write;
use std::process::ExitCode;
use std::time::{Duration, Instant};

use rtc_video::codec::av1::{Av1Decoder, Av1Encoder};
use rtc_video::codec::vp8::{Vp8Decoder, Vp8Encoder};
use rtc_video::decoder::{DecodeError, DecodedPicture, VideoDecoder};
use rtc_video::encoder::VideoEncoder;
use rtc_video::picture::{I420, I420Buffer, TestSource, psnr};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = match args.first().map(String::as_str) {
        Some("vp8-vectors") if args.len() == 2 => vp8_vectors(&args[1]),
        Some("decode") if args.len() == 4 => decode(&args[1], &args[2], &args[3]),
        Some("encode") if args.len() == 8 => encode(&args[1..]),
        _ => Err("usage: see the module documentation".to_owned()),
    };
    match result {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::FAILURE,
        Err(e) => {
            eprintln!("codec_check: {e}");
            ExitCode::FAILURE
        }
    }
}

// ---------------------------------------------------------------------------------------------
// IVF and Y4M

fn ivf_frames(data: &[u8]) -> Result<(String, Vec<&[u8]>), String> {
    if data.len() < 32 || &data[..4] != b"DKIF" {
        return Err("not an IVF file".into());
    }
    let header = u16::from_le_bytes([data[6], data[7]]) as usize;
    let fourcc = String::from_utf8_lossy(&data[8..12]).into_owned();
    let mut frames = Vec::new();
    let mut at = header;
    while at + 12 <= data.len() {
        let size =
            u32::from_le_bytes([data[at], data[at + 1], data[at + 2], data[at + 3]]) as usize;
        at += 12;
        let end = at
            .checked_add(size)
            .filter(|&e| e <= data.len())
            .ok_or("truncated frame")?;
        frames.push(&data[at..end]);
        at = end;
    }
    Ok((fourcc, frames))
}

fn ivf_write(fourcc: &[u8; 4], w: u32, h: u32, fps: u32, frames: &[Vec<u8>]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(b"DKIF");
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&32u16.to_le_bytes());
    out.extend_from_slice(fourcc);
    out.extend_from_slice(&(w as u16).to_le_bytes());
    out.extend_from_slice(&(h as u16).to_le_bytes());
    out.extend_from_slice(&fps.to_le_bytes());
    out.extend_from_slice(&1u32.to_le_bytes());
    out.extend_from_slice(&(frames.len() as u32).to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    for (i, f) in frames.iter().enumerate() {
        out.extend_from_slice(&(f.len() as u32).to_le_bytes());
        out.extend_from_slice(&(i as u64).to_le_bytes());
        out.extend_from_slice(f);
    }
    out
}

/// The pictures of a Y4M file (4:2:0 only), at most `limit`.
fn y4m_pictures(data: &[u8], limit: usize) -> Result<Vec<I420Buffer>, String> {
    let line_end = data.iter().position(|&b| b == b'\n').ok_or("not Y4M")?;
    let header = std::str::from_utf8(&data[..line_end]).map_err(|e| e.to_string())?;
    if !header.starts_with("YUV4MPEG2") {
        return Err("not Y4M".into());
    }
    let field = |c: char| {
        header
            .split(' ')
            .find_map(|f| f.strip_prefix(c))
            .and_then(|v| v.parse::<u32>().ok())
    };
    let (w, h) = (field('W').ok_or("no W")?, field('H').ok_or("no H")?);
    let size = I420Buffer::new(w, h).data.len();
    let mut at = line_end + 1;
    let mut out = Vec::new();
    while out.len() < limit && at < data.len() {
        let nl = data[at..]
            .iter()
            .position(|&b| b == b'\n')
            .ok_or("bad FRAME")?;
        at += nl + 1;
        if at + size > data.len() {
            break;
        }
        out.push(I420Buffer {
            width: w,
            height: h,
            data: data[at..at + size].to_vec(),
        });
        at += size;
    }
    Ok(out)
}

#[path = "../tests/common/md5.rs"]
mod md5;
use md5::md5;

// ---------------------------------------------------------------------------------------------
// Decoders behind one face

enum AnyDecoder {
    Vp8(Box<Vp8Decoder>),
    Av1(Box<Av1Decoder>),
}

impl AnyDecoder {
    fn new(codec: &str) -> Result<Self, String> {
        match codec {
            "vp8" => Ok(Self::Vp8(Box::default())),
            "av1" => Ok(Self::Av1(Box::new(
                Av1Decoder::new().map_err(|e| e.to_string())?,
            ))),
            other => Err(format!("unknown codec {other}")),
        }
    }

    fn decode(
        &mut self,
        data: &[u8],
        keyframe: bool,
    ) -> Result<Option<DecodedPicture>, DecodeError> {
        match self {
            Self::Vp8(d) => d.decode_bytes(data),
            Self::Av1(d) => d.decode_bytes(data, keyframe),
        }
    }

    fn picture(&self) -> Option<I420<'_>> {
        match self {
            Self::Vp8(d) => d.picture(),
            Self::Av1(d) => d.picture(),
        }
    }
}

fn vp8_keyframe(data: &[u8]) -> bool {
    data.first().is_some_and(|b| b & 1 == 0)
}

// ---------------------------------------------------------------------------------------------

fn vp8_vectors(dir: &str) -> Result<bool, String> {
    let mut names: Vec<String> = fs::read_dir(dir)
        .map_err(|e| e.to_string())?
        .filter_map(|e| e.ok()?.file_name().into_string().ok())
        .filter(|n| n.ends_with(".ivf"))
        .collect();
    names.sort();
    let (mut ok, mut frames_total) = (0, 0);
    for name in &names {
        let ivf = fs::read(format!("{dir}/{name}")).map_err(|e| e.to_string())?;
        let md5s = fs::read_to_string(format!("{dir}/{name}.md5"))
            .map_err(|e| format!("{name}.md5: {e}"))?;
        let want: Vec<&str> = md5s
            .lines()
            .filter_map(|l| l.split_whitespace().next())
            .collect();
        let (_, frames) = ivf_frames(&ivf)?;
        let mut dec = Vp8Decoder::new();
        let mut got = Vec::new();
        let mut failure = None;
        for (i, f) in frames.iter().enumerate() {
            match dec.decode_bytes(f) {
                Ok(Some(_)) => {
                    let p = dec.picture().ok_or("no picture")?;
                    got.push(md5(&mut p.rows()));
                }
                Ok(None) => {}
                Err(e) => {
                    failure = Some(format!("frame {i}: {e}"));
                    break;
                }
            }
        }
        if failure.is_none() {
            if let Some(i) = got.iter().zip(&want).position(|(g, w)| g != w) {
                failure = Some(format!("shown frame {i}: md5 {} want {}", got[i], want[i]));
            } else if got.len() != want.len() {
                failure = Some(format!(
                    "{} shown frames, {} in the .md5 file",
                    got.len(),
                    want.len()
                ));
            }
        }
        frames_total += got.len();
        match failure {
            None => {
                ok += 1;
                println!("VECTOR {name}: ok, {} frames bit-exact", got.len());
            }
            Some(f) => println!("VECTOR {name}: MISMATCH {f}"),
        }
    }
    println!(
        "MEASURE vp8 test vectors: {ok} of {} bit-exact ({frames_total} frames)",
        names.len()
    );
    Ok(ok == names.len() && !names.is_empty())
}

fn decode(codec: &str, input: &str, output: &str) -> Result<bool, String> {
    let ivf = fs::read(input).map_err(|e| e.to_string())?;
    let (_, frames) = ivf_frames(&ivf)?;
    let mut dec = AnyDecoder::new(codec)?;
    let mut out = fs::File::create(output).map_err(|e| e.to_string())?;
    let (mut shown, mut errors) = (0, 0);
    let start = Instant::now();
    for (i, f) in frames.iter().enumerate() {
        let key = if codec == "vp8" {
            vp8_keyframe(f)
        } else {
            i == 0 || shown == 0
        };
        match dec.decode(f, key) {
            Ok(Some(_)) => {
                let p = dec.picture().ok_or("no picture")?;
                for row in p.rows() {
                    out.write_all(row).map_err(|e| e.to_string())?;
                }
                shown += 1;
            }
            Ok(None) => {}
            Err(e) => {
                errors += 1;
                eprintln!("frame {i}: {e}");
            }
        }
    }
    println!(
        "MEASURE decode {codec} {input}: {} frames, {shown} shown, {errors} errors, {:.1} ms",
        frames.len(),
        start.elapsed().as_secs_f64() * 1000.0
    );
    Ok(errors == 0)
}

fn encode(args: &[String]) -> Result<bool, String> {
    let [codec, input, frames, fps, bitrate, speed, output] = args else {
        return Err("encode: wrong arguments".into());
    };
    let n: usize = frames.parse().map_err(|_| "FRAMES")?;
    let fps: u32 = fps.parse().map_err(|_| "FPS")?;
    let bitrate: u32 = bitrate.parse().map_err(|_| "BITRATE")?;
    let speed: u8 = speed.parse().map_err(|_| "SPEED")?;
    let pictures: Vec<I420Buffer> = if let Some(size) = input.strip_prefix("synthetic:") {
        let (w, h) = size.split_once('x').ok_or("synthetic:WxH")?;
        let mut s = TestSource::new(w.parse().map_err(|_| "W")?, h.parse().map_err(|_| "H")?);
        (0..n).map(|_| s.next_picture()).collect()
    } else if let Some((path, size)) = input.split_once('@') {
        // A Y4M clip scaled to WxH: `clip.y4m@640x360`.
        let (w, h) = size.split_once('x').ok_or("@WxH")?;
        let (w, h): (u32, u32) = (w.parse().map_err(|_| "W")?, h.parse().map_err(|_| "H")?);
        let data = fs::read(path).map_err(|e| e.to_string())?;
        y4m_pictures(&data, n)?
            .iter()
            .map(|p| {
                let v = p.view();
                let src = vp8_encoder::Picture {
                    width: v.width,
                    height: v.height,
                    y: v.y,
                    u: v.u,
                    v: v.v,
                    y_stride: v.y_stride,
                    uv_stride: v.uv_stride,
                };
                let mut out = Vec::new();
                vp8_encoder::scale_i420(&src, w, h, &mut out);
                I420Buffer {
                    width: w,
                    height: h,
                    data: out,
                }
            })
            .collect()
    } else {
        let data = fs::read(input).map_err(|e| e.to_string())?;
        y4m_pictures(&data, n)?
    };
    let (w, h) = (pictures[0].width, pictures[0].height);
    let (mut vp8, mut av1) = (None, None);
    match codec.as_str() {
        "vp8" => vp8 = Some(Vp8Encoder::new(w, h, fps, bitrate).map_err(|e| e.to_string())?),
        "av1" => av1 = Some(Av1Encoder::new(w, h, fps, bitrate, speed).map_err(|e| e.to_string())?),
        other => return Err(format!("unknown codec {other}")),
    }
    let enc: &mut dyn VideoEncoder = match (&mut vp8, &mut av1) {
        (Some(e), _) => e,
        (_, Some(e)) => e,
        _ => unreachable!(),
    };
    let mut encoded: Vec<(usize, Vec<u8>, bool)> = Vec::new();
    let mut encode_time = Duration::ZERO;
    let mut slowest = Duration::ZERO;
    for (i, p) in pictures.iter().enumerate() {
        let t = Instant::now();
        let out = enc.encode(&p.view(), i == 0).map_err(|e| e.to_string())?;
        let took = t.elapsed();
        encode_time += took;
        slowest = slowest.max(took);
        if let Some(e) = out {
            encoded.push((e.source_index as usize, e.data, e.keyframe));
        }
    }
    if let Some(e) = &mut av1 {
        let t = Instant::now();
        for p in e.flush().map_err(|e| e.to_string())? {
            encoded.push((p.source_index as usize, p.data, p.keyframe));
        }
        encode_time += t.elapsed();
    }
    let bytes: usize = encoded.iter().map(|e| e.1.len()).sum();
    let seconds = pictures.len() as f64 / f64::from(fps);
    // Decode what was encoded, timing it, and compare with the source.
    let mut dec = AnyDecoder::new(codec)?;
    let mut decode_time = Duration::ZERO;
    let mut psnr_sum = 0.0;
    let mut decoded = 0usize;
    for (i, data, key) in &encoded {
        let t = Instant::now();
        let r = dec.decode(data, *key);
        decode_time += t.elapsed();
        if let Ok(Some(_)) = r {
            let p = dec.picture().ok_or("no picture")?;
            psnr_sum += psnr(&pictures[*i].view(), &p).ok_or("size")?;
            decoded += 1;
        }
    }
    let fourcc = if codec == "vp8" { b"VP80" } else { b"AV01" };
    let frames_only: Vec<Vec<u8>> = encoded.iter().map(|e| e.1.clone()).collect();
    fs::write(output, ivf_write(fourcc, w, h, fps, &frames_only)).map_err(|e| e.to_string())?;
    println!(
        "MEASURE encode {codec} {input} {w}x{h} speed {speed} target {} kbit/s: {} of {} frames \
         encoded, {:.1} fps encode (slowest frame {:.1} ms), {:.0} kbit/s reached, \
         PSNR {:.2} dB over {decoded} decoded, {:.1} fps decode",
        bitrate / 1000,
        encoded.len(),
        pictures.len(),
        pictures.len() as f64 / encode_time.as_secs_f64(),
        slowest.as_secs_f64() * 1000.0,
        bytes as f64 * 8.0 / seconds / 1000.0,
        psnr_sum / decoded.max(1) as f64,
        decoded as f64 / decode_time.as_secs_f64(),
    );
    Ok(decoded == encoded.len())
}
