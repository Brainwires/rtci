//! AV1 in pure Rust (feature `av1`): decode with `rav1d` (the Rust port of dav1d), encode with
//! `rav1e`, both without their assembly (which needs NASM).
//!
//! `rav1d` 1.1 offers only dav1d's C API (its README: "A Rust API is planned"), so the decoder
//! calls those `unsafe extern "C"` functions; this module is the crate's only `unsafe` code, and
//! each call states the contract it meets. docs/video-pipeline.md 4.6 has the speed measured
//! without assembly and what the default build can do in real time.
//!
//! # A hostile stream can end the process
//!
//! With rav1d 1.1.0, a malformed AV1 frame (one flipped bit is enough) makes the decoder panic,
//! and because the panic happens inside rav1d's `extern "C"` functions, which cannot unwind,
//! **the whole process aborts**. Nothing in this crate or in the application can catch it:
//! `std::panic::catch_unwind` does not see it. A remote peer chooses what it sends, so with this
//! feature on, any peer that can send AV1 can kill the application. The bug is rav1d's
//! (memorysafety/rav1d issue 1497), fixed on its main branch (pull request 1503) but not in any
//! release yet (issue 1521 asks for one).
//!
//! So: enable `av1` only for streams from a sender you trust, or run [`Av1Decoder`] in a
//! separate process whose death you can survive. docs/video-pipeline.md 4.6 has the reproducer
//! and what containment exists.

use std::ptr::NonNull;

use rav1d::include::dav1d::data::Dav1dData;
use rav1d::include::dav1d::dav1d::{Dav1dContext, Dav1dSettings};
use rav1d::include::dav1d::headers::DAV1D_PIXEL_LAYOUT_I420;
use rav1d::include::dav1d::picture::Dav1dPicture;
use rav1d::src::lib::{
    dav1d_close, dav1d_data_create, dav1d_data_unref, dav1d_default_settings, dav1d_get_picture,
    dav1d_open, dav1d_picture_unref, dav1d_send_data,
};

use crate::decoder::{DecodeError, DecodedPicture, VideoDecoder};
use crate::encoder::{EncodeError, EncodedPicture, VideoEncoder};
use crate::frame::EncodedFrame;
use crate::picture::{I420, I420Buffer};

/// dav1d's "try again" status: `-EAGAIN` (the platform's errno value, as rav1d uses it).
fn eagain() -> i32 {
    -libc::EAGAIN
}

/// How many pictures rav1e 0.8 holds back in low-latency mode with one picture of RDO
/// look-ahead (measured: the first output follows the fifth input).
pub const AV1_ENCODER_DELAY: u64 = 4;

/// The largest picture the decoder accepts by default (`frame_size_limit`): 1920x1088.
pub const DEFAULT_MAX_PIXELS: u32 = 1920 * 1088;

/// The AV1 decoder: one thread, no frame delay (each temporal unit's picture comes out of the
/// call that took it), 8-bit 4:2:0 output.
pub struct Av1Decoder {
    ctx: Option<Dav1dContext>,
    last: I420Buffer,
    has_picture: bool,
    /// After an error (or before the first frame), only a key frame is decoded.
    need_key_frame: bool,
}

// SAFETY: a dav1d context is used through `&mut self` only, so from one thread at a time;
// dav1d allows a context to move between threads (its worker threads, none here with one
// thread, synchronise on their own).
unsafe impl Send for Av1Decoder {}

impl Av1Decoder {
    /// A decoder accepting pictures up to [`DEFAULT_MAX_PIXELS`].
    ///
    /// # Errors
    ///
    /// [`DecodeError::Corrupt`] when the decoder cannot be opened.
    pub fn new() -> Result<Self, DecodeError> {
        Self::with_max_pixels(DEFAULT_MAX_PIXELS)
    }

    /// A decoder accepting pictures up to `max_pixels` (width times height).
    ///
    /// # Errors
    ///
    /// [`DecodeError::Corrupt`] when the decoder cannot be opened.
    pub fn with_max_pixels(max_pixels: u32) -> Result<Self, DecodeError> {
        let mut settings = std::mem::MaybeUninit::<Dav1dSettings>::uninit();
        // SAFETY: `settings` is valid to write to; dav1d_default_settings initialises it.
        unsafe { dav1d_default_settings(NonNull::new_unchecked(settings.as_mut_ptr())) };
        // SAFETY: initialised by the call above.
        let mut settings = unsafe { settings.assume_init() };
        settings.n_threads = 1;
        settings.max_frame_delay = 1;
        settings.frame_size_limit = max_pixels;
        // Output the highest spatial layer of the operating point only (dav1d's default is
        // every layer): one picture per temporal unit, as a WebRTC receiver renders.
        settings.all_layers = 0;
        let mut ctx: Option<Dav1dContext> = None;
        // SAFETY: `ctx` is valid to write to and `settings` to read from.
        let r = unsafe {
            dav1d_open(
                Some(NonNull::from(&mut ctx)),
                Some(NonNull::from(&mut settings)),
            )
        };
        if r.0 != 0 || ctx.is_none() {
            return Err(DecodeError::Corrupt(format!("dav1d_open failed: {}", r.0)));
        }
        Ok(Self {
            ctx,
            last: I420Buffer::default(),
            has_picture: false,
            need_key_frame: true,
        })
    }

    /// Decodes one temporal unit (its OBUs, low-overhead format).
    ///
    /// # Errors
    ///
    /// [`DecodeError::NeedKeyFrame`] for a delta frame before a key frame or after an error;
    /// [`DecodeError::Corrupt`] for data that does not decode.
    pub fn decode_bytes(
        &mut self,
        data: &[u8],
        keyframe: bool,
    ) -> Result<Option<DecodedPicture>, DecodeError> {
        if self.need_key_frame && !keyframe {
            return Err(DecodeError::NeedKeyFrame);
        }
        let result = self.decode_inner(data);
        match &result {
            Ok(_) => self.need_key_frame = false,
            Err(_) => {
                self.need_key_frame = true;
                self.has_picture = false;
            }
        }
        result
    }

    fn decode_inner(&mut self, data: &[u8]) -> Result<Option<DecodedPicture>, DecodeError> {
        let ctx = self
            .ctx
            .ok_or_else(|| DecodeError::Corrupt("closed".into()))?;
        if data.is_empty() {
            return Err(DecodeError::Corrupt("empty temporal unit".into()));
        }
        let mut buf = OwnedData::new(data)?;
        let mut picture: Option<DecodedPicture> = None;
        let mut status = 0;
        // Send the data; when the decoder answers "again", take a picture out and retry. An
        // early return here releases what the decoder has not taken (`OwnedData`'s drop):
        // returning past it once leaked the data of every temporal unit whose picture could
        // not be copied out (found by fuzzing, docs/video-pipeline.md 4.6).
        for _ in 0..4 {
            // SAFETY: `ctx` is open (not closed until drop) and `buf.0` is valid to read and
            // write.
            let r = unsafe { dav1d_send_data(Some(ctx), Some(NonNull::from(&mut buf.0))) };
            status = r.0;
            if status == 0 || status != eagain() {
                break;
            }
            if let Some(p) = self.take_picture(ctx)? {
                picture = Some(p);
            }
        }
        drop(buf);
        if status != 0 && status != eagain() {
            return Err(DecodeError::Corrupt(format!("dav1d_send_data: {status}")));
        }
        if let Some(p) = self.take_picture(ctx)? {
            picture = Some(p);
        }
        Ok(picture)
    }

    /// The next picture the decoder has ready, copied out.
    fn take_picture(&mut self, ctx: Dav1dContext) -> Result<Option<DecodedPicture>, DecodeError> {
        let mut p = Dav1dPicture::default();
        // SAFETY: `ctx` is open and `p` is valid to write to.
        let r = unsafe { dav1d_get_picture(Some(ctx), Some(NonNull::from(&mut p))) };
        if r.0 == eagain() {
            return Ok(None);
        }
        if r.0 != 0 {
            return Err(DecodeError::Corrupt(format!("dav1d_get_picture: {}", r.0)));
        }
        let out = self.copy_picture(&p);
        // SAFETY: `p` holds a picture from dav1d_get_picture, released once.
        unsafe { dav1d_picture_unref(Some(NonNull::from(&mut p))) };
        out.map(Some)
    }

    fn copy_picture(&mut self, p: &Dav1dPicture) -> Result<DecodedPicture, DecodeError> {
        if p.p.bpc != 8 || p.p.layout != DAV1D_PIXEL_LAYOUT_I420 {
            return Err(DecodeError::Corrupt(format!(
                "unsupported picture format: {} bits, layout {}",
                p.p.bpc, p.p.layout
            )));
        }
        let (w, h) = (p.p.w.max(0) as usize, p.p.h.max(0) as usize);
        let (cw, ch) = (w.div_ceil(2), h.div_ceil(2));
        let (ys, uvs) = (p.stride[0], p.stride[1]);
        let (Some(y), Some(u), Some(v)) = (p.data[0], p.data[1], p.data[2]) else {
            return Err(DecodeError::Corrupt("picture without planes".into()));
        };
        if ys < w as isize || uvs < cw as isize {
            return Err(DecodeError::Corrupt("picture strides too small".into()));
        }
        let (ys, uvs) = (ys as usize, uvs as usize);
        // SAFETY: dav1d's 8-bit 4:2:0 picture has `h` luma rows of `ys` bytes and `ch` rows
        // of `uvs` bytes in each chroma plane (strides checked positive above), valid until
        // the picture is unreferenced, which happens after this copy.
        let (y, u, v) = unsafe {
            (
                std::slice::from_raw_parts(y.as_ptr().cast::<u8>(), (h.max(1) - 1) * ys + w),
                std::slice::from_raw_parts(u.as_ptr().cast::<u8>(), (ch.max(1) - 1) * uvs + cw),
                std::slice::from_raw_parts(v.as_ptr().cast::<u8>(), (ch.max(1) - 1) * uvs + cw),
            )
        };
        let view = I420 {
            width: w as u32,
            height: h as u32,
            y,
            u,
            v,
            y_stride: ys,
            uv_stride: uvs,
        };
        self.last.copy_from(&view);
        self.has_picture = true;
        Ok(DecodedPicture {
            width: w as u32,
            height: h as u32,
            qp: None,
        })
    }
}

/// One temporal unit's data in a dav1d buffer, released on drop unless the decoder took it
/// (`dav1d_send_data` empties the buffer when it takes the data).
struct OwnedData(Dav1dData);

impl OwnedData {
    fn new(data: &[u8]) -> Result<Self, DecodeError> {
        let mut buf = Self(Dav1dData::default());
        // SAFETY: `buf.0` is valid to write to; on success it owns an allocation of
        // `data.len()` bytes.
        let ptr = unsafe { dav1d_data_create(Some(NonNull::from(&mut buf.0)), data.len()) };
        if ptr.is_null() {
            return Err(DecodeError::Corrupt("dav1d_data_create failed".into()));
        }
        // SAFETY: `ptr` points to `data.len()` writable bytes (above) that `data` cannot
        // overlap (a fresh allocation).
        unsafe { std::ptr::copy_nonoverlapping(data.as_ptr(), ptr, data.len()) };
        Ok(buf)
    }
}

impl Drop for OwnedData {
    fn drop(&mut self) {
        if self.0.sz > 0 {
            // SAFETY: the buffer came from dav1d_data_create and still holds its data; it is
            // unreferenced once (dav1d_data_unref empties it).
            unsafe { dav1d_data_unref(Some(NonNull::from(&mut self.0))) };
        }
    }
}

impl Drop for Av1Decoder {
    fn drop(&mut self) {
        if self.ctx.is_some() {
            // SAFETY: `ctx` came from dav1d_open and is closed once (it is `None` after).
            unsafe { dav1d_close(Some(NonNull::from(&mut self.ctx))) };
        }
    }
}

impl VideoDecoder for Av1Decoder {
    fn decode(&mut self, frame: &EncodedFrame) -> Result<Option<DecodedPicture>, DecodeError> {
        self.decode_bytes(frame.data(), frame.is_keyframe())
    }

    fn picture(&self) -> Option<I420<'_>> {
        self.has_picture.then(|| self.last.view())
    }

    fn implementation_name(&self) -> &str {
        "rav1d"
    }
}

/// The AV1 encoder: `rav1e` in low-latency mode (no frame reordering), one thread, a speed
/// preset (0 slowest, 10 fastest; real time needs the fastest, docs/video-pipeline.md 4.6).
///
/// rav1e holds pictures back even in low-latency mode (its key-frame look-ahead,
/// `keyframe_lookahead_distance` = reordering latency + 1, and one picture of RDO look-ahead):
/// the first output comes [`AV1_ENCODER_DELAY`] calls after its input, and every output names
/// its input in `source_index`. [`Av1Encoder::flush`] drains what it holds.
pub struct Av1Encoder {
    ctx: rav1e::Context<u8>,
    width: usize,
    height: usize,
    frames_in: u64,
}

impl Av1Encoder {
    /// An encoder for `width` x `height` at `fps`, aiming at `bitrate_bps`, at speed `speed`
    /// (0..=10).
    ///
    /// # Errors
    ///
    /// [`EncodeError::InvalidConfig`] for settings rav1e refuses.
    pub fn new(
        width: u32,
        height: u32,
        fps: u32,
        bitrate_bps: u32,
        speed: u8,
    ) -> Result<Self, EncodeError> {
        let mut enc = rav1e::EncoderConfig::with_speed_preset(speed.min(10));
        enc.width = width as usize;
        enc.height = height as usize;
        enc.time_base = rav1e::data::Rational::new(1, u64::from(fps.max(1)));
        enc.bitrate = i32::try_from(bitrate_bps).unwrap_or(i32::MAX);
        enc.low_latency = true;
        // Key frames on request only (PLI, FIR), as the VP8 encoder.
        enc.min_key_frame_interval = 0;
        // rav1e's largest (`MAX_MAX_KEY_FRAME_INTERVAL`): in effect, never on its own.
        enc.max_key_frame_interval = i32::MAX as u64 / 3;
        // One picture in, one out: no look-ahead.
        enc.speed_settings.rdo_lookahead_frames = 1;
        enc.reservoir_frame_delay = Some(12);
        let cfg = rav1e::Config::new()
            .with_encoder_config(enc)
            .with_threads(1);
        let ctx = cfg
            .new_context()
            .map_err(|e| EncodeError::InvalidConfig(e.to_string()))?;
        Ok(Self {
            ctx,
            width: width as usize,
            height: height as usize,
            frames_in: 0,
        })
    }
}

impl Av1Encoder {
    /// Ends the stream and returns every picture still held back, in order. The encoder takes
    /// no picture after this.
    ///
    /// # Errors
    ///
    /// [`EncodeError::Failed`] when rav1e fails.
    pub fn flush(&mut self) -> Result<Vec<EncodedPicture>, EncodeError> {
        self.ctx.flush();
        let mut out = Vec::new();
        loop {
            match self.ctx.receive_packet() {
                Ok(p) => out.push(EncodedPicture {
                    source_index: p.input_frameno,
                    keyframe: p.frame_type == rav1e::prelude::FrameType::KEY,
                    temporal_id: 0,
                    qp: Some(u32::from(p.qp)),
                    data: p.data,
                }),
                Err(rav1e::EncoderStatus::Encoded) => continue,
                Err(rav1e::EncoderStatus::LimitReached) => return Ok(out),
                Err(e) => return Err(EncodeError::Failed(e.to_string())),
            }
        }
    }
}

impl VideoEncoder for Av1Encoder {
    fn encode(
        &mut self,
        picture: &I420<'_>,
        keyframe: bool,
    ) -> Result<Option<EncodedPicture>, EncodeError> {
        if picture.width as usize != self.width
            || picture.height as usize != self.height
            || !picture.is_valid()
        {
            return Err(EncodeError::InvalidPicture(format!(
                "{}x{} for a {}x{} encoder",
                picture.width, picture.height, self.width, self.height
            )));
        }
        let mut f = self.ctx.new_frame();
        f.planes[0].copy_from_raw_u8(picture.y, picture.y_stride, 1);
        f.planes[1].copy_from_raw_u8(picture.u, picture.uv_stride, 1);
        f.planes[2].copy_from_raw_u8(picture.v, picture.uv_stride, 1);
        let params = rav1e::prelude::FrameParameters {
            frame_type_override: if keyframe || self.frames_in == 0 {
                rav1e::prelude::FrameTypeOverride::Key
            } else {
                rav1e::prelude::FrameTypeOverride::No
            },
            ..Default::default()
        };
        self.ctx
            .send_frame((f, params))
            .map_err(|e| EncodeError::Failed(e.to_string()))?;
        self.frames_in += 1;
        loop {
            match self.ctx.receive_packet() {
                Ok(p) => {
                    return Ok(Some(EncodedPicture {
                        source_index: p.input_frameno,
                        keyframe: p.frame_type == rav1e::prelude::FrameType::KEY,
                        temporal_id: 0,
                        qp: Some(u32::from(p.qp)),
                        data: p.data,
                    }));
                }
                Err(rav1e::EncoderStatus::Encoded) => continue,
                Err(rav1e::EncoderStatus::NeedMoreData) => return Ok(None),
                Err(e) => return Err(EncodeError::Failed(e.to_string())),
            }
        }
    }

    fn set_bitrate(&mut self, _bitrate_bps: u32) {
        // rav1e 0.8 has no rate change on a running context; phase 3's encoder driver
        // re-creates it at a key frame. The target set at creation stays.
    }

    fn implementation_name(&self) -> &str {
        "rav1e"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::picture::{TestSource, psnr};

    #[test]
    fn what_rav1e_makes_rav1d_decodes_close_to_the_source() {
        let (w, h) = (128, 96);
        let mut source = TestSource::new(w, h);
        let mut enc = Av1Encoder::new(w, h, 30, 200_000, 10).expect("encoder");
        let mut dec = Av1Decoder::new().expect("decoder");
        let pictures: Vec<_> = (0..10).map(|_| source.next_picture()).collect();
        let mut out = Vec::new();
        for (i, pic) in pictures.iter().enumerate() {
            let tu = enc.encode(&pic.view(), i == 0).expect("encode");
            // The look-ahead: nothing comes out for the first AV1_ENCODER_DELAY pictures.
            assert_eq!(tu.is_some(), i as u64 >= AV1_ENCODER_DELAY, "picture {i}");
            out.extend(tu);
        }
        out.extend(enc.flush().expect("flush"));
        assert_eq!(out.len(), pictures.len());
        for (k, tu) in out.iter().enumerate() {
            assert_eq!(tu.source_index, k as u64);
            assert_eq!(tu.keyframe, k == 0, "picture {k}");
            let dp = dec
                .decode_bytes(&tu.data, tu.keyframe)
                .expect("decode")
                .expect("a picture per temporal unit");
            assert_eq!((dp.width, dp.height), (w, h));
            let q =
                psnr(&pictures[k].view(), &dec.picture().expect("a picture")).expect("same size");
            assert!(q > 25.0, "picture {k}: {q:.1} dB");
        }
    }

    #[test]
    fn a_delta_frame_first_needs_a_key_frame_and_garbage_is_corrupt() {
        let mut dec = Av1Decoder::new().expect("decoder");
        assert_eq!(
            dec.decode_bytes(&[0x12, 0x00], false),
            Err(DecodeError::NeedKeyFrame)
        );
        assert!(dec.decode_bytes(&[0xff; 32], true).is_err());
        assert!(dec.picture().is_none());
    }
}
