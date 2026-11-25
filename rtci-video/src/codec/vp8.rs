//! VP8 (RFC 6386) in pure Rust: `vp8-decoder` and `vp8-encoder` (feature `vp8`).
//!
//! Both crates are pinned to an exact version: docs/video-pipeline.md 4.6 records how they
//! were checked (the WebM test vectors bit for bit, libvpx's decode of the same streams,
//! speed, fuzzing) and why a new crate from a new publisher is pinned.

use std::panic::{AssertUnwindSafe, catch_unwind};

use crate::decoder::{DecodeError, DecodedPicture, VideoDecoder};
use crate::encoder::{EncodeError, EncodedPicture, VideoEncoder};
use crate::frame::EncodedFrame;
use crate::picture::{I420, I420Buffer};

/// The largest picture the decoder accepts by default: 1920x1088 (a frame that claims more is
/// refused before anything is allocated). `vp8-decoder`'s own default is 4096x2304.
pub const DEFAULT_MAX_PIXELS: u64 = 1920 * 1088;

/// The VP8 decoder.
pub struct Vp8Decoder {
    inner: vp8_decoder::Decoder,
    max_pixels: u64,
    last: I420Buffer,
    has_picture: bool,
}

impl Default for Vp8Decoder {
    fn default() -> Self {
        Self::new()
    }
}

impl Vp8Decoder {
    /// A decoder waiting for a key frame, accepting pictures up to [`DEFAULT_MAX_PIXELS`].
    pub fn new() -> Self {
        let mut inner = vp8_decoder::Decoder::new();
        inner.set_max_pixels(DEFAULT_MAX_PIXELS);
        Self {
            inner,
            max_pixels: DEFAULT_MAX_PIXELS,
            last: I420Buffer::default(),
            has_picture: false,
        }
    }

    /// The largest picture (width times height) a key frame may announce.
    pub fn set_max_pixels(&mut self, max_pixels: u64) {
        self.max_pixels = max_pixels;
        self.inner.set_max_pixels(max_pixels);
    }

    /// Decodes one raw VP8 frame (from its frame tag).
    ///
    /// # Errors
    ///
    /// [`DecodeError::NeedKeyFrame`] before the first key frame and after an error;
    /// [`DecodeError::Corrupt`] for a frame that does not decode, and for one that makes the
    /// decoder panic: the panic is caught (the decoder is pure Rust, so it unwinds), the decoder
    /// is replaced by a fresh one and waits for a key frame. No input was seen to do that
    /// (docs/video-pipeline.md 4.6: fuzzed); this is the fence for one that does.
    pub fn decode_bytes(&mut self, data: &[u8]) -> Result<Option<DecodedPicture>, DecodeError> {
        match catch_unwind(AssertUnwindSafe(|| self.decode_inner(data))) {
            Ok(result) => result,
            Err(_) => {
                self.inner = vp8_decoder::Decoder::new();
                self.inner.set_max_pixels(self.max_pixels);
                self.has_picture = false;
                Err(DecodeError::Corrupt("the VP8 decoder panicked".into()))
            }
        }
    }

    fn decode_inner(&mut self, data: &[u8]) -> Result<Option<DecodedPicture>, DecodeError> {
        match self.inner.decode(data) {
            Ok(Some(p)) => {
                let view = I420 {
                    width: p.width,
                    height: p.height,
                    y: p.y,
                    u: p.u,
                    v: p.v,
                    y_stride: p.y_stride,
                    uv_stride: p.uv_stride,
                };
                self.last.copy_from(&view);
                self.has_picture = true;
                Ok(Some(DecodedPicture {
                    width: p.width,
                    height: p.height,
                    qp: None,
                }))
            }
            Ok(None) => Ok(None),
            Err(vp8_decoder::DecodeError::NeedKeyframe) => Err(DecodeError::NeedKeyFrame),
            Err(e) => {
                self.has_picture = false;
                Err(DecodeError::Corrupt(e.to_string()))
            }
        }
    }
}

impl VideoDecoder for Vp8Decoder {
    fn decode(&mut self, frame: &EncodedFrame) -> Result<Option<DecodedPicture>, DecodeError> {
        self.decode_bytes(frame.data())
    }

    fn picture(&self) -> Option<I420<'_>> {
        self.has_picture.then(|| self.last.view())
    }

    fn implementation_name(&self) -> &str {
        "vp8-decoder"
    }
}

/// The lowest bitrate the VP8 encoder is given: libwebrtc's floor for a VP8 stream at any
/// resolution (`video/config/simulcast.cc` `kSimulcastFormatsVP8`, "The min bitrate is still
/// limited at 30 kbps", @ a222406d).
pub const MIN_BITRATE_BPS: u32 = 30_000;

/// The VP8 encoder: rate control to a target, key frames on request, no temporal layers
/// (phase 3 adds them).
pub struct Vp8Encoder {
    inner: vp8_encoder::Encoder,
    fps: u32,
    frames_in: u64,
}

impl Vp8Encoder {
    /// An encoder for `width` x `height` at `fps`, aiming at `bitrate_bps`.
    ///
    /// # Errors
    ///
    /// [`EncodeError::InvalidConfig`] for a size or rate the encoder refuses.
    pub fn new(width: u32, height: u32, fps: u32, bitrate_bps: u32) -> Result<Self, EncodeError> {
        let config = vp8_encoder::EncoderConfig::new(width, height, fps, bitrate_bps);
        let inner = vp8_encoder::Encoder::new(config)
            .map_err(|e| EncodeError::InvalidConfig(e.to_string()))?;
        Ok(Self {
            inner,
            fps,
            frames_in: 0,
        })
    }
}

impl VideoEncoder for Vp8Encoder {
    fn encode(
        &mut self,
        picture: &I420<'_>,
        keyframe: bool,
    ) -> Result<Option<EncodedPicture>, EncodeError> {
        let p = vp8_encoder::Picture {
            width: picture.width,
            height: picture.height,
            y: picture.y,
            u: picture.u,
            v: picture.v,
            y_stride: picture.y_stride,
            uv_stride: picture.uv_stride,
        };
        let source_index = self.frames_in;
        self.frames_in += 1;
        match self.inner.encode(&p, keyframe) {
            Ok(Some(f)) => Ok(Some(EncodedPicture {
                source_index,
                keyframe: f.keyframe,
                temporal_id: f.temporal_id,
                qp: Some(u32::from(f.q_index)),
                data: f.data,
            })),
            Ok(None) => Ok(None),
            Err(e @ vp8_encoder::EncodeError::SizeMismatch { .. })
            | Err(e @ vp8_encoder::EncodeError::InvalidPicture) => {
                Err(EncodeError::InvalidPicture(e.to_string()))
            }
            Err(e) => Err(EncodeError::Failed(e.to_string())),
        }
    }

    fn set_bitrate(&mut self, bitrate_bps: u32) {
        self.inner.set_rates(bitrate_bps, self.fps);
    }

    fn set_rates(&mut self, bitrate_bps: u32, framerate: f64) {
        self.fps = (framerate.round() as u32).max(1);
        self.inner.set_rates(bitrate_bps, self.fps);
    }

    fn min_bitrate_bps(&self) -> u32 {
        MIN_BITRATE_BPS
    }

    fn implementation_name(&self) -> &str {
        "vp8-encoder"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::picture::{TestSource, psnr};

    #[test]
    fn what_the_encoder_makes_the_decoder_decodes_close_to_the_source() {
        let (w, h) = (176, 144);
        let mut source = TestSource::new(w, h);
        let mut enc = Vp8Encoder::new(w, h, 30, 300_000).expect("encoder");
        let mut dec = Vp8Decoder::new();
        let mut decoded = 0;
        for i in 0..30 {
            let pic = source.next_picture();
            let Some(frame) = enc.encode(&pic.view(), i == 0).expect("encode") else {
                continue;
            };
            assert_eq!(frame.keyframe, i == 0);
            let out = dec
                .decode_bytes(&frame.data)
                .expect("decode")
                .expect("shown");
            assert_eq!((out.width, out.height), (w, h));
            let q = psnr(&pic.view(), &dec.picture().expect("a picture")).expect("same size");
            assert!(q > 25.0, "frame {i}: {q:.1} dB");
            decoded += 1;
        }
        assert!(decoded >= 28, "{decoded}");
    }

    #[test]
    fn a_delta_frame_first_needs_a_key_frame_and_garbage_is_corrupt() {
        let mut dec = Vp8Decoder::new();
        // A delta frame tag (bit 0 set), shown, version 0.
        assert_eq!(
            dec.decode_bytes(&[0x11, 0x00, 0x00, 0, 0, 0, 0, 0]),
            Err(DecodeError::NeedKeyFrame)
        );
        assert!(matches!(
            dec.decode_bytes(&[0x10, 0x02, 0x00, 1, 2, 3]),
            Err(DecodeError::Corrupt(_))
        ));
        assert!(dec.picture().is_none());
    }
}
