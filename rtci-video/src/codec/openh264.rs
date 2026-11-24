//! H.264 (Constrained Baseline) decode and encode with **Cisco's OpenH264 binary** (feature
//! `openh264`), loaded at run time from a path the application gives. Building this feature
//! compiles no C and links nothing: the `openh264` crate is used without its `source` feature,
//! and it loads a library only if the library's SHA-256 is one Cisco published for OpenH264
//! 2.6.0 or 2.7.0 (`OpenH264API::from_blob_path`).
//!
//! # Licensing, plainly
//!
//! The code licences are permissive (the `openh264` crate and OpenH264 are BSD-2-Clause). The
//! H.264 **patents** are not covered by any code licence. Cisco's binary carries Cisco's
//! AVC/H.264 patent licence at no cost, and only under the conditions of
//! `http://www.openh264.org/BINARY_LICENSE.txt` (docs/video-pipeline.md 4.1 quotes them), among
//! them: the binary is downloaded separately to the end user's device, not shipped with the
//! application; the user can enable and disable its use; and the text "OpenH264 Video Codec
//! provided by Cisco Systems, Inc." appears where the user controls it. Meeting those is the
//! application's job: this crate never downloads, bundles or builds OpenH264. An H.264 codec
//! built from source, or written in Rust, carries no patent licence at all.

use std::ffi::OsStr;

use openh264::OpenH264API;
use openh264::decoder::{Decoder, DecoderConfig};
use openh264::encoder::{
    BitRate, Encoder, EncoderConfig, FrameRate, FrameType, IntraFramePeriod, RateControlMode,
    UsageType,
};
use openh264::formats::{YUVSlices, YUVSource};

use crate::decoder::{DecodeError, DecodedPicture, VideoDecoder};
use crate::encoder::{EncodeError, EncodedPicture, VideoEncoder};
use crate::frame::EncodedFrame;
use crate::picture::{I420, I420Buffer};

/// The text Cisco's licence requires where the user controls the codec.
pub const ATTRIBUTION: &str = "OpenH264 Video Codec provided by Cisco Systems, Inc.";

fn load(path: &OsStr) -> Result<OpenH264API, String> {
    OpenH264API::from_blob_path(path).map_err(|e| format!("OpenH264 binary: {e}"))
}

/// The H.264 decoder on Cisco's OpenH264 binary.
pub struct H264Decoder {
    inner: Decoder,
    last: I420Buffer,
    has_picture: bool,
}

impl H264Decoder {
    /// A decoder on Cisco's binary at `path` (`libopenh264-2.x.y-<platform>.so`, `.dylib` or
    /// `.dll`, as Cisco publishes it).
    ///
    /// # Errors
    ///
    /// [`DecodeError::Corrupt`] when the file is not one of Cisco's published binaries or the
    /// decoder does not open.
    pub fn with_library(path: impl AsRef<OsStr>) -> Result<Self, DecodeError> {
        let api = load(path.as_ref()).map_err(DecodeError::Corrupt)?;
        let inner = Decoder::with_api_config(api, DecoderConfig::new())
            .map_err(|e| DecodeError::Corrupt(format!("OpenH264 decoder: {e}")))?;
        Ok(Self {
            inner,
            last: I420Buffer::default(),
            has_picture: false,
        })
    }

    /// Decodes one access unit (Annex B).
    ///
    /// # Errors
    ///
    /// [`DecodeError::Corrupt`] for an access unit OpenH264 refuses.
    pub fn decode_bytes(&mut self, data: &[u8]) -> Result<Option<DecodedPicture>, DecodeError> {
        match self.inner.decode(data) {
            Ok(Some(yuv)) => {
                let (w, h) = yuv.dimensions();
                let (ys, us, _) = yuv.strides();
                self.last.copy_from(&I420 {
                    width: w as u32,
                    height: h as u32,
                    y: yuv.y(),
                    u: yuv.u(),
                    v: yuv.v(),
                    y_stride: ys,
                    uv_stride: us,
                });
                self.has_picture = true;
                Ok(Some(DecodedPicture {
                    width: w as u32,
                    height: h as u32,
                    qp: None,
                }))
            }
            Ok(None) => Ok(None),
            Err(e) => {
                self.has_picture = false;
                Err(DecodeError::Corrupt(format!("OpenH264: {e}")))
            }
        }
    }
}

impl VideoDecoder for H264Decoder {
    fn decode(&mut self, frame: &EncodedFrame) -> Result<Option<DecodedPicture>, DecodeError> {
        self.decode_bytes(frame.data())
    }

    fn picture(&self) -> Option<I420<'_>> {
        self.has_picture.then(|| self.last.view())
    }

    fn implementation_name(&self) -> &str {
        "OpenH264 (Cisco binary)"
    }
}

/// The H.264 encoder on Cisco's OpenH264 binary: real-time camera mode, bitrate rate control,
/// no frame skipping, key frames on request only.
pub struct H264Encoder {
    inner: Encoder,
    width: u32,
    height: u32,
    frames_in: u64,
}

impl H264Encoder {
    /// An encoder on Cisco's binary at `path`, for `width` x `height` at `fps`, aiming at
    /// `bitrate_bps`.
    ///
    /// # Errors
    ///
    /// [`EncodeError::InvalidConfig`] when the file is not one of Cisco's published binaries or
    /// OpenH264 refuses the settings.
    pub fn with_library(
        path: impl AsRef<OsStr>,
        width: u32,
        height: u32,
        fps: u32,
        bitrate_bps: u32,
    ) -> Result<Self, EncodeError> {
        let api = load(path.as_ref()).map_err(EncodeError::InvalidConfig)?;
        let config = EncoderConfig::new()
            .bitrate(BitRate::from_bps(bitrate_bps))
            .max_frame_rate(FrameRate::from_hz(fps.max(1) as f32))
            .usage_type(UsageType::CameraVideoRealTime)
            .rate_control_mode(RateControlMode::Bitrate)
            .skip_frames(false)
            .intra_frame_period(IntraFramePeriod::from_num_frames(0));
        let inner = Encoder::with_api_config(api, config)
            .map_err(|e| EncodeError::InvalidConfig(format!("OpenH264 encoder: {e}")))?;
        Ok(Self {
            inner,
            width,
            height,
            frames_in: 0,
        })
    }
}

impl VideoEncoder for H264Encoder {
    fn encode(
        &mut self,
        picture: &I420<'_>,
        keyframe: bool,
    ) -> Result<Option<EncodedPicture>, EncodeError> {
        if picture.width != self.width || picture.height != self.height || !picture.is_valid() {
            return Err(EncodeError::InvalidPicture(format!(
                "{}x{} for a {}x{} encoder",
                picture.width, picture.height, self.width, self.height
            )));
        }
        let source_index = self.frames_in;
        self.frames_in += 1;
        if keyframe && source_index > 0 {
            self.inner.force_intra_frame();
        }
        let yuv = YUVSlices::new(
            (picture.y, picture.u, picture.v),
            (picture.width as usize, picture.height as usize),
            (picture.y_stride, picture.uv_stride, picture.uv_stride),
        );
        let stream = self
            .inner
            .encode(&yuv)
            .map_err(|e| EncodeError::Failed(format!("OpenH264: {e}")))?;
        let frame_type = stream.frame_type();
        if matches!(frame_type, FrameType::Skip | FrameType::Invalid) {
            return Ok(None);
        }
        Ok(Some(EncodedPicture {
            source_index,
            keyframe: matches!(frame_type, FrameType::IDR | FrameType::I),
            temporal_id: 0,
            qp: None,
            data: stream.to_vec(),
        }))
    }

    fn set_bitrate(&mut self, _bitrate_bps: u32) {
        // The `openh264` crate sets the rate at creation only; phase 3's encoder driver
        // re-creates the encoder at a key frame when the rate moves far.
    }

    fn implementation_name(&self) -> &str {
        "OpenH264 (Cisco binary)"
    }
}
