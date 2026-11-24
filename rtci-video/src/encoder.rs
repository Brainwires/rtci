//! The encoder interface: what the codec backends implement and what the send pipeline
//! ([`crate::send`]) drives. Layers and per-layer rates (simulcast, SVC) are not in it yet
//! (docs/video-pipeline.md section 3, phase 3).

use crate::picture::I420;

/// One encoded picture.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncodedPicture {
    /// The bitstream of the picture: one VP8 frame from its frame tag, or one AV1 temporal
    /// unit of OBUs (low-overhead format, as the AV1 RTP payload carries them).
    pub data: Vec<u8>,
    /// Whether it is a key frame (decodable on its own).
    pub keyframe: bool,
    /// The temporal layer, 0 for the base.
    pub temporal_id: u8,
    /// The quantizer used, in the codec's own scale, when known (W3C `qpSum`).
    pub qp: Option<u32>,
    /// Which input picture this is (0 for the first given to `encode`): an encoder with
    /// look-ahead returns a picture some calls after it went in.
    pub source_index: u64,
}

/// Why a picture could not be encoded.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum EncodeError {
    /// The settings are unusable.
    #[error("invalid configuration: {0}")]
    InvalidConfig(String),
    /// The picture does not match the configured size, or its planes are too short.
    #[error("invalid picture: {0}")]
    InvalidPicture(String),
    /// The encoder failed.
    #[error("encoder: {0}")]
    Failed(String),
}

/// A video encoder: synchronous, one picture in, at most one encoded picture out, in input
/// order (no reordering: WebRTC is real time). An encoder may hold pictures back for
/// look-ahead (rav1e does, docs/video-pipeline.md 4.6): `source_index` says which input each
/// output is. `Send`, so the application runs it where it likes.
pub trait VideoEncoder: Send {
    /// Encodes `picture`; `keyframe` forces a key frame (PLI, FIR). `Ok(None)` when the
    /// encoder dropped the picture to hold its rate.
    fn encode(
        &mut self,
        picture: &I420<'_>,
        keyframe: bool,
    ) -> Result<Option<EncodedPicture>, EncodeError>;

    /// The target bitrate from now on, in bits per second.
    fn set_bitrate(&mut self, bitrate_bps: u32);

    /// The target bitrate and the frame rate pictures will now arrive at (the send pipeline
    /// lowers the frame rate under `maintain-resolution`). An encoder whose rate control
    /// budgets per frame needs the frame rate; the default passes the bitrate on alone.
    fn set_rates(&mut self, bitrate_bps: u32, framerate: f64) {
        let _ = framerate;
        self.set_bitrate(bitrate_bps);
    }

    /// The lowest bitrate the encoder is given, in bits per second: below it the send pipeline
    /// keeps the encoder at this rate and drops pictures instead, so that what is sent stays
    /// under the target. 0 (the default) for an encoder that states none.
    fn min_bitrate_bps(&self) -> u32 {
        0
    }

    /// The implementation's name (W3C `encoderImplementation`).
    fn implementation_name(&self) -> &str;
}

/// Makes encoders for the send pipeline, which needs a new one when it changes the resolution
/// (resolution degradation, a source that changes size). A closure
/// `FnMut(width, height, framerate, bitrate_bps) -> Result<Box<dyn VideoEncoder>, EncodeError>`
/// is one.
pub trait EncoderFactory: Send {
    /// An encoder for `width` x `height` pictures arriving at `framerate`, aiming at
    /// `bitrate_bps`. Its first picture is a key frame.
    ///
    /// # Errors
    ///
    /// What the backend refuses.
    fn create(
        &mut self,
        width: u32,
        height: u32,
        framerate: f64,
        bitrate_bps: u32,
    ) -> Result<Box<dyn VideoEncoder>, EncodeError>;
}

impl<F> EncoderFactory for F
where
    F: FnMut(u32, u32, f64, u32) -> Result<Box<dyn VideoEncoder>, EncodeError> + Send,
{
    fn create(
        &mut self,
        width: u32,
        height: u32,
        framerate: f64,
        bitrate_bps: u32,
    ) -> Result<Box<dyn VideoEncoder>, EncodeError> {
        self(width, height, framerate, bitrate_bps)
    }
}
