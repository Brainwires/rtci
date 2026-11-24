//! The encoder interface (phase 2: what the codec backends and their tests need; phase 3
//! extends it with layers and per-layer rates, docs/video-pipeline.md section 3).

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

    /// The implementation's name (W3C `encoderImplementation`).
    fn implementation_name(&self) -> &str;
}
