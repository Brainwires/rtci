//! The decoder interface, and a decoder that checks the pipeline's decode order.

use std::collections::BTreeSet;

use crate::frame::EncodedFrame;

/// A decoded picture's description (the planes themselves belong to the decoder's own
/// buffers until a later phase adds a frame pool).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DecodedPicture {
    /// Width in pixels.
    pub width: u32,
    /// Height in pixels.
    pub height: u32,
    /// The frame's QP, when the decoder knows it (W3C `qpSum`).
    pub qp: Option<u32>,
}

/// Why a frame did not decode.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DecodeError {
    /// The decoder needs a key frame first.
    #[error("a key frame is needed")]
    NeedKeyFrame,
    /// The bitstream is corrupt.
    #[error("corrupt frame: {0}")]
    Corrupt(String),
}

/// A video decoder. Synchronous: the application calls it where it wants (on the thread that
/// drives the pipeline, or on a worker) and hands the outcome back with
/// [`ReceivePipeline::on_decoded`](crate::ReceivePipeline::on_decoded).
pub trait VideoDecoder: Send {
    /// Decodes one picture (a temporal unit: every spatial layer of it, joined). `Ok(None)` for
    /// a frame that updates references and shows nothing.
    fn decode(&mut self, frame: &EncodedFrame) -> Result<Option<DecodedPicture>, DecodeError>;

    /// The implementation's name (W3C `decoderImplementation`).
    fn implementation_name(&self) -> &str;

    /// Whether the decoder is hardware (W3C `powerEfficientDecoder`).
    fn is_hardware(&self) -> bool {
        false
    }
}

/// A decoder that decodes nothing and checks everything a decoder relies on: a frame decodes
/// when it is a key frame or when every frame it references was decoded by it before, in
/// increasing id order; otherwise it fails as a real decoder would (`NeedKeyFrame` before
/// the first key frame, `Corrupt` for a missing reference). The size is the last key frame's
/// (or `default_size`).
#[derive(Debug, Clone)]
pub struct ReferenceCheckingDecoder {
    decoded: BTreeSet<i64>,
    last_id: Option<i64>,
    size: (u32, u32),
    /// Frames decoded.
    pub frames_decoded: u64,
    /// Frames refused.
    pub errors: u64,
}

impl ReferenceCheckingDecoder {
    /// A decoder that reports `default_size` until a key frame says otherwise.
    pub fn new(default_size: (u32, u32)) -> Self {
        Self {
            decoded: BTreeSet::new(),
            last_id: None,
            size: default_size,
            frames_decoded: 0,
            errors: 0,
        }
    }
}

impl VideoDecoder for ReferenceCheckingDecoder {
    fn decode(&mut self, frame: &EncodedFrame) -> Result<Option<DecodedPicture>, DecodeError> {
        if frame.is_keyframe() {
            self.decoded.clear();
            if let Some(size) = frame.frame.resolution {
                self.size = size;
            }
        } else {
            if self.last_id.is_none() {
                self.errors += 1;
                return Err(DecodeError::NeedKeyFrame);
            }
            if self.last_id.is_some_and(|l| frame.id <= l) {
                self.errors += 1;
                return Err(DecodeError::Corrupt("decoded out of order".into()));
            }
            if let Some(missing) = frame.references.iter().find(|r| !self.decoded.contains(r)) {
                self.errors += 1;
                self.last_id = None;
                return Err(DecodeError::Corrupt(format!(
                    "reference {missing} not decoded"
                )));
            }
        }
        if frame.layer_ids.is_empty() {
            self.decoded.insert(frame.id);
        } else {
            self.decoded.extend(frame.layer_ids.iter().copied());
        }
        while self.decoded.len() > 256 {
            self.decoded.pop_first();
        }
        self.last_id = Some(frame.id);
        self.frames_decoded += 1;
        Ok(Some(DecodedPicture {
            width: self.size.0,
            height: self.size.1,
            qp: None,
        }))
    }

    fn implementation_name(&self) -> &str {
        "reference-checking"
    }
}
