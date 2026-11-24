//! A sans-I/O video pipeline for the `rtc` WebRTC engine.
//!
//! Phase one is the receive side, codec-agnostic: RTP packets in, frames that a decoder can
//! decode out, in decode order, at the time they are due, with key-frame requests when the
//! picture is lost and the W3C `RTCInboundRtpStreamStats` video members measured on the way.
//!
//! ```text
//!  RTP packets ─▶ assembly::PacketBuffer ─▶ reference::ReferenceFinder ─▶ buffer::FrameBuffer
//!   (per SSRC)     frames from packets        frame ids and references      decodability
//!                                                                              │
//!            keyframe::KeyFramePolicy ◀── receive::ReceivePipeline ◀── timing::Timing
//!             PLI when the chain broke       poll_frame / on_decoded      render time, jitter
//!                                                    │
//!                                          decoder::VideoDecoder (the application's)
//!                                                    │
//!                                          render::RenderStats (freezes, pauses)
//! ```
//!
//! Like the engine, nothing here reads a clock, opens a device or starts a thread: the caller
//! passes the time in. Decoding is the application's: the pipeline hands out
//! [`receive::DecodeRequest`]s and takes the outcome back, so a decoder runs wherever the
//! application wants it.
//!
//! See `docs/video-pipeline.md` in the repository for the design, what each part follows in
//! libwebrtc and the specifications, and the phases.

#![warn(missing_docs)]

pub mod assembly;
pub mod buffer;
pub mod decoder;
#[cfg(feature = "engine")]
pub mod engine;
pub mod frame;
pub mod keyframe;
pub mod payload;
pub mod receive;
pub mod reference;
pub mod render;
pub mod seq;
pub mod stats;
pub mod timing;

#[cfg(test)]
#[path = "test_util_test.rs"]
mod test_util;

pub use frame::{Codec, EncodedFrame};
pub use receive::{DecodeOutcome, DecodeRequest, ReceiveConfig, ReceivePipeline};

/// The RTP clock rate of every video payload format WebRTC uses.
pub const VIDEO_CLOCK_RATE: u32 = 90_000;
