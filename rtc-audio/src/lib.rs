//! A sans-I/O audio pipeline for the `rtc` WebRTC engine: codecs, the receive pipeline (an
//! adaptive jitter buffer with concealment, FEC recovery, comfort noise and time-stretching,
//! libwebrtc NetEq's equivalent), audio processing (echo cancellation, noise suppression,
//! gain control, high-pass filter, voice activity detection) and the send pipeline.
//!
//! Like the engine, nothing here reads a clock, opens a device or starts a thread: the caller
//! passes the time in, and moves audio in and out in 10 ms frames. Capture and playout
//! devices are in `rtc-devices`, behind an opt-in feature.
//!
//! | Module | What |
//! |---|---|
//! | [`codec`] | Opus (pure Rust; libopus opt-in), G.711, G.722, the RFC 7587 parameters |
//! | [`jitter`] | the receive pipeline and its W3C statistics |
//! | [`processing`] | the capture-side processing: AEC, NS, AGC, HPF, VAD, delay estimation |
//! | [`send`] | capture frames to RTP payloads: processing, encoding, bitrate and FEC control, RED, audio level |
//! | [`dsp`] | building blocks: resampling, levels, comfort noise, DTMF, time-stretching |
//! | [`signal`] | deterministic test signals (tones, noise, speech-like) and quality measures |
//! | `engine` (feature `engine`) | the glue to an `RTCRtpSender` / `RTCRtpReceiver` |
//!
//! See `docs/media-pipeline.md` in the repository for how the parts fit together and what
//! was measured.

#![warn(missing_docs)]

pub mod codec;
pub mod dsp;
#[cfg(feature = "engine")]
pub mod engine;
mod error;
pub mod frame;
pub mod jitter;
pub mod processing;
pub mod send;
pub mod signal;

pub use error::{Error, Result};
pub use frame::AudioFrame;

/// The rate the processing and the Opus codec run at.
pub const PIPELINE_RATE: u32 = 48_000;
