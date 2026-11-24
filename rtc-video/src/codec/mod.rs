//! Codec backends behind features: each implements [`VideoDecoder`](crate::decoder::VideoDecoder)
//! and [`VideoEncoder`](crate::encoder::VideoEncoder) on 8-bit I420.
//!
//! | Feature | Decode | Encode | Pure Rust |
//! |---|---|---|---|
//! | `vp8` (opt-in) | VP8 (`vp8-decoder`) | VP8 (`vp8-encoder`) | yes |
//! | `av1` (opt-in) | AV1 (`rav1d`, no assembly; **a hostile frame aborts the process**) | AV1 (`rav1e`, no assembly; not real time) | yes |
//! | `isolation` (opt-in) | any decoder above, in a child process ([`isolated`]) | - | yes |
//!
//! The default build has no codec: it receives, assembles and times every payload format and
//! decodes nothing until the application enables a codec or registers its own decoder.
//!
//! docs/video-pipeline.md section 4 lists the opt-in backends that link system libraries
//! (libvpx, dav1d, OpenH264) and the licensing of H.264.

#[cfg(feature = "av1")]
#[allow(unsafe_code)]
pub mod av1;
#[cfg(feature = "isolation")]
pub mod isolated;
#[cfg(feature = "vp8")]
pub mod vp8;

use crate::decoder::VideoDecoder;
use crate::frame::Codec;

/// A decoder for `codec` from the backends compiled in, `None` when none decodes it.
pub fn decoder_for(codec: Codec) -> Option<Box<dyn VideoDecoder>> {
    match codec {
        #[cfg(feature = "vp8")]
        Codec::Vp8 => Some(Box::new(vp8::Vp8Decoder::new())),
        #[cfg(feature = "av1")]
        Codec::Av1 => av1::Av1Decoder::new()
            .ok()
            .map(|d| Box::new(d) as Box<dyn VideoDecoder>),
        _ => None,
    }
}
