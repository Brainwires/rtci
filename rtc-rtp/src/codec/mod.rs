/// AV1 payload format ([RFC 9628]).
pub mod av1;
/// Comfort noise payload format ([RFC 3389]).
pub mod comfort_noise;
/// The Dependency Descriptor RTP header extension (AV1 RTP specification, appendix A).
pub mod dependency_descriptor;
/// G.711 and G.722 payload formats, which need no fragmentation.
pub mod g7xx;
/// H.264 payload format ([RFC 6184]): STAP-A aggregation and FU-A fragmentation.
pub mod h264;
/// H.265/HEVC payload format ([RFC 7798]).
pub mod h265;
/// A format-agnostic payload (bytes the RTP layer does not parse, such as SFrame).
pub mod opaque;
/// Opus payload format ([RFC 7587]), one packet per frame.
pub mod opus;
/// Redundant audio data, RED ([RFC 2198]).
pub mod red;
/// The SFrame RTP payload format (draft-ietf-avtcore-rtp-sframe-03): the descriptor, the
/// payloader and the reassembly of section 5.2.
pub mod sframe;
/// SMPTE ST 336 (KLV) payload ([RFC 6597]).
pub mod smpte336m;
/// Scalable video coding: the scalability modes of W3C webrtc-svc and their layer structures.
pub mod svc;
/// Named telephone events and DTMF ([RFC 4733]).
pub mod telephone_event;
/// VP8 payload format ([RFC 7741]).
pub mod vp8;
/// VP9 payload format (draft-ietf-payload-vp9).
pub mod vp9;
