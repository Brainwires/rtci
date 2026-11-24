//! FlexFEC as published: RFC 8627, negotiated as `flexfec` (`video/flexfec`).
//!
//! Its payload format is not backward compatible with draft-03 (`flexfec-03`, [`super::draft03`]):
//! the protected SSRCs are in the repair packet's CSRC list, the FEC header is 12 octets where
//! draft-03's is 20, the k bit has the opposite polarity, the third mask is 64 bits, and there
//! are two more variants (fixed L/D and retransmission). The two coders share the mask type and
//! the interleaved coverage, nothing on the wire.
pub(crate) mod decoder;
pub(crate) mod encoder;
pub(crate) mod header;
pub(crate) mod params;
pub(crate) mod receiver;
pub(crate) mod sender;
