//! Packets in, frames out: the types the stages pass along.

use std::time::Instant;

use bytes::Bytes;
use rtp::codec::dependency_descriptor::DependencyDescriptor;

/// The video payload formats the pipeline assembles.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Codec {
    /// VP8 (RFC 7741).
    Vp8,
    /// VP9 (RFC 9628).
    Vp9,
    /// AV1 (the AV1 RTP specification).
    Av1,
    /// H.264 (RFC 6184).
    H264,
    /// H.265 (RFC 7798).
    H265,
}

impl Codec {
    /// The codec of a MIME type (`video/VP8`, ...), case-insensitively.
    pub fn from_mime_type(mime: &str) -> Option<Self> {
        let sub = mime.rsplit('/').next()?.to_ascii_uppercase();
        match sub.as_str() {
            "VP8" => Some(Self::Vp8),
            "VP9" => Some(Self::Vp9),
            "AV1" => Some(Self::Av1),
            "H264" => Some(Self::H264),
            "H265" | "HEVC" => Some(Self::H265),
            _ => None,
        }
    }
}

/// One RTP packet of a video stream, as the receive pipeline takes it.
#[derive(Debug, Clone)]
pub struct VideoPacket {
    /// When it arrived.
    pub arrival: Instant,
    /// The RTP sequence number.
    pub sequence_number: u16,
    /// The RTP timestamp.
    pub timestamp: u32,
    /// The marker bit.
    pub marker: bool,
    /// The payload type.
    pub payload_type: u8,
    /// The SSRC.
    pub ssrc: u32,
    /// The RTP payload (empty for a padding-only packet).
    pub payload: Bytes,
    /// The Dependency Descriptor, read with the stream's structure, when the packet carries
    /// one.
    pub dependency_descriptor: Option<DependencyDescriptor>,
    /// The playout-delay extension's `(min, max)` in milliseconds, when present.
    pub playout_delay_ms: Option<(u32, u32)>,
    /// Whether the packet is known to be a retransmission (RFC 4588). The engine folds an RTX
    /// packet back into its original before the application sees it, so this is set from the
    /// arrival pattern (`ReceiveConfig::retransmission_lateness`) unless the application knows.
    pub retransmitted: bool,
}

/// A VP9 picture group (RFC 9628 section 4.2.1): for each picture its TID and P_DIFFs.
pub type PictureGroup = Vec<(u8, Vec<u8>)>;

/// What a codec payload descriptor says about a frame's place in the stream.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum CodecHeader {
    /// None of the descriptors below: H.264, H.265, or AV1 without a Dependency Descriptor.
    #[default]
    None,
    /// The VP8 payload descriptor (RFC 7741 section 4.2).
    Vp8 {
        /// The PictureID and whether it was sent in 15 bits.
        picture_id: Option<(u16, bool)>,
        /// TL0PICIDX.
        tl0_pic_idx: Option<u8>,
        /// TID.
        temporal_id: Option<u8>,
        /// The Y (layer sync) bit.
        layer_sync: bool,
    },
    /// The VP9 payload descriptor (RFC 9628 section 4.2), of the frame's first packet.
    Vp9 {
        /// The PictureID and whether it was sent in 15 bits.
        picture_id: Option<(u16, bool)>,
        /// Flexible mode (F).
        flexible: bool,
        /// Inter-picture predicted (P).
        inter_picture_predicted: bool,
        /// TID, when L is set.
        temporal_id: Option<u8>,
        /// SID, when L is set.
        spatial_id: u8,
        /// Inter-layer dependency (D).
        inter_layer_dependency: bool,
        /// TL0PICIDX (non-flexible mode with L set).
        tl0_pic_idx: Option<u8>,
        /// The reference picture differences (P_DIFF, flexible mode).
        p_diff: Vec<u8>,
        /// The scalability structure's picture group, when the packet carried one (V and G):
        /// for each picture its TID and its P_DIFFs.
        gof: Option<PictureGroup>,
        /// The frame's last packet had E set (end of the layer frame).
        end_of_layer_frame: bool,
    },
    /// The Dependency Descriptor of the frame's first packet.
    Generic(DependencyDescriptor),
}

/// A complete frame from the packet buffer, before its references are known.
#[derive(Debug, Clone)]
pub struct AssembledFrame {
    /// The codec.
    pub codec: Codec,
    /// The payload type of its packets.
    pub payload_type: u8,
    /// The SSRC.
    pub ssrc: u32,
    /// The RTP timestamp.
    pub rtp_timestamp: u32,
    /// The extended sequence numbers of the first and last packet.
    pub first_sequence: i64,
    /// See `first_sequence`.
    pub last_sequence: i64,
    /// Packets in the frame.
    pub packet_count: usize,
    /// The earliest and latest arrival of its packets.
    pub first_arrival: Instant,
    /// See `first_arrival`.
    pub last_arrival: Instant,
    /// Whether any of its packets was a retransmission.
    pub retransmitted: bool,
    /// The marker bit of its last packet: the last frame of its picture (temporal unit). For
    /// VP9 the final packet of the picture (RFC 9628 section 4.1), for AV1 the last packet of
    /// the temporal unit (AV1 RTP specification 4.1); for single-layer streams every frame.
    pub end_of_picture: bool,
    /// Whether the payload says it is a key frame (an intra frame that starts a sequence).
    pub keyframe: bool,
    /// The coded size, when a key frame's header carries it.
    pub resolution: Option<(u32, u32)>,
    /// What the payload descriptor says.
    pub header: CodecHeader,
    /// The playout-delay extension of its packets, when present.
    pub playout_delay_ms: Option<(u32, u32)>,
    /// The bitstream a decoder takes (descriptors removed; Annex B for H.264 / H.265).
    pub data: Bytes,
}

/// A frame with its place in the decode order: what the frame buffer holds and a decoder gets.
#[derive(Debug, Clone)]
pub struct EncodedFrame {
    /// The frame as assembled.
    pub frame: AssembledFrame,
    /// The frame's id: increasing in decode order, unique in the stream.
    pub id: i64,
    /// The ids of the frames it is predicted from.
    pub references: Vec<i64>,
    /// The spatial layer.
    pub spatial_id: u8,
    /// The temporal layer.
    pub temporal_id: u8,
    /// The RTP timestamp, extended.
    pub unwrapped_timestamp: i64,
    /// The ids of the frames joined into this picture (spatial layers), in order; empty for a
    /// single frame (whose id is `id`).
    pub layer_ids: Vec<i64>,
}

impl EncodedFrame {
    /// Whether the frame is a key frame.
    pub fn is_keyframe(&self) -> bool {
        self.frame.keyframe
    }

    /// The bitstream.
    pub fn data(&self) -> &Bytes {
        &self.frame.data
    }
}
