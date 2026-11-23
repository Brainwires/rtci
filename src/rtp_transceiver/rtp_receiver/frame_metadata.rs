//! Per-frame metadata of received encoded frames (W3C webrtc-encoded-transform section 4:
//! `RTCEncodedFrameMetadata`, `RTCEncodedVideoFrameMetadata`, `RTCEncodedAudioFrameMetadata`,
//! and the frame's `type`).
//!
//! The engine does not depacketize: the application reassembles a frame from the RTP packets
//! `poll_read` hands it, and asks the receiver for the frame's metadata with those packets
//! ([`RTCRtpReceiver::encoded_frame_metadata`](super::RTCRtpReceiver::encoded_frame_metadata)).
//! What the packets say is read from them (their header, header extensions and payload);
//! what only the engine saw is recorded as each packet passes: when it arrived, its capture
//! time (from `abs-capture-time`, or interpolated), and the frame's place in the Dependency
//! Descriptor's frame numbering, which needs the descriptor's structure from an earlier
//! packet (AV1 RTP specification appendix A).

use std::collections::VecDeque;
use std::time::Instant;

use bytes::Bytes;
use rtp::codec::dependency_descriptor::DependencyDescriptorReader;
use rtp::packetizer::Depacketizer;

/// How many frames' arrival records a receiver keeps: a few seconds of video at any frame
/// rate, so an application that reassembles behind a jitter buffer still finds its frame.
const MAX_FRAME_RECORDS: usize = 512;

/// How many Dependency Descriptor frames a receiver remembers per stream.
const MAX_DESCRIBED_FRAMES: usize = 512;

/// W3C webrtc-encoded-transform 4.3 `type` of an `RTCEncodedVideoFrame`
/// (`EncodedVideoChunkType`, with the frame without data of `RTCEncodedVideoFrameType`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RTCEncodedVideoFrameType {
    /// A frame without data.
    Empty,
    /// A key frame: decodable without any earlier frame.
    Key,
    /// A delta frame: refers to earlier frames.
    #[default]
    Delta,
}

/// W3C webrtc-encoded-transform 4.1 `RTCEncodedFrameMetadata`, the members audio and video
/// frames share.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct RTCEncodedFrameMetadata {
    /// `synchronizationSource`: the SSRC of the frame's packets.
    pub synchronization_source: u32,
    /// `payloadType`.
    pub payload_type: u8,
    /// `contributingSources`: the CSRC list of the frame's packets.
    pub contributing_sources: Vec<u32>,
    /// `rtpTimestamp`.
    pub rtp_timestamp: u32,
    /// `receiveTime`: when the last packet of the frame that the engine saw was received (the
    /// instant given with the datagram that carried it), on the engine's clock; an API layer
    /// shifts it to its time origin. `None` for packets this receiver never received.
    pub receive_time: Option<Instant>,
    /// `captureTime`, in milliseconds on the capture system's NTP clock (webrtc-extensions
    /// 8: from the frame's `abs-capture-time`, or interpolated from an earlier packet of the
    /// source by the RTP timestamp); an API layer shifts it to its time origin.
    pub capture_time: Option<f64>,
    /// `senderCaptureTimeOffset`, in milliseconds.
    pub sender_capture_time_offset: Option<f64>,
    /// `mimeType`, the negotiated codec's (e.g. `video/VP8`).
    pub mime_type: String,
}

/// W3C webrtc-encoded-transform 4.2 `RTCEncodedVideoFrameMetadata`, with the frame's type
/// (4.3).
#[derive(Debug, Clone, PartialEq, Default)]
pub struct RTCEncodedVideoFrameMetadata {
    /// The members audio and video frames share.
    pub frame: RTCEncodedFrameMetadata,
    /// The frame's `type`: key or delta, or empty for a frame without data. From the
    /// payload where the codec says it (VP8 frame tag, VP9 payload descriptor, an H.264 IDR
    /// slice, the AV1 aggregation header's N bit); otherwise a Dependency Descriptor that
    /// attaches its structure marks a key frame.
    pub frame_type: RTCEncodedVideoFrameType,
    /// `frameId`: monotonically increasing in decode order, its lower 16 bits the Dependency
    /// Descriptor's `frame_number`. Present only when the frame's packets carry the
    /// Dependency Descriptor and the receiver had its structure.
    pub frame_id: Option<u64>,
    /// `dependencies`: the `frameId`s of the frames this one refers to (the descriptor's
    /// frame differences). Empty without a Dependency Descriptor.
    pub dependencies: Vec<u64>,
    /// `width`: from the Dependency Descriptor's resolution for the frame's spatial layer,
    /// or the codec's key frame (VP8 key frame header, VP9 scalability structure, H.264
    /// sequence parameter set, AV1 sequence header); a delta frame reports the last size of
    /// its stream. `None` until a frame stated one.
    pub width: Option<u16>,
    /// `height`, as `width`.
    pub height: Option<u16>,
    /// `spatialIndex`: the Dependency Descriptor's spatial id, or the codec's (VP9 SID, the
    /// AV1 OBU extension's spatial id); 0 for a codec without spatial layers.
    pub spatial_index: Option<u32>,
    /// `temporalIndex`: the Dependency Descriptor's temporal id, or the codec's (VP8 TID,
    /// VP9 TID, the AV1 OBU extension's temporal id); 0 for a stream without temporal
    /// layers.
    pub temporal_index: Option<u32>,
}

/// W3C webrtc-encoded-transform 4.4 `RTCEncodedAudioFrameMetadata`.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct RTCEncodedAudioFrameMetadata {
    /// The members audio and video frames share.
    pub frame: RTCEncodedFrameMetadata,
    /// `sequenceNumber`: the RTP sequence number of the frame's (first) packet.
    pub sequence_number: Option<u16>,
    /// `audioLevel`, linear 0..1, converted from the RFC 6464 level of the frame's packets
    /// (127 is 0, otherwise 10^(-level/20)). `None` when no packet of the frame carries the
    /// extension.
    pub audio_level: Option<f64>,
}

/// The metadata of a received encoded frame.
#[derive(Debug, Clone, PartialEq)]
pub enum RTCEncodedFrameMetadataKind {
    /// An `RTCEncodedVideoFrame`'s.
    Video(RTCEncodedVideoFrameMetadata),
    /// An `RTCEncodedAudioFrame`'s.
    Audio(RTCEncodedAudioFrameMetadata),
}

/// What the Dependency Descriptor says of one frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DescribedFrame {
    pub(crate) frame_number: u16,
    pub(crate) frame_id: u64,
    pub(crate) dependencies: Vec<u64>,
    pub(crate) spatial_id: u8,
    pub(crate) temporal_id: u8,
    pub(crate) resolution: Option<(u16, u16)>,
    /// The descriptor that started the frame attached a structure (a key frame).
    pub(crate) structure_attached: bool,
}

/// One stream's Dependency Descriptor state: the reader (structure, active decode targets),
/// the frame numbers unwrapped to frame ids, and the frames described lately.
#[derive(Debug, Default, Clone)]
struct DescriptorStream {
    ssrc: u32,
    reader: DependencyDescriptorReader,
    last: Option<(u16, u64)>,
    frames: VecDeque<DescribedFrame>,
}

impl DescriptorStream {
    /// The frame id of `frame_number`: the nearest one to the last frame id with these low
    /// 16 bits (frame numbers arrive out of order by less than half the wrap).
    fn unwrap(&mut self, frame_number: u16) -> u64 {
        match self.last {
            None => {
                self.last = Some((frame_number, u64::from(frame_number)));
                u64::from(frame_number)
            }
            Some((last_number, last_id)) => {
                let delta = i64::from(frame_number.wrapping_sub(last_number) as i16);
                let id = (last_id as i64 + delta).max(0) as u64;
                if delta > 0 {
                    self.last = Some((frame_number, id));
                }
                id
            }
        }
    }
}

/// The arrival of the packets of one frame (one SSRC and RTP timestamp).
#[derive(Debug, Clone)]
struct FrameArrival {
    ssrc: u32,
    rtp_timestamp: u32,
    last_receive: Instant,
    capture_time: Option<f64>,
    sender_capture_time_offset: Option<f64>,
}

/// What a receiver records of the packets it delivers, for
/// [`RTCRtpReceiver::encoded_frame_metadata`](super::RTCRtpReceiver::encoded_frame_metadata).
#[derive(Debug, Default, Clone)]
pub(crate) struct FrameRecords {
    arrivals: VecDeque<FrameArrival>,
    descriptors: Vec<DescriptorStream>,
    /// The last frame size each stream stated.
    sizes: Vec<(u32, u16, u16)>,
}

impl FrameRecords {
    /// Records a packet delivered to the application at `now`: its frame's arrival and
    /// capture time, and its Dependency Descriptor (`descriptor`, the extension's payload).
    pub(crate) fn record(
        &mut self,
        now: Instant,
        header: &rtp::Header,
        capture: (Option<f64>, Option<f64>),
        descriptor: Option<&[u8]>,
    ) {
        match self
            .arrivals
            .iter_mut()
            .rev()
            .find(|a| a.ssrc == header.ssrc && a.rtp_timestamp == header.timestamp)
        {
            Some(arrival) => {
                arrival.last_receive = now;
                if arrival.capture_time.is_none() {
                    (arrival.capture_time, arrival.sender_capture_time_offset) = capture;
                }
            }
            None => {
                if self.arrivals.len() >= MAX_FRAME_RECORDS {
                    self.arrivals.pop_front();
                }
                self.arrivals.push_back(FrameArrival {
                    ssrc: header.ssrc,
                    rtp_timestamp: header.timestamp,
                    last_receive: now,
                    capture_time: capture.0,
                    sender_capture_time_offset: capture.1,
                });
            }
        }
        if let Some(data) = descriptor {
            self.record_descriptor(header.ssrc, data);
        }
    }

    fn record_descriptor(&mut self, ssrc: u32, data: &[u8]) {
        let index = match self.descriptors.iter().position(|d| d.ssrc == ssrc) {
            Some(index) => index,
            None => {
                self.descriptors.push(DescriptorStream {
                    ssrc,
                    ..Default::default()
                });
                self.descriptors.len() - 1
            }
        };
        let stream = &mut self.descriptors[index];
        // A descriptor that does not parse, or refers to a structure that was lost, says
        // nothing of its frame.
        let Ok(Some(descriptor)) = stream.reader.read(data) else {
            return;
        };
        if let Some(frame) = stream
            .frames
            .iter_mut()
            .find(|f| f.frame_number == descriptor.frame_number)
        {
            frame.structure_attached |= descriptor.attached_structure.is_some();
            return;
        }
        let frame_id = stream.unwrap(descriptor.frame_number);
        let frame = DescribedFrame {
            frame_number: descriptor.frame_number,
            frame_id,
            dependencies: descriptor
                .fdiffs
                .iter()
                .map(|&fdiff| frame_id.saturating_sub(u64::from(fdiff)))
                .collect(),
            spatial_id: descriptor.spatial_id,
            temporal_id: descriptor.temporal_id,
            resolution: descriptor.resolution.map(|r| {
                (
                    u16::try_from(r.width).unwrap_or(u16::MAX),
                    u16::try_from(r.height).unwrap_or(u16::MAX),
                )
            }),
            structure_attached: descriptor.attached_structure.is_some(),
        };
        if stream.frames.len() >= MAX_DESCRIBED_FRAMES {
            stream.frames.pop_front();
        }
        stream.frames.push_back(frame);
    }

    fn arrival(&self, ssrc: u32, rtp_timestamp: u32) -> Option<&FrameArrival> {
        self.arrivals
            .iter()
            .rev()
            .find(|a| a.ssrc == ssrc && a.rtp_timestamp == rtp_timestamp)
    }

    pub(crate) fn described_frame(&self, ssrc: u32, frame_number: u16) -> Option<&DescribedFrame> {
        self.descriptors
            .iter()
            .find(|d| d.ssrc == ssrc)?
            .frames
            .iter()
            .rev()
            .find(|f| f.frame_number == frame_number)
    }

    /// The metadata both kinds share, for a frame of `ssrc` at `rtp_timestamp`.
    pub(crate) fn common(&self, first: &rtp::Header, mime_type: String) -> RTCEncodedFrameMetadata {
        let arrival = self.arrival(first.ssrc, first.timestamp);
        RTCEncodedFrameMetadata {
            synchronization_source: first.ssrc,
            payload_type: first.payload_type,
            contributing_sources: first.csrc.clone(),
            rtp_timestamp: first.timestamp,
            receive_time: arrival.map(|a| a.last_receive),
            capture_time: arrival.and_then(|a| a.capture_time),
            sender_capture_time_offset: arrival.and_then(|a| a.sender_capture_time_offset),
            mime_type,
        }
    }

    /// Remembers the size a frame of `ssrc` stated, or gives the last one stated.
    pub(crate) fn size(&mut self, ssrc: u32, stated: Option<(u16, u16)>) -> Option<(u16, u16)> {
        match stated {
            Some((width, height)) => {
                match self.sizes.iter_mut().find(|s| s.0 == ssrc) {
                    Some(size) => *size = (ssrc, width, height),
                    None => self.sizes.push((ssrc, width, height)),
                }
                Some((width, height))
            }
            None => self
                .sizes
                .iter()
                .find(|s| s.0 == ssrc)
                .map(|&(_, width, height)| (width, height)),
        }
    }
}

/// What a video frame's payload says of it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct PayloadFrameInfo {
    /// Whether it is a key frame, when the payload says.
    pub(crate) key_frame: Option<bool>,
    pub(crate) size: Option<(u16, u16)>,
    pub(crate) spatial_id: Option<u8>,
    pub(crate) temporal_id: Option<u8>,
}

/// Reads what the payloads of one frame's packets (in sequence number order) say of it, by
/// the codec's MIME type. A payload that does not parse says nothing.
pub(crate) fn inspect_video_payloads(mime_type: &str, payloads: &[&Bytes]) -> PayloadFrameInfo {
    let mime = mime_type.to_ascii_lowercase();
    match mime.as_str() {
        "video/vp8" => inspect_vp8(payloads),
        "video/vp9" => inspect_vp9(payloads),
        "video/h264" => inspect_h264(payloads),
        "video/av1" => inspect_av1(payloads),
        _ => PayloadFrameInfo::default(),
    }
}

/// RFC 7741: the payload descriptor of the first packet of the frame (S set, partition 0)
/// gives the temporal layer; the VP8 frame tag after it whether it is a key frame (P bit 0,
/// RFC 6386 section 9.1), and a key frame's header its size (14 bits each, little endian,
/// after the start code 0x9d 0x01 0x2a).
fn inspect_vp8(payloads: &[&Bytes]) -> PayloadFrameInfo {
    let mut info = PayloadFrameInfo::default();
    for payload in payloads {
        let mut packet = rtp::codec::vp8::Vp8Packet::default();
        let Ok(frame) = packet.depacketize(payload) else {
            continue;
        };
        if packet.t == 1 || info.temporal_id.is_none() {
            info.temporal_id = Some(if packet.t == 1 { packet.tid } else { 0 });
        }
        if packet.s == 1 && packet.pid == 0 && !frame.is_empty() {
            let key = frame[0] & 0x01 == 0;
            info.key_frame = Some(key);
            if key && frame.len() >= 10 && frame[3..6] == [0x9d, 0x01, 0x2a] {
                let width = u16::from_le_bytes([frame[6], frame[7]]) & 0x3fff;
                let height = u16::from_le_bytes([frame[8], frame[9]]) & 0x3fff;
                info.size = Some((width, height));
            }
            info.spatial_id = Some(0);
            break;
        }
    }
    info
}

/// RFC 9628: the payload descriptor's P bit (inter-picture predicted), the layer indices
/// (SID, TID) and the scalability structure's resolution of the frame's spatial layer.
fn inspect_vp9(payloads: &[&Bytes]) -> PayloadFrameInfo {
    let mut info = PayloadFrameInfo::default();
    for payload in payloads {
        let mut packet = rtp::codec::vp9::Vp9Packet::default();
        if packet.depacketize(payload).is_err() {
            continue;
        }
        if info.key_frame.is_none() && packet.b {
            info.key_frame = Some(!packet.p);
        }
        if packet.l {
            info.spatial_id.get_or_insert(packet.sid);
            info.temporal_id.get_or_insert(packet.tid);
        }
        if packet.v && packet.y {
            let layer = usize::from(if packet.l { packet.sid } else { 0 });
            if let (Some(&width), Some(&height)) =
                (packet.width.get(layer), packet.height.get(layer))
            {
                info.size = Some((width, height));
            }
        }
    }
    info.spatial_id.get_or_insert(0);
    info.temporal_id.get_or_insert(0);
    info
}

/// RFC 6184: the NAL units of the frame (single NAL unit packets, STAP-A, the first fragment
/// of an FU-A): an IDR slice (type 5) makes it a key frame, a non-IDR slice (type 1) a delta
/// frame, and a sequence parameter set (type 7) gives the size.
fn inspect_h264(payloads: &[&Bytes]) -> PayloadFrameInfo {
    use rtp::codec::h264::{FUA_NALU_TYPE, SPS_NALU_TYPE, STAPA_NALU_TYPE};
    let mut info = PayloadFrameInfo {
        spatial_id: Some(0),
        temporal_id: Some(0),
        ..Default::default()
    };
    let mut nal = |nal: &[u8], whole: bool| {
        let Some(&header) = nal.first() else { return };
        match header & 0x1f {
            5 => info.key_frame = Some(true),
            1 if info.key_frame.is_none() => info.key_frame = Some(false),
            t if t == SPS_NALU_TYPE && whole => {
                if let Some(size) = h264_sps_size(&nal[1..]) {
                    info.size = Some(size);
                }
            }
            _ => {}
        }
    };
    for payload in payloads {
        let Some(&header) = payload.first() else {
            continue;
        };
        match header & 0x1f {
            STAPA_NALU_TYPE => {
                let mut rest = &payload[1..];
                while rest.len() >= 2 {
                    let size = usize::from(u16::from_be_bytes([rest[0], rest[1]]));
                    if rest.len() < 2 + size {
                        break;
                    }
                    nal(&rest[2..2 + size], true);
                    rest = &rest[2 + size..];
                }
            }
            FUA_NALU_TYPE => {
                // The FU header: S bit, then the fragmented NAL unit's type.
                if payload.len() >= 2 && payload[1] & 0x80 != 0 {
                    nal(&[(header & 0xe0) | (payload[1] & 0x1f)], false);
                }
            }
            1..=23 => nal(payload, true),
            _ => {}
        }
    }
    info
}

/// An exp-Golomb bit reader over an RBSP (emulation prevention bytes removed).
struct BitReader {
    data: Vec<u8>,
    position: usize,
}

impl BitReader {
    fn from_nal_payload(nal: &[u8]) -> Self {
        // ITU-T H.264 7.4.1: 0x000003 → 0x0000.
        let mut data = Vec::with_capacity(nal.len());
        let mut zeros = 0;
        for &byte in nal {
            if zeros >= 2 && byte == 3 {
                zeros = 0;
                continue;
            }
            zeros = if byte == 0 { zeros + 1 } else { 0 };
            data.push(byte);
        }
        Self { data, position: 0 }
    }

    fn from_bytes(data: &[u8]) -> Self {
        Self {
            data: data.to_vec(),
            position: 0,
        }
    }

    fn bit(&mut self) -> Option<u32> {
        let byte = *self.data.get(self.position / 8)?;
        let bit = (byte >> (7 - self.position % 8)) & 1;
        self.position += 1;
        Some(u32::from(bit))
    }

    fn bits(&mut self, n: u32) -> Option<u32> {
        let mut value = 0u32;
        for _ in 0..n {
            value = (value << 1) | self.bit()?;
        }
        Some(value)
    }

    fn skip(&mut self, n: u32) -> Option<()> {
        self.bits(n).map(|_| ())
    }

    /// `ue(v)`.
    fn ue(&mut self) -> Option<u32> {
        let mut zeros = 0;
        while self.bit()? == 0 {
            zeros += 1;
            if zeros > 31 {
                return None;
            }
        }
        Some((1u32 << zeros) - 1 + self.bits(zeros)?)
    }

    /// `se(v)`.
    fn se(&mut self) -> Option<i32> {
        let k = self.ue()?;
        Some(if k % 2 == 1 {
            k.div_ceil(2) as i32
        } else {
            -((k / 2) as i32)
        })
    }

    /// AV1 `uvlc()`.
    fn uvlc(&mut self) -> Option<u32> {
        let mut zeros = 0;
        while self.bit()? == 0 {
            zeros += 1;
            if zeros >= 32 {
                return Some(u32::MAX);
            }
        }
        Some((1u32 << zeros) - 1 + self.bits(zeros)?)
    }
}

/// The frame size an H.264 sequence parameter set (its RBSP after the NAL header) states
/// (ITU-T H.264 7.3.2.1.1, the cropping rectangle of 7.4.2.1.1 applied).
pub(crate) fn h264_sps_size(sps: &[u8]) -> Option<(u16, u16)> {
    let mut r = BitReader::from_nal_payload(sps);
    let profile_idc = r.bits(8)?;
    r.skip(16)?; // constraint flags, reserved, level_idc
    r.ue()?; // seq_parameter_set_id
    let mut chroma_format_idc = 1;
    let mut separate_colour_plane = 0;
    if matches!(
        profile_idc,
        100 | 110 | 122 | 244 | 44 | 83 | 86 | 118 | 128 | 138 | 139 | 134 | 135
    ) {
        chroma_format_idc = r.ue()?;
        if chroma_format_idc == 3 {
            separate_colour_plane = r.bit()?;
        }
        r.ue()?; // bit_depth_luma_minus8
        r.ue()?; // bit_depth_chroma_minus8
        r.bit()?; // qpprime_y_zero_transform_bypass_flag
        if r.bit()? == 1 {
            // seq_scaling_matrix_present_flag: skip the scaling lists (7.3.2.1.1.1).
            let lists = if chroma_format_idc == 3 { 12 } else { 8 };
            for i in 0..lists {
                if r.bit()? == 1 {
                    let size = if i < 6 { 16 } else { 64 };
                    let (mut last, mut next) = (8i32, 8i32);
                    for _ in 0..size {
                        if next != 0 {
                            next = (last + r.se()? + 256) % 256;
                        }
                        if next != 0 {
                            last = next;
                        }
                    }
                }
            }
        }
    }
    r.ue()?; // log2_max_frame_num_minus4
    match r.ue()? {
        0 => {
            r.ue()?; // log2_max_pic_order_cnt_lsb_minus4
        }
        1 => {
            r.bit()?; // delta_pic_order_always_zero_flag
            r.se()?; // offset_for_non_ref_pic
            r.se()?; // offset_for_top_to_bottom_field
            for _ in 0..r.ue()? {
                r.se()?;
            }
        }
        _ => {}
    }
    r.ue()?; // max_num_ref_frames
    r.bit()?; // gaps_in_frame_num_value_allowed_flag
    let width_in_mbs = r.ue()? + 1;
    let height_in_map_units = r.ue()? + 1;
    let frame_mbs_only = r.bit()?;
    if frame_mbs_only == 0 {
        r.bit()?; // mb_adaptive_frame_field_flag
    }
    r.bit()?; // direct_8x8_inference_flag
    let mut width = width_in_mbs * 16;
    let mut height = (2 - frame_mbs_only) * height_in_map_units * 16;
    if r.bit()? == 1 {
        // frame_cropping_flag: offsets in chroma units (Table 6-1).
        let (left, right, top, bottom) = (r.ue()?, r.ue()?, r.ue()?, r.ue()?);
        let (sub_width, sub_height) = match (chroma_format_idc, separate_colour_plane) {
            (1, 0) => (2, 2),
            (2, 0) => (2, 1),
            _ => (1, 1),
        };
        let crop_x = sub_width;
        let crop_y = sub_height * (2 - frame_mbs_only);
        width = width.checked_sub(crop_x * (left + right))?;
        height = height.checked_sub(crop_y * (top + bottom))?;
    }
    Some((u16::try_from(width).ok()?, u16::try_from(height).ok()?))
}

/// The AV1 RTP specification: the aggregation header's N bit begins a coded video sequence
/// (a key frame); the OBUs give the layer indices (OBU extension header) and, in a sequence
/// header, the maximum frame size.
fn inspect_av1(payloads: &[&Bytes]) -> PayloadFrameInfo {
    let mut info = PayloadFrameInfo::default();
    let mut depacketizer = rtp::codec::av1::Av1Depacketizer::new();
    let mut stream = Vec::new();
    for (i, payload) in payloads.iter().enumerate() {
        if i == 0 && !payload.is_empty() {
            info.key_frame = Some(payload[0] & 0x08 != 0);
        }
        if let Ok(obus) = depacketizer.depacketize(payload) {
            stream.extend_from_slice(&obus);
        }
    }
    // The low overhead bitstream format (AV1 specification 5.2, 5.3): each OBU with its
    // header, optional extension header and obu_size.
    let mut rest = stream.as_slice();
    while let Some(&header) = rest.first() {
        let obu_type = (header >> 3) & 0x0f;
        let mut index = 1;
        if header & 0x04 != 0 {
            let Some(&extension) = rest.get(1) else { break };
            index = 2;
            if info.temporal_id.is_none() {
                info.temporal_id = Some(extension >> 5);
                info.spatial_id = Some((extension >> 3) & 0x03);
            }
        }
        let size = if header & 0x02 != 0 {
            let mut size = 0usize;
            let mut shift = 0;
            loop {
                let Some(&byte) = rest.get(index) else {
                    return finish_av1(info);
                };
                index += 1;
                size |= usize::from(byte & 0x7f) << shift;
                shift += 7;
                if byte & 0x80 == 0 || shift > 56 {
                    break;
                }
            }
            size
        } else {
            rest.len().saturating_sub(index)
        };
        let Some(payload) = rest.get(index..index + size) else {
            break;
        };
        // OBU_SEQUENCE_HEADER.
        if obu_type == 1
            && let Some(size) = av1_sequence_header_size(payload)
        {
            info.size = Some(size);
        }
        rest = &rest[index + size..];
    }
    finish_av1(info)
}

fn finish_av1(mut info: PayloadFrameInfo) -> PayloadFrameInfo {
    info.spatial_id.get_or_insert(0);
    info.temporal_id.get_or_insert(0);
    info
}

/// `max_frame_width_minus_1 + 1` and `max_frame_height_minus_1 + 1` of an AV1 sequence header
/// OBU's payload (AV1 specification 5.5.1).
pub(crate) fn av1_sequence_header_size(payload: &[u8]) -> Option<(u16, u16)> {
    let mut r = BitReader::from_bytes(payload);
    r.skip(3)?; // seq_profile
    r.skip(1)?; // still_picture
    let reduced_still_picture_header = r.bit()?;
    if reduced_still_picture_header == 1 {
        r.skip(5)?; // seq_level_idx[0]
    } else {
        let timing_info_present = r.bit()?;
        let mut decoder_model_info_present = 0;
        let mut buffer_delay_length = 0;
        if timing_info_present == 1 {
            r.skip(32)?; // num_units_in_display_tick
            r.skip(32)?; // time_scale
            if r.bit()? == 1 {
                r.uvlc()?; // num_ticks_per_picture_minus_1
            }
            decoder_model_info_present = r.bit()?;
            if decoder_model_info_present == 1 {
                buffer_delay_length = r.bits(5)? + 1;
                r.skip(32)?; // num_units_in_decoding_tick
                r.skip(5)?; // buffer_removal_time_length_minus_1
                r.skip(5)?; // frame_presentation_time_length_minus_1
            }
        }
        let initial_display_delay_present = r.bit()?;
        let operating_points = r.bits(5)? + 1;
        for _ in 0..operating_points {
            r.skip(12)?; // operating_point_idc
            let seq_level_idx = r.bits(5)?;
            if seq_level_idx > 7 {
                r.skip(1)?; // seq_tier
            }
            if decoder_model_info_present == 1 && r.bit()? == 1 {
                r.skip(buffer_delay_length)?; // decoder_buffer_delay
                r.skip(buffer_delay_length)?; // encoder_buffer_delay
                r.skip(1)?; // low_delay_mode_flag
            }
            if initial_display_delay_present == 1 && r.bit()? == 1 {
                r.skip(4)?; // initial_display_delay_minus_1
            }
        }
    }
    let width_bits = r.bits(4)? + 1;
    let height_bits = r.bits(4)? + 1;
    let width = r.bits(width_bits)? + 1;
    let height = r.bits(height_bits)? + 1;
    Some((u16::try_from(width).ok()?, u16::try_from(height).ok()?))
}

#[cfg(test)]
#[path = "frame_metadata_test.rs"]
mod frame_metadata_test;
