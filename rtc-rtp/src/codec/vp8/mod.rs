#[cfg(test)]
mod vp8_descriptor_test;
#[cfg(test)]
mod vp8_layers_test;
#[cfg(test)]
mod vp8_test;

use crate::packetizer::{Depacketizer, Payloader};
use shared::error::{Error, Result};

use bytes::{BufMut, Bytes, BytesMut};

/// Bytes of mandatory VP8 payload descriptor prefixed to each payload.
pub const VP8_HEADER_SIZE: usize = 1;

/// The highest temporal layer id the two-bit `TID` field carries (RFC 7741 section 4.2).
pub const VP8_MAX_TEMPORAL_ID: u8 = 3;
/// The highest `KEYIDX` the five-bit field carries (RFC 7741 section 4.2).
pub const VP8_MAX_KEY_IDX: u8 = 31;

/// The temporal layer of one VP8 frame, as the encoder reports it (RFC 7741 section 4.2).
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Vp8TemporalLayer {
    /// `TID`: the temporal layer the frame belongs to; 0 is the base layer.
    pub tid: u8,
    /// `Y`, the layer sync bit: the frame depends only on the base layer frame with the same
    /// `TL0PICIDX`, so a receiver can start decoding this layer here. Leave it `false` when
    /// the dependency is not known (always safe).
    pub layer_sync: bool,
}

/// What the encoder knows about one VP8 frame and the payload descriptor carries (RFC 7741
/// section 4.2). The default describes a frame of a stream without temporal layers.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Vp8FrameInfo {
    /// `N`: the frame is not a reference for any other frame and can be discarded without
    /// affecting later frames. Leave it `false` when the reference status is not known.
    pub non_reference: bool,
    /// The frame's temporal layer. When set, the descriptor carries `TID`, `Y` and
    /// `TL0PICIDX` (which the payloader counts).
    pub temporal: Option<Vp8TemporalLayer>,
    /// `KEYIDX`, the encoder's running index of key frames (0 to 31). When set, the descriptor
    /// carries it; a sender that uses it sets it on key frames and interframes alike.
    pub key_idx: Option<u8>,
}

/// Vp8Payloader payloads VP8 packets
///
/// [`Payloader::payload`] sends a frame of a stream without temporal layers.
/// [`Vp8Payloader::payload_frame`] takes the frame's layer information from the encoder and
/// writes `N`, `TID`, `Y`, `TL0PICIDX` and `KEYIDX` (RFC 7741 section 4.2), which is what lets
/// a forwarder drop temporal layers.
#[derive(Default, Debug, Copy, Clone)]
pub struct Vp8Payloader {
    /// Whether to include the optional picture id in the payload descriptor.
    ///
    /// Lets a receiver detect loss within a frame, at one or two bytes per packet.
    pub enable_picture_id: bool,
    picture_id: u16,
    /// `TL0PICIDX` of the last base layer frame sent.
    tl0_pic_idx: u8,
}

impl Vp8Payloader {
    /// Sets the PictureID of the next frame (15 bits). RFC 7741 section 4.2 lets it start at a
    /// random value; the default is 0.
    pub fn set_initial_picture_id(&mut self, picture_id: u16) {
        self.picture_id = picture_id & 0x7FFF;
    }

    /// Sets `TL0PICIDX` so that the next base layer frame carries `tl0_pic_idx`. RFC 7741
    /// section 4.2 lets it start at a random value; by default the first base layer frame
    /// carries 1.
    pub fn set_initial_tl0_pic_idx(&mut self, tl0_pic_idx: u8) {
        self.tl0_pic_idx = tl0_pic_idx.wrapping_sub(1);
    }

    /// The PictureID the next frame is sent with.
    pub fn picture_id(&self) -> u16 {
        self.picture_id
    }

    /// Fragments one VP8 frame, describing it with `info`.
    ///
    /// The descriptor carries the PictureID when [`enable_picture_id`](Self::enable_picture_id)
    /// is set, `TL0PICIDX`, `TID` and `Y` when `info.temporal` is, `KEYIDX` when
    /// `info.key_idx` is, and `N` from `info.non_reference`. `TL0PICIDX` is incremented for
    /// every frame with `TID` 0 and repeated on the frames above it. `S` is set on the frame's
    /// first packet only and `PID` is 0 on all of them: the frame is cut at MTU boundaries
    /// without regard to its partitions, which section 4.4 allows.
    ///
    /// # Errors
    ///
    /// `TID` above 3 or `KEYIDX` above 31, which the fields cannot carry.
    pub fn payload_frame(
        &mut self,
        mtu: usize,
        payload: &Bytes,
        info: &Vp8FrameInfo,
    ) -> Result<Vec<Bytes>> {
        if let Some(temporal) = &info.temporal
            && temporal.tid > VP8_MAX_TEMPORAL_ID
        {
            return Err(Error::Other(format!(
                "VP8 TID {} does not fit two bits",
                temporal.tid
            )));
        }
        if let Some(key_idx) = info.key_idx
            && key_idx > VP8_MAX_KEY_IDX
        {
            return Err(Error::Other(format!(
                "VP8 KEYIDX {key_idx} does not fit five bits"
            )));
        }
        if payload.is_empty() || mtu == 0 {
            return Ok(vec![]);
        }

        /*
         * https://tools.ietf.org/html/rfc7741#section-4.2
         *
         *       0 1 2 3 4 5 6 7
         *      +-+-+-+-+-+-+-+-+
         *      |X|R|N|S|R| PID | (REQUIRED)
         *      +-+-+-+-+-+-+-+-+
         * X:   |I|L|T|K| RSV   | (OPTIONAL)
         *      +-+-+-+-+-+-+-+-+
         * I:   |M| PictureID   | (OPTIONAL)
         *      +-+-+-+-+-+-+-+-+
         * L:   |   tl0picidx   | (OPTIONAL)
         *      +-+-+-+-+-+-+-+-+
         * T/K: |tid|Y| KEYIDX  | (OPTIONAL)
         *      +-+-+-+-+-+-+-+-+
         *  S: Start of VP8 partition.  SHOULD be set to 1 when the first payload
         *     octet of the RTP packet is the beginning of a new VP8 partition,
         *     and MUST NOT be 1 otherwise.  The S bit MUST be set to 1 for the
         *     first packet of each encoded frame.
         */
        // The descriptor after its first octet: the same on every packet of the frame.
        let mut extension = [0u8; 5];
        let mut extension_len = 0;
        let has_extension =
            self.enable_picture_id || info.temporal.is_some() || info.key_idx.is_some();
        // TL0PICIDX counts base layer frames: a frame with TID 0 takes the next value, a frame
        // above it repeats the value of the base layer frame it depends on.
        let tl0_pic_idx = match &info.temporal {
            Some(temporal) if temporal.tid == 0 => self.tl0_pic_idx.wrapping_add(1),
            _ => self.tl0_pic_idx,
        };
        if has_extension {
            let mut flags = 0u8;
            extension_len = 1;
            if self.enable_picture_id {
                flags |= 0x80; // I
                if self.picture_id < 128 {
                    extension[extension_len] = self.picture_id as u8;
                    extension_len += 1;
                } else {
                    extension[extension_len] = 0x80 | (self.picture_id >> 8) as u8; // M
                    extension[extension_len + 1] = (self.picture_id & 0xFF) as u8;
                    extension_len += 2;
                }
            }
            if info.temporal.is_some() {
                // L is only sent with T (RFC 7741 4.2: "L=1 requires T=1").
                flags |= 0x40 | 0x20;
                extension[extension_len] = tl0_pic_idx;
                extension_len += 1;
            }
            if info.temporal.is_some() || info.key_idx.is_some() {
                let mut b = 0u8;
                if let Some(temporal) = &info.temporal {
                    b |= temporal.tid << 6;
                    if temporal.layer_sync {
                        b |= 0x20;
                    }
                }
                if let Some(key_idx) = info.key_idx {
                    flags |= 0x10; // K
                    b |= key_idx;
                }
                extension[extension_len] = b;
                extension_len += 1;
            }
            extension[0] = flags;
        }

        let using_header_size = VP8_HEADER_SIZE + extension_len;
        if mtu <= using_header_size {
            return Ok(vec![]);
        }
        let max_fragment_size = mtu - using_header_size;

        let mut payloads = Vec::with_capacity(payload.len().div_ceil(max_fragment_size));
        let mut payload_data_index: usize = 0;
        while payload_data_index < payload.len() {
            let current_fragment_size =
                std::cmp::min(max_fragment_size, payload.len() - payload_data_index);
            let mut out = BytesMut::with_capacity(using_header_size + current_fragment_size);
            let mut first = 0u8;
            if has_extension {
                first |= 0x80; // X
            }
            if info.non_reference {
                first |= 0x20; // N
            }
            if payload_data_index == 0 {
                first |= 0x10; // S
            }
            out.put_u8(first);
            out.put(&extension[..extension_len]);
            out.put(
                &*payload.slice(payload_data_index..payload_data_index + current_fragment_size),
            );
            payloads.push(out.freeze());

            payload_data_index += current_fragment_size;
        }

        self.picture_id += 1;
        self.picture_id &= 0x7FFF;
        self.tl0_pic_idx = tl0_pic_idx;

        Ok(payloads)
    }
}

impl Payloader for Vp8Payloader {
    /// Payload fragments a VP8 packet across one or more byte arrays
    fn payload(&mut self, mtu: usize, payload: &Bytes) -> Result<Vec<Bytes>> {
        self.payload_frame(mtu, payload, &Vp8FrameInfo::default())
    }

    fn clone_to(&self) -> Box<dyn Payloader> {
        Box::new(*self)
    }
}

/// Vp8Packet represents the VP8 header that is stored in the payload of an RTP Packet
///
/// Every field describes the packet last given to [`Depacketizer::depacketize`]: a field the
/// packet did not carry reads 0.
#[derive(PartialEq, Eq, Debug, Default, Clone)]
pub struct Vp8Packet {
    /// Required Header
    /// extended controlbits present
    pub x: u8,
    /// when set to 1 this frame can be discarded
    pub n: u8,
    /// start of VP8 partition
    pub s: u8,
    /// partition index
    pub pid: u8,

    /// Extended control bits
    /// 1 if PictureID is present
    pub i: u8,
    /// 1 if tl0picidx is present
    pub l: u8,
    /// 1 if tid is present
    pub t: u8,
    /// 1 if KEYIDX is present
    pub k: u8,

    /// Optional extension
    /// 7 or 15 bits, picture ID
    pub picture_id: u16,
    /// Whether the picture ID was sent in 15 bits (`M`=1) rather than 7. The width can change
    /// during a session (RFC 7741 section 4.2); a PictureID wraps at the width it was sent in.
    pub picture_id_15_bits: bool,
    /// 8 bits temporal level zero index
    pub tl0_pic_idx: u8,
    /// 2 bits temporal layer index
    pub tid: u8,
    /// 1 bit layer sync bit
    pub y: u8,
    /// 5 bits temporal key frame index
    pub key_idx: u8,
}

impl Vp8Packet {
    /// Parses the payload descriptor at the start of `packet` and returns its length.
    fn parse_descriptor(&mut self, packet: &[u8]) -> Result<usize> {
        //    0 1 2 3 4 5 6 7                      0 1 2 3 4 5 6 7
        //    +-+-+-+-+-+-+-+-+                   +-+-+-+-+-+-+-+-+
        //    |X|R|N|S|R| PID | (REQUIRED)        |X|R|N|S|R| PID | (REQUIRED)
        //    +-+-+-+-+-+-+-+-+                   +-+-+-+-+-+-+-+-+
        // X: |I|L|T|K| RSV   | (OPTIONAL)   X:   |I|L|T|K| RSV   | (OPTIONAL)
        //    +-+-+-+-+-+-+-+-+                   +-+-+-+-+-+-+-+-+
        // I: |M| PictureID   | (OPTIONAL)   I:   |M| PictureID   | (OPTIONAL)
        //    +-+-+-+-+-+-+-+-+                   +-+-+-+-+-+-+-+-+
        // L: |   tl0picidx   | (OPTIONAL)        |   PictureID   |
        //    +-+-+-+-+-+-+-+-+                   +-+-+-+-+-+-+-+-+
        //T/K:|tid|Y| KEYIDX  | (OPTIONAL)   L:   |   tl0picidx   | (OPTIONAL)
        //    +-+-+-+-+-+-+-+-+                   +-+-+-+-+-+-+-+-+
        //T/K:|tid|Y| KEYIDX  | (OPTIONAL)
        //    +-+-+-+-+-+-+-+-+
        // One depacketizer reads a whole stream: nothing of the previous packet's descriptor
        // may be left for this one (RFC 7741 4.2: with X=0 there are no extensions).
        *self = Self::default();

        let mut index = 0;
        let mut next = || -> Result<u8> {
            let b = *packet.get(index).ok_or(Error::ErrShortPacket)?;
            index += 1;
            Ok(b)
        };

        // The R bits (0x40, 0x08) are ignored.
        let b = next()?;
        self.x = (b & 0x80) >> 7;
        self.n = (b & 0x20) >> 5;
        self.s = (b & 0x10) >> 4;
        self.pid = b & 0x07;

        if self.x == 1 {
            // The four RSV bits are ignored.
            let b = next()?;
            self.i = (b & 0x80) >> 7;
            self.l = (b & 0x40) >> 6;
            self.t = (b & 0x20) >> 5;
            self.k = (b & 0x10) >> 4;
        }

        if self.i == 1 {
            let b = next()?;
            if b & 0x80 > 0 {
                // M == 1, PID is 15 bits
                self.picture_id = (((b & 0x7f) as u16) << 8) | (next()? as u16);
                self.picture_id_15_bits = true;
            } else {
                self.picture_id = b as u16;
            }
        }

        if self.l == 1 {
            self.tl0_pic_idx = next()?;
        }

        if self.t == 1 || self.k == 1 {
            let b = next()?;
            // TID and Y are ignored without T, KEYIDX without K.
            if self.t == 1 {
                self.tid = b >> 6;
                self.y = (b >> 5) & 0x1;
            }
            if self.k == 1 {
                self.key_idx = b & 0x1F;
            }
        }

        Ok(index)
    }

    /// Whether this packet is the first of a frame: `S`=1 and `PID`=0 (RFC 7741 section 4.5.1).
    pub fn is_frame_start(&self) -> bool {
        self.s == 1 && self.pid == 0
    }
}

impl Depacketizer for Vp8Packet {
    /// depacketize parses the passed byte slice and stores the result in the VP8Packet this method is called upon
    ///
    /// A packet is its descriptor and at least one octet of VP8 data (RFC 7741 section 4.2);
    /// anything shorter is an error.
    fn depacketize(&mut self, packet: &Bytes) -> Result<Bytes> {
        let descriptor_len = self.parse_descriptor(packet)?;
        if descriptor_len >= packet.len() {
            return Err(Error::ErrShortPacket);
        }
        Ok(packet.slice(descriptor_len..))
    }

    /// Whether the packet starts a frame: `S`=1 and `PID`=0 (RFC 7741 section 4.5.1). `S`=1
    /// with another `PID` starts a later partition of a frame.
    fn is_partition_head(&self, payload: &Bytes) -> bool {
        if payload.is_empty() {
            false
        } else {
            (payload[0] & 0x10) != 0 && (payload[0] & 0x07) == 0
        }
    }

    fn is_partition_tail(&self, marker: bool, _payload: &Bytes) -> bool {
        marker
    }
}

/// Decides which packets of a VP8 stream with temporal layers to forward for a target frame
/// rate (RFC 7741 sections 4.2 and 8: discarding by `TID`).
///
/// A middlebox keeps one per receiver. Layers at or below the target are forwarded. Going down
/// takes effect at once. Going up waits for a switch point: a key frame, or a frame with the
/// layer sync bit `Y` (it depends on the base layer only, and no later frame depends on
/// anything older than that base layer frame). A stream without `TID` is forwarded whole.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Vp8TemporalLayerFilter {
    target_tid: u8,
    /// The highest layer forwarded at the moment.
    current_tid: u8,
    /// The lowest layer, at or below the target, of which a packet was withheld since the last
    /// base layer frame. A layer sync frame vouches for what is older than that base layer
    /// frame, not for what was withheld after it.
    withheld_tid: Option<u8>,
}

impl Default for Vp8TemporalLayerFilter {
    fn default() -> Self {
        Self::new(VP8_MAX_TEMPORAL_ID)
    }
}

impl Vp8TemporalLayerFilter {
    /// A filter that forwards the layers up to `target_tid`. It starts at the base layer and
    /// adds the layers above it at a switch point.
    pub fn new(target_tid: u8) -> Self {
        Self {
            target_tid: target_tid.min(VP8_MAX_TEMPORAL_ID),
            current_tid: 0,
            withheld_tid: None,
        }
    }

    /// Changes the target layer. A lower one applies to the next packet; a higher one at the
    /// next switch point.
    pub fn set_target(&mut self, target_tid: u8) {
        self.target_tid = target_tid.min(VP8_MAX_TEMPORAL_ID);
        self.current_tid = self.current_tid.min(self.target_tid);
    }

    /// The target layer.
    pub fn target(&self) -> u8 {
        self.target_tid
    }

    /// The highest layer forwarded at the moment.
    pub fn current(&self) -> u8 {
        self.current_tid
    }

    /// Whether to forward a packet: `descriptor` is its parsed payload descriptor (a
    /// [`Vp8Packet`] after [`Depacketizer::depacketize`]) and `vp8_data` the VP8 data that
    /// follows the descriptor. Call it for every packet of the stream, in order.
    pub fn forward(&mut self, descriptor: &Vp8Packet, vp8_data: &[u8]) -> bool {
        if descriptor.t == 0 {
            // No temporal layer information: nothing to select on.
            return true;
        }
        let tid = descriptor.tid;
        if descriptor.is_frame_start() {
            // The first octet of a frame is the VP8 frame tag; its low bit is 0 on a key frame
            // (RFC 6386 section 9.1). A key frame restarts every layer.
            if vp8_data.first().is_some_and(|b| b & 0x01 == 0) {
                self.current_tid = self.target_tid;
                self.withheld_tid = None;
            } else if tid == 0 {
                self.withheld_tid = None;
            }
        }
        if tid > self.target_tid {
            return false;
        }
        if tid <= self.current_tid {
            return true;
        }
        // A layer above the ones forwarded so far. A layer sync frame opens every layer of
        // which nothing was withheld since the base layer frame it depends on. The frame's
        // first packet decides; its other packets follow because the layer is then current.
        if descriptor.y == 1 && descriptor.is_frame_start() {
            let open = match self.withheld_tid {
                Some(withheld) => withheld.saturating_sub(1).min(self.target_tid),
                None => self.target_tid,
            };
            if tid <= open {
                self.current_tid = open;
                return true;
            }
        }
        self.withheld_tid = Some(self.withheld_tid.map_or(tid, |w| w.min(tid)));
        false
    }
}
