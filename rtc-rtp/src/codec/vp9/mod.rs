#[cfg(test)]
mod vp9_depacketizer_fields_test;
#[cfg(test)]
mod vp9_test;

use crate::packetizer::{Depacketizer, Payloader};
use shared::error::{Error, Result};

use bytes::{Buf, BufMut, Bytes, BytesMut};
use std::fmt;
use std::sync::Arc;

/// Flexible mode 15 bit picture ID
const VP9HEADER_SIZE: usize = 3;
const MAX_SPATIAL_LAYERS: u8 = 5;
const MAX_VP9REF_PICS: usize = 3;

/// InitialPictureIDFn is a function that returns random initial picture ID.
pub type InitialPictureIDFn = Arc<dyn (Fn() -> u16) + Send + Sync>;

/// Vp9Payloader payloads VP9 packets.
///
/// By default it uses the non-flexible mode, as browsers expect from a sender
/// without SVC (RFC 9628 section 4.2): it reads each frame's uncompressed
/// header, marks an inter frame with `P=1` (a key frame with `P=0`), and puts
/// a scalability structure with the frame size on a key frame's first
/// packet. A frame whose header doesn't parse is sent in flexible mode, as
/// before. `flexible_mode` forces the flexible mode for every frame (one
/// 15-bit picture id, no reference indices: `P=0`).
#[derive(Default, Clone)]
pub struct Vp9Payloader {
    picture_id: u16,
    initialized: bool,

    /// Supplies the starting picture id; randomized when absent.
    pub initial_picture_id_fn: Option<InitialPictureIDFn>,
    /// Sends every frame in flexible mode (`F=1`) instead.
    pub flexible_mode: bool,
}

impl fmt::Debug for Vp9Payloader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Vp9Payloader")
            .field("picture_id", &self.picture_id)
            .field("initialized", &self.initialized)
            .field("flexible_mode", &self.flexible_mode)
            .finish()
    }
}

impl Payloader for Vp9Payloader {
    /// Payload fragments an Vp9Payloader packet across one or more byte arrays
    fn payload(&mut self, mtu: usize, payload: &Bytes) -> Result<Vec<Bytes>> {
        /*
         * https://www.ietf.org/id/draft-ietf-payload-vp9-13.txt
         *
         * Flexible mode (F=1)
         *        0 1 2 3 4 5 6 7
         *       +-+-+-+-+-+-+-+-+
         *       |I|P|L|F|B|E|V|Z| (REQUIRED)
         *       +-+-+-+-+-+-+-+-+
         *  I:   |M| PICTURE ID  | (REQUIRED)
         *       +-+-+-+-+-+-+-+-+
         *  M:   | EXTENDED PID  | (RECOMMENDED)
         *       +-+-+-+-+-+-+-+-+
         *  L:   | tid |U| SID |D| (CONDITIONALLY RECOMMENDED)
         *       +-+-+-+-+-+-+-+-+                             -\
         *  P,F: | P_DIFF      |N| (CONDITIONALLY REQUIRED)    - up to 3 times
         *       +-+-+-+-+-+-+-+-+                             -/
         *  V:   | SS            |
         *       | ..            |
         *       +-+-+-+-+-+-+-+-+
         *
         * Non-flexible mode (F=0)
         *        0 1 2 3 4 5 6 7
         *       +-+-+-+-+-+-+-+-+
         *       |I|P|L|F|B|E|V|Z| (REQUIRED)
         *       +-+-+-+-+-+-+-+-+
         *  I:   |M| PICTURE ID  | (RECOMMENDED)
         *       +-+-+-+-+-+-+-+-+
         *  M:   | EXTENDED PID  | (RECOMMENDED)
         *       +-+-+-+-+-+-+-+-+
         *  L:   | tid |U| SID |D| (CONDITIONALLY RECOMMENDED)
         *       +-+-+-+-+-+-+-+-+
         *       |   tl0picidx   | (CONDITIONALLY REQUIRED)
         *       +-+-+-+-+-+-+-+-+
         *  V:   | SS            |
         *       | ..            |
         *       +-+-+-+-+-+-+-+-+
         */

        if payload.is_empty() || mtu == 0 {
            return Ok(vec![]);
        }

        if !self.initialized {
            if self.initial_picture_id_fn.is_none() {
                self.initial_picture_id_fn =
                    Some(Arc::new(|| -> u16 { rand::random::<u16>() & 0x7FFF }));
            }
            self.picture_id = if let Some(f) = &self.initial_picture_id_fn {
                f()
            } else {
                0
            };
            self.initialized = true;
        }

        let header = if self.flexible_mode {
            None
        } else {
            Vp9FrameHeader::parse(payload)
        };
        let payloads = match header {
            Some(header) => self.payload_non_flexible(mtu, payload, &header),
            None => self.payload_flexible(mtu, payload),
        };

        if !payloads.is_empty() {
            self.picture_id += 1;
            self.picture_id &= 0x7FFF;
        }

        Ok(payloads)
    }

    fn clone_to(&self) -> Box<dyn Payloader> {
        Box::new(self.clone())
    }
}

impl Vp9Payloader {
    /// Flexible mode: `I=1` with a 15-bit picture id, `P=0`.
    fn payload_flexible(&self, mtu: usize, payload: &Bytes) -> Vec<Bytes> {
        let max_fragment_size = mtu as isize - VP9HEADER_SIZE as isize;
        let mut payloads = vec![];
        let mut payload_data_remaining = payload.len();
        let mut payload_data_index = 0;

        if std::cmp::min(max_fragment_size, payload_data_remaining as isize) <= 0 {
            return vec![];
        }

        while payload_data_remaining > 0 {
            let current_fragment_size =
                std::cmp::min(max_fragment_size as usize, payload_data_remaining);
            let mut out = BytesMut::with_capacity(VP9HEADER_SIZE + current_fragment_size);
            let mut buf = [0u8; VP9HEADER_SIZE];
            buf[0] = 0x90; // F=1 I=1
            if payload_data_index == 0 {
                buf[0] |= 0x08; // B=1
            }
            if payload_data_remaining == current_fragment_size {
                buf[0] |= 0x04; // E=1
            }
            buf[1] = (self.picture_id >> 8) as u8 | 0x80;
            buf[2] = (self.picture_id & 0xFF) as u8;

            out.put(&buf[..]);

            out.put(
                &*payload.slice(payload_data_index..payload_data_index + current_fragment_size),
            );

            payloads.push(out.freeze());

            payload_data_remaining -= current_fragment_size;
            payload_data_index += current_fragment_size;
        }

        payloads
    }

    /// Non-flexible mode (RFC 9628 section 4.2): `I=1` with a 15-bit picture
    /// id, `P` from the frame type, `Z=1` (one spatial layer), and on a key
    /// frame's first packet `V=1` with a scalability structure: one spatial
    /// layer of the frame's size (`N_S=0, Y=1, G=1`) and a picture group of
    /// one picture (`T=0, U=1, R=1, P_DIFF=1`).
    fn payload_non_flexible(
        &self,
        mtu: usize,
        payload: &Bytes,
        header: &Vp9FrameHeader,
    ) -> Vec<Bytes> {
        const SS_SIZE: usize = 8;
        let mut payloads = vec![];
        let mut payload_data_remaining = payload.len();
        let mut payload_data_index = 0;

        while payload_data_remaining > 0 {
            let with_ss = header.key_frame && payload_data_index == 0;
            let header_size = VP9HEADER_SIZE + if with_ss { SS_SIZE } else { 0 };
            let max_fragment_size = mtu as isize - header_size as isize;
            if max_fragment_size <= 0 {
                return vec![];
            }
            let current_fragment_size =
                std::cmp::min(max_fragment_size as usize, payload_data_remaining);

            let mut out = BytesMut::with_capacity(header_size + current_fragment_size);
            let mut b0 = 0x80 | 0x01; // I=1, Z=1
            if !header.key_frame {
                b0 |= 0x40; // P=1
            }
            if payload_data_index == 0 {
                b0 |= 0x08; // B=1
            }
            if payload_data_remaining == current_fragment_size {
                b0 |= 0x04; // E=1
            }
            if with_ss {
                b0 |= 0x02; // V=1
            }
            out.put_u8(b0);
            out.put_u8((self.picture_id >> 8) as u8 | 0x80);
            out.put_u8((self.picture_id & 0xFF) as u8);
            if with_ss {
                out.put_u8(0x10 | 0x08); // N_S=0, Y=1, G=1
                out.put_u16(header.width);
                out.put_u16(header.height);
                out.put_u8(0x01); // N_G=1
                out.put_u8((1 << 4) | (1 << 2)); // T=0, U=1, R=1
                out.put_u8(0x01); // P_DIFF=1
            }
            out.put(
                &*payload.slice(payload_data_index..payload_data_index + current_fragment_size),
            );
            payloads.push(out.freeze());

            payload_data_remaining -= current_fragment_size;
            payload_data_index += current_fragment_size;
        }

        payloads
    }
}

/// What the payloader needs from a VP9 frame's uncompressed header (VP9
/// bitstream specification 6.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Vp9FrameHeader {
    /// `frame_type == KEY_FRAME`.
    pub(crate) key_frame: bool,
    /// A key frame's size (0 on other frames).
    pub(crate) width: u16,
    pub(crate) height: u16,
}

impl Vp9FrameHeader {
    /// Parses the header; `None` when the bytes are not a VP9 frame.
    pub(crate) fn parse(frame: &[u8]) -> Option<Self> {
        let mut pos = 0usize;
        let mut bits = |n: usize| -> Option<u32> {
            let mut v = 0u32;
            for _ in 0..n {
                let byte = *frame.get(pos / 8)?;
                v = (v << 1) | ((byte >> (7 - (pos % 8))) & 1) as u32;
                pos += 1;
            }
            Some(v)
        };
        if bits(2)? != 2 {
            return None; // frame_marker
        }
        let low = bits(1)?;
        let high = bits(1)?;
        let profile = (high << 1) | low;
        if profile == 3 {
            bits(1)?; // reserved_zero
        }
        if bits(1)? == 1 {
            // show_existing_frame: a repeat of an earlier frame, no new data.
            bits(3)?;
            return Some(Self {
                key_frame: false,
                width: 0,
                height: 0,
            });
        }
        let key_frame = bits(1)? == 0;
        bits(2)?; // show_frame, error_resilient_mode
        if !key_frame {
            return Some(Self {
                key_frame,
                width: 0,
                height: 0,
            });
        }
        if bits(24)? != 0x49_83_42 {
            return None; // frame_sync_code
        }
        // color_config
        if profile >= 2 {
            bits(1)?; // ten_or_twelve_bit
        }
        let color_space = bits(3)?;
        if color_space != 7 {
            bits(1)?; // color_range
            if profile == 1 || profile == 3 {
                bits(3)?; // subsampling_x, subsampling_y, reserved_zero
            }
        } else if profile == 1 || profile == 3 {
            bits(1)?; // reserved_zero
        }
        let width = bits(16)? + 1;
        let height = bits(16)? + 1;
        Some(Self {
            key_frame,
            width: u16::try_from(width).ok()?,
            height: u16::try_from(height).ok()?,
        })
    }
}

/// Vp9Packet represents the VP9 header that is stored in the payload of an RTP Packet
#[derive(PartialEq, Eq, Debug, Default, Clone)]
pub struct Vp9Packet {
    /// picture ID is present
    pub i: bool,
    /// inter-picture predicted frame.
    pub p: bool,
    /// layer indices present
    pub l: bool,
    /// flexible mode
    pub f: bool,
    /// start of frame. beginning of new vp9 frame
    pub b: bool,
    /// end of frame
    pub e: bool,
    /// scalability structure (SS) present
    pub v: bool,
    /// Not a reference frame for upper spatial layers
    pub z: bool,

    /// Recommended headers
    /// 7 or 16 bits, picture ID.
    pub picture_id: u16,

    /// Conditionally recommended headers
    /// Temporal layer ID
    pub tid: u8,
    /// Switching up point
    pub u: bool,
    /// Spatial layer ID
    pub sid: u8,
    /// Inter-layer dependency used
    pub d: bool,

    /// Conditionally required headers
    /// Reference index (F=1)
    pub pdiff: Vec<u8>,
    /// Temporal layer zero index (F=0)
    pub tl0picidx: u8,

    /// Scalability structure headers
    /// N_S + 1 indicates the number of spatial layers present in the VP9 stream
    pub ns: u8,
    /// Each spatial layer's frame resolution present
    pub y: bool,
    /// PG description present flag.
    pub g: bool,
    /// N_G indicates the number of pictures in a Picture Group (PG)
    pub ng: u8,
    /// Frame width for each spatial layer.
    pub width: Vec<u16>,
    /// Frame height for each spatial layer.
    pub height: Vec<u16>,
    /// Temporal layer ID of pictures in a Picture Group
    pub pgtid: Vec<u8>,
    /// Switching up point of pictures in a Picture Group
    pub pgu: Vec<bool>,
    /// Reference indices of pictures in a Picture Group
    pub pgpdiff: Vec<Vec<u8>>,
}

impl Depacketizer for Vp9Packet {
    /// depacketize parses the passed byte slice and stores the result in the Vp9Packet this method is called upon
    fn depacketize(&mut self, packet: &Bytes) -> Result<Bytes> {
        if packet.is_empty() {
            return Err(Error::ErrShortPacket);
        }

        let reader = &mut packet.clone();
        let b = reader.get_u8();

        self.i = (b & 0x80) != 0;
        self.p = (b & 0x40) != 0;
        self.l = (b & 0x20) != 0;
        self.f = (b & 0x10) != 0;
        self.b = (b & 0x08) != 0;
        self.e = (b & 0x04) != 0;
        self.v = (b & 0x02) != 0;
        self.z = (b & 0x01) != 0;

        let mut payload_index = 1;

        // The reference indices describe this packet's picture only. They used to accumulate
        // across packets, so a long-lived depacketizer failed every flexible-mode packet once
        // two had been seen.
        self.pdiff.clear();

        if self.i {
            payload_index = self.parse_picture_id(reader, payload_index)?;
        }

        if self.l {
            payload_index = self.parse_layer_info(reader, payload_index)?;
        }

        if self.f && self.p {
            payload_index = self.parse_ref_indices(reader, payload_index)?;
        }

        if self.v {
            payload_index = self.parse_ssdata(reader, payload_index)?;
        }

        Ok(packet.slice(payload_index..))
    }

    /// is_partition_head checks whether if this is a head of the VP9 partition
    fn is_partition_head(&self, payload: &Bytes) -> bool {
        if payload.is_empty() {
            false
        } else {
            (payload[0] & 0x08) != 0
        }
    }

    fn is_partition_tail(&self, marker: bool, _payload: &Bytes) -> bool {
        marker
    }
}

impl Vp9Packet {
    // Picture ID:
    //
    //      +-+-+-+-+-+-+-+-+
    // I:   |M| PICTURE ID  |   M:0 => picture id is 7 bits.
    //      +-+-+-+-+-+-+-+-+   M:1 => picture id is 15 bits.
    // M:   | EXTENDED PID  |
    //      +-+-+-+-+-+-+-+-+
    //
    fn parse_picture_id(
        &mut self,
        reader: &mut dyn Buf,
        mut payload_index: usize,
    ) -> Result<usize> {
        if reader.remaining() == 0 {
            return Err(Error::ErrShortPacket);
        }
        let b = reader.get_u8();
        payload_index += 1;
        // PID present?
        if (b & 0x80) != 0 {
            if reader.remaining() == 0 {
                return Err(Error::ErrShortPacket);
            }
            // M == 1, PID is 15bit
            self.picture_id = (((b & 0x7f) as u16) << 8) | (reader.get_u8() as u16);
            payload_index += 1;
        } else {
            self.picture_id = (b & 0x7F) as u16;
        }

        Ok(payload_index)
    }

    fn parse_layer_info(
        &mut self,
        reader: &mut dyn Buf,
        mut payload_index: usize,
    ) -> Result<usize> {
        payload_index = self.parse_layer_info_common(reader, payload_index)?;

        if self.f {
            Ok(payload_index)
        } else {
            self.parse_layer_info_non_flexible_mode(reader, payload_index)
        }
    }

    // Layer indices (flexible mode):
    //
    //      +-+-+-+-+-+-+-+-+
    // L:   |  T  |U|  S  |D|
    //      +-+-+-+-+-+-+-+-+
    //
    fn parse_layer_info_common(
        &mut self,
        reader: &mut dyn Buf,
        mut payload_index: usize,
    ) -> Result<usize> {
        if reader.remaining() == 0 {
            return Err(Error::ErrShortPacket);
        }
        let b = reader.get_u8();
        payload_index += 1;

        self.tid = b >> 5;
        self.u = b & 0x10 != 0;
        self.sid = (b >> 1) & 0x7;
        self.d = b & 0x01 != 0;

        if self.sid >= MAX_SPATIAL_LAYERS {
            Err(Error::ErrTooManySpatialLayers)
        } else {
            Ok(payload_index)
        }
    }

    // Layer indices (non-flexible mode):
    //
    //      +-+-+-+-+-+-+-+-+
    // L:   |  T  |U|  S  |D|
    //      +-+-+-+-+-+-+-+-+
    //      |   tl0picidx   |
    //      +-+-+-+-+-+-+-+-+
    //
    fn parse_layer_info_non_flexible_mode(
        &mut self,
        reader: &mut dyn Buf,
        mut payload_index: usize,
    ) -> Result<usize> {
        if reader.remaining() == 0 {
            return Err(Error::ErrShortPacket);
        }
        self.tl0picidx = reader.get_u8();
        payload_index += 1;
        Ok(payload_index)
    }

    // Reference indices:
    //
    //      +-+-+-+-+-+-+-+-+                P=1,F=1: At least one reference index
    // P,F: | P_DIFF      |N|  up to 3 times          has to be specified.
    //      +-+-+-+-+-+-+-+-+                    N=1: An additional P_DIFF follows
    //                                                current P_DIFF.
    //
    fn parse_ref_indices(
        &mut self,
        reader: &mut dyn Buf,
        mut payload_index: usize,
    ) -> Result<usize> {
        let mut b = 1u8;
        while (b & 0x1) != 0 {
            if reader.remaining() == 0 {
                return Err(Error::ErrShortPacket);
            }
            b = reader.get_u8();
            payload_index += 1;

            // RFC 9628 4.2: up to three reference indices (P_DIFF) per picture; a fourth is
            // the error, not the third.
            self.pdiff.push(b >> 1);
            if self.pdiff.len() > MAX_VP9REF_PICS {
                return Err(Error::ErrTooManyPDiff);
            }
        }

        Ok(payload_index)
    }

    // Scalability structure (SS):
    //
    //      +-+-+-+-+-+-+-+-+
    // V:   | N_S |Y|G|-|-|-|
    //      +-+-+-+-+-+-+-+-+              -|
    // Y:   |     WIDTH     | (OPTIONAL)    .
    //      +               +               .
    //      |               | (OPTIONAL)    .
    //      +-+-+-+-+-+-+-+-+               . N_S + 1 times
    //      |     HEIGHT    | (OPTIONAL)    .
    //      +               +               .
    //      |               | (OPTIONAL)    .
    //      +-+-+-+-+-+-+-+-+              -|
    // G:   |      N_G      | (OPTIONAL)
    //      +-+-+-+-+-+-+-+-+                           -|
    // N_G: |  T  |U| R |-|-| (OPTIONAL)                 .
    //      +-+-+-+-+-+-+-+-+              -|            . N_G times
    //      |    P_DIFF     | (OPTIONAL)    . R times    .
    //      +-+-+-+-+-+-+-+-+              -|           -|
    //
    fn parse_ssdata(&mut self, reader: &mut dyn Buf, mut payload_index: usize) -> Result<usize> {
        if reader.remaining() == 0 {
            return Err(Error::ErrShortPacket);
        }

        let b = reader.get_u8();
        payload_index += 1;

        self.ns = b >> 5;
        self.y = b & 0x10 != 0;
        // `N_S |Y|G|-|-|-|`: G is bit 3 alone. The three low bits are reserved and must not
        // be read as G (RFC 9628 4.2.1).
        self.g = b & 0x08 != 0;

        let ns = (self.ns + 1) as usize;
        self.ng = 0;
        // A scalability structure replaces the previous one; its picture-group description
        // used to be appended to the old one on every SS, growing without bound.
        self.pgtid.clear();
        self.pgu.clear();
        self.pgpdiff.clear();

        if self.y {
            if reader.remaining() < 4 * ns {
                return Err(Error::ErrShortPacket);
            }

            self.width = vec![0u16; ns];
            self.height = vec![0u16; ns];
            for i in 0..ns {
                self.width[i] = reader.get_u16();
                self.height[i] = reader.get_u16();
            }
            payload_index += 4 * ns;
        }

        if self.g {
            if reader.remaining() == 0 {
                return Err(Error::ErrShortPacket);
            }

            self.ng = reader.get_u8();
            payload_index += 1;
        }

        for i in 0..self.ng as usize {
            if reader.remaining() == 0 {
                return Err(Error::ErrShortPacket);
            }
            let b = reader.get_u8();
            payload_index += 1;

            self.pgtid.push(b >> 5);
            self.pgu.push(b & 0x10 != 0);

            let r = ((b >> 2) & 0x3) as usize;
            if reader.remaining() < r {
                return Err(Error::ErrShortPacket);
            }

            self.pgpdiff.push(vec![]);
            for _ in 0..r {
                let b = reader.get_u8();
                payload_index += 1;

                self.pgpdiff[i].push(b);
            }
        }

        Ok(payload_index)
    }
}
