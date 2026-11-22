//! The RTP payload format of SFrame, draft-ietf-avtcore-rtp-sframe-03 (pinned to that
//! revision, 21 October 2026).
//!
//! Every RTP payload starts with the one-byte SFrame payload descriptor `S E T x x x x x`
//! (section 4): S on the first fragment of an SFrame frame only, E on the last only, T 1 when
//! the frame protects packetized media and 0 when it protects a raw (encoded-transform) frame,
//! the same on every fragment; the five reserved bits are sent as 0 and ignored on receipt.
//! [`SFramePayloader`] fragments an SFrame ciphertext (section 5.1); [`SFrameDepacketizer`]
//! is the [`Depacketizer`] form and [`SFrameReassembler`] the full receive algorithm of
//! section 5.2 over packets in any order, with the buffer bounded (section 9.7).

#[cfg(test)]
mod sframe_test;

use crate::header::Header;
use crate::packet::Packet;
use crate::packetizer::{Depacketizer, Payloader};
use bytes::{BufMut, Bytes, BytesMut};
use shared::error::{Error, Result};

/// The size of the SFrame payload descriptor.
pub const SFRAME_DESCRIPTOR_SIZE: usize = 1;
/// The S bit: the first fragment of an SFrame frame.
pub const SFRAME_START: u8 = 0x80;
/// The E bit: the last fragment of an SFrame frame.
pub const SFRAME_END: u8 = 0x40;
/// The T bit: the frame protects packetized media (1) or a raw frame (0).
pub const SFRAME_PACKETIZED: u8 = 0x20;

/// The SFrame RTP metadata's payload origin (section 5.1): what the SFrame frame protects.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SFramePayloadOrigin {
    /// A raw media frame, as webrtc-encoded-transform defines it (per-frame SFrame): T = 0.
    #[default]
    Raw,
    /// The payload of an RTP packet of the media format's own packetizer (per-packet
    /// SFrame): T = 1.
    Packetized,
}

impl SFramePayloadOrigin {
    fn from_descriptor(descriptor: u8) -> Self {
        if descriptor & SFRAME_PACKETIZED != 0 {
            Self::Packetized
        } else {
            Self::Raw
        }
    }
}

/// Section 5.1: fragments an SFrame ciphertext into RTP payloads no larger than the MTU, each
/// behind its descriptor. The RTP layer sets the marker bit on the last packet of the frame
/// (step 8: the marker is E when the frame's marker is set).
#[derive(Default, Debug, Copy, Clone)]
pub struct SFramePayloader {
    /// The payload origin, the T bit of every fragment.
    pub origin: SFramePayloadOrigin,
}

impl SFramePayloader {
    /// A payloader for SFrame frames of `origin`.
    pub fn new(origin: SFramePayloadOrigin) -> Self {
        Self { origin }
    }
}

impl Payloader for SFramePayloader {
    fn payload(&mut self, mtu: usize, payload: &Bytes) -> Result<Vec<Bytes>> {
        let chunk = mtu
            .checked_sub(SFRAME_DESCRIPTOR_SIZE)
            .filter(|&chunk| chunk > 0)
            .ok_or(Error::ErrShortBuffer)?;
        let origin = if self.origin == SFramePayloadOrigin::Packetized {
            SFRAME_PACKETIZED
        } else {
            0
        };
        let mut out = Vec::with_capacity(payload.len() / chunk + 1);
        let mut rest = payload.as_ref();
        let mut first = true;
        loop {
            let take = rest.len().min(chunk);
            let last = take == rest.len();
            let mut descriptor = origin;
            if first {
                descriptor |= SFRAME_START;
            }
            if last {
                descriptor |= SFRAME_END;
            }
            let mut buf = BytesMut::with_capacity(SFRAME_DESCRIPTOR_SIZE + take);
            buf.put_u8(descriptor);
            buf.put_slice(&rest[..take]);
            out.push(buf.freeze());
            rest = &rest[take..];
            first = false;
            if last {
                return Ok(out);
            }
        }
    }

    fn clone_to(&self) -> Box<dyn Payloader> {
        Box::new(*self)
    }
}

/// The [`Depacketizer`] form of section 5.2 for packets in order (behind a jitter buffer):
/// the fragments from S to E are concatenated without their descriptors; a frame whose
/// fragments disagree on T is discarded (step 6). [`origin`](Self::origin) is the payload
/// origin of the last frame it returned.
#[derive(Default, Debug, Clone)]
pub struct SFrameDepacketizer {
    unit: Option<(BytesMut, u8)>,
    origin: SFramePayloadOrigin,
}

impl SFrameDepacketizer {
    /// The payload origin of the last frame returned.
    pub fn origin(&self) -> SFramePayloadOrigin {
        self.origin
    }
}

impl Depacketizer for SFrameDepacketizer {
    fn depacketize(&mut self, payload: &Bytes) -> Result<Bytes> {
        let Some((&descriptor, data)) = payload.split_first() else {
            return Err(Error::ErrShortPacket);
        };
        let t = descriptor & SFRAME_PACKETIZED;
        if descriptor & SFRAME_START != 0 {
            self.unit = Some((BytesMut::new(), t));
        }
        let Some((unit, frame_t)) = self.unit.as_mut() else {
            return Ok(Bytes::new());
        };
        if *frame_t != t {
            // Step 6: the T bits of the list differ; the frame is discarded.
            self.unit = None;
            return Ok(Bytes::new());
        }
        unit.put_slice(data);
        if descriptor & SFRAME_END != 0 {
            self.origin = SFramePayloadOrigin::from_descriptor(t);
            return Ok(self
                .unit
                .take()
                .map(|(u, _)| u.freeze())
                .unwrap_or_default());
        }
        Ok(Bytes::new())
    }

    fn is_partition_head(&self, payload: &Bytes) -> bool {
        payload.first().is_some_and(|d| d & SFRAME_START != 0)
    }

    fn is_partition_tail(&self, _marker: bool, payload: &Bytes) -> bool {
        payload.first().is_some_and(|d| d & SFRAME_END != 0)
    }
}

/// An SFrame frame that section 5.2 reassembled: the SFrame ciphertext (the payload, step
/// 9) and its SFrame RTP metadata (step 10), for the application to decrypt (step 11) and
/// then hand to the receiving pipeline (raw) or to the payload type's depacketizer
/// (packetized).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SFrameRtpFrame {
    /// The concatenated fragments, without descriptors: the SFrame ciphertext.
    pub payload: Bytes,
    /// The T bit of the fragments.
    pub origin: SFramePayloadOrigin,
    /// The last packet's marker bit.
    pub marker: bool,
    /// The fragments' payload type (all equal, step 7).
    pub payload_type: u8,
    /// The RTP timestamp.
    pub timestamp: u32,
    /// The SSRC.
    pub ssrc: u32,
    /// The CSRCs of the last packet.
    pub csrc: Vec<u32>,
    /// The first and last sequence numbers of the fragments.
    pub sequence_numbers: (u16, u16),
}

/// The default bound on the packets [`SFrameReassembler`] holds (section 9.7).
pub const DEFAULT_MAX_BUFFERED_PACKETS: usize = 512;

/// Section 5.2 over packets that may arrive in any order: each packet is added to the set of
/// received packets; the smallest run of consecutive sequence numbers from an S packet to an
/// E packet is taken out and, unless its fragments disagree on T or on the payload type
/// (steps 6, 7: the frame is discarded), returned as an [`SFrameRtpFrame`]. Section 9.7:
/// at most `max_buffered` packets are held, the oldest evicted first; fragments older than a
/// completed frame are kept, as a retransmission may still complete theirs.
#[derive(Debug, Clone)]
pub struct SFrameReassembler {
    /// Received packets, in sequence-number order (wrap-aware, relative to the first).
    packets: Vec<(Header, Bytes)>,
    max_buffered: usize,
    discarded: u64,
}

impl Default for SFrameReassembler {
    fn default() -> Self {
        Self::new(DEFAULT_MAX_BUFFERED_PACKETS)
    }
}

impl SFrameReassembler {
    /// A reassembler that holds at most `max_buffered` packets.
    pub fn new(max_buffered: usize) -> Self {
        Self {
            packets: Vec::new(),
            max_buffered: max_buffered.max(1),
            discarded: 0,
        }
    }

    /// How many frames were discarded (inconsistent T bits or payload types) and packets
    /// dropped (buffer bound, older incomplete fragments) so far.
    pub fn discarded(&self) -> u64 {
        self.discarded
    }

    /// How many packets are held.
    pub fn buffered(&self) -> usize {
        self.packets.len()
    }

    /// Steps 1 to 10 for one received packet; returns the frame it completes, if any.
    pub fn push(&mut self, packet: &Packet) -> Option<SFrameRtpFrame> {
        if packet.payload.is_empty() {
            return None;
        }
        let seq = packet.header.sequence_number;
        if self.packets.iter().any(|(h, _)| h.sequence_number == seq) {
            return None;
        }
        // Step 2: sorted by sequence number, with wrap-around (RFC 3550 A.1 style: a
        // distance under half the space is "after").
        let after = |a: u16, b: u16| a != b && a.wrapping_sub(b) < 0x8000;
        let at = self
            .packets
            .iter()
            .position(|(h, _)| after(h.sequence_number, seq))
            .unwrap_or(self.packets.len());
        self.packets
            .insert(at, (packet.header.clone(), packet.payload.clone()));
        while self.packets.len() > self.max_buffered {
            self.packets.remove(0);
            self.discarded += 1;
        }
        self.take_frame()
    }

    /// Step 3: the smallest consecutive run from an S packet to an E packet.
    fn take_frame(&mut self) -> Option<SFrameRtpFrame> {
        let descriptor = |i: usize| self.packets[i].1[0];
        let mut found = None;
        'start: for start in 0..self.packets.len() {
            if descriptor(start) & SFRAME_START == 0 {
                continue;
            }
            for end in start..self.packets.len() {
                if end > start
                    && self.packets[end].0.sequence_number
                        != self.packets[end - 1].0.sequence_number.wrapping_add(1)
                {
                    continue 'start;
                }
                if end > start && descriptor(end) & SFRAME_START != 0 {
                    continue 'start;
                }
                if descriptor(end) & SFRAME_END != 0 {
                    found = Some((start, end));
                    break 'start;
                }
            }
        }
        let (start, end) = found?;
        // Step 5: the run leaves the set. Older fragments stay: a retransmission may still
        // complete their frame after a newer one completed (the bound evicts them).
        let run: Vec<(Header, Bytes)> = self.packets.drain(start..=end).collect();
        let t = run[0].1[0] & SFRAME_PACKETIZED;
        // Steps 6 and 7.
        if run.iter().any(|(_, p)| p[0] & SFRAME_PACKETIZED != t)
            || run
                .iter()
                .any(|(h, _)| h.payload_type != run[0].0.payload_type)
        {
            self.discarded += 1;
            return None;
        }
        // Steps 8 to 10.
        let mut payload = BytesMut::new();
        for (_, p) in &run {
            payload.put_slice(&p[SFRAME_DESCRIPTOR_SIZE..]);
        }
        let (first, last) = (&run[0].0, &run[run.len() - 1].0);
        Some(SFrameRtpFrame {
            payload: payload.freeze(),
            origin: SFramePayloadOrigin::from_descriptor(t),
            marker: last.marker,
            payload_type: first.payload_type,
            timestamp: first.timestamp,
            ssrc: first.ssrc,
            csrc: last.csrc.clone(),
            sequence_numbers: (first.sequence_number, last.sequence_number),
        })
    }
}
