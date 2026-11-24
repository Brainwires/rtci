//! H.265/HEVC RTP payload format ([RFC 7798]).
//!
//! HEVC differs from H.264 in ways that matter to packetization: NAL headers are two bytes
//! rather than one, and there is an extra aggregation form (PACI) that can carry payload
//! content information ahead of the NAL unit.
//!
//! This module provides the three packet shapes the RFC defines — single NAL unit,
//! aggregation, and fragmentation unit — plus [`HevcPayloader`](crate::codec::h265::HevcPayloader), which picks between them
//! based on the MTU, and the depacketizer that reverses the choice.
//!
//! [RFC 7798]: https://datatracker.ietf.org/doc/html/rfc7798

use bytes::{BufMut, Bytes, BytesMut};

use super::h264::{ANNEXB_NALUSTART_CODE, annex_b_nal_units, don_diff};
use crate::packetizer::{Depacketizer, Payloader};
use shared::error::{Error, Result};

#[cfg(test)]
mod h265_test;
#[cfg(test)]
mod partition_head_test;
#[cfg(test)]
mod rfc7798_test;
#[cfg(test)]
mod short_nal_test;

/// The three-byte Annex B start code (`00 00 01`).
pub static ANNEXB_3_NALUSTART_CODE: Bytes = Bytes::from_static(&[0x00, 0x00, 0x01]);
/// Payload header for a single NAL unit packet.
pub static SING_PAYLOAD_HDR: Bytes = Bytes::from_static(&[0x1C, 0x01]);
/// Payload header for an aggregation packet.
pub static AGGR_PAYLOAD_HDR: Bytes = Bytes::from_static(&[0x60, 0x01]);
/// Payload header for a fragmentation unit.
pub static FRAG_PAYLOAD_HDR: Bytes = Bytes::from_static(&[0x62, 0x01]);
/// FU header for the first fragment of an IDR frame.
pub static FU_HDR_IDR_S: u8 = 0x93;
/// FU header for a middle fragment of an IDR frame.
pub static FU_HDR_IDR_M: u8 = 0x13;
/// FU header for the last fragment of an IDR frame.
pub static FU_HDR_IDR_E: u8 = 0x53;
/// FU header for the first fragment of a P frame.
pub static FU_HDR_P_S: u8 = 0x81;
/// FU header for a middle fragment of a P frame.
pub static FU_HDR_P_M: u8 = 0x01;
/// FU header for the last fragment of a P frame.
pub static FU_HDR_P_E: u8 = 0x41;
/// FU header for the first fragment of a B frame.
pub static FU_HDR_B_S: u8 = 0x80;
/// FU header for a middle fragment of a B frame.
pub static FU_HDR_B_M: u8 = 0x00;
/// FU header for the last fragment of a B frame.
pub static FU_HDR_B_E: u8 = 0x40;
/// The payload MTU this payloader targets, chosen to survive typical paths without IP
/// fragmentation.
pub const RTP_OUTBOUND_MTU: usize = 1200;
/// Bytes of FU header following the payload header in a fragmentation unit.
pub const H265FRAGMENTATION_UNIT_HEADER_SIZE: usize = 1;
/// Bytes in an H.265 NAL header — two, unlike H.264's one.
pub const NAL_HEADER_SIZE: usize = 2;

#[derive(PartialEq, Hash, Debug, Copy, Clone)]
/// The H.265 NAL unit types this payloader distinguishes.
#[non_exhaustive]
pub enum UnitType {
    /// Video parameter set.
    VPS = 32,
    /// Sequence parameter set.
    SPS = 33,
    /// Picture parameter set.
    PPS = 34,
    /// Clean random access picture — a keyframe that allows mid-stream tune-in.
    CRA = 21,
    /// Supplemental enhancement information.
    SEI = 39,
    /// Instantaneous decoder refresh picture — a keyframe.
    IDR = 19,
    /// A predicted (P) frame.
    PFR = 1,
    /// A bidirectionally predicted (B) frame.
    BFR = 0,
    /// A unit type this payloader skips.
    IGNORE = -1,
}
impl UnitType {
    /// Maps a raw NAL type id to a [`UnitType`].
    ///
    /// # Errors
    ///
    /// Fails if the id is not one this payloader handles.
    pub fn for_id(id: u8) -> Result<UnitType> {
        if id > 64 {
            Err(Error::ErrUnhandledNaluType)
        } else {
            let t = match id {
                32 => UnitType::VPS,
                33 => UnitType::SPS,
                34 => UnitType::PPS,
                21 => UnitType::CRA,
                39 => UnitType::SEI,
                19 => UnitType::IDR,
                1 => UnitType::PFR,
                0 => UnitType::BFR,
                _ => UnitType::IGNORE, // shouldn't happen
            };
            Ok(t)
        }
    }
}

/// Largest NAL unit reassembled from fragmentation units. Far above any real slice; a
/// reassembly that would grow past it is dropped.
pub const MAX_H265_FU_NALU_SIZE: usize = 4 * 1024 * 1024;
/// The de-packetization buffer never holds more NAL units than this, whatever
/// `sprop-depack-buf-nalus` and `sprop-max-don-diff` ask for.
pub const MAX_DEPACKETIZATION_NAL_UNITS: usize = 4096;
/// Nor more bytes than this.
pub const MAX_DEPACKETIZATION_BYTES: usize = 32 * 1024 * 1024;

#[derive(Default, Debug, Clone)]
/// Packetizes H.265/HEVC NAL units into RTP payloads, fragmenting when needed.
///
/// By default the stream is one with `sprop-max-don-diff` equal to 0: no decoding order
/// numbers, NAL units in decoding order. [`HevcPayloader::with_donl`] makes one for a stream
/// whose `sprop-max-don-diff` is greater than 0, where every packet carries them (RFC 7798
/// sections 4.4.1 to 4.4.3).
pub struct HevcPayloader {
    /// `sprop-max-don-diff` > 0: DONL and DOND fields are written.
    donl: bool,
    /// The decoding order number of the next NAL unit.
    next_don: u16,
}

impl HevcPayloader {
    /// A payloader for a stream whose `sprop-max-don-diff` is greater than 0: single NAL unit
    /// packets and the first fragment of a NAL unit carry a DONL, and aggregation packets a
    /// DONL for their first unit and a DOND for each other one (RFC 7798 sections 4.4.1 to
    /// 4.4.3). NAL units are sent in the order given, which is decoding order, numbered from
    /// `initial_don` upwards by one, so every DOND is 0.
    pub fn with_donl(initial_don: u16) -> Self {
        HevcPayloader {
            donl: true,
            next_don: initial_don,
        }
    }

    /// The NAL units of an access unit that are sent: those with a whole two-byte header whose
    /// type is a NAL unit type (below 48; 48 to 50 are this format's packet types, and they
    /// are neither aggregated, fragmented nor nested: RFC 7798 sections 4.4.2 to 4.4.4).
    fn sendable_nal_units(payload: &Bytes) -> Vec<Bytes> {
        annex_b_nal_units(payload)
            .into_iter()
            .filter(|nalu| {
                nalu.len() >= NAL_HEADER_SIZE
                    && H265NALUHeader::new(nalu[0], nalu[1]).nalu_type()
                        < H265NALU_AGGREGATION_PACKET_TYPE
            })
            .collect()
    }

    /// The packets of a stream with decoding order numbers.
    fn payload_with_don(&mut self, mtu: usize, payload: &Bytes) -> Vec<Bytes> {
        const DONL_SIZE: usize = 2;
        const DOND_SIZE: usize = 1;

        fn flush(pending: &mut Vec<(u16, Bytes)>, payloads: &mut Vec<Bytes>) {
            let nalus: Vec<Bytes> = pending.iter().map(|(_, nalu)| nalu.clone()).collect();
            match pending.len() {
                0 => {}
                1 => {
                    // A single NAL unit packet: the NAL unit header, DONL, the rest.
                    let (don, nalu) = &pending[0];
                    let mut out = BytesMut::with_capacity(nalu.len() + DONL_SIZE);
                    out.extend_from_slice(&nalu[..NAL_HEADER_SIZE]);
                    out.put_u16(*don);
                    out.extend_from_slice(&nalu[NAL_HEADER_SIZE..]);
                    payloads.push(out.freeze());
                }
                _ => {
                    let mut out = BytesMut::new();
                    out.extend_from_slice(&HevcPayloader::aggregation_payload_header(&nalus));
                    let mut previous = pending[0].0;
                    for (i, (don, nalu)) in pending.iter().enumerate() {
                        if i == 0 {
                            out.put_u16(*don);
                        } else {
                            // DON = previous DON + DOND + 1.
                            out.put_u8(don.wrapping_sub(previous).wrapping_sub(1) as u8);
                        }
                        previous = *don;
                        out.put_u16(nalu.len() as u16);
                        out.extend_from_slice(nalu);
                    }
                    payloads.push(out.freeze());
                }
            }
            pending.clear();
        }

        let mut payloads = vec![];
        let mut pending: Vec<(u16, Bytes)> = vec![];
        let mut pending_size = 0;
        for nalu in Self::sendable_nal_units(payload) {
            let don = self.next_don;
            self.next_don = self.next_don.wrapping_add(1);

            if nalu.len() + DONL_SIZE > mtu || nalu.len() > u16::MAX as usize {
                flush(&mut pending, &mut payloads);
                // Fragmentation units: the first carries the DONL.
                let header = H265NALUHeader::new(nalu[0], nalu[1]);
                let data = &nalu[NAL_HEADER_SIZE..];
                let fu_header_size = NAL_HEADER_SIZE + H265FRAGMENTATION_UNIT_HEADER_SIZE;
                let (Some(first_size), Some(next_size)) = (
                    mtu.checked_sub(fu_header_size + DONL_SIZE)
                        .filter(|&size| size > 0),
                    mtu.checked_sub(fu_header_size).filter(|&size| size > 0),
                ) else {
                    continue;
                };
                // Never one FU, and no FU with an empty payload: a NAL unit that would fit
                // the first fragment is cut in two.
                let first_len = if data.len() <= first_size {
                    data.len().div_ceil(2)
                } else {
                    first_size
                };
                let (first, rest) = data.split_at(first_len);
                if first.is_empty() || rest.is_empty() {
                    continue;
                }
                let mut out = BytesMut::with_capacity(fu_header_size + DONL_SIZE + first.len());
                out.extend_from_slice(&Self::fragmentation_payload_header(header));
                out.put_u8(Self::fu_header(header.nalu_type(), true, false));
                out.put_u16(don);
                out.extend_from_slice(first);
                payloads.push(out.freeze());
                let last = rest.len().div_ceil(next_size) - 1;
                for (i, fragment) in rest.chunks(next_size).enumerate() {
                    let mut out = BytesMut::with_capacity(fu_header_size + fragment.len());
                    out.extend_from_slice(&Self::fragmentation_payload_header(header));
                    out.put_u8(Self::fu_header(header.nalu_type(), false, i == last));
                    out.extend_from_slice(fragment);
                    payloads.push(out.freeze());
                }
                continue;
            }

            let first_unit_size = DONL_SIZE + 2 + nalu.len();
            let next_unit_size = DOND_SIZE + 2 + nalu.len();
            if pending.is_empty() {
                pending_size = NAL_HEADER_SIZE + first_unit_size;
            } else if pending_size + next_unit_size > mtu {
                flush(&mut pending, &mut payloads);
                pending_size = NAL_HEADER_SIZE + first_unit_size;
            } else {
                pending_size += next_unit_size;
            }
            pending.push((don, nalu));
        }
        flush(&mut pending, &mut payloads);
        payloads
    }

    fn aggregation_payload_header(nalus: &[Bytes]) -> [u8; 2] {
        let mut f = false;
        let mut layer_id = u8::MAX;
        let mut tid = u8::MAX;

        for nalu in nalus {
            let header = H265NALUHeader::new(nalu[0], nalu[1]);
            f |= header.f();
            layer_id = layer_id.min(header.layer_id());
            tid = tid.min(header.tid());
        }

        let mut raw = (H265NALU_AGGREGATION_PACKET_TYPE as u16) << 9;
        raw |= (layer_id as u16) << 3;
        raw |= tid as u16;
        if f {
            raw |= 1 << 15;
        }

        raw.to_be_bytes()
    }

    fn fragmentation_payload_header(payload_header: H265NALUHeader) -> [u8; 2] {
        let mut raw = (H265NALU_FRAGMENTATION_UNIT_TYPE as u16) << 9;
        raw |= (payload_header.layer_id() as u16) << 3;
        raw |= payload_header.tid() as u16;
        if payload_header.f() {
            raw |= 1 << 15;
        }

        raw.to_be_bytes()
    }

    fn fu_header(nalu_type: u8, is_first: bool, is_last: bool) -> u8 {
        let mut header = nalu_type & 0b0011_1111;
        if is_first {
            header |= 0b1000_0000;
        } else if is_last {
            header |= 0b0100_0000;
        }
        header
    }

    /// Locates the NAL unit boundaries in an Annex B buffer.
    ///
    /// Returns the offset of each start code and the length of the code that was matched:
    /// four-byte codes, or three-byte codes when there is no four-byte one. A stream that
    /// mixes the two is not split right by this; the payloader does not use it.
    pub fn parse(nalu: &Bytes) -> (Vec<usize>, usize) {
        let finder = memchr::memmem::Finder::new(&ANNEXB_NALUSTART_CODE);
        let nals = finder.find_iter(nalu).collect::<Vec<usize>>();
        if nals.is_empty() {
            let finder = memchr::memmem::Finder::new(&ANNEXB_3_NALUSTART_CODE);
            return (finder.find_iter(nalu).collect::<Vec<usize>>(), 3);
        }
        (nals, 4)
    }

    fn flush_aggregation_buffer(nalus: &mut Vec<Bytes>, mtu: usize, payloads: &mut Vec<Bytes>) {
        if nalus.is_empty() {
            return;
        }
        if nalus.len() == 1 {
            payloads.push(nalus.pop().expect("single buffered NAL exists"));
            return;
        }

        // Process NALUs in original order: accumulate consecutive normal-sized
        // NALUs into an AP, but when an oversized NALU (> u16::MAX) is
        // encountered, flush the current AP first, then emit the oversized
        // NALU individually (it will be FU-fragmented).
        //
        // Defense-in-depth: In practice, payload() sends any nalu.len() > mtu
        // directly to emit() before it reaches this buffer, so the u16::MAX
        // branch below is currently unreachable (MTU << u16::MAX). The check
        // is retained to guard against future callers or MTU changes.
        let mut pending_normal: Vec<Bytes> = Vec::new();

        for nalu in nalus.drain(..) {
            if nalu.len() > u16::MAX as usize {
                // Flush any accumulated normal NALUs as an AP (or single)
                Self::flush_normal_nalus(&mut pending_normal, mtu, payloads);
                // Emit the oversized NALU individually via FU fragmentation;
                // it cannot be placed in an AP because the 16-bit size field would overflow.
                Self::emit(&nalu, mtu, payloads);
            } else {
                pending_normal.push(nalu);
            }
        }

        // Flush any remaining normal NALUs
        Self::flush_normal_nalus(&mut pending_normal, mtu, payloads);
    }

    /// Flush accumulated normal-sized NALUs: emit a single NALU directly,
    /// or pack multiple into an aggregation packet.
    fn flush_normal_nalus(nalus: &mut Vec<Bytes>, mtu: usize, payloads: &mut Vec<Bytes>) {
        match nalus.len() {
            0 => {}
            1 => {
                payloads.push(nalus.pop().expect("single normal NAL exists"));
            }
            _ => {
                let header = Self::aggregation_payload_header(nalus);
                let mut aggr_nalu = BytesMut::with_capacity(
                    NAL_HEADER_SIZE + nalus.iter().map(|nalu| 2 + nalu.len()).sum::<usize>(),
                );
                aggr_nalu.extend_from_slice(&header);
                for nalu in nalus.iter() {
                    aggr_nalu.extend_from_slice(&(nalu.len() as u16).to_be_bytes());
                    aggr_nalu.extend_from_slice(nalu);
                }
                nalus.clear();
                if aggr_nalu.len() <= mtu {
                    payloads.push(aggr_nalu.freeze());
                }
            }
        }
    }

    fn emit(nalu: &Bytes, mtu: usize, payloads: &mut Vec<Bytes>) {
        // An H.265 NAL unit header is two bytes (RFC 7798 1.1.4); anything shorter is not one.
        if nalu.len() < H265NALU_HEADER_SIZE {
            return;
        }
        let payload_header = H265NALUHeader::new(nalu[0], nalu[1]);
        let payload_nalu_type = payload_header.nalu_type();

        if payload_nalu_type >= H265NALU_AGGREGATION_PACKET_TYPE {
            return;
        }

        // Single NALU
        if nalu.len() <= mtu {
            payloads.push(nalu.clone());
            return;
        }
        let max_fragment_size =
            mtu as isize - NAL_HEADER_SIZE as isize - H265FRAGMENTATION_UNIT_HEADER_SIZE as isize;
        let nalu_data = nalu;
        let mut nalu_data_index = 2;
        let nalu_data_length = nalu.len() as isize - nalu_data_index;
        let mut nalu_data_remaining = nalu_data_length;
        if std::cmp::min(max_fragment_size, nalu_data_remaining) <= 0 {
            return;
        }
        while nalu_data_remaining > 0 {
            let current_fragment_size = std::cmp::min(max_fragment_size, nalu_data_remaining);
            let mut out = BytesMut::with_capacity(
                NAL_HEADER_SIZE
                    + H265FRAGMENTATION_UNIT_HEADER_SIZE
                    + current_fragment_size as usize,
            );
            out.extend_from_slice(&Self::fragmentation_payload_header(payload_header));
            let is_first = nalu_data_index == 2;
            let is_last = nalu_data_remaining == current_fragment_size;
            out.put_u8(Self::fu_header(payload_nalu_type, is_first, is_last));

            out.extend_from_slice(
                &nalu_data
                    [nalu_data_index as usize..(nalu_data_index + current_fragment_size) as usize],
            );
            payloads.push(out.freeze());

            nalu_data_remaining -= current_fragment_size;
            nalu_data_index += current_fragment_size;
        }
    }
}

impl Payloader for HevcPayloader {
    /// Payload fragments a H264 packet across one or more byte arrays
    fn payload(&mut self, mtu: usize, payload: &Bytes) -> Result<Vec<Bytes>> {
        if payload.is_empty() || mtu == 0 {
            return Ok(vec![]);
        }

        if self.donl {
            return Ok(self.payload_with_don(mtu, payload));
        }

        let mut payloads = vec![];
        let mut aggregation_buffer = vec![];

        // The NAL units of the access unit, split at their Annex B start codes of either
        // length. A buffer without a start code is one NAL unit.
        for nalu in Self::sendable_nal_units(payload) {
            if nalu.len() > mtu {
                Self::flush_aggregation_buffer(&mut aggregation_buffer, mtu, &mut payloads);
                Self::emit(&nalu, mtu, &mut payloads);
                continue;
            }

            let aggregated_size = NAL_HEADER_SIZE
                + aggregation_buffer
                    .iter()
                    .map(|nalu| 2 + nalu.len())
                    .sum::<usize>()
                + 2
                + nalu.len();
            if !aggregation_buffer.is_empty() && aggregated_size > mtu {
                Self::flush_aggregation_buffer(&mut aggregation_buffer, mtu, &mut payloads);
            }

            aggregation_buffer.push(nalu);
        }
        Self::flush_aggregation_buffer(&mut aggregation_buffer, mtu, &mut payloads);

        Ok(payloads)
    }

    fn clone_to(&self) -> Box<dyn Payloader> {
        Box::new(self.clone())
    }
}

///
/// Network Abstraction Unit Header implementation
///
const H265NALU_HEADER_SIZE: usize = 2;
/// <https://datatracker.ietf.org/doc/html/rfc7798#section-4.4.2>
const H265NALU_AGGREGATION_PACKET_TYPE: u8 = 48;
/// <https://datatracker.ietf.org/doc/html/rfc7798#section-4.4.3>
const H265NALU_FRAGMENTATION_UNIT_TYPE: u8 = 49;
/// <https://datatracker.ietf.org/doc/html/rfc7798#section-4.4.4>
const H265NALU_PACI_PACKET_TYPE: u8 = 50;

/// H265NALUHeader is a H265 NAL Unit Header
///
/// ```text
/// +---------------+---------------+
/// |0|1|2|3|4|5|6|7|0|1|2|3|4|5|6|7|
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |F|   Type    |  layer_id  | tid|
/// +-------------+-----------------+
/// ```
///
/// ## Specifications
///
/// * [RFC 7798 §1.1.4]
///
/// [RFC 7798 §1.1.4]: https://tools.ietf.org/html/rfc7798#section-1.1.4
#[derive(Default, Debug, Copy, Clone, PartialEq, Eq)]
pub struct H265NALUHeader(pub u16);

impl H265NALUHeader {
    /// Parses an H.265 NAL header from its two bytes.
    pub fn new(high_byte: u8, low_byte: u8) -> Self {
        H265NALUHeader(((high_byte as u16) << 8) | low_byte as u16)
    }

    /// f is the forbidden bit, should always be 0.
    pub fn f(&self) -> bool {
        (self.0 >> 15) != 0
    }

    /// nalu_type of NAL Unit.
    pub fn nalu_type(&self) -> u8 {
        // 01111110 00000000
        const MASK: u16 = 0b01111110 << 8;
        ((self.0 & MASK) >> (8 + 1)) as u8
    }

    /// is_type_vcl_unit returns whether or not the NAL Unit type is a VCL NAL unit.
    pub fn is_type_vcl_unit(&self) -> bool {
        // Type is coded on 6 bits
        const MSB_MASK: u8 = 0b00100000;
        (self.nalu_type() & MSB_MASK) == 0
    }

    /// layer_id should always be 0 in non-3D HEVC context.
    pub fn layer_id(&self) -> u8 {
        // 00000001 11111000
        const MASK: u16 = (0b00000001 << 8) | 0b11111000;
        ((self.0 & MASK) >> 3) as u8
    }

    /// tid is the temporal identifier of the NAL unit +1.
    pub fn tid(&self) -> u8 {
        const MASK: u16 = 0b00000111;
        (self.0 & MASK) as u8
    }

    /// is_aggregation_packet returns whether or not the packet is an Aggregation packet.
    pub fn is_aggregation_packet(&self) -> bool {
        self.nalu_type() == H265NALU_AGGREGATION_PACKET_TYPE
    }

    /// is_fragmentation_unit returns whether or not the packet is a Fragmentation Unit packet.
    pub fn is_fragmentation_unit(&self) -> bool {
        self.nalu_type() == H265NALU_FRAGMENTATION_UNIT_TYPE
    }

    /// is_paci_packet returns whether or not the packet is a PACI packet.
    pub fn is_paci_packet(&self) -> bool {
        self.nalu_type() == H265NALU_PACI_PACKET_TYPE
    }
}

///
/// Single NAL Unit Packet implementation
///
/// H265SingleNALUnitPacket represents a NALU packet, containing exactly one NAL unit.
///     0                   1                   2                   3
///    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///   |           PayloadHdr          |      DONL (conditional)       |
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///   |                                                               |
///   |                  NAL unit payload data                        |
///   |                                                               |
///   |                               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///   |                               :...OPTIONAL RTP padding        |
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///
/// ## Specifications
///
/// * [RFC 7798 §4.4.1]
///
/// [RFC 7798 §4.4.1]: https://tools.ietf.org/html/rfc7798#section-4.4.1
#[derive(Default, Debug, Clone, PartialEq, Eq)]
pub struct H265SingleNALUnitPacket {
    /// payload_header is the header of the H265 packet.
    payload_header: H265NALUHeader,
    /// donl is a 16-bit field, that may or may not be present.
    donl: Option<u16>,
    /// payload of the fragmentation unit.
    payload: Bytes,

    might_need_donl: bool,
}

impl H265SingleNALUnitPacket {
    /// with_donl can be called to specify whether or not DONL might be parsed.
    /// DONL may need to be parsed if `sprop-max-don-diff` is greater than 0 on the RTP stream.
    pub fn with_donl(&mut self, value: bool) {
        self.might_need_donl = value;
    }

    /// depacketize parses the passed byte slice and stores the result in the H265SingleNALUnitPacket this method is called upon.
    fn depacketize(&mut self, payload: &Bytes) -> Result<()> {
        // A NAL unit may be its two-byte header alone: end of sequence (36), end of
        // bitstream (37).
        if payload.len() < H265NALU_HEADER_SIZE {
            return Err(Error::ErrShortPacket);
        }

        let payload_header = H265NALUHeader::new(payload[0], payload[1]);
        if payload_header.f() {
            return Err(Error::ErrH265CorruptedPacket);
        }
        if payload_header.is_fragmentation_unit()
            || payload_header.is_paci_packet()
            || payload_header.is_aggregation_packet()
        {
            return Err(Error::ErrInvalidH265PacketType);
        }

        let mut payload = payload.slice(2..);

        if self.might_need_donl {
            // sizeof(uint16)
            if payload.len() < 2 {
                return Err(Error::ErrShortPacket);
            }

            let donl = ((payload[0] as u16) << 8) | (payload[1] as u16);
            self.donl = Some(donl);
            payload = payload.slice(2..);
        }

        self.payload_header = payload_header;
        self.payload = payload;

        Ok(())
    }

    /// payload_header returns the NALU header of the packet.
    pub fn payload_header(&self) -> H265NALUHeader {
        self.payload_header
    }

    /// donl returns the DONL of the packet.
    pub fn donl(&self) -> Option<u16> {
        self.donl
    }

    /// payload returns the Fragmentation Unit packet payload.
    pub fn payload(&self) -> Bytes {
        self.payload.clone()
    }
}

///
/// Aggregation Packets implementation
///
/// H265AggregationUnitFirst represent the First Aggregation Unit in an AP.
///
///    0                   1                   2                   3
///    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///                   :       DONL (conditional)      |   NALU size   |
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///   |   NALU size   |                                               |
///   +-+-+-+-+-+-+-+-+         NAL unit                              |
///   |                                                               |
///   |                               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///   |                               :
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///
/// ## Specifications
///
/// * [RFC 7798 §4.4.2]
///
/// [RFC 7798 §4.4.2]: https://tools.ietf.org/html/rfc7798#section-4.4.2
#[derive(Default, Debug, Clone, PartialEq, Eq)]
pub struct H265AggregationUnitFirst {
    donl: Option<u16>,
    nal_unit_size: u16,
    nal_unit: Bytes,
}

impl H265AggregationUnitFirst {
    /// donl field, when present, specifies the value of the 16 least
    /// significant bits of the decoding order number of the aggregated NAL
    /// unit.
    pub fn donl(&self) -> Option<u16> {
        self.donl
    }

    /// nalu_size represents the size, in bytes, of the nal_unit.
    pub fn nalu_size(&self) -> u16 {
        self.nal_unit_size
    }

    /// nal_unit payload.
    pub fn nal_unit(&self) -> Bytes {
        self.nal_unit.clone()
    }
}

/// H265AggregationUnit represent the an Aggregation Unit in an AP, which is not the first one.
///
///    0                   1                   2                   3
///    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///                   : DOND (cond)   |          NALU size            |
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///   |                                                               |
///   |                       NAL unit                                |
///   |                               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///   |                               :
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///
/// ## Specifications
///
/// * [RFC 7798 §4.4.2]
///
/// [RFC 7798 §4.4.2]: https://tools.ietf.org/html/rfc7798#section-4.4.2
#[derive(Default, Debug, Clone, PartialEq, Eq)]
pub struct H265AggregationUnit {
    dond: Option<u8>,
    nal_unit_size: u16,
    nal_unit: Bytes,
}

impl H265AggregationUnit {
    /// dond field plus 1 specifies the difference between
    /// the decoding order number values of the current aggregated NAL unit
    /// and the preceding aggregated NAL unit in the same AP.
    pub fn dond(&self) -> Option<u8> {
        self.dond
    }

    /// nalu_size represents the size, in bytes, of the nal_unit.
    pub fn nalu_size(&self) -> u16 {
        self.nal_unit_size
    }

    /// nal_unit payload.
    pub fn nal_unit(&self) -> Bytes {
        self.nal_unit.clone()
    }
}

/// H265AggregationPacket represents an Aggregation packet.
///   0                   1                   2                   3
///    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///   |    PayloadHdr (Type=48)       |                               |
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               |
///   |                                                               |
///   |             two or more aggregation units                     |
///   |                                                               |
///   |                               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///   |                               :...OPTIONAL RTP padding        |
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///
/// ## Specifications
///
/// * [RFC 7798 §4.4.2]
///
/// [RFC 7798 §4.4.2]: https://tools.ietf.org/html/rfc7798#section-4.4.2
#[derive(Default, Debug, Clone, PartialEq, Eq)]
pub struct H265AggregationPacket {
    first_unit: Option<H265AggregationUnitFirst>,
    other_units: Vec<H265AggregationUnit>,

    might_need_donl: bool,
}

impl H265AggregationPacket {
    /// with_donl can be called to specify whether or not DONL might be parsed.
    /// DONL may need to be parsed if `sprop-max-don-diff` is greater than 0 on the RTP stream.
    pub fn with_donl(&mut self, value: bool) {
        self.might_need_donl = value;
    }

    /// depacketize parses the passed byte slice and stores the result in the H265AggregationPacket this method is called upon.
    fn depacketize(&mut self, payload: &Bytes) -> Result<()> {
        if payload.len() <= H265NALU_HEADER_SIZE {
            return Err(Error::ErrShortPacket);
        }

        let payload_header = H265NALUHeader::new(payload[0], payload[1]);
        if payload_header.f() {
            return Err(Error::ErrH265CorruptedPacket);
        }
        if !payload_header.is_aggregation_packet() {
            return Err(Error::ErrInvalidH265PacketType);
        }

        // First parse the first aggregation unit
        let mut payload = payload.slice(2..);
        let mut first_unit = H265AggregationUnitFirst::default();

        if self.might_need_donl {
            if payload.len() < 2 {
                return Err(Error::ErrShortPacket);
            }

            let donl = ((payload[0] as u16) << 8) | (payload[1] as u16);
            first_unit.donl = Some(donl);

            payload = payload.slice(2..);
        }
        if payload.len() < 2 {
            return Err(Error::ErrShortPacket);
        }
        first_unit.nal_unit_size = ((payload[0] as u16) << 8) | (payload[1] as u16);
        payload = payload.slice(2..);

        if payload.len() < first_unit.nal_unit_size as usize {
            return Err(Error::ErrShortPacket);
        }

        first_unit.nal_unit = payload.slice(..first_unit.nal_unit_size as usize);
        payload = payload.slice(first_unit.nal_unit_size as usize..);

        // Parse remaining Aggregation Units
        let mut units = vec![]; //H265AggregationUnit
        loop {
            let mut unit = H265AggregationUnit::default();

            if self.might_need_donl {
                if payload.is_empty() {
                    break;
                }

                let dond = payload[0];
                unit.dond = Some(dond);

                payload = payload.slice(1..);
            }

            if payload.len() < 2 {
                break;
            }
            unit.nal_unit_size = ((payload[0] as u16) << 8) | (payload[1] as u16);
            payload = payload.slice(2..);

            if payload.len() < unit.nal_unit_size as usize {
                break;
            }

            unit.nal_unit = payload.slice(..unit.nal_unit_size as usize);
            payload = payload.slice(unit.nal_unit_size as usize..);

            units.push(unit);
        }

        // There need to be **at least** two Aggregation Units (first + another one)
        if units.is_empty() {
            return Err(Error::ErrShortPacket);
        }

        self.first_unit = Some(first_unit);
        self.other_units = units;

        Ok(())
    }

    /// first_unit returns the first Aggregated Unit of the packet.
    pub fn first_unit(&self) -> Option<&H265AggregationUnitFirst> {
        self.first_unit.as_ref()
    }

    /// other_units returns the all the other Aggregated Unit of the packet (excluding the first one).
    pub fn other_units(&self) -> &[H265AggregationUnit] {
        self.other_units.as_slice()
    }
}

/// Fragmentation Unit implementation
///
/// H265FragmentationUnitHeader is a H265 FU Header
/// +---------------+
/// |0|1|2|3|4|5|6|7|
/// +-+-+-+-+-+-+-+-+
/// |S|E|  fu_type   |
/// +---------------+
#[derive(Default, Debug, Copy, Clone, PartialEq, Eq)]
pub struct H265FragmentationUnitHeader(pub u8);

impl H265FragmentationUnitHeader {
    /// s represents the start of a fragmented NAL unit.
    pub fn s(&self) -> bool {
        const MASK: u8 = 0b10000000;
        ((self.0 & MASK) >> 7) != 0
    }

    /// e represents the end of a fragmented NAL unit.
    pub fn e(&self) -> bool {
        const MASK: u8 = 0b01000000;
        ((self.0 & MASK) >> 6) != 0
    }

    /// fu_type MUST be equal to the field Type of the fragmented NAL unit.
    pub fn fu_type(&self) -> u8 {
        const MASK: u8 = 0b00111111;
        self.0 & MASK
    }
}

/// H265FragmentationUnitPacket represents a single Fragmentation Unit packet.
///
///  0                   1                   2                   3
/// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |    PayloadHdr (Type=49)       |   FU header   | DONL (cond)   |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-|
/// | DONL (cond)   |                                               |
/// |-+-+-+-+-+-+-+-+                                               |
/// |                         FU payload                            |
/// |                                                               |
/// |                               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                               :...OPTIONAL RTP padding        |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///
/// ## Specifications
///
/// * [RFC 7798 §4.4.3]
///
/// [RFC 7798 §4.4.3]: https://tools.ietf.org/html/rfc7798#section-4.4.3
#[derive(Default, Debug, Clone, PartialEq, Eq)]
pub struct H265FragmentationUnitPacket {
    /// payload_header is the header of the H265 packet.
    payload_header: H265NALUHeader,
    /// fu_header is the header of the fragmentation unit
    fu_header: H265FragmentationUnitHeader,
    /// donl is a 16-bit field, that may or may not be present.
    donl: Option<u16>,
    /// payload of the fragmentation unit.
    payload: Bytes,

    might_need_donl: bool,
}

impl H265FragmentationUnitPacket {
    /// with_donl can be called to specify whether or not DONL might be parsed.
    /// DONL may need to be parsed if `sprop-max-don-diff` is greater than 0 on the RTP stream.
    pub fn with_donl(&mut self, value: bool) {
        self.might_need_donl = value;
    }

    /// depacketize parses the passed byte slice and stores the result in the H265FragmentationUnitPacket this method is called upon.
    fn depacketize(&mut self, payload: &Bytes) -> Result<()> {
        const TOTAL_HEADER_SIZE: usize = H265NALU_HEADER_SIZE + H265FRAGMENTATION_UNIT_HEADER_SIZE;
        if payload.len() <= TOTAL_HEADER_SIZE {
            return Err(Error::ErrShortPacket);
        }

        let payload_header = H265NALUHeader::new(payload[0], payload[1]);
        if payload_header.f() {
            return Err(Error::ErrH265CorruptedPacket);
        }
        if !payload_header.is_fragmentation_unit() {
            return Err(Error::ErrInvalidH265PacketType);
        }

        let fu_header = H265FragmentationUnitHeader(payload[2]);
        let mut payload = payload.slice(3..);

        if fu_header.s() && self.might_need_donl {
            if payload.len() <= 2 {
                return Err(Error::ErrShortPacket);
            }

            let donl = ((payload[0] as u16) << 8) | (payload[1] as u16);
            self.donl = Some(donl);
            payload = payload.slice(2..);
        }

        self.payload_header = payload_header;
        self.fu_header = fu_header;
        self.payload = payload;

        Ok(())
    }

    /// payload_header returns the NALU header of the packet.
    pub fn payload_header(&self) -> H265NALUHeader {
        self.payload_header
    }

    /// fu_header returns the Fragmentation Unit Header of the packet.
    pub fn fu_header(&self) -> H265FragmentationUnitHeader {
        self.fu_header
    }

    /// donl returns the DONL of the packet.
    pub fn donl(&self) -> Option<u16> {
        self.donl
    }

    /// payload returns the Fragmentation Unit packet payload.
    pub fn payload(&self) -> Bytes {
        self.payload.clone()
    }
}

///
/// PACI implementation
///
/// H265PACIPacket represents a single H265 PACI packet.
///
///  0                   1                   2                   3
/// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |    PayloadHdr (Type=50)       |A|   cType   | phssize |F0..2|Y|
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |        payload Header Extension Structure (phes)              |
/// |=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=|
/// |                                                               |
/// |                  PACI payload: NAL unit                       |
/// |                   . . .                                       |
/// |                                                               |
/// |                               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                               :...OPTIONAL RTP padding        |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///
/// ## Specifications
///
/// * [RFC 7798 §4.4.4]
///
/// [RFC 7798 §4.4.4]: https://tools.ietf.org/html/rfc7798#section-4.4.4
#[derive(Default, Debug, Clone, PartialEq, Eq)]
pub struct H265PACIPacket {
    /// payload_header is the header of the H265 packet.
    payload_header: H265NALUHeader,

    /// Field which holds value for `A`, `cType`, `phssize`, `F0`, `F1`, `F2` and `Y` fields.
    paci_header_fields: u16,

    /// phes is a header extension, of byte length `phssize`
    phes: Bytes,

    /// payload contains NAL units & optional padding
    payload: Bytes,
}

impl H265PACIPacket {
    /// payload_header returns the NAL Unit Header.
    pub fn payload_header(&self) -> H265NALUHeader {
        self.payload_header
    }

    /// a copies the F bit of the PACI payload NALU.
    pub fn a(&self) -> bool {
        const MASK: u16 = 0b10000000 << 8;
        (self.paci_header_fields & MASK) != 0
    }

    /// ctype copies the Type field of the PACI payload NALU.
    pub fn ctype(&self) -> u8 {
        const MASK: u16 = 0b01111110 << 8;
        ((self.paci_header_fields & MASK) >> (8 + 1)) as u8
    }

    /// phs_size indicates the size of the phes field.
    pub fn phs_size(&self) -> u8 {
        const MASK: u16 = (0b00000001 << 8) | 0b11110000;
        ((self.paci_header_fields & MASK) >> 4) as u8
    }

    /// f0 indicates the presence of a Temporal Scalability support extension in the phes.
    pub fn f0(&self) -> bool {
        const MASK: u16 = 0b00001000;
        (self.paci_header_fields & MASK) != 0
    }

    /// f1 must be zero, reserved for future extensions.
    pub fn f1(&self) -> bool {
        const MASK: u16 = 0b00000100;
        (self.paci_header_fields & MASK) != 0
    }

    /// f2 must be zero, reserved for future extensions.
    pub fn f2(&self) -> bool {
        const MASK: u16 = 0b00000010;
        (self.paci_header_fields & MASK) != 0
    }

    /// y must be zero, reserved for future extensions.
    pub fn y(&self) -> bool {
        const MASK: u16 = 0b00000001;
        (self.paci_header_fields & MASK) != 0
    }

    /// phes contains header extensions. Its size is indicated by phssize.
    pub fn phes(&self) -> Bytes {
        self.phes.clone()
    }

    /// payload is a single NALU or NALU-like struct, not including the first two octets (header).
    pub fn payload(&self) -> Bytes {
        self.payload.clone()
    }

    /// tsci returns the Temporal Scalability Control Information extension, if present.
    pub fn tsci(&self) -> Option<H265TSCI> {
        if !self.f0() || self.phs_size() < 3 || self.phes.len() < 3 {
            return None;
        }

        // TL0PICIDX, IrapPicID, then S, E and RES: the first three octets of the PHES, in the
        // high 24 bits of the value, which is where the accessors read them.
        Some(H265TSCI(
            ((self.phes[0] as u32) << 24)
                | ((self.phes[1] as u32) << 16)
                | ((self.phes[2] as u32) << 8),
        ))
    }

    /// depacketize parses the passed byte slice and stores the result in the H265PACIPacket this method is called upon.
    fn depacketize(&mut self, payload: &Bytes) -> Result<()> {
        const TOTAL_HEADER_SIZE: usize = H265NALU_HEADER_SIZE + 2;
        if payload.len() <= TOTAL_HEADER_SIZE {
            return Err(Error::ErrShortPacket);
        }

        let payload_header = H265NALUHeader::new(payload[0], payload[1]);
        if payload_header.f() {
            return Err(Error::ErrH265CorruptedPacket);
        }
        if !payload_header.is_paci_packet() {
            return Err(Error::ErrInvalidH265PacketType);
        }

        let paci_header_fields = ((payload[2] as u16) << 8) | (payload[3] as u16);
        let mut payload = payload.slice(4..);

        self.paci_header_fields = paci_header_fields;
        let header_extension_size = self.phs_size();

        if payload.len() < header_extension_size as usize + 1 {
            self.paci_header_fields = 0;
            return Err(Error::ErrShortPacket);
        }

        self.payload_header = payload_header;

        if header_extension_size > 0 {
            self.phes = payload.slice(..header_extension_size as usize);
        }

        payload = payload.slice(header_extension_size as usize..);
        self.payload = payload;

        Ok(())
    }
}

///
/// Temporal Scalability Control Information
///
/// H265TSCI is a Temporal Scalability Control Information header extension.
///
/// ## Specifications
///
/// * [RFC 7798 §4.5]
///
/// [RFC 7798 §4.5]: https://tools.ietf.org/html/rfc7798#section-4.5
#[derive(Default, Debug, Copy, Clone, PartialEq, Eq)]
pub struct H265TSCI(pub u32);

impl H265TSCI {
    /// tl0picidx see RFC7798 for more details.
    pub fn tl0picidx(&self) -> u8 {
        const M1: u32 = 0xFFFF0000;
        const M2: u32 = 0xFF00;
        ((((self.0 & M1) >> 16) & M2) >> 8) as u8
    }

    /// irap_pic_id see RFC7798 for more details.
    pub fn irap_pic_id(&self) -> u8 {
        const M1: u32 = 0xFFFF0000;
        const M2: u32 = 0x00FF;
        (((self.0 & M1) >> 16) & M2) as u8
    }

    /// s see RFC7798 for more details.
    pub fn s(&self) -> bool {
        const M1: u32 = 0xFF00;
        const M2: u32 = 0b10000000;
        (((self.0 & M1) >> 8) & M2) != 0
    }

    /// e see RFC7798 for more details.
    pub fn e(&self) -> bool {
        const M1: u32 = 0xFF00;
        const M2: u32 = 0b01000000;
        (((self.0 & M1) >> 8) & M2) != 0
    }

    /// res see RFC7798 for more details.
    pub fn res(&self) -> u8 {
        const M1: u32 = 0xFF00;
        const M2: u32 = 0b00111111;
        (((self.0 & M1) >> 8) & M2) as u8
    }
}

///
/// H265 Payload Enum
///
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum H265Payload {
    /// One NAL unit carried whole in a single packet.
    H265SingleNALUnitPacket(H265SingleNALUnitPacket),
    /// One fragment of a NAL unit too large for the MTU.
    H265FragmentationUnitPacket(H265FragmentationUnitPacket),
    /// Several small NAL units aggregated into one packet.
    H265AggregationPacket(H265AggregationPacket),
    /// A PACI packet, which carries payload content information ahead of the NAL unit.
    H265PACIPacket(H265PACIPacket),
}

impl Default for H265Payload {
    fn default() -> Self {
        H265Payload::H265SingleNALUnitPacket(H265SingleNALUnitPacket::default())
    }
}

/// One NAL unit taken out of an RTP payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct H265NalUnit {
    /// The NAL unit, its two-byte header included, without a start code or a length prefix.
    pub data: Bytes,
    /// Its decoding order number, on a stream that carries them (`sprop-max-don-diff` greater
    /// than 0): the DONL of its packet, or the previous unit's DON plus DOND plus one inside an
    /// aggregation packet (RFC 7798 sections 4.4.1 to 4.4.3).
    pub don: Option<u16>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct BufferedH265NalUnit {
    unit: H265NalUnit,
    /// AbsDon of RFC 7798 section 4.6: the DON unwrapped along the reception order.
    abs_don: i64,
}

/// The de-packetization buffer of RFC 7798 section 6, for a stream whose `sprop-max-don-diff`
/// is greater than 0: NAL units go in in reception order and come out in decoding order, by
/// AbsDon (section 4.6).
///
/// A NAL unit leaves, the smallest AbsDon first, whenever the AbsDon values in the buffer span
/// `sprop-max-don-diff` or more (condition A) or the buffer holds more than
/// `sprop-depack-buf-nalus` NAL units (condition B).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct H265DepacketizationBuffer {
    max_don_diff: i64,
    depack_buf_nalus: usize,
    units: Vec<BufferedH265NalUnit>,
    /// The DON and AbsDon of the NAL unit received last.
    last_received: Option<(u16, i64)>,
    bytes: usize,
}

impl H265DepacketizationBuffer {
    /// A buffer for a stream with these `sprop-max-don-diff` and `sprop-depack-buf-nalus`
    /// media type parameters (RFC 7798 section 7.1; both are 0 to 32767).
    pub fn new(sprop_max_don_diff: u16, sprop_depack_buf_nalus: u16) -> Self {
        H265DepacketizationBuffer {
            max_don_diff: i64::from(sprop_max_don_diff),
            depack_buf_nalus: usize::from(sprop_depack_buf_nalus),
            units: Vec::new(),
            last_received: None,
            bytes: 0,
        }
    }

    /// NAL units in the buffer.
    pub fn len(&self) -> usize {
        self.units.len()
    }

    /// Whether the buffer holds no NAL unit.
    pub fn is_empty(&self) -> bool {
        self.units.is_empty()
    }

    fn due(&self) -> bool {
        let mut abs_dons = self.units.iter().map(|buffered| buffered.abs_don);
        let Some(first) = abs_dons.next() else {
            return false;
        };
        let (smallest, greatest) = abs_dons
            .fold((first, first), |(smallest, greatest), abs_don| {
                (smallest.min(abs_don), greatest.max(abs_don))
            });
        // Condition A, condition B, and the bound.
        greatest - smallest >= self.max_don_diff
            || self.units.len() > self.depack_buf_nalus
            || self.units.len() > MAX_DEPACKETIZATION_NAL_UNITS
            || self.bytes > MAX_DEPACKETIZATION_BYTES
    }

    /// Stores a NAL unit and returns the NAL units that are now due, in decoding order. A NAL
    /// unit without a DON is returned as it is.
    pub fn push(&mut self, unit: H265NalUnit) -> Vec<H265NalUnit> {
        let Some(don) = unit.don else {
            return vec![unit];
        };
        let abs_don = match self.last_received {
            Some((last_don, last_abs)) => last_abs + i64::from(don_diff(last_don, don)),
            None => i64::from(don),
        };
        self.last_received = Some((don, abs_don));
        self.bytes += unit.data.len();
        self.units.push(BufferedH265NalUnit { unit, abs_don });

        let mut out = vec![];
        while self.due() {
            // The NAL unit with the smallest AbsDon; the earliest received among equals.
            let index = (0..self.units.len())
                .min_by_key(|&i| self.units[i].abs_don)
                .unwrap_or(0);
            let buffered = self.units.remove(index);
            self.bytes -= buffered.unit.data.len();
            out.push(buffered.unit);
        }
        out
    }

    /// Empties the buffer, in order of increasing AbsDon: no more NAL units are coming.
    pub fn flush(&mut self) -> Vec<H265NalUnit> {
        let mut buffered = std::mem::take(&mut self.units);
        self.bytes = 0;
        buffered.sort_by_key(|buffered| buffered.abs_don);
        buffered.into_iter().map(|buffered| buffered.unit).collect()
    }
}

/// One RTP stream of an [`H265MultiStreamDepacketizer`].
#[derive(Debug, Clone)]
struct H265ReceivedStream {
    id: u32,
    max_don_diff: u16,
    parser: H265Packet,
    /// The sequence number of the last packet taken.
    last_sequence_number: Option<u16>,
    /// The DON and AbsDon of this stream's NAL unit received last (RFC 7798 section 4.6:
    /// AbsDon is derived along each stream's transmission order).
    last_don: Option<(u16, i64)>,
    /// The greatest NTP timestamp seen on the stream.
    latest_ntp: Option<u64>,
}

/// A NAL unit waiting in an [`H265MultiStreamDepacketizer`].
#[derive(Debug, Clone)]
struct PendingH265NalUnit {
    unit: H265NalUnit,
    /// The position of its stream in the dependency order.
    rank: usize,
    /// AbsDon when decoding order numbers are in use, else 0.
    abs_don: i64,
    /// The NTP timestamp when no decoding order numbers are in use, else 0.
    ntp: u64,
    /// Reception order.
    arrival: u64,
}

/// The receiver of an HEVC bitstream carried in several RTP streams: MRST (several streams on
/// one transport) and MRMT (several streams on several transports), RFC 7798 section 4.3:
/// "Receivers MUST support all of SRST, MRST, and MRMT". It holds the RTP streams of one
/// bitstream, in dependency order, and passes their NAL units on in decoding order as RFC 7798
/// section 6 describes:
///
/// - When `sprop-max-don-diff` is greater than 0 for any of the streams, the NAL units of all
///   of them are stored in one de-packetization buffer with their AbsDon (section 4.6, derived
///   along each stream) and leave, the smallest AbsDon first, while the AbsDon values span the
///   highest stream's `sprop-max-don-diff` or more (condition A) or the buffer holds more than
///   `sprop-depack-buf-nalus` NAL units (condition B). Among equal AbsDon values a stream lower
///   in the dependency order goes first.
/// - Otherwise the NAL units are passed on in the order of their NTP timestamps; of the same
///   timestamp, a dependee stream's before a dependent's, and one stream's in transmission
///   order. The caller gives each packet's NTP timestamp (its RTP timestamp mapped through the
///   stream's sender reports). A NAL unit leaves once no stream can still deliver one that goes
///   before it: every stream it depends on has shown a later timestamp, and every dependent
///   stream received so far the same timestamp or a later one.
///
/// Duplicated and outdated packets (a sequence number not after the stream's last) are removed
/// (section 6). Give each stream's packets in sequence number order, after the jitter buffer:
/// an MRMT receiver feeds the packets of each transport's streams into the same instance. The
/// grouping of the streams (which streams make one bitstream and their dependency order) is
/// signalled with RFC 5583 `a=depend`, which the application reads from the description.
#[derive(Debug, Clone)]
pub struct H265MultiStreamDepacketizer {
    depack_buf_nalus: usize,
    streams: Vec<H265ReceivedStream>,
    pending: Vec<PendingH265NalUnit>,
    bytes: usize,
    arrivals: u64,
}

impl H265MultiStreamDepacketizer {
    /// A receiver whose bitstream has this `sprop-depack-buf-nalus` (RFC 7798 section 7.1; 0
    /// when the description gives none).
    pub fn new(sprop_depack_buf_nalus: u16) -> Self {
        H265MultiStreamDepacketizer {
            depack_buf_nalus: usize::from(sprop_depack_buf_nalus),
            streams: Vec::new(),
            pending: Vec::new(),
            bytes: 0,
            arrivals: 0,
        }
    }

    /// Adds the RTP stream `id` (an SSRC, or any number the caller tells the streams apart by)
    /// with its `sprop-max-don-diff`. Streams are added in dependency order: a stream depends
    /// only on streams added before it. Adding a stream already held changes nothing.
    pub fn add_stream(&mut self, id: u32, sprop_max_don_diff: u16) {
        if self.streams.iter().any(|stream| stream.id == id) {
            return;
        }
        self.streams.push(H265ReceivedStream {
            id,
            max_don_diff: sprop_max_don_diff,
            parser: H265Packet::default(),
            last_sequence_number: None,
            last_don: None,
            latest_ntp: None,
        });
        // DONL and DOND are present on every stream as soon as one of them carries DONs.
        let donl = self.uses_don();
        for stream in &mut self.streams {
            stream.parser.with_donl(donl);
        }
    }

    /// NAL units waiting.
    pub fn len(&self) -> usize {
        self.pending.len()
    }

    /// Whether no NAL unit is waiting.
    pub fn is_empty(&self) -> bool {
        self.pending.is_empty()
    }

    /// Whether decoding order numbers are in use: `sprop-max-don-diff` greater than 0 for any
    /// of the streams (RFC 7798 section 4.6).
    fn uses_don(&self) -> bool {
        self.streams.iter().any(|stream| stream.max_don_diff > 0)
    }

    /// Takes one RTP packet of stream `stream`: its sequence number, its NTP timestamp and its
    /// payload. Returns the NAL units now due, in decoding order. A packet of a stream not
    /// added, a duplicate and an outdated packet give nothing.
    ///
    /// # Errors
    ///
    /// As [`H265Packet::nal_units`].
    pub fn push(
        &mut self,
        stream: u32,
        sequence_number: u16,
        ntp: u64,
        payload: &Bytes,
    ) -> Result<Vec<H265NalUnit>> {
        let uses_don = self.uses_don();
        let Some(rank) = self.streams.iter().position(|s| s.id == stream) else {
            return Ok(vec![]);
        };
        let received = &mut self.streams[rank];
        if let Some(last) = received.last_sequence_number {
            let ahead = sequence_number.wrapping_sub(last);
            if ahead == 0 || ahead >= 0x8000 {
                return Ok(vec![]);
            }
        }
        received.last_sequence_number = Some(sequence_number);
        received.parser.note_sequence_number(sequence_number);
        let units = received.parser.nal_units(payload)?;
        received.latest_ntp = Some(received.latest_ntp.map_or(ntp, |latest| latest.max(ntp)));
        for unit in units {
            let (abs_don, ntp) = if uses_don {
                // DONL is present on every stream when any of them uses decoding order
                // numbers (RFC 7798 section 4.4.1).
                let Some(don) = unit.don else {
                    continue;
                };
                let abs_don = match received.last_don {
                    Some((last_don, last_abs)) => last_abs + i64::from(don_diff(last_don, don)),
                    None => i64::from(don),
                };
                received.last_don = Some((don, abs_don));
                (abs_don, 0)
            } else {
                (0, ntp)
            };
            self.bytes += unit.data.len();
            self.arrivals += 1;
            self.pending.push(PendingH265NalUnit {
                unit,
                rank,
                abs_don,
                ntp,
                arrival: self.arrivals,
            });
        }
        Ok(self.release())
    }

    /// The index of the waiting NAL unit that goes first in decoding order.
    fn first(&self) -> Option<usize> {
        (0..self.pending.len()).min_by_key(|&i| {
            let unit = &self.pending[i];
            (unit.abs_don, unit.ntp, unit.rank, unit.arrival)
        })
    }

    fn over_bound(&self) -> bool {
        self.pending.len() > MAX_DEPACKETIZATION_NAL_UNITS || self.bytes > MAX_DEPACKETIZATION_BYTES
    }

    /// Whether the waiting NAL unit `index` may leave.
    fn due(&self, index: usize) -> bool {
        if self.over_bound() {
            return true;
        }
        if self.uses_don() {
            let (smallest, greatest) = self.pending.iter().fold((i64::MAX, i64::MIN), |acc, u| {
                (acc.0.min(u.abs_don), acc.1.max(u.abs_don))
            });
            // The highest stream in the dependency order that uses decoding order numbers.
            let max_don_diff = self
                .streams
                .iter()
                .rev()
                .map(|stream| stream.max_don_diff)
                .find(|diff| *diff > 0)
                .unwrap_or(0);
            // Condition A or condition B.
            greatest - smallest >= i64::from(max_don_diff)
                || self.pending.len() > self.depack_buf_nalus
        } else {
            // No stream can still deliver a NAL unit that goes before this one: a dependee
            // (lower in the dependency order) has shown a later timestamp, and a dependent
            // received so far has shown this one or a later one. A dependent's NAL unit waits
            // for its dependees to be received at all: it cannot be decoded without them.
            let unit = &self.pending[index];
            self.streams
                .iter()
                .enumerate()
                .all(|(rank, stream)| match rank.cmp(&unit.rank) {
                    std::cmp::Ordering::Equal => true,
                    std::cmp::Ordering::Less => {
                        stream.latest_ntp.is_some_and(|latest| latest > unit.ntp)
                    }
                    std::cmp::Ordering::Greater => {
                        stream.latest_ntp.is_none_or(|latest| latest >= unit.ntp)
                    }
                })
        }
    }

    fn release(&mut self) -> Vec<H265NalUnit> {
        let mut out = vec![];
        while let Some(index) = self.first() {
            if !self.due(index) {
                break;
            }
            let pending = self.pending.remove(index);
            self.bytes -= pending.unit.data.len();
            out.push(pending.unit);
        }
        out
    }

    /// Every NAL unit still waiting, in decoding order: no more packets are coming.
    pub fn flush(&mut self) -> Vec<H265NalUnit> {
        let mut pending = std::mem::take(&mut self.pending);
        self.bytes = 0;
        pending.sort_by_key(|unit| (unit.abs_don, unit.ntp, unit.rank, unit.arrival));
        pending.into_iter().map(|pending| pending.unit).collect()
    }
}

///
/// Packet implementation
///
/// H265Packet represents a H265 packet, stored in the payload of an RTP packet.
///
/// As a [`Depacketizer`] it turns RTP payloads into NAL units, in an Annex B byte stream (or
/// length-prefixed, see [`with_length_prefix`](H265Packet::with_length_prefix)): a single NAL
/// unit packet's NAL unit, each NAL unit of an aggregation packet, a NAL unit reassembled from
/// its fragmentation units, and whichever of those a PACI packet carries. Nothing of type 48
/// to 63 is ever passed on (RFC 7798 section 6).
#[derive(Default, Debug, Clone, PartialEq, Eq)]
pub struct H265Packet {
    payload: H265Payload,
    might_need_donl: bool,
    length_prefixed: bool,
    /// The NAL unit being reassembled from fragmentation units: its header, then the data.
    fu_buffer: Option<BytesMut>,
    /// Its decoding order number, from the first fragment's DONL.
    fu_don: Option<u16>,
    /// The sequence number of the last packet given with one.
    last_sequence_number: Option<u16>,
    depacketization: Option<H265DepacketizationBuffer>,
}

impl H265Packet {
    /// with_donl can be called to specify whether or not DONL might be parsed.
    /// DONL may need to be parsed if `sprop-max-don-diff` is greater than 0 on the RTP stream.
    pub fn with_donl(&mut self, value: bool) {
        self.might_need_donl = value;
    }

    /// Emits each NAL unit with a four-byte big-endian length before it (the `hvcC` sample
    /// format) in place of an Annex B start code.
    pub fn with_length_prefix(&mut self, value: bool) {
        self.length_prefixed = value;
    }

    /// Receives a stream whose `sprop-max-don-diff` is greater than 0 in decoding order: DONL
    /// and DOND are parsed, and NAL units go through `buffer` before
    /// [`depacketize`](Depacketizer::depacketize) returns them (RFC 7798 section 6).
    pub fn with_depacketization_buffer(&mut self, buffer: H265DepacketizationBuffer) {
        self.might_need_donl = true;
        self.depacketization = Some(buffer);
    }

    /// The NAL units still in the de-packetization buffer, in decoding order and in the output
    /// format of [`depacketize`](Depacketizer::depacketize): for the end of the stream.
    pub fn flush_depacketization_buffer(&mut self) -> Bytes {
        let units = self
            .depacketization
            .as_mut()
            .map(H265DepacketizationBuffer::flush)
            .unwrap_or_default();
        self.format(&units)
    }

    /// payload returns the populated payload.
    /// Must be casted to one of:
    /// - H265SingleNALUnitPacket
    /// - H265FragmentationUnitPacket
    /// - H265AggregationPacket
    /// - H265PACIPacket
    pub fn payload(&self) -> &H265Payload {
        &self.payload
    }

    /// As [`depacketize`](Depacketizer::depacketize), given the packet's RTP sequence number:
    /// when a packet is missing before this one, the fragments collected so far are discarded
    /// with the rest of their NAL unit, in place of a NAL unit with a hole in it (RFC 7798
    /// section 4.4.3). Give the packets in sequence number order.
    ///
    /// # Errors
    ///
    /// As [`depacketize`](Depacketizer::depacketize).
    pub fn depacketize_with_sequence_number(
        &mut self,
        sequence_number: u16,
        payload: &Bytes,
    ) -> Result<Bytes> {
        self.note_sequence_number(sequence_number);
        self.depacketize(payload)
    }

    /// Takes note of the next packet's sequence number: after a gap the fragments collected so
    /// far are discarded.
    fn note_sequence_number(&mut self, sequence_number: u16) {
        // A repeated number is a duplicate, not a gap.
        if let Some(last) = self.last_sequence_number
            && sequence_number != last.wrapping_add(1)
            && sequence_number != last
        {
            self.fu_buffer = None;
            self.fu_don = None;
        }
        self.last_sequence_number = Some(sequence_number);
    }

    /// Whether a NAL unit may be passed to a decoder: a whole header and a type below 48.
    fn is_nal_unit(data: &[u8]) -> bool {
        data.len() >= H265NALU_HEADER_SIZE
            && H265NALUHeader::new(data[0], data[1]).nalu_type() < H265NALU_AGGREGATION_PACKET_TYPE
    }

    /// The NAL units a payload completes, with their decoding order numbers when the stream
    /// carries them: one for a single NAL unit packet, two or more for an aggregation packet,
    /// none or one for a fragmentation unit, and those of the packet a PACI carries. The
    /// de-packetization buffer is not involved. [`payload`](H265Packet::payload) is the
    /// parsed packet afterwards.
    ///
    /// # Errors
    ///
    /// Fails for a payload cut short, a packet with the F bit set, and a reassembly over
    /// [`MAX_H265_FU_NALU_SIZE`].
    pub fn nal_units(&mut self, payload: &Bytes) -> Result<Vec<H265NalUnit>> {
        if payload.len() < H265NALU_HEADER_SIZE {
            return Err(Error::ErrShortPacket);
        }

        let payload_header = H265NALUHeader::new(payload[0], payload[1]);
        if payload_header.f() {
            return Err(Error::ErrH265CorruptedPacket);
        }

        if payload_header.is_paci_packet() {
            let mut decoded = H265PACIPacket::default();
            decoded.depacketize(payload)?;
            if decoded.ctype() == H265NALU_PACI_PACKET_TYPE {
                // A PACI carries a single NAL unit, an FU or an AP, not a PACI: there is
                // nothing in it to pass on.
                self.payload = H265Payload::H265PACIPacket(decoded);
                return Ok(vec![]);
            }
            // The packet a PACI carries: its payload header is the PACI's with F and Type
            // replaced by the A and cType fields, and its body is the PACI payload (RFC 7798
            // section 4.4.4).
            let mut header = (decoded.ctype() as u16) << 9;
            header |= (payload_header.layer_id() as u16) << 3;
            header |= payload_header.tid() as u16;
            if decoded.a() {
                header |= 1 << 15;
            }
            let mut carried = BytesMut::with_capacity(2 + decoded.payload.len());
            carried.put_u16(header);
            carried.extend_from_slice(&decoded.payload);
            let units = self.nal_units(&carried.freeze());
            self.payload = H265Payload::H265PACIPacket(decoded);
            units
        } else if payload_header.is_fragmentation_unit() {
            let mut decoded = H265FragmentationUnitPacket::default();
            decoded.with_donl(self.might_need_donl);

            if let Err(err) = decoded.depacketize(payload) {
                self.fu_buffer = None;
                self.fu_don = None;
                return Err(err);
            }

            let fu_header = decoded.fu_header();
            if fu_header.s() {
                if fu_header.fu_type() < H265NALU_AGGREGATION_PACKET_TYPE {
                    // The NAL unit header: the payload header with the FU's type.
                    let mut header = (fu_header.fu_type() as u16) << 9;
                    header |= (payload_header.layer_id() as u16) << 3;
                    header |= payload_header.tid() as u16;
                    let mut buffer = BytesMut::new();
                    buffer.put_u16(header);
                    self.fu_buffer = Some(buffer);
                    self.fu_don = decoded.donl();
                } else {
                    // A fragmented aggregation packet, fragment or PACI: not a NAL unit.
                    self.fu_buffer = None;
                    self.fu_don = None;
                }
            }
            let mut units = vec![];
            if let Some(buffer) = &mut self.fu_buffer {
                if buffer.len() + decoded.payload.len() > MAX_H265_FU_NALU_SIZE {
                    // Bounded: a peer that never sends the end fragment must not grow this
                    // without limit. Drop the partial NAL unit.
                    self.fu_buffer = None;
                    self.fu_don = None;
                    self.payload = H265Payload::H265FragmentationUnitPacket(decoded);
                    return Err(Error::ErrPacketTooBig);
                }
                buffer.extend_from_slice(&decoded.payload);
                if fu_header.e()
                    && let Some(buffer) = self.fu_buffer.take()
                {
                    units.push(H265NalUnit {
                        data: buffer.freeze(),
                        don: self.fu_don.take(),
                    });
                }
            }
            // A fragment whose start was lost has nothing to join: it is dropped.
            self.payload = H265Payload::H265FragmentationUnitPacket(decoded);
            Ok(units)
        } else if payload_header.is_aggregation_packet() {
            let mut decoded = H265AggregationPacket::default();
            decoded.with_donl(self.might_need_donl);

            decoded.depacketize(payload)?;

            let mut units = vec![];
            let mut don = None;
            if let Some(first) = decoded.first_unit() {
                don = first.donl();
                if Self::is_nal_unit(&first.nal_unit) {
                    units.push(H265NalUnit {
                        data: first.nal_unit(),
                        don,
                    });
                }
            }
            for unit in decoded.other_units() {
                // DON = the previous unit's DON + DOND + 1, modulo 65536.
                don = don
                    .zip(unit.dond())
                    .map(|(don, dond)| don.wrapping_add(u16::from(dond)).wrapping_add(1));
                // An aggregated aggregation packet, fragment or PACI is not a NAL unit.
                if Self::is_nal_unit(&unit.nal_unit) {
                    units.push(H265NalUnit {
                        data: unit.nal_unit(),
                        don,
                    });
                }
            }
            self.payload = H265Payload::H265AggregationPacket(decoded);
            Ok(units)
        } else {
            let mut decoded = H265SingleNALUnitPacket::default();
            decoded.with_donl(self.might_need_donl);

            decoded.depacketize(payload)?;

            let mut units = vec![];
            // Types 51 to 63 are reserved: not passed on.
            if payload_header.nalu_type() < H265NALU_AGGREGATION_PACKET_TYPE {
                let mut data = BytesMut::with_capacity(2 + decoded.payload.len());
                data.put_u16(payload_header.0);
                data.extend_from_slice(&decoded.payload);
                units.push(H265NalUnit {
                    data: data.freeze(),
                    don: decoded.donl(),
                });
            }
            self.payload = H265Payload::H265SingleNALUnitPacket(decoded);
            Ok(units)
        }
    }

    /// NAL units as an Annex B byte stream, or length-prefixed.
    fn format(&self, units: &[H265NalUnit]) -> Bytes {
        let mut out = BytesMut::with_capacity(units.iter().map(|unit| 4 + unit.data.len()).sum());
        for unit in units {
            if self.length_prefixed {
                out.put_u32(unit.data.len() as u32);
            } else {
                out.put(&*ANNEXB_NALUSTART_CODE);
            }
            out.put(&*unit.data);
        }
        out.freeze()
    }
}

impl Depacketizer for H265Packet {
    /// Parses one RTP payload and returns the NAL units it completes, each behind an Annex B
    /// start code (or a length prefix): empty for a fragment that does not end its NAL unit.
    fn depacketize(&mut self, payload: &Bytes) -> Result<Bytes> {
        let mut units = self.nal_units(payload)?;
        if let Some(buffer) = &mut self.depacketization {
            units = units
                .into_iter()
                .flat_map(|unit| buffer.push(unit))
                .collect();
        }
        Ok(self.format(&units))
    }

    /// is_partition_head checks if this is the head of a packetized nalu stream.
    ///
    /// Every payload begins a NAL unit except a fragmentation unit whose start bit is clear
    /// (RFC 7798 4.4.3: the FU header's S bit marks the first fragment). A fragmentation unit too
    /// short to carry its FU header cannot begin anything.
    fn is_partition_head(&self, payload: &Bytes) -> bool {
        if payload.len() < H265NALU_HEADER_SIZE {
            return false;
        }
        let nalu_type = (payload[0] >> 1) & 0x3F;
        if nalu_type != H265NALU_FRAGMENTATION_UNIT_TYPE {
            return true;
        }
        payload
            .get(H265NALU_HEADER_SIZE)
            .is_some_and(|fu_header| fu_header & 0x80 != 0)
    }

    fn is_partition_tail(&self, marker: bool, _payload: &Bytes) -> bool {
        marker
    }
}
