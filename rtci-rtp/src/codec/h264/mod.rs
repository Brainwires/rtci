//! H.264 RTP payload format ([RFC 6184]).
//!
//! All three packetization modes are here:
//!
//! * mode 0, single NAL unit (section 6.2): every NAL unit in a packet of its own;
//! * mode 1, non-interleaved (section 6.3), the default and what WebRTC uses: single NAL unit
//!   packets, STAP-A aggregates and FU-A fragments, in decoding order;
//! * mode 2, interleaved (section 6.4): STAP-B, MTAP16, MTAP24, FU-B and FU-A, every NAL unit
//!   with a decoding order number (DON), and `H264DeinterleavingBuffer` to put received NAL
//!   units back in decoding order (section 7.2.2).
//!
//! `H264Payloader` sends and `H264Packet` receives. The `*_NALU_TYPE` constants name the
//! types, and the `*_BITMASK` constants describe how the NAL header and FU header pack their
//! fields.
//!
//! [RFC 6184]: https://datatracker.ietf.org/doc/html/rfc6184
#[cfg(test)]
mod h264_test;
#[cfg(test)]
mod interleaved_test;
#[cfg(test)]
mod packetization_mode_test;
#[cfg(test)]
mod rfc6184_test;

use crate::packetizer::{Depacketizer, Payloader};
use shared::error::{Error, Result};

use bytes::{BufMut, Bytes, BytesMut};
use std::time::{Duration, Instant};

/// NAL type 24: STAP-A, which aggregates several small NAL units into one payload.
pub const STAPA_NALU_TYPE: u8 = 24;
/// NAL type 25: STAP-B, a STAP-A with a decoding order number (interleaved mode).
pub const STAPB_NALU_TYPE: u8 = 25;
/// NAL type 26: MTAP16, an aggregate of NAL units of several access units, with 16-bit
/// timestamp offsets (interleaved mode).
pub const MTAP16_NALU_TYPE: u8 = 26;
/// NAL type 27: MTAP24, MTAP16 with 24-bit timestamp offsets.
pub const MTAP24_NALU_TYPE: u8 = 27;
/// NAL type 28: FU-A, which fragments one NAL unit across several payloads.
pub const FUA_NALU_TYPE: u8 = 28;
/// NAL type 29: FU-B, the first fragment of a NAL unit in interleaved mode: an FU-A with a
/// decoding order number.
pub const FUB_NALU_TYPE: u8 = 29;
/// NAL type 7: sequence parameter set.
pub const SPS_NALU_TYPE: u8 = 7;
/// NAL type 8: picture parameter set.
pub const PPS_NALU_TYPE: u8 = 8;
/// NAL type 9: access unit delimiter.
pub const AUD_NALU_TYPE: u8 = 9;
/// NAL type 12: filler data, which is dropped rather than sent.
pub const FILLER_NALU_TYPE: u8 = 12;

/// Bytes of FU-A header prefixed to each fragment.
pub const FUA_HEADER_SIZE: usize = 2;
/// Bytes of FU-B header prefixed to a first fragment: FU indicator, FU header and DON.
pub const FUB_HEADER_SIZE: usize = 4;

/// Largest NAL unit reassembled from FU-A fragments. Far above any real slice (a 4K intra frame
/// is a few hundred KiB); a reassembly that would grow past it is dropped.
pub const MAX_FUA_NALU_SIZE: usize = 4 * 1024 * 1024;
/// Bytes of STAP-A header prefixed to an aggregate.
pub const STAPA_HEADER_SIZE: usize = 1;
/// Bytes of STAP-B header prefixed to an aggregate: the type octet and the DON.
pub const STAPB_HEADER_SIZE: usize = 3;
/// Bytes of MTAP header prefixed to an aggregate: the type octet and the DON base.
pub const MTAP_HEADER_SIZE: usize = 3;
/// Bytes of length prefix before each NAL unit inside a STAP-A.
pub const STAPA_NALU_LENGTH_SIZE: usize = 2;

/// Mask selecting the NAL type from a NAL header byte.
pub const NALU_TYPE_BITMASK: u8 = 0x1F;
/// Mask selecting `nal_ref_idc` from a NAL header byte.
pub const NALU_REF_IDC_BITMASK: u8 = 0x60;
/// Mask selecting `forbidden_zero_bit` from a NAL header byte.
pub const NALU_FORBIDDEN_BITMASK: u8 = 0x80;
/// FU header start bit: this fragment begins a NAL unit.
pub const FU_START_BITMASK: u8 = 0x80;
/// FU header end bit: this fragment completes a NAL unit.
pub const FU_END_BITMASK: u8 = 0x40;

/// The STAP-A header byte for aggregated NAL units whose `nal_ref_idc` is 3 (parameter sets as
/// encoders write them). The payloader computes the header from the units it aggregates (RFC
/// 6184 section 5.7: F is the OR of their F bits, NRI the maximum of their NRIs); this constant
/// is that value for the common case.
pub const OUTPUT_STAP_AHEADER: u8 = 0x78;

/// The Annex B start code (`00 00 00 01`) that delimits NAL units in a byte stream.
pub static ANNEXB_NALUSTART_CODE: Bytes = Bytes::from_static(&[0x00, 0x00, 0x00, 0x01]);

/// Parameter sets given in calls of their own are held for the access unit that follows, up to
/// this many of them.
const MAX_HELD_PARAMETER_SETS: usize = 64;
/// And up to this many bytes.
const MAX_HELD_PARAMETER_SET_BYTES: usize = 1024 * 1024;

/// The NAL units of an Annex B byte stream, without their start codes (three or four bytes,
/// mixed freely). A buffer with no start code is one NAL unit.
pub(crate) fn annex_b_nal_units(payload: &Bytes) -> Vec<Bytes> {
    /// The next start code at or after `start`: its offset, zeros included (every zero before
    /// the `00 00 01` from `start` on: a four-byte code, or trailing zeros of the NAL unit before
    /// it), and its length. `memmem` finds the `00 00 01`; a byte at a time was most of the
    /// payloader's time on a large frame (webrtc-rs/rtc#336).
    fn next_start_code(data: &[u8], start: usize) -> Option<(usize, usize)> {
        let at = start + memchr::memmem::find(&data[start..], &[0, 0, 1])?;
        let first_zero = data[start..at]
            .iter()
            .rposition(|&b| b != 0)
            .map_or(start, |nonzero| start + nonzero + 1);
        Some((first_zero, at + 3 - first_zero))
    }

    let mut nalus = vec![];
    let Some((mut code_start, mut code_len)) = next_start_code(payload, 0) else {
        nalus.push(payload.clone());
        return nalus;
    };
    loop {
        let nalu_start = code_start + code_len;
        match next_start_code(payload, nalu_start) {
            Some((next_start, next_len)) => {
                nalus.push(payload.slice(nalu_start..next_start));
                code_start = next_start;
                code_len = next_len;
            }
            None => {
                nalus.push(payload.slice(nalu_start..));
                return nalus;
            }
        }
    }
}

/// Whether a NAL unit type is one a packet may carry as a NAL unit: 1 to 23. Type 0 and types
/// 30 and 31 are reserved, and 24 to 29 are this payload format's own packet types (RFC 6184
/// section 5.4, Table 3; section 5.7: aggregates are not nested; section 5.8: nor are FUs).
fn is_nal_unit_type(nalu_type: u8) -> bool {
    (1..=23).contains(&nalu_type)
}

/// Whether a NAL unit type is a coded slice or slice data partition (VCL): 1 to 5.
fn is_vcl_type(nalu_type: u8) -> bool {
    (1..=5).contains(&nalu_type)
}

/// The header octet of an aggregation packet: F is set if any aggregated F bit is, NRI is the
/// maximum of the aggregated NRIs (RFC 6184 section 5.7).
fn aggregation_header(packet_type: u8, nalus: &[Bytes]) -> u8 {
    let mut forbidden = 0;
    let mut ref_idc = 0;
    for nalu in nalus {
        if let Some(&header) = nalu.first() {
            forbidden |= header & NALU_FORBIDDEN_BITMASK;
            ref_idc = ref_idc.max(header & NALU_REF_IDC_BITMASK);
        }
    }
    forbidden | ref_idc | packet_type
}

/// Checks the NAL units of an aggregate: each is a NAL unit (types 1 to 23) that fits the
/// 16-bit size field.
fn check_aggregated(nalus: &[&Bytes]) -> Result<()> {
    if nalus.is_empty() {
        return Err(Error::Other(
            "an H.264 aggregation packet holds at least one NAL unit".to_owned(),
        ));
    }
    for nalu in nalus {
        let Some(&header) = nalu.first() else {
            return Err(Error::ErrShortPacket);
        };
        if !is_nal_unit_type(header & NALU_TYPE_BITMASK) {
            return Err(Error::NaluTypeIsNotHandled(header & NALU_TYPE_BITMASK));
        }
        if nalu.len() > u16::MAX as usize {
            return Err(Error::NaluTooLarge(nalu.len()));
        }
    }
    Ok(())
}

/// Builds a STAP-A payload (RFC 6184 section 5.7.1): the NAL units of one access unit, in
/// decoding order.
///
/// # Errors
///
/// Fails without NAL units, for a unit over 65535 bytes, and for a unit that is not a NAL unit
/// of types 1 to 23 (aggregates and fragments are not nested).
pub fn stap_a(nalus: &[Bytes]) -> Result<Bytes> {
    check_aggregated(&nalus.iter().collect::<Vec<_>>())?;
    let mut out = BytesMut::with_capacity(
        STAPA_HEADER_SIZE + nalus.iter().map(|nalu| 2 + nalu.len()).sum::<usize>(),
    );
    out.put_u8(aggregation_header(STAPA_NALU_TYPE, nalus));
    for nalu in nalus {
        out.put_u16(nalu.len() as u16);
        out.put(&**nalu);
    }
    Ok(out.freeze())
}

/// Builds a STAP-B payload (RFC 6184 section 5.7.1): a STAP-A whose first NAL unit has the
/// decoding order number `don`, each following one the number after it (modulo 65536).
///
/// # Errors
///
/// As [`stap_a`].
pub fn stap_b(don: u16, nalus: &[Bytes]) -> Result<Bytes> {
    check_aggregated(&nalus.iter().collect::<Vec<_>>())?;
    let mut out = BytesMut::with_capacity(
        STAPB_HEADER_SIZE + nalus.iter().map(|nalu| 2 + nalu.len()).sum::<usize>(),
    );
    out.put_u8(aggregation_header(STAPB_NALU_TYPE, nalus));
    out.put_u16(don);
    for nalu in nalus {
        out.put_u16(nalu.len() as u16);
        out.put(&**nalu);
    }
    Ok(out.freeze())
}

/// `don_diff(m, n)` of RFC 6184 section 5.5: positive when the NAL unit with DON `n` follows
/// the one with DON `m` in decoding order, negative when it precedes it, zero when they share
/// a DON.
pub fn don_diff(m: u16, n: u16) -> i32 {
    let (m, n) = (i32::from(m), i32::from(n));
    if m == n {
        0
    } else if m < n && n - m < 32768 {
        n - m
    } else if m > n && m - n >= 32768 {
        65536 - m + n
    } else if m < n {
        // n - m >= 32768
        -(m + 65536 - n)
    } else {
        // m > n and m - n < 32768
        -(m - n)
    }
}

/// The width of the timestamp offset in a multi-time aggregation packet.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum MtapKind {
    /// MTAP16: 16-bit timestamp offsets.
    Mtap16,
    /// MTAP24: 24-bit timestamp offsets.
    Mtap24,
}

impl MtapKind {
    fn nalu_type(self) -> u8 {
        match self {
            MtapKind::Mtap16 => MTAP16_NALU_TYPE,
            MtapKind::Mtap24 => MTAP24_NALU_TYPE,
        }
    }

    /// Bytes of timestamp offset in each aggregation unit.
    fn offset_size(self) -> usize {
        match self {
            MtapKind::Mtap16 => 2,
            MtapKind::Mtap24 => 3,
        }
    }
}

/// One NAL unit to place in a multi-time aggregation packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MtapUnit {
    /// The NAL unit's decoding order number.
    pub don: u16,
    /// The NAL unit's NALU-time: the RTP timestamp it would carry in a packet of its own.
    pub timestamp: u32,
    /// The NAL unit, header octet included.
    pub nalu: Bytes,
}

/// Builds an MTAP16 or MTAP24 payload (RFC 6184 section 5.7.2) and the RTP timestamp its
/// packet carries.
///
/// The DON base is the DON of the unit that is first in decoding order, each unit's DOND its
/// distance from that; the packet's timestamp is the earliest NALU-time, whose unit gets the
/// timestamp offset zero, and each other unit's offset is its NALU-time less that (modulo
/// 2^32). The units are written in decoding order (section 5.7.2: "The NAL units in the
/// multi-time aggregation packet SHOULD be in decoding order"), ascending DOND, whatever
/// order they are given in; units with the same DON keep their order.
///
/// # Errors
///
/// Fails without units, for a unit that is not a NAL unit of types 1 to 23 or is over 65535
/// bytes, when a unit's DON is more than 255 after the first in decoding order, and when a
/// timestamp offset does not fit the kind's 16 or 24 bits.
pub fn mtap(kind: MtapKind, units: &[MtapUnit]) -> Result<(Bytes, u32)> {
    check_aggregated(&units.iter().map(|unit| &unit.nalu).collect::<Vec<_>>())?;
    // The first in decoding order: the unit no other unit precedes.
    let mut don_base = units[0].don;
    // The earliest NALU-time, by the same modulo comparison.
    let mut timestamp = units[0].timestamp;
    for unit in units {
        if don_diff(don_base, unit.don) < 0 {
            don_base = unit.don;
        }
        if (unit.timestamp.wrapping_sub(timestamp) as i32) < 0 {
            timestamp = unit.timestamp;
        }
    }

    // Decoding order: ascending DON distance from the DON base (a stable sort).
    let mut ordered: Vec<&MtapUnit> = units.iter().collect();
    ordered.sort_by_key(|unit| don_diff(don_base, unit.don));
    let units = ordered;

    let nalus: Vec<Bytes> = units.iter().map(|unit| unit.nalu.clone()).collect();
    let mut out = BytesMut::with_capacity(
        MTAP_HEADER_SIZE
            + units
                .iter()
                .map(|unit| 3 + kind.offset_size() + unit.nalu.len())
                .sum::<usize>(),
    );
    out.put_u8(aggregation_header(kind.nalu_type(), &nalus));
    out.put_u16(don_base);
    for unit in units {
        let dond = u8::try_from(don_diff(don_base, unit.don)).map_err(|_| {
            Error::Other(format!(
                "MTAP: DON {} is more than 255 after the DON base {don_base}",
                unit.don
            ))
        })?;
        let offset = unit.timestamp.wrapping_sub(timestamp);
        if offset >> (8 * kind.offset_size()) != 0 {
            return Err(Error::Other(format!(
                "MTAP: a timestamp offset of {offset} does not fit {} bits",
                8 * kind.offset_size()
            )));
        }
        out.put_u16(unit.nalu.len() as u16);
        out.put_u8(dond);
        match kind {
            MtapKind::Mtap16 => out.put_u16(offset as u16),
            MtapKind::Mtap24 => {
                out.put_u8((offset >> 16) as u8);
                out.put_u16(offset as u16);
            }
        }
        out.put(&*unit.nalu);
    }
    Ok((out.freeze(), timestamp))
}

/// The packetization mode of RFC 6184 section 5.4.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Default)]
enum PacketizationMode {
    /// `packetization-mode=0`.
    SingleNalUnit,
    /// `packetization-mode=1`.
    #[default]
    NonInterleaved,
    /// `packetization-mode=2`.
    Interleaved,
}

/// H264Payloader payloads H264 packets
#[derive(Default, Debug, Clone)]
pub struct H264Payloader {
    /// Parameter sets given in calls that held nothing else: sent, in the order given, ahead
    /// of the access unit of the next call, so they carry its timestamp (RFC 6184 section 5.1).
    held_parameter_sets: Vec<Bytes>,
    mode: PacketizationMode,
    /// Interleaved mode: the DON of the next NAL unit.
    next_don: u16,
}

impl H264Payloader {
    /// A payloader for the negotiated `packetization-mode` (RFC 6184 section 5.4).
    ///
    /// Mode 1 (non-interleaved) is the default: STAP-A for runs of small non-VCL NAL units
    /// (parameter sets, SEI), FU-A for NAL units over the MTU, everything in the order given.
    /// Mode 0 (single NAL unit) sends every NAL unit in a packet of its own and refuses one
    /// that does not fit the MTU, since a mode-0 receiver cannot reassemble fragments. Mode 2
    /// (interleaved) sends STAP-B aggregates and FU-B / FU-A fragments, every NAL unit with a
    /// decoding order number that counts up by one from [`with_initial_don`](Self::with_initial_don),
    /// in decoding order; single NAL unit packets, STAP-A and a leading FU-A are never used in
    /// it (section 6.4). A value above 2 is not a packetization mode and is taken as mode 1;
    /// [`try_with_packetization_mode`](Self::try_with_packetization_mode) refuses it instead.
    pub fn with_packetization_mode(packetization_mode: u8) -> Self {
        Self::try_with_packetization_mode(packetization_mode).unwrap_or_default()
    }

    /// As [`with_packetization_mode`](Self::with_packetization_mode), refusing a value that is
    /// not 0, 1 or 2 (RFC 6184 section 8.1).
    ///
    /// # Errors
    ///
    /// Fails for a mode above 2.
    pub fn try_with_packetization_mode(packetization_mode: u8) -> Result<Self> {
        let mode = match packetization_mode {
            0 => PacketizationMode::SingleNalUnit,
            1 => PacketizationMode::NonInterleaved,
            2 => PacketizationMode::Interleaved,
            other => {
                return Err(Error::Other(format!(
                    "H.264 packetization-mode is 0, 1 or 2, not {other}"
                )));
            }
        };
        Ok(Self {
            mode,
            ..Default::default()
        })
    }

    /// Interleaved mode: the decoding order number of the first NAL unit, which may be any
    /// value (RFC 6184 section 5.5). 0 unless set.
    pub fn with_initial_don(mut self, don: u16) -> Self {
        self.next_don = don;
        self
    }

    /// Whether the payloader sends this NAL unit: not an empty one, not an access unit
    /// delimiter or filler data (never sent), and not a type that is reserved or is one of
    /// this format's packet types (RFC 6184 section 5.4: such types are not sent; sent as a
    /// "NAL unit", a type 24 to 29 would be read as an aggregate or a fragment).
    fn is_sent(nalu: &Bytes) -> bool {
        nalu.first().is_some_and(|&header| {
            let nalu_type = header & NALU_TYPE_BITMASK;
            is_nal_unit_type(nalu_type)
                && nalu_type != AUD_NALU_TYPE
                && nalu_type != FILLER_NALU_TYPE
        })
    }

    /// Mode 0: each NAL unit as it is, or an error for one over the MTU.
    fn emit_single_nal_unit(nalu: &Bytes, mtu: usize, payloads: &mut Vec<Bytes>) -> Result<()> {
        if !Self::is_sent(nalu) {
            return Ok(());
        }
        if nalu.len() > mtu {
            return Err(Error::Other(format!(
                "H.264 packetization-mode=0: a {}-byte NAL unit does not fit the {mtu}-byte MTU",
                nalu.len()
            )));
        }
        payloads.push(nalu.clone());
        Ok(())
    }

    /// Emit a NALU as a single packet or fragment it via FU-A.
    fn emit_single_or_fragment(nalu: &Bytes, mtu: usize, payloads: &mut Vec<Bytes>) {
        if nalu.is_empty() {
            return;
        }

        // Single NALU
        if nalu.len() <= mtu {
            payloads.push(nalu.clone());
            return;
        }

        // FU-A fragmentation. The FU payload is the NAL unit without its header octet, whose
        // F and NRI go in the FU indicator and whose type goes in the FU header (RFC 6184
        // section 5.8). A NAL unit over the MTU always makes two fragments or more, so no
        // fragment has both the start and the end bit.
        let Some(max_fragment_size) = mtu.checked_sub(FUA_HEADER_SIZE).filter(|&size| size > 0)
        else {
            return;
        };
        // +---------------+      +---------------+
        // |0|1|2|3|4|5|6|7|      |0|1|2|3|4|5|6|7|
        // +-+-+-+-+-+-+-+-+      +-+-+-+-+-+-+-+-+
        // |F|NRI|  Type   |      |S|E|R|  Type   |
        // +---------------+      +---------------+
        let indicator = (nalu[0] & (NALU_FORBIDDEN_BITMASK | NALU_REF_IDC_BITMASK)) | FUA_NALU_TYPE;
        let nalu_type = nalu[0] & NALU_TYPE_BITMASK;
        let data = &nalu[1..];
        let last = data.len().div_ceil(max_fragment_size) - 1;
        for (i, fragment) in data.chunks(max_fragment_size).enumerate() {
            let mut out = BytesMut::with_capacity(FUA_HEADER_SIZE + fragment.len());
            out.put_u8(indicator);
            let mut fu_header = nalu_type;
            if i == 0 {
                fu_header |= FU_START_BITMASK;
            } else if i == last {
                fu_header |= FU_END_BITMASK;
            }
            out.put_u8(fu_header);
            out.put(fragment);
            payloads.push(out.freeze());
        }
    }

    /// Interleaved mode: a NAL unit that does not fit a STAP-B, as an FU-B carrying its DON
    /// followed by FU-As (RFC 6184 section 5.8). Always two fragments or more.
    fn emit_fu_b(nalu: &Bytes, don: u16, mtu: usize, payloads: &mut Vec<Bytes>) {
        let (Some(first_size), Some(next_size)) = (
            mtu.checked_sub(FUB_HEADER_SIZE).filter(|&size| size > 0),
            mtu.checked_sub(FUA_HEADER_SIZE).filter(|&size| size > 0),
        ) else {
            return;
        };
        let flags = nalu[0] & (NALU_FORBIDDEN_BITMASK | NALU_REF_IDC_BITMASK);
        let nalu_type = nalu[0] & NALU_TYPE_BITMASK;
        let data = &nalu[1..];
        // A NAL unit is never sent in one FU: one that would fit the FU-B is cut in two.
        let first_len = if data.len() <= first_size {
            data.len().div_ceil(2)
        } else {
            first_size
        };
        let (first, rest) = data.split_at(first_len);

        let mut out = BytesMut::with_capacity(FUB_HEADER_SIZE + first.len());
        out.put_u8(flags | FUB_NALU_TYPE);
        out.put_u8(FU_START_BITMASK | nalu_type);
        out.put_u16(don);
        out.put(first);
        payloads.push(out.freeze());

        // An FU payload may be empty, so there is always an end fragment.
        let fragments = rest.len().div_ceil(next_size).max(1);
        for i in 0..fragments {
            let fragment = &rest[i * next_size..rest.len().min((i + 1) * next_size)];
            let mut out = BytesMut::with_capacity(FUA_HEADER_SIZE + fragment.len());
            out.put_u8(flags | FUA_NALU_TYPE);
            out.put_u8(if i == fragments - 1 {
                FU_END_BITMASK | nalu_type
            } else {
                nalu_type
            });
            out.put(fragment);
            payloads.push(out.freeze());
        }
    }

    /// Mode 1: the NAL units in the order given. A run of non-VCL NAL units that fits the MTU
    /// goes in one STAP-A; a NAL unit over the MTU is fragmented.
    fn payload_non_interleaved(
        &mut self,
        nalus: Vec<Bytes>,
        mtu: usize,
        payloads: &mut Vec<Bytes>,
    ) {
        let nalus: Vec<Bytes> = nalus.into_iter().filter(Self::is_sent).collect();
        if nalus.is_empty() {
            return;
        }
        // Parameter sets given on their own belong to the access unit that follows: they are
        // kept, all of them and in order, and sent ahead of it.
        let only_parameter_sets = nalus.iter().all(|nalu| {
            let nalu_type = nalu[0] & NALU_TYPE_BITMASK;
            nalu_type == SPS_NALU_TYPE || nalu_type == PPS_NALU_TYPE
        });
        let held_bytes: usize = self
            .held_parameter_sets
            .iter()
            .chain(&nalus)
            .map(Bytes::len)
            .sum();
        if only_parameter_sets
            && self.held_parameter_sets.len() + nalus.len() <= MAX_HELD_PARAMETER_SETS
            && held_bytes <= MAX_HELD_PARAMETER_SET_BYTES
        {
            self.held_parameter_sets.extend(nalus);
            return;
        }

        fn flush(pending: &mut Vec<Bytes>, payloads: &mut Vec<Bytes>) {
            match pending.len() {
                0 => {}
                // One NAL unit in a packet is a single NAL unit packet (RFC 6184 section 5.6).
                1 => payloads.extend(pending.pop()),
                _ => {
                    let mut out = BytesMut::with_capacity(
                        STAPA_HEADER_SIZE
                            + pending.iter().map(|nalu| 2 + nalu.len()).sum::<usize>(),
                    );
                    out.put_u8(aggregation_header(STAPA_NALU_TYPE, pending));
                    for nalu in pending.drain(..) {
                        out.put_u16(nalu.len() as u16);
                        out.put(nalu);
                    }
                    payloads.push(out.freeze());
                }
            }
        }

        let mut pending: Vec<Bytes> = vec![];
        let mut pending_size = STAPA_HEADER_SIZE;
        let held = std::mem::take(&mut self.held_parameter_sets);
        for nalu in held.into_iter().chain(nalus) {
            let unit_size = STAPA_NALU_LENGTH_SIZE + nalu.len();
            let aggregated = !is_vcl_type(nalu[0] & NALU_TYPE_BITMASK)
                && nalu.len() <= u16::MAX as usize
                && STAPA_HEADER_SIZE + unit_size <= mtu;
            if aggregated {
                if pending_size + unit_size > mtu {
                    flush(&mut pending, payloads);
                    pending_size = STAPA_HEADER_SIZE;
                }
                pending_size += unit_size;
                pending.push(nalu);
            } else {
                flush(&mut pending, payloads);
                pending_size = STAPA_HEADER_SIZE;
                Self::emit_single_or_fragment(&nalu, mtu, payloads);
            }
        }
        flush(&mut pending, payloads);
    }

    /// Mode 2: the NAL units in the order given, each with the next DON. NAL units that fit
    /// go in STAP-Bs, also alone (a single NAL unit packet is not allowed in this mode); the
    /// others are fragmented, the first fragment an FU-B.
    fn payload_interleaved(&mut self, nalus: Vec<Bytes>, mtu: usize, payloads: &mut Vec<Bytes>) {
        fn flush(don: u16, pending: &mut Vec<Bytes>, payloads: &mut Vec<Bytes>) {
            if pending.is_empty() {
                return;
            }
            let mut out = BytesMut::with_capacity(
                STAPB_HEADER_SIZE + pending.iter().map(|nalu| 2 + nalu.len()).sum::<usize>(),
            );
            out.put_u8(aggregation_header(STAPB_NALU_TYPE, pending));
            out.put_u16(don);
            for nalu in pending.drain(..) {
                out.put_u16(nalu.len() as u16);
                out.put(nalu);
            }
            payloads.push(out.freeze());
        }

        let mut pending: Vec<Bytes> = vec![];
        let mut pending_don = self.next_don;
        let mut pending_size = STAPB_HEADER_SIZE;
        for nalu in nalus.into_iter().filter(Self::is_sent) {
            let don = self.next_don;
            self.next_don = self.next_don.wrapping_add(1);
            let unit_size = STAPA_NALU_LENGTH_SIZE + nalu.len();
            if nalu.len() <= u16::MAX as usize && STAPB_HEADER_SIZE + unit_size <= mtu {
                if pending_size + unit_size > mtu {
                    flush(pending_don, &mut pending, payloads);
                    pending_size = STAPB_HEADER_SIZE;
                }
                if pending.is_empty() {
                    pending_don = don;
                }
                pending_size += unit_size;
                pending.push(nalu);
            } else {
                flush(pending_don, &mut pending, payloads);
                pending_size = STAPB_HEADER_SIZE;
                Self::emit_fu_b(&nalu, don, mtu, payloads);
            }
        }
        flush(pending_don, &mut pending, payloads);
    }
}

impl Payloader for H264Payloader {
    /// Payload fragments a H264 packet across one or more byte arrays
    fn payload(&mut self, mtu: usize, payload: &Bytes) -> Result<Vec<Bytes>> {
        if payload.is_empty() || mtu == 0 {
            return Ok(vec![]);
        }

        // The NAL units of the access unit, split at their Annex B start codes.
        let nalus = annex_b_nal_units(payload);

        let mut payloads = vec![];
        match self.mode {
            PacketizationMode::SingleNalUnit => {
                for nalu in &nalus {
                    Self::emit_single_nal_unit(nalu, mtu, &mut payloads)?;
                }
            }
            PacketizationMode::NonInterleaved => {
                self.payload_non_interleaved(nalus, mtu, &mut payloads)
            }
            PacketizationMode::Interleaved => self.payload_interleaved(nalus, mtu, &mut payloads),
        }

        Ok(payloads)
    }

    fn clone_to(&self) -> Box<dyn Payloader> {
        Box::new(self.clone())
    }
}

/// One NAL unit taken out of an RTP payload.
#[derive(PartialEq, Eq, Debug, Clone)]
pub struct H264NalUnit {
    /// The NAL unit, header octet included, without a start code or a length prefix.
    pub data: Bytes,
    /// Its decoding order number, when its packet carried one: STAP-B, MTAP and a NAL unit
    /// whose first fragment was an FU-B (RFC 6184 section 5.5).
    pub don: Option<u16>,
    /// Its timestamp offset from the packet's RTP timestamp, for a NAL unit of an MTAP: its
    /// NALU-time is the packet's timestamp plus this, modulo 2^32 (RFC 6184 section 5.7.2).
    pub timestamp_offset: Option<u32>,
}

impl H264NalUnit {
    fn plain(data: Bytes) -> Self {
        H264NalUnit {
            data,
            don: None,
            timestamp_offset: None,
        }
    }

    /// The NAL unit type: the low five bits of its header octet.
    pub fn nalu_type(&self) -> u8 {
        self.data.first().map_or(0, |b| b & NALU_TYPE_BITMASK)
    }
}

/// The de-interleaving buffer never holds more NAL units than this, whatever
/// `sprop-interleaving-depth` asks for: past it the NAL unit that is next in decoding order
/// is passed on.
pub const MAX_DEINTERLEAVING_NAL_UNITS: usize = 4096;
/// Nor more bytes than this.
pub const MAX_DEINTERLEAVING_BYTES: usize = 32 * 1024 * 1024;

#[derive(PartialEq, Eq, Debug, Clone)]
struct BufferedNalUnit {
    unit: H264NalUnit,
    don: u16,
    /// `AbsDON` of RFC 6184 section 8.1 (`sprop-max-don-diff`): the DON unwrapped along the
    /// reception order.
    abs_don: i64,
}

/// The de-interleaving buffer of interleaved mode (RFC 6184 section 7.2.2): NAL units go in
/// in reception order with their DON and come out in decoding order.
///
/// NAL units stay in the buffer until it holds `sprop-interleaving-depth + 1` VCL NAL units,
/// or, when `sprop-max-don-diff` is given, until a NAL unit is more than that many DONs behind
/// the latest one. They leave in ascending DON distance from the last one passed on.
#[derive(PartialEq, Eq, Debug, Clone)]
pub struct H264DeinterleavingBuffer {
    /// N of section 7.2.2: `sprop-interleaving-depth` plus one.
    vcl_capacity: usize,
    max_don_diff: Option<i32>,
    /// PDON: the DON of the last NAL unit passed on. `None` until one was: see
    /// [`distance`](Self::distance).
    previous_don: Option<u16>,
    units: Vec<BufferedNalUnit>,
    /// The DON and AbsDON of the NAL unit received last.
    last_received: Option<(u16, i64)>,
    bytes: usize,
    /// `sprop-init-buf-time`, when signalled.
    init_buf_time: Option<Duration>,
    /// When the first NAL unit was stored ([`push_at`](Self::push_at)).
    first_arrival: Option<Instant>,
    /// Initial buffering ended by the depth or the DON spread (section 7.2.2).
    initial_buffering_over: bool,
    /// PDON starts at 0, as section 7.2.2 has it ([`with_literal_pdon`](Self::with_literal_pdon)).
    literal_pdon: bool,
}

impl H264DeinterleavingBuffer {
    /// A buffer for a stream with these `sprop-interleaving-depth` and `sprop-max-don-diff`
    /// media type parameters (RFC 6184 section 8.1; both are 0 to 32767, and the second is
    /// optional).
    pub fn new(sprop_interleaving_depth: u16, sprop_max_don_diff: Option<u16>) -> Self {
        H264DeinterleavingBuffer {
            vcl_capacity: usize::from(sprop_interleaving_depth) + 1,
            max_don_diff: sprop_max_don_diff.map(i32::from),
            previous_don: None,
            units: Vec::new(),
            last_received: None,
            bytes: 0,
            init_buf_time: None,
            first_arrival: None,
            initial_buffering_over: false,
            literal_pdon: false,
        }
    }

    /// RFC 6184 section 7.2.2 as written: "Let PDON be a variable that is initialized to 0 at
    /// the beginning of the RTP session". A NAL unit whose DON is 0 then has the largest DON
    /// distance, so a stream numbered from DON 0 (or whose first DONs wrap through 0) has those
    /// NAL units passed on after the others. Default off: until a NAL unit has been passed on,
    /// PDON is the DON just before the earliest one buffered, which gives the RFC's order for
    /// every other stream and decoding order for those.
    pub fn with_literal_pdon(mut self, literal: bool) -> Self {
        self.literal_pdon = literal;
        self
    }

    /// The stream's `sprop-init-buf-time` (RFC 6184 section 8.1), in ticks of a 90 kHz
    /// clock: "the initial buffering time that a receiver MUST wait before starting decoding".
    pub fn with_init_buf_time(mut self, sprop_init_buf_time: u32) -> Self {
        self.init_buf_time = Some(Duration::from_micros(
            u64::from(sprop_init_buf_time) * 1_000_000 / 90_000,
        ));
        self
    }

    /// [`push`](Self::push) of a NAL unit that arrived at `now`, which starts the initial
    /// buffering time on the first one.
    pub fn push_at(&mut self, now: Instant, unit: H264NalUnit) -> Vec<H264NalUnit> {
        if unit.don.is_some() {
            self.first_arrival.get_or_insert(now);
        }
        self.push(unit)
    }

    /// Whether the receiver is still in initial buffering at `now` (RFC 6184 section 7.2.2),
    /// and so is not to start decoding: until the buffer has held N VCL NAL units (N being
    /// `sprop-interleaving-depth` plus one), or two NAL units more than `sprop-max-don-diff`
    /// apart, or `sprop-init-buf-time` has passed since the first NAL unit arrived. The NAL
    /// units the buffer passes on are in decoding order either way; this tells the decoder
    /// when it may begin with them.
    pub fn is_initial_buffering(&self, now: Instant) -> bool {
        if self.initial_buffering_over {
            return false;
        }
        match (self.init_buf_time, self.first_arrival) {
            (Some(wait), Some(first)) => now.saturating_duration_since(first) < wait,
            _ => true,
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

    /// The DON distance of section 7.2.2 from the last NAL unit passed on (PDON).
    ///
    /// The RFC starts PDON at 0, which puts a NAL unit whose DON is 0 at the largest distance
    /// there is: a stream numbered from 0 would have its first NAL unit passed on last. Until a
    /// NAL unit has been passed on, PDON is taken here as the DON just before the earliest one
    /// in the buffer (by AbsDON), so that the first NAL unit out is the first in decoding order
    /// whatever DON the sender started from (section 5.5 lets it start anywhere).
    fn distance(&self, don: u16) -> u32 {
        let previous_don = self.previous_don.unwrap_or_else(|| {
            if self.literal_pdon {
                return 0;
            }
            self.units
                .iter()
                .min_by_key(|buffered| buffered.abs_don)
                .map_or(0, |earliest| earliest.don.wrapping_sub(1))
        });
        if don > previous_don {
            u32::from(don - previous_don)
        } else {
            65535 - u32::from(previous_don) + u32::from(don) + 1
        }
    }

    fn vcl_count(&self) -> usize {
        self.units
            .iter()
            .filter(|buffered| is_vcl_type(buffered.unit.nalu_type()))
            .count()
    }

    /// Removes the NAL unit with the smallest DON distance. The buffer is not empty.
    fn take_next(&mut self) -> BufferedNalUnit {
        let index = (0..self.units.len())
            .min_by_key(|&i| self.distance(self.units[i].don))
            .unwrap_or(0);
        let buffered = self.units.remove(index);
        self.bytes -= buffered.unit.data.len();
        buffered
    }

    /// Stores a NAL unit and returns the NAL units that are now due, in decoding order. A NAL
    /// unit without a DON is not part of an interleaved stream and is returned as it is.
    pub fn push(&mut self, unit: H264NalUnit) -> Vec<H264NalUnit> {
        let Some(don) = unit.don else {
            return vec![unit];
        };
        let abs_don = match self.last_received {
            Some((last_don, last_abs)) => last_abs + i64::from(don_diff(last_don, don)),
            None => i64::from(don),
        };
        self.last_received = Some((don, abs_don));
        self.bytes += unit.data.len();
        self.units.push(BufferedNalUnit { unit, don, abs_don });

        let mut out = vec![];
        let mut last_out = None;
        // With N VCL NAL units or more in the buffer, NAL units leave until N - 1 are left.
        // The distances are those from PDON as it was when the removal began.
        if self.vcl_count() >= self.vcl_capacity {
            self.initial_buffering_over = true;
        }
        while self.vcl_count() >= self.vcl_capacity {
            let buffered = self.take_next();
            last_out = Some(buffered.don);
            out.push(buffered.unit);
        }
        // Every NAL unit more than sprop-max-don-diff behind the greatest AbsDON leaves too.
        if let Some(max_don_diff) = self.max_don_diff {
            let greatest = self.units.iter().map(|b| b.abs_don).max().unwrap_or(0);
            loop {
                let due = self
                    .units
                    .iter()
                    .any(|b| greatest - b.abs_don > i64::from(max_don_diff));
                if !due {
                    break;
                }
                self.initial_buffering_over = true;
                // In decoding order among those due.
                let index = (0..self.units.len())
                    .filter(|&i| greatest - self.units[i].abs_don > i64::from(max_don_diff))
                    .min_by_key(|&i| self.distance(self.units[i].don))
                    .unwrap_or(0);
                let buffered = self.units.remove(index);
                self.bytes -= buffered.unit.data.len();
                last_out = Some(buffered.don);
                out.push(buffered.unit);
            }
        }
        // Bounded, whatever the stream's parameters say.
        while self.units.len() > MAX_DEINTERLEAVING_NAL_UNITS
            || self.bytes > MAX_DEINTERLEAVING_BYTES
        {
            let buffered = self.take_next();
            last_out = Some(buffered.don);
            out.push(buffered.unit);
        }
        if last_out.is_some() {
            self.previous_don = last_out;
        }
        out
    }

    /// Empties the buffer, in decoding order: the end of the stream.
    pub fn flush(&mut self) -> Vec<H264NalUnit> {
        let mut buffered: Vec<(u32, BufferedNalUnit)> = self
            .units
            .iter()
            .map(|b| (self.distance(b.don), b.clone()))
            .collect();
        self.units.clear();
        self.bytes = 0;
        buffered.sort_by_key(|(distance, _)| *distance);
        let buffered: Vec<BufferedNalUnit> = buffered.into_iter().map(|(_, b)| b).collect();
        if let Some(last) = buffered.last() {
            self.previous_don = Some(last.don);
        }
        buffered.into_iter().map(|b| b.unit).collect()
    }
}

/// H264Packet represents the H264 header that is stored in the payload of an RTP Packet
#[derive(PartialEq, Eq, Debug, Default, Clone)]
pub struct H264Packet {
    /// Whether to emit AVCC length-prefixed output instead of Annex B start codes.
    pub is_avc: bool,
    fua_buffer: Option<BytesMut>,
    /// The DON of the NAL unit being reassembled, when its first fragment was an FU-B.
    fu_don: Option<u16>,
    /// The sequence number of the last packet given with one.
    last_sequence_number: Option<u16>,
    deinterleaving: Option<H264DeinterleavingBuffer>,
}

impl H264Packet {
    /// Receives an interleaved stream (`packetization-mode=2`) in decoding order: NAL units
    /// that carry a DON go through `buffer` before [`depacketize`](Depacketizer::depacketize)
    /// returns them (RFC 6184 section 7.2.2). Without this, NAL units come out in the order
    /// their packets hold them, which is decoding order for modes 0 and 1.
    pub fn with_deinterleaving(mut self, buffer: H264DeinterleavingBuffer) -> Self {
        self.deinterleaving = Some(buffer);
        self
    }

    /// The NAL units still in the de-interleaving buffer, in decoding order and in the output
    /// format of [`depacketize`](Depacketizer::depacketize): for the end of the stream.
    pub fn flush_deinterleaving(&mut self) -> Bytes {
        let units = self
            .deinterleaving
            .as_mut()
            .map(H264DeinterleavingBuffer::flush)
            .unwrap_or_default();
        self.format(&units)
    }

    /// As [`depacketize`](Depacketizer::depacketize), given the packet's RTP sequence number:
    /// when a packet is missing before this one, the fragments collected so far are discarded
    /// with the rest of their NAL unit, in place of a NAL unit with a hole in it (RFC 6184
    /// section 5.8: a receiver discards the following fragmentation units of a NAL unit after
    /// a lost one). Give the packets in sequence number order.
    ///
    /// # Errors
    ///
    /// As [`depacketize`](Depacketizer::depacketize).
    pub fn depacketize_with_sequence_number(
        &mut self,
        sequence_number: u16,
        packet: &Bytes,
    ) -> Result<Bytes> {
        if let Some(last) = self.last_sequence_number
            && sequence_number != last.wrapping_add(1)
        {
            self.fua_buffer = None;
            self.fu_don = None;
        }
        self.last_sequence_number = Some(sequence_number);
        self.depacketize(packet)
    }

    /// The NAL units a payload completes, with the decoding order number and timestamp offset
    /// its packet type gives them: one for a single NAL unit packet, several for an aggregate,
    /// none or one for a fragment. Reserved packet types yield nothing (RFC 6184 section 5.4:
    /// a receiver ignores them). The de-interleaving buffer is not involved.
    ///
    /// # Errors
    ///
    /// Fails for an empty payload, an aggregate or fragment cut short, a NAL unit size that
    /// runs past the payload, and a reassembly over [`MAX_FUA_NALU_SIZE`].
    pub fn nal_units(&mut self, packet: &Bytes) -> Result<Vec<H264NalUnit>> {
        // NALU Types
        // https://tools.ietf.org/html/rfc6184#section-5.4
        let Some(&b0) = packet.first() else {
            return Err(Error::ErrShortPacket);
        };
        let nalu_type = b0 & NALU_TYPE_BITMASK;

        match nalu_type {
            // A single NAL unit packet, a header octet alone included (end of sequence, end
            // of stream).
            1..=23 => Ok(vec![H264NalUnit::plain(packet.clone())]),
            STAPA_NALU_TYPE | STAPB_NALU_TYPE => {
                let mut curr_offset = STAPA_HEADER_SIZE;
                let mut don = if nalu_type == STAPB_NALU_TYPE {
                    if packet.len() < STAPB_HEADER_SIZE {
                        return Err(Error::ErrShortPacket);
                    }
                    curr_offset = STAPB_HEADER_SIZE;
                    Some(u16::from_be_bytes([packet[1], packet[2]]))
                } else {
                    None
                };
                if curr_offset >= packet.len() {
                    // An aggregate holds at least one aggregation unit.
                    return Err(Error::ErrShortPacket);
                }
                let mut units = vec![];
                while curr_offset < packet.len() {
                    if packet.len() - curr_offset < STAPA_NALU_LENGTH_SIZE {
                        return Err(Error::ErrShortPacket);
                    }
                    let nalu_size =
                        ((packet[curr_offset] as usize) << 8) | packet[curr_offset + 1] as usize;
                    curr_offset += STAPA_NALU_LENGTH_SIZE;

                    if packet.len() < curr_offset + nalu_size {
                        return Err(Error::StapASizeLargerThanBuffer(
                            nalu_size,
                            packet.len() - curr_offset,
                        ));
                    }
                    let data = packet.slice(curr_offset..curr_offset + nalu_size);
                    curr_offset += nalu_size;
                    // Each unit has the DON after the one before it, whether it is passed on
                    // or not. A unit that is not a NAL unit (empty, a nested aggregate or
                    // fragment, a reserved type) is ignored.
                    let unit_don = don;
                    don = don.map(|don| don.wrapping_add(1));
                    if data
                        .first()
                        .is_some_and(|b| is_nal_unit_type(b & NALU_TYPE_BITMASK))
                    {
                        units.push(H264NalUnit {
                            data,
                            don: unit_don,
                            timestamp_offset: None,
                        });
                    }
                }
                Ok(units)
            }
            MTAP16_NALU_TYPE | MTAP24_NALU_TYPE => {
                let offset_size = if nalu_type == MTAP16_NALU_TYPE { 2 } else { 3 };
                if packet.len() <= MTAP_HEADER_SIZE {
                    return Err(Error::ErrShortPacket);
                }
                let don_base = u16::from_be_bytes([packet[1], packet[2]]);
                let mut curr_offset = MTAP_HEADER_SIZE;
                let mut units = vec![];
                while curr_offset < packet.len() {
                    // NAL unit size, DOND and timestamp offset, then the NAL unit.
                    let unit_header = STAPA_NALU_LENGTH_SIZE + 1 + offset_size;
                    if packet.len() - curr_offset < unit_header {
                        return Err(Error::ErrShortPacket);
                    }
                    let nalu_size =
                        ((packet[curr_offset] as usize) << 8) | packet[curr_offset + 1] as usize;
                    let dond = packet[curr_offset + 2];
                    let timestamp_offset = packet[curr_offset + 3..curr_offset + unit_header]
                        .iter()
                        .fold(0u32, |offset, &b| (offset << 8) | u32::from(b));
                    curr_offset += unit_header;
                    if packet.len() < curr_offset + nalu_size {
                        return Err(Error::StapASizeLargerThanBuffer(
                            nalu_size,
                            packet.len() - curr_offset,
                        ));
                    }
                    let data = packet.slice(curr_offset..curr_offset + nalu_size);
                    curr_offset += nalu_size;
                    if data
                        .first()
                        .is_some_and(|b| is_nal_unit_type(b & NALU_TYPE_BITMASK))
                    {
                        units.push(H264NalUnit {
                            data,
                            // DON = (DONB + DOND) % 65536.
                            don: Some(don_base.wrapping_add(u16::from(dond))),
                            timestamp_offset: Some(timestamp_offset),
                        });
                    }
                }
                Ok(units)
            }
            FUA_NALU_TYPE | FUB_NALU_TYPE => {
                if packet.len() < FUA_HEADER_SIZE {
                    return Err(Error::ErrShortPacket);
                }
                // The R bit of the FU header is ignored (RFC 6184 section 5.8).
                let b1 = packet[1];
                let fragmented_nalu_type = b1 & NALU_TYPE_BITMASK;
                let start = b1 & FU_START_BITMASK != 0;
                let mut header_size = FUA_HEADER_SIZE;

                if nalu_type == FUB_NALU_TYPE {
                    // An FU-B is the first fragment of a NAL unit and nothing else.
                    if !start || packet.len() < FUB_HEADER_SIZE {
                        self.fua_buffer = None;
                        self.fu_don = None;
                        return Err(Error::ErrShortPacket);
                    }
                    header_size = FUB_HEADER_SIZE;
                }

                if start {
                    if is_nal_unit_type(fragmented_nalu_type) {
                        self.fua_buffer = Some(BytesMut::new());
                        self.fu_don = (nalu_type == FUB_NALU_TYPE)
                            .then(|| u16::from_be_bytes([packet[2], packet[3]]));
                    } else {
                        // A fragmented aggregate or fragment, or a reserved type: ignored,
                        // with the fragments that follow.
                        self.fua_buffer = None;
                        self.fu_don = None;
                    }
                }
                let Some(fua_buffer) = &mut self.fua_buffer else {
                    // A fragment whose start was lost cannot be reassembled into a NAL unit;
                    // drop it rather than splice it onto nothing.
                    return Ok(vec![]);
                };

                // The FU payload may be empty.
                let fragment = &packet[header_size..];
                if fua_buffer.len() + fragment.len() > MAX_FUA_NALU_SIZE {
                    // Bounded: a peer that never sends the end fragment must not grow this
                    // without limit. Drop the partial NAL unit.
                    self.fua_buffer = None;
                    self.fu_don = None;
                    return Err(Error::ErrShortPacket);
                }
                fua_buffer.put(fragment);

                if b1 & FU_END_BITMASK == 0 {
                    return Ok(vec![]);
                }
                // The NAL unit header: F and NRI from the FU indicator, the type from the FU
                // header.
                let mut data = BytesMut::with_capacity(1 + fua_buffer.len());
                data.put_u8(
                    (b0 & (NALU_FORBIDDEN_BITMASK | NALU_REF_IDC_BITMASK)) | fragmented_nalu_type,
                );
                if let Some(fua_buffer) = self.fua_buffer.take() {
                    data.put(fua_buffer);
                }
                Ok(vec![H264NalUnit {
                    data: data.freeze(),
                    don: self.fu_don.take(),
                    timestamp_offset: None,
                }])
            }
            // Types 0, 30 and 31 are reserved: ignored (RFC 6184 section 5.4).
            _ => Ok(vec![]),
        }
    }

    /// NAL units as an Annex B byte stream, or length-prefixed for `is_avc`.
    fn format(&self, units: &[H264NalUnit]) -> Bytes {
        let mut payload =
            BytesMut::with_capacity(units.iter().map(|unit| 4 + unit.data.len()).sum());
        for unit in units {
            if self.is_avc {
                payload.put_u32(unit.data.len() as u32);
            } else {
                payload.put(&*ANNEXB_NALUSTART_CODE);
            }
            payload.put(&*unit.data);
        }
        payload.freeze()
    }
}

impl Depacketizer for H264Packet {
    /// depacketize parses the passed byte slice and stores the result in the H264Packet this method is called upon
    fn depacketize(&mut self, packet: &Bytes) -> Result<Bytes> {
        let mut units = self.nal_units(packet)?;
        if let Some(buffer) = &mut self.deinterleaving {
            units = units
                .into_iter()
                .flat_map(|unit| buffer.push(unit))
                .collect();
        }
        Ok(self.format(&units))
    }

    /// is_partition_head checks if this is the head of a packetized nalu stream.
    fn is_partition_head(&self, payload: &Bytes) -> bool {
        let Some(&b0) = payload.first() else {
            return false;
        };

        if b0 & NALU_TYPE_BITMASK == FUA_NALU_TYPE || b0 & NALU_TYPE_BITMASK == FUB_NALU_TYPE {
            payload
                .get(1)
                .is_some_and(|fu_header| fu_header & FU_START_BITMASK != 0)
        } else {
            true
        }
    }

    fn is_partition_tail(&self, marker: bool, _payload: &Bytes) -> bool {
        marker
    }
}
