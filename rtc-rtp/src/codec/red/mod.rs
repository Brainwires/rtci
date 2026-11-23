//! Redundant audio data, RED ([RFC 2198]).
//!
//! A RED payload is a list of block headers followed by the data blocks in the same order,
//! with no padding between them (section 3):
//!
//! ```text
//!  0                   1                   2                   3
//!  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |1|   block PT  |  timestamp offset         |   block length    |   redundant block header
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |0|   block PT  |                                                   primary block header
//! +-+-+-+-+-+-+-+-+
//! ```
//!
//! The RTP header of a RED packet (sequence number, timestamp, marker, CSRCs) belongs to the
//! primary block; a redundant block's timestamp is the RTP timestamp minus its offset, and it
//! must use the same clock rate as the primary. Two things are not carried for redundant data
//! (section 4): the marker bit of a lost primary is lost with it, and the CSRC list of the RED
//! packet that carried a recovered block is the one to apply to it. `RedDecoder` exposes
//! neither; the caller takes the CSRCs from the RED packet it fed in.
//!
//! * `RedPacket` reads and writes one payload, strictly bounds-checked.
//! * `RedEncoder` builds each payload from a new primary plus copies of the previous ones
//!   (section 3: "a copy of the primary MAY be used as the redundancy", the mode Chrome uses
//!   for Opus).
//! * `RedDecoder` returns each packet's primary and recovers lost earlier primaries from
//!   later packets' redundant blocks.
//! * `parse_red_fmtp` / `format_red_fmtp` handle the `a=fmtp:<pt> 111/111` list
//!   (section 5).
//!
//! An empty primary block is accepted and produced: nothing in RFC 2198 forbids a zero-length
//! block, and RFC 4103 (T.140 text over RED) sends empty primaries while idle.
//!
//! [RFC 2198]: https://datatracker.ietf.org/doc/html/rfc2198
#[cfg(test)]
mod red_test;

use crate::packetizer::Depacketizer;
use bytes::{Buf, BufMut, Bytes};
use shared::error::{Error, Result};
use shared::marshal::{Marshal, MarshalSize, Unmarshal};
use std::collections::VecDeque;

/// The most blocks (redundant ones plus the primary) a [`RedPacket`] may have. RFC 2198 sets
/// no limit; one or two levels of redundancy are usual, and 32 bounds the parser's work.
pub const RED_MAX_BLOCKS: usize = 32;
/// The largest timestamp offset (14 bits).
pub const RED_MAX_TIMESTAMP_OFFSET: u16 = 0x3FFF;
/// The largest redundant block length (10 bits).
pub const RED_MAX_BLOCK_LENGTH: usize = 0x3FF;
/// The largest RTP payload type (7 bits).
pub const RED_MAX_PAYLOAD_TYPE: u8 = 0x7F;
/// Size of a redundant block header.
pub const RED_REDUNDANT_HEADER_SIZE: usize = 4;
/// Size of the primary block header.
pub const RED_PRIMARY_HEADER_SIZE: usize = 1;

/// One block of a RED payload.
#[derive(PartialEq, Eq, Debug, Default, Clone)]
pub struct RedBlock {
    /// RTP payload type of the block's data.
    pub payload_type: u8,
    /// How far the block's timestamp is before the RTP timestamp; 0 for the primary.
    pub timestamp_offset: u16,
    /// The block's data: a standard RTP payload of `payload_type`.
    pub data: Bytes,
    /// Whether this is the primary block.
    pub primary: bool,
}

impl RedBlock {
    /// A redundant block.
    pub fn redundant(payload_type: u8, timestamp_offset: u16, data: Bytes) -> Self {
        RedBlock {
            payload_type,
            timestamp_offset,
            data,
            primary: false,
        }
    }

    /// The primary block.
    pub fn primary(payload_type: u8, data: Bytes) -> Self {
        RedBlock {
            payload_type,
            timestamp_offset: 0,
            data,
            primary: true,
        }
    }

    /// The block's absolute RTP timestamp, given the RED packet's RTP timestamp.
    pub fn timestamp(&self, red_timestamp: u32) -> u32 {
        red_timestamp.wrapping_sub(u32::from(self.timestamp_offset))
    }

    fn header_size(&self) -> usize {
        if self.primary {
            RED_PRIMARY_HEADER_SIZE
        } else {
            RED_REDUNDANT_HEADER_SIZE
        }
    }
}

/// One RED payload: redundant blocks in header order, then the primary.
///
/// Always valid by construction: at most [`RED_MAX_BLOCKS`] blocks, the last and only the
/// last one primary, payload types at most 127, redundant offsets at most 0x3FFF and lengths
/// at most 0x3FF.
#[derive(PartialEq, Eq, Debug, Clone)]
pub struct RedPacket {
    blocks: Vec<RedBlock>,
}

impl RedPacket {
    /// A payload of `redundant` blocks (in header order, conventionally oldest first) followed
    /// by the primary.
    ///
    /// # Errors
    ///
    /// Fails on a payload type above 127, a redundant offset above 0x3FFF or length above
    /// 0x3FF, or more than [`RED_MAX_BLOCKS`] blocks in all.
    pub fn new(
        primary_payload_type: u8,
        primary: Bytes,
        redundant: impl IntoIterator<Item = (u8, u16, Bytes)>,
    ) -> Result<Self> {
        let mut blocks: Vec<RedBlock> = redundant
            .into_iter()
            .take(RED_MAX_BLOCKS)
            .map(|(pt, offset, data)| RedBlock::redundant(pt, offset, data))
            .collect();
        blocks.push(RedBlock::primary(primary_payload_type, primary));
        Self::from_blocks(blocks)
    }

    /// A payload from explicit blocks; the last must be the primary.
    ///
    /// # Errors
    ///
    /// As [`RedPacket::new`], plus: no block, or a primary block anywhere but last.
    pub fn from_blocks(blocks: Vec<RedBlock>) -> Result<Self> {
        if blocks.is_empty() || blocks.len() > RED_MAX_BLOCKS {
            return Err(Error::Other(format!(
                "a RED payload has 1 to {RED_MAX_BLOCKS} blocks, not {}",
                blocks.len()
            )));
        }
        let last = blocks.len() - 1;
        for (i, block) in blocks.iter().enumerate() {
            if block.primary != (i == last) {
                return Err(Error::Other(
                    "the primary block must be the last and only primary".into(),
                ));
            }
            if block.payload_type > RED_MAX_PAYLOAD_TYPE {
                return Err(Error::Other(format!(
                    "RED block payload type {} exceeds 127",
                    block.payload_type
                )));
            }
            if block.primary {
                if block.timestamp_offset != 0 {
                    return Err(Error::Other("the RED primary has no offset".into()));
                }
            } else {
                if block.timestamp_offset > RED_MAX_TIMESTAMP_OFFSET {
                    return Err(Error::Other(format!(
                        "RED timestamp offset {} exceeds 0x3FFF",
                        block.timestamp_offset
                    )));
                }
                if block.data.len() > RED_MAX_BLOCK_LENGTH {
                    return Err(Error::Other(format!(
                        "RED block length {} exceeds 0x3FF",
                        block.data.len()
                    )));
                }
            }
        }
        Ok(RedPacket { blocks })
    }

    /// Parses a RED payload (zero-copy: the blocks' data are slices of `payload`).
    ///
    /// # Errors
    ///
    /// Fails on an empty payload, a truncated header, no primary header within
    /// [`RED_MAX_BLOCKS`] headers, or block lengths exceeding the payload.
    pub fn parse(payload: &Bytes) -> Result<Self> {
        let mut headers: Vec<(u8, u16, usize)> = Vec::new();
        let mut pos = 0usize;
        let primary_pt = loop {
            let Some(&first) = payload.get(pos) else {
                return Err(Error::ErrShortPacket);
            };
            if first & 0x80 == 0 {
                pos += RED_PRIMARY_HEADER_SIZE;
                break first;
            }
            if headers.len() + 1 >= RED_MAX_BLOCKS {
                return Err(Error::Other(format!(
                    "RED payload has more than {RED_MAX_BLOCKS} blocks"
                )));
            }
            let Some(header) = payload.get(pos..pos + RED_REDUNDANT_HEADER_SIZE) else {
                return Err(Error::ErrShortPacket);
            };
            let rest = u32::from_be_bytes([0, header[1], header[2], header[3]]);
            headers.push((first & 0x7F, (rest >> 10) as u16, (rest & 0x3FF) as usize));
            pos += RED_REDUNDANT_HEADER_SIZE;
        };

        let mut blocks = Vec::with_capacity(headers.len() + 1);
        for (pt, offset, len) in headers {
            let end = pos + len;
            if end > payload.len() {
                return Err(Error::ErrShortPacket);
            }
            blocks.push(RedBlock::redundant(pt, offset, payload.slice(pos..end)));
            pos = end;
        }
        blocks.push(RedBlock::primary(primary_pt, payload.slice(pos..)));
        Ok(RedPacket { blocks })
    }

    /// All blocks: redundant ones in header order, the primary last.
    pub fn blocks(&self) -> &[RedBlock] {
        &self.blocks
    }

    /// The redundant blocks, in header order.
    pub fn redundant(&self) -> &[RedBlock] {
        &self.blocks[..self.blocks.len() - 1]
    }

    /// The primary block.
    pub fn primary(&self) -> &RedBlock {
        &self.blocks[self.blocks.len() - 1]
    }

    /// Takes the blocks out.
    pub fn into_blocks(self) -> Vec<RedBlock> {
        self.blocks
    }
}

impl MarshalSize for RedPacket {
    fn marshal_size(&self) -> usize {
        self.blocks
            .iter()
            .map(|b| b.header_size() + b.data.len())
            .sum()
    }
}

impl Marshal for RedPacket {
    /// Writes the headers, F set on all but the primary's, then the data blocks.
    fn marshal_to(&self, mut buf: &mut [u8]) -> Result<usize> {
        let size = self.marshal_size();
        if buf.remaining_mut() < size {
            return Err(Error::ErrBufferTooSmall);
        }
        for block in &self.blocks {
            if block.primary {
                buf.put_u8(block.payload_type);
            } else {
                buf.put_u8(0x80 | block.payload_type);
                let rest = (u32::from(block.timestamp_offset) << 10) | block.data.len() as u32;
                buf.put_slice(&rest.to_be_bytes()[1..]);
            }
        }
        for block in &self.blocks {
            buf.put_slice(&block.data);
        }
        Ok(size)
    }
}

impl Unmarshal for RedPacket {
    /// Parses all remaining bytes of `buf` as one RED payload (see [`RedPacket::parse`]).
    fn unmarshal<B>(buf: &mut B) -> Result<Self>
    where
        Self: Sized,
        B: Buf,
    {
        let payload = buf.copy_to_bytes(buf.remaining());
        RedPacket::parse(&payload)
    }
}

/// Builds RED payloads whose redundancy is copies of the previous primaries (RFC 2198
/// section 3), the way Chrome sends Opus RED.
///
/// It keeps the last `redundancy` primaries with their timestamps. Each
/// [`encode`](Self::encode) puts the still-usable ones before the new primary, oldest first,
/// dropping (oldest first) those whose offset would be 0 or exceed 0x3FFF, whose length exceeds
/// 0x3FF, or that do not fit `max_payload_size`. Deterministic and bounded.
#[derive(Debug, Clone)]
pub struct RedEncoder {
    redundancy: usize,
    max_payload_size: usize,
    history: VecDeque<(u32, u8, Bytes)>,
}

impl RedEncoder {
    /// An encoder carrying up to `redundancy` earlier primaries (capped at
    /// `RED_MAX_BLOCKS - 1`) in payloads of at most `max_payload_size` bytes.
    pub fn new(redundancy: usize, max_payload_size: usize) -> Self {
        let redundancy = redundancy.min(RED_MAX_BLOCKS - 1);
        RedEncoder {
            redundancy,
            max_payload_size,
            history: VecDeque::with_capacity(redundancy),
        }
    }

    /// The configured redundancy level.
    pub fn redundancy(&self) -> usize {
        self.redundancy
    }

    /// Forgets the earlier primaries (for a stream restart or timestamp jump).
    pub fn reset(&mut self) {
        self.history.clear();
    }

    /// The RED packet for a new primary at RTP `timestamp`. The caller sends it with the RED
    /// payload type, this `timestamp` and the primary's marker bit.
    ///
    /// # Errors
    ///
    /// Fails on a payload type above 127, or a primary that alone does not fit
    /// `max_payload_size` (nothing is remembered then).
    pub fn encode_packet(
        &mut self,
        payload_type: u8,
        timestamp: u32,
        payload: Bytes,
    ) -> Result<RedPacket> {
        if payload_type > RED_MAX_PAYLOAD_TYPE {
            return Err(Error::Other(format!(
                "RED block payload type {payload_type} exceeds 127"
            )));
        }
        let primary_size = RED_PRIMARY_HEADER_SIZE + payload.len();
        if primary_size > self.max_payload_size {
            return Err(Error::ErrPacketTooBig);
        }

        let mut redundant: Vec<(u8, u16, Bytes)> = self
            .history
            .iter()
            .filter_map(|(ts, pt, data)| {
                let offset = timestamp.wrapping_sub(*ts);
                (offset >= 1
                    && offset <= u32::from(RED_MAX_TIMESTAMP_OFFSET)
                    && data.len() <= RED_MAX_BLOCK_LENGTH)
                    .then(|| (*pt, offset as u16, data.clone()))
            })
            .collect();
        let mut size = primary_size
            + redundant
                .iter()
                .map(|(_, _, d)| RED_REDUNDANT_HEADER_SIZE + d.len())
                .sum::<usize>();
        let mut drop = 0;
        while size > self.max_payload_size && drop < redundant.len() {
            size -= RED_REDUNDANT_HEADER_SIZE + redundant[drop].2.len();
            drop += 1;
        }
        redundant.drain(..drop);

        let packet = RedPacket::new(payload_type, payload.clone(), redundant)?;
        if self.redundancy > 0 {
            if self.history.len() == self.redundancy {
                self.history.pop_front();
            }
            self.history.push_back((timestamp, payload_type, payload));
        }
        Ok(packet)
    }

    /// The RED RTP packet for the media packet `primary` (RFC 2198 section 3): "a standard
    /// RTP header ... where the payload type field indicates the redundant encoding" and the
    /// other fields (sequence number, timestamp, marker, SSRC, CSRCs, extensions) are those of
    /// the primary. Its payload is [`encode_packet`](Self::encode_packet) of the primary's.
    ///
    /// # Errors
    ///
    /// As [`encode_packet`](Self::encode_packet), and for a RED payload type above 127.
    pub fn encode_rtp(
        &mut self,
        red_payload_type: u8,
        primary: &crate::packet::Packet,
    ) -> Result<crate::packet::Packet> {
        if red_payload_type > RED_MAX_PAYLOAD_TYPE {
            return Err(Error::Other(format!(
                "RED payload type {red_payload_type} exceeds 127"
            )));
        }
        let payload = self
            .encode_packet(
                primary.header.payload_type,
                primary.header.timestamp,
                primary.payload.clone(),
            )?
            .marshal()?
            .freeze();
        let mut header = primary.header.clone();
        header.payload_type = red_payload_type;
        Ok(crate::packet::Packet { header, payload })
    }

    /// As [`encode_packet`](Self::encode_packet), marshalled.
    ///
    /// # Errors
    ///
    /// As [`encode_packet`](Self::encode_packet).
    pub fn encode(&mut self, payload_type: u8, timestamp: u32, payload: Bytes) -> Result<Bytes> {
        Ok(self
            .encode_packet(payload_type, timestamp, payload)?
            .marshal()?
            .freeze())
    }
}

/// A payload a [`RedDecoder`] delivers.
#[derive(PartialEq, Eq, Debug, Clone)]
pub struct RecoveredBlock {
    /// RTP timestamp of the data.
    pub timestamp: u32,
    /// Payload type of the data.
    pub payload_type: u8,
    /// The data: a standard RTP payload of `payload_type`.
    pub data: Bytes,
    /// `true` for the primary of the packet fed in, `false` for data recovered from a
    /// redundant block (whose marker bit is unknown).
    pub primary: bool,
}

/// A block [`RedDecoder::decode_rtp`] delivers, with what of the RED packet's header
/// applies to it (RFC 2198 section 4).
#[derive(PartialEq, Eq, Debug, Clone)]
pub struct RecoveredMedia {
    /// The block.
    pub block: RecoveredBlock,
    /// The marker bit: the RED packet's for its primary; `false` for recovered data, whose
    /// marker "is lost" with its packet.
    pub marker: bool,
    /// The CSRC list of the RED packet, which "should be applied to the reconstructed
    /// redundant data" as to the primary.
    pub csrc: Vec<u32>,
}

/// The default number of recent deliveries a [`RedDecoder`] remembers.
pub const RED_DEFAULT_DUPLICATE_WINDOW: usize = 64;
/// The largest duplicate window a [`RedDecoder`] accepts.
pub const RED_MAX_DUPLICATE_WINDOW: usize = 1024;

/// Unpacks RED packets and recovers lost primaries from later packets' redundant blocks
/// (RFC 2198 section 3), without delivering anything twice.
///
/// Each [`decode`](Self::decode) returns, in timestamp order, the redundant blocks whose
/// timestamp was not delivered yet, then the packet's primary (unless the same sequence
/// number, or a timestamp already recovered, was delivered). It remembers the last `window`
/// sequence numbers and timestamps it delivered; older duplicates can come through again.
///
/// The decoder exposes nothing of the RTP header for recovered data (section 4): its marker
/// bit was lost with the primary, and the RED packet's CSRC list, which the caller has, is the
/// one to apply to it.
#[derive(Debug, Clone)]
pub struct RedDecoder {
    window: usize,
    sequence_numbers: VecDeque<u16>,
    /// Delivered timestamps, and whether each was a recovery.
    timestamps: VecDeque<(u32, bool)>,
}

impl Default for RedDecoder {
    fn default() -> Self {
        Self::new(RED_DEFAULT_DUPLICATE_WINDOW)
    }
}

impl RedDecoder {
    /// A decoder remembering the last `window` deliveries (1 to
    /// [`RED_MAX_DUPLICATE_WINDOW`]; out-of-range values are clamped).
    pub fn new(window: usize) -> Self {
        let window = window.clamp(1, RED_MAX_DUPLICATE_WINDOW);
        RedDecoder {
            window,
            sequence_numbers: VecDeque::with_capacity(window),
            timestamps: VecDeque::with_capacity(window),
        }
    }

    /// Decodes one RED packet with RTP `sequence_number` and `timestamp`.
    ///
    /// The primary is matched against earlier primaries by sequence number (several packets
    /// may share a timestamp) and against recoveries by timestamp; a redundant block is
    /// matched against everything delivered by timestamp.
    ///
    /// # Errors
    ///
    /// Fails on a malformed payload (see [`RedPacket::parse`]); state is unchanged then.
    pub fn decode(
        &mut self,
        sequence_number: u16,
        timestamp: u32,
        payload: &Bytes,
    ) -> Result<Vec<RecoveredBlock>> {
        let packet = RedPacket::parse(payload)?;
        let mut out = Vec::with_capacity(packet.blocks.len());

        let mut redundant: Vec<&RedBlock> = packet
            .redundant()
            .iter()
            .filter(|b| b.timestamp_offset != 0)
            .collect();
        // Oldest first: largest offset first; stable for equal offsets.
        redundant.sort_by_key(|b| std::cmp::Reverse(b.timestamp_offset));
        for block in redundant {
            let ts = block.timestamp(timestamp);
            if self.timestamps.iter().any(|(t, _)| *t == ts) {
                continue;
            }
            self.remember_timestamp(ts, true);
            out.push(RecoveredBlock {
                timestamp: ts,
                payload_type: block.payload_type,
                data: block.data.clone(),
                primary: false,
            });
        }

        let primary = packet.primary();
        let seen_sequence = self.sequence_numbers.contains(&sequence_number);
        let recovered_before = self.timestamps.iter().any(|(t, r)| *r && *t == timestamp);
        if !seen_sequence && !recovered_before {
            if self.sequence_numbers.len() == self.window {
                self.sequence_numbers.pop_front();
            }
            self.sequence_numbers.push_back(sequence_number);
            self.remember_timestamp(timestamp, false);
            out.push(RecoveredBlock {
                timestamp,
                payload_type: primary.payload_type,
                data: primary.data.clone(),
                primary: true,
            });
        }
        Ok(out)
    }

    /// [`decode`](Self::decode) of a RED RTP packet, each block with the marker bit and the
    /// CSRC list section 4 gives it.
    ///
    /// # Errors
    ///
    /// As [`decode`](Self::decode).
    pub fn decode_rtp(&mut self, packet: &crate::packet::Packet) -> Result<Vec<RecoveredMedia>> {
        let header = &packet.header;
        Ok(self
            .decode(header.sequence_number, header.timestamp, &packet.payload)?
            .into_iter()
            .map(|block| RecoveredMedia {
                marker: block.primary && header.marker,
                csrc: header.csrc.clone(),
                block,
            })
            .collect())
    }

    fn remember_timestamp(&mut self, timestamp: u32, recovered: bool) {
        if self.timestamps.len() == self.window {
            self.timestamps.pop_front();
        }
        self.timestamps.push_back((timestamp, recovered));
    }
}

/// Returns a RED payload's primary data, for audio streams whose RED payload type is
/// depacketized like a codec. Redundant blocks are dropped; use [`RedDecoder`] to recover from
/// them.
#[derive(PartialEq, Eq, Debug, Default, Clone)]
pub struct RedDepacketizer;

impl Depacketizer for RedDepacketizer {
    fn depacketize(&mut self, packet: &Bytes) -> Result<Bytes> {
        Ok(RedPacket::parse(packet)?.primary().data.clone())
    }

    fn is_partition_head(&self, _payload: &Bytes) -> bool {
        true
    }

    fn is_partition_tail(&self, _marker: bool, _payload: &Bytes) -> bool {
        true
    }
}

/// Parses the RED fmtp list, `a=fmtp:<pt> 111/111` (section 5): the payload types of the
/// primary and then the redundant encodings, slash-separated.
///
/// # Errors
///
/// Fails on an empty list or entry, a non-decimal entry, a payload type above 127, or more
/// than [`RED_MAX_BLOCKS`] entries.
pub fn parse_red_fmtp(fmtp: &str) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    for entry in fmtp.split('/') {
        if out.len() == RED_MAX_BLOCKS {
            return Err(Error::Other(format!(
                "RED fmtp lists more than {RED_MAX_BLOCKS} encodings"
            )));
        }
        if entry.is_empty() || entry.len() > 3 || !entry.bytes().all(|b| b.is_ascii_digit()) {
            return Err(Error::Other(format!("invalid RED fmtp entry {entry:?}")));
        }
        let pt: u8 = entry
            .parse()
            .map_err(|_| Error::Other(format!("invalid RED fmtp entry {entry:?}")))?;
        if pt > RED_MAX_PAYLOAD_TYPE {
            return Err(Error::Other(format!(
                "RED fmtp payload type {pt} exceeds 127"
            )));
        }
        out.push(pt);
    }
    Ok(out)
}

/// Formats a RED fmtp list: payload types joined by `/`.
pub fn format_red_fmtp(payload_types: &[u8]) -> String {
    payload_types
        .iter()
        .map(|pt| pt.to_string())
        .collect::<Vec<_>>()
        .join("/")
}
