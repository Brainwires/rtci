use super::{chunk_header::*, chunk_type::*, *};

use bytes::{Buf, BufMut, Bytes, BytesMut};
use std::fmt;
use std::num::NonZeroU64;
use std::time::Instant;

pub(crate) const PAYLOAD_DATA_ENDING_FRAGMENT_BITMASK: u8 = 1;
pub(crate) const PAYLOAD_DATA_BEGINING_FRAGMENT_BITMASK: u8 = 2;
pub(crate) const PAYLOAD_DATA_UNORDERED_BITMASK: u8 = 4;
pub(crate) const PAYLOAD_DATA_IMMEDIATE_SACK: u8 = 8;
pub(crate) const PAYLOAD_DATA_HEADER_SIZE: usize = 12;
/// What follows the chunk header of an I-DATA chunk before the user data (RFC 8260 2.1): TSN,
/// Stream Identifier, Reserved, Message Identifier, and the PPID or the Fragment Sequence
/// Number.
pub(crate) const I_DATA_HEADER_SIZE: usize = 16;

/// PayloadProtocolIdentifier is an enum for DataChannel payload types
/// PayloadProtocolIdentifier enums
/// <https://www.iana.org/assignments/sctp-parameters/sctp-parameters.xhtml#sctp-parameters-25>
#[derive(Default, Debug, Copy, Clone, PartialEq)]
#[repr(C)]
#[non_exhaustive]
pub enum PayloadProtocolIdentifier {
    /// `WebRTC DCEP` (50): a Data Channel Establishment Protocol control message.
    Dcep = 50,
    /// `WebRTC String` (51): a non-empty UTF-8 string message.
    String = 51,
    /// `WebRTC Binary` (53): a non-empty binary message.
    Binary = 53,
    /// `WebRTC String Empty` (56): an empty string message.
    ///
    /// Needed because SCTP cannot carry a zero-length payload.
    StringEmpty = 56,
    /// `WebRTC Binary Empty` (57): an empty binary message.
    BinaryEmpty = 57,
    #[default]
    /// An identifier this crate does not recognise.
    Unknown,
}

impl fmt::Display for PayloadProtocolIdentifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match *self {
            PayloadProtocolIdentifier::Dcep => "WebRTC DCEP",
            PayloadProtocolIdentifier::String => "WebRTC String",
            PayloadProtocolIdentifier::Binary => "WebRTC Binary",
            PayloadProtocolIdentifier::StringEmpty => "WebRTC String (Empty)",
            PayloadProtocolIdentifier::BinaryEmpty => "WebRTC Binary (Empty)",
            _ => "Unknown Payload Protocol Identifier",
        };
        write!(f, "{}", s)
    }
}

impl PayloadProtocolIdentifier {
    /// The identifier's number on the wire. `Unknown` is 0, "not specified by the upper
    /// layer" (RFC 9260 3.3.1); a value without a name is sent with
    /// [`Stream::write_sctp_with_ppid`](crate::Stream::write_sctp_with_ppid).
    pub fn number(self) -> u32 {
        match self {
            PayloadProtocolIdentifier::Unknown => 0,
            named => named as u32,
        }
    }
}

impl From<u32> for PayloadProtocolIdentifier {
    fn from(v: u32) -> PayloadProtocolIdentifier {
        match v {
            50 => PayloadProtocolIdentifier::Dcep,
            51 => PayloadProtocolIdentifier::String,
            53 => PayloadProtocolIdentifier::Binary,
            56 => PayloadProtocolIdentifier::StringEmpty,
            57 => PayloadProtocolIdentifier::BinaryEmpty,
            _ => PayloadProtocolIdentifier::Unknown,
        }
    }
}

/// Association-local identity, unrelated to TSN, SSN, SID reuse or time.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
pub(crate) struct MessageId(NonZeroU64);

impl MessageId {
    /// Encode a zero-based association sequence with a niche for decoded DATA,
    /// which has no local identity. Option<MessageId> stays one machine word.
    /// Returns None when the sequence is exhausted.
    pub(crate) fn new(sequence: u64) -> Option<Self> {
        NonZeroU64::new(sequence.checked_add(1)?).map(Self)
    }
}

/// Sender policy captured once per message and copied to every fragment.
/// It remains valid after stream reset, SID reuse, or later policy changes.
#[derive(Debug, Default, Copy, Clone)]
pub(crate) enum MessageReliability {
    #[default]
    Reliable,
    Rexmit {
        max_retransmits: u32,
    },
    Timed {
        deadline: Instant,
    },
}

impl MessageReliability {
    pub(crate) fn deadline(self) -> Option<Instant> {
        match self {
            Self::Timed { deadline } => Some(deadline),
            _ => None,
        }
    }
}

/// ChunkPayloadData represents an SCTP Chunk of type DATA
//
// 0                   1                   2                   3
// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//|   Type = 0    | Reserved|U|B|E|    Length                     |
//+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//|                              TSN                              |
//+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//|      Stream Identifier S      |   Stream Sequence Number n    |
//+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//|                  Payload Protocol Identifier                  |
//+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//|                                                               |
//|                 User Data (seq n of Stream S)                 |
//|                                                               |
//+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
//
//An unfragmented user message shall have both the B and E bits set to
//'1'.  Setting both B and E bits to '0' indicates a middle fragment of
//a multi-fragment user message, as summarized in the following table:
//   B E                  Description
//============================================================
//|  1 0 | First piece of a fragmented user message          |
//+----------------------------------------------------------+
//|  0 0 | Middle piece of a fragmented user message         |
//+----------------------------------------------------------+
//|  0 1 | Last piece of a fragmented user message           |
//+----------------------------------------------------------+
//|  1 1 | Unfragmented message                              |
//============================================================
//|             Table 1: Fragment Description Flags          |
//============================================================
#[derive(Debug, Clone)]
pub struct ChunkPayloadData {
    pub(crate) unordered: bool,
    pub(crate) beginning_fragment: bool,
    pub(crate) ending_fragment: bool,
    pub(crate) immediate_sack: bool,

    pub(crate) tsn: u32,
    pub(crate) stream_identifier: u16,
    pub(crate) stream_sequence_number: u16,
    pub(crate) payload_type: PayloadProtocolIdentifier,
    /// The Payload Protocol Identifier as a number, used when `payload_type` has no name for
    /// it (`Unknown`): RFC 9260 3.3.1 passes any value through unchanged.
    pub(crate) payload_protocol_id: u32,
    pub(crate) user_data: Bytes,

    /// This is an I-DATA chunk (RFC 8260 2.1), used when user message interleaving was
    /// negotiated: it carries `mid` and `fsn` in place of the Stream Sequence Number.
    pub(crate) i_data: bool,
    /// The Message Identifier of an I-DATA chunk: counted per stream, separately for ordered
    /// and unordered messages.
    pub(crate) mid: u32,
    /// The Fragment Sequence Number of an I-DATA chunk: the place of this fragment in its
    /// message, from 0. On the wire only when the B bit is not set.
    pub(crate) fsn: u32,

    /// Acknowledged by a peer SACK, independently of local payload release.
    pub(crate) acknowledged: bool,
    pub(crate) miss_indicator: u32,

    /// Partial-reliability parameters used only by sender.
    ///
    /// Reassigned on every (re)transmission, so it is the RTT baseline. It is
    /// deliberately *not* the timed-reliability baseline: a message may wait in
    /// the pending queue for a long time before it is first transmitted, and
    /// `maxPacketLifeTime` has to cover that wait. See `created_at`.
    pub(crate) since: Option<Instant>,
    /// When the message this chunk belongs to was handed to the association.
    ///
    /// Set once, from the instant the caller passed to `Stream::write*`, and
    /// never reassigned. This is the baseline for `ReliabilityType::Timed`.
    pub(crate) created_at: Option<Instant>,
    /// Sender identity shared by every fragment; absent on decoded peer DATA.
    pub(crate) message_id: Option<MessageId>,
    /// Reliability belongs to the queued message, independently of its stream.
    pub(crate) reliability: MessageReliability,
    /// Identifies the stream incarnation whose send buffer owns this DATA.
    pub(crate) stream_generation: u64,
    /// number of transmission made for this chunk
    pub(crate) nsent: u32,

    /// This fragment belongs to an atomically abandoned message.
    pub(crate) abandoned: bool,

    /// Retransmission flag set when T1-RTX timeout occurred and this
    /// chunk is still in the inflight queue
    pub(crate) retransmit: bool,

    /// Marked for Fast Retransmit when the one packet of that Fast Retransmit was full (RFC
    /// 9260 7.2.4 step 5): not eligible for another, and retransmitted when cwnd allows.
    pub(crate) no_fast_retransmit: bool,
}

impl Default for ChunkPayloadData {
    fn default() -> Self {
        ChunkPayloadData {
            unordered: false,
            beginning_fragment: false,
            ending_fragment: false,
            immediate_sack: false,
            tsn: 0,
            stream_identifier: 0,
            stream_sequence_number: 0,
            payload_type: PayloadProtocolIdentifier::default(),
            payload_protocol_id: 0,
            user_data: Bytes::new(),
            i_data: false,
            mid: 0,
            fsn: 0,
            acknowledged: false,
            miss_indicator: 0,
            since: None,
            created_at: None,
            message_id: None,
            reliability: MessageReliability::Reliable,
            stream_generation: 0,
            nsent: 0,
            abandoned: false,
            retransmit: false,
            no_fast_retransmit: false,
        }
    }
}

/// makes chunkPayloadData printable
impl fmt::Display for ChunkPayloadData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}\n{}", self.header(), self.tsn)
    }
}

impl Chunk for ChunkPayloadData {
    fn header(&self) -> ChunkHeader {
        let mut flags: u8 = 0;
        if self.ending_fragment {
            flags = 1;
        }
        if self.beginning_fragment {
            flags |= 1 << 1;
        }
        if self.unordered {
            flags |= 1 << 2;
        }
        if self.immediate_sack {
            flags |= 1 << 3;
        }

        ChunkHeader {
            // RFC 8260 2.1: the four Res bits of an I-DATA chunk are sent as 0.
            typ: if self.i_data {
                CT_I_DATA
            } else {
                CT_PAYLOAD_DATA
            },
            flags,
            value_length: self.value_length() as u16,
        }
    }

    fn unmarshal(raw: &Bytes) -> Result<Self> {
        let header = ChunkHeader::unmarshal(raw)?;

        let i_data = header.typ == CT_I_DATA;
        if header.typ != CT_PAYLOAD_DATA && !i_data {
            return Err(Error::ErrChunkTypeNotPayloadData);
        }
        let fixed = if i_data {
            I_DATA_HEADER_SIZE
        } else {
            PAYLOAD_DATA_HEADER_SIZE
        };

        let immediate_sack = (header.flags & PAYLOAD_DATA_IMMEDIATE_SACK) != 0;
        let unordered = (header.flags & PAYLOAD_DATA_UNORDERED_BITMASK) != 0;
        let beginning_fragment = (header.flags & PAYLOAD_DATA_BEGINING_FRAGMENT_BITMASK) != 0;
        let ending_fragment = (header.flags & PAYLOAD_DATA_ENDING_FRAGMENT_BITMASK) != 0;

        if raw.len() < CHUNK_HEADER_SIZE + fixed {
            return Err(Error::ErrChunkPayloadSmall);
        }

        if header.value_length() < fixed {
            return Err(Error::ErrChunkUnmarshalPayloadData);
        }

        let reader = &mut raw.slice(CHUNK_HEADER_SIZE..CHUNK_HEADER_SIZE + header.value_length());

        let tsn = reader.get_u32();
        let stream_identifier = reader.get_u16();
        // RFC 8260 2.1: an I-DATA chunk has a Reserved field here, ignored on receipt.
        let stream_sequence_number = if i_data {
            reader.advance(2);
            0
        } else {
            reader.get_u16()
        };
        let mid = if i_data { reader.get_u32() } else { 0 };
        // The last field of an I-DATA chunk is the PPID in the first fragment (whose FSN is
        // 0) and the FSN in the others.
        let ppid_or_fsn = reader.get_u32();
        let (payload_protocol_id, fsn) = if i_data && !beginning_fragment {
            (0, ppid_or_fsn)
        } else {
            (ppid_or_fsn, 0)
        };
        let payload_type: PayloadProtocolIdentifier = payload_protocol_id.into();
        let user_data =
            raw.slice(CHUNK_HEADER_SIZE + fixed..CHUNK_HEADER_SIZE + header.value_length());

        Ok(ChunkPayloadData {
            unordered,
            beginning_fragment,
            ending_fragment,
            immediate_sack,
            tsn,
            stream_identifier,
            stream_sequence_number,
            payload_type,
            payload_protocol_id,
            user_data,
            i_data,
            mid,
            fsn,

            acknowledged: false,
            miss_indicator: 0,
            since: None,
            created_at: None,
            message_id: None,
            reliability: MessageReliability::Reliable,
            stream_generation: 0,
            nsent: 0,
            abandoned: false,
            retransmit: false,
            no_fast_retransmit: false,
        })
    }

    fn marshal_to(&self, writer: &mut BytesMut) -> Result<usize> {
        self.header().marshal_to(writer)?;

        writer.put_u32(self.tsn);
        writer.put_u16(self.stream_identifier);
        if self.i_data {
            // Reserved: 0 on send.
            writer.put_u16(0);
            writer.put_u32(self.mid);
            writer.put_u32(if self.beginning_fragment {
                self.ppid()
            } else {
                self.fsn
            });
        } else {
            writer.put_u16(self.stream_sequence_number);
            writer.put_u32(self.ppid());
        }
        // NB: `extend(Bytes)` iterates the payload one byte at a time (Bytes is
        // `IntoIterator<Item = u8>`); `extend_from_slice` does a single bulk copy.
        writer.extend_from_slice(&self.user_data);

        Ok(writer.len())
    }

    fn check(&self) -> Result<()> {
        Ok(())
    }

    fn value_length(&self) -> usize {
        self.header_size() - CHUNK_HEADER_SIZE + self.user_data.len()
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl ChunkPayloadData {
    /// The Payload Protocol Identifier on the wire: the named value, or the number given for
    /// one that has no name.
    pub fn ppid(&self) -> u32 {
        match self.payload_type {
            PayloadProtocolIdentifier::Unknown => self.payload_protocol_id,
            named => named.number(),
        }
    }

    /// The size of the chunk without its user data: 16 bytes for DATA, 20 for I-DATA.
    pub(crate) fn header_size(&self) -> usize {
        CHUNK_HEADER_SIZE
            + if self.i_data {
                I_DATA_HEADER_SIZE
            } else {
                PAYLOAD_DATA_HEADER_SIZE
            }
    }

    /// The size of the chunk on the wire, padding included.
    pub(crate) fn wire_size(&self) -> usize {
        (self.header_size() + self.user_data.len()).next_multiple_of(4)
    }

    pub(crate) fn abandoned(&self) -> bool {
        self.abandoned
    }

    pub(crate) fn is_outstanding(&self) -> bool {
        !self.acknowledged && !self.abandoned
    }

    pub(crate) fn is_fast_retransmit_candidate(&self) -> bool {
        self.is_outstanding()
            && self.nsent == 1
            && self.miss_indicator >= 3
            && !self.no_fast_retransmit
    }

    /// Record peer progress without changing payload ownership.
    pub(crate) fn acknowledge(&mut self) -> bool {
        let newly_acknowledged = !self.acknowledged;
        self.acknowledged = true;
        self.retransmit = false;
        newly_acknowledged
    }

    pub(crate) fn mark_abandoned(&mut self) {
        self.abandoned = true;
        self.retransmit = false;
    }
}
