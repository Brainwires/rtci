//! Layer Refresh Request (LRR, RFC 9627 §3).
//!
//! A receiver of a scalable stream asks the encoder for a layer refresh point: a picture from
//! which a temporal or spatial layer can be decoded without the pictures of that layer before
//! it. VP9 and AV1 (AV1 RTP specification §8.2) use it to switch layers up without a full key
//! frame.
use crate::{header::*, packet::*, util::*};
use shared::{
    error::{Error, Result},
    marshal::{Marshal, MarshalSize, Unmarshal},
};

use bytes::{Buf, BufMut};
use std::fmt;

const LRR_ENTRY_LENGTH: usize = 12;
const LRR_PAYLOAD_TYPE_MAX: u8 = 0x7f;
const LRR_TEMPORAL_ID_MAX: u8 = 0x07;

/// The layers a receiver decodes at the time of the request.
#[derive(Debug, PartialEq, Eq, Default, Clone, Copy)]
pub struct LrrCurrentLayer {
    /// The current temporal layer ID (CTID), 3 bits.
    pub temporal_layer_id: u8,
    /// The current layer ID (CLID), as the codec's payload format maps its layer ID to 8 bits.
    pub layer_id: u8,
}

/// One FCI entry of an LRR.
///
/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                              SSRC                             |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// | Seq nr.       |C| Payload Type| Reserved                      |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// | RES     | TTID| TLID          | RES     | CTID| CLID          |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[derive(Debug, PartialEq, Eq, Default, Clone, Copy)]
pub struct LrrEntry {
    /// The media sender asked for the refresh.
    pub ssrc: u32,
    /// The request's sequence number: it goes up with each new request, a repetition keeps it.
    pub sequence_number: u8,
    /// The RTP payload type the layer IDs are to be read with, 7 bits.
    pub payload_type: u8,
    /// The target temporal layer ID (TTID), 3 bits.
    pub target_temporal_layer_id: u8,
    /// The target layer ID (TLID), as the codec's payload format maps its layer ID to 8 bits.
    pub target_layer_id: u8,
    /// The layers decoded now, when the receiver says (the C bit). With it the encoder may
    /// refresh only the layers between the current and the target one.
    pub current: Option<LrrCurrentLayer>,
}

/// Layer Refresh Request (LRR, PSFB FMT=10).
#[derive(Debug, PartialEq, Eq, Default, Clone)]
pub struct LayerRefreshRequest {
    /// The source that makes the request.
    pub sender_ssrc: u32,
    /// At least one entry.
    pub entries: Vec<LrrEntry>,
}

impl fmt::Display for LayerRefreshRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "LayerRefreshRequest {:x}", self.sender_ssrc)?;
        for e in &self.entries {
            write!(
                f,
                " ({:x} {} pt={} t={} l={})",
                e.ssrc,
                e.sequence_number,
                e.payload_type,
                e.target_temporal_layer_id,
                e.target_layer_id
            )?;
        }
        Ok(())
    }
}

impl Packet for LayerRefreshRequest {
    fn header(&self) -> Header {
        Header {
            padding: false,
            count: FORMAT_LRR,
            packet_type: PacketType::PayloadSpecificFeedback,
            length: ((self.marshal_size() / 4) - 1) as u16,
        }
    }

    fn destination_ssrc(&self) -> Vec<u32> {
        self.entries.iter().map(|e| e.ssrc).collect()
    }

    fn raw_size(&self) -> usize {
        HEADER_LENGTH + FEEDBACK_SSRCS_LENGTH + self.entries.len() * LRR_ENTRY_LENGTH
    }

    packet_any!(LayerRefreshRequest);
}

impl MarshalSize for LayerRefreshRequest {
    fn marshal_size(&self) -> usize {
        self.raw_size()
    }
}

impl Marshal for LayerRefreshRequest {
    fn marshal_to(&self, buf: &mut [u8]) -> Result<usize> {
        // The FCI contains one or more entries.
        if self.entries.is_empty() {
            return Err(Error::PacketTooShort);
        }
        for e in &self.entries {
            if e.payload_type > LRR_PAYLOAD_TYPE_MAX {
                return Err(Error::WrongPayloadType);
            }
            if e.target_temporal_layer_id > LRR_TEMPORAL_ID_MAX
                || e.current
                    .is_some_and(|c| c.temporal_layer_id > LRR_TEMPORAL_ID_MAX)
            {
                return Err(Error::InvalidHeader);
            }
        }

        let size = self.raw_size();
        // As for FIR, the "SSRC of media source" is not used and is 0.
        let mut buf = put_feedback_start(
            buf,
            PacketType::PayloadSpecificFeedback,
            FORMAT_LRR,
            size,
            self.sender_ssrc,
            0,
        )?;
        for e in &self.entries {
            buf.put_u32(e.ssrc);
            buf.put_u8(e.sequence_number);
            buf.put_u8(((e.current.is_some() as u8) << 7) | e.payload_type);
            buf.put_u16(0); // reserved
            buf.put_u8(e.target_temporal_layer_id);
            buf.put_u8(e.target_layer_id);
            // Without the C bit the current layer fields are zero.
            let current = e.current.unwrap_or_default();
            buf.put_u8(current.temporal_layer_id);
            buf.put_u8(current.layer_id);
        }
        Ok(size)
    }
}

impl Unmarshal for LayerRefreshRequest {
    fn unmarshal<B>(raw_packet: &mut B) -> Result<Self>
    where
        Self: Sized,
        B: Buf,
    {
        let (sender_ssrc, _media_ssrc, mut fci) =
            read_feedback(raw_packet, PacketType::PayloadSpecificFeedback, FORMAT_LRR)?;
        if fci.is_empty() {
            return Err(Error::PacketTooShort);
        }
        if !fci.len().is_multiple_of(LRR_ENTRY_LENGTH) {
            return Err(Error::InvalidHeader);
        }

        let mut entries = Vec::with_capacity(fci.len() / LRR_ENTRY_LENGTH);
        while fci.has_remaining() {
            let ssrc = fci.get_u32();
            let sequence_number = fci.get_u8();
            let c_and_payload_type = fci.get_u8();
            fci.advance(2); // reserved, ignored
            let target_temporal_layer_id = fci.get_u8() & LRR_TEMPORAL_ID_MAX;
            let target_layer_id = fci.get_u8();
            let current_temporal_layer_id = fci.get_u8() & LRR_TEMPORAL_ID_MAX;
            let current_layer_id = fci.get_u8();
            entries.push(LrrEntry {
                ssrc,
                sequence_number,
                payload_type: c_and_payload_type & LRR_PAYLOAD_TYPE_MAX,
                target_temporal_layer_id,
                target_layer_id,
                // Without the C bit the current layer fields are ignored.
                current: (c_and_payload_type & 0x80 != 0).then_some(LrrCurrentLayer {
                    temporal_layer_id: current_temporal_layer_id,
                    layer_id: current_layer_id,
                }),
            });
        }

        Ok(LayerRefreshRequest {
            sender_ssrc,
            entries,
        })
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use bytes::Bytes;

    #[test]
    fn lrr_round_trips_with_and_without_the_current_layer() {
        let lrr = LayerRefreshRequest {
            sender_ssrc: 0x01020304,
            entries: vec![
                LrrEntry {
                    ssrc: 0x0a0b0c0d,
                    sequence_number: 3,
                    payload_type: 98,
                    target_temporal_layer_id: 2,
                    target_layer_id: 0x21,
                    current: Some(LrrCurrentLayer {
                        temporal_layer_id: 1,
                        layer_id: 0x10,
                    }),
                },
                LrrEntry {
                    ssrc: 0x0a0b0c0e,
                    sequence_number: 4,
                    payload_type: 98,
                    target_temporal_layer_id: 0,
                    target_layer_id: 1,
                    current: None,
                },
            ],
        };
        let raw = lrr.marshal().unwrap();
        assert_eq!(
            &[
                0x8a, 0xce, 0x00, 0x08, // v=2, FMT=10, PSFB, len=8
                0x01, 0x02, 0x03, 0x04, // sender
                0x00, 0x00, 0x00, 0x00, // media source: not used, zero
                0x0a, 0x0b, 0x0c, 0x0d, 0x03, 0xe2, 0x00, 0x00, // seq 3, C=1, pt 98
                0x02, 0x21, 0x01, 0x10, // TTID 2, TLID 0x21, CTID 1, CLID 0x10
                0x0a, 0x0b, 0x0c, 0x0e, 0x04, 0x62, 0x00, 0x00, // seq 4, C=0, pt 98
                0x00, 0x01, 0x00, 0x00,
            ][..],
            &raw[..]
        );
        assert_eq!(
            lrr,
            LayerRefreshRequest::unmarshal(&mut raw.freeze()).unwrap()
        );
        assert_eq!(vec![0x0a0b0c0d, 0x0a0b0c0e], lrr.destination_ssrc());
    }

    #[test]
    fn reserved_bits_and_an_unflagged_current_layer_are_ignored() {
        let mut raw = Bytes::from_static(&[
            0x8a, 0xce, 0x00, 0x05, 0, 0, 0, 1, 9, 9, 9, 9, // media ssrc is not used
            0, 0, 0, 2, 0x07, 0x60, 0xff, 0xff, // C=0, reserved all ones
            0xfa, 0x05, 0xff, 0xff, // RES ones, TTID 2; CTID / CLID set although C=0
        ]);
        let lrr = LayerRefreshRequest::unmarshal(&mut raw).unwrap();
        assert_eq!(
            vec![LrrEntry {
                ssrc: 2,
                sequence_number: 7,
                payload_type: 96,
                target_temporal_layer_id: 2,
                target_layer_id: 5,
                current: None,
            }],
            lrr.entries
        );
    }

    #[test]
    fn malformed_requests_are_refused() {
        assert_eq!(
            Err(Error::PacketTooShort),
            LayerRefreshRequest::default().marshal()
        );
        let bad_tid = LayerRefreshRequest {
            sender_ssrc: 1,
            entries: vec![LrrEntry {
                target_temporal_layer_id: 8,
                ..Default::default()
            }],
        };
        assert_eq!(Err(Error::InvalidHeader), bad_tid.marshal());
        let bad_pt = LayerRefreshRequest {
            sender_ssrc: 1,
            entries: vec![LrrEntry {
                payload_type: 128,
                ..Default::default()
            }],
        };
        assert_eq!(Err(Error::WrongPayloadType), bad_pt.marshal());

        let mut none = Bytes::from_static(&[0x8a, 0xce, 0, 2, 0, 0, 0, 1, 0, 0, 0, 0]);
        assert_eq!(
            Err(Error::PacketTooShort),
            LayerRefreshRequest::unmarshal(&mut none)
        );
        let mut short = Bytes::from_static(&[
            0x8a, 0xce, 0, 4, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 2, 1, 96, 0, 0,
        ]);
        assert_eq!(
            Err(Error::InvalidHeader),
            LayerRefreshRequest::unmarshal(&mut short)
        );
    }
}
