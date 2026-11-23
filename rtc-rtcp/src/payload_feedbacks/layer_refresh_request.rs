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

/// The VP9 layer index of an LRR (RFC 9628 section 5.3): the TID in the low three bits of the
/// temporal field and the SID in the low three bits of the layer field, the reserved bits 0.
const VP9_SID_MAX: u8 = 0x07;
/// AV1 uses the VP9 format "with the high order bit of its three-bit SID field set to 0" (AV1
/// RTP specification section 8.2): a two-bit spatial ID.
const AV1_SPATIAL_ID_MAX: u8 = 0x03;

impl LrrEntry {
    /// An entry for a VP9 stream (RFC 9628 section 5.3): target and, when the receiver says,
    /// current temporal and spatial layer IDs. A TID or SID over 7 is refused.
    pub fn vp9(
        ssrc: u32,
        sequence_number: u8,
        payload_type: u8,
        target: (u8, u8),
        current: Option<(u8, u8)>,
    ) -> Result<Self> {
        Self::layered(
            ssrc,
            sequence_number,
            payload_type,
            target,
            current,
            VP9_SID_MAX,
        )
    }

    /// An entry for an AV1 stream (AV1 RTP specification section 8.2): `temporal_id` and
    /// `spatial_id` as the bitstream has them, in the VP9 format with the high bit of the SID
    /// 0. A spatial ID over 3 or a temporal ID over 7 is refused.
    pub fn av1(
        ssrc: u32,
        sequence_number: u8,
        payload_type: u8,
        target: (u8, u8),
        current: Option<(u8, u8)>,
    ) -> Result<Self> {
        Self::layered(
            ssrc,
            sequence_number,
            payload_type,
            target,
            current,
            AV1_SPATIAL_ID_MAX,
        )
    }

    fn layered(
        ssrc: u32,
        sequence_number: u8,
        payload_type: u8,
        (target_temporal, target_spatial): (u8, u8),
        current: Option<(u8, u8)>,
        spatial_max: u8,
    ) -> Result<Self> {
        let layers = std::iter::once((target_temporal, target_spatial)).chain(current);
        for (temporal, spatial) in layers {
            if temporal > LRR_TEMPORAL_ID_MAX || spatial > spatial_max {
                return Err(Error::InvalidHeader);
            }
        }
        if payload_type > LRR_PAYLOAD_TYPE_MAX {
            return Err(Error::WrongPayloadType);
        }
        Ok(LrrEntry {
            ssrc,
            sequence_number,
            payload_type,
            target_temporal_layer_id: target_temporal,
            target_layer_id: target_spatial,
            current: current.map(|(temporal, spatial)| LrrCurrentLayer {
                temporal_layer_id: temporal,
                layer_id: spatial,
            }),
        })
    }

    /// The target spatial ID of a VP9 or AV1 entry: the SID bits of the layer field, the
    /// reserved bits ignored (RFC 9628 section 5.3).
    pub fn target_spatial_id(&self) -> u8 {
        self.target_layer_id & VP9_SID_MAX
    }
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

    /// AV1 RTP specification section 8.2: "AV1 streams MUST use the Layer Refresh Request
    /// format defined for VP9 in Section 5.3 of [VP9], with the high order bit of its
    /// three-bit SID field set to 0": TID in the low three bits of the temporal octet, SID in
    /// the low two of the layer octet, the rest zero; a spatial ID that needs the high bit is
    /// refused for AV1 and allowed for VP9.
    #[test]
    fn an_av1_layer_refresh_request_uses_the_vp9_format_with_a_two_bit_sid() {
        let entry = LrrEntry::av1(0x0a0b_0c0d, 7, 45, (2, 3), Some((1, 1))).unwrap();
        let lrr = LayerRefreshRequest {
            sender_ssrc: 0x0102_0304,
            entries: vec![entry],
        };
        let raw = lrr.marshal().unwrap();
        // The FCI after the 12 octets of the feedback header: SSRC, seq, C|PT, reserved, then
        // RES|TTID, TLID, RES|CTID, CLID.
        assert_eq!(
            &raw[12..24],
            &[0x0a, 0x0b, 0x0c, 0x0d, 7, 0x80 | 45, 0, 0, 2, 3, 1, 1]
        );
        let read = LayerRefreshRequest::unmarshal(&mut raw.freeze()).unwrap();
        assert_eq!(3, read.entries[0].target_spatial_id());
        assert_eq!(2, read.entries[0].target_temporal_layer_id);

        assert!(
            LrrEntry::av1(1, 0, 45, (0, 4), None).is_err(),
            "SID high bit set"
        );
        assert!(LrrEntry::av1(1, 0, 45, (8, 0), None).is_err());
        assert!(
            LrrEntry::vp9(1, 0, 98, (0, 4), None).is_ok(),
            "VP9 has three SID bits"
        );
        assert!(LrrEntry::vp9(1, 0, 98, (0, 8), None).is_err());
    }

    /// RFC 9628 section 5.3: for VP9 the layer ID of an LRR is the spatial layer (SID, three
    /// bits) and the temporal layer ID the TID: a request for spatial layer 5, temporal layer
    /// 2, from layer 3 / 1, reads back as such; a SID or TID over 7 is refused.
    #[test]
    fn a_vp9_layer_refresh_request_names_the_spatial_and_temporal_layers() {
        let entry = LrrEntry::vp9(0x0a0b0c0d, 1, 98, (2, 5), Some((1, 3))).unwrap();
        let lrr = LayerRefreshRequest {
            sender_ssrc: 1,
            entries: vec![entry],
        };
        let raw = lrr.marshal().unwrap();
        assert_eq!(&[0x02, 0x05, 0x01, 0x03][..], &raw[20..24]);
        let read = LayerRefreshRequest::unmarshal(&mut raw.freeze()).unwrap();
        assert_eq!(5, read.entries[0].target_spatial_id());
        assert_eq!(2, read.entries[0].target_temporal_layer_id);
        assert!(LrrEntry::vp9(1, 1, 98, (2, 8), None).is_err());
        assert!(LrrEntry::vp9(1, 1, 98, (8, 0), None).is_err());
    }

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
