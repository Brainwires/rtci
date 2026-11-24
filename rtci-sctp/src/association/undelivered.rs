//! The user messages an association that ended did not deliver: RFC 9260 section 8.1 ("the
//! endpoint SHOULD report the failure to the upper layer and optionally report back all
//! outstanding user data remaining in its outbound queue"), the SEND FAILURE notification
//! (11.2.2) and the Receive Unsent / Receive Unacknowledged Message primitives (11.1.14,
//! 11.1.15).

use crate::chunk::chunk_payload_data::{ChunkPayloadData, MessageId, PayloadProtocolIdentifier};
use bytes::{Bytes, BytesMut};
use rustc_hash::FxHashMap;

/// Whether any of an undelivered message left this side (RFC 9260 11.2.2, "mode").
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum UndeliveredMode {
    /// No part of the message was ever sent (RECEIVE_UNSENT, RFC 9260 11.1.14).
    Unsent,
    /// At least part of the message was sent and it is not completely acknowledged
    /// (RECEIVE_UNACKED, RFC 9260 11.1.15).
    Unacknowledged,
}

/// A user message an association did not deliver, handed back by
/// [`Association::take_undelivered_messages`](crate::Association::take_undelivered_messages)
/// once the association ended.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub struct UndeliveredMessage {
    /// The stream the message was written to.
    pub stream_identifier: u16,
    /// The Stream Sequence Number the message had (0 when it was never numbered).
    pub stream_sequence_number: u16,
    /// The Payload Protocol Identifier it was written with.
    pub payload_type: PayloadProtocolIdentifier,
    /// It was written unordered.
    pub unordered: bool,
    /// Unsent, or sent and not acknowledged.
    pub mode: UndeliveredMode,
    /// `data` is not the whole message: the peer acknowledged some of it, or some of it was
    /// sent before (RFC 9260 11.1.14 / 11.1.15 "partial flag").
    pub partial: bool,
    /// The bytes of the message that were not acknowledged, in order.
    pub data: Bytes,
}

impl UndeliveredMessage {
    /// Joins the fragments of one message that remain (in TSN or queue order). `acked`
    /// fragments (a Gap Ack Block covered them) leave a gap: the message is partial then.
    pub(crate) fn from_fragments(
        fragments: &[ChunkPayloadData],
        mode: UndeliveredMode,
    ) -> Option<Self> {
        let first = fragments.first()?;
        let last = fragments.last()?;
        let mut data = BytesMut::new();
        let mut partial = !first.beginning_fragment || !last.ending_fragment;
        for c in fragments {
            if c.acknowledged {
                partial = true;
            } else {
                data.extend_from_slice(&c.user_data);
            }
        }
        Some(UndeliveredMessage {
            stream_identifier: first.stream_identifier,
            stream_sequence_number: first.stream_sequence_number,
            payload_type: first.payload_type,
            unordered: first.unordered,
            mode,
            partial,
            data: data.freeze(),
        })
    }
}

/// Turns the chunks an ended association holds into messages: `sent` chunks (in TSN order)
/// first, then `unsent` messages (in the order written). The fragments of one message (its
/// local id) go together wherever they are, so the unsent tail of a part-sent message joins
/// its sent fragments; a message with a sent fragment is `Unacknowledged`. Abandoned chunks
/// (reported with `StreamEvent::MessageAbandoned` already) are left out.
pub(crate) fn undelivered_messages(
    sent: Vec<ChunkPayloadData>,
    unsent: Vec<Vec<ChunkPayloadData>>,
) -> Vec<UndeliveredMessage> {
    let mut groups: Vec<(Vec<ChunkPayloadData>, bool)> = Vec::new();
    let mut by_id: FxHashMap<MessageId, usize> = FxHashMap::default();
    let chunks = sent
        .into_iter()
        .map(|c| (c, true))
        .chain(unsent.into_iter().flatten().map(|c| (c, false)));
    for (c, was_sent) in chunks {
        if c.abandoned() {
            continue;
        }
        let index = match c.message_id {
            Some(id) => *by_id.entry(id).or_insert_with(|| {
                groups.push((Vec::new(), false));
                groups.len() - 1
            }),
            None => {
                groups.push((Vec::new(), false));
                groups.len() - 1
            }
        };
        groups[index].1 |= was_sent;
        groups[index].0.push(c);
    }
    groups
        .into_iter()
        .filter_map(|(fragments, was_sent)| {
            let mode = if was_sent {
                UndeliveredMode::Unacknowledged
            } else {
                UndeliveredMode::Unsent
            };
            UndeliveredMessage::from_fragments(&fragments, mode)
        })
        .collect()
}
