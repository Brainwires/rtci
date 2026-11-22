//! User message interleaving (RFC 8260 section 2): the negotiation of I-DATA, and
//! I-FORWARD-TSN, which takes the place of FORWARD TSN on an association that uses it.

use super::*;
use crate::chunk::chunk_i_forward_tsn::{
    ChunkIForwardTsn, ChunkIForwardTsnStream, I_FORWARD_TSN_STREAM_LENGTH,
};
use crate::chunk::chunk_payload_data::{I_DATA_HEADER_SIZE, PAYLOAD_DATA_HEADER_SIZE};

impl Association {
    /// Whether user message interleaving (RFC 8260) is in use: both sides announced the
    /// I-DATA chunk. `false` while the association is being set up.
    pub fn message_interleaving(&self) -> bool {
        self.use_interleaving
    }

    /// RFC 8260 2.2.1: user message interleaving is negotiated when both endpoints listed
    /// the I-DATA chunk.
    pub(super) fn negotiated_interleaving(&self, params: &HandshakeParams) -> bool {
        self.interleaving_enabled && params.i_data
    }

    /// Whether PR-SCTP is used, by what the peer's INIT or INIT ACK said. RFC 3758 3.3.2,
    /// 3.3.3: both sides announced it, and the peer did not report this side's
    /// Forward-TSN-Supported parameter as unrecognized. RFC 8260 2.3.1: together with user
    /// message interleaving, only if both sides listed the I-FORWARD-TSN chunk as well.
    pub(super) fn negotiated_partial_reliability(&self, params: &HandshakeParams) -> bool {
        if !self.partial_reliability_enabled || params.forward_tsn_rejected {
            return false;
        }
        if self.negotiated_interleaving(params) {
            params.i_forward_tsn
        } else {
            params.forward_tsn
        }
    }

    /// Takes the outcome of the negotiation of user message interleaving.
    pub(super) fn set_interleaving(&mut self, interleaving: bool) {
        self.use_interleaving = interleaving;
        self.pending_queue.set_interleaving(interleaving);
        for s in self.streams.values_mut() {
            s.reassembly_queue.interleaved = interleaving;
        }
    }

    /// The most user data one DATA chunk carries: an I-DATA chunk's header is four bytes
    /// longer than a DATA chunk's (RFC 8260 2.1), and the packet is no larger.
    pub(crate) fn fragment_size(&self) -> u32 {
        if self.use_interleaving {
            self.max_payload_size
                .saturating_sub((I_DATA_HEADER_SIZE - PAYLOAD_DATA_HEADER_SIZE) as u32)
                .max(1)
        } else {
            self.max_payload_size
        }
    }

    /// The cumulative TSN part of a FORWARD TSN or I-FORWARD-TSN (RFC 3758 3.6): the peer's
    /// cumulative TSN moves to `new_cumulative_tsn`. Returns where it stood, or `None` when
    /// the chunk is out of date, in which case a SACK is sent.
    pub(super) fn forward_cumulative_tsn(&mut self, new_cumulative_tsn: u32) -> Option<u32> {
        if sna32lte(new_cumulative_tsn, self.peer_last_tsn) {
            trace!("[{}] sending ack on Forward TSN", self.side);
            self.ack_state = AckState::Immediate;
            self.timers.stop(Timer::Ack);
            self.awake_write_loop();
            return None;
        }
        // Advance peer_last_tsn. Drop only the chunks actually queued below the new point and
        // jump straight to it: stepping one TSN at a time let a FORWARD-TSN about 2^31 ahead
        // spin for billions of iterations.
        while let Some(&front) = self.payload_queue.sorted.front() {
            if !sna32lte(front, new_cumulative_tsn) || self.payload_queue.pop(front).is_none() {
                break;
            }
        }
        let prev_peer_last_tsn = self.peer_last_tsn;
        self.peer_last_tsn = new_cumulative_tsn;
        Some(prev_peer_last_tsn)
    }

    /// RFC 8260 2.3.1: an I-FORWARD-TSN chunk.
    pub(super) fn handle_i_forward_tsn(&mut self, c: &ChunkIForwardTsn) -> Result<Vec<Packet>> {
        trace!("[{}] I-FwdTSN: {}", self.side, c);

        if !self.use_interleaving || !self.use_forward_tsn {
            // "If I-FORWARD-TSN support has not been negotiated" the chunk is a violation.
            warn!(
                "[{}] I-FORWARD-TSN that was not negotiated: aborting",
                self.side
            );
            self.abort_with(
                vec![Self::protocol_violation(
                    "I-FORWARD-TSN was not negotiated (RFC 8260 2.3.1)",
                )],
                AssociationError::TransportError,
            )?;
            return Ok(vec![]);
        }

        let Some(prev_peer_last_tsn) = self.forward_cumulative_tsn(c.new_cumulative_tsn) else {
            return Ok(vec![]);
        };

        // Each entry says which messages of a stream will not be completed, for its ordered
        // or its unordered messages; no other stream holds anything the chunk skips.
        for forwarded in &c.streams {
            if let Some(s) = self.streams.get_mut(&forwarded.identifier) {
                let bytes_before = s.get_num_bytes_in_reassembly_queue();
                s.reassembly_queue
                    .forward_mid(forwarded.unordered, forwarded.mid);
                if s.reassembly_queue.is_readable() {
                    self.events.push_back(Event::Stream(StreamEvent::Readable {
                        id: s.stream_identifier,
                    }));
                }
                self.reindex_stream(forwarded.identifier, bytes_before);
            }
        }

        let mut reset_reply = vec![];
        self.reset_streams_reached_since(prev_peer_last_tsn, &mut reset_reply)?;
        let mut reply = self.handle_peer_last_tsn_and_acknowledgement(false)?;
        reset_reply.append(&mut reply);
        Ok(reset_reply)
    }

    /// As `note_abandoned_for_forward_tsn`, for an abandoned I-DATA chunk: the greatest
    /// Message Identifier skipped is reported per stream for ordered and for unordered
    /// messages alike (RFC 8260 2.3.1).
    pub(super) fn note_abandoned_for_i_forward_tsn(&mut self, unordered: bool, si: u16, mid: u32) {
        self.i_fwd_tsn_stream_map
            .entry((si, unordered))
            .and_modify(|cur| {
                if sna32lt(*cur, mid) {
                    *cur = mid;
                }
            })
            .or_insert(mid);
    }

    /// Builds the I-FORWARD-TSN for the abandoned chunks up to the Advanced.Peer.Ack.Point.
    /// Like the FORWARD TSN (RFC 3758 3.5 C4) it fits one packet: with more entries than
    /// fit, it covers the TSNs up to the last one whose entries do.
    pub(super) fn create_i_forward_tsn(&self) -> ChunkIForwardTsn {
        let room = if self.mtu == 0 {
            usize::MAX
        } else {
            (self.mtu as usize).saturating_sub(COMMON_HEADER_SIZE as usize + CHUNK_HEADER_SIZE + 4)
                / I_FORWARD_TSN_STREAM_LENGTH
        };
        let entry =
            |(&(identifier, unordered), &mid): (&(u16, bool), &u32)| ChunkIForwardTsnStream {
                identifier,
                unordered,
                mid,
            };
        if self.i_fwd_tsn_stream_map.len() <= room {
            let mut streams: Vec<_> = self.i_fwd_tsn_stream_map.iter().map(entry).collect();
            streams.sort_by_key(|s| (s.identifier, s.unordered));
            return ChunkIForwardTsn {
                new_cumulative_tsn: self.advanced_peer_tsn_ack_point,
                streams,
            };
        }

        let mut map: FxHashMap<(u16, bool), u32> = FxHashMap::default();
        let mut covered = self.cumulative_tsn_ack_point;
        let mut tsn = self.cumulative_tsn_ack_point.wrapping_add(1);
        while sna32lte(tsn, self.advanced_peer_tsn_ack_point) {
            let Some(c) = self.inflight_queue.get(tsn) else {
                break;
            };
            let key = (c.stream_identifier, c.unordered);
            if !map.contains_key(&key) && map.len() == room {
                break;
            }
            let mid = c.mid;
            map.entry(key)
                .and_modify(|cur| {
                    if sna32lt(*cur, mid) {
                        *cur = mid;
                    }
                })
                .or_insert(mid);
            covered = tsn;
            tsn = tsn.wrapping_add(1);
        }
        let mut streams: Vec<_> = map.iter().map(entry).collect();
        streams.sort_by_key(|s| (s.identifier, s.unordered));
        ChunkIForwardTsn {
            new_cumulative_tsn: covered,
            streams,
        }
    }
}
