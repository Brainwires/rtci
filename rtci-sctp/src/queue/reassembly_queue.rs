use crate::StreamId;
use crate::chunk::chunk_payload_data::{ChunkPayloadData, PayloadProtocolIdentifier};
use crate::util::*;
use shared::error::{Error, Result};

use bytes::{Bytes, BytesMut};
use std::collections::VecDeque;

/// A chunk of data from the stream
#[derive(Debug, PartialEq)]
pub struct Chunk {
    /// The contents of the chunk
    pub bytes: Bytes,
}

/// Chunks is a set of chunks that share the same SSN
#[derive(Debug, Clone)]
pub struct Chunks {
    /// used only with the ordered chunks
    pub ssn: u16,
    /// The Message Identifier, when the message came in I-DATA chunks (RFC 8260): counted
    /// per stream, separately for ordered and unordered messages. Zero otherwise.
    pub mid: u32,
    /// The payload protocol identifier shared by every fragment of this message.
    pub ppi: PayloadProtocolIdentifier,
    /// The Payload Protocol Identifier as the number the peer sent (RFC 9260 3.3.1): the
    /// value of `ppi` when that has a name for it, and the only way to tell apart the values
    /// it calls `Unknown`.
    pub ppid: u32,
    /// The fragments, in order, that make up one complete message.
    pub chunks: Vec<ChunkPayloadData>,
    offset: usize,
    index: usize,
    /// Arrival order, used only to decide which of two ready messages came first.
    /// A counter rather than an instant: this is sequencing, not time.
    arrival: u64,
    /// The fragments are I-DATA chunks: ordered and checked by their Fragment Sequence
    /// Number, not by their TSN (RFC 8260 2.2.3).
    by_fsn: bool,
    /// The message is in partial delivery (RFC 9260 6.9): its fragments up to this one were
    /// handed to the application, and `chunks` holds those received after them. The Fragment
    /// Sequence Number with I-DATA, the TSN otherwise.
    next_part: Option<u32>,
}

impl Chunks {
    /// Whether the reassembled message carries no bytes.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The total length in bytes of the reassembled message.
    pub fn len(&self) -> usize {
        let mut l = 0;
        for c in &self.chunks {
            l += c.user_data.len();
        }
        l
    }

    /// Reassemble all fragments into a single freshly-allocated, exactly-sized
    /// buffer with one copy.
    ///
    /// Unlike [`read`](Self::read), this does not round-trip through a
    /// caller-provided scratch buffer, eliminating one full-payload copy on the
    /// receive path (the reassembled message would otherwise be copied into the
    /// scratch buffer and then again into the delivered `BytesMut`). Returns
    /// [`Error::ErrShortBuffer`] when the message exceeds `max_len`, mirroring
    /// `read`'s bound so oversized inbound messages are still rejected.
    pub fn to_payload(&self, max_len: usize) -> Result<BytesMut> {
        let total = self.len();
        if total > max_len {
            return Err(Error::ErrShortBuffer);
        }
        let mut buf = BytesMut::with_capacity(total);
        for c in &self.chunks {
            buf.extend_from_slice(&c.user_data);
        }
        Ok(buf)
    }

    /// Concatenates every fragment into `buf`, returning the number of bytes written.
    ///
    /// # Errors
    ///
    /// Returns [`Error::ErrShortBuffer`](shared::error::Error::ErrShortBuffer) if `buf` cannot
    /// hold the whole message; the partial copy is left in place.
    pub fn read(&self, buf: &mut [u8]) -> Result<usize> {
        let mut n_written = 0;
        for c in &self.chunks {
            let to_copy = c.user_data.len();
            let n = std::cmp::min(to_copy, buf.len() - n_written);
            buf[n_written..n_written + n].copy_from_slice(&c.user_data[..n]);
            n_written += n;
            if n < to_copy {
                return Err(Error::ErrShortBuffer);
            }
        }
        Ok(n_written)
    }

    /// Yields the next slice of the reassembled message, up to `max_length` bytes.
    ///
    /// Advances an internal cursor, so repeated calls walk the message; returns `None` once it is
    /// exhausted.
    pub fn next(&mut self, max_length: usize) -> Option<Chunk> {
        if self.index >= self.chunks.len() {
            return None;
        }

        let mut buf = BytesMut::with_capacity(max_length);

        let mut n_written = 0;
        while self.index < self.chunks.len() {
            let to_copy = self.chunks[self.index].user_data[self.offset..].len();
            let n = std::cmp::min(to_copy, max_length - n_written);
            buf.extend_from_slice(&self.chunks[self.index].user_data[self.offset..self.offset + n]);
            n_written += n;
            if n < to_copy {
                self.offset += n;
                return Some(Chunk {
                    bytes: buf.freeze(),
                });
            }
            self.index += 1;
            self.offset = 0;
        }

        Some(Chunk {
            bytes: buf.freeze(),
        })
    }

    pub(crate) fn new(
        arrival: u64,
        ssn: u16,
        ppi: PayloadProtocolIdentifier,
        chunks: Vec<ChunkPayloadData>,
    ) -> Self {
        Chunks {
            ssn,
            mid: 0,
            ppi,
            ppid: chunks.first().map_or(ppi.number(), ChunkPayloadData::ppid),
            chunks,
            offset: 0,
            index: 0,
            arrival,
            by_fsn: false,
            next_part: None,
        }
    }

    /// An empty set for the I-DATA fragments of message `mid`.
    fn new_interleaved(arrival: u64, mid: u32) -> Self {
        Chunks {
            ssn: mid as u16,
            mid,
            ppi: PayloadProtocolIdentifier::default(),
            ppid: 0,
            chunks: vec![],
            offset: 0,
            index: 0,
            arrival,
            by_fsn: true,
            next_part: None,
        }
    }

    /// Adds an I-DATA fragment at its place by Fragment Sequence Number. `false` for a
    /// fragment already held.
    fn insert_fragment(&mut self, chunk: ChunkPayloadData) -> bool {
        let idx = self.chunks.partition_point(|c| sna32lt(c.fsn, chunk.fsn));
        if idx < self.chunks.len() && self.chunks[idx].fsn == chunk.fsn {
            return false;
        }
        if chunk.beginning_fragment {
            // Only the first fragment carries the Payload Protocol Identifier.
            self.ppi = chunk.payload_type;
            self.ppid = chunk.ppid();
        }
        self.chunks.insert(idx, chunk);
        true
    }

    pub(crate) fn push(&mut self, chunk: ChunkPayloadData) -> bool {
        // Binary-search the insertion point (fragments are kept in TSN order),
        // which also detects duplicates -- instead of an O(n) dup scan plus a
        // full re-sort of every fragment on each push.
        let idx = self.chunks.partition_point(|c| sna32lt(c.tsn, chunk.tsn));
        if idx < self.chunks.len() && self.chunks[idx].tsn == chunk.tsn {
            return false;
        }
        if self.chunks.is_empty() && self.next_part.is_none() {
            self.ppid = chunk.ppid();
        }
        self.chunks.insert(idx, chunk);

        // Check if we now have a complete set
        self.is_complete()
    }

    pub(crate) fn is_complete(&self) -> bool {
        // A message in partial delivery is never whole again: part of it was read.
        if self.next_part.is_some() {
            return false;
        }
        // Condition for complete set
        //   0. Has at least one chunk.
        //   1. Begins with beginningFragment set to true
        //   2. Ends with endingFragment set to true
        //   3. TSN monotinically increase by 1 from beginning to end

        // 0.
        let n_chunks = self.chunks.len();
        if n_chunks == 0 {
            return false;
        }

        // 1.
        if !self.chunks[0].beginning_fragment {
            return false;
        }

        // 2.
        if !self.chunks[n_chunks - 1].ending_fragment {
            return false;
        }

        if self.by_fsn {
            // RFC 8260 2.2.3: by the Fragment Sequence Numbers, whatever the TSNs are.
            return contiguous_span(self.chunks[0].fsn, self.chunks[n_chunks - 1].fsn, n_chunks);
        }

        // 3. Fragments must have contiguous TSN
        // From RFC 4960 Section 3.3.1:
        //   When a user message is fragmented into multiple chunks, the TSNs are
        //   used by the receiver to reassemble the message.  This means that the
        //   TSNs for each fragment of a fragmented user message MUST be strictly
        //   sequential.
        // The fragments are kept sorted by TSN with no duplicates (`push`), so they are
        // contiguous exactly when the first and last TSNs span one less than their count.
        // Checking that in constant time keeps a message of many fragments from costing a
        // full rescan on every arrival.
        contiguous_span(self.chunks[0].tsn, self.chunks[n_chunks - 1].tsn, n_chunks)
    }
}

impl Chunks {
    /// The number that orders this message's fragments: the FSN with I-DATA, the TSN
    /// otherwise.
    fn key(&self, c: &ChunkPayloadData) -> u32 {
        if self.by_fsn { c.fsn } else { c.tsn }
    }

    /// The fragments that can be handed on now, in order: from the first fragment (or the
    /// one after the last part read) through those that follow it without a gap, and no
    /// further than the last fragment. Their count, their bytes, and whether the last of them
    /// ends the message. `None` when the first of them is missing.
    pub(crate) fn leading_run(&self) -> Option<(usize, usize, bool)> {
        let first = self.chunks.first()?;
        let starts = match self.next_part {
            Some(next) => self.key(first) == next,
            None => first.beginning_fragment,
        };
        if !starts {
            return None;
        }
        let start = self.key(first);
        let (mut count, mut bytes) = (0usize, 0usize);
        for (i, c) in self.chunks.iter().enumerate() {
            if self.key(c) != start.wrapping_add(i as u32) || (i > 0 && c.beginning_fragment) {
                break;
            }
            count += 1;
            bytes += c.user_data.len();
            if c.ending_fragment {
                return Some((count, bytes, true));
            }
        }
        Some((count, bytes, false))
    }

    /// Whether every fragment of a message in partial delivery that is still to be read has
    /// arrived, its last fragment included.
    pub(crate) fn remaining_complete(&self) -> bool {
        self.next_part.is_some() && self.leading_run().is_some_and(|(_, _, ends)| ends)
    }

    /// Takes out the fragments [`leading_run`](Self::leading_run) names and puts the message
    /// in partial delivery from the next one on. Returns them and whether they end it.
    fn take_leading(&mut self) -> Option<(Vec<ChunkPayloadData>, bool)> {
        let (count, _, ends) = self.leading_run()?;
        let taken: Vec<ChunkPayloadData> = self.chunks.drain(..count).collect();
        let last = taken.last().map(|c| self.key(c)).unwrap_or_default();
        self.next_part = Some(last.wrapping_add(1));
        Some((taken, ends))
    }

    /// The next fragment of a message in partial delivery when every one before it is held:
    /// after the last held, or the one after the last part read.
    fn expected_tail(&self) -> Option<u32> {
        let next = self.next_part?;
        match self.leading_run() {
            Some((_, _, true)) => None,
            Some((count, _, false)) => Some(next.wrapping_add(count as u32)),
            None => Some(next),
        }
    }

    /// A part of this message made of `chunks`.
    fn part(&self, chunks: Vec<ChunkPayloadData>) -> Chunks {
        Chunks {
            ssn: self.ssn,
            mid: self.mid,
            ppi: self.ppi,
            ppid: self.ppid,
            chunks,
            offset: 0,
            index: 0,
            arrival: self.arrival,
            by_fsn: self.by_fsn,
            next_part: None,
        }
    }
}

/// Part of a message, read with [`Stream::read_part`](crate::Stream::read_part): the partial
/// delivery API of RFC 9260 section 6.9 (the RECEIVE primitive's "partial flag", section
/// 11.1.7; `MSG_EOR` of RFC 6458 section 3.1.4).
///
/// A message that is complete when it is read is one part with `end_of_record` set. One the
/// receive buffer cannot hold whole is read in several, in order: the first with `first`
/// set, the last with `end_of_record` set, all of them from the same stream with no part of
/// another message of that stream between them (RFC 6458 section 3.1.4: "Only one message at
/// a time can be partially delivered in any stream"). If the sender abandons the message
/// before its last part (RFC 3758, RFC 8260 section 2.3.1), no part with `end_of_record`
/// follows: [`StreamEvent::PartialDeliveryAborted`](crate::StreamEvent::PartialDeliveryAborted)
/// says so instead.
#[derive(Debug)]
pub struct MessagePart {
    /// The bytes of this part, as the fragments that carried them. Its `ssn`, `mid`, `ppi` and
    /// `ppid` are the message's.
    pub chunks: Chunks,
    /// The message was sent unordered.
    pub unordered: bool,
    /// This part starts the message.
    pub first: bool,
    /// This part ends the message ("no more deliveries will be received for this stream
    /// sequence number", RFC 9260 section 11.1.7; RFC 6458 `MSG_EOR`).
    pub end_of_record: bool,
}

/// The message of a stream that is in partial delivery.
#[derive(Debug)]
struct Partial {
    set: Chunks,
    unordered: bool,
}

/// A message whose partial delivery ended without its last part: the sender abandoned it
/// (RFC 3758 section 3.6, RFC 8260 section 2.3.1), or the stream's sequence numbers were
/// reset (RFC 6525).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PartialAbort {
    pub(crate) unordered: bool,
    /// The Stream Sequence Number with DATA, the Message Identifier with I-DATA.
    pub(crate) sequence: u32,
}

/// Where the message a stream can start delivering in parts is.
enum PartCandidate {
    /// The ordered message that is due, at the front of `ordered`.
    Ordered,
    /// An unordered I-DATA message, at this index of `unordered_partial`.
    UnorderedInterleaved(usize),
    /// An unordered DATA message whose first fragment is at this index of `unordered_chunks`.
    UnorderedData(usize),
}

/// Whether `n` distinct TSNs, sorted, running from `first` to `last` are contiguous.
fn contiguous_span(first: u32, last: u32, n: usize) -> bool {
    n > 0 && last.wrapping_sub(first) as usize == n - 1
}

#[derive(Default, Debug)]
pub(crate) struct ReassemblyQueue {
    pub(crate) si: StreamId,
    pub(crate) next_ssn: u16,
    /// expected SSN for next ordered chunk
    ///
    /// `ordered`/`unordered` are consumed strictly from the front by `read`;
    /// `VecDeque` makes that O(1) instead of `Vec::remove(0)`'s full shift.
    pub(crate) ordered: VecDeque<Chunks>,
    pub(crate) unordered: VecDeque<Chunks>,
    pub(crate) unordered_chunks: Vec<ChunkPayloadData>,
    /// TSNs of the beginning fragments in `unordered_chunks`, sorted, so the message a new
    /// fragment may complete is found without rescanning every fragment held.
    unordered_begins: Vec<u32>,
    /// TSNs of the ending fragments in `unordered_chunks`, sorted.
    unordered_ends: Vec<u32>,
    pub(crate) n_bytes: usize,
    /// Monotonic counter stamped onto each reassembled message so `read` can tell which of a
    /// ready ordered and a ready unordered message arrived first.
    next_arrival: u64,
    /// The association uses I-DATA (RFC 8260): messages are told apart by their Message
    /// Identifier and put together by Fragment Sequence Number. `ordered` is then kept in
    /// Message Identifier order.
    pub(crate) interleaved: bool,
    /// The Message Identifier of the next ordered message to deliver.
    pub(crate) next_mid: u32,
    /// The unordered I-DATA messages still incomplete, in Message Identifier order.
    unordered_partial: Vec<Chunks>,
    /// The message of this stream in partial delivery, if one is (RFC 9260 6.9): at most one
    /// per stream, and no other message of the stream is read until it ends (RFC 6458 3.1.4).
    partial: Option<Partial>,
    /// A partial delivery that ended without its last part, until the association reports it.
    partial_aborted: Option<PartialAbort>,
    /// Fragments dropped because they could never be part of a complete message
    /// ([`discard_orphans`](Self::discard_orphans)).
    pub(crate) orphans_dropped: usize,
}

impl ReassemblyQueue {
    /// From RFC 4960 Sec 6.5:
    ///   The Stream Sequence Number in all the streams MUST start from 0 when
    ///   the association is Established.  Also, when the Stream Sequence
    ///   Number reaches the value 65535 the next Stream Sequence Number MUST
    ///   be set to 0.
    pub(crate) fn new(si: StreamId) -> Self {
        ReassemblyQueue {
            si,
            next_ssn: 0, // From RFC 4960 Sec 6.5:
            ordered: VecDeque::new(),
            unordered: VecDeque::new(),
            unordered_chunks: vec![],
            unordered_begins: vec![],
            unordered_ends: vec![],
            n_bytes: 0,
            next_arrival: 0,
            interleaved: false,
            next_mid: 0,
            unordered_partial: vec![],
            partial: None,
            partial_aborted: None,
            orphans_dropped: 0,
        }
    }

    /// RFC 8260 2.2.3: an I-DATA chunk goes to the message its stream, U bit and Message
    /// Identifier name, at the place its Fragment Sequence Number gives it. Returns whether
    /// the message is complete with it.
    fn push_interleaved(&mut self, chunk: ChunkPayloadData) -> bool {
        let (mid, len) = (chunk.mid, chunk.user_data.len());
        if chunk.unordered {
            let idx = self
                .unordered_partial
                .partition_point(|s| sna32lt(s.mid, mid));
            if self.unordered_partial.get(idx).is_none_or(|s| s.mid != mid) {
                self.unordered_partial
                    .insert(idx, Chunks::new_interleaved(0, mid));
            }
            let set = &mut self.unordered_partial[idx];
            if !set.insert_fragment(chunk) {
                return false;
            }
            self.n_bytes += len;
            if !set.is_complete() {
                return false;
            }
            let mut set = self.unordered_partial.remove(idx);
            set.arrival = self.next_arrival;
            self.next_arrival += 1;
            self.unordered.push_back(set);
            return true;
        }

        if sna32lt(mid, self.next_mid) {
            return false;
        }
        if chunk.beginning_fragment {
            self.drop_superseded(chunk.tsn, |set| {
                if set.mid == mid {
                    std::cmp::Ordering::Equal
                } else if sna32gt(set.mid, mid) {
                    std::cmp::Ordering::Greater
                } else {
                    std::cmp::Ordering::Less
                }
            });
        }
        let idx = self.ordered.partition_point(|s| sna32lt(s.mid, mid));
        if self.ordered.get(idx).is_none_or(|s| s.mid != mid) {
            self.ordered
                .insert(idx, Chunks::new_interleaved(self.next_arrival, mid));
            self.next_arrival += 1;
        }
        let set = &mut self.ordered[idx];
        if !set.insert_fragment(chunk) {
            return false;
        }
        self.n_bytes += len;
        set.is_complete()
    }

    /// The first fragment of an ordered message has arrived, with TSN `tsn`: drops what is held
    /// in front of it that a sender could not have sent. A sender transmits the ordered
    /// messages of a stream in the order of their numbers, each from its first fragment on, so
    /// within one use of a stream a message numbered after this one has TSNs above `tsn`, and
    /// this message has none below it. What is held against that came before a reset of the
    /// stream from a peer that sent queued data after its Sender's Last Assigned TSN with the
    /// stream's old numbers (RFC 6525 5.2.2 E2/E4 make it data of the stream as reset): kept,
    /// a message of it would be delivered in place of the next use's message with the same
    /// number, or be put together with it and never complete. `place` says where a set's
    /// number is against this message's: `Equal` for its own, `Greater` after it.
    fn drop_superseded(&mut self, tsn: u32, place: impl Fn(&Chunks) -> std::cmp::Ordering) {
        use std::cmp::Ordering::{Equal, Greater};
        let lowest = |set: &Chunks| {
            set.chunks
                .iter()
                .map(|c| c.tsn)
                .reduce(|a, b| if sna32lt(b, a) { b } else { a })
        };
        let (mut dropped, mut dropped_bytes) = (0, 0);
        for set in self.ordered.iter_mut() {
            if set.next_part.is_some() {
                continue;
            }
            match place(set) {
                Greater if lowest(set).is_some_and(|t| sna32lt(t, tsn)) => {
                    dropped += set.chunks.len();
                    dropped_bytes += set.len();
                    set.chunks.clear();
                }
                Equal => set.chunks.retain(|c| {
                    let stale = sna32lt(c.tsn, tsn);
                    if stale {
                        dropped += 1;
                        dropped_bytes += c.user_data.len();
                    }
                    !stale
                }),
                _ => {}
            }
        }
        if dropped > 0 {
            self.ordered.retain(|s| !s.chunks.is_empty());
            self.subtract_num_bytes(dropped_bytes);
            self.orphans_dropped += dropped;
        }
    }

    /// Whether `chunk`, which no message in partial delivery takes, does not begin a message
    /// while the fragment that would come before it in its message has been received (every
    /// TSN up to `cum` has) and is not held with it: the start of its message went somewhere
    /// else, and nothing that can still arrive completes it.
    fn is_orphan(&self, chunk: &ChunkPayloadData, cum: u32) -> bool {
        if chunk.beginning_fragment || !sna32lte(chunk.tsn.wrapping_sub(1), cum) {
            return false;
        }
        let before = chunk.tsn.wrapping_sub(1);
        if self.interleaved {
            // A fragment of a message of which nothing is held: its earlier fragments, the
            // first included, have TSNs below its own, all received, and none is here.
            let mid = chunk.mid;
            return if chunk.unordered {
                !self.unordered_partial.iter().any(|s| s.mid == mid)
            } else {
                !self.ordered.iter().any(|s| s.mid == mid)
            };
        }
        if chunk.unordered {
            let idx = self
                .unordered_chunks
                .partition_point(|c| sna32lt(c.tsn, before));
            return self
                .unordered_chunks
                .get(idx)
                .is_none_or(|c| c.tsn != before);
        }
        let ssn = chunk.stream_sequence_number;
        let idx = self.ordered.partition_point(|s| sna16lt(s.ssn, ssn));
        match self.ordered.get(idx) {
            Some(s) if s.ssn == ssn => {
                let i = s.chunks.partition_point(|c| sna32lt(c.tsn, before));
                s.chunks.get(i).is_none_or(|c| c.tsn != before)
            }
            _ => true,
        }
    }

    /// Whether an ordered message is the next one to deliver, or one before it.
    fn is_due(&self, set: &Chunks) -> bool {
        if self.interleaved {
            sna32lte(set.mid, self.next_mid)
        } else {
            sna16lte(set.ssn, self.next_ssn)
        }
    }

    /// The ordered message `set` is delivered: the one after it is expected next.
    fn delivered(&mut self, ssn: u16, mid: u32) {
        if self.interleaved {
            if mid == self.next_mid {
                self.next_mid = self.next_mid.wrapping_add(1);
            }
        } else if ssn == self.next_ssn {
            self.next_ssn = self.next_ssn.wrapping_add(1);
        }
    }

    /// RFC 8260 2.3.1: an I-FORWARD-TSN entry. The messages of this stream up to `mid`,
    /// ordered or unordered as the entry says, will not be completed: their fragments are
    /// dropped, and the ordered messages after them are no longer held back.
    pub(crate) fn forward_mid(&mut self, unordered: bool, mid: u32) {
        if self.partial.as_ref().is_some_and(|p| {
            p.unordered == unordered && sna32lte(p.set.mid, mid) && !p.set.remaining_complete()
        }) {
            self.abort_partial();
        }
        let mut dropped = 0;
        if unordered {
            self.unordered_partial.retain(|s| {
                let keep = sna32gt(s.mid, mid);
                if !keep {
                    dropped += s.len();
                }
                keep
            });
        } else {
            self.ordered.retain(|s| {
                let keep = sna32gt(s.mid, mid) || s.is_complete();
                if !keep {
                    dropped += s.len();
                }
                keep
            });
            if sna32lte(self.next_mid, mid) {
                self.next_mid = mid.wrapping_add(1);
            }
        }
        self.subtract_num_bytes(dropped);
    }

    pub(crate) fn push(&mut self, chunk: ChunkPayloadData) -> bool {
        self.push_received(chunk, None)
    }

    /// As [`push`](Self::push), with the receiver's cumulative TSN before `chunk`: a fragment
    /// that can never be part of a complete message (see
    /// [`discard_orphans`](Self::discard_orphans)) is dropped instead of being held.
    pub(crate) fn push_received(
        &mut self,
        chunk: ChunkPayloadData,
        cumulative_tsn: Option<u32>,
    ) -> bool {
        if chunk.stream_identifier != self.si {
            return false;
        }
        let Some(chunk) = self.push_to_partial(chunk) else {
            return false;
        };
        if let Some(cum) = cumulative_tsn
            && self.is_orphan(&chunk, cum)
        {
            self.orphans_dropped += 1;
            return false;
        }
        if self.interleaved {
            return self.push_interleaved(chunk);
        }

        if chunk.unordered {
            // First, insert into unordered_chunks array
            let tsn = chunk.tsn;
            let idx = self
                .unordered_chunks
                .partition_point(|c| sna32lt(c.tsn, tsn));
            if idx < self.unordered_chunks.len() && self.unordered_chunks[idx].tsn == tsn {
                return false;
            }
            self.n_bytes += chunk.user_data.len();
            if chunk.beginning_fragment {
                let i = self.unordered_begins.partition_point(|&t| sna32lt(t, tsn));
                self.unordered_begins.insert(i, tsn);
            }
            if chunk.ending_fragment {
                let i = self.unordered_ends.partition_point(|&t| sna32lt(t, tsn));
                self.unordered_ends.insert(i, tsn);
            }
            self.unordered_chunks.insert(idx, chunk);

            // Find the message this chunk completes, if any, and append it to the
            // unordered array.
            if let Some(cset) = self.find_complete_unordered_chunk_set(tsn) {
                self.unordered.push_back(cset);
                return true;
            }

            false
        } else {
            // This is an ordered chunk
            if sna16lt(chunk.stream_sequence_number, self.next_ssn) {
                return false;
            }

            if chunk.beginning_fragment {
                let ssn = chunk.stream_sequence_number;
                self.drop_superseded(chunk.tsn, |set| {
                    if set.ssn == ssn {
                        std::cmp::Ordering::Equal
                    } else if sna16gt(set.ssn, ssn) {
                        std::cmp::Ordering::Greater
                    } else {
                        std::cmp::Ordering::Less
                    }
                });
            }

            self.n_bytes += chunk.user_data.len();

            // `ordered` is kept sorted by SSN, so binary-search for the chunk
            // set instead of scanning linearly (O(N) per arriving chunk when
            // the application drains slower than data arrives).
            let ssn = chunk.stream_sequence_number;
            let idx = self.ordered.partition_point(|s| sna16lt(s.ssn, ssn));
            if let Some(s) = self.ordered.get_mut(idx)
                && s.ssn == ssn
            {
                return s.push(chunk);
            }

            // If not found, create a new chunkSet and insert it in SSN order
            // (this branch is only reached for ordered chunks).
            let mut cset = Chunks::new(self.next_arrival, ssn, chunk.payload_type, vec![]);
            self.next_arrival += 1;
            let ok = cset.push(chunk);
            self.ordered.insert(idx, cset);

            ok
        }
    }

    /// A fragment of the message in partial delivery goes to it; any other is given back.
    ///
    /// With I-DATA the message is named by its U bit and Message Identifier, and with DATA an
    /// ordered one by its Stream Sequence Number. An unordered DATA message has no number of
    /// its own, so a fragment belongs to it when it is the next TSN after the fragments it
    /// holds (RFC 9260 6.9: a message's fragments have consecutive TSNs) and does not begin
    /// a message; the fragments after it that are already held join it.
    fn push_to_partial(&mut self, chunk: ChunkPayloadData) -> Option<ChunkPayloadData> {
        let Some(p) = self.partial.as_mut() else {
            return Some(chunk);
        };
        let len = chunk.user_data.len();
        let next = p.set.next_part.unwrap_or_default();
        if self.interleaved {
            if chunk.unordered != p.unordered || chunk.mid != p.set.mid {
                return Some(chunk);
            }
            if sna32gte(chunk.fsn, next) && p.set.insert_fragment(chunk) {
                self.n_bytes += len;
            }
            return None;
        }
        if !p.unordered {
            if chunk.unordered || chunk.stream_sequence_number != p.set.ssn {
                return Some(chunk);
            }
            let before = p.set.chunks.len();
            if sna32gte(chunk.tsn, next) {
                p.set.push(chunk);
            }
            if p.set.chunks.len() > before {
                self.n_bytes += len;
            }
            return None;
        }
        if !chunk.unordered || chunk.beginning_fragment || p.set.expected_tail() != Some(chunk.tsn)
        {
            return Some(chunk);
        }
        p.set.chunks.push(chunk);
        self.n_bytes += len;
        // The fragments after it may have come first.
        while let Some(tsn) = p.set.expected_tail() {
            let idx = self
                .unordered_chunks
                .partition_point(|c| sna32lt(c.tsn, tsn));
            if self
                .unordered_chunks
                .get(idx)
                .is_none_or(|c| c.tsn != tsn || c.beginning_fragment)
            {
                break;
            }
            let c = self.unordered_chunks.remove(idx);
            if c.ending_fragment {
                let i = self.unordered_ends.partition_point(|&t| sna32lt(t, tsn));
                if self.unordered_ends.get(i) == Some(&tsn) {
                    self.unordered_ends.remove(i);
                }
            }
            p.set.chunks.push(c);
        }
        None
    }

    /// Takes out the complete message that holds the fragment with `tsn`, if there is one.
    ///
    /// Every complete message is taken out as soon as its last fragment arrives, so a new
    /// fragment can complete only the message it belongs to: the one from the nearest
    /// beginning fragment at or before it to the nearest ending fragment at or after it, if
    /// the TSNs between them are all held. Each step is a binary search, so a peer sending
    /// many fragments that never complete costs no rescan of what is already held.
    pub(crate) fn find_complete_unordered_chunk_set(&mut self, tsn: u32) -> Option<Chunks> {
        let bi = self.unordered_begins.partition_point(|&t| sna32lte(t, tsn));
        if bi == 0 {
            return None;
        }
        let begin_tsn = self.unordered_begins[bi - 1];
        let ei = self.unordered_ends.partition_point(|&t| sna32lt(t, tsn));
        if ei == self.unordered_ends.len() {
            return None;
        }
        let end_tsn = self.unordered_ends[ei];

        let start_idx = self
            .unordered_chunks
            .partition_point(|c| sna32lt(c.tsn, begin_tsn));
        let end_idx = self
            .unordered_chunks
            .partition_point(|c| sna32lt(c.tsn, end_tsn));
        if end_idx >= self.unordered_chunks.len()
            || self.unordered_chunks[start_idx].tsn != begin_tsn
            || self.unordered_chunks[end_idx].tsn != end_tsn
            || !contiguous_span(begin_tsn, end_tsn, end_idx - start_idx + 1)
        {
            return None;
        }

        // Extract the range of chunks
        self.unordered_begins.remove(bi - 1);
        self.unordered_ends.remove(ei);
        let chunks: Vec<ChunkPayloadData> =
            self.unordered_chunks.drain(start_idx..=end_idx).collect();
        let arrival = self.next_arrival;
        self.next_arrival += 1;
        Some(Chunks::new(arrival, 0, chunks[0].payload_type, chunks))
    }

    pub(crate) fn is_readable(&self) -> bool {
        // No other message of a stream is read while one is in partial delivery (RFC 6458
        // 3.1.4, 8.1.20).
        if self.partial.is_some() {
            return false;
        }
        // Check unordered first
        if !self.unordered.is_empty() {
            // The chunk sets in self.unordered should all be complete.
            return true;
        }

        // Check ordered sets
        if !self.ordered.is_empty() {
            let cset = &self.ordered[0];
            if cset.is_complete() && self.is_due(cset) {
                return true;
            }
        }
        false
    }

    fn readable_unordered_chunks(&self) -> Option<&Chunks> {
        self.unordered.front()
    }

    fn readable_ordered_chunks(&self) -> Option<&Chunks> {
        let ordered = self.ordered.front();
        if let Some(chunks) = ordered {
            if !chunks.is_complete() {
                return None;
            }
            if !self.is_due(chunks) {
                return None;
            }
            Some(chunks)
        } else {
            None
        }
    }

    pub(crate) fn read(&mut self) -> Option<Chunks> {
        if self.partial.is_some() {
            return None;
        }
        let chunks = if let (Some(unordered_chunks), Some(ordered_chunks)) = (
            self.readable_unordered_chunks(),
            self.readable_ordered_chunks(),
        ) {
            if unordered_chunks.arrival < ordered_chunks.arrival {
                self.unordered.pop_front().unwrap()
            } else {
                let (ssn, mid) = (ordered_chunks.ssn, ordered_chunks.mid);
                self.delivered(ssn, mid);
                self.ordered.pop_front().unwrap()
            }
        } else {
            // Check unordered first
            if !self.unordered.is_empty() {
                self.unordered.pop_front().unwrap()
            } else if !self.ordered.is_empty() {
                // Now, check ordered
                let chunks = &self.ordered[0];
                if !chunks.is_complete() {
                    return None;
                }
                if !self.is_due(chunks) {
                    return None;
                }
                let (ssn, mid) = (chunks.ssn, chunks.mid);
                self.delivered(ssn, mid);
                self.ordered.pop_front().unwrap()
            } else {
                return None;
            }
        };

        self.subtract_num_bytes(chunks.len());

        Some(chunks)
    }

    /// Use last_ssn to locate a chunkSet then remove it if the set has
    /// not been complete
    pub(crate) fn forward_tsn_for_ordered(&mut self, last_ssn: u16) {
        if self.partial.as_ref().is_some_and(|p| {
            !p.unordered && sna16lte(p.set.ssn, last_ssn) && !p.set.remaining_complete()
        }) {
            self.abort_partial();
        }
        let num_bytes = self
            .ordered
            .iter()
            .filter(|s| sna16lte(s.ssn, last_ssn) && !s.is_complete())
            .fold(0, |n, s| {
                n + s.chunks.iter().fold(0, |acc, c| acc + c.user_data.len())
            });
        self.subtract_num_bytes(num_bytes);

        self.ordered
            .retain(|s| !sna16lte(s.ssn, last_ssn) || s.is_complete());

        // Finally, forward next_ssn
        if sna16lte(self.next_ssn, last_ssn) {
            self.next_ssn = last_ssn.wrapping_add(1);
        }
    }

    /// Remove all fragments in the unordered sets that contains chunks
    /// equal to or older than `new_cumulative_tsn`.
    /// We know all sets in the r.unordered are complete ones.
    /// Just remove chunks that are equal to or older than new_cumulative_tsn
    /// from the unordered_chunks
    pub(crate) fn forward_tsn_for_unordered(&mut self, new_cumulative_tsn: u32) {
        // RFC 3758 3.6: the fragment the unordered message in partial delivery needs next is
        // skipped (were it received, it would be with the message), so it will not be
        // completed.
        if self.partial.as_ref().is_some_and(|p| {
            p.unordered
                && !p.set.by_fsn
                && p.set
                    .expected_tail()
                    .is_some_and(|tsn| sna32lte(tsn, new_cumulative_tsn))
        }) {
            self.abort_partial();
        }
        let mut last_idx: isize = -1;
        for (i, c) in self.unordered_chunks.iter().enumerate() {
            if sna32gt(c.tsn, new_cumulative_tsn) {
                break;
            }
            last_idx = i as isize;
        }
        if last_idx >= 0 {
            for i in 0..(last_idx + 1) as usize {
                self.subtract_num_bytes(self.unordered_chunks[i].user_data.len());
            }
            self.unordered_chunks.drain(..(last_idx + 1) as usize);
        }
        let n = self
            .unordered_begins
            .partition_point(|&t| sna32lte(t, new_cumulative_tsn));
        self.unordered_begins.drain(..n);
        let n = self
            .unordered_ends
            .partition_point(|&t| sna32lte(t, new_cumulative_tsn));
        self.unordered_ends.drain(..n);
    }

    /// RFC 6525 5.2.4 G4, G5 and 5.2.7 H5: the TSNs and Stream Sequence Numbers start over.
    /// As after a FORWARD TSN past everything received, the messages that are complete are
    /// delivered, in their order, and the fragments of the others are dropped; the next
    /// ordered message expected has sequence number 0.
    pub(crate) fn reset_sequence_numbers(&mut self) {
        if self
            .partial
            .as_ref()
            .is_some_and(|p| !p.set.remaining_complete())
        {
            self.abort_partial();
        }
        let mut dropped = 0;
        for set in std::mem::take(&mut self.ordered) {
            if set.is_complete() {
                // Readable whatever its number: the numbers before it will not come.
                self.unordered.push_back(set);
            } else {
                dropped += set.len();
            }
        }
        dropped += self
            .unordered_chunks
            .drain(..)
            .map(|c| c.user_data.len())
            .sum::<usize>();
        dropped += self
            .unordered_partial
            .drain(..)
            .map(|s| s.len())
            .sum::<usize>();
        self.unordered_begins.clear();
        self.unordered_ends.clear();
        self.subtract_num_bytes(dropped);
        self.next_ssn = 0;
        self.next_mid = 0;
    }

    /// Drops the fragments that can never be part of a complete message, `cumulative_tsn`
    /// being the receiver's cumulative TSN, and returns how many fragments were dropped.
    ///
    /// A message's first fragment has the B bit and the lowest TSN of the message: with DATA
    /// its fragments take consecutive TSNs (RFC 9260 6.9, step 2), with I-DATA they are sent in
    /// Fragment Sequence Number order, each with a TSN above the one before (RFC 8260 2.1).
    /// So a fragment that does not begin a message, when every TSN below it has been received
    /// and none of them is held with it, belongs to a message whose start went somewhere else:
    /// nothing that can still arrive completes it. A peer that resets a stream before the
    /// message it is sending on it has all its TSNs sends exactly that: the rest of the message
    /// comes after the reset's Sender's Last Assigned TSN, and RFC 6525 5.2.2 E2/E4 makes it
    /// data of the stream as it is after the reset. Kept, such fragments would sit in front of
    /// the messages of whatever uses the stream next: the next message with the same Stream
    /// Sequence Number (or Message Identifier) would be put together with them and never
    /// complete, and every ordered message after it would wait behind it for good, all of
    /// them acknowledged.
    ///
    /// The message in partial delivery is not looked at: its earlier fragments were read.
    pub(crate) fn discard_orphans(&mut self, cumulative_tsn: u32) -> usize {
        // Every TSN below `tsn` has been received (or skipped by a FORWARD TSN).
        let below_received = |tsn: u32| sna32lte(tsn.wrapping_sub(1), cumulative_tsn);
        let mut dropped_bytes = 0;
        let mut dropped = 0;

        if self.interleaved {
            // One set is one message (one Message Identifier): its fragment with the lowest
            // FSN is the earliest sent of those held. Without the B bit, and with every TSN
            // below it received, the first fragment went elsewhere.
            let orphaned = |s: &Chunks| {
                s.next_part.is_none()
                    && s.chunks
                        .first()
                        .is_some_and(|c| !c.beginning_fragment && below_received(c.tsn))
            };
            self.unordered_partial.retain(|s| {
                let keep = !orphaned(s);
                if !keep {
                    dropped += s.chunks.len();
                    dropped_bytes += s.len();
                }
                keep
            });
            self.ordered.retain(|s| {
                let keep = !orphaned(s);
                if !keep {
                    dropped += s.chunks.len();
                    dropped_bytes += s.len();
                }
                keep
            });
        } else {
            // Ordered: a set holds the fragments with one Stream Sequence Number, and may hold
            // the orphaned rest of an earlier message that had the same number in front of a
            // later message's fragments. Its leading fragments up to the first B bit go when
            // the TSN before the first of them has been received: it is not in the set.
            for set in self.ordered.iter_mut() {
                if set.next_part.is_some() {
                    continue;
                }
                let Some(first) = set.chunks.first() else {
                    continue;
                };
                if first.beginning_fragment || !below_received(first.tsn) {
                    continue;
                }
                let n = set
                    .chunks
                    .iter()
                    .position(|c| c.beginning_fragment)
                    .unwrap_or(set.chunks.len());
                for c in set.chunks.drain(..n) {
                    dropped += 1;
                    dropped_bytes += c.user_data.len();
                }
                if let Some(c) = set.chunks.first() {
                    // What is left is another message: its own protocol identifier.
                    set.ppi = c.payload_type;
                    set.ppid = c.ppid();
                }
            }
            self.ordered.retain(|s| !s.chunks.is_empty());

            // Unordered: a fragment without the B bit whose TSN before it was received and is
            // not held here, or was itself dropped as an orphan, and the fragments that follow
            // it without a gap or a B bit.
            let mut prev_kept: Option<u32> = None;
            let mut prev_dropped: Option<u32> = None;
            let mut drop_tsns = vec![];
            for c in &self.unordered_chunks {
                let before = c.tsn.wrapping_sub(1);
                let orphan = !c.beginning_fragment
                    && (prev_dropped == Some(before)
                        || (prev_kept != Some(before) && below_received(c.tsn)));
                if orphan {
                    drop_tsns.push(c.tsn);
                    prev_dropped = Some(c.tsn);
                } else {
                    prev_kept = Some(c.tsn);
                }
            }
            if !drop_tsns.is_empty() {
                let mut i = 0;
                self.unordered_chunks.retain(|c| {
                    if drop_tsns.get(i) == Some(&c.tsn) {
                        i += 1;
                        dropped += 1;
                        dropped_bytes += c.user_data.len();
                        false
                    } else {
                        true
                    }
                });
                self.unordered_ends.retain(|t| !drop_tsns.contains(t));
            }
        }
        self.subtract_num_bytes(dropped_bytes);
        self.orphans_dropped += dropped;
        dropped
    }

    pub(crate) fn subtract_num_bytes(&mut self, n_bytes: usize) {
        if self.n_bytes >= n_bytes {
            self.n_bytes -= n_bytes;
        } else {
            self.n_bytes = 0;
        }
    }

    pub(crate) fn get_num_bytes(&self) -> usize {
        self.n_bytes
    }

    /// Ends the partial delivery under way without its last part, dropping what is held of it.
    fn abort_partial(&mut self) {
        if let Some(p) = self.partial.take() {
            self.subtract_num_bytes(p.set.len());
            self.partial_aborted = Some(PartialAbort {
                unordered: p.unordered,
                sequence: if p.set.by_fsn {
                    p.set.mid
                } else {
                    u32::from(p.set.ssn)
                },
            });
        }
    }

    /// The partial delivery that ended without its last part since the last call, if one did.
    pub(crate) fn take_partial_abort(&mut self) -> Option<PartialAbort> {
        self.partial_aborted.take()
    }

    /// Whether a message of this stream is in partial delivery.
    pub(crate) fn in_partial_delivery(&self) -> bool {
        self.partial.is_some()
    }

    /// Whether the queue holds a message the application has not read all of and that is all
    /// here: a complete message that is readable, or the rest of the one in partial delivery.
    pub(crate) fn holds_whole_message(&self) -> bool {
        self.is_readable()
            || self
                .partial
                .as_ref()
                .is_some_and(|p| p.set.remaining_complete())
    }

    /// The message that can start delivering in parts: one whose fragments from the first
    /// on, without a gap, come to `threshold` bytes or more. Ordered, only the one that is
    /// due (the next Stream Sequence Number or Message Identifier); unordered, the first such.
    fn part_candidate(&self, threshold: usize) -> Option<PartCandidate> {
        if let Some(set) = self.ordered.front()
            && self.is_due(set)
            && set
                .leading_run()
                .is_some_and(|(_, bytes, ends)| !ends && bytes >= threshold)
        {
            return Some(PartCandidate::Ordered);
        }
        if let Some(i) = self.unordered_partial.iter().position(|set| {
            set.leading_run()
                .is_some_and(|(_, bytes, ends)| !ends && bytes >= threshold)
        }) {
            return Some(PartCandidate::UnorderedInterleaved(i));
        }
        for &begin in &self.unordered_begins {
            let start = self
                .unordered_chunks
                .partition_point(|c| sna32lt(c.tsn, begin));
            let mut bytes = 0;
            for (i, c) in self.unordered_chunks[start..].iter().enumerate() {
                if c.tsn != begin.wrapping_add(i as u32)
                    || (i > 0 && c.beginning_fragment)
                    || c.ending_fragment
                {
                    break;
                }
                bytes += c.user_data.len();
            }
            if bytes >= threshold && bytes > 0 {
                return Some(PartCandidate::UnorderedData(start));
            }
        }
        None
    }

    /// Whether [`read_part`](Self::read_part) with this `threshold` has something to return.
    pub(crate) fn part_readable(&self, threshold: usize) -> bool {
        match &self.partial {
            Some(p) => p.set.leading_run().is_some(),
            None => self.is_readable() || self.part_candidate(threshold.max(1)).is_some(),
        }
    }

    /// RFC 9260 6.9, the partial delivery API: the next part of a message on this stream.
    ///
    /// While a message is in partial delivery, the fragments of it that follow the last part
    /// read without a gap. Otherwise a complete message, whole, as [`read`](Self::read) gives
    /// it; and failing that the first fragments of a message that come to `threshold` bytes
    /// (the partial delivery point, RFC 6458 8.1.21), which puts it in partial delivery.
    pub(crate) fn read_part(&mut self, threshold: usize) -> Option<MessagePart> {
        if let Some(p) = self.partial.as_mut() {
            let (taken, ends) = p.set.take_leading()?;
            let chunks = p.set.part(taken);
            let unordered = p.unordered;
            if ends {
                self.partial = None;
            }
            self.subtract_num_bytes(chunks.len());
            return Some(MessagePart {
                chunks,
                unordered,
                first: false,
                end_of_record: ends,
            });
        }
        if self.is_readable() {
            let chunks = self.read()?;
            let unordered = chunks.chunks.first().is_some_and(|c| c.unordered);
            return Some(MessagePart {
                chunks,
                unordered,
                first: true,
                end_of_record: true,
            });
        }
        let (mut set, unordered) = match self.part_candidate(threshold.max(1))? {
            PartCandidate::Ordered => {
                let set = self.ordered.pop_front()?;
                // The messages after it are due once it ends.
                self.delivered(set.ssn, set.mid);
                (set, false)
            }
            PartCandidate::UnorderedInterleaved(i) => (self.unordered_partial.remove(i), true),
            PartCandidate::UnorderedData(start) => {
                let begin = self.unordered_chunks[start].tsn;
                let mut end = start;
                while self.unordered_chunks.get(end + 1).is_some_and(|c| {
                    c.tsn == begin.wrapping_add((end + 1 - start) as u32)
                        && !c.beginning_fragment
                        && !c.ending_fragment
                }) {
                    end += 1;
                }
                let run: Vec<ChunkPayloadData> = self.unordered_chunks.drain(start..=end).collect();
                let bi = self
                    .unordered_begins
                    .partition_point(|&t| sna32lt(t, begin));
                if self.unordered_begins.get(bi) == Some(&begin) {
                    self.unordered_begins.remove(bi);
                }
                let arrival = self.next_arrival;
                self.next_arrival += 1;
                (Chunks::new(arrival, 0, run[0].payload_type, run), true)
            }
        };
        let (taken, ends) = set.take_leading()?;
        let chunks = set.part(taken);
        self.subtract_num_bytes(chunks.len());
        if !ends {
            self.partial = Some(Partial { set, unordered });
        }
        Some(MessagePart {
            chunks,
            unordered,
            first: true,
            end_of_record: ends,
        })
    }

    /// Whether the queue holds no fragment and no message, and no message is in partial
    /// delivery (one whose next fragment is still to come has to hear of a FORWARD TSN).
    pub(crate) fn is_empty(&self) -> bool {
        self.n_bytes == 0
            && self.partial.is_none()
            && self.ordered.is_empty()
            && self.unordered.is_empty()
            && self.unordered_chunks.is_empty()
            && self.unordered_partial.is_empty()
    }
}
