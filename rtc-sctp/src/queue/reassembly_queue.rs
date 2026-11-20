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
    /// The payload protocol identifier shared by every fragment of this message.
    pub ppi: PayloadProtocolIdentifier,
    /// The fragments, in order, that make up one complete message.
    pub chunks: Vec<ChunkPayloadData>,
    offset: usize,
    index: usize,
    /// Arrival order, used only to decide which of two ready messages came first.
    /// A counter rather than an instant: this is sequencing, not time.
    arrival: u64,
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
            ppi,
            chunks,
            offset: 0,
            index: 0,
            arrival,
        }
    }

    pub(crate) fn push(&mut self, chunk: ChunkPayloadData) -> bool {
        // Binary-search the insertion point (fragments are kept in TSN order),
        // which also detects duplicates -- instead of an O(n) dup scan plus a
        // full re-sort of every fragment on each push.
        let idx = self.chunks.partition_point(|c| sna32lt(c.tsn, chunk.tsn));
        if idx < self.chunks.len() && self.chunks[idx].tsn == chunk.tsn {
            return false;
        }
        self.chunks.insert(idx, chunk);

        // Check if we now have a complete set
        self.is_complete()
    }

    pub(crate) fn is_complete(&self) -> bool {
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
        }
    }

    pub(crate) fn push(&mut self, chunk: ChunkPayloadData) -> bool {
        if chunk.stream_identifier != self.si {
            return false;
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
        // Check unordered first
        if !self.unordered.is_empty() {
            // The chunk sets in self.unordered should all be complete.
            return true;
        }

        // Check ordered sets
        if !self.ordered.is_empty() {
            let cset = &self.ordered[0];
            if cset.is_complete() && sna16lte(cset.ssn, self.next_ssn) {
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
            if sna16gt(chunks.ssn, self.next_ssn) {
                return None;
            }
            Some(chunks)
        } else {
            None
        }
    }

    pub(crate) fn read(&mut self) -> Option<Chunks> {
        let chunks = if let (Some(unordered_chunks), Some(ordered_chunks)) = (
            self.readable_unordered_chunks(),
            self.readable_ordered_chunks(),
        ) {
            if unordered_chunks.arrival < ordered_chunks.arrival {
                self.unordered.pop_front().unwrap()
            } else {
                if ordered_chunks.ssn == self.next_ssn {
                    self.next_ssn = self.next_ssn.wrapping_add(1);
                }
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
                if sna16gt(chunks.ssn, self.next_ssn) {
                    return None;
                }
                if chunks.ssn == self.next_ssn {
                    self.next_ssn = self.next_ssn.wrapping_add(1);
                }
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

    /// Whether the queue holds no fragment and no message.
    pub(crate) fn is_empty(&self) -> bool {
        self.n_bytes == 0
            && self.ordered.is_empty()
            && self.unordered.is_empty()
            && self.unordered_chunks.is_empty()
    }
}
