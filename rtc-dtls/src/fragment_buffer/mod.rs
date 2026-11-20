#[cfg(test)]
mod fragment_buffer_robustness_test;
#[cfg(test)]
mod fragment_buffer_test;

use crate::content::*;
use crate::handshake::HandshakeType;
use crate::handshake::handshake_header::*;
use crate::record_layer::record_layer_header::*;
use shared::error::*;

use std::collections::HashMap;
use std::io::{BufWriter, Cursor};

// 2 mb max buffer size
const FRAGMENT_BUFFER_MAX_SIZE: usize = 2_000_000;

/// Most fragments one handshake message may arrive in. A peer fragments at its path MTU, so
/// even a large certificate chain needs a few dozen; anything past this is dropped rather than
/// buffered, so a stream of tiny fragments cannot grow the reassembly work without bound.
pub(crate) const MAX_FRAGMENTS_PER_MESSAGE: usize = 256;

/// Most handshake messages buffered at once, counted by message sequence. A flight holds a
/// handful; fragments for further sequence numbers are dropped until earlier ones are popped.
pub(crate) const MAX_BUFFERED_MESSAGES: usize = 32;

/// How far ahead of the next expected message sequence number fragments are kept. A peer sends
/// one flight at a time, and a flight holds a handful of messages, so fragments further ahead can
/// only be forged or corrupt; kept, they would hold buffer slots (see `MAX_BUFFERED_MESSAGES`)
/// for good and stall the handshake.
pub(crate) const MESSAGE_SEQUENCE_WINDOW: u16 = 16;

/// Most distinct (type, length) readings of one message sequence number tried when reassembling
/// it. The genuine fragments agree on both; a forged fragment that disagrees must not block them,
/// but each extra reading costs a reassembly pass.
const MAX_ASSEMBLY_CANDIDATES: usize = 8;

pub(crate) struct Fragment {
    record_layer_header: RecordLayerHeader,
    handshake_header: HandshakeHeader,
    data: Vec<u8>,
}

pub(crate) struct FragmentBuffer {
    // map of MessageSequenceNumbers that hold slices of fragments
    cache: HashMap<u16, Vec<Fragment>>,

    current_message_sequence_number: u16,
}

impl FragmentBuffer {
    pub fn new() -> Self {
        FragmentBuffer {
            cache: HashMap::new(),
            current_message_sequence_number: 0,
        }
    }

    // Attempts to push a DTLS packet to the FragmentBuffer
    // when it returns true it means the FragmentBuffer has inserted and the buffer shouldn't be handled
    // when an error returns it is fatal, and the DTLS connection should be stopped
    pub fn push(&mut self, mut buf: &[u8]) -> Result<bool> {
        let current_size = self.size();
        if current_size + buf.len() >= FRAGMENT_BUFFER_MAX_SIZE {
            return Err(Error::ErrFragmentBufferOverflow {
                new_size: current_size + buf.len(),
                max_size: FRAGMENT_BUFFER_MAX_SIZE,
            });
        }

        let mut reader = Cursor::new(buf);
        let record_layer_header = RecordLayerHeader::unmarshal(&mut reader)?;

        // Fragment isn't a handshake, we don't need to handle it
        if record_layer_header.content_type != ContentType::Handshake {
            return Ok(false);
        }

        buf = &buf[RECORD_LAYER_HEADER_SIZE..];
        while !buf.is_empty() {
            let mut reader = Cursor::new(buf);
            let handshake_header = HandshakeHeader::unmarshal(&mut reader)?;

            // Bound what an unauthenticated sender can make us hold: drop (rather than fail on)
            // fragments past the per-message and per-buffer caps, so spoofed records cannot
            // tear the handshake down either.
            let at_message_cap = !self.cache.contains_key(&handshake_header.message_sequence)
                && self.cache.len() >= MAX_BUFFERED_MESSAGES;
            let at_fragment_cap = self
                .cache
                .get(&handshake_header.message_sequence)
                .is_some_and(|frags| frags.len() >= MAX_FRAGMENTS_PER_MESSAGE);

            // end index should be the length of handshake header but if the handshake
            // was fragmented, we should keep them all
            let mut end = HANDSHAKE_HEADER_LENGTH + handshake_header.length as usize;
            if end > buf.len() {
                end = buf.len();
            }

            if !(at_message_cap || at_fragment_cap) {
                // Discard all headers, when rebuilding the packet we will re-build
                let data = buf[HANDSHAKE_HEADER_LENGTH..end].to_vec();
                self.cache
                    .entry(handshake_header.message_sequence)
                    .or_default()
                    .push(Fragment {
                        record_layer_header,
                        handshake_header,
                        data,
                    });
            }
            buf = &buf[end..];
        }

        Ok(true)
    }

    pub fn pop(&mut self) -> Result<(Vec<u8>, u16)> {
        self.evict_out_of_window();
        let seq_num = self.current_message_sequence_number;
        // message_seq is 16 bits and no handshake comes near using them all, but a peer can
        // push empty messages that each consume one; the last one is never handed out, so the
        // counter cannot overflow.
        let Some(next_seq_num) = seq_num.checked_add(1) else {
            return Err(Error::ErrEmptyFragment);
        };
        let Some((content, epoch)) = self.assemble(seq_num) else {
            return Err(Error::ErrEmptyFragment);
        };

        self.cache.remove(&seq_num);
        self.current_message_sequence_number = next_seq_num;

        Ok((content, epoch))
    }

    /// Hands the sequence number [`Self::pop`] last returned out again. The message it returned
    /// did not parse, so it was forged or corrupt; the genuine one, when the peer retransmits it,
    /// must still be taken rather than kept forever as already seen.
    pub fn unpop(&mut self) {
        self.current_message_sequence_number =
            self.current_message_sequence_number.saturating_sub(1);
    }

    /// Drops fragments too far ahead of the next expected message to belong to the peer's
    /// current flight (see [`MESSAGE_SEQUENCE_WINDOW`]).
    fn evict_out_of_window(&mut self) {
        let limit = self
            .current_message_sequence_number
            .saturating_add(MESSAGE_SEQUENCE_WINDOW);
        self.cache.retain(|seq, _| *seq < limit);
    }

    /// Takes a complete message whose sequence number [`Self::pop`] has already handed out: the
    /// peer sending a message again, as it does when it retransmits a flight (RFC 6347 4.2.4).
    /// A repeat still missing fragments stays until they arrive. Returns the message (header
    /// included), the epoch it arrived in and its sequence number.
    pub fn pop_stale(&mut self) -> Option<(Vec<u8>, u16, u16)> {
        let current = self.current_message_sequence_number;
        let mut stale: Vec<u16> = self
            .cache
            .keys()
            .copied()
            .filter(|seq| *seq < current)
            .collect();
        stale.sort_unstable();
        for seq in stale {
            if let Some((content, epoch)) = self.assemble(seq) {
                self.cache.remove(&seq);
                return Some((content, epoch, seq));
            }
        }
        None
    }

    /// Reassembles message `seq_num`, its header rebuilt as for one unfragmented message, with the
    /// epoch it arrived in. `None` while fragments are missing.
    fn assemble(&self, seq_num: u16) -> Option<(Vec<u8>, u16)> {
        let frags = self.cache.get(&seq_num)?;
        let (raw_message, first) = assemble_message(frags)?;

        let mut first_header = frags[first].handshake_header;
        first_header.fragment_offset = 0;
        first_header.fragment_length = first_header.length;

        let mut raw_header = vec![];
        {
            let mut writer = BufWriter::<&mut Vec<u8>>::new(raw_header.as_mut());
            first_header.marshal(&mut writer).ok()?;
        }

        let message_epoch = frags[first].record_layer_header.epoch;

        raw_header.extend_from_slice(&raw_message);

        Some((raw_header, message_epoch))
    }

    fn size(&self) -> usize {
        self.cache
            .values()
            .map(|fragment| fragment.iter().map(|f| f.data.len()).sum::<usize>())
            .sum()
    }
}

/// Reassembles one handshake message from its fragments: start at offset 0 and follow each
/// fragment's end to the next, until the message length is reached (or a zero-length fragment
/// ends it). Returns the message body and the index of the fragment it starts with.
///
/// The fragments of one message agree on its type and length. One that disagrees (forged, or
/// corrupt) used to win its offset for good if it arrived first, so the genuine fragments could
/// never complete the message. Each (type, length) reading is tried instead, newest first, and
/// within it first the earliest then the latest fragment for each offset, so a later genuine
/// fragment can replace a conflicting one.
///
/// Iterative: the previous recursive version used one stack frame per fragment, so a peer that
/// sent enough tiny fragments could overflow the stack and abort the process.
fn assemble_message(frags: &[Fragment]) -> Option<(Vec<u8>, usize)> {
    let mut tried: Vec<(HandshakeType, u32)> = Vec::new();
    for candidate in frags.iter().rev() {
        let reading = (
            candidate.handshake_header.handshake_type,
            candidate.handshake_header.length,
        );
        if tried.contains(&reading) {
            continue;
        }
        if tried.len() >= MAX_ASSEMBLY_CANDIDATES {
            break;
        }
        tried.push(reading);
        for latest_wins in [false, true] {
            if let Some(assembled) = assemble_reading(frags, reading, latest_wins) {
                return Some(assembled);
            }
        }
    }
    None
}

/// Reassembles the message from the fragments that agree with `reading` (type, length), taking
/// for each offset the earliest fragment, or the latest when `latest_wins`.
fn assemble_reading(
    frags: &[Fragment],
    reading: (HandshakeType, u32),
    latest_wins: bool,
) -> Option<(Vec<u8>, usize)> {
    let mut by_offset: HashMap<u32, (usize, &Fragment)> = HashMap::with_capacity(frags.len());
    for (index, f) in frags.iter().enumerate() {
        if (f.handshake_header.handshake_type, f.handshake_header.length) != reading {
            continue;
        }
        if latest_wins {
            by_offset.insert(f.handshake_header.fragment_offset, (index, f));
        } else {
            by_offset
                .entry(f.handshake_header.fragment_offset)
                .or_insert((index, f));
        }
    }

    let mut raw_message = vec![];
    let mut first = None;
    let mut target_offset = 0u32;
    // Each step consumes a distinct offset, so this ends within `by_offset.len()` steps even if
    // fragment lengths point back at an offset already visited.
    for _ in 0..by_offset.len() {
        let (index, f) = by_offset.remove(&target_offset)?;
        first.get_or_insert(index);
        raw_message.extend_from_slice(&f.data);
        let fragment_end = f
            .handshake_header
            .fragment_offset
            .checked_add(f.handshake_header.fragment_length)?;
        if fragment_end == f.handshake_header.length || f.handshake_header.fragment_length == 0 {
            return Some((raw_message, first?));
        }
        target_offset = fragment_end;
    }
    None
}
