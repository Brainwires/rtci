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

            // The fragment is the `fragment_length` bytes after the header; another message
            // (or fragment) may follow it in the same record (RFC 6347 4.2.3). One that claims
            // more bytes than the record holds is malformed.
            let end = HANDSHAKE_HEADER_LENGTH + handshake_header.fragment_length as usize;
            if end > buf.len() {
                return Err(Error::ErrBufferTooSmall);
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

/// What the fragments of one message agree on: its type, its length, and the epoch they came
/// in. Fragments of different epochs are never joined: an epoch-0 fragment is unauthenticated,
/// and must not supply bytes of a message (the Finished) that arrives protected.
type Reading = (HandshakeType, u32, u16);

fn reading_of(f: &Fragment) -> Reading {
    (
        f.handshake_header.handshake_type,
        f.handshake_header.length,
        f.record_layer_header.epoch,
    )
}

/// Reassembles one handshake message from its fragments, whatever their order and however
/// their ranges overlap or repeat (RFC 6347 4.2.3): a peer that retransmits a flight after its
/// path MTU estimate changed cuts the same message differently. Returns the message body and
/// the index of a fragment it was built from.
///
/// The fragments of one message agree on its type and length. One that disagrees (forged, or
/// corrupt) must not keep the genuine ones from completing the message, so each reading is
/// tried, newest first.
fn assemble_message(frags: &[Fragment]) -> Option<(Vec<u8>, usize)> {
    let mut tried: Vec<Reading> = Vec::new();
    for candidate in frags.iter().rev() {
        let reading = reading_of(candidate);
        if tried.contains(&reading) {
            continue;
        }
        if tried.len() >= MAX_ASSEMBLY_CANDIDATES {
            break;
        }
        tried.push(reading);
        for latest_first in [false, true] {
            if let Some(assembled) = assemble_reading(frags, reading, latest_first) {
                return Some(assembled);
            }
        }
    }
    None
}

/// Reassembles the message from the fragments that agree with `reading`, laying them over the
/// message's bytes in arrival order, or newest first when `latest_first`. A fragment that
/// disagrees with bytes already placed is left out: genuine fragments, however they overlap,
/// carry the same bytes, so the one that disagrees is forged or corrupt, and trying both orders
/// lets the genuine ones win whether it came before or after them.
///
/// One pass over each fragment's bytes, no recursion: a peer that sends many tiny fragments
/// costs work in proportion to what it sent.
fn assemble_reading(
    frags: &[Fragment],
    reading: Reading,
    latest_first: bool,
) -> Option<(Vec<u8>, usize)> {
    let length = reading.1 as usize;
    let fits = |f: &&Fragment| {
        reading_of(f) == reading
            && f.data.len() == f.handshake_header.fragment_length as usize
            && (f.handshake_header.fragment_offset as usize)
                .checked_add(f.data.len())
                .is_some_and(|end| end <= length)
    };
    // The message cannot be complete with fewer bytes than its length, which also keeps a
    // length an unauthenticated header merely claims from sizing the allocation below.
    let available: usize = frags.iter().filter(fits).map(|f| f.data.len()).sum();
    if available < length {
        return None;
    }

    let mut order: Vec<usize> = (0..frags.len()).filter(|i| fits(&&frags[*i])).collect();
    if latest_first {
        order.reverse();
    }

    let mut message = vec![0u8; length];
    let mut covered = vec![false; length];
    let mut missing = length;
    let mut first = None;
    for index in order {
        let f = &frags[index];
        let start = f.handshake_header.fragment_offset as usize;
        let end = start + f.data.len();
        let agrees = (start..end).all(|i| !covered[i] || message[i] == f.data[i - start]);
        if !agrees {
            continue;
        }
        first.get_or_insert(index);
        for i in start..end {
            if !covered[i] {
                covered[i] = true;
                message[i] = f.data[i - start];
                missing -= 1;
            }
        }
        if missing == 0 {
            return Some((message, first?));
        }
    }
    None
}
