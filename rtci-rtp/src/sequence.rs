use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicU16, AtomicU64, Ordering};

/// Sequencer generates sequential sequence numbers for building RTP packets
pub trait Sequencer: Send + Sync + fmt::Debug {
    /// Returns the next sequence number, wrapping at `u16::MAX` and counting the rollover.
    fn next_sequence_number(&self) -> u16;
    /// How many times the sequence number has wrapped.
    ///
    /// SRTP needs this: the rollover counter is part of the packet index it encrypts with.
    fn roll_over_count(&self) -> u64;
    /// Clones this sequencer behind a trait object.
    fn clone_to(&self) -> Box<dyn Sequencer>;
}

impl Clone for Box<dyn Sequencer> {
    fn clone(&self) -> Box<dyn Sequencer> {
        self.clone_to()
    }
}

/// NewRandomSequencer returns a new sequencer starting from a random sequence
/// number
pub fn new_random_sequencer() -> impl Sequencer {
    let c = Counters {
        sequence_number: Arc::new(AtomicU16::new(rand::random::<u16>())),
        roll_over_count: Arc::new(AtomicU64::new(0)),
    };
    SequencerImpl(c)
}

/// NewFixedSequencer returns a new sequencer starting from a specific
/// sequence number
pub fn new_fixed_sequencer(s: u16) -> impl Sequencer {
    let sequence_number = if s == 0 { u16::MAX } else { s - 1 };

    let c = Counters {
        sequence_number: Arc::new(AtomicU16::new(sequence_number)),
        roll_over_count: Arc::new(AtomicU64::new(0)),
    };

    SequencerImpl(c)
}

#[derive(Debug, Clone)]
struct SequencerImpl(Counters);

#[derive(Debug, Clone)]
struct Counters {
    sequence_number: Arc<AtomicU16>,
    roll_over_count: Arc<AtomicU64>,
}

impl Sequencer for SequencerImpl {
    /// NextSequenceNumber increment and returns a new sequence number for
    /// building RTP packets
    fn next_sequence_number(&self) -> u16 {
        if self.0.sequence_number.load(Ordering::SeqCst) == u16::MAX {
            self.0.roll_over_count.fetch_add(1, Ordering::SeqCst);
            self.0.sequence_number.store(0, Ordering::SeqCst);
            0
        } else {
            self.0.sequence_number.fetch_add(1, Ordering::SeqCst) + 1
        }
    }

    /// RollOverCount returns the amount of times the 16bit sequence number
    /// has wrapped
    fn roll_over_count(&self) -> u64 {
        self.0.roll_over_count.load(Ordering::SeqCst)
    }

    fn clone_to(&self) -> Box<dyn Sequencer> {
        Box::new(self.clone())
    }
}

/// A source is valid once this many packets arrived in sequence (RFC 3550 Appendix A.1).
pub const MIN_SEQUENTIAL: u32 = 2;
/// A forward jump smaller than this is loss, not a restart (RFC 3550 Appendix A.1).
pub const MAX_DROPOUT: u16 = 3000;
/// A packet this far behind the highest sequence number, or less, is late or a duplicate
/// (RFC 3550 Appendix A.1).
pub const MAX_MISORDER: u16 = 100;

const RTP_SEQ_MOD: u32 = 1 << 16;

/// The per-source sequence number state of RFC 3550 Appendix A.1 (`init_seq`, `update_seq`),
/// with the loss arithmetic of Appendix A.3.
///
/// A new source is on probation until [`MIN_SEQUENTIAL`] packets arrive in sequence; a jump of
/// [`MAX_DROPOUT`] or more ahead, or more than [`MAX_MISORDER`] behind, is taken for a source
/// that restarted once two packets in a row say so, and the state starts over from there.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceSequence {
    max_seq: u16,
    cycles: u32,
    base_seq: u32,
    bad_seq: u32,
    probation: u32,
    received: u32,
}

impl SourceSequence {
    /// The state for a source whose first packet has this sequence number. That packet is
    /// counted by the first [`update`](SourceSequence::update), not here.
    pub fn new(first_sequence_number: u16) -> Self {
        let mut state = SourceSequence {
            max_seq: 0,
            cycles: 0,
            base_seq: 0,
            bad_seq: 0,
            probation: MIN_SEQUENTIAL,
            received: 0,
        };
        state.init(first_sequence_number);
        state.max_seq = first_sequence_number.wrapping_sub(1);
        state
    }

    fn init(&mut self, sequence_number: u16) {
        self.base_seq = u32::from(sequence_number);
        self.max_seq = sequence_number;
        // Not a sequence number: so that `seq == bad_seq` is false.
        self.bad_seq = RTP_SEQ_MOD + 1;
        self.cycles = 0;
        self.received = 0;
    }

    /// Takes a packet's sequence number. `true` when the packet is valid: in sequence for a
    /// source past its probation, late or duplicated within [`MAX_MISORDER`]. `false` while the
    /// source is on probation, and for a packet after a jump until the next one confirms it.
    pub fn update(&mut self, sequence_number: u16) -> bool {
        let udelta = sequence_number.wrapping_sub(self.max_seq);
        if self.probation > 0 {
            // The source is not valid until MIN_SEQUENTIAL packets with sequential sequence
            // numbers have been received.
            if sequence_number == self.max_seq.wrapping_add(1) {
                self.probation -= 1;
                self.max_seq = sequence_number;
                if self.probation == 0 {
                    self.init(sequence_number);
                    self.received += 1;
                    return true;
                }
            } else {
                self.probation = MIN_SEQUENTIAL - 1;
                self.max_seq = sequence_number;
            }
            return false;
        } else if udelta < MAX_DROPOUT {
            // In order, with a permissible gap.
            if sequence_number < self.max_seq {
                // The sequence number wrapped: count another 64K cycle.
                self.cycles = self.cycles.wrapping_add(RTP_SEQ_MOD);
            }
            self.max_seq = sequence_number;
        } else if u32::from(udelta) <= RTP_SEQ_MOD - u32::from(MAX_MISORDER) {
            // The sequence number made a very large jump.
            if u32::from(sequence_number) == self.bad_seq {
                // Two sequential packets: the other side restarted without telling us, so
                // re-sync as if this were the first packet.
                self.init(sequence_number);
            } else {
                self.bad_seq = (u32::from(sequence_number) + 1) & (RTP_SEQ_MOD - 1);
                return false;
            }
        } else {
            // A duplicate or a reordered packet.
        }
        self.received = self.received.wrapping_add(1);
        true
    }

    /// Whether the source is still on probation.
    pub fn on_probation(&self) -> bool {
        self.probation > 0
    }

    /// The extended highest sequence number: the count of sequence number cycles in the high
    /// 16 bits (RFC 3550 section 6.4.1).
    pub fn extended_max(&self) -> u32 {
        self.cycles.wrapping_add(u32::from(self.max_seq))
    }

    /// Packets accepted since the state was last initialised.
    pub fn received(&self) -> u32 {
        self.received
    }

    /// Packets expected: from the first sequence number to the highest (Appendix A.3).
    pub fn expected(&self) -> u32 {
        self.extended_max()
            .wrapping_sub(self.base_seq)
            .wrapping_add(1)
    }

    /// Packets lost: expected less received. Negative when duplicates arrived; a late packet
    /// is not lost (RFC 3550 section 6.4.1, Appendix A.3).
    pub fn cumulative_lost(&self) -> i64 {
        i64::from(self.expected()) - i64::from(self.received)
    }
}

#[cfg(test)]
#[path = "sequence_test.rs"]
mod sequence_test;
