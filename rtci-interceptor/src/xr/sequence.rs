//! RFC 3611 section 4.1 and Appendix A.1: where a 16-bit sequence number falls in the
//! extended sequence space.

/// Places each sequence number of a source in a 32-bit space, as RFC 3611 Appendix A.1 does:
/// the first one in the middle of the space, each next one at most 32,768 ahead of or behind
/// the one before, whichever is closer; on a tie (a distance of exactly 32,768) the one that
/// needs no rollover of the 16-bit number (section 4.1: both "MUST").
///
/// Every sequence number is taken as valid (section 4.1: "an RTP session participant SHOULD
/// treat all sequence numbers as valid"), and the reference moves to each one received.
#[derive(Debug, Default, Clone)]
pub(crate) struct SequenceExtender {
    reference: Option<u32>,
}

impl SequenceExtender {
    /// The extended sequence number of `seq`, which becomes the reference for the next one.
    pub(crate) fn extend(&mut self, seq: u16) -> u64 {
        let extended = match self.reference {
            None => u32::from(seq) | 0x8000_0000,
            Some(reference) => {
                let seq_a = u32::from(seq) | (reference & 0xFFFF_0000);
                let (seq_b, diff_a, diff_b) = if reference < seq_a {
                    let seq_b = seq_a.wrapping_sub(0x0001_0000);
                    (seq_b, seq_a - reference, reference.wrapping_sub(seq_b))
                } else {
                    let seq_b = seq_a.wrapping_add(0x0001_0000);
                    (seq_b, reference - seq_a, seq_b.wrapping_sub(reference))
                };
                // `seq_a` keeps the reference's upper half: no rollover. Appendix A.1's code
                // takes `seq_b` on a tie, against its own comment and section 4.1's "MUST be
                // the one that does not require a rollover"; the section is followed here.
                if diff_a <= diff_b { seq_a } else { seq_b }
            }
        };
        self.reference = Some(extended);
        u64::from(extended)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 3611 4.1: forward across the 16-bit wrap, and back.
    #[test]
    fn a_sequence_number_is_placed_on_the_closer_side_of_the_last_one() {
        let mut x = SequenceExtender::default();
        let first = x.extend(65_534);
        assert_eq!(first + 3, x.extend(1), "ahead, across the wrap");
        assert_eq!(first + 1, x.extend(65_535), "behind, back across the wrap");
        assert_eq!(first + 32_768, x.extend(32_766), "32,767 ahead is ahead");
        assert_eq!(first + 1, x.extend(65_535), "32,767 behind is behind");
    }

    /// RFC 3611 4.1: "In the event that both choices are equally distant (only possible when
    /// the distance is 32,768), the choice MUST be the one that does not require a rollover."
    #[test]
    fn at_a_distance_of_32768_the_side_without_a_rollover_is_taken() {
        let mut x = SequenceExtender::default();
        let at_100 = x.extend(100);
        // 100 + 32,768 = 32,868: no rollover ahead, so ahead.
        assert_eq!(at_100 + 32_768, x.extend(32_868));

        let mut x = SequenceExtender::default();
        let at_40000 = x.extend(40_000);
        // 40,000 - 32,768 = 7,232: no rollover behind, so behind (ahead would wrap).
        assert_eq!(at_40000 - 32_768, x.extend(7_232));
    }
}
